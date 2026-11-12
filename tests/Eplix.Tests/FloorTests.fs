/// Floor records for keys with no signing history: the floor values, the
/// stores that keep them, the import's question per key, the import end to end, and a lost setup
/// where a node hands over a source from before the loss.
module Eplix.Tests.FloorTests

open System
open System.IO
open System.Net.Http
open System.Threading
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let private spe = uint64 slotsPerEpoch

let private openDb (path: string) =
    match SlashingDb.Open(new FileMarkFile(path), gvr) with
    | Ok db -> db
    | Error e -> failwith e

let private openSlotMarks (path: string) =
    match SlotMarks.Open(new FileMarkFile(path), gvr) with
    | Ok m -> m
    | Error e -> failwith e

/// Runs `f` on a store, then closes it.
let private closing (x: #IDisposable) (f: _ -> unit) =
    use _ = x
    f x

let private att (i: int) (source: Epoch) (target: Epoch) =
    AttestationRequest(pubkeyOf i, source, target, root (int target))

let private block (i: int) (slot: Slot) = BlockRequest(pubkeyOf i, slot, root 7)

let private verdicts (db: SlashingDb) (requests: SlashingRequest list) =
    db.CheckAndRecord(Array.ofList requests, CancellationToken.None).GetAwaiter().GetResult()
    |> List.ofArray

let private refused (v: Verdict) =
    match v with
    | Verdict.Refused _ -> true
    | _ -> false

let private info (i: int) (status: string) : ValidatorInfo =
    {
        Index = uint64 i
        PubKey = pubkeyOf i
        Status = status
        ActivationEpoch = 0UL
        ExitEpoch = UInt64.MaxValue
        Slashed = false
    }

/// A terminal that gives the answers in turn (then end of input) and keeps what was asked and said.
let private terminal (interactive: bool) (answers: string list) =
    let asked = ResizeArray<string>()
    let said = ResizeArray<string>()
    let queue = Collections.Generic.Queue<string>(answers)

    let prompt: FloorImport.Prompt =
        {
            Interactive = interactive
            Ask =
                fun q ->
                    asked.Add q
                    if queue.Count = 0 then ValueNone else ValueSome(queue.Dequeue())
            Say = said.Add
        }

    prompt, asked, said

/// A config on the fake chain's config file, and its data dir.
let private importConfig () =
    let dir = tempDir ()
    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
    let text = """{ "beacon_node": "http://bn0.test", "chain_config": "chain.yaml", "data_dir": "data" }"""

    match Config.parse text dir [] with
    | Ok c -> c
    | Error es -> failtestf "%A" es

let private clientOf (i: int) (node: FakeBeaconNode) =
    BeaconClient(new HttpClient(node, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0)

let private withDataDir (config: CoreConfig) (f: DataDir -> 'a) =
    match DataDir.Acquire(config.DataDir, Log.none) with
    | Ok d ->
        use _ = d
        f d
    | Error e -> failtest e

[<Tests>]
let tests =
    testList
        "floor"
        [
            test "floor values: source = target = E + 1, block at the last slot of E + 1" {
                let m = Floor.marks 32UL 10UL

                Expect.equal
                    m.Attestation
                    (ValueSome
                        {
                            Source = 11UL
                            Target = 11UL
                            Root = ValueNone
                            RootSource = 11UL
                        })
                    "vote marks"

                Expect.equal m.Block (ValueSome { Slot = 383UL; Root = ValueNone }) "block mark"
                Expect.equal (Floor.slot 32UL 10UL) 383UL "slot marks"
                Expect.equal (Floor.epoch 32UL 10UL [ 0UL; 100UL ]) 10UL "heads below the clock leave E"
                Expect.equal (Floor.epoch 32UL 10UL [ 0UL; 415UL ]) 12UL "a head above the clock raises E"
                Expect.equal (Floor.epoch 32UL 0UL []) 0UL "no head, clock at genesis"
                Expect.equal (Floor.epochChecked 32UL 10UL [ 0UL; 383UL ]) (Ok 11UL) "a head one epoch past the clock"
                Expect.isError (Floor.epochChecked 32UL 10UL [ 384UL ]) "a head two epochs past the clock"
                Expect.isError (Floor.epochChecked 32UL 10UL [ UInt64.MaxValue ]) "a huge head"
            }

            test "floor values near the top of uint64 do not wrap" {
                let top = UInt64.MaxValue / 32UL
                Expect.throwsT<OverflowException> (fun () -> Floor.slot 32UL top |> ignore) "slot"
                Expect.throwsT<OverflowException> (fun () -> Floor.target UInt64.MaxValue |> ignore) "target"
                use db = openDb (Path.Combine(tempDir (), "s.db"))
                Expect.isError (Floor.write db ValueNone 32UL top KeyOrigin.Floor [ pubkeyOf 0 ]) "write refuses"
                Expect.isFalse (db.HasRecord(pubkeyOf 0)) "no record"
            }

            test "a floor refuses every vote and block at or below it, and any older source" {
                let path = Path.Combine(tempDir (), "s.db")

                closing (openDb path) (fun db ->
                    Expect.isOk (Floor.write db ValueNone spe 10UL KeyOrigin.Floor [ pubkeyOf 0 ]) "floor"
                    Expect.equal (db.Origin(pubkeyOf 0)) (ValueSome KeyOrigin.Floor) "origin")

                use db = openDb path
                Expect.equal (db.Marks(pubkeyOf 0)) (ValueSome(Floor.marks spe 10UL)) "kept across a reopen"

                let v =
                    verdicts
                        db
                        [
                            att 0 9UL 11UL
                            att 0 11UL 11UL
                            att 0 5UL 12UL
                            att 0 10UL 13UL
                            block 0 (Floor.slot spe 10UL)
                        ]

                Expect.isTrue (v |> List.forall refused) $"at or below the floor, or an older source: %A{v}"
                let v = verdicts db [ att 0 11UL 12UL; block 0 (Floor.slot spe 10UL + 1UL) ]
                Expect.equal v [ Verdict.Allowed; Verdict.Allowed ] "above the floor"
            }

            test "a floor only raises marks; a key with a record keeps its origin" {
                use db = openDb (Path.Combine(tempDir (), "s.db"))
                db.RegisterKeys [ pubkeyOf 0, KeyOrigin.Imported; pubkeyOf 1, KeyOrigin.Imported ] |> ignore

                Expect.equal
                    (verdicts db [ att 0 20UL 30UL; block 0 1000UL; att 1 3UL 30UL ])
                    [ Verdict.Allowed; Verdict.Allowed; Verdict.Allowed ]
                    "history"

                Expect.isOk (Floor.write db ValueNone spe 10UL KeyOrigin.Floor [ pubkeyOf 0; pubkeyOf 1 ]) "floor"
                let m0 = (db.Marks(pubkeyOf 0)).Value

                Expect.equal
                    (m0.Attestation.Value.Source, m0.Attestation.Value.Target, m0.Block.Value.Slot)
                    (20UL, 30UL, 1000UL)
                    "higher marks stay"

                let m1 = (db.Marks(pubkeyOf 1)).Value

                Expect.equal
                    (m1.Attestation.Value.Source, m1.Attestation.Value.Target)
                    (11UL, 30UL)
                    "the source mark rises to the floor"

                Expect.equal (db.Origin(pubkeyOf 1)) (ValueSome KeyOrigin.Imported) "origin kept"
            }

            test "the PTC vote and envelope marks rise to the floor slot" {
                let path = Path.Combine(tempDir (), "m.db")
                closing (openSlotMarks path) (fun m -> Expect.isOk (m.RaiseFloor([ pubkeyOf 0 ], 383UL)) "raise")
                use m = openSlotMarks path

                let req kind slot =
                    {
                        Key = pubkeyOf 0
                        Kind = kind
                        Slot = slot
                        SigningRoot = root 3
                    }

                let v =
                    m
                        .CheckAndRecord(
                            [|
                                req SlotMarkKind.PayloadAttestation 383UL
                                req SlotMarkKind.PayloadEnvelope 383UL
                                req SlotMarkKind.PayloadAttestation 384UL
                                req SlotMarkKind.PayloadEnvelope 384UL
                            |],
                            CancellationToken.None
                        )
                        .GetAwaiter()
                        .GetResult()

                Expect.isTrue (refused v[0] && refused v[1]) $"at the floor slot: %A{v}"
                Expect.equal v[2..] [| Verdict.Allowed; Verdict.Allowed |] "above it"
            }

            test "the import asks only for keys that may have signed; without a terminal it asks nothing" {
                let prompt, asked, said = terminal false []

                let answered =
                    [
                        "bn0",
                        [|
                            info 0 "active_ongoing"
                            info 1 "pending_queued"
                            info 3 "exited_unslashed"
                        |]
                        "bn1",
                        [|
                            info 0 "active_ongoing"
                            info 1 "pending_initialized"
                            { info 4 "pending_queued" with
                                Slashed = true
                            }
                        |]
                    ]

                let o = FloorImport.decide prompt 8UL answered [ for i in 0..4 -> pubkeyOf i ]
                Expect.equal o.Floored [ pubkeyOf 1; pubkeyOf 2 ] "pending and unknown keys need no question"
                Expect.equal o.Unconfirmed [ pubkeyOf 0; pubkeyOf 3; pubkeyOf 4 ] "the rest are not imported"
                Expect.isEmpty asked "nothing asked"

                Expect.isTrue
                    (said
                     |> Seq.exists (fun s ->
                         s.Contains "active_ongoing on bn0, active_ongoing on bn1" && s.Contains "epoch 8"))
                    $"names the status, nodes and floor: %A{said}"
            }

            test "y, n and all on a terminal; anything else asks again; the end of input is no" {
                let prompt, asked, _ = terminal true [ "y"; "maybe"; "N"; "all" ]
                let answered = [ "bn0", [| for i in 0..4 -> info i "active_ongoing" |] ]
                let o = FloorImport.decide prompt 8UL answered [ for i in 0..4 -> pubkeyOf i ]
                Expect.equal o.Floored [ pubkeyOf 0; pubkeyOf 2; pubkeyOf 3; pubkeyOf 4 ] "y, then all for the rest"
                Expect.equal o.Declined [ pubkeyOf 1 ] "n"
                Expect.equal asked.Count 4 "key 1 asked twice; no question after all"
                Expect.isTrue (asked |> Seq.forall (fun q -> q.EndsWith "[y/n/all] ")) "the question"
                let prompt, _, _ = terminal true []
                let o = FloorImport.decide prompt 8UL answered [ pubkeyOf 0 ]
                Expect.equal o.Declined [ pubkeyOf 0 ] "end of input"
            }

            test "no node answered: said once, and every key is asked as status unknown" {
                let prompt, asked, said = terminal true [ "y"; "n" ]
                let o = FloorImport.decide prompt 8UL [] [ pubkeyOf 0; pubkeyOf 1 ]

                Expect.equal
                    (said |> Seq.filter (fun s -> s.Contains "no synced beacon node answered") |> Seq.length)
                    1
                    "said once"

                Expect.isTrue (asked |> Seq.forall (fun q -> q.Contains "status unknown")) $"%A{asked}"
                Expect.equal (o.Floored, o.Declined) ([ pubkeyOf 0 ], [ pubkeyOf 1 ]) "answers"
            }

            testT "eplix import --no-signing-history writes the floor before the VC starts" (fun () ->
                task {
                    let h = harness ()
                    let config = importConfig ()
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    node.AddValidator(pubkeyOf 1, "pending_queued") |> ignore
                    // The clock in epoch 4, the node's head in epoch 5: E = 5.
                    h.Time.Advance(TimeSpan.FromSeconds(float (4 * slotsPerEpoch * secondsPerSlot)))
                    node.SyncHeadSlot <- 5UL * spe + 1UL
                    let prompt, _, _ = terminal false []

                    let! r =
                        withDataDir config (fun d ->
                            FloorImport.run
                                config
                                [ clientOf 0 node ]
                                d
                                h.Time
                                prompt
                                [ for i in 0..2 -> pubkeyOf i ]
                                []
                                CancellationToken.None)

                    match r with
                    | Error e -> failtest e
                    | Ok o ->
                        Expect.equal o.FloorEpoch 5UL "E from the head"
                        Expect.equal o.Floored [ pubkeyOf 1; pubkeyOf 2 ] "pending and unknown"
                        Expect.equal o.Unconfirmed [ pubkeyOf 0 ] "active, no terminal"

                    use db = openDb (Path.Combine(config.DataDir, "slashing.db"))
                    Expect.equal (db.Marks(pubkeyOf 1)) (ValueSome(Floor.marks spe 5UL)) "floor"
                    Expect.equal (db.Origin(pubkeyOf 1)) (ValueSome KeyOrigin.Floor) "origin"
                    Expect.isFalse (db.HasRecord(pubkeyOf 0)) "the unconfirmed key gets nothing"
                    use m = openSlotMarks (Path.Combine(config.DataDir, "slot-marks.db"))

                    Expect.equal
                        ((m.Marks(pubkeyOf 1)).Value.PayloadEnvelope |> ValueOption.map (fun b -> b.Slot))
                        (ValueSome(Floor.slot spe 5UL))
                        "slot marks"
                })

            testT "a node head more than one epoch past the clock fails the import" (fun () ->
                task {
                    let h = harness ()
                    let config = importConfig ()
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    h.Time.Advance(TimeSpan.FromSeconds(float (2 * slotsPerEpoch * secondsPerSlot)))

                    for head in [ 4UL * spe; UInt64.MaxValue ] do
                        node.SyncHeadSlot <- head
                        let prompt, _, _ = terminal false []

                        let! r =
                            withDataDir config (fun d ->
                                FloorImport.run
                                    config
                                    [ clientOf 0 node ]
                                    d
                                    h.Time
                                    prompt
                                    [ pubkeyOf 1 ]
                                    []
                                    CancellationToken.None)

                        match r with
                        | Ok o -> failtestf "head %d: floor written at %d" head o.FloorEpoch
                        | Error e -> Expect.stringContains e "the clock in epoch 2" $"head {head}: names the clock"

                    use db = openDb (Path.Combine(config.DataDir, "slashing.db"))
                    Expect.isFalse (db.HasRecord(pubkeyOf 1)) "no record written"
                })

            testT
                "with a chain config file and no node answering, the import fails; a built-in network asks as unknown"
                (fun () ->
                    task {
                        let h = harness ()
                        let config = importConfig ()
                        let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                        node.Fail <- fun _ -> true
                        let prompt, _, _ = terminal false []

                        let! r =
                            withDataDir config (fun d ->
                                FloorImport.run
                                    config
                                    [ clientOf 0 node ]
                                    d
                                    h.Time
                                    prompt
                                    [ pubkeyOf 0 ]
                                    []
                                    CancellationToken.None)

                        match r with
                        | Ok _ -> failtest "no genesis to compute the floor from"
                        | Error e -> Expect.stringContains e "nothing pins the whole genesis" "why"

                        let dir = tempDir ()

                        let hoodi =
                            match
                                Config.parse
                                    """{ "beacon_node": "http://bn0.test", "network": "hoodi", "data_dir": "data" }"""
                                    dir
                                    []
                            with
                            | Ok c -> c
                            | Error es -> failtestf "%A" es

                        let prompt, asked, _ = terminal true [ "y" ]

                        let! r =
                            withDataDir hoodi (fun d ->
                                FloorImport.run
                                    hoodi
                                    [ clientOf 0 node ]
                                    d
                                    (FakeTimeProvider())
                                    prompt
                                    [ pubkeyOf 0 ]
                                    []
                                    CancellationToken.None)

                        match r with
                        | Error e -> failtest e
                        | Ok o ->
                            Expect.equal o.Floored [ pubkeyOf 0 ] "answered y"
                            Expect.isTrue (asked[0].Contains "status unknown") "asked as unknown"
                    })

            testT "a node off the genesis the data dir kept fails the import" (fun () ->
                task {
                    let h = harness ()
                    let config = importConfig ()
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    let prompt, _, _ = terminal true [ "y" ]

                    let! r =
                        withDataDir config (fun d ->
                            File.WriteAllText(
                                d.AnchorPath,
                                $"genesis_time: {genesisTime + 3600UL}
slot_duration_ms: {secondsPerSlot * 1000}
slots_per_epoch: {slotsPerEpoch}
"
                            )

                            FloorImport.run
                                config
                                [ clientOf 0 node ]
                                d
                                h.Time
                                prompt
                                [ pubkeyOf 0 ]
                                []
                                CancellationToken.None)

                    match r with
                    | Ok _ -> failtest "the node is on another genesis than the data dir"
                    | Error e -> Expect.stringContains e "the data dir" "names the data dir"

                    Expect.isFalse (File.Exists(Path.Combine(config.DataDir, "slashing.db"))) "no record written"
                })

            testT "the floor follows the clock while the operator answers" (fun () ->
                task {
                    let h = harness ()
                    let config = importConfig ()
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    h.Time.Advance(TimeSpan.FromSeconds(float (2 * slotsPerEpoch * secondsPerSlot)))
                    let asked = ResizeArray<string>()
                    // The operator shuts down the old machine first: 5 epochs pass before the answer.
                    let prompt: FloorImport.Prompt =
                        {
                            Interactive = true
                            Ask =
                                fun q ->
                                    asked.Add q
                                    h.Time.Advance(TimeSpan.FromSeconds(float (5 * slotsPerEpoch * secondsPerSlot)))
                                    ValueSome "y"
                            Say = ignore
                        }

                    let! r =
                        withDataDir config (fun d ->
                            FloorImport.run
                                config
                                [ clientOf 0 node ]
                                d
                                h.Time
                                prompt
                                [ pubkeyOf 0 ]
                                []
                                CancellationToken.None)

                    match r with
                    | Error e -> failtest e
                    | Ok o ->
                        Expect.equal o.Floored [ pubkeyOf 0 ] "answered y"
                        Expect.equal o.FloorEpoch 7UL "E read again after the answer"

                    Expect.stringContains
                        asked[0]
                        "epoch 3 or later"
                        "the question names the floor at the time of asking"

                    use db = openDb (Path.Combine(config.DataDir, "slashing.db"))

                    Expect.equal
                        (db.Marks(pubkeyOf 0))
                        (ValueSome(Floor.marks spe 7UL))
                        "the floor written is the later one"
                })

            testT "a syncing or optimistic node's statuses do not count" (fun () ->
                task {
                    let h = harness ()
                    let config = importConfig ()
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    // The node does not know the key yet: it is still syncing.
                    node.Sync <- { node.Sync with IsSyncing = true }
                    let prompt, asked, said = terminal true [ "n" ]

                    let! r =
                        withDataDir config (fun d ->
                            FloorImport.run
                                config
                                [ clientOf 0 node ]
                                d
                                h.Time
                                prompt
                                [ pubkeyOf 0 ]
                                []
                                CancellationToken.None)

                    match r with
                    | Error e -> failtest e
                    | Ok o -> Expect.equal o.Declined [ pubkeyOf 0 ] "asked, answered n"

                    Expect.isTrue (asked[0].Contains "status unknown") "asked as unknown"
                    Expect.isTrue (said |> Seq.exists (fun s -> s.Contains "syncing or optimistic")) $"%A{said}"
                })

            test "a keystore already in the data dir with no record gets its floor, without a new copy" {
                let h = harness ()
                let config = importConfig ()
                let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                let src = tempDir ()

                for i in 0..1 do
                    File.WriteAllText(
                        Path.Combine(src, $"v{i}.json"),
                        Keystore.encrypt (secretOf i) "pw" (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) ""
                    )

                    File.WriteAllText(Path.Combine(src, $"v{i}.txt"), "pw")

                let source: KeystoreSource =
                    {
                        Path = src
                        PasswordFile = ValueNone
                        Layout = ValueNone
                    }

                let prompt, _, _ = terminal false []

                let r =
                    withDataDir config (fun d ->
                        // A plain import first (a keymanager import writes the same file): the keys
                        // are in the data dir with no record.
                        match ImportKeys.run d.Path source 2 with
                        | Error e -> failtest e
                        | Ok r -> Expect.equal r.Imported.Length 2 "plain import"
                        // Key 1 got history meanwhile; it keeps it and gets no floor.
                        closing (openDb d.SlashingDbPath) (fun db ->
                            db.RegisterKeys [ pubkeyOf 1, KeyOrigin.Imported ] |> ignore)

                        let choose keys present =
                            (FloorImport.run
                                config
                                [ clientOf 0 node ]
                                d
                                h.Time
                                prompt
                                keys
                                present
                                CancellationToken.None)
                                .GetAwaiter()
                                .GetResult()
                            |> Result.map (fun o -> o.Floored)

                        ImportKeys.runWith d.Path source 2 choose)

                match r with
                | Error e -> failtest e
                | Ok r ->
                    Expect.isEmpty r.Imported "no new copy"
                    Expect.equal r.Present [ pubkeyOf 0 ] "the key with no record got a floor"

                use db = openDb (Path.Combine(config.DataDir, "slashing.db"))
                Expect.equal (db.Origin(pubkeyOf 0)) (ValueSome KeyOrigin.Floor) "floor"
                Expect.equal (db.Marks(pubkeyOf 1)) (ValueSome KeyMarks.Empty) "the key with history is left alone"
            }

            test "an interchange entry with no signed block or attestation gives a new key no record" {
                use db = openDb (Path.Combine(tempDir (), "s.db"))
                db.RegisterKeys [ pubkeyOf 2, KeyOrigin.Imported ] |> ignore

                let entry i blocks : InterchangeEntry =
                    {
                        PubKey = pubkeyOf i
                        SignedBlocks = blocks
                        SignedAttestations = []
                    }

                let x =
                    {
                        GenesisValidatorsRoot = gvr
                        Data =
                            [
                                entry 0 []
                                entry 1 [ { Slot = 5UL; SigningRoot = ValueNone } ]
                                entry 2 []
                                entry 3 []
                                entry 3 [ { Slot = 6UL; SigningRoot = ValueNone } ]
                            ]
                    }

                match db.Import x with
                | Error e -> failtest e
                | Ok r ->
                    Expect.equal r.NoHistory [ pubkeyOf 0 ] "only the new key with no marks at all"
                    Expect.equal r.Entries 5 "entries"

                Expect.isFalse (db.HasRecord(pubkeyOf 0)) "no record: the key stays discovered"

                Expect.isTrue
                    (db.HasRecord(pubkeyOf 1) && db.HasRecord(pubkeyOf 2) && db.HasRecord(pubkeyOf 3))
                    "the others"

                Expect.equal (verdicts db [ att 0 0UL 1UL ]) [ Verdict.NoRecord ] "nothing signs"
            }

            test "import: only the keys the floor step returns are copied; its error copies none" {
                let src = tempDir ()

                for i in 0..2 do
                    File.WriteAllText(
                        Path.Combine(src, $"v{i}.json"),
                        Keystore.encrypt (secretOf i) "pw" (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) ""
                    )

                    File.WriteAllText(Path.Combine(src, $"v{i}.txt"), "pw")

                let source: KeystoreSource =
                    {
                        Path = src
                        PasswordFile = ValueNone
                        Layout = ValueNone
                    }

                let data = tempDir ()

                match ImportKeys.runWith data source 2 (fun _ _ -> Error "no") with
                | Ok _ -> failtest "the error stops the import"
                | Error e -> Expect.equal e "no" "error"

                Expect.isFalse (File.Exists(LocalModule.ManagedStore.keystoreFile data (pubkeyOf 0))) "nothing copied"

                match
                    ImportKeys.runWith data source 2 (fun keys _ -> Ok(keys |> List.filter (fun k -> k <> pubkeyOf 1)))
                with
                | Error e -> failtest e
                | Ok r ->
                    Expect.equal (Set.ofList r.Imported) (set [ pubkeyOf 0; pubkeyOf 2 ]) "copied"
                    Expect.equal r.Skipped [ pubkeyOf 1 ] "left out"
                    Expect.isFalse (File.Exists(LocalModule.ManagedStore.keystoreFile data (pubkeyOf 1))) "not copied"
            }

            testT "lost setup: a node that hands over a source from before the loss gets nothing signed" (fun () ->
                task {
                    let h = harness ()
                    addValidators [ h.Node ] 1
                    // Keys made again from the mnemonic, imported with --no-signing-history in epoch 3.
                    let e = 3UL
                    let dbPath = Path.Combine(tempDir (), "s.db")

                    closing (openDb dbPath) (fun db ->
                        Expect.isOk (Floor.write db ValueNone spe e KeyOrigin.Floor [ pubkeyOf 0 ]) "floor")
                    // In epoch E + 2 a node that is behind or lies hands over the old VC's source.
                    let first = (e + 2UL) * spe

                    h.Node.OverrideData(
                        Some(fun slot ->
                            let d = h.Node.DefaultData slot in

                            { d with
                                Source = { d.Source with Epoch = e - 1UL }
                            })
                    )

                    advanceTo h (h.Clock.SlotStart first + TimeSpan.FromMilliseconds 100.0)

                    let vc =
                        startVc
                            h
                            { defaults with
                                Keys = [ 0 ]
                                DbPath = Some dbPath
                            }

                    do! h.RunSlots(first, first + spe - 1UL)
                    Expect.equal h.Node.Submissions.Count 0 $"nothing signed with the old source; log:\n{vc.Log}"

                    Expect.equal
                        ((vc.Db.Marks(pubkeyOf 0)).Value.Attestation)
                        (Floor.marks spe e).Attestation
                        "the floor holds"
                    // Honest data in epoch E + 3: source E + 2, target E + 3, above the floor.
                    h.Node.OverrideData None
                    do! h.RunSlots(first + spe, first + 2UL * spe - 1UL)
                    do! vc.Stop()
                    Expect.isGreaterThan h.Node.Submissions.Count 0 "signs above the floor"

                    Expect.equal
                        ((vc.Db.Marks(pubkeyOf 0)).Value.Attestation.Value.Target)
                        (e + 3UL)
                        "the vote above the floor"
                })
        ]
