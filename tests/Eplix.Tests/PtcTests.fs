/// One mark per slot for PTC votes and envelopes (slot-marks.db), and agreement of several
/// beacon nodes on PTC data (ptc_consensus_threshold).
module Eplix.Tests.PtcTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.SlashingTests

let private chain = root 77
let private key n = PubKey.Of(Array.init 48 (fun i -> if i = 0 then byte (n + 1) else 0xC0uy))

let private openMarks (file: IMarkFile) =
    match SlotMarks.Open(file, chain) with
    | Ok m -> m
    | Error e -> failwith e

let private ptc k slot r =
    {
        Key = key k
        Kind = SlotMarkKind.PayloadAttestation
        Slot = uint64 slot
        SigningRoot = r
    }

let private env k slot r =
    {
        Key = key k
        Kind = SlotMarkKind.PayloadEnvelope
        Slot = uint64 slot
        SigningRoot = r
    }

let private mark (m: SlotMarks) reqs = m.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result

// ---- Crash model: a stream of marks, restarts and snapshots ----

type SlotOp =
    | Mark of key: int * envelope: bool * slot: int * rootTag: int
    | Reopen
    | Snapshot

/// Runs a stream; the op at `crashOp` crashes at its file operation `crashAt`, keeping `keep`
/// bytes of the unsynced tail. Checks after each op: no two roots signed for one key, kind and
/// slot, and marks never go down.
let private runSlotStream (ops: SlotOp list) (crashOp: int) (crashKind: CrashPoint) (crashAt: int) (keep: int) =
    let mutable file = new ModelFile([||])
    let mutable marks = openMarks file
    let sent = Collections.Generic.HashSet<struct (int * bool * uint64 * Root)>()

    let reopen (bytes: byte[]) =
        file <- new ModelFile(bytes)
        marks <- openMarks file

    let snapshot () = [ for k in 0..2 -> marks.Marks(key k) ]

    ops
    |> List.iteri (fun i op ->
        let before = snapshot ()

        if i = crashOp then
            file.CrashAt <- file.Ops + crashAt
            file.CrashKind <- crashKind

        try
            match op with
            | Mark(k, isEnv, slot, tag) ->
                let r = root (2000 + tag)
                let req = if isEnv then env k slot r else ptc k slot r

                match (mark marks [ req ])[0] with
                | Verdict.Allowed
                | Verdict.Repeat ->
                    let clash =
                        sent
                        |> Seq.exists (fun struct (k', e', s', r') ->
                            k' = k && e' = isEnv && s' = uint64 slot && r' <> r)

                    if clash then
                        failwithf "allowed a second root at slot %d (op %d)" slot i

                    sent.Add(struct (k, isEnv, uint64 slot, r)) |> ignore
                | Verdict.WriteFailed _ -> raise Crash
                | _ -> ()
            | Reopen -> reopen ((file :> IMarkFile).ReadAll())
            | Snapshot ->
                match marks.Compact() with
                | Ok() -> ()
                | Error _ -> raise Crash
        with Crash ->
            reopen (file.AfterCrash keep)

        file.CrashAt <- -1

        List.zip before (snapshot ())
        |> List.iteri (fun k (b, a) ->
            match b, a with
            | ValueSome b, ValueSome a ->
                let up (x: BlockMark voption) (y: BlockMark voption) =
                    match x, y with
                    | ValueSome x, ValueSome y -> y.Slot >= x.Slot
                    | ValueSome _, ValueNone -> false
                    | ValueNone, _ -> true

                if not (up b.PayloadAttestation a.PayloadAttestation && up b.PayloadEnvelope a.PayloadEnvelope) then
                    failwithf "marks of key %d went down at op %d" k i
            | ValueSome _, ValueNone -> failwithf "key %d lost its record at op %d" k i
            | _ -> ()))

let private sampleSlotStream =
    [
        Mark(0, false, 3, 0)
        Mark(1, false, 3, 0)
        Mark(0, true, 3, 0)
        Mark(0, false, 3, 0) // repeat
        Mark(0, false, 3, 1) // second vote: refused
        Mark(0, false, 2, 0) // below the mark: refused
        Reopen
        Mark(0, false, 3, 1) // still refused after a restart
        Mark(0, false, 4, 1)
        Snapshot
        Mark(2, true, 1, 2)
        Mark(2, true, 1, 1)
        Reopen
        Mark(2, true, 1, 1)
        Mark(1, false, 5, 2)
    ]

let private genSlotOp =
    Gen.frequency
        [
            8,
            Gen.map4
                (fun k e s tag -> Mark(k, e, s, tag))
                (Gen.choose (0, 2))
                (Gen.elements [ false; true ])
                (Gen.choose (0, 8))
                (Gen.choose (0, 2))
            1, Gen.constant Reopen
            1, Gen.constant Snapshot
        ]

// ---- Gloas harness bits for the pipeline and the node set ----

let private gloasSpec () =
    match ChainSpec.parse (Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch 1UL)) with
    | Ok s -> s
    | Error e -> failwith e

let private nodeSet (count: int) (ptcThreshold: int) =
    let fakes =
        [
            for _ in 1..count -> new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
        ]

    let clients =
        fakes
        |> List.mapi (fun i n ->
            BeaconClient(new HttpClient(n, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

    fakes, BeaconNodes(clients, 1, TimeProvider.System, Log.none, ptcThreshold)

let private ptcCalls (n: FakeBeaconNode) =
    n.Requests |> Seq.filter (fun r -> r.EndsWith "/payload_attestation_data") |> Seq.length

let private soon (ms: float) = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds ms

[<Tests>]
let tests =
    testList
        "ptc"
        [
            test "rules: repeat allowed, another root or a lower slot refused, kinds apart" {
                let m =
                    SlotMarkRules.merge
                        SlotKeyMarks.Empty
                        SlotMarkKind.PayloadAttestation
                        { Slot = 5UL; Root = ValueSome(root 1) }

                let check = SlotMarkRules.check m SlotMarkKind.PayloadAttestation
                Expect.equal (check 5UL (root 1)) Check.Repeat "exact repeat"

                Expect.isTrue
                    (match check 5UL (root 2) with
                     | Check.Refuse _ -> true
                     | _ -> false)
                    "another root at the mark"

                Expect.isTrue
                    (match check 4UL (root 1) with
                     | Check.Refuse _ -> true
                     | _ -> false)
                    "below the mark"

                Expect.equal (check 6UL (root 2)) Check.Allow "above the mark"

                Expect.equal
                    (SlotMarkRules.check m SlotMarkKind.PayloadEnvelope 5UL (root 2))
                    Check.Allow
                    "the envelope mark is its own"

                let merged =
                    SlotMarkRules.merge m SlotMarkKind.PayloadAttestation { Slot = 5UL; Root = ValueSome(root 2) }

                Expect.isTrue
                    (match SlotMarkRules.check merged SlotMarkKind.PayloadAttestation 5UL (root 1) with
                     | Check.Refuse _ -> true
                     | _ -> false)
                    "two roots merged: no repeat"
            }

            testProp "a mark never allows a second root at a slot or a slot below an earlier vote"
            <| fun (votes: (byte * bool) list) ->
                let m = openMarks (new ModelFile([||]))
                let mutable signed = Map.empty<uint64, Root>

                for s, t in votes do
                    let r = root (if t then 1 else 2)

                    match (mark m [ ptc 0 (int s) r ])[0] with
                    | Verdict.Allowed
                    | Verdict.Repeat ->
                        match signed.TryFind(uint64 s) with
                        | Some prev when prev <> r -> failwithf "two roots at slot %d" s
                        | _ -> ()

                        if signed |> Map.exists (fun slot _ -> slot > uint64 s) then
                            failwithf "slot %d below an earlier vote" s

                        signed <- signed.Add(uint64 s, r)
                    | Verdict.Refused _ -> ()
                    | v -> failwithf "unexpected %A" v

            test "a key without a record gets one with its first mark" {
                let m = openMarks (new ModelFile([||]))
                Expect.equal (mark m [ ptc 0 7 (root 1) ]) [| Verdict.Allowed |] "no history needed"
                Expect.equal m.KeyCount 1 "record created"

                Expect.equal
                    (m.Marks(key 0)).Value.PayloadAttestation
                    (ValueSome { Slot = 7UL; Root = ValueSome(root 1) })
                    "mark"

                Expect.equal
                    (mark m [ ptc 0 7 (root 1); ptc 0 7 (root 2); env 0 7 (root 3) ])
                    [|
                        Verdict.Repeat
                        Verdict.Refused "a different PTC vote at slot 7 was signed before"
                        Verdict.Allowed
                    |]
                    "repeat, second vote, envelope"
            }

            test "one append and one fsync per burst" {
                let file = new ModelFile([||])
                let m = openMarks file
                let before = file.Syncs
                let burst = [ for k in 0..99 -> ptc k 3 (root 9) ]
                Expect.allEqual (mark m burst) Verdict.Allowed "all allowed"
                Expect.equal (file.Syncs - before) 1 "one fsync for 100 new keys and votes"
                Expect.allEqual (mark m burst) Verdict.Repeat "repeats"
                Expect.equal (file.Syncs - before) 1 "repeats write nothing"
            }

            test "torn tail cut, a bad middle record is corruption, other chain and other store refused" {
                let file = new ModelFile([||])
                let m = openMarks file
                mark m [ ptc 0 1 (root 1) ] |> ignore
                mark m [ ptc 0 2 (root 2) ] |> ignore
                let bytes = (file :> IMarkFile).ReadAll()
                let m2 = openMarks (new ModelFile(Array.append bytes (Array.create 40 0x11uy)))
                Expect.equal m2.OpenInfo.TruncatedBytes 40L "cut 40 bytes"
                Expect.equal (m2.Marks(key 0)).Value.PayloadAttestation.Value.Slot 2UL "marks kept"
                let bad = Array.copy bytes
                bad[2 * Record.size + 10] <- bad[2 * Record.size + 10] ^^^ 0xFFuy
                Expect.isError (SlotMarks.Open(new ModelFile(bad), chain)) "corrupt"
                Expect.isError (SlotMarks.Open(new ModelFile(bytes), root 78)) "other chain"
                // Neither store opens the file of the other.
                Expect.isError (SlashingDb.Open(new ModelFile(bytes), chain)) "slashing DB refuses slot-marks.db"
                let dbFile = new ModelFile([||])
                SlashingDb.Open(dbFile, chain) |> ignore

                Expect.isError
                    (SlotMarks.Open(new ModelFile((dbFile :> IMarkFile).ReadAll()), chain))
                    "slot marks refuse slashing.db"
            }

            test "real file: write, reopen keeps marks, snapshot shrinks the log" {
                let path = Path.Combine(tempDir (), "slot-marks.db")

                let write () =
                    use m = openMarks (new FileMarkFile(path))

                    for s in 1..20 do
                        mark m [ ptc 0 s (root s); env 1 s (root s) ] |> ignore

                write ()
                Expect.equal (FileInfo(path).Length) (int64 (43 * Record.size)) "header, 2 keys, 40 marks"

                let reopen () =
                    use m = openMarks (new FileMarkFile(path))
                    Expect.equal (m.Marks(key 0)).Value.PayloadAttestation.Value.Slot 20UL "replayed"

                    Expect.equal
                        (mark m [ ptc 0 20 (root 21) ])
                        [| Verdict.Refused "a different PTC vote at slot 20 was signed before" |]
                        "refused after reopen"

                    Expect.isOk (m.Compact()) "snapshot"

                reopen ()
                Expect.equal (FileInfo(path).Length) (int64 (5 * Record.size)) "header, 2 keys, 2 marks"
                use m = openMarks (new FileMarkFile(path))

                Expect.equal
                    (mark m [ ptc 0 20 (root 20); env 1 20 (root 20) ])
                    [| Verdict.Repeat; Verdict.Repeat |]
                    "repeat after the snapshot"
            }

            test "the slot stream runs clean without crashes" {
                runSlotStream sampleSlotStream -1 CrashPoint.BeforeAppend 0 0
            }

            test "crash at each write step of each op" {
                let keeps = [ 0; 1; 40; 79; 80; 81; 159; 160; 10_000 ]

                for i in 0 .. sampleSlotStream.Length - 1 do
                    for kind in [ CrashPoint.BeforeAppend; CrashPoint.BeforeSync; CrashPoint.BeforeReplace ] do
                        for at in 1..2 do
                            for keep in keeps do
                                try
                                    runSlotStream sampleSlotStream i kind at keep
                                with e ->
                                    failtestf "op %d, %A at step %d, keep %d: %s" i kind at keep e.Message
            }

            testPropN "random slot streams with a random crash" 300
            <| Prop.forAll
                (Arb.fromGen (
                    Gen.zip3
                        (Gen.listOfLength 25 genSlotOp)
                        (Gen.choose (0, 24))
                        (Gen.zip3
                            (Gen.elements [ CrashPoint.BeforeAppend; CrashPoint.BeforeSync; CrashPoint.BeforeReplace ])
                            (Gen.choose (1, 2))
                            (Gen.choose (0, 400)))
                ))
                (fun (ops, crashOp, (kind, at, keep)) -> runSlotStream ops crashOp kind at keep)

            testT
                "pipeline: a second PTC vote for a slot is skipped, the key keeps signing, slashing.db untouched"
                (fun () ->
                    task {
                        let spec = gloasSpec ()
                        let dbFile = new ModelFile([||])

                        let db =
                            match SlashingDb.Open(dbFile, gvr) with
                            | Ok d -> d
                            | Error e -> failwith e

                        db.RegisterKeys [ pubkeyOf 0, KeyOrigin.StartedEmpty ] |> ignore
                        let marksFile = new ModelFile([||])

                        let marks =
                            match SlotMarks.Open(marksFile, gvr) with
                            | Ok m -> m
                            | Error e -> failwith e

                        let registry = KeyRegistry()

                        let backend =
                            LocalBackend.create "local" [ pubkeyOf 0, SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                        registry.Add(pubkeyOf 0, backend) |> ignore
                        registry.SetState(pubkeyOf 0, KeyState.Active)
                        let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none, marks)
                        let req duty = Duty.request spec gvr (pubkeyOf 0) Priority.High DateTimeOffset.MaxValue duty

                        let data present =
                            {
                                BeaconBlockRoot = root 5
                                Slot = 9UL
                                PayloadPresent = present
                                BlobDataAvailable = true
                            }

                        let dbBefore = (dbFile :> IMarkFile).ReadAll()
                        let! first = pipeline.Sign(req (Duty.PayloadAttestation(data true)), CancellationToken.None)

                        Expect.isTrue
                            (match first with
                             | Signed _ -> true
                             | _ -> false)
                            "first vote signed"

                        let! again = pipeline.Sign(req (Duty.PayloadAttestation(data true)), CancellationToken.None)

                        Expect.isTrue
                            (match again with
                             | Signed _ -> true
                             | _ -> false)
                            "exact repeat signed"

                        let! second = pipeline.Sign(req (Duty.PayloadAttestation(data false)), CancellationToken.None)

                        Expect.isTrue
                            (match second with
                             | Refused(Slashable _) -> true
                             | _ -> false)
                            "second vote refused"

                        Expect.equal (Metrics.missReason second) Metrics.Reason.SlashingProtection "miss reason"
                        Expect.equal (registry.TryGet(pubkeyOf 0)).Value.State KeyState.Active "the key is not halted"

                        let env =
                            {
                                Schema = Schemas.Gloas.executionPayloadEnvelope Preset.Minimal
                                Value = Ssz.zero (Schemas.Gloas.executionPayloadEnvelope Preset.Minimal)
                            }

                        let! e = pipeline.Sign(req (Duty.PayloadEnvelope(9UL, env)), CancellationToken.None)

                        Expect.isTrue
                            (match e with
                             | Signed _ -> true
                             | _ -> false)
                            "envelope signed"

                        let! next =
                            pipeline.Sign(
                                req (Duty.PayloadAttestation { data false with Slot = 10UL }),
                                CancellationToken.None
                            )

                        Expect.isTrue
                            (match next with
                             | Signed _ -> true
                             | _ -> false)
                            "next slot signed"

                        Expect.equal
                            ((dbFile :> IMarkFile).ReadAll())
                            dbBefore
                            "slashing.db unchanged by PTC votes and envelopes"

                        Expect.equal (marks.Marks(pubkeyOf 0)).Value.PayloadAttestation.Value.Slot 10UL "PTC mark"
                        Expect.equal (marks.Marks(pubkeyOf 0)).Value.PayloadEnvelope.Value.Slot 9UL "envelope mark"
                        let syncs = marksFile.Syncs

                        let reqs =
                            Duty.requests
                                spec
                                gvr
                                [| pubkeyOf 0 |]
                                Priority.High
                                DateTimeOffset.MaxValue
                                (Duty.PayloadAttestation { data true with Slot = 11UL })

                        let! _ = pipeline.SignBurst(reqs, CancellationToken.None)
                        Expect.equal (marksFile.Syncs - syncs) 1 "one fsync per burst"
                    })

            testT "PTC data: two of three nodes agree, the third differs" (fun () ->
                task {
                    let fakes, nodes = nodeSet 3 2
                    fakes[2].PayloadPresent <- false
                    let! d = nodes.PayloadAttestationData(9UL, soon 2000.0, CancellationToken.None)

                    match d with
                    | Ok(ValueSome x) ->
                        Expect.isTrue x.PayloadPresent "the data of the two"
                        Expect.equal x.Slot 9UL "slot"
                    | other -> failtestf "expected data, got %A" other

                    fakes[1].PayloadPresent <- false
                    let! d2 = nodes.PayloadAttestationData(9UL, soon 2000.0, CancellationToken.None)

                    Expect.isTrue
                        (match d2 with
                         | Ok(ValueSome x) -> not x.PayloadPresent
                         | _ -> false)
                        "the view of the two others"
                })

            testT "PTC data: 204 answers count as no data and never as a vote" (fun () ->
                task {
                    let fakes, nodes = nodeSet 3 2

                    for f in fakes do
                        f.NoBlockSlots <- Set.ofList [ 9UL ]

                    let! none = nodes.PayloadAttestationData(9UL, soon 200.0, CancellationToken.None)
                    Expect.equal none (Ok ValueNone) "every node saw no block"
                    fakes[0].NoBlockSlots <- Set.empty
                    let! one = nodes.PayloadAttestationData(9UL, soon 200.0, CancellationToken.None)
                    Expect.equal one (Ok ValueNone) "one node with data: no vote"
                    fakes[1].NoBlockSlots <- Set.empty
                    let! two = nodes.PayloadAttestationData(9UL, soon 2000.0, CancellationToken.None)

                    Expect.isTrue
                        (match two with
                         | Ok(ValueSome _) -> true
                         | _ -> false)
                        "two agree on data"
                })

            testT "PTC data: no agreement by the deadline is an error" (fun () ->
                task {
                    let fakes, nodes = nodeSet 3 3
                    fakes[2].PayloadPresent <- false
                    let! d = nodes.PayloadAttestationData(9UL, soon 200.0, CancellationToken.None)
                    Expect.isError d "three must agree"

                    let! late =
                        nodes.PayloadAttestationData(
                            9UL,
                            DateTimeOffset.UtcNow - TimeSpan.FromSeconds 1.0,
                            CancellationToken.None
                        )

                    Expect.isError late "deadline passed"
                })

            testT "PTC data with threshold 1: one call to the best node, no polling" (fun () ->
                task {
                    let fakes, nodes = nodeSet 3 1
                    let! d = nodes.PayloadAttestationData(9UL, soon 2000.0, CancellationToken.None)

                    Expect.isTrue
                        (match d with
                         | Ok(ValueSome _) -> true
                         | _ -> false)
                        "data"

                    Expect.equal (fakes |> List.map ptcCalls) [ 1; 0; 0 ] "one call"
                    fakes[0].Fail <- fun p -> p.Contains "payload_attestation_data"
                    let! d2 = nodes.PayloadAttestationData(9UL, soon 2000.0, CancellationToken.None)

                    Expect.isTrue
                        (match d2 with
                         | Ok(ValueSome _) -> true
                         | _ -> false)
                        "fallback to the next node"

                    Expect.equal (ptcCalls fakes[1]) 1 "the second node answered"
                    Expect.throws (fun () -> nodeSet 2 0 |> ignore) "threshold 0"
                    Expect.throws (fun () -> nodeSet 2 3 |> ignore) "threshold above the node count"
                })

            test "config: ptc_consensus_threshold" {
                let parse extra =
                    Config.parse
                        ("""{ "beacon_nodes": ["http://a:1", "http://b:2", "http://c:3"], "chain_config": "c.yaml", "data_dir": "d" """
                         + extra
                         + " }")
                        "/tmp"
                        []

                match parse "" with
                | Ok c -> Expect.equal c.PtcConsensusThreshold 1 "default 1"
                | Error es -> failtestf "%A" es

                match parse """, "ptc_consensus_threshold": 2""" with
                | Ok c -> Expect.equal c.PtcConsensusThreshold 2 "set"
                | Error es -> failtestf "%A" es

                Expect.isError (parse """, "ptc_consensus_threshold": 0""") "zero"
                Expect.isError (parse """, "ptc_consensus_threshold": 4""") "above the node count"
            }
        ]
