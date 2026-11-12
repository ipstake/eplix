/// Stop on an on-chain slashing of an own key.
module Eplix.Tests.SlashedOnChainTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

type private Setup =
    {
        H: Harness
        Others: FakeBeaconNode list
        Registry: KeyRegistry
        Nodes: BeaconNodes
        Db: SlashingDb
        Dir: string
        Lines: Collections.Concurrent.ConcurrentQueue<string>
        Log: Log
    }

    member s.Store() =
        let st = SlashedKeys(s.Dir)

        match st.Load() with
        | Ok _ -> st
        | Error e -> failtest e

    member s.Refresh(store: SlashedKeys) =
        task {
            let! r =
                refreshEmpty
                    (ValueSome(store, s.H.Time :> TimeProvider))
                    s.Nodes
                    s.Registry
                    s.Db
                    s.Log
                    CancellationToken.None

            Expect.isOk r "refresh"
        }

    member s.State(i: int) = (s.Registry.TryGet(pubkeyOf i)).Value.State

let private isSlashed (s: KeyState) =
    match s with
    | KeyState.Slashed _ -> true
    | _ -> false

/// `nodes` fake nodes with the same validators; the first is the harness's.
let private setup (keys: int list) (nodes: int) (threshold: int) (dir: string) =
    let h = harness ()

    let others =
        [
            for _ in 2..nodes -> new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
        ]

    for n in h.Node :: others do
        for i in keys do
            n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

    let clients =
        (h.Node :: others)
        |> List.mapi (fun i n ->
            BeaconClient(new HttpClient(n, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

    let beacon = BeaconNodes(clients, threshold, h.Time, Log.none)

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(dir, "slashing.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let registry = KeyRegistry()

    let backend =
        LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    for i in keys do
        registry.Add(pubkeyOf i, backend) |> ignore

    let log, lines = Log.memory ()

    {
        H = h
        Others = others
        Registry = registry
        Nodes = beacon
        Db = db
        Dir = dir
        Lines = lines
        Log = log
    }

let private attesterSlashing (a: uint64 list) (b: uint64 list) =
    let att (xs: uint64 list) =
        let ids = String.Join(",", xs |> List.map (fun x -> $"\"{x}\""))
        $$"""{ "attesting_indices": [{{ids}}], "data": {}, "signature": "0x00" }"""

    $$"""{ "attestation_1": {{att a}}, "attestation_2": {{att b}} }"""

let private proposerSlashing (i: uint64) =
    $$"""{ "signed_header_1": { "message": { "slot": "5", "proposer_index": "{{i}}" }, "signature": "0x00" },
           "signed_header_2": { "message": { "slot": "5", "proposer_index": "{{i}}" }, "signature": "0x00" } }"""

[<Tests>]
let tests =
    testList
        "slashed-on-chain"
        [
            test "the rule: threshold nodes, or every node that answered" {
                let d = OnChainSlashing.decide
                Expect.isTrue (d 1 [ ValueSome true ]) "one node, slashed"
                Expect.isFalse (d 1 [ ValueSome false ]) "one node, not slashed"
                Expect.isFalse (d 1 [ ValueNone ]) "no answer"
                Expect.isFalse (d 2 [ ValueSome true; ValueSome false ]) "disputed below the threshold"
                Expect.isTrue (d 2 [ ValueSome true; ValueSome true; ValueSome false ]) "threshold reached"
                Expect.isTrue (d 2 [ ValueSome true; ValueNone; ValueNone ]) "the only answer"
                Expect.isTrue (d 1 [ ValueSome true; ValueSome false ]) "threshold 1"
            }

            testProp
                "the rule never stops a key that no node reports slashed, and always stops one every answering node reports"
                (fun (answers: bool option list) (t: FsCheck.PositiveInt) ->
                    let xs =
                        answers
                        |> List.map (fun a ->
                            match a with
                            | Some b -> ValueSome b
                            | None -> ValueNone)

                    let yes = answers |> List.filter (fun a -> a = Some true) |> List.length
                    let said = answers |> List.filter Option.isSome |> List.length
                    let r = OnChainSlashing.decide t.Get xs
                    (yes = 0 && not r) || (yes > 0 && yes = said && r) || (yes > 0 && yes < said && r = (yes >= t.Get)))

            test "slashing events name the indices a slashing hits" {
                Expect.equal
                    (OnChainSlashing.eventIndices
                        "attester_slashing"
                        (attesterSlashing [ 1UL; 2UL; 3UL ] [ 2UL; 3UL; 4UL ]))
                    [ 2UL; 3UL ]
                    "intersection"

                Expect.equal
                    (OnChainSlashing.eventIndices "proposer_slashing" (proposerSlashing 7UL))
                    [ 7UL ]
                    "proposer"

                Expect.equal
                    (OnChainSlashing.eventIndices "proposer_slashing" $$"""{ "data": {{proposerSlashing 8UL}} }""")
                    [ 8UL ]
                    "wrapped in data"

                Expect.isEmpty (OnChainSlashing.eventIndices "attester_slashing" "{ not json") "junk"
                Expect.isEmpty (OnChainSlashing.eventIndices "head" (proposerSlashing 7UL)) "other topic"
            }

            testT "a key the chain shows slashed stops, and stays stopped after a restart" (fun () ->
                task {
                    let dir = tempDir ()
                    let s = setup [ 0; 1 ] 1 1 dir
                    s.H.Node.Slashed <- fun i -> i = 1UL
                    do! s.Refresh(s.Store())
                    Expect.equal (s.State 0) KeyState.Active "the other key signs"
                    Expect.isTrue (isSlashed (s.State 1)) "slashed key stopped"

                    Expect.isTrue
                        (s.Lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "slashed"))
                        "error logged"
                    // It signs nothing, an exit included.
                    let spec = s.H.Spec

                    let req kind =
                        Duty.request spec gvr (pubkeyOf 1) Priority.High (s.H.Time.GetUtcNow().AddSeconds 10.0) kind

                    let pipeline = Pipeline(s.Db, s.Registry, s.H.Time, Log.none)

                    for d in
                        [
                            Duty.RandaoReveal 1UL
                            Duty.VoluntaryExit { Epoch = 1UL; ValidatorIndex = 1UL }
                        ] do
                        let! o = pipeline.Sign(req d, CancellationToken.None)

                        Expect.isTrue
                            (match o with
                             | Refused _ -> true
                             | _ -> false)
                            $"refused: {o.Describe}"
                    // The state does not go back.
                    s.Registry.SetState(pubkeyOf 1, KeyState.Active)
                    Expect.isTrue (isSlashed (s.State 1)) "terminal"
                    // A restart against a node that no longer says so (not synced) keeps the stop.
                    let s2 = setup [ 0; 1 ] 1 1 dir
                    do! s2.Refresh(s2.Store())
                    Expect.isTrue (isSlashed (s2.State 1)) "kept across restarts"
                    Expect.equal (s2.State 0) KeyState.Active "the other key"
                })

            testT "one node out of two cannot stop a key at threshold 2; both can" (fun () ->
                task {
                    let s = setup [ 0 ] 2 2 (tempDir ())
                    s.H.Node.Slashed <- fun _ -> true
                    do! s.Refresh(s.Store())
                    Expect.equal (s.State 0) KeyState.Active "disputed"
                    s.Others.Head.Slashed <- fun _ -> true
                    do! s.Refresh(s.Store())
                    Expect.isTrue (isSlashed (s.State 0)) "both nodes"
                })

            testT "a slashing event starts a check of the named own keys" (fun () ->
                task {
                    let s = setup [ 0; 1; 2 ] 1 1 (tempDir ())
                    do! s.Refresh(s.Store())
                    let store = s.Store()

                    let x =
                        OnChainSlashing.extension
                            s.H.Spec
                            s.Nodes
                            s.Registry
                            store
                            s.Log
                            s.H.Time
                            CancellationToken.None

                    Expect.containsAll x.Topics [ "attester_slashing"; "proposer_slashing" ] "topics"
                    s.H.Node.Slashed <- fun i -> i = 2UL

                    x.OnEvent
                        {
                            Event = "attester_slashing"
                            Data = attesterSlashing [ 2UL; 9UL ] [ 2UL ]
                        }

                    let sw = Diagnostics.Stopwatch.StartNew()

                    while not (isSlashed (s.State 2)) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                        do! Task.Delay 10

                    Expect.isTrue (isSlashed (s.State 2)) "stopped after the event"
                    Expect.isTrue (store.Contains(pubkeyOf 2)) "recorded"
                    Expect.equal (s.State 0) KeyState.Active "others untouched"
                    // An event alone, without the chain showing it, stops nothing.
                    x.OnEvent
                        {
                            Event = "proposer_slashing"
                            Data = proposerSlashing 1UL
                        }

                    do! Task.Delay 200
                    Expect.equal (s.State 1) KeyState.Active "gossip alone"
                })

            test "a broken slashed-keys file fails the load" {
                let dir = tempDir ()
                File.WriteAllText(Path.Combine(dir, "slashed-keys.json"), """{ "keys": [ { "pubkey": "0x12" } ] }""")
                Expect.isError (SlashedKeys(dir).Load()) "bad key"
                File.WriteAllText(Path.Combine(dir, "slashed-keys.json"), """{ "keys": [], "x": 1 }""")
                Expect.isError (SlashedKeys(dir).Load()) "unknown field"
            }

            test "the file keeps what was added" {
                let dir = tempDir ()
                let st = SlashedKeys(dir)
                Expect.equal (st.Load()) (Ok 0) "no file"

                Expect.isOk
                    (st.Add
                        {
                            Key = pubkeyOf 3
                            Index = ValueSome 3UL
                            Since = "2026-10-25T00:00:00Z"
                            Reason = "r"
                        })
                    "add"

                let again = SlashedKeys(dir)
                Expect.equal (again.Load()) (Ok 1) "one key"
                Expect.equal (again.TryGet(pubkeyOf 3)).Value.Index (ValueSome 3UL) "index kept"
            }

            testT "a stop whose write failed stops the key at once and is written at the next refresh" (fun () ->
                task {
                    let dir = tempDir ()
                    let s = setup [ 0; 1 ] 1 1 dir
                    s.H.Node.Slashed <- fun i -> i = 1UL
                    // A directory where the temporary file goes makes the write fail.
                    let blocker = Path.Combine(dir, "slashed-keys.json.tmp")
                    Directory.CreateDirectory blocker |> ignore
                    let store = s.Store()
                    do! s.Refresh store
                    Expect.isTrue (isSlashed (s.State 1)) "stopped in this process"
                    Expect.isFalse (File.Exists(Path.Combine(dir, "slashed-keys.json"))) "not written"
                    Directory.Delete blocker
                    do! s.Refresh store
                    let again = SlashedKeys(dir)
                    Expect.equal (again.Load()) (Ok 1) "written at the next refresh"
                    Expect.isTrue (again.Contains(pubkeyOf 1)) "the stopped key"

                    Expect.isTrue
                        (s.Lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "could not record"))
                        "the failure is logged"
                })

            test "a key added again after a failed write is written" {
                let dir = tempDir ()
                let st = SlashedKeys(dir)
                let blocker = Path.Combine(dir, "slashed-keys.json.tmp")
                Directory.CreateDirectory blocker |> ignore

                let k =
                    {
                        Key = pubkeyOf 3
                        Index = ValueSome 3UL
                        Since = "2026-10-25T00:00:00Z"
                        Reason = "r"
                    }

                Expect.isError (st.Add k) "the write fails"
                Expect.isTrue (st.Contains(pubkeyOf 3)) "kept in memory"
                Directory.Delete blocker
                Expect.isOk (st.Add k) "written now"
                Expect.equal (SlashedKeys(dir).Load()) (Ok 1) "on disk"
            }
        ]
