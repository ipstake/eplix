/// When a key may start: only with a slashing record, never from beacon node data; the override writes a floor record; and no key goes active before every
/// module has started, so the doppelganger hold is in place first.
module Eplix.Tests.KeyActivationTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Doppelganger
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

/// Key 0 on `count` fake nodes with the given statuses (None: the node does not know the key),
/// a registry with the key and an empty slashing DB. Every node passed the start checks.
let private nodesWith (statuses: string option list) (threshold: int) =
    let h = harness ()

    let fakes =
        statuses |> List.map (fun _ -> new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch))

    for node, status in List.zip fakes statuses do
        status |> Option.iter (fun st -> node.AddValidator(pubkeyOf 0, st) |> ignore)

    let clients =
        fakes
        |> List.mapi (fun i node ->
            BeaconClient(new HttpClient(node, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

    let nodes = BeaconNodes(clients, threshold, h.Time, Log.none)

    for c in clients do
        nodes.MarkReady c

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let registry = KeyRegistry()

    registry.Add(pubkeyOf 0, LocalBackend.create "local" [ pubkeyOf 0, SecretKey.Copy(ReadOnlySpan(secretOf 0)) ])
    |> ignore

    h, fakes, nodes, registry, db

let private refreshAs
    (floor: FloorSource)
    (allow: AllowStartWithoutHistory)
    (log: Log)
    (nodes: BeaconNodes)
    (registry: KeyRegistry)
    (db: SlashingDb)
    =
    task {
        let! r = Validators.refresh floor nodes registry db allow log CancellationToken.None
        Expect.isOk r "refresh"
        return (registry.TryGet(pubkeyOf 0)).Value.State
    }

let private spe = uint64 slotsPerEpoch

/// A module that runs a key refresh during its start, as a keymanager import or a remote signer's
/// key refresh does, and notes each key's state right after it.
let private refreshingModule (seen: Collections.Concurrent.ConcurrentQueue<KeyState>) : Module =
    {
        Name = "probe"
        Configure = fun _ -> Ok()
        Check = fun _ -> Ok "probe"
        Start =
            fun core ct ->
                task {
                    do! core.RefreshKeys ct

                    for k in core.Registry.All do
                        seen.Enqueue k.State

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }

[<Tests>]
let tests =
    testList
        "key activation"
        [
            testT "no beacon node data starts a key: pending on every node, it waits with no record" (fun () ->
                task {
                    let _, _, nodes, registry, db = nodesWith [ Some "pending_queued"; Some "pending_initialized" ] 1
                    use _ = db
                    let log, lines = Log.memory ()
                    let! state = refreshAs testFloor AllowStartWithoutHistory.Nobody log nodes registry db
                    Expect.equal state KeyState.Discovered "a pending status does not start the key"
                    let! state = refreshAs testFloor AllowStartWithoutHistory.Nobody log nodes registry db
                    Expect.equal state KeyState.Discovered "nor a second look"
                    Expect.isFalse (db.HasRecord(pubkeyOf 0)) "no record"

                    let hints =
                        lines
                        |> Seq.filter (fun l -> l.Contains "looks new" && l.Contains "--no-signing-history")
                        |> List.ofSeq

                    Expect.equal hints.Length 2 $"one hint per refresh: %A{hints}"
                    Expect.isTrue (hints[0].StartsWith "WARN") "the first is a warning"
                    Expect.isFalse (hints[1].StartsWith "WARN") "the same hint again is not"
                })

            testT "an active key with no history waits, and the hint names the EIP-3076 file" (fun () ->
                task {
                    let _, _, nodes, registry, db = nodesWith [ Some "pending_queued"; Some "active_ongoing" ] 1
                    use _ = db
                    let log, lines = Log.memory ()
                    let! state = refreshAs testFloor AllowStartWithoutHistory.Nobody log nodes registry db
                    Expect.equal state KeyState.Discovered "no record, no start"
                    Expect.isFalse (db.HasRecord(pubkeyOf 0)) "nothing registered"

                    Expect.isTrue
                        (lines |> Seq.exists (fun l -> l.StartsWith "WARN" && l.Contains "no slashing history"))
                        "hint logged"
                })

            testT "the override writes a floor at the clock epoch, raised by a node's head" (fun () ->
                task {
                    // The clock is in epoch 3: a head in epoch 4 raises the floor, one further out is refused.
                    for head, expected in [ 0UL, 3UL; 4UL * spe + 2UL, 4UL ] do
                        let h, fakes, nodes, registry, db =
                            nodesWith [ Some "active_ongoing"; Some "active_ongoing" ] 1

                        use _ = db

                        use slotMarks =
                            match SlotMarks.Open(new FileMarkFile(Path.Combine(tempDir (), "m.db")), gvr) with
                            | Ok m -> m
                            | Error e -> failwith e

                        fakes[1].SyncHeadSlot <- head
                        // The clock in epoch 3.
                        h.Time.Advance(TimeSpan.FromSeconds(float (3 * slotsPerEpoch * secondsPerSlot)))

                        let floor =
                            {
                                Clock = h.Clock
                                SlotMarks = ValueSome slotMarks
                            }

                        let! state = refreshAs floor AllowStartWithoutHistory.All Log.none nodes registry db
                        Expect.equal state KeyState.Active $"head {head}: the key starts"
                        Expect.equal (db.Origin(pubkeyOf 0)) (ValueSome KeyOrigin.StartedEmpty) "origin: the override"

                        Expect.equal
                            (db.Marks(pubkeyOf 0))
                            (ValueSome(Floor.marks spe expected))
                            $"head {head}: a floor at E = {expected}, not an empty record"

                        let m = (slotMarks.Marks(pubkeyOf 0)).Value

                        Expect.equal
                            (m.PayloadAttestation |> ValueOption.map (fun b -> b.Slot))
                            (ValueSome(Floor.slot spe expected))
                            "PTC mark raised"

                        Expect.equal
                            (m.PayloadEnvelope |> ValueOption.map (fun b -> b.Slot))
                            (ValueSome(Floor.slot spe expected))
                            "envelope mark raised"
                })

            testT "the override writes no floor when a node's head is more than one epoch past the clock" (fun () ->
                task {
                    for head in [ 5UL * spe + 2UL; UInt64.MaxValue ] do
                        let h, fakes, nodes, registry, db =
                            nodesWith [ Some "active_ongoing"; Some "active_ongoing" ] 1

                        use _ = db
                        fakes[1].SyncHeadSlot <- head
                        // The clock in epoch 3.
                        h.Time.Advance(TimeSpan.FromSeconds(float (3 * slotsPerEpoch * secondsPerSlot)))

                        let floor =
                            {
                                Clock = h.Clock
                                SlotMarks = ValueNone
                            }

                        let log, lines = Log.memory ()
                        let! state = refreshAs floor AllowStartWithoutHistory.All log nodes registry db
                        Expect.equal state KeyState.Discovered $"head {head}: the key waits"
                        Expect.isFalse (db.HasRecord(pubkeyOf 0)) $"head {head}: no floor record"

                        Expect.isTrue
                            (lines
                             |> Seq.exists (fun l -> l.Contains "past the clock" || l.Contains "the clock in epoch"))
                            $"head {head}: the refusal is logged"
                })

            testT "a refusal while the override waits for the floor epoch keeps the key out" (fun () ->
                task {
                    let _, fakes, nodes, registry, db = nodesWith [ Some "active_ongoing" ] 1
                    use _ = db
                    let entered = TaskCompletionSource()
                    let gate = TaskCompletionSource()

                    fakes[0].Delay <-
                        fun path ->
                            if path.Contains "syncing" then
                                entered.TrySetResult() |> ignore
                                gate.Task
                            else
                                Task.CompletedTask

                    let refresh =
                        Validators.refresh
                            testFloor
                            nodes
                            registry
                            db
                            AllowStartWithoutHistory.All
                            Log.none
                            CancellationToken.None

                    do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)

                    Expect.equal
                        (registry.TryGet(pubkeyOf 0)).Value.State
                        KeyState.Discovered
                        "waits for the floor epoch"

                    registry.Refuse(pubkeyOf 0, "test: refused while the refresh waits")
                    gate.SetResult()
                    let! r = refresh
                    Expect.isOk r "refresh"

                    Expect.equal
                        (registry.TryGet(pubkeyOf 0)).Value.State
                        KeyState.Removed
                        "the refused key stays removed"
                })

            testT "a delete while the override waits for the floor epoch keeps the key removed" (fun () ->
                task {
                    let h, fakes, nodes, registry, db = nodesWith [ Some "active_ongoing" ] 1
                    use _ = db
                    let pipeline = Pipeline(db, registry, h.Time, Log.none)
                    let entered = TaskCompletionSource()
                    let gate = TaskCompletionSource()

                    fakes[0].Delay <-
                        fun path ->
                            if path.Contains "syncing" then
                                entered.TrySetResult() |> ignore
                                gate.Task
                            else
                                Task.CompletedTask

                    let refresh =
                        Validators.refresh
                            testFloor
                            nodes
                            registry
                            db
                            AllowStartWithoutHistory.All
                            Log.none
                            CancellationToken.None

                    do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)

                    Expect.equal
                        (registry.TryGet(pubkeyOf 0)).Value.State
                        KeyState.Discovered
                        "waits for the floor epoch"

                    let! _ = KeyRetirement.drain registry pipeline Log.none (pubkeyOf 0) ignore CancellationToken.None
                    gate.SetResult()
                    let! r = refresh
                    Expect.isOk r "refresh"

                    Expect.equal
                        (registry.TryGet(pubkeyOf 0)).Value.State
                        KeyState.Removed
                        "the deleted key stays removed"

                    Expect.isEmpty registry.Active "no key active"
                })

            test "closed activation keeps history-checked keys until it opens" {
                let registry = KeyRegistry()
                let backend = LocalBackend.create "local" [ pubkeyOf 0, SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]
                registry.Add(pubkeyOf 0, backend) |> ignore
                registry.CloseActivation()
                registry.SetState(pubkeyOf 0, KeyState.HistoryChecked)
                registry.PromoteChecked()
                Expect.equal (registry.TryGet(pubkeyOf 0)).Value.State KeyState.HistoryChecked "held while closed"
                registry.ActivationHold <- fun _ -> true
                registry.OpenActivation()

                Expect.equal
                    (registry.TryGet(pubkeyOf 0)).Value.State
                    KeyState.DoppelgangerWait
                    "the hold set before the opening applies"
            }

            testT
                "a key refresh while modules start makes no key active before the doppelganger hold (finding 5)"
                (fun () ->
                    task {
                        let h = harness ()
                        h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                        let dir = tempDir ()
                        let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName
                        File.WriteAllText(Path.Combine(ksDir, "k0.json"), MetricsTests.keystoreOf 0 "pw")
                        File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
                        let seen = Collections.Concurrent.ConcurrentQueue<KeyState>()
                        // The probe starts between the backend and the doppelganger module, as the keymanager does.
                        let modules = [ LocalModule.create (); refreshingModule seen; DoppelgangerModule.create () ]

                        let configText =
                            """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                       "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 } } }"""

                        match
                            Config.parse configText dir (modules |> List.map (fun m -> m.Name))
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok config ->
                            use cts = new CancellationTokenSource()
                            let log, lines = Log.memory ()
                            let ready = TaskCompletionSource<KeyState>()

                            let run =
                                Runner.run
                                    {
                                        Config = config
                                        Modules = modules
                                        Http = new HttpClient(h.Node, false)
                                        Time = h.Time
                                        Log = log
                                        OnSlotDone = h.Waiter.Done
                                        OnReady =
                                            fun core _ ->
                                                ready.TrySetResult (core.Registry.TryGet(pubkeyOf 0)).Value.State
                                                |> ignore
                                    }
                                    cts.Token

                            let! winner =
                                Task.WhenAny(ready.Task :> Task, run :> Task, Task.Delay(TimeSpan.FromSeconds 20.0))

                            if winner <> (ready.Task :> Task) then
                                failtestf "the VC did not start: %s" (String.Join("\n", lines))

                            Expect.equal
                                (List.ofSeq seen)
                                [ KeyState.HistoryChecked ]
                                "history checked during the start, not active"

                            Expect.equal ready.Task.Result KeyState.DoppelgangerWait "held once every module started"
                            cts.Cancel()
                            let! _ = run
                            ()
                    })
        ]
