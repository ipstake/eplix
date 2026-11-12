/// Doppelganger protection against the fake beacon node's liveness endpoint: epoch by epoch on the
/// checker, then end to end in the whole VC.
module Eplix.Tests.DoppelgangerTests

open System
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Doppelganger
open Eplix.Doppelganger.DoppelgangerModule
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.MetricsTests

type private Setup =
    {
        H: Harness
        Registry: KeyRegistry
        Nodes: BeaconNodes
        Db: SlashingDb
        Dir: string
        Lines: Collections.Concurrent.ConcurrentQueue<string>
    }

    member s.Refresh() =
        task {
            let log = Log.none
            let! r = refreshEmpty ValueNone s.Nodes s.Registry s.Db log CancellationToken.None
            Expect.isOk r "refresh"
        }

    member s.State(i: int) = (s.Registry.TryGet(pubkeyOf i)).Value.State

let private setup (keys: int list) (backendOf: int -> Backend) =
    let h = harness ()

    for i in keys do
        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

    let http = new HttpClient(h.Node, false)

    let nodes =
        BeaconNodes([ BeaconClient(http, Uri "http://bn.test", TimeSpan.FromSeconds 5.0) ], 1, h.Time, Log.none)

    let dir = tempDir ()

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(dir, "slashing.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let registry = KeyRegistry()

    for i in keys do
        registry.Add(pubkeyOf i, backendOf i) |> ignore

    let log, lines = Log.memory ()

    {
        H = h
        Registry = registry
        Nodes = nodes
        Db = db
        Dir = dir
        Lines = lines
    },
    log

let private local (keys: int list) =
    LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

/// A checker on the setup's registry; the returned list collects the shutdown reasons.
let private checker (s: Setup) (log: Log) (settings: Settings) =
    let stops = Collections.Concurrent.ConcurrentQueue<string>()
    let c = Checker(settings, s.Registry, s.Nodes, s.H.Clock, log, stops.Enqueue)
    s.Registry.ActivationHold <- c.Hold
    c, stops

/// One node's liveness answer for one epoch, for the property below.
type private Answer =
    | NotLive
    | Live
    | Omitted
    | Failed

/// The setup with a second node on the same chain; the second node returned.
let private twoNodes (s: Setup) =
    let second = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

    for v in s.H.Node.Validators do
        second.AddValidator(v.PubKey, v.Status) |> ignore

    let two =
        BeaconNodes(
            [
                BeaconClient(new HttpClient(s.H.Node, false), Uri "http://bn0.test", TimeSpan.FromSeconds 5.0)
                BeaconClient(new HttpClient(second, false), Uri "http://bn1.test", TimeSpan.FromSeconds 5.0)
            ],
            1,
            s.H.Time,
            Log.none
        )

    { s with Nodes = two }, second

/// Keys 0 and 1 pass their check in epochs 1 and 2.
let private passOnce (s: Setup) (c: Checker) =
    task {
        do! s.Refresh()

        for e in 1UL .. 3UL do
            do! c.OnEpochEnd e CancellationToken.None

        Expect.equal (s.State 1) KeyState.Active "key 1 passed once"
    }

let private section (json: string) =
    {
        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
        BaseDir = "/"
        Mainnet = false
    }

[<Tests>]
let tests =
    testList
        "doppelganger"
        [
            testT "keys wait for clean epochs, then go active" (fun () ->
                task {
                    let backend = local [ 0; 1; 2 ]
                    let s, log = setup [ 0; 1; 2 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    do! s.Refresh()

                    for i in 0..2 do
                        Expect.equal (s.State i) KeyState.DoppelgangerWait $"key {i} waits"
                    // Epoch 1 checks epoch 0, the start epoch: it never counts.
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "start epoch does not count"
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "one clean epoch is not enough"
                    do! c.OnEpochEnd 3UL CancellationToken.None

                    for i in 0..2 do
                        Expect.equal (s.State i) KeyState.Active $"key {i} active after epochs 1 and 2"

                    Expect.isEmpty stops "no shutdown"
                    let requested = s.H.Node.Requests |> Seq.filter (fun r -> r.Contains "/liveness/") |> List.ofSeq

                    Expect.equal
                        requested
                        [ for e in 1..2 -> $"POST /eth/v1/validator/liveness/{e}" ]
                        "liveness of each ended epoch, none for the start epoch"
                    // A restart in the same data dir checks every key again; no pass is kept.
                    let again = Checker(defaults, KeyRegistry(), s.Nodes, s.H.Clock, Log.none, ignore)
                    Expect.isTrue (again.Hold (s.Registry.TryGet(pubkeyOf 0)).Value) "a restart waits again"

                    Expect.isFalse
                        (File.Exists(Path.Combine(s.Dir, "doppelganger.json")))
                        "no pass written to the data dir"
                })

            testT "a key refused while its liveness check runs stays out" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    let entered = TaskCompletionSource()
                    let gate = TaskCompletionSource()

                    s.H.Node.Delay <-
                        fun path ->
                            if path.Contains "liveness" then
                                entered.TrySetResult() |> ignore
                                gate.Task
                            else
                                Task.CompletedTask

                    let pass = c.OnEpochEnd 3UL CancellationToken.None
                    do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "still waiting while the check runs"
                    s.Registry.Refuse(pubkeyOf 0, "test: refused during the check")
                    gate.SetResult()
                    do! pass
                    Expect.equal (s.State 0) KeyState.Removed "the refused key stays removed"
                    Expect.equal (s.State 1) KeyState.Active "the other key goes active"
                    Expect.isEmpty stops "no shutdown"
                })

            testT "a key deleted while its liveness check runs stays removed and signs nothing" (fun () ->
                task {
                    let inner = local [ 0; 1 ]
                    let seen = Collections.Concurrent.ConcurrentQueue<PubKey>()

                    let spy =
                        { inner with
                            Sign =
                                fun r ct ->
                                    seen.Enqueue r.Key
                                    inner.Sign r ct
                        }

                    let s, log = setup [ 0; 1 ] (fun _ -> spy)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    let pipeline = Pipeline(s.Db, s.Registry, s.H.Time, Log.none)
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    let entered = TaskCompletionSource()
                    let gate = TaskCompletionSource()

                    s.H.Node.Delay <-
                        fun path ->
                            if path.Contains "liveness" then
                                entered.TrySetResult() |> ignore
                                gate.Task
                            else
                                Task.CompletedTask

                    let pass = c.OnEpochEnd 3UL CancellationToken.None
                    do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)
                    // The keymanager DELETE lands during the liveness call: draining, then removed.
                    let! _ =
                        KeyRetirement.drain s.Registry pipeline Log.none (pubkeyOf 0) ignore CancellationToken.None

                    Expect.equal (s.State 0) KeyState.Removed "removed"
                    gate.SetResult()
                    do! pass
                    Expect.equal (s.State 0) KeyState.Removed "the deleted key stays removed"
                    Expect.equal (s.State 1) KeyState.Active "the other key goes active"
                    Expect.isEmpty stops "no shutdown"

                    let requests =
                        [|
                            for d in Web3SignerTests.allDuties () do
                                match d with
                                | Duty.VoluntaryExit _ -> ()
                                | d -> Web3SignerTests.req (pubkeyOf 0) d
                        |]

                    let! outcomes = pipeline.SignBurst(requests, CancellationToken.None)

                    for o in outcomes do
                        match o with
                        | Refused(PolicyDenied _) -> ()
                        | o -> failtestf "a removed key signed or tried to: %s" o.Describe

                    Expect.isEmpty seen "nothing reached the backend for the removed key"
                })

            testT "a key removed and imported again while its liveness check runs starts a new count" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    let pipeline = Pipeline(s.Db, s.Registry, s.H.Time, Log.none)
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    let entered = TaskCompletionSource()
                    let gate = TaskCompletionSource()

                    s.H.Node.Delay <-
                        fun path ->
                            if path.Contains "liveness" then
                                entered.TrySetResult() |> ignore
                                gate.Task
                            else
                                Task.CompletedTask
                    // Epoch 3 checks epoch 2, the second clean epoch: without the delete, key 0 passes.
                    let pass = c.OnEpochEnd 3UL CancellationToken.None
                    do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)

                    let! _ =
                        KeyRetirement.drain s.Registry pipeline Log.none (pubkeyOf 0) ignore CancellationToken.None

                    Expect.isTrue (s.Registry.Revive(pubkeyOf 0, backend)) "imported again"
                    s.Registry.SetState(pubkeyOf 0, KeyState.HistoryChecked)
                    s.Registry.PromoteChecked()
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "back in the wait"
                    gate.SetResult()
                    do! pass
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "the clean epochs from before do not count"
                    Expect.equal (s.State 1) KeyState.Active "the other key goes active"

                    Expect.isTrue
                        (s.Lines |> Seq.exists (fun l -> l.Contains "again (it left and came back)"))
                        "the new check is logged"

                    Expect.isEmpty stops "no shutdown"
                })

            testT "a key seen live stops the VC and activates nothing" (fun () ->
                task {
                    let backend = local [ 0; 1; 2 ]
                    let s, log = setup [ 0; 1; 2 ] (fun _ -> backend)
                    use _ = s.Db
                    // Validator 1 is live in epoch 2: another client signs with it.
                    s.H.Node.Live <- fun epoch index -> index = 1UL && epoch = 2UL
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    Expect.isEmpty stops "epoch 1 was clean"
                    // Epoch 3 would activate keys 0 and 2, but the check of epoch 2 finds key 1.
                    do! c.OnEpochEnd 3UL CancellationToken.None
                    Expect.equal stops.Count 1 "one shutdown"
                    let reason = Seq.head stops
                    Expect.stringContains reason "DOPPELGANGER" "says what"
                    Expect.stringContains reason (pubkeyOf 1).Hex "names the key"
                    Expect.stringContains reason "epoch 2" "names the epoch"
                    Expect.isFalse (reason.Contains (pubkeyOf 0).Hex) "only the live key"

                    for i in 0..2 do
                        Expect.equal (s.State i) KeyState.DoppelgangerWait $"key {i} not activated"
                })

            testT "a failed liveness call starts the count again" (fun () ->
                task {
                    let backend = local [ 0 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    s.H.Node.Fail <- fun p -> p.Contains "/liveness/"
                    do! c.OnEpochEnd 3UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "no answer, no activation"
                    s.H.Node.Fail <- fun _ -> false
                    do! c.OnEpochEnd 4UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "epoch 3 counts, epoch 4 not yet checked"
                    do! c.OnEpochEnd 5UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.Active "two clean epochs after the failure"
                    Expect.isEmpty stops "a failed call never stops the VC"
                })

            testT "threshold keys skip the check unless asked; off means no hold" (fun () ->
                task {
                    let members =
                        [
                            for i in 1..3 ->
                                {
                                    Backend = local [ 0 ]
                                    Index = uint64 i
                                    Budget = TimeSpan.FromSeconds 1.0
                                }
                        ]

                    let group = Threshold.create "group" 2 members TimeProvider.System Log.none
                    let s, log = setup [ 0; 1 ] (fun i -> if i = 0 then group else local [ 1 ])
                    use _ = s.Db
                    let _ = checker s log defaults |> fst
                    do! s.Refresh()
                    Expect.equal (s.State 0) KeyState.Active "threshold key not held"
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "whole key held"
                    let k0 = (s.Registry.TryGet(pubkeyOf 0)).Value

                    let withThreshold =
                        Checker(
                            { defaults with ThresholdKeys = true },
                            KeyRegistry(),
                            s.Nodes,
                            s.H.Clock,
                            Log.none,
                            ignore
                        )

                    Expect.isTrue (withThreshold.Hold k0) "threshold_keys: true holds it"

                    let off =
                        Checker({ defaults with Enabled = false }, KeyRegistry(), s.Nodes, s.H.Clock, Log.none, ignore)

                    Expect.isFalse (off.Hold k0) "enabled: false"
                })

            testT
                "liveness from every node: one node's live answer against another's holds every waiting key; two stop the VC"
                (fun () ->
                    task {
                        let backend = local [ 0; 1 ]
                        let s, log = setup [ 0; 1 ] (fun _ -> backend)
                        use _ = s.Db
                        let second = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

                        for i in [ 0; 1 ] do
                            second.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                        // Only the second node saw validator 1 in epoch 1.
                        second.Live <- fun epoch index -> index = 1UL && epoch = 1UL

                        let two =
                            BeaconNodes(
                                [
                                    BeaconClient(
                                        new HttpClient(s.H.Node, false),
                                        Uri "http://bn0.test",
                                        TimeSpan.FromSeconds 5.0
                                    )
                                    BeaconClient(
                                        new HttpClient(second, false),
                                        Uri "http://bn1.test",
                                        TimeSpan.FromSeconds 5.0
                                    )
                                ],
                                1,
                                s.H.Time,
                                Log.none
                            )

                        let s = { s with Nodes = two }
                        let all, stopsAll = checker s log defaults
                        do! s.Refresh()
                        do! all.OnEpochEnd 1UL CancellationToken.None
                        do! all.OnEpochEnd 2UL CancellationToken.None
                        // One node says live, the other answered not live: no stop, the key waits on.
                        Expect.isEmpty stopsAll "one node of two cannot stop the VC"
                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "key 1 keeps waiting"

                        let disputed = s.Lines |> Seq.filter (fun l -> l.Contains "DOPPELGANGER?") |> List.ofSeq

                        Expect.equal disputed.Length 1 "one error"
                        Expect.stringContains disputed.Head (pubkeyOf 1).Hex "names the key"
                        Expect.stringContains disputed.Head "bn1.test" "names the node that saw it live"
                        // Epochs 1 to 3 are clean for key 0 on both nodes, but the nodes disagreed:
                        // both keys wait until restart.
                        do! all.OnEpochEnd 3UL CancellationToken.None
                        do! all.OnEpochEnd 4UL CancellationToken.None
                        Expect.equal (s.State 0) KeyState.DoppelgangerWait "key 0 waits until restart too"
                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "key 1 waits until restart"

                        Expect.equal
                            (s.Lines |> Seq.filter (fun l -> l.Contains "DOPPELGANGER?") |> Seq.length)
                            1
                            "logged once"
                        // Both nodes see key 1 live in epoch 4: that stops the VC and names both.
                        s.H.Node.Live <- fun epoch index -> index = 1UL && epoch = 4UL
                        second.Live <- fun epoch index -> index = 1UL && epoch = 4UL
                        do! all.OnEpochEnd 5UL CancellationToken.None
                        Expect.equal stopsAll.Count 1 "two nodes stop the VC"
                        let reason = Seq.head stopsAll
                        Expect.stringContains reason (pubkeyOf 1).Hex "names the key"
                        Expect.stringContains reason "bn0.test" "names the first node"
                        Expect.stringContains reason "bn1.test" "and the second"
                        s.H.Node.Live <- fun _ _ -> false
                        second.Live <- fun epoch index -> index = 1UL && epoch = 1UL
                        // The same chain with the best node only: the first node never saw it.
                        let stopsBest = Collections.Concurrent.ConcurrentQueue<string>()

                        let best =
                            Checker(
                                { defaults with
                                    LivenessFrom = LivenessFrom.Best
                                },
                                s.Registry,
                                two,
                                s.H.Clock,
                                Log.none,
                                stopsBest.Enqueue
                            )

                        for k in s.Registry.All do
                            best.Hold k |> ignore

                        do! best.OnEpochEnd 2UL CancellationToken.None
                        Expect.isEmpty stopsBest "the best node alone misses it"
                    })

            testT "liveness from every node: a dispute holds every waiting key; active keys go on" (fun () ->
                task {
                    let backend = local [ 0; 1; 2 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db

                    for i in [ 1; 2 ] do
                        s.H.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let s, second = twoNodes s
                    let c, stops = checker s log defaults
                    do! s.Refresh()

                    for e in 1UL .. 3UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.equal (s.State 0) KeyState.Active "key 0 passed"
                    // Keys 1 and 2 come in epoch 3, as a keymanager import.
                    s.H.Time.Advance(s.H.Clock.SlotStart(3UL * uint64 slotsPerEpoch + 1UL) - s.H.Time.GetUtcNow())

                    for i in [ 1; 2 ] do
                        Expect.isTrue (s.Registry.Revive(pubkeyOf i, backend)) "imported"

                    do! s.Refresh()
                    // Only the second node sees key 1 live, in epoch 4. Key 2 is clean on both.
                    second.Live <- fun epoch index -> index = 1UL && epoch = 4UL

                    for e in 4UL .. 8UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.isEmpty stops "one node against another does not stop the VC"
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "the disputed key waits"
                    Expect.equal (s.State 2) KeyState.DoppelgangerWait "the clean key waits too"
                    Expect.equal (s.State 0) KeyState.Active "the active key goes on"
                    let errors = s.Lines |> Seq.filter (fun l -> l.Contains "DOPPELGANGER?") |> List.ofSeq
                    Expect.equal errors.Length 1 "the hold is logged once"
                    Expect.stringContains errors.Head (pubkeyOf 1).Hex "names the disputed key"
                    Expect.stringContains errors.Head "bn1.test" "names the node that saw it live"
                    Expect.stringContains errors.Head "bn0.test" "and the node that did not"
                    // Both nodes see key 2 live in epoch 9: that still stops the VC.
                    s.H.Node.Live <- fun epoch index -> index = 2UL && epoch = 9UL
                    second.Live <- fun epoch index -> index = 2UL && epoch = 9UL
                    do! c.OnEpochEnd 10UL CancellationToken.None
                    Expect.equal stops.Count 1 "two nodes stop the VC"
                    Expect.stringContains (Seq.head stops) (pubkeyOf 2).Hex "names the key"
                })

            testT "liveness from every node: one node down still counts, all down starts again" (fun () ->
                task {
                    let backend = local [ 0 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db
                    let second = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    second.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    second.Fail <- fun p -> p.Contains "/liveness/"

                    let two =
                        BeaconNodes(
                            [
                                BeaconClient(
                                    new HttpClient(s.H.Node, false),
                                    Uri "http://bn0.test",
                                    TimeSpan.FromSeconds 5.0
                                )
                                BeaconClient(
                                    new HttpClient(second, false),
                                    Uri "http://bn1.test",
                                    TimeSpan.FromSeconds 5.0
                                )
                            ],
                            1,
                            s.H.Time,
                            Log.none
                        )

                    let s = { s with Nodes = two }
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    s.H.Node.Fail <- fun p -> p.Contains "/liveness/"
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "both down: epoch 1 does not count"
                    s.H.Node.Fail <- fun _ -> false
                    do! c.OnEpochEnd 3UL CancellationToken.None
                    do! c.OnEpochEnd 4UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.Active "the first node's answers count while the second is down"
                    Expect.isEmpty stops "no shutdown"
                })

            testT "a restart in the starting epoch does not trigger" (fun () ->
                task {
                    let backend = local [ 0 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db
                    // The VC signed in epochs 2 and 3 before it restarts in slot 2 of epoch 3.
                    let restart = s.H.Clock.SlotStart(3UL * uint64 slotsPerEpoch + 2UL)
                    s.H.Time.Advance(restart - s.H.Time.GetUtcNow())
                    s.H.Node.Live <- fun epoch index -> index = 0UL && epoch <= 3UL
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "waits"

                    for e in 4UL .. 6UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.isEmpty stops "its own votes before the restart are not a doppelganger"
                    Expect.equal (s.State 0) KeyState.Active "active after epochs 4 and 5"
                    let asked = s.H.Node.Requests |> Seq.filter (fun r -> r.Contains "/liveness/") |> List.ofSeq

                    Expect.equal
                        asked
                        [ "POST /eth/v1/validator/liveness/4"; "POST /eth/v1/validator/liveness/5" ]
                        "the start epoch is never asked"
                })

            testT "a partial liveness answer fails closed" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    // The node's answer for epoch 2 leaves validator 1 out.
                    s.H.Node.LivenessOmit <- fun epoch index -> epoch = 2UL && index = 1UL
                    let c, stops = checker s log defaults
                    do! s.Refresh()

                    for e in 1UL .. 3UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.equal (s.State 0) KeyState.Active "key 0: epochs 1 and 2 clean"

                    Expect.equal
                        (s.State 1)
                        KeyState.DoppelgangerWait
                        "key 1: no answer for epoch 2, the count starts again"

                    do! c.OnEpochEnd 4UL CancellationToken.None
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "key 1: one clean epoch since"
                    do! c.OnEpochEnd 5UL CancellationToken.None
                    Expect.equal (s.State 1) KeyState.Active "key 1: epochs 3 and 4 clean"
                    Expect.isEmpty stops "no shutdown"
                })

            testT "the clock jumps two epochs: the skipped epochs are checked" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    // The clock jumps from epoch 1 to epoch 4: epochs 1 and 2 were never checked.
                    do! c.OnEpochEnd 4UL CancellationToken.None
                    let asked = s.H.Node.Requests |> Seq.filter (fun r -> r.Contains "/liveness/") |> List.ofSeq

                    Expect.equal
                        asked
                        [ for e in 1..3 -> $"POST /eth/v1/validator/liveness/{e}" ]
                        "every epoch since the last check"

                    Expect.equal (s.State 0) KeyState.Active "three clean epochs"
                    Expect.isEmpty stops "no shutdown"
                    // The same jump with a doppelganger in a skipped epoch.
                    let s2, log2 = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s2.Db
                    s2.H.Node.Live <- fun epoch index -> index = 1UL && epoch = 2UL
                    let c2, stops2 = checker s2 log2 defaults
                    do! s2.Refresh()
                    do! c2.OnEpochEnd 1UL CancellationToken.None
                    do! c2.OnEpochEnd 4UL CancellationToken.None
                    Expect.equal stops2.Count 1 "the skipped epoch's liveness stops the VC"
                    Expect.stringContains (Seq.head stops2) "epoch 2" "names the epoch"

                    for i in 0..1 do
                        Expect.equal (s2.State i) KeyState.DoppelgangerWait $"key {i} not activated"
                })

            testT "the clock steps back one epoch: the count does not advance" (fun () ->
                task {
                    let backend = local [ 0 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log { defaults with Epochs = 3UL }
                    do! s.Refresh()
                    do! c.OnEpochEnd 1UL CancellationToken.None
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    do! c.OnEpochEnd 3UL CancellationToken.None
                    // Back one epoch, twice: epochs 1 and 2 are already counted.
                    do! c.OnEpochEnd 2UL CancellationToken.None
                    do! c.OnEpochEnd 3UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "two clean epochs, not four"
                    do! c.OnEpochEnd 4UL CancellationToken.None
                    Expect.equal (s.State 0) KeyState.Active "epochs 1 to 3 clean"
                    Expect.isEmpty stops "no shutdown"
                })

            testT "a key that leaves and comes back through the keymanager waits again" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, stops = checker s log defaults
                    do! passOnce s c
                    // Deleted, then imported again: the local module's import revives the key.
                    s.Registry.SetState(pubkeyOf 1, KeyState.Removed)
                    Expect.isTrue (s.Registry.Revive(pubkeyOf 1, backend)) "revived"
                    do! s.Refresh()

                    Expect.equal
                        (s.State 1)
                        KeyState.DoppelgangerWait
                        "it may have signed elsewhere meanwhile: it waits"

                    Expect.equal (s.State 0) KeyState.Active "key 0 untouched"
                    // A restart in the same data dir holds it too.
                    let again = Checker(defaults, KeyRegistry(), s.Nodes, s.H.Clock, Log.none, ignore)
                    Expect.isTrue (again.Hold (s.Registry.TryGet(pubkeyOf 1)).Value) "it waits after a restart"

                    for e in 4UL .. 6UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.equal (s.State 1) KeyState.Active "two clean epochs after it came back"
                    Expect.isEmpty stops "no shutdown"
                })

            testT "a key imported while running waits like a key at start" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db
                    s.H.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
                    let c, _ = checker s log defaults
                    do! s.Refresh()

                    for e in 1UL .. 3UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.equal (s.State 0) KeyState.Active "key 0 passed"
                    // The keymanager import in epoch 3: Revive adds a new key as discovered.
                    s.H.Time.Advance(s.H.Clock.SlotStart(3UL * uint64 slotsPerEpoch + 1UL) - s.H.Time.GetUtcNow())
                    Expect.isTrue (s.Registry.Revive(pubkeyOf 1, backend)) "imported"
                    do! s.Refresh()
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "the imported key waits"
                    do! c.OnEpochEnd 4UL CancellationToken.None
                    do! c.OnEpochEnd 5UL CancellationToken.None
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "its start epoch (3) does not count"
                    do! c.OnEpochEnd 6UL CancellationToken.None
                    Expect.equal (s.State 1) KeyState.Active "epochs 4 and 5 clean"
                })

            testT "a key a remote signer starts to list waits; one retired and listed again waits again" (fun () ->
                task {
                    let backend = local [ 0; 1; 2 ]
                    let s, log = setup [ 0 ] (fun _ -> backend)
                    use _ = s.Db

                    for i in [ 1; 2 ] do
                        s.H.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let c, stops = checker s log defaults
                    let pipeline = Pipeline(s.Db, s.Registry, s.H.Time, Log.none)
                    let keys = ListedKeys("w3s", s.Registry, pipeline, Log.none)

                    let answer (listed: int list) =
                        [
                            {
                                Member = "w3s-1"
                                Keys =
                                    ValueSome(
                                        [ for i in listed -> pubkeyOf i ]
                                        :> Collections.Generic.IReadOnlyCollection<PubKey>
                                    )
                            }
                        ]
                    // The signer starts to list keys 1 and 2 while the VC runs.
                    Expect.equal (keys.Register [ pubkeyOf 1, backend; pubkeyOf 2, backend ]) 2 "two new keys"
                    do! s.Refresh()
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "a newly listed key waits"

                    for e in 1UL .. 3UL do
                        do! c.OnEpochEnd e CancellationToken.None

                    Expect.equal (s.State 1) KeyState.Active "passed"
                    // Handed over: the signer stops listing key 1 for two polls; the VC retires it.
                    let! _ = keys.Retire(answer [ 1; 2 ], (fun _ -> true), CancellationToken.None)
                    let! _ = keys.Retire(answer [ 2 ], (fun _ -> true), CancellationToken.None)
                    let! retired = keys.Retire(answer [ 2 ], (fun _ -> true), CancellationToken.None)
                    Expect.equal retired [ pubkeyOf 1 ] "retired"
                    Expect.equal (s.State 1) KeyState.Removed "removed"
                    // Moved back: listed again.
                    Expect.equal (keys.Register [ pubkeyOf 1, backend; pubkeyOf 2, backend ]) 1 "brought back"
                    do! s.Refresh()
                    Expect.equal (s.State 1) KeyState.DoppelgangerWait "a key moved back waits again"
                    Expect.equal (s.State 2) KeyState.Active "key 2 untouched"
                    Expect.isEmpty stops "no shutdown"
                })

            testPropN
                "random liveness answers: a key never goes active while a node saw it live in a checked epoch"
                100
                (let answerGen = Gen.elements [ NotLive; NotLive; NotLive; Live; Omitted; Failed ]

                 Prop.forAll (Arb.fromGen (Gen.listOfLength 12 answerGen)) (fun answers ->
                     let answers = Array.ofList answers
                     // Node n's answer for epoch e (1 to 6) is answers[2 * (e - 1) + n].
                     let at (n: int) (e: Epoch) =
                         if e >= 1UL && e <= 6UL then answers[2 * (int e - 1) + n] else NotLive

                     let backend = local [ 0 ]
                     let s0, log = setup [ 0 ] (fun _ -> backend)
                     use _ = s0.Db
                     let s, second = twoNodes s0

                     let program (node: FakeBeaconNode) (n: int) =
                         node.Live <- fun e _ -> at n e = Live
                         node.LivenessOmit <- fun e _ -> at n e = Omitted

                         node.Fail <-
                             fun p ->
                                 p.Contains "/liveness/"
                                 && at n (UInt64.Parse(p.Substring(p.LastIndexOf '/' + 1))) = Failed

                     program s.H.Node 0
                     program second 1
                     let c, stops = checker s log defaults
                     (s.Refresh()).GetAwaiter().GetResult()
                     let mutable activeAfter = None
                     let mutable e = 1UL

                     while e <= 7UL && stops.IsEmpty && activeAfter.IsNone do
                         (c.OnEpochEnd e CancellationToken.None).GetAwaiter().GetResult()

                         if s.State 0 = KeyState.Active then
                             activeAfter <- Some e

                         e <- e + 1UL
                     // Epochs checked before the key went active; epoch 0, its start epoch, never is.
                     let checkedEpochs =
                         match activeAfter with
                         | Some a -> [ 1UL .. a - 1UL ]
                         | None -> []

                     let liveSeen = checkedEpochs |> List.exists (fun c -> at 0 c = Live || at 1 c = Live)
                     not liveSeen))

            testT "a waiting key signs no kind of duty; an exit is the one exception (finding 1)" (fun () ->
                task {
                    let inner = local [ 0 ]
                    let seen = Collections.Concurrent.ConcurrentQueue<DutyKind>()

                    let spy =
                        { inner with
                            Sign =
                                fun r ct ->
                                    seen.Enqueue r.Duty.Kind
                                    inner.Sign r ct
                        }

                    let s, _ = setup [ 0 ] (fun _ -> spy)
                    use _ = s.Db

                    use marks =
                        match SlotMarks.Open(new FileMarkFile(Path.Combine(s.Dir, "slot-marks.db")), gvr) with
                        | Ok m -> m
                        | Error e -> failwith e

                    let pipeline = Pipeline(s.Db, s.Registry, s.H.Time, Log.none, marks)
                    s.Registry.ActivationHold <- fun _ -> true
                    do! s.Refresh()
                    Expect.equal (s.State 0) KeyState.DoppelgangerWait "waits"
                    let envelope = Schemas.Gloas.executionPayloadEnvelope Preset.Minimal

                    let duties =
                        Web3SignerTests.allDuties ()
                        @ [
                            Duty.PayloadAttestation
                                {
                                    BeaconBlockRoot = root 7
                                    Slot = 41UL
                                    PayloadPresent = true
                                    BlobDataAvailable = false
                                }
                            Duty.PayloadEnvelope(
                                41UL,
                                {
                                    Schema = envelope
                                    Value = Ssz.zero envelope
                                }
                            )
                            Duty.ProposerPreferences
                                {
                                    DependentRoot = root 3
                                    ProposalSlot = 42UL
                                    ValidatorIndex = 0UL
                                    FeeRecipient = Array.create 20 0xaauy
                                    TargetGasLimit = 60_000_000UL
                                }
                            Duty.BuilderRequestAuth
                                {
                                    AuthData = Text.Encoding.UTF8.GetBytes "builder.example.org"
                                    AuthSlot = 42UL
                                }
                            Duty.ValidatorRegistration
                                {
                                    FeeRecipient = Array.create 20 0xaauy
                                    GasLimit = 60_000_000UL
                                    Timestamp = 1_700_000_000UL
                                    PubKey = pubkeyOf 0
                                }
                        ]

                    let kinds = duties |> List.map (fun d -> d.Kind) |> Set.ofList
                    Expect.equal kinds (Set.ofList Switches.allKinds) "every duty kind the VC signs"
                    let requests = [| for d in duties -> Web3SignerTests.req (pubkeyOf 0) d |]
                    let! held = pipeline.SignBurst(requests, CancellationToken.None)

                    for r, o in Array.zip requests held do
                        match r.Duty, o with
                        | Duty.VoluntaryExit _, Signed _ -> ()
                        | Duty.VoluntaryExit _, o -> failtestf "an exit is allowed while the key waits: %s" o.Describe
                        | _, Refused(PolicyDenied _) -> ()
                        | d, o -> failtestf "%s while the key waits: %s" (string d.Kind) o.Describe

                    Expect.equal (List.ofSeq seen) [ DutyKind.VoluntaryExit ] "only the exit reached the backend"
                    // Once active, the same requests reach the backend: the hold refused them, nothing else.
                    s.Registry.SetState(pubkeyOf 0, KeyState.Active)
                    let! _ = pipeline.SignBurst(requests, CancellationToken.None)
                    Expect.equal (Set.ofSeq seen) kinds "every kind reaches the backend once active"
                })

            testT
                "a key the beacon node does not index yet counts no epoch; once indexed it is checked (finding 2)"
                (fun () ->
                    task {
                        let backend = local [ 0; 1 ]
                        let s, log = setup [ 0 ] (fun _ -> backend)
                        use _ = s.Db
                        // Key 1 is in the VC, but the node does not know it yet: no index, no liveness to ask.
                        s.Registry.Add(pubkeyOf 1, backend) |> ignore
                        let c, stops = checker s log defaults
                        do! s.Refresh()
                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "waits"

                        for e in 1UL .. 3UL do
                            do! c.OnEpochEnd e CancellationToken.None

                        Expect.equal (s.State 0) KeyState.Active "key 0 passed"

                        Expect.equal
                            (s.State 1)
                            KeyState.DoppelgangerWait
                            "without an index no epoch was checked, so none counts"
                        // The node learns the validator in epoch 3, and another client signs with it from then on.
                        let v = s.H.Node.AddValidator(pubkeyOf 1, "active_ongoing")
                        s.H.Node.Live <- fun epoch index -> index = v.Index && epoch >= 3UL
                        do! s.Refresh()
                        do! c.OnEpochEnd 4UL CancellationToken.None
                        Expect.equal stops.Count 1 "the first epoch with an index is checked and stops the VC"
                        Expect.stringContains (Seq.head stops) (pubkeyOf 1).Hex "names the key"
                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "never active"
                    })

            testT
                "keys pending activation are checked while pending, also before the node indexes them (finding 3)"
                (fun () ->
                    task {
                        let backend = local [ 0; 1 ]
                        let s, log = setup [] (fun _ -> backend)
                        use _ = s.Db
                        // Key 0: deposit processed, in the activation queue. Key 1: deposit not processed yet.
                        let v0 = s.H.Node.AddValidator(pubkeyOf 0, "pending_queued")

                        for i in [ 0; 1 ] do
                            s.Registry.Add(pubkeyOf i, backend) |> ignore

                        let c, stops = checker s log defaults
                        do! s.Refresh()

                        for i in [ 0; 1 ] do
                            Expect.equal (s.State i) KeyState.DoppelgangerWait $"key {i} waits"

                        for e in 1UL .. 3UL do
                            do! c.OnEpochEnd e CancellationToken.None

                        Expect.equal
                            (s.State 0)
                            KeyState.Active
                            "the pending key passed while pending, ready for its activation epoch"

                        let asked = s.H.Node.Requests |> Seq.filter (fun r -> r.Contains "/liveness/") |> List.ofSeq

                        Expect.equal
                            asked
                            [ for e in 1..2 -> $"POST /eth/v1/validator/liveness/{e}" ]
                            $"liveness asked for index {v0.Index} while pending"

                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "no index yet"
                        // Key 1's deposit is processed in epoch 3. Activation comes at least five epochs
                        // later on chain; the check needs epochs 3 and 4.
                        s.H.Node.AddValidator(pubkeyOf 1, "pending_initialized") |> ignore
                        do! s.Refresh()
                        do! c.OnEpochEnd 4UL CancellationToken.None
                        Expect.equal (s.State 1) KeyState.DoppelgangerWait "one clean epoch with an index"
                        do! c.OnEpochEnd 5UL CancellationToken.None
                        Expect.equal (s.State 1) KeyState.Active "epochs 3 and 4 clean"
                        Expect.isEmpty stops "no shutdown"
                    })

            testT "recent votes in the slashing DB do not skip the check (finding 5)" (fun () ->
                task {
                    let backend = local [ 0; 1 ]
                    let s, log = setup [ 0; 1 ] (fun _ -> backend)
                    use _ = s.Db
                    let c, _ = checker s log defaults
                    do! passOnce s c
                    let k0 = (s.Registry.TryGet(pubkeyOf 0)).Value
                    // The checker reads no slashing record: a DB that shows recent votes changes nothing.
                    let! v =
                        s.Db.CheckAndRecord(
                            [| AttestationRequest(pubkeyOf 0, 2UL, 3UL, root 1) |],
                            CancellationToken.None
                        )

                    Expect.equal v [| Verdict.Allowed |] "a recent vote in the slashing DB"
                    // A restart, or the same keys on a second machine with this DB. A copied data dir
                    // with an old doppelganger.json is the whole-VC test in DoppelgangerFindingsTests.
                    let restarted = Checker(defaults, KeyRegistry(), s.Nodes, s.H.Clock, Log.none, ignore)
                    Expect.isTrue (restarted.Hold k0) "the key waits"
                })

            test "config" {
                Expect.equal
                    (parse
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok defaults)
                    "defaults"

                match parse (section """{ "enabled": true, "epochs": 3, "threshold_keys": true }""") with
                | Ok s ->
                    Expect.equal
                        s
                        {
                            Enabled = true
                            Epochs = 3UL
                            ThresholdKeys = true
                            LivenessFrom = LivenessFrom.All
                        }
                        "set"
                | Error e -> failtestf "%A" e

                Expect.equal
                    (parse (section """{ "liveness_from": "best" }""") |> Result.map (fun s -> s.LivenessFrom))
                    (Ok LivenessFrom.Best)
                    "best"

                Expect.isError (parse (section """{ "liveness_from": "some" }""")) "liveness_from"
                Expect.isError (parse (section """{ "epochs": 0 }""")) "epochs 0"
                Expect.isError (parse (section """{ "check": "every_start" }""")) "check is no setting"
                Expect.isError (parse (section """{ "enabled": "yes" }""")) "enabled"
                Expect.isError (parse (section """{ "skip": true }""")) "unknown field"
            }

            testSequenced
            <| testT "the VC signs nothing while keys wait" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()

                    let! _, run, cts, lines =
                        startVc h dir [ 0; 1 ] "" [ LocalModule.create (); DoppelgangerModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, uint64 (5 * slotsPerEpoch - 1))

                    let epochsOf i =
                        h.Node.Submissions
                        |> Seq.filter (fun x -> x.AttesterIndex = uint64 i)
                        |> Seq.map (fun x -> x.Data.Target.Epoch)
                        |> Seq.distinct
                        |> Seq.sort
                        |> List.ofSeq

                    let log = String.Join("\n", lines)
                    // Checked in the last slot of epochs 2 and 3 (epochs 1 and 2): active from the last
                    // slot of epoch 3, so the first duties are in epoch 4.
                    Expect.equal (epochsOf 0) [ 4UL ] $"key 0 attests from epoch 4; log:\n{log}"
                    Expect.equal (epochsOf 1) [ 4UL ] $"key 1 attests from epoch 4; log:\n{log}"
                    Expect.isFalse (File.Exists(Path.Combine(dir, "data", "doppelganger.json"))) "no pass file"
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "run"
                })

            testSequenced
            <| testT "a late vote in an epoch's last slot is caught" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Another client signs with key 1 in the last slot of epoch 1. The node sees it
                    // live only once that vote is included, two slots into epoch 2.
                    let seenFrom = h.Clock.SlotStart(2UL * uint64 slotsPerEpoch + 2UL)
                    h.Node.Live <- fun epoch index -> index = 1UL && epoch = 1UL && h.Time.GetUtcNow() >= seenFrom
                    let dir = tempDir ()

                    let! _, run, cts, lines =
                        startVc h dir [ 0; 1 ] "" [ LocalModule.create (); DoppelgangerModule.create () ]

                    use _ = cts
                    let mutable s = 0UL

                    while not run.IsCompleted && s < uint64 (5 * slotsPerEpoch) do
                        let target = h.Clock.SlotStart s + TimeSpan.FromSeconds 2.1

                        if target > h.Time.GetUtcNow() then
                            h.Time.Advance(target - h.Time.GetUtcNow())

                        let! _ = Task.WhenAny(h.Waiter.Wait s, run :> Task, Task.Delay(TimeSpan.FromSeconds 5.0))
                        s <- s + 1UL

                    let log = String.Join("\n", lines)
                    Expect.isTrue run.IsCompleted $"the VC stopped; log:\n{log}"

                    match run.Result with
                    | Ok() -> failtest "the run must end with an error"
                    | Error e ->
                        Expect.stringContains e "DOPPELGANGER" "reason"
                        Expect.stringContains e (pubkeyOf 1).Hex "key"
                        Expect.stringContains e "epoch 1" "epoch"

                    Expect.isFalse
                        (h.Node.Submissions |> Seq.exists (fun x -> x.AttesterIndex = 1UL))
                        "key 1 signed nothing"
                })

            testSequenced
            <| testT "a key seen live stops the whole VC with an error" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.Live <- fun epoch index -> index = 1UL && epoch = 1UL
                    let dir = tempDir ()

                    let! _, run, cts, lines =
                        startVc h dir [ 0; 1 ] "" [ LocalModule.create (); DoppelgangerModule.create () ]

                    use _ = cts
                    // The last slot of epoch 2 checks epoch 1 and finds key 1: the run ends without the
                    // test cancelling it.
                    let target = h.Clock.SlotStart(3UL * uint64 slotsPerEpoch - 1UL) + TimeSpan.FromSeconds 1.0
                    h.Time.Advance(target - h.Time.GetUtcNow())
                    let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 20.0))

                    Expect.isTrue
                        (Object.ReferenceEquals(winner, run))
                        $"the VC stopped; log:\n{String.Join('\n', lines)}"

                    match run.Result with
                    | Ok() -> failtest "the run must end with an error"
                    | Error e ->
                        Expect.stringContains e "DOPPELGANGER" "reason"
                        Expect.stringContains e (pubkeyOf 1).Hex "key"
                        Expect.stringContains e "epoch 1" "epoch"

                    Expect.isEmpty h.Node.Submissions "nothing signed"
                })
        ]
