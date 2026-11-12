/// The whole VC through Runner: the data dir lock and the start with no beacon node.
module Eplix.Tests.RunnerTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

/// A data dir with four PBKDF2 keystores (keys 0 to 3), a password file and the fake chain's config.
let localVcDir (configYamlText: string) =
    let dir = tempDir ()
    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

    for i in 0..3 do
        File.WriteAllText(
            Path.Combine(ksDir, $"keystore-{i}.json"),
            Keystore.encrypt (secretOf i) "secret" (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) ""
        )

    File.WriteAllText(Path.Combine(dir, "password.txt"), "secret\n")
    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYamlText)
    dir

let localVcConfig (dir: string) =
    let text =
        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
             "use_events": false, "allow_start_without_history": ["all"],
             "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 } } }"""

    let modules = [ LocalModule.create () ]

    match
        Config.parse text dir [ "local" ]
        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
    with
    | Error es -> failtestf "%A" es
    | Ok config -> config, modules

[<Tests>]
let tests =
    testSequenced
    <| testList
        "runner"
        [
            test "a second open of the data dir fails" {
                let dir = Path.Combine(tempDir (), "data")

                let first =
                    match DataDir.Acquire(dir, Log.none) with
                    | Ok d -> d
                    | Error e -> failtest e

                match DataDir.Acquire(dir, Log.none) with
                | Ok d ->
                    (d :> IDisposable).Dispose()
                    failtest "two opens of one data dir"
                | Error e -> Expect.stringContains e "in use by another process" "the error names the cause"

                (first :> IDisposable).Dispose()

                match DataDir.Acquire(dir, Log.none) with
                | Ok d -> (d :> IDisposable).Dispose()
                | Error e -> failtestf "free again after the first closed: %s" e
            }

            testT "a second VC on a running VC's data dir does not start" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = localVcConfig dir
                    use cts = new CancellationTokenSource()
                    let ready = TaskCompletionSource()

                    let options (log: Log) onReady =
                        {
                            Config = config
                            Modules = modules
                            Http = new HttpClient(h.Node, false)
                            Time = h.Time
                            Log = log
                            OnSlotDone = h.Waiter.Done
                            OnReady = onReady
                        }

                    let log, lines = Log.memory ()
                    let first = runSeeded (options log (fun _ _ -> ready.TrySetResult() |> ignore)) cts.Token
                    do! ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                    use second = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
                    let! r = runSeeded (options Log.none (fun _ _ -> failtest "the second VC got ready")) second.Token

                    match r with
                    | Error e -> Expect.stringContains e "in use by another process" "refused with the reason"
                    | Ok() -> failtest "the second VC ran"
                    // The first VC still attests, once per key and epoch.
                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch - 1))
                    cts.Cancel()
                    let! result = first
                    Expect.isOk result $"first VC; log: {String.Join('\n', lines)}"
                    Expect.equal h.Node.Submissions.Count 4 "one attestation per key"
                })

            testT "the node's GLOAS_FORK_EPOCH changes while running" (fun () ->
                task {
                    let h = harness ()
                    h.Node.GloasEpoch <- 3UL

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = localVcDir (configYamlGloas secondsPerSlot slotsPerEpoch 3UL)

                    let text =
                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                       "use_events": false, "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
                                    "gloas": { } } }"""

                    let modules = [ LocalModule.create (); Eplix.Gloas.GloasModule.create () ]

                    let config =
                        match
                            Config.parse text dir [ "local"; "gloas" ]
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok c -> c

                    let log, lines = Log.memory ()
                    use cts = new CancellationTokenSource()

                    let run =
                        runSeeded
                            {
                                Config = config
                                Modules = modules
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = log
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> ()
                            }
                            cts.Token

                    do! h.RunSlots(0UL, uint64 slotsPerEpoch)
                    // The node now schedules Gloas at epoch 5: another chain than the pinned one.
                    h.Node.GloasEpoch <- 5UL
                    let before = h.Node.Submissions.Count
                    let next = h.Clock.SlotStart(2UL * uint64 slotsPerEpoch) + TimeSpan.FromSeconds 3.0
                    h.Time.Advance(next - h.Time.GetUtcNow())
                    let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 20.0))

                    Expect.isTrue
                        (Object.ReferenceEquals(winner, run))
                        $"the VC stopped; log: {String.Join('\n', lines)}"

                    match run.Result with
                    | Ok() -> failtest "the run must end with an error"
                    | Error e -> Expect.stringContains e "GLOAS_FORK_EPOCH" "names the value"

                    Expect.isTrue
                        (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "GLOAS_FORK_EPOCH"))
                        "logged as an error"

                    Expect.isTrue
                        (h.Node.Submissions |> Seq.forall (fun s -> s.Slot < 2UL * uint64 slotsPerEpoch))
                        "nothing signed from epoch 2"

                    Expect.isGreaterThanOrEqual before 4 "epoch 0 was attested"
                })

            testT
                "a module whose stop throws does not keep the others from stopping; the run ends with an error"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                        let config, modules = localVcConfig dir
                        let stopped = Collections.Concurrent.ConcurrentQueue<string>()

                        let extra (name: string) (stop: unit -> Task) : Module =
                            {
                                Name = name
                                Configure = fun _ -> Ok()
                                Check = fun _ -> Ok ""
                                Start =
                                    fun _ _ ->
                                        let stopIt () =
                                            stopped.Enqueue name
                                            stop ()

                                        Task.FromResult(Ok { Stop = stopIt })
                            }

                        let mods =
                            modules
                            @ [
                                extra "throws" (fun () -> failwith "stop broke")
                                extra "faults" (fun () -> Task.FromException(InvalidOperationException "stop faulted"))
                                extra "fine" (fun () -> Task.CompletedTask)
                            ]

                        let log, lines = Log.memory ()
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)

                        let! r =
                            Runner.runWith
                                {
                                    Config = config
                                    Modules = mods
                                    Http = new HttpClient(h.Node, false)
                                    Time = h.Time
                                    Log = log
                                    OnSlotDone = h.Waiter.Done
                                    OnReady = fun _ _ -> ()
                                }
                                cts.Token
                                (fun _ _ -> Task.FromResult(Ok()))

                        Expect.equal
                            (List.ofSeq stopped)
                            [ "throws"; "faults"; "fine" ]
                            $"every module asked to stop; log: {String.Join('\n', lines)}"

                        match r with
                        | Ok() -> failtest "a failed stop must make the run an error"
                        | Error e ->
                            Expect.stringContains e "module throws failed to stop: stop broke" "names the first module"
                            Expect.stringContains e "module faults failed to stop: stop faulted" "names the second"

                        Expect.isTrue
                            (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "stop broke"))
                            "logged as an error"
                    })

            testT
                "a module epoch hook that never ends: later epochs still refresh the keys and skip the hooks"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                        let config, modules = localVcConfig dir
                        let never = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                        let seen = Collections.Concurrent.ConcurrentQueue<uint64>()

                        let hook (e: uint64) : Task =
                            seen.Enqueue e
                            if e = 1UL then never.Task else Task.CompletedTask

                        let hung: Module =
                            {
                                Name = "hung"
                                Configure = fun _ -> Ok()
                                Check = fun _ -> Ok ""
                                Start =
                                    fun core _ ->
                                        core.OnEpoch(fun e _ -> hook e)
                                        Task.FromResult(Ok { Stop = fun () -> Task.CompletedTask })
                            }

                        let log, lines = Log.memory ()
                        use cts = new CancellationTokenSource()

                        let run =
                            runSeeded
                                {
                                    Config = config
                                    Modules = modules @ [ hung ]
                                    Http = new HttpClient(h.Node, false)
                                    Time = h.Time
                                    Log = log
                                    OnSlotDone = h.Waiter.Done
                                    OnReady = fun _ _ -> ()
                                }
                                cts.Token

                        let refreshes () = h.Node.RequestCount "POST /eth/v1/beacon/states/head/validators"

                        let skipped () =
                            lines
                            |> Seq.exists (fun l ->
                                l.StartsWith "ERROR"
                                && l.Contains "epoch 2: a module epoch hook of an earlier epoch is still running")

                        do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))
                        let before = refreshes ()
                        do! h.RunSlots(uint64 (2 * slotsPerEpoch), uint64 (2 * slotsPerEpoch + 1))
                        let sw = Diagnostics.Stopwatch.StartNew()

                        while not (skipped ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                            do! Task.Delay 10

                        Expect.isTrue
                            (skipped ())
                            $"epoch 2 skips the hooks with an error; log: {String.Join('\n', lines)}"

                        Expect.isGreaterThan (refreshes ()) before "epoch 2 refreshed the keys"
                        Expect.isFalse (Seq.contains 2UL seen) "the hook did not run twice at once"
                        never.TrySetResult() |> ignore
                        cts.Cancel()
                        let! r = run
                        Expect.isOk r $"log: {String.Join('\n', lines)}"
                    })

            test "snapshots never overlap" {
                let active = ref 0
                let most = ref 0

                let gate =
                    SnapshotGate(fun _ ->
                        let n = Interlocked.Increment &active.contents
                        lock most (fun () -> most.Value <- max most.Value n)
                        Thread.Sleep 20
                        Interlocked.Decrement &active.contents |> ignore)

                let runs = [| for e in 1UL .. 8UL -> Task.Run(fun () -> gate.Run e |> ignore) |]
                Expect.isTrue (Task.WaitAll(runs, TimeSpan.FromSeconds 20.0)) "all ran"
                Expect.equal most.Value 1 "one snapshot at a time"
            }

            test "no snapshot after Close; Close waits for the one being written" {
                use inside = new ManualResetEventSlim(false)
                use go = new ManualResetEventSlim(false)
                let written = Collections.Concurrent.ConcurrentQueue<uint64>()

                let gate =
                    SnapshotGate(fun e ->
                        written.Enqueue e

                        if e = 1UL then
                            inside.Set()
                            go.Wait(TimeSpan.FromSeconds 10.0) |> ignore)

                let first = Task.Run(fun () -> gate.Run 1UL)
                Expect.isTrue (inside.Wait(TimeSpan.FromSeconds 10.0)) "the first snapshot runs"
                let closing = Task.Run(fun () -> gate.Close())
                Thread.Sleep 100
                Expect.isFalse closing.IsCompleted "Close waits for the snapshot being written"
                go.Set()
                Expect.isTrue (closing.Wait(TimeSpan.FromSeconds 10.0)) "closed"
                Expect.isTrue first.Result "the first snapshot was written"
                Expect.isFalse (gate.Run 2UL) "none after Close"
                Expect.equal (List.ofSeq written) [ 1UL ] "only the first"
            }

            testT "epoch work that outlives the run writes no snapshot after the stop" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)

                    let text =
                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                       "use_events": false, "allow_start_without_history": ["all"], "snapshot_interval_epochs": 1,
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 } } }"""

                    let modules = [ LocalModule.create () ]

                    let config =
                        match
                            Config.parse text dir [ "local" ]
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok c -> c
                    // The epoch 1 hook ignores the stop and ends only when the test says so.
                    let entered = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                    let release = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

                    let hung: Module =
                        {
                            Name = "hung"
                            Configure = fun _ -> Ok()
                            Check = fun _ -> Ok ""
                            Start =
                                fun core _ ->
                                    core.OnEpoch(fun e _ ->
                                        if e = 1UL then
                                            entered.TrySetResult() |> ignore
                                            release.Task
                                        else
                                            Task.CompletedTask)

                                    Task.FromResult(Ok { Stop = fun () -> Task.CompletedTask })
                        }

                    let log, lines = Log.memory ()
                    let schedulerRun = ref Task.CompletedTask
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 30.0)
                    // The body stops the scheduler once the hook hangs and returns without waiting for
                    // it, so the run ends (and closes the DB) while epoch 1's work still runs.
                    let run =
                        Runner.runWith
                            {
                                Config = config
                                Modules = modules @ [ hung ]
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = log
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> ()
                            }
                            cts.Token
                            (fun _ scheduler ->
                                task {
                                    let stop = new CancellationTokenSource()
                                    schedulerRun.Value <- scheduler.Run stop.Token
                                    do! entered.Task
                                    stop.Cancel()
                                    return Ok()
                                })

                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch - 1))
                    let epoch1 = h.SlotDue(uint64 slotsPerEpoch) + TimeSpan.FromMilliseconds 1.0
                    h.Time.Advance(epoch1 - h.Time.GetUtcNow())
                    let! r = run.WaitAsync(TimeSpan.FromSeconds 20.0)
                    Expect.isOk r $"run; log: {String.Join('\n', lines)}"
                    let atStop = lines.Count
                    release.SetResult()

                    try
                        do! schedulerRun.Value.WaitAsync(TimeSpan.FromSeconds 20.0)
                    with _ ->
                        ()

                    let after = lines |> Seq.skip atStop |> List.ofSeq

                    let bad =
                        after
                        |> List.filter (fun l ->
                            l.Contains "snapshot" || l.Contains "compaction" || l.Contains "epoch 1 start")

                    Expect.isEmpty bad $"no snapshot after the stop; log: {String.Join('\n', lines)}"
                })

            testT "a chain before Electra does not start" (fun () ->
                task {
                    let h = harness ()
                    h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    // Deneb at genesis, Electra and Fulu not scheduled.
                    let far = string UInt64.MaxValue
                    h.Node.SpecOverride <- [ "ELECTRA_FORK_EPOCH", far; "FULU_FORK_EPOCH", far ]

                    let yaml =
                        (configYaml secondsPerSlot slotsPerEpoch)
                            .Replace("ELECTRA_FORK_EPOCH: 0", $"ELECTRA_FORK_EPOCH: {far}")
                            .Replace("FULU_FORK_EPOCH: 1", $"FULU_FORK_EPOCH: {far}")

                    let dir = localVcDir yaml
                    let config, modules = localVcConfig dir
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)

                    let! r =
                        runSeeded
                            {
                                Config = config
                                Modules = modules
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = Log.none
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> failtest "a pre-Electra chain got ready"
                            }
                            cts.Token

                    match r with
                    | Error e -> Expect.stringContains e "before Electra" "refused with the reason"
                    | Ok() -> failtest "ran on a pre-Electra chain"

                    Expect.isEmpty h.Node.Submissions "signed nothing"
                })

            testT "starts with no node and attests once one comes up" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // The node is down: every request fails, until slot 5.
                    h.Node.Fail <- fun _ -> true
                    let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = localVcConfig dir
                    use cts = new CancellationTokenSource()
                    let log, lines = Log.memory ()
                    let ready = TaskCompletionSource()

                    let run =
                        runSeeded
                            {
                                Config = config
                                Modules = modules
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = log
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> ready.TrySetResult() |> ignore
                            }
                            cts.Token
                    // 30 s on the fake clock in 1 s steps: the start retries with backoff.
                    for _ in 1..30 do
                        h.Time.Advance(TimeSpan.FromSeconds 1.0)
                        do! Task.Delay 10

                    Expect.isFalse ready.Task.IsCompleted "not ready without a node"
                    Expect.isFalse run.IsCompleted $"still trying; log: {String.Join('\n', lines)}"
                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "retrying")) "logs the retries"
                    h.Node.Fail <- fun _ -> false
                    // The next retry (at most 16 s away) finds the node.
                    for _ in 1..20 do
                        if not ready.Task.IsCompleted then
                            h.Time.Advance(TimeSpan.FromSeconds 1.0)
                            do! Task.Delay 20

                    do! ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                    let first = (h.Clock.CurrentSlot).Value + 1UL
                    do! h.RunSlots(first, uint64 (2 * slotsPerEpoch - 1))
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result $"run; log: {String.Join('\n', lines)}"
                    // Validators 0 to 3 attest in slots 8 to 11 of epoch 1.
                    let epoch1 =
                        h.Node.Submissions
                        |> Seq.filter (fun s -> s.Slot >= 8UL)
                        |> Seq.map (fun s -> s.AttesterIndex)
                        |> Seq.sort
                        |> List.ofSeq

                    Expect.equal epoch1 [ 0UL .. 3UL ] "every key attests once the node is up"
                })
        ]
