/// End to end on a fake clock: fake beacon node -> duties -> slashing DB -> local backend -> submit.
module Eplix.Tests.SchedulerTests

open System
open System.Collections.Concurrent
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode

let secondsPerSlot = 6
let slotsPerEpoch = 8
let genesisTime = 1_700_000_000UL

let secretOf (i: int) =
    let b = Array.zeroCreate<byte> 32
    b[31] <- byte (i + 1)
    b[30] <- 0x42uy
    b

let pubkeyOf i = PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i)))

/// Waits for a slot to finish, with a real-time limit so a hang fails the test.
type SlotWaiter() =
    let done' = ConcurrentDictionary<Slot, TaskCompletionSource>()

    let get s =
        done'.GetOrAdd(s, fun _ -> TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously))

    member _.Done(s: Slot) = (get s).TrySetResult() |> ignore

    member _.Wait(s: Slot) =
        task {
            let t = (get s).Task
            let! winner = Task.WhenAny(t, Task.Delay(TimeSpan.FromSeconds 20.0))

            if winner <> t then
                failtestf "slot %d did not finish" s
        }

type Harness =
    {
        Node: FakeBeaconNode
        Time: FakeTimeProvider
        Spec: ChainSpec
        Clock: SlotClock
        Waiter: SlotWaiter
    }

    member h.SlotDue(slot: Slot) = h.Clock.SlotStart slot + h.Spec.AttestationDue slot

    /// Moves the clock to the due time of each slot in turn and waits for the VC to finish it.
    member h.RunSlots(first: Slot, last: Slot) =
        task {
            for s in first..last do
                let target = h.SlotDue s + TimeSpan.FromMilliseconds 1.0
                let now = h.Time.GetUtcNow()

                if target > now then
                    h.Time.Advance(target - now)

                do! h.Waiter.Wait s
        }

let harness () =
    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

    let time =
        FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime) + TimeSpan.FromSeconds 0.5)

    let spec =
        match ChainSpec.parse (Map.ofList (specValues secondsPerSlot slotsPerEpoch)) with
        | Ok s -> s
        | Error e -> failwith e

    let clock =
        SlotClock(DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime), spec.SlotDuration, spec.SlotsPerEpoch, time)

    {
        Node = node
        Time = time
        Spec = spec
        Clock = clock
        Waiter = SlotWaiter()
    }

/// Runner.run for tests whose keys sign from epoch 0: the keys allow_start_without_history
/// allows (keys 0 to 15 for "all") first get an empty slashing record in the data dir (tests
/// only; the VC itself writes floor records). Skipped while another
/// VC holds the data dir, or when its DB is for another genesis validators root.
let rec runSeeded (opts: RunOptions) (ct: CancellationToken) =
    match opts.Config.AllowStartWithoutHistory with
    | AllowStartWithoutHistory.Nobody -> runSeededKeys [] opts ct
    | AllowStartWithoutHistory.All -> runSeededKeys [ for i in 0..15 -> pubkeyOf i ] opts ct
    | AllowStartWithoutHistory.Keys ks -> runSeededKeys (List.ofSeq ks) opts ct

/// runSeeded with the keys to seed named.
and runSeededKeys (keys: PubKey list) (opts: RunOptions) (ct: CancellationToken) =
    if not keys.IsEmpty then
        match DataDir.Acquire(opts.Config.DataDir, Log.none) with
        | Error _ -> ()
        | Ok dir ->
            use _ = dir

            match SlashingDb.Open(new FileMarkFile(dir.SlashingDbPath), gvr) with
            | Ok db ->
                use _ = db
                db.RegisterKeys [ for k in keys -> k, KeyOrigin.StartedEmpty ] |> ignore
            | Error _ -> ()

    Runner.run opts ct

/// Starts a scheduler over a slashing DB file and keys routed to the given backends.
let startSchedulerWith
    (h: Harness)
    (dbPath: string)
    (routes: (PubKey * Backend) list)
    (useEvents: bool)
    (ct: CancellationToken)
    =
    task {
        let http = new HttpClient(h.Node, false)
        let beacon = BeaconClient(http, Uri "http://bn.test", TimeSpan.FromSeconds 5.0)
        let nodes = BeaconNodes([ beacon ], 1, h.Time, Log.none)

        let db =
            match SlashingDb.Open(new FileMarkFile(dbPath), gvr) with
            | Ok db -> db
            | Error e -> failwith e

        let registry = KeyRegistry()

        for key, backend in routes do
            registry.Add(key, backend) |> ignore

        let log, lines = Log.memory ()
        let pipeline = Pipeline(db, registry, h.Time, log)

        let scheduler =
            DutyScheduler(
                h.Spec,
                gvr,
                h.Clock,
                nodes,
                registry,
                pipeline,
                log,
                {
                    UseEvents = useEvents
                    OnSlotDone = h.Waiter.Done
                    OnEpoch =
                        fun _ ct ->
                            task {
                                let! _ = refreshEmpty ValueNone nodes registry db log ct
                                ()
                            }
                    Defaults =
                        {
                            FeeRecipient = ValueNone
                            Graffiti = ""
                            GasLimit = 60_000_000UL
                        }
                }
            )

        let run = scheduler.Run ct
        return run, db, lines, scheduler
    }

/// Starts a scheduler over a slashing DB file and the given local keys.
let startScheduler (h: Harness) (dbPath: string) (keys: int list) (useEvents: bool) (ct: CancellationToken) =
    let backend =
        LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    startSchedulerWith h dbPath [ for i in keys -> pubkeyOf i, backend ] useEvents ct

let verifySubmission (h: Harness) (s: Submission) =
    let v = h.Node.Validators[int s.AttesterIndex]
    let domain = Signing.domainAt h.Spec gvr h.Spec.DomainBeaconAttester s.Data.Target.Epoch
    let signingRoot = Signing.computeSigningRoot (Codec.hashAttestationData s.Data) domain
    Bls.verify (ReadOnlySpan v.PubKey.Bytes) (ReadOnlySpan signingRoot.Bytes) (ReadOnlySpan s.Signature.Bytes)

[<Tests>]
let clockTests =
    testList
        "slot clock"
        [
            testT "a wait for a genesis more than 49.7 days away runs in steps and ends at genesis" (fun () ->
                task {
                    let time = FakeTimeProvider(DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
                    let genesis = time.GetUtcNow().AddDays 100.0
                    let clock = SlotClock(genesis, TimeSpan.FromSeconds 12.0, 32UL, time)
                    let wait = clock.WaitUntil(genesis, CancellationToken.None)
                    Expect.isFalse wait.IsFaulted $"no exception: %A{wait.Exception}"
                    let mutable days = 0

                    while not wait.IsCompleted && days < 200 do
                        time.Advance(TimeSpan.FromDays 1.0)
                        do! Task.Delay 5
                        days <- days + 1

                    Expect.isTrue wait.IsCompletedSuccessfully $"done: %A{wait.Status}"
                    Expect.isGreaterThanOrEqual days 100 "not before genesis"
                })
        ]

[<Tests>]
let recentTests =
    testList
        "recent queue"
        [
            test "keeps the last items only, oldest first" {
                let q = RecentQueue<int>(4)

                for i in 1..10 do
                    q.Enqueue i

                Expect.equal (List.ofSeq q) [ 7; 8; 9; 10 ] "the last four"
                Expect.equal q.Count 4 "bounded"
            }
            testT "many writers never leave more than the capacity" (fun () ->
                task {
                    let q = RecentQueue<int>(RecentQueue.Kept)

                    let writers =
                        [|
                            for w in 0..3 ->
                                Task.Run(fun () ->
                                    for i in 1..5000 do
                                        q.Enqueue(w * 10000 + i))
                        |]

                    do! Task.WhenAll writers
                    Expect.equal q.Count RecentQueue.Kept "bounded"
                })
        ]

[<Tests>]
let tests =
    testSequenced
    <| testList
        "scheduler e2e"
        [
            testT "16 keys attest every duty for 4 epochs" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..15 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    use cts = new CancellationTokenSource()
                    let dir = tempDir ()

                    let! run, db, lines, scheduler =
                        startScheduler h (Path.Combine(dir, "slashing.db")) [ 0..15 ] false cts.Token

                    let lastSlot = uint64 (4 * slotsPerEpoch - 1)
                    do! h.RunSlots(0UL, lastSlot)
                    cts.Cancel()
                    do! run
                    let subs = List.ofSeq h.Node.Submissions
                    // Every validator has one duty per epoch (slot = index mod 8).
                    Expect.equal
                        subs.Length
                        (16 * 4)
                        $"one attestation per key and epoch; log: {String.Join('\n', lines)}"

                    for s in subs do
                        Expect.isTrue (verifySubmission h s) $"signature of {s.AttesterIndex} at slot {s.Slot}"
                        let v = h.Node.Validators[int s.AttesterIndex]
                        Expect.equal s.Slot (h.Node.DutySlot(v, s.Slot / uint64 slotsPerEpoch)) "duty slot"
                        Expect.equal s.CommitteeIndex (s.AttesterIndex % 2UL) "committee index from the duty"
                        Expect.equal s.Data (h.Node.DefaultData s.Slot) "data from the node"

                        Expect.equal
                            s.ConsensusVersion
                            (if s.Slot < uint64 slotsPerEpoch then "electra" else "fulu")
                            "fork header"
                    // The DB holds the last vote of each key.
                    for i in 0..15 do
                        let m = (db.Marks(pubkeyOf i)).Value.Attestation.Value
                        Expect.equal m.Target 3UL $"target mark of key {i}"

                    let reports = List.ofSeq scheduler.Reports

                    Expect.equal
                        (scheduler.Reports.Capacity, scheduler.Events.Capacity)
                        (RecentQueue.Kept, RecentQueue.Kept)
                        "both queues are bounded"

                    Expect.equal (reports |> List.sumBy (fun r -> r.Signed)) 64 "reports count the signatures"
                    Expect.equal (reports |> List.sumBy (fun r -> r.Failed + r.Refused)) 0 "nothing refused or failed"
                    (db :> IDisposable).Dispose()
                })

            testT "after a restart, different data for a signed slot is refused and not submitted" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()
                    let dbPath = Path.Combine(dir, "slashing.db")

                    do!
                        task {
                            use cts = new CancellationTokenSource()
                            let! run, db, _, _ = startScheduler h dbPath [ 0..7 ] false cts.Token
                            do! h.RunSlots(0UL, 7UL)
                            cts.Cancel()
                            do! run
                            (db :> IDisposable).Dispose()
                        }

                    Expect.equal h.Node.Submissions.Count 8 "epoch 0 attested"
                    // Same epoch again (the clock went back, as after a restore), with a different head.
                    h.Node.Submissions.Clear()

                    h.Node.OverrideData(
                        Some(fun slot ->
                            { h.Node.DefaultData slot with
                                BeaconBlockRoot = root 999
                            })
                    )

                    let h2 =
                        { h with
                            Time =
                                FakeTimeProvider(
                                    DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime) + TimeSpan.FromSeconds 0.5
                                )
                            Waiter = SlotWaiter()
                        }

                    let h2 =
                        { h2 with
                            Clock = SlotClock(h.Clock.GenesisTime, h.Spec.SlotDuration, h.Spec.SlotsPerEpoch, h2.Time)
                        }

                    use cts = new CancellationTokenSource()
                    let! run, db, lines, scheduler = startScheduler h2 dbPath [ 0..7 ] false cts.Token
                    do! h2.RunSlots(0UL, 7UL)
                    cts.Cancel()
                    do! run
                    Expect.equal h.Node.Submissions.Count 0 "no double votes leave the VC"
                    Expect.equal (List.ofSeq scheduler.Reports |> List.sumBy (fun r -> r.Refused)) 8 "eight refusals"
                    Expect.exists (List.ofSeq lines) (fun l -> l.Contains "double vote") "logged"
                    (db :> IDisposable).Dispose()
                })

            testT "a head event triggers the attestation before the due time" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    use cts = new CancellationTokenSource()

                    let! run, db, _, _ =
                        startScheduler h (Path.Combine(tempDir (), "slashing.db")) [ 0..7 ] true cts.Token

                    do! h.RunSlots(0UL, 1UL)
                    // Slot 2: move to 1 s into the slot (due is at 2 s), then send the head event.
                    let now = h.Time.GetUtcNow()
                    h.Time.Advance(h.Clock.SlotStart 2UL + TimeSpan.FromSeconds 1.0 - now)
                    // The event stream connects in the background; send until the slot is done.
                    let waiter = h.Waiter.Wait 2UL
                    let mutable n = 0

                    while not waiter.IsCompleted && n < 200 do
                        h.Node.EmitHead 2UL
                        do! Task.Delay 20
                        n <- n + 1

                    do! waiter
                    Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 2UL) "attested before the due time"
                    Expect.exists (List.ofSeq h.Node.Submissions) (fun s -> s.Slot = 2UL) "slot 2 submitted"
                    cts.Cancel()
                    do! run
                    (db :> IDisposable).Dispose()
                })

            testT "keys without history wait, pending or active: no beacon node status starts a key" (fun () ->
                task {
                    let h = harness ()
                    h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    h.Node.AddValidator(pubkeyOf 1, "pending_queued") |> ignore
                    let http = new HttpClient(h.Node, false)
                    let beacon = BeaconClient(http, Uri "http://bn.test", TimeSpan.FromSeconds 5.0)

                    use db =
                        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let backend =
                        LocalBackend.create
                            "local"
                            [ for i in 0..1 -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

                    let registry = KeyRegistry()

                    for i in 0..1 do
                        registry.Add(pubkeyOf i, backend) |> ignore

                    let nodes = BeaconNodes([ beacon ], 1, h.Time, Log.none)
                    nodes.MarkReady beacon

                    let! r =
                        Validators.refresh
                            testFloor
                            nodes
                            registry
                            db
                            AllowStartWithoutHistory.Nobody
                            Log.none
                            CancellationToken.None

                    Expect.isOk r "refresh"

                    Expect.equal
                        (registry.TryGet(pubkeyOf 0)).Value.State
                        KeyState.Discovered
                        "active key without history waits"

                    Expect.equal
                        (registry.TryGet(pubkeyOf 1)).Value.State
                        KeyState.Discovered
                        "pending key without history waits too"

                    Expect.isFalse (db.HasRecord(pubkeyOf 1)) "no empty record"
                })

            testT "the whole VC through Runner: config file, keystores, fake node" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        File.WriteAllText(
                            Path.Combine(ksDir, $"keystore-{i}.json"),
                            Keystore.encrypt
                                (secretOf i)
                                "secret"
                                (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32))
                                ""
                        )

                    File.WriteAllText(Path.Combine(dir, "password.txt"), "secret\n")
                    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

                    let configText =
                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                       "use_events": false, "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ] } } }"""

                    let modules = [ LocalModule.create () ]

                    match
                        Config.parse configText dir [ "local" ]
                        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                    with
                    | Error es -> failtestf "%A" es
                    | Ok config ->
                        use cts = new CancellationTokenSource()
                        let log, lines = Log.memory ()

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

                        do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))
                        cts.Cancel()
                        let! result = run
                        Expect.isOk result $"run; log: {String.Join('\n', lines)}"
                        Expect.equal h.Node.Submissions.Count 8 "4 keys, 2 epochs"

                        for s in h.Node.Submissions do
                            Expect.isTrue (verifySubmission h s) "signature"
                        // A second VC on the same data dir is refused.
                        use _lock =
                            match DataDir.Acquire(Path.Combine(dir, "data"), Log.none) with
                            | Ok d -> d
                            | Error e -> failwith e

                        Expect.isError (DataDir.Acquire(Path.Combine(dir, "data"), Log.none)) "data dir lock"
                })
        ]

let private head (slot: Slot) (block: byte) (optimistic: bool) : HeadEvent =
    {
        Slot = slot
        Block = Root.Of(Array.create 32 block)
        EpochTransition = false
        PreviousDutyDependentRoot = Root.Zero
        CurrentDutyDependentRoot = Root.Zero
        ExecutionOptimistic = optimistic
    }

/// Answers GET /eth/v1/beacon/blocks/head/root with a fixed root, optimistic or not.
type private HeadRootHandler(root: Root, optimistic: bool) =
    inherit HttpMessageHandler()

    override _.SendAsync(_req, _ct) =
        let opt = if optimistic then "true" else "false"
        let resp = new HttpResponseMessage(Net.HttpStatusCode.OK)

        resp.Content <-
            new StringContent(
                $"""{{"execution_optimistic":{opt},"data":{{"root":"{root.Hex}"}}}}""",
                Text.Encoding.UTF8,
                "application/json"
            )

        Task.FromResult resp

[<Tests>]
let headTests =
    testList
        "head-events"
        [
            test "one node: the first verified event of a slot within one slot of the clock wins" {
                let v = HeadVotes(1)

                Expect.equal
                    (v.Add(0, head 5UL 1uy false, ValueSome 5UL))
                    (HeadVote.Agreed(Root.Of(Array.create 32 1uy)))
                    "current slot"

                Expect.equal (v.Add(0, head 5UL 2uy false, ValueSome 5UL)) HeadVote.Counted "the slot has its root"

                Expect.equal
                    (v.Add(0, head 4UL 3uy false, ValueSome 5UL))
                    (HeadVote.Agreed(Root.Of(Array.create 32 3uy)))
                    "slot - 1"

                Expect.equal
                    (v.Add(0, head 6UL 4uy false, ValueSome 5UL))
                    (HeadVote.Agreed(Root.Of(Array.create 32 4uy)))
                    "slot + 1"

                for s in [ 3UL; 7UL; 100UL; UInt64.MaxValue ] do
                    match v.Add(0, head s 5uy false, ValueSome 5UL) with
                    | HeadVote.Ignored _ -> ()
                    | other -> failtestf "slot %d at clock slot 5: %A" s other

                match v.Add(0, head 0UL 5uy false, ValueNone) with
                | HeadVote.Ignored _ -> ()
                | other -> failtestf "before genesis: %A" other

                match v.Add(1, head 5UL 5uy true, ValueSome 5UL) with
                | HeadVote.Ignored why -> Expect.stringContains why "optimistic" "reason"
                | other -> failtestf "optimistic: %A" other
            }

            test "threshold 2: one node's root does not decide, two nodes on one root do" {
                let v = HeadVotes(2)
                let a, b = Root.Of(Array.create 32 1uy), Root.Of(Array.create 32 2uy)
                Expect.equal (v.Add(0, head 5UL 1uy false, ValueSome 5UL)) HeadVote.Counted "node 0 alone"
                Expect.equal (v.Add(0, head 5UL 1uy false, ValueSome 5UL)) HeadVote.Counted "the same node again"
                Expect.equal (v.Add(1, head 5UL 2uy false, ValueSome 5UL)) HeadVote.Counted "node 1 on another root"

                Expect.equal
                    (v.Add(2, head 5UL 2uy true, ValueSome 5UL))
                    (HeadVote.Ignored "the head is optimistic")
                    "optimistic does not count"

                Expect.equal (v.Add(2, head 5UL 2uy false, ValueSome 5UL)) (HeadVote.Agreed b) "nodes 1 and 2 agree"
                Expect.equal (v.Add(0, head 5UL 2uy false, ValueSome 5UL)) HeadVote.Counted "agreed once"
                // A node's vote is its latest block: node 0 moves from a to b, so a never gets two.
                Expect.equal (v.Add(0, head 6UL 1uy false, ValueSome 5UL)) HeadVote.Counted "slot 6, node 0 on a"
                Expect.equal (v.Add(0, head 6UL 2uy false, ValueSome 5UL)) HeadVote.Counted "node 0 moves to b"

                Expect.equal
                    (v.Add(1, head 6UL 1uy false, ValueSome 5UL))
                    HeadVote.Counted
                    "node 1 on a: still one vote for a"

                v.Prune 6UL

                Expect.equal
                    (v.Add(1, head 5UL 2uy false, ValueSome 5UL))
                    HeadVote.Counted
                    "slot 5 pruned: counting starts again"

                ignore a
            }

            testT "the sync head root needs threshold nodes; optimistic answers do not count" (fun () ->
                task {
                    let a, b = Root.Of(Array.create 32 1uy), Root.Of(Array.create 32 2uy)

                    let nodesOf (answers: (Root * bool) list) (threshold: int) =
                        let clients =
                            answers
                            |> List.mapi (fun i (r, o) ->
                                BeaconClient(
                                    new HttpClient(new HeadRootHandler(r, o)),
                                    Uri $"http://bn{i}.test",
                                    TimeSpan.FromSeconds 1.0
                                ))

                        BeaconNodes(clients, threshold, TimeProvider.System, Log.none)

                    let! r = (nodesOf [ a, false; b, false; a, false ] 2).HeadBlockRoot CancellationToken.None
                    Expect.equal r (Ok a) "two of three on a"
                    let! r = (nodesOf [ a, false; b, false; a, true ] 2).HeadBlockRoot CancellationToken.None
                    Expect.isError r "the second a is optimistic: no root"
                    let! r = (nodesOf [ a, true; b, false ] 1).HeadBlockRoot CancellationToken.None
                    Expect.isError r "threshold 1: the best node's optimistic head is refused, as before"
                    let! r = (nodesOf [ b, false; a, false ] 1).HeadBlockRoot CancellationToken.None
                    Expect.equal r (Ok b) "threshold 1: the best node"
                })

            testT "head events off the clock's slot, or optimistic, do not start the attestations" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startScheduler h (Path.Combine(tempDir (), "slashing.db")) [ 0..7 ] true cts.Token

                    do! h.RunSlots(0UL, 1UL)
                    let now = h.Time.GetUtcNow()
                    h.Time.Advance(h.Clock.SlotStart 2UL + TimeSpan.FromSeconds 1.0 - now)
                    let mutable n = 0

                    while h.Node.RequestCount "GET /eth/v1/events" = 0 && n < 200 do
                        do! Task.Delay 10
                        n <- n + 1
                    // Two slots ahead, and the current slot with an optimistic head.
                    let ignored () = lines |> Seq.filter (fun l -> l.Contains "ignored") |> Seq.length
                    n <- 0

                    while ignored () < 4 && n < 200 do
                        h.Node.EmitHead 4UL
                        h.Node.EmitHeadAs(2UL, h.Node.BlockRoot 2UL, true)
                        do! Task.Delay 10
                        n <- n + 1

                    Expect.isGreaterThanOrEqual (ignored ()) 4 "the events arrived and were ignored"

                    Expect.isFalse
                        (h.Node.Submissions |> Seq.exists (fun s -> s.Slot = 2UL))
                        "no attestation before the due time"
                    // A verified head for the slot starts them.
                    let waiter = h.Waiter.Wait 2UL
                    n <- 0

                    while not waiter.IsCompleted && n < 200 do
                        h.Node.EmitHead 2UL
                        do! Task.Delay 20
                        n <- n + 1

                    do! waiter
                    Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 2UL) "attested on the verified head"
                    cts.Cancel()
                    do! run
                    (db :> IDisposable).Dispose()
                })
        ]
