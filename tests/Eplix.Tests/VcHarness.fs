/// A scheduler over one or more fake beacon nodes, with the Gloas duties when the chain schedules
/// Gloas, for the fork boundary and beacon node tests. Built like GloasTests.start, with more knobs.
module Eplix.Tests.VcHarness

open System
open System.Collections.Concurrent
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Gloas
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let feeHex = "0x00000000000000000000000000000000000000aa"

/// A harness for any preset, slot length and Gloas epoch; `extra` adds or replaces spec values.
let harnessFor (presetBase: string) (seconds: int) (spe: int) (gloasEpoch: uint64) (extra: (string * string) list) =
    let node = new FakeBeaconNode(genesisTime, seconds, spe, presetBase)
    node.GloasEpoch <- gloasEpoch

    let time =
        FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime) + TimeSpan.FromSeconds 0.5)

    let values = Map.ofList (specValuesPreset presetBase seconds spe gloasEpoch @ extra)

    let spec =
        match ChainSpec.parse values with
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

/// The minimal harness (6 s slots, 8 slots an epoch) with Gloas at `gloasEpoch`.
let gloasHarness (gloasEpoch: uint64) = harnessFor "minimal" secondsPerSlot slotsPerEpoch gloasEpoch []

/// Another fake node on the same chain as the harness's node.
let extraNode (h: Harness) =
    let n =
        new FakeBeaconNode(
            genesisTime,
            int h.Spec.SlotDuration.TotalSeconds,
            int h.Spec.SlotsPerEpoch,
            h.Spec.PresetBase
        )

    n.GloasEpoch <- h.Node.GloasEpoch
    n

let addValidators (nodes: FakeBeaconNode list) (count: int) =
    for n in nodes do
        for i in 0 .. count - 1 do
            n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

type Vc =
    {
        Run: Task
        Db: SlashingDb
        Lines: ConcurrentQueue<string>
        Scheduler: DutyScheduler
        Gloas: GloasDuties option
        Nodes: BeaconNodes
        Registry: KeyRegistry
        SlotMarks: SlotMarks
        Pipeline: Pipeline
        Core: CoreServices
        Cts: CancellationTokenSource
    }

    member r.Stop() =
        task {
            r.Cts.Cancel()
            do! r.Run.WaitAsync(TimeSpan.FromSeconds 20.0)
            (r.Db :> IDisposable).Dispose()
            (r.SlotMarks :> IDisposable).Dispose()
        }

    member r.Log = String.Join("\n", r.Lines)

type VcOptions =
    {
        Keys: int list
        UseEvents: bool
        Threshold: int
        /// More fake nodes after the harness's own (node 0).
        Extra: FakeBeaconNode list
        DbPath: string option
        SlotMarksPath: string option
        /// Roles per node, node 0 first. None: every role on every node.
        Roles: NodeRole list option
        /// Runs at each epoch start after the key refresh.
        OnEpoch: BeaconNodes -> Epoch -> CancellationToken -> Task
        /// Duty extensions to add, built over the harness's core services.
        Extensions: (CoreServices -> DutyExtension) list
        /// Selection hooks (as the Obol module sets them).
        Selections: SelectionHooks option
    }

let defaults =
    {
        Keys = [ 0..7 ]
        UseEvents = false
        Threshold = 1
        Extra = []
        DbPath = None
        SlotMarksPath = None
        Roles = None
        OnEpoch = fun _ _ _ -> Task.CompletedTask
        Extensions = []
        Selections = None
    }

/// Starts the scheduler (with the Gloas duties when the spec schedules Gloas) over local keys.
let startVc (h: Harness) (o: VcOptions) =
    let clients =
        (h.Node :: o.Extra)
        |> List.mapi (fun i n ->
            BeaconClient(new HttpClient(n, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

    let log, lines = Log.memory ()

    let nodes =
        match o.Roles with
        | Some roles -> BeaconNodes(clients, o.Threshold, h.Clock.Time, log, roles = roles)
        | None -> BeaconNodes(clients, o.Threshold, h.Clock.Time, log)

    for c in clients do
        nodes.MarkReady c

    let dbPath = defaultArg o.DbPath (Path.Combine(tempDir (), "s.db"))

    let db =
        match SlashingDb.Open(new FileMarkFile(dbPath), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let backend =
        LocalBackend.create "local" [ for i in o.Keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    let registry = KeyRegistry()

    for i in o.Keys do
        registry.Add(pubkeyOf i, backend) |> ignore

    let slotMarks =
        match
            SlotMarks.Open(
                new FileMarkFile(defaultArg o.SlotMarksPath (Path.Combine(tempDir (), "slot-marks.db"))),
                gvr
            )
        with
        | Ok m -> m
        | Error e -> failwith e

    let pipeline = Pipeline(db, registry, h.Clock.Time, log, slotMarks)

    let defaults': KeyDefaults =
        {
            FeeRecipient = ValueSome feeHex
            Graffiti = "eplix"
            GasLimit = 60_000_000UL
        }

    let refresh (ct: CancellationToken) : Task =
        task {
            let! _ = refreshEmpty ValueNone nodes registry db log ct
            ()
        }

    let core: CoreServices =
        {
            Spec = h.Spec
            Genesis =
                {
                    GenesisTime = genesisTime
                    GenesisValidatorsRoot = gvr
                    GenesisForkVersion = h.Spec.Forks[0].Version
                }
            Clock = h.Clock
            Nodes = nodes
            Registry = registry
            Pipeline = pipeline
            Slashing = db
            Defaults = defaults'
            Graffiti = GraffitiService.Plain(registry, defaults'.Graffiti)
            Log = log
            DataDir = tempDir ()
            RegisterBackend = fun _ -> Task.FromResult()
            RefreshKeys = refresh
            OnEpoch = ignore
            Shutdown = ignore
            Stopping = CancellationToken.None
            SetKeystores = ignore
            Keystores = fun () -> ValueNone
            SetRemoteKeys = ignore
            RemoteKeys = fun () -> ValueNone
            AddDutyExtension = ignore
            SetBuilder = ignore
            Builder = fun () -> ValueNone
            SetSelections = ignore
            HaPeer = false
        }

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
                UseEvents = o.UseEvents
                OnSlotDone = h.Waiter.Done
                OnEpoch =
                    fun e ct ->
                        task {
                            do! refresh ct
                            do! o.OnEpoch nodes e ct
                        }
                Defaults = defaults'
            }
        )

    let gloas =
        if h.Spec.IsScheduled Gloas then
            let g = GloasDuties(core, Settings.Default)
            scheduler.AddExtension g.Extension
            Some g
        else
            None

    for x in o.Extensions do
        scheduler.AddExtension(x core)

    o.Selections |> Option.iter scheduler.SetSelections
    let cts = new CancellationTokenSource()

    {
        Run = scheduler.Run cts.Token
        Db = db
        Lines = lines
        Scheduler = scheduler
        Gloas = gloas
        Nodes = nodes
        Registry = registry
        SlotMarks = slotMarks
        Pipeline = pipeline
        Core = core
        Cts = cts
    }

/// Polls a condition in real time (the fake clock does not move on its own), 20 s at most.
let waitUntil (vc: Vc) (what: string) (cond: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what vc.Log
    }

let advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

let postsOf (n: FakeBeaconNode) (suffix: string) =
    n.Posts |> Seq.filter (fun (p, _) -> p.EndsWith suffix) |> Seq.map snd |> List.ofSeq

let jsonItems (body: string) =
    use d = JsonDocument.Parse body
    [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

let verifySig (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let versionOf (spec: ChainSpec) (name: ForkName) = (spec.Forks |> Array.find (fun f -> f.Name = name)).Version

/// Moves the clock 100 ms into the slot, then sends head events for it until the slot is done (the
/// event stream connects in the background), before the attestation due time.
let headUntilDone (h: Harness) (slot: Slot) (emit: Slot -> unit) =
    task {
        let now = h.Time.GetUtcNow()
        let target = h.Clock.SlotStart slot + TimeSpan.FromMilliseconds 100.0

        if target > now then
            h.Time.Advance(target - now)

        let waiter = h.Waiter.Wait slot
        let mutable n = 0

        while not waiter.IsCompleted && n < 500 do
            emit slot
            do! Task.Delay 20
            n <- n + 1

        do! waiter
    }
