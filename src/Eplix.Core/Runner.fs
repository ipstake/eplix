/// Start-up and run of the VC: config, beacon node checks, slashing DB, modules, scheduler.
/// In the core so tests can run the whole VC in process against fake beacon nodes.
namespace Eplix

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Slashing

/// The data directory: the slashing DB and an exclusive lock, so one VC process uses it at a time.
type DataDir private (path: string, lockFile: FileStream) =
    member _.Path = path
    member _.SlashingDbPath = Path.Combine(path, "slashing.db")
    /// Marks for PTC votes and envelopes, apart from slashing.db.
    member _.SlotMarksPath = Path.Combine(path, "slot-marks.db")
    /// Genesis time and slot timing of the first start; the root is in slashing.db.
    member _.AnchorPath = Path.Combine(path, "chain-anchor")

    /// The genesis validators root in the slashing DB's header, when the DB exists and has one.
    member this.SlashingDbRoot: Root voption =
        try
            let file = FileInfo this.SlashingDbPath

            if not file.Exists || file.Length < int64 Record.size then
                ValueNone
            else
                let header = Array.zeroCreate<byte> Record.size

                (use f = File.OpenRead this.SlashingDbPath
                 f.ReadExactly(header, 0, header.Length))

                if Record.kind header = Record.KindHeader then
                    ValueSome(Root.Of(Record.payload header 32))
                else
                    ValueNone
        with :? IOException ->
            ValueNone

    /// Creates the data dir with mode 0700, or sets 0700 on one that exists and lets the group
    /// or others in, with one line in the log: it holds the keymanager token, imported keys and
    /// the slashing DB. Throws UnauthorizedAccessException when the mode cannot be set.
    static member Prepare(path: string, log: Log) =
        let owner = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute

        if OperatingSystem.IsWindows() then
            Directory.CreateDirectory path |> ignore
        elif not (Directory.Exists path) then
            Directory.CreateDirectory(path, owner) |> ignore
        else
            let mode = File.GetUnixFileMode path

            if int mode &&& 0o077 <> 0 then
                try
                    File.SetUnixFileMode(path, owner)

                    log.Info $"data dir {path}: mode {Convert.ToString(int mode, 8)} let other users in; set to 700"
                with
                | :? UnauthorizedAccessException
                | :? IOException as e ->
                    raise (
                        UnauthorizedAccessException(
                            $"mode {Convert.ToString(int mode, 8)} lets other users in and cannot be set to 700 ({e.Message})"
                        )
                    )

    static member Acquire(path: string, log: Log) : Result<DataDir, string> =
        try
            DataDir.Prepare(path, log)
            let lockPath = Path.Combine(path, "eplix.lock")
            // FileShare.None takes an exclusive flock on Unix.
            let fs = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)
            Ok(new DataDir(path, fs))
        with
        | :? IOException as e -> Error $"data dir {path} is in use by another process ({e.Message})"
        | :? UnauthorizedAccessException as e -> Error $"data dir {path}: {e.Message}"

    interface IDisposable with
        member _.Dispose() = lockFile.Dispose()

/// The periodic snapshots of the slashing DB and the slot marks: one at a time, and none after
/// Close. Epoch work can outlive the scheduler's stop, and the files close at the stop.
type SnapshotGate(snapshot: Epoch -> unit) =
    let gate = obj ()
    let mutable closed = false

    /// Writes the snapshot for `epoch` unless closed; false when closed.
    member _.Run(epoch: Epoch) : bool =
        lock gate (fun () ->
            if closed then
                false
            else
                snapshot epoch
                true)

    /// No snapshot from here on. Waits for a snapshot that is being written.
    member _.Close() = lock gate (fun () -> closed <- true)

type RunOptions =
    {
        Config: CoreConfig
        Modules: Module list
        Http: HttpClient
        Time: TimeProvider
        Log: Log
        /// Hooks for tests; the binary passes defaults.
        OnSlotDone: Slot -> unit
        /// Called once the VC is ready, with its services (tests use it to reach the scheduler's parts).
        OnReady: CoreServices -> DutyScheduler -> unit
    }

module Runner =
    let private retryUntilOk
        (log: Log)
        (time: TimeProvider)
        (what: string)
        (f: unit -> Task<Result<'T, ApiError>>)
        (ct: CancellationToken)
        =
        task {
            let mutable result = ValueNone
            let mutable delay = TimeSpan.FromSeconds 1.0

            while result.IsNone do
                ct.ThrowIfCancellationRequested()

                match! f () with
                | Ok v -> result <- ValueSome v
                | Error e ->
                    log.Warn $"{what}: {e.Describe}; retrying in {delay.TotalSeconds} s"
                    do! Task.Delay(delay, time, ct)
                    delay <- min (delay * 2.0) (TimeSpan.FromSeconds 16.0)

            return result.Value
        }

    /// Configures every module. Fails on the first errors.
    let configure (config: CoreConfig) (modules: Module list) (baseDir: string) : Result<unit, string list> =
        let errors =
            [
                if modules.IsEmpty then
                    "this build links no backend module"
                for m in modules do
                    match m.Configure(Config.section config m.Name baseDir) with
                    | Ok() -> ()
                    | Error es -> yield! es |> List.map (fun e -> $"module {m.Name}: {e}")
            ]

        if errors.IsEmpty then Ok() else Error errors

    /// The pinned genesis and slot timing: a built-in network's (Networks.anchor). A chain config
    /// file pins none; its nodes must agree with each other instead.
    let pinnedAnchor (chain: ChainSource) : ChainAnchor voption =
        match chain with
        | ChainSource.Network name -> Networks.anchor name
        | ChainSource.File _ -> ValueNone

    let private anchorOf (g: Genesis) (s: ChainSpec) = ChainAnchor.ofSpec g.GenesisTime g.GenesisValidatorsRoot s

    /// What the chain itself pins: the built-in network's anchor, or GENESIS_TIME and
    /// GENESIS_VALIDATORS_ROOT when a chain config file gives them.
    let chainPin (chain: ChainSource) (pinned: Map<string, string>) : Result<AnchorPin, string> =
        match chain with
        | ChainSource.Network name ->
            match Networks.anchor name with
            | ValueSome a -> Ok(AnchorPin.ofAnchor $"network {name}" a)
            | ValueNone -> Ok AnchorPin.none
        | ChainSource.File _ ->
            let src = "chain config"

            let time =
                match pinned.TryFind "GENESIS_TIME" with
                | None -> Ok ValueNone
                | Some v ->
                    match
                        UInt64.TryParse(v, Globalization.NumberStyles.None, Globalization.CultureInfo.InvariantCulture)
                    with
                    | true, n -> Ok(ValueSome(struct (n, src)))
                    | _ -> Error $"chain config: GENESIS_TIME '{v}' is not a number"

            let root =
                match pinned.TryFind "GENESIS_VALIDATORS_ROOT" with
                | None -> Ok ValueNone
                | Some v ->
                    match Root.TryParse v with
                    | ValueSome r -> Ok(ValueSome(struct (r, src)))
                    | ValueNone -> Error $"chain config: GENESIS_VALIDATORS_ROOT '{v}' is not a 32-byte hex value"

            match time, root with
            | Ok t, Ok r ->
                Ok
                    { AnchorPin.none with
                        GenesisTime = t
                        GenesisValidatorsRoot = r
                    }
            | Error e, _
            | _, Error e -> Error e

    /// What the start check holds every node to: what the chain pins
    /// (`chainPin`); the anchor the data dir kept from its first start (`anchorFile`); the slashing
    /// DB's root. Sources that disagree fail the start, whatever the nodes report.
    let startPin
        (chain: ChainSource)
        (pinned: Map<string, string>)
        (anchorFile: string)
        (dbRoot: Root voption)
        : Result<AnchorPin, string> =
        let fromChain = chainPin chain pinned

        let fromDir =
            if File.Exists anchorFile then
                ChainAnchor.pinOfFile "the data dir" (File.ReadAllText anchorFile)
                |> Result.mapError (fun e ->
                    $"{anchorFile}: {e}; it keeps the genesis and slot timing of the data dir's first start")
            else
                Ok AnchorPin.none

        let fromDb =
            match dbRoot with
            | ValueSome r ->
                { AnchorPin.none with
                    GenesisValidatorsRoot = ValueSome(struct (r, "the slashing DB"))
                }
            | ValueNone -> AnchorPin.none

        match fromChain, fromDir with
        | Error e, _
        | _, Error e -> Error e
        | Ok c, Ok d ->
            AnchorPin.merge c d
            |> Result.bind (fun p -> AnchorPin.merge p fromDb)
            |> Result.mapError (fun e -> $"the data dir belongs to another chain than {chain.Describe}: {e}")

    /// Whether an EIP-3076 file with this genesis validators root may be imported: only the root
    /// the chain pins: a built-in network's, or GENESIS_VALIDATORS_ROOT of a
    /// chain config file. A file of another chain would make a slashing DB that no node of this one
    /// can start with.
    let interchangeFits (chain: ChainSource) (pinned: Map<string, string>) (gvr: Root) : Result<unit, string> =
        match chainPin chain pinned with
        | Error e -> Error e
        | Ok p ->
            match p.GenesisValidatorsRoot with
            | ValueSome(struct (r, src)) when r <> gvr ->
                Error $"the file is for genesis validators root {gvr.Hex}, {src} has {r.Hex}"
            | _ -> Ok()

    /// Checks one node's genesis and spec against the pinned config and the pinned parts of
    /// genesis and slot timing (startPin). An error is the node's fault.
    let checkChain
        (what: string)
        (genesis: Genesis)
        (values: Map<string, string>)
        (pinned: Map<string, string>)
        (pin: AnchorPin)
        =
        match ChainSpec.checkPinned pinned values with
        | Error e -> Error $"the chain spec of {what} differs from the pinned config: {e}"
        | Ok() ->
            match ChainSpec.parse values with
            | Error e -> Error $"chain spec of {what}: {e}"
            | Ok spec when spec.Forks[0].Version <> genesis.GenesisForkVersion ->
                Error $"{what}: genesis fork version differs between /genesis and /config/spec"
            | Ok spec ->
                match AnchorPin.differences pin (anchorOf genesis spec) with
                | [] -> Ok(genesis, spec)
                | diffs ->
                    Error $"""the genesis or slot timing of {what} differs from the pin: {String.Join("; ", diffs)}"""

    /// Reads genesis and spec from one beacon node, retrying until it answers, and checks them
    /// (checkChain). An error is the node's fault: the start leaves the node out.
    let chainInfo
        (beacon: BeaconClient)
        (pinned: Map<string, string>)
        (pin: AnchorPin)
        (opts: RunOptions)
        (ct: CancellationToken)
        =
        task {
            let what = beacon.BaseUri.GetLeftPart(UriPartial.Authority)
            let! genesis = retryUntilOk opts.Log opts.Time $"{what} genesis" (fun () -> beacon.Genesis ct) ct
            let! values = retryUntilOk opts.Log opts.Time $"{what} spec" (fun () -> beacon.Spec ct) ct
            return checkChain what genesis values pinned pin
        }

    /// A client per configured node, in config order. A node with its own CA gets its own
    /// HttpClient, added to `owned`; the others share `http`. The error names the first CA that
    /// failed to load (that node then uses `http`, and the caller should not start).
    let clientsOf (config: CoreConfig) (http: HttpClient) (timeout: TimeSpan) (owned: ResizeArray<HttpClient>) =
        let httpFor (n: BeaconNodeConfig) =
            match n.CaCert with
            | ValueNone -> Ok http
            | ValueSome file ->
                BeaconClient.loadCa file
                |> Result.map (fun ca ->
                    let h = BeaconClient.createHttpWithCa ca
                    owned.Add h
                    h)

        let https = config.BeaconNodes |> List.map httpFor

        let caError =
            https
            |> List.tryPick (fun r ->
                match r with
                | Error e -> Some e
                | Ok _ -> None)

        let clients =
            List.zip config.BeaconNodes https
            |> List.map (fun (n, h) ->
                BeaconClient(
                    (match h with
                     | Ok h -> h
                     | Error _ -> http),
                    n.Url,
                    timeout,
                    n.Headers
                ))

        clients, caError

    /// Checks every beacon node. A node that fails its check is left
    /// out (dropped until the VC restarts), not a start failure. With every anchor value pinned the
    /// reference is the pin; else it is the anchor that `threshold` nodes with the role
    /// attestation_data report, and a node that reports another one is left out. Returns once the
    /// reference is known and `threshold` nodes with the role attestation_data and one with the
    /// role duties passed; fails when every node answered and that is out of reach, or when a role
    /// has no node left (BeaconNodes.Shortfall). Nodes still unreachable join later with a score of 0,
    /// and only with the reference anchor.
    let checkNodes
        (nodes: BeaconNodes)
        (pinned: Map<string, string>)
        (pin: AnchorPin)
        (opts: RunOptions)
        (ct: CancellationToken)
        =
        task {
            let checks = nodes.Nodes |> List.map (fun b -> b, chainInfo b pinned pin opts ct)

            let has (b: BeaconClient) (role: NodeRole) =
                nodes.Roles
                |> List.exists (fun (c, r) -> Object.ReferenceEquals(c, b) && r &&& role <> NodeRole.None)

            let mutable reference = AnchorPin.full pin
            let mutable first: (Genesis * ChainSpec) voption = ValueNone
            // Nodes that passed while no anchor has `threshold` nodes, with the anchor they report.
            let waiting = ResizeArray<struct (ChainAnchor * BeaconClient * Genesis * ChainSpec)>()
            let failures = ResizeArray<string>()
            let mutable ready = 0
            let mutable readyDuties = 0

            let leaveOut (b: BeaconClient) (why: string) =
                failures.Add $"{b.Name}: {why}"
                nodes.Drop(b, why)

            let accept (b: BeaconClient) (g: Genesis) (s: ChainSpec) =
                if first.IsNone then
                    first <- ValueSome(g, s)

                nodes.MarkReady b

                if has b NodeRole.AttestationData then
                    ready <- ready + 1

                if has b NodeRole.Duties then
                    readyDuties <- readyDuties + 1

            let otherChain (r: ChainAnchor) (a: ChainAnchor) =
                let diffs = String.Join("; ", ChainAnchor.differences "agreed" r a)
                $"it is on another chain ({diffs})"

            let agreeing (a: ChainAnchor) =
                waiting
                |> Seq.filter (fun (struct (x, c, _, _)) -> x = a && has c NodeRole.AttestationData)
                |> Seq.length

            let pending =
                Collections.Generic.List<Task<Result<Genesis * ChainSpec, string>>>(checks |> List.map snd)

            while (reference.IsNone || ready < nodes.Threshold || readyDuties < 1) && pending.Count > 0 do
                let! t = Task.WhenAny pending
                pending.Remove t |> ignore
                let b = checks |> List.find (fun (_, x) -> Object.ReferenceEquals(x, t)) |> fst

                match t.Result with
                | Error e -> leaveOut b e
                | Ok(g, s) ->
                    let a = anchorOf g s

                    match reference with
                    | ValueSome r when r = a -> accept b g s
                    | ValueSome r -> leaveOut b (otherChain r a)
                    | ValueNone ->
                        waiting.Add(struct (a, b, g, s))
                        // Only attestation_data nodes count toward the agreement: the threshold is
                        // theirs. Nodes of other roles wait for the reference.
                        if agreeing a >= nodes.Threshold then
                            reference <- ValueSome a

                            for struct (x, c, g, s) in waiting do
                                if x = a then accept c g s else leaveOut c (otherChain a x)

                            waiting.Clear()
            // Nodes that answer later are still checked before they get any call (the set requires
            // readiness), also those whose check ended while the loop above returned.
            match reference with
            | ValueSome r ->
                for b, t in checks do
                    if pending.Contains t then
                        t.ContinueWith(fun (t: Task<Result<Genesis * ChainSpec, string>>) ->
                            if t.Status = TaskStatus.RanToCompletion then
                                match t.Result with
                                | Ok(g, s) when anchorOf g s = r -> nodes.MarkReady b
                                | Ok(g, s) -> nodes.Drop(b, otherChain r (anchorOf g s))
                                | Error e -> nodes.Drop(b, e))
                        |> ignore
            | ValueNone -> ()
            // Anchors that no `threshold` nodes agreed on, each against the first one.
            let split =
                if waiting.Count = 0 then
                    []
                else
                    let struct (a0, b0, _, _) = waiting[0]

                    [
                        for struct (x, c, _, _) in waiting do
                            if x <> a0 then
                                let diffs = String.Join("; ", ChainAnchor.differences b0.Name a0 x)
                                $"{c.Name} is on another chain than {b0.Name} ({diffs})"
                    ]

            let reasons = List.ofSeq failures @ split
            let detail = if reasons.IsEmpty then "" else ": " + String.Join("; ", reasons)

            match reference, first with
            | ValueSome _, ValueSome f when ready >= nodes.Threshold && readyDuties >= 1 ->
                // A role whose every node failed fails the start too, not the first drop after it.
                match nodes.Shortfall with
                | ValueNone -> return Ok f
                | ValueSome why -> return Error $"too few beacon nodes passed the start checks: {why}{detail}"
            | _ ->
                let passed =
                    if reference.IsSome then
                        ready
                    else
                        waiting
                        |> Seq.filter (fun (struct (_, c, _, _)) -> has c NodeRole.AttestationData)
                        |> Seq.length

                if passed = 0 && reasons.IsEmpty then
                    return Error "no beacon node answered"
                else
                    return
                        Error
                            $"too few beacon nodes passed the start checks: {passed} with the role attestation_data on one chain, attestation_consensus_threshold is {nodes.Threshold}, and one with the role duties is needed{detail}"
        }

    /// How long one module's stop may take at shutdown.
    let moduleStopTimeout = TimeSpan.FromSeconds 10.0

    /// Stops each module on its own: one that throws or does not stop in time is logged and
    /// named in `failures`, and the next module still stops.
    let private stopModules (log: Log) (handles: ResizeArray<string * StartedModule>) (failures: ResizeArray<string>) =
        for name, h in handles do
            let failure =
                try
                    if (h.Stop()).Wait moduleStopTimeout then
                        ValueNone
                    else
                        ValueSome $"module {name} did not stop within {moduleStopTimeout.TotalSeconds} s"
                with e ->
                    let e: exn =
                        match e with
                        | :? AggregateException as a ->
                            match a.InnerException with
                            | null -> e
                            | inner -> inner
                        | _ -> e

                    ValueSome $"module {name} failed to stop: {e.Message}"

            match failure with
            | ValueSome f ->
                log.Error f
                failures.Add f
            | ValueNone -> ()

    /// Starts everything up to the scheduler, then runs `body` with the services and the
    /// scheduler (the VC runs the scheduler; the exit command signs one message). A module that
    /// fails to stop at the end makes the result an error.
    let runWith
        (opts: RunOptions)
        (ct: CancellationToken)
        (body: CoreServices -> DutyScheduler -> Task<Result<unit, string>>)
        : Task<Result<unit, string>> =
        task {
            let log = opts.Log
            let config = opts.Config
            let proposerWatcher = config.ProposerConfig |> ValueOption.map (fun p -> ProposerConfig.Watcher(p, log))
            // An invalid proposer config file fails the start: a wrong fee recipient loses rewards.
            let loadProposerFile () =
                match proposerWatcher with
                | ValueSome w -> w.Load() |> Result.map ignore
                | ValueNone -> Ok()

            match loadProposerFile () |> Result.bind (fun () -> DataDir.Acquire(config.DataDir, log)) with
            | Error e -> return Error e
            | Ok dataDir ->
                use _ = dataDir
                let pinned = config.Chain.Pinned
                let slashedKeys = SlashedKeys(dataDir.Path)
                let slashedLoad = slashedKeys.Load()
                // A node with its own CA gets its own HttpClient; the others share opts.Http.
                let owned = ResizeArray<HttpClient>()

                use _owned =
                    { new IDisposable with
                        member _.Dispose() =
                            for h in owned do
                                h.Dispose()
                    }

                let clients, caError = clientsOf config opts.Http config.RequestTimeout owned

                let nodes =
                    BeaconNodes(
                        clients,
                        config.AttestationConsensusThreshold,
                        opts.Time,
                        log,
                        config.PtcConsensusThreshold,
                        config.BeaconNodes |> List.map (fun n -> n.Roles),
                        config.Broadcast,
                        requireReady = true
                    )

                if nodes.Count > 1 then
                    log.Info
                        $"{nodes.Count} beacon nodes, attestation data needs {nodes.Threshold} to agree, PTC data {nodes.PtcThreshold}"

                if nodes.Count > 1 && config.Broadcast <> BroadcastTopic.All then
                    log.Info
                        $"broadcast to every node at once: {BroadcastTopic.describe config.Broadcast}; the rest to the best node, then the next"

                if nodes.Split then
                    for c, r in nodes.Roles do
                        log.Info $"beacon node {c.Name}: roles {NodeRole.describe r}"

                let check =
                    match caError, slashedLoad with
                    | Some e, _
                    | None, Error e -> Task.FromResult(Error e)
                    | None, Ok n ->
                        if n > 0 then
                            log.Warn $"{n} keys stay stopped: the chain showed them slashed ({slashedKeys.Path})"

                        match startPin config.Chain pinned dataDir.AnchorPath dataDir.SlashingDbRoot with
                        | Error e -> Task.FromResult(Error e)
                        | Ok pin -> checkNodes nodes pinned pin opts ct

                match! check with
                | Error e -> return Error e
                | Ok(genesis, spec) when
                    (let now =
                        SlotClock(
                            DateTimeOffset.FromUnixTimeSeconds(int64 genesis.GenesisTime),
                            spec.SlotDuration,
                            spec.SlotsPerEpoch,
                            opts.Time
                        )

                     (spec.ForkAt(defaultValueArg (now.CurrentSlot |> ValueOption.map now.EpochOf) 0UL)).Name < Electra)
                    ->
                    // Attestations, aggregates and blocks are built in the Electra formats only
                    // (SingleAttestation). A chain before Electra gets none.
                    let electra =
                        match spec.Forks |> Array.tryFind (fun f -> f.Name = Electra) with
                        | Some f -> $"Electra from epoch {f.Epoch}"
                        | None -> "Electra not scheduled"

                    return
                        Error
                            $"the chain is before Electra ({electra}); this build signs Electra and later formats only"
                | Ok(_, spec) when
                    spec.IsScheduled Gloas && not (opts.Modules |> List.exists (fun m -> m.Name = ModuleNames.Gloas))
                    ->
                    return Error "the chain schedules Gloas, and this build has no Gloas duties module"
                | Ok(genesis, spec) ->
                    log.Info
                        $"chain {spec.ConfigName}: last scheduled fork {(Array.last spec.Forks).Name.ApiName}, slot {spec.SlotDuration.TotalSeconds} s, genesis validators root {genesis.GenesisValidatorsRoot.Hex}"

                    let file = new FileMarkFile(dataDir.SlashingDbPath)

                    match SlashingDb.Open(file, genesis.GenesisValidatorsRoot) with
                    | Error e ->
                        (file :> IDisposable).Dispose()
                        return Error e
                    | Ok db ->
                        use _ = db
                        // The anchor of the first start, checked at every later one.
                        let anchorSaved =
                            if File.Exists dataDir.AnchorPath then
                                Ok()
                            else
                                try
                                    FileSync.writeAtomic
                                        dataDir.AnchorPath
                                        (Text.Encoding.UTF8.GetBytes(ChainAnchor.toFile (anchorOf genesis spec)))
                                        (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)

                                    Ok()
                                with
                                | :? IOException
                                | :? UnauthorizedAccessException as e -> Error $"{dataDir.AnchorPath}: {e.Message}"

                        if db.OpenInfo.TruncatedBytes > 0L then
                            log.Warn
                                $"slashing DB: cut a torn tail of {db.OpenInfo.TruncatedBytes} bytes (never synced, never sent)"

                        let slotFile = new FileMarkFile(dataDir.SlotMarksPath)

                        let slotMarks =
                            match SlotMarks.Open(slotFile, genesis.GenesisValidatorsRoot) with
                            | Ok m -> m.Compact() |> Result.map (fun () -> m)
                            | Error e ->
                                (slotFile :> IDisposable).Dispose()

                                Error
                                    $"{e} ({dataDir.SlotMarksPath} holds only marks for PTC votes and envelopes, which are not slashable; delete it to start without them)"

                        match db.Compact(), slotMarks, anchorSaved with
                        | Error e, _, _
                        | _, Error e, _
                        | _, _, Error e -> return Error e
                        | Ok(), Ok slotMarks, Ok() ->
                            use _ = slotMarks

                            if slotMarks.OpenInfo.TruncatedBytes > 0L then
                                log.Warn
                                    $"slot marks: cut a torn tail of {slotMarks.OpenInfo.TruncatedBytes} bytes (never synced, never sent)"

                            let clock =
                                SlotClock(
                                    DateTimeOffset.FromUnixTimeSeconds(int64 genesis.GenesisTime),
                                    spec.SlotDuration,
                                    spec.SlotsPerEpoch,
                                    opts.Time
                                )

                            let registry = KeyRegistry(Log = log)
                            // No key goes active before every module has started (OpenActivation below).
                            registry.CloseActivation()
                            proposerWatcher |> ValueOption.iter (fun w -> registry.SetProposerFile w.Current)
                            let proposerFileSeen = ref false
                            // Checked before each epoch boundary by its own task, never inside the epoch's duty work.
                            let proposerRefresher =
                                proposerWatcher
                                |> ValueOption.map (fun w ->
                                    let apply (changed: ProposerFile voption) =
                                        changed |> ValueOption.iter registry.SetProposerFile

                                        if changed.IsSome || not proposerFileSeen.Value then
                                            proposerFileSeen.Value <- true

                                            let unheld =
                                                w.Current.Keys
                                                |> Seq.filter (fun (KeyValue(k, _)) -> (registry.TryGet k).IsNone)
                                                |> Seq.length

                                            if unheld > 0 then
                                                log.Debug
                                                    $"proposer config: {unheld} listed keys are not held by this VC"

                                    ProposerConfig.Refresher(w.Reload, clock, config.ProposerConfigLead, apply, log))

                            let pipeline = Pipeline(db, registry, opts.Time, log, slotMarks)
                            pipeline.Switches.SetConfig config.Switches

                            if SigningJitter.anyAboveZero config.Signing then
                                pipeline.Jitters <- SigningJitters(config.Signing)

                            for line in SigningJitter.describe config.Signing do
                                log.Info line
                            // A stop written to the switch file before the start must hold from the first duty.
                            let switchFile = SwitchFile(dataDir.Path, pipeline.Switches, log)
                            let switchLoad = switchFile.Load()
                            let refreshGate = new SemaphoreSlim(1, 1)

                            let refresh (ct: CancellationToken) : Task =
                                task {
                                    do! refreshGate.WaitAsync ct

                                    try
                                        let floor =
                                            {
                                                Clock = clock
                                                SlotMarks = ValueSome slotMarks
                                            }

                                        match!
                                            Validators.refreshWith
                                                (ValueSome(slashedKeys, opts.Time))
                                                floor
                                                nodes
                                                registry
                                                db
                                                config.AllowStartWithoutHistory
                                                log
                                                ct
                                        with
                                        | Ok() -> ()
                                        | Error e -> log.Warn $"validator refresh: {e.Describe}"
                                    finally
                                        refreshGate.Release() |> ignore
                                }

                            let epochHooks = ResizeArray<Epoch -> CancellationToken -> Task>()
                            // Set while one epoch's module hooks run: the scheduler may start the
                            // next epoch's work while a hook of the last one still hangs.
                            let hooksBusy = ref false
                            // Snapshots run one at a time, and none after the stop: then the DB
                            // and the slot marks file close.
                            let snapshots =
                                SnapshotGate(fun epoch ->
                                    match db.Compact() with
                                    | Ok() -> log.Debug $"epoch {epoch}: slashing DB snapshot written"
                                    | Error e -> log.Error e

                                    match slotMarks.Compact() with
                                    | Ok() -> log.Debug $"epoch {epoch}: slot marks snapshot written"
                                    | Error e -> log.Error e)

                            use stopping = CancellationTokenSource.CreateLinkedTokenSource ct
                            let stopReason = ref ValueNone

                            let shutdown (reason: string) =
                                let first =
                                    lock stopReason (fun () ->
                                        if stopReason.Value.IsNone then
                                            stopReason.Value <- ValueSome reason
                                            true
                                        else
                                            false)

                                if first then
                                    log.Error $"shutting down: {reason}"
                                    stopping.Cancel()

                            // modules.tee.ha_peer maps only tee-signer's refusals, so a key of
                            // the local or web3signer module would sign on both VCs of the pair
                            // with two slashing DBs. Such keys fail the start, and the keymanager
                            // API may not import them.
                            let haPeer = Config.haPeer config

                            let haPeerImport (count: int) =
                                Task.FromResult(
                                    List.replicate
                                        count
                                        (ImportStatus.Error
                                            "modules.tee.ha_peer is on: every key must sign through the tee module")
                                )

                            let mutable keystores: KeystoreStore voption = ValueNone
                            let mutable remoteKeys: RemoteKeyStore voption = ValueNone
                            let mutable builder: BuilderHooks voption = ValueNone
                            let mutable selections: SelectionHooks voption = ValueNone
                            let extensions = ResizeArray<DutyExtension>()

                            if config.UseEvents then
                                extensions.Add(
                                    OnChainSlashing.extension
                                        spec
                                        nodes
                                        registry
                                        slashedKeys
                                        log
                                        opts.Time
                                        stopping.Token
                                )

                            let defaults =
                                {
                                    FeeRecipient = config.FeeRecipient
                                    Graffiti = config.Graffiti
                                    GasLimit = config.GasLimit
                                }

                            let graffiti =
                                GraffitiService(
                                    registry,
                                    config.Graffiti,
                                    config.GraffitiAppend,
                                    config.GraffitiVcCode,
                                    log
                                )

                            let services =
                                {
                                    Spec = spec
                                    Genesis = genesis
                                    Clock = clock
                                    Nodes = nodes
                                    Registry = registry
                                    Pipeline = pipeline
                                    Slashing = db
                                    Defaults = defaults
                                    Graffiti = graffiti
                                    Log = log
                                    DataDir = dataDir.Path
                                    RegisterBackend =
                                        fun backend ->
                                            task {
                                                let! keys = backend.Keys ct

                                                for k in keys do
                                                    if
                                                        not (registry.Add(k.Key, backend))
                                                        && not (registry.IsRefused k.Key)
                                                    then
                                                        log.Warn
                                                            $"key {k.Key.Short} is offered by more than one backend; keeping the first"
                                            }
                                    RefreshKeys = refresh
                                    OnEpoch = fun f -> lock epochHooks (fun () -> epochHooks.Add f)
                                    Shutdown = shutdown
                                    Stopping = stopping.Token
                                    SetKeystores =
                                        fun k ->
                                            keystores <-
                                                ValueSome(
                                                    if haPeer then
                                                        { k with
                                                            Import = fun items _ -> haPeerImport items.Length
                                                        }
                                                    else
                                                        k
                                                )
                                    Keystores = fun () -> keystores
                                    SetRemoteKeys =
                                        fun k ->
                                            remoteKeys <-
                                                ValueSome(
                                                    if haPeer then
                                                        { k with
                                                            Import = fun items _ -> haPeerImport items.Length
                                                        }
                                                    else
                                                        k
                                                )
                                    RemoteKeys = fun () -> remoteKeys
                                    AddDutyExtension = fun x -> extensions.Add x
                                    SetBuilder = fun b -> builder <- ValueSome b
                                    Builder = fun () -> builder
                                    SetSelections = fun h -> selections <- ValueSome h
                                    HaPeer = haPeer
                                }

                            let handles = ResizeArray<string * StartedModule>()

                            let mutable startError =
                                match switchLoad with
                                | Error e -> ValueSome e
                                | Ok() -> ValueNone

                            for m in opts.Modules do
                                if startError.IsNone then
                                    match! m.Start services ct with
                                    | Ok h -> handles.Add((m.Name, h))
                                    | Error e -> startError <- ValueSome $"module {m.Name}: {e}"

                            if haPeer && startError.IsNone then
                                let held =
                                    [
                                        match keystores with
                                        | ValueSome k when not (k.List().IsEmpty) ->
                                            $"the local module holds {k.List().Length} keystores"
                                        | _ -> ()

                                        match remoteKeys with
                                        | ValueSome r when not (r.List().IsEmpty) ->
                                            $"the web3signer module holds {r.List().Length} remote keys"
                                        | _ -> ()
                                    ]

                                if not held.IsEmpty then
                                    startError <-
                                        ValueSome
                                            $"""modules.tee.ha_peer: every key must sign through the tee module, but {String.Join(" and ", held)} (from <data_dir>/keystores, <data_dir>/remote-keys.json or keymanager imports); remove them, or turn ha_peer off"""

                            let stopFailures = ResizeArray<string>()
                            let startError = startError

                            let! result =
                                task {
                                    try
                                        match startError with
                                        | ValueSome e -> return Error e
                                        | ValueNone ->
                                            // Every module has started, so the doppelganger hold, when on, is in place.
                                            registry.OpenActivation()
                                            // From here a node that a check drops stops the VC when too
                                            // few nodes are left.
                                            nodes.OnLoss shutdown
                                            // The start checks again each epoch, on the nodes in use: a
                                            // node restarted with another fork schedule,
                                            // domain type, genesis or slot timing is
                                            // dropped, and the VC stops only when too few are left.
                                            let running = anchorOf genesis spec

                                            let checkSpecs (ct: CancellationToken) =
                                                task {
                                                    let specs = nodes.AskAll(fun b -> b.Spec ct)
                                                    let geneses = nodes.AskAll(fun b -> b.Genesis ct)
                                                    let! answers = specs
                                                    let! genesisAnswers = geneses

                                                    for (b, r), g in
                                                        List.zip
                                                            (List.zip nodes.Nodes (List.ofArray answers))
                                                            (List.ofArray genesisAnswers) do
                                                        if nodes.InUse b then
                                                            match r with
                                                            | Ok values ->
                                                                match ChainSpec.checkPinned pinned values with
                                                                | Error e ->
                                                                    nodes.Drop(
                                                                        b,
                                                                        $"its chain spec changed while running and differs from the pinned config: {e}"
                                                                    )
                                                                | Ok() ->
                                                                    // The start's checks that are not pins: the
                                                                    // domain types and the value bounds.
                                                                    match ChainSpec.parse values, g with
                                                                    | Error e, _ ->
                                                                        nodes.Drop(
                                                                            b,
                                                                            $"its chain spec changed while running: {e}"
                                                                        )
                                                                    | Ok s, Ok g ->
                                                                        match
                                                                            ChainAnchor.differences
                                                                                "running"
                                                                                running
                                                                                (anchorOf g s)
                                                                        with
                                                                        | [] -> ()
                                                                        | diffs ->
                                                                            let d = String.Join("; ", diffs)

                                                                            nodes.Drop(
                                                                                b,
                                                                                $"its genesis or slot timing changed while running: {d}"
                                                                            )
                                                                    | Ok _, Error e ->
                                                                        log.Debug $"{b.Name}: genesis: {e.Describe}"
                                                            | Error e -> log.Debug $"{b.Name}: chain spec: {e.Describe}"
                                                }

                                            let onEpoch (epoch: Epoch) (ct: CancellationToken) : Task =
                                                task {
                                                    // Versions of the block_data nodes for graffiti codes (mode all only): not awaited, so no duty waits for them.
                                                    graffiti.RefreshCodes(nodes, ct) |> ignore
                                                    do! checkSpecs ct
                                                    ct.ThrowIfCancellationRequested()
                                                    do! refresh ct
                                                    // One epoch's hooks at a time. While a hook of an
                                                    // earlier epoch still runs, this epoch skips its hooks.
                                                    let mine =
                                                        lock hooksBusy (fun () ->
                                                            if hooksBusy.Value then
                                                                false
                                                            else
                                                                (hooksBusy.Value <- true
                                                                 true))

                                                    if not mine then
                                                        log.Error
                                                            $"epoch {epoch}: a module epoch hook of an earlier epoch is still running; this epoch's hooks are skipped"
                                                    else
                                                        try
                                                            for hook in
                                                                lock epochHooks (fun () -> List.ofSeq epochHooks) do
                                                                try
                                                                    do! hook epoch ct
                                                                with
                                                                | :? OperationCanceledException -> ()
                                                                | e -> log.Error $"epoch {epoch}: {e.Message}"
                                                        finally
                                                            lock hooksBusy (fun () -> hooksBusy.Value <- false)
                                                    // Snapshot while running: the log grows by one record per vote until then.
                                                    if epoch > 0UL && epoch % config.SnapshotIntervalEpochs = 0UL then
                                                        snapshots.Run epoch |> ignore
                                                }

                                            let scheduler =
                                                DutyScheduler(
                                                    spec,
                                                    genesis.GenesisValidatorsRoot,
                                                    clock,
                                                    nodes,
                                                    registry,
                                                    pipeline,
                                                    log,
                                                    {
                                                        UseEvents = config.UseEvents
                                                        OnSlotDone = opts.OnSlotDone
                                                        OnEpoch = onEpoch
                                                        Defaults = defaults
                                                    }
                                                )

                                            for x in extensions do
                                                scheduler.AddExtension x

                                            match selections with
                                            | ValueSome h -> scheduler.SetSelections h
                                            | ValueNone -> ()

                                            scheduler.SetGraffiti graffiti
                                            graffiti.RefreshCodes(nodes, stopping.Token) |> ignore
                                            log.Info $"ready: {registry.All.Length} keys"

                                            use refresherStop =
                                                CancellationTokenSource.CreateLinkedTokenSource stopping.Token

                                            let refresherRun =
                                                match proposerRefresher with
                                                | ValueSome r -> r.Run refresherStop.Token
                                                | ValueNone -> Task.CompletedTask

                                            let switchRun = switchFile.Run(opts.Time, refresherStop.Token)
                                            opts.OnReady services scheduler

                                            let! result =
                                                task {
                                                    try
                                                        return! body services scheduler
                                                    finally
                                                        refresherStop.Cancel()
                                                }

                                            do! refresherRun
                                            do! switchRun

                                            match stopReason.Value with
                                            | ValueSome reason -> return Error reason
                                            | ValueNone -> return result
                                    finally
                                        // Epoch work still running after the scheduler's stop must
                                        // not write a snapshot into a closed file.
                                        snapshots.Close()
                                        stopModules log handles stopFailures
                                }

                            match result with
                            | Ok() when stopFailures.Count > 0 -> return Error(String.Join("; ", stopFailures))
                            | r -> return r
        }

    let run (opts: RunOptions) (ct: CancellationToken) : Task<Result<unit, string>> =
        runWith opts ct (fun core scheduler ->
            task {
                do! scheduler.Run core.Stopping
                return Ok()
            })
