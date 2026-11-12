/// The duty scheduler, driven by the slot clock. Per epoch: duties for the
/// current and next epoch (attester, proposer, sync committee), aggregation selection proofs and
/// committee subscriptions, sync committee subscriptions, fee recipients. Per slot: the block at
/// the slot start; attestations and sync committee messages at the attestation due time (or when
/// `threshold` nodes agree on the head event); aggregates and sync contributions at the aggregate
/// due time; sync selection proofs for the next slot after the messages. Duties are fetched again
/// when a head event shows a new dependent root or the key set changes.
namespace Eplix

open System
open System.Buffers.Binary
open System.Collections.Generic
open System.Numerics
open System.Security.Cryptography
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon

/// The last `capacity` items added, oldest first, safe for many writers. A long-running VC adds
/// one per slot or duty outcome; older items drop off so memory stays flat.
type RecentQueue<'T>(capacity: int) =
    do
        if capacity < 1 then
            invalidArg "capacity" "at least one item"

    let items = Collections.Concurrent.ConcurrentQueue<'T>()

    member _.Capacity = capacity
    member _.Count = items.Count

    member _.Enqueue(x: 'T) =
        items.Enqueue x

        while items.Count > capacity do
            items.TryDequeue() |> ignore

    interface IEnumerable<'T> with
        member _.GetEnumerator() = (items :> IEnumerable<'T>).GetEnumerator()

    interface Collections.IEnumerable with
        member _.GetEnumerator() = (items :> Collections.IEnumerable).GetEnumerator()

module RecentQueue =
    /// How many slot reports and duty events the scheduler keeps, for tests and diagnostics.
    [<Literal>]
    let Kept = 4096

type SchedulerOptions =
    {
        UseEvents: bool
        /// Called after the attestations of a slot are submitted (or there was nothing to do). Tests wait on it.
        OnSlotDone: Slot -> unit
        /// Called at the start of each epoch, before duties are fetched. The host refreshes keys here.
        OnEpoch: Epoch -> CancellationToken -> Task
        Defaults: KeyDefaults
    }

type SlotReport =
    {
        Slot: Slot
        Duties: int
        Signed: int
        Refused: int
        Failed: int
        Submitted: bool
    }

/// What happened to a non-attestation duty, for tests and logs.
type DutyEvent =
    | Proposed of slot: Slot * root: Root
    | ProposalFailed of slot: Slot * reason: string
    | Aggregated of slot: Slot * count: int
    | SyncMessages of slot: Slot * count: int
    | Contributions of slot: Slot * count: int
    | Subscribed of epoch: Epoch * count: int

module Selection =
    let private firstUint64 (signature: BlsSignature) =
        BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(SHA256.HashData(signature.Bytes), 0, 8))

    /// is_aggregator (phase0 validator.md).
    let isAggregator (spec: ChainSpec) (committeeLength: uint64) (proof: BlsSignature) =
        let modulo = max 1UL (committeeLength / spec.TargetAggregatorsPerCommittee)
        firstUint64 proof % modulo = 0UL

    /// is_sync_committee_aggregator (altair validator.md).
    let isSyncAggregator (spec: ChainSpec) (proof: BlsSignature) =
        let modulo =
            max 1UL (uint64 spec.Preset.SyncSubcommitteeSize / spec.TargetAggregatorsPerSyncSubcommittee)

        firstUint64 proof % modulo = 0UL

    /// The subcommittees of a validator's sync committee seats, each once (the seat dedup:
    /// Grandine signed one selection proof per seat).
    let subcommittees (spec: ChainSpec) (seats: uint64[]) =
        seats
        |> Array.map (fun i -> i / uint64 spec.Preset.SyncSubcommitteeSize)
        |> Array.distinct
        |> Array.sort

    /// Graffiti as 32 bytes: UTF-8, zero padded, cut at a character boundary.
    let graffiti (text: string) = Graffiti.toRoot text

type private AggregatorDuty =
    {
        Duty: AttesterDuty
        Proof: BlsSignature
    }

type private SyncAggregator =
    {
        Key: PubKey
        ValidatorIndex: ValidatorIndex
        Subcommittee: uint64
        Proof: BlsSignature
    }

/// What a head event did, from HeadVotes.Add.
[<RequireQualifiedAccess>]
type HeadVote =
    /// Not counted: the reason (a slot outside the clock's slot plus or minus 1, or an optimistic head).
    | Ignored of string
    /// Counted; the slot has no agreed root yet, or had one already.
    | Counted
    /// This event made `threshold` nodes name the same block for the slot: the slot's head root.
    | Agreed of Root

/// Head events from several nodes. An event counts only for the clock's slot plus or
/// minus 1 and only when the node's head is verified (not optimistic). Each node has one vote per
/// slot, its latest block; the first block that `threshold` nodes name is the slot's head root
/// and stays so. Not thread-safe: the scheduler calls it under its lock.
type HeadVotes(threshold: int) =
    let votes = Dictionary<Slot, Dictionary<int, Root>>()
    let agreed = HashSet<Slot>()

    /// Counts the event of node `node` (its config order) against the clock's slot `current`.
    member _.Add(node: int, ev: HeadEvent, current: Slot voption) : HeadVote =
        match current with
        | ValueNone -> HeadVote.Ignored "the chain has not started"
        | ValueSome now when ev.Slot + 1UL < now || ev.Slot > now + 1UL ->
            HeadVote.Ignored $"slot {ev.Slot} is not within one slot of the clock's slot {now}"
        | ValueSome _ when ev.ExecutionOptimistic -> HeadVote.Ignored "the head is optimistic"
        | ValueSome _ ->
            let slotVotes =
                match votes.TryGetValue ev.Slot with
                | true, v -> v
                | _ ->
                    let v = Dictionary<int, Root>()
                    votes[ev.Slot] <- v
                    v

            slotVotes[node] <- ev.Block

            if agreed.Contains ev.Slot then
                HeadVote.Counted
            else
                let mutable same = 0

                for r in slotVotes.Values do
                    if r = ev.Block then
                        same <- same + 1

                if same >= threshold then
                    agreed.Add ev.Slot |> ignore
                    HeadVote.Agreed ev.Block
                else
                    HeadVote.Counted

    /// Forgets the slots before `slot`.
    member _.Prune(slot: Slot) =
        for s in List.ofSeq votes.Keys do
            if s < slot then
                votes.Remove s |> ignore

        agreed.RemoveWhere(fun s -> s < slot) |> ignore

/// At most one run per epoch or slot at a time. A caller that finds a run in flight gets that run's
/// task instead of starting a second one, so it can wait for the result.
type private SingleRuns(gate: obj) =
    let running = Dictionary<uint64, Task>()

    member _.Run(key: uint64, f: unit -> Task) : Task =
        let finished = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

        let existing =
            lock gate (fun () ->
                match running.TryGetValue key with
                | true, t -> ValueSome t
                | _ ->
                    running[key] <- finished.Task
                    ValueNone)

        match existing with
        | ValueSome t -> t
        | ValueNone ->
            task {
                try
                    do! f ()
                finally
                    lock gate (fun () -> running.Remove key |> ignore)
                    finished.TrySetResult() |> ignore
            }

    member _.InFlight(key: uint64) : Task voption =
        lock gate (fun () ->
            match running.TryGetValue key with
            | true, t -> ValueSome t
            | _ -> ValueNone)

type DutyScheduler
    (
        spec: ChainSpec,
        gvr: Root,
        clock: SlotClock,
        nodes: BeaconNodes,
        registry: KeyRegistry,
        pipeline: Pipeline,
        log: Log,
        options: SchedulerOptions
    ) =
    let gate = obj ()
    let preset = spec.Preset
    let attesterDuties = Dictionary<Epoch, Duties<AttesterDuty>>()
    let proposerDuties = Dictionary<Epoch, Duties<ProposerDuty>>()
    let syncDuties = Dictionary<Epoch, SyncDuty[]>()
    let staleEpochs = HashSet<Epoch>()
    let fetchedAtVersion = Dictionary<Epoch, int64>()
    let headSeen = Dictionary<Slot, TaskCompletionSource>()
    let headRoots = Dictionary<Slot, Root>()
    let headVotes = HeadVotes(nodes.Threshold)
    let dependentVotes = Dictionary<Epoch, Dictionary<int, Root>>()
    let attested = Dictionary<Slot, AttestationData>()
    let syncRoots = Dictionary<Slot, Lazy<Task<Result<Root, string>>>>()
    let aggregators = Dictionary<Slot, List<AggregatorDuty>>()
    let selectionDone = HashSet<Epoch>()
    let selectionRuns = SingleRuns(gate)
    let syncSelectionRuns = SingleRuns(gate)
    let syncAggregators = Dictionary<Slot, SyncAggregator[]>()
    let syncSubscribed = Dictionary<uint64, HashSet<ValidatorIndex>>()
    let reports = RecentQueue<SlotReport>(RecentQueue.Kept)
    let events = RecentQueue<DutyEvent>(RecentQueue.Kept)
    let extensions = List<DutyExtension>()
    let mutable selections: SelectionHooks voption = ValueNone
    let mutable graffitiService = GraffitiService.Plain(registry, options.Defaults.Graffiti)

    let view: SchedulerView =
        {
            ProposerDuties =
                fun e ->
                    lock gate (fun () ->
                        match proposerDuties.TryGetValue e with
                        | true, d -> ValueSome d
                        | _ -> ValueNone)
            AttesterDuties =
                fun e ->
                    lock gate (fun () ->
                        match attesterDuties.TryGetValue e with
                        | true, d -> ValueSome d
                        | _ -> ValueNone)
            SyncDuties =
                fun e ->
                    lock gate (fun () ->
                        match syncDuties.TryGetValue e with
                        | true, d -> ValueSome d
                        | _ -> ValueNone)
            HeadRoot =
                fun s ->
                    lock gate (fun () ->
                        match headRoots.TryGetValue s with
                        | true, r -> ValueSome r
                        | _ -> ValueNone)
        }

    let note (e: DutyEvent) = events.Enqueue e

    let headSignal (slot: Slot) =
        lock gate (fun () ->
            match headSeen.TryGetValue slot with
            | true, t -> t
            | _ ->
                let t = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                headSeen[slot] <- t
                t)

    let activeKey (key: PubKey) =
        match registry.TryGet key with
        | ValueSome k -> k.State = KeyState.Active
        | ValueNone -> false

    let activeIndices () =
        registry.Active
        |> List.choose (fun k ->
            match k.Index with
            | ValueSome i -> Some i
            | ValueNone -> None)

    let requests keys priority deadline duty = Duty.requests spec gvr keys priority deadline duty

    /// An emergency switch stops this duty kind: count the duties as missed (reason `paused`)
    /// without asking a node for data that would not be signed. The switch board logs the
    /// change once; no line per duty.
    let paused (kind: DutyKind) (label: string) (count: int) =
        if pipeline.Switches.Stops kind then
            Metrics.missed label Metrics.Reason.Paused count
            true
        else
            false

    /// Waits for t, but not past the deadline on the slot clock.
    let awaitBy (t: Task) (deadline: DateTimeOffset) (ct: CancellationToken) =
        task {
            if not t.IsCompleted then
                use cts = CancellationTokenSource.CreateLinkedTokenSource ct
                let! _ = Task.WhenAny(t, clock.WaitUntil(deadline, cts.Token))
                cts.Cancel()
        }

    /// When aggregates and contributions stop waiting for slower nodes once one node answered: a
    /// quarter of the way from the due time to the deadline (1 s of the 4 s left in a 12 s Fulu
    /// slot), so three quarters stay to sign and publish.
    let softCutoff (due: DateTimeOffset) (deadline: DateTimeOffset) =
        if due >= deadline then deadline else due + TimeSpan.FromTicks((deadline - due).Ticks / 4L)

    /// Calls a selection hook. A module that throws counts as a failed call.
    let callSelections (what: string) (call: unit -> Task<Result<'T[], string>>) (ct: CancellationToken) =
        task {
            try
                return! call ()
            with
            | :? OperationCanceledException when ct.IsCancellationRequested ->
                return raise (OperationCanceledException ct)
            | e -> return Error $"{what}: {e.Message}"
        }

    /// The proofs that decide aggregation for attester duties: the VC's own, or with selection
    /// hooks the combined proofs the beacon node returned. Duties the answer lacks are dropped.
    let committeeProofs (epoch: Epoch) (signed: (AttesterDuty * BlsSignature)[]) (ct: CancellationToken) =
        match selections with
        | ValueSome h when signed.Length > 0 ->
            task {
                let req =
                    signed
                    |> Array.map (fun (d, p) ->
                        ({
                            ValidatorIndex = d.ValidatorIndex
                            Slot = d.Slot
                            SelectionProof = p
                        }
                        : BeaconCommitteeSelection))

                match! callSelections "beacon committee selections" (fun () -> h.BeaconCommittee req ct) ct with
                | Error e -> return Error e
                | Ok answer ->
                    let combined = Dictionary<struct (ValidatorIndex * Slot), BlsSignature>()

                    for a in answer do
                        combined[struct (a.ValidatorIndex, a.Slot)] <- a.SelectionProof

                    let found =
                        signed
                        |> Array.choose (fun (d, _) ->
                            match combined.TryGetValue(struct (d.ValidatorIndex, d.Slot)) with
                            | true, p -> Some(d, p)
                            | _ -> None)

                    let missing = signed.Length - found.Length

                    if missing > 0 then
                        log.Warn
                            $"epoch {epoch}: no combined selection proof for {missing} of {signed.Length} attester duties; they do not aggregate"

                        Metrics.missed "aggregation_slot" Metrics.Reason.BeaconNode missing

                    return Ok found
            }
        | _ -> Task.FromResult(Ok signed)

    /// The same for sync committee duties, keyed by validator, slot and subcommittee.
    let syncProofs (slot: Slot) (signed: (SyncDuty * uint64 * BlsSignature)[]) (ct: CancellationToken) =
        match selections with
        | ValueSome h when signed.Length > 0 ->
            task {
                let req =
                    signed
                    |> Array.map (fun (d, sub, p) ->
                        ({
                            ValidatorIndex = d.ValidatorIndex
                            Slot = slot
                            SubcommitteeIndex = sub
                            SelectionProof = p
                        }
                        : SyncCommitteeSelection))

                match! callSelections "sync committee selections" (fun () -> h.SyncCommittee req ct) ct with
                | Error e -> return Error e
                | Ok answer ->
                    let combined = Dictionary<struct (ValidatorIndex * Slot * uint64), BlsSignature>()

                    for a in answer do
                        combined[struct (a.ValidatorIndex, a.Slot, a.SubcommitteeIndex)] <- a.SelectionProof

                    let found =
                        signed
                        |> Array.choose (fun (d, sub, _) ->
                            match combined.TryGetValue(struct (d.ValidatorIndex, slot, sub)) with
                            | true, p -> Some(d, sub, p)
                            | _ -> None)

                    let missing = signed.Length - found.Length

                    if missing > 0 then
                        log.Warn
                            $"slot {slot}: no combined sync selection proof for {missing} of {signed.Length} duties; they do not aggregate"

                        Metrics.missed "sync_selection_proof" Metrics.Reason.BeaconNode missing

                    return Ok found
            }
        | _ -> Task.FromResult(Ok signed)

    // ---- Duties ----

    /// The registry holds `key` under validator `index`.
    let holds (key: PubKey) (index: ValidatorIndex) =
        match registry.TryGet key with
        | ValueSome k -> k.Index = ValueSome index
        | ValueNone -> false

    /// One duty per group (validator or slot). Exact repeats count once; a group with different
    /// duties in one answer gets none, since a wrong duty could make a second vote.
    let unique (what: string) (epoch: Epoch) (group: 'T -> uint64) (data: 'T[]) =
        [|
            for g, ds in data |> Array.groupBy group do
                match Array.distinct ds with
                | [| d |] -> yield d
                | many ->
                    log.Error
                        $"epoch {epoch}: {what} {g} has {many.Length} different duties in one beacon node answer; none is used"
        |]

    /// Leaves out duties of validators that were not asked for or whose key the registry holds
    /// under another index.
    let asked
        (what: string)
        (epoch: Epoch)
        (indices: ValidatorIndex list)
        (index: 'T -> ValidatorIndex)
        (key: 'T -> PubKey)
        (data: 'T[])
        =
        let wanted = HashSet<ValidatorIndex>(indices)
        let kept = data |> Array.filter (fun d -> wanted.Contains(index d) && holds (key d) (index d))

        if kept.Length < data.Length then
            log.Warn
                $"epoch {epoch}: {data.Length - kept.Length} {what} duties for validators not asked for, or under another key; not used"

        kept

    /// Duties are asked of every node until one answers with execution_optimistic false; after an
    /// optimistic answer, the other nodes get BeaconNodes.PreferWait to give a verified one. When
    /// no verified answer comes, the duties are used anyway: refusing them would miss
    /// every duty, and duties sign nothing on their own. The data to sign comes later from nodes
    /// that refuse it on an unverified head, and the slashing DB guards each signature.
    let optimisticDuties (what: string) (epoch: Epoch) (optimistic: bool) =
        if optimistic then
            log.Warn
                $"epoch {epoch}: {what} duties come from an optimistic beacon node (no node answered with a verified head); used anyway"

    let fetchAttester (epoch: Epoch) (indices: ValidatorIndex list) (ct: CancellationToken) =
        task {
            if indices.IsEmpty then
                lock gate (fun () ->
                    attesterDuties[epoch] <-
                        {
                            DependentRoot = Root.Zero
                            ExecutionOptimistic = false
                            Data = [||]
                        })

                return true
            else
                match!
                    nodes.CallPreferring(
                        (fun b -> b.AttesterDuties(epoch, indices, ct)),
                        (fun d -> not d.ExecutionOptimistic),
                        NodeRole.Duties
                    )
                with
                | Ok d ->
                    optimisticDuties "attester" epoch d.ExecutionOptimistic

                    let data =
                        d.Data
                        |> asked "attester" epoch indices (fun x -> x.ValidatorIndex) (fun x -> x.PubKey)
                        |> Array.filter (fun x -> spec.EpochOf x.Slot = epoch)
                        |> unique "validator" epoch (fun x -> x.ValidatorIndex)

                    let d = { d with Data = data }

                    lock gate (fun () ->
                        attesterDuties[epoch] <- d
                        // New duties need new selection proofs.
                        selectionDone.Remove epoch |> ignore

                        for x in aggregators.Keys |> Seq.filter (fun x -> spec.EpochOf x = epoch) |> List.ofSeq do
                            aggregators.Remove x |> ignore)

                    log.Debug $"epoch {epoch}: {d.Data.Length} attester duties, dependent root {d.DependentRoot.Hex}"
                    return true
                | Error e ->
                    log.Warn $"epoch {epoch}: attester duties failed: {e.Describe}"
                    return false
        }

    let fetchProposer (epoch: Epoch) (ct: CancellationToken) =
        task {
            match!
                nodes.CallPreferring(
                    (fun b -> b.ProposerDuties(epoch, ct)),
                    (fun d -> not d.ExecutionOptimistic),
                    NodeRole.Duties
                )
            with
            | Ok d ->
                optimisticDuties "proposer" epoch d.ExecutionOptimistic

                let mine =
                    d.Data
                    |> Array.filter (fun x ->
                        spec.EpochOf x.Slot = epoch
                        && match registry.TryGet x.PubKey with
                           | ValueSome k -> k.Index.IsNone || k.Index = ValueSome x.ValidatorIndex
                           | ValueNone -> false)
                    |> unique "slot" epoch (fun x -> x.Slot)

                lock gate (fun () -> proposerDuties[epoch] <- { d with Data = mine })

                if mine.Length > 0 then
                    log.Info
                        $"""epoch {epoch}: proposals at slots {String.Join(", ", mine |> Array.map (fun x -> x.Slot))}"""

                return true
            | Error e ->
                log.Debug $"epoch {epoch}: proposer duties: {e.Describe}"
                return false
        }

    let fetchSync (epoch: Epoch) (indices: ValidatorIndex list) (ct: CancellationToken) =
        task {
            if indices.IsEmpty then
                lock gate (fun () -> syncDuties[epoch] <- [||])
                return true
            else
                match!
                    nodes.CallPreferring(
                        (fun b -> b.SyncDuties(epoch, indices, ct)),
                        (fun (optimistic, _) -> not optimistic),
                        NodeRole.Duties
                    )
                with
                | Ok(optimistic, d) ->
                    optimisticDuties "sync committee" epoch optimistic

                    let d =
                        d
                        |> asked "sync committee" epoch indices (fun x -> x.ValidatorIndex) (fun x -> x.PubKey)
                        |> unique "validator" epoch (fun x -> x.ValidatorIndex)

                    lock gate (fun () -> syncDuties[epoch] <- d)
                    return true
                | Error e ->
                    log.Debug $"epoch {epoch}: sync duties: {e.Describe}"
                    return false
        }

    let needsFetch (epoch: Epoch) (version: int64) =
        lock gate (fun () ->
            not (attesterDuties.ContainsKey epoch)
            || staleEpochs.Contains epoch
            || (match fetchedAtVersion.TryGetValue epoch with
                | true, v -> v <> version
                | _ -> true))

    /// Attester duties when they are missing or stale; proposer and sync duties with them, and
    /// again on later slots while a fetch of them failed. A failed proposer or sync fetch does not
    /// make the attester duties (and their selection proofs) be fetched again.
    let fetchEpoch (epoch: Epoch) (version: int64) (ct: CancellationToken) =
        task {
            let indices = activeIndices ()

            if needsFetch epoch version then
                let! a = fetchAttester epoch indices ct

                if a then
                    lock gate (fun () ->
                        staleEpochs.Remove epoch |> ignore
                        fetchedAtVersion[epoch] <- version
                        proposerDuties.Remove epoch |> ignore
                        syncDuties.Remove epoch |> ignore)

            let missingProposer, missingSync =
                lock gate (fun () -> not (proposerDuties.ContainsKey epoch), not (syncDuties.ContainsKey epoch))

            if missingProposer then
                let! _ = fetchProposer epoch ct
                ()

            if missingSync then
                let! _ = fetchSync epoch indices ct
                ()
        }

    /// Selection proofs for every attester duty of an epoch, then the committee subscriptions
    /// with the aggregator flag. Low priority; a failed proof is retried while its aggregate can
    /// still be signed. One run per epoch at a time:
    /// a second call returns the run in flight. Duties fetched again during the run make it start
    /// over for the new duties: the old proofs are not kept.
    let prepareAggregation (epoch: Epoch) (ct: CancellationToken) : Task =
        selectionRuns.Run(
            epoch,
            fun () ->
                task {
                    let mutable again = true

                    while again && not ct.IsCancellationRequested do
                        again <- false
                        // The duties object this run works on; a refetch replaces it.
                        let source, duties =
                            lock gate (fun () ->
                                if selectionDone.Contains epoch then
                                    null, [||]
                                else
                                    match attesterDuties.TryGetValue epoch with
                                    | true, d -> box d, d.Data |> Array.filter (fun x -> activeKey x.PubKey)
                                    | _ -> null, [||])

                        if duties.Length > 0 then
                            use _span = Tracing.dutyOfEpoch "aggregation selection proofs" epoch duties.Length
                            // The run's duties are still the epoch's duties (no refetch since the start).
                            let isCurrent () =
                                lock gate (fun () ->
                                    match attesterDuties.TryGetValue epoch with
                                    | true, d -> Object.ReferenceEquals(d, source)
                                    | _ -> false)

                            let mutable pending = duties
                            let found = List<AggregatorDuty>()
                            let subs = List<BeaconCommitteeSubscription>()
                            let mutable attempt = 0
                            // Proofs that failed to sign get 5 passes. Signed proofs whose selection call failed
                            // are sent again (not signed again) each slot until their slot ends: in a cluster the
                            // middleware may wait for the other VCs' partials longer than the request timeout.
                            // A refetch ends the passes early, so the new duties do not wait for the old ones' slots.
                            let mutable unsent: (AttesterDuty * BlsSignature)[] = [||]

                            while ((pending.Length > 0 && attempt < 5) || unsent.Length > 0)
                                  && not ct.IsCancellationRequested
                                  && isCurrent () do
                                attempt <- attempt + 1

                                if attempt > 5 then
                                    pending <- [||]

                                let failed = List<AttesterDuty>()

                                let signed =
                                    List<AttesterDuty * BlsSignature>(
                                        unsent |> Array.filter (fun (d, _) -> clock.Now < clock.SlotStart(d.Slot + 1UL))
                                    )

                                if signed.Count < unsent.Length then
                                    let expired = unsent.Length - signed.Count

                                    log.Warn
                                        $"epoch {epoch}: {expired} attester duties do not aggregate: no combined selection proof before their slot ended"

                                    Metrics.missed "aggregation_slot" Metrics.Reason.BeaconNode expired

                                unsent <- [||]

                                for slotGroup in pending |> Array.groupBy (fun d -> d.Slot) do
                                    let slot, ds = slotGroup
                                    // The aggregate may be signed until the slot ends, so its proof too.
                                    let deadline = clock.SlotStart(slot + 1UL)

                                    let reqs =
                                        requests
                                            (ds |> Array.map (fun d -> d.PubKey))
                                            Priority.Low
                                            deadline
                                            (Duty.AggregationSlot slot)

                                    let! outcomes = pipeline.SignBurst(reqs, ct)

                                    for i in 0 .. ds.Length - 1 do
                                        match outcomes[i] with
                                        | Signed proof -> signed.Add((ds[i], proof))
                                        | Failed _ when clock.Now < deadline -> failed.Add ds[i]
                                        | _ -> ()
                                // With selection hooks: one call for all slots of the epoch, as beacon-APIs asks.
                                match! committeeProofs epoch (signed.ToArray()) ct with
                                | Ok proofs ->
                                    for d, proof in proofs do
                                        let isAgg = Selection.isAggregator spec d.CommitteeLength proof

                                        if isAgg then
                                            found.Add { Duty = d; Proof = proof }

                                        subs.Add
                                            {
                                                ValidatorIndex = d.ValidatorIndex
                                                CommitteeIndex = d.CommitteeIndex
                                                CommitteesAtSlot = d.CommitteesAtSlot
                                                Slot = d.Slot
                                                IsAggregator = isAgg
                                            }
                                | Error e ->
                                    // No combined proofs, so no aggregation for now.
                                    unsent <- signed.ToArray()

                                    log.Warn
                                        $"epoch {epoch}: {e}; {unsent.Length} attester duties do not aggregate yet, asked again next slot"

                                pending <- failed.ToArray()

                                if unsent.Length > 0 && isCurrent () then
                                    // Lighthouse also waits a slot before it asks again.
                                    do!
                                        clock.WaitUntil(
                                            clock.SlotStart((defaultValueArg clock.CurrentSlot 0UL) + 1UL),
                                            ct
                                        )

                            let current =
                                lock gate (fun () ->
                                    let current =
                                        match attesterDuties.TryGetValue epoch with
                                        | true, d -> Object.ReferenceEquals(d, source)
                                        | _ -> false

                                    if current then
                                        for a in found do
                                            match aggregators.TryGetValue a.Duty.Slot with
                                            | true, l ->
                                                l.RemoveAll(fun x -> x.Duty.PubKey = a.Duty.PubKey) |> ignore
                                                l.Add a
                                            | _ -> aggregators[a.Duty.Slot] <- List [ a ]

                                        selectionDone.Add epoch |> ignore

                                    current)

                            if not current then
                                log.Info
                                    $"epoch {epoch}: attester duties were fetched again during the selection proofs; starting over"

                                again <- true
                            elif subs.Count > 0 then
                                match!
                                    nodes.Broadcast(
                                        (fun b -> b.BeaconCommitteeSubscriptions(subs, ct)),
                                        NodeRole.subscriptions,
                                        BroadcastTopic.Subscriptions
                                    )
                                with
                                | Ok() ->
                                    note (Subscribed(epoch, subs.Count))

                                    log.Debug
                                        $"epoch {epoch}: {subs.Count} committee subscriptions, {found.Count} aggregators"
                                | Error e -> log.Warn $"epoch {epoch}: committee subscriptions: {e.Describe}"
                }
        )

    /// Sync committee subscriptions, once per sync committee period and validator: a key added
    /// during the period is subscribed when its duties appear.
    let subscribeSync (epoch: Epoch) (ct: CancellationToken) =
        task {
            let duties =
                lock gate (fun () ->
                    match syncDuties.TryGetValue epoch with
                    | true, d -> d
                    | _ -> [||])

            let period = spec.SyncPeriodOf epoch

            let fresh =
                lock gate (fun () ->
                    let done' =
                        match syncSubscribed.TryGetValue period with
                        | true, s -> s
                        | _ ->
                            let s = HashSet<ValidatorIndex>()
                            syncSubscribed[period] <- s
                            s

                    duties |> Array.filter (fun d -> done'.Add d.ValidatorIndex))

            if fresh.Length > 0 then
                let until = (period + 1UL) * spec.EpochsPerSyncCommitteePeriod

                let subs =
                    fresh
                    |> Array.map (fun d ->
                        {
                            ValidatorIndex = d.ValidatorIndex
                            Indices = d.Indices
                            UntilEpoch = until
                        })

                match!
                    nodes.Broadcast(
                        (fun b -> b.SyncCommitteeSubscriptions(subs, ct)),
                        NodeRole.syncSubscriptions,
                        BroadcastTopic.Subscriptions
                    )
                with
                | Ok() -> log.Info $"sync committee period {period}: {subs.Length} keys subscribed"
                | Error e ->
                    lock gate (fun () ->
                        match syncSubscribed.TryGetValue period with
                        | true, s ->
                            for d in fresh do
                                s.Remove d.ValidatorIndex |> ignore
                        | _ -> ())

                    log.Warn $"sync committee subscriptions: {e.Describe}"
        }

    /// Fee recipients for every active key with an index, each epoch.
    let prepareProposers (ct: CancellationToken) =
        task {
            let xs =
                registry.Active
                |> List.choose (fun k ->
                    match
                        k.Index,
                        (match k.Settings.FeeRecipient with
                         | ValueSome f -> ValueSome f
                         | ValueNone -> options.Defaults.FeeRecipient)
                    with
                    | ValueSome i, ValueSome f -> Some(i, f)
                    | _ -> None)

            if not xs.IsEmpty then
                match!
                    nodes.Broadcast(
                        (fun b -> b.PrepareBeaconProposer(xs, ct)),
                        NodeRole.BlockData,
                        BroadcastTopic.Preparations
                    )
                with
                | Ok() -> ()
                | Error e -> log.Warn $"prepare_beacon_proposer: {e.Describe}"
        }

    /// A head event of node `node` (config order). Events off the clock's slot plus or minus 1 and
    /// optimistic ones are dropped. The others mark duties stale on a new dependent root; the
    /// slot's head root, which head votes and sync messages sign and which starts the
    /// attestations early, needs `threshold` nodes to name the same block (HeadVotes).
    let onHead (node: int) (ev: HeadEvent) =
        let epoch = spec.EpochOf ev.Slot

        let vote =
            lock gate (fun () ->
                match headVotes.Add(node, ev, clock.CurrentSlot) with
                | HeadVote.Ignored _ as v -> v
                | v ->
                    // Each node's latest dependent root per epoch. Duties go stale only when
                    // `threshold` nodes name the same root and it differs from the duties' root,
                    // so one node cannot force refetches on its own.
                    let check e (root: Root) =
                        let byNode =
                            match dependentVotes.TryGetValue e with
                            | true, x -> x
                            | _ ->
                                let x = Dictionary<int, Root>()
                                dependentVotes[e] <- x
                                x

                        byNode[node] <- root
                        let agreed = byNode.Values |> Seq.filter (fun r -> r = root) |> Seq.length >= nodes.Threshold

                        match attesterDuties.TryGetValue e with
                        | true, d when agreed && d.Data.Length > 0 && d.DependentRoot <> root ->
                            if staleEpochs.Add e then
                                log.Info
                                    $"epoch {e}: dependent root changed to {root.Hex}; duties will be fetched again"
                        | _ -> ()

                    check epoch ev.PreviousDutyDependentRoot
                    check (epoch + 1UL) ev.CurrentDutyDependentRoot

                    match v with
                    | HeadVote.Agreed root when not (headRoots.ContainsKey ev.Slot) -> headRoots[ev.Slot] <- root
                    | _ -> ()

                    v)

        match vote with
        | HeadVote.Ignored why -> log.Debug $"head event for slot {ev.Slot} ignored: {why}"
        | _ ->
            match vote with
            | HeadVote.Agreed _ -> (headSignal ev.Slot).TrySetResult() |> ignore
            | _ -> ()

            for x in extensions do
                try
                    x.OnHead ev
                with e ->
                    log.Error $"{x.Name}: head event: {e.Message}"

    // ---- Attestations ----

    let attest (slot: Slot) (ct: CancellationToken) : Task<SlotReport> =
        task {
            let epoch = spec.EpochOf slot

            let mine =
                lock gate (fun () ->
                    match attesterDuties.TryGetValue epoch with
                    | true, d -> d.Data |> Array.filter (fun x -> x.Slot = slot)
                    | _ -> [||])
                |> Array.filter (fun d -> activeKey d.PubKey)

            let empty =
                {
                    Slot = slot
                    Duties = mine.Length
                    Signed = 0
                    Refused = 0
                    Failed = 0
                    Submitted = false
                }

            if mine.Length = 0 then
                return empty
            elif paused DutyKind.Attestation "attestation" mine.Length then
                return { empty with Refused = mine.Length }
            else
                use act = Tracing.duty "attestations" slot mine.Length

                let head =
                    lock gate (fun () ->
                        match headRoots.TryGetValue slot with
                        | true, r -> ValueSome r
                        | _ -> ValueNone)

                use until =
                    new CancellationTokenSource(
                        clock.SlotStart(slot + 1UL) - clock.Now |> max TimeSpan.Zero,
                        clock.Time
                    )

                use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, until.Token)

                match!
                    nodes.AttestationData(
                        slot,
                        head,
                        clock.EpochOf(defaultValueArg clock.CurrentSlot slot),
                        linked.Token
                    )
                with
                | Error e ->
                    ct.ThrowIfCancellationRequested()
                    log.Warn $"slot {slot}: attestation data: {e}"
                    Tracing.fail act "no attestation data"
                    Metrics.missed "attestation" Metrics.Reason.BeaconNode mine.Length
                    return { empty with Failed = mine.Length }
                | Ok data when
                    data.Target.Epoch <> epoch || (data.Source.Epoch >= data.Target.Epoch && data.Target.Epoch > 0UL)
                    ->
                    // An attestation for this slot targets the slot's epoch, and its source is an
                    // earlier checkpoint (both 0 only at genesis). The node's data does not fit.
                    log.Warn
                        $"slot {slot}: attestation data with source epoch {data.Source.Epoch} and target epoch {data.Target.Epoch} does not fit epoch {epoch}; {mine.Length} duties not signed"

                    Metrics.missed "attestation" Metrics.Reason.BeaconNode mine.Length
                    return { empty with Refused = mine.Length }
                | Ok data ->
                    lock gate (fun () -> attested[slot] <- data)
                    let deadline = clock.SlotStart(slot + 1UL)

                    let reqs =
                        requests (mine |> Array.map (fun d -> d.PubKey)) Priority.High deadline (Duty.Attestation data)

                    let! outcomes = pipeline.SignBurst(reqs, ct)

                    let signed =
                        Array.zip mine outcomes
                        |> Array.choose (fun (d, o) ->
                            match o with
                            | Signed s ->
                                Some
                                    {
                                        CommitteeIndex = d.CommitteeIndex
                                        AttesterIndex = d.ValidatorIndex
                                        Data = data
                                        Signature = s
                                    }
                            | _ -> None)

                    let refused =
                        outcomes
                        |> Array.sumBy (fun o ->
                            match o with
                            | Refused _ -> 1
                            | _ -> 0)

                    let failed = outcomes.Length - signed.Length - refused

                    let! submitted =
                        if signed.Length = 0 then
                            Task.FromResult false
                        else
                            task {
                                let fork = (spec.ForkAt epoch).Name

                                match!
                                    nodes.Broadcast(
                                        (fun b -> b.SubmitAttestations(fork, signed, ct)),
                                        NodeRole.AttestationPublish,
                                        BroadcastTopic.Attestations
                                    )
                                with
                                | Ok() -> return true
                                | Error e ->
                                    log.Warn $"slot {slot}: submitting {signed.Length} attestations: {e.Describe}"
                                    return false
                            }

                    Metrics.missedOutcomes "attestation" outcomes
                    Tracing.setInt act "eplix.signed" signed.Length
                    Tracing.setBool act "eplix.submitted" submitted

                    if signed.Length > 0 && not submitted then
                        Tracing.fail act "not submitted"

                    if submitted then
                        Metrics.completed "attestation" signed.Length
                    else
                        Metrics.missed "attestation" Metrics.Reason.Submit signed.Length

                    log.Info
                        $"slot {slot}: {mine.Length} duties, {signed.Length} signed, {refused} refused, {failed} failed, submitted {submitted}"

                    return
                        { empty with
                            Signed = signed.Length
                            Refused = refused
                            Failed = failed
                            Submitted = submitted
                        }
        }

    // ---- Aggregation ----

    let aggregate (slot: Slot) (ct: CancellationToken) =
        task {
            // The selection proofs of this epoch may still be in flight (right after a start or a
            // duty refetch): wait for them while the aggregate can still be signed.
            match selectionRuns.InFlight(spec.EpochOf slot) with
            | ValueSome run -> do! awaitBy run (clock.SlotStart(slot + 1UL)) ct
            | ValueNone -> ()

            let mine =
                lock gate (fun () ->
                    match aggregators.TryGetValue slot with
                    | true, l -> l.ToArray()
                    | _ -> [||])
                |> Array.filter (fun a -> activeKey a.Duty.PubKey)

            let data =
                lock gate (fun () ->
                    match attested.TryGetValue slot with
                    | true, d -> ValueSome d
                    | _ -> ValueNone)

            match data with
            | _ when mine.Length = 0 -> ()
            | _ when paused DutyKind.AggregateAndProof "aggregate_and_proof" mine.Length -> ()
            | ValueNone when pipeline.Switches.Stops DutyKind.Attestation ->
                // No attestation data while attestations are paused: no line per slot.
                Metrics.missed "aggregate_and_proof" Metrics.Reason.Paused mine.Length
            | ValueNone ->
                log.Warn $"slot {slot}: {mine.Length} aggregation duties, but no attestation data was signed"
                Metrics.missed "aggregate_and_proof" Metrics.Reason.BeaconNode mine.Length
            | ValueSome data ->
                use _span = Tracing.duty "aggregates" slot mine.Length
                let dataRoot = Codec.hashAttestationData data
                // Gloas changes the attestation to a progressive container: same bytes, new root.
                let gloas = spec.IsGloasAt(spec.EpochOf slot)
                let schema = Schemas.attestationAt gloas preset
                let deadline = clock.SlotStart(slot + 1UL)
                let soft = softCutoff (clock.SlotStart slot + spec.AggregateDueAt slot) deadline
                let byCommittee = mine |> Array.groupBy (fun a -> a.Duty.CommitteeIndex)
                let toSign = List<AggregatorDuty * Ssz.SszValue>()

                let bits (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f -> Codec.asBits f[0] |> Array.sumBy (fun b -> if b then 1 else 0)
                    | _ -> 0

                let full (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f -> Codec.asBits f[0] |> Array.forall id
                    | _ -> false

                // An aggregate of the data the VC signed, for the committee asked, one bit per
                // member. The bits themselves cannot be checked without the members' keys.
                let fits (committee: uint64) (length: uint64) (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f ->
                        let committees = Codec.asBits f[3]

                        if Root.Of(Ssz.hashTreeRoot Schemas.attestationData f[1]) <> dataRoot then
                            ValueSome "an aggregate of other attestation data"
                        elif
                            committee >= uint64 committees.Length
                            || not committees[int committee]
                            || (committees |> Array.filter id).Length <> 1
                        then
                            ValueSome $"an aggregate whose committee bits are not committee {committee} alone"
                        elif uint64 (Codec.asBits f[0]).Length <> length then
                            ValueSome
                                $"an aggregate of {(Codec.asBits f[0]).Length} bits for committee {committee} of {length}"
                        else
                            ValueNone
                    | _ -> ValueSome "not an attestation"
                // All committees at once: each waits for the slow nodes only until the soft cutoff.
                let! answers =
                    byCommittee
                    |> Array.map (fun (committee, group) ->
                        nodes.Most(
                            (fun b -> b.AggregateAttestation(slot, dataRoot, committee, schema, ct)),
                            bits,
                            full,
                            deadline,
                            ct,
                            NodeRole.AggregateData,
                            soft = soft,
                            valid = fits committee group[0].Duty.CommitteeLength
                        ))
                    |> Task.WhenAll

                for (committee, group), answer in Array.zip byCommittee answers do
                    match answer with
                    | Ok agg ->
                        for a in group do
                            toSign.Add(a, agg)
                    | Error e ->
                        log.Warn $"slot {slot}: aggregate for committee {committee}: {e.Describe}"
                        Metrics.missed "aggregate_and_proof" Metrics.Reason.BeaconNode group.Length

                if toSign.Count > 0 then
                    let msgSchema = Schemas.aggregateAndProofAt gloas preset

                    let reqs =
                        toSign.ToArray()
                        |> Array.map (fun (a, agg) ->
                            let msg = Ssz.Fields [| Ssz.U a.Duty.ValidatorIndex; agg; Ssz.Bytes a.Proof.Bytes |]

                            Duty.request
                                spec
                                gvr
                                a.Duty.PubKey
                                Priority.Low
                                deadline
                                (Duty.AggregateAndProof(slot, { Schema = msgSchema; Value = msg })))

                    let! outcomes = pipeline.SignBurst(reqs, ct)
                    Metrics.missedOutcomes "aggregate_and_proof" outcomes

                    let signed =
                        Array.zip reqs outcomes
                        |> Array.choose (fun (r, o) ->
                            match r.Duty, o with
                            | Duty.AggregateAndProof(_, m), Signed s ->
                                Some(Ssz.Fields [| m.Value; Ssz.Bytes s.Bytes |])
                            | _, Refused(Paused _) -> None
                            | _, o ->
                                log.Warn $"slot {slot}: aggregate of {r.Key.Short} not signed: {o.Describe}"
                                None)

                    if signed.Length > 0 then
                        let version = (spec.ForkAt(spec.EpochOf slot)).Name.ApiName

                        match!
                            nodes.Broadcast(
                                (fun b ->
                                    b.SubmitAggregateAndProofs(
                                        version,
                                        Schemas.signedAggregateAndProofAt gloas preset,
                                        signed,
                                        ct
                                    )),
                                NodeRole.AggregatePublish,
                                BroadcastTopic.Aggregates
                            )
                        with
                        | Ok() ->
                            note (Aggregated(slot, signed.Length))
                            Metrics.completed "aggregate_and_proof" signed.Length
                            log.Info $"slot {slot}: {signed.Length} aggregates submitted"
                        | Error e ->
                            Metrics.missed "aggregate_and_proof" Metrics.Reason.Submit signed.Length
                            log.Warn $"slot {slot}: submitting aggregates: {e.Describe}"
        }

    // ---- Sync committee ----

    /// Sync duties for messages at `slot`: those of the committee in force at slot + 1.
    let syncDutiesFor (slot: Slot) =
        lock gate (fun () ->
            match syncDuties.TryGetValue(spec.EpochOf(slot + 1UL)) with
            | true, d -> d |> Array.filter (fun x -> activeKey x.PubKey)
            | _ -> [||])

    /// Selection proofs for the sync contributions of `slot`: one per validator and subcommittee.
    /// A failed proof is retried while the contribution can still be signed. One run per slot at
    /// a time: a second call (the contribution step while the run started in the slot before is
    /// still signing) waits for the run in flight.
    let syncSelection (slot: Slot) (ct: CancellationToken) : Task =
        syncSelectionRuns.Run(
            slot,
            fun () ->
                task {
                    let known = lock gate (fun () -> syncAggregators.ContainsKey slot)
                    let duties = syncDutiesFor slot

                    if not known && duties.Length > 0 then
                        use _span = Tracing.duty "sync selection proofs" slot duties.Length
                        // The contribution may be signed until the slot ends, so its proof too.
                        let deadline = clock.SlotStart(slot + 1UL)
                        let found = List<SyncAggregator>()

                        let mutable pending =
                            duties
                            |> Array.collect (fun d ->
                                Selection.subcommittees spec d.Indices |> Array.map (fun s -> d, s))

                        let mutable attempt = 0

                        while pending.Length > 0 && not ct.IsCancellationRequested && attempt < 5 do
                            attempt <- attempt + 1

                            let reqs =
                                pending
                                |> Array.map (fun (d, s) ->
                                    Duty.request
                                        spec
                                        gvr
                                        d.PubKey
                                        Priority.Low
                                        deadline
                                        (Duty.SyncSelectionProof { Slot = slot; SubcommitteeIndex = s }))

                            let! outcomes = pipeline.SignBurst(reqs, ct)
                            let failed = List<SyncDuty * uint64>()
                            let signed = List<SyncDuty * uint64 * BlsSignature>()

                            for i in 0 .. pending.Length - 1 do
                                let d, s = pending[i]

                                match outcomes[i] with
                                | Signed proof -> signed.Add((d, s, proof))
                                | Failed _ when clock.Now < deadline -> failed.Add((d, s))
                                | _ -> ()

                            match! syncProofs slot (signed.ToArray()) ct with
                            | Ok proofs ->
                                for d, s, proof in proofs do
                                    if Selection.isSyncAggregator spec proof then
                                        found.Add
                                            {
                                                Key = d.PubKey
                                                ValidatorIndex = d.ValidatorIndex
                                                Subcommittee = s
                                                Proof = proof
                                            }
                            | Error e ->
                                // No combined proofs, so no contributions this slot. The next slot asks afresh.
                                Metrics.missed "sync_selection_proof" Metrics.Reason.BeaconNode signed.Count
                                log.Warn $"slot {slot}: {e}; {signed.Count} sync committee duties do not aggregate"

                            pending <- failed.ToArray()

                        lock gate (fun () -> syncAggregators[slot] <- found.ToArray())
                }
        )

    /// The block root the sync committee messages of `slot` sign, looked up once per slot. The
    /// contributions of the slot wait for the same lookup, so they never run ahead of it.
    let syncRootOf (slot: Slot) (ct: CancellationToken) : Task<Result<Root, string>> =
        let lookup =
            lock gate (fun () ->
                match syncRoots.TryGetValue slot with
                | true, l -> l
                | _ ->
                    let l =
                        lazy
                            (task {
                                let head =
                                    lock gate (fun () ->
                                        match headRoots.TryGetValue slot with
                                        | true, r -> ValueSome r
                                        | _ -> ValueNone)

                                match head with
                                | ValueSome r -> return Ok r
                                | ValueNone -> return! nodes.HeadBlockRoot ct
                            })

                    syncRoots[slot] <- l
                    l)

        lookup.Force()

    let syncMessages (slot: Slot) (ct: CancellationToken) =
        task {
            let duties = syncDutiesFor slot

            if
                duties.Length > 0
                && not (
                    paused
                        DutyKind.SyncCommitteeMessage
                        "sync_committee_message"
                        (duties |> Array.distinctBy (fun d -> d.ValidatorIndex)).Length
                )
            then
                use act = Tracing.duty "sync committee messages" slot duties.Length

                match! syncRootOf slot ct with
                | Error e ->
                    Tracing.fail act "no head root"
                    log.Warn $"slot {slot}: sync committee head root: {e}"

                    Metrics.missed
                        "sync_committee_message"
                        Metrics.Reason.BeaconNode
                        (duties |> Array.distinctBy (fun d -> d.ValidatorIndex)).Length
                | Ok root ->
                    let deadline = clock.SlotStart(slot + 1UL)
                    // One message per validator, however many seats it holds.
                    let one = duties |> Array.distinctBy (fun d -> d.ValidatorIndex)

                    let reqs =
                        requests
                            (one |> Array.map (fun d -> d.PubKey))
                            Priority.High
                            deadline
                            (Duty.SyncCommitteeMessage(slot, root))

                    let! outcomes = pipeline.SignBurst(reqs, ct)
                    Metrics.missedOutcomes "sync_committee_message" outcomes

                    let msgs =
                        Array.zip one outcomes
                        |> Array.choose (fun (d, o) ->
                            match o with
                            | Signed s ->
                                Some
                                    {
                                        Slot = slot
                                        BeaconBlockRoot = root
                                        ValidatorIndex = d.ValidatorIndex
                                        Signature = s
                                    }
                            | _ -> None)

                    if msgs.Length > 0 then
                        match!
                            nodes.Broadcast(
                                (fun b -> b.SubmitSyncCommitteeMessages(msgs, ct)),
                                NodeRole.SyncPublish,
                                BroadcastTopic.SyncCommittee
                            )
                        with
                        | Ok() ->
                            note (SyncMessages(slot, msgs.Length))
                            Metrics.completed "sync_committee_message" msgs.Length
                        | Error e ->
                            Metrics.missed "sync_committee_message" Metrics.Reason.Submit msgs.Length
                            log.Warn $"slot {slot}: submitting sync committee messages: {e.Describe}"
            // Selection proofs for the next slot, in the low class after this slot's messages
            // (Lighthouse computes them a slot ahead).
            do! syncSelection (slot + 1UL) ct
        }

    let contributions (slot: Slot) (ct: CancellationToken) =
        task {
            do! syncSelection slot ct

            let mine =
                lock gate (fun () ->
                    match syncAggregators.TryGetValue slot with
                    | true, a -> a
                    | _ -> [||])
                |> Array.filter (fun a -> activeKey a.Key)

            let stopped =
                mine.Length > 0 && paused DutyKind.ContributionAndProof "contribution_and_proof" mine.Length

            let! root = if mine.Length = 0 || stopped then Task.FromResult(Error "") else syncRootOf slot ct

            match root with
            | _ when mine.Length = 0 || stopped -> ()
            | Error e ->
                log.Warn $"slot {slot}: {mine.Length} sync aggregators, but no sync committee message root: {e}"
                Metrics.missed "contribution_and_proof" Metrics.Reason.BeaconNode mine.Length
            | Ok root ->
                use _span = Tracing.duty "contributions" slot mine.Length
                let schema = Schemas.syncCommitteeContribution preset
                let deadline = clock.SlotStart(slot + 1UL)
                let soft = softCutoff (clock.SlotStart slot + spec.ContributionDueAt slot) deadline
                let toSign = List<SyncAggregator * Ssz.SszValue>()

                let bits (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f -> Codec.asBits f[3] |> Array.sumBy (fun b -> if b then 1 else 0)
                    | _ -> 0

                let full (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f -> Codec.asBits f[3] |> Array.forall id
                    | _ -> false

                // A contribution for the slot, subcommittee and block root asked.
                let fits (sub: uint64) (v: Ssz.SszValue) =
                    match v with
                    | Ssz.Fields f ->
                        if Codec.asU f[0] <> slot then
                            ValueSome $"a contribution for slot {Codec.asU f[0]}"
                        elif Codec.asU f[2] <> sub then
                            ValueSome $"a contribution for subcommittee {Codec.asU f[2]}, not {sub}"
                        elif Root.Of(Codec.asBytes f[1]) <> root then
                            ValueSome "a contribution for another block root"
                        else
                            ValueNone
                    | _ -> ValueSome "not a contribution"

                let bySub = mine |> Array.groupBy (fun a -> a.Subcommittee)
                // All subcommittees at once, as for aggregates.
                let! answers =
                    bySub
                    |> Array.map (fun (sub, _) ->
                        nodes.Most(
                            (fun b -> b.SyncCommitteeContribution(slot, sub, root, schema, ct)),
                            bits,
                            full,
                            deadline,
                            ct,
                            NodeRole.SyncData,
                            soft = soft,
                            valid = fits sub
                        ))
                    |> Task.WhenAll

                for (sub, group), answer in Array.zip bySub answers do
                    match answer with
                    | Ok c ->
                        for a in group do
                            toSign.Add(a, c)
                    | Error e ->
                        log.Warn $"slot {slot}: contribution for subcommittee {sub}: {e.Describe}"
                        Metrics.missed "contribution_and_proof" Metrics.Reason.BeaconNode group.Length

                if toSign.Count > 0 then
                    let msgSchema = Schemas.contributionAndProof preset

                    let reqs =
                        toSign.ToArray()
                        |> Array.map (fun (a, c) ->
                            let msg = Ssz.Fields [| Ssz.U a.ValidatorIndex; c; Ssz.Bytes a.Proof.Bytes |]

                            Duty.request
                                spec
                                gvr
                                a.Key
                                Priority.Low
                                deadline
                                (Duty.ContributionAndProof(slot, { Schema = msgSchema; Value = msg })))

                    let! outcomes = pipeline.SignBurst(reqs, ct)
                    Metrics.missedOutcomes "contribution_and_proof" outcomes

                    let signed =
                        Array.zip reqs outcomes
                        |> Array.choose (fun (r, o) ->
                            match r.Duty, o with
                            | Duty.ContributionAndProof(_, m), Signed s ->
                                Some(Ssz.Fields [| m.Value; Ssz.Bytes s.Bytes |])
                            | _, Refused(Paused _) -> None
                            | _, o ->
                                log.Warn $"slot {slot}: contribution of {r.Key.Short} not signed: {o.Describe}"
                                None)

                    if signed.Length > 0 then
                        match!
                            nodes.Broadcast(
                                (fun b ->
                                    b.SubmitContributionAndProofs(
                                        Schemas.signedContributionAndProof preset,
                                        signed,
                                        ct
                                    )),
                                NodeRole.SyncPublish,
                                BroadcastTopic.SyncCommittee
                            )
                        with
                        | Ok() ->
                            note (Contributions(slot, signed.Length))
                            Metrics.completed "contribution_and_proof" signed.Length
                            log.Info $"slot {slot}: {signed.Length} sync contributions submitted"
                        | Error e ->
                            Metrics.missed "contribution_and_proof" Metrics.Reason.Submit signed.Length
                            log.Warn $"slot {slot}: submitting contributions: {e.Describe}"
        }

    // ---- Proposals ----

    let propose (slot: Slot) (ct: CancellationToken) =
        task {
            let epoch = spec.EpochOf slot

            let duty =
                lock gate (fun () ->
                    match proposerDuties.TryGetValue epoch with
                    | true, d -> d.Data |> Array.tryFind (fun x -> x.Slot = slot)
                    | _ -> None)

            let gloasPropose =
                if spec.IsGloasAt epoch then
                    match duty with
                    | Some d when activeKey d.PubKey ->
                        extensions
                        |> Seq.tryPick (fun x ->
                            match x.Propose view d ct with
                            | ValueSome t -> Some t
                            | ValueNone -> None)
                    | _ -> None
                else
                    None

            match duty with
            | Some d when spec.IsGloasAt epoch && activeKey d.PubKey ->
                match gloasPropose with
                | Some t ->
                    let! proposed = t

                    if not proposed then
                        note (ProposalFailed(slot, "the Gloas proposal failed"))
                | None ->
                    note (ProposalFailed(slot, "no Gloas duties module"))
                    log.Error $"slot {slot}: a Gloas proposal, and this build has no Gloas duties module"
            | Some d when activeKey d.PubKey ->
                use act = Tracing.duty "proposal" slot 1

                if not (isNull act) then
                    Tracing.setText act "eplix.key" d.PubKey.Hex

                let fail (reason: string) (why: string) =
                    Tracing.fail act why
                    Metrics.missed "block" reason 1
                    note (ProposalFailed(slot, why))
                    // A switched-off proposal was logged once, when the switch changed.
                    if reason = Metrics.Reason.Paused then
                        log.Debug $"slot {slot}: proposal by {d.PubKey.Short} skipped: {why}"
                    else
                        log.Error $"slot {slot}: proposal by {d.PubKey.Short} failed: {why}"

                let deadline = clock.SlotStart(slot + 1UL)
                let stoppedBy = [ DutyKind.RandaoReveal; DutyKind.Block ] |> List.tryFind pipeline.Switches.Stops

                let! randao =
                    match stoppedBy with
                    // No block is asked of a node when it could not be signed.
                    | Some kind -> Task.FromResult(Refused(Paused(pipeline.Switches.Reason kind)))
                    | None ->
                        pipeline.Sign(
                            Duty.request spec gvr d.PubKey Priority.High deadline (Duty.RandaoReveal epoch),
                            ct
                        )

                match randao with
                | Signed reveal ->
                    let settings = (registry.TryGet d.PubKey).Value.Settings
                    // Per node: each node gets its own client codes after the text.
                    let graffiti = graffitiService
                    let schema = Schemas.blockContents preset
                    let blindedSchema = Schemas.blindedBeaconBlock preset
                    // The legacy builder module's factor; without it the node builds locally.
                    let boost =
                        extensions
                        |> Seq.tryPick (fun x ->
                            match x.BuilderBoost d with
                            | ValueSome b -> Some b
                            | ValueNone -> None)
                        |> Option.defaultValue 0UL
                    // Vero's soft timeout: half of the attestation due time.
                    let soft = clock.SlotStart slot + TimeSpan.FromTicks((spec.AttestationDue slot).Ticks / 2L)
                    // A local payload must pay the key's fee recipient (the one
                    // prepare_beacon_proposer sent), as the Gloas bid check does.
                    // A builder payload pays the builder, which pays the proposer in a
                    // transaction the relay checks.
                    let expectedFee =
                        match settings.FeeRecipient with
                        | ValueSome f -> ValueSome f
                        | ValueNone -> options.Defaults.FeeRecipient
                        |> ValueOption.bind (Hex.tryDecodeFixed 20)
                    // Every answer is checked before the highest value is taken, so a node's
                    // claimed value counts only for a block the VC would sign. No hashing here:
                    // the body root is computed once, for the chosen block.
                    let check (factor: uint64) (p: ProducedBlock) : string voption =
                        if p.Blinded && factor = 0UL then
                            ValueSome "a blinded block for a local build"
                        elif p.Version <> "electra" && p.Version <> "fulu" then
                            ValueSome $"block version {p.Version} is not supported"
                        else
                            let block = Codec.fields (if p.Blinded then p.Contents else (Codec.fields p.Contents).[0])
                            let blockSlot, proposer = Codec.asU block[0], Codec.asU block[1]
                            let payloadFee = Codec.asBytes (Codec.fields (Codec.fields block[4]).[9]).[1]

                            if blockSlot <> slot || proposer <> d.ValidatorIndex then
                                ValueSome $"the block is for slot {blockSlot}, proposer {proposer}"
                            elif not p.Blinded && expectedFee.IsSome && expectedFee.Value <> payloadFee then
                                ValueSome
                                    $"the block pays fee recipient {Hex.encodeArray payloadFee}, the key's is {Hex.encodeArray expectedFee.Value}"
                            else
                                ValueNone

                    let produce (factor: uint64) =
                        nodes.HighestValue(
                            (fun b ->
                                b.ProduceBlockV3(
                                    slot,
                                    reveal,
                                    graffiti.For(d, epoch, b),
                                    schema,
                                    ct,
                                    factor,
                                    ?blindedSchema = (if factor > 0UL then Some blindedSchema else None)
                                )),
                            (fun (p: ProducedBlock) -> p.ConsensusBlockValue + p.ExecutionPayloadValue),
                            soft,
                            ct,
                            NodeRole.BlockData,
                            check factor
                        )

                    let! produced =
                        task {
                            match! produce boost with
                            // A relay that fails or times out behind the node: ask again for a
                            // local block, while the slot lasts. Nothing was signed yet.
                            | Error e when boost > 0UL && clock.Time.GetUtcNow() < deadline ->
                                Metrics.builderFallbacks.Add 1L
                                log.Warn $"slot {slot}: builder block: {e.Describe}; asking for a local block"
                                return! produce 0UL
                            | r -> return r
                        }

                    match produced with
                    | Error e -> fail Metrics.Reason.BeaconNode $"produce block: {e.Describe}"
                    | Ok(p, _) ->
                        let contents = Codec.fields p.Contents
                        // A blinded answer is the BlindedBeaconBlock itself; a local one is BlockContents.
                        let blockValue = if p.Blinded then p.Contents else contents[0]
                        let block = Codec.fields blockValue
                        // The blinded body has the same root as the full one (the payload header's
                        // root is the payload's), so slashing protection and remote signers see the
                        // header the full block would have.
                        let bodySchema =
                            if p.Blinded then Schemas.blindedBeaconBlockBody preset else Schemas.beaconBlockBody preset

                        let header =
                            {
                                Slot = Codec.asU block[0]
                                ProposerIndex = Codec.asU block[1]
                                ParentRoot = Root.Of(Codec.asBytes block[2])
                                StateRoot = Root.Of(Codec.asBytes block[3])
                                BodyRoot = Root.Of(Ssz.hashTreeRoot bodySchema block[4])
                            }
                        // The builder's gas limit moves toward the registered target by at most
                        // 1/1024 of the parent's per block, and the parent is not known here, so a
                        // different value is reported, not refused (the relay checks it).
                        if p.Blinded then
                            let target = defaultValueArg settings.GasLimit options.Defaults.GasLimit
                            let gasLimit = Codec.asU (Codec.fields (Codec.fields block[4]).[9]).[7]

                            if gasLimit <> target then
                                log.Info
                                    $"slot {slot}: the builder block's gas limit is {gasLimit}, the key's target {target}"
                        // The signed block encodes once, on the thread pool while the block is
                        // signed (2 MB with the blobs); every node gets the same bytes.
                        let encoding =
                            Task.Run(fun () ->
                                if p.Blinded then
                                    UnsignedPublication(
                                        Schemas.signedBlindedBeaconBlock preset,
                                        (fun sg -> Ssz.Fields [| blockValue; sg |]),
                                        [ 1 ]
                                    )
                                else
                                    UnsignedPublication(
                                        Schemas.signedBlockContents preset,
                                        (fun sg ->
                                            Ssz.Fields
                                                [| Ssz.Fields [| contents[0]; sg |]; contents[1]; contents[2] |]),
                                        [ 0; 1 ]
                                    ))

                        match!
                            pipeline.Sign(Duty.request spec gvr d.PubKey Priority.High deadline (Duty.Block header), ct)
                        with
                        | Signed s ->
                            let! unsigned = encoding
                            let signed = unsigned.WithSignature s.Bytes

                            let publish =
                                if p.Blinded then
                                    fun (b: BeaconClient) -> b.PublishBlindedBlock(p.Version, signed, ct)
                                else
                                    fun (b: BeaconClient) -> b.PublishBlock(p.Version, signed, ct)

                            match! nodes.Broadcast(publish, NodeRole.BlockPublish, BroadcastTopic.Blocks) with
                            | Ok() ->
                                let root = Codec.hashBeaconBlockHeader header
                                note (Proposed(slot, root))
                                Metrics.completed "block" 1

                                if p.Blinded then
                                    Metrics.blindedBlock "published"

                                let how = if p.Blinded then "builder block" else "block"
                                log.Info $"slot {slot}: {how} {root.Hex} proposed by {d.PubKey.Short}"
                            | Error e ->
                                if p.Blinded then
                                    Metrics.blindedBlock "refused"

                                fail Metrics.Reason.Submit $"publish: {e.Describe}"
                        | other -> fail (Metrics.missReason other) $"block signature: {SignOutcome.describe other}"
                | other -> fail (Metrics.missReason other) $"RANDAO reveal: {SignOutcome.describe other}"
            | _ -> ()
        }

    /// How long Run waits at the stop for epoch start work that is still running.
    let epochWorkStopTimeout = TimeSpan.FromSeconds 10.0

    let spawn (inFlight: List<Task>) (what: string) (f: unit -> Task<unit>) =
        let t =
            task {
                try
                    do! f ()
                with
                | :? OperationCanceledException -> ()
                | e -> log.Error $"{what}: {e.Message}"
            }

        inFlight.Add t

    member _.Reports = reports
    member _.Events = events

    /// Adds a duty extension. Call before Run.
    member _.AddExtension(x: DutyExtension) = extensions.Add x

    /// Combined selection proofs decide aggregation (the Obol module). Set before Run.
    member _.SetSelections(h: SelectionHooks) = selections <- ValueSome h

    /// The graffiti of proposals (layers and client codes). Default: the core config's graffiti
    /// under the key settings, no codes. Set before Run.
    member _.SetGraffiti(g: GraffitiService) = graffitiService <- g

    /// Runs until ct fires.
    member _.Run(ct: CancellationToken) : Task =
        task {
            let headEvents =
                if options.UseEvents then
                    nodes.RunEventsFrom(
                        "head"
                        :: [
                            for x in extensions do
                                yield! x.Topics
                        ]
                        |> List.distinct,
                        (fun node ev ->
                            match ev.Event with
                            | "head"
                            | "head_v2" ->
                                match Json.decodeString (Decoders.headEvent ev.Event) ev.Data with
                                | Ok h -> onHead node h
                                | Error e -> log.Warn $"head event: {e}"
                            | _ ->
                                for x in extensions do
                                    if List.contains ev.Event x.Topics then
                                        try
                                            x.OnEvent ev
                                        with e ->
                                            log.Error $"{x.Name}: {ev.Event} event: {e.Message}"),
                        ct,
                        NodeRole.events
                    )
                else
                    Task.CompletedTask

            do! clock.WaitUntil(clock.GenesisTime, ct)
            let mutable slot = defaultValueArg clock.CurrentSlot 0UL
            let mutable lastEpoch = UInt64.MaxValue
            let mutable epochWork: Task = Task.CompletedTask
            // Epoch start work not yet done; awaited at the end, with a bound.
            let epochWorks = List<Task>()
            let inFlight = List<Task>()

            try
                while not ct.IsCancellationRequested do
                    let epoch = spec.EpochOf slot

                    if epoch <> lastEpoch then
                        let previous = epochWork
                        let start = clock.SlotStart slot

                        let work =
                            task {
                                try
                                    // One epoch's work at a time, but the previous one holds this
                                    // one only until this epoch starts: a module hook that never
                                    // ends must not stop the health and key refresh of every
                                    // later epoch. The runner keeps hooks and snapshots from
                                    // running twice at once; the key refresh has its own lock.
                                    if not previous.IsCompleted then
                                        do! awaitBy previous start ct

                                        if not previous.IsCompleted && not ct.IsCancellationRequested then
                                            log.Error
                                                $"epoch {epoch}: the previous epoch's start work has not ended; this epoch's starts anyway"
                                    // Health first: the duties of this epoch come from the best node.
                                    do! nodes.RefreshHealth ct
                                    do! options.OnEpoch epoch ct
                                with
                                | :? OperationCanceledException when ct.IsCancellationRequested -> ()
                                // Logged, and the next epoch tries again: the keys stay as they are.
                                | e -> log.Error $"epoch {epoch} start: {e.Message}"
                            }

                        epochWork <- work :> Task
                        epochWorks.Add(work :> Task)

                        if lastEpoch = UInt64.MaxValue then
                            // At the start the keys come from this work: wait for it.
                            do! work
                        else
                            // The duties of this epoch were fetched an epoch ahead, so its first
                            // slot does not wait for this work past the slot start (a hung node
                            // can hold it for seconds). The rest finishes in the background; a
                            // key change it makes fetches the duties again on a later slot.
                            do! awaitBy (work :> Task) start ct
                            ct.ThrowIfCancellationRequested()

                            if not work.IsCompleted then
                                log.Warn
                                    $"epoch {epoch}: the epoch start work is not done at the first slot; it goes on in the background"
                                // A key that work activates needs its fee recipient prepared this
                                // epoch too: prepare again once it ends, waiting at most until the
                                // next epoch so a hung hook holds neither this nor the shutdown.
                                let nextEpochStart = clock.SlotStart((epoch + 1UL) * spec.SlotsPerEpoch)

                                spawn inFlight "prepare_beacon_proposer after the epoch start work" (fun () ->
                                    task {
                                        do! awaitBy (work :> Task) nextEpochStart ct

                                        if work.IsCompleted && not ct.IsCancellationRequested then
                                            do! prepareProposers ct
                                    })

                        lastEpoch <- epoch
                        spawn inFlight "prepare_beacon_proposer" (fun () -> prepareProposers ct)

                    let version = registry.Version
                    // The loop runs ahead: a slot's duties are fetched during the slot before. Beacon
                    // nodes serve duties for their current and next epoch only (Nimbus answers 400
                    // to more), so the look-ahead counts from the clock's epoch: in the last slot of
                    // epoch e, the first slot of e + 1 must not ask for e + 2, which nodes refuse.
                    let dutyEpoch = min epoch (spec.EpochOf(defaultValueArg clock.CurrentSlot slot))

                    for e in [ dutyEpoch; dutyEpoch + 1UL ] do
                        do! fetchEpoch e version ct

                    for x in extensions do
                        spawn inFlight $"{x.Name} duties" (fun () -> task { do! x.PrepareEpochs view dutyEpoch ct })

                    spawn inFlight "aggregation selection" (fun () ->
                        task {
                            // Both epochs' runs start now: with failing selection hooks a run
                            // asks again each slot until its last slot ends, and the next epoch's
                            // proofs must not wait for that. Each epoch still has one run at a time.
                            let current = prepareAggregation dutyEpoch ct
                            let next = prepareAggregation (dutyEpoch + 1UL) ct
                            do! subscribeSync dutyEpoch ct
                            do! subscribeSync (dutyEpoch + 1UL) ct
                            do! Task.WhenAll(current, next)
                        })

                    do! clock.WaitUntil(clock.SlotStart slot, ct)
                    let s = slot
                    spawn inFlight $"slot {s} proposal" (fun () -> propose s ct)

                    for x in extensions do
                        spawn inFlight $"slot {s} {x.Name}" (fun () -> task { do! x.RunSlot view s ct })
                    // Wait for the first due time, or the head event for this slot after the slot
                    // started. Attestations and sync messages each start at their own due time
                    // or at the head event, whichever comes first.
                    let due = clock.SlotStart slot + spec.AttestationDue slot
                    let syncDue = clock.SlotStart slot + spec.SyncMessageDueAt slot
                    let head = (headSignal slot).Task
                    use waitCts = CancellationTokenSource.CreateLinkedTokenSource ct
                    let timer = clock.WaitUntil(min due syncDue, waitCts.Token)
                    let! _ = Task.WhenAny(timer, head)
                    waitCts.Cancel()
                    ct.ThrowIfCancellationRequested()

                    spawn inFlight $"slot {s} attestations" (fun () ->
                        task {
                            try
                                do! awaitBy head due ct
                                let! r = attest s ct
                                reports.Enqueue r
                            finally
                                options.OnSlotDone s
                        })

                    spawn inFlight $"slot {s} sync committee" (fun () ->
                        task {
                            do! awaitBy head syncDue ct
                            do! syncMessages s ct
                        })

                    spawn inFlight $"slot {s} aggregation" (fun () ->
                        task {
                            let a =
                                task {
                                    do! clock.WaitUntil(clock.SlotStart s + spec.AggregateDueAt s, ct)
                                    do! aggregate s ct
                                }

                            let c =
                                task {
                                    do! clock.WaitUntil(clock.SlotStart s + spec.ContributionDueAt s, ct)
                                    do! contributions s ct
                                }

                            let! _ = Task.WhenAll(a, c)
                            ()
                        })

                    inFlight.RemoveAll(fun t -> t.IsCompleted) |> ignore
                    epochWorks.RemoveAll(fun t -> t.IsCompleted) |> ignore

                    lock gate (fun () ->
                        // Slot s keeps its entry until the next pass: its attestations or sync
                        // messages may still wait for its head event. A late head event for a
                        // past slot makes its entry again: drop those too.
                        for x in headSeen.Keys |> Seq.filter (fun x -> x < s) |> List.ofSeq do
                            headSeen.Remove x |> ignore

                        let oldSlot (x: Slot) = x + 2UL * spec.SlotsPerEpoch < s

                        for x in headRoots.Keys |> Seq.filter oldSlot |> List.ofSeq do
                            headRoots.Remove x |> ignore

                        headVotes.Prune(if s > 1UL then s - 1UL else 0UL)

                        for x in attested.Keys |> Seq.filter oldSlot |> List.ofSeq do
                            attested.Remove x |> ignore

                        for x in syncRoots.Keys |> Seq.filter oldSlot |> List.ofSeq do
                            syncRoots.Remove x |> ignore

                        for x in aggregators.Keys |> Seq.filter oldSlot |> List.ofSeq do
                            aggregators.Remove x |> ignore

                        for x in syncAggregators.Keys |> Seq.filter oldSlot |> List.ofSeq do
                            syncAggregators.Remove x |> ignore

                        for old in List.ofSeq attesterDuties.Keys do
                            if old + 2UL < epoch then
                                attesterDuties.Remove old |> ignore
                                proposerDuties.Remove old |> ignore
                                syncDuties.Remove old |> ignore
                                fetchedAtVersion.Remove old |> ignore
                                selectionDone.Remove old |> ignore

                        for old in List.ofSeq dependentVotes.Keys do
                            if old + 2UL < epoch then
                                dependentVotes.Remove old |> ignore

                        for old in List.ofSeq syncSubscribed.Keys do
                            if old + 1UL < spec.SyncPeriodOf epoch then
                                syncSubscribed.Remove old |> ignore)
                    // Next slot; skip slots that passed while this one ran (the clock may have jumped).
                    let now = defaultValueArg clock.CurrentSlot slot
                    slot <- max (slot + 1UL) now
            with :? OperationCanceledException ->
                ()
            // The epoch start work runs outside inFlight: wait for it too, so nothing of it (a
            // snapshot of the slashing DB) runs after Run returns. A hook that ignores ct holds the
            // stop only so long.
            let pending = Task.WhenAll(epochWorks)
            use timer = new CancellationTokenSource()
            let! first = Task.WhenAny(pending, Task.Delay(epochWorkStopTimeout, timer.Token))
            timer.Cancel()

            if not (Object.ReferenceEquals(first, pending)) then
                log.Error
                    $"the epoch start work did not end within {epochWorkStopTimeout.TotalSeconds} s of the stop; stopping without it"

            do! Task.WhenAll(inFlight)

            try
                do! headEvents
            with :? OperationCanceledException ->
                ()
        }

/// Voluntary exits (a command and a keymanager call, never automatic).
module Exits =
    /// The values of the exit command's --epoch: none gives ValueNone (the clock's epoch), one
    /// is parsed, more than one is an error. A repeated flag must not fall back to the clock's
    /// epoch: a submitted exit cannot be taken back.
    let parseEpoch (values: string list option) : Result<Epoch voption, string> =
        match values with
        | None
        | Some [] -> Ok ValueNone
        | Some [ e ] ->
            match UInt64.TryParse e with
            | true, v -> Ok(ValueSome v)
            | _ -> Error $"--epoch '{e}' is not a number"
        | Some _ -> Error "--epoch given more than once"

    /// Signs a voluntary exit for a key through the pipeline. Returns the message and signature.
    let sign
        (spec: ChainSpec)
        (gvr: Root)
        (pipeline: Pipeline)
        (key: PubKey)
        (index: ValidatorIndex)
        (epoch: Epoch)
        (deadline: DateTimeOffset)
        (ct: CancellationToken)
        : Task<Result<VoluntaryExit * BlsSignature, string>> =
        task {
            let x =
                {
                    Epoch = epoch
                    ValidatorIndex = index
                }

            match! pipeline.Sign(Duty.request spec gvr key Priority.Low deadline (Duty.VoluntaryExit x), ct) with
            | Signed s -> return Ok(x, s)
            | other -> return Error $"exit not signed: {SignOutcome.describe other}"
        }

    /// Which keys an `eplix exit` run signs for: named keys, or every key the VC holds.
    [<RequireQualifiedAccess>]
    type Target =
        | Keys of PubKey list
        | All

    /// What happens to one key of an exit run.
    [<RequireQualifiedAccess>]
    type Plan =
        | Sign of ValidatorIndex
        /// A named key that cannot exit: a failure of the run.
        | Fail of string
        /// A key `--all` passes over (no validator yet, slashed, already exiting): reported, not a failure.
        | Skip of string

    /// Why a key cannot sign an exit, if it cannot. A slashed key signs nothing (the chain exits
    /// it already); a draining or removed key is leaving the VC; a key the beacon node does not
    /// know has no validator index to name.
    let private blocker (k: RegisteredKey) =
        match k.State, k.Index with
        | KeyState.Slashed _, _ -> ValueSome "the chain showed this key slashed; it exits already"
        | (KeyState.Draining | KeyState.Removed), _ -> ValueSome "the key is leaving this VC"
        | _, ValueNone -> ValueSome "the beacon node does not know this key"
        | _ -> ValueNone

    /// Statuses of validators that exit already or have exited (beacon-APIs validator status).
    let private exiting (status: string) =
        status.StartsWith "active_exiting"
        || status.StartsWith "exited"
        || status.StartsWith "withdrawal"
        || status = "active_slashed"

    /// The plan per key, in key order for `All` and in the given order (duplicates once) for `Keys`.
    let plan (registry: KeyRegistry) (target: Target) : (PubKey * Plan) list =
        match target with
        | Target.Keys keys ->
            keys
            |> List.distinct
            |> List.map (fun pk ->
                match registry.TryGet pk with
                | ValueNone -> pk, Plan.Fail "the key is not in this VC"
                | ValueSome k ->
                    match blocker k with
                    | ValueSome why -> pk, Plan.Fail why
                    | ValueNone -> pk, Plan.Sign k.Index.Value)
        | Target.All ->
            registry.All
            |> List.sortBy (fun k -> k.Key)
            |> List.map (fun k ->
                match blocker k with
                | ValueSome why -> k.Key, Plan.Skip why
                | ValueNone when exiting k.Status -> k.Key, Plan.Skip $"validator status {k.Status}"
                | ValueNone -> k.Key, Plan.Sign k.Index.Value)

    /// Signs the exits of many keys in one burst through the pipeline. Results in input order.
    let signMany
        (spec: ChainSpec)
        (gvr: Root)
        (pipeline: Pipeline)
        (keys: (PubKey * ValidatorIndex) list)
        (epoch: Epoch)
        (deadline: DateTimeOffset)
        (ct: CancellationToken)
        : Task<(PubKey * Result<VoluntaryExit * BlsSignature, string>) list> =
        task {
            let reqs =
                keys
                |> List.map (fun (pk, index) ->
                    Duty.request
                        spec
                        gvr
                        pk
                        Priority.Low
                        deadline
                        (Duty.VoluntaryExit
                            {
                                Epoch = epoch
                                ValidatorIndex = index
                            }))
                |> Array.ofList

            let! outcomes = pipeline.SignBurst(reqs, ct)

            return
                Array.zip reqs outcomes
                |> Array.map (fun (r, o) ->
                    match r.Duty, o with
                    | Duty.VoluntaryExit x, Signed s -> r.Key, Ok(x, s)
                    | _, other -> r.Key, Error $"exit not signed: {SignOutcome.describe other}")
                |> List.ofArray
        }

    /// The file a saved exit goes to: `<0xpubkey>.json`, as Lighthouse's `--presign` names it.
    let fileName (key: PubKey) = key.Hex + ".json"

    /// Writes a signed exit as the Beacon API's SignedVoluntaryExit JSON, so it can be posted to
    /// `/eth/v1/beacon/pool/voluntary_exits` later. The file is written atomically with mode 0600;
    /// a missing directory is created with mode 0700. Returns the path.
    let save (dir: string) (key: PubKey) (x: VoluntaryExit) (s: BlsSignature) : string =
        if not (IO.Directory.Exists dir) then
            if OperatingSystem.IsWindows() then
                IO.Directory.CreateDirectory dir |> ignore
            else
                IO.Directory.CreateDirectory(
                    dir,
                    IO.UnixFileMode.UserRead ||| IO.UnixFileMode.UserWrite ||| IO.UnixFileMode.UserExecute
                )
                |> ignore

        let path = IO.Path.Combine(dir, fileName key)

        Slashing.FileSync.writeAtomic
            path
            (Encoders.signedVoluntaryExit x s)
            (IO.UnixFileMode.UserRead ||| IO.UnixFileMode.UserWrite)

        path
