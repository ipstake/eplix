/// The validator performance monitor as a module. Config section "monitor":
///   { "enabled": true, "per_validator": false }
/// Each slot it reads the block of the slot before (GET /eth/v2/beacon/blocks/{slot}, JSON) and
/// matches its attestations, sync aggregate and proposer to this VC's duties: inclusion and
/// inclusion distance of each attestation, proposals, sync committee messages. At each epoch
/// start it closes the attestations of epoch e - 2 (missed when no block took them), reads their
/// head, target and source flags from the attestation rewards of e - 2, and reads the balances.
/// Series by key are behind "per_validator" (off): at 10,000 keys they are 10,000 series each.
/// The module does nothing while no exporter listens to the core meter.
module Eplix.Monitor.MonitorModule

open System
open System.Collections.Generic
open System.Diagnostics.Metrics
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon
open Eplix.Json
open Eplix.Monitor.Chain

let name = "monitor"

type Settings = { Enabled: bool; PerValidator: bool }

let defaults = { Enabled = true; PerValidator = false }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok defaults
    | ValueSome e ->
        match checkFields e "modules.monitor" [ "enabled"; "per_validator" ] with
        | [] ->
            try
                let flag name fallback =
                    match tryProp e name with
                    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
                    | ValueSome v when v.ValueKind = JsonValueKind.False -> false
                    | ValueSome _ -> fail $"{name} must be true or false"
                    | ValueNone -> fallback

                Ok
                    {
                        Enabled = flag "enabled" defaults.Enabled
                        PerValidator = flag "per_validator" defaults.PerValidator
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.monitor: {x.Message}" ]
        | errs -> Error errs

/// The monitor's instruments, on the core meter. The exporter adds _total to counters.
module Instruments =
    let private m = Metrics.meter

    /// Bucket bounds in slots: 1 is the best; the window ends after 2 epochs (64 on mainnet).
    let distanceBuckets: IReadOnlyList<float> =
        [| 1.0; 2.0; 3.0; 4.0; 5.0; 8.0; 16.0; 32.0; 64.0 |] :> IReadOnlyList<float>

    let attestations =
        m.CreateCounter<int64>(
            "eplix_monitor_attestations",
            description =
                "Attestation duties by outcome on chain: included, missed, unknown (a block in the window could not be read)"
        )

    let inclusionDistance =
        m.CreateHistogram<float>(
            "eplix_monitor_inclusion_distance_slots",
            unit = "{slot}",
            description = "Slots between an attestation and the block that included it",
            tags = null,
            advice = InstrumentAdvice<float>(HistogramBucketBoundaries = distanceBuckets)
        )

    let votes =
        m.CreateCounter<int64>(
            "eplix_monitor_votes",
            description = "Head, target and source votes of included attestations, by whether they earned their flag"
        )

    let proposals =
        m.CreateCounter<int64>(
            "eplix_monitor_proposals",
            description = "Proposal duties by outcome on chain: included, missed, unknown"
        )

    let syncMessages =
        m.CreateCounter<int64>(
            "eplix_monitor_sync_messages",
            description = "Sync committee messages by outcome in the next block: included, missed"
        )

    let balanceChange =
        m.CreateGauge<int64>(
            "eplix_monitor_balance_change_gwei",
            unit = "Gwei",
            description = "Change of the summed balances of the active keys over the last epoch"
        )

    let errors =
        m.CreateCounter<int64>(
            "eplix_monitor_errors",
            description = "Monitor calls that failed (request) or gave an unknown format (format), by call"
        )

    let validatorAttestations =
        m.CreateCounter<int64>(
            "eplix_monitor_validator_attestations",
            description = "Attestation duties by outcome on chain, per key"
        )

    let validatorDistance =
        m.CreateGauge<int64>(
            "eplix_monitor_validator_inclusion_distance_slots",
            unit = "{slot}",
            description = "Inclusion distance of the last included attestation, per key"
        )

    let validatorVotes =
        m.CreateCounter<int64>(
            "eplix_monitor_validator_votes",
            description = "Votes of included attestations by flag earned, per key"
        )

    let validatorProposals =
        m.CreateCounter<int64>(
            "eplix_monitor_validator_proposals",
            description = "Proposal duties by outcome on chain, per key"
        )

    let validatorSyncMessages =
        m.CreateCounter<int64>(
            "eplix_monitor_validator_sync_messages",
            description = "Sync committee messages by outcome, per key"
        )

    let validatorBalance =
        m.CreateGauge<int64>(
            "eplix_monitor_validator_balance_gwei",
            unit = "Gwei",
            description = "Balance at the last epoch start, per key"
        )

    let validatorBalanceChange =
        m.CreateGauge<int64>(
            "eplix_monitor_validator_balance_change_gwei",
            unit = "Gwei",
            description = "Balance change over the last epoch, per key"
        )

let inline private tag (name: string) (value: string) = KeyValuePair<string, objnull>(name, box value)

/// The `vote` label values, by position in a vote tally.
let private voteNames = [| "head"; "target"; "source" |]

/// An attester duty waiting for a block to include it.
type private Pending =
    {
        Key: PubKey
        Index: ValidatorIndex
        Slot: Slot
        Committee: uint64
        Position: uint64
        mutable Included: bool
    }

/// The monitor itself, apart from the module plumbing. Its state is touched by one slot at a time.
type Tracker(spec: ChainSpec, nodes: BeaconNodes, registry: KeyRegistry, perValidator: bool, log: Log) =
    let preset = spec.Preset
    let spe = spec.SlotsPerEpoch
    /// One slot at a time, in order.
    let run = new SemaphoreSlim(1, 1)
    let pending = Dictionary<struct (Slot * ValidatorIndex), Pending>()
    /// Slots whose block could not be read: a duty they might have included is unknown, not missed.
    let failed = HashSet<Slot>()
    /// Committee sizes by slot, then by committee index.
    let sizes = Dictionary<Slot, Map<uint64, int>>()
    /// The balances read at the last epoch start, by index; refilled in place each epoch.
    let balances = Dictionary<ValidatorIndex, uint64>()
    let mutable balancesEpoch: Epoch voption = ValueNone
    let mutable lastRead: Slot voption = ValueNone

    /// How many blocks one slot reads at most when it catches up (after a stall or a clock jump).
    let catchUp = 4UL

    let active (key: PubKey) =
        match registry.TryGet key with
        | ValueSome k -> k.State = KeyState.Active
        | ValueNone -> false

    /// The best node first, then the others, until one answers. Unlike BeaconNodes.Call this
    /// leaves the node scores alone: a monitor read must not change which node does the duties.
    let call (f: BeaconClient -> Task<Result<'T, ApiError>>) : Task<Result<'T, ApiError>> =
        task {
            let mutable rest = nodes.Ranked NodeRole.Duties
            let mutable result = Error(ApiError.Transport "no beacon node")

            while not rest.IsEmpty do
                let! r = f rest.Head
                result <- r

                rest <-
                    (match r with
                     | Ok _ -> []
                     | Error _ -> rest.Tail)

            return result
        }

    let error (call: string) (e: ApiError) =
        let reason =
            match e with
            | ApiError.Decode _ -> "format"
            | _ -> "request"

        Instruments.errors.Add(1L, tag "call" call, tag "reason" reason)
        log.Debug $"monitor: {call}: {e.Describe}"

    /// The per-key series of an attestation outcome; the totals go in one Add per batch.
    let attestationOutcome (p: Pending) (outcome: string) =
        if perValidator then
            Instruments.validatorAttestations.Add(1L, tag "key" p.Key.Hex, tag "outcome" outcome)

    let attestationTotal (outcome: string) (count: int) =
        if count > 0 then
            Instruments.attestations.Add(int64 count, tag "outcome" outcome)

    let proposalOutcome (key: PubKey) (outcome: string) =
        Instruments.proposals.Add(1L, tag "outcome" outcome)

        if perValidator then
            Instruments.validatorProposals.Add(1L, tag "key" key.Hex, tag "outcome" outcome)

    let syncOutcome (key: PubKey) (outcome: string) =
        Instruments.syncMessages.Add(1L, tag "outcome" outcome)

        if perValidator then
            Instruments.validatorSyncMessages.Add(1L, tag "key" key.Hex, tag "outcome" outcome)

    /// The per-key series of a vote; `tally` collects the totals, added once per epoch.
    let vote (tally: int[]) (key: PubKey) (which: int) (ok: bool) =
        let slot = which * 2 + (if ok then 1 else 0)
        tally[slot] <- tally[slot] + 1

        if perValidator then
            Instruments.validatorVotes.Add(
                1L,
                tag "key" key.Hex,
                tag "vote" voteNames[which],
                tag "correct" (if ok then "true" else "false")
            )

    let voteTotals (tally: int[]) =
        for which in 0 .. voteNames.Length - 1 do
            for ok in [ false; true ] do
                let n = tally[which * 2 + (if ok then 1 else 0)]

                if n > 0 then
                    Instruments.votes.Add(
                        int64 n,
                        tag "vote" voteNames[which],
                        tag "correct" (if ok then "true" else "false")
                    )

    let committeeSizes (slot: Slot) (ct: CancellationToken) : Task<Map<uint64, int> voption> =
        task {
            match sizes.TryGetValue slot with
            | true, m -> return ValueSome m
            | _ ->
                let path = $"/eth/v1/beacon/states/head/committees?epoch={spec.EpochOf slot}&slot={slot}"

                match! call (fun c -> c.GetJsonBytes(path, readCommittees, ct)) with
                | Ok(ValueSome xs) ->
                    let m =
                        xs
                        |> Array.filter (fun (s, _, _) -> s = slot)
                        |> Array.map (fun (_, i, n) -> i, n)
                        |> Map.ofArray

                    sizes[slot] <- m
                    return ValueSome m
                | Ok ValueNone ->
                    error "committees" (ApiError.Http(404, "no committees"))
                    return ValueNone
                | Error e ->
                    error "committees" e
                    return ValueNone
        }

    /// Matches the attestations of a block to the duties that wait. False when one could not be
    /// matched (committee sizes missing or not adding up).
    let matchAttestations (block: BlockSummary) (ct: CancellationToken) : Task<bool> =
        task {
            let mutable allMatched = true
            let mutable included = 0
            let tried = HashSet<Slot>()

            for a in block.Attestations do
                let waiting =
                    pending.Values
                    |> Seq.filter (fun p ->
                        p.Slot = a.Slot && not p.Included && Array.contains p.Committee a.Committees)
                    |> List.ofSeq

                if not waiting.IsEmpty then
                    let mutable known = ValueNone

                    if a.Committees.Length > 1 && tried.Add a.Slot then
                        let! s = committeeSizes a.Slot ct
                        known <- s
                    elif a.Committees.Length > 1 then
                        match sizes.TryGetValue a.Slot with
                        | true, m -> known <- ValueSome m
                        | _ -> ()

                    let sizeOf (c: uint64) =
                        match known with
                        | ValueSome m ->
                            match m.TryFind c with
                            | Some n -> ValueSome n
                            | None -> ValueNone
                        | ValueNone -> ValueNone

                    for p in waiting do
                        match voted a sizeOf p.Committee p.Position with
                        | Ok true ->
                            p.Included <- true
                            let d = distance p.Slot block.Slot
                            included <- included + 1
                            attestationOutcome p "included"
                            Instruments.inclusionDistance.Record(float d)

                            if perValidator then
                                Instruments.validatorDistance.Record(int64 d, tag "key" p.Key.Hex)
                        | Ok false -> ()
                        | Error why ->
                            allMatched <- false
                            log.Debug $"monitor: block {block.Slot}: {why}"

            attestationTotal "included" included
            return allMatched
        }

    /// Closes the attestations of epochs up to e - 2, counts their votes, reads the balances.
    let endEpoch (epoch: Epoch) (slot: Slot) (ct: CancellationToken) : Task =
        task {
            if epoch >= 2UL then
                let closedEpoch = epoch - 2UL
                let closed = pending.Values |> Seq.filter (fun p -> spec.EpochOf p.Slot <= closedEpoch) |> List.ofSeq
                let mutable missed = 0
                let mutable unknown = 0

                for p in closed do
                    if not p.Included then
                        let windowEnd = spec.FirstSlot(spec.EpochOf p.Slot + 2UL)
                        let unread = failed |> Seq.exists (fun s -> s > p.Slot && s < windowEnd)
                        if unread then unknown <- unknown + 1 else missed <- missed + 1
                        attestationOutcome p (if unread then "unknown" else "missed")

                attestationTotal "missed" missed
                attestationTotal "unknown" unknown
                let included = closed |> List.filter (fun p -> p.Included && spec.EpochOf p.Slot = closedEpoch)

                if not included.IsEmpty then
                    let body = Encoders.indices (included |> List.map (fun p -> p.Index) |> List.distinct)

                    match!
                        call (fun c ->
                            c.PostJson($"/eth/v1/beacon/rewards/attestations/{closedEpoch}", body, readRewards, ct))
                    with
                    | Ok r ->
                        let tally = Array.zeroCreate (voteNames.Length * 2)

                        for p in included do
                            match r.Totals.TryGetValue p.Index with
                            | true, reward ->
                                let v = votes r.Leak reward

                                match v.Head with
                                | ValueSome ok -> vote tally p.Key 0 ok
                                | ValueNone -> ()

                                vote tally p.Key 1 v.Target
                                vote tally p.Key 2 v.Source
                            | _ -> ()

                        voteTotals tally
                    | Error e -> error "rewards" e

                for p in closed do
                    pending.Remove(struct (p.Slot, p.Index)) |> ignore

                let keep = spec.FirstSlot(epoch - 1UL)
                failed.RemoveWhere(fun s -> s < keep) |> ignore

                for s in List.ofSeq sizes.Keys do
                    if s < keep then
                        sizes.Remove s |> ignore
            // Balances at the state of the epoch's first slot, after the epoch transition. Arrays and
            // one dictionary kept across epochs: at 10,000 keys the Maps built here each epoch were
            // the largest allocation of the monitor.
            let keys = registry.Active |> List.filter (fun k -> k.Index.IsSome) |> Array.ofList

            if keys.Length > 0 then
                let body = Encoders.indices (keys |> Seq.map (fun k -> k.Index.Value))

                match!
                    call (fun c ->
                        c.PostJson($"/eth/v1/beacon/states/{slot}/validator_balances", body, readBalances, ct))
                with
                | Ok now ->
                    let keyOf =
                        if perValidator then
                            let d = Dictionary<ValidatorIndex, PubKey>(keys.Length)

                            for k in keys do
                                d[k.Index.Value] <- k.Key

                            ValueSome d
                        else
                            ValueNone

                    if balancesEpoch = ValueSome(epoch - 1UL) then
                        let deltas = balanceDeltas balances now
                        Instruments.balanceChange.Record(deltas |> Array.sumBy snd)

                        match keyOf with
                        | ValueSome keyOf ->
                            for i, d in deltas do
                                match keyOf.TryGetValue i with
                                | true, k -> Instruments.validatorBalanceChange.Record(d, tag "key" k.Hex)
                                | _ -> ()
                        | ValueNone -> ()

                    match keyOf with
                    | ValueSome keyOf ->
                        for i, b in now do
                            match keyOf.TryGetValue i with
                            | true, k -> Instruments.validatorBalance.Record(int64 b, tag "key" k.Hex)
                            | _ -> ()
                    | ValueNone -> ()

                    balances.Clear()

                    for i, b in now do
                        balances[i] <- b

                    balancesEpoch <- ValueSome epoch
                | Error e -> error "balances" e
        }

    /// Reads the block of one slot and matches it to this VC's duties.
    let readSlot (view: SchedulerView) (slot: Slot) (ct: CancellationToken) : Task =
        task {
            let epoch = spec.EpochOf slot
            // The duties of this slot start waiting: no block before the next slot can include them.
            match view.AttesterDuties epoch with
            | ValueSome d ->
                for x in d.Data do
                    let k = struct (x.Slot, x.ValidatorIndex)

                    if x.Slot = slot && active x.PubKey && not (pending.ContainsKey k) then
                        pending[k] <-
                            {
                                Key = x.PubKey
                                Index = x.ValidatorIndex
                                Slot = x.Slot
                                Committee = x.CommitteeIndex
                                Position = x.ValidatorCommitteeIndex
                                Included = false
                            }
            | ValueNone -> ()

            let proposal =
                match view.ProposerDuties epoch with
                | ValueSome d -> d.Data |> Array.tryFind (fun p -> p.Slot = slot && active p.PubKey)
                | ValueNone -> None
            // The sync aggregate of this block holds the messages of the slot before.
            let sync =
                match view.SyncDuties epoch with
                | ValueSome d when slot > 0UL -> d |> Array.filter (fun x -> active x.PubKey)
                | _ -> [||]

            let waiting = pending.Values |> Seq.exists (fun p -> not p.Included && p.Slot < slot)

            if proposal.IsSome || sync.Length > 0 || waiting then
                let path = $"/eth/v2/beacon/blocks/{slot}"

                match! call (fun c -> c.GetJsonBytes(path, readBlock preset, ct)) with
                | Error e ->
                    error "block" e
                    failed.Add slot |> ignore
                    proposal |> Option.iter (fun p -> proposalOutcome p.PubKey "unknown")
                | Ok ValueNone ->
                    // No block at this slot.
                    proposal |> Option.iter (fun p -> proposalOutcome p.PubKey "missed")
                | Ok(ValueSome(BlockRead.Unknown why)) ->
                    Instruments.errors.Add(1L, tag "call" "block", tag "reason" "format")
                    log.Debug $"monitor: block {slot} skipped: {why}"
                    failed.Add slot |> ignore
                    proposal |> Option.iter (fun p -> proposalOutcome p.PubKey "unknown")
                | Ok(ValueSome(BlockRead.Block block)) ->
                    match proposal with
                    | Some p ->
                        proposalOutcome
                            p.PubKey
                            (if block.ProposerIndex = p.ValidatorIndex then "included" else "missed")
                    | None -> ()

                    match block.SyncBits with
                    | ValueSome bits ->
                        for d in sync do
                            let inBlock = d.Indices |> Array.exists (fun i -> i < uint64 bits.Length && bits[int i])
                            syncOutcome d.PubKey (if inBlock then "included" else "missed")
                    | ValueNone -> ()

                    let! allMatched = matchAttestations block ct

                    if not allMatched then
                        Instruments.errors.Add(1L, tag "call" "block", tag "reason" "format")
                        failed.Add slot |> ignore

            if slot % spe = 0UL then
                do! endEpoch epoch slot ct
        }

    /// At the start of `slot`: reads the blocks since the last one read, up to the slot before.
    member _.RunSlot (view: SchedulerView) (slot: Slot) (ct: CancellationToken) : Task =
        task {
            if slot > 0UL && Instruments.attestations.Enabled then
                do! run.WaitAsync ct

                try
                    let last = slot - 1UL

                    let next =
                        match lastRead with
                        | ValueSome l -> l + 1UL
                        | ValueNone -> last

                    let first = if last >= catchUp && next + catchUp <= last then last - catchUp + 1UL else next
                    // Blocks a stall skipped count as unread.
                    if first > next then
                        for s in next .. first - 1UL do
                            failed.Add s |> ignore

                    if first <= last then
                        for b in first..last do
                            do! readSlot view b ct
                            lastRead <- ValueSome b
                finally
                    run.Release() |> ignore
        }

let create () : Module =
    let settings = ref defaults

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun _ ->
                let s = settings.Value

                if not s.Enabled then Ok "off"
                elif s.PerValidator then Ok "on, with series per key"
                else Ok "on, totals only"
        Start =
            fun core _ ->
                task {
                    let s = settings.Value

                    if s.Enabled then
                        let tracker = Tracker(core.Spec, core.Nodes, core.Registry, s.PerValidator, core.Log)

                        core.AddDutyExtension
                            { DutyExtension.empty name with
                                RunSlot = tracker.RunSlot
                            }

                        core.Log.Info(
                            if s.PerValidator then
                                "validator monitor on, with series per key"
                            else
                                "validator monitor on (totals; per_validator adds series per key)"
                        )

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
