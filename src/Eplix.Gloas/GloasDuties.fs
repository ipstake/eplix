/// The Gloas duties: payload timeliness committee (PTC) votes, proposals
/// through produceBlockV4 with the self-built envelope signed and published after the block, and
/// proposer preferences for the proposal slots in the lookahead. Written against consensus-specs
/// v1.7.0-beta.4 (specs/gloas the same as master 065bcd5) and beacon-APIs master 79b9b05.
namespace Eplix.Gloas

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon

type Settings =
    {
        /// Ask produceBlockV4 to return the self-built envelope and blobs with the block, so any
        /// node can take the publish. False: fetch the envelope from the node that built it.
        IncludePayload: bool
        /// BuilderConfig.min_bid for p2p bids, in Gwei.
        P2pMinBid: uint64
        /// BuilderConfig.builder_boost_factor for p2p bids: 0 prefers the local payload, 100 takes
        /// whichever pays more.
        P2pBuilderBoostFactor: uint64
        /// Sign and submit ProposerPreferences for the proposals in the lookahead.
        ProposerPreferences: bool
    }

    static member Default =
        {
            IncludePayload = true
            P2pMinBid = 0UL
            P2pBuilderBoostFactor = 100UL
            ProposerPreferences = true
        }

/// What the Gloas duties did, for tests and logs.
type GloasEvent =
    | PayloadAttested of slot: Slot * count: int
    | BlockProposed of slot: Slot * root: Root * selfBuilt: bool
    | EnvelopePublished of slot: Slot * root: Root
    | ProposalFailed of slot: Slot * reason: string
    | PreferencesSent of slots: Slot list

module Gloas =
    /// BUILDER_INDEX_SELF_BUILD (beacon-chain.md).
    let selfBuild = UInt64.MaxValue

    /// The fields of a value, by position (see Schemas.Gloas for the order).
    let internal f (v: Ssz.SszValue) = Codec.fields v

    /// The SignedExecutionPayloadBid of a Gloas BeaconBlock (body field 10).
    let signedBidOf (block: Ssz.SszValue) = (f (f block).[4]).[10]

    /// The bid message of a Gloas BeaconBlock.
    let bidOf (block: Ssz.SszValue) = (f (signedBidOf block)).[0]

    let internal same (a: byte[]) (b: byte[]) = a.AsSpan().SequenceEqual(ReadOnlySpan b)

    type Bid =
        {
            ParentBlockHash: byte[]
            ParentBlockRoot: Root
            BlockHash: byte[]
            PrevRandao: byte[]
            FeeRecipient: byte[]
            GasLimit: uint64
            BuilderIndex: uint64
            Slot: Slot
            Value: uint64
            ExecutionPayment: uint64
        }

    let bid (message: Ssz.SszValue) : Bid =
        let b = f message

        {
            ParentBlockHash = Codec.asBytes b[0]
            ParentBlockRoot = Root.Of(Codec.asBytes b[1])
            BlockHash = Codec.asBytes b[2]
            PrevRandao = Codec.asBytes b[3]
            FeeRecipient = Codec.asBytes b[4]
            GasLimit = Codec.asU b[5]
            BuilderIndex = Codec.asU b[6]
            Slot = Codec.asU b[7]
            Value = Codec.asU b[8]
            ExecutionPayment = Codec.asU b[9]
        }

type GloasDuties(core: CoreServices, settings: Settings) =
    let spec = core.Spec
    let gvr = core.Genesis.GenesisValidatorsRoot
    let clock = core.Clock
    let nodes = core.Nodes
    let registry = core.Registry
    let pipeline = core.Pipeline
    let log = core.Log
    let preset = spec.Preset
    let gate = obj ()
    let ptcDuties = Dictionary<Epoch, Duties<PtcDuty>>()
    /// The registry version each epoch's PTC duties were fetched at. A key that goes active after
    /// the fetch (a doppelganger pass, an import) needs them fetched again, or it has no PTC duties in the next epoch.
    let ptcVersion = Dictionary<Epoch, int64>()
    let staleEpochs = HashSet<Epoch>()
    let available = Dictionary<Slot, TaskCompletionSource>()
    let preferencesSent = HashSet<struct (Slot * Root)>()
    let missingFeeRecipient = HashSet<PubKey>()
    let events = RecentQueue<GloasEvent>(RecentQueue.Kept)
    // One PrepareEpochs run at a time: the scheduler starts one per slot, and a slow signer must
    // not make two runs sign the same preferences.
    let prepareGate = new SemaphoreSlim(1, 1)

    let note e = events.Enqueue e

    let gloasAt (epoch: Epoch) = spec.IsGloasAt epoch

    let activeKey (key: PubKey) =
        match registry.TryGet key with
        | ValueSome k -> k.State = KeyState.Active
        | ValueNone -> false

    let availableSignal (slot: Slot) =
        lock gate (fun () ->
            match available.TryGetValue slot with
            | true, t -> t
            | _ ->
                let t = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                available[slot] <- t
                t)

    let request key priority deadline duty = Duty.request spec gvr key priority deadline duty

    let feeRecipientOf (key: PubKey) =
        match registry.SettingsOf(key).FeeRecipient with
        | ValueSome f -> ValueSome f
        | ValueNone -> core.Defaults.FeeRecipient

    let gasLimitOf (key: PubKey) = defaultValueArg (registry.SettingsOf(key).GasLimit) core.Defaults.GasLimit

    let addressBytes (hex: string) = Hex.tryDecodeFixed 20 hex

    // ---- PTC ----

    let fetchPtc (epoch: Epoch) (ct: CancellationToken) =
        task {
            let version = registry.Version

            let indices =
                registry.Active
                |> List.choose (fun k ->
                    match k.Index with
                    | ValueSome i -> Some i
                    | ValueNone -> None)

            if indices.IsEmpty then
                lock gate (fun () ->
                    ptcDuties[epoch] <-
                        {
                            DependentRoot = Root.Zero
                            ExecutionOptimistic = false
                            Data = [||]
                        }

                    ptcVersion[epoch] <- version)
            else
                // As the scheduler's duties: a verified answer is preferred, an optimistic one is
                // used with a warning when no node gives a verified answer in time.
                match!
                    nodes.CallPreferring(
                        (fun b -> b.PtcDuties(epoch, indices, ct)),
                        (fun d -> not d.ExecutionOptimistic),
                        NodeRole.Duties
                    )
                with
                | Ok d ->
                    if d.ExecutionOptimistic then
                        log.Warn
                            $"epoch {epoch}: PTC duties come from an optimistic beacon node (no node answered with a verified head); used anyway"

                    lock gate (fun () ->
                        ptcDuties[epoch] <- d
                        ptcVersion[epoch] <- version
                        staleEpochs.Remove epoch |> ignore)

                    if d.Data.Length > 0 then
                        log.Debug $"epoch {epoch}: {d.Data.Length} PTC duties"
                | Error e -> log.Warn $"epoch {epoch}: PTC duties failed: {e.Describe}"
        }

    /// The PTC seats of this VC's active keys at a slot.
    let ptcAt (slot: Slot) =
        lock gate (fun () ->
            match ptcDuties.TryGetValue(spec.EpochOf slot) with
            | true, d -> d.Data |> Array.filter (fun x -> x.Slot = slot)
            | _ -> [||])
        |> Array.filter (fun d -> activeKey d.PubKey)

    let payloadAttest (slot: Slot) (ct: CancellationToken) =
        task {
            // Vote once the node has the envelope and blobs (execution_payload_available), and no
            // later than 5% of the slot before PAYLOAD_ATTESTATION_DUE_BPS, so the vote is out by
            // then. The duties are read after the wait: those of an epoch's first slot may still be
            // in flight at the slot start.
            let latest =
                clock.SlotStart slot
                + spec.Bps(if spec.PayloadAttestationDueBps > 500UL then spec.PayloadAttestationDueBps - 500UL else 0UL)

            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            let! _ = Task.WhenAny((availableSignal slot).Task, clock.WaitUntil(latest, cts.Token))
            cts.Cancel()
            ct.ThrowIfCancellationRequested()
            let mine = ptcAt slot

            if mine.Length > 0 then
                // With ptc_consensus_threshold above 1 the nodes are polled for agreement until 2.5%
                // of the slot before the due time (300 ms at 12 s), so signing and submission fit.
                let pollUntil =
                    clock.SlotStart slot
                    + spec.Bps(
                        if spec.PayloadAttestationDueBps > 250UL then spec.PayloadAttestationDueBps - 250UL else 0UL
                    )

                match! nodes.PayloadAttestationData(slot, pollUntil, ct) with
                | Error e ->
                    // Counted, so EplixDutiesMissed shows PTC votes lost below ptc_consensus_threshold.
                    Metrics.missed "payload_attestation" Metrics.Reason.BeaconNode mine.Length
                    log.Warn $"slot {slot}: payload attestation data: {e}"
                | Ok ValueNone -> log.Info $"slot {slot}: the node saw no block; no PTC vote (validator.md)"
                | Ok(ValueSome data) when data.Slot <> slot ->
                    log.Warn $"slot {slot}: payload attestation data for slot {data.Slot}"
                | Ok(ValueSome data) ->
                    let deadline = clock.SlotStart(slot + 1UL)

                    let reqs =
                        Duty.requests
                            spec
                            gvr
                            (mine |> Array.map (fun d -> d.PubKey))
                            Priority.High
                            deadline
                            (Duty.PayloadAttestation data)

                    let! outcomes = pipeline.SignBurst(reqs, ct)

                    let msgs =
                        Array.zip mine outcomes
                        |> Array.choose (fun (d, o) ->
                            match o with
                            | Signed s ->
                                Some
                                    {
                                        ValidatorIndex = d.ValidatorIndex
                                        Data = data
                                        Signature = s
                                    }
                            | Refused(Paused _) -> None // an emergency switch, logged once when it changed
                            | o ->
                                log.Warn $"slot {slot}: PTC vote of {d.PubKey.Short} not signed: {o.Describe}"
                                None)

                    if msgs.Length > 0 then
                        match!
                            nodes.Broadcast(
                                (fun b -> b.SubmitPayloadAttestations(msgs, ct)),
                                NodeRole.AttestationPublish,
                                BroadcastTopic.Attestations
                            )
                        with
                        | Ok() ->
                            Metrics.completed "payload_attestation" msgs.Length
                            note (PayloadAttested(slot, msgs.Length))

                            log.Info
                                $"slot {slot}: {msgs.Length} PTC votes, payload present {data.PayloadPresent}, blobs {data.BlobDataAvailable}"
                        | Error e ->
                            Metrics.missed "payload_attestation" Metrics.Reason.Submit msgs.Length
                            log.Warn $"slot {slot}: submitting PTC votes: {e.Describe}"
        }

    // ---- Proposer preferences ----

    /// ProposerPreferences for the future proposal slots of `epoch` (validator.md, "Broadcasting
    /// SignedProposerPreferences"): once per slot and dependent root.
    let sendPreferences (view: SchedulerView) (epoch: Epoch) (ct: CancellationToken) =
        task {
            match view.ProposerDuties epoch with
            | ValueNone -> ()
            | ValueSome duties ->
                let now = defaultValueArg clock.CurrentSlot 0UL

                let todo =
                    duties.Data
                    |> Array.filter (fun d ->
                        d.Slot > now
                        && activeKey d.PubKey
                        && lock gate (fun () -> not (preferencesSent.Contains(struct (d.Slot, duties.DependentRoot)))))

                let prefs =
                    todo
                    |> Array.choose (fun d ->
                        match feeRecipientOf d.PubKey |> ValueOption.bind addressBytes with
                        | ValueSome fee ->
                            Some(
                                d,
                                {
                                    DependentRoot = duties.DependentRoot
                                    ProposalSlot = d.Slot
                                    ValidatorIndex = d.ValidatorIndex
                                    FeeRecipient = fee
                                    TargetGasLimit = gasLimitOf d.PubKey
                                }
                            )
                        | ValueNone ->
                            if lock gate (fun () -> missingFeeRecipient.Add d.PubKey) then
                                log.Warn
                                    $"key {d.PubKey.Short}: no fee recipient, so no proposer preferences; builders' bids for its slots are ignored"

                            None)

                if prefs.Length > 0 then
                    let reqs =
                        prefs
                        |> Array.map (fun (d, p) ->
                            request d.PubKey Priority.Low (clock.SlotStart d.Slot) (Duty.ProposerPreferences p))

                    let! outcomes = pipeline.SignBurst(reqs, ct)

                    let signed =
                        Array.zip prefs outcomes
                        |> Array.choose (fun ((d, p), o) ->
                            match o with
                            | Signed s -> Some { Message = p; Signature = s }
                            | Refused(Paused _) -> None // an emergency switch, logged once when it changed
                            | o ->
                                log.Warn
                                    $"slot {d.Slot}: proposer preferences of {d.PubKey.Short} not signed: {o.Describe}"

                                None)

                    if signed.Length > 0 then
                        match!
                            nodes.Broadcast(
                                (fun b -> b.SubmitProposerPreferences(signed, ct)),
                                NodeRole.BlockPublish,
                                BroadcastTopic.Preparations
                            )
                        with
                        | Ok() ->
                            lock gate (fun () ->
                                for s in signed do
                                    preferencesSent.Add(struct (s.Message.ProposalSlot, s.Message.DependentRoot))
                                    |> ignore)

                            let slots = signed |> Array.map (fun s -> s.Message.ProposalSlot) |> List.ofArray
                            note (PreferencesSent slots)
                            log.Info $"""proposer preferences for slots {String.Join(", ", slots)}"""
                        | Error e -> log.Warn $"submitting proposer preferences: {e.Describe}"
        }

    // ---- Proposals ----

    let header (block: Ssz.SszValue) : BeaconBlockHeader =
        let b = Gloas.f block

        {
            Slot = Codec.asU b[0]
            ProposerIndex = Codec.asU b[1]
            ParentRoot = Root.Of(Codec.asBytes b[2])
            StateRoot = Root.Of(Codec.asBytes b[3])
            BodyRoot = Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.beaconBlockBody preset) b[4])
        }

    /// Checks a produced block before the VC signs it. Error: the reason. It runs on
    /// every node's answer before the choice, so it hashes nothing: slot, proposer and parent are
    /// read from the block, and the body root is computed once, for the chosen block.
    /// Every bid, self-built ones too, must pay the key's fee recipient: a node that missed
    /// prepare_beacon_proposer, or lies, builds with its own. A key with no fee recipient (not
    /// even the default) has nothing to compare against; a key whose fee recipient does not
    /// decode as an address gets no block signed. The bid's gas_limit is not checked
    /// against the key's target: the EL moves the limit toward the target by at most 1/1024 of
    /// the parent's limit per block, and the VC does not have the parent's limit.
    let check (d: ProposerDuty) (config: BuilderConfig) (p: ProducedBlockV4) : Result<Gloas.Bid, string> =
        let b = Gloas.f p.Block
        let blockSlot, proposer = Codec.asU b[0], Codec.asU b[1]
        let parent = Root.Of(Codec.asBytes b[2])
        let bid = Gloas.bid (Gloas.bidOf p.Block)
        let configured = feeRecipientOf d.PubKey
        let fee = configured |> ValueOption.bind addressBytes

        if configured.IsSome && fee.IsNone then
            // A fee recipient that does not decode must not turn the bid check off.
            Error $"the key's fee recipient '{configured.Value}' is not a 20-byte address"
        elif p.Version <> "gloas" then
            Error $"block version {p.Version}"
        elif blockSlot <> d.Slot || proposer <> d.ValidatorIndex then
            Error $"the block is for slot {blockSlot}, proposer {proposer}"
        elif bid.Slot <> d.Slot then
            Error $"the bid is for slot {bid.Slot}"
        elif bid.ParentBlockRoot <> parent then
            Error $"the bid builds on block {bid.ParentBlockRoot.Hex}, the block's parent is {parent.Hex}"
        elif fee.IsSome && not (Gloas.same fee.Value bid.FeeRecipient) then
            Error $"the bid pays {Hex.encodeArray bid.FeeRecipient}, not the key's fee recipient"
        elif bid.BuilderIndex = Gloas.selfBuild then
            if bid.Value <> 0UL then Error "a self-build bid with a value" else Ok bid
        else
            match p.BuilderUrl, core.Builder() with
            | ValueSome url, ValueSome hooks ->
                match hooks.CheckBid d url (Gloas.signedBidOf p.Block) with
                | Ok() -> Ok bid
                | Error e -> Error e
            | ValueSome url, ValueNone -> Error $"a builder API bid from {url}, and this build has no builder module"
            | ValueNone, _ ->
                // A p2p bid: its value alone against the p2p floor. The execution payment is a
                // promise outside the protocol that nothing enforces; a builder API bid counts it
                // only up to the builder's max_execution_payment, and p2p bids have no such cap.
                if bid.Value < config.P2pMinBid then
                    Error
                        $"a p2p bid of {bid.Value} Gwei (execution payment {bid.ExecutionPayment} not counted), below the minimum {config.P2pMinBid}"
                else
                    Ok bid

    let propose (d: ProposerDuty) (ct: CancellationToken) : Task<bool> =
        task {
            let slot = d.Slot
            let epoch = spec.EpochOf slot

            let fail (why: string) =
                note (ProposalFailed(slot, why))
                log.Error $"slot {slot}: proposal by {d.PubKey.Short} failed: {why}"
                false

            let deadline = clock.SlotStart(slot + 1UL)

            match! pipeline.Sign(request d.PubKey Priority.High deadline (Duty.RandaoReveal epoch), ct) with
            | Signed reveal ->
                // Per node: each node gets its own client codes after the text.
                let graffiti (b: BeaconClient) = core.Graffiti.For(d, epoch, b)

                let! builders =
                    task {
                        match core.Builder() with
                        | ValueSome hooks ->
                            try
                                return! hooks.EntriesFor d ct
                            with e ->
                                log.Warn $"slot {slot}: builder entries: {e.Message}; p2p bids and self-build only"
                                return []
                        | ValueNone -> return []
                    }

                let config =
                    {
                        P2pMinBid = settings.P2pMinBid
                        P2pBuilderBoostFactor = settings.P2pBuilderBoostFactor
                        Builders = builders
                    }

                let soft = clock.SlotStart slot + TimeSpan.FromTicks((spec.AttestationDue slot).Ticks / 2L)
                // Every node's answer is checked before the highest value is taken, so a claimed
                // value counts only for a block the VC would sign (`only` adds a rule to the check).
                let produce (c: BuilderConfig) (only: ProducedBlockV4 -> string voption) =
                    nodes.HighestValue(
                        (fun b -> b.ProduceBlockV4(slot, reveal, graffiti b, settings.IncludePayload, c, preset, ct)),
                        (fun (p: ProducedBlockV4) -> p.ConsensusBlockValue + p.ExecutionPayloadValue),
                        soft,
                        ct,
                        NodeRole.BlockData,
                        fun p ->
                            match check d c p with
                            | Error why -> ValueSome why
                            | Ok _ -> only p
                    )

                let! first = produce config (fun _ -> ValueNone)

                let! chosen =
                    task {
                        match first with
                        | Ok(p, node) ->
                            match check d config p with
                            | Ok bid -> return Ok(p, node, bid)
                            | Error why -> return Error why
                        | Error(ApiError.Invalid why) ->
                            // No answer passed the check: a bad bid is not signed; ask again for a
                            // local block.
                            log.Warn $"slot {slot}: {why}; asking for a self-built block"

                            let local =
                                {
                                    P2pMinBid = 0UL
                                    P2pBuilderBoostFactor = 0UL
                                    Builders = []
                                }

                            let selfBuilt (p: ProducedBlockV4) =
                                if (Gloas.bid (Gloas.bidOf p.Block)).BuilderIndex = Gloas.selfBuild then
                                    ValueNone
                                else
                                    ValueSome "the node returned a builder's bid when asked for a local block"

                            match! produce local selfBuilt with
                            | Error e -> return Error $"produce block (self-build): {e.Describe}"
                            | Ok(p2, node2) ->
                                match check d local p2 with
                                | Ok bid -> return Ok(p2, node2, bid)
                                | Error why2 -> return Error why2
                        | Error e -> return Error $"produce block: {e.Describe}"
                    }

                match chosen with
                | Error why -> return fail why
                | Ok(p, node, bid) ->
                    let h = header p.Block
                    let selfBuilt = bid.BuilderIndex = Gloas.selfBuild
                    // The block is small and encodes here. On the thread pool while it is signed:
                    // for an envelope that came with the block, its root and its encoding with the
                    // blobs (2 MB), which the envelope needs once the block is out.
                    let unsignedBlock =
                        UnsignedPublication(
                            Schemas.Gloas.signedBeaconBlock preset,
                            (fun sg -> Ssz.Fields [| p.Block; sg |]),
                            [ 1 ]
                        )

                    let early =
                        match p.Included with
                        | ValueSome(struct (env, proofs, blobs)) when selfBuilt ->
                            let root =
                                Task.Run(fun () ->
                                    Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.executionPayloadEnvelope preset) env))

                            let encoding =
                                Task.Run(fun () ->
                                    UnsignedPublication(
                                        Schemas.Gloas.signedExecutionPayloadEnvelopeContents preset,
                                        (fun sg -> Ssz.Fields [| Ssz.Fields [| env; sg |]; proofs; blobs |]),
                                        [ 0; 1 ]
                                    ))

                            ValueSome(struct (env, root, encoding))
                        | _ -> ValueNone

                    match! pipeline.Sign(request d.PubKey Priority.High deadline (Duty.Block h), ct) with
                    | Signed s ->
                        let signedBlock = unsignedBlock.WithSignature s.Bytes

                        let publish (b: BeaconClient) =
                            match p.BuilderUrl with
                            | ValueSome url -> b.PublishBlock("gloas", signedBlock, ct, url)
                            | ValueNone -> b.PublishBlock("gloas", signedBlock, ct)

                        match! nodes.Broadcast(publish, NodeRole.BlockPublish, BroadcastTopic.Blocks) with
                        | Error e -> return fail $"publish: {e.Describe}"
                        | Ok() ->
                            let root = Codec.hashBeaconBlockHeader h
                            note (BlockProposed(slot, root, selfBuilt))

                            log.Info
                                $"""slot {slot}: block {root.Hex} proposed by {d.PubKey.Short}, {(if selfBuilt then "self-built" else $"bid of builder {bid.BuilderIndex}")}"""

                            if not selfBuilt then
                                // The winning builder releases the envelope.
                                return true
                            else
                                let! envelope =
                                    task {
                                        match p.Included with
                                        | ValueSome(struct (env, _, _)) -> return Ok env
                                        | ValueNone ->
                                            match! node.ExecutionPayloadEnvelope(slot, root, preset, ct) with
                                            | Ok env -> return Ok env
                                            | Error e -> return Error $"envelope: {e.Describe}"
                                    }

                                match envelope with
                                | Error why -> return fail why
                                | Ok env ->
                                    let e = Gloas.f env
                                    let payload = Gloas.f e[0]

                                    if
                                        Codec.asU e[2] <> Gloas.selfBuild
                                        || Root.Of(Codec.asBytes e[3]) <> root
                                        || Root.Of(Codec.asBytes e[4]) <> h.ParentRoot
                                        || Codec.asU payload[18] <> slot
                                    then
                                        return fail "the envelope does not belong to the block"
                                    // The payload must be the one the bid committed to, so it
                                    // pays the fee recipient the bid check accepted.
                                    elif not (Gloas.same (Codec.asBytes payload[1]) bid.FeeRecipient) then
                                        return
                                            fail
                                                $"the envelope pays {Hex.encodeArray (Codec.asBytes payload[1])}, the bid {Hex.encodeArray bid.FeeRecipient}"
                                    elif not (Gloas.same (Codec.asBytes payload[12]) bid.BlockHash) then
                                        return
                                            fail
                                                $"the envelope's block hash {Hex.encodeArray (Codec.asBytes payload[12])} is not the bid's"
                                    elif
                                        Codec.asU payload[7] <> bid.GasLimit
                                        || not (Gloas.same (Codec.asBytes payload[0]) bid.ParentBlockHash)
                                        || not (Gloas.same (Codec.asBytes payload[5]) bid.PrevRandao)
                                    then
                                        return
                                            fail "the envelope's gas limit, parent hash or prev_randao is not the bid's"
                                    else
                                        let msg =
                                            {
                                                Schema = Schemas.Gloas.executionPayloadEnvelope preset
                                                Value = env
                                            }

                                        let duty = Duty.PayloadEnvelope(slot, msg)

                                        let! req =
                                            task {
                                                match early with
                                                // The root of this same envelope value, hashed ahead.
                                                | ValueSome(struct (e, root, _)) when obj.ReferenceEquals(e, env) ->
                                                    let! r = root

                                                    return
                                                        Duty.requestWithRoot
                                                            spec
                                                            gvr
                                                            d.PubKey
                                                            Priority.High
                                                            deadline
                                                            duty
                                                            r
                                                | _ -> return request d.PubKey Priority.High deadline duty
                                            }

                                        match! pipeline.Sign(req, ct) with
                                        | Signed es ->
                                            let signedEnv = Ssz.Fields [| env; Ssz.Bytes es.Bytes |]

                                            let! published =
                                                match early with
                                                | ValueSome(struct (_, _, encoding)) ->
                                                    // Stateless: the blobs go with it, so every node can take it.
                                                    task {
                                                        let! unsigned = encoding
                                                        let contents = unsigned.WithSignature es.Bytes

                                                        return!
                                                            nodes.Broadcast(
                                                                (fun b ->
                                                                    b.PublishExecutionPayloadEnvelope(
                                                                        contents,
                                                                        true,
                                                                        ct
                                                                    )),
                                                                NodeRole.BlockPublish,
                                                                BroadcastTopic.Blocks
                                                            )
                                                    }
                                                | ValueNone ->
                                                    // Stateful: only the node that built it holds the blobs.
                                                    node.PublishExecutionPayloadEnvelope(
                                                        Publication.Of(
                                                            Schemas.Gloas.signedExecutionPayloadEnvelope preset,
                                                            signedEnv
                                                        ),
                                                        false,
                                                        ct
                                                    )

                                            match published with
                                            | Ok() ->
                                                note (EnvelopePublished(slot, root))
                                                log.Info $"slot {slot}: payload envelope published"
                                                return true
                                            | Error err -> return fail $"publish envelope: {err.Describe}"
                                        | other -> return fail $"envelope signature: {other.Describe}"
                    | other -> return fail $"block signature: {other.Describe}"
            | other -> return fail $"RANDAO reveal: {other.Describe}"
        }

    member _.Events = events

    /// The slots that hold a payload-available signal.
    member internal _.SignalSlots = lock gate (fun () -> List.ofSeq available.Keys)

    /// The duty extension the scheduler runs.
    member _.Extension: DutyExtension =
        { DutyExtension.empty ModuleNames.Gloas with
            Topics = [ "execution_payload_available" ]
            OnEvent =
                fun ev ->
                    if ev.Event = "execution_payload_available" then
                        match Json.decodeString Decoders.payloadAvailable ev.Data with
                        | Ok(struct (slot, _)) ->
                            // Only for the clock's slot plus or minus 1, as head events: the
                            // prune drops past slots only, so a far slot would stay for good.
                            match clock.CurrentSlot with
                            | ValueSome now when slot + 1UL >= now && slot <= now + 1UL ->
                                (availableSignal slot).TrySetResult() |> ignore
                            | now ->
                                log.Debug
                                    $"execution_payload_available event for slot {slot}, not within one slot of the clock's slot {now}; ignored"
                        | Error e -> log.Warn $"execution_payload_available event: {e}"
            OnHead =
                fun ev ->
                    let epoch = spec.EpochOf ev.Slot

                    lock gate (fun () ->
                        let check e (root: Root) =
                            match ptcDuties.TryGetValue e with
                            | true, d when d.Data.Length > 0 && d.DependentRoot <> root ->
                                if staleEpochs.Add e then
                                    log.Info $"epoch {e}: dependent root changed; PTC duties will be fetched again"
                            | _ -> ()

                        check epoch ev.PreviousDutyDependentRoot
                        check (epoch + 1UL) ev.CurrentDutyDependentRoot)
            PrepareEpochs =
                fun view epoch ct ->
                    task {
                        do! prepareGate.WaitAsync ct

                        try
                            let version = registry.Version

                            for e in [ epoch; epoch + 1UL ] do
                                if gloasAt e then
                                    let need =
                                        lock gate (fun () ->
                                            not (ptcDuties.ContainsKey e)
                                            || staleEpochs.Contains e
                                            || (match ptcVersion.TryGetValue e with
                                                | true, v -> v <> version
                                                | _ -> true))

                                    if need then
                                        do! fetchPtc e ct

                                    if settings.ProposerPreferences then
                                        do! sendPreferences view e ct

                            lock gate (fun () ->
                                for old in List.ofSeq ptcDuties.Keys do
                                    if old + 2UL < epoch then
                                        ptcDuties.Remove old |> ignore
                                        ptcVersion.Remove old |> ignore

                                for s in List.ofSeq available.Keys do
                                    if spec.EpochOf s + 2UL < epoch then
                                        available.Remove s |> ignore

                                preferencesSent.RemoveWhere(fun struct (s, _) -> spec.EpochOf s + 2UL < epoch)
                                |> ignore)
                        finally
                            prepareGate.Release() |> ignore
                    }
            RunSlot =
                fun _ slot ct ->
                    if gloasAt (spec.EpochOf slot) then payloadAttest slot ct :> Task else Task.CompletedTask
            Propose = fun _ d ct -> if gloasAt (spec.EpochOf d.Slot) then ValueSome(propose d ct) else ValueNone
        }
