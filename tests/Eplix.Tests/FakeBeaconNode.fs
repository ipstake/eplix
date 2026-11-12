/// An in-process beacon node behind an HttpMessageHandler: deterministic duties and attestation
/// data, and a record of what the VC submitted. Enough of the Beacon API for the tests.
module Eplix.Tests.FakeBeaconNode

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Net
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Channels
open System.Threading.Tasks
open Eplix
open Eplix.Json

type FakeValidator =
    {
        Index: uint64
        PubKey: PubKey
        mutable Status: string
    }

type Submission =
    {
        Slot: Slot
        CommitteeIndex: uint64
        AttesterIndex: uint64
        Data: AttestationData
        Signature: BlsSignature
        ConsensusVersion: string
    }

/// The chain values the fake serves on /eth/v1/config/spec (strings, as the API does), with
/// Gloas at `gloasEpoch` (UInt64.MaxValue: not scheduled).
let rec specValuesGloas (secondsPerSlot: int) (slotsPerEpoch: int) (gloasEpoch: uint64) =
    specValuesPreset "minimal" secondsPerSlot slotsPerEpoch gloasEpoch

/// The same with another PRESET_BASE ("mainnet" for the 32-slot tests).
and specValuesPreset (presetBase: string) (secondsPerSlot: int) (slotsPerEpoch: int) (gloasEpoch: uint64) =
    [
        "CONFIG_NAME", "fake"
        "PRESET_BASE", presetBase
        "SECONDS_PER_SLOT", string secondsPerSlot
        "SLOTS_PER_EPOCH", string slotsPerEpoch
        "GENESIS_FORK_VERSION", "0x00000001"
        "ALTAIR_FORK_VERSION", "0x01000001"
        "ALTAIR_FORK_EPOCH", "0"
        "BELLATRIX_FORK_VERSION", "0x02000001"
        "BELLATRIX_FORK_EPOCH", "0"
        "CAPELLA_FORK_VERSION", "0x03000001"
        "CAPELLA_FORK_EPOCH", "0"
        "DENEB_FORK_VERSION", "0x04000001"
        "DENEB_FORK_EPOCH", "0"
        "ELECTRA_FORK_VERSION", "0x05000001"
        "ELECTRA_FORK_EPOCH", "0"
        "FULU_FORK_VERSION", "0x06000001"
        "FULU_FORK_EPOCH", "1"
        "GLOAS_FORK_VERSION", "0x07000001"
        "GLOAS_FORK_EPOCH", string gloasEpoch
        "DOMAIN_BEACON_ATTESTER", "0x01000000"
        "DOMAIN_BEACON_PROPOSER", "0x00000000"
        "DOMAIN_RANDAO", "0x02000000"
        "DOMAIN_BEACON_BUILDER", "0x0B000000"
        "DOMAIN_PTC_ATTESTER", "0x0C000000"
        "DOMAIN_PROPOSER_PREFERENCES", "0x0D000000"
        "ATTESTATION_DUE_BPS_GLOAS", "2500"
        "PAYLOAD_ATTESTATION_DUE_BPS", "7500"
        "PTC_SIZE", "16"
    ]

let specValues (secondsPerSlot: int) (slotsPerEpoch: int) = specValuesGloas secondsPerSlot slotsPerEpoch UInt64.MaxValue

/// The same values as a pinned config.yaml.
let configYamlGloas secondsPerSlot slotsPerEpoch gloasEpoch =
    let lines =
        specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch
        |> List.filter (fun (k, _) -> k <> "SLOTS_PER_EPOCH" && not (k.StartsWith "DOMAIN_"))
        |> List.map (fun (k, v) ->
            if v.StartsWith "0x" || k = "CONFIG_NAME" || k = "PRESET_BASE" then $"{k}: '{v}'" else $"{k}: {v}")

    "# fake chain\n" + String.Join("\n", lines) + "\n"

let configYaml secondsPerSlot slotsPerEpoch = configYamlGloas secondsPerSlot slotsPerEpoch UInt64.MaxValue

let gvr = Root.Of(Array.init 32 (fun i -> byte (0xA0 + i)))

/// A request as the node received it, for checks against the Beacon API spec.
type RecordedRequest =
    {
        Method: string
        Path: string
        /// The query string without the leading '?'.
        Query: string
        Headers: Map<string, string>
        ContentType: string
        Body: byte[]
    }

/// What /eth/v1/node/syncing reports.
type FakeSync =
    {
        IsSyncing: bool
        IsOptimistic: bool
        ElOffline: bool
    }

type FakeBeaconNode(genesisTime: uint64, secondsPerSlot: int, slotsPerEpoch: int, ?presetBase: string) =
    inherit HttpMessageHandler()
    let presetBase = defaultArg presetBase "minimal"

    let validators = List<FakeValidator>()
    let submissions = ConcurrentQueue<Submission>()
    let requests = ConcurrentQueue<string>()
    let eventChannels = ConcurrentBag<Channel<string>>()
    let mutable dataOverride: (Slot -> AttestationData) option = None
    let mutable dependentRootSalt = 0
    let proposals = ConcurrentDictionary<Slot, uint64>()
    let prepared = ConcurrentDictionary<uint64, byte[]>()
    let graffitis = ConcurrentDictionary<Slot, byte[]>()
    let recorded = ConcurrentQueue<RecordedRequest>()
    let syncSeats = ConcurrentDictionary<uint64, uint64[]>()
    let posts = ConcurrentQueue<string * string>()
    let published = ConcurrentQueue<string * string * byte[]>()
    let ptcSlots = ConcurrentDictionary<Slot, uint64[]>()
    let envelopes = ConcurrentDictionary<Slot, Ssz.SszValue>()
    let publishedEnvelopes = ConcurrentQueue<string * string * byte[]>()
    let builderConfigs = ConcurrentQueue<string>()
    let builderUrls = ConcurrentQueue<string>()
    let order = ConcurrentQueue<string>()
    let boostFactors = ConcurrentQueue<Slot * uint64>()
    let publishedBlinded = ConcurrentQueue<string * string * byte[]>()
    let registrations = ConcurrentQueue<string>()

    let preset =
        Preset.FromSpec(Map.ofList (specValuesPreset presetBase secondsPerSlot slotsPerEpoch UInt64.MaxValue))

    let infinitySignature = Array.init 96 (fun i -> if i = 0 then 0xC0uy else 0uy)

    let spe = uint64 slotsPerEpoch

    let blockRoot (slot: Slot) =
        let b = Array.zeroCreate<byte> 32
        Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(), slot + 1UL)
        b[31] <- 0xBBuy
        Root.Of b

    let json (status: HttpStatusCode) (write: Utf8JsonWriter -> unit) =
        let resp = new HttpResponseMessage(status)
        resp.Content <- new ByteArrayContent(toBytes write)
        resp.Content.Headers.ContentType <- Headers.MediaTypeHeaderValue "application/json"
        resp

    let dataObj (w: Utf8JsonWriter) (inner: Utf8JsonWriter -> unit) =
        w.WriteStartObject()
        w.WritePropertyName "data"
        inner w
        w.WriteEndObject()

    let defaultData (slot: Slot) : AttestationData =
        let epoch = slot / spe

        {
            Slot = slot
            Index = 0UL
            BeaconBlockRoot = blockRoot slot
            Source =
                {
                    Epoch = (if epoch = 0UL then 0UL else epoch - 1UL)
                    Root = blockRoot ((if epoch = 0UL then 0UL else epoch - 1UL) * spe)
                }
            Target =
                {
                    Epoch = epoch
                    Root = blockRoot (epoch * spe)
                }
        }

    let dutySlot (v: FakeValidator) (epoch: Epoch) = epoch * spe + (v.Index % spe)

    member val Fail: (string -> bool) = (fun _ -> false) with get, set

    /// The combined proof the selection endpoints return for (validator index, slot, the VC's
    /// proof), as a distributed validator middleware would. ValueNone leaves the entry out.
    member val CombineSelection: (uint64 -> Slot -> BlsSignature -> BlsSignature voption) =
        (fun _ _ p -> ValueSome p) with get, set

    /// Whether the liveness endpoint reports a validator index live in an epoch.
    member val Live: (Epoch -> uint64 -> bool) = (fun _ _ -> false) with get, set
    /// Indices the liveness endpoint leaves out of its answer for an epoch (a partial answer).
    member val LivenessOmit: (Epoch -> uint64 -> bool) = (fun _ _ -> false) with get, set
    /// committee_length in attester duties. 8 makes every key an aggregator (modulo 1).
    member val CommitteeLength = 64UL with get, set

    /// Which validators the validators endpoint reports as slashed, by index.
    member val Slashed: (uint64 -> bool) = (fun _ -> false) with get, set
    /// produceBlockV3 answers in JSON even when the VC asks for SSZ.
    member val BlockAsJson = false with get, set
    /// The root /eth/v1/beacon/blocks/head/root returns.
    member val HeadRoot = Root.Zero with get, set
    /// Slot -> proposer index.
    member _.Proposals = proposals
    /// Validator index -> sync committee seats.
    member _.SyncSeats = syncSeats
    /// Every POST the node accepted that is not an attestation or block: (path, body).
    member _.Posts = posts
    /// Published blocks: (consensus version, content type, body).
    member _.Published = published
    member _.Preset = preset
    /// Gloas from this epoch (default: not scheduled). Set before the VC starts.
    member val GloasEpoch = UInt64.MaxValue with get, set
    /// Spec values that replace the default ones on /eth/v1/config/spec, or add keys to it.
    member val SpecOverride: (string * string) list = [] with get, set
    /// What /eth/v1/beacon/genesis reports; the fake's own slots still count from `genesisTime`.
    member val ReportedGenesisTime = genesisTime with get, set
    member val GenesisValidatorsRoot = gvr with get, set
    /// What /eth/v1/beacon/genesis reports as the genesis fork version.
    member val GenesisForkVersion = "0x00000001" with get, set
    /// Slot -> validator indices with a PTC seat in that slot.
    member _.PtcSlots = ptcSlots
    /// payload_present in the payload attestation data the node serves.
    member val PayloadPresent = true with get, set
    /// Slots for which payload_attestation_data answers 204 (no block seen).
    member val NoBlockSlots: Set<Slot> = Set.empty with get, set
    /// When set, produceBlockV4 answers with a builder's bid paying this fee recipient, unless
    /// the request asks for a local block (builder_boost_factor 0).
    member val BuilderBid: byte[] option = None with get, set
    /// The bid's value in Gwei.
    member val BuilderBidValue = 5UL with get, set
    /// The bid's execution_payment in Gwei.
    member val BuilderBidExecutionPayment = 0UL with get, set
    /// Signs a builder's bid message (default: the infinity signature).
    member val BidSigner: (Ssz.SszValue -> byte[]) option = None with get, set
    /// fee_recipient of a self-build bid: this value when set, else the one the VC sent for the
    /// proposer through prepare_beacon_proposer, else zero.
    member val SelfBuildFeeRecipient: byte[] option = None with get, set
    /// parent_block_root of every bid (default: the block's parent).
    member val BidParentRoot: Root option = None with get, set
    /// fee_recipient and block_hash of the self-built envelope's payload (default: the bid's).
    member val EnvelopeFeeRecipient: byte[] option = None with get, set
    member val EnvelopeBlockHash: byte[] option = None with get, set
    /// gas_limit, parent_hash and prev_randao of the self-built envelope's payload (default: the
    /// bid's, which are non-zero so a swapped field shows).
    member val EnvelopeGasLimit: uint64 option = None with get, set
    member val EnvelopeParentHash: byte[] option = None with get, set
    member val EnvelopePrevRandao: byte[] option = None with get, set
    /// Published envelopes: (Eth-Blob-Data-Included, content type, body).
    member _.PublishedEnvelopes = publishedEnvelopes
    /// BuilderConfig bodies of produceBlockV4, as JSON text.
    member _.BuilderConfigs = builderConfigs
    /// Eth-Builder-Url headers of published blocks.
    member _.BuilderUrls = builderUrls
    /// "block <slot>" and "envelope <slot>" in the order they were published.
    member _.PublishOrder = order

    member _.Validators = validators
    member _.Submissions = submissions
    member _.Requests = requests
    member _.DefaultData slot = defaultData slot
    member _.BlockRoot slot = blockRoot slot
    /// Blocks include the attestations of the slot this many slots before (the monitor reads them).
    member val InclusionDelay = 1UL with get, set
    /// Attestations and sync messages (by duty slot and validator index) no block includes.
    member val Exclude: (Slot -> uint64 -> bool) = (fun _ _ -> false) with get, set
    /// Slots without a block (GET /eth/v2/beacon/blocks answers 404).
    member val MissingBlocks: Set<Slot> = Set.empty with get, set
    /// Slots whose block comes in a version the VC does not know.
    member val UnknownBlockSlots: Set<Slot> = Set.empty with get, set
    /// GET /eth/v2/beacon/blocks waits (up to 2 s) for the sync messages of the slot before from
    /// every validator with a seat, as gossip would have them. The fake clock runs ahead of the
    /// tasks that send them.
    member val WaitForSyncMessages = false with get, set
    /// Validators whose head vote earns nothing in the attestation rewards.
    member val WrongHead: (uint64 -> bool) = (fun _ -> false) with get, set

    /// The balance of a validator in the state at a slot, in Gwei.
    member val Balance: (Slot -> uint64 -> uint64) =
        (fun slot _ -> 32000000000UL + slot / uint64 slotsPerEpoch * 1000UL) with get, set

    /// Replaces the attestation data the node serves (to model a different head).
    member _.OverrideData(f: (Slot -> AttestationData) option) = dataOverride <- f

    /// Changes every dependent root, as after a reorg.
    member _.Reorg() = dependentRootSalt <- dependentRootSalt + 1

    member _.AddValidator(pk: PubKey, status: string) =
        let v =
            {
                Index = uint64 validators.Count
                PubKey = pk
                Status = status
            }

        validators.Add v
        v

    /// The slot each validator attests in an epoch: index modulo slots per epoch, unless
    /// DutySlotOverride answers.
    member this.DutySlot(v: FakeValidator, epoch: Epoch) =
        match this.DutySlotOverride v epoch with
        | ValueSome s -> s
        | ValueNone -> dutySlot v epoch

    /// Moves attester duties (validator, epoch -> slot); ValueNone keeps the default slot.
    member val DutySlotOverride: FakeValidator -> Epoch -> Slot voption = (fun _ _ -> ValueNone) with get, set

    /// More attester duties in the answer (validator, epoch -> slots), as a faulty node sends:
    /// the duty slot again is an exact copy, another slot a conflicting duty.
    member val ExtraDuties: FakeValidator -> Epoch -> Slot list = (fun _ _ -> []) with get, set

    /// Attester duties added to the answer for an epoch whatever the VC asked for, as a faulty
    /// node sends: (pubkey, validator index, slot). The pubkey need not be the index's.
    member val RawAttesterDuties: Epoch -> (PubKey * uint64 * Slot) list = (fun _ -> []) with get, set

    /// Proposer duties added to the answer for an epoch: (pubkey, validator index, slot).
    member val RawProposerDuties: Epoch -> (PubKey * uint64 * Slot) list = (fun _ -> []) with get, set

    /// Sync duties added to the answer for an epoch whatever the VC asked for:
    /// (pubkey, validator index, seats).
    member val RawSyncDuties: Epoch -> (PubKey * uint64 * uint64[]) list = (fun _ -> []) with get, set

    /// Awaited before the node answers a request (by path), to model a slow node.
    member val Delay: string -> Task = (fun _ -> Task.CompletedTask) with get, set

    /// What /eth/v1/node/syncing reports; execution_optimistic in duty answers follows IsOptimistic.
    member val Sync =
        {
            IsSyncing = false
            IsOptimistic = false
            ElOffline = false
        } with get, set

    /// Attester and proposer duty answers say execution_optimistic even when /node/syncing does
    /// not (the node became optimistic after the last health check).
    member val OptimisticDuties = false with get, set

    /// The head slot /node/syncing reports.
    member val SyncHeadSlot = 0UL with get, set

    /// Eth-Consensus-Block-Value of produceBlockV3 (Wei), and the byte the block's state root is
    /// filled with, so a test can tell which node's block was signed.
    member val BlockValue = 2000UL with get, set
    member val StateRootByte = 0x77uy with get, set

    /// Aggregation bits set in aggregates this node serves (of the committee's bits).
    member val AggregateBits = 2 with get, set
    /// Changes the attestation data of the aggregates this node serves (default: none).
    member val AggregateDataOf: (AttestationData -> AttestationData) = id with get, set
    /// Length of the aggregation_bits list of the aggregates this node serves (default: the
    /// committee length).
    member val AggregateLength: int voption = ValueNone with get, set
    /// The one committee bit set in the aggregates this node serves (default: the committee asked).
    member val AggregateCommitteeBit: uint64 voption = ValueNone with get, set

    /// produceBlockV3 answers with a blinded block.
    member val Blinded = false with get, set

    /// The proposer index produceBlockV3 writes into the block (default: the slot's duty).
    member val BlockProposer: (Slot -> uint64) option = None with get, set

    /// fee_recipient of the execution payload in produceBlockV3 blocks (20 bytes; zero by default).
    /// fee_recipient of the execution payload in produceBlockV3 blocks: this value when set, else
    /// the one the VC sent for the proposer through prepare_beacon_proposer, else zero.
    member val PayloadFeeRecipient: byte[] option = None with get, set

    /// Fee recipients from prepare_beacon_proposer, by validator index.
    member _.Prepared = prepared

    /// With builder_boost_factor above 0, produceBlockV3 answers with a BlindedBeaconBlock whose
    /// payload header pays BuilderFeeRecipient, as a node with MEV-Boost does.
    member val BuilderBlocks = false with get, set
    /// With builder_boost_factor above 0, produceBlockV3 answers 500 (a relay that failed).
    member val BuilderFails = false with get, set
    member val BuilderFeeRecipient: byte[] = Array.create 20 0xEEuy with get, set
    /// (slot, builder_boost_factor) of each produceBlockV3 request.
    member _.BoostFactors = boostFactors
    /// Published blinded blocks: (consensus version, content type, body).
    member _.PublishedBlinded = publishedBlinded
    /// register_validator bodies, as JSON text.
    member _.Registrations = registrations

    /// The graffiti of each produceBlockV3 and V4 request, by slot (the last one per slot).
    member _.Graffitis = graffitis

    /// The answer of GET /eth/v2/node/version as JSON text; None answers 404.
    member val VersionV2: string option = None with get, set

    /// data.version of GET /eth/v1/node/version; None answers 404.
    member val VersionV1: string option = Some "Lighthouse/v8.3.2-abcdef1/x86_64-linux" with get, set

    /// Every request with its query, headers and body.
    member _.Recorded = recorded

    /// The node's own clock. When set, attestation data for a slot the node has not reached is
    /// refused (400), as a beacon node does.
    member val NodeNow: (unit -> DateTimeOffset) option = None with get, set

    /// With NodeNow set: duties (attester, proposer, sync, PTC) for an epoch past the node's next
    /// epoch are refused with 400 "Invalid epoch value", as Nimbus does. The Beacon API allows
    /// the current and the next epoch (sync duties allow more; the VC never needs more).
    member val StrictDutyEpochs = false with get, set

    /// The duty requests refused by StrictDutyEpochs: (kind, epoch asked, node epoch).
    member val RefusedDuties = ConcurrentQueue<string * Epoch * Epoch>() with get

    /// Sync committee seats by epoch (epoch, validator index -> seats); default: SyncSeats in every epoch.
    member val SyncSeatsAt: (Epoch -> uint64 -> uint64[] voption) option = None with get, set

    /// Ends every open event stream, as when the node restarts.
    member _.DropEvents() =
        for c in eventChannels do
            c.Writer.TryComplete() |> ignore

    /// Requests whose path starts with the given prefix.
    member _.RequestCount(prefix: string) = requests |> Seq.filter (fun r -> r.StartsWith prefix) |> Seq.length

    member this.DependentRoot(epoch: Epoch) =
        let b = Array.zeroCreate<byte> 32
        Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(), epoch)
        b[30] <- byte dependentRootSalt
        b[31] <- 0xDDuy
        Root.Of b

    /// Sends execution_payload_available for a slot to every open event stream.
    member this.EmitPayloadAvailable(slot: Slot) =
        let data = $"""{{"slot":"{slot}","block_root":"{(blockRoot slot).Hex}"}}"""

        for c in eventChannels do
            c.Writer.TryWrite($"event: execution_payload_available\ndata: {data}\n\n") |> ignore

    /// Sends a head_v2 event (beacon-APIs v5) to every open event stream.
    member this.EmitHeadV2(slot: Slot) =
        let epoch = slot / spe
        let version = if epoch >= this.GloasEpoch then "gloas" else "fulu"

        let data =
            $"""{{"version":"{version}","data":{{"slot":"{slot}","block":"{(blockRoot slot).Hex}","state":"{(blockRoot slot).Hex}","payload_status":"full","epoch_transition":false,"current_epoch_dependent_root":"{(this.DependentRoot epoch).Hex}","next_epoch_dependent_root":"{(this.DependentRoot(epoch + 1UL)).Hex}","execution_optimistic":false}}}}"""

        for c in eventChannels do
            c.Writer.TryWrite($"event: head_v2\ndata: {data}\n\n") |> ignore

    /// Sends a head event to every open event stream.
    member this.EmitHead(slot: Slot) = this.EmitHeadAs(slot, blockRoot slot, false)

    /// Sends a head event naming `block`, optimistic or not, to every open event stream.
    member this.EmitHeadAs(slot: Slot, block: Root, optimistic: bool) =
        let epoch = slot / spe
        let opt = if optimistic then "true" else "false"

        let data =
            $"""{{"slot":"{slot}","block":"{block.Hex}","state":"{block.Hex}","epoch_transition":false,"previous_duty_dependent_root":"{(this.DependentRoot epoch).Hex}","current_duty_dependent_root":"{(this.DependentRoot(epoch + 1UL)).Hex}","execution_optimistic":{opt}}}"""

        for c in eventChannels do
            c.Writer.TryWrite($"event: head\ndata: {data}\n\n") |> ignore

    override this.SendAsync(req: HttpRequestMessage, ct: CancellationToken) : Task<HttpResponseMessage> =
        task {
            let path = (nonNull req.RequestUri).AbsolutePath
            let query = (nonNull req.RequestUri).Query
            requests.Enqueue $"{req.Method} {path}"
            do! (this.Delay path).WaitAsync ct

            let! bodyBytes =
                match req.Content with
                | null -> Task.FromResult [||]
                | c -> c.ReadAsByteArrayAsync ct

            let body = Encoding.UTF8.GetString bodyBytes

            recorded.Enqueue
                {
                    Method = req.Method.Method
                    Path = path
                    Query = query.TrimStart('?')
                    Headers = Map.ofList [ for h in req.Headers -> h.Key, String.Join(",", h.Value) ]
                    ContentType =
                        match req.Content with
                        | null -> ""
                        | c ->
                            match c.Headers.ContentType with
                            | null -> ""
                            | t -> t.MediaType
                    Body = bodyBytes
                }

            let queryValue (name: string) =
                query.TrimStart('?').Split('&')
                |> Array.pick (fun kv ->
                    if kv.StartsWith(name + "=") then Some(kv.Substring(name.Length + 1)) else None)

            let header (name: string) =
                match req.Headers.TryGetValues name with
                | true, v -> Seq.head v
                | _ -> ""

            let versionOf (slot: Slot) =
                if slot / spe >= this.GloasEpoch then "gloas"
                elif slot < spe then "electra"
                else "fulu"

            let sszOrJson
                (schema: Ssz.SszType)
                (value: Ssz.SszValue)
                (headers: (string * string) list)
                (fields: Utf8JsonWriter -> unit)
                =
                if (header "Accept").Contains "application/octet-stream" && not this.BlockAsJson then
                    let resp = new HttpResponseMessage(HttpStatusCode.OK)
                    resp.Content <- new ByteArrayContent(Ssz.serialize schema value)
                    resp.Content.Headers.ContentType <- Headers.MediaTypeHeaderValue "application/octet-stream"

                    for k, v in headers do
                        resp.Headers.Add(k, v)

                    resp
                else
                    let resp =
                        json HttpStatusCode.OK (fun w ->
                            w.WriteStartObject()
                            fields w
                            w.WritePropertyName "data"
                            SszJson.write w schema value
                            w.WriteEndObject())

                    for k, v in headers do
                        if k = "Eth-Builder-Url" then
                            resp.Headers.Add(k, v)

                    resp

            if this.Fail path then
                return
                    json HttpStatusCode.InternalServerError (fun w ->
                        w.WriteStartObject()
                        w.WriteNumber("code", 500)
                        w.WriteString("message", "injected failure")
                        w.WriteEndObject())
            else
                let seg = path.Split('/', StringSplitOptions.RemoveEmptyEntries)

                let refusedEpoch =
                    match this.NodeNow, seg with
                    | Some now, [| "eth"; "v1"; "validator"; "duties"; kind; epochText |] when this.StrictDutyEpochs ->
                        let seconds = (now () - DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime)).TotalSeconds
                        let nodeEpoch = uint64 (max 0.0 (Math.Floor(seconds / float secondsPerSlot))) / spe
                        let epoch = UInt64.Parse epochText

                        if epoch > nodeEpoch + 1UL then
                            this.RefusedDuties.Enqueue((kind, epoch, nodeEpoch))
                            true
                        else
                            false
                    | _ -> false

                if refusedEpoch then
                    return
                        json HttpStatusCode.BadRequest (fun w ->
                            w.WriteStartObject()
                            w.WriteNumber("code", 400)
                            w.WriteString("message", "Invalid epoch value")
                            w.WriteEndObject())
                else
                    match req.Method.Method, seg with
                    | "GET", [| "eth"; "v1"; "beacon"; "genesis" |] ->
                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartObject()
                                    writeU64 w "genesis_time" this.ReportedGenesisTime
                                    w.WriteString("genesis_validators_root", this.GenesisValidatorsRoot.Hex)
                                    w.WriteString("genesis_fork_version", this.GenesisForkVersion)
                                    w.WriteEndObject()))
                    | "GET", [| "eth"; "v1"; "config"; "spec" |] ->
                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartObject()
                                    let values = specValuesGloas secondsPerSlot slotsPerEpoch this.GloasEpoch

                                    for k, v in
                                        values
                                        |> List.map (fun (k, v) ->
                                            k,
                                            (match this.SpecOverride |> List.tryFind (fun (o, _) -> o = k) with
                                             | Some(_, x) -> x
                                             | None -> v)) do
                                        w.WriteString(k, v)
                                    // Overrides of keys the fake does not serve are added.
                                    for k, v in this.SpecOverride do
                                        if not (values |> List.exists (fun (b, _) -> b = k)) then
                                            w.WriteString(k, v)
                                    // A nested value, as Fulu nodes serve; the VC must skip it.
                                    w.WriteStartArray "BLOB_SCHEDULE"
                                    w.WriteEndArray()
                                    w.WriteEndObject()))
                    | "POST", [| "eth"; "v1"; "beacon"; "states"; _; "validators" |] ->
                        let ids =
                            use d = JsonDocument.Parse body
                            [ for x in d.RootElement.GetProperty("ids").EnumerateArray() -> x.GetString() ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartArray()

                                    for v in validators do
                                        if List.contains v.PubKey.Hex ids || List.contains (string v.Index) ids then
                                            w.WriteStartObject()
                                            writeU64 w "index" v.Index
                                            writeU64 w "balance" 32000000000UL
                                            w.WriteString("status", v.Status)
                                            w.WriteStartObject "validator"
                                            w.WriteString("pubkey", v.PubKey.Hex)
                                            w.WriteString("withdrawal_credentials", Root.Zero.Hex)
                                            writeU64 w "effective_balance" 32000000000UL
                                            w.WriteBoolean("slashed", this.Slashed v.Index)
                                            writeU64 w "activation_eligibility_epoch" 0UL

                                            writeU64
                                                w
                                                "activation_epoch"
                                                (if v.Status.StartsWith "pending" then UInt64.MaxValue else 0UL)

                                            writeU64 w "exit_epoch" UInt64.MaxValue
                                            writeU64 w "withdrawable_epoch" UInt64.MaxValue
                                            w.WriteEndObject()
                                            w.WriteEndObject()

                                    w.WriteEndArray()))
                    | "POST", [| "eth"; "v1"; "validator"; "duties"; "attester"; epochText |] ->
                        let epoch = UInt64.Parse epochText

                        let wanted =
                            use d = JsonDocument.Parse body
                            set [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteString("dependent_root", (this.DependentRoot epoch).Hex)
                                w.WriteBoolean("execution_optimistic", this.Sync.IsOptimistic || this.OptimisticDuties)
                                w.WriteStartArray "data"

                                for v in validators do
                                    if wanted.Contains v.Index && v.Status.StartsWith "active" then
                                        for slot in this.DutySlot(v, epoch) :: this.ExtraDuties v epoch do
                                            w.WriteStartObject()
                                            w.WriteString("pubkey", v.PubKey.Hex)
                                            writeU64 w "validator_index" v.Index
                                            writeU64 w "committee_index" (v.Index % 2UL)
                                            writeU64 w "committee_length" this.CommitteeLength
                                            writeU64 w "committees_at_slot" 2UL
                                            writeU64 w "validator_committee_index" (v.Index / 2UL)
                                            writeU64 w "slot" slot
                                            w.WriteEndObject()

                                for pk, index, slot in this.RawAttesterDuties epoch do
                                    w.WriteStartObject()
                                    w.WriteString("pubkey", pk.Hex)
                                    writeU64 w "validator_index" index
                                    writeU64 w "committee_index" (index % 2UL)
                                    writeU64 w "committee_length" this.CommitteeLength
                                    writeU64 w "committees_at_slot" 2UL
                                    writeU64 w "validator_committee_index" (index / 2UL)
                                    writeU64 w "slot" slot
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | "POST", [| "eth"; "v1"; "validator"; "liveness"; epochText |] ->
                        let epoch = UInt64.Parse epochText

                        let wanted =
                            use d = JsonDocument.Parse body
                            [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartArray()

                                    for i in wanted do
                                        if not (this.LivenessOmit epoch i) then
                                            w.WriteStartObject()
                                            writeU64 w "index" i
                                            w.WriteBoolean("is_live", this.Live epoch i)
                                            w.WriteEndObject()

                                    w.WriteEndArray()))
                    | "GET", [| "eth"; "v2"; "node"; "version" |] ->
                        match this.VersionV2 with
                        | Some text ->
                            let resp = new HttpResponseMessage(HttpStatusCode.OK)
                            resp.Content <- new StringContent(text, Text.Encoding.UTF8, "application/json")
                            return resp
                        | None -> return new HttpResponseMessage(HttpStatusCode.NotFound)
                    | "GET", [| "eth"; "v1"; "node"; "version" |] ->
                        match this.VersionV1 with
                        | Some v ->
                            return
                                json HttpStatusCode.OK (fun w ->
                                    dataObj w (fun w ->
                                        w.WriteStartObject()
                                        w.WriteString("version", v)
                                        w.WriteEndObject()))
                        | None -> return new HttpResponseMessage(HttpStatusCode.NotFound)
                    | "GET", [| "eth"; "v1"; "node"; "syncing" |] ->
                        let s = this.Sync

                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartObject()
                                    w.WriteString("head_slot", string this.SyncHeadSlot)
                                    w.WriteString("sync_distance", (if s.IsSyncing then "100" else "0"))
                                    w.WriteBoolean("is_syncing", s.IsSyncing)
                                    w.WriteBoolean("is_optimistic", s.IsOptimistic)
                                    w.WriteBoolean("el_offline", s.ElOffline)
                                    w.WriteEndObject()))
                    | "GET", [| "eth"; "v1"; "validator"; "attestation_data" |] ->
                        let slot =
                            query.TrimStart('?').Split('&')
                            |> Array.pick (fun kv ->
                                if kv.StartsWith "slot=" then Some(UInt64.Parse(kv.Substring 5)) else None)

                        let nodeSlot =
                            this.NodeNow
                            |> Option.map (fun now ->
                                Math.Floor(
                                    (now () - DateTimeOffset.FromUnixTimeSeconds(int64 genesisTime)).TotalSeconds
                                    / float secondsPerSlot
                                ))

                        match nodeSlot with
                        | Some current when float slot > current ->
                            return
                                json HttpStatusCode.BadRequest (fun w ->
                                    w.WriteStartObject()
                                    w.WriteNumber("code", 400)
                                    w.WriteString("message", $"slot {slot} is in the future (current {current})")
                                    w.WriteEndObject())
                        | _ ->
                            let d =
                                match dataOverride with
                                | Some f -> f slot
                                | None -> defaultData slot

                            return
                                json HttpStatusCode.OK (fun w ->
                                    w.WriteStartObject()
                                    Eplix.Beacon.Encoders.attestationData w d
                                    w.WriteEndObject())
                    | "POST", [| "eth"; "v2"; "beacon"; "pool"; "attestations" |] ->
                        let version =
                            match req.Headers.TryGetValues "Eth-Consensus-Version" with
                            | true, v -> Seq.head v
                            | _ -> ""

                        use d = JsonDocument.Parse body

                        for a in d.RootElement.EnumerateArray() do
                            let data = Eplix.Beacon.Decoders.attestationDataOf (a.GetProperty "data")

                            submissions.Enqueue
                                {
                                    Slot = data.Slot
                                    CommitteeIndex = u64Field a "committee_index"
                                    AttesterIndex = u64Field a "attester_index"
                                    Data = data
                                    Signature = signature (a.GetProperty "signature")
                                    ConsensusVersion = version
                                }

                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "GET", [| "eth"; "v1"; "events" |] ->
                        let ch = Channel.CreateUnbounded<string>()
                        eventChannels.Add ch
                        let stream = new SseStream(ch.Reader, ct)
                        let resp = new HttpResponseMessage(HttpStatusCode.OK)
                        resp.Content <- new StreamContent(stream)
                        resp.Content.Headers.ContentType <- Headers.MediaTypeHeaderValue "text/event-stream"
                        return resp
                    | "GET", [| "eth"; "v1"; "validator"; "duties"; "proposer"; epochText |] ->
                        let epoch = UInt64.Parse epochText

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteString("dependent_root", (this.DependentRoot epoch).Hex)
                                w.WriteBoolean("execution_optimistic", this.Sync.IsOptimistic || this.OptimisticDuties)
                                w.WriteStartArray "data"

                                for KeyValue(slot, index) in proposals do
                                    if slot / spe = epoch then
                                        let v = validators[int index]
                                        w.WriteStartObject()
                                        w.WriteString("pubkey", v.PubKey.Hex)
                                        writeU64 w "validator_index" v.Index
                                        writeU64 w "slot" slot
                                        w.WriteEndObject()

                                for pk, index, slot in this.RawProposerDuties epoch do
                                    w.WriteStartObject()
                                    w.WriteString("pubkey", pk.Hex)
                                    writeU64 w "validator_index" index
                                    writeU64 w "slot" slot
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | "POST", [| "eth"; "v1"; "validator"; "duties"; "ptc"; epochText |] ->
                        let epoch = UInt64.Parse epochText

                        let wanted =
                            use d = JsonDocument.Parse body
                            set [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteString("dependent_root", (this.DependentRoot epoch).Hex)
                                w.WriteBoolean("execution_optimistic", this.Sync.IsOptimistic || this.OptimisticDuties)
                                w.WriteStartArray "data"

                                for KeyValue(slot, indices) in ptcSlots do
                                    if slot / spe = epoch then
                                        for i in indices do
                                            if wanted.Contains i then
                                                w.WriteStartObject()
                                                w.WriteString("pubkey", validators[int i].PubKey.Hex)
                                                writeU64 w "validator_index" i
                                                writeU64 w "slot" slot
                                                w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | "GET", [| "eth"; "v1"; "validator"; "payload_attestation_data" |] ->
                        let slot = UInt64.Parse(queryValue "slot")

                        if this.NoBlockSlots.Contains slot then
                            return new HttpResponseMessage(HttpStatusCode.NoContent)
                        else
                            let d =
                                {
                                    BeaconBlockRoot = blockRoot slot
                                    Slot = slot
                                    PayloadPresent = this.PayloadPresent
                                    BlobDataAvailable = true
                                }

                            return
                                json HttpStatusCode.OK (fun w ->
                                    w.WriteStartObject()
                                    w.WriteString("version", "gloas")
                                    w.WritePropertyName "data"

                                    SszJson.write
                                        w
                                        Schemas.Gloas.payloadAttestationData
                                        (Codec.payloadAttestationDataValue d)

                                    w.WriteEndObject())
                    | "POST", [| "eth"; "v1"; "beacon"; "pool"; "payload_attestations" |]
                    | "POST", [| "eth"; "v1"; "validator"; ("proposer_preferences" | "builder_preferences") |] ->
                        posts.Enqueue((path, body))
                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "POST", [| "eth"; "v4"; "validator"; "blocks"; slotText |] ->
                        let slot = UInt64.Parse slotText
                        let randao = Hex.tryDecode (queryValue "randao_reveal") |> ValueOption.get
                        let graffiti = Hex.tryDecode (queryValue "graffiti") |> ValueOption.get
                        graffitis[slot] <- graffiti
                        let includePayload = queryValue "include_payload" = "true"
                        builderConfigs.Enqueue body

                        let local, hasBuilders =
                            use d = JsonDocument.Parse body

                            d.RootElement.GetProperty("builder_boost_factor").GetString() = "0",
                            d.RootElement.GetProperty("builders").GetArrayLength() > 0

                        let proposer = proposals[slot]
                        let parent = blockRoot (slot - 1UL)
                        let builderBid = if local then None else this.BuilderBid
                        let blockHash = Array.create 32 0x42uy
                        let parentHash = Array.create 32 0x41uy
                        let prevRandao = Array.create 32 0x44uy
                        let gasLimit = 60_000_000UL

                        let bidFee =
                            match builderBid, this.SelfBuildFeeRecipient with
                            | Some fee, _ -> fee
                            | None, Some fee -> fee
                            | None, None ->
                                match prepared.TryGetValue proposer with
                                | true, fee -> fee
                                | _ -> Array.zeroCreate 20

                        let bid =
                            match Ssz.zero Schemas.Gloas.executionPayloadBid with
                            | Ssz.Fields f ->
                                f[0] <- Ssz.Bytes parentHash
                                f[1] <- Ssz.Bytes (defaultArg this.BidParentRoot parent).Bytes
                                f[2] <- Ssz.Bytes blockHash
                                f[3] <- Ssz.Bytes prevRandao
                                f[4] <- Ssz.Bytes bidFee
                                f[5] <- Ssz.U gasLimit
                                f[7] <- Ssz.U slot

                                match builderBid with
                                | Some _ ->
                                    f[6] <- Ssz.U 7UL
                                    f[8] <- Ssz.U this.BuilderBidValue
                                    f[9] <- Ssz.U this.BuilderBidExecutionPayment
                                | None -> f[6] <- Ssz.U UInt64.MaxValue

                                Ssz.Fields f
                            | v -> v

                        let bidSignature =
                            match builderBid, this.BidSigner with
                            | Some _, Some sign -> sign bid
                            | _ -> infinitySignature

                        let body =
                            match Ssz.zero (Schemas.Gloas.beaconBlockBody preset) with
                            | Ssz.Fields f ->
                                f[0] <- Ssz.Bytes randao
                                f[2] <- Ssz.Bytes graffiti
                                f[10] <- Ssz.Fields [| bid; Ssz.Bytes bidSignature |]
                                Ssz.Fields f
                            | v -> v

                        let block =
                            Ssz.Fields
                                [|
                                    Ssz.U slot
                                    Ssz.U proposer
                                    Ssz.Bytes parent.Bytes
                                    Ssz.Bytes(Array.create 32 0x77uy)
                                    body
                                |]

                        let root = Ssz.hashTreeRoot (Schemas.Gloas.beaconBlock preset) block

                        let envelope =
                            match Ssz.zero (Schemas.Gloas.executionPayloadEnvelope preset) with
                            | Ssz.Fields f ->
                                let payload = Codec.fields f[0]
                                payload[0] <- Ssz.Bytes(defaultArg this.EnvelopeParentHash parentHash)
                                payload[1] <- Ssz.Bytes(defaultArg this.EnvelopeFeeRecipient bidFee)
                                payload[5] <- Ssz.Bytes(defaultArg this.EnvelopePrevRandao prevRandao)
                                payload[7] <- Ssz.U(defaultArg this.EnvelopeGasLimit gasLimit)
                                payload[12] <- Ssz.Bytes(defaultArg this.EnvelopeBlockHash blockHash)
                                payload[18] <- Ssz.U slot
                                f[2] <- Ssz.U UInt64.MaxValue
                                f[3] <- Ssz.Bytes root
                                f[4] <- Ssz.Bytes parent.Bytes
                                Ssz.Fields f
                            | v -> v

                        envelopes[slot] <- envelope
                        let selfBuilt = builderBid.IsNone
                        let included = includePayload && selfBuilt

                        let headers =
                            [
                                "Eth-Consensus-Version", "gloas"
                                "Eth-Execution-Payload-Included", (if included then "true" else "false")
                                "Eth-Execution-Payload-Value", "1000"
                                "Eth-Consensus-Block-Value", "2000"
                                if builderBid.IsSome && hasBuilders then
                                    "Eth-Builder-Url", "https://builder.test"
                            ]

                        let fields (w: Utf8JsonWriter) =
                            w.WriteString("version", "gloas")
                            w.WriteString("execution_payload_value", "1000")
                            w.WriteString("consensus_block_value", "2000")
                            w.WriteBoolean("execution_payload_included", included)

                        if included then
                            let contents = Ssz.Fields [| block; envelope; Ssz.Items [||]; Ssz.Items [||] |]
                            return sszOrJson (Schemas.Gloas.blockContents preset) contents headers fields
                        else
                            return sszOrJson (Schemas.Gloas.beaconBlock preset) block headers fields
                    | "GET", [| "eth"; "v1"; "validator"; "execution_payload_envelopes"; slotText; rootText |] ->
                        let slot = UInt64.Parse slotText

                        match envelopes.TryGetValue slot with
                        | true, env when Hex.encodeArray (Codec.asBytes (Codec.fields env).[3]) = rootText ->
                            return
                                sszOrJson
                                    (Schemas.Gloas.executionPayloadEnvelope preset)
                                    env
                                    [ "Eth-Consensus-Version", "gloas" ]
                                    (fun w -> w.WriteString("version", "gloas"))
                        | _ -> return new HttpResponseMessage(HttpStatusCode.NotFound)
                    | "POST", [| "eth"; "v1"; "beacon"; "execution_payload_envelopes" |] ->
                        let contentType =
                            match req.Content with
                            | null -> ""
                            | c -> c.Headers.ContentType.MediaType

                        publishedEnvelopes.Enqueue((header "Eth-Blob-Data-Included", contentType, bodyBytes))
                        order.Enqueue "envelope"
                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "POST", [| "eth"; "v1"; "validator"; "duties"; "sync"; epochText |] ->
                        let epoch = UInt64.Parse epochText

                        let wanted =
                            use d = JsonDocument.Parse body
                            set [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        let seatsNow =
                            match this.SyncSeatsAt with
                            | None -> [ for KeyValue(i, s) in syncSeats -> i, s ]
                            | Some f ->
                                [
                                    for v in validators do
                                        match f epoch v.Index with
                                        | ValueSome s -> v.Index, s
                                        | ValueNone -> ()
                                ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteBoolean("execution_optimistic", false)
                                w.WriteStartArray "data"

                                for index, seats in seatsNow do
                                    if wanted.Contains index then
                                        let v = validators[int index]
                                        w.WriteStartObject()
                                        w.WriteString("pubkey", v.PubKey.Hex)
                                        writeU64 w "validator_index" v.Index
                                        w.WriteStartArray "validator_sync_committee_indices"

                                        for s in seats do
                                            w.WriteStringValue(string s)

                                        w.WriteEndArray()
                                        w.WriteEndObject()

                                for pk, index, seats in this.RawSyncDuties epoch do
                                    w.WriteStartObject()
                                    w.WriteString("pubkey", pk.Hex)
                                    writeU64 w "validator_index" index
                                    w.WriteStartArray "validator_sync_committee_indices"

                                    for s in seats do
                                        w.WriteStringValue(string s)

                                    w.WriteEndArray()
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | "POST",
                      [| "eth"; "v1"; "validator"; ("beacon_committee_selections" | "sync_committee_selections") |] ->
                        posts.Enqueue((path, body))
                        use d = JsonDocument.Parse body
                        let items = [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                dataObj w (fun w ->
                                    w.WriteStartArray()

                                    for x in items do
                                        let index = UInt64.Parse(x.GetProperty("validator_index").GetString())
                                        let slot = UInt64.Parse(x.GetProperty("slot").GetString())

                                        let proof =
                                            BlsSignature.TryParse(x.GetProperty("selection_proof").GetString())
                                            |> ValueOption.get

                                        match this.CombineSelection index slot proof with
                                        | ValueSome combined ->
                                            w.WriteStartObject()

                                            for p in x.EnumerateObject() do
                                                if p.Name = "selection_proof" then
                                                    w.WriteString(p.Name, combined.Hex)
                                                else
                                                    p.WriteTo w

                                            w.WriteEndObject()
                                        | ValueNone -> ()

                                    w.WriteEndArray()))
                    | "POST", [| "eth"; "v1"; "validator"; "prepare_beacon_proposer" |] ->
                        posts.Enqueue((path, body))
                        use d = JsonDocument.Parse body

                        for x in d.RootElement.EnumerateArray() do
                            match Hex.tryDecode (x.GetProperty("fee_recipient").GetString()) with
                            | ValueSome f -> prepared[UInt64.Parse(x.GetProperty("validator_index").GetString())] <- f
                            | ValueNone -> ()

                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "POST",
                      [| "eth"
                         "v1"
                         "validator"
                         ("beacon_committee_subscriptions" | "sync_committee_subscriptions" | "contribution_and_proofs") |]
                    | "POST", [| "eth"; "v2"; "validator"; "aggregate_and_proofs" |]
                    | "POST", [| "eth"; "v1"; "beacon"; "pool"; ("sync_committees" | "voluntary_exits") |] ->
                        posts.Enqueue((path, body))
                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "GET", [| "eth"; "v1"; "beacon"; "blocks"; "head"; "root" |] ->
                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteBoolean("execution_optimistic", false)
                                w.WritePropertyName "data"
                                w.WriteStartObject()
                                w.WriteString("root", this.HeadRoot.Hex)
                                w.WriteEndObject()
                                w.WriteEndObject())
                    | "GET", [| "eth"; "v3"; "validator"; "blocks"; slotText |] ->
                        let slot = UInt64.Parse slotText
                        let randao = Hex.tryDecode (queryValue "randao_reveal") |> ValueOption.get
                        let graffiti = Hex.tryDecode (queryValue "graffiti") |> ValueOption.get
                        graffitis[slot] <- graffiti

                        let boost =
                            match
                                query.TrimStart('?').Split('&')
                                |> Array.tryFind (fun kv -> kv.StartsWith "builder_boost_factor=")
                            with
                            | Some kv -> UInt64.Parse(kv.Substring "builder_boost_factor=".Length)
                            | None -> 100UL

                        boostFactors.Enqueue((slot, boost))

                        let proposer =
                            match this.BlockProposer with
                            | Some f -> f slot
                            | None -> proposals[slot]

                        if boost > 0UL && this.BuilderFails then
                            return
                                json HttpStatusCode.InternalServerError (fun w ->
                                    w.WriteStartObject()
                                    w.WriteNumber("code", 500)
                                    w.WriteString("message", "builder: relay timed out")
                                    w.WriteEndObject())
                        elif boost > 0UL && this.BuilderBlocks then
                            let body =
                                match Ssz.zero (Schemas.blindedBeaconBlockBody preset) with
                                | Ssz.Fields f ->
                                    f[0] <- Ssz.Bytes randao
                                    f[2] <- Ssz.Bytes graffiti
                                    let header = Codec.fields f[9]
                                    header[1] <- Ssz.Bytes this.BuilderFeeRecipient
                                    header[13] <- Ssz.Bytes(Array.create 32 0x42uy)
                                    Ssz.Fields f
                                | v -> v

                            let block =
                                Ssz.Fields
                                    [|
                                        Ssz.U slot
                                        Ssz.U proposer
                                        Ssz.Bytes (blockRoot (slot - 1UL)).Bytes
                                        Ssz.Bytes(Array.create 32 this.StateRootByte)
                                        body
                                    |]

                            let schema = Schemas.blindedBeaconBlock preset

                            if (header "Accept").Contains "application/octet-stream" && not this.BlockAsJson then
                                let resp = new HttpResponseMessage(HttpStatusCode.OK)
                                resp.Content <- new ByteArrayContent(Ssz.serialize schema block)

                                resp.Content.Headers.ContentType <-
                                    Headers.MediaTypeHeaderValue "application/octet-stream"

                                resp.Headers.Add("Eth-Consensus-Version", versionOf slot)
                                resp.Headers.Add("Eth-Execution-Payload-Blinded", "true")
                                resp.Headers.Add("Eth-Execution-Payload-Value", "9000")
                                resp.Headers.Add("Eth-Consensus-Block-Value", string this.BlockValue)
                                return resp
                            else
                                return
                                    json HttpStatusCode.OK (fun w ->
                                        w.WriteStartObject()
                                        w.WriteString("version", versionOf slot)
                                        w.WriteBoolean("execution_payload_blinded", true)
                                        w.WriteString("execution_payload_value", "9000")
                                        w.WriteString("consensus_block_value", string this.BlockValue)
                                        w.WritePropertyName "data"
                                        SszJson.write w schema block
                                        w.WriteEndObject())
                        else
                            let body =
                                match Ssz.zero (Schemas.beaconBlockBody preset) with
                                | Ssz.Fields f ->
                                    f[0] <- Ssz.Bytes randao
                                    f[2] <- Ssz.Bytes graffiti
                                    let payload = Codec.fields f[9]

                                    let fee =
                                        match this.PayloadFeeRecipient, prepared.TryGetValue proposer with
                                        | Some f, _ -> f
                                        | None, (true, f) -> f
                                        | None, _ -> Array.zeroCreate 20

                                    payload[1] <- Ssz.Bytes fee
                                    Ssz.Fields f
                                | v -> v

                            let block =
                                Ssz.Fields
                                    [|
                                        Ssz.U slot
                                        Ssz.U proposer
                                        Ssz.Bytes (blockRoot (slot - 1UL)).Bytes
                                        Ssz.Bytes(Array.create 32 this.StateRootByte)
                                        body
                                    |]

                            let contents = Ssz.Fields [| block; Ssz.Items [||]; Ssz.Items [||] |]
                            let schema = Schemas.blockContents preset
                            let accept = header "Accept"
                            let blinded = if this.Blinded then "true" else "false"

                            if accept.Contains "application/octet-stream" && not this.BlockAsJson then
                                let resp = new HttpResponseMessage(HttpStatusCode.OK)
                                resp.Content <- new ByteArrayContent(Ssz.serialize schema contents)

                                resp.Content.Headers.ContentType <-
                                    Headers.MediaTypeHeaderValue "application/octet-stream"

                                resp.Headers.Add("Eth-Consensus-Version", versionOf slot)
                                resp.Headers.Add("Eth-Execution-Payload-Blinded", blinded)
                                resp.Headers.Add("Eth-Execution-Payload-Value", "1000")
                                resp.Headers.Add("Eth-Consensus-Block-Value", string this.BlockValue)
                                return resp
                            else
                                return
                                    json HttpStatusCode.OK (fun w ->
                                        w.WriteStartObject()
                                        w.WriteString("version", versionOf slot)
                                        w.WriteBoolean("execution_payload_blinded", this.Blinded)
                                        w.WriteString("execution_payload_value", "1000")
                                        w.WriteString("consensus_block_value", string this.BlockValue)
                                        w.WritePropertyName "data"
                                        SszJson.write w schema contents
                                        w.WriteEndObject())
                    | "POST", [| "eth"; "v2"; "beacon"; "blinded_blocks" |] ->
                        let contentType =
                            match req.Content with
                            | null -> ""
                            | c -> c.Headers.ContentType.MediaType

                        publishedBlinded.Enqueue((header "Eth-Consensus-Version", contentType, bodyBytes))
                        order.Enqueue "blinded"
                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "POST", [| "eth"; "v1"; "validator"; "register_validator" |] ->
                        registrations.Enqueue body
                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "POST", [| "eth"; "v2"; "beacon"; "blocks" |] ->
                        let contentType =
                            match req.Content with
                            | null -> ""
                            | c -> c.Headers.ContentType.MediaType

                        published.Enqueue((header "Eth-Consensus-Version", contentType, bodyBytes))
                        order.Enqueue "block"

                        match header "Eth-Builder-Url" with
                        | "" -> ()
                        | u -> builderUrls.Enqueue u

                        return new HttpResponseMessage(HttpStatusCode.OK)
                    | "GET", [| "eth"; "v2"; "validator"; "aggregate_attestation" |] ->
                        let slot = UInt64.Parse(queryValue "slot")
                        let committee = UInt64.Parse(queryValue "committee_index")

                        let d =
                            match dataOverride with
                            | Some f -> f slot
                            | None -> defaultData slot

                        let att =
                            Ssz.Fields
                                [|
                                    Ssz.Bits(
                                        Array.init
                                            (this.AggregateLength |> ValueOption.defaultValue (int this.CommitteeLength))
                                            (fun i -> i < this.AggregateBits)
                                    )
                                    Codec.attestationDataValue (this.AggregateDataOf d)
                                    Ssz.Bytes infinitySignature
                                    Ssz.Bits(
                                        Array.init preset.MaxCommitteesPerSlot (fun i ->
                                            uint64 i =
                                                (this.AggregateCommitteeBit |> ValueOption.defaultValue committee))
                                    )
                                |]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteString("version", versionOf slot)
                                w.WritePropertyName "data"
                                SszJson.write w (Schemas.attestationAt (versionOf slot = "gloas") preset) att
                                w.WriteEndObject())
                    | "GET", [| "eth"; "v1"; "validator"; "sync_committee_contribution" |] ->
                        let slot = UInt64.Parse(queryValue "slot")
                        let sub = UInt64.Parse(queryValue "subcommittee_index")
                        let root = Root.TryParse(queryValue "beacon_block_root") |> ValueOption.get

                        let c =
                            Ssz.Fields
                                [|
                                    Ssz.U slot
                                    Ssz.Bytes root.Bytes
                                    Ssz.U sub
                                    Ssz.Bits(Array.init preset.SyncSubcommitteeSize (fun i -> i % 2 = 0))
                                    Ssz.Bytes infinitySignature
                                |]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WritePropertyName "data"
                                SszJson.write w (Schemas.syncCommitteeContribution preset) c
                                w.WriteEndObject())
                    | "GET", [| "eth"; "v2"; "beacon"; "blocks"; slotText |] when slotText <> "head" ->
                        let slot = UInt64.Parse slotText

                        if this.MissingBlocks.Contains slot then
                            return new HttpResponseMessage(HttpStatusCode.NotFound)
                        else
                            let gloas = slot / spe >= this.GloasEpoch
                            // One aggregate per attestation data of the slot InclusionDelay before, over
                            // both committees of that slot (the bits of committee 1 start after committee 0).
                            let attestations =
                                if slot < this.InclusionDelay then
                                    [||]
                                else
                                    let attSlot = slot - this.InclusionDelay

                                    submissions
                                    |> Seq.filter (fun s ->
                                        s.Slot = attSlot && not (this.Exclude attSlot s.AttesterIndex))
                                    |> Seq.groupBy (fun s -> s.Data)
                                    |> Seq.map (fun (data, subs) ->
                                        let size = int this.CommitteeLength
                                        let bits = Array.zeroCreate<bool>(2 * size)

                                        for s in subs do
                                            bits[int s.CommitteeIndex * size + int (s.AttesterIndex / 2UL)] <- true

                                        Ssz.Fields
                                            [|
                                                Ssz.Bits bits
                                                Codec.attestationDataValue data
                                                Ssz.Bytes infinitySignature
                                                Ssz.Bits(Array.init preset.MaxCommitteesPerSlot (fun i -> i < 2))
                                            |])
                                    |> Array.ofSeq
                            // The sync aggregate holds the messages of the slot before.
                            let syncSent (s: Slot) =
                                posts
                                |> Seq.filter (fun (p, _) -> p.EndsWith "pool/sync_committees")
                                |> Seq.collect (fun (_, b) ->
                                    use d = JsonDocument.Parse(b: string)

                                    [
                                        for m in d.RootElement.EnumerateArray() do
                                            if u64Field m "slot" = s then
                                                u64Field m "validator_index"
                                    ])
                                |> Set.ofSeq

                            if this.WaitForSyncMessages && slot > 0UL then
                                let mutable waited = 0

                                while waited < 200 && not (Set.isSubset (set syncSeats.Keys) (syncSent (slot - 1UL))) do
                                    do! Task.Delay 10
                                    waited <- waited + 1

                            let syncBits = Array.zeroCreate<bool> preset.SyncCommitteeSize

                            if slot > 0UL then
                                for p, b in posts do
                                    if p.EndsWith "pool/sync_committees" then
                                        use d = JsonDocument.Parse(b: string)

                                        for m in d.RootElement.EnumerateArray() do
                                            let s = u64Field m "slot"
                                            let i = u64Field m "validator_index"

                                            if s = slot - 1UL && not (this.Exclude s i) then
                                                match syncSeats.TryGetValue i with
                                                | true, seats ->
                                                    for seat in seats do
                                                        syncBits[int seat] <- true
                                                | _ -> ()

                            let schema =
                                if gloas then
                                    Schemas.Gloas.signedBeaconBlock preset
                                else
                                    Schemas.signedBeaconBlock preset

                            let signed =
                                match Ssz.zero schema with
                                | Ssz.Fields sf ->
                                    let message = Codec.fields sf[0]
                                    message[0] <- Ssz.U slot

                                    message[1] <-
                                        Ssz.U(
                                            match proposals.TryGetValue slot with
                                            | true, p -> p
                                            | _ -> 999UL
                                        )

                                    message[2] <- Ssz.Bytes (blockRoot (slot - 1UL)).Bytes
                                    let body = Codec.fields message[4]
                                    body[5] <- Ssz.Items attestations
                                    body[8] <- Ssz.Fields [| Ssz.Bits syncBits; Ssz.Bytes infinitySignature |]
                                    Ssz.Fields sf
                                | v -> v

                            let version = if this.UnknownBlockSlots.Contains slot then "heze" else versionOf slot

                            return
                                json HttpStatusCode.OK (fun w ->
                                    w.WriteStartObject()
                                    w.WriteString("version", version)
                                    w.WriteBoolean("execution_optimistic", false)
                                    w.WriteBoolean("finalized", false)
                                    w.WritePropertyName "data"
                                    SszJson.write w schema signed
                                    w.WriteEndObject())
                    | "GET", [| "eth"; "v1"; "beacon"; "states"; _; "committees" |] ->
                        let slot = UInt64.Parse(queryValue "slot")

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteBoolean("execution_optimistic", false)
                                w.WriteStartArray "data"

                                for c in 0UL .. 1UL do
                                    w.WriteStartObject()
                                    writeU64 w "index" c
                                    writeU64 w "slot" slot
                                    w.WriteStartArray "validators"

                                    for i in 0UL .. this.CommitteeLength - 1UL do
                                        w.WriteStringValue(string (i * 2UL + c))

                                    w.WriteEndArray()
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | "POST", [| "eth"; "v1"; "beacon"; "rewards"; "attestations"; _ |] ->
                        let wanted =
                            use d = JsonDocument.Parse body
                            [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteBoolean("execution_optimistic", false)
                                w.WriteBoolean("finalized", false)
                                w.WriteStartObject "data"
                                w.WriteStartArray "ideal_rewards"
                                w.WriteStartObject()
                                writeU64 w "effective_balance" 32000000000UL
                                w.WriteString("head", "1000")
                                w.WriteString("target", "2000")
                                w.WriteString("source", "1500")
                                w.WriteString("inactivity", "0")
                                w.WriteEndObject()
                                w.WriteEndArray()
                                w.WriteStartArray "total_rewards"

                                for i in wanted do
                                    w.WriteStartObject()
                                    writeU64 w "validator_index" i
                                    w.WriteString("head", (if this.WrongHead i then "0" else "1000"))
                                    w.WriteString("target", "2000")
                                    w.WriteString("source", "1500")
                                    w.WriteString("inactivity", "0")
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject()
                                w.WriteEndObject())
                    | "POST", [| "eth"; "v1"; "beacon"; "states"; stateText; "validator_balances" |] ->
                        let slot =
                            match UInt64.TryParse stateText with
                            | true, s -> s
                            | _ -> 0UL

                        let wanted =
                            use d = JsonDocument.Parse body
                            [ for x in d.RootElement.EnumerateArray() -> UInt64.Parse(x.GetString()) ]

                        return
                            json HttpStatusCode.OK (fun w ->
                                w.WriteStartObject()
                                w.WriteBoolean("execution_optimistic", false)
                                w.WriteStartArray "data"

                                for i in wanted do
                                    w.WriteStartObject()
                                    writeU64 w "index" i
                                    writeU64 w "balance" (this.Balance slot i)
                                    w.WriteEndObject()

                                w.WriteEndArray()
                                w.WriteEndObject())
                    | _ -> return new HttpResponseMessage(HttpStatusCode.NotFound)
        }

/// A read-only stream fed from a channel of SSE text chunks.
and SseStream(reader: ChannelReader<string>, ct: CancellationToken) =
    inherit IO.Stream()
    let mutable pending: byte[] = [||]
    let mutable offset = 0
    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = raise (NotSupportedException())

    override _.Position
        with get () = raise (NotSupportedException())
        and set _ = raise (NotSupportedException())

    override _.Flush() = ()
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength _ = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())
    override this.Read(buffer, o, count) = this.ReadAsync(buffer, o, count, CancellationToken.None).Result

    override _.ReadAsync(buffer: byte[], o: int, count: int, token: CancellationToken) : Task<int> =
        task {
            if offset >= pending.Length then
                use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, token)

                try
                    let! chunk = reader.ReadAsync(linked.Token)
                    pending <- Encoding.UTF8.GetBytes(chunk: string)
                    offset <- 0
                with
                | :? OperationCanceledException
                | :? ChannelClosedException ->
                    // Cancelled, or the node dropped the stream: end of stream.
                    pending <- [||]
                    offset <- 0

            if offset >= pending.Length then
                return 0
            else
                let n = min count (pending.Length - offset)
                Buffer.BlockCopy(pending, offset, buffer, o, n)
                offset <- offset + n
                return n
        }
