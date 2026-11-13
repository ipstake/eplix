/// The Beacon API client for one node: JSON over HTTP with keep-alive, SSZ for blocks where the
/// node supports it. BeaconNodes.fs spreads calls over several nodes.
namespace Eplix.Beacon

open System
open System.Buffers
open System.IO
open System.Net
open System.Net.Http
open System.Net.Http.Headers
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json
open Eplix.Ssz

type Genesis =
    {
        GenesisTime: uint64
        GenesisValidatorsRoot: Root
        GenesisForkVersion: ForkVersion
    }

type ValidatorInfo =
    {
        Index: ValidatorIndex
        PubKey: PubKey
        Status: string
        ActivationEpoch: Epoch
        ExitEpoch: Epoch
        /// The chain slashed this validator (a block included a slashing of it).
        Slashed: bool
    }

type AttesterDuty =
    {
        PubKey: PubKey
        ValidatorIndex: ValidatorIndex
        CommitteeIndex: CommitteeIndex
        CommitteeLength: uint64
        CommitteesAtSlot: uint64
        ValidatorCommitteeIndex: uint64
        Slot: Slot
    }

type ProposerDuty =
    {
        PubKey: PubKey
        ValidatorIndex: ValidatorIndex
        Slot: Slot
    }

type Duties<'T> =
    {
        DependentRoot: Root
        ExecutionOptimistic: bool
        Data: 'T[]
    }

type HeadEvent =
    {
        Slot: Slot
        Block: Root
        EpochTransition: bool
        /// Dependent root of attester duties in the head's epoch (head) or current_epoch_dependent_root (head_v2).
        PreviousDutyDependentRoot: Root
        /// Dependent root of attester duties in the next epoch.
        CurrentDutyDependentRoot: Root
        ExecutionOptimistic: bool
    }

type SyncDuty =
    {
        PubKey: PubKey
        ValidatorIndex: ValidatorIndex
        /// The validator's seats in the sync committee; one validator may hold several.
        Indices: uint64[]
    }

type BeaconCommitteeSubscription =
    {
        ValidatorIndex: ValidatorIndex
        CommitteeIndex: CommitteeIndex
        CommitteesAtSlot: uint64
        Slot: Slot
        IsAggregator: bool
    }

type SyncCommitteeSubscription =
    {
        ValidatorIndex: ValidatorIndex
        Indices: uint64[]
        UntilEpoch: Epoch
    }

type SyncCommitteeMessage =
    {
        Slot: Slot
        BeaconBlockRoot: Root
        ValidatorIndex: ValidatorIndex
        Signature: BlsSignature
    }

/// Gloas: a payload timeliness committee seat (POST /eth/v1/validator/duties/ptc/{epoch}).
type PtcDuty =
    {
        PubKey: PubKey
        ValidatorIndex: ValidatorIndex
        Slot: Slot
    }

type PayloadAttestationMessage =
    {
        ValidatorIndex: ValidatorIndex
        Data: PayloadAttestationData
        Signature: BlsSignature
    }

type SignedProposerPreferences =
    {
        Message: ProposerPreferences
        Signature: BlsSignature
    }

type SignedBuilderRequestAuth =
    {
        Auth: BuilderRequestAuth
        AuthSignature: BlsSignature
    }

/// One bid request in the BuilderConfig of produceBlockV4 (beacon-APIs types/gloas/builder_entry.yaml).
type BuilderEntry =
    {
        Url: string
        Auth: SignedBuilderRequestAuth
        /// Empty accepts any builder.
        BuilderPubkeys: PubKey list
        MaxExecutionPayment: uint64
        MinBid: uint64
        BuilderBoostFactor: uint64
    }

/// The BuilderConfig body of produceBlockV4: builders to ask, and the rules for p2p bids.
type BuilderConfig =
    {
        P2pMinBid: uint64
        P2pBuilderBoostFactor: uint64
        Builders: BuilderEntry list
    }

/// POST /eth/v1/validator/builder_preferences, one entry per builder per proposer.
type BuilderPreferencesEntry =
    {
        ProposerPubkey: PubKey
        Url: string
        Auth: SignedBuilderRequestAuth
        MaxExecutionPayment: uint64
    }

/// A block from produceBlockV4 (Gloas): the BeaconBlock, and the self-built envelope with its
/// blobs when the node included them.
type ProducedBlockV4 =
    {
        Version: string
        ExecutionPayloadValue: Numerics.BigInteger
        ConsensusBlockValue: Numerics.BigInteger
        Block: SszValue
        /// ExecutionPayloadEnvelope, KZG proofs and blobs (Eth-Execution-Payload-Included).
        Included: struct (SszValue * SszValue * SszValue) voption
        /// Eth-Builder-Url: the builder whose bid won over the builder API; echoed on publish.
        BuilderUrl: string voption
        Ssz: bool
    }

/// A block from produceBlockV3: BlockContents (Fulu) as a value over the schema it was read with.
type ProducedBlock =
    {
        Version: string
        Blinded: bool
        ExecutionPayloadValue: Numerics.BigInteger
        ConsensusBlockValue: Numerics.BigInteger
        Contents: SszValue
        /// True when the node answered in SSZ.
        Ssz: bool
    }

type SyncStatus =
    {
        HeadSlot: Slot
        SyncDistance: uint64
        IsSyncing: bool
        IsOptimistic: bool
        ElOffline: bool
    }

type SubmitFailure = { Index: int; Message: string }

type ApiError =
    | Http of status: int * message: string
    /// The node refused some items of a batch (HTTP 400 with an IndexedErrorMessage).
    | Rejected of SubmitFailure list
    | Transport of string
    | Decode of string
    | Timeout
    /// The answer decoded but failed the VC's check (a block for another slot, a wrong fee recipient).
    | Invalid of string

    member this.Describe =
        match this with
        | Http(s, m) -> $"HTTP {s}: {m}"
        | Rejected fs -> String.Join("; ", fs |> List.map (fun f -> $"#{f.Index}: {f.Message}"))
        | Transport m -> $"transport: {m}"
        | Decode m -> $"decode: {m}"
        | Timeout -> "timeout"
        | Invalid m -> m

module Decoders =
    let private data e = prop e "data"

    let genesis e =
        let d = data e

        {
            GenesisTime = u64Field d "genesis_time"
            GenesisValidatorsRoot = rootField d "genesis_validators_root"
            GenesisForkVersion = version (prop d "genesis_fork_version")
        }

    /// /eth/v1/config/spec: keeps string values; nested values such as BLOB_SCHEDULE are skipped.
    let spec e : Map<string, string> =
        let d = data e

        if d.ValueKind <> JsonValueKind.Object then
            fail "spec data must be an object"

        [
            for p in d.EnumerateObject() do
                if p.Value.ValueKind = JsonValueKind.String then
                    p.Name, str p.Value
        ]
        |> Map.ofList

    let fork e : Fork =
        let d = data e

        {
            PreviousVersion = version (prop d "previous_version")
            CurrentVersion = version (prop d "current_version")
            Epoch = u64Field d "epoch"
        }

    let validators e : ValidatorInfo[] =
        array (data e)
        |> Array.map (fun v ->
            let inner = prop v "validator"

            {
                Index = u64Field v "index"
                PubKey = pubkeyField inner "pubkey"
                Status = strField v "status"
                ActivationEpoch = u64Field inner "activation_epoch"
                ExitEpoch = u64Field inner "exit_epoch"
                Slashed = optBoolField inner "slashed"
            })

    let private duties (item: JsonElement -> 'T) e : Duties<'T> =
        {
            DependentRoot = rootField e "dependent_root"
            ExecutionOptimistic = optBoolField e "execution_optimistic"
            Data = array (data e) |> Array.map item
        }

    let attesterDuties e =
        duties
            (fun d ->
                {
                    PubKey = pubkeyField d "pubkey"
                    ValidatorIndex = u64Field d "validator_index"
                    CommitteeIndex = u64Field d "committee_index"
                    CommitteeLength = u64Field d "committee_length"
                    CommitteesAtSlot = u64Field d "committees_at_slot"
                    ValidatorCommitteeIndex = u64Field d "validator_committee_index"
                    Slot = u64Field d "slot"
                }
                : AttesterDuty)
            e

    let proposerDuties e =
        duties
            (fun d ->
                {
                    PubKey = pubkeyField d "pubkey"
                    ValidatorIndex = u64Field d "validator_index"
                    Slot = u64Field d "slot"
                }
                : ProposerDuty)
            e

    let checkpoint e : Checkpoint =
        {
            Epoch = u64Field e "epoch"
            Root = rootField e "root"
        }

    let attestationDataOf (d: JsonElement) : AttestationData =
        {
            Slot = u64Field d "slot"
            Index = u64Field d "index"
            BeaconBlockRoot = rootField d "beacon_block_root"
            Source = checkpoint (prop d "source")
            Target = checkpoint (prop d "target")
        }

    let attestationData e = attestationDataOf (data e)

    let syncDuties e : bool * SyncDuty[] =
        optBoolField e "execution_optimistic",
        array (data e)
        |> Array.map (fun d ->
            {
                PubKey = pubkeyField d "pubkey"
                ValidatorIndex = u64Field d "validator_index"
                Indices = array (prop d "validator_sync_committee_indices") |> Array.map u64
            })

    /// GET /eth/v1/beacon/blocks/{id}/root
    /// POST /eth/v1/validator/liveness/{epoch}: (index, is_live) per validator.
    let liveness e : (ValidatorIndex * bool)[] =
        array (data e) |> Array.map (fun x -> u64Field x "index", boolField x "is_live")

    let blockRoot e : bool * Root = optBoolField e "execution_optimistic", rootField (data e) "root"

    let syncing e =
        let d = data e

        {
            HeadSlot = u64Field d "head_slot"
            SyncDistance = u64Field d "sync_distance"
            IsSyncing = boolField d "is_syncing"
            IsOptimistic = optBoolField d "is_optimistic"
            ElOffline = optBoolField d "el_offline"
        }

    let ptcDuties e : Duties<PtcDuty> =
        duties
            (fun d ->
                {
                    PubKey = pubkeyField d "pubkey"
                    ValidatorIndex = u64Field d "validator_index"
                    Slot = u64Field d "slot"
                }
                : PtcDuty)
            e

    let payloadAttestationDataOf (d: JsonElement) : PayloadAttestationData =
        Codec.payloadAttestationDataOf (SszJson.read Schemas.Gloas.payloadAttestationData d)

    /// The slot and block root of an execution_payload_available event.
    let payloadAvailable (e: JsonElement) : struct (Slot * Root) = struct (u64Field e "slot", rootField e "block_root")

    /// The `head` event, or the data part of a `head_v2` event.
    let headEvent (eventName: string) (e: JsonElement) : HeadEvent =
        match eventName with
        | "head_v2" ->
            let d = prop e "data"

            {
                Slot = u64Field d "slot"
                Block = rootField d "block"
                EpochTransition = optBoolField d "epoch_transition"
                PreviousDutyDependentRoot = rootField d "current_epoch_dependent_root"
                CurrentDutyDependentRoot = rootField d "next_epoch_dependent_root"
                ExecutionOptimistic = optBoolField d "execution_optimistic"
            }
        | _ ->
            {
                Slot = u64Field e "slot"
                Block = rootField e "block"
                EpochTransition = optBoolField e "epoch_transition"
                PreviousDutyDependentRoot = rootField e "previous_duty_dependent_root"
                CurrentDutyDependentRoot = rootField e "current_duty_dependent_root"
                ExecutionOptimistic = optBoolField e "execution_optimistic"
            }

    /// The most failures of one error answer the VC keeps. Each ends up in a log line.
    [<Literal>]
    let MaxFailures = 16

    /// An ErrorMessage or IndexedErrorMessage body. The texts are cut and cleaned for a log line
    /// (Threshold.cleanReason) and at most MaxFailures failures are kept: a node's answer can be
    /// megabytes long and hold newlines.
    let error (e: JsonElement) : string * SubmitFailure list =
        let message =
            match tryProp e "message" with
            | ValueSome m when m.ValueKind = JsonValueKind.String -> Threshold.cleanReason (str m)
            | _ -> ""

        let failures =
            match tryProp e "failures" with
            | ValueSome f when f.ValueKind = JsonValueKind.Array ->
                [
                    for x in Seq.truncate MaxFailures (f.EnumerateArray()) ->
                        {
                            Index = int (u64Field x "index")
                            Message =
                                (match tryProp x "message" with
                                 | ValueSome m -> Threshold.cleanReason (str m)
                                 | ValueNone -> "")
                        }
                ]
            | _ -> []

        message, failures

module Encoders =
    let private checkpoint (w: Utf8JsonWriter) (name: string) (c: Checkpoint) =
        w.WriteStartObject name
        writeU64 w "epoch" c.Epoch
        w.WriteString("root", c.Root.Hex)
        w.WriteEndObject()

    let attestationData (w: Utf8JsonWriter) (d: AttestationData) =
        w.WriteStartObject "data"
        writeU64 w "slot" d.Slot
        writeU64 w "index" d.Index
        w.WriteString("beacon_block_root", d.BeaconBlockRoot.Hex)
        checkpoint w "source" d.Source
        checkpoint w "target" d.Target
        w.WriteEndObject()

    let singleAttestations (atts: SingleAttestation seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for a in atts do
                w.WriteStartObject()
                writeU64 w "committee_index" a.CommitteeIndex
                writeU64 w "attester_index" a.AttesterIndex
                attestationData w a.Data
                w.WriteString("signature", a.Signature.Hex)
                w.WriteEndObject()

            w.WriteEndArray())

    let beaconCommitteeSubscriptions (subs: BeaconCommitteeSubscription seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for s in subs do
                w.WriteStartObject()
                writeU64 w "validator_index" s.ValidatorIndex
                writeU64 w "committee_index" s.CommitteeIndex
                writeU64 w "committees_at_slot" s.CommitteesAtSlot
                writeU64 w "slot" s.Slot
                w.WriteBoolean("is_aggregator", s.IsAggregator)
                w.WriteEndObject()

            w.WriteEndArray())

    let syncCommitteeSubscriptions (subs: SyncCommitteeSubscription seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for s in subs do
                w.WriteStartObject()
                writeU64 w "validator_index" s.ValidatorIndex
                w.WriteStartArray "sync_committee_indices"

                for i in s.Indices do
                    w.WriteStringValue(i.ToString(Globalization.CultureInfo.InvariantCulture))

                w.WriteEndArray()
                writeU64 w "until_epoch" s.UntilEpoch
                w.WriteEndObject()

            w.WriteEndArray())

    let syncCommitteeMessages (msgs: SyncCommitteeMessage seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for m in msgs do
                w.WriteStartObject()
                writeU64 w "slot" m.Slot
                w.WriteString("beacon_block_root", m.BeaconBlockRoot.Hex)
                writeU64 w "validator_index" m.ValidatorIndex
                w.WriteString("signature", m.Signature.Hex)
                w.WriteEndObject()

            w.WriteEndArray())

    /// prepare_beacon_proposer: fee recipients as 0x-hex addresses.
    let proposerPreparations (xs: (ValidatorIndex * string) seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for index, feeRecipient in xs do
                w.WriteStartObject()
                writeU64 w "validator_index" index
                w.WriteString("fee_recipient", feeRecipient)
                w.WriteEndObject()

            w.WriteEndArray())

    /// register_validator: SignedValidatorRegistrationV1 objects.
    let signedValidatorRegistrations (xs: (ValidatorRegistration * BlsSignature) seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for r, signature in xs do
                SszJson.write
                    w
                    Schemas.signedValidatorRegistration
                    (Ssz.Fields [| Codec.validatorRegistrationValue r; Ssz.Bytes signature.Bytes |])

            w.WriteEndArray())

    let signedVoluntaryExit (x: VoluntaryExit) (signature: BlsSignature) : byte[] =
        toBytes (fun w ->
            w.WriteStartObject()
            w.WriteStartObject "message"
            writeU64 w "epoch" x.Epoch
            writeU64 w "validator_index" x.ValidatorIndex
            w.WriteEndObject()
            w.WriteString("signature", signature.Hex)
            w.WriteEndObject())

    let payloadAttestationMessages (msgs: PayloadAttestationMessage seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for m in msgs do
                w.WriteStartObject()
                writeU64 w "validator_index" m.ValidatorIndex
                w.WritePropertyName "data"
                SszJson.write w Schemas.Gloas.payloadAttestationData (Codec.payloadAttestationDataValue m.Data)
                w.WriteString("signature", m.Signature.Hex)
                w.WriteEndObject()

            w.WriteEndArray())

    let signedProposerPreferences (xs: SignedProposerPreferences seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for x in xs do
                w.WriteStartObject()
                w.WritePropertyName "message"
                SszJson.write w Schemas.Gloas.proposerPreferences (Codec.proposerPreferencesValue x.Message)
                w.WriteString("signature", x.Signature.Hex)
                w.WriteEndObject()

            w.WriteEndArray())

    let private signedAuth (w: Utf8JsonWriter) (a: SignedBuilderRequestAuth) =
        w.WriteStartObject "auth"
        w.WriteStartObject "message"
        w.WriteString("data", Hex.encodeArray a.Auth.AuthData)
        writeU64 w "slot" a.Auth.AuthSlot
        w.WriteEndObject()
        w.WriteString("signature", a.AuthSignature.Hex)
        w.WriteEndObject()

    /// The BuilderConfig body of produceBlockV4. The url is a string here, not hex.
    let builderConfig (c: BuilderConfig) : byte[] =
        toBytes (fun w ->
            w.WriteStartObject()
            writeU64 w "min_bid" c.P2pMinBid
            writeU64 w "builder_boost_factor" c.P2pBuilderBoostFactor
            w.WriteStartArray "builders"

            for b in c.Builders do
                w.WriteStartObject()
                w.WriteString("url", b.Url)
                signedAuth w b.Auth
                w.WriteStartArray "builder_pubkeys"

                for k in b.BuilderPubkeys do
                    w.WriteStringValue k.Hex

                w.WriteEndArray()
                writeU64 w "max_execution_payment" b.MaxExecutionPayment
                writeU64 w "min_bid" b.MinBid
                writeU64 w "builder_boost_factor" b.BuilderBoostFactor
                w.WriteEndObject()

            w.WriteEndArray()
            w.WriteEndObject())

    let builderPreferences (xs: BuilderPreferencesEntry seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for x in xs do
                w.WriteStartObject()
                w.WriteString("proposer_pubkey", x.ProposerPubkey.Hex)
                w.WriteString("url", x.Url)
                signedAuth w x.Auth
                writeU64 w "max_execution_payment" x.MaxExecutionPayment
                w.WriteEndObject()

            w.WriteEndArray())

    /// A JSON array of SSZ values in their API form.
    let sszArray (schema: SszType) (values: SszValue seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for v in values do
                SszJson.write w schema v

            w.WriteEndArray())

    let indices (xs: uint64 seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for x in xs do
                w.WriteStringValue(x.ToString(Globalization.CultureInfo.InvariantCulture))

            w.WriteEndArray())

    let validatorIds (ids: string seq) : byte[] =
        toBytes (fun w ->
            w.WriteStartObject()
            w.WriteStartArray "ids"

            for x in ids do
                w.WriteStringValue x

            w.WriteEndArray()
            w.WriteEndObject())

type SseEvent = { Event: string; Data: string }

/// A raw answer: status, the headers the VC reads, body.
type RawResponse =
    {
        Status: int
        ContentType: string
        Headers: Map<string, string>
        Body: byte[]
    }

/// A signed block or envelope for every node: its SSZ encoding, made once, which each node's
/// request sends, and the value for a node that asks for JSON. A full block encodes to about
/// 2 MB, so encoding it per node costs 4 ms and 2 MB of garbage each.
type Publication =
    {
        Schema: SszType
        Value: SszValue
        Ssz: byte[]
    }

    static member Of(schema: SszType, value: SszValue) =
        {
            Schema = schema
            Value = value
            Ssz = Ssz.serialize schema value
        }


/// A Publication encoded before its signature exists, so the encoding can run while the signer
/// works: `build signature` is the signed value, and the 96-byte signature is its field at
/// `path` (field indexes). WithSignature writes the signature into the bytes; call it once.
type UnsignedPublication(schema: SszType, build: SszValue -> SszValue, path: int list) =
    let bytes = Ssz.serialize schema (build (Ssz.Bytes(Array.zeroCreate 96)))
    let at = Ssz.fieldOffset schema bytes path

    member _.WithSignature(signature: byte[]) : Publication =
        if signature.Length <> 96 then
            invalidArg (nameof signature) "a signature has 96 bytes"

        Buffer.BlockCopy(signature, 0, bytes, at, 96)

        {
            Schema = schema
            Value = build (Ssz.Bytes signature)
            Ssz = bytes
        }

/// `headers` go with every request (the node's API key or basic auth); they never reach a log.
/// `maxBody`: the largest answer read, in bytes (default BeaconClient.MaxBody); a larger one is a
/// transport error, so a node cannot make the VC run out of memory.
type BeaconClient
    (http: HttpClient, baseUri: Uri, requestTimeout: TimeSpan, ?headers: (string * string) list, ?maxBody: int) =
    // The node URL's path is a prefix (a proxy may serve the node under /prefix/): API paths go
    // after it, not in its place.
    let root = Uri(baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/")
    let url (path: string) = Uri(root, path.TrimStart('/'))
    let extraHeaders = defaultArg headers []
    let maxBody = defaultArg maxBody BeaconClient.MaxBody

    /// The body of an answer read with ResponseHeadersRead, at most maxBody bytes. A larger body
    /// throws HttpRequestException, which the callers map to a transport error.
    let readBody (resp: HttpResponseMessage) (ct: CancellationToken) : Task<byte[]> =
        task {
            let length = resp.Content.Headers.ContentLength

            if length.HasValue && length.Value > int64 maxBody then
                raise (HttpRequestException $"the answer has {length.Value} bytes, over the limit of {maxBody}")

            if length.HasValue then
                // Straight into an array of the announced size. LoadIntoBufferAsync and then
                // ReadAsByteArrayAsync copy the body twice: 3.9 MB for a 1.9 MB block. A body
                // shorter than its Content-Length throws an IOException, a transport error.
                let body = GC.AllocateUninitializedArray<byte>(int length.Value)
                let! stream = resp.Content.ReadAsStreamAsync ct
                use stream = stream
                do! stream.ReadExactlyAsync(Memory body, ct).AsTask()
                return body
            else
                do! resp.Content.LoadIntoBufferAsync(int64 maxBody, ct)
                return! resp.Content.ReadAsByteArrayAsync ct
        }

    let addHeaders (req: HttpRequestMessage) =
        for k, v in extraHeaders do
            req.Headers.Remove k |> ignore
            req.Headers.TryAddWithoutValidation(k, v) |> ignore

    /// The node as spans name it: scheme, host and port, never the path, user info or headers.
    let nodeName = $"{baseUri.Scheme}://{baseUri.Authority}"

    /// SendAsync with a client span when a tracing listener is on (Tracing.fs); else the plain call.
    let sendHttp
        (req: HttpRequestMessage)
        (completion: HttpCompletionOption)
        (ct: CancellationToken)
        : Task<HttpResponseMessage> =
        if not (Tracing.source.HasListeners()) then
            http.SendAsync(req, completion, ct)
        else
            task {
                let path =
                    match req.RequestUri with
                    | null -> ""
                    | u -> u.AbsolutePath

                use act =
                    Tracing.source.StartActivity(
                        $"{req.Method.Method} {Tracing.pathTemplate path}",
                        Diagnostics.ActivityKind.Client
                    )

                Tracing.setText act "eplix.node" nodeName
                Tracing.setText act "http.request.method" req.Method.Method
                let mutable answered = false

                try
                    let! resp = http.SendAsync(req, completion, ct)
                    answered <- true
                    Tracing.setInt act "http.response.status_code" (int resp.StatusCode)

                    if not resp.IsSuccessStatusCode then
                        Tracing.fail act $"HTTP {int resp.StatusCode}"

                    return resp
                finally
                    if not answered then
                        Tracing.fail act "no answer"
            }

    /// The text of a 3xx answer. The client follows no redirect, so headers and bodies go only
    /// to the configured node.
    let redirectRefused =
        "the node answered with a redirect, which the VC does not follow; configure the URL it redirects to"

    /// The message and failures of an error answer, cut and cleaned for a log line.
    let errorOf (status: int) (body: ReadOnlyMemory<byte>) : string * SubmitFailure list =
        if status >= 300 && status < 400 then
            redirectRefused, []
        else
            match decode Decoders.error body with
            | Ok r -> r
            | Error _ -> Threshold.cleanReason (Encoding.UTF8.GetString(body.Span.Slice(0, min body.Length 200))), []

    /// The error of a non-2xx answer: the node's message, or its failures for a 400.
    let failureOf (status: int) (body: ReadOnlyMemory<byte>) : ApiError =
        let message, failures = errorOf status body
        if status = 400 && not failures.IsEmpty then Rejected failures else Http(status, message)

    let send
        (req: HttpRequestMessage)
        (decoder: (JsonElement -> 'T) voption)
        (ct: CancellationToken)
        : Task<Result<'T voption, ApiError>> =
        task {
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            cts.CancelAfter requestTimeout
            addHeaders req

            try
                use! resp = sendHttp req HttpCompletionOption.ResponseHeadersRead cts.Token
                let! body = readBody resp cts.Token

                if resp.IsSuccessStatusCode then
                    match decoder with
                    | ValueNone -> return Ok ValueNone
                    | ValueSome d ->
                        match decode d (ReadOnlyMemory body) with
                        | Ok v -> return Ok(ValueSome v)
                        | Error e -> return Error(Decode e)
                else
                    return Error(failureOf (int resp.StatusCode) (ReadOnlyMemory body))
            with
            | :? OperationCanceledException when not ct.IsCancellationRequested -> return Error Timeout
            | :? HttpRequestException as e -> return Error(Transport e.Message)
            | :? IOException as e -> return Error(Transport e.Message)
        }

    /// `send` for a large answer read by a decoder over its raw bytes: the body goes into a
    /// buffer from the shared pool instead of a new array, which for a body over 85 KB would land
    /// on the large object heap at each call. The bytes are valid only while the decoder runs.
    let sendPooled
        (req: HttpRequestMessage)
        (decoder: ReadOnlyMemory<byte> -> 'T)
        (ct: CancellationToken)
        : Task<Result<'T, ApiError>> =
        task {
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            cts.CancelAfter requestTimeout
            addHeaders req

            try
                use! resp = sendHttp req HttpCompletionOption.ResponseHeadersRead cts.Token
                let length = resp.Content.Headers.ContentLength

                if length.HasValue && length.Value > int64 maxBody then
                    raise (HttpRequestException $"the answer has {length.Value} bytes, over the limit of {maxBody}")
                // At most maxBody: the pool rounds up to a power of two, and maxBody + 1 would
                // take an array twice the limit.
                let mutable buffer =
                    ArrayPool<byte>
                        .Shared.Rent(
                            if length.HasValue then int (max 4096L (min (length.Value + 1L) (int64 maxBody))) else 65536
                        )

                let probe = [| 0uy |]

                try
                    use! stream = resp.Content.ReadAsStreamAsync(cts.Token)
                    let mutable n = 0
                    let mutable reading = true

                    while reading do
                        if n >= maxBody then
                            // At the limit: a one-byte read tells whether more comes, with no
                            // bigger buffer.
                            if n > maxBody then
                                raise (HttpRequestException $"the answer is over the limit of {maxBody} bytes")

                            let! extra = stream.ReadAsync(probe.AsMemory(), cts.Token)

                            if extra > 0 then
                                raise (HttpRequestException $"the answer is over the limit of {maxBody} bytes")

                            reading <- false
                        else
                            if n = buffer.Length then
                                // Doubling stops at the limit.
                                let bigger =
                                    ArrayPool<byte>.Shared.Rent(int (min (int64 buffer.Length * 2L) (int64 maxBody)))

                                Buffer.BlockCopy(buffer, 0, bigger, 0, n)
                                ArrayPool<byte>.Shared.Return buffer
                                buffer <- bigger

                            let! read = stream.ReadAsync(buffer.AsMemory(n), cts.Token)
                            if read = 0 then reading <- false else n <- n + read

                    if n > maxBody then
                        raise (HttpRequestException $"the answer is over the limit of {maxBody} bytes")

                    let body = ReadOnlyMemory(buffer, 0, n)

                    if resp.IsSuccessStatusCode then
                        match decodeBytes decoder body with
                        | Ok v -> return Ok v
                        | Error e -> return Error(Decode e)
                    else
                        return Error(failureOf (int resp.StatusCode) body)
                finally
                    ArrayPool<byte>.Shared.Return buffer
            with
            | :? OperationCanceledException when not ct.IsCancellationRequested -> return Error Timeout
            | :? HttpRequestException as e -> return Error(Transport e.Message)
            | :? IOException as e -> return Error(Transport e.Message)
        }

    let get path decoder ct =
        task {
            use req = new HttpRequestMessage(HttpMethod.Get, url path)
            req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue "application/json")

            match! send req (ValueSome decoder) ct with
            | Ok(ValueSome v) -> return Ok v
            | Ok ValueNone -> return Error(Decode "empty response")
            | Error e -> return Error e
        }

    let postAs
        (contentType: string)
        path
        (body: byte[])
        (headers: (string * string) list)
        (decoder: (JsonElement -> 'T) voption)
        ct
        =
        task {
            use req = new HttpRequestMessage(HttpMethod.Post, url path)
            req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue "application/json")

            for k, v in headers do
                req.Headers.TryAddWithoutValidation(k, v) |> ignore

            let content = new ByteArrayContent(body)
            content.Headers.ContentType <- MediaTypeHeaderValue contentType
            req.Content <- content
            return! send req decoder ct
        }

    let post path body headers decoder ct = postAs "application/json" path body headers decoder ct

    let postUnit path body headers ct =
        task {
            match! post path body headers ValueNone ct with
            | Ok _ -> return Ok()
            | Error e -> return Error e
        }

    /// A GET that keeps status, headers and body, for answers that may come as SSZ.
    let getRaw
        (path: string)
        (accept: string)
        (timeout: TimeSpan)
        (ct: CancellationToken)
        : Task<Result<RawResponse, ApiError>> =
        task {
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            cts.CancelAfter timeout

            try
                use req = new HttpRequestMessage(HttpMethod.Get, url path)
                req.Headers.TryAddWithoutValidation("Accept", accept) |> ignore
                addHeaders req
                use! resp = sendHttp req HttpCompletionOption.ResponseHeadersRead cts.Token
                let! body = readBody resp cts.Token

                let headers =
                    [
                        for h in resp.Headers do
                            h.Key.ToLowerInvariant(), String.Join(",", h.Value)
                    ]
                    |> Map.ofList

                let contentType =
                    match resp.Content.Headers.ContentType with
                    | null -> ""
                    | c -> defaultArg (Option.ofObj c.MediaType) ""

                if resp.IsSuccessStatusCode then
                    return
                        Ok
                            {
                                Status = int resp.StatusCode
                                ContentType = contentType
                                Headers = headers
                                Body = body
                            }
                else
                    let message, _ = errorOf (int resp.StatusCode) (ReadOnlyMemory body)
                    return Error(Http(int resp.StatusCode, message))
            with
            | :? OperationCanceledException when not ct.IsCancellationRequested -> return Error Timeout
            | :? HttpRequestException as e -> return Error(Transport e.Message)
            | :? IOException as e -> return Error(Transport e.Message)
        }

    /// A POST that keeps status, headers and body, for answers that may come as SSZ.
    let postRaw
        (path: string)
        (body: byte[])
        (headers: (string * string) list)
        (accept: string)
        (timeout: TimeSpan)
        (ct: CancellationToken)
        : Task<Result<RawResponse, ApiError>> =
        task {
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            cts.CancelAfter timeout

            try
                use req = new HttpRequestMessage(HttpMethod.Post, url path)
                req.Headers.TryAddWithoutValidation("Accept", accept) |> ignore
                addHeaders req

                for k, v in headers do
                    req.Headers.TryAddWithoutValidation(k, v) |> ignore

                let content = new ByteArrayContent(body)
                content.Headers.ContentType <- MediaTypeHeaderValue "application/json"
                req.Content <- content
                use! resp = sendHttp req HttpCompletionOption.ResponseHeadersRead cts.Token
                let! respBody = readBody resp cts.Token

                let headers =
                    [
                        for h in resp.Headers do
                            h.Key.ToLowerInvariant(), String.Join(",", h.Value)
                    ]
                    |> Map.ofList

                let contentType =
                    match resp.Content.Headers.ContentType with
                    | null -> ""
                    | c -> defaultArg (Option.ofObj c.MediaType) ""

                if resp.IsSuccessStatusCode then
                    return
                        Ok
                            {
                                Status = int resp.StatusCode
                                ContentType = contentType
                                Headers = headers
                                Body = respBody
                            }
                else
                    let message, _ = errorOf (int resp.StatusCode) (ReadOnlyMemory respBody)
                    return Error(Http(int resp.StatusCode, message))
            with
            | :? OperationCanceledException when not ct.IsCancellationRequested -> return Error Timeout
            | :? HttpRequestException as e -> return Error(Transport e.Message)
            | :? IOException as e -> return Error(Transport e.Message)
        }

    /// A block value (Wei, a uint256): zero when it is not a decimal uint256.
    let bigOf (s: string) = defaultValueArg (SszJson.tryUint256 s) Numerics.BigInteger.Zero

    let postDecoded path body headers decoder ct =
        task {
            match! post path body headers (ValueSome decoder) ct with
            | Ok(ValueSome v) -> return Ok v
            | Ok ValueNone -> return Error(Decode "empty response")
            | Error e -> return Error e
        }

    /// The largest answer a client reads by default: 128 MiB. The largest expected answers are a
    /// validators list for every key (about 450 bytes a key) and a JSON block with its blobs.
    static member MaxBody = 128 * 1024 * 1024

    /// No byte on an event stream for this long ends it, and RunEvents opens it again: a node
    /// sends a head event each slot, so a silent stream is a dead one.
    static member EventIdle = TimeSpan.FromMinutes 2.0

    /// The longest event line, and the longest event data, in characters (8 Mi). The largest
    /// expected event is an attester slashing with two full indexed attestations.
    static member MaxEvent = 8 * 1024 * 1024

    member _.BaseUri = baseUri

    /// The node in logs and metric labels: scheme, host and port, never the path, user info or
    /// headers, which may carry credentials.
    member _.Name = nodeName

    /// A JSON GET for a module's own endpoint. A 404 is ValueNone, not an error, so an empty
    /// answer (a slot without a block) does not lower the node's score.
    member _.GetJson
        (path: string, decoder: JsonElement -> 'T, ct: CancellationToken)
        : Task<Result<'T voption, ApiError>> =
        task {
            match! get path decoder ct with
            | Ok v -> return Ok(ValueSome v)
            | Error(Http(404, _)) -> return Ok ValueNone
            | Error e -> return Error e
        }

    /// GetJson with a decoder over the raw bytes (a Utf8JsonReader), for large answers: the body
    /// is read into a pooled buffer and no document is built.
    member _.GetJsonBytes
        (path: string, decoder: ReadOnlyMemory<byte> -> 'T, ct: CancellationToken)
        : Task<Result<'T voption, ApiError>> =
        task {
            use req = new HttpRequestMessage(HttpMethod.Get, url path)
            req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue "application/json")

            match! sendPooled req decoder ct with
            | Ok v -> return Ok(ValueSome v)
            | Error(Http(404, _)) -> return Ok ValueNone
            | Error e -> return Error e
        }

    /// A JSON POST for a module's own endpoint (the Obol module's selection endpoints, the
    /// monitor's rewards and balances).
    member _.PostJson
        (path: string, body: byte[], decoder: JsonElement -> 'T, ct: CancellationToken)
        : Task<Result<'T, ApiError>> =
        postDecoded path body [] decoder ct

    member _.Genesis(ct) = get "/eth/v1/beacon/genesis" Decoders.genesis ct
    member _.Spec(ct) = get "/eth/v1/config/spec" Decoders.spec ct
    member _.Syncing(ct) = get "/eth/v1/node/syncing" Decoders.syncing ct
    member _.StateFork(stateId: string, ct) = get $"/eth/v1/beacon/states/{stateId}/fork" Decoders.fork ct

    /// POST /eth/v1/beacon/states/{state_id}/validators with pubkeys or indices as ids.
    member _.Validators(stateId: string, ids: string seq, ct) =
        postDecoded $"/eth/v1/beacon/states/{stateId}/validators" (Encoders.validatorIds ids) [] Decoders.validators ct

    member _.AttesterDuties(epoch: Epoch, indices: ValidatorIndex seq, ct) =
        postDecoded
            $"/eth/v1/validator/duties/attester/{epoch}"
            (Encoders.indices indices)
            []
            Decoders.attesterDuties
            ct

    /// Whether each validator was seen live (attesting or proposing) in the epoch. Nodes answer
    /// for the current and the previous epoch.
    member _.Liveness(epoch: Epoch, indices: ValidatorIndex seq, ct) =
        postDecoded $"/eth/v1/validator/liveness/{epoch}" (Encoders.indices indices) [] Decoders.liveness ct

    member _.ProposerDuties(epoch: Epoch, ct) =
        get $"/eth/v1/validator/duties/proposer/{epoch}" Decoders.proposerDuties ct

    member _.AttestationData(slot: Slot, committeeIndex: CommitteeIndex, ct) =
        get
            $"/eth/v1/validator/attestation_data?slot={slot}&committee_index={committeeIndex}"
            Decoders.attestationData
            ct

    /// POST /eth/v2/beacon/pool/attestations with SingleAttestation objects (Electra and later).
    member _.SubmitAttestations(fork: ForkName, atts: SingleAttestation seq, ct) : Task<Result<unit, ApiError>> =
        task {
            match!
                post
                    "/eth/v2/beacon/pool/attestations"
                    (Encoders.singleAttestations atts)
                    [ "Eth-Consensus-Version", fork.ApiName ]
                    ValueNone
                    ct
            with
            | Ok _ -> return Ok()
            | Error e -> return Error e
        }

    member _.SyncDuties(epoch: Epoch, indices: ValidatorIndex seq, ct) =
        postDecoded $"/eth/v1/validator/duties/sync/{epoch}" (Encoders.indices indices) [] Decoders.syncDuties ct

    member _.BeaconCommitteeSubscriptions(subs: BeaconCommitteeSubscription seq, ct) =
        postUnit "/eth/v1/validator/beacon_committee_subscriptions" (Encoders.beaconCommitteeSubscriptions subs) [] ct

    member _.SyncCommitteeSubscriptions(subs: SyncCommitteeSubscription seq, ct) =
        postUnit "/eth/v1/validator/sync_committee_subscriptions" (Encoders.syncCommitteeSubscriptions subs) [] ct

    member _.PrepareBeaconProposer(xs: (ValidatorIndex * string) seq, ct) =
        postUnit "/eth/v1/validator/prepare_beacon_proposer" (Encoders.proposerPreparations xs) [] ct

    /// GET /eth/v1/beacon/blocks/head/root: (execution_optimistic, root).
    member _.HeadBlockRoot(ct) = get "/eth/v1/beacon/blocks/head/root" Decoders.blockRoot ct

    /// produceBlockV3. Asks for SSZ first. builder_boost_factor 0 (the default) asks for a local
    /// block; the legacy builder module passes its factor and the BlindedBeaconBlock schema a
    /// builder block comes in. Without that schema a blinded answer does not decode.
    member _.ProduceBlockV3
        (
            slot: Slot,
            randao: BlsSignature,
            graffiti: Root,
            schema: SszType,
            ct,
            ?boostFactor: uint64,
            ?blindedSchema: SszType
        ) : Task<Result<ProducedBlock, ApiError>> =
        task {
            let boost = defaultArg boostFactor 0UL

            let path =
                $"/eth/v3/validator/blocks/{slot}?randao_reveal={randao.Hex}&graffiti={graffiti.Hex}&builder_boost_factor={boost}"

            match! getRaw path "application/octet-stream;q=1.0,application/json;q=0.9" (requestTimeout * 2.0) ct with
            | Error e -> return Error e
            | Ok r ->
                let header (k: string) = defaultArg (r.Headers.TryFind k) ""

                let schemaOf (blinded: bool) =
                    match blinded, blindedSchema with
                    | true, Some b -> b
                    | _ -> schema

                if r.ContentType = "application/octet-stream" then
                    let blinded = header "eth-execution-payload-blinded" = "true"

                    match Ssz.deserialize (schemaOf blinded) r.Body with
                    | Error e -> return Error(Decode $"block: {e}")
                    | Ok v ->
                        return
                            Ok
                                {
                                    Version = header "eth-consensus-version"
                                    Blinded = blinded
                                    ExecutionPayloadValue = bigOf (header "eth-execution-payload-value")
                                    ConsensusBlockValue = bigOf (header "eth-consensus-block-value")
                                    Contents = v
                                    Ssz = true
                                }
                else
                    let decoder (e: JsonElement) =
                        let blinded = optBoolField e "execution_payload_blinded"

                        let value name =
                            match tryProp e name with
                            | ValueSome v -> bigOf (str v)
                            | ValueNone -> Numerics.BigInteger.Zero

                        {
                            Version = strField e "version"
                            Blinded = blinded
                            ExecutionPayloadValue = value "execution_payload_value"
                            ConsensusBlockValue = value "consensus_block_value"
                            Contents =
                                match blinded, blindedSchema with
                                | true, None -> Ssz.U 0UL
                                | _ -> SszJson.read (schemaOf blinded) (prop e "data")
                            Ssz = false
                        }

                    match decode decoder (ReadOnlyMemory r.Body) with
                    | Ok b -> return Ok b
                    | Error e -> return Error(Decode $"block: {e}")
        }

    /// POST /eth/v2/beacon/blocks with SignedBlockContents (Fulu) or SignedBeaconBlock (Gloas), as
    /// SSZ; JSON when the node refuses SSZ (415). A Gloas block whose bid came over the builder
    /// API echoes Eth-Builder-Url.
    member _.PublishBlock
        (version: string, signed: Publication, ct, ?builderUrl: string)
        : Task<Result<unit, ApiError>> =
        task {
            let headers =
                [
                    "Eth-Consensus-Version", version
                    match builderUrl with
                    | Some u -> "Eth-Builder-Url", u
                    | None -> ()
                ]

            let path = "/eth/v2/beacon/blocks?broadcast_validation=gossip"

            match! postAs "application/octet-stream" path signed.Ssz headers ValueNone ct with
            | Ok _ -> return Ok()
            | Error(Http(415, _)) ->
                match! post path (SszJson.toBytes signed.Schema signed.Value) headers ValueNone ct with
                | Ok _ -> return Ok()
                | Error e -> return Error e
            | Error e -> return Error e
        }

    /// POST /eth/v2/beacon/blinded_blocks with a SignedBlindedBeaconBlock, as SSZ; JSON when the
    /// node refuses SSZ (415). The node asks its relays for the payload.
    member _.PublishBlindedBlock(version: string, signed: Publication, ct) : Task<Result<unit, ApiError>> =
        task {
            let headers = [ "Eth-Consensus-Version", version ]
            let path = "/eth/v2/beacon/blinded_blocks?broadcast_validation=gossip"

            match! postAs "application/octet-stream" path signed.Ssz headers ValueNone ct with
            | Ok _ -> return Ok()
            | Error(Http(415, _)) ->
                match! post path (SszJson.toBytes signed.Schema signed.Value) headers ValueNone ct with
                | Ok _ -> return Ok()
                | Error e -> return Error e
            | Error e -> return Error e
        }

    /// POST /eth/v1/validator/register_validator: signed registrations the node passes to its
    /// relays (builder-specs, through MEV-Boost).
    member _.RegisterValidator(xs: (ValidatorRegistration * BlsSignature) seq, ct) =
        postUnit "/eth/v1/validator/register_validator" (Encoders.signedValidatorRegistrations xs) [] ct

    // ---- Gloas ----

    member _.PtcDuties(epoch: Epoch, indices: ValidatorIndex seq, ct) =
        postDecoded $"/eth/v1/validator/duties/ptc/{epoch}" (Encoders.indices indices) [] Decoders.ptcDuties ct

    /// GET /eth/v1/validator/payload_attestation_data. ValueNone when the node saw no block for
    /// the slot (204): no vote then.
    member _.PayloadAttestationData(slot: Slot, ct) : Task<Result<PayloadAttestationData voption, ApiError>> =
        task {
            match!
                getRaw $"/eth/v1/validator/payload_attestation_data?slot={slot}" "application/json" requestTimeout ct
            with
            | Error e -> return Error e
            | Ok r when r.Status = 204 || r.Body.Length = 0 -> return Ok ValueNone
            | Ok r ->
                match decode (fun e -> Decoders.payloadAttestationDataOf (prop e "data")) (ReadOnlyMemory r.Body) with
                | Ok d -> return Ok(ValueSome d)
                | Error e -> return Error(Decode e)
        }

    member _.SubmitPayloadAttestations(msgs: PayloadAttestationMessage seq, ct) =
        postUnit
            "/eth/v1/beacon/pool/payload_attestations"
            (Encoders.payloadAttestationMessages msgs)
            [ "Eth-Consensus-Version", "gloas" ]
            ct

    member _.SubmitProposerPreferences(xs: SignedProposerPreferences seq, ct) =
        postUnit
            "/eth/v1/validator/proposer_preferences"
            (Encoders.signedProposerPreferences xs)
            [ "Eth-Consensus-Version", "gloas" ]
            ct

    member _.SubmitBuilderPreferences(xs: BuilderPreferencesEntry seq, ct) =
        postUnit
            "/eth/v1/validator/builder_preferences"
            (Encoders.builderPreferences xs)
            [ "Eth-Consensus-Version", "gloas" ]
            ct

    /// produceBlockV4 (POST /eth/v4/validator/blocks/{slot}) with a BuilderConfig. Asks for SSZ
    /// first. With includePayload the node returns the self-built envelope and blobs with the
    /// block, so any node can take the publish (stateless).
    member _.ProduceBlockV4
        (
            slot: Slot,
            randao: BlsSignature,
            graffiti: Root,
            includePayload: bool,
            config: BuilderConfig,
            preset: Preset,
            ct
        ) : Task<Result<ProducedBlockV4, ApiError>> =
        task {
            let inc = if includePayload then "true" else "false"

            let path =
                $"/eth/v4/validator/blocks/{slot}?randao_reveal={randao.Hex}&graffiti={graffiti.Hex}&include_payload={inc}"

            let headers = [ "Eth-Consensus-Version", "gloas" ]

            match!
                postRaw
                    path
                    (Encoders.builderConfig config)
                    headers
                    "application/octet-stream;q=1.0,application/json;q=0.9"
                    (requestTimeout * 2.0)
                    ct
            with
            | Error e -> return Error e
            | Ok r ->
                let header (k: string) = defaultArg (r.Headers.TryFind k) ""

                let builderUrl =
                    match header "eth-builder-url" with
                    | "" -> ValueNone
                    | u -> ValueSome u

                let split (included: bool) (v: SszValue) =
                    if included then
                        match v with
                        | Fields f -> f[0], ValueSome(struct (f[1], f[2], f[3]))
                        | _ -> raise (SszError "block contents")
                    else
                        v, ValueNone

                if r.ContentType = "application/octet-stream" then
                    let included = header "eth-execution-payload-included" = "true"

                    let schema =
                        if included then Schemas.Gloas.blockContents preset else Schemas.Gloas.beaconBlock preset

                    match Ssz.deserialize schema r.Body with
                    | Error e -> return Error(Decode $"block: {e}")
                    | Ok v ->
                        let block, inc = split included v

                        return
                            Ok
                                {
                                    Version = header "eth-consensus-version"
                                    ExecutionPayloadValue = bigOf (header "eth-execution-payload-value")
                                    ConsensusBlockValue = bigOf (header "eth-consensus-block-value")
                                    Block = block
                                    Included = inc
                                    BuilderUrl = builderUrl
                                    Ssz = true
                                }
                else
                    let decoder (e: JsonElement) =
                        let included = optBoolField e "execution_payload_included"

                        let schema =
                            if included then Schemas.Gloas.blockContents preset else Schemas.Gloas.beaconBlock preset

                        let value name =
                            match tryProp e name with
                            | ValueSome v -> bigOf (str v)
                            | ValueNone -> Numerics.BigInteger.Zero

                        let block, inc = split included (SszJson.read schema (prop e "data"))

                        {
                            Version = strField e "version"
                            ExecutionPayloadValue = value "execution_payload_value"
                            ConsensusBlockValue = value "consensus_block_value"
                            Block = block
                            Included = inc
                            BuilderUrl = builderUrl
                            Ssz = false
                        }

                    match decode decoder (ReadOnlyMemory r.Body) with
                    | Ok b -> return Ok b
                    | Error e -> return Error(Decode $"block: {e}")
        }

    /// GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}: the envelope
    /// the node built for its own block (when the block came without it).
    member _.ExecutionPayloadEnvelope
        (slot: Slot, blockRoot: Root, preset: Preset, ct)
        : Task<Result<SszValue, ApiError>> =
        task {
            let path = $"/eth/v1/validator/execution_payload_envelopes/{slot}/{blockRoot.Hex}"
            let schema = Schemas.Gloas.executionPayloadEnvelope preset

            match! getRaw path "application/octet-stream;q=1.0,application/json;q=0.9" requestTimeout ct with
            | Error e -> return Error e
            | Ok r when r.ContentType = "application/octet-stream" ->
                match Ssz.deserialize schema r.Body with
                | Ok v -> return Ok v
                | Error e -> return Error(Decode $"envelope: {e}")
            | Ok r ->
                match decode (fun e -> SszJson.read schema (prop e "data")) (ReadOnlyMemory r.Body) with
                | Ok v -> return Ok v
                | Error e -> return Error(Decode $"envelope: {e}")
        }

    /// POST /eth/v1/beacon/execution_payload_envelopes: SignedExecutionPayloadEnvelopeContents
    /// when the blobs go with it (Eth-Blob-Data-Included: true), else the signed envelope alone.
    /// SSZ first, JSON when the node refuses SSZ (415).
    member _.PublishExecutionPayloadEnvelope
        (signed: Publication, blobsIncluded: bool, ct)
        : Task<Result<unit, ApiError>> =
        task {
            let headers =
                [
                    "Eth-Consensus-Version", "gloas"
                    "Eth-Blob-Data-Included", (if blobsIncluded then "true" else "false")
                ]

            let path = "/eth/v1/beacon/execution_payload_envelopes?broadcast_validation=gossip"

            match! postAs "application/octet-stream" path signed.Ssz headers ValueNone ct with
            | Ok _ -> return Ok()
            | Error(Http(415, _)) ->
                match! post path (SszJson.toBytes signed.Schema signed.Value) headers ValueNone ct with
                | Ok _ -> return Ok()
                | Error e -> return Error e
            | Error e -> return Error e
        }

    /// GET /eth/v2/validator/aggregate_attestation (Electra and later).
    member _.AggregateAttestation(slot: Slot, dataRoot: Root, committeeIndex: CommitteeIndex, schema: SszType, ct) =
        get
            $"/eth/v2/validator/aggregate_attestation?attestation_data_root={dataRoot.Hex}&slot={slot}&committee_index={committeeIndex}"
            (fun e -> SszJson.read schema (prop e "data"))
            ct

    member _.SubmitAggregateAndProofs(version: string, schema: SszType, signed: SszValue seq, ct) =
        postUnit
            "/eth/v2/validator/aggregate_and_proofs"
            (Encoders.sszArray schema signed)
            [ "Eth-Consensus-Version", version ]
            ct

    member _.SubmitSyncCommitteeMessages(msgs: SyncCommitteeMessage seq, ct) =
        postUnit "/eth/v1/beacon/pool/sync_committees" (Encoders.syncCommitteeMessages msgs) [] ct

    member _.SyncCommitteeContribution(slot: Slot, subcommittee: uint64, root: Root, schema: SszType, ct) =
        get
            $"/eth/v1/validator/sync_committee_contribution?slot={slot}&subcommittee_index={subcommittee}&beacon_block_root={root.Hex}"
            (fun e -> SszJson.read schema (prop e "data"))
            ct

    member _.SubmitContributionAndProofs(schema: SszType, signed: SszValue seq, ct) =
        postUnit "/eth/v1/validator/contribution_and_proofs" (Encoders.sszArray schema signed) [] ct

    member _.SubmitVoluntaryExit(x: VoluntaryExit, signature: BlsSignature, ct) =
        postUnit "/eth/v1/beacon/pool/voluntary_exits" (Encoders.signedVoluntaryExit x signature) [] ct

    /// Reads the SSE stream until it ends or ct fires. Calls onEvent for each complete event.
    /// A line or an event's data over `maxEvent` characters (default MaxEvent) ends the stream
    /// with an error, as does no byte for `idle` (default EventIdle; the error is Timeout), so a
    /// node can neither fill the VC's memory nor hold a dead stream open. Lines end in LF, CRLF or
    /// CR (the SSE rules). The idle time runs on `time` (default the system clock).
    member _.Events
        (
            topics: string seq,
            onEvent: SseEvent -> unit,
            ct: CancellationToken,
            ?idle: TimeSpan,
            ?maxEvent: int,
            ?time: TimeProvider
        ) : Task<Result<unit, ApiError>> =
        task {
            let idle = defaultArg idle BeaconClient.EventIdle
            let maxEvent = defaultArg maxEvent BeaconClient.MaxEvent
            let topicList = String.Join(",", topics)
            use req = new HttpRequestMessage(HttpMethod.Get, url $"/eth/v1/events?topics={topicList}")
            req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue "text/event-stream")
            addHeaders req
            // A linked source has no clock of its own, so the idle limit gets a source on `time`.
            use idleCts = new CancellationTokenSource(Timeout.InfiniteTimeSpan, defaultArg time TimeProvider.System)

            use cts = CancellationTokenSource.CreateLinkedTokenSource(ct, idleCts.Token)

            try
                idleCts.CancelAfter idle
                use! resp = http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token)

                if not resp.IsSuccessStatusCode then
                    return Error(Http(int resp.StatusCode, "event stream refused"))
                else
                    use! stream = resp.Content.ReadAsStreamAsync cts.Token
                    use reader = new StreamReader(stream, Encoding.UTF8)
                    let buf = Array.zeroCreate<char> 4096
                    let line = StringBuilder()
                    let data = StringBuilder()
                    let mutable eventName = "message"
                    let mutable afterCr = false
                    let mutable failure = ValueNone

                    let endLine () =
                        let l = line.ToString()
                        line.Clear() |> ignore

                        match l with
                        | "" ->
                            if data.Length > 0 then
                                onEvent
                                    {
                                        Event = eventName
                                        Data = data.ToString()
                                    }

                            data.Clear() |> ignore
                            eventName <- "message"
                        | l when l.StartsWith ':' -> ()
                        | l ->
                            let i = l.IndexOf ':'

                            let field, value =
                                if i < 0 then l, "" else l.Substring(0, i), l.Substring(i + 1).TrimStart(' ')

                            match field with
                            | "event" -> eventName <- value
                            | "data" ->
                                if data.Length + value.Length + 1 > maxEvent then
                                    failure <- ValueSome $"event data over {maxEvent} characters"
                                else
                                    if data.Length > 0 then
                                        data.Append '\n' |> ignore

                                    data.Append value |> ignore
                            | _ -> ()

                    let mutable go = true

                    while go && failure.IsNone do
                        idleCts.CancelAfter idle
                        let! n = reader.ReadAsync(buf.AsMemory(), cts.Token)

                        if n = 0 then
                            go <- false
                        else
                            let mutable i = 0

                            while i < n && failure.IsNone do
                                match buf[i] with
                                | '\n' when afterCr -> afterCr <- false
                                | '\n' -> endLine ()
                                | '\r' ->
                                    afterCr <- true
                                    endLine ()
                                | c ->
                                    afterCr <- false

                                    if line.Length >= maxEvent then
                                        failure <- ValueSome $"an event line over {maxEvent} characters"
                                    else
                                        line.Append c |> ignore

                                i <- i + 1

                    match failure with
                    | ValueSome why -> return Error(Transport why)
                    | ValueNone -> return Ok()
            with
            | :? OperationCanceledException when ct.IsCancellationRequested -> return Ok()
            // Timeout, not Transport: the caller does not count a silent stream as a node fault.
            | :? OperationCanceledException -> return Error Timeout
            | :? HttpRequestException as e -> return Error(Transport e.Message)
            | :? IOException as e -> return Error(Transport e.Message)
        }

module BeaconClient =
    /// An HttpClient for one beacon node: pooled keep-alive connections, no overall timeout
    /// (each call has its own; the event stream has an idle limit). Buffered answers stop at
    /// BeaconClient.MaxBody, as each client also checks.
    let createHttp () =
        let handler =
            new SocketsHttpHandler(
                PooledConnectionLifetime = TimeSpan.FromMinutes 10.0,
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes 2.0,
                MaxConnectionsPerServer = 16,
                AutomaticDecompression = DecompressionMethods.None,
                // A redirect would resend the node headers (API keys) and bodies to another host.
                AllowAutoRedirect = false
            )

        new HttpClient(
            handler,
            Timeout = Threading.Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = int64 BeaconClient.MaxBody
        )

    /// Loads a CA certificate from a PEM or DER file.
    let loadCa (file: string) : Result<Security.Cryptography.X509Certificates.X509Certificate2, string> =
        try
            Ok(
                Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
                    List.exactlyOne (TlsFiles.read [ file ])
                )
            )
        with
        | :? IOException as e -> Error $"ca_cert {file}: {e.Message}"
        | :? Security.Cryptography.CryptographicException as e -> Error $"ca_cert {file}: {e.Message}"

    /// Accepts a server certificate only when it chains to `ca` and names the host. The system
    /// store is not consulted. Intermediate certificates the server sends may complete the chain;
    /// only `ca` is trusted as a root.
    let validateWith (ca: Security.Cryptography.X509Certificates.X509Certificate2) =
        Security.RemoteCertificateValidationCallback(fun _ cert presented errors ->
            match cert with
            | null -> false
            | _ when
                errors
                &&& (Security.SslPolicyErrors.RemoteCertificateNameMismatch
                     ||| Security.SslPolicyErrors.RemoteCertificateNotAvailable)
                <> Security.SslPolicyErrors.None
                ->
                false
            | cert ->
                use chain = new Security.Cryptography.X509Certificates.X509Chain()

                chain.ChainPolicy.TrustMode <-
                    Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust

                chain.ChainPolicy.CustomTrustStore.Add ca |> ignore
                chain.ChainPolicy.RevocationMode <- Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck

                match presented with
                | null -> ()
                | p ->
                    // The certificates the server sent (ExtraStore) and the path the system built
                    // from them. Extra certificates help build the path; they are not trusted.
                    chain.ChainPolicy.ExtraStore.AddRange p.ChainPolicy.ExtraStore

                    for e in p.ChainElements do
                        chain.ChainPolicy.ExtraStore.Add e.Certificate |> ignore

                use leaf = new Security.Cryptography.X509Certificates.X509Certificate2(cert)
                chain.Build leaf)

    /// An HttpClient as createHttp, that trusts only `ca` for the server certificate.
    let createHttpWithCa (ca: Security.Cryptography.X509Certificates.X509Certificate2) =
        let handler =
            new SocketsHttpHandler(
                PooledConnectionLifetime = TimeSpan.FromMinutes 10.0,
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes 2.0,
                MaxConnectionsPerServer = 16,
                AutomaticDecompression = DecompressionMethods.None,
                // A redirect would resend the node headers (API keys) and bodies to another host.
                AllowAutoRedirect = false
            )

        handler.SslOptions.RemoteCertificateValidationCallback <- validateWith ca

        new HttpClient(
            handler,
            Timeout = Threading.Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = int64 BeaconClient.MaxBody
        )
