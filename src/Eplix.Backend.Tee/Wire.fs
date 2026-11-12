/// The runner's framed protocol: frames, status codes, SIGN payloads per duty kind, PUBLIC_KEYS,
/// HEALTH and IDENTITY. Byte layouts follow the tee-signer runner protocol (signer-protocol/wire
/// and backend.go).
///
///   frame = length:u32 body                length = len(body), at most 1 MiB
///   body  = version:u8 type:u8 id:u32 payload
///
/// The version byte is 1, tee-signer's only frame version (wire.Version).
///
/// Protocol integers are big endian; SSZ inside payloads stays little endian.
module Eplix.Backend.Tee.Wire

open System
open System.Buffers.Binary
open System.Security.Cryptography
open System.Text
open System.Text.Json
open Eplix

/// The frame version (wire.Version). A frame of another version is refused.
let FrameVersion = 1uy
let MaxFrame = 1 <<< 20
let HeaderLen = 6
let ResponseFlag = 0x80uy
let MaxNonce = 1024
let MaxImportKey = 4096

[<RequireQualifiedAccess>]
type MsgType =
    | Health = 0x01uy
    | PublicKeys = 0x02uy
    | Sign = 0x03uy
    | Attest = 0x04uy
    | ImportShare = 0x05uy
    | Identity = 0x06uy
    | ImportSealed = 0x07uy
    | ConfigUpdate = 0x08uy

/// Keys one PUBLIC_KEYS answer holds: the frame limit less the header, the status and the count,
/// at 104 bytes a key. The protocol has no paging, so a runner with more keys
/// cannot list them.
let MaxKeysPerFrame = (MaxFrame - HeaderLen - 2 - 4) / 104

/// The error for an answer frame over MaxFrame, named for the request it answers. A key list
/// over the limit says how many keys the runner holds and what the operator can do.
let frameTooLarge (length: uint32) (request: byte voption) =
    match request with
    | ValueSome t when t = byte MsgType.PublicKeys ->
        let keys = (int64 length - int64 HeaderLen - 6L) / 104L
        $"the runner's key list is a {length}-byte frame, about {keys} keys; one frame holds {MaxKeysPerFrame} keys and the protocol has no paging: split the keys across runners of at most {MaxKeysPerFrame} keys each"
    | _ -> $"a {length}-byte frame is over the {MaxFrame}-byte limit"

let typeName (t: byte) =
    let n =
        match LanguagePrimitives.EnumOfValue<byte, MsgType>(t &&& ~~~ResponseFlag) with
        | MsgType.Health -> "HEALTH"
        | MsgType.PublicKeys -> "PUBLIC_KEYS"
        | MsgType.Sign -> "SIGN"
        | MsgType.Attest -> "ATTEST"
        | MsgType.ImportShare -> "IMPORT_SHARE"
        | MsgType.Identity -> "IDENTITY"
        | MsgType.ImportSealed -> "IMPORT_SHARE_SEALED"
        | MsgType.ConfigUpdate -> "CONFIG_UPDATE"
        | _ -> $"TYPE_0x{t:x2}"

    if t &&& ResponseFlag <> 0uy then n + "_RESPONSE" else n

/// One decoded frame.
[<Struct>]
type Frame =
    {
        Type: byte
        Id: uint32
        Payload: byte[]
    }

/// A string from an API that may return null.
let nonNull (s: string | null) : string =
    match s with
    | null -> ""
    | s -> s

type WireError(message: string) =
    inherit Exception(message)

let private fail msg = raise (WireError msg)

/// The bytes of one frame: length, version, type, id, payload.
let encodeFrame (t: byte) (id: uint32) (payload: ReadOnlySpan<byte>) : byte[] =
    let n = HeaderLen + payload.Length

    if n > MaxFrame then
        fail "frame too large"

    let buf = Array.zeroCreate<byte>(4 + n)
    BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(0, 4), uint32 n)
    buf[4] <- FrameVersion
    buf[5] <- t
    BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(6, 4), id)
    payload.CopyTo(buf.AsSpan 10)
    buf

/// Decodes the body of a frame (after the length prefix).
let decodeBody (body: byte[]) : Frame =
    if body.Length < HeaderLen then
        fail $"frame body of {body.Length} bytes is shorter than the header"

    if body[0] <> FrameVersion then
        fail $"unsupported version {body[0]}"

    {
        Type = body[1]
        Id = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan(body, 2, 4))
        Payload = body[HeaderLen..]
    }

// ---- status codes ----------------------------------------------------------

/// Result codes: below 1000 the signer core's sc_status, from 1000 runner and protocol codes
/// (backend/errors.go).
module Status =
    let Ok = 0us
    let Arg = 1us
    let NoMem = 2us
    let Decode = 3us
    let BadKey = 4us
    let Duplicate = 5us
    let UnknownValidator = 6us
    let Storage = 7us
    let Clock = 8us
    let SlashBlock = 9us
    let SlashSource = 10us
    let SlashTarget = 11us
    let SlashSourceGtTarget = 12us
    let PolicyFuture = 13us
    let PolicyExit = 14us
    let PolicyFeeRecipient = 15us
    let PolicyGasLimit = 16us
    let PolicyTimestamp = 17us
    let PolicyPubkey = 18us
    let PolicyIndex = 19us
    let PolicyDomain = 20us
    let PolicyFork = 21us
    let PolicyBuilder = 22us
    let PolicyEnvelope = 23us
    let Equivocation = 24us
    let SelectionProof = 25us
    let Schedule = 26us
    let PolicyBuilderAuth = 27us
    /// tee-signer: an attestation whose target epoch is not the epoch of its slot.
    let PolicyTargetSlot = 28us
    let BadRequest = 1000us
    let Unsupported = 1001us
    let Internal = 1002us
    let DomainMismatch = 1003us
    let NotReady = 1004us
    let Platform = 1005us
    let Forbidden = 1006us
    let RateLimited = 1007us
    /// tee-signer's FLOOR: only a key's restart, import or source floor refuses the message;
    /// detail starts with "floor epoch N (W floor): ". Not a slashing code.
    let Floor = 1008us
    /// tee-signer's FLOOR_UNPROVEN: refused at or below a floor; the runner's mark log says
    /// something was signed there, but the key's own history shows no conflict. Same detail as
    /// FLOOR. The client skips the duty and alerts the operator.
    let FloorUnproven = 1009us

    let name (s: uint16) =
        match s with
        | 0us -> "SC_OK"
        | 1us -> "SC_ERR_ARG"
        | 2us -> "SC_ERR_NOMEM"
        | 3us -> "SC_ERR_DECODE"
        | 4us -> "SC_ERR_BAD_KEY"
        | 5us -> "SC_ERR_DUPLICATE"
        | 6us -> "SC_ERR_UNKNOWN_VALIDATOR"
        | 7us -> "SC_ERR_STORAGE"
        | 8us -> "SC_ERR_CLOCK"
        | 9us -> "SC_ERR_SLASH_BLOCK"
        | 10us -> "SC_ERR_SLASH_SOURCE"
        | 11us -> "SC_ERR_SLASH_TARGET"
        | 12us -> "SC_ERR_SLASH_SOURCE_GT_TARGET"
        | 13us -> "SC_ERR_POLICY_FUTURE"
        | 14us -> "SC_ERR_POLICY_EXIT"
        | 15us -> "SC_ERR_POLICY_FEE_RECIPIENT"
        | 16us -> "SC_ERR_POLICY_GAS_LIMIT"
        | 17us -> "SC_ERR_POLICY_TIMESTAMP"
        | 18us -> "SC_ERR_POLICY_PUBKEY"
        | 19us -> "SC_ERR_POLICY_INDEX"
        | 20us -> "SC_ERR_POLICY_DOMAIN"
        | 21us -> "SC_ERR_POLICY_FORK"
        | 22us -> "SC_ERR_POLICY_BUILDER"
        | 23us -> "SC_ERR_POLICY_ENVELOPE"
        | 24us -> "SC_ERR_EQUIVOCATION"
        | 25us -> "SC_ERR_SELECTION_PROOF"
        | 26us -> "SC_ERR_SCHEDULE"
        | 27us -> "SC_ERR_POLICY_BUILDER_AUTH"
        | 28us -> "SC_ERR_POLICY_TARGET_SLOT"
        | 1000us -> "BAD_REQUEST"
        | 1001us -> "UNSUPPORTED"
        | 1002us -> "INTERNAL"
        | 1003us -> "DOMAIN_MISMATCH"
        | 1004us -> "NOT_READY"
        | 1005us -> "PLATFORM"
        | 1006us -> "FORBIDDEN"
        | 1007us -> "RATE_LIMITED"
        | 1008us -> "FLOOR"
        | 1009us -> "FLOOR_UNPROVEN"
        | s -> $"STATUS_{s}"

    /// Slashing-protection refusals: the four watermark checks and a second Gloas PTC vote or
    /// envelope for one slot (backend Status.IsSlashing).
    let isSlashing (s: uint16) = (s >= SlashBlock && s <= SlashSourceGtTarget) || s = Equivocation

/// A non-OK answer: the status and the runner's detail text (for people only).
type Refusal = { Code: uint16; Detail: string }

/// The body of an OK response, or the runner's refusal: status:u16, then the body when the status
/// is 0, else detail_len:u16 detail with the length matching.
let decodeResponse (p: byte[]) : Result<byte[], Refusal> =
    if p.Length < 2 then
        fail "short response"

    let st = BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(p, 0, 2))

    if st = Status.Ok then
        Ok p[2..]
    else
        if p.Length < 4 || int (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(p, 2, 2))) <> p.Length - 4 then
            fail $"malformed error response (status {Status.name st})"

        Error
            {
                Code = st
                Detail = Encoding.UTF8.GetString(p, 4, p.Length - 4)
            }

/// An error answer as a runner writes it (for fakes and tests).
let encodeError (r: Refusal) : byte[] =
    let d = Encoding.UTF8.GetBytes r.Detail
    let p = Array.zeroCreate<byte>(4 + d.Length)
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(0, 2), r.Code)
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2, 2), uint16 d.Length)
    d.CopyTo(p, 4)
    p

// ---- SIGN --------------------------------------------------------------------

/// SIGN kinds (backend/types.go, aggregates.go, gloas.go, builderauth.go).
module Kind =
    let Attestation = 1uy
    let Block = 2uy
    let VoluntaryExit = 3uy
    let ValidatorRegistration = 4uy
    /// A tagged root message: type, epoch, object root, domain.
    let Root = 5uy
    let PayloadAttestation = 6uy
    let PayloadEnvelope = 7uy
    let ProposerPreferences = 8uy
    let AggregateAndProof = 9uy
    let ContributionAndProof = 10uy
    let SelectionProof = 11uy
    let SyncCommitteeMessage = 12uy
    let SyncSelectionProof = 13uy
    let BuilderRequestAuth = 14uy

/// Root message types (backend RootType). Only RANDAO goes as a root message: the runner checks
/// object_root = hash_tree_root(epoch) for it.
let RootRandaoReveal = 1uy

/// AggregateAndProof forms of kind 9: 0 phase0, 1 Electra, 2 Gloas.
let AggregateElectra = 1uy
let AggregateGloas = 2uy

/// The form of an AggregateAndProof: Gloas when its aggregate is the progressive Attestation of
/// Gloas (Schemas.Gloas.aggregateAndProof), Electra otherwise. The runner refuses form 2 before
/// the Gloas fork and form 1 from it on (SC_ERR_POLICY_FORK).
let aggregateForm (schema: Ssz.SszType) =
    match schema with
    | Ssz.Container [| _; (_, Ssz.ProgressiveContainer _); _ |] -> AggregateGloas
    | _ -> AggregateElectra

let private le64 (out: ResizeArray<byte>) (v: uint64) =
    let b = Array.zeroCreate<byte> 8
    BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(), v)
    out.AddRange b

let private be64 (out: ResizeArray<byte>) (v: uint64) =
    let b = Array.zeroCreate<byte> 8
    BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(), v)
    out.AddRange b

/// Message encoders of the Gloas kinds (6 to 8) and kind 14. Layouts: backend/gloas.go and
/// builderauth.go.
module Gloas =
    /// Kind 6: PayloadAttestationData SSZ, 42 bytes.
    let payloadAttestation (beaconBlockRoot: Root) (slot: Slot) (payloadPresent: bool) (blobDataAvailable: bool) =
        let p = ResizeArray<byte>(42)
        p.AddRange beaconBlockRoot.Bytes
        le64 p slot
        p.Add(if payloadPresent then 1uy else 0uy)
        p.Add(if blobDataAvailable then 1uy else 0uy)
        p.ToArray()

    /// Field names of the Gloas ExecutionPayload and ExecutionPayloadEnvelope, in order.
    let private payloadFields =
        [|
            "parent_hash"
            "fee_recipient"
            "state_root"
            "receipts_root"
            "logs_bloom"
            "prev_randao"
            "block_number"
            "gas_limit"
            "gas_used"
            "timestamp"
            "extra_data"
            "base_fee_per_gas"
            "block_hash"
            "transactions"
            "withdrawals"
            "blob_gas_used"
            "excess_blob_gas"
            "block_access_list"
            "slot_number"
        |]

    let private envelopeFields =
        [|
            "payload"
            "execution_requests"
            "builder_index"
            "beacon_block_root"
            "parent_beacon_block_root"
        |]

    let PayloadEnvelopeLen = 532

    /// Kind 7: a self-built ExecutionPayloadEnvelope in signer-core's layout
    /// (sc_encode_payload_envelope), 532 bytes. Fixed fields of 8, 20 and 32 bytes go as their
    /// SSZ (base_fee_per_gas as the 32-byte little-endian uint256); the others (logs bloom, extra
    /// data, transactions, withdrawals, block access list, execution requests) as their
    /// hash_tree_root. The runner rebuilds the envelope root from these with progressive
    /// merkleization, so a wrong field gives a signature that does not verify.
    let payloadEnvelope (schema: Ssz.SszType) (value: Ssz.SszValue) =
        let part (t: Ssz.SszType) (v: Ssz.SszValue) =
            match t with
            | Ssz.Uint 8
            | Ssz.Uint256
            | Ssz.ByteVector 20
            | Ssz.ByteVector 32 -> Ssz.serialize t v
            | _ -> Ssz.hashTreeRoot t v

        match schema, value with
        | Ssz.ProgressiveContainer ef, Ssz.Fields ev when Array.map fst ef = envelopeFields && ev.Length = ef.Length ->
            match snd ef[0], ev[0] with
            | Ssz.ProgressiveContainer pf, Ssz.Fields pv when Array.map fst pf = payloadFields && pv.Length = pf.Length ->
                let p = ResizeArray<byte>(PayloadEnvelopeLen)

                for i in 0 .. pf.Length - 1 do
                    p.AddRange(part (snd pf[i]) pv[i])

                for i in 1 .. ef.Length - 1 do
                    p.AddRange(part (snd ef[i]) ev[i])

                if p.Count <> PayloadEnvelopeLen then
                    fail $"payload envelope: {p.Count} bytes, want {PayloadEnvelopeLen}"

                p.ToArray()
            | _ -> fail "payload envelope: the payload is not a Gloas ExecutionPayload"
        | _ -> fail "payload envelope: not a Gloas ExecutionPayloadEnvelope"

    /// Kind 8: ProposerPreferences SSZ, 76 bytes.
    let proposerPreferences
        (dependentRoot: Root)
        (proposalSlot: Slot)
        (validatorIndex: uint64)
        (feeRecipient: byte[])
        (targetGasLimit: uint64)
        =
        if feeRecipient.Length <> 20 then
            invalidArg "feeRecipient" "20 bytes"

        let p = ResizeArray<byte>(76)
        p.AddRange dependentRoot.Bytes
        le64 p proposalSlot
        le64 p validatorIndex
        p.AddRange feeRecipient
        le64 p targetGasLimit
        p.ToArray()

    /// Kind 14: BuilderRequestAuth SSZ (offset 12, slot, data), at most 4096 data bytes. The runner
    /// computes the domain itself (genesis fork version) and signs only data on its allowlist.
    let builderRequestAuth (data: byte[]) (slot: Slot) =
        if data.Length > 4096 then
            invalidArg "data" "at most 4096 bytes"

        let p = ResizeArray<byte>(12 + data.Length)
        let off = Array.zeroCreate<byte> 4
        BinaryPrimitives.WriteUInt32LittleEndian(off.AsSpan(), 12u)
        p.AddRange off
        le64 p slot
        p.AddRange data
        p.ToArray()

    /// A SIGN payload of one of these kinds: key, kind, domain, message.
    let sign (key: PubKey) (kind: byte) (domain: Domain) (message: byte[]) =
        Array.concat [ key.Bytes; [| kind |]; domain.Bytes; message ]

/// The SIGN kind a duty goes as.
let kindOf (duty: Duty) =
    match duty with
    | Duty.Attestation _ -> Kind.Attestation
    | Duty.Block _ -> Kind.Block
    | Duty.VoluntaryExit _ -> Kind.VoluntaryExit
    | Duty.RandaoReveal _ -> Kind.Root
    | Duty.AggregateAndProof _ -> Kind.AggregateAndProof
    | Duty.ContributionAndProof _ -> Kind.ContributionAndProof
    | Duty.AggregationSlot _ -> Kind.SelectionProof
    | Duty.SyncCommitteeMessage _ -> Kind.SyncCommitteeMessage
    | Duty.SyncSelectionProof _ -> Kind.SyncSelectionProof
    | Duty.PayloadAttestation _ -> Kind.PayloadAttestation
    | Duty.PayloadEnvelope _ -> Kind.PayloadEnvelope
    | Duty.ProposerPreferences _ -> Kind.ProposerPreferences
    | Duty.BuilderRequestAuth _ -> Kind.BuilderRequestAuth
    | Duty.ValidatorRegistration _ -> Kind.ValidatorRegistration

/// The SIGN payload for a request: key, kind, then for RANDAO (a root message) its type, epoch,
/// object root and domain, and for every other kind the VC's domain and the message. The
/// runner recomputes the domain from its own fork schedule and refuses a request whose domain
/// differs (DOMAIN_MISMATCH), so a signer that missed a fork update signs nothing.
let encodeSign (req: SignRequest) : byte[] =
    let p = ResizeArray<byte>(48 + 1 + 32 + 160)
    p.AddRange req.Key.Bytes
    p.Add(kindOf req.Duty)

    match req.Duty with
    | Duty.RandaoReveal e ->
        p.Add RootRandaoReveal
        be64 p e
        p.AddRange (Codec.hashEpoch e).Bytes
        p.AddRange req.Domain.Bytes
    | duty ->
        p.AddRange req.Domain.Bytes

        match duty with
        | Duty.Attestation d -> p.AddRange(Ssz.serialize Schemas.attestationData (Codec.attestationDataValue d))
        | Duty.Block h -> p.AddRange(Ssz.serialize Schemas.beaconBlockHeader (Codec.beaconBlockHeaderValue h))
        | Duty.VoluntaryExit x -> p.AddRange(Ssz.serialize Schemas.voluntaryExit (Codec.voluntaryExitValue x))
        | Duty.AggregateAndProof(_, m) ->
            p.Add(aggregateForm m.Schema)
            p.AddRange(Ssz.serialize m.Schema m.Value)
        | Duty.ContributionAndProof(_, m) -> p.AddRange(Ssz.serialize m.Schema m.Value)
        | Duty.AggregationSlot s -> le64 p s
        | Duty.SyncCommitteeMessage(s, root) ->
            le64 p s
            p.AddRange root.Bytes
        | Duty.SyncSelectionProof d ->
            le64 p d.Slot
            le64 p d.SubcommitteeIndex
        | Duty.PayloadAttestation d ->
            p.AddRange(Gloas.payloadAttestation d.BeaconBlockRoot d.Slot d.PayloadPresent d.BlobDataAvailable)
        | Duty.PayloadEnvelope(_, m) -> p.AddRange(Gloas.payloadEnvelope m.Schema m.Value)
        | Duty.ProposerPreferences x ->
            p.AddRange(
                Gloas.proposerPreferences
                    x.DependentRoot
                    x.ProposalSlot
                    x.ValidatorIndex
                    x.FeeRecipient
                    x.TargetGasLimit
            )
        | Duty.BuilderRequestAuth a -> p.AddRange(Gloas.builderRequestAuth a.AuthData a.AuthSlot)
        // Kind 4: ValidatorRegistrationV1 SSZ, 84 bytes (sc_sign_validator_registration).
        | Duty.ValidatorRegistration r ->
            p.AddRange(Ssz.serialize Schemas.validatorRegistration (Codec.validatorRegistrationValue r))
        | Duty.RandaoReveal _ -> ()

    p.ToArray()

/// A signature body: 96 bytes.
let decodeSignature (b: byte[]) : BlsSignature =
    if b.Length <> 96 then
        fail $"signature: want 96 bytes, got {b.Length}"

    BlsSignature.Of b

// ---- PUBLIC_KEYS -----------------------------------------------------------

/// One key a runner holds: the validator key, the key of its share (the validator key itself
/// for a whole key), and the validator index it is bound to (IndexUnknown if none).
type RunnerKey =
    {
        PubKey: PubKey
        SharePubKey: PubKey
        Index: uint64
    }

let IndexUnknown = UInt64.MaxValue

/// Keys body: count:u32, then pubkey[48] share_pubkey[48] index:u64 per key.
let decodeKeys (b: byte[]) : RunnerKey list =
    if b.Length < 4 then
        fail "short key list"

    let n = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan(b, 0, 4))

    if int64 b.Length <> 4L + int64 n * 104L then
        fail "key list length mismatch"

    [
        for i in 0 .. int n - 1 ->
            let o = 4 + i * 104

            {
                PubKey = PubKey.Of b[o .. o + 47]
                SharePubKey = PubKey.Of b[o + 48 .. o + 95]
                Index = BinaryPrimitives.ReadUInt64BigEndian(ReadOnlySpan(b, o + 96, 8))
            }
    ]

let encodeKeys (keys: RunnerKey list) : byte[] =
    let p = ResizeArray<byte>()
    let n = Array.zeroCreate<byte> 4
    BinaryPrimitives.WriteUInt32BigEndian(n.AsSpan(), uint32 keys.Length)
    p.AddRange n

    for k in keys do
        p.AddRange k.PubKey.Bytes
        p.AddRange k.SharePubKey.Bytes
        be64 p k.Index

    p.ToArray()

// ---- HEALTH ----------------------------------------------------------------

/// The tee-signer protocol level this VC needs: level 2 refuses at or below a floor with FLOOR
/// (1008) or FLOOR_UNPROVEN (1009), so every slashing code is a real conflict. Level 1 runners
/// send a slashing code with the floor in the detail, which this VC would read as a conflict.
[<Literal>]
let ProtocolLevel = 2

/// The fields of HEALTH (JSON) the VC reads. The rest is for operators.
type RunnerHealth =
    {
        Platform: string
        Version: string
        /// The runner's protocol level: `protocol`, or 1 when it is missing, below 1 or not a
        /// whole number (runners before level 2 do not send it).
        Protocol: int
        Ready: bool
        Validators: int
        ClockTrusted: bool
        RestartMode: string
        /// Every top-level field: a string as its value, true and false as "true" and "false", a
        /// number or anything else as its JSON text; the fields of an object also as "name.field"
        /// (image.state). Null fields are left out. The state table
        /// (TeeBackend HealthStates) reads the refusal fields from here.
        Fields: Map<string, string>
    }

let decodeHealth (b: byte[]) : RunnerHealth =
    use doc = JsonDocument.Parse(ReadOnlyMemory b)
    let e = doc.RootElement

    let str (n: string) =
        match e.TryGetProperty n with
        | true, v when v.ValueKind = JsonValueKind.String -> (nonNull (v.GetString()))
        | _ -> ""

    let boolean (n: string) =
        match e.TryGetProperty n with
        | true, v when v.ValueKind = JsonValueKind.True -> true
        | _ -> false

    {
        Platform = str "platform"
        Version = str "version"
        Protocol =
            match e.TryGetProperty "protocol" with
            | true, v when v.ValueKind = JsonValueKind.Number ->
                match v.TryGetInt64() with
                | true, n when n >= 1L -> int (min n (int64 Int32.MaxValue))
                | _ -> 1
            | _ -> 1
        Ready = boolean "ready"
        Validators =
            match e.TryGetProperty "validators" with
            | true, v when v.ValueKind = JsonValueKind.Number -> v.GetInt32()
            | _ -> 0
        ClockTrusted = boolean "clock_trusted"
        RestartMode = str "restart_mode"
        Fields =
            if e.ValueKind <> JsonValueKind.Object then
                Map.empty
            else
                let value (name: string) (v: JsonElement) =
                    [
                        match v.ValueKind with
                        | JsonValueKind.Null -> ()
                        | JsonValueKind.String -> name, nonNull (v.GetString())
                        | JsonValueKind.True -> name, "true"
                        | JsonValueKind.False -> name, "false"
                        | _ -> name, v.GetRawText()
                    ]

                Map.ofList
                    [
                        for p in e.EnumerateObject() do
                            yield! value p.Name p.Value
                            // One level of an object as well: image.state, image.why.
                            if p.Value.ValueKind = JsonValueKind.Object then
                                for q in p.Value.EnumerateObject() do
                                    yield! value $"{p.Name}.{q.Name}" q.Value
                    ]
    }

// ---- IDENTITY v1 (tee-signer) -----------------------------------------------

/// The version byte of an IDENTITY request and answer (wire.IdentityVersion). A runner answers
/// only this version and refuses another with UNSUPPORTED.
let IdentityVersion = 1uy

/// The context of the user data hash (backend.IdentityContext).
let IdentityContext = "signer-runner-identity-v1"

/// The highest order kind a setup state may carry (backend.ParseSetupState).
let private MaxOrderKind = 1uy

type PendingUpdate =
    {
        Version: uint64
        Hash: Root
        EffectiveAt: uint64
    }

type ConfigGroup =
    {
        Version: uint64
        Hash: Root
        Pending: PendingUpdate
    }

type Order =
    {
        Kind: byte
        Hash: Root
        ActAt: uint64
    }

type KeyOrigin =
    {
        Generated: uint32
        Imported: uint32
        OrdersHash: Root
    }

/// A runner's setup and config state (backend.SetupState). Under tee-signer KeyOrigin.Generated
/// and KeyOrigin.OrdersHash are reserved bytes, always zero.
type SetupState =
    {
        SetupHash: Root
        Locked: ConfigGroup
        Open: ConfigGroup
        ApproverSetHash: Root
        Order: Order
        KeyReleaseHash: Root
        KeyOrigin: KeyOrigin
    }

    /// A runner without a setup: setup_hash (the hash of its -config file) and every other
    /// field zero, the key origin included (runnerclient.FlagPath).
    member this.FlagPath =
        let zg =
            {
                Version = 0UL
                Hash = Root.Zero
                Pending =
                    {
                        Version = 0UL
                        Hash = Root.Zero
                        EffectiveAt = 0UL
                    }
            }

        this.Locked = zg
        && this.Open = zg
        && this.ApproverSetHash = Root.Zero
        && this.Order =
            {
                Kind = 0uy
                Hash = Root.Zero
                ActAt = 0UL
            }
        && this.KeyReleaseHash = Root.Zero
        && this.KeyOrigin =
            {
                Generated = 0u
                Imported = 0u
                OrdersHash = Root.Zero
            }

let SetupStateLen = 32 + 2 * (8 + 32 + 8 + 32 + 8) + 32 + (1 + 32 + 8) + 32 + (4 + 4 + 32)

let appendSetupState (out: ResizeArray<byte>) (s: SetupState) =
    let u32 (v: uint32) =
        let b = Array.zeroCreate<byte> 4
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(), v)
        out.AddRange b

    out.AddRange s.SetupHash.Bytes

    for g in [ s.Locked; s.Open ] do
        be64 out g.Version
        out.AddRange g.Hash.Bytes
        be64 out g.Pending.Version
        out.AddRange g.Pending.Hash.Bytes
        be64 out g.Pending.EffectiveAt

    out.AddRange s.ApproverSetHash.Bytes
    out.Add s.Order.Kind
    out.AddRange s.Order.Hash.Bytes
    be64 out s.Order.ActAt
    out.AddRange s.KeyReleaseHash.Bytes
    u32 s.KeyOrigin.Generated
    u32 s.KeyOrigin.Imported
    out.AddRange s.KeyOrigin.OrdersHash.Bytes

/// Reads exactly SetupStateLen bytes, with the runner's rules (backend.ParseSetupState): a
/// pending update is empty or above the active version, the reserved bytes are zero, an order is
/// of kind 0 or 1 and kind 0 carries nothing.
let parseSetupState (b: byte[]) : SetupState =
    if b.Length <> SetupStateLen then
        fail $"setup state: {b.Length} bytes, want {SetupStateLen}"

    let mutable at = 0

    let take n =
        let v = b[at .. at + n - 1]
        at <- at + n
        v

    let u64 () = BinaryPrimitives.ReadUInt64BigEndian(ReadOnlySpan(take 8))
    let u32 () = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan(take 4))
    let root () = Root.Of(take 32)
    let setupHash = root ()

    let group () =
        let v = u64 ()
        let h = root ()
        let pv = u64 ()
        let ph = root ()
        let pe = u64 ()

        if (pv = 0UL && (ph <> Root.Zero || pe <> 0UL)) || (pv <> 0UL && pv <= v) then
            fail "setup state: a pending update that is neither empty nor above the active version"

        {
            Version = v
            Hash = h
            Pending =
                {
                    Version = pv
                    Hash = ph
                    EffectiveAt = pe
                }
        }

    let locked = group ()
    let opn = group ()
    let approvers = root ()
    let kind = (take 1).[0]
    let orderHash = root ()
    let actAt = u64 ()
    let keyRelease = root ()
    let generated = u32 ()
    let imported = u32 ()
    let orders = root ()

    if generated <> 0u || orders <> Root.Zero then
        fail "setup state: reserved bytes are not zero"

    if kind > MaxOrderKind || (kind = 0uy && (orderHash <> Root.Zero || actAt <> 0UL)) then
        fail $"setup state: order of kind {kind}"

    {
        SetupHash = setupHash
        Locked = locked
        Open = opn
        ApproverSetHash = approvers
        Order =
            {
                Kind = kind
                Hash = orderHash
                ActAt = actAt
            }
        KeyReleaseHash = keyRelease
        KeyOrigin =
            {
                Generated = generated
                Imported = imported
                OrdersHash = orders
            }
    }

/// A platform attestation document and what the runner bound into it.
type Attestation =
    {
        Platform: string
        Format: string
        UserData: byte[]
        Document: byte[]
    }

/// What a runner proves about one boot (backend.Identity).
type Identity =
    {
        State: SetupState
        ImportKem: uint16
        ImportKdf: uint16
        ImportAead: uint16
        ImportKey: byte[]
        /// sha256 of the DER SubjectPublicKeyInfo of the runner's TLS certificate.
        TlsKeyHash: byte[]
        Attestation: Attestation
    }

/// The IDENTITY (and ATTEST) request: nonce_len:u16 nonce version:u8.
let encodeIdentityRequest (nonce: byte[]) : byte[] =
    if nonce.Length > MaxNonce then
        fail $"nonce longer than {MaxNonce} bytes"

    let p = Array.zeroCreate<byte>(2 + nonce.Length + 1)
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(0, 2), uint16 nonce.Length)
    nonce.CopyTo(p, 2)
    p[p.Length - 1] <- IdentityVersion
    p

/// Attestation body: platform_len:u8 platform format_len:u8 format user_data_len:u16 user_data
/// doc_len:u32 document, and nothing after it.
let decodeAttestation (b: byte[]) : Attestation =
    let mutable at = 0

    let take n =
        if n < 0 || n > b.Length - at then
            fail "malformed attestation"

        let v = b[at .. at + n - 1]
        at <- at + n
        v

    let pl = (take 1).[0]
    let platform = Encoding.UTF8.GetString(take (int pl))
    let fl = (take 1).[0]
    let format = Encoding.UTF8.GetString(take (int fl))
    let ud = take (int (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(take 2))))
    let docLen = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan(take 4))

    if docLen > uint32 Int32.MaxValue then
        fail "malformed attestation"

    let doc = take (int docLen)

    if at <> b.Length then
        fail "malformed attestation"

    {
        Platform = platform
        Format = format
        UserData = ud
        Document = doc
    }

let encodeAttestation (a: Attestation) : byte[] =
    let p = ResizeArray<byte>()
    let pb = Encoding.UTF8.GetBytes a.Platform
    let fb = Encoding.UTF8.GetBytes a.Format
    p.Add(byte pb.Length)
    p.AddRange pb
    p.Add(byte fb.Length)
    p.AddRange fb
    let l = Array.zeroCreate<byte> 4
    BinaryPrimitives.WriteUInt16BigEndian(l.AsSpan(0, 2), uint16 a.UserData.Length)
    p.AddRange l[0..1]
    p.AddRange a.UserData
    BinaryPrimitives.WriteUInt32BigEndian(l.AsSpan(), uint32 a.Document.Length)
    p.AddRange l
    p.AddRange a.Document
    p.ToArray()

/// An IDENTITY answer: version:u8 setup_state kem:u16 kdf:u16 aead:u16 import_key_len:u16
/// import_key tls_key_hash_len:u8 tls_key_hash attestation. Any other version is refused, so
/// nothing falls back to another form.
let decodeIdentity (b: byte[]) : Identity =
    if b.Length < 1 then
        fail "empty identity"

    if b[0] <> IdentityVersion then
        fail $"the runner answered IDENTITY v{b[0]}, want v{IdentityVersion} (tee-signer)"

    let s = ReadOnlySpan(b, 1, b.Length - 1)

    if s.Length < SetupStateLen + 8 then
        fail "malformed identity"

    let state = parseSetupState (s.Slice(0, SetupStateLen).ToArray())
    let r = s.Slice SetupStateLen
    let n = int (BinaryPrimitives.ReadUInt16BigEndian(r.Slice(6, 2)))
    let rest = r.Slice 8

    if n > rest.Length || n > MaxImportKey then
        fail "malformed identity"

    let importKey = rest.Slice(0, n).ToArray()
    let rest = rest.Slice n

    if rest.Length < 1 || int rest[0] > rest.Length - 1 then
        fail "malformed identity"

    let h = int rest[0]

    {
        State = state
        ImportKem = BinaryPrimitives.ReadUInt16BigEndian(r.Slice(0, 2))
        ImportKdf = BinaryPrimitives.ReadUInt16BigEndian(r.Slice(2, 2))
        ImportAead = BinaryPrimitives.ReadUInt16BigEndian(r.Slice(4, 2))
        ImportKey = importKey
        TlsKeyHash = rest.Slice(1, h).ToArray()
        Attestation = decodeAttestation (rest.Slice(1 + h).ToArray())
    }

let encodeIdentity (id: Identity) : byte[] =
    let p = ResizeArray<byte>()
    p.Add IdentityVersion
    appendSetupState p id.State

    let u16 (v: uint16) =
        let b = Array.zeroCreate<byte> 2
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(), v)
        p.AddRange b

    u16 id.ImportKem
    u16 id.ImportKdf
    u16 id.ImportAead
    u16 (uint16 id.ImportKey.Length)
    p.AddRange id.ImportKey
    p.Add(byte id.TlsKeyHash.Length)
    p.AddRange id.TlsKeyHash
    p.AddRange(encodeAttestation id.Attestation)
    p.ToArray()

/// What a runner binds into the platform document of an IDENTITY answer: SHA-256 over the
/// context and the nonce (each length-prefixed), the setup state, the import key's suite and
/// bytes and the TLS key hash (backend.IdentityUserData).
let identityUserData (nonce: byte[]) (id: Identity) : byte[] =
    let p = ResizeArray<byte>()

    let u16 (v: int) =
        let b = Array.zeroCreate<byte> 2
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(), uint16 v)
        p.AddRange b

    let ctx = Encoding.ASCII.GetBytes IdentityContext
    u16 ctx.Length
    p.AddRange ctx
    u16 nonce.Length
    p.AddRange nonce
    appendSetupState p id.State
    u16 (int id.ImportKem)
    u16 (int id.ImportKdf)
    u16 (int id.ImportAead)
    u16 id.ImportKey.Length
    p.AddRange id.ImportKey
    u16 id.TlsKeyHash.Length
    p.AddRange id.TlsKeyHash
    SHA256.HashData(p.ToArray())

/// The runtime data an Azure runner sends to MAA for its user data, byte for byte
/// (backend.MAARuntimeData): MAA hashes it into the SNP report data.
let maaRuntimeData (userData: byte[]) =
    Encoding.ASCII.GetBytes("{\"signer-runner-identity\":\"" + Convert.ToHexStringLower userData + "\"}")
