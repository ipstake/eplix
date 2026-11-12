/// Dirk's API messages (wealdtech/eth2-signer-api v1.7.2, package v1), the subset Eplix uses.
/// Field numbers come from the protobuf descriptors embedded in the Dirk 1.2.1 binary, read with
/// scripts/dirk-protos.py. eth2-signer-api has no licence file, so the repository carries no copy
/// of its .proto files.
module Eplix.Backend.Dirk.Messages

open System
open Eplix
open Eplix.Backend.Dirk.Protobuf

[<RequireQualifiedAccess>]
type ResponseState =
    | Unknown
    | Succeeded
    | Denied
    | Failed

    /// Written out: the compiler's union ToString fails under NativeAOT (see DutyKind).
    override this.ToString() =
        match this with
        | Unknown -> "Unknown"
        | Succeeded -> "Succeeded"
        | Denied -> "Denied"
        | Failed -> "Failed"

let private state (v: uint64) =
    match v with
    | 1UL -> ResponseState.Succeeded
    | 2UL -> ResponseState.Denied
    | 3UL -> ResponseState.Failed
    | _ -> ResponseState.Unknown

/// endpoint.proto Endpoint: a participant of a distributed account.
type Endpoint =
    {
        Id: uint64
        Name: string
        Port: uint32
    }

/// lister.proto Account.
type Account = { Name: string; PublicKey: byte[] }

/// lister.proto DistributedAccount. PublicKey is this instance's share; CompositePublicKey the
/// validator key.
type DistributedAccount =
    {
        Name: string
        PublicKey: byte[]
        Participants: Endpoint list
        SigningThreshold: uint32
        CompositePublicKey: byte[]
    }

type ListAccountsResponse =
    {
        State: ResponseState
        Accounts: Account list
        DistributedAccounts: DistributedAccount list
    }

type SignResponse =
    {
        State: ResponseState
        Signature: byte[]
    }

/// How a request names its account (the `id` oneof).
[<RequireQualifiedAccess>]
type AccountId =
    | PublicKey of byte[]
    | Name of string

let private writeId (w: Writer) (id: AccountId) =
    match id with
    | AccountId.PublicKey pk -> w.Bytes(1, ReadOnlySpan pk)
    | AccountId.Name n -> w.String(2, n)

/// ListAccountsRequest { repeated string paths = 1 }
let listAccountsRequest (paths: string list) =
    encode (fun w ->
        for p in paths do
            w.String(1, p))

let private endpoint (b: ReadOnlyMemory<byte>) : Endpoint =
    let mutable e = { Id = 0UL; Name = ""; Port = 0u }

    for f in fields b do
        match f.Number with
        | 1 -> e <- { e with Id = asVarint f }
        | 2 -> e <- { e with Name = asString f }
        | 3 -> e <- { e with Port = uint32 (asVarint f) }
        | _ -> ()

    e

let private account (b: ReadOnlyMemory<byte>) : Account =
    let mutable a = { Account.Name = ""; PublicKey = [||] }

    for f in fields b do
        match f.Number with
        | 1 -> a <- { a with Name = asString f }
        | 2 -> a <- { a with PublicKey = asBytes f }
        | _ -> ()

    a

let private distributedAccount (b: ReadOnlyMemory<byte>) : DistributedAccount =
    let mutable a =
        {
            DistributedAccount.Name = ""
            PublicKey = [||]
            Participants = []
            SigningThreshold = 0u
            CompositePublicKey = [||]
        }

    let participants = ResizeArray<Endpoint>()

    for f in fields b do
        match f.Number with
        | 1 -> a <- { a with Name = asString f }
        | 2 -> a <- { a with PublicKey = asBytes f }
        | 3 -> participants.Add(endpoint f.Bytes)
        | 4 ->
            a <-
                { a with
                    SigningThreshold = uint32 (asVarint f)
                }
        | 6 ->
            a <-
                { a with
                    CompositePublicKey = asBytes f
                }
        | _ -> ()

    { a with
        Participants = List.ofSeq participants
    }

let decodeListAccountsResponse (b: ReadOnlyMemory<byte>) : ListAccountsResponse =
    let accounts = ResizeArray<Account>()
    let distributed = ResizeArray<DistributedAccount>()
    let mutable st = ResponseState.Unknown

    for f in fields b do
        match f.Number with
        | 1 -> st <- state (asVarint f)
        | 2 -> accounts.Add(account f.Bytes)
        | 3 -> distributed.Add(distributedAccount f.Bytes)
        | _ -> ()

    {
        State = st
        Accounts = List.ofSeq accounts
        DistributedAccounts = List.ofSeq distributed
    }

/// SignRequest { oneof id { bytes public_key = 1; string account = 2; } bytes data = 3; bytes domain = 4; }
let signRequest (id: AccountId) (objectRoot: Root) (domain: Domain) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan objectRoot.Bytes)
        w.Bytes(4, ReadOnlySpan domain.Bytes))

let private checkpoint (c: Checkpoint) =
    encode (fun w ->
        w.UInt64(1, c.Epoch)
        w.Bytes(2, ReadOnlySpan c.Root.Bytes))

let private attestationData (d: AttestationData) =
    encode (fun w ->
        w.UInt64(1, d.Slot)
        w.UInt64(2, d.Index)
        w.Bytes(3, ReadOnlySpan d.BeaconBlockRoot.Bytes)
        w.Message(4, checkpoint d.Source)
        w.Message(5, checkpoint d.Target))

/// SignBeaconAttestationRequest { oneof id {...}; bytes domain = 3; AttestationData data = 4; }
let signBeaconAttestationRequest (id: AccountId) (domain: Domain) (d: AttestationData) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)
        w.Message(4, attestationData d))

/// SignBeaconAttestationsRequest { repeated SignBeaconAttestationRequest requests = 1; }
let signBeaconAttestationsRequest (requests: byte[] seq) =
    encode (fun w ->
        for r in requests do
            w.Message(1, r))

let private blockHeader (h: BeaconBlockHeader) =
    encode (fun w ->
        w.UInt64(1, h.Slot)
        w.UInt64(2, h.ProposerIndex)
        w.Bytes(3, ReadOnlySpan h.ParentRoot.Bytes)
        w.Bytes(4, ReadOnlySpan h.StateRoot.Bytes)
        w.Bytes(5, ReadOnlySpan h.BodyRoot.Bytes))

/// SignBeaconProposalRequest { oneof id {...}; bytes domain = 3; BeaconBlockHeader data = 4; }
let signBeaconProposalRequest (id: AccountId) (domain: Domain) (h: BeaconBlockHeader) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)
        w.Message(4, blockHeader h))

// The typed Gloas calls below exist only in a Dirk build that adds them (field numbers from
// its signer.proto and eth2.proto); stock Dirk answers them UNIMPLEMENTED. That build denies PTC votes,
// envelopes, proposer preferences and builder request auth sent as a generic Sign, unless its
// config names the client.

let private boolField (w: Writer) (field: int) (b: bool) = w.UInt64(field, (if b then 1UL else 0UL))

/// PayloadAttestationData { bytes beacon_block_root = 1; uint64 slot = 2; bool payload_present = 3;
/// bool blob_data_available = 4; }
let private payloadAttestationData (d: PayloadAttestationData) =
    encode (fun w ->
        w.Bytes(1, ReadOnlySpan d.BeaconBlockRoot.Bytes)
        w.UInt64(2, d.Slot)
        boolField w 3 d.PayloadPresent
        boolField w 4 d.BlobDataAvailable)

/// SignPayloadAttestationRequest { oneof id {...}; bytes domain = 3; PayloadAttestationData data = 4; }
let signPayloadAttestationRequest (id: AccountId) (domain: Domain) (d: PayloadAttestationData) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)
        w.Message(4, payloadAttestationData d))

/// ProposerPreferences { bytes dependent_root = 1; uint64 proposal_slot = 2; uint64 validator_index = 3;
/// bytes fee_recipient = 4; uint64 target_gas_limit = 5; }
let private proposerPreferences (p: ProposerPreferences) =
    encode (fun w ->
        w.Bytes(1, ReadOnlySpan p.DependentRoot.Bytes)
        w.UInt64(2, p.ProposalSlot)
        w.UInt64(3, p.ValidatorIndex)
        w.Bytes(4, ReadOnlySpan p.FeeRecipient)
        w.UInt64(5, p.TargetGasLimit))

/// SignProposerPreferencesRequest { oneof id {...}; bytes domain = 3; ProposerPreferences data = 4; }
let signProposerPreferencesRequest (id: AccountId) (domain: Domain) (p: ProposerPreferences) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)
        w.Message(4, proposerPreferences p))

/// SignBuilderRequestAuthRequest { oneof id {...}; bytes domain = 3; BuilderRequestAuth data = 4; }
/// with BuilderRequestAuth { bytes data = 1; uint64 slot = 2; }.
let signBuilderRequestAuthRequest (id: AccountId) (domain: Domain) (a: BuilderRequestAuth) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)

        w.Message(
            4,
            encode (fun x ->
                x.Bytes(1, ReadOnlySpan a.AuthData)
                x.UInt64(2, a.AuthSlot))
        ))

/// The fields of a container value by name, each with its schema.
let private namedFields (what: string) (t: Ssz.SszType) (v: Ssz.SszValue) =
    match t, v with
    | (Ssz.Container fs | Ssz.ProgressiveContainer fs), Ssz.Fields vs when fs.Length = vs.Length ->
        let byName = dict [ for i in 0 .. fs.Length - 1 -> fst fs[i], (snd fs[i], vs[i]) ]

        fun (name: string) ->
            match byName.TryGetValue name with
            | true, x -> x
            | _ -> raise (Ssz.SszError $"{what} has no field {name}")
    | _ -> raise (Ssz.SszError $"{what} is not a container")

let private rawBytes (name: string) (_: Ssz.SszType, v: Ssz.SszValue) =
    match v with
    | Ssz.Bytes b -> b
    | _ -> raise (Ssz.SszError $"{name} is not bytes")

let private number (name: string) (_: Ssz.SszType, v: Ssz.SszValue) =
    match v with
    | Ssz.U x -> x
    | _ -> raise (Ssz.SszError $"{name} is not an integer")

let private fieldRoot (t: Ssz.SszType, v: Ssz.SszValue) = Ssz.hashTreeRoot t v

/// ExecutionPayloadEnvelope of the fork: { ExecutionPayloadSummary payload = 1; bytes
/// execution_requests_root = 2; uint64 builder_index = 3; bytes beacon_block_root = 4; bytes
/// parent_beacon_block_root = 5; }. The summary (fields 1 to 19, in the payload's order) holds the
/// payload's fixed-size fields as values and logs_bloom, extra_data, base_fee_per_gas,
/// transactions, withdrawals and block_access_list as their hash_tree_root, so the fork computes
/// the envelope root without the transactions. Raises SszError for a value of another shape.
let executionPayloadEnvelope (e: SszObject) =
    let field = namedFields "the envelope" e.Schema e.Value
    let p = (field "payload") ||> namedFields "the payload"
    let raw name = rawBytes name (p name)
    let num name = number name (p name)
    let rootOf name = fieldRoot (p name)

    let summary =
        encode (fun w ->
            w.Bytes(1, ReadOnlySpan(raw "parent_hash"))
            w.Bytes(2, ReadOnlySpan(raw "fee_recipient"))
            w.Bytes(3, ReadOnlySpan(raw "state_root"))
            w.Bytes(4, ReadOnlySpan(raw "receipts_root"))
            w.Bytes(5, ReadOnlySpan(rootOf "logs_bloom"))
            w.Bytes(6, ReadOnlySpan(raw "prev_randao"))
            w.UInt64(7, num "block_number")
            w.UInt64(8, num "gas_limit")
            w.UInt64(9, num "gas_used")
            w.UInt64(10, num "timestamp")
            w.Bytes(11, ReadOnlySpan(rootOf "extra_data"))
            w.Bytes(12, ReadOnlySpan(rootOf "base_fee_per_gas"))
            w.Bytes(13, ReadOnlySpan(raw "block_hash"))
            w.Bytes(14, ReadOnlySpan(rootOf "transactions"))
            w.Bytes(15, ReadOnlySpan(rootOf "withdrawals"))
            w.UInt64(16, num "blob_gas_used")
            w.UInt64(17, num "excess_blob_gas")
            w.Bytes(18, ReadOnlySpan(rootOf "block_access_list"))
            w.UInt64(19, num "slot_number"))

    encode (fun w ->
        w.Message(1, summary)
        w.Bytes(2, ReadOnlySpan(fieldRoot (field "execution_requests")))
        w.UInt64(3, number "builder_index" (field "builder_index"))
        w.Bytes(4, ReadOnlySpan(rawBytes "beacon_block_root" (field "beacon_block_root")))
        w.Bytes(5, ReadOnlySpan(rawBytes "parent_beacon_block_root" (field "parent_beacon_block_root"))))

/// SignExecutionPayloadEnvelopeRequest { oneof id {...}; bytes domain = 3; ExecutionPayloadEnvelope data = 4; }
let signExecutionPayloadEnvelopeRequest (id: AccountId) (domain: Domain) (e: SszObject) =
    encode (fun w ->
        writeId w id
        w.Bytes(3, ReadOnlySpan domain.Bytes)
        w.Message(4, executionPayloadEnvelope e))

let decodeSignResponse (b: ReadOnlyMemory<byte>) : SignResponse =
    let mutable r =
        {
            State = ResponseState.Unknown
            Signature = [||]
        }

    for f in fields b do
        match f.Number with
        | 1 -> r <- { r with State = state (asVarint f) }
        | 2 -> r <- { r with Signature = asBytes f }
        | _ -> ()

    r

/// MultisignResponse { repeated SignResponse responses = 1; }
let decodeMultisignResponse (b: ReadOnlyMemory<byte>) : SignResponse list =
    [
        for f in fields b do
            if f.Number = 1 then
                decodeSignResponse f.Bytes
    ]
