/// The pure parts of the validator monitor: blocks, committees, rewards and balances read from
/// Beacon API JSON, and the aggregation bits of an attestation matched to a duty.
module Eplix.Monitor.Chain

open System
open System.Collections.Generic
open System.Globalization
open System.Text.Json
open Eplix
open Eplix.Json

/// The bits of an SSZ bitlist in hex. The highest set bit marks the length and is not a bit of
/// the list, so the last byte cannot be zero. ProgressiveBitlist (Gloas) has the same form.
let bitlist (hex: string) : bool[] voption =
    match Hex.tryDecode hex with
    | ValueSome b when b.Length > 0 && b[b.Length - 1] <> 0uy ->
        let last = b[b.Length - 1]
        let mutable top = 7

        while (last >>> top) &&& 1uy = 0uy do
            top <- top - 1

        let length = (b.Length - 1) * 8 + top
        ValueSome(Array.init length (fun i -> (b[i / 8] >>> (i % 8)) &&& 1uy = 1uy))
    | _ -> ValueNone

/// The bits of an SSZ bitvector of `size` bits in hex. Refuses the wrong byte count.
let bitvector (size: int) (hex: string) : bool[] voption =
    match Hex.tryDecode hex with
    | ValueSome b when b.Length = (size + 7) / 8 ->
        ValueSome(Array.init size (fun i -> (b[i / 8] >>> (i % 8)) &&& 1uy = 1uy))
    | _ -> ValueNone

/// One attestation of a block: the slot it votes for, the committees it covers (ascending) and
/// its aggregation bits.
type BlockAttestation =
    {
        Slot: Slot
        Committees: uint64[]
        Bits: bool[]
    }

type BlockSummary =
    {
        Slot: Slot
        ProposerIndex: ValidatorIndex
        Attestations: BlockAttestation[]
        /// The bits of the sync aggregate (Altair and later): the messages of the slot before.
        SyncBits: bool[] voption
    }

[<RequireQualifiedAccess>]
type BlockRead =
    | Block of BlockSummary
    /// A block format this code does not know (a later fork, or a field missing). Skipped.
    | Unknown of string

/// Forks whose attestations name their committee in data.index.
let private beforeElectra = set [ "phase0"; "altair"; "bellatrix"; "capella"; "deneb" ]

/// Forks whose attestations carry committee_bits; the aggregation bits run over those committees.
let private fromElectra = set [ "electra"; "fulu"; "gloas" ]

/// The monitor reads its two large answers, blocks and committees, with a Utf8JsonReader in one
/// pass over the bytes: no document, no element array per committee.
let private readerOptions = JsonReaderOptions(MaxDepth = 64)

/// A scalar as read, checked when it is used, so the checks run in the same order as with a
/// parsed document whatever the order of the fields.
[<RequireQualifiedAccess; Struct>]
type private Raw =
    | Missing
    | Null
    | Str of s: string
    | Num of n: uint64 voption
    | Other

let private next (r: byref<Utf8JsonReader>) =
    if not (r.Read()) then
        fail "unexpected end of the JSON"

/// The value at the reader as a Raw; a container is skipped.
let private raw (r: byref<Utf8JsonReader>) : Raw =
    match r.TokenType with
    | JsonTokenType.String ->
        match r.GetString() with
        | null -> Raw.Null
        | s -> Raw.Str s
    | JsonTokenType.Number ->
        match r.TryGetUInt64() with
        | true, v -> Raw.Num(ValueSome v)
        | _ -> Raw.Num ValueNone
    | JsonTokenType.Null -> Raw.Null
    | _ ->
        r.Skip()
        Raw.Other

let private rawStr (name: string) (v: Raw) : string =
    match v with
    | Raw.Missing -> fail $"missing field '{name}'"
    | Raw.Str s -> s
    | _ -> fail "expected a string"

/// As Json.u64Field: a decimal string or a JSON number.
let private rawU64 (name: string) (v: Raw) : uint64 =
    match v with
    | Raw.Missing -> fail $"missing field '{name}'"
    | Raw.Str s ->
        match UInt64.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture) with
        | true, x -> x
        | _ -> fail "expected a decimal uint64 string"
    | Raw.Num(ValueSome x) -> x
    | _ -> fail "expected a uint64"

/// At a property value: fails unless it is an object (as Json.prop on what it holds).
let private objectAt (r: byref<Utf8JsonReader>) (around: string) =
    if r.TokenType <> JsonTokenType.StartObject then
        fail $"expected an object around '{around}'"

/// At a property name: skips its value.
let private skipValue (r: byref<Utf8JsonReader>) =
    next &r
    r.Skip()

/// The whole input is one well-formed JSON value, as JsonDocument.Parse requires; else a JsonException.
let private wellFormed (json: ReadOnlySpan<byte>) =
    let mutable r = Utf8JsonReader(json, readerOptions)
    let mutable tokens = 0

    while r.Read() do
        tokens <- tokens + 1

    if tokens = 0 then
        raise (JsonException "no JSON value")

type private RawAttestation =
    {
        Bits: Raw
        CommitteeBits: Raw
        Slot: Raw
        Index: Raw
    }

/// The fields of a block the monitor reads, gathered in one pass.
type private BlockParts() =
    member val Version = Raw.Missing with get, set
    member val Data = false with get, set
    member val Message = false with get, set
    member val Body = false with get, set
    member val Slot = Raw.Missing with get, set
    member val Proposer = Raw.Missing with get, set
    member val Attestations: ResizeArray<RawAttestation> voption = ValueNone with get, set
    member val Sync = false with get, set
    member val SyncBits = Raw.Missing with get, set

let private attestationOf (r: byref<Utf8JsonReader>) : RawAttestation =
    objectAt &r "data"
    let mutable bits = Raw.Missing
    let mutable committeeBits = Raw.Missing
    let mutable slot = Raw.Missing
    let mutable index = Raw.Missing
    let mutable data = false
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "aggregation_bits"B then
            next &r
            bits <- raw &r
        elif r.ValueTextEquals "committee_bits"B then
            next &r
            committeeBits <- raw &r
        elif r.ValueTextEquals "data"B then
            next &r
            objectAt &r "slot"
            data <- true
            next &r

            while r.TokenType <> JsonTokenType.EndObject do
                if r.ValueTextEquals "slot"B then
                    next &r
                    slot <- raw &r
                elif r.ValueTextEquals "index"B then
                    next &r
                    index <- raw &r
                else
                    skipValue &r

                next &r
        else
            skipValue &r

        next &r

    if not data then
        fail "missing field 'data'"

    {
        Bits = bits
        CommitteeBits = committeeBits
        Slot = slot
        Index = index
    }

let private bodyOf (r: byref<Utf8JsonReader>) (p: BlockParts) =
    objectAt &r "attestations"
    p.Body <- true
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "attestations"B then
            next &r

            if r.TokenType <> JsonTokenType.StartArray then
                fail "expected an array"

            let list = ResizeArray()
            next &r

            while r.TokenType <> JsonTokenType.EndArray do
                list.Add(attestationOf &r)
                next &r

            p.Attestations <- ValueSome list
        elif r.ValueTextEquals "sync_aggregate"B then
            next &r

            if r.TokenType = JsonTokenType.Null then
                p.Sync <- false
            else
                objectAt &r "sync_committee_bits"
                p.Sync <- true
                p.SyncBits <- Raw.Missing
                next &r

                while r.TokenType <> JsonTokenType.EndObject do
                    if r.ValueTextEquals "sync_committee_bits"B then
                        next &r
                        p.SyncBits <- raw &r
                    else
                        skipValue &r

                    next &r
        else
            skipValue &r

        next &r

let private messageOf (r: byref<Utf8JsonReader>) (p: BlockParts) =
    objectAt &r "body"
    p.Message <- true
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "slot"B then
            next &r
            p.Slot <- raw &r
        elif r.ValueTextEquals "proposer_index"B then
            next &r
            p.Proposer <- raw &r
        elif r.ValueTextEquals "body"B then
            next &r
            bodyOf &r p
        else
            skipValue &r

        next &r

let private blockParts (json: ReadOnlySpan<byte>) : BlockParts =
    let p = BlockParts()
    let mutable r = Utf8JsonReader(json, readerOptions)
    next &r
    objectAt &r "version"
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "version"B then
            next &r
            p.Version <- raw &r
        elif r.ValueTextEquals "data"B then
            next &r
            objectAt &r "message"
            p.Data <- true
            next &r

            while r.TokenType <> JsonTokenType.EndObject do
                if r.ValueTextEquals "message"B then
                    next &r
                    messageOf &r p
                else
                    skipValue &r

                next &r
        else
            skipValue &r

        next &r

    p

/// Reads GET /eth/v2/beacon/blocks/{id} in JSON: slot, proposer, the attestations and the sync
/// aggregate. Malformed JSON throws, as a parsed document would. Well-formed JSON never throws:
/// anything it cannot read is BlockRead.Unknown, so a new fork does not count as a node error.
let readBlock (preset: Preset) (json: ReadOnlyMemory<byte>) : BlockRead =
    wellFormed json.Span

    try
        let p = blockParts json.Span
        let version = (rawStr "version" p.Version).ToLowerInvariant()

        if not (beforeElectra.Contains version || fromElectra.Contains version) then
            BlockRead.Unknown $"block version '{version}'"
        else
            if not p.Data then
                fail "missing field 'data'"

            if not p.Message then
                fail "missing field 'message'"

            if not p.Body then
                fail "missing field 'body'"

            let attestation (a: RawAttestation) =
                let bits =
                    match bitlist (rawStr "aggregation_bits" a.Bits) with
                    | ValueSome b -> b
                    | ValueNone -> fail "aggregation_bits is not a bitlist"

                let committees =
                    if fromElectra.Contains version then
                        match bitvector preset.MaxCommitteesPerSlot (rawStr "committee_bits" a.CommitteeBits) with
                        | ValueSome c ->
                            [|
                                for i in 0 .. c.Length - 1 do
                                    if c[i] then
                                        uint64 i
                            |]
                        | ValueNone -> fail "committee_bits is not a bitvector"
                    else
                        [| rawU64 "index" a.Index |]

                {
                    Slot = rawU64 "slot" a.Slot
                    Committees = committees
                    Bits = bits
                }

            let sync =
                if p.Sync then
                    match bitvector preset.SyncCommitteeSize (rawStr "sync_committee_bits" p.SyncBits) with
                    | ValueSome b -> ValueSome b
                    | ValueNone -> fail "sync_committee_bits is not a bitvector"
                else
                    ValueNone

            let slot = rawU64 "slot" p.Slot
            let proposer = rawU64 "proposer_index" p.Proposer

            let attestations =
                match p.Attestations with
                | ValueSome list -> list.ToArray() |> Array.map attestation
                | ValueNone -> fail "missing field 'attestations'"

            BlockRead.Block
                {
                    Slot = slot
                    ProposerIndex = proposer
                    Attestations = attestations
                    SyncBits = sync
                }
    with :? JsonDecodeError as x ->
        BlockRead.Unknown x.Message

/// Whether the attester at `position` of `committee` voted in an aggregate. From Electra the
/// aggregation bits run over the committees set in committee_bits, in order, so the bits of a
/// committee start after the sizes of the committees before it. An aggregate of one committee
/// needs no sizes; one of several needs all of them, and they must add up to the bit count.
let voted
    (a: BlockAttestation)
    (sizeOf: uint64 -> int voption)
    (committee: uint64)
    (position: uint64)
    : Result<bool, string> =
    match Array.tryFindIndex ((=) committee) a.Committees with
    | None -> Ok false
    | Some _ when a.Committees.Length = 1 ->
        if position < uint64 a.Bits.Length then
            Ok a.Bits[int position]
        else
            Error $"position {position} past the {a.Bits.Length} aggregation bits"
    | Some k ->
        let sizes = a.Committees |> Array.map sizeOf

        if sizes |> Array.exists ValueOption.isNone then
            Error $"committee sizes of slot {a.Slot} unknown"
        else
            let sizes = sizes |> Array.map ValueOption.get

            if Array.sum sizes <> a.Bits.Length then
                Error
                    $"committee sizes of slot {a.Slot} add up to {Array.sum sizes}, the aggregate has {a.Bits.Length} bits"
            elif position >= uint64 sizes[k] then
                Error $"position {position} past committee {committee} of {sizes[k]}"
            else
                let offset = Array.sum sizes[.. k - 1]
                Ok a.Bits[offset + int position]

/// Slots between the attestation and the block that included it (1 is the best).
let distance (attestationSlot: Slot) (blockSlot: Slot) : uint64 = blockSlot - attestationSlot

/// One committee of the committees answer: (slot, index, size). The validators are counted,
/// not kept.
let private committeeOf (r: byref<Utf8JsonReader>) : Slot * uint64 * int =
    objectAt &r "slot"
    let mutable slot = Raw.Missing
    let mutable index = Raw.Missing
    let mutable size = -1
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "slot"B then
            next &r
            slot <- raw &r
        elif r.ValueTextEquals "index"B then
            next &r
            index <- raw &r
        elif r.ValueTextEquals "validators"B then
            next &r

            if r.TokenType <> JsonTokenType.StartArray then
                fail "expected an array"

            let mutable n = 0
            next &r

            while r.TokenType <> JsonTokenType.EndArray do
                r.Skip()
                n <- n + 1
                next &r

            size <- n
        else
            skipValue &r

        next &r

    let slot = rawU64 "slot" slot
    let index = rawU64 "index" index

    if size < 0 then
        fail "missing field 'validators'"

    slot, index, size

/// Reads GET /eth/v1/beacon/states/{id}/committees: (slot, committee index, size).
let readCommittees (json: ReadOnlyMemory<byte>) : (Slot * uint64 * int)[] =
    let mutable r = Utf8JsonReader(json.Span, readerOptions)
    let committees = ResizeArray()
    let mutable data = false
    next &r
    objectAt &r "data"
    next &r

    while r.TokenType <> JsonTokenType.EndObject do
        if r.ValueTextEquals "data"B then
            next &r

            if r.TokenType <> JsonTokenType.StartArray then
                fail "expected an array"

            data <- true
            committees.Clear()
            next &r

            while r.TokenType <> JsonTokenType.EndArray do
                committees.Add(committeeOf &r)
                next &r
        else
            skipValue &r

        next &r
    // The rest of the input: nothing but whitespace, or a JsonException.
    while r.Read() do
        ()

    if not data then
        fail "missing field 'data'"

    committees.ToArray()

let private i64 (e: JsonElement) : int64 =
    match Int64.TryParse(str e, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
    | true, v -> v
    | _ -> fail "expected a decimal int64 string"

/// The attestation rewards of one validator in Gwei; a penalty is negative.
[<Struct>]
type Reward =
    {
        Head: int64
        Target: int64
        Source: int64
    }

type AttestationRewards =
    {
        /// No head reward in the ideal rewards: an inactivity leak, where a correct head earns 0.
        Leak: bool
        Totals: IReadOnlyDictionary<ValidatorIndex, Reward>
    }

/// Reads POST /eth/v1/beacon/rewards/attestations/{epoch}.
let readRewards (e: JsonElement) : AttestationRewards =
    let data = prop e "data"
    let ideal = array (prop data "ideal_rewards")
    let totals = Dictionary<ValidatorIndex, Reward>()

    for r in array (prop data "total_rewards") do
        totals[u64Field r "validator_index"] <-
            {
                Head = i64 (prop r "head")
                Target = i64 (prop r "target")
                Source = i64 (prop r "source")
            }

    {
        Leak = ideal |> Array.forall (fun r -> i64 (prop r "head") = 0L)
        Totals = totals
    }

/// Whether each vote of an included attestation earned its flag. Source and target cost a penalty
/// when missed (or late) and earn 0 or more when met, also in a leak. Head is never penalised: it
/// earns more than 0 when met, and in a leak nothing tells, so it is ValueNone there.
type Votes =
    {
        Head: bool voption
        Target: bool
        Source: bool
    }

let votes (leak: bool) (r: Reward) : Votes =
    {
        Head = (if leak then ValueNone else ValueSome(r.Head > 0L))
        Target = r.Target >= 0L
        Source = r.Source >= 0L
    }

/// Reads POST /eth/v1/beacon/states/{id}/validator_balances: (index, balance in Gwei).
let readBalances (e: JsonElement) : (ValidatorIndex * uint64)[] =
    array (prop e "data") |> Array.map (fun b -> u64Field b "index", u64Field b "balance")

/// The change of each balance since the last reading, for indices in both.
let balanceDeltas
    (before: IReadOnlyDictionary<ValidatorIndex, uint64>)
    (now: (ValidatorIndex * uint64)[])
    : (ValidatorIndex * int64)[] =
    now
    |> Array.choose (fun (i, b) ->
        match before.TryGetValue i with
        | true, old -> Some(i, int64 b - int64 old)
        | _ -> None)
