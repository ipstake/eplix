/// A small strict CBOR (RFC 8949) reader for AWS Nitro attestation documents, and the one
/// encoder COSE_Sign1 verification needs. The rules follow the decoder options of the Go
/// verifier (attest/nitro.go): no tags, nesting at most 8 levels, no duplicate map keys,
/// UTF-8 checked, nothing after the item, and indefinite lengths only where a caller allows
/// them. System.Formats.Cbor is not in the local package cache, and this needs about 200 lines.
module Eplix.Backend.Tee.Cbor

open System
open System.Buffers.Binary
open System.Text

type CborError(message: string) =
    inherit Exception(message)

let private fail msg = raise (CborError msg)

type Item =
    | UInt of uint64
    /// The value is -1 - n.
    | NegInt of uint64
    | Bytes of byte[]
    | Text of string
    | Array of Item list
    | Map of (Item * Item) list
    | Simple of byte
    | Float of float

type Options =
    { AllowIndefinite: bool; MaxDepth: int }

let strict =
    {
        AllowIndefinite = false
        MaxDepth = 8
    }

let private utf8 = UTF8Encoding(false, true)

type private Reader(data: byte[], opts: Options) =
    let mutable pos = 0

    member _.Pos = pos

    member _.Byte() =
        if pos >= data.Length then
            fail "unexpected end of data"

        let b = data[pos]
        pos <- pos + 1
        b

    member _.Take(n: uint64) =
        if n > uint64 (data.Length - pos) then
            fail "unexpected end of data"

        let v = data[pos .. pos + int n - 1]
        pos <- pos + int n
        v

    /// The argument of a head: the value for additional info 0 to 27, ValueNone for 31.
    member this.Arg(info: byte) : uint64 voption =
        match info with
        | i when i < 24uy -> ValueSome(uint64 i)
        | 24uy -> ValueSome(uint64 (this.Byte()))
        | 25uy -> ValueSome(uint64 (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(this.Take 2UL))))
        | 26uy -> ValueSome(uint64 (BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan(this.Take 4UL))))
        | 27uy -> ValueSome(BinaryPrimitives.ReadUInt64BigEndian(ReadOnlySpan(this.Take 8UL)))
        | 31uy -> ValueNone
        | _ -> fail $"reserved additional information {info}"

    member this.Item(depth: int) : Item =
        let ib = this.Byte()
        let major = ib >>> 5
        let info = ib &&& 0x1fuy

        let nested () =
            if depth + 1 > opts.MaxDepth then
                fail $"nested deeper than {opts.MaxDepth} levels"

        let indefinite () =
            if not opts.AllowIndefinite then
                fail "indefinite length not allowed"

        match major with
        | 0uy ->
            match this.Arg info with
            | ValueSome v -> UInt v
            | ValueNone -> fail "indefinite length on an integer"
        | 1uy ->
            match this.Arg info with
            | ValueSome v -> NegInt v
            | ValueNone -> fail "indefinite length on an integer"
        | 2uy
        | 3uy ->
            let raw =
                match this.Arg info with
                | ValueSome n -> this.Take n
                | ValueNone ->
                    indefinite ()
                    // Chunks of the same major type, each definite, until the break code.
                    let chunks = ResizeArray<byte>()
                    let mutable fin = false

                    while not fin do
                        let b = this.Byte()

                        if b = 0xffuy then
                            fin <- true
                        elif b >>> 5 <> major then
                            fail "indefinite string chunk of another type"
                        else
                            match this.Arg(b &&& 0x1fuy) with
                            | ValueSome n ->
                                let c = this.Take n

                                if major = 3uy then
                                    try
                                        utf8.GetString c |> ignore
                                    with :? DecoderFallbackException ->
                                        fail "invalid UTF-8 in a text string chunk"

                                chunks.AddRange c
                            | ValueNone -> fail "nested indefinite string chunk"

                    chunks.ToArray()

            if major = 2uy then
                Bytes raw
            else
                try
                    Text(utf8.GetString raw)
                with :? DecoderFallbackException ->
                    fail "invalid UTF-8 in a text string"
        | 4uy ->
            nested ()

            match this.Arg info with
            | ValueSome n ->
                if n > uint64 (data.Length - pos) then
                    fail "array longer than the data"

                Array [ for _ in 1UL .. n -> this.Item(depth + 1) ]
            | ValueNone ->
                indefinite ()
                let items = ResizeArray<Item>()

                while this.PeekBreak() |> not do
                    items.Add(this.Item(depth + 1))

                Array(List.ofSeq items)
        | 5uy ->
            nested ()
            let seen = Collections.Generic.HashSet<string>()

            let entry () =
                let k = this.Item(depth + 1)
                let id = this.KeyId k

                if not (seen.Add id) then
                    fail "duplicate map key"

                k, this.Item(depth + 1)

            match this.Arg info with
            | ValueSome n ->
                if n > uint64 (data.Length - pos) then
                    fail "map longer than the data"

                Map [ for _ in 1UL .. n -> entry () ]
            | ValueNone ->
                indefinite ()
                let items = ResizeArray<Item * Item>()

                while this.PeekBreak() |> not do
                    items.Add(entry ())

                Map(List.ofSeq items)
        | 6uy -> fail "CBOR tags are not allowed"
        | _ ->
            match info with
            | i when i < 24uy -> Simple i
            | 24uy ->
                let v = this.Byte()

                if v < 32uy then
                    fail "invalid simple value"

                Simple v
            | 25uy ->
                Float(
                    float (
                        BitConverter.UInt16BitsToHalf(BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(this.Take 2UL)))
                    )
                )
            | 26uy -> Float(float (BinaryPrimitives.ReadSingleBigEndian(ReadOnlySpan(this.Take 4UL))))
            | 27uy -> Float(BinaryPrimitives.ReadDoubleBigEndian(ReadOnlySpan(this.Take 8UL)))
            | 31uy -> fail "unexpected break code"
            | _ -> fail $"reserved additional information {info}"

    /// True and consumed when the next byte is the break code of an indefinite container.
    member _.PeekBreak() =
        if pos >= data.Length then
            fail "unexpected end of data"

        if data[pos] = 0xffuy then
            pos <- pos + 1
            true
        else
            false

    member _.KeyId(k: Item) =
        match k with
        | UInt v -> $"u{v}"
        | NegInt v -> $"n{v}"
        | Text s -> "t" + s
        | Bytes b -> "b" + Convert.ToHexString b
        | Simple v -> $"s{v}"
        | Float f -> $"f{f}"
        | Array _
        | Map _ -> fail "a map key that is an array or map"

/// Decodes exactly one item: trailing bytes are an error.
let decode (opts: Options) (data: byte[]) : Item =
    let r = Reader(data, opts)
    let item = r.Item 0

    if r.Pos <> data.Length then
        fail "extraneous data after the CBOR item"

    item

/// The raw bytes of the elements of a top-level definite array, each decoded as one item.
/// COSE_Sign1 needs the protected header as the bytes received.
let arrayElements (opts: Options) (data: byte[]) : (Item * byte[]) list =
    let r = Reader(data, opts)
    let ib = r.Byte()

    if ib >>> 5 <> 4uy then
        fail "not an array"

    let n =
        match r.Arg(ib &&& 0x1fuy) with
        | ValueSome n -> n
        | ValueNone -> fail "indefinite length not allowed"

    if n > uint64 data.Length then
        fail "array longer than the data"

    let out =
        [
            for _ in 1UL .. n ->
                let start = r.Pos
                let item = r.Item 1
                item, data[start .. r.Pos - 1]
        ]

    if r.Pos <> data.Length then
        fail "extraneous data after the CBOR item"

    out

// ---- encoding ----------------------------------------------------------------

let private head (out: ResizeArray<byte>) (major: byte) (n: uint64) =
    let m = major <<< 5

    if n < 24UL then
        out.Add(m ||| byte n)
    elif n <= 0xffUL then
        out.Add(m ||| 24uy)
        out.Add(byte n)
    elif n <= 0xffffUL then
        out.Add(m ||| 25uy)
        let b = Array.zeroCreate<byte> 2
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(), uint16 n)
        out.AddRange b
    elif n <= 0xffffffffUL then
        out.Add(m ||| 26uy)
        let b = Array.zeroCreate<byte> 4
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(), uint32 n)
        out.AddRange b
    else
        out.Add(m ||| 27uy)
        let b = Array.zeroCreate<byte> 8
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(), n)
        out.AddRange b

/// Sig_structure of a COSE_Sign1 (RFC 9052, 4.4) with empty external_aad:
/// ["Signature1", protected, h'', payload], definite lengths, shortest heads.
let sigStructure (protectedHeader: byte[]) (payload: byte[]) : byte[] =
    let out = ResizeArray<byte>(payload.Length + protectedHeader.Length + 32)
    head out 4uy 4UL
    let text = Encoding.ASCII.GetBytes "Signature1"
    head out 3uy (uint64 text.Length)
    out.AddRange text

    for b in [ protectedHeader; [||]; payload ] do
        head out 2uy (uint64 b.Length)
        out.AddRange b

    out.ToArray()
