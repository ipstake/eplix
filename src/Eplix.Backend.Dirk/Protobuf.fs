/// The few protobuf wire rules Dirk's messages need (proto3: varints and length-delimited
/// fields), so the module needs no code generator and no Google.Protobuf. Unknown fields are
/// skipped on read, as protobuf requires.
module Eplix.Backend.Dirk.Protobuf

open System
open System.IO

type ProtobufError(message: string) =
    inherit Exception(message)

let private fail msg = raise (ProtobufError msg)

type Writer() =
    let ms = new MemoryStream()

    member _.Varint(v: uint64) =
        let mutable x = v

        while x >= 0x80UL do
            ms.WriteByte(byte (x ||| 0x80UL))
            x <- x >>> 7

        ms.WriteByte(byte x)

    member private w.Tag(field: int, wireType: int) = w.Varint(uint64 ((field <<< 3) ||| wireType))

    /// A varint field; proto3 leaves out the default value 0.
    member w.UInt64(field: int, v: uint64) =
        if v <> 0UL then
            w.Tag(field, 0)
            w.Varint v

    member w.UInt32(field: int, v: uint32) = w.UInt64(field, uint64 v)

    /// A bytes field; proto3 leaves out empty values.
    member w.Bytes(field: int, b: ReadOnlySpan<byte>) =
        if b.Length > 0 then
            w.Tag(field, 2)
            w.Varint(uint64 b.Length)
            ms.Write b

    member w.String(field: int, s: string) =
        if not (String.IsNullOrEmpty s) then
            w.Bytes(field, ReadOnlySpan(Text.Encoding.UTF8.GetBytes s))

    /// An embedded message, written even when empty (it is set).
    member w.Message(field: int, body: byte[]) =
        w.Tag(field, 2)
        w.Varint(uint64 body.Length)
        ms.Write(body, 0, body.Length)

    member _.ToArray() = ms.ToArray()

let encode (write: Writer -> unit) : byte[] =
    let w = Writer()
    write w
    w.ToArray()

/// One field as read: a varint value or a slice of the buffer.
[<Struct>]
type Field =
    {
        Number: int
        WireType: int
        Varint: uint64
        Bytes: ReadOnlyMemory<byte>
    }

let private readVarint (b: ReadOnlySpan<byte>) (pos: byref<int>) : uint64 =
    let mutable x = 0UL
    let mutable shift = 0
    let mutable fin = false

    while not fin do
        if pos >= b.Length then
            fail "truncated varint"

        if shift > 63 then
            fail "varint too long"

        let c = b[pos]
        pos <- pos + 1
        x <- x ||| (uint64 (c &&& 0x7Fuy) <<< shift)
        shift <- shift + 7

        if c &&& 0x80uy = 0uy then
            fin <- true

    x

/// Every field of a message, in order.
let fields (buf: ReadOnlyMemory<byte>) : Field list =
    let out = ResizeArray<Field>()
    let b = buf.Span
    let mutable pos = 0

    while pos < b.Length do
        let key = readVarint b &pos
        let number = int (key >>> 3)
        let wireType = int (key &&& 7UL)

        if number = 0 then
            fail "field number 0"

        match wireType with
        | 0 ->
            let v = readVarint b &pos

            out.Add
                {
                    Number = number
                    WireType = 0
                    Varint = v
                    Bytes = ReadOnlyMemory.Empty
                }
        | 2 ->
            let len = readVarint b &pos

            if len > uint64 (b.Length - pos) then
                fail "length past the end"

            out.Add
                {
                    Number = number
                    WireType = 2
                    Varint = 0UL
                    Bytes = buf.Slice(pos, int len)
                }

            pos <- pos + int len
        | 1 ->
            if pos + 8 > b.Length then
                fail "truncated fixed64"

            pos <- pos + 8
        | 5 ->
            if pos + 4 > b.Length then
                fail "truncated fixed32"

            pos <- pos + 4
        | t -> fail $"unsupported wire type {t}"

    List.ofSeq out

let asBytes (f: Field) : byte[] =
    if f.WireType <> 2 then
        fail $"field {f.Number}: expected bytes"

    f.Bytes.ToArray()

let asString (f: Field) : string =
    if f.WireType <> 2 then
        fail $"field {f.Number}: expected a string"

    Text.Encoding.UTF8.GetString f.Bytes.Span

let asVarint (f: Field) : uint64 =
    if f.WireType <> 0 then
        fail $"field {f.Number}: expected a varint"

    f.Varint
