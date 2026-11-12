/// The OTLP trace export request (opentelemetry-proto v1, `collector/trace/v1` and `trace/v1`)
/// in the binary protobuf encoding, written by hand: no generated code, no package (as the Dirk
/// module does for its messages). Only the fields the VC fills are written.
module Eplix.Tracing.Otlp

open System
open System.IO
open System.Text

/// An attribute value: the AnyValue cases the VC uses.
[<RequireQualifiedAccess>]
type AttrValue =
    | Text of string
    | Int of int64
    | Bool of bool
    | Double of float

/// One finished span, copied out of its Activity when it stopped.
type SpanData =
    {
        /// The ActivitySource name: the instrumentation scope.
        Scope: string
        TraceId: byte[]
        SpanId: byte[]
        /// Empty for a root span.
        ParentSpanId: byte[]
        Name: string
        /// OTLP SpanKind: 1 internal, 2 server, 3 client, 4 producer, 5 consumer.
        Kind: int
        StartUnixNano: uint64
        EndUnixNano: uint64
        Attributes: (string * AttrValue)[]
        /// OTLP StatusCode: 0 unset, 1 ok, 2 error.
        StatusCode: int
        StatusMessage: string
    }

/// Writes protobuf fields into a stream. Nested messages are written to their own writer first,
/// then copied in with their length.
type ProtoWriter() =
    let ms = new MemoryStream()

    member _.Varint(v: uint64) =
        let mutable v = v

        while v >= 0x80UL do
            ms.WriteByte(byte (v ||| 0x80UL))
            v <- v >>> 7

        ms.WriteByte(byte v)

    member w.Tag(field: int, wire: int) = w.Varint(uint64 ((field <<< 3) ||| wire))

    member w.Bytes(field: int, b: ReadOnlySpan<byte>) =
        w.Tag(field, 2)
        w.Varint(uint64 b.Length)
        ms.Write b

    member w.String(field: int, s: string) = w.Bytes(field, ReadOnlySpan<byte>(Encoding.UTF8.GetBytes s))

    /// Skips empty strings, as proto3 leaves default values out.
    member w.StringIfAny(field: int, s: string) =
        if not (String.IsNullOrEmpty s) then
            w.String(field, s)

    member w.Message(field: int, m: ProtoWriter) = w.Bytes(field, ReadOnlySpan<byte>(m.ToArray(): byte[]))

    member w.Fixed64(field: int, v: uint64) =
        w.Tag(field, 1)
        let b = Array.zeroCreate<byte> 8
        Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(Span b, v)
        ms.Write(b, 0, 8)

    member w.Double(field: int, v: float) = w.Fixed64(field, uint64 (BitConverter.DoubleToInt64Bits v))

    member w.VarintField(field: int, v: uint64) =
        w.Tag(field, 0)
        w.Varint v

    member _.ToArray() = ms.ToArray()

let private anyValue (v: AttrValue) =
    let w = ProtoWriter()

    match v with
    | AttrValue.Text s -> w.String(1, s)
    | AttrValue.Bool b -> w.VarintField(2, (if b then 1UL else 0UL))
    | AttrValue.Int i -> w.VarintField(3, uint64 i)
    | AttrValue.Double d -> w.Double(4, d)

    w

let private keyValue (k: string, v: AttrValue) =
    let w = ProtoWriter()
    w.String(1, k)
    w.Message(2, anyValue v)
    w

let private span (s: SpanData) =
    let w = ProtoWriter()
    w.Bytes(1, ReadOnlySpan s.TraceId)
    w.Bytes(2, ReadOnlySpan s.SpanId)

    if s.ParentSpanId.Length > 0 then
        w.Bytes(4, ReadOnlySpan s.ParentSpanId)

    w.String(5, s.Name)

    if s.Kind <> 0 then
        w.VarintField(6, uint64 s.Kind)

    w.Fixed64(7, s.StartUnixNano)
    w.Fixed64(8, s.EndUnixNano)

    for a in s.Attributes do
        w.Message(9, keyValue a)

    if s.StatusCode <> 0 || not (String.IsNullOrEmpty s.StatusMessage) then
        let st = ProtoWriter()
        st.StringIfAny(2, s.StatusMessage)

        if s.StatusCode <> 0 then
            st.VarintField(3, uint64 s.StatusCode)

        w.Message(15, st)

    w

/// An ExportTraceServiceRequest with one ResourceSpans: the resource attributes, then one
/// ScopeSpans per scope in the order the scopes first appear.
let encodeRequest (resource: (string * AttrValue)[]) (scopeVersion: string) (spans: SpanData seq) : byte[] =
    let res = ProtoWriter()

    for a in resource do
        res.Message(1, keyValue a)

    let rs = ProtoWriter()
    rs.Message(1, res)

    for scope, group in spans |> Seq.groupBy (fun s -> s.Scope) do
        let ss = ProtoWriter()
        let sc = ProtoWriter()
        sc.String(1, scope)
        sc.StringIfAny(2, scopeVersion)
        ss.Message(1, sc)

        for s in group do
            ss.Message(2, span s)

        rs.Message(2, ss)

    let req = ProtoWriter()
    req.Message(1, rs)
    req.ToArray()

/// The rejected span count of an ExportTraceServiceResponse (`partial_success.rejected_spans`),
/// 0 when the answer is empty or does not parse. The VC only counts it.
let rejectedSpans (body: byte[]) : int64 =
    // Reads field 1 (partial_success), then its field 1 (rejected_spans); skips everything else.
    let rec varint (b: byte[]) (i: int) (shift: int) (acc: uint64) =
        if i >= b.Length || shift > 63 then
            None
        else
            let x = b[i]
            let acc = acc ||| (uint64 (x &&& 0x7Fuy) <<< shift)
            if x &&& 0x80uy = 0uy then Some(acc, i + 1) else varint b (i + 1) (shift + 7) acc

    let rec find (b: byte[]) (i: int) (field: int) : Choice<byte[], uint64> option =
        if i >= b.Length then
            None
        else
            match varint b i 0 0UL with
            | None -> None
            | Some(tag, i) ->
                let f, wire = int (tag >>> 3), int (tag &&& 7UL)

                match wire with
                | 0 ->
                    match varint b i 0 0UL with
                    | Some(v, j) -> if f = field then Some(Choice2Of2 v) else find b j field
                    | None -> None
                | 1 -> if i + 8 > b.Length then None else find b (i + 8) field
                | 5 -> if i + 4 > b.Length then None else find b (i + 4) field
                | 2 ->
                    match varint b i 0 0UL with
                    | Some(len, j) when uint64 j + len <= uint64 b.Length ->
                        if f = field then Some(Choice1Of2(b[j .. j + int len - 1])) else find b (j + int len) field
                    | _ -> None
                | _ -> None

    match find body 0 1 with
    | Some(Choice1Of2 partial) ->
        match find partial 0 1 with
        | Some(Choice2Of2 n) -> int64 n
        | _ -> 0L
    | _ -> 0L
