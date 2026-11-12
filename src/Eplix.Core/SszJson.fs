/// The Beacon API JSON form of any SSZ value, driven by its schema: integers as decimal strings,
/// byte vectors and lists as 0x-hex, bitfields as 0x-hex of their SSZ bytes, containers as objects
/// with the schema's field names. Unknown object fields are ignored on read.
module Eplix.SszJson

open System
open System.Globalization
open System.Numerics
open System.Text.Json
open Eplix.Ssz
open Eplix.Json

let private hexBytes (e: JsonElement) =
    match Hex.tryDecode (str e) with
    | ValueSome b -> b
    | ValueNone -> fail "expected 0x-hex"

/// Digits of 2^256 - 1, the longest decimal uint256.
let private uint256Digits = 78

/// A decimal uint256 string (digits only) to its value. A string longer than 78 characters is
/// refused before the parse: a node's answer can be as long as the body cap, and parsing that
/// holds a thread no request timeout can stop.
let tryUint256 (s: string) : BigInteger voption =
    if s.Length = 0 || s.Length > uint256Digits then
        ValueNone
    else
        match BigInteger.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture) with
        | true, v when v.Sign >= 0 && v.GetByteCount(isUnsigned = true) <= 32 -> ValueSome v
        | _ -> ValueNone

let private uint256Of (e: JsonElement) : byte[] =
    match tryUint256 (str e) with
    | ValueSome v ->
        let out = Array.zeroCreate<byte> 32
        let mutable written = 0
        v.TryWriteBytes(Span out, &written, true, false) |> ignore
        out
    | ValueNone -> fail "expected a decimal uint256 string"

let private uint256Text (b: byte[]) =
    BigInteger(ReadOnlySpan b, isUnsigned = true, isBigEndian = false).ToString(CultureInfo.InvariantCulture)

let rec read (t: SszType) (e: JsonElement) : SszValue =
    match t with
    | Uint _ -> U(u64 e)
    | Uint256 -> Bytes(uint256Of e)
    | Boolean ->
        match e.ValueKind with
        | JsonValueKind.True -> Bool true
        | JsonValueKind.False -> Bool false
        | _ -> fail "expected a boolean"
    | ByteVector n ->
        let b = hexBytes e

        if b.Length <> n then
            fail $"expected {n} bytes"

        Bytes b
    | ByteList n ->
        let b = hexBytes e

        if b.Length > n then
            fail $"more than {n} bytes"

        Bytes b
    | ProgressiveByteList -> Bytes(hexBytes e)
    | Bitvector _
    | Bitlist _
    | ProgressiveBitlist ->
        match deserialize t (hexBytes e) with
        | Ok v -> v
        | Error m -> fail m
    | ProgressiveList elem -> Items(array e |> Array.map (read elem))
    | ProgressiveContainer fields -> Fields(fields |> Array.map (fun (name, ft) -> read ft (prop e name)))
    | Vector(elem, n) ->
        let items = array e

        if items.Length <> n then
            fail $"expected {n} items"

        Items(items |> Array.map (read elem))
    | List(elem, n) ->
        let items = array e

        if items.Length > n then
            fail $"more than {n} items"

        Items(items |> Array.map (read elem))
    | Container fields -> Fields(fields |> Array.map (fun (name, ft) -> read ft (prop e name)))

let rec write (w: Utf8JsonWriter) (t: SszType) (v: SszValue) : unit =
    match t, v with
    | Uint _, U x -> w.WriteStringValue(x.ToString(CultureInfo.InvariantCulture))
    | Uint256, Bytes b -> w.WriteStringValue(uint256Text b)
    | Boolean, Bool b -> w.WriteBooleanValue b
    | (ByteVector _ | ByteList _ | ProgressiveByteList), Bytes b -> w.WriteStringValue(Hex.encodeArray b)
    | (Bitvector _ | Bitlist _ | ProgressiveBitlist), Bits _ -> w.WriteStringValue(Hex.encodeArray (serialize t v))
    | (Vector(elem, _) | List(elem, _) | ProgressiveList elem), Items items ->
        w.WriteStartArray()

        for x in items do
            write w elem x

        w.WriteEndArray()
    | (Container fields | ProgressiveContainer fields), Fields values when fields.Length = values.Length ->
        w.WriteStartObject()

        for i in 0 .. fields.Length - 1 do
            let name, ft = fields[i]
            w.WritePropertyName name
            write w ft values[i]

        w.WriteEndObject()
    | _ -> raise (SszError "value does not match schema")

/// Decodes a JSON element; schema errors become Error.
let tryRead (t: SszType) (e: JsonElement) : Result<SszValue, string> =
    try
        Ok(read t e)
    with
    | :? JsonDecodeError as x -> Error x.Message
    | :? SszError as x -> Error x.Message
    | :? InvalidOperationException as x -> Error x.Message

let toBytes (t: SszType) (v: SszValue) : byte[] = Json.toBytes (fun w -> write w t v)
