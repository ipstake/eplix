/// JSON helpers over System.Text.Json's reader-based DOM and Utf8JsonWriter. No reflection, so AOT-safe.
/// Beacon API numbers are decimal strings; byte values are 0x-prefixed hex strings.
module Eplix.Json

open System
open System.Globalization
open System.IO
open System.Text.Json

/// A plain .NET exception, not an F# `exception` type (whose Message needs reflection).
type JsonDecodeError(message: string) =
    inherit Exception(message)

let fail msg = raise (JsonDecodeError msg)

let prop (e: JsonElement) (name: string) : JsonElement =
    if e.ValueKind <> JsonValueKind.Object then
        fail $"expected an object around '{name}'"

    match e.TryGetProperty name with
    | true, v -> v
    | _ -> fail $"missing field '{name}'"

let tryProp (e: JsonElement) (name: string) : JsonElement voption =
    if e.ValueKind <> JsonValueKind.Object then
        ValueNone
    else
        match e.TryGetProperty name with
        | true, v when v.ValueKind <> JsonValueKind.Null -> ValueSome v
        | _ -> ValueNone

let str (e: JsonElement) : string =
    if e.ValueKind <> JsonValueKind.String then
        fail "expected a string"

    match e.GetString() with
    | null -> fail "expected a string"
    | s -> s

let strField e name = str (prop e name)

/// A uint64 given as a decimal string (the Beacon API form) or as a JSON number.
let u64 (e: JsonElement) : uint64 =
    match e.ValueKind with
    | JsonValueKind.String ->
        match UInt64.TryParse(str e, NumberStyles.None, CultureInfo.InvariantCulture) with
        | true, v -> v
        | _ -> fail "expected a decimal uint64 string"
    | JsonValueKind.Number ->
        match e.TryGetUInt64() with
        | true, v -> v
        | _ -> fail "expected a uint64"
    | _ -> fail "expected a uint64"

let u64Field e name = u64 (prop e name)

/// A whole number in lo..hi for config key `key`. A value out of range, negative, fractional or
/// not a number fails with the key and the range (Bounds.message), so the caller converts to
/// int or TimeSpan only after the check.
let bounded (key: string) (lo: uint64) (hi: uint64) (e: JsonElement) : uint64 =
    let v =
        try
            u64 e
        with :? JsonDecodeError ->
            fail (Bounds.message key lo hi)

    match Bounds.check key lo hi v with
    | Ok v -> v
    | Error m -> fail m

/// `bounded` as an int.
let boundedInt (key: string) (lo: int) (hi: int) (e: JsonElement) : int =
    if lo < 0 || hi < lo then
        invalidArg (nameof hi) $"{key}: want 0 <= lo <= hi"

    int (bounded key (uint64 lo) (uint64 hi) e)

/// `bounded` milliseconds as a TimeSpan; `hi` must be a delay a timer takes.
let boundedMs (key: string) (lo: uint64) (hi: uint64) (e: JsonElement) : TimeSpan =
    if float hi > Bounds.maxDelay.TotalMilliseconds then
        invalidArg (nameof hi) $"{key}: longer than a timer takes"

    TimeSpan.FromMilliseconds(float (bounded key lo hi e))

/// `bounded` seconds as a TimeSpan; `hi` must be a delay a timer takes.
let boundedSeconds (key: string) (lo: uint64) (hi: uint64) (e: JsonElement) : TimeSpan =
    if float hi > Bounds.maxDelay.TotalSeconds then
        invalidArg (nameof hi) $"{key}: longer than a timer takes"

    TimeSpan.FromSeconds(float (bounded key lo hi e))

/// A JSON number in 0..1. A number too large for a double reads as infinity and fails.
let fraction (key: string) (e: JsonElement) : float =
    let bad () = fail $"{key} must be a number between 0 and 1"

    if e.ValueKind <> JsonValueKind.Number then
        bad ()

    match e.TryGetDouble() with
    | true, r when Double.IsFinite r && r >= 0.0 && r <= 1.0 -> r
    | _ -> bad ()

let boolField (e: JsonElement) name =
    match (prop e name).ValueKind with
    | JsonValueKind.True -> true
    | JsonValueKind.False -> false
    | _ -> fail $"'{name}' must be a boolean"

let optBoolField (e: JsonElement) name =
    match tryProp e name with
    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
    | _ -> false

let private hexOf (parse: string -> 'T voption) (what: string) (e: JsonElement) : 'T =
    match parse (str e) with
    | ValueSome v -> v
    | ValueNone -> fail $"expected {what} as 0x-hex"

let root e = hexOf Root.TryParse "a 32-byte root" e
let pubkey e = hexOf PubKey.TryParse "a 48-byte public key" e
let signature e = hexOf BlsSignature.TryParse "a 96-byte signature" e
let version e = hexOf ForkVersion.TryParse "a 4-byte version" e
let rootField e name = root (prop e name)
let pubkeyField e name = pubkey (prop e name)

let array (e: JsonElement) : JsonElement[] =
    if e.ValueKind <> JsonValueKind.Array then
        fail "expected an array"

    [| for x in e.EnumerateArray() -> x |]

/// Parses a document and runs a decoder. Decode errors and malformed JSON become Error.
let decode (decoder: JsonElement -> 'T) (bytes: ReadOnlyMemory<byte>) : Result<'T, string> =
    try
        use doc = JsonDocument.Parse(bytes, JsonDocumentOptions(MaxDepth = 64))
        Ok(decoder doc.RootElement)
    with
    | :? JsonDecodeError as e -> Error e.Message
    | :? JsonException as e -> Error e.Message
    | :? InvalidOperationException as e -> Error e.Message

/// Runs a decoder that reads the raw bytes itself (a Utf8JsonReader); errors as in `decode`.
let decodeBytes (decoder: ReadOnlyMemory<byte> -> 'T) (bytes: ReadOnlyMemory<byte>) : Result<'T, string> =
    try
        Ok(decoder bytes)
    with
    | :? JsonDecodeError as e -> Error e.Message
    | :? JsonException as e -> Error e.Message
    | :? InvalidOperationException as e -> Error e.Message

let decodeString decoder (s: string) = decode decoder (ReadOnlyMemory(Text.Encoding.UTF8.GetBytes s))

/// Checks that an object has no fields outside `allowed`. The strict config uses it.
let checkFields (e: JsonElement) (where: string) (allowed: string list) : string list =
    [
        if e.ValueKind <> JsonValueKind.Object then
            $"{where} must be an object"
        else
            for p in e.EnumerateObject() do
                if not (List.contains p.Name allowed) then
                    $"{where}: unknown field '{p.Name}'"
    ]

// ---- Writing ----

let writeU64 (w: Utf8JsonWriter) (name: string) (v: uint64) =
    w.WriteString(name, v.ToString(CultureInfo.InvariantCulture))

let toBytes (write: Utf8JsonWriter -> unit) : byte[] =
    use ms = new MemoryStream()

    (use w = new Utf8JsonWriter(ms, JsonWriterOptions(Indented = false))
     write w)

    ms.ToArray()

let toIndentedString (write: Utf8JsonWriter -> unit) : string =
    use ms = new MemoryStream()

    (use w = new Utf8JsonWriter(ms, JsonWriterOptions(Indented = true))
     write w)

    Text.Encoding.UTF8.GetString(ms.ToArray())
