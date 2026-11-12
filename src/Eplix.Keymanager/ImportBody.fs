/// The body of POST /eth/v1/keystores read as a stream. The keystores and
/// passwords are small and come out as strings. The slashing_protection field is an EIP-3076
/// interchange inside a JSON string: its escaped content goes through JsonStringUnescaper into
/// an InterchangeReader a chunk at a time, so the import keeps the marks per key and never the
/// history or the body. Memory: a 128 KiB read buffer, the keystores and passwords, and one
/// entry per key in the interchange.
module Eplix.Keymanager.ImportBody

open System
open System.Buffers
open System.Collections.Generic
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Microsoft.AspNetCore.Http
open Eplix.Json
open Eplix.Slashing

type Parsed =
    {
        Keystores: string list
        Passwords: string list
        /// The marks of the slashing_protection interchange; ValueNone without the field or
        /// with null.
        History: InterchangeMarks voption
    }

[<RequireQualifiedAccess>]
type ReadError =
    /// More bytes than the limit.
    | TooLarge
    | Invalid of message: string
    /// More distinct keys in slashing_protection than the cap.
    | TooManyKeys of limit: int
    /// Kestrel stopped the read: a body too slow (408) or past MaxRequestBodySize (413).
    | Http of status: int * message: string

/// The read buffer. A JSON token outside slashing_protection (a keystore with its escapes) must
/// fit in it.
[<Literal>]
let BufferSize = 131072

/// The largest keystore or password, as escaped JSON. An EIP-2335 keystore is about 1 KB.
[<Literal>]
let MaxItemBytes = 65536

[<Literal>]
let private SStart = 0

[<Literal>]
let private SRoot = 1

[<Literal>]
let private SListOpen = 2

[<Literal>]
let private SList = 3

[<Literal>]
let private SHistoryValue = 4

[<Literal>]
let private SSkipValue = 5

[<Literal>]
let private SSkip = 6

[<Literal>]
let private SDone = 7

// How Feed reads the bytes: through the JSON reader, the white space and colon before the
// slashing_protection value, or the string content through the unescaper.
[<Literal>]
let private MJson = 0

[<Literal>]
let private MPrefix = 1

[<Literal>]
let private MString = 2

let private nameKeystores = "keystores"B
let private namePasswords = "passwords"B
let private nameHistory = "slashing_protection"B
let private emptyString = "\"\""B

[<Sealed>]
type private BodyReader(maxItems: int, maxKeys: int) =
    let mutable json = JsonReaderState(JsonReaderOptions(MaxDepth = 64))
    let mutable mode = MJson
    let mutable st = SStart
    let mutable skipDepth = 0
    // 1 keystores, 2 passwords: the list being read.
    let mutable list = 0
    let keystores = List<string>()
    let passwords = List<string>()
    let mutable seen = 0
    let unescaper = JsonStringUnescaper()
    let interchange = InterchangeReader maxKeys
    let unescaped: byte[] = Array.zeroCreate 16384
    let mutable history = ValueNone

    member private _.Token(r: byref<Utf8JsonReader>) : bool =
        let t = r.TokenType

        match st with
        | SStart ->
            if t <> JsonTokenType.StartObject then
                fail "expected an object around 'keystores'"

            st <- SRoot
            false
        | SRoot ->
            if t = JsonTokenType.EndObject then
                st <- SDone
                false
            else
                let field (bit: int) (name: string) =
                    if seen &&& bit <> 0 then
                        fail $"field '{name}' appears twice"

                    seen <- seen ||| bit

                if r.ValueTextEquals(ReadOnlySpan nameKeystores) then
                    field 1 "keystores"
                    list <- 1
                    st <- SListOpen
                    false
                elif r.ValueTextEquals(ReadOnlySpan namePasswords) then
                    field 2 "passwords"
                    list <- 2
                    st <- SListOpen
                    false
                elif r.ValueTextEquals(ReadOnlySpan nameHistory) then
                    field 4 "slashing_protection"
                    // The reader stops after the colon; Feed reads the value itself.
                    mode <- MPrefix
                    true
                else
                    st <- SSkipValue
                    false
        | SListOpen ->
            if t <> JsonTokenType.StartArray then
                fail "expected an array"

            st <- SList
            false
        | SList ->
            if t = JsonTokenType.EndArray then
                st <- SRoot
            else
                let what = if list = 1 then "keystores" else "passwords"

                if t <> JsonTokenType.String then
                    fail $"{what}: expected a string"

                if r.ValueSpan.Length > MaxItemBytes then
                    fail $"{what}: an item over {MaxItemBytes} bytes"

                let items = if list = 1 then keystores else passwords

                if items.Count = maxItems then
                    fail $"at most {maxItems} keystores per request"

                items.Add(nonNull (r.GetString()))

            false
        | SHistoryValue ->
            // Feed takes a string itself; anything else lands here.
            if t <> JsonTokenType.Null then
                fail "slashing_protection: expected a string"

            st <- SRoot
            false
        | SSkipValue ->
            if t = JsonTokenType.StartObject || t = JsonTokenType.StartArray then
                skipDepth <- 1
                st <- SSkip
            else
                st <- SRoot

            false
        | SSkip ->
            if t = JsonTokenType.StartObject || t = JsonTokenType.StartArray then
                skipDepth <- skipDepth + 1
            elif t = JsonTokenType.EndObject || t = JsonTokenType.EndArray then
                skipDepth <- skipDepth - 1

                if skipDepth = 0 then
                    st <- SRoot

            false
        | _ -> false

    /// Reads from `data` what it can; returns the bytes it used. The caller keeps the rest and
    /// passes it again with more.
    member this.Feed(data: ReadOnlySpan<byte>, isFinal: bool) : int =
        let mutable pos = 0
        let mutable go = true

        while go do
            if mode = MJson then
                let mutable r = Utf8JsonReader(data.Slice pos, isFinal, json)
                let mutable stop = false

                while not stop && r.Read() do
                    stop <- this.Token(&r)

                pos <- pos + int r.BytesConsumed
                json <- r.CurrentState
                go <- stop
            elif mode = MPrefix then
                while pos < data.Length
                      && (data[pos] = ' 'B || data[pos] = '\t'B || data[pos] = '\n'B || data[pos] = '\r'B) do
                    pos <- pos + 1

                if pos = data.Length then
                    go <- false
                elif data[pos] = '"'B then
                    pos <- pos + 1
                    mode <- MString
                else
                    // Not a string: the JSON reader reads the value (null, or an error).
                    mode <- MJson
                    st <- SHistoryValue
            else
                try
                    let struct (used, written) = unescaper.Run(data.Slice pos, Span unescaped)
                    pos <- pos + used
                    interchange.Feed(ReadOnlySpan(unescaped, 0, written))

                    if unescaper.Done then
                        history <- ValueSome(interchange.Finish())
                with
                | :? JsonDecodeError as e -> fail $"slashing_protection: {e.Message}"
                | :? JsonException as e -> fail $"slashing_protection: {e.Message}"

                if unescaper.Done then
                    // The JSON reader never saw the string; it reads an empty one in its place.
                    let mutable r = Utf8JsonReader(ReadOnlySpan emptyString, false, json)
                    r.Read() |> ignore
                    json <- r.CurrentState
                    mode <- MJson
                elif pos = data.Length then
                    go <- false

        if isFinal && pos < data.Length then
            fail "unexpected data after the JSON object"

        pos

    /// The body once Feed has read all of it.
    member _.Result() : Parsed =
        if st <> SDone || mode <> MJson then
            fail "the body ends early"

        if seen &&& 1 = 0 then
            fail "missing field 'keystores'"

        if seen &&& 2 = 0 then
            fail "missing field 'passwords'"

        {
            Keystores = List.ofSeq keystores
            Passwords = List.ofSeq passwords
            History = history
        }

let private feed (reader: BodyReader) (buf: byte[]) (filled: int) (isFinal: bool) : Result<int, ReadError> =
    try
        Ok(reader.Feed(ReadOnlySpan(buf, 0, filled), isFinal))
    with
    | :? JsonDecodeError as e -> Error(ReadError.Invalid e.Message)
    | :? JsonException as e -> Error(ReadError.Invalid e.Message)
    | :? InvalidOperationException as e -> Error(ReadError.Invalid e.Message)
    | :? TooManyKeysError as e -> Error(ReadError.TooManyKeys e.Limit)

let private finish (reader: BodyReader) : Result<Parsed, ReadError> =
    try
        Ok(reader.Result())
    with :? JsonDecodeError as e ->
        Error(ReadError.Invalid e.Message)

/// Reads an import body from `body`, at most `limit` bytes, at most `maxItems` keystores and
/// passwords, and at most `maxKeys` distinct keys in slashing_protection. Stops at the first
/// byte over the limit, the first key over the cap or the first JSON error.
let read
    (body: Stream)
    (limit: int64)
    (maxItems: int)
    (maxKeys: int)
    (ct: CancellationToken)
    : Task<Result<Parsed, ReadError>> =
    task {
        let reader = BodyReader(maxItems, maxKeys)
        let buf = ArrayPool<byte>.Shared.Rent BufferSize

        try
            try
                let mutable filled = 0
                let mutable total = 0L
                let mutable result = ValueNone

                while result.IsNone do
                    let! n = body.ReadAsync(buf.AsMemory(filled, BufferSize - filled), ct)
                    total <- total + int64 n

                    if total > limit then
                        result <- ValueSome(Error ReadError.TooLarge)
                    else
                        filled <- filled + n

                        match feed reader buf filled (n = 0) with
                        | Error e -> result <- ValueSome(Error e)
                        | Ok used ->
                            Buffer.BlockCopy(buf, used, buf, 0, filled - used)
                            filled <- filled - used

                            if n = 0 then
                                result <- ValueSome(finish reader)
                            elif filled = BufferSize then
                                result <- ValueSome(Error(ReadError.Invalid $"a JSON token over {BufferSize} bytes"))

                return result.Value
            with :? BadHttpRequestException as e ->
                return Error(ReadError.Http(e.StatusCode, e.Message))
        finally
            ArrayPool<byte>.Shared.Return buf
    }
