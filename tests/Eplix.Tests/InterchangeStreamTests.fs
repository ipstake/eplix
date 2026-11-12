/// The streamed keystore import: the JSON string unescaper against
/// System.Text.Json, the interchange reader against Interchange.parse on the EIP-3076 suite,
/// the import body reader, and memory on a large complete history.
module Eplix.Tests.InterchangeStreamTests

open System
open System.Buffers.Text
open System.IO
open System.Text
open System.Text.Encodings.Web
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Slashing
open Eplix.Keymanager
open Eplix.Tests.TestUtil
open Eplix.Tests.SlashingTests

// ---- The unescaper ----

/// Unescapes `content` (the bytes after the opening quote) fed in chunks; the bytes, or None
/// when the unescaper refuses them or never sees the closing quote.
let private unescape (content: byte[]) (chunk: unit -> int) : byte[] option =
    try
        let u = JsonStringUnescaper()
        let out = ResizeArray<byte>()
        let dst = Array.zeroCreate<byte> 64
        let mutable pos = 0

        while not u.Done && pos < content.Length do
            let n = min (max 1 (chunk ())) (content.Length - pos)
            let mutable src = ReadOnlyMemory(content, pos, n)

            while not src.IsEmpty && not u.Done do
                let struct (used, written) = u.Run(src.Span, Span dst)
                out.AddRange(ArraySegment(dst, 0, written))
                src <- src.Slice used
                pos <- pos + used

        if u.Done && pos = content.Length then Some(out.ToArray()) else None
    with :? Json.JsonDecodeError ->
        None

/// What System.Text.Json makes of the same string, as UTF-8; None when it refuses it.
let private reference (content: byte[]) : byte[] option =
    try
        let quoted = Array.concat [ [| byte '"' |]; content ]
        let mutable r = Utf8JsonReader(ReadOnlySpan quoted, true, JsonReaderState())

        if not (r.Read()) || r.TokenType <> JsonTokenType.String || int r.BytesConsumed <> quoted.Length then
            None
        else
            Some(Encoding.UTF8.GetBytes(r.GetString()))
    with
    | :? JsonException
    | :? InvalidOperationException -> None

let private fragments =
    [|
        "a"
        "Z"
        " "
        "~"
        "\\\""
        "\\\\"
        "\\/"
        "\\b"
        "\\f"
        "\\n"
        "\\r"
        "\\t"
        "\\u0041"
        "\\u00e9"
        "\\u20AC"
        "\\uD83D\\uDE00"
        "\\ud800"
        "\\udc00"
        "\\uDBFF\\uDFFF"
        "\\ud800\\u0041"
        "\\ud800\\n"
        "\\ud800\\ud800\\udc00"
        "\\u0000"
        "\\x"
        "\\u12"
        "\\uZZZZ"
        "\\"
        "é"
        "€"
        "😀"
        "\u007f"
    |]

let private rawBytes =
    [|
        [| 0x01uy |]
        [| 0x1Fuy |]
        [| 0xC3uy |]
        [| 0xC3uy; 0x28uy |]
        [| 0xE0uy; 0x80uy; 0x80uy |]
        [| 0xEDuy; 0xA0uy; 0x80uy |]
        [| 0xF4uy; 0x90uy; 0x80uy; 0x80uy |]
        [| 0xFFuy |]
        [| 0xC0uy; 0xAFuy |]
        [| 0xF0uy; 0x9Fuy; 0x98uy; 0x80uy |]
        [| 0xEFuy; 0xBFuy; 0xBDuy |]
    |]

let private unescaperTests =
    testList
        "JSON string unescaper"
        [
            test "edge cases decode as System.Text.Json decodes them" {
                for f in fragments do
                    let content = Array.append (Encoding.UTF8.GetBytes f) [| byte '"' |]

                    for size in [ 1; 2; 3; 1000 ] do
                        Expect.equal
                            (unescape content (fun () -> size))
                            (reference content)
                            $"'{f}' in chunks of {size}"
            }
            test "random strings in random chunks decode as System.Text.Json decodes them" {
                let rnd = Random 3076
                let mutable refused = 0

                for _ in 1..20000 do
                    let parts =
                        [
                            for _ in 0 .. rnd.Next 12 ->
                                if rnd.Next 8 = 0 then
                                    rawBytes[rnd.Next rawBytes.Length]
                                elif rnd.Next 6 = 0 then
                                    // A \u escape with random digits, surrogates included.
                                    Encoding.ASCII.GetBytes($"\\u{rnd.Next 0x10000:x4}")
                                else
                                    Encoding.UTF8.GetBytes(fragments[rnd.Next fragments.Length])
                        ]

                    let content = Array.concat (parts @ [ [| byte '"' |] ])
                    let expected = reference content

                    if expected.IsNone then
                        refused <- refused + 1

                    Expect.equal (unescape content (fun () -> 1 + rnd.Next 9)) expected "same bytes, or both refuse"

                Expect.isGreaterThan refused 1000 "the fuzz reaches the error paths"
            }
        ]

// ---- The interchange reader against Interchange.parse ----

let private interchangeDir =
    match Environment.GetEnvironmentVariable "EPLIX_EIP3076_DIR" with
    | null
    | "" -> Path.Combine(vectors, ".download", "eip3076")
    | d -> d

let private newDb (gvr: Root) =
    match SlashingDb.Open(new ModelFile([||]), gvr) with
    | Ok db -> db
    | Error e -> failwith e

/// The interchange as the slashing_protection string of an import body.
let private bodyOf (interchange: byte[]) (relaxed: bool) =
    use ms = new MemoryStream()

    (let options =
        if relaxed then
            JsonWriterOptions(Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping)
        else
            JsonWriterOptions()

     use w = new Utf8JsonWriter(ms, options)
     w.WriteStartObject()
     w.WriteStartArray "keystores"
     w.WriteEndArray()
     w.WriteStartArray "passwords"
     w.WriteEndArray()
     w.WriteString("slashing_protection", Encoding.UTF8.GetString interchange)
     w.WriteEndObject())

    ms.ToArray()

let private readBodyCapped (body: byte[]) (chunk: unit -> int) (limit: int64) (maxKeys: int) =
    use s = new ChunkStream(body, chunk)
    (ImportBody.read s limit 1000 maxKeys CancellationToken.None).Result

let private readBody (body: byte[]) (chunk: unit -> int) (limit: int64) =
    readBodyCapped body chunk limit InterchangeReader.DefaultMaxKeys

/// Each step of each suite file through the old path (Interchange.parse, Import) and the new
/// one (InterchangeReader, ImportMarks) on two DBs: the same outcome, the same import result
/// and the same marks after every step. The import body path gives the reader's marks too.
let private vectorCase (file: string) =
    test (Path.GetFileNameWithoutExtension file) {
        use doc = JsonDocument.Parse(File.ReadAllText file)
        let r = doc.RootElement
        let gvr = (Root.TryParse(r.GetProperty("genesis_validators_root").GetString())).Value
        let oldDb = newDb gvr
        let newDb = newDb gvr
        let rnd = Random(file.Length)

        for step in r.GetProperty("steps").EnumerateArray() do
            let bytes = Encoding.UTF8.GetBytes(step.GetProperty("interchange").GetRawText())
            let streamed = InterchangeStream.ofBytes bytes

            for relaxed in [ false; true ] do
                match readBody (bodyOf bytes relaxed) (fun () -> 1 + rnd.Next 300) Int64.MaxValue, streamed with
                | Ok p, Ok x -> Expect.equal p.History (ValueSome x) "the body path keeps the reader's marks"
                | Error(ImportBody.ReadError.Invalid _), Error _ -> ()
                | a, b -> failtestf "body path %A, reader %A" a b

            let before = oldDb.Export ValueNone
            let o = Interchange.parse bytes |> Result.bind oldDb.Import
            let n = streamed |> Result.bind newDb.ImportMarks

            match o, n with
            | Ok a, Ok b -> Expect.equal b a "same import result"
            | Error _, Error _ -> Expect.equal (newDb.Export ValueNone) before "a refused file changes nothing"
            | a, b -> failtestf "old %A, new %A" a b

            Expect.equal (newDb.Export ValueNone) (oldDb.Export ValueNone) "same marks"

            for d in (newDb.Export ValueNone).Data do
                Expect.isLessThanOrEqual d.SignedBlocks.Length 1 "the export is minimal: one block"
                Expect.isLessThanOrEqual d.SignedAttestations.Length 1 "the export is minimal: one attestation"
    }

let private vectorTests =
    let files =
        if Directory.Exists interchangeDir then Directory.GetFiles(interchangeDir, "*.json") |> Array.sort else [||]

    if files.Length = 38 then
        testList "EIP-3076 suite, streamed against parsed" [ for f in files -> vectorCase f ]
    else
        test "EIP-3076 suite, streamed against parsed" {
            failtestf
                "%s holds %d of the 38 EIP-3076 files; run scripts/fetch-test-vectors.sh"
                interchangeDir
                files.Length
        }

// ---- The reader on its own ----

let private gvrA = Root.Of(Array.create 32 7uy)
let private keyHex (i: int) = Hex.encodeArray (Array.init 48 (fun j -> byte (i + j + 1)))
let private rootHex (i: int) = Hex.encodeArray (Array.init 32 (fun j -> if j = 31 then byte i else 0uy))

let private doc (data: string) =
    Encoding.UTF8.GetBytes
        $$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{gvrA.Hex}}"},"data":[{{data}}]}"""

let private entry (key: int) (blocks: string) (atts: string) =
    $$"""{"pubkey":"{{keyHex key}}","signed_blocks":[{{blocks}}],"signed_attestations":[{{atts}}]}"""

let private block (slot: int) (root: int) =
    if root = 0 then $$"""{"slot":"{{slot}}"}""" else $$"""{"slot":"{{slot}}","signing_root":"{{rootHex root}}"}"""

let private att (s: int) (t: int) (root: int) =
    if root = 0 then
        $$"""{"source_epoch":"{{s}}","target_epoch":"{{t}}"}"""
    else
        $$"""{"source_epoch":"{{s}}","target_epoch":"{{t}}","signing_root":"{{rootHex root}}"}"""

let private readerTests =
    testList
        "interchange reader"
        [
            test "the same marks as Interchange.marksOf, duplicate keys merged" {
                let bytes =
                    doc (
                        String.Join(
                            ",",
                            [
                                entry 1 (block 5 1 + "," + block 9 2) (att 1 2 3 + "," + att 2 3 4)
                                entry 2 "" ""
                                entry 1 (block 7 5) (att 3 4 0)
                                entry 3 (block 4 1) ""
                            ]
                        )
                    )

                match InterchangeStream.ofBytes bytes, Interchange.parse bytes with
                | Ok x, Ok old ->
                    Expect.equal x.Entries 4 "entries"

                    let expected =
                        old.Data
                        |> List.groupBy (fun e -> e.PubKey)
                        |> List.map (fun (k, es) ->
                            k,
                            es
                            |> List.fold
                                (fun m e ->
                                    let em = Interchange.marksOf e
                                    let m = em.Block |> ValueOption.fold Marks.mergeBlock m
                                    em.Attestation |> ValueOption.fold Marks.mergeAttestation m)
                                KeyMarks.Empty)

                    Expect.equal x.Marks expected "marks per key in first-seen order"
                    Expect.isEmpty x.Slashable "a safe history"
                | a, b -> failtestf "%A %A" a b
            }
            test "a slashable pair inside the file: imported as maxima, the key flagged once" {
                let cases =
                    [
                        "double block", entry 1 (block 5 1 + "," + block 5 2) "", true
                        "double vote", entry 1 "" (att 1 3 1 + "," + att 1 3 2), true
                        "double vote, other source", entry 1 "" (att 1 3 0 + "," + att 2 3 0), true
                        "surrounding", entry 1 "" (att 2 3 1 + "," + att 1 4 2), true
                        "surrounded", entry 1 "" (att 1 5 1 + "," + att 2 4 2), true
                        "source after target", entry 1 "" (att 5 4 1), true
                        "across two entries", entry 1 (block 5 1) "" + "," + entry 1 (block 5 2) "", true
                        "a repeat", entry 1 (block 5 1 + "," + block 5 1) (att 1 2 1 + "," + att 1 2 1), false
                        "unknown roots", entry 1 (block 5 0 + "," + block 5 0) "", false
                        "ascending", entry 1 (block 5 1 + "," + block 6 2) (att 1 2 1 + "," + att 2 3 2), false
                    ]

                for name, data, slashable in cases do
                    match InterchangeStream.ofBytes (doc data) with
                    | Ok x ->
                        Expect.equal x.Slashable (if slashable then [ (PubKey.TryParse(keyHex 1)).Value ] else []) name
                        Expect.equal x.Marks.Length 1 name
                    | Error e -> failtestf "%s: %s" name e
            }
            test "malformed and unsupported interchanges are refused" {
                let bad =
                    [
                        "{"
                        """{"metadata":{"interchange_format_version":"4","genesis_validators_root":"0x00"},"data":[]}"""
                        $$$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{{gvrA.Hex}}}"}}"""
                        $$"""{"data":[]}"""
                        Encoding.UTF8.GetString(doc (entry 1 (block 5 1) "")) + "x"
                        Encoding.UTF8.GetString(doc """{"pubkey":"0x01","signed_blocks":[],"signed_attestations":[]}""")
                        Encoding.UTF8.GetString(doc $$"""{"pubkey":"{{keyHex 1}}","signed_blocks":[]}""")
                        Encoding.UTF8.GetString(doc (entry 1 """{"slot":"-1"}""" ""))
                        Encoding.UTF8.GetString(doc (entry 1 """{"slot":"18446744073709551616"}""" ""))
                        Encoding.UTF8.GetString(doc (entry 1 "" """{"source_epoch":"1"}"""))
                        Encoding.UTF8.GetString(doc (entry 1 """{"slot":"1","signing_root":"0x12"}""" ""))
                    ]

                for b in bad do
                    let bytes = Encoding.UTF8.GetBytes b
                    Expect.isError (InterchangeStream.ofBytes bytes) b
                    Expect.isError (Interchange.parse bytes) $"the old path refuses it too: {b}"
                // Stricter than the old path, which took one of the two.
                Expect.isError
                    (InterchangeStream.ofBytes (doc (entry 1 """{"slot":"1","slot":"2"}""" "")))
                    "a field twice"
            }
            test "numbers as JSON numbers or decimal strings, unknown fields skipped, null roots unknown" {
                let data =
                    $$"""{"pubkey":"{{keyHex 1}}","x":{"y":[1,{"z":null}]},"signed_blocks":[{"slot":12,"signing_root":null,"extra":[]}],"signed_attestations":[{"source_epoch":"0003","target_epoch":4,"signing_root":"{{Root.Zero.Hex}}"}]}"""

                match InterchangeStream.ofBytes (doc data), Interchange.parse (doc data) with
                | Ok x, Ok old ->
                    Expect.equal
                        x.Marks
                        [ (PubKey.TryParse(keyHex 1)).Value, Interchange.marksOf old.Data.Head ]
                        "as the old path"
                | a, b -> failtestf "%A %A" a b
            }
        ]

// ---- The import body ----

let private bodyTests =
    let ks = Encoding.UTF8.GetString(doc (entry 1 (block 5 1) (att 1 2 3)))
    let body (text: string) = Encoding.UTF8.GetBytes text

    testList
        "import body"
        [
            test "keystores, passwords and history in any order, any chunk size" {
                let history = Encoding.UTF8.GetString(Json.toBytes (fun w -> w.WriteStringValue ks))

                let texts =
                    [
                        $$"""{"keystores":["k1","k\"2"],"passwords":["p1","p2"],"slashing_protection":{{history}}}"""
                        $$""" { "slashing_protection" : {{history}} , "x":[{"a":"b"}],"passwords":["p1","p2"],"keystores":["k1","k\"2"]} """
                    ]

                let expected = InterchangeStream.ofBytes (body ks) |> Result.map ValueSome

                for t in texts do
                    for size in [ 1; 7; 4096; 1 <<< 20 ] do
                        match readBody (body t) (fun () -> size) Int64.MaxValue with
                        | Ok p ->
                            Expect.equal p.Keystores [ "k1"; "k\"2" ] "keystores"
                            Expect.equal p.Passwords [ "p1"; "p2" ] "passwords"
                            Expect.equal (Ok p.History) expected "history"
                        | Error e -> failtestf "%s in chunks of %d: %A" t size e
            }
            test "no history, or null" {
                for t in
                    [
                        """{"keystores":[],"passwords":[]}"""
                        """{"keystores":[],"passwords":[],"slashing_protection": null}"""
                    ] do
                    match readBody (body t) (fun () -> 3) Int64.MaxValue with
                    | Ok p -> Expect.equal p.History ValueNone t
                    | Error e -> failtestf "%s: %A" t e
            }
            test "bad bodies are refused" {
                let longItem = String('a', ImportBody.MaxItemBytes + 1)
                let many = String.Join(",", Array.create 1001 "\"k\"")

                let bad =
                    [
                        """{"keystores":[],"passwords":[],"slashing_protection":5}""", "expected a string"
                        """{"keystores":[],"passwords":[],"slashing_protection":"{}","slashing_protection":null}""", ""
                        """{"keystores":[],"passwords":[],"slashing_protection":"{\"metadata\":"}""",
                        "slashing_protection"
                        """{"keystores":[],"passwords":[],"slashing_protection":"\x"}""", "slashing_protection"
                        """{"keystores":[],"passwords":[]""", ""
                        """{"keystores":[],"passwords":[],"slashing_protection":"  """, "ends early"
                        """{"keystores":[],"passwords":[]} x""", ""
                        """{"keystores":[1],"passwords":[]}""", "expected a string"
                        """{"passwords":[]}""", "missing field 'keystores'"
                        $$"""{"keystores":["{{longItem}}"],"passwords":[""]}""", "over"
                        $$"""{"keystores":[{{many}}],"passwords":[]}""", "at most 1000 keystores"
                    ]

                for t, why in bad do
                    match readBody (body t) (fun () -> 5) Int64.MaxValue with
                    | Error(ImportBody.ReadError.Invalid e) -> Expect.stringContains e why t
                    | other -> failtestf "%s: %A" t other
            }
            test "the limit counts body bytes as they arrive" {
                let t = body """{"keystores":[],"passwords":[]}"""
                Expect.isOk (readBody t (fun () -> 4) (int64 t.Length)) "at the limit"

                match readBody t (fun () -> 4) (int64 t.Length - 1L) with
                | Error ImportBody.ReadError.TooLarge -> ()
                | other -> failtestf "%A" other
            }
        ]

// ---- The cap on distinct keys ----

/// A distinct key for any i up to 2^32, in bytes 4 to 7.
let private wideKeyHex (i: int) = "0xc0000000" + i.ToString("x8") + String('0', 80)

/// A minimal interchange with an entry for each key in `keys`, in that order.
let private minimal (keys: int seq) =
    let sb = StringBuilder()

    sb.Append($$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{gvrA.Hex}}"},"data":[""")
    |> ignore

    let mutable first = true

    for k in keys do
        if not first then
            sb.Append ',' |> ignore

        first <- false

        sb.Append($$"""{"pubkey":"{{wideKeyHex k}}","signed_blocks":[{"slot":"{{k + 1}}"}],"signed_attestations":[]}""")
        |> ignore

    sb.Append "]}" |> ignore
    Encoding.UTF8.GetBytes(sb.ToString())

let private readCapped (maxKeys: int) (bytes: byte[]) =
    use ms = new MemoryStream(bytes, false)
    InterchangeStream.readCapped maxKeys ms

let private capTests =
    testList
        "key cap"
        [
            test "the cap counts distinct keys, not entries" {
                // 3 distinct keys in 6 entries pass a cap of 3.
                match readCapped 3 (minimal [ 1; 2; 1; 3; 3; 2 ]) with
                | Ok x ->
                    Expect.equal x.Entries 6 "entries"
                    Expect.equal x.Marks.Length 3 "keys"
                | Error e -> failtest e

                match readCapped 3 (minimal [ 1; 2; 1; 3; 4 ]) with
                | Error e -> Expect.stringContains e "too many keys in one import" "the fourth key"
                | Ok _ -> failtest "a fourth key passed a cap of 3"
            }
            test "the reader stops at the first key over the cap" {
                // Garbage after the fourth key: the cap answers first, so the reader read no further.
                let head = minimal [ 1; 2; 3; 4 ]
                let bytes = Array.append head[.. head.Length - 3] (Encoding.ASCII.GetBytes ",not json at all")

                match readCapped 3 bytes with
                | Error e -> Expect.stringContains e "more than 3 distinct pubkeys" e
                | Ok _ -> failtest "passed"

                let r = InterchangeReader 3
                let ex = Expect.throwsT<TooManyKeysError> (fun () -> r.Feed(ReadOnlySpan bytes)) "Feed throws"
                ignore ex
            }
            test "the default cap: 100,000 keys pass, 100,001 do not, also through InterchangeStream.read" {
                Expect.equal InterchangeReader.DefaultMaxKeys 100_000 "the default"
                let atCap = minimal (seq { 0..99_999 })

                match InterchangeStream.ofBytes atCap with
                | Ok x -> Expect.equal x.Marks.Length 100_000 "every key"
                | Error e -> failtest e

                let over = minimal (seq { 0..100_000 })
                use ms = new MemoryStream(over, false)

                match InterchangeStream.read ms with
                | Error e ->
                    Expect.stringContains e "too many keys in one import" e
                    Expect.stringContains e "split it" e
                | Ok _ -> failtest "100,001 keys passed"
            }
            test "the import body: over the cap is TooManyKeys, at the cap the marks come out" {
                let body keys = bodyOf (minimal keys) false

                for size in [ 1; 7; 4096 ] do
                    match readBodyCapped (body [ 1; 2; 3; 2 ]) (fun () -> size) Int64.MaxValue 3 with
                    | Ok { History = ValueSome x } -> Expect.equal x.Marks.Length 3 $"at the cap, chunks of {size}"
                    | other -> failtestf "at the cap, chunks of %d: %A" size other

                    match readBodyCapped (body [ 1; 2; 3; 4 ]) (fun () -> size) Int64.MaxValue 3 with
                    | Error(ImportBody.ReadError.TooManyKeys 3) -> ()
                    | other -> failtestf "over the cap, chunks of %d: %A" size other
            }
        ]

// ---- A large complete history: memory stays flat ----

/// The import body for `keys` keys with `perKey` blocks and attestations each, written as it is
/// read: the interchange with signing roots, as a JSON string with \" escapes. Allocates
/// nothing per read.
type HistoryBody(keys: int, perKey: int) =
    inherit Stream()
    let piece = Array.zeroCreate<byte> 512
    let mutable len = 0
    let mutable at = 0
    // -1 head, then per key: 0 entry head, 1 blocks, 2 between, 3 attestations, 4 entry tail; 5 foot, 6 end.
    let mutable phase = -1
    let mutable key = 0
    let mutable item = 0
    let mutable total = 0L

    let num (v: int) =
        let mutable n = 0

        if not (Utf8Formatter.TryFormat(v, Span(piece, len, 20), &n)) then
            failwith "format"

        len <- len + n

    let hex64 (v: int) =
        piece[len] <- byte '0'
        piece[len + 1] <- byte 'x'
        len <- len + 2

        for i in 0..63 do
            let d = if i < 56 then 0 else (v >>> (4 * (63 - i))) &&& 0xF
            piece[len] <- byte (if d < 10 then 48 + d else 87 + d)
            len <- len + 1

    let keyHex (k: int) =
        piece[len] <- byte '0'
        piece[len + 1] <- byte 'x'
        len <- len + 2

        for i in 0..95 do
            let d = (k + i) &&& 0xF
            piece[len] <- byte (if d < 10 then 48 + d else 87 + d)
            len <- len + 1
    // The fixed parts, with ' for an escaped quote.
    let q (t: string) = Encoding.ASCII.GetBytes(t.Replace("'", "\\\""))

    let head =
        Array.append
            (Encoding.ASCII.GetBytes "{\"keystores\":[],\"passwords\":[],\"slashing_protection\":\"")
            (q $"{{'metadata':{{'interchange_format_version':'5','genesis_validators_root':'{gvrA.Hex}'}},'data':[")

    let entryHead = q "{'pubkey':'"
    let blocksOpen = q "','signed_blocks':["
    let slotOpen = q "{'slot':'"
    let rootPart = q "','signing_root':'"
    let itemClose = q "'}"
    let attsOpen = q "],'signed_attestations':["
    let sourceOpen = q "{'source_epoch':'"
    let targetPart = q "','target_epoch':'"
    let entryClose = q "]}"
    let foot = Encoding.ASCII.GetBytes "]}\"}"
    let comma = q ","

    let putb (b: byte[]) =
        Buffer.BlockCopy(b, 0, piece, len, b.Length)
        len <- len + b.Length

    let next () =
        len <- 0
        at <- 0

        match phase with
        | -1 ->
            putb head
            phase <- 0
        | 0 ->
            if key > 0 then
                putb comma

            putb entryHead
            keyHex key
            putb blocksOpen
            item <- 0
            phase <- 1
        | 1 ->
            if item > 0 then
                putb comma

            putb slotOpen
            num (item * 32)
            putb rootPart
            hex64 (item + 1)
            putb itemClose
            item <- item + 1

            if item = perKey then
                phase <- 2
        | 2 ->
            putb attsOpen
            item <- 0
            phase <- 3
        | 3 ->
            if item > 0 then
                putb comma

            putb sourceOpen
            num item
            putb targetPart
            num (item + 1)
            putb rootPart
            hex64 (item + 1)
            putb itemClose
            item <- item + 1

            if item = perKey then
                phase <- 4
        | 4 ->
            putb entryClose
            key <- key + 1
            phase <- if key = keys then 5 else 0
        | 5 ->
            putb foot
            phase <- 6
        | _ -> ()

    member _.Total = total
    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = raise (NotSupportedException())

    override _.Position
        with get () = total
        and set _ = raise (NotSupportedException())

    override _.Flush() = ()
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength _ = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())
    override this.Read(buffer: byte[], offset: int, count: int) = this.Read(Span(buffer, offset, count))

    override _.Read(buffer: Span<byte>) =
        let mutable w = 0

        while w < buffer.Length && phase <> 6 do
            if at = len then
                next ()

            let n = min (len - at) (buffer.Length - w)
            Span(piece, at, n).CopyTo(buffer.Slice w)
            at <- at + n
            w <- w + n

        total <- total + int64 w
        w

    override this.ReadAsync(buffer: Memory<byte>, _: CancellationToken) = ValueTask<int>(this.Read buffer.Span)

let private memoryTests =
    testList
        "large history"
        [
            test "a 50 MiB+ complete history imports with flat memory" {
                let keys, perKey = 4, 60_000
                // A first run warms up the array pool and the JIT.
                let warmUp () =
                    use warm = new HistoryBody(1, 10)

                    (ImportBody.read warm Int64.MaxValue 1000 InterchangeReader.DefaultMaxKeys CancellationToken.None)
                        .Result
                    |> ignore

                warmUp ()
                use s = new HistoryBody(keys, perKey)
                let before = GC.GetAllocatedBytesForCurrentThread()
                // The stream completes every read at once, so the whole import runs on this thread.
                let result =
                    (ImportBody.read s Int64.MaxValue 1000 InterchangeReader.DefaultMaxKeys CancellationToken.None)
                        .Result

                let allocated = GC.GetAllocatedBytesForCurrentThread() - before
                Expect.isGreaterThan s.Total (50L <<< 20) "the body is over 50 MiB"

                match result with
                | Ok { History = ValueSome x } ->
                    Expect.equal x.Entries keys "entries"

                    for _, m in x.Marks do
                        Expect.equal m.Block.Value.Slot (uint64 ((perKey - 1) * 32)) "highest slot"
                        Expect.equal m.Attestation.Value.Target (uint64 perKey) "highest target"
                        Expect.equal m.Attestation.Value.Source (uint64 (perKey - 1)) "highest source"
                        Expect.isTrue m.Attestation.Value.Root.IsSome "the root of the highest vote"

                    Expect.isEmpty x.Slashable "safe"
                | other -> failtestf "%A" other

                printfn $"streamed import: {s.Total} body bytes, {allocated} bytes allocated"
                Expect.isLessThan allocated (1L <<< 20) "under 1 MiB allocated for the whole import"
            }
        ]

// ---- eplix slashing export ----

/// A DB with records for keys 1 and 2 (key 1 signed a block at slot 5, key 2 an attestation).
let private exportDb () =
    let db = newDb gvrA

    match
        InterchangeStream.ofBytes (doc (entry 1 (block 5 0) "" + "," + entry 2 "" (att 3 4 0)))
        |> Result.bind db.ImportMarks
    with
    | Ok _ -> db
    | Error e -> failwith e

let private exportFile (db: SlashingDb) (pubkeys: string list option) (file: string) =
    Interchange.exportTo db.HasRecord db.Export pubkeys file

let private exportTests =
    testList
        "slashing export"
        [
            test "named keys with records are written and read back" {
                let db = exportDb ()
                let file = Path.Combine(tempDir (), "out.json")
                File.WriteAllText(file, "old")
                Expect.equal (exportFile db (Some [ keyHex 1 ]) file) (Ok 1) "one key"

                match Interchange.parse (File.ReadAllBytes file) with
                | Ok x ->
                    Expect.equal x.GenesisValidatorsRoot gvrA "genesis validators root"
                    Expect.equal [ for d in x.Data -> d.PubKey.Hex ] [ keyHex 1 ] "only the named key"
                    Expect.equal [ for b in x.Data.Head.SignedBlocks -> b.Slot ] [ 5UL ] "its block"
                | Error e -> failtest e

                Expect.equal (exportFile db None file) (Ok 2) "without --pubkey: every key"
                Expect.isFalse (File.Exists(file + ".tmp")) "no temporary file left"
            }

            test "a bad pubkey is refused and nothing is written" {
                let db = exportDb ()
                let file = Path.Combine(tempDir (), "out.json")

                Expect.equal
                    (exportFile db (Some [ keyHex 1; "0x1234" ]) file)
                    (Error "'0x1234' is not a public key")
                    "a clean error"

                Expect.isFalse (File.Exists file) "no file"
            }

            test "a key without a record is named and nothing is written" {
                let db = exportDb ()
                let file = Path.Combine(tempDir (), "out.json")
                File.WriteAllText(file, "old")

                match exportFile db (Some [ keyHex 1; keyHex 9 ]) file with
                | Error e ->
                    Expect.stringContains e $"no slashing record for {keyHex 9}" "the key is named"
                    Expect.stringContains e "nothing exported" "nothing exported"
                    Expect.isFalse (e.Contains(keyHex 1)) "the key with a record is not named"
                | Ok n -> failtestf "exported %d keys" n

                Expect.equal (File.ReadAllText file) "old" "the old file is kept"
            }

            test "a failed write leaves the old file or none, never part of one" {
                let db = exportDb ()
                // A directory that does not exist: a clean error, no file.
                let missing = Path.Combine(tempDir (), "no-such-dir", "out.json")

                match exportFile db None missing with
                | Error e -> Expect.stringContains e $"writing {missing}" "the file is named"
                | Ok _ -> failtest "written into a missing directory"

                Expect.isFalse (File.Exists missing) "no file"
                // A directory the VC cannot write to (Linux, not root): the old file stays whole and
                // no temporary file is left.
                if OperatingSystem.IsLinux() && Environment.UserName <> "root" then
                    let dir = tempDir ()
                    let file = Path.Combine(dir, "out.json")
                    File.WriteAllText(file, "old")
                    File.SetUnixFileMode(dir, UnixFileMode.UserRead ||| UnixFileMode.UserExecute)

                    try
                        match exportFile db None file with
                        | Error e -> Expect.stringContains e $"writing {file}" "a clean error"
                        | Ok _ -> failtest "written into a read-only directory"

                        Expect.equal (File.ReadAllText file) "old" "the old file is kept whole"
                        Expect.isFalse (File.Exists(file + ".tmp")) "no temporary file"
                    finally
                        File.SetUnixFileMode(
                            dir,
                            UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
                        )
            }
        ]

[<Tests>]
let tests =
    testList
        "interchange stream"
        [
            unescaperTests
            vectorTests
            readerTests
            bodyTests
            capTests
            memoryTests
            exportTests
        ]
