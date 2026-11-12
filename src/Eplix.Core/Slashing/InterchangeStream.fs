/// EIP-3076 interchange read a chunk at a time. InterchangeReader keeps per key
/// only the marks an import merges: the highest block slot and the highest source and target,
/// each with the signing root Interchange.marksOf would keep. Its memory is a 64 KiB token buffer
/// and one entry per key, whatever the size of the history. JsonStringUnescaper turns the escaped
/// content of a JSON string back into UTF-8 a chunk at a time, so the keymanager import can feed
/// the interchange it gets as a string inside its JSON body into the reader.
namespace Eplix.Slashing

open System
open System.Collections.Generic
open System.IO
open System.Text.Json
open Eplix
open Eplix.Json

module internal HexDigit =
    /// The value of one hex digit, or -1.
    let value (b: byte) : int =
        if b >= '0'B && b <= '9'B then int (b - '0'B)
        elif b >= 'a'B && b <= 'f'B then int (b - 'a'B) + 10
        elif b >= 'A'B && b <= 'F'B then int (b - 'A'B) + 10
        else -1

/// The content of a JSON string after its opening quote, unescaped as it arrives. Decodes what
/// System.Text.Json's GetString decodes, to the same bytes: the escapes of RFC 8259 and a
/// surrogate pair from two \u escapes. Fails (JsonDecodeError) where GetString fails: another
/// escape, a lone surrogate, a raw control character, invalid UTF-8.
[<Sealed>]
type JsonStringUnescaper() =
    // 0 plain, 1 after '\', 2 in the hex digits of \u, 3 a high surrogate waits for '\',
    // 4 a high surrogate and '\' wait for 'u', 5 past the closing quote.
    let mutable mode = 0
    let mutable hexLeft = 0
    let mutable code = 0
    let mutable high = 0
    // Continuation bytes still due in a raw UTF-8 sequence, and the range of the next one.
    let mutable utf8Left = 0
    let mutable lo = 0x80uy
    let mutable hi = 0xBFuy

    static member private Put(cp: int, dst: Span<byte>, at: int) : int =
        if cp < 0x80 then
            dst[at] <- byte cp
            at + 1
        elif cp < 0x800 then
            dst[at] <- byte (0xC0 ||| (cp >>> 6))
            dst[at + 1] <- byte (0x80 ||| (cp &&& 0x3F))
            at + 2
        elif cp < 0x10000 then
            dst[at] <- byte (0xE0 ||| (cp >>> 12))
            dst[at + 1] <- byte (0x80 ||| ((cp >>> 6) &&& 0x3F))
            dst[at + 2] <- byte (0x80 ||| (cp &&& 0x3F))
            at + 3
        else
            dst[at] <- byte (0xF0 ||| (cp >>> 18))
            dst[at + 1] <- byte (0x80 ||| ((cp >>> 12) &&& 0x3F))
            dst[at + 2] <- byte (0x80 ||| ((cp >>> 6) &&& 0x3F))
            dst[at + 3] <- byte (0x80 ||| (cp &&& 0x3F))
            at + 4

    /// True once the closing quote is read.
    member _.Done = mode = 5

    /// Reads escaped bytes from `src` up to the closing quote and writes the unescaped bytes to
    /// `dst`. Stops after the quote, at the end of `src`, or when `dst` has fewer than 8 bytes
    /// free. Returns the bytes read (the quote included) and the bytes written.
    member _.Run(src: ReadOnlySpan<byte>, dst: Span<byte>) : struct (int * int) =
        let mutable i = 0
        let mutable w = 0

        while mode <> 5 && i < src.Length && dst.Length - w >= 8 do
            let b = src[i]
            i <- i + 1

            match mode with
            | 0 ->
                if utf8Left > 0 then
                    if b < lo || b > hi then
                        fail "invalid UTF-8 in a string"

                    dst[w] <- b
                    w <- w + 1
                    utf8Left <- utf8Left - 1
                    lo <- 0x80uy
                    hi <- 0xBFuy
                elif b = '"'B then
                    mode <- 5
                elif b = '\\'B then
                    mode <- 1
                elif b < 0x20uy then
                    fail "a control character in a string must be escaped"
                else
                    if b >= 0x80uy then
                        // The lead byte sets the length and the range of the second byte (RFC 3629).
                        if b >= 0xC2uy && b <= 0xDFuy then
                            utf8Left <- 1
                        elif b = 0xE0uy then
                            utf8Left <- 2
                            lo <- 0xA0uy
                        elif (b >= 0xE1uy && b <= 0xECuy) || b = 0xEEuy || b = 0xEFuy then
                            utf8Left <- 2
                        elif b = 0xEDuy then
                            utf8Left <- 2
                            hi <- 0x9Fuy
                        elif b = 0xF0uy then
                            utf8Left <- 3
                            lo <- 0x90uy
                        elif b >= 0xF1uy && b <= 0xF3uy then
                            utf8Left <- 3
                        elif b = 0xF4uy then
                            utf8Left <- 3
                            hi <- 0x8Fuy
                        else
                            fail "invalid UTF-8 in a string"

                    dst[w] <- b
                    w <- w + 1
            | 1 ->
                mode <- 0

                let one =
                    match b with
                    | '"'B
                    | '\\'B
                    | '/'B -> int b
                    | 'b'B -> 8
                    | 'f'B -> 12
                    | 'n'B -> 10
                    | 'r'B -> 13
                    | 't'B -> 9
                    | 'u'B -> -1
                    | _ -> fail $"invalid escape '\\{char b}' in a string"

                if one >= 0 then
                    dst[w] <- byte one
                    w <- w + 1
                else
                    mode <- 2
                    hexLeft <- 4
                    code <- 0
            | 2 ->
                let d = HexDigit.value b

                if d < 0 then
                    fail "\\u needs four hex digits"

                code <- code * 16 + d
                hexLeft <- hexLeft - 1

                if hexLeft = 0 then
                    mode <- 0

                    if high <> 0 then
                        if code < 0xDC00 || code > 0xDFFF then
                            fail "a high surrogate without its low surrogate"

                        w <- JsonStringUnescaper.Put(0x10000 + ((high - 0xD800) <<< 10) + (code - 0xDC00), dst, w)
                        high <- 0
                    elif code >= 0xD800 && code <= 0xDBFF then
                        high <- code
                        mode <- 3
                    elif code >= 0xDC00 && code <= 0xDFFF then
                        fail "a low surrogate without its high surrogate"
                    else
                        w <- JsonStringUnescaper.Put(code, dst, w)
            | 3 ->
                if b <> '\\'B then
                    fail "a high surrogate without its low surrogate"

                mode <- 4
            | _ ->
                if b <> 'u'B then
                    fail "a high surrogate without its low surrogate"

                mode <- 2
                hexLeft <- 4
                code <- 0

        struct (i, w)

/// What an interchange holds for an import: per key, the marks of all its entries merged.
type InterchangeMarks =
    {
        GenesisValidatorsRoot: Root
        /// Entries in the data array; a key listed twice counts twice.
        Entries: int
        /// One per key, in the order of each key's first entry.
        Marks: (PubKey * KeyMarks) list
        /// Keys whose history holds a slashable pair the reader saw (a partial check).
        Slashable: PubKey list
    }

module internal InterchangeStates =
    [<Literal>]
    let SStart = 0

    [<Literal>]
    let SRoot = 1

    [<Literal>]
    let SMetaOpen = 2

    [<Literal>]
    let SMeta = 3

    [<Literal>]
    let SMetaVersion = 4

    [<Literal>]
    let SMetaGvr = 5

    [<Literal>]
    let SDataOpen = 6

    [<Literal>]
    let SData = 7

    [<Literal>]
    let SEntry = 8

    [<Literal>]
    let SEntryPubkey = 9

    [<Literal>]
    let SBlocksOpen = 10

    [<Literal>]
    let SBlocks = 11

    [<Literal>]
    let SBlock = 12

    [<Literal>]
    let SAttsOpen = 13

    [<Literal>]
    let SAtts = 14

    [<Literal>]
    let SAtt = 15

    [<Literal>]
    let SItemA = 16

    [<Literal>]
    let SItemB = 17

    [<Literal>]
    let SItemRoot = 18

    [<Literal>]
    let SSkipValue = 19

    [<Literal>]
    let SSkip = 20

    [<Literal>]
    let SEnd = 21

    let metadata = "metadata"B
    let data = "data"B
    let version = "interchange_format_version"B
    let gvr = "genesis_validators_root"B
    let pubkey = "pubkey"B
    let blocks = "signed_blocks"B
    let atts = "signed_attestations"B
    let slot = "slot"B
    let source = "source_epoch"B
    let target = "target_epoch"B
    let signingRoot = "signing_root"B

open InterchangeStates

/// An interchange with more distinct public keys than the reader takes.
type TooManyKeysError(limit: int) =
    inherit
        Exception(
            $"too many keys in one import: more than {limit} distinct pubkeys in the interchange; split it into several imports"
        )

    member _.Limit = limit

/// Reads an EIP-3076 interchange, complete or minimal form, fed a chunk at a time. Accepts what
/// Interchange.parse accepts and gives the marks Interchange.marksOf gives, merged per key with
/// Marks.mergeBlock and Marks.mergeAttestation. A field the reader uses may appear once per
/// object; it skips other fields. Errors are JsonDecodeError or JsonException, and
/// TooManyKeysError at the first entry of a key past `maxKeys` distinct keys.
[<Sealed>]
type InterchangeReader(maxKeys: int) =
    let buf: byte[] = Array.zeroCreate 65536
    let mutable filled = 0
    let mutable json = JsonReaderState(JsonReaderOptions(MaxDepth = 64))
    let mutable st = SStart
    let mutable skipReturn = 0
    let mutable skipDepth = 0
    // Fields seen in the current object (bits; an item's bits sit below its entry's), and the
    // state a field's value returns to.
    let mutable seen = 0
    let mutable itemReturn = 0
    let scratch: byte[] = Array.zeroCreate 256
    // The file.
    let mutable metaSeen = false
    let mutable dataSeen = false
    let mutable version: string = ""
    let mutable gvr = ValueNone
    let mutable entries = 0
    let marks = Dictionary<PubKey, KeyMarks>()
    let order = List<PubKey>()
    let slashable = HashSet<PubKey>()
    let slashableOrder = List<PubKey>()
    // The current entry: its key, whether it holds a slashable pair, and its running marks.
    let mutable entryKey = ValueNone
    let mutable entrySlashable = false
    let mutable bHas = false
    let mutable bSlot = 0UL
    let mutable bRootKnown = false
    let bRoot: byte[] = Array.zeroCreate 32
    let mutable aHas = false
    let mutable aSource = 0UL
    let mutable aTarget = 0UL
    let mutable aRootSource = 0UL
    let mutable aRootKnown = false
    let aRoot: byte[] = Array.zeroCreate 32
    // The current block (A = slot) or attestation (A = source, B = target).
    let mutable iA = 0UL
    let mutable iB = 0UL
    let mutable iRootKnown = false
    let iRoot: byte[] = Array.zeroCreate 32

    let flag (key: PubKey) =
        if slashable.Add key then
            slashableOrder.Add key

    let sameRoot (a: byte[]) (b: byte[]) = a.AsSpan().SequenceEqual(ReadOnlySpan b)

    /// Marks.mergeBlock on the entry's running block mark, after the in-file check.
    let applyBlock () =
        if bHas && iA = bSlot && iRootKnown && bRootKnown && not (sameRoot iRoot bRoot) then
            entrySlashable <- true

        if not bHas || iA > bSlot then
            bHas <- true
            bSlot <- iA
            bRootKnown <- iRootKnown
            Buffer.BlockCopy(iRoot, 0, bRoot, 0, 32)
        elif iA = bSlot && not (bRootKnown = iRootKnown && (not iRootKnown || sameRoot iRoot bRoot)) then
            bRootKnown <- false

    /// Marks.mergeAttestation on the entry's running attestation mark, after the in-file check
    /// against the vote at the highest target.
    let applyAttestation () =
        let s = iA
        let t = iB

        if s > t then
            entrySlashable <- true

        if aHas then
            if t = aTarget && (s <> aRootSource || (iRootKnown && aRootKnown && not (sameRoot iRoot aRoot))) then
                entrySlashable <- true

            if (s < aRootSource && t > aTarget) || (s > aRootSource && t < aTarget) then
                entrySlashable <- true

        if not aHas then
            aHas <- true
            aSource <- s
            aTarget <- t
            aRootSource <- s
            aRootKnown <- iRootKnown
            Buffer.BlockCopy(iRoot, 0, aRoot, 0, 32)
        else
            let source = max aSource s

            if t > aTarget then
                aTarget <- t
                aRootSource <- s
                aRootKnown <- iRootKnown
                Buffer.BlockCopy(iRoot, 0, aRoot, 0, 32)
            elif t = aTarget then
                let sameVote = aRootSource = s && aRootKnown = iRootKnown && (not iRootKnown || sameRoot iRoot aRoot)

                if not sameVote then
                    aRootKnown <- false

            aSource <- source

    /// Two marks of one key that cannot both come from one safe history.
    let conflict (a: KeyMarks) (b: KeyMarks) =
        let blocks =
            match a.Block, b.Block with
            | ValueSome x, ValueSome y -> x.Slot = y.Slot && x.Root.IsSome && y.Root.IsSome && x.Root <> y.Root
            | _ -> false

        let votes =
            match a.Attestation, b.Attestation with
            | ValueSome x, ValueSome y ->
                (x.Target = y.Target
                 && (x.RootSource <> y.RootSource || (x.Root.IsSome && y.Root.IsSome && x.Root <> y.Root)))
                || (x.RootSource < y.RootSource && x.Target > y.Target)
                || (x.RootSource > y.RootSource && x.Target < y.Target)
            | _ -> false

        blocks || votes

    let beginEntry () =
        entryKey <- ValueNone
        entrySlashable <- false
        bHas <- false
        bRootKnown <- false
        aHas <- false
        aRootKnown <- false
        seen <- 0

    let endEntry () =
        let key =
            match entryKey with
            | ValueSome k -> k
            | ValueNone -> fail "missing field 'pubkey'"

        if seen &&& 2 = 0 then
            fail "missing field 'signed_blocks'"

        if seen &&& 4 = 0 then
            fail "missing field 'signed_attestations'"

        let root (known: bool) (b: byte[]) = if known then ValueSome(Root.Of(Array.copy b)) else ValueNone

        let m =
            {
                Block =
                    (if bHas then
                         ValueSome
                             {
                                 Slot = bSlot
                                 Root = root bRootKnown bRoot
                             }
                     else
                         ValueNone)
                Attestation =
                    if aHas then
                        ValueSome
                            {
                                Source = aSource
                                Target = aTarget
                                Root = root aRootKnown aRoot
                                RootSource = aRootSource
                            }
                    else
                        ValueNone
            }

        entries <- entries + 1

        match marks.TryGetValue key with
        | true, before ->
            if conflict before m then
                flag key

            let mutable after = before
            m.Block |> ValueOption.iter (fun b -> after <- Marks.mergeBlock after b)
            m.Attestation |> ValueOption.iter (fun a -> after <- Marks.mergeAttestation after a)
            marks[key] <- after
        | _ ->
            if order.Count >= maxKeys then
                raise (TooManyKeysError maxKeys)

            marks[key] <- m
            order.Add key

        if entrySlashable then
            flag key

    /// Marks field `bit` of the current object as seen; a second one fails.
    let once (bit: int) (name: string) =
        if seen &&& bit <> 0 then
            fail $"field '{name}' appears twice"

        seen <- seen ||| bit

    /// Copies the string value into scratch, unescaped; returns its length.
    member private _.Text(r: byref<Utf8JsonReader>) : int =
        if r.TokenType <> JsonTokenType.String then
            fail "expected a string"

        if r.ValueSpan.Length > scratch.Length then
            fail "a string value is too long"

        if r.ValueIsEscaped then
            r.CopyString(Span scratch)
        else
            r.ValueSpan.CopyTo(Span scratch)
            r.ValueSpan.Length

    /// A uint64 as Json.u64 reads it: a decimal string or a JSON number.
    member private this.U64(r: byref<Utf8JsonReader>) : uint64 =
        match r.TokenType with
        | JsonTokenType.String ->
            let n = this.Text(&r)

            if n = 0 then
                fail "expected a decimal uint64 string"

            let mutable v = 0UL

            for i in 0 .. n - 1 do
                let d = scratch[i]

                if d < '0'B || d > '9'B then
                    fail "expected a decimal uint64 string"

                let digit = uint64 (d - '0'B)

                if v > (UInt64.MaxValue - digit) / 10UL then
                    fail "expected a decimal uint64 string"

                v <- v * 10UL + digit

            v
        | JsonTokenType.Number ->
            match r.TryGetUInt64() with
            | true, v -> v
            | _ -> fail "expected a uint64"
        | _ -> fail "expected a uint64"

    /// 0x-hex of exactly dst.Length bytes into dst, as Hex.tryDecodeFixed reads it.
    member private this.HexInto(r: byref<Utf8JsonReader>, dst: byte[], what: string) =
        let n = this.Text(&r)
        let ok = n = 2 + 2 * dst.Length && scratch[0] = '0'B && (scratch[1] = 'x'B || scratch[1] = 'X'B)

        if not ok then
            fail $"expected {what} as 0x-hex"

        for i in 0 .. dst.Length - 1 do
            let h = HexDigit.value scratch[2 + 2 * i]
            let l = HexDigit.value scratch[3 + 2 * i]

            if h < 0 || l < 0 then
                fail $"expected {what} as 0x-hex"

            dst[i] <- byte ((h <<< 4) ||| l)

    member private this.Token(r: byref<Utf8JsonReader>) =
        let t = r.TokenType

        match st with
        | SSkipValue ->
            if t = JsonTokenType.StartObject || t = JsonTokenType.StartArray then
                skipDepth <- 1
                st <- SSkip
            else
                st <- skipReturn
        | SSkip ->
            if t = JsonTokenType.StartObject || t = JsonTokenType.StartArray then
                skipDepth <- skipDepth + 1
            elif t = JsonTokenType.EndObject || t = JsonTokenType.EndArray then
                skipDepth <- skipDepth - 1

                if skipDepth = 0 then
                    st <- skipReturn
        | SStart ->
            if t <> JsonTokenType.StartObject then
                fail "expected an object around 'metadata'"

            st <- SRoot
        | SRoot ->
            if t = JsonTokenType.EndObject then
                st <- SEnd
            elif r.ValueTextEquals(ReadOnlySpan metadata) then
                if metaSeen then
                    fail "field 'metadata' appears twice"

                metaSeen <- true
                st <- SMetaOpen
            elif r.ValueTextEquals(ReadOnlySpan data) then
                if dataSeen then
                    fail "field 'data' appears twice"

                dataSeen <- true
                st <- SDataOpen
            else
                skipReturn <- SRoot
                st <- SSkipValue
        | SMetaOpen ->
            if t <> JsonTokenType.StartObject then
                fail "expected an object around 'interchange_format_version'"

            seen <- 0
            st <- SMeta
        | SMeta ->
            if t = JsonTokenType.EndObject then
                if seen &&& 1 = 0 then
                    fail "missing field 'interchange_format_version'"

                if version <> Interchange.formatVersion then
                    fail $"interchange_format_version {version} is not supported"

                if seen &&& 2 = 0 then
                    fail "missing field 'genesis_validators_root'"

                st <- SRoot
            elif r.ValueTextEquals(ReadOnlySpan InterchangeStates.version) then
                once 1 "interchange_format_version"
                st <- SMetaVersion
            elif r.ValueTextEquals(ReadOnlySpan InterchangeStates.gvr) then
                once 2 "genesis_validators_root"
                st <- SMetaGvr
            else
                skipReturn <- SMeta
                st <- SSkipValue
        | SMetaVersion ->
            if t <> JsonTokenType.String then
                fail "expected a string"

            version <- nonNull (r.GetString())
            st <- SMeta
        | SMetaGvr ->
            let b = Array.zeroCreate 32
            this.HexInto(&r, b, "a 32-byte root")
            gvr <- ValueSome(Root.Of b)
            st <- SMeta
        | SDataOpen ->
            if t <> JsonTokenType.StartArray then
                fail "expected an array"

            st <- SData
        | SData ->
            if t = JsonTokenType.EndArray then
                st <- SRoot
            elif t = JsonTokenType.StartObject then
                beginEntry ()
                st <- SEntry
            else
                fail "expected an object around 'pubkey'"
        | SEntry ->
            if t = JsonTokenType.EndObject then
                endEntry ()
                st <- SData
            elif r.ValueTextEquals(ReadOnlySpan pubkey) then
                once 1 "pubkey"
                st <- SEntryPubkey
            elif r.ValueTextEquals(ReadOnlySpan blocks) then
                once 2 "signed_blocks"
                st <- SBlocksOpen
            elif r.ValueTextEquals(ReadOnlySpan atts) then
                once 4 "signed_attestations"
                st <- SAttsOpen
            else
                skipReturn <- SEntry
                st <- SSkipValue
        | SEntryPubkey ->
            let b = Array.zeroCreate 48
            this.HexInto(&r, b, "a 48-byte public key")
            entryKey <- ValueSome(PubKey.Of b)
            st <- SEntry
        | SBlocksOpen ->
            if t <> JsonTokenType.StartArray then
                fail "expected an array"

            st <- SBlocks
        | SAttsOpen ->
            if t <> JsonTokenType.StartArray then
                fail "expected an array"

            st <- SAtts
        | SBlocks
        | SAtts ->
            let isBlocks = st = SBlocks

            if t = JsonTokenType.EndArray then
                st <- SEntry
            elif t = JsonTokenType.StartObject then
                // The entry's bits move up so the item's own fields start at zero.
                seen <- seen <<< 8
                iRootKnown <- false
                st <- (if isBlocks then SBlock else SAtt)
            else
                fail (
                    if isBlocks then "expected an object around 'slot'" else "expected an object around 'source_epoch'"
                )
        | SBlock
        | SAtt ->
            let isBlock = st = SBlock

            if t = JsonTokenType.EndObject then
                if isBlock then
                    if seen &&& 1 = 0 then
                        fail "missing field 'slot'"

                    applyBlock ()
                else
                    if seen &&& 1 = 0 then
                        fail "missing field 'source_epoch'"

                    if seen &&& 2 = 0 then
                        fail "missing field 'target_epoch'"

                    applyAttestation ()

                seen <- seen >>> 8
                st <- (if isBlock then SBlocks else SAtts)
            else
                itemReturn <- st

                if isBlock && r.ValueTextEquals(ReadOnlySpan slot) then
                    once 1 "slot"
                    st <- SItemA
                elif not isBlock && r.ValueTextEquals(ReadOnlySpan source) then
                    once 1 "source_epoch"
                    st <- SItemA
                elif not isBlock && r.ValueTextEquals(ReadOnlySpan target) then
                    once 2 "target_epoch"
                    st <- SItemB
                elif r.ValueTextEquals(ReadOnlySpan signingRoot) then
                    once 4 "signing_root"
                    st <- SItemRoot
                else
                    skipReturn <- st
                    st <- SSkipValue
        | SItemA ->
            iA <- this.U64(&r)
            st <- itemReturn
        | SItemB ->
            iB <- this.U64(&r)
            st <- itemReturn
        | SItemRoot ->
            // A null or all-zero root is unknown, as in Interchange.parse.
            if t = JsonTokenType.Null then
                iRootKnown <- false
            else
                this.HexInto(&r, iRoot, "a 32-byte root")
                iRootKnown <- iRoot.AsSpan().IndexOfAnyExcept(0uy) >= 0

            st <- itemReturn
        | _ -> ()

    member private this.Parse(isFinal: bool) =
        let mutable r = Utf8JsonReader(ReadOnlySpan(buf, 0, filled), isFinal, json)

        while r.Read() do
            this.Token(&r)

        json <- r.CurrentState
        let used = int r.BytesConsumed
        Buffer.BlockCopy(buf, used, buf, 0, filled - used)
        filled <- filled - used

    new() = InterchangeReader(InterchangeReader.DefaultMaxKeys)

    /// The default cap on distinct keys in one interchange. It bounds the memory of a read and the time the merge holds the DB key lock.
    static member DefaultMaxKeys = 100_000

    /// The largest JSON token the reader holds.
    static member TokenLimit = 65536

    /// Reads the next bytes of the interchange.
    member this.Feed(data: ReadOnlySpan<byte>) =
        let mutable rest = data

        while not rest.IsEmpty do
            let n = min rest.Length (buf.Length - filled)
            rest.Slice(0, n).CopyTo(Span(buf, filled, n))
            filled <- filled + n
            rest <- rest.Slice n
            this.Parse false

            if filled = buf.Length then
                fail $"a JSON token over {buf.Length} bytes"

    /// Reads what is left and returns the marks.
    member this.Finish() : InterchangeMarks =
        this.Parse true

        if st <> SEnd then
            fail "the interchange ends early"

        if not metaSeen then
            fail "missing field 'metadata'"

        if not dataSeen then
            fail "missing field 'data'"

        {
            GenesisValidatorsRoot = gvr.Value
            Entries = entries
            Marks = [ for k in order -> k, marks[k] ]
            Slashable = List.ofSeq slashableOrder
        }

module InterchangeStream =
    /// Reads an interchange from a stream, 64 KiB at a time, with at most `maxKeys` distinct
    /// keys; past that it stops reading.
    let readCapped (maxKeys: int) (s: Stream) : Result<InterchangeMarks, string> =
        try
            let reader = InterchangeReader maxKeys
            let chunk = Array.zeroCreate<byte> 65536
            let mutable n = s.Read(chunk, 0, chunk.Length)

            while n > 0 do
                reader.Feed(ReadOnlySpan(chunk, 0, n))
                n <- s.Read(chunk, 0, chunk.Length)

            Ok(reader.Finish())
        with
        | :? JsonDecodeError as e -> Error e.Message
        | :? JsonException as e -> Error e.Message
        | :? InvalidOperationException as e -> Error e.Message
        | :? TooManyKeysError as e -> Error e.Message

    /// readCapped with InterchangeReader.DefaultMaxKeys.
    let read (s: Stream) = readCapped InterchangeReader.DefaultMaxKeys s

    let ofBytes (bytes: byte[]) : Result<InterchangeMarks, string> =
        use ms = new MemoryStream(bytes, false)
        read ms
