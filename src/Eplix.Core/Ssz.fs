/// A schema-driven SSZ codec: one generic encoder, decoder and hash_tree_root over a type description.
/// Containers.fs maps typed F# records to and from SszValue.
module Eplix.Ssz

open System
open System.Buffers
open System.Buffers.Binary
open System.Numerics
open System.Runtime.CompilerServices
open System.Runtime.InteropServices
open System.Runtime.Intrinsics
open System.Runtime.Intrinsics.X86
open System.Security.Cryptography

type SszType =
    /// Unsigned integer of 1, 2, 4 or 8 bytes.
    | Uint of size: int
    /// uint256, held as 32 little-endian bytes in a Bytes value.
    | Uint256
    | Boolean
    | ByteVector of length: int
    | ByteList of limit: int
    | Bitvector of length: int
    | Bitlist of limit: int
    | Vector of elem: SszType * length: int
    | List of elem: SszType * limit: int
    | Container of fields: (string * SszType)[]
    /// EIP-7916 ProgressiveList: no limit, progressive merkleization.
    | ProgressiveList of elem: SszType
    /// ProgressiveList[Byte], held as a Bytes value (Gloas transactions, block access list).
    | ProgressiveByteList
    /// EIP-7916 ProgressiveBitList.
    | ProgressiveBitlist
    /// EIP-7495 ProgressiveContainer with every field active (active_fields(width=n) in Gloas).
    | ProgressiveContainer of fields: (string * SszType)[]

type SszValue =
    | U of uint64
    | Bool of bool
    | Bytes of byte[]
    | Bits of bool[]
    | Items of SszValue[]
    | Fields of SszValue[]

/// A plain .NET exception: F# `exception` types format their Message through reflection, which NativeAOT cannot keep.
type SszError(message: string) =
    inherit Exception(message)

let private fail msg = raise (SszError msg)

let rec fixedSize (t: SszType) : int voption =
    match t with
    | Uint n -> ValueSome n
    | Uint256 -> ValueSome 32
    | Boolean -> ValueSome 1
    | ByteVector n -> ValueSome n
    | Bitvector n -> ValueSome((n + 7) / 8)
    | ByteList _
    | Bitlist _
    | List _
    | ProgressiveList _
    | ProgressiveByteList
    | ProgressiveBitlist -> ValueNone
    | Vector(e, n) -> fixedSize e |> ValueOption.map (fun s -> s * n)
    | Container fields
    | ProgressiveContainer fields ->
        let mutable total = 0
        let mutable isFixed = true

        for _, ft in fields do
            match fixedSize ft with
            | ValueSome s -> total <- total + s
            | ValueNone -> isFixed <- false

        if isFixed then ValueSome total else ValueNone

let private isBasic t =
    match t with
    | Uint _
    | Uint256
    | Boolean -> true
    | _ -> false

let private slotSize t =
    match fixedSize t with
    | ValueSome s -> s
    | ValueNone -> 4

/// Packs `bits` into `dst`, bit i at bit i % 8 of byte i / 8, and clears the rest of the bytes it
/// touches. 16 bits at a time: each bool is a byte 0 or 1, so shifted to the top bit of its byte
/// it becomes one bit of ExtractMostSignificantBits. An attestation has 31,000 bits on mainnet.
let private packInto (bits: bool[]) (dst: Span<byte>) =
    let src = Runtime.InteropServices.MemoryMarshal.Cast<bool, byte>(ReadOnlySpan bits)
    let mutable i = 0

    while i + 16 <= src.Length do
        let v: Runtime.Intrinsics.Vector128<byte> = Runtime.Intrinsics.Vector128.Create<byte>(src.Slice(i, 16))
        let mask = Runtime.Intrinsics.Vector128.ExtractMostSignificantBits(v <<< 7)
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(i / 8, 2), uint16 mask)
        i <- i + 16

    dst.Slice(i / 8).Clear()

    while i < src.Length do
        if bits[i] then
            dst[i / 8] <- dst[i / 8] ||| (1uy <<< (i % 8))

        i <- i + 1

let private packBits (bits: bool[]) (extra: int) : byte[] =
    let bytes = Array.zeroCreate<byte>((bits.Length + extra + 7) / 8)
    packInto bits (Span bytes)
    bytes

// ---- Serialization ----

/// The encoded size of a value that matches its schema. A value that does not match counts as 0
/// bytes; writeAt then fails on it before it writes there.
let rec private sizeOf (t: SszType) (v: SszValue) : int =
    match t, v with
    | Uint n, _ -> n
    | Uint256, _ -> 32
    | Boolean, _ -> 1
    | (ByteVector _ | ByteList _ | ProgressiveByteList), Bytes b -> b.Length
    | Bitvector _, Bits bits -> (bits.Length + 7) / 8
    | (Bitlist _ | ProgressiveBitlist), Bits bits -> bits.Length / 8 + 1
    | (Vector(e, _) | List(e, _) | ProgressiveList e), Items items ->
        match fixedSize e with
        | ValueSome s -> s * items.Length
        | ValueNone ->
            let mutable total = 0

            for item in items do
                total <- total + 4 + sizeOf e item

            total
    | (Container fields | ProgressiveContainer fields), Fields values when fields.Length = values.Length ->
        let mutable total = 0

        for i in 0 .. fields.Length - 1 do
            let ft = snd fields[i]

            total <-
                total
                + (match fixedSize ft with
                   | ValueSome s -> s
                   | ValueNone -> 4 + sizeOf ft values[i])

        total
    | _ -> 0

/// Writes `v` at `pos` and returns the position after it.
let rec private writeAt (t: SszType) (v: SszValue) (buf: byte[]) (pos: int) : int =
    match t, v with
    | Uint n, U x ->
        if n < 8 && (x >>> (8 * n)) <> 0UL then
            fail $"uint{8 * n} overflow"

        for i in 0 .. n - 1 do
            buf[pos + i] <- byte (x >>> (8 * i))

        pos + n
    | Uint256, Bytes b ->
        if b.Length <> 32 then
            fail "uint256 needs 32 bytes"

        copyAt b buf pos
    | Boolean, Bool b ->
        buf[pos] <- if b then 1uy else 0uy
        pos + 1
    | ByteVector n, Bytes b ->
        if b.Length <> n then
            fail $"ByteVector[{n}] got {b.Length} bytes"

        copyAt b buf pos
    | ByteList n, Bytes b ->
        if b.Length > n then
            fail $"ByteList[{n}] got {b.Length} bytes"

        copyAt b buf pos
    | Bitvector n, Bits bits ->
        if bits.Length <> n then
            fail $"Bitvector[{n}] got {bits.Length} bits"

        writeBits bits false buf pos
    | Bitlist n, Bits bits ->
        if bits.Length > n then
            fail $"Bitlist[{n}] got {bits.Length} bits"

        writeBits bits true buf pos
    | ProgressiveBitlist, Bits bits -> writeBits bits true buf pos
    | ProgressiveByteList, Bytes b -> copyAt b buf pos
    | ProgressiveList e, Items items -> writeItems e items buf pos
    | ProgressiveContainer fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        writeFields fields values buf pos
    | Vector(e, n), Items items ->
        if items.Length <> n then
            fail $"Vector length {n} got {items.Length}"

        writeItems e items buf pos
    | List(e, n), Items items ->
        if items.Length > n then
            fail $"List limit {n} got {items.Length}"

        writeItems e items buf pos
    | Container fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        writeFields fields values buf pos
    | _ -> fail "value does not match schema"

and private copyAt (b: byte[]) (buf: byte[]) (pos: int) =
    Buffer.BlockCopy(b, 0, buf, pos, b.Length)
    pos + b.Length

/// Packed bits, then for a bitlist one delimiter bit.
and private writeBits (bits: bool[]) (delimiter: bool) (buf: byte[]) (pos: int) =
    let len = if delimiter then bits.Length / 8 + 1 else (bits.Length + 7) / 8
    packInto bits (buf.AsSpan(pos, len))

    if delimiter then
        let i = bits.Length
        buf[pos + i / 8] <- buf[pos + i / 8] ||| (1uy <<< (i % 8))

    pos + len

/// Elements of one type: fixed-size ones back to back, variable-size ones after a table of offsets.
and private writeItems (e: SszType) (items: SszValue[]) (buf: byte[]) (pos: int) =
    match fixedSize e with
    | ValueSome _ ->
        let mutable p = pos

        for item in items do
            p <- writeAt e item buf p

        p
    | ValueNone ->
        let mutable slot = pos
        let mutable p = pos + 4 * items.Length

        for item in items do
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(slot, 4), uint32 (p - pos))
            slot <- slot + 4
            p <- writeAt e item buf p

        p

/// Fixed parts first, with 4-byte offsets in place of variable-size parts, then the variable parts.
and private writeFields (fields: (string * SszType)[]) (values: SszValue[]) (buf: byte[]) (pos: int) =
    let mutable slot = pos
    let mutable p = pos + (fields |> Array.sumBy (snd >> slotSize))

    for i in 0 .. fields.Length - 1 do
        let ft = snd fields[i]

        match fixedSize ft with
        | ValueSome _ -> slot <- writeAt ft values[i] buf slot
        | ValueNone ->
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(slot, 4), uint32 (p - pos))
            slot <- slot + 4
            p <- writeAt ft values[i] buf p

    p

/// The SSZ encoding, written once into an array of the exact size.
let serialize (t: SszType) (v: SszValue) : byte[] =
    let buf = GC.AllocateUninitializedArray<byte>(sizeOf t v)

    let written =
        try
            writeAt t v buf 0
        with
        | :? ArgumentException
        | :? IndexOutOfRangeException -> fail "value does not match schema"

    if written <> buf.Length then
        fail "value does not match schema"

    buf

// ---- Deserialization ----

let private readU32 (buf: byte[]) (pos: int) =
    int64 (BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(buf, pos, 4)))

/// The most items the decoder reads into a ProgressiveList, which has no limit of its own: 2^20,
/// MAX_TRANSACTIONS_PER_PAYLOAD before Gloas, far above any list a block holds.
let progressiveLimit = 1 <<< 20

let rec private read (t: SszType) (buf: byte[]) (start: int) (len: int) : SszValue =
    match t with
    | Uint n ->
        if len <> n then
            fail $"uint{8 * n} needs {n} bytes"

        let mutable x = 0UL

        for i in n - 1 .. -1 .. 0 do
            x <- (x <<< 8) ||| uint64 buf[start + i]

        U x
    | Uint256 ->
        if len <> 32 then
            fail "uint256 needs 32 bytes"

        Bytes(buf.AsSpan(start, len).ToArray())
    | Boolean ->
        if len <> 1 then
            fail "boolean needs 1 byte"

        match buf[start] with
        | 0uy -> Bool false
        | 1uy -> Bool true
        | _ -> fail "boolean must be 0 or 1"
    | ByteVector n ->
        if len <> n then
            fail $"ByteVector[{n}] got {len}"

        Bytes(buf.AsSpan(start, len).ToArray())
    | ByteList n ->
        if len > n then
            fail $"ByteList[{n}] got {len}"

        Bytes(buf.AsSpan(start, len).ToArray())
    | Bitvector n ->
        if len <> (n + 7) / 8 then
            fail $"Bitvector[{n}] got {len} bytes"

        for i in n .. len * 8 - 1 do
            if (buf[start + i / 8] >>> (i % 8)) &&& 1uy = 1uy then
                fail "Bitvector padding bit set"

        Bits(Array.init n (fun i -> (buf[start + i / 8] >>> (i % 8)) &&& 1uy = 1uy))
    | Bitlist n -> readBitlist buf start len n
    | ProgressiveBitlist -> readBitlist buf start len Int32.MaxValue
    | ProgressiveByteList -> Bytes(buf.AsSpan(start, len).ToArray())
    | ProgressiveList e ->
        match fixedSize e with
        | ValueSome s ->
            if len % s <> 0 then
                fail "List size not a multiple of the element size"

            if len / s > progressiveLimit then
                fail $"ProgressiveList read limit {progressiveLimit} got {len / s}"

            Items(Array.init (len / s) (fun i -> read e buf (start + i * s) s))
        | ValueNone -> Items(readVariableItems e buf start len ValueNone progressiveLimit)
    | ProgressiveContainer fields -> Fields(readSequence (Array.map snd fields) buf start len)
    | Vector(e, n) ->
        match fixedSize e with
        | ValueSome s ->
            if len <> s * n then
                fail "Vector size mismatch"

            Items(Array.init n (fun i -> read e buf (start + i * s) s))
        | ValueNone -> Items(readVariableItems e buf start len (ValueSome n) n)
    | List(e, n) ->
        match fixedSize e with
        | ValueSome s ->
            if len % s <> 0 then
                fail "List size not a multiple of the element size"

            let count = len / s

            if count > n then
                fail $"List limit {n} got {count}"

            Items(Array.init count (fun i -> read e buf (start + i * s) s))
        | ValueNone -> Items(readVariableItems e buf start len ValueNone n)
    | Container fields -> Fields(readSequence (Array.map snd fields) buf start len)

and private readBitlist buf start len (limit: int) =
    if len = 0 then
        fail "Bitlist needs a delimiter byte"

    let last = buf[start + len - 1]

    if last = 0uy then
        fail "Bitlist delimiter missing"

    let highBit = 31 - Numerics.BitOperations.LeadingZeroCount(uint32 last)
    let bitLen = (len - 1) * 8 + highBit

    if bitLen > limit then
        fail $"Bitlist[{limit}] got {bitLen} bits"

    Bits(Array.init bitLen (fun i -> (buf[start + i / 8] >>> (i % 8)) &&& 1uy = 1uy))

/// Variable-size elements start with a table of offsets; the first offset gives the count, which
/// must be at most `limit` before any item is read: an offset table alone (4 bytes an item) would
/// otherwise cost one item per 4 bytes of input.
and private readVariableItems e buf start len (expected: int voption) (limit: int) : SszValue[] =
    if len = 0 then
        match expected with
        | ValueSome n when n > 0 -> fail "Vector of variable items is empty"
        | _ -> [||]
    else
        if len < 4 then
            fail "offset table too short"

        let first = readU32 buf start

        if first % 4L <> 0L || first = 0L || first > int64 len then
            fail "bad first offset"

        let count = int (first / 4L)

        match expected with
        | ValueSome n when n <> count -> fail "Vector count mismatch"
        | _ -> ()

        if count > limit then
            fail $"List limit {limit} got {count}"

        let offsets = Array.init count (fun i -> readU32 buf (start + 4 * i))

        Array.init count (fun i ->
            let a = offsets[i]
            let b = if i + 1 < count then offsets[i + 1] else int64 len

            if b < a || b > int64 len then
                fail "offsets out of order"

            read e buf (start + int a) (int (b - a)))

and private readSequence (types: SszType[]) buf start len : SszValue[] =
    let fixedLen = types |> Array.sumBy slotSize

    if len < fixedLen then
        fail "container too short"

    let values = Array.zeroCreate<SszValue> types.Length
    let variable = ResizeArray<struct (int * int64)>()
    let mutable pos = 0

    for i in 0 .. types.Length - 1 do
        match fixedSize types[i] with
        | ValueSome s ->
            values[i] <- read types[i] buf (start + pos) s
            pos <- pos + s
        | ValueNone ->
            variable.Add(struct (i, readU32 buf (start + pos)))
            pos <- pos + 4

    if variable.Count = 0 then
        if len <> fixedLen then
            fail "trailing bytes after a fixed-size container"
    else
        let struct (_, firstOffset) = variable[0]

        if firstOffset <> int64 fixedLen then
            fail "first offset must equal the fixed size"

        for k in 0 .. variable.Count - 1 do
            let struct (i, a) = variable[k]

            let b =
                if k + 1 < variable.Count then
                    let struct (_, nextOffset) = variable[k + 1]
                    nextOffset
                else
                    int64 len

            if b < a || b > int64 len then
                fail "offsets out of order"

            values[i] <- read types[i] buf (start + int a) (int (b - a))

    values

/// Decodes a whole buffer. Fails on trailing bytes and on any malformed field.
let deserialize (t: SszType) (bytes: byte[]) : Result<SszValue, string> =
    try
        Ok(read t bytes 0 bytes.Length)
    with
    | :? SszError as e -> Error e.Message
    | :? ArgumentException
    | :? IndexOutOfRangeException -> Error "out of bounds"

/// Where the field at `path` (field indexes, outermost container first) starts in `bytes`, the
/// encoding of a value of `t`. Lets a caller write a fixed-size field, a signature, in place.
let fieldOffset (t: SszType) (bytes: byte[]) (path: int list) : int =
    let rec go (t: SszType) (pos: int) (path: int list) =
        match t, path with
        | _, [] -> pos
        | (Container fields | ProgressiveContainer fields), i :: rest ->
            let slot = pos + (fields[.. i - 1] |> Array.sumBy (snd >> slotSize))
            let ft = snd fields[i]

            match fixedSize ft with
            | ValueSome _ -> go ft slot rest
            | ValueNone -> go ft (pos + int (readU32 bytes slot)) rest
        | _ -> fail "fieldOffset: not a container"

    go t 0 path

// ---- Merkleization ----

/// SHA-256 of 64-byte inputs (two chunks), the only input a Merkle tree hashes. SHA256.HashData
/// costs about 300 ns a call on Linux, mostly setup, for 55 ns of hashing; so inputs go through
/// SIMD lanes, one input per lane: 8 lanes with AVX2 under the JIT (about 87 ns a hash), 4 with
/// SSE2 or NEON, the NativeAOT default target (about 167 ns). HashData does single inputs.
/// NativeAOT fixes Vector<T> at build time; Wide gives 8 lanes where AVX2 is a run-time check.
module internal PairHash =
    /// One 32-bit word per lane.
    type Lanes = Numerics.Vector<uint32>

    let private k =
        [|
            0x428a2f98u
            0x71374491u
            0xb5c0fbcfu
            0xe9b5dba5u
            0x3956c25bu
            0x59f111f1u
            0x923f82a4u
            0xab1c5ed5u
            0xd807aa98u
            0x12835b01u
            0x243185beu
            0x550c7dc3u
            0x72be5d74u
            0x80deb1feu
            0x9bdc06a7u
            0xc19bf174u
            0xe49b69c1u
            0xefbe4786u
            0x0fc19dc6u
            0x240ca1ccu
            0x2de92c6fu
            0x4a7484aau
            0x5cb0a9dcu
            0x76f988dau
            0x983e5152u
            0xa831c66du
            0xb00327c8u
            0xbf597fc7u
            0xc6e00bf3u
            0xd5a79147u
            0x06ca6351u
            0x14292967u
            0x27b70a85u
            0x2e1b2138u
            0x4d2c6dfcu
            0x53380d13u
            0x650a7354u
            0x766a0abbu
            0x81c2c92eu
            0x92722c85u
            0xa2bfe8a1u
            0xa81a664bu
            0xc24b8b70u
            0xc76c51a3u
            0xd192e819u
            0xd6990624u
            0xf40e3585u
            0x106aa070u
            0x19a4c116u
            0x1e376c08u
            0x2748774cu
            0x34b0bcb5u
            0x391c0cb3u
            0x4ed8aa4au
            0x5b9cca4fu
            0x682e6ff3u
            0x748f82eeu
            0x78a5636fu
            0x84c87814u
            0x8cc70208u
            0x90befffau
            0xa4506cebu
            0xbef9a3f7u
            0xc67178f2u
        |]

    let lanes = Lanes.Count
    let private simd = Numerics.Vector.IsHardwareAccelerated
    let private kv = k |> Array.map (fun x -> Lanes x)

    let private initial =
        [|
            0x6a09e667u
            0xbb67ae85u
            0x3c6ef372u
            0xa54ff53au
            0x510e527fu
            0x9b05688cu
            0x1f83d9abu
            0x5be0cd19u
        |]
        |> Array.map (fun x -> Lanes x)

    /// A 64-byte message has a second block of fixed padding (0x80, zeros, the bit length 512),
    /// so that block's schedule words plus the round constants are fixed too.
    let private paddingWords =
        let w = Array.zeroCreate<uint32> 64
        w[0] <- 0x80000000u
        w[15] <- 512u

        for i in 16..63 do
            let s0 =
                BitOperations.RotateRight(w[i - 15], 7)
                ^^^ BitOperations.RotateRight(w[i - 15], 18)
                ^^^ (w[i - 15] >>> 3)

            let s1 =
                BitOperations.RotateRight(w[i - 2], 17)
                ^^^ BitOperations.RotateRight(w[i - 2], 19)
                ^^^ (w[i - 2] >>> 10)

            w[i] <- w[i - 16] + s0 + w[i - 7] + s1

        Array.init 64 (fun i -> k[i] + w[i])

    let private paddingKw = paddingWords |> Array.map (fun x -> Lanes x)

    /// Work arrays, one set per thread, so hashing allocates nothing.
    [<Sealed; AllowNullLiteral>]
    type Scratch() =
        member val Words = Array.zeroCreate<uint32>(16 * max 8 Lanes.Count)
        member val W = Array.zeroCreate<Lanes> 64
        member val State = Array.zeroCreate<Lanes> 8
        member val WideW = Array.zeroCreate<Vector256<uint32>> 64
        member val WideState = Array.zeroCreate<Vector256<uint32>> 8
        member val Digest = Array.zeroCreate<byte> 32
        member val Tail = Array.zeroCreate<byte>(64 * max 8 Lanes.Count)

    type private Slot =
        [<ThreadStatic; DefaultValue>]
        static val mutable private current: Scratch

        static member Get() =
            if isNull Slot.current then
                Slot.current <- Scratch()

            Slot.current

    let inline private rotr (x: Lanes) (n: int) =
        Numerics.Vector.ShiftRightLogical(x, n) ||| Numerics.Vector.ShiftLeft(x, 32 - n)

    /// The 64 rounds of one block on every lane, then the add into `state`. kw[i] is the round
    /// constant plus the schedule word.
    [<MethodImpl(MethodImplOptions.AggressiveOptimization)>]
    let private rounds (state: Lanes[]) (kw: Lanes[]) =
        let mutable a = state[0]
        let mutable b = state[1]
        let mutable c = state[2]
        let mutable d = state[3]
        let mutable e = state[4]
        let mutable f = state[5]
        let mutable g = state[6]
        let mutable h = state[7]

        for i in 0..63 do
            // ch(e, f, g) is a bitwise select by e; maj(a, b, c) is c where a and b differ, else b.
            let t1 = h + (rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25) + Numerics.Vector.ConditionalSelect(e, f, g) + kw[i]
            let t2 = (rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22) + Numerics.Vector.ConditionalSelect(a ^^^ b, c, b)
            h <- g
            g <- f
            f <- e
            e <- d + t1
            d <- c
            c <- b
            b <- a
            a <- t1 + t2

        state[0] <- state[0] + a
        state[1] <- state[1] + b
        state[2] <- state[2] + c
        state[3] <- state[3] + d
        state[4] <- state[4] + e
        state[5] <- state[5] + f
        state[6] <- state[6] + g
        state[7] <- state[7] + h

    /// `lanes` inputs of 64 bytes to `lanes` digests. Reads all input before it writes.
    [<MethodImpl(MethodImplOptions.AggressiveOptimization)>]
    let private hashGroup (input: ReadOnlySpan<byte>) (output: Span<byte>) (s: Scratch) =
        let words = s.Words
        let w = s.W
        // Word t of input l becomes lane l of w[t].
        for l in 0 .. lanes - 1 do
            for t in 0..15 do
                words[t * lanes + l] <- BinaryPrimitives.ReadUInt32BigEndian(input.Slice(64 * l + 4 * t))

        for t in 0..15 do
            w[t] <- Lanes(words, t * lanes)

        for t in 16..63 do
            let x = w[t - 15]
            let y = w[t - 2]
            let s0 = rotr x 7 ^^^ rotr x 18 ^^^ Numerics.Vector.ShiftRightLogical(x, 3)
            let s1 = rotr y 17 ^^^ rotr y 19 ^^^ Numerics.Vector.ShiftRightLogical(y, 10)
            w[t] <- w[t - 16] + s0 + w[t - 7] + s1

        for t in 0..63 do
            w[t] <- w[t] + kv[t]

        let state = s.State
        Array.blit initial 0 state 0 8
        rounds state w
        rounds state paddingKw

        for j in 0..7 do
            state[j].CopyTo(words, j * lanes)

        for l in 0 .. lanes - 1 do
            for j in 0..7 do
                BinaryPrimitives.WriteUInt32BigEndian(output.Slice(32 * l + 4 * j), words[j * lanes + l])

    /// The same hash on 8 lanes of Vector256 through Avx2 calls. It is for a NativeAOT build with
    /// AVX in its baseline (x86-64-v2,avx): there Vector<T> has 4 lanes and Avx2.IsSupported is
    /// read from the CPU at run time, but the Vector256 operators are not accelerated, so this
    /// calls Avx2 directly. Under the JIT or an x86-64-v3 build Vector<T> has 8 lanes already.
    module Wide =
        type private W = Vector256<uint32>

        let inline private add (a: W) (b: W) = Avx2.Add(a, b)
        let inline private xor (a: W) (b: W) = Avx2.Xor(a, b)

        let inline private rotr (x: W) (n: byte) =
            Avx2.Or(Avx2.ShiftRightLogical(x, n), Avx2.ShiftLeftLogical(x, 32uy - n))

        let inline private shr (x: W) (n: byte) = Avx2.ShiftRightLogical(x, n)
        /// Bits of a where m is set, else bits of b.
        let inline private select (m: W) (a: W) (b: W) = Avx2.Or(Avx2.And(m, a), Avx2.AndNot(m, b))

        let private kv = k |> Array.map (fun x -> Vector256.Create x)
        let private initial = initial |> Array.map (fun x -> Vector256.Create(x.[0]))
        let private paddingKw = paddingWords |> Array.map (fun x -> Vector256.Create x)

        [<MethodImpl(MethodImplOptions.AggressiveOptimization)>]
        let private rounds (state: W[]) (kw: W[]) =
            let mutable a = state[0]
            let mutable b = state[1]
            let mutable c = state[2]
            let mutable d = state[3]
            let mutable e = state[4]
            let mutable f = state[5]
            let mutable g = state[6]
            let mutable h = state[7]

            for i in 0..63 do
                let t1 = add (add (add h (xor (xor (rotr e 6uy) (rotr e 11uy)) (rotr e 25uy))) (select e f g)) kw[i]
                let t2 = add (xor (xor (rotr a 2uy) (rotr a 13uy)) (rotr a 22uy)) (select (xor a b) c b)
                h <- g
                g <- f
                f <- e
                e <- add d t1
                d <- c
                c <- b
                b <- a
                a <- add t1 t2

            state[0] <- add state[0] a
            state[1] <- add state[1] b
            state[2] <- add state[2] c
            state[3] <- add state[3] d
            state[4] <- add state[4] e
            state[5] <- add state[5] f
            state[6] <- add state[6] g
            state[7] <- add state[7] h

        /// 8 inputs of 64 bytes to 8 digests. Call only when Avx2.IsSupported.
        [<MethodImpl(MethodImplOptions.AggressiveOptimization)>]
        let hashGroup (input: ReadOnlySpan<byte>) (output: Span<byte>) (s: Scratch) =
            let words = s.Words
            let w = s.WideW

            for l in 0..7 do
                for t in 0..15 do
                    words[t * 8 + l] <- BinaryPrimitives.ReadUInt32BigEndian(input.Slice(64 * l + 4 * t))

            let vs = MemoryMarshal.Cast<uint32, W>(Span(words, 0, 128))

            for t in 0..15 do
                w[t] <- vs[t]

            for t in 16..63 do
                let x = w[t - 15]
                let y = w[t - 2]
                let s0 = xor (xor (rotr x 7uy) (rotr x 18uy)) (shr x 3uy)
                let s1 = xor (xor (rotr y 17uy) (rotr y 19uy)) (shr y 10uy)
                w[t] <- add (add (add w[t - 16] s0) w[t - 7]) s1

            for t in 0..63 do
                w[t] <- add w[t] kv[t]

            let state = s.WideState
            Array.blit initial 0 state 0 8
            rounds state w
            rounds state paddingKw

            for j in 0..7 do
                vs[j] <- state[j]

            for l in 0..7 do
                for j in 0..7 do
                    BinaryPrimitives.WriteUInt32BigEndian(output.Slice(32 * l + 4 * j), words[j * 8 + l])

    /// Hashes `count` inputs: input i at 64 * i, its digest to 32 * i. The output may start where
    /// the input starts (a Merkle level hashed in place): a group writes only below the inputs of
    /// the groups after it. `wide` takes the Wide path; it needs Avx2.IsSupported.
    let hashPairsOn (wide: bool) (input: ReadOnlySpan<byte>) (output: Span<byte>) (count: int) =
        let s = Slot.Get()
        let n = if wide then 8 else lanes
        let mutable i = 0

        if simd then
            while count - i >= n do
                let inp = input.Slice(64 * i, 64 * n)
                let out = output.Slice(32 * i, 32 * n)
                if wide then Wide.hashGroup inp out s else hashGroup inp out s
                i <- i + n
            // A part-filled group costs about as much as a full one, and less than three HashData calls.
            if count - i >= 3 then
                let rest = count - i
                input.Slice(64 * i, 64 * rest).CopyTo(Span s.Tail)
                let tail = Span(s.Tail, 0, 64 * n)

                if wide then
                    Wide.hashGroup (Span<byte>.op_Implicit tail) tail s
                else
                    hashGroup (Span<byte>.op_Implicit tail) tail s

                ReadOnlySpan(s.Tail, 0, 32 * rest).CopyTo(output.Slice(32 * i))
                i <- count

        while i < count do
            SHA256.HashData(input.Slice(64 * i, 64), Span s.Digest) |> ignore
            ReadOnlySpan(s.Digest).CopyTo(output.Slice(32 * i, 32))
            i <- i + 1

    /// hashPairsOn with Wide where Vector<T> has fewer than 8 lanes and the CPU has AVX2. Both are
    /// constants under the JIT and in x86-64-v2 or v3 builds, so the check folds away there.
    let hashPairs (input: ReadOnlySpan<byte>) (output: Span<byte>) (count: int) =
        hashPairsOn (Lanes.Count < 8 && Avx2.IsSupported) input output count

let private hash2 (a: byte[]) (b: byte[]) : byte[] =
    let buf = Array.zeroCreate<byte> 64
    Buffer.BlockCopy(a, 0, buf, 0, 32)
    Buffer.BlockCopy(b, 0, buf, 32, 32)
    SHA256.HashData buf

let private zeroHashes: byte[][] =
    let z = Array.zeroCreate<byte[]> 65
    z[0] <- Array.zeroCreate 32

    for i in 1..64 do
        z[i] <- hash2 z[i - 1] z[i - 1]

    z

let private nextPow2 (n: int64) =
    let mutable p = 1L

    while p < n do
        p <- p <<< 1

    p

/// Tree depth for a limit of `limit` chunks.
let private depthOf (limit: int64) = BitOperations.Log2(uint64 (nextPow2 limit))

/// Roots of many Merkle trees at once. Tree t has the bytes leaves[t], zero-padded to whole
/// chunks, under a limit of 2^depths[t] chunks (the caller checks the limit). All trees go up one
/// level per round, so a round fills the SIMD lanes even near the top, where each tree has one
/// node to hash with a zero subtree: 600 transactions under a 2^25-chunk limit are mostly such
/// pairs. A round hashes its level in place, then packs the nodes of each tree for the next round.
let private merkleizeForest (leaves: ReadOnlyMemory<byte>[]) (depths: int[]) : byte[][] =
    let n = leaves.Length
    let roots = Array.zeroCreate<byte[]> n
    let isDone = Array.zeroCreate<bool> n
    let nodes = Array.zeroCreate<int> n
    let mutable chunks = 0

    for t in 0 .. n - 1 do
        nodes[t] <- (leaves[t].Length + 31) / 32
        chunks <- chunks + nodes[t] + 1

    let mutable cur = ArrayPool<byte>.Shared.Rent(32 * chunks)
    let mutable next = ArrayPool<byte>.Shared.Rent(32 * chunks)

    try
        // Level 0: the leaves, each tree padded to an even count of chunks.
        let mutable used = 0

        for t in 0 .. n - 1 do
            let data = leaves[t].Span

            if nodes[t] = 0 then
                roots[t] <- Array.copy zeroHashes[depths[t]]
                isDone[t] <- true
            elif depths[t] = 0 then
                let root = Array.zeroCreate<byte> 32
                data.CopyTo(Span root)
                roots[t] <- root
                isDone[t] <- true
            else
                let padded = 32 * (nodes[t] + nodes[t] % 2)
                data.CopyTo(cur.AsSpan used)
                cur.AsSpan(used + data.Length, padded - data.Length).Clear()
                used <- used + padded

        let mutable level = 0

        while used > 0 do
            PairHash.hashPairs (ReadOnlySpan(cur, 0, used)) (Span(cur, 0, used / 2)) (used / 64)
            level <- level + 1
            let mutable from = 0
            let mutable into = 0

            for t in 0 .. n - 1 do
                if not isDone[t] then
                    let count = (nodes[t] + 1) / 2

                    if level = depths[t] then
                        roots[t] <- cur.AsSpan(from, 32).ToArray()
                        isDone[t] <- true
                    else
                        Buffer.BlockCopy(cur, from, next, into, 32 * count)
                        into <- into + 32 * count

                        if count % 2 = 1 then
                            Buffer.BlockCopy(zeroHashes[level], 0, next, into, 32)
                            into <- into + 32

                    nodes[t] <- count
                    from <- from + 32 * count

            let swap = cur
            cur <- next
            next <- swap
            used <- into

        roots
    finally
        ArrayPool<byte>.Shared.Return cur
        ArrayPool<byte>.Shared.Return next

/// Byte strings over this total are hashed on several cores: 256 KB is about 8,000 hashes, 0.7 ms
/// on one core with AVX2, more than the cost of handing work to the thread pool.
let private parallelFrom = 256 * 1024

/// At most 4 workers, and at most half the cores: the beacon node often runs on the same host.
let private workers = max 1 (min 4 (Environment.ProcessorCount / 2))

/// merkleizeForest over parts of `datas` with similar byte counts, on several cores when the
/// total is large. `forest` gets a range of the strings and returns their roots.
let private inParts (datas: byte[][]) (forest: byte[][] -> byte[][]) : byte[][] =
    let total = datas |> Array.sumBy (fun b -> int64 b.Length)
    let parts = int (min (int64 workers) (total / int64 parallelFrom + 1L))

    if parts <= 1 then
        forest datas
    else
        // Cut where the running byte count passes each 1/parts of the total.
        let cuts = Array.zeroCreate<int>(parts + 1)
        let mutable sum = 0L
        let mutable part = 1

        for i in 0 .. datas.Length - 1 do
            sum <- sum + int64 datas[i].Length

            while part < parts && sum * int64 parts >= total * int64 part do
                cuts[part] <- i + 1
                part <- part + 1

        cuts[parts] <- datas.Length
        let roots = Array.zeroCreate<byte[][]> parts

        Threading.Tasks.Parallel.For(0, parts, fun k -> roots[k] <- forest datas[cuts[k] .. cuts[k + 1] - 1])
        |> ignore

        Array.concat roots

/// Hashes one tree in place. `buf` holds `count` chunks, zero-padded to an even count; the tree
/// has 2^depth leaves (depth 1 or more).
let private merkleizeInPlace (buf: byte[]) (count: int) (depth: int) : byte[] =
    let mutable n = count + count % 2
    let mutable level = 0

    while level < depth do
        PairHash.hashPairs (ReadOnlySpan(buf, 0, 32 * n)) (Span(buf, 0, 16 * n)) (n / 2)
        n <- n / 2
        level <- level + 1

        if level < depth && n % 2 = 1 then
            Buffer.BlockCopy(zeroHashes[level], 0, buf, 32 * n, 32)
            n <- n + 1

    buf.AsSpan(0, 32).ToArray()

/// Trees up to this many chunks (64 KB) hash in one plain array; larger ones go through the
/// forest, whose buffers come from the shared pool and stay off the large object heap.
let private smallTree = 2048

let private depthFor (count: int64) (limit: int64 voption) =
    match limit with
    | ValueSome l ->
        if count > l then
            fail "chunk count over limit"

        depthOf l
    | ValueNone -> depthOf count

/// merkleize(pack(bytes), limit) for a limit of `limit` chunks; ValueNone uses the chunk count.
let private merkleizeBytes (bytes: byte[]) (limit: int64 voption) : byte[] =
    let count = (bytes.Length + 31) / 32
    let depth = depthFor (int64 count) limit

    if count = 0 then
        Array.copy zeroHashes[depth]
    elif depth = 0 then
        let root = Array.zeroCreate<byte> 32
        Buffer.BlockCopy(bytes, 0, root, 0, bytes.Length)
        root
    elif count > smallTree then
        (merkleizeForest [| ReadOnlyMemory bytes |] [| depth |]).[0]
    else
        let buf = Array.zeroCreate<byte>(32 * (count + count % 2))
        Buffer.BlockCopy(bytes, 0, buf, 0, bytes.Length)
        merkleizeInPlace buf count depth

/// merkleize(chunks, limit) from the SSZ spec. `limit` is a chunk limit; ValueNone uses the chunk count.
let merkleize (chunks: byte[][]) (limit: int64 voption) : byte[] =
    let count = chunks.Length
    let depth = depthFor (int64 count) limit

    if count = 0 then
        Array.copy zeroHashes[depth]
    elif depth = 0 then
        Array.copy chunks[0]
    else
        let buf = Array.zeroCreate<byte>(32 * (count + count % 2))

        for i in 0 .. count - 1 do
            Buffer.BlockCopy(chunks[i], 0, buf, 32 * i, 32)

        merkleizeInPlace buf count depth

let private concat (chunks: byte[][]) =
    let all = Array.zeroCreate<byte>(32 * chunks.Length)

    for i in 0 .. chunks.Length - 1 do
        Buffer.BlockCopy(chunks[i], 0, all, 32 * i, 32)

    all

/// hash(left[i] ++ right[i]) for every i, in one batch.
let private hashEach (left: byte[][]) (right: byte[][]) : byte[][] =
    let buf = Array.zeroCreate<byte>(64 * left.Length)

    for i in 0 .. left.Length - 1 do
        Buffer.BlockCopy(left[i], 0, buf, 64 * i, 32)
        Buffer.BlockCopy(right[i], 0, buf, 64 * i + 32, 32)

    PairHash.hashPairs (ReadOnlySpan buf) (Span buf) left.Length
    Array.init left.Length (fun i -> buf.AsSpan(32 * i, 32).ToArray())

let private lengthChunk (length: int) =
    let chunk = Array.zeroCreate<byte> 32
    BinaryPrimitives.WriteUInt64LittleEndian(chunk.AsSpan(), uint64 length)
    chunk

let mixInLength (root: byte[]) (length: int) : byte[] = hash2 root (lengthChunk length)

let private mixInLengths (roots: byte[][]) (lengths: int[]) = hashEach roots (Array.map lengthChunk lengths)

/// merkleize_progressive (EIP-7916) as remerkleable's subtree_fill_progressive computes it: the
/// first chunk in a subtree of 1, the next 4 in a subtree of 4, the next 16 in one of 16, and so
/// on; the root is hash(subtree 0, hash(subtree 1, ... hash(last subtree, zero chunk))). The Gloas
/// ssz_static vectors decide the order. Here for many byte strings at once: one forest for all
/// subtrees, then one batch per step of the folds.
let private merkleizeProgressiveMany (datas: byte[][]) : byte[][] =
    let parts = ResizeArray<ReadOnlyMemory<byte>>()
    let depths = ResizeArray<int>()
    let first = Array.zeroCreate<int> datas.Length
    let counts = Array.zeroCreate<int> datas.Length

    for t in 0 .. datas.Length - 1 do
        let data = datas[t]
        first[t] <- parts.Count
        let mutable offset = 0
        let mutable depth = 0

        while offset < data.Length do
            let size = min (32 <<< depth) (data.Length - offset)
            parts.Add(ReadOnlyMemory(data, offset, size))
            depths.Add depth
            offset <- offset + size
            depth <- depth + 2

        counts[t] <- parts.Count - first[t]

    let subtrees = merkleizeForest (parts.ToArray()) (depths.ToArray())
    let acc = Array.init datas.Length (fun _ -> Array.copy zeroHashes[0])
    // Fold from the last subtree in; every string still folding takes one step per batch.
    let mutable step = (if counts.Length = 0 then 0 else Array.max counts) - 1

    while step >= 0 do
        let active =
            [|
                for t in 0 .. datas.Length - 1 do
                    if counts[t] > step then
                        t
            |]

        let hashed =
            hashEach (active |> Array.map (fun t -> subtrees[first[t] + step])) (active |> Array.map (fun t -> acc[t]))

        for i in 0 .. active.Length - 1 do
            acc[active[i]] <- hashed[i]

        step <- step - 1

    acc

let merkleizeProgressive (chunks: byte[][]) : byte[] = (merkleizeProgressiveMany [| concat chunks |]).[0]

/// mix_in_active_fields (EIP-7495) for a ProgressiveContainer with `width` fields, all active.
let private mixInActiveFields (root: byte[]) (width: int) =
    let chunk = Array.zeroCreate<byte> 32
    let bits = packBits (Array.create width true) 0
    Buffer.BlockCopy(bits, 0, chunk, 0, bits.Length)
    hash2 root chunk

let private chunkLimit (bytes: int64) = ValueSome((bytes + 31L) / 32L)

let private bytesOf (v: SszValue) =
    match v with
    | Bytes b -> b
    | _ -> fail "value does not match schema"

let rec hashTreeRoot (t: SszType) (v: SszValue) : byte[] =
    match t, v with
    | (Uint _ | Uint256 | Boolean), _ -> merkleizeBytes (serialize t v) ValueNone
    | ByteVector n, Bytes b ->
        if b.Length <> n then
            fail "ByteVector length"

        merkleizeBytes b (chunkLimit (int64 n))
    | ByteList n, Bytes b ->
        if b.Length > n then
            fail "ByteList length"

        mixInLength (merkleizeBytes b (chunkLimit (int64 n))) b.Length
    | Bitvector n, Bits bits ->
        if bits.Length <> n then
            fail "Bitvector length"

        merkleizeBytes (packBits bits 0) (ValueSome((int64 n + 255L) / 256L))
    | Bitlist n, Bits bits ->
        if bits.Length > n then
            fail "Bitlist length"

        mixInLength (merkleizeBytes (packBits bits 0) (ValueSome((int64 n + 255L) / 256L))) bits.Length
    | Vector(e, n), Items _ when isBasic e ->
        merkleizeBytes (serialize t v) (chunkLimit (int64 n * int64 (fixedSize e).Value))
    | List(e, n), Items items when isBasic e ->
        mixInLength (merkleizeBytes (serialize t v) (chunkLimit (int64 n * int64 (fixedSize e).Value))) items.Length
    | Vector(e, n), Items items ->
        if items.Length <> n then
            fail "Vector length"

        merkleize (itemRoots e items) (ValueSome(int64 n))
    | List(e, n), Items items ->
        if items.Length > n then
            fail "List length"

        mixInLength (merkleize (itemRoots e items) (ValueSome(int64 n))) items.Length
    | Container fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        merkleize (Array.map2 (fun (_, ft) fv -> hashTreeRoot ft fv) fields values) ValueNone
    | ProgressiveList e, Items items when isBasic e ->
        mixInLength (merkleizeProgressiveMany [| serialize t v |]).[0] items.Length
    | ProgressiveList e, Items items -> mixInLength (merkleizeProgressive (itemRoots e items)) items.Length
    | ProgressiveByteList, Bytes b -> mixInLength (merkleizeProgressiveMany [| b |]).[0] b.Length
    | ProgressiveBitlist, Bits bits -> mixInLength (merkleizeProgressiveMany [| packBits bits 0 |]).[0] bits.Length
    | ProgressiveContainer fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        mixInActiveFields
            (merkleizeProgressive (Array.map2 (fun (_, ft) fv -> hashTreeRoot ft fv) fields values))
            fields.Length
    | _ -> fail "value does not match schema"

/// The roots of a composite list's items. Byte lists (transactions) are hashed together, in one
/// forest; other items one by one.
and private itemRoots (e: SszType) (items: SszValue[]) : byte[][] =
    match e with
    | ByteList n ->
        let datas = items |> Array.map bytesOf

        for b in datas do
            if b.Length > n then
                fail "ByteList length"

        let depth = depthOf ((int64 n + 31L) / 32L)

        let forest (part: byte[][]) =
            merkleizeForest (part |> Array.map ReadOnlyMemory) (Array.create part.Length depth)

        mixInLengths (inParts datas forest) (datas |> Array.map _.Length)
    | ProgressiveByteList ->
        let datas = items |> Array.map bytesOf
        mixInLengths (inParts datas merkleizeProgressiveMany) (datas |> Array.map _.Length)
    | _ -> items |> Array.map (hashTreeRoot e)

/// The default (all-zero) value of a type, as the SSZ spec defines it.
let rec zero (t: SszType) : SszValue =
    match t with
    | Uint _ -> U 0UL
    | Uint256 -> Bytes(Array.zeroCreate 32)
    | Boolean -> Bool false
    | ByteVector n -> Bytes(Array.zeroCreate n)
    | ByteList _ -> Bytes [||]
    | Bitvector n -> Bits(Array.zeroCreate n)
    | Bitlist _ -> Bits [||]
    | Vector(e, n) -> Items(Array.init n (fun _ -> zero e))
    | List _
    | ProgressiveList _ -> Items [||]
    | ProgressiveByteList -> Bytes [||]
    | ProgressiveBitlist -> Bits [||]
    | Container fields
    | ProgressiveContainer fields -> Fields(fields |> Array.map (snd >> zero))
