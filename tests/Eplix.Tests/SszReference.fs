/// The SSZ encoder and hash_tree_root as they were before the batched merkleization (integ/final
/// d91b36b02): one ResizeArray byte at a time, one SHA256.HashData call and two arrays per Merkle
/// node. Kept as the reference that SszCrossCheckTests compares the current code against.
module Eplix.Tests.SszReference

open System
open System.Buffers.Binary
open System.Security.Cryptography
open Eplix.Ssz

let private fail msg = raise (SszError msg)

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

let private packBits (bits: bool[]) (extra: int) : byte[] =
    let bytes = Array.zeroCreate<byte>((bits.Length + extra + 7) / 8)

    for i in 0 .. bits.Length - 1 do
        if bits[i] then
            bytes[i / 8] <- bytes[i / 8] ||| (1uy <<< (i % 8))

    bytes

// ---- Serialization ----

let rec private write (t: SszType) (v: SszValue) (out: ResizeArray<byte>) : unit =
    match t, v with
    | Uint n, U x ->
        if n < 8 && (x >>> (8 * n)) <> 0UL then
            fail $"uint{8 * n} overflow"

        for i in 0 .. n - 1 do
            out.Add(byte (x >>> (8 * i)))
    | Uint256, Bytes b ->
        if b.Length <> 32 then
            fail "uint256 needs 32 bytes"

        out.AddRange b
    | Boolean, Bool b -> out.Add(if b then 1uy else 0uy)
    | ByteVector n, Bytes b ->
        if b.Length <> n then
            fail $"ByteVector[{n}] got {b.Length} bytes"

        out.AddRange b
    | ByteList n, Bytes b ->
        if b.Length > n then
            fail $"ByteList[{n}] got {b.Length} bytes"

        out.AddRange b
    | Bitvector n, Bits bits ->
        if bits.Length <> n then
            fail $"Bitvector[{n}] got {bits.Length} bits"

        out.AddRange(packBits bits 0)
    | Bitlist n, Bits bits ->
        if bits.Length > n then
            fail $"Bitlist[{n}] got {bits.Length} bits"

        writeBitlist bits out
    | ProgressiveBitlist, Bits bits -> writeBitlist bits out
    | ProgressiveByteList, Bytes b -> out.AddRange b
    | ProgressiveList e, Items items -> writeSequence (Array.create items.Length e) items out
    | ProgressiveContainer fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        writeSequence (Array.map snd fields) values out
    | Vector(e, n), Items items ->
        if items.Length <> n then
            fail $"Vector length {n} got {items.Length}"

        writeSequence (Array.create n e) items out
    | List(e, n), Items items ->
        if items.Length > n then
            fail $"List limit {n} got {items.Length}"

        writeSequence (Array.create items.Length e) items out
    | Container fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        writeSequence (Array.map snd fields) values out
    | _ -> fail "value does not match schema"

/// The bits, then one delimiter bit.
and private writeBitlist (bits: bool[]) (out: ResizeArray<byte>) =
    let bytes = packBits bits 1
    let len = bits.Length
    bytes[len / 8] <- bytes[len / 8] ||| (1uy <<< (len % 8))
    out.AddRange bytes

/// Fixed parts first, with 4-byte offsets in place of variable-size parts, then the variable parts.
and private writeSequence (types: SszType[]) (values: SszValue[]) (out: ResizeArray<byte>) =
    let fixedLen = types |> Array.sumBy slotSize
    let variable = ResizeArray<byte>()

    for i in 0 .. types.Length - 1 do
        match fixedSize types[i] with
        | ValueSome _ -> write types[i] values[i] out
        | ValueNone ->
            let offset = uint32 (fixedLen + variable.Count)

            for k in 0..3 do
                out.Add(byte (offset >>> (8 * k)))

            write types[i] values[i] variable

    out.AddRange variable

let serialize (t: SszType) (v: SszValue) : byte[] =
    let out = ResizeArray<byte>()
    write t v out
    out.ToArray()

// ---- Merkleization ----

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

/// merkleize(chunks, limit) from the SSZ spec. `limit` is a chunk limit; ValueNone uses the chunk count.
let merkleize (chunks: byte[][]) (limit: int64 voption) : byte[] =
    let count = int64 chunks.Length

    let size =
        match limit with
        | ValueSome l ->
            if count > l then
                fail "chunk count over limit"

            nextPow2 l
        | ValueNone -> nextPow2 count

    let depth = Numerics.BitOperations.Log2(uint64 size)

    if count = 0L then
        zeroHashes[depth]
    else
        let mutable layer = chunks

        for d in 0 .. depth - 1 do
            let next = Array.zeroCreate<byte[]>((layer.Length + 1) / 2)

            for i in 0 .. next.Length - 1 do
                let right = if 2 * i + 1 < layer.Length then layer[2 * i + 1] else zeroHashes[d]
                next[i] <- hash2 layer[2 * i] right

            layer <- next

        layer[0]

let mixInLength (root: byte[]) (length: int) : byte[] =
    let len = Array.zeroCreate<byte> 32
    BinaryPrimitives.WriteUInt64LittleEndian(len.AsSpan(), uint64 length)
    hash2 root len

let private toChunks (bytes: byte[]) : byte[][] =
    Array.init ((bytes.Length + 31) / 32) (fun i ->
        let c = Array.zeroCreate<byte> 32
        Buffer.BlockCopy(bytes, 32 * i, c, 0, min 32 (bytes.Length - 32 * i))
        c)

let private chunkLimit (bytes: int64) = ValueSome((bytes + 31L) / 32L)

/// merkleize_progressive (EIP-7916) as remerkleable's subtree_fill_progressive computes it: the
/// first chunk in a subtree of 1, the next 4 in a subtree of 4, the next 16 in one of 16, and so
/// on; each level is hash(this subtree, rest). The Gloas ssz_static vectors decide the order.
let merkleizeProgressive (chunks: byte[][]) : byte[] =
    let rec go (offset: int) (numLeaves: int) =
        if offset >= chunks.Length then
            zeroHashes[0]
        else
            let n = min numLeaves (chunks.Length - offset)
            let here = merkleize (Array.sub chunks offset n) (ValueSome(int64 numLeaves))
            hash2 here (go (offset + n) (numLeaves * 4))

    go 0 1

/// mix_in_active_fields (EIP-7495) for a ProgressiveContainer with `width` fields, all active.
let private mixInActiveFields (root: byte[]) (width: int) =
    let chunk = Array.zeroCreate<byte> 32
    let bits = packBits (Array.create width true) 0
    Buffer.BlockCopy(bits, 0, chunk, 0, bits.Length)
    hash2 root chunk

let rec hashTreeRoot (t: SszType) (v: SszValue) : byte[] =
    match t, v with
    | (Uint _ | Uint256 | Boolean), _ -> merkleize (toChunks (serialize t v)) ValueNone
    | ByteVector n, Bytes b ->
        if b.Length <> n then
            fail "ByteVector length"

        merkleize (toChunks b) (chunkLimit (int64 n))
    | ByteList n, Bytes b ->
        if b.Length > n then
            fail "ByteList length"

        mixInLength (merkleize (toChunks b) (chunkLimit (int64 n))) b.Length
    | Bitvector n, Bits bits ->
        if bits.Length <> n then
            fail "Bitvector length"

        merkleize (toChunks (packBits bits 0)) (ValueSome((int64 n + 255L) / 256L))
    | Bitlist n, Bits bits ->
        if bits.Length > n then
            fail "Bitlist length"

        mixInLength (merkleize (toChunks (packBits bits 0)) (ValueSome((int64 n + 255L) / 256L))) bits.Length
    | Vector(e, n), Items _ when isBasic e ->
        merkleize (toChunks (serialize t v)) (chunkLimit (int64 n * int64 (fixedSize e).Value))
    | List(e, n), Items items when isBasic e ->
        mixInLength
            (merkleize (toChunks (serialize t v)) (chunkLimit (int64 n * int64 (fixedSize e).Value)))
            items.Length
    | Vector(e, n), Items items ->
        if items.Length <> n then
            fail "Vector length"

        merkleize (items |> Array.map (hashTreeRoot e)) (ValueSome(int64 n))
    | List(e, n), Items items ->
        if items.Length > n then
            fail "List length"

        mixInLength (merkleize (items |> Array.map (hashTreeRoot e)) (ValueSome(int64 n))) items.Length
    | Container fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        merkleize (Array.map2 (fun (_, ft) fv -> hashTreeRoot ft fv) fields values) ValueNone
    | ProgressiveList e, Items items when isBasic e ->
        mixInLength (merkleizeProgressive (toChunks (serialize t v))) items.Length
    | ProgressiveList e, Items items ->
        mixInLength (merkleizeProgressive (items |> Array.map (hashTreeRoot e))) items.Length
    | ProgressiveByteList, Bytes b -> mixInLength (merkleizeProgressive (toChunks b)) b.Length
    | ProgressiveBitlist, Bits bits -> mixInLength (merkleizeProgressive (toChunks (packBits bits 0))) bits.Length
    | ProgressiveContainer fields, Fields values ->
        if fields.Length <> values.Length then
            fail "container field count"

        mixInActiveFields
            (merkleizeProgressive (Array.map2 (fun (_, ft) fv -> hashTreeRoot ft fv) fields values))
            fields.Length
    | _ -> fail "value does not match schema"
