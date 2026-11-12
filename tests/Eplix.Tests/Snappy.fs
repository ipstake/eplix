/// Snappy block-format decompression, for the .ssz_snappy files of consensus-spec-tests. Test-only.
module Eplix.Tests.Snappy

open System

let decompress (src: byte[]) : byte[] =
    let mutable pos = 0

    let varint () =
        let mutable result = 0
        let mutable shift = 0
        let mutable go = true

        while go do
            let b = src[pos]
            pos <- pos + 1
            result <- result ||| ((int b &&& 0x7f) <<< shift)
            shift <- shift + 7
            go <- b &&& 0x80uy <> 0uy

        result

    let length = varint ()
    let dst = Array.zeroCreate<byte> length
    let mutable o = 0

    let readLe n =
        let mutable v = 0

        for i in 0 .. n - 1 do
            v <- v ||| (int src[pos + i] <<< (8 * i))

        pos <- pos + n
        v

    let copy offset len =
        if offset <= 0 || offset > o then
            failwith "snappy: bad offset"

        for _ in 1..len do
            dst[o] <- dst[o - offset]
            o <- o + 1

    while pos < src.Length do
        let tag = int src[pos]
        pos <- pos + 1

        match tag &&& 3 with
        | 0 ->
            let l = tag >>> 2
            let len = if l < 60 then l + 1 else readLe (l - 59) + 1
            Buffer.BlockCopy(src, pos, dst, o, len)
            pos <- pos + len
            o <- o + len
        | 1 ->
            let len = ((tag >>> 2) &&& 7) + 4
            let offset = ((tag >>> 5) <<< 8) ||| int src[pos]
            pos <- pos + 1
            copy offset len
        | 2 -> copy (readLe 2) ((tag >>> 2) + 1)
        | _ -> copy (readLe 4) ((tag >>> 2) + 1)

    if o <> length then
        failwith "snappy: length mismatch"

    dst
