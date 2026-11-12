/// The batched merkleization and the one-pass encoder against the code they replaced
/// (SszReference): the same bytes and the same roots on random schemas and values, on lists that
/// fill a SIMD group partly, and on mainnet-sized Fulu and Gloas blocks.
module Eplix.Tests.SszCrossCheckTests

open System
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Ssz

module Ref = Eplix.Tests.SszReference

let private randomBytes (rng: Random) (n: int) =
    let b = Array.zeroCreate<byte> n
    rng.NextBytes b
    b

/// A random schema with at most `depth` levels of nesting. Limits go from 1 to spec sizes: a
/// ByteList[2^30] has 25 levels of zero subtrees above its data.
let rec private randomType (rng: Random) (depth: int) : SszType =
    let leaf () =
        match rng.Next 9 with
        | 0 -> Uint([| 1; 2; 4; 8 |][rng.Next 4])
        | 1 -> Uint256
        | 2 -> Boolean
        | 3 -> ByteVector(1 + rng.Next 100)
        | 4 -> ByteList([| 1; 32; 33; 1000; 1 <<< 30 |][rng.Next 5])
        | 5 -> Bitvector(1 + rng.Next 600)
        | 6 -> Bitlist([| 1; 8; 256; 2048; 131072 |][rng.Next 5])
        | 7 -> ProgressiveByteList
        | _ -> ProgressiveBitlist

    if depth = 0 then
        leaf ()
    else
        match rng.Next 6 with
        | 0 -> Vector(randomType rng (depth - 1), 1 + rng.Next 20)
        | 1 -> List(randomType rng (depth - 1), [| 1; 5; 16; 1000; 1 <<< 20 |][rng.Next 5])
        | 2 -> Container(Array.init (1 + rng.Next 12) (fun i -> $"f{i}", randomType rng (depth - 1)))
        | 3 -> ProgressiveList(randomType rng (depth - 1))
        | 4 -> ProgressiveContainer(Array.init (1 + rng.Next 12) (fun i -> $"f{i}", randomType rng (depth - 1)))
        | _ -> leaf ()

/// A random value of `t`. Byte strings run to 3,000 bytes and progressive lists to 89 items, past
/// the first four progressive subtrees (1 + 4 + 16 + 64 chunks).
let rec private randomValue (rng: Random) (t: SszType) : SszValue =
    let upTo (limit: int) (cap: int) = rng.Next(min limit cap + 1)
    let bits n = Array.init n (fun _ -> rng.Next 2 = 1)

    match t with
    | Uint 8 -> U(uint64 (rng.NextInt64()) ^^^ (uint64 (rng.Next 2) <<< 63))
    | Uint n -> U(uint64 (rng.NextInt64(1L <<< (8 * n))))
    | Uint256 -> Bytes(randomBytes rng 32)
    | Boolean -> Bool(rng.Next 2 = 1)
    | ByteVector n -> Bytes(randomBytes rng n)
    | ByteList n -> Bytes(randomBytes rng (upTo n 3000))
    | ProgressiveByteList -> Bytes(randomBytes rng (rng.Next 3000))
    | Bitvector n -> Bits(bits n)
    | Bitlist n -> Bits(bits (upTo n 3000))
    | ProgressiveBitlist -> Bits(bits (rng.Next 3000))
    | Vector(e, n) -> Items(Array.init n (fun _ -> randomValue rng e))
    | List(e, n) -> Items(Array.init (upTo n 40) (fun _ -> randomValue rng e))
    | ProgressiveList e -> Items(Array.init (rng.Next 90) (fun _ -> randomValue rng e))
    | Container fs
    | ProgressiveContainer fs -> Fields(fs |> Array.map (fun (_, ft) -> randomValue rng ft))

/// Mainnet-like counts, as the block proposal bench fills them: `txs` transactions of 100 to
/// 3,399 bytes, 6 blobs, 8 attestations of 31,000 bits, 16 withdrawals.
let rec private fill (rng: Random) (txs: int) (parent: string) (name: string) (t: SszType) : SszValue =
    let count () =
        match parent, name with
        | ("execution_payload" | "payload"), "transactions" -> txs
        | ("execution_payload" | "payload"), "withdrawals" -> 16
        | _, "attestations" -> 8
        | _, "blob_kzg_commitments" -> 6
        | _, "kzg_proofs" -> 6 * 128
        | _, "blobs" -> 6
        | _, "payload_attestations" -> 4
        | _ -> 0

    match t with
    | Uint _ -> U(uint64 (rng.Next(1, 1_000_000)))
    | Uint256 -> Bytes(randomBytes rng 32)
    | Boolean -> Bool true
    | ByteVector n -> Bytes(randomBytes rng n)
    | ByteList limit -> Bytes(randomBytes rng (min limit 16))
    | Bitvector n -> Bits(Array.init n (fun i -> i % 3 <> 0))
    | Bitlist limit ->
        if name = "aggregation_bits" then Bits(Array.init (min limit 31_000) (fun i -> i % 50 <> 0)) else Bits [||]
    | ProgressiveBitlist -> Bits [||]
    | ProgressiveByteList -> Bytes(randomBytes rng (if name = "block_access_list" then 65_536 else 16))
    | Vector(e, n) -> Items(Array.init n (fun _ -> fill rng txs parent name e))
    | List(e, _)
    | ProgressiveList e ->
        Items(
            Array.init (count ()) (fun i ->
                if name = "transactions" then
                    Bytes(randomBytes rng (100 + (i * 7919) % 3300))
                else
                    fill rng txs name "" e)
        )
    | Container fs
    | ProgressiveContainer fs -> Fields [| for n, ft in fs -> fill rng txs name n ft |]

let private same (t: SszType) (v: SszValue) =
    Expect.equal (serialize t v) (Ref.serialize t v) "serialize"
    Expect.equal (hashTreeRoot t v) (Ref.hashTreeRoot t v) "hash_tree_root"

let private chunks (rng: Random) (n: int) = Array.init n (fun _ -> randomBytes rng 32)

/// `v` with the field at `path` (field indexes) replaced by `x`; `v` itself stays.
let rec private setAt (v: SszValue) (path: int list) (x: SszValue) =
    match v, path with
    | _, [] -> x
    | Fields fs, i :: rest ->
        let copy = Array.copy fs
        copy[i] <- setAt fs[i] rest x
        Fields copy
    | _ -> failwith "not a container"

// Sequenced: the reference code hashes 600-transaction blocks at about 16 ms each and the new
// code spreads them over several cores, so the list runs apart from the timing-sensitive ones.
[<Tests>]
let tests =
    testSequenced
    <| testList
        "ssz cross-check"
        [
            test "random schemas and values" {
                let rng = Random 20261105

                for _ in 1..800 do
                    let t = randomType rng (rng.Next 4)
                    same t (randomValue rng t)
            }

            test "merkleize of 0 to 70 chunks, under the count and under larger limits" {
                let rng = Random 1

                for n in 0..70 do
                    let cs = chunks rng n
                    Expect.equal (merkleize cs ValueNone) (Ref.merkleize cs ValueNone) $"{n} chunks"

                    for limit in [ int64 n; 128L; 1L <<< 25; 1L <<< 40 ] do
                        if int64 n <= limit then
                            Expect.equal
                                (merkleize cs (ValueSome limit))
                                (Ref.merkleize cs (ValueSome limit))
                                $"{n} chunks, limit {limit}"
            }

            test "merkleizeProgressive of 0 to 400 chunks" {
                let rng = Random 2

                for n in 0..400 do
                    let cs = chunks rng n
                    Expect.equal (merkleizeProgressive cs) (Ref.merkleizeProgressive cs) $"{n} chunks"
            }

            test "transaction lists of every size around a SIMD group" {
                let rng = Random 3
                let t = List(ByteList(1 <<< 30), 1 <<< 20)
                let pt = ProgressiveList ProgressiveByteList

                for n in 0..40 do
                    let v = Items(Array.init n (fun _ -> Bytes(randomBytes rng (rng.Next 600))))
                    same t v
                    same pt v
            }

            test "mainnet Fulu BlockContents" {
                let schema = Schemas.blockContents Preset.Mainnet

                for txs in [ 0; 1; 7; 9; 600 ] do
                    let v = fill (Random txs) txs "" "" schema
                    same schema v
                    let block = (Codec.fields v).[0]
                    same (Schemas.beaconBlockBody Preset.Mainnet) (Codec.fields block).[4]
            }

            test "mainnet Gloas BlockContents and envelope" {
                let schema = Schemas.Gloas.blockContents Preset.Mainnet

                for txs in [ 0; 1; 7; 9; 600 ] do
                    let v = fill (Random txs) txs "" "" schema
                    same schema v

                    for i, (name, ft) in
                        Array.indexed (
                            match schema with
                            | Container fs -> fs
                            | _ -> [||]
                        ) do
                        if name = "execution_payload_envelope" then
                            same ft (Codec.fields v).[i]
            }

            test "a block encoded before its signature gets the bytes of the signed block" {
                let p = Preset.Mainnet

                let shapes =
                    [
                        Schemas.signedBlockContents p, [ 0; 1 ]
                        Schemas.signedBlindedBeaconBlock p, [ 1 ]
                        Schemas.Gloas.signedBeaconBlock p, [ 1 ]
                        Schemas.Gloas.signedExecutionPayloadEnvelopeContents p, [ 0; 1 ]
                        Schemas.Gloas.signedExecutionPayloadEnvelope p, [ 1 ]
                    ]

                for schema, path in shapes do
                    let rng = Random 5
                    let v = fill rng 9 "" "" schema
                    let signature = randomBytes rng 96
                    let build (sg: SszValue) = setAt v path sg
                    let signed = UnsignedPublication(schema, build, path).WithSignature signature
                    Expect.equal signed.Ssz (serialize schema (build (Bytes signature))) $"bytes of {path}"

                    Expect.equal
                        (hashTreeRoot schema signed.Value)
                        (hashTreeRoot schema (build (Bytes signature)))
                        "value"
            }

            test "values that do not match the schema fail as before" {
                let rng = Random 4

                let cases =
                    [
                        ByteVector 32, Bytes(Array.zeroCreate 31)
                        Uint 1, U 300UL
                        List(Uint 8, 2), Items [| U 1UL; U 2UL; U 3UL |]
                        ByteList 4, Bytes(Array.zeroCreate 5)
                        List(ByteList 4, 8), Items [| Bytes [| 1uy |]; Bytes(Array.zeroCreate 5) |]
                        List(ByteList 4, 8), Items [| Bytes [| 1uy |]; U 1UL |]
                        ProgressiveList ProgressiveByteList, Items [| Bool true |]
                        Container [| "a", Uint 8; "b", Boolean |], Fields [| U 1UL |]
                        Container [| "a", Uint 8; "b", ByteList 10 |], Fields [| U 1UL; Bool false |]
                        Bitvector 9, Bits(Array.zeroCreate 8)
                        Vector(Uint256, 2), Items [| Bytes(randomBytes rng 32) |]
                    ]

                for t, v in cases do
                    Expect.throwsT<SszError> (fun () -> serialize t v |> ignore) $"serialize {t}"
                    Expect.throwsT<SszError> (fun () -> Ref.serialize t v |> ignore) $"reference serialize {t}"
                    Expect.throwsT<SszError> (fun () -> hashTreeRoot t v |> ignore) $"hash_tree_root {t}"
                    Expect.throwsT<SszError> (fun () -> Ref.hashTreeRoot t v |> ignore) $"reference hash_tree_root {t}"
            }

            test "both lane widths of PairHash match SHA256.HashData, in place too" {
                let rng = Random 6
                let paths = if Runtime.Intrinsics.X86.Avx2.IsSupported then [ false; true ] else [ false ]

                for wide in paths do
                    for count in 0..41 do
                        let input = randomBytes rng (64 * count)

                        let expected =
                            Array.init count (fun i ->
                                Security.Cryptography.SHA256.HashData(ReadOnlySpan(input, 64 * i, 64)))
                            |> Array.concat

                        let output = Array.zeroCreate<byte>(32 * count)
                        PairHash.hashPairsOn wide (ReadOnlySpan input) (Span output) count
                        Expect.equal output expected $"wide={wide} count={count}"
                        let buf = Array.copy input
                        PairHash.hashPairsOn wide (ReadOnlySpan buf) (Span buf) count
                        Expect.equal buf[.. 32 * count - 1] expected $"in place, wide={wide} count={count}"
            }
        ]
