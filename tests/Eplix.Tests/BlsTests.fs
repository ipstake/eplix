/// ethereum/bls12-381-tests v0.1.2 (JSON form), all nine handlers.
module Eplix.Tests.BlsTests

open System
open System.IO
open System.Text.Json
open Expecto
open Eplix
open Eplix.Tests.TestUtil

let private cases kind =
    Directory.GetFiles(Path.Combine(vectors, "bls", kind), "*.json")
    |> Array.sort
    |> Array.map (fun f ->
        Path.GetFileNameWithoutExtension f, JsonDocument.Parse(File.ReadAllText f).RootElement.Clone())
    |> Array.toList

let private str (e: JsonElement) (name: string) = e.GetProperty(name).GetString()

/// Inputs in the invalid cases may not even be valid hex; treat that as "not a point".
let private bytesOrEmpty (s: string) =
    match Hex.tryDecode s with
    | ValueSome b -> b
    | ValueNone -> [||]

let private signCases () =
    [
        for name, c in cases "sign" ->
            test name {
                let input = c.GetProperty "input"
                let sk = bytesOrEmpty (str input "privkey")
                let msg = hex (str input "message")
                let output = c.GetProperty "output"

                if output.ValueKind = JsonValueKind.Null then
                    Expect.isFalse (Bls.isValidSecret (ReadOnlySpan sk)) "secret must be refused"
                else
                    let s = Bls.sign (ReadOnlySpan sk) (ReadOnlySpan msg)
                    Expect.equal (Hex.encodeArray s) (output.GetString()) "signature"
            }
    ]

let private verifyCases () =
    [
        for name, c in cases "verify" ->
            test name {
                let input = c.GetProperty "input"

                let ok =
                    Bls.verify
                        (ReadOnlySpan(bytesOrEmpty (str input "pubkey")))
                        (ReadOnlySpan(hex (str input "message")))
                        (ReadOnlySpan(bytesOrEmpty (str input "signature")))

                Expect.equal ok (c.GetProperty("output").GetBoolean()) "verify result"
            }
    ]

let private aggregateCases () =
    [
        for name, c in cases "aggregate" ->
            test name {
                let sigs =
                    [
                        for s in c.GetProperty("input").EnumerateArray() -> bytesOrEmpty (s.GetString())
                    ]

                let output = c.GetProperty "output"

                match Bls.aggregate sigs with
                | ValueSome agg ->
                    Expect.notEqual output.ValueKind JsonValueKind.Null "aggregate should fail"
                    Expect.equal (Hex.encodeArray agg) (output.GetString()) "aggregate"
                | ValueNone -> Expect.equal output.ValueKind JsonValueKind.Null "aggregate should succeed"
            }
    ]

let private fastAggregateVerifyCases () =
    [
        for name, c in cases "fast_aggregate_verify" ->
            test name {
                let input = c.GetProperty "input"

                let keys =
                    [
                        for k in input.GetProperty("pubkeys").EnumerateArray() -> bytesOrEmpty (k.GetString())
                    ]

                let ok =
                    Bls.fastAggregateVerify
                        keys
                        (ReadOnlySpan(hex (str input "message")))
                        (ReadOnlySpan(bytesOrEmpty (str input "signature")))

                Expect.equal ok (c.GetProperty("output").GetBoolean()) "fast_aggregate_verify result"
            }
    ]

/// Hex with or without 0x (the deserialization vectors leave it out).
let private bytesOf (s: string) = bytesOrEmpty (if s.StartsWith "0x" then s else "0x" + s)

/// The threshold combinator checks a burst's signatures with Bls.verifyBatch. Each vector is one
/// batch of (key, 32-byte message, signature).
let private batchVerifyCases () =
    [
        for name, c in cases "batch_verify" ->
            test name {
                let input = c.GetProperty "input"

                let keys =
                    [
                        for k in input.GetProperty("pubkeys").EnumerateArray() -> bytesOf (k.GetString())
                    ]

                let msgs =
                    [
                        for m in input.GetProperty("messages").EnumerateArray() -> bytesOf (m.GetString())
                    ]

                let sigs =
                    [
                        for s in input.GetProperty("signatures").EnumerateArray() -> bytesOf (s.GetString())
                    ]

                let items =
                    List.zip3 keys msgs sigs
                    |> List.map (fun (k, m, s) ->
                        ({
                            Key = PubKey.Of k
                            Message = Root.Of m
                            Signature = s
                        }
                        : Bls.BatchItem))
                    |> Array.ofList

                Expect.equal (Bls.verifyBatch items) (c.GetProperty("output").GetBoolean()) "verifyBatch result"
            }
    ]

/// Public keys from remote signers go through Bls.keyValidate, which also refuses the point at
/// infinity: a vector that deserializes to infinity is a valid encoding but not a usable key.
let private deserializationG1Cases () =
    [
        for name, c in cases "deserialization_G1" ->
            test name {
                let pk = bytesOf (c.GetProperty("input").GetProperty("pubkey").GetString())
                let decodes = c.GetProperty("output").GetBoolean()
                let infinity = pk.Length = 48 && pk[0] = 0xC0uy && Array.forall ((=) 0uy) pk[1..]
                Expect.equal (Bls.keyValidate (ReadOnlySpan pk)) (decodes && not infinity) "keyValidate"
            }
    ]

/// Signatures from remote signers are decoded and group-checked on the way into an aggregate or a
/// combination; Bls.aggregate of one signature does exactly that.
let private deserializationG2Cases () =
    [
        for name, c in cases "deserialization_G2" ->
            test name {
                let s = bytesOf (c.GetProperty("input").GetProperty("signature").GetString())

                Expect.equal
                    (Bls.aggregate [ s ]).IsSome
                    (c.GetProperty("output").GetBoolean())
                    "decodes into an aggregate"
            }
    ]

type private Blst = Nethermind.Crypto.Bls

/// AggregateVerify (POP scheme): every key valid and not infinity, the signature in G2, and
/// prod e(H(m_i), pk_i) = e(sig, g1).
let private aggregateVerify (keys: byte[][]) (msgs: byte[][]) (sigBytes: byte[]) : bool =
    let mutable err = Blst.ERROR.SUCCESS
    let sg = Blst.P2Affine()

    if keys.Length = 0 || keys.Length <> msgs.Length || sigBytes.Length <> 96 then
        false
    elif not (sg.TryDecode(ReadOnlySpan sigBytes, &err) && sg.InGroup()) then
        false
    elif not (keys |> Array.forall (fun k -> Bls.keyValidate (ReadOnlySpan k))) then
        false
    else
        let mutable lhs = Blst.PT()

        for i in 0 .. keys.Length - 1 do
            let pk = Blst.P1Affine()
            pk.Decode(ReadOnlySpan keys[i])
            let hm = Blst.P2().HashTo(ReadOnlySpan msgs[i], ReadOnlySpan Bls.dst, ReadOnlySpan.Empty).ToAffine()
            let term = Blst.PT(hm, pk)
            lhs <- if i = 0 then term else lhs.Mul(term)

        Blst.PT.FinalVerify(lhs, Blst.PT(sg, Blst.G1().ToAffine()))

/// Eplix has no AggregateVerify of its own (it never checks one aggregate over several messages).
/// These vectors check the BLS library's pairing that Eplix's verify builds on, with the key and
/// signature checks of the Ethereum spec.
let private aggregateVerifyCases () =
    [
        for name, c in cases "aggregate_verify" ->
            test name {
                let input = c.GetProperty "input"

                let keys =
                    [|
                        for k in input.GetProperty("pubkeys").EnumerateArray() -> bytesOf (k.GetString())
                    |]

                let msgs =
                    [|
                        for m in input.GetProperty("messages").EnumerateArray() -> bytesOf (m.GetString())
                    |]

                let sigBytes = bytesOf (input.GetProperty("signature").GetString())

                Expect.equal
                    (aggregateVerify keys msgs sigBytes)
                    (c.GetProperty("output").GetBoolean())
                    "aggregate_verify result"
            }
    ]

let private hashToG2 (dst: byte[]) (msg: byte[]) : byte[] =
    Blst.P2().HashTo(ReadOnlySpan msg, ReadOnlySpan dst, ReadOnlySpan.Empty).ToAffine().Serialize()

/// hash_to_curve (RFC 9380, BLS12381G2_XMD:SHA-256_SSWU_RO_) of the BLS library, which Bls.sign and
/// Bls.verify call with Eplix's DST. The vectors use the RFC's test DST.
let private hashToG2Cases () =
    let dst = Text.Encoding.ASCII.GetBytes "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"

    [
        for name, c in cases "hash_to_G2" ->
            test name {
                let msg = Text.Encoding.ASCII.GetBytes(c.GetProperty("input").GetProperty("msg").GetString())
                let p = hashToG2 dst msg
                // Uncompressed G2: x.c1, x.c0, y.c1, y.c0, 48 bytes each; the vector writes "c0,c1".
                let fp2 (offset: int) =
                    $"{Hex.encodeArray p[offset + 48 .. offset + 95]},{Hex.encodeArray p[offset .. offset + 47]}"

                let output = c.GetProperty "output"
                Expect.equal (fp2 0) (output.GetProperty("x").GetString()) "x"
                Expect.equal (fp2 96) (output.GetProperty("y").GetString()) "y"
            }
    ]

[<Tests>]
let tests =
    testList
        "bls"
        [
            testList "sign" (signCases ())
            testList "verify" (verifyCases ())
            testList "aggregate" (aggregateCases ())
            testList "fast_aggregate_verify" (fastAggregateVerifyCases ())
            testList "batch_verify" (batchVerifyCases ())
            testList "deserialization_G1" (deserializationG1Cases ())
            testList "deserialization_G2" (deserializationG2Cases ())
            testList "aggregate_verify" (aggregateVerifyCases ())
            testList "hash_to_G2" (hashToG2Cases ())
            test "every handler of bls12-381-tests v0.1.2 is present" {
                let counts =
                    [
                        "sign", 10
                        "verify", 29
                        "aggregate", 6
                        "fast_aggregate_verify", 12
                        "batch_verify", 4
                        "deserialization_G1", 13
                        "deserialization_G2", 15
                        "aggregate_verify", 5
                        "hash_to_G2", 4
                    ]

                for kind, n in counts do
                    Expect.equal (cases kind).Length n $"{kind}: vector files"
            }

            test "public key of a known secret" {
                // The first secret of the sign vectors and its key from the verify vectors.
                let sk = hex "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"
                let pk = Bls.publicKey (ReadOnlySpan sk)

                Expect.equal
                    (Hex.encodeArray pk)
                    "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
                    "pubkey"
            }

            test "a secret is valid in [1, r - 1] only" {
                let r =
                    Numerics.BigInteger.Parse
                        "52435875175126190479447740508185965837690552500527637822603658699938581184513"

                let bytesOf (x: Numerics.BigInteger) =
                    let b = x.ToByteArray(isUnsigned = true, isBigEndian = true)
                    Array.append (Array.zeroCreate (32 - b.Length)) b

                let valid (b: byte[]) = Bls.isValidSecret (ReadOnlySpan b)
                Expect.isFalse (valid (Array.zeroCreate 32)) "zero"
                Expect.isTrue (valid (bytesOf Numerics.BigInteger.One)) "one"
                Expect.isTrue (valid (bytesOf (r - Numerics.BigInteger.One))) "r - 1"
                Expect.isFalse (valid (bytesOf r)) "r"
                Expect.isFalse (valid (bytesOf (r + Numerics.BigInteger.One))) "r + 1"
                Expect.isFalse (valid (Array.create 32 0xffuy)) "all ones"
                Expect.isFalse (valid (Array.zeroCreate 31)) "31 bytes"
                Expect.isFalse (valid (Array.zeroCreate 33)) "33 bytes"
                // Random values on both sides of r agree with a BigInteger compare.
                let rng = Random 7

                for _ in 1..2000 do
                    let b = Array.zeroCreate<byte> 32
                    rng.NextBytes b
                    b[0] <- b[0] &&& 0x7fuy
                    // Often share a prefix with r, so later bytes decide.
                    let keep = rng.Next 33
                    Array.blit (bytesOf r) 0 b 0 keep
                    let x = Numerics.BigInteger(ReadOnlySpan b, isUnsigned = true, isBigEndian = true)
                    Expect.equal (valid b) (x.Sign > 0 && x < r) $"{Convert.ToHexString b}"
            }
        ]
