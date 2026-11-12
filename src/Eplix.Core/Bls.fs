/// BLS12-381 signatures as Ethereum uses them (proof-of-possession scheme), over blst
/// through Nethermind.Crypto.Bls. Byte arrays in and out; the blst types stay inside this file.
module Eplix.Bls

open System
open System.Numerics

type private B = Nethermind.Crypto.Bls

/// The ciphersuite tag of the proof-of-possession scheme.
let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"B

let private curveOrder =
    BigInteger.Parse("52435875175126190479447740508185965837690552500527637822603658699938581184513")

/// r as 32 big-endian bytes.
let private curveOrderBytes =
    Convert.FromHexString "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

/// A secret key is a 32-byte big-endian scalar in [1, r - 1]. Compares every byte with no early
/// exit and makes no copy of the secret.
let isValidSecret (secret: ReadOnlySpan<byte>) : bool =
    if secret.Length <> 32 then
        false
    else
        // less and greater turn to 1 at the first byte that differs from r and stay there.
        let mutable less = 0
        let mutable greater = 0
        let mutable any = 0

        for i in 0..31 do
            let a = int secret[i]
            let b = int curveOrderBytes[i]
            let undecided = 1 ^^^ (less ||| greater)
            less <- less ||| (undecided &&& ((a - b) >>> 31) &&& 1)
            greater <- greater ||| (undecided &&& ((b - a) >>> 31) &&& 1)
            any <- any ||| a

        less = 1 && any <> 0

let private checkSecret (secret: ReadOnlySpan<byte>) =
    if not (isValidSecret secret) then
        invalidArg "secret" "not a valid BLS secret key"

/// The compressed 48-byte public key of a secret key.
let publicKey (secret: ReadOnlySpan<byte>) : byte[] =
    checkSecret secret
    let sk = B.SecretKey(secret, B.ByteOrder.BigEndian)
    let p = B.P1(sk)
    p.Compress()

/// Signs a message (for the VC, a 32-byte signing root). Returns the compressed 96-byte signature.
let sign (secret: ReadOnlySpan<byte>) (message: ReadOnlySpan<byte>) : byte[] =
    checkSecret secret
    let sk = B.SecretKey(secret, B.ByteOrder.BigEndian)
    let h = B.P2()
    let s = h.HashTo(message, ReadOnlySpan dst, ReadOnlySpan.Empty).SignWith(sk)
    s.Compress()

/// e(pk, H(m)) == e(g1, sig), with both points already checked.
let private coreVerify (pk: B.P1Affine) (message: ReadOnlySpan<byte>) (signature: B.P2Affine) : bool =
    let h = B.P2()
    let hm = h.HashTo(message, ReadOnlySpan dst, ReadOnlySpan.Empty).ToAffine()
    let lhs = B.PT(hm, pk)
    let g1 = B.G1().ToAffine()
    let rhs = B.PT(signature, g1)
    B.PT.FinalVerify(lhs, rhs)

/// KeyValidate: a valid compressed point in G1 that is not the point at infinity.
let keyValidate (pubkey: ReadOnlySpan<byte>) : bool =
    if pubkey.Length <> 48 then
        false
    else
        let mutable err = B.ERROR.SUCCESS
        let pk = B.P1Affine()
        pk.TryDecode(pubkey, &err) && not (pk.IsInf()) && pk.InGroup()

let verify (pubkey: ReadOnlySpan<byte>) (message: ReadOnlySpan<byte>) (signature: ReadOnlySpan<byte>) : bool =
    if pubkey.Length <> 48 || signature.Length <> 96 then
        false
    else
        let mutable err = B.ERROR.SUCCESS
        let pk = B.P1Affine()
        let sg = B.P2Affine()

        pk.TryDecode(pubkey, &err)
        && not (pk.IsInf())
        && pk.InGroup()
        && sg.TryDecode(signature, &err)
        && sg.InGroup()
        && coreVerify pk message sg

/// Aggregates signatures. ValueNone for an empty list or any invalid signature.
let aggregate (signatures: byte[] seq) : byte[] voption =
    let sigs = Seq.toArray signatures

    if sigs.Length = 0 then
        ValueNone
    else
        let acc = B.P2()
        let mutable ok = true
        let mutable err = B.ERROR.SUCCESS

        for s in sigs do
            if ok then
                let a = B.P2Affine()

                if s.Length = 96 && a.TryDecode(ReadOnlySpan s, &err) && a.InGroup() then
                    acc.Aggregate(a)
                else
                    ok <- false

        if ok then ValueSome(acc.Compress()) else ValueNone

let private modR (x: BigInteger) =
    let m = BigInteger.Remainder(x, curveOrder)
    if m.Sign < 0 then m + curveOrder else m

let private scalarBytes (x: BigInteger) : byte[] =
    let b = x.ToByteArray(isUnsigned = true, isBigEndian = true)

    if b.Length = 32 then
        b
    else
        let out = Array.zeroCreate<byte> 32
        Buffer.BlockCopy(b, 0, out, 32 - b.Length, b.Length)
        out

/// The Lagrange coefficients at x = 0 for the share ids `ids` (the x coordinates), as 32-byte
/// big-endian scalars mod r: l_i = prod over j <> i of x_j / (x_j - x_i). ValueNone when an id is
/// 0 or two ids are equal.
let lagrangeCoefficients (ids: uint64[]) : byte[][] voption =
    if ids.Length = 0 || Array.contains 0UL ids || (Array.distinct ids).Length <> ids.Length then
        ValueNone
    else
        let xs = ids |> Array.map (fun (x: uint64) -> BigInteger x)

        ValueSome
            [|
                for i in 0 .. xs.Length - 1 do
                    let mutable num = BigInteger.One
                    let mutable den = BigInteger.One

                    for j in 0 .. xs.Length - 1 do
                        if j <> i then
                            num <- modR (num * xs[j])
                            den <- modR (den * (xs[j] - xs[i]))
                    // r is prime, so den^(r-2) is the inverse of den.
                    let inv = BigInteger.ModPow(den, curveOrder - BigInteger 2, curveOrder)
                    scalarBytes (modR (num * inv))
            |]

/// Combines signature shares by Lagrange interpolation at zero: the sum of l_i * s_i in G2.
/// `coefficients` come from lagrangeCoefficients over the same ids, in the same order.
/// ValueNone when the lengths differ or a share is not a point on the curve. The shares get no
/// subgroup check here: the caller verifies the result, and verify checks its subgroup.
let combineShares (coefficients: byte[][]) (shares: byte[][]) : byte[] voption =
    if coefficients.Length = 0 || coefficients.Length <> shares.Length then
        ValueNone
    else
        let mutable acc = B.P2()
        let mutable ok = true
        let mutable err = B.ERROR.SUCCESS

        for i in 0 .. shares.Length - 1 do
            if ok then
                let a = B.P2Affine()

                if shares[i].Length = 96 && a.TryDecode(ReadOnlySpan shares[i], &err) then
                    let mutable p = B.P2(a)
                    let s = B.Scalar(ReadOnlySpan coefficients[i], B.ByteOrder.BigEndian)
                    p <- p.Mult(s)
                    acc <- acc.Add(p)
                else
                    ok <- false

        if ok then ValueSome(acc.Compress()) else ValueNone

/// The public key of a threshold key from m share public keys: the sum of l_i * pk_i in G1,
/// compressed. Configuration checks use it; ValueNone when a key is not a valid point.
let combinePublicShares (coefficients: byte[][]) (keys: byte[][]) : byte[] voption =
    if coefficients.Length = 0 || coefficients.Length <> keys.Length then
        ValueNone
    else
        let mutable acc = B.P1()
        let mutable ok = true
        let mutable err = B.ERROR.SUCCESS

        for i in 0 .. keys.Length - 1 do
            if ok then
                let a = B.P1Affine()

                if keys[i].Length = 48 && a.TryDecode(ReadOnlySpan keys[i], &err) && a.InGroup() then
                    let mutable p = B.P1(a)
                    p <- p.Mult(B.Scalar(ReadOnlySpan coefficients[i], B.ByteOrder.BigEndian))
                    acc <- acc.Add(p)
                else
                    ok <- false

        if ok then ValueSome(acc.Compress()) else ValueNone

/// Lagrange coefficients at zero for one set of share ids, in two forms. Coefficients are the
/// full scalars. When they are small fractions n_i / d (small ids, as in every real group),
/// Numerators holds each n_i as a sign and little-endian magnitude and Denominator the inverse
/// of d (ValueNone when d = 1): then a combination costs short scalar multiplications plus at
/// most one full one, instead of one full multiplication per share.
type Lagrange =
    {
        Ids: uint64[]
        Coefficients: byte[][]
        Numerators: struct (bool * byte[])[] voption
        InverseDenominator: byte[] voption
    }

let private littleEndian (x: BigInteger) = x.ToByteArray(isUnsigned = true, isBigEndian = false)

/// The coefficients of `lagrangeCoefficients` plus their small-fraction form where it exists.
let lagrange (ids: uint64[]) : Lagrange voption =
    match lagrangeCoefficients ids with
    | ValueNone -> ValueNone
    | ValueSome full ->
        let xs = ids |> Array.map (fun (x: uint64) -> BigInteger x)
        // l_i = num_i / den_i over the integers, before any reduction mod r.
        let fractions =
            [|
                for i in 0 .. xs.Length - 1 do
                    let mutable num = BigInteger.One
                    let mutable den = BigInteger.One

                    for j in 0 .. xs.Length - 1 do
                        if j <> i then
                            num <- num * xs[j]
                            den <- den * (xs[j] - xs[i])

                    num, den
            |]

        let lcm (a: BigInteger) (b: BigInteger) = a / BigInteger.GreatestCommonDivisor(a, b) * b
        let d = fractions |> Array.fold (fun acc (_, den) -> lcm acc (BigInteger.Abs den)) BigInteger.One
        let numerators = fractions |> Array.map (fun (num, den) -> num * (d / den))
        let limit = BigInteger.Pow(BigInteger 2, 64)
        let small = numerators |> Array.forall (fun n -> BigInteger.Abs n < limit) && d < curveOrder

        ValueSome
            {
                Ids = Array.copy ids
                Coefficients = full
                Numerators =
                    if small then
                        ValueSome(
                            numerators |> Array.map (fun n -> struct (n.Sign < 0, littleEndian (BigInteger.Abs n)))
                        )
                    else
                        ValueNone
                InverseDenominator =
                    if small && not d.IsOne then
                        let inv = BigInteger.ModPow(d, curveOrder - BigInteger 2, curveOrder)
                        let b = littleEndian inv
                        ValueSome(Array.append b (Array.zeroCreate (32 - b.Length)))
                    else
                        ValueNone
            }

/// combineShares with the small-fraction form when the set has one: the shares times their
/// small numerators, summed, times the inverse denominator. The same result, less CPU.
let combine (l: Lagrange) (shares: byte[][]) : byte[] voption =
    match l.Numerators with
    | ValueNone -> combineShares l.Coefficients shares
    | ValueSome numerators when numerators.Length = shares.Length ->
        let mutable acc = B.P2()
        let mutable ok = true
        let mutable err = B.ERROR.SUCCESS

        for i in 0 .. shares.Length - 1 do
            if ok then
                let a = B.P2Affine()

                if shares[i].Length = 96 && a.TryDecode(ReadOnlySpan shares[i], &err) then
                    let struct (negative, magnitude) = numerators[i]
                    let mutable p = B.P2(a)

                    if not (magnitude.Length = 1 && magnitude[0] = 1uy) then
                        p <- p.Mult(ReadOnlySpan magnitude)

                    if negative then
                        p <- p.Neg()

                    acc <- acc.Add(p)
                else
                    ok <- false

        if not ok then
            ValueNone
        else
            match l.InverseDenominator with
            | ValueSome inv -> ValueSome(acc.Mult(ReadOnlySpan inv).Compress())
            | ValueNone -> ValueSome(acc.Compress())
    | ValueSome _ -> ValueNone

/// Decoded public keys (affine G1 points as blst's limbs), checked once: valid, in the group,
/// not infinity. The batch check reads them for every signature of a burst.
let private decodedKeys = Collections.Concurrent.ConcurrentDictionary<PubKey, int64[]>()

let private decodedKey (key: PubKey) : int64[] voption =
    match decodedKeys.TryGetValue key with
    | true, p -> ValueSome p
    | _ ->
        let mutable err = B.ERROR.SUCCESS
        let pk = B.P1Affine()

        if pk.TryDecode(ReadOnlySpan key.Bytes, &err) && not (pk.IsInf()) && pk.InGroup() then
            let p = pk.Point.ToArray()
            // A bound on memory for a VC whose keys change a lot; the cache refills itself.
            if decodedKeys.Count > 200_000 then
                decodedKeys.Clear()

            decodedKeys[key] <- p
            ValueSome p
        else
            ValueNone

/// One signature for a batch check.
[<Struct>]
type BatchItem =
    {
        Key: PubKey
        Message: Root
        Signature: byte[]
    }

/// Checks a chunk with one pairing equation (random linear combination): with random 64-bit
/// r_i, prod over messages m of e(sum r_i pk_i, H(m)) = e(g1, sum r_i sig_i). Each signature
/// gets the subgroup check a single verify would do. True only if every signature is valid,
/// except with probability about 2^-64.
let private verifyChunk (items: BatchItem[]) (offset: int) (count: int) : bool =
    let scalars = Array.zeroCreate<byte>(32 * count)
    let random = Array.zeroCreate<byte>(8 * count)
    Security.Cryptography.RandomNumberGenerator.Fill(Span random)
    let sigLimbs = 24
    let keyLimbs = 12
    let sigs = Array.zeroCreate<int64>(sigLimbs * count)
    let mutable ok = true
    let mutable err = B.ERROR.SUCCESS
    let groups = Collections.Generic.Dictionary<Root, ResizeArray<int>>()
    let mutable i = 0

    while ok && i < count do
        let item = items[offset + i]
        // A zero scalar would drop the signature from the check.
        if BitConverter.ToUInt64(random, 8 * i) = 0UL then
            random[8 * i] <- 1uy

        Buffer.BlockCopy(random, 8 * i, scalars, 32 * i, 8)
        let s = B.P2Affine()

        if item.Signature.Length = 96 && s.TryDecode(ReadOnlySpan item.Signature, &err) && s.InGroup() then
            s.Point.CopyTo(Span(sigs, sigLimbs * i, sigLimbs))

            match groups.TryGetValue item.Message with
            | true, g -> g.Add i
            | _ -> groups[item.Message] <- ResizeArray [ i ]
        else
            ok <- false

        i <- i + 1

    if not ok then
        false
    else
        let sum = B.P2().MultiMultAffine(ReadOnlySpan sigs, ReadOnlySpan scalars, count)
        let lhs = B.PT(sum.ToAffine(), B.G1().ToAffine())
        let mutable rhs = B.PT()
        let mutable first = true

        for KeyValue(message, members) in groups do
            if ok then
                let keys = Array.zeroCreate<int64>(keyLimbs * members.Count)
                let ks = Array.zeroCreate<byte>(32 * members.Count)
                let mutable j = 0

                while ok && j < members.Count do
                    let idx = members[j]

                    match decodedKey items[offset + idx].Key with
                    | ValueSome p ->
                        Array.blit p 0 keys (keyLimbs * j) keyLimbs
                        Buffer.BlockCopy(scalars, 32 * idx, ks, 32 * j, 32)
                    | ValueNone -> ok <- false

                    j <- j + 1

                if ok then
                    let pk = B.P1().MultiMultAffine(ReadOnlySpan keys, ReadOnlySpan ks, members.Count)
                    let h = B.P2()
                    let hm = h.HashTo(ReadOnlySpan message.Bytes, ReadOnlySpan dst, ReadOnlySpan.Empty).ToAffine()
                    let term = B.PT(hm, pk.ToAffine())

                    if first then
                        rhs <- term
                        first <- false
                    else
                        rhs <- rhs.Mul(term)

        ok && B.PT.FinalVerify(lhs, rhs)

/// Verifies many signatures at once, split into chunks that run on every core. True when all
/// are valid (see verifyChunk). On false, at least one is invalid; the caller verifies one by
/// one to find it.
let verifyBatch (items: BatchItem[]) : bool =
    match items.Length with
    | 0 -> true
    | 1 ->
        let x = items[0]
        verify (ReadOnlySpan x.Key.Bytes) (ReadOnlySpan x.Message.Bytes) (ReadOnlySpan x.Signature)
    | n ->
        // Chunks of 32 to 256, about two per core: the pairing per chunk is cheap next to the
        // subgroup checks, and more chunks spread the work.
        let chunk = min 256 (max 32 (n / (2 * Environment.ProcessorCount) + 1))
        let chunks = (n + chunk - 1) / chunk
        let failed = ref 0

        Threading.Tasks.Parallel.For(
            0,
            chunks,
            fun c (state: Threading.Tasks.ParallelLoopState) ->
                let offset = c * chunk

                if not (verifyChunk items offset (min chunk (n - offset))) then
                    failed.Value <- 1
                    state.Stop()
        )
        |> ignore

        failed.Value = 0

/// FastAggregateVerify: many keys, one message, one aggregate signature.
let fastAggregateVerify (pubkeys: byte[] seq) (message: ReadOnlySpan<byte>) (signature: ReadOnlySpan<byte>) : bool =
    let keys = Seq.toArray pubkeys

    if keys.Length = 0 || signature.Length <> 96 then
        false
    else
        let acc = B.P1()
        let mutable ok = true
        let mutable err = B.ERROR.SUCCESS

        for k in keys do
            if ok then
                let a = B.P1Affine()

                if k.Length = 48 && a.TryDecode(ReadOnlySpan k, &err) && not (a.IsInf()) && a.InGroup() then
                    acc.Aggregate(a)
                else
                    ok <- false

        let sg = B.P2Affine()

        ok
        && sg.TryDecode(signature, &err)
        && sg.InGroup()
        && (let pk = acc.ToAffine()
            not (pk.IsInf()) && coreVerify pk message sg)
