/// scrypt (RFC 7914) for EIP-2335 keystores. .NET has PBKDF2 but no scrypt.
module Eplix.Backend.Local.Scrypt

#nowarn "9" // native memory for V, see roMix

open System
open System.Buffers.Binary
open System.Numerics
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Threading

let private salsa208 (b: uint32[]) (offset: int) (x: uint32[]) =
    Array.blit b offset x 0 16
    let inline r (a: uint32) (n: int) = BitOperations.RotateLeft(a, n)

    for _ in 1..4 do
        x[4] <- x[4] ^^^ r (x[0] + x[12]) 7
        x[8] <- x[8] ^^^ r (x[4] + x[0]) 9
        x[12] <- x[12] ^^^ r (x[8] + x[4]) 13
        x[0] <- x[0] ^^^ r (x[12] + x[8]) 18
        x[9] <- x[9] ^^^ r (x[5] + x[1]) 7
        x[13] <- x[13] ^^^ r (x[9] + x[5]) 9
        x[1] <- x[1] ^^^ r (x[13] + x[9]) 13
        x[5] <- x[5] ^^^ r (x[1] + x[13]) 18
        x[14] <- x[14] ^^^ r (x[10] + x[6]) 7
        x[2] <- x[2] ^^^ r (x[14] + x[10]) 9
        x[6] <- x[6] ^^^ r (x[2] + x[14]) 13
        x[10] <- x[10] ^^^ r (x[6] + x[2]) 18
        x[3] <- x[3] ^^^ r (x[15] + x[11]) 7
        x[7] <- x[7] ^^^ r (x[3] + x[15]) 9
        x[11] <- x[11] ^^^ r (x[7] + x[3]) 13
        x[15] <- x[15] ^^^ r (x[11] + x[7]) 18
        x[1] <- x[1] ^^^ r (x[0] + x[3]) 7
        x[2] <- x[2] ^^^ r (x[1] + x[0]) 9
        x[3] <- x[3] ^^^ r (x[2] + x[1]) 13
        x[0] <- x[0] ^^^ r (x[3] + x[2]) 18
        x[6] <- x[6] ^^^ r (x[5] + x[4]) 7
        x[7] <- x[7] ^^^ r (x[6] + x[5]) 9
        x[4] <- x[4] ^^^ r (x[7] + x[6]) 13
        x[5] <- x[5] ^^^ r (x[4] + x[7]) 18
        x[11] <- x[11] ^^^ r (x[10] + x[9]) 7
        x[8] <- x[8] ^^^ r (x[11] + x[10]) 9
        x[9] <- x[9] ^^^ r (x[8] + x[11]) 13
        x[10] <- x[10] ^^^ r (x[9] + x[8]) 18
        x[12] <- x[12] ^^^ r (x[15] + x[14]) 7
        x[13] <- x[13] ^^^ r (x[12] + x[15]) 9
        x[14] <- x[14] ^^^ r (x[13] + x[12]) 13
        x[15] <- x[15] ^^^ r (x[14] + x[13]) 18

    for i in 0..15 do
        b[offset + i] <- b[offset + i] + x[i]

/// BlockMix over 2r 64-byte blocks of `b` (as words), output to `y`.
let private blockMix (b: uint32[]) (y: uint32[]) (r: int) (x: uint32[]) (tmp: uint32[]) =
    Array.blit b ((2 * r - 1) * 16) x 0 16

    for i in 0 .. 2 * r - 1 do
        for k in 0..15 do
            x[k] <- x[k] ^^^ b[i * 16 + k]
        // salsa208 works in place on its first argument.
        salsa208 x 0 tmp
        // Even blocks go to the first half, odd blocks to the second half.
        let dst = (if i % 2 = 0 then i / 2 else r + i / 2) * 16
        Array.blit x 0 y dst 16

/// V (128 * r * n bytes, 256 MiB for keystores) lives in native memory and is zeroed and freed
/// at once. A managed array of that size stays on the large object heap until a full GC, so
/// loading 32 keystores held about 1 GiB of RSS. `ct` is read every 4096 blocks.
let private roMix (block: uint32[]) (r: int) (n: int) (ct: CancellationToken) =
    let words = 32 * r
    let total = int64 words * int64 n
    let ptr = NativeMemory.Alloc(unativeint total * 4un)
    let mutable x = Array.copy block
    let mutable y = Array.zeroCreate<uint32> words
    let t = Array.zeroCreate<uint32> 16
    let tmp = Array.zeroCreate<uint32> 16

    try
        let v = Span<uint32>(ptr, int total)

        for i in 0 .. n - 1 do
            if i &&& 4095 = 0 then
                ct.ThrowIfCancellationRequested()

            x.AsSpan().CopyTo(v.Slice(i * words, words))
            blockMix x y r t tmp
            let s = x
            x <- y
            y <- s

        for i in 0 .. n - 1 do
            if i &&& 4095 = 0 then
                ct.ThrowIfCancellationRequested()

            let j = int (x[(2 * r - 1) * 16] &&& uint32 (n - 1))
            let vj = v.Slice(j * words, words)

            for k in 0 .. words - 1 do
                x[k] <- x[k] ^^^ vj[k]

            blockMix x y r t tmp
            let s = x
            x <- y
            y <- s

        Array.blit x 0 block 0 words
    finally
        // Zeroed on cancel too.
        CryptographicOperations.ZeroMemory(Span<byte>(ptr, int (total * 4L)))
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(x.AsSpan()))
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(y.AsSpan()))
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(t.AsSpan()))
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(tmp.AsSpan()))
        NativeMemory.Free ptr

/// The largest V (128 * r * n bytes) one derivation may take. Keystores use 256 MiB; n = 2^20
/// with r = 8 is exactly 1 GiB and allowed.
let maxMemory = 1L <<< 30

/// The largest p. EIP-2335 keystores use p = 1; the RFC 7914 vectors go up to 16.
let maxP = 16

/// The largest r. EIP-2335 keystores and the RFC 7914 vectors use r = 8 (r = 1 in one vector).
/// A large r with a tiny n passes the memory and work checks on V alone, yet every per-block
/// buffer below is 128 * r bytes; 32 leaves room for unusual tools and keeps those at 4 KiB.
/// Beside V, a derivation allocates 128 * r bytes each for the p blocks of `b`, for `words` and
/// for roMix's `x` and `y`: with r and p at their caps that is at most about 76 KiB, so the caps
/// on r, p and V bound the whole allocation and no separate total check is needed.
let maxR = 32

/// The most work one derivation may take, as r * n * p: as much as one pass at the memory cap,
/// about 4 s on one core. A keystore with n = 2^18, r = 8, p = 1 takes a quarter of it.
let maxWork = maxMemory / 128L

/// scrypt that stops with OperationCanceledException when `ct` is cancelled.
let deriveWith
    (ct: CancellationToken)
    (password: byte[])
    (salt: byte[])
    (n: int)
    (r: int)
    (p: int)
    (dkLen: int)
    : byte[] =
    if n < 2 || n &&& (n - 1) <> 0 then
        invalidArg "n" "must be a power of 2 above 1"

    if r < 1 || p < 1 || int64 r * int64 p >= (1L <<< 30) then
        invalidArg "r" "bad r or p"

    if p > maxP then
        invalidArg "p" $"p {p} is above {maxP}"

    if r > maxR then
        invalidArg "r" $"r {r} is above {maxR}"

    if 128L * int64 r * int64 n > maxMemory then
        invalidArg "n" "scrypt parameters need too much memory"

    if int64 r * int64 n * int64 p > maxWork then
        invalidArg "p" "scrypt parameters need too much work"

    ct.ThrowIfCancellationRequested()
    let blockBytes = 128 * r
    let b = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1, HashAlgorithmName.SHA256, p * blockBytes)
    // roMix's output, the input of the last PBKDF2: zeroed with b.
    let words = Array.zeroCreate<uint32>(32 * r)

    try
        for i in 0 .. p - 1 do
            for k in 0 .. words.Length - 1 do
                words[k] <- BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(b, i * blockBytes + 4 * k, 4))

            roMix words r n ct

            for k in 0 .. words.Length - 1 do
                BinaryPrimitives.WriteUInt32LittleEndian(Span(b, i * blockBytes + 4 * k, 4), words[k])

        Rfc2898DeriveBytes.Pbkdf2(password, b, 1, HashAlgorithmName.SHA256, dkLen)
    finally
        CryptographicOperations.ZeroMemory(Span b)
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(words.AsSpan()))

let derive (password: byte[]) (salt: byte[]) (n: int) (r: int) (p: int) (dkLen: int) : byte[] =
    deriveWith CancellationToken.None password salt n r p dkLen
