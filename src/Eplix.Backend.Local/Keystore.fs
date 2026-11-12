/// EIP-2335 keystores (version 4): scrypt or PBKDF2-SHA256, SHA-256 checksum, AES-128-CTR.
module Eplix.Backend.Local.Keystore

open System
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Threading
open Eplix
open Eplix.Json

type Kdf =
    | Scrypt of n: int * r: int * p: int * salt: byte[] * dkLen: int
    | Pbkdf2 of c: int * salt: byte[] * dkLen: int

type Keystore =
    {
        Kdf: Kdf
        Checksum: byte[]
        Iv: byte[]
        CipherText: byte[]
        PubKey: PubKey voption
        Path: string
        Uuid: string
        Description: string
    }

let private hexBytes (e: JsonElement) =
    match Hex.tryDecode ("0x" + (str e).Replace("0x", "")) with
    | ValueSome b -> b
    | ValueNone -> fail "expected hex"

let private int32Of (e: JsonElement) =
    let v = u64 e

    if v > uint64 Int32.MaxValue then
        fail "number too large"

    int v

/// Upper bounds on the KDF work a keystore may ask for. EIP-2335 keystores use dklen 32 and
/// PBKDF2 c = 2^18; a keystore that asks for gigabytes of output or 2^31 rounds would stall the
/// import (scrypt memory is bounded in Scrypt.derive).
let maxDkLen = 64
let maxPbkdf2Rounds = 1 <<< 24

let private dkLenOf (e: JsonElement) =
    let v = int32Of e

    if v > maxDkLen then
        fail $"dklen {v} is above {maxDkLen}"

    v

let private decoder (e: JsonElement) : Keystore =
    if u64Field e "version" <> 4UL then
        fail "only keystore version 4 is supported"

    let crypto = prop e "crypto"
    let kdf = prop crypto "kdf"
    let kp = prop kdf "params"

    let kdfValue =
        match strField kdf "function" with
        | "scrypt" ->
            Scrypt(
                int32Of (prop kp "n"),
                int32Of (prop kp "r"),
                int32Of (prop kp "p"),
                hexBytes (prop kp "salt"),
                dkLenOf (prop kp "dklen")
            )
        | "pbkdf2" ->
            if strField kp "prf" <> "hmac-sha256" then
                fail "pbkdf2 prf must be hmac-sha256"

            let c = int32Of (prop kp "c")

            if c > maxPbkdf2Rounds then
                fail $"pbkdf2 c {c} is above {maxPbkdf2Rounds}"

            Pbkdf2(c, hexBytes (prop kp "salt"), dkLenOf (prop kp "dklen"))
        | other -> fail $"kdf '{other}' is not supported"

    let checksum = prop crypto "checksum"

    if strField checksum "function" <> "sha256" then
        fail "checksum function must be sha256"

    let cipher = prop crypto "cipher"

    if strField cipher "function" <> "aes-128-ctr" then
        fail "cipher must be aes-128-ctr"

    let optStr name =
        match tryProp e name with
        | ValueSome v -> str v
        | ValueNone -> ""

    {
        Kdf = kdfValue
        Checksum = hexBytes (prop checksum "message")
        Iv = hexBytes (prop (prop cipher "params") "iv")
        CipherText = hexBytes (prop cipher "message")
        PubKey =
            (match tryProp e "pubkey" with
             | ValueSome v when (str v).Length > 0 ->
                 match PubKey.TryParse("0x" + (str v).Replace("0x", "")) with
                 | ValueSome pk -> ValueSome pk
                 | ValueNone -> fail "pubkey is not a 48-byte hex value"
             | _ -> ValueNone)
        Path = optStr "path"
        Uuid = optStr "uuid"
        Description = optStr "description"
    }

let parse (json: string) : Result<Keystore, string> = decodeString decoder json

/// The EIP-2335 password rule: NFKD, then drop C0, C1 and DEL control codes, then UTF-8.
/// The build links ICU, so NFKD works for every password; with invariant globalization .NET does not normalize.
let passwordBytes (password: string) : Result<byte[], string> =
    let normalized = password.Normalize(NormalizationForm.FormKD)

    let kept =
        normalized
        |> String.filter (fun c ->
            let x = int c
            not (x <= 0x1F || x = 0x7F || (x >= 0x80 && x <= 0x9F)))

    Ok(Encoding.UTF8.GetBytes kept)

let private deriveKey (kdf: Kdf) (password: byte[]) (ct: CancellationToken) =
    match kdf with
    | Scrypt(n, r, p, salt, dkLen) -> Scrypt.deriveWith ct password salt n r p dkLen
    | Pbkdf2(c, salt, dkLen) ->
        // One call that cannot stop: a cancelled import skips the keystores not started yet.
        ct.ThrowIfCancellationRequested()
        Rfc2898DeriveBytes.Pbkdf2(password, salt, c, HashAlgorithmName.SHA256, dkLen)

/// AES-128-CTR with a 16-byte big-endian counter starting at iv. Encrypts and decrypts.
let aesCtr (key: byte[]) (iv: byte[]) (input: byte[]) : byte[] =
    use aes = Aes.Create()
    aes.Key <- key
    let counter = Array.copy iv
    let output = Array.zeroCreate<byte> input.Length
    let block = Array.zeroCreate<byte> 16
    let mutable i = 0

    while i < input.Length do
        aes.EncryptEcb(ReadOnlySpan counter, Span block, PaddingMode.None) |> ignore
        let n = min 16 (input.Length - i)

        for k in 0 .. n - 1 do
            output[i + k] <- input[i + k] ^^^ block[k]

        i <- i + n
        let mutable j = 15
        let mutable carry = true

        while carry && j >= 0 do
            counter[j] <- counter[j] + 1uy
            carry <- counter[j] = 0uy
            j <- j - 1

    CryptographicOperations.ZeroMemory(Span block)
    output

/// SHA-256 of dk[16..31] then the cipher text, hashed from spans so no copy of the key is left.
let private checksumOf (dk: byte[]) (cipherText: byte[]) =
    use h = IncrementalHash.CreateHash HashAlgorithmName.SHA256
    h.AppendData(ReadOnlySpan(dk, 16, 16))
    h.AppendData(ReadOnlySpan cipherText)
    h.GetHashAndReset()

/// aesCtr with the AES key dk[0..15]; the key copy is zeroed after use.
let private aesCtrWith (dk: byte[]) (iv: byte[]) (input: byte[]) =
    let key = Array.zeroCreate<byte> 16

    try
        Buffer.BlockCopy(dk, 0, key, 0, 16)
        aesCtr key iv input
    finally
        CryptographicOperations.ZeroMemory(Span key)

/// Decrypts the secret key. Checks the checksum, the key range and the pubkey field. A cancel
/// during scrypt gives an error.
let private decryptWith (ct: CancellationToken) (ks: Keystore) (pw: byte[]) : Result<byte[], string> =
    try
        let dk =
            try
                ct.ThrowIfCancellationRequested()
                Ok(deriveKey ks.Kdf pw ct)
            with
            | :? ArgumentException as e -> Error $"kdf parameters refused: {e.Message}"
            | :? OperationCanceledException -> Error "cancelled"

        match dk with
        | Error e -> Error e
        | Ok dk when dk.Length < 32 -> Error "dklen must be at least 32"
        | Ok dk ->
            try
                if
                    not (
                        CryptographicOperations.FixedTimeEquals(
                            ReadOnlySpan(checksumOf dk ks.CipherText),
                            ReadOnlySpan ks.Checksum
                        )
                    )
                then
                    Error "wrong password or corrupt keystore (checksum mismatch)"
                elif ks.Iv.Length <> 16 then
                    Error "iv must be 16 bytes"
                else
                    let secret = aesCtrWith dk ks.Iv ks.CipherText

                    if not (Bls.isValidSecret (ReadOnlySpan secret)) then
                        CryptographicOperations.ZeroMemory(Span secret)
                        Error "decrypted secret is not a valid BLS secret key"
                    else
                        let pk = PubKey.Of(Bls.publicKey (ReadOnlySpan secret))

                        match ks.PubKey with
                        | ValueSome expected when expected <> pk ->
                            CryptographicOperations.ZeroMemory(Span secret)
                            Error "secret does not match the keystore's pubkey"
                        | _ -> Ok secret
            finally
                CryptographicOperations.ZeroMemory(Span dk)
    finally
        CryptographicOperations.ZeroMemory(Span pw)

let decrypt (ks: Keystore) (password: string) : Result<byte[], string> =
    passwordBytes password |> Result.bind (decryptWith CancellationToken.None ks)

/// decrypt that stops with an error when `ct` is cancelled.
let decryptCancellable (ks: Keystore) (password: string) (ct: CancellationToken) : Result<byte[], string> =
    passwordBytes password |> Result.bind (decryptWith ct ks)

/// Writes a keystore for a secret key. The VC keeps original files on import; this is for tests
/// and tools.
let encrypt (secret: byte[]) (password: string) (kdf: Kdf) (path: string) : string =
    let pw =
        match passwordBytes password with
        | Ok pw -> pw
        | Error e -> invalidArg "password" e

    let dk = deriveKey kdf pw CancellationToken.None
    CryptographicOperations.ZeroMemory(Span pw)
    let iv = RandomNumberGenerator.GetBytes 16

    let cipherText, checksum =
        try
            let c = aesCtrWith dk iv secret
            c, checksumOf dk c
        finally
            CryptographicOperations.ZeroMemory(Span dk)

    let pk = Bls.publicKey (ReadOnlySpan secret)
    let hex (b: byte[]) = Convert.ToHexStringLower b

    Text.Encoding.UTF8.GetString(
        toBytes (fun w ->
            w.WriteStartObject()
            w.WriteStartObject "crypto"
            w.WriteStartObject "kdf"

            match kdf with
            | Scrypt(n, r, p, salt, dkLen) ->
                w.WriteString("function", "scrypt")
                w.WriteStartObject "params"
                w.WriteNumber("dklen", dkLen)
                w.WriteNumber("n", n)
                w.WriteNumber("p", p)
                w.WriteNumber("r", r)
                w.WriteString("salt", hex salt)
                w.WriteEndObject()
            | Pbkdf2(c, salt, dkLen) ->
                w.WriteString("function", "pbkdf2")
                w.WriteStartObject "params"
                w.WriteNumber("dklen", dkLen)
                w.WriteNumber("c", c)
                w.WriteString("prf", "hmac-sha256")
                w.WriteString("salt", hex salt)
                w.WriteEndObject()

            w.WriteString("message", "")
            w.WriteEndObject()
            w.WriteStartObject "checksum"
            w.WriteString("function", "sha256")
            w.WriteStartObject "params"
            w.WriteEndObject()
            w.WriteString("message", hex checksum)
            w.WriteEndObject()
            w.WriteStartObject "cipher"
            w.WriteString("function", "aes-128-ctr")
            w.WriteStartObject "params"
            w.WriteString("iv", hex iv)
            w.WriteEndObject()
            w.WriteString("message", hex cipherText)
            w.WriteEndObject()
            w.WriteEndObject()
            w.WriteString("description", "")
            w.WriteString("pubkey", hex pk)
            w.WriteString("path", path)
            w.WriteString("uuid", Guid.NewGuid().ToString())
            w.WriteNumber("version", 4)
            w.WriteEndObject())
    )
