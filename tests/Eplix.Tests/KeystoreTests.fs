/// EIP-2335 keystores and scrypt (RFC 7914).
module Eplix.Tests.KeystoreTests

open System
open System.IO
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil

let private eip2335 = Path.Combine(fixtures, "eip2335")
let private password () = File.ReadAllText(Path.Combine(eip2335, "password.txt"))
let private secret = "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

let private rfcVector (p: string) (s: string) n r pp (expected: string) =
    test $"scrypt N={n} r={r} p={pp}" {
        let dk = Scrypt.derive (Text.Encoding.ASCII.GetBytes p) (Text.Encoding.ASCII.GetBytes s) n r pp 64
        Expect.equal (Convert.ToHexStringLower dk) (expected.Replace(" ", "")) "RFC 7914 section 12"
    }

let private decrypts file =
    test $"EIP-2335 {file} vector" {
        match Keystore.parse (File.ReadAllText(Path.Combine(eip2335, file))) with
        | Error e -> failtest e
        | Ok ks ->
            match Keystore.decrypt ks (password ()) with
            | Ok sk -> Expect.equal (Hex.encodeArray sk) secret "secret"
            | Error e -> failtest e
    }

[<Tests>]
let tests =
    testList
        "keystore"
        [ // RFC 7914 vectors; the N = 2^20 vector needs 1 GiB and is left out.
            rfcVector
                ""
                ""
                16
                1
                1
                "77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06"
            rfcVector
                "password"
                "NaCl"
                1024
                8
                16
                "fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe 7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62 2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40"
            rfcVector
                "pleaseletmein"
                "SodiumChloride"
                16384
                8
                1
                "70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2 d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9 e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87"

            test "password normalization (EIP-2335 encoded password)" {
                Expect.equal
                    (match Keystore.passwordBytes (password ()) with
                     | Ok b -> Hex.encodeArray b
                     | Error e -> e)
                    "0x7465737470617373776f7264f09f9491"
                    "NFKD, control codes stripped"

                Expect.equal (Keystore.passwordBytes "a\u0000b\u007fc\u0085d") (Ok "abcd"B) "C0, DEL and C1 removed"

                Expect.equal
                    (Keystore.passwordBytes "Å")
                    (Ok(Text.Encoding.UTF8.GetBytes "Å"))
                    "NFKD of the angstrom sign"
            }

            decrypts "pbkdf2.json"
            decrypts "scrypt.json"

            test "wrong password fails the checksum" {
                match Keystore.parse (File.ReadAllText(Path.Combine(eip2335, "pbkdf2.json"))) with
                | Error e -> failtest e
                | Ok ks -> Expect.isError (Keystore.decrypt ks "wrong") "checksum"
            }

            test "encrypt then decrypt" {
                let sk = hex secret
                let json = Keystore.encrypt sk "pw" (Keystore.Pbkdf2(16, Array.create 32 7uy, 32)) "m/12381/3600/0/0/0"

                match Keystore.parse json |> Result.bind (fun ks -> Keystore.decrypt ks "pw") with
                | Ok back -> Expect.equal back sk "round trip"
                | Error e -> failtest e
            }

            test "a keystore whose pubkey does not match its secret is refused" {
                let sk = hex secret
                let json = Keystore.encrypt sk "pw" (Keystore.Pbkdf2(16, Array.create 32 7uy, 32)) ""

                let other =
                    Bls.publicKey (
                        ReadOnlySpan(hex "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
                    )

                let tampered =
                    json.Replace(
                        Convert.ToHexStringLower(Bls.publicKey (ReadOnlySpan sk)),
                        Convert.ToHexStringLower other
                    )

                match Keystore.parse tampered with
                | Ok ks -> Expect.isError (Keystore.decrypt ks "pw") "pubkey mismatch"
                | Error e -> failtest e
            }

            test "scrypt parameters over the memory cap are refused" {
                let json =
                    File.ReadAllText(Path.Combine(eip2335, "scrypt.json")).Replace("\"n\": 262144", "\"n\": 16777216")

                match Keystore.parse json with
                | Ok ks -> Expect.isError (Keystore.decrypt ks (password ())) "too much memory"
                | Error e -> failtest e
            }

            test "scrypt p and total work are capped" {
                let pw = "pw"B
                let salt = Array.create 32 1uy

                Expect.throwsT<ArgumentException>
                    (fun () -> Scrypt.derive pw salt 16 1 (Scrypt.maxP + 1) 32 |> ignore)
                    "p above the cap"
                // 128 MiB of memory, under the memory cap, but twice the work cap.
                Expect.throwsT<ArgumentException>
                    (fun () -> Scrypt.derive pw salt (1 <<< 17) 8 16 32 |> ignore)
                    "work above the cap"

                let json = File.ReadAllText(Path.Combine(eip2335, "scrypt.json")).Replace("\"p\": 1", "\"p\": 16")

                match Keystore.parse json with
                | Ok ks -> Expect.isError (Keystore.decrypt ks (password ())) "a keystore over the work cap"
                | Error e -> failtest e
            }

            test "a huge r with a tiny n is refused before any allocation" {
                let pw = "pw"B
                let salt = Array.create 32 1uy
                let sw = Diagnostics.Stopwatch.StartNew()
                let before = GC.GetAllocatedBytesForCurrentThread()
                // V is 1 GiB and passes the check on V; the other buffers would add 2 GiB more.
                // The cap on r refuses it.
                Expect.throwsT<ArgumentException>
                    (fun () -> Scrypt.derive pw salt 2 (1 <<< 22) 1 32 |> ignore)
                    "r = 2^22"

                Expect.throwsT<ArgumentException>
                    (fun () -> Scrypt.derive pw salt 16 (Scrypt.maxR + 1) 1 32 |> ignore)
                    "r above the cap"
                // V = 2 GiB with r = 8: refused by the V cap.
                Expect.throwsT<ArgumentException>
                    (fun () -> Scrypt.derive pw salt (1 <<< 21) 8 1 32 |> ignore)
                    "V above 1 GiB"

                Expect.isLessThan (GC.GetAllocatedBytesForCurrentThread() - before) (1L <<< 20) "under 1 MiB allocated"
                Expect.isLessThan sw.Elapsed.TotalSeconds 1.0 "refused at once"
                // Inputs that pass every check: a cancelled token stops each right after them,
                // before any allocation.
                use cancelled = new Threading.CancellationTokenSource()
                cancelled.Cancel()

                let allowed (n: int) (r: int) (p: int) (what: string) =
                    Expect.throwsT<OperationCanceledException>
                        (fun () -> Scrypt.deriveWith cancelled.Token pw salt n r p 32 |> ignore)
                        what
                // V exactly 1 GiB, the strongest common setting.
                allowed (1 <<< 20) 8 1 "n = 2^20, r = 8 is allowed"
                // r and p at their caps: the buffers beside V are as large as they get (76 KiB).
                allowed 2 Scrypt.maxR Scrypt.maxP "r and p at their caps are allowed"
                // V at the cap with r at its cap: no total check refuses the extra buffers.
                allowed (1 <<< 18) Scrypt.maxR 1 "V = 1 GiB with r = 32 is allowed"

                let json =
                    File
                        .ReadAllText(Path.Combine(eip2335, "scrypt.json"))
                        .Replace("\"n\": 262144", "\"n\": 2")
                        .Replace("\"r\": 8", "\"r\": 4194304")

                match Keystore.parse json with
                | Ok ks ->
                    match Keystore.decrypt ks (password ()) with
                    | Error e -> Expect.stringContains e "kdf parameters refused" "a clean error"
                    | Ok _ -> failtest "decrypted"
                | Error e -> failtest e
            }

            test "scrypt stops when cancelled" {
                let sw = Diagnostics.Stopwatch.StartNew()
                use cts = new Threading.CancellationTokenSource(TimeSpan.FromMilliseconds 100.0)
                // At the work cap: seconds of work when not cancelled.
                Expect.throwsT<OperationCanceledException>
                    (fun () -> Scrypt.deriveWith cts.Token "pw"B (Array.create 32 1uy) (1 <<< 16) 8 16 32 |> ignore)
                    "cancelled"

                Expect.isLessThan sw.Elapsed.TotalSeconds 2.0 "stops soon after the cancel"

                match Keystore.parse (File.ReadAllText(Path.Combine(eip2335, "scrypt.json"))) with
                | Ok ks ->
                    Expect.equal
                        (Keystore.decryptCancellable ks (password ()) cts.Token)
                        (Error "cancelled")
                        "an error, not an exception"
                | Error e -> failtest e
            }

            test "many threads decrypt the same and different keystores as one thread does" {
                let secretOf (i: int) =
                    let b = Array.zeroCreate<byte> 32
                    b[31] <- byte (i + 1)
                    b[30] <- 0x37uy
                    b

                let kdfs =
                    [|
                        Keystore.Scrypt(1 <<< 12, 8, 1, Array.create 32 1uy, 32)
                        Keystore.Scrypt(1 <<< 10, 8, 2, Array.create 32 2uy, 32)
                        Keystore.Scrypt(1 <<< 11, 4, 1, Array.create 32 3uy, 48)
                        Keystore.Pbkdf2(16, Array.create 32 4uy, 32)
                        Keystore.Pbkdf2(1024, Array.create 32 5uy, 32)
                    |]

                let passwords = [| "pw"; "pw"; "p\u00e4ssword"; "x"; "pw" |]

                let keystores =
                    kdfs
                    |> Array.mapi (fun i kdf ->
                        match Keystore.parse (Keystore.encrypt (secretOf i) passwords[i] kdf "") with
                        | Ok ks -> ks
                        | Error e -> failtest e)

                let reference =
                    keystores |> Array.mapi (fun i ks -> Keystore.decrypt ks passwords[i] |> Result.map Hex.encodeArray)

                for i in 0 .. keystores.Length - 1 do
                    Expect.equal reference[i] (Ok(Hex.encodeArray (secretOf i))) "one thread"
                // The first 200 calls all take keystore 0, the rest a mix; every 7th is cancelled.
                let ops = 1200
                let results = Array.zeroCreate<Result<string, string> * int * bool> ops
                let options = Threading.Tasks.ParallelOptions(MaxDegreeOfParallelism = 16)

                Threading.Tasks.Parallel.For(
                    0,
                    ops,
                    options,
                    fun op ->
                        let i = if op < 200 then 0 else op % keystores.Length
                        let cancel = op % 7 = 3
                        use cts = new Threading.CancellationTokenSource()

                        if cancel then
                            cts.CancelAfter(TimeSpan.FromMilliseconds(float (op % 3)))

                        let r =
                            Keystore.decryptCancellable keystores[i] passwords[i] cts.Token
                            |> Result.map Hex.encodeArray

                        results[op] <- (r, i, cancel)
                )
                |> ignore

                for r, i, cancel in results do
                    match r with
                    | Error "cancelled" when cancel -> ()
                    | r -> Expect.equal r reference[i] $"keystore {i}"
            }

            test "teku layout: <name>.json with <name>.txt" {
                let dir = tempDir ()
                let sk = hex secret

                File.WriteAllText(
                    Path.Combine(dir, "k1.json"),
                    Keystore.encrypt sk "pw1" (Keystore.Pbkdf2(16, Array.create 32 1uy, 32)) ""
                )

                File.WriteAllText(Path.Combine(dir, "k1.txt"), "pw1\n")

                match
                    KeystoreFiles.load
                        [
                            {
                                Path = dir
                                PasswordFile = ValueNone
                                Layout = ValueNone
                            }
                        ]
                        2
                        Log.none
                with
                | Ok [ k ] ->
                    Expect.equal
                        k.Key.Hex
                        "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
                        "pubkey"

                    (k.Secret :> IDisposable).Dispose()
                | other -> failtestf "unexpected %A" other
            }
        ]
