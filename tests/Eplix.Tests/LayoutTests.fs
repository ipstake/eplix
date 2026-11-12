/// Keystore layouts of other clients, parallel decryption, the managed store and
/// key reload. Sample directories follow each client's documented layout.
module Eplix.Tests.LayoutTests

open System
open System.Collections.Generic
open System.IO
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Backend.Local.Layouts
open Eplix.Tests.TestUtil

let private secretOf (i: int) =
    let b = Array.zeroCreate<byte> 32
    b[31] <- byte (i + 1)
    b[30] <- 0x42uy
    b

let private pkOf i = PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i)))

/// A cheap keystore (PBKDF2, c = 16) for key i.
let private keystore (i: int) (pw: string) =
    Keystore.encrypt (secretOf i) pw (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) $"m/12381/3600/{i}/0/0"

let private write (path: string) (text: string) =
    Directory.CreateDirectory(nonNull (Path.GetDirectoryName path)) |> ignore
    File.WriteAllText(path, text)

/// Detects the layout, lists the entries and decrypts them; returns the keys in order.
let private loadDir (dir: string) (pw: string voption) (expected: Layout) =
    match detect dir with
    | Error e -> failtest e
    | Ok l ->
        Expect.equal l expected "detected layout"

        match
            KeystoreFiles.load
                [
                    {
                        Path = dir
                        PasswordFile = pw
                        Layout = ValueNone
                    }
                ]
                2
                Log.none
        with
        | Error e -> failtestf "%A" e
        | Ok keys ->
            let pks = keys |> List.map (fun k -> k.Key)

            for k in keys do
                (k.Secret :> IDisposable).Dispose()

            pks

[<Tests>]
let tests =
    testList
        "layouts"
        [
            test "deposit-cli: keystore-m files with one password" {
                let dir = tempDir ()

                for i in 0..2 do
                    write (Path.Combine(dir, $"keystore-m_12381_3600_{i}_0_0-1700000000.json")) (keystore i "pw")

                write (Path.Combine(dir, "deposit_data-1700000000.json")) "[]"
                // The password file sits outside the keystore directory, in a directory of its own:
                // a shared parent let parallel test runs truncate it under each other.
                let pw = Path.Combine(tempDir (), "pw.txt")
                write pw "pw\n"
                let pks = loadDir dir (ValueSome pw) Layout.DepositCli
                Expect.equal pks [ pkOf 0; pkOf 1; pkOf 2 ] "three keys; deposit data ignored"
            }

            test "teku: name.json with name.txt" {
                let dir = tempDir ()

                for i in 0..1 do
                    write (Path.Combine(dir, $"validator_{i}.json")) (keystore i $"pw{i}")
                    write (Path.Combine(dir, $"validator_{i}.txt")) $"pw{i}"

                Expect.equal (loadDir dir ValueNone Layout.Teku) [ pkOf 0; pkOf 1 ] "two keys"
            }

            test "teku: a separate password directory" {
                let keys = tempDir ()
                let pws = tempDir ()
                write (Path.Combine(keys, "a.json")) (keystore 3 "x")
                write (Path.Combine(pws, "a.txt")) "x\n"

                match entries Layout.Teku keys (ValueSome pws) with
                | Ok([ e ], _) ->
                    Expect.equal e.Password (Password.File(Path.Combine(pws, "a.txt"))) "password from the password dir"
                | other -> failtestf "%A" other
            }

            test "lighthouse: validators/<pk>/voting-keystore.json and secrets/<pk>" {
                let root = tempDir ()

                for i in 0..1 do
                    write (Path.Combine(root, "validators", (pkOf i).Hex, "voting-keystore.json")) (keystore i $"s{i}")
                    write (Path.Combine(root, "secrets", (pkOf i).Hex)) $"s{i}"

                write (Path.Combine(root, "validators", "slashing_protection.sqlite")) ""

                Expect.equal
                    (Set.ofList (loadDir root ValueNone Layout.Lighthouse))
                    (set [ pkOf 0; pkOf 1 ])
                    "from the data dir"

                Expect.equal
                    (Set.ofList (loadDir (Path.Combine(root, "validators")) ValueNone Layout.Lighthouse))
                    (set [ pkOf 0; pkOf 1 ])
                    "from validators/"
            }

            test "lighthouse: validator_definitions.yml with paths, inline passwords and remote keys" {
                let root = tempDir ()
                let v = Path.Combine(root, "validators")
                let ks i = Path.Combine(v, (pkOf i).Hex, "voting-keystore.json")
                write (ks 0) (keystore 0 "a")
                write (ks 1) (keystore 1 "b")
                write (ks 2) (keystore 2 "c")
                write (Path.Combine(root, "pw", "zero")) "a\n"

                let yml =
                    $"""---
- enabled: true
  voting_public_key: "{(pkOf 0).Hex}"
  description: ""
  type: local_keystore
  voting_keystore_path: {ks 0}
  voting_keystore_password_path: {Path.Combine(root, "pw", "zero")}
- enabled: true
  voting_public_key: "{(pkOf 1).Hex}"
  type: local_keystore
  voting_keystore_path: "{ks 1}"
  voting_keystore_password: "b"
- enabled: false
  voting_public_key: "{(pkOf 2).Hex}"
  type: local_keystore
  voting_keystore_path: {ks 2}
- enabled: true
  voting_public_key: "{(pkOf 3).Hex}"
  type: web3signer
  url: "https://signer:9000"
"""

                write (Path.Combine(v, "validator_definitions.yml")) yml

                match entries Layout.Lighthouse root ValueNone with
                | Error e -> failtest e
                | Ok(list, notes) ->
                    Expect.equal list.Length 2 "two enabled local keys"
                    Expect.equal notes.Length 2 "disabled and remote keys noted"

                Expect.equal (loadDir root ValueNone Layout.Lighthouse) [ pkOf 0; pkOf 1 ] "keys from the definitions"
            }

            test "nimbus: validators/<pk>/keystore.json, remote keystores skipped" {
                let root = tempDir ()
                write (Path.Combine(root, "validators", (pkOf 4).Hex, "keystore.json")) (keystore 4 "n")
                write (Path.Combine(root, "secrets", (pkOf 4).Hex)) "n"
                write (Path.Combine(root, "validators", (pkOf 5).Hex, "remote_keystore.json")) "{}"
                Expect.equal (loadDir root ValueNone Layout.Nimbus) [ pkOf 4 ] "the local key"
            }

            test "lodestar: keystores/<pk>/voting-keystore.json and secrets/<pk>" {
                let root = tempDir ()
                write (Path.Combine(root, "keystores", (pkOf 6).Hex, "voting-keystore.json")) (keystore 6 "l")
                write (Path.Combine(root, "secrets", (pkOf 6).Hex)) "l"
                Expect.equal (loadDir root ValueNone Layout.Lodestar) [ pkOf 6 ] "one key"
            }

            test "parallel decryption keeps the input order and reports each failure" {
                let dir = tempDir ()

                for i in 0..7 do
                    write (Path.Combine(dir, $"k{i}.json")) (keystore i (if i = 5 then "wrong" else "pw"))

                write (Path.Combine(dir, "pw")) "pw"

                let es =
                    match entries Layout.Plain dir (ValueSome(Path.Combine(dir, "pw"))) with
                    | Ok(es, _) -> Array.ofList es
                    | Error e -> failtest e

                let results = KeystoreFiles.decryptAll 4 es KeystoreFiles.decryptOne

                for i in 0..7 do
                    match results[i] with
                    | Ok k ->
                        Expect.equal k.Key (pkOf i) $"key {i} in place"
                        (k.Secret :> IDisposable).Dispose()
                    | Error e -> Expect.equal i 5 $"only key 5 fails ({e})"
            }

            test "the managed store keeps the original JSON and a private password file" {
                let data = tempDir ()
                let json = keystore 7 "m"
                LocalModule.ManagedStore.save data (pkOf 7) json "m"

                Expect.equal
                    (File.ReadAllText(LocalModule.ManagedStore.keystoreFile data (pkOf 7)))
                    json
                    "byte for byte"

                let mode = File.GetUnixFileMode(LocalModule.ManagedStore.secretFile data (pkOf 7))
                Expect.equal mode (UnixFileMode.UserRead ||| UnixFileMode.UserWrite) "0600"

                Expect.equal
                    (loadDir (LocalModule.ManagedStore.keystoresDir data) ValueNone Layout.Lighthouse)
                    [ pkOf 7 ]
                    "readable as a layout"

                LocalModule.ManagedStore.delete data (pkOf 7)
                Expect.isFalse (File.Exists(LocalModule.ManagedStore.secretFile data (pkOf 7))) "password deleted"
            }

            test "a failed keystore save leaves no password file" {
                let data = tempDir ()
                let ks = LocalModule.ManagedStore.keystoresDir data
                Directory.CreateDirectory ks |> ignore
                // A file where the key's keystore dir goes makes the keystore write fail.
                File.WriteAllText(Path.Combine(ks, (pkOf 6).Hex), "")

                Expect.throws
                    (fun () -> LocalModule.ManagedStore.save data (pkOf 6) (keystore 6 "m") "m")
                    "the save fails"

                Expect.isFalse (File.Exists(LocalModule.ManagedStore.secretFile data (pkOf 6))) "no password file stays"
            }

            test "the managed store tightens loose dirs and never has a readable password file" {
                if not (OperatingSystem.IsWindows()) then
                    let data = tempDir ()

                    let loose =
                        UnixFileMode.UserRead
                        ||| UnixFileMode.UserWrite
                        ||| UnixFileMode.UserExecute
                        ||| UnixFileMode.GroupRead
                        ||| UnixFileMode.GroupExecute
                        ||| UnixFileMode.OtherRead
                        ||| UnixFileMode.OtherExecute

                    let ownerDir = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
                    let secrets = LocalModule.ManagedStore.secretsDir data
                    let keystores = LocalModule.ManagedStore.keystoresDir data

                    for d in [ secrets; keystores ] do
                        Directory.CreateDirectory d |> ignore
                        File.SetUnixFileMode(d, loose)
                    // A temporary file a crash left behind, readable by all.
                    let secret = LocalModule.ManagedStore.secretFile data (pkOf 7)
                    File.WriteAllText(secret + ".tmp", "old")

                    File.SetUnixFileMode(
                        secret + ".tmp",
                        UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.OtherRead
                    )

                    LocalModule.ManagedStore.save data (pkOf 7) (keystore 7 "m") "m"
                    Expect.equal (File.GetUnixFileMode secrets) ownerDir "secrets 0700"
                    Expect.equal (File.GetUnixFileMode keystores) ownerDir "keystores 0700"

                    Expect.equal
                        (File.GetUnixFileMode(
                            Path.GetDirectoryName(LocalModule.ManagedStore.keystoreFile data (pkOf 7))
                        ))
                        ownerDir
                        "key dir 0700"

                    Expect.equal
                        (File.GetUnixFileMode secret)
                        (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
                        "password 0600"

                    Expect.equal (File.ReadAllText secret) "m" "password"
                    File.SetUnixFileMode(secrets, loose)
                    LocalModule.ManagedStore.tighten data
                    Expect.equal (File.GetUnixFileMode secrets) ownerDir "tightened at start"
            }

            test "duplicate keys: the first is kept, at 60,000 keys in well under a second" {
                // A list scan here took over a minute at 50,000 keys.
                let key (i: int) =
                    PubKey.Of(Array.init 48 (fun b -> if b < 8 then byte (i >>> (8 * (b % 4))) else 0xA5uy))

                let loaded (i: int) (file: string) =
                    Ok
                        {
                            Key = key i
                            Secret = SecretKey.Copy(ReadOnlySpan(Array.init 32 (fun b -> if b = 31 then 1uy else 0uy)))
                            File = file
                            DerivationPath = ""
                        }

                let results =
                    Array.append
                        [| for i in 0..59_999 -> loaded i $"k{i}.json" |]
                        [| loaded 7 "again.json"; Error "bad.json: no password" |]

                let log, lines = Log.memory ()
                let sw = Diagnostics.Stopwatch.StartNew()
                let ok, errors = KeystoreFiles.keepFirst results log
                sw.Stop()
                Expect.equal ok.Count 60_000 "every key once"
                Expect.equal (ok |> Seq.find (fun k -> k.Key = key 7)).File "k7.json" "the first file of a key"
                Expect.equal (List.ofSeq errors) [ "bad.json: no password" ] "errors pass through"
                Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "again.json")) "the repeat is named"
                Expect.isLessThan sw.Elapsed.TotalSeconds 1.0 "a set, not a list scan"

                for k in ok do
                    (k.Secret :> IDisposable).Dispose()
            }

            test "an unknown layout name is refused" {
                Expect.isError (Layouts.parse "prysm") "prysm needs its export step"
            }

            test "rescan: new files are decrypted, loaded ones skipped, a failed one only after a change" {
                let entry (f: string) =
                    {
                        Keystore = f
                        Password = Password.File "pw"
                    }

                let t (s: int) = struct (DateTime(2026, 1, 1).AddSeconds(float s), DateTime.MinValue)
                let stamps = Map.ofList [ "loaded.json", t 1; "new.json", t 2; "failed.json", t 3; "changed.json", t 5 ]
                let seen = Dictionary<string, struct (DateTime * DateTime)>()
                seen["loaded.json"] <- t 1
                seen["failed.json"] <- t 3
                seen["changed.json"] <- t 4
                let loaded = HashSet<string> [ "loaded.json" ]
                let entries = [ "loaded.json"; "new.json"; "failed.json"; "changed.json" ] |> List.map entry
                let fresh = LocalModule.Rescan.fresh loaded seen (fun e -> stamps[e.Keystore]) entries

                Expect.equal
                    (fresh |> Array.map (fun e -> e.Keystore))
                    [| "new.json"; "changed.json" |]
                    "the new file and the changed failure, in order"
            }

            test "rescan: the same files as a scan over every loaded key; 50,000 keys in well under a second" {
                // Before, each file was checked against every loaded key: 0.65 s a pass at 10,000 keys.
                let rnd = Random 7

                let stamp (e: Entry) =
                    struct (DateTime(2026, 1, 1).AddSeconds(float (e.Keystore.Length % 3)), DateTime.MinValue)

                let case (n: int) =
                    let files = [ for i in 0 .. n - 1 -> $"k{i}.json" ]
                    let loadedFiles = files |> List.filter (fun _ -> rnd.Next 10 > 0)
                    let seen = Dictionary<string, struct (DateTime * DateTime)>()

                    for f in files do
                        match rnd.Next 3 with
                        | 0 -> ()
                        | 1 ->
                            seen[f] <-
                                stamp
                                    {
                                        Keystore = f
                                        Password = Password.File "pw"
                                    }
                        | _ -> seen[f] <- struct (DateTime.MinValue, DateTime.MinValue)

                    loadedFiles,
                    seen,
                    files
                    |> List.map (fun f ->
                        {
                            Keystore = f
                            Password = Password.File "pw"
                        })

                let loadedFiles, seen, entries = case 3_000

                let byScan =
                    entries
                    |> List.filter (fun e ->
                        not (loadedFiles |> List.exists (fun f -> f = e.Keystore))
                        && (match seen.TryGetValue e.Keystore with
                            | true, s -> s <> stamp e
                            | _ -> true))

                let fresh = LocalModule.Rescan.fresh (HashSet loadedFiles) seen stamp entries
                Expect.equal (List.ofArray fresh) byScan "same entries, same order"
                Expect.isGreaterThan byScan.Length 100 "the case has fresh entries"
                let loadedFiles, seen, entries = case 50_000
                let sw = Diagnostics.Stopwatch.StartNew()
                LocalModule.Rescan.fresh (HashSet loadedFiles) seen stamp entries |> ignore
                sw.Stop()
                Expect.isLessThan sw.Elapsed.TotalSeconds 1.0 "a set lookup, not a scan"
            }

            test "an atomic write never writes into a stale temporary file" {
                if not (OperatingSystem.IsWindows()) then
                    let path = Path.Combine(tempDir (), "secret")
                    File.WriteAllText(path + ".tmp", "old")

                    File.SetUnixFileMode(
                        path + ".tmp",
                        UnixFileMode.UserRead
                        ||| UnixFileMode.UserWrite
                        ||| UnixFileMode.GroupRead
                        ||| UnixFileMode.OtherRead
                    )
                    // Opened while the file could be read by all, before the write.
                    use stale =
                        new FileStream(
                            path + ".tmp",
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite ||| FileShare.Delete
                        )

                    Eplix.Slashing.FileSync.writeAtomic
                        path
                        (Text.Encoding.UTF8.GetBytes "new password")
                        (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)

                    use r = new StreamReader(stale)
                    Expect.equal (r.ReadToEnd()) "old" "the stale handle sees the old file, not the new content"
                    Expect.equal (File.ReadAllText path) "new password" "written"
                    Expect.equal (File.GetUnixFileMode path) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite) "0600"
                    Expect.isFalse (File.Exists(path + ".tmp")) "no temporary file left"
            }
        ]
