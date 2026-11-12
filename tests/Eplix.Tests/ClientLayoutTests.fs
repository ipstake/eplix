/// Key layouts and EIP-3076 exports written by the clients themselves (tests/fixtures/layouts,
/// made with each client's own tooling from the BIP-39 test mnemonic; see its README).
module Eplix.Tests.ClientLayoutTests

open System
open System.IO
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Backend.Local.Layouts
open Eplix.Slashing
open Eplix.Tests.TestUtil

let private dir = Path.Combine(fixtures, "layouts")

/// Hoodi's genesis validators root; the clients ran with --network hoodi.
let private hoodi =
    Root.TryParse "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
    |> ValueOption.get

let private pk (s: string) = PubKey.TryParse s |> ValueOption.get

// Keys 0 to 4 of the test mnemonic, one per client.
let private lighthouseKey =
    pk "0xb3e445d43871965d890a398f719348a1405ac72e35b92727cc570026f54471af7ea7b2040622a8fd0b5bfb2a209b5911"

let private tekuKey =
    pk "0xaeb399bf5648b0e9980c1731824c269631a41320c3d7f730c40587e1a37a5e1c8b5755fd90080a7b3fb90d3fd419c0a7"

let private nimbusKey =
    pk "0x92f46b0dcc7db24f4946b5773b5525efa0bbb0810088588323d9de84f0e42f22df96cbb97065b49a2006c653ec8060f4"

let private lodestarKey =
    pk "0x9948ea3862b8889636c3caeaa1b9877a12cffca9bf6a1ef2264fa7e69604d55c56b4f519062e6785d21d3c9593c2adcd"

let private prysmKey =
    pk "0x849b4bcd8670f81909baad27c4d9c8d9b956b19192f12af8fe57d30731fa11a55a97a1ab72bb1cfd76c1461dcaba714a"

let rec private copyDir (src: string) (dst: string) =
    Directory.CreateDirectory dst |> ignore

    for f in Directory.GetFiles src do
        File.Copy(f, Path.Combine(dst, Path.GetFileName f))

    for d in Directory.GetDirectories src do
        copyDir d (Path.Combine(dst, Path.GetFileName d))

/// Copies a fixture to a temp dir. The Lighthouse definitions hold the absolute paths of the
/// machine that wrote them; they point nowhere here, as after a move to another host.
let private copyOf (name: string) =
    let t = Path.Combine(tempDir (), name)
    copyDir (Path.Combine(dir, name)) t
    let defs = Path.Combine(t, "validators", "validator_definitions.yml")

    if File.Exists defs then
        File.WriteAllText(defs, File.ReadAllText(defs).Replace("/srv/layouts/", "/nonexistent/layouts/"))

    t

/// Imports a client directory the way `eplix import` does and returns the layout and keys.
let private import (src: string) (layout: Layout voption) (passwordFile: string voption) =
    let data = tempDir ()

    match
        ImportKeys.run
            data
            {
                Path = src
                PasswordFile = passwordFile
                Layout = layout
            }
            2
    with
    | Error e -> failtest e
    | Ok r ->
        Expect.isEmpty r.Errors "no errors"
        // The VC loads what was imported.
        match KeystoreFiles.load [ LocalModule.ManagedStore.source data ] 2 Log.none with
        | Error e -> failtestf "%A" e
        | Ok keys ->
            for k in keys do
                (k.Secret :> IDisposable).Dispose()

            r.Layout, keys |> List.map (fun k -> k.Key)

/// Imports a client's EIP-3076 export into a fresh DB and returns the key's marks.
let private history (client: string) (key: PubKey) =
    match Interchange.parse (File.ReadAllBytes(Path.Combine(dir, client, "interchange.json"))) with
    | Error e -> failtest e
    | Ok x ->
        Expect.equal x.GenesisValidatorsRoot hoodi "Hoodi"

        use db =
            match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), hoodi) with
            | Ok db -> db
            | Error e -> failtest e

        Expect.isOk (db.Import x) "import"
        (db.Marks key).Value

let private checkMarks (m: KeyMarks) =
    Expect.equal m.Block.Value.Slot 1000UL "block mark"
    Expect.equal (m.Attestation.Value.Source, m.Attestation.Value.Target) (30UL, 31UL) "attestation marks"

[<Tests>]
let tests =
    testList
        "client layouts"
        [
            test "ethstaker-deposit-cli v1.3.0" {
                let src = copyOf "deposit-cli"

                let layout, keys =
                    import
                        (Path.Combine(src, "validator_keys"))
                        ValueNone
                        (ValueSome(Path.Combine(src, "password.txt")))

                Expect.equal layout Layout.DepositCli "detected"
                Expect.equal keys.Length 1 "one key; deposit data ignored"
            }

            test "Lighthouse v8.3.2: validator_definitions.yml from another host" {
                let layout, keys = import (copyOf "lighthouse") ValueNone ValueNone
                Expect.equal layout Layout.Lighthouse "detected"
                Expect.equal keys [ lighthouseKey ] "key 0"
                checkMarks (history "lighthouse" lighthouseKey)
            }

            test "Lighthouse v8.3.2: pubkey directory without the definitions file" {
                let src = copyOf "lighthouse"
                File.Delete(Path.Combine(src, "validators", "validator_definitions.yml"))
                Directory.CreateDirectory(Path.Combine(src, "secrets")) |> ignore
                File.WriteAllText(Path.Combine(src, "secrets", lighthouseKey.Hex), "layout-test-pw")
                let layout, keys = import src ValueNone ValueNone
                Expect.equal layout Layout.Lighthouse "detected from the pubkey directory"
                Expect.equal keys [ lighthouseKey ] "the keystore keeps its original name"
            }

            test "Teku 26.10.2: key and password directories" {
                let src = copyOf "teku"

                let layout, keys =
                    import
                        (Path.Combine(src, "keys"))
                        (ValueSome Layout.Teku)
                        (ValueSome(Path.Combine(src, "passwords")))

                Expect.equal layout Layout.Teku "named"
                Expect.equal keys [ tekuKey ] "key 1"
                checkMarks (history "teku" tekuKey)
            }

            test "Nimbus v26.10.2: re-encrypted keystore with a random password in secrets/" {
                let layout, keys = import (copyOf "nimbus") ValueNone ValueNone
                Expect.equal layout Layout.Nimbus "detected"
                Expect.equal keys [ nimbusKey ] "key 2"
                let m = history "nimbus" nimbusKey
                checkMarks m
                Expect.equal m.Attestation.Value.Root ValueNone "Nimbus writes an unknown attestation root as zero"
            }

            test "Lodestar v1.50.1" {
                let layout, keys = import (copyOf "lodestar") ValueNone ValueNone
                Expect.equal layout Layout.Lodestar "detected"
                Expect.equal keys [ lodestarKey ] "key 3"
                checkMarks (history "lodestar" lodestarKey)
            }

            test "Prysm v7.3.1: accounts backup, unzipped" {
                let src = copyOf "prysm"

                let layout, keys =
                    import
                        (Path.Combine(src, "backup"))
                        (ValueSome Layout.Plain)
                        (ValueSome(Path.Combine(src, "backup-password.txt")))

                Expect.equal layout Layout.Plain "plain directory with the backup password"
                Expect.equal keys [ prysmKey ] "key 4"
                checkMarks (history "prysm" prysmKey)
            }
        ]
