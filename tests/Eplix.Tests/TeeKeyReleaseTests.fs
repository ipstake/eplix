/// The key release pin and the setup pin lists of the TEE module: config
/// parsing and the network rule, the check on a verified identity, and a dial against a runner on
/// loopback that reports a key release hash.
module Eplix.Tests.TeeKeyReleaseTests

open System
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil
open Eplix.Tests.TeeTlsTests

let private h (b: byte) = Root.Of(Array.create 32 b)
let private hexOf (r: Root) = Convert.ToHexStringLower r.Bytes

let private parse (json: string) =
    use doc = JsonDocument.Parse json
    Attest.parseSettings id doc.RootElement

let private noKeys =
    fun (_: string) (_: string) -> Attest.PinnedKeys(Jwt.KeySet(Collections.Generic.Dictionary())) :> Attest.KeySource

let private build net (json: string) =
    match parse json with
    | Error e -> Error e
    | Ok s -> Attest.build net s noKeys [] |> Result.map ignore

let private azure (extra: string) =
    $$"""{ "verifier": "azure-maa", "maa_host": "sharedweu.weu.attest.azure.net", "cce_policy_sha256": "{{String('c', 64)}}", "setup_sha256": "{{String('5', 64)}}" {{extra}} }"""

let private nitro (extra: string) =
    let pcr = String('1', 96)
    $$"""{ "verifier": "aws-nitro", "nitro_pcrs": { "0": "{{pcr}}", "1": "{{pcr}}", "2": "{{pcr}}" }, "setup_sha256": "{{String('5', 64)}}" {{extra}} }"""

let private gcp (extra: string) =
    $$"""{ "verifier": "gcp-cs", "gcp_image_digest": "sha256:{{String('d', 64)}}", "gcp_audience": "signer-runner-identity", "gcp_hwmodels": [ "GCP_AMD_SEV" ] {{extra}} }"""

let private expectError (r: Result<unit, string>) (part: string) (why: string) =
    match r with
    | Ok() -> failtestf "accepted: %s" why
    | Error e -> Expect.stringContains e part why

/// A runner identity with this setup and key release hash, attested by the dev platform for `nonce`.
let private devIdentity (nonce: byte[]) (setup: Root) (keyRelease: Root) : Wire.Identity =
    let zg: Wire.ConfigGroup =
        {
            Version = 0UL
            Hash = Root.Zero
            Pending =
                {
                    Version = 0UL
                    Hash = Root.Zero
                    EffectiveAt = 0UL
                }
        }

    let id: Wire.Identity =
        {
            State =
                {
                    SetupHash = setup
                    Locked = { zg with Version = 1UL; Hash = h 3uy }
                    Open = zg
                    ApproverSetHash = h 4uy
                    Order =
                        {
                            Kind = 0uy
                            Hash = Root.Zero
                            ActAt = 0UL
                        }
                    KeyReleaseHash = keyRelease
                    KeyOrigin =
                        {
                            Generated = 1u
                            Imported = 0u
                            OrdersHash = Root.Zero
                        }
                }
            ImportKem = 0us
            ImportKdf = 0us
            ImportAead = 0us
            ImportKey = [||]
            TlsKeyHash = Array.create 32 9uy
            Attestation =
                {
                    Platform = "dev"
                    Format = "dev-json"
                    UserData = [||]
                    Document = [||]
                }
        }

    let ud = Wire.identityUserData nonce id
    let doc = $"""{{"nonce":"{Convert.ToBase64String nonce}","user_data":"{Convert.ToBase64String ud}"}}"""

    { id with
        Attestation =
            { id.Attestation with
                UserData = ud
                Document = Encoding.UTF8.GetBytes doc
            }
    }

/// Verifies a dev identity with the setup pinned and these key release pins.
let private verifyWith net (setupPins: Root list) (keyPins: Root list) (setup: Root) (keyRelease: Root) =
    let quoted (rs: Root list) = String.Join(", ", rs |> List.map (fun r -> $"\"{hexOf r}\""))

    let json =
        $$"""{ "verifier": "dev", "setup_sha256": [ {{quoted setupPins}} ] {{if keyPins.IsEmpty then "" else $", \"key_release_sha256\": [ {quoted keyPins} ]"}} }"""

    match parse json |> Result.bind (fun s -> Attest.build net s noKeys []) with
    | Error e -> Error $"settings: {e}"
    | Ok v ->
        let nonce = RandomNumberGenerator.GetBytes 32

        try
            (Attest.verifyIdentity
                v
                nonce
                (devIdentity nonce setup keyRelease)
                DateTimeOffset.UtcNow
                CancellationToken.None)
                .GetAwaiter()
                .GetResult()

            Ok()
        with :? Jwt.AttestError as e ->
            Error e.Message

let private genRoot = Gen.arrayOfLength 32 (Gen.choose (0, 255) |> Gen.map byte) |> Gen.map Root.Of

[<Tests>]
let tests =
    testList
        "tee key release"
        [
            testList
                "config"
                [
                    test "key_release_sha256 takes one hash or a list; 0x and upper case are fine" {
                        match parse (nitro $""", "key_release_sha256": "0x{String('A', 64)}" """) with
                        | Ok s -> Expect.equal s.KeyReleaseSha256 [ "0x" + String('A', 64) ] "one"
                        | Error e -> failtest e

                        match
                            parse (nitro $""", "key_release_sha256": [ "{String('a', 64)}", "{String('b', 64)}" ] """)
                        with
                        | Ok s -> Expect.equal s.KeyReleaseSha256.Length 2 "two"
                        | Error e -> failtest e

                        match parse (nitro "") with
                        | Ok s -> Expect.isEmpty s.KeyReleaseSha256 "absent"
                        | Error e -> failtest e

                        match
                            parse (nitro $""", "key_release_sha256": [ "{String('a', 64)}", "{String('b', 64)}" ] """)
                            |> Result.bind (fun s -> Attest.build Attest.NetworkKind.Mainnet s noKeys [])
                        with
                        | Ok v -> Expect.equal v.Pins.KeyRelease [ h 0xaauy; h 0xbbuy ] "pins as roots"
                        | Error e -> failtest e
                    }

                    test "setup_sha256 takes one hash or a list" {
                        match
                            parse
                                $"""{{ "verifier": "dev", "setup_sha256": [ "{String('a', 64)}", "0x{String('b', 64)}" ] }}"""
                            |> Result.bind (fun s -> Attest.build Attest.NetworkKind.Testnet s noKeys [])
                        with
                        | Ok v -> Expect.equal v.Pins.Setup [ h 0xaauy; h 0xbbuy ] "two setup pins"
                        | Error e -> failtest e

                        match
                            parse
                                $"""{{ "verifier": "dev", "setup_sha256": "{String('a', 64)}", "min_locked_version": 2 }}"""
                            |> Result.bind (fun s -> Attest.build Attest.NetworkKind.Testnet s noKeys [])
                        with
                        | Ok v ->
                            Expect.equal (v.Pins.Setup, v.Pins.MinLocked) ([ h 0xaauy ], 2UL) "one setup pin, as before"
                        | Error e -> failtest e
                    }

                    test "a cloud verifier without setup_sha256 fails the config check; dev needs none" {
                        let usable net (json: string) =
                            parse json |> Result.bind (fun s -> Attest.buildUsable net s noKeys []) |> Result.map ignore

                        let unpinned (json: string) = json.Replace($", \"setup_sha256\": \"{String('5', 64)}\"", "")

                        for name, cfg in [ "azure-maa", azure ""; "aws-nitro", nitro ""; "gcp-cs", gcp "" ] do
                            expectError
                                (usable Attest.NetworkKind.Testnet (unpinned cfg))
                                $"attestation.setup_sha256: required with the {name} verifier"
                                $"{name} without a setup pin"

                        expectError
                            (usable Attest.NetworkKind.Mainnet (gcp ""))
                            "attestation.setup_sha256: required with the gcp-cs verifier"
                            "gcp-cs on mainnet"

                        let pinned = $""", "setup_sha256": "{String('5', 64)}" """

                        for name, cfg in [ "azure-maa", azure ""; "aws-nitro", nitro ""; "gcp-cs", gcp pinned ] do
                            Expect.equal (usable Attest.NetworkKind.Testnet cfg) (Ok()) $"{name} with a setup pin"

                        Expect.equal
                            (usable Attest.NetworkKind.Testnet """{ "verifier": "dev" }""")
                            (Ok())
                            "dev without a setup pin"
                        // build alone keeps tee-signer's settings check.
                        Expect.equal (build Attest.NetworkKind.Testnet (gcp "")) (Ok()) "build alone"
                    }

                    test "mistakes in the pins are refused" {
                        let bad =
                            [
                                build Attest.NetworkKind.Testnet (nitro """, "key_release_sha256": "1234" """),
                                "key_release_sha256: want 64 hex digits"
                                build Attest.NetworkKind.Testnet (nitro """, "key_release_sha256": [] """),
                                "an empty array pins nothing"
                                build Attest.NetworkKind.Testnet (nitro """, "key_release_sha256": 5 """),
                                "want a string or an array"
                                build
                                    Attest.NetworkKind.Testnet
                                    (nitro $""", "key_release_sha256": "{String('0', 64)}" """),
                                "all zero"
                                build
                                    Attest.NetworkKind.Testnet
                                    $"""{{ "verifier": "dev", "setup_sha256": [ "{String('a', 64)}", "12" ] }}""",
                                "setup_sha256: want 64 hex digits"
                                build
                                    Attest.NetworkKind.Testnet
                                    $"""{{ "verifier": "dev", "setup_sha256": [ "{String('a', 64)}" ], "allow_unpinned_setup": true }}""",
                                "allow_unpinned_setup"
                                build
                                    Attest.NetworkKind.Testnet
                                    """{ "verifier": "dev", "setup_sha256": [], "min_locked_version": 1 }""",
                                "an empty array pins nothing"
                            ]

                        for r, part in bad do
                            expectError r part part
                    }

                    test
                        "the network rule: required on mainnet for azure-maa and aws-nitro, optional on testnets, never for gcp-cs" {
                        let pin = $""", "key_release_sha256": "{String('e', 64)}" """

                        for name, cfg in [ "azure-maa", azure; "aws-nitro", nitro ] do
                            expectError
                                (build Attest.NetworkKind.Mainnet (cfg ""))
                                $"key_release_sha256: required on mainnet for {name}"
                                $"{name} unpinned on mainnet"

                            Expect.equal (build Attest.NetworkKind.Mainnet (cfg pin)) (Ok()) $"{name} pinned on mainnet"

                            Expect.equal
                                (build Attest.NetworkKind.Testnet (cfg ""))
                                (Ok())
                                $"{name} unpinned on a testnet"

                            Expect.equal
                                (build Attest.NetworkKind.Testnet (cfg pin))
                                (Ok())
                                $"{name} pinned on a testnet"

                        for net in [ Attest.NetworkKind.Mainnet; Attest.NetworkKind.Testnet ] do
                            Expect.equal (build net (gcp "")) (Ok()) "gcp-cs without a pin"
                            expectError (build net (gcp pin)) "key_release_sha256: not for gcp-cs" "gcp-cs with a pin"

                        let net = Attest.NetworkKind.Testnet

                        Expect.equal
                            (build net """{ "verifier": "dev" , "allow_unpinned_setup": true }""")
                            (Ok())
                            "dev without a pin"

                        expectError
                            (build net ($"""{{ "verifier": "dev", "allow_unpinned_setup": true {pin} }}"""))
                            "key_release_sha256: needs setup_sha256"
                            "a key release pin without a setup pin, as tee-signer refuses it"

                        Expect.equal
                            (build net ($"""{{ "verifier": "dev", "setup_sha256": "{String('5', 64)}" {pin} }}"""))
                            (Ok())
                            "dev with both pins"
                    }

                    test "the dev verifier and a testnet build are refused on mainnet" {
                        let dev = """{ "verifier": "dev", "allow_unpinned_setup": true }"""

                        expectError
                            (build Attest.NetworkKind.Mainnet dev)
                            "\"dev\" checks no platform evidence"
                            "dev on mainnet"

                        Expect.equal (build Attest.NetworkKind.Testnet dev) (Ok()) "dev on a testnet"
                        let dir = tempDir ()

                        let runner (allow: bool) (verifier: string) =
                            $"""{{ "address": "h:1", "client_cert": "c", "client_key": "k", "allow_testnet_build": {(if allow then "true" else "false")}, "attestation": {verifier} }}"""

                        let section mainnet (r: string) : ConfigSection =
                            let json = $"""{{ "runners": [ {r} ], "keys": [ "0x{String('a', 96)}" ] }}"""

                            {
                                Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
                                BaseDir = dir
                                Mainnet = mainnet
                            }

                        let nitroPinned = nitro $""", "key_release_sha256": "{String('e', 64)}" """

                        match TeeModule.parseSettings (section true (runner true nitroPinned)) with
                        | Ok _ -> failtest "allow_testnet_build passed on mainnet"
                        | Error e ->
                            Expect.stringContains
                                (String.Join("; ", e))
                                "allow_testnet_build: a testnet build is for test networks"
                                "names the field"

                        Expect.isOk
                            (TeeModule.parseSettings (section false (runner true nitroPinned)))
                            "allow_testnet_build on a testnet"

                        Expect.isOk
                            (TeeModule.parseSettings (section true (runner false nitroPinned)))
                            "no testnet build on mainnet"

                        match TeeModule.parseSettings (section true (runner false dev)) with
                        | Ok m ->
                            match TeeModule.prepare m Log.none TimeProvider.System noKeys with
                            | Ok _ -> failtest "a dev runner passed on mainnet"
                            | Error e -> Expect.stringContains e "not on mainnet" "refused at prepare"
                        | Error e -> failtestf "parse: %A" e
                    }

                    test "the tee section knows mainnet from the core config" {
                        let dir = tempDir ()

                        let runner =
                            $"""{{ "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": {nitro ""} }}"""

                        let json = $"""{{ "runners": [ {runner} ], "keys": [ "0x{String('a', 96)}" ] }}"""

                        let section mainnet : ConfigSection =
                            {
                                Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
                                BaseDir = dir
                                Mainnet = mainnet
                            }

                        match TeeModule.parseSettings (section true), TeeModule.parseSettings (section false) with
                        | Ok m, Ok t ->
                            Expect.equal m.Network Attest.NetworkKind.Mainnet "mainnet"
                            Expect.equal t.Network Attest.NetworkKind.Testnet "testnet"

                            match TeeModule.prepare m Log.none TimeProvider.System noKeys with
                            | Ok _ -> failtest "an unpinned nitro runner passed on mainnet"
                            | Error e ->
                                Expect.stringContains e "key_release_sha256: required on mainnet" "refused at prepare"
                        | a, b -> failtestf "parse: %A %A" a b
                    }

                    test
                        "core config: mainnet from the network name, or a chain_config named mainnet or with its genesis fork version" {
                        let dir = tempDir ()

                        let parse (chain: string) =
                            let json =
                                $$"""{ "beacon_nodes": [ "http://127.0.0.1:5052" ], {{chain}}, "data_dir": "d", "modules": { "tee": {} } }"""

                            match Config.parse json dir [ "tee" ] with
                            | Ok c -> c.Modules["tee"].Mainnet
                            | Error e -> failtestf "%A" e

                        File.WriteAllText(
                            Path.Combine(dir, "main.yaml"),
                            "CONFIG_NAME: 'mainnet'\nGENESIS_FORK_VERSION: 0x00000000\n"
                        )

                        File.WriteAllText(
                            Path.Combine(dir, "fork0.yaml"),
                            "CONFIG_NAME: 'mine'\nGENESIS_FORK_VERSION: 0x00000000\n"
                        )

                        File.WriteAllText(
                            Path.Combine(dir, "dev.yaml"),
                            "CONFIG_NAME: 'devnet'\nGENESIS_FORK_VERSION: 0x10000038\n"
                        )

                        Expect.isTrue (parse "\"network\": \"mainnet\"") "network mainnet"
                        Expect.isFalse (parse "\"network\": \"hoodi\"") "network hoodi"
                        Expect.isTrue (parse "\"chain_config\": \"main.yaml\"") "file named mainnet"

                        Expect.isTrue
                            (parse "\"chain_config\": \"fork0.yaml\"")
                            "file with mainnet's genesis fork version"

                        Expect.isFalse (parse "\"chain_config\": \"dev.yaml\"") "a devnet file"

                        Expect.isTrue
                            (parse "\"chain_config\": \"missing.yaml\"")
                            "a file that cannot be read counts as mainnet"
                    }

                    test "eplix check prints the pins of each runner" {
                        let r: TeeModule.RunnerConfig =
                            {
                                Name = "signer-1"
                                Host = "h"
                                Port = 1
                                ClientCert = ""
                                ClientKey = ""
                                TlsKeyPin = ValueNone
                                AllowTestnetBuild = false
                                Connections = 1
                                Attestation =
                                    { Attest.Settings.Empty with
                                        Verifier = "aws-nitro"
                                        SetupSha256 = [ String('a', 64) ]
                                        KeyReleaseSha256 = [ String('b', 64); "0x" + String('C', 64) ]
                                    }
                            }

                        let line = TeeModule.describePins r

                        Expect.equal
                            line
                            $"signer-1 (aws-nitro): setup_sha256 {String('a', 64)}; key_release_sha256 {String('b', 64)} or {String('c', 64)}"
                            "pins"

                        let none =
                            TeeModule.describePins
                                { r with
                                    Attestation =
                                        { r.Attestation with
                                            SetupSha256 = []
                                            KeyReleaseSha256 = []
                                        }
                                }

                        Expect.equal
                            none
                            "signer-1 (aws-nitro): setup_sha256 not pinned; key_release_sha256 not pinned"
                            "none"
                    }
                ]

            testList
                "identity"
                [
                    test
                        "a runner whose key release hash is pinned passes; a second accepted one passes; another fails with both hashes" {
                        let setup = h 1uy

                        Expect.equal
                            (verifyWith Attest.NetworkKind.Testnet [ setup ] [ h 0x51uy; h 0x52uy ] setup (h 0x51uy))
                            (Ok())
                            "first"

                        Expect.equal
                            (verifyWith Attest.NetworkKind.Testnet [ setup ] [ h 0x51uy; h 0x52uy ] setup (h 0x52uy))
                            (Ok())
                            "second"

                        match
                            verifyWith Attest.NetworkKind.Testnet [ setup ] [ h 0x51uy; h 0x52uy ] setup (h 0x53uy)
                        with
                        | Ok() -> failtest "a wrong key release hash passed"
                        | Error e ->
                            Expect.stringContains e (h 0x53uy).Hex "the runner's hash"
                            Expect.stringContains e (h 0x51uy).Hex "a pinned hash"
                            Expect.stringContains e (h 0x52uy).Hex "the other pinned hash"

                        match verifyWith Attest.NetworkKind.Testnet [ setup ] [ h 0x51uy ] setup Root.Zero with
                        | Ok() -> failtest "a runner without key release passed a pin"
                        | Error e -> Expect.stringContains e "key_release_sha256" "names the pin"
                    }

                    test "no pin for dev: any key release hash passes" {
                        for kr in [ Root.Zero; h 0x77uy ] do
                            Expect.equal
                                (verifyWith Attest.NetworkKind.Testnet [ h 1uy ] [] (h 1uy) kr)
                                (Ok())
                                "unpinned dev"
                    }

                    test "setup_sha256 as a list: either setup passes, a third fails with the pins named" {
                        Expect.equal
                            (verifyWith Attest.NetworkKind.Testnet [ h 1uy; h 2uy ] [] (h 1uy) Root.Zero)
                            (Ok())
                            "old setup"

                        Expect.equal
                            (verifyWith Attest.NetworkKind.Testnet [ h 1uy; h 2uy ] [] (h 2uy) Root.Zero)
                            (Ok())
                            "new setup"

                        match verifyWith Attest.NetworkKind.Testnet [ h 1uy; h 2uy ] [] (h 3uy) Root.Zero with
                        | Ok() -> failtest "a third setup passed"
                        | Error e ->
                            Expect.stringContains e "is not the pinned setup_sha256" "message"
                            Expect.stringContains e (h 2uy).Hex "the pins"
                    }

                    testPropN
                        "the identity passes exactly when the key release hash is in the pin list (or no list is set)"
                        200
                    <| Prop.forAll
                        (Arb.fromGen (
                            gen {
                                let! n = Gen.choose (0, 4)
                                let! pins = Gen.listOfLength n genRoot
                                let! pick = Gen.choose (0, 2)
                                let! other = genRoot
                                let reported = if pick > 0 && not pins.IsEmpty then pins[pick % pins.Length] else other
                                return pins, reported, Attest.NetworkKind.Testnet
                            }
                        ))
                        (fun (pins, reported, net) ->
                            let pins = pins |> List.filter (fun p -> p <> Root.Zero)
                            let passed = verifyWith net [ h 1uy ] pins (h 1uy) reported = Ok()
                            passed = (pins.IsEmpty || List.contains reported pins))
                ]

            testList
                "dial"
                [
                    testT
                        "a runner on loopback: the dial passes with its key release hash pinned and fails with another, naming both"
                        (fun () ->
                            task {
                                let client = makePki "client" false
                                use runner = new FakeTlsRunner(client.Root, RunnerMode.Plain)
                                runner.KeyRelease <- h 0x61uy

                                let ctx =
                                    System.Net.Security.SslStreamCertificateContext.Create(
                                        client.Leaf,
                                        Security.Cryptography.X509Certificates.X509Certificate2Collection(
                                            [| client.Intermediate |]
                                        ),
                                        offline = true
                                    )

                                let settings (pins: Root list) : RunnerSettings =
                                    {
                                        Name = "fake"
                                        Host = "127.0.0.1"
                                        Port = runner.Port
                                        ClientCert = TlsFile<_>.Fixed(ctx, DateTimeOffset.MaxValue)
                                        TlsKeyPin = ValueNone
                                        AllowTestnetBuild = false
                                        Verifier =
                                            {
                                                Name = "test"
                                                Document = fun _ _ _ _ _ -> Task.FromResult()
                                                Pins =
                                                    {
                                                        Setup = []
                                                        MinLocked = 0UL
                                                        MinOpen = 0UL
                                                        AllowUnpinned = true
                                                        Dev = true
                                                        KeyRelease = pins
                                                    }
                                            }
                                    }

                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)

                                let! ok =
                                    RunnerConnection.Dial(
                                        settings [ h 0x60uy; h 0x61uy ],
                                        (fun () -> DateTimeOffset.UtcNow),
                                        cts.Token
                                    )

                                ok.Close()

                                try
                                    let! c =
                                        RunnerConnection.Dial(
                                            settings [ h 0x62uy ],
                                            (fun () -> DateTimeOffset.UtcNow),
                                            cts.Token
                                        )

                                    c.Close()
                                    failtest "the dial passed with another key release hash pinned"
                                with :? IOException as e ->
                                    Expect.stringContains e.Message (h 0x61uy).Hex "the runner's hash"
                                    Expect.stringContains e.Message (h 0x62uy).Hex "the pin"
                            })
                ]
        ]
