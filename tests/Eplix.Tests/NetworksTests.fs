/// The built-in network configs: each against values written out here from the
/// published specs of the networks, the fork digests they give, and `network` in the config.
module Eplix.Tests.NetworksTests

open System
open Expecto
open Eplix

let private pinnedOf name = (ChainSource.Network name).Pinned

let private specOf name =
    match ChainSpec.parse (pinnedOf name) with
    | Ok s -> s
    | Error e -> failwith e

/// A network as its published config gives it: genesis fork version, the forks after genesis
/// (name, version, epoch; unscheduled ones left out), deposit chain and contract.
type private Known =
    {
        Name: string
        Genesis: string
        Forks: (string * string * uint64) list
        ChainId: string
        Contract: string
    }

let private known =
    [
        {
            Name = "mainnet"
            Genesis = "0x00000000"
            Forks =
                [
                    "altair", "0x01000000", 74240UL
                    "bellatrix", "0x02000000", 144896UL
                    "capella", "0x03000000", 194048UL
                    "deneb", "0x04000000", 269568UL
                    "electra", "0x05000000", 364032UL
                    "fulu", "0x06000000", 411392UL
                ]
            ChainId = "1"
            Contract = "0x00000000219ab540356cbb839cbe05303d7705fa"
        }
        {
            Name = "hoodi"
            Genesis = "0x10000910"
            Forks =
                [
                    "altair", "0x20000910", 0UL
                    "bellatrix", "0x30000910", 0UL
                    "capella", "0x40000910", 0UL
                    "deneb", "0x50000910", 0UL
                    "electra", "0x60000910", 2048UL
                    "fulu", "0x70000910", 50688UL
                ]
            ChainId = "560048"
            Contract = "0x00000000219ab540356cbb839cbe05303d7705fa"
        }
        {
            Name = "sepolia"
            Genesis = "0x90000069"
            Forks =
                [
                    "altair", "0x90000070", 50UL
                    "bellatrix", "0x90000071", 100UL
                    "capella", "0x90000072", 56832UL
                    "deneb", "0x90000073", 132608UL
                    "electra", "0x90000074", 222464UL
                    "fulu", "0x90000075", 272640UL
                    "gloas", "0x90000076", 353024UL
                ]
            ChainId = "11155111"
            Contract = "0x7f02c3e3c98b133055b8b348b2ac625669ed295d"
        }
    ]

/// The 4-byte fork digest without blob parameters: the first bytes of the fork data root, which
/// a domain carries after its type.
let private digest (version: ForkVersion) (gvr: Root) =
    let d = Signing.computeDomain (DomainType.Of [| 0uy; 0uy; 0uy; 0uy |]) version gvr
    Hex.encodeArray d.Bytes[4..7]

let private settingsOf (r: Result<ConfigSources.Setting list, string list>) =
    match r with
    | Ok s -> s
    | Error e -> failwith (String.Join("; ", e))

/// Published configs pinned at a date, as files: tests/fixtures/networks/<network>.<source>.yaml.
/// Refresh them from their sources before each release and each fork (README, "Network presets").
let private pinnedFiles () =
    let dir = IO.Path.Combine(Eplix.Tests.TestUtil.fixtures, "networks")

    [
        for f in IO.Directory.GetFiles(dir, "*.yaml") ->
            let name = IO.Path.GetFileName(f).Split('.')[0]
            name, f, ChainSpec.parseConfigYaml (IO.File.ReadAllText f)
    ]

/// Built-in networks without a pinned published file, with the reason (none at present).
let private notPinned: Map<string, string> = Map.empty

let private presetTests =
    testList
        "presets against pinned published configs"
        [
            test "each built-in network agrees with its pinned published config" {
                for name, file, published in pinnedFiles () do
                    match ChainSpec.checkPinned (pinnedOf name) published with
                    | Ok() -> ()
                    | Error e -> failtestf "the built-in %s lags %s: %s" name (IO.Path.GetFileName file) e
            }
            test "every built-in network has a pinned file or a reason" {
                let pinned = pinnedFiles () |> List.map (fun (n, _, _) -> n) |> Set.ofList

                for name in Networks.names do
                    Expect.isTrue
                        (pinned.Contains name || notPinned.ContainsKey name)
                        $"{name}: no pinned published config and no reason"

                Expect.isEmpty
                    (Set.intersect pinned (notPinned |> Map.keys |> Set.ofSeq))
                    "a network both pinned and listed as not pinned"
            }
            test "a published fork the preset does not schedule fails" {
                let name, _, published = pinnedFiles () |> List.find (fun (n, _, _) -> n = "mainnet")
                let gloas = published |> Map.add "GLOAS_FORK_EPOCH" "500000"
                Expect.isError (ChainSpec.checkPinned (pinnedOf name) gloas) "Gloas scheduled in the published config"
                let moved = published |> Map.add "FULU_FORK_EPOCH" "411393"
                Expect.isError (ChainSpec.checkPinned (pinnedOf name) moved) "a fork epoch that differs"
            }
        ]

[<Tests>]
let tests =
    testList
        "networks"
        [
            test "the built-in networks are mainnet, hoodi and sepolia" {
                Expect.equal Networks.names [ "mainnet"; "hoodi"; "sepolia" ] "names"
                Expect.equal (Networks.configYaml "goerli") ValueNone "no others"
            }

            for k in known do
                test $"{k.Name}: fork versions and epochs, genesis, deposit contract" {
                    let s = specOf k.Name
                    let p = pinnedOf k.Name
                    Expect.equal s.ConfigName k.Name "CONFIG_NAME"
                    Expect.equal p["PRESET_BASE"] "mainnet" "PRESET_BASE"
                    Expect.equal s.SlotsPerEpoch 32UL "32 slots an epoch"
                    Expect.equal s.SlotDuration (TimeSpan.FromSeconds 12.0) "12 s slots"
                    Expect.equal s.Forks[0].Name Phase0 "genesis fork first"
                    Expect.equal s.Forks[0].Version.Hex k.Genesis "genesis fork version"
                    let forks = [ for f in s.Forks[1..] -> f.Name.ApiName, f.Version.Hex, f.Epoch ]
                    Expect.equal forks k.Forks "forks after genesis"
                    Expect.equal p["DEPOSIT_CHAIN_ID"] k.ChainId "deposit chain id"
                    Expect.equal p["DEPOSIT_NETWORK_ID"] k.ChainId "deposit network id"
                    Expect.equal (p["DEPOSIT_CONTRACT_ADDRESS"].ToLowerInvariant()) k.Contract "deposit contract"
                }

            test "mainnet fork digests from phase0 to deneb" {
                // The digests in the ENR and gossip topics of mainnet nodes, before blob parameters
                // changed the digest (Fulu).
                let gvr =
                    Root.Of((Hex.tryDecode "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95").Value)

                let s = specOf "mainnet"

                let digests =
                    [
                        for f in s.Forks |> Array.filter (fun f -> f.Name <= Deneb) ->
                            f.Name.ApiName, digest f.Version gvr
                    ]

                Expect.equal
                    digests
                    [
                        "phase0", "0xb5303f2a"
                        "altair", "0xafcaaba0"
                        "bellatrix", "0x4a26c58b"
                        "capella", "0xbba4da96"
                        "deneb", "0x6a95a1a9"
                    ]
                    "fork digests"
            }

            test "a node that reports the same values and more passes the check" {
                for name in Networks.names do
                    let p = pinnedOf name

                    let node =
                        p
                            .Add("MAX_COMMITTEES_PER_SLOT", "64")
                            .Add("DEPOSIT_CONTRACT_ADDRESS", p["DEPOSIT_CONTRACT_ADDRESS"].ToLowerInvariant())

                    Expect.isOk (ChainSpec.checkPinned p node) $"{name}: same chain"

                    Expect.isError
                        (ChainSpec.checkPinned p (node.Add("FULU_FORK_EPOCH", "1")))
                        $"{name}: another Fulu epoch"

                    Expect.isError
                        (ChainSpec.checkPinned p (node.Add("GENESIS_FORK_VERSION", "0x00000001")))
                        $"{name}: another genesis fork"

                    Expect.isError
                        (ChainSpec.checkPinned p (node.Add("DEPOSIT_CONTRACT_ADDRESS", "0x" + String('1', 40))))
                        $"{name}: another deposit contract"

                    Expect.isError (ChainSpec.checkPinned p (node.Add("CONFIG_NAME", "devnet"))) $"{name}: another name"

                Expect.isError
                    (ChainSpec.checkPinned (pinnedOf "hoodi") (pinnedOf "sepolia"))
                    "hoodi pinned, sepolia node"

                Expect.isError
                    (ChainSpec.checkPinned (pinnedOf "mainnet") (pinnedOf "hoodi"))
                    "mainnet pinned, hoodi node"
            }

            test "a fork one side does not list passes only while the other side has it unscheduled" {
                let hoodi = pinnedOf "hoodi"
                let farFuture = string UInt64.MaxValue
                let withGloas epoch = hoodi.Add("GLOAS_FORK_VERSION", "0x80000910").Add("GLOAS_FORK_EPOCH", epoch)
                Expect.isOk (ChainSpec.checkPinned hoodi (withGloas farFuture)) "a node that knows Gloas, not scheduled"
                Expect.isError (ChainSpec.checkPinned hoodi (withGloas "60000")) "a node with Gloas scheduled"
                let mainnet = pinnedOf "mainnet"
                let older = mainnet.Remove("GLOAS_FORK_VERSION").Remove("GLOAS_FORK_EPOCH")

                Expect.isOk
                    (ChainSpec.checkPinned mainnet older)
                    "a node that does not know Gloas, unscheduled in the pin"

                let sepolia = pinnedOf "sepolia"

                Expect.isError
                    (ChainSpec.checkPinned sepolia (sepolia.Remove("GLOAS_FORK_VERSION").Remove("GLOAS_FORK_EPOCH")))
                    "Sepolia schedules Gloas: a node without it fails"

                Expect.isError
                    (ChainSpec.checkPinned sepolia (sepolia.Add("GLOAS_FORK_EPOCH", farFuture)))
                    "Gloas scheduled in the pin, not on the node"
            }

            test "config: network or chain_config, not both, not neither, known names only" {
                let parse (fields: string) =
                    Config.parse ("""{ "beacon_node": "http://a:1", "data_dir": "d" """ + fields + " }") "/base" []

                match parse """, "network": "Hoodi" """ with
                | Ok c -> Expect.equal c.Chain (ChainSource.Network "hoodi") "a network, any case"
                | Error e -> failwith (String.Join("; ", e))

                match parse """, "chain_config": "c.yaml" """ with
                | Ok c ->
                    Expect.equal
                        c.Chain
                        (ChainSource.File(IO.Path.Combine("/base", "c.yaml")))
                        "a file, next to the config"
                | Error e -> failwith (String.Join("; ", e))

                let errorOf fields =
                    match parse fields with
                    | Error e -> String.Join("; ", e)
                    | Ok _ -> failwith "expected an error"

                Expect.stringContains (errorOf """, "network": "hoodi", "chain_config": "c.yaml" """) "not both" "both"

                Expect.stringContains
                    (errorOf "")
                    "network (mainnet, hoodi, sepolia) or chain_config is required"
                    "neither"

                Expect.stringContains (errorOf """, "network": "holesky" """) "is not a built-in network" "unknown"
            }

            test "--network and EPLIX_NETWORK set it" {
                let load settings =
                    match ConfigSources.load ValueNone settings [] with
                    | Ok c -> c.Chain
                    | Error e -> failwith (String.Join("; ", e))

                let flags =
                    settingsOf (
                        ConfigSources.fromFlags [ "beacon-node", "http://a:1"; "data-dir", "/d"; "network", "mainnet" ]
                    )

                Expect.equal (load flags) (ChainSource.Network "mainnet") "flag"

                let env =
                    settingsOf (
                        ConfigSources.fromEnv
                            [
                                "EPLIX_BEACON_NODE", "http://a:1"
                                "EPLIX_DATA_DIR", "/d"
                                "EPLIX_NETWORK", "sepolia"
                            ]
                    )

                Expect.equal (load env) (ChainSource.Network "sepolia") "environment"
            }
            presetTests
        ]
