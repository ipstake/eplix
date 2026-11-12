/// Built-in chain configs for the public networks, picked with `network` (`--network`) in place
/// of a `chain_config` file. Each is the identity part of the network's official config.yaml:
/// name, preset, genesis, fork schedule, slot time and deposit contract. The start-up check
/// compares them with every beacon node's spec, as it does a file. Sources, read
/// 2026-10-27: mainnet from ethereum/consensus-specs configs/mainnet.yaml, Hoodi and Sepolia
/// from eth-clients/hoodi and eth-clients/sepolia metadata/config.yaml. A value here changes
/// only with a new fork schedule, and then in a release.
module Eplix.Networks

let private mainnet =
    """CONFIG_NAME: 'mainnet'
PRESET_BASE: 'mainnet'
MIN_GENESIS_TIME: 1606824000
GENESIS_FORK_VERSION: 0x00000000
GENESIS_DELAY: 604800
ALTAIR_FORK_VERSION: 0x01000000
ALTAIR_FORK_EPOCH: 74240
BELLATRIX_FORK_VERSION: 0x02000000
BELLATRIX_FORK_EPOCH: 144896
CAPELLA_FORK_VERSION: 0x03000000
CAPELLA_FORK_EPOCH: 194048
DENEB_FORK_VERSION: 0x04000000
DENEB_FORK_EPOCH: 269568
ELECTRA_FORK_VERSION: 0x05000000
ELECTRA_FORK_EPOCH: 364032
FULU_FORK_VERSION: 0x06000000
FULU_FORK_EPOCH: 411392
GLOAS_FORK_VERSION: 0x07000000
GLOAS_FORK_EPOCH: 18446744073709551615
SECONDS_PER_SLOT: 12
SLOT_DURATION_MS: 12000
DEPOSIT_CHAIN_ID: 1
DEPOSIT_NETWORK_ID: 1
DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa
"""

let private hoodi =
    """CONFIG_NAME: 'hoodi'
PRESET_BASE: 'mainnet'
MIN_GENESIS_TIME: 1742212800
GENESIS_FORK_VERSION: 0x10000910
GENESIS_DELAY: 600
ALTAIR_FORK_VERSION: 0x20000910
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_VERSION: 0x30000910
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_VERSION: 0x40000910
CAPELLA_FORK_EPOCH: 0
DENEB_FORK_VERSION: 0x50000910
DENEB_FORK_EPOCH: 0
ELECTRA_FORK_VERSION: 0x60000910
ELECTRA_FORK_EPOCH: 2048
FULU_FORK_VERSION: 0x70000910
FULU_FORK_EPOCH: 50688
SECONDS_PER_SLOT: 12
SLOT_DURATION_MS: 12000
DEPOSIT_CHAIN_ID: 560048
DEPOSIT_NETWORK_ID: 560048
DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa
"""

let private sepolia =
    """CONFIG_NAME: 'sepolia'
PRESET_BASE: 'mainnet'
MIN_GENESIS_TIME: 1655647200
GENESIS_FORK_VERSION: 0x90000069
GENESIS_DELAY: 86400
ALTAIR_FORK_VERSION: 0x90000070
ALTAIR_FORK_EPOCH: 50
BELLATRIX_FORK_VERSION: 0x90000071
BELLATRIX_FORK_EPOCH: 100
CAPELLA_FORK_VERSION: 0x90000072
CAPELLA_FORK_EPOCH: 56832
DENEB_FORK_VERSION: 0x90000073
DENEB_FORK_EPOCH: 132608
ELECTRA_FORK_VERSION: 0x90000074
ELECTRA_FORK_EPOCH: 222464
FULU_FORK_VERSION: 0x90000075
FULU_FORK_EPOCH: 272640
GLOAS_FORK_VERSION: 0x90000076
GLOAS_FORK_EPOCH: 353024
SECONDS_PER_SLOT: 12
SLOT_DURATION_MS: 12000
DEPOSIT_CHAIN_ID: 11155111
DEPOSIT_NETWORK_ID: 11155111
DEPOSIT_CONTRACT_ADDRESS: 0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D
"""

/// The network names `network` accepts, with their config.yaml text.
let all: (string * string) list = [ "mainnet", mainnet; "hoodi", hoodi; "sepolia", sepolia ]

let names = all |> List.map fst

/// The config.yaml text of a network, by name (lower case).
let configYaml (name: string) : string voption =
    match all |> List.tryFind (fun (n, _) -> n = name) with
    | Some(_, text) -> ValueSome text
    | None -> ValueNone

let private anchorOf (genesisTime: uint64) (gvr: string) : ChainAnchor =
    {
        GenesisTime = genesisTime
        GenesisValidatorsRoot = (Root.TryParse gvr).Value
        SlotDuration = System.TimeSpan.FromSeconds 12.0
        SlotsPerEpoch = 32UL
    }

/// What each network's genesis state fixes, and the mainnet preset's slot timing. Every node of a
/// built-in network must report these, at start and each epoch; config.yaml
/// does not carry them. Sources, read 2026-11-04: genesis time and root from Lodestar v1.50.1
/// `packages/config/src/networks.ts` (`genesisData`); for mainnet also the genesis state in Teku
/// 26.10.2's `teku-ethereum-networks` jar (`mainnet-genesis.ssz`, bytes 0 to 8 and 8 to 40); for
/// Hoodi also the launch time in the `eth-clients/hoodi` README. Hoodi's and Sepolia's genesis
/// time is MIN_GENESIS_TIME + GENESIS_DELAY of their config; a test checks that.
let private anchors =
    [
        "mainnet", anchorOf 1606824023UL "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        "hoodi", anchorOf 1742213400UL "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
        "sepolia", anchorOf 1655733600UL "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
    ]

/// The pinned genesis and slot timing of a built-in network, by name (lower case).
let anchor (name: string) : ChainAnchor voption =
    match anchors |> List.tryFind (fun (n, _) -> n = name) with
    | Some(_, a) -> ValueSome a
    | None -> ValueNone
