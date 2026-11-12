/// Domains and signing roots, as in the consensus specs (compute_domain, compute_signing_root).
module Eplix.Signing

open System

let computeForkDataRoot (version: ForkVersion) (genesisValidatorsRoot: Root) : Root =
    Codec.hashForkData
        {
            CurrentVersion = version
            GenesisValidatorsRoot = genesisValidatorsRoot
        }

let computeDomain (domainType: DomainType) (version: ForkVersion) (genesisValidatorsRoot: Root) : Domain =
    let forkDataRoot = computeForkDataRoot version genesisValidatorsRoot
    let d = Array.zeroCreate<byte> 32
    Buffer.BlockCopy(domainType.Bytes, 0, d, 0, 4)
    Buffer.BlockCopy(forkDataRoot.Bytes, 0, d, 4, 28)
    Domain.Of d

let computeSigningRoot (objectRoot: Root) (domain: Domain) : Root =
    Codec.hashSigningData
        {
            ObjectRoot = objectRoot
            Domain = domain
        }

/// get_domain for a message at `epoch`: the fork version in force at that epoch.
let domainAt (spec: ChainSpec) (genesisValidatorsRoot: Root) (domainType: DomainType) (epoch: Epoch) : Domain =
    computeDomain domainType (spec.ForkAt epoch).Version genesisValidatorsRoot
