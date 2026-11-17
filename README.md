<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/eplix-lockup-dark.svg">
    <img alt="eplix" src="docs/brand/eplix-lockup-light.svg" width="300">
  </picture>
</p>

<p align="center"><b>A light Ethereum validator client.</b></p>

# Eplix

**Eplix** is an Ethereum validator client written in F#. It is one native binary with a small core; every extra is a module you can leave out of the build.

It signs with local keystores, **Dirk**, **Web3Signer** or remote TEE signers. It can also split a key **m of n** across several signers and combine the parts itself, so no single signer can sign on its own.

## Why Eplix

- **Threshold signing built in.** Send each duty to n signers, combine m partial signatures in the client. Whole keys and split keys run side by side.
- **Several beacon nodes.** Attest only when a threshold of nodes agrees on the attestation data.
- **Migration.** Imports keystores in the layouts of deposit-cli, Lighthouse, Teku, Nimbus and Lodestar, with their EIP-3076 slashing history, and exports its slashing history as EIP-3076. Keymanager API included.
- **Small.** One NativeAOT binary on .NET 10. Speed has targets and measured numbers ([benchmarks](docs/benchmarks.md)).
- **Signers over mutual TLS.** Dirk and TEE signers over mutual TLS, Web3Signer over HTTPS with optional mutual TLS; client certificates reload without a restart. Each connection to a TEE signer checks the signer's remote attestation (AWS Nitro Enclaves, Azure SEV-SNP through MAA, Google Confidential Space) before it carries a request.

[Features](docs/features.md) lists every duty, module and safety check.

## Status

Version 0.1.0. It builds for linux-x64 only; a linux-arm64 build is planned. There are no binary releases yet, so build from source. [ROADMAP.md](ROADMAP.md) lists planned work, and [SECURITY.md](SECURITY.md) says which versions get security fixes and how to report a problem.

## Quick start

Needs the .NET 10 SDK, `clang` and `zlib1g-dev` to build, `libicu` at run time, and an x64 CPU with AVX ([Building and testing](docs/building.md) has the details).

```sh
git clone https://github.com/ipstake/eplix.git && cd eplix
scripts/publish-aot.sh             # artifacts/publish/linux-x64/eplix and libblst.so
```

A minimal `eplix.json` for one beacon node on Hoodi:

```json
{
  "beacon_nodes": [ "http://127.0.0.1:5052" ],
  "network": "hoodi",
  "data_dir": "data",
  "fee_recipient": "0x0000000000000000000000000000000000000000"
}
```

Import the keys with their slashing history, check the setup, then run:

```sh
eplix import --config eplix.json --from validator_keys --password-file password.txt --slashing-protection interchange.json
eplix check --config eplix.json
eplix run --config eplix.json
```

A key with no history at all (a new key) takes `--no-signing-history` instead of `--slashing-protection`. Each key waits out the doppelganger check, 2 to 3 epochs, before it signs. [Migrating keys](docs/migration.md) covers keys from other clients.

## Documentation

- [Features](docs/features.md): every duty, module and safety check.
- [Commands](docs/commands.md): `run`, `check`, `import`, `exit`, `switch` and `slashing`, emergency switches, keys slashed on chain.
- [Configuration](docs/configuration.md): flags and environment variables, the config file, chain selection, doppelganger protection, proposer config, graffiti, signing jitter, Gloas, builders, Obol mode.
- [Beacon nodes](docs/beacon-nodes.md): node entries, roles, publishing.
- [Remote signers](docs/signers.md): Dirk, Web3Signer and TEE signers, threshold groups, certificate rotation, HA pairs.
- [Keymanager API](docs/keymanager.md): TLS, the bearer token, import limits.
- [Monitoring](docs/monitoring.md): metrics, tracing and the validator monitor.
- [Migrating keys](docs/migration.md): import from deposit-cli, Teku, Lighthouse, Nimbus, Lodestar and Prysm.
- [Operator runbook](docs/runbook.md): installing as a service, keys with no slashing history, one section per alert.
- [Building and testing](docs/building.md): requirements, CPU support, tests, smoke tests, the source layout, network presets.
- [Benchmarks](docs/benchmarks.md): results and the commands that reproduce them.
- [Design](docs/design.md): architecture, backends, threshold signing, slashing protection, migration, beacon nodes, Gloas and builders, performance, testing and risks.
- [Dependencies](docs/dependencies.md): the reason for each package.
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md), [roadmap](ROADMAP.md).

## Licence

Apache-2.0, see `LICENSE`. `THIRD_PARTY.md` lists the test data and code that come from other projects.
