# Third-party material

Eplix is licensed under Apache-2.0 (`LICENSE`). These parts of the repository come from other
projects or follow their code.

## Test data in the repository

| Path | Source | Licence |
| --- | --- | --- |
| `tests/vectors/ssz_*`, `tests/vectors/spec_signatures_gloas/` | ethereum/consensus-spec-tests v1.6.1 and v1.7.0-beta.4, subsets listed in `tests/vectors/README.md` | CC0-1.0 |
| `tests/vectors/bls/` | ethereum/bls12-381-tests v0.1.2 | CC0-1.0 |
| `tests/fixtures/beacon/` | written from the examples and schemas of ethereum/beacon-APIs (`tests/fixtures/beacon/README.md`) | CC0-1.0 |
| `tests/fixtures/eip2335/` | the test vectors of EIP-2335 | CC0-1.0 |
| `tests/fixtures/networks/mainnet.consensus-specs-065bcd5.yaml` | ethereum/consensus-specs `configs/mainnet.yaml` | CC0-1.0 |
| `tests/fixtures/networks/hoodi.eth-clients-2a7efb3c.yaml`, `sepolia.eth-clients-7b1b9d95.yaml` | eth-clients/hoodi and eth-clients/sepolia `config.yaml` | none stated in the files |
| `tests/fixtures/remote-signing-api/schemas.json` | ethereum/remote-signing-api v1.4.0, converted by `scripts/remote-signing-schemas.py` | CC0-1.0 |

## Test data fetched, not in the repository

`scripts/fetch-test-vectors.sh` puts these in `tests/vectors/.download/`, which git ignores:
eth-clients/slashing-protection-interchange-tests v5.3.0 (no licence stated), ethereum/ssz-specs
v0.1.0 fixtures (MIT), and the beacon-APIs and keymanager-APIs OpenAPI documents (CC0-1.0).

## Code that follows other projects

| Path | Source | Licence |
| --- | --- | --- |
| `src/Eplix.Backend.Tee/Attest.fs` | ported from tee-signer's `attestation-verify` module and its `runnerclient` package (Go) | Apache-2.0 |
| `src/Eplix.Backend.Tee/Jwt.fs`, `Cbor.fs` | the token, key set and CBOR rules of tee-signer's `attestation-verify` | Apache-2.0 |
| `src/Eplix.Backend.Tee/Wire.fs` | the byte layouts of tee-signer's `signer-protocol` | Apache-2.0 |
| `src/Eplix.Backend.Dirk/Messages.fs` | message field numbers of wealdtech/eth2-signer-api v1.7.2, read from the Dirk binary; no `.proto` file is copied | none stated |

The packages the build pulls in, with their licences, are in `docs/dependencies.md`.
