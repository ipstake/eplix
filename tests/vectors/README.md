# Test vectors

| Path | Source | Licence |
| --- | --- | --- |
| `ssz_static/` | consensus-spec-tests v1.6.1, `minimal.tar.gz`, `tests/minimal/fulu/ssz_static/`: 38 containers (duties, blocks, aggregation and sync committee), cases 0 to 2 of each kind, `roots.yaml` and `serialized.ssz_snappy` only | CC0-1.0 (consensus-specs) |
| `ssz_static_gloas/` | consensus-spec-tests v1.7.0-beta.4, `minimal.tar.gz`, `tests/minimal/gloas/ssz_static/`: the 44 containers Eplix encodes, hashes or reads in Gloas, cases 0 to 2 of each kind (660 cases), `roots.yaml` and `serialized.ssz_snappy` only. `EPLIX_GLOAS_SSZ_STATIC=<dir>` runs every case of an unpacked release as well | CC0-1.0 (consensus-specs) |
| `ssz_static_mainnet_fulu/`, `ssz_static_mainnet_gloas/` | consensus-spec-tests v1.7.0-beta.4, `mainnet.tar.gz` (967,886,924 B, equal to the GitHub release digest), `tests/mainnet/{fulu,gloas}/ssz_static/`: the same 38 and 44 containers as for minimal, cases 0 to 2 (mainnet has the `ssz_random` suite only; 114 and 132 cases), `roots.yaml` and `serialized.ssz_snappy` only | CC0-1.0 (consensus-specs) |
| `spec_signatures_gloas/` | consensus-spec-tests v1.7.0-beta.4, `minimal.tar.gz`, `tests/minimal/gloas/`: `operations/{voluntary_exit,proposer_slashing,attester_slashing}` (each `post.ssz_snappy` replaced by an empty `valid` marker) and `networking/gossip_{payload_attestation_message,proposer_preferences,execution_payload_envelope,voluntary_exit,beacon_attestation,beacon_aggregate_and_proof}`, whole cases (3.0 MB) | CC0-1.0 (consensus-specs) |
| `ssz_generic/` | consensus-spec-tests v1.6.1, `general.tar.gz`, `tests/general/phase0/ssz_generic/`: every case whose `serialized.ssz_snappy` is at most 32 KiB (4,946 of 5,145; `serialized.ssz_snappy`, and `meta.yaml` for valid cases). `EPLIX_SSZ_GENERIC=<dir>` runs every case of an unpacked release as well | CC0-1.0 (consensus-specs) |
| `bls/` | ethereum/bls12-381-tests v0.1.2, `bls_tests_json.tar.gz`: all nine handlers (`sign`, `verify`, `aggregate`, `fast_aggregate_verify`, `batch_verify`, `aggregate_verify`, `deserialization_G1`, `deserialization_G2`, `hash_to_G2`) | CC0-1.0 |
| `.download/eip3076/` | eth-clients/slashing-protection-interchange-tests v5.3.0, the 38 files of `tests/generated/`, fetched by `scripts/fetch-test-vectors.sh` (from GitHub, or from a local copy of the archive given as an argument or found in `$DL_DIR/eip3076/`); not committed (the repository has no licence file). The suite fails when any file is missing; `EPLIX_EIP3076_DIR` points it at another directory | none stated |
| `.download/ssz-specs/` | ethereum/ssz-specs v0.1.0, `ssz-test-vectors-v0.1.0.tar.gz`: the 117 fixtures (JSON), fetched by `scripts/fetch-test-vectors.sh`; not committed (MIT, and the archive carries no licence text). `EPLIX_SSZ_SPECS_DIR` points the tests elsewhere | MIT |
| `.download/beacon-apis/beacon-node-oapi.json` | ethereum/beacon-APIs v5.0.0-beta.0 release asset, fetched by `scripts/fetch-test-vectors.sh` (6.9 MB) | CC0-1.0 |
| `.download/keymanager-apis/keymanager-oapi.json` | ethereum/keymanager-APIs v1.2.0-alpha.0 release asset (the newest tag), fetched by `scripts/fetch-test-vectors.sh` | CC0-1.0 |

SHA-256 of the archives the subsets come from:

| Archive | SHA-256 |
| --- | --- |
| consensus-spec-tests v1.6.1 `general.tar.gz` | `87898ba7a3fa16bc66b08c88b4ccab008833a517a7602cf421c6ce79734e07e9` |
| consensus-spec-tests v1.6.1 `minimal.tar.gz` | `e1d0c9dc3d09fb74a98b324c40b2587a17dc555e6149d3f9741601fffcf43901` |
| consensus-spec-tests v1.7.0-beta.4 `minimal.tar.gz` | `26d09aea70c62ed235a120a95082d544ab1c2e6fe36bd35ea1bd5da62f3b7b68` |
| consensus-spec-tests v1.7.0-beta.4 `mainnet.tar.gz` | `67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c` |
| bls12-381-tests v0.1.2 `bls_tests_json.tar.gz` | `0dc1dfabfa7b3e0f8e8029f9cb2bb8733597526fa085b18f160d2c4eb0b448bc` |

`scripts/fetch-test-vectors.sh` pins the hashes of the files it fetches.
