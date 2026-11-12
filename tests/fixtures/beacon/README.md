# Beacon API fixtures

Responses as a beacon node sends them, written by hand from the examples and schemas in
ethereum/beacon-APIs at commit `79b9b05e354da4f80d8f18879871af6f0068108d` (2026-10-20). Where the
spec gives an example value, the fixture uses it; other values follow the schema. No live node
was used.

| File | Endpoint |
| --- | --- |
| `genesis.json` | `GET /eth/v1/beacon/genesis` |
| `spec.json` | `GET /eth/v1/config/spec` (a Fulu node; includes the nested `BLOB_SCHEDULE`) |
| `fork.json` | `GET /eth/v1/beacon/states/{state_id}/fork` |
| `validators.json` | `POST /eth/v1/beacon/states/{state_id}/validators` |
| `attester_duties.json` | `POST /eth/v1/validator/duties/attester/{epoch}` |
| `proposer_duties.json` | `GET /eth/v1/validator/duties/proposer/{epoch}` |
| `attestation_data.json` | `GET /eth/v1/validator/attestation_data` |
| `syncing.json` | `GET /eth/v1/node/syncing` |
| `submit_attestations_400.json` | `POST /eth/v2/beacon/pool/attestations`, IndexedErrorMessage |
| `error_400.json` | ErrorMessage |
| `events.txt` | `GET /eth/v1/events?topics=head` stream with a `head` and a `head_v2` event |
| `monitor_block_fulu.json` | `GET /eth/v2/beacon/blocks/{block_id}`, a Fulu block, mainnet preset, 8 aggregates and 150 transactions (192 KB) |
| `monitor_committees.json` | `GET /eth/v1/beacon/states/{state_id}/committees`, 64 committees of 500 (387 KB) |

The two `monitor_*` files are not from the spec examples: they were recorded from the fake mainnet
node used for the 2026-10-31 hot path measurements, as the monitor's readers got them there.
