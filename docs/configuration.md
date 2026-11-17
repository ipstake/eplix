# Configuration

Signer sections (`dirk`, `web3signer`, `tee`) are in [Remote signers](signers.md), beacon node entries in [Beacon nodes](beacon-nodes.md), the keymanager API in [Keymanager API](keymanager.md), and metrics, tracing and the validator monitor in [Monitoring](monitoring.md).

## Flags and environment variables

Any config key can come from a flag or an environment variable. A flag wins over the environment, the environment over the file, and unknown keys fail from every source:

```sh
eplix run --config eplix.json --fee-recipient 0x... --log-format json
eplix run --beacon-nodes http://a:5052,http://b:5052 --chain-config config.yaml --data-dir data --modules.metrics.port 5065
EPLIX_CONFIG=eplix.json EPLIX_GRAFFITI=eplix EPLIX_MODULES__METRICS__ADDRESS=0.0.0.0 eplix run
```

Dots separate levels in a flag, `__` in a variable. `true`, `false`, `null` and values that start with `[` or `{` are JSON, anything else is a string. Without `--config` and `EPLIX_CONFIG` there is no file. `"log_format": "json"` writes each log line as `{"time": .., "level": .., "msg": ..}`.

## Example config file

A minimal file, the same setup as the quick start in the README:

```json
{
  "beacon_nodes": [ "http://127.0.0.1:5052" ],
  "network": "hoodi",
  "data_dir": "data",
  "fee_recipient": "0x..."
}
```

Run with `eplix run --config eplix.json`. A fuller example (every key can also come from a flag or an environment variable, see above):

```json
{
  "beacon_nodes": [ "http://127.0.0.1:5052", "http://192.0.2.2:5052", "http://192.0.2.3:5052" ],
  "attestation_consensus_threshold": 2,
  "ptc_consensus_threshold": 1,
  "network": "hoodi",
  "data_dir": "data",
  "fee_recipient": "0x0000000000000000000000000000000000000000",
  "graffiti": "eplix",
  "graffiti_append": "off",
  "proposer_config": "proposers.json",
  "modules": {
    "local": { "keystores": [ { "path": "validator_keys", "password_file": "password.txt" } ] },
    "keymanager": { "port": 5062 },
    "metrics": { "address": "127.0.0.1", "port": 5064 },
    "doppelganger": { "enabled": true, "epochs": 2, "threshold_keys": false },
    "monitor": { "enabled": true, "per_validator": false }
  }
}
```

## Chain and slashing history

`beacon_node` (one URL) can stand in for `beacon_nodes`. The chain comes from `network` (`--network`, `EPLIX_NETWORK`) or `chain_config`, never both. `network` takes `mainnet`, `hoodi` or `sepolia`, whose fork schedule, genesis and deposit contract are built into the binary. `chain_config` is a consensus `config.yaml`, for devnets and other chains. Either way every node's spec must match it. Unknown fields fail the start. A key signs only after it has a slashing record: import one, give it a floor record with `eplix import --no-signing-history` (a new key, or a lost setup), or list the key in `allow_start_without_history` (or `["all"]`), which writes the same floor. No beacon node status starts a key (`docs/runbook.md`, "Keys with no slashing history"). A node whose spec, genesis or slot timing differs from the chain, at start or at the check each epoch, is left out until a restart; the VC stops only when fewer than `attestation_consensus_threshold` nodes with attestation data are left. A `chain_config` file may add `GENESIS_TIME` and `GENESIS_VALIDATORS_ROOT` to pin a devnet's genesis; without them the nodes must agree on it, `attestation_consensus_threshold` of them. The data dir keeps the genesis and slot timing of its first start in `chain-anchor`, and every later start checks them.

## Doppelganger protection

Doppelganger protection holds every key at every start until no beacon node has seen it live for `epochs` epochs after the start epoch, so each start, restart or migration misses 3 to 4 epochs of duties with the default of 2. Nothing about the check is kept in the data dir, so a copied data dir waits too. `"enabled": false` turns the check off. Threshold keys skip the check unless `threshold_keys` is true. A key the beacon node sees live stops Eplix: the error starts with `DOPPELGANGER`, names the key and the epoch, and the process exits with code 1. Stop the other client before you start Eplix again. Eplix asks every beacon node for liveness and counts any "live" answer; `"liveness_from": "best"` asks only the best node. Both sections are optional; without them the metrics endpoint listens on 127.0.0.1:5064 and doppelganger protection is on with these defaults.

## Proposer config file

`proposer_config` (optional) names a file with fee recipients, gas limits and graffiti, as defaults and per key. It uses Teku's layout with those three fields only, all at the top of each entry:

```json
{
  "default_config": { "fee_recipient": "0x6e35733c5af9B61374A128e6F85f553aF09ff89A", "gas_limit": "60000000", "graffiti": "eplix" },
  "proposer_config": {
    "0xa057816155ad77931185101128655c0191bd0214c201ca48ed887f6c4c6adf334070efcd75140eada5ac83a92506dd7a": { "fee_recipient": "0x50155530FCE8a85ec7055A5F8b2bE214B3DaeFd3" }
  }
}
```

For each field of a key, the first value set wins: the file's entry for the key, then the value set through the keymanager API, then the file's `default_config`, then the config's `fee_recipient`, `gas_limit` and `graffiti`. The keymanager API answers 403 to a write for a key the file lists; edit the file instead, and 404 to a read or write for a key the VC does not hold. The API's values live in `<data_dir>/key-settings.json`; at start each must pass the API's own rules, and a file that does not parse or holds a bad value stops the start with the key named. A task of its own checks the file's size and write time 500 ms before each epoch boundary (`proposer_config_lead_ms`, 1 to 600000) and reads and parses the file only when they changed, so a change is in place when the next epoch starts and duties never wait for the file. A check that ends after the boundary applies when it ends; until then duties use the content in place. An invalid file stops the start; at a check it keeps the last good one and logs an error each epoch. Metrics: `eplix_proposer_config_errors_total` (failed reads and parses), `eplix_proposer_config_late_total` (checks that ended after their boundary) and the histogram `eplix_proposer_config_check_duration_seconds`. Unknown fields fail, and so does a Teku `builder` block: the file takes no builder settings. `eplix check` validates the file and prints the number of keys and the defaults.

## Graffiti

The graffiti of a proposal comes from the first of these that is set: the proposer config file's entry for the key, the keymanager API's graffiti for the key, the graffiti file (module, below), the proposer config file's `default_config`, the config's `graffiti`. The keymanager API's GET reports the per-key value or the defaults; it does not show the graffiti file's lines.

### Graffiti file

The graffiti file module reads a file of `name: text` lines, one name per line: `default` for every key, or a 0x public key for one key. Several lines for one name rotate: a proposal at slot s takes line s mod (number of lines), the same after a restart; `"rotation": "random"` picks one at random. A key with no line of its own takes the `default` lines; with neither, the next layer decides. `{{SLOT}}`, `{{EPOCH}}` and `{{VALIDATORINDEX}}` fill in at proposal time; the text around them must fit 32 bytes, and a filled-in text is cut to 32 bytes at a character boundary. Blank lines and lines starting with `#` are skipped. A Lighthouse `--graffiti-file` reads as it is.

```json
"graffiti": { "file": "graffiti.txt", "rotation": "slot" }
```

```text
# graffiti.txt
default: Eplix {{SLOT}}
default: second line of the rotation
0xa057816155ad77931185101128655c0191bd0214c201ca48ed887f6c4c6adf334070efcd75140eada5ac83a92506dd7a: key {{VALIDATORINDEX}}
```

A missing or invalid file stops the start, and `eplix check` validates it. A task of its own checks the file's size and write time 500 ms before each epoch boundary and reads it again only on a change; an invalid file at a check keeps the last good one and logs an error each epoch until it is fixed. Unknown templates and unknown fields fail.

### Client codes

`"graffiti_append"` puts client codes after the graffiti, with a space between them. `"off"` (default) sends the graffiti as written. `"vc"` appends this VC's code (`"graffiti_vc_code"`, two ASCII letters, required when appending; no code is set by default) with 4 hex digits of its commit, and leaves room for a beacon node that appends its own and its execution client's codes (Lighthouse, Teku, Prysm and Grandine do by default). `"all"` appends the execution client's, the beacon node's and the VC's codes, as each node reports them on `/eth/v2/node/version` (else the beacon node's name on `/eth/v1/node/version`, code only), for example `eplix NMc066LHced4EXab12`; turn the node's own appending off then (Teku: `--validators-graffiti-client-append-format=DISABLED`), or the codes come twice. The codes take 4 commit digits each, else 2, else none, else they are left out: the operator's text is never cut for them. Each node gets its own codes. Eplix asks the nodes that build blocks (role `block_data`; without `roles`, every node) for their versions at start and once per epoch, in the background, so a proposal never waits for it. A node that does not answer keeps its last codes and logs one warning until it answers again. A code tells the network which clients run here.

## Signing jitter

`signing` adds a random wait before each signing request, so VCs that share signers do not send at the same instant and the signers queue less. Each request waits a uniformly random 0 to J ms. `jitter_ms` sets J for attestations and sync committee messages (0 to 1,000). `jitter_by_duty_ms` sets it per duty: `attestation`, `sync_committee_message`, `aggregate`, `sync_contribution`, `selection_proof` and `sync_selection_proof` take 0 to 1,000, `registration` 0 to 2,000. Blocks, RANDAO reveals, exits, PTC votes, payload envelopes, proposer preferences and builder request auth never wait. The object goes at the top level, per key under `keys`, or as `signing` in the `local`, `tee`, `dirk` or `web3signer` section; the most specific value wins (key over module over top level; in each, a duty's own value over `jitter_ms`). It is off by default, and the start log names every value set:

```json
"signing": { "jitter_ms": 100, "jitter_by_duty_ms": { "aggregate": 50, "registration": 2000 },
             "keys": { "0x<pubkey>": { "jitter_ms": 0 } } }
```

## Gloas

On a chain that schedules Gloas, the `gloas` section is optional; these are its defaults. `include_payload` asks the node to return the self-built envelope and blobs with the block, so any node can take the publish. `p2p_min_bid` (Gwei) and `p2p_builder_boost_factor` weigh the bids the node received over p2p (0 prefers the local payload, 100 takes whichever pays more). A p2p bid meets `p2p_min_bid` by its value alone: its execution payment is a promise nothing enforces, so it does not count. Proposer preferences carry each key's fee recipient and gas limit (the proposer config file and keymanager settings, else the defaults); a key without a fee recipient sends none.

```json
"gloas": { "include_payload": true, "p2p_min_bid": "0", "p2p_builder_boost_factor": "100", "proposer_preferences": true }
```

## External builders

External builders go in a `builder` section. `auth_data` is what the builder agreed to check (default: the host name of the URL); an empty `builder_pubkeys` accepts any builder; a bid below `min_bid` (value plus execution payment up to `max_execution_payment`) is not signed:

```json
"builder": {
  "builders": [ { "url": "https://builder.example", "builder_pubkeys": [], "max_execution_payment": "1000000000",
                  "min_bid": "10000000", "builder_boost_factor": "100" } ]
}
```

## Obol mode

To run Eplix as a VC in a Charon cluster, point `beacon_nodes` at Charon's validator API and turn on Obol mode. Each Eplix VC signs with its node's key shares (the keystores Charon's DKG wrote, as local keys), and Charon combines the partial signatures:

```json
"obol": { "enabled": true }
```

Without the section, or with `"enabled": false`, the VC decides aggregation from its own selection proofs. When Charon cannot return a combined proof (a failed call, or not enough partials before the request timeout), those keys do not aggregate: the VC asks again each slot for attester duties and counts each duty left without a proof as missed with reason `beacon_node`.
