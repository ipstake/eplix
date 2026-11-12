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
- **Small.** One NativeAOT binary on .NET 10. Speed has targets and measured numbers (`docs/benchmarks.md`).
- **Signers over mutual TLS.** Dirk and TEE signers over mutual TLS, Web3Signer over HTTPS with optional mutual TLS; client certificates reload without a restart. Each connection to a TEE signer checks the signer's remote attestation (AWS Nitro Enclaves, Azure SEV-SNP through MAA, Google Confidential Space) before it carries a request.

The design is in `docs/design.md`: architecture, backends, threshold signing, slashing protection, migration, beacon nodes, Gloas and builders, performance, testing and risks.

## Features

- Duties: attestations, block proposals (produceBlockV3, SSZ body root), RANDAO, aggregation (selection proofs, committee subscriptions, aggregates), sync committee (messages, selection proofs a slot ahead, contributions, one message per validator however many seats), fee recipients, voluntary exits (a command for one, several or all keys, printed or saved one file per key for later; never automatic).
- Gloas (module, needed on a chain that schedules Gloas): payload timeliness committee votes, proposals through produceBlockV4 with the self-built payload envelope signed and published after the block, proposer preferences for the proposals in the lookahead (from the epoch before the fork), the Gloas due times and the progressive attestation and block roots.
- Builder (module): external builders in produceBlockV4's builder config, with a builder request auth signed by the proposer's key an epoch ahead, builder preferences, and a check of a won bid before the block is signed. Without it the VC proposes with self-build and the node's p2p bids.
- Pre-Gloas builder flow (module, off by default, config section `builder_legacy`): validator registrations each epoch and a `builder_boost_factor` per key for MEV-Boost behind the beacon node, blinded blocks, and a local block when the builder request fails. It does nothing from the Gloas fork on.
- Several beacon nodes: attestation data only when a threshold of nodes agrees, duties from the best node with fallback, blocks by value, aggregates by bit count, publishing to every node, and optional roles per node (proposal-only nodes, per-duty publish nodes). Gloas PTC data comes from the best node by default; with `ptc_consensus_threshold` above 1 the VC asks every node until that many return the same data, and votes nothing without agreement. A higher threshold can miss the 75% due time when the nodes see the envelope at different times, so it is opt-in.
- Keys: EIP-2335 keystores in the layouts of deposit-cli, Teku, Lighthouse, Nimbus and Lodestar, decrypted in parallel; keys added and removed while the VC runs; import of keys and their EIP-3076 history. A key the chain shows slashed stops for good, also across restarts.
- Keymanager API (module): keystores, per-key fee recipient, gas limit and graffiti (read-only for keys the proposer config file lists), voluntary exit, bearer token, HTTPS with an optional client certificate check.
- Proposer config file (core): fee recipient, gas limit and graffiti per key and as defaults, in Teku's layout, read again each epoch.
- Graffiti client codes (core, off by default): the VC's own two-letter code, or the execution client's, the beacon node's and the VC's codes with commit digits, appended after the operator's graffiti in the room the 32 bytes leave.
- Graffiti file (module): per-key and default texts with `{{SLOT}}`, `{{EPOCH}}` and `{{VALIDATORINDEX}}` templates and several lines as a rotation; a Lighthouse graffiti file reads as it is.
- Dirk (module): gRPC over mutual TLS to stock Dirk; plain accounts as whole keys, distributed accounts as m of n threshold keys combined in the client (Lagrange interpolation, one verification against the validator key); typed attestation and proposal calls, batched attestations, Dirk's refusals mapped to typed refusals.
- Web3Signer (module): the Eth2 remote signing API over HTTP or HTTPS with optional mutual TLS; whole keys from a signer's key list, and m of n share groups (each endpoint holds one share, Eplix combines); typed bodies for every duty kind, 412 mapped to a slashing refusal, key lists read again every epoch and on a 404.
- TEE signers (module): the runner protocol of the tee-signer project over mutual TLS 1.3, a warm pool of attested connections per runner with two priority classes (attestations, blocks, RANDAO, PTC votes and envelopes first), typed SIGN requests for every duty kind, builder request auth included (the runner signs it only for auth data on its allowlist), the runner's status codes mapped to typed refusals (a slashing refusal halts the key, a floor refusal does not). Eplix needs tee-signer protocol level 2 or higher (`protocol` in HEALTH): such runners answer a refusal at a key's floor with FLOOR or FLOOR_UNPROVEN (status 1008 or 1009), and Eplix reads every slashing code as a conflict and halts the key. A runner that reports a lower level, or none, gets no requests. Each connection checks the runner's attestation first: dev, Azure MAA (SEV-SNP), AWS Nitro or GCP Confidential Space, with the image measurement and setup hash pinned and the TLS key bound to the attested identity; the verifiers are ports of tee-signer's Go verifiers and give their verdicts on 438 synthetic cases (`tests/fixtures/tee/README.md`). Whole keys through one runner, m of n keys through n runners, combined in Eplix.
- Threshold combinator (core): m of n over any backends that return partials, with these straggler rules: a queue per member with two priority classes, stragglers kept for votes and blocks and dropped for the rest, restart floors per member in the group's health, latency per member. The combined signatures of a burst are checked together (one random-linear-combination check per batch); when a combination fails, bad partials are dropped and other sets of m are tried. Tested at 2 of 3, 3 of 5 and 5 of 7.
- Slashing protection: an append-only log with one fsync per burst, snapshots while running, EIP-3076 import and export (also while running). Gloas PTC votes and envelopes get one mark per key and slot in a separate file, `slot-marks.db`: a second, different vote or envelope for a slot at or below the mark is skipped (an exact repeat goes through). These kinds are not slashable on chain, so a refusal never halts a key, a key needs no imported history for them, and the EIP-3076 files do not carry them.
- Eplix's own schema-driven SSZ codec and its JSON form, with the progressive containers and lists of Gloas, checked against consensus-spec-tests v1.6.1 (Fulu) and v1.7.0-beta.4 (Gloas); BLS through `Nethermind.Crypto.Bls`.
- Metrics (module): a Prometheus endpoint with duties done and missed by reason, signing latency per backend and duty kind, slashing DB latency and size, beacon node scores and requests, publish sends per node, topic and result, key states, signer denials, keys retired because their signer no longer lists them, and the runtime's GC, CPU time, memory and thread pool.
- Validator monitor (module): reads each block from the beacon node and matches it to the VC's duties. It counts attestations included, missed or unknown, their inclusion distance, head, target and source votes (from the attestation rewards), proposals, sync committee messages and the change of the balances per epoch. Totals always; series per key behind `per_validator`.
- Doppelganger protection (module): a key starting for the first time in this VC waits until no beacon node's liveness endpoint has seen it for 2 epochs (configurable); a key seen live stops the VC with an error.
- Tracing (module, off unless enabled): OpenTelemetry spans per duty, with the signing bursts, slashing checks, beacon node calls and submits under them, sent to an OTLP/HTTP collector as protobuf by an exporter of its own (no OpenTelemetry package). A span per signing request is opt-in.
- Config from a file, flags and environment variables; logs as text or JSON lines.
- Emergency switches (core): stop all signing, or pause single duty kinds (attestations only, say, to keep proposing), from the config or while running through `eplix switch`, with no restart.
- Obol mode (module, off unless configured): in a Charon cluster, the VC's partial selection proofs go to the middleware through the Beacon API's `beacon_committee_selections` (once per epoch) and `sync_committee_selections` (once per slot); the combined proofs it returns decide aggregation and go into the aggregates and contributions.
- A fuzz campaign over the SSZ, Beacon API, EIP-2335 and EIP-3076 decoders (FsCheck; `EPLIX_FUZZ_CASES` sets the cases).

`ROADMAP.md` lists planned work. `docs/benchmarks.md` has the benchmark results and the commands that reproduce them, `docs/dependencies.md` the reason for each package and `docs/runbook.md` the operator runbook.

## Layout

Code paths use `eplix` in lower case; projects are `Eplix.*` and the binary is `eplix`.

| Path | What |
| --- | --- |
| `src/Eplix.Core` | the core: types, SSZ, BLS, chain spec, Beacon API client and node set, slashing DB, key registry, pipeline, duty scheduler, runner |
| `src/Eplix.Backend.Local` | the local key module: EIP-2335 keystores, client layouts, key reload |
| `src/Eplix.Keymanager` | the keymanager API module (Kestrel) |
| `src/Eplix.Backend.Dirk` | the Dirk module: gRPC client, accounts, threshold groups for distributed accounts |
| `src/Eplix.Backend.Web3Signer` | the Web3Signer module: HTTP client, request bodies, whole keys and share groups |
| `src/Eplix.Backend.Tee` | the TEE signer module: runner protocol, connection pool, attestation verifiers, whole keys and m of n groups |
| `src/Eplix.Gloas` | the Gloas duties module: PTC votes, produceBlockV4 proposals and envelopes, proposer preferences |
| `src/Eplix.Builder` | the builder module: builder config, request auth, builder preferences, bid checks |
| `src/Eplix.Metrics` | the metrics module: Prometheus text endpoint (Kestrel) over the core's instruments |
| `src/Eplix.Doppelganger` | the doppelganger module: liveness checks before a key signs |
| `src/Eplix.Obol` | the Obol module: combined selection proofs from a distributed validator middleware |
| `src/Eplix.Monitor` | the validator monitor module: inclusion, votes, proposals, sync messages and balances of the VC's keys on chain |
| `src/Eplix.Graffiti` | the graffiti file module: per-key and default graffiti with templates and rotation |
| `src/Eplix.Tracing` | the tracing module: an ActivityListener over the core's spans and an OTLP/HTTP exporter |
| `src/Eplix` | the `eplix` binary; links the modules (`-p:EplixLocal=false`, `-p:EplixDirk=false`, `-p:EplixWeb3Signer=false`, `-p:EplixTee=false`, `-p:EplixKeymanager=false`, `-p:EplixGloas=false`, `-p:EplixBuilder=false`, `-p:EplixMetrics=false`, `-p:EplixDoppelganger=false` `-p:EplixObol=false`, `-p:EplixMonitor=false`, `-p:EplixGraffiti=false` and `-p:EplixTracing=false` drop them) |
| `tests/Eplix.Tests` | Expecto and FsCheck tests |
| `benchmarks/Eplix.Bench` | BenchmarkDotNet microbenchmarks of the hot paths |
| `tests/vectors` | spec test vectors (subset), see `tests/vectors/README.md` |
| `tests/fixtures` | recorded Beacon API responses, EIP-2335 keystores, runner wire bytes and attestation verdicts of tee-signer's Go verifiers (`tee/`) |
| `scripts` | AOT publish with the warning check, smoke tests, vector download, fake beacon node, a local Dirk cluster, the TEE runner integration tests |
| `tests/tools/tee-oracle` | the Go program that makes `tests/fixtures/tee/oracle-vectors.json` |

## Build

Needs the .NET 10 SDK (`global.json` pins 10.0.403), `libicu` at run time (EIP-2335 passwords need NFKD) and, for the NativeAOT publish, `clang` and `zlib1g-dev`.

### CPU

The linux-x64 binary needs AVX: Intel Sandy Bridge (2011) or newer, AMD Bulldozer or Jaguar or newer, and every AMD Zen. It does not run on Nehalem, Westmere or older Intel cores, nor on Intel Atom-class cores up to Tremont, which includes the Celeron and Pentium N and J series (N5105, J4125 and the like). On such a CPU it stops at once with:

```
The required instruction sets are not supported by the current CPU.
```

`grep -m1 -o -w avx /proc/cpuinfo` prints `avx` on a CPU that can run it. AVX2 is optional: with it, SSZ hashing (block and envelope roots) uses 8 lanes instead of 4. Version 0.1.0 builds linux-x64 only; a linux-arm64 build is planned. To build for an older x64 CPU anyway, publish with `-p:IlcInstructionSet=x86-64-v2` (unsupported; the block root takes about 1.3 ms longer).

```sh
dotnet build -m:2
scripts/fetch-test-vectors.sh      # EIP-3076 interchange tests, not in the repo; the tests fail without them
dotnet test -m:2
scripts/publish-aot.sh             # artifacts/publish/linux-x64/eplix and libblst.so
scripts/smoke-aot.sh               # the published binary decrypts the EIP-2335 vectors
scripts/smoke-gloas.sh             # the published binary attests across the Gloas fork and casts PTC votes
scripts/smoke-metrics.sh           # the published binary waits out the doppelganger check, attests, serves /metrics
scripts/smoke-two-instances.sh     # a second binary on the same data dir exits with the lock error
scripts/smoke-crash.sh [rounds]    # kill -9 while signing (64 keys, 200 rounds): no mark lost, no double vote
scripts/interchange-out.sh         # an Eplix slashing export imports into Lighthouse, Teku, Nimbus, Lodestar and Prysm
scripts/ci.sh                      # everything above plus the integration tests, each step with a time limit
scripts/nightly.sh [ssz] [fuzz] [flaky]   # every spec vector, 100,000 fuzz cases with a logged seed, 30 repeats of the timing-heavy lists
scripts/fuzz-week.sh --round       # one of the 7 nightly fuzz rounds (cron), or --now for all 7
scripts/soak.sh [seconds]          # 1,000 keys for 24 h: memory and descriptors flat, no duty missed
scripts/startup-keys.sh <keys>     # start-up time and memory at a key count
scripts/mutants.sh                 # about 30 hand-written mutants of the slashing, signing and duty checks must each fail a test
EPLIX_FUZZ_CASES=100000 dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --filter-test-list fuzz   # a longer fuzz run, about 20 min
dotnet run -c Release --project benchmarks/Eplix.Bench -- --filter '*'
scripts/dirk-local.sh setup ~/dirk-net   # three local Dirk instances, 2 of 3 accounts, test keys only
scripts/dirk-it.sh ~/dirk-net            # integration tests against them
scripts/smoke-dirk.sh ~/dirk-net         # the published binary attests through them, also with one down
scripts/web3signer-it.sh ~/tools/web3signer-26.10.1/bin/web3signer   # four local Web3Signer instances: whole keys over mutual TLS, 2 of 3 shares
scripts/web3signer-pg-it.sh ~/w3s-pg   # one Web3Signer with its slashing protection on PostgreSQL: a 412 halts the key (W3S, JAVA_HOME, PG_BIN set)
scripts/gateway-smoke.sh ~/dirk-net <gateway binary>                 # a Web3Signer-compatible gateway in front of the Dirk cluster
scripts/tee-it.sh <runner-dev-debugimport>   # five local dev-platform TEE runners; with the published binary also its smoke test
scripts/charon-it.sh ~/charon-net        # Obol mode: four VCs against a local 4-node Charon cluster (threshold 3) on its beacon mock
```

Run:

```sh
eplix run --config eplix.json
eplix check --config eplix.json          # config, pinned chain config and keystores, offline
eplix import --config eplix.json --from ~/.lighthouse/hoodi --slashing-protection lighthouse-interchange.json
eplix exit --config eplix.json --pubkey 0x... [--submit true]
eplix exit --config eplix.json --all --save-dir exits    # presigned: exits/<0xpubkey>.json, mode 0600, not submitted
eplix switch stop --config eplix.json      # next to a running VC: stop signing within a second
eplix slashing import --config eplix.json --file interchange.json
eplix slashing export --config eplix.json --file out.json
```

`import`, `exit` and `slashing` take the data dir lock, so they run while the VC is stopped; a running VC offers the same through the keymanager API. The VC, these commands and `switch` create a missing data dir with mode 0700. The VC and these commands also set 0700 on one that lets the group or others in, with one info line that names the old mode, and fail when they cannot. `slashing export` takes `--pubkey` to export only some keys; a key that does not parse or has no record stops the export with an error, and the file is written whole or not at all.

`exit` takes `--pubkey` more than once or as a comma-separated list, or `--all` for every key the VC holds (keys with no validator index, slashed or already exiting are skipped and listed). `--epoch` sets the exit epoch (default: the current one). Without `--save-dir` each signed exit is printed as a line of JSON; with it each goes to `<dir>/<0xpubkey>.json` (mode 0600, the directory made with mode 0700), written whole or not at all. The files hold the Beacon API's `SignedVoluntaryExit`, so `curl -X POST -H 'Content-Type: application/json' -d @<file> <node>/eth/v1/beacon/pool/voluntary_exits` submits one later. Since Deneb an exit is signed with the Capella fork version (EIP-7044) and stays valid for good: keep the files as safe as the keys. A key that fails makes the command exit with code 1; the others are still signed and saved.

Emergency switches stop signing without a restart. `"stop_signing": true` stops every duty kind except voluntary exits; `"paused_duties": ["attestation", "sync_committee_message"]` stops the kinds named (the duty labels of the metrics: `attestation`, `block`, `randao_reveal`, `aggregation_slot`, `aggregate_and_proof`, `sync_committee_message`, `sync_selection_proof`, `contribution_and_proof`, `voluntary_exit`, `payload_attestation`, `payload_envelope`, `proposer_preferences`, `builder_request_auth`). Both keys go in the config file, a flag (`--stop-signing true`) or the environment (`EPLIX_PAUSED_DUTIES=attestation,block`), and in `<data_dir>/switches.json`, which the VC reads once a second while it runs. `eplix switch stop`, `resume`, `pause <duty>...`, `resume-duty <duty>...` and `status` edit that file. A switch is on when the config or the file turns it on, so `resume` lifts only what the file set. Stopped duties are not signed and count in `eplix_duties_missed_total` with reason `paused`; nothing is written to the slashing DB for them and no key is halted. Each change is logged once as a warning. A `switches.json` that does not parse fails the start and, while running, keeps the switches in place with an error. Lighthouse's `--disable-attesting` is `paused_duties` with `attestation`, `aggregation_slot`, `aggregate_and_proof`, `sync_committee_message`, `sync_selection_proof` and `contribution_and_proof`.

Any config key can come from a flag or an environment variable. A flag wins over the environment, the environment over the file, and unknown keys fail from every source:

```sh
eplix run --config eplix.json --fee-recipient 0x... --log-format json
eplix run --beacon-nodes http://a:5052,http://b:5052 --chain-config config.yaml --data-dir data --modules.metrics.port 5065
EPLIX_CONFIG=eplix.json EPLIX_GRAFFITI=eplix EPLIX_MODULES__METRICS__ADDRESS=0.0.0.0 eplix run
```

Dots separate levels in a flag, `__` in a variable. `true`, `false`, `null` and values that start with `[` or `{` are JSON, anything else is a string. Without `--config` and `EPLIX_CONFIG` there is no file. `"log_format": "json"` writes each log line as `{"time": .., "level": .., "msg": ..}`.

A key that the chain shows slashed (confirmed by `attestation_consensus_threshold` nodes, or by every node that answers) stops for good: it signs nothing, Eplix logs an error and counts it in `eplix_slashed_on_chain_total`, and `<data_dir>/slashed-keys.json` keeps the stop across restarts. Remove the key's entry from that file, with the VC stopped, only once you know why it was slashed.

A config file (every key can also come from a flag or an environment variable, see below):

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

The keymanager API listens on 127.0.0.1:5062 over plain HTTP unless told otherwise. `tls_cert` (PEM: the certificate, then its intermediates) and `tls_key` (PEM) switch it to HTTPS, and the intermediates go out in the handshake. `client_ca` (PEM or DER, one or more CA certificates) also requires a client certificate that chains to one of them, through the intermediates the client sends or the ones listed in the file. An address that is not a loopback address needs TLS, or `"allow_plain_http": true`, since the bearer token would cross the network in clear text. `eplix check` loads the files and prints the certificate's subject and end date:

```json
"keymanager": { "address": "0.0.0.0", "port": 5062, "tls_cert": "km-cert.pem", "tls_key": "km-key.pem", "client_ca": "ops-ca.pem" }
```

The bearer token lives in `token_file` (default `<data_dir>/api-token.txt`); when the file is missing Eplix writes a random token there with mode 0600. A token file that the group or others can read or write, or an empty one, stops the start. One import request takes at most 1,000 keystores. `max_import_bytes` caps the body of a keystore import (default 268435456, 256 MiB; 1 MiB to 16 GiB). Eplix reads the import as a stream and keeps only the highest block and attestation per key from its `slashing_protection` history, so the cap bounds how long one request reads, not memory. A larger body gets 413: split the import, or minimise the interchange first. `max_import_keys` caps the distinct keys in that history (default 100,000; 1,000 to 1,000,000); more also get 413 and import nothing. `eplix slashing import` takes at most 100,000 keys per file.

The metrics endpoint is `GET /metrics` in the Prometheus text format, plain HTTP with no token: keep it on loopback or a private network. Doppelganger protection holds every key at every start until no beacon node has seen it live for `epochs` epochs after the start epoch, so each start, restart or migration misses 3 to 4 epochs of duties with the default of 2. Nothing about the check is kept in the data dir, so a copied data dir waits too. `"enabled": false` turns the check off. Threshold keys skip the check unless `threshold_keys` is true. A key the beacon node sees live stops Eplix: the error starts with `DOPPELGANGER`, names the key and the epoch, and the process exits with code 1. Stop the other client before you start Eplix again. Eplix asks every beacon node for liveness and counts any "live" answer; `"liveness_from": "best"` asks only the best node. Both sections are optional; without them the metrics endpoint listens on 127.0.0.1:5064 and doppelganger protection is on with these defaults.

Tracing is off until `modules.tracing.enabled` is true. Then every duty with work in a slot (attestations, aggregates, sync committee messages, contributions, a proposal, selection proofs) is the root span of a trace, with the signing burst, the slashing check, each beacon node request and the submit to the nodes under it. Spans go in batches to an OTLP/HTTP collector (the OpenTelemetry Collector, Jaeger, Tempo) as binary protobuf. `sample_ratio` keeps that share of traces, decided by trace id. `sign_spans` adds a span per signing request, 1,250 per slot at 10,000 keys, so it is off by default. A full queue drops spans and a collector that is down costs a warning; neither delays a duty. `eplix_tracing_spans_exported_total` and `eplix_tracing_spans_dropped_total{reason}` count them. Off, the core's spans cost one check each and the module adds no thread:

```json
"tracing": { "enabled": true, "endpoint": "http://127.0.0.1:4318/v1/traces", "sample_ratio": 1.0, "sign_spans": false,
             "service_name": "eplix", "headers": { "Authorization": "Basic ..." },
             "queue_size": 4096, "batch_size": 512, "flush_interval_ms": 2000, "timeout_ms": 5000 }
```

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

The graffiti of a proposal comes from the first of these that is set: the proposer config file's entry for the key, the keymanager API's graffiti for the key, the graffiti file (module, below), the proposer config file's `default_config`, the config's `graffiti`. The keymanager API's GET reports the per-key value or the defaults; it does not show the graffiti file's lines.

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

`"graffiti_append"` puts client codes after the graffiti, with a space between them. `"off"` (default) sends the graffiti as written. `"vc"` appends this VC's code (`"graffiti_vc_code"`, two ASCII letters, required when appending; no code is set by default) with 4 hex digits of its commit, and leaves room for a beacon node that appends its own and its execution client's codes (Lighthouse, Teku, Prysm and Grandine do by default). `"all"` appends the execution client's, the beacon node's and the VC's codes, as each node reports them on `/eth/v2/node/version` (else the beacon node's name on `/eth/v1/node/version`, code only), for example `eplix NMc066LHced4EXab12`; turn the node's own appending off then (Teku: `--validators-graffiti-client-append-format=DISABLED`), or the codes come twice. The codes take 4 commit digits each, else 2, else none, else they are left out: the operator's text is never cut for them. Each node gets its own codes. Eplix asks the nodes that build blocks (role `block_data`; without `roles`, every node) for their versions at start and once per epoch, in the background, so a proposal never waits for it. A node that does not answer keeps its last codes and logs one warning until it answers again. A code tells the network which clients run here.

The validator monitor is on by default and costs one block read per slot (only while a key waits for something on chain), at most one committee read per slot, and two calls per epoch (attestation rewards, balances). It does nothing without the metrics module. Its series:

- `eplix_monitor_attestations_total{outcome}`: attestation duties `included`, `missed` (no block took them by the end of the next epoch) or `unknown` (a block in that window could not be read).
- `eplix_monitor_inclusion_distance_slots`: a histogram of the slots between the attestation and the block that took it (1 is the best).
- `eplix_monitor_votes_total{vote,correct}`: `head`, `target` and `source` of included attestations; `correct="true"` when the vote earned its flag in the attestation rewards (correct and in time). Head is not counted in an inactivity leak.
- `eplix_monitor_proposals_total{outcome}` and `eplix_monitor_sync_messages_total{outcome}`: proposals in the canonical chain or missed, sync committee messages in the next block or missed.
- `eplix_monitor_balance_change_gwei`: the change of the summed balances of the active keys over the last epoch (rewards, penalties and withdrawals).
- `eplix_monitor_errors_total{call,reason}`: reads that failed (`request`) or came in a format the monitor does not know (`format`).

`"per_validator": true` adds the same per key, with a `key` label: `eplix_monitor_validator_attestations_total`, `eplix_monitor_validator_inclusion_distance_slots` (the last one), `eplix_monitor_validator_votes_total`, `eplix_monitor_validator_proposals_total`, `eplix_monitor_validator_sync_messages_total`, `eplix_monitor_validator_balance_gwei` and `eplix_monitor_validator_balance_change_gwei`. Leave it off for thousands of keys: each key adds up to 17 series.

The metrics module also exports the runtime's meters: `eplix_gc_collections_total{generation}`, `eplix_gc_heap_bytes`, `eplix_gc_allocated_bytes_total`, `eplix_gc_pause_seconds_total`, `eplix_process_cpu_seconds_total{mode}`, `eplix_process_working_set_bytes`, `eplix_threadpool_threads`, `eplix_threadpool_queue_length` and `eplix_threadpool_completed_items_total`.

Keys in Dirk go in a `dirk` section. Each endpoint lists the accounts under `accounts`; a distributed account brings its participants and threshold, so name the endpoints as the participants name themselves. An endpoint's distributed account that names no participant at that endpoint's own address is ignored there, with a warning:

```json
"dirk": {
  "endpoints": [ "dirk1:13141", "dirk2:13141", "dirk3:13141" ],
  "accounts": [ "Validators" ],
  "ca_cert": "certs/ca.crt", "client_cert": "certs/eplix.crt", "client_key": "certs/eplix.key",
  "timeout_ms": 2000,
  "gloas_calls": "auto"
}
```

`gloas_calls` sets how PTC votes, payload envelopes, proposer preferences and builder request auth go to Dirk. `"auto"` (the default) uses typed calls for these kinds, which a Dirk build with Gloas calls offers; an instance that answers UNIMPLEMENTED (stock Dirk) gets those kinds as root and domain through the generic `Sign` from then on. `"typed"` uses the typed calls only, so stock Dirk fails those kinds. `"generic"` always sends root and domain, for stock Dirk; a build with the typed calls denies them unless its `server.rules.generic-gloas-clients` names this client.

Keys in Web3Signer go in a `web3signer` section. A signer holds whole keys; a group is m of n signers that each hold one share of the listed keys (as in a Charon cluster), with the share key per member index. Eplix checks at start that every share of each key lies on one split of it, and names a member whose share does not:

```json
"web3signer": {
  "signers": [ { "url": "https://w3s:9000", "ca_cert": "certs/ca.crt", "client_cert": "certs/eplix.crt", "client_key": "certs/eplix.key" } ],
  "groups": [ { "threshold": 2,
                "members": [ { "index": 1, "url": "https://w3s-1:9000" }, { "index": 2, "url": "https://w3s-2:9000" }, { "index": 3, "url": "https://w3s-3:9000" } ],
                "keys_file": "shares.json" } ],
  "timeout_ms": 2000
}
```

`shares.json` (or `keys` inline) is a list of `{ "pubkey": "0x..", "shares": { "1": "0x..", "2": "0x..", "3": "0x.." } }`.

A Web3Signer endpoint that runs in a TEE can be attested before it gets a request: add `"attestation"` to the signer or member. `{ "source": "pinned", "tls_key_pin": "<sha256 of the server's SubjectPublicKeyInfo>" }` trusts that key; `{ "source": "runner", "runner": { ... } }` takes a runner entry as in the `tee` section and checks the signer's IDENTITY over its runner port (attestation, setup and key release pins), then trusts the TLS key it names. The check repeats every `refresh_interval_seconds` (default 384) and right after the server shows a key the evidence does not cover. Until an endpoint is attested it counts as down and gets no request; a share group signs from its other members. Eplix keeps one endpoint per URL. A URL listed more than once, in `signers` or as a group member, must have the same `ca_cert`, `client_cert`, `client_key` and `attestation` in every entry, or the start fails.

On mainnet every signer and group member URL must be `https`: an `http` URL fails the start, and the keymanager API refuses one at import. A key that `remote-keys.json` saved earlier with an `http` URL does not sign on mainnet. It stays in the file and in the API's list, with an error in the log at start, until DELETE removes it. Eplix checks every whole-key signature that Web3Signer or Dirk returns against the key before it uses it; one that does not verify fails the duty and logs an error.

TEE signers that speak the tee-signer runner protocol go in a `tee` section. Each runner names its address, the client certificate it accepts and how to check its attestation, with the field names of tee-signer's own client config. A key a runner holds whole signs through it alone; the shares of a key held by the members of a group sign m of n:

```json
"tee": {
  "runners": [
    { "name": "signer-1", "address": "tcp:192.0.2.1:7100", "client_cert": "certs/eplix.crt", "client_key": "certs/eplix.key",
      "attestation": { "verifier": "azure-maa", "maa_host": "sharedweu.weu.attest.azure.net", "cce_policy_sha256": "..", "setup_sha256": "..", "key_release_sha256": ".." } },
    { "name": "signer-2", "address": "tcp:192.0.2.2:7100", "client_cert": "certs/eplix.crt", "client_key": "certs/eplix.key",
      "attestation": { "verifier": "aws-nitro", "nitro_pcrs": { "0": "..", "1": "..", "2": ".." }, "setup_sha256": "..", "key_release_sha256": ".." } },
    { "name": "signer-3", "address": "tcp:192.0.2.3:7100", "client_cert": "certs/eplix.crt", "client_key": "certs/eplix.key",
      "attestation": { "verifier": "gcp-cs", "gcp_image_digest": "sha256:..", "gcp_audience": "signer-runner-identity", "gcp_hwmodels": [ "GCP_INTEL_TDX" ], "setup_sha256": ".." } } ],
  "groups": [ { "threshold": 2, "members": [ { "runner": "signer-1", "index": 1 }, { "runner": "signer-2", "index": 2 }, { "runner": "signer-3", "index": 3 } ] } ],
  "keys_file": "tee-keys.txt",
  "attestation_ca_file": "certs/ca-bundle.pem",
  "timeout_ms": 2000
}
```

A group's `threshold` must be more than half its members (2 of 3, 3 of 4, 3 of 5): with half or fewer, two sets of members with no member in common could each sign a different message, and every member's slashing protection would allow it. Such a config fails the start, in the `tee` and `web3signer` sections; a Dirk distributed account at such a threshold is left out with an error. Eplix also checks at start and at every key list that each member's share key lies on one split of the key. A key whose shares do not, or a key that one signer or keystore holds whole while a group holds it split, signs on no route until a restart, whichever modules list the two and in whichever order: an error names the key and the cause, and `eplix_keys_refused` counts it (alert `EplixKeyRefused`).

`keys` (a list) and `keys_file` (one key per line, `#` comments) name the validator keys Eplix signs for through the runners; at least one is required, because a runner may hold other clients' keys too, and keys the runners list beyond these are not used. Each pin of `attestation` (`cce_policy_sha256`, `gcp_image_digest`, `nitro_pcrs`) also takes a list (for `nitro_pcrs` a list of PCR maps), so the old and the new image both pass during an image swap. `setup_sha256` and `key_release_sha256` take a list too, for a setup or key release policy rotation. `azure-maa`, `aws-nitro` and `gcp-cs` need `setup_sha256`: without it every runner fails the setup check, so the config check refuses it.

`key_release_sha256` pins the `key_release_hash` a runner reports in its IDENTITY, the hash of the policy under which its cloud releases the key (Azure secure key release, AWS KMS). On mainnet (`network` mainnet, or a `chain_config` named mainnet or with mainnet's genesis fork version) an `azure-maa` or `aws-nitro` runner needs it, and the start fails without it. On other networks it is optional: unset, any hash passes. `gcp-cs` runners report no key release hash, so the field is refused there. This is the rule of the signers' own client. A runner whose hash is not in the list fails the dial, and the error names both. `eplix check` prints each runner's setup and key release pins.

On mainnet the start fails when a runner, or the `runner` source of a Web3Signer endpoint, has `"verifier": "dev"` (it checks no platform evidence) or `"allow_testnet_build": true`. Both are for test networks.

Dirk, Web3Signer and the TEE runners are asked for their key lists at start and every `refresh_interval_seconds` (default 384, 0 turns the refresh off, at most 86,400). A key that every signer holding it answers without, two polls in a row, stops getting duties and is removed once its signatures in flight finish. A signer that is down, fails or answers an empty list never causes that. Web3Signer share group keys and keys added through the keymanager API are not retired this way. A retired key that is listed again passes the history check before it signs.

Each runner keeps `connections` (default 8) attested connections open; `priority_low_every` (default 8) sets how often a free connection goes to sync and aggregation work while attestations wait.

`client_cert` holds the client certificate first, then the intermediate CAs up to the root, in PEM. All of them go to the runner in the TLS handshake, so a runner that trusts only the root accepts a certificate from an intermediate CA. The Azure MAA and Confidential Space verifiers fetch their issuers' key sets over HTTPS, trusting the system store; `attestation_ca_file` (a PEM bundle, at the `tee` level) makes them trust only its CAs instead, for a host or image without a system store.

Certificates rotate without a restart. The TEE, Web3Signer, Dirk and keymanager modules read their certificate, key and CA files every `reload_interval_seconds` (default 10, 0 turns it off) and load a changed set when it is valid; a set that does not load (a key that does not match, an expired certificate) keeps the old one in use and logs an error. After a new client certificate, each runner's connections are redialed one at a time within `rotate_within_seconds` (default 300, `tee` level) and before the old certificate expires, so the pool stays full. The TEE module also reads its files soon after a change to one of them (a write in place, or a new file renamed over the old one, as certificate agents do; a burst of changes is read once the directory has been quiet for 0.5 s) and at once on SIGHUP. A file reached through a symlinked directory that is swapped as a whole (a `..data` link) raises no change event for its name; the poll reads it. A half-written or mismatched pair, or a file cut short in its last certificate, keeps the old one, logs an error and counts in `eplix_tls_cert_reloads{result="error"}`; the next change is read again. With `reload_interval_seconds` 0 none of this runs. SIGHUP never stops the VC, so it keeps running when its terminal hangs up; with no reload running it logs `SIGHUP: no certificate reload configured`. Web3Signer and Dirk test a connection with the new certificate, then move new requests to it. `eplix_tls_cert_not_after_seconds{use,name}` shows when each certificate in use expires; alert on it.

Eplix reads each runner's HEALTH at every new connection and each epoch, in the background. A runner that says it refuses to sign (`ready` false, a request panic, an image check state of not_allowed, restart_needed or unknown), or that it no longer serves its keys (its mark log is lost), gets no signing requests until HEALTH says it signs again; a group signs from its other members. Before its first HEALTH answer, and after each new connection while it signs, a runner is `pending` and gets no signing requests; the first request asks HEALTH and waits up to 5 s for the answer. A failed HEALTH call keeps the last state for the rest of the epoch; after that the state is unknown and requests go again, but only if the last answer showed protocol level 2 or higher. A `pending` or `protocol_too_old` runner stays in that state while HEALTH fails. A runner below tee-signer protocol level 2, or one that sends no `protocol` in HEALTH, is in state `protocol_too_old`: it gets no signing requests, and Eplix logs one error for it that names its level. A runner above level 2 stays in use, with one warning, since some of its answers may mean something this Eplix does not read. `eplix_signer_state{signer,state}` gives each runner's state, and `eplix_signer_mark_log_lost_total{signer}` counts each time a runner's HEALTH turns to `log_lost`.

Two VCs can sign the same keys through the same runners as an HA pair: set `"ha_peer": true` in the `tee` section of both. A runner signs each duty once, so the VC that asks second gets an "already signed" refusal (`SC_ERR_SLASH_TARGET`, `SC_ERR_SLASH_SOURCE`, `SC_ERR_SLASH_BLOCK` or `SC_ERR_EQUIVOCATION`). With `ha_peer` that VC skips the duty and keeps the key; it logs the loss at Info and counts it in `eplix_ha_peer_lost_total{duty}` and in `eplix_duties_missed_total` with reason `lost_to_peer`, which the shipped alerts leave out. Every other slashing refusal still halts the key, and without `ha_peer` the four above halt it too. Every key must then sign through the `tee` module: a `local`, `dirk` or `web3signer` section fails the config check, a keystore in `<data_dir>/keystores` or a remote key in `<data_dir>/remote-keys.json` fails the start, and the keymanager API refuses to import keystores or remote keys. The runbook's "HA pairs" section says how to watch a pair.

`signing` adds a random wait before each signing request, so VCs that share signers do not send at the same instant and the signers queue less. Each request waits a uniformly random 0 to J ms. `jitter_ms` sets J for attestations and sync committee messages (0 to 1,000). `jitter_by_duty_ms` sets it per duty: `attestation`, `sync_committee_message`, `aggregate`, `sync_contribution`, `selection_proof` and `sync_selection_proof` take 0 to 1,000, `registration` 0 to 2,000. Blocks, RANDAO reveals, exits, PTC votes, payload envelopes, proposer preferences and builder request auth never wait. The object goes at the top level, per key under `keys`, or as `signing` in the `local`, `tee`, `dirk` or `web3signer` section; the most specific value wins (key over module over top level; in each, a duty's own value over `jitter_ms`). It is off by default, and the start log names every value set:

```json
"signing": { "jitter_ms": 100, "jitter_by_duty_ms": { "aggregate": 50, "registration": 2000 },
             "keys": { "0x<pubkey>": { "jitter_ms": 0 } } }
```

On a chain that schedules Gloas, the `gloas` section is optional; these are its defaults. `include_payload` asks the node to return the self-built envelope and blobs with the block, so any node can take the publish. `p2p_min_bid` (Gwei) and `p2p_builder_boost_factor` weigh the bids the node received over p2p (0 prefers the local payload, 100 takes whichever pays more). A p2p bid meets `p2p_min_bid` by its value alone: its execution payment is a promise nothing enforces, so it does not count. Proposer preferences carry each key's fee recipient and gas limit (the proposer config file and keymanager settings, else the defaults); a key without a fee recipient sends none.

```json
"gloas": { "include_payload": true, "p2p_min_bid": "0", "p2p_builder_boost_factor": "100", "proposer_preferences": true }
```

External builders go in a `builder` section. `auth_data` is what the builder agreed to check (default: the host name of the URL); an empty `builder_pubkeys` accepts any builder; a bid below `min_bid` (value plus execution payment up to `max_execution_payment`) is not signed:

```json
"builder": {
  "builders": [ { "url": "https://builder.example", "builder_pubkeys": [], "max_execution_payment": "1000000000",
                  "min_bid": "10000000", "builder_boost_factor": "100" } ]
}
```

To run Eplix as a VC in a Charon cluster, point `beacon_nodes` at Charon's validator API and turn on Obol mode. Each Eplix VC signs with its node's key shares (the keystores Charon's DKG wrote, as local keys), and Charon combines the partial signatures:

```json
"obol": { "enabled": true }
```

Without the section, or with `"enabled": false`, the VC decides aggregation from its own selection proofs. When Charon cannot return a combined proof (a failed call, or not enough partials before the request timeout), those keys do not aggregate: the VC asks again each slot for attester duties and counts each duty left without a proof as missed with reason `beacon_node`.

A beacon node entry is a URL or an object. `ca_cert` names the only CA trusted for that node's HTTPS certificate; `headers` and `headers_file` (one `Name: value` per line) go with every request to it, for an API key or basic auth. Header values never appear in logs or metrics; keep them in `headers_file` or the environment, not on the command line:

```json
"beacon_nodes": [ "http://127.0.0.1:5052",
                  { "url": "https://bn.example:5052", "ca_cert": "certs/bn-ca.pem", "headers_file": "bn.headers" } ]
```

A node object may also name the node's `roles`. Without `roles` a node does everything, as before. With roles, each call goes only to the nodes that hold its role, so a set of proposal-only nodes never learns which keys attest through the others, and the attestation nodes never see a block request:

```json
"beacon_nodes": [ { "url": "http://192.0.2.1:5052", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                  { "url": "http://192.0.2.2:5052", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                  { "url": "http://192.0.2.9:5052", "roles": [ "block" ] } ]
```

| Role | What the node is asked or sent |
| --- | --- |
| `duties` | attester, proposer, sync and PTC duties; validator states (key refresh, the slashed check); doppelganger liveness; the monitor's reads |
| `attestation_data` | attestation data and Gloas PTC data; both consensus thresholds count these nodes |
| `attestation_publish` | attestations and PTC votes, beacon committee subscriptions |
| `aggregate_data` | aggregates to sign, beacon committee subscriptions, Obol attester selections |
| `aggregate_publish` | signed aggregates |
| `sync_data` | the block root for sync messages, contributions to sign, sync subscriptions, Obol sync selections |
| `sync_publish` | sync committee messages and contributions, sync subscriptions |
| `block_data` | block production, `prepare_beacon_proposer`, the envelope of a stateful Gloas block |
| `block_publish` | blocks, envelopes, Gloas proposer and builder preferences |

Groups: `attestation`, `aggregate`, `sync` and `block` (each the data and publish role), `publish` (the four publish roles) and `all`. A comma-separated string works too (`"roles": "block"`), as flags and environment variables give it. Every role needs at least one node, and `attestation_consensus_threshold` and `ptc_consensus_threshold` count only the nodes with `attestation_data` (default: a majority of those); the start and `eplix check` refuse a config that breaks either rule. A call never falls back to a node without its role: when every block node is down, the proposal is missed. Every node, whatever its roles, still gets the start checks, the chain spec check each epoch, the syncing check and voluntary exits. Event streams run on the nodes with `duties`, `attestation_data`, `aggregate_data` or `sync_data`.

`broadcast` sets how the VC publishes when it has several nodes. By default (`true`, or `"all"`) each message goes to every node with its role at once, and the duty counts as done when the first node accepts it; the sends to the other nodes run on in the background until they answer or reach `request_timeout_ms`, so a slow or hanging node does not hold up the duty. With `false`, subscriptions and preparations still go to every node, and every other message goes to the best node only (synced first, then by score), then to the next one when it fails or times out. With `"none"` (or `[]`) every message goes to one node at a time. A list or a comma-separated string picks topics to broadcast, the rest go to the best node: `attestations` (with PTC votes), `aggregates`, `sync_committee`, `blocks` (with envelopes), `subscriptions`, `preparations` (`prepare_beacon_proposer`, Gloas proposer and builder preferences) and `exits`:

```json
"broadcast": [ "attestations", "blocks" ]
```

`eplix_beacon_node_submissions_total{node,topic,result}` counts every publish send when it ends, whether broadcast or one node at a time, and the background sends that end after the duty is done: `accepted`, `failed`, or `skipped` (the node already had 16 sends running and got none). `topic` is one of the names above.

`beacon_node` (one URL) can stand in for `beacon_nodes`. The chain comes from `network` (`--network`, `EPLIX_NETWORK`) or `chain_config`, never both. `network` takes `mainnet`, `hoodi` or `sepolia`, whose fork schedule, genesis and deposit contract are built into the binary. `chain_config` is a consensus `config.yaml`, for devnets and other chains. Either way every node's spec must match it. Unknown fields fail the start. A key signs only after it has a slashing record: import one, give it a floor record with `eplix import --no-signing-history` (a new key, or a lost setup), or list the key in `allow_start_without_history` (or `["all"]`), which writes the same floor. No beacon node status starts a key (`docs/runbook.md`, "Keys with no slashing history"). A node whose spec, genesis or slot timing differs from the chain, at start or at the check each epoch, is left out until a restart; the VC stops only when fewer than `attestation_consensus_threshold` nodes with attestation data are left. A `chain_config` file may add `GENESIS_TIME` and `GENESIS_VALIDATORS_ROOT` to pin a devnet's genesis; without them the nodes must agree on it, `attestation_consensus_threshold` of them. The data dir keeps the genesis and slot timing of its first start in `chain-anchor`, and every later start checks them.

## Network presets

`network` picks a built-in chain config (`src/Eplix.Core/Networks.fs`). Before each release, and as soon as a fork is scheduled on a built-in network:

- Refresh `tests/fixtures/networks/` from the sources `Networks.fs` names and run `dotnet test`. The preset tests fail while a built-in config lags its published one.
- For each fork: its `*_FORK_VERSION` and `*_FORK_EPOCH` in `Networks.fs` for every network that schedules it, the values in `NetworksTests.fs`, and a duties module for the fork linked in the build.

## Migrating keys

`eplix import --from <dir>` detects the layout or takes `--layout`:

| Client | Point `--from` at | Passwords |
| --- | --- | --- |
| staking-deposit-cli, ethstaker-deposit-cli | `validator_keys/` | `--password-file` |
| Teku | the `--validator-keys` key directory | `<name>.txt` next to each key, or `--password-file <password dir>` |
| Lighthouse | the network data dir (holds `validators/` and `secrets/`) | `secrets/<0xpubkey>` or `validator_definitions.yml` |
| Nimbus | the data dir (holds `validators/` and `secrets/`) | `secrets/<0xpubkey>` |
| Lodestar | the dir that holds `keystores/` and `secrets/` | `secrets/<0xpubkey>` |
| Prysm | `validator accounts backup --wallet-dir=W --wallet-password-file=F --backup-dir=B --backup-password-file=P --backup-public-keys=0x...`, unzip `B/backup.zip`, then `--layout plain --password-file P` | the backup password |

Export the old client's slashing history as EIP-3076 (`lighthouse account validator slashing-protection export`, `teku slashing-protection export`, `nimbus_beacon_node slashingdb export`, `lodestar validator slashing-protection export`, `validator slashing-protection-history export` for Prysm). `tests/fixtures/layouts/README.md` has the exact commands each client was run with and pass it with `--slashing-protection`. Stop the old client first, and keep it stopped. On its first start in Eplix each key waits for the doppelganger check (2 to 3 epochs with the defaults) before it signs. With no history at all (a new key, or keys made again after a disk loss), pass `--no-signing-history` instead: each key gets a floor record at the epoch now + 1, and a key a beacon node shows as possibly having signed needs a `y` on the terminal. A beacon node head more than one epoch past the system clock stops the import with an error and writes no floor: check the clock and the nodes first (`docs/runbook.md`).

## Licence

Apache-2.0, see `LICENSE`. `THIRD_PARTY.md` lists the test data and code that come from other projects.
