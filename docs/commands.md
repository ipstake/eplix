# Commands

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

## Voluntary exits

`exit` takes `--pubkey` more than once or as a comma-separated list, or `--all` for every key the VC holds (keys with no validator index, slashed or already exiting are skipped and listed). `--epoch` sets the exit epoch (default: the current one). Without `--save-dir` each signed exit is printed as a line of JSON; with it each goes to `<dir>/<0xpubkey>.json` (mode 0600, the directory made with mode 0700), written whole or not at all. The files hold the Beacon API's `SignedVoluntaryExit`, so `curl -X POST -H 'Content-Type: application/json' -d @<file> <node>/eth/v1/beacon/pool/voluntary_exits` submits one later. Since Deneb an exit is signed with the Capella fork version (EIP-7044) and stays valid for good: keep the files as safe as the keys. A key that fails makes the command exit with code 1; the others are still signed and saved.

## Emergency switches

Emergency switches stop signing without a restart. `"stop_signing": true` stops every duty kind except voluntary exits; `"paused_duties": ["attestation", "sync_committee_message"]` stops the kinds named (the duty labels of the metrics: `attestation`, `block`, `randao_reveal`, `aggregation_slot`, `aggregate_and_proof`, `sync_committee_message`, `sync_selection_proof`, `contribution_and_proof`, `voluntary_exit`, `payload_attestation`, `payload_envelope`, `proposer_preferences`, `builder_request_auth`). Both keys go in the config file, a flag (`--stop-signing true`) or the environment (`EPLIX_PAUSED_DUTIES=attestation,block`), and in `<data_dir>/switches.json`, which the VC reads once a second while it runs. `eplix switch stop`, `resume`, `pause <duty>...`, `resume-duty <duty>...` and `status` edit that file. A switch is on when the config or the file turns it on, so `resume` lifts only what the file set. Stopped duties are not signed and count in `eplix_duties_missed_total` with reason `paused`; nothing is written to the slashing DB for them and no key is halted. Each change is logged once as a warning. A `switches.json` that does not parse fails the start and, while running, keeps the switches in place with an error. Lighthouse's `--disable-attesting` is `paused_duties` with `attestation`, `aggregation_slot`, `aggregate_and_proof`, `sync_committee_message`, `sync_selection_proof` and `contribution_and_proof`.

## Keys slashed on chain

A key that the chain shows slashed (confirmed by `attestation_consensus_threshold` nodes, or by every node that answers) stops for good: it signs nothing, Eplix logs an error and counts it in `eplix_slashed_on_chain_total`, and `<data_dir>/slashed-keys.json` keeps the stop across restarts. Remove the key's entry from that file, with the VC stopped, only once you know why it was slashed.

Config keys, flags and environment variables are in [Configuration](configuration.md).
