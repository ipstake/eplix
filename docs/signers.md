# Remote signers

Local keystores are set in the `local` section ([Configuration](configuration.md#example-config-file)). This page covers Dirk, Web3Signer and TEE signers, and the rules they share.

## Dirk

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

## Web3Signer

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

## TEE signers

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

### Keys and attestation pins

`keys` (a list) and `keys_file` (one key per line, `#` comments) name the validator keys Eplix signs for through the runners; at least one is required, because a runner may hold other clients' keys too, and keys the runners list beyond these are not used. Each pin of `attestation` (`cce_policy_sha256`, `gcp_image_digest`, `nitro_pcrs`) also takes a list (for `nitro_pcrs` a list of PCR maps), so the old and the new image both pass during an image swap. `setup_sha256` and `key_release_sha256` take a list too, for a setup or key release policy rotation. `azure-maa`, `aws-nitro` and `gcp-cs` need `setup_sha256`: without it every runner fails the setup check, so the config check refuses it.

`key_release_sha256` pins the `key_release_hash` a runner reports in its IDENTITY, the hash of the policy under which its cloud releases the key (Azure secure key release, AWS KMS). On mainnet (`network` mainnet, or a `chain_config` named mainnet or with mainnet's genesis fork version) an `azure-maa` or `aws-nitro` runner needs it, and the start fails without it. On other networks it is optional: unset, any hash passes. `gcp-cs` runners report no key release hash, so the field is refused there. This is the rule of the signers' own client. A runner whose hash is not in the list fails the dial, and the error names both. `eplix check` prints each runner's setup and key release pins.

On mainnet the start fails when a runner, or the `runner` source of a Web3Signer endpoint, has `"verifier": "dev"` (it checks no platform evidence) or `"allow_testnet_build": true`. Both are for test networks.

### Connections

Each runner keeps `connections` (1 to 64) attested connections open. Without it, a runner gets one connection per 64 keys it serves (its whole keys and the threshold keys of its groups), at least 8 and at most 16. The pool starts with 8, grows once the key list is read, and grows again when a key list refresh brings more keys; it does not shrink while running. In a local load test with 1,000 keys in a 3 of 4 group, one runner 500 ms slower than the others and a second one refusing every tenth key (so those votes needed the slow runner), 8 connections per runner missed 55 to 69 of 2,000 votes and 16 missed none; with 39 keys neither size missed a vote. The steps between 8 and 16 were not measured. A pool has at most 16 dials to a runner in its window (a dial counts from its start until 15 s after it ended, or 1 s after a failed one, whose connection is closed by then): by default a runner refuses a 17th handshake at once from one address, and on AWS the forwarder closes a 17th connection from one address within 15 s. So 64 connections take four rounds of dials. Two VCs behind one address share those 16, and so does the one connection a Web3Signer `runner` attestation source opens for each check: it is not counted in the pool's window.

`priority_low_every` (default 8) sets how often a free connection goes to the low class while high requests wait. High are the requests the scheduler marks high: attestations, sync committee messages, blocks, RANDAO, PTC votes, envelopes, and builder request auth when a proposal waits for it. Low are selection proofs, aggregates, sync contributions, exits, registrations, proposer preferences and builder request auth an epoch ahead.

`client_cert` holds the client certificate first, then the intermediate CAs up to the root, in PEM. All of them go to the runner in the TLS handshake, so a runner that trusts only the root accepts a certificate from an intermediate CA. The Azure MAA and Confidential Space verifiers fetch their issuers' key sets over HTTPS, trusting the system store; `attestation_ca_file` (a PEM bundle, at the `tee` level) makes them trust only its CAs instead, for a host or image without a system store.

### Runner health

Eplix reads each runner's HEALTH at every new connection and each epoch, in the background. A runner that says it refuses to sign (`ready` false, a request panic, an image check state of not_allowed, restart_needed or unknown), or that it no longer serves its keys (its mark log is lost), gets no signing requests until HEALTH says it signs again; a group signs from its other members. Before its first HEALTH answer, and after each new connection while it signs, a runner is `pending` and gets no signing requests; the first request asks HEALTH and waits up to 5 s for the answer. A failed HEALTH call keeps the last state for the rest of the epoch; after that the state is unknown and requests go again, but only if the last answer showed protocol level 2 or higher. A `pending` or `protocol_too_old` runner stays in that state while HEALTH fails. A runner below tee-signer protocol level 2, or one that sends no `protocol` in HEALTH, is in state `protocol_too_old`: it gets no signing requests, and Eplix logs one error for it that names its level. A runner above level 2 stays in use, with one warning, since some of its answers may mean something this Eplix does not read. `eplix_signer_state{signer,state}` gives each runner's state, and `eplix_signer_mark_log_lost_total{signer}` counts each time a runner's HEALTH turns to `log_lost`.

## Threshold groups

A group's `threshold` must be more than half its members (2 of 3, 3 of 4, 3 of 5): with half or fewer, two sets of members with no member in common could each sign a different message, and every member's slashing protection would allow it. Such a config fails the start, in the `tee` and `web3signer` sections; a Dirk distributed account at such a threshold is left out with an error. Eplix also checks at start and at every key list that each member's share key lies on one split of the key. A key whose shares do not, or a key that one signer or keystore holds whole while a group holds it split, signs on no route until a restart, whichever modules list the two and in whichever order: an error names the key and the cause, and `eplix_keys_refused` counts it (alert `EplixKeyRefused`).

## Key list refresh

Dirk, Web3Signer and the TEE runners are asked for their key lists at start and every `refresh_interval_seconds` (default 384, 0 turns the refresh off, at most 86,400). A key that every signer holding it answers without, two polls in a row, stops getting duties and is removed once its signatures in flight finish. A signer that is down, fails or answers an empty list never causes that. Web3Signer share group keys and keys added through the keymanager API are not retired this way. A retired key that is listed again passes the history check before it signs.

## Certificate rotation

Certificates rotate without a restart. The TEE, Web3Signer, Dirk and keymanager modules read their certificate, key and CA files every `reload_interval_seconds` (default 10, 0 turns it off) and load a changed set when it is valid; a set that does not load (a key that does not match, an expired certificate) keeps the old one in use and logs an error. After a new client certificate, each runner's connections are redialed one at a time within `rotate_within_seconds` (default 300, `tee` level) and before the old certificate expires, so the pool stays full. The TEE module also reads its files soon after a change to one of them (a write in place, or a new file renamed over the old one, as certificate agents do; a burst of changes is read once the directory has been quiet for 0.5 s) and at once on SIGHUP. A file reached through a symlinked directory that is swapped as a whole (a `..data` link) raises no change event for its name; the poll reads it. A half-written or mismatched pair, or a file cut short in its last certificate, keeps the old one, logs an error and counts in `eplix_tls_cert_reloads{result="error"}`; the next change is read again. With `reload_interval_seconds` 0 none of this runs. SIGHUP never stops the VC, so it keeps running when its terminal hangs up; with no reload running it logs `SIGHUP: no certificate reload configured`. Web3Signer and Dirk test a connection with the new certificate, then move new requests to it. `eplix_tls_cert_not_after_seconds{use,name}` shows when each certificate in use expires; alert on it.

## HA pairs

Two VCs can sign the same keys through the same runners as an HA pair: set `"ha_peer": true` in the `tee` section of both. A runner signs each duty once, so the VC that asks second gets an "already signed" refusal (`SC_ERR_SLASH_TARGET`, `SC_ERR_SLASH_SOURCE`, `SC_ERR_SLASH_BLOCK` or `SC_ERR_EQUIVOCATION`). With `ha_peer` that VC skips the duty and keeps the key; it logs the loss at Info and counts it in `eplix_ha_peer_lost_total{duty}` and in `eplix_duties_missed_total` with reason `lost_to_peer`, which the shipped alerts leave out. An aggregate or sync contribution for a committee where every vote or message of the VC was lost is skipped and counted the same way. Every other slashing refusal still halts the key, and without `ha_peer` the four above halt it too. Every key must then sign through the `tee` module: a `local`, `dirk` or `web3signer` section fails the config check, a keystore in `<data_dir>/keystores` or a remote key in `<data_dir>/remote-keys.json` fails the start, and the keymanager API refuses to import keystores or remote keys. The [runbook's "HA pairs" section](runbook.md#ha-pairs) says how to watch a pair.
