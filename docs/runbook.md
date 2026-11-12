# Operator runbook

One section per alert in `contrib/prometheus/eplix-alerts.yml`, named after the alert. Each says what fired, what to check first and what to do. The dashboard `contrib/grafana/eplix-dashboard.json` has a panel for every metric named here. Times assume mainnet: a slot is 12 s, an epoch 6.4 minutes.

Two rules hold for every alert:

- Never start a second instance with the same keys to "fix" a missed duty. A second signer is how keys get slashed. Eplix's slashing DB protects one data dir, not two hosts.
- Before you restore a data dir from a backup or move keys to another host, stop the old instance and export its slashing history (`eplix slashing export --config <file> --file <out.json>`), then import it on the new one (`eplix slashing import`).

## Keys with no slashing history

A key signs only with a slashing record. Eplix never gives a key one from beacon node data: a key with no record stays `discovered` and never signs, whatever status the nodes show. There are three ways to give it one:

- History from the previous client: `eplix import --from <dir> --slashing-protection <eip3076.json>`, or `eplix slashing import`, or the keymanager import with its `slashing_protection` field. A key whose entry in the file has no signed block and no signed attestation gets no record: an empty entry is no history.
- No history exists: `eplix import --config <file> --from <dir> --no-signing-history`. For each key it writes a floor record before the VC starts: with E the epoch now (the clock, raised by the highest head any configured beacon node reports), the key may vote only with source at E + 1 or later and target above E + 1, and propose only after epoch E + 1. E is read again after the last answer, so a long wait at the prompt moves the floor up with the clock. When a beacon node's head is more than one epoch past the clock, the import writes no floor and exits with `a beacon node's head is in epoch N, the clock in epoch M; no floor written`. Either the system clock is behind (check NTP: then the head is right, and a floor at the clock's epoch could sit below votes the key already signed) or the node is wrong. Fix the one that is off, then run the import again.
- The config override `allow_start_without_history` (a key, or `["all"]`) writes the same floor at the next key refresh of a running VC. It never starts a key with an empty record. The same head check applies: the log says `could not write floor records` with the epochs, the keys stay `discovered`, and each later refresh tries again. This is the only floor path for a remote (Web3Signer, Dirk, TEE) key and for a key from a configured keystore directory outside the data dir: `eplix import` copies keystores into the data dir.

A complete history is large: about 11 MiB per validator-year with signing roots, twice that once the keymanager request escapes it into a JSON string. The keymanager import reads it as a stream and keeps only each key's highest block and attestation, so memory does not grow with it, but the body may not pass `modules.keymanager.max_import_bytes` (default 256 MiB). Over it the import answers 413 and imports nothing: split the keys over several requests, raise the limit, or minimise the interchange first (any client that exports the minimal form, or `eplix slashing import` and then `eplix slashing export` on a scratch data dir). One import also takes at most `modules.keymanager.max_import_keys` distinct keys in its history (default 100,000); over that it answers 413 with `too many keys in one import` and imports nothing. `eplix slashing import` stops at 100,000 keys per file with an error that starts with the same `too many keys in one import`; that cap is fixed, so the error names no setting. Split the interchange by key. A history that holds a slashable pair (two blocks at one slot, a double or surround vote) still goes in as its highest marks, and the log says `holds a slashable pair` once per key: find out which machine signed what before the key signs here.

Moving keys from Eplix to another client goes the other way. `DELETE /eth/v1/keystores` returns the minimal history, about 360 bytes per key as escaped JSON, so a delete of 10,000 keys (the most one request takes) returns about 3.6 MB. Some clients take less in one import, for example about 2 MB, which is about 5,000 keys of minimal history. For such a target, delete the keys in smaller batches, or split the exported interchange by key over several imports. If the target answers 413 or refuses the body, check its limit and send the keys again in parts.

A keymanager import without `slashing_protection` leaves the key `discovered`, and the response message says why. Stop the VC and run `eplix import --no-signing-history --from <dir>` on the directory that holds the keystore, or import the key again with its history. A key whose keystore is already in the data dir and that has no slashing record gets its floor without a new copy; the same holds after a plain `eplix import` without either flag.

A new validator: import its key with `--no-signing-history` right after the deposit. The floor then sits long before the key activates and costs nothing.

A lost setup (the data dir is gone, the keys are made again from the mnemonic): first make sure the old machine is off for good and nothing else signs with the keys, then import with `--no-signing-history`. Every vote and block the old setup signed is at or below the epoch now, so the floor protects against all of them, but only if no other machine signs with the keys from now on.

During the import, each key that a beacon node shows `active_*`, `exited_*`, `withdrawal_*` or slashed may have signed before, so the import asks on the terminal:

    key 0x...: status active_ongoing on http://bn1:5052; it may have signed before. The floor at epoch N protects against those votes only if no other machine signs with this key now. Import with a floor? [y/n/all]

`y` imports this key, `n` skips it, `all` says yes for this key and every later one. Pending keys and keys the nodes do not know need no question. Only synced nodes count: a node that is syncing or optimistic may not know an active key yet, so its statuses are not used. When no synced beacon node answers, the import says so once and asks for every key as status unknown. Run the import on a terminal: without one (a pipe, a script, cron) it imports no key that needs a question, lists them, and exits 1. There is no flag to answer yes.

After a floor, a key attests once the chain's justified checkpoint reaches the floor epoch, usually 2 to 3 epochs later. While the chain does not finalize, justification can stall and the key waits until it passes the floor; the slashing DB refuses each vote with an older source (`EplixSlashingProtectionRefused`). That is the floor working, not a fault.

## Install

The x64 binary needs a CPU with AVX: Intel Sandy Bridge (2011) or newer, AMD Bulldozer or Jaguar or newer, any AMD Zen. Nehalem, Westmere and older, and Intel Atom-class cores up to Tremont (Celeron and Pentium N and J series such as the N5105 and J4125) cannot run it. Check before you install: `grep -m1 -o -w avx /proc/cpuinfo` must print `avx`. On a CPU without AVX the runtime stops the binary at start, before any Eplix code runs or the config is read, with this line on stderr:

```
The required instruction sets are not supported by the current CPU.
```

`journalctl -u eplix` shows the line, once per restart. Nothing was signed, and the slashing DB was not opened. Move the VC to a host with AVX (keep its data dir, which holds the slashing DB), or, only as a stopgap and unsupported, build a binary with `scripts/publish-aot.sh` after setting `-p:IlcInstructionSet=x86-64-v2` in `src/Eplix/Eplix.fsproj`. On a virtual machine, check that the hypervisor passes AVX to the guest (`host-passthrough` in libvirt, or a CPU model with AVX).

`contrib/systemd/eplix.service` runs the published binary (`scripts/publish-aot.sh`) as a dedicated user with a sandbox: no new privileges, the whole file system read-only except the data dir `/var/lib/eplix`, no capabilities, a private `/tmp`, and only IPv4, IPv6 and Unix sockets. To install:

1. `useradd --system --home-dir /var/lib/eplix --shell /usr/sbin/nologin eplix`
2. Copy `eplix` and `libblst.so` to `/usr/local/lib/eplix/`, the config to `/etc/eplix/eplix.json` (readable by `eplix`, `data_dir` set to `/var/lib/eplix`), keystores and password files under `/etc/eplix/` (mode 0640, group `eplix`).
3. Copy the unit to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now eplix`.
4. `systemd-analyze security eplix` lists what the sandbox still allows.

The unit writes nothing outside `/var/lib/eplix`. A config that names another writable path (a keymanager token file elsewhere, a proposer config the keymanager API edits) needs that path in `ReadWritePaths=`. `contrib/systemd/sandbox-check.sh` runs the binary under the same file system limits without systemd and checks that it attests.

Scrape the metrics module (`modules.metrics`, port 5064 by default) under job `eplix`; the rules select on `job="eplix"`.

## The VC

### EplixDown

Prometheus cannot scrape the VC for 2 minutes. Either the process is down or its metrics port is not reachable.

- `systemctl status eplix` and `journalctl -u eplix -n 100`. A start that fails prints the reason on the last lines: a config error, a beacon node that never answered, a slashing DB that does not open, a key without history.
- If it runs, check the scrape target and the `modules.metrics` address.
- An exit with code 1 and a log line naming a key seen live is a doppelganger stop: see `EplixDoppelgangerDetected`.
- A crash loop with `slashing DB` in the message: do not delete `slashing.db`. A DB that does not open fails the start on purpose; an empty one would let the keys sign again what they signed before. Keep the file for the report and restore from your last export only after the keys have been idle for two epochs past their last signed vote.

### EplixNoDutiesCompleted

The VC has active keys and finished no duty in 15 minutes, two epochs. Every active key has one attestation an epoch, so this means the duty loop stalled or every duty failed. It stays quiet while an operator switch pauses attestations, but only when the paused attestation misses (reason `paused`) in those 15 minutes reach the number of active keys. A full pause always reaches that. A pause of a few keys does not, so a stall of the other keys still fires. A pause of about 40% of the keys or more also reaches it, because each key has two or three attestations in 15 minutes. Attestations lost to an HA peer (reason `lost_to_peer`) count the same way, so a VC whose peer signs every duty stays quiet; see "HA pairs".

- Look at `EplixDutiesMissed` and the dashboard's missed duties panel: the reason label says where the duties stop.
- No misses either: the loop is not running. Check the log for the last `slot N:` line and for exceptions, then restart the service. Report the log.

### EplixDutiesMissed

Duties were missed in the last 15 minutes. The `reason` label says why:

- `beacon_node`: no attestation data, block or aggregate from the beacon nodes, or no consensus between them. See the beacon node alerts and the node's own logs (syncing, 503s). For `duty="payload_attestation"` (Gloas PTC votes), fewer than `ptc_consensus_threshold` nodes agreed; after drops (`EplixBeaconNodeDropped`) the threshold may be out of reach.
- `slashing_protection`: the VC's slashing DB refused. See `EplixSlashingProtectionRefused`.
- `refused`: a backend or the key state refused (a remote signer's policy, a key not active yet, an unknown key).
- `signer_error`: the backend did not answer in time or failed. See the signer alerts.
- `submit`: signed, but no beacon node accepted the submission. See `EplixSubmissionsFailing`.
- `paused`: an operator switch (`stop_signing`, `paused_duties`, `switches.json`) stopped the duty. Expected while you hold it, so these misses fire neither this alert nor `EplixAttestationsMissedHigh`; the dashboard's missed duties panel still shows them.
- `lost_to_peer`: with `modules.tee.ha_peer`, the HA peer signed the duty first. The pair did the duty, so these misses fire no alert either. See "HA pairs".

A few misses around a beacon node restart are normal. Misses that go on are not.

### EplixAttestationsMissedHigh

More than 10% of attestation duties missed over 30 minutes. Treat as an outage: the keys are losing rewards. Work through `EplixDutiesMissed` by reason; the largest reason first.

### EplixNoActiveKeys

The VC holds keys and none has been active for 30 minutes. Keys wait in `discovered` (no slashing history yet), `doppelganger_wait`, `halted` or `slashed`. The dashboard's keys by state panel says which.

- `discovered`: the key has no slashing record. Import the EIP-3076 file from the previous client, or, once you are sure no other machine signs with it, give it a floor with `eplix import --no-signing-history` or `allow_start_without_history` (see "Keys with no slashing history").
- `doppelganger_wait`: see `EplixKeysWaiting`.
- `halted` or `slashed`: see those alerts.

## Keys

### EplixKeyHalted

The VC stopped signing for a key: a remote signer refused a request as slashable (Web3Signer's 412, a TEE runner's slashing refusal) that this VC's slashing DB allowed. That is the only cause of a halt. With `modules.tee.ha_peer` the four "already signed" refusals of a TEE runner do not halt the key; see "HA pairs". A halted key stays halted until restart; removing its keystore or deleting it through the keymanager API does not clear the halt. Dirk answers every refusal with DENIED, which does not halt the key: the VC skips the duty and counts it as a denial (EplixSignerDenied).

- Find the key in the log: `halted` lines name it and the reason.
- A refusal from the signer's own slashing protection while this VC's DB allowed the message means someone else signed with the key, or the signer's DB is ahead of this one (a restored backup, a second VC on the same signer). Stop and find the other signer before you restart.
- Restart only when you know why. The halt protects the key.

### EplixKeyRefused

The VC took a key out until restart and signs nothing with it, on any route. Each refusal is logged once as an error with `refused until restart`, the key and the cause:

- The share keys of a threshold key are not one split of it: a TEE runner, Web3Signer member or Dirk participant holds a share of another split of the same key, or a share at the wrong index. The log names the members whose share is off. Two splits of one key let more sets of members sign than the threshold says. Find out how the second split came about, and remove the shares that do not belong.
- A Dirk distributed account has a threshold of half its participants or less, so two sets of participants with none in common could each sign. The log names the account. Make a new distributed account with a threshold above half, and move the validator to it.
- The key is whole on one signer or keystore and split in a configured group, in one module or across two (a keystore or keymanager import can meet a group's key too). The whole key alone could sign, so the group's threshold means nothing while it exists. The log names both routes. Remove the whole key, or the group's shares, from where it should not be. A remote signer can also list a key it does not hold; if the listing is wrong, fix that signer or take it out of the config. If the module with the split copy cannot list its keys at start (its signers are down), the whole copy can sign until that module's next key refresh shows the clash; then the key is refused. The slashing DB covers both routes in one VC, and with `ha_peer` on local and remote keys are refused, so this window cannot cause a double vote, but remove the whole copy as soon as the alert fires.

Then restart the VC. A key stays refused until the restart, also after the cause is gone.

The share check runs when a TEE or Dirk module starts, when a key's share keys change, and at the Web3Signer config check, never per signature. At start it uses every core the VC may use. The first key list, with the check, takes about 2 ms of CPU per key in a 3 of 5 group and 0.7 ms in a 2 of 3 group: on 6 cores, 3,000 keys of a 3 of 5 group add about 1.2 s to the start. Duties start only after every module has started, so give a VC with many threshold keys more than one or two cores. A refresh checks only the keys whose share keys changed, on half the cores.

### EplixKeySlashed

The chain shows a key of this VC as slashed, or a key is in state `slashed`. The VC stopped signing for it. Slashing cannot be undone: the key is exited by the protocol.

- Stop every other client and host that holds the key. Find how a second signature happened: a second instance, a restored data dir, a key imported elsewhere.
- Keep `slashing.db`, the logs and the signer logs for the post-mortem.
- Other keys on the same hosts may be at the same risk: check them before anything restarts.

### EplixDoppelgangerDetected

A key waiting in the doppelganger check was seen live on chain: something else signs with it. The VC stops at once (exit code 1) with an error that names the key, its index, the epoch and the beacon nodes that saw it, so this alert can miss the count when the process exits before the next scrape; `EplixDown` and the log line are the sure signs.

With `liveness_from: all` and several beacon nodes, one node that saw the key live while another node that answered did not does not stop the VC. Every key still in the doppelganger wait then waits until restart and signs nothing, keys already active go on signing, and one error starting `DOPPELGANGER?` names the key and both nodes. Either the one node is right (the others missed the votes, maybe for other waiting keys too), or it is wrong or lying. Look for another client that signs with the key first; if there is none, take the node that saw it live out of the config before you restart. The VC still stops when two nodes see a key live, or when no node that answered says otherwise.

- Do not restart to get past the check. Find the other client first; it is the one signing. Under systemd the unit restarts the VC, which checks the key again and stops again while the other client signs. That loop is safe, and it is noisy on purpose.
- Every key waits in the check at every start, also one that passed before, and nothing about the check is kept in the data dir. A restart or a move to another host checks every key again.
- Once only one signer is left and that signer is this VC, restart.

### EplixKeysWaiting

Keys have waited in the doppelganger check for over 45 minutes. The check takes `modules.doppelganger.epochs` epochs (2 by default, about 13 minutes) after the start or after a key was added.

- A beacon node that does not answer liveness requests keeps keys waiting: the check fails closed. See the beacon node alerts and the log's `doppelganger` lines.

### EplixSlashingProtectionRefused

The VC's own slashing DB refused a request: the message conflicts with one this data dir already signed.

- One refusal right after a restart inside an epoch is expected: the VC signed the duty before the restart and refuses to sign it again. Nothing to do.
- Refusals that go on mean the VC is asked to sign conflicting messages: a beacon node on another fork, or a clock off by an epoch. Check the beacon nodes' heads and the host clock.
- Never delete or reset `slashing.db` to make refusals stop.

### EplixKeysRetired

Keys were retired because no signer of the named backend lists them any more (Web3Signer key lists, Dirk accounts, TEE runner key lists). The VC stops their duties.

- Expected when you removed keys from the signers. Otherwise check the signers' key stores and that every signer answered the last key list.

## Signers

### EplixSignerMarkLogLost

A TEE runner's HEALTH answer reports `mark_log_lost`: the runner lost its slashing mark log, so it can no longer prove what it signed before. `eplix_signer_mark_log_lost_total{signer}` counts each time a runner's HEALTH state turns to `log_lost`. The VC sends that runner no signing requests while HEALTH says so, logs `<runner> no longer serves its keys` at Error, and a group signs from its other members. The runner must not sign again until its operator acts.

- Read the runner's own log for the cause.
- Remove the runner from `modules.tee`, or move its key shares to a runner that has its slashing history. Do not reset the runner so it signs again without that history.
- While the runner stays in this state, EplixSignerDegraded keeps firing with `state="log_lost"`.

### EplixSignerErrors

Over 5% of the requests to one backend failed for 5 minutes: timeouts, refused connections, TLS failures.

- Check the signer processes and the network between the VC and the signers.
- For threshold groups, the VC still signs while a threshold of members answers; the alert warns before that margin is gone.
- TLS errors after a certificate change: check the client certificate, its chain and expiry.
- A Dirk or Web3Signer server certificate without the serverAuth extended key usage is refused: a certificate made for clients only does not pass as a server. Issue the server one with serverAuth.
- TEE: `the runner closed the connection right after the dial` means the runner accepted the handshake and dropped the connection within 5 s. The pool counts that as a failed dial and backs off (1 s doubling to 16 s). Check the runner's log for why it closes connections.
- Failures with `is not used for <key>`: the VC stopped sending that key to a Web3Signer or Dirk whose signatures for it did not verify. See EplixRemoteSignatureInvalid.

### EplixSignerDenied

A remote signer denied requests without a reason (Dirk's DENIED). Usually the signer's own rules: an account it does not hold, a lock, a policy. Dirk also answers DENIED when its slashing protection refuses a vote or block, so denied attestations or proposals can mean another VC signs with the key; the key is not halted.

- Read the signer's logs at the time of the denial.

### EplixRemoteSignatureInvalid

A Web3Signer or Dirk returned whole-key signatures that do not verify against the key and signing root (`eplix_remote_signature_invalid_total{backend,endpoint}`). The VC checks them in the background after it has handed them on, so the beacon node got them and dropped them: each one is a missed duty. Usual cause: the signer signs with another key than the one it lists (a wrong key file, account or share setup).

- The error log names the key, the endpoint and the duty kind: `the signature for the <duty> of <key> does not verify (<n> in a row)`.
- After 3 in a row for one key, the VC stops sending that key to that endpoint (`requests for <key> no longer go to it`, `eplix_remote_signer_key_stops_total`). Its requests fail as `is not used for <key>` and count as `signer_error` misses. The key is not halted and its slashing records are not touched.
- Fix the key at the signer. The VC sends one probe an epoch, a RANDAO reveal for the current epoch, before the key's next request; once the probe verifies, the key signs again (`go to it again`, `eplix_remote_signer_key_resumes_total{reason="probe"}`). Removing the key from the signer's list and adding it back, or a VC restart, also resumes it.
- A probe that fails counts here too, so the alert keeps firing while the key stays stopped.
- `eplix_remote_signature_checks_dropped_total` counts checks skipped because 4,096 already waited at one endpoint. Signing goes on; only detection is lost for those signatures. It rises when the VC's CPU cannot keep up with a large burst.

### EplixSigningSlow

The 99th percentile of one backend's signing time is over a second for 10 minutes. Attestations are due 4 seconds into the slot, so slow signing turns into late votes.

- Check the signer's host load and the network round trip. For Dirk and threshold groups, one slow member slows every request that needs it.

### EplixSignerDegraded

A TEE runner's HEALTH answer has put it in a state other than ready for 5 minutes: a refusal (`protocol_too_old`, `not_ready`, `request_panic`, an `image_*` state), `log_lost` (its mark log is lost, see EplixSignerMarkLogLost), `pending` (no HEALTH answer since the start or since a new connection), or `unknown` (HEALTH failed past one epoch after an answer with protocol level 2 or higher; requests go to it). The `state` label of `eplix_signer_state` names it. The VC sends the runner no SIGN while it refuses; a group signs from its other members.

- Read the runner's state in the log and in its own monitoring. A runner that refuses keeps refusing until its operator acts.
- `protocol_too_old`: the runner reports a tee-signer protocol level below 2, or none (`<runner> gets no requests: it speaks protocol level <n>; Eplix needs tee-signer protocol level 2 (FLOOR/FLOOR_UNPROVEN)` at Error). Update the runner to a tee-signer build that reports `protocol` 2 or higher in HEALTH. The VC reads HEALTH at each new connection and each epoch and sends requests again once the level is 2 or higher.
- A warning `speaks tee-signer protocol level <n>, above level 2` means the runner is newer than this Eplix. It stays in use; update Eplix.

### EplixClientCertificateExpiring

A TLS certificate or CA file the VC uses expires within 2 days: a client certificate for a TEE runner, Web3Signer or Dirk, the keymanager's certificate, or a CA file (`eplix_tls_cert_not_after_seconds{use,name}`). If your certificates live less than 2 days and renew on time, this fires for every one of them; lower the threshold to under the renewal period.

- Replace the certificate files; the VC reloads them without a restart. Check the new chain includes the intermediates.

## HA pairs

With `"ha_peer": true` in `modules.tee`, two VCs sign the same keys through the same runners. A runner signs each duty once. The VC that asks second gets an "already signed" refusal (`SC_ERR_SLASH_TARGET`, `SC_ERR_SLASH_SOURCE`, `SC_ERR_SLASH_BLOCK` or `SC_ERR_EQUIVOCATION`), skips the duty and keeps the key. It logs `lost the <duty> to an HA peer` at Info and counts the duty in `eplix_ha_peer_lost_total{duty}` and in `eplix_duties_missed_total` with reason `lost_to_peer`. `EplixDutiesMissed` and `EplixAttestationsMissedHigh` leave those misses out, and `EplixNoDutiesCompleted` counts lost attestations as it counts paused ones. Every other slashing refusal still halts the key.

So one VC's alerts do not show whether the pair does its work. Watch the pair:

- The two VCs together complete about one attestation per active key and epoch: `sum(increase(eplix_duties_completed_total{job="eplix",duty="attestation",instance=~"<vc-a>|<vc-b>"}[15m]))` against two or three times the active keys of one VC. Far fewer means both VCs lose or miss duties.
- With ha_peer the four refusals above do not halt a key, so `EplixKeyHalted` stays quiet when a third signer uses the same runners. Both VCs then lose the same duties and the pair completes too few. Stop and find the third signer: a VC with these keys outside the pair, or a copy of a data dir.
- Misses with any other reason are real misses of that VC and fire the usual alerts.

## Beacon nodes

### EplixNoReadyBeaconNode

No beacon node passed the VC's start checks (genesis, spec against the pinned config, reachability) for 2 minutes. Nothing can be signed.

- Check each node: is it up, synced, on the same network as the config (`network` or `chain_config`)? A spec that differs from the pinned config shows in the log and keeps the node out.
- A start that fails with "too few beacon nodes passed the start checks" lists each node's reason. A reason that names `the data dir` or `the slashing DB` means the data dir was first used on another chain: point the VC at the right network, or move to a new data dir. Do not delete `chain-anchor` or `slashing.db` to get past it.

### EplixBeaconNodeDropped

A check took a beacon node out of use: at start, or at the check each epoch, the node reported another fork schedule, domain type, genesis time, genesis validators root or slot timing than the chain the VC runs on, or a spec the VC refuses. The VC goes on with the other nodes and gives this one no call until it restarts. It stops by itself when fewer nodes with the role `attestation_data` than `attestation_consensus_threshold` are left, or a role has no node left.

- `journalctl -u eplix | grep 'gets no calls'` shows the node and the value that differs.
- Check the node: restarted on another network, a wrong `--network` or testnet dir, a fork schedule from an older or newer release, or a node you do not trust. Fix it, then restart the VC to take it back.
- With one node fewer, the threshold margin is smaller; add a node if only the threshold is left.
- The VC does not stop when fewer nodes than `ptc_consensus_threshold` are left. It goes on attesting, and every PTC vote after the Gloas fork fails: `EplixDutiesMissed` with `duty="payload_attestation"` shows it.

### EplixNoHealthyBeaconNode

The best node's health score has been under 50 of 100 for 5 minutes. Scores fall with errors and timeouts and recover with good answers; with every node low, duties fail or come late.

- Check the nodes' logs and sync state. `eplix_beacon_node_requests_total{result="error"}` on the dashboard shows which calls fail.
- Add a second node (`beacon_nodes`) if there is only one.

### EplixBeaconNodeUnhealthy

One node's score has been under 50 for 15 minutes. The VC prefers the others, so duties go on; the margin is smaller.

- Same checks as above, for the named node.

### EplixSubmissionsFailing

A node refused over 20% of the sends for 15 minutes (attestations, aggregates, blocks, subscriptions, by `topic`). With broadcast on, other nodes may still take them; with one node, the duties are missed with reason `submit`.

- The node's logs at the time say why it refused: syncing, an unknown block root, a full queue.

### EplixBlindedBlockRefused

No beacon node took a signed blinded block from the pre-Gloas builder flow (`eplix_blinded_blocks_total{result="refused"}`). The block is signed, so the VC cannot sign another for that slot, and the proposal is likely lost.

- Check the relay and MEV-Boost logs for the slot and the beacon node's publish errors.

### EplixRegistrationsFailing

A beacon node refused validator registrations and accepted none in the last epoch. Without a registration, builders cannot build for the keys and proposals use local blocks.

- Check MEV-Boost and the relay list. Registrations go out each epoch; one failure clears on the next.

## Host and config

### EplixSlashingDbSlow

The 99th percentile of the slashing DB's check, append and fsync has been over 250 ms for 10 minutes. Every signature waits for it, so a slow disk delays every duty.

- Check the disk of the data dir: other I/O on it, a network or overlay file system, a failing device. Put the data dir on a local SSD.

### EplixProposerConfigErrors

The proposer config file failed to read or parse on a reload. The VC keeps the last good content, so proposals still use the old fee recipient and gas limit.

- The log line names the file and the error. Fix the file; the next check (each epoch) picks it up.

### EplixThreadPoolQueue

Over 100 work items have waited in the .NET thread pool for 5 minutes. The host is short of CPU, or something blocks the pool.

- Check the host's CPU and the VC's CPU time on the dashboard. If it persists on an idle host, report it with the log.

## The chain

These come from the duties monitor (`modules.monitor`), which reads the blocks after each duty. They see what the network saw, so they also catch duties the VC thinks it did.

### EplixChainAttestationsMissed

Attestations of the VC's keys are not in any block of their inclusion window.

- Misses the VC also counted (`EplixDutiesMissed`) have their reason there.
- Misses the VC did not count were submitted and still not included: a beacon node that does not gossip them, a late submission, or a fork. Compare the node's peers and the submission times.

### EplixChainProposalMissed

A block the VC was to propose is not on chain. A proposal is rare and worth more than many attestations.

- Find the slot in the log: was the block produced, signed and published, and when? A late publish loses the slot to the next proposer.
- With external builders, check the relay's answer and whether the VC fell back to a local block in time.

### EplixChainInclusionSlow

Attestations take over 2 slots on average to be included, over an hour. Late inclusion costs rewards: a head vote earns its reward only when the next slot's block includes it.

- Compare with the network: a slow chain affects everyone. If only these keys are slow, check the beacon node's peers and the attestation submission times.
