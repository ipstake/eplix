# Beacon nodes

A beacon node entry is a URL or an object. `ca_cert` names the only CA trusted for that node's HTTPS certificate; `headers` and `headers_file` (one `Name: value` per line) go with every request to it, for an API key or basic auth. Header values never appear in logs or metrics; keep them in `headers_file` or the environment, not on the command line:

```json
"beacon_nodes": [ "http://127.0.0.1:5052",
                  { "url": "https://bn.example:5052", "ca_cert": "certs/bn-ca.pem", "headers_file": "bn.headers" } ]
```

## Roles

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

## Publishing

`broadcast` sets how the VC publishes when it has several nodes. By default (`true`, or `"all"`) each message goes to every node with its role at once, and the duty counts as done when the first node accepts it; the sends to the other nodes run on in the background until they answer or reach `request_timeout_ms`, so a slow or hanging node does not hold up the duty. With `false`, subscriptions and preparations still go to every node, and every other message goes to the best node only (synced first, then by score), then to the next one when it fails or times out. With `"none"` (or `[]`) every message goes to one node at a time. A list or a comma-separated string picks topics to broadcast, the rest go to the best node: `attestations` (with PTC votes), `aggregates`, `sync_committee`, `blocks` (with envelopes), `subscriptions`, `preparations` (`prepare_beacon_proposer`, Gloas proposer and builder preferences) and `exits`:

```json
"broadcast": [ "attestations", "blocks" ]
```

`eplix_beacon_node_submissions_total{node,topic,result}` counts every publish send when it ends, whether broadcast or one node at a time, and the background sends that end after the duty is done: `accepted`, `failed`, or `skipped` (the node already had 16 sends running and got none). `topic` is one of the names above.
