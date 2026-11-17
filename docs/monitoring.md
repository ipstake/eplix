# Monitoring

`contrib/prometheus/eplix-alerts.yml` holds the alert rules and `contrib/grafana/eplix-dashboard.json` the dashboard. The [runbook](runbook.md) has a section for each alert.

## Metrics endpoint

The metrics endpoint is `GET /metrics` in the Prometheus text format, plain HTTP with no token: keep it on loopback or a private network. Without a `metrics` section it listens on 127.0.0.1:5064.

The metrics module also exports the runtime's meters: `eplix_gc_collections_total{generation}`, `eplix_gc_heap_bytes`, `eplix_gc_allocated_bytes_total`, `eplix_gc_pause_seconds_total`, `eplix_process_cpu_seconds_total{mode}`, `eplix_process_working_set_bytes`, `eplix_threadpool_threads`, `eplix_threadpool_queue_length` and `eplix_threadpool_completed_items_total`.

## Tracing

Tracing is off until `modules.tracing.enabled` is true. Then every duty with work in a slot (attestations, aggregates, sync committee messages, contributions, a proposal, selection proofs) is the root span of a trace, with the signing burst, the slashing check, each beacon node request and the submit to the nodes under it. Spans go in batches to an OTLP/HTTP collector (the OpenTelemetry Collector, Jaeger, Tempo) as binary protobuf. `sample_ratio` keeps that share of traces, decided by trace id. `sign_spans` adds a span per signing request, 1,250 per slot at 10,000 keys, so it is off by default. A full queue drops spans and a collector that is down costs a warning; neither delays a duty. `eplix_tracing_spans_exported_total` and `eplix_tracing_spans_dropped_total{reason}` count them. Off, the core's spans cost one check each and the module adds no thread:

```json
"tracing": { "enabled": true, "endpoint": "http://127.0.0.1:4318/v1/traces", "sample_ratio": 1.0, "sign_spans": false,
             "service_name": "eplix", "headers": { "Authorization": "Basic ..." },
             "queue_size": 4096, "batch_size": 512, "flush_interval_ms": 2000, "timeout_ms": 5000 }
```

## Validator monitor

The validator monitor is on by default and costs one block read per slot (only while a key waits for something on chain), at most one committee read per slot, and two calls per epoch (attestation rewards, balances). It does nothing without the metrics module. Its series:

- `eplix_monitor_attestations_total{outcome}`: attestation duties `included`, `missed` (no block took them by the end of the next epoch) or `unknown` (a block in that window could not be read).
- `eplix_monitor_inclusion_distance_slots`: a histogram of the slots between the attestation and the block that took it (1 is the best).
- `eplix_monitor_votes_total{vote,correct}`: `head`, `target` and `source` of included attestations; `correct="true"` when the vote earned its flag in the attestation rewards (correct and in time). Head is not counted in an inactivity leak.
- `eplix_monitor_proposals_total{outcome}` and `eplix_monitor_sync_messages_total{outcome}`: proposals in the canonical chain or missed, sync committee messages in the next block or missed.
- `eplix_monitor_balance_change_gwei`: the change of the summed balances of the active keys over the last epoch (rewards, penalties and withdrawals).
- `eplix_monitor_errors_total{call,reason}`: reads that failed (`request`) or came in a format the monitor does not know (`format`).

`"per_validator": true` adds the same per key, with a `key` label: `eplix_monitor_validator_attestations_total`, `eplix_monitor_validator_inclusion_distance_slots` (the last one), `eplix_monitor_validator_votes_total`, `eplix_monitor_validator_proposals_total`, `eplix_monitor_validator_sync_messages_total`, `eplix_monitor_validator_balance_gwei` and `eplix_monitor_validator_balance_change_gwei`. Leave it off for thousands of keys: each key adds up to 17 series.
