#!/usr/bin/env bash
# Smoke test of the published binary with the metrics and doppelganger modules: eplix runs one
# local key (the EIP-2335 PBKDF2 vector) against scripts/fake-beacon-node.py with 1-second slots
# and 4-slot epochs, holds the key for one doppelganger epoch, then attests; /metrics must show
# the attestations, the active key and the signing latency. The keymanager API runs on HTTPS with
# a certificate from a test CA (leaf plus intermediate in one file) and must answer curl, which
# trusts only the root; the tracing module sends spans to a fake OTLP/HTTP collector, which must
# receive protobuf bodies with the attestation spans. A chunked keystore import with a complete
# slashing history (2,000 blocks and votes) must go through the streamed import.
# Run after scripts/publish-aot.sh.
# Usage: scripts/smoke-metrics.sh [seconds]
set -euo pipefail
cd "$(dirname "$0")/.."
seconds=${1:-20}
bin="$PWD/artifacts/publish/linux-x64/eplix"
work=$(mktemp -d)
bnport=15055
metricsport=15064
kmport=15062
otlpport=15318
cleanup() {
  [ -n "${vc:-}" ] && kill "$vc" 2>/dev/null || true
  [ -n "${bn:-}" ] && kill "$bn" 2>/dev/null || true
  [ -n "${otlp:-}" ] && kill "$otlp" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

sed -n 's/.*"pubkey": *"\([0-9a-fx]*\)".*/\1/p' tests/fixtures/eip2335/pbkdf2.json | sed 's/^0x//; s/^/0x/' > "$work/pubkeys.txt"
cat > "$work/chain.yaml" <<'Y'
CONFIG_NAME: 'fake'
PRESET_BASE: 'minimal'
SECONDS_PER_SLOT: 1
GENESIS_FORK_VERSION: 0x00000001
ALTAIR_FORK_VERSION: 0x01000001
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_VERSION: 0x02000001
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_VERSION: 0x03000001
CAPELLA_FORK_EPOCH: 0
DENEB_FORK_VERSION: 0x04000001
DENEB_FORK_EPOCH: 0
ELECTRA_FORK_VERSION: 0x05000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 18446744073709551615
Y
# A root CA, an intermediate and a server certificate for 127.0.0.1 under it.
(
  cd "$work"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key -out root.pem -days 2 \
    -subj "/CN=smoke root" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout inter.key -out inter.csr -subj "/CN=smoke intermediate" 2>/dev/null
  printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign\n' > inter.ext
  openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -out inter.pem -days 2 -extfile inter.ext 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout km-key.pem -out km.csr -subj "/CN=localhost" 2>/dev/null
  printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > km.ext
  openssl x509 -req -in km.csr -CA inter.pem -CAkey inter.key -CAcreateserial -out km.pem -days 2 -extfile km.ext 2>/dev/null
  cat km.pem inter.pem > km-chain.pem
)
# A fake OTLP/HTTP collector: keeps each POST body to /v1/traces in its own file, answers 200.
mkdir -p "$work/otlp"
python3 -I - "$otlpport" "$work/otlp" > "$work/otlp.log" 2>&1 <<'P' &
import http.server, sys, os, itertools
port, out = int(sys.argv[1]), sys.argv[2]
n = itertools.count()
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        ok = self.path == "/v1/traces" and self.headers["Content-Type"] == "application/x-protobuf"
        if ok:
            open(os.path.join(out, "%04d.bin" % next(n)), "wb").write(body)
        self.send_response(200 if ok else 400)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
P
otlp=$!
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$bnport", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": {
    "local": { "keystores": [ { "path": "$PWD/tests/fixtures/eip2335/pbkdf2.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" } ] },
    "keymanager": { "port": $kmport, "tls_cert": "km-chain.pem", "tls_key": "km-key.pem" },
    "tracing": { "enabled": true, "endpoint": "http://127.0.0.1:$otlpport/v1/traces", "flush_interval_ms": 500 },
    "metrics": { "port": $metricsport },
    "doppelganger": { "epochs": 1 } } }
J
python3 -I scripts/fake-beacon-node.py "$bnport" "$work/pubkeys.txt" 1 4 > "$work/bn.log" 2>&1 &
bn=$!
sleep 0.5
(cd "$work" && exec "$bin" run --config eplix.json) > "$work/vc.log" 2>&1 &
vc=$!
sleep "$seconds"
curl -fsS "http://127.0.0.1:$metricsport/metrics" > "$work/metrics.txt"
curl -fsS --cacert "$work/root.pem" -H "Authorization: Bearer $(cat "$work/data/api-token.txt")" \
  "https://127.0.0.1:$kmport/eth/v1/keystores" > "$work/keystores.json"
if curl -fsS "http://127.0.0.1:$kmport/eth/v1/keystores" > /dev/null 2>&1; then
  echo "the keymanager API answered plain HTTP on its TLS port"; exit 1
fi
# A chunked import with history. The first try, with a zero root, reads the DB's genesis
# validators root from the error; the second must import.
km() {
  curl -sS --cacert "$work/root.pem" -H "Authorization: Bearer $(cat "$work/data/api-token.txt")" \
    -H "Content-Type: application/json" -H "Transfer-Encoding: chunked" --data-binary @"$1" \
    "https://127.0.0.1:$kmport/eth/v1/keystores"
}
importbody() {
  python3 -I -c '
import json, sys
x = {"metadata": {"interchange_format_version": "5", "genesis_validators_root": sys.argv[1]},
     "data": [{"pubkey": "0x" + "ab" * 48,
               "signed_blocks": [{"slot": str(s)} for s in range(2000)],
               "signed_attestations": [{"source_epoch": str(e), "target_epoch": str(e + 1),
                                        "signing_root": "0x%064x" % (e + 1)} for e in range(2000)]}]}
print(json.dumps({"keystores": [], "passwords": [], "slashing_protection": json.dumps(x)}))' "$1" > "$2"
}
importbody "0x$(printf '00%.0s' {1..32})" "$work/import0.json"
gvr=$(km "$work/import0.json" | grep -o 'the DB for 0x[0-9a-f]*' | sed 's/the DB for //' || true)
[ -n "$gvr" ] || { echo "no genesis validators root in the import error"; exit 1; }
importbody "$gvr" "$work/import.json"
km "$work/import.json" > "$work/import-answer.json"
grep -q '"data":\[\]' "$work/import-answer.json" || { echo "import: $(cat "$work/import-answer.json")"; exit 1; }
echo "keymanager import, chunked, $(wc -c < "$work/import.json") bytes with history: $(cat "$work/import-answer.json")"
kill "$vc"; wait "$vc" 2>/dev/null || true
vc=
grep -E "doppelganger|ready:" "$work/vc.log" | head -n 5
grep -E '^eplix_(duties_completed_total|keys\{state="(active|doppelganger_wait)"\}|signing_duration_seconds_count|slashing_db_keys|beacon_node_score)' "$work/metrics.txt"
echo "metrics lines: $(wc -l < "$work/metrics.txt")"
# SMOKE_METRICS_OUT: keep the scrape for scripts/check-ops.py.
[ -n "${SMOKE_METRICS_OUT:-}" ] && cp "$work/metrics.txt" "$SMOKE_METRICS_OUT"
grep -qE '^eplix_duties_completed_total\{duty="attestation"\} [1-9]' "$work/metrics.txt"
grep -qE '^eplix_keys\{state="active"\} 1$' "$work/metrics.txt"
grep -qE '^eplix_signing_duration_seconds_count\{backend="local",duty="attestation"\} [1-9]' "$work/metrics.txt"
grep -qE '^eplix_process_working_set_bytes [1-9]' "$work/metrics.txt"
# The keymanager certificate loads before the metrics module listens; its expiry still shows.
grep -qE '^eplix_tls_cert_not_after_seconds\{name="tls_cert",use="keymanager"\} [1-9]' "$work/metrics.txt"
grep -qE '^eplix_process_cpu_seconds_total\{mode="user"\} ' "$work/metrics.txt"
grep -qE '^eplix_gc_collections_total\{generation="0"\} ' "$work/metrics.txt"
grep -E '^eplix_(process|gc|threadpool|monitor)_' "$work/metrics.txt" | head -n 20
grep -q "doppelganger check passed" "$work/vc.log"
grep -q '"validating_pubkey"' "$work/keystores.json"
echo "keymanager over HTTPS: $(cat "$work/keystores.json" | head -c 120)"
bodies=$(ls "$work/otlp" | wc -l)
echo "OTLP bodies received: $bodies"
[ "$bodies" -gt 0 ]
grep -qa "attestations" "$work"/otlp/*.bin
grep -qa "sign burst" "$work"/otlp/*.bin
grep -qa "service.name" "$work"/otlp/*.bin
echo "smoke ok: the published binary waits for the doppelganger check, attests, serves /metrics with the runtime meters, the keymanager API over HTTPS with a streamed import, and spans over OTLP"
