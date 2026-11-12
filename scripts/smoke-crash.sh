#!/usr/bin/env bash
# kill -9 of the published binary while it signs, on a real file system: 64 keys against
# scripts/fake-beacon-node.py (2 s slots, 4 slots an epoch, so 16 attestations a slot), killed at a
# random offset of 0 to 2,000 ms after each start, then started again. After every kill:
#   - `eplix slashing export` opens the DB (cutting a torn tail) or fails closed with a named
#     error, never an unhandled exception;
#   - every attestation the fake node received is covered by the exported marks of its key (no
#     mark lost for anything that left the VC);
#   - no two different attestations for one key and target reached the fake node (no double vote).
# Run after scripts/publish-aot.sh and a Debug build of the tests (the keystore writer).
# Usage: scripts/smoke-crash.sh [rounds] [rid]   (default 200 rounds, linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rounds="${1:-200}"
rid="${2:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
tests="$PWD/tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll"
work=$(mktemp -d)
port=19471
cleanup() {
  kill -9 "${vc:-}" 2>/dev/null || true
  kill "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
timeout 120 dotnet "$tests" write-keystores "$work" 64 > /dev/null
FAKE_BN_ATTESTATIONS="$work/attestations.jsonl" python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 4 > "$work/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
    "keymanager": { "port": 19472 }, "metrics": { "port": 19473 }, "doppelganger": { "enabled": false } } }
J
touch "$work/attestations.jsonl"
check() {
  # The DB opens, or fails with a named error; then marks cover what the node received.
  local out rc
  set +e
  out=$(timeout 60 "$bin" slashing export --config "$work/eplix.json" --file "$work/export.json" 2>&1)
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    if echo "$out" | grep -q -E "Unhandled|Exception|   at "; then
      echo "round $1: export crashed: $out" >&2
      return 1
    fi
    if echo "$out" | grep -q "no slashing DB in the data dir"; then
      # Killed before the DB existed: nothing can have been signed.
      [ ! -s "$work/attestations.jsonl" ] || { echo "round $1: no DB but attestations were sent" >&2; return 1; }
      return 0
    fi
    echo "round $1: the DB fails closed: $out" >&2
    return 2
  fi
  python3 -I - "$work/attestations.jsonl" "$work/export.json" "$work/pubkeys.txt" <<'PY'
import collections, json, sys
atts = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
export = json.load(open(sys.argv[2]))
keys = [l.strip() for l in open(sys.argv[3]) if l.strip()]
marks = {}
for d in export["data"]:
    a = d.get("signed_attestations", [])
    marks[d["pubkey"]] = (max([int(x["source_epoch"]) for x in a], default=-1), max([int(x["target_epoch"]) for x in a], default=-1))
votes = collections.defaultdict(set)
for a in atts:
    pk = keys[a["attester_index"]]
    s, t = marks.get(pk, (-1, -1))
    assert t >= a["target"] and s >= a["source"], f"key {a['attester_index']}: the node got {a['source']}->{a['target']}, marks are {s}->{t}"
    votes[(a["attester_index"], a["target"])].add((a["source"], a["root"], a["slot"]))
double = {k: v for k, v in votes.items() if len(v) > 1}
assert not double, f"double votes reached the node: {double}"
PY
}
start=$(date +%s)
for round in $(seq 1 "$rounds"); do
  "$bin" run --config "$work/eplix.json" >> "$work/vc.log" 2>&1 &
  vc=$!
  sleep "$(python3 -I -c 'import random; print(f"{random.uniform(0, 2):.3f}")')"
  kill -9 "$vc" 2>/dev/null || true
  wait "$vc" 2>/dev/null || true
  if ! check "$round"; then
    rc=$?
    if [ "$rc" -eq 2 ]; then
      # Failing closed is allowed: the VC must then refuse to start as well.
      if timeout 30 "$bin" run --config "$work/eplix.json" > "$work/refuse.log" 2>&1; then
        echo "round $round: the VC started on a DB the export refused" >&2; exit 1
      fi
      echo "round $round: the DB failed closed with a named error; stopping here"
      break
    fi
    tail -20 "$work/vc.log" >&2
    exit 1
  fi
done
n=$(wc -l < "$work/attestations.jsonl")
echo "smoke ok: $rounds kill -9 rounds in $(( $(date +%s) - start )) s, $n attestations at the node, no mark lost, no double vote"
[ "$n" -gt 0 ] || { echo "no attestation ever left the VC" >&2; exit 1; }
