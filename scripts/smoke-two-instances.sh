#!/usr/bin/env bash
# Two published binaries on one data dir: the second must exit non-zero with "in use by another
# process" while the first keeps attesting, and the fake beacon node must see one attestation per
# duty.
# The key gets its record from an EIP-3076 file with one block at slot 0: the start floor of
# allow_start_without_history (the clock epoch + 1) would hold its attestations back.
# Run after scripts/publish-aot.sh. Usage: scripts/smoke-two-instances.sh [rid]
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
work=$(mktemp -d)
port=19461
cleanup() {
  kill "${vc:-}" "${vc2:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
echo 0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07 > "$work/pubkeys.txt"
FAKE_BN_ATTESTATIONS="$work/attestations.jsonl" python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 4 > "$work/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "use_events": false,
  "modules": { "local": { "keystores": [
    { "path": "$PWD/tests/fixtures/eip2335/pbkdf2.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" } ] },
    "keymanager": { "port": 19462 }, "metrics": { "port": 19463 }, "doppelganger": { "enabled": false } } }
J
gvr=$(curl -fsS "http://127.0.0.1:$port/eth/v1/beacon/genesis" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["data"]["genesis_validators_root"])')
cat > "$work/history.json" <<J
{ "metadata": { "interchange_format_version": "5", "genesis_validators_root": "$gvr" },
  "data": [ { "pubkey": "$(cat "$work/pubkeys.txt")", "signed_blocks": [ { "slot": "0" } ], "signed_attestations": [] } ] }
J
"$bin" slashing import --config "$work/eplix.json" --file "$work/history.json"
"$bin" run --config "$work/eplix.json" > "$work/vc.log" 2>&1 &
vc=$!
# Wait until the first VC holds the lock and is ready.
for _ in $(seq 1 100); do grep -q "ready:" "$work/vc.log" && break; sleep 0.1; done
grep -q "ready:" "$work/vc.log" || { echo "first VC not ready" >&2; cat "$work/vc.log" >&2; exit 1; }
set +e
timeout 20 "$bin" run --config "$work/eplix.json" > "$work/vc2.log" 2>&1
rc2=$?
set -e
[ "$rc2" -ne 0 ] || { echo "the second VC exited 0" >&2; cat "$work/vc2.log" >&2; exit 1; }
[ "$rc2" -ne 124 ] || { echo "the second VC was still running after 20 s" >&2; cat "$work/vc2.log" >&2; exit 1; }
grep -q "in use by another process" "$work/vc2.log" || { echo "no lock error from the second VC" >&2; cat "$work/vc2.log" >&2; exit 1; }
sleep 20
kill "$vc" 2>/dev/null || true
wait "$vc" 2>/dev/null || true
python3 -I - "$work/attestations.jsonl" <<'PY'
import collections, json, sys
seen = collections.Counter()
for line in open(sys.argv[1]):
    a = json.loads(line)
    seen[(a["attester_index"], a["slot"])] += 1
assert len(seen) >= 2, f"{len(seen)} attestations reached the fake node, expected one per epoch"
dup = [k for k, n in seen.items() if n > 1]
assert not dup, f"more than one attestation for (validator, slot): {dup}"
print(f"{len(seen)} duties, one attestation each")
PY
grep -E "ERROR" "$work/vc.log" && { echo "errors in the first VC's log" >&2; exit 1; }
echo "smoke ok: a second VC on the same data dir exits with the lock error, the first attests once per duty"
