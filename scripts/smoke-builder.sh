#!/usr/bin/env bash
# Smoke test of the published binary's pre-Gloas builder flow: one local key (the EIP-2335 PBKDF2
# test keystore) against scripts/fake-beacon-node.py in builder mode (FAKE_BN_BUILDER=1: a node
# with MEV-Boost that answers produceBlockV3 with a blinded block). Passes when the binary sends a
# validator registration with the configured fee recipient, asks for the block with
# builder_boost_factor 100, and publishes the signed blinded block to the blinded endpoint.
# It also checks /metrics for the registration and blinded block counters; with SMOKE_METRICS_OUT
# set, the scrape is copied there (scripts/check-ops.py reads it).
# The key gets its record from an EIP-3076 file with one block at slot 0: the start floor of
# allow_start_without_history (the clock epoch + 1) would refuse the proposal in slot 3.
# Run after scripts/publish-aot.sh. Usage: scripts/smoke-builder.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
work=$(mktemp -d)
port=19461
fee=0x00000000000000000000000000000000000000aa
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
echo 0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07 > "$work/pubkeys.txt"
# Genesis 5 s ahead, so the VC is up before the proposal in slot 3.
FAKE_BN_BUILDER=1 FAKE_BN_GENESIS=$(( $(date +%s) + 5 )) python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 8 > "$work/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "use_events": false, "fee_recipient": "$fee",
  "modules": { "local": { "keystores": [
    { "path": "$PWD/tests/fixtures/eip2335/pbkdf2.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" } ] },
    "builder_legacy": { "enabled": true },
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
sleep 14
curl -fsS "http://127.0.0.1:19463/metrics" > "$work/metrics.txt" || true
kill "$vc" 2>/dev/null || true
wait "$vc" 2>/dev/null || true
cat "$work/bn.log"
fail() { echo "$1" >&2; tail -30 "$work/vc.log" >&2; exit 1; }
grep -q "registration of $(cat "$work/pubkeys.txt") fee recipient $fee gas limit 60000000" "$work/bn.log" || fail "no validator registration"
grep -q "produce block for slot 3 with builder_boost_factor 100" "$work/bn.log" || fail "no builder block request"
grep -q "published blinded block for slot 3 (application/octet-stream, fulu" "$work/bn.log" || fail "no blinded block published"
grep -q "slot 3: builder block 0x" "$work/vc.log" || fail "the VC did not log the builder block"
grep -qE '^eplix_validator_registrations_total\{node="[^"]+",result="accepted"\} [1-9]' "$work/metrics.txt" || fail "no accepted registration in /metrics"
grep -qE '^eplix_blinded_blocks_total\{result="published"\} 1$' "$work/metrics.txt" || fail "no published blinded block in /metrics"
[ -n "${SMOKE_METRICS_OUT:-}" ] && cp "$work/metrics.txt" "$SMOKE_METRICS_OUT"
grep -E "ERROR" "$work/vc.log" && fail "errors in the VC log"
echo "smoke ok: the published binary registers, asks for a builder block and publishes it blinded"
