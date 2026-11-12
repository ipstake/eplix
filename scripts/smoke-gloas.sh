#!/usr/bin/env bash
# Smoke test of the published binary across the Gloas fork: one local key (the EIP-2335 PBKDF2
# test keystore) against scripts/fake-beacon-node.py with Gloas at epoch 1 (2 s slots, 8 slots an
# epoch). Passes when the binary attests in both forks and casts a PTC vote after the fork.
# The key gets its record from an EIP-3076 file with one block at slot 0: a floor record (the
# override, or import --no-signing-history) would hold it back past the fork.
# Run after scripts/publish-aot.sh. Usage: scripts/smoke-gloas.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
work=$(mktemp -d)
port=19451
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
echo 0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07 > "$work/pubkeys.txt"
# Genesis 5 s ahead, so the VC is up before the one Fulu duty (slot 0).
FAKE_BN_GENESIS=$(( $(date +%s) + 5 )) python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 8 1 > "$work/bn.log" 2>&1 &
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
    "keymanager": { "port": 19452 }, "metrics": { "port": 19453 }, "doppelganger": { "enabled": false } } }
J
gvr=$(curl -fsS "http://127.0.0.1:$port/eth/v1/beacon/genesis" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["data"]["genesis_validators_root"])')
cat > "$work/history.json" <<J
{ "metadata": { "interchange_format_version": "5", "genesis_validators_root": "$gvr" },
  "data": [ { "pubkey": "$(cat "$work/pubkeys.txt")", "signed_blocks": [ { "slot": "0" } ], "signed_attestations": [] } ] }
J
"$bin" slashing import --config "$work/eplix.json" --file "$work/history.json"
"$bin" run --config "$work/eplix.json" > "$work/vc.log" 2>&1 &
vc=$!
sleep 36
kill "$vc" 2>/dev/null || true
wait "$vc" 2>/dev/null || true
cat "$work/bn.log"
grep -q "(fulu)" "$work/bn.log" || { echo "no Fulu attestation" >&2; tail -20 "$work/vc.log" >&2; exit 1; }
grep -q "(gloas)" "$work/bn.log" || { echo "no Gloas attestation" >&2; tail -20 "$work/vc.log" >&2; exit 1; }
grep -q "payload attestations" "$work/bn.log" || { echo "no PTC vote" >&2; tail -20 "$work/vc.log" >&2; exit 1; }
grep -E "ERROR" "$work/vc.log" && { echo "errors in the VC log" >&2; exit 1; }
echo "smoke ok: the published binary attests in Fulu and Gloas and casts PTC votes"
