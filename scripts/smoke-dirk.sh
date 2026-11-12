#!/usr/bin/env bash
# Smoke test of the published binary with the Dirk module: eplix attests for the Dirk cluster's
# accounts (wallets Dist and Solo) against scripts/fake-beacon-node.py, first with three Dirk
# instances and then with dirk3 stopped. Run after scripts/publish-aot.sh and
# scripts/dirk-local.sh setup. Wipes Dirk's slashing protection first.
# Usage: scripts/smoke-dirk.sh <cluster dir> [seconds per phase]   (dirk and ethdo on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
net=$(cd "${1:?cluster directory}" && pwd)
phase=${2:-24}
bin="$PWD/artifacts/publish/linux-x64/eplix"
work=$(mktemp -d)
port=15052
cleanup() {
  [ -n "${vc:-}" ] && kill "$vc" 2>/dev/null || true
  [ -n "${bn:-}" ] && kill "$bn" 2>/dev/null || true
  bash scripts/dirk-local.sh start "$net" 3 > /dev/null
  rm -rf "$work"
}
trap cleanup EXIT

bash scripts/dirk-local.sh wipe-protection "$net"
bash scripts/dirk-local.sh start "$net"
ethdo_list() {
  ethdo --remote dirk1:19591 --server-ca-cert "$net/certs/ca.crt" --client-cert "$net/certs/admin.crt" \
    --client-key "$net/certs/admin.key" wallet accounts --wallet "$1" --verbose
}
{ ethdo_list Dist | sed -n 's/^ *Composite public key: //p'; ethdo_list Solo | sed -n 's/^ *Public key: //p'; } > "$work/pubkeys.txt"
echo "$(wc -l < "$work/pubkeys.txt") keys"

cat > "$work/chain.yaml" <<'Y'
CONFIG_NAME: 'fake'
PRESET_BASE: 'minimal'
SECONDS_PER_SLOT: 2
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
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"],
  "modules": { "doppelganger": { "enabled": false }, "dirk": {
    "endpoints": [ "dirk1:19591", "dirk2:19592", "dirk3:19593" ],
    "accounts": [ "Dist", "Solo" ],
    "ca_cert": "$net/certs/ca.crt", "client_cert": "$net/certs/eplix.crt", "client_key": "$net/certs/eplix.key" } } }
J
python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 8 > "$work/bn.log" 2>&1 &
bn=$!
sleep 0.5
(cd "$work" && exec "$bin" run --config eplix.json) > "$work/vc.log" 2>&1 &
vc=$!
sleep "$phase"
bash scripts/dirk-local.sh stop "$net" 3
mark=$(wc -l < "$work/vc.log")
sleep "$phase"
kill "$vc"; wait "$vc" 2>/dev/null || true
vc=
grep -E "dirk:|ready:" "$work/vc.log"
echo "--- with three Dirk instances"
head -n "$mark" "$work/vc.log" | grep -E "slot [0-9]+: " | tail -n 4
echo "--- with dirk3 stopped"
tail -n +"$((mark + 1))" "$work/vc.log" | grep -E "slot [0-9]+: " | tail -n 4
signed=$(tail -n +"$((mark + 1))" "$work/vc.log" | grep -cE "slot [0-9]+: [0-9]+ duties, [1-9][0-9]* signed, 0 refused, 0 failed, submitted True" || true)
failed=$(grep -E "slot [0-9]+: [0-9]+ duties" "$work/vc.log" | grep -vcE " 0 refused, 0 failed" || true)
echo "slots signed with dirk3 down: $signed; slots with a refusal or failure: $failed"
grep -E "slot [0-9]+: [0-9]+ duties" "$work/vc.log" | grep -vE " 0 refused, 0 failed" || true
grep -E "ERROR|WARN" "$work/vc.log" | grep -v -E "starting without slashing history|HTTP 404" | head -n 5 || true
[ "$signed" -gt 0 ] && [ "$failed" -eq 0 ]
echo "smoke ok: the published binary attests through Dirk, also with one of three down"
