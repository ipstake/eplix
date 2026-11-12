#!/usr/bin/env bash
# Smoke test through a load-test gateway (a Web3Signer-compatible API in front of Dirk
# distributed accounts): the gateway signs for the Dist accounts of the cluster from
# scripts/dirk-local.sh, pinned to the chain of the in-process fake beacon node, and the
# web3signer-gateway tests sign every duty kind through it and check that a double vote
# (Dirk refuses, the gateway answers 412) halts the key. Wipes Dirk's slashing protection first.
# Usage: scripts/gateway-smoke.sh <cluster dir> <gateway binary>   (dirk and ethdo on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
net=$(cd "${1:?cluster directory}" && pwd)
gateway=$(realpath "${2:?gateway binary}")
work=$(mktemp -d)
cleanup() {
  [ -n "${gw:-}" ] && kill "$gw" 2>/dev/null || true
  bash scripts/dirk-local.sh stop "$net" > /dev/null
  rm -rf "$work"
}
trap cleanup EXIT

bash scripts/dirk-local.sh wipe-protection "$net"
bash scripts/dirk-local.sh start "$net"
# The chain of tests/Eplix.Tests/FakeBeaconNode.fs (minimal preset, Fulu at epoch 1).
cat > "$work/gateway.yml" <<Y
listen: 127.0.0.1:19000
chain:
  preset: minimal
  genesis_fork_version: "0x00000001"
  genesis_validators_root: "0xa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
  seconds_per_slot: 6
  forks:
    - {epoch: 0, version: "0x01000001"}
    - {epoch: 0, version: "0x02000001"}
    - {epoch: 0, version: "0x03000001"}
    - {epoch: 0, version: "0x04000001"}
    - {epoch: 0, version: "0x05000001"}
    - {epoch: 1, version: "0x06000001"}
dirk:
  wallet: Dist
  endpoints: ["dirk1:19591", "dirk2:19592", "dirk3:19593"]
  client_cert: $net/certs/eplix.crt
  client_key: $net/certs/eplix.key
  ca_cert: $net/certs/ca.crt
  timeout: 5s
policy:
  fee_recipient_allowlist: ["0x1111111111111111111111111111111111111111"]
Y
"$gateway" -config "$work/gateway.yml" > "$work/gateway.log" 2>&1 &
gw=$!
for _ in $(seq 1 100); do curl -sf http://127.0.0.1:19000/upcheck > /dev/null && break; sleep 0.1; done
dotnet build tests/Eplix.Tests -c Release -nologo -v q
EPLIX_GATEWAY_URL=http://127.0.0.1:19000 dotnet tests/Eplix.Tests/bin/Release/net10.0/Eplix.Tests.dll \
  --filter-test-list web3signer-gateway --summary || { tail -n 20 "$work/gateway.log"; exit 1; }
grep -cE '"msg":"signed"|msg=signed' "$work/gateway.log" | sed 's/^/gateway signed lines: /' || true
grep -E 'denied|refused|412' "$work/gateway.log" | tail -n 3 || true
