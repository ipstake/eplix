#!/usr/bin/env bash
# Leaving Eplix: its EIP-3076 export must import into every other client, and each client's own
# export must then hold marks at or above Eplix's (max block slot, max attestation source and
# target per key). Offline: no beacon node, no network.
# Needs the published binary (scripts/publish-aot.sh; built here if missing) and the client
# binaries under CLIENTS (default ~/.cache/eplix/clients). Teku needs a JRE: JAVA_HOME, or the
# default below under EPLIX_TOOLS.
# Usage: scripts/interchange-out.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
cache="${EPLIX_CACHE:-$HOME/.cache/eplix}"
clients="${CLIENTS:-$cache/clients}"
export JAVA_HOME="${JAVA_HOME:-${EPLIX_TOOLS:-$cache/tools}/jdk-25.0.5+8-jre}"
lighthouse="$clients/lighthouse/lighthouse"
teku="$clients/teku/teku-26.10.2/bin/teku"
nimbus="$clients/nimbus/nimbus-eth2_Linux_amd64_26.10.2_0abc0dd0/build/nimbus_beacon_node"
lodestar="$clients/lodestar/lodestar"
prysm="$clients/prysm/validator"

[[ -x "$bin" ]] || timeout 900 scripts/publish-aot.sh "$rid"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mainnet_gvr=0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95

# Source history: three keys, blocks and attestations with and without signing roots, out of
# order, one key with blocks only. Eplix imports it; its export is the file under test.
cat > "$work/source.json" <<J
{ "metadata": { "interchange_format_version": "5", "genesis_validators_root": "$mainnet_gvr" },
  "data": [
  { "pubkey": "0x849b4bcd8670f81909baad27c4d9c8d9b956b19192f12af8fe57d30731fa11a55a97a1ab72bb1cfd76c1461dcaba714a",
    "signed_blocks": [
      { "slot": "81952", "signing_root": "0x$(printf '11%.0s' {1..32})" },
      { "slot": "81951" },
      { "slot": "81960", "signing_root": "0x$(printf '12%.0s' {1..32})" } ],
    "signed_attestations": [
      { "source_epoch": "2290", "target_epoch": "3007", "signing_root": "0x$(printf '21%.0s' {1..32})" },
      { "source_epoch": "3006", "target_epoch": "3008" },
      { "source_epoch": "3007", "target_epoch": "3009", "signing_root": "0x$(printf '22%.0s' {1..32})" } ] },
  { "pubkey": "0x92f46b0dcc7db24f4946b5773b5525efa0bbb0810088588323d9de84f0e42f22df96cbb97065b49a2006c653ec8060f4",
    "signed_blocks": [ { "slot": "1000" } ],
    "signed_attestations": [
      { "source_epoch": "30", "target_epoch": "31" },
      { "source_epoch": "31", "target_epoch": "32", "signing_root": "0x$(printf '31%.0s' {1..32})" } ] },
  { "pubkey": "0x9948ea3862b8889636c3caeaa1b9877a12cffca9bf6a1ef2264fa7e69604d55c56b4f519062e6785d21d3c9593c2adcd",
    "signed_blocks": [ { "slot": "123456", "signing_root": "0x$(printf '41%.0s' {1..32})" } ],
    "signed_attestations": [] } ] }
J
printf 'CONFIG_NAME: mainnet\nGENESIS_FORK_VERSION: 0x00000000\n' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:1", "chain_config": "chain.yaml", "data_dir": "data", "modules": {} }
J
timeout 60 "$bin" slashing import --config "$work/eplix.json" --file "$work/source.json"
timeout 60 "$bin" slashing export --config "$work/eplix.json" --file "$work/eplix-export.json"

# Exits non-zero unless the client export ($2) covers every key of the Eplix export ($1) with
# marks at or above Eplix's, under the same genesis validators root.
compare() {
  python3 -I - "$1" "$2" <<'PY'
import json, sys
def marks(path):
    x = json.load(open(path))
    out = {}
    for d in x["data"]:
        b = [int(e["slot"]) for e in d.get("signed_blocks", [])]
        a = d.get("signed_attestations", [])
        out[d["pubkey"].lower()] = (max(b, default=None),
                                    max((int(e["source_epoch"]) for e in a), default=None),
                                    max((int(e["target_epoch"]) for e in a), default=None))
    return x["metadata"]["genesis_validators_root"].lower(), out
gvr_e, eplix = marks(sys.argv[1])
gvr_c, client = marks(sys.argv[2])
errs = [] if gvr_e == gvr_c else [f"genesis validators root {gvr_c} != {gvr_e}"]
for pk, want in eplix.items():
    got = client.get(pk)
    if got is None:
        errs.append(f"{pk[:12]}: missing")
        continue
    for name, w, g in zip(("block slot", "source", "target"), want, got):
        if w is not None and (g is None or g < w):
            errs.append(f"{pk[:12]}: {name} {g} < {w}")
if errs:
    print("; ".join(errs))
    sys.exit(1)
print(f"{len(eplix)} keys, marks >= eplix")
PY
}

# Runs one client step under a time limit, its output in a log printed on failure.
step() {
  local log="$1"; shift
  local rc=0
  timeout 120 "$@" > "$log" 2>&1 || rc=$?
  ((rc == 0)) && return 0
  echo "--- $log (exit $rc):" >&2
  tail -20 "$log" >&2
  return 1
}

in="$work/eplix-export.json"
# The export under test must itself keep the source marks, or the client checks prove little.
res=$(compare "$work/source.json" "$in") || { echo "eplix export: marks FAILED: $res" >&2; exit 1; }
echo "eplix export vs source: ${res/eplix/source}"
# Lighthouse imports history only into an existing slashing DB, which a keystore import creates.
import_lighthouse() {
  cp tests/fixtures/eip2335/pbkdf2.json "$1/keystore-a.json"
  step "$1/keys.log" "$lighthouse" account validator import --network mainnet --datadir "$1/dd" \
    --keystore "$1/keystore-a.json" --reuse-password --password-file tests/fixtures/eip2335/password.txt \
    --stdin-inputs < /dev/null || return 1
  step "$1/import.log" "$lighthouse" account validator slashing-protection import --network mainnet --datadir "$1/dd" "$in"
}
export_lighthouse() { step "$1/export.log" "$lighthouse" account validator slashing-protection export --network mainnet --datadir "$1/dd" "$1/out.json"; }
import_teku() { step "$1/import.log" "$teku" slashing-protection import --data-path "$1/dd" --from "$in"; }
export_teku() { step "$1/export.log" "$teku" slashing-protection export --data-path "$1/dd" --to "$1/out.json"; }
import_nimbus() { step "$1/import.log" "$nimbus" slashingdb import --network=mainnet --data-dir="$1/dd" "$in"; }
export_nimbus() { step "$1/export.log" "$nimbus" slashingdb export --network=mainnet --data-dir="$1/dd" "$1/out.json"; }
import_lodestar() { step "$1/import.log" "$lodestar" validator slashing-protection import --network mainnet --dataDir "$1/dd" --file "$in"; }
export_lodestar() { step "$1/export.log" "$lodestar" validator slashing-protection export --network mainnet --dataDir "$1/dd" --file "$1/out.json"; }
# Prysm imports only into an existing validator.db, and only its validator client creates one.
# Start it with a remote-signer key and unreachable local beacon node and signer, stop it once
# the DB is on disk.
init_prysm() {
  timeout 60 "$prysm" --datadir "$1/dd" --accept-terms-of-use --disable-monitoring \
    --remote-signer-url http://127.0.0.1:1 --remote-signer-keys "$(python3 -I -c \
      'import json,sys; print(json.load(open(sys.argv[1]))["data"][0]["pubkey"])' "$in")" \
    --beacon-rpc-provider 127.0.0.1:1 --beacon-rest-api-provider http://127.0.0.1:1 \
    > "$1/init.log" 2>&1 &
  local pid=$! i
  for i in $(seq 60); do
    [[ -s "$1/dd/validator.db" ]] && break
    sleep 0.5
  done
  kill -TERM "$pid" 2>/dev/null || true
  timeout 30 tail --pid="$pid" -f /dev/null || kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  [[ -s "$1/dd/validator.db" ]] || { echo "prysm: no validator.db after start" >&2; tail -20 "$1/init.log" >&2; return 1; }
}
import_prysm() { init_prysm "$1" || return 1; step "$1/import.log" "$prysm" slashing-protection-history import --datadir "$1/dd" --slashing-protection-json-file "$in" --accept-terms-of-use; }
export_prysm() {
  mkdir -p "$1/exp"
  step "$1/export.log" "$prysm" slashing-protection-history export --datadir "$1/dd" --slashing-protection-export-dir "$1/exp" --accept-terms-of-use || return 1
  local f=("$1"/exp/*.json)
  [[ ${#f[@]} -eq 1 && -f "${f[0]}" ]] && cp "${f[0]}" "$1/out.json"
}

failed=()
for c in lighthouse teku nimbus lodestar prysm; do
  d="$work/$c"
  mkdir -p "$d/dd"
  if ! "import_$c" "$d"; then
    echo "$c: import FAILED"; failed+=("$c"); continue
  fi
  if ! "export_$c" "$d"; then
    echo "$c: import ok, export FAILED"; failed+=("$c"); continue
  fi
  if res=$(compare "$in" "$d/out.json"); then
    echo "$c: import ok, export ok, marks compared: $res"
  else
    echo "$c: import ok, export ok, marks FAILED: $res"; failed+=("$c")
  fi
done
if ((${#failed[@]})); then
  echo "interchange-out FAILED for: ${failed[*]}" >&2
  exit 1
fi
echo "interchange-out ok: the Eplix export imports into all five clients"
