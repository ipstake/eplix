#!/usr/bin/env bash
# Runs the published binary under the file system limits of contrib/systemd/eplix.service, without
# systemd: a user and mount namespace (unshare) with the top-level directories read-only, the data
# dir the only writable path among them, a private /tmp, no new privileges and an empty capability
# set (setpriv).
# Against scripts/fake-beacon-node.py with 2 s slots and 8 slots an epoch, for 4 epochs. Passes
# when every key attests in every whole epoch and the log has no ERROR line. It also saves the
# VC's /metrics to <out>/metrics.txt, which scripts/check-ops.py reads.
# What it does not cover: the system call filter, address families, the dedicated user and the
# other Protect* settings, which need systemd (systemd-analyze security eplix on a systemd host).
# Run after scripts/publish-aot.sh and a Debug build of the tests (the keystore writer).
# Usage: contrib/systemd/sandbox-check.sh [keys] [port]   (default 64 keys, ports 19591 to 19593)
set -euo pipefail
cd "$(dirname "$0")/../.."
keys="${1:-64}"
port="${2:-19591}"
bin="$PWD/artifacts/publish/linux-x64/eplix"
tests="$PWD/tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll"
out="$PWD/artifacts/sandbox-check/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
# Outside /tmp, which the sandbox replaces.
work=$(mktemp -d -p "$PWD/artifacts")
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
timeout 600 dotnet "$tests" write-keystores "$work" "$keys" > /dev/null
mkdir -p "$work/state"
FAKE_BN_ATTESTATIONS="$out/attestations.jsonl" python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 8 > "$out/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "$work/chain.yaml", "data_dir": "$work/state",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": { "local": { "keystores": [ { "path": "$work/keys", "password_file": "$work/password.txt" } ], "reload_interval_seconds": 0 },
    "keymanager": { "port": $((port + 1)) }, "metrics": { "port": $((port + 2)) }, "doppelganger": { "enabled": false } } }
J
# The sandbox, close to what ProtectSystem=strict builds: every top-level directory bound
# read-only over itself, a tmpfs on /tmp, the data dir bound writable again, then setpriv. The
# unit has ProtectHome=yes, which hides /home; here /home stays readable because the binary and
# the data dir of this check live in the repo under /home (the unit's are /usr/local/lib/eplix
# and /var/lib/eplix). Inside the user namespace the process is root over its own files only. (A chroot into
# a read-only bind of / instead makes the AOT binary crash with SIGSEGV after the key decryption,
# even with the bind writable; systemd does not chroot, so this check does not either.)
sandbox='
  set -e
  state=$1; shift
  for d in /usr /etc /home /opt /var /root /srv /boot /mnt; do
    # --rbind: /usr and /mnt have mounts below them, which a plain bind refuses here.
    if [ -d "$d" ]; then mount --rbind "$d" "$d"; mount -o remount,bind,ro "$d"; fi
  done
  mount -t tmpfs -o size=64m tmpfs /tmp
  mount --bind "$state" "$state"
  mount -o remount,bind,rw "$state"
  exec setpriv --no-new-privs --bounding-set=-all --inh-caps=-all "$@"
'
unshare --user --map-root-user --mount --propagation private sh -c "$sandbox" sandbox "$work/state" "$bin" run --config "$work/eplix.json" > "$out/vc.log" 2>&1 &
vc=$!
sleep 66
kill -0 "$vc" 2>/dev/null || { echo "the VC exited"; tail -20 "$out/vc.log"; exit 1; }
curl -fsS "http://127.0.0.1:$((port + 2))/metrics" > "$out/metrics.txt"
# The sandbox holds: a write next to the data dir fails, a write in it works.
if unshare --user --map-root-user --mount --propagation private sh -c "$sandbox" sandbox "$work/state" touch "$work/probe" 2>/dev/null; then
  echo "the sandbox accepted a write outside the data dir" >&2
  exit 1
fi
unshare --user --map-root-user --mount --propagation private sh -c "$sandbox" sandbox "$work/state" touch "$work/state/probe"
rm -f "$work/state/probe"
kill "$vc"
wait "$vc" 2>/dev/null || true
python3 -I - "$out/attestations.jsonl" "$keys" 8 <<'PY'
import collections, json, sys
keys, spe = int(sys.argv[2]), int(sys.argv[3])
per_epoch = collections.defaultdict(set)
for l in open(sys.argv[1]):
    a = json.loads(l)
    per_epoch[a["slot"] // spe].add(a["attester_index"])
whole = sorted(per_epoch)[1:-1]
assert whole, "no whole epoch"
missed = {e: keys - len(per_epoch[e]) for e in whole if len(per_epoch[e]) != keys}
assert not missed, f"missed duties per epoch: {missed}"
print(f"{len(whole)} whole epochs, every key attested")
PY
if grep -q "ERROR" "$out/vc.log"; then
  grep "ERROR" "$out/vc.log" | head -5 >&2
  echo "errors in the VC log" >&2
  exit 1
fi
ls "$work/state" > "$out/data-dir.txt"
echo "sandbox ok: $keys keys; data dir holds $(tr '\n' ' ' < "$out/data-dir.txt"); log in $out"
