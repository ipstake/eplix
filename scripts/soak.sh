#!/usr/bin/env bash
# Soak test of the published binary: 1,000 keys against scripts/fake-beacon-node.py with 2 s slots
# and 8 slots an epoch, for 24 h by default. SOAK_KEYS, SOAK_SECONDS_PER_SLOT and
# SOAK_SLOTS_PER_EPOCH change the key count and the slot timing (a mainnet-scale run uses
# 10000 keys, 12 s slots and 32 slots an epoch, which keeps the attestation log near 1 GB a day);
# SOAK_PORT moves the three ports (default 19491 to 19493). Every minute it samples the VC's
# resident memory, open file descriptors and CPU time. Passes when, after the first quarter of the
# run (the first hour of 24 h):
#   - RSS and open descriptors stay flat: the mean of the last quarter is at most 15% (RSS) and
#     10 descriptors above the mean of the second quarter;
#   - no duty is missed: every key has one attestation in every whole epoch the node saw;
#   - the VC log has no ERROR line.
# Run after scripts/publish-aot.sh and a Debug build of the tests (the keystore writer).
# Usage: scripts/soak.sh [seconds] [rid]   (default 86400 s, linux-x64). Samples and logs stay in
# artifacts/soak/<UTC time>/.
set -euo pipefail
cd "$(dirname "$0")/.."
duration="${1:-86400}"
rid="${2:-linux-x64}"
keys="${SOAK_KEYS:-1000}"
sps="${SOAK_SECONDS_PER_SLOT:-2}"
spe="${SOAK_SLOTS_PER_EPOCH:-8}"
bin="$PWD/artifacts/publish/$rid/eplix"
tests="$PWD/tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll"
out="$PWD/artifacts/soak/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
work=$(mktemp -d)
port="${SOAK_PORT:-19491}"
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
timeout 1800 dotnet "$tests" write-keystores "$work" "$keys" > /dev/null
FAKE_BN_ATTESTATIONS="$out/attestations.jsonl" python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" "$sps" "$spe" > "$out/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
    "keymanager": { "port": $((port + 1)) }, "metrics": { "port": $((port + 2)) }, "doppelganger": { "enabled": false } } }
J
"$bin" run --config "$work/eplix.json" > "$out/vc.log" 2>&1 &
vc=$!
start=$(date +%s)
echo "t_s rss_kb fds cpu_ticks" > "$out/samples.txt"
while [ $(( $(date +%s) - start )) -lt "$duration" ]; do
  kill -0 "$vc" 2>/dev/null || { echo "the VC exited early" >&2; tail -20 "$out/vc.log" >&2; exit 1; }
  rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$vc/status")
  fds=$(ls "/proc/$vc/fd" | wc -l)
  # utime + stime, fields 14 and 15 of /proc/<pid>/stat (the name in field 2 has no space here).
  cpu=$(awk '{print $14 + $15}' "/proc/$vc/stat")
  echo "$(( $(date +%s) - start )) $rss $fds $cpu" >> "$out/samples.txt"
  sleep 60
done
kill "$vc"
wait "$vc" 2>/dev/null || true
python3 -I - "$out/samples.txt" "$out/attestations.jsonl" "$keys" "$spe" <<'PY'
import collections, json, sys
rows = [tuple(map(int, l.split())) for l in open(sys.argv[1]).read().split("\n")[1:] if l.strip()]
assert len(rows) >= 4, f"only {len(rows)} samples"
q = len(rows) // 4
second, last = rows[q:2 * q], rows[-q:]
mean = lambda xs: sum(xs) / len(xs)
rss2, rss4 = mean([r[1] for r in second]), mean([r[1] for r in last])
fd2, fd4 = mean([r[2] for r in second]), mean([r[2] for r in last])
print(f"RSS {rss2 / 1024:.1f} MiB -> {rss4 / 1024:.1f} MiB, descriptors {fd2:.0f} -> {fd4:.0f}")
# CPU: ticks are 1/100 s; the share of one core over each quarter.
cpu = lambda part: 100 * (part[-1][3] - part[0][3]) / 100 / max(1, part[-1][0] - part[0][0])
print(f"CPU {cpu(second):.2f}% -> {cpu(last):.2f}% of one core, max RSS {max(r[1] for r in rows) / 1024:.1f} MiB")
assert rss4 <= rss2 * 1.15, "RSS grows"
assert fd4 <= fd2 + 10, "descriptors grow"
keys, spe = int(sys.argv[3]), int(sys.argv[4])
per_epoch = collections.defaultdict(set)
for l in open(sys.argv[2]):
    a = json.loads(l)
    per_epoch[a["slot"] // spe].add(a["attester_index"])
epochs = sorted(per_epoch)
whole = epochs[1:-1]  # the first and last epoch of the run may be partial
missed = {e: keys - len(per_epoch[e]) for e in whole if len(per_epoch[e]) != keys}
print(f"{len(whole)} whole epochs, {sum(len(per_epoch[e]) for e in whole)} attestations")
assert whole, "no whole epoch"
assert not missed, f"missed duties per epoch: {dict(list(missed.items())[:10])}"
PY
if grep -q "ERROR" "$out/vc.log"; then
  grep "ERROR" "$out/vc.log" | head -5 >&2
  echo "errors in the VC log" >&2
  exit 1
fi
echo "soak ok: $duration s, $keys keys; samples in $out/samples.txt"
