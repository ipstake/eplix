#!/usr/bin/env bash
# Start-up time and memory of the published binary at a key count: local keystores (PBKDF2 with 16
# rounds, as the soak uses) against scripts/fake-beacon-node.py with 12 s slots and 8 slots an
# epoch, for a few epochs. Reports, from the VC's log and /proc: the time to the decrypted keys,
# to the first attestation duty submitted, the resident memory then and its highest value, and
# whether every key attested in every whole epoch.
# Run after scripts/publish-aot.sh and a Debug build of the tests (the keystore writer).
# Usage: scripts/startup-keys.sh <keys> [epochs] [port]   (default 4 epochs, ports 19891 to 19893)
set -euo pipefail
cd "$(dirname "$0")/.."
keys="$1"
epochs="${2:-4}"
port="${3:-19891}"
bin="$PWD/artifacts/publish/linux-x64/eplix"
tests="$PWD/tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll"
out="$PWD/artifacts/startup-keys/$(date -u +%Y%m%dT%H%M%SZ)-$keys"
mkdir -p "$out"
work=$(mktemp -d)
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
timeout 3600 dotnet "$tests" write-keystores "$work" "$keys" > /dev/null
FAKE_BN_ATTESTATIONS="$out/attestations.jsonl" python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 12 8 > "$out/bn.log" 2>&1 &
bn=$!
sleep 2
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
    "keymanager": { "port": $((port + 1)) }, "metrics": { "port": $((port + 2)) }, "doppelganger": { "enabled": false } } }
J
start_ms=$(date +%s%3N)
"$bin" run --config "$work/eplix.json" > "$out/vc.log" 2>&1 &
vc=$!
echo "t_ms rss_kb" > "$out/rss.txt"
end=$(( $(date +%s) + epochs * 96 ))
while [ "$(date +%s)" -lt "$end" ]; do
  kill -0 "$vc" 2>/dev/null || { echo "the VC exited early" >&2; tail -20 "$out/vc.log" >&2; exit 1; }
  echo "$(( $(date +%s%3N) - start_ms )) $(awk '/^VmRSS:/ {print $2}' "/proc/$vc/status")" >> "$out/rss.txt"
  sleep 2
done
kill "$vc"
wait "$vc" 2>/dev/null || true
python3 -I - "$out" "$keys" "$start_ms" <<'PY'
import collections, datetime, json, re, sys
out, keys, start_ms = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
def ms(line):
    t = datetime.datetime.strptime(line[:23], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
    return int(t.timestamp() * 1000) - start_ms
log = open(f"{out}/vc.log").read().splitlines()
decrypted = next(l for l in log if "local backend:" in l)
first = next(l for l in log if re.search(r"slot \d+: \d+ duties, \d+ signed.*submitted True", l))
rss = [tuple(map(int, l.split())) for l in open(f"{out}/rss.txt").read().splitlines()[1:]]
at_first = min(rss, key=lambda r: abs(r[0] - ms(first)))[1]
per_epoch = collections.defaultdict(set)
for l in open(f"{out}/attestations.jsonl"):
    a = json.loads(l)
    per_epoch[a["slot"] // 8].add(a["attester_index"])
whole = sorted(per_epoch)[1:-1]
missed = sum(keys - len(per_epoch[e]) for e in whole)
print(f"{keys} keys: decrypted at {ms(decrypted) / 1000:.1f} s ({decrypted.split('decrypted in ')[1]}), "
      f"first attestation duty submitted at {ms(first) / 1000:.1f} s; RSS then {at_first / 1024:.0f} MiB, "
      f"highest {max(r[1] for r in rss) / 1024:.0f} MiB, last {rss[-1][1] / 1024:.0f} MiB; "
      f"{len(whole)} whole epochs, {missed} missed attestations")
PY
