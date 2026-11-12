#!/usr/bin/env bash
# Smoke test of the published binary's exit and switch commands against
# scripts/fake-beacon-node.py, with one local key (the EIP-2335 PBKDF2 test keystore):
#   - `exit --all --save-dir` writes <0xpubkey>.json with mode 0600 in a 0700 directory;
#   - `exit --pubkey <held>,<unknown>` saves the held key's exit and exits with code 1;
#   - `exit --pubkey <held> --submit true` reaches the node;
#   - `switch stop`, `pause`, `resume-duty`, `status`, `resume` edit <data_dir>/switches.json;
#   - a VC started with the stop in the file attests nothing, and attests after `switch resume`.
# Run after scripts/publish-aot.sh. Usage: scripts/smoke-exits.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
work=$(mktemp -d)
port=19461
cleanup() {
  kill "${vc:-}" "${bn:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
die() { echo "smoke-exits: $*" >&2; exit 1; }
pk=0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07
# A key from the test fixtures that this VC does not hold.
other=0x849b4bcd8670f81909baad27c4d9c8d9b956b19192f12af8fe57d30731fa11a55a97a1ab72bb1cfd76c1461dcaba714a
echo "$pk" > "$work/pubkeys.txt"
# 2 s slots, 4-slot epochs: the key attests in slot 0 of each epoch, every 8 s.
FAKE_BN_GENESIS=$(( $(date +%s) + 4 )) python3 -I scripts/fake-beacon-node.py "$port" "$work/pubkeys.txt" 2 4 > "$work/bn.log" 2>&1 &
bn=$!
sleep 1
curl -fsS "http://127.0.0.1:$port/eth/v1/config/spec" \
  | python3 -I -c 'import json,sys; [print(f"{k}: {v}") for k, v in json.load(sys.stdin)["data"].items()]' \
  | grep -v -E '^(SLOTS_PER_EPOCH|PRESET_BASE|SECONDS_PER_SLOT):' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:$port", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"], "use_events": false,
  "modules": { "local": { "keystores": [
    { "path": "$PWD/tests/fixtures/eip2335/pbkdf2.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" } ] },
    "keymanager": { "port": 19462 }, "metrics": { "port": 19463 }, "doppelganger": { "enabled": false } } }
J
cfg=(--config "$work/eplix.json")

# Presigned exits for every key.
"$bin" exit "${cfg[@]}" --all --save-dir "$work/exits" > "$work/exit-all.log" 2>&1 \
  || { cat "$work/exit-all.log"; die "exit --all failed"; }
f="$work/exits/$pk.json"
[ -f "$f" ] || { cat "$work/exit-all.log"; die "no file $f"; }
[ "$(stat -c %a "$f")" = 600 ] || die "file mode $(stat -c %a "$f"), want 600"
[ "$(stat -c %a "$work/exits")" = 700 ] || die "directory mode $(stat -c %a "$work/exits"), want 700"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["message"]["validator_index"]=="0" and len(d["signature"])==194, d' "$f" \
  || die "bad exit file"
[ "$(ls -A "$work/exits" | wc -l)" = 1 ] || die "files other than the exit in the directory"

# A key the VC does not hold fails; the held key is still saved.
rm "$f"
if "$bin" exit "${cfg[@]}" --pubkey "$pk,$other" --save-dir "$work/exits" > "$work/exit-two.log" 2>&1; then
  cat "$work/exit-two.log"; die "exit with an unknown key returned 0"
fi
grep -q "error: $other" "$work/exit-two.log" || { cat "$work/exit-two.log"; die "the unknown key is not named"; }
[ -f "$f" ] || { cat "$work/exit-two.log"; die "the held key's exit was not saved"; }

# Submitted to the node.
"$bin" exit "${cfg[@]}" --pubkey "$pk" --submit true > "$work/exit-submit.log" 2>&1 \
  || { cat "$work/exit-submit.log"; die "exit --submit failed"; }
grep -q "submitted voluntary exit of validator 0" "$work/bn.log" || { cat "$work/exit-submit.log" "$work/bn.log"; die "the node got no exit"; }

# The switch file.
sw() { "$bin" switch "$@" "${cfg[@]}"; }
sw pause attestation block > "$work/sw.log" || die "switch pause failed"
grep -q "paused: attestation, block" "$work/sw.log" || { cat "$work/sw.log"; die "pause not shown"; }
sw resume-duty block > "$work/sw.log" || die "switch resume-duty failed"
grep -q "switch file .*: paused: attestation$" "$work/sw.log" || { cat "$work/sw.log"; die "resume-duty not shown"; }
if sw pause attesting > "$work/sw.log" 2>&1; then die "an unknown duty kind was taken"; fi
sw stop > "$work/sw.log" || die "switch stop failed"
sw status > "$work/sw.log" || die "switch status failed"
grep -q "signing stopped" "$work/sw.log" || { cat "$work/sw.log"; die "status does not show the stop"; }
[ "$(stat -c %a "$work/data/switches.json")" = 640 ] || die "switches.json mode $(stat -c %a "$work/data/switches.json")"

# A VC started with the stop in the file signs nothing until `switch resume`.
"$bin" run "${cfg[@]}" > "$work/vc.log" 2>&1 &
vc=$!
sleep 12
grep -q "submitted .* attestations" "$work/bn.log" && { tail -20 "$work/vc.log"; die "attested while stopped"; }
grep -q "emergency switches: signing stopped" "$work/vc.log" || { tail -20 "$work/vc.log"; die "no switch line in the log"; }
sw resume > "$work/sw.log" || die "switch resume failed"
for _ in $(seq 30); do grep -q "submitted .* attestations" "$work/bn.log" && break; sleep 1; done
kill "$vc" 2>/dev/null || true
wait "$vc" 2>/dev/null || true
grep -q "signing resumed" "$work/vc.log" || { tail -20 "$work/vc.log"; die "no resume line in the log"; }
grep -q "submitted .* attestations" "$work/bn.log" || { tail -20 "$work/vc.log"; die "no attestation after the resume"; }
grep -E "ERROR" "$work/vc.log" && die "errors in the VC log"
echo "smoke ok: presigned and submitted exits, the switch commands, and a stop and resume in a running VC"
