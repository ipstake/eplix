#!/usr/bin/env bash
# Smoke test of the published binary: `eplix check` decrypts the two EIP-2335 test keystores,
# whose password is non-ASCII and needs NFKD (ICU). Run after scripts/publish-aot.sh.
# Usage: scripts/smoke-aot.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
bin="$PWD/artifacts/publish/$rid/eplix"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'CONFIG_NAME: smoke\nGENESIS_FORK_VERSION: 0x00000001\n' > "$work/chain.yaml"
cat > "$work/eplix.json" <<J
{ "beacon_node": "http://127.0.0.1:1", "chain_config": "chain.yaml", "data_dir": "data",
  "modules": { "local": { "keystores": [
    { "path": "$PWD/tests/fixtures/eip2335/scrypt.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" },
    { "path": "$PWD/tests/fixtures/eip2335/pbkdf2.json", "password_file": "$PWD/tests/fixtures/eip2335/password.txt" } ] },
    "keymanager": { "port": 19402 }, "metrics": { "port": 19403 } } }
J
out=$("$bin" check --config "$work/eplix.json" 2>&1)
echo "$out"
# The two vectors hold the same key, so the second is skipped as a duplicate.
grep -q "module local: 1 keystores decrypted" <<<"$out"
echo "smoke ok: non-ASCII EIP-2335 password decrypts in the published binary"
