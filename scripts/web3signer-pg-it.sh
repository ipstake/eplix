#!/usr/bin/env bash
# Runs the Web3Signer test with Web3Signer's own slashing protection on: a local PostgreSQL and
# one Web3Signer from scripts/web3signer-pg.sh in <dir>, stopped on exit. Ten minutes at most.
# Usage: scripts/web3signer-pg-it.sh <dir>   (W3S, JAVA_HOME and PG_BIN as for web3signer-pg.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
dir=$(realpath -m "${1:?directory}")
pg=scripts/web3signer-pg.sh
trap '"$pg" stop "$dir"' EXIT
end=$((SECONDS + 600))
left() { echo $((end - SECONDS > 0 ? end - SECONDS : 1)); }
[ -f "$dir/pg/PG_VERSION" ] || timeout "$(left)" "$pg" setup "$dir"
timeout "$(left)" "$pg" start "$dir"
timeout "$(left)" dotnet build tests/Eplix.Tests -c Debug -nologo -v q
out="$dir/test.log"
EPLIX_WEB3SIGNER_PG="$dir" timeout "$(left)" dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll \
  --filter-test-case "a 412 from Web3Signer's DB halts the key" --summary --colours 0 2>&1 | tee "$out"
# A filter that matches nothing passes; make sure the test ran.
grep -Eq 'Passed: +1$' "$out" || { echo "the test did not run and pass" >&2; exit 1; }
