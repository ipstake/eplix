#!/usr/bin/env bash
# Runs the Charon integration test (Obol mode) against a local cluster made by
# scripts/charon-local.sh: sets the cluster up if needed, starts it, runs the test list
# charon-integration, stops the cluster. Exits non-zero when the test fails.
# Usage: scripts/charon-it.sh <cluster dir>   (charon on PATH or in CHARON)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p "${1:?cluster directory}"
net=$(cd "$1" && pwd)
# The cluster stops by itself after CHARON_TIMEOUT seconds even if this script is killed.
export CHARON_TIMEOUT=${CHARON_TIMEOUT:-600}
bash scripts/charon-local.sh setup "$net"
trap 'bash scripts/charon-local.sh stop "$net"' EXIT
bash scripts/charon-local.sh run "$net"
timeout 600 dotnet build tests/Eplix.Tests -c Debug -nologo -v q
EPLIX_CHARON_NET="$net" timeout --kill-after=10 420 \
  dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --filter-test-list charon-integration --summary
