#!/usr/bin/env bash
# Runs the TEE signer integration tests: the tests start five local dev-platform runners
# with a test CA made in process, load keys and shares through the debug
# build's plaintext import, sign every duty kind, run duties on the fake beacon node with one
# runner stopped half way, and stop the runners. With the published binary (after
# scripts/publish-aot.sh) it also attests through three runners of its own against
# scripts/fake-beacon-node.py. EPLIX_TEE_BENCH=1000 adds the 1,000-attestation burst.
# Usage: scripts/tee-it.sh <runner-dev-debugimport binary>
# The runner comes from tee-signer: its scripts/build-runner.sh builds runner-dev-debugimport
# (platform dev, -tags debugimport).
set -euo pipefail
cd "$(dirname "$0")/.."
runner=$(realpath "${1:?path to runner-dev-debugimport}")
dotnet build tests/Eplix.Tests -c Release -nologo -v q
aot="$PWD/artifacts/publish/linux-x64/eplix"
[ -x "$aot" ] && export EPLIX_AOT_BIN="$aot"
EPLIX_TEE_RUNNER="$runner" dotnet tests/Eplix.Tests/bin/Release/net10.0/Eplix.Tests.dll --filter-test-list tee-real --sequenced --summary
