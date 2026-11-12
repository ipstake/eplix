#!/usr/bin/env bash
# Runs the Dirk integration tests against a cluster made by scripts/dirk-local.sh setup.
# Dirk's slashing protection is wiped first, so the tests can sign the same slots again.
# Usage: scripts/dirk-it.sh <cluster dir>   (dirk and ethdo on PATH or in DIRK and ETHDO)
set -euo pipefail
cd "$(dirname "$0")/.."
net=$(cd "${1:?cluster directory}" && pwd)
bash scripts/dirk-local.sh wipe-protection "$net"
bash scripts/dirk-local.sh start "$net"
dotnet build tests/Eplix.Tests -c Release -nologo -v q
EPLIX_DIRK_NET="$net" dotnet tests/Eplix.Tests/bin/Release/net10.0/Eplix.Tests.dll --filter-test-list dirk-integration --summary
