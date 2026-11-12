#!/usr/bin/env bash
# Runs the Web3Signer integration tests: the tests start four local Web3Signer instances (one
# with whole keys behind mutual TLS, three with one share each of 2 of 3 keys) and stop them.
# Usage: scripts/web3signer-it.sh <web3signer launcher>   (JAVA_HOME set to a Java 21+ runtime)
set -euo pipefail
cd "$(dirname "$0")/.."
launcher=$(realpath "${1:?path to bin/web3signer}")
dotnet build tests/Eplix.Tests -c Release -nologo -v q
EPLIX_WEB3SIGNER="$launcher" dotnet tests/Eplix.Tests/bin/Release/net10.0/Eplix.Tests.dll --filter-test-list web3signer-integration --summary
