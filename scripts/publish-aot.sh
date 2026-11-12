#!/usr/bin/env bash
# NativeAOT publish of the eplix binary. Fails if a trim or AOT warning comes from anything
# other than FSharp.Core (whose printf and %A code reports warnings the VC does not reach).
# Usage: scripts/publish-aot.sh [rid]   (default linux-x64)
set -euo pipefail
cd "$(dirname "$0")/.."
rid="${1:-linux-x64}"
out="artifacts/publish/$rid"
log="artifacts/publish-$rid.log"
mkdir -p artifacts
# ContinuousIntegrationBuild=true: locked restore (Directory.Build.props), so a lock file out of
# date fails the publish.
dotnet publish src/Eplix -c Release -r "$rid" -m:2 -nologo -p:ContinuousIntegrationBuild=true -o "$out" | tee "$log"
# FSharp.Core warnings carry its build path (src/fsharp/src/...). Anything else is Eplix's to fix.
if grep -E 'warning IL[0-9]+|error IL[0-9]+' "$log" | grep -v -E '[\/]src[\/]fsharp[\/]src[\/]' ; then
  echo "AOT or trim warnings outside FSharp.Core (above)" >&2
  exit 1
fi
count=$(grep -c -E 'warning IL[0-9]+' "$log" || true)
echo "FSharp.Core trim/AOT warnings: $count"
ls -l "$out"
