#!/usr/bin/env bash
# Checks the F# formatting with the Fantomas version that .config/dotnet-tools.json
# pins. The style comes from .editorconfig.
#
#   scripts/check-format.sh         list the files Fantomas would change; fails if any
#   scripts/check-format.sh --fix   format them
set -euo pipefail
cd "$(dirname "$0")/.."
version=8.1.1
# SHA-512 of fantomas.8.1.1.nupkg as nuget.org served it on 2026-11-12.
sha=24b9caf224a8dfed08b57e1fe48029000a559cc0979b791bc8034c414751ff0f2bc8878c0d3e8d936a7ae7116c616c8c3c5efc08d3f224c8ac1d36dbcd2f8084

grep -q "\"version\": \"$version\"" .config/dotnet-tools.json ||
  { echo ".config/dotnet-tools.json does not pin Fantomas $version" >&2; exit 1; }
dotnet tool restore > /dev/null
packages=$(dotnet nuget locals global-packages --list | sed 's/^global-packages: //')
echo "$sha  ${packages%/}/fantomas/$version/fantomas.$version.nupkg" | sha512sum -c --quiet -

mapfile -t files < <(git ls-files '*.fs' '*.fsi' '*.fsx')
if [[ ${1:-} == --fix ]]; then
  dotnet fantomas "${files[@]}"
else
  dotnet fantomas --check "${files[@]}"
fi
