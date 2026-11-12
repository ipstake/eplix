#!/usr/bin/env bash
# Installs the .NET SDK that global.json pins, from Microsoft's tarball,
# checked against the SHA-512 Microsoft publishes in
# https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json.
# x64 only for now: the arm64 hash goes in when a job needs it. A version bump
# changes global.json and the hash.
# Usage: .github/scripts/install-dotnet.sh   (installs into $HOME/.dotnet, adds it to the job's PATH)
set -euo pipefail
cd "$(dirname "$0")/../.."
version=10.0.403
grep -q "\"version\": \"$version\"" global.json || { echo "global.json does not pin SDK $version" >&2; exit 1; }
case "$(uname -m)" in
  x86_64)
    rid=linux-x64
    sha=b7b3d8461cf98b07d2552ce9199702fa3ad010ac2671a5f8cd5136f7534e50f6855ba7bbb02b11494563f1d04156276a31cda1103b900e5eecd0d9473dc7b9c5 ;;
  *) echo "no SDK hash for $(uname -m)" >&2; exit 1 ;;
esac
dest=$HOME/.dotnet
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/sdk.tar.gz" "https://builds.dotnet.microsoft.com/dotnet/Sdk/$version/dotnet-sdk-$version-$rid.tar.gz"
echo "$sha  $tmp/sdk.tar.gz" | sha512sum -c --quiet -
mkdir -p "$dest"
tar -xzf "$tmp/sdk.tar.gz" -C "$dest" --no-same-owner
{
  echo "DOTNET_ROOT=$dest"
  echo "DOTNET_CLI_TELEMETRY_OPTOUT=1"
  echo "DOTNET_NOLOGO=1"
  echo "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
} >> "$GITHUB_ENV"
echo "$dest" >> "$GITHUB_PATH"
"$dest/dotnet" --version
