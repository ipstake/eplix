#!/usr/bin/env bash
# Puts the test vectors that are not in the repository into tests/vectors/.download/ (git-ignored),
# pinned by hash. The test suite fails while any of them is missing.
#   eip3076/    slashing-protection-interchange-tests v5.3.0: no licence file, so not committed
#   ssz-specs/  ethereum/ssz-specs v0.1.0 fixtures: MIT, shipped without the licence text
#   beacon-apis/beacon-node-oapi.json      beacon-APIs v5.0.0-beta.0, bundled OpenAPI (6.9 MB)
#   keymanager-apis/keymanager-oapi.json   keymanager-APIs v1.2.0-alpha.0, bundled OpenAPI
#
#   scripts/fetch-test-vectors.sh                  download from GitHub
#   DL_DIR=<dir> scripts/fetch-test-vectors.sh   use local copies under <dir> where present:
#     <dir>/eip3076/interchange-tests-v5.3.0.tar.gz, <dir>/ssz-specs-v0.1.0/ssz-test-vectors-v0.1.0.tar.gz,
#     <dir>/beacon-apis-v5.0.0-beta.0/beacon-node-oapi.json, <dir>/keymanager-apis-v1.2.0-alpha.0/keymanager-oapi.json
#   scripts/fetch-test-vectors.sh <eip3076 archive>  a local copy of the EIP-3076 archive (older form)
# Nothing from these files runs: the archives are unpacked for their JSON files only.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=tests/vectors/.download
mkdir -p "$dest"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dl=${DL_DIR:-}

# fetch <url> <sha256> <local copy under $DL_DIR> <output file>
fetch() {
  local url=$1 sha=$2 local_copy=$3 out=$4
  if [ -n "$local_copy" ] && [ -f "$local_copy" ]; then
    cp "$local_copy" "$out"
  else
    curl -fsSL --retry 3 -o "$out" "$url"
  fi
  echo "$sha  $out" | sha256sum -c --quiet - || { echo "hash mismatch: $url" >&2; exit 1; }
}

# EIP-3076 interchange tests v5.3.0
archive=${1:-}
[ -n "$archive" ] || archive=${dl:+$dl/eip3076/interchange-tests-v5.3.0.tar.gz}
fetch https://codeload.github.com/eth-clients/slashing-protection-interchange-tests/tar.gz/refs/tags/v5.3.0 \
  516d551cfb3e50e4ac2f42db0992f4ceb573a7cb1616d727a725c8161485329f "$archive" "$tmp/interchange.tar.gz"
mkdir -p "$tmp/x"
tar -xzf "$tmp/interchange.tar.gz" -C "$tmp/x" --no-same-owner --wildcards '*/tests/generated/*.json'
rm -rf "$dest/eip3076"
mkdir -p "$dest/eip3076"
cp "$tmp"/x/*/tests/generated/*.json "$dest/eip3076/"
n=$(ls "$dest/eip3076" | wc -l)
echo "EIP-3076 interchange tests v5.3.0: $n files in $dest/eip3076"
[ "$n" -eq 38 ] || { echo "expected 38 files, found $n" >&2; exit 1; }

# ssz-specs v0.1.0 fixtures
fetch https://github.com/ethereum/ssz-specs/releases/download/v0.1.0/ssz-test-vectors-v0.1.0.tar.gz \
  e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878 "${dl:+$dl/ssz-specs-v0.1.0/ssz-test-vectors-v0.1.0.tar.gz}" "$tmp/ssz-specs.tar.gz"
mkdir -p "$tmp/s"
tar -xzf "$tmp/ssz-specs.tar.gz" -C "$tmp/s" --no-same-owner --wildcards 'fixtures/*.json'
rm -rf "$dest/ssz-specs"
mkdir -p "$dest/ssz-specs"
cp -r "$tmp/s/fixtures/ssz/ssz/." "$dest/ssz-specs/"
n=$(find "$dest/ssz-specs" -name '*.json' | wc -l)
echo "ssz-specs v0.1.0: $n fixtures in $dest/ssz-specs"
[ "$n" -eq 117 ] || { echo "expected 117 fixtures, found $n" >&2; exit 1; }

# Bundled OpenAPI documents of beacon-APIs and keymanager-APIs
mkdir -p "$dest/beacon-apis" "$dest/keymanager-apis"
fetch https://github.com/ethereum/beacon-APIs/releases/download/v5.0.0-beta.0/beacon-node-oapi.json \
  c104d962349c5c1aba2099b72e84a81cb7a98f25bb297891b752761ab3056820 "${dl:+$dl/beacon-apis-v5.0.0-beta.0/beacon-node-oapi.json}" "$dest/beacon-apis/beacon-node-oapi.json"
fetch https://github.com/ethereum/keymanager-APIs/releases/download/v1.2.0-alpha.0/keymanager-oapi.json \
  e93bfe1f84a6388d1ddf7531dc0de528f406a6d7d08e2d76df921ff95ca98375 "${dl:+$dl/keymanager-apis-v1.2.0-alpha.0/keymanager-oapi.json}" "$dest/keymanager-apis/keymanager-oapi.json"
echo "beacon-APIs v5.0.0-beta.0 and keymanager-APIs v1.2.0-alpha.0 OpenAPI in $dest"
