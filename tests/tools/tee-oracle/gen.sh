#!/usr/bin/env bash
# Regenerates tests/fixtures/tee/oracle-vectors.json from the Go attestation verifiers of
# tee-signer (its Go module attestation-verify).
#
#   TEE_SIGNER_DIR=/path/to/tee-signer tests/tools/tee-oracle/gen.sh [output]
#
# Needs Go (the version tee-signer's go.mod names) and the modules tee-signer depends on, from
# GOPROXY or the module cache. The generator is built in a temporary module whose go.mod points
# at the checkout, so the checkout is not changed. Every run makes new keys and documents; the
# verdicts stay the same, and TeeVerifierTests must pass with the new file.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
out=${1:-$repo/tests/fixtures/tee/oracle-vectors.json}
tee=${TEE_SIGNER_DIR:?set TEE_SIGNER_DIR to a tee-signer checkout}
tee=$(cd "$tee" && pwd)
[ -f "$tee/attestation-verify/go.mod" ] || { echo "no attestation-verify/go.mod in $tee" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here"/*.go "$work/"

{
    echo "module eplix.test/tee-oracle"
    echo
    echo "go $(sed -n 's/^go //p' "$tee/attestation-verify/go.mod")"
    echo
    echo "require ("
    echo "	github.com/lidofinance/tee-signer/attestation-verify v0.0.0"
    echo "	github.com/lidofinance/tee-signer/signer-protocol v0.0.0"
    echo ")"
    echo
    echo "replace ("
    for d in "$tee"/*/; do
        d=${d%/}
        [ -f "$d/go.mod" ] || continue
        m=$(sed -n 's/^module //p' "$d/go.mod")
        case $m in github.com/lidofinance/tee-signer/*) echo "	$m => $d" ;; esac
    done
    echo ")"
} > "$work/go.mod"

src="tee-signer attestation-verify"
if rev=$(git -C "$tee" rev-parse --short=12 HEAD 2>/dev/null); then src="$src $rev"; fi

cd "$work"
go mod tidy >/dev/null
go run . -out "$out" -source "$src"
