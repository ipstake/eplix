#!/usr/bin/env bash
# Runs the lint checks of .github/workflows/lint.yml that need no container:
# commit messages since BASE, public text in the tree (plus the local name
# list, if there is one), F# formatting.
# Runs all three and fails if any failed.
#
#   scripts/lint.sh [BASE]   BASE defaults to origin/main
set -uo pipefail
cd "$(dirname "$0")/.." || exit
base=${1:-origin/main}
fail=0
echo "== commit messages ($base..HEAD)" >&2
scripts/check-commits.sh "$base..HEAD" || fail=1
echo "== public text" >&2
scripts/check-public.sh || fail=1
echo "== F# formatting" >&2
scripts/check-format.sh || fail=1
exit $fail
