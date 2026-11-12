#!/usr/bin/env bash
# A week of fuzzing: 7 rounds of `scripts/nightly.sh fuzz`
# (the fuzz and slashing lists with EPLIX_FUZZ_CASES, default 100000, and a new logged seed each
# round), one round per night when run from cron, or back to back with --now. Stops at the first
# failing round. Each round has its own time limit inside nightly.sh; the whole run stops after
# 8 days at the latest.
#   cron, 01:00 each night for a week:  0 1 * * *  cd <repo> && scripts/fuzz-week.sh --round
#   back to back:                       scripts/fuzz-week.sh --now
# Rounds and seeds are appended to artifacts/fuzz-week/rounds.txt.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts/fuzz-week
record=artifacts/fuzz-week/rounds.txt
round() {
  local n start
  n=$(( $(grep -c "^round" "$record" 2>/dev/null || echo 0) + 1 ))
  start=$(date -u +%FT%TZ)
  if out=$(scripts/nightly.sh fuzz 2>&1); then r=pass; else r=FAIL; fi
  echo "round $n $start $r $(echo "$out" | grep -o 'seed [0-9]*, [0-9]* cases')" >> "$record"
  echo "$out"
  [ "$r" = pass ]
}
case "${1:-}" in
  --round)
    done=$(grep -c "^round" "$record" 2>/dev/null || echo 0)
    [ "$done" -lt 7 ] || { echo "7 rounds done; see $record"; exit 0; }
    grep -q " FAIL " "$record" 2>/dev/null && { echo "a round failed; see $record" >&2; exit 1; }
    round
    ;;
  --now)
    end=$(( $(date +%s) + 8 * 86400 ))
    for _ in 1 2 3 4 5 6 7; do
      [ "$(date +%s)" -lt "$end" ] || { echo "8-day limit reached" >&2; exit 1; }
      round || exit 1
    done
    echo "7 rounds without a finding; see $record"
    ;;
  *) echo "usage: scripts/fuzz-week.sh --round | --now" >&2; exit 2 ;;
esac
