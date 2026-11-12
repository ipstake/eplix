#!/usr/bin/env bash
# The nightly run, kept out of the per-change suite (scripts/ci.sh) for its length:
#   ssz    every ssz_static case of consensus-spec-tests v1.6.1 (Fulu) and v1.7.0-beta.4 (Gloas)
#          and every ssz_generic case of v1.6.1, from the unpacked archives under $DL_DIR
#   fuzz   the fuzz and slashing lists with EPLIX_FUZZ_CASES (default 100000) and a logged seed
#   flaky  the duties, gloas, scheduler, beacon nodes and fork boundary lists 30 times each
# Every step has a time limit. Logs go to artifacts/nightly/<UTC time>/; the exit code is 1 when
# any step failed. Replay a fuzz failure with the seed from fuzz-seed.txt:
#   EPLIX_FUZZ_SEED=<seed> EPLIX_FUZZ_CASES=<cases> dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --filter-test-list fuzz
# Usage: scripts/nightly.sh [ssz] [fuzz] [flaky]   (no argument: all three)
set -uo pipefail
cd "$(dirname "$0")/.."
dl=${DL_DIR:-${EPLIX_CACHE:-$HOME/.cache/eplix}/dl}
steps=${*:-ssz fuzz flaky}
out=artifacts/nightly/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$out"
bin=tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll
# ContinuousIntegrationBuild=true: locked restore, as in scripts/ci.sh.
if ! timeout 900 dotnet build -c Debug -m:2 -nologo -p:ContinuousIntegrationBuild=true > "$out/build.log" 2>&1; then
  echo "build failed, see $out/build.log" >&2
  exit 1
fi
failed=0
# step <name> <time limit> <command...>: runs the command under the limit, logs it, reports.
step() {
  local name=$1 limit=$2
  shift 2
  local start rc
  start=$(date +%s)
  timeout --kill-after=60 "$limit" "$@" > "$out/$name.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "$name: pass, $(( $(date +%s) - start )) s"
  else
    echo "$name: FAIL (exit $rc$([ "$rc" -eq 124 ] && echo ", time limit $limit")), $(( $(date +%s) - start )) s; log $out/$name.log"
    failed=1
  fi
  grep -a "EXPECTO!" "$out/$name.log" | tail -1 | sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g'
}

for s in $steps; do
  case "$s" in
    ssz)
      fulu=$dl/cst-v1.6.1/ssz-static-fulu-x/tests/minimal/fulu/ssz_static
      gloas=$dl/cst-v1.7.0-beta.4/x/tests/minimal/gloas/ssz_static
      generic=$dl/cst-v1.6.1/ssz-generic-x/tests/general/phase0/ssz_generic
      for d in "$fulu" "$gloas" "$generic"; do
        [ -d "$d" ] || { echo "ssz: $d is missing (unpack the archive, see tests/vectors/README.md)"; failed=1; }
      done
      step ssz 2h env EPLIX_FULU_SSZ_STATIC="$fulu" EPLIX_GLOAS_SSZ_STATIC="$gloas" EPLIX_SSZ_GENERIC="$generic" \
        dotnet "$bin" --colours 0 --no-spinner --filter-test-list ssz
      ;;
    fuzz)
      seed=$(od -An -N8 -tu8 /dev/urandom | tr -d ' ')
      cases=${EPLIX_FUZZ_CASES:-100000}
      echo "seed $seed, $cases cases" | tee "$out/fuzz-seed.txt"
      step fuzz 6h env EPLIX_TEST_LIMIT_SECONDS=10800 EPLIX_FUZZ_CASES="$cases" EPLIX_FUZZ_SEED="$seed" dotnet "$bin" --colours 0 --no-spinner --filter-test-list fuzz
      step fuzz-slashing 6h env EPLIX_TEST_LIMIT_SECONDS=10800 EPLIX_FUZZ_CASES="$cases" EPLIX_FUZZ_SEED="$seed" dotnet "$bin" --colours 0 --no-spinner --filter-test-list slashing
      ;;
    flaky)
      for list in duties gloas scheduler "beacon nodes" "fork boundary"; do
        name=flaky-${list// /-}
        pass=0
        for i in $(seq 1 30); do
          if timeout --kill-after=30 600 dotnet "$bin" --colours 0 --no-spinner --filter-test-list "$list" > "$out/$name-$i.log" 2>&1; then
            pass=$((pass + 1))
            rm -f "$out/$name-$i.log"
          fi
        done
        echo "$name: $pass of 30"
        [ "$pass" -eq 30 ] || failed=1
      done
      ;;
    *) echo "unknown step $s" >&2; exit 2 ;;
  esac
done
exit $failed
