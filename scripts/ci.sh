#!/usr/bin/env bash
# What runs on each change on a developer machine (no hosted CI). Each step has a time
# limit, a log in artifacts/ci/<UTC time>/, and a line in the summary; the exit code is 1 when a
# step failed. Nothing is skipped silently: a step whose tools are missing fails, unless
# --no-integration leaves out the integration steps, and then the summary says so.
#   1. test vectors in place (scripts/fetch-test-vectors.sh, local copies under $DL_DIR)
#   2. build, and the whole test binary (unit, property, vector and fake-node tests)
#   3. NativeAOT publish with its warning check (scripts/publish-aot.sh)
#   4. smoke tests of the published binary: EIP-2335, Gloas fork, the pre-Gloas builder flow, metrics, two instances on one
#      data dir, exits and the emergency switches, 30 rounds of kill -9, export into the five
#      other clients; scripts/check-ops.py with promtool on the metrics and builder scrapes
#      (PROMTOOL, default under $DL_DIR/prometheus-3.14.0)
#   5. integration: Dirk cluster, Web3Signer (TLS and shares), Web3Signer with Postgres, Charon
# Longer runs are elsewhere: scripts/nightly.sh (full vectors, fuzz, flaky hunt),
# scripts/fuzz-week.sh, scripts/soak.sh, scripts/mutants.sh, scripts/smoke-crash.sh 200.
# The TEE runner integration (scripts/tee-it.sh) needs a tee-signer runner binary
# (EPLIX_TEE_RUNNER); run it by hand when one is built.
# Usage: scripts/ci.sh [--no-integration]
set -uo pipefail
cd "$(dirname "$0")/.."
integration=1
[ "${1:-}" = "--no-integration" ] && integration=0
# Local copies of downloads and the tools of the integration steps. Defaults under
# ~/.cache/eplix; set DL_DIR, EPLIX_TOOLS and DIRK_NET to use other places.
cache=${EPLIX_CACHE:-$HOME/.cache/eplix}
export DL_DIR=${DL_DIR:-$cache/dl}
tools=${EPLIX_TOOLS:-$cache/tools}
dirk_net=${DIRK_NET:-$cache/dirk-net}
out=artifacts/ci/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$out"
summary=()
failed=0
started=$(date +%s)

# step <name> <time limit> <command...>
step() {
  local name=$1 limit=$2
  shift 2
  local start rc
  start=$(date +%s)
  timeout --kill-after=30 "$limit" "$@" > "$out/$name.log" 2>&1
  rc=$?
  local took=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then
    summary+=("pass  $name ($took s)")
  else
    summary+=("FAIL  $name ($took s, exit $rc$([ "$rc" -eq 124 ] && echo ", time limit $limit"); $out/$name.log)")
    failed=1
  fi
  echo "${summary[-1]}"
}
need() { # need <name> <path>: the tool must exist, or the step fails
  [ -e "$2" ] || { summary+=("FAIL  $1 (missing $2)"); echo "${summary[-1]}"; failed=1; return 1; }
}

step vectors 600 scripts/fetch-test-vectors.sh
# ContinuousIntegrationBuild=true turns on locked restore (Directory.Build.props): a lock file
# out of date with the packages fails the build.
step build 900 dotnet build -c Debug -m:2 -nologo -p:ContinuousIntegrationBuild=true
step tests 1800 dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --colours 0 --no-spinner --summary
grep -a "EXPECTO!" "$out/tests.log" | sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | tail -1
step publish-aot 1200 scripts/publish-aot.sh
step smoke-aot 300 scripts/smoke-aot.sh
step smoke-gloas 300 scripts/smoke-gloas.sh
step smoke-builder 300 env SMOKE_METRICS_OUT="$PWD/$out/metrics-builder.txt" scripts/smoke-builder.sh
step smoke-metrics 300 env SMOKE_METRICS_OUT="$PWD/$out/metrics-smoke.txt" scripts/smoke-metrics.sh
# The alert rules, dashboard and runbook against the two scrapes above, with promtool's rule
# check and unit tests. A missing promtool or scrape fails the step, as a missing tool does.
promtool=${PROMTOOL:-$DL_DIR/prometheus-3.14.0/prometheus-3.14.0.linux-amd64/promtool}
if need check-ops "$promtool" && need check-ops "$out/metrics-smoke.txt" && need check-ops "$out/metrics-builder.txt"; then
  step check-ops 120 env PROMTOOL="$promtool" python3 -I scripts/check-ops.py "$out/metrics-smoke.txt" "$out/metrics-builder.txt"
fi
step smoke-two-instances 300 scripts/smoke-two-instances.sh
step smoke-exits 300 scripts/smoke-exits.sh
step smoke-crash 900 scripts/smoke-crash.sh 30
step interchange-out 600 scripts/interchange-out.sh

if [ "$integration" -eq 1 ]; then
  if need dirk-integration "$dirk_net"; then
    step dirk-integration 1200 env PATH="$tools/dirk-1.2.1:$tools/ethdo-1.39.1:$PATH" scripts/dirk-it.sh "$dirk_net"
  fi
  if need web3signer-integration "$tools/web3signer-26.10.1/bin/web3signer"; then
    step web3signer-integration 1200 env JAVA_HOME="$tools/jdk-25.0.5+8-jre" scripts/web3signer-it.sh "$tools/web3signer-26.10.1/bin/web3signer"
  fi
  pg=$DL_DIR/postgresql-16/root
  if need web3signer-postgres "$pg/usr/lib/postgresql/16/bin/postgres"; then
    step web3signer-postgres 900 env W3S="$tools/web3signer-26.10.1/bin/web3signer" JAVA_HOME="$tools/jdk-25.0.5+8-jre" \
      PG_BIN="$pg/usr/lib/postgresql/16/bin" LD_LIBRARY_PATH="$pg/usr/lib/x86_64-linux-gnu" \
      scripts/web3signer-pg-it.sh "$out/w3s-pg"
  fi
  charon=$DL_DIR/charon-v1.11.2/bin/charon-v1.11.2-linux-amd64
  if need charon-integration "$charon"; then
    step charon-integration 1200 env CHARON="$charon" scripts/charon-it.sh "$PWD/$out/charon"
  fi
else
  summary+=("off   integration steps (--no-integration)")
fi

echo
echo "ci: $(( $(date +%s) - started )) s, logs in $out"
printf '%s\n' "${summary[@]}"
exit $failed
