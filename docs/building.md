# Building and testing

## Requirements

Needs the .NET 10 SDK (`global.json` pins 10.0.403), `libicu` at run time (EIP-2335 passwords need NFKD) and, for the NativeAOT publish, `clang` and `zlib1g-dev`.

## CPU

The linux-x64 binary needs AVX: Intel Sandy Bridge (2011) or newer, AMD Bulldozer or Jaguar or newer, and every AMD Zen. It does not run on Nehalem, Westmere or older Intel cores, nor on Intel Atom-class cores up to Tremont, which includes the Celeron and Pentium N and J series (N5105, J4125 and the like). On such a CPU it stops at once with:

```
The required instruction sets are not supported by the current CPU.
```

`grep -m1 -o -w avx /proc/cpuinfo` prints `avx` on a CPU that can run it. AVX2 is optional: with it, SSZ hashing (block and envelope roots) uses 8 lanes instead of 4. Version 0.1.0 builds linux-x64 only; a linux-arm64 build is planned. To build for an older x64 CPU anyway, publish with `-p:IlcInstructionSet=x86-64-v2` (unsupported; the block root takes about 1.3 ms longer).

The [runbook's "Install" section](runbook.md#install) says what to do on a host without AVX and how to install the binary as a systemd service.

## Build, test and smoke tests

```sh
dotnet build -m:2
scripts/fetch-test-vectors.sh      # EIP-3076 interchange tests, not in the repo; the tests fail without them
dotnet test -m:2
scripts/publish-aot.sh             # artifacts/publish/linux-x64/eplix and libblst.so
scripts/smoke-aot.sh               # the published binary decrypts the EIP-2335 vectors
scripts/smoke-gloas.sh             # the published binary attests across the Gloas fork and casts PTC votes
scripts/smoke-metrics.sh           # the published binary waits out the doppelganger check, attests, serves /metrics
scripts/smoke-two-instances.sh     # a second binary on the same data dir exits with the lock error
scripts/smoke-crash.sh [rounds]    # kill -9 while signing (64 keys, 200 rounds): no mark lost, no double vote
scripts/interchange-out.sh         # an Eplix slashing export imports into Lighthouse, Teku, Nimbus, Lodestar and Prysm
scripts/ci.sh                      # everything above plus the integration tests, each step with a time limit
scripts/nightly.sh [ssz] [fuzz] [flaky]   # every spec vector, 100,000 fuzz cases with a logged seed, 30 repeats of the timing-heavy lists
scripts/fuzz-week.sh --round       # one of the 7 nightly fuzz rounds (cron), or --now for all 7
scripts/soak.sh [seconds]          # 1,000 keys for 24 h: memory and descriptors flat, no duty missed
scripts/startup-keys.sh <keys>     # start-up time and memory at a key count
scripts/mutants.sh                 # about 30 hand-written mutants of the slashing, signing and duty checks must each fail a test
EPLIX_FUZZ_CASES=100000 dotnet tests/Eplix.Tests/bin/Debug/net10.0/Eplix.Tests.dll --filter-test-list fuzz   # a longer fuzz run, about 20 min
dotnet run -c Release --project benchmarks/Eplix.Bench -- --filter '*'
scripts/dirk-local.sh setup ~/dirk-net   # three local Dirk instances, 2 of 3 accounts, test keys only
scripts/dirk-it.sh ~/dirk-net            # integration tests against them
scripts/smoke-dirk.sh ~/dirk-net         # the published binary attests through them, also with one down
scripts/web3signer-it.sh ~/tools/web3signer-26.10.1/bin/web3signer   # four local Web3Signer instances: whole keys over mutual TLS, 2 of 3 shares
scripts/web3signer-pg-it.sh ~/w3s-pg   # one Web3Signer with its slashing protection on PostgreSQL: a 412 halts the key (W3S, JAVA_HOME, PG_BIN set)
scripts/gateway-smoke.sh ~/dirk-net <gateway binary>                 # a Web3Signer-compatible gateway in front of the Dirk cluster
scripts/tee-it.sh <runner-dev-debugimport>   # five local dev-platform TEE runners; with the published binary also its smoke test
scripts/charon-it.sh ~/charon-net        # Obol mode: four VCs against a local 4-node Charon cluster (threshold 3) on its beacon mock
```

## Layout

Code paths use `eplix` in lower case; projects are `Eplix.*` and the binary is `eplix`.

| Path | What |
| --- | --- |
| `src/Eplix.Core` | the core: types, SSZ, BLS, chain spec, Beacon API client and node set, slashing DB, key registry, pipeline, duty scheduler, runner |
| `src/Eplix.Backend.Local` | the local key module: EIP-2335 keystores, client layouts, key reload |
| `src/Eplix.Keymanager` | the keymanager API module (Kestrel) |
| `src/Eplix.Backend.Dirk` | the Dirk module: gRPC client, accounts, threshold groups for distributed accounts |
| `src/Eplix.Backend.Web3Signer` | the Web3Signer module: HTTP client, request bodies, whole keys and share groups |
| `src/Eplix.Backend.Tee` | the TEE signer module: runner protocol, connection pool, attestation verifiers, whole keys and m of n groups |
| `src/Eplix.Gloas` | the Gloas duties module: PTC votes, produceBlockV4 proposals and envelopes, proposer preferences |
| `src/Eplix.Builder` | the builder module: builder config, request auth, builder preferences, bid checks |
| `src/Eplix.Metrics` | the metrics module: Prometheus text endpoint (Kestrel) over the core's instruments |
| `src/Eplix.Doppelganger` | the doppelganger module: liveness checks before a key signs |
| `src/Eplix.Obol` | the Obol module: combined selection proofs from a distributed validator middleware |
| `src/Eplix.Monitor` | the validator monitor module: inclusion, votes, proposals, sync messages and balances of the VC's keys on chain |
| `src/Eplix.Graffiti` | the graffiti file module: per-key and default graffiti with templates and rotation |
| `src/Eplix.Tracing` | the tracing module: an ActivityListener over the core's spans and an OTLP/HTTP exporter |
| `src/Eplix` | the `eplix` binary; links the modules (`-p:EplixLocal=false`, `-p:EplixDirk=false`, `-p:EplixWeb3Signer=false`, `-p:EplixTee=false`, `-p:EplixKeymanager=false`, `-p:EplixGloas=false`, `-p:EplixBuilder=false`, `-p:EplixMetrics=false`, `-p:EplixDoppelganger=false` `-p:EplixObol=false`, `-p:EplixMonitor=false`, `-p:EplixGraffiti=false` and `-p:EplixTracing=false` drop them) |
| `tests/Eplix.Tests` | Expecto and FsCheck tests |
| `benchmarks/Eplix.Bench` | BenchmarkDotNet microbenchmarks of the hot paths |
| `tests/vectors` | spec test vectors (subset), see `tests/vectors/README.md` |
| `tests/fixtures` | recorded Beacon API responses, EIP-2335 keystores, runner wire bytes and attestation verdicts of tee-signer's Go verifiers (`tee/`) |
| `scripts` | AOT publish with the warning check, smoke tests, vector download, fake beacon node, a local Dirk cluster, the TEE runner integration tests |
| `tests/tools/tee-oracle` | the Go program that makes `tests/fixtures/tee/oracle-vectors.json` |

## Network presets

`network` picks a built-in chain config (`src/Eplix.Core/Networks.fs`). Before each release, and as soon as a fork is scheduled on a built-in network:

- Refresh `tests/fixtures/networks/` from the sources `Networks.fs` names and run `dotnet test`. The preset tests fail while a built-in config lags its published one.
- For each fork: its `*_FORK_VERSION` and `*_FORK_EPOCH` in `Networks.fs` for every network that schedules it, the values in `NetworksTests.fs`, and a duties module for the fork linked in the build.
