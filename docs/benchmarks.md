# Benchmarks

Measured on the tree of release 0.1.0. Each section has the command that gives its numbers. Design 10.4 lists the targets.

## Setup

- Machine: a WSL2 virtual machine with 8 vCPUs (the VM reports 4 cores with 2 threads each) and 32 GB of RAM on an Intel Core i7-13700 host. Ubuntu 24.04.5, kernel 5.15.167.4-microsoft-standard-WSL2. Other virtual machines shared the host, so runs on the same tree can differ by tens of percent.
- .NET SDK 10.0.403 with runtime 10.0.14. The benchmark program runs under the JIT (RyuJIT, x86-64-v3). The start-up runs use the NativeAOT binary.
- BenchmarkDotNet 0.15.8, ShortRun job (one launch, 3 warm-up and 3 measured iterations), in-process toolchain, with the memory diagnoser. Its host line says `DEBUG`; the benchmark and the projects it references are built with `-c Release`. With 3 iterations the Error column (half the 99.9% confidence interval) is wide, so read the means as orders of magnitude.
- Dirk 1.2.1 and ethdo 1.39.1 for the Dirk path, Python 3.12.3 for `scripts/fake-beacon-node.py`.
- One run per benchmark, two for the Dirk path. A range in a table is the lowest and highest value over the rounds of the runs.

## Local signing hot path

```
dotnet run -c Release --project benchmarks/Eplix.Bench -- --filter 'Eplix.Bench.Benchmarks*'
```

| Benchmark | Mean | StdDev | Allocated | What it does |
| --- | --- | --- | --- | --- |
| `Ssz.HashAttestationData` | 2.77 µs | 0.02 µs | 1,976 B | hash tree root of one AttestationData |
| `Ssz.SigningRoot` | 3.20 µs | 0.02 µs | 2,480 B | the same plus the signing root |
| `Ssz.Domain` | 0.47 µs | 0.01 µs | 640 B | the domain of an epoch |
| `Bls.Sign` | 250 µs | 2 µs | 488 B | one signature (blst through Nethermind.Crypto.Bls) |
| `Bls.Verify` | 803 µs | 10 µs | 2,355 B | one verification |
| `Bls.FastAggregateVerify64` | 5.39 ms | 0.06 ms | 10,767 B | 64 keys, one message |
| `Slashing.Burst1000InMemory` | 291 µs | 35 µs | 1,780 KB | 1,000 attestations checked and recorded, no fsync |
| `Slashing.Burst1000Fsync` | 1.62 ms | 0.06 ms | 756 KB | the same on a real file with one fsync |
| `Json.DecodeAttesterDuties1000` | 558 µs | 32 µs | 598 KB | the duties answer for 1,000 keys |
| `Json.EncodeAttestations1000` | 2.32 ms | 0.07 ms | 4,846 KB | the submission body of 1,000 attestations |
| `Pipeline.AttestationBurst1000` | 46.3 ms | 5.0 ms | 2.16 MB | 1,000 keys through the pipeline: slashing check in memory, local signing on 8 vCPUs |
| `PipelineTraced.AttestationBurst1000`, `Listen=duty` | 63.2 ms (median 44.7 ms) | 35.7 ms | 2.24 MB | the same burst with a listener on the duty spans |
| `PipelineTraced.AttestationBurst1000`, `Listen=all` | 45.7 ms | 0.8 ms | 3.23 MB | the same plus one span per signing request (`sign_spans`) |

The 1,000-key burst is 1,000 signatures in about 46 ms on 8 vCPUs.

## Threshold signing (bench mode, no signers)

```
dotnet run -c Release --project benchmarks/Eplix.Bench -- threshold 1000 5
dotnet run -c Release --project benchmarks/Eplix.Bench -- threshold 8000 5
```

Each key has 2 of 3 members in the same process that answer at once, on the thread pool, with partial signatures made ahead. The run measures what Eplix does for a burst: it combines the partials and verifies each combined signature. Round 0 warms up and is not counted; the table gives the range over rounds 1 to 5. Latency counts from the start of the burst to each request's verified signature.

| Keys | Last signature | Eplix CPU | p50 | p99 |
| --- | --- | --- | --- | --- |
| 1,000 | 30.7 to 42.3 ms | 194 to 209 ms | 30.6 to 33.9 ms | 30.7 to 42.2 ms |
| 8,000 | 279.7 to 322.6 ms | 1,527 to 1,766 ms | 216.3 to 277.7 ms | 279.4 to 321.7 ms |

That is about 0.2 ms of CPU per threshold signature.

## Dirk path

```
scripts/dirk-local.sh setup ~/dirk-bench
scripts/dirk-local.sh bench-accounts ~/dirk-bench 1000
scripts/dirk-local.sh wipe-protection ~/dirk-bench
scripts/dirk-local.sh start ~/dirk-bench
dotnet run -c Release --project benchmarks/Eplix.Bench -- dirk ~/dirk-bench 1000
```

The cluster is three Dirk instances on the same 8 vCPUs as Eplix, over loopback with mutual TLS, with 1,000 distributed 2 of 3 accounts. `dirk1` to `dirk3` must resolve to 127.0.0.1, and `dirk` and `ethdo` must be on the PATH (or in `DIRK` and `ETHDO`). Wipe Dirk's slashing protection before each run: the bench signs fixed epochs. The bench warms up with one burst of each kind first. Two runs.

One request at a time, 200 after 20 warm-up requests:

| Request | p50 | p99 |
| --- | --- | --- |
| One Dirk, share of a distributed account, RANDAO (`Sign`) | 0.58 to 0.59 ms | 0.72 to 0.88 ms |
| One Dirk, plain account, RANDAO (`Sign`) | 0.59 ms | 1.23 to 1.54 ms |
| One Dirk, plain account, attestation (Dirk writes its slashing DB) | 1.82 to 1.83 ms | 8.71 to 9.44 ms |
| 2 of 3, RANDAO: three calls, combine, verify | 1.60 to 1.63 ms | 2.96 to 3.57 ms |
| 2 of 3, attestation, one request per call | 3.01 to 3.06 ms | 8.27 to 8.98 ms |
| 2 of 3, attestation, batched call (`SignBeaconAttestations`, a batch of one) | 2.93 to 2.95 ms | 6.64 to 9.27 ms |

Bursts of 1,000 requests for 1,000 keys with one AttestationData, through the pipeline: the slashing check on a real file with one fsync, then every request at once. Three rounds per run for the 2 of 3 attestation bursts, one per run for the rest:

| Burst | Last signature | Eplix CPU |
| --- | --- | --- |
| Attestations, 2 of 3, batched | 180.9 to 214.3 ms | 231 to 342 ms |
| Attestations, 2 of 3, one request per call | 213.6 to 273.0 ms | 341 to 452 ms |
| RANDAO, 2 of 3 (Dirk writes no slashing DB) | 201.6 to 236.4 ms | 361 to 399 ms |
| Attestations to `dirk1` only (shares, no combination) | 56.7 to 78.1 ms | 20 to 34 ms |
| RANDAO to `dirk1` only (shares) | 39.9 to 51.4 ms | 15 to 45 ms |

Latency of each request from the start of one 1,000-attestation burst sent straight to the 2 of 3 groups:

| Calls | p50 | p99 |
| --- | --- | --- |
| Batched | 168.3 to 173.4 ms | 177.4 to 180.4 ms |
| One request per call | 150.4 to 154.2 ms | 212.5 to 220.7 ms |

One Dirk answers the 1,000 shares in 40 to 80 ms. In a 2 of 3 burst the three Dirk instances sign 3,000 requests on the same 8 vCPUs as Eplix, and Eplix waits for the second answer per key.

## TEE runners

Not measured for this release: it needs a tee-signer runner binary. Build `runner-dev-debugimport` with tee-signer's `scripts/build-runner.sh` (platform dev, `-tags debugimport`, protocol level 2 or higher), then:

```
EPLIX_TEE_BENCH=1000 scripts/tee-it.sh <path to runner-dev-debugimport>
```

The test `burst: 1,000 attestations through 2 of 3 runners` starts three local runners, gives each one share of 1,000 keys, sends each attestation to all three over mutual TLS 1.3 and prints p50, p99, the last signature and Eplix's CPU per round.

## Start-up and memory

```
scripts/publish-aot.sh
dotnet build -c Debug
scripts/startup-keys.sh 1000
scripts/startup-keys.sh 10000
```

The published binary loads local keystores (PBKDF2 with 16 rounds) and attests against `scripts/fake-beacon-node.py` with 12 s slots and 8 slots an epoch, for 4 epochs. The script samples the resident memory every 2 s. The fake chain starts at genesis, and the keys have no slashing history, so `allow_start_without_history` gives each a floor at epoch 1 and the first attestation duty is at epoch 2, about 194 s after the start.

| Keys | Keys decrypted | First log line to ready | RSS 2 s after the start | Highest RSS | RSS at the end | Attestations |
| --- | --- | --- | --- | --- | --- | --- |
| 1,000 | 0.05 s | 0.13 s | 66 MiB | 73 MiB | 72 MiB | every key in epochs 2 and 3 |
| 10,000 | 0.51 s | 0.60 s | 121 MiB | 139 MiB | 132 MiB | every key in epochs 2 and 3 |

## Binary size

```
scripts/publish-aot.sh
```

The NativeAOT binary for linux-x64 with every default module (`artifacts/publish/linux-x64/eplix`, instruction set `x86-64-v2,avx`) is 23,759,304 bytes (22.7 MiB).
