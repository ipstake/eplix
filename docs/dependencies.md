# Dependencies

Every package is pinned in `Directory.Packages.props` and by content hash in each project's
`packages.lock.json`. CI restores with `-p:ContinuousIntegrationBuild=true`, which turns on locked
mode.

## Runtime

| Package | Version | Licence | Where | Why |
| --- | --- | --- | --- | --- |
| FSharp.Core | 10.1.402 | MIT | every project | the F# standard library, the version that ships with SDK 10.0.402 |
| Nethermind.Crypto.Bls | 0.3.17.15 | MIT; bundled blst is Apache-2.0 | core | BLS sign, verify, aggregate and the G2 arithmetic threshold signing needs (design 11.3). 0.3.17.15 is the newest listed version; the 1.x versions are unlisted. |
| ASP.NET Core shared framework (`Microsoft.AspNetCore.App`) | 10.0.14 | MIT | keymanager and metrics modules | Kestrel for the keymanager API (design 10.2) and the metrics endpoint. A framework reference, not a NuGet package; the linux-x64 runtime pack is in the SDK cache. It adds about 5 MB to the binary; it goes only when both modules go, `-p:EplixKeymanager=false -p:EplixMetrics=false`. |
| Grpc.Net.Client | 2.84.0 | Apache-2.0 | Dirk module | gRPC over HTTP/2 to Dirk (design 5.2, 10.2). The newest stable version. The module brings its own message code, so no `Google.Protobuf`. Brings `Grpc.Net.Common` and `Grpc.Core.Api` 2.84.0 (Apache-2.0) and `Microsoft.Extensions.Logging.Abstractions` with `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.1 (MIT), all transitive and pinned by the lock files. About 1.5 MB in the binary; `-p:EplixDirk=false` drops it. |

The Web3Signer module adds no package: it uses `System.Net.Http`, `System.Text.Json` and the X.509 classes of the BCL.

The TEE signer module adds no package either: TLS, X.509, ECDSA, RSA and JSON come from the BCL. Design 10.6 lists `System.Formats.Cbor` for the Nitro documents; it is not in the local package cache, so the module carries a small CBOR reader.

The NativeAOT toolchain (Microsoft.DotNet.ILCompiler and its runtime packs, 10.0.14) is a build
input, not a dependency of the binary.

## Test only

| Package | Version | Licence | Why |
| --- | --- | --- | --- |
| Expecto | 10.2.3 | Apache-2.0 | test framework (design 12) |
| YoloDev.Expecto.TestSdk | 0.16.1 | MIT | lets `dotnet test` run Expecto tests |
| Microsoft.NET.Test.Sdk | 18.11.0 | MIT | the `dotnet test` host |
| FsCheck | 3.6.0 | BSD-3-Clause | property and model-based tests (design 12.2, 12.3) |
| Microsoft.Extensions.TimeProvider.Testing | 10.11.0 | MIT | `FakeTimeProvider`, so scheduler tests run on a fake clock |
| BenchmarkDotNet | 0.15.8 | MIT | microbenchmarks of the hot paths (`benchmarks/Eplix.Bench`, design 10.5); its transitive packages are in `benchmarks/Eplix.Bench/packages.lock.json` |

## Not used, on purpose

- Nethermind's SSZ generator and containers (LGPL-3.0): the VC has its own SSZ codec.
- System.Text.Json source generators: they do not run in F# projects.
- Microsoft.Extensions.Logging: a small logger in the core. The logging abstractions are in the binary only as a dependency of Grpc.Net.Client, which gets no logger factory.
- The OpenTelemetry packages (`OpenTelemetry`, `OpenTelemetry.Exporter.OpenTelemetryProtocol`): metrics use `System.Diagnostics.Metrics` with the Prometheus endpoint of the metrics module, and spans use `System.Diagnostics.Activity` with the tracing module's own OTLP/HTTP protobuf writer (`src/Eplix.Tracing/Otlp.fs`). The SDK and its exporter would be new runtime packages under design 10.6 for one request whose spans need five message types, written by hand as the Dirk module's are.
- `Google.Protobuf` and `Grpc.Tools`: the Dirk module writes its few messages by hand; `Grpc.Tools` would add native `protoc` binaries to the build inputs.
