/// Hot paths of the signing pipeline.
module Eplix.Bench.Benchmarks

open System
open System.IO
open System.Threading
open BenchmarkDotNet.Attributes
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing

let secretOf (i: int) =
    let b = Array.zeroCreate<byte> 32
    b[28] <- 0x11uy
    b[29] <- byte (i >>> 16)
    b[30] <- byte (i >>> 8)
    b[31] <- byte i
    b

let root (n: int) =
    let b = Array.zeroCreate<byte> 32
    b[0] <- byte n
    b[1] <- byte (n >>> 8)
    b[31] <- 0x5Auy
    Root.Of b

let data (slot: uint64) =
    {
        Slot = slot
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = slot / 32UL; Root = root 2 }
        Target =
            {
                Epoch = slot / 32UL + 1UL
                Root = root 3
            }
    }

let spec =
    match
        ChainSpec.parse (
            Map.ofList
                [
                    "PRESET_BASE", "mainnet"
                    "SECONDS_PER_SLOT", "12"
                    "GENESIS_FORK_VERSION", "0x00000000"
                    "ELECTRA_FORK_VERSION", "0x05000000"
                    "ELECTRA_FORK_EPOCH", "0"
                    "FULU_FORK_VERSION", "0x06000000"
                    "FULU_FORK_EPOCH", "0"
                ]
        )
    with
    | Ok s -> s
    | Error e -> failwith e

/// The slashing DB file in memory, for the cost of the checks without the fsync.
type MemoryMarkFile() =
    let ms = new MemoryStream()

    interface IMarkFile with
        member _.ReadAll() = ms.ToArray()
        member _.Append b = ms.Write(b, 0, b.Length)
        member _.Sync() = ()
        member _.Truncate n = ms.SetLength n

        member _.Replace b =
            ms.SetLength 0L
            ms.Write(b, 0, b.Length)

        member _.Dispose() = ms.Dispose()

[<MemoryDiagnoser>]
type Ssz() =
    let d = data 1000UL
    let domain = Signing.domainAt spec (root 0) spec.DomainBeaconAttester 1UL

    [<Benchmark>]
    member _.HashAttestationData() = Codec.hashAttestationData d

    [<Benchmark>]
    member _.SigningRoot() = Signing.computeSigningRoot (Codec.hashAttestationData d) domain

    [<Benchmark>]
    member _.Domain() = Signing.domainAt spec (root 0) spec.DomainBeaconAttester 1UL

[<MemoryDiagnoser>]
type Bls() =
    let sk = secretOf 1
    let msg = (root 9).Bytes
    let pk = Bls.publicKey (ReadOnlySpan sk)
    let sg = Bls.sign (ReadOnlySpan sk) (ReadOnlySpan msg)
    let keys = Array.init 64 (fun i -> Bls.publicKey (ReadOnlySpan(secretOf i)))

    let agg =
        (Bls.aggregate (Array.init 64 (fun i -> Bls.sign (ReadOnlySpan(secretOf i)) (ReadOnlySpan msg)))).Value

    [<Benchmark>]
    member _.Sign() = Bls.sign (ReadOnlySpan sk) (ReadOnlySpan msg)

    [<Benchmark>]
    member _.Verify() = Bls.verify (ReadOnlySpan pk) (ReadOnlySpan msg) (ReadOnlySpan sg)

    [<Benchmark>]
    member _.FastAggregateVerify64() = Bls.fastAggregateVerify keys (ReadOnlySpan msg) (ReadOnlySpan agg)

/// One attestation burst through the slashing DB: check, one append, one sync.
[<MemoryDiagnoser>]
type Slashing() =
    let n = 1000
    let keys = Array.init n (fun i -> PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i))))
    let mutable mem: SlashingDb = Unchecked.defaultof<_>
    let mutable disk: SlashingDb = Unchecked.defaultof<_>
    let mutable target = 1UL
    let dir = Path.Combine(Path.GetTempPath(), "eplix-bench-" + Guid.NewGuid().ToString("N"))

    let openDb (file: IMarkFile) =
        match SlashingDb.Open(file, root 0) with
        | Ok db ->
            db.RegisterKeys [ for k in keys -> k, KeyOrigin.StartedEmpty ] |> ignore
            db
        | Error e -> failwith e

    let burst () =
        target <- target + 1UL

        [|
            for k in keys -> AttestationRequest(k, target - 1UL, target, root (int target))
        |]

    [<GlobalSetup>]
    member _.Setup() =
        Directory.CreateDirectory dir |> ignore
        mem <- openDb (new MemoryMarkFile())
        disk <- openDb (new FileMarkFile(Path.Combine(dir, "slashing.db")))

    [<GlobalCleanup>]
    member _.Cleanup() =
        (mem :> IDisposable).Dispose()
        (disk :> IDisposable).Dispose()
        Directory.Delete(dir, true)

    /// 1,000 keys, no fsync: the cost of the checks and records.
    [<Benchmark>]
    member _.Burst1000InMemory() = mem.CheckAndRecord(burst (), CancellationToken.None).Result

    /// 1,000 keys with the real file and one fsync.
    [<Benchmark>]
    member _.Burst1000Fsync() = disk.CheckAndRecord(burst (), CancellationToken.None).Result

/// Beacon API JSON of the attestation path.
[<MemoryDiagnoser>]
type Json() =
    let n = 1000

    let duties =
        Json.toBytes (fun w ->
            w.WriteStartObject()
            w.WriteString("dependent_root", (root 4).Hex)
            w.WriteBoolean("execution_optimistic", false)
            w.WriteStartArray "data"

            for i in 0 .. n - 1 do
                w.WriteStartObject()
                w.WriteString("pubkey", PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i))).Hex)
                Json.writeU64 w "validator_index" (uint64 i)
                Json.writeU64 w "committee_index" (uint64 (i % 64))
                Json.writeU64 w "committee_length" 128UL
                Json.writeU64 w "committees_at_slot" 64UL
                Json.writeU64 w "validator_committee_index" (uint64 (i % 128))
                Json.writeU64 w "slot" (uint64 (i % 32))
                w.WriteEndObject()

            w.WriteEndArray()
            w.WriteEndObject())

    let sig96 = BlsSignature.Of(Bls.sign (ReadOnlySpan(secretOf 1)) (ReadOnlySpan (root 1).Bytes))

    let atts =
        Array.init n (fun i ->
            {
                CommitteeIndex = uint64 (i % 64)
                AttesterIndex = uint64 i
                Data = data 100UL
                Signature = sig96
            })

    [<Benchmark>]
    member _.DecodeAttesterDuties1000() = Json.decode Decoders.attesterDuties (ReadOnlyMemory duties)

    [<Benchmark>]
    member _.EncodeAttestations1000() = Encoders.singleAttestations atts

/// A whole burst through the pipeline: slashing DB (in memory) and local signing on every core.
[<MemoryDiagnoser>]
type Pipeline() =
    let n = 1000
    let keys = Array.init n (fun i -> PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i))))
    let mutable pipeline: Eplix.Pipeline = Unchecked.defaultof<_>
    let mutable target = 1UL

    [<GlobalSetup>]
    member _.Setup() =
        let db =
            match SlashingDb.Open(new MemoryMarkFile(), root 0) with
            | Ok db -> db
            | Error e -> failwith e

        db.RegisterKeys [ for k in keys -> k, KeyOrigin.StartedEmpty ] |> ignore

        let backend =
            LocalBackend.create "local" [ for i in 0 .. n - 1 -> keys[i], SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

        let registry = KeyRegistry()

        for k in keys do
            registry.Add(k, backend) |> ignore
            registry.SetState(k, KeyState.Active)

        pipeline <- Eplix.Pipeline(db, registry, TimeProvider.System, Log.none)

    /// 1,000 attestations with the same data: one signing root, 1,000 signatures.
    [<Benchmark>]
    member _.AttestationBurst1000() =
        target <- target + 1UL

        let d =
            { data (target * 32UL) with
                Source = { Epoch = target - 1UL; Root = root 2 }
                Target = { Epoch = target; Root = root 3 }
            }

        let reqs =
            Duty.requests spec (root 0) keys Priority.High (DateTimeOffset.UtcNow.AddMinutes 1.0) (Duty.Attestation d)

        pipeline.SignBurst(reqs, CancellationToken.None).Result

/// The same burst with a listener on the core's spans that records every span and drops it on
/// stop: the cost of the spans themselves, without the tracing module's queue and export.
/// `duty` listens to the duty source (sign burst, slashing check), `all` adds the span per
/// signing request (`sign_spans`). The duty root span is opened here, as the scheduler does.
[<MemoryDiagnoser>]
type PipelineTraced() =
    let inner = Pipeline()
    let mutable listener: Diagnostics.ActivityListener = null

    [<Params("duty", "all")>]
    member val Listen = "duty" with get, set

    [<GlobalSetup>]
    member this.Setup() =
        inner.Setup()
        let all = this.Listen = "all"
        let l = new Diagnostics.ActivityListener()
        l.ShouldListenTo <- fun s -> s.Name = Tracing.SourceName || (all && s.Name = Tracing.SignSourceName)
        l.Sample <- fun _ -> Diagnostics.ActivitySamplingResult.AllDataAndRecorded
        l.ActivityStopped <- fun _ -> ()
        Diagnostics.ActivitySource.AddActivityListener l
        listener <- l

    [<GlobalCleanup>]
    member _.Cleanup() = listener.Dispose()

    [<Benchmark>]
    member _.AttestationBurst1000() =
        use _duty = Tracing.duty "attestations" 1UL 1000
        inner.AttestationBurst1000()
