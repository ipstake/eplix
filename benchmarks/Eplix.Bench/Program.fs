module Eplix.Bench.Program

open BenchmarkDotNet.Configs
open BenchmarkDotNet.Jobs
open BenchmarkDotNet.Running
open BenchmarkDotNet.Toolchains.InProcess.Emit

[<EntryPoint>]
let main argv =
    match List.ofArray argv with
    | "dirk" :: rest -> DirkBench.run rest
    | "threshold" :: rest -> ThresholdBench.run rest
    | "w3s-attest" :: rest -> W3sAttestBench.run rest
    | "slashing-merge" :: rest -> SlashingMergeBench.run rest
    | "pubkey-hash" :: rest -> PubKeyHashBench.run rest
    | _ ->
        // In process: no generated project to build, so the run needs no network and no Roslyn.
        let config = DefaultConfig.Instance.AddJob(Job.ShortRun.WithToolchain(InProcessEmitToolchain.Instance))
        BenchmarkSwitcher.FromAssembly(typeof<Benchmarks.Ssz>.Assembly).Run(argv, config) |> ignore
        0
