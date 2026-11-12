/// PubKeyHashBench's cases under BenchmarkDotNet (JIT): the old hash over bytes 4 to 7
/// (OldKey) against PubKey's over all 48 bytes. Each op is one hash or one
/// TryGetValue of a hit, with probes that are copies of the keys in shuffled order.
/// Run: dotnet run -c Release --project benchmarks/Eplix.Bench -- --filter '*PubKeyHash*'
module Eplix.Bench.PubKeyHashBdn

open System
open System.Collections.Generic
open BenchmarkDotNet.Attributes
open Eplix
open Eplix.Bench.PubKeyHashBench

[<MemoryDiagnoser>]
type PubKeyHash() =
    let mutable oldD = Dictionary<OldKey, int>()
    let mutable newD = Dictionary<PubKey, int>()
    let mutable oldP: OldKey[] = [||]
    let mutable newP: PubKey[] = [||]

    [<Params(1_000, 10_000, 100_000)>]
    member val N = 0 with get, set

    [<GlobalSetup>]
    member this.Setup() =
        let rng = Random 524

        let keys =
            Array.init this.N (fun _ ->
                let b = Array.zeroCreate<byte> 48
                rng.NextBytes b
                b)

        oldD <- Dictionary<OldKey, int>(this.N)
        newD <- Dictionary<PubKey, int>(this.N)

        keys
        |> Array.iteri (fun i k ->
            oldD[OldKey k] <- i
            newD[PubKey.Of k] <- i)

        let order = Array.init this.N id
        rng.Shuffle order
        oldP <- order |> Array.map (fun i -> OldKey(Array.copy keys[i]))
        newP <- order |> Array.map (fun i -> PubKey.Of(Array.copy keys[i]))

    [<Benchmark(OperationsPerInvoke = 1_000)>]
    member _.OldHash() =
        let mutable acc = 0

        for i in 0..999 do
            acc <- acc ^^^ oldP[i].GetHashCode()

        acc

    [<Benchmark(OperationsPerInvoke = 1_000)>]
    member _.NewHash() =
        let mutable acc = 0

        for i in 0..999 do
            acc <- acc ^^^ newP[i].GetHashCode()

        acc

    [<Benchmark(OperationsPerInvoke = 100_000)>]
    member this.OldLookup() =
        let mutable acc = 0
        let n = oldP.Length

        for i in 0..99_999 do
            match oldD.TryGetValue oldP[i % n] with
            | true, v -> acc <- acc + v
            | _ -> ()

        acc

    [<Benchmark(OperationsPerInvoke = 100_000)>]
    member this.NewLookup() =
        let mutable acc = 0
        let n = newP.Length

        for i in 0..99_999 do
            match newD.TryGetValue newP[i % n] with
            | true, v -> acc <- acc + v
            | _ -> ()

        acc
