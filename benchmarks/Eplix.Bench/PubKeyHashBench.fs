/// PubKey.GetHashCode and Dictionary<PubKey, _>.TryGetValue, the hash over all 48 bytes
/// against the old one over bytes 4 to 7. OldKey is PubKey with the old hash
/// code, everything else equal. Rounds of each kind interleave; the table gives the median
/// round. Stopwatch and no printf, so the file also builds into a NativeAOT binary.
/// Run: dotnet run -c Release --project benchmarks/Eplix.Bench -- pubkey-hash [rounds]
module Eplix.Bench.PubKeyHashBench

open System
open System.Collections.Generic
open System.Diagnostics
open Eplix

[<Struct; CustomEquality; NoComparison>]
type OldKey =
    | OldKey of byte[]

    member this.Bytes = let (OldKey b) = this in b

    override this.Equals(o) =
        match o with
        | :? OldKey as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 4)

    interface IEquatable<OldKey> with
        member this.Equals(r) = this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)

let private keyBytes (rng: Random) (n: int) =
    Array.init n (fun _ ->
        let b = Array.zeroCreate<byte> 48
        rng.NextBytes b
        b)

/// Nanoseconds per hash over `keys`, `reps` passes.
let private hashNs (keys: 'K[]) (reps: int) =
    let mutable acc = 0
    let sw = Stopwatch.StartNew()

    for _ in 1..reps do
        for i in 0 .. keys.Length - 1 do
            acc <- acc ^^^ keys[i].GetHashCode()

    let ns = sw.Elapsed.TotalNanoseconds / float (reps * keys.Length)

    if acc = 42 then
        Console.Write ""

    ns

/// Nanoseconds per TryGetValue of a hit: `probes` are copies of the keys (other arrays, as a
/// key parsed from a request is), in a shuffled order.
let private lookupNs<'K when 'K: equality> (d: Dictionary<'K, int>) (probes: 'K[]) (reps: int) =
    let mutable acc = 0
    let sw = Stopwatch.StartNew()

    for _ in 1..reps do
        for i in 0 .. probes.Length - 1 do
            match d.TryGetValue probes[i] with
            | true, v -> acc <- acc + v
            | _ -> ()

    let ns = sw.Elapsed.TotalNanoseconds / float (reps * probes.Length)

    if acc = 42 then
        Console.Write ""

    ns

let private median (xs: ResizeArray<float>) =
    let a = xs.ToArray()
    Array.sortInPlace a
    a[a.Length / 2]

let run (args: string list) =
    let rounds =
        match args with
        | r :: _ -> int r
        | [] -> 21

    let aot = not Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported
    Console.WriteLine $"runtime: {Runtime.InteropServices.RuntimeInformation.FrameworkDescription}, NativeAOT: {aot}"
    // Hash: 1,024 keys that stay in cache, 2,000 passes per round.
    let rng = Random 524
    let hk = keyBytes rng 1024
    let oldH = hk |> Array.map OldKey
    let newH = hk |> Array.map PubKey.Of
    let ho, hn = ResizeArray<float>(), ResizeArray<float>()

    for _ in 1..rounds do
        ho.Add(hashNs oldH 2000)
        hn.Add(hashNs newH 2000)

    Console.WriteLine "| case | old ns | new ns |"
    Console.WriteLine "|---|---:|---:|"
    Console.WriteLine $"| GetHashCode | {median ho:F2} | {median hn:F2} |"

    for n in [ 1_000; 10_000; 100_000 ] do
        let keys = keyBytes rng n
        let oldD = Dictionary<OldKey, int>(n)
        let newD = Dictionary<PubKey, int>(n)

        keys
        |> Array.iteri (fun i k ->
            oldD[OldKey k] <- i
            newD[PubKey.Of k] <- i)

        let order = Array.init n id
        rng.Shuffle order
        let oldP = order |> Array.map (fun i -> OldKey(Array.copy keys[i]))
        let newP = order |> Array.map (fun i -> PubKey.Of(Array.copy keys[i]))
        // About 2 million lookups per round.
        let reps = max 1 (2_000_000 / n)
        let lo, ln = ResizeArray<float>(), ResizeArray<float>()
        lookupNs oldD oldP reps |> ignore
        lookupNs newD newP reps |> ignore

        for _ in 1..rounds do
            lo.Add(lookupNs oldD oldP reps)
            ln.Add(lookupNs newD newP reps)

        Console.WriteLine $"| TryGetValue, {n} keys | {median lo:F2} | {median ln:F2} |"

    0
