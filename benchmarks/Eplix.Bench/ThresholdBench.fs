/// The VC's own work for a burst of threshold signatures, without signers: 2 of 3 members that
/// answer at once with partial signatures made ahead, so the run measures combining and
/// verifying only. Run: dotnet run -c Release --project benchmarks/Eplix.Bench -- threshold [keys] [rounds]
module Eplix.Bench.ThresholdBench

open System
open System.Diagnostics
open System.Numerics
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Bench.Benchmarks

let private r =
    BigInteger.Parse "52435875175126190479447740508185965837690552500527637822603658699938581184513"

let private scalar32 (x: BigInteger) =
    let b = x.ToByteArray(isUnsigned = true, isBigEndian = true)
    Array.append (Array.zeroCreate (32 - b.Length)) b

/// Shares of secretOf i at x = 1, 2, 3 on the line s + a x (2 of 3).
let private shares (i: int) =
    let s = BigInteger(ReadOnlySpan(secretOf i), isUnsigned = true, isBigEndian = true)
    let a = BigInteger(1000 + i)
    [| for x in 1..3 -> scalar32 (BigInteger.Remainder(s + a * BigInteger x, r)) |]

let private percentile (sorted: float[]) (p: float) =
    sorted[min (sorted.Length - 1) (int (Math.Ceiling(p / 100.0 * float sorted.Length)) - 1 |> max 0)]

let private caps =
    {
        Duties = set [ DutyKind.Attestation ]
        TypedOnly = false
        EnforcesSlashing = true
        ReturnsPartials = true
        MaxInFlight = 4096
    }

/// A member that answers from a table of partial signatures, without delay.
let private memberOf (index: uint64) (partials: Collections.Generic.Dictionary<PubKey, BlsSignature>) : Backend =
    {
        Name = $"member {index}"
        Capabilities = caps
        Keys = fun _ -> Task.FromResult []
        Health = fun _ -> Task.FromResult Up
        // Answers on the thread pool, as a network answer would.
        Sign =
            fun req _ ->
                task {
                    do! Task.Yield()
                    return Partial(index, partials[req.Key])
                }
        Dispose = fun () -> ValueTask.CompletedTask
    }

let run (argv: string list) =
    let n, rounds =
        match argv with
        | [] -> 1000, 5
        | [ k ] -> int k, 5
        | k :: rs :: _ -> int k, int rs

    printfn "Threshold burst, %d keys, 2 of 3, %d cores" n Environment.ProcessorCount
    let keys = Array.init n (fun i -> PubKey.Of(Bls.publicKey (ReadOnlySpan(secretOf i))))
    let d = data 64UL

    let reqs =
        Duty.requests spec (root 0) keys Priority.High (DateTimeOffset.UtcNow.AddMinutes 10.0) (Duty.Attestation d)

    let root = reqs[0].SigningRoot
    let tables = Array.init 3 (fun _ -> Collections.Generic.Dictionary<PubKey, BlsSignature>())

    Parallel.For(
        0,
        n,
        fun i ->
            let sh = shares i

            for x in 0..2 do
                let s = BlsSignature.Of(Bls.sign (ReadOnlySpan sh[x]) (ReadOnlySpan root.Bytes))
                lock tables[x] (fun () -> tables[x][keys[i]] <- s)
    )
    |> ignore

    let group =
        Threshold.create
            "bench 2 of 3"
            2
            [
                for x in 0..2 ->
                    {
                        Backend = memberOf (uint64 (x + 1)) tables[x]
                        Index = uint64 (x + 1)
                        Budget = TimeSpan.FromSeconds 30.0
                    }
            ]
            TimeProvider.System
            Log.none

    for round in 0..rounds do
        let latencies = Array.zeroCreate<float> n
        let cpu0 = Process.GetCurrentProcess().TotalProcessorTime
        let sw = Stopwatch.StartNew()

        let outcomes =
            reqs
            |> Array.mapi (fun i req ->
                task {
                    let! o = group.Sign req CancellationToken.None
                    latencies[i] <- sw.Elapsed.TotalMilliseconds
                    return o
                })
            |> Task.WhenAll
            |> fun t -> t.Result

        let total = sw.Elapsed.TotalMilliseconds
        let cpu = (Process.GetCurrentProcess().TotalProcessorTime - cpu0).TotalMilliseconds

        let bad =
            outcomes
            |> Array.filter (fun o ->
                match o with
                | Signed _ -> false
                | _ -> true)

        if bad.Length > 0 then
            printfn "  %d not signed, first: %s" bad.Length bad[0].Describe

        let s = Array.sort latencies
        // Round 0 warms up (JIT, decoded keys); it is printed but not counted.
        printfn
            "%s round %d: last %7.1f ms, CPU %6.0f ms, p50 %7.1f ms, p99 %7.1f ms"
            (if round = 0 then "warm-up" else "burst  ")
            round
            total
            cpu
            (percentile s 50.0)
            (percentile s 99.0)

    0
