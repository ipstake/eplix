/// The Dirk path against a live local cluster (scripts/dirk-local.sh with bench-accounts):
/// latency per request and a burst of attestations through 2 of 3 Dirk instances.
/// Run: dotnet run -c Release --project benchmarks/Eplix.Bench -- dirk <cluster dir> [burst size]
/// Wipe Dirk's slashing protection first (scripts/dirk-local.sh wipe-protection), since the
/// attestations use fixed target epochs.
module Eplix.Bench.DirkBench

open System
open System.Diagnostics
open System.IO
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Backend.Dirk
open Eplix.Slashing
open Eplix.Bench.Benchmarks

let private gvr = root 77

let private percentile (sorted: float[]) (p: float) =
    sorted[min (sorted.Length - 1) (int (Math.Ceiling(p / 100.0 * float sorted.Length)) - 1 |> max 0)]

let private report (what: string) (ms: float[]) =
    let s = Array.sort ms

    printfn
        "%-58s n=%5d  p50 %7.2f ms  p90 %7.2f ms  p99 %7.2f ms  max %7.2f ms  mean %7.2f ms"
        what
        s.Length
        (percentile s 50.0)
        (percentile s 90.0)
        (percentile s 99.0)
        (Array.last s)
        (Array.average s)

let private settings (net: string) (batch: bool) : DirkModule.Settings =
    {
        Endpoints = [ "dirk1:19591"; "dirk2:19592"; "dirk3:19593" ]
        Accounts = [ "Bench"; "Solo" ]
        Tls =
            {
                CaCert = Path.Combine(net, "certs", "ca.crt")
                ClientCert = Path.Combine(net, "certs", "eplix.crt")
                ClientKey = Path.Combine(net, "certs", "eplix.key")
            }
        Timeout = TimeSpan.FromSeconds 20.0
        BatchAttestations = batch
        RefreshInterval = TimeSpan.Zero
        GloasCalls = GloasCalls.Auto
        ReloadInterval = TimeSpan.Zero
    }

let private discover (net: string) (batch: bool) =
    let s = settings net batch

    match GrpcDirk.loadTls s.Tls Log.none TimeProvider.System with
    | Error e -> failwith e
    | Ok tls ->
        let dirks = DirkModule.DirkSet((fun a -> GrpcDirk.connect a tls), s, TimeProvider.System, Log.none)
        let found, answered = dirks.Discover(CancellationToken.None).Result

        if answered < 3 then
            failwith $"{answered} of 3 Dirk instances answered"

        let named =
            found
            |> List.map (fun (key, backend) ->
                let name =
                    dirks.Endpoints
                    |> List.pick (fun e ->
                        e.TryAccount key |> ValueOption.map (fun a -> a.Name) |> ValueOption.toOption)

                name, (key, backend))
            |> Map.ofList

        dirks, named

let private attestation (target: Epoch) =
    {
        Slot = target * 32UL + 3UL
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = target - 1UL; Root = root 2 }
        Target = { Epoch = target; Root = root 3 }
    }

let private time (f: unit -> Task<SignOutcome>) =
    task {
        let sw = Stopwatch.StartNew()
        let! o = f ()
        sw.Stop()

        match o with
        | Signed _
        | Partial _ -> ()
        | o -> failwith $"not signed: {o.Describe}"

        return sw.Elapsed.TotalMilliseconds
    }

let private sequential (n: int) (warmup: int) (make: int -> SignRequest) (backend: Backend) =
    task {
        let out = ResizeArray<float>()

        for i in 0 .. n + warmup - 1 do
            let req = make i
            let! ms = time (fun () -> backend.Sign req CancellationToken.None)

            if i >= warmup then
                out.Add ms

        return out.ToArray()
    }

let private request (key: PubKey) (duty: Duty) =
    Duty.request spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 30.0) duty

/// The burst as the pipeline sends it: the slashing check of all with one fsync, then every
/// request at once. Returns the time to the last answer, the process CPU time it took, and
/// each request's latency from the start.
let private burst (routes: (PubKey * Backend) list) (duty: Duty) =
    task {
        let dir = Path.Combine(Path.GetTempPath(), "eplix-dirk-bench", Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory dir |> ignore

        use db =
            match SlashingDb.Open(new FileMarkFile(Path.Combine(dir, "s.db")), gvr) with
            | Ok db -> db
            | Error e -> failwith e

        db.RegisterKeys [ for k, _ in routes -> k, KeyOrigin.StartedEmpty ] |> ignore
        let registry = KeyRegistry()

        for k, b in routes do
            registry.Add(k, b) |> ignore
            registry.SetState(k, KeyState.Active)

        let pipeline = Eplix.Pipeline(db, registry, TimeProvider.System, Log.none)
        let keys = routes |> List.map fst |> Array.ofList
        let reqs = Duty.requests spec gvr keys Priority.High (DateTimeOffset.UtcNow.AddSeconds 30.0) duty
        let latencies = Array.zeroCreate<float> reqs.Length
        let cpu0 = Process.GetCurrentProcess().TotalProcessorTime
        let sw = Stopwatch.StartNew()

        let! outcomes =
            pipeline.SignBurst(reqs, CancellationToken.None)
            |> fun t ->
                task {
                    let! o = t
                    return o
                }

        let total = sw.Elapsed.TotalMilliseconds
        ignore latencies
        let cpu = (Process.GetCurrentProcess().TotalProcessorTime - cpu0).TotalMilliseconds

        let failed =
            outcomes
            |> Array.filter (fun o ->
                match o with
                | Signed _
                | Partial _ -> false
                | _ -> true)

        if failed.Length > 0 then
            printfn "  %d of %d not signed, first: %s" failed.Length outcomes.Length failed[0].Describe

        Directory.Delete(dir, true)
        return total, cpu
    }

/// The same burst with each request timed from the start of the burst to its own answer.
let private burstLatencies (routes: (PubKey * Backend) list) (duty: Duty) =
    task {
        let keys = routes |> List.map fst |> Array.ofList
        let reqs = Duty.requests spec gvr keys Priority.High (DateTimeOffset.UtcNow.AddSeconds 30.0) duty
        let byKey = Map.ofList routes
        let latencies = Array.zeroCreate<float> reqs.Length
        let sw = Stopwatch.StartNew()

        let! outcomes =
            reqs
            |> Array.mapi (fun i r ->
                task {
                    let! o = byKey[r.Key].Sign r CancellationToken.None
                    latencies[i] <- sw.Elapsed.TotalMilliseconds
                    return o
                })
            |> Task.WhenAll

        let failed =
            outcomes
            |> Array.filter (fun o ->
                match o with
                | Signed _
                | Partial _ -> false
                | _ -> true)

        if failed.Length > 0 then
            printfn "  %d of %d not signed, first: %s" failed.Length outcomes.Length failed[0].Describe

        return latencies
    }

let private runBurst (what: string) (routes: (PubKey * Backend) list) (duty: Duty) =
    let total, cpu = (burst routes duty).Result
    printfn "%-58s %d requests, last answer after %7.1f ms, Eplix CPU %6.0f ms" what routes.Length total cpu

let run (argv: string list) =
    let net, size =
        match argv with
        | [ net ] -> net, 1000
        | [ net; n ] -> net, int n
        | _ -> failwith "usage: dirk <cluster dir> [burst size]"

    printfn "Dirk path, cluster %s, %d cores" net Environment.ProcessorCount

    for batch in [ false; true ] do
        let dirks, named = discover net batch
        let label = if batch then "batched" else "unary"
        let benchKeys = [ for i in 1..size -> named[$"Bench/B{i}"] ]
        let key1, group1 = benchKeys.Head
        let soloKey, solo = named["Solo/Solo1"]
        let epochBase = if batch then 3000 else 1000
        let att (key: PubKey) i = request key (Duty.Attestation(attestation (uint64 (epochBase + i))))
        let randao (key: PubKey) i = request key (Duty.RandaoReveal(uint64 (epochBase + i)))
        let member1 = dirks.Endpoints |> List.find (fun e -> e.Address = "dirk1:19591")
        let share = member1.Backend "dirk1 share" true (fun _ _ -> true)
        // Warm-up, not reported: JIT, connections, and Dirk's first writes after a start.
        (burst benchKeys (Duty.RandaoReveal(uint64 (epochBase - 1)))).Result |> ignore
        (burst benchKeys (Duty.Attestation(attestation (uint64 (epochBase - 100))))).Result |> ignore
        // One request at a time.
        if not batch then
            report "one Dirk, distributed account share, RANDAO (Sign)" (sequential 200 20 (randao key1) share).Result
            report "one Dirk, plain account, RANDAO (Sign)" (sequential 200 20 (randao soloKey) solo).Result
            report "2 of 3, RANDAO (Sign), combine and verify" (sequential 200 20 (randao key1) group1).Result
            report "one Dirk, plain account, attestation" (sequential 200 20 (att soloKey) solo).Result

        report $"2 of 3, attestation ({label})" (sequential 200 20 (att key1) group1).Result
        // Bursts: one request per key, all at once, through the pipeline.
        for round in 0..2 do
            runBurst
                $"burst, attestations, 2 of 3, {label}, round {round}"
                benchKeys
                (Duty.Attestation(attestation (uint64 (epochBase + 500 + round))))

        report
            $"  latencies, attestations, 2 of 3, {label}"
            (burstLatencies benchKeys (Duty.Attestation(attestation (uint64 (epochBase + 510))))).Result

        runBurst
            $"burst, attestations, dirk1 only (shares), {label}"
            [ for k, _ in benchKeys -> k, share ]
            (Duty.Attestation(attestation (uint64 (epochBase + 520))))

        runBurst $"burst, RANDAO, 2 of 3 (no Dirk slashing DB)" benchKeys (Duty.RandaoReveal(uint64 (epochBase + 530)))

        runBurst
            $"burst, RANDAO, dirk1 only (shares)"
            [ for k, _ in benchKeys -> k, share ]
            (Duty.RandaoReveal(uint64 (epochBase + 540)))

        dirks.Stop()

    0
