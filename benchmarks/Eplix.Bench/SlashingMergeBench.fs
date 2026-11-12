/// SlashingDb.ImportMarks on an in-memory mark file (fsync costs nothing here), with n new keys
/// plus 10% repeated entries, 5% empty entries and one key the DB already has. Reports the
/// wall time of the call, which runs entirely under the DB's key lock, the bytes it allocates,
/// and the longest wait of a CheckAndRecord on the known key while it runs (that key's lock is
/// held for the whole merge).
/// Run: dotnet run -c Release --project benchmarks/Eplix.Bench -- slashing-merge [n,n,...] [rounds]
module Eplix.Bench.SlashingMergeBench

open System
open System.Diagnostics
open System.Threading
open Eplix
open Eplix.Slashing

type private MemFile() =
    let data = Collections.Generic.List<byte>()

    interface IMarkFile with
        member _.ReadAll() = data.ToArray()
        member _.Append(bytes) = data.AddRange bytes
        member _.Sync() = ()
        member _.Truncate(length) = data.RemoveRange(int length, data.Count - int length)

        member _.Replace(bytes) =
            data.Clear()
            data.AddRange bytes

        member _.Dispose() = ()

let private gvr = Root.Of(Array.create 32 9uy)

let private keyOf (rng: Random) =
    let b = Array.zeroCreate<byte> 48
    rng.NextBytes b
    PubKey.Of b

let private marksOf (rng: Random) : KeyMarks =
    let root () =
        let b = Array.zeroCreate<byte> 32
        rng.NextBytes b
        ValueSome(Root.Of b)

    let s = uint64 (rng.Next(1, 100_000))

    {
        Block =
            ValueSome
                {
                    Slot = uint64 (rng.Next(1, 3_000_000))
                    Root = root ()
                }
        Attestation =
            ValueSome
                {
                    Source = s
                    Target = s + 1UL
                    Root = root ()
                    RootSource = s
                }
    }

/// The entries of one run: `known` first, then n new keys, some twice, some empty.
let entries (seed: int) (n: int) (known: PubKey) =
    let rng = Random seed
    let fresh = Array.init n (fun _ -> keyOf rng)

    [
        yield known, marksOf rng
        for i in 0 .. n - 1 do
            yield fresh[i], (if i % 20 = 0 then KeyMarks.Empty else marksOf rng)

            if i % 10 = 5 then
                yield fresh[rng.Next(0, i + 1)], marksOf rng
    ]

let private once (n: int) (seed: int) =
    let db =
        match SlashingDb.Open(new MemFile(), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let known = PubKey.Of(Array.create 48 1uy)
    db.RegisterKeys [ known, KeyOrigin.Imported ] |> ignore
    let es = entries seed n known

    let x =
        {
            GenesisValidatorsRoot = gvr
            Entries = es.Length
            Marks = es
            Slashable = []
        }

    GC.Collect()
    GC.WaitForPendingFinalizers()
    let mutable running = true
    let mutable worstWait = 0.0

    let probe =
        Thread(fun () ->
            let mutable target = 1UL

            while Volatile.Read &running do
                let sw = Stopwatch.StartNew()

                db
                    .CheckAndRecord(
                        [| AttestationRequest(known, 0UL, 1_000_000UL + target, Root.Zero) |],
                        CancellationToken.None
                    )
                    .Wait()

                worstWait <- max worstWait sw.Elapsed.TotalMilliseconds
                target <- target + 1UL
                Thread.Sleep 1)

    probe.Start()
    Thread.Sleep 20
    let before = GC.GetAllocatedBytesForCurrentThread()
    let sw = Stopwatch.StartNew()
    let r = db.ImportMarks x
    let ms = sw.Elapsed.TotalMilliseconds
    let allocated = GC.GetAllocatedBytesForCurrentThread() - before
    Volatile.Write(&running, false)
    probe.Join()

    match r with
    | Ok _ -> ()
    | Error e -> failwith e

    ms, allocated, worstWait, db.Keys.Length

let run (args: string list) =
    let sizes, rounds =
        match args with
        | s :: r :: _ -> s.Split(',') |> Array.map int, int r
        | [ s ] -> s.Split(',') |> Array.map int, 3
        | [] -> [| 1_000; 10_000; 100_000 |], 3
    // Warm up the JIT.
    once 200 1 |> ignore

    for n in sizes do
        let results = [ for r in 1..rounds -> once n (100 + r) ]
        let med (f: float * int64 * float * int -> float) = results |> List.map f |> List.sort |> List.item (rounds / 2)
        let _, _, _, keys = results.Head

        printfn
            "n=%d keys=%d  merge (= key lock held) %.1f ms  allocated %.1f MB  worst CheckAndRecord wait on a key in the import %.1f ms  (median of %d)"
            n
            keys
            (med (fun (ms, _, _, _) -> ms))
            (med (fun (_, a, _, _) -> float a / 1e6))
            (med (fun (_, _, w, _) -> w))
            rounds

    0
