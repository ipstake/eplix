/// SlashingDb's merge (ImportMarks, Import, RaiseFloor) against the quadratic algorithm it
/// replaced: the same records byte for byte, the same key order, marks and
/// keys without history, on random inputs; and an import of 100,000 new keys in bounded time.
module Eplix.Tests.SlashingMergeTests

open System
open System.Collections.Generic
open System.Diagnostics
open System.Threading
open Expecto
open Eplix
open Eplix.Slashing
open Eplix.Tests.SlashingTests

let private gvr = Root.Of(Array.create 32 5uy)

let private openDb (file: IMarkFile) =
    match SlashingDb.Open(file, gvr) with
    | Ok db -> db
    | Error e -> failwith e

/// The old quadratic merge, written out on plain lists: linear scans for a new key.
/// `known` is the DB before, in key id order. Returns the records it appends, the keys in id
/// order with their marks and origin after, and the keys left without history.
let private oldMerge
    (known: (PubKey * KeyOrigin * KeyMarks) list)
    (origin: KeyOrigin)
    (entries: (PubKey * KeyMarks) list)
    =
    let states = ResizeArray<PubKey * KeyOrigin * KeyMarks>(known)
    let records = ResizeArray<byte[]>()
    let idOf (key: PubKey) = states.FindIndex(fun (k, _, _) -> k = key)
    let isNew key = idOf key < 0

    let stateOf key =
        match idOf key with
        | i when i >= 0 -> i
        | _ ->
            states.Add((key, origin, KeyMarks.Empty))
            let id = states.Count - 1
            records.Add(Record.key (uint32 id) key origin)
            id

    let noHistory = ResizeArray<PubKey>()

    for key, marks in entries do
        if origin = KeyOrigin.Imported && marks = KeyMarks.Empty && isNew key then
            noHistory.Add key
        else
            let id = stateOf key
            let k, o, before = states[id]
            let mutable after = before
            marks.Block |> ValueOption.iter (fun b -> after <- Marks.mergeBlock after b)
            marks.Attestation |> ValueOption.iter (fun a -> after <- Marks.mergeAttestation after a)

            if after <> before then
                states[id] <- (k, o, after)
                marks.Block |> ValueOption.iter (fun b -> records.Add(Record.block (uint32 id) b))
                marks.Attestation |> ValueOption.iter (fun a -> records.Add(Record.attestation (uint32 id) a))

    let all = List.ofSeq states
    let stillNone = noHistory |> Seq.distinct |> Seq.filter (fun k -> isNew k) |> List.ofSeq
    Array.concat records, all, stillNone

let private keyOf (rng: Random) (pool: PubKey[]) = pool[rng.Next pool.Length]

let private rootOf (rng: Random) =
    // A small set of roots, so equal roots and unknown roots both come up.
    match rng.Next 4 with
    | 0 -> ValueNone
    | n -> ValueSome(Root.Of(Array.init 32 (fun i -> if i = 0 then byte n else 0uy)))

let private marksOf (rng: Random) : KeyMarks =
    let block () =
        ValueSome
            {
                Slot = uint64 (rng.Next(0, 8))
                Root = rootOf rng
            }

    let att () =
        let s = uint64 (rng.Next(0, 6))

        ValueSome
            {
                Source = s
                Target = s + uint64 (rng.Next(0, 3))
                Root = rootOf rng
                RootSource = s
            }

    match rng.Next 5 with
    | 0 -> KeyMarks.Empty
    | 1 ->
        {
            Block = block ()
            Attestation = ValueNone
        }
    | 2 ->
        {
            Block = ValueNone
            Attestation = att ()
        }
    | _ ->
        {
            Block = block ()
            Attestation = att ()
        }

let private pool (rng: Random) (n: int) =
    Array.init n (fun _ ->
        let b = Array.zeroCreate<byte> 48
        rng.NextBytes b
        PubKey.Of b)

let private snapshot (db: SlashingDb) = [ for k in db.Keys -> k, (db.Origin k).Value, (db.Marks k).Value ]

/// One random case: a DB with some keys and marks, then one merge through `run`; the result
/// must match oldMerge.
let private case (seed: int) (keys: int) (entries: int) (floor: bool) =
    let rng = Random seed
    let keyPool = pool rng keys
    let file = new ModelFile([||])
    let db = openDb file
    // A DB that already holds some of the keys, some with marks.
    let first = [ for _ in 1 .. rng.Next(0, keys) -> keyOf rng keyPool, marksOf rng ]

    db.ImportMarks
        {
            GenesisValidatorsRoot = gvr
            Entries = first.Length
            Marks = first
            Slashable = []
        }
    |> ignore

    let known = snapshot db
    let before = (file :> IMarkFile).ReadAll().Length

    let expectedRecords, expectedKeys, expectedNone, result =
        if floor then
            let floorKeys = [ for _ in 1..entries -> keyOf rng keyPool ]

            let floorMarks =
                { marksOf rng with
                    Block = ValueSome { Slot = 3UL; Root = ValueNone }
                }

            let r, k, n = oldMerge known KeyOrigin.Floor [ for k in List.distinct floorKeys -> k, floorMarks ]
            r, k, n, db.RaiseFloor(floorKeys, KeyOrigin.Floor, floorMarks) |> Result.map (fun () -> [])
        else
            let es = [ for _ in 1..entries -> keyOf rng keyPool, marksOf rng ]
            let r, k, n = oldMerge known KeyOrigin.Imported es

            let x =
                {
                    GenesisValidatorsRoot = gvr
                    Entries = es.Length
                    Marks = es
                    Slashable = []
                }

            r, k, n, db.ImportMarks x |> Result.map (fun r -> r.NoHistory)

    let name = $"seed {seed}, {keys} keys, {entries} entries, floor {floor}"

    match result with
    | Error e -> failtestf "%s: %s" name e
    | Ok noHistory ->
        let all = (file :> IMarkFile).ReadAll()
        Expect.equal all[before..] expectedRecords $"{name}: the same records, byte for byte"
        Expect.equal (snapshot db) expectedKeys $"{name}: the same keys in id order, origins and marks"

        if not floor then
            Expect.equal noHistory expectedNone $"{name}: the same keys without history"

        let reopened = openDb (new ModelFile(all))
        Expect.equal (snapshot reopened) expectedKeys $"{name}: the same after a reopen"

let private importNew (n: int) =
    let rng = Random n
    let keys = pool rng n

    let es =
        [
            for k in keys ->
                let s = uint64 (rng.Next(1, 100_000))

                k,
                {
                    Block =
                        ValueSome
                            {
                                Slot = uint64 (rng.Next(1, 3_000_000))
                                Root = rootOf rng
                            }
                    Attestation =
                        ValueSome
                            {
                                Source = s
                                Target = s + 1UL
                                Root = rootOf rng
                                RootSource = s
                            }
                }
        ]

    let db = openDb (new ModelFile([||]))
    let sw = Stopwatch.StartNew()

    let r =
        db.ImportMarks
            {
                GenesisValidatorsRoot = gvr
                Entries = n
                Marks = es
                Slashable = []
            }

    let elapsed = sw.Elapsed
    Expect.isOk r "imported"
    Expect.equal db.Keys.Length n "every key has a record"
    elapsed

[<Tests>]
let tests =
    testList
        "slashing merge"
        [
            test "random merges give what the old algorithm gave" {
                for seed in 1..400 do
                    let keys = 1 + seed % 40
                    case seed keys (seed % 120) (seed % 5 = 0)
            }
            test "many keys: the same as the old algorithm" {
                case 9001 6_000 8_000 false
                case 9002 3_000 3_000 true
            }
            test "100,000 new keys import in bounded time" {
                importNew 1_000 |> ignore
                let t = importNew 100_000
                printfn $"slashing merge: 100,000 new keys in {t.TotalMilliseconds:F0} ms"
                // The quadratic merge took 151 s here on a Release build; the linear one under 1 s.
                Expect.isLessThan t (TimeSpan.FromSeconds 20.0) "100,000 new keys in under 20 s"
            }
        ]
