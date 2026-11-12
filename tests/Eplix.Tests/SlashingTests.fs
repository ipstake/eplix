/// Slashing protection: rules, the EIP-3076 interchange suite, group commit, and a model-based
/// test that crashes at each write step.
module Eplix.Tests.SlashingTests

open System
open System.IO
open System.Text.Json
open System.Threading
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Slashing
open Eplix.Tests.TestUtil

// ---- A mark file that models what survives a crash ----

exception Crash

[<RequireQualifiedAccess>]
type CrashPoint =
    | BeforeAppend
    /// The append reached the OS; the crash comes before fsync.
    | BeforeSync
    | BeforeReplace

/// Durable bytes plus bytes appended since the last sync. A crash keeps the durable bytes and
/// any prefix of the rest.
type ModelFile(initial: byte[]) =
    let durable = ResizeArray<byte>(initial)
    let pending = ResizeArray<byte>()
    let mutable ops = 0
    member val CrashAt = -1 with get, set
    member val CrashKind = CrashPoint.BeforeAppend with get, set
    member val Syncs = 0 with get, set
    member _.Ops = ops
    member _.Durable = durable.ToArray()
    member _.Pending = pending.ToArray()

    /// The bytes on disk after a crash that kept `keep` bytes of the unsynced tail.
    member _.AfterCrash(keep: int) =
        Array.append (durable.ToArray()) (pending.GetRange(0, min keep pending.Count).ToArray())

    member private this.Step(kind: CrashPoint) =
        ops <- ops + 1

        if ops = this.CrashAt && this.CrashKind = kind then
            raise Crash

    interface IMarkFile with
        member _.ReadAll() = Array.append (durable.ToArray()) (pending.ToArray())

        member this.Append(bytes) =
            this.Step CrashPoint.BeforeAppend
            pending.AddRange bytes

        member this.Sync() =
            this.Step CrashPoint.BeforeSync
            this.Syncs <- this.Syncs + 1
            durable.AddRange pending
            pending.Clear()

        member _.Truncate(length) =
            let all = Array.append (durable.ToArray()) (pending.ToArray())
            durable.Clear()
            durable.AddRange(all[0 .. int length - 1])
            pending.Clear()

        member this.Replace(bytes) =
            this.Step CrashPoint.BeforeReplace
            durable.Clear()
            durable.AddRange bytes
            pending.Clear()

        member _.Dispose() = ()

/// A ModelFile whose next append, once armed, sets Entered and waits for Release, then throws
/// Crash when Fail is set, or appends.
type GatedFile(inner: ModelFile) =
    member val Armed = false with get, set
    member val Fail = false with get, set
    member val Entered = new ManualResetEventSlim(false)
    member val Release = new ManualResetEventSlim(false)

    interface IMarkFile with
        member _.ReadAll() = (inner :> IMarkFile).ReadAll()

        member this.Append(bytes) =
            if this.Armed then
                this.Armed <- false
                this.Entered.Set()
                this.Release.Wait(TimeSpan.FromSeconds 30.0) |> ignore

                if this.Fail then
                    raise Crash

            (inner :> IMarkFile).Append bytes

        member _.Sync() = (inner :> IMarkFile).Sync()
        member _.Truncate(length) = (inner :> IMarkFile).Truncate length
        member _.Replace(bytes) = (inner :> IMarkFile).Replace bytes
        member _.Dispose() = ()

let private gvr = root 77
let private key n = PubKey.Of(Array.init 48 (fun i -> if i = 0 then byte (n + 1) else 0xC0uy))

let private openDb (file: IMarkFile) =
    match SlashingDb.Open(file, gvr) with
    | Ok db -> db
    | Error e -> failwith e

let private check (db: SlashingDb) reqs = db.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result

// ---- EIP-3076 interchange tests ----

/// The 38 files of tests/generated in slashing-protection-interchange-tests v5.3.0, put there by
/// scripts/fetch-test-vectors.sh. EPLIX_EIP3076_DIR points elsewhere.
let private interchangeDir =
    match Environment.GetEnvironmentVariable "EPLIX_EIP3076_DIR" with
    | null
    | "" -> Path.Combine(vectors, ".download", "eip3076")
    | d -> d

let private interchangeFileCount = 38

/// The VC's DB keeps the signing root at each mark, so it sits between the suite's two strategies:
/// it must allow what "minimal" allows and refuse what "complete" refuses. Where they differ
/// (an exact re-sign of an imported message with its root) either answer passes.
let private expectOutcome (allowed: bool) (e: JsonElement) (what: string) =
    let minimal = e.GetProperty("should_succeed").GetBoolean()

    let complete =
        match e.TryGetProperty "should_succeed_complete" with
        | true, v -> v.GetBoolean()
        | _ -> minimal

    if minimal then
        Expect.isTrue allowed $"{what}: minimal strategy allows it"
    elif not complete then
        Expect.isFalse allowed $"{what}: refused by both strategies"

/// Lighthouse's minified run: the interchange goes through a fresh DB first, and the DB's own
/// export (one block and one attestation mark per key) is what the case DB imports.
let private minifyThrough (gvr: Root) (x: Interchange) : Result<Interchange, string> =
    match SlashingDb.Open(new ModelFile([||]), gvr) with
    | Error e -> Error e
    | Ok scratch ->
        scratch.Import x
        |> Result.bind (fun _ -> Interchange.parse (Interchange.write (scratch.Export ValueNone)))

let private interchangeCase (minified: bool) (file: string) =
    test (Path.GetFileNameWithoutExtension file) {
        use doc = JsonDocument.Parse(File.ReadAllText file)
        let r = doc.RootElement
        let caseGvr = (Root.TryParse(r.GetProperty("genesis_validators_root").GetString())).Value

        let db =
            match SlashingDb.Open(new ModelFile([||]), caseGvr) with
            | Ok db -> db
            | Error e -> failwith e

        let mutable stop = false

        for step in r.GetProperty("steps").EnumerateArray() do
            if not stop then
                let bytes = Text.Encoding.UTF8.GetBytes(step.GetProperty("interchange").GetRawText())
                let shouldSucceed = step.GetProperty("should_succeed").GetBoolean()
                let slashableData = step.GetProperty("contains_slashable_data").GetBoolean()
                let parsed = Interchange.parse bytes
                let parsed = if minified then parsed |> Result.bind (minifyThrough caseGvr) else parsed
                let imported = parsed |> Result.bind db.Import

                match imported with
                | Error _ when not shouldSucceed -> stop <- true
                | Error _ when slashableData -> stop <- true // allowed to refuse slashable data
                | Error e -> failtestf "import failed: %s" e
                | Ok _ when not shouldSucceed -> failtest "import should have failed"
                | Ok _ ->
                    let pk (e: JsonElement) = (PubKey.TryParse(e.GetProperty("pubkey").GetString())).Value

                    let rootOf (e: JsonElement) =
                        match e.TryGetProperty "signing_root" with
                        | true, v -> (Root.TryParse(v.GetString())).Value
                        | _ -> Root.Zero

                    for b in step.GetProperty("blocks").EnumerateArray() do
                        let v = check db [ BlockRequest(pk b, Json.u64Field b "slot", rootOf b) ]
                        let allowed = v[0] = Verdict.Allowed || v[0] = Verdict.Repeat
                        // Keys first seen in a signing request have no record; the suite assumes they start empty.
                        let allowed =
                            if v[0] = Verdict.NoRecord then
                                db.RegisterKeys [ pk b, KeyOrigin.StartedEmpty ] |> ignore
                                let v2 = check db [ BlockRequest(pk b, Json.u64Field b "slot", rootOf b) ]
                                v2[0] = Verdict.Allowed || v2[0] = Verdict.Repeat
                            else
                                allowed

                        expectOutcome allowed b $"""block at slot {Json.u64Field b "slot"}"""

                    for a in step.GetProperty("attestations").EnumerateArray() do
                        let req () =
                            AttestationRequest(
                                pk a,
                                Json.u64Field a "source_epoch",
                                Json.u64Field a "target_epoch",
                                rootOf a
                            )

                        let v = check db [ req () ]

                        let allowed =
                            if v[0] = Verdict.NoRecord then
                                db.RegisterKeys [ pk a, KeyOrigin.StartedEmpty ] |> ignore
                                let v2 = check db [ req () ]
                                v2[0] = Verdict.Allowed || v2[0] = Verdict.Repeat
                            else
                                v[0] = Verdict.Allowed || v[0] = Verdict.Repeat

                        expectOutcome
                            allowed
                            a
                            $"""attestation {Json.u64Field a "source_epoch"}->{Json.u64Field a "target_epoch"}"""
    }

/// The suite always runs: missing or incomplete vectors fail the run instead of skipping it.
let private interchangeSuite (name: string) (minified: bool) =
    let files =
        if Directory.Exists interchangeDir then Directory.GetFiles(interchangeDir, "*.json") |> Array.sort else [||]

    if files.Length = interchangeFileCount then
        testList name [ for f in files -> interchangeCase minified f ]
    else
        test name {
            failtestf
                "%s holds %d of the %d EIP-3076 v5.3.0 files; run scripts/fetch-test-vectors.sh (or set EPLIX_EIP3076_DIR)"
                interchangeDir
                files.Length
                interchangeFileCount
        }

// ---- The model: a stream of operations and a full-history oracle ----

type Op =
    | Att of key: int * source: int * target: int * rootTag: int
    | Blk of key: int * slot: int * rootTag: int
    | Import of key: int * slot: int * source: int * target: int
    | Restart
    | Compact

type Sent =
    | SentBlock of key: int * slot: uint64 * root: Root voption
    | SentAtt of key: int * source: uint64 * target: uint64 * root: Root voption

let private tagRoot tag = root (1000 + tag)

/// Is a request slashable against everything sent so far (EIP-3076 conditions, full history)?
let slashable (history: Sent list) (req: SlashingRequest) (k: int) =
    // Signing the exact message again adds no new evidence.
    let repeat =
        match req with
        | BlockRequest(_, s, root) -> List.contains (SentBlock(k, s, ValueSome root)) history
        | AttestationRequest(_, s, t, root) -> List.contains (SentAtt(k, s, t, ValueSome root)) history

    not repeat
    && history
       |> List.exists (fun h ->
           match h, req with
           | SentBlock(hk, slot, r), BlockRequest(_, s, root) -> hk = k && slot = s && r <> ValueSome root
           | SentAtt(hk, hs, ht, r), AttestationRequest(_, s, t, root) ->
               hk = k
               && ((ht = t && r <> ValueSome root) // double vote
                   || (s < hs && ht < t) // surrounds
                   || (hs < s && t < ht)) // surrounded
           | _ -> false)

/// Runs a stream. The op at index `crashOp` crashes at its file operation `crashAt` (1-based within the op),
/// keeping `keep` bytes of the unsynced tail. Checks the invariants after every op.
let runStream (ops: Op list) (crashOp: int) (crashKind: CrashPoint) (crashAt: int) (keep: int) =
    let mutable file = new ModelFile([||])
    let mutable db = openDb file
    db.RegisterKeys [ for k in 0..2 -> key k, KeyOrigin.StartedEmpty ] |> ignore
    let mutable history: Sent list = []

    let reopen (bytes: byte[]) =
        file <- new ModelFile(bytes)
        db <- openDb file

    let marksOf () = [ for k in 0..2 -> db.Marks(key k) ]

    ops
    |> List.iteri (fun i op ->
        let before = marksOf ()

        if i = crashOp then
            file.CrashAt <- file.Ops + crashAt
            file.CrashKind <- crashKind

        try
            match op with
            | Att(k, s, t, tag) ->
                let req = AttestationRequest(key k, uint64 s, uint64 t, tagRoot tag)
                let v = check db [ req ]

                match v[0] with
                | Verdict.Allowed
                | Verdict.Repeat ->
                    if slashable history req k then
                        failwithf "allowed a slashable attestation %d->%d (op %d)" s t i

                    history <- SentAtt(k, uint64 s, uint64 t, ValueSome(tagRoot tag)) :: history
                | Verdict.WriteFailed _ -> raise Crash
                | _ -> ()
            | Blk(k, slot, tag) ->
                let req = BlockRequest(key k, uint64 slot, tagRoot tag)
                let v = check db [ req ]

                match v[0] with
                | Verdict.Allowed
                | Verdict.Repeat ->
                    if slashable history req k then
                        failwithf "allowed a slashable block at %d (op %d)" slot i

                    history <- SentBlock(k, uint64 slot, ValueSome(tagRoot tag)) :: history
                | Verdict.WriteFailed _ -> raise Crash
                | _ -> ()
            | Import(k, slot, s, t) ->
                let x =
                    {
                        GenesisValidatorsRoot = gvr
                        Data =
                            [
                                {
                                    PubKey = key k
                                    SignedBlocks =
                                        [
                                            {
                                                Slot = uint64 slot
                                                SigningRoot = ValueNone
                                            }
                                        ]
                                    SignedAttestations =
                                        [
                                            {
                                                SourceEpoch = uint64 s
                                                TargetEpoch = uint64 t
                                                SigningRoot = ValueNone
                                            }
                                        ]
                                }
                            ]
                    }
                // Another client signed these. A failed import is reported to the operator, who
                // must not start the key, so only a completed import joins the history.
                match db.Import x with
                | Ok _ ->
                    history <-
                        SentBlock(k, uint64 slot, ValueNone) :: SentAtt(k, uint64 s, uint64 t, ValueNone) :: history
                | Error _ -> raise Crash
            | Restart -> reopen ((file :> IMarkFile).ReadAll())
            | Compact ->
                match db.Compact() with
                | Ok() -> ()
                | Error _ -> raise Crash
        with Crash ->
            // The process dies here. What is on disk: the durable bytes and a prefix of the rest.
            reopen (file.AfterCrash keep)
        // An op without file writes leaves the crash unused; it must not fire in a later op.
        file.CrashAt <- -1
        // Marks never go down, across crashes and imports.
        List.zip before (marksOf ())
        |> List.iteri (fun k (b, a) ->
            match b, a with
            | ValueSome b, ValueSome a when not (Marks.atLeast b a) ->
                failwithf "marks of key %d went down at op %d" k i
            | ValueSome _, ValueNone -> failwithf "key %d lost its record at op %d" k i
            | _ -> ()))

let private sampleStream =
    [
        Att(0, 0, 1, 0)
        Att(1, 0, 1, 0)
        Blk(0, 5, 0)
        Att(0, 1, 2, 0)
        Att(0, 1, 2, 1) // double vote: refused
        Att(0, 0, 3, 0) // surrounds: refused
        Import(1, 9, 2, 4)
        Att(1, 1, 3, 0) // below imported marks: refused
        Att(1, 4, 5, 0)
        Blk(0, 5, 0) // repeat
        Blk(0, 5, 1) // double proposal: refused
        Restart
        Att(0, 2, 3, 0)
        Compact
        Att(0, 3, 4, 0)
        Blk(1, 10, 2)
        Att(2, 0, 0, 0)
        Att(2, 0, 1, 2)
        Restart
        Att(2, 1, 2, 2)
    ]

/// Every op, every write step inside it, every interesting amount of the unsynced tail.
let private crashEverywhere () =
    let keeps = [ 0; 1; 40; 79; 80; 81; 159; 160; 10_000 ]

    [
        for i in 0 .. sampleStream.Length - 1 do
            for kind in [ CrashPoint.BeforeAppend; CrashPoint.BeforeSync; CrashPoint.BeforeReplace ] do
                for at in 1..2 do
                    for keep in keeps do
                        i, kind, at, keep
    ]

let private genOp =
    Gen.oneof
        [
            Gen.map4
                (fun k s d tag -> Att(k, s, s + d, tag))
                (Gen.choose (0, 2))
                (Gen.choose (0, 6))
                (Gen.choose (0, 3))
                (Gen.choose (0, 2))
            Gen.map3 (fun k s tag -> Blk(k, s, tag)) (Gen.choose (0, 2)) (Gen.choose (0, 12)) (Gen.choose (0, 2))
            Gen.map4
                (fun k slot s d -> Import(k, slot, s, s + d))
                (Gen.choose (0, 2))
                (Gen.choose (0, 12))
                (Gen.choose (0, 6))
                (Gen.choose (0, 2))
            Gen.constant Restart
            Gen.constant Compact
        ]

// ---- Racing callers ----

[<RequireQualifiedAccess>]
type RaceKind =
    /// Attestations for one target with different roots: double votes of each other.
    | DoubleVote
    /// Blocks for one slot with different roots.
    | DoubleBlock
    /// Nested votes (k, 2n - k): each pair surrounds the other.
    | Surround

/// n callers on n threads, one request each, against one key in a DB on a real file. Exactly one
/// wins, the marks are the winner's, and they stay the winner's after a reopen.
let raceOneKey (kind: RaceKind) (n: int) =
    let dir = tempDir ()
    let path = Path.Combine(dir, "slashing.db")

    let reqs =
        [|
            for i in 0 .. n - 1 ->
                match kind with
                | RaceKind.DoubleVote -> AttestationRequest(key 0, 3UL, 4UL, root (100 + i))
                | RaceKind.DoubleBlock -> BlockRequest(key 0, 9UL, root (100 + i))
                | RaceKind.Surround -> AttestationRequest(key 0, uint64 i, uint64 (2 * n - i), root (100 + i))
        |]

    let winnerMarks =
        use db = openDb (new FileMarkFile(path))
        db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
        use start = new ManualResetEventSlim(false)

        let calls =
            reqs
            |> Array.map (fun r ->
                Tasks.Task.Run(fun () ->
                    start.Wait()
                    (db.CheckAndRecord([| r |], CancellationToken.None)).Result[0]))

        start.Set()
        let verdicts = (Tasks.Task.WhenAll calls).Result
        let winners = Array.zip reqs verdicts |> Array.filter (fun (_, v) -> v = Verdict.Allowed)
        Expect.equal winners.Length 1 $"one winner among {n} callers: %A{verdicts}"

        Expect.equal
            (verdicts
             |> Array.filter (fun v ->
                 match v with
                 | Verdict.Refused _ -> true
                 | _ -> false))
                .Length
            (n - 1)
            "the rest refused"

        let marks = (db.Marks(key 0)).Value

        match fst winners[0] with
        | BlockRequest(_, slot, r) ->
            Expect.equal marks.Block (ValueSome { Slot = slot; Root = ValueSome r }) "block mark is the winner's"
        | AttestationRequest(_, s, t, r) ->
            let a = marks.Attestation.Value
            Expect.equal (a.Source, a.Target, a.Root) (s, t, ValueSome r) "vote mark is the winner's"

        marks

    use db = openDb (new FileMarkFile(path))
    Expect.equal (db.Marks(key 0)) (ValueSome winnerMarks) "the same marks after a reopen"
    // Every loser stays refused after the reopen; the winner is a repeat.
    let again = check db (List.ofArray reqs)
    Expect.equal (again |> Array.filter (fun v -> v = Verdict.Repeat)).Length 1 "the winner repeats"

    Expect.isTrue
        (again
         |> Array.forall (fun v ->
             v = Verdict.Repeat
             || (match v with
                 | Verdict.Refused _ -> true
                 | _ -> false)))
        "the rest still refused"

[<Tests>]
let tests =
    testList
        "slashing"
        [
            test "rules" {
                let m = KeyMarks.Empty |> fun m -> Marks.mergeAttestation m (Marks.vote 2UL 5UL (root 1))
                Expect.equal (Marks.checkAttestation m 2UL 6UL (root 2)) Check.Allow "higher target"
                Expect.equal (Marks.checkAttestation m 2UL 5UL (root 1)) Check.Repeat "exact repeat"

                Expect.isTrue
                    (Marks.checkAttestation m 2UL 5UL (root 2)
                     |> function
                         | Check.Refuse _ -> true
                         | _ -> false)
                    "double"

                Expect.isTrue
                    (Marks.checkAttestation m 1UL 6UL (root 2)
                     |> function
                         | Check.Refuse _ -> true
                         | _ -> false)
                    "surround"

                Expect.isTrue
                    (Marks.checkAttestation m 3UL 4UL (root 2)
                     |> function
                         | Check.Refuse _ -> true
                         | _ -> false)
                    "surrounded"

                Expect.isTrue
                    (Marks.checkAttestation KeyMarks.Empty 3UL 2UL (root 2)
                     |> function
                         | Check.Refuse _ -> true
                         | _ -> false)
                    "source after target"
            }

            test "two roots at one target leave the root unknown" {
                // This VC voted 1->2 with root A; an import says another client voted 1->2 with root B.
                // The mark keeps no root, so not even A counts as a repeat any more.
                let db = openDb (new ModelFile([||]))
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                Expect.equal (check db [ AttestationRequest(key 0, 1UL, 2UL, root 1) ]) [| Verdict.Allowed |] "A"

                let x =
                    {
                        GenesisValidatorsRoot = gvr
                        Data =
                            [
                                {
                                    PubKey = key 0
                                    SignedBlocks = []
                                    SignedAttestations =
                                        [
                                            {
                                                SourceEpoch = 1UL
                                                TargetEpoch = 2UL
                                                SigningRoot = ValueSome(root 2)
                                            }
                                        ]
                                }
                            ]
                    }

                Expect.isOk (db.Import x) "import B"
                Expect.equal (db.Marks(key 0)).Value.Attestation.Value.Root ValueNone "root unknown"

                Expect.isTrue
                    (match (check db [ AttestationRequest(key 0, 1UL, 2UL, root 1) ])[0] with
                     | Verdict.Refused _ -> true
                     | _ -> false)
                    "A again refused"
            }

            test "the key list and the export read while keys are added never fail or tear" {
                let db = openDb (new ModelFile([||]))
                let n = 3000

                let adding =
                    Threading.Tasks.Task.Run(fun () ->
                        for k in 0 .. n - 1 do
                            let pk = PubKey.Of(Array.init 48 (fun i -> if i < 2 then byte (k >>> (8 * i)) else 0xD0uy))
                            db.RegisterKeys [ pk, KeyOrigin.StartedEmpty ] |> ignore)

                let mutable last = 0

                while not adding.IsCompleted do
                    let count = db.Keys.Length
                    Expect.isGreaterThanOrEqual count last "the count never goes down"
                    last <- count
                    db.Export ValueNone |> ignore

                adding.Wait()
                Expect.equal db.Keys.Length n "every key"
            }

            test "one append and one fsync per burst" {
                let file = new ModelFile([||])
                let db = openDb file
                db.RegisterKeys [ for k in 0..99 -> key k, KeyOrigin.StartedEmpty ] |> ignore
                let syncsBefore = file.Syncs
                let burst = [ for k in 0..99 -> AttestationRequest(key k, 0UL, 1UL, root k) ]
                let v = check db burst
                Expect.allEqual v Verdict.Allowed "all allowed"
                Expect.equal (file.Syncs - syncsBefore) 1 "one fsync for 100 votes"
                let again = check db burst
                Expect.allEqual again Verdict.Repeat "repeats"
                Expect.equal (file.Syncs - syncsBefore) 1 "repeats write nothing"
            }

            test "two requests for one key in a burst are checked in order" {
                let db = openDb (new ModelFile([||]))
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore

                let v =
                    check
                        db
                        [
                            AttestationRequest(key 0, 0UL, 1UL, root 1)
                            AttestationRequest(key 0, 0UL, 1UL, root 2)
                        ]

                Expect.equal v[0] Verdict.Allowed "first"

                Expect.isTrue
                    (match v[1] with
                     | Verdict.Refused _ -> true
                     | _ -> false)
                    "second is a double vote"
            }

            test "a failed write refuses both copies of a request listed twice in a burst" {
                // A beacon node that lists a key twice in its duties gives a burst with the same
                // request twice: the second is a Repeat of the first's mark, which never got durable.
                let writeFailed v =
                    match v with
                    | Verdict.WriteFailed _ -> true
                    | _ -> false

                for kind, step in [ CrashPoint.BeforeAppend, 1; CrashPoint.BeforeSync, 2 ] do
                    for req in
                        [
                            AttestationRequest(key 0, 0UL, 1UL, root 1)
                            BlockRequest(key 0, 4UL, root 2)
                        ] do
                        let file = new ModelFile([||])
                        let db = openDb file
                        db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                        file.CrashAt <- file.Ops + step
                        file.CrashKind <- kind
                        let v = check db [ req; req ]
                        Expect.isTrue (v |> Array.forall writeFailed) $"{kind}: both refused: %A{v}"
                        Expect.equal (db.Marks(key 0)) (ValueSome KeyMarks.Empty) "marks unchanged"
                        Expect.isTrue (check db [ req ] |> Array.forall writeFailed) "the DB refuses until restart"
            }

            test "slot marks: a failed write refuses both copies of a request listed twice in a burst" {
                let writeFailed v =
                    match v with
                    | Verdict.WriteFailed _ -> true
                    | _ -> false

                for kind, step in [ CrashPoint.BeforeAppend, 1; CrashPoint.BeforeSync, 2 ] do
                    let file = new ModelFile([||])

                    let marks =
                        match SlotMarks.Open(file, gvr) with
                        | Ok m -> m
                        | Error e -> failwith e

                    let req =
                        {
                            Key = key 0
                            Kind = SlotMarkKind.PayloadAttestation
                            Slot = 9UL
                            SigningRoot = root 3
                        }
                    // Give the key its record first, so the failing burst holds only the two marks.
                    marks.CheckAndRecord([| { req with Slot = 8UL } |], CancellationToken.None).Result |> ignore
                    file.CrashAt <- file.Ops + step
                    file.CrashKind <- kind
                    let v = marks.CheckAndRecord([| req; req |], CancellationToken.None).Result
                    Expect.isTrue (v |> Array.forall writeFailed) $"{kind}: both refused: %A{v}"
            }

            test "a burst waiting on the append gate gets nothing after another burst's write failed" {
                let gated = new GatedFile(new ModelFile([||]))
                let db = openDb gated
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty; key 1, KeyOrigin.StartedEmpty ] |> ignore
                gated.Armed <- true
                gated.Fail <- true
                let first = Tasks.Task.Run(fun () -> check db [ AttestationRequest(key 0, 0UL, 1UL, root 1) ])
                Expect.isTrue (gated.Entered.Wait(TimeSpan.FromSeconds 10.0)) "the first burst is in its append"
                // Another key, so no key lock is shared: the second burst passes the DB's first
                // check and waits for the append gate. Its key lock is free, so CheckAndRecord runs
                // on this thread up to the gate, and the first place the thread blocks is the gate.
                let second = ref [||]

                let t =
                    Thread(
                        ThreadStart(fun () -> second.Value <- check db [ AttestationRequest(key 1, 0UL, 1UL, root 2) ])
                    )

                t.Start()
                let sw = Diagnostics.Stopwatch.StartNew()
                let waiting () = (t.ThreadState &&& ThreadState.WaitSleepJoin) <> ThreadState.Running

                while not (waiting ()) && t.IsAlive && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                    Thread.Yield() |> ignore

                Expect.isTrue (waiting ()) "the second burst waits on the append gate"
                gated.Release.Set()
                Expect.isTrue (t.Join(TimeSpan.FromSeconds 10.0)) "the second burst ends"

                let writeFailed (v: Verdict[]) =
                    match v[0] with
                    | Verdict.WriteFailed _ -> true
                    | _ -> false

                Expect.isTrue (writeFailed first.Result) $"first: %A{first.Result}"
                Expect.isTrue (writeFailed second.Value) $"second: %A{second.Value}"
                Expect.equal (db.Marks(key 1)) (ValueSome KeyMarks.Empty) "no mark for the second burst"
            }

            test "slot marks: a burst waiting on the gate gets nothing after another burst's write failed" {
                let gated = new GatedFile(new ModelFile([||]))

                let marks =
                    match SlotMarks.Open(gated, gvr) with
                    | Ok m -> m
                    | Error e -> failwith e

                let req n slot =
                    {
                        Key = key n
                        Kind = SlotMarkKind.PayloadAttestation
                        Slot = slot
                        SigningRoot = root (n + 1)
                    }

                gated.Armed <- true
                gated.Fail <- true

                let first =
                    Tasks.Task.Run(fun () -> marks.CheckAndRecord([| req 0 9UL |], CancellationToken.None).Result)

                Expect.isTrue (gated.Entered.Wait(TimeSpan.FromSeconds 10.0)) "the first burst is in its append"
                // The second burst passes the first check of `failed` (nothing failed yet) and waits
                // on the gate. CheckAndRecord runs on this thread up to its first await, the gate's
                // WaitAsync, so the call returns once the burst waits there. No key locks here,
                // unlike the slashing DB, so no thread is needed.
                let second = marks.CheckAndRecord([| req 1 9UL |], CancellationToken.None)
                Expect.isFalse second.IsCompleted "the second burst waits on the gate"
                gated.Release.Set()
                Expect.isTrue (second.Wait(TimeSpan.FromSeconds 10.0)) "the second burst ends"

                let writeFailed (v: Verdict[]) =
                    match v[0] with
                    | Verdict.WriteFailed _ -> true
                    | _ -> false

                Expect.isTrue (writeFailed first.Result) $"first: %A{first.Result}"
                Expect.isTrue (writeFailed second.Result) $"second: %A{second.Result}"
                Expect.equal (marks.Marks(key 1)) ValueNone "no mark for the second burst"
            }

            test "a key without a record never signs" {
                let db = openDb (new ModelFile([||]))
                Expect.equal (check db [ BlockRequest(key 0, 1UL, root 1) ]) [| Verdict.NoRecord |] "no record"
            }

            test "a torn tail is cut; a bad record in the middle is corruption" {
                let file = new ModelFile([||])
                let db = openDb file
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                check db [ AttestationRequest(key 0, 0UL, 1UL, root 1) ] |> ignore
                check db [ AttestationRequest(key 0, 1UL, 2UL, root 2) ] |> ignore
                let bytes = (file :> IMarkFile).ReadAll()
                // Half of a third record at the end: cut, marks from the two full records stay.
                let torn = Array.append bytes (Array.create 40 0x11uy)
                let db2 = openDb (new ModelFile(torn))
                Expect.equal db2.OpenInfo.TruncatedBytes 40L "cut 40 bytes"
                Expect.equal (db2.Marks(key 0)).Value.Attestation.Value.Target 2UL "marks kept"
                // Flip a byte in record 2 of 4: the valid record after it makes this corruption.
                let bad = Array.copy bytes
                bad[2 * Record.size + 10] <- bad[2 * Record.size + 10] ^^^ 0xFFuy
                Expect.isError (SlashingDb.Open(new ModelFile(bad), gvr)) "corrupt"
                Expect.isError (SlashingDb.Open(new ModelFile(bytes), root 78)) "other chain"
            }

            test "export then import into a fresh DB keeps the marks" {
                let db = openDb (new ModelFile([||]))
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty; key 1, KeyOrigin.StartedEmpty ] |> ignore

                check
                    db
                    [
                        AttestationRequest(key 0, 3UL, 7UL, root 1)
                        BlockRequest(key 1, 40UL, root 2)
                    ]
                |> ignore

                let x = db.Export ValueNone
                let json = Interchange.write x

                match Interchange.parse json with
                | Error e -> failtest e
                | Ok parsed ->
                    let db2 = openDb (new ModelFile([||]))
                    Expect.isOk (db2.Import parsed) "import"
                    Expect.equal (db2.Marks(key 0)) (db.Marks(key 0)) "key 0"
                    Expect.equal (db2.Marks(key 1)) (db.Marks(key 1)) "key 1"

                    Expect.equal
                        (check db2 [ AttestationRequest(key 0, 3UL, 7UL, root 1) ])
                        [| Verdict.Repeat |]
                        "root survives"
            }

            test "real file: write, reopen, compact" {
                let dir = tempDir ()
                let path = Path.Combine(dir, "slashing.db")

                let write () =
                    use db = openDb (new FileMarkFile(path))
                    db.RegisterKeys [ key 0, KeyOrigin.Imported ] |> ignore

                    for t in 1..20 do
                        check db [ AttestationRequest(key 0, uint64 (t - 1), uint64 t, root t) ] |> ignore

                write ()
                Expect.equal (FileInfo(path).Length) (int64 (22 * Record.size)) "header, key, 20 votes"

                let compact () =
                    use db = openDb (new FileMarkFile(path))
                    Expect.equal (db.Marks(key 0)).Value.Attestation.Value.Target 20UL "replayed"
                    Expect.isOk (db.Compact()) "compact"

                compact ()
                Expect.equal (FileInfo(path).Length) (int64 (3 * Record.size)) "header, key, one mark"
                use db = openDb (new FileMarkFile(path))
                Expect.equal (db.Origin(key 0)) (ValueSome KeyOrigin.Imported) "origin kept"

                Expect.equal
                    (check db [ AttestationRequest(key 0, 19UL, 20UL, root 20) ])
                    [| Verdict.Repeat |]
                    "repeat after compaction"
            }

            test "the stream runs clean without crashes" { runStream sampleStream -1 CrashPoint.BeforeAppend 0 0 }

            test "crash at each write step of each op" {
                let cases = crashEverywhere ()

                for i, kind, at, keep in cases do
                    try
                        runStream sampleStream i kind at keep
                    with e ->
                        failtestf "op %d, %A at step %d, keep %d: %s" i kind at keep e.Message
            }

            test "fuzz round 3: a vote on disk but never signed, then an import it surrounds" {
                // Seed 14520790331330252722. Op 7 writes 3->6 and crashes before fsync; the bytes
                // survive but the VC never signed. The import of 5->5 at op 15 lies inside 3->6, so
                // signing 3->6 at op 18 would be a surround, not a repeat.
                let ops =
                    [
                        Att(0, 5, 5, 0)
                        Import(1, 2, 0, 0)
                        Import(2, 3, 0, 1)
                        Blk(0, 3, 0)
                        Blk(1, 10, 2)
                        Blk(0, 8, 2)
                        Restart
                        Att(1, 3, 6, 0)
                        Compact
                        Att(1, 3, 6, 2)
                        Restart
                        Restart
                        Blk(1, 4, 0)
                        Import(2, 5, 5, 7)
                        Import(2, 7, 5, 5)
                        Import(1, 9, 5, 5)
                        Att(1, 6, 6, 0)
                        Blk(1, 9, 2)
                        Att(1, 3, 6, 0)
                        Import(1, 4, 4, 6)
                        Import(1, 4, 5, 6)
                        Import(2, 4, 4, 4)
                        Import(0, 12, 5, 6)
                        Att(2, 5, 8, 1)
                        Compact
                    ]

                runStream ops 7 CrashPoint.BeforeSync 2 345
            }

            testPropFuzz "random streams with a random crash" 300
            <| Prop.forAll
                (Arb.fromGen (
                    Gen.zip3
                        (Gen.listOfLength 25 genOp)
                        (Gen.choose (0, 24))
                        (Gen.zip3
                            (Gen.elements [ CrashPoint.BeforeAppend; CrashPoint.BeforeSync; CrashPoint.BeforeReplace ])
                            (Gen.choose (1, 2))
                            (Gen.choose (0, 400)))
                ))
                (fun (ops, crashOp, (kind, at, keep)) -> runStream ops crashOp kind at keep)

            testPropN "parallel callers: one key, one winner" 30
            <| Prop.forAll
                (Arb.fromGen (
                    Gen.zip
                        (Gen.elements [ RaceKind.DoubleVote; RaceKind.DoubleBlock; RaceKind.Surround ])
                        (Gen.choose (10, 50))
                ))
                (fun (kind, n) -> raceOneKey kind n)

            test "a vote with source in Fulu and target in Gloas" {
                // Gloas at epoch 2: source epoch 1 (Fulu), target epoch 2 (Gloas). The DB sees epochs only.
                let file = new ModelFile([||])
                let db = openDb file
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore

                Expect.equal
                    (check db [ AttestationRequest(key 0, 0UL, 1UL, root 1) ])
                    [| Verdict.Allowed |]
                    "the last Fulu vote"

                let before = db.Marks(key 0)

                Expect.equal
                    (check db [ AttestationRequest(key 0, 1UL, 2UL, root 2) ])
                    [| Verdict.Allowed |]
                    "allowed once"

                Expect.equal
                    (check db [ AttestationRequest(key 0, 1UL, 2UL, root 2) ])
                    [| Verdict.Repeat |]
                    "the exact repeat"

                Expect.isTrue
                    (match (check db [ AttestationRequest(key 0, 1UL, 2UL, root 3) ])[0] with
                     | Verdict.Refused _ -> true
                     | _ -> false)
                    "a double vote refused"

                Expect.isTrue
                    (match (check db [ AttestationRequest(key 0, 0UL, 3UL, root 4) ])[0] with
                     | Verdict.Refused _ -> true
                     | _ -> false)
                    "a surround over the fork refused"

                let m = (db.Marks(key 0)).Value.Attestation.Value
                Expect.equal (m.Source, m.Target, m.Root) (1UL, 2UL, ValueSome(root 2)) "the marks are the Gloas vote's"
                Expect.isTrue (Marks.atLeast before.Value (db.Marks(key 0)).Value) "marks only went up"
                let reopened = openDb (new ModelFile((file :> IMarkFile).ReadAll()))
                Expect.equal (reopened.Marks(key 0)) (db.Marks(key 0)) "the same after a reopen"
            }

            interchangeSuite "eip3076 suite" false
            interchangeSuite "eip3076 suite minified" true
        ]
