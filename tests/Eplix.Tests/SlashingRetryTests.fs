/// A failed write to the slashing DB or the slot marks file: nothing signs until a write succeeds
/// again, the store tries again after a backoff, and signing resumes after the first good write.
module Eplix.Tests.SlashingRetryTests

open System
open System.IO
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.SlashingTests
open Eplix.Tests.SchedulerTests

/// A ModelFile whose next `FailWrites` append, sync or replace calls fail as on a full disk. A
/// failed append leaves the first `PartBytes` of its bytes in the file (half when below 0), as a
/// short write does.
type FlakyFile(inner: ModelFile) =
    member val FailWrites = 0 with get, set
    member val PartBytes = -1 with get, set
    /// Append, sync and replace calls, failed or not.
    member val Writes = 0 with get, set

    member private this.Next() =
        this.Writes <- this.Writes + 1

        if this.FailWrites > 0 then
            this.FailWrites <- this.FailWrites - 1
            true
        else
            false

    interface IMarkFile with
        member _.ReadAll() = (inner :> IMarkFile).ReadAll()

        member this.Append(bytes) =
            if this.Next() then
                let n = if this.PartBytes >= 0 then min this.PartBytes bytes.Length else bytes.Length / 2

                (inner :> IMarkFile).Append(bytes[0 .. n - 1])
                raise (IOException "No space left on device")

            (inner :> IMarkFile).Append bytes

        member this.Sync() =
            if this.Next() then
                raise (IOException "No space left on device")

            (inner :> IMarkFile).Sync()

        member _.Truncate(length) = (inner :> IMarkFile).Truncate length

        member this.Replace(bytes) =
            if this.Next() then
                raise (IOException "No space left on device")

            (inner :> IMarkFile).Replace bytes

        member _.Dispose() = ()

/// Wraps the real file's stream. A write armed with `FailWriteAfter` passes that many bytes on
/// and then throws; an armed flush throws before it flushes anything.
type FailingStream(inner: Stream) =
    inherit Stream()
    member val FailWriteAfter = -1 with get, set
    member val FailFlush = false with get, set
    override _.CanRead = inner.CanRead
    override _.CanSeek = inner.CanSeek
    override _.CanWrite = inner.CanWrite
    override _.Length = inner.Length

    override _.Position
        with get () = inner.Position
        and set v = inner.Position <- v

    override _.Read(buffer: byte[], offset: int, count: int) = inner.Read(buffer, offset, count)
    override _.Seek(offset: int64, origin: SeekOrigin) = inner.Seek(offset, origin)
    override _.SetLength(length: int64) = inner.SetLength length

    override this.Write(buffer: byte[], offset: int, count: int) =
        if this.FailWriteAfter >= 0 then
            let n = min count this.FailWriteAfter
            this.FailWriteAfter <- -1
            inner.Write(buffer, offset, n)
            raise (IOException "No space left on device")

        inner.Write(buffer, offset, count)

    override this.Flush() =
        if this.FailFlush then
            this.FailFlush <- false
            raise (IOException "No space left on device")

        inner.Flush()

    override _.Dispose(disposing: bool) =
        if disposing then
            inner.Dispose()

        base.Dispose disposing

let private gvr = root 77
let private key n = PubKey.Of(Array.init 48 (fun i -> if i = 0 then byte (n + 1) else 0xC0uy))

/// A log that keeps every line.
let private capture () =
    let lines = Collections.Concurrent.ConcurrentQueue<LogLevel * string>()

    let log =
        {
            Write = fun level msg -> lines.Enqueue((level, msg))
            MinLevel = LogLevel.Debug
        }

    log, lines

/// The lines at Info and above.
let private loud (lines: Collections.Concurrent.ConcurrentQueue<LogLevel * string>) =
    [
        for level, msg in lines do
            if level >= LogLevel.Info then
                level, msg
    ]

let private writeFailed (v: Verdict[]) =
    v
    |> Array.forall (fun v ->
        match v with
        | Verdict.WriteFailed _ -> true
        | _ -> false)

let private openDb (file: IMarkFile) (gvr: Root) =
    match SlashingDb.Open(file, gvr) with
    | Ok db -> db
    | Error e -> failwith e

let private openSlotMarks (file: IMarkFile) =
    match SlotMarks.Open(file, gvr) with
    | Ok m -> m
    | Error e -> failwith e

let private mainnetSpec () =
    let node =
        ChainSpec.parseConfigYaml (Networks.configYaml "mainnet").Value |> Map.add "SLOTS_PER_EPOCH" "32"

    match ChainSpec.parse node with
    | Ok s -> s
    | Error e -> failwith e

/// An attestation at mainnet epoch 420000 + n, its source the epoch before its target.
let private attestation (n: int) =
    let epoch = 420000UL + uint64 n

    {
        Slot = epoch * 32UL + 5UL
        Index = 0UL
        BeaconBlockRoot = Root.Of(Array.create 32 (byte n))
        Source =
            {
                Epoch = epoch - 1UL
                Root = Root.Of(Array.create 32 1uy)
            }
        Target =
            {
                Epoch = epoch
                Root = Root.Of(Array.create 32 2uy)
            }
    }

let private expectOneFailureOneRecovery (lines: Collections.Concurrent.ConcurrentQueue<LogLevel * string>) =
    match loud lines with
    | [ LogLevel.Error, failure; LogLevel.Info, recovery ] ->
        Expect.stringContains failure "No space left on device" "the failure line names the cause"
        Expect.stringContains recovery "resumes" "the recovery line"
    | other -> failtest $"one line for the failure and one for the recovery: %A{other}"

[<Tests>]
let tests =
    testList
        "slashing DB retry"
        [
            test "a DB that failed to write tries again after a backoff and signs again once a write succeeds" {
                let model = new ModelFile([||])
                let file = new FlakyFile(model)
                let db = openDb file gvr
                let time = FakeTimeProvider()
                let log, lines = capture ()
                db.Time <- time
                db.Log <- ValueSome log
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                let check reqs = db.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result
                let att s t n = AttestationRequest(key 0, uint64 s, uint64 t, root n)
                Expect.equal (check [ att 0 1 1 ]) [| Verdict.Allowed |] "signed before the failure"
                let signedBefore = (db.Marks(key 0)).Value
                // Three writes fail: the burst's append, then the first two tries.
                file.FailWrites <- 3
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "the burst whose append failed"
                Expect.equal (db.Marks(key 0)) (ValueSome signedBefore) "marks unchanged"
                let writes = file.Writes
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "refused right after the failure"
                time.Advance(TimeSpan.FromMilliseconds 999.0)
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "refused before the first try is due"
                Expect.equal file.Writes writes "no write before the first try is due"
                time.Advance(TimeSpan.FromMilliseconds 1.0)
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "the first try fails"
                Expect.equal file.Writes (writes + 1) "the first try wrote, 1 s after the failure"
                time.Advance(TimeSpan.FromSeconds 1.0)
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "refused before the second try is due"
                Expect.equal file.Writes (writes + 1) "the backoff doubled to 2 s"
                time.Advance(TimeSpan.FromSeconds 1.0)
                Expect.isTrue (writeFailed (check [ att 1 2 2 ])) "the second try fails"
                Expect.equal file.Writes (writes + 2) "the second try wrote"
                time.Advance(TimeSpan.FromSeconds 4.0)
                Expect.equal (check [ att 1 2 2 ]) [| Verdict.Allowed |] "the third try succeeds and signs"
                Expect.equal (check [ att 2 3 3 ]) [| Verdict.Allowed |] "the next burst signs"
                Expect.equal (db.Marks(key 0)).Value.Attestation.Value.Target 3UL "marks of both bursts"
                // The half record the failed append left must not stay in the file: records after it
                // would fail their checksums and the replay would cut them.
                let reopened = openDb (new ModelFile((model :> IMarkFile).ReadAll())) gvr
                Expect.equal reopened.OpenInfo.TruncatedBytes 0L "no torn tail"
                Expect.equal (reopened.Marks(key 0)) (db.Marks(key 0)) "the file holds the marks in memory"
                expectOneFailureOneRecovery lines
            }

            test "the backoff doubles up to 12 s" {
                let file = new FlakyFile(new ModelFile([||]))
                let db = openDb file gvr
                let time = FakeTimeProvider()
                db.Time <- time
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                let check reqs = db.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result
                file.FailWrites <- 1000
                check [ BlockRequest(key 0, 1UL, root 1) ] |> ignore
                // Step 100 ms at a time and note when each try writes.
                let tries = Collections.Generic.List<int64>()
                let start = time.GetUtcNow()

                for _ in 1..1200 do
                    time.Advance(TimeSpan.FromMilliseconds 100.0)
                    let before = file.Writes
                    check [ BlockRequest(key 0, 1UL, root 1) ] |> ignore

                    if file.Writes > before then
                        tries.Add(int64 (time.GetUtcNow() - start).TotalMilliseconds)

                let gaps = [ for i in 1 .. tries.Count - 1 -> tries[i] - tries[i - 1] ]
                Expect.equal tries[0] 1000L "the first try 1 s after the failure"
                Expect.equal (List.truncate 5 gaps) [ 2000L; 4000L; 8000L; 12000L; 12000L ] "doubling to 12 s"
            }

            test "while writes fail no burst signs, also repeats; the burst after the first good write signs" {
                let model = new ModelFile([||])
                let file = new FlakyFile(model)
                let db = openDb file gvr
                let time = FakeTimeProvider()
                db.Time <- time

                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty; key 1, KeyOrigin.StartedEmpty ] |> ignore

                let check reqs = db.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result
                let earlier = AttestationRequest(key 0, 0UL, 1UL, root 1)
                Expect.equal (check [ earlier ]) [| Verdict.Allowed |] "signed before the failure"
                // Fails the burst's append and then every try for 10 minutes.
                file.FailWrites <- 1000

                for i in 1..600 do
                    let v = check [ earlier; BlockRequest(key 1, uint64 i, root i) ]
                    Expect.isTrue (writeFailed v) $"burst {i}: %A{v}"
                    time.Advance(TimeSpan.FromSeconds 1.0)

                Expect.equal (db.Marks(key 1)) (ValueSome KeyMarks.Empty) "no mark from a failed burst"
                file.FailWrites <- 0
                time.Advance(TimeSpan.FromSeconds 12.0)

                Expect.equal
                    (check [ earlier; BlockRequest(key 1, 601UL, root 601) ])
                    [| Verdict.Repeat; Verdict.Allowed |]
                    "signs again"

                let reopened = openDb (new ModelFile((model :> IMarkFile).ReadAll())) gvr

                Expect.equal
                    (reopened.Marks(key 0)).Value.Attestation.Value.Target
                    1UL
                    "the vote signed before the failure stays"

                Expect.equal (reopened.Marks(key 1)).Value.Block.Value.Slot 601UL "the block after the recovery"
            }

            test "slot marks try again after a backoff and sign again once a write succeeds" {
                let model = new ModelFile([||])
                let file = new FlakyFile(model)
                let marks = openSlotMarks file
                let time = FakeTimeProvider()
                let log, lines = capture ()
                marks.Time <- time
                marks.Log <- ValueSome log

                let req slot =
                    {
                        Key = key 0
                        Kind = SlotMarkKind.PayloadAttestation
                        Slot = uint64 slot
                        SigningRoot = root slot
                    }

                let check r = marks.CheckAndRecord([| r |], CancellationToken.None).Result

                Expect.equal (check (req 8)) [| Verdict.Allowed |] "signed before the failure"
                file.FailWrites <- 2
                Expect.isTrue (writeFailed (check (req 9))) "the burst whose append failed"
                let writes = file.Writes
                Expect.isTrue (writeFailed (check (req 9))) "refused before the first try is due"
                Expect.equal file.Writes writes "no write before the first try is due"
                time.Advance(TimeSpan.FromSeconds 1.0)
                Expect.isTrue (writeFailed (check (req 9))) "the first try fails"
                time.Advance(TimeSpan.FromSeconds 2.0)
                Expect.equal (check (req 9)) [| Verdict.Allowed |] "the second try succeeds and signs"
                Expect.equal (check (req 10)) [| Verdict.Allowed |] "the next burst signs"
                let reopened = openSlotMarks (new ModelFile((model :> IMarkFile).ReadAll()))
                Expect.equal reopened.OpenInfo.TruncatedBytes 0L "no torn tail"
                Expect.equal (reopened.Marks(key 0)) (marks.Marks(key 0)) "the file holds the marks in memory"
                expectOneFailureOneRecovery lines
            }

            test "a failed write leaves the real file at its last good length, also after the close" {
                let floor =
                    {
                        Block = ValueSome { Slot = 10UL; Root = ValueNone }
                        Attestation = ValueNone
                    }

                // The burst, then how the write fails: after some bytes of the write, or at the flush.
                let cases =
                    [
                        "half a record of a vote", false, 40, false
                        "the key record of a floor for a new key", true, 80, false
                        "a whole floor for a new key, failed at the flush", true, -1, true
                    ]

                for name, newKey, after, atFlush in cases do
                    let path = Path.Combine(tempDir (), "slashing.db")
                    let current = ref Unchecked.defaultof<FailingStream>

                    let wrap (s: Stream) =
                        current.Value <- new FailingStream(s)
                        current.Value :> Stream

                    let db = openDb (new FileMarkFile(path, wrap)) gvr
                    db.Time <- FakeTimeProvider()
                    db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore

                    Expect.equal
                        (db
                            .CheckAndRecord([| AttestationRequest(key 0, 0UL, 1UL, root 1) |], CancellationToken.None)
                            .Result)
                        [| Verdict.Allowed |]
                        $"{name}: signed before the failure"

                    let good = FileInfo(path).Length
                    let marks = db.Marks(key 0)

                    if atFlush then current.Value.FailFlush <- true else current.Value.FailWriteAfter <- after

                    if newKey then
                        Expect.isError (db.RaiseFloor([ key 1 ], KeyOrigin.Floor, floor)) $"{name}: the floor fails"
                    else
                        Expect.isTrue
                            (writeFailed (
                                db
                                    .CheckAndRecord(
                                        [| AttestationRequest(key 0, 1UL, 2UL, root 2) |],
                                        CancellationToken.None
                                    )
                                    .Result
                            ))
                            $"{name}: the vote fails"

                    Expect.equal (FileInfo(path).Length) good $"{name}: the file is at its last good length"
                    (db :> IDisposable).Dispose()
                    Expect.equal (FileInfo(path).Length) good $"{name}: still after the close"
                    use file = new FileMarkFile(path)
                    let reopened = openDb file gvr
                    Expect.equal reopened.OpenInfo.TruncatedBytes 0L $"{name}: no torn tail"
                    Expect.isFalse (reopened.HasRecord(key 1)) $"{name}: no record of the failed floor"
                    Expect.equal (reopened.Marks(key 0)) marks $"{name}: the durable marks"
            }

            test
                "a restart in the middle of an outage cuts what the failed write left and checks against the durable marks" {
                // A half record of the failed vote is a torn tail; a whole record of it is a mark
                // for a vote that was never sent.
                for part, torn in [ 40, 40L; 80, 0L ] do
                    let model = new ModelFile([||])
                    let file = new FlakyFile(model)
                    file.PartBytes <- part
                    let db = openDb file gvr
                    let time = FakeTimeProvider()
                    db.Time <- time
                    db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore

                    let check (db: SlashingDb) reqs =
                        db.CheckAndRecord(Array.ofList reqs, CancellationToken.None).Result

                    let att s t n = AttestationRequest(key 0, uint64 s, uint64 t, root n)
                    Expect.equal (check db [ att 0 1 1 ]) [| Verdict.Allowed |] "signed before the failure"
                    file.FailWrites <- 1
                    // Two votes, so a whole record of the burst still leaves the second one out.
                    Expect.isTrue (writeFailed (check db [ att 1 2 2; att 2 3 3 ])) "the failed burst"
                    let restarted = openDb (new ModelFile((model :> IMarkFile).ReadAll())) gvr
                    Expect.equal restarted.OpenInfo.TruncatedBytes torn $"part {part}: cut"

                    let isRefused v =
                        match v with
                        | Verdict.Refused _ -> true
                        | _ -> false

                    Expect.isTrue (isRefused (check restarted [ att 0 1 9 ]).[0]) "a double vote on the signed one"

                    if torn > 0L then
                        Expect.equal (restarted.Marks(key 0)) (db.Marks(key 0)) "the marks before the failure"
                        Expect.equal (check restarted [ att 1 2 2 ]) [| Verdict.Allowed |] "the unsent vote signs"
                    else
                        Expect.equal
                            (restarted.Marks(key 0)).Value.Attestation.Value.Target
                            2UL
                            "the whole record left a mark for the unsent vote"

                        Expect.isTrue (isRefused (check restarted [ att 1 2 9 ]).[0]) "another vote at that target"
                        Expect.equal (check restarted [ att 1 2 2 ]) [| Verdict.Repeat |] "the unsent vote itself"

                    Expect.equal (check restarted [ att 3 4 4 ]) [| Verdict.Allowed |] "a later vote signs"
                    // The first process signs again after its backoff, and its file holds no torn record.
                    time.Advance(TimeSpan.FromSeconds 1.0)
                    Expect.equal (check db [ att 1 2 2; att 2 3 3 ]) [| Verdict.Allowed; Verdict.Allowed |] "recovered"
                    let reopened = openDb (new ModelFile((model :> IMarkFile).ReadAll())) gvr
                    Expect.equal reopened.OpenInfo.TruncatedBytes 0L "no torn tail after the recovery"
                    Expect.equal (reopened.Marks(key 0)) (db.Marks(key 0)) "the file holds the marks in memory"
            }

            test "a long outage warns every 10 minutes and the gauge says since when" {
                let file = new FlakyFile(new ModelFile([||]))
                let db = openDb file gvr
                let time = FakeTimeProvider()
                let log, lines = capture ()
                db.Time <- time
                db.Log <- ValueSome log
                db.RegisterKeys [ key 0, KeyOrigin.StartedEmpty ] |> ignore
                let store = "test_slashing_db_retry"
                Metrics.watchSlashingStore store (fun () -> db.DownSince)
                let gauge () = Metrics.slashingStoresDownNow () |> List.tryFind (fun (s, _) -> s = store)
                Expect.equal (gauge ()) (Some(store, 0L)) "0 while the DB writes"

                let check n =
                    db.CheckAndRecord([| BlockRequest(key 0, uint64 n, root n) |], CancellationToken.None).Result

                file.FailWrites <- 100000
                let start = time.GetUtcNow()
                Expect.isTrue (writeFailed (check 1)) "the first failure"
                Expect.equal db.DownSince (ValueSome start) "down since the first failure"
                Expect.equal (gauge ()) (Some(store, start.ToUnixTimeSeconds())) "the gauge"
                // 25 minutes of a request each second.
                for i in 1..1500 do
                    time.Advance(TimeSpan.FromSeconds 1.0)
                    Expect.isTrue (writeFailed (check (i + 1))) $"second {i}"

                file.FailWrites <- 0
                time.Advance(TimeSpan.FromSeconds 12.0)
                Expect.equal (check 2000) [| Verdict.Allowed |] "signs again"
                Expect.equal db.DownSince ValueNone "up"
                Expect.equal (gauge ()) (Some(store, 0L)) "0 again"

                match loud lines with
                | [ LogLevel.Error, _; LogLevel.Warn, w1; LogLevel.Warn, w2; LogLevel.Info, recovery ] ->
                    for w in [ w1; w2 ] do
                        Expect.stringContains w (start.ToString "u") "the warning says since when"
                        Expect.stringContains w "failed writes" "and how many"

                    Expect.stringContains recovery "resumes" "the recovery line"
                | other -> failtest $"an error, a warning at 10 and at 20 minutes, the recovery: %A{other}"
            }

            test "slot marks report since when they are down" {
                let file = new FlakyFile(new ModelFile([||]))
                let marks = openSlotMarks file
                let time = FakeTimeProvider()
                marks.Time <- time

                let req slot =
                    {
                        Key = key 0
                        Kind = SlotMarkKind.PayloadAttestation
                        Slot = uint64 slot
                        SigningRoot = root slot
                    }

                let check r = marks.CheckAndRecord([| r |], CancellationToken.None).Result
                file.FailWrites <- 1
                let start = time.GetUtcNow()
                Expect.isTrue (writeFailed (check (req 8))) "the failure"
                Expect.equal marks.DownSince (ValueSome start) "down since the failure"
                time.Advance(TimeSpan.FromSeconds 1.0)
                Expect.equal (check (req 8)) [| Verdict.Allowed |] "signs again"
                Expect.equal marks.DownSince ValueNone "up"
            }

            testTask "no signature leaves the pipeline while slashing DB writes fail, and signing resumes after" {
                let spec = mainnetSpec ()
                let chainGvr = Root.Of(Array.init 32 (fun i -> byte (i + 1)))
                let sk = secretOf 0
                let pk = pubkeyOf 0
                let calls = ref 0

                let backend =
                    {
                        Name = "counting"
                        Capabilities = LocalBackend.capabilities
                        Keys = fun _ -> Task.FromResult []
                        Health = fun _ -> Task.FromResult Up
                        Sign =
                            fun req _ ->
                                Interlocked.Increment calls |> ignore

                                Task.FromResult(
                                    Signed(
                                        BlsSignature.Of(Bls.sign (ReadOnlySpan sk) (ReadOnlySpan req.SigningRoot.Bytes))
                                    )
                                )
                        Dispose = fun () -> ValueTask.CompletedTask
                    }

                let file = new FlakyFile(new ModelFile([||]))
                let db = openDb file chainGvr
                let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                let log, lines = capture ()
                db.Time <- time
                db.Log <- ValueSome log
                db.RegisterKeys [ pk, KeyOrigin.StartedEmpty ] |> ignore
                let registry = KeyRegistry()
                registry.Add(pk, backend) |> ignore
                registry.SetState(pk, KeyState.Active)
                let pipeline = Pipeline(db, registry, time, log)

                let sign n =
                    let deadline = time.GetUtcNow().AddMinutes 1.0
                    let req = Duty.request spec chainGvr pk Priority.High deadline (Duty.Attestation(attestation n))
                    pipeline.Sign(req, CancellationToken.None)

                let signed (o: SignOutcome) =
                    match o with
                    | Signed _ -> true
                    | _ -> false

                let! o = sign 0
                Expect.isTrue (signed o) $"before the failure: {o.Describe}"
                Expect.equal calls.Value 1 "one signature"
                file.FailWrites <- 2

                // The burst's append fails, the try 1 s later fails, and the requests in between
                // are refused without a write.
                for _ in 1..6 do
                    let! o = sign 1
                    Expect.isFalse (signed o) $"refused: {o.Describe}"
                    time.Advance(TimeSpan.FromMilliseconds 500.0)

                Expect.equal calls.Value 1 "no request reached the backend while writes failed"
                Expect.equal file.FailWrites 0 "both failing writes were tried"
                time.Advance(TimeSpan.FromSeconds 2.0)
                let! o = sign 1
                Expect.isTrue (signed o) $"after the first good write: {o.Describe}"
                let! o = sign 2
                Expect.isTrue (signed o) $"the next duty: {o.Describe}"
                Expect.equal calls.Value 3 "two more signatures"
                expectOneFailureOneRecovery lines
            }
        ]
