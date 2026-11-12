module Eplix.Tests.TestUtil

open System
open System.IO

/// The repository root: the first parent directory of the test binary that holds global.json.
let repoRoot =
    let rec up (d: DirectoryInfo) =
        if isNull d then failwith "repository root not found"
        elif File.Exists(Path.Combine(d.FullName, "global.json")) then d.FullName
        else up d.Parent

    up (DirectoryInfo AppContext.BaseDirectory)

let vectors = Path.Combine(repoRoot, "tests", "vectors")
let fixtures = Path.Combine(repoRoot, "tests", "fixtures")

let hex (s: string) =
    match Eplix.Hex.tryDecode s with
    | ValueSome b -> b
    | ValueNone -> failwithf "bad hex %s" s

let tempDir () =
    let d = Path.Combine(Path.GetTempPath(), "eplix-tests", Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory d |> ignore
    d

/// A deterministic 32-byte value from a small number, for test roots.
let root (n: int) =
    let b = Array.zeroCreate<byte> 32
    b[0] <- byte n
    b[1] <- byte (n >>> 8)
    b[31] <- 0x5Auy
    Eplix.Root.Of b

/// An FsCheck runner that writes nothing and throws on a failure, with FsCheck's message (seed
/// and input). FsCheck's console runners write to Console.Out ("Ok, passed 100 tests."). Under
/// Expecto that can deadlock the whole run: Console.Out is then Expecto's synchronized writer, so
/// a test thread holds its lock and waits for the lock of Expecto's ANSI writer, while Expecto's
/// flush holds that one and waits for the first, which .NET takes on every console write.
let quietThrowingRunner =
    { new FsCheck.IRunner with
        member _.OnStartFixture _ = ()
        member _.OnArguments(_, _, _) = ()
        member _.OnShrink(_, _) = ()

        member _.OnFinished(name, result) =
            match result with
            | FsCheck.TestResult.Passed _ -> ()
            | r -> failwith (FsCheck.Runner.onFinishedToString name r)
    }

/// FsCheck's QuickThrowOnFailure with `n` cases and the quiet runner.
let propConfig (n: int) = FsCheck.Config.QuickThrowOnFailure.WithMaxTest(n).WithRunner(quietThrowingRunner)

/// Runs an FsCheck property inside an Expecto test (100 cases, throws on failure).
let testProp name (property: 'P) = Expecto.Tests.test name { FsCheck.Check.One(propConfig 100, property) }

let testPropN name (n: int) (property: 'P) = Expecto.Tests.test name { FsCheck.Check.One(propConfig n, property) }

/// EPLIX_FUZZ_CASES: cases per fuzz property (default 200), for long runs.
let fuzzCases =
    match Environment.GetEnvironmentVariable "EPLIX_FUZZ_CASES" with
    | null
    | "" -> 200
    | s -> int s

/// EPLIX_FUZZ_SEED: a fixed FsCheck seed, so a long run can be logged and replayed. It also takes
/// the failing step FsCheck prints, `(seed,gamma,size)`, which starts at the failing case.
let fuzzReplay (config: FsCheck.Config) =
    match Environment.GetEnvironmentVariable "EPLIX_FUZZ_SEED" with
    | null
    | "" -> config
    | s ->
        let parts = s.Trim('(', ')', ' ').Split(',', StringSplitOptions.TrimEntries)

        let replay: FsCheck.Replay =
            match parts with
            | [| seed |] ->
                {
                    Rnd = FsCheck.Rnd(UInt64.Parse seed)
                    Size = None
                }
            | [| seed; gamma |] ->
                {
                    Rnd = FsCheck.Rnd(UInt64.Parse seed, UInt64.Parse gamma)
                    Size = None
                }
            | [| seed; gamma; size |] ->
                {
                    Rnd = FsCheck.Rnd(UInt64.Parse seed, UInt64.Parse gamma)
                    Size = Some(int size)
                }
            | _ -> failwith $"EPLIX_FUZZ_SEED '{s}' is not a seed or (seed,gamma,size)"

        config.WithReplay(Some replay)

/// A model property: `n` cases, or EPLIX_FUZZ_CASES when that is more, with EPLIX_FUZZ_SEED.
let testPropFuzz name (n: int) (property: 'P) =
    Expecto.Tests.test name { FsCheck.Check.One(fuzzReplay (propConfig (max n fuzzCases)), property) }

/// A test whose body is an F# task (Expecto's own task builder lacks `use`, tuple patterns and more).
let testT name (body: unit -> System.Threading.Tasks.Task<unit>) =
    Expecto.Tests.test name { body().GetAwaiter().GetResult() }

/// Waits until every background check the watch has queued has changed its state. Check results
/// land in completion order, not request order, so a test settles before each next request.
let settle (w: Eplix.SignatureWatch) : System.Threading.Tasks.Task<unit> =
    task {
        try
            do! w.Settled().WaitAsync(TimeSpan.FromSeconds 10.0)
        with :? TimeoutException ->
            Expecto.Tests.failtestf "%d background checks still wait after 10 s" w.Pending
    }

/// A floor source for tests that call Validators.refresh: a clock from genesis 0. Refresh reads it
/// only to write an override floor.
let testFloor: Eplix.FloorSource =
    {
        Clock = Eplix.SlotClock(DateTimeOffset.UnixEpoch, TimeSpan.FromSeconds 12.0, 32UL, TimeProvider.System)
        SlotMarks = ValueNone
    }

/// Validators.refresh for tests whose keys sign from epoch 0: a live key without a record first
/// gets an empty one (tests only, through the internal RegisterKeys; the VC writes floors).
let refreshEmpty slashed nodes (registry: Eplix.KeyRegistry) (db: Eplix.Slashing.SlashingDb) log ct =
    db.RegisterKeys [ for k in registry.Live -> k.Key, Eplix.Slashing.KeyOrigin.StartedEmpty ] |> ignore
    Eplix.Validators.refreshWith slashed testFloor nodes registry db Eplix.AllowStartWithoutHistory.Nobody log ct

/// A stream over bytes that hands out at most `chunk ()` bytes per read, synchronously.
type ChunkStream(bytes: byte[], chunk: unit -> int) =
    inherit System.IO.Stream()
    let mutable pos = 0
    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = int64 bytes.Length

    override _.Position
        with get () = int64 pos
        and set _ = raise (System.NotSupportedException())

    override _.Flush() = ()
    override _.Seek(_, _) = raise (System.NotSupportedException())
    override _.SetLength _ = raise (System.NotSupportedException())
    override _.Write(_, _, _) = raise (System.NotSupportedException())

    override _.Read(buffer: byte[], offset: int, count: int) =
        let n = min (min count (max 1 (chunk ()))) (bytes.Length - pos)
        System.Buffer.BlockCopy(bytes, pos, buffer, offset, n)
        pos <- pos + n
        n

    override this.ReadAsync(buffer: System.Memory<byte>, _: System.Threading.CancellationToken) =
        let n = min (min buffer.Length (max 1 (chunk ()))) (bytes.Length - pos)
        bytes.AsSpan(pos, n).CopyTo(buffer.Span)
        pos <- pos + n
        System.Threading.Tasks.ValueTask<int>(n)

/// Two loopback HTTP servers: `Url` answers every request with a 307 to `Target`, and `Target`
/// counts the requests that reach it. A client that follows no redirect never reaches it.
type RedirectServer() =
    let listen () =
        let l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0)
        l.Start()
        l

    let front = listen ()
    let back = listen ()
    let portOf (l: System.Net.Sockets.TcpListener) = (l.LocalEndpoint :?> System.Net.IPEndPoint).Port
    let reached = ref 0
    let cts = new System.Threading.CancellationTokenSource()

    let serve (l: System.Net.Sockets.TcpListener) (answer: unit -> string) =
        System.Threading.Tasks.Task.Run(fun () ->
            task {
                try
                    while not cts.IsCancellationRequested do
                        let! c = l.AcceptTcpClientAsync cts.Token

                        try
                            use c = c
                            use s = c.GetStream()
                            // Reads the request head; the bodies here are small enough for one read.
                            let buf = Array.zeroCreate<byte> 65536
                            let! _ = s.ReadAsync(buf, 0, buf.Length)
                            let bytes = System.Text.Encoding.ASCII.GetBytes(answer ())
                            do! s.WriteAsync(bytes, 0, bytes.Length)
                        with _ ->
                            ()
                with _ ->
                    ()
            }
            :> System.Threading.Tasks.Task)
        |> ignore

    do
        serve front (fun () ->
            $"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{portOf back}/moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        serve back (fun () ->
            System.Threading.Interlocked.Increment &reached.contents |> ignore
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")

    member _.Url = Uri $"http://127.0.0.1:{portOf front}/"
    member _.Reached = System.Threading.Volatile.Read &reached.contents

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            front.Stop()
            back.Stop()
