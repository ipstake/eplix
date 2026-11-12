/// TLS certificate and CA files that reload while the VC runs.
/// One TlsFile per certificate and key pair, or per CA file. A task reads the files every reload
/// interval on the VC clock, off the duty path, and compares the bytes with the last good load;
/// only a change is parsed. A change that loads replaces the value whole and raises Swapped. One
/// that does not (no certificate, a key that does not match, an expired certificate, one never
/// valid) keeps the value in force and logs one error per bad content, as the switch file does.
/// A pair that loads but is not valid yet waits, and takes over at its NotBefore.
/// Connections are built from the value in memory; nothing reads the files again.
namespace Eplix

open System
open System.IO
open System.Net.Security
open System.Runtime.InteropServices
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Threading
open System.Threading.Tasks

/// One load of a TLS file set.
type TlsLoad<'T> =
    {
        Value: 'T
        /// The earliest NotAfter of the certificates in it.
        NotAfter: DateTimeOffset
        /// 1 for the load at start, one more at each swap.
        Generation: int
    }

/// What the reload task checks.
type TlsCheck =
    abstract Check: unit -> unit

[<Sealed>]
type TlsFile<'T>
    private
    (
        use': string,
        name: string,
        files: string list,
        parse: byte[] list -> DateTimeOffset -> 'T * DateTimeOffset,
        validFrom: 'T -> DateTimeOffset,
        warnExpiry: bool,
        log: Log,
        time: TimeProvider,
        first: TlsLoad<'T>,
        firstBytes: byte[] list
    ) =
    let gate = obj ()

    [<VolatileField>]
    let mutable current = first

    let mutable lastBytes = firstBytes
    let mutable lastBroken: byte[] list = []
    let mutable lastReadError = ""
    let mutable lastExpiryLog = DateTimeOffset.MinValue
    /// A changed set that loads but is not valid yet: value, NotBefore, NotAfter, bytes.
    let mutable waiting: ('T * DateTimeOffset * DateTimeOffset * byte[] list) option = None
    let swapped = Event<TlsLoad<'T> * TlsLoad<'T>>()
    let fileNames = String.Join(" and ", files)

    static let same (a: byte[] list) (b: byte[] list) =
        a.Length = b.Length
        && List.forall2 (fun (x: byte[]) (y: byte[]) -> x.AsSpan().SequenceEqual(ReadOnlySpan y)) a b

    /// The message of a failed load, with the file names in front unless it starts with one.
    static let named (files: string list) (m: string) =
        if files |> List.exists (fun f -> m.StartsWith f) then m else $"""{String.Join(" and ", files)}: {m}"""

    static let tryParse (files: string list) parse (bytes: byte[] list) (now: DateTimeOffset) =
        try
            Ok(parse bytes now)
        with e ->
            Error(named files e.Message)

    /// Loads the files at start; a file that does not load fails.
    static member Load
        (
            use': string,
            name: string,
            files: string list,
            parse,
            validFrom: 'T -> DateTimeOffset,
            warnExpiry: bool,
            log: Log,
            time: TimeProvider
        ) : Result<TlsFile<'T>, string> =
        let bytes =
            try
                Ok(files |> List.map File.ReadAllBytes)
            with e ->
                Error(named files e.Message)

        match
            bytes
            |> Result.bind (fun b -> tryParse files parse b (time.GetUtcNow()) |> Result.map (fun v -> v, b))
        with
        | Error e -> Error e
        | Ok((v, notAfter), b) ->
            Metrics.tlsNotAfter use' name notAfter

            Ok(
                TlsFile<'T>(
                    use',
                    name,
                    files,
                    parse,
                    validFrom,
                    warnExpiry,
                    log,
                    time,
                    {
                        Value = v
                        NotAfter = notAfter
                        Generation = 1
                    },
                    b
                )
            )

    /// A value that never reloads: for tests, and for endpoints without TLS files.
    static member Fixed(value: 'T, notAfter: DateTimeOffset) : TlsFile<'T> =
        TlsFile<'T>(
            "",
            "",
            [],
            (fun _ _ -> value, notAfter),
            (fun _ -> DateTimeOffset.MinValue),
            false,
            Log.none,
            TimeProvider.System,
            {
                Value = value
                NotAfter = notAfter
                Generation = 1
            },
            []
        )

    member _.Use = use'
    member _.Name = name

    /// The files, for messages.
    member _.Files = fileNames

    /// The paths of the files, for a watcher (TlsReloader).
    member _.Paths = files

    /// The value in force: one volatile read.
    member _.Current = current

    /// Raised after a swap, with the old and the new load, on the reload task.
    [<CLIEvent>]
    member _.Swapped = swapped.Publish

    /// Reads the files once: swaps in a changed set that loads, keeps the value on one that does
    /// not, and logs an expired certificate with no replacement once a minute. A changed set
    /// that loads but is not valid yet waits: each check looks at its NotBefore again, with no
    /// parse, and swaps it in once it is valid, so no peer gets a certificate it refuses for its NotBefore.
    member _.Check() =
        if not files.IsEmpty then
            let now = time.GetUtcNow()

            let bytes =
                try
                    Ok(files |> List.map File.ReadAllBytes)
                with e ->
                    Error e.Message

            let swap, waitingFrom =
                lock gate (fun () ->
                    let swapIn (v: 'T) (notAfter: DateTimeOffset) (b: byte[] list) =
                        let old = current

                        let next =
                            {
                                Value = v
                                NotAfter = notAfter
                                Generation = old.Generation + 1
                            }

                        current <- next
                        lastBytes <- b
                        lastBroken <- []
                        waiting <- None
                        Metrics.tlsReload use' name true
                        Metrics.tlsNotAfter use' name notAfter
                        ValueSome(old, next)

                    let refuse (b: byte[] list) (m: string) =
                        lastBroken <- b
                        waiting <- None
                        Metrics.tlsReload use' name false
                        log.Error $"{use'} {name}: {m}; the certificate in use stays"
                        ValueNone

                    let swap =
                        match bytes with
                        | Error m ->
                            if m <> lastReadError then
                                lastReadError <- m
                                Metrics.tlsReload use' name false
                                log.Error $"{use'} {name}: {m}; the certificate in use stays"

                            ValueNone
                        | Ok b ->
                            lastReadError <- ""

                            match waiting with
                            | Some(v, notBefore, notAfter, wb) when same b wb ->
                                if now > notAfter then
                                    refuse
                                        b
                                        $"{fileNames}: the certificate expired on {notAfter.UtcDateTime:u} before it became valid"
                                elif now >= notBefore then
                                    swapIn v notAfter b
                                else
                                    ValueNone
                            | _ ->
                                if same b lastBytes || same b lastBroken then
                                    waiting <- None
                                    ValueNone
                                else
                                    match tryParse files parse b now with
                                    | Ok(v, notAfter) ->
                                        let notBefore = validFrom v

                                        if notBefore >= notAfter then
                                            refuse
                                                b
                                                $"{fileNames}: the certificate is never valid (NotBefore {notBefore.UtcDateTime:u}, NotAfter {notAfter.UtcDateTime:u})"
                                        elif now < notBefore then
                                            waiting <- Some(v, notBefore, notAfter, b)

                                            log.Warn
                                                $"{use'} {name}: the certificate in {fileNames} is not valid until {notBefore.UtcDateTime:u}; it takes over then, the one in use stays until that"

                                            ValueNone
                                        else
                                            swapIn v notAfter b
                                    | Error m -> refuse b m

                    swap, (waiting |> Option.map (fun (_, nb, _, _) -> nb)))

            match swap with
            | ValueSome(old, next) ->
                log.Info $"{use'} {name}: {fileNames} reloaded, valid until {next.NotAfter.UtcDateTime:u}"

                try
                    swapped.Trigger((old, next))
                with e ->
                    log.Error $"{use'} {name}: applying the new certificate failed: {e.Message}"
            | ValueNone -> ()

            let c = current

            if warnExpiry && now >= c.NotAfter && now - lastExpiryLog >= TimeSpan.FromMinutes 1.0 then
                lastExpiryLog <- now

                let replacement =
                    match waitingFrom with
                    | Some nb -> $"the replacement in the files is not valid until {nb.UtcDateTime:u}"
                    | None -> "no valid replacement loaded"

                log.Error
                    $"{use'} {name}: the certificate in {fileNames} expired on {c.NotAfter.UtcDateTime:u} and {replacement}; new connections fail until one does"

    interface TlsCheck with
        member this.Check() = this.Check()

/// A client object built from one certificate generation (an HTTP handler, a gRPC channel) and
/// its replacement after a swap: built and tested off the request path, then made current. The
/// old one is disposed after a grace period, so requests that took it finish.
/// A replacement whose test fails is tried again with backoff (1 s doubling to 16 s); it becomes
/// current anyway once `expires` passes, since the old certificate is no use after that.
[<Sealed>]
type Rotating<'T when 'T: not struct>(name: string, first: 'T, dispose: 'T -> unit, log: Log, time: TimeProvider) =
    let gate = obj ()

    [<VolatileField>]
    let mutable current = first

    let mutable wanted = 0
    let mutable running = false

    let mutable job: struct ((unit -> 'T) * ('T -> CancellationToken -> Task) * DateTimeOffset * TimeSpan) voption =
        ValueNone

    let stop = new CancellationTokenSource()

    let later (grace: TimeSpan) (x: 'T) =
        task {
            try
                do! Task.Delay(grace, time, stop.Token)
            with :? OperationCanceledException ->
                ()

            try
                dispose x
            with _ ->
                ()
        }
        |> ignore

    let work () : Task =
        task {
            let mutable go = true
            let mutable failed = 0

            while go do
                let struct (n, j) = lock gate (fun () -> struct (wanted, job))

                match j with
                | ValueNone ->
                    lock gate (fun () -> running <- false)
                    go <- false
                | ValueSome(struct (make, test, expires, grace)) ->
                    let mutable fresh = ValueNone
                    let mutable error = ""

                    try
                        fresh <- ValueSome(make ())
                    with e ->
                        error <- e.Message

                    let mutable tested = false

                    match fresh with
                    | ValueSome f ->
                        try
                            use cts = CancellationTokenSource.CreateLinkedTokenSource stop.Token
                            cts.CancelAfter(TimeSpan.FromSeconds 15.0)
                            do! test f cts.Token
                            tested <- true
                        with e ->
                            error <- e.Message
                    | ValueNone -> ()

                    let now = time.GetUtcNow()
                    let latest = lock gate (fun () -> wanted)

                    match fresh with
                    | ValueSome f when stop.IsCancellationRequested ->
                        dispose f
                        go <- false
                    | ValueSome f when latest <> n ->
                        // A newer certificate came while this one was tested: build that one.
                        dispose f
                    | ValueSome f when tested || now >= expires ->
                        let old = current
                        current <- f
                        later grace old

                        if tested then
                            log.Info $"{name}: new connections use the new client certificate"
                        else
                            log.Error
                                $"{name}: the old client certificate expired; switched to the new one although a test connection failed: {error}"

                        failed <- 0

                        let finished =
                            lock gate (fun () ->
                                if wanted = n then
                                    job <- ValueNone
                                    running <- false
                                    true
                                else
                                    false)

                        if finished then
                            go <- false
                    | fresh ->
                        fresh |> ValueOption.iter dispose
                        failed <- failed + 1
                        let mutable wait = TimeSpan.FromSeconds 1.0

                        for _ in 2..failed do
                            if wait < TimeSpan.FromSeconds 16.0 then
                                wait <- wait * 2.0

                        let left = expires - now
                        let wait = if left > TimeSpan.Zero && left < wait then left else wait

                        log.Warn
                            $"{name}: a test connection with the new client certificate failed, again in {wait.TotalSeconds:F0} s: {error}"

                        try
                            do! Task.Delay(wait, time, stop.Token)
                        with :? OperationCanceledException ->
                            go <- false
        }

    /// The object new requests take.
    member _.Current = current

    /// Builds a replacement with `make`, checks it with `test` and makes it current; `expires` is
    /// the old certificate's NotAfter. A later call replaces an earlier one still in progress.
    member _.Replace
        (make: unit -> 'T, test: 'T -> CancellationToken -> Task, expires: DateTimeOffset, grace: TimeSpan)
        =
        let start =
            lock gate (fun () ->
                wanted <- wanted + 1
                job <- ValueSome(struct (make, test, expires, grace))

                if running || stop.IsCancellationRequested then
                    false
                else
                    running <- true
                    true)

        if start then
            Task.Run(fun () -> work ()) |> ignore

    /// Stops a replacement in progress and disposes the current object.
    member _.Dispose() =
        stop.Cancel()
        dispose current

/// SIGHUP in the VC. Program registers the signal once, for the whole run: the
/// handler cancels the default action, which would end the process, and calls every TLS reloader
/// running; with none it logs that no certificate reload is configured.
[<Sealed>]
type SighupHub() =
    let gate = obj ()
    let handlers = ResizeArray<unit -> unit>()

    /// The hub of the process, which Program registers and the reloaders join.
    static member val Default = SighupHub()

    /// Adds a handler until the result is disposed.
    member _.Add(f: unit -> unit) : IDisposable =
        lock gate (fun () -> handlers.Add f)

        { new IDisposable with
            member _.Dispose() = lock gate (fun () -> handlers.Remove f |> ignore)
        }

    /// What the signal does: runs every handler, or logs that there is none. Returns how many ran.
    member _.Raise(log: Log) : int =
        let hs = lock gate (fun () -> List.ofSeq handlers)

        if hs.IsEmpty then
            log.Info "SIGHUP: no certificate reload configured"

        for h in hs do
            try
                h ()
            with e ->
                log.Error $"SIGHUP: {e.Message}"

        hs.Length

    /// Registers the process's SIGHUP handler until the result is disposed.
    member this.Register(log: Log) : IDisposable =
        PosixSignalRegistration.Create(
            PosixSignal.SIGHUP,
            Action<PosixSignalContext>(fun ctx ->
                ctx.Cancel <- true
                this.Raise log |> ignore)
        )
        :> IDisposable

/// Runs the checks of TLS file sets while the VC runs: every `interval`, after
/// a change to a watched file, and on SIGHUP (through SighupHub.Default). Certificate agents
/// often write a new file and rename it over the old one, so the watcher looks at the directory
/// and wakes on any event that names a watched file, as the old or the new name. A file reached
/// through a symlinked directory that is swapped (a ..data link) raises no such event; the poll
/// reads it. A burst of events gives one check once the directory has been quiet for
/// `debounce`, or after 20 debounce periods of steady events. SIGHUP checks at once. A check
/// swaps only a set that loads (TlsFile.Check): a half-written or mismatched pair keeps the one in
/// use, logs an error and counts in eplix_tls_cert_reloads, and the next change tries again. A
/// zero interval turns all of it off, as reload_interval_seconds 0 does.
[<Sealed>]
type TlsReloader
    (
        name: string,
        files: TlsCheck list,
        paths: string list,
        interval: TimeSpan,
        debounce: TimeSpan,
        log: Log,
        time: TimeProvider
    ) =
    let gate = obj ()

    let mutable wake: TaskCompletionSource =
        TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

    let mutable signalled = false
    let mutable checks = 0

    let woken () = lock gate (fun () -> wake.Task)

    let set () = lock gate (fun () -> wake.TrySetResult() |> ignore)

    /// Clears the wake-up and the signal before a check; events after this wake the next round.
    let clear () =
        lock gate (fun () ->
            if wake.Task.IsCompleted then
                wake <- TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

            signalled <- false)

    let startWatchers () =
        let ws = ResizeArray<FileSystemWatcher>()
        // Directory to the names of the watched files in it.
        let dirs =
            paths
            |> List.choose (fun p ->
                let full = Path.GetFullPath p

                match Path.GetDirectoryName full with
                | null
                | "" -> None
                | d -> Some(d, Path.GetFileName full))
            |> List.groupBy fst
            |> List.map (fun (d, xs) -> d, xs |> List.map snd |> Set.ofList)

        for dir, names in dirs do
            try
                let w = new FileSystemWatcher(dir)

                w.NotifyFilter <-
                    NotifyFilters.FileName
                    ||| NotifyFilters.DirectoryName
                    ||| NotifyFilters.LastWrite
                    ||| NotifyFilters.Size
                    ||| NotifyFilters.CreationTime

                let watched (n: string | null) =
                    match n with
                    | null -> false
                    | n -> names.Contains n

                let on =
                    FileSystemEventHandler(fun _ e ->
                        if watched e.Name then
                            set ())

                w.Changed.AddHandler on
                w.Created.AddHandler on
                w.Deleted.AddHandler on

                w.Renamed.AddHandler(
                    RenamedEventHandler(fun _ e ->
                        if watched e.Name || watched e.OldName then
                            set ())
                )
                // A lost event (queue overflow) may hide a change: check anyway.
                w.Error.AddHandler(ErrorEventHandler(fun _ _ -> set ()))
                w.EnableRaisingEvents <- true
                ws.Add w
            with e ->
                log.Warn
                    $"{name}: cannot watch {dir} for changes ({e.Message}); its TLS files are read every {interval.TotalSeconds:F0} s"

        List.ofSeq ws

    let checkAll () =
        for f in files do
            try
                f.Check()
            with e ->
                log.Error $"{name}: reading TLS files failed: {e.Message}"

        Interlocked.Increment(&checks) |> ignore

    /// What SIGHUP does: check now, with no debounce.
    member _.RequestNow() =
        lock gate (fun () ->
            signalled <- true
            wake.TrySetResult() |> ignore)

    /// Checks run so far, for tests.
    member _.Checks = Volatile.Read(&checks)

    /// Runs until `ct` is cancelled; the watchers and the SIGHUP handler go with it.
    member this.Run(ct: CancellationToken) : Task =
        if files.IsEmpty || interval <= TimeSpan.Zero then
            Task.CompletedTask
        else
            let watchers = startWatchers ()
            let hup = SighupHub.Default.Add(fun () -> this.RequestNow())

            task {
                try
                    try
                        while not ct.IsCancellationRequested do
                            use round = CancellationTokenSource.CreateLinkedTokenSource ct
                            let! _ = Task.WhenAny(Task.Delay(interval, time, round.Token), woken ())
                            round.Cancel()
                            ct.ThrowIfCancellationRequested()

                            if woken().IsCompleted && not (lock gate (fun () -> signalled)) then
                                let mutable quiet = false
                                let mutable rounds = 0

                                while not quiet do
                                    lock gate (fun () ->
                                        if wake.Task.IsCompleted then
                                            wake <-
                                                TaskCompletionSource(
                                                    TaskCreationOptions.RunContinuationsAsynchronously
                                                ))

                                    use d = CancellationTokenSource.CreateLinkedTokenSource ct
                                    let! _ = Task.WhenAny(Task.Delay(debounce, time, d.Token), woken ())
                                    d.Cancel()
                                    ct.ThrowIfCancellationRequested()
                                    rounds <- rounds + 1

                                    quiet <-
                                        not (woken().IsCompleted) || lock gate (fun () -> signalled) || rounds >= 20
                            elif lock gate (fun () -> signalled) then
                                log.Info $"{name}: SIGHUP, reading the TLS files"

                            clear ()
                            checkAll ()
                    with :? OperationCanceledException ->
                        ()
                finally
                    for w in watchers do
                        w.Dispose()

                    hup.Dispose()
            }

module TlsFiles =
    /// The bytes of certificate, key or CA files, for a load at start that does not reload. The
    /// one read of such files outside TlsFile.
    let read (files: string list) : byte[] list = files |> List.map File.ReadAllBytes

    /// The client certificate with its key and intermediates (ClientCert.ofPem) from two files.
    let clientPair
        (certFile: string)
        (bytes: byte[] list)
        (now: DateTimeOffset)
        : SslStreamCertificateContext * DateTimeOffset =
        match bytes with
        | [ c; k ] -> ClientCert.ofPem certFile (Encoding.UTF8.GetString c) (Encoding.UTF8.GetString k) now
        | _ -> invalidArg "bytes" "a certificate file and a key file"

    /// The CA certificates of a PEM file (one or more) or a DER file (one).
    let caBundle (bytes: byte[] list) (_: DateTimeOffset) : X509Certificate2Collection * DateTimeOffset =
        let b = List.exactlyOne bytes
        let c = X509Certificate2Collection()
        let text = Encoding.UTF8.GetString b

        if text.Contains "-----BEGIN" then
            c.ImportFromPem(text.AsSpan())
            ClientCert.checkPemCount text c.Count
        else
            try
                c.Add(X509CertificateLoader.LoadCertificate b) |> ignore
            with _ ->
                ()

        if c.Count = 0 then
            raise (InvalidDataException "no PEM certificate, nor one DER certificate")

        c, ClientCert.notAfter c

    /// A client certificate file pair; the start fails on an expired certificate.
    let client (use': string) (name: string) (certFile: string) (keyFile: string) (log: Log) (time: TimeProvider) =
        TlsFile<SslStreamCertificateContext>
            .Load(use', name, [ certFile; keyFile ], clientPair certFile, ClientCert.validFrom, true, log, time)

    /// A CA file. It has no validity rule: a bundle may hold old and new CAs side by side.
    let ca (use': string) (name: string) (file: string) (log: Log) (time: TimeProvider) =
        TlsFile<X509Certificate2Collection>
            .Load(use', name, [ file ], caBundle, (fun _ -> DateTimeOffset.MinValue), false, log, time)

    /// Checks every file once per `interval` until cancelled; a zero interval turns reloading off.
    let watch (files: TlsCheck list) (interval: TimeSpan) (time: TimeProvider) (ct: CancellationToken) : Task =
        if files.IsEmpty || interval <= TimeSpan.Zero then
            Task.CompletedTask
        else
            task {
                try
                    while not ct.IsCancellationRequested do
                        do! Task.Delay(interval, time, ct)

                        for f in files do
                            f.Check()
                with :? OperationCanceledException ->
                    ()
            }

    /// The reload settings of a module section: `reload_interval_seconds` (default 10, 0 turns
    /// reloading off) and `rotate_within_seconds` (default 300).
    let reloadInterval (seconds: uint64 voption) =
        match seconds with
        | ValueSome s when s > 3600UL -> Error "reload_interval_seconds must be 0 (off) to 3600"
        | ValueSome s -> Ok(TimeSpan.FromSeconds(float s))
        | ValueNone -> Ok(TimeSpan.FromSeconds 10.0)

    let rotateWithin (seconds: uint64 voption) =
        match seconds with
        | ValueSome s when s < 1UL || s > 86400UL -> Error "rotate_within_seconds must be 1 to 86400"
        | ValueSome s -> Ok(TimeSpan.FromSeconds(float s))
        | ValueNone -> Ok(TimeSpan.FromSeconds 300.0)
