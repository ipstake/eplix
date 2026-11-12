/// The graffiti file module. Config section "graffiti":
///   { "file": "graffiti.txt", "rotation": "slot" }
/// Off when the section is absent. The file (GraffitiFile.fs) gives a text per key or for every
/// key, with templates and rotation. It sits below the per-key settings (the proposer config
/// file's entry and the keymanager API's graffiti) and above the defaults (the proposer config
/// file's default_config and the core `graffiti`); GraffitiService in the core holds the order.
///
/// The file loads when the config is read: a missing or invalid file fails the start. After that
/// a task of its own checks the file's size and write time before each epoch boundary and reads
/// it again only on a change, off the duty path. A file that fails to read or parse keeps the
/// last good content and logs an error at each check until it is fixed. A proposal reads the
/// content in place and never waits for a check.
module Eplix.Graffiti.GraffitiModule

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json
open Eplix.Graffiti.GraffitiFile

let name = "graffiti"

type Settings = { File: string; Rotation: Rotation }

let parseSettings (section: ConfigSection) : Result<Settings voption, string list> =
    match section.Element with
    | ValueNone -> Ok ValueNone
    | ValueSome e when e.ValueKind <> JsonValueKind.Object -> Error [ "modules.graffiti must be an object" ]
    | ValueSome e ->
        match checkFields e "modules.graffiti" [ "file"; "rotation" ] with
        | [] ->
            let file =
                match tryProp e "file" with
                | ValueSome f when f.ValueKind = JsonValueKind.String -> Ok(section.Path(f.GetString() |> nonNull))
                | ValueSome _ -> Error "modules.graffiti: file must be a path"
                | ValueNone -> Error "modules.graffiti: file is required"

            let rotation =
                match tryProp e "rotation" with
                | ValueNone -> Ok Rotation.Slot
                | ValueSome r when r.ValueKind = JsonValueKind.String ->
                    match r.GetString() with
                    | "slot" -> Ok Rotation.Slot
                    | "random" -> Ok Rotation.Random
                    | other -> Error $"modules.graffiti: rotation '{other}' is not slot or random"
                | ValueSome _ -> Error "modules.graffiti: rotation must be slot or random"

            match file, rotation with
            | Ok f, Ok r -> Ok(ValueSome { File = f; Rotation = r })
            | _ ->
                Error
                    [
                        for x in [ file |> Result.map ignore; rotation |> Result.map ignore ] do
                            match x with
                            | Error m -> m
                            | Ok() -> ()
                    ]
        | errs -> Error errs

/// The largest graffiti file read, in bytes. Each line holds at most 32 bytes of text and a key,
/// so 1 MiB holds a text for over 5,000 keys; a larger file is a mistake (a wrong path, a log).
[<Literal>]
let MaxFileBytes = 1_048_576

let private readFile (path: string) : Result<byte[], string> =
    try
        use f = File.OpenRead path
        // Reads at most one byte past the limit, so a file that grows or reports no length (a
        // pipe, a device) cannot make the read take all memory.
        let buffer = Array.zeroCreate<byte>(MaxFileBytes + 1)
        let mutable n = 0
        let mutable reading = true

        while reading && n < buffer.Length do
            let r = f.Read(buffer, n, buffer.Length - n)
            if r = 0 then reading <- false else n <- n + r

        if n > MaxFileBytes then Error $"the file is over {MaxFileBytes} bytes" else Ok(Array.sub buffer 0 n)
    with
    | :? FileNotFoundException
    | :? DirectoryNotFoundException -> Error "the file does not exist"
    | :? IOException
    | :? UnauthorizedAccessException as e -> Error e.Message

let private parseBytes (bytes: byte[]) =
    try
        parse (UTF8Encoding(false, true).GetString bytes)
    with :? DecoderFallbackException ->
        Error [ "the file is not UTF-8" ]

/// The file at run time, as ProposerConfig.Watcher keeps the proposer config: the last good
/// content in place, swapped whole, and a reload only when the size or write time changed.
type Watcher(path: string, log: Log) =
    let mutable lastGood: byte[] = [||]

    [<VolatileField>]
    let mutable current = GraffitiFile.Empty

    let mutable errors = 0L
    /// Size and write time of the last good content's file, kept once the write time was 2 s
    /// old at the read (as the proposer config file does).
    let mutable stamp: struct (int64 * DateTime) voption = ValueNone

    let stat () =
        try
            let i = FileInfo path
            if i.Exists then ValueSome(struct (i.Length, i.LastWriteTimeUtc)) else ValueNone
        with
        | :? IOException
        | :? UnauthorizedAccessException -> ValueNone

    let settled (s: struct (int64 * DateTime) voption) (now: DateTime) =
        match s with
        | ValueSome(struct (_, written)) when now - written >= TimeSpan.FromSeconds 2.0 -> s
        | _ -> ValueNone

    let failed (message: string) =
        Interlocked.Increment &errors |> ignore
        log.Error message

    member _.Current = current
    member _.Errors = Interlocked.Read &errors

    /// The first read; an error fails the start.
    member _.Load() : Result<GraffitiFile, string> =
        let now = DateTime.UtcNow
        let s = stat ()

        match readFile path with
        | Error e -> Error $"graffiti file {path}: {e}"
        | Ok bytes ->
            match parseBytes bytes with
            | Error es -> Error $"""graffiti file {path}: {String.Join("; ", es)}"""
            | Ok f ->
                lastGood <- bytes
                current <- f
                stamp <- settled s now
                Ok f

    /// Reads the file again when its size or write time changed. True when new content is in place.
    member _.Reload() : bool =
        let now = DateTime.UtcNow
        let s = stat ()

        match s, stamp with
        | ValueSome a, ValueSome b when a = b -> false
        | _ ->
            match readFile path with
            | Error e ->
                failed $"graffiti file {path}: {e}; keeping the last good one"
                false
            | Ok bytes when bytes.AsSpan().SequenceEqual(ReadOnlySpan lastGood) ->
                stamp <- settled s now
                false
            | Ok bytes ->
                match parseBytes bytes with
                | Error es ->
                    failed $"""graffiti file {path}: {String.Join("; ", es)}; keeping the last good one"""
                    false
                | Ok f ->
                    lastGood <- bytes
                    current <- f
                    stamp <- settled s now
                    log.Info $"graffiti file {path} reloaded: {summary f}"
                    true

/// How long before each epoch boundary the file is checked.
let lead = TimeSpan.FromMilliseconds 500.0

/// Checks the file before each epoch boundary until `ct` fires; the read runs on a thread pool thread.
let refreshLoop (watcher: Watcher) (clock: SlotClock) (log: Log) (ct: CancellationToken) : Task =
    task {
        let time = clock.Time
        let epochTicks = clock.SlotDuration.Ticks * int64 clock.SlotsPerEpoch

        let nextBoundary (t: DateTimeOffset) =
            if t < clock.GenesisTime then
                clock.GenesisTime
            else
                let n = (t - clock.GenesisTime).Ticks / epochTicks + 1L
                clock.GenesisTime + TimeSpan.FromTicks(n * epochTicks)

        try
            while not ct.IsCancellationRequested do
                let boundary = nextBoundary (time.GetUtcNow() + lead)
                do! clock.WaitUntil(boundary - lead, ct)

                try
                    let! _ = Task.Run<bool>(fun () -> watcher.Reload())
                    ()
                with e ->
                    log.Error $"graffiti file check: {e.Message}"
        with :? OperationCanceledException ->
            ()
    }

let create () : Module =
    let settings: Settings voption ref = ref ValueNone
    let watcher: Watcher voption ref = ref ValueNone

    {
        Name = name
        Configure =
            fun section ->
                match parseSettings section with
                | Error e -> Error e
                | Ok ValueNone -> Ok()
                | Ok(ValueSome s) ->
                    settings.Value <- ValueSome s
                    // Read now, so a bad file fails the start before anything else runs.
                    let w = Watcher(s.File, Log.none)

                    match w.Load() with
                    | Ok _ -> Ok()
                    | Error e -> Error [ e ]
        Check =
            fun _ ->
                match settings.Value with
                | ValueNone -> Ok "off"
                | ValueSome s ->
                    match Watcher(s.File, Log.none).Load() with
                    | Ok f -> Ok $"{s.File}: {summary f}"
                    | Error e -> Error [ e ]
        Start =
            fun core _ ->
                task {
                    match settings.Value with
                    | ValueNone -> return Ok { Stop = fun () -> Task.CompletedTask }
                    | ValueSome s ->
                        let w = Watcher(s.File, core.Log)

                        match w.Load() with
                        | Error e -> return Error e
                        | Ok f ->
                            watcher.Value <- ValueSome w
                            core.Graffiti.SetSource(fun ctx -> pick s.Rotation w.Current ctx)

                            let rotation =
                                match s.Rotation with
                                | Rotation.Slot -> "slot"
                                | Rotation.Random -> "random"

                            core.Log.Info $"graffiti file {s.File}: {summary f}, rotation {rotation}"
                            let stop = CancellationTokenSource.CreateLinkedTokenSource core.Stopping
                            let run = refreshLoop w core.Clock core.Log stop.Token

                            return
                                Ok
                                    {
                                        Stop =
                                            fun () ->
                                                task {
                                                    stop.Cancel()
                                                    do! run
                                                    stop.Dispose()
                                                }
                                    }
                }
    }
