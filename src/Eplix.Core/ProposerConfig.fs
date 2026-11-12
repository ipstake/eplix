/// The operator's proposer config file: fee recipient, gas limit, graffiti and the pre-Gloas
/// builder flow as defaults and per key, in Teku's layout:
///   { "default_config": { "fee_recipient": "0x..", "gas_limit": "60000000", "graffiti": "...",
///       "builder": { "enabled": true, "boost_factor": "100" } },
///     "proposer_config": { "0x<pubkey>": { "fee_recipient": "0x..", "builder": { "enabled": false } } } }
/// `builder.gas_limit` (Teku's place for it) is the same setting as `gas_limit`. Strict: an
/// unknown field fails.
/// The VC reads the file at start (an invalid file fails the start) and again each epoch.
module Eplix.ProposerConfig

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix.Json

let private entryFields = [ "fee_recipient"; "gas_limit"; "graffiti"; "builder" ]
let private builderFields = [ "enabled"; "gas_limit"; "boost_factor" ]

let private entry (where: string) (e: JsonElement) (errors: ResizeArray<string>) : KeySettings =
    if e.ValueKind <> JsonValueKind.Object then
        errors.Add $"{where} must be an object"
        KeySettings.Default
    else
        for p in e.EnumerateObject() do
            if not (List.contains p.Name entryFields) then
                errors.Add $"{where}: unknown field '{p.Name}'"

        let fieldOf (at: string) (o: JsonElement) name (f: JsonElement -> 'T) : 'T voption =
            match tryProp o name with
            | ValueNone -> ValueNone
            | ValueSome v ->
                try
                    ValueSome(f v)
                with :? JsonDecodeError as x ->
                    errors.Add $"{at}.{name}: {x.Message}"
                    ValueNone

        let field name f = fieldOf where e name f

        let gasLimit (v: JsonElement) =
            let g = u64 v

            if g = 0UL then
                fail "must be above 0"

            g
        // Teku's builder block: enabled and gas_limit; boost_factor is produceBlockV3's
        // builder_boost_factor.
        let builderAt = $"{where}.builder"

        let builder =
            match tryProp e "builder" with
            | ValueNone -> ValueNone
            | ValueSome b when b.ValueKind <> JsonValueKind.Object ->
                errors.Add $"{builderAt} must be an object"
                ValueNone
            | ValueSome b ->
                for p in b.EnumerateObject() do
                    if not (List.contains p.Name builderFields) then
                        errors.Add $"{builderAt}: unknown field '{p.Name}'"

                ValueSome b

        let fromBuilder name f =
            match builder with
            | ValueSome b -> fieldOf builderAt b name f
            | ValueNone -> ValueNone

        let topGas = field "gas_limit" gasLimit
        let builderGas = fromBuilder "gas_limit" gasLimit

        if topGas.IsSome && builderGas.IsSome then
            errors.Add $"{where}: gas_limit is set both at the top and in builder; keep one"

        {
            FeeRecipient =
                field "fee_recipient" (fun v ->
                    match Hex.tryDecodeFixed 20 (str v) with
                    | ValueSome b -> Hex.encodeArray b
                    | ValueNone -> fail "must be a 20-byte 0x-hex address")
            GasLimit = (if topGas.IsSome then topGas else builderGas)
            Graffiti =
                field "graffiti" (fun v ->
                    let g = str v

                    if Encoding.UTF8.GetByteCount g > 32 then
                        fail "must be at most 32 bytes of UTF-8"

                    g)
            BuilderEnabled =
                fromBuilder "enabled" (fun v ->
                    match v.ValueKind with
                    | JsonValueKind.True -> true
                    | JsonValueKind.False -> false
                    | _ -> fail "must be true or false")
            BuilderBoostFactor = fromBuilder "boost_factor" u64
        }

/// Parses the file's bytes. Collects every error.
let parse (bytes: byte[]) : Result<ProposerFile, string list> =
    // JsonDocument throws InvalidOperationException on invalid UTF-8 inside a string.
    if not (Unicode.Utf8.IsValid(ReadOnlySpan bytes)) then
        Error [ "not valid UTF-8" ]
    else
        try
            use doc =
                JsonDocument.Parse(
                    ReadOnlyMemory bytes,
                    JsonDocumentOptions(CommentHandling = JsonCommentHandling.Skip)
                )

            let root = doc.RootElement

            let errors =
                ResizeArray<string>(checkFields root "proposer config" [ "default_config"; "proposer_config" ])

            let defaults =
                match tryProp root "default_config" with
                | ValueSome d -> entry "default_config" d errors
                | ValueNone -> KeySettings.Default

            let mutable keys = Map.empty

            match tryProp root "proposer_config" with
            | ValueNone -> ()
            | ValueSome pc when pc.ValueKind <> JsonValueKind.Object -> errors.Add "proposer_config must be an object"
            | ValueSome pc ->
                for p in pc.EnumerateObject() do
                    let where = $"proposer_config.{p.Name}"

                    match PubKey.TryParse p.Name with
                    | ValueNone -> errors.Add $"{where}: '{p.Name}' is not a 48-byte 0x-hex public key"
                    | ValueSome pk when keys.ContainsKey pk -> errors.Add $"{where}: the key is listed twice"
                    | ValueSome pk -> keys <- keys.Add(pk, entry where p.Value errors)

            if errors.Count > 0 then Error(List.ofSeq errors) else Ok { Defaults = defaults; Keys = keys }
        with :? JsonException as e ->
            Error [ $"not valid JSON: {e.Message}" ]

let private read (path: string) : Result<byte[], string> =
    try
        Ok(File.ReadAllBytes path)
    with
    | :? IOException as e -> Error e.Message
    | :? UnauthorizedAccessException as e -> Error e.Message

/// Reads and parses the file. Errors name the file.
let load (path: string) : Result<ProposerFile, string> =
    match read path |> Result.mapError List.singleton |> Result.bind parse with
    | Ok f -> Ok f
    | Error es -> Error $"""proposer config {path}: {String.Join("; ", es)}"""

/// One line for logs and `eplix check`: the number of keys and the defaults.
let summary (f: ProposerFile) : string =
    let d = f.Defaults
    let fee = defaultValueArg d.FeeRecipient "not set"

    let gas =
        match d.GasLimit with
        | ValueSome g -> g.ToString(Globalization.CultureInfo.InvariantCulture)
        | ValueNone -> "not set"

    let graffiti =
        match d.Graffiti with
        | ValueSome g -> "\"" + g + "\""
        | ValueNone -> "not set"

    $"{f.Keys.Count} keys; defaults: fee recipient {fee}, gas limit {gas}, graffiti {graffiti}"

/// The file at run time: read at start, read again on each Reload. A file that fails to read or
/// parse keeps the last good content, logs an error and counts it, each epoch until it is fixed.
/// One caller at a time for Load and Reload (the start, then the Refresher); `Current` may be
/// read from any thread.
type Watcher(path: string, log: Log) =
    let mutable lastGood: byte[] = [||]

    /// The parsed content in place, swapped whole: a reader sees the old or the new file.
    [<VolatileField>]
    let mutable current = ProposerFile.Empty

    let mutable errors = 0L
    /// Size and write time of the last good content's file, kept only once the write time was
    /// 2 s old at the read. A newer write in the same timestamp tick with the same size would
    /// leave both as they were; 2 s covers the coarsest file system timestamps (FAT).
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
        Metrics.proposerConfigErrors.Add 1L
        log.Error message

    member _.Path = path
    member _.Current = current
    /// Reloads that failed to read or parse, since the start.
    member _.Errors = Interlocked.Read &errors

    /// The first read. An error here fails the start: a wrong fee recipient loses rewards.
    member _.Load() : Result<ProposerFile, string> =
        let now = DateTime.UtcNow
        let s = stat ()

        match read path with
        | Error e -> Error $"proposer config {path}: {e}"
        | Ok bytes ->
            match parse bytes with
            | Error es -> Error $"""proposer config {path}: {String.Join("; ", es)}"""
            | Ok f ->
                lastGood <- bytes
                current <- f
                stamp <- settled s now
                Ok f

    /// Reads the file again when its size or write time changed, or its last stamp was too
    /// recent to trust. Returns the new content when the bytes changed and parse.
    member _.Reload() : ProposerFile voption =
        let now = DateTime.UtcNow
        let s = stat ()

        match s, stamp with
        | ValueSome a, ValueSome b when a = b -> ValueNone
        | _ ->
            match read path with
            | Error e ->
                failed $"proposer config {path}: {e}; keeping the last good one"
                ValueNone
            | Ok bytes when bytes.AsSpan().SequenceEqual(ReadOnlySpan lastGood) ->
                stamp <- settled s now
                ValueNone
            | Ok bytes ->
                match parse bytes with
                | Error es ->
                    failed $"""proposer config {path}: {String.Join("; ", es)}; keeping the last good one"""
                    ValueNone
                | Ok f ->
                    lastGood <- bytes
                    current <- f
                    stamp <- settled s now
                    log.Info $"proposer config {path} reloaded: {summary f}"
                    ValueSome f

/// Checks the file once before each epoch boundary, off the duty path. A background task wakes
/// `lead` before the boundary, runs `check` (Watcher.Reload: the size and write time, then a read
/// and parse only on a change) on a thread pool thread, and hands the result to `apply`. Duties
/// read the content in place and never wait for a check. A check that ends after its boundary
/// applies its result when it ends and counts as late.
type Refresher
    (
        check: unit -> ProposerFile voption,
        clock: SlotClock,
        lead: TimeSpan,
        apply: ProposerFile voption -> unit,
        log: Log
    ) =
    let time = clock.Time
    let epochTicks = clock.SlotDuration.Ticks * int64 clock.SlotsPerEpoch
    let mutable late = 0L
    let mutable checks = 0L

    /// The first epoch boundary after `t`.
    let nextBoundary (t: DateTimeOffset) =
        if t < clock.GenesisTime then
            clock.GenesisTime
        else
            let n = (t - clock.GenesisTime).Ticks / epochTicks + 1L
            clock.GenesisTime + TimeSpan.FromTicks(n * epochTicks)

    /// Checks that ended after their epoch boundary, since the start.
    member _.Late = Interlocked.Read &late
    /// Checks that ended, since the start.
    member _.Checks = Interlocked.Read &checks

    /// One check for the epoch that starts at `boundary`.
    member _.Check(boundary: DateTimeOffset) : Task =
        task {
            let started = time.GetTimestamp()

            try
                let! changed = Task.Run<ProposerFile voption>(fun () -> check ())
                apply changed
            with e ->
                log.Error $"proposer config check: {e.Message}"

            Metrics.proposerConfigCheckDuration.Record((time.GetElapsedTime started).TotalSeconds)
            let over = time.GetUtcNow() - boundary

            if over > TimeSpan.Zero then
                Interlocked.Increment &late |> ignore
                Metrics.proposerConfigLate.Add 1L

                log.Warn
                    $"proposer config: the check for the epoch starting {boundary:u} ended {over.TotalMilliseconds:F0} ms after it; duties used the content in place until then"

            Interlocked.Increment &checks |> ignore
        }

    /// Runs one check before each epoch boundary until `ct` is cancelled.
    member this.Run(ct: CancellationToken) : Task =
        task {
            try
                while not ct.IsCancellationRequested do
                    let boundary = nextBoundary (time.GetUtcNow() + lead)
                    do! clock.WaitUntil(boundary - lead, ct)
                    do! this.Check boundary
            with :? OperationCanceledException ->
                ()
        }
