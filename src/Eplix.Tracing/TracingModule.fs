/// OpenTelemetry tracing as a module. Config section "tracing":
///   { "enabled": false, "endpoint": "http://127.0.0.1:4318/v1/traces", "sample_ratio": 1.0,
///     "sign_spans": false, "service_name": "eplix", "headers": { "Name": "value" },
///     "queue_size": 4096, "batch_size": 512, "flush_interval_ms": 2000, "timeout_ms": 5000 }
/// Off by default: without "enabled": true no listener exists, and the core's spans cost one
/// check each (Tracing.fs). On, an ActivityListener samples root spans by trace id, copies each
/// finished span into a bounded queue (a full queue drops the span, it never blocks a duty), and
/// a background task posts batches to an OTLP/HTTP collector as binary protobuf.
module Eplix.Tracing.TracingModule

open System
open System.Collections.Concurrent
open System.Diagnostics
open System.Net.Http
open System.Net.Http.Headers
open System.Reflection
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json
open Eplix.Tracing.Otlp

let name = "tracing"

type Settings =
    {
        Enabled: bool
        Endpoint: Uri
        SampleRatio: float
        SignSpans: bool
        ServiceName: string
        Headers: (string * string) list
        QueueSize: int
        BatchSize: int
        FlushInterval: TimeSpan
        Timeout: TimeSpan
    }

let defaults =
    {
        Enabled = false
        Endpoint = Uri "http://127.0.0.1:4318/v1/traces"
        SampleRatio = 1.0
        SignSpans = false
        ServiceName = "eplix"
        Headers = []
        QueueSize = 4096
        BatchSize = 512
        FlushInterval = TimeSpan.FromSeconds 2.0
        Timeout = TimeSpan.FromSeconds 5.0
    }

let parse (section: ConfigSection) : Result<Settings, string list> =
    let d = defaults

    match section.Element with
    | ValueNone -> Ok d
    | ValueSome e ->
        let fields =
            [
                "enabled"
                "endpoint"
                "sample_ratio"
                "sign_spans"
                "service_name"
                "headers"
                "queue_size"
                "batch_size"
                "flush_interval_ms"
                "timeout_ms"
            ]

        match checkFields e "modules.tracing" fields with
        | [] ->
            try
                let flag (n: string) (fallback: bool) =
                    match tryProp e n with
                    | ValueNone -> fallback
                    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
                    | ValueSome v when v.ValueKind = JsonValueKind.False -> false
                    | ValueSome _ -> fail $"{n} must be true or false"

                let int' (n: string) (lo: int) (hi: int) (fallback: int) =
                    match tryProp e n with
                    | ValueNone -> fallback
                    | ValueSome v -> boundedInt n lo hi v

                let ms (n: string) (lo: uint64) (hi: uint64) (fallback: float) =
                    match tryProp e n with
                    | ValueNone -> TimeSpan.FromMilliseconds fallback
                    | ValueSome v -> boundedMs n lo hi v

                let endpoint =
                    match tryProp e "endpoint" with
                    | ValueNone -> d.Endpoint
                    | ValueSome v ->
                        match Uri.TryCreate(str v, UriKind.Absolute) with
                        | true, NonNull u when
                            (u.Scheme = "http" || u.Scheme = "https") && String.IsNullOrEmpty u.UserInfo
                            ->
                            u
                        | _ ->
                            fail
                                "endpoint must be an http or https URL without user info (for example http://127.0.0.1:4318/v1/traces)"

                let ratio =
                    match tryProp e "sample_ratio" with
                    | ValueNone -> d.SampleRatio
                    | ValueSome v -> fraction "sample_ratio" v

                let headers =
                    match tryProp e "headers" with
                    | ValueNone -> []
                    | ValueSome h when h.ValueKind = JsonValueKind.Object ->
                        let hs = [ for p in h.EnumerateObject() -> p.Name, str p.Value ]

                        for n, v in hs do
                            match Headers.check n v with
                            | Ok() -> ()
                            | Error err -> fail err

                        if (hs |> List.distinctBy (fun (n, _) -> n.ToLowerInvariant())).Length <> hs.Length then
                            fail "a header name appears more than once"

                        hs
                    | ValueSome _ -> fail "headers must be an object of names and values"

                let serviceName =
                    match tryProp e "service_name" with
                    | ValueNone -> d.ServiceName
                    | ValueSome v ->
                        let s = str v

                        if s.Length = 0 then
                            fail "service_name must not be empty"

                        s

                let queueSize = int' "queue_size" 1 1_000_000 d.QueueSize
                let batchSize = int' "batch_size" 1 100_000 d.BatchSize

                if batchSize > queueSize then
                    fail "batch_size must not be above queue_size"

                Ok
                    {
                        Enabled = flag "enabled" d.Enabled
                        Endpoint = endpoint
                        SampleRatio = ratio
                        SignSpans = flag "sign_spans" d.SignSpans
                        ServiceName = serviceName
                        Headers = headers
                        QueueSize = queueSize
                        BatchSize = batchSize
                        FlushInterval = ms "flush_interval_ms" 10UL 600_000UL 2000.0
                        Timeout = ms "timeout_ms" 100UL 600_000UL 5000.0
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.tracing: {x.Message}" ]
        | errs -> Error errs

/// Whether a root span with this trace id is kept at this ratio: the trace id's last 8 bytes, as
/// a big-endian number, below ratio * 2^64 (the rule of OpenTelemetry's TraceIdRatioBased
/// sampler in its newer form, so every component that sees the trace id decides alike).
let keepTrace (ratio: float) (traceId: ReadOnlySpan<byte>) =
    if ratio >= 1.0 then
        true
    elif ratio <= 0.0 then
        false
    else
        let x = Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(traceId.Slice(8, 8))
        float x < ratio * 18446744073709551616.0

/// The sampling decision. A span with a parent follows the parent: recorded when the parent is,
/// else not created at all. A root span is recorded when its trace id passes the ratio; one that
/// does not is created unrecorded (PropagationData), so its children see a parent that says no
/// and are not sampled as roots of their own.
let sample (ratio: float) (options: inref<ActivityCreationOptions<ActivityContext>>) : ActivitySamplingResult =
    let parent = options.Parent

    if parent.TraceId <> Unchecked.defaultof<ActivityTraceId> then
        if parent.TraceFlags.HasFlag ActivityTraceFlags.Recorded then
            ActivitySamplingResult.AllDataAndRecorded
        else
            ActivitySamplingResult.None
    else
        let id = options.TraceId
        let b = Array.zeroCreate<byte> 16
        id.CopyTo(Span b)

        if keepTrace ratio (ReadOnlySpan b) then
            ActivitySamplingResult.AllDataAndRecorded
        else
            ActivitySamplingResult.PropagationData

let private unixNanos (t: DateTime) = uint64 (t.Ticks - DateTime.UnixEpoch.Ticks) * 100UL

let private attr (v: objnull) : AttrValue voption =
    match v with
    | :? string as s -> ValueSome(AttrValue.Text s)
    | :? bool as b -> ValueSome(AttrValue.Bool b)
    | :? int as i -> ValueSome(AttrValue.Int(int64 i))
    | :? int64 as i -> ValueSome(AttrValue.Int i)
    | :? uint64 as u ->
        ValueSome(if u <= uint64 Int64.MaxValue then AttrValue.Int(int64 u) else AttrValue.Text(string u))
    | :? uint32 as u -> ValueSome(AttrValue.Int(int64 u))
    | :? float as d -> ValueSome(AttrValue.Double d)
    | null -> ValueNone
    | o -> ValueSome(AttrValue.Text(string o))

/// Copies a stopped Activity into a SpanData.
let ofActivity (a: Activity) : SpanData =
    let trace = Array.zeroCreate<byte> 16
    a.TraceId.CopyTo(Span trace)
    let id = Array.zeroCreate<byte> 8
    a.SpanId.CopyTo(Span id)

    let parent =
        if a.ParentSpanId = Unchecked.defaultof<ActivitySpanId> then
            [||]
        else
            let p = Array.zeroCreate<byte> 8
            a.ParentSpanId.CopyTo(Span p)
            p

    let start = unixNanos a.StartTimeUtc

    {
        Scope = a.Source.Name
        TraceId = trace
        SpanId = id
        ParentSpanId = parent
        Name = a.DisplayName
        Kind =
            match a.Kind with
            | ActivityKind.Server -> 2
            | ActivityKind.Client -> 3
            | ActivityKind.Producer -> 4
            | ActivityKind.Consumer -> 5
            | _ -> 1
        StartUnixNano = start
        EndUnixNano = start + uint64 a.Duration.Ticks * 100UL
        Attributes =
            [|
                for KeyValue(k, v) in a.TagObjects do
                    match attr v with
                    | ValueSome x -> k, x
                    | ValueNone -> ()
            |]
        StatusCode =
            match a.Status with
            | ActivityStatusCode.Ok -> 1
            | ActivityStatusCode.Error -> 2
            | _ -> 0
        StatusMessage = defaultArg (Option.ofObj a.StatusDescription) ""
    }

let private exported =
    Metrics.meter.CreateCounter<int64>(
        "eplix_tracing_spans_exported",
        description = "Spans the OTLP collector accepted"
    )

let private dropped =
    Metrics.meter.CreateCounter<int64>(
        "eplix_tracing_spans_dropped",
        description = "Spans not exported, by reason (queue_full, export_failed, rejected)"
    )

let private droppedFor (reason: string) (n: int64) =
    if n > 0L then
        dropped.Add(n, Collections.Generic.KeyValuePair<string, objnull>("reason", box reason))

/// The queue and the export loop. Enqueue never blocks: past `QueueSize` spans waiting, a new
/// span is dropped and counted.
type Exporter(s: Settings, http: HttpClient, log: Log, resource: (string * AttrValue)[], scopeVersion: string) =
    let queue = ConcurrentQueue<SpanData>()
    let count = ref 0
    let signal = new SemaphoreSlim(0)
    let mutable failing = false

    let post (batch: SpanData[]) (ct: CancellationToken) =
        task {
            let body = encodeRequest resource scopeVersion batch
            use req = new HttpRequestMessage(HttpMethod.Post, s.Endpoint)

            for k, v in s.Headers do
                req.Headers.TryAddWithoutValidation(k, v) |> ignore

            let content = new ByteArrayContent(body)
            content.Headers.ContentType <- MediaTypeHeaderValue "application/x-protobuf"
            req.Content <- content
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct
            cts.CancelAfter s.Timeout

            try
                use! resp = http.SendAsync(req, cts.Token)
                let! answer = resp.Content.ReadAsByteArrayAsync(cts.Token)

                if resp.IsSuccessStatusCode then
                    let rejected = rejectedSpans answer
                    exported.Add(int64 batch.Length - rejected)
                    droppedFor "rejected" rejected

                    if failing then
                        log.Info
                            $"tracing: the collector at {s.Endpoint.GetLeftPart UriPartial.Authority} accepts spans again"

                    failing <- false
                else
                    droppedFor "export_failed" (int64 batch.Length)

                    if not failing then
                        log.Warn
                            $"tracing: the collector answered HTTP {int resp.StatusCode}; {batch.Length} spans dropped"

                    failing <- true
            with e ->
                droppedFor "export_failed" (int64 batch.Length)

                if not failing && not ct.IsCancellationRequested then
                    log.Warn
                        $"tracing: export to {s.Endpoint.GetLeftPart UriPartial.Authority} failed: {e.Message}; {batch.Length} spans dropped"

                failing <- true
        }

    let take () =
        let batch = Collections.Generic.List<SpanData>(min s.BatchSize (max 1 count.Value))
        let mutable x = Unchecked.defaultof<SpanData>

        while batch.Count < s.BatchSize && queue.TryDequeue(&x) do
            Interlocked.Decrement(&count.contents) |> ignore
            batch.Add x

        batch.ToArray()

    /// Spans waiting to be sent.
    member _.Pending = count.Value

    member _.Enqueue(span: SpanData) =
        if Interlocked.Increment(&count.contents) > s.QueueSize then
            Interlocked.Decrement(&count.contents) |> ignore
            droppedFor "queue_full" 1L
        else
            queue.Enqueue span

            if count.Value = s.BatchSize then
                signal.Release() |> ignore

    /// Sends what is queued, batch by batch.
    member _.Flush(ct: CancellationToken) : Task =
        task {
            let mutable batch = take ()

            while batch.Length > 0 && not ct.IsCancellationRequested do
                do! post batch ct
                batch <- take ()
        }

    /// Sends a batch when one is full or every flush interval, until ct fires.
    member this.Run(ct: CancellationToken) : Task =
        task {
            try
                while not ct.IsCancellationRequested do
                    let! _ = signal.WaitAsync(s.FlushInterval, ct)
                    do! this.Flush ct
            with :? OperationCanceledException ->
                ()
        }

/// The most the VC reads of a collector's answer. A partial success answer with its message is
/// a few hundred bytes; a longer one fails the export.
[<Literal>]
let MaxAnswer = 16384

/// The HTTP client of the exporter: keep-alive connections, no redirect (span batches go only
/// to the configured collector), and a small cap on the answer.
let createHttp () =
    let handler =
        new SocketsHttpHandler(PooledConnectionLifetime = TimeSpan.FromMinutes 5.0, AllowAutoRedirect = false)

    new HttpClient(handler, true, MaxResponseContentBufferSize = int64 MaxAnswer)

let private version =
    match typeof<KeyRegistry>.Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>() with
    | null -> "unknown"
    | a -> a.InformationalVersion

/// The listener: the core's span sources (the per-request one only with sign_spans), the sampler,
/// and each recorded span into the exporter when it stops.
let listen (s: Settings) (exporter: Exporter) : ActivityListener =
    let l = new ActivityListener()
    l.ShouldListenTo <- fun src -> src.Name = Tracing.SourceName || (s.SignSpans && src.Name = Tracing.SignSourceName)
    let ratio = s.SampleRatio
    l.Sample <- SampleActivity<ActivityContext>(fun options -> sample ratio &options)

    l.ActivityStopped <-
        fun a ->
            if a.Recorded then
                exporter.Enqueue(ofActivity a)

    ActivitySource.AddActivityListener l
    l

let create () : Module =
    let settings = ref defaults

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun _ ->
                let s = settings.Value

                if s.Enabled then
                    let spans = if s.SignSpans then ", a span per signing request" else ""

                    Ok
                        $"spans to {s.Endpoint.GetLeftPart UriPartial.Path} (OTLP/HTTP protobuf), sample ratio {s.SampleRatio}{spans}"
                else
                    Ok "off"
        Start =
            fun core _ ->
                task {
                    let s = settings.Value

                    if not s.Enabled then
                        return Ok { Stop = fun () -> Task.CompletedTask }
                    else
                        let http = createHttp ()

                        let resource =
                            [|
                                "service.name", AttrValue.Text s.ServiceName
                                "service.version", AttrValue.Text version
                                "telemetry.sdk.name", AttrValue.Text "eplix"
                                "telemetry.sdk.language", AttrValue.Text "dotnet"
                            |]

                        let exporter = Exporter(s, http, core.Log, resource, version)
                        let listener = listen s exporter
                        let cts = new CancellationTokenSource()
                        let loop = exporter.Run cts.Token
                        let signSpans = if s.SignSpans then ", a span per signing request" else ""

                        core.Log.Info
                            $"tracing: spans to {s.Endpoint.GetLeftPart UriPartial.Path}, sample ratio {s.SampleRatio}{signSpans}"

                        return
                            Ok
                                {
                                    Stop =
                                        fun () ->
                                            task {
                                                listener.Dispose()
                                                // What is queued goes out once, within the request timeout.
                                                use last = new CancellationTokenSource(s.Timeout)
                                                do! exporter.Flush last.Token
                                                cts.Cancel()
                                                do! loop
                                                http.Dispose()
                                            }
                                            :> Task
                                }
                }
    }
