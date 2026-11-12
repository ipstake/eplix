/// OpenTelemetry tracing: the OTLP encoding, the sampler, the
/// exporter against a fake collector, and the whole VC's spans.
module Eplix.Tests.TracingTests

open System
open System.Collections.Concurrent
open System.Diagnostics
open System.IO
open System.Net
open System.Net.Sockets
open System.Text
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Tracing
open Eplix.Tracing.Otlp
open Eplix.Tests.TestUtil
open Eplix.Tests.SchedulerTests

// ---- A protobuf reader, written apart from the encoder, for the checks. ----

type private Field =
    | Varint of int * uint64
    | Fixed64 of int * uint64
    | Bytes of int * byte[]
    | Fixed32 of int * uint32

let private readFields (b: byte[]) : Field list =
    let mutable i = 0

    let varint () =
        let mutable v = 0UL
        let mutable shift = 0
        let mutable go = true

        while go do
            let x = b[i]
            i <- i + 1
            v <- v ||| (uint64 (x &&& 0x7Fuy) <<< shift)
            shift <- shift + 7
            go <- x &&& 0x80uy <> 0uy

        v

    [
        while i < b.Length do
            let tag = varint ()
            let f = int (tag >>> 3)

            match int (tag &&& 7UL) with
            | 0 -> Varint(f, varint ())
            | 1 ->
                let v = BitConverter.ToUInt64(b, i)
                i <- i + 8
                Fixed64(f, v)
            | 5 ->
                let v = BitConverter.ToUInt32(b, i)
                i <- i + 4
                Fixed32(f, v)
            | 2 ->
                let n = int (varint ())
                let v = b[i .. i + n - 1]
                i <- i + n
                Bytes(f, v)
            | w -> failwithf "wire type %d" w
    ]

let private bytesOf f fields =
    [
        for x in fields do
            match x with
            | Bytes(n, v) when n = f -> v
            | _ -> ()
    ]

let private varintOf f fields =
    fields
    |> List.tryPick (fun x ->
        match x with
        | Varint(n, v) when n = f -> Some v
        | _ -> None)

let private fixed64Of f fields =
    fields
    |> List.pick (fun x ->
        match x with
        | Fixed64(n, v) when n = f -> Some v
        | _ -> None)

let private textOf f fields = bytesOf f fields |> List.tryHead |> Option.map Encoding.UTF8.GetString

let private decodeAttr (kv: byte[]) =
    let f = readFields kv
    let key = (textOf 1 f).Value
    let any = readFields (bytesOf 2 f).Head

    let value =
        match any with
        | [ Bytes(1, s) ] -> AttrValue.Text(Encoding.UTF8.GetString s)
        | [] -> AttrValue.Text ""
        | [ Varint(2, v) ] -> AttrValue.Bool(v <> 0UL)
        | [ Varint(3, v) ] -> AttrValue.Int(int64 v)
        | [ Fixed64(4, v) ] -> AttrValue.Double(BitConverter.Int64BitsToDouble(int64 v))
        | other -> failwithf "AnyValue %A" other

    key, value

let private decodeSpan (scope: string) (b: byte[]) : SpanData =
    let f = readFields b
    let status = bytesOf 15 f |> List.tryHead |> Option.map readFields |> Option.defaultValue []

    {
        Scope = scope
        TraceId = (bytesOf 1 f).Head
        SpanId = (bytesOf 2 f).Head
        ParentSpanId = bytesOf 4 f |> List.tryHead |> Option.defaultValue [||]
        Name = defaultArg (textOf 5 f) ""
        Kind = varintOf 6 f |> Option.map int |> Option.defaultValue 0
        StartUnixNano = fixed64Of 7 f
        EndUnixNano = fixed64Of 8 f
        Attributes = bytesOf 9 f |> List.map decodeAttr |> Array.ofList
        StatusCode = varintOf 3 status |> Option.map int |> Option.defaultValue 0
        StatusMessage = defaultArg (textOf 2 status) ""
    }

/// The resource attributes and every span of an ExportTraceServiceRequest.
let private decodeRequest (body: byte[]) =
    let rs = readFields (bytesOf 1 (readFields body)).Head
    let resource = readFields (bytesOf 1 rs).Head |> bytesOf 1 |> List.map decodeAttr

    let spans =
        [
            for ss in bytesOf 2 rs do
                let f = readFields ss
                let scope = (textOf 1 (readFields (bytesOf 1 f).Head)).Value

                for sp in bytesOf 2 f do
                    decodeSpan scope sp
        ]

    resource, spans

// ---- A fake OTLP/HTTP collector on loopback. ----

type private Collector() =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let bodies = ConcurrentQueue<byte[]>()
    let heads = ConcurrentQueue<string>()
    let cts = new CancellationTokenSource()
    let mutable status = 200
    let mutable answer: byte[] = [||]
    do listener.Start()

    let handle (client: TcpClient) =
        task {
            use client = client
            use s = client.GetStream()
            let buf = Array.zeroCreate<byte> 65536
            let acc = new MemoryStream()
            let mutable headEnd = -1

            while headEnd < 0 do
                let! n = s.ReadAsync(buf, 0, buf.Length)

                if n = 0 then
                    failwith "closed"

                acc.Write(buf, 0, n)
                let text = Encoding.ASCII.GetString(acc.ToArray())
                headEnd <- text.IndexOf "\r\n\r\n"

            let all = acc.ToArray()
            let head = Encoding.ASCII.GetString(all, 0, headEnd)

            let length =
                head.Split("\r\n")
                |> Array.pick (fun l ->
                    if l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) then
                        Some(int (l.Substring(15).Trim()))
                    else
                        None)

            let body = new MemoryStream()
            body.Write(all, headEnd + 4, all.Length - headEnd - 4)

            while body.Length < int64 length do
                let! n = s.ReadAsync(buf, 0, buf.Length)

                if n = 0 then
                    failwith "closed"

                body.Write(buf, 0, n)

            heads.Enqueue head

            if status = 200 then
                bodies.Enqueue(body.ToArray())

            let reason = if status = 200 then "OK" else "Error"

            let h =
                $"HTTP/1.1 {status} {reason}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {answer.Length}\r\nConnection: close\r\n\r\n"

            do! s.WriteAsync(ReadOnlyMemory(Encoding.ASCII.GetBytes h))
            do! s.WriteAsync(ReadOnlyMemory answer)
        }

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! c = listener.AcceptTcpClientAsync cts.Token
                    handle c |> ignore
            with _ ->
                ()
        }

    member _.Url = Uri $"http://127.0.0.1:{(listener.LocalEndpoint :?> IPEndPoint).Port}/v1/traces"
    member _.Bodies = bodies
    member _.Heads = heads

    member _.Status
        with set v = status <- v

    member _.Answer
        with set v = answer <- v

    /// Every span received so far.
    member _.Spans =
        [
            for b in bodies do
                yield! snd (decodeRequest b)
        ]

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

let private settings (url: Uri) =
    { TracingModule.defaults with
        Enabled = true
        Endpoint = url
        FlushInterval = TimeSpan.FromMilliseconds 50.0
    }

let private resource = [| "service.name", AttrValue.Text "eplix-test" |]

/// Waits up to 10 s for a condition.
let private eventually (what: string) (f: unit -> bool) =
    task {
        let sw = Stopwatch.StartNew()

        while not (f ()) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
            do! Task.Delay 20

        Expect.isTrue (f ()) what
    }

/// Runs f with a listener and exporter on, then stops both.
let private withTracing (s: TracingModule.Settings) (f: TracingModule.Exporter -> Task<unit>) =
    task {
        use http = new Net.Http.HttpClient()
        let log, _ = Log.memory ()
        let exporter = TracingModule.Exporter(s, http, log, resource, "test")
        use cts = new CancellationTokenSource()
        let loop = exporter.Run cts.Token
        let listener = TracingModule.listen s exporter

        try
            do! f exporter
        finally
            listener.Dispose()
            cts.Cancel()

        do! loop
    }

// ---- Generators for the encoding property. ----

let private genBytes n = Gen.arrayOfLength n (Gen.choose (0, 255) |> Gen.map byte)

let private genText =
    ArbMap.defaults |> ArbMap.generate<string> |> Gen.map (fun s -> if isNull s then "" else s)

let private genAttr =
    Gen.oneof
        [
            genText |> Gen.map AttrValue.Text
            ArbMap.defaults |> ArbMap.generate<int64> |> Gen.map AttrValue.Int
            ArbMap.defaults |> ArbMap.generate<bool> |> Gen.map AttrValue.Bool
            ArbMap.defaults |> ArbMap.generate<NormalFloat> |> Gen.map (fun f -> AttrValue.Double f.Get)
        ]

let private genSpan =
    gen {
        let! scope = Gen.elements [ Tracing.SourceName; Tracing.SignSourceName; "other" ]
        let! trace = genBytes 16
        let! id = genBytes 8
        let! hasParent = ArbMap.defaults |> ArbMap.generate<bool>
        let! parent = genBytes 8
        let! name = genText
        let! kind = Gen.choose (0, 5)
        let! start = ArbMap.defaults |> ArbMap.generate<uint64>
        let! stop = ArbMap.defaults |> ArbMap.generate<uint64>
        let! attrs = Gen.listOf (Gen.zip genText genAttr)
        let! code = Gen.choose (0, 2)
        let! msg = genText

        return
            {
                Scope = scope
                TraceId = trace
                SpanId = id
                ParentSpanId = (if hasParent then parent else [||])
                Name = name
                Kind = kind
                StartUnixNano = start
                EndUnixNano = stop
                Attributes = Array.ofList attrs
                StatusCode = code
                StatusMessage = msg
            }
    }

let private sameSpans (a: SpanData list) (b: SpanData list) =
    // Records with arrays compare by reference; compare their contents instead.
    let key (s: SpanData) =
        s.Scope,
        List.ofArray s.TraceId,
        List.ofArray s.SpanId,
        List.ofArray s.ParentSpanId,
        s.Name,
        s.Kind,
        (s.StartUnixNano, s.EndUnixNano, List.ofArray s.Attributes, s.StatusCode, s.StatusMessage)

    List.map key a = List.map key b

let private section (json: string) : ConfigSection =
    {
        Element = ValueSome (Text.Json.JsonDocument.Parse json).RootElement
        BaseDir = "/"
        Mainnet = false
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "tracing"
        [
            test "config: defaults, every field, refusals" {
                Expect.equal
                    (TracingModule.parse
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok TracingModule.defaults)
                    "absent: defaults"

                Expect.isFalse TracingModule.defaults.Enabled "off by default"

                match
                    TracingModule.parse (
                        section
                            """{ "enabled": true, "endpoint": "https://otel.example:4318/v1/traces", "sample_ratio": 0.25, "sign_spans": true,
                               "service_name": "vc-1", "headers": { "Authorization": "Basic x" }, "queue_size": 100, "batch_size": 10,
                               "flush_interval_ms": 500, "timeout_ms": 1000 }"""
                    )
                with
                | Error es -> failtestf "%A" es
                | Ok s ->
                    Expect.isTrue s.Enabled "on"
                    Expect.equal s.Endpoint (Uri "https://otel.example:4318/v1/traces") "endpoint"
                    Expect.equal s.SampleRatio 0.25 "ratio"
                    Expect.isTrue s.SignSpans "sign spans"
                    Expect.equal s.ServiceName "vc-1" "service"
                    Expect.equal s.Headers [ "Authorization", "Basic x" ] "headers"
                    Expect.equal (s.QueueSize, s.BatchSize) (100, 10) "sizes"

                    Expect.equal
                        (s.FlushInterval, s.Timeout)
                        (TimeSpan.FromMilliseconds 500.0, TimeSpan.FromSeconds 1.0)
                        "times"

                let refused (json: string) (part: string) =
                    match TracingModule.parse (section json) with
                    | Ok _ -> failtestf "accepted %s" json
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"{part} in %A{es}"

                refused """{ "enabled": "yes" }""" "true or false"
                refused """{ "endpoint": "grpc://x:4317" }""" "http or https"
                refused """{ "endpoint": "http://u:p@x:4318/v1/traces" }""" "without user info"
                refused """{ "sample_ratio": 1.5 }""" "between 0 and 1"
                refused """{ "sample_ratio": "0.5" }""" "a number"
                refused """{ "headers": { "Bad Name": "x" } }""" "not an HTTP token"
                refused """{ "headers": { "X-A": "1", "x-a": "2" } }""" "more than once"
                refused """{ "queue_size": 0 }""" "between 1"
                refused """{ "queue_size": 10, "batch_size": 20 }""" "not be above"
                refused """{ "service_name": "" }""" "not be empty"
                refused """{ "exporter": "otlp" }""" "unknown field"
            }

            testPropN "the OTLP request decodes to the spans and resource it was made from" 300
            <| Prop.forAll
                (Arb.fromGen (Gen.zip (Gen.listOf genSpan) (Gen.listOf (Gen.zip genText genAttr))))
                (fun (spans, res) ->
                    let body = encodeRequest (Array.ofList res) "1.0" spans
                    let resource, decoded = decodeRequest body
                    let grouped = spans |> List.groupBy (fun s -> s.Scope) |> List.collect snd
                    resource = res && sameSpans decoded grouped)

            test "the request names each scope with its version, and the resource" {
                let s =
                    {
                        Scope = Tracing.SourceName
                        TraceId = Array.create 16 1uy
                        SpanId = Array.create 8 2uy
                        ParentSpanId = [||]
                        Name = "attestations"
                        Kind = 1
                        StartUnixNano = 1UL
                        EndUnixNano = 2UL
                        Attributes = [||]
                        StatusCode = 0
                        StatusMessage = ""
                    }

                let body = encodeRequest resource "9.9" [ s ]
                let rs = readFields (bytesOf 1 (readFields body)).Head
                let scope = readFields (bytesOf 1 (readFields (bytesOf 2 rs).Head)).Head
                Expect.equal (textOf 1 scope) (Some Tracing.SourceName) "scope name"
                Expect.equal (textOf 2 scope) (Some "9.9") "scope version"
                Expect.equal (fst (decodeRequest body)) [ "service.name", AttrValue.Text "eplix-test" ] "resource"
            }

            test "rejected spans come out of a partial success answer, and nothing else breaks it" {
                // partial_success { rejected_spans: 7, error_message: "x" }
                let partial = [| 0x08uy; 0x07uy; 0x12uy; 0x01uy; byte 'x' |]
                Expect.equal (rejectedSpans (Array.append [| 0x0Auy; byte partial.Length |] partial)) 7L "seven"
                Expect.equal (rejectedSpans [||]) 0L "empty answer"
                Expect.equal (rejectedSpans [| 0x0Auy; 0x50uy |]) 0L "truncated"
                Expect.equal (rejectedSpans (Encoding.ASCII.GetBytes "{\"partialSuccess\":{}}")) 0L "JSON"
            }

            test "the ratio sampler keeps all, none, or about that share of trace ids" {
                let rng = Random 7

                let ids =
                    Array.init 20000 (fun _ ->
                        let b = Array.zeroCreate<byte> 16 in
                        rng.NextBytes b
                        b)

                let share r =
                    float (ids |> Array.filter (fun b -> TracingModule.keepTrace r (ReadOnlySpan b)) |> Array.length)
                    / float ids.Length

                Expect.equal (share 1.0) 1.0 "all"
                Expect.equal (share 0.0) 0.0 "none"
                Expect.floatClose { absolute = 0.02; relative = 0.0 } (share 0.25) 0.25 "a quarter"
            }

            testProp "a trace kept at one ratio is kept at every higher ratio"
            <| Prop.forAll
                (Arb.fromGen (Gen.zip3 (genBytes 16) (Gen.choose (0, 1000)) (Gen.choose (0, 1000))))
                (fun (id, a, b) ->
                    let lo, hi = float (min a b) / 1000.0, float (max a b) / 1000.0
                    not (TracingModule.keepTrace lo (ReadOnlySpan id)) || TracingModule.keepTrace hi (ReadOnlySpan id))

            testT "spans reach the collector with their parent, kind, tags and status" (fun () ->
                task {
                    use collector = new Collector()

                    do!
                        withTracing (settings collector.Url) (fun _ ->
                            task {
                                let makeSpans () =
                                    use root = Tracing.duty "attestations" 17UL 3
                                    use child = Tracing.start "sign burst"
                                    Tracing.setInt child "eplix.requests" 3
                                    Tracing.fail child "two refused"

                                    match root with
                                    | null -> failtest "not sampled"
                                    | r -> r.TraceId.ToHexString()

                                let traceId = makeSpans ()

                                do!
                                    eventually "two spans exported" (fun () ->
                                        collector.Spans
                                        |> List.filter (fun s -> Convert.ToHexStringLower s.TraceId = traceId)
                                        |> List.length
                                            =
                                            2)

                                let spans =
                                    collector.Spans
                                    |> List.filter (fun s -> Convert.ToHexStringLower s.TraceId = traceId)

                                let root = spans |> List.find (fun s -> s.Name = "attestations")
                                let child = spans |> List.find (fun s -> s.Name = "sign burst")
                                Expect.equal root.ParentSpanId [||] "root has no parent"
                                Expect.equal child.ParentSpanId root.SpanId "child under the root"
                                Expect.equal root.Scope Tracing.SourceName "scope"
                                Expect.equal root.Kind 1 "internal"
                                Expect.contains root.Attributes ("eplix.slot", AttrValue.Int 17L) "slot tag"
                                Expect.contains root.Attributes ("eplix.duties", AttrValue.Int 3L) "count tag"
                                Expect.equal (child.StatusCode, child.StatusMessage) (2, "two refused") "error status"
                                Expect.isGreaterThanOrEqual child.EndUnixNano child.StartUnixNano "end after start"

                                Expect.isTrue
                                    (collector.Heads
                                     |> Seq.forall (fun h -> h.Contains "Content-Type: application/x-protobuf"))
                                    "protobuf"
                            })
                })

            testT "ratio 0: nothing is exported, children of an unsampled root included" (fun () ->
                task {
                    use collector = new Collector()

                    do!
                        withTracing
                            { settings collector.Url with
                                SampleRatio = 0.0
                            }
                            (fun _ ->
                                task {
                                    use root = Tracing.duty "attestations" 1UL 1
                                    Expect.isNotNull root "created for propagation"
                                    Expect.isFalse root.Recorded "not recorded"
                                    use child = Tracing.start "sign burst"
                                    Expect.isNull child "a child of an unsampled root is not created"
                                })

                    do! Task.Delay 200

                    Expect.isEmpty
                        (collector.Spans |> List.filter (fun s -> s.Name = "attestations" || s.Name = "sign burst"))
                        "none"
                })

            testT "sign spans only when asked" (fun () ->
                task {
                    use collector = new Collector()

                    do!
                        withTracing (settings collector.Url) (fun _ ->
                            task { Expect.isFalse (Tracing.signSource.HasListeners()) "per-request source off" })

                    do!
                        withTracing
                            { settings collector.Url with
                                SignSpans = true
                            }
                            (fun _ ->
                                task { Expect.isTrue (Tracing.signSource.HasListeners()) "per-request source on" })
                })

            testT "a full queue drops spans and never blocks; a collector that fails drops the batch" (fun () ->
                task {
                    use http = new Net.Http.HttpClient()
                    let log, lines = Log.memory ()
                    use collector = new Collector()

                    let s =
                        { settings collector.Url with
                            QueueSize = 3
                            BatchSize = 3
                        }

                    let exporter = TracingModule.Exporter(s, http, log, resource, "test")

                    let span name =
                        {
                            Scope = Tracing.SourceName
                            TraceId = Array.create 16 9uy
                            SpanId = Array.create 8 1uy
                            ParentSpanId = [||]
                            Name = name
                            Kind = 1
                            StartUnixNano = 1UL
                            EndUnixNano = 2UL
                            Attributes = [||]
                            StatusCode = 0
                            StatusMessage = ""
                        }

                    for i in 1..5 do
                        exporter.Enqueue(span $"s{i}")

                    Expect.equal exporter.Pending 3 "two dropped"
                    collector.Status <- 503
                    do! exporter.Flush CancellationToken.None
                    Expect.equal exporter.Pending 0 "batch taken"
                    Expect.isEmpty collector.Spans "collector refused"
                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "HTTP 503")) "one warning"
                    collector.Status <- 200
                    exporter.Enqueue(span "after")
                    do! exporter.Flush CancellationToken.None

                    Expect.equal
                        (collector.Spans |> List.map (fun s -> s.Name))
                        [ "after" ]
                        "sent once the collector answers"

                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "accepts spans again")) "recovery logged"
                })

            testT "a collector that is down costs a warning, not a failure" (fun () ->
                task {
                    use http = new Net.Http.HttpClient()
                    let log, lines = Log.memory ()

                    let port =
                        (let l = new TcpListener(IPAddress.Loopback, 0) in
                         l.Start()
                         let p = (l.LocalEndpoint :?> IPEndPoint).Port in
                         l.Stop()
                         p)

                    let s = settings (Uri $"http://127.0.0.1:{port}/v1/traces")
                    let exporter = TracingModule.Exporter(s, http, log, resource, "test")

                    exporter.Enqueue(
                        {
                            Scope = "x"
                            TraceId = Array.zeroCreate 16
                            SpanId = Array.zeroCreate 8
                            ParentSpanId = [||]
                            Name = "n"
                            Kind = 1
                            StartUnixNano = 0UL
                            EndUnixNano = 0UL
                            Attributes = [||]
                            StatusCode = 0
                            StatusMessage = ""
                        }
                    )

                    do! exporter.Flush CancellationToken.None
                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "export to")) "warned"
                })

            testT "the exporter's client follows no redirect and reads a small answer only" (fun () ->
                task {
                    use server = new RedirectServer()
                    use http = TracingModule.createHttp ()
                    use! resp = http.PostAsync(server.Url, new Net.Http.ByteArrayContent([| 1uy |]))
                    Expect.equal (int resp.StatusCode) 307 "the redirect comes back as it is"
                    Expect.equal server.Reached 0 "the batch did not reach the target"
                    use collector = new Collector()
                    collector.Answer <- Array.zeroCreate (1024 * 1024)

                    let! r =
                        task {
                            try
                                use! _ = http.PostAsync(collector.Url, new Net.Http.ByteArrayContent([| 1uy |]))
                                return "read"
                            with :? Net.Http.HttpRequestException as e ->
                                return e.Message
                        }

                    Expect.notEqual r "read" "a 1 MiB answer fails the export"
                })

            test "path templates hide numbers and 0x values" {
                Expect.equal
                    (Tracing.pathTemplate "/eth/v1/validator/duties/attester/12")
                    "/eth/v1/validator/duties/attester/{id}"
                    "epoch"

                Expect.equal
                    (Tracing.pathTemplate "/eth/v1/validator/attestation_data?slot=5&committee_index=0")
                    "/eth/v1/validator/attestation_data"
                    "query"

                Expect.equal
                    (Tracing.pathTemplate "/eth/v1/beacon/states/head/validators/0xabc")
                    "/eth/v1/beacon/states/head/validators/{id}"
                    "key"
            }

            testT "the module off: no listener, so the core's spans are never created" (fun () ->
                task {
                    let m = TracingModule.create ()

                    Expect.equal
                        (m.Configure
                            {
                                Element = ValueNone
                                BaseDir = "/"
                                Mainnet = false
                            })
                        (Ok())
                        "configured"

                    Expect.equal (m.Check Log.none) (Ok "off") "check says off"
                    Expect.isFalse (Tracing.source.HasListeners()) "no listener"
                    Expect.isNull (Tracing.duty "attestations" 1UL 1) "no span"
                })

            testT "the whole VC: duty spans with signing, slashing, beacon node and submit spans under them" (fun () ->
                task {
                    use collector = new Collector()
                    let h = harness ()
                    let dir = tempDir ()

                    for i in 0..1 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let! _, run, cts, lines =
                        MetricsTests.startVc
                            h
                            dir
                            [ 0; 1 ]
                            $$""", "tracing": { "enabled": true, "endpoint": "{{collector.Url}}", "flush_interval_ms": 50, "sign_spans": true }"""
                            [ LocalModule.create (); TracingModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch - 1))

                    do!
                        eventually "attestation spans" (fun () ->
                            collector.Spans |> List.exists (fun s -> s.Name = "attestations"))

                    cts.Cancel()
                    let! _ = run
                    let spans = collector.Spans
                    let att = spans |> List.find (fun s -> s.Name = "attestations")

                    let under (parent: SpanData) =
                        spans |> List.filter (fun s -> s.ParentSpanId = parent.SpanId && s.TraceId = parent.TraceId)

                    let names = under att |> List.map (fun s -> s.Name) |> Set.ofList
                    Expect.contains names "sign burst" $"children: %A{names}"
                    Expect.contains names "submit" $"children: %A{names}"
                    Expect.contains names "GET /eth/v1/validator/attestation_data" $"children: %A{names}"
                    let burst = under att |> List.find (fun s -> s.Name = "sign burst")
                    let burstChildren = under burst |> List.map (fun s -> s.Name)
                    Expect.contains burstChildren "slashing check" "slashing check under the burst"
                    let sign = under burst |> List.filter (fun s -> s.Name = "sign")
                    Expect.isNonEmpty sign "a sign span per request"
                    Expect.equal sign.Head.Scope Tracing.SignSourceName "own scope"
                    Expect.contains sign.Head.Attributes ("eplix.backend", AttrValue.Text "local") "backend"
                    Expect.contains sign.Head.Attributes ("eplix.outcome", AttrValue.Text "signed") "outcome"
                    let submit = under att |> List.find (fun s -> s.Name = "submit")
                    let post = under submit |> List.find (fun s -> s.Name = "POST /eth/v2/beacon/pool/attestations")
                    Expect.equal post.Kind 3 "client span"

                    Expect.contains
                        post.Attributes
                        ("eplix.node", AttrValue.Text "http://bn.test")
                        "node, by scheme, host and port"

                    Expect.contains post.Attributes ("http.response.status_code", AttrValue.Int 200L) "status"

                    Expect.isFalse
                        (lines |> Seq.exists (fun l -> l.Contains "tracing:" && l.Contains "failed"))
                        "no export error"
                })
        ]
