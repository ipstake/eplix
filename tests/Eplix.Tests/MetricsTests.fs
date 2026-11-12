/// The metrics module: the Prometheus text exporter on its own, and the endpoint against the whole VC.
module Eplix.Tests.MetricsTests

open System
open System.Collections.Generic
open System.Diagnostics.Metrics
open System.IO
open System.Net
open System.Net.Http
open System.Net.Sockets
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Metrics
open Eplix.Metrics.Prometheus
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let freePort () =
    let l = new TcpListener(IPAddress.Loopback, 0)
    l.Start()
    let p = (l.LocalEndpoint :?> IPEndPoint).Port
    l.Stop()
    p

let keystoreOf (i: int) (pw: string) =
    Keystore.encrypt (secretOf i) pw (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) $"m/12381/3600/{i}/0/0"

/// A whole VC on the fake node and clock: local keystores for `keys`, the given extra config
/// under "modules" and the given modules. Returns the services once ready, the run and its token source.
let startVc (h: Harness) (dir: string) (keys: int list) (extraModules: string) (modules: Module list) =
    task {
        let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

        for i in keys do
            File.WriteAllText(Path.Combine(ksDir, $"k{i}.json"), keystoreOf i "pw")

        File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
        let names = modules |> List.map (fun m -> m.Name)

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "allow_start_without_history": ["all"],
                 "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 }
                              {{extraModules}} } }"""

        match
            Config.parse configText dir names
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> return failtestf "%A" es
        | Ok config ->
            let cts = new CancellationTokenSource()
            let log, lines = Log.memory ()
            let ready = TaskCompletionSource<CoreServices>()

            let run =
                runSeededKeys
                    [ for i in keys -> pubkeyOf i ]
                    {
                        Config = config
                        Modules = modules
                        Http = new HttpClient(h.Node, false)
                        Time = h.Time
                        Log = log
                        OnSlotDone = h.Waiter.Done
                        OnReady = fun core _ -> ready.TrySetResult core |> ignore
                    }
                    cts.Token

            let! winner = Task.WhenAny(ready.Task :> Task, run :> Task, Task.Delay(TimeSpan.FromSeconds 20.0))

            if winner <> (ready.Task :> Task) then
                failtestf
                    "the VC did not start: %A\n%s"
                    (if run.IsCompleted then box run.Result else box "timeout")
                    (String.Join("\n", lines))

            return ready.Task.Result, run, cts, lines
    }

/// The value of one series line `name{labels} value` in exposition text, if present.
let seriesValue (text: string) (series: string) =
    text.Split('\n')
    |> Array.tryPick (fun l ->
        if l.StartsWith(series + " ") then Some(float (l.Substring(series.Length + 1))) else None)

[<Tests>]
let tests =
    testList
        "metrics"
        [
            test "counters, histograms and gauges in the text format" {
                use meter = new Meter($"Eplix.Test.{Guid.NewGuid():N}")
                use collector = new Collector([ meter.Name ])
                let c = meter.CreateCounter<int64>("test_requests", description = "Requests")

                let h =
                    meter.CreateHistogram<float>(
                        "test_duration_seconds",
                        unit = "s",
                        description = "Duration",
                        tags = null,
                        advice = InstrumentAdvice<float>(HistogramBucketBoundaries = [| 0.1; 1.0 |])
                    )

                let tag (k: string) (v: string) = KeyValuePair<string, obj>(k, box v)
                c.Add(2L, tag "b" "y", tag "a" "x")
                c.Add(1L, tag "a" "x", tag "b" "y")
                c.Add(5L, tag "a" "quote\"and\nline\\")
                h.Record(0.05, tag "kind" "k")
                h.Record(0.5, tag "kind" "k")
                h.Record(3.0, tag "kind" "k")
                h.Record(1.0, tag "kind" "k")

                let text =
                    collector.Render
                        [
                            {
                                Name = "test_gauge"
                                Help = "A gauge"
                                Samples =
                                    [
                                        {
                                            Labels = [ "state", "active" ]
                                            Value = 3.0
                                        }
                                    ]
                            }
                        ]

                let lines = text.Split('\n') |> Set.ofArray

                for expected in
                    [
                        "# HELP test_requests_total Requests"
                        "# TYPE test_requests_total counter"
                        """test_requests_total{a="x",b="y"} 3"""
                        """test_requests_total{a="quote\"and\nline\\"} 5"""
                        "# TYPE test_duration_seconds histogram"
                        """test_duration_seconds_bucket{kind="k",le="0.1"} 1"""
                        """test_duration_seconds_bucket{kind="k",le="1"} 3"""
                        """test_duration_seconds_bucket{kind="k",le="+Inf"} 4"""
                        """test_duration_seconds_sum{kind="k"} 4.55"""
                        """test_duration_seconds_count{kind="k"} 4"""
                        "# TYPE test_gauge gauge"
                        """test_gauge{state="active"} 3"""
                    ] do
                    Expect.isTrue (lines.Contains expected) $"missing line: {expected}\n{text}"

                Expect.isTrue (text.EndsWith "\n") "ends with a line feed"
            }

            test "signing latency: 10 ms steps where remote signers answer, the old bounds kept" {
                let b = Array.ofSeq Metrics.signingBuckets
                Expect.equal b (b |> Array.distinct |> Array.sort) "ascending, no repeats"

                for x in Metrics.latencyBuckets do
                    Expect.contains b x $"old bound {x} kept"

                for x in
                    [
                        0.01
                        0.02
                        0.03
                        0.04
                        0.05
                        0.06
                        0.075
                        0.1
                        0.125
                        0.15
                        0.2
                        0.25
                        0.4
                        0.6
                        1.0
                        2.5
                    ] do
                    Expect.contains b x $"bound {x}"

                use collector = new Collector([ Metrics.MeterName ])
                let backend = $"test-{Guid.NewGuid():N}"

                for s in [ 0.045; 0.045; 0.12; 0.7 ] do
                    Metrics.signed backend DutyKind.Attestation (Failed SignFailure.Timeout) s

                let text = collector.Render []

                let bucket le =
                    seriesValue
                        text
                        $"""eplix_signing_duration_seconds_bucket{{backend="{backend}",duty="attestation",le="{le}"}}"""

                Expect.equal (bucket "0.04") (Some 0.0) "45 ms is above 40 ms"
                Expect.equal (bucket "0.05") (Some 2.0) "45 ms is in the 50 ms bucket"
                Expect.equal (bucket "0.1") (Some 2.0) "120 ms is above 100 ms"
                Expect.equal (bucket "0.125") (Some 3.0) "120 ms is in the 125 ms bucket"
                Expect.equal (bucket "0.6") (Some 3.0) "700 ms is above 600 ms"
                Expect.equal (bucket "1") (Some 4.0) "700 ms is in the 1 s bucket"
                Expect.equal (bucket "+Inf") (Some 4.0) "all four"
                let lines = text.Split('\n') |> Array.filter (fun l -> l.Contains backend && l.Contains "_bucket")
                Expect.equal lines.Length (b.Length + 1) "one line per bound and +Inf"
            }

            test "a measurement finds its series without allocating" {
                use meter = new Meter($"Eplix.Test.{Guid.NewGuid():N}")
                use collector = new Collector([ meter.Name ])
                let c = meter.CreateCounter<int64>("test_alloc", description = "Allocation check")
                let h = meter.CreateHistogram<float>("test_alloc_seconds", unit = "s", description = "Allocation check")
                let tag (k: string) (v: string) = KeyValuePair<string, obj>(k, box v)
                let a, b, d = tag "backend" "local", tag "duty" "attestation", tag "outcome" "signed"

                let once () =
                    c.Add(1L, a, b, d)
                    c.Add(1L, d, a, b)
                    h.Record(0.001, a, b)
                    h.Record(0.002)

                once ()
                let before = GC.GetAllocatedBytesForCurrentThread()

                for _ in 1..10_000 do
                    once ()

                let allocated = GC.GetAllocatedBytesForCurrentThread() - before
                // With label arrays per call, each measurement allocated its label arrays, list and text: about
                // 40,000 measurements here would take megabytes. One object per measurement would be
                // at least 960 KB. The 64 KB bound leaves room for runtime work on this thread while
                // the rest of the suite runs in parallel (8 KB seen there).
                Expect.isLessThan allocated 65536L $"40,000 measurements allocated {allocated} B"
                let text = collector.Render []

                Expect.equal
                    (seriesValue text """test_alloc_total{backend="local",duty="attestation",outcome="signed"}""")
                    (Some 20002.0)
                    "one series for both tag orders"

                Expect.equal (seriesValue text "test_alloc_seconds_count") (Some 10001.0) "the series without labels"

                Expect.equal
                    (seriesValue text """test_alloc_seconds_count{backend="local",duty="attestation"}""")
                    (Some 10001.0)
                    "the histogram with labels"
            }

            test "label keys: order, values, more than four labels, other value types" {
                let kv (k: string) (v: obj) = KeyValuePair<string, objnull>(k, v)
                let key (tags: KeyValuePair<string, objnull>[]) = labelKey (ReadOnlySpan tags)

                Expect.equal
                    (key [| kv "b" "2"; kv "a" "1" |])
                    (key [| kv "a" "1"; kv "b" "2" |])
                    "order does not matter"

                Expect.notEqual
                    (key [| kv "a" "1"; kv "b" "2" |])
                    (key [| kv "a" "2"; kv "b" "1" |])
                    "values stay with their names"

                Expect.notEqual
                    (key [| kv "a" "1" |])
                    (key [| kv "a" "1"; kv "b" "" |])
                    "an empty value is still a label"

                Expect.notEqual (key [||]) (key [| kv "" "" |]) "no labels differ from one empty label"
                let five = [| for c in "edcba" -> kv (string c) (box (int c)) |]
                Expect.equal (key five) (key (Array.rev five)) "five labels, any order"

                Expect.notEqual
                    (key five)
                    (key (Array.append five.[0..3] [| kv "a" "x" |]))
                    "five labels, one value differs"

                Expect.equal (key [| kv "n" (box 7) |]) (key [| kv "n" "7" |]) "a number reads as its text"
                Expect.equal (key [| kv "n" null |]) (key [| kv "n" "" |]) "null reads as empty"
            }

            testProp
                "any label sets, in any order, sum into the series of their sorted labels"
                (fun (sets: (byte * byte * int) list) ->
                    use meter = new Meter($"Eplix.Test.{Guid.NewGuid():N}")
                    use collector = new Collector([ meter.Name ])
                    let c = meter.CreateCounter<int64>("test_prop", description = "Property")
                    let names = [| "a"; "b"; "c"; "d"; "e" |]
                    let expected = Dictionary<string, int64>()

                    for labels, values, n in sets do
                        // Up to five of the names, each with one of two values, in an order the bits pick.
                        let chosen =
                            [|
                                for i in 0..4 do
                                    if (labels >>> i) &&& 1uy = 1uy then
                                        names[i], (if (values >>> i) &&& 1uy = 1uy then "x" else "y")
                            |]

                        let ordered = if values &&& 0x80uy = 0uy then chosen else Array.rev chosen
                        let tags = ordered |> Array.map (fun (k, v) -> KeyValuePair<string, objnull>(k, box v))
                        let delta = int64 (abs (n % 1000))
                        c.Add(delta, ReadOnlySpan tags)
                        let series = "test_prop_total" + renderLabels chosen

                        expected[series] <-
                            (match expected.TryGetValue series with
                             | true, v -> v
                             | _ -> 0L)
                            + delta

                    let text = collector.Render []
                    let lines = text.Split('\n') |> Array.filter (fun l -> l.StartsWith "test_prop_total")

                    lines.Length = expected.Count
                    && expected |> Seq.forall (fun (KeyValue(series, v)) -> seriesValue text series = Some(float v)))

            test "gauges and observable instruments keep their last value" {
                use meter = new Meter($"Eplix.Test.{Guid.NewGuid():N}")
                use collector = new Collector([ meter.Name ])
                let tag (k: string) (v: string) = KeyValuePair<string, obj>(k, box v)
                let g = meter.CreateGauge<int64>("test_balance", unit = "Gwei", description = "A push gauge")
                g.Record(5L, tag "key" "a")
                g.Record(-3L, tag "key" "a")
                let total = ref 10L

                meter.CreateObservableCounter<int64>(
                    "test_seen",
                    (fun () -> total.Value),
                    description = "An observable counter"
                )
                |> ignore

                meter.CreateObservableGauge<float>("test_level", (fun () -> 0.5), description = "An observable gauge")
                |> ignore

                let first = collector.Render []
                total.Value <- 12L
                let lines = (collector.Render []).Split('\n') |> Set.ofArray

                for expected in
                    [
                        "# TYPE test_balance gauge"
                        """test_balance{key="a"} -3"""
                        "# TYPE test_seen_total counter"
                        "test_seen_total 12"
                        "# TYPE test_level gauge"
                        "test_level 0.5"
                    ] do
                    Expect.isTrue (lines.Contains expected) $"missing line: {expected}\n{first}"

                Expect.stringContains first "test_seen_total 10" "the first scrape reads the value then"
            }

            test "a TLS file's expiry loaded before the collector listens shows in the scrape" {
                // Modules load their TLS files at start, which can come before the metrics module's
                // collector exists (the keymanager's certificate was missing from the scrape).
                let notAfter = DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero)
                let name = $"tls_cert_{Guid.NewGuid():N}"
                Metrics.tlsNotAfter "test-early" name notAfter
                use collector = new Collector([ Metrics.MeterName ])
                let lines = (collector.Render []).Split('\n') |> Set.ofArray

                let want =
                    $"""eplix_tls_cert_not_after_seconds{{name="{name}",use="test-early"}} {notAfter.ToUnixTimeSeconds()}"""

                Expect.isTrue (lines.Contains want) $"missing line: {want}"
            }

            test "a disposed collector stops listening" {
                use meter = new Meter($"Eplix.Test.{Guid.NewGuid():N}")
                let collector = new Collector([ meter.Name ])
                let c = meter.CreateCounter<int64>("test_after")
                c.Add 1L
                (collector :> IDisposable).Dispose()
                c.Add 1L
                Expect.isFalse ((collector.Render []).Contains "test_after_total 2") "no count after dispose"
            }

            test "names are sanitized" {
                Expect.equal (sanitize "eplix.sign-requests") "eplix_sign_requests" "dots and dashes"
                Expect.equal (sanitize "9lives") "_lives" "no leading digit"
            }

            test "config" {
                let section (json: string) =
                    {
                        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
                        BaseDir = "/"
                        Mainnet = false
                    }

                Expect.equal
                    (MetricsModule.parse
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok MetricsModule.defaults)
                    "defaults"

                match MetricsModule.parse (section """{ "address": "0.0.0.0", "port": 9100 }""") with
                | Ok s -> Expect.equal (s.Address, s.Port) (IPAddress.Any, 9100) "set"
                | Error e -> failtestf "%A" e

                Expect.isError (MetricsModule.parse (section """{ "port": 0 }""")) "port 0"
                Expect.isError (MetricsModule.parse (section """{ "path": "/x" }""")) "unknown field"
            }

            testSequenced
            <| testT "the endpoint serves duties, signing latency, keys and nodes while the VC runs" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()

                    for i in 0..2 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let port = freePort ()

                    let! core, run, cts, lines =
                        startVc
                            h
                            dir
                            [ 0; 1 ]
                            $$""", "metrics": { "port": {{port}} }"""
                            [ LocalModule.create (); MetricsModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch - 1))
                    use client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")
                    use! resp = client.GetAsync "/metrics"
                    Expect.equal resp.StatusCode HttpStatusCode.OK "200"

                    Expect.equal
                        (string resp.Content.Headers.ContentType)
                        "text/plain; version=0.0.4; charset=utf-8"
                        "content type"

                    let! text = resp.Content.ReadAsStringAsync()

                    let value series =
                        match seriesValue text series with
                        | Some v -> v
                        | None -> failtestf "no series %s in:\n%s\nlog:\n%s" series text (String.Join("\n", lines))

                    Expect.isGreaterThanOrEqual
                        (value """eplix_duties_completed_total{duty="attestation"}""")
                        2.0
                        "attestations counted"

                    Expect.equal (value """eplix_keys{state="active"}""") 2.0 "two active keys"
                    Expect.equal (value """eplix_keys{state="halted"}""") 0.0 "states with no key show 0"

                    Expect.isGreaterThan
                        (value """eplix_signing_duration_seconds_count{backend="local",duty="attestation"}""")
                        0.0
                        "latency"

                    Expect.isGreaterThan
                        (value
                            """eplix_signing_duration_seconds_bucket{backend="local",duty="attestation",le="+Inf"}""")
                        0.0
                        "buckets"

                    Expect.isGreaterThan
                        (value """eplix_sign_requests_total{backend="local",duty="attestation",outcome="signed"}""")
                        0.0
                        "outcomes"

                    Expect.isGreaterThan
                        (value "eplix_slashing_check_duration_seconds_count")
                        0.0
                        "slashing DB latency"

                    Expect.equal (value "eplix_slashing_db_keys") 2.0 "slashing DB keys"
                    Expect.isGreaterThan (value "eplix_slashing_db_bytes") 0.0 "slashing DB size"
                    Expect.isGreaterThan (value """eplix_beacon_node_score{node="http://bn.test"}""") 0.0 "node score"
                    Expect.equal (value """eplix_beacon_node_ready{node="http://bn.test"}""") 1.0 "node ready"

                    Expect.isGreaterThan
                        (value """eplix_beacon_node_requests_total{node="http://bn.test",result="ok"}""")
                        0.0
                        "node requests"

                    Expect.isGreaterThanOrEqual (value "eplix_slot") 7.0 "slot"
                    Expect.isGreaterThan (value "eplix_process_working_set_bytes") 0.0 "working set"
                    Expect.isGreaterThan (value """eplix_process_cpu_seconds_total{mode="user"}""") 0.0 "CPU time"

                    Expect.isGreaterThanOrEqual
                        (value """eplix_gc_collections_total{generation="0"}""")
                        0.0
                        "GC collections"

                    Expect.isGreaterThan (value "eplix_gc_heap_bytes") 0.0 "GC heap"
                    Expect.isGreaterThan (value "eplix_threadpool_threads") 0.0 "thread pool"
                    use! notFound = client.GetAsync "/other"
                    Expect.equal notFound.StatusCode HttpStatusCode.NotFound "other paths"
                    // A beacon node that refuses the attestations: misses counted with their reason.
                    h.Node.Fail <- fun p -> p.EndsWith "pool/attestations"

                    let before =
                        defaultArg
                            (seriesValue text """eplix_duties_missed_total{duty="attestation",reason="submit"}""")
                            0.0

                    do! h.RunSlots(uint64 slotsPerEpoch, uint64 (2 * slotsPerEpoch - 1))
                    let! text = client.GetStringAsync "/metrics"

                    let after =
                        defaultArg
                            (seriesValue text """eplix_duties_missed_total{duty="attestation",reason="submit"}""")
                            0.0

                    Expect.isGreaterThanOrEqual (after - before) 2.0 "misses by reason"
                    ignore core
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "run"
                })

            // Sequenced: the environment variable is process-wide, and another test's Kestrel
            // must not see it.
            testSequenced
            <| testT "the metrics and keymanager listeners read no Kestrel endpoint from the environment" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    let metricsPort, keymanagerPort, extraPort = freePort (), freePort (), freePort ()
                    let variable = "Kestrel__Endpoints__Extra__Url"
                    Environment.SetEnvironmentVariable(variable, $"http://127.0.0.1:{extraPort}")

                    try
                        let! _, run, cts, lines =
                            startVc
                                h
                                dir
                                [ 0 ]
                                $$""", "metrics": { "port": {{metricsPort}} }, "keymanager": { "port": {{keymanagerPort}} }"""
                                [
                                    LocalModule.create ()
                                    MetricsModule.create ()
                                    Eplix.Keymanager.KeymanagerModule.create ()
                                ]

                        use _ = cts
                        use client = new HttpClient()
                        let! text = client.GetStringAsync $"http://127.0.0.1:{metricsPort}/metrics"
                        Expect.stringContains text "eplix_keys" "the configured metrics listener answers"
                        use! km = client.GetAsync $"http://127.0.0.1:{keymanagerPort}/eth/v1/keystores"

                        Expect.equal
                            km.StatusCode
                            HttpStatusCode.Unauthorized
                            "the configured keymanager listener answers"

                        let connects =
                            try
                                use tcp = new TcpClient()
                                tcp.Connect(IPAddress.Loopback, extraPort)
                                true
                            with :? SocketException ->
                                false

                        Expect.isFalse
                            connects
                            $"""nothing listens on the port of {variable}; log: {String.Join('\n', lines)}"""

                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"
                    finally
                        Environment.SetEnvironmentVariable(variable, null)
                })
        ]
