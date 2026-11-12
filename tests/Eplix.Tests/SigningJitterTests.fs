/// Signing jitter (SigningJitter.fs): the config levels, the resolution order,
/// the refusals, the per key tables and the draw, the pipeline's wait and the start log.
module Eplix.Tests.SigningJitterTests

open System
open System.Collections.Concurrent
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Slashing
open Eplix.Backend.Local
open Eplix.Backend.Tee
open Eplix.Metrics.Prometheus
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.MetricsTests

let private ms (x: float) = TimeSpan.FromMilliseconds x
let private key (i: int) = pk (secretOf (500 + i))

let private moduleNames = [ "local"; "tee"; "dirk"; "web3signer"; "metrics"; "keymanager" ]

/// A core config with `signing` (text after the other top-level keys, starting with a comma or
/// empty) and the module sections `modules`.
let private parse (signing: string) (modules: string) =
    let text =
        $$"""{ "beacon_node": "http://127.0.0.1:5052", "network": "hoodi", "data_dir": "data" {{signing}}, "modules": { {{modules}} } }"""

    Config.parse text (tempDir ()) moduleNames

let private fakeBackend (name: string) (calls: ConcurrentQueue<DutyKind>) : Backend =
    {
        Name = name
        Capabilities = caps
        Keys = fun _ -> Task.FromResult []
        Health = fun _ -> Task.FromResult Up
        Sign =
            fun req _ ->
                calls.Enqueue req.Duty.Kind
                Task.FromResult(Failed SignFailure.Timeout)
        Dispose = fun () -> ValueTask.CompletedTask
    }

let private allKinds = SigningJitter.allKinds

let private never =
    [
        DutyKind.Block
        DutyKind.RandaoReveal
        DutyKind.VoluntaryExit
        DutyKind.PayloadAttestation
        DutyKind.PayloadEnvelope
        DutyKind.ProposerPreferences
        DutyKind.BuilderRequestAuth
    ]

/// A whole VC on the fake node and clock with one local key, as MetricsTests.startVc, plus
/// top-level config text `top`. Returns the log once it is ready, then stops it.
let private startWith (h: Harness) (dir: string) (top: string) =
    task {
        let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName
        File.WriteAllText(Path.Combine(ksDir, "k0.json"), keystoreOf 0 "pw")
        File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
        let modules = [ LocalModule.create () ]

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "allow_start_without_history": ["all"] {{top}},
                 "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 } } }"""

        match
            Config.parse configText dir [ "local" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> return failtestf "%A" es
        | Ok config ->
            let cts = new CancellationTokenSource()
            let log, lines = Log.memory ()
            let ready = TaskCompletionSource<CoreServices>()

            let run =
                Runner.run
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
                failtestf "the VC did not start: %s" (String.Join("\n", lines))

            cts.Cancel()
            let! _ = run
            return String.Join("\n", lines)
    }

[<Tests>]
let tests =
    testList
        "signing jitter"
        [
            test "the jitterable duties have one documented key each; blocks, RANDAO, exits, PTC and builder auth none" {
                Expect.equal (allKinds |> List.distinct |> List.length) 14 "14 kinds"

                Expect.equal
                    (allKinds |> List.map SigningJitter.kindIndex |> List.sort)
                    [ 0..13 ]
                    "one table slot per kind"

                let keys =
                    allKinds
                    |> List.choose (fun k ->
                        match SigningJitter.dutyKey k with
                        | ValueSome n -> Some n
                        | ValueNone -> None)

                Expect.equal (List.sort keys) (List.sort SigningJitter.dutyKeys) "one key per jitterable kind"

                for k in never do
                    Expect.equal (SigningJitter.dutyKey k) ValueNone $"{k} never waits"
            }

            test "off by default; jitter_ms 100 covers attestations and sync committee messages, nothing else" {
                match parse "" "" with
                | Error e -> failtestf "%A" e
                | Ok c ->
                    for k in allKinds do
                        Expect.equal (SigningJitter.resolve c.Signing (key 1) "tee" k) TimeSpan.Zero $"{k}: 0"

                    Expect.isFalse (SigningJitter.anyAboveZero c.Signing) "off: no table"
                    Expect.equal (SigningJitter.describe c.Signing) [ "signing jitter: off" ] "check line"

                match parse """, "signing": { "jitter_ms": 100 }""" "" with
                | Error e -> failtestf "%A" e
                | Ok c ->
                    let r = SigningJitter.resolve c.Signing (key 1) "tee"
                    Expect.equal (r DutyKind.Attestation) (ms 100.0) "attestation"
                    Expect.equal (r DutyKind.SyncCommitteeMessage) (ms 100.0) "sync committee message"

                    for k in allKinds |> List.except [ DutyKind.Attestation; DutyKind.SyncCommitteeMessage ] do
                        Expect.equal (r k) TimeSpan.Zero $"{k}: 0"

                    Expect.isTrue (SigningJitter.anyAboveZero c.Signing) "on"

                    Expect.equal
                        (SigningJitter.describe c.Signing)
                        [ "signing jitter: up to 100 ms for attestation and sync_committee_message" ]
                        "check line"
            }

            test "resolution: key and duty, key, module and duty, module, general and duty, general, else 0" {
                let k1, k2, k3 = key 1, key 2, key 3

                let signing =
                    $$""", "signing": { "jitter_ms": 80, "jitter_by_duty_ms": { "aggregate": 300, "registration": 1500 },
                        "keys": { "{{k1.Hex}}": { "jitter_ms": 10, "jitter_by_duty_ms": { "attestation": 5 } },
                                  "{{k2.Hex}}": { "jitter_by_duty_ms": { "sync_contribution": 40 } } } }"""

                let modules =
                    """ "tee": { "signing": { "jitter_ms": 50, "jitter_by_duty_ms": { "selection_proof": 20 } } } """

                match parse signing modules with
                | Error e -> failtestf "%A" e
                | Ok c ->
                    let r = SigningJitter.resolve c.Signing
                    Expect.equal (r k1 "tee" DutyKind.Attestation) (ms 5.0) "key and duty"

                    Expect.equal
                        (r k1 "tee" DutyKind.SyncCommitteeMessage)
                        (ms 10.0)
                        "key jitter_ms covers sync messages"

                    Expect.equal
                        (r k1 "tee" DutyKind.AggregateAndProof)
                        (ms 300.0)
                        "key jitter_ms does not cover aggregates: general and duty"

                    Expect.equal (r k3 "tee" DutyKind.AggregationSlot) (ms 20.0) "module and duty"
                    Expect.equal (r k3 "tee" DutyKind.Attestation) (ms 50.0) "module jitter_ms"
                    Expect.equal (r k3 "local" DutyKind.Attestation) (ms 80.0) "general jitter_ms"

                    Expect.equal
                        (r k3 "local" DutyKind.ValidatorRegistration)
                        (ms 1500.0)
                        "general and duty, above 1 s for registrations"

                    Expect.equal (r k3 "local" DutyKind.SyncSelectionProof) TimeSpan.Zero "not set: 0"

                    Expect.equal
                        (r k2 "local" DutyKind.ContributionAndProof)
                        (ms 40.0)
                        "key and duty without key jitter_ms"

                    Expect.equal (r k2 "tee" DutyKind.Attestation) (ms 50.0) "then the module"

                    for k in [ k1; k2; k3 ] do
                        for m in [ "tee"; "local" ] do
                            for kind in never do
                                Expect.equal (r k m kind) TimeSpan.Zero $"{kind} never ({m})"
            }

            test "nothing set or 0 everywhere: no table; one value above 0: a table" {
                let off =
                    [
                        "", ""
                        """, "signing": { "jitter_ms": 0 }""", ""
                        """, "signing": { "jitter_by_duty_ms": { "attestation": 0, "sync_committee_message": 0 } }""",
                        ""
                        $$""", "signing": { "jitter_ms": 0, "keys": { "{{(key 1).Hex}}": { "jitter_ms": 0 } } }""",
                        """ "tee": { "signing": { "jitter_ms": 0 } } """
                    ]

                for signing, modules in off do
                    match parse signing modules with
                    | Ok c ->
                        Expect.isFalse (SigningJitter.anyAboveZero c.Signing) $"off: {signing}"
                        Expect.equal (SigningJitter.describe c.Signing) [ "signing jitter: off" ] "check line"
                    | Error e -> failtestf "%A" e

                let on =
                    [
                        """, "signing": { "jitter_ms": 100 }""", ""
                        """, "signing": { "jitter_ms": 0, "jitter_by_duty_ms": { "registration": 1 } }""", ""
                        """, "signing": { "jitter_ms": 0 }""", """ "dirk": { "signing": { "jitter_ms": 5 } } """
                    ]

                for signing, modules in on do
                    match parse signing modules with
                    | Ok c -> Expect.isTrue (SigningJitter.anyAboveZero c.Signing) $"on: {signing} {modules}"
                    | Error e -> failtestf "%A" e
            }

            test "mistakes are refused: never-jittered duties, unknown duties, ranges, keys, modules, fields" {
                let k1 = (key 1).Hex
                let neverMsg = "never jittered"

                let neverCases =
                    [
                        for d in
                            [
                                "block"
                                "randao_reveal"
                                "randao"
                                "exit"
                                "builder_auth"
                                "ptc"
                                "payload_envelope"
                                "proposer_preferences"
                            ] -> $$""", "signing": { "jitter_by_duty_ms": { "{{d}}": 0 } }""", "", neverMsg
                    ]

                let bad =
                    neverCases
                    @ [
                        """, "signing": { "jitter_by_duty_ms": { "attestations": 1 } }""",
                        "",
                        "unknown duty \"attestations\""
                        """, "signing": { "jitter_ms": 1001 }""", "", "signing.jitter_ms must be between 0 and 1000"
                        """, "signing": { "jitter_ms": -1 }""", "", "signing.jitter_ms must be between 0 and 1000"
                        """, "signing": { "jitter_by_duty_ms": { "attestation": 1001 } }""",
                        "",
                        "signing.jitter_by_duty_ms.attestation must be between 0 and 1000"
                        """, "signing": { "jitter_by_duty_ms": { "registration": 2001 } }""",
                        "",
                        "signing.jitter_by_duty_ms.registration must be between 0 and 2000"
                        "",
                        """ "tee": { "signing": { "jitter_ms": 1001 } } """,
                        "modules.tee.signing.jitter_ms must be between 0 and 1000"
                        "",
                        """ "dirk": { "signing": { "jitter_by_duty_ms": { "aggregate": 1001 } } } """,
                        "modules.dirk.signing.jitter_by_duty_ms.aggregate must be between 0 and 1000"
                        $$""", "signing": { "keys": { "{{k1}}": { "jitter_ms": 1001 } } }""",
                        "",
                        $"signing.keys.{k1}.jitter_ms must be between 0 and 1000"
                        $$""", "signing": { "keys": { "{{k1}}": { "jitter_by_duty_ms": { "block": 1 } } } }""",
                        "",
                        neverMsg
                        """, "signing": { "keys": { "0x1234": { "jitter_ms": 1 } } }""",
                        "",
                        "is not a validator public key"
                        "", """ "metrics": { "signing": { "jitter_ms": 1 } } """, "metrics is not a signing backend"
                        "", """ "foo": { "signing": { "jitter_ms": 1 } } """, "'foo' is not a module"
                        """, "signing": { "delay_ms": 100 }""", "", "signing: unknown field 'delay_ms'"
                        $$""", "signing": { "keys": { "{{k1}}": { "keys": {} } } }""", "", "unknown field 'keys'"
                        "", """ "tee": { "signing": { "keys": {} } } """, "modules.tee.signing: unknown field 'keys'"
                        """, "signing": { "jitter_by_duty_ms": [ 1 ] }""", "", "must be an object"
                    ]

                for signing, modules, want in bad do
                    match parse signing modules with
                    | Ok _ -> failtestf "accepted %s %s" signing modules
                    | Error e -> Expect.stringContains (String.Join("; ", e)) want $"{signing} {modules}"

                match
                    parse """, "signing": { "jitter_by_duty_ms": { "registration": 2000, "attestation": 1000 } }""" ""
                with
                | Ok _ -> ()
                | Error e -> failtestf "the upper bounds pass: %A" e
            }

            test "the backend modules accept a signing section" {
                let dir = tempDir ()

                let tee =
                    """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                       "keys": [ "0x"""
                    + String('a', 96)
                    + """" ], "signing": { "jitter_ms": 100 } }"""

                let doc = JsonDocument.Parse tee

                match
                    TeeModule.parseSettings
                        {
                            Element = ValueSome doc.RootElement
                            BaseDir = dir
                            Mainnet = false
                        }
                with
                | Ok _ -> ()
                | Error e -> failtestf "tee: %A" e

                let local = LocalModule.create ()
                let ldoc = JsonDocument.Parse """{ "keystores": [], "signing": { "jitter_ms": 100 } }"""

                match
                    local.Configure
                        {
                            Element = ValueSome ldoc.RootElement
                            BaseDir = dir
                            Mainnet = false
                        }
                with
                | Ok() -> ()
                | Error e -> Expect.all e (fun m -> not (m.Contains "signing")) $"local: %A{e}"
            }

            test "per key tables: rebuilt when the key moves; draws uniform in 0..J; no allocation" {
                let c =
                    { SigningJitterConfig.Default with
                        General =
                            { JitterLevel.Empty with
                                Default = ValueSome(ms 100.0)
                            }
                        Modules =
                            Map.ofList
                                [
                                    "tee",
                                    { JitterLevel.Empty with
                                        Default = ValueSome(ms 50.0)
                                    }
                                ]
                    }

                let j = SigningJitters c
                let calls = ConcurrentQueue<DutyKind>()
                let tee = fakeBackend "tee 2 of 3 (a,b,c)" calls
                let local = fakeBackend "local" calls
                let k = key 4
                Expect.equal (j.Bound(k, tee, DutyKind.Attestation)) (ms 50.0) "tee: the module"
                Expect.equal (j.Bound(k, local, DutyKind.Attestation)) (ms 100.0) "moved to local: the general value"
                Expect.equal (j.Draw(k, local, DutyKind.Block)) TimeSpan.Zero "a block draws 0"
                let n = 20_000
                let draws = Array.init n (fun _ -> j.Draw(k, local, DutyKind.Attestation))
                Expect.all draws (fun d -> d >= TimeSpan.Zero && d <= ms 100.0) "within 0..100 ms"
                let mean = (draws |> Array.averageBy (fun d -> d.TotalMilliseconds))
                Expect.isTrue (mean > 47.0 && mean < 53.0) $"mean {mean} ms near 50"
                Expect.isLessThan (Array.min draws) (ms 1.0) "reaches near 0"
                Expect.isGreaterThan (Array.max draws) (ms 99.0) "reaches near 100"
                let before = GC.GetAllocatedBytesForCurrentThread()
                let mutable total = 0L

                for _ in 1..10_000 do
                    total <- total + j.Draw(k, local, DutyKind.Attestation).Ticks

                let allocated = GC.GetAllocatedBytesForCurrentThread() - before
                Expect.isLessThan allocated 4096L $"10,000 draws allocated {allocated} B"
                let fixedMax = SigningJitters(c, Func<int64, int64>(fun n -> n - 1L))
                Expect.equal (fixedMax.Draw(k, tee, DutyKind.Attestation)) (ms 50.0) "the bound is inclusive"
            }

            testT
                "the pipeline waits before the backend; the latency metric leaves the wait out; exits go at once"
                (fun () ->
                    task {
                        let calls = ConcurrentQueue<DutyKind>()
                        let name = $"local test-{Guid.NewGuid():N}"
                        let backend = fakeBackend name calls
                        let registry = KeyRegistry()
                        let k = key 7
                        registry.Add(k, backend) |> ignore
                        registry.SetState(k, KeyState.Active)

                        use db =
                            match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), root 1) with
                            | Ok db -> db
                            | Error e -> failwith e
                        // A fake clock: the wait ends when the test moves the clock, not when a timer fires.
                        let time = Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow)
                        let pipeline = Pipeline(db, registry, time, Log.none)
                        Expect.isNull pipeline.Jitters "no table unless the runner sets one"
                        // The draw always takes the bound, so the wait is exactly 150 ms.
                        pipeline.Jitters <-
                            SigningJitters(
                                { SigningJitterConfig.Default with
                                    General =
                                        { JitterLevel.Empty with
                                            Default = ValueSome(ms 150.0)
                                        }
                                },
                                Func<int64, int64>(fun n -> n - 1L)
                            )

                        use collector = new Collector([ Metrics.MeterName ])

                        let burst =
                            pipeline.SignBurst(
                                [| request k (Duty.SyncCommitteeMessage(41UL, root 9)) |],
                                CancellationToken.None
                            )
                        // Real time passes; the fake clock does not, so nothing may reach the backend.
                        do! Task.Delay(ms 50.0)
                        Expect.isEmpty calls "nothing before the wait ends"
                        time.Advance(ms 149.0)
                        do! Task.Delay(ms 50.0)
                        Expect.isEmpty calls "nothing 1 ms before the wait ends"
                        time.Advance(ms 1.0)
                        let! _ = burst.WaitAsync(TimeSpan.FromSeconds 10.0)

                        Expect.sequenceEqual
                            calls
                            [ DutyKind.SyncCommitteeMessage ]
                            "the sync committee message reached the backend after 150 ms"

                        let text = collector.Render []

                        match
                            seriesValue
                                text
                                $"""eplix_signing_duration_seconds_sum{{backend="{name}",duty="sync_committee_message"}}"""
                        with
                        | Some s -> Expect.isLessThan s 0.1 "the backend's time, without the wait"
                        | None -> failtestf "no latency series in\n%s" text
                        // An exit never waits: it is done without moving the clock.
                        let! _ =
                            pipeline
                                .SignBurst(
                                    [| request k (Duty.VoluntaryExit { Epoch = 5UL; ValidatorIndex = 9UL }) |],
                                    CancellationToken.None
                                )
                                .WaitAsync(TimeSpan.FromSeconds 10.0)

                        Expect.sequenceEqual
                            calls
                            [ DutyKind.SyncCommitteeMessage; DutyKind.VoluntaryExit ]
                            "exit sent"
                    })

            testT "a drain waits for a request that is still in its jitter" (fun () ->
                task {
                    let calls = ConcurrentQueue<DutyKind>()
                    let backend = fakeBackend $"local test-{Guid.NewGuid():N}" calls
                    let registry = KeyRegistry()
                    let k = key 8
                    registry.Add(k, backend) |> ignore
                    registry.SetState(k, KeyState.Active)

                    use db =
                        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), root 1) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none)

                    pipeline.Jitters <-
                        SigningJitters(
                            { SigningJitterConfig.Default with
                                General =
                                    { JitterLevel.Empty with
                                        Default = ValueSome(ms 600.0)
                                    }
                            },
                            Func<int64, int64>(fun n -> n - 1L)
                        )

                    let burst =
                        pipeline.SignBurst(
                            [| request k (Duty.SyncCommitteeMessage(42UL, root 9)) |],
                            CancellationToken.None
                        )

                    do! Task.Delay(ms 50.0)
                    let! idleEarly = pipeline.WaitIdle([ k ], ms 150.0, CancellationToken.None)
                    Expect.isFalse idleEarly "busy while the request waits out its jitter"
                    Expect.isEmpty calls "nothing reached the backend yet"
                    let! idleLater = pipeline.WaitIdle([ k ], TimeSpan.FromSeconds 5.0, CancellationToken.None)
                    Expect.isTrue idleLater "idle once the request is done"
                    let! _ = burst
                    Expect.sequenceEqual calls [ DutyKind.SyncCommitteeMessage ] "sent after the wait"
                })

            testSequenced
            <| testT "the start logs the jitter: off by default, the bound when set" (fun () ->
                task {
                    let! plain = startWith (harness ()) (tempDir ()) ""
                    Expect.stringContains plain "signing jitter: off" "off by default"
                    let! on = startWith (harness ()) (tempDir ()) """, "signing": { "jitter_ms": 100 }"""

                    Expect.stringContains
                        on
                        "signing jitter: up to 100 ms for attestation and sync_committee_message"
                        "on"
                })
        ]
