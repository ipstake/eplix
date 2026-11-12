/// Emergency switches: the rule, the config keys, the switch file, the pipeline
/// refusal and the scheduler with a switch on.
module Eplix.Tests.SwitchesTests

open System
open System.IO
open System.Text
open System.Threading
open System.Net.Http
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let private kindGen = Gen.elements Switches.allKinds

let private switchesGen =
    Gen.map2
        (fun stop paused ->
            {
                StopSigning = stop
                Paused = Set.ofList paused
            })
        (Gen.elements [ false; true ])
        (Gen.subListOf Switches.allKinds)

let private config (extra: string) =
    let dir = tempDir ()
    File.WriteAllText(Path.Combine(dir, "chain.yaml"), "CONFIG_NAME: 'x'\n")

    Config.parse
        $"""{{ "beacon_node": "http://127.0.0.1:5052", "chain_config": "chain.yaml", "data_dir": "data"{extra} }}"""
        dir
        []

let private emergencyLines (lines: Collections.Concurrent.ConcurrentQueue<string>) =
    lines |> Seq.filter (fun l -> l.Contains "emergency switches") |> List.ofSeq

let private pipelineWith (keys: int list) =
    let registry = KeyRegistry()

    let backend =
        LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    for i in keys do
        registry.Add(pubkeyOf i, backend) |> ignore
        registry.SetState(pubkeyOf i, KeyState.Active)

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    db.RegisterKeys [ for i in keys -> pubkeyOf i, KeyOrigin.Imported ] |> ignore
    let log, lines = Log.memory ()
    let h = harness ()
    db, registry, Pipeline(db, registry, h.Time, log), lines, h

let private attestation (h: Harness) (keys: int list) (target: uint64) =
    let data =
        {
            Slot = target * h.Spec.SlotsPerEpoch
            Index = 0UL
            BeaconBlockRoot = Root.Zero
            Source = { Epoch = 0UL; Root = Root.Zero }
            Target = { Epoch = target; Root = Root.Zero }
        }

    Duty.requests
        h.Spec
        gvr
        [| for i in keys -> pubkeyOf i |]
        Priority.High
        DateTimeOffset.MaxValue
        (Duty.Attestation data)

[<Tests>]
let tests =
    testList
        "switches"
        [
            testCase "stop signing stops every kind but exits; paused kinds stop" (fun () ->
                let stop =
                    { Switches.none with
                        StopSigning = true
                    }

                for k in Switches.allKinds do
                    Expect.equal (Switches.stops stop k) (k <> DutyKind.VoluntaryExit) $"stop: {k}"

                let p =
                    { Switches.none with
                        Paused = set [ DutyKind.Attestation; DutyKind.VoluntaryExit ]
                    }

                Expect.isTrue (Switches.stops p DutyKind.VoluntaryExit) "an exit can be paused by name"
                Expect.isFalse (Switches.stops p DutyKind.Block) "a block is not paused"
                Expect.equal (Switches.mask Switches.none) 0 "nothing on: mask 0")

            testPropN
                "the mask matches the rule for every kind"
                200
                (Prop.forAll (Arb.fromGen (Gen.zip switchesGen kindGen)) (fun (s, k) ->
                    Switches.stops s k = ((s.StopSigning && k <> DutyKind.VoluntaryExit) || s.Paused.Contains k)))

            testPropN
                "the file format round-trips"
                200
                (Prop.forAll (Arb.fromGen switchesGen) (fun s -> Switches.parseFile (Switches.toJson s) = Ok s))

            testCase "every duty kind has its own bit and its label parses" (fun () ->
                let bits = Switches.allKinds |> List.map Switches.bit
                Expect.equal (List.distinct bits).Length Switches.allKinds.Length "distinct bits"

                for k in Switches.allKinds do
                    Expect.equal (Switches.parseKind (Metrics.dutyLabel k)) (Ok k) (Metrics.dutyLabel k)

                Expect.isError (Switches.parseKind "attesting") "unknown name")

            testCase "the switch file: good, comma list, unknown field, bad kind, bad JSON" (fun () ->
                let parse (t: string) = Switches.parseFile (Encoding.UTF8.GetBytes t)

                Expect.equal
                    (parse """{ "stop_signing": true, "paused_duties": ["attestation", "block"] }""")
                    (Ok
                        {
                            StopSigning = true
                            Paused = set [ DutyKind.Attestation; DutyKind.Block ]
                        })
                    "good"

                Expect.equal
                    (parse """{ "paused_duties": "attestation, sync_committee_message" }""")
                    (Ok
                        {
                            StopSigning = false
                            Paused = set [ DutyKind.Attestation; DutyKind.SyncCommitteeMessage ]
                        })
                    "comma list"

                Expect.equal (parse "{}") (Ok Switches.none) "empty object"
                Expect.isError (parse """{ "stop": true }""") "unknown field"
                Expect.isError (parse """{ "paused_duties": ["attesting"] }""") "unknown kind"
                Expect.isError (parse """{ "stop_signing": "yes" }""") "not a bool"
                Expect.isError (parse "[]") "not an object"
                Expect.isError (parse "{ broken") "not JSON")

            testCase "config: stop_signing and paused_duties" (fun () ->
                match config ", \"stop_signing\": true, \"paused_duties\": [\"attestation\"]" with
                | Ok c ->
                    Expect.equal
                        c.Switches
                        {
                            StopSigning = true
                            Paused = set [ DutyKind.Attestation ]
                        }
                        "parsed"
                | Error e -> failtestf "%A" e

                match config "" with
                | Ok c -> Expect.equal c.Switches Switches.none "default: nothing switched off"
                | Error e -> failtestf "%A" e

                Expect.isError (config ", \"paused_duties\": [\"nope\"]") "unknown duty kind fails the start"
                Expect.isError (config ", \"stop_signing\": 1") "not a bool fails the start")

            testCase "config from flags and the environment" (fun () ->
                let dir = tempDir ()
                File.WriteAllText(Path.Combine(dir, "chain.yaml"), "CONFIG_NAME: 'x'\n")
                let file = Path.Combine(dir, "eplix.json")

                File.WriteAllText(
                    file,
                    """{ "beacon_node": "http://127.0.0.1:5052", "chain_config": "chain.yaml", "data_dir": "data" }"""
                )

                let env =
                    match ConfigSources.fromEnv [ "EPLIX_PAUSED_DUTIES", "attestation,block" ] with
                    | Ok e -> e
                    | Error e -> failtestf "%A" e

                let flags =
                    match ConfigSources.fromFlags [ "stop-signing", "true" ] with
                    | Ok f -> f
                    | Error e -> failtestf "%A" e

                match ConfigSources.load (ValueSome file) (env @ flags) [] with
                | Ok c ->
                    Expect.equal
                        c.Switches
                        {
                            StopSigning = true
                            Paused = set [ DutyKind.Attestation; DutyKind.Block ]
                        }
                        "both sources"
                | Error e -> failtestf "%A" e)

            testCase "the board logs once per change, not per check" (fun () ->
                let log, lines = Log.memory ()
                let b = SwitchBoard(log)
                b.SetConfig Switches.none
                Expect.isEmpty (emergencyLines lines) "nothing on: no line"

                let paused =
                    { Switches.none with
                        Paused = set [ DutyKind.Attestation ]
                    }

                b.SetFile paused
                b.SetFile paused
                b.SetConfig paused
                Expect.equal (emergencyLines lines).Length 1 "one line for one change"
                Expect.isTrue (b.Stops DutyKind.Attestation) "attestations stop"
                Expect.isFalse (b.Stops DutyKind.Block) "blocks go on"
                b.SetFile Switches.none
                Expect.isTrue (b.Stops DutyKind.Attestation) "the config still pauses attestations"
                b.SetConfig Switches.none
                Expect.isFalse (b.Stops DutyKind.Attestation) "resumed"
                let l = emergencyLines lines
                Expect.equal l.Length 2 "a second line for the resume"
                Expect.stringContains (List.last l) "resumed" "says so")

            testCase "the switch file: load, change, delete, broken" (fun () ->
                let dir = tempDir ()
                let log, lines = Log.memory ()
                let b = SwitchBoard(log)
                let f = SwitchFile(dir, b, log)
                Expect.isOk (f.Load()) "no file: fine"

                SwitchFile.Write(
                    dir,
                    { Switches.none with
                        StopSigning = true
                    }
                )

                f.Check()
                Expect.isTrue (b.Stops DutyKind.Attestation) "the stop applies"

                if not (OperatingSystem.IsWindows()) then
                    Expect.isFalse
                        ((File.GetUnixFileMode f.Path).HasFlag UnixFileMode.OtherWrite)
                        "not writable by others"

                File.WriteAllText(f.Path, "{ broken")
                f.Check()
                f.Check()
                Expect.isTrue (b.Stops DutyKind.Attestation) "a broken file keeps the last good content"

                Expect.equal
                    (lines |> Seq.filter (fun l -> l.Contains "the switches in place stay") |> Seq.length)
                    1
                    "one error line per broken content"

                File.Delete f.Path
                f.Check()
                Expect.isFalse (b.Stops DutyKind.Attestation) "deleting the file resumes"
                File.WriteAllText(f.Path, "{ broken")
                let b2 = SwitchBoard(log)
                Expect.isError (SwitchFile(dir, b2, log).Load()) "a broken file at start fails the start")

            testT "the pipeline refuses switched-off kinds, writes no mark and halts no key" (fun () ->
                task {
                    let db, registry, pipeline, lines, h = pipelineWith [ 0; 1 ]
                    use _ = db

                    pipeline.Switches.SetFile
                        { Switches.none with
                            StopSigning = true
                        }

                    let! outcomes = pipeline.SignBurst(attestation h [ 0; 1 ] 1UL, CancellationToken.None)

                    for o in outcomes do
                        match o with
                        | Refused(Paused why) -> Expect.stringContains why "stopped" "the reason"
                        | o -> failtestf "expected Paused, got %s" o.Describe

                    Expect.equal (Metrics.missReason outcomes[0]) Metrics.Reason.Paused "miss reason"
                    Expect.isTrue (db.Marks(pubkeyOf 0)).Value.Attestation.IsNone "no slashing mark recorded"
                    Expect.equal (registry.TryGet(pubkeyOf 0)).Value.State KeyState.Active "the key stays active"

                    let exit =
                        Duty.request
                            h.Spec
                            gvr
                            (pubkeyOf 0)
                            Priority.Low
                            DateTimeOffset.MaxValue
                            (Duty.VoluntaryExit { Epoch = 1UL; ValidatorIndex = 0UL })

                    let! x = pipeline.Sign(exit, CancellationToken.None)

                    Expect.isTrue
                        (match x with
                         | Signed _ -> true
                         | _ -> false)
                        $"an exit still signs: {x.Describe}"

                    pipeline.Switches.SetFile
                        { Switches.none with
                            Paused = set [ DutyKind.Block ]
                        }

                    let! again = pipeline.SignBurst(attestation h [ 0; 1 ] 1UL, CancellationToken.None)

                    Expect.all
                        again
                        (fun o ->
                            match o with
                            | Signed _ -> true
                            | _ -> false)
                        "attestations sign with only blocks paused"

                    Expect.equal (emergencyLines lines).Length 2 "two changes, two lines"
                })

            testT "the scheduler skips paused attestations without asking for data, then resumes" (fun () ->
                task {
                    let h = harness ()
                    addValidators [ h.Node ] 8
                    h.Node.Proposals[3UL] <- 3UL
                    h.Node.Proposals[10UL] <- 2UL
                    let vc = startVc h defaults

                    vc.Pipeline.Switches.SetFile
                        {
                            StopSigning = true
                            Paused = Set.empty
                        }

                    do! h.RunSlots(0UL, 7UL)
                    Expect.equal h.Node.Submissions.Count 0 $"no attestation while stopped; log:\n{vc.Log}"

                    Expect.equal
                        (h.Node.RequestCount "GET /eth/v1/validator/attestation_data")
                        0
                        "no attestation data asked"

                    Expect.equal (h.Node.RequestCount "GET /eth/v3/validator/blocks") 0 "no block asked"
                    Expect.equal h.Node.Published.Count 0 "no block published"

                    vc.Pipeline.Switches.SetFile
                        { Switches.none with
                            Paused = set [ DutyKind.Attestation ]
                        }

                    do! h.RunSlots(8UL, 9UL)
                    advanceTo h (h.Clock.SlotStart 10UL + TimeSpan.FromMilliseconds 1.0)
                    do! waitUntil vc "the block of slot 10" (fun () -> h.Node.Published.Count = 1)
                    do! h.RunSlots(10UL, 11UL)
                    Expect.equal h.Node.Submissions.Count 0 "attestations still paused"
                    // Lines up to the resume: later ones may name duties of the change-over.
                    let whilePaused = List.ofSeq vc.Lines
                    vc.Pipeline.Switches.SetFile Switches.none
                    do! h.RunSlots(12UL, 15UL)
                    do! vc.Stop()
                    Expect.isGreaterThan h.Node.Submissions.Count 0 "attestations again after the resume"
                    Expect.equal (emergencyLines vc.Lines).Length 3 $"one line per change; log:\n{vc.Log}"

                    let skipped =
                        whilePaused
                        |> Seq.filter (fun l ->
                            (l.StartsWith "WARN" || l.StartsWith "ERROR")
                            && (l.Contains "not signed" || l.Contains "proposal by"))
                        |> List.ofSeq

                    Expect.isEmpty skipped $"no warning per duty; log:{Char.ConvertFromUtf32 10}{vc.Log}"
                })

            testT "the whole VC: a broken switch file fails the start" (fun () ->
                task {
                    let h = harness ()
                    let dir = RunnerTests.localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = RunnerTests.localVcConfig dir
                    Directory.CreateDirectory config.DataDir |> ignore
                    File.WriteAllText(Path.Combine(config.DataDir, Switches.FileName), """{ "stop_signing": "yes" }""")
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)

                    let! r =
                        runSeeded
                            {
                                Config = config
                                Modules = modules
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = Log.none
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> failtest "the VC got ready"
                            }
                            cts.Token

                    match r with
                    | Error e -> Expect.stringContains e Switches.FileName "names the file"
                    | Ok() -> failtest "the VC ran"
                })

            testT "the whole VC: a stop in the switch file holds from the start and lifts when deleted" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = RunnerTests.localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = RunnerTests.localVcConfig dir
                    Directory.CreateDirectory config.DataDir |> ignore

                    SwitchFile.Write(
                        config.DataDir,
                        { Switches.none with
                            StopSigning = true
                        }
                    )

                    let log, lines = Log.memory ()
                    use cts = new CancellationTokenSource()

                    let run =
                        runSeeded
                            {
                                Config = config
                                Modules = modules
                                Http = new HttpClient(h.Node, false)
                                Time = h.Time
                                Log = log
                                OnSlotDone = h.Waiter.Done
                                OnReady = fun _ _ -> ()
                            }
                            cts.Token

                    do! h.RunSlots(0UL, uint64 slotsPerEpoch - 1UL)

                    Expect.equal
                        h.Node.Submissions.Count
                        0
                        $"nothing signed in epoch 0; log: {String.Join(Char.ConvertFromUtf32 10, lines)}"

                    File.Delete(Path.Combine(config.DataDir, Switches.FileName))
                    // The VC reads the file once a second on its clock: move it a second, before slot 8.
                    h.Time.Advance(TimeSpan.FromSeconds 1.1)
                    let sw = Diagnostics.Stopwatch.StartNew()

                    while not (lines |> Seq.exists (fun l -> l.Contains "signing resumed"))
                          && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                        do! Task.Delay 10

                    do! h.RunSlots(uint64 slotsPerEpoch, 2UL * uint64 slotsPerEpoch - 1UL)
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "ran"

                    Expect.equal
                        h.Node.Submissions.Count
                        4
                        $"one attestation per key in epoch 1; log: {String.Join(Char.ConvertFromUtf32 10, lines)}"

                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "signing resumed")) "the resume is logged"
                })
        ]
