/// Doppelganger protection in the whole VC against failures found in other validator clients:
/// what a held key signs on a Gloas chain, and a restart.
module Eplix.Tests.DoppelgangerFindingsTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Doppelganger
open Eplix.Gloas
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

/// MetricsTests.startVc with a chain config of the caller's choice.
let private startOn
    (h: Harness)
    (dir: string)
    (chainYaml: string)
    (keys: int list)
    (extraModules: string)
    (modules: Module list)
    =
    task {
        let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

        for i in keys do
            File.WriteAllText(Path.Combine(ksDir, $"k{i}.json"), MetricsTests.keystoreOf i "pw")

        File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), chainYaml)
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
                failtestf
                    "the VC did not start: %A\n%s"
                    (if run.IsCompleted then box run.Result else box "timeout")
                    (String.Join("\n", lines))

            return run, cts, lines
    }

let private waitFor (lines: Collections.Concurrent.ConcurrentQueue<string>) (what: string) (cond: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what (String.Join("\n", lines))
    }

/// POST paths of the messages a validator key signs, other than attestations and blocks (the
/// node keeps those apart, in Submissions and Published).
let private signedPaths =
    [
        "pool/payload_attestations"
        "pool/sync_committees"
        "contribution_and_proofs"
        "aggregate_and_proofs"
        "proposer_preferences"
        "builder_preferences"
        "execution_payload_envelopes"
        "pool/voluntary_exits"
    ]

let private advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

/// Target epochs of the attestations the node got from validator `i` since submission `from`.
let private epochsOf (h: Harness) (from: int) (i: int) =
    h.Node.Submissions
    |> Seq.skip from
    |> Seq.filter (fun x -> x.AttesterIndex = uint64 i)
    |> Seq.map (fun x -> x.Data.Target.Epoch)
    |> Seq.distinct
    |> Seq.sort
    |> List.ofSeq

/// Runs the VC with keys 0 and 7 (they attest in the first and the last slot of each epoch)
/// to the end of epoch 5, then starts it again on the same data dir in the first slot of epoch 6.
/// The node sees a key live in an epoch when it holds an attestation of the key for that epoch,
/// so the VC's own votes before the restart are live. Returns the second run and where its
/// submissions start.
let private restart () =
    task {
        let h = harness ()

        for i in 0..7 do
            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

        h.Node.Live <-
            fun epoch index ->
                h.Node.Submissions |> Seq.exists (fun x -> x.AttesterIndex = index && x.Data.Target.Epoch = epoch)

        let dir = tempDir ()
        let section = ""
        let spe = uint64 slotsPerEpoch

        let! run1, cts1, lines1 =
            startOn
                h
                dir
                (configYaml secondsPerSlot slotsPerEpoch)
                [ 0; 7 ]
                section
                [ LocalModule.create (); DoppelgangerModule.create () ]

        do! h.RunSlots(0UL, 6UL * spe - 1UL)
        cts1.Cancel()
        let! r1 = run1
        Expect.isOk r1 $"first run; log:\n{String.Join('\n', lines1)}"
        Expect.equal (epochsOf h 0 7) [ 4UL; 5UL ] "key 7 voted in the last slot of epochs 4 and 5"
        let before = h.Node.Submissions.Count
        let liveness = h.Node.Requests |> Seq.filter (fun r -> r.Contains "/liveness/") |> Seq.length
        advanceTo h (h.Clock.SlotStart(6UL * spe) + TimeSpan.FromMilliseconds 100.0)

        let! run2, cts2, lines2 =
            startOn
                h
                dir
                (configYaml secondsPerSlot slotsPerEpoch)
                [ 0; 7 ]
                section
                [ LocalModule.create (); DoppelgangerModule.create () ]

        return h, run2, cts2, lines2, before, liveness
    }

[<Tests>]
let tests =
    testList
        "doppelganger findings"
        [
            testSequenced
            <| testT
                "a held key on a Gloas chain casts no PTC vote, sync message or preferences; once active it does (finding 1)"
                (fun () ->
                    task {
                        let h = VcHarness.gloasHarness 1UL
                        VcHarness.addValidators [ h.Node ] 4
                        // Duties in the hold (epochs 0 to 3) and after it.
                        h.Node.PtcSlots[9UL] <- [| 1UL |]
                        h.Node.PtcSlots[33UL] <- [| 1UL |]
                        h.Node.SyncSeats[2UL] <- [| 0UL |]
                        h.Node.Proposals[12UL] <- 3UL
                        let dir = tempDir ()

                        let! run, cts, lines =
                            startOn
                                h
                                dir
                                (configYamlGloas secondsPerSlot slotsPerEpoch 1UL)
                                [ 0..3 ]
                                """, "gloas": { "include_payload": true, "p2p_min_bid": "0" }"""
                                [ LocalModule.create (); GloasModule.create (); DoppelgangerModule.create () ]

                        use _ = cts
                        // Checked in the last slots of epochs 2 and 3: active from slot 31.
                        do! h.RunSlots(0UL, 30UL)

                        let held =
                            h.Node.Posts
                            |> Seq.map fst
                            |> Seq.filter (fun p -> signedPaths |> List.exists p.EndsWith)
                            |> List.ofSeq

                        Expect.isEmpty held $"no signed message while the keys wait; log:\n{String.Join('\n', lines)}"
                        Expect.isEmpty h.Node.Submissions "no attestation"
                        Expect.isEmpty h.Node.Published "no block"
                        Expect.isFalse run.IsCompleted "still running"
                        do! h.RunSlots(31UL, 33UL)
                        advanceTo h (h.Clock.SlotStart 33UL + h.Spec.Bps 7100UL)

                        do!
                            waitFor lines "the PTC vote of slot 33" (fun () ->
                                not (List.isEmpty (VcHarness.postsOf h.Node "pool/payload_attestations")))

                        Expect.isNonEmpty (VcHarness.postsOf h.Node "pool/sync_committees") "sync messages once active"
                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"
                    })

            testSequenced
            <| testT
                "a restart checks every key again, and does not take the VC's own votes for a doppelganger (findings 4 and 6)"
                (fun () ->
                    task {
                        let! h, run, cts, lines, before, liveness = restart ()
                        use _ = cts
                        let spe = uint64 slotsPerEpoch
                        do! h.RunSlots(6UL * spe, 11UL * spe - 1UL)
                        let log = String.Join("\n", lines)
                        Expect.isFalse run.IsCompleted $"no shutdown; log:\n{log}"
                        // Waits from epoch 6, epochs 7 and 8 checked: active from the last slot of epoch 9.
                        Expect.equal (epochsOf h before 0) [ 10UL ] "key 0 attests again from epoch 10"
                        Expect.equal (epochsOf h before 7) [ 10UL ] "key 7 attests again from epoch 10"

                        let asked =
                            h.Node.Requests
                            |> Seq.filter (fun r -> r.Contains "/liveness/")
                            |> Seq.skip liveness
                            |> List.ofSeq

                        Expect.equal
                            asked
                            [ "POST /eth/v1/validator/liveness/7"; "POST /eth/v1/validator/liveness/8" ]
                            "epochs 4 to 6 are never asked"

                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"
                    })
        ]
