/// modules.tee.ha_peer: tee-signer's "already signed" refusals skip the duty
/// and keep the key; every other slashing refusal still halts it; only a tee-only VC may set it.
module Eplix.Tests.HaPeerTests

open System
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Slashing
open Eplix.Backend.Local
open Eplix.Backend.Tee
open Eplix.Backend.Web3Signer
open Eplix.Metrics.Prometheus
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.MetricsTests

let private refusal code (detail: string) : Wire.Refusal = { Code = code; Detail = detail }

let private block =
    Duty.Block
        {
            Slot = 9UL
            ProposerIndex = 1UL
            ParentRoot = root 1
            StateRoot = root 2
            BodyRoot = root 3
        }

let private isSlashable o =
    match o with
    | Refused(Slashable _) -> true
    | _ -> false

let private isLost o =
    match o with
    | Refused(LostToPeer _) -> true
    | _ -> false

let private moduleNames = [ "local"; "tee"; "dirk"; "web3signer"; "keymanager"; "metrics" ]

let private parse (modules: string) =
    let text =
        $$"""{ "beacon_node": "http://127.0.0.1:5052", "network": "hoodi", "data_dir": "data", "modules": { {{modules}} } }"""

    Config.parse text (tempDir ()) moduleNames

/// A key in a registry and a slashing DB that lets its first attestation through, signing with
/// `backend`, and a pipeline over them.
let private pipelineWith (backend: Backend) (k: PubKey) =
    let registry = KeyRegistry()
    registry.Add(k, backend) |> ignore
    registry.SetState(k, KeyState.Active)

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), root 1) with
        | Ok db -> db
        | Error e -> failwith e

    db.RegisterKeys [ k, KeyOrigin.StartedEmpty ] |> ignore
    registry, db, Pipeline(db, registry, TimeProvider.System, Log.none)

let private keystoreOf (i: int) =
    Keystore.encrypt (secretOf i) "pw" (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) $"m/12381/3600/{i}/0/0"

/// Runs the VC with modules.tee.ha_peer on and the local and web3signer modules linked without
/// a section, as a tee-only build links them. `ready` runs on the services once the VC is
/// ready, then the VC stops. `ready` also gets the harness and the log lines. Returns the run's
/// result and whether `ready` ran.
let private runHaPeerWith
    (dir: string)
    (ready: Harness -> Collections.Concurrent.ConcurrentQueue<string> -> CoreServices -> Task)
    =
    task {
        let h = harness ()
        let log, lines = Log.memory ()
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

        let text =
            """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "modules": { "tee": { "ha_peer": true } } }"""

        let modules = [ LocalModule.create (); Web3SignerModule.create () ]

        match
            Config.parse text dir [ "tee"; "local"; "web3signer" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> return failtestf "%A" es
        | Ok config ->
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 30.0)
            let readyDone = TaskCompletionSource()

            let run =
                Runner.run
                    {
                        Config = config
                        Modules = modules
                        Http = new Net.Http.HttpClient(h.Node, false)
                        Time = h.Time
                        Log = log
                        OnSlotDone = h.Waiter.Done
                        OnReady =
                            fun core _ ->
                                task {
                                    try
                                        do! ready h lines core
                                        readyDone.TrySetResult() |> ignore
                                    with e ->
                                        readyDone.TrySetException e |> ignore

                                    cts.Cancel()
                                }
                                |> ignore
                    }
                    cts.Token

            let! result = run.WaitAsync(TimeSpan.FromSeconds 30.0)

            if readyDone.Task.IsFaulted then
                raise readyDone.Task.Exception

            return result, readyDone.Task.IsCompletedSuccessfully
    }

let private runHaPeer (dir: string) (ready: CoreServices -> Task) = runHaPeerWith dir (fun _ _ core -> ready core)

let private answering (name: string) (o: SignOutcome) : Backend =
    {
        Name = name
        Capabilities = caps
        Keys = fun _ -> Task.FromResult []
        Health = fun _ -> Task.FromResult Up
        Sign = fun _ _ -> Task.FromResult o
        Dispose = fun () -> ValueTask.CompletedTask
    }

[<Tests>]
let tests =
    testList
        "ha peer"
        [
            test "tee mapping: without ha_peer every slashing code halts as before" {
                for duty, code in
                    [
                        attestation, 11us
                        attestation, 10us
                        attestation, 12us
                        block, 9us
                        attestation, 24us
                    ] do
                    Expect.isTrue
                        (isSlashable (Mapping.toOutcome "r" duty (refusal code "detail")))
                        $"{Wire.Status.name code}"
            }

            test
                "tee mapping with ha_peer: SC_ERR_SLASH_TARGET, SC_ERR_SLASH_BLOCK and SC_ERR_EQUIVOCATION are lost to the peer" {
                let o = Mapping.toOutcomeWith true "r"
                Expect.isTrue (isLost (o attestation (refusal 11us "target 5 already signed"))) "target"
                Expect.isTrue (isLost (o block (refusal 9us ""))) "block"
                Expect.isTrue (isLost (o attestation (refusal 24us ""))) "equivocation"

                match o attestation (refusal 11us "") with
                | Refused(LostToPeer why) -> Expect.stringContains why "SC_ERR_SLASH_TARGET" "the code is in the text"
                | other -> failtestf "%A" other
            }

            test "a runner's text lost to the peer is cut and cleaned, whole key and group alike" {
                let detail = "a\nWARN forged‮" + String('x', 1 <<< 20)

                let expectClean (what: string) (o: SignOutcome) =
                    match o with
                    | Refused(LostToPeer why) ->
                        Expect.isLessThanOrEqual why.Length (Threshold.MaxReason + 3) $"{what}: cut"
                        Expect.isFalse (why.Contains '\n') $"{what}: no line break"
                        Expect.isFalse (why.Contains '‮') $"{what}: no bidi override"
                        Expect.stringContains why "SC_ERR_SLASH_TARGET" $"{what}: the code stays"
                    | other -> failtestf "%s: %A" what other

                let o = Mapping.toOutcomeWith true "r"
                expectClean "whole key" (o attestation (refusal 11us detail))

                expectClean
                    "group member"
                    (Refused(Threshold.cleanRefusal (LostToPeer("r: SC_ERR_SLASH_TARGET: " + detail))))
            }

            test "tee mapping with ha_peer: SC_ERR_SLASH_SOURCE is lost to the peer; the source floor still waits" {
                let o = Mapping.toOutcomeWith true "r"

                Expect.isTrue
                    (isLost (o attestation (refusal 10us "attestation source 5 below 7")))
                    "source below the signed source"

                match o attestation (refusal 10us "") with
                | Refused(LostToPeer why) -> Expect.stringContains why "SC_ERR_SLASH_SOURCE" "the code is in the text"
                | other -> failtestf "%A" other

                Expect.equal
                    (o attestation (refusal Wire.Status.Floor "floor epoch 12 (source floor): attestation source 3"))
                    (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                    "the source floor waits, it is not lost"
            }

            test "tee mapping with ha_peer: source after target still halts; the restart floor still waits" {
                let o = Mapping.toOutcomeWith true "r"

                Expect.isTrue
                    (isSlashable (o attestation (refusal 12us "attestation source 6, target 5")))
                    "SC_ERR_SLASH_SOURCE_GT_TARGET"

                Expect.equal
                    (o attestation (refusal Wire.Status.Floor "floor epoch 12 (restart floor): target 12"))
                    (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                    "the restart floor is not ready, not lost"

                Expect.isTrue
                    (match o attestation (refusal Wire.Status.PolicyTargetSlot "") with
                     | Refused(PolicyDenied _) -> true
                     | _ -> false)
                    "policy codes unchanged"
            }

            testT
                "pipeline: a refusal lost to the peer keeps the key and counts; a slashable refusal halts it"
                (fun () ->
                    task {
                        use collector = new Collector([ Metrics.MeterName ])
                        let k = pk (secretOf 601)

                        let registry, db, pipeline =
                            pipelineWith (answering "tee r1" (Refused(LostToPeer "r1: SC_ERR_SLASH_TARGET"))) k

                        use _ = db

                        let before =
                            defaultArg
                                (seriesValue (collector.Render []) """eplix_ha_peer_lost_total{duty="attestation"}""")
                                0.0

                        let! outcomes = pipeline.SignBurst([| request k attestation |], CancellationToken.None)
                        Expect.isTrue (isLost outcomes[0]) $"lost: %A{outcomes[0]}"

                        match registry.TryGet k with
                        | ValueSome rk -> Expect.equal rk.State KeyState.Active "the key keeps signing"
                        | ValueNone -> failtest "key gone"

                        let after =
                            defaultArg
                                (seriesValue (collector.Render []) """eplix_ha_peer_lost_total{duty="attestation"}""")
                                0.0

                        Expect.isGreaterThanOrEqual (after - before) 1.0 "counted by duty"
                        let k2 = pk (secretOf 602)

                        let registry2, db2, pipeline2 =
                            pipelineWith
                                (answering "tee r1" (Refused(Slashable "r1: SC_ERR_SLASH_SOURCE_GT_TARGET")))
                                k2

                        use _ = db2
                        let! _ = pipeline2.SignBurst([| request k2 attestation |], CancellationToken.None)

                        match registry2.TryGet k2 with
                        | ValueSome rk ->
                            Expect.isTrue
                                (match rk.State with
                                 | KeyState.Halted _ -> true
                                 | _ -> false)
                                $"halted: %A{rk.State}"
                        | ValueNone -> failtest "key gone"
                    })

            testT "pipeline: SC_ERR_SLASH_SOURCE keeps the key with ha_peer and halts it without" (fun () ->
                task {
                    // The lagging-node case seen on Hoodi: the peer signed a newer source first.
                    let refusal = refusal Wire.Status.SlashSource "attestation source 5 below 7"

                    let mapped haPeer =
                        { (answering "tee r1" (Refused UnknownKey)) with
                            Sign = fun req _ -> Task.FromResult(Mapping.toOutcomeWith haPeer "r1" req.Duty refusal)
                        }

                    let k = pk (secretOf 603)
                    let registry, db, pipeline = pipelineWith (mapped true) k
                    use _ = db
                    let! outcomes = pipeline.SignBurst([| request k attestation |], CancellationToken.None)
                    Expect.isTrue (isLost outcomes[0]) $"lost: %A{outcomes[0]}"

                    match registry.TryGet k with
                    | ValueSome rk -> Expect.equal rk.State KeyState.Active "with ha_peer the key keeps signing"
                    | ValueNone -> failtest "key gone"

                    let k2 = pk (secretOf 604)
                    let registry2, db2, pipeline2 = pipelineWith (mapped false) k2
                    use _ = db2
                    let! outcomes2 = pipeline2.SignBurst([| request k2 attestation |], CancellationToken.None)
                    Expect.isTrue (isSlashable outcomes2[0]) $"slashable: %A{outcomes2[0]}"

                    match registry2.TryGet k2 with
                    | ValueSome rk ->
                        Expect.isTrue
                            (match rk.State with
                             | KeyState.Halted _ -> true
                             | _ -> false)
                            $"without ha_peer halted: %A{rk.State}"
                    | ValueNone -> failtest "key gone"
                })

            testT
                "2 of 3 group: members lost to the peer make the group lost; a member's other slashing refusal wins"
                (fun () ->
                    task {
                        let secret, shares = shamir 610 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret
                        let lost = fun (_: SignRequest) -> Refused(LostToPeer "SC_ERR_SLASH_TARGET")
                        let surround = fun (_: SignRequest) -> Refused(Slashable "SC_ERR_SLASH_SOURCE_GT_TARGET")

                        let make answers =
                            group
                                [
                                    for (i, s), a in List.zip shares answers -> FakeMember(i, key, s, a, TimeSpan.Zero)
                                ]
                                2

                        let req = request key attestation
                        let! o = (make [ lost; lost; partialOf 3UL (snd shares[2]) ]).Sign req CancellationToken.None
                        Expect.isTrue (isLost o) $"two lost, one signed: %A{o}"
                        let! o = (make [ lost; surround; lost ]).Sign req CancellationToken.None
                        Expect.isTrue (isSlashable o) $"a surround among them halts: %A{o}"

                        let! o =
                            (make [ lost; partialOf 2UL (snd shares[1]); partialOf 3UL (snd shares[2]) ]).Sign
                                req
                                CancellationToken.None

                        Expect.isTrue
                            (match o with
                             | Signed _ -> true
                             | _ -> false)
                            $"two partials sign: %A{o}"
                    })

            test "a duty lost to the peer counts as a miss with its own reason, not as refused" {
                Expect.equal (Metrics.missReason (Refused(LostToPeer "r1: SC_ERR_SLASH_TARGET"))) "lost_to_peer" "lost"

                Expect.equal
                    (Metrics.missReason (Refused(PolicyDenied "r1: policy")))
                    Metrics.Reason.Refused
                    "other refusals stay refused"
            }

            test "the ha_peer start line names every code that is lost to the peer" {
                Expect.equal
                    Mapping.haPeerStartLine
                    "tee: ha_peer on: SC_ERR_SLASH_TARGET, SC_ERR_SLASH_SOURCE, SC_ERR_SLASH_BLOCK and SC_ERR_EQUIVOCATION skip the duty and keep the key; other slashing refusals still halt it"
                    "the line"

                for c in Mapping.alreadySignedCodes do
                    Expect.isTrue (Mapping.alreadySigned c) (Wire.Status.name c)
            }

            test "config: ha_peer only when every key signs through the tee module" {
                let tee = """ "tee": { "ha_peer": true } """

                match parse tee with
                | Ok _ -> ()
                | Error e -> failtestf "tee alone: %A" e

                match parse (tee + """, "keymanager": {} """) with
                | Ok _ -> ()
                | Error e -> failtestf "tee and keymanager: %A" e

                for other in [ "local"; "dirk"; "web3signer" ] do
                    match parse (tee + $$""", "{{other}}": {} """) with
                    | Ok _ -> failtestf "accepted ha_peer with %s" other
                    | Error e ->
                        Expect.stringContains
                            (String.Join("; ", e))
                            $"modules.tee.ha_peer: every key must sign through the tee module, but modules.{other} is configured"
                            other

                match parse """ "tee": { "ha_peer": false }, "local": {} """ with
                | Ok _ -> ()
                | Error e -> failtestf "ha_peer false with local: %A" e
            }

            testT "start: a keystore in the data dir fails the start with ha_peer on" (fun () ->
                task {
                    let dir = tempDir ()
                    LocalModule.ManagedStore.save (Path.Combine(dir, "data")) (pubkeyOf 0) (keystoreOf 0) "pw"
                    let! result, _ = runHaPeer dir (fun _ -> Task.CompletedTask)

                    match result with
                    | Ok() -> failtest "started with a local key and ha_peer on"
                    | Error e ->
                        Expect.stringContains
                            e
                            "modules.tee.ha_peer: every key must sign through the tee module, but the local module holds 1 keystores"
                            "names the local key"
                })

            testT "rescan: a keystore that appears while the VC runs stays unloaded with ha_peer on" (fun () ->
                task {
                    let dir = tempDir ()

                    let! result, ran =
                        runHaPeerWith dir (fun h lines core ->
                            task {
                                LocalModule.ManagedStore.save core.DataDir (pubkeyOf 3) (keystoreOf 3) "pw"
                                let file = LocalModule.ManagedStore.keystoreFile core.DataDir (pubkeyOf 3)
                                let errors () = lines |> Seq.filter (fun l -> l.Contains file) |> List.ofSeq
                                // The directory check runs every 12 s of the fake clock.
                                let mutable tries = 0

                                while (errors ()).IsEmpty && tries < 200 do
                                    h.Time.Advance(TimeSpan.FromSeconds 13.0)
                                    do! Task.Delay 25
                                    tries <- tries + 1

                                // Two more checks: the file stays out and the error is not repeated.
                                for _ in 1..2 do
                                    h.Time.Advance(TimeSpan.FromSeconds 13.0)
                                    do! Task.Delay 200

                                match errors () with
                                | [ line ] ->
                                    Expect.stringContains line "ERROR" "an error"
                                    Expect.stringContains line "modules.tee.ha_peer is on" "names the reason"
                                | other -> failtestf "want one error naming the file: %A" other

                                match core.Keystores() with
                                | ValueSome store -> Expect.isEmpty (store.List()) "not loaded"
                                | ValueNone -> failtest "no keystore store"

                                Expect.isEmpty core.Registry.All "no key registered"
                            })

                    Expect.isTrue ran $"the VC got ready: %A{result}"
                })

            testT "keymanager: keystore and remote key imports are refused with ha_peer on" (fun () ->
                task {
                    let dir = tempDir ()

                    let! result, ran =
                        runHaPeer dir (fun core ->
                            task {
                                match core.Keystores() with
                                | ValueNone -> failtest "no keystore store"
                                | ValueSome store ->
                                    let! statuses = store.Import [ keystoreOf 1, "pw" ] CancellationToken.None

                                    Expect.equal
                                        statuses
                                        [
                                            ImportStatus.Error
                                                "modules.tee.ha_peer is on: every key must sign through the tee module"
                                        ]
                                        "keystore import"

                                    Expect.isEmpty (store.List()) "nothing imported"

                                match core.RemoteKeys() with
                                | ValueNone -> failtest "no remote key store"
                                | ValueSome store ->
                                    let! statuses =
                                        store.Import
                                            [ pubkeyOf 2, ValueSome "https://w3s.test:9000" ]
                                            CancellationToken.None

                                    Expect.equal
                                        statuses
                                        [
                                            ImportStatus.Error
                                                "modules.tee.ha_peer is on: every key must sign through the tee module"
                                        ]
                                        "remote key import"

                                    Expect.isEmpty (store.List()) "nothing imported"

                                Expect.isEmpty core.Registry.All "no key registered"
                            })

                    Expect.isTrue ran $"the VC got ready: %A{result}"
                })

            test "the tee module reads ha_peer: default false, true, and not a boolean refused" {
                let dir = tempDir ()

                let cfg (extra: string) =
                    """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                       "keys": [ "0x"""
                    + String('a', 96)
                    + "\" ]"
                    + extra
                    + " }"

                let settings (extra: string) =
                    let doc = JsonDocument.Parse(cfg extra)

                    TeeModule.parseSettings
                        {
                            Element = ValueSome doc.RootElement
                            BaseDir = dir
                            Mainnet = false
                        }

                match settings "" with
                | Ok s -> Expect.isFalse s.HaPeer "default false"
                | Error e -> failtestf "%A" e

                match settings """, "ha_peer": true""" with
                | Ok s -> Expect.isTrue s.HaPeer "true"
                | Error e -> failtestf "%A" e

                Expect.isError (settings """, "ha_peer": "yes" """) "not a boolean"
            }
        ]
