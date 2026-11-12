/// Refusal states from HEALTH: the state table, HEALTH at a new connection
/// and each epoch, the skip of a runner that refuses, a refusing group member, a failed HEALTH
/// call, and a property that no runner in a non-ready state gets a slashable kind.
module Eplix.Tests.TeeHealthTests

open System
open System.Collections.Concurrent
open System.Text
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.SchedulerTests
open Eplix.Tests.TeeTests

let private health (json: string) = Wire.decodeHealth (Encoding.UTF8.GetBytes json)

let private att (target: uint64) =
    {
        Slot = target * 8UL
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = target - 1UL; Root = root 4 }
        Target = { Epoch = target; Root = root 5 }
    }

/// A log that keeps its lines.
let private capture () =
    let lines = ConcurrentQueue<LogLevel * string>()

    let log: Log =
        {
            Write = (fun l m -> lines.Enqueue(l, m))
            MinLevel = LogLevel.Debug
        }

    log, lines

let private waitUntil (what: string) (cond: unit -> bool) =
    let sw = Diagnostics.Stopwatch.StartNew()

    while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
        Thread.Sleep 5

    Expect.isTrue (cond ()) what

/// One runner holding one whole key, its endpoint at `epoch`, and the backend over it.
let private single (name: string) (log: Log) (epoch: uint64 ref) =
    let secret = secretOf 501
    let r = FakeRunner(name, [ pk secret, secret ])
    let x = RunnerEndpoint(r.Api, log)
    x.EpochNow <- fun () -> ValueSome epoch.Value
    (x.Refresh CancellationToken.None).GetAwaiter().GetResult() |> ignore
    r, x, x.WholeKeys $"tee {name}", pk secret

let private signAtt (r: FakeRunner) (b: Backend) (key: PubKey) (target: uint64) =
    let req = request key (Duty.Attestation(att target))
    r.Expect req
    b.Sign req CancellationToken.None

[<Tests>]
let tests =
    testList
        "tee health"
        [
            testList
                "state table"
                [
                    test "each HEALTH form maps to one state" {
                        let at (json: string) = HealthStates.classify (health json)
                        let label json = HealthStates.label (at json)

                        Expect.equal
                            (at """{"protocol":2,"platform":"dev","ready":true}""")
                            RunnerSignState.Ready
                            "ready"

                        Expect.equal (label "{}") "protocol_too_old" "no field at all: protocol level 1"

                        for json, want in
                            [
                                """{"protocol":2,"ready":false,"mark_log_lost":"mark file missing at boot"}""",
                                "log_lost"
                                """{"protocol":2,"ready":false,"image":{"state":"not_allowed","kind":"nitro","why":"pcr0 not on the allowlist"}}""",
                                "image_not_allowed"
                                """{"protocol":2,"ready":false,"image":{"state":"unknown"}}""", "image_unknown"
                                """{"protocol":2,"ready":false,"image":{"state":"restart_needed","locked_version":4}}""",
                                "image_restart_needed"
                                """{"protocol":2,"ready":true,"image":{"state":"unknown"}}""", "image_unknown"
                                """{"protocol":2,"ready":false,"request_panic":"index out of range"}""", "request_panic"
                                """{"protocol":2,"ready":true,"request_panic":"index out of range"}""", "request_panic"
                                """{"protocol":2,"ready":false,"key_lock":"locked","key_lock_why":"KMS refused the key release"}""",
                                "not_ready"
                                """{"protocol":2,"ready":false}""", "not_ready"
                                """{"ready":true}""", "protocol_too_old"
                                """{"protocol":1,"ready":true}""", "protocol_too_old"
                                """{"protocol":0,"ready":true}""", "protocol_too_old"
                                """{"protocol":"2","ready":true}""", "protocol_too_old"
                                """{"protocol":1,"ready":false}""", "protocol_too_old"
                                """{"protocol":1,"ready":false,"mark_log_lost":"lost"}""", "log_lost"
                            ] do
                            Expect.equal (label json) want json

                        for json in
                            [
                                """{"protocol":2,"ready":true,"mark_log_lost":"","request_panic":"","key_lock":"not_locked","key_lock_why":"","image":{"state":"allowed","kind":"nitro"}}"""
                                """{"protocol":2,"ready":true,"image":{"state":"not_applicable"}}"""
                                """{"protocol":2,"ready":true,"image":{"state":"override","why":"testnet override"}}"""
                                """{"protocol":2,"ready":true,"key_lock":"locked","key_lock_why":"locked until the setup is approved"}"""
                                """{"protocol":2,"ready":true,"key_lock":"none"}"""
                                """{"protocol":2,"ready":true,"key_lock":"unread"}"""
                                """{"protocol":2,"ready":true,"handed_over":true}"""
                                """{"protocol":3,"ready":true}"""
                            ] do
                            Expect.equal (at json) RunnerSignState.Ready json

                        Expect.isTrue
                            (match at """{"protocol":2,"mark_log_lost":"gone"}""" with
                             | RunnerSignState.Gone _ -> true
                             | _ -> false)
                            "mark_log_lost is gone"

                        Expect.isTrue
                            (match at """{"protocol":2,"image":{"state":"not_allowed"}}""" with
                             | RunnerSignState.Refusing _ -> true
                             | _ -> false)
                            "an image not allowed refuses"

                        match
                            at
                                """{"protocol":2,"ready":false,"key_lock":"locked","key_lock_why":"KMS refused the key release"}"""
                        with
                        | RunnerSignState.Refusing(_, why) ->
                            Expect.stringContains why "KMS refused the key release" "key_lock_why explains ready false"
                        | s -> failtestf "%s" (HealthStates.label s)

                        match
                            at """{"protocol":2,"image":{"state":"not_allowed","why":"pcr0 not on the allowlist"}}"""
                        with
                        | RunnerSignState.Refusing(_, why) ->
                            Expect.stringContains why "pcr0 not on the allowlist" "image.why"
                        | s -> failtestf "%s" (HealthStates.label s)

                        Expect.isTrue
                            (HealthStates.imageOverride (health """{"protocol":2,"image":{"state":"override"}}"""))
                            "override seen"

                        Expect.isFalse
                            (HealthStates.imageOverride (health """{"protocol":2,"image":{"state":"allowed"}}"""))
                            "allowed is no override"
                    }
                ]

            testList
                "endpoint"
                [
                    testT
                        "a refusing runner gets no SIGN until HEALTH says it signs; HEALTH runs at a new connection"
                        (fun () ->
                            task {
                                let log, lines = capture ()
                                let epoch = ref 5UL
                                let r, x, b, key = single "h-refuse" log epoch
                                let! o1 = signAtt r b key 5UL

                                Expect.isTrue
                                    (verifies key (request key (Duty.Attestation(att 5UL))) o1)
                                    $"ready: {o1.Describe}"

                                r.SetHealth
                                    """{"protocol":2,"ready":false,"key_lock":"locked","key_lock_why":"KMS refused the key release"}"""

                                r.Connect()

                                waitUntil "HEALTH read at the new connection" (fun () ->
                                    HealthStates.label x.State = "not_ready")

                                let before = r.SignCalls
                                let! o2 = signAtt r b key 6UL
                                Expect.equal r.SignCalls before "no SIGN to a refusing runner"

                                Expect.isTrue
                                    (match o2 with
                                     | Failed(Unavailable m) -> m.Contains "KMS refused"
                                     | _ -> false)
                                    $"unavailable: {o2.Describe}"

                                let! h = b.Health CancellationToken.None

                                Expect.isTrue
                                    (match h with
                                     | Down m -> m.Contains "not_ready"
                                     | _ -> false)
                                    $"down: {h}"

                                Expect.contains
                                    (Metrics.signerStatesNow ())
                                    ("h-refuse", "not_ready")
                                    "eplix_signer_state"

                                r.SetHealth """{"protocol":2,"ready":true}"""
                                epoch.Value <- 6UL
                                x.OnEpoch 6UL
                                waitUntil "HEALTH read at the epoch" (fun () -> x.State = RunnerSignState.Ready)
                                let! o3 = signAtt r b key 7UL
                                Expect.equal r.SignCalls (before + 1) "signs again"

                                Expect.isTrue
                                    (match o3 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    o3.Describe

                                Expect.contains (Metrics.signerStatesNow ()) ("h-refuse", "ready") "back to ready"
                                let logged = [ for _, m in lines -> m ]

                                Expect.exists
                                    logged
                                    (fun m -> m.Contains "h-refuse" && m.Contains "not_ready")
                                    "the change is logged"

                                Expect.exists
                                    logged
                                    (fun m -> m.Contains "h-refuse" && m.Contains "signs again")
                                    "the recovery is logged"
                            })

                    testT
                        "a gone runner (log lost) gets nothing, says so to the operator, and is down until HEALTH says otherwise"
                        (fun () ->
                            task {
                                let log, lines = capture ()
                                let epoch = ref 5UL
                                let r, x, b, key = single "h-gone" log epoch
                                let losses () = Metrics.markLogLostNow () |> List.filter (fst >> (=) "h-gone")
                                Expect.equal (losses ()) [ "h-gone", 0L ] "the counter starts at 0"

                                r.SetHealth
                                    """{"protocol":2,"ready":false,"mark_log_lost":"mark file missing at boot"}"""

                                do! x.PollHealth CancellationToken.None

                                Expect.equal
                                    (losses ())
                                    [ "h-gone", 1L ]
                                    "eplix_signer_mark_log_lost counts the change"

                                do! x.PollHealth CancellationToken.None
                                Expect.equal (losses ()) [ "h-gone", 1L ] "the same state again counts nothing"
                                let! o = signAtt r b key 5UL
                                Expect.equal r.SignCalls 0 "no SIGN"

                                Expect.isTrue
                                    (match o with
                                     | Failed(Gone _) -> true
                                     | _ -> false)
                                    o.Describe

                                let! h = b.Health CancellationToken.None

                                Expect.isTrue
                                    (match h with
                                     | Down m -> m.Contains "gone"
                                     | _ -> false)
                                    $"down: {h}"

                                Expect.exists
                                    [ for l, m in lines -> l, m ]
                                    (fun (l, m) -> l = LogLevel.Error && m.Contains "remove the runner or its keys")
                                    "the operator message for a gone runner"

                                r.SetHealth """{"protocol":2,"ready":true}"""
                                do! x.PollHealth CancellationToken.None
                                let! o2 = signAtt r b key 6UL

                                Expect.isTrue
                                    (match o2 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    o2.Describe

                                r.SetHealth
                                    """{"protocol":2,"ready":false,"mark_log_lost":"mark file missing again"}"""

                                do! x.PollHealth CancellationToken.None
                                Expect.equal (losses ()) [ "h-gone", 2L ] "a second loss after ready counts again"
                            })

                    testT
                        "protocol level: missing and 1 get nothing with one error, 2 signs, 3 signs with one warning"
                        (fun () ->
                            task {
                                for level, json in
                                    [ "missing", """{"ready":true}"""; "1", """{"protocol":1,"ready":true}""" ] do
                                    let log, lines = capture ()
                                    let epoch = ref 5UL
                                    let name = $"h-proto-{level}"
                                    let r, x, b, key = single name log epoch
                                    r.SetHealth json
                                    do! x.PollHealth CancellationToken.None
                                    do! x.PollHealth CancellationToken.None
                                    // HEALTH fails past an epoch: the runner keeps protocol_too_old
                                    // and gets nothing, since no answer has shown level 2.
                                    r.SetHealthReply(Reply.Failure(Transport "connection reset"))
                                    epoch.Value <- 6UL
                                    do! x.PollHealth CancellationToken.None
                                    epoch.Value <- 7UL
                                    do! x.PollHealth CancellationToken.None

                                    Expect.equal
                                        (HealthStates.label x.State)
                                        "protocol_too_old"
                                        $"{level}: still protocol_too_old after a failed epoch"

                                    let! failedHealth = signAtt r b key 7UL
                                    Expect.equal r.SignCalls 0 $"{level}: no SIGN while HEALTH fails"

                                    Expect.isTrue
                                        (match failedHealth with
                                         | Failed(Unavailable _) -> true
                                         | _ -> false)
                                        $"{level}: unavailable while HEALTH fails: {failedHealth.Describe}"

                                    r.SetHealth json
                                    do! x.PollHealth CancellationToken.None
                                    Expect.equal (HealthStates.label x.State) "protocol_too_old" level
                                    let! o = signAtt r b key 8UL
                                    Expect.equal r.SignCalls 0 $"{level}: no SIGN"

                                    Expect.isTrue
                                        (match o with
                                         | Failed(Unavailable m) -> m.Contains "protocol level 1"
                                         | _ -> false)
                                        $"{level}: unavailable: {o.Describe}"

                                    let! h = b.Health CancellationToken.None

                                    Expect.isTrue
                                        (match h with
                                         | Down m -> m.Contains "protocol_too_old"
                                         | _ -> false)
                                        $"{level}: down: {h}"

                                    Expect.contains
                                        (Metrics.signerStatesNow ())
                                        (name, "protocol_too_old")
                                        $"{level}: eplix_signer_state"

                                    let errors =
                                        [
                                            for l, m in lines do
                                                if l = LogLevel.Error then
                                                    m
                                        ]

                                    Expect.equal errors.Length 1 $"{level}: one error: {errors}"
                                    Expect.stringContains errors.Head name $"{level}: names the runner"
                                    Expect.stringContains errors.Head "protocol level 1" $"{level}: names its level"

                                    Expect.stringContains
                                        errors.Head
                                        "needs tee-signer protocol level 2 (FLOOR/FLOOR_UNPROVEN)"
                                        $"{level}: names the level needed"

                                for level in [ 2; 3 ] do
                                    let log, lines = capture ()
                                    let epoch = ref 5UL
                                    let r, x, b, key = single $"h-proto-{level}" log epoch
                                    r.SetHealth("{\"protocol\":" + string level + ",\"ready\":true}")
                                    do! x.PollHealth CancellationToken.None
                                    do! x.PollHealth CancellationToken.None
                                    Expect.equal x.State RunnerSignState.Ready $"level {level}: ready"
                                    let! o = signAtt r b key 5UL

                                    Expect.isTrue
                                        (match o with
                                         | Signed _ -> true
                                         | _ -> false)
                                        $"level {level}: signs: {o.Describe}"

                                    let warned =
                                        [
                                            for l, m in lines do
                                                if l >= LogLevel.Warn && m.Contains "protocol level" then
                                                    m
                                        ]

                                    Expect.equal
                                        warned.Length
                                        (if level = 3 then 1 else 0)
                                        $"level {level}: warnings {warned}"
                            })

                    testT
                        "before its first HEALTH answer a runner gets no SIGN; the first request asks HEALTH and waits for it"
                        (fun () ->
                            task {
                                // A level 1 runner, never polled: the first request reads HEALTH
                                // and goes nowhere.
                                let epoch = ref 5UL
                                let r1, x1, b1, key1 = single "h-first-1" Log.none epoch
                                r1.SetHealth """{"protocol":1,"ready":true}"""
                                let! o1 = signAtt r1 b1 key1 5UL
                                Expect.equal r1.SignCalls 0 "level 1, not polled: no SIGN"

                                Expect.isTrue
                                    (match o1 with
                                     | Failed(Unavailable m) -> m.Contains "protocol level 1"
                                     | _ -> false)
                                    $"level 1, not polled: {o1.Describe}"

                                Expect.equal
                                    (HealthStates.label x1.State)
                                    "protocol_too_old"
                                    "read at the first request"

                                // A level 2 runner, never polled: the first request signs.
                                let r2, x2, b2, key2 = single "h-first-2" Log.none epoch
                                let! o2 = signAtt r2 b2 key2 5UL

                                Expect.isTrue
                                    (match o2 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"level 2, not polled: signs: {o2.Describe}"

                                Expect.equal (HealthStates.label x2.State) "ready" "ready after the first answer"

                                // HEALTH fails from the start, also past an epoch: no SIGN.
                                let r3, x3, b3, key3 = single "h-first-3" Log.none epoch
                                r3.SetHealthReply(Reply.Failure(Transport "connection reset"))
                                let! o3 = signAtt r3 b3 key3 5UL
                                epoch.Value <- 6UL
                                do! x3.PollHealth CancellationToken.None
                                epoch.Value <- 7UL
                                do! x3.PollHealth CancellationToken.None
                                let! o4 = signAtt r3 b3 key3 7UL
                                Expect.equal r3.SignCalls 0 "no HEALTH answer: no SIGN"

                                for o in [ o3; o4 ] do
                                    Expect.isTrue
                                        (match o with
                                         | Failed(Unavailable _) -> true
                                         | _ -> false)
                                        $"no HEALTH answer: {o.Describe}"

                                Expect.contains
                                    (Metrics.signerStatesNow ())
                                    ("h-first-3", "pending")
                                    "eplix_signer_state says pending"
                            })

                    testT
                        "a new connection makes a ready runner pending until HEALTH answers: a rollback to level 1 gets no SIGN"
                        (fun () ->
                            task {
                                let epoch = ref 5UL
                                let r, x, b, key = single "h-rollback" Log.none epoch
                                do! x.PollHealth CancellationToken.None
                                let! o1 = signAtt r b key 5UL

                                Expect.isTrue
                                    (match o1 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"level 2 signs: {o1.Describe}"

                                // The runner comes back as a level 1 build; its HEALTH answer is slow.
                                let gate = r.HoldHealth()
                                r.SetHealth """{"protocol":1,"ready":true}"""
                                r.Connect()

                                Expect.contains
                                    (Metrics.signerStatesNow ())
                                    ("h-rollback", "pending")
                                    "pending after the new connection"

                                let pending = signAtt r b key 6UL
                                do! Task.Delay 50
                                Expect.equal r.SignCalls 1 "no SIGN while HEALTH is out"
                                gate.SetResult()
                                let! o2 = pending
                                Expect.equal r.SignCalls 1 "no SIGN to the level 1 build"

                                Expect.isTrue
                                    (match o2 with
                                     | Failed(Unavailable m) -> m.Contains "protocol level 1"
                                     | _ -> false)
                                    $"level 1 after the reconnect: {o2.Describe}"

                                // Back to level 2 on the next connection: the waiting request signs.
                                r.SetHealth """{"protocol":2,"ready":true}"""
                                do! x.PollHealth CancellationToken.None
                                let gate2 = r.HoldHealth()
                                r.Connect()
                                let again = signAtt r b key 7UL
                                do! Task.Delay 50
                                Expect.equal r.SignCalls 1 "the request waits for HEALTH"
                                gate2.SetResult()
                                let! o3 = again

                                Expect.isTrue
                                    (match o3 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"level 2 after the reconnect signs: {o3.Describe}"
                            })

                    testT "a pending runner and a protocol_too_old runner report health Down" (fun () ->
                        task {
                            let epoch = ref 5UL
                            let r, x, b, _ = single "h-health-pending" Log.none epoch
                            Expect.equal (HealthStates.label x.State) "pending" "no HEALTH answer yet"
                            let! h1 = b.Health CancellationToken.None

                            Expect.isTrue
                                (match h1 with
                                 | Down m -> m.Contains "pending"
                                 | _ -> false)
                                $"pending is down: {h1}"

                            r.SetHealth """{"protocol":1,"ready":true}"""
                            do! x.PollHealth CancellationToken.None
                            let! h2 = b.Health CancellationToken.None

                            Expect.isTrue
                                (match h2 with
                                 | Down m -> m.Contains "protocol_too_old"
                                 | _ -> false)
                                $"protocol_too_old is down: {h2}"

                            r.SetHealth """{"protocol":2,"ready":true}"""
                            do! x.PollHealth CancellationToken.None
                            let! h3 = b.Health CancellationToken.None
                            Expect.equal h3 Up "ready is up"
                        })

                    testT
                        "a request that waits for a connection gets no SIGN on the new session of a runner rolled back to level 1"
                        (fun () ->
                            task {
                                let epoch = ref 5UL
                                let r, x, b, key = single "h-waiting" Log.none epoch
                                do! x.PollHealth CancellationToken.None
                                let! o1 = signAtt r b key 5UL

                                Expect.isTrue
                                    (match o1 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"level 2 signs: {o1.Describe}"

                                // The runner restarts as a level 1 build: every connection drops, a
                                // vote waits for a connection, and the new one goes to it.
                                r.DropConnections()
                                r.SetHealth """{"protocol":1,"ready":true}"""
                                let waiting = signAtt r b key 6UL
                                do! Task.Delay 50
                                r.NewConnection()
                                let! o2 = waiting
                                Expect.equal r.SignCalls 1 "no SIGN on the new session before its HEALTH answer"

                                Expect.isTrue
                                    (match o2 with
                                     | Failed(Unavailable m) -> m.Contains "protocol level 1"
                                     | _ -> false)
                                    $"the waiting vote fails as level 1: {o2.Describe}"

                                // Back to level 2: a vote that waits for the next connection signs.
                                r.SetHealth """{"protocol":2,"ready":true}"""
                                do! x.PollHealth CancellationToken.None
                                r.DropConnections()
                                let again = signAtt r b key 7UL
                                do! Task.Delay 50
                                r.NewConnection()
                                let! o3 = again

                                Expect.isTrue
                                    (match o3 with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"level 2 after the reconnect signs: {o3.Describe}"
                            })

                    testT "an image override signs and is logged once" (fun () ->
                        task {
                            let log, lines = capture ()
                            let epoch = ref 5UL
                            let r, x, b, key = single "h-override" log epoch

                            r.SetHealth
                                """{"protocol":2,"ready":true,"image":{"state":"override","why":"testnet override"}}"""

                            do! x.PollHealth CancellationToken.None
                            do! x.PollHealth CancellationToken.None
                            let! o = signAtt r b key 5UL

                            Expect.isTrue
                                (match o with
                                 | Signed _ -> true
                                 | _ -> false)
                                o.Describe

                            let warned =
                                [
                                    for l, m in lines do
                                        if l = LogLevel.Warn && m.Contains "override" then
                                            m
                                ]

                            Expect.equal warned.Length 1 "one warning"
                        })

                    testT
                        "a failed HEALTH call keeps the last state for one epoch, then the state is unknown and requests go"
                        (fun () ->
                            task {
                                let epoch = ref 5UL
                                let r, x, b, key = single "h-unknown" Log.none epoch
                                r.SetHealth """{"protocol":2,"ready":false}"""
                                do! x.PollHealth CancellationToken.None
                                Expect.equal (HealthStates.label x.State) "not_ready" "not ready"
                                r.SetHealthReply(Reply.Failure(Transport "connection reset"))
                                epoch.Value <- 6UL
                                do! x.PollHealth CancellationToken.None

                                Expect.equal
                                    (HealthStates.label x.State)
                                    "not_ready"
                                    "kept in the epoch of the first failure"

                                do! x.PollHealth CancellationToken.None

                                Expect.equal
                                    (HealthStates.label x.State)
                                    "not_ready"
                                    "kept on a second failure in that epoch"

                                epoch.Value <- 7UL
                                do! x.PollHealth CancellationToken.None
                                Expect.equal (HealthStates.label x.State) "unknown" "unknown after an epoch"
                                let! o = signAtt r b key 7UL
                                Expect.equal r.SignCalls 1 "an unknown runner gets requests; its own answer decides"

                                Expect.isTrue
                                    (match o with
                                     | Signed _ -> true
                                     | _ -> false)
                                    o.Describe
                            })
                ]

            testList
                "group"
                [
                    testT
                        "a 2 of 3 group with one member that refuses signs from the other two without sending to it"
                        (fun () ->
                            task {
                                let secret, shares = shamir 931 2 [ 1UL; 2UL; 3UL ]
                                let key = pk secret
                                let runners = [ for m in 0..2 -> FakeRunner($"r{m + 1}", [ key, snd shares[m] ]) ]

                                let runnerCfg (n: string) : TeeModule.RunnerConfig =
                                    {
                                        Name = n
                                        Host = "127.0.0.1"
                                        Port = 1
                                        ClientCert = ""
                                        ClientKey = ""
                                        TlsKeyPin = ValueNone
                                        AllowTestnetBuild = false
                                        Connections = 1
                                        Attestation = Attest.Settings.Empty
                                    }

                                let settings: TeeModule.Settings =
                                    {
                                        Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
                                        Groups =
                                            [
                                                {
                                                    Threshold = 2
                                                    Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                                }
                                            ]
                                        Timeout = TimeSpan.FromSeconds 2.0
                                        DialTimeout = TimeSpan.FromSeconds 5.0
                                        LowEvery = 8
                                        RefreshInterval = TimeSpan.Zero
                                        Keys = TeeModule.KeyFilter.AnyListedTestOnly
                                        AttestationCaFile = ValueNone
                                        ReloadInterval = TimeSpan.Zero
                                        RotateWithin = TimeSpan.FromSeconds 300.0
                                        HaPeer = false
                                        Network = Attest.NetworkKind.Testnet
                                    }

                                let set =
                                    TeeModule.TeeSet(
                                        [ for c, f in List.zip settings.Runners runners -> c, f.Api ],
                                        settings,
                                        TimeProvider.System,
                                        Log.none
                                    )

                                let! found, _ = set.Discover CancellationToken.None
                                let group = (Map.ofList found)[key]
                                let endpoint (n: string) = set.Endpoints |> List.find (fun x -> x.Name = n)
                                // r1 and r2 answer HEALTH (a pending member counts as down).
                                do! (endpoint "r1").PollHealth CancellationToken.None
                                do! (endpoint "r2").PollHealth CancellationToken.None
                                runners[2].SetHealth """{"protocol":2,"ready":false}"""
                                do! (endpoint "r3").PollHealth CancellationToken.None
                                let! h1 = group.Health CancellationToken.None

                                Expect.isTrue
                                    (match h1 with
                                     | Degraded m -> m.Contains "2 of 3 members ready"
                                     | _ -> false)
                                    $"the refusal shows before any request: {h1}"

                                let req = request key (Duty.Attestation(att 9UL))

                                for r in runners do
                                    r.Expect req

                                let! o = group.Sign req CancellationToken.None
                                Expect.isTrue (verifies key req o) $"signed by r1 and r2: {o.Describe}"
                                Expect.equal runners[2].SignCalls 0 "nothing sent to the member that refuses"
                                let sel = request key (Duty.AggregationSlot 72UL)

                                for r in runners do
                                    r.Expect sel

                                let! s = group.Sign sel CancellationToken.None
                                Expect.isTrue (verifies key sel s) $"selection proof: {s.Describe}"
                            })
                ]

            testList
                "property"
                [
                    testPropN "no runner in a non-ready state gets a slashable kind, and a ready one does" 300
                    <| Prop.forAll
                        (Arb.fromGen (
                            gen {
                                let opt (xs: string list) = Gen.elements ("" :: xs)
                                let! ready = opt [ "true"; "false" ]
                                let! lost = opt [ "\"\""; "\"mark file missing\"" ]
                                let! keyLock = opt [ "\"locked\""; "\"not_locked\""; "\"none\""; "\"unread\"" ]
                                let! lock = opt [ "\"\""; "\"kms\"" ]
                                let! panic = opt [ "\"\""; "\"boom\"" ]

                                let! image =
                                    opt
                                        [
                                            for s in
                                                [
                                                    "allowed"
                                                    "not_allowed"
                                                    "restart_needed"
                                                    "unknown"
                                                    "override"
                                                    "not_applicable"
                                                ] -> $"{{\"state\":\"{s}\",\"why\":\"w\"}}"
                                        ]

                                let! epoch = Gen.choose (1, 20) |> Gen.map uint64
                                let! protocol = Gen.elements [ ""; "0"; "1"; "2"; "2"; "2"; "3" ]
                                return ready, lost, keyLock, lock, panic, image, epoch, protocol
                            }
                        ))
                        (fun (ready, lost, keyLock, lock, panic, image, epoch, protocol) ->
                            let fields =
                                [
                                    "protocol", protocol
                                    "ready", ready
                                    "mark_log_lost", lost
                                    "key_lock", keyLock
                                    "key_lock_why", lock
                                    "request_panic", panic
                                    "image", image
                                ]
                                |> List.filter (fun (_, v) -> v <> "")

                            let json = "{" + String.Join(",", [ for n, v in fields -> $"\"{n}\":{v}" ]) + "}"

                            let notReady =
                                (protocol <> "2" && protocol <> "3")
                                || ready = "false"
                                || lost = "\"mark file missing\""
                                || panic = "\"boom\""
                                || image.Contains "\"not_allowed\""
                                || image.Contains "\"restart_needed\""
                                || image.Contains "\"unknown\""

                            let r, x, b, key = single "h-prop" Log.none (ref epoch)
                            r.SetHealth json
                            (x.PollHealth CancellationToken.None).GetAwaiter().GetResult()
                            (signAtt r b key epoch).GetAwaiter().GetResult() |> ignore
                            let sent = r.SignCalls > 0

                            if sent = notReady then
                                failwithf
                                    "%s at epoch %d: sent %b, state %s"
                                    json
                                    epoch
                                    sent
                                    (HealthStates.label x.State)

                            true)
                ]
        ]
