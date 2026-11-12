/// The local module's directory check in the whole VC, on the fake clock: a keystore written
/// while running is loaded, one removed is retired, and a file that fails is tried again only
/// after it changes.
module Eplix.Tests.RescanTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

/// The VC with one keystore source: `keys` as files in `dir/keys` with a password file, or with
/// `lodestar`, in a Lodestar layout at `dir/ls` (keystores and secrets dirs). Returns the source's
/// keystore dir with the rest.
let private startWith (h: Harness) (dir: string) (keys: int list) (lodestar: bool) =
    task {
        let ksDir, source =
            if lodestar then
                let root = Path.Combine(dir, "ls")

                for i in keys do
                    LocalModule.ManagedStore.save root (pubkeyOf i) (MetricsTests.keystoreOf i "pw") "pw"

                (LocalModule.ManagedStore.source root).Path,
                $"""{{ "path": "{(LocalModule.ManagedStore.source root).Path}", "layout": "lodestar" }}"""
            else
                let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                for i in keys do
                    File.WriteAllText(Path.Combine(ksDir, $"k{i}.json"), MetricsTests.keystoreOf i "pw")

                File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                ksDir, """{ "path": "keys", "password_file": "password.txt" }"""

        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
        let modules = [ LocalModule.create () ]

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "allow_start_without_history": ["all"],
                 "modules": { "local": { "keystores": [ {{source}} ], "reload_interval_seconds": 6 } } }"""

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
                failtestf
                    "the VC did not start: %A\n%s"
                    (if run.IsCompleted then box run.Result else box "timeout")
                    (String.Join("\n", lines))

            return ready.Task.Result, run, cts, lines, ksDir
    }

let private start (h: Harness) (dir: string) (keys: int list) = startWith h dir keys false

let private count (lines: Collections.Concurrent.ConcurrentQueue<string>) (part: string) =
    lines |> Seq.filter (fun l -> l.Contains part) |> Seq.length

/// Moves the clock a check interval at a time until `cond` holds (real time 20 s at most).
let private passUntil
    (h: Harness)
    (lines: Collections.Concurrent.ConcurrentQueue<string>)
    (what: string)
    (cond: unit -> bool)
    =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            h.Time.Advance(TimeSpan.FromSeconds 6.0)
            do! Task.Delay 50

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what (String.Join("\n", lines))
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "local rescan"
        [
            testT
                "a new keystore loads, a removed one retires, a failed one is tried again only after a change"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        let dir = tempDir ()
                        let! core, run, cts, lines, ksDir = start h dir [ 0; 1 ]
                        use _ = cts
                        Expect.equal (core.Registry.Active.Length) 2 "two keys at start"
                        File.WriteAllText(Path.Combine(ksDir, "k2.json"), MetricsTests.keystoreOf 2 "pw")

                        do!
                            passUntil h lines "k2 added" (fun () ->
                                count lines "k2.json" > 0 && count lines "added from" = 1)
                        // A keystore with the wrong password fails once and is not tried again while unchanged.
                        File.WriteAllText(Path.Combine(ksDir, "k3.json"), MetricsTests.keystoreOf 3 "other")
                        do! passUntil h lines "k3 fails" (fun () -> count lines "k3.json" > 0)
                        let failures = count lines "k3.json"
                        // A file written later shows that later checks ran.
                        File.WriteAllText(Path.Combine(ksDir, "k0-copy.json"), MetricsTests.keystoreOf 0 "pw")
                        do! passUntil h lines "the copy" (fun () -> count lines "k0-copy.json" > 0)
                        h.Time.Advance(TimeSpan.FromSeconds 6.0)
                        do! Task.Delay 200

                        Expect.equal
                            (count lines "k3.json")
                            failures
                            "the failed file is not tried again while unchanged"

                        Expect.equal (count lines "added from") 1 "a copy of a loaded key adds nothing"
                        // The right password now: a changed file is tried again.
                        File.WriteAllText(Path.Combine(ksDir, "k3.json"), MetricsTests.keystoreOf 3 "pw")
                        File.SetLastWriteTimeUtc(Path.Combine(ksDir, "k3.json"), DateTime.UtcNow.AddMinutes 1.0)
                        do! passUntil h lines "k3 added" (fun () -> count lines "added from" = 2)
                        File.Delete(Path.Combine(ksDir, "k1.json"))
                        do! passUntil h lines "k1 retired" (fun () -> count lines "removing the key" = 1)
                        Expect.equal (core.Registry.Active.Length) 3 "keys 0, 2 and 3"
                        cts.Cancel()
                        let! r = run
                        Expect.isOk r "clean stop"
                    })

            testT "a password file that cannot be read fails only its key, and is tried again" (fun () ->
                task {
                    if OperatingSystem.IsWindows() then
                        skiptest "needs Unix file modes"

                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()
                    let! core, run, cts, lines, _ = startWith h dir [ 0 ] true
                    use _ = cts
                    let root = Path.Combine(dir, "ls")

                    for i in 1..3 do
                        LocalModule.ManagedStore.save root (pubkeyOf i) (MetricsTests.keystoreOf i "pw") "pw"

                    let secret = LocalModule.ManagedStore.secretFile root (pubkeyOf 2)
                    File.SetUnixFileMode(secret, UnixFileMode.None)
                    do! passUntil h lines "keys 1 and 3" (fun () -> count lines "added from" = 2)
                    Expect.equal (count lines "cannot be read") 1 "the unreadable file is named"

                    for _ in 1..3 do
                        h.Time.Advance(TimeSpan.FromSeconds 6.0)
                        do! Task.Delay 100

                    Expect.equal (count lines "cannot be read") 1 "warned once while the error is the same"
                    Expect.equal (count lines "directory check failed") 0 "the check itself does not fail"
                    // A mode change keeps the write time; the file is tried again anyway.
                    File.SetUnixFileMode(secret, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
                    do! passUntil h lines "key 2" (fun () -> count lines "added from" = 3)
                    Expect.equal (core.Registry.Active.Length) 4 "all four keys"
                    cts.Cancel()
                    let! r = run
                    Expect.isOk r "clean stop"
                })

            testT "a copy skipped as a duplicate loads when the original file goes" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..1 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()
                    let! core, run, cts, lines, ksDir = start h dir [ 0; 1 ]
                    use _ = cts
                    File.WriteAllText(Path.Combine(ksDir, "k0-copy.json"), MetricsTests.keystoreOf 0 "pw")
                    do! passUntil h lines "the copy skipped" (fun () -> count lines "k0-copy.json" > 0)
                    Expect.equal (count lines "added from") 0 "the copy adds nothing while the original is there"
                    File.Delete(Path.Combine(ksDir, "k0.json"))
                    do! passUntil h lines "key 0 retired" (fun () -> count lines "removing the key" = 1)

                    do!
                        passUntil h lines "the copy loaded" (fun () ->
                            lines |> Seq.exists (fun l -> l.Contains "added from" && l.Contains "k0-copy.json"))

                    Expect.equal (core.Registry.Active.Length) 2 "keys 0 and 1"
                    cts.Cancel()
                    let! r = run
                    Expect.isOk r "clean stop"
                })

            testT
                "a halted key stays halted when its keystore goes and comes back, and when the API deletes and imports it"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..2 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        let dir = tempDir ()
                        let! core, run, cts, lines, ksDir = start h dir [ 0; 1 ]
                        use _ = cts

                        let halted i =
                            match (core.Registry.TryGet(pubkeyOf i)).Value.State with
                            | KeyState.Halted _ -> true
                            | _ -> false

                        core.Registry.SetState(pubkeyOf 1, KeyState.Halted "the signer refused a vote as slashable")
                        File.Delete(Path.Combine(ksDir, "k1.json"))

                        do!
                            passUntil h lines "the halted key kept" (fun () ->
                                count lines "stays loaded and halted" = 1)

                        File.WriteAllText(Path.Combine(ksDir, "k1.json"), MetricsTests.keystoreOf 1 "pw")

                        for _ in 1..3 do
                            h.Time.Advance(TimeSpan.FromSeconds 6.0)
                            do! Task.Delay 100

                        Expect.isTrue (halted 1) "halted after the keystore came back"
                        Expect.equal (count lines "stays loaded and halted") 1 "one warning"
                        // The keymanager API: a managed key, halted, then deleted and imported again.
                        let store = core.Keystores().Value
                        let! imported = store.Import [ MetricsTests.keystoreOf 2 "pw", "pw" ] CancellationToken.None
                        Expect.equal imported [ ImportStatus.Imported ] "imported"
                        do! core.RefreshKeys CancellationToken.None
                        core.Registry.SetState(pubkeyOf 2, KeyState.Active)
                        core.Registry.SetState(pubkeyOf 2, KeyState.Halted "the signer refused a vote as slashable")
                        let! deleted = store.Delete [ pubkeyOf 2 ] CancellationToken.None

                        Expect.isTrue
                            (match deleted with
                             | [ DeleteStatus.Error m ] -> m.Contains "halted"
                             | _ -> false)
                            $"refused: %A{deleted}"

                        let! again = store.Import [ MetricsTests.keystoreOf 2 "pw", "pw" ] CancellationToken.None
                        Expect.equal again [ ImportStatus.Duplicate ] "still loaded"
                        Expect.isTrue (halted 2) "halted after the delete and import"
                        cts.Cancel()
                        let! r = run
                        Expect.isOk r "clean stop"
                    })

            for lodestar in [ false; true ] do
                testT
                    $"a source that fails to read keeps its keys, with one warning (lodestar layout: {lodestar})"
                    (fun () ->
                        task {
                            let h = harness ()

                            for i in 0..1 do
                                h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                            let dir = tempDir ()
                            let! core, run, cts, lines, ksDir = startWith h dir [ 0; 1 ] lodestar
                            use _ = cts
                            Expect.equal (core.Registry.Active.Length) 2 "two keys at start"
                            Directory.Move(ksDir, ksDir + ".away")
                            do! passUntil h lines "the warning" (fun () -> count lines "stay loaded" > 0)

                            for _ in 1..3 do
                                h.Time.Advance(TimeSpan.FromSeconds 6.0)
                                do! Task.Delay 100

                            Expect.equal (count lines "stay loaded") 1 "warned once while the error is the same"

                            Expect.isTrue
                                (lines |> Seq.exists (fun l -> l.Contains "stay loaded" && l.StartsWith "WARN"))
                                $"""at warn level: {String.Join("\n", lines)}"""

                            Expect.equal (count lines "removing the key") 0 "no key retired"
                            Expect.equal (core.Registry.Active.Length) 2 "both keys still active"
                            Directory.Move(ksDir + ".away", ksDir)
                            do! passUntil h lines "back" (fun () -> count lines "reads again" > 0)
                            Expect.equal (count lines "added from") 0 "nothing loaded twice"
                            cts.Cancel()
                            let! r = run
                            Expect.isOk r "clean stop"
                        })
        ]
