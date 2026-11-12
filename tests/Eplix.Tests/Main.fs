module Eplix.Tests.Main

open System
open System.IO
open Expecto

/// `write-keystores <dir> <count>`: test keystores (the test secrets 0 to count-1, PBKDF2 with 16
/// rounds, password "secret") and pubkeys.txt, for the smoke scripts. Test keys only.
/// The test secret of key i: SchedulerTests.secretOf for i below 255, distinct beyond (that one
/// repeats after 255 keys).
let private secret (i: int) =
    let b = SchedulerTests.secretOf (i % 255)
    b[29] <- byte (i / 255)
    b

let private writeKeystores (dir: string) (count: int) =
    Directory.CreateDirectory dir |> ignore
    let keys = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

    for i in 0 .. count - 1 do
        File.WriteAllText(
            Path.Combine(keys, $"keystore-{i}.json"),
            Eplix.Backend.Local.Keystore.encrypt
                (secret i)
                "secret"
                (Eplix.Backend.Local.Keystore.Pbkdf2(16, Array.create 32 (byte i), 32))
                ""
        )

    File.WriteAllText(Path.Combine(dir, "password.txt"), "secret\n")

    File.WriteAllLines(
        Path.Combine(dir, "pubkeys.txt"),
        [
            for i in 0 .. count - 1 -> Eplix.Hex.encodeArray (Eplix.Bls.publicKey (ReadOnlySpan(secret i)))
        ]
    )

    0

/// Time one test may take before it fails as hung: 300 s, or EPLIX_TEST_LIMIT_SECONDS (the long
/// fuzz runs raise it). A test that never ends would otherwise stall the whole run.
let private limit =
    match Environment.GetEnvironmentVariable "EPLIX_TEST_LIMIT_SECONDS" with
    | null
    | "" -> TimeSpan.FromSeconds 300.0
    | s -> TimeSpan.FromSeconds(float s)

let private bounded (name: string) (work: Async<unit>) =
    async {
        try
            let! child = Async.StartChild(work, int limit.TotalMilliseconds)
            return! child
        with :? TimeoutException ->
            return
                failwithf
                    "%s ran longer than %.0f s (EPLIX_TEST_LIMIT_SECONDS) and counts as hung"
                    name
                    limit.TotalSeconds
    }

/// Every test case under the time limit; lists, labels and states stay as they are.
let rec private withLimit (path: string) (t: Test) : Test =
    match t with
    | TestCase(Sync f, state) -> TestCase(Async(bounded path (async { f () })), state)
    | TestCase(SyncWithCancel f, state) ->
        TestCase(Async(bounded path (async { let! ct = Async.CancellationToken in f ct })), state)
    | TestCase(Async a, state) -> TestCase(Async(bounded path a), state)
    | TestCase(AsyncFsCheck(c1, c2, f), state) -> TestCase(AsyncFsCheck(c1, c2, (fun c -> bounded path (f c))), state)
    | TestList(tests, state) -> TestList(tests |> List.map (withLimit path), state)
    | TestLabel(label, test, state) -> TestLabel(label, withLimit $"{path}/{label}" test, state)
    | Test.Sequenced(s, test) -> Test.Sequenced(s, withLimit path test)

[<EntryPoint>]
let main argv =
    match argv with
    | [| "write-keystores"; dir; count |] -> writeKeystores dir (int count)
    | _ ->
        match Impl.testFromThisAssembly () with
        | Some tests -> Tests.runTestsWithCLIArgs [] argv (withLimit "" tests)
        | None -> 1
