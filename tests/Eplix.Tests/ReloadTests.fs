/// Key reload without restart: the whole VC through Runner, keystores added and removed while it runs.
module Eplix.Tests.ReloadTests

open System
open System.IO
open System.Net.Http
open System.Threading
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private keystore (i: int) (pw: string) =
    Keystore.encrypt (secretOf i) pw (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) ""

[<Tests>]
let tests =
    testSequenced
    <| testList
        "reload"
        [
            testT "keys added to and removed from the key directories while running" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    for i in 0..1 do
                        File.WriteAllText(Path.Combine(ksDir, $"k{i}.json"), keystore i "pw")

                    File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

                    let configText =
                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                       "use_events": false, "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ],
                                               "reload_interval_seconds": 6 } } }"""

                    let modules = [ LocalModule.create () ]

                    match
                        Config.parse configText dir [ "local" ]
                        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                    with
                    | Error es -> failtestf "%A" es
                    | Ok config ->
                        use cts = new CancellationTokenSource()
                        let log, lines = Log.memory ()

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

                        let spe = uint64 slotsPerEpoch
                        do! h.RunSlots(0UL, spe - 1UL)
                        let attesters () = h.Node.Submissions |> Seq.map (fun s -> s.AttesterIndex) |> Set.ofSeq
                        Expect.equal (attesters ()) (set [ 0UL; 1UL ]) "epoch 0: the two configured keys"
                        // Add key 2 to the managed store (as an import does) and remove key 0's file.
                        let data = Path.Combine(dir, "data")
                        LocalModule.ManagedStore.save data (pubkeyOf 2) (keystore 2 "two") "two"
                        File.Delete(Path.Combine(ksDir, "k0.json"))
                        h.Node.Submissions.Clear()
                        do! h.RunSlots(spe, 3UL * spe - 1UL)

                        let epoch2 =
                            h.Node.Submissions
                            |> Seq.filter (fun s -> s.Slot >= 2UL * spe)
                            |> Seq.map (fun s -> s.AttesterIndex)
                            |> Set.ofSeq

                        Expect.equal
                            epoch2
                            (set [ 1UL; 2UL ])
                            $"epoch 2: key 2 added, key 0 gone; log: {String.Join('\n', lines)}"

                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"
                })

            testT "migration: keys from Lighthouse and Teku with their interchange files" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()

                    for i in 0..2 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Lighthouse data dir with key 0; Teku key dir with key 1; key 2 without history.
                    let lh = Path.Combine(dir, "lighthouse")
                    Directory.CreateDirectory(Path.Combine(lh, "validators", (pubkeyOf 0).Hex)) |> ignore
                    Directory.CreateDirectory(Path.Combine(lh, "secrets")) |> ignore

                    File.WriteAllText(
                        Path.Combine(lh, "validators", (pubkeyOf 0).Hex, "voting-keystore.json"),
                        keystore 0 "lh"
                    )

                    File.WriteAllText(Path.Combine(lh, "secrets", (pubkeyOf 0).Hex), "lh")
                    let teku = Directory.CreateDirectory(Path.Combine(dir, "teku")).FullName
                    File.WriteAllText(Path.Combine(teku, "v1.json"), keystore 1 "tk")
                    File.WriteAllText(Path.Combine(teku, "v1.txt"), "tk")
                    let other = Directory.CreateDirectory(Path.Combine(dir, "other")).FullName
                    File.WriteAllText(Path.Combine(other, "v2.json"), keystore 2 "o")
                    File.WriteAllText(Path.Combine(other, "v2.txt"), "o")
                    // Key 0 already voted for target 0 in Lighthouse; key 1 only proposed at slot 0 in
                    // Teku. An entry with nothing signed would give it no record.
                    let interchange (i: int) blocks (atts: Slashing.InterchangeAttestation list) =
                        Slashing.Interchange.write
                            {
                                GenesisValidatorsRoot = gvr
                                Data =
                                    [
                                        {
                                            PubKey = pubkeyOf i
                                            SignedBlocks = blocks
                                            SignedAttestations = atts
                                        }
                                    ]
                            }

                    File.WriteAllBytes(
                        Path.Combine(dir, "lh.json"),
                        interchange
                            0
                            []
                            [
                                {
                                    SourceEpoch = 0UL
                                    TargetEpoch = 0UL
                                    SigningRoot = ValueNone
                                }
                            ]
                    )

                    File.WriteAllBytes(
                        Path.Combine(dir, "teku.json"),
                        interchange 1 [ { Slot = 0UL; SigningRoot = ValueNone } ] []
                    )

                    let data = Path.Combine(dir, "data")
                    Directory.CreateDirectory data |> ignore

                    let importOne (src: string) (file: string option) =
                        match file with
                        | Some f ->
                            use mf = new Slashing.FileMarkFile(Path.Combine(data, "slashing.db"))

                            match Slashing.SlashingDb.Open(mf, gvr) with
                            | Ok db ->
                                Expect.isOk
                                    (db.Import(
                                        Result.defaultWith failwith (Slashing.Interchange.parse (File.ReadAllBytes f))
                                    ))
                                    "interchange"
                            | Error e -> failtest e
                        | None -> ()

                        match
                            ImportKeys.run
                                data
                                {
                                    Path = src
                                    PasswordFile = ValueNone
                                    Layout = ValueNone
                                }
                                2
                        with
                        | Ok r ->
                            Expect.equal r.Imported.Length 1 $"one key from {src}"
                            r.Layout
                        | Error e -> failtest e

                    Expect.equal
                        (importOne lh (Some(Path.Combine(dir, "lh.json"))))
                        Layouts.Layout.Lighthouse
                        "detected Lighthouse"

                    Expect.equal
                        (importOne teku (Some(Path.Combine(dir, "teku.json"))))
                        Layouts.Layout.Teku
                        "detected Teku"

                    Expect.equal (importOne other None) Layouts.Layout.Teku "a third key, no history"
                    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

                    let configText =
                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                       "modules": { "local": { } } }"""

                    let modules = [ LocalModule.create () ]

                    match
                        Config.parse configText dir [ "local" ]
                        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                    with
                    | Error es -> failtestf "%A" es
                    | Ok config ->
                        use cts = new CancellationTokenSource()
                        let log, lines = Log.memory ()

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

                        do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))
                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"

                        let by i =
                            h.Node.Submissions
                            |> Seq.filter (fun s -> s.AttesterIndex = uint64 i)
                            |> Seq.map (fun s -> s.Data.Target.Epoch)
                            |> List.ofSeq

                        Expect.equal
                            (by 0)
                            [ 1UL ]
                            $"Lighthouse key: target 0 refused (already voted), target 1 signed; log: {String.Join('\n', lines)}"

                        Expect.equal (by 1) [ 0UL; 1UL ] "Teku key: both epochs"
                        Expect.equal (by 2) [] "a key without history does not sign"
                })
        ]
