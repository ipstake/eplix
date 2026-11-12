/// Genesis time, genesis validators root and slot timing: pinned for the
/// built-in networks, the same on every node of a chain config file, and checked each epoch.
module Eplix.Tests.ChainAnchorTests

open System
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.RunnerTests

/// The fake chain as a pin: what every fake node reports by default.
let private fakeAnchor: ChainAnchor =
    {
        GenesisTime = genesisTime
        GenesisValidatorsRoot = gvr
        SlotDuration = TimeSpan.FromSeconds(float secondsPerSlot)
        SlotsPerEpoch = uint64 slotsPerEpoch
    }

let private otherRoot = Root.Of(Array.create 32 0x5Auy)

let private options (h: Harness) (log: Log) =
    let config, modules = localVcConfig (localVcDir (configYaml secondsPerSlot slotsPerEpoch))

    {
        Config = config
        Modules = modules
        Http = new HttpClient(h.Node, false)
        Time = h.Time
        Log = log
        OnSlotDone = h.Waiter.Done
        OnReady = fun _ _ -> ()
    }

let private pinnedFake = ChainSpec.parseConfigYaml (configYaml secondsPerSlot slotsPerEpoch)

let private client (node: FakeBeaconNode) (i: int) =
    BeaconClient(new HttpClient(node, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0)

let private errorOf (r: Result<'T, string>) =
    match r with
    | Error e -> e
    | Ok _ -> failtest "expected an error"

/// The first node is the harness's; the second gets `change`. Both must pass (threshold 2).
let private checkTwo (change: FakeBeaconNode -> unit) =
    task {
        let h = harness ()
        let second = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
        change second
        let nodes = BeaconNodes([ client h.Node 0; client second 1 ], 2, h.Time, Log.none)
        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
        let! r = Runner.checkNodes nodes pinnedFake AnchorPin.none (options h Log.none) cts.Token
        return r |> Result.map ignore
    }

let private runUntilStopped (change: FakeBeaconNode -> unit) (expected: string) =
    task {
        let h = harness ()

        for i in 0..3 do
            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

        let log, lines = Log.memory ()
        use cts = new CancellationTokenSource()
        let run = Runner.run (options h log) cts.Token
        do! h.RunSlots(0UL, uint64 slotsPerEpoch)
        change h.Node
        let next = h.Clock.SlotStart(2UL * uint64 slotsPerEpoch) + TimeSpan.FromSeconds 3.0
        h.Time.Advance(next - h.Time.GetUtcNow())
        let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 20.0))
        Expect.isTrue (Object.ReferenceEquals(winner, run)) $"the VC stopped; log: {String.Join('\n', lines)}"

        match run.Result with
        | Ok() -> failtest "the run must end with an error"
        | Error e -> Expect.stringContains e expected "names the value"

        Expect.isTrue
            (h.Node.Submissions |> Seq.forall (fun s -> s.Slot < 2UL * uint64 slotsPerEpoch))
            "nothing signed from epoch 2"
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "chain anchor"
        [
            test "every built-in network pins its genesis and slot timing" {
                let expected =
                    [
                        "mainnet", 1606824023UL, "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
                        "hoodi", 1742213400UL, "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
                        "sepolia", 1655733600UL, "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
                    ]

                Expect.equal [ for n, _, _ in expected -> n ] Networks.names "one anchor per network"

                for name, time, root in expected do
                    let a = (Networks.anchor name).Value
                    Expect.equal a.GenesisTime time $"{name}: genesis time"
                    Expect.equal a.GenesisValidatorsRoot.Hex root $"{name}: genesis validators root"
                    Expect.equal a.SlotsPerEpoch 32UL $"{name}: 32 slots an epoch"

                    let spec =
                        match ChainSpec.parse ((ChainSource.Network name).Pinned) with
                        | Ok s -> s
                        | Error e -> failwith e

                    Expect.equal a.SlotDuration spec.SlotDuration $"{name}: the pinned config's slot time"

                    Expect.equal
                        (Runner.pinnedAnchor (ChainSource.Network name))
                        (ValueSome a)
                        $"{name}: the runner pins it"
                // Networks that started at MIN_GENESIS_TIME + GENESIS_DELAY: a check on the copied times.
                for name in [ "hoodi"; "sepolia" ] do
                    let p = (ChainSource.Network name).Pinned

                    Expect.equal
                        (Networks.anchor name).Value.GenesisTime
                        (UInt64.Parse p["MIN_GENESIS_TIME"] + UInt64.Parse p["GENESIS_DELAY"])
                        $"{name}: genesis time from the config"

                Expect.equal
                    (Runner.pinnedAnchor (ChainSource.File "chain.yaml"))
                    ValueNone
                    "a chain config file pins none"
            }

            test "each value that differs is named" {
                Expect.isEmpty (ChainAnchor.differences "pinned" fakeAnchor fakeAnchor) "the same"

                let cases =
                    [
                        { fakeAnchor with
                            GenesisTime = genesisTime - 3600UL
                        },
                        "genesis_time"
                        { fakeAnchor with
                            GenesisValidatorsRoot = otherRoot
                        },
                        "genesis_validators_root"
                        { fakeAnchor with
                            SlotDuration = TimeSpan.FromSeconds 1.0
                        },
                        "slot duration"
                        { fakeAnchor with SlotsPerEpoch = 1UL }, "SLOTS_PER_EPOCH"
                    ]

                for actual, name in cases do
                    match ChainAnchor.differences "pinned" fakeAnchor actual with
                    | [ d ] -> Expect.stringContains d name name
                    | ds -> failtestf "%s: %A" name ds
            }

            test "a mainnet node with 1 slot an epoch or an earlier genesis differs from the pin" {
                // The review's proof of concept: SLOTS_PER_EPOCH = 1 passed checkPinned. It still
                // does (the pinned config has no preset values), so the anchor must catch it.
                let pinned = (ChainSource.Network "mainnet").Pinned
                let node = pinned |> Map.add "SLOTS_PER_EPOCH" "1"
                Expect.isOk (ChainSpec.checkPinned pinned node) "the config pin alone lets it pass"

                let spec =
                    match ChainSpec.parse node with
                    | Ok s -> s
                    | Error e -> failwith e

                let mainnet = (Networks.anchor "mainnet").Value
                let short = ChainAnchor.ofSpec mainnet.GenesisTime mainnet.GenesisValidatorsRoot spec
                Expect.isNonEmpty (ChainAnchor.differences "pinned" mainnet short) "1 slot an epoch"

                let honest =
                    match ChainSpec.parse (pinned |> Map.add "SLOTS_PER_EPOCH" "32") with
                    | Ok s -> s
                    | Error e -> failwith e

                let early = ChainAnchor.ofSpec (mainnet.GenesisTime - 86400UL) mainnet.GenesisValidatorsRoot honest
                Expect.isNonEmpty (ChainAnchor.differences "pinned" mainnet early) "a day earlier"

                Expect.isEmpty
                    (ChainAnchor.differences
                        "pinned"
                        mainnet
                        (ChainAnchor.ofSpec mainnet.GenesisTime mainnet.GenesisValidatorsRoot honest))
                    "the real one"
            }

            testT "a node that differs from the pinned genesis or slot timing fails the start check" (fun () ->
                task {
                    let cases: ((FakeBeaconNode -> unit) * string) list =
                        [
                            (fun _ -> ()), ""
                            (fun n -> n.ReportedGenesisTime <- genesisTime - 3600UL), "genesis_time"
                            (fun n -> n.GenesisValidatorsRoot <- otherRoot), "genesis_validators_root"
                            (fun n -> n.SpecOverride <- [ "SLOTS_PER_EPOCH", "1" ]), "SLOTS_PER_EPOCH"
                        ]

                    for change, name in cases do
                        let h = harness ()
                        change h.Node
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)

                        let! r =
                            Runner.chainInfo
                                (client h.Node 0)
                                pinnedFake
                                (AnchorPin.ofAnchor "pinned network" fakeAnchor)
                                (options h Log.none)
                                cts.Token

                        if name = "" then
                            Expect.isOk r "the same values pass"
                        else
                            let e = errorOf r
                            Expect.stringContains e name $"{name}: named"
                            Expect.stringContains e "pinned network" $"{name}: against the pin"
                    // Without a pin (a chain config file) a single node is taken as it is.
                    let h = harness ()
                    h.Node.ReportedGenesisTime <- genesisTime - 3600UL
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)

                    let! r =
                        Runner.chainInfo (client h.Node 0) pinnedFake AnchorPin.none (options h Log.none) cts.Token

                    Expect.isOk r "no pin"
                })

            testT "nodes of a chain config file must agree on genesis and slot timing" (fun () ->
                task {
                    let! same = checkTwo ignore
                    Expect.isOk same "two nodes with the same values"

                    for change, name in
                        [
                            (fun (n: FakeBeaconNode) -> n.ReportedGenesisTime <- genesisTime - 3600UL), "genesis_time"
                            (fun n -> n.GenesisValidatorsRoot <- otherRoot), "genesis_validators_root"
                            (fun n -> n.SpecOverride <- [ "SLOTS_PER_EPOCH", "4" ]), "SLOTS_PER_EPOCH"
                            (fun n -> n.SpecOverride <- [ "SLOTS_PER_EPOCH", "1" ]), "SLOTS_PER_EPOCH"
                        ] do
                        let! r = checkTwo change
                        let e = errorOf r
                        Expect.stringContains e "another chain" $"{name}: refused"
                        Expect.stringContains e name $"{name}: named"
                })

            testT "a node that later reports an earlier genesis stops the VC" (fun () ->
                task { do! runUntilStopped (fun n -> n.ReportedGenesisTime <- genesisTime - 3600UL) "genesis_time" })

            testT "a node that later reports fewer slots an epoch stops the VC" (fun () ->
                task { do! runUntilStopped (fun n -> n.SpecOverride <- [ "SLOTS_PER_EPOCH", "1" ]) "SLOTS_PER_EPOCH" })

            testT "a node that later reports another genesis validators root stops the VC" (fun () ->
                task { do! runUntilStopped (fun n -> n.GenesisValidatorsRoot <- otherRoot) "genesis_validators_root" })
        ]
