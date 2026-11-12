/// One bad beacon node does not stop the VC: a node that fails a
/// start check or the check each epoch is left out, and the VC stops only when too few are left.
/// Also the anchor the data dir keeps from its first start, and the import pin.
module Eplix.Tests.NodeLossTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.RunnerTests

/// Sends each request to the fake node of its host: bn0.test to the first, bn1.test to the next.
type private HostRouter(nodes: FakeBeaconNode list) =
    inherit HttpMessageHandler()
    let invokers = nodes |> List.map (fun n -> new HttpMessageInvoker(n, false)) |> Array.ofList

    override _.SendAsync(req, ct) =
        let host = (nonNull req.RequestUri).Host
        invokers[int (host.Substring(2, host.IndexOf '.' - 2))].SendAsync(req, ct)

let private otherRoot = Root.Of(Array.create 32 0x5Auy)

let private joined (lines: Collections.Concurrent.ConcurrentQueue<string>) = String.Join("\n", lines)

/// A VC config over `count` nodes bn0.test, bn1.test, ... with the local keys 0 to 3.
let private configFor (dir: string) (count: int) (threshold: int) (chain: string) =
    let urls = String.Join(", ", [ for i in 0 .. count - 1 -> $"\"http://bn{i}.test\"" ])

    let text =
        $"""{{ "beacon_nodes": [{urls}], "attestation_consensus_threshold": {threshold}, {chain}, "data_dir": "data",
             "use_events": false, "allow_start_without_history": ["all"],
             "modules": {{ "local": {{ "keystores": [ {{ "path": "keys", "password_file": "password.txt" }} ], "reload_interval_seconds": 0 }} }} }}"""

    let modules = [ LocalModule.create () ]

    match
        Config.parse text dir [ "local" ]
        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
    with
    | Error es -> failtestf "%A" es
    | Ok config -> config, modules

let private chainFile = "\"chain_config\": \"chain.yaml\""

/// The harness's node first, then more fake nodes on the same chain.
let private nodesOf (h: Harness) (count: int) =
    h.Node
    :: [
        for _ in 2..count -> new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
    ]

let private optionsFor
    (h: Harness)
    (nodes: FakeBeaconNode list)
    (config: CoreConfig)
    (modules: Module list)
    (log: Log)
    onReady
    =
    {
        Config = config
        Modules = modules
        Http = new HttpClient(new HostRouter(nodes), true)
        Time = h.Time
        Log = log
        OnSlotDone = h.Waiter.Done
        OnReady = onReady
    }

/// Runs the VC over `count` nodes through epoch 1, then lets `change` alter the nodes.
let private runAndChange (count: int) (threshold: int) (change: FakeBeaconNode list -> unit) =
    task {
        let h = harness ()
        let nodes = nodesOf h count

        for n in nodes do
            for i in 0..3 do
                n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

        let config, modules =
            configFor (localVcDir (configYaml secondsPerSlot slotsPerEpoch)) count threshold chainFile

        let log, lines = Log.memory ()
        let set = TaskCompletionSource<BeaconNodes>()
        let cts = new CancellationTokenSource()

        let run =
            Runner.run
                (optionsFor h nodes config modules log (fun core _ -> set.TrySetResult core.Nodes |> ignore))
                cts.Token

        do! h.RunSlots(0UL, uint64 slotsPerEpoch)
        change nodes
        let! beaconNodes = set.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
        return h, nodes, run, beaconNodes, lines, cts
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "beacon node loss"
        [
            testT "a lying node among 3 is dropped at the epoch check, and the VC goes on with 2" (fun () ->
                task {
                    let! h, nodes, run, set, lines, cts =
                        runAndChange 3 2 (fun ns -> ns[1].SpecOverride <- [ "DOMAIN_SYNC_COMMITTEE", "0x01000000" ])

                    do! h.RunSlots(uint64 slotsPerEpoch + 1UL, uint64 (4 * slotsPerEpoch - 1))
                    Expect.isFalse run.IsCompleted $"still running; log: {joined lines}"
                    let bn = set.Nodes
                    Expect.isFalse (set.InUse bn[1]) "the lying node is out"
                    Expect.isTrue (set.InUse bn[0] && set.InUse bn[2]) "the other two stay"
                    Expect.equal (set.Dropped |> Array.map snd) [| false; true; false |] "the metric's view"

                    Expect.isTrue
                        (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "DOMAIN_SYNC_COMMITTEE"))
                        "logged as an error, naming the key"

                    let late =
                        nodes[0].Submissions
                        |> Seq.filter (fun s -> s.Slot >= 3UL * uint64 slotsPerEpoch)
                        |> Seq.map (fun s -> s.AttesterIndex)
                        |> Seq.sort
                        |> List.ofSeq

                    Expect.equal late [ 0UL .. 3UL ] "every key attests in epoch 3 on the 2 nodes left"
                    cts.Cancel()
                    let! r = run
                    Expect.isOk r "stopped by the caller only"
                })

            testT "a drop below the threshold stops the VC" (fun () ->
                task {
                    let! h, nodes, run, _, lines, _ =
                        runAndChange 2 2 (fun ns -> ns[1].ReportedGenesisTime <- genesisTime - 3600UL)

                    let next = h.Clock.SlotStart(2UL * uint64 slotsPerEpoch) + TimeSpan.FromSeconds 3.0
                    h.Time.Advance(next - h.Time.GetUtcNow())
                    let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 20.0))
                    Expect.isTrue (Object.ReferenceEquals(winner, run)) $"the VC stopped; log: {joined lines}"

                    match run.Result with
                    | Ok() -> failtest "the run must end with an error"
                    | Error e ->
                        Expect.stringContains e "genesis_time" "names the value"
                        Expect.stringContains e "attestation_consensus_threshold is 2" "names the shortfall"

                    Expect.isTrue
                        (nodes[0].Submissions |> Seq.forall (fun s -> s.Slot < 2UL * uint64 slotsPerEpoch))
                        "nothing signed from epoch 2"
                })

            testT "a node that joins late on another chain is left out, and the VC goes on" (fun () ->
                task {
                    let h = harness ()
                    let nodes = nodesOf h 3

                    for n in nodes do
                        for i in 0..3 do
                            n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Node 2 is down at start, then answers with an earlier genesis.
                    nodes[2].Fail <- fun _ -> true
                    nodes[2].ReportedGenesisTime <- genesisTime - 3600UL

                    let config, modules =
                        configFor (localVcDir (configYaml secondsPerSlot slotsPerEpoch)) 3 2 chainFile

                    let log, lines = Log.memory ()
                    let set = TaskCompletionSource<BeaconNodes>()
                    use cts = new CancellationTokenSource()

                    let run =
                        Runner.run
                            (optionsFor h nodes config modules log (fun core _ ->
                                set.TrySetResult core.Nodes |> ignore))
                            cts.Token

                    let! bn = set.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                    Expect.isFalse (bn.InUse bn.Nodes[2]) "not in use before its check"
                    nodes[2].Fail <- fun _ -> false
                    do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))
                    // The late node's check ends in a continuation on the thread pool, which may run
                    // after the slots above (seen with 2 cores and the whole suite in parallel). The
                    // drop logs its error last.
                    let sw = Diagnostics.Stopwatch.StartNew()

                    while not (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "another chain"))
                          && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                        do! Task.Delay 10

                    Expect.isFalse run.IsCompleted $"still running; log: {joined lines}"

                    Expect.equal
                        (bn.Dropped |> Array.map snd)
                        [| false; false; true |]
                        $"the late node is dropped; log: {joined lines}"

                    Expect.isTrue
                        (lines
                         |> Seq.exists (fun l ->
                             l.StartsWith "ERROR" && l.Contains "another chain" && l.Contains "genesis_time"))
                        "logged with the value"

                    Expect.isEmpty nodes[2].Submissions "the late node got nothing to publish"
                    cts.Cancel()
                    let! r = run
                    Expect.isOk r "stopped by the caller only"
                })

            testT "a chain config file takes the anchor that the threshold agrees on, not the first node's" (fun () ->
                task {
                    let h = harness ()
                    let nodes = nodesOf h 3
                    nodes[0].ReportedGenesisTime <- genesisTime - 3600UL

                    let clients =
                        [
                            for i in 0..2 ->
                                BeaconClient(
                                    new HttpClient(nodes[i], false),
                                    Uri $"http://bn{i}.test",
                                    TimeSpan.FromSeconds 5.0
                                )
                        ]

                    let set = BeaconNodes(clients, 2, h.Time, Log.none, requireReady = true)

                    let config, modules =
                        configFor (localVcDir (configYaml secondsPerSlot slotsPerEpoch)) 3 2 chainFile

                    let opts = optionsFor h nodes config modules Log.none (fun _ _ -> ())
                    let pinned = ChainSpec.parseConfigYaml (configYaml secondsPerSlot slotsPerEpoch)
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
                    let! r = Runner.checkNodes set pinned AnchorPin.none opts cts.Token

                    match r with
                    | Ok(g, _) -> Expect.equal g.GenesisTime genesisTime "the two that agree"
                    | Error e -> failtest e

                    Expect.isFalse (set.InUse clients[0]) "the odd node is out"
                    Expect.isTrue (set.InUse clients[1] && set.InUse clients[2]) "the two that agree are in"
                    // Two nodes that differ with threshold 2: no anchor, no start.
                    let pair = BeaconNodes([ clients[0]; clients[1] ], 2, h.Time, Log.none, requireReady = true)
                    let! r = Runner.checkNodes pair pinned AnchorPin.none opts cts.Token

                    match r with
                    | Ok _ -> failtest "two nodes that differ must not start"
                    | Error e -> Expect.stringContains e "another chain" "names the split"
                })

            testT "on a built-in network a node off the pin is left out and the VC starts on the others" (fun () ->
                task {
                    let hoodi = (Networks.anchor "hoodi").Value
                    let pinned = (ChainSource.Network "hoodi").Pinned
                    // Well after Fulu (epoch 50688), so the Electra check passes.
                    let time =
                        FakeTimeProvider(
                            DateTimeOffset.FromUnixTimeSeconds(int64 hoodi.GenesisTime)
                            + TimeSpan.FromSeconds(51000.0 * 384.0 + 0.5)
                        )

                    let fake () =
                        let n = new FakeBeaconNode(hoodi.GenesisTime, 12, 32, "mainnet")
                        n.GenesisValidatorsRoot <- hoodi.GenesisValidatorsRoot
                        n.GenesisForkVersion <- pinned["GENESIS_FORK_VERSION"]
                        n.SpecOverride <- pinned |> Map.toList
                        n

                    let nodes = [ fake (); fake (); fake () ]
                    nodes[1].ReportedGenesisTime <- hoodi.GenesisTime - 600UL
                    let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = configFor dir 3 2 "\"network\": \"hoodi\""
                    let log, lines = Log.memory ()

                    let opts =
                        {
                            Config = config
                            Modules = modules
                            Http = new HttpClient(new HostRouter(nodes), true)
                            Time = time
                            Log = log
                            OnSlotDone = ignore
                            OnReady = fun _ _ -> ()
                        }

                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 30.0)
                    let mutable inUse = [||]

                    let! r =
                        Runner.runWith opts cts.Token (fun core _ ->
                            task {
                                inUse <- core.Nodes.Nodes |> List.map core.Nodes.InUse |> Array.ofList
                                return Ok()
                            })

                    Expect.isOk r $"started on 2 of 3; log: {joined lines}"
                    Expect.equal inUse [| true; false; true |] "the node off the pin is out"

                    Expect.isTrue
                        (lines
                         |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "genesis_time: network hoodi"))
                        "logged against the pin"

                    let kept = File.ReadAllText(Path.Combine(config.DataDir, "chain-anchor"))
                    Expect.stringContains kept $"genesis_time: {hoodi.GenesisTime}" "the data dir keeps the anchor"
                    // With 2 of 3 off the pin the threshold is out of reach: no start.
                    nodes[2].GenesisValidatorsRoot <- otherRoot
                    let! r = Runner.runWith opts cts.Token (fun _ _ -> Task.FromResult(Ok()))

                    match r with
                    | Ok() -> failtest "1 of 3 on the pin must not start"
                    | Error e -> Expect.stringContains e "too few beacon nodes" "names the reason"
                })

            testT "the data dir keeps the first start's anchor and checks it at every start" (fun () ->
                task {
                    let h = harness ()
                    let dir = localVcDir (configYaml secondsPerSlot slotsPerEpoch)
                    let config, modules = configFor dir 1 1 chainFile

                    let start () =
                        task {
                            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 30.0)

                            return!
                                Runner.runWith
                                    (optionsFor h [ h.Node ] config modules Log.none (fun _ _ -> ()))
                                    cts.Token
                                    (fun _ _ -> Task.FromResult(Ok()))
                        }

                    let! first = start ()
                    Expect.isOk first "first start"
                    let file = Path.Combine(config.DataDir, "chain-anchor")

                    Expect.equal
                        (File.ReadAllText file)
                        $"genesis_time: {genesisTime}\nslot_duration_ms: {secondsPerSlot * 1000}\nslots_per_epoch: {slotsPerEpoch}\n"
                        "written"
                    // A single node of a custom devnet that later reports another genesis or epoch length.
                    for change, name in
                        [
                            (fun (n: FakeBeaconNode) -> n.ReportedGenesisTime <- genesisTime - 3600UL),
                            "genesis_time: the data dir"
                            (fun n -> n.SpecOverride <- [ "SLOTS_PER_EPOCH", "4" ]), "SLOTS_PER_EPOCH: the data dir"
                            (fun n -> n.GenesisValidatorsRoot <- otherRoot), "genesis_validators_root: the slashing DB"
                        ] do
                        change h.Node
                        let! r = start ()

                        match r with
                        | Ok() -> failtestf "started with %s" name
                        | Error e -> Expect.stringContains e name name

                        h.Node.ReportedGenesisTime <- genesisTime
                        h.Node.SpecOverride <- []
                        h.Node.GenesisValidatorsRoot <- gvr

                    let! again = start ()
                    Expect.isOk again "the same chain starts again"
                    // A data dir of another chain than the config pins fails before any node is asked.
                    File.WriteAllText(
                        file,
                        $"genesis_time: {genesisTime + 1UL}\nslot_duration_ms: 6000\nslots_per_epoch: 8\n"
                    )

                    let! r = start ()

                    match r with
                    | Ok() -> failtest "a wrong anchor file must not start"
                    | Error e -> Expect.stringContains e "genesis_time: the data dir" "names the file's value"
                })

            test "the start pin merges the config, the data dir and the slashing DB" {
                let dir = tempDir ()
                let anchorFile = Path.Combine(dir, "chain-anchor")
                let hoodi = (Networks.anchor "hoodi").Value

                let ok r =
                    match r with
                    | Ok p -> p
                    | Error e -> failtest e

                Expect.equal
                    (AnchorPin.full (ok (Runner.startPin (ChainSource.Network "hoodi") Map.empty anchorFile ValueNone)))
                    (ValueSome hoodi)
                    "the network"

                Expect.equal
                    (ok (Runner.startPin (ChainSource.File "x") Map.empty anchorFile ValueNone))
                    AnchorPin.none
                    "a file with no pin"

                let devnet = Map.ofList [ "GENESIS_TIME", "1700000000"; "GENESIS_VALIDATORS_ROOT", gvr.Hex ]
                let p = ok (Runner.startPin (ChainSource.File "x") devnet anchorFile ValueNone)
                Expect.equal p.GenesisTime (ValueSome(struct (1700000000UL, "chain config"))) "GENESIS_TIME of the file"

                Expect.equal
                    p.GenesisValidatorsRoot
                    (ValueSome(struct (gvr, "chain config")))
                    "GENESIS_VALIDATORS_ROOT of the file"

                Expect.isError
                    (Runner.startPin (ChainSource.File "x") (Map.ofList [ "GENESIS_TIME", "soon" ]) anchorFile ValueNone)
                    "a bad value"

                match Runner.startPin (ChainSource.Network "hoodi") Map.empty anchorFile (ValueSome otherRoot) with
                | Ok _ -> failtest "a slashing DB of another chain"
                | Error e -> Expect.stringContains e "genesis_validators_root: network hoodi" "names both"

                File.WriteAllText(anchorFile, ChainAnchor.toFile { hoodi with GenesisTime = 1UL })

                Expect.isError
                    (Runner.startPin (ChainSource.Network "hoodi") Map.empty anchorFile ValueNone)
                    "a data dir of another chain"

                File.WriteAllText(anchorFile, "genesis_time: 5\n")
                Expect.isError (Runner.startPin (ChainSource.File "x") Map.empty anchorFile ValueNone) "a damaged file"
            }

            test "an interchange file of another chain is refused when the chain pins its root" {
                let hoodi = (Networks.anchor "hoodi").Value
                let fits chain root = Runner.interchangeFits chain Map.empty root
                Expect.isOk (fits (ChainSource.Network "hoodi") hoodi.GenesisValidatorsRoot) "hoodi's root"
                Expect.isError (fits (ChainSource.Network "hoodi") otherRoot) "another root"

                Expect.isError
                    (fits (ChainSource.Network "mainnet") hoodi.GenesisValidatorsRoot)
                    "hoodi's file on mainnet"

                Expect.isOk (fits (ChainSource.File "x") otherRoot) "a chain config file without the root pins none"
                let devnet = Map.ofList [ "GENESIS_VALIDATORS_ROOT", gvr.Hex ]
                Expect.isOk (Runner.interchangeFits (ChainSource.File "x") devnet gvr) "the devnet's root"

                match Runner.interchangeFits (ChainSource.File "x") devnet otherRoot with
                | Ok() -> failtest "a file of another chain than GENESIS_VALIDATORS_ROOT"
                | Error e -> Expect.stringContains e "chain config has" "names the source"
            }

            testT "only attestation_data nodes agree on the reference anchor" (fun () ->
                task {
                    let h = harness ()
                    let nodes = nodesOf h 4
                    // Nodes 0 and 1 hold only duties and answer first, from another chain.
                    for i in 0..1 do
                        nodes[i].ReportedGenesisTime <- genesisTime - 3600UL

                    for i in 2..3 do
                        nodes[i].Delay <- fun _ -> Task.Delay 300

                    let clients =
                        [
                            for i in 0..3 ->
                                BeaconClient(
                                    new HttpClient(nodes[i], false),
                                    Uri $"http://bn{i}.test",
                                    TimeSpan.FromSeconds 5.0
                                )
                        ]

                    let roles = [ NodeRole.Duties; NodeRole.Duties; NodeRole.All; NodeRole.All ]
                    let set = BeaconNodes(clients, 2, h.Time, Log.none, roles = roles, requireReady = true)

                    let config, modules =
                        configFor (localVcDir (configYaml secondsPerSlot slotsPerEpoch)) 1 1 chainFile

                    let opts = optionsFor h nodes config modules Log.none (fun _ _ -> ())
                    let pinned = ChainSpec.parseConfigYaml (configYaml secondsPerSlot slotsPerEpoch)
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
                    let! r = Runner.checkNodes set pinned AnchorPin.none opts cts.Token

                    match r with
                    | Ok(g, _) -> Expect.equal g.GenesisTime genesisTime "the attestation_data nodes set the reference"
                    | Error e -> failtest e

                    Expect.equal
                        (clients |> List.map set.InUse)
                        [ false; false; true; true ]
                        "the duties-only nodes of another chain are out"
                })

            testT "a role whose every node failed fails the start" (fun () ->
                task {
                    let h = harness ()
                    let nodes = nodesOf h 3
                    // Node 2 is the only block_publish node and is on another chain.
                    nodes[2].ReportedGenesisTime <- genesisTime - 3600UL

                    for i in 0..1 do
                        nodes[i].Delay <- fun _ -> Task.Delay 300

                    let clients =
                        [
                            for i in 0..2 ->
                                BeaconClient(
                                    new HttpClient(nodes[i], false),
                                    Uri $"http://bn{i}.test",
                                    TimeSpan.FromSeconds 5.0
                                )
                        ]

                    let roles =
                        [
                            NodeRole.All &&& ~~~NodeRole.BlockPublish
                            NodeRole.All &&& ~~~NodeRole.BlockPublish
                            NodeRole.BlockPublish
                        ]

                    let set = BeaconNodes(clients, 2, h.Time, Log.none, roles = roles, requireReady = true)

                    let config, modules =
                        configFor (localVcDir (configYaml secondsPerSlot slotsPerEpoch)) 1 1 chainFile

                    let opts = optionsFor h nodes config modules Log.none (fun _ _ -> ())
                    let pinned = ChainSpec.parseConfigYaml (configYaml secondsPerSlot slotsPerEpoch)
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
                    let! r = Runner.checkNodes set pinned AnchorPin.none opts cts.Token

                    match r with
                    | Ok _ -> failtest "no block_publish node is left"
                    | Error e ->
                        Expect.stringContains e "too few beacon nodes passed the start checks" "a start failure"
                        Expect.stringContains e "no beacon node with the role block_publish" "names the role"
                        Expect.stringContains e "another chain" "names the node's fault"
                })
        ]
