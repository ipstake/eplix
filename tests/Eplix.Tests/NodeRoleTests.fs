/// Role-split beacon nodes: role names, config, the call filter of
/// BeaconNodes, and a VC whose block node never sees attestation work and the reverse.
module Eplix.Tests.NodeRoleTests

open System
open System.Collections.Concurrent
open System.Net.Http
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let private base' = """ "chain_config": "c.yaml", "data_dir": "d" """

let private parse (body: string) = Config.parse $$"""{ {{body}}, {{base'}} }""" (tempDir ()) []

let private refused (body: string) (part: string) =
    match parse body with
    | Ok _ -> failtestf "accepted %s" body
    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"'{part}' in %A{es}"

let private client (i: int) = BeaconClient(new HttpClient(), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 1.0)

/// Every role is held by some node of the list.
let private covers (roles: NodeRole list) =
    NodeRole.names |> List.forall (fun (r, _) -> roles |> List.exists (fun x -> x &&& r = r))

/// A role list per node (1 to 5 nodes, any role set but the empty one) and a call mask.
let private genCase =
    gen {
        let! n = Gen.choose (1, 5)
        let! roles = Gen.listOfLength n (Gen.choose (1, int NodeRole.All))
        let! mask = Gen.choose (1, int NodeRole.All)
        return roles |> List.map enum<NodeRole>, enum<NodeRole> mask
    }

let private reached (roles: NodeRole list) (mask: NodeRole) =
    roles
    |> List.indexed
    |> List.filter (fun (_, r) -> r &&& mask <> NodeRole.None)
    |> List.map fst
    |> Set.ofList

/// Calls `f` on the node set and returns the indices of the clients it was given.
let private calledWith
    (clients: BeaconClient list)
    (f: BeaconNodes -> (BeaconClient -> Task<Result<unit, ApiError>>) -> Task)
    (nodes: BeaconNodes)
    (answer: Result<unit, ApiError>)
    =
    let seen = ConcurrentBag<int>()

    let call (c: BeaconClient) =
        seen.Add(clients |> List.findIndex (fun x -> Object.ReferenceEquals(x, c)))
        Task.FromResult answer

    (f nodes call).Wait()
    Set.ofSeq seen

let private unitTests =
    [
        test "role names and groups" {
            Expect.equal
                (NodeRole.parse "block")
                (ValueSome(NodeRole.BlockData ||| NodeRole.BlockPublish))
                "block group"

            Expect.equal (NodeRole.parse "attestation_data") (ValueSome NodeRole.AttestationData) "one role"
            Expect.equal (NodeRole.parse "all") (ValueSome NodeRole.All) "all"
            Expect.equal (NodeRole.parse "Block") ValueNone "names are lower case"
            Expect.equal (NodeRole.parse "sentry") ValueNone "unknown"
            let publish = (NodeRole.parse "publish").Value

            Expect.equal
                (NodeRole.describe publish)
                "attestation_publish, aggregate_publish, sync_publish, block_publish"
                "publish group"

            Expect.equal (NodeRole.describe NodeRole.All) "all" "all"
            Expect.equal (NodeRole.names.Length) 9 "nine roles"

            Expect.equal
                (NodeRole.names |> List.fold (fun acc (r, _) -> acc ||| r) NodeRole.None)
                NodeRole.All
                "the roles make All"
        }

        test "check: every role needs a node, thresholds count attestation_data nodes" {
            Expect.isOk (NodeRole.check [ NodeRole.All ] 1 1) "one node, all roles"
            let block = NodeRole.BlockData ||| NodeRole.BlockPublish
            let rest = NodeRole.All &&& ~~~block
            Expect.isOk (NodeRole.check [ rest; rest; block ] 2 2) "two data nodes, threshold 2"

            match NodeRole.check [ rest; rest; block ] 3 1 with
            | Error es ->
                Expect.isTrue (es |> List.exists (fun e -> e.Contains "attestation_consensus_threshold 3")) $"%A{es}"
            | Ok() -> failtest "threshold 3 over 2 data nodes"

            match NodeRole.check [ rest; rest ] 1 1 with
            | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains "block_data")) $"%A{es}"
            | Ok() -> failtest "no block node"
        }

        test "the node set refuses roles that leave a role without a node" {
            let block = NodeRole.BlockData ||| NodeRole.BlockPublish

            Expect.throwsT<ArgumentException>
                (fun () ->
                    BeaconNodes([ client 0; client 1 ], 1, TimeProvider.System, Log.none, roles = [ block; block ])
                    |> ignore)
                "no duties node"

            Expect.throwsT<ArgumentException>
                (fun () ->
                    BeaconNodes(
                        [ client 0; client 1 ],
                        2,
                        TimeProvider.System,
                        Log.none,
                        roles = [ NodeRole.All; block ]
                    )
                    |> ignore)
                "threshold 2 with one data node"

            Expect.throwsT<ArgumentException>
                (fun () ->
                    BeaconNodes([ client 0 ], 1, TimeProvider.System, Log.none, roles = [ NodeRole.All; NodeRole.All ])
                    |> ignore)
                "one role set per node"

            let nodes = BeaconNodes([ client 0; client 1 ], 1, TimeProvider.System, Log.none)
            Expect.isFalse nodes.Split "default: every role"
            Expect.equal (nodes.Roles |> List.map snd) [ NodeRole.All; NodeRole.All ] "default roles"
        }

        test "config: roles in a node object, as a list or a comma-separated string" {
            match
                parse
                    """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                                        { "url": "http://b:1", "roles": "duties, attestation_data, attestation_publish" },
                                        { "url": "http://c:1", "roles": [ "block" ] },
                                        "http://d:1" ] """
            with
            | Error es -> failtestf "%A" es
            | Ok c ->
                let r = c.BeaconNodes |> List.map (fun n -> n.Roles)
                let block = NodeRole.BlockData ||| NodeRole.BlockPublish
                Expect.equal r[0] (NodeRole.All &&& ~~~block) "list with groups"

                Expect.equal
                    r[1]
                    (NodeRole.Duties ||| NodeRole.AttestationData ||| NodeRole.AttestationPublish)
                    "comma string"

                Expect.equal r[2] block "block only"
                Expect.equal r[3] NodeRole.All "a plain URL has every role"
                Expect.equal c.AttestationConsensusThreshold 2 "default: a majority of the 3 attestation_data nodes"
        }

        test "config: old forms keep every role and the old default threshold" {
            match parse """ "beacon_nodes": [ "http://a:1", { "url": "http://b:1" }, "http://c:1" ] """ with
            | Error es -> failtestf "%A" es
            | Ok c ->
                Expect.isTrue (c.BeaconNodes |> List.forall (fun n -> n.Roles = NodeRole.All)) "every role"
                Expect.equal c.AttestationConsensusThreshold 2 "majority of 3"

            match parse """ "beacon_node": "http://a:1" """ with
            | Error es -> failtestf "%A" es
            | Ok c -> Expect.equal c.BeaconNodes[0].Roles NodeRole.All "one node"
        }

        test "config: mistakes in roles are refused" {
            refused """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "sentry" ] } ] """ "unknown role 'sentry'"

            match parse """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "sentry" ] } ] """ with
            | Error es ->
                Expect.isFalse
                    (es |> List.exists (fun e -> e.Contains "must not be empty"))
                    $"only the role error: %A{es}"
            | Ok _ -> failtest "accepted"

            refused """ "beacon_nodes": [] """ "beacon_nodes must not be empty"
            refused """ "beacon_nodes": [ { "url": "http://a:1", "roles": [] } ] """ "roles must not be empty"
            refused """ "beacon_nodes": [ { "url": "http://a:1", "roles": 3 } ] """ "roles must be a list"
            refused """ "beacon_nodes": [ { "url": "http://a:1", "role": [ "block" ] } ] """ "unknown field 'role'"
        }

        test "config: a role without a node and a threshold above the data nodes fail" {
            refused
                """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "duties", "attestation", "aggregate", "sync" ] } ] """
                "no beacon node has the role block_data"

            refused
                """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "block" ] }, { "url": "http://b:1", "roles": [ "block" ] } ] """
                "no beacon node has the role duties"

            refused
                """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                                    { "url": "http://b:1", "roles": [ "block" ] } ],
                  "attestation_consensus_threshold": 2 """
                "with the role attestation_data (1)"

            refused
                """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                                    { "url": "http://b:1", "roles": [ "block" ] } ],
                  "ptc_consensus_threshold": 2 """
                "with the role attestation_data (1)"

            match
                parse
                    """ "beacon_nodes": [ { "url": "http://a:1", "roles": [ "duties", "attestation", "aggregate", "sync" ] },
                                        { "url": "http://b:1", "roles": [ "block" ] } ] """
            with
            | Ok c ->
                Expect.equal c.AttestationConsensusThreshold 1 "default threshold: a majority of the one data node"
            | Error es -> failtestf "%A" es
        }
    ]

let private properties =
    [
        testProp "a call with a role reaches exactly the nodes that hold it"
        <| Prop.forAll (Arb.fromGen genCase) (fun (roles, mask) ->
            let clients = roles |> List.mapi (fun i _ -> client i)

            if not (covers roles) then
                // The set refuses such roles: some role would have no node.
                try
                    BeaconNodes(clients, 1, TimeProvider.System, Log.none, roles = roles) |> ignore
                    false
                with :? ArgumentException ->
                    true
            else
                let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, roles = roles)
                let expected = reached roles mask
                let fail = Error(ApiError.Transport "down")
                let broadcast = calledWith clients (fun n f -> n.Broadcast(f, mask)) nodes (Ok())
                let askAll = calledWith clients (fun n f -> n.AskAll(f, mask)) nodes (Ok())
                // Call stops at the first good answer; with every node failing it tries them all.
                let call = calledWith clients (fun n f -> n.Call(f, mask)) nodes fail
                let callOk = calledWith clients (fun n f -> n.Call(f, mask)) nodes (Ok())

                let most =
                    calledWith
                        clients
                        (fun n f ->
                            n.Most(
                                f,
                                (fun () -> 0),
                                (fun () -> false),
                                DateTimeOffset.UtcNow.AddSeconds 5.0,
                                Threading.CancellationToken.None,
                                mask
                            ))
                        nodes
                        (Ok())

                broadcast = expected
                && askAll = expected
                && call = expected
                && callOk.Count = 1
                && expected.Contains(Seq.head callOk)
                && most = expected
                && Set.ofList (
                    nodes.NodesWith mask
                    |> List.map (fun c -> clients |> List.findIndex (fun x -> Object.ReferenceEquals(x, c)))
                )
                    =
                    expected
                && (nodes.Ranked mask).Length = expected.Count)
    ]

/// Three nodes: n0 and n1 do everything but blocks, n2 only blocks. Attestation data needs both
/// data nodes (threshold 2). The block node gets the proposal and prepare_beacon_proposer and no
/// attestation work; the data nodes get no block request.
let private splitVc () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let n2 = extraNode h
        let all = [ h.Node; n1; n2 ]
        addValidators all 8

        for n in all do
            n.Proposals[4UL] <- 3UL
            n.CommitteeLength <- 8UL

        let block = NodeRole.BlockData ||| NodeRole.BlockPublish
        let rest = NodeRole.All &&& ~~~block

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ n1; n2 ]
                    Threshold = 2
                    Roles = Some [ rest; rest; block ]
                }

        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the block of slot 4" (fun () -> n2.Published.Count > 0)
        advanceTo h (h.Clock.SlotStart 4UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

        do!
            waitUntil vc "the aggregate of slot 4" (fun () ->
                not (List.isEmpty (postsOf h.Node "aggregate_and_proofs")))

        do! vc.Stop()
        Expect.equal n2.Published.Count 1 $"the block went to the block node; log:\n{vc.Log}"

        for n, name in [ h.Node, "n0"; n1, "n1" ] do
            Expect.equal n.Published.Count 0 $"{name}: no block published"
            Expect.equal (n.RequestCount "GET /eth/v3/validator/blocks") 0 $"{name}: no block produced"
            Expect.isEmpty (postsOf n "prepare_beacon_proposer") $"{name}: no prepare_beacon_proposer"
            Expect.isGreaterThan n.Submissions.Count 0 $"{name}: attestations"

        Expect.isNonEmpty (postsOf n2 "prepare_beacon_proposer") "the block node got the fee recipients"

        Expect.equal
            (n2.RequestCount "GET /eth/v1/validator/attestation_data")
            0
            "no attestation data from the block node"

        Expect.equal
            (n2.RequestCount "POST /eth/v1/validator/duties")
            0
            "no attester or sync duties from the block node"

        Expect.equal (n2.RequestCount "GET /eth/v1/validator/duties") 0 "no proposer duties from the block node"
        Expect.equal (n2.RequestCount "POST /eth/v1/beacon/states") 0 "no validator states from the block node"
        Expect.equal n2.Submissions.Count 0 "no attestations to the block node"
        Expect.isEmpty (postsOf n2 "aggregate_and_proofs") "no aggregates to the block node"
        Expect.isEmpty (postsOf n2 "beacon_committee_subscriptions") "no subscriptions to the block node"

        Expect.isGreaterThan
            (n1.RequestCount "GET /eth/v1/validator/attestation_data")
            0
            "both data nodes asked (threshold 2)"
    }

/// The reverse: a proposal-only set and an attestation-only set; each publishes its own kind.
let private publishSplit () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let all = [ h.Node; n1 ]
        addValidators all 8

        for n in all do
            n.Proposals[4UL] <- 3UL
        // n0: duties and attestation data only; n1 publishes everything and builds blocks.
        let n0Roles =
            NodeRole.Duties ||| NodeRole.AttestationData ||| NodeRole.AggregateData ||| NodeRole.SyncData

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ n1 ]
                    Threshold = 1
                    Roles = Some [ n0Roles; NodeRole.All &&& ~~~n0Roles ]
                }

        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the block of slot 4" (fun () -> n1.Published.Count > 0)
        do! vc.Stop()
        Expect.equal h.Node.Submissions.Count 0 $"n0 publishes no attestation; log:\n{vc.Log}"
        Expect.isGreaterThan n1.Submissions.Count 0 "n1 publishes the attestations"
        Expect.equal (n1.RequestCount "GET /eth/v1/validator/attestation_data") 0 "n1 gives no attestation data"
        Expect.isGreaterThan (h.Node.RequestCount "GET /eth/v1/validator/attestation_data") 0 "n0 gives it"
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "node roles"
        (unitTests
         @ properties
         @ [
             testT "a block-only node gets the proposal and no attestation work" splitVc
             testT "publish-only and data-only nodes" publishSplit
         ])

// ---- The broadcast setting ----

/// Three ready nodes (score 100, config order breaks ties) with the given broadcast setting.
let private threeNodes (broadcast: BroadcastTopic) =
    let clients = [ client 0; client 1; client 2 ]
    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, broadcast = broadcast)

    for c in clients do
        nodes.MarkReady c

    clients, nodes

let private indexOf (clients: BeaconClient list) (c: BeaconClient) =
    clients |> List.findIndex (fun x -> Object.ReferenceEquals(x, c))

let private scoreOf (nodes: BeaconNodes) (i: int) =
    let _, s, _ = nodes.Scores[i]
    s

let private ok: Task<Result<unit, ApiError>> = Task.FromResult(Ok())
let private down (i: int) : Task<Result<unit, ApiError>> = Task.FromResult(Error(ApiError.Transport $"node {i} down"))

let private broadcastOnFast () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All

        let hang =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        let called = ConcurrentBag<int>()

        let f (c: BeaconClient) =
            let i = indexOf clients c
            called.Add i

            match i with
            | 0 -> hang.Task
            | 1 ->
                task {
                    do! Task.Delay 50
                    return Ok()
                }
            | _ -> down i

        let sw = Diagnostics.Stopwatch.StartNew()
        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        Expect.equal r (Ok()) "the fast node accepted"
        Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 2.0) "returned without waiting for the hanging node"
        Expect.equal (Set.ofSeq called) (set [ 0; 1; 2 ]) "sent to every node"
        Expect.equal (scoreOf nodes 0) 100 "the hanging send has not ended yet"
        // The late answer still scores the node.
        hang.SetResult(Error(ApiError.Transport "late"))
        let sw = Diagnostics.Stopwatch.StartNew()

        while scoreOf nodes 0 = 100 && sw.Elapsed < TimeSpan.FromSeconds 5.0 do
            do! Task.Delay 5

        Expect.equal (scoreOf nodes 0) 95 "the late failure cost node 0 five points"
        Expect.equal (scoreOf nodes 2) 95 "the failed node lost five points"
        Expect.equal (scoreOf nodes 1) 100 "the good node stays at 100 (capped)"
    }

let private broadcastOnAllFail () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All

        let f (c: BeaconClient) =
            let i = indexOf clients c

            if i = 0 then
                task {
                    do! Task.Delay 30
                    return! down 0
                }
            else
                down i

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Blocks)
        Expect.equal r (Error(ApiError.Transport "node 0 down")) "every node failed: the first node's error"
    }

let private broadcastOffPrimaryOnly () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.None
        let called = ConcurrentQueue<int>()

        let! r =
            nodes.Broadcast(
                (fun c ->
                    called.Enqueue(indexOf clients c)
                    ok),
                NodeRole.All,
                BroadcastTopic.Attestations
            )

        Expect.equal r (Ok()) "accepted"
        Expect.equal (List.ofSeq called) [ 0 ] "only the primary got it"
        // Another best node by score: it becomes the primary.
        nodes
            .Broadcast(
                (fun c -> if indexOf clients c = 0 then down 0 else ok),
                NodeRole.All,
                BroadcastTopic.Attestations
            )
            .Wait()

        let called = ConcurrentQueue<int>()

        let! _ =
            nodes.Broadcast(
                (fun c ->
                    called.Enqueue(indexOf clients c)
                    ok),
                NodeRole.All,
                BroadcastTopic.Attestations
            )

        Expect.equal (List.ofSeq called) [ 1 ] "node 0 lost score, node 1 is the primary now"
    }

let private broadcastOffFallback () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.None
        // Primary fails at once: the next node, then stop.
        let called = ConcurrentQueue<int>()

        let! r =
            nodes.Broadcast(
                (fun c ->
                    let i = indexOf clients c in
                    called.Enqueue i
                    if i = 0 then down 0 else ok),
                NodeRole.All,
                BroadcastTopic.Blocks
            )

        Expect.equal r (Ok()) "the second node accepted"
        Expect.equal (List.ofSeq called) [ 0; 1 ] "one at a time, in rank order, stopping at the first that accepts"
        // All fail: the last error, after trying each once.
        let called = ConcurrentQueue<int>()

        let! r =
            nodes.Broadcast(
                (fun c ->
                    let i = indexOf clients c in
                    called.Enqueue i
                    down i),
                NodeRole.All,
                BroadcastTopic.Blocks
            )

        Expect.isError r "all failed"
        Expect.equal (List.length (List.ofSeq called)) 3 "each node tried once"
    }

/// A primary that does not answer: the request timeout of a real client ends it and the next node
/// gets the message.
let private broadcastOffTimeout () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let never = TaskCompletionSource()
        h.Node.Delay <- fun path -> if path.EndsWith "prepare_beacon_proposer" then never.Task else Task.CompletedTask

        let clients =
            [ h.Node; n1 ]
            |> List.mapi (fun i n ->
                BeaconClient(new HttpClient(n, false), Uri $"http://bn{i}.test", TimeSpan.FromMilliseconds 300.0))

        let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, broadcast = BroadcastTopic.None)

        for c in clients do
            nodes.MarkReady c

        let sw = Diagnostics.Stopwatch.StartNew()

        let! r =
            nodes.Broadcast(
                (fun b -> b.PrepareBeaconProposer([ 1UL, feeHex ], Threading.CancellationToken.None)),
                NodeRole.All,
                BroadcastTopic.Preparations
            )

        Expect.equal r (Ok()) "the second node accepted after the first timed out"
        Expect.isGreaterThanOrEqual sw.Elapsed (TimeSpan.FromMilliseconds 250.0) "after the request timeout"
        Expect.isNonEmpty (postsOf n1 "prepare_beacon_proposer") "node 1 got it"
        never.SetResult()
    }

let private broadcastTopics () =
    task {
        let clients, nodes = threeNodes (BroadcastTopic.Attestations ||| BroadcastTopic.Blocks)

        let count (topic: BroadcastTopic) =
            let called = ConcurrentBag<int>()

            nodes
                .Broadcast(
                    (fun c ->
                        called.Add(indexOf clients c)
                        ok),
                    NodeRole.All,
                    topic
                )
                .Wait()
            // Sends to the other nodes may still be running: wait for them.
            let sw = Diagnostics.Stopwatch.StartNew()

            while called.Count < 3 && sw.Elapsed < TimeSpan.FromMilliseconds 200.0 do
                Threading.Thread.Sleep 5

            called.Count

        Expect.equal (count BroadcastTopic.Attestations) 3 "attestations: every node"
        Expect.equal (count BroadcastTopic.Blocks) 3 "blocks: every node"
        Expect.equal (count BroadcastTopic.Subscriptions) 1 "subscriptions: the primary only"
        Expect.equal (count BroadcastTopic.Exits) 1 "exits: the primary only"
        // broadcast: false, Lighthouse's default: subscriptions and preparations to every node.
        let clients, nodes = threeNodes BroadcastTopic.lighthouseDefault

        let count (topic: BroadcastTopic) =
            let called = ConcurrentBag<int>()

            nodes
                .Broadcast(
                    (fun c ->
                        called.Add(indexOf clients c)
                        ok),
                    NodeRole.All,
                    topic
                )
                .Wait()

            let sw = Diagnostics.Stopwatch.StartNew()

            while called.Count < 3 && sw.Elapsed < TimeSpan.FromMilliseconds 200.0 do
                Threading.Thread.Sleep 5

            called.Count

        Expect.equal (count BroadcastTopic.Subscriptions) 3 "off: subscriptions still to every node"
        Expect.equal (count BroadcastTopic.Preparations) 3 "off: preparations still to every node"

        for t in
            [
                BroadcastTopic.Attestations
                BroadcastTopic.Aggregates
                BroadcastTopic.SyncCommittee
                BroadcastTopic.Blocks
                BroadcastTopic.Exits
            ] do
            Expect.equal (count t) 1 $"off: {BroadcastTopic.describe t} to the primary only"
    }

/// A node that hangs gets at most MaxBackground sends at once; the rest skip it.
let private broadcastBounded () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All

        let hang =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        let mutable toHanging = 0

        let f (c: BeaconClient) =
            if indexOf clients c = 2 then
                Threading.Interlocked.Increment(&toHanging) |> ignore
                hang.Task
            else
                ok

        for _ in 1 .. 3 * BeaconNodes.MaxBackground do
            let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
            Expect.equal r (Ok()) "the good nodes accept"

        Expect.equal toHanging BeaconNodes.MaxBackground "no more than MaxBackground sends to the hanging node"
        hang.SetResult(Ok())
        // The score moves before the send's counter drops: wait for the counter.
        let sw = Diagnostics.Stopwatch.StartNew()

        while nodes.Running[2] > 0 && sw.Elapsed < TimeSpan.FromSeconds 2.0 do
            do! Task.Delay 5

        let! _ = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        Expect.equal toHanging (BeaconNodes.MaxBackground + 1) "once its sends ended, the node gets sends again"
    }

/// Sums eplix_beacon_node_submissions per (node, topic, result) for nodes whose name holds
/// `host`, so other tests' sends running at the same time do not count.
type private Submissions(host: string) =
    let counts = ConcurrentDictionary<struct (string * string * string), int64>()
    let listener = new Diagnostics.Metrics.MeterListener()

    do
        listener.InstrumentPublished <-
            fun i l ->
                if i.Meter.Name = Metrics.MeterName && i.Name = "eplix_beacon_node_submissions" then
                    l.EnableMeasurementEvents i

        listener.SetMeasurementEventCallback<int64>(fun _ v tags _ ->
            let mutable node = ""
            let mutable topic = ""
            let mutable result = ""

            for t in tags do
                match t.Key with
                | "node" -> node <- string t.Value
                | "topic" -> topic <- string t.Value
                | "result" -> result <- string t.Value
                | _ -> ()

            if node.Contains host then
                counts.AddOrUpdate(struct (node, topic, result), v, fun _ old -> old + v) |> ignore)

        listener.Start()

    member _.Get(node: int, topic: string, result: string) =
        match counts.TryGetValue(struct ($"http://{host}{node}.test", topic, result)) with
        | true, v -> v
        | _ -> 0L

    member _.Total = counts.Values |> Seq.sum

    interface IDisposable with
        member _.Dispose() = listener.Dispose()

let private namedNodes (host: string) (broadcast: BroadcastTopic) =
    let clients =
        [
            for i in 0..2 -> BeaconClient(new HttpClient(), Uri $"http://{host}{i}.test", TimeSpan.FromSeconds 1.0)
        ]

    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, broadcast = broadcast)

    for c in clients do
        nodes.MarkReady c

    clients, nodes

let private waitFor (cond: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 5.0 do
            do! Task.Delay 5
    }

/// Every send counts when it ends, also the ones that end after the broadcast returned.
let private submissionsCounted () =
    task {
        use counts = new Submissions "cnta"
        let clients, nodes = namedNodes "cnta" BroadcastTopic.All

        let late =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        let f (c: BeaconClient) =
            match indexOf clients c with
            | 0 -> ok
            | 1 -> late.Task
            | i -> down i

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        Expect.equal r (Ok()) "node 0 accepted"
        Expect.equal (counts.Get(1, "attestations", "accepted")) 0L "node 1 has not answered yet"
        late.SetResult(Ok())
        do! waitFor (fun () -> counts.Total >= 3L)
        Expect.equal (counts.Get(0, "attestations", "accepted")) 1L "node 0 accepted"
        Expect.equal (counts.Get(1, "attestations", "accepted")) 1L "node 1 accepted after the broadcast returned"
        Expect.equal (counts.Get(2, "attestations", "failed")) 1L "node 2 failed"
        Expect.equal counts.Total 3L "one count per send"
    }

/// A topic out of the setting goes one node at a time; each try counts.
let private submissionsCountedFailover () =
    task {
        use counts = new Submissions "cntb"
        let clients, nodes = namedNodes "cntb" BroadcastTopic.None

        let f (c: BeaconClient) =
            match indexOf clients c with
            | 0 -> down 0
            | _ -> ok

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Blocks)
        Expect.equal r (Ok()) "the second node accepted"
        Expect.equal (counts.Get(0, "blocks", "failed")) 1L "the primary failed"
        Expect.equal (counts.Get(1, "blocks", "accepted")) 1L "the next node accepted"
        Expect.equal counts.Total 2L "the third node was not tried"
    }

/// A node at MaxBackground is skipped, and the skip counts.
let private submissionsCountedSkipped () =
    task {
        use counts = new Submissions "cntc"
        let clients, nodes = namedNodes "cntc" BroadcastTopic.All

        let hang =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        let f (c: BeaconClient) = if indexOf clients c = 2 then hang.Task else ok

        for _ in 1 .. BeaconNodes.MaxBackground + 2 do
            let! _ = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.SyncCommittee)
            ()

        Expect.equal (counts.Get(2, "sync_committee", "skipped")) 2L "two sends skipped the hanging node"
        Expect.equal (counts.Get(2, "sync_committee", "accepted")) 0L "its running sends have not ended"
        hang.SetResult(Ok())
        do! waitFor (fun () -> counts.Get(2, "sync_committee", "accepted") >= int64 BeaconNodes.MaxBackground)

        Expect.equal
            (counts.Get(2, "sync_committee", "accepted"))
            (int64 BeaconNodes.MaxBackground)
            "the hanging sends count when they end"

        Expect.equal
            (counts.Get(0, "sync_committee", "accepted"))
            (int64 BeaconNodes.MaxBackground + 2L)
            "node 0 took every send"
    }

/// Records the `submit` spans under a parent span of the test's own, so spans of tests running
/// at the same time do not count. `sample = false` makes the sampler drop every span.
type private SubmitSpans(sample: bool) =
    let spans = ConcurrentQueue<Diagnostics.Activity>()
    let listener = new Diagnostics.ActivityListener()
    let mutable parent: Diagnostics.Activity | null = null

    do
        listener.ShouldListenTo <- fun s -> s.Name = Tracing.SourceName

        listener.Sample <-
            fun _ ->
                if sample then
                    Diagnostics.ActivitySamplingResult.AllDataAndRecorded
                else
                    Diagnostics.ActivitySamplingResult.None

        listener.ActivityStopped <-
            fun a ->
                match parent with
                | null -> ()
                | p ->
                    if a.OperationName = "submit" && a.TraceId = p.TraceId then
                        spans.Enqueue a

        Diagnostics.ActivitySource.AddActivityListener listener

        if sample then
            parent <- Tracing.source.StartActivity "test"

    member _.Spans = List.ofSeq spans

    interface IDisposable with
        member _.Dispose() =
            match parent with
            | null -> ()
            | p -> p.Dispose()

            listener.Dispose()

let private tagOf (a: Diagnostics.Activity) (key: string) = a.GetTagItem key

/// Traced: the same answer as untraced, the span stops at the first accept while a node still
/// hangs, its tags, and the late send still ends (Running back to 0).
let private tracedBroadcast () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All
        use spans = new SubmitSpans(true)

        let hang =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        let f (c: BeaconClient) =
            match indexOf clients c with
            | 0 -> hang.Task
            | 1 -> ok
            | i -> down i

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        Expect.equal r (Ok()) "the same answer as untraced"

        match spans.Spans with
        | [ a ] ->
            Expect.equal (tagOf a "eplix.nodes") (box 3) "eplix.nodes: the nodes with the role"
            Expect.equal (tagOf a "eplix.broadcast") (box true) "eplix.broadcast"
            Expect.equal a.Status Diagnostics.ActivityStatusCode.Unset "no error"
        | xs -> failtestf "one submit span stopped while node 0 still hangs, got %d" xs.Length

        Expect.equal nodes.Running[0] 1 "node 0's send still runs"
        hang.SetResult(Ok())
        do! waitFor (fun () -> nodes.Running[0] = 0)
        Expect.equal nodes.Running [| 0; 0; 0 |] "the late send ended"
        let! r = nodes.Broadcast((fun _ -> down 0), NodeRole.All, BroadcastTopic.Attestations)
        Expect.isError r "every node failed"
        Expect.equal (List.last spans.Spans).Status Diagnostics.ActivityStatusCode.Error "an error status when all fail"
    }

/// The sampler drops the span (null activity): the broadcast works as untraced.
let private tracedDropped () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All
        use spans = new SubmitSpans(false)

        let! r =
            nodes.Broadcast(
                (fun c -> if indexOf clients c = 2 then ok else down 0),
                NodeRole.All,
                BroadcastTopic.Attestations
            )

        Expect.equal r (Ok()) "accepted"
        let! r = nodes.Broadcast((fun _ -> down 0), NodeRole.All, BroadcastTopic.Attestations)
        Expect.isError r "all failed"
        Expect.isEmpty spans.Spans "no span"
    }

/// A cancelled failover goes on as a cancellation, with the tags and an error status on the span,
/// and no next node is tried.
let private tracedCancelled () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.None
        use spans = new SubmitSpans(true)
        let called = ConcurrentQueue<int>()

        let f (c: BeaconClient) : Task<Result<unit, ApiError>> =
            called.Enqueue(indexOf clients c)
            raise (OperationCanceledException "the caller stopped")

        let! thrown =
            task {
                try
                    let! _ = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Blocks)
                    return false
                with :? OperationCanceledException ->
                    return true
            }

        Expect.isTrue thrown "the cancellation goes on"
        Expect.equal (List.ofSeq called) [ 0 ] "no next node after a cancellation"

        match spans.Spans with
        | [ a ] ->
            Expect.equal a.Status Diagnostics.ActivityStatusCode.Error "error status"
            Expect.equal a.StatusDescription "cancelled" "cancelled"
            Expect.equal (tagOf a "eplix.nodes") (box 3) "tagged"
            Expect.equal (tagOf a "eplix.broadcast") (box false) "tagged"
        | xs -> failtestf "one submit span, got %d" xs.Length
    }

/// Traced failover: the same order as untraced.
let private tracedFailover () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.None
        use spans = new SubmitSpans(true)
        let called = ConcurrentQueue<int>()

        let f (c: BeaconClient) =
            let i = indexOf clients c
            called.Enqueue i
            if i = 0 then down 0 else ok

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Blocks)
        Expect.equal r (Ok()) "the second node accepted"
        Expect.equal (List.ofSeq called) [ 0; 1 ] "best node first, then the next"
        Expect.equal spans.Spans.Length 1 "one span"
    }

/// A node whose f throws at once or returns a faulted task: an error of that node, scored and
/// counted, and its send counter back to 0.
let private throwingSends () =
    task {
        use counts = new Submissions "cntd"
        let clients, nodes = namedNodes "cntd" BroadcastTopic.All

        let f (c: BeaconClient) : Task<Result<unit, ApiError>> =
            match indexOf clients c with
            | 0 -> raise (InvalidOperationException "thrown")
            | 1 -> Task.FromException<Result<unit, ApiError>>(InvalidOperationException "faulted")
            | _ -> ok

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        Expect.equal r (Ok()) "node 2 accepted"
        do! waitFor (fun () -> counts.Total >= 3L)
        Expect.equal (counts.Get(0, "attestations", "failed")) 1L "thrown: failed"
        Expect.equal (counts.Get(1, "attestations", "failed")) 1L "faulted: failed"
        Expect.equal (counts.Get(2, "attestations", "accepted")) 1L "accepted"
        Expect.equal (scoreOf nodes 0) 95 "thrown: scored"
        Expect.equal (scoreOf nodes 1) 95 "faulted: scored"
        Expect.equal nodes.Running [| 0; 0; 0 |] "no send left running"
    }

/// The caller's token fires while every send waits: the broadcast answers, it does not hang.
let private cancelledMidBroadcast () =
    task {
        let _, nodes = threeNodes BroadcastTopic.All
        use cts = new Threading.CancellationTokenSource()

        let f (_: BeaconClient) =
            task {
                do! Task.Delay(Threading.Timeout.Infinite, cts.Token)
                return Ok()
            }

        let call = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Attestations)
        cts.CancelAfter 50
        let! first = Task.WhenAny(call, Task.Delay 5000)
        Expect.isTrue (Object.ReferenceEquals(first, call)) "answered after the cancel"
        Expect.equal call.Result (Error(ApiError.Transport "send cancelled")) "the first node's error"
        do! waitFor (fun () -> nodes.Running = [| 0; 0; 0 |])
        Expect.equal nodes.Running [| 0; 0; 0 |] "no send left running"
    }

/// Node 0 at MaxBackground is skipped and the others fail: the answer is node 0's skip.
let private skippedFirstOthersFail () =
    task {
        let clients, nodes = threeNodes BroadcastTopic.All

        let hang =
            TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

        for _ in 1 .. BeaconNodes.MaxBackground do
            let! _ =
                nodes.Broadcast(
                    (fun c -> if indexOf clients c = 0 then hang.Task else ok),
                    NodeRole.All,
                    BroadcastTopic.Attestations
                )

            ()

        let! r = nodes.Broadcast((fun c -> down (indexOf clients c)), NodeRole.All, BroadcastTopic.Attestations)

        Expect.equal
            r
            (Error(ApiError.Transport $"{BeaconNodes.MaxBackground} earlier sends to this node still running; skipped"))
            "node 0's skip, the first node in config order"

        hang.SetResult(Ok())
        do! waitFor (fun () -> nodes.Running[0] = 0)
    }

/// A failover whose first node throws tries the next node and counts the throw.
let private failoverThrows () =
    task {
        use counts = new Submissions "cnte"
        let clients, nodes = namedNodes "cnte" BroadcastTopic.None
        let called = ConcurrentQueue<int>()

        let f (c: BeaconClient) : Task<Result<unit, ApiError>> =
            let i = indexOf clients c
            called.Enqueue i
            if i = 0 then raise (InvalidOperationException "thrown") else ok

        let! r = nodes.Broadcast(f, NodeRole.All, BroadcastTopic.Blocks)
        Expect.equal r (Ok()) "node 1 accepted"
        Expect.equal (List.ofSeq called) [ 0; 1 ] "node 1 tried after node 0 threw"
        Expect.equal (counts.Get(0, "blocks", "failed")) 1L "node 0 counted as failed"
        Expect.equal (scoreOf nodes 0) 95 "node 0 scored"

        let! r =
            nodes.Call(fun c -> if indexOf clients c = 1 then raise (InvalidOperationException "thrown") else ok)

        Expect.equal r (Ok()) "Call: past the throwing node too"
    }

/// Runs a broadcast test with a listener on the core's spans that keeps every span.
let private withListener (body: unit -> Task<unit>) () =
    task {
        use l = new Diagnostics.ActivityListener()
        l.ShouldListenTo <- fun s -> s.Name = Tracing.SourceName
        l.Sample <- fun _ -> Diagnostics.ActivitySamplingResult.AllDataAndRecorded
        Diagnostics.ActivitySource.AddActivityListener l
        do! body ()
    }

let private broadcastConfig =
    test "config: broadcast takes true, false, a list or a comma-separated string" {
        let parsed (v: string) =
            match parse $""" "beacon_node": "http://a:1", "broadcast": {v} """ with
            | Ok c -> c.Broadcast
            | Error es -> failtestf "%s: %A" v es

        match parse """ "beacon_node": "http://a:1" """ with
        | Ok c -> Expect.equal c.Broadcast BroadcastTopic.All "default: every topic"
        | Error es -> failtestf "%A" es

        Expect.equal (parsed "true") BroadcastTopic.All "true"

        Expect.equal
            (parsed "false")
            (BroadcastTopic.Subscriptions ||| BroadcastTopic.Preparations)
            "false: Lighthouse's default"

        Expect.equal (parsed "\"none\"") BroadcastTopic.None "none"
        Expect.equal (parsed "[]") BroadcastTopic.None "empty list"

        Expect.equal
            (parsed "[ \"attestations\", \"blocks\" ]")
            (BroadcastTopic.Attestations ||| BroadcastTopic.Blocks)
            "list"

        Expect.equal
            (parsed "\"sync_committee, subscriptions\"")
            (BroadcastTopic.SyncCommittee ||| BroadcastTopic.Subscriptions)
            "string"

        Expect.equal
            (BroadcastTopic.describe (BroadcastTopic.Attestations ||| BroadcastTopic.Exits))
            "attestations, exits"
            "describe"

        refused """ "beacon_node": "http://a:1", "broadcast": [ "attestation" ] """ "unknown topic 'attestation'"
        refused """ "beacon_node": "http://a:1", "broadcast": 1 """ "must be true, false, or a list"
    }

[<Tests>]
let broadcastTests =
    testSequenced
    <| testList
        "broadcast"
        [
            broadcastConfig
            // Every send test runs twice, without and with a span listener: HasListeners is
            // process-wide, so both runs sit in this one sequenced list.
            for traced in [ false; true ] do
                let name (n: string) = if traced then n + " (traced)" else n
                let run body = if traced then withListener body else body

                testT
                    (name "on: returns with the fast node while another hangs; the late answer scores")
                    (run broadcastOnFast)

                testT (name "on: every node fails, the first node's error") (run broadcastOnAllFail)
                testT (name "off: only the primary when it accepts") (run broadcastOffPrimaryOnly)
                testT (name "off: the next node on failure, an error when all fail") (run broadcastOffFallback)
                testT (name "off: the next node after the primary's request timeout") (run broadcastOffTimeout)
                testT (name "per topic") (run broadcastTopics)
                testT (name "a hanging node gets a bounded number of sends") (run broadcastBounded)
                testT (name "submissions count per node and topic, late sends included") (run submissionsCounted)
                testT (name "submissions count each failover try") (run submissionsCountedFailover)
                testT (name "submissions count a skipped node") (run submissionsCountedSkipped)
                testT (name "a send that throws or faults is that node's error") (run throwingSends)
                testT (name "the caller's token fires mid-broadcast: no hang") (run cancelledMidBroadcast)
                testT (name "node 0 skipped and the others fail: node 0's skip") (run skippedFirstOthersFail)
                testT (name "failover past a node that throws") (run failoverThrows)
            testT "traced: same answer, span stops at the first accept, tags, error when all fail" tracedBroadcast
            testT "traced: the sampler drops the span" tracedDropped
            testT "traced: a cancelled send keeps the tags and an error status" tracedCancelled
            testT "traced: failover order" tracedFailover
        ]

/// The clients each call shape reached, by index.
let private reachedBy (clients: BeaconClient list) (nodes: BeaconNodes) =
    task {
        let seen = ConcurrentBag<int>()

        let f (c: BeaconClient) =
            seen.Add(indexOf clients c)
            Task.FromResult(Ok 1)

        let! _ = nodes.Call f

        let! _ =
            nodes.Broadcast((fun c -> task { let! _ = f c in return Ok() }), NodeRole.All, BroadcastTopic.All)

        let! asked = nodes.AskAll f

        let! _ =
            nodes.HighestValue(
                f,
                (fun _ -> Numerics.BigInteger.One),
                DateTimeOffset.UtcNow,
                Threading.CancellationToken.None
            )

        let! _ =
            nodes.Most(
                f,
                id,
                (fun _ -> false),
                DateTimeOffset.UtcNow.AddMilliseconds 200.0,
                Threading.CancellationToken.None
            )

        return Set.ofSeq seen, asked |> Array.map Result.isOk
    }

[<Tests>]
let mostTests =
    testList
        "most bits"
        [
            testT
                "Most stops at the soft cutoff once a node answered; a hung node does not hold it to the deadline"
                (fun () ->
                    task {
                        let clients = [ client 0; client 1 ]
                        let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)

                        let hang =
                            TaskCompletionSource<Result<int, ApiError>>(
                                TaskCreationOptions.RunContinuationsAsynchronously
                            )

                        let f (c: BeaconClient) = if indexOf clients c = 0 then hang.Task else Task.FromResult(Ok 3)
                        let now = DateTimeOffset.UtcNow
                        let sw = Diagnostics.Stopwatch.StartNew()

                        let! r =
                            nodes.Most(
                                f,
                                id,
                                (fun _ -> false),
                                now.AddSeconds 30.0,
                                Threading.CancellationToken.None,
                                soft = now.AddMilliseconds 100.0
                            )

                        Expect.equal r (Ok 3) "the answer of the node that answered"

                        Expect.isLessThan
                            sw.Elapsed
                            (TimeSpan.FromSeconds 5.0)
                            "returned at the soft cutoff, not the deadline"

                        hang.SetResult(Ok 9)
                    })

            testT "Most with no answer by the soft cutoff takes the first answer after it" (fun () ->
                task {
                    let clients = [ client 0; client 1 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)

                    let hang =
                        TaskCompletionSource<Result<int, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

                    let f (c: BeaconClient) =
                        if indexOf clients c = 0 then
                            hang.Task
                        else
                            task {
                                do! Task.Delay 400
                                return Ok 2
                            }

                    let now = DateTimeOffset.UtcNow
                    let sw = Diagnostics.Stopwatch.StartNew()

                    let! r =
                        nodes.Most(
                            f,
                            id,
                            (fun _ -> false),
                            now.AddSeconds 30.0,
                            Threading.CancellationToken.None,
                            soft = now.AddMilliseconds 50.0
                        )

                    Expect.equal r (Ok 2) "the late answer"
                    Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 5.0) "did not wait for the hung node"
                    hang.SetResult(Ok 9)
                })

            testT "Most: the most bits win; an answer that fails the check does not count" (fun () ->
                task {
                    let clients = [ client 0; client 1; client 2 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)

                    // Node 2 answers all 8 bits at once; nodes 0 and 1 answer 5 and 3 a little later.
                    let f (c: BeaconClient) =
                        match indexOf clients c with
                        | 2 -> Task.FromResult(Ok 8)
                        | i ->
                            task {
                                do! Task.Delay 100
                                return Ok(if i = 0 then 5 else 3)
                            }

                    let! r =
                        nodes.Most(
                            f,
                            id,
                            (fun n -> n = 8),
                            DateTimeOffset.UtcNow.AddSeconds 10.0,
                            Threading.CancellationToken.None
                        )

                    Expect.equal r (Ok 8) "node 2's answer, with the most bits, though node 0 ranks first"

                    let! checkedOut =
                        nodes.Most(
                            f,
                            id,
                            (fun n -> n = 8),
                            DateTimeOffset.UtcNow.AddSeconds 10.0,
                            Threading.CancellationToken.None,
                            valid = (fun n -> if n = 8 then ValueSome "other data" else ValueNone)
                        )

                    Expect.equal checkedOut (Ok 5) "an answer that fails the check does not count"
                })

            testT "Most returns at once on a complete answer" (fun () ->
                task {
                    let clients = [ client 0; client 1; client 2 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)

                    let hang =
                        TaskCompletionSource<Result<int, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

                    let f (c: BeaconClient) = if indexOf clients c = 1 then Task.FromResult(Ok 8) else hang.Task
                    let sw = Diagnostics.Stopwatch.StartNew()

                    let! r =
                        nodes.Most(
                            f,
                            id,
                            (fun n -> n = 8),
                            DateTimeOffset.UtcNow.AddSeconds 30.0,
                            Threading.CancellationToken.None
                        )

                    Expect.equal r (Ok 8) "complete"
                    Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 5.0) "did not wait for the hung node"
                    hang.SetResult(Ok 1)
                })

            testT
                "Most: with two nodes the second-ranked one's answer wins on more bits; equal counts go to rank"
                (fun () ->
                    task {
                        let clients = [ client 0; client 1 ]
                        let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)
                        let mutable bits = [| 3; 6 |]

                        // Node 1 answers at once, node 0 a little later: each answer is (bits, node).
                        let f (c: BeaconClient) =
                            let i = indexOf clients c

                            task {
                                if i = 0 then
                                    do! Task.Delay 100

                                return Ok(bits[i], i)
                            }

                        let most () =
                            nodes.Most(
                                f,
                                fst,
                                (fun _ -> false),
                                DateTimeOffset.UtcNow.AddSeconds 10.0,
                                Threading.CancellationToken.None
                            )

                        let! r = most ()
                        Expect.equal r (Ok(6, 1)) "node 1's 6 bits beat node 0's 3"
                        bits <- [| 5; 5 |]
                        let! tie = most ()
                        Expect.equal tie (Ok(5, 0)) "equal counts: node 0, first in the config"
                    })

            testT "Most without a soft cutoff waits for every node until the deadline, as before" (fun () ->
                task {
                    let clients = [ client 0; client 1 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)

                    let f (c: BeaconClient) =
                        if indexOf clients c = 0 then
                            task {
                                do! Task.Delay 300
                                return Ok 7
                            }
                        else
                            Task.FromResult(Ok 3)

                    let! r =
                        nodes.Most(
                            f,
                            id,
                            (fun _ -> false),
                            DateTimeOffset.UtcNow.AddSeconds 10.0,
                            Threading.CancellationToken.None
                        )

                    Expect.equal r (Ok 7) "the slower answer with more bits"
                })
        ]

/// CallPreferring with three nodes; answers below 10 are not preferred (optimistic).
let private preferringNodes () =
    let clients = [ client 0; client 1; client 2 ]
    clients, BeaconNodes(clients, 1, TimeProvider.System, Log.none)

/// The call, failed when it has not answered after `limit` of real time.
let private within (limit: TimeSpan) (call: Task<Result<int, ApiError>>) =
    task {
        let! first = Task.WhenAny(call, Task.Delay limit)

        if not (Object.ReferenceEquals(first, call)) then
            failtestf "no answer within %O" limit

        return call.Result
    }

[<Tests>]
let preferringTests =
    testList
        "call preferring"
        [
            testT "a preferred first answer is one call" (fun () ->
                task {
                    let clients, nodes = preferringNodes ()
                    let called = ConcurrentBag<int>()

                    let f (c: BeaconClient) =
                        called.Add(indexOf clients c)
                        Task.FromResult(Ok 10)

                    let! r = nodes.CallPreferring(f, (fun v -> v >= 10))
                    Expect.equal r (Ok 10) "the first answer"
                    Expect.equal (List.ofSeq called) [ 0 ] "only the best node asked"
                })

            // The best node answers optimistic and the others hang. Before, each hung
            // node held the call for its request timeout in turn; now the answer in hand comes back
            // after PreferWait.
            testT "a non-preferred answer with the other nodes hung comes back after PreferWait" (fun () ->
                task {
                    let clients, nodes = preferringNodes ()

                    let hang =
                        TaskCompletionSource<Result<int, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

                    let called = ConcurrentBag<int>()

                    let f (c: BeaconClient) =
                        let i = indexOf clients c
                        called.Add i
                        if i = 0 then Task.FromResult(Ok 1) else hang.Task

                    let sw = Diagnostics.Stopwatch.StartNew()
                    let! r = within (TimeSpan.FromSeconds 4.0) (nodes.CallPreferring(f, (fun v -> v >= 10)))
                    Expect.equal r (Ok 1) "the answer in hand"

                    Expect.isGreaterThanOrEqual
                        sw.Elapsed
                        (BeaconNodes.PreferWait - TimeSpan.FromMilliseconds 50.0)
                        "waited for a better answer"

                    Expect.isLessThan sw.Elapsed (BeaconNodes.PreferWait + TimeSpan.FromSeconds 1.5) "not much longer"
                    Expect.equal (Set.ofSeq called) (set [ 0; 1; 2 ]) "both other nodes asked"
                    hang.SetResult(Error(ApiError.Transport "late"))
                })

            testT
                "after a non-preferred answer, the other nodes are asked at once; a hung one does not hold a preferred answer"
                (fun () ->
                    task {
                        let clients, nodes = preferringNodes ()

                        let hang =
                            TaskCompletionSource<Result<int, ApiError>>(
                                TaskCreationOptions.RunContinuationsAsynchronously
                            )

                        let f (c: BeaconClient) =
                            match indexOf clients c with
                            | 0 -> Task.FromResult(Ok 1)
                            | 1 -> hang.Task
                            | _ ->
                                task {
                                    do! Task.Delay 50
                                    return Ok 12
                                }

                        let sw = Diagnostics.Stopwatch.StartNew()
                        let! r = within (TimeSpan.FromSeconds 4.0) (nodes.CallPreferring(f, (fun v -> v >= 10)))
                        Expect.equal r (Ok 12) "the preferred answer of the third node"
                        Expect.isLessThan sw.Elapsed BeaconNodes.PreferWait "without waiting for the hung node"
                        hang.SetResult(Ok 11)
                    })

            testT "errors before the first good answer pass the call on one node at a time" (fun () ->
                task {
                    let clients, nodes = preferringNodes ()
                    let called = ConcurrentBag<int>()

                    let f (c: BeaconClient) =
                        let i = indexOf clients c
                        called.Add i
                        if i = 0 then Task.FromResult(Error(ApiError.Transport "down")) else Task.FromResult(Ok 10)

                    let! r = nodes.CallPreferring(f, (fun v -> v >= 10))
                    Expect.equal r (Ok 10) "the second node's answer"
                    Expect.equal (List.ofSeq called |> List.sort) [ 0; 1 ] "the third node not asked"
                })

            testT "no preferred answer: the first good one, also when a later node fails" (fun () ->
                task {
                    let clients, nodes = preferringNodes ()

                    let f (c: BeaconClient) =
                        match indexOf clients c with
                        | 0 -> Task.FromResult(Ok 1)
                        | 1 -> Task.FromResult(Error(ApiError.Transport "down"))
                        | _ -> Task.FromResult(Ok 2)

                    let! r = within (TimeSpan.FromSeconds 4.0) (nodes.CallPreferring(f, (fun v -> v >= 10)))
                    Expect.equal r (Ok 1) "the best node's answer"
                })
        ]

[<Tests>]
let readinessTests =
    testList
        "node-readiness"
        [
            testT "with requireReady a node gets no call before it passed the start checks" (fun () ->
                task {
                    let clients = [ client 0; client 1 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, requireReady = true)
                    let! none, asked = reachedBy clients nodes
                    Expect.isEmpty none "no node is ready: no call"
                    Expect.equal asked [| false; false |] "AskAll answers an error per node, in config order"
                    let! r = nodes.Call(fun _ -> Task.FromResult(Ok 1))
                    Expect.isError r "Call fails"
                    let! d = nodes.AttestationData(1UL, ValueNone, 0UL, Threading.CancellationToken.None)
                    Expect.isError d "no attestation data without a ready node, and no wait for the slot to end"
                    nodes.MarkReady clients[1]
                    let! one, asked = reachedBy clients nodes
                    Expect.equal one (set [ 1 ]) "only the ready node"
                    Expect.equal asked [| false; true |] "AskAll asks the ready node only"
                    Expect.equal (nodes.NodesWith NodeRole.All) clients "NodesWith keeps the config order of AskAll"
                })

            testT "a dropped node gets no call again, also after MarkReady" (fun () ->
                task {
                    let clients = [ client 0; client 1 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none, requireReady = true)

                    for c in clients do
                        nodes.MarkReady c

                    let! both, _ = reachedBy clients nodes
                    Expect.equal both (set [ 0; 1 ]) "both ready"
                    nodes.Drop(clients[0], "test")
                    nodes.MarkReady clients[0]
                    let! one, _ = reachedBy clients nodes
                    Expect.equal one (set [ 1 ]) "the dropped node stays out"
                    Expect.isFalse (nodes.InUse clients[0]) "not in use"
                })

            testT "a drop ends the node's open event stream" (fun () ->
                task {
                    let node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    let c = BeaconClient(new HttpClient(node, false), Uri "http://bn0.test", TimeSpan.FromSeconds 5.0)
                    let nodes = BeaconNodes([ c ], 1, TimeProvider.System, Log.none, requireReady = true)
                    nodes.MarkReady c
                    use cts = new Threading.CancellationTokenSource(TimeSpan.FromSeconds 30.0)
                    let run = nodes.RunEvents([ "head" ], ignore, cts.Token)
                    let mutable waited = 0

                    while not (node.Requests |> Seq.exists (fun p -> p.Contains "/eth/v1/events")) && waited < 100 do
                        do! Task.Delay 50
                        waited <- waited + 1

                    Expect.isFalse run.IsCompleted "the stream is open"
                    nodes.Drop(c, "test")
                    let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 10.0))

                    Expect.isTrue
                        (Object.ReferenceEquals(winner, run))
                        "the open stream ended with the drop, not at its idle limit"

                    Expect.isFalse cts.IsCancellationRequested "not by the caller's token"
                })

            testT "a drop that leaves too few nodes calls the loss handler, and only then" (fun () ->
                task {
                    let clients = [ client 0; client 1; client 2 ]
                    let nodes = BeaconNodes(clients, 2, TimeProvider.System, Log.none, requireReady = true)

                    for c in clients do
                        nodes.MarkReady c

                    let reasons = ConcurrentQueue<string>()
                    nodes.OnLoss reasons.Enqueue
                    Expect.isEmpty reasons "3 of threshold 2: nothing"
                    nodes.Drop(clients[1], "lied")
                    Expect.isEmpty reasons "2 left: the VC goes on"
                    Expect.equal nodes.Shortfall ValueNone "no shortfall"
                    nodes.Drop(clients[1], "again")
                    Expect.isEmpty reasons "a node is dropped once"
                    nodes.Drop(clients[2], "lied too")

                    match List.ofSeq reasons with
                    | [ r ] ->
                        Expect.stringContains r "lied too" "the node's fault"
                        Expect.stringContains r "attestation_consensus_threshold is 2" "the shortfall"
                    | rs -> failtestf "one call: %A" rs
                    // A handler set after the loss is called at once.
                    let late = ConcurrentQueue<string>()
                    nodes.OnLoss late.Enqueue
                    Expect.equal late.Count 1 "called at once"
                })

            testT "without requireReady every node is used from the start (tests and tools)" (fun () ->
                task {
                    let clients = [ client 0; client 1 ]
                    let nodes = BeaconNodes(clients, 1, TimeProvider.System, Log.none)
                    let! both, _ = reachedBy clients nodes
                    Expect.equal both (set [ 0; 1 ]) "both"
                })
        ]
