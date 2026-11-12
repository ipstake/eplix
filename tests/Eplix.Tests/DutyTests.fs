/// Duties end to end on a fake clock: proposals, aggregation, sync committee, exits, and
/// attestation data consensus over several beacon nodes.
module Eplix.Tests.DutyTests

open System
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let private signingRoot (h: Harness) (domainType: DomainType) (epoch: Epoch) (objectRoot: Root) =
    Signing.computeSigningRoot objectRoot (Signing.domainAt h.Spec gvr domainType epoch)

/// Polls a condition in real time; the fake clock does not move on its own.
let private waitForLog (lines: Collections.Concurrent.ConcurrentQueue<string>) (what: string) (cond: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what (String.Join("\n", lines))
    }

let private waitFor what cond = waitForLog (Collections.Concurrent.ConcurrentQueue()) what cond

let private posts (h: Harness) (suffix: string) =
    h.Node.Posts |> Seq.filter (fun (p, _) -> p.EndsWith suffix) |> Seq.map snd |> List.ofSeq

let private jsonItems (body: string) =
    use d = JsonDocument.Parse body
    [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

/// Moves the fake clock to `t` if it is later than now.
let private advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

let private stop (cts: CancellationTokenSource) (run: Task) (db: SlashingDb) =
    task {
        cts.Cancel()
        do! run
        (db :> IDisposable).Dispose()
    }

/// Local keys whose signatures for the matching duties wait until the test opens the gate.
let private gatedKeys (keys: int list) (held: Duty -> bool) =
    let gate = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

    let inner =
        LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    let backend =
        { inner with
            Sign =
                fun r ct ->
                    task {
                        if held r.Duty then
                            do! gate.Task.WaitAsync ct

                        return! inner.Sign r ct
                    }
        }

    [ for i in keys -> pubkeyOf i, backend ], (fun () -> gate.TrySetResult() |> ignore)

let private proposalTest (asJson: bool) =
    testT (if asJson then "proposal with a JSON block" else "proposal with an SSZ block") (fun () ->
        task {
            let h = harness ()

            for i in 0..7 do
                h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

            h.Node.BlockAsJson <- asJson
            // Validator 3 proposes slot 10 (epoch 1, Fulu); validator 5 proposes slot 4 (epoch 0, Electra).
            h.Node.Proposals[10UL] <- 3UL
            h.Node.Proposals[4UL] <- 5UL
            use cts = new CancellationTokenSource()

            let! run, db, lines, scheduler =
                startScheduler h (Path.Combine(tempDir (), "s.db")) [ 0..7 ] false cts.Token
            // Slot by slot, so each block is signed before its slot ends on the fake clock.
            for s in 0UL .. 11UL do
                do! h.RunSlots(s, s)

                if h.Node.Proposals.ContainsKey s then
                    let before = if s = 4UL then 0 else 1
                    do! waitForLog lines $"the block of slot {s}" (fun () -> h.Node.Published.Count > before)

            do! stop cts run db
            let schema = Schemas.signedBlockContents h.Node.Preset

            let blocks =
                [
                    for version, contentType, bytes in h.Node.Published ->
                        Expect.equal contentType "application/octet-stream" "published as SSZ"

                        match Ssz.deserialize schema bytes with
                        | Ok v -> version, v
                        | Error e -> failtestf "published block does not decode: %s" e
                ]

            Expect.equal (blocks |> List.map fst) [ "electra"; "fulu" ] "fork version header per slot"

            for _, v in blocks do
                let signedBlock = Codec.fields (Codec.fields v).[0]
                let block = Codec.fields signedBlock[0]
                let slot = Codec.asU block[0]
                let proposer = h.Node.Validators[int (Codec.asU block[1])].PubKey

                let header =
                    {
                        Slot = slot
                        ProposerIndex = Codec.asU block[1]
                        ParentRoot = Root.Of(Codec.asBytes block[2])
                        StateRoot = Root.Of(Codec.asBytes block[3])
                        BodyRoot = Root.Of(Ssz.hashTreeRoot (Schemas.beaconBlockBody h.Node.Preset) block[4])
                    }

                let epoch = h.Spec.EpochOf slot
                let s = BlsSignature.Of(Codec.asBytes signedBlock[1])

                Expect.isTrue
                    (verify
                        proposer
                        (signingRoot h h.Spec.DomainBeaconProposer epoch (Codec.hashBeaconBlockHeader header))
                        s)
                    $"block signature at slot {slot}"

                let body = Codec.fields block[4]
                let reveal = BlsSignature.Of(Codec.asBytes body[0])

                Expect.isTrue
                    (verify proposer (signingRoot h h.Spec.DomainRandao epoch (Codec.hashEpoch epoch)) reveal)
                    "RANDAO reveal"
                // The block went through slashing protection.
                Expect.equal (db.Marks proposer).Value.Block.Value.Slot slot "block mark"

            let proposed =
                scheduler.Events
                |> Seq.choose (fun e ->
                    match e with
                    | Proposed(s, _) -> Some s
                    | _ -> None)
                |> List.ofSeq

            Expect.equal (List.sort proposed) [ 4UL; 10UL ] $"proposal events; log: {String.Join('\n', lines)}"
        })

[<Tests>]
let tests =
    testSequenced
    <| testList
        "duties"
        [
            proposalTest false
            proposalTest true

            testT "aggregation: selection proofs, subscriptions and aggregates" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startScheduler h (Path.Combine(tempDir (), "s.db")) [ 0..7 ] false cts.Token
                    // Slot by slot: the aggregate is due at 2/3 of the slot and must be signed before the slot ends.
                    for s in 0UL .. 7UL do
                        do! h.RunSlots(s, s)
                        advanceTo h (h.Clock.SlotStart s + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

                        do!
                            waitForLog lines $"aggregate of slot {s}" (fun () ->
                                (posts h "aggregate_and_proofs" |> List.collect jsonItems).Length >= int s + 1)

                    do! stop cts run db
                    let schema = Schemas.signedAggregateAndProof h.Node.Preset
                    let aggs = posts h "aggregate_and_proofs" |> List.collect jsonItems
                    Expect.equal aggs.Length 8 $"one aggregate per key in epoch 0; log: {String.Join('\n', lines)}"

                    for a in aggs do
                        match SszJson.tryRead schema a with
                        | Error e -> failtestf "aggregate does not decode: %s" e
                        | Ok v ->
                            let f = Codec.fields v
                            let msg = Codec.fields f[0]
                            let index = Codec.asU msg[0]
                            let pk = h.Node.Validators[int index].PubKey
                            let data = Codec.attestationDataOf (Codec.fields msg[1]).[1]
                            let epoch = h.Spec.EpochOf data.Slot
                            let proof = BlsSignature.Of(Codec.asBytes msg[2])

                            Expect.isTrue
                                (verify
                                    pk
                                    (signingRoot h h.Spec.DomainSelectionProof epoch (Codec.hashSlot data.Slot))
                                    proof)
                                "selection proof"

                            let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.aggregateAndProof h.Node.Preset) f[0])

                            Expect.isTrue
                                (verify
                                    pk
                                    (signingRoot h h.Spec.DomainAggregateAndProof epoch msgRoot)
                                    (BlsSignature.Of(Codec.asBytes f[1])))
                                "aggregate and proof signature"
                    // Subscriptions name every duty with the aggregator flag.
                    let subs = posts h "beacon_committee_subscriptions" |> List.collect jsonItems
                    Expect.isGreaterThanOrEqual subs.Length 8 "subscriptions for epoch 0"

                    Expect.isTrue
                        (subs |> List.forall (fun s -> s.GetProperty("is_aggregator").GetBoolean()))
                        "all aggregators at length 8"
                })

            testT "selection proofs that come back after the aggregate due time still make the aggregates" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    // A slow signer: the proofs of slot 0 are still out when the aggregate is due, and
                    // the next slot's loop asks for the selection of epoch 0 again meanwhile.
                    let routes, release = gatedKeys [ 0..7 ] (fun d -> d = Duty.AggregationSlot 0UL)
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startSchedulerWith h (Path.Combine(tempDir (), "s.db")) routes false cts.Token

                    do! h.RunSlots(0UL, 0UL)
                    advanceTo h (h.Clock.SlotStart 0UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)
                    release ()

                    do!
                        waitForLog lines "the aggregate of slot 0" (fun () ->
                            not (List.isEmpty (posts h "aggregate_and_proofs")))

                    do! stop cts run db
                    let aggs = posts h "aggregate_and_proofs" |> List.collect jsonItems
                    Expect.equal aggs.Length 1 $"one aggregator at slot 0; log: {String.Join('\n', lines)}"
                })

            testT "duties fetched again while selection proofs sign: the run starts over for the new duties" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    // The proofs of epoch 1 wait while its duties change.
                    let routes, release =
                        gatedKeys [ 0..7 ] (fun d ->
                            match d with
                            | Duty.AggregationSlot s -> s >= 8UL
                            | _ -> false)

                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startSchedulerWith h (Path.Combine(tempDir (), "s.db")) routes true cts.Token

                    do! h.RunSlots(0UL, 3UL)
                    // A reorg moves validator 0 in epoch 1 from slot 8 to slot 12.
                    h.Node.DutySlotOverride <-
                        fun v e -> if v.Index = 0UL && e = 1UL then ValueSome 12UL else ValueNone

                    h.Node.Reorg()
                    advanceTo h (h.Clock.SlotStart 4UL + TimeSpan.FromMilliseconds 100.0)
                    let waiter = h.Waiter.Wait 4UL
                    let mutable n = 0

                    while not waiter.IsCompleted && n < 200 do
                        h.Node.EmitHead 4UL
                        do! Task.Delay 20
                        n <- n + 1

                    do! waiter
                    let fetches () = h.Node.RequestCount "POST /eth/v1/validator/duties/attester/1"
                    do! waitForLog lines "the new duties of epoch 1" (fun () -> fetches () >= 2)
                    do! Task.Delay 200
                    release ()
                    do! h.RunSlots(5UL, 12UL)
                    advanceTo h (h.Clock.SlotStart 12UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

                    let at12 () =
                        posts h "aggregate_and_proofs"
                        |> List.collect jsonItems
                        |> List.filter (fun a ->
                            a
                                .GetProperty("message")
                                .GetProperty("aggregate")
                                .GetProperty("data")
                                .GetProperty("slot")
                                .GetString()
                                =
                                "12")
                        |> List.map (fun a -> a.GetProperty("message").GetProperty("aggregator_index").GetString())

                    do! waitForLog lines "the aggregates of slot 12" (fun () -> (at12 ()).Length >= 2)
                    do! stop cts run db

                    Expect.equal
                        (List.sort (at12 ()))
                        [ "0"; "4" ]
                        $"validators 0 and 4 aggregate in slot 12; log: {String.Join('\n', lines)}"
                })

            testT
                "a sync selection proof that comes back after the contribution due time still makes the contribution"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        h.Node.SyncSeats[0UL] <- [| 0UL |]
                        // The proof for slot 1, asked for after the messages of slot 0, is still out when the
                        // contribution of slot 1 is due.
                        let routes, release =
                            gatedKeys [ 0..3 ] (fun d ->
                                d = Duty.SyncSelectionProof { Slot = 1UL; SubcommitteeIndex = 0UL })

                        use cts = new CancellationTokenSource()

                        let! run, db, lines, _ =
                            startSchedulerWith h (Path.Combine(tempDir (), "s.db")) routes false cts.Token

                        do! h.RunSlots(0UL, 1UL)
                        advanceTo h (h.Clock.SlotStart 1UL + h.Spec.ContributionDue + TimeSpan.FromMilliseconds 1.0)
                        release ()

                        let at1 () =
                            posts h "contribution_and_proofs"
                            |> List.collect jsonItems
                            |> List.filter (fun c ->
                                c.GetProperty("message").GetProperty("contribution").GetProperty("slot").GetString() =
                                    "1")

                        do! waitForLog lines "the contribution of slot 1" (fun () -> not (List.isEmpty (at1 ())))
                        do! stop cts run db
                        Expect.equal (at1 ()).Length 1 $"one contribution at slot 1; log: {String.Join('\n', lines)}"
                    })

            testT "sync committee: one message per validator, one selection proof per subcommittee" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Validator 0 holds three seats in two subcommittees; validator 2 one seat.
                    h.Node.SyncSeats[0UL] <- [| 0UL; 1UL; 9UL |]
                    h.Node.SyncSeats[2UL] <- [| 16UL |]
                    h.Node.HeadRoot <- root 77
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startScheduler h (Path.Combine(tempDir (), "s.db")) [ 0..3 ] false cts.Token

                    do! h.RunSlots(0UL, 3UL)
                    advanceTo h (h.Clock.SlotStart 3UL + h.Spec.ContributionDue + TimeSpan.FromMilliseconds 1.0)

                    do!
                        waitForLog lines "contributions of slot 3" (fun () ->
                            posts h "contribution_and_proofs"
                            |> List.collect jsonItems
                            |> List.exists (fun c ->
                                c.GetProperty("message").GetProperty("contribution").GetProperty("slot").GetString() =
                                    "3"))

                    do! stop cts run db
                    let msgs = posts h "sync_committees" |> List.collect jsonItems
                    let slots = msgs |> List.map (fun m -> m.GetProperty("slot").GetString()) |> List.distinct

                    for s in slots do
                        let atSlot = msgs |> List.filter (fun m -> m.GetProperty("slot").GetString() = s)
                        Expect.equal atSlot.Length 2 $"one message per validator at slot {s}, not one per seat"

                    for m in msgs do
                        let index = UInt64.Parse(m.GetProperty("validator_index").GetString())
                        let slot = UInt64.Parse(m.GetProperty("slot").GetString())
                        let r = Root.TryParse(m.GetProperty("beacon_block_root").GetString()) |> ValueOption.get
                        Expect.equal r (root 77) "head root from the node"
                        let s = BlsSignature.TryParse(m.GetProperty("signature").GetString()) |> ValueOption.get

                        Expect.isTrue
                            (verify
                                h.Node.Validators[int index].PubKey
                                (signingRoot h h.Spec.DomainSyncCommittee (h.Spec.EpochOf slot) r)
                                s)
                            "sync committee message signature"

                    let schema = Schemas.signedContributionAndProof h.Node.Preset
                    let contribs = posts h "contribution_and_proofs" |> List.collect jsonItems

                    let perSlot =
                        contribs
                        |> List.choose (fun c ->
                            match SszJson.tryRead schema c with
                            | Ok v -> Some v
                            | Error e -> failtestf "contribution does not decode: %s" e)
                        |> List.map (fun v ->
                            let f = Codec.fields v
                            let msg = Codec.fields f[0]
                            let index = Codec.asU msg[0]
                            let c = Codec.fields msg[1]
                            let slot = Codec.asU c[0]
                            let sub = Codec.asU c[2]
                            let pk = h.Node.Validators[int index].PubKey
                            let epoch = h.Spec.EpochOf slot
                            let sel = Codec.hashSyncAggregatorSelectionData { Slot = slot; SubcommitteeIndex = sub }

                            Expect.isTrue
                                (verify
                                    pk
                                    (signingRoot h h.Spec.DomainSyncCommitteeSelectionProof epoch sel)
                                    (BlsSignature.Of(Codec.asBytes msg[2])))
                                "sync selection proof"

                            let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.contributionAndProof h.Node.Preset) f[0])

                            Expect.isTrue
                                (verify
                                    pk
                                    (signingRoot h h.Spec.DomainContributionAndProof epoch msgRoot)
                                    (BlsSignature.Of(Codec.asBytes f[1])))
                                "contribution and proof signature"

                            slot, (index, sub))

                    let at3 = perSlot |> List.filter (fun (s, _) -> s = 3UL) |> List.map snd |> List.sort

                    Expect.equal
                        at3
                        [ (0UL, 0UL); (0UL, 1UL); (2UL, 2UL) ]
                        $"one contribution per validator and subcommittee; log: {String.Join('\n', lines)}"
                })

            testT "a voluntary exit is signed with the Capella fork version" (fun () ->
                task {
                    let h = harness ()
                    let pk = pubkeyOf 0
                    let backend = LocalBackend.create "local" [ pk, SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]
                    let registry = KeyRegistry()
                    registry.Add(pk, backend) |> ignore

                    use db =
                        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, h.Time, Log.none)
                    // The key is only discovered: an exit is not slashable, so it may still be signed.
                    match!
                        Exits.sign h.Spec gvr pipeline pk 7UL 3UL DateTimeOffset.MaxValue CancellationToken.None
                    with
                    | Error e -> failtest e
                    | Ok(x, s) ->
                        let capella = h.Spec.Forks |> Array.find (fun f -> f.Name = Capella)
                        let domain = Signing.computeDomain h.Spec.DomainVoluntaryExit capella.Version gvr

                        Expect.isTrue
                            (verify pk (Signing.computeSigningRoot (Codec.hashVoluntaryExit x) domain) s)
                            "exit signature"

                    registry.SetState(pk, KeyState.Draining)
                    let! r = Exits.sign h.Spec gvr pipeline pk 7UL 3UL DateTimeOffset.MaxValue CancellationToken.None
                    Expect.isError r "a draining key signs nothing"
                })

            testT "attestation data needs the threshold of beacon nodes to agree" (fun () ->
                task {
                    let h = harness ()

                    let extra =
                        [
                            for _ in 1..2 -> new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                        ]

                    for n in h.Node :: extra do
                        for i in 0..7 do
                            n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // The third node sees another head.
                    extra[1]
                        .OverrideData(
                            Some(fun slot ->
                                { extra[1].DefaultData slot with
                                    BeaconBlockRoot = root 999
                                })
                        )

                    let clients =
                        (h.Node :: extra)
                        |> List.mapi (fun i n ->
                            BeaconClient(new HttpClient(n, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

                    let nodes = BeaconNodes(clients, 2, h.Time, Log.none)
                    let! d = nodes.AttestationData(1UL, ValueNone, 0UL, CancellationToken.None)
                    Expect.equal d (Ok(h.Node.DefaultData 1UL)) "two of three agree"
                    // Path A: a head event names the minority root; the checkpoints still need two nodes.
                    let! a = nodes.AttestationData(2UL, ValueSome(root 999), 0UL, CancellationToken.None)

                    Expect.equal
                        a
                        (Ok
                            { extra[1].DefaultData 2UL with
                                BeaconBlockRoot = root 999
                            })
                        "head from the event, checkpoints confirmed by two"
                    // Two nodes on two other heads: no majority, nothing to sign.
                    extra[0]
                        .OverrideData(
                            Some(fun slot ->
                                { extra[0].DefaultData slot with
                                    BeaconBlockRoot = root 998
                                })
                        )

                    use cts = new CancellationTokenSource(TimeSpan.FromMilliseconds 300.0)
                    let! none = nodes.AttestationData(3UL, ValueNone, 0UL, cts.Token)
                    Expect.isError none "no two nodes agree"
                    // Data ahead of the current epoch never counts.
                    let! ahead =
                        nodes.AttestationData(
                            9UL,
                            ValueNone,
                            0UL,
                            (new CancellationTokenSource(TimeSpan.FromMilliseconds 300.0)).Token
                        )

                    Expect.isError ahead "target epoch 1 while the current epoch is 0"
                })

            testT "every beacon node gets the attestations; duties come from the best node" (fun () ->
                task {
                    let h = harness ()
                    let second = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

                    for n in [ h.Node; second ] do
                        for i in 0..3 do
                            n.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // The first node fails duties; the second answers.
                    h.Node.Fail <- fun path -> path.Contains "/duties/"

                    let clients =
                        [
                            BeaconClient(
                                new HttpClient(h.Node, false),
                                Uri "http://bn0.test",
                                TimeSpan.FromSeconds 5.0
                            )
                            BeaconClient(
                                new HttpClient(second, false),
                                Uri "http://bn1.test",
                                TimeSpan.FromSeconds 5.0
                            )
                        ]

                    let nodes = BeaconNodes(clients, 1, h.Time, Log.none)

                    let backend =
                        LocalBackend.create
                            "local"
                            [ for i in 0..3 -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

                    let registry = KeyRegistry()

                    for i in 0..3 do
                        registry.Add(pubkeyOf i, backend) |> ignore

                    use db =
                        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, h.Time, Log.none)

                    let scheduler =
                        DutyScheduler(
                            h.Spec,
                            gvr,
                            h.Clock,
                            nodes,
                            registry,
                            pipeline,
                            Log.none,
                            {
                                UseEvents = false
                                OnSlotDone = h.Waiter.Done
                                OnEpoch =
                                    fun _ ct ->
                                        task {
                                            let! _ = refreshEmpty ValueNone nodes registry db Log.none ct
                                            ()
                                        }
                                Defaults =
                                    {
                                        FeeRecipient = ValueSome "0x00000000000000000000000000000000000000aa"
                                        Graffiti = "eplix"
                                        GasLimit = 1UL
                                    }
                            }
                        )

                    use cts = new CancellationTokenSource()
                    let run = scheduler.Run cts.Token
                    do! h.RunSlots(0UL, 7UL)
                    cts.Cancel()
                    do! run
                    Expect.equal h.Node.Submissions.Count 4 "node 0 got every attestation"
                    Expect.equal second.Submissions.Count 4 "node 1 got every attestation"

                    let prepared =
                        second.Posts |> Seq.filter (fun (p, _) -> p.EndsWith "prepare_beacon_proposer") |> List.ofSeq

                    Expect.isNonEmpty prepared "fee recipients sent"

                    Expect.stringContains
                        (snd prepared.Head)
                        "0x00000000000000000000000000000000000000aa"
                        "default fee recipient"
                })

            test "aggregator selection follows the spec's modulo" {
                let h = harness ()
                let sg = BlsSignature.Of(Bls.sign (ReadOnlySpan(secretOf 1)) (ReadOnlySpan(Array.zeroCreate<byte> 32)))
                Expect.isTrue (Selection.isAggregator h.Spec 8UL sg) "committee of 8: modulo 1"

                let hits =
                    [
                        for i in 0..199 ->
                            let s =
                                BlsSignature.Of(
                                    Bls.sign
                                        (ReadOnlySpan(secretOf (i % 200)))
                                        (ReadOnlySpan(
                                            BitConverter.GetBytes(int64 i) |> Array.append (Array.zeroCreate 24)
                                        ))
                                )

                            Selection.isAggregator h.Spec 128UL s
                    ]
                    |> List.filter id
                    |> List.length
                // Committee of 128: modulo 8, so about 25 of 200.
                Expect.isTrue (hits > 5 && hits < 60) $"about one in eight is an aggregator ({hits})"

                Expect.equal
                    (Selection.subcommittees h.Spec [| 0UL; 1UL; 9UL; 31UL |])
                    [| 0UL; 1UL; 3UL |]
                    "seats to subcommittees, deduplicated"
            }

            test "signing roots of every duty kind use the spec's domain types" {
                let h = harness ()
                let pk = pubkeyOf 0

                let check (duty: Duty) (domainType: DomainType) (epoch: Epoch) (objectRoot: Root) =
                    let r = Duty.request h.Spec gvr pk Priority.Low DateTimeOffset.MaxValue duty
                    Expect.equal r.SigningRoot (signingRoot h domainType epoch objectRoot) $"{duty.Kind}"

                check (Duty.RandaoReveal 3UL) h.Spec.DomainRandao 3UL (Codec.hashEpoch 3UL)
                check (Duty.AggregationSlot 17UL) h.Spec.DomainSelectionProof 2UL (Codec.hashSlot 17UL)
                check (Duty.SyncCommitteeMessage(9UL, root 5)) h.Spec.DomainSyncCommittee 1UL (root 5)
                let sel = { Slot = 9UL; SubcommitteeIndex = 2UL }

                check
                    (Duty.SyncSelectionProof sel)
                    h.Spec.DomainSyncCommitteeSelectionProof
                    1UL
                    (Codec.hashSyncAggregatorSelectionData sel)

                Expect.equal (Domain.Of(Array.zeroCreate 32)).Bytes.Length 32 "domain size"
            }

            testT "registry: a removed key stays removed until revived" (fun () ->
                task {
                    let backend = LocalBackend.create "local" []
                    let registry = KeyRegistry()
                    let pk = pubkeyOf 1
                    Expect.isTrue (registry.Add(pk, backend)) "added"
                    let v = registry.Version
                    registry.SetState(pk, KeyState.Removed)
                    Expect.isGreaterThan registry.Version v "version moves"
                    Expect.isFalse (registry.Add(pk, backend)) "a tombstone is not re-added"
                    Expect.isTrue (registry.Revive(pk, backend)) "explicit import revives"
                    Expect.equal (registry.TryGet pk).Value.State KeyState.Discovered "back to discovered"
                })
        ]
