/// The scheduler and the beacon node set against hostile or failing nodes: reorgs, slow and
/// unhealthy nodes, bad data, best block and aggregate, lost event streams, clock skew.
module Eplix.Tests.DutyGapTests

open System
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

/// (validator, slot) of every attestation a node received.
let private attested (n: FakeBeaconNode) = n.Submissions |> Seq.map (fun s -> s.AttesterIndex, s.Slot) |> List.ofSeq

let private attesterFetches (n: FakeBeaconNode) (epoch: Epoch) =
    n.RequestCount $"POST /eth/v1/validator/duties/attester/{epoch}"

let private reorgMovesDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let vc = startVc h { defaults with UseEvents = true }
        // Epoch 1: validator i attests in slot 8 + i.
        do! h.RunSlots(0UL, 10UL)
        Expect.equal (attesterFetches h.Node 1UL) 1 "epoch 1 duties fetched once so far"
        // A reorg swaps the slots of validators 4 and 6 in epoch 1 and changes every dependent root.
        h.Node.DutySlotOverride <-
            fun v epoch ->
                match v.Index, epoch with
                | 4UL, 1UL -> ValueSome 14UL
                | 6UL, 1UL -> ValueSome 12UL
                | _ -> ValueNone

        h.Node.Reorg()
        do! headUntilDone h 11UL h.Node.EmitHead
        do! h.RunSlots(12UL, 15UL)
        do! vc.Stop()
        Expect.isGreaterThanOrEqual (attesterFetches h.Node 1UL) 2 $"duties of epoch 1 fetched again; log:\n{vc.Log}"
        let at s = attested h.Node |> List.filter (fun (_, x) -> x = s) |> List.map fst
        Expect.equal (at 12UL) [ 6UL ] "slot 12: the duty that moved there"
        Expect.equal (at 14UL) [ 4UL ] "slot 14: validator 4's new slot"
        Expect.isFalse (attested h.Node |> List.contains (4UL, 12UL)) "the old duty is not signed"

        Expect.equal
            (attested h.Node |> List.distinct).Length
            h.Node.Submissions.Count
            "one attestation per validator and slot"

        Expect.isTrue (vc.Lines |> Seq.exists (fun l -> l.Contains "dependent root changed")) "logged"
    }

let private sameRootKeepsDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let vc = startVc h { defaults with UseEvents = true }

        for s in 0UL .. 15UL do
            do! headUntilDone h s h.Node.EmitHead

        do! vc.Stop()

        for epoch in 0UL .. 2UL do
            Expect.equal (attesterFetches h.Node epoch) 1 $"duties of epoch {epoch} fetched once"

        Expect.equal h.Node.Submissions.Count 16 "every duty of epochs 0 and 1"
    }

let private slowNodeOfThree () =
    task {
        let h = harness ()
        let slow = extraNode h
        let other = extraNode h
        addValidators [ h.Node; other; slow ] 8
        let gate = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        slow.Delay <- fun path -> if path.EndsWith "attestation_data" then gate.Task else Task.CompletedTask

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ other; slow ]
                    Threshold = 2
                }

        for s in 0UL .. 7UL do
            do! h.RunSlots(s, s)
            Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart(s + 1UL)) $"slot {s} done inside the slot"
        // The slow node answers now; nothing may be signed again.
        gate.TrySetResult() |> ignore
        do! Task.Delay 300
        do! h.RunSlots(8UL, 9UL)
        do! vc.Stop()
        let epoch0 = attested h.Node |> List.filter (fun (_, s) -> s < 8UL)

        Expect.equal
            (List.sort epoch0)
            [ for i in 0UL .. 7UL -> i, i ]
            $"every duty of epoch 0 attested once; log:\n{vc.Log}"

        for n in [ h.Node; other; slow ] do
            Expect.equal (attested n |> List.distinct).Length n.Submissions.Count "no attestation twice"
    }

let private healthy =
    {
        IsSyncing = false
        IsOptimistic = false
        ElOffline = false
    }

/// Two nodes, the first in the config optimistic: duties and attestation data come from the second.
let private optimisticNotBest () =
    task {
        let h = harness ()
        let good = extraNode h
        addValidators [ h.Node; good ] 8
        h.Node.Sync <- { healthy with IsOptimistic = true }
        let vc = startVc h { defaults with Extra = [ good ] }
        do! h.RunSlots(0UL, 7UL)
        do! vc.Stop()

        Expect.equal
            (h.Node.RequestCount "POST /eth/v1/validator/duties/attester")
            0
            $"no duties from the optimistic node; log:\n{vc.Log}"

        Expect.equal (h.Node.RequestCount "GET /eth/v1/validator/attestation_data") 0 "no attestation data from it"

        Expect.isGreaterThan
            (good.RequestCount "POST /eth/v1/validator/duties/attester")
            0
            "duties from the healthy node"

        Expect.equal good.Submissions.Count 8 "every duty attested"
        Expect.equal h.Node.Submissions.Count 8 "and sent to both nodes"
    }

/// Ranking: synced, then EL offline, then optimistic, then syncing; a failing node passes the call on.
let private rankingByHealth () =
    task {
        let h = harness ()
        let n = [ for _ in 0..3 -> extraNode h ]
        addValidators n 2
        n[0].Sync <- { healthy with IsSyncing = true }
        n[1].Sync <- { healthy with IsOptimistic = true }
        n[2].Sync <- { healthy with ElOffline = true }
        n[3].Sync <- healthy

        let clients =
            n
            |> List.mapi (fun i x ->
                BeaconClient(new Net.Http.HttpClient(x, false), Uri $"http://bn{i}.test", TimeSpan.FromSeconds 5.0))

        let nodes = BeaconNodes(clients, 1, h.Time, Log.none)

        for c in clients do
            nodes.MarkReady c

        do! nodes.RefreshHealth CancellationToken.None

        let served () =
            task {
                let before = n |> List.map (fun x -> x.RequestCount "POST /eth/v1/validator/duties/attester")
                let! r = nodes.Call(fun b -> b.AttesterDuties(0UL, [ 0UL; 1UL ], CancellationToken.None))
                Expect.isOk r "duties"
                let after = n |> List.map (fun x -> x.RequestCount "POST /eth/v1/validator/duties/attester")
                // The node that answered: asked, and not failing.
                return
                    List.zip3 before after n
                    |> List.findIndex (fun (b, a, x) -> a > b && not (x.Fail "/eth/v1/validator/duties/attester/0"))
            }

        let! first = served ()
        Expect.equal first 3 "the synced node first"
        n[3].Fail <- fun p -> p.Contains "/duties/"
        let! second = served ()
        Expect.equal second 2 "then the node whose EL is offline"
        n[2].Fail <- fun p -> p.Contains "/duties/"
        let! third = served ()
        Expect.equal third 1 "then the optimistic node"
        n[1].Fail <- fun p -> p.Contains "/duties/"
        let! last = served ()
        Expect.equal last 0 "the syncing node last"
        // A node that recovers moves back up at the next refresh.
        for x in n do
            x.Fail <- fun _ -> false

        n[0].Sync <- healthy
        n[3].Sync <- { healthy with IsSyncing = true }
        do! nodes.RefreshHealth CancellationToken.None
        let! again = served ()
        Expect.equal again 0 "the node that finished syncing serves again"
    }

/// With one node, the VC uses it whatever it reports (the node itself refuses to serve data it
/// cannot vouch for).
let private onlyOptimistic () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Sync <- { healthy with IsOptimistic = true }
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 7UL)
        do! vc.Stop()
        Expect.equal h.Node.Submissions.Count 8 "attests through the only node"

        Expect.isTrue
            (vc.Lines
             |> Seq.exists (fun l ->
                 l.StartsWith "WARN" && l.Contains "attester duties come from an optimistic beacon node"))
            $"the optimistic duties are logged; log:\n{vc.Log}"
    }

/// Two nodes, both synced at the health check, but the first answers duties with
/// execution_optimistic (it turned optimistic since): the duties come from the second node.
/// Before, the first node's optimistic answer was used as is.
let private optimisticDutiesAskTheNext () =
    task {
        let h = harness ()
        let good = extraNode h
        addValidators [ h.Node; good ] 8
        h.Node.OptimisticDuties <- true
        let vc = startVc h { defaults with Extra = [ good ] }
        do! h.RunSlots(0UL, 7UL)
        do! vc.Stop()

        Expect.isGreaterThan
            (good.RequestCount "POST /eth/v1/validator/duties/attester")
            0
            $"attester duties asked of the second node; log:\n{vc.Log}"

        Expect.isGreaterThan (good.RequestCount "GET /eth/v1/validator/duties/proposer") 0 "proposer duties too"

        Expect.isFalse
            (vc.Lines |> Seq.exists (fun l -> l.Contains "from an optimistic beacon node"))
            "no warning: a verified answer came"

        Expect.equal h.Node.Submissions.Count 8 "every duty attested"
    }

/// The first node answers duties with execution_optimistic and the second hangs on
/// duties. The optimistic duties are used after BeaconNodes.PreferWait per duty kind, well inside
/// the 5 s request timeout. Before, each duty kind waited the full request timeout for the hung
/// node first.
let private optimisticDutiesHungNext () =
    task {
        let h = harness ()
        let hung = extraNode h
        addValidators [ h.Node; hung ] 8
        h.Node.OptimisticDuties <- true
        let never = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        hung.Delay <- fun path -> if path.Contains "/duties/" then never.Task else Task.CompletedTask
        let vc = startVc h { defaults with Extra = [ hung ] }

        let warned (what: string) =
            vc.Lines
            |> Seq.exists (fun l ->
                l.StartsWith "WARN" && l.Contains $"epoch 0: {what} duties come from an optimistic beacon node")
        // The fake clock moves 50 ms per 10 ms of real time, up to the end of slot 0; real time
        // stops at 3 s, below the request timeout that would end the hung calls.
        let stopAt = h.Clock.SlotStart 1UL - TimeSpan.FromMilliseconds 100.0
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (warned "attester" && warned "proposer") && sw.Elapsed < TimeSpan.FromSeconds 3.0 do
            if h.Time.GetUtcNow() + TimeSpan.FromMilliseconds 50.0 < stopAt then
                h.Time.Advance(TimeSpan.FromMilliseconds 50.0)

            do! Task.Delay 10

        let attester, proposer = warned "attester", warned "proposer"
        never.TrySetResult() |> ignore
        do! vc.Stop()
        Expect.isTrue attester $"epoch 0 attester duties used within 3 s; log:\n{vc.Log}"
        Expect.isTrue proposer "epoch 0 proposer duties too"
        Expect.isGreaterThan (hung.RequestCount "POST /eth/v1/validator/duties/attester") 0 "the second node was asked"
    }

/// A clock whose wall time can step back (as an NTP step does) while timers keep running.
type SteppableTime(inner: Microsoft.Extensions.Time.Testing.FakeTimeProvider) =
    inherit TimeProvider()
    member val Offset = TimeSpan.Zero with get, set
    override this.GetUtcNow() = inner.GetUtcNow() + this.Offset
    override _.CreateTimer(callback, state, dueTime, period) = inner.CreateTimer(callback, state, dueTime, period)
    override _.GetTimestamp() = inner.GetTimestamp()
    override _.TimestampFrequency = inner.TimestampFrequency
    override _.LocalTimeZone = inner.LocalTimeZone

let private ptcVotes (n: FakeBeaconNode) =
    postsOf n "payload_attestations"
    |> List.collect jsonItems
    |> List.map (fun v ->
        UInt64.Parse(v.GetProperty("validator_index").GetString()),
        UInt64.Parse(v.GetProperty("data").GetProperty("slot").GetString()))

let private gloasWithPtc () =
    let h = gloasHarness 1UL
    addValidators [ h.Node ] 8

    for s in 8UL .. 80UL do
        h.Node.PtcSlots[s] <- [| s % 8UL |]

    h

/// Timers that fire 5 ms before their due time, as the system clock and the timer clock can.
type EarlyTimers(inner: Microsoft.Extensions.Time.Testing.FakeTimeProvider) =
    inherit TimeProvider()
    override _.GetUtcNow() = inner.GetUtcNow()

    override _.CreateTimer(callback, state, dueTime, period) =
        let early =
            if dueTime > TimeSpan.FromMilliseconds 5.0 then dueTime - TimeSpan.FromMilliseconds 5.0 else dueTime

        inner.CreateTimer(callback, state, early, period)

    override _.GetTimestamp() = inner.GetTimestamp()
    override _.TimestampFrequency = inner.TimestampFrequency

/// A VC started before genesis, with timers that fire early: it neither crashes at genesis (the
/// published binary died with "ValueOption.Value" there) nor attests before the due time.
let private startBeforeGenesis () =
    task {
        let h0 = harness ()
        addValidators [ h0.Node ] 8
        // The clock 3 s before genesis.
        let time =
            Microsoft.Extensions.Time.Testing.FakeTimeProvider(h0.Clock.GenesisTime - TimeSpan.FromSeconds 3.0)

        let early = EarlyTimers(time)

        let h =
            { h0 with
                Time = time
                Clock = SlotClock(h0.Clock.GenesisTime, h0.Spec.SlotDuration, h0.Spec.SlotsPerEpoch, early)
            }

        let vc = startVc h defaults
        // Exactly to the early firing time of the genesis wait, then on through the epoch.
        time.Advance(TimeSpan.FromSeconds 3.0 - TimeSpan.FromMilliseconds 5.0)
        do! Task.Delay 100
        Expect.isFalse vc.Run.IsCompleted $"the scheduler still runs at genesis - 5 ms; log:\n{vc.Log}"

        for s in 0UL .. 7UL do
            let due = h.Clock.SlotStart s + h.Spec.AttestationDue s
            time.Advance(due - TimeSpan.FromMilliseconds 5.0 - time.GetUtcNow())
            do! Task.Delay 50

            Expect.isFalse
                (h.Node.Submissions |> Seq.exists (fun x -> x.Slot = s))
                $"slot {s}: nothing before the due time"

            time.Advance(TimeSpan.FromMilliseconds 6.0)
            do! h.Waiter.Wait s

        do! vc.Stop()
        Expect.equal h.Node.Submissions.Count 8 "every duty of epoch 0, slot 0 included"
    }

/// The wall clock steps back 10 slots at slot 40: the scheduler signs nothing it signed already,
/// casts no second PTC vote for a slot, and goes on once the clock is past slot 40 again.
let private clockStepsBackInRun () =
    task {
        let h0 = gloasWithPtc ()
        let stepper = SteppableTime(h0.Time)

        let h =
            { h0 with
                Clock = SlotClock(h0.Clock.GenesisTime, h0.Spec.SlotDuration, h0.Spec.SlotsPerEpoch, stepper)
            }

        let vc = startVc h defaults
        // Moves the stepped clock (the VC's) to t.
        let advanceApparent (t: DateTimeOffset) =
            let now = stepper.GetUtcNow()

            if t > now then
                h.Time.Advance(t - now)

        /// The attestation, then the PTC vote of slot s.
        let runSlot (s: Slot) (waitDone: bool) =
            task {
                advanceApparent (h.Clock.SlotStart s + h.Spec.AttestationDue s + TimeSpan.FromMilliseconds 1.0)
                if waitDone then do! h.Waiter.Wait s else do! Task.Delay 20
                advanceApparent (h.Clock.SlotStart s + h.Spec.Bps 7100UL)

                if waitDone && s >= 8UL then
                    do!
                        waitUntil vc $"the PTC vote of slot {s}" (fun () ->
                            ptcVotes h.Node |> List.exists (fun (_, x) -> x = s))
            }

        for s in 0UL .. 40UL do
            do! runSlot s true

        let before = h.Node.Submissions.Count
        let votesBefore = (ptcVotes h.Node).Length
        stepper.Offset <- TimeSpan.FromSeconds(-10.0 * h.Spec.SlotDuration.TotalSeconds)
        // Slots 31 to 40 again in the stepped clock's time: nothing to do; then 41 to 45.
        for s in 31UL .. 45UL do
            do! runSlot s (s > 40UL)

        do! vc.Stop()

        Expect.equal
            (ptcVotes h.Node |> List.filter (fun (_, s) -> s <= 40UL)).Length
            votesBefore
            "no PTC vote for slots up to 40 after the step"

        let all = attested h.Node
        Expect.equal (List.distinct all).Length all.Length $"no (validator, slot) attested twice; log:\n{vc.Log}"
        Expect.isGreaterThan h.Node.Submissions.Count before "attests again after slot 40"
        Expect.isFalse (all |> List.exists (fun (_, s) -> s > 40UL && s < 41UL)) "no slot in between"
        let votes = ptcVotes h.Node
        Expect.equal (List.distinct votes).Length votes.Length "no second PTC vote for a slot"
        // Each epoch's target is signed once per validator.
        let targets =
            h.Node.Submissions |> Seq.map (fun x -> x.AttesterIndex, x.Data.Target.Epoch) |> List.ofSeq

        Expect.equal (List.distinct targets).Length targets.Length "one vote per validator and target"
    }

/// A restart with the clock 10 slots back and different data from the node: the slashing DB
/// refuses the votes again, the slot marks skip the PTC votes again.
let private clockBackAcrossRestart () =
    task {
        let h = gloasWithPtc ()
        let dir = tempDir ()

        let o =
            { defaults with
                DbPath = Some(IO.Path.Combine(dir, "slashing.db"))
                SlotMarksPath = Some(IO.Path.Combine(dir, "slot-marks.db"))
            }

        let vc = startVc h o

        for s in 0UL .. 40UL do
            do! h.RunSlots(s, s)
            advanceTo h (h.Clock.SlotStart s + h.Spec.Bps 7100UL)

            if s >= 8UL then
                do!
                    waitUntil vc $"the PTC vote of slot {s}" (fun () ->
                        ptcVotes h.Node |> List.exists (fun (_, x) -> x = s))

        do! vc.Stop()
        Expect.equal (ptcVotes h.Node).Length 33 "a PTC vote in each slot from 8 to 40"
        let attestedBefore = h.Node.Submissions.Count
        let votesBefore = (ptcVotes h.Node).Length
        // The same data dir, the clock at slot 30 and another head and payload status.
        h.Node.OverrideData(
            Some(fun slot ->
                { h.Node.DefaultData slot with
                    BeaconBlockRoot = root 999
                })
        )

        h.Node.PayloadPresent <- false

        let time2 =
            Microsoft.Extensions.Time.Testing.FakeTimeProvider(h.Clock.SlotStart 30UL + TimeSpan.FromSeconds 0.5)

        let h2 =
            { h with
                Time = time2
                Clock = SlotClock(h.Clock.GenesisTime, h.Spec.SlotDuration, h.Spec.SlotsPerEpoch, time2)
                Waiter = SlotWaiter()
            }

        let vc2 = startVc h2 o

        for s in 30UL .. 40UL do
            do! h2.RunSlots(s, s)
            advanceTo h2 (h2.Clock.SlotStart s + h2.Spec.Bps 7100UL)
            do! Task.Delay 50

        do! vc2.Stop()

        Expect.isTrue
            (vc2.Lines |> Seq.exists (fun l -> l.Contains "PTC vote" && l.Contains "not signed"))
            "PTC votes skipped by the slot marks"

        Expect.equal h.Node.Submissions.Count attestedBefore $"no attestation for slots 30 to 40 again; log:\n{vc2.Log}"
        Expect.equal (ptcVotes h.Node).Length votesBefore "no PTC vote for slots 30 to 40 again"
        Expect.isTrue (vc2.Lines |> Seq.exists (fun l -> l.Contains "refused")) "refusals logged"
    }

// ---- B7: best block and aggregate ----

/// Four nodes: among the blocks in by the soft timeout (a higher one that comes later does not
/// count), the highest value wins: node 3's 6000, though node 3 ranks last. The aggregate with
/// the most bits is signed; nodes 1 and 3 tie at 6.
let private bestBlockAndAggregate () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let n2 = extraNode h
        let n3 = extraNode h
        addValidators [ h.Node; n1; n2; n3 ] 8

        for n in [ h.Node; n1; n2; n3 ] do
            n.Proposals[4UL] <- 3UL
            n.CommitteeLength <- 8UL

        h.Node.BlockValue <- 1000UL
        h.Node.StateRootByte <- 0x10uy
        n1.BlockValue <- 5000UL
        n1.StateRootByte <- 0x11uy
        n2.BlockValue <- 9000UL
        n2.StateRootByte <- 0x12uy
        n3.BlockValue <- 6000UL
        n3.StateRootByte <- 0x13uy
        // Node 2's block comes after the soft timeout (half the attestation due time).
        let late = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        n2.Delay <- fun path -> if path.StartsWith "/eth/v3/validator/blocks" then late.Task else Task.CompletedTask
        h.Node.AggregateBits <- 2
        n1.AggregateBits <- 6
        n2.AggregateBits <- 4
        n3.AggregateBits <- 6
        let vc = startVc h { defaults with Extra = [ n1; n2; n3 ] }
        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the block of slot 4" (fun () -> h.Node.Published.Count > 0)
        late.TrySetResult() |> ignore
        advanceTo h (h.Clock.SlotStart 4UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

        do!
            waitUntil vc "the aggregate of slot 4" (fun () ->
                not (List.isEmpty (postsOf h.Node "aggregate_and_proofs")))

        do! vc.Stop()
        let _, _, bytes = Seq.head h.Node.Published

        match Ssz.deserialize (Schemas.signedBlockContents h.Node.Preset) bytes with
        | Error e -> failtestf "block: %s" e
        | Ok v ->
            let block = Codec.fields (Codec.fields (Codec.fields v).[0]).[0]

            Expect.equal
                (Codec.asBytes block[3])
                (Array.create 32 0x13uy)
                "node 3's block (6000), not node 1's (5000) nor node 2's late one (9000)"

        let aggs = postsOf h.Node "aggregate_and_proofs" |> List.collect jsonItems

        for a in aggs do
            let v = SszJson.read (Schemas.signedAggregateAndProof h.Node.Preset) a
            let aggregate = Codec.fields (Codec.fields (Codec.fields v).[0]).[1]
            let bits = Codec.asBits aggregate[0] |> Array.filter id |> Array.length
            Expect.equal bits 6 "the aggregate with the most bits (nodes 1 and 3)"
    }

/// Three nodes: node 2 reports a block value far above the others'. The beacon nodes are trusted,
/// so node 2's block is signed, though node 2 ranks last.
let private highestBlockValueWins () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let n2 = extraNode h
        addValidators [ h.Node; n1; n2 ] 8

        for n in [ h.Node; n1; n2 ] do
            n.Proposals[4UL] <- 3UL

        h.Node.BlockValue <- 1000UL
        h.Node.StateRootByte <- 0x10uy
        n1.BlockValue <- 1200UL
        n1.StateRootByte <- 0x11uy
        n2.BlockValue <- UInt64.MaxValue
        n2.StateRootByte <- 0x12uy
        let vc = startVc h { defaults with Extra = [ n1; n2 ] }
        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the block of slot 4" (fun () -> h.Node.Published.Count > 0)
        do! vc.Stop()
        let _, _, bytes = Seq.head h.Node.Published

        match Ssz.deserialize (Schemas.signedBlockContents h.Node.Preset) bytes with
        | Error e -> failtestf "block: %s" e
        | Ok v ->
            let block = Codec.fields (Codec.fields (Codec.fields v).[0]).[0]

            Expect.equal
                (Codec.asBytes block[3])
                (Array.create 32 0x12uy)
                $"node 2's block, with the highest value; log:\n{vc.Log}"
    }

/// Three nodes: node 2 serves an aggregate with every bit set, node 1 one of other attestation
/// data with more bits than node 0's. Node 2's full aggregate is signed; node 1's is refused.
let private fullAggregateWinsOtherDataRefused () =
    task {
        let h = harness ()
        let n1 = extraNode h
        let n2 = extraNode h
        addValidators [ h.Node; n1; n2 ] 8

        for n in [ h.Node; n1; n2 ] do
            n.CommitteeLength <- 8UL

        h.Node.AggregateBits <- 2
        n1.AggregateBits <- 6

        n1.AggregateDataOf <-
            fun d ->
                { d with
                    BeaconBlockRoot = Root.Of(Array.create 32 0xeeuy)
                }

        n2.AggregateBits <- 8
        // Node 2's full answer comes last, so node 1's answer is in and checked before it.
        n2.Delay <- fun path -> if path.Contains "aggregate_attestation" then Task.Delay 200 else Task.CompletedTask

        let vc = startVc h { defaults with Extra = [ n1; n2 ] }
        do! h.RunSlots(0UL, 4UL)
        advanceTo h (h.Clock.SlotStart 4UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

        do!
            waitUntil vc "the aggregate of slot 4" (fun () ->
                not (List.isEmpty (postsOf h.Node "aggregate_and_proofs")))

        do! vc.Stop()
        let aggs = postsOf h.Node "aggregate_and_proofs" |> List.collect jsonItems
        Expect.isNonEmpty aggs "aggregates"

        for a in aggs do
            let v = SszJson.read (Schemas.signedAggregateAndProof h.Node.Preset) a
            let aggregate = Codec.fields (Codec.fields (Codec.fields v).[0]).[1]
            let bits = Codec.asBits aggregate[0] |> Array.filter id |> Array.length

            Expect.equal bits 8 $"node 2's full aggregate; log:\n{vc.Log}"

        Expect.isTrue
            (vc.Lines
             |> Seq.exists (fun l -> l.Contains "http://bn1.test" && l.Contains "other attestation data"))
            "node 1's aggregate of other data logged"
    }

/// Charon v1.11.2's beacon mock answers every aggregate with committee 0's bit and an empty
/// aggregation_bits list. An Electra aggregate for committee c carries c's bit alone and one bit
/// per member of c, so the VC signs neither committee's answer: committee 1's has the wrong
/// committee bit, committee 0's has no bits.
let private charonMockAggregateRefused () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.CommitteeLength <- 8UL
        h.Node.AggregateCommitteeBit <- ValueSome 0UL
        h.Node.AggregateLength <- ValueSome 0
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 4UL)
        advanceTo h (h.Clock.SlotStart 4UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)
        let has (s: string) = vc.Lines |> Seq.exists (fun l -> l.Contains s)

        do!
            waitUntil vc "both committees' answers refused" (fun () ->
                has "committee bits are not committee 1 alone" && has "an aggregate of 0 bits for committee 0 of 8")

        do! vc.Stop()

        Expect.isEmpty
            (postsOf h.Node "aggregate_and_proofs")
            $"no aggregate signed; log:
{vc.Log}"
    }

/// The same answer in the shape of the asked committee (its bit alone, a list of its length) with
/// no bit set is signed, as the Charon integration test's proxy serves it.
let private emptyAggregateOfAskedCommittee () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.CommitteeLength <- 8UL
        h.Node.AggregateBits <- 0
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 4UL)
        advanceTo h (h.Clock.SlotStart 4UL + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

        do!
            waitUntil vc "the aggregate of slot 4" (fun () ->
                not (List.isEmpty (postsOf h.Node "aggregate_and_proofs")))

        do! vc.Stop()
    }

/// Three nodes: the highest claimed value belongs to a block that fails the checks (another fee
/// recipient, or blinded for a local build), so it does not win; the best block that passes is
/// signed. Before the checks ran on every answer, the bad block won and the proposal failed.
let private bestValidBlockWins () =
    task {
        for what, spoil in
            [
                "another fee recipient",
                (fun (n: FakeBeaconNode) ->
                    n.PayloadFeeRecipient <- Some(hex "0x00000000000000000000000000000000000000bb"))
                "a blinded block for a local build", (fun (n: FakeBeaconNode) -> n.Blinded <- true)
            ] do
            let h = harness ()
            let n1 = extraNode h
            let n2 = extraNode h
            addValidators [ h.Node; n1; n2 ] 8

            for n in [ h.Node; n1; n2 ] do
                n.Proposals[4UL] <- 3UL

            h.Node.BlockValue <- 1000UL
            h.Node.StateRootByte <- 0x10uy
            n1.BlockValue <- 5000UL
            n1.StateRootByte <- 0x11uy
            n2.BlockValue <- 9000UL
            n2.StateRootByte <- 0x12uy
            spoil n2
            let vc = startVc h { defaults with Extra = [ n1; n2 ] }
            do! h.RunSlots(0UL, 4UL)
            do! waitUntil vc $"{what}: the block of slot 4" (fun () -> h.Node.Published.Count > 0)
            do! vc.Stop()
            let _, _, bytes = Seq.head h.Node.Published

            match Ssz.deserialize (Schemas.signedBlockContents h.Node.Preset) bytes with
            | Error e -> failtestf "block: %s" e
            | Ok v ->
                let block = Codec.fields (Codec.fields (Codec.fields v).[0]).[0]

                Expect.equal
                    (Codec.asBytes block[3])
                    (Array.create 32 0x11uy)
                    $"{what}: node 1's block (5000), not node 2's (9000); log:\n{vc.Log}"

            Expect.isTrue
                (vc.Lines |> Seq.exists (fun l -> l.Contains "http://bn2.test" && l.Contains "not used"))
                $"{what}: node 2's answer logged"
    }

// ---- Data that does not fit the duty ----

/// Moves the clock to `slot` without running the slots before (the scheduler skips them).
let private jumpTo (h: Harness) (slot: Slot) = advanceTo h (h.Clock.SlotStart slot + TimeSpan.FromMilliseconds 100.0)

let private refusedIn (vc: Vc) = vc.Scheduler.Reports |> Seq.sumBy (fun r -> r.Refused)

/// Attestation data whose target is not the slot's epoch, or whose source is not before its
/// target, is not signed and counts as refused. The keys start fresh in epoch 2, so the slashing
/// DB alone would allow these votes.
let private badAttestationData () =
    task {
        for what, tweak in
            [
                "a target epoch that is not the slot's epoch",
                (fun (d: AttestationData) ->
                    { d with
                        Target =
                            { d.Target with
                                Epoch = d.Target.Epoch - 1UL
                            }
                    })
                "a source equal to the target",
                (fun (d: AttestationData) ->
                    { d with
                        Source = { d.Source with Epoch = d.Target.Epoch }
                    })
            ] do
            let h = harness ()
            addValidators [ h.Node ] 8
            h.Node.OverrideData(Some(fun slot -> tweak (h.Node.DefaultData slot)))
            // The VC starts in epoch 2.
            jumpTo h 16UL
            let vc = startVc h defaults
            do! h.RunSlots(16UL, 23UL)
            do! vc.Stop()
            Expect.equal h.Node.Submissions.Count 0 $"{what}: nothing signed; log:\n{vc.Log}"
            Expect.equal (refusedIn vc) 8 $"{what}: eight refusals counted"

            Expect.isNone
                ((vc.Db.Marks(pubkeyOf 0)) |> ValueOption.bind (fun m -> m.Attestation) |> ValueOption.toOption)
                $"{what}: no mark recorded"
        // Data for another slot of the same epoch: the node set drops it, so the duty fails.
        let h = harness ()
        addValidators [ h.Node ] 8

        h.Node.OverrideData(
            Some(fun slot ->
                { h.Node.DefaultData slot with
                    Slot = slot + 1UL
                })
        )

        jumpTo h 16UL
        let vc = startVc h defaults
        do! h.RunSlots(16UL, 22UL)
        do! vc.Stop()
        Expect.equal h.Node.Submissions.Count 0 $"another slot: nothing signed; log:\n{vc.Log}"
        Expect.equal (vc.Scheduler.Reports |> Seq.sumBy (fun r -> r.Failed)) 7 "another slot: seven failed duties"
    }

/// A pre-Gloas block for another proposer, paying another fee recipient, or blinded, is not signed.
let private badBlocks () =
    task {
        for what, setup, reason in
            [
                "another proposer index",
                (fun (n: FakeBeaconNode) -> n.BlockProposer <- Some(fun _ -> 6UL)),
                "proposer 6"
                "another fee recipient",
                (fun (n: FakeBeaconNode) ->
                    n.PayloadFeeRecipient <- Some(hex "0x00000000000000000000000000000000000000bb")),
                "fee recipient"
                "a blinded block", (fun (n: FakeBeaconNode) -> n.Blinded <- true), "blinded"
            ] do
            let h = harness ()
            addValidators [ h.Node ] 8
            h.Node.Proposals[4UL] <- 3UL
            setup h.Node
            let vc = startVc h defaults

            let failedAt4 () =
                vc.Scheduler.Events
                |> Seq.exists (fun e ->
                    match e with
                    | ProposalFailed(4UL, _) -> true
                    | _ -> false)

            do! h.RunSlots(0UL, 4UL)

            do!
                waitUntil vc $"{what}: the proposal of slot 4 to end" (fun () ->
                    failedAt4 () || h.Node.Published.Count > 0)

            do! vc.Stop()

            let failed =
                vc.Scheduler.Events
                |> Seq.choose (fun e ->
                    match e with
                    | ProposalFailed(s, why) -> Some(s, why)
                    | _ -> None)
                |> List.ofSeq

            Expect.equal h.Node.Published.Count 0 $"{what}: nothing published; log:\n{vc.Log}"

            Expect.exists
                failed
                (fun (s, why) -> s = 4UL && why.Contains reason)
                $"{what}: counted as a failed proposal; log:\n{vc.Log}"

            Expect.isNone
                ((vc.Db.Marks(pubkeyOf 3)) |> ValueOption.bind (fun m -> m.Block) |> ValueOption.toOption)
                $"{what}: no block mark"
        // The right block from the same node is signed.
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Proposals[4UL] <- 3UL
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the good block" (fun () -> h.Node.Published.Count = 1)
        do! vc.Stop()
    }

// ---- B8: clock skew ----

/// The node's clock differs from the VC's by `skew` (positive: the VC is ahead).
let private skewed (skew: TimeSpan) =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.NodeNow <- Some(fun () -> h.Time.GetUtcNow() - skew)
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 15UL)
        do! vc.Stop()
        return h, vc
    }

let private clockSkewInsideTolerance () =
    task {
        for skew in [ TimeSpan.FromSeconds 1.5; TimeSpan.FromSeconds -1.5 ] do
            let! h, vc = skewed skew
            Expect.equal h.Node.Submissions.Count 16 $"skew {skew.TotalSeconds} s: every duty attested; log:\n{vc.Log}"
            // The VC asks at its due time (2 s into the slot); the node is then 0.5 s or 3.5 s into it.
            for s in h.Node.Submissions do
                Expect.equal s.Data.Slot s.Slot "data for the slot"
    }

let private clockSkewBeyondTheDueTime () =
    task {
        // 2.5 s ahead: at the VC's due time (2 s) the node is still in the slot before.
        let! h, vc = skewed (TimeSpan.FromSeconds 2.5)
        Expect.equal h.Node.Submissions.Count 0 $"nothing signed for a slot the node has not reached; log:\n{vc.Log}"
        Expect.equal (vc.Scheduler.Reports |> Seq.sumBy (fun r -> r.Signed)) 0 "no signature at all"
        Expect.equal (vc.Scheduler.Reports |> Seq.sumBy (fun r -> r.Failed)) 16 "each duty a counted failure"
    }

/// A node that refuses duties past its next epoch (Nimbus: 400 "Invalid epoch value"). The VC
/// fetches the duties of a slot during the slot before, so without a cap it would ask for epoch
/// e + 2 in the last slot of epoch e.
let private dutiesNeverPastNextEpoch () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.NodeNow <- Some(fun () -> h.Time.GetUtcNow())
        h.Node.StrictDutyEpochs <- true
        h.Node.SyncSeats[0UL] <- [| 0UL |]
        let vc = startVc h defaults
        let last = uint64 (4 * slotsPerEpoch - 1)
        do! h.RunSlots(0UL, last)
        do! vc.Stop()
        let refused = List.ofSeq h.Node.RefusedDuties

        Expect.isEmpty
            refused
            $"no duty request past the next epoch; log:
{vc.Log}"

        Expect.isFalse (vc.Log.Contains "Invalid epoch value") "no refused request in the log"

        for e in 0UL .. 4UL do
            Expect.equal (attesterFetches h.Node e) 1 $"epoch {e}: attester duties fetched once"

            Expect.isGreaterThanOrEqual
                (h.Node.RequestCount $"GET /eth/v1/validator/duties/proposer/{e}")
                1
                $"epoch {e}: proposer duties fetched"

            Expect.isGreaterThanOrEqual
                (h.Node.RequestCount $"POST /eth/v1/validator/duties/sync/{e}")
                1
                $"epoch {e}: sync duties fetched"

        Expect.equal (attesterFetches h.Node 5UL) 0 "epoch 5 waits for epoch 4"

        Expect.equal
            (List.sort (attested h.Node))
            (List.sort [ for s in 0UL .. last -> s % 8UL, s ])
            "every duty attested"
    }

// ---- B5: the event stream drops ----

let private eventStreamDrops () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let vc = startVc h { defaults with UseEvents = true }

        for s in 0UL .. 2UL do
            do! headUntilDone h s h.Node.EmitHead

        Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 2UL) "head events drive the attestations"
        let connects () = h.Node.RequestCount "GET /eth/v1/events"
        let before = connects ()
        h.Node.DropEvents()
        // While the stream is down, slots 3 to 5 attest at the due time.
        do! h.RunSlots(3UL, 5UL)
        do! waitUntil vc "a reconnect" (fun () -> connects () > before)
        // Back up: a head event triggers the attestation before the due time again.
        do! headUntilDone h 6UL h.Node.EmitHead
        Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 6UL) "attested on the head event after the reconnect"
        do! h.RunSlots(7UL, 7UL)
        do! vc.Stop()
        let all = attested h.Node
        Expect.equal (List.sort all) [ for i in 0UL .. 7UL -> i, i ] "each duty once, none missed"
    }

// ---- Review fixes ----

/// Two nodes, the second hangs on aggregates and sync contributions. Two committees and two
/// subcommittees in slot 1: every aggregate and contribution is still signed and published once
/// the soft cutoff passes, before the slot ends. Before the cutoff the first call waited for the
/// hung node until the slot ended, and the rest of the slot's calls came too late.
let private hungAggregateNode () =
    task {
        let h = harness ()
        let hung = extraNode h
        addValidators [ h.Node; hung ] 8

        for n in [ h.Node; hung ] do
            n.CommitteeLength <- 8UL
            // Validators 0 to 3 in slot 1 (committees 0 and 1), 4 to 7 in slot 2.
            n.DutySlotOverride <- fun v e -> ValueSome(e * 8UL + 1UL + v.Index / 4UL)
            // Validator 0 in subcommittees 0 and 1.
            n.SyncSeats[0UL] <- [| 0UL; 9UL |]

        let never = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

        hung.Delay <-
            fun path ->
                if path.EndsWith "aggregate_attestation" || path.EndsWith "sync_committee_contribution" then
                    never.Task
                else
                    Task.CompletedTask

        let vc = startVc h { defaults with Extra = [ hung ] }
        do! h.RunSlots(0UL, 1UL)
        let due = h.Clock.SlotStart 1UL + max (h.Spec.AggregateDueAt 1UL) (h.Spec.ContributionDueAt 1UL)
        advanceTo h (due + TimeSpan.FromMilliseconds 1.0)
        do! Task.Delay 200
        let ends = h.Clock.SlotStart 2UL
        advanceTo h (due + TimeSpan.FromTicks((ends - due).Ticks / 4L) + TimeSpan.FromMilliseconds 1.0)

        let slotOf (path: string list) (x: Text.Json.JsonElement) =
            let mutable e = x.GetProperty "message"

            for p in path do
                e <- e.GetProperty p

            e.GetProperty("slot").GetString()

        let aggs () =
            postsOf h.Node "aggregate_and_proofs"
            |> List.collect jsonItems
            |> List.filter (fun x -> slotOf [ "aggregate"; "data" ] x = "1")

        let contribs () =
            postsOf h.Node "contribution_and_proofs"
            |> List.collect jsonItems
            |> List.filter (fun x -> slotOf [ "contribution" ] x = "1")
        // Real time: 3 s, less than the 5 s request timeout that would end the hung calls.
        let sw = Diagnostics.Stopwatch.StartNew()

        while (aggs().Length < 4 || contribs().Length < 2) && sw.Elapsed < TimeSpan.FromSeconds 3.0 do
            do! Task.Delay 20

        Expect.equal (aggs ()).Length 4 $"every aggregate of slot 1 with one node hung; log:\n{vc.Log}"
        Expect.equal (contribs ()).Length 2 "every contribution of slot 1"
        Expect.isLessThan (h.Time.GetUtcNow()) ends "inside the slot"
        never.TrySetResult() |> ignore
        do! vc.Stop()
    }

/// A node answers a copy of one validator's duty and a second, conflicting duty for another:
/// the copy counts once, the validator with two duties gets none this epoch.
let private duplicateDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8

        h.Node.ExtraDuties <-
            fun v e ->
                match v.Index with
                | 1UL -> [ h.Node.DutySlot(v, e) ]
                | 2UL -> [ e * 8UL + 5UL ]
                | _ -> []

        let vc = startVc h defaults
        do! h.RunSlots(0UL, 15UL)
        do! vc.Stop()
        let all = attested h.Node

        Expect.equal
            (all |> List.filter (fun (v, _) -> v = 1UL) |> List.sort)
            [ 1UL, 1UL; 1UL, 9UL ]
            $"validator 1: one attestation per epoch; log:\n{vc.Log}"

        Expect.isFalse (all |> List.exists (fun (v, _) -> v = 2UL)) "validator 2 with two different duties: none signed"
        Expect.equal (List.distinct all).Length all.Length "no (validator, slot) twice"
        Expect.equal all.Length 14 "the other validators attest as usual"

        Expect.isTrue
            (vc.Lines |> Seq.exists (fun l -> l.Contains "validator 2 has 2 different duties"))
            "the conflict is logged"
    }

/// Starts a VC over 8 validators, runs slot 0, then halts key 7 (the VC holds it under index 7
/// but no longer asks for its duties) and turns `on` the node's foreign duties.
let private withHaltedKey7 (h: Harness) (on: bool ref) =
    task {
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 0UL)
        on.Value <- true
        vc.Registry.SetState(pubkeyOf 7, KeyState.Halted "test")
        return vc
    }

/// Attester duties the VC must not use: one for validator 7 that it holds but did not ask for,
/// one naming key 3 under index 5 (at validator 5's slot), and one for validator 6 with a slot
/// in the next epoch. Each would clash with a real duty or be counted; validators 0 to 6 attest
/// in epoch 1 at their own slots and the two foreign duties are logged.
let private foreignAttesterDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let on = ref false

        h.Node.RawAttesterDuties <-
            fun e ->
                if on.Value then
                    [
                        pubkeyOf 7, 7UL, e * 8UL + 2UL
                        pubkeyOf 3, 5UL, e * 8UL + 5UL
                        pubkeyOf 6, 6UL, (e + 1UL) * 8UL + 6UL
                    ]
                else
                    []

        let! vc = withHaltedKey7 h on
        do! h.RunSlots(1UL, 15UL)
        do! vc.Stop()
        let epoch1 = attested h.Node |> List.filter (fun (_, s) -> s >= 8UL) |> List.sort

        Expect.equal
            epoch1
            [ for i in 0UL .. 6UL -> i, 8UL + i ]
            $"epoch 1: validators 0 to 6, each at its own slot; log:\n{vc.Log}"

        Expect.isTrue
            (vc.Lines
             |> Seq.exists (fun l -> l.Contains "2 attester duties for validators not asked for, or under another key"))
            "the duty not asked for and the one under another key are left out and logged"

        Expect.isFalse
            (vc.Lines |> Seq.exists (fun l -> l.Contains "different duties"))
            "the next epoch's duty makes no conflict"
    }

/// Proposer duties for epoch 1: a copy of validator 1's duty at slot 9 counts once, slot 11 with
/// two proposers is dropped, key 5 under index 6 at slot 13 and a slot of epoch 2 are left out.
let private foreignProposerDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Proposals[9UL] <- 1UL
        h.Node.Proposals[11UL] <- 3UL

        h.Node.RawProposerDuties <-
            fun e ->
                if e = 1UL then
                    [
                        pubkeyOf 1, 1UL, 9UL
                        pubkeyOf 4, 4UL, 11UL
                        pubkeyOf 5, 6UL, 13UL
                        pubkeyOf 2, 2UL, 20UL
                    ]
                else
                    []

        let vc = startVc h defaults
        do! h.RunSlots(0UL, 9UL)
        // The fake clock waits for the block of slot 9 before it moves on.
        do! waitUntil vc "the block of slot 9" (fun () -> h.Node.Published.Count >= 1)
        do! h.RunSlots(10UL, 15UL)
        do! vc.Stop()
        let planned = vc.Lines |> Seq.filter (fun l -> l.Contains "epoch 1: proposals at slots") |> List.ofSeq
        Expect.isNonEmpty planned $"epoch 1 proposals logged; log:\n{vc.Log}"

        for l in planned do
            Expect.isTrue (l.EndsWith "proposals at slots 9") $"only slot 9 is planned: {l}"

        Expect.equal h.Node.Published.Count 1 "one block, at slot 9"
        Expect.equal (h.Node.RequestCount "GET /eth/v3/validator/blocks/9") 1 "slot 9 asked once"

        Expect.equal
            (h.Node.RequestCount "GET /eth/v3/validator/blocks/11")
            0
            "slot 11 with two proposers: no block asked"

        Expect.equal (h.Node.RequestCount "GET /eth/v3/validator/blocks/13") 0 "key 5 under index 6: no block asked"

        Expect.isTrue
            (vc.Lines |> Seq.exists (fun l -> l.Contains "slot 11 has 2 different duties"))
            "the two proposers are logged"
    }

/// Sync duties: a copy of validator 0's duty counts once, validator 1 with two different seat
/// lists gets none, validator 7 (held, not asked) and key 3 under index 5 are left out.
let private foreignSyncDuties () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.SyncSeats[0UL] <- [| 0UL |]
        h.Node.SyncSeats[1UL] <- [| 1UL |]
        let on = ref false

        h.Node.RawSyncDuties <-
            fun _ ->
                if on.Value then
                    [
                        pubkeyOf 0, 0UL, [| 0UL |]
                        pubkeyOf 1, 1UL, [| 2UL |]
                        pubkeyOf 7, 7UL, [| 7UL |]
                        pubkeyOf 3, 5UL, [| 5UL |]
                    ]
                else
                    []

        let! vc = withHaltedKey7 h on
        do! h.RunSlots(1UL, 15UL)

        let sent () =
            postsOf h.Node "pool/sync_committees"
            |> List.collect jsonItems
            |> List.map (fun m ->
                UInt64.Parse(m.GetProperty("slot").GetString()), m.GetProperty("validator_index").GetString())
            |> List.filter (fun (s, _) -> s >= 9UL)

        do! waitUntil vc "the sync message of slot 15" (fun () -> sent () |> List.exists (fun (s, _) -> s = 15UL))
        do! Task.Delay 200
        do! vc.Stop()

        Expect.equal
            (sent () |> List.sort)
            [ for s in 9UL .. 15UL -> s, "0" ]
            $"one message a slot, from validator 0 only; log:\n{vc.Log}"

        Expect.isTrue
            (vc.Lines
             |> Seq.exists (fun l ->
                 l.Contains "2 sync committee duties for validators not asked for, or under another key"))
            "the duty not asked for and the one under another key are logged"

        Expect.isTrue
            (vc.Lines |> Seq.exists (fun l -> l.Contains "validator 1 has 2 different duties"))
            "the conflict is logged"
    }

/// The epoch start work (here a module's epoch hook) hangs: slot 8, the first of epoch 1, still
/// attests at its due time with the duties fetched an epoch ahead.
let private epochWorkHangs () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let gate = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

        let vc =
            startVc
                h
                { defaults with
                    OnEpoch = fun _ e ct -> if e = 1UL then gate.Task.WaitAsync ct else Task.CompletedTask
                }

        do! h.RunSlots(0UL, 7UL)
        advanceTo h (h.SlotDue 8UL + TimeSpan.FromMilliseconds 1.0)
        do! waitUntil vc "the attestation of slot 8" (fun () -> attested h.Node |> List.exists (fun (_, s) -> s = 8UL))
        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart 9UL) "inside slot 8"
        gate.TrySetResult() |> ignore
        do! h.RunSlots(9UL, 9UL)
        do! vc.Stop()

        Expect.equal
            (attested h.Node |> List.filter (fun (_, s) -> s >= 8UL))
            [ 0UL, 8UL; 1UL, 9UL ]
            "slots 8 and 9 attested"
    }

/// Threshold 2: one node's head events with a new dependent root do not refetch duties; the
/// same root from both nodes does.
let private dependentRootNeedsThreshold () =
    task {
        let h = harness ()
        let other = extraNode h
        addValidators [ h.Node; other ] 8

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ other ]
                    Threshold = 2
                    UseEvents = true
                }

        do! h.RunSlots(0UL, 3UL)
        let fetches () = attesterFetches h.Node 1UL + attesterFetches other 1UL
        Expect.equal (fetches ()) 1 "epoch 1 duties fetched once"

        do!
            waitUntil vc "both event streams" (fun () ->
                h.Node.RequestCount "GET /eth/v1/events" > 0 && other.RequestCount "GET /eth/v1/events" > 0)
        // Only node 1 reports the new roots.
        other.Reorg()
        advanceTo h (h.Clock.SlotStart 4UL + TimeSpan.FromMilliseconds 100.0)

        for _ in 1..20 do
            other.EmitHead 4UL
            do! Task.Delay 20

        do! h.RunSlots(4UL, 5UL)
        Expect.equal (fetches ()) 1 $"one node's dependent root does not refetch; log:\n{vc.Log}"
        // Both nodes report it.
        h.Node.Reorg()

        do!
            headUntilDone h 6UL (fun s ->
                h.Node.EmitHead s
                other.EmitHead s)

        do! h.RunSlots(7UL, 7UL)
        do! vc.Stop()
        Expect.isGreaterThanOrEqual (fetches ()) 2 $"two nodes on the new root refetch; log:\n{vc.Log}"
    }

/// Sync messages wait for SYNC_MESSAGE_DUE_BPS, not the attestation due time.
let private syncMessagesAtTheirDueTime () =
    task {
        let h =
            harnessFor "minimal" secondsPerSlot slotsPerEpoch UInt64.MaxValue [ "SYNC_MESSAGE_DUE_BPS", "5000" ]

        addValidators [ h.Node ] 4
        h.Node.SyncSeats[0UL] <- [| 0UL |]
        let vc = startVc h { defaults with Keys = [ 0..3 ] }
        do! h.RunSlots(0UL, 2UL)

        let at (s: Slot) =
            postsOf h.Node "pool/sync_committees"
            |> List.collect jsonItems
            |> List.filter (fun m -> m.GetProperty("slot").GetString() = string s)

        do! Task.Delay 300
        Expect.isEmpty (at 2UL) $"no sync message at the attestation due time; log:\n{vc.Log}"
        advanceTo h (h.Clock.SlotStart 2UL + h.Spec.SyncMessageDueAt 2UL + TimeSpan.FromMilliseconds 1.0)
        do! waitUntil vc "the sync message of slot 2" (fun () -> not (List.isEmpty (at 2UL)))
        do! vc.Stop()
    }

/// A key added during a sync committee period gets its sync committee subscription.
let private syncSubscriptionForNewKey () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 2
        h.Node.SyncSeats[0UL] <- [| 0UL |]
        h.Node.SyncSeats[1UL] <- [| 1UL |]
        let vc = startVc h { defaults with Keys = [ 0 ] }
        do! h.RunSlots(0UL, 3UL)

        let subscribed () =
            postsOf h.Node "sync_committee_subscriptions"
            |> List.collect jsonItems
            |> List.map (fun x -> x.GetProperty("validator_index").GetString())
            |> Set.ofList

        do! waitUntil vc "key 0's subscription" (fun () -> (subscribed ()).Contains "0")

        let backend =
            Eplix.Backend.Local.LocalBackend.create
                "local"
                [ pubkeyOf 1, Eplix.Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 1)) ]

        vc.Registry.Add(pubkeyOf 1, backend) |> ignore
        // The next epoch's refresh activates the key; its duties come with the new key set.
        do! h.RunSlots(4UL, 10UL)
        do! waitUntil vc "key 1's subscription" (fun () -> (subscribed ()).Contains "1")
        do! vc.Stop()
    }

/// Epoch 1's hook never ends and ignores ct: epoch 2's work still refreshes the keys and runs
/// its hook. Before, each epoch's work waited for the last one without a bound.
let private hungEpochWorkDoesNotStopLaterEpochs () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let never = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        let seen = Collections.Concurrent.ConcurrentQueue<Epoch>()

        let hook (e: Epoch) : Task =
            seen.Enqueue e
            if e = 1UL then never.Task else Task.CompletedTask

        let vc =
            startVc
                h
                { defaults with
                    OnEpoch = fun _ e _ -> hook e
                }

        let refreshes () = h.Node.RequestCount "POST /eth/v1/beacon/states/head/validators"
        do! h.RunSlots(0UL, 15UL)
        let before = refreshes ()
        do! h.RunSlots(16UL, 17UL)
        do! waitUntil vc "epoch 2's hook" (fun () -> Seq.contains 2UL seen)
        Expect.isGreaterThan (refreshes ()) before "epoch 2 refreshed the keys"

        Expect.isTrue
            (vc.Lines
             |> Seq.exists (fun l ->
                 l.StartsWith "ERROR" && l.Contains "epoch 2: the previous epoch's start work has not ended"))
            "logged as an error"

        never.TrySetResult() |> ignore
        do! vc.Stop()
    }

/// A stop while the loop waits for the epoch start work: Run returns only after that work ended
/// (here a hook that takes 300 ms to stop). Before, Run returned at once and the work went on.
let private stopWaitsForEpochWork () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let started = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        let finished = ref false

        let hook (e: Epoch) (ct: CancellationToken) : Task =
            if e <> 1UL then
                Task.CompletedTask
            else
                task {
                    started.TrySetResult() |> ignore

                    try
                        do! Task.Delay(Timeout.Infinite, ct)
                    with _ ->
                        ()

                    do! Task.Delay 300
                    finished.Value <- true
                }

        let vc =
            startVc
                h
                { defaults with
                    OnEpoch = fun _ e ct -> hook e ct
                }
        // The work of epoch 1 starts before slot 8; the clock stays before slot 8 starts.
        do! h.RunSlots(0UL, 7UL)
        do! started.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
        do! vc.Stop()
        Expect.isTrue finished.Value $"Run returned after the epoch work; log:\n{vc.Log}"
    }

/// The epoch start work throws before the epoch's first slot: logged as an error, the VC goes on.
/// Before, the exception ended Run.
let private epochWorkThrows () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let hook (e: Epoch) : Task = if e = 1UL then failwith "hook broke" else Task.CompletedTask

        let vc =
            startVc
                h
                { defaults with
                    OnEpoch = fun _ e _ -> hook e
                }

        do! h.RunSlots(0UL, 9UL)
        Expect.isFalse vc.Run.IsCompleted "Run goes on"
        do! vc.Stop()

        Expect.isTrue
            (vc.Lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "hook broke"))
            $"logged as an error; log:\n{vc.Log}"

        Expect.isTrue (attested h.Node |> List.exists (fun (_, s) -> s = 9UL)) "slot 9 attested"
    }

/// Selection hooks fail, so the epoch 0 run asks again each slot until slots 0 to 7 end. A
/// refetch of the duties in slot 2 starts the run over at its next pass, long before slot 8.
let private refetchRestartsSelectionEarly () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8

        let failing: SelectionHooks =
            {
                BeaconCommittee = fun _ _ -> Task.FromResult(Error "no combined proofs")
                SyncCommittee = fun _ _ -> Task.FromResult(Error "no combined proofs")
            }

        let vc =
            startVc
                h
                { defaults with
                    UseEvents = true
                    Selections = Some failing
                }

        do! h.RunSlots(0UL, 1UL)
        do! waitUntil vc "the event stream" (fun () -> h.Node.RequestCount "GET /eth/v1/events" > 0)
        h.Node.Reorg()
        do! headUntilDone h 2UL h.Node.EmitHead
        do! h.RunSlots(3UL, 5UL)

        do!
            waitUntil vc "the selection run of epoch 0 starting over" (fun () ->
                vc.Lines
                |> Seq.exists (fun l ->
                    l.Contains "epoch 0: attester duties were fetched again during the selection proofs"))

        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart 6UL) "before the old duties' slots ended"
        do! vc.Stop()
    }

/// Selection hooks fail, so the epoch 0 run asks again each slot until slot 7 ends. Epoch 1's
/// proofs still reach the hook early in epoch 0. Before, the epoch 1 run started only after the
/// epoch 0 run ended, at slot 8, and its first slots could miss aggregation.
let private nextEpochSelectionDoesNotWait () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let asked = Collections.Concurrent.ConcurrentQueue<Slot>()

        let failing: SelectionHooks =
            {
                BeaconCommittee =
                    fun req _ ->
                        for r in req do
                            asked.Enqueue r.Slot

                        Task.FromResult(Error "no combined proofs")
                SyncCommittee = fun _ _ -> Task.FromResult(Error "no combined proofs")
            }

        let vc =
            startVc
                h
                { defaults with
                    Selections = Some failing
                }

        do! h.RunSlots(0UL, 2UL)
        do! waitUntil vc "epoch 1's selection proofs" (fun () -> asked |> Seq.exists (fun s -> s >= 8UL))
        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart 3UL) "early in epoch 0"
        Expect.isTrue (asked |> Seq.exists (fun s -> s = 7UL)) "the epoch 0 run goes on too"
        do! vc.Stop()
    }

/// The epoch 1 start work ends after slot 8 started and activates key 7 on the way: once it
/// ends, prepare_beacon_proposer runs again with key 7, still in slot 8. Without the second call,
/// key 7's fee recipient waited for epoch 2's call.
let private lateEpochWorkPreparesNewKey () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        let gate = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
        let vcRef: Vc option ref = ref None

        let hook (e: Epoch) (ct: CancellationToken) : Task =
            if e <> 1UL then
                Task.CompletedTask
            else
                task {
                    do! gate.Task.WaitAsync ct
                    let vc = vcRef.Value.Value

                    let backend =
                        Eplix.Backend.Local.LocalBackend.create
                            "local"
                            [ pubkeyOf 7, Eplix.Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 7)) ]

                    vc.Registry.Add(pubkeyOf 7, backend) |> ignore
                    do! vc.Core.RefreshKeys ct
                }

        let vc =
            startVc
                h
                { defaults with
                    Keys = [ 0..6 ]
                    OnEpoch = fun _ e ct -> hook e ct
                }

        vcRef.Value <- Some vc
        do! h.RunSlots(0UL, 7UL)
        advanceTo h (h.Clock.SlotStart 8UL + TimeSpan.FromMilliseconds 1.0)

        do!
            waitUntil vc "the epoch work going on past slot 8's start" (fun () ->
                vc.Lines
                |> Seq.exists (fun l -> l.Contains "epoch 1: the epoch start work is not done at the first slot"))

        do! Task.Delay 200
        Expect.isFalse (h.Node.Prepared.ContainsKey 7UL) "key 7 is not active yet"
        gate.TrySetResult() |> ignore
        do! waitUntil vc "key 7's prepare_beacon_proposer" (fun () -> h.Node.Prepared.ContainsKey 7UL)
        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart 9UL) "inside slot 8"
        do! vc.Stop()
    }

/// The head event of slot 2 comes after the attestation due time and before the sync message due
/// time: the sync message goes out at the event. Before, the loop dropped the slot's head signal
/// at the attestation due time and the sync message waited for its due time.
let private lateHeadStartsSyncMessages () =
    task {
        let h =
            harnessFor "minimal" secondsPerSlot slotsPerEpoch UInt64.MaxValue [ "SYNC_MESSAGE_DUE_BPS", "5000" ]

        addValidators [ h.Node ] 4
        h.Node.SyncSeats[0UL] <- [| 0UL |]

        let vc =
            startVc
                h
                { defaults with
                    Keys = [ 0..3 ]
                    UseEvents = true
                }

        do! waitUntil vc "the event stream" (fun () -> h.Node.RequestCount "GET /eth/v1/events" > 0)
        do! h.RunSlots(0UL, 2UL)

        let at (s: Slot) =
            postsOf h.Node "pool/sync_committees"
            |> List.collect jsonItems
            |> List.filter (fun m -> m.GetProperty("slot").GetString() = string s)

        do! Task.Delay 200
        Expect.isEmpty (at 2UL) $"no sync message before the head event; log:\n{vc.Log}"
        let mutable n = 0

        while List.isEmpty (at 2UL) && n < 100 do
            h.Node.EmitHead 2UL
            do! Task.Delay 20
            n <- n + 1

        Expect.isNonEmpty (at 2UL) $"the sync message of slot 2 at the head event; log:\n{vc.Log}"

        Expect.isLessThan
            (h.Time.GetUtcNow())
            (h.Clock.SlotStart 2UL + h.Spec.SyncMessageDueAt 2UL)
            "before the due time"

        do! vc.Stop()
    }

[<Tests>]
let reviewTests =
    testSequenced
    <| testList
        "scheduler review fixes"
        [
            testT "a node hung on aggregates: every committee still aggregates in time" hungAggregateNode
            testT "duplicate and conflicting attester duties" duplicateDuties
            testT "attester duties not asked for, under another key or in another epoch" foreignAttesterDuties
            testT "proposer duties: copies, two proposers, another index, another epoch" foreignProposerDuties
            testT "sync duties: copies, conflicts, not asked for, under another key" foreignSyncDuties
            testT "hung epoch start work does not delay slot 0 of the epoch" epochWorkHangs
            testT "a new dependent root needs threshold nodes" dependentRootNeedsThreshold
            testT "sync messages at their own due time" syncMessagesAtTheirDueTime
            testT "a key added mid-period gets a sync subscription" syncSubscriptionForNewKey
            testT "a hung epoch hook does not stop later epochs' work" hungEpochWorkDoesNotStopLaterEpochs
            testT "the stop waits for the epoch start work" stopWaitsForEpochWork
            testT "an epoch start work that throws is logged, the VC goes on" epochWorkThrows
            testT "a duties refetch restarts failing selection passes early" refetchRestartsSelectionEarly
            testT "the next epoch's selection proofs do not wait for a failing run" nextEpochSelectionDoesNotWait
            testT "epoch start work that ends late prepares the keys it activated" lateEpochWorkPreparesNewKey
            testT "a head event after the attestation due time starts sync messages" lateHeadStartsSyncMessages
        ]

[<Tests>]
let tests =
    testSequenced
    <| testList
        "scheduler"
        [
            testT "a new dependent root refetches duties" reorgMovesDuties
            testT "the same root keeps duties" sameRootKeepsDuties
            testT "the clock steps back one epoch" clockStepsBackInRun
            testT "the clock steps back across a restart" clockBackAcrossRestart
            testT "a start before genesis with timers that fire early" startBeforeGenesis
            testT "attestation data that does not fit the duty is not signed" badAttestationData
            testT "host clock 1.5 s ahead and behind" clockSkewInsideTolerance
            testT "host clock ahead past the due time signs nothing early" clockSkewBeyondTheDueTime
            testT "duties are never asked past the next epoch" dutiesNeverPastNextEpoch
        ]

[<Tests>]
let proposalTests =
    testSequenced
    <| testList
        "proposal"
        [
            testT "a blinded block, another proposer or another fee recipient is not signed" badBlocks
        ]

[<Tests>]
let eventTests =
    testSequenced
    <| testList "events" [ testT "the stream drops, reconnects, attests on time" eventStreamDrops ]

[<Tests>]
let nodeTests =
    testSequenced
    <| testList
        "beacon nodes"
        [
            testT "one slow node of three" slowNodeOfThree
            testT "an optimistic node is not the best node" optimisticNotBest
            testT "a syncing node: ranking by health" rankingByHealth
            testT "with only an optimistic node the VC still uses it" onlyOptimistic
            testT "optimistic duties answers ask the next node" optimisticDutiesAskTheNext
            testT "optimistic duties with the next node hung come after PreferWait" optimisticDutiesHungNext
            testT "the highest value block and the aggregate with most bits win" bestBlockAndAggregate
            testT "Charon's beacon mock aggregate is not signed" charonMockAggregateRefused
            testT "an aggregate of the asked committee with no bit set is signed" emptyAggregateOfAskedCommittee
            testT "a higher value block that fails the checks does not win" bestValidBlockWins
            testT "a full aggregate wins; one of other data does not" fullAggregateWinsOtherDataRefused
            testT "the highest block value wins, far above the others too" highestBlockValueWins
        ]
