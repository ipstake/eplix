/// The Obol module: config, the selection endpoint JSON, and the whole VC against a fake node
/// that answers the selection endpoints with given combined proofs.
module Eplix.Tests.ObolTests

open System
open System.Text.Json
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Json
open Eplix.Obol
open Eplix.Obol.ObolModule
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.MetricsTests

let private section (json: string) =
    {
        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
        BaseDir = "/"
        Mainnet = false
    }

let private posts (h: Harness) (suffix: string) =
    h.Node.Posts |> Seq.filter (fun (p, _) -> p.EndsWith suffix) |> Seq.map snd |> List.ofSeq

let private jsonItems (body: string) =
    use d = JsonDocument.Parse body
    [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

let private waitFor (lines: Collections.Concurrent.ConcurrentQueue<string>) (what: string) (cond: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what (String.Join("\n", lines))
    }

let private advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

/// A 96-byte proof of one repeated byte, picked so is_aggregator at this committee length is `want`.
let private proofWhere (h: Harness) (committeeLength: uint64) (want: bool) =
    seq { 1..255 }
    |> Seq.map (fun b -> BlsSignature.Of(Array.create 96 (byte b)))
    |> Seq.find (fun p -> Selection.isAggregator h.Spec committeeLength p = want)

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let private obolOn = """, "obol": { "enabled": true }"""

/// (validator index, selection proof) of each aggregate submitted.
let private aggregates (h: Harness) =
    let schema = Schemas.signedAggregateAndProof h.Node.Preset

    posts h "aggregate_and_proofs"
    |> List.collect jsonItems
    |> List.map (fun a ->
        match SszJson.tryRead schema a with
        | Ok v ->
            let msg = Codec.fields (Codec.fields v).[0]
            Codec.asU msg[0], BlsSignature.Of(Codec.asBytes msg[2])
        | Error e -> failtestf "aggregate does not decode: %s" e)

/// (validator index, slot, selection proof) of each contribution submitted.
let private contributions (h: Harness) =
    let schema = Schemas.signedContributionAndProof h.Node.Preset

    posts h "contribution_and_proofs"
    |> List.collect jsonItems
    |> List.map (fun c ->
        match SszJson.tryRead schema c with
        | Ok v ->
            let msg = Codec.fields (Codec.fields v).[0]
            Codec.asU msg[0], Codec.asU (Codec.fields msg[1]).[0], BlsSignature.Of(Codec.asBytes msg[2])
        | Error e -> failtestf "contribution does not decode: %s" e)

/// Runs epoch 0 up to the aggregate due time of each slot.
let private runEpoch0 (h: Harness) =
    task {
        for s in 0UL .. 7UL do
            do! h.RunSlots(s, s)
            advanceTo h (h.Clock.SlotStart s + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)
            do! Task.Delay 20
    }

let private genU64 = Gen.elements [ 0UL; 1UL; 7UL; 255UL; 65536UL; UInt64.MaxValue ]

let private selectionGen =
    Gen.map4
        (fun (i: uint64) (s: uint64) (sub: int) (b: int) -> i, s, uint64 sub, BlsSignature.Of(Array.create 96 (byte b)))
        genU64
        genU64
        (Gen.choose (0, 3))
        (Gen.choose (0, 255))

let private selectionProofRoot (h: Harness) (slot: Slot) =
    Signing.computeSigningRoot
        (Codec.hashSlot slot)
        (Signing.domainAt h.Spec gvr h.Spec.DomainSelectionProof (h.Spec.EpochOf slot))

[<Tests>]
let tests =
    testList
        "obol"
        [
            test "config" {
                Expect.equal
                    (parse
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok { Enabled = false })
                    "absent: off"

                Expect.equal (parse (section """{ "enabled": true }""")) (Ok { Enabled = true }) "on"
                Expect.equal (parse (section """{ }""")) (Ok { Enabled = false }) "empty: off"
                Expect.isError (parse (section """{ "enabled": "yes" }""")) "enabled not a bool"
                Expect.isError (parse (section """{ "enabled": true, "distributed": true }""")) "unknown field"
            }

            testProp "beacon committee selections round-trip"
            <| Prop.forAll (Arb.fromGen (Gen.listOf selectionGen)) (fun xs ->
                let sel =
                    xs
                    |> List.map (fun (i, s, _, p) ->
                        ({
                            ValidatorIndex = i
                            Slot = s
                            SelectionProof = p
                        }
                        : BeaconCommitteeSelection))
                    |> Array.ofList

                let body = Text.Encoding.UTF8.GetString(Selections.encodeBeaconCommittee sel)
                decodeString Selections.decodeBeaconCommittee ("{\"data\":" + body + "}") = Ok sel)

            testProp "sync committee selections round-trip"
            <| Prop.forAll (Arb.fromGen (Gen.listOf selectionGen)) (fun xs ->
                let sel =
                    xs
                    |> List.map (fun (i, s, sub, p) ->
                        ({
                            ValidatorIndex = i
                            Slot = s
                            SubcommitteeIndex = sub
                            SelectionProof = p
                        }
                        : SyncCommitteeSelection))
                    |> Array.ofList

                let body = Text.Encoding.UTF8.GetString(Selections.encodeSyncCommittee sel)
                decodeString Selections.decodeSyncCommittee ("{\"data\":" + body + "}") = Ok sel)

            test "the request body has the beacon-APIs field names" {
                let p = BlsSignature.Of(Array.create 96 7uy)

                let sel: SyncCommitteeSelection =
                    {
                        ValidatorIndex = 3UL
                        Slot = 9UL
                        SubcommitteeIndex = 1UL
                        SelectionProof = p
                    }

                let body = Text.Encoding.UTF8.GetString(Selections.encodeSyncCommittee [ sel ])

                Expect.equal
                    body
                    ("[{\"validator_index\":\"3\",\"slot\":\"9\",\"subcommittee_index\":\"1\",\"selection_proof\":\""
                     + p.Hex
                     + "\"}]")
                    "body"

                Expect.isError
                    (decodeString Selections.decodeBeaconCommittee """{"data":[{"validator_index":"1","slot":"2"}]}""")
                    "an answer without a proof"
            }

            testSequenced
            <| testT "aggregators come from the combined proof, which goes into the aggregate" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // 64 per committee: one proof in 4 aggregates, so own and combined proofs pick different keys.
                    h.Node.CommitteeLength <- 64UL
                    let yes = proofWhere h 64UL true
                    let no = proofWhere h 64UL false
                    h.Node.CombineSelection <- fun index _ _ -> ValueSome(if index % 2UL = 0UL then yes else no)

                    let! _, run, cts, lines =
                        startVc h (tempDir ()) [ 0..7 ] obolOn [ LocalModule.create (); ObolModule.create () ]

                    use _ = cts
                    do! runEpoch0 h
                    do! waitFor lines "four aggregates" (fun () -> (aggregates h).Length >= 4)
                    cts.Cancel()
                    let! _ = run
                    let log = String.Join("\n", lines)
                    let aggs = aggregates h

                    Expect.equal
                        (aggs |> List.map fst |> List.sort)
                        [ 0UL; 2UL; 4UL; 6UL ]
                        $"even keys aggregate; log:\n{log}"

                    for _, p in aggs do
                        Expect.equal p yes "the combined proof is in the aggregate"
                    // One request for epoch 0 with every duty, each the VC's own proof.
                    let first = posts h "beacon_committee_selections" |> List.head |> jsonItems
                    Expect.equal first.Length 8 "all slots of the epoch in one request"

                    for x in first do
                        let index = UInt64.Parse(x.GetProperty("validator_index").GetString())
                        let slot = UInt64.Parse(x.GetProperty("slot").GetString())

                        let proof =
                            BlsSignature.TryParse(x.GetProperty("selection_proof").GetString()) |> ValueOption.get

                        Expect.isTrue
                            (verify (pubkeyOf (int index)) (selectionProofRoot h slot) proof)
                            "the own proof is sent"

                    let subs = posts h "beacon_committee_subscriptions" |> List.collect jsonItems

                    for s in subs |> List.filter (fun s -> UInt64.Parse(s.GetProperty("slot").GetString()) < 8UL) do
                        let index = UInt64.Parse(s.GetProperty("validator_index").GetString())

                        Expect.equal
                            (s.GetProperty("is_aggregator").GetBoolean())
                            (index % 2UL = 0UL)
                            "subscription flag from the combined proof"
                })

            testSequenced
            <| testT
                "contributions carry the combined proof; a key the answer leaves out does not contribute"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        h.Node.SyncSeats[0UL] <- [| 0UL |]
                        h.Node.SyncSeats[2UL] <- [| 16UL |]
                        let combined = BlsSignature.Of(Array.create 96 0x5Auy)

                        h.Node.CombineSelection <-
                            fun index _ _ -> if index = 2UL then ValueNone else ValueSome combined

                        let! _, run, cts, lines =
                            startVc h (tempDir ()) [ 0..3 ] obolOn [ LocalModule.create (); ObolModule.create () ]

                        use _ = cts
                        do! h.RunSlots(0UL, 3UL)
                        advanceTo h (h.Clock.SlotStart 3UL + h.Spec.ContributionDue + TimeSpan.FromMilliseconds 1.0)

                        do!
                            waitFor lines "the contribution of slot 3" (fun () ->
                                contributions h |> List.exists (fun (_, s, _) -> s = 3UL))

                        cts.Cancel()
                        let! _ = run
                        let log = String.Join("\n", lines)
                        let cs = contributions h

                        Expect.isTrue
                            (cs |> List.forall (fun (i, _, _) -> i = 0UL))
                            $"only key 0 contributes; log:\n{log}"

                        for _, _, p in cs do
                            Expect.equal p combined "the combined proof is in the contribution"

                        let sync = posts h "sync_committee_selections" |> List.collect jsonItems
                        Expect.isNonEmpty sync "sync selections sent"

                        Expect.isTrue
                            (sync |> List.forall (fun x -> fst (x.TryGetProperty "subcommittee_index")))
                            "each sync selection names its subcommittee"
                    })

            testSequenced
            <| testT "a failed selection call means no aggregation, and attestations go on" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Length 8: every own proof would aggregate.
                    h.Node.CommitteeLength <- 8UL
                    h.Node.SyncSeats[0UL] <- [| 0UL |]
                    h.Node.Fail <- fun p -> p.EndsWith "_selections"

                    let! _, run, cts, lines =
                        startVc h (tempDir ()) [ 0..7 ] obolOn [ LocalModule.create (); ObolModule.create () ]

                    use _ = cts
                    do! runEpoch0 h
                    advanceTo h (h.Clock.SlotStart 7UL + h.Spec.ContributionDue + TimeSpan.FromMilliseconds 1.0)
                    do! Task.Delay 200
                    cts.Cancel()
                    let! _ = run
                    let log = String.Join("\n", lines)
                    Expect.isEmpty (posts h "aggregate_and_proofs") $"no aggregates; log:\n{log}"
                    Expect.isEmpty (posts h "contribution_and_proofs") "no contributions"

                    Expect.equal
                        (h.Node.Submissions |> Seq.filter (fun s -> s.Slot < 8UL) |> Seq.length)
                        8
                        "attestations"

                    Expect.stringContains log "do not aggregate" "warning"

                    let calls =
                        h.Node.Requests |> Seq.filter (fun r -> r.EndsWith "beacon_committee_selections") |> Seq.length

                    Expect.isGreaterThan calls 2 "the epoch's call is retried a slot later"
                })

            testSequenced
            <| testT "after a failed call the epoch's proofs are sent again a slot later" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    let failing = ref true
                    h.Node.Fail <- fun p -> failing.Value && p.EndsWith "beacon_committee_selections"

                    let! _, run, cts, lines =
                        startVc h (tempDir ()) [ 0..7 ] obolOn [ LocalModule.create (); ObolModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, 0UL)

                    do!
                        waitFor lines "a failed call" (fun () ->
                            lines |> Seq.exists (fun l -> l.Contains "asked again next slot"))

                    failing.Value <- false
                    do! runEpoch0 h

                    do!
                        waitFor lines "aggregates from slot 2" (fun () ->
                            (aggregates h |> List.filter (fun (i, _) -> i >= 2UL)).Length >= 6)

                    cts.Cancel()
                    let! _ = run
                    let log = String.Join("\n", lines)
                    let late = aggregates h |> List.map fst |> List.filter (fun i -> i >= 2UL) |> List.sort
                    Expect.equal late [ 2UL .. 7UL ] $"keys with later slots aggregate; log:\n{log}"
                })

            testSequenced
            <| testT "linked but off: no selection calls, own proofs decide" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..7 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    h.Node.CombineSelection <- fun _ _ _ -> ValueNone

                    let! _, run, cts, lines =
                        startVc h (tempDir ()) [ 0..7 ] "" [ LocalModule.create (); ObolModule.create () ]

                    use _ = cts
                    do! runEpoch0 h
                    do! waitFor lines "eight aggregates" (fun () -> (aggregates h).Length >= 8)
                    cts.Cancel()
                    let! _ = run

                    Expect.isFalse
                        (h.Node.Requests |> Seq.exists (fun r -> r.Contains "_selections"))
                        "no selection calls"

                    for i, p in aggregates h do
                        Expect.isTrue
                            (verify (pubkeyOf (int i)) (selectionProofRoot h i) p)
                            "the own proof is in the aggregate"
                })
        ]
