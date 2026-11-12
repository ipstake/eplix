/// The Fulu to Gloas boundary (G the Gloas fork epoch, E the slots per epoch): the fork version of
/// every duty kind at slots G*E-1 and G*E, duty lookahead, due times, the switch from
/// produceBlockV3 to V4, events, the sync committee period edge, and the fork epoch changing under
/// a running VC. The same with the mainnet preset (32 slots, 12 s).
module Eplix.Tests.ForkBoundaryTests

open System
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let private g = 2UL

/// The fork version and domain of each duty kind at the last Fulu slot and the first Gloas slot.
let private domainsAtBoundary (h: Harness) =
    let spec = h.Spec
    let e = spec.SlotsPerEpoch
    let last = g * e - 1UL
    let first = g * e
    let fulu = versionOf spec Fulu
    let gloasV = versionOf spec Gloas
    let capella = versionOf spec Capella
    let pk = pubkeyOf 0
    let req duty = Duty.request spec gvr pk Priority.Low DateTimeOffset.MaxValue duty

    let expect (duty: Duty) (domainType: DomainType) (version: ForkVersion) (what: string) =
        let r = req duty
        Expect.equal r.Domain (Signing.computeDomain domainType version gvr) $"{what}: domain"
        Expect.equal r.SigningRoot (Signing.computeSigningRoot (Duty.objectRoot duty) r.Domain) $"{what}: signing root"

        match duty with
        | Duty.VoluntaryExit _ -> ()
        | _ -> Expect.equal r.Fork.Fork.CurrentVersion version $"{what}: fork info"

    let data slot targetEpoch =
        {
            Slot = slot
            Index = 0UL
            BeaconBlockRoot = root 1
            Source =
                {
                    Epoch = targetEpoch - 1UL
                    Root = root 2
                }
            Target = { Epoch = targetEpoch; Root = root 3 }
        }
    // Attestations take the fork of the target epoch.
    expect (Duty.Attestation(data last (g - 1UL))) spec.DomainBeaconAttester fulu "attestation in G*E-1"
    expect (Duty.Attestation(data first g)) spec.DomainBeaconAttester gloasV "attestation in G*E"
    // The target epoch decides, not the slot (the pyspec's get_domain takes data.target.epoch):
    // data for slot G*E naming target G-1 is signed under Fulu.
    expect (Duty.Attestation(data first (g - 1UL))) spec.DomainBeaconAttester fulu "slot G*E with target G-1"
    // RANDAO and blocks: the epoch of the slot.
    expect (Duty.RandaoReveal(g - 1UL)) spec.DomainRandao fulu "RANDAO for G-1"
    expect (Duty.RandaoReveal g) spec.DomainRandao gloasV "RANDAO for G"

    let header slot =
        {
            Slot = slot
            ProposerIndex = 1UL
            ParentRoot = root 4
            StateRoot = root 5
            BodyRoot = root 6
        }

    expect (Duty.Block(header last)) spec.DomainBeaconProposer fulu "block in G*E-1"
    expect (Duty.Block(header first)) spec.DomainBeaconProposer gloasV "block in G*E"
    // Sync committee messages: the epoch of their slot.
    expect (Duty.SyncCommitteeMessage(last, root 7)) spec.DomainSyncCommittee fulu "sync message in G*E-1"
    expect (Duty.SyncCommitteeMessage(first, root 7)) spec.DomainSyncCommittee gloasV "sync message in G*E"
    // Selection proofs for G*E, signed a slot ahead during G*E-1: the slot's fork.
    expect
        (Duty.SyncSelectionProof
            {
                Slot = first
                SubcommitteeIndex = 0UL
            })
        spec.DomainSyncCommitteeSelectionProof
        gloasV
        "sync selection proof for G*E"

    expect
        (Duty.SyncSelectionProof { Slot = last; SubcommitteeIndex = 0UL })
        spec.DomainSyncCommitteeSelectionProof
        fulu
        "sync selection proof for G*E-1"

    expect (Duty.AggregationSlot first) spec.DomainSelectionProof gloasV "aggregation selection for G*E"
    expect (Duty.AggregationSlot last) spec.DomainSelectionProof fulu "aggregation selection for G*E-1"
    // The aggregate of a last-Fulu attestation keeps the Electra container and the Fulu version,
    // whenever it is signed.
    Expect.isFalse (spec.IsGloasAt(spec.EpochOf last)) "G*E-1 is Fulu"
    let p = spec.Preset

    let msg =
        Ssz.Fields
            [|
                Ssz.U 3UL
                Ssz.zero (Schemas.attestation p)
                Ssz.Bytes(Array.zeroCreate 96)
            |]

    let electraMsg =
        {
            Schema = Schemas.aggregateAndProofAt (spec.IsGloasAt(spec.EpochOf last)) p
            Value = msg
        }

    Expect.equal
        electraMsg.HashTreeRoot
        (Root.Of(Ssz.hashTreeRoot (Schemas.aggregateAndProof p) msg))
        "Electra AggregateAndProof root"

    expect (Duty.AggregateAndProof(last, electraMsg)) spec.DomainAggregateAndProof fulu "aggregate of G*E-1"

    let gloasMsg =
        {
            Schema = Schemas.aggregateAndProofAt (spec.IsGloasAt(spec.EpochOf first)) p
            Value = msg
        }

    Expect.equal
        gloasMsg.HashTreeRoot
        (Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.aggregateAndProof p) msg))
        "Gloas AggregateAndProof root"

    expect (Duty.AggregateAndProof(first, gloasMsg)) spec.DomainAggregateAndProof gloasV "aggregate of G*E"
    // A contribution for G*E-1 keeps the Fulu version.
    let contribution =
        {
            Schema = Schemas.contributionAndProof p
            Value = Ssz.zero (Schemas.contributionAndProof p)
        }

    expect (Duty.ContributionAndProof(last, contribution)) spec.DomainContributionAndProof fulu "contribution of G*E-1"
    expect (Duty.ContributionAndProof(first, contribution)) spec.DomainContributionAndProof gloasV "contribution of G*E"
    // Proposer preferences for G*E, signed in G-1: the proposal epoch's version.
    let prefs =
        {
            DependentRoot = root 8
            ProposalSlot = first
            ValidatorIndex = 1UL
            FeeRecipient = hex feeHex
            TargetGasLimit = 60_000_000UL
        }

    expect (Duty.ProposerPreferences prefs) spec.DomainProposerPreferences gloasV "proposer preferences for G*E"
    // PTC votes start at G*E.
    let pad =
        {
            BeaconBlockRoot = root 9
            Slot = first
            PayloadPresent = true
            BlobDataAvailable = true
        }

    expect (Duty.PayloadAttestation pad) spec.DomainPtcAttester gloasV "PTC vote in G*E"
    // Exits: Capella on both sides (EIP-7044).
    expect
        (Duty.VoluntaryExit
            {
                Epoch = g - 1UL
                ValidatorIndex = 1UL
            })
        spec.DomainVoluntaryExit
        capella
        "exit in G-1"

    expect (Duty.VoluntaryExit { Epoch = g; ValidatorIndex = 1UL }) spec.DomainVoluntaryExit capella "exit in G"

/// Aggregates at G*E-1 and G*E through the scheduler: Electra root and Fulu version, then the
/// progressive root and the Gloas version; attestations with the matching consensus version.
let private aggregatesAcrossTheFork (h: Harness) =
    task {
        addValidators [ h.Node ] 8
        h.Node.CommitteeLength <- 8UL
        let e = h.Spec.SlotsPerEpoch
        // Even validators attest in the last slot of each epoch, odd ones in the first.
        h.Node.DutySlotOverride <-
            fun v epoch -> ValueSome(if v.Index % 2UL = 0UL then epoch * e + e - 1UL else epoch * e)

        let vc = startVc h defaults
        let last = g * e - 1UL
        let first = g * e

        let aggsAt (s: Slot) =
            postsOf h.Node "aggregate_and_proofs"
            |> List.collect jsonItems
            |> List.filter (fun a ->
                a.GetProperty("message").GetProperty("aggregate").GetProperty("data").GetProperty("slot").GetString() =
                    string s)

        do! h.RunSlots(0UL, last)
        advanceTo h (h.Clock.SlotStart last + h.Spec.AggregateDueAt last + TimeSpan.FromMilliseconds 1.0)
        do! waitUntil vc "the aggregate of G*E-1" (fun () -> not (List.isEmpty (aggsAt last)))
        do! h.RunSlots(first, first)
        advanceTo h (h.Clock.SlotStart first + h.Spec.AggregateDueAt first + TimeSpan.FromMilliseconds 1.0)
        do! waitUntil vc "the aggregate of G*E" (fun () -> not (List.isEmpty (aggsAt first)))
        do! vc.Stop()
        let p = h.Node.Preset

        for slot, gloas, version in [ last, false, versionOf h.Spec Fulu; first, true, versionOf h.Spec Gloas ] do
            for a in aggsAt slot do
                let v = SszJson.read (Schemas.signedAggregateAndProofAt gloas p) a
                let f = Codec.fields v
                let index = Codec.asU (Codec.fields f[0]).[0]
                let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.aggregateAndProofAt gloas p) f[0])
                let domain = Signing.computeDomain h.Spec.DomainAggregateAndProof version gvr

                Expect.isTrue
                    (verifySig
                        (pubkeyOf (int index))
                        (Signing.computeSigningRoot msgRoot domain)
                        (BlsSignature.Of(Codec.asBytes f[1])))
                    $"aggregate of slot {slot} signed with the {(if gloas then Gloas else Fulu).ApiName} root and version"

        let versionAt (s: Slot) =
            h.Node.Submissions
            |> Seq.filter (fun x -> x.Slot = s)
            |> Seq.map (fun x -> x.ConsensusVersion)
            |> Seq.distinct
            |> List.ofSeq

        Expect.equal (versionAt last) [ "fulu" ] "attestations of G*E-1 as fulu"
        Expect.equal (versionAt first) [ "gloas" ] "attestations of G*E as gloas"

        for x in h.Node.Submissions do
            let domain =
                Signing.computeDomain h.Spec.DomainBeaconAttester (h.Spec.ForkAt x.Data.Target.Epoch).Version gvr

            Expect.isTrue
                (verifySig
                    (pubkeyOf (int x.AttesterIndex))
                    (Signing.computeSigningRoot (Codec.hashAttestationData x.Data) domain)
                    x.Signature)
                $"attestation of slot {x.Slot} under its target epoch's version"
    }

/// PTC duties for G are fetched during G-1 (none before), the first Gloas slot's attestation goes
/// out at the Gloas due time, and a PTC vote goes out in G*E.
let private ptcLookahead (h: Harness) =
    task {
        addValidators [ h.Node ] 8
        let e = h.Spec.SlotsPerEpoch
        let first = g * e
        h.Node.PtcSlots[first] <- [| 3UL |]
        let vc = startVc h defaults
        let ptcAsked (epoch: Epoch) = h.Node.RequestCount $"POST /eth/v1/validator/duties/ptc/{epoch}"
        // The epoch loop of G-1 (it starts once the last slot of G-2 is done) fetches duties for G-1 and G.
        do! h.RunSlots(0UL, (g - 1UL) * e)
        do! waitUntil vc "PTC duties for G during G-1" (fun () -> ptcAsked g > 0)
        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart first) "asked before the fork"

        for epoch in 0UL .. g - 1UL do
            Expect.equal (ptcAsked epoch) 0 $"no PTC duties asked for Fulu epoch {epoch}"

        do! h.RunSlots((g - 1UL) * e + 1UL, first - 1UL)
        // G*E: the attestation is done once the clock reaches the Gloas due time (25%, not 33%).
        Expect.equal (h.Spec.AttestationDue first) (h.Spec.Bps 2500UL) "Gloas due time"
        advanceTo h (h.Clock.SlotStart first + h.Spec.Bps 2500UL + TimeSpan.FromMilliseconds 1.0)
        do! h.Waiter.Wait first
        Expect.isTrue (h.Node.Submissions |> Seq.exists (fun s -> s.Slot = first)) "attested in G*E"
        advanceTo h (h.Clock.SlotStart first + h.Spec.Bps 7100UL)
        do! waitUntil vc "the PTC vote in G*E" (fun () -> not (List.isEmpty (postsOf h.Node "payload_attestations")))
        do! vc.Stop()
        let votes = postsOf h.Node "payload_attestations" |> List.collect jsonItems

        Expect.equal
            (votes
             |> List.map (fun v ->
                 v.GetProperty("validator_index").GetString(), v.GetProperty("data").GetProperty("slot").GetString()))
            [ "3", string first ]
            "one PTC vote, validator 3, slot G*E"
    }

let private dueKeys =
    [
        "ATTESTATION_DUE_BPS"
        "AGGREGATE_DUE_BPS"
        "SYNC_MESSAGE_DUE_BPS"
        "CONTRIBUTION_DUE_BPS"
        "ATTESTATION_DUE_BPS_GLOAS"
        "AGGREGATE_DUE_BPS_GLOAS"
        "SYNC_MESSAGE_DUE_BPS_GLOAS"
        "CONTRIBUTION_DUE_BPS_GLOAS"
        "PAYLOAD_ATTESTATION_DUE_BPS"
    ]

/// Values a node may report, unlike the spec defaults, so a test sees which ones the VC uses.
let private reportedDue =
    [
        "ATTESTATION_DUE_BPS", "3000"
        "AGGREGATE_DUE_BPS", "6000"
        "SYNC_MESSAGE_DUE_BPS", "3100"
        "CONTRIBUTION_DUE_BPS", "6100"
        "ATTESTATION_DUE_BPS_GLOAS", "2400"
        "AGGREGATE_DUE_BPS_GLOAS", "4800"
        "SYNC_MESSAGE_DUE_BPS_GLOAS", "2300"
        "CONTRIBUTION_DUE_BPS_GLOAS", "4700"
        "PAYLOAD_ATTESTATION_DUE_BPS", "7400"
    ]

/// A spec without any *_DUE_BPS value, or with the reported ones.
let private specWithDue (presetBase: string) (seconds: int) (spe: int) (reported: bool) =
    let values =
        specValuesPreset presetBase seconds spe g
        |> List.filter (fun (k, _) -> not (List.contains k dueKeys))
        |> fun vs -> if reported then vs @ reportedDue else vs

    match ChainSpec.parse (Map.ofList values) with
    | Ok s -> s
    | Error e -> failwith e

/// Each kind's due time at G*E-1 and G*E: the basis points of that slot's fork.
let private dueTable (presetBase: string) (seconds: int) (spe: int) =
    for reported in [ false; true ] do
        let spec = specWithDue presetBase seconds spe reported
        let last = g * spec.SlotsPerEpoch - 1UL
        let first = last + 1UL

        let bps (k: string) (fallback: uint64) =
            if reported then reportedDue |> List.find (fun (x, _) -> x = k) |> snd |> UInt64.Parse else fallback

        let at (b: uint64) = TimeSpan.FromTicks(spec.SlotDuration.Ticks * int64 b / 10000L)
        let what = if reported then "reported" else "defaults"
        Expect.equal (spec.AttestationDue last) (at (bps "ATTESTATION_DUE_BPS" 3333UL)) $"{what}: attestation, Fulu"

        Expect.equal
            (spec.AttestationDue first)
            (at (bps "ATTESTATION_DUE_BPS_GLOAS" 2500UL))
            $"{what}: attestation, Gloas"

        Expect.equal (spec.AggregateDueAt last) (at (bps "AGGREGATE_DUE_BPS" 6667UL)) $"{what}: aggregate, Fulu"
        Expect.equal (spec.AggregateDueAt first) (at (bps "AGGREGATE_DUE_BPS_GLOAS" 5000UL)) $"{what}: aggregate, Gloas"
        Expect.equal (spec.SyncMessageDueAt last) (at (bps "SYNC_MESSAGE_DUE_BPS" 3333UL)) $"{what}: sync message, Fulu"

        Expect.equal
            (spec.SyncMessageDueAt first)
            (at (bps "SYNC_MESSAGE_DUE_BPS_GLOAS" 2500UL))
            $"{what}: sync message, Gloas"

        Expect.equal
            (spec.ContributionDueAt last)
            (at (bps "CONTRIBUTION_DUE_BPS" 6667UL))
            $"{what}: contribution, Fulu"

        Expect.equal
            (spec.ContributionDueAt first)
            (at (bps "CONTRIBUTION_DUE_BPS_GLOAS" 5000UL))
            $"{what}: contribution, Gloas"

        Expect.equal spec.PayloadAttestationDue (at (bps "PAYLOAD_ATTESTATION_DUE_BPS" 7500UL)) $"{what}: PTC vote"

/// The scheduler waits for each slot's own due time: attestations and aggregates of G*E-1 not
/// before the Fulu times, those of G*E at the Gloas times (the node's reported values).
let private dueTimesInTheScheduler () =
    task {
        let h =
            { gloasHarness g with
                Spec = specWithDue "minimal" secondsPerSlot slotsPerEpoch true
            }

        addValidators [ h.Node ] 8
        h.Node.CommitteeLength <- 8UL
        let vc = startVc h defaults
        let e = h.Spec.SlotsPerEpoch
        let last = g * e - 1UL
        let first = last + 1UL
        let attestedAt (s: Slot) = h.Node.Submissions |> Seq.exists (fun x -> x.Slot = s)

        let aggregatedAt (s: Slot) =
            postsOf h.Node "aggregate_and_proofs"
            |> List.collect jsonItems
            |> List.exists (fun a ->
                a.GetProperty("message").GetProperty("aggregate").GetProperty("data").GetProperty("slot").GetString() =
                    string s)

        do! h.RunSlots(0UL, last - 1UL)

        for s in [ last; first ] do
            let att = h.Spec.AttestationDue s
            let agg = h.Spec.AggregateDueAt s
            advanceTo h (h.Clock.SlotStart s + att - TimeSpan.FromMilliseconds 1.0)
            do! Task.Delay 200
            Expect.isFalse (attestedAt s) $"slot {s}: no attestation before {att.TotalMilliseconds} ms"
            advanceTo h (h.Clock.SlotStart s + att + TimeSpan.FromMilliseconds 1.0)
            do! h.Waiter.Wait s
            Expect.isTrue (attestedAt s) $"slot {s}: attested at {att.TotalMilliseconds} ms"
            advanceTo h (h.Clock.SlotStart s + agg - TimeSpan.FromMilliseconds 1.0)
            do! Task.Delay 200
            Expect.isFalse (aggregatedAt s) $"slot {s}: no aggregate before {agg.TotalMilliseconds} ms"
            advanceTo h (h.Clock.SlotStart s + agg + TimeSpan.FromMilliseconds 1.0)
            do! waitUntil vc $"the aggregate of slot {s}" (fun () -> aggregatedAt s)

        do! vc.Stop()
    }

/// A proposal in G*E-1 goes through produceBlockV3, one in G*E through V4 with the envelope after
/// the block; each block is signed with its slot's fork version.
let private v3ThenV4 (h: Harness) =
    task {
        addValidators [ h.Node ] 8
        let e = h.Spec.SlotsPerEpoch
        let last = g * e - 1UL
        let first = last + 1UL
        h.Node.Proposals[last] <- 3UL
        h.Node.Proposals[first] <- 5UL
        let vc = startVc h defaults

        for s in 0UL .. first do
            let before = h.Node.Published.Count
            do! h.RunSlots(s, s)

            if h.Node.Proposals.ContainsKey s then
                do! waitUntil vc $"the block of slot {s}" (fun () -> h.Node.Published.Count > before)

        do! waitUntil vc "the envelope of G*E" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
        do! vc.Stop()
        Expect.equal (h.Node.RequestCount $"GET /eth/v3/validator/blocks/{last}") 1 "V3 for G*E-1"
        Expect.equal (h.Node.RequestCount $"POST /eth/v4/validator/blocks/{last}") 0 "no V4 for G*E-1"
        Expect.equal (h.Node.RequestCount $"POST /eth/v4/validator/blocks/{first}") 1 "V4 for G*E"
        Expect.equal (h.Node.RequestCount $"GET /eth/v3/validator/blocks/{first}") 0 "no V3 for G*E"
        let blocks = List.ofSeq h.Node.Published
        Expect.equal (blocks |> List.map (fun (v, _, _) -> v)) [ "fulu"; "gloas" ] "consensus versions"

        Expect.equal
            (List.ofSeq h.Node.PublishOrder)
            [ "block"; "block"; "envelope" ]
            "one envelope, after the Gloas block"

        let p = h.Node.Preset
        let _, _, fuluBytes = blocks[0]

        let signedFulu =
            match Ssz.deserialize (Schemas.signedBlockContents p) fuluBytes with
            | Ok v -> Codec.fields (Codec.fields v).[0]
            | Error err -> failtestf "Fulu block: %s" err

        let _, _, gloasBytes = blocks[1]

        let signedGloas =
            match Ssz.deserialize (Schemas.Gloas.signedBeaconBlock p) gloasBytes with
            | Ok v -> Codec.fields v
            | Error err -> failtestf "Gloas block: %s" err

        for signed, bodySchema, version, proposer in
            [
                signedFulu, Schemas.beaconBlockBody p, versionOf h.Spec Fulu, 3
                signedGloas, Schemas.Gloas.beaconBlockBody p, versionOf h.Spec Gloas, 5
            ] do
            let block = Codec.fields signed[0]

            let header =
                {
                    Slot = Codec.asU block[0]
                    ProposerIndex = Codec.asU block[1]
                    ParentRoot = Root.Of(Codec.asBytes block[2])
                    StateRoot = Root.Of(Codec.asBytes block[3])
                    BodyRoot = Root.Of(Ssz.hashTreeRoot bodySchema block[4])
                }

            let domain = Signing.computeDomain h.Spec.DomainBeaconProposer version gvr

            Expect.isTrue
                (verifySig
                    (pubkeyOf proposer)
                    (Signing.computeSigningRoot (Codec.hashBeaconBlockHeader header) domain)
                    (BlsSignature.Of(Codec.asBytes signed[1])))
                $"block of slot {header.Slot} under its fork version"
    }

/// The beacon-APIs examples (79b9b05, apis/eventstream/index.yaml) of both head forms decode to
/// the same dependent roots.
let private headForms () =
    let head =
        """{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}"""

    let headV2 =
        """{"version": "gloas", "data":{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "payload_status": "empty", "epoch_transition":false, "current_epoch_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "next_epoch_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}}"""

    let decode name text =
        match Json.decodeString (Decoders.headEvent name) text with
        | Ok h -> h
        | Error e -> failtestf "%s: %s" name e

    let a = decode "head" head
    let b = decode "head_v2" headV2
    Expect.equal b a "head and head_v2 decode to the same event"
    Expect.equal a.Slot 10UL "slot"

    Expect.equal
        a.Block
        (Root.TryParse "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf").Value
        "block"

/// Head events drive attestations before and after the fork, in either form; a head_v2 with a
/// new dependent root refetches duties like a head does; execution_payload_available drives a PTC
/// vote only from G on.
let private eventsAcrossTheFork () =
    task {
        let h = gloasHarness 1UL
        addValidators [ h.Node ] 8
        h.Node.PtcSlots[10UL] <- [| 2UL |]
        let vc = startVc h { defaults with UseEvents = true }
        do! h.RunSlots(0UL, 4UL)
        // Slot 5, Fulu: a head event, and a payload event that must do nothing.
        do!
            headUntilDone h 5UL (fun s ->
                h.Node.EmitHead s
                h.Node.EmitPayloadAvailable s)

        Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 5UL) "Fulu: attested on the head event"
        do! h.RunSlots(6UL, 8UL)
        // Slot 9, Gloas: head_v2 drives the attestation.
        do! headUntilDone h 9UL h.Node.EmitHeadV2
        Expect.isLessThan (h.Time.GetUtcNow()) (h.SlotDue 9UL) "Gloas: attested on the head_v2 event"
        // Slot 10: head_v2 again, then the payload event for the PTC vote, before the 70% fallback.
        do! headUntilDone h 10UL h.Node.EmitHeadV2
        let mutable n = 0

        while List.isEmpty (postsOf h.Node "payload_attestations") && n < 200 do
            h.Node.EmitPayloadAvailable 10UL
            do! Task.Delay 20
            n <- n + 1

        Expect.isNonEmpty (postsOf h.Node "payload_attestations") "the PTC vote on the payload event"
        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart 10UL + h.Spec.Bps 7000UL) "before the fallback time"
        // A head_v2 with new dependent roots refetches the duties of epoch 1.
        let fetches () = h.Node.RequestCount "POST /eth/v1/validator/duties/attester/1"
        let before = fetches ()
        h.Node.Reorg()
        do! headUntilDone h 11UL h.Node.EmitHeadV2
        do! h.RunSlots(12UL, 12UL)
        do! vc.Stop()
        Expect.isGreaterThan (fetches ()) before "duties fetched again after a head_v2 with a new root"
        Expect.isTrue (vc.Lines |> Seq.forall (fun l -> not (l.StartsWith "ERROR"))) $"no error; log:\n{vc.Log}"
        let all = h.Node.Submissions |> Seq.map (fun x -> x.AttesterIndex, x.Slot) |> List.ofSeq
        Expect.equal (List.distinct all).Length all.Length "each duty once"
    }

/// The sync committee period changes with the fork (EPOCHS_PER_SYNC_COMMITTEE_PERIOD 2, Gloas at
/// 2): the new period's duties arrive during G-1; from slot G*E-1 the new committee signs, under
/// the Fulu version in G*E-1 and the Gloas version from G*E.
let private syncPeriodAtTheFork () =
    task {
        let h = harnessFor "minimal" secondsPerSlot slotsPerEpoch g [ "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "2" ]
        addValidators [ h.Node ] 8
        h.Node.HeadRoot <- root 77
        // Period 0 (epochs 0, 1): validator 1 holds seat 0. Period 1 (epochs 2, 3): validator 5 holds seat 3.
        h.Node.SyncSeatsAt <-
            Some(fun epoch index ->
                match epoch / 2UL, index with
                | 0UL, 1UL -> ValueSome [| 0UL |]
                | 1UL, 5UL -> ValueSome [| 3UL |]
                | _ -> ValueNone)

        let vc = startVc h defaults
        let e = h.Spec.SlotsPerEpoch
        let last = g * e - 1UL
        let first = last + 1UL
        do! h.RunSlots(0UL, (g - 1UL) * e)

        do!
            waitUntil vc "sync duties of G during G-1" (fun () ->
                h.Node.RequestCount $"POST /eth/v1/validator/duties/sync/{g}" > 0)

        Expect.isLessThan (h.Time.GetUtcNow()) (h.Clock.SlotStart first) "asked before the fork"
        do! h.RunSlots((g - 1UL) * e + 1UL, first + 1UL)

        let msgsAt (s: Slot) =
            postsOf h.Node "sync_committees"
            |> List.collect jsonItems
            |> List.filter (fun m -> m.GetProperty("slot").GetString() = string s)

        do! waitUntil vc "the sync message of G*E+1" (fun () -> not (List.isEmpty (msgsAt (first + 1UL))))
        do! vc.Stop()
        let signer (s: Slot) = msgsAt s |> List.map (fun m -> m.GetProperty("validator_index").GetString())
        Expect.equal (signer (last - 1UL)) [ "1" ] "G*E-2: the old committee"
        Expect.equal (signer last) [ "5" ] "G*E-1: the new committee signs (it is in force at G*E)"
        Expect.equal (signer first) [ "5" ] "G*E: the new committee"

        for s, version in
            [
                last, versionOf h.Spec Fulu
                first, versionOf h.Spec Gloas
                first + 1UL, versionOf h.Spec Gloas
            ] do
            for m in msgsAt s do
                let r = Root.TryParse(m.GetProperty("beacon_block_root").GetString()) |> ValueOption.get
                let sg = BlsSignature.TryParse(m.GetProperty("signature").GetString()) |> ValueOption.get
                let domain = Signing.computeDomain h.Spec.DomainSyncCommittee version gvr

                Expect.isTrue
                    (verifySig (pubkeyOf 5) (Signing.computeSigningRoot r domain) sg)
                    $"slot {s}: signed under its slot's fork"

        let subs = postsOf h.Node "sync_committee_subscriptions" |> List.collect jsonItems
        Expect.exists subs (fun x -> x.GetProperty("validator_index").GetString() = "5") "subscribed for the new period"
    }

let private minimalG () = gloasHarness g
let private mainnetG () = harnessFor "mainnet" 12 32 g []

[<Tests>]
let tests =
    testSequenced
    <| testList
        "fork boundary"
        [
            test "domains of every kind at slots G*E-1 and G*E" { domainsAtBoundary (minimalG ()) }
            testT "aggregates and attestations at G*E-1 and G*E" (fun () -> aggregatesAcrossTheFork (minimalG ()))
            testT "PTC duties for the first Gloas epoch arrive in the last Fulu epoch" (fun () ->
                ptcLookahead (minimalG ()))
            test "due times at slots G*E-1 and G*E" { dueTable "minimal" secondsPerSlot slotsPerEpoch }
            testT "the scheduler keeps each slot's due times across the fork" dueTimesInTheScheduler
            testT "V3 then V4" (fun () -> v3ThenV4 (minimalG ()))
            test "head and head_v2 events decode alike" { headForms () }
            testT "event stream before and after" eventsAcrossTheFork
            testT "sync committee period change in the fork epoch" syncPeriodAtTheFork
            testList
                "mainnet preset"
                [
                    test "domains of every kind at slots G*E-1 and G*E" { domainsAtBoundary (mainnetG ()) }
                    testT "aggregates and attestations at G*E-1 and G*E" (fun () ->
                        aggregatesAcrossTheFork (mainnetG ()))
                    testT "PTC duties for the first Gloas epoch arrive in the last Fulu epoch" (fun () ->
                        ptcLookahead (mainnetG ()))
                    test "due times at slots G*E-1 and G*E" { dueTable "mainnet" 12 32 }
                    testT "V3 then V4" (fun () -> v3ThenV4 (mainnetG ()))
                ]
        ]
