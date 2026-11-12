/// Gloas: signing roots of the new kinds, and the Gloas duties end to end on a fake clock
/// against the fake beacon node: PTC votes, produceBlockV4 proposals with the self-built envelope,
/// proposer preferences before the fork, the builder module, the progressive aggregate root.
module Eplix.Tests.GloasTests

open System
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Beacon
open Eplix.Gloas
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private feeHex = "0x00000000000000000000000000000000000000aa"
let private fee = hex feeHex
let private gloasVersion = ForkVersion.Of(hex "0x07000001")

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let private gloasHarness (gloasEpoch: uint64) =
    let h = harness ()
    h.Node.GloasEpoch <- gloasEpoch

    let spec =
        match ChainSpec.parse (Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch)) with
        | Ok s -> s
        | Error e -> failwith e

    { h with Spec = spec }

let private waitForLog (lines: Collections.Concurrent.ConcurrentQueue<string>) (what: string) (cond: unit -> bool) =
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

let private posts (h: Harness) (suffix: string) =
    h.Node.Posts |> Seq.filter (fun (p, _) -> p.EndsWith suffix) |> Seq.map snd |> List.ofSeq

let private jsonItems (body: string) =
    use d = JsonDocument.Parse body
    [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

type private Running =
    {
        Run: Task
        Db: SlashingDb
        Lines: Collections.Concurrent.ConcurrentQueue<string>
        Scheduler: DutyScheduler
        Gloas: GloasDuties
        Registry: KeyRegistry
        Cts: CancellationTokenSource
    }

    member r.Stop() =
        task {
            r.Cts.Cancel()
            do! r.Run
            (r.Db :> IDisposable).Dispose()
        }

/// The scheduler with the Gloas duties (and the builder module when given), local keys 0 to 7
/// behind `wrap` of the local backend, with `feeRecipient` as the core default fee recipient.
/// A key `hold` names waits in DoppelgangerWait instead of going active.
let private startHeld
    (hold: PubKey -> bool)
    (wrap: Backend -> Backend)
    (feeRecipient: string voption)
    (h: Harness)
    (settings: Settings)
    (builders: Eplix.Builder.BuilderModule.Settings option)
    (useEvents: bool)
    =
    let http = new HttpClient(h.Node, false)
    let beacon = BeaconClient(http, Uri "http://bn.test", TimeSpan.FromSeconds 5.0)
    let nodes = BeaconNodes([ beacon ], 1, h.Time, Log.none)

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let keys = [ 0..7 ]

    let backend =
        wrap (LocalBackend.create "local" [ for i in keys -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ])

    let registry = KeyRegistry()
    registry.ActivationHold <- fun k -> hold k.Key

    for i in keys do
        registry.Add(pubkeyOf i, backend) |> ignore

    let log, lines = Log.memory ()

    let slotMarks =
        match SlotMarks.Open(new FileMarkFile(Path.Combine(tempDir (), "slot-marks.db")), gvr) with
        | Ok m -> m
        | Error e -> failwith e

    let pipeline = Pipeline(db, registry, h.Time, log, slotMarks)

    let defaults: KeyDefaults =
        {
            FeeRecipient = feeRecipient
            Graffiti = "eplix"
            GasLimit = 60_000_000UL
        }

    let refresh (ct: CancellationToken) : Task =
        task {
            let! _ = refreshEmpty ValueNone nodes registry db log ct
            ()
        }

    let builder = ref ValueNone

    let core: CoreServices =
        {
            Spec = h.Spec
            Genesis =
                {
                    GenesisTime = genesisTime
                    GenesisValidatorsRoot = gvr
                    GenesisForkVersion = h.Spec.Forks[0].Version
                }
            Clock = h.Clock
            Nodes = nodes
            Registry = registry
            Pipeline = pipeline
            Slashing = db
            Defaults = defaults
            Graffiti = GraffitiService.Plain(registry, defaults.Graffiti)
            Log = log
            DataDir = tempDir ()
            RegisterBackend = fun _ -> Task.FromResult()
            RefreshKeys = refresh
            OnEpoch = ignore
            Shutdown = ignore
            Stopping = CancellationToken.None
            SetKeystores = ignore
            Keystores = fun () -> ValueNone
            SetRemoteKeys = ignore
            RemoteKeys = fun () -> ValueNone
            AddDutyExtension = ignore
            SetBuilder = fun b -> builder.Value <- ValueSome b
            Builder = fun () -> builder.Value
            SetSelections = ignore
            HaPeer = false
        }

    let gloas = GloasDuties(core, settings)

    let scheduler =
        DutyScheduler(
            h.Spec,
            gvr,
            h.Clock,
            nodes,
            registry,
            pipeline,
            log,
            {
                UseEvents = useEvents
                OnSlotDone = h.Waiter.Done
                OnEpoch = fun _ ct -> refresh ct
                Defaults = defaults
            }
        )

    scheduler.AddExtension gloas.Extension

    match builders with
    | Some bs ->
        let b = Eplix.Builder.BuilderModule.Builders(core, bs)
        core.SetBuilder b.Hooks
        scheduler.AddExtension b.Extension
    | None -> ()

    let cts = new CancellationTokenSource()

    {
        Run = scheduler.Run cts.Token
        Db = db
        Lines = lines
        Scheduler = scheduler
        Gloas = gloas
        Registry = registry
        Cts = cts
    }

let private startWrapped = startHeld (fun _ -> false)

let private startWith = startWrapped id

let private start = startWith (ValueSome feeHex)

let private addValidators (h: Harness) =
    for i in 0..7 do
        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

/// Runs slots up to `last` one at a time, waiting for each block of a proposal slot.
let private runProposals (h: Harness) (r: Running) (last: Slot) (published: unit -> int) =
    task {
        for s in 0UL .. last do
            let before = published ()
            do! h.RunSlots(s, s)

            if h.Node.Proposals.ContainsKey s then
                do! waitForLog r.Lines $"the proposal of slot {s}" (fun () -> published () > before)
    }

let private signedBlockOf (h: Harness) (bytes: byte[]) =
    match Ssz.deserialize (Schemas.Gloas.signedBeaconBlock h.Node.Preset) bytes with
    | Ok v -> v
    | Error e -> failtestf "published Gloas block does not decode: %s" e

let private builderSettings (minBid: uint64) : Eplix.Builder.BuilderModule.Settings =
    {
        Builders =
            [
                {
                    Url = "https://builder.test"
                    AuthData = Text.Encoding.UTF8.GetBytes "builder.test"
                    BuilderPubkeys = []
                    MaxExecutionPayment = 0UL
                    MinBid = minBid
                    BuilderBoostFactor = 100UL
                }
            ]
        Preferences = true
    }

/// The bid in a published SignedBeaconBlock (Gloas).
let private bidOfSigned (signed: Ssz.SszValue) = Gloas.bid (Gloas.bidOf (Codec.fields signed).[0])

/// Runs slots up to `last` and waits for the proposal of `slot` to fail; returns the reason.
let private proposalFails (h: Harness) (r: Running) (slot: Slot) (last: Slot) =
    task {
        let failed () =
            r.Gloas.Events
            |> Seq.tryPick (fun e ->
                match e with
                | ProposalFailed(s, why) when s = slot -> Some why
                | _ -> None)

        do! h.RunSlots(0UL, last)
        do! waitForLog r.Lines $"the failed proposal of slot {slot}" (fun () -> (failed ()).IsSome)
        return (failed ()).Value
    }

/// A builder's bid signature: builder key `i` over the bid under DOMAIN_BEACON_BUILDER.
let private signBid (h: Harness) (i: int) (message: Ssz.SszValue) =
    let domain = Signing.computeDomain h.Spec.DomainBeaconBuilder gloasVersion gvr

    let root =
        Signing.computeSigningRoot (Root.Of(Ssz.hashTreeRoot Schemas.Gloas.executionPayloadBid message)) domain

    Bls.sign (ReadOnlySpan(secretOf i)) (ReadOnlySpan root.Bytes)

let private builderWithKeys (keys: PubKey list) : Eplix.Builder.BuilderModule.Settings =
    let s = builderSettings 0UL

    { s with
        Builders = s.Builders |> List.map (fun b -> { b with BuilderPubkeys = keys })
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "gloas"
        [
            test "signing roots of the Gloas kinds use the spec's domains and fork versions" {
                let h = gloasHarness 2UL
                let spec = h.Spec
                let pk = pubkeyOf 0
                let req duty = Duty.request spec gvr pk Priority.Low DateTimeOffset.MaxValue duty
                let fulu = (spec.Forks |> Array.find (fun f -> f.Name = Fulu)).Version
                // PTC vote: DOMAIN_PTC_ATTESTER at the epoch of data.slot.
                let pad =
                    {
                        BeaconBlockRoot = root 9
                        Slot = 17UL
                        PayloadPresent = true
                        BlobDataAvailable = false
                    }

                let r = req (Duty.PayloadAttestation pad)
                let ptcDomain = Signing.computeDomain (DomainType.Of(hex "0x0c000000")) gloasVersion gvr

                Expect.equal
                    r.SigningRoot
                    (Signing.computeSigningRoot (Codec.hashPayloadAttestationData pad) ptcDomain)
                    "PTC vote"

                Expect.equal r.Fork.Fork.CurrentVersion gloasVersion "fork info of the PTC vote"
                // Preferences for the first Gloas slot, signed in the epoch before: the Gloas version
                // of the proposal epoch (compute_fork_version(proposal_epoch)).
                let prefs =
                    {
                        DependentRoot = root 3
                        ProposalSlot = 16UL
                        ValidatorIndex = 4UL
                        FeeRecipient = fee
                        TargetGasLimit = 60_000_000UL
                    }

                let pr = req (Duty.ProposerPreferences prefs)
                let prefDomain = Signing.computeDomain (DomainType.Of(hex "0x0d000000")) gloasVersion gvr

                Expect.equal
                    pr.SigningRoot
                    (Signing.computeSigningRoot (Codec.hashProposerPreferences prefs) prefDomain)
                    "preferences"

                Expect.notEqual
                    pr.SigningRoot
                    (Signing.computeSigningRoot
                        (Codec.hashProposerPreferences prefs)
                        (Signing.computeDomain (DomainType.Of(hex "0x0d000000")) fulu gvr))
                    "not the Fulu version"
                // Envelope: DOMAIN_BEACON_BUILDER at the epoch of the block.
                let env =
                    {
                        Schema = Schemas.Gloas.executionPayloadEnvelope h.Node.Preset
                        Value = Ssz.zero (Schemas.Gloas.executionPayloadEnvelope h.Node.Preset)
                    }

                let er = req (Duty.PayloadEnvelope(17UL, env))
                let builderDomain = Signing.computeDomain (DomainType.Of(hex "0x0b000000")) gloasVersion gvr
                Expect.equal er.SigningRoot (Signing.computeSigningRoot env.HashTreeRoot builderDomain) "envelope"
                // Builder request auth: genesis fork version and a zero genesis validators root.
                let auth =
                    {
                        AuthData = Text.Encoding.UTF8.GetBytes "builder.test"
                        AuthSlot = 16UL
                    }

                let ar = req (Duty.BuilderRequestAuth auth)

                let authDomain =
                    Signing.computeDomain (DomainType.Of(hex "0x0b000001")) (ForkVersion.Of(hex "0x00000001")) Root.Zero

                Expect.equal
                    ar.SigningRoot
                    (Signing.computeSigningRoot (Codec.hashBuilderRequestAuth auth) authDomain)
                    "builder request auth"
                // None of them is slashable; PTC votes and envelopes keep their stragglers.
                for d in [ r.Duty; pr.Duty; er.Duty; ar.Duty ] do
                    Expect.isFalse d.IsSlashable $"{d.Kind} is not slashable"

                Expect.isTrue r.Duty.KeepsStragglers "PTC votes reach every threshold member"
                Expect.isTrue er.Duty.KeepsStragglers "envelopes reach every threshold member"
                Expect.isFalse pr.Duty.KeepsStragglers "preferences stop at m"
                // Gloas due times.
                Expect.equal (spec.AttestationDue 16UL) (TimeSpan.FromSeconds 1.5) "attestation at 25%"
                Expect.equal (spec.AggregateDueAt 16UL) (TimeSpan.FromSeconds 3.0) "aggregate at 50%"
                Expect.equal (spec.AggregateDueAt 8UL) spec.AggregateDue "Fulu aggregate due before the fork"
                Expect.equal spec.PayloadAttestationDue (TimeSpan.FromSeconds 4.5) "PTC due at 75%"
            }

            test "the Gloas aggregate root differs from the Electra root for the same bytes" {
                let p = Preset.Minimal
                let att = Ssz.zero (Schemas.attestation p)
                let msg = Ssz.Fields [| Ssz.U 3UL; att; Ssz.Bytes(Array.zeroCreate 96) |]
                let electra = Ssz.hashTreeRoot (Schemas.aggregateAndProof p) msg
                let gloas = Ssz.hashTreeRoot (Schemas.Gloas.aggregateAndProof p) msg

                Expect.equal
                    (Ssz.serialize (Schemas.aggregateAndProof p) msg)
                    (Ssz.serialize (Schemas.Gloas.aggregateAndProof p) msg)
                    "same bytes"

                Expect.notEqual electra gloas "different root"
            }

            testT
                "PTC votes wait for execution_payload_available and sign the data under DOMAIN_PTC_ATTESTER"
                (fun () ->
                    task {
                        let h = gloasHarness 1UL
                        addValidators h
                        h.Node.PtcSlots[9UL] <- [| 2UL; 5UL |]
                        let r = start h Settings.Default None true
                        do! h.RunSlots(0UL, 9UL)
                        do! Task.Delay 200
                        Expect.isEmpty (posts h "payload_attestations") "no vote before the payload is available"
                        h.Node.EmitPayloadAvailable 9UL

                        do!
                            waitForLog r.Lines "PTC votes" (fun () ->
                                not (List.isEmpty (posts h "payload_attestations")))

                        do! r.Stop()
                        let votes = posts h "payload_attestations" |> List.collect jsonItems

                        Expect.equal
                            (votes |> List.map (fun v -> v.GetProperty("validator_index").GetString()) |> List.sort)
                            [ "2"; "5" ]
                            "the two PTC members"

                        let domain = Signing.computeDomain h.Spec.DomainPtcAttester gloasVersion gvr

                        for v in votes do
                            let data = Decoders.payloadAttestationDataOf (v.GetProperty "data")
                            Expect.equal data.Slot 9UL "slot"
                            Expect.equal data.BeaconBlockRoot (h.Node.BlockRoot 9UL) "block root"
                            let index = UInt64.Parse(v.GetProperty("validator_index").GetString())
                            let s = BlsSignature.TryParse(v.GetProperty("signature").GetString()) |> ValueOption.get

                            Expect.isTrue
                                (verify
                                    (pubkeyOf (int index))
                                    (Signing.computeSigningRoot (Codec.hashPayloadAttestationData data) domain)
                                    s)
                                "signature over the data"

                        Expect.contains (List.ofSeq r.Gloas.Events) (PayloadAttested(9UL, 2)) "event"
                    })

            testT "execution_payload_available for a slot far from the clock's slot keeps no signal" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    let r = start h Settings.Default None false
                    do! h.RunSlots(0UL, 9UL)

                    let emit (slot: uint64) =
                        r.Gloas.Extension.OnEvent
                            {
                                Event = "execution_payload_available"
                                Data = $"""{{"slot":"{slot}","block_root":"{(h.Node.BlockRoot 9UL).Hex}"}}"""
                            }

                    for s in 1000UL .. 1099UL do
                        emit s

                    emit 3UL
                    emit 10UL
                    let kept = r.Gloas.SignalSlots
                    do! r.Stop()
                    Expect.isFalse (kept |> List.exists (fun s -> s > 10UL)) $"no far-future slot kept: {kept}"
                    Expect.isFalse (List.contains 3UL kept) "nor a past one"
                    Expect.contains kept 10UL "the next slot is kept"
                })

            // PTC duties answered with execution_optimistic are used, with the same WARN
            // as the scheduler's duties. Before, nodes.Call used them silently.
            testT "PTC duties from an optimistic node are used with a warning" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.OptimisticDuties <- true
                    h.Node.PtcSlots[9UL] <- [| 2UL |]
                    let r = start h Settings.Default None true
                    do! h.RunSlots(0UL, 9UL)

                    do!
                        waitForLog r.Lines "the PTC duties warning" (fun () ->
                            r.Lines
                            |> Seq.exists (fun l ->
                                l.StartsWith "WARN" && l.Contains "PTC duties come from an optimistic beacon node"))

                    h.Node.EmitPayloadAvailable 9UL

                    do!
                        waitForLog r.Lines "the PTC vote" (fun () ->
                            not (List.isEmpty (posts h "payload_attestations")))

                    do! r.Stop()
                })

            testT
                "without the event the PTC vote goes out at 70% of the slot; a slot with no block gets none"
                (fun () ->
                    task {
                        let h = gloasHarness 1UL
                        addValidators h
                        h.Node.PtcSlots[10UL] <- [| 1UL |]
                        h.Node.PtcSlots[11UL] <- [| 2UL |]
                        h.Node.NoBlockSlots <- Set.ofList [ 11UL ]
                        let r = start h Settings.Default None false
                        do! h.RunSlots(0UL, 10UL)
                        advanceTo h (h.Clock.SlotStart 10UL + h.Spec.Bps 6900UL)
                        do! Task.Delay 200
                        Expect.isEmpty (posts h "payload_attestations") "not before 70%"
                        advanceTo h (h.Clock.SlotStart 10UL + h.Spec.Bps 7000UL + TimeSpan.FromMilliseconds 1.0)

                        do!
                            waitForLog r.Lines "the PTC vote of slot 10" (fun () ->
                                not (List.isEmpty (posts h "payload_attestations")))

                        do! h.RunSlots(11UL, 11UL)
                        advanceTo h (h.Clock.SlotStart 11UL + h.Spec.Bps 7100UL)

                        do!
                            waitForLog r.Lines "the no-block log line" (fun () ->
                                r.Lines |> Seq.exists (fun l -> l.Contains "slot 11: the node saw no block"))

                        do! r.Stop()
                        let votes = posts h "payload_attestations" |> List.collect jsonItems
                        Expect.equal votes.Length 1 "one vote, for slot 10 only"
                    })

            testT "a Gloas proposal: produceBlockV4, the block, then the signed envelope with its blobs" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[4UL] <- 5UL
                    h.Node.Proposals[10UL] <- 3UL
                    let r = start h Settings.Default None false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    let blocks = List.ofSeq h.Node.Published

                    Expect.equal
                        (blocks |> List.map (fun (v, _, _) -> v))
                        [ "electra"; "gloas" ]
                        "produceBlockV3 before the fork, V4 after"

                    Expect.equal
                        (List.ofSeq h.Node.PublishOrder)
                        [ "block"; "block"; "envelope" ]
                        "the envelope after its block"

                    let _, contentType, bytes = blocks[1]
                    Expect.equal contentType "application/octet-stream" "SSZ"
                    let signed = signedBlockOf h bytes
                    let block = Codec.fields (Codec.fields signed).[0]

                    let header =
                        {
                            Slot = Codec.asU block[0]
                            ProposerIndex = Codec.asU block[1]
                            ParentRoot = Root.Of(Codec.asBytes block[2])
                            StateRoot = Root.Of(Codec.asBytes block[3])
                            BodyRoot = Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.beaconBlockBody h.Node.Preset) block[4])
                        }

                    let proposer = pubkeyOf 3
                    let blockDomain = Signing.computeDomain h.Spec.DomainBeaconProposer gloasVersion gvr
                    let blockRoot = Codec.hashBeaconBlockHeader header

                    Expect.isTrue
                        (verify
                            proposer
                            (Signing.computeSigningRoot blockRoot blockDomain)
                            (BlsSignature.Of(Codec.asBytes (Codec.fields signed).[1])))
                        "block signature"

                    Expect.equal (bidOfSigned signed).BuilderIndex UInt64.MaxValue "self-build bid"

                    Expect.equal
                        (r.Db.Marks proposer).Value.Block.Value.Slot
                        10UL
                        "the block went through slashing protection"

                    let included, envType, envBytes = Seq.head h.Node.PublishedEnvelopes
                    Expect.equal included "true" "stateless: blobs with the envelope"
                    Expect.equal envType "application/octet-stream" "SSZ"

                    match
                        Ssz.deserialize (Schemas.Gloas.signedExecutionPayloadEnvelopeContents h.Node.Preset) envBytes
                    with
                    | Error e -> failtestf "envelope does not decode: %s" e
                    | Ok v ->
                        let signedEnv = Codec.fields (Codec.fields v).[0]
                        let env = signedEnv[0]

                        Expect.equal
                            (Root.Of(Codec.asBytes (Codec.fields env).[3]))
                            blockRoot
                            "envelope names the block"

                        let envRoot =
                            Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.executionPayloadEnvelope h.Node.Preset) env)

                        let domain = Signing.computeDomain h.Spec.DomainBeaconBuilder gloasVersion gvr

                        Expect.isTrue
                            (verify
                                proposer
                                (Signing.computeSigningRoot envRoot domain)
                                (BlsSignature.Of(Codec.asBytes signedEnv[1])))
                            "envelope signed by the proposer under DOMAIN_BEACON_BUILDER"

                    let config = Seq.head h.Node.BuilderConfigs
                    Expect.stringContains config "\"builder_boost_factor\":\"100\"" "p2p bids weighed"
                    Expect.stringContains config "\"builders\":[]" "no builder module"
                })

            testT "include_payload false: the envelope comes from the node that built it" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.BlockAsJson <- true
                    h.Node.Proposals[10UL] <- 3UL

                    let r =
                        start
                            h
                            { Settings.Default with
                                IncludePayload = false
                            }
                            None
                            false

                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()

                    Expect.isTrue
                        (h.Node.Requests
                         |> Seq.exists (fun x -> x.StartsWith "GET /eth/v1/validator/execution_payload_envelopes/10/"))
                        "fetched the envelope"

                    let included, _, bytes = Seq.head h.Node.PublishedEnvelopes
                    Expect.equal included "false" "stateful: the node holds the blobs"

                    Expect.isOk
                        (Ssz.deserialize (Schemas.Gloas.signedExecutionPayloadEnvelope h.Node.Preset) bytes)
                        "a SignedExecutionPayloadEnvelope"
                })

            testT "a p2p bid paying another fee recipient is not signed; the VC asks for a local block" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some(hex "0x00000000000000000000000000000000000000bb")
                    let r = start h Settings.Default None false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    let configs = List.ofSeq h.Node.BuilderConfigs
                    Expect.equal configs.Length 2 "asked twice"

                    Expect.stringContains
                        configs[1]
                        "\"builder_boost_factor\":\"0\""
                        "the second time for a local block"

                    let _, _, bytes = Seq.last h.Node.Published
                    Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex UInt64.MaxValue "self-built"
                })

            testT "a p2p bid under p2p_min_bid is not signed, whatever execution payment it promises" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BuilderBidValue <- 0UL
                    h.Node.BuilderBidExecutionPayment <- 1_000_000_000UL

                    let r =
                        start
                            h
                            { Settings.Default with
                                P2pMinBid = 1UL
                            }
                            None
                            false

                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    Expect.equal (List.ofSeq h.Node.BuilderConfigs).Length 2 "asked again for a local block"
                    let _, _, bytes = Seq.last h.Node.Published
                    Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex UInt64.MaxValue "self-built"
                })

            testT "a p2p bid to the key's fee recipient is signed; the builder publishes the envelope" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    let r = start h Settings.Default None false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! Task.Delay 200
                    do! r.Stop()
                    let _, _, bytes = Seq.last h.Node.Published
                    let bid = bidOfSigned (signedBlockOf h bytes)
                    Expect.equal bid.BuilderIndex 7UL "the builder's bid"
                    Expect.equal h.Node.PublishedEnvelopes.Count 0 "no envelope from the VC"
                    Expect.isEmpty (List.ofSeq h.Node.BuilderUrls) "a p2p bid: no Eth-Builder-Url"
                })

            testT "proposer preferences one epoch before the fork, under the Gloas fork version, once" (fun () ->
                task {
                    let h = gloasHarness 2UL
                    addValidators h
                    h.Node.Proposals[17UL] <- 4UL
                    let r = start h Settings.Default None false
                    do! h.RunSlots(0UL, 10UL)

                    do!
                        waitForLog r.Lines "proposer preferences" (fun () ->
                            not (List.isEmpty (posts h "proposer_preferences")))

                    do! h.RunSlots(11UL, 12UL)
                    do! r.Stop()
                    let sent = posts h "proposer_preferences" |> List.collect jsonItems
                    Expect.equal sent.Length 1 "one message for slot 17, not one per slot"
                    let m = sent.Head.GetProperty "message"
                    let p = Codec.proposerPreferencesOf (SszJson.read Schemas.Gloas.proposerPreferences m)
                    Expect.equal p.ProposalSlot 17UL "slot"
                    Expect.equal p.ValidatorIndex 4UL "index"
                    Expect.equal p.DependentRoot (h.Node.DependentRoot 2UL) "dependent root of the proposer duties"
                    Expect.equal p.FeeRecipient fee "fee recipient"
                    Expect.equal p.TargetGasLimit 60_000_000UL "gas limit"
                    let s = BlsSignature.TryParse(sent.Head.GetProperty("signature").GetString()) |> ValueOption.get
                    let domain = Signing.computeDomain h.Spec.DomainProposerPreferences gloasVersion gvr

                    Expect.isTrue
                        (verify (pubkeyOf 4) (Signing.computeSigningRoot (Codec.hashProposerPreferences p) domain) s)
                        "signature"
                })

            testT
                "builder module: request auth per builder, builder preferences, a won bid echoes Eth-Builder-Url"
                (fun () ->
                    task {
                        let h = gloasHarness 1UL
                        addValidators h
                        h.Node.Proposals[10UL] <- 3UL
                        h.Node.BuilderBid <- Some fee
                        h.Node.BuilderBidValue <- 50UL
                        let r = start h Settings.Default (Some(builderSettings 10UL)) false
                        do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                        do! r.Stop()
                        let prefs = posts h "builder_preferences" |> List.collect jsonItems
                        Expect.equal prefs.Length 1 "one builder, one proposal"
                        let e = prefs.Head
                        Expect.equal (e.GetProperty("url").GetString()) "https://builder.test" "url"
                        Expect.equal (e.GetProperty("proposer_pubkey").GetString()) (pubkeyOf 3).Hex "proposer"
                        let msg = e.GetProperty("auth").GetProperty("message")

                        let auth =
                            {
                                AuthData = hex (msg.GetProperty("data").GetString())
                                AuthSlot = UInt64.Parse(msg.GetProperty("slot").GetString())
                            }

                        Expect.equal
                            auth.AuthData
                            (Text.Encoding.UTF8.GetBytes "builder.test")
                            "default auth data: the host name"

                        Expect.equal auth.AuthSlot 10UL "the proposal slot"

                        let s =
                            BlsSignature.TryParse(e.GetProperty("auth").GetProperty("signature").GetString())
                            |> ValueOption.get

                        let domain =
                            Signing.computeDomain h.Spec.DomainBuilderRequestAuth h.Spec.GenesisForkVersion Root.Zero

                        Expect.isTrue
                            (verify
                                (pubkeyOf 3)
                                (Signing.computeSigningRoot (Codec.hashBuilderRequestAuth auth) domain)
                                s)
                            "auth signature"

                        let config = Seq.head h.Node.BuilderConfigs

                        Expect.stringContains
                            config
                            "\"url\":\"https://builder.test\""
                            "the builder in the BuilderConfig"

                        Expect.stringContains
                            config
                            (e.GetProperty("auth").GetProperty("signature").GetString())
                            "the auth signed ahead is reused"

                        Expect.equal
                            (List.ofSeq h.Node.BuilderUrls)
                            [ "https://builder.test" ]
                            "Eth-Builder-Url echoed"

                        let _, _, bytes = Seq.last h.Node.Published
                        Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex 7UL "the builder's bid"
                    })

            // The pipeline refuses a key in doppelganger wait with PolicyDenied. That refusal must
            // not shut the key out of the builders for the life of the process.
            testT "builder module: a key in doppelganger wait at prepare time gets its auth once active" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BuilderBidValue <- 50UL

                    let r =
                        startHeld
                            (fun k -> k = pubkeyOf 3)
                            id
                            (ValueSome feeHex)
                            h
                            Settings.Default
                            (Some(builderSettings 10UL))
                            false

                    do! h.RunSlots(0UL, 7UL)

                    do!
                        waitForLog r.Lines "key 3 in doppelganger wait" (fun () ->
                            (r.Registry.TryGet(pubkeyOf 3) |> ValueOption.map (fun k -> k.State)) =
                                ValueSome KeyState.DoppelgangerWait)

                    Expect.isEmpty (posts h "builder_preferences") "no preferences while the key waits"
                    r.Registry.SetState(pubkeyOf 3, KeyState.Active)

                    for s in 8UL .. 10UL do
                        let before = h.Node.Published.Count
                        do! h.RunSlots(s, s)

                        if s = 10UL then
                            do!
                                waitForLog r.Lines "the proposal of slot 10" (fun () ->
                                    h.Node.Published.Count > before)

                    do! r.Stop()
                    let prefs = posts h "builder_preferences" |> List.collect jsonItems
                    Expect.equal prefs.Length 1 "preferences sent once the key is active"
                    Expect.equal (prefs.Head.GetProperty("proposer_pubkey").GetString()) (pubkeyOf 3).Hex "proposer"
                    Expect.equal (List.ofSeq h.Node.BuilderUrls) [ "https://builder.test" ] "the builder's bid won"
                })

            testT "builder module: a bid below the builder's minimum is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BuilderBidValue <- 5UL
                    let r = start h Settings.Default (Some(builderSettings 10UL)) false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    Expect.equal h.Node.BuilderConfigs.Count 2 "asked again"
                    let _, _, bytes = Seq.last h.Node.Published
                    Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex UInt64.MaxValue "self-built"
                    Expect.isTrue (r.Lines |> Seq.exists (fun l -> l.Contains "below its minimum")) "logged"
                })

            testT "a self-build bid paying another fee recipient is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.SelfBuildFeeRecipient <- Some(hex "0x00000000000000000000000000000000000000bb")
                    let r = start h Settings.Default None false
                    let! why = proposalFails h r 10UL 10UL
                    do! r.Stop()
                    Expect.stringContains why "not the key's fee recipient" "reason"
                    Expect.equal h.Node.BuilderConfigs.Count 2 "asked again for a local block, which pays the same"

                    Expect.isEmpty
                        (h.Node.Published |> Seq.filter (fun (v, _, _) -> v = "gloas") |> List.ofSeq)
                        "no block signed"

                    Expect.equal h.Node.PublishedEnvelopes.Count 0 "no envelope"

                    Expect.isTrue
                        (r.Db.Marks(pubkeyOf 3).IsNone || (r.Db.Marks(pubkeyOf 3)).Value.Block.IsNone)
                        "no block mark"
                })

            testT "a self-built envelope paying another fee recipient is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.EnvelopeFeeRecipient <- Some(hex "0x00000000000000000000000000000000000000bb")
                    let r = start h Settings.Default None false
                    let! why = proposalFails h r 10UL 10UL
                    do! r.Stop()
                    Expect.stringContains why "the envelope pays 0x00000000000000000000000000000000000000bb" "reason"

                    Expect.equal
                        (bidOfSigned (signedBlockOf h (let _, _, b = Seq.last h.Node.Published in b))).FeeRecipient
                        fee
                        "the block's bid pays the key"

                    Expect.equal h.Node.PublishedEnvelopes.Count 0 "no envelope signed"
                })

            testT "a self-built envelope with another block hash than the bid is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.EnvelopeBlockHash <- Some(Array.create 32 0x43uy)

                    let r =
                        start
                            h
                            { Settings.Default with
                                IncludePayload = false
                            }
                            None
                            false

                    let! why = proposalFails h r 10UL 10UL
                    do! r.Stop()
                    Expect.stringContains why "block hash" "reason"
                    Expect.equal h.Node.PublishedEnvelopes.Count 0 "no envelope signed"
                })

            testList
                "a self-built envelope that differs from the bid is not signed"
                [
                    for name, set in
                        [
                            "gas limit", (fun (n: FakeBeaconNode) -> n.EnvelopeGasLimit <- Some 30_000_000UL)
                            "parent hash", (fun n -> n.EnvelopeParentHash <- Some(Array.create 32 0x51uy))
                            "prev_randao", (fun n -> n.EnvelopePrevRandao <- Some(Array.create 32 0x54uy))
                        ] ->
                        testT name (fun () ->
                            task {
                                let h = gloasHarness 1UL
                                addValidators h
                                h.Node.Proposals[10UL] <- 3UL
                                set h.Node
                                let r = start h Settings.Default None false
                                let! why = proposalFails h r 10UL 10UL
                                do! r.Stop()

                                Expect.stringContains
                                    why
                                    "gas limit, parent hash or prev_randao is not the bid's"
                                    "reason"

                                Expect.equal h.Node.PublishedEnvelopes.Count 0 "no envelope signed"
                            })
                ]

            testT "a key with no fee recipient, not even the default, still proposes self-built" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    let r = startWith ValueNone h Settings.Default None false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    let _, _, bytes = Seq.last h.Node.Published

                    Expect.equal
                        (bidOfSigned (signedBlockOf h bytes)).BuilderIndex
                        UInt64.MaxValue
                        "self-built block signed"

                    Expect.equal h.Node.PublishedEnvelopes.Count 1 "envelope signed"
                })

            testT "a fee recipient that is not an address gets no block signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    // The node builds a block that pays some address; the key's own does not decode.
                    h.Node.SelfBuildFeeRecipient <- Some fee
                    let r = startWith (ValueSome "0x1234") h Settings.Default None false
                    let! why = proposalFails h r 10UL 10UL
                    do! r.Stop()
                    Expect.stringContains why "is not a 20-byte address" "reason"

                    Expect.isEmpty
                        (h.Node.Published |> Seq.filter (fun (v, _, _) -> v = "gloas") |> List.ofSeq)
                        "no block signed"
                })

            testT "builder module: a request auth that times out once is tried again, not given up for good" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BuilderBidValue <- 50UL
                    // The first builder request auth times out; the signer answers after that.
                    let failures = [| 1 |]

                    let wrap (b: Backend) =
                        { b with
                            Sign =
                                fun req ct ->
                                    match req.Duty with
                                    | Duty.BuilderRequestAuth _ when Interlocked.Decrement(&failures[0]) >= 0 ->
                                        Task.FromResult(Failed SignFailure.Timeout)
                                    | _ -> b.Sign req ct
                        }

                    let r = startWrapped wrap (ValueSome feeHex) h Settings.Default (Some(builderSettings 10UL)) false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! r.Stop()
                    Expect.isLessThan failures[0] 1 "the timeout happened"

                    Expect.equal
                        (posts h "builder_preferences" |> List.collect jsonItems).Length
                        1
                        "builder preferences sent once the signer answers"

                    Expect.isTrue
                        (r.Lines
                         |> Seq.exists (fun l -> l.Contains "builder request auth of" && l.Contains "tried again"))
                        "logged"
                })

            testT "builder module: a group denial with a member down is tried again, not parked" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BuilderBidValue <- 50UL
                    // A 2 of 3 group: one member denies, one does not answer. The next try signs.
                    let failures = [| 1 |]

                    let groupDenied =
                        Refused(
                            Denied(
                                "2 of 3 signatures needed",
                                {
                                    Signed = 1
                                    Denied = 1
                                    Failed = 0
                                    Errored = 1
                                }
                            )
                        )

                    let wrap (b: Backend) =
                        { b with
                            Sign =
                                fun req ct ->
                                    match req.Duty with
                                    | Duty.BuilderRequestAuth _ when Interlocked.Decrement(&failures[0]) >= 0 ->
                                        Task.FromResult groupDenied
                                    | _ -> b.Sign req ct
                        }

                    let r = startWrapped wrap (ValueSome feeHex) h Settings.Default (Some(builderSettings 10UL)) false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! r.Stop()
                    Expect.isLessThan failures[0] 1 "the group denial happened"

                    Expect.isFalse
                        (r.Lines |> Seq.exists (fun l -> l.Contains "p2p bids and self-build only"))
                        "not parked"

                    Expect.equal
                        (posts h "builder_preferences" |> List.collect jsonItems).Length
                        1
                        "builder preferences sent once the group signs"
                })

            testList
                "builder module: a signer that refuses request auth for good is asked once"
                [
                    for name, refusal in
                        [
                            "web3signer 400", Refused(BadRequest "unknown type BUILDER_REQUEST_AUTH")
                            "dirk denied",
                            Refused(
                                Denied(
                                    "denied",
                                    {
                                        Signed = 0
                                        Denied = 1
                                        Failed = 0
                                        Errored = 0
                                    }
                                )
                            )
                        ] ->
                        testT name (fun () ->
                            task {
                                let h = gloasHarness 1UL
                                addValidators h
                                h.Node.Proposals[10UL] <- 3UL
                                let asked = ref 0

                                let wrap (b: Backend) =
                                    { b with
                                        Sign =
                                            fun req ct ->
                                                match req.Duty with
                                                | Duty.BuilderRequestAuth _ ->
                                                    Interlocked.Increment &asked.contents |> ignore
                                                    Task.FromResult refusal
                                                | _ -> b.Sign req ct
                                    }

                                let r =
                                    startWrapped
                                        wrap
                                        (ValueSome feeHex)
                                        h
                                        Settings.Default
                                        (Some(builderSettings 10UL))
                                        false

                                do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                                do! r.Stop()
                                Expect.equal asked.Value 1 "asked once, then the key is parked"

                                Expect.isTrue
                                    (r.Lines |> Seq.exists (fun l -> l.Contains "p2p bids and self-build only"))
                                    "parked, logged"

                                Expect.isTrue (r.Registry.Denials(pubkeyOf 3) <= 1L) "at most one denial counted"
                                Expect.isEmpty (posts h "builder_preferences") "no builder preferences"
                                Expect.isGreaterThan h.Node.Published.Count 0 "the block is still proposed"
                            })
                ]

            testT "a bid on another parent block is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BidParentRoot <- Some(root 77)
                    let r = start h Settings.Default None false
                    let! why = proposalFails h r 10UL 10UL
                    do! r.Stop()
                    Expect.stringContains why "the bid builds on block" "reason"

                    Expect.isEmpty
                        (h.Node.Published |> Seq.filter (fun (v, _, _) -> v = "gloas") |> List.ofSeq)
                        "no block signed"
                })

            testT "builder module: a bid signed by a key in builder_pubkeys is signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BidSigner <- Some(signBid h 40)
                    let r = start h Settings.Default (Some(builderWithKeys [ pubkeyOf 41; pubkeyOf 40 ])) false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! r.Stop()
                    Expect.equal h.Node.BuilderConfigs.Count 1 "asked once"
                    let _, _, bytes = Seq.last h.Node.Published
                    Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex 7UL "the builder's bid"
                })

            testT "builder module: a bid not signed by a key in builder_pubkeys is not signed" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.Proposals[10UL] <- 3UL
                    h.Node.BuilderBid <- Some fee
                    h.Node.BidSigner <- Some(signBid h 42)
                    let r = start h Settings.Default (Some(builderWithKeys [ pubkeyOf 40 ])) false
                    do! runProposals h r 10UL (fun () -> h.Node.Published.Count)
                    do! waitForLog r.Lines "the envelope of slot 10" (fun () -> h.Node.PublishedEnvelopes.Count > 0)
                    do! r.Stop()
                    Expect.equal h.Node.BuilderConfigs.Count 2 "asked again"
                    let _, _, bytes = Seq.last h.Node.Published
                    Expect.equal (bidOfSigned (signedBlockOf h bytes)).BuilderIndex UInt64.MaxValue "self-built"

                    Expect.isTrue
                        (r.Lines |> Seq.exists (fun l -> l.Contains "is not signed by a key in its builder_pubkeys"))
                        "logged"
                })

            testT "aggregates in a Gloas epoch sign the progressive AggregateAndProof root" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    addValidators h
                    h.Node.CommitteeLength <- 8UL
                    let r = start h Settings.Default None false
                    do! h.RunSlots(0UL, 8UL)
                    advanceTo h (h.Clock.SlotStart 8UL + h.Spec.AggregateDueAt 8UL + TimeSpan.FromMilliseconds 1.0)

                    let atSlot8 () =
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
                                "8")

                    do! waitForLog r.Lines "the aggregate of slot 8" (fun () -> not (List.isEmpty (atSlot8 ())))
                    do! r.Stop()
                    let schema = Schemas.Gloas.signedAggregateAndProof h.Node.Preset

                    for a in atSlot8 () do
                        let v = SszJson.read schema a
                        let f = Codec.fields v
                        let index = Codec.asU (Codec.fields f[0]).[0]
                        let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.Gloas.aggregateAndProof h.Node.Preset) f[0])
                        let domain = Signing.computeDomain h.Spec.DomainAggregateAndProof gloasVersion gvr

                        Expect.isTrue
                            (verify
                                (pubkeyOf (int index))
                                (Signing.computeSigningRoot msgRoot domain)
                                (BlsSignature.Of(Codec.asBytes f[1])))
                            "Gloas root"
                })

            testT "the whole VC: a Gloas chain needs the Gloas module, and runs with it" (fun () ->
                task {
                    let h = gloasHarness 1UL
                    let dir = tempDir ()
                    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        File.WriteAllText(
                            Path.Combine(ksDir, $"keystore-{i}.json"),
                            Keystore.encrypt
                                (secretOf i)
                                "secret"
                                (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32))
                                ""
                        )

                    h.Node.PtcSlots[9UL] <- [| 1UL |]
                    File.WriteAllText(Path.Combine(dir, "password.txt"), "secret\n")

                    File.WriteAllText(
                        Path.Combine(dir, "chain.yaml"),
                        configYamlGloas secondsPerSlot slotsPerEpoch 1UL
                    )

                    let configOf (gloas: bool) =
                        let section =
                            if gloas then """, "gloas": { "include_payload": true, "p2p_min_bid": "0" }""" else ""

                        """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                       "use_events": false, "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ] }"""
                        + section
                        + " } }"

                    let runWith (modules: Module list) =
                        let configText = configOf (modules |> List.exists (fun m -> m.Name = "gloas"))

                        match
                            Config.parse configText dir (modules |> List.map (fun m -> m.Name))
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok config ->
                            let cts = new CancellationTokenSource()
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

                            run, cts, lines

                    let refused, _, _ = runWith [ LocalModule.create () ]
                    let! r1 = refused

                    Expect.equal
                        r1
                        (Error "the chain schedules Gloas, and this build has no Gloas duties module")
                        "refused without the module"

                    let run, cts, lines = runWith [ LocalModule.create (); GloasModule.create () ]
                    do! h.RunSlots(0UL, 9UL)
                    advanceTo h (h.Clock.SlotStart 9UL + h.Spec.Bps 7100UL)

                    do!
                        waitForLog lines "the PTC vote through the whole VC" (fun () ->
                            not (List.isEmpty (posts h "payload_attestations")))

                    cts.Cancel()
                    let! result = run
                    Expect.isOk result $"run; log: {String.Join('\n', lines)}"

                    Expect.equal
                        h.Node.Submissions.Count
                        6
                        "attestations in both forks: 4 in epoch 0, slots 8 and 9 of epoch 1"

                    Expect.isTrue
                        (h.Node.Submissions |> Seq.exists (fun s -> s.ConsensusVersion = "gloas"))
                        "Gloas attestations"
                })
        ]
