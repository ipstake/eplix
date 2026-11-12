/// The pre-Gloas builder flow (the legacy builder module): validator registrations, the boost
/// factor, blinded blocks and the fallback to a local block, over fake beacon nodes.
module Eplix.Tests.BuilderLegacyTests

open System
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.BuilderLegacy
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let private on =
    { LegacyBuilderModule.Settings.Default with
        Enabled = true
    }

/// The module's extension over the harness's core, keeping the Registrations for the test.
let private legacy (settings: LegacyBuilderModule.Settings) (held: LegacyBuilderModule.Registrations option ref) =
    fun (core: CoreServices) ->
        let r = LegacyBuilderModule.Registrations(core, settings)
        held.Value <- Some r
        r.Extension

let private registrationDomain (spec: ChainSpec) =
    Signing.computeDomain spec.DomainApplicationBuilder spec.GenesisForkVersion Root.Zero

/// The registrations of one register_validator body, each with its signature checked.
let private registrationsOf (spec: ChainSpec) (body: string) =
    [
        for x in jsonItems body ->
            let v = SszJson.read Schemas.signedValidatorRegistration x
            let f = Codec.fields v
            let m = Codec.fields f[0]

            let r: ValidatorRegistration =
                {
                    FeeRecipient = Codec.asBytes m[0]
                    GasLimit = Codec.asU m[1]
                    Timestamp = Codec.asU m[2]
                    PubKey = PubKey.Of(Codec.asBytes m[3])
                }

            let s = BlsSignature.Of(Codec.asBytes f[1])
            let root = Signing.computeSigningRoot (Codec.hashValidatorRegistration r) (registrationDomain spec)
            Expect.isTrue (verifySig r.PubKey root s) $"registration signature of {r.PubKey.Short}"
            r
    ]

let private feeB = "0x00000000000000000000000000000000000000bb"

let private domainAndSignature () =
    task {
        let h = harness ()

        let r: ValidatorRegistration =
            {
                FeeRecipient = hex feeHex
                GasLimit = 60_000_000UL
                Timestamp = 1_700_000_100UL
                PubKey = pubkeyOf 1
            }

        let req =
            Duty.request h.Spec gvr (pubkeyOf 1) Priority.Low DateTimeOffset.MaxValue (Duty.ValidatorRegistration r)
        // builder-specs compute_builder_domain: DOMAIN_APPLICATION_BUILDER, the genesis fork
        // version and a zero genesis validators root, whatever fork the chain is in.
        Expect.equal h.Spec.DomainApplicationBuilder.Bytes [| 0uy; 0uy; 0uy; 1uy |] "domain type 0x00000001"
        Expect.equal req.Domain (registrationDomain h.Spec) "the builder domain"

        Expect.notEqual
            req.Domain
            (Signing.computeDomain h.Spec.DomainApplicationBuilder h.Spec.GenesisForkVersion gvr)
            "not under the chain's root"

        Expect.equal
            req.SigningRoot
            (Signing.computeSigningRoot (Codec.hashValidatorRegistration r) req.Domain)
            "signing root"

        Expect.equal (Duty.ValidatorRegistration r).IsSlashable false "not slashable"
        let backend = LocalBackend.create "local" [ pubkeyOf 1, SecretKey.Copy(ReadOnlySpan(secretOf 1)) ]

        match! backend.Sign req CancellationToken.None with
        | Signed s -> Expect.isTrue (verifySig (pubkeyOf 1) req.SigningRoot s) "the local key signs it"
        | o -> failtestf "local: %s" o.Describe
    }

/// Eight keys, two nodes, batches of three: each epoch every node gets three requests with the
/// eight registrations, signed once. A changed fee recipient re-signs that key alone.
let private registrationsCachedAndBatched () =
    task {
        let h = harness ()
        let n2 = extraNode h
        addValidators [ h.Node; n2 ] 8
        let held = ref None

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ n2 ]
                    Extensions = [ legacy { on with BatchSize = 3 } held ]
                }

        let regs () = held.Value.Value
        do! h.RunSlots(0UL, 1UL)

        do!
            waitUntil vc "the first registrations" (fun () ->
                h.Node.Registrations.Count = 3 && n2.Registrations.Count = 3)

        Expect.equal (regs ()).Signings 8L "eight registrations signed"

        let first =
            [
                for b in h.Node.Registrations do
                    yield! registrationsOf h.Spec b
            ]

        Expect.equal (first |> List.map _.PubKey |> set) (set [ for i in 0..7 -> pubkeyOf i ]) "every key registered"

        for r in first do
            Expect.equal (Hex.encodeArray r.FeeRecipient) feeHex "the default fee recipient"
            Expect.equal r.GasLimit 60_000_000UL "the default gas limit"
        // Epoch 1: the cached signatures go again.
        do! h.RunSlots(2UL, 9UL)

        do!
            waitUntil vc "the epoch 1 registrations" (fun () ->
                h.Node.Registrations.Count = 6 && n2.Registrations.Count = 6)

        Expect.equal (regs ()).Signings 8L "cache hits: nothing signed again"

        let second =
            [
                for b in Seq.skip 3 h.Node.Registrations do
                    yield! registrationsOf h.Spec b
            ]

        Expect.equal
            (second |> List.sortBy _.PubKey.Hex)
            (first |> List.sortBy _.PubKey.Hex)
            "the same registrations, timestamps included"
        // A new fee recipient and a new gas limit for key 2: re-signed in epoch 2, the rest cached.
        vc.Registry.SetSettings(
            pubkeyOf 2,
            fun s ->
                { s with
                    FeeRecipient = ValueSome feeB
                    GasLimit = ValueSome 36_000_000UL
                }
        )

        do! h.RunSlots(10UL, 17UL)
        do! waitUntil vc "the epoch 2 registrations" (fun () -> h.Node.Registrations.Count = 9)
        do! vc.Stop()
        Expect.equal (regs ()).Signings 9L "one registration signed again"

        let third =
            [
                for b in Seq.skip 6 h.Node.Registrations do
                    yield! registrationsOf h.Spec b
            ]

        let k2 = third |> List.find (fun r -> r.PubKey = pubkeyOf 2)
        Expect.equal (Hex.encodeArray k2.FeeRecipient) feeB "the new fee recipient"
        Expect.equal k2.GasLimit 36_000_000UL "the new gas limit"
        Expect.equal third.Length 8 "still eight"
    }

/// Keys with the builder flow off are not registered and propose with a factor of 0.
let private perKeySettings () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Proposals[4UL] <- 3UL
        h.Node.Proposals[5UL] <- 5UL
        h.Node.BuilderBlocks <- true
        let held = ref None

        let vc =
            startVc
                h
                { defaults with
                    Extensions = [ legacy on held ]
                }

        vc.Registry.SetProposerFile
            { ProposerFile.Empty with
                Keys =
                    Map.ofList
                        [
                            pubkeyOf 3,
                            { KeySettings.Default with
                                BuilderBoostFactor = ValueSome 250UL
                            }
                            pubkeyOf 5,
                            { KeySettings.Default with
                                BuilderEnabled = ValueSome false
                            }
                        ]
            }

        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the builder block of key 3" (fun () -> h.Node.PublishedBlinded.Count = 1)
        do! h.RunSlots(5UL, 5UL)
        do! waitUntil vc "the local block of key 5" (fun () -> h.Node.Published.Count = 1)
        // The file may land after the epoch 0 registrations went out; epoch 1 follows it.
        let before = h.Node.Registrations.Count
        do! h.RunSlots(6UL, 9UL)
        do! waitUntil vc "the epoch 1 registrations" (fun () -> h.Node.Registrations.Count > before)
        do! vc.Stop()
        let factors = List.ofSeq h.Node.BoostFactors
        Expect.contains factors (4UL, 250UL) "key 3: its own factor"
        Expect.contains factors (5UL, 0UL) "key 5: builder off, a local block"
        let registered = registrationsOf h.Spec (Seq.last h.Node.Registrations) |> List.map _.PubKey |> set
        Expect.isFalse (registered.Contains(pubkeyOf 5)) "key 5 not registered"
        Expect.isTrue (registered.Contains(pubkeyOf 3)) "key 3 registered"
    }

/// A blinded answer: the header with the blinded body's root is signed (and recorded in the
/// slashing DB) and the signed blinded block goes to the blinded endpoint. JSON and SSZ.
let private blindedProposal () =
    task {
        for asJson in [ false; true ] do
            let h = harness ()
            addValidators [ h.Node ] 8
            h.Node.Proposals[4UL] <- 3UL
            h.Node.BuilderBlocks <- true
            h.Node.BlockAsJson <- asJson
            let held = ref None

            let vc =
                startVc
                    h
                    { defaults with
                        Extensions = [ legacy on held ]
                    }

            do! h.RunSlots(0UL, 4UL)
            do! waitUntil vc "the blinded block" (fun () -> h.Node.PublishedBlinded.Count = 1)
            do! vc.Stop()
            Expect.contains (List.ofSeq h.Node.BoostFactors) (4UL, 100UL) "the default factor"
            Expect.equal h.Node.Published.Count 0 "no full block"
            let version, contentType, bytes = h.Node.PublishedBlinded |> Seq.head
            Expect.equal version "electra" "consensus version of epoch 0"
            Expect.equal contentType "application/octet-stream" "SSZ"
            let p = h.Node.Preset

            match Ssz.deserialize (Schemas.signedBlindedBeaconBlock p) bytes with
            | Error e -> failtestf "decode: %s" e
            | Ok v ->
                let f = Codec.fields v
                let block = Codec.fields f[0]

                let header =
                    {
                        Slot = Codec.asU block[0]
                        ProposerIndex = Codec.asU block[1]
                        ParentRoot = Root.Of(Codec.asBytes block[2])
                        StateRoot = Root.Of(Codec.asBytes block[3])
                        BodyRoot = Root.Of(Ssz.hashTreeRoot (Schemas.blindedBeaconBlockBody p) block[4])
                    }

                Expect.equal header.Slot 4UL "slot"
                Expect.equal header.ProposerIndex 3UL "proposer"
                let payloadHeader = Codec.fields (Codec.fields block[4]).[9]

                Expect.equal
                    (Codec.asBytes payloadHeader[1])
                    h.Node.BuilderFeeRecipient
                    "the builder's payload, fee check skipped"

                let req = Duty.request h.Spec gvr (pubkeyOf 3) Priority.High DateTimeOffset.MaxValue (Duty.Block header)

                Expect.isTrue
                    (verifySig (pubkeyOf 3) req.SigningRoot (BlsSignature.Of(Codec.asBytes f[1])))
                    "the signature is over the block's header"

                match (vc.Db.Marks(pubkeyOf 3)) |> ValueOption.bind (fun m -> m.Block) with
                | ValueSome m -> Expect.equal m.Slot 4UL "the slashing DB recorded the proposal"
                | ValueNone -> failtest "no block mark"
    }

/// The blinded body's root is the full body's: a header root equals its payload's root.
let private blindedBodyRoot () =
    task {
        let p = (harness ()).Node.Preset
        let full = Ssz.zero (Schemas.beaconBlockBody p)
        let payload = Codec.fields (Codec.fields full).[9]
        payload[1] <- Ssz.Bytes(Array.create 20 7uy)
        payload[6] <- Ssz.U 99UL
        let payloadSchema = Schemas.executionPayload p
        let headerSchema = Schemas.executionPayloadHeader p
        let hp = Codec.fields (Ssz.zero headerSchema)

        let pf =
            match payloadSchema with
            | Ssz.Container fs -> fs
            | _ -> failwith "container"

        let hf =
            match headerSchema with
            | Ssz.Container fs -> fs
            | _ -> failwith "container"

        for i in 0 .. hf.Length - 1 do
            let name = fst hf[i]

            match pf |> Array.tryFindIndex (fun (n, _) -> n = name) with
            | Some j -> hp[i] <- payload[j]
            | None ->
                // transactions_root, withdrawals_root
                let j = pf |> Array.findIndex (fun (n, _) -> n + "_root" = name)
                hp[i] <- Ssz.Bytes(Ssz.hashTreeRoot (snd pf[j]) payload[j])

        let blinded = Codec.fields (Ssz.zero (Schemas.blindedBeaconBlockBody p))
        let fullFields = Codec.fields full

        for i in 0 .. blinded.Length - 1 do
            blinded[i] <- if i = 9 then Ssz.Fields hp else fullFields[i]

        Expect.equal
            (Ssz.hashTreeRoot (Schemas.blindedBeaconBlockBody p) (Ssz.Fields blinded))
            (Ssz.hashTreeRoot (Schemas.beaconBlockBody p) full)
            "same body root"
    }

/// The builder request fails at the node: the VC asks again with factor 0 and publishes the
/// local block.
let private fallbackToLocal () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Proposals[4UL] <- 3UL
        h.Node.BuilderFails <- true
        let held = ref None

        let vc =
            startVc
                h
                { defaults with
                    Extensions = [ legacy on held ]
                }

        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the local block" (fun () -> h.Node.Published.Count = 1)
        do! vc.Stop()
        let at4 = h.Node.BoostFactors |> Seq.filter (fun (s, _) -> s = 4UL) |> Seq.map snd |> List.ofSeq
        Expect.equal at4 [ 100UL; 0UL ] "the builder factor, then a local block"
        Expect.equal h.Node.PublishedBlinded.Count 0 "nothing blinded"
        Expect.stringContains vc.Log "asking for a local block" "the fallback is logged"
    }

/// Without the module the VC asks for a local block (factor 0) and refuses a blinded answer.
let private noModuleLocalOnly () =
    task {
        let h = harness ()
        addValidators [ h.Node ] 8
        h.Node.Proposals[4UL] <- 3UL
        h.Node.BuilderBlocks <- true
        let vc = startVc h defaults
        do! h.RunSlots(0UL, 4UL)
        do! waitUntil vc "the local block" (fun () -> h.Node.Published.Count = 1)
        do! vc.Stop()
        Expect.equal (List.ofSeq h.Node.BoostFactors) [ 4UL, 0UL ] "factor 0"
        Expect.equal h.Node.Registrations.Count 0 "no registrations"
    }

/// Gloas at epoch 2: registrations in epochs 0 and 1 only, and no factor for a Gloas slot.
let private offAtGloas () =
    task {
        let h = gloasHarness 2UL
        addValidators [ h.Node ] 8
        let held = ref None

        let vc =
            startVc
                h
                { defaults with
                    Extensions = [ legacy on held ]
                }

        do! h.RunSlots(0UL, 1UL)
        do! waitUntil vc "epoch 0 registrations" (fun () -> h.Node.Registrations.Count = 1)
        do! h.RunSlots(2UL, 9UL)
        do! waitUntil vc "epoch 1 registrations" (fun () -> h.Node.Registrations.Count = 2)
        do! h.RunSlots(10UL, 33UL)
        do! vc.Stop()
        Expect.equal h.Node.Registrations.Count 2 "none from the Gloas fork on"
        let r = held.Value.Value

        let duty slot : Beacon.ProposerDuty =
            {
                PubKey = pubkeyOf 1
                ValidatorIndex = 1UL
                Slot = slot
            }

        Expect.equal (r.BoostFor(duty 15UL)) (ValueSome 100UL) "before the fork"
        Expect.equal (r.BoostFor(duty 16UL)) ValueNone "from the fork on"
    }

let private config () =
    task {
        let parse (text: string) =
            use d = JsonDocument.Parse text

            LegacyBuilderModule.parse
                {
                    Element = ValueSome(d.RootElement.Clone())
                    BaseDir = "/"
                    Mainnet = false
                }

        Expect.equal
            (LegacyBuilderModule.parse
                {
                    Element = ValueNone
                    BaseDir = "/"
                    Mainnet = false
                })
            (Ok LegacyBuilderModule.Settings.Default)
            "absent"

        Expect.equal
            (parse """{ "enabled": true, "boost_factor": "90", "registration_batch_size": 100 }""")
            (Ok
                {
                    Enabled = true
                    BoostFactor = 90UL
                    BatchSize = 100
                })
            "all fields"

        Expect.isError (parse """{ "registration_batch_size": 0 }""") "batch of 0"
        Expect.isError (parse """{ "relays": [] }""") "unknown field"
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "builder legacy"
        [
            testT "registrations: builder domain, genesis fork, zero root; the local key signs" domainAndSignature
            testT
                "registrations: signed once, sent each epoch to every node in batches, re-signed on a change"
                registrationsCachedAndBatched
            testT "per-key builder settings: own boost factor, builder off" perKeySettings
            testT "a blinded block is signed over its header, recorded and published blinded" blindedProposal
            testT "the blinded body root equals the full body root" blindedBodyRoot
            testT "a failed builder request falls back to a local block" fallbackToLocal
            testT "without the module: factor 0, no registrations" noModuleLocalOnly
            testT "off from the Gloas fork on" offAtGloas
            testT "config section" config
        ]
