/// remote-signing-api v1.4.0 (signing/paths/sign.yaml): the request examples, extracted to
/// tests/fixtures/remote-signing-api/sign-examples.json by scripts/remote-signing-examples.py.
/// For each type and fork Eplix sends, the body Eplix writes for the example's message has the
/// example's shape (the same keys at every level), and Eplix's signing root equals the example's.
module Eplix.Tests.RemoteSigningExamplesTests

open System
open System.IO
open System.Text.Json
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Backend.Web3Signer
open Eplix.Tests.TestUtil

let private examplesFile = Path.Combine(fixtures, "remote-signing-api", "sign-examples.json")

/// Every fork at epoch 0 with the examples' fork version (all examples use 0x00000001), and the
/// minimal preset, which the examples' sizes show (8 contribution bits, not 128).
let private specFor (version: string) =
    let forks = [ "ALTAIR"; "BELLATRIX"; "CAPELLA"; "DENEB"; "ELECTRA"; "FULU"; "GLOAS" ]

    let values =
        [
            "PRESET_BASE", "minimal"
            "SECONDS_PER_SLOT", "12"
            "GENESIS_FORK_VERSION", version
            for f in forks do
                $"{f}_FORK_VERSION", version
                $"{f}_FORK_EPOCH", "0"
        ]

    match ChainSpec.parse (Map.ofList values) with
    | Ok s -> s
    | Error e -> failwith e

/// The keys of a JSON value at every level; arrays by their first element. The top-level
/// signingRoot is left out: it is optional in every request schema and Eplix always sends it,
/// while the Gloas examples leave it out. Two examples (AGGREGATION_SLOT, the deprecated BLOCK)
/// spell the fork fields in camel case, unlike the schema's Fork; they count as the schema's names.
let rec private shapeAt (top: bool) (e: JsonElement) : string =
    let name (n: string) =
        match n with
        | "currentVersion" -> "current_version"
        | "previousVersion" -> "previous_version"
        | n -> n

    match e.ValueKind with
    | JsonValueKind.Object ->
        let fields =
            e.EnumerateObject()
            |> Seq.filter (fun p -> not (top && p.Name = "signingRoot"))
            |> Seq.map (fun p -> $"{name p.Name}:{shapeAt false p.Value}")
            |> Seq.sort

        "{" + String.Join(",", fields) + "}"
    | JsonValueKind.Array ->
        match e.EnumerateArray() |> Seq.tryHead with
        | Some x -> $"[{shapeAt false x}]"
        | None -> "[]"
    | _ -> "_"

let private shape = shapeAt true

let private u64 (e: JsonElement) (name: string) = UInt64.Parse(e.GetProperty(name).GetString())
let private rootOf (e: JsonElement) (name: string) = (Root.TryParse(e.GetProperty(name).GetString())).Value

/// The Duty an example describes, or None for a type or fork Eplix never sends.
let private dutyOf (spec: ChainSpec) (v: JsonElement) : Duty option =
    let p = spec.Preset
    let versioned (name: string) = v.GetProperty(name).GetProperty("version").GetString().ToUpperInvariant()
    let data (name: string) = v.GetProperty(name).GetProperty("data")

    match v.GetProperty("type").GetString() with
    | "ATTESTATION" -> Some(Duty.Attestation(Decoders.attestationDataOf (v.GetProperty "attestation")))
    | "BLOCK_V2" ->
        match v.GetProperty("beacon_block").TryGetProperty "block_header" with
        | true, h ->
            Some(
                Duty.Block
                    {
                        Slot = u64 h "slot"
                        ProposerIndex = u64 h "proposer_index"
                        ParentRoot = rootOf h "parent_root"
                        StateRoot = rootOf h "state_root"
                        BodyRoot = rootOf h "body_root"
                    }
            )
        | _ -> None // full blocks of Phase 0 and Altair: Eplix sends headers only
    | "AGGREGATION_SLOT" -> Some(Duty.AggregationSlot(u64 (v.GetProperty "aggregation_slot") "slot"))
    | "AGGREGATE_AND_PROOF_V2" ->
        match versioned "aggregate_and_proof" with
        | "ELECTRA"
        | "FULU"
        | "GLOAS" as fork ->
            // The aggregate examples use the mainnet preset (64 committee bits).
            let schema = Schemas.aggregateAndProofAt (fork = "GLOAS") Preset.Mainnet
            let value = SszJson.read schema (data "aggregate_and_proof")
            let slot = Codec.asU (Codec.fields (Codec.fields (Codec.fields value).[1]).[1]).[0]
            Some(Duty.AggregateAndProof(slot, { Schema = schema; Value = value }))
        | _ -> None // pre-Electra aggregates: Eplix starts at Electra
    | "RANDAO_REVEAL" -> Some(Duty.RandaoReveal(u64 (v.GetProperty "randao_reveal") "epoch"))
    | "VOLUNTARY_EXIT" ->
        let x = v.GetProperty "voluntary_exit"

        Some(
            Duty.VoluntaryExit
                {
                    Epoch = u64 x "epoch"
                    ValidatorIndex = u64 x "validator_index"
                }
        )
    | "SYNC_COMMITTEE_MESSAGE" ->
        let m = v.GetProperty "sync_committee_message"
        Some(Duty.SyncCommitteeMessage(u64 m "slot", rootOf m "beacon_block_root"))
    | "SYNC_COMMITTEE_SELECTION_PROOF" ->
        let s = v.GetProperty "sync_aggregator_selection_data"

        Some(
            Duty.SyncSelectionProof
                {
                    Slot = u64 s "slot"
                    SubcommitteeIndex = u64 s "subcommittee_index"
                }
        )
    | "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" ->
        let schema = Schemas.contributionAndProof p
        let value = SszJson.read schema (v.GetProperty "contribution_and_proof")
        let slot = Codec.asU (Codec.fields (Codec.fields value).[1]).[0]
        Some(Duty.ContributionAndProof(slot, { Schema = schema; Value = value }))
    | "EXECUTION_PAYLOAD_ENVELOPE" ->
        // The example's logs_bloom is shorter than 256 bytes, so it does not decode; the example
        // has no signing root either. A zero envelope checks the shape.
        let schema = Schemas.Gloas.executionPayloadEnvelope p

        Some(
            Duty.PayloadEnvelope(
                1UL,
                {
                    Schema = schema
                    Value = Ssz.zero schema
                }
            )
        )
    | "PAYLOAD_ATTESTATION_MESSAGE" ->
        Some(Duty.PayloadAttestation(Decoders.payloadAttestationDataOf (data "payload_attestation_message")))
    | "PROPOSER_PREFERENCES" ->
        Some(
            Duty.ProposerPreferences(
                Codec.proposerPreferencesOf (
                    SszJson.read Schemas.Gloas.proposerPreferences (data "proposer_preferences")
                )
            )
        )
    | "BUILDER_REQUEST_AUTH" ->
        let value = SszJson.read Schemas.Gloas.builderRequestAuth (data "builder_request_auth")
        let f = Codec.fields value

        Some(
            Duty.BuilderRequestAuth
                {
                    AuthData = Codec.asBytes f[0]
                    AuthSlot = Codec.asU f[1]
                }
        )
    | "VALIDATOR_REGISTRATION" ->
        let r = v.GetProperty "validator_registration"

        Some(
            Duty.ValidatorRegistration
                {
                    FeeRecipient = hex (r.GetProperty("fee_recipient").GetString())
                    GasLimit = u64 r "gas_limit"
                    Timestamp = u64 r "timestamp"
                    PubKey = (PubKey.TryParse(r.GetProperty("pubkey").GetString())).Value
                }
        )
    | _ -> None // AGGREGATE_AND_PROOF and BLOCK (deprecated), DEPOSIT, EXECUTION_PAYLOAD_BID

/// Types Eplix sends; the test fails if the examples stop covering one of them.
let private sentTypes =
    set
        [
            "ATTESTATION"
            "BLOCK_V2"
            "AGGREGATION_SLOT"
            "AGGREGATE_AND_PROOF_V2"
            "RANDAO_REVEAL"
            "VOLUNTARY_EXIT"
            "SYNC_COMMITTEE_MESSAGE"
            "SYNC_COMMITTEE_SELECTION_PROOF"
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
            "EXECUTION_PAYLOAD_ENVELOPE"
            "PAYLOAD_ATTESTATION_MESSAGE"
            "PROPOSER_PREFERENCES"
            "BUILDER_REQUEST_AUTH"
            "VALIDATOR_REGISTRATION"
        ]

/// Example roots that match no schema for their data. The Electra and Fulu aggregate examples
/// carry 0x2475...: neither the Electra AggregateAndProof (with any of the aggregation-bit limits
/// 2048, 8192, 131072, 262144) nor the Gloas one gives it, while the Gloas example, with the same
/// message, matches Eplix's Gloas root. Eplix's Electra root is checked by the consensus-spec-tests
/// AggregateAndProof cases and by Web3Signer 26.10.1 in the integration tests.
let private unreproducibleRoots =
    set [ "AGGREGATE_AND_PROOF_V2 (ELECTRA)"; "AGGREGATE_AND_PROOF_V2 (FULU)" ]

let private examples () =
    if not (File.Exists examplesFile) then
        failwithf "%s is missing" examplesFile

    use doc = JsonDocument.Parse(File.ReadAllText examplesFile)

    [
        for e in doc.RootElement.EnumerateArray() -> e.GetProperty("name").GetString(), e.GetProperty("value").Clone()
    ]

let private exampleTest (name: string) (v: JsonElement) =
    test name {
        let gvr, version =
            match v.TryGetProperty "fork_info" with
            | true, fi ->
                let fork = fi.GetProperty "fork"

                let cur =
                    match fork.TryGetProperty "current_version" with
                    | true, c -> c
                    | _ -> fork.GetProperty "currentVersion"

                rootOf fi "genesis_validators_root", cur.GetString()
            | _ -> Root.Zero, "0x00000001"

        let spec = specFor version

        match dutyOf spec v with
        | None -> ()
        | Some duty ->
            let pk = PubKey.Of(Array.init 48 (fun i -> if i = 0 then 0xA0uy else 0uy))
            let req = Duty.request spec gvr pk Priority.Low DateTimeOffset.MaxValue duty
            use body = JsonDocument.Parse(ReadOnlyMemory<byte>(Body.encode spec req))
            Expect.equal (shape body.RootElement) (shape v) "the body has the example's keys at every level"

            match v.TryGetProperty "signingRoot" with
            | true, r when unreproducibleRoots.Contains name ->
                // Still unreproducible: when the example changes, this exception should go.
                Expect.notEqual req.SigningRoot.Hex (r.GetString()) "the example's root (see unreproducibleRoots)"
            | true, r -> Expect.equal req.SigningRoot.Hex (r.GetString()) "Eplix's signing root equals the example's"
            | _ -> ()
    }

[<Tests>]
let tests =
    testList
        "web3signer"
        [
            testList "bodies match the v1.4.0 examples" [ for name, v in examples () -> exampleTest name v ]
            test "the examples cover every type Eplix sends" {
                let covered = examples () |> List.map (fun (_, v) -> v.GetProperty("type").GetString()) |> Set.ofList
                Expect.isEmpty (Set.difference sentTypes covered) "types without an example"
            }
        ]
