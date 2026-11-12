/// Contract tests for the bodies Eplix sends to a signer that speaks the Web3Signer API
/// (POST /api/v1/eth2/sign/{identifier}), against remote-signing-api v1.4.0. Grandine lost every
/// PTC vote on a devnet because a gateway refused its request type, so each body is
/// pinned three ways:
/// - Eplix writes, for a fixed duty, the body in tests/fixtures/remote-signing-api/eplix-bodies/.
///   The files sit apart from the code, so another signer (`tee-signer` once its API exists) can
///   be checked against the same bodies. EPLIX_UPDATE_FIXTURES=1 rewrites them.
/// - Each body fits the API's request schema (tests/fixtures/remote-signing-api/schemas.json, from
///   scripts/remote-signing-schemas.py), through the schema the `type` discriminator names.
/// - Each property of each body is one the schema names: a strict server refuses unknown fields.
/// The Web3Signer integration list (Web3SignerIntegrationTests.fs) sends the same files, as they
/// are, to a real Web3Signer.
module Eplix.Tests.RemoteSigningContractTests

open System
open System.IO
open System.Text
open System.Text.Json
open Expecto
open Eplix
open Eplix.Backend.Web3Signer
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

/// Gloas from this epoch, as in the Web3Signer network file of the integration tests.
let gloasEpoch = 10UL

/// The chain of the integration tests: minimal preset, every fork before Gloas at epoch 0.
let contractSpec =
    match ChainSpec.parse (Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch)) with
    | Ok s -> s
    | Error e -> failwith e

/// One duty of each pre-Gloas type, at slots in epoch 5 (Fulu).
let preGloasDuties (p: Preset) =
    [
        Duty.Attestation
            {
                Slot = 41UL
                Index = 0UL
                BeaconBlockRoot = root 1
                Source = { Epoch = 4UL; Root = root 4 }
                Target = { Epoch = 5UL; Root = root 5 }
            }
        Duty.Block
            {
                Slot = 40UL
                ProposerIndex = 1UL
                ParentRoot = root 1
                StateRoot = root 2
                BodyRoot = root 3
            }
        Duty.RandaoReveal 5UL
        Duty.AggregationSlot 41UL
        // Slot 0, as in the zero message: the signer takes the epoch from the message.
        Duty.AggregateAndProof(
            0UL,
            {
                Schema = Schemas.aggregateAndProof p
                Value = Ssz.zero (Schemas.aggregateAndProof p)
            }
        )
        Duty.SyncCommitteeMessage(41UL, root 9)
        Duty.SyncSelectionProof { Slot = 41UL; SubcommitteeIndex = 1UL }
        Duty.ContributionAndProof(
            0UL,
            {
                Schema = Schemas.contributionAndProof p
                Value = Ssz.zero (Schemas.contributionAndProof p)
            }
        )
        Duty.VoluntaryExit { Epoch = 5UL; ValidatorIndex = 1UL }
        // The pre-Gloas builder flow: signed in the builder domain, sent without fork_info.
        Duty.ValidatorRegistration
            {
                FeeRecipient = Array.create 20 0xaauy
                GasLimit = 60_000_000UL
                Timestamp = 1_700_000_000UL
                PubKey = pubkeyOf 0
            }
    ]

/// The Gloas kinds (remote-signing-api v1.4.0) and the Gloas forms of the block and aggregate,
/// at slots in the first Gloas epoch.
let gloasDuties (p: Preset) =
    let slot = gloasEpoch * uint64 slotsPerEpoch + 1UL

    let envelope =
        match Ssz.zero (Schemas.Gloas.executionPayloadEnvelope p) with
        | Ssz.Fields f ->
            (Codec.fields f[0]).[18] <- Ssz.U slot
            f[2] <- Ssz.U UInt64.MaxValue
            f[3] <- Ssz.Bytes (root 7).Bytes
            Ssz.Fields f
        | v -> v

    let aggregate =
        match Ssz.zero (Schemas.Gloas.aggregateAndProof p) with
        | Ssz.Fields f ->
            let att = Codec.fields f[1]
            (Codec.fields att[1]).[0] <- Ssz.U slot
            att[0] <- Ssz.Bits [| true; false; true |]
            Ssz.Fields f
        | v -> v

    [
        Duty.PayloadAttestation
            {
                BeaconBlockRoot = root 7
                Slot = slot
                PayloadPresent = true
                BlobDataAvailable = false
            }
        Duty.PayloadEnvelope(
            slot,
            {
                Schema = Schemas.Gloas.executionPayloadEnvelope p
                Value = envelope
            }
        )
        Duty.ProposerPreferences
            {
                DependentRoot = root 3
                ProposalSlot = slot + 1UL
                ValidatorIndex = 1UL
                FeeRecipient = Array.create 20 0xaauy
                TargetGasLimit = 60_000_000UL
            }
        // Preferences for the first Gloas slot, signed before the fork.
        Duty.ProposerPreferences
            {
                DependentRoot = root 3
                ProposalSlot = gloasEpoch * uint64 slotsPerEpoch
                ValidatorIndex = 1UL
                FeeRecipient = Array.create 20 0xaauy
                TargetGasLimit = 60_000_000UL
            }
        Duty.BuilderRequestAuth
            {
                AuthData = Encoding.UTF8.GetBytes "builder.example.org"
                AuthSlot = slot + 1UL
            }
        Duty.Block
            {
                Slot = slot
                ProposerIndex = 1UL
                ParentRoot = root 1
                StateRoot = root 2
                BodyRoot = root 3
            }
        Duty.AggregateAndProof(
            slot,
            {
                Schema = Schemas.Gloas.aggregateAndProof p
                Value = aggregate
            }
        )
    ]

/// Each duty with its fixture name: the type, and a suffix where a type comes twice.
let contractDuties () =
    let p = contractSpec.Preset

    let pre =
        [
            for d in preGloasDuties p ->
                match d with
                | Duty.Block _
                | Duty.AggregateAndProof _ -> $"{Body.typeName d}.fulu", d
                | _ -> Body.typeName d, d
        ]

    let gloas =
        List.zip
            [
                "PAYLOAD_ATTESTATION_MESSAGE"
                "EXECUTION_PAYLOAD_ENVELOPE"
                "PROPOSER_PREFERENCES"
                "PROPOSER_PREFERENCES.before-fork"
                "BUILDER_REQUEST_AUTH"
                "BLOCK_V2.gloas"
                "AGGREGATE_AND_PROOF_V2.gloas"
            ]
            (gloasDuties p)

    pre @ gloas

let fixtureDir = Path.Combine(fixtures, "remote-signing-api", "eplix-bodies")
let fixtureFile (name: string) = Path.Combine(fixtureDir, name + ".json")

/// The body Eplix writes for a duty (the key only picks the URL, not the body).
let bodyOf (duty: Duty) =
    Body.encode contractSpec (Duty.request contractSpec gvr (pubkeyOf 0) Priority.High DateTimeOffset.UnixEpoch duty)

/// JSON text with the property order kept: compact, or indented for the files.
let private reformat (indented: bool) (bytes: byte[]) =
    use doc = JsonDocument.Parse(ReadOnlyMemory bytes)
    use ms = new MemoryStream()

    (use w = new Utf8JsonWriter(ms, JsonWriterOptions(Indented = indented))
     doc.WriteTo w)

    Encoding.UTF8.GetString(ms.ToArray())

let private schemasFile = Path.Combine(fixtures, "remote-signing-api", "schemas.json")
let private api = lazy (OpenApi.load schemasFile)
let private request () = api.Force().Root.GetProperty("components").GetProperty("request")

/// The request schema the `type` discriminator names, as a reference.
let private schemaFor (typeName: string) =
    match request().GetProperty("discriminator").GetProperty("mapping").TryGetProperty typeName with
    | true, r ->
        let reference = dict [ "$ref", r.GetString() ]
        ValueSome(JsonDocument.Parse(JsonSerializer.Serialize reference).RootElement.Clone())
    | _ -> ValueNone

/// Every request type of the API's discriminator.
let private apiTypes () =
    [
        for p in request().GetProperty("discriminator").GetProperty("mapping").EnumerateObject() -> p.Name
    ]
    |> Set.ofList

/// Properties of `v` that no schema reaching it names: through $ref and allOf, and the oneOf or
/// anyOf branches `v` fits. Maps (additionalProperties with a schema) are not checked.
let rec unnamed (schema: JsonElement) (v: JsonElement) (at: string) : string list =
    let spec = api.Force()

    let rec parts (s: JsonElement) : JsonElement list =
        let s = spec.Resolve s

        [
            yield s
            match s.TryGetProperty "allOf" with
            | true, all ->
                for x in all.EnumerateArray() do
                    yield! parts x
            | _ -> ()
            for key in [ "oneOf"; "anyOf" ] do
                match s.TryGetProperty key with
                | true, any ->
                    for x in any.EnumerateArray() do
                        if List.isEmpty (spec.Check(x, v)) then
                            yield! parts x
                | _ -> ()
        ]

    let ps = parts schema

    let has (name: string) (p: JsonElement) =
        match p.TryGetProperty name with
        | true, x -> ValueSome x
        | _ -> ValueNone

    match v.ValueKind with
    | JsonValueKind.Object ->
        let isMap =
            ps
            |> List.exists (fun p ->
                match has "additionalProperties" p with
                | ValueSome a -> a.ValueKind = JsonValueKind.Object
                | ValueNone -> false)

        let props =
            ps
            |> List.collect (fun p ->
                match has "properties" p with
                | ValueSome pr -> [ for x in pr.EnumerateObject() -> x.Name, x.Value ]
                | ValueNone -> [])

        [
            for p in v.EnumerateObject() do
                match props |> List.filter (fun (n, _) -> n = p.Name) with
                | [] ->
                    if not isMap then
                        yield at + "." + p.Name
                | named ->
                    for _, s in named do
                        yield! unnamed s p.Value (at + "." + p.Name)
        ]
        |> List.distinct
    | JsonValueKind.Array ->
        let items =
            ps
            |> List.choose (fun p ->
                match has "items" p with
                | ValueSome i -> Some i
                | ValueNone -> None)

        [
            for i, x in Seq.indexed (v.EnumerateArray()) do
                for s in items do
                    yield! unnamed s x $"{at}[{i}]"
        ]
        |> List.distinct
    | _ -> []

/// The API's types Eplix does not send, each with the reason. A new type in a later API version
/// fails the coverage test until it is sent or listed here.
let notSent =
    Map.ofList
        [
            "BLOCK", "deprecated; Eplix sends BLOCK_V2"
            "AGGREGATE_AND_PROOF", "deprecated; Eplix sends AGGREGATE_AND_PROOF_V2"
            "DEPOSIT", "the VC signs no deposits"
            "EXECUTION_PAYLOAD_BID", "signed by builders, not by the proposer's VC"
        ]

/// The fixture's bytes; a missing file fails with how to make it.
let readFixture (name: string) =
    let file = fixtureFile name

    if not (File.Exists file) then
        failtestf "%s is missing; run the tests with EPLIX_UPDATE_FIXTURES=1" file

    File.ReadAllBytes file

let private element (node: Nodes.JsonNode) = JsonDocument.Parse(node.ToJsonString()).RootElement.Clone()

[<Tests>]
let tests =
    testList
        "web3signer contract"
        [
            test "Eplix writes the fixture bodies" {
                let update = Environment.GetEnvironmentVariable "EPLIX_UPDATE_FIXTURES" = "1"

                if update then
                    Directory.CreateDirectory fixtureDir |> ignore

                for name, duty in contractDuties () do
                    let body = bodyOf duty

                    if update then
                        File.WriteAllText(fixtureFile name, reformat true body + "\n")

                    Expect.equal
                        (reformat false body)
                        (reformat false (readFixture name))
                        $"{name}: Eplix's body differs from the fixture"

                let names = contractDuties () |> List.map (fun (n, _) -> n + ".json") |> Set.ofList
                let files = Directory.GetFiles(fixtureDir, "*.json") |> Array.map Path.GetFileName |> Set.ofArray
                Expect.isEmpty (Set.difference files names) "fixture files without a duty"
            }
            test "each fixture fits the request schema of its type" {
                for name, _ in contractDuties () do
                    use doc = JsonDocument.Parse(readFixture name)
                    let body = doc.RootElement
                    let typeName = body.GetProperty("type").GetString()

                    match schemaFor typeName with
                    | ValueNone -> failtestf "%s: the API has no type %s" name typeName
                    | ValueSome schema ->
                        Expect.isEmpty (api.Force().Check(schema, body)) $"{name} against the {typeName} schema"
                        Expect.isEmpty (api.Force().Check(request (), body)) $"{name} against the request schema"
            }
            test "each property of each fixture is one the schema names" {
                for name, _ in contractDuties () do
                    use doc = JsonDocument.Parse(readFixture name)
                    let body = doc.RootElement
                    let schema = (schemaFor (body.GetProperty("type").GetString())).Value
                    Expect.isEmpty (unnamed schema body "$") $"{name}: properties the schema does not name"
            }
            test "the fixtures cover every type Eplix sends, and the API's other types are listed" {
                let sent = contractDuties () |> List.map (fun (_, d) -> Body.typeName d) |> Set.ofList
                let all = apiTypes ()
                Expect.isEmpty (Set.difference sent all) "types Eplix sends that the API does not have"
                let unlisted = Set.difference all sent |> Set.filter (fun t -> not (notSent.ContainsKey t))
                Expect.isEmpty unlisted "API types neither sent nor listed in notSent"

                Expect.isEmpty
                    (Set.intersect sent (notSent |> Map.keys |> Set.ofSeq))
                    "types in notSent that Eplix sends"
            }
            test "the checks catch a wrong PTC vote" {
                // The data without its version wrapper, the slot as a number, an extra field.
                let _, duty = contractDuties () |> List.find (fun (n, _) -> n = "PAYLOAD_ATTESTATION_MESSAGE")
                let schema = (schemaFor "PAYLOAD_ATTESTATION_MESSAGE").Value
                let fresh () = Nodes.JsonNode.Parse(Encoding.UTF8.GetString(bodyOf duty))
                let flat = fresh ()
                let message = flat["payload_attestation_message"]
                flat["payload_attestation_message"] <- message["data"].DeepClone()
                let numberSlot = fresh ()
                let data = numberSlot["payload_attestation_message"]["data"]
                let slot = data["slot"].GetValue<string>()
                data["slot"] <- Nodes.JsonValue.Create(uint64 slot)
                let extra = fresh ()
                let extraData = extra["payload_attestation_message"]["data"]
                extraData["extra"] <- Nodes.JsonValue.Create 1
                Expect.isNonEmpty (api.Force().Check(schema, element flat)) "the data without version"
                Expect.isNonEmpty (api.Force().Check(schema, element numberSlot)) "a number slot"
                Expect.isEmpty (api.Force().Check(schema, element extra)) "an extra field fits the schema itself"

                Expect.equal
                    (unnamed schema (element extra) "$")
                    [ "$.payload_attestation_message.data.extra" ]
                    "the strict check names it"
            }
        ]
