/// The JSON of the Beacon API selection endpoints (beacon-APIs v2.4.0 and later):
/// POST /eth/v1/validator/beacon_committee_selections takes [{validator_index, slot,
/// selection_proof}], POST /eth/v1/validator/sync_committee_selections takes [{validator_index,
/// slot, subcommittee_index, selection_proof}]. Both answer {data: [...]} with the same objects,
/// each carrying the combined proof. Numbers are decimal strings, proofs 0x-hex.
module Eplix.Obol.Selections

open System.Text.Json
open Eplix
open Eplix.Json

[<Literal>]
let BeaconCommitteePath = "/eth/v1/validator/beacon_committee_selections"

[<Literal>]
let SyncCommitteePath = "/eth/v1/validator/sync_committee_selections"

let encodeBeaconCommittee (xs: BeaconCommitteeSelection seq) : byte[] =
    toBytes (fun w ->
        w.WriteStartArray()

        for x in xs do
            w.WriteStartObject()
            writeU64 w "validator_index" x.ValidatorIndex
            writeU64 w "slot" x.Slot
            w.WriteString("selection_proof", x.SelectionProof.Hex)
            w.WriteEndObject()

        w.WriteEndArray())

let encodeSyncCommittee (xs: SyncCommitteeSelection seq) : byte[] =
    toBytes (fun w ->
        w.WriteStartArray()

        for x in xs do
            w.WriteStartObject()
            writeU64 w "validator_index" x.ValidatorIndex
            writeU64 w "slot" x.Slot
            writeU64 w "subcommittee_index" x.SubcommitteeIndex
            w.WriteString("selection_proof", x.SelectionProof.Hex)
            w.WriteEndObject()

        w.WriteEndArray())

let decodeBeaconCommittee (e: JsonElement) : BeaconCommitteeSelection[] =
    array (prop e "data")
    |> Array.map (fun x ->
        ({
            ValidatorIndex = u64Field x "validator_index"
            Slot = u64Field x "slot"
            SelectionProof = signature (prop x "selection_proof")
        }
        : BeaconCommitteeSelection))

let decodeSyncCommittee (e: JsonElement) : SyncCommitteeSelection[] =
    array (prop e "data")
    |> Array.map (fun x ->
        ({
            ValidatorIndex = u64Field x "validator_index"
            Slot = u64Field x "slot"
            SubcommitteeIndex = u64Field x "subcommittee_index"
            SelectionProof = signature (prop x "selection_proof")
        }
        : SyncCommitteeSelection))
