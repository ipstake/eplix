/// Obol mode as a module. Config section "obol": { "enabled": true }. Off when the section is
/// absent.
///
/// In a distributed validator cluster each VC signs with a key share, so its selection proof is
/// a partial and does not decide aggregation. When on, the scheduler sends its partial proofs to
/// the beacon node, which in a Charon cluster is the middleware: once per epoch of attester
/// duties to beacon_committee_selections and once per slot of sync duties to
/// sync_committee_selections. The middleware answers with the combined proofs. These decide
/// aggregation, and they go into the AggregateAndProof and ContributionAndProof messages. The
/// calls go to the best node with fallback (BeaconNodes.Call). A failed call means no
/// aggregation for the batch until a call works: the scheduler sends the attester proofs again
/// each slot until their slot ends, and does not retry the sync proofs of a slot. Duties left
/// without a combined proof count as missed (eplix_duties_missed, reason beacon_node).
module Eplix.Obol.ObolModule

open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon
open Eplix.Json

let name = "obol"

type Settings = { Enabled: bool }

let defaults = { Enabled = false }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok defaults
    | ValueSome e ->
        match checkFields e "modules.obol" [ "enabled" ] with
        | [] ->
            match tryProp e "enabled" with
            | ValueSome v when v.ValueKind = JsonValueKind.True -> Ok { Enabled = true }
            | ValueSome v when v.ValueKind = JsonValueKind.False -> Ok { Enabled = false }
            | ValueSome _ -> Error [ "modules.obol: enabled must be true or false" ]
            | ValueNone -> Ok defaults
        | errs -> Error errs

/// The selection hooks over a node set.
let hooks (nodes: BeaconNodes) : SelectionHooks =
    {
        BeaconCommittee =
            fun xs ct ->
                task {
                    let body = Selections.encodeBeaconCommittee xs

                    match!
                        nodes.Call(
                            (fun b ->
                                b.PostJson(Selections.BeaconCommitteePath, body, Selections.decodeBeaconCommittee, ct)),
                            NodeRole.AggregateData
                        )
                    with
                    | Ok answer -> return Ok answer
                    | Error e -> return Error $"beacon_committee_selections: {e.Describe}"
                }
        SyncCommittee =
            fun xs ct ->
                task {
                    let body = Selections.encodeSyncCommittee xs

                    match!
                        nodes.Call(
                            (fun b ->
                                b.PostJson(Selections.SyncCommitteePath, body, Selections.decodeSyncCommittee, ct)),
                            NodeRole.SyncData
                        )
                    with
                    | Ok answer -> return Ok answer
                    | Error e -> return Error $"sync_committee_selections: {e.Describe}"
                }
    }

let create () : Module =
    let settings = ref defaults

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun _ -> Ok(if settings.Value.Enabled then "on: combined selection proofs from the beacon node" else "off")
        Start =
            fun core _ ->
                task {
                    if settings.Value.Enabled then
                        core.SetSelections(hooks core.Nodes)
                        core.Log.Info "obol mode on: combined selection proofs from the beacon node decide aggregation"

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
