/// The Gloas duties module. Config section "gloas":
///   { "include_payload": true, "p2p_min_bid": "0", "p2p_builder_boost_factor": "100",
///     "proposer_preferences": true }
/// A chain that schedules Gloas needs this module; -p:EplixGloas=false leaves it out of a
/// Fulu-only build.
module Eplix.Gloas.GloasModule

open System.Text.Json
open System.Threading.Tasks
open Eplix
open Eplix.Json

let name = ModuleNames.Gloas

let parse (section: ConfigSection) : Result<Settings, string list> =
    let d = Settings.Default

    match section.Element with
    | ValueNone -> Ok d
    | ValueSome e ->
        match
            checkFields
                e
                "modules.gloas"
                [
                    "include_payload"
                    "p2p_min_bid"
                    "p2p_builder_boost_factor"
                    "proposer_preferences"
                ]
        with
        | [] ->
            try
                let flag n (fallback: bool) =
                    match tryProp e n with
                    | ValueSome _ -> boolField e n
                    | ValueNone -> fallback

                let num n (fallback: uint64) =
                    match tryProp e n with
                    | ValueSome v -> u64 v
                    | ValueNone -> fallback

                Ok
                    {
                        IncludePayload = flag "include_payload" d.IncludePayload
                        P2pMinBid = num "p2p_min_bid" d.P2pMinBid
                        P2pBuilderBoostFactor = num "p2p_builder_boost_factor" d.P2pBuilderBoostFactor
                        ProposerPreferences = flag "proposer_preferences" d.ProposerPreferences
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.gloas: {x.Message}" ]
        | errs -> Error errs

let create () : Module =
    let settings = ref Settings.Default

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check = fun _ -> Ok "Gloas duties: PTC votes, envelopes, proposer preferences"
        Start =
            fun core _ ->
                task {
                    if core.Spec.IsScheduled Gloas then
                        let duties = GloasDuties(core, settings.Value)
                        core.AddDutyExtension duties.Extension
                        let fork = core.Spec.Forks |> Array.find (fun f -> f.Name = Gloas)

                        core.Log.Info
                            $"Gloas from epoch {fork.Epoch}: PTC votes, produceBlockV4 with self-built envelopes, proposer preferences"

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
