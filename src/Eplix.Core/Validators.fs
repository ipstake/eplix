/// Moves keys from discovered to active: chain index and status from the beacon node, then the
/// slashing history check. A key never signs before it has a slashing record, and no
/// beacon node data gives it one.
namespace Eplix

open System
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Slashing

/// What the allow_start_without_history override needs to write a floor record (Floor.fs).
type FloorSource =
    {
        Clock: SlotClock
        /// The PTC vote and envelope marks, raised with the floor when the VC has them.
        SlotMarks: SlotMarks voption
    }

module Validators =
    /// Statuses of a validator that was never activated. Only shapes the log hint: no status
    /// starts a key.
    let private looksNew (status: string) = status = "pending_initialized" || status = "pending_queued"

    /// The floor epoch E now: the clock's epoch, raised by the head slot of any node that answers
    /// (Floor.epochChecked). Asked only when a key gets a floor. A head more than one epoch past
    /// the clock is an error.
    let floorEpoch (clock: SlotClock) (nodes: BeaconNodes) (ct: CancellationToken) : Task<Result<Epoch, string>> =
        task {
            let now = clock.CurrentSlot |> ValueOption.map clock.EpochOf |> ValueOption.defaultValue 0UL
            let! answers = nodes.AskAll(fun b -> b.Syncing ct)

            let heads =
                answers
                |> Array.choose (fun r ->
                    match r with
                    | Ok s -> Some s.HeadSlot
                    | Error _ -> None)

            return Floor.epochChecked clock.SlotsPerEpoch now heads
        }

    /// Reads index and status of every live key from the beacon node (state "head"), then
    /// promotes keys whose slashing history is settled. Keys the node does not know stay discovered.
    /// A key with no record stays discovered too, unless the operator's override lists it: then
    /// it gets a floor record, never an empty one. With `slashed`, keys listed there and keys the
    /// chain shows slashed (checked against every node) stop for good before any promotion.
    let refreshWith
        (slashed: (SlashedKeys * TimeProvider) voption)
        (floor: FloorSource)
        (nodes: BeaconNodes)
        (registry: KeyRegistry)
        (db: SlashingDb)
        (allow: AllowStartWithoutHistory)
        (log: Log)
        (ct: CancellationToken)
        : Task<Result<unit, ApiError>> =
        task {
            let all = registry.Live
            let ids = all |> List.map (fun k -> k.Key.Hex)

            let! infos =
                if ids.IsEmpty then
                    Task.FromResult(Ok [||])
                else
                    nodes.Call((fun b -> b.Validators("head", ids, ct)), NodeRole.Duties)

            match infos with
            | Error e -> return Error e
            | Ok infos ->
                for v in infos do
                    registry.SetChainInfo(v.PubKey, v.Index, v.Status)

                match slashed with
                | ValueNone -> ()
                | ValueSome(store, time) ->
                    // A stop whose write failed earlier: the key is stopped in this process, and
                    // the file must name it before a restart.
                    match store.Flush() with
                    | Ok() -> ()
                    | Error e -> log.Error $"could not record a stopped key, tried again at the next refresh: {e}"

                    let notStopped (k: RegisteredKey) =
                        match k.State with
                        | KeyState.Slashed _ -> false
                        | _ -> true

                    for k in registry.Live |> List.filter notStopped do
                        match store.TryGet k.Key with
                        | ValueSome s -> registry.SetState(k.Key, KeyState.Slashed $"stopped on {s.Since}: {s.Reason}")
                        | ValueNone -> ()

                    let suspects =
                        infos
                        |> Array.filter (fun v -> v.Slashed)
                        |> Array.map (fun v -> v.PubKey)
                        |> Array.filter (fun pk ->
                            match registry.TryGet pk with
                            | ValueSome k -> notStopped k
                            | ValueNone -> false)
                        |> List.ofArray

                    if not suspects.IsEmpty then
                        let! _ = OnChainSlashing.check nodes registry store log time suspects ct
                        ()

                let overridden = ResizeArray<PubKey>()

                for k in registry.InState(fun s -> s = KeyState.Discovered) do
                    if db.HasRecord k.Key then
                        registry.TrySetState(k.Key, KeyState.Discovered, KeyState.HistoryChecked) |> ignore
                    elif allow.Allows k.Key then
                        overridden.Add k.Key
                    else
                        let hint =
                            // eplix import copies keystores into the data dir; a key of another
                            // backend ("local" is the local keystore module) cannot take that path.
                            if k.Backend.Name <> "local" then
                                $"key {k.Key.Short}: no slashing history (status {k.Status}); import the EIP-3076 file of the previous client with eplix slashing import, or list it in allow_start_without_history once you are sure no other machine signs with it"
                            elif k.Index.IsSome && looksNew k.Status then
                                $"key {k.Key.Short}: no slashing history; this key looks new (status {k.Status} on the beacon node). Import it with eplix import --no-signing-history, or list it in allow_start_without_history once you are sure no other machine signs with it"
                            else
                                $"key {k.Key.Short}: no slashing history (status {k.Status}); import the EIP-3076 file of the previous client, or use eplix import --no-signing-history or allow_start_without_history once you are sure no other machine signs with it"

                        if registry.Notice(k.Key, hint) then log.Warn hint else log.Debug hint

                if overridden.Count > 0 then
                    match! floorEpoch floor.Clock nodes ct with
                    | Error why -> log.Error $"could not write floor records: {why}"
                    | Ok e ->
                        match
                            Floor.write
                                db
                                floor.SlotMarks
                                floor.Clock.SlotsPerEpoch
                                e
                                KeyOrigin.StartedEmpty
                                (List.ofSeq overridden)
                        with
                        | Ok() ->
                            for k in overridden do
                                // Read as discovered before the floor await: a key drained or
                                // removed meanwhile keeps that state.
                                if registry.TrySetState(k, KeyState.Discovered, KeyState.HistoryChecked) then
                                    log.Warn
                                        $"key {k.Short}: no slashing history, starting with a floor at epoch {Floor.target e} (operator override); it signs once the chain is past the floor"
                        | Error e -> log.Error $"could not write floor records in the slashing DB: {e}"
                // The doppelganger module, when linked and on for the key, holds it back.
                registry.PromoteChecked()
                return Ok()
        }

    let refresh floor nodes registry db allow log ct = refreshWith ValueNone floor nodes registry db allow log ct
