/// Doppelganger protection as a module. Config section "doppelganger":
///   { "enabled": true, "epochs": 2, "threshold_keys": false, "liveness_from": "all" }
/// A key that passed its slashing history check waits in DoppelgangerWait instead of going
/// active. At the start of the last slot of each epoch the module asks the beacon node's liveness
/// endpoint (POST /eth/v1/validator/liveness/{epoch}) about the epoch before, so votes from that
/// epoch's last slot had a whole epoch to reach the node (at the epoch start they had
/// not). A key goes active after `epochs` epochs in a row in which no node saw it live. The epoch
/// the key started waiting in never counts: this VC may have signed in it before a restart. Every
/// key waits at every start, and a key that leaves the VC (deleted, retired) and comes back waits
/// again. Nothing is kept in the data dir, so a copied data dir
/// carries no pass. A key seen live stops the VC: the error names the key, its index, the epoch
/// and the nodes that saw it, the eplix_doppelganger_detected counter counts it, and the binary
/// exits with code 1. A failed
/// liveness call does not stop anything; it starts the key's count again, and so does an answer
/// that leaves the key out, and an epoch in which the key had no validator index yet: the count
/// runs from the epochs the node knew the key. Each epoch is checked once: after a
/// clock jump the skipped epochs are checked one by one (64 at most), and a clock that went back
/// checks nothing twice.
///
/// "liveness_from": "all" (default) asks every beacon node, so one node that missed the other
/// client's votes cannot hide them. A key any node that answered saw live never goes active.
/// It stops the VC when two or more nodes saw it, or when no node that answered for it said
/// otherwise. When one node saw it and the others that answered did not, the nodes disagree: the
/// one node may be wrong or lying, or the others may have missed the votes, also for other keys.
/// Every key still waiting then waits until restart and signs nothing, keys already active go on,
/// one error names the key and the nodes, and the counter counts each disputed key. The epoch
/// counts as checked when at least one node answered. "best" asks the best-scored node with
/// fallback, as before.
///
/// Threshold keys are skipped unless "threshold_keys" is true: the signers' own marks protect
/// them, but not against a whole copy of the key elsewhere.
module Eplix.Doppelganger.DoppelgangerModule

open System
open System.Collections.Generic
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon
open Eplix.Json

let name = "doppelganger"

/// Which beacon nodes answer the liveness question.
[<RequireQualifiedAccess>]
type LivenessFrom =
    /// Every node; any "live" counts.
    | All
    /// The best-scored node, with fallback.
    | Best

type Settings =
    {
        Enabled: bool
        /// Clean epochs in a row a key needs before it goes active.
        Epochs: uint64
        ThresholdKeys: bool
        LivenessFrom: LivenessFrom
    }

let defaults =
    {
        Enabled = true
        Epochs = 2UL
        ThresholdKeys = false
        LivenessFrom = LivenessFrom.All
    }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok defaults
    | ValueSome e ->
        match checkFields e "modules.doppelganger" [ "enabled"; "epochs"; "threshold_keys"; "liveness_from" ] with
        | [] ->
            try
                let flag name fallback =
                    match tryProp e name with
                    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
                    | ValueSome v when v.ValueKind = JsonValueKind.False -> false
                    | ValueSome _ -> fail $"{name} must be true or false"
                    | ValueNone -> fallback

                let epochs =
                    match tryProp e "epochs" with
                    | ValueSome v -> bounded "epochs" 1UL 64UL v
                    | ValueNone -> defaults.Epochs

                let from =
                    match tryProp e "liveness_from" with
                    | ValueSome v ->
                        match str v with
                        | "all" -> LivenessFrom.All
                        | "best" -> LivenessFrom.Best
                        | other -> fail $"liveness_from '{other}' is not all or best"
                    | ValueNone -> defaults.LivenessFrom

                Ok
                    {
                        Enabled = flag "enabled" defaults.Enabled
                        Epochs = epochs
                        ThresholdKeys = flag "threshold_keys" defaults.ThresholdKeys
                        LivenessFrom = from
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.doppelganger: {x.Message}" ]
        | errs -> Error errs

/// What the beacon nodes that answered a liveness request said about one validator.
[<RequireQualifiedAccess>]
type Seen =
    /// No node answered for it.
    | NoAnswer
    | NotLive
    /// Live, per these nodes: two or more said so, or no node that answered for it said otherwise.
    | Live of nodes: string list
    /// One node saw it live, and the other nodes that answered for it did not: every waiting key
    /// waits until restart.
    | Disputed of live: string * notLive: string list

/// One beacon node's liveness answer: per validator index, whether the node saw it live.
type NodeLiveness =
    {
        Node: string
        Live: IReadOnlyDictionary<ValidatorIndex, bool>
    }

module Liveness =
    let read (node: string) (answer: (ValidatorIndex * bool)[]) =
        let live = Dictionary<ValidatorIndex, bool>()

        for i, l in answer do
            live[i] <-
                l
                || (match live.TryGetValue i with
                    | true, v -> v
                    | _ -> false)

        { Node = node; Live = live }

    /// A live answer stops the VC when two or more nodes give it, or when no node that answered
    /// for the validator says otherwise. One node's live answer against the others' is disputed:
    /// every waiting key waits until restart, so no key goes active after the nodes disagreed, but
    /// that one node cannot stop the VC on its own.
    let seen (answers: NodeLiveness[]) (i: ValidatorIndex) : Seen =
        let said (value: bool) =
            [
                for a in answers do
                    match a.Live.TryGetValue i with
                    | true, l when l = value -> a.Node
                    | _ -> ()
            ]

        match said true, said false with
        | [], [] -> Seen.NoAnswer
        | [], _ -> Seen.NotLive
        | [ one ], (_ :: _ as notLive) -> Seen.Disputed(one, notLive)
        | live, _ -> Seen.Live live

/// The check itself, apart from the module plumbing so tests drive it epoch by epoch.
type Checker
    (settings: Settings, registry: KeyRegistry, nodes: BeaconNodes, clock: SlotClock, log: Log, shutdown: string -> unit)
    =
    let gate = obj ()
    /// Per waiting key, the last epoch that does not count; clean epochs after it count.
    let since = Dictionary<PubKey, Epoch>()

    let currentEpoch () =
        match clock.CurrentSlot with
        | ValueSome s -> clock.EpochOf s
        | ValueNone -> 0UL

    /// Per waiting key, the last epoch checked clean (from `since` on, without a gap).
    let cleanTo = Dictionary<PubKey, Epoch>()

    /// Keys that went through Hold in this process. A second Hold for a key means it left (a
    /// delete, a retirement after its signer stopped listing it) and came back; the log says so.
    let entered = HashSet<PubKey>()

    /// Keys one beacon node saw live while another that answered did not (Seen.Disputed), each
    /// counted once.
    let held = HashSet<PubKey>()

    /// Set at the first dispute: from then on no waiting key goes active until the process ends,
    /// also when the nodes go on answering not live. A node that missed one key's votes may have
    /// missed another's.
    let mutable holdAll = false

    /// Per key, how many times it entered the wait. A liveness check that started before a key
    /// left and came back writes nothing for the new entry.
    let generation = Dictionary<PubKey, int>()

    let generationOf (k: PubKey) =
        match generation.TryGetValue k with
        | true, g -> g
        | _ -> 0

    /// Liveness of `indices` in one epoch: each answering node's name with its answer, the
    /// indices it answered for and whether it saw each live. Error when no node answered at all.
    let liveness (epoch: Epoch) (indices: ValidatorIndex list) (ct: CancellationToken) =
        task {
            let ask (b: BeaconClient) =
                task {
                    match! b.Liveness(epoch, indices, ct) with
                    | Ok xs -> return Ok(Liveness.read b.Name xs)
                    | Error e -> return Error e
                }

            match settings.LivenessFrom with
            | LivenessFrom.Best ->
                match! nodes.Call(ask, NodeRole.Duties) with
                | Ok x -> return Ok [| x |]
                | Error e -> return Error e.Describe
            | LivenessFrom.All ->
                let! answers = nodes.AskAll(ask, NodeRole.Duties)

                let ok =
                    answers
                    |> Array.choose (fun r ->
                        match r with
                        | Ok x -> Some x
                        | Error _ -> None)

                if ok.Length = 0 then
                    let first =
                        answers
                        |> Array.tryPick (fun r ->
                            match r with
                            | Error e -> Some e.Describe
                            | Ok _ -> None)

                    return Error(defaultArg first "no beacon node")
                else
                    if ok.Length < answers.Length then
                        log.Debug
                            $"doppelganger: {answers.Length - ok.Length} of {answers.Length} beacon nodes did not answer liveness for epoch {epoch}"

                    return Ok ok
        }

    /// Epochs checked in one call at most, after a long stop of the clock or the process.
    let maxGap = 64UL

    /// Whether a history-checked key waits. Installed as the registry's ActivationHold.
    member _.Hold(k: RegisteredKey) : bool =
        if not settings.Enabled then
            false
        elif Threshold.isGroup k.Backend && not settings.ThresholdKeys then
            false
        else
            lock gate (fun () ->
                let back = not (entered.Add k.Key)
                generation[k.Key] <- generationOf k.Key + 1
                // A key that left and came back starts a new count: one removed and imported
                // again during a liveness call must not keep the clean epochs from before.
                if back then
                    since.Remove k.Key |> ignore
                    cleanTo.Remove k.Key |> ignore

                if not (since.ContainsKey k.Key) then
                    let e = currentEpoch ()
                    since[k.Key] <- e
                    let again = if back then " again (it left and came back)" else ""

                    if holdAll then
                        log.Info
                            $"key {k.Key.Short}: doppelganger check{again}; it waits until the VC restarts, as the beacon nodes disagreed on a key before (see the DOPPELGANGER? error)"
                    elif k.Index.IsSome then
                        log.Info
                            $"key {k.Key.Short}: doppelganger check{again}, signs from the last slot of epoch {e + settings.Epochs + 1UL} if no beacon node sees it live before"
                    else
                        log.Info
                            $"key {k.Key.Short}: doppelganger check{again}; the beacon node has no index for it yet, so the {settings.Epochs} clean epochs count from when it has one"

                true)

    /// Keys in DoppelgangerWait and the epoch their count starts after.
    member _.Waiting: (PubKey * Epoch) list = lock gate (fun () -> [ for KeyValue(k, e) in since -> k, e ])

    /// Runs in the last slot of `epoch`. Checks every epoch from the last one checked to the epoch
    /// before `epoch` (one, unless the clock jumped) and moves keys with enough clean epochs in a
    /// row to active. A key some node
    /// did not answer for starts its count again, as a failed call does. A clock that went back
    /// checks nothing twice.
    member _.OnEpochEnd (epoch: Epoch) (ct: CancellationToken) : Task =
        task {
            let waiting = registry.InState(fun s -> s = KeyState.DoppelgangerWait)

            lock gate (fun () ->
                // Keys removed or halted meanwhile leave the check.
                let still = HashSet(waiting |> List.map (fun k -> k.Key))

                for k in List.ofSeq since.Keys do
                    if not (still.Contains k) then
                        since.Remove k |> ignore
                        cleanTo.Remove k |> ignore)

            if epoch > 0UL && not waiting.IsEmpty then
                let checkedEpoch = epoch - 1UL
                // The entry each key is in now. Taken before anything is read, so a key that
                // leaves and comes back during this check gets none of its results.
                let startedAt =
                    lock gate (fun () ->
                        Dictionary(waiting |> List.map (fun k -> KeyValuePair(k.Key, generationOf k.Key))))

                let same (k: PubKey) =
                    startedAt.TryGetValue k
                    |> function
                        | true, g -> g = generationOf k
                        | _ -> false
                // Per key, the first epoch not yet checked.
                let due =
                    waiting
                    |> List.choose (fun k ->
                        lock gate (fun () ->
                            match since.TryGetValue k.Key with
                            | true, s ->
                                let from =
                                    (match cleanTo.TryGetValue k.Key with
                                     | true, c -> c
                                     | _ -> s)
                                    + 1UL

                                if from > checkedEpoch then
                                    None
                                elif checkedEpoch - from >= maxGap then
                                    // Too long a gap: the epochs before the last maxGap do not count.
                                    since[k.Key] <- checkedEpoch - maxGap
                                    cleanTo[k.Key] <- checkedEpoch - maxGap
                                    Some(k, checkedEpoch - maxGap + 1UL)
                                else
                                    Some(k, from)
                            | _ ->
                                // Put in wait before this checker saw it (a restart of the module): start now.
                                since[k.Key] <- checkedEpoch
                                None))

                let seenLive = ResizeArray<RegisteredKey * Epoch * string list>()
                let restarted = HashSet<PubKey>()

                if not due.IsEmpty then
                    let first = due |> List.map snd |> List.min
                    let mutable c = first

                    while c <= checkedEpoch && seenLive.Count = 0 do
                        let atC = due |> List.filter (fun (k, from) -> from <= c && not (restarted.Contains k.Key))
                        let indices = atC |> List.choose (fun (k, _) -> Option.ofValueOption k.Index)

                        let! answer = if indices.IsEmpty then Task.FromResult(Ok [||]) else liveness c indices ct

                        let restart (k: RegisteredKey) =
                            restarted.Add k.Key |> ignore

                            lock gate (fun () ->
                                if same k.Key then
                                    since[k.Key] <- c
                                    cleanTo[k.Key] <- c)

                        for k, _ in atC do
                            match answer, k.Index with
                            | Ok answers, ValueSome i ->
                                match Liveness.seen answers i with
                                | Seen.Live nodes -> seenLive.Add((k, c, nodes))
                                | Seen.Disputed(live, notLive) ->
                                    // Not stopped: every waiting key waits until restart, and
                                    // the active keys go on.
                                    restart k

                                    let first, counted =
                                        lock gate (fun () ->
                                            let first = not holdAll
                                            holdAll <- true
                                            first, held.Add k.Key)

                                    if counted then
                                        Metrics.doppelgangerDetected.Add(
                                            1L,
                                            KeyValuePair<string, objnull>("key", box k.Key.Hex)
                                        )

                                    if first then
                                        let others = String.Join(", ", notLive)

                                        log.Error
                                            $"DOPPELGANGER? key {k.Key.Hex} (index {i}): beacon node {live} saw it live in epoch {c}, beacon node {others} did not. Every waiting key ({waiting.Length}) waits until the VC restarts and signs nothing; active keys go on. If another validator client signs with this key, stop that client; if {live} is wrong, take it out of the config. Then restart"
                                | Seen.NoAnswer ->
                                    restart k

                                    log.Warn
                                        $"key {k.Key.Short}: no beacon node answered its liveness for epoch {c}; the count starts again"
                                | Seen.NotLive ->
                                    lock gate (fun () ->
                                        if same k.Key then
                                            cleanTo[k.Key] <- c)
                            | Error e, ValueSome _ ->
                                restart k

                                log.Warn
                                    $"key {k.Key.Short}: doppelganger liveness for epoch {c} failed ({e}); the count starts again"
                            | _, ValueNone ->
                                // No index, nothing to ask: the epoch does not count. The node
                                // may lag behind a chain on which the key is active.
                                restart k
                                log.Debug $"key {k.Key.Short}: no validator index yet; epoch {c} does not count"

                        c <- c + 1UL

                if seenLive.Count > 0 then
                    // Another client signs with these keys: stop the VC, activate nothing.
                    for k, _, _ in seenLive do
                        Metrics.doppelgangerDetected.Add(1L, KeyValuePair<string, objnull>("key", box k.Key.Hex))

                    let keys =
                        seenLive
                        |> Seq.map (fun (k, _, nodes) ->
                            let by = String.concat ", " nodes
                            $"{k.Key.Hex} (index {defaultValueArg k.Index 0UL}, seen by beacon node {by})")
                        |> String.concat ", "

                    let _, liveEpoch, _ = seenLive[0]

                    shutdown
                        $"DOPPELGANGER: {keys} live in epoch {liveEpoch}, while this VC had not signed with them. Another validator client signs with these keys. Stop it, then start Eplix again; each key then waits {settings.Epochs} clean epochs before it signs."
                else
                    for k, _ in due do
                        let passedNow =
                            lock gate (fun () ->
                                match since.TryGetValue k.Key, cleanTo.TryGetValue k.Key with
                                | (true, s), (true, clean) when
                                    clean >= s + settings.Epochs && same k.Key && not holdAll
                                    ->
                                    since.Remove k.Key |> ignore
                                    cleanTo.Remove k.Key |> ignore
                                    true
                                | _ -> false)
                        // Only a key still waiting goes active: one drained, removed or halted
                        // during the liveness calls keeps that state.
                        if passedNow && registry.TrySetState(k.Key, KeyState.DoppelgangerWait, KeyState.Active) then
                            log.Info
                                $"key {k.Key.Short}: doppelganger check passed ({settings.Epochs} epochs not seen live); active"
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
            fun _ ->
                let s = settings.Value

                if s.Enabled then
                    let from =
                        match s.LivenessFrom with
                        | LivenessFrom.All -> "liveness from every node"
                        | LivenessFrom.Best -> "liveness from the best node"

                    Ok $"on: {s.Epochs} epochs, every start, {from}"
                else
                    Ok "off"
        Start =
            fun core _ ->
                task {
                    let s = settings.Value

                    if s.Enabled then
                        let checker = Checker(s, core.Registry, core.Nodes, core.Clock, core.Log, core.Shutdown)
                        core.Registry.ActivationHold <- checker.Hold
                        let spe = core.Spec.SlotsPerEpoch
                        // One check at a time, in epoch order.
                        let running = new SemaphoreSlim(1, 1)

                        core.AddDutyExtension
                            { DutyExtension.empty name with
                                RunSlot =
                                    fun _ slot ct ->
                                        task {
                                            if (slot + 1UL) % spe = 0UL then
                                                do! running.WaitAsync ct

                                                try
                                                    do! checker.OnEpochEnd (slot / spe) ct
                                                finally
                                                    running.Release() |> ignore
                                        }
                            }

                        core.Log.Info
                            $"doppelganger protection on: keys wait {s.Epochs} epochs without liveness before they sign"

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
