/// The key registry: each key's state, route, chain index and settings.
/// States: discovered -> history-checked -> (doppelganger-wait ->) active -> draining -> removed,
/// and halted on a divergence alarm. Doppelganger-wait only with the doppelganger module.
namespace Eplix

open System.Collections.Generic

[<RequireQualifiedAccess>]
type KeyState =
    | Discovered
    /// The key has a slashing record, imported or explicitly started empty.
    | HistoryChecked
    /// The doppelganger module holds the key back until the chain shows no other signer with it.
    | DoppelgangerWait
    | Active
    /// Being removed: no new duty starts, signatures in flight finish.
    | Draining
    /// A tombstone: the key never signs again in this process unless imported again.
    | Removed
    /// The divergence alarm: a remote signer refused as slashable what the VC's DB allowed. A
    /// refusal without a reason (Dirk's DENIED) never halts a key.
    | Halted of reason: string
    /// The chain shows the validator slashed. The key signs nothing, exits included, and the
    /// state stays until the key is removed. `<data_dir>/slashed-keys.json` keeps it across restarts.
    | Slashed of reason: string

/// Per-key settings: fee recipient, gas limit, graffiti and the builder flow. ValueNone means the next layer down
/// decides, in the end the core config defaults.
type KeySettings =
    {
        FeeRecipient: string voption
        GasLimit: uint64 voption
        Graffiti: string voption
        /// Pre-Gloas builder flow (the legacy builder module): register with relays and ask for
        /// builder blocks. ValueNone: the module's default.
        BuilderEnabled: bool voption
        /// builder_boost_factor of produceBlockV3 for an enabled key. ValueNone: the module's default.
        BuilderBoostFactor: uint64 voption
    }

    static member Default =
        {
            FeeRecipient = ValueNone
            GasLimit = ValueNone
            Graffiti = ValueNone
            BuilderEnabled = ValueNone
            BuilderBoostFactor = ValueNone
        }

    /// Field by field: this value where set, else the value of `lower`.
    member this.Over(lower: KeySettings) =
        {
            FeeRecipient = (if this.FeeRecipient.IsSome then this.FeeRecipient else lower.FeeRecipient)
            GasLimit = (if this.GasLimit.IsSome then this.GasLimit else lower.GasLimit)
            Graffiti = (if this.Graffiti.IsSome then this.Graffiti else lower.Graffiti)
            BuilderEnabled = (if this.BuilderEnabled.IsSome then this.BuilderEnabled else lower.BuilderEnabled)
            BuilderBoostFactor =
                (if this.BuilderBoostFactor.IsSome then this.BuilderBoostFactor else lower.BuilderBoostFactor)
        }

/// The operator's proposer config file (ProposerConfig.fs reads it): defaults and per-key entries.
type ProposerFile =
    {
        Defaults: KeySettings
        Keys: Map<PubKey, KeySettings>
    }

    static member Empty =
        {
            Defaults = KeySettings.Default
            Keys = Map.empty
        }

type RegisteredKey =
    {
        Key: PubKey
        mutable Backend: Backend
        mutable State: KeyState
        mutable Index: ValidatorIndex voption
        mutable Status: string
        /// The effective settings (see KeyRegistry.SettingsOf). ValueNone fields take the core defaults.
        mutable Settings: KeySettings
    }

type KeyRegistry() =
    let keys = Dictionary<PubKey, RegisteredKey>()
    /// Settings by key, also for keys not (or no longer) registered, so a key that arrives later
    /// gets the settings the keymanager API stored for it.
    let settings = Dictionary<PubKey, KeySettings>()
    let mutable proposerFile = ProposerFile.Empty
    let gate = obj ()
    let mutable version = 0L
    /// Requests a remote signer denied, by key, since the start.
    let denials = Dictionary<PubKey, int64>()
    /// The last notice logged per key (Notice), so a waiting key warns once, not every epoch.
    let notices = Dictionary<PubKey, string>()
    let mutable activationOpen = true
    /// Keys refused until restart, with the reason (Refuse).
    let refused = Dictionary<PubKey, string>()

    let bump () = version <- version + 1L

    /// Whether a key is in use: not draining and not removed.
    let live (k: RegisteredKey) =
        match k.State with
        | KeyState.Draining
        | KeyState.Removed -> false
        | _ -> true

    /// The refusal reason when `backend` would give a live key a second route of the other kind:
    /// whole on one backend and split in a threshold group, where the whole copy would sign alone. Called under the lock.
    let mixed (key: PubKey) (backend: Backend) =
        match keys.TryGetValue key with
        | true, k when live k && Threshold.isGroup k.Backend <> Threshold.isGroup backend ->
            let whole, group = if Threshold.isGroup backend then k.Backend, backend else backend, k.Backend

            ValueSome
                $"whole on {whole.Name} and split in {group.Name}; neither route signs. Remove the whole key or the group's shares, then restart"
        | _ -> ValueNone

    /// Marks a key refused and takes it out. Called under the lock; true the first time.
    let refuse (key: PubKey) (reason: string) =
        let first = refused.TryAdd(key, reason)

        match keys.TryGetValue key with
        | true, k when k.State <> KeyState.Removed ->
            // Straight to removed: a request that already passed the state check finishes, and
            // no new one starts. Nothing to clean up, unlike a drain.
            k.State <- KeyState.Removed
            bump ()
        | _ -> ()

        first

    let stored key =
        match settings.TryGetValue key with
        | true, s -> s
        | _ -> KeySettings.Default

    /// Per field: the file's entry for the key, the API's stored setting, the file's defaults.
    let effective key =
        let api = stored key

        let upper =
            match proposerFile.Keys.TryFind key with
            | Some f -> f.Over api
            | None -> api

        upper.Over proposerFile.Defaults

    let fresh key backend =
        {
            Key = key
            Backend = backend
            State = KeyState.Discovered
            Index = ValueNone
            Status = "unknown"
            Settings = effective key
        }

    /// Decides whether a history-checked key waits in DoppelgangerWait instead of going active.
    /// The doppelganger module sets it; without the module every key goes active at once.
    member val ActivationHold: RegisteredKey -> bool = (fun _ -> false) with get, set

    /// Keeps every history-checked key in that state until OpenActivation. The runner closes it
    /// before any module starts, so a keymanager import or a key refresh during the start cannot
    /// make a key active before the doppelganger module has set ActivationHold.
    member _.CloseActivation() = lock gate (fun () -> activationOpen <- false)

    /// Ends CloseActivation and moves the history-checked keys on.
    member this.OpenActivation() =
        lock gate (fun () -> activationOpen <- true)
        this.PromoteChecked()

    /// Moves each history-checked key to DoppelgangerWait or Active, as ActivationHold says.
    /// Does nothing while activation is closed. A key whose state changed meanwhile keeps it.
    member this.PromoteChecked() =
        if lock gate (fun () -> activationOpen) then
            for k in this.InState(fun s -> s = KeyState.HistoryChecked) do
                let next = if this.ActivationHold k then KeyState.DoppelgangerWait else KeyState.Active

                lock gate (fun () ->
                    match keys.TryGetValue k.Key with
                    | true, k when k.State = KeyState.HistoryChecked ->
                        k.State <- next
                        bump ()
                    | _ -> ())

    /// Changes whenever a key is added, removed or changes state or index. The scheduler fetches
    /// duties again when it moves.
    member _.Version = lock gate (fun () -> version)

    /// Logs each key refusal once (Refuse). The runner sets it to the VC's log.
    member val Log = Log.none with get, set

    /// Takes a key out until the VC restarts and keeps Add and Revive from routing it again
    /// (shares not on one split, or a key both whole and split). Logged once per key as an error; counted in
    /// `eplix_keys_refused`.
    member this.Refuse(key: PubKey, reason: string) =
        if lock gate (fun () -> refuse key reason) then
            this.Log.Error $"key {key.Hex} refused until restart: {reason}"

    /// True when the key is refused until restart (Refuse).
    member _.IsRefused(key: PubKey) : bool = lock gate (fun () -> refused.ContainsKey key)

    /// The refused keys with their reasons.
    member _.Refused: (PubKey * string) list = lock gate (fun () -> [ for KeyValue(k, r) in refused -> k, r ])

    /// Adds a key routed to one backend. A key already present keeps its route; a removed key
    /// stays removed (see Revive). A refused key is not added, and a key whole on one backend
    /// and split in a group is refused.
    member this.Add(key: PubKey, backend: Backend) : bool =
        let result =
            lock gate (fun () ->
                if refused.ContainsKey key then
                    Ok false
                else
                    match mixed key backend with
                    | ValueSome why -> Error why
                    | ValueNone when keys.ContainsKey key -> Ok false
                    | ValueNone ->
                        keys[key] <- fresh key backend
                        bump ()
                        Ok true)

        match result with
        | Ok added -> added
        | Error why ->
            this.Refuse(key, why)
            false

    /// Brings back a removed key after an explicit import, as discovered, so it passes the
    /// history check again. Adds the key if it is new. A refused key stays out, as in Add.
    member this.Revive(key: PubKey, backend: Backend) : bool =
        let result =
            lock gate (fun () ->
                if refused.ContainsKey key then
                    Ok false
                else
                    match mixed key backend with
                    | ValueSome why -> Error why
                    | ValueNone ->
                        match keys.TryGetValue key with
                        | true, k when k.State = KeyState.Removed ->
                            k.Backend <- backend
                            k.State <- KeyState.Discovered
                            bump ()
                            Ok true
                        | true, _ -> Ok false
                        | _ ->
                            keys[key] <- fresh key backend
                            bump ()
                            Ok true)

        match result with
        | Ok added -> added
        | Error why ->
            this.Refuse(key, why)
            false

    member _.TryGet(key: PubKey) : RegisteredKey voption =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, k -> ValueSome k
            | _ -> ValueNone)

    member _.All: RegisteredKey list = lock gate (fun () -> List.ofSeq keys.Values)

    member this.InState(pred: KeyState -> bool) = this.All |> List.filter (fun k -> pred k.State)

    member this.Active = this.InState(fun s -> s = KeyState.Active)

    /// Keys that are neither draining nor removed.
    member this.Live =
        this.InState(fun s ->
            match s with
            | KeyState.Draining
            | KeyState.Removed -> false
            | _ -> true)

    /// Changes a key's state. A slashed key only leaves that state to be drained or removed. A
    /// refused key stays removed, so a caller that read the key before the refusal and sets its
    /// state after it cannot route it again; only Revive leaves Removed, and it skips refused keys.
    member _.SetState(key: PubKey, state: KeyState) =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, { State = KeyState.Slashed _ } when
                (match state with
                 | KeyState.Draining
                 | KeyState.Removed -> false
                 | _ -> true)
                ->
                ()
            | true, { State = KeyState.Removed } when refused.ContainsKey key -> ()
            | true, k when k.State <> state ->
                k.State <- state
                bump ()
            | _ -> ())

    /// Sets a key draining, as SetState does, unless it is halted. Returns false for a halted
    /// key, which keeps its state: a halt holds until restart. The check and the change happen
    /// under one lock, so a halt cannot slip in between.
    member this.TryDrain(key: PubKey) : bool =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, { State = KeyState.Halted _ } -> false
            | _ ->
                this.SetState(key, KeyState.Draining)
                true)

    /// Changes a key's state only while it is still `expected`, the state the caller read, and
    /// returns true when it did. A caller that read the key before an await uses this instead of
    /// SetState, so a drain, removal or refusal meanwhile wins and the key does not come back.
    /// The guards of SetState apply too.
    member _.TrySetState(key: PubKey, expected: KeyState, next: KeyState) : bool =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, k when k.State = expected ->
                let blocked =
                    match k.State, next with
                    | KeyState.Slashed _, (KeyState.Draining | KeyState.Removed) -> false
                    | KeyState.Slashed _, _ -> true
                    | KeyState.Removed, _ -> refused.ContainsKey key
                    | _ -> false

                if not blocked && k.State <> next then
                    k.State <- next
                    bump ()

                not blocked
            | _ -> false)

    /// Counts a request a remote signer denied for the key and returns the key's count.
    member _.NoteDenial(key: PubKey) : int64 =
        lock gate (fun () ->
            let n =
                (match denials.TryGetValue key with
                 | true, n -> n
                 | _ -> 0L)
                + 1L

            denials[key] <- n
            n)

    /// True when `text` differs from the last notice for the key, which it then becomes.
    member _.Notice(key: PubKey, text: string) : bool =
        lock gate (fun () ->
            match notices.TryGetValue key with
            | true, t when t = text -> false
            | _ ->
                notices[key] <- text
                true)

    member _.Denials(key: PubKey) : int64 =
        lock gate (fun () ->
            match denials.TryGetValue key with
            | true, n -> n
            | _ -> 0L)

    member _.SetChainInfo(key: PubKey, index: ValidatorIndex, status: string) =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, k ->
                if k.Index <> ValueSome index then
                    bump ()

                k.Index <- ValueSome index
                k.Status <- status
            | _ -> ())

    /// Changes the settings the keymanager API stored for a key, registered or not.
    member _.SetSettings(key: PubKey, f: KeySettings -> KeySettings) =
        lock gate (fun () ->
            settings[key] <- f (stored key)

            match keys.TryGetValue key with
            | true, k -> k.Settings <- effective key
            | _ -> ())

    /// The effective settings of a key: per field the proposer config file's entry for the key,
    /// then the keymanager API's stored setting, then the file's defaults. ValueNone fields take
    /// the core config defaults (CoreServices.Defaults).
    member _.SettingsOf(key: PubKey) : KeySettings = lock gate (fun () -> effective key)

    /// The graffiti set for this key alone: the proposer config file's entry, else the keymanager
    /// API's setting. ValueNone: the defaults decide (a graffiti module's text comes first).
    member _.KeyGraffiti(key: PubKey) : string voption =
        lock gate (fun () ->
            let fromFile =
                match proposerFile.Keys.TryFind key with
                | Some f -> f.Graffiti
                | None -> ValueNone

            if fromFile.IsSome then fromFile else (stored key).Graffiti)

    /// The settings the keymanager API stored for a key, without the file's layers.
    member _.StoredSettingsOf(key: PubKey) : KeySettings = lock gate (fun () -> stored key)

    /// The keymanager API's stored settings of every key, for key-settings.json.
    member _.AllSettings: (PubKey * KeySettings) list =
        lock gate (fun () -> [ for KeyValue(k, s) in settings -> k, s ])

    /// Replaces the proposer config file's layers and updates every key's effective settings.
    member _.SetProposerFile(file: ProposerFile) =
        lock gate (fun () ->
            proposerFile <- file

            for k in keys.Values do
                k.Settings <- effective k.Key)

    /// True when the proposer config file has an entry for the key. The keymanager API treats
    /// such a key's settings as read-only.
    member _.InProposerFile(key: PubKey) : bool = lock gate (fun () -> proposerFile.Keys.ContainsKey key)
