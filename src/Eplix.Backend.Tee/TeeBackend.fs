/// One TEE signer runner as Eplix sees it: its pool, the keys it lists, and backends over it,
/// one for the whole keys it holds and one per threshold group it is a member of.
namespace Eplix.Backend.Tee

open System
open System.Collections.Generic
open System.IO
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks
open Eplix

/// The runner's status codes as typed refusals. The rule: an explicit slashing refusal is Slashable (the pipeline halts the
/// key when its own DB allowed the request), a policy refusal skips the duty, a transport error
/// is a failure, and nothing without a reason halts a key.
module Mapping =

    /// tee-signer's FLOOR (1008) detail: "floor epoch N (W floor): " and the reason, W restart,
    /// import or source (signer-protocol errors.go, server.go sign). Only the start counts.
    let private floorStatusRe =
        Regex(@"\Afloor epoch ([0-9]+) \((restart|import|source) floor\)", RegexOptions.CultureInvariant)

    /// A floor epoch the key can get past: a number below UInt64.MaxValue, so N + 1 exists.
    let private floorEpoch (text: string) =
        match UInt64.TryParse(text, Globalization.NumberStyles.None, Globalization.CultureInfo.InvariantCulture) with
        | true, e when e < UInt64.MaxValue -> ValueSome e
        | _ -> ValueNone

    /// The floor behind a FLOOR or FLOOR_UNPROVEN answer, as (kind, N) from its detail's prefix.
    /// The key signs votes and blocks again from N + 1. None for any other refusal, and for a
    /// floor epoch that does not parse or is UInt64.MaxValue: the answer then waits with no epoch.
    let floorOf (r: Wire.Refusal) : struct (string * uint64) voption =
        if r.Code = Wire.Status.Floor || r.Code = Wire.Status.FloorUnproven then
            let m = floorStatusRe.Match r.Detail

            if m.Success then
                floorEpoch m.Groups[1].Value |> ValueOption.map (fun e -> struct (m.Groups[2].Value, e))
            else
                ValueNone
        else
            ValueNone

    /// The codes that say "already signed another message for this target or slot", or an
    /// attestation with a newer source (SC_ERR_SLASH_SOURCE: this VC's beacon node lags behind
    /// the peer's). With modules.tee.ha_peer they mean another VC with these keys won the duty.
    /// SC_ERR_SLASH_SOURCE_GT_TARGET is not here: a source after the target is a bad request
    /// whatever the peer signed.
    let alreadySignedCodes =
        [|
            Wire.Status.SlashTarget
            Wire.Status.SlashSource
            Wire.Status.SlashBlock
            Wire.Status.Equivocation
        |]

    let alreadySigned (code: uint16) = Array.contains code alreadySignedCodes

    /// The start line with ha_peer on, built from alreadySignedCodes so the two cannot drift.
    let haPeerStartLine =
        let names = alreadySignedCodes |> Array.map Wire.Status.name
        let listed = String.Join(", ", names[.. names.Length - 2]) + " and " + names[names.Length - 1]
        $"tee: ha_peer on: {listed} skip the duty and keep the key; other slashing refusals still halt it"

    /// A refusal lost to an HA peer. Its text goes into the log line of every such duty, so
    /// the runner's detail is cut and cleaned here, as a group member's refusal is.
    let private lostToPeer (why: string) = Refused(LostToPeer(Threshold.cleanReason why))

    /// A refusal by its code; the detail matters only for a floor epoch and a missing SIGN kind.
    let private byCode (haPeer: bool) (duty: Duty) (why: string) (r: Wire.Refusal) : SignOutcome =
        match r.Code with
        // A slashing code is a conflict: the key halts. With ha_peer, a refusal that says another
        // VC already signed this duty skips the duty and keeps the key.
        | c when Wire.Status.isSlashing c ->
            if haPeer && alreadySigned c then lostToPeer why else Refused(Slashable why)
        // Only a floor refuses (FLOOR), or the runner's mark log but not the key's own history
        // (FLOOR_UNPROVEN): the duty is skipped and the key waits, never halts. A runner with a
        // real conflict at or below its floor sends a slashing code instead.
        | c when c = Wire.Status.Floor || c = Wire.Status.FloorUnproven ->
            match floorOf r with
            | ValueSome(struct (_, e)) -> Refused(Refusal.NotReadyUntil(ValueSome(e + 1UL)))
            | ValueNone -> Refused(Refusal.NotReadyUntil ValueNone)
        | c when c = Wire.Status.PolicyDomain || c = Wire.Status.DomainMismatch -> Refused DomainMismatch
        | c when
            (c >= Wire.Status.PolicyFuture && c <= Wire.Status.PolicyEnvelope)
            || c = Wire.Status.SelectionProof
            || c = Wire.Status.Schedule
            || c = Wire.Status.PolicyBuilderAuth
            || c = Wire.Status.PolicyTargetSlot
            || c = Wire.Status.Forbidden
            || c = Wire.Status.RateLimited
            ->
            Refused(PolicyDenied why)
        | c when c = Wire.Status.UnknownValidator -> Refused UnknownKey
        | c when c = Wire.Status.Unsupported -> Refused(Unsupported duty.Kind)
        // A runner without a SIGN kind answers it with BAD_REQUEST "no SSZ encoding for <kind>":
        // the runner lacks the kind, so Unsupported.
        | c when c = Wire.Status.BadRequest && r.Detail.StartsWith("no SSZ encoding", StringComparison.Ordinal) ->
            Refused(Unsupported duty.Kind)
        | c when c = Wire.Status.NotReady || c = Wire.Status.Clock -> Refused(Refusal.NotReadyUntil ValueNone)
        | c when
            c = Wire.Status.Arg
            || c = Wire.Status.Decode
            || c = Wire.Status.BadRequest
            || c = Wire.Status.BadKey
            || c = Wire.Status.Duplicate
            ->
            Refused(BadRequest why)
        // Storage (a handed-over or broken store), Internal, Platform, NoMem and codes this
        // build does not know: the runner could not sign.
        | _ -> Failed(Internal why)

    /// The outcome of a refusal; `haPeer` is modules.tee.ha_peer.
    let toOutcomeWith (haPeer: bool) (runner: string) (duty: Duty) (r: Wire.Refusal) : SignOutcome =
        let s = Wire.Status.name r.Code
        let why = if r.Detail = "" then $"{runner}: {s}" else $"{runner}: {s}: {r.Detail}"
        byCode haPeer duty why r

    /// toOutcomeWith without ha_peer.
    let toOutcome (runner: string) (duty: Duty) (r: Wire.Refusal) : SignOutcome = toOutcomeWith false runner duty r

    /// Requests in the high class of the pool: the ones a slot's timing depends on. Builder
    /// request auth follows the request's priority: low an epoch ahead, high when a proposal
    /// waits for it.
    let classOf (req: SignRequest) =
        match req.Duty with
        | Duty.Attestation _
        | Duty.Block _
        | Duty.RandaoReveal _
        | Duty.PayloadAttestation _
        | Duty.PayloadEnvelope _ -> PoolClass.High
        | Duty.BuilderRequestAuth _ when req.Priority = Priority.High -> PoolClass.High
        | _ -> PoolClass.Low

/// What a runner's HEALTH says about its signing.
[<RequireQualifiedAccess>]
type RunnerSignState =
    /// No HEALTH answer read yet, or a new connection since the last answer (the runner may
    /// run another build now). It gets no SIGN: its protocol level is not known. The first
    /// request asks HEALTH and waits for the answer.
    | Pending
    /// Signs every kind.
    | Ready
    /// Refuses to sign for now: it answers only HEALTH, PUBLIC_KEYS, ATTEST and IDENTITY and
    /// gives every other request NOT_READY. It gets no SIGN until HEALTH says it signs.
    | Refusing of label: string * why: string
    /// No longer serves its keys (its mark log is lost). It gets no SIGN, and the operator acts.
    | Gone of label: string * why: string
    /// No HEALTH answer for over an epoch, after an answer that showed protocol level 2 or
    /// higher. Requests go to it, and its own answers decide.
    | Unknown of why: string

/// A HEALTH answer as a RunnerSignState. One table: a new runner state is a new row.
module HealthStates =
    /// A refusal state: its label (the state label of eplix_signer_state), whether it is gone,
    /// and the test that gives the reason when the answer is in that state.
    type Row =
        {
            Label: string
            Gone: bool
            Test: Wire.RunnerHealth -> string voption
        }

    let private field (h: Wire.RunnerHealth) (n: string) =
        match h.Fields.TryFind n with
        | Some v -> v
        | None -> ""

    /// A string field that says something when it is not empty (mark_log_lost, request_panic).
    let private text (n: string) (why: string -> string) (h: Wire.RunnerHealth) =
        let v = field h n
        if v <> "" then ValueSome(why v) else ValueNone

    /// An image check state that refuses (image.state; allowed, not_applicable and override pass).
    let private image (state: string) : Row =
        {
            Label = $"image_{state}"
            Gone = false
            Test =
                fun h ->
                    if field h "image.state" = state then
                        let why = field h "image.why"

                        ValueSome(
                            if why = "" then $"its image check says {state}" else $"its image check says {state}: {why}"
                        )
                    else
                        ValueNone
        }

    /// The first row that matches decides: the gone row first, then the refusals. A runner whose
    /// mark log is lost is gone: the operator must remove it or move its keys. A runner below
    /// protocol level 2 refuses before any other refusal: its other answers mean something else.
    /// key_lock and key_lock_why only explain a lock: ready false is the refusal.
    let rows: Row list =
        [
            {
                Label = "log_lost"
                Gone = true
                Test = text "mark_log_lost" (fun v -> $"its slashing mark log is lost: {v}")
            }
            {
                Label = "protocol_too_old"
                Gone = false
                Test =
                    fun h ->
                        if h.Protocol < Wire.ProtocolLevel then
                            ValueSome
                                $"it speaks protocol level {h.Protocol}; Eplix needs tee-signer protocol level {Wire.ProtocolLevel} (FLOOR/FLOOR_UNPROVEN)"
                        else
                            ValueNone
            }
            image "not_allowed"
            image "restart_needed"
            image "unknown"
            {
                Label = "request_panic"
                Gone = false
                Test = text "request_panic" (fun v -> $"a request panicked: {v}")
            }
            {
                Label = "not_ready"
                Gone = false
                Test =
                    fun h ->
                        if field h "ready" = "false" then
                            let why = field h "key_lock_why"
                            let lock = field h "key_lock"

                            ValueSome(
                                match lock, why with
                                | "", "" -> "it reports ready false"
                                | l, "" -> $"it reports ready false (key_lock {l})"
                                | "", w -> $"it reports ready false ({w})"
                                | l, w -> $"it reports ready false (key_lock {l}: {w})"
                            )
                        else
                            ValueNone
            }
        ]

    /// The state of a HEALTH answer.
    let classify (h: Wire.RunnerHealth) : RunnerSignState =
        let hit =
            rows
            |> List.tryPick (fun r ->
                match r.Test h with
                | ValueSome why -> Some(r, why)
                | ValueNone -> None)

        match hit with
        | Some(r, why) when r.Gone -> RunnerSignState.Gone(r.Label, why)
        | Some(r, why) -> RunnerSignState.Refusing(r.Label, why)
        | None -> RunnerSignState.Ready

    /// The state's label: pending, ready, unknown, or the row's label.
    let label (s: RunnerSignState) =
        match s with
        | RunnerSignState.Pending -> "pending"
        | RunnerSignState.Ready -> "ready"
        | RunnerSignState.Refusing(l, _)
        | RunnerSignState.Gone(l, _) -> l
        | RunnerSignState.Unknown _ -> "unknown"

    /// The runner signs under a testnet-only override of its image check (image.state override).
    let imageOverride (h: Wire.RunnerHealth) = field h "image.state" = "override"

/// What a request to the runner gave, before it is read as a SignOutcome.
[<RequireQualifiedAccess>]
type Reply =
    | Body of byte[]
    | Refused of Wire.Refusal
    | Failure of SignFailure
    /// Not sent: the send gate held the request back once it had its connection.
    | Held

/// The calls Eplix makes to one runner, as a record of functions: the pool below is one
/// implementation, tests use fakes.
type RunnerApi =
    {
        Name: string
        Call: PoolClass -> Wire.MsgType -> byte[] -> CancellationToken -> Task<Reply>
        /// Connections up, of the pool size.
        Up: unit -> int * int
        LastError: unit -> string
        /// Fires after each new connection (the endpoint reads HEALTH then).
        Connected: IEvent<unit>
        /// Fires when a connection comes up while none was up, before any request gets it.
        FirstUp: IEvent<unit>
        /// Sets the check a request runs once it has its connection, before it is sent: true
        /// holds it back unsent (Reply.Held).
        SetSendGate: (Wire.MsgType -> bool) -> unit
        Close: unit -> unit
    }

module RunnerApi =
    /// A runner behind a connection pool. A request that fails on a broken connection before an
    /// answer is sent once more on another connection while its token allows: the same bytes,
    /// an exact repeat, which the runner signs again.
    let ofPool (pool: ConnectionPool<RunnerConnection>) : RunnerApi =
        let mutable sendGate: Wire.MsgType -> bool = fun _ -> false

        let once (cls: PoolClass) (t: Wire.MsgType) (payload: byte[]) (ct: CancellationToken) =
            task {
                match! pool.Take(cls, ct) with
                | Error _ when ct.IsCancellationRequested -> return Reply.Failure SignFailure.Timeout, false
                | Error e -> return Reply.Failure(Transport $"{pool.Name}: {e}"), false
                | Ok c ->
                    try
                        try
                            if sendGate t then
                                return Reply.Held, false
                            else
                                let! f = c.Send(t, payload, ct)

                                match Wire.decodeResponse f.Payload with
                                | Ok b -> return Reply.Body b, false
                                | Error r -> return Reply.Refused r, false
                        with
                        | :? OperationCanceledException -> return Reply.Failure SignFailure.Timeout, false
                        | :? Wire.WireError as e -> return Reply.Failure(Internal $"{pool.Name}: {e.Message}"), false
                        | e -> return Reply.Failure(Transport $"{pool.Name}: {e.Message}"), true
                    finally
                        pool.Done c
            }

        {
            Name = pool.Name
            Call =
                fun cls t payload ct ->
                    task {
                        let! first, retry = once cls t payload ct

                        if retry && not ct.IsCancellationRequested then
                            let! again, _ = once cls t payload ct
                            return again
                        else
                            return first
                    }
            Up =
                fun () ->
                    let struct (up, _, _, _, _) = pool.Snapshot
                    up, pool.Size
            LastError = fun () -> pool.LastError
            Connected = pool.Connected
            FirstUp = pool.FirstUp
            SetSendGate = fun g -> sendGate <- g
            Close = fun () -> pool.Close()
        }

type RunnerEndpoint(api: RunnerApi, log: Log) =
    // The key list from the last answer, replaced as a whole.
    let mutable listed: Dictionary<PubKey, Wire.RunnerKey> = Dictionary()
    let mutable answered = false
    let unknownKey = Event<unit>()
    let verifier = BatchVerifier.Shared
    // HEALTH: the state of the last answer, whether the last answer showed protocol level 2 or
    // higher, the epoch of the first failed call since, whether a call runs, and where the
    // current epoch comes from.
    let mutable signState = RunnerSignState.Pending
    let mutable protocolOk = false
    let mutable failingSince: uint64 voption = ValueNone
    let mutable polling = 0
    // modules.tee.ha_peer: "already signed" refusals are lost to the peer, not slashable.
    let mutable haPeer = false
    let mutable overrideLogged = false
    // One error per runner for a protocol level below Wire.ProtocolLevel, one warning above it.
    let mutable oldProtocolLogged = false
    let mutable newProtocolLogged = false
    let mutable epochNow: unit -> uint64 voption = fun () -> ValueNone
    let mutable epochSeen: uint64 voption = ValueNone
    // Per key, the epoch of the last floor refusal logged: one warning per key per epoch.
    let floorLogged = Collections.Concurrent.ConcurrentDictionary<PubKey, uint64>()
    // Per key and floor kind (restart, import, source; "none" when the detail gave no epoch),
    // the floor epoch of the last FLOOR_UNPROVEN alert: one alert per key, kind and floor. A key
    // can wait for a source floor and a restart floor at different epochs at once.
    let unprovenLogged = Dictionary<struct (PubKey * string), uint64>()
    let stop = new CancellationTokenSource()

    let epoch () =
        match epochNow () with
        | ValueSome e -> ValueSome e
        | ValueNone -> epochSeen

    let health (ct: CancellationToken) : Task<Result<Wire.RunnerHealth, string>> =
        task {
            match! api.Call PoolClass.Low Wire.MsgType.Health [||] ct with
            | Reply.Body b ->
                try
                    return Ok(Wire.decodeHealth b)
                with e ->
                    return Error $"{api.Name}: undecodable HEALTH: {e.Message}"
            | Reply.Refused r -> return Error $"{api.Name}: HEALTH refused: {Wire.Status.name r.Code}"
            | Reply.Failure f -> return Error $"{api.Name}: {(Failed f).Describe}"
            | Reply.Held -> return Error $"{api.Name}: HEALTH held back"
        }

    let apply (s: RunnerSignState) =
        let before = HealthStates.label signState
        signState <- s
        let now = HealthStates.label s
        Metrics.setSignerState api.Name now

        if before <> now then
            if now = "log_lost" then
                Metrics.markLogLost api.Name

            match s with
            | RunnerSignState.Gone(_, why) ->
                log.Error
                    $"{api.Name} no longer serves its keys: {why} (HEALTH state {now}); remove the runner or its keys from the config"
            | RunnerSignState.Refusing("protocol_too_old", why) ->
                if not oldProtocolLogged then
                    oldProtocolLogged <- true

                    log.Error
                        $"{api.Name} gets no requests: {why}; update the runner to a tee-signer build that reports protocol {Wire.ProtocolLevel} or higher in HEALTH"
            | RunnerSignState.Refusing(_, why) ->
                log.Warn
                    $"{api.Name} refuses to sign: {why} (HEALTH state {now}); it gets no requests until HEALTH says it signs"
            | RunnerSignState.Ready when before = "pending" -> log.Debug $"{api.Name}: HEALTH says it signs"
            | RunnerSignState.Ready -> log.Info $"{api.Name} signs again (HEALTH state {before} before)"
            | RunnerSignState.Pending -> ()
            | RunnerSignState.Unknown why ->
                log.Warn $"{api.Name}: no HEALTH answer for over an epoch ({why}); requests go to it again"

    /// One HEALTH call, unless one runs. A failed call keeps the last state in the epoch of the
    /// first failure; from the next epoch on the state is unknown, but only after an answer that
    /// showed protocol level 2 or higher. Before that the state stays (pending, protocol_too_old).
    let poll (ct: CancellationToken) : Task =
        task {
            if Interlocked.CompareExchange(&polling, 1, 0) = 0 then
                try
                    let! r = health ct
                    let e = epoch ()

                    match r with
                    | Ok h ->
                        failingSince <- ValueNone
                        protocolOk <- h.Protocol >= Wire.ProtocolLevel

                        if h.Protocol > Wire.ProtocolLevel && not newProtocolLogged then
                            newProtocolLogged <- true

                            log.Warn
                                $"{api.Name} speaks tee-signer protocol level {h.Protocol}, above level {Wire.ProtocolLevel} that this Eplix knows: some answers may mean something Eplix does not read. It stays in use; update Eplix"

                        if HealthStates.imageOverride h && not overrideLogged then
                            overrideLogged <- true
                            let why = h.Fields.TryFind "image.why" |> Option.defaultValue ""
                            log.Warn $"{api.Name} signs under an image check override (testnet only): {why}"

                        apply (HealthStates.classify h)
                    | Error why ->
                        let since =
                            match failingSince with
                            | ValueSome s -> ValueSome s
                            | ValueNone ->
                                failingSince <- e
                                e

                        match since, e with
                        | ValueSome s, ValueSome now when now > s && protocolOk -> apply (RunnerSignState.Unknown why)
                        | ValueSome s, ValueSome now when now > s ->
                            log.Debug
                                $"{api.Name}: HEALTH failed: {why}; keeping state {HealthStates.label signState}, since no answer has shown protocol level {Wire.ProtocolLevel}"
                        | _ -> log.Debug $"{api.Name}: HEALTH failed: {why}; keeping its last state for now"
                finally
                    Volatile.Write(&polling, 0)
        }

    /// A HEALTH call in the background, bounded by 10 s, ended by Close.
    let pollInBackground () =
        if not stop.IsCancellationRequested then
            task {
                try
                    use cts = CancellationTokenSource.CreateLinkedTokenSource stop.Token
                    cts.CancelAfter(TimeSpan.FromSeconds 10.0)
                    do! poll cts.Token
                with e ->
                    log.Debug $"{api.Name}: HEALTH call: {e.Message}"
            }
            |> ignore

    /// A new connection is a new attested session, maybe with another build behind it: a runner
    /// that requests go to (ready, unknown) is pending until the next HEALTH answer. Refusing and
    /// gone runners get no SIGN anyway and keep their state.
    let onConnected () =
        match signState with
        | RunnerSignState.Ready
        | RunnerSignState.Unknown _ ->
            signState <- RunnerSignState.Pending
            Metrics.setSignerState api.Name (HealthStates.label signState)
            log.Debug $"{api.Name}: new connection; no SIGN until its HEALTH answer"
        | _ -> ()

        pollInBackground ()

    /// The first connection after none was up, under the pool's lock: the runner may have
    /// restarted with another build, so a runner that requests go to is pending before any
    /// waiting request gets the connection.
    let onFirstUp () =
        match signState with
        | RunnerSignState.Ready
        | RunnerSignState.Unknown _ ->
            signState <- RunnerSignState.Pending
            Metrics.setSignerState api.Name (HealthStates.label signState)
        | _ -> ()

    do
        Metrics.markLogLostWatch api.Name
        Metrics.setSignerState api.Name (HealthStates.label signState)
        api.FirstUp.Add(fun () -> onFirstUp ())
        api.Connected.Add(fun () -> onConnected ())

    /// Before the first HEALTH answer: one HEALTH call, or the wait for the one that runs, bounded
    /// by the request and 5 s.
    let firstHealth (ct: CancellationToken) : Task =
        task {
            match signState with
            | RunnerSignState.Pending ->
                use cts = CancellationTokenSource.CreateLinkedTokenSource(ct, stop.Token)
                cts.CancelAfter(TimeSpan.FromSeconds 5.0)

                try
                    do! poll cts.Token

                    while signState = RunnerSignState.Pending && Volatile.Read(&polling) = 1 do
                        do! Task.Delay(5, cts.Token)
                with :? OperationCanceledException ->
                    ()
            | _ -> ()
        }

    /// Why a request does not go to the runner, from its HEALTH state.
    let skip () : SignOutcome voption =
        match signState with
        | RunnerSignState.Pending ->
            ValueSome(
                Failed(Unavailable $"{api.Name}: pending: no HEALTH answer yet, so its protocol level is not known")
            )
        | RunnerSignState.Gone(l, why) -> ValueSome(Failed(Gone $"{api.Name}: {why} ({l})"))
        | RunnerSignState.Refusing(l, why) -> ValueSome(Failed(Unavailable $"{api.Name}: {l}: {why}"))
        | _ -> ValueNone

    // A SIGN that waited for a connection is checked again once it has one: the state may have
    // turned pending (a first connection after none was up) or refusing meanwhile.
    do api.SetSendGate(fun t -> t = Wire.MsgType.Sign && (skip ()).IsSome)

    /// SIGN through the pool. A request the send gate held back waits for HEALTH (firstHealth)
    /// and goes once more if the state then allows it.
    let callSign (cls: PoolClass) (payload: byte[]) (ct: CancellationToken) : Task<Reply> =
        task {
            match! api.Call cls Wire.MsgType.Sign payload ct with
            | Reply.Held ->
                do! firstHealth ct

                match skip () with
                | ValueSome(Failed f) -> return Reply.Failure f
                | ValueSome _ -> return Reply.Failure(Unavailable $"{api.Name}: held back by its HEALTH state")
                | ValueNone ->
                    match! api.Call cls Wire.MsgType.Sign payload ct with
                    | Reply.Held -> return Reply.Failure(Unavailable $"{api.Name}: held back by its HEALTH state")
                    | r -> return r
            | r -> return r
        }

    static member Duties =
        set
            [
                DutyKind.Attestation
                DutyKind.Block
                DutyKind.RandaoReveal
                DutyKind.AggregationSlot
                DutyKind.AggregateAndProof
                DutyKind.SyncCommitteeMessage
                DutyKind.SyncSelectionProof
                DutyKind.ContributionAndProof
                DutyKind.VoluntaryExit
                DutyKind.PayloadAttestation
                DutyKind.PayloadEnvelope
                DutyKind.ProposerPreferences
                DutyKind.ValidatorRegistration
                DutyKind.BuilderRequestAuth
            ]

    /// modules.tee.ha_peer (TeeSet sets it from the config).
    member _.HaPeer
        with get () = haPeer
        and set (v: bool) = haPeer <- v

    member _.Name = api.Name
    member _.Api = api
    member _.Answered = answered

    /// Raised when the runner does not know a key: the caller refreshes the key lists early.
    member _.UnknownKey = unknownKey.Publish

    member _.Listed: Wire.RunnerKey list = List.ofSeq listed.Values

    member _.Lists(key: PubKey) = listed.ContainsKey key

    member _.TryGet(key: PubKey) =
        match listed.TryGetValue key with
        | true, k -> ValueSome k
        | _ -> ValueNone

    /// Reads the key list again (PUBLIC_KEYS). On failure the old list stays.
    member _.Refresh(ct: CancellationToken) : Task<Result<int, SignFailure>> =
        task {
            match! api.Call PoolClass.High Wire.MsgType.PublicKeys [||] ct with
            | Reply.Body b ->
                try
                    let keys = Wire.decodeKeys b
                    let d = Dictionary<PubKey, Wire.RunnerKey>()

                    for k in keys do
                        d[k.PubKey] <- k

                    listed <- d
                    answered <- true
                    return Ok d.Count
                with :? Wire.WireError as e ->
                    return Error(Internal $"{api.Name}: undecodable key list: {e.Message}")
            | Reply.Refused r ->
                return Error(Internal $"{api.Name}: PUBLIC_KEYS refused: {Wire.Status.name r.Code}: {r.Detail}")
            | Reply.Failure f -> return Error f
            | Reply.Held -> return Error(Unavailable $"{api.Name}: PUBLIC_KEYS held back")
        }

    /// HEALTH, in the low class.
    member _.RunnerHealth(ct: CancellationToken) : Task<Result<Wire.RunnerHealth, string>> = health ct

    /// Reads HEALTH now and takes its state (at most one call at a time).
    member _.PollHealth(ct: CancellationToken) : Task = poll ct

    /// Reads HEALTH in the background (at the start).
    member _.PollInBackground() = pollInBackground ()

    /// At the start of an epoch: the epoch, used when the clock gives none, and a HEALTH call
    /// in the background.
    member _.OnEpoch(e: uint64) =
        epochSeen <- ValueSome e
        pollInBackground ()

    /// The current epoch (the module sets the VC clock's).
    member _.EpochNow
        with get () = epochNow
        and set v = epochNow <- v

    /// The runner's state from its last HEALTH answer.
    member _.State = signState

    /// Up while a connection is up; down with the last dial error otherwise. Down too while
    /// HEALTH puts it in a gone or refusal state, or while it is pending: a group then counts the
    /// member as down.
    member _.Health: Health =
        let up, size = api.Up()

        if up = 0 then
            Down $"{api.Name}: no connection up: {api.LastError()}"
        else
            match signState with
            | RunnerSignState.Pending -> Down $"{api.Name}: pending: no HEALTH answer yet"
            | RunnerSignState.Gone(l, why) -> Down $"{api.Name}: gone: {why} ({l})"
            | RunnerSignState.Refusing(l, why) -> Down $"{api.Name}: {l}: {why}"
            | _ when up < size -> Degraded $"{api.Name}: {up} of {size} connections up"
            | _ -> Up

    /// Signs one request with the key the runner holds for `req.Key`.
    member _.SignRaw (req: SignRequest) (ct: CancellationToken) : Task<Result<BlsSignature, SignOutcome>> =
        task {
            // A message that does not fit its kind's layout (a bug on the VC side) is refused
            // here, as the runner would refuse it.
            let encoded =
                try
                    Ok(Wire.encodeSign req)
                with
                | :? Wire.WireError as e -> Error e.Message
                | :? ArgumentException as e -> Error e.Message

            // No SIGN before the first HEALTH answer: the protocol level decides.
            do! firstHealth ct
            let skipped = skip ()

            match encoded with
            | _ when skipped.IsSome -> return Error skipped.Value
            | Error m ->
                log.Error $"{api.Name}: cannot encode the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short}: {m}"
                return Error(Refused(BadRequest $"{api.Name}: {m}"))
            | Ok payload ->
                match! callSign (Mapping.classOf req) payload ct with
                | Reply.Held -> return Error(Failed(Unavailable $"{api.Name}: held back by its HEALTH state"))
                | Reply.Body b ->
                    try
                        return Ok(Wire.decodeSignature b)
                    with :? Wire.WireError as e ->
                        return Error(Failed(Internal $"{api.Name}: {e.Message}"))
                | Reply.Refused r ->
                    let o = Mapping.toOutcomeWith haPeer api.Name req.Duty r

                    match o with
                    | Failed(Unavailable why) ->
                        log.Warn
                            $"{api.Name} cannot sign the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short}: {why}"
                    | Refused UnknownKey ->
                        log.Warn $"{api.Name} does not know key {req.Key.Short}; refreshing the key lists"
                        unknownKey.Trigger()
                    | Refused(BadRequest m) ->
                        log.Error
                            $"{api.Name} refused the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short} as malformed: {m}"
                    | Refused DomainMismatch ->
                        log.Error
                            $"{api.Name} computes another domain for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short}: the chain config or fork schedule differs"
                    // FLOOR_UNPROVEN: counted every time; the operator is told once per key, floor
                    // kind and floor epoch, also when the detail gives no epoch.
                    | Refused(Refusal.NotReadyUntil _) when r.Code = Wire.Status.FloorUnproven ->
                        Metrics.floorUnproven api.Name
                        let floor = Mapping.floorOf r

                        let struct (kind, f) =
                            match floor with
                            | ValueSome x -> x
                            | ValueNone -> struct ("none", UInt64.MaxValue)

                        let first =
                            lock unprovenLogged (fun () ->
                                match unprovenLogged.TryGetValue(struct (req.Key, kind)) with
                                | true, last when last = f -> false
                                | _ ->
                                    unprovenLogged[struct (req.Key, kind)] <- f
                                    true)

                        if first then
                            match floor with
                            | ValueSome _ ->
                                log.Warn
                                    $"{api.Name} refused the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short} at or below its {kind} floor epoch {f} and could not prove this key's history after a restart: its mark log covers the epoch, the key's own record shows no conflict. Skipped; the key signs again from epoch {f + 1UL}. Check that no other signer holds this key"
                            | ValueNone ->
                                log.Warn
                                    $"{api.Name} refused the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short} at or below a floor and could not prove this key's history after a restart; it gave no floor epoch ({Threshold.cleanReason r.Detail}). Skipped. Check that no other signer holds this key"
                    | Refused(Refusal.NotReadyUntil _) ->
                        match Mapping.floorOf r with
                        | ValueSome(struct (kind, f)) ->
                            let now =
                                match epoch () with
                                | ValueSome e -> e
                                | ValueNone -> f

                            match floorLogged.TryGetValue req.Key with
                            | true, last when last = now -> ()
                            | _ ->
                                floorLogged[req.Key] <- now

                                log.Warn
                                    $"{api.Name} refused the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short} at or below its {kind} floor epoch {f}: skipped, the key stays active and its votes and blocks sign again from epoch {f + 1UL}"
                        | ValueNone -> ()
                    | _ -> ()

                    return Error o
                | Reply.Failure f -> return Error(Failed f)
        }

    /// The whole keys of this runner: those it lists with the share key equal to the validator
    /// key. Each signature is checked against the key, in a batch with the burst's others.
    member this.WholeKeys(name: string) : Backend =
        {
            Name = name
            Capabilities =
                {
                    Duties = RunnerEndpoint.Duties
                    TypedOnly = true
                    EnforcesSlashing = true
                    ReturnsPartials = false
                    MaxInFlight = 1024
                }
            Keys =
                fun _ ->
                    Task.FromResult
                        [
                            for k in this.Listed do
                                if k.SharePubKey = k.PubKey then
                                    { Key = k.PubKey; Share = ValueNone }
                        ]
            Health = fun _ -> Task.FromResult this.Health
            Sign =
                fun req ct ->
                    task {
                        match this.TryGet req.Key with
                        | ValueSome k when k.SharePubKey = k.PubKey ->
                            match! this.SignRaw req ct with
                            | Ok s ->
                                let! ok = verifier.Verify(req.Key, req.SigningRoot, s.Bytes)

                                if ok then
                                    return Signed s
                                else
                                    log.Error
                                        $"{api.Name}: the signature for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short} does not verify"

                                    return Failed(Internal $"{api.Name}: signature does not verify")
                            | Error o -> return o
                        | _ -> return Refused UnknownKey
                    }
            Dispose = fun () -> ValueTask.CompletedTask
        }

    /// A member of a threshold group at share index `index`: the keys this runner lists with a
    /// share key of their own, answered with partial signatures.
    member this.Shares (name: string) (index: uint64) : Backend =
        {
            Name = name
            Capabilities =
                {
                    Duties = RunnerEndpoint.Duties
                    TypedOnly = true
                    EnforcesSlashing = true
                    ReturnsPartials = true
                    MaxInFlight = 1024
                }
            Keys =
                fun _ ->
                    Task.FromResult
                        [
                            for k in this.Listed do
                                if k.SharePubKey <> k.PubKey then
                                    {
                                        Key = k.PubKey
                                        Share = ValueSome(struct (index, k.SharePubKey))
                                    }
                        ]
            Health = fun _ -> Task.FromResult this.Health
            Sign =
                fun req ct ->
                    task {
                        match this.TryGet req.Key with
                        | ValueSome k when k.SharePubKey <> k.PubKey ->
                            match! this.SignRaw req ct with
                            | Ok s -> return Partial(index, s)
                            | Error o -> return o
                        | _ -> return Refused UnknownKey
                    }
            Dispose = fun () -> ValueTask.CompletedTask
        }

    member _.Close() =
        stop.Cancel()
        api.Close()
