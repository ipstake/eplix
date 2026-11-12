/// The signing pipeline: a burst goes through slashing protection (one
/// append, one fsync for its slashable requests), then to each key's backend in parallel under the
/// request deadline. Gloas PTC votes and envelopes pass the slot marks instead (one append, one
/// fsync for those of the burst); a refusal there skips the duty and never halts the key. Other
/// non-slashable kinds skip both. Priority queues per backend live in the remote
/// backends; the local backend signs in process.
namespace Eplix

open System
open System.Collections.Concurrent
open System.Threading
open System.Threading.Tasks
open Eplix.Slashing

/// Without `slotMarks` (tests and tools without a data dir), PTC votes and envelopes go to the
/// backend unchecked, with no slot mark.
type Pipeline(db: SlashingDb, registry: KeyRegistry, time: TimeProvider, log: Log, ?slotMarks: SlotMarks) =
    let inFlight = ConcurrentDictionary<PubKey, int>()
    /// The signing jitter table, or null when no request waits.
    let mutable jitters: SigningJitters = null
    let switches = SwitchBoard(log)

    // One delegate each for the life of the process: a lambda here would allocate per call.
    static let increment = Func<PubKey, int, int>(fun _ n -> n + 1)
    static let decrement = Func<PubKey, int, int>(fun _ n -> n - 1)
    let enter (key: PubKey) = inFlight.AddOrUpdate(key, 1, increment) |> ignore
    let leave (key: PubKey) = inFlight.AddOrUpdate(key, 0, decrement) |> ignore

    let slashingRequest (r: SignRequest) =
        match r.Duty with
        | Duty.Attestation d -> AttestationRequest(r.Key, d.Source.Epoch, d.Target.Epoch, r.SigningRoot)
        | Duty.Block h -> BlockRequest(r.Key, h.Slot, r.SigningRoot)
        | _ -> invalidArg "r" "not a slashable duty"

    let slotMarkRequest (r: SignRequest) =
        match r.Duty with
        | Duty.PayloadAttestation d ->
            ValueSome
                {
                    Key = r.Key
                    Kind = SlotMarkKind.PayloadAttestation
                    Slot = d.Slot
                    SigningRoot = r.SigningRoot
                }
        | Duty.PayloadEnvelope(slot, _) ->
            ValueSome
                {
                    Key = r.Key
                    Kind = SlotMarkKind.PayloadEnvelope
                    Slot = slot
                    SigningRoot = r.SigningRoot
                }
        | _ -> ValueNone

    /// Whether the request goes through the slot marks.
    let marked (r: SignRequest) = slotMarks.IsSome && (slotMarkRequest r).IsSome

    /// Whether the key may sign this duty in its current state. Slashable kinds need an active
    /// key. Other kinds also run for a halted key. An exit runs for any key not being removed.
    let allowedIn (state: KeyState) (duty: Duty) =
        match state, duty with
        | KeyState.Active, _ -> true
        | KeyState.Halted _, d -> not d.IsSlashable
        | (KeyState.Draining | KeyState.Removed | KeyState.Slashed _), _ -> false
        | _, Duty.VoluntaryExit _ -> true
        | _ -> false

    let allowed (r: SignRequest) =
        match registry.TryGet r.Key with
        | ValueNone -> false
        | ValueSome k -> allowedIn k.State r.Duty

    /// The span of one signing request, made only when the tracing module listens to the
    /// per-request source: the key's hex and the tags cost nothing otherwise.
    let signSpan (backend: string) (r: SignRequest) : Diagnostics.Activity | null =
        if Tracing.signSource.HasListeners() then
            match Tracing.signSource.StartActivity("sign", Diagnostics.ActivityKind.Client) with
            | null -> null
            | a ->
                a
                    .SetTag("eplix.backend", backend)
                    .SetTag("eplix.duty", Metrics.dutyLabel r.Duty.Kind)
                    .SetTag("eplix.key", r.Key.Hex)
                |> ignore

                a
        else
            null

    let callBackendNow (r: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        task {
            match registry.TryGet r.Key with
            | ValueNone -> return Refused UnknownKey
            | ValueSome k ->
                // Capped: CancellationTokenSource refuses delays of more than about 49 days.
                let remaining = min (r.Deadline - time.GetUtcNow()) (TimeSpan.FromDays 1.0)

                if remaining <= TimeSpan.Zero then
                    return Failed SignFailure.Timeout
                else
                    enter r.Key
                    // The key may have started draining since SignBurst checked it. Checked after
                    // `enter`, so a drain that saw no signature in flight sees this refusal instead.
                    // `k` is the registry's own record, so its State is current: no second lookup
                    // under the registry lock. The barrier keeps this read after the count, as the
                    // one in WaitIdle keeps its read of the count after the state change.
                    Interlocked.MemoryBarrier()

                    if not (allowedIn k.State r.Duty) then
                        leave r.Key
                        return Refused(PolicyDenied "key is not active")
                    else
                        // Everything after `enter` sits inside the try, so the count always goes down.
                        try
                            use act = signSpan k.Backend.Name r
                            use cts = new CancellationTokenSource(remaining, time)
                            use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, cts.Token)
                            let started = Diagnostics.Stopwatch.GetTimestamp()

                            try
                                let! outcome = k.Backend.Sign r linked.Token

                                Metrics.signed
                                    k.Backend.Name
                                    r.Duty.Kind
                                    outcome
                                    (Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds)

                                match act with
                                | null -> ()
                                | a ->
                                    a.SetTag("eplix.outcome", Metrics.outcomeLabel outcome) |> ignore

                                    match outcome with
                                    | Signed _
                                    | Partial _ -> ()
                                    | o -> Tracing.fail a (SignOutcome.describe o)

                                match outcome with
                                | Refused(Slashable why) when r.Duty.IsSlashable ->
                                    // The VC's DB allowed it, the backend did not: another VC with this key is the likely cause.
                                    let reason =
                                        $"backend {k.Backend.Name} refused as slashable what the VC's DB allowed: {why}"

                                    log.Error $"key {r.Key.Short}: {reason}; slashable duties stop for this key"
                                    // A slashable duty signs only for an active key. A drain that
                                    // moved it on during the call wins: Halted would make it live again.
                                    registry.TrySetState(r.Key, KeyState.Active, KeyState.Halted reason) |> ignore
                                | Refused(LostToPeer why) ->
                                    // modules.tee.ha_peer: another VC with these keys signed first.
                                    Metrics.lostToPeer r.Duty.Kind

                                    log.Info
                                        $"key {r.Key.Short}: lost the {Metrics.dutyLabel r.Duty.Kind} to an HA peer ({why}); the key keeps signing"
                                | Refused(Denied _ as refusal) ->
                                    // A refusal without a reason (Dirk's DENIED) skips the duty and keeps the
                                    // key, as in Vouch: a missing permission must not stop a key.
                                    let n = registry.NoteDenial r.Key
                                    Metrics.denied r.Key r.Duty.Kind

                                    log.Warn
                                        $"key {r.Key.Short}: {Metrics.dutyLabel r.Duty.Kind} skipped, {k.Backend.Name} {refusal.Describe}; {n} denied for this key so far"
                                | _ -> ()

                                return outcome
                            with
                            | :? OperationCanceledException when cts.IsCancellationRequested ->
                                let outcome = Failed SignFailure.Timeout

                                Metrics.signed
                                    k.Backend.Name
                                    r.Duty.Kind
                                    outcome
                                    (Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds)

                                Tracing.fail act "timeout"
                                return outcome
                            | e when not (e :? OperationCanceledException) ->
                                let outcome = Failed(Internal e.Message)

                                Metrics.signed
                                    k.Backend.Name
                                    r.Duty.Kind
                                    outcome
                                    (Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds)

                                Tracing.fail act e.Message
                                return outcome
                        finally
                            leave r.Key
        }

    /// The random wait (SigningJitter.fs) goes before the deadline timer and the latency clock
    /// start. The key counts as in flight from before the wait, so a drain (WaitIdle) waits for
    /// a request that is still in its jitter; callBackendNow checks the key's state again after
    /// the wait. Without a table this is one null check, and callBackendNow's state machine
    /// stays as it was.
    let callBackend (r: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        match jitters with
        | null -> callBackendNow r ct
        | t ->
            let wait =
                match registry.TryGet r.Key with
                | ValueSome k -> t.Draw(r.Key, k.Backend, r.Duty.Kind)
                | ValueNone -> TimeSpan.Zero

            if wait <= TimeSpan.Zero then
                callBackendNow r ct
            else
                // Counted before the task's first await, so the count stays above zero from
                // here until callBackendNow has taken its own.
                enter r.Key

                task {
                    let mutable call = Unchecked.defaultof<Task<SignOutcome>>

                    try
                        do! Task.Delay(wait, time, ct)
                        call <- callBackendNow r ct
                    finally
                        leave r.Key

                    return! call
                }

    let notAllowed = Task.FromResult(Refused(PolicyDenied "key is not active"))

    /// SignBurst after the state and switch checks: `ok` marks the requests that passed them.
    /// Returns once every request has started its backend call or got its outcome.
    let signChecked
        (requests: SignRequest[])
        (ok: bool[])
        (stopped: int)
        (ct: CancellationToken)
        : Task<Task<SignOutcome>[]> =
        task {
            let toCheck = requests |> Array.indexed |> Array.filter (fun (i, r) -> ok[i] && r.Duty.IsSlashable)
            let toMark = requests |> Array.indexed |> Array.filter (fun (i, r) -> ok[i] && marked r)

            let dbCheck =
                if toCheck.Length = 0 then
                    Task.FromResult [||]
                else
                    task {
                        use check = Tracing.start "slashing check"
                        Tracing.setInt check "eplix.requests" toCheck.Length
                        let started = Diagnostics.Stopwatch.GetTimestamp()
                        let! v = db.CheckAndRecord(toCheck |> Array.map (snd >> slashingRequest), ct)
                        Metrics.slashingCheckDuration.Record(Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds)
                        return v
                    }

            let markCheck =
                match slotMarks with
                | Some marks when toMark.Length > 0 ->
                    marks.CheckAndRecord(toMark |> Array.map (fun (_, r) -> (slotMarkRequest r).Value), ct)
                | _ -> Task.FromResult [||]

            let! verdicts = dbCheck
            let! markVerdicts = markCheck
            let outcomes: Task<SignOutcome>[] = Array.create requests.Length notAllowed

            if stopped <> 0 then
                for i in 0 .. requests.Length - 1 do
                    let kind = requests[i].Duty.Kind

                    if stopped &&& Switches.bit kind <> 0 then
                        outcomes[i] <- Task.FromResult(Refused(Paused(switches.Reason kind)))

            for i in 0 .. requests.Length - 1 do
                // A domain of another duty kind: a bug in the request's builder. Nothing was
                // recorded and nothing goes to a backend.
                if not ok[i] && not (Duty.domainFits requests[i]) then
                    let r = requests[i]

                    log.Error
                        $"key {r.Key.Short}: {Metrics.dutyLabel r.Duty.Kind} not signed, its domain {r.Domain.Bytes[0..3] |> Hex.encodeArray} is not the domain type of the kind"

                    outcomes[i] <- Task.FromResult(Refused DomainMismatch)

            for i in 0 .. requests.Length - 1 do
                if ok[i] && not requests[i].Duty.IsSlashable && not (marked requests[i]) then
                    outcomes[i] <- callBackend requests[i] ct

            toMark
            |> Array.iteri (fun j (i, r) ->
                outcomes[i] <-
                    match markVerdicts[j] with
                    | Verdict.Allowed
                    | Verdict.Repeat -> callBackend r ct
                    | Verdict.Refused why ->
                        // Not slashable on chain: skip this duty, keep the key.
                        log.Warn
                            $"key {r.Key.Short}: {Metrics.dutyLabel r.Duty.Kind} skipped, slot marks refused: {why}"

                        Metrics.refusedBySlashing r.Duty.Kind
                        Task.FromResult(Refused(Slashable why))
                    | Verdict.NoRecord -> Task.FromResult(Refused(PolicyDenied "no slot mark record"))
                    | Verdict.WriteFailed why ->
                        log.Error why
                        Task.FromResult(Failed(Internal why)))

            toCheck
            |> Array.iteri (fun j (i, r) ->
                outcomes[i] <-
                    match verdicts[j] with
                    | Verdict.Allowed
                    | Verdict.Repeat -> callBackend r ct
                    | Verdict.Refused why ->
                        log.Warn $"key {r.Key.Short}: slashing protection refused: {why}"
                        Metrics.refusedBySlashing r.Duty.Kind
                        Task.FromResult(Refused(Slashable why))
                    | Verdict.NoRecord -> Task.FromResult(Refused(PolicyDenied "no slashing record"))
                    | Verdict.WriteFailed why ->
                        log.Error why
                        Task.FromResult(Failed(Internal why)))

            return outcomes
        }

    /// The emergency switches (Switches.fs). The runner sets them from the config and the switch file.
    member _.Switches = switches

    /// The signing jitter (SigningJitter.fs). The runner sets it when some bound is above 0; null
    /// means no request waits.
    member _.Jitters
        with get () = jitters
        and set (v: SigningJitters) = jitters <- v

    /// Signs a burst. The slashable requests pass slashing protection with one fsync, and PTC
    /// votes and envelopes the slot marks with one fsync, before any request of the burst reaches
    /// a backend. Outcomes are in request order.
    member _.SignBurst(requests: SignRequest[], ct: CancellationToken) : Task<SignOutcome[]> =
        task {
            use act = Tracing.start "sign burst"

            if not (isNull act) && requests.Length > 0 then
                Tracing.setText act "eplix.duty" (Metrics.dutyLabel requests[0].Duty.Kind)
                Tracing.setInt act "eplix.requests" requests.Length
            // One volatile read per burst; with no switch on, nothing else changes.
            let stopped = switches.Mask

            let ok =
                if stopped = 0 then
                    requests |> Array.map (fun r -> Duty.domainFits r && allowed r)
                else
                    requests
                    |> Array.map (fun r -> stopped &&& Switches.bit r.Duty.Kind = 0 && Duty.domainFits r && allowed r)
            // A request counts as in flight from here, through the slashing check, until its
            // backend call starts, so a drain that starts meanwhile waits for it (WaitIdle).
            // callBackend counts the backend call itself: it enters before its first await, so
            // the count never drops to zero in between. Releasing here, before the backend calls
            // end, keeps one slow key from holding the drain of the other keys of the burst.
            let counted =
                [|
                    for i in 0 .. requests.Length - 1 do
                        if ok[i] then
                            requests[i].Key
                |]

            for k in counted do
                enter k

            let mutable outcomes = [||]

            try
                let! dispatched = signChecked requests ok stopped ct
                outcomes <- dispatched
            finally
                for k in counted do
                    leave k

            let! all = Task.WhenAll outcomes

            if not (isNull act) then
                Tracing.setInt
                    act
                    "eplix.signed"
                    (all
                     |> Array.sumBy (fun o ->
                         match o with
                         | Signed _
                         | Partial _ -> 1
                         | _ -> 0))

            return all
        }

    member this.Sign(request: SignRequest, ct: CancellationToken) : Task<SignOutcome> =
        task {
            let! r = this.SignBurst([| request |], ct)
            return r[0]
        }

    /// Waits until no signature for these keys is in flight, or the timeout passes. Draining uses it.
    member _.WaitIdle(keys: PubKey list, timeout: TimeSpan, ct: CancellationToken) : Task<bool> =
        task {
            // Wall-clock wait: signatures in flight finish in real time, also under a test clock.
            let sw = Diagnostics.Stopwatch.StartNew()

            let busy () =
                // Pairs with the barrier in callBackend: the caller changed the key's state first.
                Interlocked.MemoryBarrier()

                keys
                |> List.exists (fun k ->
                    match inFlight.TryGetValue k with
                    | true, n -> n > 0
                    | _ -> false)

            while busy () && sw.Elapsed < timeout do
                do! Task.Delay(TimeSpan.FromMilliseconds 10.0, ct)

            return not (busy ())
        }
