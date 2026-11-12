/// Background checks of the whole-key signatures that Dirk and Web3Signer return. A remote
/// signer is the only backend of its keys, so a bad signature cannot be replaced,
/// and the beacon node checks it anyway: the VC returns the signature at once, checks it off the
/// latency path, alerts on a bad one, and stops sending a key to an endpoint that keeps signing
/// it wrong.
namespace Eplix

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks

/// What a watch needs to build its probe: the chain spec and the wall-clock epoch.
type ProbeChain =
    {
        Spec: ChainSpec
        CurrentEpoch: unit -> Epoch voption
    }

/// One key's check state at one endpoint. It exists only after a check failed; a pass, a resume
/// or a VC restart removes it.
type private KeyWatch() =
    member val Fails = 0 with get, set
    member val Stopped = false with get, set
    /// The last epoch a probe ran in, or the epoch of the stop.
    member val ProbedEpoch = 0UL with get, set
    member val Probing = false with get, set

[<RequireQualifiedAccess>]
type private Admission =
    | Send
    | Refuse
    | Probe of epoch: Epoch * chain: ProbeChain

/// The checks of one endpoint. `Check` queues one signature to the verifier and returns at once;
/// at most `capacity` checks wait, and the rest are dropped and counted. `stopAfter` failed checks
/// in a row for one key stop that key at this endpoint: its requests get `Failed(Unavailable)`, a
/// refusal that halts nothing and leaves the slashing DB alone. Once an epoch, the first request
/// for a stopped key sends a RANDAO reveal for the current epoch as a probe and verifies it
/// before the request goes on; a good one resumes the key. Without `chain` there is no probe, and
/// a key resumes only through `Resume` (a key list change) or a VC restart.
type SignatureWatch
    (
        backend: string,
        endpoint: string,
        log: Log,
        ?chain: ProbeChain,
        ?verify: PubKey -> Root -> byte[] -> Task<bool>,
        ?capacity: int,
        ?stopAfter: int
    ) =
    let verify = defaultArg verify (fun k r s -> BatchVerifier.Shared.Verify(k, r, s))
    let capacity = defaultArg capacity 4096
    let stopAfter = defaultArg stopAfter 3
    let gate = obj ()
    let keys = Dictionary<PubKey, KeyWatch>()
    // Read without the lock on the signing path: keys.Count, and the stopped keys among them.
    let mutable tracked = 0
    let mutable stopped = 0
    let mutable pending = 0
    let mutable lastDropLog = 0L
    // Set under the lock while a caller of Settled waits; the last check to finish completes it.
    // `waiting` lets that check skip the lock when nobody waits.
    let mutable idle: TaskCompletionSource voption = ValueNone
    let mutable waiting = false

    let currentEpoch () =
        match chain with
        | Some c -> c.CurrentEpoch()
        | None -> ValueNone

    let refusal (key: PubKey) =
        Failed(
            Unavailable
                $"{backend} {endpoint} is not used for {key.Short}: {stopAfter} of its signatures in a row did not verify; it is probed once an epoch"
        )

    /// Removes a key's state. Called under the lock; true when the key was stopped.
    let forget (key: PubKey) =
        match keys.TryGetValue key with
        | true, w ->
            keys.Remove key |> ignore
            tracked <- keys.Count

            if w.Stopped then
                stopped <- stopped - 1

            w.Stopped
        | _ -> false

    let resumed (key: PubKey) (reason: string) (why: string) =
        Metrics.remoteSignerKeyResumed backend endpoint reason
        log.Warn $"{backend} {endpoint}: requests for {key.Short} go to it again: {why}"

    let failed (req: SignRequest) (what: string) =
        Metrics.remoteSignatureInvalid backend endpoint

        let struct (fails, stopNow) =
            lock gate (fun () ->
                let w =
                    match keys.TryGetValue req.Key with
                    | true, w -> w
                    | _ ->
                        let w = KeyWatch()
                        keys[req.Key] <- w
                        tracked <- keys.Count
                        w
                // Late results for a stopped key (requests sent before the stop) change nothing.
                if w.Stopped then
                    struct (w.Fails, false)
                else
                    w.Fails <- w.Fails + 1

                    if w.Fails >= stopAfter then
                        w.Stopped <- true
                        w.ProbedEpoch <- defaultValueArg (currentEpoch ()) 0UL
                        stopped <- stopped + 1
                        struct (w.Fails, true)
                    else
                        struct (w.Fails, false))

        log.Error
            $"{backend} {endpoint}: the {what} for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short} does not verify ({fails} in a row)"

        if stopNow then
            Metrics.remoteSignerKeyStopped backend endpoint

            let next =
                match chain with
                | Some _ -> "a RANDAO probe once an epoch, a key list change or a restart resumes it"
                | None -> "a key list change or a restart resumes it"

            log.Error
                $"{backend} {endpoint}: requests for {req.Key.Short} no longer go to it after {fails} signatures in a row that did not verify; {next}"

    let passed (req: SignRequest) =
        if Volatile.Read(&tracked) > 0 then
            lock gate (fun () ->
                match keys.TryGetValue req.Key with
                | true, w when not w.Stopped -> forget req.Key |> ignore
                | _ -> ())

    let checkedOne (req: SignRequest) (t: Task<bool>) =
        try
            if t.IsCompletedSuccessfully then
                if t.Result then passed req else failed req "signature"
        finally
            if Interlocked.Decrement(&pending) = 0 && Volatile.Read(&waiting) then
                lock gate (fun () ->
                    match idle with
                    | ValueSome t when Volatile.Read(&pending) = 0 ->
                        t.TrySetResult() |> ignore
                        idle <- ValueNone
                        Volatile.Write(&waiting, false)
                    | _ -> ())

    /// The checks queued and not done yet.
    member _.Pending = Volatile.Read(&pending)

    /// Completes once no check waits: at once when none does, else when the last queued one has
    /// changed this watch's state. Results of checks from different requests can land in any
    /// order, so tests wait on this between requests instead of polling counters.
    member _.Settled() : Task =
        lock gate (fun () ->
            let t =
                match idle with
                | ValueSome t -> t
                | ValueNone ->
                    let t = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                    idle <- ValueSome t
                    Volatile.Write(&waiting, true)
                    t
            // A check that finished before `waiting` was set saw no waiter; look again. The fence
            // keeps this read of `pending` after the write of `waiting`.
            Interlocked.MemoryBarrier()

            if Volatile.Read(&pending) = 0 then
                t.TrySetResult() |> ignore
                idle <- ValueNone
                Volatile.Write(&waiting, false)

            t.Task)

    /// True while some key is stopped at this endpoint; the backend then asks `Admit` first.
    member _.AnyStopped = Volatile.Read(&stopped) > 0

    /// True while some key has a failed check on record.
    member _.Tracking = Volatile.Read(&tracked) > 0

    member _.IsStopped(key: PubKey) =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, w -> w.Stopped
            | _ -> false)

    /// Failed checks in a row for `key`.
    member _.Fails(key: PubKey) =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, w -> w.Fails
            | _ -> 0)

    /// Queues the check of a whole-key signature and returns at once. The result only changes
    /// this watch's state: never the request, its outcome or the slashing DB.
    member _.Check(req: SignRequest, signature: BlsSignature) : unit =
        if Interlocked.Increment(&pending) > capacity then
            Interlocked.Decrement(&pending) |> ignore
            Metrics.remoteSignatureCheckDropped backend endpoint
            let now = Environment.TickCount64
            let last = Volatile.Read(&lastDropLog)

            if now - last > 60_000L && Interlocked.CompareExchange(&lastDropLog, now, last) = last then
                log.Warn
                    $"{backend} {endpoint}: {capacity} signature checks wait; new ones are dropped until the queue drains"
        else
            let t =
                try
                    verify req.Key req.SigningRoot signature.Bytes
                with e ->
                    Task.FromException<bool> e

            t.ContinueWith((fun (t: Task<bool>) -> checkedOne req t), TaskContinuationOptions.ExecuteSynchronously)
            |> ignore

    /// ValueNone: send `req`. ValueSome: the refusal for a key stopped at this endpoint. When the
    /// key's probe is due it runs here first: `probe` signs a RANDAO reveal for the current epoch
    /// with no background check, and the reveal is verified before `req` goes on.
    member _.Admit
        (req: SignRequest, probe: SignRequest -> CancellationToken -> Task<SignOutcome>, ct: CancellationToken)
        : Task<SignOutcome voption> =
        let decision =
            lock gate (fun () ->
                match keys.TryGetValue req.Key with
                | true, w when w.Stopped ->
                    match chain, currentEpoch () with
                    | Some c, ValueSome e when e > w.ProbedEpoch && not w.Probing ->
                        w.Probing <- true
                        w.ProbedEpoch <- e
                        Admission.Probe(e, c)
                    | _ -> Admission.Refuse
                | _ -> Admission.Send)

        match decision with
        | Admission.Send -> Task.FromResult ValueNone
        | Admission.Refuse -> Task.FromResult(ValueSome(refusal req.Key))
        | Admission.Probe(epoch, c) ->
            task {
                let mutable ok = false

                try
                    let p =
                        Duty.request
                            c.Spec
                            req.Fork.GenesisValidatorsRoot
                            req.Key
                            Priority.High
                            req.Deadline
                            (Duty.RandaoReveal epoch)

                    match! probe p ct with
                    | Signed s ->
                        let! good = verify p.Key p.SigningRoot s.Bytes
                        if good then ok <- true else failed p "probe signature"
                    | o ->
                        log.Warn
                            $"{backend} {endpoint}: the probe for {req.Key.Short} at epoch {epoch} got no signature: {o.Describe}"
                finally
                    lock gate (fun () ->
                        match keys.TryGetValue req.Key with
                        | true, w ->
                            w.Probing <- false

                            if ok then
                                forget req.Key |> ignore
                        | _ -> ())

                if ok then
                    resumed req.Key "probe" $"its RANDAO reveal for epoch {epoch} verifies"
                    return ValueNone
                else
                    return ValueSome(refusal req.Key)
            }

    /// Clears `key`'s failed checks and resumes it if stopped: its key list entry changed (a
    /// refresh lists it again after it was gone, or under another account).
    member _.Resume(key: PubKey) =
        if Volatile.Read(&tracked) > 0 then
            let wasStopped = lock gate (fun () -> forget key)

            if wasStopped then
                resumed key "key_list" "the key list registers it again"
