/// One Dirk instance as Eplix sees it: the accounts it holds for each validator key, the
/// mapping of duties to Dirk's calls and of Dirk's answers to SignOutcome.
namespace Eplix.Backend.Dirk

open System
open System.Collections.Concurrent
open System.Threading
open System.Threading.Channels
open System.Threading.Tasks
open Eplix
open Eplix.Backend.Dirk.Messages

/// A validator key's account at one Dirk instance. Share is set for a distributed account:
/// the participant id and, when this instance listed the account itself, its share key.
type DirkAccount =
    {
        Name: string
        Share: struct (uint64 * PubKey voption) voption
    }

/// How the Gloas kinds (PTC votes, envelopes, proposer preferences, builder request auth) go to
/// Dirk: config `gloas_calls`.
[<RequireQualifiedAccess>]
type GloasCalls =
    /// The fork's typed calls; at the first UNIMPLEMENTED, root and domain from then on.
    | Auto
    /// The fork's typed calls only; UNIMPLEMENTED is a failure.
    | Typed
    /// Root and domain through the generic Sign only (stock Dirk).
    | Generic

    /// The config value.
    member this.Name =
        match this with
        | Auto -> "auto"
        | Typed -> "typed"
        | Generic -> "generic"

    static member TryParse(s: string) =
        match s with
        | "auto" -> ValueSome GloasCalls.Auto
        | "typed" -> ValueSome GloasCalls.Typed
        | "generic" -> ValueSome GloasCalls.Generic
        | _ -> ValueNone

type private PendingAttestation =
    {
        Item: AccountId * Domain * AttestationData
        Done: TaskCompletionSource<Result<SignResponse, CallError>>
    }

/// Without `gloasCalls` the endpoint uses GloasCalls.Auto. Without `watch` it checks whole-key
/// signatures with a watch that has no probe (tests, benchmarks).
type DirkEndpoint
    (
        api: DirkApi,
        batchAttestations: bool,
        batchTimeout: TimeSpan,
        log: Log,
        ?gloasCalls: GloasCalls,
        ?watch: SignatureWatch
    ) =
    let gloasCalls = defaultArg gloasCalls GloasCalls.Auto
    let accounts = ConcurrentDictionary<PubKey, DirkAccount>()
    // Health: the transport error and whether a call timed out since the last answered call.
    let mutable lastTransportError: string voption = ValueNone
    let mutable timedOut = false
    let queue = Channel.CreateUnbounded<PendingAttestation>(UnboundedChannelOptions(SingleReader = true))
    let stop = new CancellationTokenSource()
    let maxBatch = 512
    let inFlight = new SemaphoreSlim(16, 16)

    let watch =
        match watch with
        | Some w -> w
        | None -> SignatureWatch("dirk", api.Address, log)
    // Whether to send Gloas kinds with the fork's typed calls. In auto mode it is cleared for good
    // at the first UNIMPLEMENTED answer: stock Dirk then gets them as root and domain.
    let mutable typedGloas = gloasCalls <> GloasCalls.Generic

    // Only an answer clears the state: a blackholed Dirk gives timeouts, not transport errors.
    // Any result but a transport error or a timeout is an answer (a refusal, UNIMPLEMENTED,
    // PERMISSION_DENIED, an undecodable reply), so the transport works.
    let note (r: Result<'T, CallError>) =
        match r with
        | Error(CallError.Failure(Transport m)) -> lastTransportError <- ValueSome m
        | Error(CallError.Failure SignFailure.Timeout) -> timedOut <- true
        | Ok _
        | Error _ ->
            lastTransportError <- ValueNone
            timedOut <- false

        r

    /// Sends one batch; Dirk refuses two requests for one account in a batch, so the caller
    /// splits batches per account first.
    let sendBatch (batch: PendingAttestation list) =
        task {
            try
                use cts = new CancellationTokenSource(batchTimeout)
                let! r = api.SignAttestations [ for p in batch -> p.Item ] cts.Token

                match note r with
                | Ok responses when responses.Length = batch.Length ->
                    List.iter2
                        (fun (p: PendingAttestation) resp -> p.Done.TrySetResult(Ok resp) |> ignore)
                        batch
                        responses
                | Ok responses ->
                    let e =
                        CallError.Failure(
                            Internal $"Dirk {api.Address} answered {responses.Length} of {batch.Length} requests"
                        )

                    for p in batch do
                        p.Done.TrySetResult(Error e) |> ignore
                | Error e ->
                    log.Debug $"Dirk {api.Address}: a batch of {batch.Length} attestations failed"

                    for p in batch do
                        p.Done.TrySetResult(Error e) |> ignore
            finally
                inFlight.Release() |> ignore
        }

    let drain (first: PendingAttestation) =
        let taken = ResizeArray<PendingAttestation>([ first ])
        let mutable next = Unchecked.defaultof<PendingAttestation>

        while taken.Count < maxBatch && queue.Reader.TryRead(&next) do
            taken.Add next

        taken

    /// Takes what is queued (up to maxBatch), splits it into batches with one request per
    /// account, and sends each. Up to 16 batches are in flight at once.
    let batcher =
        task {
            try
                while not stop.IsCancellationRequested do
                    let! first = queue.Reader.ReadAsync(stop.Token)
                    let taken = drain first
                    let rounds = ResizeArray<ResizeArray<PendingAttestation>>()
                    let seen = Collections.Generic.Dictionary<string, int>()

                    for p in taken do
                        let id, _, _ = p.Item

                        let name =
                            match id with
                            | AccountId.Name n -> n
                            | AccountId.PublicKey pk -> Hex.encodeArray pk

                        let round =
                            match seen.TryGetValue name with
                            | true, r -> r + 1
                            | _ -> 0

                        seen[name] <- round

                        if rounds.Count <= round then
                            rounds.Add(ResizeArray())

                        rounds[round].Add p

                    for b in rounds do
                        do! inFlight.WaitAsync(stop.Token)
                        sendBatch (List.ofSeq b) |> ignore
            with :? OperationCanceledException ->
                ()
        }

    let genericCall (req: SignRequest) (account: DirkAccount) =
        DirkCall.Generic(AccountId.Name account.Name, Duty.objectRoot req.Duty, req.Domain)

    let callFor (req: SignRequest) (account: DirkAccount) : DirkCall =
        let id = AccountId.Name account.Name

        match req.Duty with
        | Duty.Attestation d -> DirkCall.Attestation(id, req.Domain, d)
        | Duty.Block h -> DirkCall.Proposal(id, req.Domain, h)
        | Duty.PayloadAttestation d when typedGloas -> DirkCall.PayloadAttestation(id, req.Domain, d)
        | Duty.PayloadEnvelope(_, e) when typedGloas -> DirkCall.PayloadEnvelope(id, req.Domain, e)
        | Duty.ProposerPreferences p when typedGloas -> DirkCall.ProposerPreferences(id, req.Domain, p)
        | Duty.BuilderRequestAuth a when typedGloas -> DirkCall.BuilderRequestAuth(id, req.Domain, a)
        | _ -> genericCall req account

    let outcome (req: SignRequest) (account: DirkAccount) (r: Result<SignResponse, CallError>) : SignOutcome =
        match r with
        | Error(CallError.Failure f) -> Failed f
        | Error(CallError.Rejected m) ->
            Refused(PolicyDenied $"Dirk {api.Address} rejected the client certificate: {m}")
        | Error(CallError.Unimplemented m) ->
            Failed(
                Internal
                    $"Dirk {api.Address} has no call for the {Metrics.dutyLabel req.Duty.Kind} ({m}); with stock Dirk set gloas_calls to auto or generic"
            )
        | Ok s ->
            match s.State with
            | ResponseState.Succeeded when s.Signature.Length = 96 ->
                let sg = BlsSignature.Of s.Signature

                match account.Share with
                | ValueSome(struct (id, _)) -> Partial(id, sg)
                | ValueNone -> Signed sg
            | ResponseState.Succeeded ->
                Failed(Internal $"Dirk {api.Address} returned a signature of {s.Signature.Length} bytes")
            // Dirk answers DENIED for its slashing protection, a missing permission or a refused
            // exit, with no reason. The pipeline skips the duty and keeps the key, since DENIED can mean a missing permission.
            | ResponseState.Denied ->
                Refused(
                    Refusal.Denied(
                        $"Dirk {api.Address} denied the {Metrics.dutyLabel req.Duty.Kind} for {account.Name}",
                        {
                            Signed = 0
                            Denied = 1
                            Failed = 0
                            Errored = 0
                        }
                    )
                )
            | ResponseState.Failed ->
                Failed(
                    Internal
                        $"Dirk {api.Address} failed to sign the {Metrics.dutyLabel req.Duty.Kind} for {account.Name}"
                )
            | ResponseState.Unknown -> Failed(Internal $"Dirk {api.Address} answered without a state")

    /// The outcome; with `check`, a whole-key signature is queued for its background check.
    let checkedOutcome (check: bool) (req: SignRequest) (account: DirkAccount) (r: Result<SignResponse, CallError>) =
        let o = outcome req account r

        match o with
        | Signed s when check -> watch.Check(req, s)
        | _ -> ()

        o

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
                DutyKind.BuilderRequestAuth
                DutyKind.ValidatorRegistration
            ]

    member _.Address = api.Address
    member _.Api = api

    /// Sets the account of a key. An account this instance listed itself (with its share key)
    /// is not replaced by one learnt from another participant's list.
    member _.SetAccount(key: PubKey, account: DirkAccount) : bool =
        let added = ref false
        let renamed = ref false

        accounts.AddOrUpdate(
            key,
            (fun _ ->
                added.Value <- true
                account),
            (fun _ old ->
                match old.Share, account.Share with
                | ValueSome(struct (_, ValueSome _)), ValueSome(struct (_, ValueNone)) -> old
                | _ ->
                    renamed.Value <- old.Name <> account.Name
                    account)
        )
        |> ignore
        // A key the list registers anew, or under another account, starts with a clean record.
        if added.Value || renamed.Value then
            watch.Resume key

        added.Value

    member _.TryAccount(key: PubKey) =
        match accounts.TryGetValue key with
        | true, a -> ValueSome a
        | _ -> ValueNone

    member _.Accounts: (PubKey * DirkAccount) list = [ for KeyValue(k, a) in accounts -> k, a ]

    /// Down after a transport error. Degraded after a timeout: the caller's own cancel (a
    /// threshold group stops its stragglers) also ends a call as a timeout, so it is not Down.
    member _.Health: Health =
        match lastTransportError with
        | ValueSome m -> Down $"Dirk {api.Address}: {m}"
        | ValueNone when timedOut -> Degraded $"Dirk {api.Address}: a call timed out with no answer since"
        | ValueNone -> Up

    /// Sends `req`; with `check`, a whole-key signature is queued for its background check.
    member private _.Send (check: bool) (req: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        task {
            match accounts.TryGetValue req.Key with
            | false, _ -> return Refused UnknownKey
            | true, account ->
                match callFor req account with
                | DirkCall.Attestation(id, domain, d) when batchAttestations ->
                    let tcs =
                        TaskCompletionSource<Result<SignResponse, CallError>>(
                            TaskCreationOptions.RunContinuationsAsynchronously
                        )

                    if not (queue.Writer.TryWrite { Item = (id, domain, d); Done = tcs }) then
                        return Failed(Internal "the Dirk module is stopping")
                    else
                        try
                            let! r = tcs.Task.WaitAsync(ct)
                            return checkedOutcome check req account r
                        with :? OperationCanceledException ->
                            return Failed SignFailure.Timeout
                | call ->
                    match! api.Sign call ct with
                    | Error(CallError.Unimplemented _) when call.IsTypedGloas && gloasCalls = GloasCalls.Auto ->
                        if typedGloas then
                            typedGloas <- false

                            log.Info
                                $"Dirk {api.Address} has no typed Gloas calls; PTC votes, envelopes, proposer preferences and builder request auth go to it as root and domain"

                        let! r = api.Sign (genericCall req account) ct
                        return checkedOutcome check req account (note r)
                    | r -> return checkedOutcome check req account (note r)
        }

    /// A request for a key stopped at this instance: the refusal, or the request after a good probe.
    member private this.SignAdmitted (req: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        task {
            match! watch.Admit(req, this.Send false, ct) with
            | ValueSome refused -> return refused
            | ValueNone -> return! this.Send true req ct
        }

    /// Signs `req`. A whole-key signature comes back at once and is checked against the key and
    /// signing root in the background; a partial is checked when the group
    /// combines.
    member this.Sign (req: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        if watch.AnyStopped then this.SignAdmitted req ct else this.Send true req ct

    /// The background checks of this instance's whole-key signatures.
    member _.Watch = watch

    /// A backend over the keys of this instance that `include` selects.
    member this.Backend (name: string) (shares: bool) (includeKey: PubKey -> DirkAccount -> bool) : Backend =
        {
            Name = name
            Capabilities =
                {
                    Duties = DirkEndpoint.Duties
                    TypedOnly = false
                    EnforcesSlashing = true
                    ReturnsPartials = shares
                    MaxInFlight = 1024
                }
            Keys =
                fun _ ->
                    Task.FromResult
                        [
                            for KeyValue(k, a) in accounts do
                                if includeKey k a then
                                    {
                                        Key = k
                                        Share =
                                            match a.Share with
                                            | ValueSome(struct (id, ValueSome share)) -> ValueSome(struct (id, share))
                                            | _ -> ValueNone
                                    }
                        ]
            Health = fun _ -> Task.FromResult this.Health
            Sign = this.Sign
            Dispose = fun () -> ValueTask.CompletedTask
        }

    member _.Stop() =
        stop.Cancel()
        queue.Writer.TryComplete() |> ignore

        try
            batcher.Wait(TimeSpan.FromSeconds 5.0) |> ignore
        with _ ->
            ()

        api.Dispose()
