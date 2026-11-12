/// One Web3Signer endpoint as Eplix sees it: the keys it lists, its health, and backends over
/// it, one for whole keys and one per share group it belongs to.
namespace Eplix.Backend.Web3Signer

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Eplix

/// Without `watch` it checks whole-key signatures with a watch that has no probe (tests,
/// benchmarks).
type SignerEndpoint(api: SignerApi, timeout: TimeSpan, log: Log, ?watch: SignatureWatch) =
    // The key list from the last answer; replaced as a whole.
    let mutable listed: HashSet<PubKey> = HashSet()
    let mutable answered = false
    let mutable lastTransportError: string voption = ValueNone
    let unknownKey = Event<unit>()

    let watch =
        match watch with
        | Some w -> w
        | None -> SignatureWatch("web3signer", api.Url, log)

    let note (a: Answer) =
        match a with
        | Answer.Failure(Transport m) -> lastTransportError <- ValueSome m
        | Answer.Failure _
        // Nothing was sent: says nothing about the transport.
        | Answer.Unsupported -> ()
        | _ -> lastTransportError <- ValueNone

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

    member _.Url = api.Url

    /// Raised when the signer answers 404 for a key: the caller refreshes the key lists early.
    member _.UnknownKey = unknownKey.Publish

    /// Whether the last key list call answered.
    member _.Answered = answered

    member _.Lists(key: PubKey) = listed.Contains key

    member _.Listed: PubKey list = List.ofSeq listed

    /// Reads the key list again. On failure the old list stays.
    member _.Refresh(ct: CancellationToken) : Task<Result<int, SignFailure>> =
        task {
            match! api.PublicKeys ct with
            | Ok keys ->
                let before = listed
                listed <- HashSet keys
                // A key that comes back to the list starts with a clean record.
                if watch.Tracking then
                    for k in listed do
                        if not (before.Contains k) then
                            watch.Resume k

                answered <- true
                lastTransportError <- ValueNone
                return Ok listed.Count
            | Error f ->
                match f with
                | Transport m -> lastTransportError <- ValueSome m
                | _ -> ()

                return Error f
        }

    /// Down while the endpoint is not attested or after a transport error.
    member _.Health: Health =
        match api.NotAttested(), lastTransportError with
        | ValueSome r, _ -> Down r
        | ValueNone, ValueSome m -> Down $"{api.Url}: {m}"
        | ValueNone, ValueNone -> Up

    /// Signs with `identifier` under the endpoint's timeout and the caller's token. A whole-key
    /// signature comes back at once and is checked against the key and signing root in the
    /// background; a share signature is checked when the group combines.
    member this.SignWith
        (identifier: PubKey)
        (partialIndex: uint64 voption)
        (req: SignRequest)
        (ct: CancellationToken)
        : Task<SignOutcome> =
        this.Call identifier partialIndex true req ct

    /// A whole-key request for a key stopped at this endpoint: the refusal, or the request after
    /// a good probe.
    member private this.SignAdmitted (req: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
        task {
            match! watch.Admit(req, (fun p ct -> this.Call p.Key ValueNone false p ct), ct) with
            | ValueSome refused -> return refused
            | ValueNone -> return! this.Call req.Key ValueNone true req ct
        }

    /// The background checks of this endpoint's whole-key signatures.
    member _.Watch = watch

    /// Signs; with `check`, a whole-key signature is queued for its background check.
    member private _.Call
        (identifier: PubKey)
        (partialIndex: uint64 voption)
        (check: bool)
        (req: SignRequest)
        (ct: CancellationToken)
        : Task<SignOutcome> =
        task {
            use own = new CancellationTokenSource(timeout)
            use linked = CancellationTokenSource.CreateLinkedTokenSource(own.Token, ct)
            let! answer = api.Sign identifier req linked.Token
            note answer
            let outcome = Answer.toOutcome api.Url req.Duty partialIndex answer

            match outcome with
            | Refused UnknownKey ->
                log.Warn $"{api.Url} does not know key {identifier.Short}; refreshing the key lists"
                unknownKey.Trigger()
            | Refused(BadRequest m) ->
                log.Error
                    $"{api.Url} refused the {Metrics.dutyLabel req.Duty.Kind} for {req.Key.Short} as malformed: {m}"
            | Signed s when check -> watch.Check(req, s)
            | _ -> ()

            return outcome
        }

    /// The whole keys this endpoint lists.
    member this.WholeKeys(name: string) : Backend =
        {
            Name = name
            Capabilities =
                {
                    Duties = SignerEndpoint.Duties
                    TypedOnly = false
                    EnforcesSlashing = true
                    ReturnsPartials = false
                    MaxInFlight = 1024
                }
            Keys = fun _ -> Task.FromResult [ for k in this.Listed -> { Key = k; Share = ValueNone } ]
            Health = fun _ -> Task.FromResult this.Health
            Sign =
                fun req ct ->
                    if watch.AnyStopped then this.SignAdmitted req ct else this.Call req.Key ValueNone true req ct
            Dispose = fun () -> ValueTask.CompletedTask
        }

    /// A member of a share group: `shares` maps each validator key to this endpoint's share key.
    /// It lists a validator key once the endpoint lists the share, and answers with partials.
    member this.Shares (name: string) (index: uint64) (shares: IReadOnlyDictionary<PubKey, PubKey>) : Backend =
        {
            Name = name
            Capabilities =
                {
                    Duties = SignerEndpoint.Duties
                    TypedOnly = false
                    EnforcesSlashing = true
                    ReturnsPartials = true
                    MaxInFlight = 1024
                }
            Keys =
                fun _ ->
                    Task.FromResult
                        [
                            for KeyValue(validator, share) in shares do
                                if this.Lists share then
                                    {
                                        Key = validator
                                        Share = ValueSome(struct (index, share))
                                    }
                        ]
            Health = fun _ -> Task.FromResult this.Health
            Sign =
                fun req ct ->
                    match shares.TryGetValue req.Key with
                    | true, share -> this.SignWith share (ValueSome index) req ct
                    | _ -> Task.FromResult(Refused UnknownKey)
            Dispose = fun () -> ValueTask.CompletedTask
        }

    member _.Dispose() = api.Dispose()
