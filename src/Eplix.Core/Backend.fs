/// The signing backend interface (design section 3): typed requests in, typed outcomes out.
namespace Eplix

open System
open System.Threading
open System.Threading.Tasks

[<RequireQualifiedAccess>]
type DutyKind =
    | Attestation
    | Block
    | RandaoReveal
    | AggregationSlot
    | AggregateAndProof
    | SyncCommitteeMessage
    | SyncSelectionProof
    | ContributionAndProof
    | VoluntaryExit
    | PayloadAttestation
    | PayloadEnvelope
    | ProposerPreferences
    | BuilderRequestAuth
    | ValidatorRegistration

    /// The case name, written out: the compiler's ToString for a union goes through %A, whose
    /// reflection fails under NativeAOT (KeyNotFoundException), and log lines and refusal
    /// reasons put the kind in strings.
    override this.ToString() =
        match this with
        | Attestation -> "Attestation"
        | Block -> "Block"
        | RandaoReveal -> "RandaoReveal"
        | AggregationSlot -> "AggregationSlot"
        | AggregateAndProof -> "AggregateAndProof"
        | SyncCommitteeMessage -> "SyncCommitteeMessage"
        | SyncSelectionProof -> "SyncSelectionProof"
        | ContributionAndProof -> "ContributionAndProof"
        | VoluntaryExit -> "VoluntaryExit"
        | PayloadAttestation -> "PayloadAttestation"
        | PayloadEnvelope -> "PayloadEnvelope"
        | ProposerPreferences -> "ProposerPreferences"
        | BuilderRequestAuth -> "BuilderRequestAuth"
        | ValidatorRegistration -> "ValidatorRegistration"

/// What a backend is asked to sign: the whole message, never a bare root (design section 3).
[<RequireQualifiedAccess>]
type Duty =
    | Attestation of AttestationData
    /// The VC computes body_root itself and sends the header.
    | Block of BeaconBlockHeader
    | RandaoReveal of Epoch
    /// Selection proof for attestation aggregation at a slot.
    | AggregationSlot of Slot
    /// The AggregateAndProof message (Electra schema) for an aggregate of `slot`.
    | AggregateAndProof of slot: Slot * message: SszObject
    | SyncCommitteeMessage of slot: Slot * beaconBlockRoot: Root
    | SyncSelectionProof of SyncAggregatorSelectionData
    /// The ContributionAndProof message for a contribution of `slot`.
    | ContributionAndProof of slot: Slot * message: SszObject
    | VoluntaryExit of VoluntaryExit
    /// Gloas PTC vote: the data is signed, not the message with the validator index.
    | PayloadAttestation of PayloadAttestationData
    /// Gloas: the ExecutionPayloadEnvelope of a self-built block at `slot`, signed with the
    /// validator key under DOMAIN_BEACON_BUILDER.
    | PayloadEnvelope of slot: Slot * message: SszObject
    | ProposerPreferences of ProposerPreferences
    /// builder-specs Gloas: out of protocol, authenticates requests to an external builder.
    | BuilderRequestAuth of BuilderRequestAuth
    /// builder-specs, pre-Gloas: out of protocol, tells relays (through the node) a key's fee
    /// recipient and gas limit.
    | ValidatorRegistration of ValidatorRegistration

    member this.Kind =
        match this with
        | Attestation _ -> DutyKind.Attestation
        | Block _ -> DutyKind.Block
        | RandaoReveal _ -> DutyKind.RandaoReveal
        | AggregationSlot _ -> DutyKind.AggregationSlot
        | AggregateAndProof _ -> DutyKind.AggregateAndProof
        | SyncCommitteeMessage _ -> DutyKind.SyncCommitteeMessage
        | SyncSelectionProof _ -> DutyKind.SyncSelectionProof
        | ContributionAndProof _ -> DutyKind.ContributionAndProof
        | VoluntaryExit _ -> DutyKind.VoluntaryExit
        | PayloadAttestation _ -> DutyKind.PayloadAttestation
        | PayloadEnvelope _ -> DutyKind.PayloadEnvelope
        | ProposerPreferences _ -> DutyKind.ProposerPreferences
        | BuilderRequestAuth _ -> DutyKind.BuilderRequestAuth
        | ValidatorRegistration _ -> DutyKind.ValidatorRegistration

    /// Attestations and blocks go through slashing protection; the rest do not. Gloas PTC votes
    /// and envelopes are not slashable on chain (consensus-specs gloas, no slashing operation).
    member this.IsSlashable =
        match this with
        | Attestation _
        | Block _ -> true
        | _ -> false

    /// Kinds whose requests to threshold members are never cancelled once sent, so every member
    /// records the message: the slashable kinds, PTC votes and envelopes.
    member this.KeepsStragglers =
        match this with
        | Attestation _
        | Block _
        | PayloadAttestation _
        | PayloadEnvelope _ -> true
        | _ -> false

/// The fork and genesis validators root a request is signed under.
type ForkInfo =
    {
        Fork: Fork
        GenesisValidatorsRoot: Root
    }

[<RequireQualifiedAccess>]
type Priority =
    | High
    | Low

type SignRequest =
    {
        /// The validator key. A share backend maps it to its share.
        Key: PubKey
        Duty: Duty
        Fork: ForkInfo
        /// Computed by the VC. Remote signers recompute and compare.
        Domain: Domain
        /// compute_signing_root of the duty under Domain, computed once per message: a burst of
        /// attestations with the same data shares one root.
        SigningRoot: Root
        Priority: Priority
        Deadline: DateTimeOffset
    }

/// How the signers asked for one request answered, counted as go-eth2-wallet-dirk counts them:
/// signed, denied (a refusal such as Dirk's DENIED), failed (the signer answered but could not
/// sign) and errored (no answer: timeout or transport).
type Tally =
    {
        Signed: int
        Denied: int
        Failed: int
        Errored: int
    }

    member this.Describe =
        $"{this.Signed} signed, {this.Denied} denied, {this.Failed} failed, {this.Errored} errored"

type Refusal =
    /// Never retried. An alarm if the VC's own slashing DB allowed the request: a remote signer
    /// that names slashing as its reason halts the key.
    | Slashable of string
    /// tee-signer already signed another message for this target or slot, or a vote with a
    /// newer source (SC_ERR_SLASH_TARGET, SC_ERR_SLASH_SOURCE, SC_ERR_SLASH_BLOCK,
    /// SC_ERR_EQUIVOCATION), and the operator said another VC shares the
    /// keys (modules.tee.ha_peer): that peer won the duty. Skipped; the key keeps signing.
    | LostToPeer of string
    | PolicyDenied of string
    /// A remote signer denied the request without a reason (Dirk's DENIED), or too few members
    /// of a group signed and at least one denied. Skipped, never retried, the key keeps signing.
    | Denied of reason: string * tally: Tally
    /// Restart floor, no trusted time, setup pending. The epoch, when known, is the first one
    /// the key signs again.
    | NotReadyUntil of Epoch voption
    | UnknownKey
    | Unsupported of DutyKind
    | DomainMismatch
    | BadRequest of string
    /// An emergency switch of the operator stops this duty kind (stop_signing, paused_duties).
    /// Never sent to a backend, never halts a key.
    | Paused of string

    member this.Describe =
        match this with
        | Slashable why -> $"slashable: {why}"
        | LostToPeer why -> $"lost to an HA peer: {why}"
        | PolicyDenied why -> $"policy: {why}"
        | Denied(why, t) -> $"denied: {why} ({t.Describe})"
        | NotReadyUntil(ValueSome e) -> $"not ready until epoch {e}"
        | NotReadyUntil ValueNone -> "not ready"
        | UnknownKey -> "unknown key"
        | Unsupported _ -> "duty kind not supported"
        | DomainMismatch -> "domain mismatch"
        | BadRequest why -> $"bad request: {why}"
        | Paused why -> $"paused: {why}"

type SignFailure =
    | Timeout
    | Transport of string
    | Internal of string
    /// The signer answered that it cannot sign at the moment (a TEE runner whose HEALTH refuses).
    | Unavailable of string
    /// The signer answered that it no longer serves the key: handed over to another signer, or
    /// its slashing log is lost. It will not sign the key again; the operator acts.
    | Gone of string

type SignOutcome =
    | Signed of BlsSignature
    | Partial of shareIndex: uint64 * BlsSignature
    | Refused of Refusal
    | Failed of SignFailure

    member this.Describe =
        match this with
        | Signed _ -> "signed"
        | Partial(i, _) -> $"partial {i}"
        | Refused r -> $"refused, {r.Describe}"
        | Failed Timeout -> "timed out"
        | Failed(Transport m) -> $"transport: {m}"
        | Failed(Internal m) -> $"internal: {m}"
        | Failed(Unavailable m) -> $"unavailable: {m}"
        | Failed(Gone m) -> $"gone: {m}"

type Capabilities =
    {
        Duties: Set<DutyKind>
        /// Refuses bare roots, as tee-signer runners do.
        TypedOnly: bool
        EnforcesSlashing: bool
        ReturnsPartials: bool
        MaxInFlight: int
    }

type Health =
    | Up
    | Degraded of string
    | NotReadyUntil of Epoch
    | Down of string

type KeyEntry =
    {
        Key: PubKey
        Share: struct (uint64 * PubKey) voption
    }

/// A record of functions, so tests build fakes in a few lines and wrappers compose.
type Backend =
    {
        Name: string
        Capabilities: Capabilities
        Keys: CancellationToken -> Task<KeyEntry list>
        Health: CancellationToken -> Task<Health>
        Sign: SignRequest -> CancellationToken -> Task<SignOutcome>
        Dispose: unit -> ValueTask
    }

module Duty =
    let objectRoot (duty: Duty) : Root =
        match duty with
        | Duty.Attestation d -> Codec.hashAttestationData d
        | Duty.Block h -> Codec.hashBeaconBlockHeader h
        | Duty.RandaoReveal e -> Codec.hashEpoch e
        | Duty.AggregationSlot s -> Codec.hashSlot s
        | Duty.AggregateAndProof(_, m) -> m.HashTreeRoot
        | Duty.SyncCommitteeMessage(_, root) -> root
        | Duty.SyncSelectionProof d -> Codec.hashSyncAggregatorSelectionData d
        | Duty.ContributionAndProof(_, m) -> m.HashTreeRoot
        | Duty.VoluntaryExit x -> Codec.hashVoluntaryExit x
        | Duty.PayloadAttestation d -> Codec.hashPayloadAttestationData d
        | Duty.PayloadEnvelope(_, m) -> m.HashTreeRoot
        | Duty.ProposerPreferences p -> Codec.hashProposerPreferences p
        | Duty.BuilderRequestAuth a -> Codec.hashBuilderRequestAuth a
        | Duty.ValidatorRegistration r -> Codec.hashValidatorRegistration r

    /// The domain type of each duty kind: a constant of the specs, never a value from the chain
    /// spec, so no node can have one kind signed under another kind's domain.
    let domainType (duty: Duty) : DomainType =
        match duty with
        | Duty.Attestation _ -> DomainTypes.BeaconAttester
        | Duty.Block _ -> DomainTypes.BeaconProposer
        | Duty.RandaoReveal _ -> DomainTypes.Randao
        | Duty.AggregationSlot _ -> DomainTypes.SelectionProof
        | Duty.AggregateAndProof _ -> DomainTypes.AggregateAndProof
        | Duty.SyncCommitteeMessage _ -> DomainTypes.SyncCommittee
        | Duty.SyncSelectionProof _ -> DomainTypes.SyncCommitteeSelectionProof
        | Duty.ContributionAndProof _ -> DomainTypes.ContributionAndProof
        | Duty.VoluntaryExit _ -> DomainTypes.VoluntaryExit
        | Duty.PayloadAttestation _ -> DomainTypes.PtcAttester
        | Duty.PayloadEnvelope _ -> DomainTypes.BeaconBuilder
        | Duty.ProposerPreferences _ -> DomainTypes.ProposerPreferences
        | Duty.BuilderRequestAuth _ -> DomainTypes.BuilderRequestAuth
        | Duty.ValidatorRegistration _ -> DomainTypes.ApplicationBuilder

    /// Whether the request's domain starts with its duty kind's domain type. Duty.requests builds
    /// every request that way; the pipeline checks it before any mark or backend sees the request,
    /// so a request built another way cannot carry another kind's domain (four byte compares).
    let domainFits (r: SignRequest) : bool =
        let t = (domainType r.Duty).Bytes
        let d = r.Domain.Bytes
        d[0] = t[0] && d[1] = t[1] && d[2] = t[2] && d[3] = t[3]

    /// The epoch whose fork version signs the duty: the target epoch for attestations,
    /// the slot's epoch for slot-based messages, the given epoch otherwise.
    let signingEpoch (spec: ChainSpec) (duty: Duty) : Epoch =
        match duty with
        | Duty.Attestation d -> d.Target.Epoch
        | Duty.Block h -> spec.EpochOf h.Slot
        | Duty.RandaoReveal e -> e
        | Duty.AggregationSlot s
        | Duty.AggregateAndProof(s, _)
        | Duty.SyncCommitteeMessage(s, _)
        | Duty.ContributionAndProof(s, _) -> spec.EpochOf s
        | Duty.SyncSelectionProof d -> spec.EpochOf d.Slot
        | Duty.VoluntaryExit x -> x.Epoch
        | Duty.PayloadAttestation d -> spec.EpochOf d.Slot
        | Duty.PayloadEnvelope(s, _) -> spec.EpochOf s
        // validator.md: compute_fork_version(proposal_epoch), not the state's fork.
        | Duty.ProposerPreferences p -> spec.EpochOf p.ProposalSlot
        | Duty.BuilderRequestAuth _
        | Duty.ValidatorRegistration _ -> 0UL

    /// get_domain for the duty. Exits use the Capella fork version since Deneb (EIP-7044).
    /// Builder request auth uses compute_domain's defaults: the genesis fork version and a zero
    /// genesis validators root (builder-specs Gloas). So do validator registrations
    /// (builder-specs, compute_builder_domain).
    let domain (spec: ChainSpec) (gvr: Root) (duty: Duty) : Domain =
        match duty with
        | Duty.VoluntaryExit _ -> Signing.computeDomain DomainTypes.VoluntaryExit spec.ExitForkVersion gvr
        | Duty.BuilderRequestAuth _ ->
            Signing.computeDomain DomainTypes.BuilderRequestAuth spec.GenesisForkVersion Root.Zero
        | Duty.ValidatorRegistration _ ->
            Signing.computeDomain DomainTypes.ApplicationBuilder spec.GenesisForkVersion Root.Zero
        | _ -> Signing.domainAt spec gvr (domainType duty) (signingEpoch spec duty)

    /// Requests for one message signed by several keys: fork info, domain and signing root are
    /// computed once.
    let private requestsFor
        (spec: ChainSpec)
        (gvr: Root)
        (keys: PubKey[])
        (priority: Priority)
        (deadline: DateTimeOffset)
        (duty: Duty)
        (dutyRoot: Root)
        =
        let fork =
            {
                Fork = spec.ForkInfoAt(signingEpoch spec duty)
                GenesisValidatorsRoot = gvr
            }

        let d = domain spec gvr duty
        let root = Signing.computeSigningRoot dutyRoot d

        keys
        |> Array.map (fun key ->
            {
                Key = key
                Duty = duty
                Fork = fork
                Domain = d
                SigningRoot = root
                Priority = priority
                Deadline = deadline
            })

    let requests
        (spec: ChainSpec)
        (gvr: Root)
        (keys: PubKey[])
        (priority: Priority)
        (deadline: DateTimeOffset)
        (duty: Duty)
        =
        requestsFor spec gvr keys priority deadline duty (objectRoot duty)

    /// A complete request for the duty, with fork info, domain and signing root computed here.
    let request
        (spec: ChainSpec)
        (gvr: Root)
        (key: PubKey)
        (priority: Priority)
        (deadline: DateTimeOffset)
        (duty: Duty)
        =
        (requests spec gvr [| key |] priority deadline duty)[0]

    /// `request` with the duty's object root hashed ahead of time, from the same message: a
    /// payload envelope hashes while its block is signed and published.
    let requestWithRoot
        (spec: ChainSpec)
        (gvr: Root)
        (key: PubKey)
        (priority: Priority)
        (deadline: DateTimeOffset)
        (duty: Duty)
        (dutyRoot: Root)
        =
        (requestsFor spec gvr [| key |] priority deadline duty dutyRoot)[0]

module Refusal =
    let describe (r: Refusal) = r.Describe

module SignOutcome =
    let describe (o: SignOutcome) = o.Describe

module SignRequest =
    let signingRoot (r: SignRequest) : Root = r.SigningRoot
