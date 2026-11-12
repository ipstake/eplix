/// How optional parts plug in. NativeAOT links everything at build time, so a module is a
/// project the host references (or not) and exposes one Module value.
namespace Eplix

open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Slashing

/// Results of the keymanager keystore calls, as the keymanager API names them.
[<RequireQualifiedAccess>]
type ImportStatus =
    | Imported
    | Duplicate
    | Error of string

[<RequireQualifiedAccess>]
type DeleteStatus =
    | Deleted
    | NotFound
    | Error of string

type StoredKeystore =
    {
        Key: PubKey
        DerivationPath: string
        ReadOnly: bool
    }

/// Keystores a module holds and can add or remove at run time (the local backend). The keymanager
/// API and the import command use it.
type KeystoreStore =
    {
        List: unit -> StoredKeystore list
        /// Decrypts, saves and registers each (keystore JSON, password). Keys stay discovered until
        /// the history check passes.
        Import: (string * string) list -> CancellationToken -> Task<ImportStatus list>
        /// Stops signing with the keys and deletes their files. The caller drains them first.
        Delete: PubKey list -> CancellationToken -> Task<DeleteStatus list>
    }

/// A key that signs through a remote signer URL (the keymanager API's remote keys).
type RemoteKey =
    {
        Key: PubKey
        Url: string
        /// Configured keys are read-only; keys the API added are not.
        ReadOnly: bool
    }

/// Remote keys a module can add or remove at run time (the Web3Signer module). The keymanager
/// API's /eth/v1/remotekeys uses it.
type RemoteKeyStore =
    {
        List: unit -> RemoteKey list
        /// Registers each (key, signer URL) as a whole key of that signer and keeps it across
        /// restarts. Without a URL the module's only configured signer is used. Keys stay
        /// discovered until the history check passes.
        Import: (PubKey * string voption) list -> CancellationToken -> Task<ImportStatus list>
        /// Drains each key the API added (no new duty, signatures in flight finish), then removes
        /// it. Its slashing record stays in the DB.
        Delete: PubKey list -> CancellationToken -> Task<DeleteStatus list>
    }

/// Defaults for per-key settings.
type KeyDefaults =
    {
        FeeRecipient: string voption
        Graffiti: string
        GasLimit: uint64
    }

/// What the scheduler shares with a duty extension.
type SchedulerView =
    {
        /// This VC's proposer duties of an epoch, once fetched.
        ProposerDuties: Epoch -> Duties<ProposerDuty> voption
        /// This VC's attester duties of an epoch, once fetched (keys in any state).
        AttesterDuties: Epoch -> Duties<AttesterDuty> voption
        /// This VC's sync committee seats for the messages of an epoch, once fetched. The messages
        /// of slot s use the seats of the epoch of slot s + 1.
        SyncDuties: Epoch -> SyncDuty[] voption
        /// The block root of the first head event for a slot.
        HeadRoot: Slot -> Root voption
    }

/// Duties a module adds to the scheduler: the Gloas duties module (PTC votes, Gloas proposals
/// with their envelopes, proposer preferences) and the builder module (builder preferences).
/// The scheduler calls each function in the background; a failure is logged and does not stop
/// other duties.
type DutyExtension =
    {
        Name: string
        /// SSE topics to read besides head (each needs a node that serves it).
        Topics: string list
        OnEvent: SseEvent -> unit
        OnHead: HeadEvent -> unit
        /// Once per slot after the scheduler fetched the duties of `epoch` and the next epoch.
        /// `epoch` is the clock's epoch: never ask a node for duties past `epoch` + 1.
        PrepareEpochs: SchedulerView -> Epoch -> CancellationToken -> Task
        /// At the start of each slot.
        RunSlot: SchedulerView -> Slot -> CancellationToken -> Task
        /// Proposes the block of a slot this extension's fork handles. ValueNone: not its fork.
        Propose: SchedulerView -> ProposerDuty -> CancellationToken -> Task<bool> voption
        /// Pre-Gloas proposals: the builder_boost_factor to ask produceBlockV3 for (the legacy
        /// builder module). ValueNone: not this extension's call. With no answer the node builds
        /// locally (factor 0).
        BuilderBoost: ProposerDuty -> uint64 voption
    }

module DutyExtension =
    /// An extension that does nothing; modules override the parts they need.
    let empty (name: string) : DutyExtension =
        {
            Name = name
            Topics = []
            OnEvent = ignore
            OnHead = ignore
            PrepareEpochs = fun _ _ _ -> Task.CompletedTask
            RunSlot = fun _ _ _ -> Task.CompletedTask
            Propose = fun _ _ _ -> ValueNone
            BuilderBoost = fun _ -> ValueNone
        }

/// What the builder module offers the Gloas proposal flow.
type BuilderHooks =
    {
        /// The builders to ask for a bid for this proposal, each with its signed request auth.
        /// Empty when the key has none (or its signer cannot sign the auth: p2p bids only).
        EntriesFor: ProposerDuty -> CancellationToken -> Task<BuilderEntry list>
        /// Checks the SignedExecutionPayloadBid of a block won over the builder API
        /// (Eth-Builder-Url names the builder) before the VC signs it. Error: the VC asks again
        /// and self-builds.
        CheckBid: ProposerDuty -> string -> Ssz.SszValue -> Result<unit, string>
    }

/// One selection proof of an attester duty, as POST /eth/v1/validator/beacon_committee_selections
/// carries it.
type BeaconCommitteeSelection =
    {
        ValidatorIndex: ValidatorIndex
        Slot: Slot
        SelectionProof: BlsSignature
    }

/// One selection proof of a sync committee duty, as POST
/// /eth/v1/validator/sync_committee_selections carries it.
type SyncCommitteeSelection =
    {
        ValidatorIndex: ValidatorIndex
        Slot: Slot
        SubcommitteeIndex: uint64
        SelectionProof: BlsSignature
    }

/// Turns the selection proofs this VC signed into the proofs that decide aggregation. In a
/// distributed validator cluster (the Obol module) the VC signs with a key share, so its proof is
/// a partial; the middleware combines the partials of the cluster and returns the combined proof.
/// The scheduler calls these after it signed the proofs and before it picks aggregators. An
/// entry missing from the answer does not aggregate; an Error means none of the batch does.
type SelectionHooks =
    {
        /// One call per epoch of attester duties (per retry pass), all slots of the epoch.
        BeaconCommittee:
            BeaconCommitteeSelection[] -> CancellationToken -> Task<Result<BeaconCommitteeSelection[], string>>
        /// One call per slot of sync committee duties (per retry pass).
        SyncCommittee: SyncCommitteeSelection[] -> CancellationToken -> Task<Result<SyncCommitteeSelection[], string>>
    }

module ModuleNames =
    /// The name the Gloas duties module registers under; a chain that schedules Gloas needs it.
    [<Literal>]
    let Gloas = "gloas"

type CoreServices =
    {
        Spec: ChainSpec
        Genesis: Genesis
        Clock: SlotClock
        Nodes: BeaconNodes
        Registry: KeyRegistry
        Pipeline: Pipeline
        Slashing: SlashingDb
        Defaults: KeyDefaults
        /// The graffiti of each proposal; a graffiti module offers its source here (SetSource).
        Graffiti: GraffitiService
        Log: Log
        DataDir: string
        /// Adds a backend and routes each key it lists to it.
        RegisterBackend: Backend -> Task<unit>
        /// Moves new keys through the history check now instead of at the next epoch.
        RefreshKeys: CancellationToken -> Task
        /// Runs a function at the start of each epoch, after the key refresh and before duties are
        /// fetched (the doppelganger module checks liveness here).
        OnEpoch: (Epoch -> CancellationToken -> Task) -> unit
        /// Stops the VC: duties end, modules stop, and the run returns this reason as its error
        /// (the binary exits with code 1). The first reason wins.
        Shutdown: string -> unit
        /// Fires when Shutdown is called or the caller's token fires.
        Stopping: CancellationToken
        /// A module that holds keystores offers them here (at most one).
        SetKeystores: KeystoreStore -> unit
        Keystores: unit -> KeystoreStore voption
        /// A module that signs through remote signers offers its remote keys here (at most one).
        SetRemoteKeys: RemoteKeyStore -> unit
        RemoteKeys: unit -> RemoteKeyStore voption
        /// Adds duties to the scheduler (Gloas duties, builder preferences).
        AddDutyExtension: DutyExtension -> unit
        /// The builder module offers its hooks here; the Gloas module reads them per proposal.
        SetBuilder: BuilderHooks -> unit
        Builder: unit -> BuilderHooks voption
        /// The Obol module offers its selection hooks here (at most one); the scheduler uses them
        /// for aggregator selection. Without them the VC's own proofs decide.
        SetSelections: SelectionHooks -> unit
        /// modules.tee.ha_peer: every key must sign through the tee module, so other modules
        /// add no key at run time.
        HaPeer: bool
    }

type StartedModule = { Stop: unit -> Task }

type Module =
    {
        Name: string
        /// Reads and checks the module's config section before anything starts.
        Configure: ConfigSection -> Result<unit, string list>
        /// Offline self-check for `eplix check` (for example: decrypt the keystores). Returns a summary line.
        Check: Log -> Result<string, string list>
        Start: CoreServices -> CancellationToken -> Task<Result<StartedModule, string>>
    }
