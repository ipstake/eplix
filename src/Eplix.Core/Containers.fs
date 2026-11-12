/// Consensus containers the VC signs or checks, as typed records with their SSZ schemas.
/// Small messages the VC builds are typed records. Large ones it only passes on (blocks,
/// aggregates, contributions) stay SszValue trees over their schema.
namespace Eplix

open System
open System.Globalization
open Eplix.Ssz

type Checkpoint = { Epoch: Epoch; Root: Root }

type AttestationData =
    {
        Slot: Slot
        Index: CommitteeIndex
        BeaconBlockRoot: Root
        Source: Checkpoint
        Target: Checkpoint
    }

type Fork =
    {
        PreviousVersion: ForkVersion
        CurrentVersion: ForkVersion
        Epoch: Epoch
    }

type ForkData =
    {
        CurrentVersion: ForkVersion
        GenesisValidatorsRoot: Root
    }

type SigningData = { ObjectRoot: Root; Domain: Domain }

type BeaconBlockHeader =
    {
        Slot: Slot
        ProposerIndex: ValidatorIndex
        ParentRoot: Root
        StateRoot: Root
        BodyRoot: Root
    }

/// The attestation a single validator submits since Electra.
type SingleAttestation =
    {
        CommitteeIndex: CommitteeIndex
        AttesterIndex: ValidatorIndex
        Data: AttestationData
        Signature: BlsSignature
    }

type VoluntaryExit =
    {
        Epoch: Epoch
        ValidatorIndex: ValidatorIndex
    }

type SyncAggregatorSelectionData =
    {
        Slot: Slot
        SubcommitteeIndex: uint64
    }

/// Gloas: what a payload timeliness committee (PTC) member votes on.
type PayloadAttestationData =
    {
        BeaconBlockRoot: Root
        Slot: Slot
        PayloadPresent: bool
        BlobDataAvailable: bool
    }

/// Gloas: a proposer's fee recipient and gas limit for one proposal slot (p2p-interface.md).
type ProposerPreferences =
    {
        DependentRoot: Root
        ProposalSlot: Slot
        ValidatorIndex: ValidatorIndex
        /// 20 bytes.
        FeeRecipient: byte[]
        TargetGasLimit: uint64
    }

/// builder-specs Gloas: authenticates requests to one external builder for one proposal slot.
/// Out of protocol; signed under DOMAIN_BUILDER_REQUEST_AUTH with the genesis fork version.
type BuilderRequestAuth =
    {
        /// Up to 4096 bytes agreed with the builder; by default its URL's host name.
        AuthData: byte[]
        AuthSlot: Slot
    }

/// builder-specs ValidatorRegistrationV1: the fee recipient and gas limit a key asks relays to
/// build for. Out of protocol; signed under DOMAIN_APPLICATION_BUILDER with the genesis fork
/// version and a zero genesis validators root. Pre-Gloas only.
type ValidatorRegistration =
    {
        /// 20 bytes.
        FeeRecipient: byte[]
        GasLimit: uint64
        /// Unix seconds.
        Timestamp: uint64
        PubKey: PubKey
    }

/// A value with its schema, for containers the VC passes on without a typed record.
type SszObject =
    {
        Schema: SszType
        Value: SszValue
    }

    member this.HashTreeRoot = Root.Of(hashTreeRoot this.Schema this.Value)
    member this.Serialize() = serialize this.Schema this.Value

/// Preset values that change container shapes. The beacon node reports them in /eth/v1/config/spec;
/// FromSpec reads them there and falls back to the preset named by PRESET_BASE.
type Preset =
    {
        MaxValidatorsPerCommittee: int
        MaxCommitteesPerSlot: int
        SyncCommitteeSize: int
        MaxProposerSlashings: int
        MaxAttesterSlashingsElectra: int
        MaxAttestationsElectra: int
        MaxDeposits: int
        MaxVoluntaryExits: int
        MaxBlsToExecutionChanges: int
        MaxBlobCommitmentsPerBlock: int
        MaxWithdrawalsPerPayload: int
        MaxDepositRequestsPerPayload: int
        MaxWithdrawalRequestsPerPayload: int
        MaxConsolidationRequestsPerPayload: int
        MaxTransactionsPerPayload: int
        MaxBytesPerTransaction: int
        MaxExtraDataBytes: int
        BytesPerLogsBloom: int
        FieldElementsPerBlob: int
        FieldElementsPerExtBlob: int
        DepositContractTreeDepth: int
        /// Gloas: members of the payload timeliness committee per slot.
        PtcSize: int
    }

    static member Mainnet =
        {
            MaxValidatorsPerCommittee = 2048
            MaxCommitteesPerSlot = 64
            SyncCommitteeSize = 512
            MaxProposerSlashings = 16
            MaxAttesterSlashingsElectra = 1
            MaxAttestationsElectra = 8
            MaxDeposits = 16
            MaxVoluntaryExits = 16
            MaxBlsToExecutionChanges = 16
            MaxBlobCommitmentsPerBlock = 4096
            MaxWithdrawalsPerPayload = 16
            MaxDepositRequestsPerPayload = 8192
            MaxWithdrawalRequestsPerPayload = 16
            MaxConsolidationRequestsPerPayload = 2
            MaxTransactionsPerPayload = 1048576
            MaxBytesPerTransaction = 1073741824
            MaxExtraDataBytes = 32
            BytesPerLogsBloom = 256
            FieldElementsPerBlob = 4096
            FieldElementsPerExtBlob = 8192
            DepositContractTreeDepth = 32
            PtcSize = 512
        }

    static member Minimal =
        { Preset.Mainnet with
            MaxCommitteesPerSlot = 4
            SyncCommitteeSize = 32
            MaxWithdrawalsPerPayload = 4
            PtcSize = 16
        }

    /// The preset from the spec values the beacon node reports.
    static member FromSpec(values: Map<string, string>) : Preset =
        let basePreset =
            match values.TryFind "PRESET_BASE" |> Option.map (fun s -> s.Trim('"', '\'').ToLowerInvariant()) with
            | Some "minimal" -> Preset.Minimal
            | _ -> Preset.Mainnet

        let get (key: string) (fallback: int) =
            match values.TryFind key with
            | Some s ->
                match Int32.TryParse(s.Trim('"', '\''), NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, v when v > 0 -> v
                | _ -> fallback
            | None -> fallback

        let b = basePreset

        {
            MaxValidatorsPerCommittee = get "MAX_VALIDATORS_PER_COMMITTEE" b.MaxValidatorsPerCommittee
            MaxCommitteesPerSlot = get "MAX_COMMITTEES_PER_SLOT" b.MaxCommitteesPerSlot
            SyncCommitteeSize = get "SYNC_COMMITTEE_SIZE" b.SyncCommitteeSize
            MaxProposerSlashings = get "MAX_PROPOSER_SLASHINGS" b.MaxProposerSlashings
            MaxAttesterSlashingsElectra = get "MAX_ATTESTER_SLASHINGS_ELECTRA" b.MaxAttesterSlashingsElectra
            MaxAttestationsElectra = get "MAX_ATTESTATIONS_ELECTRA" b.MaxAttestationsElectra
            MaxDeposits = get "MAX_DEPOSITS" b.MaxDeposits
            MaxVoluntaryExits = get "MAX_VOLUNTARY_EXITS" b.MaxVoluntaryExits
            MaxBlsToExecutionChanges = get "MAX_BLS_TO_EXECUTION_CHANGES" b.MaxBlsToExecutionChanges
            MaxBlobCommitmentsPerBlock = get "MAX_BLOB_COMMITMENTS_PER_BLOCK" b.MaxBlobCommitmentsPerBlock
            MaxWithdrawalsPerPayload = get "MAX_WITHDRAWALS_PER_PAYLOAD" b.MaxWithdrawalsPerPayload
            MaxDepositRequestsPerPayload = get "MAX_DEPOSIT_REQUESTS_PER_PAYLOAD" b.MaxDepositRequestsPerPayload
            MaxWithdrawalRequestsPerPayload =
                get "MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD" b.MaxWithdrawalRequestsPerPayload
            MaxConsolidationRequestsPerPayload =
                get "MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD" b.MaxConsolidationRequestsPerPayload
            MaxTransactionsPerPayload = get "MAX_TRANSACTIONS_PER_PAYLOAD" b.MaxTransactionsPerPayload
            MaxBytesPerTransaction = get "MAX_BYTES_PER_TRANSACTION" b.MaxBytesPerTransaction
            MaxExtraDataBytes = get "MAX_EXTRA_DATA_BYTES" b.MaxExtraDataBytes
            BytesPerLogsBloom = get "BYTES_PER_LOGS_BLOOM" b.BytesPerLogsBloom
            FieldElementsPerBlob = get "FIELD_ELEMENTS_PER_BLOB" b.FieldElementsPerBlob
            FieldElementsPerExtBlob = get "FIELD_ELEMENTS_PER_EXT_BLOB" b.FieldElementsPerExtBlob
            DepositContractTreeDepth = get "DEPOSIT_CONTRACT_TREE_DEPTH" b.DepositContractTreeDepth
            PtcSize = get "PTC_SIZE" b.PtcSize
        }

    /// Sync committee subnets are fixed at 4 (SYNC_COMMITTEE_SUBNET_COUNT).
    member this.SyncSubcommitteeSize = this.SyncCommitteeSize / 4

module Schemas =
    let uint64 = Uint 8
    let bytes32 = ByteVector 32
    let bytes4 = ByteVector 4
    let pubkey = ByteVector 48
    let signature = ByteVector 96
    let address = ByteVector 20

    let checkpoint = Container [| "epoch", uint64; "root", bytes32 |]

    let attestationData =
        Container
            [|
                "slot", uint64
                "index", uint64
                "beacon_block_root", bytes32
                "source", checkpoint
                "target", checkpoint
            |]

    let fork = Container [| "previous_version", bytes4; "current_version", bytes4; "epoch", uint64 |]
    let forkData = Container [| "current_version", bytes4; "genesis_validators_root", bytes32 |]
    let signingData = Container [| "object_root", bytes32; "domain", bytes32 |]

    let beaconBlockHeader =
        Container
            [|
                "slot", uint64
                "proposer_index", uint64
                "parent_root", bytes32
                "state_root", bytes32
                "body_root", bytes32
            |]

    let singleAttestation =
        Container
            [|
                "committee_index", uint64
                "attester_index", uint64
                "data", attestationData
                "signature", signature
            |]

    let voluntaryExit = Container [| "epoch", uint64; "validator_index", uint64 |]

    let validator =
        Container
            [|
                "pubkey", pubkey
                "withdrawal_credentials", bytes32
                "effective_balance", uint64
                "slashed", Boolean
                "activation_eligibility_epoch", uint64
                "activation_epoch", uint64
                "exit_epoch", uint64
                "withdrawable_epoch", uint64
            |]

    /// Electra and later.
    let attestation (p: Preset) =
        Container
            [|
                "aggregation_bits", Bitlist(p.MaxValidatorsPerCommittee * p.MaxCommitteesPerSlot)
                "data", attestationData
                "signature", signature
                "committee_bits", Bitvector p.MaxCommitteesPerSlot
            |]

    /// Electra and later.
    let indexedAttestation (p: Preset) =
        Container
            [|
                "attesting_indices", List(uint64, p.MaxValidatorsPerCommittee * p.MaxCommitteesPerSlot)
                "data", attestationData
                "signature", signature
            |]

    // ---- Block body, Electra and Fulu (the body did not change in Fulu) ----

    let eth1Data = Container [| "deposit_root", bytes32; "deposit_count", uint64; "block_hash", bytes32 |]

    let signedBeaconBlockHeader = Container [| "message", beaconBlockHeader; "signature", signature |]

    let proposerSlashing =
        Container
            [|
                "signed_header_1", signedBeaconBlockHeader
                "signed_header_2", signedBeaconBlockHeader
            |]

    let attesterSlashing (p: Preset) =
        Container
            [|
                "attestation_1", indexedAttestation p
                "attestation_2", indexedAttestation p
            |]

    let depositData =
        Container
            [|
                "pubkey", pubkey
                "withdrawal_credentials", bytes32
                "amount", uint64
                "signature", signature
            |]

    let deposit (p: Preset) =
        Container
            [|
                "proof", Vector(bytes32, p.DepositContractTreeDepth + 1)
                "data", depositData
            |]

    let signedVoluntaryExit = Container [| "message", voluntaryExit; "signature", signature |]

    let syncAggregate (p: Preset) =
        Container
            [|
                "sync_committee_bits", Bitvector p.SyncCommitteeSize
                "sync_committee_signature", signature
            |]

    let withdrawal =
        Container
            [|
                "index", uint64
                "validator_index", uint64
                "address", address
                "amount", uint64
            |]

    /// Deneb and later.
    let executionPayload (p: Preset) =
        Container
            [|
                "parent_hash", bytes32
                "fee_recipient", address
                "state_root", bytes32
                "receipts_root", bytes32
                "logs_bloom", ByteVector p.BytesPerLogsBloom
                "prev_randao", bytes32
                "block_number", uint64
                "gas_limit", uint64
                "gas_used", uint64
                "timestamp", uint64
                "extra_data", ByteList p.MaxExtraDataBytes
                "base_fee_per_gas", Uint256
                "block_hash", bytes32
                "transactions", List(ByteList p.MaxBytesPerTransaction, p.MaxTransactionsPerPayload)
                "withdrawals", List(withdrawal, p.MaxWithdrawalsPerPayload)
                "blob_gas_used", uint64
                "excess_blob_gas", uint64
            |]

    /// Deneb and later.
    let executionPayloadHeader (p: Preset) =
        Container
            [|
                "parent_hash", bytes32
                "fee_recipient", address
                "state_root", bytes32
                "receipts_root", bytes32
                "logs_bloom", ByteVector p.BytesPerLogsBloom
                "prev_randao", bytes32
                "block_number", uint64
                "gas_limit", uint64
                "gas_used", uint64
                "timestamp", uint64
                "extra_data", ByteList p.MaxExtraDataBytes
                "base_fee_per_gas", Uint256
                "block_hash", bytes32
                "transactions_root", bytes32
                "withdrawals_root", bytes32
                "blob_gas_used", uint64
                "excess_blob_gas", uint64
            |]

    let blsToExecutionChange =
        Container
            [|
                "validator_index", uint64
                "from_bls_pubkey", pubkey
                "to_execution_address", address
            |]

    let signedBlsToExecutionChange = Container [| "message", blsToExecutionChange; "signature", signature |]

    let depositRequest =
        Container
            [|
                "pubkey", pubkey
                "withdrawal_credentials", bytes32
                "amount", uint64
                "signature", signature
                "index", uint64
            |]

    let withdrawalRequest =
        Container [| "source_address", address; "validator_pubkey", pubkey; "amount", uint64 |]

    let consolidationRequest =
        Container
            [|
                "source_address", address
                "source_pubkey", pubkey
                "target_pubkey", pubkey
            |]

    let executionRequests (p: Preset) =
        Container
            [|
                "deposits", List(depositRequest, p.MaxDepositRequestsPerPayload)
                "withdrawals", List(withdrawalRequest, p.MaxWithdrawalRequestsPerPayload)
                "consolidations", List(consolidationRequest, p.MaxConsolidationRequestsPerPayload)
            |]

    let beaconBlockBody (p: Preset) =
        Container
            [|
                "randao_reveal", signature
                "eth1_data", eth1Data
                "graffiti", bytes32
                "proposer_slashings", List(proposerSlashing, p.MaxProposerSlashings)
                "attester_slashings", List(attesterSlashing p, p.MaxAttesterSlashingsElectra)
                "attestations", List(attestation p, p.MaxAttestationsElectra)
                "deposits", List(deposit p, p.MaxDeposits)
                "voluntary_exits", List(signedVoluntaryExit, p.MaxVoluntaryExits)
                "sync_aggregate", syncAggregate p
                "execution_payload", executionPayload p
                "bls_to_execution_changes", List(signedBlsToExecutionChange, p.MaxBlsToExecutionChanges)
                "blob_kzg_commitments", List(ByteVector 48, p.MaxBlobCommitmentsPerBlock)
                "execution_requests", executionRequests p
            |]

    let beaconBlock (p: Preset) =
        Container
            [|
                "slot", uint64
                "proposer_index", uint64
                "parent_root", bytes32
                "state_root", bytes32
                "body", beaconBlockBody p
            |]

    let signedBeaconBlock (p: Preset) = Container [| "message", beaconBlock p; "signature", signature |]

    let private kzgProofs (p: Preset) = List(ByteVector 48, p.FieldElementsPerExtBlob * p.MaxBlobCommitmentsPerBlock)
    let private blobs (p: Preset) = List(ByteVector(32 * p.FieldElementsPerBlob), p.MaxBlobCommitmentsPerBlock)

    /// Fulu BlockContents (Beacon API): the block with its cell KZG proofs and blobs.
    let blockContents (p: Preset) = Container [| "block", beaconBlock p; "kzg_proofs", kzgProofs p; "blobs", blobs p |]

    let signedBlockContents (p: Preset) =
        Container
            [|
                "signed_block", signedBeaconBlock p
                "kzg_proofs", kzgProofs p
                "blobs", blobs p
            |]

    // ---- Pre-Gloas builder flow (builder-specs) ----

    /// Electra and Fulu: the body with the payload header in place of the payload. Its root
    /// equals the full body's, since a header's root is its payload's.
    let blindedBeaconBlockBody (p: Preset) =
        match beaconBlockBody p with
        | Container fs ->
            Container(
                fs
                |> Array.map (fun (n, t) ->
                    if n = "execution_payload" then "execution_payload_header", executionPayloadHeader p else n, t)
            )
        | t -> t

    let blindedBeaconBlock (p: Preset) =
        Container
            [|
                "slot", uint64
                "proposer_index", uint64
                "parent_root", bytes32
                "state_root", bytes32
                "body", blindedBeaconBlockBody p
            |]

    let signedBlindedBeaconBlock (p: Preset) = Container [| "message", blindedBeaconBlock p; "signature", signature |]

    let validatorRegistration =
        Container
            [|
                "fee_recipient", address
                "gas_limit", uint64
                "timestamp", uint64
                "pubkey", pubkey
            |]

    let signedValidatorRegistration =
        Container [| "message", validatorRegistration; "signature", signature |]

    // ---- Aggregation and sync committee ----

    /// Electra and later.
    let aggregateAndProof (p: Preset) =
        Container
            [|
                "aggregator_index", uint64
                "aggregate", attestation p
                "selection_proof", signature
            |]

    let signedAggregateAndProof (p: Preset) = Container [| "message", aggregateAndProof p; "signature", signature |]

    let syncCommitteeMessage =
        Container
            [|
                "slot", uint64
                "beacon_block_root", bytes32
                "validator_index", uint64
                "signature", signature
            |]

    let syncCommitteeContribution (p: Preset) =
        Container
            [|
                "slot", uint64
                "beacon_block_root", bytes32
                "subcommittee_index", uint64
                "aggregation_bits", Bitvector p.SyncSubcommitteeSize
                "signature", signature
            |]

    let contributionAndProof (p: Preset) =
        Container
            [|
                "aggregator_index", uint64
                "contribution", syncCommitteeContribution p
                "selection_proof", signature
            |]

    let signedContributionAndProof (p: Preset) =
        Container [| "message", contributionAndProof p; "signature", signature |]

    let syncAggregatorSelectionData = Container [| "slot", uint64; "subcommittee_index", uint64 |]

    /// Gloas (consensus-specs v1.7.0-beta.4, the same as master 065bcd5 for specs/gloas): EIP-7688
    /// progressive containers and lists, EIP-7732 bids, envelopes and PTC votes, and the Beacon API
    /// and builder-specs shapes around them.
    module Gloas =
        let attestation (p: Preset) =
            ProgressiveContainer
                [|
                    "aggregation_bits", ProgressiveBitlist
                    "data", attestationData
                    "signature", signature
                    "committee_bits", Bitvector p.MaxCommitteesPerSlot
                |]

        let indexedAttestation =
            ProgressiveContainer
                [|
                    "attesting_indices", ProgressiveList uint64
                    "data", attestationData
                    "signature", signature
                |]

        let attesterSlashing =
            Container [| "attestation_1", indexedAttestation; "attestation_2", indexedAttestation |]

        let builderDepositRequest =
            Container
                [|
                    "pubkey", pubkey
                    "withdrawal_credentials", bytes32
                    "amount", uint64
                    "signature", signature
                |]

        let builderExitRequest = Container [| "source_address", address; "pubkey", pubkey |]

        let executionRequests =
            ProgressiveContainer
                [|
                    "deposits", ProgressiveList depositRequest
                    "withdrawals", ProgressiveList withdrawalRequest
                    "consolidations", ProgressiveList consolidationRequest
                    "builder_deposits", ProgressiveList builderDepositRequest
                    "builder_exits", ProgressiveList builderExitRequest
                |]

        let executionPayload (p: Preset) =
            ProgressiveContainer
                [|
                    "parent_hash", bytes32
                    "fee_recipient", address
                    "state_root", bytes32
                    "receipts_root", bytes32
                    "logs_bloom", ByteVector p.BytesPerLogsBloom
                    "prev_randao", bytes32
                    "block_number", uint64
                    "gas_limit", uint64
                    "gas_used", uint64
                    "timestamp", uint64
                    "extra_data", ByteList p.MaxExtraDataBytes
                    "base_fee_per_gas", Uint256
                    "block_hash", bytes32
                    "transactions", ProgressiveList ProgressiveByteList
                    "withdrawals", ProgressiveList withdrawal
                    "blob_gas_used", uint64
                    "excess_blob_gas", uint64
                    "block_access_list", ProgressiveByteList
                    "slot_number", uint64
                |]

        let executionPayloadBid =
            ProgressiveContainer
                [|
                    "parent_block_hash", bytes32
                    "parent_block_root", bytes32
                    "block_hash", bytes32
                    "prev_randao", bytes32
                    "fee_recipient", address
                    "gas_limit", uint64
                    "builder_index", uint64
                    "slot", uint64
                    "value", uint64
                    "execution_payment", uint64
                    "blob_kzg_commitments", ProgressiveList(ByteVector 48)
                    "execution_requests_root", bytes32
                |]

        let signedExecutionPayloadBid = Container [| "message", executionPayloadBid; "signature", signature |]

        let executionPayloadEnvelope (p: Preset) =
            ProgressiveContainer
                [|
                    "payload", executionPayload p
                    "execution_requests", executionRequests
                    "builder_index", uint64
                    "beacon_block_root", bytes32
                    "parent_beacon_block_root", bytes32
                |]

        let signedExecutionPayloadEnvelope (p: Preset) =
            Container [| "message", executionPayloadEnvelope p; "signature", signature |]

        let payloadAttestationData =
            Container
                [|
                    "beacon_block_root", bytes32
                    "slot", uint64
                    "payload_present", Boolean
                    "blob_data_available", Boolean
                |]

        let payloadAttestation (p: Preset) =
            ProgressiveContainer
                [|
                    "aggregation_bits", Bitvector p.PtcSize
                    "data", payloadAttestationData
                    "signature", signature
                |]

        let payloadAttestationMessage =
            Container
                [|
                    "validator_index", uint64
                    "data", payloadAttestationData
                    "signature", signature
                |]

        let indexedPayloadAttestation (p: Preset) =
            ProgressiveContainer
                [|
                    "attesting_indices", List(uint64, p.PtcSize)
                    "data", payloadAttestationData
                    "signature", signature
                |]

        let beaconBlockBody (p: Preset) =
            ProgressiveContainer
                [|
                    "randao_reveal", signature
                    "eth1_data", eth1Data
                    "graffiti", bytes32
                    "proposer_slashings", ProgressiveList proposerSlashing
                    "attester_slashings", ProgressiveList attesterSlashing
                    "attestations", ProgressiveList(attestation p)
                    "deposits", ProgressiveList(deposit p)
                    "voluntary_exits", ProgressiveList signedVoluntaryExit
                    "sync_aggregate", syncAggregate p
                    "bls_to_execution_changes", ProgressiveList signedBlsToExecutionChange
                    "signed_execution_payload_bid", signedExecutionPayloadBid
                    "payload_attestations", ProgressiveList(payloadAttestation p)
                    "parent_execution_requests", executionRequests
                |]

        let beaconBlock (p: Preset) =
            Container
                [|
                    "slot", uint64
                    "proposer_index", uint64
                    "parent_root", bytes32
                    "state_root", bytes32
                    "body", beaconBlockBody p
                |]

        let signedBeaconBlock (p: Preset) = Container [| "message", beaconBlock p; "signature", signature |]

        let aggregateAndProof (p: Preset) =
            Container
                [|
                    "aggregator_index", uint64
                    "aggregate", attestation p
                    "selection_proof", signature
                |]

        let signedAggregateAndProof (p: Preset) = Container [| "message", aggregateAndProof p; "signature", signature |]

        let proposerPreferences =
            Container
                [|
                    "dependent_root", bytes32
                    "proposal_slot", uint64
                    "validator_index", uint64
                    "fee_recipient", address
                    "target_gas_limit", uint64
                |]

        let signedProposerPreferences = Container [| "message", proposerPreferences; "signature", signature |]

        /// builder-specs: MAX_BUILDER_AUTH_DATA_SIZE = 4096.
        let builderRequestAuth = Container [| "data", ByteList 4096; "slot", uint64 |]

        let signedBuilderRequestAuth = Container [| "message", builderRequestAuth; "signature", signature |]

        /// Beacon API BlockContents of produceBlockV4 when the node self-built and was asked to
        /// include the payload.
        let blockContents (p: Preset) =
            Container
                [|
                    "block", beaconBlock p
                    "execution_payload_envelope", executionPayloadEnvelope p
                    "kzg_proofs", kzgProofs p
                    "blobs", blobs p
                |]

        /// Beacon API SignedExecutionPayloadEnvelopeContents (Eth-Blob-Data-Included: true).
        let signedExecutionPayloadEnvelopeContents (p: Preset) =
            Container
                [|
                    "signed_execution_payload_envelope", signedExecutionPayloadEnvelope p
                    "kzg_proofs", kzgProofs p
                    "blobs", blobs p
                |]

        /// Schemas by the container names consensus-spec-tests use (Gloas).
        let byName (p: Preset) =
            Map.ofList
                [
                    "Checkpoint", checkpoint
                    "AttestationData", attestationData
                    "Fork", fork
                    "ForkData", forkData
                    "SigningData", signingData
                    "BeaconBlockHeader", beaconBlockHeader
                    "SingleAttestation", singleAttestation
                    "VoluntaryExit", voluntaryExit
                    "SignedVoluntaryExit", signedVoluntaryExit
                    "Attestation", attestation p
                    "IndexedAttestation", indexedAttestation
                    "AttesterSlashing", attesterSlashing
                    "ProposerSlashing", proposerSlashing
                    "Deposit", deposit p
                    "Eth1Data", eth1Data
                    "SyncAggregate", syncAggregate p
                    "Withdrawal", withdrawal
                    "DepositRequest", depositRequest
                    "WithdrawalRequest", withdrawalRequest
                    "ConsolidationRequest", consolidationRequest
                    "BuilderDepositRequest", builderDepositRequest
                    "BuilderExitRequest", builderExitRequest
                    "ExecutionRequests", executionRequests
                    "ExecutionPayload", executionPayload p
                    "ExecutionPayloadBid", executionPayloadBid
                    "SignedExecutionPayloadBid", signedExecutionPayloadBid
                    "ExecutionPayloadEnvelope", executionPayloadEnvelope p
                    "SignedExecutionPayloadEnvelope", signedExecutionPayloadEnvelope p
                    "PayloadAttestationData", payloadAttestationData
                    "PayloadAttestation", payloadAttestation p
                    "PayloadAttestationMessage", payloadAttestationMessage
                    "IndexedPayloadAttestation", indexedPayloadAttestation p
                    "BeaconBlockBody", beaconBlockBody p
                    "BeaconBlock", beaconBlock p
                    "SignedBeaconBlock", signedBeaconBlock p
                    "AggregateAndProof", aggregateAndProof p
                    "SignedAggregateAndProof", signedAggregateAndProof p
                    "ProposerPreferences", proposerPreferences
                    "SignedProposerPreferences", signedProposerPreferences
                    "SyncCommitteeMessage", syncCommitteeMessage
                    "SyncCommitteeContribution", syncCommitteeContribution p
                    "ContributionAndProof", contributionAndProof p
                    "SignedContributionAndProof", signedContributionAndProof p
                    "SyncAggregatorSelectionData", syncAggregatorSelectionData
                ]

    /// The attestation schema before Gloas (Electra, Fulu) or from Gloas on.
    let attestationAt (gloas: bool) (p: Preset) = if gloas then Gloas.attestation p else attestation p

    let aggregateAndProofAt (gloas: bool) (p: Preset) = if gloas then Gloas.aggregateAndProof p else aggregateAndProof p

    let signedAggregateAndProofAt (gloas: bool) (p: Preset) =
        if gloas then Gloas.signedAggregateAndProof p else signedAggregateAndProof p

    /// Schemas by the container names that consensus-spec-tests use.
    let byName (p: Preset) =
        Map.ofList
            [
                "Checkpoint", checkpoint
                "AttestationData", attestationData
                "Fork", fork
                "ForkData", forkData
                "SigningData", signingData
                "BeaconBlockHeader", beaconBlockHeader
                "SingleAttestation", singleAttestation
                "VoluntaryExit", voluntaryExit
                "Validator", validator
                "Attestation", attestation p
                "IndexedAttestation", indexedAttestation p
                "Eth1Data", eth1Data
                "SignedBeaconBlockHeader", signedBeaconBlockHeader
                "ProposerSlashing", proposerSlashing
                "AttesterSlashing", attesterSlashing p
                "DepositData", depositData
                "Deposit", deposit p
                "SignedVoluntaryExit", signedVoluntaryExit
                "SyncAggregate", syncAggregate p
                "Withdrawal", withdrawal
                "ExecutionPayload", executionPayload p
                "ExecutionPayloadHeader", executionPayloadHeader p
                "BLSToExecutionChange", blsToExecutionChange
                "SignedBLSToExecutionChange", signedBlsToExecutionChange
                "DepositRequest", depositRequest
                "WithdrawalRequest", withdrawalRequest
                "ConsolidationRequest", consolidationRequest
                "ExecutionRequests", executionRequests p
                "BeaconBlockBody", beaconBlockBody p
                "BeaconBlock", beaconBlock p
                "SignedBeaconBlock", signedBeaconBlock p
                "AggregateAndProof", aggregateAndProof p
                "SignedAggregateAndProof", signedAggregateAndProof p
                "SyncCommitteeMessage", syncCommitteeMessage
                "SyncCommitteeContribution", syncCommitteeContribution p
                "ContributionAndProof", contributionAndProof p
                "SignedContributionAndProof", signedContributionAndProof p
                "SyncAggregatorSelectionData", syncAggregatorSelectionData
            ]

/// Conversions between records and SszValue, and their hash_tree_root.
module Codec =
    let private u (x: uint64) = U x
    let private b (r: Root) = Bytes r.Bytes

    let asU v =
        match v with
        | U x -> x
        | _ -> raise (SszError "expected uint")

    let asBytes v =
        match v with
        | Bytes x -> x
        | _ -> raise (SszError "expected bytes")

    let asBits v =
        match v with
        | Bits x -> x
        | _ -> raise (SszError "expected bits")

    let fields v =
        match v with
        | Fields f -> f
        | _ -> raise (SszError "expected container")

    let checkpointValue (c: Checkpoint) = Fields [| u c.Epoch; b c.Root |]

    let checkpointOf v =
        let f = fields v

        {
            Epoch = asU f[0]
            Root = Root.Of(asBytes f[1])
        }

    let attestationDataValue (d: AttestationData) =
        Fields
            [|
                u d.Slot
                u d.Index
                b d.BeaconBlockRoot
                checkpointValue d.Source
                checkpointValue d.Target
            |]

    let attestationDataOf v : AttestationData =
        let f = fields v

        {
            Slot = asU f[0]
            Index = asU f[1]
            BeaconBlockRoot = Root.Of(asBytes f[2])
            Source = checkpointOf f[3]
            Target = checkpointOf f[4]
        }

    let forkDataValue (d: ForkData) = Fields [| Bytes d.CurrentVersion.Bytes; b d.GenesisValidatorsRoot |]

    let signingDataValue (d: SigningData) = Fields [| b d.ObjectRoot; Bytes d.Domain.Bytes |]

    let beaconBlockHeaderValue (h: BeaconBlockHeader) =
        Fields [| u h.Slot; u h.ProposerIndex; b h.ParentRoot; b h.StateRoot; b h.BodyRoot |]

    let singleAttestationValue (a: SingleAttestation) =
        Fields
            [|
                u a.CommitteeIndex
                u a.AttesterIndex
                attestationDataValue a.Data
                Bytes a.Signature.Bytes
            |]

    let singleAttestationOf v : SingleAttestation =
        let f = fields v

        {
            CommitteeIndex = asU f[0]
            AttesterIndex = asU f[1]
            Data = attestationDataOf f[2]
            Signature = BlsSignature.Of(asBytes f[3])
        }

    let voluntaryExitValue (x: VoluntaryExit) = Fields [| u x.Epoch; u x.ValidatorIndex |]

    let syncAggregatorSelectionDataValue (x: SyncAggregatorSelectionData) = Fields [| u x.Slot; u x.SubcommitteeIndex |]

    let private root t v = Root.Of(hashTreeRoot t v)

    let hashCheckpoint c = root Schemas.checkpoint (checkpointValue c)
    let hashAttestationData d = root Schemas.attestationData (attestationDataValue d)
    let hashForkData d = root Schemas.forkData (forkDataValue d)
    let hashSigningData d = root Schemas.signingData (signingDataValue d)
    let hashBeaconBlockHeader h = root Schemas.beaconBlockHeader (beaconBlockHeaderValue h)
    let hashEpoch (e: Epoch) = root Schemas.uint64 (U e)
    let hashSlot (s: Slot) = root Schemas.uint64 (U s)
    let hashVoluntaryExit x = root Schemas.voluntaryExit (voluntaryExitValue x)

    let hashSyncAggregatorSelectionData x =
        root Schemas.syncAggregatorSelectionData (syncAggregatorSelectionDataValue x)

    let payloadAttestationDataValue (d: PayloadAttestationData) =
        Fields
            [|
                b d.BeaconBlockRoot
                u d.Slot
                Bool d.PayloadPresent
                Bool d.BlobDataAvailable
            |]

    let asBool v =
        match v with
        | Bool x -> x
        | _ -> raise (SszError "expected boolean")

    let payloadAttestationDataOf v : PayloadAttestationData =
        let f = fields v

        {
            BeaconBlockRoot = Root.Of(asBytes f[0])
            Slot = asU f[1]
            PayloadPresent = asBool f[2]
            BlobDataAvailable = asBool f[3]
        }

    let proposerPreferencesValue (p: ProposerPreferences) =
        Fields
            [|
                b p.DependentRoot
                u p.ProposalSlot
                u p.ValidatorIndex
                Bytes p.FeeRecipient
                u p.TargetGasLimit
            |]

    let proposerPreferencesOf v : ProposerPreferences =
        let f = fields v

        {
            DependentRoot = Root.Of(asBytes f[0])
            ProposalSlot = asU f[1]
            ValidatorIndex = asU f[2]
            FeeRecipient = asBytes f[3]
            TargetGasLimit = asU f[4]
        }

    let builderRequestAuthValue (a: BuilderRequestAuth) = Fields [| Bytes a.AuthData; u a.AuthSlot |]

    let hashPayloadAttestationData d = root Schemas.Gloas.payloadAttestationData (payloadAttestationDataValue d)
    let hashProposerPreferences p = root Schemas.Gloas.proposerPreferences (proposerPreferencesValue p)
    let hashBuilderRequestAuth a = root Schemas.Gloas.builderRequestAuth (builderRequestAuthValue a)

    let validatorRegistrationValue (r: ValidatorRegistration) =
        Fields [| Bytes r.FeeRecipient; u r.GasLimit; u r.Timestamp; Bytes r.PubKey.Bytes |]

    let hashValidatorRegistration r = root Schemas.validatorRegistration (validatorRegistrationValue r)
