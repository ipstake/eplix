/// The chain spec: fork schedule and slot timing, from the beacon node (/eth/v1/config/spec) and
/// checked against a pinned config. The domain types are constants here, not node values.
namespace Eplix

open System
open System.Globalization

type ForkName =
    | Phase0
    | Altair
    | Bellatrix
    | Capella
    | Deneb
    | Electra
    | Fulu
    | Gloas

    /// The lower-case name the Beacon API uses in Eth-Consensus-Version.
    member this.ApiName =
        match this with
        | Phase0 -> "phase0"
        | Altair -> "altair"
        | Bellatrix -> "bellatrix"
        | Capella -> "capella"
        | Deneb -> "deneb"
        | Electra -> "electra"
        | Fulu -> "fulu"
        | Gloas -> "gloas"

type ForkEntry =
    {
        Name: ForkName
        Version: ForkVersion
        Epoch: Epoch
    }

/// The domain types Eplix signs with. They are constants of the specs, not config values:
/// consensus-specs beacon-chain.md of phase0, Altair and Gloas, and builder-specs. A beacon node
/// that could set them could have a message of one kind signed as another, such as an
/// attestation handed over as a sync committee message.
module DomainTypes =
    let private of4 (b0: byte) (b3: byte) = DomainType.Of [| b0; 0uy; 0uy; b3 |]

    let BeaconProposer = of4 0x00uy 0x00uy
    let BeaconAttester = of4 0x01uy 0x00uy
    let Randao = of4 0x02uy 0x00uy
    let VoluntaryExit = of4 0x04uy 0x00uy
    let SelectionProof = of4 0x05uy 0x00uy
    let AggregateAndProof = of4 0x06uy 0x00uy
    let SyncCommittee = of4 0x07uy 0x00uy
    let SyncCommitteeSelectionProof = of4 0x08uy 0x00uy
    let ContributionAndProof = of4 0x09uy 0x00uy
    /// Gloas: bids and payload envelopes (a self-building proposer signs its envelope with it).
    let BeaconBuilder = of4 0x0buy 0x00uy
    let PtcAttester = of4 0x0cuy 0x00uy
    let ProposerPreferences = of4 0x0duy 0x00uy
    /// builder-specs Gloas, out of protocol: requests to external builders.
    let BuilderRequestAuth = of4 0x0buy 0x01uy
    /// builder-specs, out of protocol: pre-Gloas validator registrations.
    let ApplicationBuilder = of4 0x00uy 0x01uy

    /// Each constant with its key in /eth/v1/config/spec.
    let all =
        [
            "DOMAIN_BEACON_PROPOSER", BeaconProposer
            "DOMAIN_BEACON_ATTESTER", BeaconAttester
            "DOMAIN_RANDAO", Randao
            "DOMAIN_VOLUNTARY_EXIT", VoluntaryExit
            "DOMAIN_SELECTION_PROOF", SelectionProof
            "DOMAIN_AGGREGATE_AND_PROOF", AggregateAndProof
            "DOMAIN_SYNC_COMMITTEE", SyncCommittee
            "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF", SyncCommitteeSelectionProof
            "DOMAIN_CONTRIBUTION_AND_PROOF", ContributionAndProof
            "DOMAIN_BEACON_BUILDER", BeaconBuilder
            "DOMAIN_PTC_ATTESTER", PtcAttester
            "DOMAIN_PROPOSER_PREFERENCES", ProposerPreferences
            "DOMAIN_BUILDER_REQUEST_AUTH", BuilderRequestAuth
            "DOMAIN_APPLICATION_BUILDER", ApplicationBuilder
        ]

type ChainSpec =
    {
        ConfigName: string
        PresetBase: string
        SlotDuration: TimeSpan
        SlotsPerEpoch: uint64
        /// Scheduled forks in ascending epoch order, Phase0 first.
        Forks: ForkEntry[]
        AttestationDueBps: uint64
        AttestationDueBpsGloas: uint64 voption
        AggregateDueBps: uint64
        SyncMessageDueBps: uint64
        ContributionDueBps: uint64
        /// Gloas due times (validator.md): aggregates, sync messages, contributions, the
        /// self-built payload envelope and the PTC vote.
        AggregateDueBpsGloas: uint64
        SyncMessageDueBpsGloas: uint64
        ContributionDueBpsGloas: uint64
        PayloadDueBps: uint64
        PayloadAttestationDueBps: uint64
        TargetAggregatorsPerCommittee: uint64
        TargetAggregatorsPerSyncSubcommittee: uint64
        EpochsPerSyncCommitteePeriod: uint64
        /// Container limits from the preset values the node reports.
        Preset: Preset
        /// Every string value as received, for the pin check and later modules.
        Values: Map<string, string>
    }

    // The domain types are constants (DomainTypes), never read from a node, so no node can change the domain a kind is signed under.
    member _.DomainBeaconProposer = DomainTypes.BeaconProposer
    member _.DomainBeaconAttester = DomainTypes.BeaconAttester
    member _.DomainRandao = DomainTypes.Randao
    member _.DomainVoluntaryExit = DomainTypes.VoluntaryExit
    member _.DomainSelectionProof = DomainTypes.SelectionProof
    member _.DomainAggregateAndProof = DomainTypes.AggregateAndProof
    member _.DomainSyncCommittee = DomainTypes.SyncCommittee
    member _.DomainSyncCommitteeSelectionProof = DomainTypes.SyncCommitteeSelectionProof
    member _.DomainContributionAndProof = DomainTypes.ContributionAndProof
    member _.DomainBeaconBuilder = DomainTypes.BeaconBuilder
    member _.DomainPtcAttester = DomainTypes.PtcAttester
    member _.DomainProposerPreferences = DomainTypes.ProposerPreferences
    member _.DomainBuilderRequestAuth = DomainTypes.BuilderRequestAuth
    member _.DomainApplicationBuilder = DomainTypes.ApplicationBuilder

    member this.EpochOf(slot: Slot) : Epoch = slot / this.SlotsPerEpoch
    member this.FirstSlot(epoch: Epoch) : Slot = epoch * this.SlotsPerEpoch

    member this.ForkAt(epoch: Epoch) : ForkEntry = this.Forks |> Array.findBack (fun f -> f.Epoch <= epoch)

    member this.IsScheduled(name: ForkName) = this.Forks |> Array.exists (fun f -> f.Name = name)

    /// When in the slot attestations are due, as an offset from the slot start.
    member this.AttestationDue(slot: Slot) : TimeSpan =
        let bps =
            match this.AttestationDueBpsGloas with
            | ValueSome g when this.ForkAt(this.EpochOf slot).Name = Gloas -> g
            // The Gloas value of validator.md when the node does not report it.
            | ValueNone when this.ForkAt(this.EpochOf slot).Name = Gloas -> 2500UL
            | _ -> this.AttestationDueBps

        TimeSpan.FromTicks(this.SlotDuration.Ticks * int64 bps / 10000L)

    /// An offset into the slot from basis points of the slot duration.
    member this.Bps(bps: uint64) : TimeSpan = TimeSpan.FromTicks(this.SlotDuration.Ticks * int64 bps / 10000L)

    member this.AggregateDue = this.Bps this.AggregateDueBps
    member this.SyncMessageDue = this.Bps this.SyncMessageDueBps
    member this.ContributionDue = this.Bps this.ContributionDueBps

    /// Whether the epoch is at or after the Gloas fork.
    member this.IsGloasAt(epoch: Epoch) = this.ForkAt(epoch).Name = Gloas

    /// Due times of a slot, from the Gloas values once Gloas is in force.
    member this.AggregateDueAt(slot: Slot) =
        this.Bps(if this.IsGloasAt(this.EpochOf slot) then this.AggregateDueBpsGloas else this.AggregateDueBps)

    member this.SyncMessageDueAt(slot: Slot) =
        this.Bps(if this.IsGloasAt(this.EpochOf slot) then this.SyncMessageDueBpsGloas else this.SyncMessageDueBps)

    member this.ContributionDueAt(slot: Slot) =
        this.Bps(if this.IsGloasAt(this.EpochOf slot) then this.ContributionDueBpsGloas else this.ContributionDueBps)

    member this.PayloadDue = this.Bps this.PayloadDueBps
    member this.PayloadAttestationDue = this.Bps this.PayloadAttestationDueBps

    /// The genesis fork version, which builder request auth is signed under.
    member this.GenesisForkVersion = this.Forks[0].Version

    member this.SyncPeriodOf(epoch: Epoch) = epoch / this.EpochsPerSyncCommitteePeriod

    /// The fork version voluntary exits are signed with since Deneb (EIP-7044): Capella's.
    member this.ExitForkVersion =
        match this.Forks |> Array.tryFind (fun f -> f.Name = Capella) with
        | Some f -> f.Version
        | None -> (Array.last this.Forks).Version

    /// The fork and genesis validators root a message at `epoch` is signed under.
    member this.ForkInfoAt(epoch: Epoch) : Fork =
        let current = this.ForkAt epoch

        let previous =
            match this.Forks |> Array.tryFindIndex (fun f -> f.Name = current.Name) with
            | Some i when i > 0 -> this.Forks[i - 1].Version
            | _ -> current.Version

        {
            PreviousVersion = previous
            CurrentVersion = current.Version
            Epoch = current.Epoch
        }

module ChainSpec =
    let farFutureEpoch = UInt64.MaxValue

    let private forkKeys =
        [
            Altair, "ALTAIR"
            Bellatrix, "BELLATRIX"
            Capella, "CAPELLA"
            Deneb, "DENEB"
            Electra, "ELECTRA"
            Fulu, "FULU"
            Gloas, "GLOAS"
        ]

    /// Values compare as numbers when both parse as numbers, else as lower-case strings.
    let private normalize (s: string) =
        let t = s.Trim().Trim('"', '\'')

        match UInt64.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture) with
        | true, n -> n.ToString(CultureInfo.InvariantCulture)
        | _ -> t.ToLowerInvariant()

    let private defaultSlotsPerEpoch preset =
        match preset with
        | "minimal" -> ValueSome 8UL
        | "mainnet" -> ValueSome 32UL
        | _ -> ValueNone

    let parse (values: Map<string, string>) : Result<ChainSpec, string> =
        let v = values |> Map.map (fun _ s -> normalize s)
        let errors = ResizeArray<string>()

        let get k =
            match v.TryFind k with
            | Some s -> ValueSome s
            | None -> ValueNone

        let num k =
            match get k with
            | ValueSome s ->
                match UInt64.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, n -> ValueSome n
                | _ ->
                    errors.Add $"{k} is not a number"
                    ValueNone
            | ValueNone -> ValueNone

        let version k =
            match get k with
            | ValueSome s ->
                match ForkVersion.TryParse s with
                | ValueSome x -> ValueSome x
                | ValueNone ->
                    errors.Add $"{k} is not a 4-byte hex value"
                    ValueNone
            | ValueNone -> ValueNone
        // A node may report the domain types, but only with the values of the specs: another value
        // fails the start and the check each epoch.
        for k, d in DomainTypes.all do
            match v.TryFind k with
            | Some s when DomainType.TryParse s <> ValueSome d ->
                errors.Add $"{k}: the specs fix {d.Hex}, beacon node {s}"
            | _ -> ()

        let preset = defaultArg (v.TryFind "PRESET_BASE") ""

        let inRange k lo hi (x: uint64) =
            match Bounds.check k lo hi x with
            | Ok _ -> true
            | Error m ->
                errors.Add m
                false

        let slotDuration =
            match num "SLOT_DURATION_MS", num "SECONDS_PER_SLOT" with
            // Over a day is no chain; the bound also keeps TimeSpan from overflowing.
            | ValueSome ms, _ when not (inRange "SLOT_DURATION_MS" 1UL (Bounds.Day * 1000UL) ms) -> TimeSpan.Zero
            | ValueSome ms, _ -> TimeSpan.FromMilliseconds(float ms)
            | ValueNone, ValueSome s when not (inRange "SECONDS_PER_SLOT" 1UL Bounds.Day s) -> TimeSpan.Zero
            | ValueNone, ValueSome s -> TimeSpan.FromSeconds(float s)
            | ValueNone, ValueNone ->
                errors.Add "SLOT_DURATION_MS or SECONDS_PER_SLOT missing"
                TimeSpan.Zero

        let slotsPerEpoch =
            match num "SLOTS_PER_EPOCH", defaultSlotsPerEpoch preset with
            // Real chains use 8 to 32. The epoch length in ticks (slot times slots) must fit an
            // int64: with a slot of a day, 1,024 slots are far inside it.
            | ValueSome n, _ when not (inRange "SLOTS_PER_EPOCH" 1UL 1024UL n) -> 1UL
            | ValueSome n, _ -> n
            | ValueNone, ValueSome n -> n
            | ValueNone, ValueNone ->
                errors.Add "SLOTS_PER_EPOCH missing"
                1UL

        let genesis =
            match version "GENESIS_FORK_VERSION" with
            | ValueSome g ->
                [
                    {
                        Name = Phase0
                        Version = g
                        Epoch = 0UL
                    }
                ]
            | ValueNone ->
                errors.Add "GENESIS_FORK_VERSION missing"
                []

        let later =
            [
                for name, key in forkKeys do
                    match version $"{key}_FORK_VERSION", num $"{key}_FORK_EPOCH" with
                    | ValueSome ver, ValueSome epoch when epoch <> farFutureEpoch ->
                        {
                            Name = name
                            Version = ver
                            Epoch = epoch
                        }
                    | _ -> ()
            ]

        let forks = genesis @ later |> List.toArray

        for i in 1 .. forks.Length - 1 do
            if forks[i].Epoch < forks[i - 1].Epoch then
                errors.Add $"fork {forks[i].Name.ApiName} is scheduled before {forks[i - 1].Name.ApiName}"

        let numOr k (fallback: uint64) =
            match num k with
            | ValueSome n -> n
            | ValueNone -> fallback

        let spec =
            {
                ConfigName = defaultArg (v.TryFind "CONFIG_NAME") ""
                PresetBase = preset
                SlotDuration = slotDuration
                SlotsPerEpoch = slotsPerEpoch
                Forks = forks
                AttestationDueBps =
                    (match num "ATTESTATION_DUE_BPS" with
                     | ValueSome b -> b
                     | ValueNone -> 3333UL)
                AttestationDueBpsGloas = num "ATTESTATION_DUE_BPS_GLOAS"
                AggregateDueBps = numOr "AGGREGATE_DUE_BPS" 6667UL
                SyncMessageDueBps = numOr "SYNC_MESSAGE_DUE_BPS" 3333UL
                ContributionDueBps = numOr "CONTRIBUTION_DUE_BPS" 6667UL
                AggregateDueBpsGloas = numOr "AGGREGATE_DUE_BPS_GLOAS" 5000UL
                SyncMessageDueBpsGloas = numOr "SYNC_MESSAGE_DUE_BPS_GLOAS" 2500UL
                ContributionDueBpsGloas = numOr "CONTRIBUTION_DUE_BPS_GLOAS" 5000UL
                PayloadDueBps = numOr "PAYLOAD_DUE_BPS" 5000UL
                PayloadAttestationDueBps = numOr "PAYLOAD_ATTESTATION_DUE_BPS" 7500UL
                TargetAggregatorsPerCommittee = numOr "TARGET_AGGREGATORS_PER_COMMITTEE" 16UL
                TargetAggregatorsPerSyncSubcommittee = numOr "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE" 16UL
                EpochsPerSyncCommitteePeriod =
                    numOr "EPOCHS_PER_SYNC_COMMITTEE_PERIOD" (if preset = "minimal" then 8UL else 256UL)
                Preset = Preset.FromSpec values
                Values = values
            }
        // A due time is slot ticks times basis points: over 10000 is past the slot, and a huge
        // value overflows the product.
        for k, b in
            [
                "ATTESTATION_DUE_BPS", spec.AttestationDueBps
                "ATTESTATION_DUE_BPS_GLOAS", defaultValueArg spec.AttestationDueBpsGloas 0UL
                "AGGREGATE_DUE_BPS", spec.AggregateDueBps
                "CONTRIBUTION_DUE_BPS", spec.ContributionDueBps
                "SYNC_MESSAGE_DUE_BPS", spec.SyncMessageDueBps
                "AGGREGATE_DUE_BPS_GLOAS", spec.AggregateDueBpsGloas
                "SYNC_MESSAGE_DUE_BPS_GLOAS", spec.SyncMessageDueBpsGloas
                "CONTRIBUTION_DUE_BPS_GLOAS", spec.ContributionDueBpsGloas
                "PAYLOAD_DUE_BPS", spec.PayloadDueBps
                "PAYLOAD_ATTESTATION_DUE_BPS", spec.PayloadAttestationDueBps
            ] do
            inRange k 0UL 10000UL b |> ignore
        // Divisors in the aggregator selection and the sync committee period.
        for k, n in
            [
                "TARGET_AGGREGATORS_PER_COMMITTEE", spec.TargetAggregatorsPerCommittee
                "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE", spec.TargetAggregatorsPerSyncSubcommittee
                "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", spec.EpochsPerSyncCommitteePeriod
            ] do
            inRange k 1UL UInt64.MaxValue n |> ignore

        if errors.Count = 0 then Ok spec else Error(String.Join("; ", errors))

    /// Reads the flat `KEY: value` lines of a consensus config.yaml. Nested entries
    /// (such as BLOB_SCHEDULE) and comments are skipped.
    let parseConfigYaml (text: string) : Map<string, string> =
        text.Split('\n')
        |> Array.choose (fun line ->
            let line = line.TrimEnd('\r')
            let hash = line.IndexOf '#'
            let line = if hash >= 0 then line.Substring(0, hash) else line

            if line.Length = 0 || Char.IsWhiteSpace line[0] || line.StartsWith '-' then
                None
            else
                match line.IndexOf ':' with
                | i when i > 0 ->
                    let value = line.Substring(i + 1).Trim().Trim('"', '\'')
                    if value.Length = 0 then None else Some(line.Substring(0, i).Trim(), value)
                | _ -> None)
        |> Map.ofArray

    /// Every key in the pinned config that the beacon node also reports must have the same value.
    /// The fork schedule keys must be present on both sides, except a fork that one side does
    /// not list and the other lists as not scheduled (epoch 2^64 - 1): a built-in config written
    /// before a fork was named still matches a node that knows the fork.
    let checkPinned (pinned: Map<string, string>) (fromNode: Map<string, string>) : Result<unit, string> =
        let farFuture = normalize (string UInt64.MaxValue)

        let unscheduled (m: Map<string, string>) (fork: string) =
            match m.TryFind $"{fork}_FORK_EPOCH" with
            | Some e -> normalize e = farFuture
            | None -> false

        let absent (m: Map<string, string>) (fork: string) =
            not (m.ContainsKey $"{fork}_FORK_VERSION") && not (m.ContainsKey $"{fork}_FORK_EPOCH")

        let excused =
            [
                for _, f in forkKeys do
                    if (absent pinned f && unscheduled fromNode f) || (absent fromNode f && unscheduled pinned f) then
                        $"{f}_FORK_VERSION"
                        $"{f}_FORK_EPOCH"
            ]

        let mustMatch =
            [
                "GENESIS_FORK_VERSION"
                for _, k in forkKeys do
                    $"{k}_FORK_VERSION"
                    $"{k}_FORK_EPOCH"
            ]
            |> List.filter (fun k -> not (List.contains k excused))

        let errors =
            [
                for KeyValue(k, pv) in pinned do
                    match fromNode.TryFind k with
                    | Some nv when normalize nv <> normalize pv -> $"{k}: pinned {pv}, beacon node {nv}"
                    | None when List.contains k mustMatch -> $"{k}: pinned {pv}, beacon node does not report it"
                    | _ -> ()
                for k in mustMatch do
                    if pinned.ContainsKey k |> not && fromNode.ContainsKey k then
                        $"{k}: reported by the beacon node but not in the pinned config"
            ]

        if errors.IsEmpty then Ok() else Error(String.Join("; ", errors))

/// What ties the slot clock and the signing domains to one chain: genesis time, genesis
/// validators root, slot duration and slots per epoch. A node with an earlier genesis or a
/// shorter epoch moves the clock ahead, and marks set there never go down.
type ChainAnchor =
    {
        GenesisTime: uint64
        GenesisValidatorsRoot: Root
        SlotDuration: TimeSpan
        SlotsPerEpoch: uint64
    }

/// The parts of the anchor known before any node answers, each with where it comes from: a
/// built-in network, the chain config file, the data dir of an earlier start, the slashing DB.
/// A node that reports another value is left out.
type AnchorPin =
    {
        GenesisTime: struct (uint64 * string) voption
        GenesisValidatorsRoot: struct (Root * string) voption
        SlotDuration: struct (TimeSpan * string) voption
        SlotsPerEpoch: struct (uint64 * string) voption
    }

module AnchorPin =
    let none =
        {
            GenesisTime = ValueNone
            GenesisValidatorsRoot = ValueNone
            SlotDuration = ValueNone
            SlotsPerEpoch = ValueNone
        }

    let ofAnchor (source: string) (a: ChainAnchor) =
        {
            GenesisTime = ValueSome(struct (a.GenesisTime, source))
            GenesisValidatorsRoot = ValueSome(struct (a.GenesisValidatorsRoot, source))
            SlotDuration = ValueSome(struct (a.SlotDuration, source))
            SlotsPerEpoch = ValueSome(struct (a.SlotsPerEpoch, source))
        }

    let private ms (t: TimeSpan) = $"{t.TotalMilliseconds} ms"

    /// The values of `actual` that differ from the pin, as "name: <source> x, beacon node y".
    let differences (pin: AnchorPin) (actual: ChainAnchor) : string list =
        [
            match pin.GenesisTime with
            | ValueSome(struct (v, src)) when v <> actual.GenesisTime ->
                $"genesis_time: {src} {v}, beacon node {actual.GenesisTime}"
            | _ -> ()
            match pin.GenesisValidatorsRoot with
            | ValueSome(struct (v, src)) when v <> actual.GenesisValidatorsRoot ->
                $"genesis_validators_root: {src} {v.Hex}, beacon node {actual.GenesisValidatorsRoot.Hex}"
            | _ -> ()
            match pin.SlotDuration with
            | ValueSome(struct (v, src)) when v <> actual.SlotDuration ->
                $"slot duration: {src} {ms v}, beacon node {ms actual.SlotDuration}"
            | _ -> ()
            match pin.SlotsPerEpoch with
            | ValueSome(struct (v, src)) when v <> actual.SlotsPerEpoch ->
                $"SLOTS_PER_EPOCH: {src} {v}, beacon node {actual.SlotsPerEpoch}"
            | _ -> ()
        ]

    /// Both pins in one. A value both give differently is an error naming both sources: the
    /// config, the data dir and the slashing DB disagree, whatever the nodes say.
    let merge (a: AnchorPin) (b: AnchorPin) : Result<AnchorPin, string> =
        let errors = ResizeArray<string>()

        let one name (show: 'T -> string) (x: struct ('T * string) voption) (y: struct ('T * string) voption) =
            match x, y with
            | ValueSome(struct (u, su)), ValueSome(struct (v, sv)) when u <> v ->
                errors.Add $"{name}: {su} {show u}, {sv} {show v}"
                x
            | ValueSome _, _ -> x
            | ValueNone, _ -> y

        let pin =
            {
                GenesisTime = one "genesis_time" string a.GenesisTime b.GenesisTime
                GenesisValidatorsRoot =
                    one
                        "genesis_validators_root"
                        (fun (r: Root) -> r.Hex)
                        a.GenesisValidatorsRoot
                        b.GenesisValidatorsRoot
                SlotDuration = one "slot duration" ms a.SlotDuration b.SlotDuration
                SlotsPerEpoch = one "SLOTS_PER_EPOCH" string a.SlotsPerEpoch b.SlotsPerEpoch
            }

        if errors.Count = 0 then Ok pin else Error(String.Join("; ", errors))

    /// The whole anchor when the pin holds every value.
    let full (pin: AnchorPin) : ChainAnchor voption =
        match pin.GenesisTime, pin.GenesisValidatorsRoot, pin.SlotDuration, pin.SlotsPerEpoch with
        | ValueSome(struct (t, _)), ValueSome(struct (r, _)), ValueSome(struct (d, _)), ValueSome(struct (n, _)) ->
            ValueSome(
                {
                    GenesisTime = t
                    GenesisValidatorsRoot = r
                    SlotDuration = d
                    SlotsPerEpoch = n
                }
                : ChainAnchor
            )
        | _ -> ValueNone

module ChainAnchor =
    let ofSpec (genesisTime: uint64) (genesisValidatorsRoot: Root) (spec: ChainSpec) : ChainAnchor =
        {
            GenesisTime = genesisTime
            GenesisValidatorsRoot = genesisValidatorsRoot
            SlotDuration = spec.SlotDuration
            SlotsPerEpoch = spec.SlotsPerEpoch
        }

    /// The values of `actual` that differ from `expected`, as "name: <source> x, beacon node y".
    /// Empty when they agree.
    let differences (source: string) (expected: ChainAnchor) (actual: ChainAnchor) : string list =
        AnchorPin.differences (AnchorPin.ofAnchor source expected) actual

    /// The data dir file that keeps the anchor of the first start: genesis
    /// time, slot duration and slots per epoch, as `key: value` lines. The genesis validators root
    /// stays in slashing.db.
    let toFile (a: ChainAnchor) =
        $"genesis_time: {a.GenesisTime}
slot_duration_ms: {int64 a.SlotDuration.TotalMilliseconds}
slots_per_epoch: {a.SlotsPerEpoch}
"

    /// Reads toFile's text as a pin with `source` named. Every key must be there.
    let pinOfFile (source: string) (text: string) : Result<AnchorPin, string> =
        let values = ChainSpec.parseConfigYaml text

        let num k =
            match values.TryFind k with
            | Some s ->
                match UInt64.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture) with
                | true, n -> Ok n
                | _ -> Error $"{k} is not a number"
            | None -> Error $"{k} is missing"

        match num "genesis_time", num "slot_duration_ms", num "slots_per_epoch" with
        | Ok t, Ok d, Ok n when d > 0UL && d <= Bounds.Day * 1000UL ->
            Ok
                {
                    GenesisTime = ValueSome(struct (t, source))
                    GenesisValidatorsRoot = ValueNone
                    SlotDuration = ValueSome(struct (TimeSpan.FromMilliseconds(float d), source))
                    SlotsPerEpoch = ValueSome(struct (n, source))
                }
        | Ok _, Ok _, Ok _ -> Error "slot_duration_ms is out of range"
        | Error e, _, _
        | _, Error e, _
        | _, _, Error e -> Error e
