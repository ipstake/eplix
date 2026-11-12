/// Random jitter before signing requests go to a backend. Two VCs that share
/// keys and signers send at the same moments; a random wait per request spreads their requests,
/// so the signers queue less and the two VCs do not tie on the same instant. Each request waits
/// a uniformly random 0 to J ms. Config:
///   "signing": { "jitter_ms": 100, "jitter_by_duty_ms": { "aggregate": 50, "registration": 2000 },
///                "keys": { "0x<pubkey>": { "jitter_ms": 0, "jitter_by_duty_ms": { ... } } } }
///   "modules": { "<backend>": { "signing": { "jitter_ms": ..., "jitter_by_duty_ms": { ... } } } }
/// for the backends local, tee, dirk and web3signer. jitter_ms covers attestations and sync
/// committee messages; jitter_by_duty_ms sets any jitterable duty. Off by default. The most
/// specific value wins: key and duty, key, module and duty, module, general and duty, general,
/// else 0. Blocks, RANDAO reveals, exits, PTC
/// votes, payload envelopes, proposer preferences and builder request auth never wait.
namespace Eplix

open System
open System.Collections.Concurrent
open System.Text.Json
open Eplix.Json

/// The jitter one level gives: `jitter_ms` for attestations and sync committee messages, and
/// values per duty key, sorted by key. ValueNone and absent keys leave the duty to the next
/// level, so an explicit 0 overrides a level below. A list of pairs, not a Map: at most seven
/// entries, and no new generic code in the NativeAOT binary.
type JitterLevel =
    {
        Default: TimeSpan voption
        ByDuty: (string * TimeSpan) list
    }

    static member Empty = { Default = ValueNone; ByDuty = [] }

    member this.IsEmpty = this.Default.IsNone && this.ByDuty.IsEmpty

    member this.AnyAboveZero =
        (match this.Default with
         | ValueSome d -> d > TimeSpan.Zero
         | ValueNone -> false)
        || this.ByDuty |> List.exists (fun (_, d) -> d > TimeSpan.Zero)

/// The parsed `signing` settings: the general level, one per backend module, one per key.
type SigningJitterConfig =
    {
        General: JitterLevel
        Modules: Map<string, JitterLevel>
        Keys: Map<PubKey, JitterLevel>
    }

    /// Nothing configured: no jitter.
    static member Default =
        {
            General = JitterLevel.Empty
            Modules = Map.empty
            Keys = Map.empty
        }

module SigningJitter =
    /// The modules whose keys sign through a backend, and so take module level jitter.
    let backendModules = [ "local"; "tee"; "dirk"; "web3signer" ]

    /// The jitter_by_duty_ms key of a duty kind; ValueNone for the kinds that never wait.
    let dutyKey (kind: DutyKind) : string voption =
        match kind with
        | DutyKind.Attestation -> ValueSome "attestation"
        | DutyKind.SyncCommitteeMessage -> ValueSome "sync_committee_message"
        | DutyKind.AggregateAndProof -> ValueSome "aggregate"
        | DutyKind.ContributionAndProof -> ValueSome "sync_contribution"
        | DutyKind.AggregationSlot -> ValueSome "selection_proof"
        | DutyKind.SyncSelectionProof -> ValueSome "sync_selection_proof"
        | DutyKind.ValidatorRegistration -> ValueSome "registration"
        | DutyKind.Block
        | DutyKind.RandaoReveal
        | DutyKind.VoluntaryExit
        | DutyKind.PayloadAttestation
        | DutyKind.PayloadEnvelope
        | DutyKind.ProposerPreferences
        | DutyKind.BuilderRequestAuth -> ValueNone

    /// Every key dutyKey gives, in the order the docs list them.
    let dutyKeys =
        [
            "attestation"
            "sync_committee_message"
            "aggregate"
            "sync_contribution"
            "selection_proof"
            "sync_selection_proof"
            "registration"
        ]

    /// Duty names the map refuses with a reason: these duties never wait.
    let neverKeys =
        [
            "block"
            "randao"
            "randao_reveal"
            "exit"
            "voluntary_exit"
            "builder_auth"
            "ptc"
            "payload_envelope"
            "proposer_preferences"
        ]

    /// The duties jitter_ms covers.
    let isDefaultDuty (dutyKey: string) = dutyKey = "attestation" || dutyKey = "sync_committee_message"

    /// The highest value a duty key takes, in ms: registrations wait up to 2 s, the rest 1 s.
    let maxMs (dutyKey: string) = if dutyKey = "registration" then 2000UL else 1000UL

    /// A duty kind's slot in the per key tables (0 to 13).
    let kindIndex (kind: DutyKind) =
        match kind with
        | DutyKind.Attestation -> 0
        | DutyKind.Block -> 1
        | DutyKind.RandaoReveal -> 2
        | DutyKind.AggregationSlot -> 3
        | DutyKind.AggregateAndProof -> 4
        | DutyKind.SyncCommitteeMessage -> 5
        | DutyKind.SyncSelectionProof -> 6
        | DutyKind.ContributionAndProof -> 7
        | DutyKind.VoluntaryExit -> 8
        | DutyKind.PayloadAttestation -> 9
        | DutyKind.PayloadEnvelope -> 10
        | DutyKind.ProposerPreferences -> 11
        | DutyKind.BuilderRequestAuth -> 12
        | DutyKind.ValidatorRegistration -> 13

    /// Every duty kind, for the per key tables.
    let allKinds =
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

    /// One level: `jitter_ms` and `jitter_by_duty_ms`, plus `extra` fields the caller reads.
    let parseLevel (where: string) (extra: string list) (e: JsonElement) : JitterLevel =
        match checkFields e where ([ "jitter_ms"; "jitter_by_duty_ms" ] @ extra) with
        | [] -> ()
        | errors -> fail (String.Join("; ", errors))

        let byDuty =
            match tryProp e "jitter_by_duty_ms" with
            | ValueNone -> []
            | ValueSome v ->
                let w = $"{where}.jitter_by_duty_ms"

                if v.ValueKind <> JsonValueKind.Object then
                    fail $"{w} must be an object of duty to milliseconds"

                let mutable m = []

                for p in v.EnumerateObject() do
                    if List.contains p.Name neverKeys then
                        fail
                            $"{w}.{p.Name}: blocks, RANDAO reveals, exits, PTC votes, payload envelopes, proposer preferences and builder request auth are never jittered"

                    if not (List.contains p.Name dutyKeys) then
                        fail $"""{w}: unknown duty "{p.Name}"; the keys are {String.Join(", ", dutyKeys)}"""

                    if m |> List.exists (fun (k, _) -> k = p.Name) then
                        fail $"{w}: {p.Name} is given twice"

                    m <- (p.Name, boundedMs $"{w}.{p.Name}" 0UL (maxMs p.Name) p.Value) :: m

                List.sortBy fst m

        {
            Default = tryProp e "jitter_ms" |> ValueOption.map (boundedMs $"{where}.jitter_ms" 0UL 1000UL)
            ByDuty = byDuty
        }

    /// The top-level `signing` object and the `signing` object of each module section.
    let parse (signing: JsonElement voption) (modules: (string * JsonElement voption) list) : SigningJitterConfig =
        let general, keys =
            match signing with
            | ValueNone -> JitterLevel.Empty, Map.empty
            | ValueSome s ->
                let level = parseLevel "signing" [ "keys" ] s

                let keys =
                    match tryProp s "keys" with
                    | ValueNone -> Map.empty
                    | ValueSome k ->
                        if k.ValueKind <> JsonValueKind.Object then
                            fail "signing.keys must be an object of validator key to jitter"

                        let mutable m = Map.empty

                        for p in k.EnumerateObject() do
                            match PubKey.TryParse p.Name with
                            | ValueNone ->
                                fail $"signing.keys: \"{p.Name}\" is not a validator public key (0x and 96 hex digits)"
                            | ValueSome pk ->
                                if Map.containsKey pk m then
                                    fail $"signing.keys: {p.Name} is given twice"

                                m <- m.Add(pk, parseLevel $"signing.keys.{p.Name}" [] p.Value)

                        m

                level, keys

        let moduleLevels =
            [
                for name, section in modules do
                    match section |> ValueOption.bind (fun e -> tryProp e "signing") with
                    | ValueNone -> ()
                    | ValueSome s ->
                        if not (List.contains name backendModules) then
                            fail
                                $"""modules.{name}.signing: {name} is not a signing backend ({String.Join(", ", backendModules)})"""

                        name, parseLevel $"modules.{name}.signing" [] s
            ]
            |> Map.ofList

        {
            General = general
            Modules = moduleLevels
            Keys = keys
        }

    /// The module a backend belongs to: the first word of its name ("tee 2 of 3 (...)",
    /// "dirk host:port", "web3signer https://...", "local").
    let moduleOf (backendName: string) =
        match backendName.IndexOf ' ' with
        | -1 -> backendName
        | i -> backendName.Substring(0, i)

    let private fromLevel (dk: string) (l: JitterLevel) =
        match l.ByDuty |> List.tryFind (fun (k, _) -> k = dk) with
        | Some(_, d) -> ValueSome d
        | None -> if isDefaultDuty dk then l.Default else ValueNone

    /// The jitter bound for one key, module and duty kind, most specific first.
    let resolve (c: SigningJitterConfig) (key: PubKey) (moduleName: string) (kind: DutyKind) : TimeSpan =
        match dutyKey kind with
        | ValueNone -> TimeSpan.Zero
        | ValueSome dk ->
            let level (l: JitterLevel option) =
                match l with
                | Some l -> fromLevel dk l
                | None -> ValueNone

            match level (c.Keys.TryFind key) with
            | ValueSome d -> d
            | ValueNone ->
                match level (c.Modules.TryFind moduleName) with
                | ValueSome d -> d
                | ValueNone ->
                    match fromLevel dk c.General with
                    | ValueSome d -> d
                    | ValueNone -> TimeSpan.Zero

    /// Whether any request can wait: some value at some level is above 0.
    let anyAboveZero (c: SigningJitterConfig) =
        c.General.AnyAboveZero
        || c.Modules |> Map.exists (fun _ l -> l.AnyAboveZero)
        || c.Keys |> Map.exists (fun _ l -> l.AnyAboveZero)

    /// One line per level for `eplix check` and the start log.
    let describe (c: SigningJitterConfig) : string list =
        if not (anyAboveZero c) then
            [ "signing jitter: off" ]
        else
            let per (l: JitterLevel) =
                [ for k, v in l.ByDuty -> $"; {k} up to {v.TotalMilliseconds} ms" ] |> String.Concat

            let other (l: JitterLevel) =
                let d =
                    match l.Default with
                    | ValueSome d -> $"up to {d.TotalMilliseconds} ms for attestation and sync_committee_message"
                    | ValueNone -> "jitter_ms unset"

                d + per l

            [
                $"signing jitter: {other c.General}"
                for KeyValue(m, l) in c.Modules do
                    $"signing jitter, module {m}: {other l}"
                for KeyValue(k, l) in c.Keys do
                    $"signing jitter, key {k.Short}: {other l}"
            ]

/// One key's bounds, in ticks by SigningJitter.kindIndex, and the backend they were built for.
[<Sealed>]
type JitterTable(backend: Backend, bounds: int64[]) =
    member _.Backend = backend
    member _.Bounds = bounds

/// The jitter bounds per key and duty kind, and the draw. Each key's table is built at its first
/// request (its backend gives the module) and again if the key moves to another backend; after
/// that a request costs one dictionary lookup, an array read and one draw from Random.Shared
/// (xoshiro, seeded once, thread-safe, no allocation).
[<AllowNullLiteral>]
type SigningJitters(config: SigningJitterConfig, draw: Func<int64, int64>) =
    let width = (SigningJitter.allKinds |> List.map SigningJitter.kindIndex |> List.max) + 1
    let tables = ConcurrentDictionary<PubKey, JitterTable>()

    let build (key: PubKey) (backend: Backend) =
        let m = SigningJitter.moduleOf backend.Name
        let t = Array.zeroCreate<int64> width

        for k in SigningJitter.allKinds do
            t[SigningJitter.kindIndex k] <- (SigningJitter.resolve config key m k).Ticks

        t

    let fresh (key: PubKey) (backend: Backend) =
        let t = build key backend
        tables[key] <- JitterTable(backend, t)
        t

    /// Draws from Random.Shared.
    new(config: SigningJitterConfig) = SigningJitters(config, Func<int64, int64>(fun n -> Random.Shared.NextInt64 n))

    member _.Config = config

    /// The bound for a request of `kind` for `key`, which signs through `backend`.
    member _.Bound(key: PubKey, backend: Backend, kind: DutyKind) : TimeSpan =
        let mutable e = Unchecked.defaultof<JitterTable>

        let t =
            if tables.TryGetValue(key, &e) && obj.ReferenceEquals(e.Backend, backend) then
                e.Bounds
            else
                fresh key backend

        TimeSpan.FromTicks t[SigningJitter.kindIndex kind]

    /// A uniformly random wait from 0 to the bound, inclusive; zero when the bound is zero.
    member this.Draw(key: PubKey, backend: Backend, kind: DutyKind) : TimeSpan =
        let bound = this.Bound(key, backend, kind).Ticks
        if bound <= 0L then TimeSpan.Zero else TimeSpan.FromTicks(draw.Invoke(bound + 1L))
