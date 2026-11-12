/// The Dirk backend as a module. Config section "dirk":
///   { "endpoints": [ "dirk1:19591" ], "accounts": [ "Wallet", "Wallet/Account" ],
///     "ca_cert": "<file>", "client_cert": "<file>", "client_key": "<file>",
///     "timeout_ms": 2000, "batch_attestations": true, "refresh_interval_seconds": 384,
///     "gloas_calls": "auto" }
/// `gloas_calls` sets how PTC votes, envelopes, proposer preferences and builder request auth go
/// to Dirk: "auto" (default) uses the typed Gloas calls of a Dirk build that has them and, at an instance's first
/// UNIMPLEMENTED answer, root and domain through the generic Sign from then on; "typed" uses the
/// typed calls only, so stock Dirk fails those kinds; "generic" always sends root and domain (stock
/// Dirk; the fork denies them unless its generic-gloas-clients names this client).
/// Each endpoint lists the accounts under `accounts`. A plain account is a whole key signed by
/// that instance. A distributed account names its participants and threshold; its key goes to a
/// threshold combinator over one member per participant, at the address the account gives.
module Eplix.Backend.Dirk.DirkModule

open System
open System.Collections.Generic
open System.IO
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json
open Eplix.Backend.Dirk.Messages

let name = "dirk"

type Settings =
    {
        Endpoints: string list
        Accounts: string list
        Tls: TlsSettings
        /// Per request and member: a member's budget in a threshold group.
        Timeout: TimeSpan
        BatchAttestations: bool
        /// 0 turns the account refresh off.
        RefreshInterval: TimeSpan
        GloasCalls: GloasCalls
        /// How often the TLS files are read for a change; zero turns it off.
        ReloadInterval: TimeSpan
    }

let parseSettings (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Error [ "the dirk module is linked but has no config section (modules.dirk)" ]
    | ValueSome e ->
        let errors =
            checkFields
                e
                "modules.dirk"
                [
                    "endpoints"
                    "accounts"
                    "ca_cert"
                    "client_cert"
                    "client_key"
                    "timeout_ms"
                    "batch_attestations"
                    "refresh_interval_seconds"
                    "gloas_calls"
                    "reload_interval_seconds"
                    "signing"
                ]

        if not errors.IsEmpty then
            Error errors
        else
            try
                let strings field =
                    match tryProp e field with
                    | ValueSome a -> array a |> Array.map str |> List.ofArray
                    | ValueNone -> fail $"'{field}' is required"

                let endpoints = strings "endpoints"

                if endpoints.IsEmpty then
                    fail "'endpoints' is empty"

                for ep in endpoints do
                    match ep.LastIndexOf ':' with
                    | i when i > 0 && fst (UInt16.TryParse(ep.Substring(i + 1))) -> ()
                    | _ -> fail $"endpoint '{ep}' must be host:port"

                let accounts = strings "accounts"

                if accounts.IsEmpty then
                    fail "'accounts' is empty"

                let file field = section.Path(strField e field)

                let timeout =
                    match tryProp e "timeout_ms" with
                    | ValueSome v -> boundedMs "timeout_ms" 1UL 60_000UL v
                    | ValueNone -> TimeSpan.FromSeconds 2.0

                let batch =
                    match tryProp e "batch_attestations" with
                    | ValueSome v when v.ValueKind = JsonValueKind.False -> false
                    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
                    | ValueSome _ -> fail "batch_attestations must be a boolean"
                    | ValueNone -> true
                // 0 turns the refresh off.
                let refresh =
                    match tryProp e "refresh_interval_seconds" with
                    | ValueSome v -> boundedSeconds "refresh_interval_seconds" 0UL Bounds.Day v
                    | ValueNone -> TimeSpan.FromSeconds 384.0

                let gloasCalls =
                    match tryProp e "gloas_calls" with
                    | ValueSome v ->
                        let s = if v.ValueKind = JsonValueKind.String then str v else ""

                        match GloasCalls.TryParse s with
                        | ValueSome g -> g
                        | ValueNone ->
                            fail $"gloas_calls must be \"auto\", \"typed\" or \"generic\", not {v.GetRawText()}"
                    | ValueNone -> GloasCalls.Auto

                let reload =
                    match TlsFiles.reloadInterval (tryProp e "reload_interval_seconds" |> ValueOption.map u64) with
                    | Ok t -> t
                    | Error m -> fail m

                Ok
                    {
                        Endpoints = endpoints
                        Accounts = accounts
                        Tls =
                            {
                                CaCert = file "ca_cert"
                                ClientCert = file "client_cert"
                                ClientKey = file "client_key"
                            }
                        Timeout = timeout
                        BatchAttestations = batch
                        RefreshInterval = refresh
                        GloasCalls = gloasCalls
                        ReloadInterval = reload
                    }
            with :? JsonDecodeError as e ->
                Error [ $"modules.dirk: {e.Message}" ]

/// The Dirk instances, their accounts and the threshold groups built from them.
/// `chain` lets each instance probe keys it stopped for bad signatures.
type DirkSet(connect: string -> DirkApi, settings: Settings, time: TimeProvider, log: Log, ?chain: ProbeChain) =
    let gate = obj ()
    let endpoints = Dictionary<string, DirkEndpoint>()
    let singles = Dictionary<string, Backend>()
    let groups = Dictionary<string, Backend * HashSet<PubKey>>()
    let mutable lastAnswers: MemberAnswer list = []
    let mutable refused: (PubKey * string) list = []
    let shareChecks = Threshold.ShareChecks()

    let endpoint (address: string) =
        lock gate (fun () ->
            match endpoints.TryGetValue address with
            | true, e -> e
            | _ ->
                let watch = SignatureWatch("dirk", address, log, ?chain = chain)

                let e =
                    DirkEndpoint(
                        connect address,
                        settings.BatchAttestations,
                        settings.Timeout,
                        log,
                        settings.GloasCalls,
                        watch
                    )

                endpoints[address] <- e
                e)

    let single (address: string) =
        lock gate (fun () ->
            match singles.TryGetValue address with
            | true, b -> b
            | _ ->
                let e = endpoint address
                let b = e.Backend $"dirk {address}" false (fun _ a -> a.Share.IsNone)
                singles[address] <- b
                b)

    let addressOf (p: Endpoint) = $"{p.Name}:{p.Port}"

    let group (threshold: int) (participants: Endpoint list) =
        let id =
            let members = participants |> List.map (fun p -> $"{p.Id}@{addressOf p}")
            $"""{threshold} of {String.Join(",", members)}"""

        lock gate (fun () ->
            match groups.TryGetValue id with
            | true, g -> g
            | _ ->
                let keys = HashSet<PubKey>()
                let ids = participants |> List.map (fun p -> string p.Id)
                let groupName = $"""dirk {threshold} of {participants.Length} ({String.Join(",", ids)})"""

                let members =
                    [
                        for p in participants ->
                            let e = endpoint (addressOf p)

                            {
                                Backend =
                                    e.Backend $"dirk {addressOf p}" true (fun k _ ->
                                        lock gate (fun () -> keys.Contains k))
                                Index = p.Id
                                Budget = settings.Timeout
                            }
                    ]

                let g = Threshold.create groupName threshold members time log, keys
                groups[id] <- g
                g)

    member _.Endpoints = lock gate (fun () -> List.ofSeq endpoints.Values)

    /// What each configured endpoint answered at the last Discover: the keys of its plain and
    /// distributed accounts, or nothing when the call failed.
    member _.LastAnswers = lastAnswers

    /// The distributed keys the last Discover found unfit, with the reason: the share keys the
    /// participants listed are not one split of the key, or the threshold is
    /// half the participants or less (two disjoint sets could then each sign). The module refuses them in the registry.
    member _.Refused = refused

    /// The share checks of the distributed keys, cached across refreshes.
    member _.ShareChecks = shareChecks

    /// Lists the accounts on every configured endpoint and records them. Returns each key with
    /// its backend, and how many endpoints answered. A key that is a plain account somewhere and
    /// distributed elsewhere comes once with each route, so the registry refuses it.
    /// A distributed account at a threshold of half its participants or less is left out
    /// and listed in Refused.
    member _.Discover(ct: CancellationToken) : Task<(PubKey * Backend) list * int> =
        task {
            let! listings =
                settings.Endpoints
                |> List.map (fun address ->
                    task {
                        let! r =
                            ListedKeys.WithDeadline(
                                time,
                                ListedKeys.ListDeadline,
                                ct,
                                (endpoint address).Api.ListAccounts settings.Accounts
                            )

                        return address, r
                    })
                |> Task.WhenAll

            let out = ResizeArray<PubKey * Backend>()
            let mutable answered = 0
            let answers = ResizeArray<MemberAnswer>()
            // Per distributed key: its threshold and the share key each answering participant listed.
            let shares = Dictionary<PubKey, struct (int * Dictionary<uint64, PubKey>)>()
            // Distributed keys at a threshold of half the participants or less, with the reason.
            let small = Dictionary<PubKey, string>()

            for address, r in listings do
                let listed = HashSet<PubKey>()

                match r with
                | Error(CallError.Failure f) ->
                    log.Warn $"dirk {address}: listing accounts failed: {(Failed f).Describe}"
                | Error(CallError.Rejected m) -> log.Error $"dirk {address}: the client certificate was rejected: {m}"
                | Error(CallError.Unimplemented m) ->
                    log.Warn $"dirk {address}: listing accounts is not implemented: {m}"
                | Ok resp when resp.State <> ResponseState.Succeeded ->
                    log.Warn $"dirk {address}: listing accounts answered {resp.State}"
                | Ok resp ->
                    answered <- answered + 1

                    for a in resp.Accounts do
                        match PubKey.TryParse(Hex.encodeArray a.PublicKey) with
                        | ValueNone -> log.Warn $"dirk {address}: account {a.Name} has no valid public key"
                        | ValueSome pk ->
                            listed.Add pk |> ignore
                            (endpoint address).SetAccount(pk, { Name = a.Name; Share = ValueNone }) |> ignore
                            out.Add(pk, single address)

                    for d in resp.DistributedAccounts do
                        let parts = d.Participants |> List.sortBy (fun p -> p.Id)
                        let threshold = int d.SigningThreshold

                        if d.CompositePublicKey.Length <> 48 || d.PublicKey.Length <> 48 then
                            log.Warn $"dirk {address}: distributed account {d.Name} has no valid keys"
                        elif
                            threshold < 1
                            || threshold > parts.Length
                            || (parts |> List.distinctBy (fun p -> p.Id)).Length <> parts.Length
                        then
                            log.Warn
                                $"dirk {address}: distributed account {d.Name}: threshold {threshold} of {parts.Length} participants"
                        elif 2 * threshold <= parts.Length then
                            // Threshold.checkSize: two sets of participants with none in common
                            // could each sign. The registry refuses the key: logged once, counted.
                            let key = PubKey.Of d.CompositePublicKey

                            small.TryAdd(
                                key,
                                $"distributed account {d.Name}: threshold {threshold} of {parts.Length} participants; it must be more than half"
                            )
                            |> ignore
                        else
                            let key = PubKey.Of d.CompositePublicKey

                            match parts |> List.tryFind (fun p -> addressOf p = address) with
                            | None ->
                                // An instance describes only groups it is in: one that names
                                // only other participants could route any key to a group, with
                                // no share of its own to check, and so take that key from the
                                // module that holds it.
                                log.Warn
                                    $"dirk {address}: {d.Name} lists no participant at this address; ignored here. Configure endpoints as the participants name them"
                            | Some self ->
                                listed.Add key |> ignore

                                for p in parts do
                                    let share = if p = self then ValueSome(PubKey.Of d.PublicKey) else ValueNone

                                    (endpoint (addressOf p))
                                        .SetAccount(
                                            key,
                                            {
                                                Name = d.Name
                                                Share = ValueSome(struct (p.Id, share))
                                            }
                                        )
                                    |> ignore

                                let struct (_, byId) =
                                    match shares.TryGetValue key with
                                    | true, s -> s
                                    | _ ->
                                        let s = struct (threshold, Dictionary<uint64, PubKey>())
                                        shares[key] <- s
                                        s

                                byId[self.Id] <- PubKey.Of d.PublicKey
                                let backend, keys = group threshold parts
                                lock gate (fun () -> keys.Add key |> ignore)
                                out.Add(key, backend)

                let ok =
                    match r with
                    | Ok resp -> resp.State = ResponseState.Succeeded
                    | Error _ -> false

                answers.Add
                    {
                        Member = address
                        Keys = (if ok then ValueSome(listed :> IReadOnlyCollection<_>) else ValueNone)
                    }

            lastAnswers <- List.ofSeq answers
            // The checks in one call, in parallel when many need one.
            let keys = Array.ofSeq shares.Keys

            let item i =
                let key = keys[i]
                let struct (threshold, byId) = shares[key]
                struct (threshold, key, [ for KeyValue(i, s) in byId -> i, s ])

            let results = shareChecks.CheckAll(keys.Length, item, ct)

            let offSplit =
                [
                    for i in 0 .. keys.Length - 1 do
                        match results[i] with
                        | Ok() -> ()
                        | Error why -> keys[i], $"distributed key {keys[i].Hex}: {why}"
                ]

            shareChecks.Sweep()
            refused <- offSplit @ [ for KeyValue(key, why) in small -> key, why ]
            let off = offSplit |> List.map fst |> set

            let routes =
                out
                |> Seq.filter (fun (k, b) -> not (Threshold.isGroup b && off.Contains k))
                |> Seq.distinctBy (fun (k, b) -> struct (k, Threshold.isGroup b))

            return List.ofSeq routes, answered
        }

    member _.Stop() =
        for e in lock gate (fun () -> List.ofSeq endpoints.Values) do
            e.Stop()

let create () : Module =
    let settings = ref ValueNone

    {
        Name = name
        Configure =
            fun section ->
                match section.Element with
                | ValueNone ->
                    // Linked but not configured: the module stays off.
                    settings.Value <- ValueNone
                    Ok()
                | ValueSome _ ->
                    match parseSettings section with
                    | Ok s ->
                        settings.Value <- ValueSome s
                        Ok()
                    | Error e -> Error e
        Check =
            fun _ ->
                match settings.Value with
                | ValueNone -> Ok "not configured"
                | ValueSome s ->
                    match GrpcDirk.loadTls s.Tls Log.none TimeProvider.System with
                    | Ok _ -> Ok $"{s.Endpoints.Length} endpoints, TLS files load"
                    | Error e -> Error [ e ]
        Start =
            fun core ct ->
                task {
                    match settings.Value with
                    | ValueNone -> return Ok { Stop = fun () -> Task.CompletedTask }
                    | ValueSome s ->
                        match GrpcDirk.loadTls s.Tls core.Log core.Clock.Time with
                        | Error e -> return Error e
                        | Ok tls ->
                            let connect address = GrpcDirk.connect address tls

                            let chain: ProbeChain =
                                {
                                    Spec = core.Spec
                                    CurrentEpoch =
                                        fun () -> core.Clock.CurrentSlot |> ValueOption.map core.Clock.EpochOf
                                }

                            let set = DirkSet(connect, s, core.Clock.Time, core.Log, chain)
                            let keys = ListedKeys(name, core.Registry, core.Pipeline, core.Log)
                            let! found, answered = set.Discover ct
                            keys.Refuse set.Refused
                            let added = keys.Register found
                            let! _ = keys.Retire(set.LastAnswers, (fun _ -> true), ct)
                            core.Log.Info $"dirk: {answered} of {s.Endpoints.Length} endpoints answered, {added} keys"
                            let stopper = new CancellationTokenSource()
                            let stopToken = stopper.Token

                            let reloader =
                                TlsFiles.watch [ tls.Ca; tls.Client ] s.ReloadInterval core.Clock.Time stopToken

                            let refresher =
                                if s.RefreshInterval > TimeSpan.Zero then
                                    task {
                                        use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stopToken)
                                        let mutable lastAnswered = answered

                                        try
                                            while not linked.IsCancellationRequested do
                                                // Until an endpoint answers, try again every 12 s.
                                                let wait =
                                                    if lastAnswered = 0 then
                                                        min s.RefreshInterval (TimeSpan.FromSeconds 12.0)
                                                    else
                                                        s.RefreshInterval

                                                do! Task.Delay(wait, core.Clock.Time, linked.Token)

                                                try
                                                    let! found, n = set.Discover linked.Token
                                                    keys.Refuse set.Refused
                                                    lastAnswered <- n
                                                    let added = keys.Register found
                                                    let! _ = keys.Retire(set.LastAnswers, (fun _ -> true), linked.Token)

                                                    if added > 0 then
                                                        core.Log.Info $"dirk: {added} new keys"
                                                        do! core.RefreshKeys linked.Token
                                                with
                                                | :? OperationCanceledException -> ()
                                                | e -> core.Log.Warn $"dirk: account refresh failed: {e.Message}"
                                        with :? OperationCanceledException ->
                                            ()
                                    }
                                    :> Task
                                else
                                    Task.CompletedTask

                            return
                                Ok
                                    {
                                        Stop =
                                            fun () ->
                                                task {
                                                    stopper.Cancel()
                                                    do! refresher
                                                    do! reloader
                                                    set.Stop()
                                                    stopper.Dispose()
                                                }
                                                :> Task
                                    }
                }
    }
