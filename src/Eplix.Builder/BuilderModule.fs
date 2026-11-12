/// The builder module: the market side of Gloas proposals. It asks external builders
/// for bids through produceBlockV4's BuilderConfig, each request authenticated by a
/// SignedBuilderRequestAuth that the proposer's key signs (signed an epoch ahead, in the low
/// class), sends builder preferences in the epoch before each proposal, and checks a won bid
/// against the builder's floor before the VC signs the block. Config section "builder":
///   { "builders": [ { "url": "https://builder.example", "auth_data": "0x..." (default: the URL's
///       host name), "builder_pubkeys": [ "0x..." ], "max_execution_payment": "0",
///       "min_bid": "0", "builder_boost_factor": "100" } ],
///     "preferences": true }
/// Without the module the VC still proposes: self-build and the node's p2p bids.
/// -p:EplixBuilder=false drops it.
module Eplix.Builder.BuilderModule

open System
open System.Collections.Generic
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon
open Eplix.Json

let name = "builder"

type BuilderSettings =
    {
        Url: string
        /// Agreed with the builder; by default the UTF-8 host name of the URL (builder-specs,
        /// "default auth data").
        AuthData: byte[]
        BuilderPubkeys: PubKey list
        MaxExecutionPayment: uint64
        MinBid: uint64
        BuilderBoostFactor: uint64
    }

type Settings =
    {
        Builders: BuilderSettings list
        /// Submit builder preferences (max_execution_payment) in the epoch before each proposal.
        Preferences: bool
    }

    static member Default = { Builders = []; Preferences = true }

let private builderOf (e: JsonElement) : BuilderSettings =
    match
        checkFields
            e
            "modules.builder.builders[]"
            [
                "url"
                "auth_data"
                "builder_pubkeys"
                "max_execution_payment"
                "min_bid"
                "builder_boost_factor"
            ]
    with
    | err :: _ -> fail err
    | [] ->
        let url = strField e "url"

        let uri =
            match Uri.TryCreate(url, UriKind.Absolute) with
            | true, NonNull u when u.Scheme = Uri.UriSchemeHttps || u.Scheme = Uri.UriSchemeHttp -> u
            | _ -> fail $"builder url {url} is not an http(s) URL"

        let authData =
            match tryProp e "auth_data" with
            | ValueSome a ->
                match Hex.tryDecode (str a) with
                | ValueSome b when b.Length >= 1 && b.Length <= 4096 -> b
                | _ -> fail "auth_data must be 1 to 4096 bytes of 0x-hex"
            | ValueNone -> Encoding.UTF8.GetBytes uri.Host

        let num n (fallback: uint64) =
            match tryProp e n with
            | ValueSome v -> u64 v
            | ValueNone -> fallback

        {
            Url = url
            AuthData = authData
            BuilderPubkeys =
                match tryProp e "builder_pubkeys" with
                | ValueSome ks -> array ks |> Array.map pubkey |> List.ofArray
                | ValueNone -> []
            MaxExecutionPayment = num "max_execution_payment" 0UL
            MinBid = num "min_bid" 0UL
            BuilderBoostFactor = num "builder_boost_factor" 100UL
        }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok Settings.Default
    | ValueSome e ->
        match checkFields e "modules.builder" [ "builders"; "preferences" ] with
        | [] ->
            try
                let builders =
                    match tryProp e "builders" with
                    | ValueSome b -> array b |> Array.map builderOf |> List.ofArray
                    | ValueNone -> []

                if builders.Length > 64 then
                    fail "at most 64 builders (MAX_BUILDER_ENTRIES)"

                Ok
                    {
                        Builders = builders
                        Preferences =
                            (match tryProp e "preferences" with
                             | ValueSome _ -> boolField e "preferences"
                             | ValueNone -> true)
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.builder: {x.Message}" ]
        | errs -> Error errs

/// The value of a bid toward a builder's floor and weight: value plus the execution payment up to
/// the entry's cap (beacon-APIs BuilderEntry), saturating at 2^64 - 1.
let bidValue (value: uint64) (executionPayment: uint64) (maxExecutionPayment: uint64) =
    let counted = min executionPayment maxExecutionPayment
    if UInt64.MaxValue - value < counted then UInt64.MaxValue else value + counted

/// Signs and caches the request auths, and offers the hooks and the preferences duty.
type Builders(core: CoreServices, settings: Settings) =
    let spec = core.Spec
    let gvr = core.Genesis.GenesisValidatorsRoot
    let log = core.Log
    let gate = obj ()
    /// Signed auths by (key, slot, builder url).
    let auths = Dictionary<struct (PubKey * Slot * string), SignedBuilderRequestAuth>()
    /// Keys whose signer does not support a request auth: p2p bids and self-build only (design Q7).
    let noAuth = HashSet<PubKey>()
    /// Proposals whose auth failed for a passing reason (a timeout, a signer briefly down),
    /// logged once each; the next prepare run tries again.
    let authFailed = HashSet<struct (PubKey * Slot)>()
    let preferencesSent = HashSet<struct (PubKey * Slot)>()
    // One prepare run at a time (the scheduler starts one per slot).
    let prepareGate = new SemaphoreSlim(1, 1)

    /// The signed auths of one proposal for every builder. Empty when the key's signer cannot
    /// sign builder request auth.
    let authsFor
        (d: ProposerDuty)
        (priority: Priority)
        (ct: CancellationToken)
        : Task<(BuilderSettings * SignedBuilderRequestAuth) list> =
        task {
            let missing =
                lock gate (fun () ->
                    // A parked key (noAuth) is not asked again, at the proposal either.
                    if noAuth.Contains d.PubKey then
                        []
                    else
                        settings.Builders
                        |> List.filter (fun b -> not (auths.ContainsKey(struct (d.PubKey, d.Slot, b.Url)))))

            if not missing.IsEmpty then
                let reqs =
                    missing
                    |> List.map (fun b ->
                        let a =
                            {
                                AuthData = b.AuthData
                                AuthSlot = d.Slot
                            }

                        b,
                        a,
                        Duty.request
                            spec
                            gvr
                            d.PubKey
                            priority
                            (core.Clock.SlotStart(d.Slot + 1UL))
                            (Duty.BuilderRequestAuth a))

                let! outcomes = core.Pipeline.SignBurst(reqs |> List.map (fun (_, _, r) -> r) |> Array.ofList, ct)

                List.iteri
                    (fun i (b, a, _) ->
                        match outcomes[i] with
                        | Signed s ->
                            lock gate (fun () ->
                                auths[struct (d.PubKey, d.Slot, b.Url)] <- { Auth = a; AuthSignature = s })
                        // An emergency switch: no auth now, but the key keeps its builders once it lifts.
                        | Refused(Paused _) -> ()
                        // The signer cannot or will not sign this kind for the key: no builders
                        // while the VC runs. Web3Signer answers an unknown type with 400
                        // (BadRequest); Dirk answers a missing permission with DENIED. Asked
                        // again each slot, each Denied would also count against the key. A
                        // group's Denied with a member down or failing may be short-lived, so
                        // only one where every member answered parks the key.
                        | Refused(Unsupported _ | BadRequest _ | Denied(_, { Failed = 0; Errored = 0 })) as o ->
                            if lock gate (fun () -> noAuth.Add d.PubKey) then
                                log.Warn
                                    $"key {d.PubKey.Short}: builder request auth not signed ({o.Describe}); p2p bids and self-build only"
                        // A policy refusal is tried again like a timeout: the pipeline answers
                        // PolicyDenied for any key that is not active, and a key in doppelganger
                        // wait becomes active soon.
                        | o ->
                            if lock gate (fun () -> authFailed.Add(struct (d.PubKey, d.Slot))) then
                                log.Warn
                                    $"slot {d.Slot}: builder request auth of {d.PubKey.Short} not signed ({o.Describe}); tried again at the next slot")
                    reqs

            return
                lock gate (fun () ->
                    [
                        for b in settings.Builders do
                            match auths.TryGetValue(struct (d.PubKey, d.Slot, b.Url)) with
                            | true, a -> b, a
                            | _ -> ()
                    ])
        }

    let entriesFor (d: ProposerDuty) (ct: CancellationToken) : Task<BuilderEntry list> =
        task {
            let! signed = authsFor d Priority.High ct

            return
                [
                    for b, a in signed ->
                        {
                            Url = b.Url
                            Auth = a
                            BuilderPubkeys = b.BuilderPubkeys
                            MaxExecutionPayment = b.MaxExecutionPayment
                            MinBid = b.MinBid
                            BuilderBoostFactor = b.BuilderBoostFactor
                        }
                ]
        }

    /// True when a key of `b.BuilderPubkeys` signed the bid. The bid names its builder by index
    /// only, and the VC has no index to key map without a state read. The chain checks the bid
    /// signature against the key at that index, and a BLS signature verifies under one key at
    /// most, so a valid block whose bid a listed key signed is that builder's. Cost: one
    /// pairing check per listed key, once per builder bid at proposal time.
    let signedByListed (b: BuilderSettings) (slot: Slot) (message: Ssz.SszValue) (signature: byte[]) =
        let domain = Signing.domainAt spec gvr spec.DomainBeaconBuilder (spec.EpochOf slot)

        let root =
            Signing.computeSigningRoot (Root.Of(Ssz.hashTreeRoot Schemas.Gloas.executionPayloadBid message)) domain

        b.BuilderPubkeys
        |> List.exists (fun k -> Bls.verify (ReadOnlySpan k.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan signature))

    let checkBid (d: ProposerDuty) (url: string) (signedBid: Ssz.SszValue) : Result<unit, string> =
        match settings.Builders |> List.tryFind (fun b -> b.Url = url) with
        | None -> Error $"the node names builder {url}, which is not configured"
        | Some b ->
            let sb = Codec.fields signedBid
            let f = Codec.fields sb[0]
            let value = bidValue (Codec.asU f[8]) (Codec.asU f[9]) b.MaxExecutionPayment

            if Codec.asU f[7] <> d.Slot then
                Error $"the bid of {url} is for slot {Codec.asU f[7]}"
            elif value < b.MinBid then
                Error $"the bid of {url} pays {value} Gwei, below its minimum {b.MinBid}"
            elif not b.BuilderPubkeys.IsEmpty && not (signedByListed b d.Slot sb[0] (Codec.asBytes sb[1])) then
                Error $"the bid of {url} (builder {Codec.asU f[6]}) is not signed by a key in its builder_pubkeys"
            else
                Ok()

    /// In the epoch before each proposal: sign the auths in the low class and send builder
    /// preferences once per proposal.
    let prepare (view: SchedulerView) (epoch: Epoch) (ct: CancellationToken) =
        task {
            if not settings.Builders.IsEmpty then
                for e in [ epoch; epoch + 1UL ] do
                    if spec.IsGloasAt e then
                        match view.ProposerDuties e with
                        | ValueNone -> ()
                        | ValueSome duties ->
                            let now = defaultValueArg core.Clock.CurrentSlot 0UL
                            // A key that is not active (doppelganger wait, draining) is skipped:
                            // the pipeline would refuse it. A later run signs once it is active.
                            let active (k: PubKey) =
                                match core.Registry.TryGet k with
                                | ValueSome r -> r.State = KeyState.Active
                                | ValueNone -> false

                            for d in duties.Data do
                                if
                                    d.Slot > now
                                    && active d.PubKey
                                    && lock gate (fun () -> not (noAuth.Contains d.PubKey))
                                then
                                    let! signed = authsFor d Priority.Low ct

                                    let fresh =
                                        lock gate (fun () ->
                                            not signed.IsEmpty && preferencesSent.Add(struct (d.PubKey, d.Slot)))

                                    if settings.Preferences && fresh then
                                        let entries =
                                            [
                                                for b, a in signed ->
                                                    {
                                                        ProposerPubkey = d.PubKey
                                                        Url = b.Url
                                                        Auth = a
                                                        MaxExecutionPayment = b.MaxExecutionPayment
                                                    }
                                            ]

                                        match!
                                            core.Nodes.Broadcast(
                                                (fun n -> n.SubmitBuilderPreferences(entries, ct)),
                                                NodeRole.BlockPublish,
                                                BroadcastTopic.Preparations
                                            )
                                        with
                                        | Ok() ->
                                            log.Info
                                                $"slot {d.Slot}: builder preferences sent to {entries.Length} builders"
                                        | Error err ->
                                            lock gate (fun () ->
                                                preferencesSent.Remove(struct (d.PubKey, d.Slot)) |> ignore)

                                            log.Warn $"slot {d.Slot}: builder preferences: {err.Describe}"

                lock gate (fun () ->
                    let old (s: Slot) = spec.EpochOf s + 2UL < epoch

                    for k in List.ofSeq auths.Keys do
                        let struct (_, s, _) = k

                        if old s then
                            auths.Remove k |> ignore

                    preferencesSent.RemoveWhere(fun struct (_, s) -> old s) |> ignore
                    authFailed.RemoveWhere(fun struct (_, s) -> old s) |> ignore)
        }

    member _.Hooks: BuilderHooks =
        {
            EntriesFor = entriesFor
            CheckBid = checkBid
        }

    member _.Extension: DutyExtension =
        { DutyExtension.empty name with
            PrepareEpochs =
                fun view epoch ct ->
                    task {
                        do! prepareGate.WaitAsync ct

                        try
                            do! prepare view epoch ct
                        finally
                            prepareGate.Release() |> ignore
                    }
        }

let create () : Module =
    let settings = ref Settings.Default

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check = fun _ -> Ok $"{settings.Value.Builders.Length} builders"
        Start =
            fun core _ ->
                task {
                    if core.Spec.IsScheduled Gloas && not settings.Value.Builders.IsEmpty then
                        let b = Builders(core, settings.Value)
                        core.SetBuilder b.Hooks
                        core.AddDutyExtension b.Extension

                        core.Log.Info
                            $"""builders: {String.Join(", ", settings.Value.Builders |> List.map (fun x -> x.Url))}"""

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
