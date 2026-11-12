/// The VC config: one JSON file. Strict: an unknown field fails the start.
/// Each linked module reads its own section under "modules".
namespace Eplix

open System
open System.IO
open System.Text.Json
open Eplix.Json

[<RequireQualifiedAccess>]
type AllowStartWithoutHistory =
    | Nobody
    | All
    | Keys of Set<PubKey>

    member this.Allows(key: PubKey) =
        match this with
        | Nobody -> false
        | All -> true
        | Keys ks -> ks.Contains key

/// A module's config section, with the directory that relative paths in it resolve against.
type ConfigSection =
    {
        Element: JsonElement voption
        BaseDir: string
        /// The VC runs on mainnet (`ChainSource.IsMainnet`): modules with rules for mainnet read it.
        Mainnet: bool
    }

    /// `p` resolved against `baseDir`. A NUL character fails as a decode error (GetFullPath
    /// throws ArgumentException on it), so it reaches the operator as a config error.
    static member FullPath(p: string, baseDir: string) =
        if p.Contains(char 0) then
            fail "the path has a NUL character"

        Path.GetFullPath(p, baseDir)

    member this.Path(p: string) = ConfigSection.FullPath(p, this.BaseDir)

/// One beacon node: its URL, a CA file to trust for its HTTPS certificate, and headers sent
/// with every request (an API key or basic auth for a hosted node).
type BeaconNodeConfig =
    {
        Url: Uri
        /// PEM or DER file of the CA that signed the node's certificate. Only this CA is trusted for
        /// the node. ValueNone: the system store.
        CaCert: string voption
        /// Sent with every request to this node. Values may be secrets: they never go to logs.
        Headers: (string * string) list
        /// What the node is used for. Default: every role.
        Roles: Eplix.Beacon.NodeRole
    }

/// Which client codes go after the graffiti (`graffiti_append`).
[<RequireQualifiedAccess>]
type GraffitiAppend =
    /// None: the graffiti as the operator wrote it (the beacon node may still append its own).
    | Off
    /// The VC's own code only; a beacon node that appends codes adds its own and its execution client's.
    | Vc
    /// The execution client's, the beacon node's and the VC's codes; turn the node's appending off.
    | All

/// Where the chain config the beacon nodes must match comes from.
[<RequireQualifiedAccess>]
type ChainSource =
    /// A built-in network (Networks.fs): mainnet, hoodi or sepolia.
    | Network of string
    /// A consensus config.yaml file, for devnets and other chains.
    | File of string

    /// The pinned `KEY: value` pairs. Reads the file of a File source.
    member c.Pinned: Map<string, string> =
        match c with
        | Network name ->
            match Networks.configYaml name with
            | ValueSome text -> ChainSpec.parseConfigYaml text
            | ValueNone -> failwith $"no built-in network {name}"
        | File path -> ChainSpec.parseConfigYaml (System.IO.File.ReadAllText path)

    /// For messages: "network hoodi" or "chain config <path>".
    member c.Describe =
        match c with
        | Network name -> $"network {name}"
        | File path -> $"chain config {path}"

    /// Mainnet: the built-in network, or a config file named mainnet or with mainnet's genesis
    /// fork version. A file that cannot be read counts as mainnet, so mainnet's rules hold.
    member c.IsMainnet =
        match c with
        | Network name -> name = "mainnet"
        | File _ ->
            try
                let p = c.Pinned
                p.TryFind "CONFIG_NAME" = Some "mainnet" || p.TryFind "GENESIS_FORK_VERSION" = Some "0x00000000"
            with _ ->
                true

type CoreConfig =
    {
        /// The beacon nodes, in order of preference (ties in health score go to the earlier one).
        BeaconNodes: BeaconNodeConfig list
        /// How many nodes must agree on attestation data. Default: a majority.
        AttestationConsensusThreshold: int
        /// How many nodes must agree on Gloas PTC data. Default 1: the best node answers.
        PtcConsensusThreshold: int
        /// What goes to every node at once, returning with the first that accepts; the rest goes to
        /// the best node, then the next on failure. Default: all.
        Broadcast: Eplix.Beacon.BroadcastTopic
        /// The pinned chain config every beacon node's spec must match: `network` or `chain_config`.
        Chain: ChainSource
        DataDir: string
        LogLevel: LogLevel
        LogFormat: LogFormat
        AllowStartWithoutHistory: AllowStartWithoutHistory
        RequestTimeout: TimeSpan
        /// Subscribe to head events to attest when the block arrives; else only at the due time.
        UseEvents: bool
        /// Default fee recipient (0x-hex address) sent with prepare_beacon_proposer. ValueNone: the node's own.
        FeeRecipient: string voption
        /// Default graffiti, at most 32 bytes of UTF-8.
        Graffiti: string
        /// Client codes appended to the graffiti of each proposal. Default Off.
        GraffitiAppend: GraffitiAppend
        /// This VC's two-letter client code, required when GraffitiAppend is not Off.
        GraffitiVcCode: string voption
        /// Default gas limit, reported by the keymanager API (the builder module uses it too).
        GasLimit: uint64
        /// The operator's proposer config file (ProposerConfig.fs), read again each epoch. ValueNone: none.
        ProposerConfig: string voption
        /// How long before each epoch boundary the proposer config file is checked.
        ProposerConfigLead: TimeSpan
        /// Epochs between slashing DB snapshots while running.
        SnapshotIntervalEpochs: uint64
        /// Emergency switches set in the config (stop_signing, paused_duties). The switch file in
        /// the data dir adds to them while running.
        Switches: Switches
        /// Random waits before signing requests go to a backend (`signing` and
        /// `modules.<backend>.signing`, SigningJitter.fs). Default: none.
        Signing: SigningJitterConfig
        Modules: Map<string, ConfigSection>
    }

    /// The first beacon node, for messages that name one.
    member this.BeaconNode = (List.head this.BeaconNodes).Url

/// Request headers for a beacon node: checks and the headers file format.
module Headers =
    let private tokenChar (c: char) = Char.IsAsciiLetterOrDigit c || "!#$%&'*+-.^_`|~".Contains c

    /// A header name is an HTTP token; a value has no control characters (no CR or LF).
    let check (name: string) (value: string) : Result<unit, string> =
        if name.Length = 0 || not (Seq.forall tokenChar name) then
            Error $"header name '{name}' is not an HTTP token"
        elif value |> Seq.exists (fun c -> Char.IsControl c && c <> '\t') then
            Error $"header {name}: the value has a control character"
        else
            Ok()

    /// One "Name: value" per line; blank lines and lines starting with # are skipped.
    let parseFile (text: string) : Result<(string * string) list, string> =
        let parsed =
            text.Split('\n')
            |> Array.map (fun l -> l.TrimEnd('\r'))
            |> Array.indexed
            |> Array.filter (fun (_, l) -> l.Trim().Length > 0 && not (l.TrimStart().StartsWith '#'))
            |> Array.map (fun (i, l) ->
                match l.IndexOf ':' with
                | n when n > 0 -> Ok(l.Substring(0, n).Trim(), l.Substring(n + 1).Trim())
                | _ -> Error $"line {i + 1} is not 'Name: value'")

        match
            parsed
            |> Array.tryPick (fun r ->
                match r with
                | Error e -> Some e
                | Ok _ -> None)
        with
        | Some e -> Error e
        | None ->
            Ok
                [
                    for r in parsed do
                        match r with
                        | Ok h -> h
                        | Error _ -> ()
                ]

module Config =
    /// The top-level keys of the config file.
    let coreFields =
        [
            "beacon_node"
            "beacon_nodes"
            "attestation_consensus_threshold"
            "ptc_consensus_threshold"
            "broadcast"
            "fee_recipient"
            "graffiti"
            "graffiti_append"
            "graffiti_vc_code"
            "gas_limit"
            "proposer_config"
            "proposer_config_lead_ms"
            "snapshot_interval_epochs"
            "chain_config"
            "network"
            "data_dir"
            "log_level"
            "log_format"
            "allow_start_without_history"
            "request_timeout_ms"
            "use_events"
            "stop_signing"
            "paused_duties"
            "signing"
            "modules"
        ]

    let private logLevel (s: string) =
        match s with
        | "debug" -> Ok LogLevel.Debug
        | "info" -> Ok LogLevel.Info
        | "warn" -> Ok LogLevel.Warn
        | "error" -> Ok LogLevel.Error
        | other -> Error $"log_level '{other}' is not debug, info, warn or error"

    /// Whether modules.tee.ha_peer is true in these module sections.
    let private haPeerIn (modules: Map<string, ConfigSection>) =
        match
            modules.TryFind "tee"
            |> Option.map (fun s -> s.Element |> ValueOption.bind (fun e -> tryProp e "ha_peer"))
        with
        | Some(ValueSome v) -> v.ValueKind = JsonValueKind.True
        | _ -> false

    /// modules.tee.ha_peer: another VC signs the same keys through the same runners, so every key
    /// must sign through the tee module.
    let haPeer (c: CoreConfig) = haPeerIn c.Modules

    /// Parses the config text. `baseDir` resolves relative paths; `moduleNames` are the linked modules.
    let parse (text: string) (baseDir: string) (moduleNames: string list) : Result<CoreConfig, string list> =
        try
            use doc = JsonDocument.Parse(text, JsonDocumentOptions(CommentHandling = JsonCommentHandling.Skip))
            let root = doc.RootElement
            let errors = ResizeArray<string>(checkFields root "config" coreFields)
            let path (p: string) = ConfigSection.FullPath(p, baseDir)

            let opt name f fallback =
                match tryProp root name with
                | ValueSome v ->
                    try
                        f v
                    with :? JsonDecodeError as e ->
                        // A range error from `bounded` names the key already.
                        errors.Add(if e.Message.StartsWith $"{name} " then e.Message else $"{name}: {e.Message}")
                        fallback
                | ValueNone -> fallback

            let required name f fallback =
                match tryProp root name with
                | ValueSome _ -> opt name f fallback
                | ValueNone ->
                    errors.Add $"{name} is required"
                    fallback
            // User info in a node URL would reach logs and metric labels; basic auth goes in
            // `headers`. The error names scheme, host and port only, not the credentials.
            let uriOf (s: string) =
                match Uri.TryCreate(s, UriKind.Absolute) with
                | true, NonNull u when
                    (u.Scheme = "http" || u.Scheme = "https") && not (String.IsNullOrEmpty u.UserInfo)
                    ->
                    fail
                        $"the beacon node URL {u.Scheme}://{u.Authority} carries user info; give credentials in headers (Authorization: Basic ...)"
                | true, NonNull u when u.Scheme = "http" || u.Scheme = "https" -> u
                // A value with '@' may hold a password, also after a '/' or without '//': show
                // only the scheme.
                | _ ->
                    let shown =
                        match s.IndexOf '@', s.IndexOf "://" with
                        | -1, _ -> $"'{s}'"
                        | _, i when i > 0 -> $"'{s.Substring(0, i)}://...' (the rest may hold credentials)"
                        | _ -> "the value (it may hold credentials)"

                    fail $"{shown} is not an http or https URL"

            let uri (v: JsonElement) = uriOf (str v)

            let invalid =
                {
                    Url = Uri "http://invalid"
                    CaCert = ValueNone
                    Headers = []
                    Roles = Eplix.Beacon.NodeRole.All
                }

            let node (v: JsonElement) =
                match v.ValueKind with
                | JsonValueKind.String -> { invalid with Url = uri v }
                | JsonValueKind.Object ->
                    match checkFields v "beacon node" [ "url"; "ca_cert"; "headers"; "headers_file"; "roles" ] with
                    | e :: _ -> fail e
                    | [] -> ()

                    let u = uri (prop v "url")

                    let ca =
                        match tryProp v "ca_cert" with
                        | ValueSome c ->
                            let f = path (str c)

                            if u.Scheme <> "https" then
                                fail $"ca_cert needs an https URL ({u.GetLeftPart(UriPartial.Authority)})"

                            if not (File.Exists f) then
                                fail $"ca_cert {f} does not exist"

                            ValueSome f
                        | ValueNone -> ValueNone

                    let given =
                        match tryProp v "headers" with
                        | ValueSome h when h.ValueKind = JsonValueKind.Object ->
                            [ for p in h.EnumerateObject() -> p.Name, str p.Value ]
                        | ValueSome _ -> fail "headers must be an object of name: value"
                        | ValueNone -> []

                    let fromFile =
                        match tryProp v "headers_file" with
                        | ValueSome f ->
                            let file = path (str f)

                            if not (File.Exists file) then
                                fail $"headers_file {file} does not exist"

                            let text =
                                try
                                    File.ReadAllText file
                                with
                                | :? IOException
                                | :? UnauthorizedAccessException as e -> fail $"headers_file {file}: {e.Message}"

                            match Headers.parseFile text with
                            | Ok hs -> hs
                            | Error e -> fail $"headers_file {file}: {e}"
                        | ValueNone -> []

                    let headers = given @ fromFile

                    for name, value in headers do
                        match Headers.check name value with
                        | Ok() -> ()
                        | Error e -> fail e

                    let names = headers |> List.map (fun (n, _) -> n.ToLowerInvariant())

                    if (List.distinct names).Length <> names.Length then
                        fail "a header is given more than once"

                    let roles =
                        match tryProp v "roles" with
                        | ValueNone -> Eplix.Beacon.NodeRole.All
                        | ValueSome r ->
                            let names =
                                match r.ValueKind with
                                | JsonValueKind.Array -> array r |> Array.map str |> List.ofArray
                                // A comma-separated string, as a flag or environment variable gives it.
                                | JsonValueKind.String ->
                                    (str r)
                                        .Split(
                                            ',',
                                            StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries
                                        )
                                    |> List.ofArray
                                | _ -> fail "roles must be a list of role names"

                            if names.IsEmpty then
                                fail "roles must not be empty (leave it out for every role)"

                            names
                            |> List.fold
                                (fun acc n ->
                                    match Eplix.Beacon.NodeRole.parse n with
                                    | ValueSome x -> acc ||| x
                                    | ValueNone ->
                                        let known =
                                            (List.map snd Eplix.Beacon.NodeRole.names)
                                            @ (List.map fst Eplix.Beacon.NodeRole.groups)

                                        fail $"""unknown role '{n}' (known: {String.Join(", ", known)})""")
                                Eplix.Beacon.NodeRole.None

                    {
                        Url = u
                        CaCert = ca
                        Headers = headers
                        Roles = roles
                    }
                | _ -> fail "a beacon node is a URL or an object with url"

            let beacons =
                match tryProp root "beacon_node", tryProp root "beacon_nodes" with
                | ValueSome _, ValueSome _ ->
                    errors.Add "give beacon_node or beacon_nodes, not both"
                    [ invalid ]
                | ValueNone, ValueNone ->
                    errors.Add "beacon_node or beacon_nodes is required"
                    [ invalid ]
                | ValueSome _, ValueNone -> [ opt "beacon_node" node invalid ]
                | ValueNone, ValueSome _ ->
                    // A bad entry already has its error; the list is then empty but was not given so.
                    let errorsBefore = errors.Count

                    let list =
                        opt
                            "beacon_nodes"
                            (fun v ->
                                match v.ValueKind with
                                // A comma-separated string, as flags and environment variables give it.
                                | JsonValueKind.String ->
                                    (str v)
                                        .Split(
                                            ',',
                                            StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries
                                        )
                                    |> Array.map (fun u -> { invalid with Url = uriOf u })
                                    |> List.ofArray
                                | _ -> array v |> Array.map node |> List.ofArray)
                            []

                    let hosts = list |> List.map (fun n -> n.Url.GetLeftPart(UriPartial.Authority).ToLowerInvariant())

                    if list.IsEmpty && errors.Count = errorsBefore then
                        errors.Add "beacon_nodes must not be empty"
                        [ invalid ]
                    else
                        if (List.distinct hosts).Length <> hosts.Length then
                            errors.Add "beacon_nodes: each node needs its own host and port"

                        list
            // Thresholds count the nodes that serve attestation data (all of them unless roles split).
            let dataNodes =
                beacons
                |> List.filter (fun n ->
                    n.Roles &&& Eplix.Beacon.NodeRole.AttestationData <> Eplix.Beacon.NodeRole.None)
                |> List.length

            let split = beacons |> List.exists (fun n -> n.Roles <> Eplix.Beacon.NodeRole.All)

            let thresholdRange =
                if split then
                    $"must be between 1 and the number of beacon nodes with the role attestation_data ({dataNodes})"
                else
                    $"must be between 1 and the number of beacon nodes ({beacons.Length})"

            let threshold =
                opt
                    "attestation_consensus_threshold"
                    (fun v ->
                        let t = u64 v

                        if t = 0UL || t > uint64 dataNodes then
                            fail thresholdRange

                        int t)
                    (max 1 (dataNodes / 2 + 1))

            let ptcThreshold =
                opt
                    "ptc_consensus_threshold"
                    (fun v ->
                        let t = u64 v

                        if t = 0UL || t > uint64 dataNodes then
                            fail thresholdRange

                        int t)
                    1

            let broadcast =
                opt
                    "broadcast"
                    (fun v ->
                        let one (n: string) =
                            match Eplix.Beacon.BroadcastTopic.parse n with
                            | ValueSome t -> t
                            | ValueNone ->
                                let known = "all" :: "none" :: (List.map snd Eplix.Beacon.BroadcastTopic.names)
                                fail $"""unknown topic '{n}' (known: {String.Join(", ", known)})"""

                        match v.ValueKind with
                        | JsonValueKind.True -> Eplix.Beacon.BroadcastTopic.All
                        // As Lighthouse without --broadcast: subscriptions and preparations still go to every node.
                        | JsonValueKind.False -> Eplix.Beacon.BroadcastTopic.lighthouseDefault
                        | JsonValueKind.Array ->
                            array v |> Array.fold (fun acc x -> acc ||| one (str x)) Eplix.Beacon.BroadcastTopic.None
                        // A comma-separated string, as a flag or environment variable gives it.
                        | JsonValueKind.String ->
                            (str v)
                                .Split(',', StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
                            |> Array.fold (fun acc x -> acc ||| one x) Eplix.Beacon.BroadcastTopic.None
                        | _ -> fail "must be true, false, or a list of topics")
                    Eplix.Beacon.BroadcastTopic.All
            // Every role needs a node, else its duty would stop for good.
            if split then
                for n in beacons do
                    if n.Roles = Eplix.Beacon.NodeRole.None then
                        errors.Add $"beacon node {n.Url.GetLeftPart(UriPartial.Authority)}: no role"

                match Eplix.Beacon.NodeRole.check (beacons |> List.map (fun n -> n.Roles)) 1 1 with
                | Error es ->
                    for e in es do
                        errors.Add $"beacon_nodes: {e}"
                | Ok() -> ()

            let feeRecipient =
                opt
                    "fee_recipient"
                    (fun v ->
                        match Hex.tryDecodeFixed 20 (str v) with
                        | ValueSome b -> ValueSome(Hex.encodeArray b)
                        | ValueNone -> fail "must be a 20-byte 0x-hex address")
                    ValueNone

            let graffiti =
                opt
                    "graffiti"
                    (fun v ->
                        let g = str v

                        if Text.Encoding.UTF8.GetByteCount g > 32 then
                            fail "must be at most 32 bytes of UTF-8"

                        g)
                    ""

            let graffitiAppend =
                opt
                    "graffiti_append"
                    (fun v ->
                        match str v with
                        | "off" -> GraffitiAppend.Off
                        | "vc" -> GraffitiAppend.Vc
                        | "all" -> GraffitiAppend.All
                        | other -> fail $"'{other}' is not off, vc or all")
                    GraffitiAppend.Off

            let graffitiVcCode =
                opt
                    "graffiti_vc_code"
                    (fun v ->
                        let c = str v

                        if c.Length = 2 && Seq.forall Char.IsAsciiLetter c then
                            ValueSome(c.ToUpperInvariant())
                        else
                            fail $"'{c}' is not a client code of two ASCII letters")
                    ValueNone

            if graffitiAppend <> GraffitiAppend.Off && graffitiVcCode.IsNone then
                errors.Add "graffiti_append needs graffiti_vc_code, this VC's two-letter client code"

            // The default of every key without its own; the per-key setters and the proposer
            // config refuse 0 too.
            let gasLimit =
                opt
                    "gas_limit"
                    (fun v ->
                        let g = u64 v
                        if g = 0UL then fail "must be above 0" else g)
                    60_000_000UL

            let proposerConfig = opt "proposer_config" (str >> path >> ValueSome) ValueNone

            let proposerConfigLead =
                opt
                    "proposer_config_lead_ms"
                    (boundedMs "proposer_config_lead_ms" 1UL 600_000UL)
                    (TimeSpan.FromMilliseconds 500.0)

            let snapshotInterval =
                opt
                    "snapshot_interval_epochs"
                    (fun v ->
                        let n = u64 v

                        if n = 0UL then
                            fail "must be at least 1"

                        n)
                    8UL

            let networkNames = String.Join(", ", Networks.names)

            let chain =
                match tryProp root "network", tryProp root "chain_config" with
                | ValueSome _, ValueSome _ ->
                    errors.Add "give network or chain_config, not both"
                    ChainSource.File ""
                | ValueNone, ValueNone ->
                    errors.Add $"network ({networkNames}) or chain_config is required"
                    ChainSource.File ""
                | ValueSome _, ValueNone ->
                    opt
                        "network"
                        (fun v ->
                            let name = (str v).Trim().ToLowerInvariant()

                            if List.contains name Networks.names then
                                ChainSource.Network name
                            else
                                fail
                                    $"'{str v}' is not a built-in network ({networkNames}); use chain_config for others")
                        (ChainSource.File "")
                | ValueNone, ValueSome _ -> opt "chain_config" (str >> path >> ChainSource.File) (ChainSource.File "")

            let dataDir = required "data_dir" (str >> path) ""

            let level =
                opt
                    "log_level"
                    (fun v ->
                        match logLevel (str v) with
                        | Ok l -> l
                        | Error e -> fail e)
                    LogLevel.Info

            let logFormat =
                opt
                    "log_format"
                    (fun v ->
                        match str v with
                        | "text" -> LogFormat.Text
                        | "json" -> LogFormat.Json
                        | other -> fail $"'{other}' is not text or json")
                    LogFormat.Text

            let allow =
                opt
                    "allow_start_without_history"
                    (fun v ->
                        let items = array v |> Array.map str |> Array.toList

                        match items with
                        | [] -> AllowStartWithoutHistory.Nobody
                        | [ "all" ] -> AllowStartWithoutHistory.All
                        | ks ->
                            ks
                            |> List.map (fun k ->
                                match PubKey.TryParse k with
                                | ValueSome pk -> pk
                                | ValueNone -> fail $"'{k}' is not a public key or \"all\"")
                            |> Set.ofList
                            |> AllowStartWithoutHistory.Keys)
                    AllowStartWithoutHistory.Nobody

            let timeout =
                opt "request_timeout_ms" (boundedMs "request_timeout_ms" 1UL 600_000UL) (TimeSpan.FromSeconds 4.0)

            let useEvents =
                opt
                    "use_events"
                    (fun v ->
                        match v.ValueKind with
                        | JsonValueKind.True -> true
                        | JsonValueKind.False -> false
                        | _ -> fail "must be true or false")
                    true

            let switches =
                try
                    Switches.read root
                with :? JsonDecodeError as e ->
                    errors.Add e.Message
                    Switches.none

            let modules =
                match tryProp root "modules" with
                | ValueNone -> Map.empty
                | ValueSome m when m.ValueKind <> JsonValueKind.Object ->
                    errors.Add "modules must be an object"
                    Map.empty
                | ValueSome m ->
                    let mainnet = lazy chain.IsMainnet

                    [
                        for p in m.EnumerateObject() do
                            if List.contains p.Name moduleNames then
                                p.Name,
                                {
                                    Element = ValueSome(p.Value.Clone())
                                    BaseDir = baseDir
                                    Mainnet = mainnet.Value
                                }
                            else
                                errors.Add $"modules: '{p.Name}' is not a module in this build"
                    ]
                    |> Map.ofList
            // modules.tee.ha_peer turns tee-signer's "already signed" refusals into skipped duties.
            // Only tee-signer's codes are mapped, so every key must sign through the tee module.
            // Keys that the local and web3signer modules hold without a section (data dir
            // keystores, keymanager imports) are refused by the runner at start and at import.
            if haPeerIn modules then
                for other in [ "local"; "dirk"; "web3signer" ] do
                    if modules.ContainsKey other then
                        errors.Add
                            $"modules.tee.ha_peer: every key must sign through the tee module, but modules.{other} is configured"

            let signing =
                try
                    SigningJitter.parse (tryProp root "signing") [ for KeyValue(n, s) in modules -> n, s.Element ]
                with :? JsonDecodeError as e ->
                    errors.Add e.Message
                    SigningJitterConfig.Default

            if errors.Count > 0 then
                Error(List.ofSeq errors)
            else
                Ok
                    {
                        BeaconNodes = beacons
                        AttestationConsensusThreshold = threshold
                        PtcConsensusThreshold = ptcThreshold
                        Broadcast = broadcast
                        FeeRecipient = feeRecipient
                        Graffiti = graffiti
                        GraffitiAppend = graffitiAppend
                        GraffitiVcCode = graffitiVcCode
                        GasLimit = gasLimit
                        ProposerConfig = proposerConfig
                        ProposerConfigLead = proposerConfigLead
                        SnapshotIntervalEpochs = snapshotInterval
                        Chain = chain
                        DataDir = dataDir
                        LogLevel = level
                        LogFormat = logFormat
                        AllowStartWithoutHistory = allow
                        RequestTimeout = timeout
                        UseEvents = useEvents
                        Switches = switches
                        Signing = signing
                        Modules = modules
                    }
        with :? JsonException as e ->
            Error [ $"config is not valid JSON: {e.Message}" ]

    let load (file: string) (moduleNames: string list) =
        let full = Path.GetFullPath file
        parse (File.ReadAllText full) (nonNull (Path.GetDirectoryName full)) moduleNames

    let section (c: CoreConfig) (name: string) (baseDir: string) : ConfigSection =
        match c.Modules.TryFind name with
        | Some s -> s
        | None ->
            {
                Element = ValueNone
                BaseDir = baseDir
                Mainnet = c.Chain.IsMainnet
            }

/// Settings from command-line flags and environment variables over the config file. Precedence:
/// flag, then environment variable, then file. Each setting names a key path; the file's JSON gets
/// those keys replaced and then goes through the same strict parse, so an unknown key fails the
/// start whatever its source.
module ConfigSources =
    /// Where a setting came from, for error messages.
    type Setting =
        {
            Path: string list
            Value: string
            Source: string
        }

    /// EPLIX_ variables that are not config keys: the config file path and the test harness's
    /// switches. Every other EPLIX_ variable must name a config key.
    let ignoredEnv =
        set
            [
                "EPLIX_CONFIG"
                "EPLIX_FUZZ_CASES"
                "EPLIX_REQUIRE_ALL_VECTORS"
                "EPLIX_TEE_ORACLE"
                "EPLIX_TEE_RUNNER"
                "EPLIX_TEE_BENCH"
                "EPLIX_WEB3SIGNER"
                "EPLIX_GATEWAY_URL"
                "EPLIX_DIRK_NET"
                "EPLIX_GLOAS_SSZ_STATIC"
                // Also the test harness's and scripts/ci.sh's: a published binary started by a
                // test inherits them.
                "EPLIX_AOT_BIN"
                "EPLIX_CHARON_NET"
                "EPLIX_EIP3076_DIR"
                "EPLIX_FULU_SSZ_STATIC"
                "EPLIX_FUZZ_SEED"
                "EPLIX_SSZ_GENERIC"
                "EPLIX_SSZ_SPECS_DIR"
                "EPLIX_TEST_LIMIT_SECONDS"
                "EPLIX_TOOLS"
            ]

    let private check (source: string) (path: string list) : Result<unit, string> =
        match path with
        | p when p.IsEmpty || p |> List.exists (fun x -> x.Length = 0) -> Error $"{source}: empty key"
        | "modules" :: _ -> Ok()
        | top :: _ when List.contains top Config.coreFields -> Ok()
        | top :: _ -> Error $"{source}: '{top}' is not a config key"
        | [] -> Error $"{source}: empty key"

    let private collect (items: Result<Setting, string> list) =
        match
            items
            |> List.choose (fun r ->
                match r with
                | Error e -> Some e
                | Ok _ -> None)
        with
        | [] ->
            Ok
                [
                    for r in items do
                        match r with
                        | Ok s -> s
                        | Error _ -> ()
                ]
        | es -> Error es

    /// Flags as (name, value): `--fee-recipient 0x..` is the key fee_recipient, `--modules.metrics.port`
    /// a module key (dots separate levels, dashes become underscores), and `--set key=value` the
    /// same with the key in the value.
    let fromFlags (flags: (string * string) list) : Result<Setting list, string list> =
        flags
        |> List.map (fun (name, value) ->
            let key, v, source =
                if name = "set" then
                    match value.IndexOf '=' with
                    | i when i > 0 -> value.Substring(0, i), value.Substring(i + 1), $"--set {value.Substring(0, i)}"
                    | _ -> "", value, $"--set {value}"
                else
                    name, value, $"--{name}"

            let path = key.Split('.') |> Array.map (fun x -> x.Replace('-', '_')) |> List.ofArray

            check source path
            |> Result.map (fun () ->
                {
                    Path = path
                    Value = v
                    Source = source
                }))
        |> collect

    /// Environment variables: EPLIX_<KEY> for a top-level key (EPLIX_FEE_RECIPIENT), with `__`
    /// between levels (EPLIX_MODULES__METRICS__PORT). Names are case-insensitive after EPLIX_.
    let fromEnv (env: (string * string) seq) : Result<Setting list, string list> =
        env
        |> Seq.filter (fun (name, _) ->
            name.StartsWith("EPLIX_", StringComparison.Ordinal) && not (ignoredEnv.Contains name))
        |> Seq.sortBy fst
        |> Seq.map (fun (name, value) ->
            let path = name.Substring(6).ToLowerInvariant().Split("__") |> List.ofArray

            check $"environment variable {name}" path
            |> Result.map (fun () ->
                {
                    Path = path
                    Value = value
                    Source = $"environment variable {name}"
                }))
        |> List.ofSeq
        |> collect

    /// The JSON text of a setting's value: true, false, null, an array or an object stay JSON;
    /// anything else is a string (number keys accept decimal strings).
    let jsonValue (v: string) : Result<string, string> =
        let t = v.Trim()

        if t = "true" || t = "false" || t = "null" || t.StartsWith '[' || t.StartsWith '{' then
            try
                use _ = JsonDocument.Parse t
                Ok t
            with :? JsonException as e ->
                Error e.Message
        else
            Ok(Text.Encoding.UTF8.GetString(Eplix.Json.toBytes (fun w -> w.WriteStringValue v)))

    type private Node =
        | Leaf of string
        | Branch of Collections.Generic.Dictionary<string, Node>

    /// A leaf that holds a JSON object turns into a branch, so a deeper setting can go into it.
    let private asBranch (n: Node) =
        match n with
        | Branch b -> b
        | Leaf raw ->
            let b = Collections.Generic.Dictionary<string, Node>()
            use doc = JsonDocument.Parse raw

            if doc.RootElement.ValueKind = JsonValueKind.Object then
                for p in doc.RootElement.EnumerateObject() do
                    b[p.Name] <- Leaf(p.Value.GetRawText())

            b

    let rec private write (w: Utf8JsonWriter) (e: JsonElement voption) (n: Node) =
        match n with
        | Leaf raw -> w.WriteRawValue(raw, false)
        | Branch b ->
            w.WriteStartObject()

            match e with
            | ValueSome o when o.ValueKind = JsonValueKind.Object ->
                for p in o.EnumerateObject() do
                    match b.TryGetValue p.Name with
                    | true, child ->
                        w.WritePropertyName p.Name
                        write w (ValueSome p.Value) child
                    | _ -> p.WriteTo w

                for KeyValue(k, child) in b do
                    let present =
                        match o.TryGetProperty k with
                        | true, _ -> true
                        | _ -> false

                    if not present then
                        w.WritePropertyName k
                        write w ValueNone child
            | _ ->
                for KeyValue(k, child) in b do
                    w.WritePropertyName k
                    write w ValueNone child

            w.WriteEndObject()

    /// The config text with the settings applied in order (a later one wins).
    let apply (text: string) (settings: Setting list) : Result<string, string list> =
        if settings.IsEmpty then
            Ok text
        else
            let values = settings |> List.map (fun s -> s, jsonValue s.Value)

            match
                values
                |> List.choose (fun (s, r) ->
                    match r with
                    | Error e -> Some $"{s.Source}: {e}"
                    | Ok _ -> None)
            with
            | _ :: _ as es -> Error es
            | [] ->
                try
                    let top = Collections.Generic.Dictionary<string, Node>()

                    for s, r in values do
                        let raw =
                            match r with
                            | Ok x -> x
                            | Error _ -> "null"

                        let mutable level = top
                        let parts = Array.ofList s.Path

                        for i in 0 .. parts.Length - 2 do
                            let next =
                                match level.TryGetValue parts[i] with
                                | true, n -> asBranch n
                                | _ -> Collections.Generic.Dictionary<string, Node>()

                            level[parts[i]] <- Branch next
                            level <- next

                        level[parts[parts.Length - 1]] <- Leaf raw

                    use doc = JsonDocument.Parse(text, JsonDocumentOptions(CommentHandling = JsonCommentHandling.Skip))

                    Ok(
                        Text.Encoding.UTF8.GetString(
                            Eplix.Json.toBytes (fun w -> write w (ValueSome doc.RootElement) (Branch top))
                        )
                    )
                with :? JsonException as e ->
                    Error [ $"config is not valid JSON: {e.Message}" ]

    /// Reads the config file (or starts from an empty object without one), applies the settings
    /// and parses the result. Relative paths resolve against the file's directory, or the working
    /// directory without a file.
    let load
        (file: string voption)
        (settings: Setting list)
        (moduleNames: string list)
        : Result<CoreConfig, string list> =
        let read =
            match file with
            | ValueNone -> Ok("{}", Directory.GetCurrentDirectory())
            | ValueSome f ->
                let full = Path.GetFullPath f

                try
                    Ok(File.ReadAllText full, nonNull (Path.GetDirectoryName full))
                with
                | :? IOException as e -> Error [ $"config {full}: {e.Message}" ]
                | :? UnauthorizedAccessException as e -> Error [ $"config {full}: {e.Message}" ]

        match read with
        | Error es -> Error es
        | Ok(text, baseDir) ->
            match apply text settings with
            | Error es -> Error es
            | Ok merged -> Config.parse merged baseDir moduleNames
