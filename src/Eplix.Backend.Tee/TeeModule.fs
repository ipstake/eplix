/// TEE signers (tee-signer runners) as a module: Eplix talks to the runners directly, with no
/// gateway in between. Config section "tee":
///   { "runners": [ { "name": "signer-1", "address": "tcp:192.0.2.1:7100",
///                    "client_cert": "<file>", "client_key": "<file>",
///                    "tls_key_pin": "<hex>", "allow_testnet_build": false, "connections": 8,
///                    "attestation": { "verifier": "aws-nitro", "nitro_pcrs": { ... }, "setup_sha256": [ "..." ],
///                                     "key_release_sha256": [ "..." ] } } ],
///     "groups": [ { "threshold": 2, "members": [ { "runner": "signer-1", "index": 1 }, ... ] } ],
///     "keys": [ "0x..." ], "keys_file": "<file>",
///     "timeout_ms": 2000, "dial_timeout_ms": 30000, "priority_low_every": 8,
///     "refresh_interval_seconds": 384, "attestation_ca_file": "<PEM bundle>",
///     "reload_interval_seconds": 10, "rotate_within_seconds": 300, "ha_peer": false }
/// client_cert holds the client's certificate first, then any intermediates; all of them go to
/// the runner in the TLS handshake. The client certificates and attestation_ca_file reload while
/// running: every reload_interval_seconds, soon after a change in
/// their directories, and on SIGHUP. A changed client certificate redials the pool's connections
/// one at a time within rotate_within_seconds.
/// "signing" (jitter_ms, jitter_by_duty_ms) is read by the core (SigningJitter.fs).
/// ha_peer: another VC signs the same keys through the same runners (HA). A runner's "already
/// signed" refusal (SC_ERR_SLASH_TARGET, SC_ERR_SLASH_SOURCE, SC_ERR_SLASH_BLOCK,
/// SC_ERR_EQUIVOCATION) then means the peer won the duty: skipped, counted, the key keeps
/// signing. Every other slashing refusal still halts the key. The core refuses ha_peer when the
/// local, dirk or web3signer module is configured, fails the start when the local or web3signer
/// module holds a key without a section, and refuses keymanager imports.
/// A key a runner lists with its own key as the share is a whole key and signs through that
/// runner alone. A key it lists with another share key is a share of a threshold key; the
/// group the runner is a member of signs it, m of n, combined in Eplix. Only the keys named in
/// "keys" or "keys_file" are used: a runner may hold the keys of other validator clients, so a
/// config without that list fails the start. The attestation block
/// has the JSON names of the Go client's cloud.json, so one block serves both.
module Eplix.Backend.Tee.TeeModule

open System
open System.Collections.Generic
open System.IO
open System.Net.Http
open System.Net.Security
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json

let name = "tee"

/// How long the directory of a client certificate must be quiet after a change before the files
/// are read: an agent's write and rename, or a rewrite in place, come as a burst of events.
let ReloadDebounce = TimeSpan.FromMilliseconds 500.0

type RunnerConfig =
    {
        Name: string
        Host: string
        Port: int
        ClientCert: string
        ClientKey: string
        TlsKeyPin: byte[] voption
        AllowTestnetBuild: bool
        Connections: int
        Attestation: Attest.Settings
    }

type GroupConfig =
    {
        Threshold: int
        /// Runner name and share index.
        Members: (string * uint64) list
    }

/// Which of the keys the runners list Eplix signs for.
type KeyFilter =
    /// Only these keys, lower-case 0x hex. The only form the config parser yields.
    | Only of Set<string>
    /// Every listed key. For tests with fake runners only; no config can ask for it.
    | AnyListedTestOnly

type Settings =
    {
        Runners: RunnerConfig list
        Groups: GroupConfig list
        /// Per request and runner; a member's budget in a group.
        Timeout: TimeSpan
        /// Bound of one dial, from TCP to the end of the attestation check, and of the wait for a
        /// late reply.
        DialTimeout: TimeSpan
        /// 0 serves requests first come first served; otherwise every lowEvery-th free connection
        /// goes to the low class while it waits.
        LowEvery: int
        RefreshInterval: TimeSpan
        Keys: KeyFilter
        /// PEM bundle of the CAs trusted for the attestation HTTPS fetches (OIDC discovery and key
        /// sets of MAA and Confidential Space). Without it, the system store.
        AttestationCaFile: string voption
        /// How often the TLS files are read for a change; zero turns reloading off.
        ReloadInterval: TimeSpan
        /// The time within which the pool redials its connections after a client certificate
        /// changed (sooner when the old certificate expires first).
        RotateWithin: TimeSpan
        /// modules.tee.ha_peer: "already signed" refusals are lost to an HA peer, not slashable.
        HaPeer: bool
        /// Mainnet or not, from the core config: on mainnet azure-maa and aws-nitro runners need
        /// key_release_sha256.
        Network: Attest.NetworkKind
    }

let private runnerFields =
    [
        "name"
        "address"
        "client_cert"
        "client_key"
        "tls_key_pin"
        "allow_testnet_build"
        "connections"
        "attestation"
    ]

/// tcp:HOST:PORT (the Go client's form) or HOST:PORT. Unix and vsock are refused: an AWS
/// runner is reached through the plain forwarder on its parent, which TLS and the attestation
/// check make harmless.
let parseAddress (where: string) (a: string) =
    let s = if a.StartsWith "tcp:" then a.Substring 4 else a

    if s.StartsWith "unix:" || s.StartsWith "vsock:" then
        fail $"{where}: address \"{a}\" is not a tcp: address"

    let i = s.LastIndexOf ':'

    if i <= 0 then
        fail $"{where}: address \"{a}\" wants tcp:HOST:PORT"

    let host = s.Substring(0, i).Trim('[', ']')

    match Int32.TryParse(s.Substring(i + 1)) with
    | true, p when p > 0 && p < 65536 -> host, p
    | _ -> fail $"{where}: address \"{a}\" has no valid port"

/// One runner entry at `where`: in modules.tee.runners, or the runner of a Web3Signer
/// endpoint's attestation.
let parseRunnerAt (section: ConfigSection) (where: string) (e: JsonElement) : RunnerConfig =
    match checkFields e where runnerFields with
    | [] -> ()
    | errors -> fail (String.Join("; ", errors))

    let host, port = parseAddress where (strField e "address")

    let pin =
        match tryProp e "tls_key_pin" with
        | ValueSome v ->
            let h = (str v).ToLowerInvariant()
            let h = if h.StartsWith "0x" then h.Substring 2 else h

            if h.Length <> 64 || not (h |> Seq.forall Char.IsAsciiHexDigit) then
                fail $"{where}: tls_key_pin: want 64 hex digits, the sha256 of the runner's TLS key"

            ValueSome(Convert.FromHexString h)
        | ValueNone -> ValueNone

    let connections =
        match tryProp e "connections" with
        | ValueSome v -> boundedInt $"{where}.connections" 1 64 v
        | ValueNone -> 8

    let allowTestnet =
        match tryProp e "allow_testnet_build" with
        | ValueSome _ -> boolField e "allow_testnet_build"
        | ValueNone -> false
    // A testnet build has governance time locks in minutes.
    if allowTestnet && section.Mainnet then
        fail $"{where}.allow_testnet_build: a testnet build is for test networks; not on mainnet"

    let att =
        match Attest.parseSettings section.Path (prop e "attestation") with
        | Ok a -> a
        | Error m -> fail $"{where}: {m}"

    {
        Name =
            (match tryProp e "name" with
             | ValueSome v -> str v
             | ValueNone -> $"{host}:{port}")
        Host = host
        Port = port
        ClientCert = section.Path(strField e "client_cert")
        ClientKey = section.Path(strField e "client_key")
        TlsKeyPin = pin
        AllowTestnetBuild = allowTestnet
        Connections = connections
        Attestation = att
    }

let private parseRunner (section: ConfigSection) (i: int) (e: JsonElement) : RunnerConfig =
    parseRunnerAt section $"modules.tee.runners[{i}]" e

let private parseGroup (runners: RunnerConfig list) (i: int) (e: JsonElement) : GroupConfig =
    let where = $"modules.tee.groups[{i}]"

    match checkFields e where [ "threshold"; "members" ] with
    | [] -> ()
    | errors -> fail (String.Join("; ", errors))

    let members =
        array (prop e "members")
        |> Array.mapi (fun j m ->
            let w = $"{where}.members[{j}]"

            match checkFields m w [ "runner"; "index" ] with
            | [] -> ()
            | errors -> fail (String.Join("; ", errors))

            let r = strField m "runner"

            if not (runners |> List.exists (fun x -> x.Name = r)) then
                fail $"{w}: no runner named \"{r}\""

            let index = u64Field m "index"

            if index = 0UL then
                fail $"{w}: index must be 1 or more"

            r, index)
        |> List.ofArray

    if members.IsEmpty then
        fail $"{where}: no members"

    if (members |> List.distinctBy snd).Length <> members.Length then
        fail $"{where}: member indices must differ"

    if (members |> List.distinctBy fst).Length <> members.Length then
        fail $"{where}: a runner is a member twice"
    // Bounded before the cast: 2^32 + 1 is 1 as an int.
    let threshold = boundedInt $"{where}.threshold" 1 members.Length (prop e "threshold")

    match Threshold.checkSize threshold members.Length with
    | Ok() -> ()
    | Error m -> fail $"{where}.threshold: {m}"

    {
        Threshold = threshold
        Members = members
    }

/// One validator key as the allowlist holds it: lower-case 0x hex of 48 bytes.
let private allowKey (where: string) (s: string) =
    match PubKey.TryParse(s.Trim()) with
    | ValueSome k -> k.Hex.ToLowerInvariant()
    | ValueNone -> fail $"{where}: \"{s}\" is not a validator public key (0x and 96 hex digits)"

/// The keys of "keys" (an array) and "keys_file" (one key per line, # starts a comment).
/// Both may be given; together they must name at least one key.
let private parseKeys (section: ConfigSection) (e: JsonElement) : Set<string> =
    let inline_ =
        match tryProp e "keys" with
        | ValueSome v -> array v |> Array.mapi (fun i k -> allowKey $"modules.tee.keys[{i}]" (str k)) |> List.ofArray
        | ValueNone -> []

    let fromFile =
        match tryProp e "keys_file" with
        | ValueSome v ->
            let f = section.Path(str v)

            let lines =
                try
                    File.ReadAllLines f
                with :? IOException as x ->
                    fail $"modules.tee.keys_file: {x.Message}"

            [
                for i, l in Array.indexed lines do
                    let t =
                        (match l.IndexOf '#' with
                         | -1 -> l
                         | j -> l.Substring(0, j))
                            .Trim()

                    if t <> "" then
                        allowKey $"modules.tee.keys_file line {i + 1}" t
            ]
        | ValueNone -> []

    let all = Set.ofList (inline_ @ fromFile)

    if all.IsEmpty then
        fail
            "modules.tee: no keys; list the validator keys this VC signs for in \"keys\" or \"keys_file\" (the runners may hold other clients' keys)"

    all

let parseSettings (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Error [ "the tee module is linked but has no config section (modules.tee)" ]
    | ValueSome e ->
        let errors =
            checkFields
                e
                "modules.tee"
                [
                    "runners"
                    "groups"
                    "timeout_ms"
                    "dial_timeout_ms"
                    "priority_low_every"
                    "refresh_interval_seconds"
                    "keys"
                    "keys_file"
                    "attestation_ca_file"
                    "reload_interval_seconds"
                    "rotate_within_seconds"
                    "signing"
                    "ha_peer"
                ]

        if not errors.IsEmpty then
            Error errors
        else
            try
                let runners = array (prop e "runners") |> Array.mapi (parseRunner section) |> List.ofArray

                if runners.IsEmpty then
                    fail "modules.tee: no runners"

                if (runners |> List.distinctBy (fun r -> r.Name)).Length <> runners.Length then
                    fail "modules.tee: runner names must differ"

                let groups =
                    match tryProp e "groups" with
                    | ValueSome a -> array a |> Array.mapi (parseGroup runners) |> List.ofArray
                    | ValueNone -> []
                // A runner's share keys name no group, so each runner is in one group at most.
                let inGroups = groups |> List.collect (fun g -> g.Members |> List.map fst)

                if (List.distinct inGroups).Length <> inGroups.Length then
                    fail
                        "modules.tee: a runner is a member of two groups; this build routes a runner's shares to one group"

                let ms field (dflt: float) lo hi =
                    match tryProp e field with
                    | ValueSome v -> boundedMs $"modules.tee.{field}" lo hi v
                    | ValueNone -> TimeSpan.FromMilliseconds dflt

                let lowEvery =
                    match tryProp e "priority_low_every" with
                    | ValueSome v ->
                        let n =
                            try
                                boundedInt "modules.tee.priority_low_every" 0 1000 v
                            with :? JsonDecodeError ->
                                1

                        if n = 1 then
                            fail "modules.tee.priority_low_every must be 0 (no priority) or between 2 and 1000"

                        n
                    | ValueNone -> 8

                let keys = parseKeys section e
                let seconds field = tryProp e field |> ValueOption.map u64

                let reload =
                    match TlsFiles.reloadInterval (seconds "reload_interval_seconds") with
                    | Ok t -> t
                    | Error m -> fail $"modules.tee.{m}"

                let rotate =
                    match TlsFiles.rotateWithin (seconds "rotate_within_seconds") with
                    | Ok t -> t
                    | Error m -> fail $"modules.tee.{m}"

                Ok
                    {
                        Runners = runners
                        Groups = groups
                        Timeout = ms "timeout_ms" 2000.0 1UL 60_000UL
                        DialTimeout = ms "dial_timeout_ms" 30_000.0 100UL 600_000UL
                        LowEvery = lowEvery
                        RefreshInterval =
                            match tryProp e "refresh_interval_seconds" with
                            // 0 turns the refresh off.
                            | ValueSome v -> boundedSeconds "modules.tee.refresh_interval_seconds" 0UL Bounds.Day v
                            | ValueNone -> TimeSpan.FromSeconds 384.0
                        Keys = Only keys
                        AttestationCaFile =
                            match tryProp e "attestation_ca_file" with
                            | ValueSome v ->
                                let f = str v

                                if f = "" then
                                    fail "modules.tee.attestation_ca_file: empty path"

                                ValueSome(section.Path f)
                            | ValueNone -> ValueNone
                        ReloadInterval = reload
                        RotateWithin = rotate
                        HaPeer =
                            (match tryProp e "ha_peer" with
                             | ValueSome _ -> boolField e "ha_peer"
                             | ValueNone -> false)
                        Network = if section.Mainnet then Attest.NetworkKind.Mainnet else Attest.NetworkKind.Testnet
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.tee: {x.Message}" ]

/// The client certificate with its key (PEM) and the certificates after it in the same file,
/// the intermediates up to the root, reloaded while running (TlsFiles.client). The first
/// certificate in `client_cert` is the client's. TLS sends the client's certificate and the
/// intermediates, so a runner that trusts only the root CA can build the chain. Refused when the
/// certificate or an intermediate has expired.
let clientCertFile
    (r: RunnerConfig)
    (log: Log)
    (time: TimeProvider)
    : Result<TlsFile<SslStreamCertificateContext>, string> =
    TlsFiles.client name $"{r.Name}/client_cert" r.ClientCert r.ClientKey log time
    |> Result.mapError (fun e -> $"{r.Name}: client_cert and client_key: {e}")

/// The client certificate in force now (clientCertFile without the reload).
let loadClientCert (r: RunnerConfig) : Result<SslStreamCertificateContext, string> =
    clientCertFile r Log.none TimeProvider.System |> Result.map (fun f -> f.Current.Value)

/// The CAs of a PEM bundle, reloaded while running; a file with none is an error.
let caBundleFile (file: string) (log: Log) (time: TimeProvider) : Result<TlsFile<X509Certificate2Collection>, string> =
    TlsFiles.ca name "attestation_ca_file" file log time
    |> Result.mapError (fun e -> $"attestation_ca_file {e}")

/// The CAs of a PEM bundle; a file with none is an error.
let loadCaBundle (file: string) : Result<X509Certificate2Collection, string> =
    caBundleFile file Log.none TimeProvider.System |> Result.map (fun f -> f.Current.Value)

/// Accepts a server certificate that names the host and chains to one of the CAs in force at
/// the handshake (`cas`, a reloaded bundle), with the intermediates the server sent. The system
/// store is not consulted.
let validateWith (cas: unit -> X509Certificate2Collection) =
    Net.Security.RemoteCertificateValidationCallback(fun _ cert chain errors ->
        match cert with
        | null -> false
        | _ when
            errors
            &&& (Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch
                 ||| Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable)
            <> Net.Security.SslPolicyErrors.None
            ->
            false
        | cert ->
            use c = new X509Chain()
            c.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust
            c.ChainPolicy.CustomTrustStore.AddRange(cas ())
            c.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck
            // serverAuth: a client-only certificate from a bundle CA is not a key server.
            c.ChainPolicy.ApplicationPolicy.Add(Oid "1.3.6.1.5.5.7.3.1") |> ignore

            match chain with
            | null -> ()
            | chain ->
                c.ChainPolicy.ExtraStore.AddRange chain.ChainPolicy.ExtraStore

                for el in chain.ChainElements do
                    c.ChainPolicy.ExtraStore.Add el.Certificate |> ignore

            use leaf = new X509Certificate2(cert)
            c.Build leaf)

/// validateWith over a fixed bundle.
let validateWithBundle (cas: X509Certificate2Collection) = validateWith (fun () -> cas)

/// The HTTP client of the attestation fetches: the system store, or only the CAs of the bundle
/// in force at each handshake. It follows no redirect: a key set comes only from the URL the
/// issuer names.
let attestationHttpWith (bundle: (unit -> X509Certificate2Collection) voption) =
    let handler = new SocketsHttpHandler(AllowAutoRedirect = false)

    match bundle with
    | ValueNone -> ()
    | ValueSome cas -> handler.SslOptions.RemoteCertificateValidationCallback <- validateWith cas

    new HttpClient(handler, Timeout = TimeSpan.FromSeconds 15.0)

/// attestationHttpWith over a fixed bundle.
let attestationHttp (bundle: X509Certificate2Collection voption) =
    attestationHttpWith (bundle |> ValueOption.map (fun cas -> fun () -> cas))

/// Key sets of MAA and Confidential Space issuers, one cache per issuer, fetched over HTTPS.
let discoveredKeysWith (http: HttpClient) =
    let cache = Dictionary<string, Attest.KeySource>()

    fun (what: string) (issuer: string) ->
        lock cache (fun () ->
            match cache.TryGetValue issuer with
            | true, k -> k
            | _ ->
                let k = Attest.DiscoveredKeys(what, issuer, http) :> Attest.KeySource
                cache[issuer] <- k
                k)

/// The key sources of a config, and the CA bundle's file to reload. The bundle loads here, so a
/// bad file fails the start.
let discoveredKeysReloading (s: Settings) (log: Log) (time: TimeProvider) =
    match s.AttestationCaFile with
    | ValueNone -> Ok(discoveredKeysWith (attestationHttp ValueNone), ValueNone)
    | ValueSome f ->
        caBundleFile f log time
        |> Result.map (fun cas ->
            discoveredKeysWith (attestationHttpWith (ValueSome(fun () -> cas.Current.Value))), ValueSome cas)

/// The key sources of a config. The CA bundle loads here, so a bad file fails the start.
let discoveredKeys (s: Settings) = discoveredKeysReloading s Log.none TimeProvider.System |> Result.map fst

/// Every runner, whole-key backend and threshold group of the config.
type TeeSet(runners: (RunnerConfig * RunnerApi) list, settings: Settings, time: TimeProvider, log: Log) =
    let endpoints = [ for cfg, api in runners -> cfg.Name, RunnerEndpoint(api, log) ] |> Map.ofList

    do
        for KeyValue(_, x) in endpoints do
            x.HaPeer <- settings.HaPeer

    let wholeKey = [ for KeyValue(n, x) in endpoints -> x, x.WholeKeys $"tee {n}" ]
    let mutable lastAnswers: MemberAnswer list = []
    let mutable refused: (PubKey * string) list = []
    let shareChecks = Threshold.ShareChecks()

    let groups =
        [
            for g in settings.Groups ->
                let n = g.Members.Length
                let groupName = $"""tee {g.Threshold} of {n} ({String.Join(",", g.Members |> List.map fst)})"""

                let members =
                    [
                        for runner, index in g.Members ->
                            let x = endpoints[runner]

                            {
                                Backend = x.Shares $"tee {runner} share {index}" index
                                Index = index
                                Budget = settings.Timeout
                            }
                    ]

                g, Threshold.create groupName g.Threshold members time log
        ]

    let groupArray = Array.ofList groups

    member _.Endpoints = endpoints |> Map.toList |> List.map snd

    /// What each runner answered at the last Discover: every validator key it listed (whole or
    /// share, allowed or not), or nothing when the call failed. A failed runner keeps its old
    /// list for signing, but its answer here is a failure.
    member _.LastAnswers = lastAnswers

    /// The threshold keys the last Discover left out because their share keys are not one
    /// split of the key, with the reason. The module refuses them in the registry.
    member _.Refused = refused

    /// The share checks of the threshold keys, cached across refreshes.
    member _.ShareChecks = shareChecks

    /// Reads every runner's key list, then returns each key with its backend and how many
    /// runners answered. A threshold key whose shares are not one split of it is left out. A key
    /// whole on a runner and split in a group comes once with each route, so the registry
    /// refuses it.
    member _.Discover(ct: CancellationToken) : Task<(PubKey * Backend) list * int> =
        task {
            let all = endpoints |> Map.toList
            // The call may wait for a dial first (TCP to the end of the attestation check).
            let deadline = settings.DialTimeout + ListedKeys.ListDeadline

            let! results =
                all
                |> List.map (fun (_, x) -> ListedKeys.WithDeadline(time, deadline, ct, x.Refresh))
                |> Task.WhenAll

            let mutable answered = 0
            let answers = ResizeArray<MemberAnswer>()

            for (n, x), r in Seq.zip all results do
                match r with
                | Ok _ ->
                    answered <- answered + 1

                    answers.Add
                        {
                            Member = n
                            Keys = ValueSome(x.Listed |> List.map (fun k -> k.PubKey) :> IReadOnlyCollection<_>)
                        }
                | Error f ->
                    log.Warn $"tee {n}: listing keys failed: {(Failed f).Describe}"
                    answers.Add { Member = n; Keys = ValueNone }

            lastAnswers <- List.ofSeq answers
            let out = ResizeArray<PubKey * Backend>()

            let allowed (k: PubKey) =
                match settings.Keys with
                | Only s -> s.Contains(k.Hex.ToLowerInvariant())
                | AnyListedTestOnly -> true

            let skipped = HashSet<string>()
            let offSplit = ResizeArray<PubKey * string>()

            for x, backend in wholeKey do
                for k in x.Listed do
                    if k.SharePubKey = k.PubKey then
                        if allowed k.PubKey then out.Add(k.PubKey, backend) else skipped.Add k.PubKey.Hex |> ignore
            // Every group key first, then their checks in one call (in parallel when many need
            // one), then the routes in the same order.
            let groupKeys = ResizeArray<struct (int * PubKey)>()

            for gi in 0 .. groupArray.Length - 1 do
                let _, backend = groupArray[gi]
                let! keys = backend.Keys ct

                for k in keys do
                    if allowed k.Key then groupKeys.Add(struct (gi, k.Key)) else skipped.Add k.Key.Hex |> ignore

            let item i =
                let struct (gi, key) = groupKeys[i]
                let g, _ = groupArray[gi]

                let shares =
                    [
                        for runner, index in g.Members do
                            match endpoints[runner].TryGet key with
                            | ValueSome rk when rk.SharePubKey <> rk.PubKey -> index, rk.SharePubKey
                            | _ -> ()
                    ]

                struct (g.Threshold, key, shares)

            let results = shareChecks.CheckAll(groupKeys.Count, item, ct)

            for i in 0 .. results.Length - 1 do
                let struct (gi, key) = groupKeys[i]
                let _, backend = groupArray[gi]

                match results[i] with
                | Ok() -> out.Add(key, backend)
                | Error why -> offSplit.Add(key, $"{backend.Name}: {why}")

            shareChecks.Sweep()
            refused <- List.ofSeq offSplit
            let inGroup = settings.Groups |> List.collect (fun g -> g.Members |> List.map fst) |> set

            for KeyValue(n, x) in endpoints do
                if not (inGroup.Contains n) then
                    let shares = x.Listed |> List.filter (fun k -> k.SharePubKey <> k.PubKey) |> List.length

                    if shares > 0 then
                        log.Warn $"tee {n}: lists {shares} share keys but is in no group; they are not used"

            if skipped.Count > 0 then
                log.Debug $"tee: {skipped.Count} listed keys are not in modules.tee.keys; not used"

            return (out |> Seq.distinctBy (fun (k, b) -> struct (k, Threshold.isGroup b)) |> List.ofSeq), answered
        }

    member _.Stop() =
        for KeyValue(_, x) in endpoints do
            x.Close()

/// The pins of a runner for `eplix check`, the hashes lower case without 0x.
let describePins (r: RunnerConfig) =
    let hashes (xs: string list) =
        match xs with
        | [] -> "not pinned"
        | xs ->
            let norm (x: string) =
                let x = x.ToLowerInvariant()
                if x.StartsWith "0x" then x.Substring 2 else x

            String.Join(" or ", xs |> List.map norm)

    $"{r.Name} ({r.Attestation.Verifier}): setup_sha256 {hashes r.Attestation.SetupSha256}; key_release_sha256 {hashes r.Attestation.KeyReleaseSha256}"

/// Builds the verifier and the client certificate of every runner, or the first error.
let prepare
    (s: Settings)
    (log: Log)
    (time: TimeProvider)
    (keys: string -> string -> Attest.KeySource)
    : Result<(RunnerConfig * RunnerSettings) list, string> =
    let rec go acc (rest: RunnerConfig list) =
        match rest with
        | [] -> Ok(List.rev acc)
        | r :: tail ->
            match Attest.buildUsable s.Network r.Attestation keys [] with
            | Error m -> Error $"{r.Name}: {m}"
            | Ok v ->
                match clientCertFile r log time with
                | Error m -> Error m
                | Ok cert ->
                    let rs =
                        {
                            Name = r.Name
                            Host = r.Host
                            Port = r.Port
                            ClientCert = cert
                            TlsKeyPin = r.TlsKeyPin
                            AllowTestnetBuild = r.AllowTestnetBuild
                            Verifier = v
                        }

                    go ((r, rs) :: acc) tail

    go [] s.Runners

/// One pool per runner, dialing at once.
let connect
    (s: Settings)
    (prepared: (RunnerConfig * RunnerSettings) list)
    (log: Log)
    : (RunnerConfig * RunnerApi) list =
    [
        for r, rs in prepared ->
            let dial ct = RunnerConnection.Dial(rs, (fun () -> DateTimeOffset.UtcNow), ct)

            let pool =
                new ConnectionPool<RunnerConnection>(
                    $"tee {r.Name}",
                    r.Connections,
                    s.LowEvery,
                    s.DialTimeout,
                    dial,
                    log
                )
            // A new client certificate: redial the connections made under an older one, within
            // rotate_within_seconds and before the old certificate expires.
            rs.ClientCert.Swapped.Add(fun (old, next) ->
                let deadline = min (DateTimeOffset.UtcNow + s.RotateWithin) old.NotAfter
                pool.Rotate((fun c -> c.CertGeneration < next.Generation), deadline))

            pool.Start()
            r, RunnerApi.ofPool pool
    ]

/// The `runner` attestation source of a Web3Signer endpoint: a dial over
/// the runner protocol as the pool makes one (TLS 1.3 with the client certificate, the TLS key
/// pin, IDENTITY with a fresh nonce, the attestation document, the setup and key release pins),
/// then closed. The TLS key the attested identity names is the one the endpoint may present: a
/// single-node signer serves its runner port and its Web3Signer port with one TLS key.
type RunnerAttestation(rs: RunnerSettings, dialTimeout: TimeSpan, caFile: TlsFile<X509Certificate2Collection> voption) =
    /// A failed check refuses, and so does an answer that does not decode (a peer that passed
    /// TLS sent it). A runner that does not answer, or an attestation key set that cannot be
    /// fetched, leaves the last keys for a while.
    static let rec refused (e: exn) =
        match e with
        | :? Attest.KeySetUnavailable -> false
        | :? Jwt.AttestError
        | :? Security.Authentication.AuthenticationException
        | :? InvalidDataException
        | :? Wire.WireError
        | :? Cbor.CborError
        | :? Text.DecoderFallbackException -> true
        | e ->
            match e.InnerException with
            | null -> false
            | inner -> refused inner

    /// Whether a failed dial refuses the endpoint (true) or leaves it unavailable (false).
    static member IsRefusal(e: exn) = refused e

    interface AttestationSource with
        member _.Describe = $"runner {rs.Name} at {rs.Host}:{rs.Port}"

        member _.Files =
            [
                yield rs.ClientCert :> TlsCheck
                match caFile with
                | ValueSome f -> yield f :> TlsCheck
                | ValueNone -> ()
            ]

        member _.Attest(ct: CancellationToken) =
            task {
                use cts = CancellationTokenSource.CreateLinkedTokenSource ct
                cts.CancelAfter dialTimeout

                try
                    let! c = RunnerConnection.Dial(rs, (fun () -> DateTimeOffset.UtcNow), cts.Token)
                    let key = c.Identity.TlsKeyHash
                    c.Close()
                    return AttestationResult.Attested [ key ]
                with e ->
                    return
                        if refused e then
                            AttestationResult.Refused e.Message
                        else
                            AttestationResult.Unavailable e.Message
            }

let private runnerSourceFields =
    [ "source"; "refresh_interval_seconds"; "runner"; "attestation_ca_file" ]

/// The runner entry of a `runner` source and its attestation_ca_file (the CAs of the MAA and
/// Confidential Space key fetches, as modules.tee.attestation_ca_file), resolved to a path.
let private runnerOfBlock
    (section: ConfigSection)
    (where: string)
    (e: JsonElement)
    : Result<RunnerConfig * string voption, string> =
    try
        match checkFields e where runnerSourceFields with
        | [] -> ()
        | errors -> fail (String.Join("; ", errors))

        let caFile =
            match tryProp e "attestation_ca_file" with
            | ValueSome v ->
                let f = str v

                if f = "" then
                    fail $"{where}.attestation_ca_file: empty path"

                ValueSome(section.Path f)
            | ValueNone -> ValueNone

        match tryProp e "runner" with
        | ValueSome r -> Ok(parseRunnerAt section $"{where}.runner" r, caFile)
        | ValueNone -> Error $"{where}: the runner source needs \"runner\", a runner entry as in modules.tee.runners"
    with :? JsonDecodeError as x ->
        Error x.Message

let private networkOf (section: ConfigSection) =
    if section.Mainnet then Attest.NetworkKind.Mainnet else Attest.NetworkKind.Testnet

/// The `runner` source kind; the module registers it when it is created.
let runnerAttestationKind: AttestationSourceKind =
    {
        Name = "runner"
        Check =
            fun section where e ->
                runnerOfBlock section where e
                |> Result.bind (fun (r, _) ->
                    Attest.buildUsable
                        (networkOf section)
                        r.Attestation
                        (discoveredKeysWith (attestationHttp ValueNone))
                        []
                    |> Result.map ignore
                    |> Result.mapError (fun m -> $"{where}.runner: {m}"))
        Build =
            fun b ->
                let caFileOf (f: string voption) =
                    match f with
                    | ValueNone -> Ok ValueNone
                    | ValueSome f -> caBundleFile f b.Log b.Time |> Result.map ValueSome

                match runnerOfBlock b.Section b.Endpoint b.Block with
                | Error m -> Error m
                | Ok(r, caPath) ->
                    // The bundle loads here, so a bad file fails the start; it reloads while running.
                    match caFileOf caPath with
                    | Error m -> Error $"{b.Endpoint}: {m}"
                    | Ok caFile ->
                        let http =
                            attestationHttpWith (caFile |> ValueOption.map (fun cas -> fun () -> cas.Current.Value))

                        match Attest.buildUsable (networkOf b.Section) r.Attestation (discoveredKeysWith http) [] with
                        | Error m -> Error $"{b.Endpoint}: runner {r.Name}: {m}"
                        | Ok verifier ->
                            match clientCertFile r b.Log b.Time with
                            | Error m -> Error $"{b.Endpoint}: {m}"
                            | Ok cert ->
                                let rs =
                                    {
                                        Name = r.Name
                                        Host = r.Host
                                        Port = r.Port
                                        ClientCert = cert
                                        TlsKeyPin = r.TlsKeyPin
                                        AllowTestnetBuild = r.AllowTestnetBuild
                                        Verifier = verifier
                                    }

                                Ok(RunnerAttestation(rs, TimeSpan.FromSeconds 30.0, caFile) :> AttestationSource)
    }

let create () : Module =
    AttestationSources.register runnerAttestationKind
    let settings = ref ValueNone

    {
        Name = name
        Configure =
            fun section ->
                match section.Element with
                | ValueNone ->
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
                    match discoveredKeys s |> Result.bind (prepare s Log.none TimeProvider.System) with
                    | Ok rs ->
                        let verifiers = rs |> List.map (fun (_, x) -> x.Verifier.Name) |> List.distinct
                        let pins = [ for r, _ in rs -> "\n  " + describePins r ]
                        let peer = if s.HaPeer then ", ha_peer on" else ""

                        Ok
                            $"""{rs.Length} runners ({String.Join(", ", verifiers)}), {s.Groups.Length} groups{peer}, client certificates load{String.Concat pins}"""
                    | Error e -> Error [ e ]
        Start =
            fun core ct ->
                task {
                    match settings.Value with
                    | ValueNone -> return Ok { Stop = fun () -> Task.CompletedTask }
                    | ValueSome s ->
                        let time = core.Clock.Time

                        match
                            discoveredKeysReloading s core.Log time
                            |> Result.bind (fun (keys, ca) ->
                                prepare s core.Log time keys |> Result.map (fun p -> p, ca))
                        with
                        | Error e -> return Error e
                        | Ok(prepared, ca) ->
                            let set = TeeSet(connect s prepared core.Log, s, core.Clock.Time, core.Log)
                            // HEALTH: at each new connection, now, and each epoch,
                            // all in the background.
                            let clock = core.Clock

                            for x in set.Endpoints do
                                x.EpochNow <- fun () -> clock.CurrentSlot |> ValueOption.map clock.EpochOf
                                x.PollInBackground()

                            core.OnEpoch(fun epoch _ ->
                                for x in set.Endpoints do
                                    x.OnEpoch epoch

                                Task.CompletedTask)

                            let keys = ListedKeys(name, core.Registry, core.Pipeline, core.Log)
                            let! found, answered = set.Discover ct
                            keys.Refuse set.Refused
                            let added = keys.Register found
                            let! _ = keys.Retire(set.LastAnswers, (fun _ -> true), ct)
                            core.Log.Info $"tee: {answered} of {set.Endpoints.Length} runners answered, {added} keys"

                            if s.HaPeer then
                                core.Log.Info Mapping.haPeerStartLine

                            let stopper = new CancellationTokenSource()
                            let stopToken = stopper.Token
                            // The client certificates and the CA bundle: read every reload interval, on
                            // a change in their directories and on SIGHUP. A swap
                            // only redials the pool; no start-up check runs again.
                            let tlsFiles =
                                [ for _, rs in prepared -> rs.ClientCert :> TlsCheck, rs.ClientCert.Paths ]
                                @ (match ca with
                                   | ValueSome f -> [ f :> TlsCheck, f.Paths ]
                                   | ValueNone -> [])

                            let reloader =
                                TlsReloader(
                                    name,
                                    List.map fst tlsFiles,
                                    List.collect snd tlsFiles,
                                    s.ReloadInterval,
                                    ReloadDebounce,
                                    core.Log,
                                    time
                                )
                                    .Run(stopToken)
                            // An unknown key asks for a refresh of the key list now.
                            let early = new SemaphoreSlim(0, 1)

                            for x in set.Endpoints do
                                x.UnknownKey.Add(fun () ->
                                    try
                                        early.Release() |> ignore
                                    with :? SemaphoreFullException ->
                                        ())

                            let refresher =
                                if s.RefreshInterval > TimeSpan.Zero then
                                    task {
                                        use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stopToken)
                                        let mutable lastAnswered = answered

                                        try
                                            while not linked.IsCancellationRequested do
                                                // Until every runner answers, try again every 12 s.
                                                let wait =
                                                    if lastAnswered < set.Endpoints.Length then
                                                        min s.RefreshInterval (TimeSpan.FromSeconds 12.0)
                                                    else
                                                        s.RefreshInterval

                                                let timer = Task.Delay(wait, core.Clock.Time, linked.Token)
                                                let! _ = Task.WhenAny(timer, early.WaitAsync(linked.Token))
                                                linked.Token.ThrowIfCancellationRequested()

                                                try
                                                    let! found, n = set.Discover linked.Token
                                                    keys.Refuse set.Refused
                                                    lastAnswered <- n
                                                    let added = keys.Register found
                                                    let! _ = keys.Retire(set.LastAnswers, (fun _ -> true), linked.Token)

                                                    if added > 0 then
                                                        core.Log.Info $"tee: {added} new keys"
                                                        do! core.RefreshKeys linked.Token
                                                with
                                                | :? OperationCanceledException -> ()
                                                | e -> core.Log.Warn $"tee: key list refresh failed: {e.Message}"
                                                // At most one early refresh per 12 s.
                                                do! Task.Delay(TimeSpan.FromSeconds 12.0, core.Clock.Time, linked.Token)
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
