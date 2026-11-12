/// The Web3Signer backend as a module. Config section "web3signer":
///   { "signers": [ { "url": "https://w3s:9000", "ca_cert": "<file>",
///                    "client_cert": "<file>", "client_key": "<file>" } ],
///     "groups": [ { "threshold": 2,
///                   "members": [ { "index": 1, "url": "https://w3s-1:9000", ... }, ... ],
///                   "keys": [ { "pubkey": "0x..", "shares": { "1": "0x..", "2": "0x..", "3": "0x.." } } ],
///                   "keys_file": "<file with the same array>" } ],
///     "timeout_ms": 2000, "max_connections": 64, "refresh_interval_seconds": 384,
///     "reload_interval_seconds": 10 }
/// An endpoint may add "attestation": the TLS keys it may present
/// are attested before it gets a request, by
///   { "source": "pinned", "tls_key_pin": "<hex>" or [ ... ] }, or
///   { "source": "runner", "refresh_interval_seconds": 384,
///     "runner": { <a modules.tee runner entry: address, client_cert, client_key, tls_key_pin,
///                 allow_testnet_build, attestation> },
///     "attestation_ca_file": "<PEM bundle>" }   (needs the tee module in the build)
/// attestation_ca_file is optional: the CAs of the MAA and Confidential Space key fetches, as
/// modules.tee.attestation_ca_file; without it the system store checks them.
/// A signer holds whole keys: every key it lists signs through it. A group is m of n endpoints
/// that each hold one share of the listed validator keys (Web3Signer instances of a Charon-style
/// cluster); Eplix asks all n and combines m partials. TLS fields are optional per endpoint.
/// One URL is one endpoint: a URL listed more than once needs the same TLS files and attestation
/// block in every entry.
/// The keymanager API adds more whole keys at run time (/eth/v1/remotekeys), each with its
/// signer URL; they persist in <data_dir>/remote-keys.json. The module offers that API also
/// without a config section.
module Eplix.Backend.Web3Signer.Web3SignerModule

open System
open System.Collections.Generic
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json

let name = "web3signer"

type GroupKey =
    {
        PubKey: PubKey
        /// Share key per member index.
        Shares: Map<uint64, PubKey>
    }

type GroupSettings =
    {
        Threshold: int
        Members: (uint64 * EndpointSettings) list
        Keys: GroupKey list
    }

type Settings =
    {
        Signers: EndpointSettings list
        Groups: GroupSettings list
        /// Per request and endpoint; a member's budget in a group.
        Timeout: TimeSpan
        MaxConnections: int
        /// 0 turns the key list refresh off.
        RefreshInterval: TimeSpan
        /// How often the TLS files are read for a change; zero turns it off.
        ReloadInterval: TimeSpan
    }

let private endpointFields = [ "url"; "ca_cert"; "client_cert"; "client_key"; "attestation" ]

/// 64 hex digits, the SHA-256 of a TLS key's SubjectPublicKeyInfo.
let private keyHash (where: string) (s: string) =
    let h = s.ToLowerInvariant()
    let h = if h.StartsWith "0x" then h.Substring 2 else h

    if h.Length <> 64 || not (h |> Seq.forall Char.IsAsciiHexDigit) then
        fail $"{where}: want 64 hex digits, the sha256 of the server's TLS key (SubjectPublicKeyInfo)"

    Convert.FromHexString h

/// The `attestation` block of an endpoint.
let private parseAttestation (section: ConfigSection) (where: string) (e: JsonElement) : AttestationSettings =
    let where = $"{where}.attestation"

    if e.ValueKind <> JsonValueKind.Object then
        fail $"{where}: want an object with \"source\""

    let source =
        match tryProp e "source" with
        | ValueSome v -> str v
        | ValueNone -> fail $"{where}: \"source\" is required"

    let refresh =
        match tryProp e "refresh_interval_seconds" with
        | ValueSome v -> boundedSeconds $"{where}.refresh_interval_seconds" 1UL Bounds.Day v
        | ValueNone -> TimeSpan.FromSeconds 384.0

    let pins =
        match source with
        | "pinned" ->
            match checkFields e where [ "source"; "tls_key_pin"; "refresh_interval_seconds" ] with
            | [] -> ()
            | errors -> fail (String.Join("; ", errors))

            let pins =
                match tryProp e "tls_key_pin" with
                | ValueSome v when v.ValueKind = JsonValueKind.String -> [ keyHash $"{where}.tls_key_pin" (str v) ]
                | ValueSome v ->
                    array v |> Array.mapi (fun i x -> keyHash $"{where}.tls_key_pin[{i}]" (str x)) |> List.ofArray
                | ValueNone -> fail $"{where}: the pinned source needs tls_key_pin"

            if pins.IsEmpty then
                fail $"{where}.tls_key_pin: empty"

            pins
        | "http" ->
            fail
                $"{where}: the http source waits for tee-signer's evidence format and is not built yet; use runner or pinned"
        | other ->
            match AttestationSources.tryFind other with
            | ValueSome k ->
                match k.Check section where e with
                | Ok() -> []
                | Error m -> fail m
            | ValueNone when other = "runner" ->
                fail $"{where}: the runner source needs the tee module, which this build leaves out"
            | ValueNone -> fail $"{where}: source \"{other}\" is not one of pinned, runner"

    {
        Source = source
        RefreshInterval = refresh
        Pins = pins
        Block = e.Clone()
        Section = section
    }

let private parseEndpoint
    (section: ConfigSection)
    (where: string)
    (extra: string list)
    (e: JsonElement)
    : EndpointSettings =
    match checkFields e where (endpointFields @ extra) with
    | [] -> ()
    | errors -> fail (String.Join("; ", errors))

    let url =
        let u =
            try
                Uri(strField e "url", UriKind.Absolute)
            with :? UriFormatException ->
                fail $"{where}: url must be an absolute http or https URL"

        if u.Scheme <> Uri.UriSchemeHttp && u.Scheme <> Uri.UriSchemeHttps then
            fail $"{where}: url must be an absolute http or https URL"
        // Anyone on the path of a plain http signer can halt its keys with a 412.
        if u.Scheme = Uri.UriSchemeHttp && section.Mainnet then
            fail $"{where}: url must be https on mainnet"

        u

    let file field = tryProp e field |> ValueOption.map (fun v -> section.Path(str v))

    let tls =
        {
            CaCert = file "ca_cert"
            ClientCert = file "client_cert"
            ClientKey = file "client_key"
        }

    if tls.ClientCert.IsSome <> tls.ClientKey.IsSome then
        fail $"{where}: client_cert and client_key go together"

    if url.Scheme = Uri.UriSchemeHttp && (tls.CaCert.IsSome || tls.ClientCert.IsSome) then
        fail $"{where}: TLS files need an https URL"

    let attestation = tryProp e "attestation" |> ValueOption.map (parseAttestation section where)

    if attestation.IsSome && url.Scheme <> Uri.UriSchemeHttps then
        fail $"{where}: attestation needs an https URL"

    {
        Url = url
        Tls = tls
        Attestation = attestation
    }

let private parseKeys (where: string) (e: JsonElement) : GroupKey list =
    [
        for k in array e ->
            match checkFields k where [ "pubkey"; "shares" ] with
            | [] -> ()
            | errors -> fail (String.Join("; ", errors))

            let shares = prop k "shares"

            if shares.ValueKind <> JsonValueKind.Object then
                fail $"{where}: shares must map member indices to share keys"

            {
                PubKey = pubkeyField k "pubkey"
                Shares =
                    Map.ofList
                        [
                            for p in shares.EnumerateObject() ->
                                match UInt64.TryParse p.Name with
                                | true, i -> i, pubkey p.Value
                                | _ -> fail $"{where}: '{p.Name}' is not a member index"
                        ]
            }
    ]

/// Checks that every share of each key is on one split of the key, so a
/// mistyped share key or a share of another split fails the start instead of signing.
let private checkShares (where: string) (threshold: int) (keys: GroupKey list) =
    // On all cores; the first key in config order that fails names the
    // error, as a check one by one would.
    let keys = Array.ofList keys

    let results =
        Threshold.checkSharesAll
            Environment.ProcessorCount
            CancellationToken.None
            [| for k in keys -> struct (threshold, k.PubKey, Map.toList k.Shares) |]

    for i in 0 .. keys.Length - 1 do
        match results[i] with
        | Ok() -> ()
        | Error why -> fail $"{where}: the share keys of {keys[i].PubKey.Hex}: {why}"

let private parseGroup (section: ConfigSection) (i: int) (e: JsonElement) : GroupSettings =
    let where = $"modules.web3signer.groups[{i}]"

    match checkFields e where [ "threshold"; "members"; "keys"; "keys_file" ] with
    | [] -> ()
    | errors -> fail (String.Join("; ", errors))

    let members =
        array (prop e "members")
        |> Array.mapi (fun j m ->
            let w = $"{where}.members[{j}]"
            let index = u64Field m "index"

            if index = 0UL then
                fail $"{w}: index must be 1 or more"

            index, parseEndpoint section w [ "index" ] m)
        |> List.ofArray

    if members.IsEmpty then
        fail $"{where}: no members"

    if (members |> List.distinctBy fst).Length <> members.Length then
        fail $"{where}: member indices must differ"
    // Bounded before the cast: 2^32 + 1 is 1 as an int.
    let threshold = boundedInt $"{where}.threshold" 1 members.Length (prop e "threshold")

    match Threshold.checkSize threshold members.Length with
    | Ok() -> ()
    | Error m -> fail $"{where}.threshold: {m}"

    let listed =
        match tryProp e "keys" with
        | ValueSome k -> parseKeys where k
        | ValueNone -> []

    let fromFile =
        match tryProp e "keys_file" with
        | ValueSome f ->
            let path = section.Path(str f)

            let text =
                try
                    File.ReadAllText path
                with :? IOException as x ->
                    fail $"{where}: keys_file: {x.Message}"

            match decodeString (parseKeys $"{where}.keys_file") text with
            | Ok keys -> keys
            | Error m -> fail $"{where}: keys_file {path}: {m}"
        | ValueNone -> []

    let keys = listed @ fromFile
    let indices = members |> List.map fst |> set

    for k in keys do
        for KeyValue(index, _) in k.Shares do
            if not (indices.Contains index) then
                fail $"{where}: key {k.PubKey.Short} has a share for index {index}, which no member has"

    checkShares where threshold keys

    {
        Threshold = threshold
        Members = members
        Keys = keys
    }

/// The TLS files and the attestation block of an endpoint, to compare two entries. The block is
/// written back without whitespace, so only a change in its content counts.
let private endpointSetup (e: EndpointSettings) =
    let attestation =
        e.Attestation
        |> ValueOption.map (fun a ->
            use buffer = new MemoryStream()

            (use w = new Utf8JsonWriter(buffer)
             a.Block.WriteTo w)

            Text.Encoding.UTF8.GetString(buffer.ToArray()))

    e.Tls, attestation

/// Fails when one URL is listed more than once with other TLS files or another attestation
/// block. The VC keeps one endpoint per URL, built from the first entry, so the settings of a
/// later entry would be dropped without a word: an attestation check among them would not run.
let private checkRepeatedUrls (endpoints: (string * EndpointSettings) list) =
    for _, entries in endpoints |> List.groupBy (fun (_, e) -> e.Url.AbsoluteUri) do
        match entries with
        | (firstAt, first) :: rest ->
            for at, e in rest do
                if endpointSetup e <> endpointSetup first then
                    fail
                        $"{at}: url {e.Url.AbsoluteUri} is also at {firstAt} with other ca_cert, client_cert, client_key or attestation settings; one URL is one endpoint, so give every entry of it the same settings"
        | [] -> ()

let parseSettings (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone ->
        Error
            [
                "the web3signer module is linked but has no config section (modules.web3signer)"
            ]
    | ValueSome e ->
        let errors =
            checkFields
                e
                "modules.web3signer"
                [
                    "signers"
                    "groups"
                    "timeout_ms"
                    "max_connections"
                    "refresh_interval_seconds"
                    "reload_interval_seconds"
                    "signing"
                ]

        if not errors.IsEmpty then
            Error errors
        else
            try
                let signers =
                    match tryProp e "signers" with
                    | ValueSome a ->
                        array a
                        |> Array.mapi (fun i x -> parseEndpoint section $"modules.web3signer.signers[{i}]" [] x)
                        |> List.ofArray
                    | ValueNone -> []

                let groups =
                    match tryProp e "groups" with
                    | ValueSome a -> array a |> Array.mapi (parseGroup section) |> List.ofArray
                    | ValueNone -> []

                if signers.IsEmpty && groups.IsEmpty then
                    fail "neither 'signers' nor 'groups'"

                checkRepeatedUrls
                    [
                        for i, s in List.indexed signers -> $"modules.web3signer.signers[{i}]", s
                        for gi, g in List.indexed groups do
                            for j, (_, m) in List.indexed g.Members ->
                                $"modules.web3signer.groups[{gi}].members[{j}]", m
                    ]

                let timeout =
                    match tryProp e "timeout_ms" with
                    | ValueSome v -> boundedMs "timeout_ms" 1UL 60_000UL v
                    | ValueNone -> TimeSpan.FromSeconds 2.0

                let maxConnections =
                    match tryProp e "max_connections" with
                    | ValueSome v -> boundedInt "max_connections" 1 4096 v
                    | ValueNone -> 64
                // 0 turns the refresh off.
                let refresh =
                    match tryProp e "refresh_interval_seconds" with
                    | ValueSome v -> boundedSeconds "refresh_interval_seconds" 0UL Bounds.Day v
                    | ValueNone -> TimeSpan.FromSeconds 384.0

                let reload =
                    match TlsFiles.reloadInterval (tryProp e "reload_interval_seconds" |> ValueOption.map u64) with
                    | Ok t -> t
                    | Error m -> fail m

                Ok
                    {
                        Signers = signers
                        Groups = groups
                        Timeout = timeout
                        MaxConnections = maxConnections
                        RefreshInterval = refresh
                        ReloadInterval = reload
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.web3signer: {x.Message}" ]

/// Settings without signers or groups: the module linked without a config section, for keys
/// the keymanager API adds.
let apiOnly =
    {
        Signers = []
        Groups = []
        Timeout = TimeSpan.FromSeconds 2.0
        MaxConnections = 64
        RefreshInterval = TimeSpan.Zero
        ReloadInterval = TimeSpan.Zero
    }

/// Every endpoint, whole-key signer and share group of the config, and the endpoints of
/// remote keys the keymanager API added. `chain` lets each endpoint probe keys it stopped for bad
/// signatures.
type Web3SignerSet
    (connect: EndpointSettings -> SignerApi, settings: Settings, time: TimeProvider, log: Log, ?chain: ProbeChain) =
    let endpoints = Dictionary<string, SignerEndpoint>()

    let endpoint (e: EndpointSettings) =
        let id = e.Url.AbsoluteUri

        lock endpoints (fun () ->
            match endpoints.TryGetValue id with
            | true, x -> x
            | _ ->
                let api = connect e

                let x =
                    SignerEndpoint(
                        api,
                        settings.Timeout,
                        log,
                        SignatureWatch("web3signer", api.Url, log, ?chain = chain)
                    )

                endpoints[id] <- x
                x)

    let wholeKey =
        [
            for s in settings.Signers ->
                let x = endpoint s
                x, x.WholeKeys $"web3signer {x.Url}"
        ]

    let groupKeys = settings.Groups |> List.collect (fun g -> g.Keys |> List.map (fun k -> k.PubKey)) |> set
    let mutable lastAnswers: MemberAnswer list = []

    let groups =
        [
            for g in settings.Groups ->
                let n = g.Members.Length

                let groupName =
                    $"""web3signer {g.Threshold} of {n} ({String.Join(",", g.Members |> List.map (fun (_, m) -> m.Url.Authority))})"""

                let members =
                    [
                        for index, m in g.Members ->
                            let x = endpoint m

                            let shares =
                                Dictionary<PubKey, PubKey>(
                                    [
                                        for k in g.Keys do
                                            match k.Shares.TryFind index with
                                            | Some s -> KeyValuePair(k.PubKey, s)
                                            | None -> ()
                                    ]
                                )

                            {
                                Backend =
                                    x.Shares
                                        $"web3signer {x.Url} share {index}"
                                        index
                                        (shares :> IReadOnlyDictionary<_, _>)
                                Index = index
                                Budget = settings.Timeout
                            }
                    ]

                Threshold.create groupName g.Threshold members time log
        ]

    member _.Endpoints = lock endpoints (fun () -> List.ofSeq endpoints.Values)

    /// What each configured whole-key signer answered at the last Discover: its key list, or
    /// nothing when the call failed. Share group members are left out: their keys come from
    /// the config.
    member _.LastAnswers = lastAnswers

    /// Whether the config names the key in a share group.
    member _.IsGroupKey(key: PubKey) = groupKeys.Contains key

    /// The whole-key signers of the config.
    member _.Signers: Uri list = settings.Signers |> List.map (fun s -> s.Url)

    /// The keys the configured whole-key signers listed at the last refresh, with their URLs.
    member _.ConfiguredKeys: (PubKey * Uri) list =
        [
            for (x: SignerEndpoint), _ in wholeKey do
                for k in x.Listed -> k, Uri x.Url
        ]

    /// A whole-key backend over the signer at `url`. A configured endpoint with that URL is
    /// reused with its TLS settings; a new one connects without client certificates.
    member _.WholeKeyBackend(url: Uri) : Backend =
        let x =
            endpoint
                {
                    Url = url
                    Tls = TlsSettings.None
                    Attestation = ValueNone
                }

        x.WholeKeys $"web3signer {x.Url}"

    /// Reads every endpoint's key list, then returns each key of the configured signers and
    /// groups with its backend, and how many endpoints answered. A key whole on a signer and
    /// split in a group comes once with each route, so the registry refuses it.
    member this.Discover(ct: CancellationToken) : Task<(PubKey * Backend) list * int> =
        task {
            let all = this.Endpoints

            let! results =
                all
                |> List.map (fun x -> ListedKeys.WithDeadline(time, ListedKeys.ListDeadline, ct, x.Refresh))
                |> Task.WhenAll

            let mutable answered = 0

            for x, r in Seq.zip all results do
                match r with
                | Ok _ -> answered <- answered + 1
                | Error f -> log.Warn $"web3signer {x.Url}: listing keys failed: {(Failed f).Describe}"

            lastAnswers <-
                [
                    for x, _ in wholeKey ->
                        match Seq.zip all results |> Seq.tryFind (fun (e, _) -> obj.ReferenceEquals(e, x)) with
                        | Some(_, Ok _) ->
                            {
                                Member = x.Url
                                Keys = ValueSome(x.Listed :> IReadOnlyCollection<_>)
                            }
                        | _ -> { Member = x.Url; Keys = ValueNone }
                ]

            let out = ResizeArray<PubKey * Backend>()

            for x, backend in wholeKey do
                for k in x.Listed do
                    out.Add(k, backend)

            for g in groups do
                let! keys = g.Keys ct

                for k in keys do
                    out.Add(k.Key, g)

            return (out |> Seq.distinctBy (fun (k, b) -> struct (k, Threshold.isGroup b)) |> List.ofSeq), answered
        }

    member this.Stop() =
        for x in this.Endpoints do
            x.Dispose()

/// Remote keys the keymanager API adds and deletes. Each signs as a whole key through the
/// signer URL given with it; keys of the configured signers are listed as read-only.
module RemoteKeys =
    let fileOf (dataDir: string) = Path.Combine(dataDir, "remote-keys.json")

    /// An absolute https URL, or http off mainnet.
    let parseUrl (mainnet: bool) (text: string) : Result<Uri, string> =
        match Uri.TryCreate(text, UriKind.Absolute) with
        | true, NonNull u when u.Scheme = Uri.UriSchemeHttps -> Ok u
        | true, NonNull u when u.Scheme = Uri.UriSchemeHttp ->
            if mainnet then Error $"'{text}': an http URL is refused on mainnet; use https" else Ok u
        | _ -> Error $"'{text}' is not an absolute http or https URL"

    /// An http URL, which mainnet refuses.
    let private refusedOn (mainnet: bool) (u: Uri) = mainnet && u.Scheme = Uri.UriSchemeHttp

    let toJson (keys: (PubKey * Uri) list) : byte[] =
        toBytes (fun w ->
            w.WriteStartArray()

            for k, u in keys do
                w.WriteStartObject()
                w.WriteString("pubkey", k.Hex)
                w.WriteString("url", u.AbsoluteUri)
                w.WriteEndObject()

            w.WriteEndArray())

    let ofJson (bytes: byte[]) : Result<(PubKey * Uri) list, string> =
        decode
            (fun e ->
                [
                    for k in array e ->
                        let url =
                            match parseUrl false (strField k "url") with
                            | Ok u -> u
                            | Error m -> fail m

                        pubkeyField k "pubkey", url
                ])
            (ReadOnlyMemory bytes)

    /// The keys the API added before, from the file. A file that does not read or parse is an
    /// error that fails the start, as a bad key-settings.json does: with a warning, the next
    /// import would rewrite the file with its own key and drop the others.
    let load (file: string) : Result<(PubKey * Uri) list, string> =
        if not (File.Exists file) then
            Ok []
        else
            let read =
                try
                    ofJson (File.ReadAllBytes file)
                with
                | :? IOException
                | :? UnauthorizedAccessException as e -> Error e.Message

            match read with
            | Ok keys -> Ok keys
            | Error e ->
                Error $"{file}: {e}; fix or remove the file (it lists the remote keys the keymanager API added)"

    /// The store over `set`. Loads the keys the API added before and routes them; a key that a
    /// configured backend already holds keeps that route. On mainnet a key saved with an http URL
    /// is not routed: it stays in the file and in the list until the API deletes it.
    let start (mainnet: bool) (core: CoreServices) (set: Web3SignerSet) : RemoteKeyStore =
        let log = core.Log
        let file = fileOf core.DataDir
        let added = Dictionary<PubKey, Uri>()
        // Saved keys with an http URL on mainnet: kept, not routed.
        let refused = Dictionary<PubKey, Uri>()
        let gate = new SemaphoreSlim(1, 1)
        // Atomic and durable (temporary file, fsync, rename, fsync of the directory), mode 0600:
        // an import the API answered must survive a power loss.
        let save () =
            Slashing.FileSync.writeAtomic
                file
                (toJson [ for KeyValue(k, u) in Seq.append added refused -> k, u ])
                (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        // The module's start checked the file with `load` first.
        match load file with
        | Error e -> raise (InvalidDataException e)
        | Ok keys ->
            for k, url in keys do
                if refusedOn mainnet url then
                    refused[k] <- url

                    log.Error
                        $"web3signer: remote key {k.Short} signs through {url.AbsoluteUri}, an http URL, which is refused on mainnet; it does not sign. Delete it and import it again with an https URL"
                elif core.Registry.Add(k, set.WholeKeyBackend url) then
                    added[k] <- url
                else
                    // Add also says false for a key another module refused first, which may
                    // never have been added.
                    match core.Registry.TryGet k with
                    | ValueSome r when not (core.Registry.IsRefused k) ->
                        log.Info $"web3signer: remote key {k.Short} is held by {r.Backend.Name}; ignoring the API entry"
                    | _ ->
                        log.Warn
                            $"web3signer: remote key {k.Short} is refused until restart, see the earlier error; ignoring the API entry"

            if added.Count > 0 then
                log.Info $"web3signer: {added.Count} remote keys added through the keymanager API"
        // Takes a refused entry out; the caller holds the `added` lock.
        let takeRefused k =
            match refused.TryGetValue k with
            | true, u ->
                refused.Remove k |> ignore
                ValueSome u
            | _ -> ValueNone

        let configured () = set.ConfiguredKeys |> List.filter (fun (k, _) -> not (added.ContainsKey k))

        {
            List =
                fun () ->
                    lock added (fun () ->
                        [
                            for k, u in configured () ->
                                {
                                    Key = k
                                    Url = u.AbsoluteUri
                                    ReadOnly = true
                                }
                        ]
                        @ [
                            for KeyValue(k, u) in Seq.append added refused ->
                                {
                                    Key = k
                                    Url = u.AbsoluteUri
                                    ReadOnly = false
                                }
                        ])
            Import =
                fun items ct ->
                    task {
                        do! gate.WaitAsync ct

                        try
                            let statuses =
                                [
                                    for k, url in items ->
                                        let parsed =
                                            match url, set.Signers with
                                            | ValueSome u, _ -> parseUrl mainnet u
                                            | ValueNone, [ only ] -> Ok only
                                            | ValueNone, _ ->
                                                Error
                                                    "url is missing and the config has not exactly one Web3Signer signer"

                                        match parsed with
                                        | Error e -> ImportStatus.Error e
                                        | Ok u ->
                                            match core.Registry.TryGet k with
                                            | ValueSome r when r.State <> KeyState.Removed -> ImportStatus.Duplicate
                                            | _ ->
                                                if core.Registry.Revive(k, set.WholeKeyBackend u) then
                                                    let old =
                                                        lock added (fun () ->
                                                            added[k] <- u
                                                            takeRefused k)

                                                    try
                                                        save ()

                                                        log.Info
                                                            $"web3signer: remote key {k.Short} added, signs through {u.AbsoluteUri}"

                                                        ImportStatus.Imported
                                                    with e ->
                                                        // The file still names the refused entry, so keep it listed.
                                                        lock added (fun () ->
                                                            added.Remove k |> ignore

                                                            match old with
                                                            | ValueSome o -> refused[k] <- o
                                                            | ValueNone -> ())

                                                        core.Registry.SetState(k, KeyState.Removed)
                                                        ImportStatus.Error $"saving {file} failed: {e.Message}"
                                                elif core.Registry.IsRefused k then
                                                    ImportStatus.Error
                                                        "the key is refused until restart; see the VC log"
                                                else
                                                    ImportStatus.Duplicate
                                ]

                            if statuses |> List.contains ImportStatus.Imported then
                                do! core.RefreshKeys ct

                            return statuses
                        finally
                            gate.Release() |> ignore
                    }
            Delete =
                fun pks ct ->
                    task {
                        do! gate.WaitAsync ct

                        try
                            let out = ResizeArray<DeleteStatus>()

                            for k in pks do
                                let old = lock added (fun () -> takeRefused k)

                                match
                                    lock added (fun () -> added.ContainsKey k),
                                    configured () |> List.tryFind (fun (c, _) -> c = k)
                                with
                                | _ when old.IsSome ->
                                    // Never routed: only the file names it. If the save fails, the
                                    // entry goes back, so a retried DELETE finds it again.
                                    try
                                        save ()
                                        log.Info $"web3signer: remote key {k.Short} deleted"
                                        out.Add DeleteStatus.Deleted
                                    with e ->
                                        lock added (fun () -> refused[k] <- old.Value)
                                        out.Add(DeleteStatus.Error $"saving {file} failed: {e.Message}")
                                | true, _ ->
                                    let! drained = KeyRetirement.drain core.Registry core.Pipeline log k ignore ct

                                    if not drained then
                                        out.Add(
                                            DeleteStatus.Error
                                                "the key is halted; it stays until restart, see the VC log for why"
                                        )
                                    else
                                        lock added (fun () -> added.Remove k |> ignore)

                                        try
                                            save ()
                                            log.Info $"web3signer: remote key {k.Short} deleted"
                                            out.Add DeleteStatus.Deleted
                                        with e ->
                                            // The key no longer signs; only the file still names it.
                                            out.Add(
                                                DeleteStatus.Error
                                                    $"the key no longer signs, but saving {file} failed: {e.Message}"
                                            )
                                | false, Some(_, u) ->
                                    out.Add(
                                        DeleteStatus.Error
                                            $"read-only: the configured signer {u.AbsoluteUri} holds this key; remove it there"
                                    )
                                | false, None -> out.Add DeleteStatus.NotFound

                            return List.ofSeq out
                        finally
                            gate.Release() |> ignore
                    }
        }

    /// Whether a key may be retired when the configured signers stop listing it. Share group
    /// keys come from the config, and keys the keymanager API added leave only through the API.
    let retirable (set: Web3SignerSet) (store: RemoteKeyStore) (key: PubKey) =
        not (set.IsGroupKey key)
        && not (store.List() |> List.exists (fun r -> r.Key = key && not r.ReadOnly))

/// The `pinned` source: the configured key hashes, always attested.
type PinnedSource(pins: byte[] list) =
    interface AttestationSource with
        member _.Describe = "pinned tls_key_pin"
        member _.Attest _ = Task.FromResult(AttestationResult.Attested pins)
        member _.Files = []

/// The source of an endpoint's attestation block.
let attestationSource
    (endpoint: string)
    (a: AttestationSettings)
    (log: Log)
    (time: TimeProvider)
    : Result<AttestationSource, string> =
    match a.Source with
    | "pinned" -> Ok(PinnedSource a.Pins :> AttestationSource)
    | other ->
        match AttestationSources.tryFind other with
        | ValueSome k ->
            k.Build
                {
                    Endpoint = endpoint
                    Block = a.Block
                    Section = a.Section
                    Log = log
                    Time = time
                }
        | ValueNone -> Error $"{endpoint}: attestation source \"{other}\" is not in this build"

/// At most one attestation after an unknown TLS key per this time, and the retry of a down endpoint.
let attestMinGap = TimeSpan.FromSeconds 12.0

let private loadAll
    (settings: Settings)
    (log: Log)
    (time: TimeProvider)
    : Result<Map<string, HttpSigner.LoadedTls>, string> =
    let all =
        (settings.Signers
         @ [
             for g in settings.Groups do
                 for _, m in g.Members -> m
         ])
        |> List.distinctBy (fun e -> e.Url.AbsoluteUri)

    let rec go acc (rest: EndpointSettings list) =
        match rest with
        | [] -> Ok acc
        | e :: tail ->
            match HttpSigner.loadTls e.Tls e.Url.AbsoluteUri log time with
            | Error m -> Error $"{e.Url.AbsoluteUri}: {m}"
            | Ok t ->
                match e.Attestation with
                | ValueNone -> go (Map.add e.Url.AbsoluteUri t acc) tail
                | ValueSome a ->
                    match attestationSource e.Url.AbsoluteUri a log time with
                    | Error m -> Error m
                    | Ok src ->
                        let keys =
                            AttestedKeys(
                                $"web3signer {e.Url.AbsoluteUri}",
                                src,
                                a.RefreshInterval,
                                attestMinGap,
                                attestMinGap,
                                log,
                                time
                            )

                        go (Map.add e.Url.AbsoluteUri { t with Attested = ValueSome keys } acc) tail

    go Map.empty all

let create () : Module =
    let settings = ref ValueNone
    let mainnet = ref false

    {
        Name = name
        Configure =
            fun section ->
                mainnet.Value <- section.Mainnet

                match section.Element with
                | ValueNone ->
                    // Linked but not configured: only keys the keymanager API adds.
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
                | ValueNone -> Ok "not configured; remote keys from the keymanager API only"
                | ValueSome s ->
                    match loadAll s Log.none TimeProvider.System with
                    | Ok _ ->
                        let shareKeys = s.Groups |> List.sumBy (fun g -> g.Keys.Length)

                        Ok
                            $"{s.Signers.Length} signers, {s.Groups.Length} share groups with {shareKeys} keys, TLS files load"
                    | Error e -> Error [ e ]
        Start =
            fun core ct ->
                task {
                    // Endpoints of keys the API adds have no TLS files: an https URL is checked
                    // against the system trust store.
                    let connect (tls: Map<string, HttpSigner.LoadedTls>) (maxConnections: int) (e: EndpointSettings) =
                        let t = tls.TryFind e.Url.AbsoluteUri |> Option.defaultValue HttpSigner.LoadedTls.None
                        HttpSigner.create e t core.Spec maxConnections

                    let chain: ProbeChain =
                        {
                            Spec = core.Spec
                            CurrentEpoch = fun () -> core.Clock.CurrentSlot |> ValueOption.map core.Clock.EpochOf
                        }

                    match RemoteKeys.load (RemoteKeys.fileOf core.DataDir), settings.Value with
                    | Error e, _ -> return Error $"web3signer: {e}"
                    | Ok _, ValueNone ->
                        let set =
                            Web3SignerSet(
                                connect Map.empty apiOnly.MaxConnections,
                                apiOnly,
                                core.Clock.Time,
                                core.Log,
                                chain
                            )

                        core.SetRemoteKeys(RemoteKeys.start mainnet.Value core set)

                        return
                            Ok
                                {
                                    Stop = fun () -> task { set.Stop() } :> Task
                                }
                    | Ok _, ValueSome s ->
                        match loadAll s core.Log core.Clock.Time with
                        | Error e -> return Error e
                        | Ok tls ->
                            // Attest every attested endpoint before the first request; one that fails
                            // stays down and is tried again by its task.
                            let attested =
                                [
                                    for KeyValue(_, t) in tls do
                                        match t.Attested with
                                        | ValueSome a -> a
                                        | ValueNone -> ()
                                ]

                            if not attested.IsEmpty then
                                let first = attested |> List.map (fun a -> a.Refresh ct) |> Task.WhenAll
                                let! _ = Task.WhenAny(first, Task.Delay(TimeSpan.FromSeconds 60.0, core.Clock.Time, ct))
                                ()

                            let set = Web3SignerSet(connect tls s.MaxConnections, s, core.Clock.Time, core.Log, chain)
                            let keys = ListedKeys(name, core.Registry, core.Pipeline, core.Log)
                            let! found, answered = set.Discover ct
                            let added = keys.Register found

                            core.Log.Info
                                $"web3signer: {answered} of {set.Endpoints.Length} endpoints answered, {added} keys"

                            let store = RemoteKeys.start mainnet.Value core set
                            core.SetRemoteKeys store
                            let retirable = RemoteKeys.retirable set store
                            let! _ = keys.Retire(set.LastAnswers, retirable, ct)
                            let stopper = new CancellationTokenSource()
                            let stopToken = stopper.Token

                            let tlsFiles =
                                [
                                    for KeyValue(_, t) in tls do
                                        match t.Ca with
                                        | ValueSome f -> f :> TlsCheck
                                        | ValueNone -> ()

                                        match t.Client with
                                        | ValueSome f -> f :> TlsCheck
                                        | ValueNone -> ()

                                        match t.Attested with
                                        | ValueSome a -> yield! a.Source.Files
                                        | ValueNone -> ()
                                ]

                            let reloader = TlsFiles.watch tlsFiles s.ReloadInterval core.Clock.Time stopToken
                            let attesters = [ for a in attested -> a.Run stopToken ] |> Task.WhenAll
                            // A 404 asks for a refresh now (UnknownKey refreshes the key list).
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
                                                // Until every endpoint answers, try again every 12 s.
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
                                                    lastAnswered <- n
                                                    let added = keys.Register found
                                                    let! _ = keys.Retire(set.LastAnswers, retirable, linked.Token)

                                                    if added > 0 then
                                                        core.Log.Info $"web3signer: {added} new keys"
                                                        do! core.RefreshKeys linked.Token
                                                with
                                                | :? OperationCanceledException -> ()
                                                | e -> core.Log.Warn $"web3signer: key list refresh failed: {e.Message}"
                                                // At most one early refresh per 12 s, whatever the 404 rate.
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
                                                    do! attesters
                                                    set.Stop()
                                                    stopper.Dispose()
                                                }
                                                :> Task
                                    }
                }
    }
