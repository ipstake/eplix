/// The Eth2 remote signing API of Web3Signer (EIP-3030, consensus-specs remote-signing-api):
/// the typed request bodies, the HTTP client and the mapping of its answers to SignOutcome.
/// A gateway in front of Dirk can speak the same API.
namespace Eplix.Backend.Web3Signer

open System
open System.IO
open System.Net
open System.Net.Http
open System.Net.Http.Headers
open System.Net.Security
open System.Security.Authentication
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix

/// TLS for one endpoint. Without CaCert the system trust store checks the server; with
/// ClientCert and ClientKey (PEM files) the client authenticates itself (mutual TLS).
type TlsSettings =
    {
        CaCert: string voption
        ClientCert: string voption
        ClientKey: string voption
    }

    static member None =
        {
            CaCert = ValueNone
            ClientCert = ValueNone
            ClientKey = ValueNone
        }

/// The `attestation` block of an endpoint: where the TLS keys the endpoint
/// may present come from.
type AttestationSettings =
    {
        /// `pinned`, or a kind another module registers (`runner`, from the TEE module).
        Source: string
        /// How often the evidence is checked again; zero: at start and after an unknown key only.
        RefreshInterval: TimeSpan
        /// The TLS key hashes of a `pinned` source.
        Pins: byte[] list
        /// The block itself, for a registered kind's build.
        Block: JsonElement
        Section: ConfigSection
    }

type EndpointSettings =
    {
        Url: Uri
        Tls: TlsSettings
        /// None: the CA chain and host name checks only, no attestation.
        Attestation: AttestationSettings voption
    }

/// What a request to the signer gave, before it is read as a SignOutcome.
[<RequireQualifiedAccess>]
type Answer =
    | Signature of BlsSignature
    | Status of code: int * message: string
    | Failure of SignFailure
    /// Eplix cannot write this request in the remote signing API; nothing was sent.
    | Unsupported

/// The calls Eplix makes to one Web3Signer, as a record of functions: the HTTP client below is
/// one implementation, tests use fakes.
type SignerApi =
    {
        Url: string
        PublicKeys: CancellationToken -> Task<Result<PubKey list, SignFailure>>
        Upcheck: CancellationToken -> Task<bool>
        /// Signs `request` with the key `identifier` (the validator key, or a share key).
        Sign: PubKey -> SignRequest -> CancellationToken -> Task<Answer>
        /// Why the endpoint is not attested now, or none: a lookup, no I/O.
        NotAttested: unit -> string voption
        Dispose: unit -> unit
    }

module Body =
    let private hex (w: Utf8JsonWriter) (name: string) (b: byte[]) = w.WriteString(name, Hex.encodeArray b)
    let private u64 = Json.writeU64

    let private forkName (spec: ChainSpec) (epoch: Epoch) = (spec.ForkAt epoch).Name.ApiName.ToUpperInvariant()

    let private checkpoint (w: Utf8JsonWriter) (name: string) (c: Checkpoint) =
        w.WriteStartObject name
        u64 w "epoch" c.Epoch
        hex w "root" c.Root.Bytes
        w.WriteEndObject()

    let private forkInfo (w: Utf8JsonWriter) (spec: ChainSpec) (req: SignRequest) =
        // Exits are signed with Capella's fork version since Deneb (EIP-7044). Web3Signer builds
        // the domain from fork_info, so the request names that version as both previous and
        // current, as Teku does for exits.
        let fork =
            match req.Duty with
            | Duty.VoluntaryExit _ ->
                {
                    PreviousVersion = spec.ExitForkVersion
                    CurrentVersion = spec.ExitForkVersion
                    Epoch = 0UL
                }
            | _ -> req.Fork.Fork

        w.WriteStartObject "fork_info"
        w.WriteStartObject "fork"
        hex w "previous_version" fork.PreviousVersion.Bytes
        hex w "current_version" fork.CurrentVersion.Bytes
        u64 w "epoch" fork.Epoch
        w.WriteEndObject()
        hex w "genesis_validators_root" req.Fork.GenesisValidatorsRoot.Bytes
        w.WriteEndObject()

    /// The remote signing API's type name of a duty.
    let typeName (duty: Duty) =
        match duty with
        | Duty.Attestation _ -> "ATTESTATION"
        | Duty.Block _ -> "BLOCK_V2"
        | Duty.RandaoReveal _ -> "RANDAO_REVEAL"
        | Duty.AggregationSlot _ -> "AGGREGATION_SLOT"
        | Duty.AggregateAndProof _ -> "AGGREGATE_AND_PROOF_V2"
        | Duty.SyncCommitteeMessage _ -> "SYNC_COMMITTEE_MESSAGE"
        | Duty.SyncSelectionProof _ -> "SYNC_COMMITTEE_SELECTION_PROOF"
        | Duty.ContributionAndProof _ -> "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
        | Duty.VoluntaryExit _ -> "VOLUNTARY_EXIT"
        | Duty.PayloadAttestation _ -> "PAYLOAD_ATTESTATION_MESSAGE"
        | Duty.PayloadEnvelope _ -> "EXECUTION_PAYLOAD_ENVELOPE"
        | Duty.ProposerPreferences _ -> "PROPOSER_PREFERENCES"
        | Duty.BuilderRequestAuth _ -> "BUILDER_REQUEST_AUTH"
        | Duty.ValidatorRegistration _ -> "VALIDATOR_REGISTRATION"

    /// Whether `encode` can write the request. BLOCK_V2 before Bellatrix carries the whole
    /// block, not the header, and a duty holds only the header.
    let supported (spec: ChainSpec) (req: SignRequest) =
        match req.Duty with
        | Duty.Block h ->
            match (spec.ForkAt(spec.EpochOf h.Slot)).Name with
            | ForkName.Phase0
            | ForkName.Altair -> false
            | _ -> true
        | _ -> true

    /// The JSON body of POST /api/v1/eth2/sign/{identifier}: type, fork_info, signingRoot and
    /// the typed message, so the signer recomputes the root and applies its own rules.
    let encode (spec: ChainSpec) (req: SignRequest) : byte[] =
        Json.toBytes (fun w ->
            w.WriteStartObject()
            w.WriteString("type", typeName req.Duty)
            // Builder request auth and validator registrations have no fork_info: their domain
            // uses the genesis fork version.
            match req.Duty with
            | Duty.BuilderRequestAuth _
            | Duty.ValidatorRegistration _ -> ()
            | _ -> forkInfo w spec req

            hex w "signingRoot" req.SigningRoot.Bytes

            match req.Duty with
            | Duty.Attestation d ->
                w.WriteStartObject "attestation"
                u64 w "slot" d.Slot
                u64 w "index" d.Index
                hex w "beacon_block_root" d.BeaconBlockRoot.Bytes
                checkpoint w "source" d.Source
                checkpoint w "target" d.Target
                w.WriteEndObject()
            | Duty.Block h ->
                w.WriteStartObject "beacon_block"
                w.WriteString("version", forkName spec (spec.EpochOf h.Slot))
                w.WriteStartObject "block_header"
                u64 w "slot" h.Slot
                u64 w "proposer_index" h.ProposerIndex
                hex w "parent_root" h.ParentRoot.Bytes
                hex w "state_root" h.StateRoot.Bytes
                hex w "body_root" h.BodyRoot.Bytes
                w.WriteEndObject()
                w.WriteEndObject()
            | Duty.RandaoReveal e ->
                w.WriteStartObject "randao_reveal"
                u64 w "epoch" e
                w.WriteEndObject()
            | Duty.AggregationSlot s ->
                w.WriteStartObject "aggregation_slot"
                u64 w "slot" s
                w.WriteEndObject()
            | Duty.AggregateAndProof(slot, m) ->
                w.WriteStartObject "aggregate_and_proof"
                w.WriteString("version", forkName spec (spec.EpochOf slot))
                w.WritePropertyName "data"
                SszJson.write w m.Schema m.Value
                w.WriteEndObject()
            | Duty.SyncCommitteeMessage(slot, root) ->
                w.WriteStartObject "sync_committee_message"
                hex w "beacon_block_root" root.Bytes
                u64 w "slot" slot
                w.WriteEndObject()
            | Duty.SyncSelectionProof d ->
                w.WriteStartObject "sync_aggregator_selection_data"
                u64 w "slot" d.Slot
                u64 w "subcommittee_index" d.SubcommitteeIndex
                w.WriteEndObject()
            | Duty.ContributionAndProof(_, m) ->
                w.WritePropertyName "contribution_and_proof"
                SszJson.write w m.Schema m.Value
            | Duty.VoluntaryExit x ->
                w.WriteStartObject "voluntary_exit"
                u64 w "epoch" x.Epoch
                u64 w "validator_index" x.ValidatorIndex
                w.WriteEndObject()
            // Gloas types (remote-signing-api v1.4.0): {"version": "GLOAS", "data": ...}.
            | Duty.PayloadAttestation d ->
                w.WriteStartObject "payload_attestation_message"
                w.WriteString("version", "GLOAS")
                w.WritePropertyName "data"
                SszJson.write w Schemas.Gloas.payloadAttestationData (Codec.payloadAttestationDataValue d)
                w.WriteEndObject()
            | Duty.PayloadEnvelope(_, m) ->
                w.WriteStartObject "execution_payload_envelope"
                w.WriteString("version", "GLOAS")
                w.WritePropertyName "data"
                SszJson.write w m.Schema m.Value
                w.WriteEndObject()
            | Duty.ProposerPreferences p ->
                w.WriteStartObject "proposer_preferences"
                w.WriteString("version", "GLOAS")
                w.WritePropertyName "data"
                SszJson.write w Schemas.Gloas.proposerPreferences (Codec.proposerPreferencesValue p)
                w.WriteEndObject()
            | Duty.BuilderRequestAuth a ->
                w.WriteStartObject "builder_request_auth"
                w.WriteString("version", "GLOAS")
                w.WritePropertyName "data"
                SszJson.write w Schemas.Gloas.builderRequestAuth (Codec.builderRequestAuthValue a)
                w.WriteEndObject()
            | Duty.ValidatorRegistration r ->
                w.WritePropertyName "validator_registration"
                SszJson.write w Schemas.validatorRegistration (Codec.validatorRegistrationValue r)

            w.WriteEndObject())

    /// A sign answer: {"signature": "0x..."} for Accept: application/json, or the bare hex.
    let signature (body: string) : BlsSignature voption =
        let text = body.Trim()

        if text.StartsWith "{" then
            match Json.decodeString (fun e -> Json.signature (Json.prop e "signature")) text with
            | Ok s -> ValueSome s
            | Error _ -> ValueNone
        else
            BlsSignature.TryParse(text.Trim('"'))

    /// GET /api/v1/eth2/publicKeys: a JSON array of 0x-hex keys.
    let publicKeys (body: string) : Result<PubKey list, string> =
        Json.decodeString (fun e -> Json.array e |> Array.map Json.pubkey |> List.ofArray) body

    /// The message of an error answer ({"code": 412, "message": "..."}), or the body itself, cut
    /// and cleaned for a log line (Threshold.cleanReason).
    let errorMessage (body: string) =
        match Json.decodeString (fun e -> Json.strField e "message") body with
        | Ok m -> Threshold.cleanReason m
        | Error _ -> Threshold.cleanReason body

/// How an answer maps to a SignOutcome.
module Answer =
    /// `partialIndex` is the share index in share mode: a signature then is a Partial.
    let toOutcome (url: string) (duty: Duty) (partialIndex: uint64 voption) (answer: Answer) : SignOutcome =
        match answer with
        | Answer.Signature s ->
            match partialIndex with
            | ValueSome i -> Partial(i, s)
            | ValueNone -> Signed s
        | Answer.Failure f -> Failed f
        | Answer.Unsupported -> Refused(Unsupported duty.Kind)
        // Web3Signer's slashing protection refused: an explicit slashing refusal. For an
        // attestation or block the pipeline halts the key if its own DB allowed it.
        | Answer.Status(412, m) when duty.IsSlashable -> Refused(Slashable $"{url} answered 412: {m}")
        // 412 on a kind with no slashing rules is the signer's policy (a gateway may refuse exits).
        | Answer.Status(412, m) -> Refused(PolicyDenied $"{url} answered 412: {m}")
        | Answer.Status(404, _) -> Refused UnknownKey
        | Answer.Status(400, m) -> Refused(BadRequest $"{url} answered 400: {m}")
        | Answer.Status((401 | 403) as c, m) -> Refused(PolicyDenied $"{url} answered {c}: {m}")
        | Answer.Status((408 | 504), _) -> Failed SignFailure.Timeout
        // The client follows no redirect: the sign request goes only to the configured URL.
        | Answer.Status(c, _) when c >= 300 && c < 400 ->
            Failed(
                Internal
                    $"{url} answered {c}, a redirect, which the VC does not follow; configure the URL it redirects to"
            )
        | Answer.Status(c, m) -> Failed(Internal $"{url} answered {c}: {m}")

module HttpSigner =
    /// Checks the server certificate against the configured CAs in force at the handshake (not
    /// the system store) and the host name against the certificate, as the Dirk module does.
    let private validator (ca: TlsFile<X509Certificate2Collection>) =
        RemoteCertificateValidationCallback(fun _ cert chain errors ->
            match cert with
            | null -> false
            | _ when
                errors
                &&& (SslPolicyErrors.RemoteCertificateNameMismatch ||| SslPolicyErrors.RemoteCertificateNotAvailable)
                <> SslPolicyErrors.None
                ->
                false
            | cert ->
                use c = new X509Chain()
                c.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust
                c.ChainPolicy.CustomTrustStore.AddRange ca.Current.Value
                c.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck
                c.ChainPolicy.VerificationFlags <- X509VerificationFlags.NoFlag
                // serverAuth: a client-only certificate from the same CA is not a server.
                c.ChainPolicy.ApplicationPolicy.Add(Security.Cryptography.Oid "1.3.6.1.5.5.7.3.1") |> ignore
                // The intermediates the server sent, so a ca_cert with only the root CA is enough.
                match chain with
                | null -> ()
                | chain ->
                    c.ChainPolicy.ExtraStore.AddRange chain.ChainPolicy.ExtraStore

                    for el in chain.ChainElements do
                        c.ChainPolicy.ExtraStore.Add el.Certificate |> ignore

                use leaf = new X509Certificate2(cert)
                c.Build leaf)

    type LoadedTls =
        {
            Ca: TlsFile<X509Certificate2Collection> voption
            /// The client certificate with the intermediates from its file,
            /// reloaded while running.
            Client: TlsFile<SslStreamCertificateContext> voption
            /// The attested TLS keys of the endpoint.
            Attested: AttestedKeys voption
            Log: Log
            Time: TimeProvider
        }

        /// No TLS files: an https URL is checked against the system trust store.
        static member None =
            {
                Ca = ValueNone
                Client = ValueNone
                Attested = ValueNone
                Log = Log.none
                Time = TimeProvider.System
            }

    /// Loads the CA and the client certificate with its key. Errors name the files. `name`
    /// labels the files in the reload metrics and logs (the endpoint URL).
    let loadTls (tls: TlsSettings) (name: string) (log: Log) (time: TimeProvider) : Result<LoadedTls, string> =
        let ca =
            match tls.CaCert with
            | ValueSome f -> TlsFiles.ca "web3signer" $"{name} ca_cert" f log time |> Result.map ValueSome
            | ValueNone -> Ok ValueNone

        let client =
            match tls.ClientCert, tls.ClientKey with
            | ValueSome c, ValueSome k ->
                TlsFiles.client "web3signer" $"{name} client_cert" c k log time |> Result.map ValueSome
            | ValueNone, ValueNone -> Ok ValueNone
            | _ -> Error "client_cert and client_key go together"

        match ca, client with
        | Ok ca, Ok client ->
            Ok
                {
                    Ca = ca
                    Client = client
                    Attested = ValueNone
                    Log = log
                    Time = time
                }
        | Error e, _
        | _, Error e -> Error $"TLS files: {e}"

    /// The server check of an endpoint: the CA chain and the host name when
    /// ca_cert is set, and when the endpoint is attested, the hash of the server's TLS key in
    /// the attested set. The second is a lookup; a key not in the set fails the handshake and
    /// asks for a new attestation. An attested endpoint without ca_cert is trusted on the
    /// attestation alone, as a TEE runner is. None: the system trust store.
    let validatorFor (tls: LoadedTls) : RemoteCertificateValidationCallback voption =
        let attested (cert: X509Certificate) =
            match tls.Attested with
            | ValueNone -> true
            | ValueSome a ->
                let h = Spki.hash cert

                if a.Contains h then
                    true
                else
                    a.Unknown h
                    false

        match tls.Ca, tls.Attested with
        | ValueNone, ValueNone -> ValueNone
        | ValueSome ca, ValueNone -> ValueSome(validator ca)
        | ValueSome ca, ValueSome _ ->
            let chain = validator ca

            ValueSome(
                RemoteCertificateValidationCallback(fun sender cert ch errors ->
                    match cert with
                    | null -> false
                    | c -> chain.Invoke(sender, c, ch, errors) && attested c)
            )
        | ValueNone, ValueSome _ ->
            ValueSome(
                RemoteCertificateValidationCallback(fun _ cert _ _ ->
                    match cert with
                    | null -> false
                    | c -> attested c)
            )

    let private failureOf (e: exn) : SignFailure =
        match e with
        | :? OperationCanceledException
        | :? TimeoutException -> SignFailure.Timeout
        | :? HttpRequestException as h ->
            match h.InnerException with
            | null -> Transport h.Message
            | inner -> Transport $"{h.Message} {inner.Message}"
        | e -> Transport e.Message

    /// How long requests that took the old client get before it is disposed after a swap.
    let SwapGrace = TimeSpan.FromSeconds 60.0

    /// Web3Signer closes a connection idle for 30 s (`--idle-connection-timeout-seconds`). After
    /// this much idle time the client sends GET /upcheck, so one connection stays open between
    /// duties and a duty does not wait for a new TLS handshake. Web3Signer closes a connection idle for 30 s by default.
    let KeepAliveIdle = TimeSpan.FromSeconds 15.0

    /// The largest answer body the client reads. A key list of 100,000 keys is about 10 MB; a
    /// signer that sends more fails the call instead of filling memory.
    let MaxBody = 16L * 1024L * 1024L

    /// The client closes a connection idle this long itself, before the server's 30 s, so a
    /// request never goes out on a connection the server is closing. With the keepalive only the
    /// extra connections of a burst get this old.
    let IdleClose = TimeSpan.FromSeconds 25.0

    /// The HTTP client of one client certificate generation. A connection lives at most an hour
    /// and never past the certificate's NotAfter. A dial with an expired certificate fails and
    /// names its file.
    let private httpClient
        (endpoint: EndpointSettings)
        (tls: LoadedTls)
        (client: TlsLoad<SslStreamCertificateContext> voption)
        (maxConnections: int)
        =
        let lifetime =
            match client with
            | ValueSome c ->
                max (TimeSpan.FromSeconds 1.0) (min (TimeSpan.FromHours 1.0) (c.NotAfter - tls.Time.GetUtcNow()))
            | ValueNone -> TimeSpan.FromHours 1.0

        let handler =
            new SocketsHttpHandler(
                MaxConnectionsPerServer = maxConnections,
                PooledConnectionIdleTimeout = IdleClose,
                PooledConnectionLifetime = lifetime,
                ConnectTimeout = TimeSpan.FromSeconds 5.0,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false,
                // A redirect would resend a sign request to another host.
                AllowAutoRedirect = false
            )

        if endpoint.Url.Scheme = Uri.UriSchemeHttps then
            let options =
                SslClientAuthenticationOptions(EnabledSslProtocols = (SslProtocols.Tls12 ||| SslProtocols.Tls13))

            match validatorFor tls with
            | ValueSome v -> options.RemoteCertificateValidationCallback <- v
            | ValueNone -> ()

            match client, tls.Client with
            | ValueSome c, ValueSome file ->
                options.ClientCertificateContext <- c.Value

                handler.ConnectCallback <-
                    fun ctx ct ->
                        ValueTask<IO.Stream>(
                            task {
                                if tls.Time.GetUtcNow() >= c.NotAfter then
                                    raise (
                                        AuthenticationException
                                            $"the client certificate in {file.Files} expired on {c.NotAfter.UtcDateTime:u}; replace it (it reloads while running)"
                                    )

                                let socket =
                                    new Sockets.Socket(
                                        Sockets.SocketType.Stream,
                                        Sockets.ProtocolType.Tcp,
                                        NoDelay = true
                                    )

                                try
                                    do! socket.ConnectAsync(ctx.DnsEndPoint, ct)
                                    return new Sockets.NetworkStream(socket, true) :> IO.Stream
                                with e ->
                                    socket.Dispose()
                                    return raise (IOException(e.Message, e))
                            }
                        )
            | _ -> ()

            handler.SslOptions <- options

        new HttpClient(
            handler,
            BaseAddress = endpoint.Url,
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = MaxBody
        )

    /// A client for one endpoint. `maxConnections` caps the HTTP/1.1 connections a burst opens.
    /// When the client certificate changes, a new HTTP client with it is tested with /upcheck
    /// off the request path and then takes the new requests; the old one is disposed a minute
    /// later. A handler fixes its client certificate once it has sent a request.
    let create (endpoint: EndpointSettings) (tls: LoadedTls) (spec: ChainSpec) (maxConnections: int) : SignerApi =
        let url = endpoint.Url.GetLeftPart(UriPartial.Authority)
        let first = httpClient endpoint tls (tls.Client |> ValueOption.map (fun c -> c.Current)) maxConnections

        let clients =
            Rotating<HttpClient>($"web3signer {url}", first, (fun c -> c.Dispose()), tls.Log, tls.Time)

        match tls.Client with
        | ValueSome file when endpoint.Url.Scheme = Uri.UriSchemeHttps ->
            file.Swapped.Add(fun (old, next) ->
                let test (c: HttpClient) (ct: CancellationToken) : Task =
                    task {
                        use msg = new HttpRequestMessage(HttpMethod.Get, "/upcheck")
                        use! resp = c.SendAsync(msg, ct)
                        // Any HTTP answer means the TLS handshake with the new certificate passed.
                        ignore resp.StatusCode
                    }

                clients.Replace(
                    (fun () -> httpClient endpoint tls (ValueSome next) maxConnections),
                    test,
                    old.NotAfter,
                    SwapGrace
                ))
        | _ -> ()

        let json = MediaTypeWithQualityHeaderValue "application/json"

        let notAttested () =
            match tls.Attested with
            | ValueSome a -> a.Down
            | ValueNone -> ValueNone

        // When the last request went out, as a TimeProvider timestamp.
        let lastUse = [| tls.Time.GetTimestamp() |]
        let touch () = Volatile.Write(&lastUse[0], tls.Time.GetTimestamp())

        let get (path: string) (acceptJson: bool) (ct: CancellationToken) =
            task {
                touch ()
                use msg = new HttpRequestMessage(HttpMethod.Get, path)

                if acceptJson then
                    msg.Headers.Accept.Add json

                use! resp = clients.Current.SendAsync(msg, ct)
                let! body = resp.Content.ReadAsStringAsync(ct)
                return int resp.StatusCode, body
            }

        // The keepalive: every 5 s, an /upcheck when nothing went out for KeepAliveIdle. It skips
        // an endpoint that is not attested, which must not be dialled.
        let stop = new CancellationTokenSource()

        let _keepAlive =
            task {
                try
                    while not stop.IsCancellationRequested do
                        do! Task.Delay(TimeSpan.FromSeconds 5.0, tls.Time, stop.Token)

                        if
                            tls.Time.GetElapsedTime(Volatile.Read &lastUse[0]) >= KeepAliveIdle
                            && (notAttested ()).IsNone
                        then
                            try
                                use cts = CancellationTokenSource.CreateLinkedTokenSource stop.Token
                                cts.CancelAfter(TimeSpan.FromSeconds 5.0)
                                let! _ = get "/upcheck" false cts.Token
                                ()
                            with _ ->
                                ()
                with _ ->
                    ()
            }

        {
            Url = url
            PublicKeys =
                fun ct ->
                    task {
                        try
                            match notAttested () with
                            | ValueSome r -> raise (HttpRequestException r)
                            | ValueNone -> ()

                            let! code, body = get "/api/v1/eth2/publicKeys" true ct

                            if code >= 300 && code < 400 then
                                return
                                    Error(
                                        Internal
                                            $"{url} answered {code} to the key list, a redirect, which the VC does not follow; configure the URL it redirects to"
                                    )
                            elif code <> 200 then
                                return
                                    Error(Internal $"{url} answered {code} to the key list: {Body.errorMessage body}")
                            else
                                match Body.publicKeys body with
                                | Ok keys -> return Ok keys
                                | Error e -> return Error(Internal $"{url}: undecodable key list: {e}")
                        with e ->
                            return Error(failureOf e)
                    }
            Upcheck =
                fun ct ->
                    task {
                        try
                            if (notAttested ()).IsSome then
                                raise (HttpRequestException "not attested")

                            let! code, _ = get "/upcheck" false ct
                            return code = 200
                        with _ ->
                            return false
                    }
            Sign =
                fun identifier req ct ->
                    task {
                        if not (Body.supported spec req) then
                            return Answer.Unsupported
                        else
                            try
                                // Not attested: fail at once, without a dial.
                                match notAttested () with
                                | ValueSome r -> raise (HttpRequestException r)
                                | ValueNone -> ()

                                touch ()
                                use msg = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/eth2/sign/{identifier.Hex}")
                                msg.Headers.Accept.Add json
                                let content = new ByteArrayContent(Body.encode spec req)
                                content.Headers.ContentType <- MediaTypeHeaderValue("application/json")
                                msg.Content <- content
                                use! resp = clients.Current.SendAsync(msg, ct)
                                let! body = resp.Content.ReadAsStringAsync(ct)
                                let code = int resp.StatusCode

                                if code = 200 then
                                    match Body.signature body with
                                    | ValueSome s -> return Answer.Signature s
                                    | ValueNone -> return Answer.Failure(Internal $"{url}: undecodable signature")
                                else
                                    return Answer.Status(code, Body.errorMessage body)
                            with e ->
                                return Answer.Failure(failureOf e)
                    }
            NotAttested = notAttested
            Dispose =
                fun () ->
                    stop.Cancel()
                    clients.Dispose()
        }
