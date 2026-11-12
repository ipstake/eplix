/// The calls Eplix makes to one Dirk instance, as a record of functions: the gRPC client below
/// is one implementation, tests use fakes.
namespace Eplix.Backend.Dirk

open System
open System.IO
open System.Net.Http
open System.Net.Security
open System.Security.Authentication
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Grpc.Core
open Grpc.Net.Client
open Eplix
open Eplix.Backend.Dirk.Messages

/// A typed sign call: the attestation and proposal calls carry the message, so Dirk applies its
/// slashing protection to it; Generic carries the object root for the other kinds. The Gloas
/// calls are the typed calls of a Dirk build that has them (Messages.fs); stock Dirk answers them
/// UNIMPLEMENTED, and the endpoint then sends those kinds as Generic.
[<RequireQualifiedAccess>]
type DirkCall =
    | Generic of id: AccountId * objectRoot: Root * domain: Domain
    | Attestation of id: AccountId * domain: Domain * data: AttestationData
    | Proposal of id: AccountId * domain: Domain * header: BeaconBlockHeader
    | PayloadAttestation of id: AccountId * domain: Domain * data: PayloadAttestationData
    | PayloadEnvelope of id: AccountId * domain: Domain * envelope: SszObject
    | ProposerPreferences of id: AccountId * domain: Domain * preferences: ProposerPreferences
    | BuilderRequestAuth of id: AccountId * domain: Domain * auth: BuilderRequestAuth

    /// Whether this is one of the fork's typed Gloas calls.
    member this.IsTypedGloas =
        match this with
        | Generic _
        | Attestation _
        | Proposal _ -> false
        | PayloadAttestation _
        | PayloadEnvelope _
        | ProposerPreferences _
        | BuilderRequestAuth _ -> true

/// Why a call got no answer from Dirk.
[<RequireQualifiedAccess>]
type CallError =
    | Failure of SignFailure
    /// gRPC PERMISSION_DENIED or UNAUTHENTICATED: the client certificate is not allowed.
    | Rejected of string
    /// gRPC UNIMPLEMENTED: this Dirk has no such call (stock Dirk and the fork's typed Gloas calls).
    | Unimplemented of string

type DirkApi =
    {
        /// host:port
        Address: string
        ListAccounts: string list -> CancellationToken -> Task<Result<ListAccountsResponse, CallError>>
        Sign: DirkCall -> CancellationToken -> Task<Result<SignResponse, CallError>>
        /// SignBeaconAttestations: one response per request, in order. One request per account.
        SignAttestations:
            (AccountId * Domain * AttestationData) list
                -> CancellationToken
                -> Task<Result<SignResponse list, CallError>>
        Dispose: unit -> unit
    }

/// Mutual TLS settings shared by every Dirk connection.
type TlsSettings =
    {
        CaCert: string
        ClientCert: string
        ClientKey: string
    }

/// The loaded TLS files, reloaded while running.
type LoadedTls =
    {
        Ca: TlsFile<X509Certificate2Collection>
        Client: TlsFile<SslStreamCertificateContext>
        Log: Log
        Time: TimeProvider
    }

/// The gRPC channel of one client certificate generation.
type private ChannelGeneration =
    {
        Channel: GrpcChannel
        Invoker: CallInvoker
    }

module GrpcDirk =
    let private bytesMarshaller = Marshallers.Create((fun (b: byte[]) -> b), (fun (b: byte[]) -> b))

    let private unary service name =
        Method<byte[], byte[]>(MethodType.Unary, service, name, bytesMarshaller, bytesMarshaller)

    let private listAccounts = unary "v1.Lister" "ListAccounts"
    let private sign = unary "v1.Signer" "Sign"
    let private signAttestation = unary "v1.Signer" "SignBeaconAttestation"
    let private signAttestations = unary "v1.Signer" "SignBeaconAttestations"
    let private signProposal = unary "v1.Signer" "SignBeaconProposal"
    let private signPayloadAttestation = unary "v1.Signer" "SignPayloadAttestation"
    let private signExecutionPayloadEnvelope = unary "v1.Signer" "SignExecutionPayloadEnvelope"
    let private signProposerPreferences = unary "v1.Signer" "SignProposerPreferences"
    let private signBuilderRequestAuth = unary "v1.Signer" "SignBuilderRequestAuth"

    /// Checks the server certificate against the configured CAs in force at the handshake (not
    /// the system store) and the host name against the certificate.
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

    /// Loads the CA and the client certificate with its key and the intermediates from its file
    /// (so a Dirk that trusts only the root CA accepts it). Errors name the file.
    let loadTls (tls: TlsSettings) (log: Log) (time: TimeProvider) : Result<LoadedTls, string> =
        match
            TlsFiles.ca "dirk" "ca_cert" tls.CaCert log time,
            TlsFiles.client "dirk" "client_cert" tls.ClientCert tls.ClientKey log time
        with
        | Ok ca, Ok client ->
            Ok
                {
                    Ca = ca
                    Client = client
                    Log = log
                    Time = time
                }
        | Error e, _
        | _, Error e -> Error $"TLS files: {e}"

    /// How long calls that took the old channel get before it is disposed after a swap.
    let SwapGrace = TimeSpan.FromSeconds 60.0

    let private callError (e: exn) : CallError =
        match e with
        | :? RpcException as r ->
            match r.StatusCode with
            | StatusCode.DeadlineExceeded
            | StatusCode.Cancelled -> CallError.Failure SignFailure.Timeout
            | StatusCode.PermissionDenied
            | StatusCode.Unauthenticated -> CallError.Rejected r.Status.Detail
            | StatusCode.Unimplemented -> CallError.Unimplemented r.Status.Detail
            | StatusCode.Unavailable -> CallError.Failure(Transport $"unavailable: {r.Status.Detail}")
            | c -> CallError.Failure(Transport $"{c}: {r.Status.Detail}")
        | :? OperationCanceledException -> CallError.Failure SignFailure.Timeout
        | e -> CallError.Failure(Transport e.Message)

    /// Opens a TCP connection with TCP keepalive on: probes after 30 s idle, every 10 s, and on
    /// Linux the kernel drops a connection whose data or probes go unacknowledged for 30 s. That
    /// finds a dead Dirk between calls without HTTP/2 pings, which Dirk's gRPC server counts
    /// against the connection when no call is open.
    let keepAliveConnect (endpoint: Net.DnsEndPoint) (ct: CancellationToken) : ValueTask<Stream> =
        ValueTask<Stream>(
            task {
                let socket =
                    new Net.Sockets.Socket(Net.Sockets.SocketType.Stream, Net.Sockets.ProtocolType.Tcp, NoDelay = true)

                try
                    socket.SetSocketOption(
                        Net.Sockets.SocketOptionLevel.Socket,
                        Net.Sockets.SocketOptionName.KeepAlive,
                        true
                    )

                    socket.SetSocketOption(
                        Net.Sockets.SocketOptionLevel.Tcp,
                        Net.Sockets.SocketOptionName.TcpKeepAliveTime,
                        30
                    )

                    socket.SetSocketOption(
                        Net.Sockets.SocketOptionLevel.Tcp,
                        Net.Sockets.SocketOptionName.TcpKeepAliveInterval,
                        10
                    )

                    socket.SetSocketOption(
                        Net.Sockets.SocketOptionLevel.Tcp,
                        Net.Sockets.SocketOptionName.TcpKeepAliveRetryCount,
                        3
                    )
                    // TCP_USER_TIMEOUT (18) at IPPROTO_TCP (6), in milliseconds.
                    if OperatingSystem.IsLinux() then
                        socket.SetRawSocketOption(6, 18, ReadOnlySpan(BitConverter.GetBytes 30_000))

                    do! socket.ConnectAsync(endpoint, ct)
                    return new Net.Sockets.NetworkStream(socket, true) :> Stream
                with e ->
                    socket.Dispose()
                    return raise (IOException(e.Message, e))
            }
        )

    /// The HTTP handler of one channel. HTTP/2 pings go out only while a call is open: Dirk's
    /// gRPC server closes a connection that pings with no call open, which made every duty of a
    /// small key set dial again.
    let handlerFor (lifetime: TimeSpan) =
        new SocketsHttpHandler(
            EnableMultipleHttp2Connections = true,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            PooledConnectionLifetime = lifetime,
            KeepAlivePingDelay = TimeSpan.FromSeconds 20.0,
            KeepAlivePingTimeout = TimeSpan.FromSeconds 10.0,
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.WithActiveRequests,
            ConnectTimeout = TimeSpan.FromSeconds 5.0,
            AllowAutoRedirect = false,
            ConnectCallback = (fun ctx ct -> keepAliveConnect ctx.DnsEndPoint ct)
        )

    /// The channel of one client certificate generation. Its HTTP/2 connection lives until the
    /// certificate's NotAfter at most.
    let private channelFor
        (address: string)
        (tls: LoadedTls)
        (client: TlsLoad<SslStreamCertificateContext>)
        : ChannelGeneration =
        let handler = handlerFor (max (TimeSpan.FromSeconds 1.0) (client.NotAfter - tls.Time.GetUtcNow()))

        handler.SslOptions <-
            SslClientAuthenticationOptions(
                ClientCertificateContext = client.Value,
                EnabledSslProtocols = (SslProtocols.Tls12 ||| SslProtocols.Tls13),
                RemoteCertificateValidationCallback = validator tls.Ca
            )

        let channel =
            GrpcChannel.ForAddress(
                $"https://{address}",
                GrpcChannelOptions(
                    HttpHandler = handler,
                    DisposeHttpClient = true,
                    MaxReceiveMessageSize = Nullable(64 * 1024 * 1024)
                )
            )

        {
            Channel = channel
            Invoker = channel.CreateCallInvoker()
        }

    /// One HTTP/2 channel to a Dirk instance with mutual TLS. The channel connects on first use
    /// and reconnects by itself. A handler's client certificate is fixed and its one HTTP/2
    /// connection lives on, so a new client certificate gets a new channel: a ListAccounts call
    /// with no paths opens and tests its connection off the request path, then it takes the new
    /// calls and the old channel is disposed a minute later. A new channel is needed: the HTTP/2 connection keeps its first client certificate.
    let connect (address: string) (tls: LoadedTls) : DirkApi =
        let gens =
            Rotating<ChannelGeneration>(
                $"dirk {address}",
                channelFor address tls tls.Client.Current,
                (fun g -> g.Channel.Dispose()),
                tls.Log,
                tls.Time
            )

        let expiredNote () =
            let c = tls.Client.Current

            if tls.Time.GetUtcNow() >= c.NotAfter then
                $" (the client certificate in {tls.Client.Files} expired on {c.NotAfter.UtcDateTime:u}; replace it, it reloads while running)"
            else
                ""

        let callOn
            (g: ChannelGeneration)
            (m: Method<byte[], byte[]>)
            (body: byte[])
            (ct: CancellationToken)
            : Task<Result<byte[], CallError>> =
            task {
                try
                    let c = g.Invoker.AsyncUnaryCall(m, null, CallOptions(cancellationToken = ct), body)
                    let! r = c.ResponseAsync
                    return Ok r
                with e ->
                    return
                        match callError e with
                        | CallError.Failure(Transport m) -> Error(CallError.Failure(Transport(m + expiredNote ())))
                        | CallError.Rejected m -> Error(CallError.Rejected(m + expiredNote ()))
                        | err -> Error err
            }

        let call (m: Method<byte[], byte[]>) (body: byte[]) (ct: CancellationToken) = callOn gens.Current m body ct

        tls.Client.Swapped.Add(fun (old, next) ->
            let test (g: ChannelGeneration) (ct: CancellationToken) : Task =
                task {
                    match! callOn g listAccounts (listAccountsRequest []) ct with
                    | Ok _
                    | Error(CallError.Unimplemented _) -> ()
                    | Error(CallError.Rejected m) ->
                        raise (IOException $"Dirk rejected the new client certificate: {m}")
                    | Error(CallError.Failure f) -> raise (IOException((Failed f).Describe))
                }

            gens.Replace((fun () -> channelFor address tls next), test, old.NotAfter, SwapGrace))

        let decodeWith (f: ReadOnlyMemory<byte> -> 'T) (r: Result<byte[], CallError>) =
            match r with
            | Error e -> Error e
            | Ok b ->
                try
                    Ok(f (ReadOnlyMemory b))
                with :? Protobuf.ProtobufError as e ->
                    Error(CallError.Failure(Internal $"undecodable answer from Dirk: {e.Message}"))

        let api =
            {
                Address = address
                ListAccounts =
                    fun paths ct ->
                        task {
                            let! r = call listAccounts (listAccountsRequest paths) ct
                            return decodeWith decodeListAccountsResponse r
                        }
                Sign =
                    fun c ct ->
                        task {
                            let request =
                                try
                                    Ok(
                                        match c with
                                        | DirkCall.Generic(id, root, domain) -> sign, signRequest id root domain
                                        | DirkCall.Attestation(id, domain, d) ->
                                            signAttestation, signBeaconAttestationRequest id domain d
                                        | DirkCall.Proposal(id, domain, h) ->
                                            signProposal, signBeaconProposalRequest id domain h
                                        | DirkCall.PayloadAttestation(id, domain, d) ->
                                            signPayloadAttestation, signPayloadAttestationRequest id domain d
                                        | DirkCall.PayloadEnvelope(id, domain, e) ->
                                            signExecutionPayloadEnvelope,
                                            signExecutionPayloadEnvelopeRequest id domain e
                                        | DirkCall.ProposerPreferences(id, domain, p) ->
                                            signProposerPreferences, signProposerPreferencesRequest id domain p
                                        | DirkCall.BuilderRequestAuth(id, domain, a) ->
                                            signBuilderRequestAuth, signBuilderRequestAuthRequest id domain a
                                    )
                                with :? Ssz.SszError as e ->
                                    Error(
                                        CallError.Failure(Internal $"cannot encode the request for Dirk: {e.Message}")
                                    )

                            match request with
                            | Error e -> return Error e
                            | Ok(m, body) ->
                                let! r = call m body ct
                                return decodeWith decodeSignResponse r
                        }
                SignAttestations =
                    fun items ct ->
                        task {
                            let body =
                                signBeaconAttestationsRequest
                                    [ for id, domain, d in items -> signBeaconAttestationRequest id domain d ]

                            let! r = call signAttestations body ct
                            return decodeWith decodeMultisignResponse r
                        }
                Dispose = fun () -> gens.Dispose()
            }

        api
