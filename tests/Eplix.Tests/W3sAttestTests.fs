/// Attestation of Web3Signer endpoints: the attested key set and its
/// refresh, the TLS check of each new connection, the `runner` source against the dev
/// verifier, the config, and a fake source (what the `http` source will be).
module Eplix.Tests.W3sAttestTests

open System
open System.Buffers.Binary
open System.Collections.Concurrent
open System.Diagnostics
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Tee
open Eplix.Backend.Web3Signer
open Eplix.Tests.TestUtil

/// A self-signed server certificate for localhost, with its key.
let private serverCert (name: string) =
    use key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256)
    let san = SubjectAlternativeNameBuilder()
    san.AddDnsName "localhost"
    san.AddIpAddress IPAddress.Loopback
    req.CertificateExtensions.Add(san.Build())
    use c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 1.0)
    X509CertificateLoader.LoadPkcs12(c.Export X509ContentType.Pkcs12, null)

/// A source whose answer the test sets: the fake the `http` source will be tested against.
type private FakeSource(first: AttestationResult) =
    let mutable answer = first
    let mutable calls = 0

    member _.Answer
        with get () = answer
        and set v = answer <- v

    member _.Calls = calls

    interface AttestationSource with
        member _.Describe = "fake source"
        member _.Files = []

        member _.Attest _ =
            Interlocked.Increment &calls |> ignore
            Task.FromResult answer

/// A Web3Signer on 127.0.0.1 over HTTPS with keep-alive, whose certificate the test swaps
/// (Rotate drops the open connections, as a restart does). Counts handshakes and records
/// request paths.
type private RotatingSigner(first: X509Certificate2) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let mutable cert = first
    let mutable handshakes = 0
    let requests = ConcurrentQueue<string>()
    let openConns = ConcurrentDictionary<TcpClient, bool>()
    do listener.Start()

    let serve (tcp: TcpClient) =
        task {
            openConns[tcp] <- true

            try
                use tcp = tcp
                use ssl = new SslStream(tcp.GetStream(), false)
                do! ssl.AuthenticateAsServerAsync(SslServerAuthenticationOptions(ServerCertificate = cert), cts.Token)
                Interlocked.Increment &handshakes |> ignore
                let buf = Array.zeroCreate<byte> 8192
                let sb = StringBuilder()

                while true do
                    while not (sb.ToString().Contains "\r\n\r\n") do
                        let! n = ssl.ReadAsync(buf, 0, buf.Length, cts.Token)

                        if n = 0 then
                            raise (EndOfStreamException())

                        sb.Append(Encoding.ASCII.GetString(buf, 0, n)) |> ignore

                    let text = sb.ToString()
                    let head = text.Substring(0, text.IndexOf "\r\n\r\n" + 4)
                    sb.Remove(0, head.Length) |> ignore
                    let path = head.Split(' ').[1]
                    requests.Enqueue path
                    let body = if path.EndsWith "publicKeys" then "[]" else "OK"

                    let resp =
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n{body}"

                    do! ssl.WriteAsync(ReadOnlyMemory(Encoding.ASCII.GetBytes resp), cts.Token)
                    do! ssl.FlushAsync cts.Token
            with _ ->
                openConns.TryRemove tcp |> ignore
        }

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! c = listener.AcceptTcpClientAsync cts.Token
                    serve c |> ignore
            with _ ->
                ()
        }

    member _.Port = (listener.LocalEndpoint :?> IPEndPoint).Port
    member _.Handshakes = handshakes
    member _.Requests = List.ofSeq requests

    member _.Rotate(next: X509Certificate2) =
        cert <- next

        for KeyValue(c, _) in openConns do
            try
                c.Client.Shutdown SocketShutdown.Both
                c.Close()
            with _ ->
                ()

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

/// A runner on 127.0.0.1 that answers IDENTITY like a dev runner: TLS 1.3 with `cert`, any
/// client certificate, the identity naming `cert`'s key (or `names` when given), with this
/// setup hash, attested by the dev platform for the request's nonce.
type private DevRunner(cert: X509Certificate2, setup: Root, names: byte[] voption) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let mutable dials = 0
    do listener.Start()

    let identity (nonce: byte[]) =
        let zg: Wire.ConfigGroup =
            {
                Version = 0UL
                Hash = Root.Zero
                Pending =
                    {
                        Version = 0UL
                        Hash = Root.Zero
                        EffectiveAt = 0UL
                    }
            }

        let id: Wire.Identity =
            {
                State =
                    {
                        SetupHash = setup
                        Locked = zg
                        Open = zg
                        ApproverSetHash = Root.Zero
                        Order =
                            {
                                Kind = 0uy
                                Hash = Root.Zero
                                ActAt = 0UL
                            }
                        KeyReleaseHash = Root.Zero
                        KeyOrigin =
                            {
                                Generated = 0u
                                Imported = 0u
                                OrdersHash = Root.Zero
                            }
                    }
                ImportKem = 0us
                ImportKdf = 0us
                ImportAead = 0us
                ImportKey = [||]
                TlsKeyHash = defaultValueArg names (Spki.hash cert)
                Attestation =
                    {
                        Platform = "dev"
                        Format = "dev-json"
                        UserData = [||]
                        Document = [||]
                    }
            }

        let ud = Wire.identityUserData nonce id
        let doc = $"""{{"nonce":"{Convert.ToBase64String nonce}","user_data":"{Convert.ToBase64String ud}"}}"""

        { id with
            Attestation =
                { id.Attestation with
                    UserData = ud
                    Document = Encoding.UTF8.GetBytes doc
                }
        }

    let serve (client: TcpClient) =
        task {
            use client = client

            use ssl =
                new SslStream(client.GetStream(), false, RemoteCertificateValidationCallback(fun _ _ _ _ -> true))

            try
                do!
                    ssl.AuthenticateAsServerAsync(
                        SslServerAuthenticationOptions(
                            ServerCertificate = cert,
                            ClientCertificateRequired = true,
                            EnabledSslProtocols = SslProtocols.Tls13
                        ),
                        cts.Token
                    )

                Interlocked.Increment &dials |> ignore
                let len = Array.zeroCreate<byte> 4

                while true do
                    do! ssl.ReadExactlyAsync(len.AsMemory(), cts.Token)
                    let body = Array.zeroCreate<byte>(int (BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan len)))
                    do! ssl.ReadExactlyAsync(body.AsMemory(), cts.Token)
                    let f = Wire.decodeBody body
                    let n = int (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(f.Payload, 0, 2)))
                    let answer = Array.append [| 0uy; 0uy |] (Wire.encodeIdentity (identity f.Payload[2 .. 1 + n]))
                    let frame = Wire.encodeFrame (f.Type ||| Wire.ResponseFlag) f.Id (ReadOnlySpan answer)
                    do! ssl.WriteAsync(frame.AsMemory(), cts.Token)
                    do! ssl.FlushAsync cts.Token
            with _ ->
                ()
        }

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! c = listener.AcceptTcpClientAsync cts.Token
                    serve c |> ignore
            with _ ->
                ()
        }

    member _.Port = (listener.LocalEndpoint :?> IPEndPoint).Port
    member _.Dials = dials

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

let private endpointAt (port: int) : EndpointSettings =
    {
        Url = Uri $"https://localhost:{port}"
        Tls = TlsSettings.None
        Attestation = ValueNone
    }

let private apiWith (port: int) (keys: AttestedKeys) =
    HttpSigner.create
        (endpointAt port)
        { HttpSigner.LoadedTls.None with
            Attested = ValueSome keys
        }
        Web3SignerTests.spec.Value
        4

let private waitFor (what: string) (seconds: float) (cond: unit -> bool) =
    task {
        let sw = Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds seconds do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s" what
    }

let private section (json: string) (dir: string) (mainnet: bool) : ConfigSection =
    {
        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
        BaseDir = dir
        Mainnet = mainnet
    }

/// Writes a client certificate and key for the runner dial, returns their paths.
let private clientFiles (dir: string) =
    let p = TeeTlsTests.makePki "w3s attest client" false
    let crt = Path.Combine(dir, "client.crt")
    let key = Path.Combine(dir, "client.key")
    File.WriteAllText(crt, p.Leaf.ExportCertificatePem() + "\n" + p.Intermediate.ExportCertificatePem() + "\n")
    File.WriteAllText(key, p.LeafKey.ExportPkcs8PrivateKeyPem())
    crt, key

let private setupPin = Root.Of(Array.create 32 7uy)

/// An HTTP handler that answers with `f`, for the key set fetches.
type private FnHandler(f: Net.Http.HttpRequestMessage -> CancellationToken -> Task<Net.Http.HttpResponseMessage>) =
    inherit Net.Http.HttpMessageHandler()
    override _.SendAsync(req, ct) = f req ct

/// The error a key set fetch through `f` raises.
let private keySetError (f: Net.Http.HttpRequestMessage -> CancellationToken -> Task<Net.Http.HttpResponseMessage>) =
    task {
        use http = new Net.Http.HttpClient(new FnHandler(f), true, Timeout = TimeSpan.FromSeconds 1.0)
        let keys = Attest.DiscoveredKeys("MAA", "https://maa.test", http) :> Attest.KeySource

        try
            let! _ = keys.Get(false, CancellationToken.None)
            return failtest "the fetch passed"
        with e ->
            return e
    }

let private answer (status: int) (body: string) =
    Task.FromResult(
        new Net.Http.HttpResponseMessage(enum<HttpStatusCode> status, Content = new Net.Http.StringContent(body))
    )

[<Tests>]
let tests =
    testList
        "web3signer attestation"
        [
            test "the SPKI hash is the one a runner attests (Der.subjectPublicKeyInfo), for EC and RSA keys" {
                let ec = serverCert "ec"
                Expect.equal (Spki.hash ec) (SHA256.HashData(Der.subjectPublicKeyInfo ec.RawData)) "EC P-256"
                use rsa = RSA.Create 2048
                let req = CertificateRequest("CN=rsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                use r = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 1.0)
                Expect.equal (Spki.hash r) (SHA256.HashData(Der.subjectPublicKeyInfo r.RawData)) "RSA"
            }

            testT
                "an attested key serves; a rotated key not yet attested takes the endpoint down at once, then the refresh brings it up"
                (fun () ->
                    task {
                        let a = serverCert "key A"
                        let b = serverCert "key B"
                        use signer = new RotatingSigner(a)
                        let source = FakeSource(AttestationResult.Attested [ Spki.hash a ])
                        let log, lines = Log.memory ()

                        let keys =
                            AttestedKeys(
                                "w3s",
                                source,
                                TimeSpan.Zero,
                                TimeSpan.FromMilliseconds 50.0,
                                TimeSpan.FromMilliseconds 300.0,
                                log,
                                TimeProvider.System
                            )

                        do! keys.Refresh CancellationToken.None
                        let api = apiWith signer.Port keys
                        use stop = new CancellationTokenSource()
                        let run = keys.Run stop.Token
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
                        let! r = api.PublicKeys cts.Token
                        Expect.isOk r "key A is attested"
                        Expect.equal (api.NotAttested()) ValueNone "up"
                        // The signer restarts with key B; the evidence still names A.
                        signer.Rotate b
                        let! r = api.PublicKeys cts.Token
                        Expect.isError r "key B fails the TLS check"
                        Expect.isTrue (api.NotAttested()).IsSome "down"
                        do! waitFor "the asked attestation" 5.0 (fun () -> source.Calls >= 2)
                        Expect.isTrue (api.NotAttested()).IsSome "still down: the evidence does not name B"
                        // Down: requests fail at once, with no dial.
                        let handshakes = signer.Handshakes
                        let sw = Stopwatch.StartNew()
                        let! r = api.PublicKeys cts.Token
                        Expect.isError r "no request while down"
                        Expect.isLessThan sw.Elapsed (TimeSpan.FromMilliseconds 50.0) "at once"
                        Expect.equal signer.Handshakes handshakes "no dial while down"
                        // The evidence now names B: the next timed attestation brings the endpoint up.
                        source.Answer <- AttestationResult.Attested [ Spki.hash b ]
                        do! waitFor "up again" 5.0 (fun () -> (api.NotAttested()).IsNone)
                        let! r = api.PublicKeys cts.Token
                        Expect.isOk r "key B serves"
                        Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "still does not attest")) "logged"
                        stop.Cancel()
                        do! run
                        api.Dispose()
                    })

            testT "a refused attestation: no request reaches the endpoint, and its health is down" (fun () ->
                task {
                    let a = serverCert "key A"
                    use signer = new RotatingSigner(a)
                    let source = FakeSource(AttestationResult.Refused "setup_hash is not the pinned setup_sha256")

                    let keys =
                        AttestedKeys(
                            "w3s",
                            source,
                            TimeSpan.Zero,
                            TimeSpan.Zero,
                            TimeSpan.FromSeconds 1.0,
                            Log.none,
                            TimeProvider.System
                        )

                    do! keys.Refresh CancellationToken.None
                    let api = apiWith signer.Port keys
                    let x = SignerEndpoint(api, TimeSpan.FromSeconds 2.0, Log.none)

                    Expect.isTrue
                        (match x.Health with
                         | Down m -> m.Contains "setup_hash"
                         | _ -> false)
                        $"down with the reason: %A{x.Health}"

                    let key = PubKey.Of(Array.create 48 1uy)

                    let! o =
                        x.SignWith
                            key
                            ValueNone
                            (Web3SignerTests.req key (Duty.RandaoReveal 1UL))
                            CancellationToken.None

                    Expect.isTrue
                        (match o with
                         | Failed(Transport m) -> m.Contains "refused"
                         | _ -> false)
                        $"failed at once: {o.Describe}"

                    let! r = api.PublicKeys CancellationToken.None
                    Expect.isError r "no key list"
                    Expect.equal signer.Handshakes 0 "no handshake"
                    Expect.isEmpty signer.Requests "no request"
                    // A key the evidence does not name: the handshake fails before any request.
                    source.Answer <- AttestationResult.Attested [ Array.create 32 1uy ]
                    do! keys.Refresh CancellationToken.None
                    let! r = api.PublicKeys CancellationToken.None
                    Expect.isError r "the TLS check refuses the key"
                    Expect.isEmpty signer.Requests "still no request"
                    api.Dispose()
                })

            testT
                "no answer from the source keeps the last keys for three refresh intervals, then the endpoint goes down"
                (fun () ->
                    task {
                        let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                        let source = FakeSource(AttestationResult.Attested [ Array.create 32 5uy ])

                        let keys =
                            AttestedKeys(
                                "w3s",
                                source,
                                TimeSpan.FromMinutes 1.0,
                                TimeSpan.Zero,
                                TimeSpan.FromSeconds 1.0,
                                Log.none,
                                time
                            )

                        do! keys.Refresh CancellationToken.None
                        source.Answer <- AttestationResult.Unavailable "connection refused"
                        time.Advance(TimeSpan.FromMinutes 2.0)
                        do! keys.Refresh CancellationToken.None
                        Expect.isTrue (keys.Contains(Array.create 32 5uy) && keys.Down.IsNone) "kept after two minutes"
                        time.Advance(TimeSpan.FromMinutes 1.5)
                        do! keys.Refresh CancellationToken.None
                        Expect.isFalse (keys.Contains(Array.create 32 5uy)) "gone after three intervals"
                        Expect.isTrue keys.Down.IsSome "down"
                        source.Answer <- AttestationResult.Refused "bad document"
                        do! keys.Refresh CancellationToken.None

                        Expect.isTrue
                            (match keys.Down with
                             | ValueSome m -> m.Contains "bad document"
                             | _ -> false)
                            "a refusal says why"
                    })

            testT
                "the runner source against the dev verifier: the key the identity names is attested; a wrong setup or another key is not"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt, key = clientFiles dir
                        let tlsKey = serverCert "tee-signer"
                        TeeModule.runnerAttestationKind |> AttestationSources.register

                        let block (port: int) (pin: Root) =
                            $$"""{ "source": "runner", "refresh_interval_seconds": 60,
                         "runner": { "name": "single", "address": "tcp:127.0.0.1:{{port}}", "client_cert": "{{crt}}", "client_key": "{{key}}",
                                     "attestation": { "verifier": "dev", "setup_sha256": "{{pin.Hex}}" } } }"""

                        let build (port: int) (pin: Root) =
                            let s = section (block port pin) dir false
                            let e = s.Element.Value

                            match TeeModule.runnerAttestationKind.Check s "w3s.attestation" e with
                            | Error m -> failtest m
                            | Ok() ->
                                match
                                    TeeModule.runnerAttestationKind.Build
                                        {
                                            Endpoint = "w3s"
                                            Block = e
                                            Section = s
                                            Log = Log.none
                                            Time = TimeProvider.System
                                        }
                                with
                                | Ok src -> src
                                | Error m -> failtest m

                        use runner = new DevRunner(tlsKey, setupPin, ValueNone)
                        let src = build runner.Port setupPin
                        Expect.equal src.Files.Length 1 "the runner client certificate reloads"
                        let! r = src.Attest CancellationToken.None
                        Expect.equal r (AttestationResult.Attested [ Spki.hash tlsKey ]) "the identity's TLS key"
                        // The same key serves the Web3Signer port: the endpoint takes requests.
                        use signer = new RotatingSigner(tlsKey)

                        let keys =
                            AttestedKeys(
                                "w3s",
                                src,
                                TimeSpan.Zero,
                                TimeSpan.Zero,
                                TimeSpan.FromSeconds 1.0,
                                Log.none,
                                TimeProvider.System
                            )

                        do! keys.Refresh CancellationToken.None
                        let api = apiWith signer.Port keys
                        let! keysList = api.PublicKeys CancellationToken.None
                        Expect.isOk keysList "attested through the runner port"
                        api.Dispose()
                        // Another setup pinned: refused.
                        let! wrong = (build runner.Port (Root.Of(Array.create 32 8uy))).Attest CancellationToken.None

                        Expect.isTrue
                            (match wrong with
                             | AttestationResult.Refused m -> m.Contains "setup"
                             | _ -> false)
                            $"setup pin: %A{wrong}"
                        // An identity that names a key other than its TLS key: refused.
                        use liar = new DevRunner(tlsKey, setupPin, ValueSome(Array.create 32 3uy))
                        let! lie = (build liar.Port setupPin).Attest CancellationToken.None

                        Expect.isTrue
                            (match lie with
                             | AttestationResult.Refused _ -> true
                             | _ -> false)
                            $"identity key: %A{lie}"
                        // No runner there: unavailable, not refused.
                        let closed = new TcpListener(IPAddress.Loopback, 0)
                        closed.Start()
                        let port = (closed.LocalEndpoint :?> IPEndPoint).Port
                        closed.Stop()
                        let! none = (build port setupPin).Attest CancellationToken.None

                        Expect.isTrue
                            (match none with
                             | AttestationResult.Unavailable _ -> true
                             | _ -> false)
                            $"no runner: %A{none}"
                    })

            test "the runner source takes an attestation_ca_file that loads at start and reloads" {
                let dir = tempDir ()
                let crt, key = clientFiles dir
                let ca = Path.Combine(dir, "attest-ca.pem")
                File.WriteAllText(ca, (serverCert "attest ca").ExportCertificatePem() + "\n")
                TeeModule.runnerAttestationKind |> AttestationSources.register

                let block (caField: string) =
                    $$"""{ "source": "runner", {{caField}}
                         "runner": { "name": "single", "address": "tcp:127.0.0.1:7100", "client_cert": "{{crt}}", "client_key": "{{key}}",
                                     "attestation": { "verifier": "dev", "allow_unpinned_setup": true } } }"""

                let build (caField: string) =
                    let s = section (block caField) dir false
                    let e = s.Element.Value

                    match TeeModule.runnerAttestationKind.Check s "w3s.attestation" e with
                    | Error m -> Error m
                    | Ok() ->
                        TeeModule.runnerAttestationKind.Build
                            {
                                Endpoint = "w3s"
                                Block = e
                                Section = s
                                Log = Log.none
                                Time = TimeProvider.System
                            }

                match build "\"attestation_ca_file\": \"attest-ca.pem\"," with
                | Ok src -> Expect.equal src.Files.Length 2 "the client certificate and the CA bundle reload"
                | Error m -> failtest m

                match build "" with
                | Ok src -> Expect.equal src.Files.Length 1 "no bundle: the system store"
                | Error m -> failtest m

                match build "\"attestation_ca_file\": \"missing.pem\"," with
                | Ok _ -> failtest "a missing bundle starts"
                | Error m -> Expect.stringContains m "attestation_ca_file" "names the field"

                match build "\"attestation_ca_file\": \"\"," with
                | Ok _ -> failtest "an empty path passes"
                | Error m -> Expect.stringContains m "empty path" "empty path"
            }

            test "config: pinned, runner, http and the mainnet key release rule" {
                let dir = tempDir ()
                let crt, key = clientFiles dir
                TeeModule.runnerAttestationKind |> AttestationSources.register

                let parse (mainnet: bool) (att: string) =
                    Web3SignerModule.parseSettings (
                        section
                            $$"""{ "signers": [ { "url": "https://w3s:9000", "attestation": {{att}} } ] }"""
                            dir
                            mainnet
                    )

                let pin = String('a', 64)

                match parse false $$"""{ "source": "pinned", "tls_key_pin": "{{pin}}" }""" with
                | Ok s ->
                    let a = s.Signers.Head.Attestation.Value

                    Expect.equal
                        (a.Source, a.Pins, a.RefreshInterval)
                        ("pinned", [ Convert.FromHexString pin ], TimeSpan.FromSeconds 384.0)
                        "pinned"
                | Error e -> failtestf "%A" e

                match
                    parse false $$"""{ "source": "pinned", "tls_key_pin": [ "0x{{pin}}", "{{String('B', 64)}}" ] }"""
                with
                | Ok s -> Expect.equal s.Signers.Head.Attestation.Value.Pins.Length 2 "a list"
                | Error e -> failtestf "%A" e

                let refused (mainnet: bool) (att: string) (part: string) =
                    match parse mainnet att with
                    | Ok _ -> failtestf "accepted %s" att
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"{part} in %A{es}"

                refused false """{ "source": "pinned", "tls_key_pin": "abc" }""" "64 hex digits"
                refused false """{ "source": "pinned" }""" "needs tls_key_pin"
                refused false """{ "source": "http" }""" "not built yet"
                refused false """{ "source": "magic" }""" "not one of"
                refused false """{ "tls_key_pin": "x" }""" "source"
                refused false $$"""{ "source": "pinned", "tls_key_pin": "{{pin}}", "extra": 1 }""" "extra"

                let runner (att: string) =
                    $$"""{ "source": "runner", "runner": { "address": "tcp:192.0.2.1:7100", "client_cert": "{{crt}}", "client_key": "{{key}}", "attestation": {{att}} } }"""

                match parse false (runner """{ "verifier": "dev", "allow_unpinned_setup": true }""") with
                | Ok s -> Expect.equal s.Signers.Head.Attestation.Value.Source "runner" "runner"
                | Error e -> failtestf "%A" e

                refused false """{ "source": "runner" }""" "needs \"runner\""
                // B1's rule: on mainnet a nitro runner needs key_release_sha256.
                let pcr = String('1', 96)

                let nitro =
                    $$"""{ "verifier": "aws-nitro", "setup_sha256": "{{pin}}", "nitro_pcrs": { "0": "{{pcr}}", "1": "{{pcr}}", "2": "{{pcr}}" } }"""

                refused true (runner nitro) "key_release_sha256"

                match
                    Web3SignerModule.parseSettings (
                        section
                            $$"""{ "signers": [ { "url": "http://w3s:9000", "attestation": { "source": "pinned", "tls_key_pin": "{{pin}}" } } ] }"""
                            dir
                            false
                    )
                with
                | Ok _ -> failtest "attestation over http"
                | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains "https")) $"%A{es}"
            }

            test "the runner source refuses an answer that does not decode" {
                let dial (inner: exn) = IOException($"runner r: {inner.Message}", inner) :> exn
                let refusal = TeeModule.RunnerAttestation.IsRefusal

                Expect.isTrue
                    (refusal (dial (Wire.WireError "IDENTITY: field 3 is not a byte string")))
                    "a body that does not decode"

                Expect.isTrue (refusal (dial (Cbor.CborError "unexpected end of data"))) "CBOR that does not decode"
                Expect.isTrue (refusal (dial (DecoderFallbackException "bad UTF-8"))) "invalid UTF-8"
                Expect.isTrue (refusal (dial (Jwt.AttestError("nonce", "wrong nonce")))) "a failed check"
                Expect.isFalse (refusal (dial (SocketException 111))) "no answer"
                Expect.isFalse (refusal (dial (TimeoutException "no answer"))) "a timeout"
                // An indefinite text string whose chunk is not UTF-8 is a decode error, not an
                // exception of the text decoder.
                let bad = [| 0x7fuy; 0x61uy; 0xffuy; 0xffuy |]

                Expect.throwsT<Cbor.CborError>
                    (fun () -> Cbor.decode { AllowIndefinite = true; MaxDepth = 8 } bad |> ignore)
                    "a CBOR error"
            }

            testT
                "a key set fetch that gets no answer leaves the endpoint unavailable; a failed check refuses it"
                (fun () ->
                    task {
                        let refusal (e: exn) =
                            TeeModule.RunnerAttestation.IsRefusal(IOException($"runner r: {e.Message}", e))

                        let unavailable (what: string) (e: exn) =
                            Expect.isTrue (e :? Attest.KeySetUnavailable) $"{what}: %A{e}"
                            Expect.isFalse (refusal e) $"{what}: not a refusal"
                        // A TLS failure on the way to the provider is an outage too.
                        let! e =
                            keySetError (fun _ _ ->
                                raise (
                                    Net.Http.HttpRequestException(
                                        "connect failed",
                                        AuthenticationException "certificate"
                                    )
                                ))

                        unavailable "no connection" e

                        let hang (_: Net.Http.HttpRequestMessage) (ct: CancellationToken) =
                            task {
                                do! Task.Delay(Timeout.Infinite, ct)
                                return new Net.Http.HttpResponseMessage()
                            }

                        let! e = keySetError hang
                        unavailable "the 1 s client timeout" e
                        let! e = keySetError (fun _ _ -> answer 503 "busy")
                        unavailable "HTTP 503" e
                        let! e = keySetError (fun _ _ -> answer 200 """{ "issuer": "https://other.test" }""")
                        Expect.isTrue (e :? Jwt.AttestError) $"another issuer: %A{e}"
                        Expect.isTrue (refusal e) "a wrong issuer refuses"
                    })

            testT "the attestation HTTP client follows no redirect" (fun () ->
                task {
                    use server = new RedirectServer()

                    for bundle in [ ValueNone; ValueSome(X509Certificate2Collection()) ] do
                        use http = TeeModule.attestationHttp bundle
                        use! resp = http.GetAsync server.Url
                        Expect.equal (int resp.StatusCode) 307 "the redirect comes back as it is"

                    Expect.equal server.Reached 0 "nothing reached the target"
                })

            test "config: a URL listed twice needs the same TLS and attestation settings in each entry" {
                let dir = tempDir ()
                let pin = String('a', 64)
                let attested = $$""" "attestation": { "source": "pinned", "tls_key_pin": "{{pin}}" } """

                let parse (signers: string) (members: string) =
                    Web3SignerModule.parseSettings (
                        section
                            $$"""{ "signers": [ {{signers}} ],
                                   "groups": [ { "threshold": 2, "members": [ {{members}} ] } ] }"""
                            dir
                            false
                    )

                let others =
                    """{ "index": 2, "url": "https://w3s-2:9000" }, { "index": 3, "url": "https://w3s-3:9000" }"""

                let refused (what: string) (r: Result<Web3SignerModule.Settings, string list>) =
                    match r with
                    | Ok _ -> failtestf "%s: accepted" what
                    | Error e -> Expect.stringContains (String.Join("; ", e)) "https://w3s-1:9000/ is also at" what

                // The signer entry has no attestation, the group member has one: the member's
                // block would be dropped.
                parse
                    """{ "url": "https://w3s-1:9000" }"""
                    $$"""{ "index": 1, "url": "https://w3s-1:9000", {{attested}} }, {{others}}"""
                |> refused "signer without attestation, member with"

                parse
                    $$"""{ "url": "https://w3s-1:9000", {{attested}} }"""
                    $$"""{ "index": 1, "url": "https://w3s-1:9000", "ca_cert": "ca.pem", {{attested}} }, {{others}}"""
                |> refused "another ca_cert"

                parse
                    $$"""{ "url": "https://w3s-1:9000", {{attested}} }, { "url": "https://w3s-1:9000" }"""
                    $$"""{ "index": 1, "url": "https://w3s-9:9000" }, {{others}}"""
                |> refused "twice in signers"

                // The same settings in each entry, whitespace aside, are one endpoint.
                match
                    parse
                        $$"""{ "url": "https://w3s-1:9000", {{attested}} }"""
                        $$"""{ "index": 1, "url": "https://w3s-1:9000", "attestation": {"source":"pinned","tls_key_pin":"{{pin}}"} }, {{others}}"""
                with
                | Ok s -> Expect.equal s.Groups.Head.Members.Length 3 "parsed"
                | Error e -> failtestf "same settings refused: %A" e
            }

            test "config: a runner source with a cloud verifier and no setup_sha256 fails the check" {
                let dir = tempDir ()
                let crt, key = clientFiles dir
                TeeModule.runnerAttestationKind |> AttestationSources.register

                let check (setup: string) =
                    let s =
                        section
                            $$"""{ "source": "runner",
                                   "runner": { "name": "single", "address": "tcp:127.0.0.1:7100", "client_cert": "{{crt}}", "client_key": "{{key}}",
                                               "attestation": { "verifier": "gcp-cs", "gcp_image_digest": "sha256:{{String('d', 64)}}",
                                                                "gcp_audience": "signer-runner-identity", "gcp_hwmodels": [ "GCP_AMD_SEV" ] {{setup}} } } }"""
                            dir
                            false

                    TeeModule.runnerAttestationKind.Check s "w3s.attestation" s.Element.Value

                match check "" with
                | Ok() -> failtest "a gcp-cs runner without setup_sha256 passed"
                | Error m -> Expect.stringContains m "attestation.setup_sha256: required with the gcp-cs verifier" m

                Expect.equal (check $""", "setup_sha256": "{String('5', 64)}" """) (Ok()) "pinned"
            }

            test "the key set fetch takes a certificate from the CA bundle only with serverAuth" {
                let check (server: bool) =
                    let p = TeeTlsTests.makePki "attest ca" server
                    use chain = new X509Chain()
                    chain.ChainPolicy.ExtraStore.Add p.Intermediate |> ignore

                    (TeeModule.validateWithBundle (X509Certificate2Collection p.Root))
                        .Invoke(null, p.Leaf, chain, SslPolicyErrors.None)

                Expect.isTrue (check true) "serverAuth passes"
                Expect.isFalse (check false) "clientAuth only is refused"
            }
        ]
