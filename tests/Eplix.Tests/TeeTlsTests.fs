/// The TEE module's TLS and dial behaviour against a runner played by a TLS server on loopback:
/// the client certificate chain (root, intermediate, client) for a runner that trusts only the
/// root, the dial and its errors, and the CA bundle of the attestation HTTPS fetches.
module Eplix.Tests.TeeTlsTests

open System
open System.Buffers.Binary
open System.Collections.Concurrent
open System.IO
open System.Net
open System.Net.Http
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
open Eplix
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil

let private newKey () = ECDsa.Create(ECCurve.NamedCurves.nistP256)

let private asCa (req: CertificateRequest) =
    req.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))

    req.CertificateExtensions.Add(
        X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign ||| X509KeyUsageFlags.CrlSign, true)
    )

    req.CertificateExtensions.Add(X509SubjectKeyIdentifierExtension(req.PublicKey, false))

/// Through PKCS#12, so SslStream on Linux gets a key it can use.
let private withKey (c: X509Certificate2) (k: ECDsa) =
    use x = c.CopyWithPrivateKey k
    X509CertificateLoader.LoadPkcs12(x.Export X509ContentType.Pkcs12, null)

/// A root CA, an intermediate CA under it, and a leaf under the intermediate, for client or
/// server use (the server leaf names localhost and 127.0.0.1).
type Pki =
    {
        Root: X509Certificate2
        Intermediate: X509Certificate2
        Leaf: X509Certificate2
        LeafKey: ECDsa
    }

let makePki (name: string) (server: bool) =
    let now = DateTimeOffset.UtcNow
    use rootKey = newKey ()
    let rootReq = CertificateRequest($"CN={name} root", rootKey, HashAlgorithmName.SHA256)
    asCa rootReq
    let root = rootReq.CreateSelfSigned(now.AddDays -1.0, now.AddDays 30.0)
    use intKey = newKey ()
    let intReq = CertificateRequest($"CN={name} intermediate", intKey, HashAlgorithmName.SHA256)
    asCa intReq
    intReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false))
    use intCert = intReq.Create(root, now.AddDays -1.0, now.AddDays 20.0, [| 2uy |])
    let intermediate = withKey intCert intKey
    let leafKey = newKey ()
    let leafReq = CertificateRequest($"CN={name} leaf", leafKey, HashAlgorithmName.SHA256)
    leafReq.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, false))
    let usage = if server then "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2"
    let oids = OidCollection()
    oids.Add(Oid usage) |> ignore
    leafReq.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))

    if server then
        let san = SubjectAlternativeNameBuilder()
        san.AddDnsName "localhost"
        san.AddIpAddress IPAddress.Loopback
        leafReq.CertificateExtensions.Add(san.Build())

    leafReq.CertificateExtensions.Add(
        X509AuthorityKeyIdentifierExtension.CreateFromCertificate(intermediate, true, false)
    )

    use leaf = leafReq.Create(intermediate, now.AddDays -1.0, now.AddDays 10.0, [| 3uy |])

    {
        Root = X509CertificateLoader.LoadCertificate root.RawData
        Intermediate = X509CertificateLoader.LoadCertificate intermediate.RawData
        Leaf = withKey leaf leafKey
        LeafKey = leafKey
    }

/// Writes client.crt (the leaf, then the intermediate when `chain`) and client.key as PEM.
let private writeClient (dir: string) (p: Pki) (chain: bool) =
    let crt = Path.Combine(dir, (if chain then "chain.crt" else "leaf.crt"))

    let pems =
        if chain then
            [ p.Leaf.ExportCertificatePem(); p.Intermediate.ExportCertificatePem() ]
        else
            [ p.Leaf.ExportCertificatePem() ]

    File.WriteAllText(crt, String.Join("\n", pems) + "\n")
    let key = Path.Combine(dir, "client.key")
    File.WriteAllText(key, p.LeafKey.ExportPkcs8PrivateKeyPem())
    crt, key

/// Accepts a certificate only when it chains to `root` with the certificates the peer sent.
let private trustsOnly (root: X509Certificate2) =
    RemoteCertificateValidationCallback(fun _ cert chain _ ->
        match cert with
        | null -> false
        | cert ->
            use c = new X509Chain()
            c.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust
            c.ChainPolicy.CustomTrustStore.Add root |> ignore
            c.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck

            match chain with
            | null -> ()
            | chain -> c.ChainPolicy.ExtraStore.AddRange chain.ChainPolicy.ExtraStore

            use leaf = new X509Certificate2(cert)
            c.Build leaf)

[<RequireQualifiedAccess>]
type RunnerMode =
    /// Answers IDENTITY, and refuses every other request with SC_ERR_POLICY_FUTURE.
    | Plain
    /// Answers IDENTITY with a TLS key hash that is not its own, so the dial fails after an answer.
    | WrongIdentity
    /// Refuses an IDENTITY v1 request with UNSUPPORTED: it answers only version 3.
    | RefusesIdentityV1

/// A runner on 127.0.0.1: TLS 1.3 with a self-signed certificate, a client certificate that must
/// chain to `clientRoot`, a flag-path IDENTITY v1 answer (a request of another version gets
/// UNSUPPORTED, as from a tee-signer runner), and SIGN answered with a refusal. Records the
/// message types each connection received.
type FakeTlsRunner(clientRoot: X509Certificate2, mode: RunnerMode) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let connections = ConcurrentQueue<ConcurrentQueue<byte>>()
    let handshakeErrors = ConcurrentQueue<string>()
    let serverKey = newKey ()

    let serverCert =
        let req = CertificateRequest("CN=signer-runner", serverKey, HashAlgorithmName.SHA256)
        use c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 1.0)
        X509CertificateLoader.LoadPkcs12(c.Export X509ContentType.Pkcs12, null)

    let keyHash = SHA256.HashData(Der.subjectPublicKeyInfo serverCert.RawData)
    let mutable keyRelease = Root.Zero
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
                        SetupHash = Root.Of(Array.create 32 7uy)
                        Locked = zg
                        Open = zg
                        ApproverSetHash = Root.Zero
                        Order =
                            {
                                Kind = 0uy
                                Hash = Root.Zero
                                ActAt = 0UL
                            }
                        KeyReleaseHash = keyRelease
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
                TlsKeyHash = (if mode = RunnerMode.WrongIdentity then Array.zeroCreate 32 else keyHash)
                Attestation =
                    {
                        Platform = "dev"
                        Format = "test"
                        UserData = [||]
                        Document = [||]
                    }
            }

        { id with
            Attestation =
                { id.Attestation with
                    UserData = Wire.identityUserData nonce id
                }
        }

    let serve (client: TcpClient) =
        task {
            use client = client
            use ssl = new SslStream(client.GetStream(), false, trustsOnly clientRoot)

            let opts =
                SslServerAuthenticationOptions(
                    ServerCertificate = serverCert,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                )

            let types = ConcurrentQueue<byte>()
            connections.Enqueue types

            try
                do! ssl.AuthenticateAsServerAsync(opts, cts.Token)
                let len = Array.zeroCreate<byte> 4

                while true do
                    do! ssl.ReadExactlyAsync(len.AsMemory(), cts.Token)
                    let body = Array.zeroCreate<byte>(int (BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan len)))
                    do! ssl.ReadExactlyAsync(body.AsMemory(), cts.Token)
                    let f = Wire.decodeBody body
                    types.Enqueue f.Type

                    let answer =
                        match LanguagePrimitives.EnumOfValue<byte, Wire.MsgType> f.Type with
                        | Wire.MsgType.Identity ->
                            let n = int (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(f.Payload, 0, 2)))
                            let asked = f.Payload[f.Payload.Length - 1]
                            let answers = if mode = RunnerMode.RefusesIdentityV1 then 3uy else Wire.IdentityVersion

                            if asked <> answers then
                                Wire.encodeError
                                    {
                                        Code = Wire.Status.Unsupported
                                        Detail =
                                            $"wire: ATTEST or IDENTITY request of another version: version {asked}, this runner answers version {answers}"
                                    }
                            else
                                Array.append [| 0uy; 0uy |] (Wire.encodeIdentity (identity f.Payload[2 .. 1 + n]))
                        | _ ->
                            Wire.encodeError
                                {
                                    Code = Wire.Status.PolicyFuture
                                    Detail = "too early"
                                }

                    let frame = Wire.encodeFrame (f.Type ||| Wire.ResponseFlag) f.Id (ReadOnlySpan answer)
                    do! ssl.WriteAsync(frame.AsMemory(), cts.Token)
                    do! ssl.FlushAsync cts.Token
            with e ->
                if types.IsEmpty then
                    handshakeErrors.Enqueue e.Message
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

    /// The message types each connection received, in order of the connections.
    member _.Connections = [ for c in connections -> List.ofSeq c ]

    member _.HandshakeErrors = List.ofSeq handshakeErrors

    /// The key_release_hash of its IDENTITY answers (zero: a runner without a key release policy).
    member _.KeyRelease
        with get () = keyRelease
        and set v = keyRelease <- v

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

let verifier: Attest.Verifier =
    {
        Name = "test"
        Document = fun _ _ _ _ _ -> Task.FromResult()
        Pins =
            {
                Setup = []
                MinLocked = 0UL
                MinOpen = 0UL
                AllowUnpinned = true
                Dev = true
                KeyRelease = []
            }
    }

let private settings (port: int) (cert: SslStreamCertificateContext) : RunnerSettings =
    {
        Name = "fake"
        Host = "127.0.0.1"
        Port = port
        ClientCert = TlsFile<_>.Fixed(cert, DateTimeOffset.MaxValue)
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Verifier = verifier
    }

let private runnerConfig (crt: string) (key: string) : TeeModule.RunnerConfig =
    {
        Name = "fake"
        Host = "127.0.0.1"
        Port = 1
        ClientCert = crt
        ClientKey = key
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Connections = 1
        Attestation = Attest.Settings.Empty
    }

let private load crt key =
    match TeeModule.loadClientCert (runnerConfig crt key) with
    | Ok c -> c
    | Error e -> failtest e

let private dial (s: RunnerSettings) =
    task {
        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
        return! RunnerConnection.Dial(s, (fun () -> DateTimeOffset.UtcNow), cts.Token)
    }

/// An HTTPS server on 127.0.0.1 that sends its intermediate and answers every request with "{}".
type private HttpsServer(p: Pki) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    do listener.Start()

    let ctx =
        SslStreamCertificateContext.Create(p.Leaf, X509Certificate2Collection([| p.Intermediate |]), offline = true)

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! client = listener.AcceptTcpClientAsync cts.Token

                    task {
                        try
                            use client = client
                            use ssl = new SslStream(client.GetStream())

                            do!
                                ssl.AuthenticateAsServerAsync(
                                    SslServerAuthenticationOptions(ServerCertificateContext = ctx),
                                    cts.Token
                                )

                            let buf = Array.zeroCreate<byte> 8192
                            let sb = StringBuilder()

                            while not (sb.ToString().Contains "\r\n\r\n") do
                                let! n = ssl.ReadAsync(buf, 0, buf.Length)

                                if n = 0 then
                                    raise (EndOfStreamException())

                                sb.Append(Encoding.ASCII.GetString(buf, 0, n)) |> ignore

                            let head =
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"

                            do! ssl.WriteAsync(ReadOnlyMemory(Encoding.ASCII.GetBytes head))
                            do! ssl.FlushAsync()
                        with _ ->
                            ()
                    }
                    |> ignore
            with _ ->
                ()
        }

    member _.Url = $"https://localhost:{(listener.LocalEndpoint :?> IPEndPoint).Port}/x"

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

let private section (json: string) (dir: string) : ConfigSection =
    let doc = JsonDocument.Parse json

    {
        Element = ValueSome doc.RootElement
        BaseDir = dir
        Mainnet = false
    }

[<Tests>]
let tests =
    testList
        "tee tls"
        [
            testT
                "a client certificate under an intermediate: the chain from client_cert reaches a runner that trusts only the root"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let client = makePki "client" false
                        use runner = new FakeTlsRunner(client.Root, RunnerMode.Plain)
                        let crt, key = writeClient dir client true
                        let! c = dial (settings runner.Port (load crt key))
                        c.Close()
                        // The same certificate without the intermediate, as the module loaded it before
                        // (X509Certificate2.CreateFromPemFile keeps only the first certificate): refused.
                        let leafOnly =
                            SslStreamCertificateContext.Create(
                                X509Certificate2.CreateFromPemFile(crt, key),
                                null,
                                offline = true
                            )

                        let! failed =
                            task {
                                try
                                    let! c = dial (settings runner.Port leafOnly)
                                    c.Close()
                                    return false
                                with _ ->
                                    return true
                            }

                        Expect.isTrue failed "without the intermediate the runner refuses the client"
                        Expect.isNonEmpty runner.HandshakeErrors "the runner refused a handshake"
                        // A file with only the leaf loads too, and is refused the same way.
                        let crt1, key1 = writeClient dir client false

                        let! failed1 =
                            task {
                                try
                                    let! c = dial (settings runner.Port (load crt1 key1))
                                    c.Close()
                                    return false
                                with _ ->
                                    return true
                            }

                        Expect.isTrue failed1 "a leaf-only file gets no chain"
                    })

            test "an expired intermediate in client_cert fails the load and names it" {
                let dir = tempDir ()
                let p = makePki "old" false
                let now = DateTimeOffset.UtcNow
                use k = newKey ()
                let req = CertificateRequest("CN=expired intermediate", k, HashAlgorithmName.SHA256)
                asCa req
                use old = req.CreateSelfSigned(now.AddDays -10.0, now.AddDays -1.0)
                let crt = Path.Combine(dir, "c.crt")
                File.WriteAllText(crt, p.Leaf.ExportCertificatePem() + "\n" + old.ExportCertificatePem() + "\n")
                let key = Path.Combine(dir, "c.key")
                File.WriteAllText(key, p.LeafKey.ExportPkcs8PrivateKeyPem())

                match TeeModule.loadClientCert (runnerConfig crt key) with
                | Error e -> Expect.stringContains e "expired intermediate" "named"
                | Ok _ -> failtest "loaded an expired chain"
            }

            testT "a refusal comes back with its code and detail, on the connection of the dial" (fun () ->
                task {
                    let dir = tempDir ()
                    let client = makePki "client" false
                    use runner = new FakeTlsRunner(client.Root, RunnerMode.Plain)
                    let crt, key = writeClient dir client true
                    let! c = dial (settings runner.Port (load crt key))
                    let! f = c.Send(Wire.MsgType.Sign, [| 1uy |], CancellationToken.None)

                    match Wire.decodeResponse f.Payload with
                    | Error r -> Expect.equal (r.Code, r.Detail) (Wire.Status.PolicyFuture, "too early") "a refusal"
                    | Ok _ -> failtest "a refusal"

                    c.Close()

                    Expect.equal
                        runner.Connections
                        [ [ byte Wire.MsgType.Identity; byte Wire.MsgType.Sign ] ]
                        "IDENTITY and SIGN on one connection"
                })

            testT
                "a runner that refuses IDENTITY v1 is refused with its own words, after one dial, with no other IDENTITY version tried"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let client = makePki "client" false
                        use runner = new FakeTlsRunner(client.Root, RunnerMode.RefusesIdentityV1)
                        let crt, key = writeClient dir client true

                        let! err =
                            task {
                                try
                                    let! c = dial (settings runner.Port (load crt key))
                                    c.Close()
                                    return ""
                                with e ->
                                    return e.Message
                            }

                        Expect.stringContains
                            err
                            "does not speak IDENTITY v1 of tee-signer"
                            "names the version this build speaks"

                        Expect.stringContains
                            err
                            "version 1, this runner answers version 3"
                            "carries the runner's detail"

                        Expect.equal runner.Connections [ [ byte Wire.MsgType.Identity ] ] "one dial, no retry"
                    })

            testT "no fallback after an answer: an IDENTITY answer that fails a check fails the dial" (fun () ->
                task {
                    let dir = tempDir ()
                    let client = makePki "client" false
                    use runner = new FakeTlsRunner(client.Root, RunnerMode.WrongIdentity)
                    let crt, key = writeClient dir client true

                    let! err =
                        task {
                            try
                                let! c = dial (settings runner.Port (load crt key))
                                c.Close()
                                return ""
                            with e ->
                                return e.Message
                        }

                    Expect.stringContains err "attested identity names" "the identity check failed"
                    Expect.equal runner.Connections [ [ byte Wire.MsgType.Identity ] ] "one dial, no retry"
                })

            testT
                "attestation_ca_file: the fetches trust the bundle's CAs, with the server's intermediate, and not the system store"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let p = makePki "issuer" true
                        use server = new HttpsServer(p)
                        let bundle = Path.Combine(dir, "ca.pem")
                        File.WriteAllText(bundle, p.Root.ExportCertificatePem())

                        let cas =
                            match TeeModule.loadCaBundle bundle with
                            | Ok c -> c
                            | Error e -> failtest e

                        use http = TeeModule.attestationHttp (ValueSome cas)
                        let! body = http.GetStringAsync server.Url
                        Expect.equal body "{}" "fetched through the bundle"
                        use system = TeeModule.attestationHttp ValueNone

                        let! sysFailed =
                            task {
                                try
                                    let! _ = system.GetStringAsync server.Url in return false
                                with :? HttpRequestException ->
                                    return true
                            }

                        Expect.isTrue sysFailed "the system store does not hold the test CA"
                        let other = makePki "other" true
                        let otherFile = Path.Combine(dir, "other.pem")
                        File.WriteAllText(otherFile, other.Root.ExportCertificatePem())

                        let otherCas =
                            match TeeModule.loadCaBundle otherFile with
                            | Ok c -> c
                            | Error e -> failtest e

                        use wrong = TeeModule.attestationHttp (ValueSome otherCas)

                        let! wrongFailed =
                            task {
                                try
                                    let! _ = wrong.GetStringAsync server.Url in return false
                                with :? HttpRequestException ->
                                    return true
                            }

                        Expect.isTrue wrongFailed "another CA's bundle refuses the server"
                    })

            test "attestation_ca_file in the config: parsed relative to it; a missing or empty bundle fails the start" {
                let dir = tempDir ()

                let runner =
                    """{ "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } }"""

                let json f =
                    sprintf
                        "{ \"runners\": [ %s ], \"keys\": [ \"0x%s\" ], \"attestation_ca_file\": %s }"
                        runner
                        (String('a', 96))
                        f

                match TeeModule.parseSettings (section (json "\"ca.pem\"") dir) with
                | Ok s ->
                    Expect.equal s.AttestationCaFile (ValueSome(Path.Combine(dir, "ca.pem"))) "relative to the config"

                    Expect.isTrue
                        (match TeeModule.discoveredKeys s with
                         | Error e -> e.Contains "ca.pem"
                         | Ok _ -> false)
                        "a missing file fails"

                    File.WriteAllText(Path.Combine(dir, "ca.pem"), "not a certificate\n")

                    Expect.isTrue
                        (match TeeModule.discoveredKeys s with
                         | Error e -> e.Contains "no PEM certificate"
                         | Ok _ -> false)
                        "no certificate fails"
                | Error e -> failtestf "%s" (String.Join("; ", e))

                match TeeModule.parseSettings (section (json "\"\"") dir) with
                | Ok _ -> failtest "an empty path"
                | Error e -> Expect.stringContains (String.Join("; ", e)) "attestation_ca_file" "named"

                match TeeModule.parseSettings (section (json "7") dir) with
                | Ok _ -> failtest "a number"
                | Error _ -> ()
            }
        ]
