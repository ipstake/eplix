/// Client certificate chains of the Web3Signer and Dirk modules: a client
/// certificate from an intermediate CA, against a server that trusts only the root, must reach
/// the server with the intermediate.
module Eplix.Tests.ClientChainTests

open System
open System.Collections.Concurrent
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Tests.TestUtil
open Eplix.Tests.TeeTlsTests

/// Accepts a client certificate only when it chains to `root` with the certificates the peer sent.
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

/// A TLS server on 127.0.0.1 that requires a client certificate chaining to `clientRoot` and
/// records the result of each handshake. With `http` it answers one HTTP/1.1 request with an
/// empty JSON list; without, it offers h2 and closes after the handshake. Its certificate is
/// self-signed, or with `eku` issued by a CA of its own with that one extended key usage.
type private ChainServer(clientRoot: X509Certificate2, http: bool, ?eku: string) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let results = ConcurrentQueue<bool>()
    let key = ECDsa.Create(ECCurve.NamedCurves.nistP256)

    let ca, cert =
        let now = DateTimeOffset.UtcNow
        let req = CertificateRequest("CN=signer", key, HashAlgorithmName.SHA256)
        let san = SubjectAlternativeNameBuilder()
        san.AddDnsName "localhost"
        san.AddIpAddress IPAddress.Loopback
        req.CertificateExtensions.Add(san.Build())

        match eku with
        | None ->
            use c = req.CreateSelfSigned(now.AddDays -1.0, now.AddDays 1.0)
            let cert = X509CertificateLoader.LoadPkcs12(c.Export X509ContentType.Pkcs12, null)
            cert, cert
        | Some oid ->
            use caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
            let caReq = CertificateRequest("CN=signer ca", caKey, HashAlgorithmName.SHA256)
            caReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
            caReq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
            let ca = caReq.CreateSelfSigned(now.AddDays -1.0, now.AddDays 1.0)
            let oids = OidCollection()
            oids.Add(Oid oid) |> ignore
            req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
            use leaf = req.Create(ca, now.AddDays -1.0, now.AddDays 1.0, [| 9uy |])
            use withKey = leaf.CopyWithPrivateKey key
            ca, X509CertificateLoader.LoadPkcs12(withKey.Export X509ContentType.Pkcs12, null)

    do listener.Start()

    let serve (tcp: TcpClient) =
        task {
            use tcp = tcp
            use ssl = new SslStream(tcp.GetStream(), false)
            let protocol = if http then SslApplicationProtocol.Http11 else SslApplicationProtocol.Http2

            let opts =
                SslServerAuthenticationOptions(
                    ServerCertificate = cert,
                    ClientCertificateRequired = true,
                    RemoteCertificateValidationCallback = trustsOnly clientRoot,
                    ApplicationProtocols = Collections.Generic.List([ protocol ])
                )

            try
                do! ssl.AuthenticateAsServerAsync(opts, cts.Token)
                results.Enqueue true

                if http then
                    let buf = Array.zeroCreate<byte> 4096
                    let! _ = ssl.ReadAsync(buf, 0, buf.Length, cts.Token)

                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"

                    do! ssl.WriteAsync(Encoding.ASCII.GetBytes resp, cts.Token)
            with _ ->
                results.Enqueue false
        }

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! tcp = listener.AcceptTcpClientAsync(cts.Token)
                    serve tcp |> ignore
            with _ ->
                ()
        }

    member _.Port = (listener.LocalEndpoint :?> IPEndPoint).Port
    member _.Results = List.ofSeq results

    member _.CaPem(dir: string) =
        let f = Path.Combine(dir, "server-ca.pem")
        File.WriteAllText(f, ca.ExportCertificatePem())
        f

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

/// The leaf (and the intermediate when `chain`) in one PEM file, and the key in another.
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

let private waitResult (s: ChainServer) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while s.Results.IsEmpty && sw.Elapsed < TimeSpan.FromSeconds 5.0 do
            do! Task.Delay 10

        return List.tryHead s.Results
    }

let private web3signerWith (chain: bool) (eku: string option) =
    task {
        let dir = tempDir ()
        let pki = makePki "w3s client" false
        use server = new ChainServer(pki.Root, true, ?eku = eku)
        let crt, key = writeClient dir pki chain

        let endpoint: Eplix.Backend.Web3Signer.EndpointSettings =
            {
                Url = Uri $"https://127.0.0.1:{server.Port}"
                Tls =
                    {
                        CaCert = ValueSome(server.CaPem dir)
                        ClientCert = ValueSome crt
                        ClientKey = ValueSome key
                    }
                Attestation = ValueNone
            }

        match Eplix.Backend.Web3Signer.HttpSigner.loadTls endpoint.Tls "test" Log.none TimeProvider.System with
        | Error e -> return failtestf "load: %s" e
        | Ok tls ->
            let api = Eplix.Backend.Web3Signer.HttpSigner.create endpoint tls Web3SignerTests.spec.Value 4
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
            let! keys = api.PublicKeys cts.Token
            let! accepted = waitResult server
            return accepted, Result.isOk keys
    }

let private web3signer (chain: bool) = web3signerWith chain None

let private dirkWith (chain: bool) (eku: string option) =
    task {
        let dir = tempDir ()
        let pki = makePki "dirk client" false
        use server = new ChainServer(pki.Root, false, ?eku = eku)
        let crt, key = writeClient dir pki chain

        let tls: Eplix.Backend.Dirk.TlsSettings =
            {
                CaCert = server.CaPem dir
                ClientCert = crt
                ClientKey = key
            }

        match Eplix.Backend.Dirk.GrpcDirk.loadTls tls Log.none TimeProvider.System with
        | Error e -> return failtestf "load: %s" e
        | Ok loaded ->
            let api = Eplix.Backend.Dirk.GrpcDirk.connect $"127.0.0.1:{server.Port}" loaded
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
            let! r = api.ListAccounts [ "w" ] cts.Token
            api.Dispose()
            let! accepted = waitResult server
            return accepted, r
    }

let private dirk (chain: bool) =
    task {
        let! accepted, _ = dirkWith chain None
        return accepted
    }

let private clientAuth = "1.3.6.1.5.5.7.3.2"
let private serverAuth = "1.3.6.1.5.5.7.3.1"

[<Tests>]
let tests =
    testList
        "client chain"
        [
            testT "web3signer: the client chain reaches a signer that trusts only the root" (fun () ->
                task {
                    let! accepted, ok = web3signer true
                    Expect.equal accepted (Some true) "the signer accepted the client chain"
                    Expect.isTrue ok "the key list came back"
                })
            testT "web3signer: a client certificate without its intermediate is refused" (fun () ->
                task {
                    let! accepted, _ = web3signer false
                    Expect.equal accepted (Some false) "refused without the intermediate"
                })
            testT "dirk: the client chain reaches a Dirk that trusts only the root" (fun () ->
                task {
                    let! accepted = dirk true
                    Expect.equal accepted (Some true) "Dirk accepted the client chain"
                })
            testT "dirk: a client certificate without its intermediate is refused" (fun () ->
                task {
                    let! accepted = dirk false
                    Expect.equal accepted (Some false) "refused without the intermediate"
                })
            testT "web3signer: a server certificate for clientAuth only is refused, serverAuth passes" (fun () ->
                task {
                    // The server may finish its side of the handshake before the client checks the
                    // certificate, so only the client's result tells.
                    let! _, ok = web3signerWith true (Some clientAuth)
                    Expect.isFalse ok "no key list from a client-only certificate"
                    let! accepted, ok = web3signerWith true (Some serverAuth)
                    Expect.equal accepted (Some true) "serverAuth handshake"
                    Expect.isTrue ok "the key list came back"
                })
            testT "dirk: a server certificate for clientAuth only is refused, serverAuth passes" (fun () ->
                task {
                    let! _, r = dirkWith true (Some clientAuth)

                    match r with
                    | Error(Eplix.Backend.Dirk.CallError.Failure(Transport m)) ->
                        Expect.stringContains m "SSL" "a TLS failure"
                    | other -> failtestf "expected a TLS failure, got %A" other
                    // The test server closes after the handshake, so the call fails after it either way.
                    let! _, r = dirkWith true (Some serverAuth)

                    match r with
                    | Error(Eplix.Backend.Dirk.CallError.Failure(Transport m)) ->
                        Expect.isFalse (m.Contains "SSL") $"not a TLS failure: {m}"
                    | other -> failtestf "expected a call failure, got %A" other
                })
        ]
