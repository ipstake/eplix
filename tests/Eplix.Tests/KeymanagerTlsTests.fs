/// The keymanager API over HTTPS: config, a certificate chain the
/// server sends whole, and client certificates.
module Eplix.Tests.KeymanagerTlsTests

open System
open System.IO
open System.Net
open System.Net.Http
open System.Net.Security
open System.Net.Sockets
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Keymanager
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private freePort () =
    let l = new TcpListener(IPAddress.Loopback, 0)
    l.Start()
    let p = (l.LocalEndpoint :?> IPEndPoint).Port
    l.Stop()
    p

let private now = DateTimeOffset.UtcNow

/// NotBefore of the test certificates: before the fake VC clock's start in 2023 (genesis
/// 1,700,000,000), which judges a reloaded certificate's NotBefore.
let private validFrom = DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero)

let private serial () = RandomNumberGenerator.GetBytes 8

/// A self-signed CA.
let private rootCa (name: string) =
    use key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256)
    req.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    req.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
    req.CreateSelfSigned(validFrom, now.AddDays 30.0)

/// An intermediate CA signed by `issuer`.
let private intermediate (issuer: X509Certificate2) (name: string) =
    let key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256)
    req.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    req.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
    use signed = req.Create(issuer, validFrom, now.AddDays 20.0, serial ())
    signed.CopyWithPrivateKey key

/// A leaf for 127.0.0.1 and localhost signed by `issuer`, for server or client use. Returns the
/// certificate (with its key) and the key.
let private leaf (issuer: X509Certificate2) (client: bool) =
    let key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256)
    let san = SubjectAlternativeNameBuilder()
    san.AddDnsName "localhost"
    san.AddIpAddress IPAddress.Loopback
    req.CertificateExtensions.Add(san.Build())
    req.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, false))
    let usage = if client then "1.3.6.1.5.5.7.3.2" else "1.3.6.1.5.5.7.3.1"
    let oids = OidCollection()
    oids.Add(Oid usage) |> ignore
    req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
    use signed = req.Create(issuer, validFrom, now.AddDays 10.0, serial ())
    let withKey = signed.CopyWithPrivateKey key
    X509CertificateLoader.LoadPkcs12(withKey.Export X509ContentType.Pkcs12, null), key

/// Root, intermediate and a server leaf under it, written as PEM: cert.pem (leaf, then the
/// intermediate), leaf-only.pem, key.pem and root.pem.
type private Pki =
    {
        Root: X509Certificate2
        Dir: string
        Cert: string
        LeafOnly: string
        Key: string
        RootFile: string
    }

let private pki () =
    let dir = tempDir ()
    let root = rootCa "eplix test root"
    let inter = intermediate root "eplix test intermediate"
    let server, key = leaf inter false

    let write (name: string) (text: string) =
        let f = Path.Combine(dir, name)
        File.WriteAllText(f, text)
        f

    {
        Root = root
        Dir = dir
        Cert = write "cert.pem" (server.ExportCertificatePem() + "\n" + inter.ExportCertificatePem() + "\n")
        LeafOnly = write "leaf-only.pem" (server.ExportCertificatePem() + "\n")
        Key = write "key.pem" (key.ExportPkcs8PrivateKeyPem())
        RootFile = write "root.pem" (root.ExportCertificatePem())
    }

/// A client that trusts only `root` (no system store, no downloads), with an optional client
/// certificate.
let private client (root: X509Certificate2) (port: int) (clientCert: X509Certificate2 option) =
    let policy = new X509ChainPolicy()
    policy.TrustMode <- X509ChainTrustMode.CustomRootTrust
    policy.CustomTrustStore.Add root |> ignore
    policy.RevocationMode <- X509RevocationMode.NoCheck
    policy.DisableCertificateDownloads <- true
    let handler = new SocketsHttpHandler()
    handler.SslOptions.CertificateChainPolicy <- policy

    clientCert
    |> Option.iter (fun c ->
        handler.SslOptions.ClientCertificates <- X509CertificateCollection [| c :> X509Certificate |])

    new HttpClient(handler, BaseAddress = Uri $"https://127.0.0.1:{port}", Timeout = TimeSpan.FromSeconds 10.0)

let private parseSection (json: string) (dir: string) =
    let doc = Text.Json.JsonDocument.Parse json

    KeymanagerModule.parse
        {
            Element = ValueSome doc.RootElement
            BaseDir = dir
            Mainnet = false
        }

/// Runs the VC with the keymanager module only, with this module section, and calls f with the
/// API token.
let private withVc (section: string) (dir: string) (f: string -> Task<unit>) =
    task {
        let h = harness ()
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "modules": { "keymanager": {{section}} } }"""

        let modules = [ KeymanagerModule.create () ]

        match
            Config.parse configText dir [ "keymanager" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> failtestf "%A" es
        | Ok config ->
            use cts = new CancellationTokenSource()
            let log, _ = Log.memory ()
            let ready = TaskCompletionSource<CoreServices>()

            let run =
                Runner.run
                    {
                        Config = config
                        Modules = modules
                        Http = new HttpClient(h.Node, false)
                        Time = h.Time
                        Log = log
                        OnSlotDone = h.Waiter.Done
                        OnReady = fun core _ -> ready.TrySetResult core |> ignore
                    }
                    cts.Token

            let! _ = ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
            let token = File.ReadAllText(Path.Combine(dir, "data", "api-token.txt")).Trim()

            try
                do! f token
            finally
                cts.Cancel()

            let! _ = run
            ()
    }

/// withVc that also hands f the harness, to move the VC clock.
let private withVcClock (section: string) (dir: string) (f: Harness -> string -> Task<unit>) =
    task {
        let h = harness ()
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "modules": { "keymanager": {{section}} } }"""

        let modules = [ KeymanagerModule.create () ]

        match
            Config.parse configText dir [ "keymanager" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> failtestf "%A" es
        | Ok config ->
            use cts = new CancellationTokenSource()
            let log, _ = Log.memory ()
            let ready = TaskCompletionSource<CoreServices>()

            let run =
                Runner.run
                    {
                        Config = config
                        Modules = modules
                        Http = new HttpClient(h.Node, false)
                        Time = h.Time
                        Log = log
                        OnSlotDone = h.Waiter.Done
                        OnReady = fun core _ -> ready.TrySetResult core |> ignore
                    }
                    cts.Token

            let! _ = ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
            let token = File.ReadAllText(Path.Combine(dir, "data", "api-token.txt")).Trim()

            try
                do! f h token
            finally
                cts.Cancel()

            let! _ = run
            ()
    }

let private get (c: HttpClient) (token: string) =
    task {
        use req = new HttpRequestMessage(HttpMethod.Get, "/eth/v1/keystores")
        req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", token)
        use! resp = c.SendAsync req
        return int resp.StatusCode
    }

let private fails (t: unit -> Task<int>) (what: string) =
    task {
        try
            let! s = t ()
            failtestf "%s: got HTTP %d" what s
        with
        | :? HttpRequestException -> ()
        | :? TaskCanceledException -> ()
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "keymanager-tls"
        [
            test "config: TLS files, loopback rule and refusals" {
                let p = pki ()

                let ok (json: string) =
                    match parseSection json p.Dir with
                    | Ok s -> s
                    | Error es -> failtestf "%A" es

                let refused (json: string) (part: string) =
                    match parseSection json p.Dir with
                    | Ok _ -> failtestf "accepted %s" json
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"{part} in %A{es}"

                let d = ok "{}"
                Expect.equal d.Tls ValueNone "plain by default"
                Expect.isTrue (IPAddress.IsLoopback d.Address) "loopback by default"

                let s =
                    ok
                        """{ "tls_cert": "cert.pem", "tls_key": "key.pem", "client_ca": "root.pem", "address": "0.0.0.0" }"""

                Expect.equal
                    s.Tls
                    (ValueSome
                        {
                            CertFile = p.Cert
                            KeyFile = p.Key
                            ClientCa = ValueSome p.RootFile
                        })
                    "paths resolved"

                Expect.isTrue
                    (ok """{ "address": "0.0.0.0", "allow_plain_http": true }""").AllowPlainHttp
                    "plain HTTP when asked"

                Expect.isTrue (ok """{ "address": "::1" }""").Tls.IsNone "IPv6 loopback is plain"
                refused """{ "address": "0.0.0.0" }""" "not a loopback address"
                refused """{ "address": "192.0.2.1", "allow_plain_http": false }""" "not a loopback address"
                refused """{ "tls_cert": "cert.pem" }""" "go together"
                refused """{ "tls_key": "key.pem" }""" "go together"
                refused """{ "client_ca": "root.pem" }""" "client_ca needs tls_cert"
                refused """{ "tls_cert": "missing.pem", "tls_key": "key.pem" }""" "does not exist"
                refused """{ "allow_plain_http": "yes" }""" "true or false"
                refused """{ "tls": true }""" "unknown field"
            }

            test "the PEM chain loads: leaf with its key, the intermediate apart" {
                let p = pki ()
                let leafCert, chain = KeymanagerModule.loadServerCertificate p.Cert p.Key
                Expect.isTrue leafCert.HasPrivateKey "leaf has its key"
                Expect.equal leafCert.Subject "CN=localhost" "leaf first"
                Expect.equal chain.Count 1 "one intermediate"
                Expect.equal chain[0].Subject "CN=eplix test intermediate" "the intermediate"
                let _, none = KeymanagerModule.loadServerCertificate p.LeafOnly p.Key
                Expect.equal none.Count 0 "no intermediate in a leaf-only file"
            }

            testT
                "HTTPS with the chain: a client that trusts only the root gets answers; plain HTTP does not"
                (fun () ->
                    task {
                        let p = pki ()
                        let port = freePort ()

                        do!
                            withVc
                                $$"""{ "port": {{port}}, "tls_cert": "{{p.Cert}}", "tls_key": "{{p.Key}}" }"""
                                p.Dir
                                (fun token ->
                                    task {
                                        use c = client p.Root port None
                                        let! s = get c token
                                        Expect.equal s 200 "token accepted over HTTPS"
                                        let! s = get c "wrong"
                                        Expect.equal s 403 "wrong token refused over HTTPS"

                                        use plain =
                                            new HttpClient(
                                                BaseAddress = Uri $"http://127.0.0.1:{port}",
                                                Timeout = TimeSpan.FromSeconds 5.0
                                            )

                                        do! fails (fun () -> get plain token) "plain HTTP on the TLS port"
                                        use other = client (rootCa "another root") port None
                                        do! fails (fun () -> get other token) "a client that trusts another root"
                                    })
                    })

            testT "HTTPS with a leaf-only file: a client that trusts only the root cannot build the chain" (fun () ->
                task {
                    let p = pki ()
                    let port = freePort ()

                    do!
                        withVc
                            $$"""{ "port": {{port}}, "tls_cert": "{{p.LeafOnly}}", "tls_key": "{{p.Key}}" }"""
                            p.Dir
                            (fun token ->
                                task {
                                    use c = client p.Root port None
                                    do! fails (fun () -> get c token) "no intermediate sent"
                                })
                })

            testT "client_ca: a client certificate from that CA is required" (fun () ->
                task {
                    let p = pki ()
                    let port = freePort ()
                    let clientInter = intermediate p.Root "eplix client intermediate"
                    let good, _ = leaf p.Root true
                    let viaIntermediate, _ = leaf clientInter true
                    let strangerRoot = rootCa "stranger"
                    let stranger, _ = leaf strangerRoot true
                    // The client CA file holds the root and the client intermediate.
                    let caFile = Path.Combine(p.Dir, "clients.pem")

                    File.WriteAllText(
                        caFile,
                        p.Root.ExportCertificatePem() + "\n" + clientInter.ExportCertificatePem() + "\n"
                    )

                    do!
                        withVc
                            $$"""{ "port": {{port}}, "tls_cert": "{{p.Cert}}", "tls_key": "{{p.Key}}", "client_ca": "{{caFile}}" }"""
                            p.Dir
                            (fun token ->
                                task {
                                    use c = client p.Root port (Some good)
                                    let! s = get c token
                                    Expect.equal s 200 "client certificate from the CA"
                                    use c2 = client p.Root port (Some viaIntermediate)
                                    let! s = get c2 token
                                    Expect.equal s 200 "client certificate under the listed intermediate"
                                    use none = client p.Root port None
                                    do! fails (fun () -> get none token) "no client certificate"
                                    use bad = client p.Root port (Some stranger)
                                    do! fails (fun () -> get bad token) "a client certificate from another CA"
                                })
                })

            testT "client_ca with the root only: a client that sends its intermediate is accepted" (fun () ->
                task {
                    let p = pki ()
                    let port = freePort ()
                    let clientInter = intermediate p.Root "eplix client intermediate"
                    let viaIntermediate, _ = leaf clientInter true
                    let caFile = Path.Combine(p.Dir, "root-only.pem")
                    File.WriteAllText(caFile, p.Root.ExportCertificatePem())
                    let interPublic = X509CertificateLoader.LoadCertificate clientInter.RawData

                    let withChain =
                        SslStreamCertificateContext.Create(
                            viaIntermediate,
                            X509Certificate2Collection interPublic,
                            offline = true
                        )

                    do!
                        withVc
                            $$"""{ "port": {{port}}, "tls_cert": "{{p.Cert}}", "tls_key": "{{p.Key}}", "client_ca": "{{caFile}}" }"""
                            p.Dir
                            (fun token ->
                                task {
                                    let policy = new X509ChainPolicy()
                                    policy.TrustMode <- X509ChainTrustMode.CustomRootTrust
                                    policy.CustomTrustStore.Add p.Root |> ignore
                                    policy.RevocationMode <- X509RevocationMode.NoCheck
                                    policy.DisableCertificateDownloads <- true
                                    let handler = new SocketsHttpHandler()
                                    handler.SslOptions.CertificateChainPolicy <- policy
                                    handler.SslOptions.ClientCertificateContext <- withChain

                                    use chained =
                                        new HttpClient(
                                            handler,
                                            BaseAddress = Uri $"https://127.0.0.1:{port}",
                                            Timeout = TimeSpan.FromSeconds 10.0
                                        )

                                    let! s = get chained token

                                    Expect.equal
                                        s
                                        200
                                        "the intermediate the client sent completes the chain to the root"

                                    use leafOnly = client p.Root port (Some viaIntermediate)

                                    do!
                                        fails
                                            (fun () -> get leafOnly token)
                                            "without the intermediate the chain does not reach the root"
                                })
                })

            testT
                "client_ca with the root only: every new connection of a client that sends its intermediate is accepted, TLS 1.3 and 1.2 (resumption)"
                (fun () ->
                    task {
                        let p = pki ()
                        let port = freePort ()
                        let clientInter = intermediate p.Root "eplix client intermediate"
                        let viaIntermediate, _ = leaf clientInter true
                        let caFile = Path.Combine(p.Dir, "root-only.pem")
                        File.WriteAllText(caFile, p.Root.ExportCertificatePem())
                        let interPublic = X509CertificateLoader.LoadCertificate clientInter.RawData

                        let withChain =
                            SslStreamCertificateContext.Create(
                                viaIntermediate,
                                X509Certificate2Collection interPublic,
                                offline = true
                            )

                        let chained (protocols: Security.Authentication.SslProtocols) =
                            let policy = new X509ChainPolicy()
                            policy.TrustMode <- X509ChainTrustMode.CustomRootTrust
                            policy.CustomTrustStore.Add p.Root |> ignore
                            policy.RevocationMode <- X509RevocationMode.NoCheck
                            policy.DisableCertificateDownloads <- true
                            let handler = new SocketsHttpHandler()
                            handler.SslOptions.CertificateChainPolicy <- policy
                            handler.SslOptions.ClientCertificateContext <- withChain
                            handler.SslOptions.EnabledSslProtocols <- protocols

                            new HttpClient(
                                handler,
                                BaseAddress = Uri $"https://127.0.0.1:{port}",
                                Timeout = TimeSpan.FromSeconds 10.0
                            )

                        do!
                            withVc
                                $$"""{ "port": {{port}}, "tls_cert": "{{p.Cert}}", "tls_key": "{{p.Key}}", "client_ca": "{{caFile}}" }"""
                                p.Dir
                                (fun token ->
                                    task {
                                        for protocols, name in
                                            [
                                                Security.Authentication.SslProtocols.Tls13, "TLS 1.3"
                                                Security.Authentication.SslProtocols.Tls12, "TLS 1.2"
                                            ] do
                                            for i in 1..4 do
                                                use c = chained protocols

                                                let! s =
                                                    task {
                                                        try
                                                            return! get c token
                                                        with _ ->
                                                            return -1
                                                    }

                                                Expect.equal s 200 $"{name} connection {i}"
                                    })
                    })

            testT
                "client_ca reload: a client of the old CA is refused on its next connection, resumed session or not"
                (fun () ->
                    task {
                        let a = pki ()
                        let port = freePort ()
                        let dir = a.Dir
                        let clients = Path.Combine(dir, "clients.pem")
                        let clientRootA = rootCa "client root A"
                        let clientRootB = rootCa "client root B"
                        File.WriteAllText(clients, clientRootA.ExportCertificatePem())
                        let clientA, _ = leaf clientRootA true

                        do!
                            withVcClock
                                $$"""{ "port": {{port}}, "tls_cert": "{{a.Cert}}", "tls_key": "{{a.Key}}", "client_ca": "{{clients}}", "reload_interval_seconds": 1 }"""
                                dir
                                (fun h token ->
                                    task {
                                        for i in 1..3 do
                                            use c = client a.Root port (Some clientA)
                                            let! s = get c token
                                            Expect.equal s 200 $"client A, connection {i}"

                                        File.WriteAllText(clients, clientRootB.ExportCertificatePem())

                                        for _ in 1..3 do
                                            h.Time.Advance(TimeSpan.FromSeconds 1.0)
                                            do! Task.Delay 50

                                        use c = client a.Root port (Some clientA)
                                        do! fails (fun () -> get c token) "client A after the client_ca reload"
                                    })
                    })

            testT
                "tls_cert and client_ca reload: a new client gets the new certificate, and the new client CA decides"
                (fun () ->
                    task {
                        let a = pki ()
                        let b = pki ()
                        let port = freePort ()
                        let dir = a.Dir
                        let cert = Path.Combine(dir, "server.pem")
                        let key = Path.Combine(dir, "server.key")
                        let clients = Path.Combine(dir, "clients.pem")
                        File.Copy(a.Cert, cert)
                        File.Copy(a.Key, key)
                        let clientRootA = rootCa "client root A"
                        let clientRootB = rootCa "client root B"
                        File.WriteAllText(clients, clientRootA.ExportCertificatePem())
                        let clientA, _ = leaf clientRootA true
                        let clientB, _ = leaf clientRootB true

                        do!
                            withVcClock
                                $$"""{ "port": {{port}}, "tls_cert": "{{cert}}", "tls_key": "{{key}}", "client_ca": "{{clients}}", "reload_interval_seconds": 1 }"""
                                dir
                                (fun h token ->
                                    task {
                                        use c = client a.Root port (Some clientA)
                                        let! s = get c token
                                        Expect.equal s 200 "certificate A, client from CA A"
                                        File.Copy(b.Cert, cert, true)
                                        File.Copy(b.Key, key, true)
                                        File.WriteAllText(clients, clientRootB.ExportCertificatePem())
                                        // The reload task runs on the VC clock.
                                        let sw = Diagnostics.Stopwatch.StartNew()
                                        let passed = ref false

                                        while not passed.Value && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                                            h.Time.Advance(TimeSpan.FromSeconds 1.0)
                                            do! Task.Delay 50
                                            use probe = client b.Root port (Some clientB)

                                            try
                                                let! s = get probe token
                                                passed.Value <- (s = 200)
                                            with _ ->
                                                ()

                                        Expect.isTrue
                                            passed.Value
                                            "a new client that trusts root B, with a client certificate from CA B, gets in"

                                        use oldTrust = client a.Root port (Some clientA)

                                        do!
                                            fails
                                                (fun () -> get oldTrust token)
                                                "a client that trusts only root A sees the new certificate"

                                        use oldClient = client b.Root port (Some clientA)

                                        do!
                                            fails
                                                (fun () -> get oldClient token)
                                                "a client certificate from CA A is refused now"
                                    })
                    })

            testT
                "tls_cert reload: new connections take the checked certificate in memory, not the files as they are now"
                (fun () ->
                    task {
                        let a = pki ()
                        let b = pki ()
                        let c = pki ()
                        let port = freePort ()
                        let dir = a.Dir
                        let cert = Path.Combine(dir, "server.pem")
                        let key = Path.Combine(dir, "server.key")
                        File.Copy(a.Cert, cert)
                        File.Copy(a.Key, key)

                        do!
                            withVcClock
                                $$"""{ "port": {{port}}, "tls_cert": "{{cert}}", "tls_key": "{{key}}", "reload_interval_seconds": 1 }"""
                                dir
                                (fun h token ->
                                    task {
                                        File.Copy(b.Cert, cert, true)
                                        File.Copy(b.Key, key, true)
                                        let sw = Diagnostics.Stopwatch.StartNew()
                                        let passed = ref false

                                        while not passed.Value && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                                            h.Time.Advance(TimeSpan.FromSeconds 1.0)
                                            do! Task.Delay 50
                                            use probe = client b.Root port None

                                            try
                                                let! s = get probe token
                                                passed.Value <- (s = 200)
                                            with _ ->
                                                ()

                                        Expect.isTrue passed.Value "certificate B in force"
                                        // A good pair written after the check; the reload task has not run since.
                                        File.Copy(c.Cert, cert, true)
                                        File.Copy(c.Key, key, true)
                                        use stillB = client b.Root port None
                                        let! s = get stillB token
                                        Expect.equal s 200 "a new connection gets B, not the files not checked yet"
                                        use trustsC = client c.Root port None
                                        do! fails (fun () -> get trustsC token) "C is not served before a check"
                                        // A bad pair: C's certificate with B's key. The reload task refuses it.
                                        File.Copy(b.Key, key, true)

                                        for _ in 1..3 do
                                            h.Time.Advance(TimeSpan.FromSeconds 1.0)
                                            do! Task.Delay 50

                                        use afterBad = client b.Root port None
                                        let! s = get afterBad token
                                        Expect.equal s 200 "a refused pair is not served; B stays"
                                    })
                    })

            test "clientTrusted: chain to a listed CA, client use, in date" {
                let root = rootCa "r"
                let ca = X509Certificate2Collection root
                let c, _ = leaf root true
                Expect.isTrue (KeymanagerModule.clientTrusted ca c) "client leaf"
                let s, _ = leaf root false
                Expect.isFalse (KeymanagerModule.clientTrusted ca s) "server-only leaf"
                let other, _ = leaf (rootCa "other") true
                Expect.isFalse (KeymanagerModule.clientTrusted ca other) "another CA"
            }
        ]
