/// Per-node TLS trust and request headers.
module Eplix.Tests.NodeTlsTests

open System
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
open Eplix.Beacon
open Eplix.Tests.TestUtil

let private base' = """ "chain_config": "c.yaml", "data_dir": "d" """

let private parse (nodes: string) = Config.parse $$"""{ "beacon_nodes": {{nodes}}, {{base'}} }""" (tempDir ()) []

/// A CA and a leaf for "localhost" signed by it; the leaf carries its private key.
let private makeCa (name: string) =
    use caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let caReq = CertificateRequest($"CN={name}", caKey, HashAlgorithmName.SHA256)
    caReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    caReq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
    let ca = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 30.0)
    use leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let leafReq = CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256)
    let san = SubjectAlternativeNameBuilder()
    san.AddDnsName "localhost"
    leafReq.CertificateExtensions.Add(san.Build())
    leafReq.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, false))
    let serial = Array.init 8 (fun i -> byte (i + 1))

    use signed =
        leafReq.Create(ca, DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 10.0, serial)

    use withKey = signed.CopyWithPrivateKey leafKey
    // Through PKCS#12 so SslStream on Linux gets a key it can use.
    let leaf = X509CertificateLoader.LoadPkcs12(withKey.Export X509ContentType.Pkcs12, null)
    ca, leaf

/// A root CA, an intermediate CA it signed, and a leaf for "localhost" the intermediate signed;
/// the leaf carries its private key.
let private makeChain () =
    use rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let rootReq = CertificateRequest("CN=eplix test root", rootKey, HashAlgorithmName.SHA256)
    rootReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    rootReq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))

    let root =
        rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 30.0)

    use interKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let interReq = CertificateRequest("CN=eplix test intermediate", interKey, HashAlgorithmName.SHA256)
    interReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, true, 0, true))
    interReq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))

    use interSigned =
        interReq.Create(
            root,
            DateTimeOffset.UtcNow.AddDays -1.0,
            DateTimeOffset.UtcNow.AddDays 20.0,
            Array.init 8 (fun i -> byte (i + 20))
        )

    use interWithKey = interSigned.CopyWithPrivateKey interKey
    use leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let leafReq = CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256)
    let san = SubjectAlternativeNameBuilder()
    san.AddDnsName "localhost"
    leafReq.CertificateExtensions.Add(san.Build())
    leafReq.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, false))

    use signed =
        leafReq.Create(
            interWithKey,
            DateTimeOffset.UtcNow.AddDays -1.0,
            DateTimeOffset.UtcNow.AddDays 10.0,
            Array.init 8 (fun i -> byte (i + 40))
        )

    use withKey = signed.CopyWithPrivateKey leafKey
    let leaf = X509CertificateLoader.LoadPkcs12(withKey.Export X509ContentType.Pkcs12, null)
    let intermediate = X509CertificateLoader.LoadCertificate(interSigned.RawData)
    root, intermediate, leaf

let private genesisJson =
    """{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95","genesis_fork_version":"0x00000000"}}"""

/// An HTTPS server on 127.0.0.1 that answers every request with the genesis JSON and keeps the
/// request head of each request it read. It sends `intermediates` after its certificate.
type private TlsServer(leaf: X509Certificate2, intermediates: X509Certificate2 list) =
    let context =
        SslStreamCertificateContext.Create(leaf, X509Certificate2Collection(Array.ofList intermediates), true)

    let listener = new TcpListener(IPAddress.Loopback, 0)
    let heads = Collections.Concurrent.ConcurrentQueue<string>()
    let cts = new CancellationTokenSource()
    do listener.Start()

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! client = listener.AcceptTcpClientAsync cts.Token

                    try
                        use client = client
                        use ssl = new SslStream(client.GetStream())

                        do!
                            ssl.AuthenticateAsServerAsync(
                                SslServerAuthenticationOptions(ServerCertificateContext = context)
                            )

                        let buf = Array.zeroCreate<byte> 8192
                        let sb = StringBuilder()
                        let mutable go = true

                        while go do
                            let! n = ssl.ReadAsync(buf, 0, buf.Length)

                            if n = 0 then
                                go <- false
                            else
                                sb.Append(Encoding.ASCII.GetString(buf, 0, n)) |> ignore

                                if sb.ToString().Contains "\r\n\r\n" then
                                    go <- false

                        heads.Enqueue(sb.ToString())
                        let body = Encoding.UTF8.GetBytes genesisJson

                        let head =
                            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"

                        do! ssl.WriteAsync(ReadOnlyMemory(Encoding.ASCII.GetBytes head))
                        do! ssl.WriteAsync(ReadOnlyMemory body)
                        do! ssl.FlushAsync()
                    with _ ->
                        ()
            with _ ->
                ()
        }

    new(leaf: X509Certificate2) = new TlsServer(leaf, [])
    member _.Port = (listener.LocalEndpoint :?> IPEndPoint).Port
    member _.Heads = heads

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

let private writePem (dir: string) (name: string) (c: X509Certificate2) =
    let f = Path.Combine(dir, name)
    File.WriteAllText(f, c.ExportCertificatePem())
    f

[<Tests>]
let tests =
    testList
        "node-tls"
        [
            test "beacon_nodes takes URLs and objects with ca_cert, headers and headers_file" {
                let dir = tempDir ()
                File.WriteAllText(Path.Combine(dir, "ca.pem"), "x")
                File.WriteAllText(Path.Combine(dir, "bn.headers"), "# token\nX-Api-Key: k1\n\n")

                let text =
                    """{ "beacon_nodes": [ "http://a:5052",
                         { "url": "https://b:5052", "ca_cert": "ca.pem", "headers": { "Authorization": "Bearer t" }, "headers_file": "bn.headers" } ],
                       "chain_config": "c.yaml", "data_dir": "d" }"""

                match Config.parse text dir [] with
                | Error es -> failtestf "%A" es
                | Ok c ->
                    let a, b = c.BeaconNodes[0], c.BeaconNodes[1]
                    Expect.equal a.Url (Uri "http://a:5052") "plain URL"
                    Expect.equal a.CaCert ValueNone "no CA"
                    Expect.isEmpty a.Headers "no headers"
                    Expect.equal b.CaCert (ValueSome(Path.Combine(dir, "ca.pem"))) "CA path resolved"
                    Expect.equal b.Headers [ "Authorization", "Bearer t"; "X-Api-Key", "k1" ] "inline, then the file"
                    Expect.equal c.BeaconNode (Uri "http://a:5052") "first node"
            }

            test "a comma-separated string of URLs works, as flags and environment variables give it" {
                match parse "\"http://a:5052, http://b:5052\"" with
                | Ok c ->
                    Expect.equal
                        (c.BeaconNodes |> List.map (fun n -> n.Url.ToString()))
                        [ "http://a:5052/"; "http://b:5052/" ]
                        "two nodes"
                | Error es -> failtestf "%A" es
            }

            test "mistakes in a node entry are refused" {
                let dir = tempDir ()
                File.WriteAllText(Path.Combine(dir, "ca.pem"), "x")
                File.WriteAllText(Path.Combine(dir, "bad.headers"), "no colon here\n")

                let refused (nodes: string) (part: string) =
                    match Config.parse $$"""{ "beacon_nodes": {{nodes}}, {{base'}} }""" dir [] with
                    | Ok _ -> failtestf "accepted %s" nodes
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"{part} in %A{es}"

                refused """[ { "url": "https://b:1", "cert": "x" } ]""" "unknown field 'cert'"
                refused """[ { "url": "http://b:1", "ca_cert": "ca.pem" } ]""" "needs an https URL"
                refused """[ { "url": "https://b:1", "ca_cert": "missing.pem" } ]""" "does not exist"
                refused """[ { "url": "https://b:1", "headers": { "Bad Name": "x" } } ]""" "not an HTTP token"
                refused """[ { "url": "https://b:1", "headers": { "X-A": "a\nb" } } ]""" "control character"
                refused """[ { "url": "https://b:1", "headers": { "X-A": "1", "x-a": "2" } } ]""" "more than once"
                refused """[ { "url": "https://b:1", "headers_file": "bad.headers" } ]""" "line 1"
                refused """[ { "url": "https://b:1", "headers": [ "X-A: 1" ] } ]""" "headers must be an object"
                refused """[ { "ca_cert": "ca.pem" } ]""" "missing field 'url'"
                refused """[ 5 ]""" "a URL or an object"
            }

            test "a node URL with user info is refused, and the error does not repeat the credentials" {
                for nodes in
                    [
                        "\"http://user:s3cret@b:5052\""
                        """[ { "url": "https://user:s3cret@b:5052" } ]"""
                        "\"http://user@b:5052\""
                    ] do
                    match parse nodes with
                    | Ok _ -> failtestf "accepted %s" nodes
                    | Error es ->
                        Expect.isTrue (es |> List.exists (fun e -> e.Contains "carries user info")) $"refused: %A{es}"

                        Expect.isFalse
                            (es |> List.exists (fun e -> e.Contains "s3cret" || e.Contains "user@"))
                            $"no credentials in %A{es}"
            }

            test "a node URL with user info that is not http(s), or has a bad port, is refused without the credentials" {
                for nodes in
                    [
                        "\"ws://user:s3cret@b:5052\""
                        "\"http://user:s3cret@b:99999\""
                        "\"ws://user:s3/cret@b\""
                        "\"user:s3cret@b:5052\""
                    ] do
                    match parse nodes with
                    | Ok _ -> failtestf "accepted %s" nodes
                    | Error es ->
                        Expect.isTrue
                            (es |> List.exists (fun e -> e.Contains "is not an http or https URL"))
                            $"refused: %A{es}"

                        Expect.isFalse
                            (es
                             |> List.exists (fun e -> e.Contains "s3cret" || e.Contains "cret@" || e.Contains "user:"))
                            $"no credentials in %A{es}"
            }

            test "a node is named by scheme, host and port only" {
                use http = new Net.Http.HttpClient()
                let c = BeaconClient(http, Uri "https://user:s3cret@bn.test:5052/key/abc", TimeSpan.FromSeconds 1.0)
                Expect.equal c.Name "https://bn.test:5052" "no user info or path"
                let nodes = BeaconNodes([ c ], 1, TimeProvider.System, Log.none)
                let name, _, _ = nodes.Scores[0]
                Expect.equal name "https://bn.test:5052" "the metrics label"
            }

            testProp
                "a headers file gives back any valid name and value"
                (fun (n: FsCheck.NonEmptyString) (v: FsCheck.NonEmptyString) ->
                    let name = String(n.Get |> Seq.filter Char.IsAsciiLetterOrDigit |> Array.ofSeq)
                    let value = String(v.Get |> Seq.filter (fun c -> not (Char.IsControl c)) |> Array.ofSeq).Trim()

                    (name.Length = 0 || value.Length = 0)
                    || (Headers.check name value = Ok() && Headers.parseFile $"{name}: {value}\n" = Ok [ name, value ]))

            testT "the client trusts only the node's CA and sends its headers" (fun () ->
                task {
                    let dir = tempDir ()
                    let ca, leaf = makeCa "eplix test node CA"
                    let otherCa, _ = makeCa "another CA"
                    use server = new TlsServer(leaf)
                    let url = Uri $"https://localhost:{server.Port}"
                    let caFile = writePem dir "ca.pem" ca
                    let otherFile = writePem dir "other.pem" otherCa

                    let load f =
                        match BeaconClient.loadCa f with
                        | Ok c -> c
                        | Error e -> failtest e

                    use good = BeaconClient.createHttpWithCa (load caFile)

                    let client =
                        BeaconClient(
                            good,
                            url,
                            TimeSpan.FromSeconds 5.0,
                            [ "Authorization", "Bearer secret-1"; "X-Api-Key", "k2" ]
                        )

                    match! client.Genesis CancellationToken.None with
                    | Ok g -> Expect.equal g.GenesisTime 1606824023UL "genesis through TLS"
                    | Error e -> failtestf "genesis: %s" e.Describe

                    let head = server.Heads |> Seq.last
                    Expect.stringContains head "Authorization: Bearer secret-1" "auth header sent"
                    Expect.stringContains head "X-Api-Key: k2" "custom header sent"
                    // A client that trusts another CA refuses the node's certificate.
                    use bad = BeaconClient.createHttpWithCa (load otherFile)

                    match! BeaconClient(bad, url, TimeSpan.FromSeconds 5.0).Genesis CancellationToken.None with
                    | Ok _ -> failtest "a certificate from another CA was accepted"
                    | Error(ApiError.Transport _) -> ()
                    | Error e -> failtestf "expected a transport error, got %s" e.Describe
                    // The name must match too: 127.0.0.1 is not in the certificate.
                    match!
                        BeaconClient(good, Uri $"https://127.0.0.1:{server.Port}", TimeSpan.FromSeconds 5.0).Genesis
                            CancellationToken.None
                    with
                    | Ok _ -> failtest "a certificate for another name was accepted"
                    | Error _ -> ()
                })

            testT "a node certificate under an intermediate the node sends chains to the configured root" (fun () ->
                task {
                    let dir = tempDir ()
                    let root, intermediate, leaf = makeChain ()
                    let otherRoot, _ = makeCa "another CA"
                    use server = new TlsServer(leaf, [ intermediate ])
                    let url = Uri $"https://localhost:{server.Port}"

                    let load f =
                        match BeaconClient.loadCa f with
                        | Ok c -> c
                        | Error e -> failtest e

                    use good = BeaconClient.createHttpWithCa (load (writePem dir "root.pem" root))

                    match! BeaconClient(good, url, TimeSpan.FromSeconds 5.0).Genesis CancellationToken.None with
                    | Ok g -> Expect.equal g.GenesisTime 1606824023UL "genesis through the intermediate"
                    | Error e -> failtestf "genesis: %s" e.Describe
                    // The intermediate the server sends is not trusted on its own.
                    use bad = BeaconClient.createHttpWithCa (load (writePem dir "other.pem" otherRoot))

                    match! BeaconClient(bad, url, TimeSpan.FromSeconds 5.0).Genesis CancellationToken.None with
                    | Ok _ -> failtest "a chain to another root was accepted"
                    | Error _ -> ()
                })

            test "a CA file that does not load fails with its name" {
                let dir = tempDir ()
                let f = Path.Combine(dir, "junk.pem")
                File.WriteAllText(f, "not a certificate")

                match BeaconClient.loadCa f with
                | Ok _ -> failtest "junk loaded"
                | Error e -> Expect.stringContains e "junk.pem" "names the file"
            }
        ]
