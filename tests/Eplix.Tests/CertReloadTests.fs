/// Client certificates and CA files that reload while running: the
/// file set's rules, the TEE pool's redial, and the Web3Signer and Dirk clients' swap, each
/// against a server on loopback that checks the certificate a connection presents.
module Eplix.Tests.CertReloadTests

open System
open System.Collections.Concurrent
open System.Buffers.Binary
open System.Diagnostics
open System.Diagnostics.Metrics
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Server.Kestrel.Core
open Microsoft.AspNetCore.Server.Kestrel.Https
open Microsoft.Extensions.Logging
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil
open Eplix.Tests.TeeTlsTests

/// Writes the leaf and its intermediate to `crt` and the key to `key`, in place, as a
/// certificate rotation does.
let private writePair (crt: string) (key: string) (p: Pki) =
    File.WriteAllText(crt, p.Leaf.ExportCertificatePem() + "\n" + p.Intermediate.ExportCertificatePem() + "\n")
    File.WriteAllText(key, p.LeafKey.ExportPkcs8PrivateKeyPem())

/// A self-signed client certificate valid from `notBefore` to `notAfter`, with its key.
let private validBetween (name: string) (notBefore: DateTimeOffset) (notAfter: DateTimeOffset) =
    let key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256)
    let oids = OidCollection()
    oids.Add(Oid "1.3.6.1.5.5.7.3.2") |> ignore
    req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
    use c = req.CreateSelfSigned(notBefore, notAfter)
    X509CertificateLoader.LoadPkcs12(c.Export X509ContentType.Pkcs12, null), key

/// A self-signed client certificate valid until `notAfter`, with its key.
let private shortLived (name: string) (notAfter: DateTimeOffset) =
    validBetween name (DateTimeOffset.UtcNow.AddDays -1.0) notAfter

/// Writes a single certificate and its key, in place.
let private writeSingle (crt: string) (key: string) (c: X509Certificate2) (k: ECDsa) =
    File.WriteAllText(crt, c.ExportCertificatePem())
    File.WriteAllText(key, k.ExportPkcs8PrivateKeyPem())

let private thumb (f: TlsFile<SslStreamCertificateContext>) = f.Current.Value.TargetCertificate.Thumbprint

/// The client pair of `crt` and `key` as the TEE module loads it.
let private loadPair (crt: string) (key: string) (log: Log) =
    match TlsFiles.client "test" (Guid.NewGuid().ToString "N") crt key log TimeProvider.System with
    | Ok f -> f
    | Error e -> failwith e

/// Waits up to 10 s for `cond`.
let private until (what: string) (cond: unit -> bool) =
    task {
        let sw = Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting until %s" what
    }

/// Loads of a certificate or key by file path: the path overloads of the .NET
/// certificate APIs, an X509Certificate, Kestrel or collection import given a path, and a file
/// read whose argument names a certificate, key or CA. Only the reload module may read them.
let private pathLoads =
    [
        Regex
            @"\b(CreateFromPemFile|CreateFromEncryptedPemFile|ImportFromPemFile|ImportFromEncryptedPemFile|LoadCertificateFromFile|LoadPkcs12FromFile|CreateFromCertFile|CreateFromSignedFile)\b"
        Regex(@"(\bX509Certificate2?|\bUseHttps|\.Import)\s*\(\s*(""|[\w.]*(file|path)\b)", RegexOptions.IgnoreCase)
        Regex(
            @"\bFile\.(ReadAll(Text|Bytes|Lines)|ReadLines|Open(Read|Text)?)(Async)?\b.*(cert|pem|\bca\b|ca_?file|tls|\bkey\b|key_?file|client_?key|server_?key)",
            RegexOptions.IgnoreCase
        )
    ]

/// The reload module, the one place that reads certificate and key files.
let private reloadModule = "src/Eplix.Core/TlsFiles.fs"

/// path:line: code for each load by path in (path relative to the repository, text), comments
/// and the reload module left out.
let private scanForPathLoads (files: (string * string) list) =
    [
        for path, text in files do
            if path <> reloadModule then
                for i, line in Array.indexed (text.Split '\n') do
                    let code = line.Trim()

                    if not (code.StartsWith "//") && pathLoads |> List.exists (fun r -> r.IsMatch code) then
                        yield $"{path}:{i + 1}: {code}"
    ]

/// The repository root above the test binary.
let private repoRoot () =
    let rec up (d: DirectoryInfo | null) =
        match d with
        | null -> failtest $"no {reloadModule} above {AppContext.BaseDirectory}"
        | d when File.Exists(Path.Combine(d.FullName, reloadModule)) -> d.FullName
        | d -> up d.Parent

    up (DirectoryInfo AppContext.BaseDirectory)

let private waitFor (what: string) (seconds: float) (cond: unit -> bool) =
    task {
        let sw = Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds seconds do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s" what
    }

/// Measurements of the reload counter for one name.
type private ReloadCounter(name: string) =
    let results = ConcurrentQueue<string>()
    let listener = new MeterListener()

    do
        listener.InstrumentPublished <-
            fun i l ->
                if i.Meter.Name = Metrics.MeterName && i.Name = "eplix_tls_cert_reloads" then
                    l.EnableMeasurementEvents i

        listener.SetMeasurementEventCallback<int64>(fun _ _ tags _ ->
            let mutable n = ""
            let mutable r = ""

            for t in tags do
                if t.Key = "name" then
                    n <- string t.Value

                if t.Key = "result" then
                    r <- string t.Value

            if n = name then
                results.Enqueue r)

        listener.Start()

    member _.Results = List.ofSeq results

    interface IDisposable with
        member _.Dispose() = listener.Dispose()

/// A runner on 127.0.0.1 that accepts a client certificate only when its thumbprint is in
/// `accepted ()` at the handshake, answers IDENTITY (dev form) and every other request with a
/// refusal, and records each handshake: the client certificate's thumbprint and whether it
/// passed, and the time.
type private CheckingRunner(accepted: unit -> Set<string>) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let handshakes = ConcurrentQueue<struct (string * bool * DateTimeOffset)>()
    let serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)

    let serverCert =
        let req = CertificateRequest("CN=signer-runner", serverKey, HashAlgorithmName.SHA256)
        use c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddDays 1.0)
        X509CertificateLoader.LoadPkcs12(c.Export X509ContentType.Pkcs12, null)

    let keyHash = SHA256.HashData(Der.subjectPublicKeyInfo serverCert.RawData)
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
                TlsKeyHash = keyHash
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

    let check =
        RemoteCertificateValidationCallback(fun _ cert _ _ ->
            match cert with
            | null -> false
            | c ->
                use c2 = new X509Certificate2(c)
                let ok = (accepted ()).Contains c2.Thumbprint
                handshakes.Enqueue(struct (c2.Thumbprint, ok, DateTimeOffset.UtcNow))
                ok)

    let serve (client: TcpClient) =
        task {
            use client = client
            use ssl = new SslStream(client.GetStream(), false, check)

            let opts =
                SslServerAuthenticationOptions(
                    ServerCertificate = serverCert,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                )

            try
                do! ssl.AuthenticateAsServerAsync(opts, cts.Token)
                let len = Array.zeroCreate<byte> 4

                while true do
                    do! ssl.ReadExactlyAsync(len.AsMemory(), cts.Token)
                    let body = Array.zeroCreate<byte>(int (BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan len)))
                    do! ssl.ReadExactlyAsync(body.AsMemory(), cts.Token)
                    let f = Wire.decodeBody body

                    let answer =
                        match LanguagePrimitives.EnumOfValue<byte, Wire.MsgType> f.Type with
                        | Wire.MsgType.Identity ->
                            let n = int (BinaryPrimitives.ReadUInt16BigEndian(ReadOnlySpan(f.Payload, 0, 2)))
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

    /// Thumbprint, accepted, when.
    member _.Handshakes = List.ofSeq handshakes

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

/// A Web3Signer on 127.0.0.1 (HTTP/1.1 with keep-alive) that accepts a client certificate only
/// when it chains, with the certificates the client sent, to a root in `roots ()`. Records each
/// handshake (thumbprint, accepted) and each request (path, the connection's thumbprint).
/// With `acceptAny`, any client certificate passes (for tests of the client's own checks).
type private CheckingSigner(roots: unit -> X509Certificate2 list, ?acceptAny: bool) =
    let listener = new TcpListener(IPAddress.Loopback, 0)
    let cts = new CancellationTokenSource()
    let handshakes = ConcurrentQueue<struct (string * bool)>()
    let requests = ConcurrentQueue<struct (string * string)>()
    let server = makePki "w3s server" true

    let context =
        SslStreamCertificateContext.Create(
            server.Leaf,
            X509Certificate2Collection([| server.Intermediate |]),
            offline = true
        )

    do listener.Start()

    let check =
        RemoteCertificateValidationCallback(fun _ cert chain _ ->
            match cert with
            | null -> false
            | cert ->
                use c = new X509Chain()
                c.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust

                for r in roots () do
                    c.ChainPolicy.CustomTrustStore.Add r |> ignore

                c.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck

                match chain with
                | null -> ()
                | chain -> c.ChainPolicy.ExtraStore.AddRange chain.ChainPolicy.ExtraStore

                use leaf = new X509Certificate2(cert)
                let ok = c.Build leaf || acceptAny = Some true
                handshakes.Enqueue(struct (leaf.Thumbprint, ok))
                ok)

    let serve (client: TcpClient) =
        task {
            use client = client
            use ssl = new SslStream(client.GetStream(), false, check)

            try
                do!
                    ssl.AuthenticateAsServerAsync(
                        SslServerAuthenticationOptions(
                            ServerCertificateContext = context,
                            ClientCertificateRequired = true
                        ),
                        cts.Token
                    )

                let thumbprint =
                    match ssl.RemoteCertificate with
                    | null -> ""
                    | c -> (new X509Certificate2(c)).Thumbprint

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
                    requests.Enqueue(struct (path, thumbprint))
                    let body = if path.EndsWith "publicKeys" then "[]" else "OK"

                    let resp =
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n{body}"

                    do! ssl.WriteAsync(ReadOnlyMemory(Encoding.ASCII.GetBytes resp), cts.Token)
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
    member _.Handshakes = List.ofSeq handshakes
    member _.Requests = List.ofSeq requests

    member _.CaPem(dir: string) =
        let f = Path.Combine(dir, "w3s-ca.pem")
        File.WriteAllText(f, server.Root.ExportCertificatePem())
        f

    interface IDisposable with
        member _.Dispose() =
            cts.Cancel()
            listener.Stop()

/// A Dirk on 127.0.0.1: Kestrel over HTTP/2 with TLS, a client certificate that must chain to a
/// root in `roots ()`, and every gRPC call answered UNIMPLEMENTED. Records each handshake and
/// each call (path, the connection's client certificate thumbprint).
/// With `acceptAny`, any client certificate passes (for tests of the client's own checks).
type private CheckingDirk(roots: unit -> X509Certificate2 list, ?acceptAny: bool) =
    let handshakes = ConcurrentQueue<struct (string * bool)>()
    let calls = ConcurrentQueue<struct (string * string)>()
    let server = makePki "dirk server" true

    let context =
        SslStreamCertificateContext.Create(
            server.Leaf,
            X509Certificate2Collection([| server.Intermediate |]),
            offline = true
        )

    let port =
        let l = new TcpListener(IPAddress.Loopback, 0)
        l.Start()
        let p = (l.LocalEndpoint :?> IPEndPoint).Port
        l.Stop()
        p

    let app =
        let builder = WebApplication.CreateSlimBuilder()
        builder.Logging.ClearProviders() |> ignore

        builder.WebHost.ConfigureKestrel(fun o ->
            o.Listen(
                IPAddress.Loopback,
                port,
                fun listen ->
                    listen.Protocols <- HttpProtocols.Http2

                    let options (_: TlsHandshakeCallbackContext) =
                        let opts =
                            SslServerAuthenticationOptions(
                                ServerCertificateContext = context,
                                ClientCertificateRequired = true,
                                ApplicationProtocols = Collections.Generic.List([ SslApplicationProtocol.Http2 ])
                            )

                        opts.RemoteCertificateValidationCallback <-
                            RemoteCertificateValidationCallback(fun _ cert chain _ ->
                                match cert with
                                | null -> false
                                | cert ->
                                    use c = new X509Chain()
                                    c.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust

                                    for r in roots () do
                                        c.ChainPolicy.CustomTrustStore.Add r |> ignore

                                    c.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck

                                    match chain with
                                    | null -> ()
                                    | chain -> c.ChainPolicy.ExtraStore.AddRange chain.ChainPolicy.ExtraStore

                                    use leaf = new X509Certificate2(cert)
                                    let ok = c.Build leaf || acceptAny = Some true
                                    handshakes.Enqueue(struct (leaf.Thumbprint, ok))
                                    ok)

                        ValueTask<SslServerAuthenticationOptions>(opts)

                    listen.UseHttps(TlsHandshakeCallbackOptions(OnConnection = Func<_, _>(options))) |> ignore
            ))
        |> ignore

        let app = builder.Build()

        app.Run(
            RequestDelegate(fun ctx ->
                task {
                    let tls = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.ITlsConnectionFeature>()

                    let thumbprint =
                        match tls with
                        | null -> ""
                        | f ->
                            match f.ClientCertificate with
                            | null -> ""
                            | c -> c.Thumbprint

                    calls.Enqueue(struct (string ctx.Request.Path, thumbprint))
                    ctx.Response.StatusCode <- 200
                    ctx.Response.ContentType <- "application/grpc"
                    ctx.Response.Headers["grpc-status"] <- Microsoft.Extensions.Primitives.StringValues "12"
                    ctx.Response.Headers["grpc-message"] <- Microsoft.Extensions.Primitives.StringValues "fake"
                }
                :> Task)
        )

        app.StartAsync().GetAwaiter().GetResult()
        app

    member _.Address = $"localhost:{port}"
    member _.Handshakes = List.ofSeq handshakes
    member _.Calls = List.ofSeq calls

    member _.CaPem(dir: string) =
        let f = Path.Combine(dir, "dirk-ca.pem")
        File.WriteAllText(f, server.Root.ExportCertificatePem())
        f

    interface IDisposable with
        member _.Dispose() = app.StopAsync().GetAwaiter().GetResult()

/// A pool connection for the rotation tests: its certificate generation and whether it closed.
type private GenConn(gen: int) =
    let mutable closed = false
    member _.Gen = gen
    member _.Closed = closed

    interface PoolConn with
        member _.State = if closed then ConnState.Broken else ConnState.Ready
        member _.Drained = Task.FromResult true
        member _.Close() = closed <- true

let private runnerSettings (name: string) (port: int) (cert: TlsFile<SslStreamCertificateContext>) : RunnerSettings =
    {
        Name = name
        Host = "127.0.0.1"
        Port = port
        ClientCert = cert
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Verifier = TeeTlsTests.verifier
    }

let private runnerConfig (name: string) (crt: string) (key: string) (connections: int) : TeeModule.RunnerConfig =
    {
        Name = name
        Host = "127.0.0.1"
        Port = 1
        ClientCert = crt
        ClientKey = key
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Connections = connections
        Attestation = Attest.Settings.Empty
    }

let private teeSettings (cfg: TeeModule.RunnerConfig) (rotateWithin: TimeSpan) : TeeModule.Settings =
    {
        Runners = [ cfg ]
        Groups = []
        Timeout = TimeSpan.FromSeconds 2.0
        DialTimeout = TimeSpan.FromSeconds 5.0
        LowEvery = 8
        RefreshInterval = TimeSpan.Zero
        Keys = TeeModule.KeyFilter.AnyListedTestOnly
        AttestationCaFile = ValueNone
        ReloadInterval = TimeSpan.Zero
        RotateWithin = rotateWithin
        HaPeer = false
        Network = Attest.NetworkKind.Testnet
    }

/// Sends requests to the runner every few milliseconds until stopped, and samples the pool:
/// the answers that were failures, and the smallest number of connections up.
let private load (api: RunnerApi) (stop: CancellationToken) =
    task {
        let failures = ResizeArray<string>()
        let mutable minUp = Int32.MaxValue
        let mutable sent = 0

        while not stop.IsCancellationRequested do
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 2.0)

            match! api.Call PoolClass.High Wire.MsgType.Sign [| 1uy |] cts.Token with
            | Reply.Failure f -> failures.Add((Failed f).Describe)
            | _ -> ()

            sent <- sent + 1
            let up, _ = api.Up()
            minUp <- min minUp up
            do! Task.Delay 5

        return List.ofSeq failures, minUp, sent
    }

[<Tests>]
let tests =
    testList
        "cert reload"
        [
            testPropN
                "tls files: any sequence of good and bad writes leaves the last good pair in force"
                25
                (fun (ops: int list) ->
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "client.crt")
                    let key = Path.Combine(dir, "client.key")
                    let good = [| for i in 0..2 -> makePki $"good {i}" false |]
                    let expired, expiredKey = shortLived "expired" (DateTimeOffset.UtcNow.AddMinutes -1.0)
                    writePair crt key good[0]

                    let file =
                        match TlsFiles.client "test" "prop" crt key Log.none TimeProvider.System with
                        | Ok f -> f
                        | Error e -> failwith e

                    let mutable expected = good[0].Leaf.Thumbprint

                    for op in ops |> List.truncate 12 do
                        match abs op % 6 with
                        | i when i < 3 ->
                            writePair crt key good[i]
                            expected <- good[i].Leaf.Thumbprint
                        | 3 ->
                            // A certificate with another pair's key.
                            File.WriteAllText(crt, good[0].Leaf.ExportCertificatePem())
                            File.WriteAllText(key, good[1].LeafKey.ExportPkcs8PrivateKeyPem())
                        | 4 -> File.WriteAllText(crt, "not a certificate\n")
                        | _ ->
                            File.WriteAllText(crt, expired.ExportCertificatePem())
                            File.WriteAllText(key, expiredKey.ExportPkcs8PrivateKeyPem())

                        file.Check()

                        if thumb file <> expected then
                            failwithf "after op %d the pair in force is not the last good one" op

                    true)

            test "tls files: a swap per good change, one error per bad content, the reload counter" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "c.crt")
                let key = Path.Combine(dir, "c.key")
                let a = makePki "a" false
                let b = makePki "b" false
                writePair crt key a
                let name = Guid.NewGuid().ToString "N"
                use counter = new ReloadCounter(name)
                let log, lines = Log.memory ()

                let file =
                    match TlsFiles.client "test" name crt key log TimeProvider.System with
                    | Ok f -> f
                    | Error e -> failtest e

                let swaps = ResizeArray<int * int>()
                file.Swapped.Add(fun (o, n) -> swaps.Add(o.Generation, n.Generation))
                file.Check()
                Expect.isEmpty swaps "same bytes: no swap"
                File.WriteAllText(crt, "garbage\n")
                file.Check()
                file.Check()
                let errors () = lines |> Seq.filter (fun l -> l.StartsWith "ERROR") |> List.ofSeq
                Expect.equal (errors ()).Length 1 "one error for one bad content"
                Expect.stringContains (errors ()).Head crt "the error names the file"
                Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays"
                writePair crt key b
                file.Check()
                Expect.equal (List.ofSeq swaps) [ 1, 2 ] "one swap, generation 1 to 2"
                Expect.equal (thumb file) b.Leaf.Thumbprint "the new pair"

                Expect.equal
                    file.Current.NotAfter
                    (ClientCert.notAfter [ b.Leaf; b.Intermediate ])
                    "NotAfter of the chain"

                File.WriteAllText(crt, "garbage\n")
                file.Check()
                Expect.equal (errors ()).Length 2 "the same bad content again after a good one logs again"
                Expect.equal counter.Results [ "error"; "ok"; "error" ] "the reload counter"
            }

            test
                "tls files: start fails on an expired certificate; while running, an expired one with no replacement logs once a minute" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "c.crt")
                let key = Path.Combine(dir, "c.key")
                let old, oldKey = shortLived "old" (DateTimeOffset.UtcNow.AddMinutes -1.0)
                File.WriteAllText(crt, old.ExportCertificatePem())
                File.WriteAllText(key, oldKey.ExportPkcs8PrivateKeyPem())

                match TlsFiles.client "test" "x" crt key Log.none TimeProvider.System with
                | Ok _ -> failtest "an expired certificate loaded at start"
                | Error e -> Expect.stringContains e "expired" "named"

                let p = makePki "p" false
                writePair crt key p
                let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                let log, lines = Log.memory ()

                let file =
                    match TlsFiles.client "test" "x" crt key log time with
                    | Ok f -> f
                    | Error e -> failtest e

                time.SetUtcNow(file.Current.NotAfter + TimeSpan.FromSeconds 1.0)
                file.Check()
                time.Advance(TimeSpan.FromSeconds 30.0)
                file.Check()
                let expiredLines () = lines |> Seq.filter (fun l -> l.Contains "expired on") |> Seq.length
                Expect.equal (expiredLines ()) 1 "once in the first minute"
                time.Advance(TimeSpan.FromSeconds 31.0)
                file.Check()
                Expect.equal (expiredLines ()) 2 "again a minute later"
                Expect.equal (thumb file) p.Leaf.Thumbprint "the expired pair stays in force"
            }

            test "tls files: a pair not valid yet waits, logs once, and takes over at its NotBefore" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "c.crt")
                let key = Path.Combine(dir, "c.key")
                let a = makePki "a" false
                writePair crt key a
                let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                let log, lines = Log.memory ()

                let file =
                    match TlsFiles.client "test" (Guid.NewGuid().ToString "N") crt key log time with
                    | Ok f -> f
                    | Error e -> failtest e

                let swaps = ResizeArray<int * int>()
                file.Swapped.Add(fun (o, n) -> swaps.Add(o.Generation, n.Generation))
                // NotBefore has whole seconds.
                let notBefore = DateTimeOffset.FromUnixTimeSeconds(time.GetUtcNow().ToUnixTimeSeconds() + 60L)
                let early, earlyKey = validBetween "early" notBefore (notBefore.AddDays 1.0)
                writeSingle crt key early earlyKey
                file.Check()
                file.Check()
                Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays while the new one is not valid yet"
                Expect.isEmpty swaps "no swap before NotBefore"
                let waiting () = lines |> Seq.filter (fun l -> l.Contains "not valid until") |> Seq.length
                Expect.equal (waiting ()) 1 "one line while it waits"

                Expect.isEmpty
                    (lines |> Seq.filter (fun l -> l.StartsWith "ERROR") |> List.ofSeq)
                    "no error: the pair is good, only early"

                time.SetUtcNow(notBefore - TimeSpan.FromSeconds 1.0)
                file.Check()
                Expect.isEmpty swaps "not a second early"
                time.SetUtcNow notBefore
                file.Check()
                Expect.equal (List.ofSeq swaps) [ 1, 2 ] "one swap at NotBefore, with no change to the files"
                Expect.equal (thumb file) early.Thumbprint "the new pair is in force"
                file.Check()
                Expect.equal swaps.Count 1 "one swap only"
                Expect.equal (waiting ()) 1 "still one waiting line"

                Expect.equal
                    (lines |> Seq.filter (fun l -> l.Contains "reloaded") |> Seq.length)
                    1
                    "one line when it takes over"
            }

            test
                "tls files: a pair never valid, or one that expires while it waits, is refused; a waiting pair goes when the files change" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "c.crt")
                let key = Path.Combine(dir, "c.key")
                let a = makePki "a" false
                writePair crt key a
                let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                let log, lines = Log.memory ()

                let file =
                    match TlsFiles.client "test" (Guid.NewGuid().ToString "N") crt key log time with
                    | Ok f -> f
                    | Error e -> failtest e

                let swaps = ResizeArray<int>()
                file.Swapped.Add(fun (_, n) -> swaps.Add n.Generation)
                let errors () = lines |> Seq.filter (fun l -> l.StartsWith "ERROR") |> List.ofSeq
                let at (s: int64) = DateTimeOffset.FromUnixTimeSeconds(time.GetUtcNow().ToUnixTimeSeconds() + s)
                // NotAfter at NotBefore: valid for no time at all.
                let never, neverKey = validBetween "never" (at 60L) (at 60L)
                writeSingle crt key never neverKey
                file.Check()
                Expect.equal (errors ()).Length 1 "a pair that is never valid is an error"
                Expect.stringContains (errors ()).Head "never valid" "and says so"
                time.Advance(TimeSpan.FromSeconds 120.0)
                file.Check()
                Expect.isEmpty swaps "and never swaps in"
                // Valid from 60 s to 120 s from now; the clock jumps past both before a check.
                let brief, briefKey = validBetween "brief" (at 60L) (at 120L)
                writeSingle crt key brief briefKey
                file.Check()
                Expect.equal (errors ()).Length 1 "waiting is not an error"
                time.Advance(TimeSpan.FromSeconds 200.0)
                file.Check()
                file.Check()
                Expect.equal (errors ()).Length 2 "one error when it expired while it waited"
                Expect.stringContains (List.last (errors ())) "expired" "says why"
                Expect.isEmpty swaps "it never swaps in"
                // A waiting pair, then the old pair back in the files: nothing waits any more.
                let later, laterKey = validBetween "later" (at 60L) (at 600L)
                writeSingle crt key later laterKey
                file.Check()
                writePair crt key a
                file.Check()
                time.Advance(TimeSpan.FromSeconds 61.0)
                file.Check()
                Expect.isEmpty swaps "the files went back to the pair in force: nothing waits"
                Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays"
            }

            testT "tee: a dial after a swap takes the checked pair in memory, not the files as they are now" (fun () ->
                task {
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "c.crt")
                    let key = Path.Combine(dir, "c.key")
                    let n = makePki "N" false
                    let n1 = makePki "N+1" false
                    let n2 = makePki "N+2" false
                    writePair crt key n

                    let file =
                        match TlsFiles.client "tee" "r/client_cert" crt key Log.none TimeProvider.System with
                        | Ok f -> f
                        | Error e -> failtest e

                    use runner =
                        new CheckingRunner(fun () -> set [ n.Leaf.Thumbprint; n1.Leaf.Thumbprint; n2.Leaf.Thumbprint ])

                    let s = runnerSettings "r" runner.Port file
                    writePair crt key n1
                    file.Check()
                    Expect.equal (thumb file) n1.Leaf.Thumbprint "N+1 swapped in"

                    let dialed () =
                        task {
                            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
                            let before = runner.Handshakes.Length
                            let! c = RunnerConnection.Dial(s, (fun () -> DateTimeOffset.UtcNow), cts.Token)
                            c.Close()
                            let struct (t, _, _) = runner.Handshakes[before]
                            return t
                        }
                    // A good pair written after the check, not checked yet.
                    writePair crt key n2
                    let! t = dialed ()
                    Expect.equal t n1.Leaf.Thumbprint "a pair not checked yet is not used"
                    // A bad pair: N+2's certificate with N's key. The check refuses it.
                    File.WriteAllText(key, n.LeafKey.ExportPkcs8PrivateKeyPem())
                    file.Check()
                    let! t = dialed ()
                    Expect.equal t n1.Leaf.Thumbprint "a refused pair is not used"
                })

            testT "tee: a dial with an expired client certificate fails and names the file" (fun () ->
                task {
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "c.crt")
                    let key = Path.Combine(dir, "c.key")
                    let p = makePki "p" false
                    writePair crt key p

                    let file =
                        match TlsFiles.client "tee" "r/client_cert" crt key Log.none TimeProvider.System with
                        | Ok f -> f
                        | Error e -> failtest e

                    use runner = new CheckingRunner(fun () -> set [ p.Leaf.Thumbprint ])
                    let s = runnerSettings "r" runner.Port file
                    let later () = file.Current.NotAfter + TimeSpan.FromSeconds 1.0
                    use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)

                    let! err =
                        task {
                            try
                                let! c = RunnerConnection.Dial(s, later, cts.Token)
                                c.Close()
                                return ""
                            with e ->
                                return e.Message
                        }

                    Expect.stringContains err crt "the message names the certificate file"
                    Expect.stringContains err "expired" "and says why"
                    Expect.isEmpty runner.Handshakes "no handshake was tried"
                })

            testT
                "pool: rotation dials before it closes, one at a time, and a busy stale connection leaves when it comes back"
                (fun () ->
                    task {
                        let mutable gen = 1
                        let mutable dialing = 0
                        let mutable maxDialing = 0
                        let made = ConcurrentQueue<GenConn>()

                        let dial (_: CancellationToken) =
                            task {
                                let d = Interlocked.Increment &dialing
                                maxDialing <- max maxDialing d
                                do! Task.Delay 5
                                let c = GenConn(gen)
                                made.Enqueue c
                                Interlocked.Decrement &dialing |> ignore
                                return c
                            }

                        let pool = new ConnectionPool<GenConn>("p", 4, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)
                        pool.Start()
                        do! waitFor "four up" 5.0 (fun () -> let struct (up, _, _, _, _) = pool.Snapshot in up = 4)
                        // One connection is busy when the rotation starts.
                        let! busy = pool.Take(PoolClass.High, CancellationToken.None)

                        let busy =
                            match busy with
                            | Ok c -> c
                            | Error e -> failtest e

                        maxDialing <- 0
                        gen <- 2
                        let mutable minUp = 4
                        let sampling = new CancellationTokenSource()

                        let sampler =
                            task {
                                while not sampling.IsCancellationRequested do
                                    let struct (up, _, _, _, _) = pool.Snapshot
                                    minUp <- min minUp up
                                    do! Task.Delay 1
                            }

                        pool.Rotate((fun c -> c.Gen < 2), DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds 400.0)

                        do!
                            waitFor "the idle ones replaced" 5.0 (fun () ->
                                pool.Retiring = 1 && (made |> Seq.filter (fun c -> c.Gen = 2) |> Seq.length) = 4)

                        Expect.isFalse busy.Closed "the busy one serves on"
                        pool.Done busy
                        Expect.isTrue busy.Closed "it closes when it comes back"
                        sampling.Cancel()
                        do! sampler
                        Expect.isGreaterThanOrEqual minUp 4 "never fewer than four connections up"
                        Expect.equal maxDialing 1 "one redial at a time"
                        let old = made |> Seq.filter (fun c -> c.Gen = 1) |> List.ofSeq
                        Expect.isTrue (old |> List.forall (fun c -> c.Closed)) "every old connection closed"
                        let struct (up, free, _, _, _) = pool.Snapshot
                        Expect.equal (up, free) (4, 4) "four new connections, idle"
                        pool.Close()
                    })

            testT
                "tee: a runner that accepts only certificate N, then only N+1: the pool moves to N+1 with no failed request and no dial on the request path"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "N" false
                        let n1 = makePki "N+1" false
                        writePair crt key n
                        let mutable accepted = set [ n.Leaf.Thumbprint ]
                        use runner = new CheckingRunner(fun () -> accepted)
                        let cfg = runnerConfig "r" crt key 4
                        let s = teeSettings cfg (TimeSpan.FromSeconds 1.0)

                        let file =
                            match TeeModule.clientCertFile cfg Log.none TimeProvider.System with
                            | Ok f -> f
                            | Error e -> failtest e

                        let rs = runnerSettings "r" runner.Port file
                        let api = TeeModule.connect s [ cfg, rs ] Log.none |> List.exactlyOne |> snd
                        do! waitFor "four up" 10.0 (fun () -> fst (api.Up()) = 4)
                        use stop = new CancellationTokenSource()
                        let traffic = load api stop.Token
                        do! Task.Delay 100
                        accepted <- set [ n1.Leaf.Thumbprint ]
                        writePair crt key n1
                        file.Check()

                        do!
                            waitFor "four connections with N+1" 10.0 (fun () ->
                                (runner.Handshakes
                                 |> List.filter (fun struct (t, ok, _) -> ok && t = n1.Leaf.Thumbprint))
                                    .Length
                                    =
                                    4
                                && fst (api.Up()) = 4)

                        do! Task.Delay 100
                        stop.Cancel()
                        let! failures, minUp, sent = traffic
                        api.Close()
                        Expect.isEmpty failures "no request failed"
                        Expect.isGreaterThan sent 20 "requests ran through the rotation"
                        Expect.isGreaterThanOrEqual minUp 4 "the pool never ran short, so no request waited for a dial"
                        let hs = runner.Handshakes

                        Expect.isTrue
                            (hs |> List.forall (fun struct (_, ok, _) -> ok))
                            "no handshake refused: no dial with the old certificate after the switch"

                        Expect.equal hs.Length 8 "four dials with N, four redials with N+1, nothing else"
                    })

            testT
                "tee: an old certificate that expires inside the rotate window: every connection moves before it expires"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        // NotAfter has whole seconds: at least 4 s from now.
                        let notAfter =
                            DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5L)

                        let old, oldKey = shortLived "old" notAfter
                        File.WriteAllText(crt, old.ExportCertificatePem())
                        File.WriteAllText(key, oldKey.ExportPkcs8PrivateKeyPem())
                        let next = makePki "next" false
                        use runner = new CheckingRunner(fun () -> set [ old.Thumbprint; next.Leaf.Thumbprint ])
                        let cfg = runnerConfig "r" crt key 4
                        // A rotate window far past the old certificate's NotAfter.
                        let s = teeSettings cfg (TimeSpan.FromMinutes 10.0)

                        let file =
                            match TeeModule.clientCertFile cfg Log.none TimeProvider.System with
                            | Ok f -> f
                            | Error e -> failtest e

                        let api =
                            TeeModule.connect s [ cfg, runnerSettings "r" runner.Port file ] Log.none
                            |> List.exactlyOne
                            |> snd

                        do! waitFor "four up" 10.0 (fun () -> fst (api.Up()) = 4)
                        writePair crt key next
                        file.Check()

                        do!
                            waitFor "four redials" 10.0 (fun () ->
                                (runner.Handshakes |> List.filter (fun struct (t, _, _) -> t = next.Leaf.Thumbprint))
                                    .Length
                                    =
                                    4)

                        api.Close()

                        let last =
                            runner.Handshakes
                            |> List.filter (fun struct (t, _, _) -> t = next.Leaf.Thumbprint)
                            |> List.map (fun struct (_, _, at) -> at)
                            |> List.max

                        Expect.isLessThan last notAfter "the last redial came before the old certificate expired"

                        let first =
                            runner.Handshakes
                            |> List.filter (fun struct (t, _, _) -> t = next.Leaf.Thumbprint)
                            |> List.map (fun struct (_, _, at) -> at)
                            |> List.min

                        Expect.isGreaterThan
                            (last - first)
                            (TimeSpan.FromSeconds 1.0)
                            "spread over the time left, not all at once"
                    })

            testT
                "web3signer: a new client certificate reaches the signer with its chain, and requests move to it with none failing"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "w3s N" false
                        let n1 = makePki "w3s N+1" false
                        writePair crt key n
                        let mutable roots = [ n.Root ]
                        use signer = new CheckingSigner(fun () -> roots)

                        let endpoint: Eplix.Backend.Web3Signer.EndpointSettings =
                            {
                                Url = Uri $"https://localhost:{signer.Port}"
                                Tls =
                                    {
                                        CaCert = ValueSome(signer.CaPem dir)
                                        ClientCert = ValueSome crt
                                        ClientKey = ValueSome key
                                    }
                                Attestation = ValueNone
                            }

                        let tls =
                            match
                                Eplix.Backend.Web3Signer.HttpSigner.loadTls
                                    endpoint.Tls
                                    "w3s"
                                    Log.none
                                    TimeProvider.System
                            with
                            | Ok t -> t
                            | Error e -> failtest e

                        let api = Eplix.Backend.Web3Signer.HttpSigner.create endpoint tls Web3SignerTests.spec.Value 4
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
                        let! r = api.PublicKeys cts.Token
                        Expect.isOk r "keys with N"
                        roots <- [ n1.Root ]
                        writePair crt key n1
                        tls.Client.Value.Check()

                        do!
                            waitFor "the test request with N+1" 10.0 (fun () ->
                                signer.Requests
                                |> List.exists (fun struct (p, t) -> p = "/upcheck" && t = n1.Leaf.Thumbprint))
                        // The fake records /upcheck before it answers, and the new client becomes current
                        // only once the answer is back: send until a request goes with N+1.
                        let onN1 () =
                            signer.Requests
                            |> List.exists (fun struct (p, t) -> p.EndsWith "publicKeys" && t = n1.Leaf.Thumbprint)

                        let sw = Stopwatch.StartNew()

                        while not (onN1 ()) && sw.Elapsed < TimeSpan.FromSeconds 5.0 do
                            let! r = api.PublicKeys cts.Token
                            Expect.isOk r "keys during the swap"
                            do! Task.Delay 10

                        for _ in 1..3 do
                            let! r = api.PublicKeys cts.Token
                            Expect.isOk r "keys after the swap"

                        let keyRequests = signer.Requests |> List.filter (fun struct (p, _) -> p.EndsWith "publicKeys")
                        let struct (_, lastThumb) = List.last keyRequests
                        Expect.equal lastThumb n1.Leaf.Thumbprint "requests go over a connection with N+1"

                        Expect.isTrue
                            (signer.Handshakes |> List.forall (fun struct (_, ok) -> ok))
                            "every handshake passed: N+1 came with its intermediate"

                        api.Dispose()
                    })

            testT
                "web3signer: a client built after a swap takes the checked pair in memory, not the files as they are now"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "w3s N" false
                        let n1 = makePki "w3s N+1" false
                        let n2 = makePki "w3s N+2" false
                        writePair crt key n
                        use signer = new CheckingSigner(fun () -> [ n.Root; n1.Root; n2.Root ])

                        let endpoint: Eplix.Backend.Web3Signer.EndpointSettings =
                            {
                                Url = Uri $"https://localhost:{signer.Port}"
                                Tls =
                                    {
                                        CaCert = ValueSome(signer.CaPem dir)
                                        ClientCert = ValueSome crt
                                        ClientKey = ValueSome key
                                    }
                                Attestation = ValueNone
                            }

                        let tls =
                            match
                                Eplix.Backend.Web3Signer.HttpSigner.loadTls
                                    endpoint.Tls
                                    "w3s"
                                    Log.none
                                    TimeProvider.System
                            with
                            | Ok t -> t
                            | Error e -> failtest e

                        writePair crt key n1
                        tls.Client.Value.Check()

                        let fresh () =
                            task {
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)

                                let api =
                                    Eplix.Backend.Web3Signer.HttpSigner.create
                                        endpoint
                                        tls
                                        Web3SignerTests.spec.Value
                                        4

                                let before = signer.Handshakes.Length
                                // Only the certificate the client sent counts here: the fake may refuse a
                                // resumed session, whose chain lacks the intermediate.
                                let! _ = api.PublicKeys cts.Token
                                api.Dispose()
                                Expect.isGreaterThan signer.Handshakes.Length before "a handshake reached the fake"
                                let struct (t, _) = signer.Handshakes[before]
                                return t
                            }
                        // A good pair written after the check, not checked yet.
                        writePair crt key n2
                        let! t = fresh ()
                        Expect.equal t n1.Leaf.Thumbprint "a pair not checked yet is not used"
                        // A bad pair: N+2's certificate with N's key. The check refuses it.
                        File.WriteAllText(key, n.LeafKey.ExportPkcs8PrivateKeyPem())
                        tls.Client.Value.Check()
                        let! t = fresh ()
                        Expect.equal t n1.Leaf.Thumbprint "a refused pair is not used"
                    })

            testT
                "dirk: a new client certificate gets a new channel, tested off the request path; calls move to it"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "dirk N" false
                        let n1 = makePki "dirk N+1" false
                        writePair crt key n
                        let mutable roots = [ n.Root ]
                        use dirk = new CheckingDirk(fun () -> roots)

                        let tlsSettings: Eplix.Backend.Dirk.TlsSettings =
                            {
                                CaCert = dirk.CaPem dir
                                ClientCert = crt
                                ClientKey = key
                            }

                        let tls =
                            match Eplix.Backend.Dirk.GrpcDirk.loadTls tlsSettings Log.none TimeProvider.System with
                            | Ok t -> t
                            | Error e -> failtest e

                        let api = Eplix.Backend.Dirk.GrpcDirk.connect dirk.Address tls
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)

                        let unimplemented (r: Result<_, Eplix.Backend.Dirk.CallError>) =
                            match r with
                            | Error(Eplix.Backend.Dirk.CallError.Unimplemented _) -> true
                            | _ -> false

                        let! r = api.ListAccounts [ "w" ] cts.Token
                        Expect.isTrue (unimplemented r) $"the call reached the fake with N: %A{r}"
                        roots <- [ n1.Root ]
                        writePair crt key n1
                        tls.Client.Check()

                        do!
                            waitFor "the test call with N+1" 10.0 (fun () ->
                                dirk.Calls |> List.exists (fun struct (_, t) -> t = n1.Leaf.Thumbprint))

                        do! Task.Delay 50
                        let before = dirk.Calls.Length
                        let! r = api.ListAccounts [ "w" ] cts.Token
                        Expect.isTrue (unimplemented r) $"a call after the swap: %A{r}"
                        let struct (_, t) = dirk.Calls[before]
                        Expect.equal t n1.Leaf.Thumbprint "the call went over the new channel"

                        Expect.isTrue
                            (dirk.Handshakes |> List.forall (fun struct (_, ok) -> ok))
                            "every handshake passed, with the intermediate"

                        api.Dispose()
                    })

            testT
                "dirk: a channel built after a swap takes the checked pair in memory, not the files as they are now"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "dirk N" false
                        let n1 = makePki "dirk N+1" false
                        let n2 = makePki "dirk N+2" false
                        writePair crt key n
                        use dirk = new CheckingDirk(fun () -> [ n.Root; n1.Root; n2.Root ])

                        let tlsSettings: Eplix.Backend.Dirk.TlsSettings =
                            {
                                CaCert = dirk.CaPem dir
                                ClientCert = crt
                                ClientKey = key
                            }

                        let tls =
                            match Eplix.Backend.Dirk.GrpcDirk.loadTls tlsSettings Log.none TimeProvider.System with
                            | Ok t -> t
                            | Error e -> failtest e

                        writePair crt key n1
                        tls.Client.Check()

                        let fresh () =
                            task {
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
                                let api = Eplix.Backend.Dirk.GrpcDirk.connect dirk.Address tls
                                let before = dirk.Handshakes.Length
                                let! _ = api.ListAccounts [ "w" ] cts.Token
                                api.Dispose()
                                Expect.isGreaterThan dirk.Handshakes.Length before "a handshake reached the fake"
                                let struct (t, _) = dirk.Handshakes[before]
                                return t
                            }
                        // A good pair written after the check, not checked yet.
                        writePair crt key n2
                        let! t = fresh ()
                        Expect.equal t n1.Leaf.Thumbprint "a pair not checked yet is not used"
                        // A bad pair: N+2's certificate with N's key. The check refuses it.
                        File.WriteAllText(key, n.LeafKey.ExportPkcs8PrivateKeyPem())
                        tls.Client.Check()
                        let! t = fresh ()
                        Expect.equal t n1.Leaf.Thumbprint "a refused pair is not used"
                    })

            testT
                "tee: dials one after another with the same certificate all pass the checks (TLS resumption)"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "N" false
                        writePair crt key n

                        let file =
                            match TlsFiles.client "tee" "r/client_cert" crt key Log.none TimeProvider.System with
                            | Ok f -> f
                            | Error e -> failtest e

                        use runner = new CheckingRunner(fun () -> set [ n.Leaf.Thumbprint ])
                        let s = runnerSettings "r" runner.Port file

                        for i in 1..4 do
                            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)

                            let! r =
                                task {
                                    try
                                        let! c = RunnerConnection.Dial(s, (fun () -> DateTimeOffset.UtcNow), cts.Token)
                                        c.Close()
                                        return ""
                                    with e ->
                                        return e.Message
                                }

                            Expect.equal r "" $"dial {i}"
                    })

            testT
                "web3signer: new connections to a server under an intermediate CA pass, and a ca_cert reload decides each one (TLS resumption)"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "w3s N" false
                        writePair crt key n
                        use signer = new CheckingSigner((fun () -> []), true)
                        let ca = signer.CaPem dir

                        let endpoint: Eplix.Backend.Web3Signer.EndpointSettings =
                            {
                                Url = Uri $"https://localhost:{signer.Port}"
                                Tls =
                                    {
                                        CaCert = ValueSome ca
                                        ClientCert = ValueSome crt
                                        ClientKey = ValueSome key
                                    }
                                Attestation = ValueNone
                            }

                        let tls =
                            match
                                Eplix.Backend.Web3Signer.HttpSigner.loadTls
                                    endpoint.Tls
                                    "w3s"
                                    Log.none
                                    TimeProvider.System
                            with
                            | Ok t -> t
                            | Error e -> failtest e

                        let fresh () =
                            task {
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)

                                let api =
                                    Eplix.Backend.Web3Signer.HttpSigner.create
                                        endpoint
                                        tls
                                        Web3SignerTests.spec.Value
                                        4

                                let! r = api.PublicKeys cts.Token
                                api.Dispose()
                                return r
                            }

                        for i in 1..4 do
                            let! r = fresh ()
                            Expect.isOk r $"connection {i}: the server's chain checks against the root in ca_cert"
                        // ca_cert now names another root: a new connection must fail the server check.
                        File.WriteAllText(ca, (makePki "other" true).Root.ExportCertificatePem())
                        tls.Ca.Value.Check()
                        let! r = fresh ()

                        Expect.isError
                            r
                            "after the ca_cert reload the old server is not trusted, resumed session or not"
                    })

            testT
                "dirk: new channels to a server under an intermediate CA pass, and a ca_cert reload decides each one (TLS resumption)"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "c.crt")
                        let key = Path.Combine(dir, "c.key")
                        let n = makePki "dirk N" false
                        writePair crt key n
                        use dirk = new CheckingDirk((fun () -> []), true)
                        let ca = dirk.CaPem dir

                        let tlsSettings: Eplix.Backend.Dirk.TlsSettings =
                            {
                                CaCert = ca
                                ClientCert = crt
                                ClientKey = key
                            }

                        let tls =
                            match Eplix.Backend.Dirk.GrpcDirk.loadTls tlsSettings Log.none TimeProvider.System with
                            | Ok t -> t
                            | Error e -> failtest e

                        let reached () =
                            task {
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
                                let api = Eplix.Backend.Dirk.GrpcDirk.connect dirk.Address tls
                                let! r = api.ListAccounts [ "w" ] cts.Token
                                api.Dispose()

                                return
                                    match r with
                                    | Error(Eplix.Backend.Dirk.CallError.Unimplemented _) -> Ok()
                                    | r -> Error $"%A{r}"
                            }

                        for i in 1..4 do
                            let! r = reached ()
                            Expect.isOk r $"channel {i}: the server's chain checks against the root in ca_cert"

                        File.WriteAllText(ca, (makePki "other" true).Root.ExportCertificatePem())
                        tls.Ca.Check()
                        let! r = reached ()

                        Expect.isError
                            r
                            "after the ca_cert reload the old server is not trusted, resumed session or not"
                    })

            test "source scan: no certificate or key is loaded by file path outside the reload module" {
                let root = repoRoot ()

                let files =
                    Directory.EnumerateFiles(Path.Combine(root, "src"), "*.fs", SearchOption.AllDirectories)
                    |> Seq.map (fun f -> Path.GetRelativePath(root, f).Replace('\\', '/'), f)
                    |> Seq.filter (fun (rel, _) -> not (rel.Contains "/obj/" || rel.Contains "/bin/"))
                    |> Seq.map (fun (rel, f) -> rel, File.ReadAllText f)
                    |> List.ofSeq

                Expect.isGreaterThan files.Length 50 "the scan sees the sources"
                Expect.isTrue (files |> List.exists (fun (p, _) -> p = reloadModule)) "and the reload module among them"
                let found = scanForPathLoads files

                Expect.isEmpty
                    found
                    $"""certificate and key files are read by {reloadModule} only; connections take the checked value in memory:
{String.Join("\n", found)}"""
            }

            test "source scan: finds each kind of load by path, and passes the reload module, comments and copies" {
                let bad =
                    [
                        "use pemLeaf = X509Certificate2.CreateFromPemFile(certFile, keyFile)"
                        "all.ImportFromPemFile certFile"
                        "Ok(X509CertificateLoader.LoadCertificateFromFile file)"
                        "let c = new X509Certificate2(certPath)"
                        "listen.UseHttps(\"server.pfx\", \"secret\") |> ignore"
                        "let pem = File.ReadAllText certFile"
                        "let k = File.ReadAllBytes t.KeyFile"
                        "if File.ReadAllText(caFile).Contains \"-----BEGIN\" then ()"
                    ]

                for line in bad do
                    Expect.isNonEmpty (scanForPathLoads [ "src/Eplix.Backend.Web3Signer/X.fs", line ]) line

                Expect.isEmpty
                    (scanForPathLoads
                        [
                            reloadModule, "Ok(files |> List.map File.ReadAllBytes)\nlet pem = File.ReadAllText certFile"
                        ])
                    "the reload module reads the files"

                let fine =
                    [
                        "use leaf = new X509Certificate2(cert)"
                        "match Keystore.parse (File.ReadAllText e.Keystore) with"
                        "File.ReadAllText(file).Trim()"
                        "// X509Certificate2.CreateFromPemFile(a, b) is what this avoids"
                    ]

                for line in fine do
                    Expect.isEmpty (scanForPathLoads [ "src/Eplix.Core/X.fs", line ]) line
            }

            // The reloader tests run one at a time: a SIGHUP reaches every reloader in the process.
            testSequencedGroup "tls reloader"
            <| testT
                "reloader: a pair written to temp files and renamed over the old ones is in force soon, with no poll"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "client.crt")
                        let key = Path.Combine(dir, "client.key")
                        let a = makePki "a" false
                        let b = makePki "b" false
                        writePair crt key a
                        let file = loadPair crt key Log.none
                        use stop = new CancellationTokenSource()

                        let r =
                            TlsReloader(
                                "test",
                                [ file :> TlsCheck ],
                                file.Paths,
                                TimeSpan.FromHours 1.0,
                                TimeSpan.FromMilliseconds 50.0,
                                Log.none,
                                TimeProvider.System
                            )

                        let run = r.Run stop.Token
                        // As an agent does: write new files beside the old ones, then rename each over its old one.
                        writePair (crt + ".tmp") (key + ".tmp") b
                        File.Move(key + ".tmp", key, true)
                        File.Move(crt + ".tmp", crt, true)
                        do! until "the renamed pair is in force" (fun () -> thumb file = b.Leaf.Thumbprint)
                        Expect.equal file.Current.Generation 2 "one swap"
                        stop.Cancel()
                        do! run
                    })

            testSequencedGroup "tls reloader"
            <| testT
                "reloader: a partial write keeps the old pair and logs an error; the full write then loads"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "client.crt")
                        let key = Path.Combine(dir, "client.key")
                        let a = makePki "a" false
                        let b = makePki "b" false
                        writePair crt key a
                        let name = Guid.NewGuid().ToString "N"
                        use counter = new ReloadCounter(name)
                        let log, lines = Log.memory ()

                        let file =
                            match TlsFiles.client "test" name crt key log TimeProvider.System with
                            | Ok f -> f
                            | Error e -> failtest e

                        use stop = new CancellationTokenSource()

                        let r =
                            TlsReloader(
                                "test",
                                [ file :> TlsCheck ],
                                file.Paths,
                                TimeSpan.FromHours 1.0,
                                TimeSpan.FromMilliseconds 50.0,
                                log,
                                TimeProvider.System
                            )

                        let run = r.Run stop.Token
                        // The key of b in place, and a third of b's certificate file: a write cut short.
                        let pem = b.Leaf.ExportCertificatePem() + "\n" + b.Intermediate.ExportCertificatePem() + "\n"
                        File.WriteAllText(key, b.LeafKey.ExportPkcs8PrivateKeyPem())
                        File.WriteAllText(crt, pem.Substring(0, pem.Length / 3))
                        do! until "the partial write is read" (fun () -> counter.Results |> List.contains "error")
                        Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays"

                        Expect.isTrue
                            (lines
                             |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "the certificate in use stays"))
                            "an error is logged"

                        File.WriteAllText(crt, pem)
                        do! until "the full write is in force" (fun () -> thumb file = b.Leaf.Thumbprint)
                        Expect.equal (counter.Results |> List.filter ((=) "ok")) [ "ok" ] "one good reload"
                        stop.Cancel()
                        do! run
                    })

            testSequencedGroup "tls reloader"
            <| testT
                "reloader: a certificate with another pair's key keeps the old pair, counts an error, and the next change loads"
                (fun () ->
                    task {
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "client.crt")
                        let key = Path.Combine(dir, "client.key")
                        let a = makePki "a" false
                        let b = makePki "b" false
                        let c = makePki "c" false
                        writePair crt key a
                        let name = Guid.NewGuid().ToString "N"
                        use counter = new ReloadCounter(name)
                        let log, lines = Log.memory ()

                        let file =
                            match TlsFiles.client "test" name crt key log TimeProvider.System with
                            | Ok f -> f
                            | Error e -> failtest e

                        let swaps = ResizeArray<int>()
                        file.Swapped.Add(fun (_, n) -> lock swaps (fun () -> swaps.Add n.Generation))
                        use stop = new CancellationTokenSource()

                        let r =
                            TlsReloader(
                                "test",
                                [ file :> TlsCheck ],
                                file.Paths,
                                TimeSpan.FromHours 1.0,
                                TimeSpan.FromMilliseconds 50.0,
                                log,
                                TimeProvider.System
                            )

                        let run = r.Run stop.Token

                        File.WriteAllText(
                            crt,
                            b.Leaf.ExportCertificatePem() + "\n" + b.Intermediate.ExportCertificatePem() + "\n"
                        )

                        File.WriteAllText(key, c.LeafKey.ExportPkcs8PrivateKeyPem())
                        do! until "the mismatched pair is read" (fun () -> counter.Results |> List.contains "error")
                        Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays"
                        Expect.isEmpty (lock swaps (fun () -> List.ofSeq swaps)) "no swap"

                        Expect.isTrue
                            (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains crt))
                            "the error names the file"

                        writePair crt key c
                        do! until "the next change loads" (fun () -> thumb file = c.Leaf.Thumbprint)
                        Expect.equal (lock swaps (fun () -> List.ofSeq swaps)) [ 2 ] "one swap, to generation 2"
                        stop.Cancel()
                        do! run
                    })

            testSequencedGroup "tls reloader"
            <| testT "reloader: a burst of writes is one check once the directory is quiet" (fun () ->
                task {
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "client.crt")
                    let key = Path.Combine(dir, "client.key")
                    let pairs = [| for i in 0..5 -> makePki $"p{i}" false |]
                    writePair crt key pairs[0]
                    let file = loadPair crt key Log.none
                    use stop = new CancellationTokenSource()

                    let r =
                        TlsReloader(
                            "test",
                            [ file :> TlsCheck ],
                            file.Paths,
                            TimeSpan.FromHours 1.0,
                            TimeSpan.FromMilliseconds 300.0,
                            Log.none,
                            TimeProvider.System
                        )

                    let run = r.Run stop.Token

                    for i in 1..5 do
                        writePair crt key pairs[i]
                        do! Task.Delay 20

                    do! until "the last pair is in force" (fun () -> thumb file = pairs[5].Leaf.Thumbprint)
                    do! Task.Delay 600
                    // One check after the burst; a second only if an event comes late on a slow machine.
                    // Without the debounce each write would load: generation 6.
                    Expect.isLessThanOrEqual r.Checks 2 $"checks after a burst of 5 writes: {r.Checks}"

                    Expect.isLessThanOrEqual
                        file.Current.Generation
                        3
                        "the pairs in between were not loaded one by one"

                    stop.Cancel()
                    do! run
                })

            testSequencedGroup "tls reloader"
            <| testT "reloader: RequestNow, what SIGHUP calls, checks at once with no file event and no poll" (fun () ->
                task {
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "client.crt")
                    let key = Path.Combine(dir, "client.key")
                    let a = makePki "a" false
                    let b = makePki "b" false
                    writePair crt key a
                    let log, lines = Log.memory ()
                    let file = loadPair crt key log
                    use stop = new CancellationTokenSource()
                    // No paths: no watcher, so only the request can start a check within the hour.
                    let r =
                        TlsReloader(
                            "test",
                            [ file :> TlsCheck ],
                            [],
                            TimeSpan.FromHours 1.0,
                            TimeSpan.FromHours 1.0,
                            log,
                            TimeProvider.System
                        )

                    let run = r.Run stop.Token
                    writePair crt key b
                    do! Task.Delay 200
                    Expect.equal (thumb file) a.Leaf.Thumbprint "nothing reads the files by itself"
                    r.RequestNow()
                    do! until "the request loads the new pair" (fun () -> thumb file = b.Leaf.Thumbprint)
                    Expect.isTrue (lines |> Seq.exists (fun l -> l.Contains "SIGHUP")) "logged"
                    stop.Cancel()
                    do! run
                })

            testSequencedGroup "tls reloader"
            <| testT "reloader: SIGHUP to the process reloads and does not end it" (fun () ->
                task {
                    if OperatingSystem.IsLinux() then
                        let dir = tempDir ()
                        let crt = Path.Combine(dir, "client.crt")
                        let key = Path.Combine(dir, "client.key")
                        let a = makePki "a" false
                        let b = makePki "b" false
                        writePair crt key a
                        let file = loadPair crt key Log.none
                        // As Program does, for the run of the VC.
                        use _hup = SighupHub.Default.Register Log.none
                        use stop = new CancellationTokenSource()

                        let r =
                            TlsReloader(
                                "test",
                                [ file :> TlsCheck ],
                                [],
                                TimeSpan.FromHours 1.0,
                                TimeSpan.FromHours 1.0,
                                Log.none,
                                TimeProvider.System
                            )

                        let run = r.Run stop.Token
                        writePair crt key b
                        let kill = Process.Start("kill", [ "-HUP"; string Environment.ProcessId ]) |> nonNull
                        do! kill.WaitForExitAsync()
                        Expect.equal kill.ExitCode 0 "kill -HUP"
                        kill.Dispose()
                        do! until "SIGHUP loads the new pair" (fun () -> thumb file = b.Leaf.Thumbprint)
                        stop.Cancel()
                        do! run
                })

            testSequencedGroup "tls reloader"
            <| testT "SIGHUP with no reloader running logs that and does not end the process" (fun () ->
                task {
                    if OperatingSystem.IsLinux() then
                        // A hub of its own: no reloader of another test can join it.
                        let hub = SighupHub()
                        let log, lines = Log.memory ()
                        Expect.equal (hub.Raise log) 0 "no handler ran"
                        use _hup = hub.Register log
                        let kill = Process.Start("kill", [ "-HUP"; string Environment.ProcessId ]) |> nonNull
                        do! kill.WaitForExitAsync()
                        Expect.equal kill.ExitCode 0 "kill -HUP"
                        kill.Dispose()

                        do!
                            until "the signal is logged" (fun () ->
                                (lines
                                 |> Seq.filter (fun l -> l.Contains "SIGHUP: no certificate reload configured")
                                 |> Seq.length)
                                >= 2)
                })

            testSequencedGroup "tls reloader"
            <| testT "reloader: events for other files in the directory start no check" (fun () ->
                task {
                    let dir = tempDir ()
                    let crt = Path.Combine(dir, "client.crt")
                    let key = Path.Combine(dir, "client.key")
                    let a = makePki "a" false
                    let b = makePki "b" false
                    writePair crt key a
                    let file = loadPair crt key Log.none
                    use stop = new CancellationTokenSource()

                    let r =
                        TlsReloader(
                            "test",
                            [ file :> TlsCheck ],
                            file.Paths,
                            TimeSpan.FromHours 1.0,
                            TimeSpan.FromMilliseconds 50.0,
                            Log.none,
                            TimeProvider.System
                        )

                    let run = r.Run stop.Token

                    for i in 1..5 do
                        File.WriteAllText(Path.Combine(dir, "other.txt"), string i)
                        File.Move(Path.Combine(dir, "other.txt"), Path.Combine(dir, $"other-{i}.txt"))

                    do! Task.Delay 400
                    Expect.equal r.Checks 0 "no check for other files"
                    writePair crt key b
                    do! until "a change to the watched files loads" (fun () -> thumb file = b.Leaf.Thumbprint)
                    stop.Cancel()
                    do! run
                })

            test "tls files: a certificate file or CA bundle cut short in its last certificate keeps the set in use" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "client.crt")
                let key = Path.Combine(dir, "client.key")
                let a = makePki "a" false
                let b = makePki "b" false
                writePair crt key a
                let name = Guid.NewGuid().ToString "N"
                use counter = new ReloadCounter(name)
                let log, lines = Log.memory ()

                let file =
                    match TlsFiles.client "test" name crt key log TimeProvider.System with
                    | Ok f -> f
                    | Error e -> failtest e
                // The leaf whole, the intermediate cut after its BEGIN line: ImportFromPem alone would
                // load the leaf and drop the intermediate without a word.
                let inter = b.Intermediate.ExportCertificatePem()
                File.WriteAllText(key, b.LeafKey.ExportPkcs8PrivateKeyPem())
                File.WriteAllText(crt, b.Leaf.ExportCertificatePem() + "\n" + inter.Substring(0, inter.Length / 2))
                file.Check()
                Expect.equal (thumb file) a.Leaf.Thumbprint "the old pair stays"
                Expect.equal counter.Results [ "error" ] "counted as an error"

                Expect.isTrue
                    (lines
                     |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "2 BEGIN CERTIFICATE blocks but 1"))
                    "the error says why"

                writePair crt key b
                file.Check()
                Expect.equal (thumb file) b.Leaf.Thumbprint "the whole file loads"
                let caFile = Path.Combine(dir, "ca.pem")
                File.WriteAllText(caFile, a.Root.ExportCertificatePem() + "\n" + b.Root.ExportCertificatePem() + "\n")

                let ca =
                    match TlsFiles.ca "test" (Guid.NewGuid().ToString "N") caFile log TimeProvider.System with
                    | Ok f -> f
                    | Error e -> failtest e

                Expect.equal ca.Current.Value.Count 2 "two CAs"

                File.WriteAllText(
                    caFile,
                    a.Root.ExportCertificatePem() + "\n" + b.Root.ExportCertificatePem().Substring(0, 60)
                )

                ca.Check()
                Expect.equal ca.Current.Generation 1 "the bundle in use stays"
                Expect.equal ca.Current.Value.Count 2 "still two CAs"
            }

            test "reloader: a zero interval turns reloading off" {
                let dir = tempDir ()
                let crt = Path.Combine(dir, "client.crt")
                let key = Path.Combine(dir, "client.key")
                writePair crt key (makePki "a" false)
                let file = loadPair crt key Log.none

                let r =
                    TlsReloader(
                        "test",
                        [ file :> TlsCheck ],
                        file.Paths,
                        TimeSpan.Zero,
                        TimeSpan.FromMilliseconds 50.0,
                        Log.none,
                        TimeProvider.System
                    )

                Expect.isTrue (r.Run CancellationToken.None).IsCompleted "nothing runs"
            }

            test "config: reload_interval_seconds and rotate_within_seconds" {
                let section (json: string) =
                    let doc = Text.Json.JsonDocument.Parse json

                    ({
                        Element = ValueSome doc.RootElement
                        BaseDir = "/"
                        Mainnet = false
                    }
                    : ConfigSection)

                let tee (extra: string) =
                    TeeModule.parseSettings (
                        section (
                            sprintf
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ], "keys": [ "0x%s" ] %s }"""
                                (String('a', 96))
                                extra
                        )
                    )

                match tee "" with
                | Ok s ->
                    Expect.equal
                        (s.ReloadInterval, s.RotateWithin)
                        (TimeSpan.FromSeconds 10.0, TimeSpan.FromSeconds 300.0)
                        "defaults"
                | Error e -> failtestf "%A" e

                match tee """, "reload_interval_seconds": 0, "rotate_within_seconds": 60""" with
                | Ok s ->
                    Expect.equal
                        (s.ReloadInterval, s.RotateWithin)
                        (TimeSpan.Zero, TimeSpan.FromSeconds 60.0)
                        "set; 0 turns reloading off"
                | Error e -> failtestf "%A" e

                Expect.isError (tee """, "rotate_within_seconds": 0""") "rotate_within_seconds 0"
                Expect.isError (tee """, "reload_interval_seconds": 3601""") "reload_interval_seconds above an hour"

                match
                    Eplix.Backend.Dirk.DirkModule.parseSettings (
                        section
                            """{ "endpoints": [ "d:1" ], "accounts": [ "w" ], "ca_cert": "a", "client_cert": "b", "client_key": "c", "reload_interval_seconds": 30 }"""
                    )
                with
                | Ok s -> Expect.equal s.ReloadInterval (TimeSpan.FromSeconds 30.0) "dirk"
                | Error e -> failtestf "%A" e

                match
                    Eplix.Backend.Web3Signer.Web3SignerModule.parseSettings (
                        section """{ "signers": [ { "url": "http://w:1" } ], "reload_interval_seconds": 5 }"""
                    )
                with
                | Ok s -> Expect.equal s.ReloadInterval (TimeSpan.FromSeconds 5.0) "web3signer"
                | Error e -> failtestf "%A" e
            }
        ]
