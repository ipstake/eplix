/// Against real signers that speak the Web3Signer API.
///
/// web3signer-integration: four local Web3Signer processes, started here. One holds whole keys
/// behind mutual TLS; three hold one share each of 2 of 3 keys made with Eplix's own Shamir
/// code. Web3Signer's slashing protection needs PostgreSQL, so these run with it off. Runs when
/// EPLIX_WEB3SIGNER names the web3signer launcher (JAVA_HOME set); scripts/web3signer-it.sh runs
/// them.
///
/// The same list with Web3Signer's slashing protection on: one Web3Signer over a local
/// PostgreSQL, started by scripts/web3signer-pg.sh in a directory. Runs when EPLIX_WEB3SIGNER_PG
/// names that directory; scripts/web3signer-pg-it.sh runs it.
///
/// web3signer-gateway: a Web3Signer-compatible load-test gateway in front of the Dirk cluster of
/// scripts/dirk-local.sh. Runs when EPLIX_GATEWAY_URL is set; scripts/gateway-smoke.sh runs it.
module Eplix.Tests.Web3SignerIntegrationTests

open System
open System.Diagnostics
open System.IO
open System.IO.Compression
open System.Net
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Web3Signer
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.ThresholdTests

let launcher = Environment.GetEnvironmentVariable "EPLIX_WEB3SIGNER"
let gatewayUrl = Environment.GetEnvironmentVariable "EPLIX_GATEWAY_URL"
let pgDir = Environment.GetEnvironmentVariable "EPLIX_WEB3SIGNER_PG"

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let private allDuties (h: Harness) = RemoteSigningContractTests.preGloasDuties h.Node.Preset

/// Gloas from this epoch in the Web3Signer network file, after every slot allDuties uses.
let private gloasEpoch = RemoteSigningContractTests.gloasEpoch

/// A harness whose chain spec schedules Gloas at gloasEpoch, as the network file does.
let private gloasHarness () =
    let h = harness ()

    match ChainSpec.parse (Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch)) with
    | Ok s -> { h with Spec = s }
    | Error e -> failwith e

let private gloasDuties (h: Harness) = RemoteSigningContractTests.gloasDuties h.Node.Preset

/// Test certificates made in process: a CA, the server (localhost, 127.0.0.1), the client
/// Web3Signer knows and one it does not.
module private Pki =
    let password = "eplix-test-only"

    let private request (cn: string) (key: RSA) =
        CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)

    let make (dir: string) =
        let now = DateTimeOffset.UtcNow
        use caKey = RSA.Create 2048
        let caReq = request "eplix test CA" caKey
        caReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))

        caReq.CertificateExtensions.Add(
            X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign ||| X509KeyUsageFlags.CrlSign, true)
        )

        use ca = caReq.CreateSelfSigned(now.AddDays -1.0, now.AddDays 30.0)
        File.WriteAllText(Path.Combine(dir, "ca.crt"), ca.ExportCertificatePem())

        let issue (cn: string) (serial: byte) (server: bool) =
            use key = RSA.Create 2048
            let req = request cn key

            if server then
                let san = SubjectAlternativeNameBuilder()
                san.AddDnsName "localhost"
                san.AddIpAddress IPAddress.Loopback
                req.CertificateExtensions.Add(san.Build())

            let usage = if server then "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2"
            let oids = OidCollection()
            oids.Add(Oid usage) |> ignore
            req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
            use cert = req.Create(ca, now.AddDays -1.0, now.AddDays 30.0, [| serial; 1uy |])
            use withKey = cert.CopyWithPrivateKey key

            if server then
                File.WriteAllBytes(Path.Combine(dir, "server.p12"), withKey.Export(X509ContentType.Pkcs12, password))
            else
                File.WriteAllText(Path.Combine(dir, $"{cn}.crt"), withKey.ExportCertificatePem())
                File.WriteAllText(Path.Combine(dir, $"{cn}.key"), key.ExportPkcs8PrivateKeyPem())

            Convert.ToHexString(SHA256.HashData(cert.RawData))

        issue "localhost" 2uy true |> ignore
        let fingerprint = issue "eplix" 3uy false
        issue "stranger" 4uy false |> ignore
        File.WriteAllText(Path.Combine(dir, "password.txt"), password)

        let colons =
            String.Join(":", [ for i in 0..2 .. fingerprint.Length - 2 -> fingerprint.Substring(i, 2) ])

        File.WriteAllText(Path.Combine(dir, "known-clients.txt"), $"eplix {colons}\n")

/// The fake chain as a Web3Signer network file: Teku's minimal config from the Web3Signer
/// distribution with the fork schedule of the fake beacon node. The file name must end in .yaml.
let private networkFile (dir: string) =
    let lib = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath launcher)), "lib")
    let jar = Directory.GetFiles(lib, "spec-*.jar") |> Array.head
    use zip = ZipFile.OpenRead jar
    let entry = zip.GetEntry "tech/pegasys/teku/spec/config/configs/minimal.yaml"
    use reader = new StreamReader(entry.Open())
    let values = Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch)

    let lines =
        reader.ReadToEnd().Split('\n')
        |> Array.map (fun line ->
            match line.IndexOf ':' with
            | i when i > 0 && not (line.StartsWith "#") && not (line.StartsWith " ") ->
                let key = line.Substring(0, i)

                match values.TryFind key with
                | Some v when key.EndsWith "_FORK_EPOCH" || key.EndsWith "_FORK_VERSION" -> $"{key}: {v}"
                | _ -> line
            | _ -> line)

    let path = Path.Combine(dir, "network.yaml")
    File.WriteAllText(path, String.Join("\n", lines))
    path

let private writeKeys (dir: string) (secrets: byte[] list) =
    Directory.CreateDirectory dir |> ignore

    for i, s in List.indexed secrets do
        File.WriteAllText(
            Path.Combine(dir, $"key{i}.yaml"),
            $"type: \"file-raw\"\nkeyType: \"BLS\"\nprivateKey: \"{Hex.encodeArray s}\"\n"
        )

/// Four Web3Signer processes over a temporary directory.
type Cluster() =
    let dir = tempDir ()
    let processes = Collections.Generic.Dictionary<int, Process>()
    let wholeSecrets = [ for i in 0..3 -> secretOf i ]
    let groups = [ for s in 0..2 -> shamir (600 + s) 2 [ 1UL; 2UL; 3UL ] ]

    let start (port: int) (args: string list) =
        let log = Path.Combine(dir, $"w3s-{port}.log")
        let dataDir = Path.Combine(dir, $"data-{port}")
        Directory.CreateDirectory dataDir |> ignore

        let all =
            [
                $"--http-listen-port={port}"
                "--http-listen-host=127.0.0.1"
                $"--data-path={dataDir}"
                "--logging=INFO"
            ]
            @ args

        let psi =
            ProcessStartInfo("bash", [ "-c"; $"""exec "{launcher}" {String.Join(" ", all)} > "{log}" 2>&1""" ])

        processes[port] <- Process.Start psi

    do
        Pki.make dir
        let network = networkFile dir
        writeKeys (Path.Combine(dir, "keys-whole")) wholeSecrets

        for m in 0..2 do
            writeKeys (Path.Combine(dir, $"keys-share{m + 1}")) [ for _, shares in groups -> snd shares[m] ]

        let eth2 = [ "eth2"; $"--network={network}"; "--slashing-protection-enabled=false" ]

        start
            19310
            ([
                $"--key-store-path={dir}/keys-whole"
                $"--tls-keystore-file={dir}/server.p12"
                $"--tls-keystore-password-file={dir}/password.txt"
                $"--tls-known-clients-file={dir}/known-clients.txt"
                "--tls-allow-any-client=false"
             ]
             @ eth2)

        for m in 1..3 do
            start (19310 + m) ([ $"--key-store-path={dir}/keys-share{m}" ] @ eth2)

        AppDomain.CurrentDomain.ProcessExit.Add(fun _ ->
            for p in processes.Values do
                try
                    p.Kill true
                with _ ->
                    ())

    member _.Dir = dir
    member _.WholeKeys = wholeSecrets |> List.map pk
    member _.Groups = groups

    member _.Whole: EndpointSettings =
        {
            Url = Uri "https://localhost:19310"
            Tls =
                {
                    CaCert = ValueSome(Path.Combine(dir, "ca.crt"))
                    ClientCert = ValueSome(Path.Combine(dir, "eplix.crt"))
                    ClientKey = ValueSome(Path.Combine(dir, "eplix.key"))
                }
            Attestation = ValueNone
        }

    member _.Share(m: int) : EndpointSettings =
        {
            Url = Uri $"http://127.0.0.1:{19310 + m}"
            Tls = TlsSettings.None
            Attestation = ValueNone
        }

    member _.Stop(port: int) =
        match processes.TryGetValue port with
        | true, p ->
            p.Kill true
            p.WaitForExit()
        | _ -> ()

    member this.StopAll() =
        for port in List.ofSeq processes.Keys do
            this.Stop port

let private connect (spec: ChainSpec) (e: EndpointSettings) =
    match HttpSigner.loadTls e.Tls e.Url.AbsoluteUri Log.none TimeProvider.System with
    | Ok tls -> HttpSigner.create e tls spec 16
    | Error m -> failtest m

let private settings (c: Cluster) : Web3SignerModule.Settings =
    {
        Signers = [ c.Whole ]
        Groups =
            [
                {
                    Threshold = 2
                    Members = [ for m in 1..3 -> uint64 m, c.Share m ]
                    Keys =
                        [
                            for secret, shares in c.Groups ->
                                {
                                    PubKey = pk secret
                                    Shares = Map.ofList [ for id, s in shares -> id, pk s ]
                                }
                        ]
                }
            ]
        Timeout = TimeSpan.FromSeconds 5.0
        MaxConnections = 16
        RefreshInterval = TimeSpan.Zero
        ReloadInterval = TimeSpan.Zero
    }

let private cluster =
    lazy
        (let c = Cluster()
         let spec = (harness ()).Spec
         // A JVM start takes a few seconds; wait until every instance answers.
         let apis = [ connect spec c.Whole ] @ [ for m in 1..3 -> connect spec (c.Share m) ]
         let sw = Stopwatch.StartNew()
         let up () = apis |> List.forall (fun a -> (a.Upcheck CancellationToken.None).Result)

         while not (up ()) && sw.Elapsed < TimeSpan.FromSeconds 60.0 do
             Thread.Sleep 200

         if not (up ()) then
             failtestf "Web3Signer did not start; logs in %s" c.Dir

         for a in apis do
             a.Dispose()

         c)

let private discover (h: Harness) =
    task {
        let c = cluster.Value
        let ws = Web3SignerModule.Web3SignerSet(connect h.Spec, settings c, h.Time, Log.none)
        let! found, answered = ws.Discover CancellationToken.None
        return c, ws, Map.ofList found, answered
    }

let private integration =
    testSequenced
    <| testList
        "web3signer-integration"
        [
            testT "whole keys over mutual TLS and 2 of 3 share keys are listed" (fun () ->
                task {
                    let h = harness ()
                    let! c, ws, found, answered = discover h
                    Expect.equal answered 4 "four Web3Signer instances answer"

                    for k in c.WholeKeys do
                        Expect.stringContains found[k].Name "web3signer https://localhost:19310" "a whole key"

                    for secret, _ in c.Groups do
                        Expect.stringContains found[pk secret].Name "web3signer 2 of 3" "a share group key"

                    ws.Stop()
                })

            testT "every duty kind signs through Web3Signer and verifies, whole keys and 2 of 3 shares" (fun () ->
                task {
                    let h = harness ()
                    let! c, ws, found, _ = discover h
                    let keys = [ c.WholeKeys.Head; pk (fst c.Groups.Head) ]

                    for key in keys do
                        // The pre-Gloas registration (no fork_info; Web3Signer computes the builder domain).
                        let registration =
                            Duty.ValidatorRegistration
                                {
                                    FeeRecipient = Array.create 20 0xAAuy
                                    GasLimit = 60_000_000UL
                                    Timestamp = 1_700_000_000UL
                                    PubKey = key
                                }

                        for duty in allDuties h @ [ registration ] do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! found[key].Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.isTrue (verify key req.SigningRoot s) $"{found[key].Name} {duty.Kind} verifies"
                            | o -> failtestf "%s %A: %s" found[key].Name duty.Kind o.Describe

                    ws.Stop()
                })

            testT "Gloas kinds sign through Web3Signer, which computes the same signing roots" (fun () ->
                task {
                    // Web3Signer recomputes each signing root and answers 400 when it differs from the
                    // signingRoot Eplix sends, so a signature here means both sides agree on the root.
                    let h = gloasHarness ()
                    let! c, ws, found, _ = discover h
                    let keys = [ c.WholeKeys.Head; pk (fst c.Groups.Head) ]

                    for key in keys do
                        for duty in gloasDuties h do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! found[key].Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.isTrue (verify key req.SigningRoot s) $"{found[key].Name} {duty.Kind} verifies"
                            | o -> failtestf "%s %A: %s" found[key].Name duty.Kind o.Describe

                    ws.Stop()
                })

            testT "the contract fixtures sign as they are, through Web3Signer" (fun () ->
                task {
                    // The bytes of tests/fixtures/remote-signing-api/eplix-bodies, sent to the first share
                    // instance (plain HTTP) for its share of the first group's key. Web3Signer checks each
                    // body's signingRoot against its own, so a signature means it read the body as Eplix means it.
                    let c = cluster.Value
                    let key = pk (snd (snd c.Groups.Head).[0])
                    use http = new Net.Http.HttpClient(BaseAddress = (c.Share 1).Url)
                    let problems = ResizeArray<string>()

                    for name, _ in RemoteSigningContractTests.contractDuties () do
                        let body = RemoteSigningContractTests.readFixture name
                        use content = new Net.Http.ByteArrayContent(body)
                        content.Headers.ContentType <- Net.Http.Headers.MediaTypeHeaderValue "application/json"

                        use msg =
                            new Net.Http.HttpRequestMessage(
                                Net.Http.HttpMethod.Post,
                                $"/api/v1/eth2/sign/{key.Hex}",
                                Content = content
                            )

                        msg.Headers.Accept.Add(Net.Http.Headers.MediaTypeWithQualityHeaderValue "application/json")
                        use! resp = http.SendAsync msg
                        let! text = resp.Content.ReadAsStringAsync()

                        if resp.StatusCode <> HttpStatusCode.OK then
                            problems.Add $"{name}: {int resp.StatusCode} {text}"
                        else
                            use doc = JsonDocument.Parse body

                            let signingRoot =
                                (Root.TryParse(doc.RootElement.GetProperty("signingRoot").GetString())).Value

                            match Body.signature text with
                            | ValueSome s when verify key signingRoot s -> ()
                            | ValueSome _ -> problems.Add $"{name}: the signature does not verify"
                            | ValueNone -> problems.Add $"{name}: no signature in {text}"

                    Expect.isEmpty problems "fixtures Web3Signer did not sign"
                    // The check can fail: the PTC vote with its data outside the version wrapper, the
                    // shape a stock signer refuses, gets no signature.
                    let flat =
                        Nodes.JsonNode.Parse(
                            Text.Encoding.UTF8.GetString(
                                RemoteSigningContractTests.readFixture "PAYLOAD_ATTESTATION_MESSAGE"
                            )
                        )

                    let message = flat["payload_attestation_message"]
                    flat["payload_attestation_message"] <- message["data"].DeepClone()

                    use content =
                        new Net.Http.StringContent(flat.ToJsonString(), Text.Encoding.UTF8, "application/json")

                    use! resp = http.PostAsync($"/api/v1/eth2/sign/{key.Hex}", content)
                    Expect.equal resp.StatusCode HttpStatusCode.BadRequest "Web3Signer refuses the flat PTC vote"
                })

            testT "Web3Signer refuses a client it does not know and a wrong signing root" (fun () ->
                task {
                    let h = harness ()
                    let c = cluster.Value

                    let stranger =
                        { c.Whole with
                            Tls =
                                { c.Whole.Tls with
                                    ClientCert = ValueSome(Path.Combine(c.Dir, "stranger.crt"))
                                    ClientKey = ValueSome(Path.Combine(c.Dir, "stranger.key"))
                                }
                        }

                    for e in
                        [
                            stranger
                            { c.Whole with
                                Tls =
                                    { c.Whole.Tls with
                                        ClientCert = ValueNone
                                        ClientKey = ValueNone
                                    }
                            }
                        ] do
                        let api = connect h.Spec e

                        match! api.PublicKeys CancellationToken.None with
                        | Error(Transport _) -> ()
                        | x -> failtestf "expected a TLS failure, got %A" x

                        api.Dispose()

                    let api = connect h.Spec c.Whole
                    let key = c.WholeKeys.Head

                    let req =
                        Duty.request
                            h.Spec
                            gvr
                            key
                            Priority.High
                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                            (Duty.RandaoReveal 3UL)

                    let! wrong = api.Sign key { req with SigningRoot = root 1 } CancellationToken.None

                    match Answer.toOutcome api.Url req.Duty ValueNone wrong with
                    | Refused(BadRequest _) -> ()
                    | o -> failtestf "a wrong root: expected BadRequest, got %s" o.Describe

                    let unknown = pk (scalar32 (Numerics.BigInteger 4242))
                    let! a = api.Sign unknown { req with Key = unknown } CancellationToken.None

                    Expect.equal
                        (Answer.toOutcome api.Url req.Duty ValueNone a)
                        (Refused UnknownKey)
                        "404 for a key it does not hold"

                    api.Dispose()
                })

            testT
                "a remote key added through the keymanager API signs every duty kind through its Web3Signer"
                (fun () ->
                    task {
                        let h = harness ()
                        let c = cluster.Value
                        // Share 1 of the first group: the signer on port 19311 holds it as a plain BLS key.
                        let key = pk (snd (snd c.Groups.Head).[0])
                        h.Node.AddValidator(key, "active_ongoing") |> ignore
                        use tc = new RemoteKeysTests.TestCore(h, tempDir ())
                        let core = tc.Services

                        let ws =
                            Web3SignerModule.Web3SignerSet(connect h.Spec, Web3SignerModule.apiOnly, h.Time, Log.none)

                        core.SetRemoteKeys(Web3SignerModule.RemoteKeys.start false core ws)

                        let! _, text =
                            RemoteKeysTests.callApi
                                core
                                "POST"
                                (RemoteKeysTests.importBody [ key, Some (c.Share 1).Url.AbsoluteUri ])

                        Expect.equal (RemoteKeysTests.statusesOf text) [ "imported" ] text

                        for duty in allDuties h do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! core.Pipeline.Sign(req, CancellationToken.None) with
                            | Signed s -> Expect.isTrue (verify key req.SigningRoot s) $"{duty.Kind} verifies"
                            | o -> failtestf "%A: %s" duty.Kind o.Describe

                        let! _, text = RemoteKeysTests.callApi core "DELETE" (RemoteKeysTests.deleteBody [ key ])
                        Expect.equal (RemoteKeysTests.statusesOf text) [ "deleted" ] text

                        let req =
                            Duty.request
                                h.Spec
                                gvr
                                key
                                Priority.High
                                (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                (Duty.RandaoReveal 9UL)

                        let! o = core.Pipeline.Sign(req, CancellationToken.None)

                        Expect.isFalse
                            (match o with
                             | Signed _ -> true
                             | _ -> false)
                            $"a deleted key signs nothing ({o.Describe})"

                        ws.Stop()
                    })

            testT "duties on the fake beacon node through Web3Signer, then with one share signer down" (fun () ->
                task {
                    let h = harness ()
                    let! c, ws, found, _ = discover h

                    let routes =
                        [ for k in c.WholeKeys |> List.take 2 -> k, found[k] ]
                        @ [ for s, _ in c.Groups -> pk s, found[pk s] ]

                    for key, _ in routes do
                        h.Node.AddValidator(key, "active_ongoing") |> ignore

                    h.Node.Proposals[5UL] <- 0UL
                    h.Node.Proposals[12UL] <- 3UL
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startSchedulerWith h (Path.Combine(tempDir (), "s.db")) routes false cts.Token

                    let waitBlocks (n: int) =
                        task {
                            let sw = Stopwatch.StartNew()

                            while Seq.length h.Node.Published < n && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                                do! Task.Delay 10
                        }
                    // Slot by slot: the fake clock must not pass a block's deadline while Web3Signer answers.
                    for s in 0UL .. 15UL do
                        if s = 8UL then
                            c.Stop 19313

                        do! h.RunSlots(s, s)

                        if s = 5UL then
                            do! waitBlocks 1

                        if s = 12UL then
                            do! waitBlocks 2

                    cts.Cancel()
                    do! run
                    (db :> IDisposable).Dispose()
                    let subs = List.ofSeq h.Node.Submissions
                    Expect.equal subs.Length 10 $"two epochs, five validators; log:\n{String.Join('\n', lines)}"

                    for s in subs do
                        Expect.isTrue
                            (verifySubmission h s)
                            $"attestation of validator {s.AttesterIndex} at slot {s.Data.Slot} verifies"

                    Expect.equal
                        (Seq.length h.Node.Published)
                        2
                        $"blocks at slots 5 (whole key) and 12 (share key, one signer down); log:\n{String.Join('\n', lines)}"

                    ws.Stop()
                    c.StopAll()
                })
        ]

/// Signs an attestation at Web3Signer with a plain HTTP POST, as another VC that uses the same
/// Web3Signer would, and returns the signature.
let private signElsewhere (spec: ChainSpec) (url: Uri) (key: PubKey) (d: AttestationData) =
    task {
        let req =
            Duty.request spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) (Duty.Attestation d)

        let hex (b: byte[]) = Hex.encodeArray b
        let fork = req.Fork.Fork
        let cp (c: Checkpoint) = $"""{{"epoch":"{c.Epoch}","root":"{hex c.Root.Bytes}"}}"""

        let body =
            $"""{{"type":"ATTESTATION","fork_info":{{"fork":{{"previous_version":"{hex fork.PreviousVersion.Bytes}","current_version":"{hex fork.CurrentVersion.Bytes}","epoch":"{fork.Epoch}"}},"genesis_validators_root":"{hex req.Fork.GenesisValidatorsRoot.Bytes}"}},"""
            + $""""attestation":{{"slot":"{d.Slot}","index":"{d.Index}","beacon_block_root":"{hex d.BeaconBlockRoot.Bytes}","source":{cp d.Source},"target":{cp d.Target}}}}}"""

        use http = new Net.Http.HttpClient(Timeout = TimeSpan.FromSeconds 10.0)

        use msg =
            new Net.Http.HttpRequestMessage(Net.Http.HttpMethod.Post, Uri(url, $"/api/v1/eth2/sign/{hex key.Bytes}"))

        msg.Content <- new Net.Http.StringContent(body, Encoding.UTF8, "application/json")
        msg.Headers.Accept.ParseAdd "application/json"
        use! resp = http.SendAsync msg
        let! text = resp.Content.ReadAsStringAsync()
        Expect.equal resp.StatusCode HttpStatusCode.OK $"Web3Signer signs the other VC's vote: {text}"

        let sigHex =
            if text.TrimStart().StartsWith "{" then
                JsonDocument.Parse(text).RootElement.GetProperty("signature").GetString()
            else
                text.Trim()

        match BlsSignature.TryParse sigHex with
        | ValueSome s -> return req, s
        | ValueNone -> return failtestf "not a signature: %s" text
    }

let private withPostgres =
    testSequenced
    <| testList
        "web3signer-integration"
        [
            testT "a 412 from Web3Signer's DB halts the key" (fun () ->
                task {
                    let h = harness ()
                    let url = Uri(File.ReadAllText(Path.Combine(pgDir, "w3s.url")).Trim())

                    let s: Web3SignerModule.Settings =
                        {
                            Signers =
                                [
                                    {
                                        Url = url
                                        Tls = TlsSettings.None
                                        Attestation = ValueNone
                                    }
                                ]
                            Groups = []
                            Timeout = TimeSpan.FromSeconds 10.0
                            MaxConnections = 16
                            RefreshInterval = TimeSpan.Zero
                            ReloadInterval = TimeSpan.Zero
                        }

                    let ws = Web3SignerModule.Web3SignerSet(connect h.Spec, s, h.Time, Log.none)
                    let! found, answered = ws.Discover CancellationToken.None
                    Expect.equal answered 1 "Web3Signer answers"
                    Expect.equal found.Length 1 "Web3Signer holds one key"
                    let key, backend = found.Head
                    h.Node.AddValidator(key, "active_ongoing") |> ignore
                    // Eplix with an empty slashing DB of its own (start without history allowed for
                    // every key) attests in epochs 0, 1 and 2 through Web3Signer.
                    let spe = uint64 slotsPerEpoch
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startSchedulerWith h (Path.Combine(tempDir (), "s.db")) [ key, backend ] false cts.Token

                    for slot in 0UL .. 3UL * spe - 1UL do
                        do! h.RunSlots(slot, slot)

                        if slot = spe - 1UL then
                            // Before Eplix's epoch 1 vote, another VC with this key, using the same
                            // Web3Signer, votes in epoch 1 for another head. Web3Signer's DB holds it;
                            // Eplix's DB does not. (Web3Signer refuses any target below the lowest
                            // target it holds, so this vote cannot come before Eplix's epoch 0 vote.)
                            let other =
                                {
                                    Slot = spe + 3UL
                                    Index = 0UL
                                    BeaconBlockRoot = root 0xee
                                    Source = { Epoch = 0UL; Root = root 0xed }
                                    Target = { Epoch = 1UL; Root = root 0xef }
                                }

                            let! req, sg = signElsewhere h.Spec url key other
                            Expect.isTrue (verify key req.SigningRoot sg) "the other VC's vote verifies"

                    cts.Cancel()
                    do! run
                    (db :> IDisposable).Dispose()
                    ws.Stop()
                    let log = String.Join('\n', lines)
                    // Epoch 0 signs. Epoch 1 is a double vote in Web3Signer's DB: 412, a slashing
                    // refusal, and the key halts. Epoch 2 would sign at Web3Signer (no conflict
                    // there), so its absence shows the halt.
                    let targets = [ for s in h.Node.Submissions -> s.Data.Target.Epoch ]
                    Expect.equal targets [ 0UL ] $"only the epoch 0 vote is published; log:\n{log}"

                    for s in h.Node.Submissions do
                        Expect.isTrue (verifySubmission h s) "the epoch 0 vote verifies"

                    let halts =
                        lines
                        |> Seq.filter (fun l ->
                            l.Contains "answered 412" && l.Contains "slashable duties stop for this key")
                        |> List.ofSeq

                    Expect.equal halts.Length 1 $"one halt, from Web3Signer's 412; log:\n{log}"
                    Expect.stringContains halts.Head key.Short "the halt names the key"
                })
        ]

let private gateway =
    testSequenced
    <| testList
        "web3signer-gateway"
        [
            testT "Dirk distributed keys sign through the gateway; a double vote halts the key" (fun () ->
                task {
                    let h = harness ()

                    let s: Web3SignerModule.Settings =
                        {
                            Signers =
                                [
                                    {
                                        Url = Uri gatewayUrl
                                        Tls = TlsSettings.None
                                        Attestation = ValueNone
                                    }
                                ]
                            Groups = []
                            Timeout = TimeSpan.FromSeconds 10.0
                            MaxConnections = 16
                            RefreshInterval = TimeSpan.Zero
                            ReloadInterval = TimeSpan.Zero
                        }

                    let ws = Web3SignerModule.Web3SignerSet(connect h.Spec, s, h.Time, Log.none)
                    let! found, answered = ws.Discover CancellationToken.None
                    Expect.equal answered 1 "the gateway answers"
                    Expect.isGreaterThanOrEqual found.Length 4 "the gateway lists the Dist accounts"
                    let key, backend = found.Head

                    for duty in allDuties h do
                        let req =
                            Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                        let! o = backend.Sign req CancellationToken.None

                        match o, duty with
                        | Signed sg, _ -> Expect.isTrue (verify key req.SigningRoot sg) $"{duty.Kind} verifies"
                        | Refused(PolicyDenied _), Duty.VoluntaryExit _ -> () // the gateway never signs exits
                        | o, _ -> failtestf "%A: %s" duty.Kind o.Describe
                    // Two VCs with the same key, each with its own slashing DB: the gateway's Dirks refuse
                    // the second vote with 412, which halts the key in the second VC.
                    let vc () =
                        let db =
                            match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
                            | Ok db -> db
                            | Error e -> failwith e

                        db.RegisterKeys [ key, KeyOrigin.StartedEmpty ] |> ignore
                        let registry = KeyRegistry()
                        registry.Add(key, backend) |> ignore
                        registry.SetState(key, KeyState.Active)
                        db, registry, Pipeline(db, registry, h.Time, Log.none)

                    let dbA, _, a = vc ()
                    let dbB, registryB, b = vc ()
                    use _ = dbA
                    use _ = dbB

                    let vote (p: Pipeline) (n: int) =
                        let d =
                            {
                                Slot = 801UL
                                Index = 0UL
                                BeaconBlockRoot = root n
                                Source = { Epoch = 99UL; Root = root 4 }
                                Target = { Epoch = 100UL; Root = root 5 }
                            }

                        p.Sign(
                            Duty.request
                                h.Spec
                                gvr
                                key
                                Priority.High
                                (h.Time.GetUtcNow().AddSeconds 10.0)
                                (Duty.Attestation d),
                            CancellationToken.None
                        )

                    let! first = vote a 1

                    Expect.isTrue
                        (match first with
                         | Signed _ -> true
                         | _ -> false)
                        $"the first vote: {first.Describe}"

                    let! second = vote b 2

                    Expect.isTrue
                        (match second with
                         | Refused(Slashable _) -> true
                         | _ -> false)
                        $"the double vote: {second.Describe}"

                    Expect.isTrue
                        (match (registryB.TryGet key).Value.State with
                         | KeyState.Halted _ -> true
                         | _ -> false)
                        "the key is halted in the second VC"

                    ws.Stop()
                })
        ]

[<Tests>]
let tests =
    testList
        "web3signer-real"
        [
            (if String.IsNullOrEmpty launcher then
                 testList "web3signer-integration" [ ptest "set EPLIX_WEB3SIGNER to the web3signer launcher" { () } ]
             else
                 integration)
            (if String.IsNullOrEmpty pgDir then
                 testList
                     "web3signer-integration"
                     [
                         ptest "set EPLIX_WEB3SIGNER_PG to a directory of scripts/web3signer-pg.sh" { () }
                     ]
             else
                 withPostgres)
            (if String.IsNullOrEmpty gatewayUrl then
                 testList "web3signer-gateway" [ ptest "set EPLIX_GATEWAY_URL to a running gateway" { () } ]
             else
                 gateway)
        ]
