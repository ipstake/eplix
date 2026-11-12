/// Against real tee-signer runners, dev platform. Runs when
/// EPLIX_TEE_RUNNER names a runner binary built with -tags platform_dev,debugimport (the debug
/// build takes plaintext IMPORT_SHARE, which these tests use to load keys and shares);
/// scripts/tee-it.sh runs them. Each runner serves mutual TLS with a test CA made here and
/// answers IDENTITY with the dev platform's document; Eplix checks every connection with the
/// dev verifier and the runner's setup hash (the SHA-256 of its chain config) pinned.
///
/// Runners: "w" holds whole keys, "s1" to "s3" one share each of 2 of 3 keys, "f" runs with the
/// restart floor on (the others use persisted commit-ahead marks instead, so keys sign at once).
/// "g" (whole keys) and "g1" to "g3" (shares) run a chain config with Gloas from epoch 2 and one
/// builder request auth value on their allowlist.
module Eplix.Tests.TeeIntegrationTests

open System
open System.Collections.Concurrent
open System.Diagnostics
open System.IO
open System.Net.Sockets
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Tee
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.ThresholdTests

let runnerBin = Environment.GetEnvironmentVariable "EPLIX_TEE_RUNNER"
let aotBin = Environment.GetEnvironmentVariable "EPLIX_AOT_BIN"

let benchKeys =
    match Environment.GetEnvironmentVariable "EPLIX_TEE_BENCH" with
    | null
    | "" -> 0
    | s -> int s

/// A test CA, the client certificate the runners accept, and one from another CA.
module private Pki =
    let private ec () = ECDsa.Create(ECCurve.NamedCurves.nistP256)

    let private ca (cn: string) =
        let key = ec ()
        let req = CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256)
        req.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))

        req.CertificateExtensions.Add(
            X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign ||| X509KeyUsageFlags.CrlSign, true)
        )

        let now = DateTimeOffset.UtcNow
        req.CreateSelfSigned(now.AddDays -1.0, now.AddDays 30.0)

    let private client (issuer: X509Certificate2) (cn: string) (serial: byte) (dir: string) =
        use key = ec ()
        let req = CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256)
        let oids = OidCollection()
        oids.Add(Oid "1.3.6.1.5.5.7.3.2") |> ignore
        req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
        req.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true))
        let now = DateTimeOffset.UtcNow
        use cert = req.Create(issuer, now.AddDays -1.0, now.AddDays 30.0, [| serial; 7uy |])
        File.WriteAllText(Path.Combine(dir, $"{cn}.crt"), cert.ExportCertificatePem())
        File.WriteAllText(Path.Combine(dir, $"{cn}.key"), key.ExportPkcs8PrivateKeyPem())

    /// The admin OID of tee-signer's client roles (backend.AdminClientOID).
    let private adminOid = "1.2.840.113556.1.8000.2554.49247.57036.45844.17649.38356.1811430.10320378.2"

    /// An admin client: a leaf under an intermediate with pathlen 0, both marked with the admin
    /// OID, under the root. Since tee-signer's client roles only an admin certificate may import.
    let private admin (root: X509Certificate2) (dir: string) =
        use ikey = ec ()
        let ireq = CertificateRequest("CN=eplix test admin CA", ikey, HashAlgorithmName.SHA256)
        ireq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, true, 0, true))
        ireq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
        let ioids = OidCollection()
        ioids.Add(Oid "1.3.6.1.5.5.7.3.2") |> ignore
        ioids.Add(Oid adminOid) |> ignore
        ireq.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(ioids, false))
        ireq.CertificateExtensions.Add(X509SubjectKeyIdentifierExtension(ireq.PublicKey, false))
        let now = DateTimeOffset.UtcNow
        use icert0 = ireq.Create(root, now.AddDays -1.0, now.AddDays 30.0, [| 9uy; 1uy |])
        use icert = icert0.CopyWithPrivateKey ikey
        use key = ec ()
        let req = CertificateRequest("CN=eplix test admin", key, HashAlgorithmName.SHA256)
        let oids = OidCollection()
        oids.Add(Oid "1.3.6.1.5.5.7.3.2") |> ignore
        oids.Add(Oid adminOid) |> ignore
        req.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(oids, false))
        req.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true))
        use cert = req.Create(icert, now.AddDays -1.0, now.AddDays 30.0, [| 9uy; 2uy |])

        File.WriteAllText(
            Path.Combine(dir, "admin.crt"),
            cert.ExportCertificatePem() + string (char 10) + icert0.ExportCertificatePem() + string (char 10)
        )

        File.WriteAllText(Path.Combine(dir, "admin.key"), key.ExportPkcs8PrivateKeyPem())

    let make (dir: string) =
        use c = ca "eplix test runner CA"
        File.WriteAllText(Path.Combine(dir, "ca.crt"), c.ExportCertificatePem())
        client c "eplix" 2uy dir
        admin c dir
        use other = ca "another CA"
        client other "stranger" 3uy dir

/// The runner's chain config for the fake chain of FakeBeaconNode (core.Config of the runner).
let private chainJson =
    let hexs (b: byte[]) = "\"" + Hex.encodeArray b + "\""

    $$"""{
  "genesis_validators_root": {{hexs gvr.Bytes}},
  "genesis_fork_version": "0x00000001",
  "forks": [ { "epoch": 0, "version": "0x05000001" }, { "epoch": 1, "version": "0x06000001" } ],
  "voluntary_exit_fork_version": "0x03000001",
  "genesis_time": {{genesisTime}},
  "seconds_per_slot": {{secondsPerSlot}},
  "slots_per_epoch": {{slotsPerEpoch}},
  "max_epochs_ahead": 1,
  "exit_allowlist": [ 1 ],
  "fee_recipients": [ "0x1111111111111111111111111111111111111111" ],
  "gas_limit_min": 30000000,
  "gas_limit_max": 60000000,
  "registration_max_future_seconds": 3600,
  "commit_ahead": { "block_slots": 32, "source_epochs": 16, "target_epochs": 16 }
}
"""

let private gloasEpoch = 2UL

/// The auth data the Gloas runners allow (builder_request_auth_roots holds its root as
/// ByteList[4096]).
let private builderAuthData = Text.Encoding.ASCII.GetBytes "builder.example"

/// The same chain with Gloas (version 0x07000001, as FakeBeaconNode's spec) from gloasEpoch.
let private chainJsonGloas =
    let authRoot = Hex.encodeArray (Ssz.hashTreeRoot (Ssz.ByteList 4096) (Ssz.Bytes builderAuthData))

    chainJson
        .Replace(
            """{ "epoch": 1, "version": "0x06000001" } ]""",
            $$"""{ "epoch": 1, "version": "0x06000001" }, { "epoch": {{gloasEpoch}}, "version": "0x07000001" } ]"""
        )
        .Replace(
            "  \"commit_ahead\"",
            $"  \"gloas_fork_epoch\": {gloasEpoch},\n  \"builder_request_auth_roots\": [ \"{authRoot}\" ],\n  \"commit_ahead\""
        )

/// A harness whose chain spec schedules Gloas at gloasEpoch, as the Gloas runners' chain does.
let private gloasHarness () =
    let h = harness ()

    match ChainSpec.parse (Map.ofList (specValuesGloas secondsPerSlot slotsPerEpoch gloasEpoch)) with
    | Ok s -> { h with Spec = s }
    | Error e -> failwith e

let private freePort () =
    let l = new TcpListener(Net.IPAddress.Loopback, 0)
    l.Start()
    let p = (l.LocalEndpoint :?> Net.IPEndPoint).Port
    l.Stop()
    p

/// One runner process.
type RunnerProc(name: string, dir: string, floor: bool) =
    let port = freePort ()
    let state = Path.Combine(dir, $"state-{name}")
    let log = Path.Combine(dir, $"{name}.log")
    let mutable proc: Process voption = ValueNone

    member _.Name = name
    member _.Port = port
    member _.Log = log

    member _.Start() =
        let args =
            [
                "-platform"
                "dev"
                "-config"
                Path.Combine(dir, "chain.json")
                "-state-dir"
                state
                "-listen"
                $"tcp:127.0.0.1:{port}"
                "-tls-client-ca"
                Path.Combine(dir, "ca.crt")
                "-allow-import"
            ]
            @ (if floor then [] else [ "-restart-floor=false"; "-persist-watermarks=true" ])

        let line = String.Join(" ", args)
        let psi = ProcessStartInfo("bash", [ "-c"; $"""exec "{runnerBin}" {line} >> "{log}" 2>&1""" ])
        proc <- ValueSome(Process.Start psi)

    member _.Stop() =
        match proc with
        | ValueSome p ->
            try
                p.Kill true
                p.WaitForExit()
            with _ ->
                ()

            proc <- ValueNone
        | ValueNone -> ()

/// The runners over a temporary directory, started once for all tests.
type Cluster() =
    let dir = tempDir ()
    let chainPath = Path.Combine(dir, "chain.json")

    do
        Pki.make dir
        File.WriteAllText(chainPath, chainJson)

    let setupHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes chainPath))
    let gdir = Path.Combine(dir, "gloas")

    do
        Directory.CreateDirectory gdir |> ignore
        File.Copy(Path.Combine(dir, "ca.crt"), Path.Combine(gdir, "ca.crt"))
        File.WriteAllText(Path.Combine(gdir, "chain.json"), chainJsonGloas)

    let gloasHash =
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(gdir, "chain.json"))))

    let runners =
        [
            for n, d, floor in
                [
                    "w", dir, false
                    "s1", dir, false
                    "s2", dir, false
                    "s3", dir, false
                    "f", dir, true
                    "g", gdir, false
                    "g1", gdir, false
                    "g2", gdir, false
                    "g3", gdir, false
                ] -> n, RunnerProc(n, d, floor)
        ]
        |> Map.ofList
    // Each test signs with keys of its own: the runners keep their marks across tests.
    let wholeSecrets = [ for i in 0..5 -> secretOf (200 + i) ]
    let groups = [ for s in 0..3 -> shamir (700 + s) 2 [ 1UL; 2UL; 3UL ] ]
    let bench = [ for s in 0 .. benchKeys - 1 -> shamir (5000 + s) 2 [ 1UL; 2UL; 3UL ] ]
    let gloasWhole = [ for i in 0..1 -> secretOf (400 + i) ]
    let gloasGroup = shamir 7400 2 [ 1UL; 2UL; 3UL ]

    do
        for KeyValue(_, r) in runners do
            r.Start()

        AppDomain.CurrentDomain.ProcessExit.Add(fun _ ->
            for KeyValue(_, r) in runners do
                r.Stop())

    member _.Dir = dir
    member _.SetupHash = setupHash
    /// The setup hash a runner reports: that of its own chain config.
    member _.PinOf(n: string) = if n.StartsWith "g" then gloasHash else setupHash
    member _.GloasWhole = gloasWhole
    member _.GloasGroup = gloasGroup
    member _.Runner(n: string) = runners[n]
    member _.WholeKeys = wholeSecrets |> List.map pk
    member _.WholeSecrets = wholeSecrets
    member _.Groups = groups
    member _.Bench = bench

    member _.Verifier(pin: string) =
        match
            Attest.build
                Attest.NetworkKind.Testnet
                { Attest.Settings.Empty with
                    Verifier = "dev"
                    SetupSha256 = [ pin ]
                }
                (fun _ _ -> failwith "no key sets")
                []
        with
        | Ok v -> v
        | Error e -> failwith e

    member this.Settings(n: string, ?client: string, ?pin: string) : RunnerSettings =
        let client = defaultArg client "eplix"

        {
            Name = n
            Host = "127.0.0.1"
            Port = runners[n].Port
            ClientCert =
                TlsFile<_>
                    .Fixed(
                        (let crt = Path.Combine(dir, $"{client}.crt")
                         // The intermediates after the leaf go along in the handshake (the admin chain).
                         let chain = X509Certificate2Collection()
                         chain.ImportFromPemFile crt
                         let extra = X509Certificate2Collection()

                         for i in 1 .. chain.Count - 1 do
                             extra.Add chain[i] |> ignore

                         Net.Security.SslStreamCertificateContext.Create(
                             X509Certificate2.CreateFromPemFile(crt, Path.Combine(dir, $"{client}.key")),
                             extra,
                             offline = true
                         )),
                        DateTimeOffset.MaxValue
                    )
            TlsKeyPin = ValueNone
            AllowTestnetBuild = false
            Verifier = this.Verifier(defaultArg pin (this.PinOf n))
        }

    member this.Dial(n: string) =
        task {
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
            return! RunnerConnection.Dial(this.Settings n, (fun () -> DateTimeOffset.UtcNow), cts.Token)
        }

    /// Waits until the runner takes connections.
    member this.WaitUp(n: string) =
        task {
            let sw = Stopwatch.StartNew()
            let mutable up = false
            let mutable last = ""

            while not up && sw.Elapsed < TimeSpan.FromSeconds 30.0 do
                try
                    let! c = this.Dial n
                    c.Close()
                    up <- true
                with e ->
                    last <- e.Message
                    do! Task.Delay 200

            if not up then
                failtestf "runner %s did not come up: %s; log %s" n last runners[n].Log
        }

    /// Loads (validator key, secret) pairs into a runner with the debug build's plaintext import.
    member this.Import(n: string, keys: (PubKey * byte[]) list) =
        task {
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
            let! c = RunnerConnection.Dial(this.Settings(n, "admin"), (fun () -> DateTimeOffset.UtcNow), cts.Token)

            try
                for v, secret in keys do
                    let p = Array.concat [ v.Bytes; secret; Array.create 8 0xffuy; Array.zeroCreate 25 ]
                    let! f = c.Send(Wire.MsgType.ImportShare, p, CancellationToken.None)

                    match Wire.decodeResponse f.Payload with
                    | Ok _ -> ()
                    | Error r when r.Code = Wire.Status.Duplicate -> ()
                    | Error r -> failtestf "import into %s: %s %s" n (Wire.Status.name r.Code) r.Detail
            finally
                c.Close()
        }

    member _.Stop(n: string) = runners[n].Stop()
    member _.Start(n: string) = runners[n].Start()

let private cluster =
    lazy
        (let c = Cluster()

         task {
             for n in [ "w"; "s1"; "s2"; "s3"; "f"; "g"; "g1"; "g2"; "g3" ] do
                 do! c.WaitUp n

             do! c.Import("w", [ for s in c.WholeSecrets -> pk s, s ])
             do! c.Import("f", [ for s in c.WholeSecrets -> pk s, s ])

             for m in 0..2 do
                 do! c.Import($"s{m + 1}", [ for secret, shares in c.Groups @ c.Bench -> pk secret, snd shares[m] ])

             do! c.Import("g", [ for s in c.GloasWhole -> pk s, s ])
             let gSecret, gShares = c.GloasGroup

             for m in 0..2 do
                 do! c.Import($"g{m + 1}", [ pk gSecret, snd gShares[m] ])
         }
         |> fun t -> t.GetAwaiter().GetResult()

         c)

let private teeSettings (c: Cluster) (runners: string list) (groups: TeeModule.GroupConfig list) : TeeModule.Settings =
    {
        Runners =
            [
                for n in runners ->
                    {
                        Name = n
                        Host = "127.0.0.1"
                        Port = c.Runner(n).Port
                        ClientCert = Path.Combine(c.Dir, "eplix.crt")
                        ClientKey = Path.Combine(c.Dir, "eplix.key")
                        TlsKeyPin = ValueNone
                        AllowTestnetBuild = false
                        Connections = 8
                        Attestation =
                            { Attest.Settings.Empty with
                                Verifier = "dev"
                                SetupSha256 = [ c.PinOf n ]
                            }
                    }
            ]
        Groups = groups
        Timeout = TimeSpan.FromSeconds 5.0
        DialTimeout = TimeSpan.FromSeconds 10.0
        LowEvery = 8
        RefreshInterval = TimeSpan.Zero
        Keys = TeeModule.KeyFilter.AnyListedTestOnly
        AttestationCaFile = ValueNone
        ReloadInterval = TimeSpan.Zero
        RotateWithin = TimeSpan.FromSeconds 300.0
        HaPeer = false
        Network = Attest.NetworkKind.Testnet
    }

let private group3: TeeModule.GroupConfig =
    {
        Threshold = 2
        Members = [ "s1", 1UL; "s2", 2UL; "s3", 3UL ]
    }

let private groupG: TeeModule.GroupConfig =
    {
        Threshold = 2
        Members = [ "g1", 1UL; "g2", 2UL; "g3", 3UL ]
    }

/// A TeeSet over real pools to the named runners.
let private openWith
    (c: Cluster)
    (runners: string list)
    (groups: TeeModule.GroupConfig list)
    (time: TimeProvider)
    (timeout: TimeSpan)
    =
    let s =
        { teeSettings c runners groups with
            Timeout = timeout
        }

    match TeeModule.prepare s Log.none TimeProvider.System (fun _ _ -> failwith "no key sets") with
    | Error e -> failtest e
    | Ok prepared -> TeeModule.TeeSet(TeeModule.connect s prepared Log.none, s, time, Log.none)

let private open' c runners groups time = openWith c runners groups time (TimeSpan.FromSeconds 5.0)

/// Every duty kind, with real selection proofs inside the aggregate and the contribution.
let private allDuties (h: Harness) (sign: Duty -> Task<BlsSignature>) =
    task {
        let p = h.Node.Preset
        let! aggProof = sign (Duty.AggregationSlot 0UL)
        let! syncProof = sign (Duty.SyncSelectionProof { Slot = 0UL; SubcommitteeIndex = 0UL })

        let withProof (schema: Ssz.SszType) (proof: BlsSignature) =
            match Ssz.zero schema with
            | Ssz.Fields f ->
                let f = Array.copy f
                f[2] <- Ssz.Bytes proof.Bytes

                {
                    Schema = schema
                    Value = Ssz.Fields f
                }
            | _ -> failwith "a container"

        return
            [
                Duty.Attestation
                    {
                        Slot = 41UL
                        Index = 0UL
                        BeaconBlockRoot = root 1
                        Source = { Epoch = 4UL; Root = root 4 }
                        Target = { Epoch = 5UL; Root = root 5 }
                    }
                Duty.Block
                    {
                        Slot = 40UL
                        ProposerIndex = 1UL
                        ParentRoot = root 1
                        StateRoot = root 2
                        BodyRoot = root 3
                    }
                Duty.RandaoReveal 5UL
                Duty.AggregationSlot 41UL
                Duty.AggregateAndProof(0UL, withProof (Schemas.aggregateAndProof p) aggProof)
                Duty.SyncCommitteeMessage(41UL, root 9)
                Duty.SyncSelectionProof { Slot = 41UL; SubcommitteeIndex = 1UL }
                Duty.ContributionAndProof(0UL, withProof (Schemas.contributionAndProof p) syncProof)
                Duty.VoluntaryExit { Epoch = 5UL; ValidatorIndex = 1UL }
            ]
    }

let private verify (key: PubKey) (req: SignRequest) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan key.Bytes) (ReadOnlySpan req.SigningRoot.Bytes) (ReadOnlySpan s.Bytes)

let private percentile (xs: float[]) (p: float) =
    let s = Array.sort xs
    s[min (s.Length - 1) (int (Math.Ceiling(p * float s.Length)) - 1)]

let private integration =
    testSequenced
    <| testList
        "tee-integration"
        [
            testT "every connection is attested; a stranger's certificate and another setup pin are refused" (fun () ->
                task {
                    let c = cluster.Value

                    for n in [ "w"; "s1"; "s2"; "s3" ] do
                        let! conn = c.Dial n
                        Expect.equal conn.Identity.Attestation.Platform "dev" "dev platform"

                        Expect.equal
                            conn.Identity.State.SetupHash.Hex
                            ("0x" + c.SetupHash)
                            "setup hash = sha256 of the chain config"
                        // A runner without a setup (the flag path) reports its chain config's hash and zero
                        // for the rest, the key origin included.
                        Expect.isTrue conn.Identity.State.FlagPath "flag path"
                        let! f = conn.Send(Wire.MsgType.Health, [||], CancellationToken.None)

                        match Wire.decodeResponse f.Payload with
                        | Ok b ->
                            let h = Wire.decodeHealth b
                            Expect.equal h.Platform "dev" "HEALTH"
                            Expect.isGreaterThanOrEqual h.Protocol Wire.ProtocolLevel "protocol level"

                            Expect.isTrue h.Ready "ready"
                        | Error r -> failtestf "HEALTH: %s" (Wire.Status.name r.Code)

                        conn.Close()

                    let tryDial (s: RunnerSettings) =
                        task {
                            try
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 10.0)
                                let! conn = RunnerConnection.Dial(s, (fun () -> DateTimeOffset.UtcNow), cts.Token)
                                conn.Close()
                                return "connected"
                            with e ->
                                return e.Message
                        }

                    let! stranger = tryDial (c.Settings("w", client = "stranger"))
                    Expect.notEqual stranger "connected" "a client certificate from another CA"
                    let! otherPin = tryDial (c.Settings("w", pin = String('9', 64)))
                    Expect.stringContains otherPin "is not the pinned setup_sha256" "another setup pin"

                    let! pinned =
                        tryDial
                            { c.Settings "w" with
                                TlsKeyPin = ValueSome(Array.zeroCreate 32)
                            }

                    Expect.stringContains pinned "is not the pinned key" "a TLS key pin of another key"
                })

            testT
                "every duty kind signs through one runner (whole keys) and through 2 of 3 runners (shares), and verifies"
                (fun () ->
                    task {
                        let c = cluster.Value
                        let h = harness ()
                        let set = open' c [ "w"; "s1"; "s2"; "s3" ] [ group3 ] TimeProvider.System
                        let! found, answered = set.Discover CancellationToken.None
                        Expect.equal answered 4 "four runners answer"
                        let found = Map.ofList found

                        for k in c.WholeKeys do
                            Expect.equal found[k].Name "tee w" "a whole key"

                        for secret, _ in c.Groups do
                            Expect.stringContains found[pk secret].Name "tee 2 of 3" "a threshold key"

                        for key in [ c.WholeKeys.Head; pk (fst c.Groups.Head) ] do
                            let backend = found[key]

                            let signOne (duty: Duty) =
                                task {
                                    let req =
                                        Duty.request
                                            h.Spec
                                            gvr
                                            key
                                            Priority.High
                                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                            duty

                                    match! backend.Sign req CancellationToken.None with
                                    | Signed s ->
                                        Expect.isTrue (verify key req s) $"{backend.Name} {duty.Kind} verifies"
                                        return s
                                    | o -> return failtestf "%s %A: %s" backend.Name duty.Kind o.Describe
                                }

                            let! duties = allDuties h signOne
                            // Kind 4, the pre-Gloas registration, signed by a whole key and a 2 of 3 group.
                            // The runner checks it against its chain config: the fee recipient on
                            // fee_recipients, the gas limit within gas_limit_min and gas_limit_max.
                            let registration (fee: byte) (gas: uint64) =
                                Duty.ValidatorRegistration
                                    {
                                        FeeRecipient = Array.create 20 fee
                                        GasLimit = gas
                                        Timestamp = uint64 (DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                                        PubKey = key
                                    }

                            for duty in duties @ [ registration 0x11uy 60_000_000UL ] do
                                let! _ = signOne duty
                                ()

                            for duty, why in
                                [
                                    registration 0xAAuy 60_000_000UL, "FEE_RECIPIENT"
                                    registration 0x11uy 70_000_000UL, "GAS"
                                ] do
                                let req =
                                    Duty.request
                                        h.Spec
                                        gvr
                                        key
                                        Priority.High
                                        (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                        duty

                                match! backend.Sign req CancellationToken.None with
                                | Refused(PolicyDenied m) ->
                                    Expect.stringContains m why $"{backend.Name}: refused off the runner's policy"
                                // A group: every member refused, so too few signed.
                                | Refused(Denied(_, t)) when t.Signed = 0 && t.Denied >= 2 -> ()
                                | o -> failtestf "%s: a registration off the policy: %s" backend.Name o.Describe

                        set.Stop()
                    })

            testT "a runner's slashing refusal halts the key in the VC that sent the second vote" (fun () ->
                task {
                    let c = cluster.Value
                    let h = harness ()
                    let set = open' c [ "w" ] [] TimeProvider.System
                    let! found, _ = set.Discover CancellationToken.None
                    let key = c.WholeKeys[5]
                    let backend = (Map.ofList found)[key]

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

                    let dbA, registryA, a = vc ()
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

                    let! again = vote a 1

                    Expect.isTrue
                        (match again with
                         | Signed _ -> true
                         | _ -> false)
                        $"an exact repeat signs again: {again.Describe}"

                    let! second = vote b 2

                    Expect.isTrue
                        (match second with
                         | Refused(Slashable m) -> m.Contains "SC_ERR_SLASH"
                         | _ -> false)
                        $"the double vote: {second.Describe}"

                    Expect.isTrue
                        (match (registryB.TryGet key).Value.State with
                         | KeyState.Halted _ -> true
                         | _ -> false)
                        "the key is halted in the second VC"

                    Expect.equal (registryA.TryGet key).Value.State KeyState.Active "and still active in the first"
                    set.Stop()
                })

            testT "a runner in its restart floor answers not ready; the key is not halted" (fun () ->
                task {
                    let c = cluster.Value
                    let h = harness ()
                    let set = open' c [ "f" ] [] TimeProvider.System
                    let! found, _ = set.Discover CancellationToken.None
                    let key = c.WholeKeys[0]
                    let backend = (Map.ofList found)[key]
                    // The fake chain's epochs are far below the runner's clock epoch, so below its floor.
                    let d =
                        {
                            Slot = 41UL
                            Index = 0UL
                            BeaconBlockRoot = root 1
                            Source = { Epoch = 4UL; Root = root 4 }
                            Target = { Epoch = 5UL; Root = root 5 }
                        }

                    let req =
                        Duty.request
                            h.Spec
                            gvr
                            key
                            Priority.High
                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                            (Duty.Attestation d)

                    match! backend.Sign req CancellationToken.None with
                    | Refused(Refusal.NotReadyUntil(ValueSome e)) ->
                        Expect.isGreaterThan e 5UL "not ready until after the floor"
                    | o -> failtestf "expected not ready, got %s" o.Describe
                    // Non-slashable kinds still sign in the floor.
                    let r2 =
                        Duty.request
                            h.Spec
                            gvr
                            key
                            Priority.High
                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                            (Duty.RandaoReveal 5UL)

                    match! backend.Sign r2 CancellationToken.None with
                    | Signed s -> Expect.isTrue (verify key r2 s) "RANDAO in the floor"
                    | o -> failtestf "RANDAO: %s" o.Describe

                    set.Stop()
                })

            testT
                "Gloas kinds sign through one runner (whole keys) and 2 of 3 runners (shares), and verify; refusals map"
                (fun () ->
                    task {
                        let c = cluster.Value
                        let h = gloasHarness ()
                        let p = h.Node.Preset
                        let set = open' c [ "g"; "g1"; "g2"; "g3" ] [ groupG ] TimeProvider.System
                        let! found, answered = set.Discover CancellationToken.None
                        Expect.equal answered 4 "four Gloas runners answer"
                        let found = Map.ofList found
                        let fee = Array.create 20 0x11uy
                        // Slots in epoch 5, after the Gloas fork at epoch 2.
                        let slot = 41UL

                        for key in [ pk c.GloasWhole.Head; pk (fst c.GloasGroup) ] do
                            let backend = found[key]

                            let sign (duty: Duty) =
                                task {
                                    let req =
                                        Duty.request
                                            h.Spec
                                            gvr
                                            key
                                            Priority.High
                                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                            duty

                                    let! o = backend.Sign req CancellationToken.None
                                    return req, o
                                }

                            let signed (duty: Duty) =
                                task {
                                    match! sign duty with
                                    | req, Signed s ->
                                        Expect.isTrue (verify key req s) $"{backend.Name} {duty.Kind} verifies"
                                        return s
                                    | _, o -> return failtestf "%s %A: %s" backend.Name duty.Kind o.Describe
                                }

                            let! _ =
                                signed (
                                    Duty.PayloadAttestation
                                        {
                                            BeaconBlockRoot = root 7
                                            Slot = slot
                                            PayloadPresent = true
                                            BlobDataAvailable = false
                                        }
                                )

                            let! _ =
                                signed (
                                    Duty.ProposerPreferences
                                        {
                                            DependentRoot = root 3
                                            ProposalSlot = slot + 2UL
                                            ValidatorIndex = 1UL
                                            FeeRecipient = fee
                                            TargetGasLimit = 36_000_000UL
                                        }
                                )
                            // Builder request auth: tee-signer hashes the plain Container, as Eplix does.
                            let! _ =
                                signed (
                                    Duty.BuilderRequestAuth
                                        {
                                            AuthData = builderAuthData
                                            AuthSlot = slot + 2UL
                                        }
                                )
                            // The aggregate in its Gloas form (kind 9, form 2) with a real selection proof.
                            let! proof = signed (Duty.AggregationSlot slot)

                            let aggregate =
                                match Ssz.zero (Schemas.Gloas.aggregateAndProof p) with
                                | Ssz.Fields f ->
                                    let att = Codec.fields f[1]
                                    (Codec.fields att[1]).[0] <- Ssz.U slot
                                    att[0] <- Ssz.Bits [| true; false; true |]
                                    f[2] <- Ssz.Bytes proof.Bytes
                                    Ssz.Fields f
                                | v -> v

                            let! _ =
                                signed (
                                    Duty.AggregateAndProof(
                                        slot,
                                        {
                                            Schema = Schemas.Gloas.aggregateAndProof p
                                            Value = aggregate
                                        }
                                    )
                                )
                            // A self-built envelope for the block the key signed last, with content in the
                            // variable fields the runner gets as roots.
                            let header =
                                {
                                    Slot = slot + 1UL
                                    ProposerIndex = 1UL
                                    ParentRoot = root 1
                                    StateRoot = root 2
                                    BodyRoot = root 3
                                }

                            let! _ = signed (Duty.Block header)
                            let envSchema = Schemas.Gloas.executionPayloadEnvelope p

                            let envelope =
                                match Ssz.zero envSchema with
                                | Ssz.Fields f ->
                                    let pay = Codec.fields f[0]
                                    pay[0] <- Ssz.Bytes (root 11).Bytes
                                    pay[1] <- Ssz.Bytes fee
                                    pay[4] <- Ssz.Bytes(Array.init 256 byte)
                                    pay[6] <- Ssz.U 1234UL
                                    pay[10] <- Ssz.Bytes [| 1uy; 2uy; 3uy |]
                                    pay[11] <- Ssz.Bytes(Array.init 32 (fun i -> if i = 0 then 7uy else 0uy))
                                    pay[13] <- Ssz.Items [| Ssz.Bytes [| 0xdeuy; 0xaduy |]; Ssz.Bytes [| 0xbeuy |] |]
                                    pay[17] <- Ssz.Bytes [| 9uy; 9uy |]
                                    pay[18] <- Ssz.U header.Slot
                                    f[2] <- Ssz.U UInt64.MaxValue
                                    f[3] <- Ssz.Bytes (Codec.hashBeaconBlockHeader header).Bytes
                                    f[4] <- Ssz.Bytes header.ParentRoot.Bytes
                                    Ssz.Fields f
                                | v -> v

                            let! _ =
                                signed (Duty.PayloadEnvelope(header.Slot, { Schema = envSchema; Value = envelope }))
                            // A second PTC vote for the slot: the runner's equivocation code.
                            match!
                                sign (
                                    Duty.PayloadAttestation
                                        {
                                            BeaconBlockRoot = root 8
                                            Slot = slot
                                            PayloadPresent = false
                                            BlobDataAvailable = false
                                        }
                                )
                            with
                            | _, Refused(Slashable m) ->
                                Expect.stringContains m "SC_ERR_EQUIVOCATION" "a second PTC vote for the slot"
                            | _, o -> failtestf "%s: second PTC vote: %s" backend.Name o.Describe

                        set.Stop()
                        // Kind 14 on the wire: tee-signer signs allowed auth data over the plain Container
                        // root, the one Eplix and Web3Signer 26.10.1 sign, and refuses data off
                        // its allowlist.
                        let key = pk c.GloasWhole.Head
                        let! conn = c.Dial "g"

                        try
                            let send (data: byte[]) =
                                task {
                                    let req =
                                        Duty.request
                                            h.Spec
                                            gvr
                                            key
                                            Priority.High
                                            (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                            (Duty.BuilderRequestAuth
                                                {
                                                    AuthData = data
                                                    AuthSlot = slot + 2UL
                                                })

                                    let! f = conn.Send(Wire.MsgType.Sign, Wire.encodeSign req, CancellationToken.None)
                                    return req, Wire.decodeResponse f.Payload
                                }

                            match! send builderAuthData with
                            | req, Ok b ->
                                let s = Wire.decodeSignature b
                                Expect.isTrue (verify key req s) "over Eplix's Container root"
                            | _, Error r -> failtestf "kind 14: %s %s" (Wire.Status.name r.Code) r.Detail

                            match! send (Text.Encoding.ASCII.GetBytes "other.example") with
                            | _, Error r ->
                                Expect.equal r.Code Wire.Status.PolicyBuilderAuth "auth data off the allowlist"
                            | _, Ok _ -> failtest "other auth data signed"
                        finally
                            conn.Close()
                        // A runner whose chain has no Gloas refuses the Gloas kinds as a policy matter.
                        let fulu = harness ()
                        let w = open' c [ "w" ] [] TimeProvider.System
                        let! foundW, _ = w.Discover CancellationToken.None
                        let key = c.WholeKeys[4]

                        let req =
                            Duty.request
                                fulu.Spec
                                gvr
                                key
                                Priority.High
                                (DateTimeOffset.UtcNow.AddSeconds 10.0)
                                (Duty.PayloadAttestation
                                    {
                                        BeaconBlockRoot = root 7
                                        Slot = slot
                                        PayloadPresent = true
                                        BlobDataAvailable = false
                                    })

                        let backendW = (Map.ofList foundW)[key]

                        match! backendW.Sign req CancellationToken.None with
                        | Refused(PolicyDenied m) ->
                            Expect.stringContains m "SC_ERR_POLICY_FORK" "no Gloas in the runner's chain"
                        | o -> failtestf "PTC vote on a chain without Gloas: %s" o.Describe

                        w.Stop()
                    })

            testT
                "duties on the fake beacon node through the runners, with one share runner stopped half way"
                (fun () ->
                    task {
                        let c = cluster.Value
                        let h = harness ()
                        // The group's member timers use the deadline, which is on the scheduler's clock.
                        let set = open' c [ "w"; "s1"; "s2"; "s3" ] [ group3 ] h.Time
                        let! found, _ = set.Discover CancellationToken.None
                        let found = Map.ofList found

                        let routes =
                            [ for k in c.WholeKeys[1..2] -> k, found[k] ]
                            @ [ for s, _ in c.Groups.Tail -> pk s, found[pk s] ]

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

                        try
                            for s in 0UL .. 15UL do
                                if s = 8UL then
                                    c.Stop "s3"

                                do! h.RunSlots(s, s)

                                if s = 5UL then
                                    do! waitBlocks 1

                                if s = 12UL then
                                    do! waitBlocks 2
                        finally
                            c.Start "s3"

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
                            $"blocks at slots 5 (whole key) and 12 (share key, s3 down); log:\n{String.Join('\n', lines)}"

                        do! c.WaitUp "s3"
                        set.Stop()
                    })

            testT "burst: 1,000 attestations through 2 of 3 runners (EPLIX_TEE_BENCH keys)" (fun () ->
                task {
                    let c = cluster.Value

                    if c.Bench.IsEmpty then
                        skiptest "set EPLIX_TEE_BENCH to the number of keys (1000)"

                    let h = harness ()

                    let set =
                        openWith c [ "s1"; "s2"; "s3" ] [ group3 ] TimeProvider.System (TimeSpan.FromSeconds 60.0)

                    let! found, _ = set.Discover CancellationToken.None
                    let found = Map.ofList found
                    let keys = [| for s, _ in c.Bench -> pk s |]
                    let backend = found[keys[0]]
                    let results = ResizeArray<string>()
                    // Warm-up: one vote of every key. The runners write each key's mark 16 epochs ahead
                    // (commit_ahead), one fsync per key; the measured rounds after it write none, as a
                    // runner in steady state with its mark raised once per epoch.
                    let warm =
                        Duty.Attestation
                            {
                                Slot = 72UL
                                Index = 0UL
                                BeaconBlockRoot = root 1
                                Source = { Epoch = 8UL; Root = root 4 }
                                Target = { Epoch = 9UL; Root = root 5 }
                            }

                    let sw0 = Stopwatch.StartNew()

                    let! w =
                        Task.WhenAll
                            [
                                for k in keys ->
                                    backend.Sign
                                        (Duty.request
                                            h.Spec
                                            gvr
                                            k
                                            Priority.High
                                            (DateTimeOffset.UtcNow.AddSeconds 120.0)
                                            warm)
                                        CancellationToken.None
                            ]

                    Expect.isTrue
                        (w
                         |> Array.forall (fun o ->
                             match o with
                             | Signed _ -> true
                             | _ -> false))
                        "warm-up signed"

                    results.Add
                        $"warm-up: {keys.Length} first votes (one mark write each) in {sw0.Elapsed.TotalMilliseconds:F0} ms"

                    for round in 0..2 do
                        let target = 10UL + uint64 round

                        let duty =
                            Duty.Attestation
                                {
                                    Slot = target * 8UL
                                    Index = 0UL
                                    BeaconBlockRoot = root 1
                                    Source = { Epoch = target - 1UL; Root = root 4 }
                                    Target = { Epoch = target; Root = root 5 }
                                }

                        let reqs =
                            Duty.requests h.Spec gvr keys Priority.High (DateTimeOffset.UtcNow.AddSeconds 60.0) duty

                        let lat = Array.zeroCreate<float> reqs.Length
                        let cpu0 = Process.GetCurrentProcess().TotalProcessorTime
                        let sw = Stopwatch.StartNew()

                        let! outs =
                            reqs
                            |> Array.mapi (fun i r ->
                                task {
                                    let! o = backend.Sign r CancellationToken.None
                                    lat[i] <- sw.Elapsed.TotalMilliseconds
                                    return o
                                })
                            |> Task.WhenAll

                        let total = sw.Elapsed.TotalMilliseconds
                        let cpu = (Process.GetCurrentProcess().TotalProcessorTime - cpu0).TotalMilliseconds

                        let signed =
                            outs
                            |> Array.filter (fun o ->
                                match o with
                                | Signed _ -> true
                                | _ -> false)
                            |> Array.length

                        Expect.equal
                            signed
                            reqs.Length
                            $"all signed: {(outs
                                            |> Array.tryFind (fun o ->
                                                match o with
                                                | Signed _ -> false
                                                | _ -> true)
                                            |> Option.map (fun o -> o.Describe))}"

                        let line =
                            $"round {round}: {reqs.Length} attestations, 2 of 3, 8 connections per runner: p50 {percentile lat 0.5:F1} ms, p99 {percentile lat 0.99:F1} ms, all done {total:F1} ms, Eplix CPU {cpu:F0} ms"

                        results.Add line
                        printfn "%s" line

                    File.WriteAllLines(Path.Combine(c.Dir, "bench.txt"), results)
                    set.Stop()
                })
        ]

/// The published NativeAOT binary attests for whole keys and a 2 of 3 key through runners of
/// their own, against scripts/fake-beacon-node.py on the wall clock: TLS, IDENTITY, the
/// attestation check and the SIGN codec as compiled ahead of time.
let private smoke =
    testT "the published binary attests through the runners (EPLIX_AOT_BIN)" (fun () ->
        task {
            let c = cluster.Value
            let dir = tempDir ()
            let whole = [ for i in 0..1 -> secretOf (300 + i) ]
            let grp = shamir 7300 2 [ 1UL; 2UL; 3UL ]
            let pubkeys = (whole |> List.map pk) @ [ pk (fst grp) ]
            File.WriteAllLines(Path.Combine(dir, "pubkeys.txt"), [ for k in pubkeys -> k.Hex ])
            let bnPort = freePort ()

            let bn =
                Process.Start(
                    ProcessStartInfo(
                        "bash",
                        [
                            "-c"
                            $"""exec python3 -I "{repoRoot}/scripts/fake-beacon-node.py" {bnPort} "{dir}/pubkeys.txt" 2 8 > "{dir}/bn.log" 2>&1"""
                        ]
                    )
                )

            try
                use http = new Net.Http.HttpClient()
                let mutable genesis = ""
                let sw = Stopwatch.StartNew()

                while genesis = "" && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                    try
                        let! body = http.GetStringAsync $"http://127.0.0.1:{bnPort}/eth/v1/beacon/genesis"
                        use d = Text.Json.JsonDocument.Parse body

                        genesis <-
                            d.RootElement.GetProperty("data").GetProperty("genesis_time").GetString() |> Wire.nonNull
                    with _ ->
                        do! Task.Delay 100
                // The runners' chain: the fake node's (every fork at epoch 0, Fulu in force).
                let chain =
                    chainJson
                        .Replace(Hex.encodeArray gvr.Bytes, "0x" + String.replicate 32 "a0")
                        .Replace(
                            """[ { "epoch": 0, "version": "0x05000001" }, { "epoch": 1, "version": "0x06000001" } ]""",
                            """[ { "epoch": 0, "version": "0x06000001" } ]"""
                        )
                        .Replace($"\"genesis_time\": {genesisTime}", $"\"genesis_time\": {genesis}")
                        .Replace($"\"seconds_per_slot\": {secondsPerSlot}", "\"seconds_per_slot\": 2")

                File.WriteAllText(Path.Combine(dir, "chain.json"), chain)
                File.Copy(Path.Combine(c.Dir, "ca.crt"), Path.Combine(dir, "ca.crt"))

                for f in [ "eplix.crt"; "eplix.key" ] do
                    File.Copy(Path.Combine(c.Dir, f), Path.Combine(dir, f))

                let runners = [ for n in [ "a"; "b"; "c" ] -> RunnerProc(n, dir, false) ]

                for r in runners do
                    r.Start()

                let pin = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(dir, "chain.json"))))

                let importInto (r: RunnerProc) (keys: (PubKey * byte[]) list) =
                    task {
                        let mutable conn = None
                        let sw = Stopwatch.StartNew()

                        while conn.IsNone && sw.Elapsed < TimeSpan.FromSeconds 30.0 do
                            try
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)

                                let! x =
                                    RunnerConnection.Dial(
                                        { c.Settings("w", "admin", pin) with
                                            Name = r.Name
                                            Port = r.Port
                                        },
                                        (fun () -> DateTimeOffset.UtcNow),
                                        cts.Token
                                    )

                                conn <- Some x
                            with _ ->
                                do! Task.Delay 200

                        let x =
                            match conn with
                            | Some x -> x
                            | None -> failtestf "runner %s did not come up; log %s" r.Name r.Log

                        for v, secret in keys do
                            let p = Array.concat [ v.Bytes; secret; Array.create 8 0xffuy; Array.zeroCreate 25 ]
                            let! f = x.Send(Wire.MsgType.ImportShare, p, CancellationToken.None)

                            match Wire.decodeResponse f.Payload with
                            | Ok _ -> ()
                            | Error e -> failtestf "import: %s" (Wire.Status.name e.Code)

                        x.Close()
                    }

                let gSecret, gShares = grp
                let share i = snd gShares.[i]
                do! importInto runners[0] ([ for s in whole -> pk s, s ] @ [ pk gSecret, share 0 ])
                do! importInto runners[1] [ pk gSecret, share 1 ]
                do! importInto runners[2] [ pk gSecret, share 2 ]

                let runnerJson (r: RunnerProc) =
                    $$"""{ "name": "{{r.Name}}", "address": "tcp:127.0.0.1:{{r.Port}}", "client_cert": "eplix.crt", "client_key": "eplix.key",
                       "connections": 4, "attestation": { "verifier": "dev", "setup_sha256": "{{pin}}" } }"""

                File.WriteAllText(
                    Path.Combine(dir, "chain.yaml"),
                    (configYaml 2 8)
                        .Replace("ELECTRA_FORK_EPOCH: 0", "ELECTRA_FORK_EPOCH: 0")
                        .Replace("FULU_FORK_EPOCH: 1", "FULU_FORK_EPOCH: 0")
                )

                let runnersJson = String.Join(", ", runners |> List.map runnerJson)

                File.WriteAllText(
                    Path.Combine(dir, "eplix.json"),
                    $$"""{ "beacon_node": "http://127.0.0.1:{{bnPort}}", "chain_config": "chain.yaml", "data_dir": "data",
  "allow_start_without_history": ["all"],
  "modules": { "doppelganger": { "enabled": false }, "keymanager": { "port": {{freePort ()}} }, "metrics": { "port": {{freePort ()}} }, "tee": { "runners": [ {{runnersJson}} ],
                        "groups": [ { "threshold": 2, "members": [ { "runner": "a", "index": 1 }, { "runner": "b", "index": 2 }, { "runner": "c", "index": 3 } ] } ],
                        "keys_file": "pubkeys.txt" } } }"""
                )

                let vcLog = Path.Combine(dir, "vc.log")

                let vc =
                    Process.Start(
                        ProcessStartInfo(
                            "bash",
                            [
                                "-c"
                                $"""cd "{dir}" && exec "{aotBin}" run --config eplix.json > "{vcLog}" 2>&1"""
                            ]
                        )
                    )

                do! Task.Delay(TimeSpan.FromSeconds 24.0)
                vc.Kill true
                vc.WaitForExit()

                for r in runners do
                    r.Stop()

                let lines = File.ReadAllLines vcLog
                let slots = lines |> Array.filter (fun l -> l.Contains " duties, ")
                let good = slots |> Array.filter (fun l -> l.Contains " 0 refused, 0 failed, submitted True")

                let text =
                    String.Join(
                        "
",
                        lines |> Array.truncate 60
                    )

                Expect.isTrue
                    (lines |> Array.exists (fun l -> l.Contains "tee: 3 of 3 runners answered, 3 keys"))
                    $"three runners, three keys:
{text}"

                Expect.isGreaterThan
                    good.Length
                    3
                    $"slots signed and submitted:
{text}"

                Expect.equal
                    good.Length
                    slots.Length
                    $"no slot with a refusal or failure:
{text}"

                File.WriteAllLines(
                    Path.Combine(c.Dir, "smoke.txt"),
                    Array.append [| $"slots: {slots.Length}, all signed: {good.Length}" |] slots
                )
            finally
                bn.Kill true
        })

[<Tests>]
let tests =
    if String.IsNullOrEmpty runnerBin then
        testList "tee-integration" [ ptest "set EPLIX_TEE_RUNNER to a runner-dev-debugimport binary" { () } ]
    else
        testList
            "tee-real"
            [
                integration
                (if String.IsNullOrEmpty aotBin then
                     testList "tee-aot-smoke" [ ptest "set EPLIX_AOT_BIN to the published eplix binary" { () } ]
                 else
                     testSequenced (testList "tee-aot-smoke" [ smoke ]))
            ]
