/// The Web3Signer module with fake signers: request bodies, the answer mapping, whole keys and
/// share groups, and what the pipeline does with a 412.
module Eplix.Tests.Web3SignerTests

open System
open System.Collections.Generic
open System.Numerics
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Web3Signer
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Microsoft.Extensions.Time.Testing

let spec = lazy ((Eplix.Tests.SchedulerTests.harness ()).Spec)
let private gvr = Eplix.Tests.FakeBeaconNode.gvr

let req (key: PubKey) (duty: Duty) =
    Duty.request spec.Value gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

let private header =
    {
        Slot = 12UL
        ProposerIndex = 3UL
        ParentRoot = root 1
        StateRoot = root 2
        BodyRoot = root 3
    }

let allDuties () =
    let p = spec.Value.Preset

    [
        attestation
        Duty.Block header
        Duty.RandaoReveal 2UL
        Duty.AggregationSlot 17UL
        Duty.AggregateAndProof(
            17UL,
            {
                Schema = Schemas.aggregateAndProof p
                Value = Ssz.zero (Schemas.aggregateAndProof p)
            }
        )
        Duty.SyncCommitteeMessage(17UL, root 9)
        Duty.SyncSelectionProof { Slot = 17UL; SubcommitteeIndex = 1UL }
        Duty.ContributionAndProof(
            17UL,
            {
                Schema = Schemas.contributionAndProof p
                Value = Ssz.zero (Schemas.contributionAndProof p)
            }
        )
        Duty.VoluntaryExit { Epoch = 2UL; ValidatorIndex = 5UL }
    ]

/// A signer that holds secrets by public key and signs whatever root it is asked for. It
/// decodes each body first, so a body Web3Signer could not read fails the test. `answer`
/// overrides the result for a request.
type FakeSigner(url: string, secrets: (PubKey * byte[]) list) =
    let keys = Dictionary<PubKey, byte[]>(dict secrets)
    member val Up = true with get, set
    /// The keys it lists and signs with, by key.
    member _.Keys = keys
    member val Override: (SignRequest -> Answer option) = (fun _ -> None) with get, set
    member val Bodies = Collections.Concurrent.ConcurrentQueue<string>()
    /// Not attested: requests fail at once, as HttpSigner does them, and never reach it.
    member val NotAttestedReason: string voption = ValueNone with get, set

    member this.Api: SignerApi =
        {
            Url = url
            PublicKeys =
                fun _ ->
                    Task.FromResult(if this.Up then Ok(List.ofSeq keys.Keys) else Error(Transport "connection refused"))
            Upcheck = fun _ -> Task.FromResult this.Up
            Sign =
                fun identifier r _ ->
                    match this.NotAttestedReason with
                    | ValueSome why -> Task.FromResult(Answer.Failure(Transport why))
                    | ValueNone ->
                        let body = Text.Encoding.UTF8.GetString(Body.encode spec.Value r)
                        use _ = JsonDocument.Parse body
                        this.Bodies.Enqueue body

                        Task.FromResult(
                            if not this.Up then
                                Answer.Failure(Transport "connection refused")
                            else
                                match this.Override r with
                                | Some a -> a
                                | None ->
                                    match keys.TryGetValue identifier with
                                    | true, s -> Answer.Signature(sign s r.SigningRoot)
                                    | _ -> Answer.Status(404, "Public Key not found")
                        )
            NotAttested = fun () -> this.NotAttestedReason
            Dispose = ignore
        }

let private endpoint (url: string) =
    {
        Url = Uri url
        Tls = TlsSettings.None
        Attestation = ValueNone
    }

let private settings signers groups : Web3SignerModule.Settings =
    {
        Signers = signers
        Groups = groups
        Timeout = TimeSpan.FromSeconds 2.0
        MaxConnections = 8
        RefreshInterval = TimeSpan.Zero
        ReloadInterval = TimeSpan.Zero
    }

let private property (body: string) (path: string list) =
    use d = JsonDocument.Parse body
    let mutable e = d.RootElement

    for p in path do
        e <- e.GetProperty p

    e.ToString()

let private section (json: string) : ConfigSection =
    {
        Element = ValueSome((JsonDocument.Parse json).RootElement.Clone())
        BaseDir = tempDir ()
        Mainnet = false
    }

/// A plain HTTP/1.1 signer for the keepalive test: answers /upcheck and the key list and logs
/// each request with the number of its connection. CloseIdle closes the open connections, as
/// Web3Signer does with a connection idle for 30 s.
type private ClosingSigner() =
    let listener = new Net.Sockets.TcpListener(Net.IPAddress.Loopback, 0)
    do listener.Start()
    let cts = new CancellationTokenSource()
    let requests = Collections.Concurrent.ConcurrentQueue<int * string>()
    let open' = Collections.Concurrent.ConcurrentDictionary<int, Net.Sockets.TcpClient>()
    let mutable connections = 0

    let serve (n: int) (client: Net.Sockets.TcpClient) =
        task {
            try
                use client = client
                use stream = client.GetStream()
                let reader = new IO.StreamReader(stream, Text.Encoding.ASCII)
                let mutable line = reader.ReadLine()

                while not (isNull line) do
                    // Headers to the blank line; these requests carry no body.
                    let mutable h = line

                    while not (String.IsNullOrEmpty h) do
                        h <- reader.ReadLine()

                    let path = line.Split(' ')[1]
                    requests.Enqueue((n, path))
                    let body = if path = "/upcheck" then "OK" else "[]"

                    let answer =
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n{body}"

                    let bytes = Text.Encoding.ASCII.GetBytes answer
                    do! stream.WriteAsync(bytes, 0, bytes.Length)
                    line <- reader.ReadLine()
            with _ ->
                ()
        }

    let _loop =
        task {
            try
                while not cts.IsCancellationRequested do
                    let! c = listener.AcceptTcpClientAsync cts.Token
                    let n = Interlocked.Increment &connections
                    open'[n] <- c
                    Task.Run(fun () -> serve n c :> Task) |> ignore
            with _ ->
                ()
        }

    member _.Port = (listener.LocalEndpoint :?> Net.IPEndPoint).Port
    member _.Connections = Volatile.Read &connections
    member _.Requests = List.ofSeq requests

    member _.CloseIdle() =
        for KeyValue(n, c) in List.ofSeq open' do
            // A connection the client closed is already disposed.
            try
                c.Client.Shutdown Net.Sockets.SocketShutdown.Both
            with _ ->
                ()

            c.Dispose()
            open'.TryRemove n |> ignore

    interface IDisposable with
        member this.Dispose() =
            cts.Cancel()
            listener.Stop()
            this.CloseIdle()

/// The fake clock, counting the one-shot timers that have not fired or been disposed. Between
/// checks the client's keepalive loop waits on one such timer.
type private CountedTimers(inner: FakeTimeProvider) =
    inherit TimeProvider()
    let mutable waiting = 0
    member _.Waiting = Volatile.Read &waiting
    member _.Advance(d: TimeSpan) = inner.Advance d
    override _.GetUtcNow() = inner.GetUtcNow()
    override _.GetTimestamp() = inner.GetTimestamp()
    override _.TimestampFrequency = inner.TimestampFrequency
    override _.LocalTimeZone = inner.LocalTimeZone

    override _.CreateTimer(callback, state, dueTime, period) =
        let ended = [| 0 |]

        let finish () =
            if Interlocked.Exchange(&ended[0], 1) = 0 then
                Interlocked.Decrement &waiting |> ignore

        Interlocked.Increment &waiting |> ignore

        let fire (st: obj) =
            if period = Timeout.InfiniteTimeSpan then
                finish ()

            callback.Invoke st

        let t = inner.CreateTimer(TimerCallback fire, state, dueTime, period)

        { new ITimer with
            member _.Change(d, p) = t.Change(d, p)

            member _.Dispose() =
                finish ()
                t.Dispose()
          interface IAsyncDisposable with
              member _.DisposeAsync() =
                  finish ()
                  t.DisposeAsync()
        }

[<Tests>]
let tests =
    testList
        "web3signer"
        [
            test "every duty kind has its remote signing API type and typed body" {
                let key = pk (scalar32 (BigInteger 7))

                let expected =
                    [
                        "ATTESTATION", "attestation"
                        "BLOCK_V2", "beacon_block"
                        "RANDAO_REVEAL", "randao_reveal"
                        "AGGREGATION_SLOT", "aggregation_slot"
                        "AGGREGATE_AND_PROOF_V2", "aggregate_and_proof"
                        "SYNC_COMMITTEE_MESSAGE", "sync_committee_message"
                        "SYNC_COMMITTEE_SELECTION_PROOF", "sync_aggregator_selection_data"
                        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "contribution_and_proof"
                        "VOLUNTARY_EXIT", "voluntary_exit"
                    ]

                for duty, (typ, field) in List.zip (allDuties ()) expected do
                    let r = req key duty
                    let body = Text.Encoding.UTF8.GetString(Body.encode spec.Value r)
                    Expect.equal (property body [ "type" ]) typ $"{duty.Kind} type"
                    Expect.isNotEmpty (property body [ field ]) $"{duty.Kind} body field"
                    Expect.equal (property body [ "signingRoot" ]) r.SigningRoot.Hex "the signing root Eplix computed"

                    Expect.equal
                        (property body [ "fork_info"; "genesis_validators_root" ])
                        gvr.Hex
                        "genesis validators root"
            }

            test "bodies carry the values the signer recomputes the root from" {
                let key = pk (scalar32 (BigInteger 7))
                let a = Text.Encoding.UTF8.GetString(Body.encode spec.Value (req key attestation))
                Expect.equal (property a [ "attestation"; "slot" ]) "9" "slot as a decimal string"
                Expect.equal (property a [ "attestation"; "target"; "epoch" ]) "1" "target epoch"
                Expect.equal (property a [ "fork_info"; "fork"; "current_version" ]) "0x06000001" "Fulu at epoch 1"
                Expect.equal (property a [ "fork_info"; "fork"; "previous_version" ]) "0x05000001" "Electra before it"
                let b = Text.Encoding.UTF8.GetString(Body.encode spec.Value (req key (Duty.Block header)))
                Expect.equal (property b [ "beacon_block"; "version" ]) "FULU" "block version from the slot's fork"
                Expect.equal (property b [ "beacon_block"; "block_header"; "body_root" ]) (root 3).Hex "header"

                let x =
                    Text.Encoding.UTF8.GetString(
                        Body.encode spec.Value (req key (Duty.VoluntaryExit { Epoch = 2UL; ValidatorIndex = 5UL }))
                    )

                Expect.equal
                    (property x [ "fork_info"; "fork"; "current_version" ])
                    "0x03000001"
                    "exits name Capella (EIP-7044)"

                Expect.equal (property x [ "fork_info"; "fork"; "previous_version" ]) "0x03000001" "as both versions"
                let agg = Text.Encoding.UTF8.GetString(Body.encode spec.Value (req key (allDuties ()).[4]))
                Expect.equal (property agg [ "aggregate_and_proof"; "version" ]) "FULU" "aggregate version"
                Expect.equal (property agg [ "aggregate_and_proof"; "data"; "aggregator_index" ]) "0" "aggregate data"
            }

            test "answers parse in both forms" {
                let s = sign (scalar32 (BigInteger 7)) (root 1)
                Expect.equal (Body.signature $"{{\"signature\":\"{s.Hex}\"}}") (ValueSome s) "JSON"
                Expect.equal (Body.signature s.Hex) (ValueSome s) "bare hex"
                Expect.isTrue (Body.signature "nope").IsNone "garbage"

                Expect.equal
                    (Body.errorMessage
                        """{"code":412,"message":"Signing operation failed due to slashing protection rules"}""")
                    "Signing operation failed due to slashing protection rules"
                    "error message"

                match Body.publicKeys $"""["{(pk (scalar32 (BigInteger 7))).Hex}"]""" with
                | Ok [ k ] -> Expect.equal k (pk (scalar32 (BigInteger 7))) "key list"
                | x -> failtestf "key list: %A" x
            }

            test "the refusal mapping: 412 is Slashable for slashable kinds only" {
                let att = attestation
                let randao = Duty.RandaoReveal 1UL
                let out d a = Answer.toOutcome "w3s" d ValueNone a

                Expect.isTrue
                    (match out att (Answer.Status(412, "slashing")) with
                     | Refused(Slashable _) -> true
                     | _ -> false)
                    "attestation 412"

                Expect.isTrue
                    (match out (Duty.Block header) (Answer.Status(412, "slashing")) with
                     | Refused(Slashable _) -> true
                     | _ -> false)
                    "block 412"

                Expect.isTrue
                    (match out randao (Answer.Status(412, "policy")) with
                     | Refused(PolicyDenied _) -> true
                     | _ -> false)
                    "412 elsewhere is policy"

                Expect.equal (out att (Answer.Status(404, "x"))) (Refused UnknownKey) "404"

                Expect.isTrue
                    (match out att (Answer.Status(400, "x")) with
                     | Refused(BadRequest _) -> true
                     | _ -> false)
                    "400"

                Expect.isTrue
                    (match out att (Answer.Status(403, "x")) with
                     | Refused(PolicyDenied _) -> true
                     | _ -> false)
                    "403"

                Expect.isTrue
                    (match out att (Answer.Status(500, "x")) with
                     | Failed(Internal _) -> true
                     | _ -> false)
                    "500 is a failure"

                Expect.isTrue
                    (match out att (Answer.Status(503, "x")) with
                     | Failed(Internal _) -> true
                     | _ -> false)
                    "503 is a failure"

                Expect.equal (out att (Answer.Status(504, "x"))) (Failed SignFailure.Timeout) "504"
                Expect.equal (out att (Answer.Failure SignFailure.Timeout)) (Failed SignFailure.Timeout) "timeout"
                let s = sign (scalar32 (BigInteger 7)) (root 1)

                Expect.equal
                    (Answer.toOutcome "w3s" att (ValueSome 2UL) (Answer.Signature s))
                    (Partial(2UL, s))
                    "a share signature is a partial"
            }

            testT "the pipeline halts a key on a 412 and keeps it on other errors" (fun () ->
                task {
                    let secrets = [ for i in 1..3 -> scalar32 (BigInteger(8000 + i)) ]
                    let keys = secrets |> List.map pk
                    let signer = FakeSigner("http://w3s", List.zip keys secrets)

                    signer.Override <-
                        fun r ->
                            if r.Key = keys[0] then
                                Some(Answer.Status(412, "Signing operation failed due to slashing protection rules"))
                            elif r.Key = keys[1] then
                                Some(Answer.Status(500, "Internal Server Error"))
                            else
                                None

                    let ws =
                        Web3SignerModule.Web3SignerSet(
                            (fun _ -> signer.Api),
                            settings [ endpoint "http://w3s" ] [],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, answered = ws.Discover CancellationToken.None
                    Expect.equal answered 1 "one endpoint"
                    Expect.equal found.Length 3 "three whole keys"

                    use db =
                        match SlashingDb.Open(new FileMarkFile(IO.Path.Combine(tempDir (), "s.db")), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    db.RegisterKeys [ for k in keys -> k, KeyOrigin.StartedEmpty ] |> ignore
                    let registry = KeyRegistry()

                    for k, b in found do
                        registry.Add(k, b) |> ignore
                        registry.SetState(k, KeyState.Active)

                    let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none)
                    let! outs = pipeline.SignBurst([| for k in keys -> req k attestation |], CancellationToken.None)

                    Expect.isTrue
                        (match outs[0] with
                         | Refused(Slashable _) -> true
                         | _ -> false)
                        $"412: {outs[0].Describe}"

                    Expect.isTrue
                        (match (registry.TryGet keys[0]).Value.State with
                         | KeyState.Halted _ -> true
                         | _ -> false)
                        "412 halts the key"

                    Expect.isTrue
                        (match outs[1] with
                         | Failed(Internal _) -> true
                         | _ -> false)
                        $"500: {outs[1].Describe}"

                    Expect.equal
                        (registry.TryGet keys[1]).Value.State
                        KeyState.Active
                        "a failure leaves the key active"

                    Expect.isTrue
                        (verifies keys[2] (req keys[2] attestation) outs[2])
                        $"the third signs: {outs[2].Describe}"
                    // A halted key still signs non-slashable kinds.
                    let r = req keys[0] (Duty.RandaoReveal 1UL)
                    signer.Override <- fun _ -> None
                    let! o = pipeline.Sign(r, CancellationToken.None)
                    Expect.isTrue (verifies keys[0] r o) "RANDAO for a halted key"
                })

            testT "a 404 refuses with UnknownKey and asks for a key list refresh" (fun () ->
                task {
                    let signer = FakeSigner("http://w3s", [])
                    let x = SignerEndpoint(signer.Api, TimeSpan.FromSeconds 1.0, Log.none)
                    let mutable asked = 0
                    x.UnknownKey.Add(fun () -> asked <- asked + 1)
                    let key = pk (scalar32 (BigInteger 99))
                    let! o = (x.WholeKeys "w").Sign (req key attestation) CancellationToken.None
                    Expect.equal o (Refused UnknownKey) "unknown"
                    Expect.equal asked 1 "refresh asked"
                })

            testT "share mode: 2 of 3 endpoints, each with one share, sign every duty kind" (fun () ->
                task {
                    let group = [ for s in 1..4 -> shamir (300 + s) 2 [ 1UL; 2UL; 3UL ] ]

                    let signers =
                        [
                            for i in 0..2 ->
                                FakeSigner(
                                    $"http://w3s-{i + 1}",
                                    [ for _, shares in group -> pk (snd shares[i]), snd shares[i] ]
                                )
                        ]

                    let apis = Map.ofList [ for s in signers -> s.Api.Url, s.Api ]

                    let g: Web3SignerModule.GroupSettings =
                        {
                            Threshold = 2
                            Members = [ for i in 1..3 -> uint64 i, endpoint $"http://w3s-{i}" ]
                            Keys =
                                [
                                    for secret, shares in group ->
                                        {
                                            PubKey = pk secret
                                            Shares = Map.ofList [ for id, s in shares -> id, pk s ]
                                        }
                                ]
                        }

                    let ws =
                        Web3SignerModule.Web3SignerSet(
                            (fun e -> apis[e.Url.GetLeftPart(UriPartial.Authority)]),
                            settings [] [ g ],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, answered = ws.Discover CancellationToken.None
                    Expect.equal answered 3 "three endpoints"

                    Expect.equal
                        (found |> List.map fst |> set)
                        (group |> List.map (fst >> pk) |> set)
                        "the validator keys"

                    for key, backend in found do
                        for duty in allDuties () do
                            let r = req key duty
                            let! o = backend.Sign r CancellationToken.None
                            Expect.isTrue (verifies key r o) $"{duty.Kind}: {o.Describe}"
                    // Each endpoint got its own share key in the URL's place, never the validator key.
                    Expect.isGreaterThan signers[0].Bodies.Count 0 "requests reached endpoint 1"
                    // One endpoint down: the other two sign.
                    signers[2].Up <- false
                    let key, backend = found.Head
                    let r = req key attestation
                    let! o = backend.Sign r CancellationToken.None
                    Expect.isTrue (verifies key r o) $"with one down: {o.Describe}"
                    // A 412 from one member is outvoted; from two it is Slashable.
                    signers[2].Up <- true
                    signers[0].Override <- fun _ -> Some(Answer.Status(412, "slashing"))

                    let! one =
                        backend.Sign
                            (req
                                key
                                (Duty.Attestation
                                    {
                                        Slot = 10UL
                                        Index = 0UL
                                        BeaconBlockRoot = root 1
                                        Source = { Epoch = 0UL; Root = root 4 }
                                        Target = { Epoch = 1UL; Root = root 6 }
                                    }))
                            CancellationToken.None

                    Expect.isTrue
                        (match one with
                         | Signed _ -> true
                         | _ -> false)
                        $"one 412 of three: {one.Describe}"

                    signers[1].Override <- fun _ -> Some(Answer.Status(412, "slashing"))
                    let! two = backend.Sign (req key attestation) CancellationToken.None

                    Expect.isTrue
                        (match two with
                         | Refused(Slashable _) -> true
                         | _ -> false)
                        $"two 412 of three: {two.Describe}"
                })

            testT
                "share mode: a 2 of 3 group with one member not attested signs from the other two, and sends it nothing"
                (fun () ->
                    task {
                        let group = [ for s in 1..2 -> shamir (500 + s) 2 [ 1UL; 2UL; 3UL ] ]

                        let signers =
                            [
                                for i in 0..2 ->
                                    FakeSigner(
                                        $"http://w3s-{i + 1}",
                                        [ for _, shares in group -> pk (snd shares[i]), snd shares[i] ]
                                    )
                            ]

                        let apis = Map.ofList [ for s in signers -> s.Api.Url, s.Api ]

                        let g: Web3SignerModule.GroupSettings =
                            {
                                Threshold = 2
                                Members = [ for i in 1..3 -> uint64 i, endpoint $"http://w3s-{i}" ]
                                Keys =
                                    [
                                        for secret, shares in group ->
                                            {
                                                PubKey = pk secret
                                                Shares = Map.ofList [ for id, s in shares -> id, pk s ]
                                            }
                                    ]
                            }

                        let ws =
                            Web3SignerModule.Web3SignerSet(
                                (fun e -> apis[e.Url.GetLeftPart(UriPartial.Authority)]),
                                settings [] [ g ],
                                TimeProvider.System,
                                Log.none
                            )

                        let! found, _ = ws.Discover CancellationToken.None
                        signers[1].NotAttestedReason <- ValueSome "w3s-2: attestation refused: setup"
                        let before = signers[1].Bodies.Count

                        for key, backend in found do
                            let! h = backend.Health CancellationToken.None

                            Expect.isTrue
                                (match h with
                                 | Degraded _ -> true
                                 | _ -> false)
                                $"the group is degraded, not down: %A{h}"

                            for duty in [ attestation; Duty.RandaoReveal 3UL ] do
                                let r = req key duty
                                let! o = backend.Sign r CancellationToken.None
                                Expect.isTrue (verifies key r o) $"{duty.Kind}: {o.Describe}"

                        Expect.equal signers[1].Bodies.Count before "the member that is not attested got no request"
                        let x = ws.Endpoints |> List.find (fun e -> e.Url = "http://w3s-2")

                        Expect.isTrue
                            (match x.Health with
                             | Down m -> m.Contains "attestation refused"
                             | _ -> false)
                            "the member is down"
                    })

            testT
                "share mode: a validator registration signs through a 2 of 3 group, one message to every member"
                (fun () ->
                    task {
                        let secret, shares = shamir 351 2 [ 1UL; 2UL; 3UL ]

                        let signers =
                            [
                                for i in 0..2 ->
                                    FakeSigner($"http://w3s-{i + 1}", [ pk (snd shares[i]), snd shares[i] ])
                            ]

                        let apis = Map.ofList [ for s in signers -> s.Api.Url, s.Api ]

                        let g: Web3SignerModule.GroupSettings =
                            {
                                Threshold = 2
                                Members = [ for i in 1..3 -> uint64 i, endpoint $"http://w3s-{i}" ]
                                Keys =
                                    [
                                        {
                                            PubKey = pk secret
                                            Shares = Map.ofList [ for id, s in shares -> id, pk s ]
                                        }
                                    ]
                            }

                        let ws =
                            Web3SignerModule.Web3SignerSet(
                                (fun e -> apis[e.Url.GetLeftPart(UriPartial.Authority)]),
                                settings [] [ g ],
                                TimeProvider.System,
                                Log.none
                            )

                        let! found, _ = ws.Discover CancellationToken.None
                        let key, backend = found.Head

                        Expect.isTrue
                            (backend.Capabilities.Duties.Contains DutyKind.ValidatorRegistration)
                            "the group signs registrations"

                        let reg =
                            Duty.ValidatorRegistration
                                {
                                    FeeRecipient = Array.create 20 0xAAuy
                                    GasLimit = 60_000_000UL
                                    Timestamp = 1_700_000_000UL
                                    PubKey = key
                                }

                        let r = req key reg
                        let! o = backend.Sign r CancellationToken.None
                        Expect.isTrue (verifies key r o) $"combined: {o.Describe}"

                        let bodies =
                            [
                                for s in signers do
                                    yield! s.Bodies
                            ]

                        Expect.isGreaterThanOrEqual bodies.Length 2 "at least two members asked"

                        let messages =
                            bodies |> List.map (fun b -> property b [ "validator_registration" ]) |> List.distinct

                        Expect.equal
                            messages.Length
                            1
                            "every member got the same registration: one fee recipient, gas limit and timestamp"

                        Expect.stringContains messages.Head key.Hex "the validator key in the message, not a share key"

                        for b in bodies do
                            Expect.equal (property b [ "type" ]) "VALIDATOR_REGISTRATION" "type"
                            Expect.isFalse (b.Contains "fork_info") "no fork_info"
                    })

            testT "share mode lists a key only when m endpoints list its share" (fun () ->
                task {
                    let secret, shares = shamir 401 2 [ 1UL; 2UL; 3UL ]

                    let signers =
                        [
                            for i in 0..2 ->
                                FakeSigner(
                                    $"http://w3s-{i + 1}",
                                    (if i = 0 then [ pk (snd shares[i]), snd shares[i] ] else [])
                                )
                        ]

                    let apis = Map.ofList [ for s in signers -> s.Api.Url, s.Api ]

                    let g: Web3SignerModule.GroupSettings =
                        {
                            Threshold = 2
                            Members = [ for i in 1..3 -> uint64 i, endpoint $"http://w3s-{i}" ]
                            Keys =
                                [
                                    {
                                        PubKey = pk secret
                                        Shares = Map.ofList [ for id, s in shares -> id, pk s ]
                                    }
                                ]
                        }

                    let ws =
                        Web3SignerModule.Web3SignerSet(
                            (fun e -> apis[e.Url.GetLeftPart(UriPartial.Authority)]),
                            settings [] [ g ],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, _ = ws.Discover CancellationToken.None
                    Expect.isEmpty found "one share listed of the two needed"
                })

            test "config: share keys that do not combine to the key fail the start" {
                let secret, shares = shamir 501 2 [ 1UL; 2UL; 3UL ]

                let shareJson (swap: bool) =
                    String.Join(
                        ",",
                        [
                            for id, s in shares ->
                                let s' = if swap && id = 2UL then snd shares[2] else s
                                $"\"{id}\": \"{(pk s').Hex}\""
                        ]
                    )

                let json swap =
                    $"""{{ "groups": [ {{ "threshold": 2,
                         "members": [ {{ "index": 1, "url": "http://a:9000" }}, {{ "index": 2, "url": "http://b:9000" }}, {{ "index": 3, "url": "http://c:9000" }} ],
                         "keys": [ {{ "pubkey": "{(pk secret).Hex}", "shares": {{ {shareJson swap} }} }} ] }} ] }}"""

                match Web3SignerModule.parseSettings (section (json false)) with
                | Ok s -> Expect.equal s.Groups.Head.Keys.Length 1 "one key"
                | Error e -> failtestf "valid config refused: %A" e

                match Web3SignerModule.parseSettings (section (json true)) with
                | Error [ e ] ->
                    Expect.stringContains e (pk secret).Hex "the check names the key"
                    Expect.stringContains e "member 2" "and the member whose share is off"
                | x -> failtestf "expected an error, got %A" x
            }

            test "config: a share key beyond the first m from another split of the key fails the start" {
                let secret, shares = shamir 502 2 [ 1UL; 2UL ]
                let other = resplit 503 secret 2 [ 3UL ]
                let all = shares @ other

                let json =
                    let shareJson = String.Join(",", [ for id, s in all -> $"\"{id}\": \"{(pk s).Hex}\"" ])

                    $"""{{ "groups": [ {{ "threshold": 2,
                         "members": [ {{ "index": 1, "url": "http://a:9000" }}, {{ "index": 2, "url": "http://b:9000" }}, {{ "index": 3, "url": "http://c:9000" }} ],
                         "keys": [ {{ "pubkey": "{(pk secret).Hex}", "shares": {{ {shareJson} }} }} ] }} ] }}"""

                match Web3SignerModule.parseSettings (section json) with
                | Error [ e ] -> Expect.stringContains e "member 3" "names the member"
                | x -> failtestf "expected an error, got %A" x
            }

            test "config: a group needs more than half its members to sign" {
                let members n =
                    String.Join(", ", [ for i in 1..n -> $"{{ \"index\": {i}, \"url\": \"http://s{i}:9000\" }}" ])

                for m, n in [ 2, 4; 1, 2; 3, 6 ] do
                    match
                        Web3SignerModule.parseSettings (
                            section $"""{{ "groups": [ {{ "threshold": {m}, "members": [ {members n} ] }} ] }}"""
                        )
                    with
                    | Error [ e ] -> Expect.stringContains e "more than half" $"{m} of {n}"
                    | x -> failtestf "%d of %d: expected an error, got %A" m n x

                for m, n in [ 1, 1; 2, 2; 2, 3; 3, 4; 3, 5 ] do
                    Expect.isOk
                        (Web3SignerModule.parseSettings (
                            section $"""{{ "groups": [ {{ "threshold": {m}, "members": [ {members n} ] }} ] }}"""
                        ))
                        $"{m} of {n}"
            }

            test "config: strict fields and URLs" {
                let bad =
                    [
                        """{ "signers": [ { "url": "ftp://x" } ] }"""
                        """{ "signers": [ { "url": "http://x:9000", "ca_cert": "ca.pem" } ] }"""
                        """{ "signers": [ { "url": "https://x:9000", "client_cert": "c.pem" } ] }"""
                        """{ "signers": [ { "url": "https://x:9000", "color": "red" } ] }"""
                        """{ "signers": [], "timeout_ms": 0 }"""
                        """{ }"""
                        """{ "groups": [ { "threshold": 3, "members": [ { "index": 1, "url": "http://a" }, { "index": 2, "url": "http://b" } ] } ] }"""
                        """{ "groups": [ { "threshold": 1, "members": [ { "index": 1, "url": "http://a" }, { "index": 1, "url": "http://b" } ] } ] }"""
                    ]

                for json in bad do
                    Expect.isError (Web3SignerModule.parseSettings (section json)) json

                match Web3SignerModule.parseSettings (section """{ "signers": [ { "url": "https://x:9000" } ] }""") with
                | Ok s ->
                    Expect.equal s.Timeout (TimeSpan.FromSeconds 2.0) "default timeout"
                    Expect.equal s.RefreshInterval (TimeSpan.FromSeconds 384.0) "refresh every mainnet epoch"
                | Error e -> failtestf "%A" e
            }

            testT
                "an idle connection is kept with /upcheck; one the server closed is replaced without an error"
                (fun () ->
                    task {
                        use server = new ClosingSigner()
                        let time = CountedTimers(FakeTimeProvider(DateTimeOffset.UtcNow))

                        let endpoint =
                            {
                                Url = Uri $"http://127.0.0.1:{server.Port}"
                                Tls = TlsSettings.None
                                Attestation = ValueNone
                            }

                        let api =
                            HttpSigner.create
                                endpoint
                                { HttpSigner.LoadedTls.None with
                                    Time = time
                                }
                                spec.Value
                                4

                        try
                            let duty () =
                                task {
                                    let! r = api.PublicKeys CancellationToken.None
                                    Expect.isOk r "the key list"
                                }

                            let upchecks () =
                                server.Requests |> List.filter (fun (_, p) -> p = "/upcheck") |> List.length
                            // Idle on the client clock, a second at a time, until one keepalive goes out. The
                            // server logs a request before it answers, so then wait until the keepalive has
                            // read the answer and waits on its next timer. Its connection is then back in the
                            // pool, so the next request does not find it busy and dial another.
                            let idle () =
                                task {
                                    let before = upchecks ()
                                    let sw = Diagnostics.Stopwatch.StartNew()

                                    while upchecks () = before && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                                        time.Advance(TimeSpan.FromSeconds 1.0)
                                        do! Task.Delay 20

                                    Expect.equal (upchecks ()) (before + 1) "one keepalive"

                                    while time.Waiting = 0 && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                                        do! Task.Delay 5

                                    Expect.equal time.Waiting 1 "the keepalive ended and waits again"
                                }

                            do! duty ()
                            Expect.equal server.Connections 1 "first connection"
                            do! idle ()

                            Expect.equal
                                (server.Requests |> List.last)
                                (1, "/upcheck")
                                "the keepalive on the open connection"
                            // A request within the last 15 s: no keepalive.
                            do! duty ()
                            time.Advance(TimeSpan.FromSeconds 6.0)
                            do! Task.Delay 300
                            Expect.equal (upchecks ()) 1 "no keepalive while requests go out"
                            // The server closes the idle connection: the next request takes a new one.
                            server.CloseIdle()
                            do! Task.Delay 200
                            do! duty ()

                            Expect.isGreaterThanOrEqual
                                server.Connections
                                2
                                "a new connection after the server closed the old one"

                            Expect.isTrue
                                (server.Requests |> List.skip 3 |> List.forall (fun (c, _) -> c > 1))
                                "nothing more on the closed connection"
                            // The pool may have dialled a spare while the first connection was found closed.
                            let dialled = server.Connections

                            for _ in 1..3 do
                                do! idle ()

                            do! duty ()
                            Expect.equal server.Connections dialled "no new connection under keepalives"
                            let last = server.Requests |> List.rev |> List.take 4 |> List.map fst |> List.distinct
                            Expect.equal last.Length 1 "the keepalives and the last request on one connection"
                        finally
                            api.Dispose()
                    })

            testT "a signer that never answers its key list fails it after the deadline; the others list" (fun () ->
                task {
                    let secret = scalar32 (BigInteger 4242)
                    let quick = FakeSigner("http://w3s-a", [ pk secret, secret ])
                    let silentFake = FakeSigner("http://w3s-b", [])

                    let silent =
                        { silentFake.Api with
                            PublicKeys =
                                fun ct ->
                                    task {
                                        try
                                            do! Task.Delay(-1, ct)
                                        with :? OperationCanceledException ->
                                            ()

                                        return Error SignFailure.Timeout
                                    }
                        }

                    let apis = Map.ofList [ "http://w3s-a", quick.Api; "http://w3s-b", silent ]
                    let time = FakeTimeProvider(DateTimeOffset.UtcNow)

                    let ws =
                        Web3SignerModule.Web3SignerSet(
                            (fun e -> apis[e.Url.GetLeftPart(UriPartial.Authority)]),
                            settings [ endpoint "http://w3s-a"; endpoint "http://w3s-b" ] [],
                            time,
                            Log.none
                        )

                    let discover = ws.Discover CancellationToken.None
                    time.Advance(ListedKeys.ListDeadline - TimeSpan.FromSeconds 1.0)
                    do! Task.Delay 100
                    Expect.isFalse discover.IsCompleted "waits within the deadline"
                    time.Advance(TimeSpan.FromSeconds 1.0)
                    let! found, answered = discover.WaitAsync(TimeSpan.FromSeconds 10.0)
                    Expect.equal answered 1 "the silent signer failed its list"
                    Expect.equal (found |> List.map fst) [ pk secret ] "the key of the other signer"
                })

            testT "an answer body over the cap fails the call" (fun () ->
                task {
                    let listener = new Net.Sockets.TcpListener(Net.IPAddress.Loopback, 0)
                    listener.Start()
                    let port = (listener.LocalEndpoint :?> Net.IPEndPoint).Port
                    // One request, answered with a valid key list (an empty array padded with spaces)
                    // longer than the cap. The connection stays open until the client closes it.
                    let serve =
                        task {
                            use! client = listener.AcceptTcpClientAsync()
                            use stream = client.GetStream()
                            let buf = Array.zeroCreate<byte> 4096
                            let! _ = stream.ReadAsync(buf, 0, buf.Length)

                            try
                                let chunk = Array.create (1024 * 1024) 32uy
                                let chunks = int (HttpSigner.MaxBody / int64 chunk.Length) + 1
                                let length = int64 chunks * int64 chunk.Length + 2L

                                let head =
                                    $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n["

                                do! stream.WriteAsync(ReadOnlyMemory(Text.Encoding.ASCII.GetBytes head))

                                for _ in 1..chunks do
                                    do! stream.WriteAsync(ReadOnlyMemory chunk)

                                do! stream.WriteAsync(ReadOnlyMemory(Text.Encoding.ASCII.GetBytes "]"))
                                let! _ = stream.ReadAsync(buf, 0, buf.Length)
                                ()
                            with _ ->
                                ()
                        }

                    let at =
                        {
                            Url = Uri $"http://127.0.0.1:{port}"
                            Tls = TlsSettings.None
                            Attestation = ValueNone
                        }

                    let api = HttpSigner.create at HttpSigner.LoadedTls.None spec.Value 4

                    try
                        let! r = api.PublicKeys(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds 30.0)

                        Expect.isTrue
                            (match r with
                             | Error(Transport _) -> true
                             | _ -> false)
                            (sprintf "a transport error: %A" r)
                    finally
                        api.Dispose()
                        serve.Wait(TimeSpan.FromSeconds 30.0) |> ignore
                        listener.Stop()
                })

            testT "a 3xx from a signer is an error, and the request does not reach the redirect target" (fun () ->
                task {
                    use server = new RedirectServer()

                    let at =
                        {
                            Url = server.Url
                            Tls = TlsSettings.None
                            Attestation = ValueNone
                        }

                    let api = HttpSigner.create at HttpSigner.LoadedTls.None spec.Value 4

                    try
                        let! r = api.PublicKeys(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds 30.0)

                        Expect.isTrue
                            (match r with
                             | Error(Internal m) -> m.Contains "redirect"
                             | _ -> false)
                            $"%A{r}"
                    finally
                        api.Dispose()

                    Expect.equal server.Reached 0 "nothing reached the target"

                    let att =
                        Duty.Attestation
                            {
                                Slot = 1UL
                                Index = 0UL
                                BeaconBlockRoot = Root.Zero
                                Source = { Epoch = 0UL; Root = Root.Zero }
                                Target = { Epoch = 1UL; Root = Root.Zero }
                            }

                    match Answer.toOutcome "w3s" att ValueNone (Answer.Status(307, "")) with
                    | Failed(Internal m) -> Expect.stringContains m "redirect" "a sign answered with a redirect"
                    | o -> failtestf "%A" o
                })

            test "a signer's error text is cut and cleaned for a log line" {
                let m = Body.errorMessage $"""{{"code":500,"message":"{String('x', 5000)}\nINFO forged"}}"""
                Expect.isTrue (m.Length <= Threshold.MaxReason + 3 && not (m.Contains '\n')) m
                let raw = Body.errorMessage ("<html>\r\n" + String('y', 5000))
                Expect.isTrue (raw.Length <= Threshold.MaxReason + 3 && not (raw.Contains '\n')) raw
            }

            testT
                "a phase0 or altair block is refused as unsupported without a request; BLOCK_V2 then needs the whole block"
                (fun () ->
                    task {
                        let forks =
                            spec.Value.Forks |> Array.take 3 |> Array.mapi (fun i f -> { f with Epoch = uint64 i })

                        Expect.equal
                            [ for f in forks -> f.Name ]
                            [ ForkName.Phase0; ForkName.Altair; ForkName.Bellatrix ]
                            "the first three forks"

                        let early = { spec.Value with Forks = forks }
                        let key = pk (scalar32 (BigInteger 7))

                        let block (epoch: uint64) =
                            req
                                key
                                (Duty.Block
                                    { header with
                                        Slot = early.FirstSlot epoch
                                    })

                        Expect.isFalse (Body.supported early (block 0UL)) "phase0"
                        Expect.isFalse (Body.supported early (block 1UL)) "altair"
                        Expect.isTrue (Body.supported early (block 2UL)) "bellatrix sends the header"
                        Expect.isTrue (Body.supported early (req key attestation)) "other kinds"
                        let listener = new Net.Sockets.TcpListener(Net.IPAddress.Loopback, 0)
                        listener.Start()
                        let port = (listener.LocalEndpoint :?> Net.IPEndPoint).Port

                        let at =
                            {
                                Url = Uri $"http://127.0.0.1:{port}"
                                Tls = TlsSettings.None
                                Attestation = ValueNone
                            }

                        let api = HttpSigner.create at HttpSigner.LoadedTls.None early 4

                        try
                            for epoch in [ 0UL; 1UL ] do
                                let r = block epoch
                                // The listener never answers: a request sent would wait on this token.
                                use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
                                let! a = (api.Sign key r cts.Token).WaitAsync(TimeSpan.FromSeconds 10.0)

                                Expect.isTrue
                                    (match a with
                                     | Answer.Unsupported -> true
                                     | _ -> false)
                                    $"epoch {epoch}: %A{a}"

                                Expect.equal
                                    (Answer.toOutcome "w3s" r.Duty ValueNone a)
                                    (Refused(Unsupported DutyKind.Block))
                                    "an explicit refusal"

                            Expect.isFalse (listener.Pending()) "no connection to the signer"
                        finally
                            api.Dispose()
                            listener.Stop()
                    })

            testT
                "a whole-key signature that does not verify is returned and counted by the background check"
                (fun () ->
                    task {
                        let secret = scalar32 (BigInteger 4343)
                        let key = pk secret
                        let signer = FakeSigner("http://w3s", [ key, secret ])
                        let x = SignerEndpoint(signer.Api, TimeSpan.FromSeconds 1.0, Log.none)
                        let backend = x.WholeKeys "w"
                        let r = req key attestation
                        let! good = backend.Sign r CancellationToken.None
                        Expect.isTrue (verifies key r good) $"a good signature passes: {good.Describe}"
                        // The good check must land first: a pass that lands after the failure clears it.
                        do! settle x.Watch

                        let failsReach n =
                            task {
                                do! settle x.Watch
                                Expect.equal (x.Watch.Fails key) n $"{n} failed checks"
                            }

                        signer.Override <- fun _ -> Some(Answer.Signature(sign secret (root 99)))
                        let! wrongRoot = backend.Sign r CancellationToken.None

                        Expect.isTrue
                            (match wrongRoot with
                             | Signed _ -> true
                             | _ -> false)
                            $"another root, returned: {wrongRoot.Describe}"

                        do! failsReach 1

                        signer.Override <-
                            fun _ -> Some(Answer.Signature(sign (scalar32 (BigInteger 4344)) r.SigningRoot))

                        let! wrongKey = backend.Sign r CancellationToken.None

                        Expect.isTrue
                            (match wrongKey with
                             | Signed _ -> true
                             | _ -> false)
                            $"another key, returned: {wrongKey.Describe}"

                        do! failsReach 2
                    })

            test "mainnet: http signer URLs are refused, https ones pass" {
                let parse mainnet (url: string) =
                    let json = $$"""{ "signers": [ { "url": "{{url}}" } ] }"""

                    Web3SignerModule.parseSettings
                        {
                            Element = ValueSome((JsonDocument.Parse json).RootElement.Clone())
                            BaseDir = tempDir ()
                            Mainnet = mainnet
                        }

                match parse true "http://w3s:9000" with
                | Error [ e ] -> Expect.stringContains e "url must be https on mainnet" "names the rule"
                | x -> failtestf "http on mainnet: %A" x

                Expect.isOk (parse true "https://w3s:9000") "https on mainnet"
                Expect.isOk (parse false "http://w3s:9000") "http on a testnet"

                let groupJson =
                    """{ "groups": [ { "threshold": 1, "members": [ { "index": 1, "url": "http://a:9000" } ] } ] }"""

                let group =
                    Web3SignerModule.parseSettings
                        {
                            Element = ValueSome((JsonDocument.Parse groupJson).RootElement.Clone())
                            BaseDir = tempDir ()
                            Mainnet = true
                        }

                Expect.isError group "an http group member on mainnet"
                Expect.isError (Web3SignerModule.RemoteKeys.parseUrl true "http://w3s:9000") "API: http on mainnet"
                Expect.isOk (Web3SignerModule.RemoteKeys.parseUrl true "https://w3s:9000") "API: https on mainnet"
                Expect.isOk (Web3SignerModule.RemoteKeys.parseUrl false "http://w3s:9000") "API: http on a testnet"
            }
        ]
