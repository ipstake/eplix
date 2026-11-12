/// The Dirk module with fake Dirk instances: wire codec, duty to call mapping, answer to outcome
/// mapping, batching, and account discovery with distributed accounts.
module Eplix.Tests.DirkTests

open System
open System.Collections.Concurrent
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Dirk
open Eplix.Backend.Dirk.Messages
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.SchedulerTests
open Eplix.Tests.SlashingTests
open Eplix.Tests.ThresholdTests

let private signingRootOf (call: DirkCall) =
    match call with
    | DirkCall.Attestation(_, domain, d) -> Signing.computeSigningRoot (Codec.hashAttestationData d) domain
    | DirkCall.Proposal(_, domain, h) -> Signing.computeSigningRoot (Codec.hashBeaconBlockHeader h) domain
    | DirkCall.Generic(_, objectRoot, domain) -> Signing.computeSigningRoot objectRoot domain
    | DirkCall.PayloadAttestation(_, domain, d) ->
        Signing.computeSigningRoot (Codec.hashPayloadAttestationData d) domain
    | DirkCall.PayloadEnvelope(_, domain, e) -> Signing.computeSigningRoot e.HashTreeRoot domain
    | DirkCall.ProposerPreferences(_, domain, p) -> Signing.computeSigningRoot (Codec.hashProposerPreferences p) domain
    | DirkCall.BuilderRequestAuth(_, domain, a) -> Signing.computeSigningRoot (Codec.hashBuilderRequestAuth a) domain

let private idName (id: AccountId) =
    match id with
    | AccountId.Name n -> n
    | AccountId.PublicKey pk -> Hex.encodeArray pk

let private nameOf (call: DirkCall) =
    match call with
    | DirkCall.Attestation(id, _, _)
    | DirkCall.Proposal(id, _, _)
    | DirkCall.Generic(id, _, _)
    | DirkCall.PayloadAttestation(id, _, _)
    | DirkCall.PayloadEnvelope(id, _, _)
    | DirkCall.ProposerPreferences(id, _, _)
    | DirkCall.BuilderRequestAuth(id, _, _) -> idName id

/// A Dirk instance in memory: accounts by name with their (share) secrets. With Typed off it is
/// stock Dirk, which answers the fork's typed Gloas calls UNIMPLEMENTED.
type FakeDirk(address: string, listing: ListAccountsResponse voption, secrets: Map<string, byte[]>) =
    let calls = ConcurrentQueue<DirkCall>()
    let batches = ConcurrentQueue<string list>()
    let unimplemented = ref 0
    member val Answer: DirkCall -> SignResponse voption = (fun _ -> ValueNone) with get, set
    member val Down = false with get, set
    member val Typed = true with get, set
    /// Typed calls answered UNIMPLEMENTED.
    member _.Unimplemented = unimplemented.Value
    /// What ListAccounts answers while the instance is up.
    member val Listing = listing with get, set
    member _.Calls = List.ofSeq calls
    member _.Batches = List.ofSeq batches

    member this.SignOne(call: DirkCall) : SignResponse =
        calls.Enqueue call

        match this.Answer call with
        | ValueSome r -> r
        | ValueNone ->
            match secrets.TryFind(nameOf call) with
            | Some s ->
                {
                    State = ResponseState.Succeeded
                    Signature = (sign s (signingRootOf call)).Bytes
                }
            | None ->
                {
                    State = ResponseState.Failed
                    Signature = [||]
                }

    member this.Api: DirkApi =
        let down () = Error(CallError.Failure(Transport $"{address}: connection refused"))

        {
            Address = address
            ListAccounts =
                fun _ _ ->
                    Task.FromResult(
                        match this.Listing with
                        | ValueSome l when not this.Down -> Ok l
                        | _ -> down ()
                    )
            Sign =
                fun call _ ->
                    Task.FromResult(
                        if this.Down then
                            down ()
                        elif call.IsTypedGloas && not this.Typed then
                            Interlocked.Increment(&unimplemented.contents) |> ignore
                            Error(CallError.Unimplemented "unknown method for service v1.Signer")
                        else
                            Ok(this.SignOne call)
                    )
            SignAttestations =
                fun items _ ->
                    task {
                        if this.Down then
                            return down ()
                        else
                            batches.Enqueue [ for id, _, _ in items -> idName id ]

                            return
                                Ok
                                    [
                                        for id, domain, d in items -> this.SignOne(DirkCall.Attestation(id, domain, d))
                                    ]
                    }
            Dispose = ignore
        }

let private attestationAt (target: Epoch) (n: int) =
    Duty.Attestation
        {
            Slot = target * 8UL
            Index = 0UL
            BeaconBlockRoot = root n
            Source = { Epoch = target - 1UL; Root = root 4 }
            Target = { Epoch = target; Root = root 5 }
        }

let private header =
    {
        Slot = 17UL
        ProposerIndex = 3UL
        ParentRoot = root 1
        StateRoot = root 2
        BodyRoot = root 3
    }

let private verifyWith (key: PubKey) (req: SignRequest) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan key.Bytes) (ReadOnlySpan req.SigningRoot.Bytes) (ReadOnlySpan s.Bytes)

let private wholeSecret = scalar32 (Numerics.BigInteger 987654321)
let private wholeKey = pk wholeSecret

let private soloListing =
    {
        State = ResponseState.Succeeded
        Accounts =
            [
                {
                    Name = "Solo/A"
                    PublicKey = wholeKey.Bytes
                }
            ]
        DistributedAccounts = []
    }

let private endpointWith (fake: FakeDirk) (batch: bool) =
    let e = DirkEndpoint(fake.Api, batch, TimeSpan.FromSeconds 5.0, Log.none)
    e.SetAccount(wholeKey, { Name = "Solo/A"; Share = ValueNone }) |> ignore
    e

/// Encodes a ListAccountsResponse the way Dirk does, for the decoder test.
let private encodeListing (l: ListAccountsResponse) =
    Protobuf.encode (fun w ->
        w.UInt64(
            1,
            (match l.State with
             | ResponseState.Succeeded -> 1UL
             | ResponseState.Denied -> 2UL
             | ResponseState.Failed -> 3UL
             | _ -> 0UL)
        )

        for a in l.Accounts do
            w.Message(
                2,
                Protobuf.encode (fun x ->
                    x.String(1, a.Name)
                    x.Bytes(2, ReadOnlySpan a.PublicKey))
            )

        for d in l.DistributedAccounts do
            w.Message(
                3,
                Protobuf.encode (fun x ->
                    x.String(1, d.Name)
                    x.Bytes(2, ReadOnlySpan d.PublicKey)

                    for p in d.Participants do
                        x.Message(
                            3,
                            Protobuf.encode (fun y ->
                                y.UInt64(1, p.Id)
                                y.String(2, p.Name)
                                y.UInt32(3, p.Port))
                        )

                    x.UInt32(4, d.SigningThreshold)
                    x.Bytes(5, ReadOnlySpan(Array.create 16 7uy))
                    x.Bytes(6, ReadOnlySpan d.CompositePublicKey))
            ))

/// Three fake Dirk instances holding a 2 of 3 distributed account "Dist/V1", plus a plain
/// account on the first. Endpoint i is "dirk<i>:<i>".
let private cluster () =
    let secret, shares = shamir 21 2 [ 1UL; 2UL; 3UL ]
    let key = pk secret

    let participants =
        [
            for i in 1UL .. 3UL ->
                {
                    Id = i
                    Name = $"dirk{i}"
                    Port = uint32 i
                }
        ]

    let fakes =
        [
            for id, share in shares ->
                let listing =
                    {
                        State = ResponseState.Succeeded
                        Accounts = if id = 1UL then soloListing.Accounts else []
                        DistributedAccounts =
                            [
                                {
                                    Name = "Dist/V1"
                                    PublicKey = (pk share).Bytes
                                    Participants = participants
                                    SigningThreshold = 2u
                                    CompositePublicKey = key.Bytes
                                }
                            ]
                    }

                let secrets = Map [ "Dist/V1", share; "Solo/A", wholeSecret ]
                $"dirk{id}:{id}", FakeDirk($"dirk{id}:{id}", ValueSome listing, secrets)
        ]
        |> Map.ofList

    key, fakes

/// Dirk instances "dirk<id>:<id>" that each hold one of `shares` of `secret` as the distributed
/// account "Dist/V1" at threshold `m`; the ids in `plain` also hold the whole key as "Solo/K".
let private distributed (secret: byte[]) (shares: (uint64 * byte[]) list) (m: int) (plain: uint64 list) =
    let key = pk secret

    let participants =
        [
            for id, _ in shares ->
                {
                    Id = id
                    Name = $"dirk{id}"
                    Port = uint32 id
                }
        ]

    let fakes =
        [
            for id, share in shares ->
                let listing =
                    {
                        State = ResponseState.Succeeded
                        Accounts =
                            if List.contains id plain then
                                [
                                    {
                                        Name = "Solo/K"
                                        PublicKey = key.Bytes
                                    }
                                ]
                            else
                                []
                        DistributedAccounts =
                            [
                                {
                                    Name = "Dist/V1"
                                    PublicKey = (pk share).Bytes
                                    Participants = participants
                                    SigningThreshold = uint32 m
                                    CompositePublicKey = key.Bytes
                                }
                            ]
                    }

                $"dirk{id}:{id}",
                FakeDirk($"dirk{id}:{id}", ValueSome listing, Map [ "Dist/V1", share; "Solo/K", secret ])
        ]
        |> Map.ofList

    let addresses = [ for id, _ in shares -> $"dirk{id}:{id}" ]

    let settings: DirkModule.Settings =
        {
            Endpoints = addresses
            Accounts = [ "Dist"; "Solo" ]
            Tls =
                {
                    CaCert = ""
                    ClientCert = ""
                    ClientKey = ""
                }
            Timeout = TimeSpan.FromSeconds 2.0
            BatchAttestations = true
            RefreshInterval = TimeSpan.Zero
            GloasCalls = GloasCalls.Auto
            ReloadInterval = TimeSpan.Zero
        }

    DirkModule.DirkSet((fun a -> fakes[a].Api), settings, TimeProvider.System, Log.none), key

let private settings (endpoints: string list) : DirkModule.Settings =
    {
        Endpoints = endpoints
        Accounts = [ "Dist"; "Solo" ]
        Tls =
            {
                CaCert = ""
                ClientCert = ""
                ClientKey = ""
            }
        Timeout = TimeSpan.FromSeconds 2.0
        BatchAttestations = true
        RefreshInterval = TimeSpan.Zero
        GloasCalls = GloasCalls.Auto
        ReloadInterval = TimeSpan.Zero
    }

let private testSpec = lazy ((harness ()).Spec)

/// A Dirk build with typed Gloas calls denies a generic Sign in the Gloas domains from a client its config does
/// not name (rules/standard/repeat.go there): such a client must use the typed calls.
let private forkRules (call: DirkCall) =
    let spec = testSpec.Value

    let gloas =
        [
            spec.DomainPtcAttester
            spec.DomainBeaconBuilder
            spec.DomainProposerPreferences
            spec.DomainBuilderRequestAuth
        ]

    match call with
    | DirkCall.Generic(_, _, domain) when gloas |> List.exists (fun t -> domain.Bytes[0..3] = t.Bytes) ->
        ValueSome
            {
                State = ResponseState.Denied
                Signature = [||]
            }
    | _ -> ValueNone

let private gloasDuties =
    let envelope = Schemas.Gloas.executionPayloadEnvelope Preset.Minimal

    [
        Duty.PayloadAttestation
            {
                BeaconBlockRoot = root 7
                Slot = 41UL
                PayloadPresent = true
                BlobDataAvailable = false
            }
        Duty.PayloadEnvelope(
            41UL,
            {
                Schema = envelope
                Value = Ssz.zero envelope
            }
        )
        Duty.ProposerPreferences
            {
                DependentRoot = root 3
                ProposalSlot = 42UL
                ValidatorIndex = 1UL
                FeeRecipient = Array.create 20 0xaauy
                TargetGasLimit = 60_000_000UL
            }
        Duty.BuilderRequestAuth
            {
                AuthData = Text.Encoding.UTF8.GetBytes "builder.example.org"
                AuthSlot = 42UL
            }
    ]

/// A config section from JSON, for the settings parser.
let private dirkSection (json: string) : ConfigSection =
    {
        Element = ValueSome(Text.Json.JsonDocument.Parse(json).RootElement)
        BaseDir = "/"
        Mainnet = false
    }

let private ptcVote =
    Duty.PayloadAttestation
        {
            BeaconBlockRoot = root 7
            Slot = 41UL
            PayloadPresent = true
            BlobDataAvailable = false
        }

/// A value of the type with every field set: lists hold a few items, integers are not zero.
let rec private sample (rnd: Random) (t: Ssz.SszType) : Ssz.SszValue =
    let bytes n =
        let b = Array.zeroCreate n
        rnd.NextBytes b
        b

    match t with
    | Ssz.Uint n -> Ssz.U(uint64 (rnd.Next(1, (if n = 1 then 255 else Int32.MaxValue))))
    | Ssz.Uint256 -> Ssz.Bytes(bytes 32)
    | Ssz.Boolean -> Ssz.Bool true
    | Ssz.ByteVector n -> Ssz.Bytes(bytes n)
    | Ssz.ByteList n -> Ssz.Bytes(bytes (min n 7))
    | Ssz.ProgressiveByteList -> Ssz.Bytes(bytes 45)
    | Ssz.Bitvector n -> Ssz.Bits(Array.init n (fun i -> i % 3 = 0))
    | Ssz.Bitlist n -> Ssz.Bits(Array.init (min n 5) (fun i -> i % 2 = 0))
    | Ssz.ProgressiveBitlist -> Ssz.Bits [| true; false; true |]
    | Ssz.Vector(e, n) -> Ssz.Items(Array.init n (fun _ -> sample rnd e))
    | Ssz.List(e, n) -> Ssz.Items(Array.init (min n 2) (fun _ -> sample rnd e))
    | Ssz.ProgressiveList e -> Ssz.Items(Array.init 3 (fun _ -> sample rnd e))
    | Ssz.Container fs
    | Ssz.ProgressiveContainer fs -> Ssz.Fields(fs |> Array.map (fun (_, ft) -> sample rnd ft))

[<Tests>]
let tests =
    testList
        "dirk"
        [
            test "the gRPC handler follows no redirect" {
                use h = GrpcDirk.handlerFor (TimeSpan.FromMinutes 1.0)
                Expect.isFalse h.AllowAutoRedirect "redirects off"
            }

            test "protobuf varints and fields" {
                let b =
                    Protobuf.encode (fun w ->
                        w.UInt64(1, 300UL)
                        w.Bytes(2, ReadOnlySpan [| 1uy; 2uy |])
                        w.UInt64(3, 0UL))

                Expect.equal
                    b
                    [| 0x08uy; 0xACuy; 0x02uy; 0x12uy; 0x02uy; 1uy; 2uy |]
                    "300 is AC 02; a zero field is left out"

                let f = Protobuf.fields (ReadOnlyMemory b)
                Expect.equal (f |> List.map (fun x -> x.Number)) [ 1; 2 ] "field numbers"
                Expect.equal (Protobuf.asVarint f[0]) 300UL "varint back"

                Expect.throws
                    (fun () -> Protobuf.fields (ReadOnlyMemory [| 0x12uy; 0x05uy; 1uy |]) |> ignore)
                    "length past the end"
            }

            test "a SignBeaconAttestationRequest has the field numbers of eth2-signer-api v1" {
                let d =
                    {
                        Slot = 5UL
                        Index = 1UL
                        BeaconBlockRoot = root 3
                        Source = { Epoch = 0UL; Root = root 4 }
                        Target = { Epoch = 1UL; Root = root 5 }
                    }

                let domain = Domain.Of(Array.create 32 9uy)
                let b = signBeaconAttestationRequest (AccountId.Name "W/A") domain d
                let f = Protobuf.fields (ReadOnlyMemory b)
                Expect.equal (f |> List.map (fun x -> x.Number)) [ 2; 3; 4 ] "account, domain, data"
                Expect.equal (Protobuf.asString f[0]) "W/A" "account name"
                let data = Protobuf.fields f[2].Bytes

                Expect.equal
                    (data |> List.map (fun x -> x.Number))
                    [ 1; 2; 3; 4; 5 ]
                    "slot, committee index, root, source, target"

                let target = Protobuf.fields data[4].Bytes
                Expect.equal (Protobuf.asVarint target[0]) 1UL "target epoch"
                Expect.equal (Protobuf.asBytes target[1]) (root 5).Bytes "target root"
                // A checkpoint at epoch 0 still carries its root.
                let source = Protobuf.fields data[3].Bytes
                Expect.equal (source |> List.map (fun x -> x.Number)) [ 2 ] "epoch 0 is left out, the root is not"
            }

            test "ListAccountsResponse decodes plain and distributed accounts" {
                let key, fakes = cluster ()

                let listing =
                    {
                        State = ResponseState.Succeeded
                        Accounts = soloListing.Accounts
                        DistributedAccounts =
                            [
                                {
                                    Name = "Dist/V1"
                                    PublicKey = (pubkeyOf 1).Bytes
                                    Participants =
                                        [
                                            {
                                                Id = 1UL
                                                Name = "dirk1"
                                                Port = 19591u
                                            }
                                            {
                                                Id = 2UL
                                                Name = "dirk2"
                                                Port = 19592u
                                            }
                                        ]
                                    SigningThreshold = 2u
                                    CompositePublicKey = key.Bytes
                                }
                            ]
                    }

                ignore fakes
                let back = decodeListAccountsResponse (ReadOnlyMemory(encodeListing listing))
                Expect.equal back listing "round trip"
            }

            testT "duties map to Dirk's typed calls and the signatures verify" (fun () ->
                task {
                    let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                    let e = endpointWith fake false
                    let b = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)

                    for duty in
                        [
                            attestationAt 2UL 1
                            Duty.Block header
                            Duty.RandaoReveal 4UL
                            Duty.SyncCommitteeMessage(9UL, root 8)
                        ] do
                        let req = request wholeKey duty

                        match! b.Sign req CancellationToken.None with
                        | Signed s -> Expect.isTrue (verifyWith wholeKey req s) $"{duty.Kind} verifies"
                        | o -> failtestf "%A: %s" duty.Kind o.Describe

                    match fake.Calls with
                    | [ DirkCall.Attestation _
                        DirkCall.Proposal(_, _, h)
                        DirkCall.Generic(_, randao, _)
                        DirkCall.Generic(_, syncRoot, _) ] ->
                        Expect.equal h header "the block header goes as it is"
                        Expect.equal randao (Codec.hashEpoch 4UL) "RANDAO: hash_tree_root(epoch)"
                        Expect.equal syncRoot (root 8) "sync message: the block root"
                    | calls -> failtestf "unexpected calls %A" calls
                })

            testT "Dirk's answers map to typed refusals" (fun () ->
                task {
                    let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                    let e = endpointWith fake false

                    let denied =
                        fun _ ->
                            ValueSome
                                {
                                    State = ResponseState.Denied
                                    Signature = [||]
                                }

                    fake.Answer <- denied
                    let! a = e.Sign (request wholeKey (attestationAt 2UL 1)) CancellationToken.None

                    let isDenied o =
                        match o with
                        | Refused(Refusal.Denied(_, t)) ->
                            t =
                                {
                                    Signed = 0
                                    Denied = 1
                                    Failed = 0
                                    Errored = 0
                                }
                        | _ -> false

                    Expect.isTrue (isDenied a) $"denied attestation: {a.Describe}"
                    let! p = e.Sign (request wholeKey (Duty.Block header)) CancellationToken.None
                    Expect.isTrue (isDenied p) $"denied proposal: {p.Describe}"
                    let! r = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None
                    Expect.isTrue (isDenied r) $"denied RANDAO: {r.Describe}"

                    fake.Answer <-
                        fun _ ->
                            ValueSome
                                {
                                    State = ResponseState.Failed
                                    Signature = [||]
                                }

                    let! f = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match f with
                         | Failed(Internal _) -> true
                         | _ -> false)
                        $"failed: {f.Describe}"

                    fake.Answer <- fun _ -> ValueNone
                    fake.Down <- true
                    let! d = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match d with
                         | Failed(Transport _) -> true
                         | _ -> false)
                        $"down: {d.Describe}"

                    Expect.isTrue
                        (match e.Health with
                         | Down _ -> true
                         | _ -> false)
                        "health down after a transport error"

                    let! u = e.Sign (request (pubkeyOf 3) (Duty.RandaoReveal 1UL)) CancellationToken.None
                    Expect.equal u (Refused UnknownKey) "a key without an account"

                    let rejecting =
                        { fake.Api with
                            Sign = fun _ _ -> Task.FromResult(Error(CallError.Rejected "no permission"))
                        }

                    let e2 = DirkEndpoint(rejecting, false, TimeSpan.FromSeconds 1.0, Log.none)
                    e2.SetAccount(wholeKey, { Name = "Solo/A"; Share = ValueNone }) |> ignore
                    let! j = e2.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match j with
                         | Refused(PolicyDenied _) -> true
                         | _ -> false)
                        $"rejected certificate: {j.Describe}"
                })

            testT "a timeout does not show a Dirk as up; only an answer clears it" (fun () ->
                task {
                    let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                    let timingOut = ref true
                    let answer: CallError voption ref = ref ValueNone

                    let api =
                        { fake.Api with
                            Sign =
                                fun call ct ->
                                    match answer.Value with
                                    | ValueSome err -> Task.FromResult(Error err)
                                    | ValueNone ->
                                        if timingOut.Value then
                                            Task.FromResult(Error(CallError.Failure SignFailure.Timeout))
                                        else
                                            fake.Api.Sign call ct
                        }

                    let e = DirkEndpoint(api, false, TimeSpan.FromSeconds 1.0, Log.none)
                    e.SetAccount(wholeKey, { Name = "Solo/A"; Share = ValueNone }) |> ignore
                    Expect.equal e.Health Up "up before any call"
                    let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match e.Health with
                         | Degraded _ -> true
                         | _ -> false)
                        $"degraded after a timeout: {e.Health}"
                    // A transport error, then a timeout: still down.
                    fake.Down <- true
                    timingOut.Value <- false
                    let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None
                    timingOut.Value <- true
                    let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match e.Health with
                         | Down _ -> true
                         | _ -> false)
                        $"down: a timeout does not clear a transport error: {e.Health}"

                    fake.Down <- false
                    timingOut.Value <- false
                    let! s = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                    Expect.isTrue
                        (match s with
                         | Signed _ -> true
                         | _ -> false)
                        $"signed: {s.Describe}"

                    Expect.equal e.Health Up "an answer clears it"
                    // A refusal of the certificate, UNIMPLEMENTED or an undecodable reply is an answer
                    // too: each clears a transport error and a timeout.
                    for err in
                        [
                            CallError.Rejected "no permission"
                            CallError.Unimplemented "no such method"
                            CallError.Failure(Internal "undecodable answer from Dirk")
                        ] do
                        fake.Down <- true
                        let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                        Expect.isTrue
                            (match e.Health with
                             | Down _ -> true
                             | _ -> false)
                            $"down after a transport error: {e.Health}"

                        fake.Down <- false
                        answer.Value <- ValueSome err
                        let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None
                        Expect.equal e.Health Up $"{err} clears a transport error"
                        answer.Value <- ValueNone
                        timingOut.Value <- true
                        let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None

                        Expect.isTrue
                            (match e.Health with
                             | Degraded _ -> true
                             | _ -> false)
                            $"degraded after a timeout: {e.Health}"

                        answer.Value <- ValueSome err
                        let! _ = e.Sign (request wholeKey (Duty.RandaoReveal 1UL)) CancellationToken.None
                        Expect.equal e.Health Up $"{err} clears a timeout"
                        answer.Value <- ValueNone
                        timingOut.Value <- false
                })

            testT "batched attestations never put one account twice in a batch" (fun () ->
                task {
                    let secrets = Map [ for i in 0..3 -> $"W/{i}", scalar32 (Numerics.BigInteger(1000 + i)) ]
                    let fake = FakeDirk("dirk1:1", ValueNone, secrets)
                    let e = DirkEndpoint(fake.Api, true, TimeSpan.FromSeconds 5.0, Log.none)
                    let keys = [ for i in 0..3 -> pk secrets[$"W/{i}"], $"W/{i}" ]

                    for k, n in keys do
                        e.SetAccount(k, { Name = n; Share = ValueNone }) |> ignore
                    // Two attestations for each key (two target epochs), all at once.
                    let reqs =
                        [
                            for target in [ 2UL; 3UL ] do
                                for k, _ in keys -> request k (attestationAt target (int target))
                        ]

                    let! outs = reqs |> List.map (fun r -> e.Sign r CancellationToken.None) |> Task.WhenAll

                    for r, o in List.zip reqs (List.ofArray outs) do
                        match o with
                        | Signed s -> Expect.isTrue (verifyWith r.Key r s) "verifies"
                        | o -> failtestf "not signed: %s" o.Describe

                    for b in fake.Batches do
                        Expect.equal (List.distinct b) b "one request per account in a batch"

                    Expect.equal (fake.Batches |> List.sumBy List.length) 8 "every attestation went in a batch"
                })

            testT "discovery: a distributed account becomes a 2 of 3 group that signs with one Dirk down" (fun () ->
                task {
                    let key, fakes = cluster ()
                    fakes["dirk3:3"].Down <- true

                    let dirks =
                        DirkModule.DirkSet(
                            (fun a -> fakes[a].Api),
                            settings [ "dirk1:1"; "dirk2:2"; "dirk3:3" ],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, answered = dirks.Discover CancellationToken.None
                    Expect.equal answered 2 "dirk3 is down"
                    let byKey = Map.ofList found

                    Expect.equal
                        (byKey |> Map.keys |> Set.ofSeq)
                        (set [ key; wholeKey ])
                        "the composite key and the plain key"

                    let group = byKey[key]
                    let! listed = group.Keys CancellationToken.None
                    Expect.equal (listed |> List.map (fun k -> k.Key)) [ key ] "the group lists the validator key"

                    for duty in [ attestationAt 3UL 2; Duty.Block header; Duty.AggregationSlot 25UL ] do
                        let req = request key duty

                        match! group.Sign req CancellationToken.None with
                        | Signed s -> Expect.isTrue (verifyWith key req s) $"{duty.Kind}: combined signature verifies"
                        | o -> failtestf "%A: %s" duty.Kind o.Describe

                    let solo = byKey[wholeKey]
                    let req = request wholeKey (attestationAt 3UL 2)

                    match! solo.Sign req CancellationToken.None with
                    | Signed s -> Expect.isTrue (verifyWith wholeKey req s) "plain account verifies"
                    | o -> failtestf "solo: %s" o.Describe
                    // Dirk 3 comes back: its own listing adds its share key.
                    fakes["dirk3:3"].Down <- false
                    let! _, answered2 = dirks.Discover CancellationToken.None
                    Expect.equal answered2 3 "all three answer"
                    dirks.Stop()
                })

            testT "discovery: a share from another split of the key refuses the distributed account" (fun () ->
                task {
                    let secret, shares = shamir 22 2 [ 1UL; 2UL ]
                    let other = resplit 23 secret 2 [ 3UL ]
                    let dirks, key = distributed secret (shares @ other) 2 []
                    let! found, _ = dirks.Discover CancellationToken.None
                    Expect.isFalse (found |> List.exists (fun (k, _) -> k = key)) "the key is refused"
                    dirks.Stop()
                })

            testT
                "discovery: a key that is a plain account on one Dirk and distributed on others is routed to neither"
                (fun () ->
                    task {
                        let secret, shares = shamir 24 2 [ 1UL; 2UL; 3UL ]
                        let dirks, key = distributed secret shares 2 [ 1UL ]
                        let! found, _ = dirks.Discover CancellationToken.None
                        let registry = KeyRegistry()

                        for k, b in found do
                            registry.Add(k, b) |> ignore

                        match registry.TryGet key with
                        | ValueSome k when k.State <> KeyState.Removed ->
                            failtestf "the key signs through %s" k.Backend.Name
                        | _ -> ()

                        dirks.Stop()
                    })

            testT "discovery: a distributed account where half the participants could sign is refused" (fun () ->
                task {
                    let secret, shares = shamir 25 2 [ 1UL; 2UL; 3UL; 4UL ]
                    let dirks, key = distributed secret shares 2 []
                    let registry = KeyRegistry()
                    let log, lines = Log.memory ()
                    registry.Log <- log

                    for _ in 1..3 do
                        let! found, _ = dirks.Discover CancellationToken.None
                        Expect.isFalse (found |> List.exists (fun (k, _) -> k = key)) "2 of 4 is refused"

                        match dirks.Refused with
                        | [ k, why ] ->
                            Expect.equal k key "the composite key"
                            Expect.stringContains why "threshold 2 of 4 participants" "the reason"
                        | x -> failtestf "refused: %A" x
                        // What the module does with the list (ListedKeys.Refuse).
                        for k, why in dirks.Refused do
                            registry.Refuse(k, why)

                    Expect.equal (registry.Refused |> List.map fst) [ key ] "in the registry's refused keys"
                    let errors = lines |> Seq.filter (fun l -> l.StartsWith "ERROR") |> List.ofSeq
                    Expect.equal errors.Length 1 $"logged once over three refreshes: %A{errors}"
                    dirks.Stop()
                })

            testT "discovery: an unchanged share set is not checked again" (fun () ->
                task {
                    let secret, shares = shamir 26 2 [ 1UL; 2UL; 3UL ]
                    let dirks, key = distributed secret shares 2 []
                    let! found, _ = dirks.Discover CancellationToken.None
                    Expect.isTrue (found |> List.exists (fun (k, _) -> k = key)) "routed"
                    let runs = dirks.ShareChecks.Runs
                    Expect.isGreaterThan runs 0L "checked"
                    let! _ = dirks.Discover CancellationToken.None
                    Expect.equal dirks.ShareChecks.Runs runs "not again"
                    dirks.Stop()
                })

            testT "distributed accounts at 3 of 5 and 5 of 7 sign with n - m Dirks down, not with one more" (fun () ->
                task {
                    for m, n in [ 3, 5; 5, 7 ] do
                        let secret, shares = shamir (40 + n) m [ 1UL .. uint64 n ]
                        let key = pk secret

                        let participants =
                            [
                                for i in 1UL .. uint64 n ->
                                    {
                                        Id = i
                                        Name = $"dirk{i}"
                                        Port = uint32 i
                                    }
                            ]

                        let fakes =
                            [
                                for id, share in shares ->
                                    let listing =
                                        {
                                            State = ResponseState.Succeeded
                                            Accounts = []
                                            DistributedAccounts =
                                                [
                                                    {
                                                        Name = "Dist/V1"
                                                        PublicKey = (pk share).Bytes
                                                        Participants = participants
                                                        SigningThreshold = uint32 m
                                                        CompositePublicKey = key.Bytes
                                                    }
                                                ]
                                        }

                                    $"dirk{id}:{id}",
                                    FakeDirk($"dirk{id}:{id}", ValueSome listing, Map [ "Dist/V1", share ])
                            ]
                            |> Map.ofList

                        let addresses = [ for i in 1..n -> $"dirk{i}:{i}" ]

                        let dirks =
                            DirkModule.DirkSet(
                                (fun a -> fakes[a].Api),
                                settings addresses,
                                TimeProvider.System,
                                Log.none
                            )

                        let! found, answered = dirks.Discover CancellationToken.None
                        Expect.equal answered n $"{n} Dirks"
                        let group = (Map.ofList found)[key]
                        Expect.stringContains group.Name $"dirk {m} of {n}" "a group per participant set"
                        // The last n - m participants go down.
                        for i in m + 1 .. n do
                            fakes[$"dirk{i}:{i}"].Down <- true

                        for duty in [ attestationAt 3UL 2; Duty.Block header; Duty.RandaoReveal 3UL ] do
                            let req = request key duty

                            match! group.Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.equal
                                    s.Hex
                                    (sign secret req.SigningRoot).Hex
                                    $"{m} of {n}, {duty.Kind}: the whole key's signature"
                            | o -> failtestf "%d of %d, %A: %s" m n duty.Kind o.Describe

                        fakes[$"dirk{m}:{m}"].Down <- true
                        let! few = group.Sign (request key (Duty.RandaoReveal 4UL)) CancellationToken.None

                        Expect.isTrue
                            (match few with
                             | Failed(Transport _) -> true
                             | _ -> false)
                            $"{m - 1} up: {few.Describe}"

                        dirks.Stop()
                })

            testT "a denied attestation in a batch leaves only that entry unsigned" (fun () ->
                task {
                    let secrets = Map [ for i in 0..3 -> $"W/{i}", scalar32 (Numerics.BigInteger(2000 + i)) ]
                    let fake = FakeDirk("dirk1:1", ValueNone, secrets)

                    fake.Answer <-
                        fun call ->
                            if nameOf call = "W/1" then
                                ValueSome
                                    {
                                        State = ResponseState.Denied
                                        Signature = [||]
                                    }
                            else
                                ValueNone

                    let e = DirkEndpoint(fake.Api, true, TimeSpan.FromSeconds 5.0, Log.none)
                    let keys = [ for i in 0..3 -> pk secrets[$"W/{i}"], $"W/{i}" ]

                    for k, n in keys do
                        e.SetAccount(k, { Name = n; Share = ValueNone }) |> ignore

                    let reqs = [ for k, _ in keys -> request k (attestationAt 2UL 2) ]
                    let! outs = reqs |> List.map (fun r -> e.Sign r CancellationToken.None) |> Task.WhenAll

                    for (r, (_, name)), o in List.zip (List.zip reqs keys) (List.ofArray outs) do
                        match name, o with
                        | "W/1", Refused(Refusal.Denied _) -> ()
                        | "W/1", o -> failtestf "W/1: expected Denied, got %s" o.Describe
                        | _, Signed s -> Expect.isTrue (verifyWith r.Key r s) $"{name} verifies"
                        | _, o -> failtestf "%s: not signed: %s" name o.Describe

                    Expect.equal (fake.Batches |> List.sumBy List.length) 4 "every attestation went in a batch"
                })

            testT "a denied attestation skips the duty, counts it and keeps the key active" (fun () ->
                task {
                    let secrets = Map [ for i in 0..2 -> $"W/{i}", scalar32 (Numerics.BigInteger(3000 + i)) ]
                    let fake = FakeDirk("dirk1:1", ValueNone, secrets)

                    fake.Answer <-
                        fun call ->
                            if nameOf call = "W/1" then
                                ValueSome
                                    {
                                        State = ResponseState.Denied
                                        Signature = [||]
                                    }
                            else
                                ValueNone

                    let e = DirkEndpoint(fake.Api, true, TimeSpan.FromSeconds 5.0, Log.none)
                    let keys = [ for i in 0..2 -> pk secrets[$"W/{i}"] ]

                    for k, i in List.zip keys [ 0..2 ] do
                        e.SetAccount(k, { Name = $"W/{i}"; Share = ValueNone }) |> ignore

                    let backend = e.Backend "dirk" false (fun _ _ -> true)

                    use db =
                        match
                            Eplix.Slashing.SlashingDb.Open(
                                new Eplix.Slashing.FileMarkFile(IO.Path.Combine(tempDir (), "s.db")),
                                root 1
                            )
                        with
                        | Ok db -> db
                        | Error err -> failwith err

                    db.RegisterKeys [ for k in keys -> k, Eplix.Slashing.KeyOrigin.StartedEmpty ] |> ignore
                    let registry = KeyRegistry()

                    for k in keys do
                        registry.Add(k, backend) |> ignore
                        registry.SetState(k, KeyState.Active)

                    let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none)

                    let! outs =
                        pipeline.SignBurst(
                            [| for k in keys -> request k (attestationAt 2UL 2) |],
                            CancellationToken.None
                        )

                    Expect.isTrue
                        (match outs[1] with
                         | Refused(Refusal.Denied _) -> true
                         | _ -> false)
                        $"W/1 denied: {outs[1].Describe}"

                    Expect.isTrue
                        (match outs[0], outs[2] with
                         | Signed _, Signed _ -> true
                         | _ -> false)
                        "the rest of the burst is signed"

                    Expect.equal (registry.TryGet keys[1]).Value.State KeyState.Active "the denied key stays active"
                    Expect.equal (registry.Denials keys[1]) 1L "the denial is counted for that key"
                    Expect.equal (registry.Denials keys[0]) 0L "no denial for the others"
                    // The next duty for the key goes to Dirk as usual.
                    fake.Answer <- fun _ -> ValueNone
                    let! next = pipeline.Sign(request keys[1] (attestationAt 3UL 3), CancellationToken.None)

                    Expect.isTrue
                        (match next with
                         | Signed _ -> true
                         | _ -> false)
                        $"the next attestation is signed: {next.Describe}"
                })

            testT "every Dirk of a group denying a double vote gives one Denied with the counts" (fun () ->
                task {
                    let key, fakes = cluster ()

                    for f in fakes.Values do
                        f.Answer <-
                            fun call ->
                                match call with
                                | DirkCall.Attestation _ ->
                                    ValueSome
                                        {
                                            State = ResponseState.Denied
                                            Signature = [||]
                                        }
                                | _ -> ValueNone

                    let dirks =
                        DirkModule.DirkSet(
                            (fun a -> fakes[a].Api),
                            settings [ "dirk1:1"; "dirk2:2"; "dirk3:3" ],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, _ = dirks.Discover CancellationToken.None
                    let group = (Map.ofList found)[key]

                    match! group.Sign (request key (attestationAt 3UL 2)) CancellationToken.None with
                    | Refused(Refusal.Denied(_, t)) ->
                        // The group gives up once two have denied; the third answer may come before or after.
                        Expect.equal t.Signed 0 "nobody signed"
                        Expect.isGreaterThanOrEqual t.Denied 2 "at least two denied"
                    | o -> failtestf "expected Denied: %s" o.Describe

                    dirks.Stop()
                })

            testT "a PTC vote signs through the Dirk module with the fork's typed call" (fun () ->
                task {
                    let spec = testSpec.Value
                    Expect.equal spec.DomainPtcAttester.Hex "0x0c000000" "DOMAIN_PTC_ATTESTER"
                    // Dirk 1 to 3 hold a 2 of 3 distributed account; Dirk 1 also a plain one. Each denies
                    // a PTC vote sent as root and domain, as the fork does.
                    let key, fakes = cluster ()

                    for f in fakes.Values do
                        f.Answer <- forkRules

                    let dirks =
                        DirkModule.DirkSet(
                            (fun a -> fakes[a].Api),
                            settings [ "dirk1:1"; "dirk2:2"; "dirk3:3" ],
                            TimeProvider.System,
                            Log.none
                        )

                    let! found, _ = dirks.Discover CancellationToken.None
                    let registry = KeyRegistry()

                    for k, backend in found do
                        registry.Add(k, backend) |> ignore
                        registry.SetState(k, KeyState.Active)

                    use db =
                        match SlashingDb.Open(new FileMarkFile(IO.Path.Combine(tempDir (), "s.db")), root 1) with
                        | Ok db -> db
                        | Error err -> failwith err

                    let marks =
                        match SlotMarks.Open(new ModelFile([||]), root 1) with
                        | Ok m -> m
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none, marks)
                    let keys = [| key; wholeKey |]

                    let reqs =
                        Duty.requests spec (root 1) keys Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) ptcVote

                    let! outs = pipeline.SignBurst(reqs, CancellationToken.None)

                    for r, o in Array.zip reqs outs do
                        match o with
                        | Signed s -> Expect.isTrue (verifyWith r.Key r s) $"the PTC vote of {r.Key.Short} verifies"
                        | o -> failtestf "PTC vote of %s: %s" r.Key.Short o.Describe

                    for f in fakes.Values do
                        for c in f.Calls do
                            match c with
                            | DirkCall.PayloadAttestation(_, domain, d) ->
                                Expect.equal domain reqs[0].Domain "the request's domain"
                                Expect.equal (Duty.PayloadAttestation d) ptcVote "the vote's data"
                            | c -> failtestf "expected SignPayloadAttestation, got %A" c
                    // Dirk 1 signs twice (its share and the plain key), Dirk 2 and 3 once each, unless
                    // the group stopped asking once two shares were in.
                    Expect.isGreaterThanOrEqual (fakes.Values |> Seq.sumBy (fun f -> f.Calls.Length)) 3 "typed calls"
                    dirks.Stop()
                })

            testT
                "Gloas kinds go typed to the fork, and as root and domain to stock Dirk after one UNIMPLEMENTED"
                (fun () ->
                    task {
                        let p = Preset.Minimal
                        let envelope = Schemas.Gloas.executionPayloadEnvelope p

                        let duties =
                            [
                                ptcVote
                                Duty.PayloadEnvelope(
                                    41UL,
                                    {
                                        Schema = envelope
                                        Value = sample (Random 5) envelope
                                    }
                                )
                                Duty.ProposerPreferences
                                    {
                                        DependentRoot = root 3
                                        ProposalSlot = 42UL
                                        ValidatorIndex = 1UL
                                        FeeRecipient = Array.create 20 0xaauy
                                        TargetGasLimit = 60_000_000UL
                                    }
                                Duty.BuilderRequestAuth
                                    {
                                        AuthData = Text.Encoding.UTF8.GetBytes "builder.example.org"
                                        AuthSlot = 42UL
                                    }
                            ]

                        let fork = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                        fork.Answer <- forkRules
                        let stock = FakeDirk("dirk2:2", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                        stock.Typed <- false

                        for fake in [ fork; stock ] do
                            let b = (endpointWith fake false).Backend "dirk" false (fun _ a -> a.Share.IsNone)

                            for duty in duties do
                                let req = request wholeKey duty

                                match! b.Sign req CancellationToken.None with
                                | Signed s -> Expect.isTrue (verifyWith wholeKey req s) $"{duty.Kind} verifies"
                                | o -> failtestf "%s, %A: %s" fake.Api.Address duty.Kind o.Describe

                        Expect.isTrue
                            (fork.Calls |> List.forall (fun c -> c.IsTypedGloas))
                            "the fork gets typed calls only"

                        Expect.equal fork.Calls.Length 4 "one call per duty"
                        Expect.equal stock.Unimplemented 1 "stock Dirk is asked one typed call"

                        match stock.Calls with
                        | [ DirkCall.Generic(_, r1, _)
                            DirkCall.Generic _
                            DirkCall.Generic _
                            DirkCall.Generic(_, r4, _) ] ->
                            Expect.equal r1 (Duty.objectRoot ptcVote) "the PTC vote's root"
                            Expect.equal r4 (Duty.objectRoot (List.last duties)) "the builder auth's root"
                        | calls -> failtestf "unexpected calls %A" calls
                    })

            test "the fork's request messages: field numbers, and an envelope summary with the envelope's root" {
                let vote =
                    match ptcVote with
                    | Duty.PayloadAttestation d -> d
                    | _ -> failwith "a PTC vote"

                let f =
                    Protobuf.fields (
                        ReadOnlyMemory(
                            signPayloadAttestationRequest (AccountId.Name "W/A") (Domain.Of(Array.create 32 9uy)) vote
                        )
                    )

                Expect.equal (f |> List.map (fun x -> x.Number)) [ 2; 3; 4 ] "account, domain, data"
                let data = Protobuf.fields f[2].Bytes

                Expect.equal
                    (data |> List.map (fun x -> x.Number))
                    [ 1; 2; 3 ]
                    "root, slot, payload_present (a false blob_data_available is left out)"

                Expect.equal (Protobuf.asBytes data[0]) (root 7).Bytes "beacon block root"
                Expect.equal (Protobuf.asVarint data[1]) 41UL "slot"
                // The fork computes the envelope root from the summary (backend/gloas.go there): each
                // summary field is one chunk of a progressive container. Rebuilt here from the bytes.
                let get (fs: Protobuf.Field list) n = fs |> List.tryFind (fun x -> x.Number = n)

                let chunkOf (fs: Protobuf.Field list) (n: int) (isNumber: bool) : string * Ssz.SszType * Ssz.SszValue =
                    match isNumber, get fs n with
                    | true, Some x -> $"f{n}", Ssz.Uint 8, Ssz.U(Protobuf.asVarint x)
                    | true, None -> $"f{n}", Ssz.Uint 8, Ssz.U 0UL
                    | false, Some x ->
                        let b = Protobuf.asBytes x
                        $"f{n}", Ssz.ByteVector b.Length, Ssz.Bytes b
                    | false, None -> failtestf "field %d missing" n

                let rootOf (chunks: (string * Ssz.SszType * Ssz.SszValue) list) =
                    Ssz.hashTreeRoot
                        (Ssz.ProgressiveContainer [| for n, t, _ in chunks -> n, t |])
                        (Ssz.Fields [| for _, _, v in chunks -> v |])

                let numbers = set [ 7; 8; 9; 10; 16; 17; 19 ]
                let schema = Schemas.Gloas.executionPayloadEnvelope Preset.Minimal

                for seed in 1..5 do
                    let e =
                        {
                            Schema = schema
                            Value = sample (Random seed) schema
                        }

                    let env = Protobuf.fields (ReadOnlyMemory(executionPayloadEnvelope e))
                    let summary = Protobuf.fields (get env 1).Value.Bytes
                    let payloadRoot = rootOf [ for n in 1..19 -> chunkOf summary n (numbers.Contains n) ]

                    let envRoot =
                        rootOf
                            [
                                "payload", Ssz.ByteVector 32, Ssz.Bytes payloadRoot
                                chunkOf env 2 false
                                chunkOf env 3 true
                                chunkOf env 4 false
                                chunkOf env 5 false
                            ]

                    Expect.equal (Root.Of envRoot) e.HashTreeRoot $"seed {seed}: the summary's root is the envelope's"
            }

            testT "gloas_calls: each mode against a fork-like and a stock-like Dirk" (fun () ->
                task {
                    let run (mode: GloasCalls) (typed: bool) =
                        task {
                            let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                            fake.Typed <- typed

                            if typed then
                                fake.Answer <- forkRules

                            let e = DirkEndpoint(fake.Api, false, TimeSpan.FromSeconds 5.0, Log.none, mode)
                            e.SetAccount(wholeKey, { Name = "Solo/A"; Share = ValueNone }) |> ignore

                            let! outs =
                                [ for d in gloasDuties -> e.Sign (request wholeKey d) CancellationToken.None ]
                                |> Task.WhenAll

                            return fake, List.ofArray outs
                        }

                    let allSigned outs =
                        outs
                        |> List.forall (fun o ->
                            match o with
                            | Signed _ -> true
                            | _ -> false)

                    let typedOnly (f: FakeDirk) = f.Calls |> List.forall (fun c -> c.IsTypedGloas)

                    let genericOnly (f: FakeDirk) =
                        f.Calls
                        |> List.forall (fun c ->
                            match c with
                            | DirkCall.Generic _ -> true
                            | _ -> false)
                    // auto: typed to the fork; stock Dirk gets one typed call, then root and domain.
                    let! f, outs = run GloasCalls.Auto true

                    Expect.isTrue
                        (allSigned outs && typedOnly f && f.Calls.Length = 4)
                        "auto, fork: typed calls, all signed"

                    let! f, outs = run GloasCalls.Auto false

                    Expect.isTrue
                        (allSigned outs && genericOnly f && f.Calls.Length = 4)
                        "auto, stock: root and domain, all signed"

                    Expect.isLessThanOrEqual f.Unimplemented 4 "auto, stock: typed calls asked until the first answer"
                    Expect.isGreaterThanOrEqual f.Unimplemented 1 "auto, stock: one UNIMPLEMENTED at least"
                    // typed: the fork signs; stock Dirk fails every Gloas kind and is never asked generic.
                    let! f, outs = run GloasCalls.Typed true
                    Expect.isTrue (allSigned outs && typedOnly f) "typed, fork: all signed"
                    let! f, outs = run GloasCalls.Typed false
                    Expect.equal f.Unimplemented 4 "typed, stock: every request tried typed"
                    Expect.isEmpty f.Calls "typed, stock: no generic call"

                    for o in outs do
                        match o with
                        | Failed(Internal m) -> Expect.stringContains m "gloas_calls" "the error names the setting"
                        | o -> failtestf "typed, stock: expected a failure, got %s" o.Describe
                    // generic: never a typed call; stock Dirk signs, the fork denies as its rules say.
                    let! f, outs = run GloasCalls.Generic false
                    Expect.isTrue (allSigned outs && genericOnly f && f.Calls.Length = 4) "generic, stock: all signed"
                    Expect.equal f.Unimplemented 0 "generic, stock: no typed call"
                    let! f, outs = run GloasCalls.Generic true
                    Expect.isTrue (genericOnly f && f.Calls.Length = 4) "generic, fork: root and domain only"

                    Expect.isTrue
                        (outs
                         |> List.forall (fun o ->
                             match o with
                             | Refused(Refusal.Denied _) -> true
                             | _ -> false))
                        "generic, fork: denied"
                    // Other kinds do not depend on the mode.
                    let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                    let e = DirkEndpoint(fake.Api, false, TimeSpan.FromSeconds 5.0, Log.none, GloasCalls.Generic)
                    e.SetAccount(wholeKey, { Name = "Solo/A"; Share = ValueNone }) |> ignore
                    let! a = e.Sign (request wholeKey (attestationAt 2UL 1)) CancellationToken.None

                    Expect.isTrue
                        (match a, fake.Calls with
                         | Signed _, [ DirkCall.Attestation _ ] -> true
                         | _ -> false)
                        "attestations stay typed"
                })

            test "gloas_calls: default auto, the three values, a clear error otherwise" {
                let parse (extra: string) =
                    DirkModule.parseSettings (
                        dirkSection (
                            $$"""{ "endpoints": [ "d1:1" ], "accounts": [ "W" ], "ca_cert": "ca", "client_cert": "c", "client_key": "k"{{extra}} }"""
                        )
                    )

                let mode extra =
                    match parse extra with
                    | Ok s -> s.GloasCalls
                    | Error e -> failtestf "%A" e

                Expect.equal (mode "") GloasCalls.Auto "default"

                for g in [ GloasCalls.Auto; GloasCalls.Typed; GloasCalls.Generic ] do
                    Expect.equal (mode $", \"gloas_calls\": \"{g.Name}\"") g g.Name

                for bad in [ "\"Typed\""; "\"stock\""; "true"; "1" ] do
                    match parse $", \"gloas_calls\": {bad}" with
                    | Error [ m ] ->
                        Expect.stringContains
                            m
                            "gloas_calls must be \"auto\", \"typed\" or \"generic\""
                            $"{bad}: the error lists the values"

                        Expect.stringContains m bad $"{bad}: the error quotes the value"
                    | r -> failtestf "%s: expected one error, got %A" bad r
            }

            test "channels ping only while a call is open, and dial with TCP keepalive" {
                use h = GrpcDirk.handlerFor (TimeSpan.FromHours 1.0)

                Expect.equal
                    h.KeepAlivePingPolicy
                    Net.Http.HttpKeepAlivePingPolicy.WithActiveRequests
                    "no pings on an idle connection"

                Expect.equal h.PooledConnectionIdleTimeout Threading.Timeout.InfiniteTimeSpan "an idle connection stays"
                Expect.isNotNull h.ConnectCallback "own dial"
                let listener = new Net.Sockets.TcpListener(Net.IPAddress.Loopback, 0)
                listener.Start()

                try
                    let port = (listener.LocalEndpoint :?> Net.IPEndPoint).Port

                    use stream =
                        GrpcDirk.keepAliveConnect (Net.DnsEndPoint("localhost", port)) CancellationToken.None
                        |> fun v -> v.AsTask().Result

                    let socket = (stream :?> Net.Sockets.NetworkStream).Socket
                    let opt level name = socket.GetSocketOption(level, name) :?> int

                    Expect.notEqual
                        (opt Net.Sockets.SocketOptionLevel.Socket Net.Sockets.SocketOptionName.KeepAlive)
                        0
                        "SO_KEEPALIVE"

                    Expect.equal
                        (opt Net.Sockets.SocketOptionLevel.Tcp Net.Sockets.SocketOptionName.TcpKeepAliveTime)
                        30
                        "idle 30 s"

                    Expect.equal
                        (opt Net.Sockets.SocketOptionLevel.Tcp Net.Sockets.SocketOptionName.TcpKeepAliveInterval)
                        10
                        "every 10 s"

                    Expect.equal
                        (opt Net.Sockets.SocketOptionLevel.Tcp Net.Sockets.SocketOptionName.TcpKeepAliveRetryCount)
                        3
                        "3 probes"

                    if OperatingSystem.IsLinux() then
                        let v = Array.zeroCreate<byte> 4
                        socket.GetRawSocketOption(6, 18, Span v) |> ignore
                        Expect.equal (BitConverter.ToInt32(v, 0)) 30_000 "TCP_USER_TIMEOUT 30 s"
                finally
                    listener.Stop()
            }

            testT "an instance that never answers ListAccounts fails it after the deadline; the others list" (fun () ->
                task {
                    let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map.empty)
                    let silentFake = FakeDirk("dirk2:2", ValueNone, Map.empty)

                    let silent =
                        { silentFake.Api with
                            ListAccounts =
                                fun _ ct ->
                                    task {
                                        try
                                            do! Task.Delay(-1, ct)
                                        with :? OperationCanceledException ->
                                            ()

                                        return Error(CallError.Failure SignFailure.Timeout)
                                    }
                        }

                    let apis = Map.ofList [ "dirk1:1", fake.Api; "dirk2:2", silent ]
                    let time = Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow)

                    let dirks =
                        DirkModule.DirkSet((fun a -> apis[a]), settings [ "dirk1:1"; "dirk2:2" ], time, Log.none)

                    let discover = dirks.Discover CancellationToken.None
                    time.Advance(ListedKeys.ListDeadline - TimeSpan.FromSeconds 1.0)
                    do! Task.Delay 100
                    Expect.isFalse discover.IsCompleted "waits within the deadline"
                    time.Advance(TimeSpan.FromSeconds 1.0)
                    let! found, answered = discover.WaitAsync(TimeSpan.FromSeconds 10.0)
                    Expect.equal answered 1 "the silent instance failed its list"
                    Expect.equal (found |> List.map fst) [ wholeKey ] "the key of the other instance"
                    dirks.Stop()
                })

            testT
                "a whole-key signature that does not verify is returned and counted by the background check"
                (fun () ->
                    task {
                        let fake = FakeDirk("dirk1:1", ValueSome soloListing, Map [ "Solo/A", wholeSecret ])
                        let e = endpointWith fake false
                        let backend = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)
                        let r = request wholeKey (attestationAt 3UL 2)

                        match! backend.Sign r CancellationToken.None with
                        | Signed s -> Expect.isTrue (verifyWith wholeKey r s) "a good signature passes"
                        | o -> failtestf "good: %s" o.Describe
                        // The good check must land first: a pass that lands after the failure clears it.
                        do! settle e.Watch

                        fake.Answer <-
                            fun _ ->
                                ValueSome
                                    {
                                        State = ResponseState.Succeeded
                                        Signature = (sign wholeSecret (root 99)).Bytes
                                    }

                        let! bad = backend.Sign r CancellationToken.None

                        Expect.isTrue
                            (match bad with
                             | Signed _ -> true
                             | _ -> false)
                            $"returned at once: {bad.Describe}"

                        do! settle e.Watch
                        Expect.equal (e.Watch.Fails wholeKey) 1 "the check failed once"
                        e.Stop()
                    })
        ]
