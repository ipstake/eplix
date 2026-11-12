/// The TEE signer module with fakes: the runner codec against bytes the runner's own Go encoder
/// made (tests/fixtures/tee/wire-go.json, identity-v1-teesigner.json), the refusal mapping, the pool's
/// priorities, dials and late replies, whole keys and 2 of 3 groups over fake runners, and the
/// config.
module Eplix.Tests.TeeTests

open System
open System.Collections.Concurrent
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Tee
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.SchedulerTests

let private goVectors =
    lazy
        (use doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(fixtures, "tee", "wire-go.json")))

         Map.ofList
             [
                 for p in doc.RootElement.EnumerateObject() -> p.Name, Convert.FromHexString(p.Value.GetString())
             ])

let private go (name: string) = goVectors.Value[name]

/// IDENTITY v1 vectors made by tee-signer's Go code (signer-protocol and its wire
/// package: EncodeAttest, EncodeIdentity, IdentityUserData, MAARuntimeData, DecodeAttest).
let private teeSignerV1 =
    lazy
        (use doc =
            JsonDocument.Parse(File.ReadAllText(Path.Combine(fixtures, "tee", "identity-v1-teesigner.json")))

         Map.ofList
             [
                 for p in doc.RootElement.EnumerateObject() -> p.Name, Wire.nonNull (p.Value.GetString())
             ])

/// The Go generator's root(b): bytes b, b+1, ... b+31.
let private goRoot (b: int) = Root.Of(Array.init 32 (fun i -> byte (b + i)))

let private goKey = lazy (PubKey.Of(go "pubkey"))
let private goDomain = lazy (Domain.Of(go "domain"))

let private signReq (duty: Duty) =
    {
        Key = goKey.Value
        Duty = duty
        Fork =
            {
                Fork =
                    {
                        PreviousVersion = ForkVersion.Of [| 0uy; 0uy; 0uy; 1uy |]
                        CurrentVersion = ForkVersion.Of [| 0uy; 0uy; 0uy; 1uy |]
                        Epoch = 0UL
                    }
                GenesisValidatorsRoot = Root.Zero
            }
        Domain = goDomain.Value
        SigningRoot = Root.Zero
        Priority = Priority.High
        Deadline = DateTimeOffset.UtcNow.AddSeconds 10.0
    }

/// A runner's refusal: a status code and its detail text.
let private refusal code (detail: string) : Wire.Refusal = { Code = code; Detail = detail }

let private att =
    {
        Slot = 41UL
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = 4UL; Root = root 4 }
        Target = { Epoch = 5UL; Root = root 5 }
    }

// ---- fakes ---------------------------------------------------------------------

/// A runner in memory: it holds one secret per validator key (the whole key, or a share), signs
/// the root the test registered for each SIGN payload, and can refuse or fail on demand.
type FakeRunner(name: string, keys: (PubKey * byte[]) list) =
    let roots = ConcurrentDictionary<string, Root>()
    let mutable behaviour: byte[] -> Reply voption = fun _ -> ValueNone
    let mutable calls = 0
    let mutable signCalls = 0

    let mutable health =
        Reply.Body(Text.Encoding.UTF8.GetBytes """{"platform":"fake","protocol":2,"ready":true}""")

    let connected = Event<unit>()
    let firstUp = Event<unit>()
    let mutable sendGate: Wire.MsgType -> bool = fun _ -> false
    let mutable healthGate: Task = Task.CompletedTask
    // While set, every call waits here as a request waits in the pool for a connection.
    let mutable connectionGate: Task = Task.CompletedTask
    let mutable openConnection: TaskCompletionSource | null = null

    member _.Calls = calls

    /// Holds every HEALTH answer until the returned source is set.
    member _.HoldHealth() =
        let gate = TaskCompletionSource()
        healthGate <- gate.Task
        gate

    /// SIGN requests that reached the runner.
    member _.SignCalls = signCalls

    /// What HEALTH answers: this JSON (the default says ready).
    member _.SetHealth(json: string) = health <- Reply.Body(Text.Encoding.UTF8.GetBytes json)

    /// What HEALTH answers, as a reply (a failure or a refusal).
    member _.SetHealthReply(r: Reply) = health <- r

    /// Fires the pool's new-connection event.
    member _.Connect() = connected.Trigger()

    /// Every connection is down: calls wait until NewConnection.
    member _.DropConnections() =
        let gate = TaskCompletionSource()
        openConnection <- gate
        connectionGate <- gate.Task

    /// A connection comes up after all were down, in the pool's order: the waiting requests get
    /// it, then the new-connection event fires.
    member _.NewConnection() =
        match openConnection with
        | null -> ()
        | gate ->
            openConnection <- null
            connectionGate <- Task.CompletedTask
            firstUp.Trigger()
            gate.SetResult()

        connected.Trigger()

    /// Makes the runner answer `f payload` instead of signing, where f gives a reply.
    member _.Behave(f: byte[] -> Reply voption) = behaviour <- f

    /// Tells the runner which signing root a request's SIGN payload stands for.
    member _.Expect(req: SignRequest) = roots[Convert.ToHexString(Wire.encodeSign req)] <- req.SigningRoot

    member this.Api: RunnerApi =
        {
            Name = name
            Call =
                fun _ t payload _ ->
                    task {
                        do! connectionGate
                        Interlocked.Increment &calls |> ignore
                        let held = sendGate t

                        if t = Wire.MsgType.Sign && not held then
                            Interlocked.Increment &signCalls |> ignore

                        if t = Wire.MsgType.Health then
                            do! healthGate

                        match
                            (if held then ValueSome Reply.Held
                             elif t = Wire.MsgType.Health then ValueSome health
                             else behaviour payload)
                        with
                        | ValueSome r -> return r
                        | ValueNone ->
                            match t with
                            | Wire.MsgType.PublicKeys ->
                                return
                                    Reply.Body(
                                        Wire.encodeKeys
                                            [
                                                for v, s in keys ->
                                                    {
                                                        PubKey = v
                                                        SharePubKey = pk s
                                                        Index = Wire.IndexUnknown
                                                    }
                                            ]
                                    )
                            | Wire.MsgType.Sign ->
                                let v = PubKey.Of payload[0..47]

                                match
                                    keys |> List.tryFind (fun (k, _) -> k = v),
                                    roots.TryGetValue(Convert.ToHexString payload)
                                with
                                | Some(_, s), (true, r) -> return Reply.Body (sign s r).Bytes
                                | None, _ ->
                                    return Reply.Refused(refusal Wire.Status.UnknownValidator "no such validator")
                                | _ -> return Reply.Failure(Internal "the test registered no root for this payload")
                            | _ -> return Reply.Failure(Internal "not faked")
                    }
            Up = fun () -> 1, 1
            LastError = fun () -> ""
            Connected = connected.Publish
            FirstUp = firstUp.Publish
            SetSendGate = fun g -> sendGate <- g
            Close = ignore
        }


/// A pool connection the test drives.
type FakeConn(id: int) =
    let mutable state = ConnState.Ready
    let mutable drained = TaskCompletionSource<bool>()
    let mutable closed = false
    member _.Id = id
    member _.IsClosed = closed

    member _.SetState s =
        if s = ConnState.Late then
            drained <- TaskCompletionSource<bool>()

        state <- s

    member _.FinishDrain ok =
        if ok then
            state <- ConnState.Ready

        drained.TrySetResult ok |> ignore

    interface PoolConn with
        member _.State = state
        member _.Drained = drained.Task
        member _.Close() = closed <- true

/// A pool connection that reports its break, as RunnerConnection does when its read loop ends.
type NoticeConn(id: int) =
    let mutable state = ConnState.Ready
    let mutable closed = false
    let mutable onBroken: (unit -> unit) voption = ValueNone
    member _.Id = id
    member _.IsClosed = closed

    /// The runner went away: broken, and the pool is told.
    member _.Break() =
        state <- ConnState.Broken

        match onBroken with
        | ValueSome f -> f ()
        | ValueNone -> ()

    interface PoolConn with
        member _.State = state
        member _.Drained = Task.FromResult false
        member _.Close() = closed <- true

    interface BreakNotice with
        member _.OnBroken f = if state = ConnState.Broken then f () else onBroken <- ValueSome f

/// A pool connection that can break between two reads of its state: the first read after
/// BreakAfterNextRead says Ready, every later one Broken (the runner closed it in between).
type FlipConn(id: int) =
    let mutable state = ConnState.Ready
    let mutable reads = -1
    let mutable closed = false
    member _.Id = id
    member _.IsClosed = closed
    member _.BreakAfterNextRead() = reads <- 0

    interface PoolConn with
        member _.State =
            if reads >= 0 then
                reads <- reads + 1

                if reads > 1 then
                    state <- ConnState.Broken

            state

        member _.Drained = Task.FromResult false
        member _.Close() = closed <- true

let private waitFor (cond: unit -> bool) =
    let sw = Diagnostics.Stopwatch.StartNew()

    while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
        Thread.Sleep 5

    Expect.isTrue (cond ()) "condition within 10 s"

/// A fake clock whose wall clock can step back while its timestamps and timers run on.
type private SteppedClock(inner: Microsoft.Extensions.Time.Testing.FakeTimeProvider) =
    inherit TimeProvider()
    member val Back = TimeSpan.Zero with get, set
    override this.GetUtcNow() = inner.GetUtcNow() - this.Back
    override _.GetTimestamp() = inner.GetTimestamp()
    override _.TimestampFrequency = inner.TimestampFrequency
    override _.LocalTimeZone = inner.LocalTimeZone
    override _.CreateTimer(callback, state, dueTime, period) = inner.CreateTimer(callback, state, dueTime, period)

let private section (json: string) (dir: string) : ConfigSection =
    let doc = JsonDocument.Parse json

    {
        Element = ValueSome doc.RootElement
        BaseDir = dir
        Mainnet = false
    }

let private teeSettings: TeeModule.Settings =
    {
        Runners = []
        Groups = []
        Timeout = TimeSpan.FromSeconds 2.0
        DialTimeout = TimeSpan.FromSeconds 5.0
        LowEvery = 8
        RefreshInterval = TimeSpan.Zero
        Keys = TeeModule.KeyFilter.AnyListedTestOnly
        AttestationCaFile = ValueNone
        ReloadInterval = TimeSpan.Zero
        RotateWithin = TimeSpan.FromSeconds 300.0
        HaPeer = false
        Network = Attest.NetworkKind.Testnet
    }

let private runnerCfg (n: string) : TeeModule.RunnerConfig =
    {
        Name = n
        Host = "127.0.0.1"
        Port = 1
        ClientCert = ""
        ClientKey = ""
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Connections = 1
        Attestation = Attest.Settings.Empty
    }

/// Three fake runners with one share each of 2 of 3 keys, and a whole key on the first.
let private teeSetLog (log: Log) =
    let groupKeys = [ for s in 0..1 -> shamir (900 + s) 2 [ 1UL; 2UL; 3UL ] ]
    let whole = secretOf 77

    let runners =
        [
            for m in 0..2 ->
                let shares = [ for secret, sh in groupKeys -> pk secret, snd sh[m] ]
                let all = if m = 0 then (pk whole, whole) :: shares else shares
                FakeRunner($"r{m + 1}", all)
        ]

    let settings =
        { teeSettings with
            Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
            Groups =
                [
                    {
                        Threshold = 2
                        Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                    }
                ]
        }

    let set =
        TeeModule.TeeSet(
            [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
            settings,
            TimeProvider.System,
            log
        )

    set, runners, groupKeys, whole

let private teeSet () = teeSetLog Log.none

/// tee-signer's answer to a vote at or below a key's floor (server.go sign): FLOOR with the
/// floor epoch and kind at the start of the detail.
let private floorRefusal (kind: string) (floor: uint64) (p: byte[]) =
    if p[48] = Wire.Kind.Attestation then
        ValueSome(
            Reply.Refused(refusal Wire.Status.Floor $"floor epoch {floor} ({kind} floor): attestation source 3 below 4")
        )
    else
        ValueNone

/// A pipeline on the clock of `h` over one backend for `key`, active, with an empty slashing
/// DB; and votes for it.
let private pipelineOn (h: Eplix.Tests.SchedulerTests.Harness) (key: PubKey) (backend: Backend) =
    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), Eplix.Tests.FakeBeaconNode.gvr) with
        | Ok db -> db
        | Error e -> failwith e

    db.RegisterKeys [ key, KeyOrigin.StartedEmpty ] |> ignore
    let registry = KeyRegistry()
    registry.Add(key, backend) |> ignore
    registry.SetState(key, KeyState.Active)

    let vote target =
        let d =
            { att with
                Source = { Epoch = target - 1UL; Root = root 4 }
                Target = { Epoch = target; Root = root 5 }
            }

        Duty.request
            h.Spec
            Eplix.Tests.FakeBeaconNode.gvr
            key
            Priority.High
            (h.Time.GetUtcNow().AddSeconds 10.0)
            (Duty.Attestation d)

    Pipeline(db, registry, h.Time, Log.none), registry, db, vote

let private pipelineFor (key: PubKey) (backend: Backend) =
    pipelineOn (Eplix.Tests.SchedulerTests.harness ()) key backend

let private expectAll (runners: FakeRunner list) (req: SignRequest) =
    for r in runners do
        r.Expect req

[<Tests>]
let tests =
    testList
        "tee"
        [
            testList
                "wire"
                [
                    test "SIGN payloads match the runner's own encoder for every kind" {
                        let r = signReq
                        let check name (duty: Duty) = Expect.equal (Wire.encodeSign (r duty)) (go $"sign_{name}") name

                        check
                            "attestation"
                            (Duty.Attestation
                                {
                                    Slot = 41UL
                                    Index = 0UL
                                    BeaconBlockRoot = goRoot 1
                                    Source = { Epoch = 4UL; Root = goRoot 4 }
                                    Target = { Epoch = 5UL; Root = goRoot 5 }
                                })

                        check
                            "block"
                            (Duty.Block
                                {
                                    Slot = 40UL
                                    ProposerIndex = 7UL
                                    ParentRoot = goRoot 1
                                    StateRoot = goRoot 2
                                    BodyRoot = goRoot 3
                                })

                        check "exit" (Duty.VoluntaryExit { Epoch = 5UL; ValidatorIndex = 9UL })
                        check "selection" (Duty.AggregationSlot 41UL)
                        check "syncmsg" (Duty.SyncCommitteeMessage(41UL, goRoot 9))
                        check "syncsel" (Duty.SyncSelectionProof { Slot = 41UL; SubcommitteeIndex = 1UL })
                        // RANDAO goes as a root message; Eplix puts hash_tree_root(epoch) as the object
                        // root, which the runner requires. The layout around it is the Go one.
                        let randao = Wire.encodeSign (r (Duty.RandaoReveal 5UL))
                        let goRandao = go "sign_randao"
                        Expect.equal randao[0..57] goRandao[0..57] "key, kind 5, type 1, epoch 5"
                        Expect.equal randao[58..89] (Codec.hashEpoch 5UL).Bytes "object root = hash_tree_root(epoch)"
                        Expect.equal randao[90..] goRandao[90..] "domain"
                        // Aggregates and contributions: key, kind, domain (and form 1 for Electra) as Go
                        // writes them, then the SSZ of the message.
                        let p = Preset.FromSpec(Map.ofList (Eplix.Tests.FakeBeaconNode.specValues 6 8))

                        let aggObj =
                            {
                                Schema = Schemas.aggregateAndProof p
                                Value = Ssz.zero (Schemas.aggregateAndProof p)
                            }

                        let agg = Wire.encodeSign (r (Duty.AggregateAndProof(0UL, aggObj)))
                        let goAgg = go "sign_aggregate"
                        Expect.equal agg[0..81] goAgg[0..81] "key, kind 9, domain, form 1"
                        Expect.equal agg[82..] (Ssz.serialize aggObj.Schema aggObj.Value) "AggregateAndProof SSZ"

                        let conObj =
                            {
                                Schema = Schemas.contributionAndProof p
                                Value = Ssz.zero (Schemas.contributionAndProof p)
                            }

                        let con = Wire.encodeSign (r (Duty.ContributionAndProof(0UL, conObj)))
                        let goCon = go "sign_contribution"
                        Expect.equal con[0..80] goCon[0..80] "key, kind 10, domain"
                        Expect.equal con[81..] (Ssz.serialize conObj.Schema conObj.Value) "ContributionAndProof SSZ"
                    }

                    test "the Gloas kinds and kind 14 match the runner's encoder" {
                        let k, d = goKey.Value, goDomain.Value

                        Expect.equal
                            (Wire.Gloas.sign
                                k
                                Wire.Kind.PayloadAttestation
                                d
                                (Wire.Gloas.payloadAttestation (goRoot 7) 99UL true false))
                            (go "sign_ptc")
                            "kind 6"

                        let fee = Array.append [| 1uy; 2uy; 3uy |] (Array.zeroCreate 17)

                        Expect.equal
                            (Wire.Gloas.sign
                                k
                                Wire.Kind.ProposerPreferences
                                d
                                (Wire.Gloas.proposerPreferences (goRoot 8) 100UL 12UL fee 36_000_000UL))
                            (go "sign_prefs")
                            "kind 8"

                        Expect.equal
                            (Wire.Gloas.sign
                                k
                                Wire.Kind.BuilderRequestAuth
                                d
                                (Wire.Gloas.builderRequestAuth (Text.Encoding.ASCII.GetBytes "builder.example") 77UL))
                            (go "sign_builderauth")
                            "kind 14"
                    }

                    test "a validator registration goes as kind 4: the 84-byte ValidatorRegistrationV1 SSZ" {
                        let k = goKey.Value
                        let fee = Array.append [| 1uy; 2uy; 3uy |] (Array.zeroCreate 17)

                        let reg: ValidatorRegistration =
                            {
                                FeeRecipient = fee
                                GasLimit = 36_000_000UL
                                Timestamp = 1_700_000_123UL
                                PubKey = k
                            }

                        let req = signReq (Duty.ValidatorRegistration reg)
                        let b = Wire.encodeSign req
                        Expect.equal b.Length (48 + 1 + 32 + 84) "key, kind, domain, message"
                        Expect.equal b[0..48] (Array.append k.Bytes [| 4uy |]) "key and kind 4"
                        Expect.equal b[49..80] req.Domain.Bytes "the builder domain the VC computed"
                        let le (v: uint64) = BitConverter.GetBytes v

                        Expect.equal
                            b[81..]
                            (Array.concat [ fee; le 36_000_000UL; le 1_700_000_123UL; k.Bytes ])
                            "fee recipient, gas limit, timestamp, pubkey"
                    }

                    test "Gloas duties go as kinds 6, 7, 8 and 14; Gloas aggregates as form 2" {
                        let r = signReq
                        let p = Preset.FromSpec(Map.ofList (Eplix.Tests.FakeBeaconNode.specValues 6 8))
                        let k, d = goKey.Value, goDomain.Value
                        let fee = Array.append [| 1uy; 2uy; 3uy |] (Array.zeroCreate 17)

                        Expect.equal
                            (Wire.encodeSign (
                                r (
                                    Duty.PayloadAttestation
                                        {
                                            BeaconBlockRoot = goRoot 7
                                            Slot = 99UL
                                            PayloadPresent = true
                                            BlobDataAvailable = false
                                        }
                                )
                            ))
                            (go "sign_ptc")
                            "PTC vote: kind 6"

                        Expect.equal
                            (Wire.encodeSign (
                                r (
                                    Duty.ProposerPreferences
                                        {
                                            DependentRoot = goRoot 8
                                            ProposalSlot = 100UL
                                            ValidatorIndex = 12UL
                                            FeeRecipient = fee
                                            TargetGasLimit = 36_000_000UL
                                        }
                                )
                            ))
                            (go "sign_prefs")
                            "proposer preferences: kind 8"

                        Expect.equal
                            (Wire.encodeSign (
                                r (
                                    Duty.BuilderRequestAuth
                                        {
                                            AuthData = Text.Encoding.ASCII.GetBytes "builder.example"
                                            AuthSlot = 77UL
                                        }
                                )
                            ))
                            (go "sign_builderauth")
                            "builder request auth: kind 14"
                        // Kind 7: the 532-byte summary. Fixed fields as SSZ, variable ones as their roots.
                        let schema = Schemas.Gloas.executionPayloadEnvelope p

                        let env =
                            match Ssz.zero schema with
                            | Ssz.Fields f ->
                                let pay = Codec.fields f[0]
                                pay[1] <- Ssz.Bytes fee
                                pay[10] <- Ssz.Bytes [| 1uy; 2uy; 3uy |]
                                pay[13] <- Ssz.Items [| Ssz.Bytes [| 0xdeuy |] |]
                                pay[18] <- Ssz.U 17UL
                                f[2] <- Ssz.U UInt64.MaxValue
                                f[3] <- Ssz.Bytes (goRoot 3).Bytes
                                Ssz.Fields f
                            | v -> v

                        let b = Wire.encodeSign (r (Duty.PayloadEnvelope(17UL, { Schema = schema; Value = env })))

                        Expect.equal
                            b[0..80]
                            (Array.concat [ k.Bytes; [| Wire.Kind.PayloadEnvelope |]; d.Bytes ])
                            "key, kind 7, domain"

                        let m = b[81..]
                        Expect.equal m.Length 532 "532 bytes"
                        Expect.equal m[32..51] fee "fee recipient at 32"

                        let pf =
                            match schema with
                            | Ssz.ProgressiveContainer ef ->
                                match snd ef[0] with
                                | Ssz.ProgressiveContainer pf -> pf
                                | _ -> [||]
                            | _ -> [||]

                        let pv = Codec.fields (Codec.fields env).[0]
                        Expect.equal m[116..147] (Ssz.hashTreeRoot (snd pf[4]) pv[4]) "logs bloom root at 116"
                        Expect.equal m[212..243] (Ssz.hashTreeRoot (snd pf[10]) pv[10]) "extra data root at 212"
                        Expect.equal m[308..339] (Ssz.hashTreeRoot (snd pf[13]) pv[13]) "transactions root at 308"
                        Expect.equal m[420..427] (BitConverter.GetBytes 17UL) "slot_number at 420"
                        Expect.equal m[460..467] (Array.create 8 0xffuy) "self-build builder index at 460"
                        Expect.equal m[468..499] (goRoot 3).Bytes "beacon block root at 468"

                        Expect.throwsT<Wire.WireError>
                            (fun () ->
                                Wire.encodeSign (
                                    r (
                                        Duty.PayloadEnvelope(
                                            17UL,
                                            {
                                                Schema = Schemas.beaconBlockHeader
                                                Value = Ssz.zero Schemas.beaconBlockHeader
                                            }
                                        )
                                    )
                                )
                                |> ignore)
                            "a value that is not an envelope"

                        let form (schema: Ssz.SszType) =
                            (Wire.encodeSign (
                                r (
                                    Duty.AggregateAndProof(
                                        0UL,
                                        {
                                            Schema = schema
                                            Value = Ssz.zero schema
                                        }
                                    )
                                )
                            ))[81]

                        Expect.equal (form (Schemas.aggregateAndProof p)) Wire.AggregateElectra "Electra form"
                        Expect.equal (form (Schemas.Gloas.aggregateAndProof p)) Wire.AggregateGloas "Gloas form"
                    }

                    test "key list and error answers" {
                        let keys = Wire.decodeKeys (go "keys")
                        Expect.equal keys.Length 2 "two keys"
                        Expect.equal keys[0].SharePubKey keys[0].PubKey "a whole key lists itself as the share"
                        Expect.equal keys[0].Index Wire.IndexUnknown "unbound"
                        Expect.equal keys[1].Index 5UL "bound to index 5"
                        Expect.equal (Wire.encodeKeys keys) (go "keys") "round trip"

                        match Wire.decodeResponse (go "error_slash_target") with
                        | Error r ->
                            Expect.equal r.Code Wire.Status.SlashTarget "SC_ERR_SLASH_TARGET"

                            Expect.isTrue
                                (match Mapping.toOutcome "r" (Duty.Attestation att) r with
                                 | Refused(Slashable _) -> true
                                 | _ -> false)
                                "a slashing code halts, whatever its detail says"
                        | Ok _ -> failtest "an error answer"

                        match Wire.decodeResponse (go "error_policy_exit") with
                        | Error r ->
                            match
                                Mapping.toOutcome "r" (Duty.VoluntaryExit { Epoch = 1UL; ValidatorIndex = 9UL }) r
                            with
                            | Refused(PolicyDenied m) -> Expect.stringContains m "SC_ERR_POLICY_EXIT" "named"
                            | o -> failtestf "policy exit: %s" o.Describe
                        | Ok _ -> failtest "an error answer"
                    }

                    test "tee-signer IDENTITY v1: request, answer, user data and MAA runtime data byte for byte" {
                        let v = teeSignerV1.Value
                        let hex (n: string) = Convert.FromHexString v[n]
                        Expect.equal v["context"] Wire.IdentityContext "context signer-runner-identity-v1"
                        Expect.equal Wire.IdentityVersion 1uy "version 1"
                        Expect.equal (Wire.encodeIdentityRequest (hex "nonce")) (hex "request") "nonce_len nonce 1"
                        let b = hex "identity"
                        let id = Wire.decodeIdentity b

                        Expect.equal
                            (Wire.identityUserData (hex "nonce") id)
                            (hex "user_data")
                            "user data as the runner binds it"

                        Expect.equal id.Attestation.UserData (hex "user_data") "carried"
                        Expect.equal id.State.KeyOrigin.Imported 39u "imported keys"
                        Expect.equal id.State.Order.Kind 1uy "order kind 1"
                        Expect.equal id.State.Locked.Pending.Version 3UL "pending locked update"
                        Expect.equal (Wire.encodeIdentity id) b "round trip"

                        Expect.equal
                            (Text.Encoding.ASCII.GetString(Wire.maaRuntimeData (hex "user_data")))
                            v["maa_runtime"]
                            "MAA runtime data"
                        // A version 3 answer is refused, and a runner refuses a version 3 request.
                        let v3 = Array.copy b
                        v3[0] <- 3uy

                        Expect.throwsT<Wire.WireError>
                            (fun () -> Wire.decodeIdentity v3 |> ignore)
                            "an IDENTITY v3 answer is refused"

                        Expect.stringContains
                            v["v3_refusal"]
                            "this runner answers version 1"
                            "what a tee-signer runner says to a v3 request"
                        // Offsets after the version byte: setup_hash 32, two groups of 88, approvers 32,
                        // order 41, key_release 32, then reserved[4] imported:u32 reserved[32].
                        let reserved = 1 + 32 + 2 * 88 + 32 + 41 + 32

                        for at in [ reserved; reserved + 3; reserved + 8; reserved + 39 ] do
                            let bad = Array.copy b
                            bad[at] <- 1uy

                            Expect.throwsT<Wire.WireError>
                                (fun () -> Wire.decodeIdentity bad |> ignore)
                                $"reserved byte at {at} not zero"

                        let kind2 = Array.copy b
                        kind2[1 + 32 + 2 * 88 + 32] <- 2uy

                        Expect.throwsT<Wire.WireError>
                            (fun () -> Wire.decodeIdentity kind2 |> ignore)
                            "order kind 2 is refused, as backend.ParseSetupState does"

                        Expect.throwsT<Wire.WireError>
                            (fun () -> Wire.decodeIdentity b[.. b.Length - 2] |> ignore)
                            "a truncated answer is refused"
                    }

                    test "a pending update at or below the active version is refused" {
                        let b = Convert.FromHexString teeSignerV1.Value["identity"]
                        let bad = Array.copy b
                        // After the version byte and setup_hash: locked version (8), hash (32), pending version.
                        let active = Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(ReadOnlySpan(b, 1 + 32, 8))
                        Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bad.AsSpan(1 + 32 + 8 + 32, 8), active)

                        Expect.throwsT<Wire.WireError> (fun () -> Wire.decodeIdentity bad |> ignore) "refused"
                    }
                ]

            testList
                "mapping"
                [
                    test "every status code maps to its refusal" {
                        let a = Duty.Attestation att
                        let o c = Mapping.toOutcome "r" a (refusal c "detail")

                        let isSlashable c =
                            match o c with
                            | Refused(Slashable _) -> true
                            | _ -> false

                        for c in [ 9us; 10us; 11us; 12us; 24us ] do
                            Expect.isTrue (isSlashable c) $"{Wire.Status.name c} is a slashing refusal"

                        for c in [ 13us .. 19us ] @ [ 21us; 22us; 23us; 25us; 26us; 27us; 1006us; 1007us ] do
                            Expect.isTrue
                                (match o c with
                                 | Refused(PolicyDenied _) -> true
                                 | _ -> false)
                                $"{Wire.Status.name c} skips"

                        for c in [ 20us; 1003us ] do
                            Expect.equal (o c) (Refused DomainMismatch) $"{Wire.Status.name c}"

                        Expect.equal (o 6us) (Refused UnknownKey) "unknown validator"
                        Expect.equal (o 1001us) (Refused(Unsupported DutyKind.Attestation)) "unsupported"
                        Expect.equal (o 1004us) (Refused(Refusal.NotReadyUntil ValueNone)) "not ready"
                        Expect.equal (o 8us) (Refused(Refusal.NotReadyUntil ValueNone)) "no trusted clock"

                        for c in [ 1us; 3us; 4us; 5us; 1000us ] do
                            Expect.isTrue
                                (match o c with
                                 | Refused(BadRequest _) -> true
                                 | _ -> false)
                                $"{Wire.Status.name c} is a bug"

                        for c in [ 2us; 7us; 1002us; 1005us; 999us ] do
                            Expect.isTrue
                                (match o c with
                                 | Failed(Internal _) -> true
                                 | _ -> false)
                                $"{Wire.Status.name c} is a failure"

                        Expect.equal
                            (Mapping.toOutcome
                                "r"
                                (Duty.Block
                                    {
                                        Slot = 9UL
                                        ProposerIndex = 1UL
                                        ParentRoot = root 1
                                        StateRoot = root 2
                                        BodyRoot = root 3
                                    })
                                (refusal Wire.Status.Floor "floor epoch 3 (restart floor): block slot 9 at or below 9"))
                            (Refused(Refusal.NotReadyUntil(ValueSome 4UL)))
                            "a block at the restart floor"
                    }

                    test "tee-signer refusals: a source refusal halts whatever its detail; code 28 skips" {
                        let a = Duty.Attestation att

                        for d in
                            [
                                "attestation source 5 below 7"
                                "attestation source 5 below the source floor epoch 12: no import carried this validator's vote history"
                            ] do
                            Expect.isTrue
                                (match Mapping.toOutcome "r" a (refusal Wire.Status.SlashSource d) with
                                 | Refused(Slashable _) -> true
                                 | _ -> false)
                                d

                        Expect.equal (Wire.Status.name 28us) "SC_ERR_POLICY_TARGET_SLOT" "code 28 named"

                        Expect.isTrue
                            (match
                                Mapping.toOutcome "r" a (refusal 28us "target epoch 3 is not the epoch of slot 200")
                             with
                             | Refused(PolicyDenied _) -> true
                             | _ -> false)
                            "code 28 skips"
                    }

                    test
                        "a slashing code always halts: a floor text in its detail changes nothing; other codes map by code" {
                        let a = Duty.Attestation att
                        let o code detail = Mapping.toOutcome "r" a (refusal code detail)

                        let halts code detail =
                            match o code detail with
                            | Refused(Slashable _) -> true
                            | _ -> false

                        let import =
                            "attestation source 487600 at or below 487600 (at or below import floor epoch 487617)"

                        let restart = "target 10 at or below 10 (at or below restart floor epoch 12)"

                        for c in [ 9us; 10us; 11us; 12us; 24us ] do
                            Expect.isTrue (halts c import) $"{Wire.Status.name c}: import floor text"
                            Expect.isTrue (halts c restart) $"{Wire.Status.name c}: restart floor text"

                            Expect.equal
                                (Mapping.floorOf (refusal c import))
                                ValueNone
                                $"{Wire.Status.name c}: no floor"

                        Expect.isTrue
                            (match o 13us import with
                             | Refused(PolicyDenied _) -> true
                             | _ -> false)
                            "policy code"

                        Expect.equal (o 1004us import) (Refused(Refusal.NotReadyUntil ValueNone)) "NOT_READY"

                        Expect.isTrue
                            (match o 7us import with
                             | Failed(Internal _) -> true
                             | _ -> false)
                            "storage"

                        Expect.isTrue
                            (match o 1000us import with
                             | Refused(BadRequest _) -> true
                             | _ -> false)
                            "bad request"
                    }

                    test "tee-signer FLOOR (1008): waits until epoch N + 1, or with no epoch; never halts" {
                        let a = Duty.Attestation att
                        let o code detail = Mapping.toOutcome "r" a (refusal code detail)
                        Expect.equal (Wire.Status.name 1008us) "FLOOR" "named"

                        for w in [ "restart"; "import"; "source" ] do
                            Expect.equal
                                (o Wire.Status.Floor $"floor epoch 12 ({w} floor): target 10 at or below 10")
                                (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                $"{w} floor"

                        Expect.equal
                            (Mapping.floorOf (refusal Wire.Status.Floor "floor epoch 487617 (import floor): x"))
                            (ValueSome(struct ("import", 487617UL)))
                            "floorOf reads the prefix"

                        Expect.equal
                            (o Wire.Status.Floor "floor epoch 18446744073709551614 (restart floor): x")
                            (Refused(Refusal.NotReadyUntil(ValueSome UInt64.MaxValue)))
                            "the largest floor with an epoch after it"
                        // A detail that does not parse still waits, with no epoch: never Slashable, never a failure.
                        for d in
                            [
                                ""
                                "floor epoch"
                                "floor epoch x (restart floor): y"
                                "floor epoch -1 (restart floor): y"
                                "floor epoch ١٢ (restart floor): y"
                                "floor epoch 18446744073709551615 (restart floor): y"
                                "floor epoch 99999999999999999999999 (restart floor): y"
                                "Floor epoch 12 (restart floor): y"
                                "x floor epoch 12 (restart floor): y"
                                "floor epoch 12 (other floor): y"
                            ] do
                            Expect.equal
                                (o Wire.Status.Floor d)
                                (Refused(Refusal.NotReadyUntil ValueNone))
                                $"no epoch: {d}"
                    }

                    test "tee-signer FLOOR_UNPROVEN (1009): waits like FLOOR" {
                        let a = Duty.Attestation att
                        let o code detail = Mapping.toOutcome "r" a (refusal code detail)
                        Expect.equal (Wire.Status.name 1009us) "FLOOR_UNPROVEN" "named"

                        for w in [ "restart"; "import"; "source" ] do
                            Expect.equal
                                (o Wire.Status.FloorUnproven $"floor epoch 12 ({w} floor): target 10 at or below 10")
                                (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                $"{w} floor"

                        Expect.equal
                            (Mapping.floorOf (refusal Wire.Status.FloorUnproven "floor epoch 40 (restart floor): x"))
                            (ValueSome(struct ("restart", 40UL)))
                            "floorOf reads the prefix"

                        for d in
                            [
                                ""
                                "floor epoch x (restart floor): y"
                                "floor epoch 18446744073709551615 (restart floor): y"
                                "floor epoch ١٢ (restart floor): y"
                                "target 10 at or below 10 (at or below restart floor epoch 12)"
                            ] do
                            Expect.equal
                                (o Wire.Status.FloorUnproven d)
                                (Refused(Refusal.NotReadyUntil ValueNone))
                                $"no epoch: {d}"
                    }

                    test "Gloas refusals: no kind on an older runner is Unsupported; fork, builder and equivocation" {
                        let auth = Duty.BuilderRequestAuth { AuthData = [| 1uy |]; AuthSlot = 9UL }

                        let ptc =
                            Duty.PayloadAttestation
                                {
                                    BeaconBlockRoot = root 1
                                    Slot = 9UL
                                    PayloadPresent = true
                                    BlobDataAvailable = true
                                }

                        Expect.equal
                            (Mapping.toOutcome "r" auth (refusal 1000us "no SSZ encoding for kind 14"))
                            (Refused(Unsupported DutyKind.BuilderRequestAuth))
                            "a runner from before kind 14"

                        Expect.isTrue
                            (match Mapping.toOutcome "r" auth (refusal 1000us "kind 14: want offset 12") with
                             | Refused(BadRequest _) -> true
                             | _ -> false)
                            "another BAD_REQUEST stays a bug"

                        for c in [ 21us; 22us; 23us; 27us ] do
                            Expect.isTrue
                                (match Mapping.toOutcome "r" ptc (refusal c "") with
                                 | Refused(PolicyDenied _) -> true
                                 | _ -> false)
                                $"{Wire.Status.name c} skips"

                        Expect.isTrue
                            (match Mapping.toOutcome "r" ptc (refusal 24us "") with
                             | Refused(Slashable _) -> true
                             | _ -> false)
                            "equivocation"

                        let cls duty prio = Mapping.classOf { signReq duty with Priority = prio }
                        Expect.equal (cls ptc Priority.Low) PoolClass.High "PTC votes go first"
                        Expect.equal (cls auth Priority.Low) PoolClass.Low "auth an epoch ahead"
                        Expect.equal (cls auth Priority.High) PoolClass.High "auth a proposal waits for"
                    }
                ]

            testList
                "pool"
                [
                    testT
                        "a free connection goes to high requests first, and to low ones every lowEvery-th time"
                        (fun () ->
                            task {
                                let conns = ConcurrentQueue<FakeConn>()

                                let dial (_: CancellationToken) =
                                    let c = FakeConn(conns.Count)
                                    conns.Enqueue c
                                    Task.FromResult c

                                let pool =
                                    new ConnectionPool<FakeConn>("p", 1, 3, TimeSpan.FromSeconds 5.0, dial, Log.none)

                                pool.Start()
                                let! first = pool.Take(PoolClass.High, CancellationToken.None)

                                let held =
                                    match first with
                                    | Ok c -> c
                                    | Error e -> failtest e

                                let order = ConcurrentQueue<string>()

                                let waiter (label: string) cls =
                                    task {
                                        match! pool.Take(cls, CancellationToken.None) with
                                        | Ok c ->
                                            order.Enqueue label
                                            pool.Done c
                                        | Error e -> failtest e
                                    }

                                let ws = ResizeArray<Task>()

                                for i in 1..3 do
                                    ws.Add(waiter $"low{i}" PoolClass.Low)

                                for i in 1..5 do
                                    ws.Add(waiter $"high{i}" PoolClass.High)

                                waitFor (fun () -> let struct (_, _, _, h, l) = pool.Snapshot in h = 5 && l = 3)
                                pool.Done held
                                do! Task.WhenAll ws
                                // lowEvery 3: at most two high in a row while a low request waits.
                                Expect.equal
                                    (List.ofSeq order)
                                    [ "high1"; "high2"; "low1"; "high3"; "high4"; "low2"; "high5"; "low3" ]
                                    "order"

                                pool.Close()
                            })

                    testT
                        "FirstUp fires before a waiting request gets the first connection, and not for the second"
                        (fun () ->
                            task {
                                let gates = ConcurrentQueue<TaskCompletionSource<FakeConn>>()

                                let dial (_: CancellationToken) =
                                    let g = TaskCompletionSource<FakeConn>()
                                    gates.Enqueue g
                                    g.Task

                                let pool =
                                    new ConnectionPool<FakeConn>("p", 2, 3, TimeSpan.FromSeconds 5.0, dial, Log.none)

                                let mutable got = false
                                let seen = ConcurrentQueue<bool>()
                                pool.FirstUp.Add(fun () -> seen.Enqueue(Volatile.Read &got))
                                pool.Start()

                                let waiter =
                                    task {
                                        match! pool.Take(PoolClass.High, CancellationToken.None) with
                                        | Ok c ->
                                            Volatile.Write(&got, true)
                                            return c
                                        | Error e -> return failtest e
                                    }

                                waitFor (fun () -> gates.Count = 2)
                                let all = Array.ofSeq gates
                                all[0].SetResult(FakeConn 0)
                                let! c = waiter
                                Expect.equal (List.ofSeq seen) [ false ] "once, before the waiter had the connection"
                                all[1].SetResult(FakeConn 1)
                                waitFor (fun () -> let struct (up, _, _, _, _) = pool.Snapshot in up = 2)
                                Expect.equal seen.Count 1 "not for a connection while another is up"
                                pool.Done c
                                pool.Close()
                            })

                    testT "without priority requests go first come first served" (fun () ->
                        task {
                            let pool =
                                new ConnectionPool<FakeConn>(
                                    "p",
                                    1,
                                    0,
                                    TimeSpan.FromSeconds 5.0,
                                    (fun _ -> Task.FromResult(FakeConn 0)),
                                    Log.none
                                )

                            pool.Start()
                            let! first = pool.Take(PoolClass.High, CancellationToken.None)

                            let held =
                                match first with
                                | Ok c -> c
                                | Error e -> failtest e

                            let order = ConcurrentQueue<string>()

                            let ws =
                                [
                                    for label, cls in [ "a", PoolClass.Low; "b", PoolClass.High; "c", PoolClass.Low ] ->
                                        task {
                                            match! pool.Take(cls, CancellationToken.None) with
                                            | Ok c ->
                                                order.Enqueue label
                                                pool.Done c
                                            | Error e -> failtest e
                                        }
                                        :> Task
                                ]

                            waitFor (fun () -> let struct (_, _, _, h, _) = pool.Snapshot in h = 3)
                            pool.Done held
                            do! Task.WhenAll ws
                            Expect.equal (List.ofSeq order) [ "a"; "b"; "c" ] "first come first served"
                            pool.Close()
                        })

                    testT
                        "a failed dial with nothing up fails the waiting requests; the pool dials again after a backoff"
                        (fun () ->
                            task {
                                let attempts = ref 0

                                let dial (_: CancellationToken) : Task<FakeConn> =
                                    task {
                                        let n = Interlocked.Increment &attempts.contents

                                        if n <= 1 then
                                            return raise (IOException "connection refused")
                                        else
                                            return FakeConn n
                                    }

                                let pool =
                                    new ConnectionPool<FakeConn>("p", 1, 8, TimeSpan.FromSeconds 5.0, dial, Log.none)

                                pool.Start()
                                let! r = pool.Take(PoolClass.High, CancellationToken.None)

                                match r with
                                | Error e -> Expect.stringContains e "connection refused" "the dial's error"
                                | Ok c ->
                                    // The first dial may have failed before the request queued; the retry then
                                    // already served it after its 1 s backoff.
                                    Expect.isGreaterThanOrEqual attempts.Value 2 "a second dial"
                                    pool.Done c

                                let sw = Diagnostics.Stopwatch.StartNew()
                                let! again = pool.Take(PoolClass.High, CancellationToken.None)

                                Expect.isTrue
                                    (match again with
                                     | Ok _ -> true
                                     | _ -> false)
                                    "the redial after the backoff serves the next request"

                                Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 3.0) "1 s backoff"
                                pool.Close()
                            })

                    testT "a request that gives up waiting is never served" (fun () ->
                        task {
                            let pool =
                                new ConnectionPool<FakeConn>(
                                    "p",
                                    1,
                                    8,
                                    TimeSpan.FromSeconds 5.0,
                                    (fun _ -> Task.FromResult(FakeConn 0)),
                                    Log.none
                                )

                            pool.Start()
                            let! first = pool.Take(PoolClass.High, CancellationToken.None)

                            let held =
                                match first with
                                | Ok c -> c
                                | Error e -> failtest e

                            use cts = new CancellationTokenSource(TimeSpan.FromMilliseconds 50.0)
                            let! r = pool.Take(PoolClass.Low, cts.Token)

                            Expect.isTrue
                                (match r with
                                 | Error e -> e.Contains "timed out"
                                 | _ -> false)
                                "timed out"

                            let struct (_, _, _, h, l) = pool.Snapshot
                            Expect.equal (h + l) 0 "left the queue"
                            pool.Done held
                            let struct (_, idle, _, _, _) = pool.Snapshot
                            Expect.equal idle 1 "the connection is idle again"
                            pool.Close()
                        })

                    testT "a backward step of the wall clock does not stretch the dial backoff" (fun () ->
                        task {
                            let fake =
                                Microsoft.Extensions.Time.Testing.FakeTimeProvider(
                                    DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero)
                                )

                            let clock = SteppedClock(fake)
                            let attempts = ref 0

                            let dial (_: CancellationToken) =
                                if Interlocked.Increment &attempts.contents = 1 then
                                    Task.FromException<FakeConn>(IOException "the runner is down")
                                else
                                    Task.FromResult(FakeConn 0)

                            let pool =
                                new ConnectionPool<FakeConn>(
                                    "p",
                                    1,
                                    0,
                                    TimeSpan.FromSeconds 5.0,
                                    dial,
                                    Log.none,
                                    clock
                                )

                            pool.Start()
                            waitFor (fun () -> pool.LastError <> "")
                            // An NTP correction or a VM resume sets the wall clock ten minutes back.
                            clock.Back <- TimeSpan.FromMinutes 10.0
                            fake.Advance(TimeSpan.FromSeconds 1.0)
                            waitFor (fun () -> let struct (up, _, _, _, _) = pool.Snapshot in up = 1)
                            Expect.equal attempts.Value 2 "dialed again after the 1 s backoff"
                            pool.Close()
                        })

                    testT "a late connection comes back when its reply is read, and is closed without one" (fun () ->
                        task {
                            let made = ConcurrentQueue<FakeConn>()

                            let dial (_: CancellationToken) =
                                let c = FakeConn made.Count
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<FakeConn>(
                                    "p",
                                    1,
                                    8,
                                    TimeSpan.FromMilliseconds 300.0,
                                    dial,
                                    Log.none
                                )

                            pool.Start()
                            let! a = pool.Take(PoolClass.High, CancellationToken.None)

                            let c1 =
                                match a with
                                | Ok c -> c
                                | Error e -> failtest e

                            c1.SetState ConnState.Late
                            pool.Done c1
                            let struct (_, idle, _, _, _) = pool.Snapshot
                            Expect.equal idle 0 "a late connection is not handed out"
                            c1.FinishDrain true
                            waitFor (fun () -> let struct (_, idle, _, _, _) = pool.Snapshot in idle = 1)
                            let! b = pool.Take(PoolClass.High, CancellationToken.None)

                            let c2 =
                                match b with
                                | Ok c -> c
                                | Error e -> failtest e

                            Expect.equal c2.Id c1.Id "the same connection"
                            // This time no reply comes: closed after the cap (300 ms), and a new one is dialed.
                            c2.SetState ConnState.Late
                            pool.Done c2
                            Thread.Sleep 100
                            Expect.isFalse c2.IsClosed "still waiting for the reply"
                            waitFor (fun () -> c2.IsClosed)
                            waitFor (fun () -> made.Count = 2)
                            // A broken connection is closed at once.
                            let! c = pool.Take(PoolClass.High, CancellationToken.None)

                            let c3 =
                                match c with
                                | Ok c -> c
                                | Error e -> failtest e

                            c3.SetState ConnState.Broken
                            pool.Done c3
                            waitFor (fun () -> c3.IsClosed)
                            pool.Close()
                        })

                    testT "a connection that breaks while idle leaves the pool and is dialed again" (fun () ->
                        task {
                            let made = ConcurrentQueue<NoticeConn>()
                            let ids = ref -1
                            // Two dials run at once: ids from a counter, not from made.Count.
                            let dial (_: CancellationToken) =
                                let c = NoticeConn(Interlocked.Increment &ids.contents)
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<NoticeConn>("p", 2, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)

                            pool.Start()
                            waitFor (fun () -> let struct (up, idle, _, _, _) = pool.Snapshot in up = 2 && idle = 2)
                            let first = made.ToArray() |> Array.find (fun c -> c.Id = 0)
                            first.Break()
                            waitFor (fun () -> first.IsClosed)
                            waitFor (fun () -> made.Count = 3)
                            waitFor (fun () -> let struct (up, idle, _, _, _) = pool.Snapshot in up = 2 && idle = 2)
                            // Both requests get live connections.
                            let! a = pool.Take(PoolClass.High, CancellationToken.None)
                            let! b = pool.Take(PoolClass.High, CancellationToken.None)

                            for r in [ a; b ] do
                                match r with
                                | Ok c -> Expect.notEqual c.Id first.Id "not the broken connection"
                                | Error e -> failtest e

                            pool.Close()
                        })

                    testT "a broken idle connection that did not report is skipped when taken" (fun () ->
                        task {
                            let made = ConcurrentQueue<FakeConn>()

                            let dial (_: CancellationToken) =
                                let c = FakeConn made.Count
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<FakeConn>("p", 1, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)

                            pool.Start()
                            waitFor (fun () -> let struct (_, idle, _, _, _) = pool.Snapshot in idle = 1)
                            let first = made.ToArray()[0]
                            first.SetState ConnState.Broken
                            let! r = pool.Take(PoolClass.High, CancellationToken.None)

                            match r with
                            | Ok c -> Expect.equal c.Id 1 "a new connection"
                            | Error e -> failtest e

                            Expect.isTrue first.IsClosed "the broken one is closed"
                            pool.Close()
                        })

                    testT "a runner that drops each connection right after the dial is redialed with backoff" (fun () ->
                        task {
                            // Broken already at the handover, and broken 5 ms after it: both count as
                            // failed dials. Without that the pool redialed many thousand times a second.
                            // On a fake clock: the dials of each backoff step are counted exactly.
                            for delayMs in [ 0; 5 ] do
                                let dials = ref 0

                                let dial (_: CancellationToken) =
                                    let c = NoticeConn(Interlocked.Increment &dials.contents)

                                    if delayMs = 0 then
                                        c.Break()
                                    else
                                        // Real time: the fake clock stands still, so the connection is
                                        // still young when it breaks.
                                        let breakLater () : Task =
                                            task {
                                                do! Task.Delay delayMs
                                                c.Break()
                                            }

                                        Task.Run breakLater |> ignore

                                    Task.FromResult c

                                let time =
                                    Microsoft.Extensions.Time.Testing.FakeTimeProvider(
                                        DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero)
                                    )

                                let pool =
                                    new ConnectionPool<NoticeConn>(
                                        "p",
                                        2,
                                        0,
                                        TimeSpan.FromSeconds 5.0,
                                        dial,
                                        Log.none,
                                        time
                                    )
                                // Both connections of a step dialed and broken, the next timer set.
                                let settledAt (n: int) =
                                    waitFor (fun () ->
                                        let struct (up, _, dialing, _, _) = pool.Snapshot
                                        dials.Value = n && up = 0 && dialing = 0)

                                let quietFor (n: int) (span: TimeSpan) =
                                    time.Advance span
                                    Thread.Sleep 100

                                    Expect.equal
                                        dials.Value
                                        n
                                        $"no dial before the backoff ends (break after {delayMs} ms)"

                                pool.Start()
                                settledAt 2
                                // The backoff doubles per step: 1 s, 2 s, 4 s. Two connections that
                                // break in one window count as one failure.
                                let mutable expected = 2

                                for step in [ 1.0; 2.0; 4.0 ] do
                                    quietFor expected (TimeSpan.FromSeconds step - TimeSpan.FromMilliseconds 1.0)
                                    time.Advance(TimeSpan.FromMilliseconds 1.0)
                                    expected <- expected + 2
                                    settledAt expected

                                pool.Close()
                        })

                    testT "young connections that break together raise the backoff one step" (fun () ->
                        task {
                            let made = ConcurrentQueue<NoticeConn>()
                            let ids = ref -1

                            let dial (_: CancellationToken) =
                                let c = NoticeConn(Interlocked.Increment &ids.contents)
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<NoticeConn>("p", 4, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)

                            pool.Start()
                            waitFor (fun () -> let struct (up, idle, _, _, _) = pool.Snapshot in up = 4 && idle = 4)
                            // One runner restart breaks all four before any served a request.
                            let sw = Diagnostics.Stopwatch.StartNew()

                            for c in made.ToArray() do
                                c.Break()

                            waitFor (fun () -> made.Count = 8)

                            Expect.isLessThan
                                sw.Elapsed
                                (TimeSpan.FromSeconds 3.0)
                                "redialed after one 1 s step, not after 8 s"

                            pool.Close()
                        })

                    testT "a connection that served a request resets the backoff when it breaks later" (fun () ->
                        task {
                            let made = ConcurrentQueue<NoticeConn>()
                            let ids = ref -1

                            let dial (_: CancellationToken) =
                                let c = NoticeConn(Interlocked.Increment &ids.contents)
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<NoticeConn>("p", 1, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)

                            pool.Start()
                            let! r = pool.Take(PoolClass.High, CancellationToken.None)

                            let c =
                                match r with
                                | Ok c -> c
                                | Error e -> failtest e

                            pool.Done c
                            let sw = Diagnostics.Stopwatch.StartNew()
                            c.Break()
                            waitFor (fun () -> made.Count = 2)

                            Expect.isLessThan
                                sw.Elapsed
                                (TimeSpan.FromMilliseconds 800.0)
                                "redialed at once, no backoff"

                            pool.Close()
                        })

                    testT "a connection that breaks between Done and its return leaves the pool" (fun () ->
                        task {
                            let made = ConcurrentQueue<FlipConn>()
                            let ids = ref -1

                            let dial (_: CancellationToken) =
                                let c = FlipConn(Interlocked.Increment &ids.contents)
                                made.Enqueue c
                                Task.FromResult c

                            let pool =
                                new ConnectionPool<FlipConn>("p", 1, 0, TimeSpan.FromSeconds 5.0, dial, Log.none)

                            pool.Start()
                            let! r = pool.Take(PoolClass.High, CancellationToken.None)

                            let c =
                                match r with
                                | Ok c -> c
                                | Error e -> failtest e
                            // Done reads Ready, then the return to the pool reads Broken.
                            c.BreakAfterNextRead()
                            pool.Done c
                            Expect.isTrue c.IsClosed "the broken connection is closed"
                            // A pool of one must dial again; with the dead one still counted it never would.
                            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
                            let! r2 = pool.Take(PoolClass.High, cts.Token)

                            match r2 with
                            | Ok c2 -> Expect.notEqual c2.Id c.Id "a new connection"
                            | Error e -> failtest $"no new connection: {e}"

                            pool.Close()
                        })
                ]

            testList
                "backends"
                [
                    testT
                        "whole keys and 2 of 3 groups over fake runners: listed, signed, combined, verified"
                        (fun () ->
                            task {
                                let set, runners, groupKeys, whole = teeSet ()
                                let! found, answered = set.Discover CancellationToken.None
                                Expect.equal answered 3 "three runners"
                                let found = Map.ofList found

                                Expect.stringContains
                                    found[pk whole].Name
                                    "tee r1"
                                    "the whole key signs through r1 alone"

                                for secret, _ in groupKeys do
                                    Expect.stringContains found[pk secret].Name "tee 2 of 3" "a threshold key"

                                for key in pk whole :: [ for s, _ in groupKeys -> pk s ] do
                                    for duty in
                                        [ Duty.Attestation att; Duty.RandaoReveal 5UL; Duty.AggregationSlot 41UL ] do
                                        let req = request key duty
                                        expectAll runners req
                                        let! o = found[key].Sign req CancellationToken.None

                                        Expect.isTrue
                                            (verifies key req o)
                                            $"{found[key].Name}: {duty.Kind} verifies ({o.Describe})"
                            })

                    testT
                        "one runner down: the other two carry a threshold key; a bad signature from a whole-key runner fails"
                        (fun () ->
                            task {
                                let set, runners, groupKeys, whole = teeSet ()
                                let! found, _ = set.Discover CancellationToken.None
                                let found = Map.ofList found
                                runners[1].Behave(fun _ -> ValueSome(Reply.Failure(Transport "connection refused")))
                                let key = pk (fst groupKeys.Head)
                                let req = request key (Duty.Attestation att)
                                expectAll runners req
                                let! o = found[key].Sign req CancellationToken.None
                                Expect.isTrue (verifies key req o) $"2 of 3 with one down: {o.Describe}"

                                runners[0]
                                    .Behave(fun p ->
                                        if p[48] = Wire.Kind.Root then
                                            ValueSome(Reply.Body(Array.zeroCreate 96))
                                        else
                                            ValueNone)

                                let r2 = request (pk whole) (Duty.RandaoReveal 6UL)
                                let! bad = found[pk whole].Sign r2 CancellationToken.None

                                Expect.isTrue
                                    (match bad with
                                     | Failed(Internal m) -> m.Contains "does not verify"
                                     | _ -> false)
                                    $"bad signature: {bad.Describe}"
                            })

                    testT "a runner's slashing refusal halts the key; a restart floor refusal does not" (fun () ->
                        task {
                            let set, runners, _, whole = teeSet ()
                            let! found, _ = set.Discover CancellationToken.None
                            let backend = (Map.ofList found)[pk whole]
                            let key = pk whole
                            let h = Eplix.Tests.SchedulerTests.harness ()

                            use db =
                                match
                                    SlashingDb.Open(
                                        new FileMarkFile(Path.Combine(tempDir (), "s.db")),
                                        Eplix.Tests.FakeBeaconNode.gvr
                                    )
                                with
                                | Ok db -> db
                                | Error e -> failwith e

                            db.RegisterKeys [ key, KeyOrigin.StartedEmpty ] |> ignore
                            let registry = KeyRegistry()
                            registry.Add(key, backend) |> ignore
                            registry.SetState(key, KeyState.Active)
                            let pipeline = Pipeline(db, registry, h.Time, Log.none)

                            let vote target =
                                let d =
                                    { att with
                                        Source = { Epoch = target - 1UL; Root = root 4 }
                                        Target = { Epoch = target; Root = root 5 }
                                    }

                                Duty.request
                                    h.Spec
                                    Eplix.Tests.FakeBeaconNode.gvr
                                    key
                                    Priority.High
                                    (h.Time.GetUtcNow().AddSeconds 10.0)
                                    (Duty.Attestation d)
                            // The floor first: a FLOOR answer leaves the key active.
                            runners[0]
                                .Behave(fun p ->
                                    if p[48] = Wire.Kind.Attestation then
                                        ValueSome(
                                            Reply.Refused(
                                                refusal
                                                    Wire.Status.Floor
                                                    "floor epoch 12 (restart floor): target 10 at or below 10"
                                            )
                                        )
                                    else
                                        ValueNone)

                            let! o1 = pipeline.Sign(vote 10UL, CancellationToken.None)

                            Expect.equal
                                o1
                                (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                "not ready until the epoch after the floor"

                            Expect.equal (registry.TryGet key).Value.State KeyState.Active "the key stays active"
                            // A real slashing refusal: the VC's DB allowed the vote, the runner did not.
                            runners[0]
                                .Behave(fun p ->
                                    if p[48] = Wire.Kind.Attestation then
                                        ValueSome(
                                            Reply.Refused(refusal Wire.Status.SlashTarget "target 20 at or below 20")
                                        )
                                    else
                                        ValueNone)

                            let! o2 = pipeline.Sign(vote 20UL, CancellationToken.None)

                            Expect.isTrue
                                (match o2 with
                                 | Refused(Slashable m) -> m.Contains "SC_ERR_SLASH_TARGET"
                                 | _ -> false)
                                $"slashable: {o2.Describe}"

                            Expect.isTrue
                                (match (registry.TryGet key).Value.State with
                                 | KeyState.Halted _ -> true
                                 | _ -> false)
                                "the key is halted"
                            // A policy refusal on a halted key's non-slashable duty only skips it.
                            runners[0]
                                .Behave(fun _ ->
                                    ValueSome(Reply.Refused(refusal Wire.Status.PolicyFuture "too far ahead")))

                            let! o3 =
                                pipeline.Sign(
                                    Duty.request
                                        h.Spec
                                        Eplix.Tests.FakeBeaconNode.gvr
                                        key
                                        Priority.Low
                                        (h.Time.GetUtcNow().AddSeconds 10.0)
                                        (Duty.RandaoReveal 3UL),
                                    CancellationToken.None
                                )

                            Expect.isTrue
                                (match o3 with
                                 | Refused(PolicyDenied _) -> true
                                 | _ -> false)
                                $"policy: {o3.Describe}"
                        })

                    testT
                        "FLOOR_UNPROVEN: the group still signs; one operator alert per runner, key, floor kind and epoch"
                        (fun () ->
                            task {
                                // Every FLOOR_UNPROVEN answer is counted, by signer.
                                let counted = Collections.Concurrent.ConcurrentQueue<string>()
                                use listener = new Diagnostics.Metrics.MeterListener()

                                listener.InstrumentPublished <-
                                    fun i l ->
                                        if i.Meter.Name = Metrics.MeterName && i.Name = "eplix_tee_floor_unproven" then
                                            l.EnableMeasurementEvents i

                                listener.SetMeasurementEventCallback<int64>(fun _ _ tags _ ->
                                    for t in tags do
                                        if t.Key = "signer" then
                                            counted.Enqueue(string t.Value))

                                listener.Start()
                                let log, lines = Log.memory ()
                                let set, runners, groupKeys, _ = teeSetLog log
                                let! found, _ = set.Discover CancellationToken.None
                                let key = pk (fst groupKeys.Head)
                                let b = (Map.ofList found)[key]
                                let floor = ref 12UL
                                let kind = ref "restart"
                                let code = ref Wire.Status.FloorUnproven
                                let detail = ref ValueNone

                                runners[2]
                                    .Behave(fun p ->
                                        if p[48] = Wire.Kind.Attestation then
                                            let d =
                                                match detail.Value with
                                                | ValueSome d -> d
                                                | ValueNone ->
                                                    $"floor epoch {floor.Value} ({kind.Value} floor): target 10 at or below 10"

                                            ValueSome(Reply.Refused(refusal code.Value d))
                                        else
                                            ValueNone)

                                let signOnce () =
                                    task {
                                        let req = request key (Duty.Attestation att)
                                        expectAll runners req
                                        let! o = b.Sign req CancellationToken.None
                                        Expect.isTrue (verifies key req o) $"the other two sign: {o.Describe}"
                                    }

                                let alerts () =
                                    lines
                                    |> Seq.filter (fun l -> l.Contains "could not prove this key's history")
                                    |> List.ofSeq

                                for _ in 1..3 do
                                    do! signOnce ()

                                waitFor (fun () -> (alerts ()).Length >= 1)
                                Thread.Sleep 100
                                Expect.equal (alerts ()).Length 1 "one alert for three refusals"
                                let a = (alerts ()).Head
                                Expect.stringStarts a "WARN " "at Warn"
                                Expect.stringContains a "r3 refused the attestation" "the runner"
                                Expect.stringContains a key.Short "the key"
                                Expect.stringContains a "floor epoch 12" "the floor epoch"
                                // A new floor epoch alerts again; a plain FLOOR never alerts.
                                floor.Value <- 14UL
                                do! signOnce ()
                                waitFor (fun () -> (alerts ()).Length >= 2)
                                code.Value <- Wire.Status.Floor
                                floor.Value <- 16UL
                                do! signOnce ()
                                Thread.Sleep 100
                                Expect.equal (alerts ()).Length 2 "FLOOR does not alert"

                                Expect.isFalse
                                    (lines |> Seq.exists (fun l -> l.Contains "did not sign"))
                                    "no member failure line"
                                // A source floor and a restart floor at different epochs at once: one alert
                                // each, not one per refusal as the answers alternate.
                                code.Value <- Wire.Status.FloorUnproven

                                for round in 1..8 do
                                    if round % 2 = 0 then
                                        kind.Value <- "source"
                                        floor.Value <- 12UL
                                    else
                                        kind.Value <- "restart"
                                        floor.Value <- 20UL

                                    do! signOnce ()

                                waitFor (fun () -> (alerts ()).Length >= 4)
                                Thread.Sleep 100
                                Expect.equal (alerts ()).Length 4 "one alert per floor kind and epoch"
                                // A detail that gives no floor epoch: still a wait, one alert for the key.
                                detail.Value <- ValueSome "garbled"

                                for _ in 1..3 do
                                    do! signOnce ()

                                waitFor (fun () -> (alerts ()).Length >= 5)
                                Thread.Sleep 100
                                Expect.equal (alerts ()).Length 5 "one alert with no floor epoch"

                                Expect.stringContains
                                    (List.last (alerts ()))
                                    "gave no floor epoch (garbled)"
                                    "says there was no epoch"
                                // 3 + 1 + 8 + 3 FLOOR_UNPROVEN answers, every one counted.
                                waitFor (fun () -> (counted |> Seq.filter ((=) "r3") |> Seq.length) >= 15)
                                Thread.Sleep 100
                                Expect.equal (counted |> Seq.filter ((=) "r3") |> Seq.length) 15 "each answer counted"
                            })

                    test "a malformed refusal names its status" {
                        let p = [| 0x03uy; 0xF1uy; 0x00uy; 0x05uy |]

                        let message =
                            try
                                Wire.decodeResponse p |> ignore
                                ""
                            with :? Wire.WireError as e ->
                                e.Message

                        Expect.stringContains message "FLOOR_UNPROVEN" "1009"
                    }

                    testT "in a group, two slashing refusals answer Slashable; one is outvoted" (fun () ->
                        task {
                            let set, runners, groupKeys, _ = teeSet ()
                            let! found, _ = set.Discover CancellationToken.None
                            let key = pk (fst groupKeys.Head)
                            let b = (Map.ofList found)[key]

                            let slash =
                                fun (p: byte[]) ->
                                    if p[48] = Wire.Kind.Attestation then
                                        ValueSome(Reply.Refused(refusal Wire.Status.SlashSource "surround"))
                                    else
                                        ValueNone

                            runners[2].Behave slash
                            let req = request key (Duty.Attestation att)
                            expectAll runners req
                            let! one = b.Sign req CancellationToken.None
                            Expect.isTrue (verifies key req one) $"one refusal is outvoted: {one.Describe}"
                            runners[1].Behave slash
                            let! two = b.Sign req CancellationToken.None

                            Expect.isTrue
                                (match two with
                                 | Refused(Slashable _) -> true
                                 | _ -> false)
                                $"two of three: {two.Describe}"
                        })

                    testT
                        "an import or restart floor refusal skips the vote, the key stays active, and the vote after the floor signs"
                        (fun () ->
                            task {
                                for kind in [ "import"; "restart" ] do
                                    let log, lines = Log.memory ()
                                    let set, runners, _, whole = teeSetLog log
                                    let! found, _ = set.Discover CancellationToken.None
                                    let key = pk whole
                                    let backend = (Map.ofList found)[key]
                                    let pipeline, registry, db, vote = pipelineFor key backend
                                    use _db = db
                                    runners[0].Behave(floorRefusal kind 12UL)
                                    let! o1 = pipeline.Sign(vote 10UL, CancellationToken.None)

                                    Expect.equal
                                        o1
                                        (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                        $"{kind}: not ready until the epoch after the floor"

                                    Expect.equal
                                        (registry.TryGet key).Value.State
                                        KeyState.Active
                                        $"{kind}: the key stays active"

                                    let! o2 = pipeline.Sign(vote 11UL, CancellationToken.None)

                                    Expect.equal
                                        o2
                                        (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                        $"{kind}: the next vote at the floor waits too"

                                    Expect.equal
                                        (registry.TryGet key).Value.State
                                        KeyState.Active
                                        $"{kind}: still active"

                                    let warned =
                                        [
                                            for l in lines do
                                                if l.StartsWith "WARN" && l.Contains $"{kind} floor epoch 12" then
                                                    l
                                        ]

                                    Expect.equal
                                        warned.Length
                                        1
                                        $"{kind}: one warning per key per epoch: {List.ofSeq lines}"

                                    Expect.isFalse
                                        (lines |> Seq.exists (fun l -> l.StartsWith "ERROR"))
                                        $"{kind}: no error"
                                    // Past the floor the runner signs, and so does the key.
                                    runners[0].Behave(fun _ -> ValueNone)
                                    let req = vote 13UL
                                    expectAll runners req
                                    let! o3 = pipeline.Sign(req, CancellationToken.None)

                                    Expect.isTrue
                                        (verifies key req o3)
                                        $"{kind}: the vote after the floor signs ({o3.Describe})"
                            })

                    testT
                        "a group with members at their import floor skips the vote and keeps the key; a real slashing refusal still halts"
                        (fun () ->
                            task {
                                for m, n in [ 3, 4; 3, 5 ] do
                                    let secret, shares = shamir (970 + n) m [ 1UL .. uint64 n ]
                                    let key = pk secret

                                    let runners =
                                        [ for i in 0 .. n - 1 -> FakeRunner($"r{i + 1}", [ key, snd shares[i] ]) ]

                                    let settings =
                                        { teeSettings with
                                            Runners = [ for i in 1..n -> runnerCfg $"r{i}" ]
                                            Groups =
                                                [
                                                    {
                                                        Threshold = m
                                                        Members = [ for i in 1..n -> $"r{i}", uint64 i ]
                                                    }
                                                ]
                                        }
                                    // The group reads the deadline on the pipeline's clock.
                                    let h = Eplix.Tests.SchedulerTests.harness ()

                                    let set =
                                        TeeModule.TeeSet(
                                            [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                            settings,
                                            h.Time,
                                            Log.none
                                        )

                                    let! found, _ = set.Discover CancellationToken.None
                                    let backend = (Map.ofList found)[key]
                                    let pipeline, registry, db, vote = pipelineOn h key backend
                                    use _db = db
                                    // Two members at their import floor: 3 of 5 still sign, 3 of 4 have too few.
                                    runners[0].Behave(floorRefusal "import" 12UL)
                                    runners[1].Behave(floorRefusal "import" 12UL)
                                    let req = vote 10UL
                                    expectAll runners req
                                    let! o = pipeline.Sign(req, CancellationToken.None)

                                    if n = 5 then
                                        Expect.isTrue
                                            (verifies key req o)
                                            $"{m} of {n}, two at the floor: the others sign ({o.Describe})"
                                    else
                                        Expect.equal
                                            o
                                            (Refused(Refusal.NotReadyUntil(ValueSome 13UL)))
                                            $"{m} of {n}, two at the floor: skipped"

                                    Expect.equal
                                        (registry.TryGet key).Value.State
                                        KeyState.Active
                                        $"{m} of {n}: the key stays active"
                                    // One member at the floor and one with a real slashing refusal: too few
                                    // sign in 3 of 4, and the slashing refusal answers for the group.
                                    if n = 4 then
                                        runners[1]
                                            .Behave(fun p ->
                                                if p[48] = Wire.Kind.Attestation then
                                                    ValueSome(
                                                        Reply.Refused(
                                                            refusal Wire.Status.SlashTarget "target 11 at or below 11"
                                                        )
                                                    )
                                                else
                                                    ValueNone)

                                        let req2 = vote 11UL
                                        expectAll runners req2
                                        let! o2 = pipeline.Sign(req2, CancellationToken.None)

                                        Expect.isTrue
                                            (match o2 with
                                             | Refused(Slashable _) -> true
                                             | _ -> false)
                                            $"a real slashing refusal: {o2.Describe}"

                                        Expect.isTrue
                                            (match (registry.TryGet key).Value.State with
                                             | KeyState.Halted _ -> true
                                             | _ -> false)
                                            "the key is halted"
                            })

                    testT
                        "m of n groups over fake runners (2 of 3, 3 of 5, 5 of 7): every m-subset of runners gives the same signature"
                        (fun () ->
                            task {
                                for m, n in [ 2, 3; 3, 5; 5, 7 ] do
                                    let secret, shares = shamir (960 + n) m [ 1UL .. uint64 n ]
                                    let key = pk secret

                                    let runners =
                                        [ for i in 0 .. n - 1 -> FakeRunner($"r{i + 1}", [ key, snd shares[i] ]) ]

                                    let settings =
                                        { teeSettings with
                                            Runners = [ for i in 1..n -> runnerCfg $"r{i}" ]
                                            Groups =
                                                [
                                                    {
                                                        Threshold = m
                                                        Members = [ for i in 1..n -> $"r{i}", uint64 i ]
                                                    }
                                                ]
                                        }

                                    let set =
                                        TeeModule.TeeSet(
                                            [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                            settings,
                                            TimeProvider.System,
                                            Log.none
                                        )

                                    let! found, answered = set.Discover CancellationToken.None
                                    Expect.equal answered n $"{n} runners"
                                    let b = (Map.ofList found)[key]
                                    Expect.stringContains b.Name $"tee {m} of {n}" "a threshold key"
                                    let req = request key (Duty.Attestation att)
                                    expectAll runners req
                                    let whole = (sign secret req.SigningRoot).Hex

                                    for up in Threshold.subsets n m do
                                        let upSet = Set.ofArray up

                                        for i in 0 .. n - 1 do
                                            runners[i]
                                                .Behave(fun _ ->
                                                    if upSet.Contains i then
                                                        ValueNone
                                                    else
                                                        ValueSome(Reply.Failure(Transport "down")))

                                        match! b.Sign req CancellationToken.None with
                                        | Signed s ->
                                            Expect.equal
                                                s.Hex
                                                whole
                                                $"{m} of {n}, runners {up}: the whole key's signature"
                                        | o -> failtestf "%d of %d, runners %A: %s" m n up o.Describe
                                    // One fewer than m: no signature.
                                    for i in 0 .. n - 1 do
                                        runners[i]
                                            .Behave(fun _ ->
                                                if i < m - 1 then
                                                    ValueNone
                                                else
                                                    ValueSome(Reply.Failure(Transport "down")))

                                    let! few = b.Sign req CancellationToken.None

                                    Expect.isTrue
                                        (match few with
                                         | Failed(Transport _) -> true
                                         | _ -> false)
                                        $"{m - 1} of {n} up: {few.Describe}"
                            })

                    testT "only allowlisted keys are registered; other listed keys, whole or shared, are not" (fun () ->
                        task {
                            let groupKeys = [ for s in 0..2 -> shamir (960 + s) 2 [ 1UL; 2UL; 3UL ] ]
                            let whole = secretOf 78
                            let otherWhole = secretOf 79

                            let runners =
                                [
                                    for m in 0..2 ->
                                        let shares = [ for secret, sh in groupKeys -> pk secret, snd sh[m] ]

                                        let all =
                                            if m = 0 then
                                                (pk whole, whole) :: (pk otherWhole, otherWhole) :: shares
                                            else
                                                shares

                                        FakeRunner($"r{m + 1}", all)
                                ]

                            let allowed = [ pk whole; pk (fst groupKeys[1]) ]

                            let settings =
                                { teeSettings with
                                    Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
                                    Groups =
                                        [
                                            {
                                                Threshold = 2
                                                Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                            }
                                        ]
                                    Keys =
                                        TeeModule.KeyFilter.Only(set [ for k in allowed -> k.Hex.ToLowerInvariant() ])
                                }

                            let tset =
                                TeeModule.TeeSet(
                                    [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                    settings,
                                    TimeProvider.System,
                                    Log.none
                                )

                            let! found, answered = tset.Discover CancellationToken.None
                            Expect.equal answered 3 "three runners"

                            Expect.equal
                                (found |> List.map fst |> Set.ofList)
                                (Set.ofList allowed)
                                "exactly the allowlisted keys"

                            let byKey = Map.ofList found
                            Expect.stringContains byKey[pk whole].Name "tee r1" "the whole key through r1"

                            Expect.stringContains
                                byKey[pk (fst groupKeys[1])].Name
                                "tee 2 of 3"
                                "the threshold key through the group"
                        })

                    testT
                        "a runner that never answers PUBLIC_KEYS fails its list after the deadline; the others list"
                        (fun () ->
                            task {
                                let whole = secretOf 78
                                let quick = FakeRunner("r1", [ pk whole, whole ])
                                let silentFake = FakeRunner("r2", [])

                                let silent =
                                    { silentFake.Api with
                                        Call =
                                            fun cls t payload ct ->
                                                if t = Wire.MsgType.PublicKeys then
                                                    task {
                                                        try
                                                            do! Task.Delay(-1, ct)
                                                        with :? OperationCanceledException ->
                                                            ()

                                                        return Reply.Failure SignFailure.Timeout
                                                    }
                                                else
                                                    silentFake.Api.Call cls t payload ct
                                    }

                                let settings =
                                    { teeSettings with
                                        Runners = [ runnerCfg "r1"; runnerCfg "r2" ]
                                    }

                                let time = Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow)

                                let set =
                                    TeeModule.TeeSet(
                                        [ settings.Runners[0], quick.Api; settings.Runners[1], silent ],
                                        settings,
                                        time,
                                        Log.none
                                    )
                                // The first list call may wait for a dial: the deadline adds the dial bound.
                                let discover = set.Discover CancellationToken.None
                                time.Advance(settings.DialTimeout + ListedKeys.ListDeadline - TimeSpan.FromSeconds 1.0)
                                do! Task.Delay 100
                                Expect.isFalse discover.IsCompleted "waits within the deadline"
                                time.Advance(TimeSpan.FromSeconds 1.0)
                                let! found, answered = discover.WaitAsync(TimeSpan.FromSeconds 10.0)
                                Expect.equal answered 1 "the silent runner failed its list"
                                Expect.equal (found |> List.map fst) [ pk whole ] "the key of the other runner"
                            })

                    testT "a threshold key whose shares do not combine at the configured indices is left out" (fun () ->
                        task {
                            let groupKeys = [ shamir 950 2 [ 1UL; 2UL; 3UL ] ]

                            let runners =
                                [
                                    for m in 0..2 ->
                                        FakeRunner(
                                            $"r{m + 1}",
                                            [ for secret, sh in groupKeys -> pk secret, snd sh[m] ]
                                        )
                                ]
                            // Indices 1, 3, 2: r2 and r3 swapped.
                            let settings =
                                { teeSettings with
                                    Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
                                    Groups =
                                        [
                                            {
                                                Threshold = 2
                                                Members = [ "r1", 1UL; "r2", 3UL; "r3", 2UL ]
                                            }
                                        ]
                                }

                            let set =
                                TeeModule.TeeSet(
                                    [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                    settings,
                                    TimeProvider.System,
                                    Log.none
                                )

                            let! found, _ = set.Discover CancellationToken.None
                            Expect.isEmpty found "no key"
                        })

                    testT "a share beyond the first m from another split of the same key refuses the key" (fun () ->
                        task {
                            let secret, shares = shamir 951 2 [ 1UL; 2UL; 3UL ]
                            let other = resplit 952 secret 2 [ 3UL ]
                            let key = pk secret
                            // r1 and r2 hold the split the first two indices give; r3 a share of another split.
                            let runners =
                                [
                                    FakeRunner("r1", [ key, snd shares[0] ])
                                    FakeRunner("r2", [ key, snd shares[1] ])
                                    FakeRunner("r3", [ key, snd other[0] ])
                                ]

                            let settings =
                                { teeSettings with
                                    Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
                                    Groups =
                                        [
                                            {
                                                Threshold = 2
                                                Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                            }
                                        ]
                                }

                            let set =
                                TeeModule.TeeSet(
                                    [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                    settings,
                                    TimeProvider.System,
                                    Log.none
                                )

                            let! found, _ = set.Discover CancellationToken.None
                            Expect.isEmpty found "the key is refused, not routed to the group"
                        })

                    testT "a key whole on one runner and split in a group is routed to neither" (fun () ->
                        task {
                            let secret, shares = shamir 953 2 [ 1UL; 2UL; 3UL ]
                            let key = pk secret

                            let runners =
                                [
                                    FakeRunner("r1", [ key, snd shares[0] ])
                                    FakeRunner("r2", [ key, snd shares[1] ])
                                    FakeRunner("r3", [ key, snd shares[2] ])
                                    FakeRunner("w", [ key, secret ])
                                ]

                            let settings =
                                { teeSettings with
                                    Runners = [ for n in [ "r1"; "r2"; "r3"; "w" ] -> runnerCfg n ]
                                    Groups =
                                        [
                                            {
                                                Threshold = 2
                                                Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                            }
                                        ]
                                }

                            let set =
                                TeeModule.TeeSet(
                                    [ for r, f in List.zip settings.Runners runners -> r, f.Api ],
                                    settings,
                                    TimeProvider.System,
                                    Log.none
                                )

                            let! found, _ = set.Discover CancellationToken.None
                            let registry = KeyRegistry()

                            for k, b in found do
                                registry.Add(k, b) |> ignore

                            match registry.TryGet key with
                            | ValueSome k when k.State <> KeyState.Removed ->
                                failtestf "the key signs through %s" k.Backend.Name
                            | _ -> ()

                            Expect.equal (registry.Refused |> List.map fst) [ key ] "refused"
                            let reason = snd registry.Refused.Head
                            Expect.stringContains reason "whole on tee w" "names the whole-key runner"
                            Expect.stringContains reason "tee 2 of 3" "and the group"
                        })

                    testT
                        "a key list refresh in which a runner lists a share of another split refuses a routed key"
                        (fun () ->
                            task {
                                let secret, shares = shamir 954 2 [ 1UL; 2UL; 3UL ]
                                let other = resplit 955 secret 2 [ 3UL ]
                                let key = pk secret
                                let good = FakeRunner("r3", [ key, snd shares[2] ])
                                let bad = FakeRunner("r3", [ key, snd other[0] ])
                                let mutable switched = false

                                let r3 =
                                    { good.Api with
                                        Call =
                                            fun cls t payload ct ->
                                                (if switched then bad else good).Api.Call cls t payload ct
                                    }

                                let runners =
                                    [
                                        FakeRunner("r1", [ key, snd shares[0] ]).Api
                                        FakeRunner("r2", [ key, snd shares[1] ]).Api
                                        r3
                                    ]

                                let settings =
                                    { teeSettings with
                                        Runners = [ for m in 1..3 -> runnerCfg $"r{m}" ]
                                        Groups =
                                            [
                                                {
                                                    Threshold = 2
                                                    Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                                }
                                            ]
                                    }

                                let set =
                                    TeeModule.TeeSet(
                                        List.zip settings.Runners runners,
                                        settings,
                                        TimeProvider.System,
                                        Log.none
                                    )

                                let registry = KeyRegistry()
                                let! found, _ = set.Discover CancellationToken.None
                                Expect.isEmpty set.Refused "one split at start"

                                for k, b in found do
                                    registry.Add(k, b) |> ignore

                                Expect.equal
                                    (registry.TryGet key).Value.State
                                    KeyState.Discovered
                                    "routed to the group"

                                Expect.equal set.ShareChecks.Runs 1L "checked at start"
                                let! again, _ = set.Discover CancellationToken.None
                                Expect.equal (again |> List.map fst) [ key ] "an unchanged refresh keeps the key"
                                Expect.equal set.ShareChecks.Runs 1L "and does not check it again"
                                switched <- true
                                let! found, _ = set.Discover CancellationToken.None
                                Expect.isEmpty found "left out at the refresh"
                                Expect.equal set.ShareChecks.Runs 2L "the changed share set is checked"

                                match set.Refused with
                                | [ k, why ] ->
                                    Expect.equal k key "the key"
                                    Expect.stringContains why "member 3:" "names the member"
                                | x -> failtestf "refused: %A" x
                                // What the module does with the list (ListedKeys.Refuse).
                                for k, why in set.Refused do
                                    registry.Refuse(k, why)

                                Expect.equal (registry.TryGet key).Value.State KeyState.Removed "taken out"
                            })
                ]

            testList
                "config"
                [
                    test "a config with runners and a group parses; mistakes are refused" {
                        let dir = tempDir ()

                        let good =
                            """{ "runners": [
                               { "name": "a", "address": "tcp:127.0.0.1:7100", "client_cert": "c.pem", "client_key": "k.pem",
                                 "attestation": { "verifier": "dev" } },
                               { "name": "b", "address": "192.0.2.2:7100", "client_cert": "c.pem", "client_key": "k.pem", "connections": 4,
                                 "attestation": { "verifier": "aws-nitro", "nitro_pcrs": { "0": "11", "1": "22", "2": "33" } } } ],
                             "groups": [ { "threshold": 2, "members": [ { "runner": "a", "index": 1 }, { "runner": "b", "index": 2 } ] } ],
                             "keys": [ "0xAA"""
                            + String('a', 94)
                            + """" ],
                             "timeout_ms": 1500, "priority_low_every": 4 }"""

                        match TeeModule.parseSettings (section good dir) with
                        | Ok s ->
                            Expect.equal s.Runners.Length 2 "two runners"
                            Expect.equal (s.Runners[1].Host, s.Runners[1].Port) ("192.0.2.2", 7100) "address"
                            Expect.equal s.Runners[0].Connections 8 "default 8 connections"
                            Expect.equal s.LowEvery 4 "lowEvery"
                            Expect.equal s.Timeout (TimeSpan.FromMilliseconds 1500.0) "timeout"
                            Expect.equal s.Runners[0].ClientCert (Path.Combine(dir, "c.pem")) "relative to the config"

                            Expect.equal
                                s.Keys
                                (TeeModule.KeyFilter.Only(set [ "0x" + String('a', 96) ]))
                                "the allowlist, lower case"
                        | Error e -> failtestf "%s" (String.Join("; ", e))

                        let bad =
                            [
                                """{ "runners": [], "x": 1 }""", "x"
                                """{ "runners": [ { "address": "unix:/tmp/s", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ] }""",
                                "tcp"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev", "pcr": 1 } } ] }""",
                                "unknown field"
                                """{ "runners": [ { "name": "a", "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                               "groups": [ { "threshold": 2, "members": [ { "runner": "a", "index": 1 } ] } ] }""",
                                "threshold"
                                """{ "runners": [ { "name": "a", "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } },
                                            { "name": "b", "address": "h:2", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                               "groups": [ { "threshold": 1, "members": [ { "runner": "a", "index": 1 } ] },
                                           { "threshold": 2, "members": [ { "runner": "a", "index": 2 }, { "runner": "b", "index": 1 } ] } ] }""",
                                "two groups"
                                """{ "runners": [ { "name": "a", "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } },
                                            { "name": "b", "address": "h:2", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } },
                                            { "name": "c", "address": "h:3", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } },
                                            { "name": "d", "address": "h:4", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                               "groups": [ { "threshold": 2, "members": [ { "runner": "a", "index": 1 }, { "runner": "b", "index": 2 },
                                                                         { "runner": "c", "index": 3 }, { "runner": "d", "index": 4 } ] } ],
                               "keys": [ "0x"""
                                + String('a', 96)
                                + """" ] }""",
                                "more than half"
                                """{ "runners": [ { "name": "a", "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } },
                                            { "name": "b", "address": "h:2", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ],
                               "groups": [ { "threshold": 1, "members": [ { "runner": "a", "index": 1 }, { "runner": "b", "index": 2 } ] } ],
                               "keys": [ "0x"""
                                + String('a', 96)
                                + """" ] }""",
                                "more than half"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ], "priority_low_every": 1 }""",
                                "priority_low_every"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ] }""",
                                "no keys"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ], "keys": [] }""",
                                "no keys"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ], "keys": [ "0x1234" ] }""",
                                "not a validator public key"
                                """{ "runners": [ { "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } } ], "keys_file": "missing.txt" }""",
                                "keys_file"
                            ]

                        for json, why in bad do
                            match TeeModule.parseSettings (section json dir) with
                            | Ok _ -> failtestf "accepted a config with a mistake (%s)" why
                            | Error e -> Expect.stringContains (String.Join("; ", e)) why why
                    }

                    test "keys_file: one key per line with comments, merged with keys" {
                        let dir = tempDir ()
                        let k1 = "0x" + String('b', 96)
                        let k2 = "0x" + String('c', 96)

                        File.WriteAllLines(
                            Path.Combine(dir, "keys.txt"),
                            [|
                                "# the lane's keys"
                                ""
                                k1 + "  # first"
                                k2.ToUpperInvariant().Replace("0X", "0x")
                            |]
                        )

                        let runner =
                            """{ "address": "h:1", "client_cert": "c", "client_key": "k", "attestation": { "verifier": "dev" } }"""

                        let json =
                            sprintf
                                "{ \"runners\": [ %s ], \"keys\": [ \"%s\" ], \"keys_file\": \"keys.txt\" }"
                                runner
                                k1

                        match TeeModule.parseSettings (section json dir) with
                        | Ok s -> Expect.equal s.Keys (TeeModule.KeyFilter.Only(set [ k1; k2 ])) "two distinct keys"
                        | Error e -> failtestf "%s" (String.Join("; ", e))
                    }

                    test "the SubjectPublicKeyInfo read from a certificate is the one .NET exports" {
                        for k in
                            [
                                ECDsa.Create(ECCurve.NamedCurves.nistP256) :> AsymmetricAlgorithm
                                RSA.Create 2048
                            ] do
                            use cert =
                                match k with
                                | :? ECDsa as e ->
                                    CertificateRequest("CN=signer-runner", e, HashAlgorithmName.SHA256)
                                        .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays 1.0)
                                | :? RSA as r ->
                                    CertificateRequest(
                                        "CN=signer-runner",
                                        r,
                                        HashAlgorithmName.SHA256,
                                        RSASignaturePadding.Pkcs1
                                    )
                                        .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays 1.0)
                                | _ -> failwith "key"

                            Expect.equal
                                (Der.subjectPublicKeyInfo cert.RawData)
                                (cert.PublicKey.ExportSubjectPublicKeyInfo())
                                "SPKI"

                            k.Dispose()
                    }
                ]
        ]
