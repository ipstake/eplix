/// Against a real local Dirk cluster (scripts/dirk-local.sh): three Dirk 1.2.1 instances with
/// 2 of 3 distributed accounts and plain accounts. Runs only when EPLIX_DIRK_NET names the
/// cluster directory; scripts/dirk-it.sh sets it up and runs these tests.
module Eplix.Tests.DirkIntegrationTests

open System
open System.Diagnostics
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Dirk
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let netDir = Environment.GetEnvironmentVariable "EPLIX_DIRK_NET"
let enabled = not (String.IsNullOrEmpty netDir)

/// Runs scripts/dirk-local.sh with the given arguments and waits for it.
let dirkCtl (args: string list) =
    let psi = ProcessStartInfo("bash", [ Path.Combine(repoRoot, "scripts", "dirk-local.sh") ] @ args)
    psi.RedirectStandardOutput <- true
    psi.RedirectStandardError <- true
    use p = Process.Start psi
    let out = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()
    p.WaitForExit()

    if p.ExitCode <> 0 then
        failtestf "dirk-local.sh %s failed: %s" (String.Join(' ', args)) out

let settings (accounts: string list) : DirkModule.Settings =
    {
        Endpoints = [ "dirk1:19591"; "dirk2:19592"; "dirk3:19593" ]
        Accounts = accounts
        Tls =
            {
                CaCert = Path.Combine(netDir, "certs", "ca.crt")
                ClientCert = Path.Combine(netDir, "certs", "eplix.crt")
                ClientKey = Path.Combine(netDir, "certs", "eplix.key")
            }
        Timeout = TimeSpan.FromSeconds 2.0
        BatchAttestations = true
        RefreshInterval = TimeSpan.Zero
        GloasCalls = GloasCalls.Auto
        ReloadInterval = TimeSpan.Zero
    }

let connectSet (s: DirkModule.Settings) (time: TimeProvider) (log: Log) =
    match GrpcDirk.loadTls s.Tls log time with
    | Error e -> failtest e
    | Ok tls -> DirkModule.DirkSet((fun a -> GrpcDirk.connect a tls), s, time, log)

/// Accounts by name: the key and its backend.
let discover (s: DirkModule.Settings) (time: TimeProvider) =
    task {
        let dirks = connectSet s time Log.none
        let! found, answered = dirks.Discover CancellationToken.None

        let names =
            [
                for key, backend in found ->
                    let name =
                        dirks.Endpoints
                        |> List.pick (fun e ->
                            e.TryAccount key |> ValueOption.map (fun a -> a.Name) |> ValueOption.toOption)

                    name, (key, backend)
            ]
            |> Map.ofList

        return dirks, names, answered
    }

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

let private posts (h: Harness) (suffix: string) =
    h.Node.Posts |> Seq.filter (fun (p, _) -> p.EndsWith suffix) |> Seq.map snd |> List.ofSeq

let private jsonItems (body: string) =
    use d = JsonDocument.Parse body
    [ for x in d.RootElement.EnumerateArray() -> x.Clone() ]

let private waitFor (lines: Collections.Concurrent.ConcurrentQueue<string>) (what: string) (cond: unit -> bool) =
    task {
        let sw = Stopwatch.StartNew()

        while not (cond ()) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
            do! Task.Delay 10

        if not (cond ()) then
            failtestf "timed out waiting for %s; log:\n%s" what (String.Join("\n", lines))
    }

let private advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

let private freshDb () =
    match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
    | Ok db -> db
    | Error e -> failwith e

let private attestationData (target: Epoch) (n: int) =
    {
        Slot = target * 8UL + 1UL
        Index = 0UL
        BeaconBlockRoot = root n
        Source = { Epoch = target - 1UL; Root = root 4 }
        Target = { Epoch = target; Root = root 5 }
    }

let private integration =
    testSequenced
    <| testList
        "dirk-integration"
        [
            testT "Dirk lists 2 of 3 distributed accounts and plain accounts" (fun () ->
                task {
                    let! dirks, names, answered = discover (settings [ "Dist"; "Solo" ]) TimeProvider.System
                    Expect.equal answered 3 "three Dirk instances answer"

                    Expect.equal
                        (names |> Map.keys |> List.ofSeq |> List.sort)
                        [
                            "Dist/Val1"
                            "Dist/Val2"
                            "Dist/Val3"
                            "Dist/Val4"
                            "Solo/Solo1"
                            "Solo/Solo2"
                        ]
                        "accounts"

                    let _, group = names["Dist/Val1"]
                    Expect.stringContains group.Name "dirk 2 of 3" "a threshold group"
                    let! keys = group.Keys CancellationToken.None
                    Expect.equal keys.Length 4 "the group lists the four distributed keys"
                    dirks.Stop()
                })

            testT "every duty kind signs through Dirk and verifies" (fun () ->
                task {
                    let! dirks, names, _ = discover (settings [ "Dist"; "Solo" ]) TimeProvider.System
                    let h = harness ()

                    let header =
                        {
                            Slot = 40UL
                            ProposerIndex = 1UL
                            ParentRoot = root 1
                            StateRoot = root 2
                            BodyRoot = root 3
                        }

                    let aggregate =
                        {
                            Schema = Schemas.aggregateAndProof h.Node.Preset
                            Value = Ssz.zero (Schemas.aggregateAndProof h.Node.Preset)
                        }

                    let contribution =
                        {
                            Schema = Schemas.contributionAndProof h.Node.Preset
                            Value = Ssz.zero (Schemas.contributionAndProof h.Node.Preset)
                        }

                    let duties =
                        [
                            Duty.Attestation(attestationData 5UL 1)
                            Duty.Block header
                            Duty.RandaoReveal 5UL
                            Duty.AggregationSlot 41UL
                            Duty.AggregateAndProof(41UL, aggregate)
                            Duty.SyncCommitteeMessage(41UL, root 9)
                            Duty.SyncSelectionProof { Slot = 41UL; SubcommitteeIndex = 1UL }
                            Duty.ContributionAndProof(41UL, contribution)
                            Duty.VoluntaryExit { Epoch = 5UL; ValidatorIndex = 1UL }
                        ]

                    for account in [ "Dist/Val4"; "Solo/Solo2" ] do
                        let key, backend = names[account]
                        // The pre-Gloas registration goes as a generic sign in the builder domain; the
                        // 2 of 3 account checks that a threshold group signs it.
                        let registration =
                            Duty.ValidatorRegistration
                                {
                                    FeeRecipient = Array.create 20 0xAAuy
                                    GasLimit = 60_000_000UL
                                    Timestamp = 1_700_000_000UL
                                    PubKey = key
                                }

                        for duty in duties @ [ registration ] do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! backend.Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.isTrue (verify key req.SigningRoot s) $"{account} {duty.Kind} verifies"
                            | o -> failtestf "%s %A: %s" account duty.Kind o.Describe

                    dirks.Stop()
                })

            testT "the Gloas kinds sign through Dirk's generic call and verify" (fun () ->
                task {
                    // Stock Dirk has no typed Gloas calls: it answers the first UNIMPLEMENTED, and Eplix
                    // sends the root and domain from then on.
                    let! dirks, names, _ = discover (settings [ "Dist"; "Solo" ]) TimeProvider.System
                    let h = harness ()
                    let p = h.Node.Preset

                    let duties =
                        [
                            Duty.PayloadAttestation
                                {
                                    BeaconBlockRoot = root 7
                                    Slot = 41UL
                                    PayloadPresent = true
                                    BlobDataAvailable = true
                                }
                            Duty.PayloadEnvelope(
                                41UL,
                                {
                                    Schema = Schemas.Gloas.executionPayloadEnvelope p
                                    Value = Ssz.zero (Schemas.Gloas.executionPayloadEnvelope p)
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

                    for account in [ "Dist/Val4"; "Solo/Solo2" ] do
                        let key, backend = names[account]

                        for duty in duties do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! backend.Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.isTrue (verify key req.SigningRoot s) $"{account} {duty.Kind} verifies"
                            | o -> failtestf "%s %A: %s" account duty.Kind o.Describe

                    dirks.Stop()
                })

            testT "gloas_calls generic signs the Gloas kinds without a typed call; typed fails on stock Dirk" (fun () ->
                task {
                    let h = harness ()

                    let ptc =
                        Duty.PayloadAttestation
                            {
                                BeaconBlockRoot = root 8
                                Slot = 43UL
                                PayloadPresent = true
                                BlobDataAvailable = true
                            }

                    let prefs =
                        Duty.ProposerPreferences
                            {
                                DependentRoot = root 4
                                ProposalSlot = 44UL
                                ValidatorIndex = 1UL
                                FeeRecipient = Array.create 20 0xbbuy
                                TargetGasLimit = 60_000_000UL
                            }

                    let! dirks, names, _ =
                        discover
                            { settings [ "Dist"; "Solo" ] with
                                GloasCalls = GloasCalls.Generic
                            }
                            TimeProvider.System

                    for account in [ "Dist/Val4"; "Solo/Solo2" ] do
                        let key, backend = names[account]

                        for duty in [ ptc; prefs ] do
                            let req =
                                Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

                            match! backend.Sign req CancellationToken.None with
                            | Signed s ->
                                Expect.isTrue (verify key req.SigningRoot s) $"generic: {account} {duty.Kind} verifies"
                            | o -> failtestf "generic: %s %A: %s" account duty.Kind o.Describe

                    dirks.Stop()

                    let! dirks, names, _ =
                        discover
                            { settings [ "Solo" ] with
                                GloasCalls = GloasCalls.Typed
                            }
                            TimeProvider.System

                    let key, backend = names["Solo/Solo2"]
                    let req = Duty.request h.Spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) ptc

                    match! backend.Sign req CancellationToken.None with
                    | Failed(Internal m) -> Expect.stringContains m "gloas_calls" "typed: the error names the setting"
                    | o -> failtestf "typed on stock Dirk: expected a failure, got %s" o.Describe

                    dirks.Stop()
                })

            testT "duties on the fake beacon node through three Dirks, then with one Dirk down" (fun () ->
                task {
                    let h = harness ()
                    let! dirks, names, _ = discover (settings [ "Dist"; "Solo" ]) h.Time
                    let accounts = [ "Dist/Val1"; "Dist/Val2"; "Dist/Val3"; "Solo/Solo1" ]
                    let routes = [ for a in accounts -> names[a] ]

                    for key, _ in routes do
                        h.Node.AddValidator(key, "active_ongoing") |> ignore

                    h.Node.CommitteeLength <- 8UL
                    h.Node.Proposals[5UL] <- 1UL
                    h.Node.Proposals[12UL] <- 2UL
                    h.Node.Proposals[20UL] <- 0UL
                    h.Node.SyncSeats[0UL] <- [| 0UL; 9UL |]
                    h.Node.SyncSeats[3UL] <- [| 16UL |]
                    h.Node.HeadRoot <- root 77
                    use cts = new CancellationTokenSource()

                    let! run, db, lines, _ =
                        startSchedulerWith h (Path.Combine(tempDir (), "s.db")) routes false cts.Token

                    let runSlot (s: Slot) =
                        task {
                            do! h.RunSlots(s, s)

                            if h.Node.Proposals.ContainsKey s then
                                do!
                                    waitFor lines $"the block of slot {s}" (fun () ->
                                        h.Node.Published |> Seq.length
                                        >= (h.Node.Proposals.Keys |> Seq.filter (fun p -> p <= s) |> Seq.length))

                            advanceTo h (h.Clock.SlotStart s + h.Spec.AggregateDue + TimeSpan.FromMilliseconds 1.0)

                            do!
                                waitFor lines $"aggregates of slot {s}" (fun () ->
                                    (posts h "aggregate_and_proofs" |> List.collect jsonItems).Length
                                    >= int s / 8 * 4 + min (int s % 8 + 1) 4)

                            advanceTo h (h.Clock.SlotStart s + h.Spec.ContributionDue + TimeSpan.FromMilliseconds 1.0)

                            do!
                                waitFor lines $"contributions of slot {s}" (fun () ->
                                    posts h "contribution_and_proofs"
                                    |> List.collect jsonItems
                                    |> List.exists (fun c ->
                                        c
                                            .GetProperty("message")
                                            .GetProperty("contribution")
                                            .GetProperty("slot")
                                            .GetString()
                                            =
                                            string s))
                        }

                    for s in 0UL .. 15UL do
                        do! runSlot s

                    let before = h.Node.Submissions.Count
                    Expect.equal before 8 "two epochs, four validators"
                    // One Dirk down: the distributed keys sign with the other two.
                    dirkCtl [ "stop"; netDir; "3" ]

                    try
                        for s in 16UL .. 23UL do
                            do! runSlot s

                        let dirk3 = dirks.Endpoints |> List.find (fun e -> e.Address = "dirk3:19593")

                        Expect.isTrue
                            (match dirk3.Health with
                             | Down _ -> true
                             | _ -> false)
                            "dirk3 was down while the epoch ran"
                    finally
                        dirkCtl [ "start"; netDir; "3" ]

                    cts.Cancel()
                    do! run
                    (db :> IDisposable).Dispose()
                    let subs = List.ofSeq h.Node.Submissions
                    Expect.equal subs.Length 12 $"three epochs, four validators; log:\n{String.Join('\n', lines)}"

                    for s in subs do
                        Expect.isTrue
                            (verifySubmission h s)
                            $"attestation of validator {s.AttesterIndex} at slot {s.Data.Slot} verifies"

                    Expect.equal
                        (h.Node.Published |> Seq.length)
                        3
                        "blocks at slots 5, 12 and 20 (the last with dirk3 down)"

                    for version, _, bytes in h.Node.Published do
                        match Ssz.deserialize (Schemas.signedBlockContents h.Node.Preset) bytes with
                        | Error e -> failtestf "block does not decode: %s" e
                        | Ok v ->
                            let signedBlock = Codec.fields (Codec.fields v).[0]
                            let block = Codec.fields signedBlock[0]
                            let slot = Codec.asU block[0]
                            let proposer = h.Node.Validators[int (Codec.asU block[1])].PubKey

                            let hdr =
                                {
                                    Slot = slot
                                    ProposerIndex = Codec.asU block[1]
                                    ParentRoot = Root.Of(Codec.asBytes block[2])
                                    StateRoot = Root.Of(Codec.asBytes block[3])
                                    BodyRoot =
                                        Root.Of(Ssz.hashTreeRoot (Schemas.beaconBlockBody h.Node.Preset) block[4])
                                }

                            let domain = Signing.domainAt h.Spec gvr h.Spec.DomainBeaconProposer (h.Spec.EpochOf slot)
                            let s = BlsSignature.Of(Codec.asBytes signedBlock[1])

                            Expect.isTrue
                                (verify
                                    proposer
                                    (Signing.computeSigningRoot (Codec.hashBeaconBlockHeader hdr) domain)
                                    s)
                                $"{version} block at slot {slot} verifies"

                    let aggs = posts h "aggregate_and_proofs" |> List.collect jsonItems

                    Expect.equal
                        aggs.Length
                        12
                        "one aggregate per validator and epoch (committees of 8 make everyone an aggregator)"

                    for a in aggs do
                        match SszJson.tryRead (Schemas.signedAggregateAndProof h.Node.Preset) a with
                        | Error e -> failtestf "aggregate does not decode: %s" e
                        | Ok v ->
                            let f = Codec.fields v
                            let msg = Codec.fields f[0]
                            let pk = h.Node.Validators[int (Codec.asU msg[0])].PubKey
                            let data = Codec.attestationDataOf (Codec.fields msg[1]).[1]
                            let epoch = h.Spec.EpochOf data.Slot

                            let sel =
                                Signing.computeSigningRoot
                                    (Codec.hashSlot data.Slot)
                                    (Signing.domainAt h.Spec gvr h.Spec.DomainSelectionProof epoch)

                            Expect.isTrue (verify pk sel (BlsSignature.Of(Codec.asBytes msg[2]))) "selection proof"
                            let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.aggregateAndProof h.Node.Preset) f[0])

                            let r =
                                Signing.computeSigningRoot
                                    msgRoot
                                    (Signing.domainAt h.Spec gvr h.Spec.DomainAggregateAndProof epoch)

                            Expect.isTrue (verify pk r (BlsSignature.Of(Codec.asBytes f[1]))) "aggregate and proof"

                    let msgs = posts h "sync_committees" |> List.collect jsonItems
                    Expect.isGreaterThanOrEqual msgs.Length 46 "two sync committee members, every slot"

                    for m in msgs do
                        let index = UInt64.Parse(m.GetProperty("validator_index").GetString())
                        let slot = UInt64.Parse(m.GetProperty("slot").GetString())
                        let r = Root.TryParse(m.GetProperty("beacon_block_root").GetString()) |> ValueOption.get
                        let s = BlsSignature.TryParse(m.GetProperty("signature").GetString()) |> ValueOption.get

                        let sr =
                            Signing.computeSigningRoot
                                r
                                (Signing.domainAt h.Spec gvr h.Spec.DomainSyncCommittee (h.Spec.EpochOf slot))

                        Expect.isTrue (verify h.Node.Validators[int index].PubKey sr s) "sync committee message"

                    let contribs = posts h "contribution_and_proofs" |> List.collect jsonItems
                    Expect.isGreaterThanOrEqual contribs.Length 24 "contributions every slot"

                    for c in contribs do
                        match SszJson.tryRead (Schemas.signedContributionAndProof h.Node.Preset) c with
                        | Error e -> failtestf "contribution does not decode: %s" e
                        | Ok v ->
                            let f = Codec.fields v
                            let msg = Codec.fields f[0]
                            let pk = h.Node.Validators[int (Codec.asU msg[0])].PubKey
                            let slot = Codec.asU (Codec.fields msg[1]).[0]
                            let msgRoot = Root.Of(Ssz.hashTreeRoot (Schemas.contributionAndProof h.Node.Preset) f[0])

                            let r =
                                Signing.computeSigningRoot
                                    msgRoot
                                    (Signing.domainAt
                                        h.Spec
                                        gvr
                                        h.Spec.DomainContributionAndProof
                                        (h.Spec.EpochOf slot))

                            Expect.isTrue (verify pk r (BlsSignature.Of(Codec.asBytes f[1]))) "contribution and proof"

                    dirks.Stop()
                })

            testT
                "a double vote that only Dirk's protection sees is skipped as Denied and the key keeps signing"
                (fun () ->
                    task {
                        let h = harness ()
                        let! dirks, names, _ = discover (settings [ "Dist"; "Solo" ]) h.Time

                        for account in [ "Dist/Val4"; "Solo/Solo2" ] do
                            let key, backend = names[account]
                            // Two VCs with the same key, each with its own slashing DB.
                            let vc () =
                                let db = freshDb ()
                                db.RegisterKeys [ key, KeyOrigin.StartedEmpty ] |> ignore
                                let registry = KeyRegistry()
                                registry.Add(key, backend) |> ignore
                                registry.SetState(key, KeyState.Active)
                                db, registry, Pipeline(db, registry, h.Time, Log.none)

                            let dbA, registryA, a = vc ()
                            let dbB, registryB, b = vc ()
                            use _ = dbA
                            use _ = dbB

                            let vote (p: Pipeline) (target: Epoch) (n: int) =
                                let req =
                                    Duty.request
                                        h.Spec
                                        gvr
                                        key
                                        Priority.High
                                        (h.Time.GetUtcNow().AddSeconds 10.0)
                                        (Duty.Attestation(attestationData target n))

                                p.Sign(req, CancellationToken.None)

                            let! first = vote a 50UL 1

                            Expect.isTrue
                                (match first with
                                 | Signed _ -> true
                                 | _ -> false)
                                $"{account}: the first vote is signed ({first.Describe})"
                            // B's DB has no record of A's vote; Dirk's protection has.
                            let! second = vote b 50UL 2

                            match second with
                            | Refused(Denied(_, t)) ->
                                Expect.equal t.Signed 0 $"{account}: nobody signed ({second.Describe})"
                            | o -> failtestf "%s: expected Denied, got %s" account o.Describe

                            Expect.equal
                                (registryB.TryGet key).Value.State
                                KeyState.Active
                                $"{account}: the key is not halted"

                            Expect.equal (registryB.Denials key) 1L $"{account}: the denial is counted"
                            let! next = vote b 51UL 3

                            Expect.isTrue
                                (match next with
                                 | Signed _ -> true
                                 | _ -> false)
                                $"{account}: the next vote is signed ({next.Describe})"
                            // A's own DB knows its vote and refuses the double vote before Dirk sees it.
                            let! own = vote a 50UL 2

                            match own with
                            | Refused(Slashable _) -> ()
                            | o -> failtestf "%s: expected Eplix's DB to refuse, got %s" account o.Describe

                            Expect.equal
                                (registryA.Denials key)
                                0L
                                $"{account}: Eplix's own refusal is no remote denial"

                        dirks.Stop()
                    })
        ]

[<Tests>]
let tests =
    if enabled then
        integration
    else
        testList "dirk-integration" [ ptest "set EPLIX_DIRK_NET to a cluster from scripts/dirk-local.sh" { () } ]
