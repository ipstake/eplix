/// The domain types are constants of the specs, not beacon node config: a node
/// that reports another value fails the start and the check each epoch, each duty kind signs under
/// its own domain type, and the pipeline refuses a request that carries another kind's domain.
module Eplix.Tests.DomainTypeTests

open System
open System.IO
open System.Net.Http
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.RunnerTests

/// The mainnet pin as a node reports it (with the preset value the pin leaves out).
let private mainnetNode () =
    ChainSpec.parseConfigYaml (Networks.configYaml "mainnet").Value |> Map.add "SLOTS_PER_EPOCH" "32"

let private mainnetSpec () =
    match ChainSpec.parse (mainnetNode ()) with
    | Ok s -> s
    | Error e -> failwith e

let private chainGvr = Root.Of(Array.init 32 (fun i -> byte (i + 1)))

let private cp (e: Epoch) (b: byte) =
    {
        Epoch = e
        Root = Root.Of(Array.create 32 b)
    }

/// An attestation at a Fulu epoch of mainnet.
let private attestation (blockRoot: byte) =
    let epoch = 420000UL

    {
        Slot = epoch * 32UL + 5UL
        Index = 0UL
        BeaconBlockRoot = Root.Of(Array.create 32 blockRoot)
        Source = cp (epoch - 1UL) 1uy
        Target = cp epoch 2uy
    }

let private deadline () = DateTimeOffset.UtcNow.AddMinutes 1.0

/// A pipeline over one active key whose backend signs any root and counts its calls.
let private pipelineWithCounter () =
    let sk = secretOf 0
    let pk = pubkeyOf 0
    let calls = ref 0

    let backend =
        {
            Name = "counting"
            Capabilities = LocalBackend.capabilities
            Keys = fun _ -> Task.FromResult []
            Health = fun _ -> Task.FromResult Up
            Sign =
                fun req _ ->
                    Interlocked.Increment calls |> ignore

                    Task.FromResult(
                        Signed(BlsSignature.Of(Bls.sign (ReadOnlySpan sk) (ReadOnlySpan req.SigningRoot.Bytes)))
                    )
            Dispose = fun () -> ValueTask.CompletedTask
        }

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), chainGvr) with
        | Ok db -> db
        | Error e -> failwith e

    db.RegisterKeys [ pk, KeyOrigin.StartedEmpty ] |> ignore
    let registry = KeyRegistry()
    registry.Add(pk, backend) |> ignore
    registry.SetState(pk, KeyState.Active)
    Pipeline(db, registry, TimeProvider.System, Log.none), pk, calls

let private runVc (h: Harness) (config: CoreConfig) (modules: Module list) (log: Log) (ct: CancellationToken) =
    Runner.run
        {
            Config = config
            Modules = modules
            Http = new HttpClient(h.Node, false)
            Time = h.Time
            Log = log
            OnSlotDone = h.Waiter.Done
            OnReady = fun _ _ -> ()
        }
        ct

[<Tests>]
let tests =
    testSequenced
    <| testList
        "domain types"
        [
            test "the constants are the specs' values" {
                let expected =
                    [
                        "DOMAIN_BEACON_PROPOSER", "0x00000000"
                        "DOMAIN_BEACON_ATTESTER", "0x01000000"
                        "DOMAIN_RANDAO", "0x02000000"
                        "DOMAIN_VOLUNTARY_EXIT", "0x04000000"
                        "DOMAIN_SELECTION_PROOF", "0x05000000"
                        "DOMAIN_AGGREGATE_AND_PROOF", "0x06000000"
                        "DOMAIN_SYNC_COMMITTEE", "0x07000000"
                        "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF", "0x08000000"
                        "DOMAIN_CONTRIBUTION_AND_PROOF", "0x09000000"
                        "DOMAIN_BEACON_BUILDER", "0x0b000000"
                        "DOMAIN_PTC_ATTESTER", "0x0c000000"
                        "DOMAIN_PROPOSER_PREFERENCES", "0x0d000000"
                        "DOMAIN_BUILDER_REQUEST_AUTH", "0x0b000001"
                        "DOMAIN_APPLICATION_BUILDER", "0x00000001"
                    ]

                Expect.equal [ for k, d in DomainTypes.all -> k, d.Hex ] expected "keys and values"
            }

            test "a node that reports another domain type fails the chain spec check" {
                let cases =
                    [
                        "DOMAIN_SYNC_COMMITTEE", "0x01000000"
                        "DOMAIN_SYNC_COMMITTEE", "0x00000000"
                        "DOMAIN_BEACON_ATTESTER", "0x07000000"
                        "DOMAIN_BEACON_ATTESTER", "0x00000000"
                        "DOMAIN_BEACON_PROPOSER", "0x01000000"
                        "DOMAIN_BEACON_PROPOSER", "0x07000000"
                        "DOMAIN_SELECTION_PROOF", "0x01000000"
                        "DOMAIN_PTC_ATTESTER", "0x01000000"
                        "DOMAIN_APPLICATION_BUILDER", "0x00000000"
                        "DOMAIN_RANDAO", "not hex"
                    ]

                for k, v in cases do
                    match ChainSpec.parse (mainnetNode () |> Map.add k v) with
                    | Ok _ -> failtestf "%s = %s passed" k v
                    | Error e -> Expect.stringContains e k $"{k} = {v}: the error names the key"
            }

            test "a node that reports the specs' values, in any case, or none, passes" {
                let all =
                    [
                        for k, d in DomainTypes.all -> k, d.Hex.ToUpperInvariant().Replace("0X", "0x")
                    ]

                Expect.isOk
                    (ChainSpec.parse (Seq.fold (fun m (k, v) -> Map.add k v m) (mainnetNode ()) all))
                    "every key, upper case"

                Expect.isOk (ChainSpec.parse (mainnetNode ())) "no domain key"
                // Keys Eplix does not sign with are not checked.
                Expect.isOk (ChainSpec.parse (mainnetNode () |> Map.add "DOMAIN_DEPOSIT" "0x03000000")) "DOMAIN_DEPOSIT"
            }

            test "each duty kind signs under its own domain type" {
                let spec = mainnetSpec ()
                let a = attestation 0xaauy

                let header =
                    {
                        Slot = a.Slot
                        ProposerIndex = 1UL
                        ParentRoot = Root.Zero
                        StateRoot = Root.Zero
                        BodyRoot = Root.Zero
                    }

                let duties =
                    [
                        Duty.Attestation a, "0x01000000"
                        Duty.Block header, "0x00000000"
                        Duty.RandaoReveal 420000UL, "0x02000000"
                        Duty.AggregationSlot a.Slot, "0x05000000"
                        Duty.SyncCommitteeMessage(a.Slot, Root.Zero), "0x07000000"
                        Duty.SyncSelectionProof
                            {
                                Slot = a.Slot
                                SubcommitteeIndex = 0UL
                            },
                        "0x08000000"
                        Duty.VoluntaryExit
                            {
                                Epoch = 420000UL
                                ValidatorIndex = 1UL
                            },
                        "0x04000000"
                    ]

                for duty, expected in duties do
                    let r = Duty.request spec chainGvr (pubkeyOf 0) Priority.High (deadline ()) duty
                    Expect.equal (Duty.domainType duty).Hex expected $"{duty.Kind}: domain type"
                    Expect.equal (Hex.encodeArray r.Domain.Bytes[0..3]) expected $"{duty.Kind}: the request's domain"
                    Expect.isTrue (Duty.domainFits r) $"{duty.Kind}: fits"
            }

            test "a sync message over an attestation's or a block's root never signs that attestation or block" {
                // The attack: a node hands over htr(AttestationData) as the head root of
                // a sync committee message. Under the sync committee domain type the signing root
                // differs from the attestation's, so the signature is no attestation signature.
                let spec = mainnetSpec ()
                let a = attestation 0xbbuy
                let key = pubkeyOf 0
                let att = Duty.request spec chainGvr key Priority.High (deadline ()) (Duty.Attestation a)

                let sync =
                    Duty.request
                        spec
                        chainGvr
                        key
                        Priority.High
                        (deadline ())
                        (Duty.SyncCommitteeMessage(a.Slot, Codec.hashAttestationData a))

                Expect.notEqual sync.SigningRoot att.SigningRoot "not the attestation's signing root"
                Expect.notEqual sync.Domain att.Domain "not the attester domain"

                let header =
                    {
                        Slot = a.Slot
                        ProposerIndex = 1UL
                        ParentRoot = Root.Zero
                        StateRoot = Root.Zero
                        BodyRoot = Root.Zero
                    }

                let block = Duty.request spec chainGvr key Priority.High (deadline ()) (Duty.Block header)

                let sync2 =
                    Duty.request
                        spec
                        chainGvr
                        key
                        Priority.High
                        (deadline ())
                        (Duty.SyncCommitteeMessage(a.Slot, Codec.hashBeaconBlockHeader header))

                Expect.notEqual sync2.SigningRoot block.SigningRoot "not the block's signing root"
            }

            testT "the pipeline refuses a request with another kind's domain, before marks and backend" (fun () ->
                task {
                    let spec = mainnetSpec ()
                    let pipeline, key, calls = pipelineWithCounter ()
                    let d1 = attestation 0xaauy
                    let d2 = attestation 0xbbuy
                    let att1 = Duty.request spec chainGvr key Priority.High (deadline ()) (Duty.Attestation d1)
                    let att2 = Duty.request spec chainGvr key Priority.High (deadline ()) (Duty.Attestation d2)
                    // A sync message request built by hand with the attester domain and D2's signing root:
                    // what the node's DOMAIN_SYNC_COMMITTEE = 0x01000000 produced before the fix.
                    let sync =
                        Duty.request
                            spec
                            chainGvr
                            key
                            Priority.High
                            (deadline ())
                            (Duty.SyncCommitteeMessage(d2.Slot, Codec.hashAttestationData d2))

                    let forged =
                        { sync with
                            Domain = att2.Domain
                            SigningRoot = att2.SigningRoot
                        }

                    Expect.isFalse (Duty.domainFits forged) "the forged request does not fit"
                    let! o1 = pipeline.Sign(att1, CancellationToken.None)

                    Expect.isTrue
                        (match o1 with
                         | Signed _ -> true
                         | _ -> false)
                        $"attestation D1: {o1.Describe}"

                    let! o2 = pipeline.Sign(forged, CancellationToken.None)
                    Expect.equal o2 (Refused DomainMismatch) "refused as a domain mismatch"
                    Expect.equal calls.Value 1 "the backend got D1 only"
                    // An attestation request with the sync committee domain is refused before the
                    // slashing DB records it: an honest attestation for a later target still signs.
                    let d3 =
                        { attestation 0xccuy with
                            Target = cp 420001UL 3uy
                        }

                    let att3 = Duty.request spec chainGvr key Priority.High (deadline ()) (Duty.Attestation d3)
                    let! o3 = pipeline.Sign({ att3 with Domain = sync.Domain }, CancellationToken.None)
                    Expect.equal o3 (Refused DomainMismatch) "an attestation under the sync domain"
                    let! o4 = pipeline.Sign(att3, CancellationToken.None)

                    Expect.isTrue
                        (match o4 with
                         | Signed _ -> true
                         | _ -> false)
                        $"the honest D3 still signs: {o4.Describe}"

                    Expect.equal calls.Value 2 "D1 and D3"
                })

            testT "a node with another DOMAIN_SYNC_COMMITTEE does not start the VC" (fun () ->
                task {
                    for k, v in
                        [
                            "DOMAIN_SYNC_COMMITTEE", "0x01000000"
                            "DOMAIN_BEACON_ATTESTER", "0x07000000"
                            "DOMAIN_BEACON_PROPOSER", "0x07000000"
                        ] do
                        let h = harness ()
                        h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                        h.Node.SpecOverride <- [ k, v ]
                        let config, modules = localVcConfig (localVcDir (configYaml secondsPerSlot slotsPerEpoch))
                        use cts = new CancellationTokenSource(TimeSpan.FromSeconds 20.0)
                        let! r = runVc h config modules Log.none cts.Token

                        match r with
                        | Error e -> Expect.stringContains e k $"{k}: refused with the key"
                        | Ok() -> failtestf "started with %s = %s" k v

                        Expect.isEmpty h.Node.Submissions $"{k}: signed nothing"
                })

            testT "a node whose DOMAIN_SYNC_COMMITTEE changes while running stops the VC" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let config, modules = localVcConfig (localVcDir (configYaml secondsPerSlot slotsPerEpoch))
                    let log, lines = Log.memory ()
                    use cts = new CancellationTokenSource()
                    let run = runVc h config modules log cts.Token
                    do! h.RunSlots(0UL, uint64 slotsPerEpoch)
                    h.Node.SpecOverride <- [ "DOMAIN_SYNC_COMMITTEE", "0x01000000" ]
                    let next = h.Clock.SlotStart(2UL * uint64 slotsPerEpoch) + TimeSpan.FromSeconds 3.0
                    h.Time.Advance(next - h.Time.GetUtcNow())
                    let! winner = Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds 20.0))

                    Expect.isTrue
                        (Object.ReferenceEquals(winner, run))
                        $"the VC stopped; log: {String.Join('\n', lines)}"

                    match run.Result with
                    | Ok() -> failtest "the run must end with an error"
                    | Error e -> Expect.stringContains e "DOMAIN_SYNC_COMMITTEE" "names the key"

                    Expect.isTrue
                        (h.Node.Submissions |> Seq.forall (fun s -> s.Slot < 2UL * uint64 slotsPerEpoch))
                        "nothing signed from epoch 2"
                })
        ]
