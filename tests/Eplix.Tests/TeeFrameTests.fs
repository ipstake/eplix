/// The runner's frames on the client side: error answers, frame versions, the refusal mapping
/// for codes the Go vectors do not cover, a runner failure in a group, and the key list frame
/// limit.
module Eplix.Tests.TeeFrameTests

open System
open System.Threading
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.SchedulerTests
open Eplix.Tests.TeeTests

let private refusal code (detail: string) : Wire.Refusal = { Code = code; Detail = detail }

let private att =
    {
        Slot = 41UL
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = 4UL; Root = root 4 }
        Target = { Epoch = 5UL; Root = root 5 }
    }

let private settings: TeeModule.Settings =
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

let private genRefusal =
    gen {
        let! code = Gen.choose (1, 65535) |> Gen.map uint16

        let! detail =
            ArbMap.defaults
            |> ArbMap.generate<string>
            |> Gen.map (fun s ->
                match s with
                | null -> ""
                | s -> s)

        return refusal code detail
    }

[<Tests>]
let tests =
    testList
        "tee frame"
        [
            testList
                "wire"
                [
                    test "every length of an error answer is checked; an OK answer carries its body" {
                        let good = Wire.encodeError (refusal 11us "target")

                        for bad in [ good[.. good.Length - 2]; Array.append good [| 0uy |]; good[..2] ] do
                            Expect.throwsT<Wire.WireError>
                                (fun () -> Wire.decodeResponse bad |> ignore)
                                $"{bad.Length} bytes"

                        let ok = Array.append [| 0uy; 0uy |] [| 1uy; 2uy; 3uy |]
                        Expect.equal (Wire.decodeResponse ok) (Ok [| 1uy; 2uy; 3uy |]) "the body"
                    }

                    test "frames of version 1 decode; others are refused" {
                        let f = Wire.encodeFrame 0x83uy 7u (ReadOnlySpan [| 9uy |])
                        Expect.equal f[4] Wire.FrameVersion "version byte"
                        let b = Wire.decodeBody f[4..]
                        Expect.equal (b.Type, b.Id, b.Payload) (0x83uy, 7u, [| 9uy |]) "decoded"

                        for v in [ 0uy; 2uy; 3uy ] do
                            let other = Array.copy f[4..]
                            other[0] <- v
                            Expect.throwsT<Wire.WireError> (fun () -> Wire.decodeBody other |> ignore) $"version {v}"
                    }

                    testPropN "error answers encode and decode to the same refusal" 300
                    <| Prop.forAll (Arb.fromGen genRefusal) (fun r ->
                        Wire.decodeResponse (Wire.encodeError r) = Error r)

                    testPropN "random answers decode or raise WireError" 500
                    <| Prop.forAll (Arb.fromGen (Gen.arrayOf (Gen.choose (0, 255) |> Gen.map byte))) (fun b ->
                        try
                            Wire.decodeResponse b |> ignore
                            true
                        with :? Wire.WireError ->
                            true)
                ]

            testList
                "mapping"
                [
                    test "an unknown code is a failure; FLOOR and FLOOR_UNPROVEN wait" {
                        let a = Duty.Attestation att
                        let o r = Mapping.toOutcome "r" a r

                        for c in [ 1010us; 1011us; 1012us; 1013us; 4242us ] do
                            Expect.isTrue
                                (match o (refusal c "") with
                                 | Failed(Internal m) -> m.Contains $"STATUS_{c}"
                                 | _ -> false)
                                $"{c} is not a tee-signer code"

                        Expect.equal (o (refusal 1008us "")) (Refused(Refusal.NotReadyUntil ValueNone)) "FLOOR"

                        Expect.equal (o (refusal 1009us "")) (Refused(Refusal.NotReadyUntil ValueNone)) "FLOOR_UNPROVEN"
                    }

                    test "a floor text on a slashing code halts; SIGN kinds a runner lacks" {
                        let a = Duty.Attestation att
                        let floorText = "target 10 at or below 10 (at or below restart floor epoch 12)"

                        Expect.isTrue
                            (match Mapping.toOutcome "r" a (refusal 11us floorText) with
                             | Refused(Slashable _) -> true
                             | _ -> false)
                            "a slashing code halts"

                        let auth = Duty.BuilderRequestAuth { AuthData = [| 1uy |]; AuthSlot = 9UL }

                        Expect.equal
                            (Mapping.toOutcome "r" auth (refusal 1001us "unknown kind 14"))
                            (Refused(Unsupported DutyKind.BuilderRequestAuth))
                            "an unknown SIGN kind is UNSUPPORTED"

                        Expect.equal
                            (Mapping.toOutcome "r" auth (refusal 1000us "no SSZ encoding for kind 14"))
                            (Refused(Unsupported DutyKind.BuilderRequestAuth))
                            "BAD_REQUEST no SSZ encoding is UNSUPPORTED"

                        Expect.isTrue
                            (match Mapping.toOutcome "r" auth (refusal 1000us "bad length") with
                             | Refused(BadRequest _) -> true
                             | _ -> false)
                            "another BAD_REQUEST stays a bad request"

                        Expect.isTrue
                            (RunnerEndpoint.Duties.Contains DutyKind.BuilderRequestAuth)
                            "runners take builder request auth"
                    }

                    test "every slashing code is slashable; storage, internal and platform codes fail" {
                        let a = Duty.Attestation att

                        for c in [ 9us; 10us; 11us; 12us; 24us ] do
                            Expect.isTrue
                                (match Mapping.toOutcome "r" a (refusal c "") with
                                 | Refused(Slashable _) -> true
                                 | _ -> false)
                                $"{c}"

                        for c in [ 2us; 7us; 1002us; 1005us ] do
                            Expect.isTrue
                                (match Mapping.toOutcome "r" a (refusal c "") with
                                 | Failed(Internal _) -> true
                                 | _ -> false)
                                $"{c}"
                    }
                ]

            testList
                "failures"
                [
                    test "a group's merged failure keeps a gone member visible" {
                        match
                            Threshold.mergeFailures
                                [ Transport "r1: refused"; Gone "r2: log lost"; Unavailable "r3: NOT_READY" ]
                        with
                        | Transport m ->
                            Expect.stringContains m "gone: r2: log lost" "gone named"
                            Expect.stringContains m "r3: NOT_READY" "unavailable kept"
                        | f -> failtestf "%A" f

                        Expect.equal
                            (Threshold.mergeFailures [ Gone "x"; SignFailure.Timeout ])
                            SignFailure.Timeout
                            "a timeout still wins"
                    }

                    testT
                        "an INTERNAL answer is a failure, not a refusal, and the group signs with the others"
                        (fun () ->
                            task {
                                let groupSecret, shares = shamir 991 2 [ 1UL; 2UL; 3UL ]

                                let runners =
                                    [ for m in 0..2 -> FakeRunner($"r{m + 1}", [ pk groupSecret, snd shares[m] ]) ]

                                let s =
                                    { settings with
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
                                        [ for r, f in List.zip s.Runners runners -> r, f.Api ],
                                        s,
                                        TimeProvider.System,
                                        Log.none
                                    )

                                let! found, _ = set.Discover CancellationToken.None
                                let key = pk groupSecret
                                let b = (Map.ofList found)[key]
                                let req = request key (Duty.Attestation att)

                                for r in runners do
                                    r.Expect req

                                runners[2].Behave(fun _ -> ValueSome(Reply.Refused(refusal 1002us "internal")))

                                let! o = b.Sign req CancellationToken.None
                                Expect.isTrue (verifies key req o) $"two of three sign: {o.Describe}"
                            })
                ]
            testList
                "key list frame limit"
                [
                    test "one PUBLIC_KEYS answer holds 10,082 keys" {
                        Expect.equal Wire.MaxKeysPerFrame 10082 "keys per frame"

                        let answer (n: int) =
                            let keys: Wire.RunnerKey list =
                                [
                                    for i in 1..n ->
                                        {
                                            PubKey = pubkeyOf (i % 4)
                                            SharePubKey = pubkeyOf (i % 4)
                                            Index = uint64 i
                                        }
                                ]

                            Array.append [| 0uy; 0uy |] (Wire.encodeKeys keys)

                        let fits =
                            Wire.encodeFrame
                                (byte Wire.MsgType.PublicKeys ||| Wire.ResponseFlag)
                                1u
                                (ReadOnlySpan(answer Wire.MaxKeysPerFrame))

                        Expect.isLessThanOrEqual (fits.Length - 4) Wire.MaxFrame "the largest list fits"

                        Expect.throws
                            (fun () ->
                                Wire.encodeFrame
                                    (byte Wire.MsgType.PublicKeys ||| Wire.ResponseFlag)
                                    1u
                                    (ReadOnlySpan(answer (Wire.MaxKeysPerFrame + 1)))
                                |> ignore)
                            "one more key does not"
                    }
                    test "a key list over the limit says how many keys and what to do" {
                        // The length a runner with 10,083 keys sends: header, status, count, keys.
                        let length = uint32 (Wire.HeaderLen + 2 + 4 + 10083 * 104)
                        let m = Wire.frameTooLarge length (ValueSome(byte Wire.MsgType.PublicKeys))
                        Expect.stringContains m "10083 keys" "the runner's count"
                        Expect.stringContains m "10082" "the limit"
                        Expect.stringContains m "split the keys" "what to do"
                        let other = Wire.frameTooLarge length (ValueSome(byte Wire.MsgType.Sign))
                        Expect.isFalse (other.Contains "keys") "another request: only the size"
                        Expect.stringContains other $"{length}-byte" "the size"
                    }
                ]
        ]
