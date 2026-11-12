/// Bulk and presigned exits: which keys an exit run signs, one burst for many
/// keys, and the saved files.
module Eplix.Tests.ExitTests

open System
open System.IO
open System.Text.Json
open System.Threading
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private setup (n: int) =
    let registry = KeyRegistry()

    let backend =
        LocalBackend.create "local" [ for i in 0 .. n - 1 -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

    for i in 0 .. n - 1 do
        registry.Add(pubkeyOf i, backend) |> ignore
        registry.SetChainInfo(pubkeyOf i, uint64 (10 + i), "active_ongoing")

    registry

let private openDb () =
    match SlashingDb.Open(new FileMarkFile(Path.Combine(tempDir (), "s.db")), gvr) with
    | Ok db -> db
    | Error e -> failwith e

/// What a key's state and chain info can be for the plan.
type private KeyCase =
    | Plain
    | NoIndex
    | Slashed
    | Draining
    | Halted
    | Exited

let private apply (registry: KeyRegistry) (pk: PubKey) (c: KeyCase) =
    match c with
    | Plain -> ()
    | NoIndex ->
        let k = (registry.TryGet pk).Value
        k.Index <- ValueNone
    | Slashed -> registry.SetState(pk, KeyState.Slashed "test")
    | Draining -> registry.SetState(pk, KeyState.Draining)
    | Halted -> registry.SetState(pk, KeyState.Halted "test")
    | Exited -> registry.SetChainInfo(pk, 99UL, "exited_unslashed")

[<Tests>]
let tests =
    testList
        "exits"
        [
            testCase "--epoch: none is the clock's epoch, one is parsed, a repeat is an error" (fun () ->
                Expect.equal (Exits.parseEpoch None) (Ok ValueNone) "not given"
                Expect.equal (Exits.parseEpoch (Some [ "400000" ])) (Ok(ValueSome 400000UL)) "one value"
                Expect.equal (Exits.parseEpoch (Some [ "x" ])) (Error "--epoch 'x' is not a number") "not a number"

                for values in [ [ "400000"; "400000" ]; [ "1"; "2" ] ] do
                    Expect.equal
                        (Exits.parseEpoch (Some values))
                        (Error "--epoch given more than once")
                        $"repeated: %A{values}")

            testCase "named keys: unknown, no index, slashed and draining fail; duplicates once" (fun () ->
                let registry = setup 5
                apply registry (pubkeyOf 1) NoIndex
                apply registry (pubkeyOf 2) Slashed
                apply registry (pubkeyOf 3) Draining
                apply registry (pubkeyOf 4) Halted

                let plan =
                    Exits.plan
                        registry
                        (Exits.Target.Keys
                            [
                                pubkeyOf 0
                                pubkeyOf 1
                                pubkeyOf 2
                                pubkeyOf 3
                                pubkeyOf 4
                                pubkeyOf 7
                                pubkeyOf 0
                            ])

                Expect.equal
                    (plan |> List.map fst)
                    [ for i in [ 0; 1; 2; 3; 4; 7 ] -> pubkeyOf i ]
                    "in order, once each"

                let at i = plan |> List.find (fun (k, _) -> k = pubkeyOf i) |> snd
                Expect.equal (at 0) (Exits.Plan.Sign 10UL) "a plain key signs"
                Expect.equal (at 4) (Exits.Plan.Sign 14UL) "a halted key may still exit"

                for i in [ 1; 2; 3; 7 ] do
                    Expect.isTrue
                        (match at i with
                         | Exits.Plan.Fail _ -> true
                         | _ -> false)
                        $"key {i} fails")

            testCase "all keys: blocked and exiting keys are skipped, not failed" (fun () ->
                let registry = setup 4
                apply registry (pubkeyOf 1) NoIndex
                apply registry (pubkeyOf 2) Exited
                let plan = Exits.plan registry Exits.Target.All
                Expect.equal (plan |> List.map fst) (plan |> List.map fst |> List.sort) "in key order"
                let at i = plan |> List.find (fun (k, _) -> k = pubkeyOf i) |> snd
                Expect.equal (at 0) (Exits.Plan.Sign 10UL) "key 0"
                Expect.equal (at 3) (Exits.Plan.Sign 13UL) "key 3"

                Expect.isTrue
                    (match at 1 with
                     | Exits.Plan.Skip _ -> true
                     | _ -> false)
                    "no index: skipped"

                Expect.isTrue
                    (match at 2 with
                     | Exits.Plan.Skip _ -> true
                     | _ -> false)
                    "exited: skipped")

            testPropN
                "the plan signs exactly the keys that may exit, each once"
                200
                (let caseGen = Gen.elements [ Plain; NoIndex; Slashed; Draining; Halted; Exited ]

                 Prop.forAll (Arb.fromGen (Gen.listOfLength 6 caseGen)) (fun cases ->
                     let registry = setup 6
                     cases |> List.iteri (fun i c -> apply registry (pubkeyOf i) c)
                     let plan = Exits.plan registry Exits.Target.All

                     let signs i =
                         plan
                         |> List.exists (fun (k, p) ->
                             k = pubkeyOf i
                             && (match p with
                                 | Exits.Plan.Sign _ -> true
                                 | _ -> false))

                     plan.Length = 6
                     && (plan |> List.map fst |> List.distinct).Length = 6
                     && (cases |> List.mapi (fun i c -> signs i = (c = Plain || c = Halted)) |> List.forall id)))

            testT "many keys in one burst, each saved to its own file" (fun () ->
                task {
                    let h = harness ()
                    let registry = setup 3
                    use db = openDb ()
                    let pipeline = Pipeline(db, registry, h.Time, Log.none)
                    let dir = Path.Combine(tempDir (), "exits", "out")
                    let keys = [ for i in 0..2 -> pubkeyOf i, uint64 (10 + i) ]

                    let! signed =
                        Exits.signMany h.Spec gvr pipeline keys 5UL DateTimeOffset.MaxValue CancellationToken.None

                    Expect.equal (signed |> List.map fst) (keys |> List.map fst) "in input order"
                    let capella = h.Spec.Forks |> Array.find (fun f -> f.Name = Capella)
                    let domain = Signing.computeDomain h.Spec.DomainVoluntaryExit capella.Version gvr

                    for pk, r in signed do
                        match r with
                        | Error e -> failtest e
                        | Ok(x, s) ->
                            let path = Exits.save dir pk x s
                            Expect.equal (Path.GetFileName path) (pk.Hex + ".json") "file name"
                            use doc = JsonDocument.Parse(File.ReadAllText path)
                            let m = doc.RootElement.GetProperty "message"
                            Expect.equal (m.GetProperty("epoch").GetString()) "5" "epoch as a decimal string"

                            Expect.equal
                                (m.GetProperty("validator_index").GetString())
                                (string x.ValidatorIndex)
                                "index"

                            let sigHex = doc.RootElement.GetProperty("signature").GetString()
                            let sigFromFile = BlsSignature.Of((Hex.tryDecode (nonNull sigHex)).Value)

                            Expect.isTrue
                                (VcHarness.verifySig
                                    pk
                                    (Signing.computeSigningRoot (Codec.hashVoluntaryExit x) domain)
                                    sigFromFile)
                                "the saved signature verifies"

                            if not (OperatingSystem.IsWindows()) then
                                Expect.equal
                                    (File.GetUnixFileMode path)
                                    (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
                                    "mode 0600"

                    if not (OperatingSystem.IsWindows()) then
                        Expect.equal
                            (File.GetUnixFileMode dir)
                            (UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
                            "directory mode 0700"

                    Expect.equal (Directory.GetFiles dir).Length 3 "three files, no temporary file left"
                    // Saving again replaces the file whole.
                    match snd signed[0] with
                    | Ok(x, s) ->
                        Exits.save dir (fst signed[0]) { x with Epoch = 6UL } s |> ignore

                        Expect.stringContains
                            (File.ReadAllText(Path.Combine(dir, (fst signed[0]).Hex + ".json")))
                            "\"6\""
                            "replaced"
                    | Error e -> failtest e
                })

            testT "a key that cannot sign fails alone in the burst" (fun () ->
                task {
                    let h = harness ()
                    let registry = setup 3
                    use db = openDb ()
                    let pipeline = Pipeline(db, registry, h.Time, Log.none)
                    registry.SetState(pubkeyOf 1, KeyState.Draining)

                    let! signed =
                        Exits.signMany
                            h.Spec
                            gvr
                            pipeline
                            [ for i in 0..2 -> pubkeyOf i, uint64 i ]
                            5UL
                            DateTimeOffset.MaxValue
                            CancellationToken.None

                    Expect.equal
                        (signed |> List.map (fun (_, r) -> Result.isOk r))
                        [ true; false; true ]
                        "only key 1 fails"
                })
        ]
