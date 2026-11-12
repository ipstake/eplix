/// Domains, signing roots, the local backend, the chain spec checks and the strict config.
module Eplix.Tests.SigningTests

open System
open System.IO
open System.Threading
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil

let private sk1 = hex "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"

let private spec () =
    match ChainSpec.parse (Map.ofList (FakeBeaconNode.specValues 6 8)) with
    | Ok s -> s
    | Error e -> failwith e

[<Tests>]
let tests =
    testList
        "signing"
        [
            test "mainnet deposit domain" {
                // compute_domain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION 0x00000000, zero root): the domain
                // every mainnet deposit is signed under.
                let d =
                    Signing.computeDomain
                        (DomainType.Of [| 3uy; 0uy; 0uy; 0uy |])
                        (ForkVersion.Of [| 0uy; 0uy; 0uy; 0uy |])
                        Root.Zero

                Expect.equal d.Hex "0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9" "domain"
            }

            test "attestation domain uses the fork of the target epoch" {
                let s = spec ()
                let before = Signing.domainAt s FakeBeaconNode.gvr s.DomainBeaconAttester 0UL
                let after = Signing.domainAt s FakeBeaconNode.gvr s.DomainBeaconAttester 1UL
                Expect.notEqual before.Hex after.Hex "Fulu at epoch 1 changes the domain"
                Expect.equal (after.Bytes[0..3]) [| 1uy; 0uy; 0uy; 0uy |] "domain type prefix"

                Expect.equal
                    after
                    (Signing.computeDomain
                        s.DomainBeaconAttester
                        (ForkVersion.Of [| 6uy; 0uy; 0uy; 1uy |])
                        FakeBeaconNode.gvr)
                    "Fulu version"
            }

            testT "local backend signs the signing root of the duty" (fun () ->
                task {
                    let pk = PubKey.Of(Bls.publicKey (ReadOnlySpan sk1))
                    let backend = LocalBackend.create "local" [ pk, SecretKey.Copy(ReadOnlySpan sk1) ]
                    let s = spec ()

                    let data =
                        {
                            Slot = 9UL
                            Index = 0UL
                            BeaconBlockRoot = root 9
                            Source = { Epoch = 0UL; Root = root 0 }
                            Target = { Epoch = 1UL; Root = root 8 }
                        }

                    let domain = Signing.domainAt s FakeBeaconNode.gvr s.DomainBeaconAttester 1UL

                    let req =
                        {
                            Key = pk
                            Duty = Duty.Attestation data
                            Fork =
                                {
                                    Fork =
                                        {
                                            PreviousVersion = (s.ForkAt 0UL).Version
                                            CurrentVersion = (s.ForkAt 1UL).Version
                                            Epoch = 1UL
                                        }
                                    GenesisValidatorsRoot = FakeBeaconNode.gvr
                                }
                            Domain = domain
                            SigningRoot = Signing.computeSigningRoot (Codec.hashAttestationData data) domain
                            Priority = Priority.High
                            Deadline = DateTimeOffset.MaxValue
                        }

                    let! outcome = backend.Sign req CancellationToken.None

                    match outcome with
                    | Signed sg ->
                        let signingRoot = Signing.computeSigningRoot (Codec.hashAttestationData data) domain

                        Expect.isTrue
                            (Bls.verify
                                (ReadOnlySpan pk.Bytes)
                                (ReadOnlySpan signingRoot.Bytes)
                                (ReadOnlySpan sg.Bytes))
                            "verifies"
                    | other -> failtestf "expected a signature, got %A" other

                    let! unknown =
                        backend.Sign
                            { req with
                                Key = PubKey.Of(Array.zeroCreate 48)
                            }
                            CancellationToken.None

                    Expect.equal unknown (Refused UnknownKey) "unknown key is a typed refusal"
                    do! backend.Dispose()
                })

            test "pinned config: equal values pass, a different fork epoch fails" {
                let pinned = ChainSpec.parseConfigYaml (FakeBeaconNode.configYaml 6 8)
                let node = Map.ofList (FakeBeaconNode.specValues 6 8)
                Expect.isOk (ChainSpec.checkPinned pinned node) "same chain"
                let other = node.Add("FULU_FORK_EPOCH", "2")
                Expect.isError (ChainSpec.checkPinned pinned other) "fork epoch differs"
                Expect.isError (ChainSpec.checkPinned (pinned.Remove "FULU_FORK_EPOCH") node) "missing from the pin"
            }

            test "config.yaml subset parser" {
                let m = ChainSpec.parseConfigYaml "# c\nA: 1 # x\nB: '0x01'\nBLOB_SCHEDULE:\n  - EPOCH: 5\nC: \"x\"\n"
                Expect.equal m (Map.ofList [ "A", "1"; "B", "0x01"; "C", "x" ]) "flat keys only"
            }

            test "strict config refuses unknown fields and modules" {
                let text =
                    """{ "beacon_node": "http://localhost:5052", "chain_config": "c.yaml", "data_dir": "d",
                       "colour": "blue", "modules": { "dirk": {} } }"""

                match Config.parse text "/tmp" [ "local" ] with
                | Error es ->
                    Expect.contains es "config: unknown field 'colour'" "unknown field"
                    Expect.contains es "modules: 'dirk' is not a module in this build" "unknown module"
                | Ok _ -> failtest "should fail"
            }

            test "config with defaults" {
                let text =
                    """{ "beacon_node": "http://localhost:5052", "chain_config": "c.yaml", "data_dir": "d",
                       "allow_start_without_history": ["all"], "modules": { "local": { "keystores": [] } } }"""

                match Config.parse text "/srv/eplix" [ "local" ] with
                | Ok c ->
                    Expect.equal c.DataDir "/srv/eplix/d" "relative path"
                    Expect.isTrue (c.AllowStartWithoutHistory.Allows(PubKey.Of(Array.zeroCreate 48))) "all"
                    Expect.equal c.RequestTimeout (TimeSpan.FromSeconds 4.0) "default timeout"
                | Error es -> failtestf "%A" es
            }

            test "local module refuses unknown fields in its section" {
                let m = LocalModule.create ()

                let section =
                    {
                        Element = ValueSome(Text.Json.JsonDocument.Parse("""{ "keystore": [] }""").RootElement.Clone())
                        BaseDir = "/tmp"
                        Mainnet = false
                    }

                Expect.isError (m.Configure section) "typo in field name"
            }
        ]
