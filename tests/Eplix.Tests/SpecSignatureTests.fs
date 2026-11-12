/// V5: signatures made by the pyspec in consensus-spec-tests v1.7.0-beta.4 (Gloas, minimal), checked
/// with Eplix's own domains and signing roots: valid operations and gossip messages must verify,
/// messages rejected for their signature must not. A differential test of Signing.fs and Duty.fs
/// against the pyspec. Vectors in tests/vectors/spec_signatures_gloas (operations voluntary_exit,
/// proposer_slashing, attester_slashing; gossip payload_attestation_message, proposer_preferences,
/// execution_payload_envelope, voluntary_exit, beacon_attestation, beacon_aggregate_and_proof).
module Eplix.Tests.SpecSignatureTests

open System
open System.Buffers.Binary
open System.IO
open Expecto
open Eplix
open Eplix.Tests.TestUtil

let private root = Path.Combine(vectors, "spec_signatures_gloas")
let private p = Preset.Minimal

let private read (file: string) = Snappy.decompress (File.ReadAllBytes file)

let private decode (schema: Ssz.SszType) (bytes: byte[]) =
    match Ssz.deserialize schema bytes with
    | Ok v -> v
    | Error e -> failtestf "decode: %s" e

/// From a minimal BeaconState (Gloas): genesis validators root, fork, and the validators' keys.
/// The fields before `validators` are fixed size: genesis_time 8, genesis_validators_root 32,
/// slot 8, fork 16, latest_block_header 112, block_roots and state_roots 64 x 32 each,
/// historical_roots (offset), eth1_data 72, eth1_data_votes (offset), eth1_deposit_index 8, then
/// the offsets of validators and balances; a Validator is 121 bytes, its pubkey first.
type private StateInfo =
    {
        Gvr: Root
        Previous: ForkVersion
        Current: ForkVersion
        ForkEpoch: Epoch
        Keys: PubKey[]
    }

let private stateInfo (state: byte[]) =
    let validatorsOffset = 8 + 32 + 8 + 16 + 112 + 2048 + 2048 + 4 + 72 + 4 + 8
    let start = int (BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(state, validatorsOffset, 4)))
    let stop = int (BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(state, validatorsOffset + 4, 4)))

    if (stop - start) % 121 <> 0 then
        failtestf "validators: %d bytes" (stop - start)

    {
        Gvr = Root.Of state[8..39]
        Previous = ForkVersion.Of state[48..51]
        Current = ForkVersion.Of state[52..55]
        ForkEpoch = BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(state, 56, 8))
        Keys =
            [|
                for i in 0 .. (stop - start) / 121 - 1 -> PubKey.Of state[start + 121 * i .. start + 121 * i + 47]
            |]
    }

/// A spec with the minimal config's fork versions. Forks before Gloas at epoch 0; Gloas at the
/// state's fork epoch when the state's current version is Gloas's.
let private specFor (s: StateInfo) =
    let v n = $"0x0{n}000001"

    let values =
        [
            "PRESET_BASE", "minimal"
            "SECONDS_PER_SLOT", "6"
            "GENESIS_FORK_VERSION", "0x00000001"
            for i, name in
                [
                    1, "ALTAIR"
                    2, "BELLATRIX"
                    3, "CAPELLA"
                    4, "DENEB"
                    5, "ELECTRA"
                    6, "FULU"
                ] do
                $"{name}_FORK_VERSION", v i
                $"{name}_FORK_EPOCH", "0"
            "GLOAS_FORK_VERSION", v 7
            "GLOAS_FORK_EPOCH", string s.ForkEpoch
        ]

    let spec =
        match ChainSpec.parse (Map.ofList values) with
        | Ok x -> x
        | Error e -> failwith e

    Expect.equal s.Current (spec.ForkAt s.ForkEpoch).Version "the state's fork is the Gloas fork of this spec"
    spec

let private verifyDuty (spec: ChainSpec) (gvr: Root) (key: PubKey) (duty: Duty) (signature: byte[]) =
    let r = Duty.request spec gvr key Priority.Low DateTimeOffset.MaxValue duty
    Bls.verify (ReadOnlySpan key.Bytes) (ReadOnlySpan r.SigningRoot.Bytes) (ReadOnlySpan signature)

let private headerOf (v: Ssz.SszValue) =
    let f = Codec.fields v

    {
        Slot = Codec.asU f[0]
        ProposerIndex = Codec.asU f[1]
        ParentRoot = Root.Of(Codec.asBytes f[2])
        StateRoot = Root.Of(Codec.asBytes f[3])
        BodyRoot = Root.Of(Codec.asBytes f[4])
    }

/// An operation case: the signatures of a valid one verify; an invalid one is not checked unless
/// its name says the signature is bad, then at least one must fail.
let private operationCase (op: string) (dir: string) =
    let name = Path.GetFileName dir

    test $"operations/{op}/{name}" {
        let valid = File.Exists(Path.Combine(dir, "valid"))
        let badSig = name.Contains "invalid_sig" || name.Contains "bad_sig" || name.Contains "signature"

        if valid || badSig then
            let s = stateInfo (read (Path.Combine(dir, "pre.ssz_snappy")))
            let spec = specFor s
            let key i = s.Keys[int i]

            let checks: bool list =
                match op with
                | "voluntary_exit" ->
                    let v =
                        Codec.fields (
                            decode Schemas.signedVoluntaryExit (read (Path.Combine(dir, "voluntary_exit.ssz_snappy")))
                        )

                    let x = Codec.fields v[0]

                    let exit =
                        {
                            Epoch = Codec.asU x[0]
                            ValidatorIndex = Codec.asU x[1]
                        }

                    [
                        verifyDuty spec s.Gvr (key exit.ValidatorIndex) (Duty.VoluntaryExit exit) (Codec.asBytes v[1])
                    ]
                | "proposer_slashing" ->
                    let v =
                        Codec.fields (
                            decode Schemas.proposerSlashing (read (Path.Combine(dir, "proposer_slashing.ssz_snappy")))
                        )

                    [
                        for signed in [ v[0]; v[1] ] do
                            let f = Codec.fields signed
                            let h = headerOf f[0]

                            if int h.ProposerIndex < s.Keys.Length then
                                verifyDuty spec s.Gvr (key h.ProposerIndex) (Duty.Block h) (Codec.asBytes f[1])
                    ]
                | "attester_slashing" ->
                    let v =
                        Codec.fields (
                            decode
                                Schemas.Gloas.attesterSlashing
                                (read (Path.Combine(dir, "attester_slashing.ssz_snappy")))
                        )

                    [
                        for att in [ v[0]; v[1] ] do
                            let f = Codec.fields att

                            let indices =
                                match f[0] with
                                | Ssz.Items xs -> xs |> Array.map Codec.asU
                                | _ -> [||]

                            let data = Codec.attestationDataOf f[1]

                            if indices.Length > 0 && indices |> Array.forall (fun i -> int i < s.Keys.Length) then
                                let r =
                                    Duty.request
                                        spec
                                        s.Gvr
                                        s.Keys[0]
                                        Priority.Low
                                        DateTimeOffset.MaxValue
                                        (Duty.Attestation data)

                                Bls.fastAggregateVerify
                                    (indices |> Array.map (fun i -> s.Keys[int i].Bytes))
                                    (ReadOnlySpan r.SigningRoot.Bytes)
                                    (ReadOnlySpan(Codec.asBytes f[2]))
                    ]
                | o -> failtestf "operation %s" o

            if valid then
                Expect.isNonEmpty checks "something to check"
                Expect.allEqual checks true "every signature verifies under Eplix's domains"
            elif not checks.IsEmpty then
                Expect.isTrue (checks |> List.exists not) "a bad signature fails"
    }

/// A gossip case: (message file, expected, reason) from meta.yaml.
let private gossipMessages (dir: string) =
    let lines = File.ReadAllText(Path.Combine(dir, "meta.yaml")).Replace("\r", "")
    // Entries look like "{..., message: \n    <name>,\n  expected: valid, reason: ...}".
    let flat = Text.RegularExpressions.Regex.Replace(lines, @"\s+", " ")

    [
        for m in Text.RegularExpressions.Regex.Matches(flat, @"message: (\S+?), expected: (\w+)(, reason: ([^}]*))?\}") ->
            m.Groups[1].Value, m.Groups[2].Value, m.Groups[4].Value
    ]

let private gossipCase (topic: string) (dir: string) =
    let name = Path.GetFileName dir

    test $"gossip/{topic}/{name}" {
        let s = stateInfo (read (Path.Combine(dir, "state.ssz_snappy")))
        let spec = specFor s
        let key i = s.Keys[int i]
        let msgFile (m: string) = read (Path.Combine(dir, m + ".ssz_snappy"))

        for message, expected, reason in gossipMessages dir do
            // "invalid aggregate signature" is the inner aggregate's (committee members'), which
            // needs the committee; the aggregator's own two signatures are checked.
            let signatureCase = reason.Contains "signature" && not (reason.Contains "aggregate signature")

            if expected = "valid" || signatureCase then
                let bytes = msgFile message

                let checks: bool list =
                    match topic with
                    | "gossip_payload_attestation_message" ->
                        let f = Codec.fields (decode Schemas.Gloas.payloadAttestationMessage bytes)
                        let data = Codec.payloadAttestationDataOf f[1]

                        [
                            verifyDuty
                                spec
                                s.Gvr
                                (key (Codec.asU f[0]))
                                (Duty.PayloadAttestation data)
                                (Codec.asBytes f[2])
                        ]
                    | "gossip_proposer_preferences" ->
                        let f = Codec.fields (decode Schemas.Gloas.signedProposerPreferences bytes)
                        let prefs = Codec.proposerPreferencesOf f[0]

                        [
                            verifyDuty
                                spec
                                s.Gvr
                                (key prefs.ValidatorIndex)
                                (Duty.ProposerPreferences prefs)
                                (Codec.asBytes f[1])
                        ]
                    | "gossip_voluntary_exit" ->
                        let f = Codec.fields (decode Schemas.signedVoluntaryExit bytes)
                        let x = Codec.fields f[0]

                        let exit =
                            {
                                Epoch = Codec.asU x[0]
                                ValidatorIndex = Codec.asU x[1]
                            }

                        [
                            verifyDuty
                                spec
                                s.Gvr
                                (key exit.ValidatorIndex)
                                (Duty.VoluntaryExit exit)
                                (Codec.asBytes f[1])
                        ]
                    | "gossip_beacon_attestation" ->
                        let a = Codec.singleAttestationOf (decode Schemas.singleAttestation bytes)

                        [
                            verifyDuty spec s.Gvr (key a.AttesterIndex) (Duty.Attestation a.Data) a.Signature.Bytes
                        ]
                    | "gossip_beacon_aggregate_and_proof" ->
                        let schema = Schemas.Gloas.signedAggregateAndProof p
                        let f = Codec.fields (decode schema bytes)
                        let msg = Codec.fields f[0]
                        let aggregator = Codec.asU msg[0]
                        let data = Codec.attestationDataOf (Codec.fields msg[1]).[1]

                        let m =
                            {
                                Schema = Schemas.Gloas.aggregateAndProof p
                                Value = f[0]
                            }

                        [
                            verifyDuty
                                spec
                                s.Gvr
                                (key aggregator)
                                (Duty.AggregationSlot data.Slot)
                                (Codec.asBytes msg[2])
                            verifyDuty
                                spec
                                s.Gvr
                                (key aggregator)
                                (Duty.AggregateAndProof(data.Slot, m))
                                (Codec.asBytes f[1])
                        ]
                    | "gossip_execution_payload_envelope" ->
                        let schema = Schemas.Gloas.signedExecutionPayloadEnvelope p
                        let f = Codec.fields (decode schema bytes)
                        let env = Codec.fields f[0]
                        let builderIndex = Codec.asU env[2]
                        let blockRoot = Root.Of(Codec.asBytes env[3])
                        // A self-built envelope is signed by the block's proposer, as Eplix signs it.
                        let blockFile = Path.Combine(dir, $"block_{blockRoot.Hex}.ssz_snappy")

                        if builderIndex = UInt64.MaxValue && File.Exists blockFile then
                            let block =
                                Codec.fields
                                    (Codec.fields (decode (Schemas.Gloas.signedBeaconBlock p) (read blockFile))).[0]

                            let proposer = Codec.asU block[1]
                            let slot = Codec.asU block[0]

                            [
                                verifyDuty
                                    spec
                                    s.Gvr
                                    (key proposer)
                                    (Duty.PayloadEnvelope(
                                        slot,
                                        {
                                            Schema = Schemas.Gloas.executionPayloadEnvelope p
                                            Value = f[0]
                                        }
                                    ))
                                    (Codec.asBytes f[1])
                            ]
                        else
                            []
                    | t -> failtestf "topic %s" t

                if expected = "valid" then
                    Expect.allEqual checks true $"{message}: verifies under Eplix's domains"
                elif not checks.IsEmpty then
                    Expect.isTrue (checks |> List.exists not) $"{message}: the bad signature fails ({reason})"
    }

let private suite () =
    if not (Directory.Exists root) then
        [ test "vectors present" { failtestf "%s is missing" root } ]
    else
        [
            for op in [ "voluntary_exit"; "proposer_slashing"; "attester_slashing" ] do
                let dir = Path.Combine(root, "operations", op, "pyspec_tests")

                yield
                    testList
                        $"operations {op}"
                        [ for d in Directory.GetDirectories dir |> Array.sort -> operationCase op d ]
            for topic in
                [
                    "gossip_payload_attestation_message"
                    "gossip_proposer_preferences"
                    "gossip_voluntary_exit"
                    "gossip_beacon_attestation"
                    "gossip_beacon_aggregate_and_proof"
                    "gossip_execution_payload_envelope"
                ] do
                let dir = Path.Combine(root, "networking", topic, "pyspec_tests")
                yield testList topic [ for d in Directory.GetDirectories dir |> Array.sort -> gossipCase topic d ]
            yield
                test "the valid cases checked" {
                    let validOps =
                        [
                            for op in [ "voluntary_exit"; "proposer_slashing"; "attester_slashing" ] do
                                yield!
                                    Directory.GetFiles(
                                        Path.Combine(root, "operations", op, "pyspec_tests"),
                                        "valid",
                                        SearchOption.AllDirectories
                                    )
                        ]

                    Expect.isGreaterThan validOps.Length 20 "valid operations"

                    for topic in
                        [
                            "gossip_payload_attestation_message"
                            "gossip_proposer_preferences"
                            "gossip_voluntary_exit"
                            "gossip_beacon_attestation"
                            "gossip_beacon_aggregate_and_proof"
                            "gossip_execution_payload_envelope"
                        ] do
                        let dirs = Directory.GetDirectories(Path.Combine(root, "networking", topic, "pyspec_tests"))

                        let valid =
                            dirs
                            |> Array.sumBy (fun d ->
                                gossipMessages d |> List.filter (fun (_, e, _) -> e = "valid") |> List.length)

                        let badSig =
                            dirs
                            |> Array.sumBy (fun d ->
                                gossipMessages d
                                |> List.filter (fun (_, _, r) -> r.Contains "signature")
                                |> List.length)

                        Expect.isGreaterThan valid 0 $"{topic}: valid messages"
                        Expect.isGreaterThan (valid + badSig) 1 $"{topic}: messages checked"
                }
        ]

[<Tests>]
let tests = testList "signing" [ testList "spec vectors verify under Eplix domains" (suite ()) ]
