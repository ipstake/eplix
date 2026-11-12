/// The attestation verifiers against tee-signer's Go verifiers as a test oracle. The Go code
/// (module attestation-verify: runnerclient/verify for settings and identities,
/// attest.VerifyNitro for Nitro documents) ran on every case of
/// tests/fixtures/tee/oracle-vectors.json and recorded its verdict; Eplix must reach the same
/// one. All inputs are synthetic. tests/tools/tee-oracle makes the file; EPLIX_TEE_ORACLE names
/// another one.
module Eplix.Tests.TeeVerifierTests

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix.Backend.Tee
open Eplix.Tests.TestUtil

let private file =
    match Environment.GetEnvironmentVariable "EPLIX_TEE_ORACLE" with
    | null
    | "" -> Path.Combine(fixtures, "tee", "oracle-vectors.json")
    | p -> p

/// Settings cases where Eplix is stricter than Go's encoding/json on purpose: the config is
/// strict (unknown fields fail the start, names are case-sensitive), so these are refused.
let stricter =
    set
        [
            "verifier JSON key upper case (encoding/json matches names case-insensitively)"
            "nitro JSON keys in mixed case accepted"
            "unknown JSON field ignored"
        ]

/// A key source over the case's key set. A key set that does not parse fails the verification,
/// as a failed fetch does in Go.
type private CaseKeys(jwks: JsonElement voption) =
    interface Attest.KeySource with
        member _.Get(_, _) =
            task {
                match jwks with
                | ValueSome j -> return Jwt.parseJwks (Encoding.UTF8.GetBytes(j.GetRawText()))
                | ValueNone -> return Jwt.fail "keys" "no key set"
            }

let private settingsOf (e: JsonElement) = Attest.parseSettings id e

let private opt (e: JsonElement) (n: string) =
    match e.TryGetProperty n with
    | true, v when v.ValueKind <> JsonValueKind.Null -> ValueSome v
    | _ -> ValueNone

let private str (e: JsonElement) (n: string) =
    match opt e n with
    | ValueSome v -> v.GetString() |> Wire.nonNull
    | ValueNone -> ""

/// The verdict of Eplix on one identity case, with the parsed settings changed by `f` first,
/// and its reason.
let identityVerdictWith (f: Attest.Settings -> Attest.Settings) (c: JsonElement) : bool * string =
    match settingsOf (c.GetProperty "attestation") with
    | Error m -> false, $"settings: {m}"
    | Ok s ->
        let keys = CaseKeys(opt c "jwks")

        match Attest.build Attest.NetworkKind.Testnet (f s) (fun _ _ -> keys :> Attest.KeySource) [] with
        | Error m -> false, $"settings: {m}"
        | Ok v ->
            try
                let id = Wire.decodeIdentity (Convert.FromHexString(str c "identity"))
                let now = DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64())

                (Attest.verifyIdentity v (Convert.FromHexString(str c "nonce")) id now CancellationToken.None)
                    .GetAwaiter()
                    .GetResult()

                true, ""
            with e ->
                false, e.Message

/// The verdict of Eplix on one identity case, and its reason.
let identityVerdict (c: JsonElement) : bool * string = identityVerdictWith id c

let nitroVerdict (c: JsonElement) : bool * string =
    try
        let pcrs =
            match opt c "pcrs" with
            | ValueSome p ->
                [
                    for x in p.EnumerateObject() ->
                        int x.Name, Convert.FromHexString(x.Value.GetString() |> Wire.nonNull)
                ]
            | ValueNone -> []

        let bytesOpt n =
            match opt c n with
            | ValueSome v -> ValueSome(Convert.FromHexString(v.GetString() |> Wire.nonNull))
            | ValueNone -> ValueNone

        let roots =
            match opt c "roots_pem" with
            | ValueSome r ->
                [
                    for p in r.EnumerateArray() ->
                        let pem: string = p.GetString() |> Wire.nonNull
                        use cert = Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(pem.AsSpan())
                        cert.RawData
                ]
            | ValueNone -> []

        let o: Attest.NitroOptions =
            {
                Pcrs = pcrs
                Nonce = bytesOpt "nonce"
                UserData = bytesOpt "user_data"
                Roots = roots
                Now = DateTimeOffset.FromUnixTimeMilliseconds(c.GetProperty("now_ms").GetInt64())
            }

        Attest.verifyNitro (Convert.FromHexString(str c "document")) o |> ignore
        true, ""
    with e ->
        false, e.Message

let private load () =
    let doc = JsonDocument.Parse(File.ReadAllText file)
    doc.RootElement

/// Runs every case of a section and fails with the list of disagreements.
let private compare
    (section: string)
    (verdict: JsonElement -> bool * string)
    (expected: JsonElement -> bool)
    (skip: string -> bool)
    =
    let root = load ()
    let cases = [ for c in root.GetProperty(section).EnumerateArray() -> c ]
    Expect.isGreaterThan cases.Length 10 $"{section}: cases"

    let disagree =
        [
            for c in cases do
                let name = str c "name"

                if not (skip name) then
                    let ok, why = verdict c
                    let want = expected c

                    if ok <> want then
                        let goErr = str c "error"
                        let verb b = if b then "accepts" else "refuses"
                        let g, e = verb want, verb ok
                        $"{name}: Go {g} ({goErr}), Eplix {e} ({why})"
        ]

    if not disagree.IsEmpty then
        failtestf "%d of %d %s disagree:\n%s" disagree.Length cases.Length section (String.Join("\n", disagree))

    cases.Length

[<Tests>]
let tests =
    testList
        "tee-oracle"
        [
            test "settings: the same configs are valid and refused as in Go" {
                let n =
                    compare
                        "settings_cases"
                        (fun c ->
                            match settingsOf (c.GetProperty "attestation") with
                            | Error m -> false, m
                            | Ok s ->
                                match
                                    Attest.build
                                        Attest.NetworkKind.Testnet
                                        s
                                        (fun _ _ ->
                                            Attest.PinnedKeys(Jwt.KeySet(Collections.Generic.Dictionary()))
                                            :> Attest.KeySource)
                                        []
                                with
                                | Ok _ -> true, ""
                                | Error m -> false, m)
                        (fun c -> c.GetProperty("valid").GetBoolean())
                        stricter.Contains

                Expect.isGreaterThan n 100 "cases"
            }

            test "settings: Eplix refuses the field names Go matches loosely" {
                let root = load ()

                for c in root.GetProperty("settings_cases").EnumerateArray() do
                    if stricter.Contains(str c "name") then
                        Expect.isTrue
                            (match settingsOf (c.GetProperty "attestation") with
                             | Error _ -> true
                             | Ok _ -> false)
                            (str c "name")
            }

            test "identity: dev, azure-maa and gcp-cs identities get Go's verdict" {
                let n = compare "identity_cases" identityVerdict (fun c -> str c "expect" = "ok") (fun _ -> false)
                Expect.isGreaterThan n 150 "cases"
            }

            test "pin lists: old and new pins pass when either matches; a wrong pin alone is refused" {
                let wrongCce = String('1', 64)
                let wrongDigest = "sha256:" + String('2', 64)
                let root = load ()
                let mutable azure = 0
                let mutable gcp = 0

                for c in root.GetProperty("identity_cases").EnumerateArray() do
                    if str c "expect" = "ok" then
                        let name = str c "name"

                        match settingsOf (c.GetProperty "attestation") with
                        | Ok s when s.Verifier = "azure-maa" ->
                            azure <- azure + 1

                            let ok, why =
                                identityVerdictWith
                                    (fun s ->
                                        { s with
                                            CcePolicySha256 = wrongCce :: s.CcePolicySha256
                                        })
                                    c

                            Expect.isTrue ok $"{name}: wrong then right CCE hash: {why}"

                            let ok2, why2 =
                                identityVerdictWith
                                    (fun s ->
                                        { s with
                                            CcePolicySha256 = s.CcePolicySha256 @ [ wrongCce ]
                                        })
                                    c

                            Expect.isTrue ok2 $"{name}: right then wrong CCE hash: {why2}"

                            let bad, msg =
                                identityVerdictWith
                                    (fun s ->
                                        { s with
                                            CcePolicySha256 = [ wrongCce ]
                                        })
                                    c

                            Expect.isFalse bad $"{name}: a wrong CCE hash alone"
                            Expect.stringContains msg "CCE policy" "refused for the measurement"
                        | Ok s when s.Verifier = "gcp-cs" ->
                            gcp <- gcp + 1

                            let ok, why =
                                identityVerdictWith
                                    (fun s ->
                                        { s with
                                            GcpImageDigest = wrongDigest :: s.GcpImageDigest
                                        })
                                    c

                            Expect.isTrue ok $"{name}: wrong then right digest: {why}"

                            let bad, msg =
                                identityVerdictWith
                                    (fun s ->
                                        { s with
                                            GcpImageDigest = [ wrongDigest ]
                                        })
                                    c

                            Expect.isFalse bad $"{name}: a wrong digest alone"
                            Expect.stringContains msg "image_digest" "refused for the measurement"
                        | _ -> ()

                Expect.isGreaterThan azure 0 "azure cases"
                Expect.isGreaterThan gcp 0 "gcp cases"
            }

            test "pin lists: nitro passes with any one matching PCR set and fails with only wrong ones" {
                let root = load ()
                let mutable n = 0

                for c in root.GetProperty("nitro_cases").EnumerateArray() do
                    let hasPcrs =
                        match opt c "pcrs" with
                        | ValueSome _ -> true
                        | ValueNone -> false

                    if str c "expect" = "ok" && hasPcrs then
                        n <- n + 1

                        let right =
                            [
                                for x in (c.GetProperty "pcrs").EnumerateObject() ->
                                    int x.Name, Convert.FromHexString(x.Value.GetString() |> Wire.nonNull)
                            ]

                        let wrong = right |> List.map (fun (i, v) -> i, Array.map (fun (b: byte) -> b ^^^ 0xffuy) v)

                        let bytesOpt n =
                            match opt c n with
                            | ValueSome v -> ValueSome(Convert.FromHexString(v.GetString() |> Wire.nonNull))
                            | ValueNone -> ValueNone

                        let roots =
                            match opt c "roots_pem" with
                            | ValueSome r ->
                                [
                                    for p in r.EnumerateArray() ->
                                        let pem: string = p.GetString() |> Wire.nonNull

                                        use cert =
                                            Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(
                                                pem.AsSpan()
                                            )

                                        cert.RawData
                                ]
                            | ValueNone -> []

                        let o: Attest.NitroOptions =
                            {
                                Pcrs = []
                                Nonce = bytesOpt "nonce"
                                UserData = bytesOpt "user_data"
                                Roots = roots
                                Now = DateTimeOffset.FromUnixTimeMilliseconds(c.GetProperty("now_ms").GetInt64())
                            }

                        let doc = Convert.FromHexString(str c "document")
                        Attest.verifyNitroAny doc [ wrong; right ] o |> ignore
                        Attest.verifyNitroAny doc [ right; wrong ] o |> ignore

                        let refused =
                            try
                                Attest.verifyNitroAny doc [ wrong ] o |> ignore
                                false
                            with :? Jwt.AttestError as e ->
                                e.Kind = "measurement"

                        let name = str c "name"
                        Expect.isTrue refused $"{name}: only a wrong PCR set is a measurement refusal"

                Expect.isGreaterThan n 0 "nitro cases with PCRs"
            }

            test "pin lists: settings take a string or an array; an empty array is refused" {
                let parse (j: string) = settingsOf (JsonDocument.Parse(j).RootElement)
                let h (c: char) = String(c, 64)
                let p (c: char) = String(c, 96)
                let q (x: string) = "\"" + x + "\""

                match
                    parse (
                        "{ \"verifier\": \"azure-maa\", \"maa_host\": \"a.b.attest.azure.net\", \"cce_policy_sha256\": [ "
                        + q (h '1')
                        + ", "
                        + q (h '2')
                        + " ] }"
                    )
                with
                | Ok s -> Expect.equal s.CcePolicySha256 [ h '1'; h '2' ] "two CCE hashes"
                | Error e -> failtest e

                let set3 (a: char) (b: char) (c: char) =
                    "{ \"0\": " + q (p a) + ", \"1\": " + q (p b) + ", \"2\": " + q (p c) + " }"

                match
                    parse (
                        "{ \"verifier\": \"aws-nitro\", \"nitro_pcrs\": [ "
                        + set3 'a' 'b' 'c'
                        + ", "
                        + set3 'd' 'e' 'f'
                        + " ] }"
                    )
                with
                | Ok s -> Expect.equal s.NitroPcrs.Length 2 "two PCR sets"
                | Error e -> failtest e

                match parse ("{ \"verifier\": \"gcp-cs\", \"gcp_image_digest\": " + q ("sha256:" + h '3') + " }") with
                | Ok s -> Expect.equal s.GcpImageDigest [ "sha256:" + h '3' ] "a single digest is a list of one"
                | Error e -> failtest e

                for j, why in
                    [
                        "{ \"verifier\": \"gcp-cs\", \"gcp_image_digest\": [] }", "empty array"
                        "{ \"verifier\": \"aws-nitro\", \"nitro_pcrs\": [] }", "empty array"
                        "{ \"verifier\": \"azure-maa\", \"cce_policy_sha256\": [ 1 ] }", "string"
                    ] do
                    match parse j with
                    | Ok _ -> failtestf "accepted %s" j
                    | Error e -> Expect.stringContains e why why
            }

            test "nitro: synthetic NSM documents get Go's verdict" {
                let n = compare "nitro_cases" nitroVerdict (fun c -> str c "expect" = "ok") (fun _ -> false)
                Expect.isGreaterThan n 50 "cases"
            }
        ]
