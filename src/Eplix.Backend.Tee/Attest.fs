/// The attestation check of a runner's IDENTITY, ported from the Go reference client
/// (tee-signer's attestation-verify and its runnerclient package): the document's user data must bind the identity and the nonce, the
/// platform verifier checks the document against the pinned values, then the setup and key
/// release pins.
/// Verifiers: dev (unsigned, local runners), azure-maa (MAA token for an SEV-SNP container),
/// aws-nitro (NSM COSE_Sign1 document), gcp-cs (Confidential Space token). Every one fails
/// closed. The Go code is the test oracle (tests/Eplix.Tests/TeeVerifierTests.fs).
module Eplix.Backend.Tee.Attest

open System
open System.Collections.Generic
open System.Globalization
open System.Net.Http
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Json
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks
open Eplix.Backend.Tee.Jwt
open Eplix.Backend.Tee.Wire

// ---- settings ----------------------------------------------------------------

/// The network the VC runs on, for the key release rule: on mainnet an azure-maa or aws-nitro
/// runner needs key_release_sha256; on other networks it is optional. GCP runners have no key release hash.
[<RequireQualifiedAccess>]
type NetworkKind =
    | Mainnet
    | Testnet

/// The attestation settings of one runner, with the JSON names of the Go client's
/// runnerclient.Attestation, so one config block serves both.
type Settings =
    {
        Verifier: string
        /// Accepted setup hashes; any one passes (old and new setup during a rotation).
        SetupSha256: string list
        /// Accepted key release policy hashes; any one passes, so a policy rotation needs no restart.
        KeyReleaseSha256: string list
        MinLockedVersion: uint64
        MinOpenVersion: uint64
        AllowUnpinnedSetup: bool
        MaaHost: string
        /// Accepted CCE policy hashes; any one passes (old and new image during a swap).
        CcePolicySha256: string list
        ComplianceStatus: string
        /// Accepted PCR sets; a document passes when it matches every PCR of any one set.
        NitroPcrs: (string * string) list list
        NitroRootSha256: string
        /// Accepted image digests; any one passes.
        GcpImageDigest: string list
        GcpAudience: string
        GcpHwModels: string list
        GcpIssuer: string
        GcpJwksFile: string
        GcpServiceAccount: string
        GcpProjectId: string
    }

    static member Empty =
        {
            Verifier = ""
            SetupSha256 = []
            KeyReleaseSha256 = []
            MinLockedVersion = 0UL
            MinOpenVersion = 0UL
            AllowUnpinnedSetup = false
            MaaHost = ""
            CcePolicySha256 = []
            ComplianceStatus = ""
            NitroPcrs = []
            NitroRootSha256 = ""
            GcpImageDigest = []
            GcpAudience = ""
            GcpHwModels = []
            GcpIssuer = ""
            GcpJwksFile = ""
            GcpServiceAccount = ""
            GcpProjectId = ""
        }

let settingsFields =
    [
        "verifier"
        "setup_sha256"
        "key_release_sha256"
        "min_locked_version"
        "min_open_version"
        "allow_unpinned_setup"
        "maa_host"
        "cce_policy_sha256"
        "compliance_status"
        "nitro_pcrs"
        "nitro_root_sha256"
        "gcp_image_digest"
        "gcp_audience"
        "gcp_hwmodels"
        "gcp_issuer"
        "gcp_jwks_file"
        "gcp_service_account"
        "gcp_project_id"
    ]

/// Reads the settings object. Unknown fields are an error; `path` resolves gcp_jwks_file.
let parseSettings (path: string -> string) (e: JsonElement) : Result<Settings, string> =
    try
        if e.ValueKind <> JsonValueKind.Object then
            failwith "attestation: not an object"

        for p in e.EnumerateObject() do
            if not (List.contains p.Name settingsFields) then
                failwith $"attestation: unknown field \"{p.Name}\""
        // An explicit null is an absent field, as Go's encoding/json reads it.
        let present (n: string) =
            match e.TryGetProperty n with
            | true, v when v.ValueKind <> JsonValueKind.Null -> true
            | _ -> false

        let str n =
            match (if present n then e.TryGetProperty(n: string) else (false, Unchecked.defaultof<JsonElement>)) with
            | true, v when v.ValueKind = JsonValueKind.String -> (nonNull (v.GetString()))
            | true, _ -> failwith $"attestation.{n}: want a string"
            | _ -> ""

        let u64 n =
            match (if present n then e.TryGetProperty(n: string) else (false, Unchecked.defaultof<JsonElement>)) with
            | true, v when v.ValueKind = JsonValueKind.Number ->
                match v.TryGetUInt64() with
                | true, x -> x
                | _ -> failwith $"attestation.{n}: want an unsigned integer"
            | true, _ -> failwith $"attestation.{n}: want an unsigned integer"
            | _ -> 0UL

        let boolean n =
            match (if present n then e.TryGetProperty(n: string) else (false, Unchecked.defaultof<JsonElement>)) with
            | true, v when v.ValueKind = JsonValueKind.True -> true
            | true, v when v.ValueKind = JsonValueKind.False -> false
            | true, _ -> failwith $"attestation.{n}: want true or false"
            | _ -> false
        // A pin is a string or a non-empty array of strings; an empty string is an absent pin.
        let strs n =
            match (if present n then e.TryGetProperty(n: string) else (false, Unchecked.defaultof<JsonElement>)) with
            | true, v when v.ValueKind = JsonValueKind.String ->
                let x = nonNull (v.GetString())
                if x = "" then [] else [ x ]
            | true, v when v.ValueKind = JsonValueKind.Array ->
                let xs =
                    [
                        for x in v.EnumerateArray() ->
                            if x.ValueKind <> JsonValueKind.String then
                                failwith $"attestation.{n}: want a string or an array of strings"

                            let s = nonNull (x.GetString())

                            if s = "" then
                                failwith $"attestation.{n}: an empty string in the array"

                            s
                    ]

                if xs.IsEmpty then
                    failwith $"attestation.{n}: an empty array pins nothing"

                xs
            | true, _ -> failwith $"attestation.{n}: want a string or an array of strings"
            | _ -> []

        let pcrSet (v: JsonElement) =
            [
                for p in v.EnumerateObject() ->
                    if p.Value.ValueKind <> JsonValueKind.String then
                        failwith "attestation.nitro_pcrs: want hex strings"

                    p.Name, (nonNull (p.Value.GetString()))
            ]

        let pcrs =
            match e.TryGetProperty "nitro_pcrs" with
            | true, v when v.ValueKind = JsonValueKind.Object -> [ pcrSet v ]
            | true, v when v.ValueKind = JsonValueKind.Array ->
                let sets =
                    [
                        for x in v.EnumerateArray() ->
                            if x.ValueKind <> JsonValueKind.Object then
                                failwith "attestation.nitro_pcrs: want an object or an array of objects"

                            pcrSet x
                    ]

                if sets.IsEmpty then
                    failwith "attestation.nitro_pcrs: an empty array pins nothing"

                sets
            | true, v when v.ValueKind = JsonValueKind.Null -> []
            | true, _ -> failwith "attestation.nitro_pcrs: want an object or an array of objects"
            | _ -> []

        let models =
            match e.TryGetProperty "gcp_hwmodels" with
            | true, v when v.ValueKind = JsonValueKind.Array ->
                [
                    for x in v.EnumerateArray() ->
                        if x.ValueKind <> JsonValueKind.String then
                            failwith "attestation.gcp_hwmodels: want strings"

                        (nonNull (x.GetString()))
                ]
            | true, v when v.ValueKind = JsonValueKind.Null -> []
            | true, _ -> failwith "attestation.gcp_hwmodels: want an array"
            | _ -> []

        let jwks = str "gcp_jwks_file"

        Ok
            {
                Verifier = str "verifier"
                SetupSha256 = strs "setup_sha256"
                KeyReleaseSha256 = strs "key_release_sha256"
                MinLockedVersion = u64 "min_locked_version"
                MinOpenVersion = u64 "min_open_version"
                AllowUnpinnedSetup = boolean "allow_unpinned_setup"
                MaaHost = str "maa_host"
                CcePolicySha256 = strs "cce_policy_sha256"
                ComplianceStatus = str "compliance_status"
                NitroPcrs = pcrs
                NitroRootSha256 = str "nitro_root_sha256"
                GcpImageDigest = strs "gcp_image_digest"
                GcpAudience = str "gcp_audience"
                GcpHwModels = models
                GcpIssuer = str "gcp_issuer"
                GcpJwksFile = (if jwks = "" then "" else path jwks)
                GcpServiceAccount = str "gcp_service_account"
                GcpProjectId = str "gcp_project_id"
            }
    with Failure m ->
        Error m

// ---- constants ---------------------------------------------------------------

let ComplianceAci = "azure-compliant-uvm"
let ComplianceCvm = "azure-compliant-cvm"
let ConfidentialSpaceIssuer = "https://confidentialcomputing.googleapis.com"
let StsAudience = "https://sts.googleapis.com"
let DefaultSkew = TimeSpan.FromMinutes 1.0

/// The AWS Nitro Enclaves root certificate G1 (attest/nitro.go NitroRootPEM), pinned by its
/// SHA-256 as AWS prints it.
let NitroRootPem =
    "-----BEGIN CERTIFICATE-----\n\
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\n\
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\n\
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\n\
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\n\
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\n\
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n\
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\n\
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\n\
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\n\
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\n\
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\n\
IwLz3/Y=\n\
-----END CERTIFICATE-----\n"

let NitroRootSha256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

let private nitroRootDer =
    lazy
        (let pem =
            NitroRootPem
                .Replace("-----BEGIN CERTIFICATE-----", "")
                .Replace("-----END CERTIFICATE-----", "")
                .Replace("\n", "")

         let der = Convert.FromBase64String pem

         if Convert.ToHexStringLower(SHA256.HashData der) <> NitroRootSha256 then
             failwith "the pinned AWS Nitro root does not match its SHA-256"

         der)

// ---- the platform checks -------------------------------------------------------

/// The keys a JWT verifier uses: fetched from the issuer (OIDC discovery) and cached, or pinned.
type KeySource =
    abstract Get: unknownKey: bool * CancellationToken -> Task<KeySet>

/// The key set could not be fetched (no answer, a timeout, an HTTP error status): an outage of
/// the provider, not a failed check. An attestation source treats it as unavailable.
type KeySetUnavailable(message: string, inner: exn | null) =
    inherit Exception(message, inner)

/// A document check: nonce, the user data the caller computed, the attestation, the time.
type DocumentCheck = byte[] -> byte[] -> Wire.Attestation -> DateTimeOffset -> CancellationToken -> Task<unit>

let private isHex32 (s: string) = s.Length = 64 && s |> Seq.forall Char.IsAsciiHexDigit

let private bytesEq (a: byte[]) (b: byte[]) = ReadOnlySpan(a).SequenceEqual(ReadOnlySpan b)

/// The checks a document check makes before any key: this platform and format, binding the
/// user data the caller expects (runnerclient checkUserData).
let private checkUserData (userData: byte[]) (a: Wire.Attestation) (platform: string) (format: string) (what: string) =
    if a.Platform <> platform || a.Format <> format then
        fail "platform" $"platform \"{a.Platform}\" format \"{a.Format}\" is not {what}"

    if userData.Length = 0 || not (bytesEq a.UserData userData) then
        fail "user-data" "attestation user data is not the one expected"

/// Decodes a JSON string as Go's encoding/json decodes []byte: standard base64 with padding, CR
/// and LF skipped; null gives empty.
let private goBytes (e: JsonElement) : byte[] =
    match e.ValueKind with
    | JsonValueKind.Null -> [||]
    | JsonValueKind.String ->
        try
            Convert.FromBase64String((nonNull (e.GetString())).Replace("\r", "").Replace("\n", ""))
        with :? FormatException ->
            fail "format" "dev document: bad base64"
    | _ -> fail "format" "dev document: want a base64 string"

/// The dev platform's unsigned document {"nonce": base64, "user_data": base64}. It proves
/// nothing about the code that made it; local runners only.
let devCheck: DocumentCheck =
    fun nonce userData a _ _ ->
        checkUserData userData a "dev" "dev-json" "the dev platform's document"

        let doc =
            try
                JsonDocument.Parse(ReadOnlyMemory a.Document)
            with :? JsonException as e ->
                fail "format" $"dev document: {e.Message}"

        use doc = doc
        let root = doc.RootElement

        let n, u =
            match root.ValueKind with
            | JsonValueKind.Object ->
                let get name =
                    match goField root name with
                    | ValueSome v -> goBytes v
                    | ValueNone -> [||]

                get "nonce", get "user_data"
            | JsonValueKind.Null -> [||], [||]
            | _ -> fail "format" "dev document: not an object"

        if not (bytesEq n nonce) || not (bytesEq u a.UserData) then
            fail "nonce" "dev document does not carry the nonce and user data"

        Task.FromResult()

let private containsFold (list: string list) (s: string) =
    list |> List.exists (fun e -> String.Equals(e, s, StringComparison.OrdinalIgnoreCase))

/// Runs `check` with the key set; on an unknown key id once more with a fresh set, as the Go
/// key source does after a provider rotated its keys.
let private withKeys (keys: KeySource) (ct: CancellationToken) (check: KeySet -> unit) : Task<unit> =
    task {
        let! ks = keys.Get(false, ct)

        try
            check ks
        with :? AttestError as e when e.Kind = "unknown-key" ->
            let! fresh = keys.Get(true, ct)

            if obj.ReferenceEquals(fresh, ks) then
                raise e

            check fresh
    }

/// An MAA token (attest.VerifyMAA with the options runnerclient sets): RS256 by the provider,
/// issuer, TEE type sevsnpvm, compliance status, debug off, VMPL 0, host data (the CCE policy
/// hash) and the report data = SHA-256(runtime data) followed by 32 zero bytes.
let maaToken
    (issuer: string)
    (compliance: string)
    (hostData: string list)
    (runtimeData: byte[])
    (token: string)
    (ks: KeySet)
    (now: DateTimeOffset)
    =
    use doc = Jwt.verify token ks
    let c = Claims(doc.RootElement)
    checkStandard c issuer "" now DefaultSkew
    let attType = c.StrOr "x-ms-attestation-type"

    let pre =
        if attType = "azurevm" then
            match c.Path "x-ms-isolation-tee" with
            | ValueSome v when v.ValueKind = JsonValueKind.Object -> "x-ms-isolation-tee."
            | _ -> fail "format" "azurevm token without x-ms-isolation-tee"
        else
            ""

    if c.StrOr(pre + "x-ms-attestation-type") <> "sevsnpvm" then
        fail "claim" "TEE type is not sevsnpvm"

    if c.StrOr(pre + "x-ms-compliance-status") <> compliance then
        fail "claim" $"x-ms-compliance-status is not {compliance}"

    match c.Bool(pre + "x-ms-sevsnpvm-is-debuggable") with
    | ValueSome false -> ()
    | ValueSome true -> fail "debug" "x-ms-sevsnpvm-is-debuggable is true"
    | ValueNone -> fail "debug" "no boolean x-ms-sevsnpvm-is-debuggable"

    match c.Int(pre + "x-ms-sevsnpvm-vmpl") with
    | ValueSome 0L -> ()
    | _ ->
        let got = c.Raw(pre + "x-ms-sevsnpvm-vmpl")
        fail "claim" $"x-ms-sevsnpvm-vmpl {got}, want 0"

    let host = c.StrOr(pre + "x-ms-sevsnpvm-hostdata")

    if not (containsFold hostData host) then
        fail "measurement" $"x-ms-sevsnpvm-hostdata \"{host}\" is not the pinned CCE policy hash"

    let want = Convert.ToHexStringLower(SHA256.HashData runtimeData) + String('0', 64)

    if not (String.Equals(c.StrOr(pre + "x-ms-sevsnpvm-reportdata"), want, StringComparison.OrdinalIgnoreCase)) then
        fail "nonce" "x-ms-sevsnpvm-reportdata is not sha256 of the runtime data"

let private csSupport = "STABLE"

/// A Confidential Space token (attest.VerifyConfidentialSpace with the options runnerclient
/// sets): issuer, audience, CONFIDENTIAL_SPACE, debug disabled since boot, secure boot, STABLE
/// support, hardware model, image digest, service account and project when pinned, and the
/// eat_nonce hex(user data).
let csToken
    (issuer: string)
    (audience: string)
    (imageDigests: string list)
    (hwModels: string list)
    (serviceAccount: string)
    (projectId: string)
    (nonce: string)
    (token: string)
    (ks: KeySet)
    (now: DateTimeOffset)
    =
    use doc = Jwt.verify token ks
    let c = Claims(doc.RootElement)
    checkStandard c issuer audience now DefaultSkew

    if c.StrOr "swname" <> "CONFIDENTIAL_SPACE" then
        fail "claim" "swname is not CONFIDENTIAL_SPACE"

    match c.StrOr "dbgstat" with
    | "disabled-since-boot" -> ()
    | s -> fail "debug" $"dbgstat \"{s}\", want disabled-since-boot"

    match c.Bool "secboot" with
    | ValueSome true -> ()
    | _ -> fail "claim" "secboot is not true"

    let support = c.StrList "submods.confidential_space.support_attributes" |> ValueOption.defaultValue []

    if not (List.contains csSupport support) then
        fail "claim" "support_attributes lack STABLE"

    let model = c.StrOr "hwmodel"

    if not (List.contains model hwModels) then
        fail "claim" $"hwmodel \"{model}\" is not accepted"

    if not (List.contains (c.StrOr "submods.container.image_digest") imageDigests) then
        fail "measurement" "image_digest is not a pinned one"

    if serviceAccount <> "" then
        let accounts = c.StrList "google_service_accounts" |> ValueOption.defaultValue []

        if not (List.contains serviceAccount accounts) then
            fail "claim" $"google_service_accounts lack {serviceAccount}"

    if projectId <> "" && c.StrOr "submods.gce.project_id" <> projectId then
        fail "claim" $"submods.gce.project_id is not {projectId}"

    let nonces = c.StrList "eat_nonce" |> ValueOption.defaultValue []

    if not (List.contains nonce nonces) then
        fail "nonce" "eat_nonce lacks the identity's user data"

// ---- AWS Nitro -----------------------------------------------------------------

/// What VerifyNitro checks a document against.
type NitroOptions =
    {
        /// PCR index to expected value. Required, non-empty.
        Pcrs: (int * byte[]) list
        Nonce: byte[] voption
        UserData: byte[] voption
        /// Trust anchors as DER; empty means the pinned AWS root.
        Roots: byte[] list
        Now: DateTimeOffset
    }

type NitroDocument =
    {
        ModuleId: string
        Timestamp: DateTimeOffset
        Pcrs: Map<int, byte[]>
        UserData: byte[]
        Nonce: byte[]
    }

let private formatErr msg = fail "format" msg

let private bytesOf (what: string) (item: Cbor.Item) : byte[] =
    match item with
    | Cbor.Bytes b -> b
    // CBOR null and undefined decode to a nil slice in Go.
    | Cbor.Simple 22uy
    | Cbor.Simple 23uy -> [||]
    | _ -> formatErr $"{what}: not a byte string"

let private decodeCose (doc: byte[]) =
    let b = if doc.Length > 0 && doc[0] = 0xd2uy then doc[1..] else doc

    let elements =
        try
            Cbor.arrayElements Cbor.strict b
        with :? Cbor.CborError as e ->
            formatErr $"COSE_Sign1: {e.Message}"

    if elements.Length <> 4 then
        formatErr $"COSE_Sign1 has {elements.Length} elements, want 4"

    let el i = fst elements[i]

    let bstr i =
        match el i with
        | Cbor.Bytes b -> b
        | _ -> formatErr $"COSE_Sign1 element {i} is not a byte string"

    let prot, payload, signature = bstr 0, bstr 2, bstr 3

    match el 1 with
    | Cbor.Map entries ->
        for k, _ in entries do
            match k with
            | Cbor.UInt v when v <= uint64 Int64.MaxValue -> ()
            | Cbor.NegInt v when v <= uint64 Int64.MaxValue -> ()
            | _ -> formatErr "COSE_Sign1 unprotected header is not a map"
    | _ -> formatErr "COSE_Sign1 unprotected header is not a map"

    let hdr =
        try
            Cbor.decode Cbor.strict prot
        with :? Cbor.CborError as e ->
            formatErr $"protected header: {e.Message}"

    let entries =
        match hdr with
        | Cbor.Map e -> e
        | Cbor.Simple 22uy -> []
        | _ -> formatErr "protected header is not a map"

    let intKey (k: Cbor.Item) =
        match k with
        | Cbor.UInt v when v <= uint64 Int64.MaxValue -> int64 v
        | Cbor.NegInt v when v < uint64 Int64.MaxValue -> -1L - int64 v
        | _ -> formatErr "protected header key is not an integer"

    let byKey = entries |> List.map (fun (k, v) -> intKey k, v)

    match byKey |> List.tryFind (fun (k, _) -> k = 1L) with
    | None -> formatErr "protected header has no alg"
    | Some(_, Cbor.NegInt 34UL) -> ()
    | Some(_, (Cbor.UInt _ | Cbor.NegInt _)) -> formatErr "alg is not ES384 (-35)"
    | Some _ -> formatErr "protected header alg is not an integer"

    if byKey |> List.exists (fun (k, _) -> k = 2L) then
        formatErr "protected header has crit, not supported"

    if payload.Length = 0 then
        formatErr "empty or detached payload"

    if signature.Length <> 96 then
        formatErr $"signature is {signature.Length} bytes, want 96 (ES384)"

    prot, payload, signature

type private NitroPayload =
    {
        ModuleId: string
        Timestamp: uint64
        Digest: string
        Pcrs: Map<uint64, byte[]>
        Certificate: byte[]
        CaBundle: byte[] list
        PublicKey: byte[]
        UserData: byte[]
        Nonce: byte[]
    }

let private decodePayload (b: byte[]) : NitroPayload =
    let item =
        try
            Cbor.decode
                { Cbor.strict with
                    AllowIndefinite = true
                }
                b
        with :? Cbor.CborError as e ->
            formatErr $"payload: {e.Message}"

    let entries =
        match item with
        | Cbor.Map e -> e
        | Cbor.Simple 22uy -> []
        | _ -> formatErr "payload: not a map"

    let field (name: string) =
        entries
        |> List.tryPick (fun (k, v) ->
            match k with
            | Cbor.Text s when s = name -> Some v
            | _ -> None)

    let textOf name =
        match field name with
        | None
        | Some(Cbor.Simple 22uy) -> ""
        | Some(Cbor.Text s) -> s
        | Some _ -> formatErr $"payload: {name} is not a text string"

    let bytesField name =
        match field name with
        | None -> [||]
        | Some v -> bytesOf $"payload: {name}" v

    let p =
        {
            ModuleId = textOf "module_id"
            Timestamp =
                match field "timestamp" with
                | None
                | Some(Cbor.Simple 22uy) -> 0UL
                | Some(Cbor.UInt v) -> v
                | Some _ -> formatErr "payload: timestamp is not an unsigned integer"
            Digest = textOf "digest"
            Pcrs =
                match field "pcrs" with
                | None
                | Some(Cbor.Simple 22uy) -> Map.empty
                | Some(Cbor.Map m) ->
                    m
                    |> List.map (fun (k, v) ->
                        match k with
                        | Cbor.UInt i -> i, bytesOf "payload: pcr" v
                        | _ -> formatErr "payload: pcr index is not an unsigned integer")
                    |> Map.ofList
                | Some _ -> formatErr "payload: pcrs is not a map"
            Certificate = bytesField "certificate"
            CaBundle =
                match field "cabundle" with
                | None
                | Some(Cbor.Simple 22uy) -> []
                | Some(Cbor.Array a) -> a |> List.map (bytesOf "payload: cabundle")
                | Some _ -> formatErr "payload: cabundle is not an array"
            PublicKey = bytesField "public_key"
            UserData = bytesField "user_data"
            Nonce = bytesField "nonce"
        }

    if p.ModuleId = "" then
        formatErr "no module_id"

    if p.Timestamp = 0UL then
        formatErr "no timestamp"

    if p.Digest <> "SHA384" then
        formatErr $"digest \"{p.Digest}\", want SHA384"

    if p.Pcrs.IsEmpty then
        formatErr "no pcrs"

    if p.Certificate.Length = 0 || p.Certificate.Length > 1024 then
        formatErr $"certificate size {p.Certificate.Length}"

    if p.CaBundle.IsEmpty then
        formatErr "empty cabundle"

    if p.PublicKey.Length > 1024 || p.UserData.Length > 1024 || p.Nonce.Length > 1024 then
        formatErr "public_key, user_data or nonce over 1024 bytes"

    p.CaBundle
    |> List.iteri (fun i c ->
        if c.Length = 0 || c.Length > 1024 then
            formatErr $"cabundle[{i}] size {c.Length}")

    for KeyValue(i, v) in p.Pcrs do
        if i > 31UL then
            formatErr $"pcr index {i}"

        if v.Length <> 48 then
            formatErr $"pcr{i} is {v.Length} bytes, want 48 (SHA384)"

    for i in 0UL .. 8UL do
        if not (p.Pcrs.ContainsKey i) then
            formatErr $"pcr{i} missing"

    p

/// Chains the signing certificate to a pinned root at `now`: cabundle[0] must be one of the
/// roots byte for byte, the rest of the bundle are intermediates.
let private verifyChain (p: NitroPayload) (roots: byte[] list) (now: DateTimeOffset) : X509Certificate2 =
    let roots = if roots.IsEmpty then [ nitroRootDer.Value ] else roots

    if not (roots |> List.exists (fun r -> bytesEq r p.CaBundle.Head)) then
        fail "chain" "cabundle[0] is not a pinned root"

    let load (what: string) (der: byte[]) =
        try
            X509CertificateLoader.LoadCertificate der
        with :? CryptographicException as e ->
            formatErr $"{what}: {e.Message}"
    // The roots and intermediates are only for the build; the caller owns the leaf.
    let loaded = ResizeArray<X509Certificate2>()

    try
        let inter =
            p.CaBundle.Tail
            |> List.mapi (fun i d ->
                let c = load $"cabundle[{i + 1}]" d
                loaded.Add c
                c)

        let leaf = load "certificate" p.Certificate
        // The leaf goes to the caller only when the chain holds; on every other path it is
        // disposed here.
        let mutable trusted = false

        try
            use chain = new X509Chain()
            let cp = chain.ChainPolicy
            cp.TrustMode <- X509ChainTrustMode.CustomRootTrust

            for r in roots do
                let c = X509CertificateLoader.LoadCertificate r
                loaded.Add c
                cp.CustomTrustStore.Add c |> ignore

            for c in inter do
                cp.ExtraStore.Add c |> ignore

            cp.RevocationMode <- X509RevocationMode.NoCheck
            cp.DisableCertificateDownloads <- true
            cp.VerificationTime <- now.UtcDateTime
            cp.VerificationTimeIgnored <- false

            if not (chain.Build leaf) then
                let why = String.Join("; ", [ for s in chain.ChainStatus -> s.StatusInformation.Trim() ])
                fail "chain" $"certificate chain not trusted: {why}"

            trusted <- true
            leaf
        finally
            if not trusted then
                leaf.Dispose()
    finally
        for c in loaded do
            c.Dispose()

/// Verifies an NSM attestation document (attest.VerifyNitro): COSE_Sign1 structure, the chain
/// to the pinned root, the ES384 signature, then debug mode, PCRs, nonce, user data and the
/// timestamp (not after now plus the skew).
let verifyNitro (doc: byte[]) (o: NitroOptions) : NitroDocument =
    if o.Pcrs.IsEmpty then
        fail "config" "no expected PCRs"

    if o.Nonce.IsNone then
        fail "config" "set Nonce or MaxAge"

    let prot, payload, signature = decodeCose doc
    let p = decodePayload payload
    use leaf = verifyChain p o.Roots o.Now

    use pub =
        match leaf.GetECDsaPublicKey() with
        | null -> fail "signature" "signing certificate key is not ECDSA P-384"
        | k -> k

    if pub.KeySize <> 384 then
        fail "signature" "signing certificate key is not ECDSA P-384"

    let curve = pub.ExportParameters(false).Curve

    if not curve.IsNamed || (curve.Oid.Value <> "1.3.132.0.34" && curve.Oid.FriendlyName <> "nistP384") then
        fail "signature" "signing certificate key is not ECDSA P-384"

    let hash = SHA384.HashData(Cbor.sigStructure prot payload)

    let ok =
        try
            pub.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
        with _ ->
            false

    if not ok then
        fail "signature" "COSE_Sign1 signature does not verify"

    let pcrs = p.Pcrs |> Seq.map (fun (KeyValue(k, v)) -> int k, v) |> Map.ofSeq
    let zero (b: byte[]) = b |> Array.forall (fun x -> x = 0uy)

    if zero pcrs[0] && zero pcrs[1] && zero pcrs[2] then
        fail "debug" "PCR0, PCR1 and PCR2 are zero (enclave started with --debug-mode)"

    for i, want in o.Pcrs do
        match pcrs.TryFind i with
        | Some got when bytesEq got want -> ()
        | _ -> fail "measurement" $"pcr{i} is not the expected value"

    match o.Nonce with
    | ValueSome n when not (bytesEq p.Nonce n) -> fail "nonce" "document nonce is not the expected one"
    | _ -> ()

    match o.UserData with
    | ValueSome u when not (bytesEq p.UserData u) -> fail "user-data" "document user_data is not the expected one"
    | _ -> ()

    let ts = DateTimeOffset.FromUnixTimeMilliseconds(int64 (min p.Timestamp (uint64 Int64.MaxValue / 2UL)))

    if ts > o.Now + DefaultSkew then
        fail "stale" $"timestamp {ts:u} is after now"

    {
        ModuleId = p.ModuleId
        Timestamp = ts
        Pcrs = pcrs
        UserData = p.UserData
        Nonce = p.Nonce
    }

// ---- key sources -------------------------------------------------------------

/// Verifies against each accepted PCR set in turn (old and new image during a swap). Only a
/// PCR mismatch moves on to the next set; any other failure ends the check.
let verifyNitroAny (doc: byte[]) (sets: (int * byte[]) list list) (o: NitroOptions) : NitroDocument =
    let rec go (rest: (int * byte[]) list list) =
        match rest with
        | [] -> fail "config" "no expected PCRs"
        | [ last ] -> verifyNitro doc { o with Pcrs = last }
        | set :: more ->
            try
                verifyNitro doc { o with Pcrs = set }
            with :? AttestError as x when x.Kind = "measurement" ->
                go more

    go sets

/// Key sets from the issuer's OIDC discovery document, cached for an hour; a token under an
/// unknown key id fetches again, at most every 30 s (runnerclient keySource).
type DiscoveredKeys(name: string, issuer: string, http: HttpClient) =
    let gate = new SemaphoreSlim(1, 1)
    let mutable cached: KeySet voption = ValueNone
    let mutable at = DateTimeOffset.MinValue

    let get (url: string) (ct: CancellationToken) =
        task {
            if not (url.StartsWith "https://") then
                failwith $"refusing non-https URL {url}"

            use! resp = http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
            let status = int resp.StatusCode

            if status >= 300 && status < 400 then
                let target =
                    match resp.Headers.Location with
                    | null -> "no location"
                    | l -> l.OriginalString

                raise (
                    KeySetUnavailable(
                        $"{url}: HTTP {status}, a redirect to {Eplix.Threshold.cleanReason target}; redirects are not followed",
                        null
                    )
                )

            if status <> 200 then
                raise (KeySetUnavailable($"{url}: HTTP {status}", null))

            use! stream = resp.Content.ReadAsStreamAsync ct
            use ms = new IO.MemoryStream()
            let buf = Array.zeroCreate<byte> 65536
            let mutable n = 1

            while n > 0 do
                let! k = stream.ReadAsync(buf, 0, buf.Length, ct)
                n <- k
                ms.Write(buf, 0, k)

                if ms.Length > (1L <<< 20) then
                    failwith $"{url}: response over 1 MiB"

            return ms.ToArray()
        }

    let fetch (ct: CancellationToken) =
        task {
            let iss = issuer.TrimEnd '/'
            let! cfg = get (iss + "/.well-known/openid-configuration") ct
            use doc = JsonDocument.Parse(ReadOnlyMemory cfg)

            let s (n: string) =
                match goField doc.RootElement n with
                | ValueSome v when v.ValueKind = JsonValueKind.String -> (nonNull (v.GetString()))
                | _ -> ""

            let named: string = s "issuer"

            if named.TrimEnd('/') <> iss then
                fail "issuer" $"openid-configuration names issuer \"{named}\", want \"{iss}\""

            let! jwks = get (s "jwks_uri") ct
            return parseJwks jwks
        }

    interface KeySource with
        member _.Get(unknownKey, ct) =
            task {
                do! gate.WaitAsync ct

                try
                    let age = DateTimeOffset.UtcNow - at

                    match cached with
                    | ValueSome ks when
                        age < TimeSpan.FromHours 1.0 && not (unknownKey && age >= TimeSpan.FromSeconds 30.0)
                        ->
                        return ks
                    | _ ->
                        try
                            let! ks = fetch ct
                            cached <- ValueSome ks
                            at <- DateTimeOffset.UtcNow
                            return ks
                        with
                        | :? AttestError as e -> return raise e
                        // No answer, a timeout or an error status: an outage, not a failed check.
                        | :? KeySetUnavailable
                        | :? HttpRequestException
                        | :? OperationCanceledException
                        | :? IO.IOException as e ->
                            return raise (KeySetUnavailable($"{name} key set of {issuer}: {e.Message}", e))
                        | e -> return fail "keys" $"{name} key set of {issuer}: {e.Message}"
                finally
                    gate.Release() |> ignore
            }

/// A key set given by the caller (gcp_jwks_file, tests).
type PinnedKeys(ks: KeySet) =
    interface KeySource with
        member _.Get(_, _) = Task.FromResult ks

// ---- the verifier --------------------------------------------------------------

let private hostRe =
    Regex(@"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$", RegexOptions.CultureInvariant)

let private projectRe = Regex(@"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", RegexOptions.CultureInvariant)

/// The setup pins (runnerclient setup.go), checked on the setup state of a verified identity.
type Pins =
    {
        /// Accepted setup hashes; empty: no setup pinned.
        Setup: Eplix.Root list
        MinLocked: uint64
        MinOpen: uint64
        AllowUnpinned: bool
        /// The dev verifier: a runner on the flag path passes without a setup pin. A cloud
        /// verifier reaches such a runner only with its hash pinned, since it has no approvers and
        /// a client CA its host chose.
        Dev: bool
        /// Accepted key release hashes; empty: any key release hash passes.
        KeyRelease: Eplix.Root list
    }

/// The version of a config group in force at `now`: a pending update counts once its effective
/// activation time has passed (runnerclient EffectiveVersion).
let effectiveVersion (g: Wire.ConfigGroup) (now: DateTimeOffset) =
    let unixNow = uint64 (max (now.ToUnixTimeSeconds()) 0L)
    if g.Pending.Version <> 0UL && not (g.Pending.EffectiveAt > unixNow) then g.Pending.Version else g.Version

let private joinHex (rs: Eplix.Root list) = String.Join(" or ", rs |> List.map (fun r -> r.Hex))

let checkPins (p: Pins) (s: Wire.SetupState) (now: DateTimeOffset) =
    match p.Setup with
    | [] when not s.FlagPath && not p.AllowUnpinned ->
        fail
            "setup"
            $"the runner reports setup {s.SetupHash.Hex} and no setup_sha256 is pinned; pin the hash of the setup you built"
    | [] when s.FlagPath && not p.Dev ->
        fail
            "setup"
            $"the runner has no setup and no setup_sha256 is pinned (config hash {s.SetupHash.Hex}); a cloud verifier reaches a flag path runner only with its hash pinned"
    | [] -> ()
    | pins when not (List.contains s.SetupHash pins) ->
        fail "setup" $"the runner's setup_hash {s.SetupHash.Hex} is not the pinned setup_sha256 {joinHex pins}"
    | _ -> ()

    if not p.KeyRelease.IsEmpty && not (List.contains s.KeyReleaseHash p.KeyRelease) then
        let what =
            if s.KeyReleaseHash = Eplix.Root.Zero then
                "reports no key release policy (key_release_hash zero)"
            else
                $"has key_release_hash {s.KeyReleaseHash.Hex}"

        fail "key-release" $"the runner {what}, not the pinned key_release_sha256 {joinHex p.KeyRelease}"

    let locked = effectiveVersion s.Locked now

    if locked < p.MinLocked then
        fail "setup" $"the runner's locked config is at version {locked}, below min_locked_version {p.MinLocked}"

    let opn = effectiveVersion s.Open now

    if opn < p.MinOpen then
        fail "setup" $"the runner's open config is at version {opn}, below min_open_version {p.MinOpen}"

/// A checked verifier: the platform's document check and the setup pins.
type Verifier =
    {
        Name: string
        Document: DocumentCheck
        Pins: Pins
    }

/// Checks the settings as runnerclient does (the verifier name, settings of another verifier,
/// the platform's required values, the setup settings) and builds the verifier. `keys` gives
/// the key source of an issuer for azure-maa and gcp-cs (the tests pass pinned sets);
/// `nitroRoots` replaces the AWS root in tests only. `net` decides whether the key release pin
/// is required.
let build
    (net: NetworkKind)
    (a: Settings)
    (keys: string -> string -> KeySource)
    (nitroRoots: byte[] list)
    : Result<Verifier, string> =
    try
        match a.Verifier with
        | "" -> failwith "attestation.verifier: not set, want \"dev\", \"azure-maa\", \"aws-nitro\" or \"gcp-cs\""
        | "dev"
        | "azure-maa"
        | "aws-nitro"
        | "gcp-cs" -> ()
        | v ->
            failwith
                $"attestation.verifier: unknown verifier \"{v}\", want \"dev\", \"azure-maa\", \"aws-nitro\" or \"gcp-cs\""
        // The dev verifier checks no platform evidence: test networks only.
        if a.Verifier = "dev" && net = NetworkKind.Mainnet then
            failwith
                "attestation.verifier: \"dev\" checks no platform evidence and is for test networks; not on mainnet"

        let groups =
            [
                "azure-maa",
                "maa_host, cce_policy_sha256 and compliance_status",
                a.MaaHost <> "" || not a.CcePolicySha256.IsEmpty || a.ComplianceStatus <> ""
                "aws-nitro", "nitro_pcrs and nitro_root_sha256", not a.NitroPcrs.IsEmpty || a.NitroRootSha256 <> ""
                "gcp-cs",
                "gcp_image_digest, gcp_audience, gcp_hwmodels, gcp_issuer, gcp_jwks_file, gcp_service_account and gcp_project_id",
                not a.GcpImageDigest.IsEmpty
                || a.GcpAudience <> ""
                || not a.GcpHwModels.IsEmpty
                || a.GcpIssuer <> ""
                || a.GcpJwksFile <> ""
                || a.GcpServiceAccount <> ""
                || a.GcpProjectId <> ""
            ]

        for v, names, set in groups do
            if set && v <> a.Verifier then
                failwith $"attestation: {names} belong to the verifier \"{v}\", not \"{a.Verifier}\""

        let document: DocumentCheck =
            match a.Verifier with
            | "dev" -> devCheck
            | "azure-maa" ->
                let host = a.MaaHost.ToLowerInvariant()

                if host = "" then
                    failwith
                        "attestation.maa_host: not set (the attestation provider, e.g. sharedweu.weu.attest.azure.net)"

                if not (hostRe.IsMatch host) || host.Contains '\n' then
                    failwith $"attestation.maa_host: \"{a.MaaHost}\" is not a host name (no scheme, no path)"

                let issuer = "https://" + host
                let cce = a.CcePolicySha256 |> List.map (fun c -> c.ToLowerInvariant())

                if cce.IsEmpty then
                    failwith
                        "attestation.cce_policy_sha256: not set (the expected x-ms-sevsnpvm-hostdata, the SHA-256 of the CCE policy)"

                for c in cce do
                    if not (isHex32 c) then
                        failwith "attestation.cce_policy_sha256: want 64 hex digits"

                let compliance =
                    match a.ComplianceStatus with
                    | "" -> ComplianceAci
                    | c when c = ComplianceAci || c = ComplianceCvm -> c
                    | c ->
                        failwith
                            $"attestation.compliance_status: \"{c}\", want \"{ComplianceAci}\" or \"{ComplianceCvm}\""

                let ks = keys "MAA" issuer

                fun _ userData att now ct ->
                    checkUserData userData att "azure" "azure-maa-jwt" "an Azure MAA token"

                    withKeys ks ct (fun k ->
                        maaToken
                            issuer
                            compliance
                            cce
                            (Wire.maaRuntimeData userData)
                            (Encoding.UTF8.GetString att.Document)
                            k
                            now)
            | "aws-nitro" ->
                if a.NitroPcrs.IsEmpty then
                    failwith
                        "attestation.nitro_pcrs: not set (the expected PCR0, PCR1 and PCR2 of the enclave image, 96 hex digits each)"

                let pcrSet (set: (string * string) list) =
                    let pcrs =
                        [
                            for k, v in set |> List.sortBy fst ->
                                let idx =
                                    match
                                        Int32.TryParse(k, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture)
                                    with
                                    | true, i when i >= 0 && i <= 31 && string i = k -> i
                                    | _ ->
                                        failwith
                                            $"attestation.nitro_pcrs: key \"{k}\" is not a PCR index (0 to 31, plain decimal)"

                                let lv = v.ToLowerInvariant()

                                if lv.Length <> 96 || not (lv |> Seq.forall Char.IsAsciiHexDigit) then
                                    failwith $"attestation.nitro_pcrs: pcr{idx} want 96 hex digits (SHA-384)"

                                idx, Convert.FromHexString lv
                        ]

                    for i in 0..2 do
                        match pcrs |> List.tryFind (fun (j, _) -> j = i) with
                        | None -> failwith $"attestation.nitro_pcrs: pcr{i} not set (PCR0, PCR1 and PCR2 are required)"
                        | Some(_, v) when v |> Array.forall (fun x -> x = 0uy) ->
                            failwith $"attestation.nitro_pcrs: pcr{i} is all zero, the value of a debug-mode enclave"
                        | _ -> ()

                    pcrs

                let sets = a.NitroPcrs |> List.map pcrSet

                if a.NitroRootSha256 <> "" then
                    let r = a.NitroRootSha256.ToLowerInvariant()

                    if not (isHex32 r) then
                        failwith "attestation.nitro_root_sha256: want 64 hex digits"

                    if r <> NitroRootSha256 then
                        failwith
                            $"attestation.nitro_root_sha256: this build pins the AWS Nitro root {NitroRootSha256}, not {r}"

                fun nonce userData att now _ ->
                    checkUserData userData att "nitro" "aws-nitro-cose-sign1" "an AWS Nitro document"

                    verifyNitroAny
                        att.Document
                        sets
                        {
                            Pcrs = []
                            Nonce = ValueSome nonce
                            UserData = ValueSome userData
                            Roots = nitroRoots
                            Now = now
                        }
                    |> ignore

                    Task.FromResult()
            | _ ->
                if a.GcpImageDigest.IsEmpty then
                    failwith "attestation.gcp_image_digest: not set (the expected image digest, sha256:HEX)"

                let digests =
                    [
                        for d in a.GcpImageDigest ->
                            let d = d.ToLowerInvariant()
                            let d = if d.StartsWith "sha256:" then d.Substring 7 else d

                            if not (isHex32 d) then
                                failwith "attestation.gcp_image_digest: want sha256: and 64 hex digits"

                            "sha256:" + d
                    ]

                let aud = a.GcpAudience

                if aud = "" then
                    failwith
                        "attestation.gcp_audience: not set (the runner's attest_audience, default signer-runner-identity)"

                if aud = StsAudience then
                    failwith
                        $"attestation.gcp_audience: \"{aud}\" is the STS audience; a token with it is a credential for the KMS key"

                if aud.StartsWith "//iam.googleapis.com/" || aud.StartsWith "https://iam.googleapis.com/" then
                    failwith $"attestation.gcp_audience: \"{aud}\" names a Workload Identity Federation resource"

                if a.GcpHwModels.IsEmpty then
                    failwith
                        "attestation.gcp_hwmodels: not set (the accepted hwmodel claims, for example GCP_AMD_SEV or GCP_INTEL_TDX)"

                for m in a.GcpHwModels do
                    if m = "" || m.Trim() <> m then
                        failwith $"attestation.gcp_hwmodels: \"{m}\" is not a hwmodel name"

                    if String.Equals(m, "GCP_SHIELDED_VM", StringComparison.OrdinalIgnoreCase) then
                        failwith "attestation.gcp_hwmodels: GCP_SHIELDED_VM is a VM without memory encryption"

                let issuer = if a.GcpIssuer = "" then ConfidentialSpaceIssuer else a.GcpIssuer

                let issuerOk =
                    match Uri.TryCreate(issuer, UriKind.Absolute) with
                    | true, (NonNull u) ->
                        // Go's url.Parse lower-cases the scheme; the path must be empty, not "/".
                        let afterScheme = issuer.Substring(issuer.IndexOf "://" + 3)

                        u.Scheme = "https"
                        && u.Host <> ""
                        && u.UserInfo = ""
                        && not (afterScheme.Contains '/')
                        && not (issuer.Contains '?' || issuer.Contains '#')
                        && issuer.Contains "://"
                    | _ -> false

                if not issuerOk then
                    failwith
                        $"attestation.gcp_issuer: \"{issuer}\" is not an https URL without a path or a trailing slash"

                if
                    a.GcpServiceAccount <> ""
                    && (not (a.GcpServiceAccount.Contains '@')
                        || a.GcpServiceAccount.IndexOfAny [| ' '; '\t'; '\r'; '\n' |] >= 0)
                then
                    failwith
                        $"attestation.gcp_service_account: \"{a.GcpServiceAccount}\" is not a service account e-mail address"

                if
                    a.GcpProjectId <> "" && not (projectRe.IsMatch a.GcpProjectId && not (a.GcpProjectId.Contains '\n'))
                then
                    failwith
                        $"attestation.gcp_project_id: \"{a.GcpProjectId}\" is not a project ID (6 to 30 of a-z, 0-9 and -)"

                let ks =
                    if a.GcpJwksFile <> "" then
                        let b =
                            try
                                IO.File.ReadAllBytes a.GcpJwksFile
                            with :? IO.IOException as e ->
                                failwith $"attestation.gcp_jwks_file: {e.Message}"

                        try
                            PinnedKeys(parseJwks b) :> KeySource
                        with :? AttestError as e ->
                            failwith $"attestation.gcp_jwks_file: {e.Message}"
                    else
                        keys "Confidential Space" issuer

                let models = a.GcpHwModels

                fun _ userData att now ct ->
                    checkUserData userData att "gcp" "gcp-confidential-space-jwt" "a Confidential Space token"
                    let token = Encoding.UTF8.GetString att.Document

                    withKeys ks ct (fun k ->
                        csToken
                            issuer
                            aud
                            digests
                            models
                            a.GcpServiceAccount
                            a.GcpProjectId
                            (Convert.ToHexStringLower userData)
                            token
                            k
                            now)

        let hashes (field: string) (what: string) (xs: string list) =
            [
                for x in xs ->
                    let h = x.ToLowerInvariant()
                    let h = if h.StartsWith "0x" then h.Substring 2 else h

                    if not (isHex32 h) then
                        failwith $"attestation.{field}: want 64 hex digits, {what}"

                    Eplix.Root.Of(Convert.FromHexString h)
            ]

        let setup = hashes "setup_sha256" "the setup_sha256 that setup-tool prints" a.SetupSha256

        if setup.IsEmpty && a.MinLockedVersion <> 0UL then
            failwith "attestation.min_locked_version: needs setup_sha256, since versions count within one setup"

        if setup.IsEmpty && a.MinOpenVersion <> 0UL then
            failwith "attestation.min_open_version: needs setup_sha256, since versions count within one setup"

        if a.AllowUnpinnedSetup && not setup.IsEmpty then
            failwith
                "attestation.allow_unpinned_setup: not with setup_sha256; pin the setup or allow unpinned ones, not both"

        if a.AllowUnpinnedSetup && a.Verifier <> "dev" then
            failwith $"attestation.allow_unpinned_setup: for tests with the dev verifier only, not \"{a.Verifier}\""
        // The rule of the signer's own client: required on mainnet for the platforms whose
        // runners release keys under a policy (Azure SKR, AWS KMS), optional elsewhere, and never
        // for Confidential Space, whose runners report zero.
        let keyRelease =
            hashes "key_release_sha256" "the key_release_hash the runner reports in IDENTITY" a.KeyReleaseSha256

        if keyRelease |> List.contains Eplix.Root.Zero then
            failwith
                "attestation.key_release_sha256: all zero is what a runner without a key release policy reports; it pins nothing"

        match a.Verifier with
        | "gcp-cs" when not keyRelease.IsEmpty ->
            failwith
                "attestation.key_release_sha256: not for gcp-cs; Confidential Space runners report no key release hash"
        | "azure-maa"
        | "aws-nitro" when keyRelease.IsEmpty && net = NetworkKind.Mainnet ->
            failwith
                $"attestation.key_release_sha256: required on mainnet for {a.Verifier}; pin the key_release_hash of the runner's key release policy"
        | _ -> ()
        // tee-signer's rule: the runner reads its key rule per setup, so a key release pin needs
        // a setup pin.
        if not keyRelease.IsEmpty && setup.IsEmpty then
            failwith "attestation.key_release_sha256: needs setup_sha256, since the key rule is read per setup"

        Ok
            {
                Name = a.Verifier
                Document = document
                Pins =
                    {
                        Setup = setup
                        MinLocked = a.MinLockedVersion
                        MinOpen = a.MinOpenVersion
                        AllowUnpinned = a.AllowUnpinnedSetup
                        Dev = (a.Verifier = "dev")
                        KeyRelease = keyRelease
                    }
            }
    with
    | Failure m -> Error m
    | :? AttestError as e -> Error e.Message

/// build, and a cloud verifier must pin a setup. checkPins refuses every runner of a cloud
/// verifier without setup_sha256 (a setup runner because nothing is pinned, a flag path runner
/// because only the dev verifier lets one pass), so such a config would start and never sign.
/// build alone keeps tee-signer's settings check, which allows it.
let buildUsable
    (net: NetworkKind)
    (a: Settings)
    (keys: string -> string -> KeySource)
    (nitroRoots: byte[] list)
    : Result<Verifier, string> =
    match build net a keys nitroRoots with
    | Ok v when not v.Pins.Dev && v.Pins.Setup.IsEmpty ->
        Error
            $"attestation.setup_sha256: required with the {v.Name} verifier; without it every runner is refused at the setup check"
    | r -> r

/// Checks the identity a runner gave for `nonce`: the document binds the identity's fields and
/// the nonce, the platform check passes, the setup pins pass. Throws AttestError otherwise.
let verifyIdentity
    (v: Verifier)
    (nonce: byte[])
    (id: Wire.Identity)
    (now: DateTimeOffset)
    (ct: CancellationToken)
    : Task<unit> =
    task {
        let ud = Wire.identityUserData nonce id

        if not (bytesEq id.Attestation.UserData ud) then
            fail "user-data" "attestation user data does not match the identity fields and nonce"

        do! v.Document nonce ud id.Attestation now ct
        checkPins v.Pins id.State now
    }
