/// RS256 JSON Web Tokens and key sets, as the Go verifiers read them (attest/jwt.go, jwks.go):
/// RS256 only, the key from the caller's key set by kid (never from the token header), no
/// duplicate JSON members at any depth, nothing after the JSON object.
module Eplix.Backend.Tee.Jwt

open System
open System.Collections.Generic
open System.Globalization
open System.Numerics
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Json
open Eplix.Backend.Tee.Wire

/// Why a token or key set was refused. Kind names the class of the Go sentinel errors
/// (attest/errors.go), so a caller can tell an unknown key from the rest.
type AttestError(kind: string, message: string) =
    inherit Exception(message)
    member _.Kind = kind

let fail kind msg = raise (AttestError(kind, msg))

let maxToken = 256 <<< 10
let maxNumericDate = 253402300799.0

/// base64url without padding, strict about trailing bits; CR and LF are skipped, as Go's
/// decoder does.
let decodeB64Url (s: string) : byte[] =
    let s = s.Replace("\r", "").Replace("\n", "")

    if s.Length % 4 = 1 then
        fail "format" "illegal base64 data"

    for c in s do
        if not (Char.IsAsciiLetterOrDigit c || c = '-' || c = '_') then
            fail "format" "illegal base64 data"

    let padded = s.Replace('-', '+').Replace('_', '/') + String('=', (4 - s.Length % 4) % 4)
    let b = Convert.FromBase64String padded
    // Strict: the unused low bits of the last character must be zero.
    let rem = s.Length % 4

    if rem <> 0 then
        let last = padded[s.Length - 1]
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".IndexOf last
        let mask = if rem = 2 then 0x0f else 0x03

        if v &&& mask <> 0 then
            fail "format" "illegal base64 data"

    b

/// base64url without padding, not strict (Go's RawURLEncoding, for JWK n and e).
let decodeB64UrlLoose (s: string) : byte[] =
    let s = s.Replace("\r", "").Replace("\n", "")

    if s.Length % 4 = 1 || s.Contains '=' then
        raise (FormatException "bad base64")

    for c in s do
        if not (Char.IsAsciiLetterOrDigit c || c = '-' || c = '_') then
            raise (FormatException "bad base64")

    Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/') + String('=', (4 - s.Length % 4) % 4))

/// Refuses duplicate member names at any depth and more than 32 levels (attest/jwt.go).
let rec private checkNoDuplicates (e: JsonElement) (depth: int) =
    if depth > 32 then
        fail "format" "JSON nested too deep"

    match e.ValueKind with
    | JsonValueKind.Object ->
        let seen = HashSet<string>(StringComparer.Ordinal)

        for p in e.EnumerateObject() do
            if not (seen.Add p.Name) then
                fail "format" $"duplicate JSON member \"{p.Name}\""

            checkNoDuplicates p.Value (depth + 1)
    | JsonValueKind.Array ->
        for x in e.EnumerateArray() do
            checkNoDuplicates x (depth + 1)
    | _ -> ()

/// Parses one JSON value with the Go rules: valid UTF-8, nothing after it, no duplicate members.
let parseJson (b: byte[]) : JsonDocument =
    let doc =
        try
            JsonDocument.Parse(ReadOnlyMemory b, JsonDocumentOptions(MaxDepth = 256))
        with :? JsonException as e ->
            fail "format" e.Message

    try
        checkNoDuplicates doc.RootElement 0
        doc
    with _ ->
        doc.Dispose()
        reraise ()

/// A verified token's claims: the payload object.
type Claims(root: JsonElement) =
    member _.Root = root

    /// A dotted claim path ("x-ms-isolation-tee.x-ms-attestation-type").
    member _.Path(p: string) : JsonElement voption =
        let mutable cur = ValueSome root

        for part in p.Split '.' do
            cur <-
                match cur with
                | ValueSome e when e.ValueKind = JsonValueKind.Object ->
                    match e.TryGetProperty part with
                    | true, v -> ValueSome v
                    | _ -> ValueNone
                | _ -> ValueNone

        cur

    member this.Str(p: string) : string voption =
        match this.Path p with
        | ValueSome e when e.ValueKind = JsonValueKind.String -> ValueSome((nonNull (e.GetString())))
        | _ -> ValueNone

    member this.StrOr(p: string) = this.Str p |> ValueOption.defaultValue ""

    member this.Bool(p: string) : bool voption =
        match this.Path p with
        | ValueSome e when e.ValueKind = JsonValueKind.True -> ValueSome true
        | ValueSome e when e.ValueKind = JsonValueKind.False -> ValueSome false
        | _ -> ValueNone

    /// An integer claim, as json.Number.Int64: digits with an optional minus sign only.
    member this.Int(p: string) : int64 voption =
        match this.Path p with
        | ValueSome e when e.ValueKind = JsonValueKind.Number ->
            match Int64.TryParse(e.GetRawText(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
            | true, v -> ValueSome v
            | _ -> ValueNone
        | _ -> ValueNone

    /// A string or an array of strings.
    member this.StrList(p: string) : string list voption =
        match this.Path p with
        | ValueSome e when e.ValueKind = JsonValueKind.String -> ValueSome [ (nonNull (e.GetString())) ]
        | ValueSome e when e.ValueKind = JsonValueKind.Array ->
            let items = [ for x in e.EnumerateArray() -> x ]

            if items |> List.forall (fun x -> x.ValueKind = JsonValueKind.String) then
                ValueSome [ for x in items -> (nonNull (x.GetString())) ]
            else
                ValueNone
        | _ -> ValueNone

    member this.Raw(p: string) =
        match this.Path p with
        | ValueSome e -> e.GetRawText()
        | ValueNone -> "<missing>"

    /// A NumericDate (top level only): seconds since 1970, fractions allowed, 0 to year 9999.
    member _.NumericDate(name: string) : DateTimeOffset voption =
        match root.TryGetProperty name with
        | true, v ->
            if v.ValueKind <> JsonValueKind.Number then
                fail "format" $"{name} is not a number"

            let f =
                match Double.TryParse(v.GetRawText(), NumberStyles.Float, CultureInfo.InvariantCulture) with
                | true, f -> f
                | _ -> fail "format" $"{name} out of range"

            if Double.IsNaN f || f < 0.0 || f > maxNumericDate then
                fail "format" $"{name} out of range"

            let sec = Math.Truncate f
            let ticks = int64 sec * TimeSpan.TicksPerSecond + int64 ((f - sec) * 1e9) / 100L
            ValueSome(DateTimeOffset(DateTime.UnixEpoch.Ticks + ticks, TimeSpan.Zero))
        | _ -> ValueNone

/// The RSA signing keys of one issuer by key id.
type KeySet(keys: IReadOnlyDictionary<string, RSAParameters>) =
    member _.Lookup(kid: string) =
        match keys.TryGetValue kid with
        | true, k -> ValueSome k
        | _ -> ValueNone

    member _.KeyIds = keys.Keys |> Seq.sort |> List.ofSeq

let private trimZeros (b: byte[]) =
    let i = b |> Array.tryFindIndex (fun x -> x <> 0uy) |> Option.defaultValue b.Length
    b[i..]

let private bitLen (n: byte[] | null) =
    let n =
        match n with
        | null -> [||]
        | n -> trimZeros n

    if n.Length = 0 then 0 else (n.Length - 1) * 8 + (32 - BitOperations.LeadingZeroCount(uint32 n[0]))

/// A JSON property by name the way Go's json.Unmarshal finds struct fields: an exact match,
/// else a case-insensitive one; the last occurrence wins.
let goField (e: JsonElement) (name: string) : JsonElement voption =
    let mutable exact = ValueNone
    let mutable folded = ValueNone

    for p in e.EnumerateObject() do
        if p.Name = name then
            exact <- ValueSome p.Value
        elif String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) then
            folded <- ValueSome p.Value

    match exact with
    | ValueSome _ -> exact
    | ValueNone -> folded

/// Reads a JSON Web Key Set (attest.ParseJWKS): RSA keys for signatures (use "sig" or none, alg
/// RS256 or none), each with a kid; n and e must match an x5c certificate when both are there;
/// moduli under 2048 bits are refused.
let parseJwks (b: byte[]) : KeySet =
    use doc =
        try
            JsonDocument.Parse(ReadOnlyMemory b)
        with :? JsonException as e ->
            fail "format" $"jwks: {e.Message}"

    let root = doc.RootElement

    if root.ValueKind <> JsonValueKind.Object && root.ValueKind <> JsonValueKind.Null then
        fail "format" "jwks: not an object"

    let str (k: JsonElement) (n: string) =
        match goField k n with
        | ValueSome v when v.ValueKind = JsonValueKind.String -> (nonNull (v.GetString()))
        | ValueSome v when v.ValueKind = JsonValueKind.Null -> ""
        | ValueSome _ -> fail "format" $"jwks: {n} is not a string"
        | ValueNone -> ""

    let keys = Dictionary<string, RSAParameters>()

    let list =
        if root.ValueKind = JsonValueKind.Null then
            []
        else
            match goField root "keys" with
            | ValueSome v when v.ValueKind = JsonValueKind.Array -> [ for x in v.EnumerateArray() -> x ]
            | ValueSome v when v.ValueKind = JsonValueKind.Null -> []
            | ValueSome _ -> fail "format" "jwks: keys is not an array"
            | ValueNone -> []

    list
    |> List.iteri (fun i k ->
        if k.ValueKind <> JsonValueKind.Object then
            fail "format" $"jwks: key {i} is not an object"

        let kid, kty, alg, used, n, e = str k "kid", str k "kty", str k "alg", str k "use", str k "n", str k "e"

        let x5c =
            match goField k "x5c" with
            | ValueSome v when v.ValueKind = JsonValueKind.Array ->
                [
                    for x in v.EnumerateArray() ->
                        if x.ValueKind <> JsonValueKind.String then
                            fail "format" "jwks: x5c entry is not a string"

                        (nonNull (x.GetString()))
                ]
            | ValueSome v when v.ValueKind = JsonValueKind.Null -> []
            | ValueSome _ -> fail "format" "jwks: x5c is not an array"
            | ValueNone -> []

        if kty = "RSA" && (used = "" || used = "sig") && (alg = "" || alg = "RS256") then
            if kid = "" then
                fail "format" $"jwks key {i} has no kid"

            if keys.ContainsKey kid then
                fail "format" $"jwks has kid \"{kid}\" twice"

            let mutable pub = ValueNone

            if n <> "" || e <> "" then
                let nb =
                    try
                        decodeB64UrlLoose n
                    with _ ->
                        [||]

                if nb.Length = 0 then
                    fail "format" $"jwks kid \"{kid}\": bad n"

                let eb =
                    try
                        decodeB64UrlLoose e
                    with _ ->
                        [||]

                if eb.Length = 0 || eb.Length > 4 then
                    fail "format" $"jwks kid \"{kid}\": bad e"

                let ev = eb |> Array.fold (fun acc x -> (acc <<< 8) ||| int64 x) 0L

                if ev < 3L || ev % 2L = 0L then
                    fail "format" $"jwks kid \"{kid}\": bad e {ev}"

                pub <- ValueSome(RSAParameters(Modulus = trimZeros nb, Exponent = trimZeros eb))

            if not x5c.IsEmpty then
                let der =
                    try
                        Convert.FromBase64String x5c.Head
                    with :? FormatException as x ->
                        fail "format" $"jwks kid \"{kid}\" x5c: {x.Message}"

                let cert =
                    try
                        X509CertificateLoader.LoadCertificate der
                    with :? CryptographicException as x ->
                        fail "format" $"jwks kid \"{kid}\" x5c: {x.Message}"

                use cert = cert

                let cp =
                    match cert.GetRSAPublicKey() with
                    | null -> fail "format" $"jwks kid \"{kid}\": x5c key is not RSA"
                    | rsa ->
                        use rsa = rsa
                        rsa.ExportParameters false

                let bytesOrEmpty (b: byte[] | null) =
                    match b with
                    | null -> [||]
                    | b -> b

                let cp =
                    RSAParameters(
                        Modulus = trimZeros (bytesOrEmpty cp.Modulus),
                        Exponent = trimZeros (bytesOrEmpty cp.Exponent)
                    )

                match pub with
                | ValueSome p when
                    not (
                        ReadOnlySpan(p.Modulus).SequenceEqual(ReadOnlySpan(cp.Modulus))
                        && ReadOnlySpan(p.Exponent).SequenceEqual(ReadOnlySpan(cp.Exponent))
                    )
                    ->
                    fail "format" $"jwks kid \"{kid}\": n/e differ from the x5c certificate"
                | _ -> ()

                pub <- ValueSome cp

            match pub with
            | ValueNone -> fail "format" $"jwks kid \"{kid}\" has neither n/e nor x5c"
            | ValueSome p ->
                let bits = bitLen p.Modulus

                if bits < 2048 then
                    fail "format" $"jwks kid \"{kid}\": RSA key of {bits} bits"

                keys[kid] <- p)

    if keys.Count = 0 then
        fail "format" "jwks has no RSA signing key"

    KeySet keys

/// Checks a compact JWS signed with RS256 by a key of `keys` and returns its payload.
let verify (token: string) (keys: KeySet) : JsonDocument =
    let token = token.Trim()

    if token.Length > maxToken then
        fail "format" $"token over {maxToken} bytes"

    let parts = token.Split '.'

    if parts.Length <> 3 then
        fail "format" $"JWT has {parts.Length} parts, want 3"

    let hb = decodeB64Url parts[0]
    let cb = decodeB64Url parts[1]
    let sg = decodeB64Url parts[2]
    use hdr = parseJson hb
    let h = hdr.RootElement

    let hstr (n: string) =
        if h.ValueKind <> JsonValueKind.Object then
            ""
        else
            match h.TryGetProperty n with
            | true, v when v.ValueKind = JsonValueKind.String -> (nonNull (v.GetString()))
            | _ -> ""

    if h.ValueKind <> JsonValueKind.Object && h.ValueKind <> JsonValueKind.Null then
        fail "format" "JWT header is not an object"

    if hstr "alg" <> "RS256" then
        fail "signature" "JWT alg is not RS256"

    if
        h.ValueKind = JsonValueKind.Object
        && (match h.TryGetProperty "crit" with
            | true, _ -> true
            | _ -> false)
    then
        fail "format" "JWT header has crit, not supported"

    let kid = hstr "kid"

    if kid = "" then
        fail "format" "JWT header has no kid"

    match keys.Lookup kid with
    | ValueNone -> fail "unknown-key" $"kid \"{kid}\" is not in the key set"
    | ValueSome p ->
        let digest = SHA256.HashData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]))
        use rsa = RSA.Create p

        let ok =
            try
                sg.Length =
                    (match p.Modulus with
                     | null -> -1
                     | m -> m.Length)
                && rsa.VerifyHash(digest, sg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            with _ ->
                false

        if not ok then
            fail "signature" $"RS256 signature does not verify with kid \"{kid}\""

        let claims = parseJson cb

        if
            claims.RootElement.ValueKind <> JsonValueKind.Object
            && claims.RootElement.ValueKind <> JsonValueKind.Null
        then
            claims.Dispose()
            fail "format" "JWT payload is not an object"

        claims

/// iss, aud (when wanted), exp, nbf and iat (attest checkStandard).
let checkStandard (c: Claims) (issuer: string) (audience: string) (now: DateTimeOffset) (skew: TimeSpan) =
    let iss = c.StrOr "iss"
    // strings.TrimSuffix: one trailing slash at most.
    let trim1 (s: string) = if s.EndsWith "/" then s.Substring(0, s.Length - 1) else s

    if trim1 iss <> trim1 issuer then
        fail "issuer" $"iss \"{iss}\", want \"{issuer}\""

    if audience <> "" then
        match c.StrList "aud" with
        | ValueSome auds when auds |> List.contains audience -> ()
        | _ ->
            let got = c.Raw "aud"
            fail "audience" $"aud {got}, want \"{audience}\""

    let exp =
        match c.NumericDate "exp" with
        | ValueSome t -> t
        | ValueNone -> fail "format" "no exp"

    let iat =
        match c.NumericDate "iat" with
        | ValueSome t -> t
        | ValueNone -> fail "format" "no iat"

    let nbf = c.NumericDate "nbf"

    if not (now < exp + skew) then
        fail "expired" $"expired at {exp:u}"

    match nbf with
    | ValueSome nb when now + skew < nb -> fail "expired" $"not valid before {nb:u}"
    | _ -> ()

    if now + skew < iat then
        fail "stale" $"issued in the future ({iat:u})"
