/// The standard keymanager API (ethereum/keymanager-APIs) as a function from request to response,
/// so tests call it without a server. KeymanagerModule.fs puts it behind Kestrel.
/// Endpoints: /eth/v1/keystores (list, import with slashing protection, delete with export),
/// /eth/v1/remotekeys (list, import, delete, through the Web3Signer module), per-key fee
/// recipient, gas limit and graffiti, and the voluntary exit. Every call needs
/// `Authorization: Bearer <token>`.
module Eplix.Keymanager.KeymanagerApi

open System
open System.Globalization
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json
open Eplix.Slashing

type Request =
    {
        Method: string
        Path: string
        Query: Map<string, string>
        Authorization: string
        Body: byte[]
    }

type Response = { Status: int; Body: byte[] }

let private respond status (write: Utf8JsonWriter -> unit) =
    {
        Status = status
        Body = toBytes write
    }

let private empty status = { Status = status; Body = [||] }

let private error status (message: string) =
    respond status (fun w ->
        w.WriteStartObject()
        w.WriteNumber("code", status)
        w.WriteString("message", message)
        w.WriteEndObject())

/// The keymanager API state the handlers need.
type Context =
    {
        Core: CoreServices
        Token: string
        /// Persists per-key settings after a change.
        SaveSettings: unit -> unit
    }

/// The answer to a request without the right bearer token, or None. It reads only the header,
/// so the server calls it before it reads a body: a client without the token cannot make it buffer a large body.
let authorized (ctx: Context) (header: string) =
    if String.IsNullOrEmpty header || not (header.StartsWith "Bearer ") then
        Some(error 401 "missing bearer token")
    else
        let given = Encoding.UTF8.GetBytes(header.Substring 7)
        let expected = Encoding.UTF8.GetBytes ctx.Token

        if CryptographicOperations.FixedTimeEquals(ReadOnlySpan given, ReadOnlySpan expected) then
            None
        else
            Some(error 403 "wrong bearer token")

/// The default limit of a keystore import body (modules.keymanager.max_import_bytes).
/// A complete EIP-3076 history with signing roots grows by about 11.4 MiB per
/// validator-year, and inside the JSON string every quote doubles to \", so a few years of one
/// key fit. The import reads the body as a stream and keeps only the marks, so the limit bounds
/// the time to read a body, not its memory.
[<Literal>]
let DefaultImportLimit = 268_435_456L

/// The largest body a route takes, in bytes. A keystore import is the one
/// large request and takes `importLimit`: up to maxImport (1,000) EIP-2335 keystores of about
/// 1 KB, about 1.2 KB each as an escaped JSON string, with their passwords, come to about
/// 1.5 MB, and the EIP-3076 interchange beside them has no bound in the spec. A keystore or
/// remote key delete lists public keys of 100 bytes: 1 MiB holds 10,000. A remote key import
/// holds a public key and a URL per key: 1 MiB holds over 4,000 at 250 bytes. A per-key setting
/// is one short field; the other routes take no body.
let bodyLimit (importLimit: int64) (meth: string) (path: string) : int64 =
    match meth, path.Split('/', StringSplitOptions.RemoveEmptyEntries) with
    | "POST", [| "eth"; "v1"; "keystores" |] -> importLimit
    | ("DELETE" | "POST"), [| "eth"; "v1"; ("keystores" | "remotekeys") |] -> 1L <<< 20
    | _ -> 4096L

/// True for POST /eth/v1/keystores, the route that reads its body as a stream.
let isImport (meth: string) (path: string) =
    meth = "POST"
    && path.Split('/', StringSplitOptions.RemoveEmptyEntries) = [| "eth"; "v1"; "keystores" |]

/// The answer to a body over its route's limit.
let tooLarge (limit: int64) = error 413 $"request body over {limit} bytes"

/// The answer to an import body over the limit.
let importTooLarge (limit: int64) =
    error
        413
        $"request body over {limit} bytes (modules.keymanager.max_import_bytes): split the import into several requests, or minimise the slashing_protection interchange to one entry per key with its highest block and attestation"

/// The answer to an import whose slashing_protection holds more distinct keys than the cap
/// 413: the request asks for more than the server takes in one go, and the
/// remedy is the one for a large body.
let importTooManyKeys (limit: int) =
    error
        413
        $"too many keys in one import: more than {limit} distinct pubkeys in slashing_protection (modules.keymanager.max_import_keys); split it into several requests"

let private status (w: Utf8JsonWriter) (s: string) (message: string) =
    w.WriteStartObject()
    w.WriteString("status", s)
    w.WriteString("message", message)
    w.WriteEndObject()

let private listKeystores (ctx: Context) =
    let stored =
        match ctx.Core.Keystores() with
        | ValueSome s -> s.List()
        | ValueNone -> []

    respond 200 (fun w ->
        w.WriteStartObject()
        w.WriteStartArray "data"

        for k in stored |> List.sortBy (fun k -> k.Key.Hex) do
            w.WriteStartObject()
            w.WriteString("validating_pubkey", k.Key.Hex)
            w.WriteString("derivation_path", k.DerivationPath)
            w.WriteBoolean("readonly", k.ReadOnly)
            w.WriteEndObject()

        w.WriteEndArray()
        w.WriteEndObject())

/// Why an imported key does not sign: it has no slashing record and the override does not list
/// it. Empty when the key has a record or is not held. `eplix import` copies local
/// keystores only, so a remote key's way out is a slashing import or the override.
let private noHistoryNote (ctx: Context) (remote: bool) (key: PubKey voption) =
    match key with
    | ValueSome k when not (ctx.Core.Slashing.HasRecord k) ->
        match ctx.Core.Registry.TryGet k with
        | ValueSome r when r.State = KeyState.Discovered ->
            if remote then
                "no slashing history: the key stays discovered and does not sign. Import its slashing history (eplix slashing import), or list it in allow_start_without_history once you are sure no other machine signs with it"
            else
                "no slashing history (no slashing_protection, or no signed block or attestation for this key in it): the key stays discovered and does not sign. Import it again with its slashing_protection, or stop the VC and run eplix import --no-signing-history --from <its keystore directory> once you are sure no other machine signs with it"
        | _ -> ""
    | _ -> ""

/// The key an EIP-2335 keystore names in its `pubkey` field, if any.
let private keystoreKey (text: string) =
    try
        use doc = JsonDocument.Parse text

        match doc.RootElement.TryGetProperty "pubkey" with
        | true, v when v.ValueKind = JsonValueKind.String ->
            // EIP-2335 writes the key without the 0x prefix.
            let hex = nonNull (v.GetString())
            PubKey.TryParse(if hex.StartsWith "0x" then hex else "0x" + hex)
        | _ -> ValueNone
    with _ ->
        ValueNone

/// Keystores per import request. Each costs up to a few seconds of KDF work on one core, and a
/// pbkdf2 derivation cannot be stopped once started; a bigger set goes in several requests.
let maxImport = 1000

/// POST /eth/v1/keystores with its body as a stream of at most `limit` bytes.
/// The slashing history goes into the DB first, as maxima: a key never signs before it has a
/// record. A history with a slashable pair inside the file still goes in, with one warning per
/// key, as Lighthouse and Teku do; EIP-3076 asks only for a safe import.
let importFrom (ctx: Context) (body: IO.Stream) (limit: int64) (maxKeys: int) (ct: CancellationToken) : Task<Response> =
    task {
        match ctx.Core.Keystores() with
        | ValueNone -> return error 500 "this build has no keystore backend"
        | ValueSome store ->
            let! parsed = ImportBody.read body limit maxImport maxKeys ct

            match parsed with
            | Error ImportBody.ReadError.TooLarge -> return importTooLarge limit
            | Error(ImportBody.ReadError.TooManyKeys n) -> return importTooManyKeys n
            | Error(ImportBody.ReadError.Http(413, _)) -> return importTooLarge limit
            | Error(ImportBody.ReadError.Http(status, message)) -> return error status message
            | Error(ImportBody.ReadError.Invalid e) -> return error 400 e
            | Ok p when p.Keystores.Length <> p.Passwords.Length ->
                return error 400 "keystores and passwords differ in length"
            | Ok p ->
                let history =
                    match p.History with
                    | ValueNone -> Ok()
                    | ValueSome x ->
                        match ctx.Core.Slashing.ImportMarks x with
                        | Error e -> Error $"slashing_protection: {e}"
                        | Ok _ ->
                            for k in x.Slashable do
                                ctx.Core.Log.Warn
                                    $"keymanager import: the slashing_protection history of {k.Hex} holds a slashable pair; imported as its highest block and attestation"

                            Ok()

                match history with
                | Error e -> return error 400 e
                | Ok() ->
                    let ks = p.Keystores
                    let! statuses = store.Import (List.zip ks p.Passwords) ct

                    if statuses |> List.exists (fun s -> s = ImportStatus.Imported) then
                        do! ctx.Core.RefreshKeys ct

                    return
                        respond 200 (fun w ->
                            w.WriteStartObject()
                            w.WriteStartArray "data"

                            for text, s in List.zip ks statuses do
                                match s with
                                | ImportStatus.Imported ->
                                    status w "imported" (noHistoryNote ctx false (keystoreKey text))
                                | ImportStatus.Duplicate -> status w "duplicate" "the key is already present"
                                | ImportStatus.Error m -> status w "error" m

                            w.WriteEndArray()
                            w.WriteEndObject())
    }

/// POST /eth/v1/keystores with the body already in memory. The server never takes this route: it
/// streams every import through importFrom with modules.keymanager.max_import_keys. Only tests and
/// in-process callers of `handle` reach it, so it takes the default cap.
let private importKeystores (ctx: Context) (body: byte[]) (ct: CancellationToken) =
    task {
        use ms = new IO.MemoryStream(body, false)
        return! importFrom ctx ms Int64.MaxValue InterchangeReader.DefaultMaxKeys ct
    }

let private deleteKeystores (ctx: Context) (body: byte[]) =
    task {
        match
            decode (fun e -> array (prop e "pubkeys") |> Array.map pubkey |> List.ofArray) (ReadOnlyMemory body),
            ctx.Core.Keystores()
        with
        | Error e, _ -> return error 400 e
        | _, ValueNone -> return error 500 "this build has no keystore backend"
        | Ok pks, ValueSome store ->
            // The store drains each key (no new duty, signatures in flight finish) before removing it,
            // so the export below includes every signature this VC made. It runs to the end under
            // the VC's stopping token, not the request's: a client that gives up halfway would
            // otherwise leave keystores deleted with no slashing_protection returned.
            let! statuses = store.Delete pks ctx.Core.Stopping
            let db = ctx.Core.Slashing
            let exported = db.Export(ValueSome(pks |> List.filter db.HasRecord))

            return
                respond 200 (fun w ->
                    w.WriteStartObject()
                    w.WriteStartArray "data"

                    for pk, s in List.zip pks statuses do
                        match s with
                        | DeleteStatus.Deleted -> status w "deleted" ""
                        | DeleteStatus.NotFound when db.HasRecord pk ->
                            status w "not_active" "not held; slashing protection exported"
                        | DeleteStatus.NotFound -> status w "not_found" ""
                        | DeleteStatus.Error m -> status w "error" m

                    w.WriteEndArray()
                    w.WriteString("slashing_protection", Encoding.UTF8.GetString(Interchange.write exported))
                    w.WriteEndObject())
    }

let private statuses (write: Utf8JsonWriter -> unit) =
    respond 200 (fun w ->
        w.WriteStartObject()
        w.WriteStartArray "data"
        write w
        w.WriteEndArray()
        w.WriteEndObject())

/// /eth/v1/remotekeys. Without a module that offers remote keys (a build without the Web3Signer
/// module) the list is empty, every import is an error and every delete not_found. The spec's
/// remote key delete returns no slashing protection: the signer keeps its own, and the VC keeps
/// the key's record in its DB.
let private remoteKeys (ctx: Context) (meth: string) (body: byte[]) (ct: CancellationToken) =
    task {
        let store = ctx.Core.RemoteKeys()

        match meth with
        | "GET" ->
            let keys =
                match store with
                | ValueSome s -> s.List() |> List.sortBy (fun k -> k.Key.Hex)
                | ValueNone -> []

            return
                statuses (fun w ->
                    for k in keys do
                        w.WriteStartObject()
                        w.WriteString("pubkey", k.Key.Hex)
                        w.WriteString("url", k.Url)
                        w.WriteBoolean("readonly", k.ReadOnly)
                        w.WriteEndObject())
        | "POST" ->
            let parsed =
                decode
                    (fun e ->
                        [
                            for k in array (prop e "remote_keys") ->
                                pubkeyField k "pubkey", tryProp k "url" |> ValueOption.map str
                        ])
                    (ReadOnlyMemory body)

            match parsed, store with
            | Error e, _ -> return error 400 e
            | Ok keys, ValueNone ->
                return
                    statuses (fun w ->
                        for _ in keys do
                            status w "error" "this build has no Web3Signer module")
            | Ok keys, ValueSome s ->
                let! result = s.Import keys ct

                return
                    statuses (fun w ->
                        for (key, _), r in List.zip keys result do
                            match r with
                            | ImportStatus.Imported -> status w "imported" (noHistoryNote ctx true (ValueSome key))
                            | ImportStatus.Duplicate -> status w "duplicate" "the key is already present"
                            | ImportStatus.Error m -> status w "error" m)
        | "DELETE" ->
            match
                decode (fun e -> array (prop e "pubkeys") |> Array.map pubkey |> List.ofArray) (ReadOnlyMemory body),
                store
            with
            | Error e, _ -> return error 400 e
            | Ok pks, ValueNone ->
                return
                    statuses (fun w ->
                        for _ in pks do
                            status w "not_found" "")
            | Ok pks, ValueSome s ->
                let! result = s.Delete pks ct

                return
                    statuses (fun w ->
                        for r in result do
                            match r with
                            | DeleteStatus.Deleted -> status w "deleted" ""
                            | DeleteStatus.NotFound -> status w "not_found" ""
                            | DeleteStatus.Error m -> status w "error" m)
        | _ -> return error 405 "method not allowed"
    }

/// GET, POST and DELETE of one per-key setting. GET reports the effective value. A key the VC
/// does not hold answers 404 to all three, so no setting is stored for it. A key the proposer
/// config file lists is read-only here: POST and DELETE answer 403, as Teku does.
let private setting
    (ctx: Context)
    (meth: string)
    (pk: PubKey)
    (body: byte[])
    (field: string)
    (read: KeySettings -> string)
    (write: string -> KeySettings -> Result<KeySettings, string>)
    (reset: KeySettings -> KeySettings)
    =
    let known = (ctx.Core.Registry.TryGet pk).IsSome

    match meth with
    | "GET"
    | "POST"
    | "DELETE" when not known -> error 404 "unknown key"
    | "GET" ->
        respond 200 (fun w ->
            w.WriteStartObject()
            w.WriteStartObject "data"
            w.WriteString("pubkey", pk.Hex)
            w.WriteString(field, read (ctx.Core.Registry.SettingsOf pk))
            w.WriteEndObject()
            w.WriteEndObject())
    | "POST"
    | "DELETE" when ctx.Core.Registry.InProposerFile pk ->
        error
            403
            "the proposer config file sets this key's fee recipient, gas limit and graffiti; edit the file instead"
    | "POST" ->
        match
            decode
                (fun e ->
                    match (prop e field).ValueKind with
                    | JsonValueKind.String -> str (prop e field)
                    | _ -> (prop e field).GetRawText())
                (ReadOnlyMemory body)
        with
        | Error e -> error 400 e
        | Ok v ->
            match write v (ctx.Core.Registry.StoredSettingsOf pk) with
            | Error e -> error 400 e
            | Ok s ->
                ctx.Core.Registry.SetSettings(pk, fun _ -> s)
                ctx.SaveSettings()
                empty 202
    | "DELETE" ->
        ctx.Core.Registry.SetSettings(pk, reset)
        ctx.SaveSettings()
        empty 204
    | _ -> error 405 "method not allowed"

let private exit (ctx: Context) (pk: PubKey) (query: Map<string, string>) (ct: CancellationToken) =
    task {
        match ctx.Core.Registry.TryGet pk with
        | ValueNone -> return error 404 "unknown key"
        | ValueSome k when k.Index.IsNone -> return error 400 "the beacon node does not know this key"
        | ValueSome k ->
            let clock = ctx.Core.Clock

            let epoch =
                match query.TryFind "epoch" with
                | Some e ->
                    match UInt64.TryParse(e, NumberStyles.None, CultureInfo.InvariantCulture) with
                    | true, v -> Ok v
                    | _ -> Error "epoch is not a number"
                | None -> Ok(clock.EpochOf(defaultValueArg clock.CurrentSlot 0UL))

            match epoch with
            | Error e -> return error 400 e
            | Ok epoch ->
                let gvr = ctx.Core.Genesis.GenesisValidatorsRoot

                match!
                    Exits.sign ctx.Core.Spec gvr ctx.Core.Pipeline pk k.Index.Value epoch (clock.Now.AddMinutes 1.0) ct
                with
                | Error e ->
                    ctx.Core.Log.Error $"keymanager: signing the exit of {pk.Short} failed: {e}"
                    return error 500 "signing the exit failed; see the VC log"
                | Ok(x, s) ->
                    return
                        respond 200 (fun w ->
                            w.WriteStartObject()
                            w.WriteStartObject "data"
                            w.WriteStartObject "message"
                            writeU64 w "epoch" x.Epoch
                            writeU64 w "validator_index" x.ValidatorIndex
                            w.WriteEndObject()
                            w.WriteString("signature", s.Hex)
                            w.WriteEndObject()
                            w.WriteEndObject())
    }

/// The rules of each per-key setting, shared by the API setters and the settings file read at
/// start. The gas limit rule is the proposer config file's: above 0.
let checkFeeRecipient (v: string) : Result<string, string> =
    match Hex.tryDecodeFixed 20 v with
    | ValueSome b -> Ok(Hex.encodeArray b)
    | ValueNone -> Error "must be a 20-byte 0x-hex address"

let checkGasLimit (g: uint64) : Result<uint64, string> = if g = 0UL then Error "must be above 0" else Ok g

let checkGraffiti (v: string) : Result<string, string> =
    if Encoding.UTF8.GetByteCount v > 32 then Error "is longer than 32 bytes" else Ok v

let private feeRecipient (v: string) (s: KeySettings) =
    match checkFeeRecipient v with
    | Ok f -> Ok { s with FeeRecipient = ValueSome f }
    | Error e -> Error $"ethaddress {e}"

let private gasLimit (v: string) (s: KeySettings) =
    match UInt64.TryParse(v.Trim('"'), NumberStyles.None, CultureInfo.InvariantCulture) with
    | true, g ->
        match checkGasLimit g with
        | Ok g -> Ok { s with GasLimit = ValueSome g }
        | Error e -> Error $"gas_limit {e}"
    | _ -> Error "gas_limit must be a decimal number"

let private graffiti (v: string) (s: KeySettings) =
    match checkGraffiti v with
    | Ok g -> Ok { s with Graffiti = ValueSome g }
    | Error e -> Error $"graffiti {e}"

/// Routes one request.
let handle (ctx: Context) (req: Request) (ct: CancellationToken) : Task<Response> =
    task {
        match authorized ctx req.Authorization with
        | Some denied -> return denied
        | None ->
            let seg = req.Path.Split('/', StringSplitOptions.RemoveEmptyEntries)
            let d = ctx.Core.Defaults

            try
                match req.Method, seg with
                | "GET", [| "eth"; "v1"; "keystores" |] -> return listKeystores ctx
                | "POST", [| "eth"; "v1"; "keystores" |] -> return! importKeystores ctx req.Body ct
                | "DELETE", [| "eth"; "v1"; "keystores" |] -> return! deleteKeystores ctx req.Body
                | m, [| "eth"; "v1"; "remotekeys" |] -> return! remoteKeys ctx m req.Body ct
                | m, [| "eth"; "v1"; "validator"; key; what |] ->
                    match PubKey.TryParse key, what with
                    | ValueNone, _ -> return error 400 $"'{key}' is not a public key"
                    | ValueSome pk, "feerecipient" ->
                        return
                            setting
                                ctx
                                m
                                pk
                                req.Body
                                "ethaddress"
                                (fun s ->
                                    defaultValueArg
                                        s.FeeRecipient
                                        (defaultValueArg d.FeeRecipient "0x0000000000000000000000000000000000000000"))
                                feeRecipient
                                (fun s -> { s with FeeRecipient = ValueNone })
                    | ValueSome pk, "gas_limit" ->
                        return
                            setting
                                ctx
                                m
                                pk
                                req.Body
                                "gas_limit"
                                (fun s ->
                                    (defaultValueArg s.GasLimit d.GasLimit).ToString(CultureInfo.InvariantCulture))
                                gasLimit
                                (fun s -> { s with GasLimit = ValueNone })
                    | ValueSome pk, "graffiti" ->
                        return
                            setting
                                ctx
                                m
                                pk
                                req.Body
                                "graffiti"
                                (fun s -> defaultValueArg s.Graffiti d.Graffiti)
                                graffiti
                                (fun s -> { s with Graffiti = ValueNone })
                    | ValueSome pk, "voluntary_exit" when m = "POST" -> return! exit ctx pk req.Query ct
                    | _ -> return error 404 "no such endpoint"
                | _ -> return error 404 "no such endpoint"
            with
            | :? OperationCanceledException -> return error 503 "stopping"
            // The text can hold paths or backend URLs: it goes to the VC log, not to the caller.
            | e ->
                ctx.Core.Log.Error $"keymanager: {req.Method} {req.Path} failed: {e}"
                return error 500 "internal error; see the VC log"
    }

/// Per-key settings as JSON, for the settings file in the data dir.
let settingsToJson (all: (PubKey * KeySettings) list) : byte[] =
    toBytes (fun w ->
        w.WriteStartObject()

        for pk, s in all do
            w.WriteStartObject pk.Hex
            s.FeeRecipient |> ValueOption.iter (fun f -> w.WriteString("fee_recipient", f))
            s.GasLimit |> ValueOption.iter (fun g -> writeU64 w "gas_limit" g)
            s.Graffiti |> ValueOption.iter (fun g -> w.WriteString("graffiti", g))
            w.WriteEndObject()

        w.WriteEndObject())

/// Reads the settings file. Each value must pass the rule the API setter applies: a value that
/// does not would reach the proposal checks and prepare_beacon_proposer as it is.
let settingsOfJson (bytes: byte[]) : Result<(PubKey * KeySettings) list, string> =
    decode
        (fun e ->
            [
                for p in e.EnumerateObject() ->
                    match PubKey.TryParse p.Name with
                    | ValueNone -> fail $"'{p.Name}' is not a public key"
                    | ValueSome pk ->
                        let field (name: string) (read: JsonElement -> 'a) (check: 'a -> Result<'a, string>) =
                            tryProp p.Value name
                            |> ValueOption.map (fun v ->
                                let checked' =
                                    try
                                        check (read v)
                                    with :? JsonDecodeError as x ->
                                        Error x.Message

                                match checked' with
                                | Ok x -> x
                                | Error m -> fail $"key {pk.Hex}: {name} {m}")

                        pk,
                        { KeySettings.Default with
                            FeeRecipient = field "fee_recipient" str checkFeeRecipient
                            GasLimit = field "gas_limit" u64 checkGasLimit
                            Graffiti = field "graffiti" str checkGraffiti
                        }
            ])
        (ReadOnlyMemory bytes)
