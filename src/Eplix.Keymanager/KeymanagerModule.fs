/// The keymanager API as a module. Config section "keymanager":
///   { "address": "127.0.0.1", "port": 5062, "token_file": "<file>",
///     "tls_cert": "<PEM, leaf first, then intermediates>", "tls_key": "<PEM>",
///     "client_ca": "<PEM or DER>", "allow_plain_http": false, "reload_interval_seconds": 10,
///     "max_import_bytes": 268435456, "max_import_keys": 100000 }
/// The bearer token comes from token_file; when the file does not exist the module writes a
/// random token there (0600) at start, as the keymanager API describes. A token file the group
/// or others can read or write, or an empty one, fails the start. Default token file:
/// <data_dir>/api-token.txt. With tls_cert and tls_key the listener speaks HTTPS only; with
/// client_ca it also asks for a client certificate that chains to that CA. Without TLS the
/// address must be a loopback address unless allow_plain_http is true (Lighthouse's
/// --unencrypted-http-transport): the bearer token would cross the network in clear text.
/// tls_cert, tls_key and client_ca reload while running: a new connection gets the certificate
/// and the client CAs in force. max_import_bytes caps the body of a keystore
/// import (1 MiB to 16 GiB, default 256 MiB); the import reads it as a stream.
/// max_import_keys caps the distinct keys in its slashing_protection (1,000 to 1,000,000,
/// default 100,000).
module Eplix.Keymanager.KeymanagerModule

open System
open System.IO
open System.Net
open System.Net.Security
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Server.Kestrel.Https
open Microsoft.Extensions.Logging
open Eplix
open Eplix.Json

let name = "keymanager"

type Tls =
    {
        CertFile: string
        KeyFile: string
        ClientCa: string voption
    }

type Settings =
    {
        Address: IPAddress
        Port: int
        TokenFile: string voption
        Tls: Tls voption
        AllowPlainHttp: bool
        /// How often the TLS files are read for a change; zero turns it off.
        ReloadInterval: TimeSpan
        /// The largest keystore import body, in bytes; also Kestrel's MaxRequestBodySize.
        ImportLimit: int64
        /// The most distinct keys in one import's slashing_protection.
        ImportKeyLimit: int
    }

let private defaults =
    {
        Address = IPAddress.Loopback
        Port = 5062
        TokenFile = ValueNone
        Tls = ValueNone
        AllowPlainHttp = false
        ReloadInterval = TimeSpan.FromSeconds 10.0
        ImportLimit = KeymanagerApi.DefaultImportLimit
        ImportKeyLimit = Slashing.InterchangeReader.DefaultMaxKeys
    }

let parse (section: ConfigSection) : Result<Settings, string list> =
    let d = defaults

    match section.Element with
    | ValueNone -> Ok d
    | ValueSome e ->
        match
            checkFields
                e
                "modules.keymanager"
                [
                    "address"
                    "port"
                    "token_file"
                    "tls_cert"
                    "tls_key"
                    "client_ca"
                    "allow_plain_http"
                    "reload_interval_seconds"
                    "max_import_bytes"
                    "max_import_keys"
                ]
        with
        | [] ->
            try
                let address =
                    match tryProp e "address" with
                    | ValueSome a ->
                        match IPAddress.TryParse(str a) with
                        | true, NonNull ip -> ip
                        | _ -> fail "address must be an IP address"
                    | ValueNone -> d.Address

                let port =
                    match tryProp e "port" with
                    | ValueSome p -> boundedInt "port" 1 65535 p
                    | ValueNone -> d.Port

                let file (name: string) =
                    tryProp e name
                    |> ValueOption.map (fun v ->
                        let f = section.Path(str v)

                        if not (File.Exists f) then
                            fail $"{name} {f} does not exist"

                        f)

                let tls =
                    match file "tls_cert", file "tls_key", file "client_ca" with
                    | ValueSome c, ValueSome k, ca ->
                        ValueSome
                            {
                                CertFile = c
                                KeyFile = k
                                ClientCa = ca
                            }
                    | ValueNone, ValueNone, ValueNone -> ValueNone
                    | ValueNone, ValueNone, ValueSome _ -> fail "client_ca needs tls_cert and tls_key"
                    | _ -> fail "tls_cert and tls_key go together"

                let allowPlain =
                    match tryProp e "allow_plain_http" with
                    | ValueNone -> false
                    | ValueSome v when v.ValueKind = JsonValueKind.True -> true
                    | ValueSome v when v.ValueKind = JsonValueKind.False -> false
                    | ValueSome _ -> fail "allow_plain_http must be true or false"

                if tls.IsNone && not allowPlain && not (IPAddress.IsLoopback address) then
                    fail
                        $"address {address} is not a loopback address: set tls_cert and tls_key, or allow_plain_http to send the bearer token in clear text"

                let reload =
                    match TlsFiles.reloadInterval (tryProp e "reload_interval_seconds" |> ValueOption.map u64) with
                    | Ok t -> t
                    | Error m -> fail m

                let importLimit =
                    match tryProp e "max_import_bytes" with
                    | ValueSome v -> int64 (bounded "max_import_bytes" (1UL <<< 20) (16UL <<< 30) v)
                    | ValueNone -> d.ImportLimit

                let importKeyLimit =
                    match tryProp e "max_import_keys" with
                    | ValueSome v -> boundedInt "max_import_keys" 1_000 1_000_000 v
                    | ValueNone -> d.ImportKeyLimit

                Ok
                    {
                        Address = address
                        Port = port
                        TokenFile = tryProp e "token_file" |> ValueOption.map (fun t -> section.Path(str t))
                        Tls = tls
                        AllowPlainHttp = allowPlain
                        ReloadInterval = reload
                        ImportLimit = importLimit
                        ImportKeyLimit = importKeyLimit
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.keymanager: {x.Message}" ]
        | errs -> Error errs

/// The server certificate with its private key, and the intermediates that follow it in the
/// PEM text. Kestrel sends the intermediates in the handshake, so a client that trusts only the
/// root still builds the chain.
let private serverCertificate (certPem: string) (keyPem: string) : X509Certificate2 * X509Certificate2Collection =
    use pemLeaf = X509Certificate2.CreateFromPem(certPem.AsSpan(), keyPem.AsSpan())
    // Through PKCS#12 so the key is one SslStream can use on every platform.
    let leaf = X509CertificateLoader.LoadPkcs12(pemLeaf.Export X509ContentType.Pkcs12, null)
    let all = X509Certificate2Collection()
    all.ImportFromPem(certPem.AsSpan())
    let chain = X509Certificate2Collection()

    for c in all do
        if c.Thumbprint <> leaf.Thumbprint then
            chain.Add c |> ignore

    leaf, chain

/// serverCertificate over the two files, read through TlsFiles.read.
let loadServerCertificate (certFile: string) (keyFile: string) : X509Certificate2 * X509Certificate2Collection =
    match TlsFiles.read [ certFile; keyFile ] with
    | [ c; k ] -> serverCertificate (Text.Encoding.UTF8.GetString c) (Text.Encoding.UTF8.GetString k)
    | _ -> invalidOp "a certificate file and a key file"

/// The server certificate with its key and intermediates from PEM text, as TLS sends it, and
/// the earliest NotAfter of the chain. An expired certificate loads (the start does not refuse
/// it); the reload task logs it once a minute.
let serverPair (bytes: byte[] list) (_: DateTimeOffset) : SslStreamCertificateContext * DateTimeOffset =
    match bytes with
    | [ c; k ] ->
        let leaf, chain = serverCertificate (Text.Encoding.UTF8.GetString c) (Text.Encoding.UTF8.GetString k)
        SslStreamCertificateContext.Create(leaf, chain, offline = true), ClientCert.notAfter (Seq.append [ leaf ] chain)
    | _ -> invalidArg "bytes" "a certificate file and a key file"

/// The CA certificates of a PEM or DER file.
let loadCa (file: string) : X509Certificate2Collection =
    try
        fst (TlsFiles.caBundle (TlsFiles.read [ file ]) DateTimeOffset.UtcNow)
    with :? InvalidDataException as e ->
        raise (InvalidDataException $"{file} holds no certificate: {e.Message}")

/// Whether a client certificate chains to one of the CA certificates at the current time, for
/// client authentication, with the intermediates the client sent (`sent`), so client_ca may hold only the root. No
/// revocation check (a private CA rarely runs one); the system store is left out.
let clientTrustedWith
    (ca: X509Certificate2Collection)
    (sent: X509Certificate2Collection)
    (cert: X509Certificate2)
    : bool =
    use chain = new X509Chain()
    chain.ChainPolicy.TrustMode <- X509ChainTrustMode.CustomRootTrust
    chain.ChainPolicy.CustomTrustStore.AddRange ca
    chain.ChainPolicy.ExtraStore.AddRange sent
    chain.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck
    chain.ChainPolicy.ApplicationPolicy.Add(Oid "1.3.6.1.5.5.7.3.2") |> ignore
    chain.Build cert

/// clientTrustedWith without certificates sent by the client.
let clientTrusted (ca: X509Certificate2Collection) (cert: X509Certificate2) : bool =
    clientTrustedWith ca (X509Certificate2Collection()) cert

/// Mode bits that let the group or others read or write a token file.
let private looseToken =
    UnixFileMode.GroupRead
    ||| UnixFileMode.GroupWrite
    ||| UnixFileMode.OtherRead
    ||| UnixFileMode.OtherWrite

/// Reads the token, or writes a new random one (32 bytes as hex) with mode 0600, in a directory
/// created 0700 if missing. A token file the group or others may read or write is refused, as
/// is an empty one: either would hand the API to another local user.
let loadOrCreateToken (file: string) : Result<string, string> =
    let unix = not (OperatingSystem.IsWindows())

    if File.Exists file then
        if unix && (File.GetUnixFileMode file &&& looseToken) <> UnixFileMode.None then
            Error $"token file {file} is readable or writable by group or others; chmod 600 it"
        else
            let token = File.ReadAllText(file).Trim()
            if token.Length = 0 then Error $"token file {file} is empty" else Ok token
    else
        let token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes 32)
        let dir = nonNull (Path.GetDirectoryName(Path.GetFullPath file))

        if not (Directory.Exists dir) then
            if unix then
                Directory.CreateDirectory(
                    dir,
                    UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
                )
                |> ignore
            else
                Directory.CreateDirectory dir |> ignore
        // The mode is set at create, so no one else can open the file in between. CreateNew fails
        // on a file or link someone put there since the check above.
        let options =
            FileStreamOptions(Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None)

        if unix then
            options.UnixCreateMode <- Nullable(UnixFileMode.UserRead ||| UnixFileMode.UserWrite)

        (use f = new FileStream(file, options)
         let bytes = Text.Encoding.ASCII.GetBytes(token + "\n")
         f.Write(bytes, 0, bytes.Length)
         f.Flush true)

        Ok token

/// Reads the body up to `limit` bytes: ValueNone when the body is longer, by
/// its Content-Length before any byte is read, or once more than `limit` bytes came in (a
/// chunked body). Kestrel's own limit stays the outer bound.
let private readBody (ctx: HttpContext) (limit: int64) =
    task {
        let length = ctx.Request.ContentLength

        if length.HasValue && length.Value > limit then
            return ValueNone
        else
            use ms = new MemoryStream()
            let buffer = Array.zeroCreate<byte> 16384
            let mutable reading = true
            let mutable over = false

            while reading do
                let! n =
                    task {
                        try
                            return! ctx.Request.Body.ReadAsync(buffer.AsMemory(), ctx.RequestAborted)
                        with :? BadHttpRequestException as e when e.StatusCode = StatusCodes.Status413PayloadTooLarge ->
                            // Past Kestrel's MaxRequestBodySize.
                            return -1
                    }

                if n = 0 then
                    reading <- false
                elif n < 0 || ms.Length + int64 n > limit then
                    over <- true
                    reading <- false
                else
                    ms.Write(buffer, 0, n)

            return if over then ValueNone else ValueSome(ms.ToArray())
    }

/// Writes a response. `close` ends the connection after it, for an answer sent before the body
/// was read: Kestrel would otherwise read and drop the rest of the body to reuse the connection.
let private send (http: HttpContext) (resp: KeymanagerApi.Response) (close: bool) =
    task {
        http.Response.StatusCode <- resp.Status

        if close then
            http.Response.Headers.Connection <- Microsoft.Extensions.Primitives.StringValues "close"

        if resp.Body.Length > 0 then
            http.Response.ContentType <- "application/json"
            do! http.Response.Body.WriteAsync(ReadOnlyMemory resp.Body, http.RequestAborted)
    }

/// The settings file in the data dir: per-key fee recipient, gas limit and graffiti.
let settingsFile (dataDir: string) = Path.Combine(dataDir, "key-settings.json")

/// Writes the settings file, one writer at a time: each write takes the settings in force once
/// it holds the lock, so two API calls at once never leave the older settings on disk. Atomic
/// and durable (FileSync.writeAtomic), mode 0600.
let settingsWriter (file: string) (all: unit -> (PubKey * KeySettings) list) : unit -> unit =
    let gate = obj ()

    fun () ->
        lock gate (fun () ->
            Slashing.FileSync.writeAtomic
                file
                (KeymanagerApi.settingsToJson (all ()))
                (UnixFileMode.UserRead ||| UnixFileMode.UserWrite))

/// Reads the settings file: no settings when it does not exist, an error naming the file when it
/// does not read, does not parse or holds a value the API would refuse.
let loadSettings (file: string) : Result<(PubKey * KeySettings) list, string> =
    if not (File.Exists file) then
        Ok []
    else
        let bytes =
            try
                Ok(File.ReadAllBytes file)
            with
            | :? IOException
            | :? UnauthorizedAccessException as e -> Error e.Message

        bytes
        |> Result.bind KeymanagerApi.settingsOfJson
        |> Result.mapError (fun e -> $"settings file {file}: {e}; fix the file, then start again")

/// A web application builder that reads no host configuration: no appsettings.json from the
/// working directory, no environment variables, no command line. Kestrel binds its "Kestrel"
/// section from this configuration, so an environment variable such as
/// Kestrel__Endpoints__X__Url would add a listener beside the one Listen sets, without TLS or
/// the client certificate check.
let webBuilder () : WebApplicationBuilder =
    let builder =
        WebApplication.CreateSlimBuilder(
            WebApplicationOptions(
                Args = [||],
                ContentRootPath = AppContext.BaseDirectory,
                EnvironmentName = "Production"
            )
        )

    builder.Configuration.Sources.Clear()
    builder.Logging.ClearProviders() |> ignore
    builder

let create () : Module =
    let settings = ref defaults

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun _ ->
                let s = settings.Value

                match s.Tls with
                | ValueNone -> Ok $"listens on http://{s.Address}:{s.Port}"
                | ValueSome t ->
                    try
                        let leaf, chain = loadServerCertificate t.CertFile t.KeyFile

                        let clients =
                            match t.ClientCa with
                            | ValueSome f -> $", client certificates from {(loadCa f).Count} CA certificates"
                            | ValueNone -> ""

                        let until = leaf.NotAfter.ToUniversalTime().ToString "yyyy-MM-dd"

                        Ok
                            $"listens on https://{s.Address}:{s.Port} as {leaf.Subject}, valid until {until}, {chain.Count} intermediates{clients}"
                    with e ->
                        Error [ $"modules.keymanager: TLS files: {e.Message}" ]
        Start =
            fun core _ ->
                task {
                    let s = settings.Value
                    let tokenFile = defaultValueArg s.TokenFile (Path.Combine(core.DataDir, "api-token.txt"))

                    match loadOrCreateToken tokenFile with
                    | Error e -> return Error $"keymanager: {e}"
                    | Ok token ->
                        let file = settingsFile core.DataDir
                        // A file that does not read or holds a bad value fails the start, as a bad proposer
                        // config does: a warning would let the next API write replace it with the settings
                        // of one key and drop the others.
                        match loadSettings file with
                        | Error e -> return Error $"keymanager: {e}"
                        | Ok all ->
                            for pk, ks in all do
                                core.Registry.SetSettings(pk, fun _ -> ks)

                            let save = settingsWriter file (fun () -> core.Registry.AllSettings)

                            let ctx: KeymanagerApi.Context =
                                {
                                    Core = core
                                    Token = token
                                    SaveSettings = save
                                }

                            let builder = webBuilder ()
                            let time = core.Clock.Time

                            let loaded =
                                match s.Tls with
                                | ValueNone -> Ok ValueNone
                                | ValueSome t ->
                                    let cert =
                                        TlsFile<SslStreamCertificateContext>
                                            .Load(
                                                name,
                                                "tls_cert",
                                                [ t.CertFile; t.KeyFile ],
                                                serverPair,
                                                ClientCert.validFrom,
                                                true,
                                                core.Log,
                                                time
                                            )

                                    let ca =
                                        match t.ClientCa with
                                        | ValueSome f ->
                                            TlsFiles.ca name "client_ca" f core.Log time |> Result.map ValueSome
                                        | ValueNone -> Ok ValueNone

                                    match cert, ca with
                                    | Ok c, Ok ca -> Ok(ValueSome(c, ca))
                                    | Error e, _
                                    | _, Error e -> Error $"keymanager: TLS files: {e}"

                            match loaded with
                            | Error e -> return Error e
                            | Ok tls ->
                                builder.WebHost.ConfigureKestrel(fun o ->
                                    // The outer bound, the import's limit; each other route sets a lower one (bodyLimit).
                                    o.Limits.MaxRequestBodySize <- Nullable s.ImportLimit
                                    // Kestrel's default, set here as the import relies on it: a body slower than
                                    // 240 bytes/s after a 5 s grace period ends with 408.
                                    o.Limits.MinRequestBodyDataRate <-
                                        Microsoft.AspNetCore.Server.Kestrel.Core.MinDataRate(
                                            240.0,
                                            TimeSpan.FromSeconds 5.0
                                        )

                                    o.Listen(
                                        s.Address,
                                        s.Port,
                                        fun listen ->
                                            match tls with
                                            | ValueNone -> ()
                                            | ValueSome(cert, ca) ->
                                                // Each handshake takes the certificate and the client CAs in force.
                                                let options (_: TlsHandshakeCallbackContext) =
                                                    // No TLS resumption: a resumed client sends no intermediates, which
                                                    // the client check below needs with a root-only client_ca, and every
                                                    // connection gets the full check against the CAs in force.
                                                    let o =
                                                        SslServerAuthenticationOptions(
                                                            ServerCertificateContext = cert.Current.Value,
                                                            AllowTlsResume = false
                                                        )

                                                    match ca with
                                                    | ValueNone -> ()
                                                    | ValueSome ca ->
                                                        o.ClientCertificateRequired <- true
                                                        o.CertificateRevocationCheckMode <- X509RevocationMode.NoCheck
                                                        // The chain holds the certificates the client sent in its ExtraStore.
                                                        o.RemoteCertificateValidationCallback <-
                                                            RemoteCertificateValidationCallback(fun _ c chain _ ->
                                                                match c, chain with
                                                                | null, _ -> false
                                                                | c, chain ->
                                                                    use leaf = new X509Certificate2(c)

                                                                    let sent =
                                                                        match chain with
                                                                        | null -> X509Certificate2Collection()
                                                                        | chain -> chain.ChainPolicy.ExtraStore

                                                                    clientTrustedWith ca.Current.Value sent leaf)

                                                    ValueTask<SslServerAuthenticationOptions>(o)

                                                listen.UseHttps(
                                                    TlsHandshakeCallbackOptions(OnConnection = Func<_, _>(options))
                                                )
                                                |> ignore
                                    ))
                                |> ignore

                                let tlsFiles =
                                    match tls with
                                    | ValueNone -> []
                                    | ValueSome(cert, ca) ->
                                        (cert :> TlsCheck)
                                        :: (match ca with
                                            | ValueSome f -> [ f :> TlsCheck ]
                                            | ValueNone -> [])

                                let scheme = if tls.IsSome then "https" else "http"
                                let app = builder.Build()

                                app.Run(
                                    RequestDelegate(fun http ->
                                        task {
                                            let meth = http.Request.Method
                                            let path = defaultArg (Option.ofObj http.Request.Path.Value) "/"
                                            let authorization = string http.Request.Headers.Authorization
                                            // The token first, from the headers: a client without it gets no body read.
                                            match KeymanagerApi.authorized ctx authorization with
                                            | Some denied -> do! send http denied true
                                            | None ->
                                                let limit = KeymanagerApi.bodyLimit s.ImportLimit meth path
                                                let length = http.Request.ContentLength

                                                if KeymanagerApi.isImport meth path then
                                                    if length.HasValue && length.Value > limit then
                                                        do! send http (KeymanagerApi.importTooLarge limit) true
                                                    else
                                                        let! resp =
                                                            task {
                                                                try
                                                                    return!
                                                                        KeymanagerApi.importFrom
                                                                            ctx
                                                                            http.Request.Body
                                                                            limit
                                                                            s.ImportKeyLimit
                                                                            http.RequestAborted
                                                                with :? OperationCanceledException ->
                                                                    return
                                                                        ({ Status = 503; Body = [||] }
                                                                        : KeymanagerApi.Response)
                                                            }
                                                        // After an error the rest of the body stays unread: close.
                                                        do! send http resp (resp.Status >= 400)
                                                else
                                                    match! readBody http limit with
                                                    | ValueNone -> do! send http (KeymanagerApi.tooLarge limit) true
                                                    | ValueSome body ->
                                                        let req: KeymanagerApi.Request =
                                                            {
                                                                Method = meth
                                                                Path = path
                                                                Query =
                                                                    Map.ofList
                                                                        [
                                                                            for q in http.Request.Query ->
                                                                                q.Key, string q.Value
                                                                        ]
                                                                Authorization = authorization
                                                                Body = body
                                                            }

                                                        let! resp = KeymanagerApi.handle ctx req http.RequestAborted
                                                        do! send http resp false
                                        }
                                        :> Task)
                                )

                                try
                                    do! app.StartAsync()

                                    core.Log.Info
                                        $"keymanager API on {scheme}://{s.Address}:{s.Port}, token in {tokenFile}"

                                    let stopper = new CancellationTokenSource()
                                    let reloader = TlsFiles.watch tlsFiles s.ReloadInterval time stopper.Token

                                    return
                                        Ok
                                            {
                                                Stop =
                                                    fun () ->
                                                        task {
                                                            stopper.Cancel()
                                                            do! reloader
                                                            do! app.StopAsync()
                                                        }
                                                        :> Task
                                            }
                                with e ->
                                    return Error $"keymanager API cannot listen on {s.Address}:{s.Port}: {e.Message}"
                }
    }
