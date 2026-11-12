/// One checked connection to a runner. Before it takes a request it goes through the steps of
/// tee-signer's Go client (attestation-verify/runnerclient): TLS 1.3 with the client
/// certificate (a runner of the testnet build is refused unless allowed), the runner's TLS key
/// against the pin when one is set, IDENTITY v1 (tee-signer) with a fresh nonce, the TLS key the identity
/// names against the handshake's, then the attestation check (Attest.verifyIdentity).
///
/// The runner serves a connection in order, one request at a time, and answers each with its
/// id and type|0x80. A request whose deadline passes while its reply is on the wire leaves the
/// connection "late": the read loop drops that reply when it comes and the connection takes
/// requests again; any other frame, a read error or no reply within the cap closes it.
namespace Eplix.Backend.Tee

open System
open System.Buffers.Binary
open System.IO
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Eplix

/// Where a runner is and how to trust it.
type RunnerSettings =
    {
        Name: string
        Host: string
        Port: int
        /// The client certificate with its key and the intermediates up to (not including) the
        /// root, so the runner can build the chain when it trusts only the root. Reloaded while
        /// running; a dial takes the one in force.
        ClientCert: TlsFile<SslStreamCertificateContext>
        /// sha256 of the runner's TLS key; holds for one run of the runner only.
        TlsKeyPin: byte[] voption
        AllowTestnetBuild: bool
        Verifier: Attest.Verifier
    }

[<RequireQualifiedAccess>]
type ConnState =
    | Ready
    /// A request gave up waiting; its reply is still to come.
    | Late
    | Broken

    /// Written out: the compiler's union ToString fails under NativeAOT (see DutyKind).
    override this.ToString() =
        match this with
        | Ready -> "ready"
        | Late -> "late"
        | Broken -> "broken"

/// A connection as the pool sees it; RunnerConnection in production, fakes in tests.
type PoolConn =
    abstract State: ConnState
    abstract Drained: Task<bool>
    abstract Close: unit -> unit

/// A connection that tells the pool when it breaks, so one that breaks while idle (the runner
/// restarted) leaves the pool at once. The pool registers one handler when it takes the
/// connection in; a connection already broken calls it at once.
type BreakNotice =
    abstract OnBroken: (unit -> unit) -> unit

module Der =
    /// The DER TLV at `pos`: (header length, content length).
    let private tlv (b: byte[]) (pos: int) =
        if pos + 2 > b.Length then
            raise (InvalidDataException "truncated DER")

        let l0 = int b[pos + 1]

        if l0 < 0x80 then
            2, l0
        else
            let n = l0 &&& 0x7f

            if n = 0 || n > 4 || pos + 2 + n > b.Length then
                raise (InvalidDataException "bad DER length")

            let mutable len = 0

            for i in 0 .. n - 1 do
                len <- (len <<< 8) ||| int b[pos + 2 + i]

            2 + n, len

    /// The SubjectPublicKeyInfo of a certificate, as the bytes in the certificate (Go's
    /// RawSubjectPublicKeyInfo): the seventh field of tbsCertificate, the sixth without a version.
    let subjectPublicKeyInfo (cert: byte[]) : byte[] =
        let h, _ = tlv cert 0
        let tbs = h
        let th, _ = tlv cert tbs
        let mutable pos = tbs + th
        // [0] EXPLICIT version, optional.
        if cert[pos] = 0xa0uy then
            let fh, fl = tlv cert pos
            pos <- pos + fh + fl
        // serialNumber, signature, issuer, validity, subject.
        for _ in 1..5 do
            let fh, fl = tlv cert pos
            pos <- pos + fh + fl

        let fh, fl = tlv cert pos

        if cert[pos] <> 0x30uy || pos + fh + fl > cert.Length then
            raise (InvalidDataException "no SubjectPublicKeyInfo")

        cert[pos .. pos + fh + fl - 1]

/// The common name of the runner certificate of a testnet build (backend/buildflavor).
module Flavor =
    let TestnetCertName = "signer-runner testnet"

/// The runner closed the connection before its first answer.
type ClosedBeforeAnswer(message: string) =
    inherit IOException(message)

type RunnerConnection
    private
    (
        settings: RunnerSettings,
        tcp: TcpClient,
        ssl: SslStream,
        identity: Wire.Identity,
        firstId: uint32,
        certGeneration: int
    ) =
    let gate = obj ()
    let mutable nextId = firstId
    let mutable state = ConnState.Ready
    let mutable closed = false
    // The request on the wire: its id, type and the answer's completion.
    let mutable pending: struct (uint32 * byte * TaskCompletionSource<Wire.Frame>) voption = ValueNone
    let mutable lateSince = DateTimeOffset.MinValue
    let mutable drained = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
    let mutable brokenReason = ""
    let mutable onBroken: (unit -> unit) voption = ValueNone

    let breakWith (why: string) =
        let struct (p, notify) =
            lock gate (fun () ->
                let p = pending
                pending <- ValueNone

                if state <> ConnState.Broken then
                    state <- ConnState.Broken
                    brokenReason <- why
                    struct (p, onBroken)
                else
                    struct (p, ValueNone))

        match p with
        | ValueSome(struct (_, _, tcs)) -> tcs.TrySetException(IOException why) |> ignore
        | ValueNone -> ()

        drained.TrySetResult false |> ignore

        try
            ssl.Dispose()
            tcp.Dispose()
        with _ ->
            ()

        match notify with
        | ValueSome f -> f ()
        | ValueNone -> ()

    let readExactly (buf: byte[]) =
        task {
            let mutable got = 0

            while got < buf.Length do
                let! n = ssl.ReadAsync(buf.AsMemory(got, buf.Length - got))

                if n = 0 then
                    raise (EndOfStreamException "the runner closed the connection")

                got <- got + n
        }

    let readLoop () =
        task {
            try
                let len = Array.zeroCreate<byte> 4

                while true do
                    do! readExactly len
                    let n = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan len)

                    if n > uint32 Wire.MaxFrame then
                        let request =
                            lock gate (fun () ->
                                match pending with
                                | ValueSome(struct (_, t, _)) -> ValueSome t
                                | ValueNone -> ValueNone)

                        raise (InvalidDataException(Wire.frameTooLarge n request))

                    let body = Array.zeroCreate<byte>(int n)
                    do! readExactly body
                    let f = Wire.decodeBody body

                    let action =
                        lock gate (fun () ->
                            match pending with
                            | ValueSome(struct (id, t, tcs)) when f.Id = id && f.Type = (t ||| Wire.ResponseFlag) ->
                                pending <- ValueNone

                                if state = ConnState.Late then
                                    state <- ConnState.Ready
                                    Choice1Of3()
                                else
                                    Choice2Of3 tcs
                            | ValueSome(struct (id, _, _)) ->
                                Choice3Of3 $"unexpected frame {Wire.typeName f.Type} id {f.Id}, want id {id}"
                            | ValueNone ->
                                Choice3Of3 $"unexpected frame {Wire.typeName f.Type} id {f.Id} with no request out")

                    match action with
                    | Choice1Of3() -> drained.TrySetResult true |> ignore
                    | Choice2Of3 tcs -> tcs.TrySetResult f |> ignore
                    | Choice3Of3 why -> raise (InvalidDataException why)
            with e ->
                breakWith e.Message
        }

    member _.Settings = settings
    member _.Identity = identity

    /// The generation of the client certificate this connection was dialed with.
    member _.CertGeneration = certGeneration

    member _.State = lock gate (fun () -> state)
    member _.BrokenReason = brokenReason

    /// Completes true when the late reply came and the connection is ready again, false when
    /// the connection broke.
    member _.Drained = drained.Task
    member _.LateSince = lateSince

    /// Sends one request and waits for its answer frame. Cancellation leaves the connection late
    /// when the request is on the wire; a request cancelled before it was sent leaves it as it is.
    member this.Send(t: Wire.MsgType, payload: byte[], ct: CancellationToken) : Task<Wire.Frame> =
        task {
            ct.ThrowIfCancellationRequested()
            let tcs = TaskCompletionSource<Wire.Frame>(TaskCreationOptions.RunContinuationsAsynchronously)

            let id =
                lock gate (fun () ->
                    if state <> ConnState.Ready then
                        raise (IOException $"connection not ready ({state})")

                    nextId <- nextId + 1u
                    pending <- ValueSome(struct (nextId, byte t, tcs))
                    drained <- TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
                    nextId)

            let frame = Wire.encodeFrame (byte t) id (ReadOnlySpan payload)

            try
                // Not cancelled by ct: a frame cut in half would leave the runner out of step.
                do! ssl.WriteAsync(frame.AsMemory())
                do! ssl.FlushAsync()
            with e ->
                breakWith $"write: {e.Message}"
                raise (IOException($"write: {e.Message}", e))

            use _ =
                ct.Register(fun () ->
                    let late =
                        lock gate (fun () ->
                            match pending with
                            | ValueSome(struct (pid, _, _)) when pid = id && state = ConnState.Ready ->
                                state <- ConnState.Late
                                lateSince <- DateTimeOffset.UtcNow
                                true
                            | _ -> false)

                    if late then
                        tcs.TrySetCanceled ct |> ignore)

            return! tcs.Task
        }

    member _.Close() =
        lock gate (fun () -> closed <- true)
        breakWith "closed"

    member _.IsClosed = closed

    /// The TLS client side of a dial: TLS 1.3, the client certificate with its intermediates,
    /// and the runner's certificate read for the build flavour only (the attested identity
    /// checks it after).
    static member Authenticate
        (
            ssl: SslStream,
            s: RunnerSettings,
            cert: SslStreamCertificateContext,
            flavourRefused: bool ref,
            ct: CancellationToken
        ) : Task =
        task {
            let opts =
                SslClientAuthenticationOptions(
                    TargetHost = s.Host,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    ClientCertificateContext = cert,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                )

            try
                do! ssl.AuthenticateAsClientAsync(opts, ct)
            with :? AuthenticationException as e when flavourRefused.Value ->
                raise (
                    AuthenticationException(
                        "the runner is a testnet build (governance time locks in minutes, test networks only); set allow_testnet_build to accept it",
                        e
                    )
                )
        }

    /// The certificate check of a dial: any certificate, unless it names the testnet build and
    /// that is not allowed. The certificate is self-signed inside the TEE: it is checked against
    /// the attested identity, not against a CA.
    static member Validator(s: RunnerSettings, flavourRefused: bool ref) =
        RemoteCertificateValidationCallback(fun _ cert _ _ ->
            match cert with
            | null -> false
            | c ->
                use c2 = new X509Certificate2(c)
                let cn = c2.GetNameInfo(X509NameType.SimpleName, false)

                if cn = Flavor.TestnetCertName && not s.AllowTestnetBuild then
                    flavourRefused.Value <- true
                    false
                else
                    true)

    /// Connects, runs TLS and IDENTITY and checks the runner. `now` is the wall clock for the
    /// attestation check. The token bounds all of it.
    static member Dial(s: RunnerSettings, now: unit -> DateTimeOffset, ct: CancellationToken) : Task<RunnerConnection> =
        task {
            let tcp = new TcpClient(NoDelay = true)
            // Disposed with tcp when the dial fails after TLS started.
            let sslOf: (SslStream | null) ref = ref null

            try
                let cert = s.ClientCert.Current

                if now () >= cert.NotAfter then
                    raise (
                        AuthenticationException
                            $"the client certificate in {s.ClientCert.Files} expired on {cert.NotAfter.UtcDateTime:u}; replace it (it reloads while running)"
                    )

                do! tcp.ConnectAsync(s.Host, s.Port, ct)
                let flavourRefused = ref false
                let ssl = new SslStream(tcp.GetStream(), false, RunnerConnection.Validator(s, flavourRefused))
                sslOf.Value <- ssl
                do! RunnerConnection.Authenticate(ssl, s, cert.Value, flavourRefused, ct)

                let peer =
                    match ssl.RemoteCertificate with
                    | null -> raise (AuthenticationException "the runner sent no certificate")
                    | c -> c.GetRawCertData()

                let keyHash = SHA256.HashData(Der.subjectPublicKeyInfo peer)

                match s.TlsKeyPin with
                | ValueSome pin when not (ReadOnlySpan(pin).SequenceEqual(ReadOnlySpan keyHash)) ->
                    raise (
                        AuthenticationException
                            $"runner TLS key {Convert.ToHexStringLower keyHash} is not the pinned key"
                    )
                | _ -> ()
                // IDENTITY with a fresh nonce over the new channel, frame id 1.
                let nonce = RandomNumberGenerator.GetBytes 32

                let req =
                    Wire.encodeFrame (byte Wire.MsgType.Identity) 1u (ReadOnlySpan(Wire.encodeIdentityRequest nonce))

                do! ssl.WriteAsync(req.AsMemory(), ct)
                do! ssl.FlushAsync ct
                let len = Array.zeroCreate<byte> 4

                try
                    do! ssl.ReadExactlyAsync(len.AsMemory(), ct)
                with :? EndOfStreamException ->
                    // Under TLS 1.3 the client's handshake ends before the server checks the
                    // client certificate, so a refused certificate looks like this.
                    raise (
                        ClosedBeforeAnswer
                            "the runner closed the connection before its first answer; a runner that refuses the client certificate does the same (check client_cert, its intermediates and the runner's client CA)"
                    )

                let n = BinaryPrimitives.ReadUInt32BigEndian(ReadOnlySpan len)

                if n > uint32 Wire.MaxFrame then
                    raise (InvalidDataException "frame too large")

                let body = Array.zeroCreate<byte>(int n)
                do! ssl.ReadExactlyAsync(body.AsMemory(), ct)
                let f = Wire.decodeBody body

                if f.Id <> 1u || f.Type <> (byte Wire.MsgType.Identity ||| Wire.ResponseFlag) then
                    raise (InvalidDataException $"unexpected response {Wire.typeName f.Type} id {f.Id}, want id 1")

                let identity =
                    match Wire.decodeResponse f.Payload with
                    | Ok b -> Wire.decodeIdentity b
                    | Error r when r.Code = Wire.Status.Unsupported || r.Code = Wire.Status.BadRequest ->
                        raise (
                            InvalidDataException
                                $"the runner does not speak IDENTITY v{Wire.IdentityVersion} of tee-signer: {Wire.Status.name r.Code}: {r.Detail}"
                        )
                    | Error r -> raise (InvalidDataException $"IDENTITY refused: {Wire.Status.name r.Code}: {r.Detail}")

                if not (ReadOnlySpan(identity.TlsKeyHash).SequenceEqual(ReadOnlySpan keyHash)) then
                    raise (
                        AuthenticationException(
                            $"runner presented TLS key {Convert.ToHexStringLower keyHash} but its attested identity names {Convert.ToHexStringLower identity.TlsKeyHash}"
                        )
                    )

                do! Attest.verifyIdentity s.Verifier nonce identity (now ()) ct
                let c = new RunnerConnection(s, tcp, ssl, identity, 1u, cert.Generation)
                c.StartReading()
                return c
            with e ->
                match sslOf.Value with
                | null -> ()
                | ssl -> ssl.Dispose()

                tcp.Dispose()
                return raise (IOException($"{s.Name}: {e.Message}", e))
        }

    member private _.StartReading() = readLoop () |> ignore

    interface PoolConn with
        member this.State = this.State
        member this.Drained = this.Drained
        member this.Close() = this.Close()

    interface BreakNotice with
        member _.OnBroken(f: unit -> unit) =
            let now =
                lock gate (fun () ->
                    if state = ConnState.Broken then
                        true
                    else
                        onBroken <- ValueSome f
                        false)

            if now then
                f ()
