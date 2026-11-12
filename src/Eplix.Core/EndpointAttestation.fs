/// Attestation of a remote signer endpoint before it gets a request.
/// A source fetches and checks evidence off the request path and returns the TLS keys it
/// attests; AttestedKeys holds them for the TLS check of each new connection, which is a
/// lookup with no I/O. Sources: `pinned` (Web3Signer module), `runner` (TEE module, registered
/// here so the Web3Signer module does not depend on it), `http` (later, for tee-signer).
namespace Eplix

open System
open System.Collections.Concurrent
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Threading
open System.Threading.Tasks

/// What one attestation gave.
[<RequireQualifiedAccess>]
type AttestationResult =
    /// The SHA-256 hashes of the SubjectPublicKeyInfo of the TLS keys the evidence attests.
    | Attested of keys: byte[] list
    /// The evidence was there and failed a check: the endpoint is not trusted.
    | Refused of reason: string
    /// No evidence came (the source did not answer): the last attested keys stay for a while.
    | Unavailable of reason: string

/// One way to attest an endpoint.
type AttestationSource =
    /// For logs: the source and where it asks.
    abstract Describe: string
    /// Fetches the evidence and checks it. Runs off the request path.
    abstract Attest: CancellationToken -> Task<AttestationResult>
    /// TLS files the source reads, for the module's reload task.
    abstract Files: TlsCheck list

/// What a source kind gets to build a source at start.
type AttestationBuild =
    {
        /// The endpoint the source attests, for messages.
        Endpoint: string
        /// The endpoint's `attestation` block.
        Block: JsonElement
        Section: ConfigSection
        Log: Log
        Time: TimeProvider
    }

/// A source kind another module provides: a check of its config block (at configure time) and
/// a build (at start).
type AttestationSourceKind =
    {
        Name: string
        Check: ConfigSection -> string -> JsonElement -> Result<unit, string>
        Build: AttestationBuild -> Result<AttestationSource, string>
    }

module AttestationSources =
    let private kinds = ConcurrentDictionary<string, AttestationSourceKind>()

    /// Registers a kind; the module that provides it calls this when it is created.
    let register (k: AttestationSourceKind) = kinds[k.Name] <- k

    let tryFind (name: string) =
        match kinds.TryGetValue name with
        | true, k -> ValueSome k
        | _ -> ValueNone

module Spki =
    /// The SHA-256 of a certificate's SubjectPublicKeyInfo, the TLS key hash runners attest.
    let hash (cert: X509Certificate) : byte[] =
        match cert with
        | :? X509Certificate2 as c -> SHA256.HashData(c.PublicKey.ExportSubjectPublicKeyInfo())
        | c ->
            use c2 = X509CertificateLoader.LoadCertificate(c.GetRawCertData())
            SHA256.HashData(c2.PublicKey.ExportSubjectPublicKeyInfo())

/// The TLS keys attested for one endpoint, and the task that refreshes them:
/// at start, every `refresh` (zero: never on a timer while up), and at once after a handshake
/// met a key not in the set, at most once per `minGap`. `Contains` is the lookup of the TLS
/// check. While the set is empty, or the server presented a key the evidence does not cover,
/// `Down` gives the reason: the endpoint counts as down and its requests fail at once, with no
/// dial. A down endpoint is attested again every `retry`; after a timed attempt that still
/// misses the presented key, the next request may dial once more, so a server that went back
/// to an attested key comes back. When the source gives no answer, the last keys stay for
/// three refresh intervals (an hour without a refresh interval), then go.
[<Sealed>]
type AttestedKeys
    (
        endpoint: string,
        source: AttestationSource,
        refresh: TimeSpan,
        minGap: TimeSpan,
        retry: TimeSpan,
        log: Log,
        time: TimeProvider
    ) =
    let gate = obj ()

    [<VolatileField>]
    let mutable keys: byte[][] = [||]

    [<VolatileField>]
    let mutable down = $"{endpoint}: not attested yet"

    let mutable rejected: byte[] voption = ValueNone
    let mutable lastGood = DateTimeOffset.MinValue
    let early = new SemaphoreSlim(0, 1)
    let keep = if refresh > TimeSpan.Zero then refresh * 3.0 else TimeSpan.FromHours 1.0

    let hex (ks: byte[] seq) = String.Join(", ", ks |> Seq.map Convert.ToHexStringLower)

    let has (ks: byte[][]) (hash: byte[]) =
        let mutable found = false

        for k in ks do
            if not found && ReadOnlySpan(k).SequenceEqual(ReadOnlySpan hash) then
                found <- true

        found

    member _.Endpoint = endpoint
    member _.Source = source

    /// Whether the key hash is attested: the TLS check's lookup.
    member _.Contains(hash: byte[]) = has keys hash

    /// Why the endpoint is down, when it is.
    member _.Down: string voption =
        match down with
        | "" -> ValueNone
        | d -> ValueSome d

    member _.Keys = List.ofArray keys

    /// From the TLS check: the server presented a key not in the set. Marks the endpoint down
    /// and asks for an attestation now.
    member _.Unknown(hash: byte[]) =
        lock gate (fun () ->
            rejected <- ValueSome hash

            down <-
                $"{endpoint}: the server's TLS key {Convert.ToHexStringLower hash} is not attested; attesting again")

        try
            early.Release() |> ignore
        with :? SemaphoreFullException ->
            ()

    /// One attestation; `asked` when an unknown key asked for it.
    member _.Refresh(ct: CancellationToken, ?asked: bool) : Task =
        let asked = defaultArg asked false

        task {
            let! r =
                task {
                    try
                        return! source.Attest ct
                    with e ->
                        return AttestationResult.Unavailable e.Message
                }

            let now = time.GetUtcNow()

            lock gate (fun () ->
                match r with
                | AttestationResult.Attested ks ->
                    let fresh = Array.ofList ks
                    let changed = hex fresh <> hex keys
                    keys <- fresh
                    lastGood <- now

                    match rejected with
                    | ValueSome k when not (has fresh k) && asked ->
                        log.Warn
                            $"{endpoint}: {source.Describe} still does not attest the server's TLS key {Convert.ToHexStringLower k}"
                    | _ ->
                        let wasDown = down <> ""
                        rejected <- ValueNone
                        down <- ""

                        if changed || wasDown then
                            log.Info $"{endpoint}: attested by {source.Describe}, TLS keys {hex fresh}"
                | AttestationResult.Refused m ->
                    keys <- [||]
                    down <- $"{endpoint}: attestation refused: {m}"
                    log.Error $"{endpoint}: {source.Describe} refused: {m}; no request goes to it"
                | AttestationResult.Unavailable m when keys.Length > 0 && now - lastGood < keep ->
                    log.Warn
                        $"{endpoint}: {source.Describe} gave no answer: {m}; the keys attested at {lastGood.UtcDateTime:u} stay"
                | AttestationResult.Unavailable m ->
                    keys <- [||]
                    down <- $"{endpoint}: not attested: {m}"
                    log.Error $"{endpoint}: {source.Describe} gave no answer: {m}; no request goes to it")
        }

    /// Refreshes until cancelled.
    member this.Run(ct: CancellationToken) : Task =
        task {
            try
                // One wait on the semaphore at a time, so no release is lost to a stale waiter.
                let mutable asked = early.WaitAsync ct

                while not ct.IsCancellationRequested do
                    let wait =
                        match down, refresh > TimeSpan.Zero with
                        | "", true -> refresh
                        | "", false -> Timeout.InfiniteTimeSpan
                        | _, true -> min refresh retry
                        | _, false -> retry

                    let! first = Task.WhenAny(Task.Delay(wait, time, ct), asked)
                    ct.ThrowIfCancellationRequested()
                    let byKey = obj.ReferenceEquals(first, asked)

                    if byKey then
                        asked <- early.WaitAsync ct

                    do! this.Refresh(ct, byKey)
                    do! Task.Delay(minGap, time, ct)
            with :? OperationCanceledException ->
                ()
        }
