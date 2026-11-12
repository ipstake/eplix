/// A TLS client certificate with its intermediates, for the modules that dial a server with
/// mutual TLS (TEE runners, Web3Signer, Dirk).
/// The intermediates go with the leaf, so a server that trusts only the root CA accepts it.
module Eplix.ClientCert

open System
open System.IO
open System.Net.Security
open System.Security.Cryptography.X509Certificates

/// The earliest NotAfter of `certs`: the chain stops working when any of them expires.
let notAfter (certs: X509Certificate2 seq) =
    certs |> Seq.map (fun c -> DateTimeOffset(c.NotAfter.ToUniversalTime())) |> Seq.min

/// The latest NotBefore of `certs`: the chain works only once every one of them is valid.
let notBefore (certs: X509Certificate2 seq) =
    certs |> Seq.map (fun c -> DateTimeOffset(c.NotBefore.ToUniversalTime())) |> Seq.max

/// The latest NotBefore of a context's certificate and the intermediates it sends.
let validFrom (c: SslStreamCertificateContext) =
    notBefore (Seq.append [ c.TargetCertificate ] c.IntermediateCertificates)

/// Fails when the PEM text has more BEGIN CERTIFICATE lines than `imported` certificates:
/// ImportFromPem skips a block without its END line, so a file cut short in its last
/// certificate would load with one certificate less.
let checkPemCount (pem: string) (imported: int) =
    let marker = "-----BEGIN CERTIFICATE-----"
    let mutable n = 0
    let mutable i = pem.IndexOf(marker, StringComparison.Ordinal)

    while i >= 0 do
        n <- n + 1
        i <- pem.IndexOf(marker, i + marker.Length, StringComparison.Ordinal)

    if n <> imported then
        raise (
            InvalidDataException
                $"{n} BEGIN CERTIFICATE blocks but {imported} certificates read; the file may be cut short"
        )

/// The client certificate with its key and the certificates after it in the same PEM text, the
/// intermediates up to the root, as of `now`. The first certificate in `certPem` is the client
/// certificate. TLS sends it with the intermediates, so a server that trusts only the root CA
/// can build the chain; the context is built offline (no download of missing issuers). Returns
/// the context and the earliest NotAfter of the chain. An IOException names `certFile` and the
/// certificate when it or one after it has expired; a key that does not match the certificate
/// throws a CryptographicException.
let ofPem
    (certFile: string)
    (certPem: string)
    (keyPem: string)
    (now: DateTimeOffset)
    : SslStreamCertificateContext * DateTimeOffset =
    let leaf = X509Certificate2.CreateFromPem(certPem.AsSpan(), keyPem.AsSpan())
    let all = X509Certificate2Collection()
    all.ImportFromPem(certPem.AsSpan())

    try
        checkPemCount certPem all.Count
    with :? InvalidDataException as e ->
        raise (InvalidDataException $"{certFile}: {e.Message}")

    let extra = X509Certificate2Collection()

    for c in all do
        if c.Thumbprint <> leaf.Thumbprint then
            extra.Add c |> ignore

    for c in Seq.append [ leaf ] extra do
        if now > DateTimeOffset(c.NotAfter.ToUniversalTime()) then
            raise (IOException $"{certFile}: the certificate {c.Subject} expired on {c.NotAfter.ToUniversalTime():u}")

    SslStreamCertificateContext.Create(leaf, extra, offline = true), notAfter (Seq.append [ leaf ] extra)
