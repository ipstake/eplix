/// The TLS check of a new Web3Signer connection, measured like the other micro benchmarks:
/// the callback called in a loop, 7 runs, the median per call and the bytes allocated per call.
/// Three checks: the CA chain alone (no attestation), the attested key set alone, and both.
/// Usage: Eplix.Bench w3s-attest [calls per run]   (default 20000)
module Eplix.Bench.W3sAttestBench

open System
open System.Diagnostics
open System.Net
open System.Net.Security
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading.Tasks
open Eplix
open Eplix.Backend.Web3Signer

type private Fixed(keys: byte[] list) =
    interface AttestationSource with
        member _.Describe = "bench"
        member _.Files = []
        member _.Attest _ = Task.FromResult(AttestationResult.Attested keys)

let private pki () =
    let now = DateTimeOffset.UtcNow
    use rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let rootReq = CertificateRequest("CN=bench root", rootKey, HashAlgorithmName.SHA256)
    rootReq.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    rootReq.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
    use root = rootReq.CreateSelfSigned(now.AddDays -1.0, now.AddDays 30.0)
    use key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let req = CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256)
    let san = SubjectAlternativeNameBuilder()
    san.AddDnsName "localhost"
    req.CertificateExtensions.Add(san.Build())
    use leaf = req.Create(root, now.AddDays -1.0, now.AddDays 10.0, [| 1uy |])
    X509CertificateLoader.LoadCertificate root.RawData, X509CertificateLoader.LoadCertificate leaf.RawData

let run (args: string list) =
    let calls =
        match args with
        | n :: _ -> int n
        | [] -> 20000

    let root, leaf = pki ()

    let ca =
        TlsFile<X509Certificate2Collection>.Fixed(X509Certificate2Collection root, DateTimeOffset.MaxValue)

    let keys =
        AttestedKeys(
            "bench",
            Fixed [ Array.create 32 1uy; Spki.hash leaf; Array.create 32 2uy ],
            TimeSpan.Zero,
            TimeSpan.Zero,
            TimeSpan.Zero,
            Log.none,
            TimeProvider.System
        )

    keys.Refresh(Threading.CancellationToken.None).GetAwaiter().GetResult()

    let check (name: string) (tls: HttpSigner.LoadedTls) =
        let v = (HttpSigner.validatorFor tls).Value

        if not (v.Invoke(null, leaf, null, SslPolicyErrors.None)) then
            failwith $"{name}: the check refused the certificate"

        let runs =
            [
                for _ in 1..7 ->
                    let a0 = GC.GetAllocatedBytesForCurrentThread()
                    let sw = Stopwatch.StartNew()

                    for _ in 1..calls do
                        v.Invoke(null, leaf, null, SslPolicyErrors.None) |> ignore

                    sw.Stop()
                    let bytes = GC.GetAllocatedBytesForCurrentThread() - a0
                    sw.Elapsed.TotalNanoseconds / float calls, float bytes / float calls
            ]

        let ns = runs |> List.map fst |> List.sort
        let b = runs |> List.map snd |> List.sort

        printfn
            $"{name, -12} median {ns[3], 9:F0} ns/call (runs {ns.Head:F0} to {List.last ns:F0}), {b[3], 7:F0} B/call"

    let none = HttpSigner.LoadedTls.None
    check "ca_cert" { none with Ca = ValueSome ca }
    check "attested" { none with Attested = ValueSome keys }

    check
        "both"
        { none with
            Ca = ValueSome ca
            Attested = ValueSome keys
        }

    0
