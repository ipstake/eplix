/// The local key backend: whole keys from EIP-2335 keystores, signing in process.
/// The VC's slashing DB is the only protection for these keys.
namespace Eplix.Backend.Local

open System
open System.Collections.Generic
open System.IO
open System.Security.Cryptography
open System.Threading
open System.Threading.Tasks
open Eplix

/// A secret key in a pinned array, zeroed on Dispose.
type SecretKey private (bytes: byte[]) =
    let mutable disposed = false

    static member Copy(secret: ReadOnlySpan<byte>) =
        let pinned = GC.AllocateArray<byte>(32, pinned = true)
        secret.CopyTo(Span pinned)
        new SecretKey(pinned)

    member _.Span: ReadOnlySpan<byte> =
        if disposed then
            raise (ObjectDisposedException "SecretKey")

        ReadOnlySpan bytes

    interface IDisposable with
        member _.Dispose() =
            if not disposed then
                CryptographicOperations.ZeroMemory(Span bytes)
                disposed <- true

/// The keys of the local backend. Keys can be added and removed while the VC runs; a removed
/// key's secret is zeroed once no signature uses it.
type LocalKeys(name: string) =
    let table = Dictionary<PubKey, SecretKey>()
    let gate = obj ()
    // Signing holds the read side while it uses a secret; Remove takes the write side before
    // it zeroes one. Many signatures run at once.
    let rw = new ReaderWriterLockSlim()

    let signWith (key: PubKey) (root: Root) : SignOutcome =
        rw.EnterReadLock()

        try
            match
                lock gate (fun () ->
                    match table.TryGetValue key with
                    | true, sk -> ValueSome sk
                    | _ -> ValueNone)
            with
            | ValueSome sk -> Signed(BlsSignature.Of(Bls.sign sk.Span (ReadOnlySpan root.Bytes)))
            | ValueNone -> Refused UnknownKey
        finally
            rw.ExitReadLock()

    static member Capabilities =
        {
            Duties =
                set
                    [
                        DutyKind.Attestation
                        DutyKind.Block
                        DutyKind.RandaoReveal
                        DutyKind.AggregationSlot
                        DutyKind.AggregateAndProof
                        DutyKind.SyncCommitteeMessage
                        DutyKind.SyncSelectionProof
                        DutyKind.ContributionAndProof
                        DutyKind.VoluntaryExit
                        DutyKind.PayloadAttestation
                        DutyKind.PayloadEnvelope
                        DutyKind.ProposerPreferences
                        DutyKind.BuilderRequestAuth
                        DutyKind.ValidatorRegistration
                    ]
            TypedOnly = false
            EnforcesSlashing = false
            ReturnsPartials = false
            MaxInFlight = Environment.ProcessorCount
        }

    /// Adds a key; the backend owns the secret from here on. False (and the secret is disposed)
    /// when the key is already present.
    member _.Add(pk: PubKey, sk: SecretKey) : bool =
        lock gate (fun () ->
            if table.ContainsKey pk then
                (sk :> IDisposable).Dispose()
                false
            else
                table[pk] <- sk
                true)

    member _.Remove(pk: PubKey) : bool =
        rw.EnterWriteLock()

        try
            lock gate (fun () ->
                match table.TryGetValue pk with
                | true, sk ->
                    table.Remove pk |> ignore
                    (sk :> IDisposable).Dispose()
                    true
                | _ -> false)
        finally
            rw.ExitWriteLock()

    member _.Contains(pk: PubKey) = lock gate (fun () -> table.ContainsKey pk)
    member _.Keys: PubKey list = lock gate (fun () -> List.ofSeq table.Keys)

    member this.Backend: Backend =
        {
            Name = name
            Capabilities = LocalKeys.Capabilities
            Keys = fun _ -> Task.FromResult [ for k in this.Keys -> { Key = k; Share = ValueNone } ]
            Health = fun _ -> Task.FromResult Up
            // On the thread pool, so a burst signs on every core instead of one after another.
            Sign = fun req _ -> Task.Run(fun () -> signWith req.Key req.SigningRoot)
            Dispose =
                fun () ->
                    rw.EnterWriteLock()

                    try
                        lock gate (fun () ->
                            for sk in table.Values do
                                (sk :> IDisposable).Dispose()

                            table.Clear())
                    finally
                        rw.ExitWriteLock()

                    ValueTask.CompletedTask
        }

module LocalBackend =
    let capabilities = LocalKeys.Capabilities

    /// A backend over in-memory secret keys. The keys are owned by the backend from here on.
    let create (name: string) (keys: (PubKey * SecretKey) list) : Backend =
        let k = LocalKeys name

        for pk, sk in keys do
            k.Add(pk, sk) |> ignore

        k.Backend

type KeystoreSource =
    {
        Path: string
        /// One password for every keystore (deposit-cli), or the password directory (Teku).
        PasswordFile: string voption
        /// ValueNone: detect the layout.
        Layout: Layouts.Layout voption
    }

/// A keystore read from disk and decrypted.
type LoadedKey =
    {
        Key: PubKey
        Secret: SecretKey
        File: string
        DerivationPath: string
    }

module KeystoreFiles =
    /// The keystore entries of a source in its layout. Notes name skipped entries.
    let entries (src: KeystoreSource) : Result<Layouts.Entry list * string list, string> =
        let layout =
            match src.Layout with
            | ValueSome l -> Ok l
            | ValueNone -> Layouts.detect src.Path

        layout |> Result.bind (fun l -> Layouts.entries l src.Path src.PasswordFile)

    /// Reads an entry's password and keystore text. An error when a file is missing or cannot be
    /// read (permissions, removed after the check); nothing is decrypted then.
    let read (e: Layouts.Entry) : Result<string * string, string> =
        match Layouts.readPassword e.Password with
        | Error err -> Error $"{e.Keystore}: {err}"
        | Ok password ->
            if not (File.Exists e.Keystore) then
                Error $"{e.Keystore}: not found"
            else
                try
                    Ok(password, File.ReadAllText e.Keystore)
                with
                | :? IOException
                | :? UnauthorizedAccessException as x -> Error $"{e.Keystore}: cannot be read: {x.Message}"

    /// Checks and decrypts a keystore read by `read`.
    let decryptRead (e: Layouts.Entry) (password: string) (json: string) : Result<LoadedKey, string> =
        match Keystore.parse json with
        | Error err -> Error $"{e.Keystore}: {err}"
        | Ok ks ->
            match Keystore.decrypt ks password with
            | Error err -> Error $"{e.Keystore}: {err}"
            | Ok secret ->
                try
                    let pk = PubKey.Of(Bls.publicKey (ReadOnlySpan secret))

                    Ok
                        {
                            Key = pk
                            Secret = SecretKey.Copy(ReadOnlySpan secret)
                            File = e.Keystore
                            DerivationPath = ks.Path
                        }
                finally
                    CryptographicOperations.ZeroMemory(Span secret)

    /// Reads, checks and decrypts one keystore.
    let decryptOne (e: Layouts.Entry) : Result<LoadedKey, string> =
        read e |> Result.bind (fun (password, json) -> decryptRead e password json)

    /// Decrypts keystores, `parallelism` at a time. scrypt with n = 2^18 takes 256 MiB per
    /// keystore, so parallelism bounds memory. Results keep the order of the input. An exception
    /// from one item is that item's error; the others go on, so the batch itself does not throw.
    let decryptAll
        (parallelism: int)
        (items: 'T[])
        (decrypt: 'T -> Result<LoadedKey, string>)
        : Result<LoadedKey, string>[] =
        let results = Array.zeroCreate<Result<LoadedKey, string>> items.Length
        let options = ParallelOptions(MaxDegreeOfParallelism = max 1 parallelism)

        let one i =
            results[i] <-
                try
                    decrypt items[i]
                with e ->
                    Error $"decrypt failed: {e.Message}"

        Parallel.For(0, items.Length, options, (fun i -> one i)) |> ignore
        results

    /// The decrypted keys in input order, each public key once: a repeat is disposed and named in
    /// a warning. The errors in input order. A set of the keys seen, so 50,000 keys take
    /// milliseconds; the list scan it replaces took over a minute at 50,000.
    let keepFirst (results: Result<LoadedKey, string>[]) (log: Log) : ResizeArray<LoadedKey> * ResizeArray<string> =
        let ok = ResizeArray<LoadedKey>(results.Length)
        let errors = ResizeArray<string>()
        let seen = HashSet<PubKey>()

        for r in results do
            match r with
            | Ok k when not (seen.Add k.Key) ->
                (k.Secret :> IDisposable).Dispose()
                log.Warn $"{k.File}: key {k.Key.Short} is already loaded; skipped"
            | Ok k -> ok.Add k
            | Error e -> errors.Add e

        ok, errors

    /// Decrypts every keystore of the sources. Duplicate keys are kept once, with a warning.
    let load (sources: KeystoreSource list) (parallelism: int) (log: Log) : Result<LoadedKey list, string list> =
        let errors = ResizeArray<string>()
        let all = ResizeArray<Layouts.Entry>()

        for src in sources do
            match entries src with
            | Error e -> errors.Add e
            | Ok(list, notes) ->
                for n in notes do
                    log.Warn n

                all.AddRange list

        let results = decryptAll parallelism (all.ToArray()) decryptOne
        let ok, failed = keepFirst results log
        errors.AddRange failed

        if errors.Count = 0 then
            Ok(List.ofSeq ok)
        else
            for k in ok do
                (k.Secret :> IDisposable).Dispose()

            Error(List.ofSeq errors)
