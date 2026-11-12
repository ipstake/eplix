/// The local backend as a module. Config section "local":
///   { "keystores": [ { "path": "<dir or file>", "password_file": "<file or dir>", "layout": "<name>" } ],
///     "decrypt_parallelism": 4, "reload_interval_seconds": 12, "signing": { ... } }
/// "signing" (jitter_ms, jitter_by_duty_ms) is read by the core (SigningJitter.fs).
/// Keys imported at run time (keymanager API, `eplix import`) live in the data dir in the
/// Lodestar layout: keystores/<0xpubkey>/voting-keystore.json and secrets/<0xpubkey>.
/// The module checks its directories for new and removed keystores every reload interval.
module Eplix.Backend.Local.LocalModule

open System
open System.Collections.Generic
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Json

let name = "local"

type Settings =
    {
        Sources: KeystoreSource list
        /// Keystores decrypted at once. scrypt (n = 2^18) takes 256 MiB each.
        DecryptParallelism: int
        /// 0 turns the directory check off.
        ReloadInterval: TimeSpan
    }

let defaultParallelism = max 1 (min 4 Environment.ProcessorCount)

/// The keystores Eplix keeps in its data dir.
module ManagedStore =
    let keystoresDir (dataDir: string) = Path.Combine(dataDir, "keystores")
    let secretsDir (dataDir: string) = Path.Combine(dataDir, "secrets")
    let keystoreFile (dataDir: string) (pk: PubKey) = Path.Combine(keystoresDir dataDir, pk.Hex, "voting-keystore.json")
    let secretFile (dataDir: string) (pk: PubKey) = Path.Combine(secretsDir dataDir, pk.Hex)

    let private owner = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private ownerDir = owner ||| UnixFileMode.UserExecute

    /// Creates a missing directory with mode 0700 from the start.
    let private ensureDir (d: string) =
        if not (Directory.Exists d) then
            if OperatingSystem.IsWindows() then
                Directory.CreateDirectory d |> ignore
            else
                Directory.CreateDirectory(d, ownerDir) |> ignore

    /// Sets 0700 on the keystores and secrets dirs that exist. A dir made by hand, copied in or
    /// left by a migration may let other users list it or read a password file.
    let tighten (dataDir: string) =
        if not (OperatingSystem.IsWindows()) then
            for d in [ keystoresDir dataDir; secretsDir dataDir ] do
                if Directory.Exists d then
                    File.SetUnixFileMode(d, ownerDir)

    /// Writes a file atomically and durably, created 0600 (FileSync.writeAtomic).
    let private writeDurable (path: string) (content: byte[]) =
        ensureDir (nonNull (Path.GetDirectoryName path))
        Slashing.FileSync.writeAtomic path content owner

    /// Saves the original keystore JSON (never re-encrypted) and its password. When the keystore
    /// cannot be written, the password file goes too: no clear text password stays for a key the
    /// VC does not hold.
    let save (dataDir: string) (pk: PubKey) (keystoreJson: string) (password: string) =
        ensureDir dataDir
        ensureDir (keystoresDir dataDir)
        ensureDir (secretsDir dataDir)
        tighten dataDir
        let secret = secretFile dataDir pk
        writeDurable secret (Text.Encoding.UTF8.GetBytes password)

        try
            writeDurable (keystoreFile dataDir pk) (Text.Encoding.UTF8.GetBytes keystoreJson)
        with _ ->
            try
                File.Delete secret
            with _ ->
                ()

            reraise ()

    let delete (dataDir: string) (pk: PubKey) =
        let ks = keystoreFile dataDir pk

        if File.Exists ks then
            File.Delete ks

        let d = nonNull (Path.GetDirectoryName ks)

        if Directory.Exists d && Directory.GetFileSystemEntries(d).Length = 0 then
            Directory.Delete d

        let s = secretFile dataDir pk

        if File.Exists s then
            File.Delete s

    let source (dataDir: string) : KeystoreSource =
        {
            Path = keystoresDir dataDir
            PasswordFile = ValueNone
            Layout = ValueSome Layouts.Layout.Lodestar
        }

    let isManaged (dataDir: string) (file: string) =
        Path.GetFullPath(file).StartsWith(Path.GetFullPath(keystoresDir dataDir) + string Path.DirectorySeparatorChar)

let private parseSettings (section: ConfigSection) : Result<Settings, string list> =
    let empty =
        {
            Sources = []
            DecryptParallelism = defaultParallelism
            ReloadInterval = TimeSpan.FromSeconds 12.0
        }

    match section.Element with
    | ValueNone -> Ok empty
    | ValueSome e ->
        let errors =
            checkFields e "modules.local" [ "keystores"; "decrypt_parallelism"; "reload_interval_seconds"; "signing" ]

        if not errors.IsEmpty then
            Error errors
        else
            try
                let sources =
                    match tryProp e "keystores" with
                    | ValueNone -> []
                    | ValueSome ks ->
                        array ks
                        |> Array.toList
                        |> List.map (fun k ->
                            match checkFields k "modules.local.keystores[]" [ "path"; "password_file"; "layout" ] with
                            | [] ->
                                {
                                    Path = section.Path(strField k "path")
                                    PasswordFile =
                                        tryProp k "password_file" |> ValueOption.map (fun p -> section.Path(str p))
                                    Layout =
                                        match tryProp k "layout" with
                                        | ValueNone -> ValueNone
                                        | ValueSome l when str l = "auto" -> ValueNone
                                        | ValueSome l ->
                                            match Layouts.parse (str l) with
                                            | Ok x -> ValueSome x
                                            | Error err -> fail err
                                }
                            | errs -> fail (String.concat "; " errs))

                let parallelism =
                    match tryProp e "decrypt_parallelism" with
                    | ValueSome v -> boundedInt "decrypt_parallelism" 1 64 v
                    | ValueNone -> defaultParallelism
                // 0 turns the reload off.
                let reload =
                    match tryProp e "reload_interval_seconds" with
                    | ValueSome v -> boundedSeconds "reload_interval_seconds" 0UL Bounds.Day v
                    | ValueNone -> empty.ReloadInterval

                Ok
                    {
                        Sources = sources
                        DecryptParallelism = parallelism
                        ReloadInterval = reload
                    }
            with :? JsonDecodeError as e ->
                Error [ $"modules.local: {e.Message}" ]

type private KeyInfo =
    {
        File: string
        DerivationPath: string
        Managed: bool
    }

/// What one directory check decrypts.
module Rescan =
    /// The entries to decrypt: keystore files no loaded key came from that were never tried, or
    /// whose keystore or password file changed since the last try. `loaded` holds the files of
    /// the loaded keys, so each entry costs one hash lookup, not a pass over every key.
    let fresh
        (loaded: IReadOnlySet<string>)
        (seen: IReadOnlyDictionary<string, struct (DateTime * DateTime)>)
        (stamp: Layouts.Entry -> struct (DateTime * DateTime))
        (entries: Layouts.Entry list)
        : Layouts.Entry[] =
        entries
        |> List.filter (fun e ->
            not (loaded.Contains e.Keystore)
            && (match seen.TryGetValue e.Keystore with
                | true, t -> t <> stamp e
                | _ -> true))
        |> Array.ofList

/// The running module: keys, their files, imports and deletes, and the directory check.
type private Running(core: CoreServices, settings: Settings, keys: LocalKeys) =
    let gate = new SemaphoreSlim(1, 1)
    /// One batch of decrypts at a time, a keymanager import or the directory check, so memory
    /// stays at decrypt_parallelism derivations. An import decrypts outside `gate`: scrypt takes
    /// seconds per keystore, and list and delete go on meanwhile. Taken before `gate`.
    let importGate = new SemaphoreSlim(1, 1)
    let info = Dictionary<PubKey, KeyInfo>()
    /// The files of the keys in `info`, kept with it, for the directory check.
    let loadedFiles = HashSet<string>()
    /// Keystore files seen, with the write times of keystore and password file at the last
    /// attempt. A file that failed is tried again when either changes.
    let seen = Dictionary<string, struct (DateTime * DateTime)>()
    /// Keystore files whose keystore or password could not be read at the last check, with the
    /// error, so the warning shows once per change.
    let unreadable = Dictionary<string, string>()
    /// Keystore files skipped because another file already held their key, with that key. When
    /// the key goes because its file went away, these files lose their stamp and load again.
    let duplicates = Dictionary<string, PubKey>()
    /// Halted keys whose keystore is gone. They stay loaded and halted until restart; the set
    /// keeps the warning to one line per key.
    let haltedGone = HashSet<PubKey>()
    /// Keystore files the directory check left out because modules.tee.ha_peer is on, so the
    /// error shows once per file.
    let haPeerSkipped = HashSet<string>()
    let log = core.Log

    let sources () = settings.Sources @ [ ManagedStore.source core.DataDir ]
    let managedPath = (ManagedStore.source core.DataDir).Path

    /// The last error of each source that failed to read, so the warning shows once per change.
    let failing = Dictionary<string, string>()

    /// The entries of every source, and the paths of the sources that could not be read.
    let entriesNow () =
        let failed = ResizeArray<string>()

        let entries =
            [
                for src in sources () do
                    // The managed store exists only after the first import. A configured dir that
                    // is gone is a source that fails to read, whatever its layout.
                    let missingLodestar =
                        src.Layout = ValueSome Layouts.Layout.Lodestar && not (Directory.Exists src.Path)

                    if missingLodestar && src.Path = managedPath then
                        ()
                    else
                        let read =
                            if missingLodestar then
                                Error $"keystore dir {src.Path} does not exist"
                            else
                                KeystoreFiles.entries src

                        match read with
                        | Ok(list, _) ->
                            if failing.Remove src.Path then
                                log.Info $"local: {src.Path} reads again"

                            yield! list
                        | Error e ->
                            failed.Add src.Path

                            match failing.TryGetValue src.Path with
                            | true, last when last = e -> ()
                            | _ ->
                                failing[src.Path] <- e
                                log.Warn $"local: {e}; its keys stay loaded until it reads again"
            ]

        entries, List.ofSeq failed

    /// Whether a keystore file is in one of the source paths.
    let inAny (paths: string list) (file: string) =
        not paths.IsEmpty
        && (let f = Path.GetFullPath file

            paths
            |> List.exists (fun p ->
                let p = Path.TrimEndingDirectorySeparator(Path.GetFullPath p)
                f = p || f.StartsWith(p + string Path.DirectorySeparatorChar)))

    let writeTime (f: string) = if File.Exists f then File.GetLastWriteTimeUtc f else DateTime.MinValue

    let stamp (e: Layouts.Entry) =
        struct (writeTime e.Keystore,
                match e.Password with
                | Layouts.Password.File p -> writeTime p
                | Layouts.Password.Inline _ -> DateTime.MinValue)

    let stampOf (file: string) = struct (writeTime file, DateTime.MinValue)

    let addLoaded (k: LoadedKey) =
        let managed = ManagedStore.isManaged core.DataDir k.File

        if keys.Add(k.Key, k.Secret) then
            info[k.Key] <-
                {
                    File = k.File
                    DerivationPath = k.DerivationPath
                    Managed = managed
                }

            loadedFiles.Add k.File |> ignore

            if not (core.Registry.Revive(k.Key, keys.Backend)) then
                if core.Registry.IsRefused k.Key then
                    log.Warn
                        $"key {k.Key.Short} is refused until restart, see the earlier error; the local copy is not used"
                else
                    log.Warn $"key {k.Key.Short} is offered by another backend; the local copy is not used"

            true
        else
            log.Warn $"{k.File}: key {k.Key.Short} is already loaded; skipped"
            false

    /// Adds the keys of a directory check and logs its errors. Returns the number added, and the
    /// exception that stopped it, if any.
    let addAll (results: Result<LoadedKey, string>[]) : struct (int * exn | null) =
        let mutable added = 0
        let mutable next = 0

        try
            while next < results.Length do
                let r = results[next]
                next <- next + 1

                match r with
                | Ok k ->
                    if addLoaded k then
                        added <- added + 1
                        log.Info $"local: key {k.Key.Short} added from {k.File}"
                    else
                        duplicates[k.File] <- k.Key
                | Error e -> log.Warn $"local: {e}"

            struct (added, null)
        with e ->
            // The key that failed may be half added: its stamp goes, so the next check tries its
            // file again unless the key is loaded from it. The keys after it have no owner: they
            // are disposed, and their stamps go so the next check decrypts them again.
            for i in next - 1 .. results.Length - 1 do
                match results[i] with
                | Ok k ->
                    seen.Remove k.File |> ignore

                    if i >= next then
                        (k.Secret :> IDisposable).Dispose()
                | Error _ -> ()

            struct (added, e)

    /// The backend the registry routes a key to. A key another backend offered first keeps that
    /// route, and the local copy only sits in `keys` (addLoaded).
    let routedTo (pk: PubKey) =
        match core.Registry.TryGet pk with
        | ValueSome k -> ValueSome k.Backend.Name
        | ValueNone -> ValueNone

    let owns (pk: PubKey) = routedTo pk = ValueSome name

    /// Another backend holds the key and has not retired it.
    let heldElsewhere (pk: PubKey) =
        match core.Registry.TryGet pk with
        | ValueSome r -> r.State <> KeyState.Removed && r.Backend.Name <> name
        | ValueNone -> false

    /// Drops the local copy of a key.
    let forget (pk: PubKey) =
        keys.Remove pk |> ignore

        match info.TryGetValue pk with
        | true, i ->
            loadedFiles.Remove i.File |> ignore
            info.Remove pk |> ignore
        | _ -> ()

    /// Stops a key: draining, wait for signatures in flight, then removed. A key routed to another
    /// backend keeps its route; only the local copy goes. Returns false for a halted key, which
    /// stays loaded and halted until restart.
    let retire (pk: PubKey) (ct: CancellationToken) : Task<bool> =
        task {
            if owns pk then
                return! KeyRetirement.drain core.Registry core.Pipeline log pk (fun () -> forget pk) ct
            else
                forget pk
                return true
        }

    member _.Keys = keys

    /// Loads the keys at start. Returns the number loaded.
    member _.Load(loaded: LoadedKey list) =
        for k in loaded do
            seen[k.File] <- stampOf k.File
            addLoaded k |> ignore

        info.Count

    /// One pass of the directory check: new keystores are decrypted and added, keystores whose
    /// file is gone are retired.
    member _.Rescan(ct: CancellationToken) : Task<int * int> =
        task {
            do! importGate.WaitAsync ct

            try
                do! gate.WaitAsync ct

                try
                    let now, failed = entriesNow ()
                    let files = now |> List.map (fun e -> e.Keystore) |> Set.ofList
                    let fresh = Rescan.fresh loadedFiles seen stamp now
                    // modules.tee.ha_peer: a local key would sign on both VCs of the pair, each
                    // with its own slashing DB. A keystore that shows up while the VC runs stays
                    // unloaded; the next start refuses it.
                    let fresh =
                        if core.HaPeer then
                            for e in fresh do
                                if haPeerSkipped.Add e.Keystore then
                                    log.Error
                                        $"local: {e.Keystore} is not loaded: modules.tee.ha_peer is on, so every key must sign through the tee module; remove the file"

                            [||]
                        else
                            fresh
                    // A file that cannot be read is not stamped, so the next check tries it again:
                    // a fixed permission does not change the write time, and a failed read costs
                    // no scrypt. Its warning shows once per error.
                    let readable =
                        [|
                            for e in fresh do
                                let t = stamp e

                                match KeystoreFiles.read e with
                                | Ok(password, json) ->
                                    seen[e.Keystore] <- t
                                    unreadable.Remove e.Keystore |> ignore
                                    yield e, password, json
                                | Error err ->
                                    match unreadable.TryGetValue e.Keystore with
                                    | true, last when last = err -> ()
                                    | _ ->
                                        unreadable[e.Keystore] <- err
                                        log.Warn $"local: {err}; tried again at each check"
                        |]

                    let results =
                        KeystoreFiles.decryptAll settings.DecryptParallelism readable (fun (e, password, json) ->
                            KeystoreFiles.decryptRead e password json)

                    let struct (added, addError) = addAll results

                    match addError with
                    | null -> ()
                    | e ->
                        // The keys added before the failure still go to the duties.
                        if added > 0 then
                            do! core.RefreshKeys ct

                        Runtime.ExceptionServices.ExceptionDispatchInfo.Throw e
                    // A source that fails to read (a dir unmounted, a permission change) keeps its keys.
                    let missing =
                        [
                            for KeyValue(pk, i) in info do
                                if not (files.Contains i.File) && not (inAny failed i.File) then
                                    pk
                        ]

                    let gone = ResizeArray<PubKey>()

                    for pk in missing do
                        if not (haltedGone.Contains pk) then
                            log.Info $"local: keystore of {pk.Short} is gone; removing the key"
                            let! retired = retire pk ct

                            if retired then
                                gone.Add pk
                            else
                                haltedGone.Add pk |> ignore

                                log.Warn
                                    $"local: keystore of {pk.Short} is gone, but the key is halted; it stays loaded and halted until restart"

                    let gone = List.ofSeq gone
                    // A file skipped as a duplicate of a key now gone loads at the next check.
                    let goneKeys = HashSet<PubKey>(gone)

                    for KeyValue(f, pk) in List.ofSeq duplicates do
                        if goneKeys.Contains pk then
                            duplicates.Remove f |> ignore
                            seen.Remove f |> ignore
                        elif not (files.Contains f) && not (inAny failed f) then
                            duplicates.Remove f |> ignore

                    for f in List.ofSeq seen.Keys do
                        if not (files.Contains f) && not (inAny failed f) then
                            seen.Remove f |> ignore

                    for f in List.ofSeq unreadable.Keys do
                        if not (files.Contains f) then
                            unreadable.Remove f |> ignore

                    if added > 0 then
                        do! core.RefreshKeys ct

                    return added, gone.Length
                finally
                    gate.Release() |> ignore
            finally
                importGate.Release() |> ignore
        }

    member _.Store: KeystoreStore =
        {
            List =
                fun () ->
                    gate.Wait()

                    try
                        [
                            for KeyValue(pk, i) in info ->
                                {
                                    Key = pk
                                    DerivationPath = i.DerivationPath
                                    ReadOnly = not i.Managed
                                }
                        ]
                    finally
                        gate.Release() |> ignore
            Import =
                fun items ct ->
                    task {
                        do! importGate.WaitAsync ct

                        try
                            let parsed =
                                items
                                |> List.map (fun (json, password) ->
                                    match Keystore.parse json with
                                    | Error e -> Error $"keystore: {e}"
                                    | Ok ks -> Ok(json, password, ks))
                                |> Array.ofList

                            let decrypted =
                                KeystoreFiles.decryptAll settings.DecryptParallelism parsed (fun p ->
                                    match p with
                                    | Error e -> Error e
                                    | Ok(_, password, ks) ->
                                        match Keystore.decryptCancellable ks password ct with
                                        | Error e -> Error e
                                        | Ok secret ->
                                            let pk = PubKey.Of(Bls.publicKey (ReadOnlySpan secret))
                                            let sk = SecretKey.Copy(ReadOnlySpan secret)
                                            Security.Cryptography.CryptographicOperations.ZeroMemory(Span secret)

                                            Ok
                                                {
                                                    Key = pk
                                                    Secret = sk
                                                    File = ""
                                                    DerivationPath = ks.Path
                                                })
                            // Waited for without the token: a cancel here would leave the decrypted
                            // keys with no owner to dispose them.
                            do! gate.WaitAsync CancellationToken.None

                            try
                                let statuses =
                                    [
                                        for i in 0 .. decrypted.Length - 1 do
                                            match decrypted[i], parsed[i] with
                                            | Ok k, Ok(json, password, _) ->
                                                if keys.Contains k.Key || heldElsewhere k.Key then
                                                    (k.Secret :> IDisposable).Dispose()
                                                    ImportStatus.Duplicate
                                                else
                                                    try
                                                        ManagedStore.save core.DataDir k.Key json password
                                                        let file = ManagedStore.keystoreFile core.DataDir k.Key
                                                        seen[file] <- stampOf file

                                                        if not (addLoaded { k with File = file }) then
                                                            ImportStatus.Duplicate
                                                        elif owns k.Key then
                                                            log.Info $"local: key {k.Key.Short} imported"
                                                            ImportStatus.Imported
                                                        else
                                                            // Another backend took the key since the check above.
                                                            forget k.Key
                                                            ManagedStore.delete core.DataDir k.Key
                                                            seen.Remove file |> ignore
                                                            ImportStatus.Duplicate
                                                    with e ->
                                                        (k.Secret :> IDisposable).Dispose()
                                                        ImportStatus.Error $"saving the keystore failed: {e.Message}"
                                            | Error e, _
                                            | _, Error e -> ImportStatus.Error e
                                    ]

                                return statuses
                            finally
                                gate.Release() |> ignore
                        finally
                            importGate.Release() |> ignore
                    }
            Delete =
                fun pks ct ->
                    task {
                        do! gate.WaitAsync ct

                        try
                            let out = ResizeArray<DeleteStatus>()

                            for pk in pks do
                                match info.TryGetValue pk with
                                | true, i when not i.Managed ->
                                    out.Add(
                                        DeleteStatus.Error
                                            $"read-only: {i.File} is a configured keystore source; remove it from the config"
                                    )
                                | true, _ when heldElsewhere pk ->
                                    let other = defaultValueArg (routedTo pk) "another backend"

                                    out.Add(
                                        DeleteStatus.Error
                                            $"the key signs through {other}, not this keystore; remove it there"
                                    )
                                | true, _ ->
                                    let! retired = retire pk ct

                                    if retired then
                                        ManagedStore.delete core.DataDir pk
                                        seen.Remove(ManagedStore.keystoreFile core.DataDir pk) |> ignore
                                        out.Add DeleteStatus.Deleted
                                    else
                                        out.Add(
                                            DeleteStatus.Error
                                                "the key is halted; it stays until restart, see the VC log for why"
                                        )
                                | _ -> out.Add DeleteStatus.NotFound

                            return List.ofSeq out
                        finally
                            gate.Release() |> ignore
                    }
        }

let create () : Module =
    let settings =
        ref
            {
                Sources = []
                DecryptParallelism = defaultParallelism
                ReloadInterval = TimeSpan.FromSeconds 12.0
            }

    {
        Name = name
        Configure =
            fun section ->
                match parseSettings section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun log ->
                match KeystoreFiles.load settings.Value.Sources settings.Value.DecryptParallelism log with
                | Error e -> Error e
                | Ok keys ->
                    for k in keys do
                        (k.Secret :> IDisposable).Dispose()

                    Ok $"{keys.Length} keystores decrypted"
        Start =
            fun core ct ->
                task {
                    let s = settings.Value

                    try
                        ManagedStore.tighten core.DataDir
                    with e ->
                        core.Log.Warn
                            $"local: cannot set mode 0700 on the keystores and secrets dirs in {core.DataDir}: {e.Message}"

                    let managed = ManagedStore.source core.DataDir
                    let sources = if Directory.Exists managed.Path then s.Sources @ [ managed ] else s.Sources
                    let sw = Diagnostics.Stopwatch.StartNew()

                    match KeystoreFiles.load sources s.DecryptParallelism core.Log with
                    | Error errors -> return Error(String.concat "; " errors)
                    | Ok loaded ->
                        let keys = LocalKeys name
                        let running = Running(core, s, keys)
                        let n = running.Load loaded

                        core.Log.Info
                            $"local backend: {n} keys, decrypted in {sw.Elapsed.TotalSeconds:F2} s ({s.DecryptParallelism} at a time)"

                        core.SetKeystores running.Store
                        let stopper = new CancellationTokenSource()
                        let stopToken = stopper.Token

                        let watcher =
                            if s.ReloadInterval > TimeSpan.Zero then
                                task {
                                    use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stopToken)

                                    try
                                        while not linked.IsCancellationRequested do
                                            do! Task.Delay(s.ReloadInterval, core.Clock.Time, linked.Token)

                                            try
                                                let! _ = running.Rescan linked.Token
                                                ()
                                            with
                                            | :? OperationCanceledException -> ()
                                            | e -> core.Log.Warn $"local: directory check failed: {e.Message}"
                                    with :? OperationCanceledException ->
                                        ()
                                }
                                :> Task
                            else
                                Task.CompletedTask

                        return
                            Ok
                                {
                                    Stop =
                                        fun () ->
                                            task {
                                                stopper.Cancel()
                                                do! watcher
                                                stopper.Dispose()
                                                do! keys.Backend.Dispose()
                                            }
                                            :> Task
                                }
                }
    }
