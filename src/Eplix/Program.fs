/// The eplix binary: argument parsing, signals, exit codes. The work is in Eplix.Core.Runner.
module Eplix.Host.Program

open System
open System.IO
open System.Reflection
open System.Runtime.InteropServices
open System.Threading
open Eplix
open Eplix.Beacon
open Eplix.Slashing

let private version () =
    let asm = typeof<Eplix.Module>.Assembly

    match asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>() with
    | null -> "unknown"
    | a -> a.InformationalVersion

let private usage =
    """usage:
  eplix version
  eplix run [--config <file>] [settings]
  eplix check [--config <file>] [settings]    check the config and the keystores, then exit
  eplix slashing import --config <file> --file <eip3076.json>
  eplix slashing export --config <file> --file <out.json> [--pubkey <0x...>]...
  eplix import --config <file> --from <dir> [--layout <name>] [--password-file <file or dir>]
               [--slashing-protection <eip3076.json> | --no-signing-history]
                                              copy keystores from another client's directory;
                                              layouts: auto, deposit-cli, teku, lighthouse, nimbus, lodestar, plain;
                                              --no-signing-history: no history exists (a new key, or a
                                              lost setup); writes a floor record at the epoch now + 1
  eplix exit --config <file> (--pubkey <0x...>[,<0x...>]... | --all) [--epoch <n>] [--save-dir <dir>]
             [--submit true]                  sign voluntary exits; prints each, or writes <dir>/<0xpubkey>.json
                                              (mode 0600); submits only with --submit true
  eplix switch [stop | resume | pause <duty>... | resume-duty <duty>... | status] --config <file>
                                              emergency switches of a running VC (<data dir>/switches.json):
                                              stop signing (exits still sign), or pause duty kinds such as
                                              attestation, block, sync_committee_message
import --no-signing-history asks y/n/all for each key a beacon node shows as possibly having signed;
without a terminal it leaves those keys out.
slashing, import and exit take the data dir lock, so they run while the VC is stopped;
a running VC offers the same through the keymanager API. switch runs next to a running VC.
settings override config keys: --<key> <value> (--fee-recipient 0x..), --modules.<module>.<key> <value>,
--set <key>=<value>, or the environment: EPLIX_<KEY>, EPLIX_MODULES__<MODULE>__<KEY>. A flag wins over
the environment, the environment over the file. EPLIX_CONFIG names the file when --config is absent."""

/// --name value and --name=value pairs, in order; a name may repeat.
let private optionList (args: string list) : Result<(string * string) list, string> =
    let rec go acc rest =
        match rest with
        | [] -> Ok(List.rev acc)
        | (name: string) :: tail when name.StartsWith "--" && name.Contains '=' ->
            let i = name.IndexOf '='
            go ((name.Substring(2, i - 2), name.Substring(i + 1)) :: acc) tail
        | (name: string) :: value :: tail when name.StartsWith "--" -> go ((name.Substring 2, value) :: acc) tail
        | x :: _ -> Error $"unexpected argument '{x}'"

    go [] args

let private toMap (pairs: (string * string) list) : Map<string, string list> =
    pairs
    |> List.fold (fun acc (k, v) -> Map.add k (defaultArg (Map.tryFind k acc) [] @ [ v ]) acc) Map.empty

let private options (args: string list) : Result<Map<string, string list>, string> = optionList args |> Result.map toMap

let private one (opts: Map<string, string list>) name =
    match Map.tryFind name opts with
    | Some [ v ] -> Ok v
    | Some _ -> Error $"--{name} given more than once"
    | None -> Error $"--{name} is required"

/// A flag given bare or as true/false (`--all`, `--no-signing-history`); main turns a bare one
/// into `--name=true`.
let private boolFlag (opts: Map<string, string list>) (name: string) =
    match Map.tryFind name opts with
    | None
    | Some [ "false" ] -> Ok false
    | Some [ "true" ] -> Ok true
    | Some [ v ] -> Error $"--{name} takes true or false, not '{v}'"
    | Some _ -> Error $"--{name} given more than once"

/// `--name` followed by nothing or by another flag becomes `--name=true`.
let private bare (name: string) (args: string list) =
    let flag = "--" + name

    args
    |> List.mapi (fun i a ->
        if a = flag && (i = args.Length - 1 || args[i + 1].StartsWith "--") then flag + "=true" else a)

let private fail (msg: string) =
    Console.Error.WriteLine $"error: {msg}"
    1

/// The config from the file (--config, else EPLIX_CONFIG, else none), the environment and the
/// flags. `own` names the command's own flags; every other flag is a config setting.
let private loadConfig (args: string list) (own: string list) (modules: Eplix.Module list) =
    match optionList args with
    | Error e -> Error e
    | Ok opts ->
        let file =
            match opts |> List.filter (fun (k, _) -> k = "config") with
            | [ _, f ] -> Ok(ValueSome f)
            | _ :: _ :: _ -> Error "--config given more than once"
            | [] ->
                match Environment.GetEnvironmentVariable "EPLIX_CONFIG" with
                | null
                | "" -> Ok ValueNone
                | f -> Ok(ValueSome f)

        let flags = opts |> List.filter (fun (k, _) -> k <> "config" && not (List.contains k own))

        let env =
            [
                for o in Environment.GetEnvironmentVariables() do
                    let e = o :?> Collections.DictionaryEntry

                    string e.Key,
                    (match e.Value with
                     | null -> ""
                     | v -> string v)
            ]

        let join (es: string list) = String.Join("\n  ", es)

        match file, ConfigSources.fromEnv env, ConfigSources.fromFlags flags with
        | Error e, _, _ -> Error e
        | _, Error es, _
        | _, _, Error es -> Error(join es)
        | Ok file, Ok fromEnv, Ok fromFlags ->
            match ConfigSources.load file (fromEnv @ fromFlags) (modules |> List.map (fun m -> m.Name)) with
            | Error es -> Error(join es)
            | Ok c ->
                let baseDir =
                    match file with
                    | ValueSome f -> nonNull (Path.GetDirectoryName(Path.GetFullPath f))
                    | ValueNone -> Directory.GetCurrentDirectory()

                match Runner.configure c modules baseDir with
                | Error es -> Error(join es)
                | Ok() -> Ok c

let private run (args: string list) =
    let modules = Modules.all ()

    match loadConfig args [] modules with
    | Error e -> fail e
    | Ok config ->
        let time = TimeProvider.System
        let log = Log.create time config.LogLevel config.LogFormat
        log.Info $"eplix {version ()} starting, modules: {String.Join(',', modules |> List.map (fun m -> m.Name))}"
        use cts = new CancellationTokenSource()

        let stop (ctx: PosixSignalContext) =
            ctx.Cancel <- true
            log.Info $"{ctx.Signal}: stopping"
            cts.Cancel()

        use _int = PosixSignalRegistration.Create(PosixSignal.SIGINT, Action<PosixSignalContext> stop)
        use _term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Action<PosixSignalContext> stop)
        // SIGHUP reloads TLS files and never stops the VC, with or without a reload configured.
        use _hup = SighupHub.Default.Register log
        use http = BeaconClient.createHttp ()

        let result =
            try
                (Runner.run
                    {
                        Config = config
                        Modules = modules
                        Http = http
                        Time = time
                        Log = log
                        OnSlotDone = ignore
                        OnReady = fun _ _ -> ()
                    }
                    cts.Token)
                    .GetAwaiter()
                    .GetResult()
            with :? OperationCanceledException ->
                Ok()

        match result with
        | Ok() ->
            log.Info "stopped"
            0
        | Error e ->
            log.Error e
            1

/// Offline checks: config, pinned chain config, proposer config file, keystores. Prints the keys it would use.
let private check (args: string list) =
    let modules = Modules.all ()

    match loadConfig args [] modules with
    | Error e -> fail e
    | Ok config ->
        let pinned = config.Chain.Pinned

        Console.Out.WriteLine
            $"config ok: beacon node {config.BeaconNode}, data dir {config.DataDir}, {config.Chain.Describe} ({pinned.Count} pinned chain values)"

        for line in SigningJitter.describe config.Signing do
            Console.Out.WriteLine line

        let log = Log.create TimeProvider.System config.LogLevel config.LogFormat

        let proposerOk =
            match config.ProposerConfig |> ValueOption.map ProposerConfig.load with
            | ValueNone -> true
            | ValueSome(Ok f) ->
                Console.Out.WriteLine $"proposer config: {ProposerConfig.summary f}"
                true
            | ValueSome(Error e) ->
                Console.Error.WriteLine e
                false

        let results = modules |> List.map (fun m -> m.Name, m.Check log)

        for name, r in results do
            match r with
            | Ok summary -> Console.Out.WriteLine $"module {name}: {summary}"
            | Error es -> Console.Error.WriteLine $"""module {name}: {String.Join("; ", es)}"""

        if proposerOk && results |> List.forall (fun (_, r) -> Result.isOk r) then 0 else 1

/// Imports an EIP-3076 file into the slashing DB of a data dir. A new DB takes the file's
/// genesis validators root; an existing one must match it, and so must the root the chain pins
/// (Runner.interchangeFits). Reads the file as a stream and keeps only the marks per key.
let private importInterchange (config: CoreConfig) (dataDir: DataDir) (file: string) : Result<string, string> =
    let parsed =
        (use f = File.OpenRead file
         InterchangeStream.read f)
        |> Result.bind (fun x ->
            Runner.interchangeFits config.Chain config.Chain.Pinned x.GenesisValidatorsRoot
            |> Result.map (fun () -> x))

    match parsed with
    | Error e -> Error $"{file}: {e}"
    | Ok x ->
        use mf = new FileMarkFile(dataDir.SlashingDbPath)

        match SlashingDb.Open(mf, x.GenesisValidatorsRoot) with
        | Error e -> Error e
        | Ok db ->
            match db.ImportMarks x with
            | Error e -> Error e
            | Ok r ->
                for k in x.Slashable do
                    Console.Error.WriteLine
                        $"warning: the history of {k.Hex} in {file} holds a slashable pair; imported as its highest block and attestation"

                let empty =
                    if r.NoHistory.IsEmpty then
                        ""
                    else
                        $"; {r.NoHistory.Length} keys have no signed block or attestation in the file and got no record: they never sign until eplix import --no-signing-history or allow_start_without_history gives them a floor"

                Ok $"imported {r.Entries} slashing protection entries; the DB has {db.Keys.Length} keys{empty}"

let private slashing (sub: string) (args: string list) (opts: Map<string, string list>) =
    let modules = Modules.all ()

    match one opts "file" with
    | Error e -> fail e
    | Ok file ->
        match loadConfig args [ "file"; "pubkey" ] modules with
        | Error e -> fail e
        | Ok config ->
            match DataDir.Acquire(config.DataDir, Log.create TimeProvider.System config.LogLevel config.LogFormat) with
            | Error e -> fail e
            | Ok dataDir ->
                use _ = dataDir

                match sub with
                | "import" ->
                    match importInterchange config dataDir file with
                    | Error e -> fail e
                    | Ok msg ->
                        Console.Out.WriteLine msg
                        0
                | "export" ->
                    if not (File.Exists dataDir.SlashingDbPath) then
                        fail "no slashing DB in the data dir"
                    else
                        let header = Array.zeroCreate<byte> Record.size

                        (use f = File.OpenRead dataDir.SlashingDbPath
                         f.ReadExactly(header, 0, header.Length))

                        let gvr = Root.Of(Record.payload header 32)
                        use mf = new FileMarkFile(dataDir.SlashingDbPath)

                        match SlashingDb.Open(mf, gvr) with
                        | Error e -> fail e
                        | Ok db ->
                            match Interchange.exportTo db.HasRecord db.Export (Map.tryFind "pubkey" opts) file with
                            | Error e -> fail e
                            | Ok n ->
                                Console.Out.WriteLine $"exported {n} keys to {file}"
                                0
                | other -> fail $"unknown slashing command '{other}'"

#if EPLIX_LOCAL
/// Copies keystores from another client's layout into the data dir, with their slashing history
/// (--slashing-protection) or a floor record per key (--no-signing-history).
let private importKeys (args: string list) (opts: Map<string, string list>) =
    let modules = Modules.all ()

    match one opts "from", boolFlag opts "no-signing-history" with
    | Error e, _
    | _, Error e -> fail e
    | Ok _, Ok true when Map.containsKey "slashing-protection" opts ->
        fail "give --slashing-protection or --no-signing-history, not both"
    | Ok from, Ok noHistory ->
        match
            loadConfig
                args
                [
                    "from"
                    "layout"
                    "password-file"
                    "slashing-protection"
                    "no-signing-history"
                ]
                modules
        with
        | Error e -> fail e
        | Ok config ->
            let layout =
                match Map.tryFind "layout" opts with
                | None
                | Some [ "auto" ] -> Ok ValueNone
                | Some [ l ] -> Eplix.Backend.Local.Layouts.parse l |> Result.map ValueSome
                | Some _ -> Error "--layout given more than once"

            match
                layout, DataDir.Acquire(config.DataDir, Log.create TimeProvider.System config.LogLevel config.LogFormat)
            with
            | Error e, _
            | _, Error e -> fail e
            | Ok layout, Ok dataDir ->
                use _ = dataDir

                let src: Eplix.Backend.Local.KeystoreSource =
                    {
                        Path = Path.GetFullPath from
                        PasswordFile =
                            match Map.tryFind "password-file" opts with
                            | Some [ p ] -> ValueSome(Path.GetFullPath p)
                            | _ -> ValueNone
                        Layout = layout
                    }

                let slashingResult =
                    match Map.tryFind "slashing-protection" opts with
                    | Some [ f ] -> importInterchange config dataDir f |> Result.map Some
                    | _ -> Ok None

                match slashingResult with
                | Error e -> fail $"slashing protection: {e}; no keys were imported"
                | Ok slashingMsg ->
                    use http = BeaconClient.createHttp ()
                    let owned = ResizeArray<Net.Http.HttpClient>()

                    use _owned =
                        { new IDisposable with
                            member _.Dispose() =
                                for h in owned do
                                    h.Dispose()
                        }

                    let mutable outcome = ValueNone
                    // With --no-signing-history: the floor records are written here, before any
                    // keystore is copied; a key left out gets neither. A key already in the data
                    // dir with no slashing record gets a floor too, without a new copy.
                    let choose (keys: PubKey list) (present: PubKey list) =
                        if not noHistory then
                            Ok keys
                        else
                            match
                                Runner.clientsOf
                                    config
                                    http
                                    (max config.RequestTimeout (TimeSpan.FromSeconds 30.0))
                                    owned
                            with
                            | _, Some e -> Error e
                            | clients, None ->
                                let prompt: FloorImport.Prompt =
                                    {
                                        Interactive = not Console.IsInputRedirected
                                        Ask =
                                            fun q ->
                                                Console.Out.Write q
                                                Console.Out.Flush()

                                                match Console.In.ReadLine() with
                                                | null -> ValueNone
                                                | a -> ValueSome a
                                        Say = fun s -> Console.Out.WriteLine s
                                    }

                                let run =
                                    FloorImport.run
                                        config
                                        clients
                                        dataDir
                                        TimeProvider.System
                                        prompt
                                        keys
                                        present
                                        CancellationToken.None

                                match run.GetAwaiter().GetResult() with
                                | Error e -> Error $"{e}; no keys were imported"
                                | Ok o ->
                                    outcome <- ValueSome o
                                    Ok o.Floored

                    match
                        Eplix.Backend.Local.ImportKeys.runWith
                            dataDir.Path
                            src
                            Eplix.Backend.Local.LocalModule.defaultParallelism
                            choose
                    with
                    | Error e -> fail e
                    | Ok r ->
                        Console.Out.WriteLine
                            $"layout {Eplix.Backend.Local.Layouts.name r.Layout}: {r.Imported.Length} keys imported, {r.Duplicates.Length} already present"

                        if not r.Present.IsEmpty then
                            Console.Out.WriteLine
                                $"{r.Present.Length} of the keys already present had no slashing record and got a floor record"

                        for n in r.Notes do
                            Console.Out.WriteLine $"  note: {n}"

                        for e in r.Errors do
                            Console.Error.WriteLine $"  error: {e}"

                        if noHistory && not r.CopyFailed.IsEmpty then
                            Console.Error.WriteLine
                                $"error: {r.CopyFailed.Length} keys got a floor record but no keystore copy (see above); fix the cause and run the import again"

                        let unconfirmed =
                            match outcome with
                            | ValueSome o -> o.Unconfirmed.Length
                            | ValueNone -> 0

                        match slashingMsg, outcome with
                        | Some m, _ -> Console.Out.WriteLine m
                        | None, ValueSome o ->
                            if not o.Floored.IsEmpty then
                                Console.Out.WriteLine
                                    $"{o.Floored.Length} keys have a floor record at epoch {Floor.target o.FloorEpoch}: they attest once the justified checkpoint reaches it, and propose after epoch {Floor.target o.FloorEpoch}"

                            if not o.Declined.IsEmpty then
                                Console.Out.WriteLine $"{o.Declined.Length} keys not imported (answered no)"

                            if unconfirmed > 0 then
                                Console.Error.WriteLine
                                    $"error: {unconfirmed} keys not imported: they may have signed before (see above), and there is no terminal to confirm; run the import on a terminal"
                        | None, ValueNone ->
                            if not r.Imported.IsEmpty then
                                Console.Out.WriteLine
                                    "no --slashing-protection file and no --no-signing-history: the keys have no slashing record and never sign until they get one (or are listed in allow_start_without_history)"

                        if r.Errors.IsEmpty && unconfirmed = 0 then 0 else 1
#endif

/// The keys an exit run names: --pubkey, repeated or comma-separated, or --all.
let private exitTarget (opts: Map<string, string list>) : Result<Exits.Target, string> =
    let all = boolFlag opts "all"

    let named =
        defaultArg (Map.tryFind "pubkey" opts) []
        |> List.collect (fun v ->
            v.Split(',', StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
            |> List.ofArray)

    match all with
    | Error e -> Error e
    | Ok true when not named.IsEmpty -> Error "give --pubkey or --all, not both"
    | Ok true -> Ok Exits.Target.All
    | Ok false when named.IsEmpty -> Error "--pubkey or --all is required"
    | Ok false ->
        let parsed = named |> List.map (fun k -> k, PubKey.TryParse k)

        match parsed |> List.tryFind (fun (_, pk) -> pk.IsNone) with
        | Some(k, _) -> Error $"'{k}' is not a public key"
        | None -> Ok(Exits.Target.Keys(parsed |> List.map (fun (_, pk) -> pk.Value)))

/// Signs voluntary exits for one, several or all keys the VC holds. Each signed exit goes to
/// stdout, or with --save-dir to its own file (`<0xpubkey>.json`, mode 0600); it is submitted only
/// with --submit true. Exit code 1 when any named key fails or nothing was signed.
let private exitCommand (args: string list) (opts: Map<string, string list>) =
    let modules = Modules.all ()

    match exitTarget opts with
    | Error e -> fail e
    | Ok target ->
        match loadConfig args [ "pubkey"; "all"; "epoch"; "submit"; "save-dir" ] modules with
        | Error e -> fail e
        | Ok config ->
            let submit = Map.tryFind "submit" opts = Some [ "true" ]

            let saveDir =
                match Map.tryFind "save-dir" opts with
                | Some [ d ] -> Ok(ValueSome(Path.GetFullPath d))
                | Some _ -> Error "--save-dir given more than once"
                | None -> Ok ValueNone

            let epochArg = Exits.parseEpoch (Map.tryFind "epoch" opts)

            match epochArg, saveDir with
            | Error e, _
            | _, Error e -> fail e
            | Ok epochArg, Ok saveDir ->
                let time = TimeProvider.System
                let log = Log.create time config.LogLevel config.LogFormat
                use cts = new CancellationTokenSource(TimeSpan.FromMinutes 5.0)
                use http = BeaconClient.createHttp ()

                let opts =
                    {
                        Config = config
                        Modules = modules
                        Http = http
                        Time = time
                        Log = log
                        OnSlotDone = ignore
                        OnReady = fun _ _ -> ()
                    }

                let result =
                    (Runner.runWith opts cts.Token (fun core _ ->
                        task {
                            do! core.RefreshKeys cts.Token
                            let plan = Exits.plan core.Registry target

                            let epoch =
                                defaultValueArg
                                    epochArg
                                    (core.Clock.EpochOf(defaultValueArg core.Clock.CurrentSlot 0UL))

                            let mutable failures = 0

                            for pk, p in plan do
                                match p with
                                | Exits.Plan.Fail why ->
                                    failures <- failures + 1
                                    Console.Error.WriteLine $"error: {pk.Hex}: {why}"
                                | Exits.Plan.Skip why -> Console.Error.WriteLine $"skipped: {pk.Hex}: {why}"
                                | Exits.Plan.Sign _ -> ()

                            let toSign =
                                plan
                                |> List.choose (fun (pk, p) ->
                                    match p with
                                    | Exits.Plan.Sign i -> Some(pk, i)
                                    | _ -> None)

                            let! signed =
                                Exits.signMany
                                    core.Spec
                                    core.Genesis.GenesisValidatorsRoot
                                    core.Pipeline
                                    toSign
                                    epoch
                                    (time.GetUtcNow().AddMinutes 1.0)
                                    cts.Token

                            let mutable completed = 0

                            for pk, r in signed do
                                match r with
                                | Error e ->
                                    failures <- failures + 1
                                    Console.Error.WriteLine $"error: {pk.Hex}: {e}"
                                | Ok(x, s) ->
                                    let written =
                                        match saveDir with
                                        | ValueSome dir ->
                                            try
                                                let path = Exits.save dir pk x s

                                                Console.Out.WriteLine
                                                    $"{pk.Hex}: exit of validator {x.ValidatorIndex} at epoch {x.Epoch} saved to {path}"

                                                true
                                            with e ->
                                                Console.Error.WriteLine
                                                    $"error: {pk.Hex}: writing the exit: {e.Message}"

                                                false
                                        | ValueNone ->
                                            Console.Out.WriteLine(
                                                Text.Encoding.UTF8.GetString(Encoders.signedVoluntaryExit x s)
                                            )

                                            true

                                    if not written then
                                        failures <- failures + 1
                                    elif submit then
                                        match!
                                            core.Nodes.Broadcast(
                                                (fun b -> b.SubmitVoluntaryExit(x, s, cts.Token)),
                                                NodeRole.All,
                                                BroadcastTopic.Exits
                                            )
                                        with
                                        | Ok() ->
                                            completed <- completed + 1

                                            log.Info
                                                $"exit of validator {x.ValidatorIndex} at epoch {x.Epoch} submitted"
                                        | Error e ->
                                            failures <- failures + 1
                                            Console.Error.WriteLine $"error: {pk.Hex}: submit: {e.Describe}"
                                    else
                                        completed <- completed + 1

                            if not submit && completed > 0 then
                                log.Info $"{completed} exits signed, not submitted (add --submit true to submit)"

                            if failures > 0 then
                                return Error $"{failures} of {plan.Length} keys failed; {completed} exits done"
                            elif completed = 0 then
                                return Error "no key could sign an exit"
                            else
                                return Ok()
                        }))
                        .GetAwaiter()
                        .GetResult()

                match result with
                | Ok() -> 0
                | Error e -> fail e

/// Emergency switches while the VC runs: writes `<data_dir>/switches.json`, which the VC reads
/// once a second. No data dir lock: the VC holds it.
let private switchCommand (args: string list) =
    let verb, rest =
        match args with
        | v :: rest when not (v.StartsWith "--") -> v, rest
        | _ -> "status", args

    let kinds, rest =
        match verb with
        | "pause"
        | "resume-duty" ->
            let ks = rest |> List.takeWhile (fun a -> not (a.StartsWith "--"))
            ks, rest |> List.skip ks.Length
        | _ -> [], rest

    let modules = Modules.all ()

    match loadConfig rest [] modules with
    | Error e -> fail e
    | Ok config ->
        let parsed =
            kinds
            |> List.collect (fun k -> k.Split(',', StringSplitOptions.RemoveEmptyEntries) |> List.ofArray)
            |> List.map Switches.parseKind

        match
            parsed
            |> List.tryPick (fun r ->
                match r with
                | Error e -> Some e
                | Ok _ -> None)
        with
        | Some e -> fail e
        | None ->
            let kinds =
                parsed
                |> List.choose (fun r ->
                    match r with
                    | Ok k -> Some k
                    | Error _ -> None)
                |> Set.ofList

            let path = Path.Combine(config.DataDir, Switches.FileName)
            let current = if File.Exists path then Switches.parseFile (File.ReadAllBytes path) else Ok Switches.none

            match current with
            | Error e -> fail $"{path}: {e}; fix or delete it"
            | Ok current ->
                let next =
                    match verb with
                    | "stop" -> Ok { current with StopSigning = true }
                    | "resume" -> Ok Switches.none
                    | "pause" when kinds.IsEmpty -> Error "pause needs one or more duty kinds"
                    | "pause" ->
                        Ok
                            { current with
                                Paused = Set.union current.Paused kinds
                            }
                    | "resume-duty" when kinds.IsEmpty -> Error "resume-duty needs one or more duty kinds"
                    | "resume-duty" ->
                        Ok
                            { current with
                                Paused = Set.difference current.Paused kinds
                            }
                    | "status" -> Ok current
                    | other -> Error $"unknown switch command '{other}'"

                match next with
                | Error e -> fail e
                | Ok next ->
                    if verb <> "status" then
                        // A missing data dir is made 0700; the VC's start tightens one that exists.
                        if not (Directory.Exists config.DataDir) then
                            DataDir.Prepare(config.DataDir, Log.none)

                        SwitchFile.Write(config.DataDir, next)

                    Console.Out.WriteLine $"switch file {path}: {Switches.describe next}"
                    Console.Out.WriteLine $"config: {Switches.describe config.Switches}"

                    Console.Out.WriteLine
                        $"in force once the VC reads the file (within a second): {Switches.describe (Switches.union config.Switches next)}"

                    0

[<EntryPoint>]
let main argv =
    match List.ofArray argv with
    | [ "version" ]
    | [ "--version" ] ->
        Console.Out.WriteLine $"eplix {version ()} ({RuntimeInformation.FrameworkDescription})"
        0
    | "run" :: rest -> run rest
    | "check" :: rest -> check rest
#if EPLIX_LOCAL
    | "import" :: rest ->
        let rest = bare "no-signing-history" rest

        match options rest with
        | Ok o -> importKeys rest o
        | Error e -> fail e
#endif
    | "exit" :: rest ->
        let rest = bare "all" rest

        match options rest with
        | Ok o -> exitCommand rest o
        | Error e -> fail e
    | "switch" :: rest -> switchCommand rest
    | "slashing" :: sub :: rest ->
        match options rest with
        | Ok o -> slashing sub rest o
        | Error e -> fail e
    | _ ->
        Console.Error.WriteLine usage
        2
