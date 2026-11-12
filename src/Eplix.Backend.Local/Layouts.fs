/// Keystore directory layouts of other clients, so keys migrate without renaming
/// files. Each layout lists (keystore file, where its password is). Layouts as each client
/// documents them; the tests build sample directories in each layout.
module Eplix.Backend.Local.Layouts

open System
open System.IO
open Eplix

[<RequireQualifiedAccess>]
type Password =
    /// A file holding the password (a trailing newline is not part of it).
    | File of string
    /// The password itself (Lighthouse's validator_definitions.yml may hold it inline).
    | Inline of string

type Entry =
    { Keystore: string; Password: Password }

[<RequireQualifiedAccess>]
type Layout =
    /// staking-deposit-cli and ethstaker-deposit-cli: keystore-m_12381_3600_<i>_0_0-<time>.json, one password.
    | DepositCli
    /// Teku: <name>.json with <name>.txt in the same or a separate password directory.
    | Teku
    /// Lighthouse: validators/<0xpubkey>/voting-keystore.json, secrets/<0xpubkey> or validator_definitions.yml.
    | Lighthouse
    /// Nimbus: validators/<0xpubkey>/keystore.json, secrets/<0xpubkey>.
    | Nimbus
    /// Lodestar: keystores/<0xpubkey>/voting-keystore.json, secrets/<0xpubkey>. Eplix keeps imported keys this way too.
    | Lodestar
    /// A single keystore file, or every *.json of a directory with one password file.
    | Plain

let names =
    [
        "deposit-cli", Layout.DepositCli
        "teku", Layout.Teku
        "lighthouse", Layout.Lighthouse
        "nimbus", Layout.Nimbus
        "lodestar", Layout.Lodestar
        "plain", Layout.Plain
    ]

let parse (s: string) =
    match names |> List.tryFind (fun (n, _) -> n = s) with
    | Some(_, l) -> Ok l
    | None -> Error $"""layout '{s}' is not one of auto, {String.Join(", ", names |> List.map fst)}"""

let name (l: Layout) = names |> List.find (fun (_, x) -> x = l) |> fst

let private isPubkeyDir (d: string) =
    let n = nonNull (Path.GetFileName d)
    n.StartsWith "0x" && (PubKey.TryParse n).IsSome

let private pubkeyDirs (dir: string) =
    if Directory.Exists dir then
        Directory.GetDirectories dir |> Array.filter isPubkeyDir |> Array.sort |> List.ofArray
    else
        []

/// The keystore in a Lighthouse pubkey directory: `voting-keystore.json` when Lighthouse created
/// the key, else the original file name it keeps on import (`keystore-m_...json`, Lighthouse v8.3.2).
let private lighthouseKeystore (pubkeyDir: string) =
    let voting = Path.Combine(pubkeyDir, "voting-keystore.json")

    if File.Exists voting then
        voting
    else
        match Directory.GetFiles(pubkeyDir, "*.json") |> Array.sort with
        | [| one |] -> one
        | _ -> voting

/// A directory that holds `validators/` (Lighthouse and Nimbus point at their data dir) or is it.
let private validatorsAndSecrets (dir: string) =
    if Directory.Exists(Path.Combine(dir, "validators")) then
        Path.Combine(dir, "validators"), Path.Combine(dir, "secrets")
    else
        dir, Path.Combine(nonNull (Path.GetDirectoryName(Path.GetFullPath dir)), "secrets")

/// Reads the local keystore entries of Lighthouse's validator_definitions.yml. Only the flat
/// `key: value` lines of each `- ` item are read; that is how Lighthouse writes the file.
let lighthouseDefinitions (text: string) : Map<string, string> list =
    let items = ResizeArray<Map<string, string>>()
    let mutable current: Map<string, string> option = None

    let unquote (s: string) =
        let t = s.Trim()

        if t.Length >= 2 && ((t[0] = '"' && t[t.Length - 1] = '"') || (t[0] = '\'' && t[t.Length - 1] = '\'')) then
            t.Substring(1, t.Length - 2)
        else
            t

    for raw in text.Split('\n') do
        let line = raw.TrimEnd('\r')
        let trimmed = line.TrimStart()

        if trimmed.StartsWith "- " || trimmed = "-" then
            current |> Option.iter items.Add
            current <- Some Map.empty

        let body = if trimmed.StartsWith "- " then trimmed.Substring 2 else trimmed

        match current, body.IndexOf ':' with
        | Some m, i when i > 0 && not (body.StartsWith "#") ->
            let key = body.Substring(0, i).Trim()
            let value = unquote (body.Substring(i + 1))
            current <- Some(m.Add(key, value))
        | _ -> ()

    current |> Option.iter items.Add
    List.ofSeq items

/// Lists the keystores of a directory in a layout. Skipped entries (remote keys, disabled keys)
/// come back as notes.
let entries (layout: Layout) (path: string) (passwordFile: string voption) : Result<Entry list * string list, string> =
    let need (what: string) = Error $"{path}: {what}"

    let onePassword () =
        match passwordFile with
        | ValueSome p -> Ok(Password.File p)
        | ValueNone -> Error $"{path}: this layout needs a password file"

    let secretsFor (secrets: string) (pubkeyDir: string) =
        Password.File(Path.Combine(secrets, nonNull (Path.GetFileName pubkeyDir)))

    match layout with
    | Layout.Plain when File.Exists path ->
        onePassword () |> Result.map (fun pw -> [ { Keystore = path; Password = pw } ], [])
    | Layout.Plain ->
        if not (Directory.Exists path) then
            need "not found"
        else
            let files = Directory.GetFiles(path, "*.json") |> Array.sort |> List.ofArray

            match passwordFile with
            | ValueSome p ->
                Ok(
                    files
                    |> List.map (fun f ->
                        {
                            Keystore = f
                            Password = Password.File p
                        }),
                    []
                )
            | ValueNone ->
                // No password file: each keystore needs <name>.txt next to it (as Teku keeps them).
                Ok(
                    files
                    |> List.map (fun f ->
                        {
                            Keystore = f
                            Password = Password.File(nonNull (Path.ChangeExtension(f, ".txt")))
                        }),
                    []
                )
    | Layout.DepositCli ->
        if not (Directory.Exists path) then
            need "not found"
        else
            onePassword ()
            |> Result.map (fun pw ->
                Directory.GetFiles(path, "keystore-m_*.json")
                |> Array.sort
                |> Array.map (fun f -> { Keystore = f; Password = pw })
                |> List.ofArray,
                [])
    | Layout.Teku ->
        if not (Directory.Exists path) then
            need "not found"
        else
            let passwords = defaultValueArg passwordFile path

            if File.Exists passwords then
                Error $"{path}: Teku keeps one password file per keystore; give the password directory"
            else
                Ok(
                    Directory.GetFiles(path, "*.json")
                    |> Array.sort
                    |> Array.map (fun f ->
                        {
                            Keystore = f
                            Password =
                                Password.File(
                                    Path.Combine(passwords, nonNull (Path.GetFileNameWithoutExtension f) + ".txt")
                                )
                        })
                    |> List.ofArray,
                    []
                )
    | Layout.Lighthouse ->
        let validators, secrets = validatorsAndSecrets path
        let defs = Path.Combine(validators, "validator_definitions.yml")

        if File.Exists defs then
            let notes = ResizeArray<string>()

            let list =
                [
                    for d in lighthouseDefinitions (File.ReadAllText defs) do
                        let key = defaultArg (d.TryFind "voting_public_key") "?"

                        match d.TryFind "type", d.TryFind "enabled" with
                        | Some t, _ when t <> "local_keystore" ->
                            notes.Add $"{key}: type {t} skipped (remote keys need the Web3Signer module)"
                        | _, Some "false" -> notes.Add $"{key}: disabled in Lighthouse, skipped"
                        | _ ->
                            match d.TryFind "voting_keystore_path" with
                            | None -> notes.Add $"{key}: no voting_keystore_path, skipped"
                            | Some ks ->
                                // The file holds absolute paths. A copied data dir keeps the layout
                                // under validators/<pubkey>/ and secrets/<pubkey>, so look there too.
                                let ks =
                                    if File.Exists ks then
                                        ks
                                    else
                                        Path.Combine(validators, key, nonNull (Path.GetFileName ks))

                                let password =
                                    match
                                        d.TryFind "voting_keystore_password_path", d.TryFind "voting_keystore_password"
                                    with
                                    | Some p, _ when File.Exists p -> Password.File p
                                    | Some _, _ -> Password.File(Path.Combine(secrets, key))
                                    | None, Some p -> Password.Inline p
                                    | None, None -> Password.File(Path.Combine(secrets, key))

                                { Keystore = ks; Password = password }
                ]

            Ok(list, List.ofSeq notes)
        else
            let dirs = pubkeyDirs validators

            if dirs.IsEmpty then
                need "no validators/<0xpubkey> directories and no validator_definitions.yml"
            else
                Ok(
                    dirs
                    |> List.map (fun d ->
                        {
                            Keystore = lighthouseKeystore d
                            Password = secretsFor secrets d
                        }),
                    []
                )
    | Layout.Nimbus ->
        let validators, secrets = validatorsAndSecrets path
        let dirs = pubkeyDirs validators

        if dirs.IsEmpty then
            need "no validators/<0xpubkey> directories"
        else
            let notes = ResizeArray<string>()

            let list =
                [
                    for d in dirs do
                        let ks = Path.Combine(d, "keystore.json")

                        if File.Exists ks then
                            {
                                Keystore = ks
                                Password = secretsFor secrets d
                            }
                        elif File.Exists(Path.Combine(d, "remote_keystore.json")) then
                            notes.Add
                                $"{Path.GetFileName d}: remote keystore skipped (remote keys need the Web3Signer module)"
                ]

            Ok(list, List.ofSeq notes)
    | Layout.Lodestar ->
        let keystores =
            if Directory.Exists(Path.Combine(path, "keystores")) then Path.Combine(path, "keystores") else path

        let secrets = Path.Combine(nonNull (Path.GetDirectoryName(Path.GetFullPath keystores)), "secrets")
        let dirs = pubkeyDirs keystores

        if dirs.IsEmpty then
            need "no keystores/<0xpubkey> directories"
        else
            Ok(
                dirs
                |> List.map (fun d ->
                    {
                        Keystore = Path.Combine(d, "voting-keystore.json")
                        Password = secretsFor secrets d
                    }),
                []
            )

/// Guesses the layout of a directory.
let detect (path: string) : Result<Layout, string> =
    let has (p: string) = Directory.Exists(Path.Combine(path, p)) || File.Exists(Path.Combine(path, p))
    let validators, _ = validatorsAndSecrets path
    let dirs = pubkeyDirs validators

    if File.Exists path then
        Ok Layout.Plain
    elif not (Directory.Exists path) then
        Error $"{path}: not found"
    elif File.Exists(Path.Combine(validators, "validator_definitions.yml")) then
        Ok Layout.Lighthouse
    elif
        dirs
        |> List.exists (fun d ->
            File.Exists(Path.Combine(d, "keystore.json"))
            || File.Exists(Path.Combine(d, "remote_keystore.json")))
    then
        Ok Layout.Nimbus
    elif dirs |> List.exists (fun d -> Directory.GetFiles(d, "*.json").Length > 0) then
        Ok Layout.Lighthouse
    elif has "keystores" || (pubkeyDirs path |> List.isEmpty |> not) then
        Ok Layout.Lodestar
    elif Directory.GetFiles(path, "keystore-m_*.json").Length > 0 then
        Ok Layout.DepositCli
    elif
        Directory.GetFiles(path, "*.json")
        |> Array.exists (fun f -> File.Exists(nonNull (Path.ChangeExtension(f, ".txt"))))
    then
        Ok Layout.Teku
    elif Directory.GetFiles(path, "*.json").Length > 0 then
        Ok Layout.Plain
    else
        Error $"{path}: no keystores found in any known layout"

/// Reads a password as EIP-2335 tools write it: a trailing newline is not part of it. A file that
/// cannot be read (permissions, removed after the check) is an error, not an exception.
let readPassword (p: Password) : Result<string, string> =
    match p with
    | Password.Inline s -> Ok s
    | Password.File f when File.Exists f ->
        try
            Ok(File.ReadAllText(f).TrimEnd('\r', '\n'))
        with
        | :? IOException
        | :? UnauthorizedAccessException as e -> Error $"password file {f} cannot be read: {e.Message}"
    | Password.File f -> Error $"password file {f} not found"
