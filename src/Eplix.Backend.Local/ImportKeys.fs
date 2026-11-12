/// `eplix import`: copies keystores from another client's directory into the data dir after
/// decrypting each one, so the VC loads them at the next start (or the next directory check).
module Eplix.Backend.Local.ImportKeys

open System
open System.IO
open Eplix

type Report =
    {
        Layout: Layouts.Layout
        Imported: PubKey list
        Duplicates: PubKey list
        /// Keys already in the data dir that the `choose` step of runWith returned. Not copied again.
        Present: PubKey list
        /// Keys the `choose` step of runWith left out.
        Skipped: PubKey list
        /// Keys `choose` returned whose copy failed after it ran.
        CopyFailed: PubKey list
        Errors: string list
        Notes: string list
    }

/// Decrypts every keystore of `src` and reads the password of each key new to the data dir. Then
/// calls `choose` with those keys and with the keys already present, and copies only the new keys
/// it returns. `choose` runs before any file is written; its error stops the import with nothing
/// copied. A key whose password cannot be read never reaches `choose`.
let runWith
    (dataDir: string)
    (src: KeystoreSource)
    (parallelism: int)
    (choose: PubKey list -> PubKey list -> Result<PubKey list, string>)
    : Result<Report, string> =
    let layout =
        match src.Layout with
        | ValueSome l -> Ok l
        | ValueNone -> Layouts.detect src.Path

    match layout with
    | Error e -> Error e
    | Ok layout ->
        match Layouts.entries layout src.Path src.PasswordFile with
        | Error e -> Error e
        | Ok(entries, notes) ->
            let arr = Array.ofList entries
            let results = KeystoreFiles.decryptAll parallelism arr KeystoreFiles.decryptOne
            let fresh = ResizeArray<int * PubKey>()
            let dups = ResizeArray<PubKey>()
            let errors = ResizeArray<string>()

            for i in 0 .. arr.Length - 1 do
                match results[i] with
                | Error e -> errors.Add e
                | Ok k ->
                    (k.Secret :> IDisposable).Dispose()

                    if
                        File.Exists(LocalModule.ManagedStore.keystoreFile dataDir k.Key)
                        || fresh.Exists(fun (_, x) -> x = k.Key)
                    then
                        dups.Add k.Key
                    else
                        fresh.Add((i, k.Key))

            let ready = ResizeArray<PubKey * string * string>()

            for i, key in fresh do
                match Layouts.readPassword arr[i].Password with
                | Error e -> errors.Add e
                | Ok password ->
                    try
                        ready.Add((key, File.ReadAllText arr[i].Keystore, password))
                    with e ->
                        errors.Add $"{arr[i].Keystore}: {e.Message}"

            let present =
                dups |> Seq.distinct |> Seq.filter (fun k -> not (fresh.Exists(fun (_, x) -> x = k))) |> List.ofSeq

            match choose [ for k, _, _ in ready -> k ] present with
            | Error e -> Error e
            | Ok chosen ->
                let chosen = Set.ofList chosen
                let imported = ResizeArray<PubKey>()
                let skipped = ResizeArray<PubKey>()
                let copyFailed = ResizeArray<PubKey>()

                for key, json, password in ready do
                    if not (chosen.Contains key) then
                        skipped.Add key
                    else
                        try
                            LocalModule.ManagedStore.save dataDir key json password
                            imported.Add key
                        with e ->
                            copyFailed.Add key
                            errors.Add $"key {key.Short}: copy failed: {e.Message}"

                Ok
                    {
                        Layout = layout
                        Imported = List.ofSeq imported
                        Duplicates = List.ofSeq dups
                        Present = present |> List.filter chosen.Contains
                        Skipped = List.ofSeq skipped
                        CopyFailed = List.ofSeq copyFailed
                        Errors = List.ofSeq errors
                        Notes = notes
                    }

let run (dataDir: string) (src: KeystoreSource) (parallelism: int) : Result<Report, string> =
    runWith dataDir src parallelism (fun keys _ -> Ok keys)
