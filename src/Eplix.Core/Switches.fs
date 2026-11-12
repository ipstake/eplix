/// Emergency switches: stop all signing, or pause single duty kinds. Set in
/// the config, and while running through `<data_dir>/switches.json` (the `eplix switch` command
/// writes it), which the VC reads once a second off the duty path. The pipeline checks the
/// switches with one volatile read per burst.
namespace Eplix

open System
open System.IO
open System.Text.Json
open Eplix.Json

/// What the operator switched off.
type Switches =
    {
        /// Every duty kind except voluntary exits stops.
        StopSigning: bool
        /// These duty kinds stop.
        Paused: Set<DutyKind>
    }

module Switches =
    let none =
        {
            StopSigning = false
            Paused = Set.empty
        }

    let allKinds =
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

    /// The bit of a duty kind in a switch mask.
    let bit (kind: DutyKind) =
        match kind with
        | DutyKind.Attestation -> 1 <<< 0
        | DutyKind.Block -> 1 <<< 1
        | DutyKind.RandaoReveal -> 1 <<< 2
        | DutyKind.AggregationSlot -> 1 <<< 3
        | DutyKind.AggregateAndProof -> 1 <<< 4
        | DutyKind.SyncCommitteeMessage -> 1 <<< 5
        | DutyKind.SyncSelectionProof -> 1 <<< 6
        | DutyKind.ContributionAndProof -> 1 <<< 7
        | DutyKind.VoluntaryExit -> 1 <<< 8
        | DutyKind.PayloadAttestation -> 1 <<< 9
        | DutyKind.PayloadEnvelope -> 1 <<< 10
        | DutyKind.ProposerPreferences -> 1 <<< 11
        | DutyKind.BuilderRequestAuth -> 1 <<< 12
        | DutyKind.ValidatorRegistration -> 1 <<< 13

    /// The kinds this switch setting stops, as a mask of `bit`.
    let mask (s: Switches) =
        allKinds
        |> List.filter (fun k -> (s.StopSigning && k <> DutyKind.VoluntaryExit) || s.Paused.Contains k)
        |> List.fold (fun m k -> m ||| bit k) 0

    let stops (s: Switches) (kind: DutyKind) = mask s &&& bit kind <> 0

    /// A duty kind by its metric label (`attestation`, `block`, ...).
    let parseKind (name: string) : Result<DutyKind, string> =
        match allKinds |> List.tryFind (fun k -> Metrics.dutyLabel k = name) with
        | Some k -> Ok k
        | None ->
            let names = String.Join(", ", allKinds |> List.map Metrics.dutyLabel)
            Error $"'{name}' is not a duty kind ({names})"

    /// The config and the file together: a switch is on when either source turns it on.
    let union (a: Switches) (b: Switches) =
        {
            StopSigning = a.StopSigning || b.StopSigning
            Paused = Set.union a.Paused b.Paused
        }

    let describe (s: Switches) =
        let paused = s.Paused |> Set.toList |> List.map Metrics.dutyLabel

        match s.StopSigning, paused with
        | false, [] -> "every duty signs"
        | true, [] -> "signing stopped (exits still sign)"
        | false, ps -> $"""paused: {String.Join(", ", ps)}"""
        | true, ps -> $"""signing stopped (exits still sign); paused: {String.Join(", ", ps)}"""

    /// Reads `stop_signing` (bool) and `paused_duties` (a list of duty kinds) from an object.
    /// Throws JsonDecodeError on a bad value; the caller checks for unknown fields.
    let read (e: JsonElement) : Switches =
        let stop =
            match tryProp e "stop_signing" with
            | ValueSome v when v.ValueKind = JsonValueKind.True -> true
            | ValueSome v when v.ValueKind = JsonValueKind.False -> false
            | ValueSome _ -> fail "stop_signing must be true or false"
            | ValueNone -> false

        let paused =
            match tryProp e "paused_duties" with
            | ValueSome v ->
                let names =
                    match v.ValueKind with
                    // A comma-separated string, as flags and environment variables give it.
                    | JsonValueKind.String ->
                        (str v).Split(',', StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
                    | _ -> array v |> Array.map str

                names
                |> Array.map (fun x ->
                    match parseKind x with
                    | Ok k -> k
                    | Error err -> fail $"paused_duties: {err}")
                |> Set.ofArray
            | ValueNone -> Set.empty

        { StopSigning = stop; Paused = paused }

    /// The switch file's name in the data dir.
    [<Literal>]
    let FileName = "switches.json"

    let parseFile (bytes: byte[]) : Result<Switches, string> =
        // JsonDocument throws InvalidOperationException on invalid UTF-8 inside a string.
        if not (Text.Unicode.Utf8.IsValid(ReadOnlySpan bytes)) then
            Error $"{FileName} is not valid UTF-8"
        else
            try
                use doc =
                    JsonDocument.Parse(
                        ReadOnlyMemory bytes,
                        JsonDocumentOptions(CommentHandling = JsonCommentHandling.Skip)
                    )

                let root = doc.RootElement

                if root.ValueKind <> JsonValueKind.Object then
                    Error $"{FileName} must be a JSON object"
                else
                    match checkFields root FileName [ "stop_signing"; "paused_duties" ] with
                    | e :: _ -> Error e
                    | [] -> Ok(read root)
            with
            | :? JsonDecodeError as e -> Error $"{FileName}: {e.Message}"
            | :? JsonException as e -> Error $"{FileName} is not valid JSON: {e.Message}"

    let toJson (s: Switches) : byte[] =
        toBytes (fun w ->
            w.WriteStartObject()
            w.WriteBoolean("stop_signing", s.StopSigning)
            w.WriteStartArray "paused_duties"

            for k in s.Paused |> Set.toList |> List.map Metrics.dutyLabel |> List.sort do
                w.WriteStringValue k

            w.WriteEndArray()
            w.WriteEndObject())

/// The switches in force for one pipeline: the config's, joined with the switch file's. `Mask`
/// is the one volatile read the pipeline makes per burst. A change logs one line.
[<Sealed>]
type SwitchBoard(log: Log) =
    [<VolatileField>]
    let mutable mask = 0

    let mutable fromConfig = Switches.none
    let mutable fromFile = Switches.none
    let gate = obj ()

    let apply () =
        let s = Switches.union fromConfig fromFile
        let m = Switches.mask s

        if m <> mask then
            mask <- m

            if m = 0 then
                log.Warn $"emergency switches: {Switches.describe s}; signing resumed"
            else
                log.Warn $"emergency switches: {Switches.describe s}"

    /// The kinds switched off, as a mask of `Switches.bit`.
    member _.Mask = mask

    member _.Stops(kind: DutyKind) = mask &&& Switches.bit kind <> 0

    /// The switches in force.
    member _.Current = lock gate (fun () -> Switches.union fromConfig fromFile)

    member _.SetConfig(s: Switches) =
        lock gate (fun () ->
            fromConfig <- s
            apply ())

    member _.SetFile(s: Switches) =
        lock gate (fun () ->
            fromFile <- s
            apply ())

    /// Why a duty of this kind does not sign now, for its refusal.
    member this.Reason(kind: DutyKind) =
        let s = this.Current

        if s.StopSigning && kind <> DutyKind.VoluntaryExit then
            "signing stopped by the operator"
        else
            $"{Metrics.dutyLabel kind} paused by the operator"

/// Reads `<data_dir>/switches.json` once a second and applies a change to the board. No file
/// means no file switches, so deleting the file resumes what the file stopped. A file that does
/// not parse keeps the last good content and logs one error per change of the bytes; at start it
/// fails, so a stop written before the start is never lost.
[<Sealed>]
type SwitchFile(dataDir: string, board: SwitchBoard, log: Log) =
    let path = Path.Combine(dataDir, Switches.FileName)
    let mutable last: byte[] = [||]
    let mutable lastBroken: byte[] voption = ValueNone

    let read () =
        try
            if File.Exists path then ValueSome(File.ReadAllBytes path) else ValueNone
        with
        | :? IOException
        | :? UnauthorizedAccessException as e ->
            log.Error $"{path}: {e.Message}; the switches in place stay"
            ValueSome last

    member _.Path = path

    /// Reads the file at start. A broken file fails the start.
    member _.Load() : Result<unit, string> =
        match read () with
        | ValueNone -> Ok()
        | ValueSome bytes ->
            match Switches.parseFile bytes with
            | Ok s ->
                last <- bytes
                board.SetFile s
                Ok()
            | Error e -> Error $"{path}: {e}"

    /// One check: applies a changed file, keeps the last good content on a broken one.
    member _.Check() =
        match read () with
        | ValueNone ->
            if last.Length > 0 then
                last <- [||]
                lastBroken <- ValueNone
                board.SetFile Switches.none
        | ValueSome bytes when bytes.AsSpan().SequenceEqual(ReadOnlySpan last) -> ()
        | ValueSome bytes ->
            match Switches.parseFile bytes with
            | Ok s ->
                last <- bytes
                lastBroken <- ValueNone
                board.SetFile s
            | Error e ->
                let seen =
                    match lastBroken with
                    | ValueSome b -> b.AsSpan().SequenceEqual(ReadOnlySpan bytes)
                    | ValueNone -> false

                if not seen then
                    lastBroken <- ValueSome bytes
                    log.Error $"{path}: {e}; the switches in place stay"

    /// Checks once a second until cancelled.
    member this.Run(time: TimeProvider, ct: Threading.CancellationToken) : Threading.Tasks.Task =
        task {
            try
                while not ct.IsCancellationRequested do
                    do! Threading.Tasks.Task.Delay(TimeSpan.FromSeconds 1.0, time, ct)
                    this.Check()
            with :? OperationCanceledException ->
                ()
        }

    /// Writes the file atomically (temporary file, fsync, rename, fsync of the directory), for
    /// the `eplix switch` command.
    static member Write(dataDir: string, s: Switches) =
        let path = Path.Combine(dataDir, Switches.FileName)

        Slashing.FileSync.writeAtomic
            path
            (Switches.toJson s)
            (UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead)
