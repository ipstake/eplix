/// The graffiti file: one text per line, for every key (`default`) or for one key, with
/// templates, and several lines for one name as a rotation.
///
///   # comment
///   default: Eplix {{SLOT}}
///   default: second line of the rotation
///   0x<public key>: text for this key
///
/// A Lighthouse --graffiti-file (one default line, one line per key) reads as it is. Templates:
/// {{SLOT}}, {{EPOCH}}, {{VALIDATORINDEX}}; any other {{...}} fails the parse.
module Eplix.Graffiti.GraffitiFile

open System
open System.Text
open Eplix

/// One piece of a line.
[<RequireQualifiedAccess>]
type Segment =
    | Text of string
    | Slot
    | Epoch
    | ValidatorIndex

/// One line's text, parsed.
type Template =
    {
        Segments: Segment list
        /// The line as written, for messages.
        Source: string
    }

/// How a line is picked when a name has several.
[<RequireQualifiedAccess>]
type Rotation =
    /// Line (slot mod count): the same answer for a slot after a restart, no state.
    | Slot
    /// A random line per proposal.
    | Random

type GraffitiFile =
    {
        Defaults: Template[]
        Keys: Map<PubKey, Template[]>
    }

    static member Empty = { Defaults = [||]; Keys = Map.empty }

/// Parses one line's text into segments. The text outside templates must fit 32 bytes.
let parseTemplate (text: string) : Result<Template, string> =
    let segments = ResizeArray<Segment>()
    let literal = StringBuilder()

    let flush () =
        if literal.Length > 0 then
            segments.Add(Segment.Text(literal.ToString()))
            literal.Clear() |> ignore

    let mutable i = 0
    let mutable error = ValueNone

    while error.IsNone && i < text.Length do
        if i + 1 < text.Length && text[i] = '{' && text[i + 1] = '{' then
            match text.IndexOf("}}", i + 2, StringComparison.Ordinal) with
            | -1 -> error <- ValueSome $"'{{{{' without '}}}}' in '{text}'"
            | close ->
                let name = text.Substring(i + 2, close - i - 2)

                let seg =
                    match name with
                    | "SLOT" -> ValueSome Segment.Slot
                    | "EPOCH" -> ValueSome Segment.Epoch
                    | "VALIDATORINDEX" -> ValueSome Segment.ValidatorIndex
                    | _ -> ValueNone

                match seg with
                | ValueSome s ->
                    flush ()
                    segments.Add s
                    i <- close + 2
                | ValueNone ->
                    error <-
                        ValueSome
                            $"unknown template {{{{{name}}}}} in '{text}' (known: {{{{SLOT}}}}, {{{{EPOCH}}}}, {{{{VALIDATORINDEX}}}})"
        else
            literal.Append text[i] |> ignore
            i <- i + 1

    flush ()

    match error with
    | ValueSome e -> Error e
    | ValueNone ->
        let fixedBytes =
            segments
            |> Seq.sumBy (fun s ->
                match s with
                | Segment.Text t -> Encoding.UTF8.GetByteCount t
                | _ -> 0)

        if fixedBytes > Graffiti.MaxBytes then
            Error $"'{text}' is longer than 32 bytes of UTF-8 without its templates"
        else
            Ok
                {
                    Segments = List.ofSeq segments
                    Source = text
                }

/// The text of a line for a proposal, cut to 32 bytes at a character boundary.
let render (ctx: GraffitiContext) (t: Template) : string =
    let sb = StringBuilder()

    for s in t.Segments do
        match s with
        | Segment.Text x -> sb.Append x |> ignore
        | Segment.Slot -> sb.Append ctx.Slot |> ignore
        | Segment.Epoch -> sb.Append ctx.Epoch |> ignore
        | Segment.ValidatorIndex -> sb.Append ctx.Index |> ignore

    Graffiti.fit Graffiti.MaxBytes (sb.ToString())

/// Parses the file. Every error is listed with its line number.
let parse (text: string) : Result<GraffitiFile, string list> =
    let errors = ResizeArray<string>()
    let defaults = ResizeArray<Template>()
    let keys = Collections.Generic.Dictionary<PubKey, ResizeArray<Template>>()
    let lines = text.Split('\n')

    for n in 0 .. lines.Length - 1 do
        let line = lines[n].TrimEnd('\r')
        let t = line.Trim()

        if t.Length > 0 && not (t.StartsWith '#') then
            match line.IndexOf ':' with
            | c when c > 0 ->
                let name = line.Substring(0, c).Trim()
                let value = line.Substring(c + 1).Trim()

                match parseTemplate value with
                | Error e -> errors.Add $"line {n + 1}: {e}"
                | Ok tpl ->
                    if name = "default" then
                        defaults.Add tpl
                    else
                        match
                            (if name.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
                                 PubKey.TryParse name
                             else
                                 ValueNone)
                        with
                        | ValueSome k ->
                            match keys.TryGetValue k with
                            | true, l -> l.Add tpl
                            | _ -> keys[k] <- ResizeArray [ tpl ]
                        | ValueNone ->
                            errors.Add $"line {n + 1}: '{name}' is not default or a 0x-hex public key of 48 bytes"
            | _ -> errors.Add $"line {n + 1}: not 'default: text' or '0x<public key>: text'"

    if errors.Count > 0 then
        Error(List.ofSeq errors)
    else
        Ok
            {
                Defaults = defaults.ToArray()
                Keys = keys |> Seq.map (fun (KeyValue(k, l)) -> k, l.ToArray()) |> Map.ofSeq
            }

/// The line for a proposal: the key's lines if it has any, else the default lines. ValueNone
/// when neither has one, so the next layer down decides.
let pick (rotation: Rotation) (file: GraffitiFile) (ctx: GraffitiContext) : string voption =
    let lines =
        match file.Keys.TryFind ctx.Key with
        | Some l when l.Length > 0 -> l
        | _ -> file.Defaults

    if lines.Length = 0 then
        ValueNone
    else
        let i =
            match rotation with
            | Rotation.Slot -> int (ctx.Slot % uint64 lines.Length)
            | Rotation.Random -> Random.Shared.Next lines.Length

        ValueSome(render ctx lines[i])

let summary (f: GraffitiFile) = $"{f.Keys.Count} keys, {f.Defaults.Length} default lines"
