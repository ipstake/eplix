/// A small OpenAPI 3.1 checker for the beacon-APIs and keymanager-APIs bundles: path templates,
/// parameters, request bodies and responses against their JSON schemas. It knows the keywords
/// these two documents use: $ref (local), type, properties, required, additionalProperties,
/// items, prefixItems, allOf, anyOf, oneOf (checked as anyOf: several of these schemas overlap),
/// enum, const, pattern, minItems, maxItems, minLength, maxLength. Formats are not checked.
module Eplix.Tests.OpenApi

open System
open System.Collections.Generic
open System.Text.Json
open System.Text.RegularExpressions

type Spec(doc: JsonDocument) =
    let root = doc.RootElement
    let patterns = Dictionary<string, Regex>()

    let rec resolve (e: JsonElement) =
        match e.ValueKind with
        | JsonValueKind.Object ->
            match e.TryGetProperty "$ref" with
            | true, r ->
                let path = r.GetString()

                if not (path.StartsWith "#/") then
                    failwithf "external $ref %s" path

                let mutable x = root

                for part in path.Substring(2).Split('/') do
                    x <- x.GetProperty(part.Replace("~1", "/").Replace("~0", "~"))

                resolve x
            | _ -> e
        | _ -> e

    let regex (p: string) =
        match patterns.TryGetValue p with
        | true, r -> r
        | _ ->
            let r = Regex(p, RegexOptions.CultureInvariant)
            patterns[p] <- r
            r

    let typeOk (t: string) (v: JsonElement) =
        match t, v.ValueKind with
        | "object", JsonValueKind.Object
        | "array", JsonValueKind.Array
        | "string", JsonValueKind.String
        | "null", JsonValueKind.Null -> true
        | "boolean", (JsonValueKind.True | JsonValueKind.False) -> true
        | "number", JsonValueKind.Number -> true
        | "integer", JsonValueKind.Number ->
            let mutable i = 0L
            v.TryGetInt64(&i)
        | _ -> false

    /// Errors of `v` against `schema`, with JSON paths.
    let rec check (schema: JsonElement) (v: JsonElement) (at: string) : string list =
        let s = resolve schema

        if s.ValueKind = JsonValueKind.True then
            []
        elif s.ValueKind = JsonValueKind.False then
            [ $"{at}: no value allowed" ]
        else
            [
                match s.TryGetProperty "type" with
                | true, t when t.ValueKind = JsonValueKind.String ->
                    if not (typeOk (t.GetString()) v) then
                        yield $"{at}: expected {t.GetString()}, got {v.ValueKind}"
                | true, t when t.ValueKind = JsonValueKind.Array ->
                    if not (t.EnumerateArray() |> Seq.exists (fun x -> typeOk (x.GetString()) v)) then
                        yield $"{at}: expected one of {t.GetRawText()}, got {v.ValueKind}"
                | _ -> ()
                match s.TryGetProperty "enum" with
                | true, en when not (en.EnumerateArray() |> Seq.exists (fun x -> x.GetRawText() = v.GetRawText())) ->
                    yield $"{at}: {v.GetRawText()} not in {en.GetRawText()}"
                | _ -> ()
                match s.TryGetProperty "const" with
                | true, c when c.GetRawText() <> v.GetRawText() ->
                    yield $"{at}: {v.GetRawText()} is not {c.GetRawText()}"
                | _ -> ()
                if v.ValueKind = JsonValueKind.String then
                    let str = v.GetString()

                    match s.TryGetProperty "pattern" with
                    | true, p when not ((regex (p.GetString())).IsMatch str) ->
                        yield $"{at}: '{str}' does not match {p.GetString()}"
                    | _ -> ()

                    match s.TryGetProperty "minLength" with
                    | true, m when str.Length < m.GetInt32() -> yield $"{at}: shorter than {m.GetInt32()}"
                    | _ -> ()

                    match s.TryGetProperty "maxLength" with
                    | true, m when str.Length > m.GetInt32() -> yield $"{at}: longer than {m.GetInt32()}"
                    | _ -> ()
                if v.ValueKind = JsonValueKind.Object then
                    let props =
                        match s.TryGetProperty "properties" with
                        | true, p -> p.EnumerateObject() |> Seq.map (fun x -> x.Name, x.Value) |> Map.ofSeq
                        | _ -> Map.empty

                    match s.TryGetProperty "required" with
                    | true, req ->
                        for r in req.EnumerateArray() do
                            match v.TryGetProperty(r.GetString()) with
                            | true, _ -> ()
                            | _ -> yield $"{at}: missing required {r.GetString()}"
                    | _ -> ()

                    for p in v.EnumerateObject() do
                        match props.TryFind p.Name with
                        | Some ps -> yield! check ps p.Value $"{at}.{p.Name}"
                        | None ->
                            match s.TryGetProperty "additionalProperties" with
                            | true, a when a.ValueKind = JsonValueKind.False ->
                                yield $"{at}: unexpected property {p.Name}"
                            | true, a when a.ValueKind = JsonValueKind.Object -> yield! check a p.Value $"{at}.{p.Name}"
                            | _ -> ()
                if v.ValueKind = JsonValueKind.Array then
                    let items = v.EnumerateArray() |> Array.ofSeq

                    match s.TryGetProperty "minItems" with
                    | true, m when items.Length < m.GetInt32() -> yield $"{at}: fewer than {m.GetInt32()} items"
                    | _ -> ()

                    match s.TryGetProperty "maxItems" with
                    | true, m when items.Length > m.GetInt32() -> yield $"{at}: more than {m.GetInt32()} items"
                    | _ -> ()

                    let prefix =
                        match s.TryGetProperty "prefixItems" with
                        | true, p -> p.EnumerateArray() |> Array.ofSeq
                        | _ -> [||]

                    for i in 0 .. items.Length - 1 do
                        if i < prefix.Length then
                            yield! check prefix[i] items[i] $"{at}[{i}]"
                        else
                            match s.TryGetProperty "items" with
                            | true, it -> yield! check it items[i] $"{at}[{i}]"
                            | _ -> ()
                match s.TryGetProperty "allOf" with
                | true, all ->
                    for x in all.EnumerateArray() do
                        yield! check x v at
                | _ -> ()
                for key in [ "anyOf"; "oneOf" ] do
                    match s.TryGetProperty key with
                    | true, any ->
                        let results = any.EnumerateArray() |> Seq.map (fun x -> check x v at) |> List.ofSeq

                        if not (results |> List.exists List.isEmpty) then
                            let first = results |> List.minBy List.length
                            let closest = String.Join("; ", first |> List.truncate 3)
                            yield $"{at}: matches no {key} branch; closest: {closest}"
                    | _ -> ()
            ]

    member _.Root = root
    member _.Resolve(e: JsonElement) = resolve e
    member _.Check(schema: JsonElement, value: JsonElement) = check schema value "$"

    /// The path template and operation for a method and concrete path, if the API has one.
    member _.Find(meth: string, path: string) : (string * JsonElement) option =
        root.GetProperty("paths").EnumerateObject()
        |> Seq.tryPick (fun p ->
            let rx = "^" + Regex.Replace(Regex.Escape p.Name, @"\\\{[^}]+\}", "[^/]+") + "$"

            if Regex.IsMatch(path, rx) then
                match p.Value.TryGetProperty(meth.ToLowerInvariant()) with
                | true, op -> Some(p.Name, op)
                | _ -> None
            else
                None)

    /// The parameters of an operation (its own and its path item's), resolved.
    member this.Parameters(template: string, op: JsonElement) =
        let item = root.GetProperty("paths").GetProperty(template)

        [
            for source in [ item; op ] do
                match source.TryGetProperty "parameters" with
                | true, ps ->
                    for p in ps.EnumerateArray() do
                        resolve p
                | _ -> ()
        ]

let load (file: string) = Spec(JsonDocument.Parse(IO.File.ReadAllText file))

/// The values of each template parameter in a concrete path.
let pathValues (template: string) (path: string) =
    let names =
        Regex.Matches(template, @"\{([^}]+)\}") |> Seq.map (fun m -> m.Groups[1].Value) |> List.ofSeq

    let rx = "^" + Regex.Replace(Regex.Escape template, @"\\\{[^}]+\}", "([^/]+)") + "$"
    let m = Regex.Match(path, rx)

    [
        for i in 0 .. names.Length - 1 -> names[i], Uri.UnescapeDataString(m.Groups[i + 1].Value)
    ]

/// A JSON string element for a parameter value.
let stringElement (s: string) = (JsonDocument.Parse(JsonSerializer.Serialize s)).RootElement.Clone()
