/// The graffiti of a proposal: which layer gives the text, and the client codes appended to it.
///
/// Layers, the first one set wins: the proposer config file's entry for the key, the keymanager
/// API's setting for the key, a graffiti source a module offers (the graffiti file module), the
/// proposer config file's default_config, the core `graffiti`. Then, with `graffiti_append` on,
/// client codes go after the text, separated by a space, in the room the 32 bytes leave. The
/// operator's text is never cut for codes: when the codes do not fit, fewer digits go in, or none.
namespace Eplix

open System
open System.Collections.Generic
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Json

/// A client's identity as the Engine API's ClientVersionV1 gives it: a two-letter code and the
/// commit as hex (without 0x, lower case, possibly empty).
type ClientVersion = { Code: string; Commit: string }

/// What a node reported about itself and its execution client.
type NodeClients =
    {
        BeaconNode: ClientVersion voption
        ExecutionClient: ClientVersion voption
    }

    static member Unknown =
        {
            BeaconNode = ValueNone
            ExecutionClient = ValueNone
        }

/// What a graffiti source needs to pick and fill a text.
type GraffitiContext =
    {
        Key: PubKey
        Index: ValidatorIndex
        Slot: Slot
        Epoch: Epoch
    }

module Graffiti =
    [<Literal>]
    let MaxBytes = 32

    /// The longest prefix of `text` that is at most `max` bytes of UTF-8, never splitting a
    /// character (a surrogate pair counts as one).
    let fit (max: int) (text: string) =
        if Encoding.UTF8.GetByteCount text <= max then
            text
        else
            let mutable bytes = 0
            let mutable i = 0
            let mutable stop = false

            while not stop && i < text.Length do
                let width =
                    if Char.IsHighSurrogate text[i] && i + 1 < text.Length && Char.IsLowSurrogate text[i + 1] then
                        2
                    else
                        1

                let n = Encoding.UTF8.GetByteCount(text.AsSpan(i, width))

                if bytes + n > max then
                    stop <- true
                else
                    bytes <- bytes + n
                    i <- i + width

            text.Substring(0, i)

    /// The 32-byte field: UTF-8, zero padded, cut at a character boundary.
    let toRoot (text: string) =
        let b = Array.zeroCreate<byte> 32
        let raw = Encoding.UTF8.GetBytes(fit MaxBytes text)
        Buffer.BlockCopy(raw, 0, b, 0, raw.Length)
        Root.Of b

    /// A client code: two ASCII letters, upper-cased.
    let checkCode (code: string) =
        if code.Length = 2 && Seq.forall Char.IsAsciiLetter code then
            Ok(code.ToUpperInvariant())
        else
            Error $"'{code}' is not a client code of two ASCII letters"

    /// The commit digits kept: the graffiti uses at most 4, the log line shows these.
    let commitDigits = 8

    /// A commit as reported (0x-prefixed hex, any case) to its first `commitDigits` digits in
    /// lower-case hex, without 0x. Anything that is not hex, or longer than a SHA-256 commit (64
    /// digits), gives an empty commit, so only the code is used. A node's answer can be as long
    /// as the body cap; only the short form goes to the cache and the log.
    let normalCommit (commit: string) =
        let c =
            if commit.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then commit.Substring 2 else commit

        if c.Length > 0 && c.Length <= 64 && Seq.forall Char.IsAsciiHexDigit c then
            c.Substring(0, min commitDigits c.Length).ToLowerInvariant()
        else
            ""

    let private part (digits: int) (v: ClientVersion) = v.Code + v.Commit.Substring(0, min digits v.Commit.Length)

    /// The codes to append in at most `room` bytes: each code with 4 commit digits, else with 2,
    /// else the codes alone, else nothing. The order is execution client, beacon node, VC.
    let codes (parts: ClientVersion list) (room: int) =
        if parts.IsEmpty then
            ""
        else
            [ 4; 2; 0 ]
            |> List.map (fun d -> parts |> List.map (part d) |> String.concat "")
            |> List.tryFind (fun s -> s.Length <= room)
            |> Option.defaultValue ""

    /// The operator's text with the codes after it: a space between them when the text is not
    /// empty. The text is cut to 32 bytes first and never cut for the codes.
    let append (text: string) (parts: ClientVersion list) =
        let text = fit MaxBytes text
        let used = Encoding.UTF8.GetByteCount text
        let sep = if used > 0 then 1 else 0

        match codes parts (MaxBytes - used - sep) with
        | "" -> text
        | c when sep = 1 -> text + " " + c
        | c -> c

    /// Beacon node names in /eth/v1/node/version ("Lighthouse/v8.3.2-...") and their codes, for
    /// nodes without /eth/v2/node/version. The codes are the Engine API's ClientCode list.
    let private knownNodes =
        [
            "lighthouse", "LH"
            "teku", "TK"
            "lodestar", "LS"
            "nimbus", "NB"
            "prysm", "PM"
            "grandine", "GR"
        ]

    /// The beacon node of a v1 version string, code only (the string has no commit field).
    let ofV1 (version: string) : ClientVersion voption =
        let name = (version.Split('/') |> Array.head).Trim().ToLowerInvariant()

        knownNodes
        |> List.tryFind (fun (n, _) -> name.StartsWith n)
        |> Option.map (fun (_, c) -> { Code = c; Commit = "" })
        |> Option.toValueOption

    let private clientVersion (e: JsonElement) : ClientVersion voption =
        match tryProp e "code" with
        | ValueSome c when c.ValueKind = JsonValueKind.String ->
            match checkCode (str c) with
            | Ok code ->
                let commit =
                    match tryProp e "commit" with
                    | ValueSome m when m.ValueKind = JsonValueKind.String -> normalCommit (str m)
                    | _ -> ""

                ValueSome { Code = code; Commit = commit }
            | Error _ -> ValueNone
        | _ -> ValueNone

    /// GET /eth/v2/node/version: data.beacon_node and the optional data.execution_client.
    let decodeV2 (e: JsonElement) : NodeClients =
        let data = prop e "data"

        {
            BeaconNode =
                match tryProp data "beacon_node" with
                | ValueSome b when b.ValueKind = JsonValueKind.Object -> clientVersion b
                | _ -> ValueNone
            ExecutionClient =
                match tryProp data "execution_client" with
                | ValueSome x when x.ValueKind = JsonValueKind.Object -> clientVersion x
                | _ -> ValueNone
        }

    /// GET /eth/v1/node/version: data.version.
    let decodeV1 (e: JsonElement) : NodeClients =
        {
            BeaconNode = ofV1 (strField (prop e "data") "version")
            ExecutionClient = ValueNone
        }

    /// This build's commit from the informational version ("0.1.0+<sha>").
    let buildCommit () =
        match
            typeof<ClientVersion>
                .Assembly.GetCustomAttributes(typeof<Reflection.AssemblyInformationalVersionAttribute>, false)
        with
        | [| :? Reflection.AssemblyInformationalVersionAttribute as a |] ->
            match a.InformationalVersion.IndexOf '+' with
            | i when i >= 0 -> normalCommit (a.InformationalVersion.Substring(i + 1))
            | _ -> ""
        | _ -> ""

/// Picks the graffiti of each proposal and appends client codes (see the file header). One per
/// VC; the scheduler and the Gloas duties module ask it per proposal and per node, so each node
/// gets its own codes. Node codes come from a cache that `RefreshCodes` fills off the duty path;
/// a proposal never waits for a version call.
type GraffitiService(registry: KeyRegistry, defaultText: string, mode: GraffitiAppend, vcCode: string voption, log: Log)
    =
    let vc =
        match vcCode with
        | ValueSome c ->
            ValueSome
                {
                    Code = c
                    Commit = Graffiti.buildCommit ()
                }
        | ValueNone -> ValueNone

    let gate = obj ()
    let nodeCodes = Dictionary<BeaconClient, NodeClients>(HashIdentity.Reference)
    // Nodes whose last version call failed: the next failure logs at debug level only.
    let down = HashSet<BeaconClient>(HashIdentity.Reference)

    [<VolatileField>]
    let mutable source: GraffitiContext -> string voption = fun _ -> ValueNone

    let mutable refreshing = 0

    /// A service with no codes and no source: the core config's graffiti and the key settings only.
    static member Plain(registry: KeyRegistry, defaultText: string) =
        GraffitiService(registry, defaultText, GraffitiAppend.Off, ValueNone, Log.none)

    member _.Mode = mode

    /// A module's graffiti (the graffiti file). It sits below the per-key settings and above the
    /// defaults. Set once, before duties run.
    member _.SetSource(f: GraffitiContext -> string voption) = source <- f

    /// The text of a proposal, before codes.
    member _.Text(ctx: GraffitiContext) : string =
        match registry.KeyGraffiti ctx.Key with
        | ValueSome g -> g
        | ValueNone ->
            match source ctx with
            | ValueSome g -> Graffiti.fit Graffiti.MaxBytes g
            | ValueNone ->
                match (registry.SettingsOf ctx.Key).Graffiti with
                | ValueSome g -> g
                | ValueNone -> defaultText

    /// The codes this node gets: per the mode, from the cache.
    member _.Parts(node: BeaconClient) : ClientVersion list =
        match mode with
        | GraffitiAppend.Off -> []
        | GraffitiAppend.Vc -> Option.toList (ValueOption.toOption vc)
        | GraffitiAppend.All ->
            let n =
                lock gate (fun () ->
                    match nodeCodes.TryGetValue node with
                    | true, c -> c
                    | _ -> NodeClients.Unknown)

            [ n.ExecutionClient; n.BeaconNode; vc ] |> List.choose ValueOption.toOption

    /// The 32-byte graffiti of a proposal sent to `node`.
    member this.For(ctx: GraffitiContext, node: BeaconClient) : Root =
        Graffiti.toRoot (Graffiti.append (this.Text ctx) (this.Parts node))

    member this.For(duty: ProposerDuty, epoch: Epoch, node: BeaconClient) : Root =
        this.For(
            {
                Key = duty.PubKey
                Index = duty.ValidatorIndex
                Slot = duty.Slot
                Epoch = epoch
            },
            node
        )

    /// What the cache holds for a node.
    member _.NodeClients(node: BeaconClient) =
        lock gate (fun () ->
            match nodeCodes.TryGetValue node with
            | true, c -> ValueSome c
            | _ -> ValueNone)

    /// The nodes whose codes a proposal can carry: those with `block_data`, which build blocks and
    /// get the graffiti in their produceBlock query, and only those in use (a node not ready or
    /// dropped gets no call). A node without roles in the config holds every role.
    static member CodeNodes(nodes: BeaconNodes) : BeaconClient list =
        nodes.NodesWith NodeRole.BlockData |> List.filter nodes.InUse

    /// Refreshes the codes of the nodes that build blocks (`CodeNodes`).
    member this.RefreshCodes(nodes: BeaconNodes, ct: CancellationToken) : Task =
        if mode <> GraffitiAppend.All then
            Task.CompletedTask
        else
            this.RefreshCodes(GraffitiService.CodeNodes nodes, ct)

    /// Asks each node for its version (v2, else v1) and keeps the answers. Only with mode All;
    /// one run at a time: a call while one runs returns at once. A node that fails keeps its
    /// last answer. The first failure after an answer logs a warning, later ones log at debug
    /// level, so a node that stays down does not log each epoch.
    member _.RefreshCodes(nodes: BeaconClient list, ct: CancellationToken) : Task =
        if mode <> GraffitiAppend.All || Interlocked.Exchange(&refreshing, 1) = 1 then
            Task.CompletedTask
        else
            task {
                try
                    for node in nodes do
                        let name = node.Name

                        let failed (e: string) =
                            if lock gate (fun () -> down.Add node) then
                                log.Warn
                                    $"beacon node {name}: no version for graffiti codes, keeping its last codes: {e}"
                            else
                                log.Debug $"beacon node {name}: version for graffiti codes: {e}"

                        try
                            let! v2 = node.GetJson("/eth/v2/node/version", Graffiti.decodeV2, ct)

                            let! answer =
                                task {
                                    match v2 with
                                    | Ok(ValueSome c) -> return Ok c
                                    | _ ->
                                        match! node.GetJson("/eth/v1/node/version", Graffiti.decodeV1, ct) with
                                        | Ok(ValueSome c) -> return Ok c
                                        | Ok ValueNone -> return Error "no version endpoint"
                                        | Error e -> return Error e.Describe
                                }

                            match answer with
                            | Ok c ->
                                if lock gate (fun () -> down.Remove node) then
                                    log.Info $"beacon node {name}: answers the version call for graffiti codes again"

                                let changed =
                                    lock gate (fun () ->
                                        let old =
                                            match nodeCodes.TryGetValue node with
                                            | true, o -> ValueSome o
                                            | _ -> ValueNone

                                        nodeCodes[node] <- c
                                        old <> ValueSome c)

                                if changed then
                                    let show (v: ClientVersion voption) =
                                        match v with
                                        | ValueSome v -> $"{v.Code} {v.Commit}"
                                        | ValueNone -> "unknown"

                                    log.Info
                                        $"beacon node {name}: graffiti codes: beacon node {show c.BeaconNode}, execution client {show c.ExecutionClient}"
                            | Error e -> failed e
                        with
                        | :? OperationCanceledException -> ()
                        | e -> failed e.Message
                finally
                    Volatile.Write(&refreshing, 0)
            }
