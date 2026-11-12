/// `eplix import --no-signing-history`: a floor record (Floor.fs) for each
/// imported key, written before the VC starts. It covers a new validator and a lost setup (keys
/// made again from a mnemonic after a disk loss). A key that a beacon node shows as possibly
/// having signed (active, exited, withdrawal or slashed) needs the operator's yes on a terminal.
namespace Eplix

open System
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Slashing

module FloorImport =
    /// The validator may have signed: an active_*, exited_* or withdrawal_* status, or slashed.
    let mayHaveSigned (v: ValidatorInfo) =
        v.Slashed
        || v.Status.StartsWith "active_"
        || v.Status.StartsWith "exited_"
        || v.Status.StartsWith "withdrawal_"

    /// The operator's terminal. `Ask` shows a question and returns the answer, ValueNone at the end
    /// of input. Without a terminal (`Interactive` false) nothing is asked.
    type Prompt =
        {
            Interactive: bool
            Ask: string -> string voption
            Say: string -> unit
        }

    type Outcome =
        {
            /// E; the floor is at epoch E + 1.
            FloorEpoch: Epoch
            /// Keys that got a floor record.
            Floored: PubKey list
            /// Keys the operator answered no for.
            Declined: PubKey list
            /// Keys that needed a yes with no terminal to give it.
            Unconfirmed: PubKey list
        }

    /// Genesis and slot timing, and the nodes that answered on that chain. `pin` is what the start
    /// holds the nodes to (Runner.startPin). When it holds every value it stands even when no node
    /// answers; else a node must answer, and every node that answers must agree. A node that
    /// answers off the pin or with another spec fails the import.
    let chain
        (config: CoreConfig)
        (pin: AnchorPin)
        (clients: BeaconClient list)
        (say: string -> unit)
        (ct: CancellationToken)
        =
        task {
            let pinned = config.Chain.Pinned
            let anchor = AnchorPin.full pin

            let ask (b: BeaconClient) =
                task {
                    match! b.Genesis ct with
                    | Error e -> return Ok(Error e)
                    | Ok g ->
                        match! b.Spec ct with
                        | Error e -> return Ok(Error e)
                        | Ok values ->
                            return
                                Runner.checkChain b.Name g values pinned pin
                                |> Result.map (fun (g, s) ->
                                    Ok(ChainAnchor.ofSpec g.GenesisTime g.GenesisValidatorsRoot s))
                }

            let! answers = clients |> List.map ask |> Task.WhenAll
            let answers = List.zip clients (List.ofArray answers)

            match
                answers
                |> List.tryPick (fun (_, r) ->
                    match r with
                    | Error e -> Some e
                    | Ok _ -> None)
            with
            | Some e -> return Error e
            | None ->
                let onChain =
                    [
                        for b, r in answers do
                            match r with
                            | Ok(Ok a) -> b, a
                            | Ok(Error e) -> say $"beacon node {b.Name} did not answer: {e.Describe}"
                            | Error _ -> ()
                    ]

                match anchor, onChain with
                | ValueSome a, _ -> return Ok(a, List.map fst onChain)
                | ValueNone, [] ->
                    return
                        Error
                            "no beacon node answered, and nothing pins the whole genesis and slot timing; the floor needs it"
                | ValueNone, (_, first) :: rest ->
                    match
                        rest
                        |> List.tryPick (fun (b, a) ->
                            match ChainAnchor.differences "first node" first a with
                            | [] -> None
                            | d -> Some(b, d))
                    with
                    | Some(b, d) -> return Error $"""{b.Name} is on another chain ({String.Join("; ", d)})"""
                    | None -> return Ok(first, List.map fst onChain)
        }

    /// Asks the operator for each key a node shows as possibly having signed; the others need no
    /// question. `answered`: each synced node that answered and the validators it knows. No such
    /// node: every key counts as status unknown.
    let decide
        (prompt: Prompt)
        (floorTarget: Epoch)
        (answered: (string * ValidatorInfo[]) list)
        (keys: PubKey list)
        : Outcome =
        let floored = ResizeArray<PubKey>()
        let declined = ResizeArray<PubKey>()
        let unconfirmed = ResizeArray<PubKey>()
        let mutable all = false

        if answered.IsEmpty && not keys.IsEmpty then
            prompt.Say "no synced beacon node answered: every key counts as status unknown"

        for k in keys do
            let risk =
                if answered.IsEmpty then
                    [ "unknown" ]
                else
                    [
                        for name, infos in answered do
                            match infos |> Array.tryFind (fun v -> v.PubKey = k) with
                            | Some v when mayHaveSigned v -> $"{v.Status} on {name}"
                            | _ -> ()
                    ]

            if risk.IsEmpty then
                floored.Add k
            else
                let text =
                    $"""key {k.Hex}: status {String.Join(", ", risk)}; it may have signed before. The floor at epoch {floorTarget} or later protects against those votes only if no other machine signs with this key now."""

                if all then
                    prompt.Say $"{text} Import with a floor: yes (all)"
                    floored.Add k
                elif not prompt.Interactive then
                    prompt.Say $"{text} Not imported: no terminal to confirm it."
                    unconfirmed.Add k
                else
                    let mutable answer = ValueNone

                    while answer.IsNone do
                        match prompt.Ask $"{text} Import with a floor? [y/n/all] " with
                        | ValueNone -> answer <- ValueSome "n"
                        | ValueSome a ->
                            match a.Trim().ToLowerInvariant() with
                            | "y"
                            | "yes" -> answer <- ValueSome "y"
                            | "n"
                            | "no" -> answer <- ValueSome "n"
                            | "all" -> answer <- ValueSome "all"
                            | _ -> prompt.Say "answer y, n or all"

                    match answer.Value with
                    | "n" -> declined.Add k
                    | "all" ->
                        all <- true
                        floored.Add k
                    | _ -> floored.Add k

        {
            FloorEpoch = 0UL
            Floored = List.ofSeq floored
            Declined = List.ofSeq declined
            Unconfirmed = List.ofSeq unconfirmed
        }

    /// Asks the nodes for each key's status and their heads, asks the operator where needed, then
    /// writes the floor of the keys that pass into the data dir's slashing DB and slot marks.
    /// E is the clock's epoch, raised by the highest head a node reports. `keys` are new to the
    /// data dir; of the keys in `present` (keystore already there) only those with no slashing
    /// record take part, so a key a plain or keymanager import left without one can get a floor.
    let run
        (config: CoreConfig)
        (clients: BeaconClient list)
        (dataDir: DataDir)
        (time: TimeProvider)
        (prompt: Prompt)
        (keys: PubKey list)
        (present: PubKey list)
        (ct: CancellationToken)
        : Task<Result<Outcome, string>> =
        task {
            if keys.IsEmpty && present.IsEmpty then
                return
                    Ok
                        {
                            FloorEpoch = 0UL
                            Floored = []
                            Declined = []
                            Unconfirmed = []
                        }
            else
                let pin = Runner.startPin config.Chain config.Chain.Pinned dataDir.AnchorPath dataDir.SlashingDbRoot

                match!
                    (match pin with
                     | Error e -> Task.FromResult(Error e)
                     | Ok pin -> chain config pin clients prompt.Say ct)
                with
                | Error e -> return Error e
                | Ok(anchor, nodes) ->
                    // The DB first: a DB of another chain fails before any question.
                    let dbFile = new FileMarkFile(dataDir.SlashingDbPath)

                    match SlashingDb.Open(dbFile, anchor.GenesisValidatorsRoot) with
                    | Error e ->
                        (dbFile :> IDisposable).Dispose()
                        return Error e
                    | Ok db ->
                        use _ = db
                        let slotFile = new FileMarkFile(dataDir.SlotMarksPath)

                        match SlotMarks.Open(slotFile, anchor.GenesisValidatorsRoot) with
                        | Error e ->
                            (slotFile :> IDisposable).Dispose()
                            return Error e
                        | Ok slotMarks ->
                            use _ = slotMarks

                            let keys =
                                keys
                                @ (present |> List.filter (fun k -> not (db.HasRecord k) && not (List.contains k keys)))

                            let ids = keys |> List.map (fun k -> k.Hex)
                            let! syncs = nodes |> List.map (fun b -> b.Syncing ct) |> Task.WhenAll

                            let heads =
                                syncs
                                |> Array.choose (fun r ->
                                    match r with
                                    | Ok s -> Some s.HeadSlot
                                    | Error _ -> None)
                            // A node that is syncing or optimistic may not know an active key yet, so
                            // its statuses would let the key through with no question.
                            let synced =
                                [
                                    for b, r in List.zip nodes (List.ofArray syncs) do
                                        match r with
                                        | Ok s when not s.IsSyncing && not s.IsOptimistic -> b
                                        | Ok _ ->
                                            prompt.Say
                                                $"beacon node {b.Name} is syncing or optimistic; its validator statuses are not used"
                                        | Error e ->
                                            prompt.Say
                                                $"beacon node {b.Name}: sync status: {e.Describe}; its validator statuses are not used"
                                ]

                            let! statuses = synced |> List.map (fun b -> b.Validators("head", ids, ct)) |> Task.WhenAll

                            let answered =
                                [
                                    for b, r in List.zip synced (List.ofArray statuses) do
                                        match r with
                                        | Ok infos -> b.Name, infos
                                        | Error e -> prompt.Say $"beacon node {b.Name}: validator status: {e.Describe}"
                                ]

                            let clock =
                                SlotClock(
                                    DateTimeOffset.FromUnixTimeSeconds(int64 anchor.GenesisTime),
                                    anchor.SlotDuration,
                                    anchor.SlotsPerEpoch,
                                    time
                                )

                            let clockEpoch () =
                                clock.CurrentSlot |> ValueOption.map clock.EpochOf |> ValueOption.defaultValue 0UL

                            let now = clockEpoch ()

                            match Floor.epochChecked anchor.SlotsPerEpoch now heads with
                            | Error e -> return Error e
                            | Ok asked ->
                                let decision = decide prompt (Floor.target asked) answered keys
                                // An answer can take hours, and the old machine may sign until it is off,
                                // so the floor follows the clock at the time of writing.
                                let e = max asked (clockEpoch ())
                                let decision = { decision with FloorEpoch = e }

                                match
                                    Floor.write
                                        db
                                        (ValueSome slotMarks)
                                        anchor.SlotsPerEpoch
                                        e
                                        KeyOrigin.Floor
                                        decision.Floored
                                with
                                | Error e -> return Error $"writing the floor records: {e}"
                                | Ok() -> return Ok decision
        }
