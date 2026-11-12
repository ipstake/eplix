/// Retiring keys at run time: the drain every module uses to take a key out (draining,
/// then removed), and the count of polls in a row in which a remote signer's members
/// no longer list a key.
namespace Eplix

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks

/// One member's answer to a key list poll: a Dirk endpoint, a Web3Signer, a TEE runner.
type MemberAnswer =
    {
        Member: string
        /// The keys it listed, as the module holds them (no set needed; a key listed twice counts
        /// once). ValueNone: the call failed. An empty list counts as failed.
        Keys: IReadOnlyCollection<PubKey> voption
    }

/// One key in the absence count. `Poll`, `Listers`, `LastMember` and `Same` are scratch for the
/// poll being recorded.
[<Sealed; AllowNullLiteral>]
type internal AbsenceEntry(holders: Set<string>) =
    /// The members that listed the key the last time one did, plus earlier holders that have not
    /// answered since.
    member val Holders = holders with get, set
    /// Polls in a row that counted against the key.
    member val Misses = 0 with get, set
    /// The last poll that listed the key.
    member val Poll = 0 with get, set
    /// How many answering members listed it in that poll.
    member val Listers = 0 with get, set
    /// The index of the last member counted, so a key listed twice by one member counts once.
    member val LastMember = -1 with get, set
    /// Every member that listed it in that poll is one of `Holders`.
    member val Same = false with get, set

/// Per key: the members that hold it and the polls in a row that lacked it. One entry per key in
/// a dictionary, updated in place: a poll in which every key keeps its holders allocates nothing
/// per key.
[<Sealed>]
type AbsenceTracker() =
    let entries = Dictionary<PubKey, AbsenceEntry>()
    let mutable poll = 0

    /// Polls in a row without a key before it is retired.
    static member DefaultPolls = 2

    /// Records one poll. A poll counts against a key only when every holder of the key answered
    /// with a non-empty list and no member that answered lists it; any other poll starts the
    /// count again. Returns the keys that reached `polls` polls in a row, each with its holders,
    /// in key order. Those keys leave the tracker; a key listed later starts afresh.
    member _.Step(polls: int, answers: MemberAnswer list) : (PubKey * Set<string>) list =
        let polls = max 1 polls
        poll <- poll + 1
        let failed = HashSet<string>()

        for a in answers do
            match a.Keys with
            | ValueSome k when k.Count > 0 -> ()
            | _ -> failed.Add a.Member |> ignore
        // A member named twice counts as answered only if no copy failed; its lists count together.
        let answered = Dictionary<string, ResizeArray<IReadOnlyCollection<PubKey>>>()

        for a in answers do
            match a.Keys with
            | ValueSome k when not (failed.Contains a.Member) ->
                match answered.TryGetValue a.Member with
                | true, l -> l.Add k
                | _ -> answered[a.Member] <- ResizeArray [ k ]
            | _ -> ()
        // Count the members that list each key, and note whether they are all holders already.
        let mutable i = 0

        for KeyValue(m, lists) in answered do
            for keys in lists do
                for k in keys do
                    match entries.TryGetValue k with
                    | true, e ->
                        if e.Poll <> poll then
                            e.Poll <- poll
                            e.Listers <- 0
                            e.LastMember <- -1
                            e.Same <- true

                        if e.LastMember <> i then
                            e.LastMember <- i
                            e.Listers <- e.Listers + 1

                            if e.Same && not (e.Holders.Contains m) then
                                e.Same <- false
                    | _ -> entries[k] <- AbsenceEntry(Set.empty, Poll = poll, Listers = 1, LastMember = i, Same = false)

            i <- i + 1
        // Listed keys whose holders change: the holders that did not answer, then the listers.
        let changed = Dictionary<PubKey, Set<string>>()
        let gone = ResizeArray<PubKey * Set<string>>()

        for KeyValue(k, e) in entries do
            if e.Poll = poll then
                e.Misses <- 0
                // Listers that are all holders and as many as the holders: the holders stay.
                if not (e.Same && e.Listers = e.Holders.Count) then
                    changed[k] <- e.Holders |> Set.filter (fun m -> not (answered.ContainsKey m))
            else
                let old = e.Holders

                if not old.IsEmpty && old |> Set.forall answered.ContainsKey then
                    let n = e.Misses + 1
                    if n >= polls then gone.Add(k, old) else e.Misses <- n
                else
                    e.Misses <- 0

        if changed.Count > 0 then
            for KeyValue(m, lists) in answered do
                for keys in lists do
                    for k in keys do
                        match changed.TryGetValue k with
                        | true, s -> changed[k] <- s.Add m
                        | _ -> ()

            for KeyValue(k, s) in changed do
                entries[k].Holders <- s

        for k, _ in gone do
            entries.Remove k |> ignore

        gone |> Seq.sortBy fst |> List.ofSeq

    /// Every tracked key with its holders and its count (for tests).
    member _.Snapshot() : Map<PubKey, Set<string> * int> =
        entries |> Seq.map (fun (KeyValue(k, e)) -> k, (e.Holders, e.Misses)) |> Map.ofSeq

module KeyRetirement =
    /// Takes a key out: draining (no new duty), up to 5 s for its signatures in flight,
    /// `cleanup`, then removed. Its slashing record stays in the DB. A halted key is not
    /// drained: it stays halted until restart, so a removal and a new import cannot bring it
    /// back as a fresh key. Returns false then, and `cleanup` does not run.
    let drain
        (registry: KeyRegistry)
        (pipeline: Pipeline)
        (log: Log)
        (key: PubKey)
        (cleanup: unit -> unit)
        (ct: CancellationToken)
        : Task<bool> =
        task {
            if not (registry.TryDrain key) then
                return false
            else
                let! idle = pipeline.WaitIdle([ key ], TimeSpan.FromSeconds 5.0, ct)

                if not idle then
                    log.Warn $"key {key.Short}: signatures still in flight after 5 s; removing anyway"

                cleanup ()
                registry.SetState(key, KeyState.Removed)
                return true
        }

/// The keys a remote signer module routes, kept in step with its members' key lists: new keys
/// are added, keys gone from every member for `polls` polls in a row are retired, and a retired
/// key that is listed again comes back through the history check.
type ListedKeys(label: string, registry: KeyRegistry, pipeline: Pipeline, log: Log, polls: int) =
    let gate = obj ()
    /// The keys this module routes, with the backend it gave each.
    let mine = Dictionary<PubKey, Backend>()
    /// Keys this module retired, so it may bring them back.
    let retired = HashSet<PubKey>()
    let tracker = AbsenceTracker()

    new(label, registry, pipeline, log) = ListedKeys(label, registry, pipeline, log, AbsenceTracker.DefaultPolls)

    /// The time one key list call gets. A signer that never answers then fails its list like
    /// one that is down: the start goes on to the next module, and the refresh loop tries again.
    static member ListDeadline = TimeSpan.FromSeconds 10.0

    /// Runs one key list call with a token that ends at `ct` or after `deadline` on `time`.
    static member WithDeadline
        (time: TimeProvider, deadline: TimeSpan, ct: CancellationToken, call: CancellationToken -> Task<'T>)
        : Task<'T> =
        task {
            use own = new CancellationTokenSource(deadline, time)
            use linked = CancellationTokenSource.CreateLinkedTokenSource(own.Token, ct)
            return! call linked.Token
        }

    /// Refuses the keys this module found unfit to route, such as a threshold key whose shares
    /// are not one split of it: each stops until the VC restarts.
    member _.Refuse(refused: (PubKey * string) list) =
        for key, why in refused do
            registry.Refuse(key, $"{label}: {why}")

    /// Routes each new key to its backend; a key this module retired goes back to discovered, so
    /// it passes the history check again. A key another backend holds keeps that route, unless
    /// one route is whole and the other a threshold group: the registry then refuses the key
    /// rather than let the whole copy sign alone. Returns how many keys were added or brought back.
    member _.Register(found: (PubKey * Backend) list) : int =
        lock gate (fun () ->
            let mutable added = 0

            for key, backend in found do
                if registry.Add(key, backend) then
                    mine[key] <- backend
                    added <- added + 1
                else
                    match registry.TryGet key with
                    | ValueSome k when k.State = KeyState.Removed && retired.Contains key ->
                        if registry.Revive(key, backend) then
                            retired.Remove key |> ignore
                            mine[key] <- backend
                            added <- added + 1

                            log.Info
                                $"{label}: key {key.Short} is listed again; it goes through the history check again"
                    | ValueSome k ->
                        // Brought back another way (the keymanager API): no longer this module's to revive.
                        if k.State <> KeyState.Removed then
                            retired.Remove key |> ignore

                        if k.Backend.Name <> backend.Name && not (mine.ContainsKey key) then
                            log.Debug
                                $"key {key.Short} is offered by {k.Backend.Name} and {backend.Name}; keeping the first"
                    | ValueNone -> ()

            added)

    /// Records one poll and retires the keys of this module that every holder answered without
    /// for `polls` polls in a row, except keys `retirable` refuses and halted keys. Returns the
    /// retired keys.
    member _.Retire(answers: MemberAnswer list, retirable: PubKey -> bool, ct: CancellationToken) : Task<PubKey list> =
        task {
            let todo =
                lock gate (fun () ->
                    let gone = tracker.Step(polls, answers)

                    [
                        for key, holders in gone do
                            match mine.TryGetValue key, registry.TryGet key with
                            | (true, ours), ValueSome k when obj.ReferenceEquals(k.Backend, ours) && retirable key ->
                                match k.State with
                                | KeyState.Draining
                                | KeyState.Removed -> ()
                                | KeyState.Halted _ ->
                                    log.Warn
                                        $"{label}: key {key.Short} is no longer listed but stays halted; a halted key is never retired"
                                | _ -> yield key, holders
                            | _ -> ()
                    ])

            for key, holders in todo do
                let names = String.Join(", ", holders)
                log.Warn $"{label}: key {key.Short} retired: {names} answered {polls} polls in a row without it"
                Metrics.retired label

            let! _ =
                todo
                |> List.map (fun (key, _) ->
                    KeyRetirement.drain
                        registry
                        pipeline
                        log
                        key
                        (fun () -> lock gate (fun () -> retired.Add key |> ignore))
                        ct)
                |> Task.WhenAll

            return todo |> List.map fst
        }
