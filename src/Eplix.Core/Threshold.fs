/// The threshold combinator (design section 4): m of n members that each return a partial
/// signature for the same validator key. The result is a Backend like any other, so the pipeline
/// routes a threshold key to it as it routes a whole key to one backend.
namespace Eplix

open System
open System.Collections.Concurrent
open System.Runtime.ExceptionServices
open System.Threading
open System.Threading.Channels
open System.Threading.Tasks

/// One signer of a threshold group. Index is the x coordinate of its share (Dirk's participant id).
type Member =
    {
        Backend: Backend
        Index: uint64
        /// Time this member gets for one request, capped by the request deadline.
        Budget: TimeSpan
    }

/// Checks combined signatures in batches. A burst of attestations gives hundreds of combined
/// signatures within a few milliseconds; one random-linear-combination check (Bls.verifyBatch)
/// costs about what a few single checks cost. While one batch is checked the next one queues,
/// so a lone request is checked at once and a burst in a few large batches. When a batch fails,
/// each of its signatures is checked alone, so a bad one fails only its own request.
type BatchVerifier(maxBatch: int) =
    let queue =
        Channel.CreateUnbounded<struct (Bls.BatchItem * TaskCompletionSource<bool>)>(
            UnboundedChannelOptions(SingleReader = true)
        )

    let checkOneByOne (items: struct (Bls.BatchItem * TaskCompletionSource<bool>)[]) =
        Parallel.For(
            0,
            items.Length,
            fun i ->
                let struct (x, tcs) = items[i]

                let ok =
                    try
                        Bls.verify (ReadOnlySpan x.Key.Bytes) (ReadOnlySpan x.Message.Bytes) (ReadOnlySpan x.Signature)
                    with _ ->
                        false

                tcs.TrySetResult ok |> ignore
        )
        |> ignore

    let worker =
        Task.Run(fun () ->
            task {
                let taken = ResizeArray<struct (Bls.BatchItem * TaskCompletionSource<bool>)>()

                while true do
                    let! first = queue.Reader.ReadAsync()
                    taken.Clear()
                    taken.Add first
                    let mutable next = Unchecked.defaultof<_>

                    while taken.Count < maxBatch && queue.Reader.TryRead(&next) do
                        taken.Add next

                    let items = taken.ToArray()

                    let ok =
                        try
                            Bls.verifyBatch (items |> Array.map (fun struct (x, _) -> x))
                        with _ ->
                            false

                    if ok then
                        for struct (_, tcs) in items do
                            tcs.TrySetResult true |> ignore
                    else
                        checkOneByOne items
            }
            :> Task)

    static member val Shared = BatchVerifier(4096)

    /// True when `signature` is valid for `key` over `message`.
    member _.Verify(key: PubKey, message: Root, signature: byte[]) : Task<bool> =
        let tcs = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)

        queue.Writer.TryWrite(
            struct ({
                        Bls.BatchItem.Key = key
                        Message = message
                        Signature = signature
                    },
                    tcs)
        )
        |> ignore

        ignore worker
        tcs.Task

/// One member's queue (the TEE pool's rule): at most `capacity` requests
/// in flight, the high class first, and every `lowEvery`-th free slot to the oldest low request
/// while one waits (0: first come first served). A request whose token ends while it waits leaves
/// the queue unsent, so a non-slashable request still queued when m partials are in is dropped.
type MemberGate(capacity: int, lowEvery: int) =
    let gate = obj ()
    let high = Collections.Generic.Queue<TaskCompletionSource<bool>>()
    let low = Collections.Generic.Queue<TaskCompletionSource<bool>>()
    let mutable free = capacity
    let mutable sinceLow = 0

    /// The oldest waiter of a queue that still waits; drops the ones whose token ended.
    let rec live (q: Collections.Generic.Queue<TaskCompletionSource<bool>>) =
        if q.Count = 0 then
            ValueNone
        elif q.Peek().Task.IsCompleted then
            q.Dequeue() |> ignore
            live q
        else
            ValueSome(q.Peek())

    /// The next waiter to get a free slot; ValueNone frees the slot. Called under the lock.
    let next () : TaskCompletionSource<bool> voption =
        match live high, live low with
        | ValueSome _, ValueSome _ when lowEvery > 0 && sinceLow + 1 >= lowEvery ->
            sinceLow <- 0
            ValueSome(low.Dequeue())
        | ValueSome _, l ->
            if l.IsSome then
                sinceLow <- sinceLow + 1

            ValueSome(high.Dequeue())
        | ValueNone, ValueSome _ ->
            sinceLow <- 0
            ValueSome(low.Dequeue())
        | ValueNone, ValueNone ->
            free <- free + 1
            ValueNone

    /// The answer of an Enter that found a free slot, made once.
    static member val Entered = Task.FromResult true

    member _.InFlight = lock gate (fun () -> capacity - free)

    /// Waits for a slot. True: the caller holds one and must call Leave. False: the token ended first.
    member _.Enter(priority: Priority, ct: CancellationToken) : Task<bool> =
        let waiter =
            lock gate (fun () ->
                if free > 0 && (live high).IsNone && (live low).IsNone then
                    free <- free - 1
                    ValueNone
                else
                    let t = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
                    (if priority = Priority.High then high else low).Enqueue t
                    ValueSome t)

        match waiter with
        | ValueNone -> MemberGate.Entered
        | ValueSome w ->
            task {
                use _ = ct.Register(fun () -> w.TrySetResult false |> ignore)
                return! w.Task
            }

    /// Hands the slot to the next waiter, or frees it.
    member _.Leave() =
        let mutable handed = false

        while not handed do
            match lock gate next with
            | ValueNone -> handed <- true
            | ValueSome w -> handed <- w.TrySetResult true

/// One key of a RepeatLimit: when its last line was written and how many repeats since then
/// were not written.
type RepeatEntry(last: DateTimeOffset) =
    member val Last = last with get, set
    member val Suppressed = 0 with get, set

/// Limits repeated log lines: at most one line per key per `window`. The first line after the
/// window says how many repeats were not written. Keys whose window ended are dropped by Sweep,
/// which returns the ones with repeats not written yet. Past `capacity` keys, new keys are not
/// written but counted, and Sweep reports that count. Used on failure paths only.
type RepeatLimit<'K when 'K: equality and 'K: not null>(window: TimeSpan, capacity: int) =
    let gate = obj ()
    let entries = Collections.Generic.Dictionary<'K, RepeatEntry>()
    let mutable lastSweep = DateTimeOffset.MinValue
    let mutable overflow = 0

    /// Whether to write the line for `key` now: (write, repeats not written since `since`).
    member _.Admit(key: 'K, now: DateTimeOffset) : struct (bool * int * DateTimeOffset) =
        lock gate (fun () ->
            match entries.TryGetValue key with
            | true, e when now - e.Last < window ->
                e.Suppressed <- e.Suppressed + 1
                struct (false, 0, e.Last)
            | true, e ->
                let r = struct (true, e.Suppressed, e.Last)
                e.Last <- now
                e.Suppressed <- 0
                r
            | _ when entries.Count >= capacity ->
                overflow <- overflow + 1
                struct (false, 0, now)
            | _ ->
                entries[key] <- RepeatEntry now
                struct (true, 0, now))

    /// Once per window: drops the keys whose window ended and returns those with repeats not
    /// written, as (key, repeats, time of the last line written), and the count of lines not
    /// written because the table was full. Empty and 0 between sweeps.
    member _.Sweep(now: DateTimeOffset) : struct ('K * int * DateTimeOffset)[] * int =
        lock gate (fun () ->
            if now - lastSweep < window then
                Array.Empty(), 0
            else
                lastSweep <- now
                let ended = ResizeArray()
                let stale = ResizeArray()

                for KeyValue(k, e) in entries do
                    if now - e.Last >= window then
                        stale.Add k

                        if e.Suppressed > 0 then
                            ended.Add(struct (k, e.Suppressed, e.Last))

                for k in stale do
                    entries.Remove k |> ignore

                let o = overflow
                overflow <- 0
                ended.ToArray(), o)

module Threshold =
    /// The backends `create` made, so other parts can tell a threshold key from a whole key.
    let private groups = System.Runtime.CompilerServices.ConditionalWeakTable<Backend, string>()

    /// Whether the backend is a threshold group made by `create`.
    let isGroup (b: Backend) =
        match groups.TryGetValue b with
        | true, _ -> true
        | _ -> false

    /// Refusals that say "will not sign this", counted as denied in the tally. A group with too
    /// few signatures answers Slashable if a member said slashable (the divergence alarm, design
    /// 4 point 5), else Denied with the tally.
    let isDenial (r: Refusal) =
        match r with
        | Denied _
        | Slashable _
        | LostToPeer _
        | PolicyDenied _ -> true
        | _ -> false

    /// The refusal that answers for a group when too few signed and no member denied: the one
    /// the pipeline must act on first (a config alarm before a key refresh).
    let mergeRefusals (refusals: Refusal list) : Refusal =
        let rank r =
            match r with
            | DomainMismatch -> 0
            | BadRequest _ -> 1
            | Refusal.NotReadyUntil _ -> 2
            | UnknownKey -> 3
            | Unsupported _ -> 4
            | Paused _
            | Denied _
            | Slashable _
            | LostToPeer _
            | PolicyDenied _ -> 5

        refusals |> List.minBy rank

    /// One failure for the group. A timeout wins (the deadline passed); otherwise the members'
    /// texts joined, with a member that is gone named as such so the operator sees it.
    let mergeFailures (failures: SignFailure list) : SignFailure =
        if failures |> List.exists (fun f -> f = SignFailure.Timeout) then
            SignFailure.Timeout
        else
            let parts =
                failures
                |> List.map (fun f ->
                    match f with
                    | Transport m -> m
                    | Internal m -> m
                    | Unavailable m -> m
                    | Gone m -> $"gone: {m}"
                    | SignFailure.Timeout -> "timeout")
                |> List.distinct

            Transport(String.Join("; ", parts))

    /// A member's answer as the tally counts it: signed, denied, failed or errored.
    let outcomeClass (o: SignOutcome) =
        match o with
        | Signed _
        | Partial _ -> "signed"
        | Refused r when isDenial r -> "denied"
        | Refused _
        | Failed(Internal _) -> "failed"
        | Failed _ -> "errored"

    /// The longest reason text a log line carries, in UTF-16 units.
    [<Literal>]
    let MaxReason = 200

    /// Characters that cannot stand in a log line: control characters (CR and LF too), the
    /// line and paragraph separators U+2028 and U+2029, and format characters such as the bidi
    /// override U+202E, which can make a line read other than it is.
    let private unsafeChar (c: char) =
        Char.IsControl c
        || c = '\u2028'
        || c = '\u2029'
        || Char.GetUnicodeCategory c = Globalization.UnicodeCategory.Format

    /// A signer's text made safe for one log line: at most MaxReason units and "..." when cut,
    /// unsafe characters as spaces (a format character outside the BMP too), a lone surrogate
    /// as U+FFFD, and no pair split at the cut. A signer's text can be megabytes long and hold
    /// newlines that would forge log lines. Reads at most MaxReason + 1 units of the input.
    let cleanReason (s: string) =
        let look = min s.Length (MaxReason + 1)
        let mutable clean = s.Length <= MaxReason
        let mutable k = 0

        while clean && k < look do
            if unsafeChar s[k] || Char.IsSurrogate s[k] then
                clean <- false

            k <- k + 1

        if clean then
            s
        else
            let b = Text.StringBuilder(MaxReason + 3)
            let mutable i = 0
            let mutable full = false

            while not full && i < s.Length do
                let c = s[i]

                if Char.IsHighSurrogate c && i + 1 < s.Length && Char.IsLowSurrogate s[i + 1] then
                    let format =
                        Globalization.CharUnicodeInfo.GetUnicodeCategory(Char.ConvertToUtf32(c, s[i + 1])) =
                            Globalization.UnicodeCategory.Format

                    if format && b.Length + 1 <= MaxReason then
                        b.Append(' ') |> ignore
                        i <- i + 2
                    elif format || b.Length + 2 > MaxReason then
                        full <- true
                    else
                        b.Append(c).Append(s[i + 1]) |> ignore
                        i <- i + 2
                elif b.Length + 1 > MaxReason then
                    full <- true
                else
                    b.Append(
                        if Char.IsSurrogate c then '\uFFFD'
                        elif unsafeChar c then ' '
                        else c
                    )
                    |> ignore

                    i <- i + 1

            if i < s.Length then
                b.Append("...") |> ignore

            b.ToString()

    /// A member's refusal with its text cleaned by cleanReason. The case stays the same, so a
    /// Slashable stays Slashable; only the text changes.
    let cleanRefusal (r: Refusal) =
        match r with
        | Slashable why -> Slashable(cleanReason why)
        | LostToPeer why -> LostToPeer(cleanReason why)
        | PolicyDenied why -> PolicyDenied(cleanReason why)
        | Denied(why, t) -> Denied(cleanReason why, t)
        | BadRequest why -> BadRequest(cleanReason why)
        | Paused why -> Paused(cleanReason why)
        | r -> r

    /// A member's failure with its text cleaned by cleanReason; the case stays the same.
    let cleanFailure (f: SignFailure) =
        match f with
        | Transport m -> Transport(cleanReason m)
        | Internal m -> Internal(cleanReason m)
        | Unavailable m -> Unavailable(cleanReason m)
        | Gone m -> Gone(cleanReason m)
        | SignFailure.Timeout -> f

    /// Why a member did not sign, for the log, cleaned by cleanReason. The signer's text is cut
    /// before it is formatted, so a long text is never copied whole.
    let outcomeReason (o: SignOutcome) =
        let c = cleanReason

        match o with
        // The class already says denied; the member's own tally adds nothing.
        | Refused(Denied(why, _)) -> c why
        | Refused(Slashable why) -> c $"slashable: {c why}"
        | Refused(PolicyDenied why) -> c $"policy: {c why}"
        | Refused(BadRequest why) -> c $"bad request: {c why}"
        | Refused(Paused why) -> c $"paused: {c why}"
        | Refused r -> c r.Describe
        | Failed(Transport m) -> c $"transport: {c m}"
        | Failed(Internal m) -> c $"internal: {c m}"
        | Failed(Unavailable m) -> c $"unavailable: {c m}"
        | Failed(Gone m) -> c $"gone: {c m}"
        | o -> c o.Describe

    /// The kind of a member's answer, from a fixed set: the rate limit of the failure lines
    /// keys on it, so free text from a signer cannot make new keys.
    let outcomeKind (o: SignOutcome) =
        match o with
        | Signed _
        | Partial _ -> "signed"
        | Refused(Slashable _) -> "slashable"
        | Refused(LostToPeer _) -> "lost to peer"
        | Refused(PolicyDenied _) -> "policy"
        | Refused(Denied _) -> "denied"
        | Refused(Refusal.NotReadyUntil _) -> "not ready"
        | Refused UnknownKey -> "unknown key"
        | Refused(Unsupported _) -> "unsupported"
        | Refused DomainMismatch -> "domain mismatch"
        | Refused(BadRequest _) -> "bad request"
        | Refused(Paused _) -> "paused"
        | Failed SignFailure.Timeout -> "timeout"
        | Failed(Transport _) -> "transport"
        | Failed(Internal _) -> "internal"
        | Failed(Unavailable _) -> "unavailable"
        | Failed(Gone _) -> "gone"

    /// The window of the per-member failure lines: one line per member, duty kind and answer kind.
    let memberLineWindow = TimeSpan.FromMinutes 5.0

    /// Rate limit keys per member. Duty kinds times answer kinds is about 230, so the cap is
    /// reached only by a bug; each member has its own, so one member cannot hide another.
    let memberLineKeys = 256

    /// Validator keys per member whose floor line is remembered, so it is written once per
    /// key and floor epoch.
    let memberFloorKeys = 4096

    /// Index sets one request may combine before it gives up. C(7, 5) = 21 fits; a larger group
    /// with many bad partials stops here rather than spend a pairing check per set.
    let maxAttempts = 32

    /// In a member's queue, every 8th free slot goes to a waiting low-class request (the TEE
    /// pool's rule).
    [<Literal>]
    let LowEvery = 8

    /// A member's floor state: signs votes and blocks.
    [<Literal>]
    let Ready = 0UL

    /// A member's floor state: refused a vote for want of trusted time, with no epoch.
    [<Literal>]
    let NoTrustedTime = UInt64.MaxValue

    /// The m-element subsets of 0 .. k - 1 as position arrays, in lexicographic order.
    let subsets (k: int) (m: int) : int[] seq =
        let rec go (start: int) (left: int) : int list seq =
            seq {
                if left = 0 then
                    yield []
                else
                    for i in start .. k - left do
                        for rest in go (i + 1) (left - 1) do
                            yield i :: rest
            }

        go 0 m |> Seq.map Array.ofList

    /// Checks the size of a group where it is configured: 1 <= m <= n and
    /// 2m > n. With 2m <= n two sets of m members share no member, so each set can sign a
    /// different message for the same slot and every member's slashing protection allows it.
    let checkSize (m: int) (n: int) : Result<unit, string> =
        if m < 1 || m > n then
            Error $"threshold {m} of {n} members; it must be 1 to {n}"
        elif 2 * m <= n then
            Error
                $"threshold {m} of {n} members lets two sets of members with no member in common sign; it must be more than half the members ({n / 2 + 1} or more)"
        else
            Ok()

    /// Index sets in lexicographic order checkShares tries, after the m + 1 sets that leave
    /// one of the lowest m + 1 shares out, when it looks for m shares that combine to the key.
    let private maxShareSets = 64

    /// Checks the share keys of a threshold key where they are loaded (config, key lists),
    /// never per signature: every share must lie on one polynomial of degree
    /// m - 1 whose value at 0 is the key. It finds m shares that combine to the key, lowest
    /// indices first, then checks each other share with m - 1 of those: the set combines to
    /// the key only when the share is on the same polynomial. The error names the members whose
    /// share is off. Fewer than m shares pass: there is nothing to check yet.
    let checkShares (m: int) (key: PubKey) (shares: (uint64 * PubKey) list) : Result<unit, string> =
        let shares = shares |> List.sortBy fst |> Array.ofList

        let combines (chosen: (uint64 * PubKey)[]) =
            match Bls.lagrangeCoefficients (chosen |> Array.map fst) with
            | ValueNone -> false
            | ValueSome c ->
                match Bls.combinePublicShares c [| for _, s in chosen -> s.Bytes |] with
                | ValueSome pk -> pk.AsSpan().SequenceEqual(ReadOnlySpan key.Bytes)
                | ValueNone -> false

        let names (xs: (uint64 * PubKey) seq) = String.Join(", ", xs |> Seq.map fst)

        if m < 1 || shares.Length < m then
            Ok()
        else
            // The lowest m + 1 shares with one left out each come first: one bad share among them
            // still leaves a set without it, so the error can name it. The first index sets in
            // lexicographic order all hold the lowest index once n is large.
            let leaveOneOut =
                seq {
                    if shares.Length > m then
                        for skip in m .. -1 .. 0 do
                            yield
                                [|
                                    for j in 0..m do
                                        if j <> skip then
                                            j
                                |]
                }

            let basis =
                Seq.append leaveOneOut (subsets shares.Length m |> Seq.truncate maxShareSets)
                |> Seq.distinct
                |> Seq.map (Array.map (fun j -> shares[j]))
                |> Seq.tryFind combines

            match basis with
            | None ->
                Error $"no {m} of the share keys of members {names shares} combine to the key; check the member indices"
            | Some basis ->
                let rest = basis[.. m - 2]

                let off =
                    shares
                    |> Array.filter (fun s ->
                        not (Array.contains s basis) && not (combines (Array.append rest [| s |])))

                if off.Length = 0 then
                    Ok()
                else
                    let who = if off.Length = 1 then "member" else "members"
                    Error $"{who} {names off}: share key not on the split of members {names basis}"

    /// checkShares for each (threshold, key, shares), `parallelism` at a time, so the start does
    /// not wait seconds for 10,000 keys.
    /// Each check reads only its own item and logs nothing, so the results, in input order,
    /// are those of a check one by one. Cancelling `ct` stops before the next check starts and
    /// throws OperationCanceledException.
    let checkSharesAll
        (parallelism: int)
        (ct: CancellationToken)
        (items: struct (int * PubKey * (uint64 * PubKey) list)[])
        : Result<unit, string>[] =
        let results = Array.zeroCreate items.Length

        let one i =
            let struct (m, key, shares) = items[i]
            results[i] <- checkShares m key shares

        if parallelism <= 1 || items.Length < 2 then
            for i in 0 .. items.Length - 1 do
                ct.ThrowIfCancellationRequested()
                one i
        else
            let options = ParallelOptions(MaxDegreeOfParallelism = parallelism, CancellationToken = ct)

            try
                Parallel.For(0, items.Length, options, (fun i -> one i)) |> ignore
            with :? AggregateException as e when e.InnerExceptions.Count = 1 ->
                // The exception a check one by one would throw.
                ExceptionDispatchInfo.Capture(e.InnerExceptions[0]).Throw()

        results

    /// The last checkShares result per key, with the threshold and the (index, share key) set it
    /// was given. A key list refresh runs the check again only for a key whose threshold or
    /// shares changed. Sweep drops the keys no Check asked about since the last Sweep.
    /// The checks a round needs run `atStart` at a time until the first Sweep (module start,
    /// before any duty), then `later` at a time, so a refresh leaves cores to signing.
    type ShareChecks(atStart: int, later: int) =
        let gate = obj ()

        let mutable last =
            Collections.Generic.Dictionary<PubKey, struct (int * (uint64 * PubKey)[] * Result<unit, string>)>()

        let mutable current =
            Collections.Generic.Dictionary<PubKey, struct (int * (uint64 * PubKey)[] * Result<unit, string>)>()

        let mutable runs = 0L
        let mutable swept = false

        /// The last result for the key when its threshold and shares are unchanged.
        let cached (m: int) (key: PubKey) (given: (uint64 * PubKey)[]) =
            lock gate (fun () ->
                let hit (d: Collections.Generic.Dictionary<_, _>) =
                    match d.TryGetValue key with
                    | true, struct (m', s, r) when m' = m && s = given -> ValueSome r
                    | _ -> ValueNone

                match hit current with
                | ValueSome r -> ValueSome r
                | ValueNone ->
                    match hit last with
                    | ValueSome r ->
                        current[key] <- struct (m, given, r)
                        ValueSome r
                    | ValueNone -> ValueNone)

        /// All cores at start, half of them at a refresh.
        new() = ShareChecks(Environment.ProcessorCount, max 1 (Environment.ProcessorCount / 2))

        /// How many times a check ran checkShares, for tests.
        member _.Runs = lock gate (fun () -> runs)

        /// checkShares for items 0 to count - 1, or the last result of an item whose key,
        /// threshold and shares are unchanged. `item` runs once per index, in order, on the
        /// calling thread; only the items that need a check stay in memory until the end. Those
        /// checks run in parallel; the results keep the order of the indices.
        member _.CheckAll
            (count: int, item: int -> struct (int * PubKey * (uint64 * PubKey) list), ct: CancellationToken)
            : Result<unit, string>[] =
            let results = Array.zeroCreate count

            let misses =
                ResizeArray<struct (int * (uint64 * PubKey)[] * struct (int * PubKey * (uint64 * PubKey) list))>()

            for i in 0 .. count - 1 do
                let struct (m, key, shares) as x = item i
                let given = shares |> List.sortBy fst |> Array.ofList

                match cached m key given with
                | ValueSome r -> results[i] <- r
                | ValueNone -> misses.Add(struct (i, given, x))

            if misses.Count > 0 then
                let width = lock gate (fun () -> if swept then later else atStart)
                let checkedNow = checkSharesAll width ct [| for struct (_, _, x) in misses -> x |]

                lock gate (fun () ->
                    runs <- runs + int64 misses.Count

                    for j in 0 .. misses.Count - 1 do
                        let struct (i, given, struct (m, key, _)) = misses[j]
                        results[i] <- checkedNow[j]
                        current[key] <- struct (m, given, checkedNow[j]))

            results

        /// CheckAll over an array.
        member this.CheckAll
            (items: struct (int * PubKey * (uint64 * PubKey) list)[], ct: CancellationToken)
            : Result<unit, string>[] =
            this.CheckAll(items.Length, (fun i -> items[i]), ct)

        /// CheckAll for one key.
        member this.Check(m: int, key: PubKey, shares: (uint64 * PubKey) list) : Result<unit, string> =
            (this.CheckAll(1, (fun _ -> struct (m, key, shares)), CancellationToken.None))[0]

        /// Ends a refresh: keeps the results of this round only.
        member _.Sweep() =
            lock gate (fun () ->
                swept <- true
                last <- current
                current <- Collections.Generic.Dictionary())

    let private setKey (chosen: struct (uint64 * BlsSignature)[]) =
        String.Join(',', chosen |> Array.map (fun struct (i, _) -> i))

    /// `create` with the number of rate limit keys per member given, for tests.
    let createWith
        (keysPerMember: int)
        (name: string)
        (m: int)
        (members: Member list)
        (time: TimeProvider)
        (log: Log)
        : Backend =
        let members = Array.ofList members
        let n = members.Length

        if m < 1 || m > n then
            invalidArg "m" $"threshold {m} of {n} members"

        if (members |> Array.map (fun x -> x.Index) |> Array.distinct).Length <> n then
            invalidArg "members" "member indices must differ"

        let shareKeys = ConcurrentDictionary<struct (PubKey * uint64), PubKey>()
        let verifier = BatchVerifier.Shared

        let gates =
            members |> Array.map (fun x -> MemberGate(max 1 x.Backend.Capabilities.MaxInFlight, LowEvery))
        // Per member: Ready, or the epoch from which it signs votes and blocks again after a
        // restart (its floor + 1), or NoTrustedTime when it gave no epoch. Set by its refusals
        // of votes and blocks, cleared by its next signed vote or block.
        let floors = Array.create n Ready

        let noteFloor (i: int) (req: SignRequest) (o: SignOutcome) =
            if req.Duty.IsSlashable then
                match o with
                | Refused(Refusal.NotReadyUntil e) ->
                    let v =
                        match e with
                        | ValueSome e -> e
                        | ValueNone -> NoTrustedTime

                    if Volatile.Read &floors[i] = Ready then
                        let until =
                            match e with
                            | ValueSome e -> $" until epoch {e}"
                            | ValueNone -> ""

                        log.Info $"{name}: member {members[i].Index} is in its restart floor{until}"

                    Volatile.Write(&floors[i], v)
                | Partial _
                | Signed _ when Volatile.Read &floors[i] <> Ready ->
                    log.Info $"{name}: member {members[i].Index} signs votes and blocks again"
                    Volatile.Write(&floors[i], Ready)
                | _ -> ()

        // Per-member failure lines, one table per member keyed by (duty kind, answer kind).
        let repeats =
            Array.init n (fun _ -> RepeatLimit<struct (DutyKind * string)>(memberLineWindow, keysPerMember))

        let since (t: DateTimeOffset) = t.ToString("HH:mm:ss'Z'", Globalization.CultureInfo.InvariantCulture)

        /// Logs that member i did not sign, at most once per member, duty kind and answer kind
        /// per window. `late`: the answer came after the group's result.
        let memberFailed (i: int) (req: SignRequest) (o: SignOutcome) (late: bool) =
            if log.MinLevel <= LogLevel.Warn then
                let now = time.GetUtcNow()
                let kind = outcomeKind o
                // Admit first: a repeat of this key reports its own count on its line, not in the sweep.
                let struct (write, count, last) = repeats[i].Admit(struct (req.Duty.Kind, kind), now)

                if write then
                    let after = if late then ", after the group's result" else ""
                    let more = if count > 0 then $"; {count} more {kind} answers since {since last} not logged" else ""

                    log.Warn
                        $"{name}: member {members[i].Backend.Name} did not sign the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short}, {outcomeClass o}: {outcomeReason o}{after}{more}"

                for j in 0 .. n - 1 do
                    let ended, overflow = repeats[j].Sweep now

                    for struct (struct (duty, what), k, at) in ended do
                        log.Warn
                            $"{name}: member {members[j].Backend.Name}: {k} more {what} answers on the {Metrics.dutyLabel duty} since {since at} not logged"

                    if overflow > 0 then
                        log.Warn
                            $"{name}: member {members[j].Backend.Name}: {overflow} failure lines not logged: too many distinct keys"

        // Per member and validator key: the epoch of the last floor line. Import and source
        // floors are per key, so one value per member would flip between keys. At most
        // memberFloorKeys keys per member; lines for keys past that are counted, not written.
        let floorLogged = Array.init n (fun _ -> Collections.Generic.Dictionary<PubKey, Epoch>())
        let floorOverflow = Array.zeroCreate<int> n

        /// Logs at Info that member i waits for a floor (restart, import or source) of the key
        /// until epoch `until`: expected after a restart or an import, so once per member, key
        /// and epoch. The next line written for the member counts the lines a full table dropped.
        let memberFloor (i: int) (req: SignRequest) (until: Epoch) =
            if log.MinLevel <= LogLevel.Info then
                let seen = floorLogged[i]

                let struct (write, dropped) =
                    lock seen (fun () ->
                        match seen.TryGetValue req.Key with
                        | true, e when e = until -> struct (false, 0)
                        | true, _ ->
                            seen[req.Key] <- until
                            let d = floorOverflow[i]
                            floorOverflow[i] <- 0
                            struct (true, d)
                        | _ when seen.Count >= memberFloorKeys ->
                            floorOverflow[i] <- floorOverflow[i] + 1
                            struct (false, 0)
                        | _ ->
                            seen[req.Key] <- until
                            let d = floorOverflow[i]
                            floorOverflow[i] <- 0
                            struct (true, d))

                if write then
                    let more =
                        if dropped > 0 then
                            $"; {dropped} floor lines for keys past {memberFloorKeys} not logged"
                        else
                            ""

                    log.Info
                        $"{name}: member {members[i].Backend.Name} waits for the floor of {req.Key.Short} until epoch {until}: the {Metrics.dutyLabel req.Duty.Kind} is skipped{more}"

        /// The position in `members` of the member at a share index.
        let positionOf (index: uint64) =
            let mutable j = 0

            while j < n - 1 && members[j].Index <> index do
                j <- j + 1

            j

        /// Every member by name with its answer so far, for the lines that say why the group
        /// did not sign. Members with no answer yet are pending. Called on the failure path only.
        let memberAnswers
            (partials: ResizeArray<struct (uint64 * BlsSignature)>)
            (refusals: ResizeArray<struct (int * Refusal)>)
            (failures: ResizeArray<struct (int * SignFailure)>)
            =
            let status = Array.create n "pending"

            for struct (index, _) in partials do
                status[positionOf index] <- "signed"

            for struct (j, r) in refusals do
                let o = Refused r
                status[j] <- $"{outcomeClass o} ({outcomeReason o})"

            for struct (j, f) in failures do
                let o = Failed f
                status[j] <- $"{outcomeClass o} ({outcomeReason o})"

            String.Join(", ", Array.init n (fun j -> $"{members[j].Backend.Name} {status[j]}"))

        // Lagrange coefficients depend only on the set of indices, so they are cached per set.
        let coefficients = ConcurrentDictionary<string, Bls.Lagrange>()

        let lagrangeFor (ids: uint64[]) =
            let cacheKey = String.Join(',', ids)

            match coefficients.TryGetValue cacheKey with
            | true, c -> ValueSome c
            | _ ->
                match Bls.lagrange ids with
                | ValueSome c ->
                    coefficients[cacheKey] <- c
                    ValueSome c
                | ValueNone -> ValueNone

        let duties = members |> Array.map (fun x -> x.Backend.Capabilities.Duties) |> Array.reduce Set.intersect

        let capabilities =
            {
                Duties = duties
                TypedOnly = members |> Array.exists (fun x -> x.Backend.Capabilities.TypedOnly)
                EnforcesSlashing = members |> Array.forall (fun x -> x.Backend.Capabilities.EnforcesSlashing)
                ReturnsPartials = false
                MaxInFlight = members |> Array.map (fun x -> x.Backend.Capabilities.MaxInFlight) |> Array.min
            }

        let keys (ct: CancellationToken) : Task<KeyEntry list> =
            task {
                let! lists =
                    members
                    |> Array.map (fun x ->
                        task {
                            try
                                return! x.Backend.Keys ct
                            with e ->
                                log.Warn $"{name}: member {x.Index} ({x.Backend.Name}) did not list keys: {e.Message}"
                                return []
                        })
                    |> Task.WhenAll

                let counts = Collections.Generic.Dictionary<PubKey, int>()

                for i in 0 .. n - 1 do
                    for e in lists[i] |> List.distinctBy (fun e -> e.Key) do
                        match e.Share with
                        | ValueSome(struct (_, share)) -> shareKeys[struct (e.Key, members[i].Index)] <- share
                        | ValueNone -> ()

                        counts[e.Key] <-
                            (match counts.TryGetValue e.Key with
                             | true, c -> c
                             | _ -> 0)
                            + 1

                return
                    [
                        for KeyValue(k, c) in counts do
                            if c >= m then
                                { Key = k; Share = ValueNone }
                    ]
            }

        let health (ct: CancellationToken) : Task<Health> =
            task {
                let! hs =
                    members
                    |> Array.map (fun x ->
                        task {
                            try
                                return! x.Backend.Health ct
                            with e ->
                                return Down e.Message
                        })
                    |> Task.WhenAll
                // A member not ready until an epoch is up, in its restart floor: its backend knows
                // the floor (a TEE runner from HEALTH) before the member's first refusal.
                let isUp h =
                    match h with
                    | Up
                    | Degraded _
                    | Health.NotReadyUntil _ -> true
                    | _ -> false

                let floorOf i =
                    match hs[i] with
                    | Health.NotReadyUntil e when floors[i] = Ready || floors[i] = NoTrustedTime -> e
                    | Health.NotReadyUntil e -> max e floors[i]
                    | _ -> floors[i]

                let up = hs |> Array.filter isUp |> Array.length
                // Members up but in their restart floor sign everything except votes and blocks.
                let floorsUp =
                    [
                        for i in 0 .. n - 1 do
                            if isUp hs[i] && floorOf i <> Ready then
                                floorOf i
                    ]

                let ready = up - floorsUp.Length

                return
                    if up < m then
                        Down $"{up} of {n} members up, {m} needed"
                    elif ready < m then
                        // The epoch from which enough members are out of their floor, if all floors are known.
                        let needed = m - ready
                        let sorted = List.sort floorsUp

                        if sorted[needed - 1] = NoTrustedTime then
                            Degraded $"{ready} of {n} members ready for votes and blocks, {m} needed"
                        else
                            Health.NotReadyUntil sorted[needed - 1]
                    elif ready = m && ready < n then
                        Degraded $"{ready} of {n} members ready, {m} needed"
                    else
                        Up
            }

        /// Checks one partial against its share key. Unknown share keys pass: the caller then
        /// has nothing to drop.
        let partialOk (req: SignRequest) (index: uint64) (s: BlsSignature) =
            match shareKeys.TryGetValue(struct (req.Key, index)) with
            | true, share ->
                Bls.verify (ReadOnlySpan share.Bytes) (ReadOnlySpan req.SigningRoot.Bytes) (ReadOnlySpan s.Bytes)
            | _ -> true

        /// Combines exactly the given m partials and checks the result against the validator key.
        let combine (req: SignRequest) (chosen: struct (uint64 * BlsSignature)[]) : Task<BlsSignature voption> =
            let ids = chosen |> Array.map (fun struct (i, _) -> i)

            match lagrangeFor ids with
            | ValueNone -> Task.FromResult ValueNone
            | ValueSome l ->
                match Bls.combine l (chosen |> Array.map (fun struct (_, s) -> s.Bytes)) with
                | ValueNone -> Task.FromResult ValueNone
                | ValueSome sg ->
                    task {
                        // Checked in a batch with the other combined signatures of the burst.
                        let! ok = verifier.Verify(req.Key, req.SigningRoot, sg)
                        return if ok then ValueSome(BlsSignature.Of sg) else ValueNone
                    }

        let sign (req: SignRequest) (ct: CancellationToken) : Task<SignOutcome> =
            task {
                let results =
                    Channel.CreateBounded<struct (int * SignOutcome)>(BoundedChannelOptions(n, SingleReader = true))
                // Slashable kinds, PTC votes and envelopes are never cancelled once sent: every
                // member records the message, so the members' marks stay level.
                // Other kinds stop when m are in.
                let keepStragglers = req.Duty.KeepsStragglers
                // Not disposed: member tasks may still hold registrations on it after this returns.
                let stopOthers = new CancellationTokenSource()
                let now = time.GetUtcNow()

                for i in 0 .. n - 1 do
                    let x = members[i]
                    let timeout = min x.Budget (min (req.Deadline - now) (TimeSpan.FromDays 1.0))

                    let run =
                        task {
                            let! outcome =
                                task {
                                    if timeout <= TimeSpan.Zero then
                                        return Failed SignFailure.Timeout
                                    else
                                        // The deadline is on the VC's clock; the member timer is a network
                                        // timeout, so it runs on the wall clock (also under a test clock).
                                        use own = new CancellationTokenSource(timeout)

                                        use linked =
                                            if keepStragglers then
                                                CancellationTokenSource.CreateLinkedTokenSource(own.Token)
                                            else
                                                CancellationTokenSource.CreateLinkedTokenSource(
                                                    own.Token,
                                                    stopOthers.Token,
                                                    ct
                                                )

                                        let started = Diagnostics.Stopwatch.GetTimestamp()
                                        let! entered = gates[i].Enter(req.Priority, linked.Token)

                                        if not entered || linked.IsCancellationRequested then
                                            if entered then
                                                gates[i].Leave()
                                            // Dropped from the member's queue: m were in, or no time left.
                                            return Failed SignFailure.Timeout
                                        else
                                            try
                                                let! o =
                                                    task {
                                                        try
                                                            return! x.Backend.Sign req linked.Token
                                                        with
                                                        | :? OperationCanceledException ->
                                                            return Failed SignFailure.Timeout
                                                        | e -> return Failed(Internal e.Message)
                                                    }

                                                Metrics.signed
                                                    x.Backend.Name
                                                    req.Duty.Kind
                                                    o
                                                    (Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds)

                                                return o
                                            finally
                                                gates[i].Leave()
                                }

                            noteFloor i req outcome
                            // The reader completes the channel when the result is decided, so a
                            // refused write is exactly an answer that came after the result.
                            let late = not (results.Writer.TryWrite(struct (i, outcome)))

                            match outcome with
                            | Partial _
                            | Signed _ -> ()
                            // A kind that stops its members once the result is in: a failure after the
                            // result (m were in) or after the caller gave up is most likely the stop.
                            | _ when not keepStragglers && (late || ct.IsCancellationRequested) -> ()
                            // A floor wait is expected; not ready with no epoch (no trusted time) is a failure line.
                            | Refused(Refusal.NotReadyUntil(ValueSome until)) -> memberFloor i req until
                            | _ -> memberFailed i req outcome late
                        }

                    run |> ignore

                let partials = ResizeArray<struct (uint64 * BlsSignature)>()
                // With the member's position, so the log can name it.
                let refusals = ResizeArray<struct (int * Refusal)>()
                let failures = ResizeArray<struct (int * SignFailure)>()
                let mutable received = 0
                let mutable result = ValueNone
                // Index sets combined so far, and whether one of them failed. After a failure each
                // partial is checked against its share key before it joins a set.
                let tried = Collections.Generic.HashSet<string>()
                let suspect = ref false

                let dropIfBad (struct (index, s) as p) =
                    if partialOk req index s then
                        true
                    else
                        let j = positionOf index

                        log.Warn
                            $"{name}: member {members[j].Backend.Name} (index {index}) returned a partial for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short} that does not verify against its share; dropped"

                        partials.Remove p |> ignore
                        failures.Add(struct (j, Internal $"member {index}: bad partial"))
                        false

                /// Combines untried m-subsets of the partials until one verifies, at most
                /// maxAttempts sets per request. The first failure checks every partial against
                /// its share key. A set can still fail with only good partials when a member's
                /// configured index is not its share's x coordinate; another set then finds m good ones.
                let tryCombine () : Task<BlsSignature voption> =
                    task {
                        let mutable found = ValueNone
                        let mutable again = true

                        while found.IsNone && again && tried.Count < maxAttempts do
                            again <- false
                            let sorted = partials |> Seq.sortBy (fun struct (i, _) -> i) |> Array.ofSeq

                            match
                                subsets sorted.Length m
                                |> Seq.map (Array.map (fun j -> sorted[j]))
                                |> Seq.tryFind (fun s -> not (tried.Contains(setKey s)))
                            with
                            | None -> ()
                            | Some chosen ->
                                tried.Add(setKey chosen) |> ignore

                                match! combine req chosen with
                                | ValueSome sg -> found <- ValueSome sg
                                | ValueNone ->
                                    if not suspect.Value then
                                        suspect.Value <- true

                                        for p in partials.ToArray() do
                                            dropIfBad p |> ignore

                                    again <- true

                        return found
                    }

                while result.IsNone && received < n do
                    let! struct (i, outcome) =
                        task {
                            try
                                return! results.Reader.ReadAsync(ct)
                            with :? OperationCanceledException ->
                                return struct (-1, Failed SignFailure.Timeout)
                        }

                    if i < 0 then
                        result <- ValueSome(Failed SignFailure.Timeout)
                    else
                        received <- received + 1
                        let x = members[i]

                        let added =
                            match outcome with
                            | Partial(index, s) ->
                                if index <> x.Index then
                                    log.Warn
                                        $"{name}: member {x.Index} returned a partial for index {index}; using {x.Index}"

                                partials.Add(struct (x.Index, s))
                                true
                            | Signed s ->
                                partials.Add(struct (x.Index, s))
                                true
                            // A member's text goes into the group's answer, which callers log.
                            | Refused r ->
                                refusals.Add(struct (i, cleanRefusal r))
                                false
                            | Failed f ->
                                failures.Add(struct (i, cleanFailure f))
                                false

                        let keep = not added || not suspect.Value || dropIfBad partials[partials.Count - 1]

                        if keep && partials.Count >= m then
                            match! tryCombine () with
                            | ValueSome sg -> result <- ValueSome(Signed sg)
                            | ValueNone -> ()
                        // Give up only when the members still out cannot bring m signatures.
                        if result.IsNone && received = n && partials.Count >= m then
                            results.Writer.TryComplete() |> ignore

                            log.Warn
                                $"{name}: no {m} of the {partials.Count} partials for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short} combine to the key; check the member indices; {memberAnswers partials refusals failures}"

                            result <-
                                ValueSome(
                                    Failed(Internal $"no {m} of {partials.Count} partials combine to the validator key")
                                )
                        elif result.IsNone && partials.Count + (n - received) < m then
                            // Closed, then drained, before the line is built: an answer written before
                            // the close is counted and named; a member still pending answers late. The
                            // drained answers cannot bring m: they were among the members still out.
                            results.Writer.TryComplete() |> ignore
                            let mutable buffered = Unchecked.defaultof<struct (int * SignOutcome)>
                            // Drained refusals join the denials below on purpose: a slashable refusal from
                            // any member wins, also one read only here. Drained
                            // partials count in the tally and the line; they are never combined.
                            while results.Reader.TryRead(&buffered) do
                                let struct (j, o) = buffered
                                received <- received + 1

                                match o with
                                | Partial(_, s)
                                | Signed s -> partials.Add(struct (members[j].Index, s))
                                | Refused r -> refusals.Add(struct (j, cleanRefusal r))
                                | Failed f -> failures.Add(struct (j, cleanFailure f))

                            let denials, others = [ for struct (_, r) in refusals -> r ] |> List.partition isDenial

                            let tally =
                                {
                                    Signed = partials.Count
                                    Denied = denials.Length
                                    Failed =
                                        others.Length
                                        + (failures |> Seq.filter (fun struct (_, f) -> f.IsInternal) |> Seq.length)
                                    Errored =
                                        failures |> Seq.filter (fun struct (_, f) -> not f.IsInternal) |> Seq.length
                                }

                            log.Warn
                                $"{name}: not enough signatures for the {Metrics.dutyLabel req.Duty.Kind} of {req.Key.Short}, {m} needed: {tally.Describe}; {memberAnswers partials refusals failures}"

                            result <-
                                ValueSome(
                                    // A member's slashing refusal halts; members that lost to an HA peer
                                    // (and none slashable) make the group lost too.
                                    match
                                        denials |> List.tryFind (fun r -> r.IsSlashable),
                                        denials |> List.tryFind (fun r -> r.IsLostToPeer),
                                        denials,
                                        others
                                    with
                                    | Some slashable, _, _, _ -> Refused slashable
                                    | None, Some lost, _, _ -> Refused lost
                                    // Only policy refusals (a rejected client certificate, a 401
                                    // or 403, a rate limit): they can pass, as they do for a single
                                    // signer, so the group answers as a single signer would.
                                    | None, None, _ :: _, _ when
                                        denials
                                        |> List.forall (function
                                            | PolicyDenied _ -> true
                                            | _ -> false)
                                        ->
                                        Refused(
                                            PolicyDenied
                                                $"{name}: {m} of {n} signatures needed ({tally.Describe}); {(mergeRefusals denials).Describe}"
                                        )
                                    | None, None, _ :: _, _ ->
                                        Refused(Denied($"{name}: {m} of {n} signatures needed", tally))
                                    | None, None, [], _ :: _ -> Refused(mergeRefusals others)
                                    | None, None, [], [] -> Failed(mergeFailures [ for struct (_, f) in failures -> f ])
                                )
                // Answers from now on are late; members that keep no stragglers are stopped.
                results.Writer.TryComplete() |> ignore

                if not keepStragglers then
                    stopOthers.Cancel()

                return
                    match result with
                    | ValueSome r -> r
                    | ValueNone -> Failed(mergeFailures [ for struct (_, f) in failures -> f ])
            }

        let backend =
            {
                Name = name
                Capabilities = capabilities
                Keys = keys
                Health = health
                Sign = sign
                Dispose = fun () -> ValueTask.CompletedTask
            }

        groups.AddOrUpdate(backend, name)
        backend

    /// A backend that signs with m of the members. Members answer with Partial (or Signed, read
    /// as the member's share); their share keys, from their key lists, find a bad partial.
    let create (name: string) (m: int) (members: Member list) (time: TimeProvider) (log: Log) : Backend =
        createWith memberLineKeys name m members time log
