/// A pool of checked connections to one runner. The pool keeps all its connections dialed and
/// attested from the start ("warm"), so a request never waits for a dial it caused.
/// A lost connection is dialed again in the background; dials that fail in a row back off
/// (1 s, doubling to 16 s). A connection lost within 5 s of its dial, before it served a request,
/// counts as a failed dial. Each connection carries one request at a time.
///
/// Two queues, each first come first served. A connection that comes free goes to the oldest
/// high request first (attestations, blocks, RANDAO; Gloas PTC votes and envelopes when they
/// exist), so they wait at most for the requests already on a connection. Low requests (sync
/// committee and aggregation work, exits, HEALTH) do not starve: while any waits, at least
/// every lowEvery-th connection that comes free goes to the oldest of them. lowEvery 0 keeps one
/// queue.
namespace Eplix.Backend.Tee

open System
open System.Collections.Generic
open System.IO
open System.Threading
open System.Threading.Tasks
open Eplix

[<RequireQualifiedAccess>]
type PoolClass =
    | High
    | Low

type ConnectionPool<'C when 'C :> PoolConn and 'C: not struct>
    (
        name: string,
        size: int,
        lowEvery: int,
        dialTimeout: TimeSpan,
        dial: CancellationToken -> Task<'C>,
        log: Log,
        ?time: TimeProvider
    ) =
    do
        if size < 1 then
            invalidArg "size" "at least one connection"

        if lowEvery < 0 || lowEvery = 1 then
            invalidArg "lowEvery" "0 (no priority) or at least 2"
    // The backoff, the young window and the rotation spacing run on monotonic timestamps of
    // this clock, so a step of the system clock does not stretch them.
    let time = defaultArg time TimeProvider.System
    let gate = obj ()
    let up = HashSet<'C>(HashIdentity.Reference)
    let free = Stack<'C>()
    let high = LinkedList<TaskCompletionSource<Choice<'C, string>>>()
    let low = LinkedList<TaskCompletionSource<Choice<'C, string>>>()
    let mutable highRun = 0
    let mutable dialing = 0
    let mutable failed = 0
    let mutable lastError = ""
    /// No dial before this timestamp (time.GetTimestamp).
    let mutable notBefore = Int64.MinValue
    let mutable kick: ITimer | null = null
    let mutable closed = false
    let stop = new CancellationTokenSource()
    // Rotation after a client certificate swap: connections to close when they come back, which ones are
    // stale, the deadline, and whether the rotation task runs.
    let retiring = HashSet<'C>(HashIdentity.Reference)
    let mutable stale: 'C -> bool = fun _ -> false
    /// The rotation deadline as a timestamp.
    let mutable rotateBy = Int64.MinValue
    let mutable rotating = false
    let connected = Event<unit>()
    let firstUp = Event<unit>()
    // Connections dialed less than `settle` ago that have not served a request yet, with the
    // timestamp of their dial.
    let young = Dictionary<obj, int64>(HashIdentity.Reference)
    let youngKey (c: 'C) : obj = nonNull (box c)
    let ticksOf (d: TimeSpan) = int64 (d.TotalSeconds * float time.TimestampFrequency)

    /// The time from now to timestamp `ts`, zero when it has passed.
    let until (ts: int64) =
        let now = time.GetTimestamp()
        if ts <= now then TimeSpan.Zero else time.GetElapsedTime(now, ts)

    static let backoff (n: int) =
        let mutable d = TimeSpan.FromSeconds 1.0

        for _ in 2..n do
            if d < TimeSpan.FromSeconds 16.0 then
                d <- d * 2.0

        min d (TimeSpan.FromSeconds 16.0)

    // A connection that is lost within this time of its dial, before it served a request, counts
    // as a failed dial. A runner that accepts TLS and attestation and then drops the connection
    // would otherwise be redialed at once, in a loop as fast as the handshake (and each dial
    // reads HEALTH). 5 s is far above a handshake and the time to the first request on a warm
    // pool, and far below the life of a good connection.
    static let settle = TimeSpan.FromSeconds 5.0

    /// Under the gate: a dial went well, or a connection proved it works. Resets the backoff.
    let settled () =
        failed <- 0
        lastError <- ""
        notBefore <- Int64.MinValue

    /// Under the gate: a dial failed. Counts it and sets the backoff. At most one failure counts
    /// per backoff window: n connections that one runner restart breaks at once raise the
    /// backoff one step, not n.
    let dialFailed (err: string) =
        lastError <- err
        let now = time.GetTimestamp()

        if now >= notBefore then
            failed <- failed + 1
            notBefore <- now + ticksOf (backoff failed)

    /// Under the gate: `c` left the pool broken. Young: a failed dial. Older and not seen to
    /// work yet: it has now, so the backoff resets.
    let lost (c: 'C) =
        match young.TryGetValue(youngKey c) with
        | true, t ->
            young.Remove(youngKey c) |> ignore

            if time.GetElapsedTime t < settle then
                dialFailed "the runner closed the connection right after the dial"
            else
                settled ()
        | _ -> ()

    /// Under the gate: `c` served a request and came back ready.
    let served (c: 'C) =
        if young.Remove(youngKey c) then
            settled ()

    /// The waiter that gets the next free connection. Called under the gate.
    let next () : TaskCompletionSource<Choice<'C, string>> voption =
        let pop (q: LinkedList<_>) =
            match q.First with
            | null -> ValueNone
            | first ->
                q.RemoveFirst()
                ValueSome first.Value

        if high.Count = 0 && low.Count = 0 then
            ValueNone
        elif low.Count > 0 && (high.Count = 0 || highRun >= lowEvery - 1) then
            highRun <- 0
            pop low
        else
            if low.Count > 0 then highRun <- highRun + 1 else highRun <- 0
            pop high

    /// Gives an idle connection to the next waiter, or puts it on the idle stack. Under the gate.
    /// A connection that is not ready leaves the pool instead: false, and the caller calls
    /// maintain and closes it.
    let give (c: 'C) =
        if c.State <> ConnState.Ready then
            up.Remove c |> ignore
            retiring.Remove c |> ignore
            false
        else
            let mutable given = false

            while not given do
                match next () with
                | ValueNone ->
                    free.Push c
                    given <- true
                | ValueSome w -> given <- w.TrySetResult(Choice1Of2 c)

            true

    /// Under the gate: takes `c` off the idle stack. False when it is not there.
    let removeFree (c: 'C) =
        let all = free.ToArray()

        if not (all |> Array.exists (fun x -> obj.ReferenceEquals(x, c))) then
            false
        else
            free.Clear()
            // ToArray lists the top first; push back in reverse to keep the order.
            for i in all.Length - 1 .. -1 .. 0 do
                if not (obj.ReferenceEquals(all[i], c)) then
                    free.Push all[i]

            true

    /// Under the gate: when no connection is up or dialing, moves every waiting request to
    /// `into`, to be failed after the gate: nothing else can serve them.
    let failAllIfNoneLeft (into: ResizeArray<TaskCompletionSource<Choice<'C, string>>>) =
        if up.Count = 0 && dialing = 0 then
            into.AddRange high
            into.AddRange low
            high.Clear()
            low.Clear()

    let rec maintain () =
        // Called under the gate: dial until size connections are up or dialing.
        while not closed && up.Count + dialing < size && time.GetTimestamp() >= notBefore do
            dialing <- dialing + 1
            Task.Run(fun () -> dialOne ()) |> ignore

        if not closed && up.Count + dialing < size && isNull kick then
            let wait = until notBefore
            // The callback leaves the timer's thread first: a test clock can fire it inside
            // CreateTimer, before kick holds the timer.
            kick <-
                time.CreateTimer(
                    (fun _ ->
                        Task.Run(fun () ->
                            lock gate (fun () ->
                                match kick with
                                | null -> ()
                                | k -> k.Dispose()

                                kick <- null
                                maintain ()))
                        |> ignore),
                    null,
                    wait,
                    Timeout.InfiniteTimeSpan
                )

    and dialOne () : Task =
        task {
            let sw = Diagnostics.Stopwatch.StartNew()

            let! result =
                task {
                    try
                        use cts = CancellationTokenSource.CreateLinkedTokenSource stop.Token
                        cts.CancelAfter dialTimeout
                        let! c = dial cts.Token
                        return Choice1Of2 c
                    with e ->
                        return Choice2Of2 e.Message
                }

            let failedWaiters = ResizeArray<TaskCompletionSource<Choice<'C, string>>>()

            let closeIt =
                lock gate (fun () ->
                    dialing <- dialing - 1

                    match result with
                    | Choice1Of2 c when closed -> ValueSome c
                    | Choice1Of2 c ->
                        // The backoff resets only once the connection proves itself (lost, served).
                        lastError <- ""
                        let wasEmpty = up.Count = 0
                        up.Add c |> ignore
                        young[youngKey c] <- time.GetTimestamp()

                        // The first connection after none was up: told before any waiter gets it.
                        if wasEmpty then
                            try
                                firstUp.Trigger()
                            with e ->
                                log.Warn $"{name}: a first-connection handler failed: {e.Message}"

                        if give c then
                            ValueNone
                        else
                            // Broken already at the handover: a failed dial.
                            young.Remove(youngKey c) |> ignore
                            dialFailed "the runner closed the connection right after the dial"
                            failAllIfNoneLeft failedWaiters
                            maintain ()
                            ValueSome c
                    | Choice2Of2 err ->
                        dialFailed err
                        failAllIfNoneLeft failedWaiters
                        maintain ()
                        ValueNone)

            let failWith err =
                for w in failedWaiters do
                    w.TrySetResult(Choice2Of2 err) |> ignore

            match result, closeIt with
            | Choice1Of2 _, ValueSome c ->
                c.Close()

                if not closed then
                    let err = "the runner closed the connection right after the dial"
                    log.Warn $"{name}: {err}"
                    failWith err
            | Choice1Of2 c, ValueNone ->
                watchBreak c
                log.Debug $"{name}: connection up in {sw.ElapsedMilliseconds} ms"

                if not closed then
                    try
                        connected.Trigger()
                    with e ->
                        log.Warn $"{name}: a new-connection handler failed: {e.Message}"
            | Choice2Of2 err, _ ->
                log.Warn $"{name}: dial failed after {sw.ElapsedMilliseconds} ms: {err}"
                failWith err
        }

    /// Asks a connection that can tell (BreakNotice) to report its break. A connection that
    /// breaks while idle then leaves the idle stack and is dialed again (after the backoff when it
    /// broke right after its dial), so HEALTH and the next requests do not count on it.
    and watchBreak (c: 'C) =
        match box c with
        | :? BreakNotice as n -> n.OnBroken(fun () -> dropIdle c)
        | _ -> ()

    /// Drops a connection that broke while idle. One that broke during a request goes through
    /// Done instead.
    and dropIdle (c: 'C) =
        let dropped =
            lock gate (fun () ->
                if closed || not (removeFree c) then
                    false
                else
                    up.Remove c |> ignore
                    retiring.Remove c |> ignore
                    lost c
                    maintain ()
                    true)

        if dropped then
            c.Close()
            log.Warn $"{name}: idle connection broke; dialing again"

    let lose (c: 'C) (why: string) =
        c.Close()

        lock gate (fun () ->
            up.Remove c |> ignore
            retiring.Remove c |> ignore
            lost c
            maintain ())

        if not closed then
            log.Warn $"{name}: connection closed: {why}"

    let put (c: 'C) =
        let closeIt =
            lock gate (fun () ->
                if closed then
                    true
                elif retiring.Remove c then
                    // Replaced by a connection with the new certificate while it served a request.
                    up.Remove c |> ignore
                    served c
                    maintain ()
                    true
                elif
                    c.State = ConnState.Ready
                    && (served c
                        give c)
                then
                    false
                else
                    // It broke after Done saw it ready: out of `up`, or the pool counts it forever.
                    up.Remove c |> ignore
                    retiring.Remove c |> ignore
                    lost c
                    maintain ()
                    true)

        if closeIt then
            c.Close()

    /// Under the gate: the stale connections not yet replaced.
    let staleLeft () =
        let mutable n = 0

        for c in up do
            if stale c && not (retiring.Contains c) then
                n <- n + 1

        n

    /// Under the gate: takes one stale connection out of service, an idle one first (closed by
    /// the caller), else a busy one (closed when it comes back).
    let retireOne () : 'C voption =
        let idle = free.ToArray() |> Array.tryFind stale

        match idle with
        | Some c ->
            let rest = free.ToArray() |> Array.filter (fun x -> not (obj.ReferenceEquals(x, c)))
            free.Clear()
            // ToArray lists the top first; push back in reverse to keep the order.
            for i in rest.Length - 1 .. -1 .. 0 do
                free.Push rest[i]

            up.Remove c |> ignore
            young.Remove(youngKey c) |> ignore
            ValueSome c
        | None ->
            match up |> Seq.tryFind (fun c -> stale c && not (retiring.Contains c)) with
            | Some c -> retiring.Add c |> ignore
            | None -> ()

            ValueNone

    /// Replaces the stale connections one at a time: a new connection is dialed and put in
    /// service before a stale one leaves, so the pool never runs short and no request waits for
    /// a dial. The redials are spread over the time to the deadline.
    let rotateLoop () : Task =
        task {
            let mutable go = true
            let mutable failedRow = 0
            let mutable replaced = 0

            while go do
                let struct (left, deadline) =
                    lock gate (fun () ->
                        let n = if closed then 0 else staleLeft ()

                        if n = 0 then
                            rotating <- false

                        struct (n, rotateBy))

                if left = 0 then
                    go <- false

                    if replaced > 0 then
                        log.Info $"{name}: {replaced} connections redialed with the new client certificate"
                else
                    let sw = Diagnostics.Stopwatch.StartNew()

                    let! result =
                        task {
                            try
                                use cts = CancellationTokenSource.CreateLinkedTokenSource stop.Token
                                cts.CancelAfter dialTimeout
                                let! c = dial cts.Token
                                return Choice1Of2 c
                            with e ->
                                return Choice2Of2 e.Message
                        }

                    match result with
                    | Choice1Of2 c ->
                        failedRow <- 0
                        replaced <- replaced + 1

                        let struct (toClose, fresh) =
                            lock gate (fun () ->
                                if closed then
                                    struct (ValueSome c, ValueNone)
                                else
                                    let old = retireOne ()
                                    up.Add c |> ignore
                                    young[youngKey c] <- time.GetTimestamp()

                                    if give c then
                                        struct (old, ValueNone)
                                    else
                                        young.Remove(youngKey c) |> ignore
                                        dialFailed "the runner closed the connection right after the dial"
                                        maintain ()
                                        struct (old, ValueSome c))

                        match toClose with
                        | ValueSome x -> x.Close()
                        | ValueNone -> ()

                        match fresh with
                        | ValueSome x -> x.Close()
                        | ValueNone ->
                            if not closed then
                                watchBreak c

                        log.Debug
                            $"{name}: redialed one connection with the new client certificate in {sw.ElapsedMilliseconds} ms"
                        // Spread the rest over the time left: n left get n + 1 gaps.
                        let rest = lock gate (fun () -> staleLeft ())
                        let gap = until deadline / float (rest + 1)

                        if rest > 0 && gap > TimeSpan.Zero then
                            try
                                do! Task.Delay(gap, time, stop.Token)
                            with :? OperationCanceledException ->
                                go <- false
                    | Choice2Of2 err ->
                        failedRow <- failedRow + 1
                        let wait = backoff failedRow

                        log.Warn
                            $"{name}: redial with the new client certificate failed, again in {wait.TotalSeconds:F0} s: {err}"

                        try
                            do! Task.Delay(wait, time, stop.Token)
                        with :? OperationCanceledException ->
                            go <- false
        }

    member _.Name = name
    member _.Size = size

    /// Connections up, idle, dialing; requests waiting high and low.
    member _.Snapshot = lock gate (fun () -> struct (up.Count, free.Count, dialing, high.Count, low.Count))

    member _.LastError = lock gate (fun () -> lastError)

    /// Fires after each dial that brought a connection up (the TEE endpoint reads HEALTH then).
    member _.Connected = connected.Publish

    /// Fires under the pool's lock when a dial brings a connection up while none was up, before
    /// a waiting request gets it. A handler must be quick and must not call the pool.
    member _.FirstUp = firstUp.Publish

    /// Dials every connection in the background.
    member _.Start() = lock gate (fun () -> maintain ())

    /// Redials the connections for which `isStale` holds, one at a time in the background, by
    /// `deadline`. A later call replaces the test and the deadline of one
    /// still running. A redial that fails is tried again with the dial backoff; the stale
    /// connections serve until they are replaced.
    member _.Rotate(isStale: 'C -> bool, deadline: DateTimeOffset) =
        let start =
            lock gate (fun () ->
                stale <- isStale
                rotateBy <- time.GetTimestamp() + ticksOf (max TimeSpan.Zero (deadline - time.GetUtcNow()))

                if rotating || closed then
                    false
                else
                    rotating <- true
                    true)

        if start then
            Task.Run(fun () -> rotateLoop ()) |> ignore

    /// Connections that serve while a newer one replaces them (for tests and the status line).
    member _.Retiring = lock gate (fun () -> retiring.Count)

    /// Waits for an idle connection. A request whose token ends while it waits is never sent.
    member _.Take(cls: PoolClass, ct: CancellationToken) : Task<Result<'C, string>> =
        task {
            let tcs = TaskCompletionSource<Choice<'C, string>>(TaskCreationOptions.RunContinuationsAsynchronously)
            // Idle connections that broke and were not dropped yet: out of the pool, closed below.
            let dead = ResizeArray<'C>()

            let immediate =
                lock gate (fun () ->
                    let mutable ready = ValueNone

                    while not closed && ready.IsNone && free.Count > 0 do
                        let c = free.Pop()

                        if c.State = ConnState.Ready then
                            ready <- ValueSome c
                        else
                            up.Remove c |> ignore
                            retiring.Remove c |> ignore
                            lost c
                            dead.Add c

                    if dead.Count > 0 then
                        maintain ()

                    if closed then
                        ValueSome(Error "pool closed")
                    else
                        match ready with
                        | ValueSome c -> ValueSome(Ok c)
                        | ValueNone ->
                            let q = if lowEvery = 0 || cls = PoolClass.High then high else low
                            q.AddLast tcs |> ignore
                            maintain ()
                            ValueNone)

            for c in dead do
                c.Close()

            if dead.Count > 0 then
                log.Warn $"{name}: {dead.Count} idle connections broke; dialing again"

            match immediate with
            | ValueSome r -> return r
            | ValueNone ->
                use _ =
                    ct.Register(fun () ->
                        let removed = lock gate (fun () -> high.Remove tcs || low.Remove tcs)

                        if removed then
                            tcs.TrySetCanceled ct |> ignore)

                try
                    match! tcs.Task with
                    | Choice1Of2 c -> return Ok c
                    | Choice2Of2 err -> return Error err
                with :? OperationCanceledException ->
                    let why =
                        lock gate (fun () ->
                            if up.Count = 0 then
                                " (no connection up, "
                                + string dialing
                                + " dialing"
                                + (if lastError = "" then "" else "; last dial: " + lastError)
                                + ")"
                            else
                                "")

                    return Error $"timed out waiting for a runner connection{why}"
        }

    /// Takes a connection back after a request: to the next request, to the read of its late
    /// reply (at most dialTimeout), or closed.
    member _.Done(c: 'C) =
        match c.State with
        | ConnState.Ready -> put c
        | ConnState.Broken -> lose c "error"
        | ConnState.Late ->
            task {
                let drained = c.Drained
                let! first = Task.WhenAny(drained :> Task, Task.Delay(dialTimeout, stop.Token))
                let ok = obj.ReferenceEquals(first, drained) && drained.Result
                if ok && c.State = ConnState.Ready then put c else lose c "no late reply within the cap"
            }
            |> ignore

    member _.Close() =
        let toClose, waiters =
            lock gate (fun () ->
                closed <- true

                match kick with
                | null -> ()
                | k ->
                    k.Dispose()
                    kick <- null

                let w = List.ofSeq high @ List.ofSeq low
                high.Clear()
                low.Clear()
                free.Clear()
                retiring.Clear()
                let cs = List.ofSeq up
                up.Clear()
                young.Clear()
                cs, w)

        stop.Cancel()

        for w in waiters do
            w.TrySetResult(Choice2Of2 "pool closed") |> ignore

        for c in toClose do
            c.Close()
