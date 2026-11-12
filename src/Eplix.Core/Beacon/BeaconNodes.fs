/// Several beacon nodes at once. The rules follow Vero
/// (serenita-org/vero at b89214b, src/providers/multi_beacon_node.py and
/// attestation_data_provider.py; see docs/design.md):
/// - attestation data needs `threshold` nodes to agree, so one bad or lagging node cannot make
///   the validators vote for its view; Gloas PTC data needs `ptcThreshold` nodes (default 1);
/// - duties and other single answers come from the best-scored node, with fallback in score order;
/// - blocks are asked from every node and the highest value wins after a soft timeout;
/// - aggregates and contributions are asked from every node and the one with most bits wins;
/// - everything the VC publishes goes to every node and succeeds when one node accepts it.
/// Scores run from 0 to 100: 100 once a node passed the start checks, +1 per good answer,
/// -5 per failed request. Ties go to the order in the config.
/// With `requireReady` (the VC sets it) a node gets no call for any role until it passed the start
/// checks, and none again once a later check drops it.
/// One node is the case threshold = 1 and takes the same paths with no polling.
/// Each node has roles (NodeRole, data and publish per duty family, as Nimbus splits them); every rule above applies to the nodes that hold
/// the role of the call. Default: every node holds every role.
namespace Eplix.Beacon

open System
open System.Collections.Generic
open System.Numerics
open System.Runtime.ExceptionServices
open System.Runtime.InteropServices
open System.Threading
open System.Threading.Tasks
open Eplix

/// What a node's /eth/v1/node/syncing last reported, best first. Nodes are ranked by health
/// before score (Lighthouse's order: synced, EL offline, optimistic, syncing).
[<RequireQualifiedAccess>]
type NodeHealth =
    | Synced
    | ElOffline
    | Optimistic
    | Syncing

    member this.Rank =
        match this with
        | Synced -> 0
        | ElOffline -> 1
        | Optimistic -> 2
        | Syncing -> 3

    member this.Describe =
        match this with
        | Synced -> "synced"
        | ElOffline -> "its execution client is offline"
        | Optimistic -> "optimistic (its head is not verified by an execution client)"
        | Syncing -> "syncing"

/// What a node is used for. A node without a role is never called for it.
/// A call that names several roles goes to the nodes that hold any of them.
[<Flags>]
type NodeRole =
    | None = 0
    /// Duty lists, validator states (key refresh, slashed check), liveness, monitor reads.
    | Duties = 1
    /// Attestation data and Gloas PTC data, with their consensus thresholds.
    | AttestationData = 2
    /// Attestations and PTC votes.
    | AttestationPublish = 4
    /// Aggregates to sign, and the Obol attester selections.
    | AggregateData = 8
    /// Signed aggregates.
    | AggregatePublish = 16
    /// The block root of sync messages, contributions to sign, the Obol sync selections.
    | SyncData = 32
    /// Sync committee messages and contributions.
    | SyncPublish = 64
    /// Block production, the envelope of a stateful Gloas block, prepare_beacon_proposer.
    | BlockData = 128
    /// Blocks, envelopes, Gloas proposer and builder preferences.
    | BlockPublish = 256
    | All = 511

module NodeRole =
    /// The single roles, with their config names, in bit order.
    let names =
        [
            NodeRole.Duties, "duties"
            NodeRole.AttestationData, "attestation_data"
            NodeRole.AttestationPublish, "attestation_publish"
            NodeRole.AggregateData, "aggregate_data"
            NodeRole.AggregatePublish, "aggregate_publish"
            NodeRole.SyncData, "sync_data"
            NodeRole.SyncPublish, "sync_publish"
            NodeRole.BlockData, "block_data"
            NodeRole.BlockPublish, "block_publish"
        ]

    /// Names that stand for several roles.
    let groups =
        [
            "attestation", NodeRole.AttestationData ||| NodeRole.AttestationPublish
            "aggregate", NodeRole.AggregateData ||| NodeRole.AggregatePublish
            "sync", NodeRole.SyncData ||| NodeRole.SyncPublish
            "block", NodeRole.BlockData ||| NodeRole.BlockPublish
            "publish",
            NodeRole.AttestationPublish
            ||| NodeRole.AggregatePublish
            ||| NodeRole.SyncPublish
            ||| NodeRole.BlockPublish
            "all", NodeRole.All
        ]

    /// The roles of one config name.
    let parse (name: string) : NodeRole voption =
        match names |> List.tryFind (fun (_, n) -> n = name) with
        | Some(r, _) -> ValueSome r
        | None ->
            match groups |> List.tryFind (fun (n, _) -> n = name) with
            | Some(_, r) -> ValueSome r
            | None -> ValueNone

    /// Beacon committee subscriptions: the nodes that publish attestations (they join the
    /// subnets) and those that give aggregates (they collect the subnet's attestations).
    let subscriptions = NodeRole.AttestationPublish ||| NodeRole.AggregateData

    /// Sync committee subscriptions: the nodes that give sync data or publish sync messages.
    let syncSubscriptions = NodeRole.SyncData ||| NodeRole.SyncPublish

    /// Event streams: the nodes that give data (head events time attestations and sync messages,
    /// Gloas events time PTC votes, slashing events start the slashed check). Nodes that only
    /// produce or publish blocks get no stream.
    let events =
        NodeRole.Duties ||| NodeRole.AttestationData ||| NodeRole.AggregateData ||| NodeRole.SyncData

    /// The config names of the single roles in `r`, comma-separated ("all" for every role).
    let describe (r: NodeRole) =
        if r = NodeRole.All then
            "all"
        else
            names |> List.filter (fun (x, _) -> r &&& x = x) |> List.map snd |> String.concat ", "

    /// Checks one role list per node: every role held by at least one node, and the consensus
    /// thresholds no higher than the nodes that hold attestation data.
    let check (roles: NodeRole list) (threshold: int) (ptcThreshold: int) : Result<unit, string list> =
        let missing =
            [
                for r, name in names do
                    if roles |> List.forall (fun x -> x &&& r = NodeRole.None) then
                        $"no beacon node has the role {name}"
            ]

        let data =
            roles |> List.filter (fun x -> x &&& NodeRole.AttestationData <> NodeRole.None) |> List.length

        let errors =
            [
                yield! missing
                if data > 0 && threshold > data then
                    $"attestation_consensus_threshold {threshold} is above the {data} beacon nodes with the role attestation_data"
                if data > 0 && ptcThreshold > data then
                    $"ptc_consensus_threshold {ptcThreshold} is above the {data} beacon nodes with the role attestation_data"
            ]

        if errors.IsEmpty then Ok() else Error errors

/// What the VC publishes, for the `broadcast` setting. A topic in the setting
/// goes to every node with the call's role at once; a topic out of it goes to the best node,
/// then to the next on failure.
[<Flags>]
type BroadcastTopic =
    | None = 0
    /// Attestations and PTC votes.
    | Attestations = 1
    | Aggregates = 2
    /// Sync committee messages and contributions.
    | SyncCommittee = 4
    /// Blocks and envelopes.
    | Blocks = 8
    /// Beacon committee and sync committee subscriptions.
    | Subscriptions = 16
    /// prepare_beacon_proposer, Gloas proposer and builder preferences.
    | Preparations = 32
    | Exits = 64
    | All = 127

module BroadcastTopic =
    let names =
        [
            BroadcastTopic.Attestations, "attestations"
            BroadcastTopic.Aggregates, "aggregates"
            BroadcastTopic.SyncCommittee, "sync_committee"
            BroadcastTopic.Blocks, "blocks"
            BroadcastTopic.Subscriptions, "subscriptions"
            BroadcastTopic.Preparations, "preparations"
            BroadcastTopic.Exits, "exits"
        ]

    /// What `broadcast: false` keeps sending to every node: Lighthouse's default without
    /// `--broadcast`, its `subscriptions` topic, which also carries prepare_beacon_proposer.
    let lighthouseDefault = BroadcastTopic.Subscriptions ||| BroadcastTopic.Preparations

    /// One topic name, or "all" or "none".
    let parse (name: string) : BroadcastTopic voption =
        match name with
        | "all" -> ValueSome BroadcastTopic.All
        | "none" -> ValueSome BroadcastTopic.None
        | _ ->
            match names |> List.tryFind (fun (_, n) -> n = name) with
            | Some(t, _) -> ValueSome t
            | None -> ValueNone

    /// The topic as a metrics label: its name, "all", or "mixed" for another set of topics.
    /// Literals only, so a send allocates no label.
    let label (t: BroadcastTopic) =
        match t with
        | BroadcastTopic.Attestations -> "attestations"
        | BroadcastTopic.Aggregates -> "aggregates"
        | BroadcastTopic.SyncCommittee -> "sync_committee"
        | BroadcastTopic.Blocks -> "blocks"
        | BroadcastTopic.Subscriptions -> "subscriptions"
        | BroadcastTopic.Preparations -> "preparations"
        | BroadcastTopic.Exits -> "exits"
        | BroadcastTopic.All -> "all"
        | _ -> "mixed"

    let describe (t: BroadcastTopic) =
        if t = BroadcastTopic.All then "all"
        elif t = BroadcastTopic.None then "none"
        else names |> List.filter (fun (x, _) -> t &&& x = x) |> List.map snd |> String.concat ", "

type BeaconNode =
    {
        Client: BeaconClient
        Name: string
        Order: int
        Roles: NodeRole
        mutable Score: int
        mutable Ready: bool
        /// A check failed (another chain): the node gets no call until the VC restarts.
        mutable Dropped: bool
        /// Synced until a syncing check says otherwise.
        mutable Health: NodeHealth
        /// Cancelled when the node is dropped: ends its open event stream.
        Stop: CancellationTokenSource
        /// Broadcast sends to this node still running, also after their broadcast returned.
        mutable Background: int
    }

/// `roles`: one entry per client, in the same order; default every role for every node.
/// `broadcast`: the topics sent to every node at once (default all).
/// `requireReady`: a node is used only after MarkReady (default false: every node from the start).
type BeaconNodes
    (
        clients: BeaconClient list,
        threshold: int,
        time: TimeProvider,
        log: Log,
        ?ptcThreshold: int,
        ?roles: NodeRole list,
        ?broadcast: BroadcastTopic,
        ?requireReady: bool
    ) =
    let broadcast = defaultArg broadcast BroadcastTopic.All
    let requireReady = defaultArg requireReady false
    let ptcThreshold = defaultArg ptcThreshold 1
    let roles = defaultArg roles (clients |> List.map (fun _ -> NodeRole.All))

    do
        if clients.IsEmpty then
            invalidArg "clients" "at least one beacon node"

        if roles.Length <> clients.Length then
            invalidArg "roles" "one role set per beacon node"

        let dataNodes =
            roles |> List.filter (fun r -> r &&& NodeRole.AttestationData <> NodeRole.None) |> List.length

        if threshold < 1 || threshold > dataNodes then
            invalidArg "threshold" $"must be between 1 and {dataNodes}"

        if ptcThreshold < 1 || ptcThreshold > dataNodes then
            invalidArg "ptcThreshold" $"must be between 1 and {dataNodes}"

        match NodeRole.check roles threshold ptcThreshold with
        | Error es -> invalidArg "roles" (String.Join("; ", es))
        | Ok() -> ()

    let nodes =
        List.zip clients roles
        |> List.mapi (fun i (c, r) ->
            {
                Client = c
                Name = c.Name
                Order = i
                Roles = r &&& NodeRole.All
                Score = 0
                Ready = false
                Dropped = false
                Health = NodeHealth.Synced
                Stop = new CancellationTokenSource()
                Background = 0
            })
        |> Array.ofList

    /// The nodes with any role of each mask, in config order, made once: role sets do not
    /// change while running, so a call pays one array index for its filter.
    let byMask =
        Array.init (int NodeRole.All + 1) (fun m ->
            let mask = enum<NodeRole> m
            nodes |> Array.filter (fun n -> n.Roles &&& mask <> NodeRole.None))

    let gate = obj ()
    /// Called when a drop leaves too few nodes (OnLoss), with the reason.
    let mutable onLoss: (string -> unit) voption = ValueNone

    let inUse (n: BeaconNode) = not n.Dropped && (n.Ready || not requireReady)

    /// byMask without the nodes not in use. Made again under the gate when a node is marked ready
    /// or dropped (rare), so a call still pays one array index for its filter.
    let liveOf () = byMask |> Array.map (Array.filter inUse)
    let mutable live = liveOf ()

    let withRole (role: NodeRole) = live[int (role &&& NodeRole.All)]
    /// Source and target confirmed by `threshold` nodes, per target epoch (Vero keeps the newest 3).
    let confirmed = Dictionary<Epoch, struct (Checkpoint * Checkpoint)>()

    let record (n: BeaconNode) (ok: bool) =
        Metrics.beaconRequest n.Name ok
        lock gate (fun () -> n.Score <- max 0 (min 100 (if ok then n.Score + 1 else n.Score - 5)))

    let rankedOf (set: BeaconNode[]) =
        if set.Length = 1 then
            set
        else
            lock gate (fun () -> set |> Array.sortBy (fun n -> struct (n.Health.Rank, -n.Score, n.Order)))

    let ranked (role: NodeRole) = rankedOf (withRole role)

    /// The answer with the highest score (aggregation bits, block value) as each node reports it:
    /// the beacon nodes are trusted. Equal scores go to the best-ranked node (health, score,
    /// config order).
    let highest (score: 'T -> 'S) (answers: ('T * BeaconNode) list) : 'T * BeaconNode =
        match answers with
        | [] -> invalidArg (nameof answers) "no answer"
        | [ one ] -> one
        | _ ->
            let top = answers |> List.map (fst >> score) |> List.max
            let tied = answers |> List.filter (fun (v, _) -> score v = top)
            let first = (rankedOf (tied |> List.map snd |> Array.ofList)).[0]
            tied |> List.find (fun (_, n) -> Object.ReferenceEquals(n, first))

    /// The nodes with `role` asked for data that `count` of them must agree on: the synced ones
    /// when there are enough of them, else all of them (a lone or mostly unhealthy set still
    /// gets asked).
    let usable (role: NodeRole) (count: int) =
        let set = withRole role

        lock gate (fun () ->
            let synced = set |> Array.filter (fun n -> n.Health = NodeHealth.Synced)
            if synced.Length >= count then synced else set)

    /// Scores the node by the answer; with a topic, counts the answer as a publish send too.
    let trackAs (n: BeaconNode) (topic: string voption) (t: Task<Result<'T, ApiError>>) : Task<Result<'T, ApiError>> =
        task {
            let! r = t
            let ok = Result.isOk r
            record n ok

            match topic with
            | ValueSome topic ->
                Metrics.beaconSubmission n.Name topic (if ok then Metrics.Send.Accepted else Metrics.Send.Failed)
            | ValueNone -> ()

            return r
        }

    let track (n: BeaconNode) (t: Task<Result<'T, ApiError>>) : Task<Result<'T, ApiError>> = trackAs n ValueNone t

    /// f on one node, scored. With `valid`, an answer that fails it (ValueSome reason) is an error
    /// of its node: logged, scored as a failure, and ApiError.Invalid.
    let fetchValid
        (n: BeaconNode)
        (f: BeaconClient -> Task<Result<'T, ApiError>>)
        (valid: ('T -> string voption) option)
        =
        match valid with
        | None -> track n (f n.Client)
        | Some check ->
            task {
                match! f n.Client with
                | Ok v ->
                    let why =
                        try
                            check v
                        with e ->
                            ValueSome $"check failed: {e.Message}"

                    match why with
                    | ValueNone ->
                        record n true
                        return Ok v
                    | ValueSome why ->
                        record n false
                        log.Warn $"beacon node {n.Name}: {why}; its answer is not used"
                        return Error(ApiError.Invalid why)
                | Error e ->
                    record n false
                    return Error e
            }

    /// f on one node, scored and, with a topic, counted. An exception from f, thrown or faulted,
    /// is an error of that node, as in a broadcast send. A cancellation is the caller's: it counts
    /// as a failed send, costs the node nothing, and goes on as a cancellation.
    let attempt
        (n: BeaconNode)
        (topic: string voption)
        (f: BeaconClient -> Task<Result<'T, ApiError>>)
        : Task<Result<'T, ApiError>> =
        // One task, not a wrapper around trackAs: a wrapper costs a task object per try.
        task {
            try
                let! r = f n.Client
                let ok = Result.isOk r
                record n ok

                match topic with
                | ValueSome topic ->
                    Metrics.beaconSubmission n.Name topic (if ok then Metrics.Send.Accepted else Metrics.Send.Failed)
                | ValueNone -> ()

                return r
            with
            | :? OperationCanceledException as e ->
                match topic with
                | ValueSome topic -> Metrics.beaconSubmission n.Name topic Metrics.Send.Failed
                | ValueNone -> ()

                ExceptionDispatchInfo.Throw e
                return Unchecked.defaultof<_>
            | e ->
                record n false

                match topic with
                | ValueSome topic -> Metrics.beaconSubmission n.Name topic Metrics.Send.Failed
                | ValueNone -> ()

                return Error(ApiError.Transport e.Message)
        }

    /// The best node with `role` first, then the others in score order until one succeeds.
    let failover
        (role: NodeRole)
        (topic: string voption)
        (f: BeaconClient -> Task<Result<'T, ApiError>>)
        : Task<Result<'T, ApiError>> =
        task {
            let order = ranked role
            let mutable result = Error(ApiError.Transport "no beacon node")
            let mutable i = 0

            while i < order.Length do
                let! r = attempt order[i] topic f
                result <- r

                match r with
                | Ok _ -> i <- order.Length
                | Error e ->
                    if i + 1 < order.Length then
                        log.Debug $"beacon node {order[i].Name}: {e.Describe}; trying the next node"

                    i <- i + 1

            return result
        }

    /// Asks every node of `rest` at once for an answer that `preferred` accepts, for at most
    /// PreferWait. The first such answer wins; ValueNone when none came in time. Calls still
    /// running then go on in the background and still score their node when they end.
    let preferredWithin
        (rest: BeaconNode[])
        (preferred: 'T -> bool)
        (f: BeaconClient -> Task<Result<'T, ApiError>>)
        : Task<Result<'T, ApiError> voption> =
        task {
            let calls =
                rest
                |> Array.map (fun n ->
                    task {
                        try
                            return! attempt n ValueNone f
                        with :? OperationCanceledException ->
                            return Error(ApiError.Transport "cancelled")
                    })

            let pending = List<Task<Result<'T, ApiError>>>(calls)
            let stop = Task.Delay(BeaconNodes.PreferWait, time)
            let mutable found = ValueNone
            let mutable go = true

            while go && pending.Count > 0 do
                let! any = Task.WhenAny(Seq.append (pending |> Seq.map (fun t -> t :> Task)) [ stop ])

                if Object.ReferenceEquals(any, stop) then
                    go <- false
                else
                    let t = pending |> Seq.find (fun t -> Object.ReferenceEquals(t, any))
                    pending.Remove t |> ignore
                    let name = rest[Array.IndexOf(calls, t)].Name

                    match t.Result with
                    | Ok v when preferred v ->
                        found <- ValueSome t.Result
                        go <- false
                    | Ok _ -> log.Debug $"beacon node {name}: answer not preferred"
                    | Error e -> log.Debug $"beacon node {name}: {e.Describe}"

            if found.IsNone && pending.Count > 0 then
                log.Debug
                    $"no preferred answer within {BeaconNodes.PreferWait.TotalMilliseconds} ms; {pending.Count} beacon nodes still asked"

            return found
        }

    /// As failover, but an answer that `preferred` rejects sends the call on to the other nodes.
    /// Until the first good answer, the nodes are asked one at a time as in failover. Once a good
    /// answer that is not preferred is in hand, the remaining nodes are asked at once and waited
    /// for at most PreferWait (preferredWithin), so a hung node cannot hold the caller for its
    /// request timeout. When no node gives a preferred answer in time, the first good answer
    /// wins. Such an answer does not cost the node score: the node answered, only not as well as
    /// hoped.
    let failoverPreferring
        (role: NodeRole)
        (preferred: 'T -> bool)
        (f: BeaconClient -> Task<Result<'T, ApiError>>)
        : Task<Result<'T, ApiError>> =
        task {
            let order = ranked role
            let mutable result = Error(ApiError.Transport "no beacon node")
            let mutable i = 0

            while i < order.Length do
                let! r = attempt order[i] ValueNone f

                match r with
                | Ok v when preferred v ->
                    result <- r
                    i <- order.Length
                | Ok _ ->
                    result <- r

                    if i + 1 < order.Length then
                        log.Debug $"beacon node {order[i].Name}: answer not preferred; asking the other nodes"

                        match! preferredWithin order[i + 1 ..] preferred f with
                        | ValueSome better -> result <- better
                        | ValueNone -> ()

                    i <- order.Length
                | Error e ->
                    result <- r

                    if i + 1 < order.Length then
                        log.Debug $"beacon node {order[i].Name}: {e.Describe}; trying the next node"

                    i <- i + 1

            return result
        }

    /// Calls f on each of `asked` until the token fires. onResult runs under a lock with each good
    /// answer; the first ValueSome it returns is the result. Each node waits `interval` between calls.
    let poll
        (asked: BeaconNode[])
        (interval: TimeSpan)
        (ct: CancellationToken)
        (f: BeaconClient -> CancellationToken -> Task<Result<'T, ApiError>>)
        (onResult: int -> 'T -> 'R voption)
        : Task<'R voption> =
        task {
            let tcs = TaskCompletionSource<'R voption>(TaskCreationOptions.RunContinuationsAsynchronously)
            use cts = CancellationTokenSource.CreateLinkedTokenSource ct

            let loop (i: int) (n: BeaconNode) : Task =
                task {
                    try
                        while not cts.IsCancellationRequested do
                            let started = time.GetUtcNow()
                            let! r = track n (f n.Client cts.Token)

                            match r with
                            | Ok v ->
                                match lock gate (fun () -> onResult i v) with
                                | ValueSome x -> tcs.TrySetResult(ValueSome x) |> ignore
                                | ValueNone -> ()
                            | Error _ -> ()

                            let wait = interval - (time.GetUtcNow() - started)

                            if wait > TimeSpan.Zero then
                                do! Task.Delay(wait, time, cts.Token)
                    with :? OperationCanceledException ->
                        ()
                }

            use _reg = ct.Register(fun () -> tcs.TrySetResult ValueNone |> ignore)
            let loops = asked |> Array.mapi loop
            let! result = tcs.Task
            cts.Cancel()
            do! Task.WhenAll loops
            return result
        }

    let sane (slot: Slot) (currentEpoch: Epoch) (d: AttestationData) =
        d.Slot = slot && d.Source.Epoch <= currentEpoch && d.Target.Epoch <= currentEpoch

    member _.Nodes = nodes |> Array.map (fun n -> n.Client) |> List.ofArray
    member _.Count = nodes.Length
    member _.Threshold = threshold
    member _.PtcThreshold = ptcThreshold
    member _.Scores = lock gate (fun () -> nodes |> Array.map (fun n -> n.Name, n.Score, n.Ready))

    /// The roles of each node, in config order.
    member _.Roles = nodes |> Array.map (fun n -> n.Client, n.Roles) |> List.ofArray

    /// True when some node lacks a role: the config splits roles.
    member _.Split = nodes |> Array.exists (fun n -> n.Roles <> NodeRole.All)

    /// The nodes with any of `role`, in config order, also those not in use (the order of AskAll).
    member _.NodesWith(role: NodeRole) =
        byMask[int (role &&& NodeRole.All)] |> Array.map (fun n -> n.Client) |> List.ofArray

    /// The nodes in use with any of `role`, best first (health, then score, then config order).
    member _.Ranked(role: NodeRole) = ranked role |> Array.map (fun n -> n.Client) |> List.ofArray

    /// The node in use with the highest score (the first configured node when none is in use).
    member _.Best =
        match ranked NodeRole.All with
        | [||] -> nodes[0].Client
        | r -> r[0].Client

    /// A node passed the start checks. A dropped node stays dropped.
    member _.MarkReady(client: BeaconClient) =
        lock gate (fun () ->
            for n in nodes do
                if Object.ReferenceEquals(n.Client, client) && not n.Dropped then
                    n.Ready <- true
                    n.Score <- 100

            live <- liveOf ())

    /// A check of the node failed: it gets no call for any role until the VC restarts, and its
    /// event stream ends. Logged as an error; eplix_beacon_node_dropped shows it. After OnLoss, a
    /// drop that leaves too few nodes (Shortfall) calls the handler.
    member this.Drop(client: BeaconClient, reason: string) =
        let dropped =
            lock gate (fun () ->
                let mutable found = ValueNone

                for n in nodes do
                    if Object.ReferenceEquals(n.Client, client) && not n.Dropped then
                        n.Dropped <- true
                        n.Ready <- false
                        n.Score <- 0
                        found <- ValueSome n

                live <- liveOf ()
                found)

        match dropped with
        | ValueSome n ->
            n.Stop.Cancel()
            log.Error $"beacon node {client.Name}: {reason}; it gets no calls until the VC restarts"

            match onLoss, this.Shortfall with
            | ValueSome f, ValueSome why -> f $"beacon node {client.Name}: {reason}; {why}"
            | _ -> ()
        | ValueNone -> ()

    /// Why the nodes in use can no longer do the duties, if they cannot: fewer nodes with the role
    /// attestation_data than the threshold, or a role whose every node was dropped. One bad node is dropped; only a shortfall stops the VC.
    member _.Shortfall: string voption =
        lock gate (fun () ->
            let data = byMask[int NodeRole.AttestationData] |> Array.filter inUse |> Array.length

            if data < threshold then
                ValueSome
                    $"{data} beacon nodes with the role attestation_data are left in use, attestation_consensus_threshold is {threshold}"
            else
                match
                    NodeRole.names |> List.tryFind (fun (r, _) -> byMask[int r] |> Array.forall (fun n -> n.Dropped))
                with
                | Some(_, name) -> ValueSome $"no beacon node with the role {name} is left"
                | None -> ValueNone)

    /// From now on, a drop that leaves too few nodes calls `handler` (the VC's shutdown). Called
    /// at once when too few are left already.
    member this.OnLoss(handler: string -> unit) =
        lock gate (fun () -> onLoss <- ValueSome handler)

        match this.Shortfall with
        | ValueSome why -> handler why
        | ValueNone -> ()

    /// Whether each node was dropped, in config order.
    member _.Dropped = lock gate (fun () -> nodes |> Array.map (fun n -> n.Name, n.Dropped))

    /// Whether the node gets calls: ready (or no readiness required) and not dropped.
    member _.InUse(client: BeaconClient) =
        lock gate (fun () -> nodes |> Array.exists (fun n -> Object.ReferenceEquals(n.Client, client) && inUse n))

    /// Health per node, in config order.
    member _.Health = lock gate (fun () -> nodes |> Array.map (fun n -> n.Name, n.Health))

    /// Asks every node's /eth/v1/node/syncing and ranks it by the answer. A node that does not
    /// answer keeps its last health (its failed requests cost it score anyway). One node: nothing
    /// to rank, no request.
    member _.RefreshHealth(ct: CancellationToken) : Task =
        task {
            let asked = lock gate (fun () -> nodes |> Array.filter inUse)

            if nodes.Length > 1 then
                let! answers =
                    asked
                    |> Array.map (fun n ->
                        task {
                            try
                                return! n.Client.Syncing ct
                            with
                            | :? OperationCanceledException as e when ct.IsCancellationRequested -> return raise e
                            | e -> return Error(ApiError.Transport e.Message)
                        })
                    |> Task.WhenAll

                for n, answer in Array.zip asked answers do
                    match answer with
                    | Ok s ->
                        let health =
                            if s.IsSyncing then NodeHealth.Syncing
                            elif s.IsOptimistic then NodeHealth.Optimistic
                            elif s.ElOffline then NodeHealth.ElOffline
                            else NodeHealth.Synced

                        let old =
                            lock gate (fun () ->
                                let o = n.Health in
                                n.Health <- health
                                o)

                        if old <> health then
                            if health = NodeHealth.Synced then
                                log.Info $"beacon node {n.Name}: {health.Describe}"
                            else
                                log.Warn $"beacon node {n.Name}: {health.Describe}; it ranks below synced nodes"
                    | Error e -> log.Debug $"beacon node {n.Name}: syncing status: {e.Describe}"
        }

    /// One answer: the best node first, then the others in score order until one succeeds.
    /// `role`: only nodes with it are asked (default: every node).
    member _.Call
        (f: BeaconClient -> Task<Result<'T, ApiError>>, [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole) : Task<
            Result<'T, ApiError>
                                                                                                                             >
        =
        failover role ValueNone f

    /// As Call, but an answer that `preferred` rejects (for example duties computed on an
    /// optimistic head) asks the other nodes at once, for at most PreferWait; with no preferred
    /// answer in that time, the first good answer is returned and the caller decides what to do
    /// with it. A first answer that is preferred costs one call, as Call.
    member _.CallPreferring
        (
            f: BeaconClient -> Task<Result<'T, ApiError>>,
            preferred: 'T -> bool,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole
        ) : Task<Result<'T, ApiError>> =
        failoverPreferring role preferred f

    /// Asks every node in use with `role` (default: every node) at once and returns each node's
    /// answer, in config order (the order of NodesWith role). A node not in use gets no call and
    /// answers an error.
    member _.AskAll
        (f: BeaconClient -> Task<Result<'T, ApiError>>, [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole) : Task<
            Result<'T, ApiError>[]
                                                                                                                             >
        =
        byMask[int (role &&& NodeRole.All)]
        |> Array.map (fun n ->
            if lock gate (fun () -> inUse n) then
                track n (f n.Client)
            else
                Task.FromResult(Error(ApiError.Transport "not in use: start checks not passed, or dropped")))
        |> Task.WhenAll

    /// Publishes to the nodes with `role` (default: every node). With `topic` in the `broadcast`
    /// setting: to all of them at once, returning with the first node that accepts; the other
    /// sends run on (their results still score the node and reach the debug log), each bounded by
    /// the request timeout and the caller's token. A node with MaxBackground sends still running
    /// is skipped. When every send fails, the first node's error (config order). With `topic` out
    /// of the setting: the best node, then the next on failure, one at a time (as Call). Every
    /// send counts in eplix_beacon_node_submissions when it ends, background sends included.
    member this.Broadcast
        (
            f: BeaconClient -> Task<Result<unit, ApiError>>,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole,
            [<Optional; DefaultParameterValue(BroadcastTopic.All)>] topic: BroadcastTopic
        ) : Task<Result<unit, ApiError>> =
        if Tracing.source.HasListeners() then
            task {
                // The span ends when the broadcast returns, at the first node that accepts, so it
                // does not report how many nodes accepted: eplix_beacon_node_submissions counts
                // every send, also those still running then. `eplix.nodes` is the number of nodes
                // with the role, the set the broadcast or the failover draws from, not the number
                // of nodes sent to.
                use act = Tracing.start "submit"

                if not (isNull act) then
                    Tracing.setInt act "eplix.nodes" (withRole role).Length
                    Tracing.setBool act "eplix.broadcast" (broadcast &&& topic <> BroadcastTopic.None)

                try
                    let! r = this.Send(f, role, topic)

                    match r with
                    | Ok() -> ()
                    | Error _ -> Tracing.fail act "no node accepted"

                    return r
                with e ->
                    Tracing.fail act (if e :? OperationCanceledException then "cancelled" else e.Message)
                    ExceptionDispatchInfo.Throw e
                    return Unchecked.defaultof<_>
            }
        else
            this.Send(f, role, topic)

    member private this.Send
        (f: BeaconClient -> Task<Result<unit, ApiError>>, role: NodeRole, topic: BroadcastTopic)
        : Task<Result<unit, ApiError>> =
        let label = BroadcastTopic.label topic

        if broadcast &&& topic = BroadcastTopic.None then
            failover role (ValueSome label) f
        else
            let set = withRole role

            if set.Length = 0 then
                Task.FromResult(Error(ApiError.Transport "no beacon node with the role is in use"))
            elif set.Length = 1 then
                attempt set[0] (ValueSome label) f
            else
                let tcs =
                    TaskCompletionSource<Result<unit, ApiError>>(TaskCreationOptions.RunContinuationsAsynchronously)

                let results: Result<unit, ApiError> voption[] = Array.create set.Length ValueNone
                let mutable left = set.Length

                let finish (i: int) (result: string) (r: Result<unit, ApiError>) =
                    // The bookkeeping and the answer come first: the metric and the log run
                    // after, and a throw from them cannot leave the broadcast without an answer.
                    let last =
                        lock results (fun () ->
                            results[i] <- ValueSome r
                            left <- left - 1
                            left = 0)

                    match r with
                    | Ok() -> tcs.TrySetResult r |> ignore
                    | Error _ when last ->
                        // Every send failed (no Ok set the result): the first node's error.
                        match results[0] with
                        | ValueSome first -> tcs.TrySetResult first |> ignore
                        | ValueNone -> ()
                    | Error _ -> ()

                    try
                        Metrics.beaconSubmission set[i].Name (BroadcastTopic.label topic) result

                        match r with
                        | Error e -> log.Debug $"beacon node {set[i].Name}: {e.Describe}"
                        | Ok() -> ()
                    with _ ->
                        ()

                for i in 0 .. set.Length - 1 do
                    let n = set[i]

                    if Interlocked.Increment(&n.Background) > BeaconNodes.MaxBackground then
                        Interlocked.Decrement(&n.Background) |> ignore

                        finish
                            i
                            Metrics.Send.Skipped
                            (Error(
                                ApiError.Transport
                                    $"{BeaconNodes.MaxBackground} earlier sends to this node still running; skipped"
                            ))
                    else
                        let send: Task<Result<unit, ApiError>> =
                            task {
                                try
                                    try
                                        return! track n (f n.Client)
                                    with
                                    | :? OperationCanceledException -> return Error(ApiError.Transport "send cancelled")
                                    | e ->
                                        record n false
                                        return Error(ApiError.Transport e.Message)
                                finally
                                    Interlocked.Decrement(&n.Background) |> ignore
                            }

                        send.ContinueWith(
                            (fun (t: Task<Result<unit, ApiError>>) ->
                                let r =
                                    if t.IsCompletedSuccessfully then
                                        t.Result
                                    else
                                        Error(ApiError.Transport "send cancelled")

                                finish i (if Result.isOk r then Metrics.Send.Accepted else Metrics.Send.Failed) r),
                            TaskContinuationOptions.ExecuteSynchronously
                        )
                        |> ignore

                tcs.Task

    /// Sends to one node still running, also after their broadcast returned, at most. A node past
    /// it is skipped: it hangs, and each of its sends waits for the request timeout.
    static member MaxBackground = 16

    /// How long CallPreferring waits for a preferred answer once it holds a good one that is not
    /// preferred. A synced node answers duties in well under a second; the scheduler fetches
    /// three duty kinds inline per epoch, so a hung node costs at most 3 s there, inside the
    /// one-slot look-ahead, where the full request timeout (default 4 s) cost 12 s per hung node.
    static member PreferWait = TimeSpan.FromSeconds 1.0

    /// The topics sent to every node at once (the `broadcast` setting).
    member _.BroadcastTopics = broadcast

    /// Broadcast sends still running per node, in config order, also those past their broadcast.
    member _.Running = nodes |> Array.map (fun n -> Volatile.Read(&n.Background))

    /// Attestation data for a slot that `threshold` nodes agree on (Vero's two paths).
    /// Path A, with the head block root from an event: the first node whose data names that root
    /// gives the data, and `threshold` nodes must report the same source and target (cached per
    /// target epoch). Path B, without a head event or when path A times out: data equal in full
    /// on `threshold` nodes. Data whose checkpoints are ahead of the current epoch never counts.
    /// ValueNone when no data reaches the threshold before the token fires.
    member _.AttestationData
        (slot: Slot, head: Root voption, currentEpoch: Epoch, ct: CancellationToken)
        : Task<Result<AttestationData, string>> =
        task {
            let fetch (c: BeaconClient) (t: CancellationToken) = c.AttestationData(slot, 0UL, t)
            let dataNodes = withRole NodeRole.AttestationData

            if dataNodes.Length = 0 then
                return Error "no beacon node with the role attestation_data is in use"
            elif dataNodes.Length = 1 then
                match! track dataNodes[0] (fetch dataNodes[0].Client ct) with
                | Ok d when sane slot currentEpoch d -> return Ok d
                | Ok d -> return Error $"beacon node returned data for slot {d.Slot}, target epoch {d.Target.Epoch}"
                | Error e -> return Error e.Describe
            else
                let asked = usable NodeRole.AttestationData threshold

                let checkpointsConfirmed (d: AttestationData) =
                    lock gate (fun () ->
                        match confirmed.TryGetValue d.Target.Epoch with
                        | true, struct (s, t) -> s = d.Source && t = d.Target
                        | _ -> false)

                let confirm (d: AttestationData) =
                    lock gate (fun () ->
                        confirmed[d.Target.Epoch] <- struct (d.Source, d.Target)

                        for e in List.ofSeq confirmed.Keys do
                            if e + 3UL <= d.Target.Epoch then
                                confirmed.Remove e |> ignore)

                let! pathA =
                    task {
                        match head with
                        | ValueNone -> return ValueNone
                        | ValueSome root ->
                            use a = CancellationTokenSource.CreateLinkedTokenSource ct
                            a.CancelAfter(TimeSpan.FromMilliseconds 500.0)

                            let! first =
                                poll asked (TimeSpan.FromMilliseconds 50.0) a.Token fetch (fun _ d ->
                                    if d.BeaconBlockRoot = root && sane slot currentEpoch d then
                                        ValueSome d
                                    else
                                        ValueNone)

                            match first with
                            | ValueNone -> return ValueNone
                            | ValueSome d when checkpointsConfirmed d -> return ValueSome d
                            | ValueSome d ->
                                use b = CancellationTokenSource.CreateLinkedTokenSource ct
                                b.CancelAfter(TimeSpan.FromSeconds 1.0)
                                let agree = HashSet<int>()

                                let! ok =
                                    poll asked (TimeSpan.FromMilliseconds 50.0) b.Token fetch (fun i x ->
                                        if x.Source = d.Source && x.Target = d.Target && sane slot currentEpoch x then
                                            agree.Add i |> ignore

                                        if agree.Count >= threshold then ValueSome() else ValueNone)

                                match ok with
                                | ValueSome() ->
                                    confirm d
                                    return ValueSome d
                                | ValueNone -> return ValueNone
                    }

                match pathA with
                | ValueSome d -> return Ok d
                | ValueNone ->
                    let latest = Dictionary<int, AttestationData>()

                    let! b =
                        poll asked (TimeSpan.FromMilliseconds 30.0) ct fetch (fun i d ->
                            if sane slot currentEpoch d then latest[i] <- d else latest.Remove i |> ignore
                            let votes = latest.Values |> Seq.filter (fun x -> x = d) |> Seq.length
                            if votes >= threshold then ValueSome d else ValueNone)

                    match b with
                    | ValueSome d ->
                        confirm d
                        return Ok d
                    | ValueNone ->
                        let seen = lock gate (fun () -> latest.Count)

                        return
                            Error
                                $"no attestation data reached {threshold} of {dataNodes.Length} beacon nodes ({seen} answered)"
        }

    /// Gloas payload_attestation_data for a slot. ValueNone means no block seen (204): no vote.
    /// With ptcThreshold 1, one answer from the best node, with fallback. Above 1, path B of
    /// attestation data: every node is asked in rounds at least 30 ms apart until `ptcThreshold`
    /// nodes return the same data in full; a 204 counts as an answer of no data, and data for
    /// another slot never counts. Data that reaches the threshold returns at once. At `deadline`
    /// the latest answers decide: `ptcThreshold` answers of no data give ValueNone, anything
    /// else is an error. Either way no vote unless the threshold agrees on data.
    member _.PayloadAttestationData
        (slot: Slot, deadline: DateTimeOffset, ct: CancellationToken)
        : Task<Result<PayloadAttestationData voption, string>> =
        task {
            let fetch (c: BeaconClient) (t: CancellationToken) = c.PayloadAttestationData(slot, t)

            if (withRole NodeRole.AttestationData).Length = 0 then
                return Error "no beacon node with the role attestation_data is in use"
            elif ptcThreshold = 1 then
                let order = ranked NodeRole.AttestationData
                let mutable result = Error "no beacon node"
                let mutable i = 0

                while i < order.Length do
                    match! track order[i] (fetch order[i].Client ct) with
                    | Ok(ValueSome d) when d.Slot <> slot ->
                        result <- Error $"beacon node returned payload attestation data for slot {d.Slot}"
                        i <- order.Length
                    | Ok v ->
                        result <- Ok v
                        i <- order.Length
                    | Error e ->
                        result <- Error e.Describe

                        if i + 1 < order.Length then
                            log.Debug $"beacon node {order[i].Name}: {e.Describe}; trying the next node"

                        i <- i + 1

                return result
            else
                let latest = Dictionary<int, PayloadAttestationData voption>()
                use timeout = new CancellationTokenSource(max (deadline - time.GetUtcNow()) TimeSpan.Zero, time)
                use cts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token)

                let! agreed =
                    poll
                        (usable NodeRole.AttestationData ptcThreshold)
                        (TimeSpan.FromMilliseconds 30.0)
                        cts.Token
                        fetch
                        (fun i v ->
                            match v with
                            | ValueSome d when d.Slot <> slot ->
                                latest.Remove i |> ignore
                                ValueNone
                            | ValueSome d ->
                                latest[i] <- v
                                let votes = latest.Values |> Seq.filter (fun x -> x = v) |> Seq.length
                                if votes >= ptcThreshold then ValueSome d else ValueNone
                            | ValueNone ->
                                latest[i] <- ValueNone
                                ValueNone)

                match agreed with
                | ValueSome d -> return Ok(ValueSome d)
                | ValueNone ->
                    let noData, answered =
                        lock gate (fun () ->
                            latest.Values |> Seq.filter (fun x -> x.IsNone) |> Seq.length, latest.Count)

                    if noData >= ptcThreshold then
                        return Ok ValueNone
                    else
                        return
                            Error
                                $"no payload attestation data reached {ptcThreshold} of {(withRole NodeRole.AttestationData).Length} beacon nodes ({answered} answered)"
        }

    /// The head block root that sync committee messages sign, from the nodes with the role
    /// sync_data. With threshold 1, or one such node in use: the best node, then the next on
    /// failure. Above: every such node is asked once and `threshold` of them (at most all of
    /// them) must name the same root. An optimistic head never counts.
    member _.HeadBlockRoot(ct: CancellationToken) : Task<Result<Root, string>> =
        task {
            let set = withRole NodeRole.SyncData
            let need = min threshold set.Length

            if set.Length = 0 then
                return Error "no beacon node with the role sync_data is in use"
            elif need <= 1 then
                match! failover NodeRole.SyncData ValueNone (fun b -> b.HeadBlockRoot ct) with
                | Ok(false, r) -> return Ok r
                | Ok(true, _) -> return Error "the head is optimistic"
                | Error e -> return Error e.Describe
            else
                let! answers =
                    set |> Array.map (fun n -> attempt n ValueNone (fun b -> b.HeadBlockRoot ct)) |> Task.WhenAll

                let roots =
                    answers
                    |> Array.choose (fun a ->
                        match a with
                        | Ok(false, r) -> Some r
                        | _ -> None)

                match roots |> Array.countBy id |> Array.sortByDescending snd |> Array.tryHead with
                | Some(r, count) when count >= need -> return Ok r
                | _ ->
                    return
                        Error
                            $"no head root reached {need} of {set.Length} beacon nodes ({roots.Length} answered with a verified head)"
        }

    /// Asks every node with `role` (default: every node), waits until `soft` for answers, and takes
    /// the one with the highest score; equal scores go to the best-ranked node. With no answer by
    /// then, takes the first answer that comes (until ct fires). With `valid`, each answer is checked as it comes
    /// and one that fails (ValueSome reason) is an error of its node (ApiError.Invalid, logged,
    /// scored as a failure), so a claimed value counts only for an answer the VC would sign. When
    /// no answer passes, the error is an Invalid one if any answer failed the check.
    member _.HighestValue
        (
            f: BeaconClient -> Task<Result<'T, ApiError>>,
            score: 'T -> BigInteger,
            soft: DateTimeOffset,
            ct: CancellationToken,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole,
            ?valid: 'T -> string voption
        ) : Task<Result<'T * BeaconClient, ApiError>> =
        let fetch (n: BeaconNode) = fetchValid n f valid

        task {
            let nodes = withRole role

            if nodes.Length = 1 then
                match! fetch nodes[0] with
                | Ok v -> return Ok(v, nodes[0].Client)
                | Error e -> return Error e
            else
                let calls = nodes |> Array.map fetch
                let wait = soft - time.GetUtcNow()

                if wait > TimeSpan.Zero then
                    let all = Task.WhenAll calls :> Task
                    let! _ = Task.WhenAny(all, Task.Delay(wait, time, ct))
                    ()

                let done' () =
                    [
                        for i in 0 .. calls.Length - 1 do
                            if calls[i].IsCompletedSuccessfully then
                                match calls[i].Result with
                                | Ok v -> v, nodes[i]
                                | Error _ -> ()
                    ]

                match done' () with
                | [] ->
                    // Nothing yet: the first good answer wins.
                    let pending = List<Task<Result<'T, ApiError>>>(calls)
                    let mutable result = Error(ApiError.Transport "no beacon node answered")
                    let mutable go = true

                    while go && pending.Count > 0 do
                        let! t = Task.WhenAny(pending)
                        pending.Remove t |> ignore

                        match t.Result, result with
                        | Ok v, _ ->
                            result <- Ok(v, nodes[Array.IndexOf(calls, t)].Client)
                            go <- false
                        // A failed check says more than a later transport error.
                        | Error _, Error(ApiError.Invalid _) -> ()
                        | Error e, _ -> result <- Error e

                    return result
                | answers ->
                    let v, n = highest score answers
                    return Ok(v, n.Client)
        }

    /// Asks every node with `role` (default: every node) until `deadline` and takes the answer with
    /// the highest count (most aggregation bits); equal counts go to the best-ranked node of those
    /// that answered. Returns early when an answer is complete, and at `soft` (default: `deadline`) when it has an answer: a hung
    /// node then costs the wait until `soft`, not the whole time to `deadline`. With no answer by
    /// `soft`, the first answer after it is taken. With `valid`, an answer that fails it
    /// (ValueSome reason) is an error of its node and does not count.
    member _.Most
        (
            f: BeaconClient -> Task<Result<'T, ApiError>>,
            count: 'T -> int,
            complete: 'T -> bool,
            deadline: DateTimeOffset,
            ct: CancellationToken,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole,
            ?soft: DateTimeOffset,
            ?valid: 'T -> string voption
        ) : Task<Result<'T, ApiError>> =
        task {
            let nodes = withRole role

            if nodes.Length = 1 then
                return! fetchValid nodes[0] f valid
            else
                let calls = nodes |> Array.map (fun n -> fetchValid n f valid)
                let pending = List<Task<Result<'T, ApiError>>>(calls)
                let answers = List<'T * BeaconNode>()
                let mutable lastError = ApiError.Transport "no beacon node answered"
                let now = time.GetUtcNow()
                use timeout = new CancellationTokenSource(max (deadline - now) TimeSpan.Zero, time)
                use linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token)
                let stop = Task.Delay(Timeout.InfiniteTimeSpan, linked.Token)
                let softAt = min (defaultArg soft deadline) deadline
                use softTimeout = new CancellationTokenSource(max (softAt - now) TimeSpan.Zero, time)
                use softLinked = CancellationTokenSource.CreateLinkedTokenSource(ct, softTimeout.Token)
                let softStop = Task.Delay(Timeout.InfiniteTimeSpan, softLinked.Token)
                let mutable softPassed = false
                let mutable go = true

                while go && pending.Count > 0 do
                    let waits = pending |> Seq.map (fun t -> t :> Task)
                    let waits = if softPassed then Seq.append waits [ stop ] else Seq.append waits [ stop; softStop ]
                    let! any = Task.WhenAny waits

                    if Object.ReferenceEquals(any, stop) then
                        go <- false
                    elif Object.ReferenceEquals(any, softStop) then
                        softPassed <- true

                        if answers.Count > 0 then
                            go <- false
                    else
                        let t = pending |> Seq.find (fun t -> Object.ReferenceEquals(t, any))
                        pending.Remove t |> ignore

                        match t.Result with
                        | Ok v ->
                            answers.Add((v, nodes[Array.IndexOf(calls, t)]))

                            if complete v || softPassed then
                                go <- false
                        | Error e -> lastError <- e

                if answers.Count > 0 then
                    return Ok(fst (highest count (List.ofSeq answers)))
                else
                    return Error lastError
        }

    /// Reads head events from every node. Each stream reconnects with backoff (1 s doubling to
    /// 16 s, reset after an event); a stream error or an exception costs the node score, a
    /// stream silent for BeaconClient.EventIdle does not.
    /// `role`: only nodes with it get a stream (default: every node). A node not in use yet gets
    /// its stream once it is (checked each second); a dropped node's stream ends and its events
    /// are ignored.
    member this.RunEvents
        (
            topics: string list,
            onEvent: SseEvent -> unit,
            ct: CancellationToken,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole
        ) : Task =
        this.RunEventsFrom(topics, (fun _ ev -> onEvent ev), ct, role)

    /// RunEvents with the config order of the node that sent each event, for votes per node.
    member _.RunEventsFrom
        (
            topics: string list,
            onEvent: int -> SseEvent -> unit,
            ct: CancellationToken,
            [<Optional; DefaultParameterValue(NodeRole.All)>] role: NodeRole
        ) : Task =
        let one (n: BeaconNode) : Task =
            task {
                let mutable backoff = TimeSpan.FromSeconds 1.0

                while not ct.IsCancellationRequested && not n.Dropped do
                    if not (lock gate (fun () -> inUse n)) then
                        try
                            do! Task.Delay(TimeSpan.FromSeconds 1.0, time, ct)
                        with :? OperationCanceledException ->
                            ()
                    else
                        let gotEvent = ref false
                        // A drop ends the stream at once (n.Stop).
                        use stream = CancellationTokenSource.CreateLinkedTokenSource(ct, n.Stop.Token)
                        // Any exception (from the stream or from onEvent) is an error of this
                        // stream: it reconnects, so the node's events never stop for good.
                        let! result =
                            task {
                                try
                                    return!
                                        n.Client.Events(
                                            topics,
                                            (fun ev ->
                                                gotEvent.Value <- true

                                                if not n.Dropped then
                                                    onEvent n.Order ev),
                                            stream.Token
                                        )
                                with
                                | :? OperationCanceledException when stream.IsCancellationRequested -> return Ok()
                                | e -> return Error(ApiError.Transport e.Message)
                            }

                        match result with
                        | Error _ when stream.IsCancellationRequested -> ()
                        // Silent for EventIdle: a chain with no new block is no fault of the node,
                        // so the stream reconnects without a score cost.
                        | Error ApiError.Timeout ->
                            log.Debug
                                $"event stream of {n.Name}: no data for {BeaconClient.EventIdle.TotalSeconds} s; reconnecting"
                        | Error e ->
                            record n false
                            log.Warn $"event stream of {n.Name}: {e.Describe}"
                        | Ok() -> ()

                        if gotEvent.Value then
                            backoff <- TimeSpan.FromSeconds 1.0

                        if not ct.IsCancellationRequested then
                            try
                                do! Task.Delay(backoff, time, ct)
                            with :? OperationCanceledException ->
                                ()

                            backoff <- min (backoff * 2.0) (TimeSpan.FromSeconds 16.0)
            }

        Task.WhenAll(byMask[int (role &&& NodeRole.All)] |> Array.map one)
