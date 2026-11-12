/// Stops a key for good when the chain shows it slashed. A slashing means a
/// second signer holds the key, and each further vote risks another offence while the key waits
/// in the exit queue. The divergence alarm only fires when a remote signer refuses; a copy of a
/// local key in another client stays unseen once the doppelganger wait is over. This check does
/// not depend on any signer.
namespace Eplix

open System
open System.Collections.Generic
open System.IO
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Eplix.Beacon
open Eplix.Json

/// A key the chain showed slashed, as kept in `<data_dir>/slashed-keys.json`.
type SlashedKey =
    {
        Key: PubKey
        Index: ValidatorIndex voption
        /// The time Eplix stopped the key (UTC, ISO 8601).
        Since: string
        Reason: string
    }

/// The keys this VC stopped because the chain showed them slashed. The file keeps the stop across
/// restarts, also when the nodes are not synced yet. Only the operator removes an entry (with the
/// VC stopped).
type SlashedKeys(dataDir: string) =
    let path = Path.Combine(dataDir, "slashed-keys.json")
    let keys = Dictionary<PubKey, SlashedKey>()
    let gate = obj ()
    /// A key went into memory but the last write of the file failed. The key keeps its stop in
    /// this process; Flush and the next Add write the file again.
    let mutable dirty = false

    let write () =
        let bytes =
            toBytes (fun w ->
                w.WriteStartObject()
                w.WriteStartArray "keys"

                for k in keys.Values |> Seq.sortBy (fun k -> k.Key) do
                    w.WriteStartObject()
                    w.WriteString("pubkey", k.Key.Hex)

                    match k.Index with
                    | ValueSome i -> writeU64 w "index" i
                    | ValueNone -> ()

                    w.WriteString("since", k.Since)
                    w.WriteString("reason", k.Reason)
                    w.WriteEndObject()

                w.WriteEndArray()
                w.WriteEndObject())

        let tmp = path + ".tmp"

        (use f = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None)
         f.Write(bytes, 0, bytes.Length)
         f.Flush true)

        File.Move(tmp, path, true)
        Slashing.FileSync.syncDirectory dataDir

    member _.Path = path

    /// Reads the file. A file that does not parse fails the start: the VC must not forget a stop.
    member _.Load() : Result<int, string> =
        lock gate (fun () ->
            if not (File.Exists path) then
                Ok 0
            else
                let parse (e: JsonElement) =
                    match checkFields e "slashed-keys.json" [ "keys" ] with
                    | err :: _ -> fail err
                    | [] -> ()

                    [
                        for k in array (prop e "keys") ->
                            match checkFields k "slashed-keys.json key" [ "pubkey"; "index"; "since"; "reason" ] with
                            | err :: _ -> fail err
                            | [] -> ()

                            {
                                Key = pubkeyField k "pubkey"
                                Index =
                                    (match tryProp k "index" with
                                     | ValueSome i -> ValueSome(u64 i)
                                     | ValueNone -> ValueNone)
                                Since =
                                    (match tryProp k "since" with
                                     | ValueSome s -> str s
                                     | ValueNone -> "")
                                Reason =
                                    (match tryProp k "reason" with
                                     | ValueSome s -> str s
                                     | ValueNone -> "")
                            }
                    ]

                match decode parse (ReadOnlyMemory(File.ReadAllBytes path)) with
                | Error e -> Error $"{path}: {e}; fix or remove the file (it lists keys the chain showed slashed)"
                | Ok list ->
                    for k in list do
                        keys[k.Key] <- k

                    Ok list.Length)

    member _.Contains(key: PubKey) = lock gate (fun () -> keys.ContainsKey key)

    member _.TryGet(key: PubKey) : SlashedKey voption =
        lock gate (fun () ->
            match keys.TryGetValue key with
            | true, k -> ValueSome k
            | _ -> ValueNone)

    member _.All: SlashedKey list = lock gate (fun () -> List.ofSeq keys.Values)

    /// Writes the file under the gate. On failure the keys stay in memory and the file is
    /// written again by the next Flush or Add.
    member private _.WriteLocked() : Result<unit, string> =
        try
            write ()
            dirty <- false
            Ok()
        with e ->
            dirty <- true
            Error $"{path}: {e.Message}"

    /// Adds a key and writes the file (temporary file, fsync, rename, fsync of the directory).
    /// A key added before whose write failed is written again.
    member this.Add(k: SlashedKey) : Result<unit, string> =
        lock gate (fun () ->
            if keys.ContainsKey k.Key && not dirty then
                Ok()
            else
                if not (keys.ContainsKey k.Key) then
                    keys[k.Key] <- k

                this.WriteLocked())

    /// Writes the file again when an earlier write failed; Ok when there is nothing to write.
    member this.Flush() : Result<unit, string> = lock gate (fun () -> if dirty then this.WriteLocked() else Ok())

module OnChainSlashing =
    /// The rule for one key over every node's answer (ValueNone: no answer, or the node does not
    /// know the key). Slashed when `threshold` nodes say so, or when at least one node answered
    /// and every node that answered says so. One node on its own cannot stop a key while another
    /// node disputes it and the threshold is above 1.
    let decide (threshold: int) (answers: bool voption list) : bool =
        let said =
            answers
            |> List.choose (fun a ->
                match a with
                | ValueSome b -> Some b
                | ValueNone -> None)

        let yes = said |> List.filter id |> List.length
        yes >= threshold || (yes > 0 && yes = said.Length)

    /// Asks every node about the keys and returns those the rule says are slashed.
    let confirm (nodes: BeaconNodes) (keys: PubKey list) (ct: CancellationToken) : Task<PubKey list> =
        task {
            if keys.IsEmpty then
                return []
            else
                let ids = keys |> List.map (fun k -> k.Hex)
                let! answers = nodes.AskAll((fun b -> b.Validators("head", ids, ct)), NodeRole.Duties)

                let byNode =
                    answers
                    |> Array.map (fun r ->
                        match r with
                        | Ok infos ->
                            ValueSome(
                                infos |> Array.map (fun (v: ValidatorInfo) -> v.PubKey, v.Slashed) |> Map.ofArray
                            )
                        | Error _ -> ValueNone)

                return
                    keys
                    |> List.filter (fun k ->
                        byNode
                        |> Array.map (fun m ->
                            match m with
                            | ValueSome m ->
                                match Map.tryFind k m with
                                | Some s -> ValueSome s
                                | None -> ValueNone
                            | ValueNone -> ValueNone)
                        |> List.ofArray
                        |> decide nodes.Threshold)
        }

    /// Stops the key for good: state Slashed, the file, an error line and a metric.
    let stop
        (registry: KeyRegistry)
        (store: SlashedKeys)
        (log: Log)
        (time: TimeProvider)
        (key: PubKey)
        (reason: string)
        =
        let index =
            match registry.TryGet key with
            | ValueSome k -> k.Index
            | ValueNone -> ValueNone

        let fresh = not (store.Contains key)

        match
            store.Add
                {
                    Key = key
                    Index = index
                    Since =
                        time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ", Globalization.CultureInfo.InvariantCulture)
                    Reason = reason
                }
        with
        | Ok() -> ()
        | Error e -> log.Error $"key {key.Short}: could not record the stop, tried again at the next refresh: {e}"

        registry.SetState(key, KeyState.Slashed reason)

        if fresh then
            Metrics.slashedOnChain key
            log.Error $"key {key.Hex}: {reason}; the key signs nothing more in this VC (listed in {store.Path})"

    /// Checks keys against every node and stops the slashed ones. Returns the keys stopped.
    let check
        (nodes: BeaconNodes)
        (registry: KeyRegistry)
        (store: SlashedKeys)
        (log: Log)
        (time: TimeProvider)
        (keys: PubKey list)
        (ct: CancellationToken)
        =
        task {
            let! slashed = confirm nodes keys ct

            for k in slashed do
                stop registry store log time k "the chain shows this validator slashed"

            return slashed
        }

    /// The validator indices an attester_slashing or proposer_slashing event names: the indices
    /// in both attestations (those the slashing would hit), or the proposer.
    let eventIndices (event: string) (data: string) : ValidatorIndex list =
        let decoder (e: JsonElement) =
            let e =
                match tryProp e "data" with
                | ValueSome d -> d
                | ValueNone -> e

            match event with
            | "attester_slashing" ->
                let indices name = array (prop (prop e name) "attesting_indices") |> Array.map u64 |> Set.ofArray
                Set.intersect (indices "attestation_1") (indices "attestation_2") |> Set.toList
            | "proposer_slashing" -> [ u64 (prop (prop (prop e "signed_header_1") "message") "proposer_index") ]
            | _ -> []

        match decodeString decoder data with
        | Ok xs -> xs
        | Error _ -> []

    /// Reads slashing events as an early warning. One gossip event never stops a key: it starts
    /// a check of the named keys against every node at once and then each slot for two epochs,
    /// until the chain shows the slashing (it shows once a block includes it).
    let extension
        (spec: ChainSpec)
        (nodes: BeaconNodes)
        (registry: KeyRegistry)
        (store: SlashedKeys)
        (log: Log)
        (time: TimeProvider)
        (stopping: CancellationToken)
        : DutyExtension =
        let watching = HashSet<PubKey>()

        let watch (keys: PubKey list) =
            task {
                try
                    try
                        let mutable left = keys
                        let mutable round = 0UL

                        while not left.IsEmpty
                              && round <= 2UL * spec.SlotsPerEpoch
                              && not stopping.IsCancellationRequested do
                            let! stopped = check nodes registry store log time left stopping
                            left <- left |> List.filter (fun k -> not (List.contains k stopped))
                            round <- round + 1UL

                            if not left.IsEmpty then
                                do! Task.Delay(spec.SlotDuration, time, stopping)
                    with
                    | :? OperationCanceledException -> ()
                    | e -> log.Error $"slashing watch: {e.Message}"
                finally
                    lock watching (fun () ->
                        for k in keys do
                            watching.Remove k |> ignore)
            }
            :> Task

        { DutyExtension.empty "slashing-watch" with
            Topics = [ "attester_slashing"; "proposer_slashing" ]
            OnEvent =
                fun ev ->
                    let indices = eventIndices ev.Event ev.Data |> Set.ofList

                    if not indices.IsEmpty then
                        let mine =
                            registry.All
                            |> List.filter (fun k ->
                                (match k.Index with
                                 | ValueSome i -> indices.Contains i
                                 | ValueNone -> false)
                                && (match k.State with
                                    | KeyState.Slashed _
                                    | KeyState.Removed -> false
                                    | _ -> true))
                            |> List.map (fun k -> k.Key)

                        let fresh = lock watching (fun () -> mine |> List.filter (fun k -> watching.Add k))

                        if not fresh.IsEmpty then
                            log.Warn
                                $"""{ev.Event} event names {String.Join(", ", fresh |> List.map (fun k -> k.Short))}; checking the chain each slot"""

                            watch fresh |> ignore
        }
