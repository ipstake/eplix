/// One mark per key for Gloas PTC votes and one for execution payload envelopes: the highest
/// slot and the signing root signed there. Neither kind is slashable on chain, so a
/// refusal skips the duty and never halts a key, and a key needs no imported history: its first
/// request creates its record. EIP-3076 has no field for these marks.
/// The marks live in their own file (slot-marks.db), not in slashing.db, with the same record
/// format and file code as the slashing DB.
namespace Eplix.Slashing

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Eplix

[<RequireQualifiedAccess>]
type SlotMarkKind =
    | PayloadAttestation
    | PayloadEnvelope

type SlotMarkRequest =
    {
        Key: PubKey
        Kind: SlotMarkKind
        Slot: Slot
        SigningRoot: Root
    }

/// The marks of one key. Root is ValueNone when two roots at the mark slot merged, so no message
/// at that slot counts as a repeat.
type SlotKeyMarks =
    {
        PayloadAttestation: BlockMark voption
        PayloadEnvelope: BlockMark voption
    }

    static member Empty =
        {
            PayloadAttestation = ValueNone
            PayloadEnvelope = ValueNone
        }

module SlotMarkRules =
    let private name (kind: SlotMarkKind) =
        match kind with
        | SlotMarkKind.PayloadAttestation -> "PTC vote"
        | SlotMarkKind.PayloadEnvelope -> "envelope"

    let get (m: SlotKeyMarks) (kind: SlotMarkKind) =
        match kind with
        | SlotMarkKind.PayloadAttestation -> m.PayloadAttestation
        | SlotMarkKind.PayloadEnvelope -> m.PayloadEnvelope

    /// The block rule: above the mark is allowed, the same root at the mark is a repeat, anything
    /// else at or below the mark is refused.
    let check (m: SlotKeyMarks) (kind: SlotMarkKind) (slot: Slot) (root: Root) : Check =
        match get m kind with
        | ValueNone -> Check.Allow
        | ValueSome b when slot > b.Slot -> Check.Allow
        | ValueSome b when slot = b.Slot && b.Root = ValueSome root -> Check.Repeat
        | ValueSome b when slot = b.Slot -> Check.Refuse $"a different {name kind} at slot {slot} was signed before"
        | ValueSome b -> Check.Refuse $"slot {slot} is below the {name kind} mark {b.Slot}"

    /// Takes the maximum. Two different roots at the same slot leave the root unknown.
    let merge (m: SlotKeyMarks) (kind: SlotMarkKind) (x: BlockMark) : SlotKeyMarks =
        let merged =
            match get m kind with
            | ValueNone -> x
            | ValueSome b when x.Slot > b.Slot -> x
            | ValueSome b when x.Slot = b.Slot && b.Root <> x.Root -> { b with Root = ValueNone }
            | ValueSome b -> b

        match kind with
        | SlotMarkKind.PayloadAttestation ->
            { m with
                PayloadAttestation = ValueSome merged
            }
        | SlotMarkKind.PayloadEnvelope ->
            { m with
                PayloadEnvelope = ValueSome merged
            }

/// Records of slot-marks.db, in the 80-byte format of slashing.db (Record). The header carries
/// its own tag, so neither store opens the file of the other; the mark kinds are numbers that
/// slashing.db does not use.
module SlotRecord =
    /// "SLOT" and format version 1. The slashing.db header has 1 here.
    let formatTag = 0x534C4F54_00000001UL

    [<Literal>]
    let KindPayloadAttestation = 5uy

    [<Literal>]
    let KindPayloadEnvelope = 6uy

    let header (gvr: Root) = Record.make Record.KindHeader 0uy 0u formatTag 0UL (ReadOnlySpan gvr.Bytes)
    let key (id: uint32) (pubkey: PubKey) = Record.make Record.KindKey 0uy id 0UL 0UL (ReadOnlySpan pubkey.Bytes)

    let mark (id: uint32) (kind: SlotMarkKind) (m: BlockMark) =
        let k =
            match kind with
            | SlotMarkKind.PayloadAttestation -> KindPayloadAttestation
            | SlotMarkKind.PayloadEnvelope -> KindPayloadEnvelope

        match m.Root with
        | ValueSome r -> Record.make k 1uy id m.Slot 0UL (ReadOnlySpan r.Bytes)
        | ValueNone -> Record.make k 0uy id m.Slot 0UL ReadOnlySpan.Empty

type private SlotKeyState =
    {
        Id: uint32
        Key: PubKey
        mutable Marks: SlotKeyMarks
    }

/// The slot marks store. One gate for every key: these kinds come once per slot per key, so a
/// burst holds the gate for one append and one fsync.
type SlotMarks
    private
    (file: IMarkFile, gvr: Root, keys: Dictionary<PubKey, SlotKeyState>, byId: List<SlotKeyState>, info: OpenInfo) =
    let gate = new SemaphoreSlim(1, 1)
    let mutable failed: string voption = ValueNone

    /// One append and one fsync. Any exception poisons the store. The caller holds the gate;
    /// checks `failed` again under it, as another write may have failed after the caller's check.
    let write (records: List<byte[]>) : Result<unit, string> =
        if failed.IsSome then
            Error $"failed earlier: {failed.Value}"
        elif records.Count = 0 then
            Ok()
        else
            try
                file.Append(Array.concat records)
                file.Sync()
                Ok()
            with e ->
                failed <- ValueSome e.Message
                Error e.Message

    /// Opens or creates the store. Replays the log, cuts a torn tail, checks the genesis
    /// validators root. A record that fails its checksum with valid records after it is corruption.
    static member Open(file: IMarkFile, gvr: Root) : Result<SlotMarks, string> =
        let bytes = file.ReadAll()

        if bytes.Length = 0 then
            file.Append(SlotRecord.header gvr)
            file.Sync()

            Ok(
                new SlotMarks(
                    file,
                    gvr,
                    Dictionary(),
                    List(),
                    {
                        Records = 1
                        Keys = 0
                        TruncatedBytes = 0L
                    }
                )
            )
        else
            let count = bytes.Length / Record.size
            let valid i = Record.isValid (ReadOnlySpan(bytes, i * Record.size, Record.size))
            let firstBad = seq { 0 .. count - 1 } |> Seq.tryFind (valid >> not)

            let goodCount, corrupt =
                match firstBad with
                | None -> count, false
                | Some i -> i, (seq { i + 1 .. count - 1 } |> Seq.exists valid)

            if corrupt then
                Error $"slot marks corrupt: record {firstBad.Value} fails its checksum and later records are valid"
            elif goodCount = 0 then
                Error "slot marks have no valid header"
            else
                let record i = bytes.AsSpan(i * Record.size, Record.size).ToArray()
                let h = record 0

                if Record.kind h <> Record.KindHeader || Record.a h <> SlotRecord.formatTag then
                    Error "slot marks header is not slot marks format version 1"
                elif Root.Of(Record.payload h 32) <> gvr then
                    Error $"slot marks belong to genesis validators root {Root.Of(Record.payload h 32)}, not {gvr}"
                else
                    let keys = Dictionary<PubKey, SlotKeyState>()
                    let ids = List<SlotKeyState>()
                    let mutable error = ValueNone

                    for i in 1 .. goodCount - 1 do
                        if error.IsNone then
                            let r = record i
                            let id = int (Record.keyId r)

                            let markOf kind =
                                if id < ids.Count then
                                    ids[id].Marks <-
                                        SlotMarkRules.merge
                                            ids[id].Marks
                                            kind
                                            {
                                                Slot = Record.a r
                                                Root = Record.rootOf r
                                            }
                                else
                                    error <- ValueSome $"record {i}: unknown key id"

                            match Record.kind r with
                            | Record.KindKey ->
                                let key = PubKey.Of(Record.payload r 48)

                                if id <> ids.Count || keys.ContainsKey key then
                                    error <- ValueSome $"record {i}: key id out of sequence or key repeated"
                                else
                                    let s =
                                        {
                                            Id = uint32 id
                                            Key = key
                                            Marks = SlotKeyMarks.Empty
                                        }

                                    keys[key] <- s
                                    ids.Add s
                            | SlotRecord.KindPayloadAttestation -> markOf SlotMarkKind.PayloadAttestation
                            | SlotRecord.KindPayloadEnvelope -> markOf SlotMarkKind.PayloadEnvelope
                            | k -> error <- ValueSome $"record {i}: unknown kind {k}"

                    match error with
                    | ValueSome e -> Error $"slot marks corrupt: {e}"
                    | ValueNone ->
                        let keep = int64 goodCount * int64 Record.size
                        let truncated = int64 bytes.Length - keep

                        if truncated > 0L then
                            file.Truncate keep

                        Ok(
                            new SlotMarks(
                                file,
                                gvr,
                                keys,
                                ids,
                                {
                                    Records = goodCount
                                    Keys = keys.Count
                                    TruncatedBytes = truncated
                                }
                            )
                        )

    member _.OpenInfo = info
    member _.KeyCount = lock keys (fun () -> keys.Count)

    member _.Marks(key: PubKey) : SlotKeyMarks voption =
        lock keys (fun () ->
            match keys.TryGetValue key with
            | true, s -> ValueSome s.Marks
            | _ -> ValueNone)

    /// Checks a burst and makes the marks of every allowed request durable with one append and
    /// one fsync. A key seen for the first time gets its record in the same append. Verdicts are
    /// Allowed, Repeat, Refused or WriteFailed, never NoRecord. A failed write refuses everything
    /// until restart, as in the slashing DB.
    member _.CheckAndRecord(requests: SlotMarkRequest[], ct: CancellationToken) : Task<Verdict[]> =
        task {
            match failed with
            | ValueSome f -> return Array.create requests.Length (Verdict.WriteFailed $"slot marks failed earlier: {f}")
            | ValueNone ->
                do! gate.WaitAsync ct

                try
                    // Work on copies so a failed write leaves the marks as they were.
                    let working = Dictionary<PubKey, SlotKeyState>()
                    let fresh = List<SlotKeyState>()
                    let records = List<byte[]>()

                    let stateOf key =
                        match working.TryGetValue key with
                        | true, s -> s
                        | _ ->
                            let s =
                                match lock keys (fun () -> keys.TryGetValue key) with
                                | true, s -> { s with Marks = s.Marks }
                                | _ ->
                                    let s =
                                        {
                                            Id = uint32 (byId.Count + fresh.Count)
                                            Key = key
                                            Marks = SlotKeyMarks.Empty
                                        }

                                    fresh.Add s
                                    records.Add(SlotRecord.key s.Id key)
                                    s

                            working[key] <- s
                            s

                    let verdicts =
                        requests
                        |> Array.map (fun r ->
                            let s = stateOf r.Key

                            match SlotMarkRules.check s.Marks r.Kind r.Slot r.SigningRoot with
                            | Check.Allow ->
                                let x =
                                    {
                                        Slot = r.Slot
                                        Root = ValueSome r.SigningRoot
                                    }

                                s.Marks <- SlotMarkRules.merge s.Marks r.Kind x
                                records.Add(SlotRecord.mark s.Id r.Kind x)
                                Verdict.Allowed
                            | Check.Repeat -> Verdict.Repeat
                            | Check.Refuse why -> Verdict.Refused why)

                    match write records with
                    | Ok() ->
                        lock keys (fun () ->
                            for s in fresh do
                                keys[s.Key] <- s
                                byId.Add s

                            for KeyValue(k, w) in working do
                                keys[k].Marks <- w.Marks)

                        return verdicts
                    | Error e ->
                        // A Repeat may match a mark of an Allowed request earlier in this burst,
                        // and that mark is not durable now. Refuse both.
                        let why = $"slot marks write failed: {e}"

                        return
                            verdicts
                            |> Array.map (fun v ->
                                match v with
                                | Verdict.Allowed
                                | Verdict.Repeat -> Verdict.WriteFailed why
                                | other -> other)
                finally
                    gate.Release() |> ignore
        }

    /// Raises the PTC vote and envelope marks of each key to `slot`, with no root, for a key that
    /// starts with a floor record (Floor.fs). A higher mark stays. One append and one fsync.
    /// Waits on the gate without async: it runs only at an import or a key refresh that writes
    /// floors, off the signing path, and waits for at most one PTC burst's fsync.
    member _.RaiseFloor(floorKeys: PubKey list, slot: Slot) : Result<unit, string> =
        match failed with
        | ValueSome f -> Error $"slot marks failed earlier: {f}"
        | ValueNone ->
            gate.Wait()

            try
                let records = List<byte[]>()
                let fresh = List<SlotKeyState>()
                let updates = List<PubKey * SlotKeyMarks>()
                let x = { Slot = slot; Root = ValueNone }

                for key in List.distinct floorKeys do
                    let id, before =
                        match lock keys (fun () -> keys.TryGetValue key) with
                        | true, s -> s.Id, s.Marks
                        | _ ->
                            let s =
                                {
                                    Id = uint32 (byId.Count + fresh.Count)
                                    Key = key
                                    Marks = SlotKeyMarks.Empty
                                }

                            fresh.Add s
                            records.Add(SlotRecord.key s.Id key)
                            s.Id, s.Marks

                    let mutable after = before

                    for kind in [ SlotMarkKind.PayloadAttestation; SlotMarkKind.PayloadEnvelope ] do
                        let raised = SlotMarkRules.merge after kind x

                        if raised <> after then
                            after <- raised
                            records.Add(SlotRecord.mark id kind x)

                    updates.Add((key, after))

                match write records with
                | Error e -> Error $"slot marks write failed: {e}"
                | Ok() ->
                    lock keys (fun () ->
                        for s in fresh do
                            keys[s.Key] <- s
                            byId.Add s

                        for k, m in updates do
                            keys[k].Marks <- m)

                    Ok()
            finally
                gate.Release() |> ignore

    /// Rewrites the log as one record per key and mark (the snapshot). Atomic through IMarkFile.Replace.
    member _.Compact() : Result<unit, string> =
        gate.Wait()

        try
            try
                let records =
                    [
                        SlotRecord.header gvr
                        for s in byId do
                            SlotRecord.key s.Id s.Key
                        for s in byId do
                            match s.Marks.PayloadAttestation with
                            | ValueSome m -> SlotRecord.mark s.Id SlotMarkKind.PayloadAttestation m
                            | ValueNone -> ()

                            match s.Marks.PayloadEnvelope with
                            | ValueSome m -> SlotRecord.mark s.Id SlotMarkKind.PayloadEnvelope m
                            | ValueNone -> ()
                    ]

                file.Replace(Array.concat records)
                Ok()
            with e ->
                failed <- ValueSome e.Message
                Error $"slot marks compaction failed: {e.Message}"
        finally
            gate.Release() |> ignore

    interface IDisposable with
        member _.Dispose() = file.Dispose()
