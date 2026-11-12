/// The slashing protection DB, default mode: an append-only log of
/// fixed-size records with CRC32C, one append and one fsync per burst (group commit).
/// Write order: check, append, fsync, then the caller sends to the backend.
namespace Eplix.Slashing

open System
open System.Buffers.Binary
open System.Collections
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Eplix

/// How a key got its slashing record, kept in the key record.
type KeyOrigin =
    /// History imported from an EIP-3076 file.
    | Imported = 1uy
    /// Started by the operator's allow_start_without_history override, with a floor record
    /// (Floor.fs).
    | StartedEmpty = 2uy
    /// A floor record from `eplix import --no-signing-history` (Floor.fs).
    | Floor = 4uy

/// What SlashingDb.Import did with an interchange.
type ImportResult =
    {
        Entries: int
        /// New keys whose entry had no signed block and no signed attestation: no record written.
        NoHistory: PubKey list
    }

type SlashingRequest =
    | BlockRequest of key: PubKey * slot: Slot * signingRoot: Root
    | AttestationRequest of key: PubKey * source: Epoch * target: Epoch * signingRoot: Root

    member this.Key =
        match this with
        | BlockRequest(k, _, _) -> k
        | AttestationRequest(k, _, _, _) -> k

[<RequireQualifiedAccess>]
type Verdict =
    /// The mark is durable; the caller may send.
    | Allowed
    /// An exact repeat of the last message; nothing written.
    | Repeat
    | Refused of reason: string
    /// The key has no slashing record yet; it must not sign.
    | NoRecord
    /// The write failed. The DB refuses everything until restart.
    | WriteFailed of reason: string

module Record =
    let size = 80

    [<Literal>]
    let KindHeader = 1uy

    [<Literal>]
    let KindKey = 2uy

    [<Literal>]
    let KindBlock = 3uy

    [<Literal>]
    let KindAttestation = 4uy

    let formatVersion = 1UL
    let private flagRoot = 1uy

    // Layout: 0 kind, 1 flags, 2-3 zero, 4-7 key id, 8-15 a, 16-23 b,
    // 24-71 payload (pubkey, or root + root source), 72-75 zero, 76-79 CRC32C of bytes 0-75.

    let crc (r: ReadOnlySpan<byte>) : uint32 =
        let mutable c = 0xFFFFFFFFu

        for i in 0..8 do
            c <- Numerics.BitOperations.Crc32C(c, BinaryPrimitives.ReadUInt64LittleEndian(r.Slice(i * 8, 8)))

        c <- Numerics.BitOperations.Crc32C(c, BinaryPrimitives.ReadUInt32LittleEndian(r.Slice(72, 4)))
        ~~~c

    let make kind flags (keyId: uint32) (a: uint64) (b: uint64) (payload: ReadOnlySpan<byte>) =
        let r = Array.zeroCreate<byte> size
        r[0] <- kind
        r[1] <- flags
        BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(4), keyId)
        BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(8), a)
        BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(16), b)
        payload.CopyTo(r.AsSpan(24, 48))
        BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(76), crc (ReadOnlySpan r))
        r

    let header (gvr: Root) = make KindHeader 0uy 0u formatVersion 0UL (ReadOnlySpan gvr.Bytes)

    let key (id: uint32) (pubkey: PubKey) (origin: KeyOrigin) =
        make KindKey 0uy id (uint64 origin) 0UL (ReadOnlySpan pubkey.Bytes)

    let block (id: uint32) (m: BlockMark) =
        match m.Root with
        | ValueSome r -> make KindBlock flagRoot id m.Slot 0UL (ReadOnlySpan r.Bytes)
        | ValueNone -> make KindBlock 0uy id m.Slot 0UL ReadOnlySpan.Empty

    let attestation (id: uint32) (m: AttestationMark) =
        let payload = Array.zeroCreate<byte> 48
        m.Root |> ValueOption.iter (fun r -> Buffer.BlockCopy(r.Bytes, 0, payload, 0, 32))
        BinaryPrimitives.WriteUInt64LittleEndian(payload.AsSpan(32), m.RootSource)
        make KindAttestation (if m.Root.IsSome then flagRoot else 0uy) id m.Source m.Target (ReadOnlySpan payload)

    let isValid (r: ReadOnlySpan<byte>) = r.Length = size && BinaryPrimitives.ReadUInt32LittleEndian(r.Slice 76) = crc r

    let kind (r: byte[]) = r[0]
    let keyId (r: byte[]) = BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(r, 4, 4))
    let a (r: byte[]) = BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(r, 8, 8))
    let b (r: byte[]) = BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(r, 16, 8))
    let hasRoot (r: byte[]) = r[1] &&& flagRoot <> 0uy
    let payload (r: byte[]) (n: int) = r.AsSpan(24, n).ToArray()

    let rootOf (r: byte[]) = if hasRoot r then ValueSome(Root.Of(payload r 32)) else ValueNone

    let rootSource (r: byte[]) = BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(r, 56, 8))

type private KeyState =
    {
        Id: uint32
        Key: PubKey
        Origin: KeyOrigin
        Lock: SemaphoreSlim
        mutable Marks: KeyMarks
    }

/// Equality of marks field by field. F#'s structural `=` on KeyMarks boxes its value options
/// and allocates on each call; merge compares once or twice per entry.
module internal MarksEquality =
    let private root (a: Root voption) (b: Root voption) =
        match a, b with
        | ValueNone, ValueNone -> true
        | ValueSome x, ValueSome y -> x.Bytes.AsSpan().SequenceEqual(ReadOnlySpan y.Bytes)
        | _ -> false

    let same (a: KeyMarks) (b: KeyMarks) =
        (match a.Block, b.Block with
         | ValueNone, ValueNone -> true
         | ValueSome x, ValueSome y -> x.Slot = y.Slot && root x.Root y.Root
         | _ -> false)
        && (match a.Attestation, b.Attestation with
            | ValueNone, ValueNone -> true
            | ValueSome x, ValueSome y ->
                x.Source = y.Source && x.Target = y.Target && x.RootSource = y.RootSource && root x.Root y.Root
            | _ -> false)

    let isEmpty (m: KeyMarks) = m.Block.IsNone && m.Attestation.IsNone

type OpenInfo =
    {
        Records: int
        Keys: int
        /// Bytes cut from a torn tail: records that were appended but never synced.
        TruncatedBytes: int64
    }

type SlashingDb
    private (file: IMarkFile, gvr: Root, keys: Concurrent.ConcurrentDictionary<PubKey, KeyState>, info: OpenInfo) =
    let byId = List<KeyState>(keys.Values |> Seq.sortBy (fun k -> k.Id))
    let appendGate = new SemaphoreSlim(1, 1)
    let mutable failed: string voption = ValueNone

    /// Appends and syncs under the append gate, then runs `apply` (the in-memory update) still
    /// under the gate, so a snapshot never sees records on disk without their marks in memory.
    /// Any exception from the write poisons the DB. Checks `failed` again under the gate: another
    /// write may have failed after the caller's own check, and nothing may land after that.
    let write (records: byte[] list) (apply: unit -> unit) =
        appendGate.Wait()

        try
            match failed with
            | ValueSome f -> failwith $"slashing DB failed earlier: {f}"
            | ValueNone -> ()

            if not records.IsEmpty then
                try
                    file.Append(Array.concat records)
                    file.Sync()
                with e ->
                    failed <- ValueSome e.Message
                    reraise ()

            apply ()
        finally
            appendGate.Release() |> ignore

    /// Merges marks per key: maximum per field, marks never go down. Keys new to the DB get a
    /// record with `origin`, except an imported key with no marks at all: an empty interchange
    /// entry is no history, and no path starts a key with an empty record. Returns
    /// those keys. Holds the per-key locks of the keys it touches, in key id order, as
    /// CheckAndRecord does, so it is safe while the VC runs. One fsync.
    let merge (origin: KeyOrigin) (entries: (PubKey * KeyMarks) list) : Result<PubKey list, string> =
        match failed with
        | ValueSome f -> Error $"slashing DB failed earlier: {f}"
        | ValueNone ->
            lock keys (fun () ->
                let touched =
                    entries
                    |> List.choose (fun (k, _) ->
                        match keys.TryGetValue k with
                        | true, s -> Some s
                        | _ -> None)
                    |> List.distinctBy (fun s -> s.Id)
                    |> List.sortBy (fun s -> s.Id)

                for s in touched do
                    s.Lock.Wait()

                try
                    let records = List<byte[]>()
                    // New keys in id order, and by key for the lookups, so the merge stays linear in the new keys.
                    let newStates = List<KeyState>()
                    let newByKey = Dictionary<PubKey, KeyState>()
                    let updates = Dictionary<uint32, KeyMarks>()

                    let stateOf key =
                        match keys.TryGetValue key with
                        | true, s -> s
                        | _ ->
                            match newByKey.TryGetValue key with
                            | true, s -> s
                            | _ ->
                                let s =
                                    {
                                        Id = uint32 (byId.Count + newStates.Count)
                                        Key = key
                                        Origin = origin
                                        Lock = new SemaphoreSlim(1, 1)
                                        Marks = KeyMarks.Empty
                                    }

                                newStates.Add s
                                newByKey.Add(key, s)
                                records.Add(Record.key s.Id s.Key s.Origin)
                                s

                    let isNew key = not (keys.ContainsKey key) && not (newByKey.ContainsKey key)
                    let noHistory = List<PubKey>()

                    for key, marks in entries do
                        if origin = KeyOrigin.Imported && MarksEquality.isEmpty marks && isNew key then
                            noHistory.Add key
                        else
                            let s = stateOf key

                            let before =
                                match updates.TryGetValue s.Id with
                                | true, m -> m
                                | _ -> s.Marks

                            let mutable after = before
                            marks.Block |> ValueOption.iter (fun b -> after <- Marks.mergeBlock after b)
                            marks.Attestation |> ValueOption.iter (fun a -> after <- Marks.mergeAttestation after a)

                            if not (MarksEquality.same after before) then
                                updates[s.Id] <- after
                                marks.Block |> ValueOption.iter (fun b -> records.Add(Record.block s.Id b))
                                marks.Attestation |> ValueOption.iter (fun a -> records.Add(Record.attestation s.Id a))

                    try
                        write (List.ofSeq records) (fun () ->
                            for s in newStates do
                                keys[s.Key] <- s
                                byId.Add s

                            for KeyValue(id, m) in updates do
                                byId[int id].Marks <- m)
                        // A later entry with marks may have given the key a record.
                        Ok(noHistory |> Seq.distinct |> Seq.filter (fun k -> not (keys.ContainsKey k)) |> List.ofSeq)
                    with e ->
                        Error $"slashing DB write failed: {e.Message}"
                finally
                    for s in touched do
                        s.Lock.Release() |> ignore)

    /// Opens or creates the DB. Replays the log, cuts a torn tail, checks the genesis validators root.
    static member Open(file: IMarkFile, gvr: Root) : Result<SlashingDb, string> =
        let bytes = file.ReadAll()

        if bytes.Length = 0 then
            file.Append(Record.header gvr)
            file.Sync()

            Ok(
                new SlashingDb(
                    file,
                    gvr,
                    Concurrent.ConcurrentDictionary(),
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
            // The first invalid record starts the torn tail, unless a valid record follows it.
            let firstBad = seq { 0 .. count - 1 } |> Seq.tryFind (valid >> not)

            let goodCount, corrupt =
                match firstBad with
                | None -> count, false
                | Some i -> i, (seq { i + 1 .. count - 1 } |> Seq.exists valid)

            if corrupt then
                Error $"slashing DB corrupt: record {firstBad.Value} fails its checksum and later records are valid"
            elif goodCount = 0 then
                Error "slashing DB has no valid header"
            else
                let record i = bytes.AsSpan(i * Record.size, Record.size).ToArray()
                let h = record 0

                if Record.kind h <> Record.KindHeader || Record.a h <> Record.formatVersion then
                    Error "slashing DB header is not format version 1"
                elif Root.Of(Record.payload h 32) <> gvr then
                    Error $"slashing DB belongs to genesis validators root {Root.Of(Record.payload h 32)}, not {gvr}"
                else
                    let keys = Concurrent.ConcurrentDictionary<PubKey, KeyState>()
                    let ids = List<KeyState>()
                    let mutable error = ValueNone

                    for i in 1 .. goodCount - 1 do
                        if error.IsNone then
                            let r = record i

                            let byId () =
                                let id = int (Record.keyId r)
                                if id < ids.Count then ValueSome ids[id] else ValueNone

                            match Record.kind r with
                            | Record.KindKey ->
                                let key = PubKey.Of(Record.payload r 48)

                                if int (Record.keyId r) <> ids.Count || keys.ContainsKey key then
                                    error <- ValueSome $"record {i}: key id out of sequence or key repeated"
                                else
                                    let s =
                                        {
                                            Id = Record.keyId r
                                            Key = key
                                            Origin = LanguagePrimitives.EnumOfValue<byte, KeyOrigin>(byte (Record.a r))
                                            Lock = new SemaphoreSlim(1, 1)
                                            Marks = KeyMarks.Empty
                                        }

                                    keys[key] <- s
                                    ids.Add s
                            | Record.KindBlock ->
                                match byId () with
                                | ValueSome s ->
                                    s.Marks <-
                                        Marks.mergeBlock
                                            s.Marks
                                            {
                                                Slot = Record.a r
                                                Root = Record.rootOf r
                                            }
                                | ValueNone -> error <- ValueSome $"record {i}: unknown key id"
                            | Record.KindAttestation ->
                                match byId () with
                                | ValueSome s ->
                                    s.Marks <-
                                        Marks.mergeAttestation
                                            s.Marks
                                            {
                                                Source = Record.a r
                                                Target = Record.b r
                                                Root = Record.rootOf r
                                                RootSource = Record.rootSource r
                                            }
                                | ValueNone -> error <- ValueSome $"record {i}: unknown key id"
                            | k -> error <- ValueSome $"record {i}: unknown kind {k}"

                    match error with
                    | ValueSome e -> Error $"slashing DB corrupt: {e}"
                    | ValueNone ->
                        let keep = int64 goodCount * int64 Record.size
                        let truncated = int64 bytes.Length - keep

                        if truncated > 0L then
                            file.Truncate keep

                        Ok(
                            new SlashingDb(
                                file,
                                gvr,
                                keys,
                                {
                                    Records = goodCount
                                    Keys = keys.Count
                                    TruncatedBytes = truncated
                                }
                            )
                        )

    member _.GenesisValidatorsRoot = gvr
    member _.OpenInfo = info
    member _.HasRecord(key: PubKey) = keys.ContainsKey key
    /// Under the lock the writers hold: merge and RegisterKeys add to byId while the VC runs.
    member _.Keys: PubKey list = lock keys (fun () -> [ for s in byId -> s.Key ])

    member _.Origin(key: PubKey) : KeyOrigin voption =
        match keys.TryGetValue key with
        | true, s -> ValueSome s.Origin
        | _ -> ValueNone

    member _.Marks(key: PubKey) : KeyMarks voption =
        match keys.TryGetValue key with
        | true, s -> ValueSome s.Marks
        | _ -> ValueNone

    /// Gives keys an empty slashing record. Keys that already have one are skipped. One fsync.
    /// Tests and benchmarks only: the VC starts a key with no history only through a floor
    /// (RaiseFloor).
    member internal _.RegisterKeys(newKeys: (PubKey * KeyOrigin) list) : Result<int, string> =
        match failed with
        | ValueSome f -> Error $"slashing DB failed earlier: {f}"
        | ValueNone ->
            lock keys (fun () ->
                let fresh = newKeys |> List.distinctBy fst |> List.filter (fun (k, _) -> not (keys.ContainsKey k))

                let states =
                    fresh
                    |> List.mapi (fun i (k, origin) ->
                        {
                            Id = uint32 (byId.Count + i)
                            Key = k
                            Origin = origin
                            Lock = new SemaphoreSlim(1, 1)
                            Marks = KeyMarks.Empty
                        })

                try
                    write [ for s in states -> Record.key s.Id s.Key s.Origin ] (fun () ->
                        for s in states do
                            keys[s.Key] <- s
                            byId.Add s)

                    Ok states.Length
                with e ->
                    Error $"slashing DB write failed: {e.Message}")

    /// Checks a burst and makes the marks of every allowed request durable with one append and
    /// one fsync. Locks are per key, taken in key id order.
    member _.CheckAndRecord(requests: SlashingRequest[], ct: CancellationToken) : Task<Verdict[]> =
        task {
            match failed with
            | ValueSome f ->
                return Array.create requests.Length (Verdict.WriteFailed $"slashing DB failed earlier: {f}")
            | ValueNone ->
                let states =
                    requests
                    |> Array.choose (fun r ->
                        match keys.TryGetValue r.Key with
                        | true, s -> Some s
                        | _ -> None)
                    |> Array.distinctBy (fun s -> s.Id)
                    |> Array.sortBy (fun s -> s.Id)

                let taken = List<KeyState>()

                try
                    for s in states do
                        do! s.Lock.WaitAsync ct
                        taken.Add s
                    // Work on copies so a failed write leaves the marks as they were.
                    let working = Dictionary<uint32, KeyMarks>()

                    for s in states do
                        working[s.Id] <- s.Marks

                    let records = List<byte[]>()

                    let verdicts =
                        requests
                        |> Array.map (fun r ->
                            match keys.TryGetValue r.Key with
                            | false, _ -> Verdict.NoRecord
                            | true, s ->
                                let m = working[s.Id]

                                match r with
                                | BlockRequest(_, slot, root) ->
                                    match Marks.checkBlock m slot root with
                                    | Check.Allow ->
                                        let x = { Slot = slot; Root = ValueSome root }
                                        working[s.Id] <- Marks.mergeBlock m x
                                        records.Add(Record.block s.Id x)
                                        Verdict.Allowed
                                    | Check.Repeat -> Verdict.Repeat
                                    | Check.Refuse why -> Verdict.Refused why
                                | AttestationRequest(_, source, target, root) ->
                                    match Marks.checkAttestation m source target root with
                                    | Check.Allow ->
                                        let x = Marks.vote source target root
                                        working[s.Id] <- Marks.mergeAttestation m x
                                        records.Add(Record.attestation s.Id x)
                                        Verdict.Allowed
                                    | Check.Repeat -> Verdict.Repeat
                                    | Check.Refuse why -> Verdict.Refused why)

                    try
                        write (List.ofSeq records) (fun () ->
                            for s in states do
                                s.Marks <- working[s.Id])

                        return verdicts
                    with e ->
                        // A Repeat may match a mark of an Allowed request earlier in this burst
                        // (the same request twice), and that mark is not durable now. Refuse both.
                        let why = $"slashing DB write failed: {e.Message}"

                        return
                            verdicts
                            |> Array.map (fun v ->
                                match v with
                                | Verdict.Allowed
                                | Verdict.Repeat -> Verdict.WriteFailed why
                                | other -> other)
                finally
                    for s in taken do
                        s.Lock.Release() |> ignore
        }

    /// Merges an interchange into the DB: maximum per field, marks never go down. One fsync.
    /// Keys new to the DB get a record with origin Imported, except keys whose entry has no
    /// signed block and no signed attestation: they get none and stay without history. Safe
    /// while the VC runs: it holds the per-key locks of the keys it touches, in key id order, as
    /// CheckAndRecord does.
    member _.Import(x: Interchange) : Result<ImportResult, string> =
        if x.GenesisValidatorsRoot <> gvr then
            Error $"interchange is for genesis validators root {x.GenesisValidatorsRoot}, the DB for {gvr}"
        else
            merge KeyOrigin.Imported [ for e in x.Data -> e.PubKey, Interchange.marksOf e ]
            |> Result.map (fun empty ->
                {
                    Entries = x.Data.Length
                    NoHistory = empty
                })

    /// Merges the marks an InterchangeReader kept, as Import merges a parsed interchange: the
    /// same records, maximum per field, one fsync.
    member _.ImportMarks(x: InterchangeMarks) : Result<ImportResult, string> =
        if x.GenesisValidatorsRoot <> gvr then
            Error $"interchange is for genesis validators root {x.GenesisValidatorsRoot}, the DB for {gvr}"
        else
            merge KeyOrigin.Imported x.Marks
            |> Result.map (fun empty ->
                {
                    Entries = x.Entries
                    NoHistory = empty
                })

    /// Writes a floor record (Floor.marks) for each key: a key new to the DB gets one with
    /// `origin`; a key with a record keeps the higher of each mark. One fsync.
    member _.RaiseFloor(floorKeys: PubKey list, origin: KeyOrigin, floor: KeyMarks) : Result<unit, string> =
        merge origin [ for k in List.distinct floorKeys -> k, floor ] |> Result.map ignore

    /// The minimal interchange for the given keys, or for every key.
    member _.Export(only: PubKey list voption) : Interchange =
        let selected =
            match only with
            | ValueSome ks ->
                [
                    for k in ks do
                        match keys.TryGetValue k with
                        | true, s -> s
                        | _ -> ()
                ]
            | ValueNone -> lock keys (fun () -> List.ofSeq byId)

        {
            GenesisValidatorsRoot = gvr
            Data = [ for s in selected -> Interchange.entryOf s.Key s.Marks ]
        }

    /// Rewrites the log as one record per key and mark (the snapshot). Atomic through IMarkFile.Replace.
    member _.Compact() : Result<unit, string> =
        lock keys (fun () ->
            appendGate.Wait()

            try
                try
                    let records =
                        [
                            Record.header gvr
                            for s in byId do
                                Record.key s.Id s.Key s.Origin
                            for s in byId do
                                match s.Marks.Block with
                                | ValueSome b -> Record.block s.Id b
                                | ValueNone -> ()

                                match s.Marks.Attestation with
                                | ValueSome a -> Record.attestation s.Id a
                                | ValueNone -> ()
                        ]

                    file.Replace(Array.concat records)
                    Ok()
                with e ->
                    failed <- ValueSome e.Message
                    Error $"slashing DB compaction failed: {e.Message}"
            finally
                appendGate.Release() |> ignore)

    interface IDisposable with
        member _.Dispose() = file.Dispose()
