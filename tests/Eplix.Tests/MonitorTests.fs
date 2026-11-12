/// The validator monitor: bit offsets across committees, block, rewards and balance decoding, and
/// the whole VC on the fake beacon node with the exported metric text checked.
module Eplix.Tests.MonitorTests

open System
open System.IO
open System.Net.Http
open System.Text.Json
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Json
open Eplix.Backend.Local
open Eplix.Metrics
open Eplix.Monitor
open Eplix.Monitor.Chain
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.MetricsTests

let private preset = Preset.Minimal
let private signature = Array.init 96 (fun i -> if i = 0 then 0xC0uy else 0uy)

let private data (slot: Slot) : AttestationData =
    {
        Slot = slot
        Index = 0UL
        BeaconBlockRoot = root 1
        Source = { Epoch = 0UL; Root = root 2 }
        Target = { Epoch = 0UL; Root = root 3 }
    }

/// A signed block in the Beacon API JSON form (GET /eth/v2/beacon/blocks), written by the core
/// SSZ JSON writer from the schema of its fork.
let private blockJson
    (version: string)
    (slot: Slot)
    (proposer: uint64)
    (atts: (Slot * bool[] * bool[]) list)
    (sync: bool[])
    =
    let gloas = version = "gloas"
    let schema = if gloas then Schemas.Gloas.signedBeaconBlock preset else Schemas.signedBeaconBlock preset

    let value =
        match Ssz.zero schema with
        | Ssz.Fields sf ->
            let message = Codec.fields sf[0]
            message[0] <- Ssz.U slot
            message[1] <- Ssz.U proposer
            let body = Codec.fields message[4]

            body[5] <-
                Ssz.Items
                    [|
                        for s, bits, committees in atts ->
                            Ssz.Fields
                                [|
                                    Ssz.Bits bits
                                    Codec.attestationDataValue (data s)
                                    Ssz.Bytes signature
                                    Ssz.Bits committees
                                |]
                    |]

            body[8] <- Ssz.Fields [| Ssz.Bits sync; Ssz.Bytes signature |]
            Ssz.Fields sf
        | v -> v

    toBytes (fun w ->
        w.WriteStartObject()
        w.WriteString("version", version)
        w.WriteBoolean("execution_optimistic", false)
        w.WritePropertyName "data"
        SszJson.write w schema value
        w.WriteEndObject())

let private read (json: byte[]) =
    match decodeBytes (readBlock preset) (ReadOnlyMemory json) with
    | Ok r -> r
    | Error e -> failtestf "decode: %s" e

let private committeeBits (set: int list) = Array.init preset.MaxCommitteesPerSlot (fun i -> List.contains i set)

/// Committees of random sizes, a random subset of them in one aggregate, and random bits.
let private genAggregate =
    gen {
        let! sizes = Gen.listOfLength preset.MaxCommitteesPerSlot (Gen.choose (1, 20))

        let! chosen =
            Gen.subListOf [ 0 .. preset.MaxCommitteesPerSlot - 1 ] |> Gen.filter (fun l -> not l.IsEmpty)

        let total = chosen |> List.sumBy (fun c -> sizes[c])
        let! bits = Gen.arrayOfLength total (Gen.elements [ true; false ])
        return sizes, List.sort chosen, bits
    }

let private section (json: string) =
    {
        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
        BaseDir = "/"
        Mainnet = false
    }

/// The block and committee readers as they were before the Utf8JsonReader ones, over a parsed
/// document: the reference the new readers must match.
module private Reference =
    let private beforeElectra = set [ "phase0"; "altair"; "bellatrix"; "capella"; "deneb" ]
    let private fromElectra = set [ "electra"; "fulu"; "gloas" ]

    let readBlock (preset: Preset) (e: JsonElement) : BlockRead =
        try
            let version = (strField e "version").ToLowerInvariant()

            if not (beforeElectra.Contains version || fromElectra.Contains version) then
                BlockRead.Unknown $"block version '{version}'"
            else
                let message = prop (prop e "data") "message"
                let body = prop message "body"

                let attestation (a: JsonElement) =
                    let data = prop a "data"

                    let bits =
                        match bitlist (strField a "aggregation_bits") with
                        | ValueSome b -> b
                        | ValueNone -> fail "aggregation_bits is not a bitlist"

                    let committees =
                        if fromElectra.Contains version then
                            match bitvector preset.MaxCommitteesPerSlot (strField a "committee_bits") with
                            | ValueSome c ->
                                [|
                                    for i in 0 .. c.Length - 1 do
                                        if c[i] then
                                            uint64 i
                                |]
                            | ValueNone -> fail "committee_bits is not a bitvector"
                        else
                            [| u64Field data "index" |]

                    {
                        Slot = u64Field data "slot"
                        Committees = committees
                        Bits = bits
                    }

                let sync =
                    match tryProp body "sync_aggregate" with
                    | ValueSome s ->
                        match bitvector preset.SyncCommitteeSize (strField s "sync_committee_bits") with
                        | ValueSome b -> ValueSome b
                        | ValueNone -> fail "sync_committee_bits is not a bitvector"
                    | ValueNone -> ValueNone

                BlockRead.Block
                    {
                        Slot = u64Field message "slot"
                        ProposerIndex = u64Field message "proposer_index"
                        Attestations = array (prop body "attestations") |> Array.map attestation
                        SyncBits = sync
                    }
        with :? JsonDecodeError as x ->
            BlockRead.Unknown x.Message

    let readCommittees (e: JsonElement) : (Slot * uint64 * int)[] =
        array (prop e "data")
        |> Array.map (fun c -> u64Field c "slot", u64Field c "index", (array (prop c "validators")).Length)

/// What a reader gave, with the messages of errors and unknown blocks left out: those may differ.
let private outcome (r: Result<'T, string>) (shape: 'T -> 'S) : string =
    match r with
    | Ok v -> $"ok %A{shape v}"
    | Error _ -> "error"

let private blockShape (b: BlockRead) =
    match b with
    | BlockRead.Block b -> box b
    | BlockRead.Unknown _ -> box "unknown"

let private sameBlock (p: Preset) (json: byte[]) =
    let old = outcome (decode (Reference.readBlock p) (ReadOnlyMemory json)) blockShape
    let now = outcome (decodeBytes (readBlock p) (ReadOnlyMemory json)) blockShape
    old, now

let private sameCommittees (json: byte[]) =
    let old = outcome (decode Reference.readCommittees (ReadOnlyMemory json)) id
    let now = outcome (decodeBytes readCommittees (ReadOnlyMemory json)) id
    old, now

/// One random change to a JSON value: object fields reordered, a field dropped, a value set to
/// null, a scalar replaced by another kind, or a hex string cut short.
let private mutate (rnd: Random) (root: Nodes.JsonNode) =
    let nodes = ResizeArray<Nodes.JsonNode>()

    let rec walk (n: Nodes.JsonNode) =
        if not (isNull n) then
            nodes.Add n

            match n with
            | :? Nodes.JsonObject as o ->
                for KeyValue(_, v) in List.ofSeq o do
                    walk v
            | :? Nodes.JsonArray as a ->
                for v in List.ofSeq a do
                    walk v
            | _ -> ()

    walk root
    let n = nodes[rnd.Next nodes.Count]

    match n with
    | :? Nodes.JsonObject as o when o.Count > 0 ->
        let fields = List.ofSeq o

        match rnd.Next 3 with
        | 0 ->
            o.Clear()

            for KeyValue(k, v) in fields |> List.sortBy (fun _ -> rnd.Next()) do
                o[k] <- v
        | 1 -> o.Remove(fields[rnd.Next fields.Length].Key) |> ignore
        | _ -> o[fields[rnd.Next fields.Length].Key] <- null
    | :? Nodes.JsonValue as v when not (isNull n.Parent) ->
        let replacement: Nodes.JsonNode =
            match rnd.Next 5 with
            | 0 -> Nodes.JsonValue.Create(rnd.Next 100)
            | 1 -> Nodes.JsonValue.Create true
            | 2 -> Nodes.JsonObject()
            | 3 -> Nodes.JsonValue.Create "12"
            | _ ->
                let text = v.ToJsonString().Trim('"')
                Nodes.JsonValue.Create(text.Substring(0, text.Length / 2))

        match n.Parent with
        | :? Nodes.JsonObject as o -> o[n.GetPropertyName()] <- replacement
        | :? Nodes.JsonArray as a -> a[n.GetElementIndex()] <- replacement
        | _ -> ()
    | _ -> ()

let private recorded (name: string) = File.ReadAllBytes(Path.Combine(fixtures, "beacon", name))

[<Tests>]
let tests =
    testList
        "monitor"
        [
            test "the Utf8JsonReader readers match the document readers on the recorded block and committees" {
                let block = recorded "monitor_block_fulu.json"
                let old, now = sameBlock Preset.Mainnet block
                Expect.stringStarts old "ok" "the recorded block reads"
                Expect.equal now old "same block"

                match decodeBytes (readBlock Preset.Mainnet) (ReadOnlyMemory block) with
                | Ok(BlockRead.Block b) -> Expect.equal b.Attestations.Length 8 "eight aggregates"
                | r -> failtestf "%A" r

                let committees = recorded "monitor_committees.json"
                let old, now = sameCommittees committees
                Expect.equal now old "same committees"

                match decodeBytes readCommittees (ReadOnlyMemory committees) with
                | Ok cs ->
                    Expect.equal
                        (cs |> Array.map (fun (_, _, n) -> n) |> Array.distinct)
                        [| 500 |]
                        "64 committees of 500"
                | Error e -> failtest e
            }

            test "the Utf8JsonReader readers match the document readers on changed and broken input" {
                let rnd = Random 11
                let sync = Array.init preset.SyncCommitteeSize (fun i -> i % 3 = 0)

                let blocks =
                    [
                        for version in [ "deneb"; "electra"; "fulu"; "gloas" ] ->
                            blockJson
                                version
                                7UL
                                42UL
                                [
                                    6UL, [| true; false; true; true |], committeeBits [ 1; 3 ]
                                    5UL, [| true |], committeeBits [ 0 ]
                                ]
                                sync
                    ]

                let committees =
                    Text.Encoding.UTF8.GetBytes
                        """{ "execution_optimistic": false, "data": [ { "index": "0", "slot": "40", "validators": [ "1", "2", "3" ] },
                           { "slot": "40", "index": "1", "validators": [] } ] }"""

                let changed (json: byte[]) =
                    let node = Nodes.JsonNode.Parse(json)

                    for _ in 0 .. rnd.Next 3 do
                        mutate rnd node

                    Text.Encoding.UTF8.GetBytes(node.ToJsonString())

                let broken (json: byte[]) =
                    match rnd.Next 4 with
                    | 0 -> json[.. rnd.Next json.Length - 1]
                    | 1 -> Array.append json "x"B
                    | 2 -> Array.append json " {}"B
                    | _ -> [||]

                let mutable outcomes = Set.empty

                for i in 0..3999 do
                    let block = blocks[i % blocks.Length]
                    let json = if i % 10 = 9 then broken block else changed block
                    let old, now = sameBlock preset json
                    Expect.equal now old $"block case {i}: {Text.Encoding.UTF8.GetString json}"
                    outcomes <- outcomes.Add(old.Split(' ')[0] + (if old.Contains "unknown" then " unknown" else ""))
                    let json = if i % 10 = 9 then broken committees else changed committees
                    let old, now = sameCommittees json
                    Expect.equal now old $"committees case {i}: {Text.Encoding.UTF8.GetString json}"

                Expect.equal
                    outcomes
                    (set [ "ok"; "ok unknown"; "error" ])
                    "the cases reach blocks, unknown blocks and errors"
            }

            test "reading the recorded committees allocates no large object" {
                let committees = recorded "monitor_committees.json"
                decodeBytes readCommittees (ReadOnlyMemory committees) |> ignore
                let before = GC.GetAllocatedBytesForCurrentThread()

                for _ in 1..10 do
                    decodeBytes readCommittees (ReadOnlyMemory committees) |> ignore

                let each = (GC.GetAllocatedBytesForCurrentThread() - before) / 10L
                // The document reader allocated about 1.5 MB per read here.
                Expect.isLessThan each 85_000L $"{each} bytes per read, below the 85 KB of one large object"
            }

            testProp "a bitlist reads back as the SSZ codec wrote it"
            <| fun (bits: bool[]) ->
                let hex = Hex.encodeArray (Ssz.serialize (Ssz.Bitlist 4096) (Ssz.Bits bits))
                bitlist hex = ValueSome bits

            testProp "a bitvector reads back as the SSZ codec wrote it"
            <| fun (NonEmptyArray(bits: bool[])) ->
                let hex = Hex.encodeArray (Ssz.serialize (Ssz.Bitvector bits.Length) (Ssz.Bits bits))
                bitvector bits.Length hex = ValueSome bits

            test "malformed bits" {
                Expect.equal (bitlist "0x00") ValueNone "no length bit"
                Expect.equal (bitlist "0x") ValueNone "no bytes"
                Expect.equal (bitlist "0x01") (ValueSome [||]) "empty list"
                Expect.equal (bitlist "zz") ValueNone "not hex"
                Expect.equal (bitvector 4 "0x0f00") ValueNone "too many bytes"
            }

            testProp "each attester reads its own bit, after the committees before it"
            <| Prop.forAll (Arb.fromGen genAggregate) (fun (sizes, chosen, bits) ->
                let a =
                    {
                        Slot = 5UL
                        Committees = chosen |> List.map uint64 |> Array.ofList
                        Bits = bits
                    }

                let sizeOf (c: uint64) = ValueSome sizes[int c]
                let mutable offset = 0
                let mutable ok = true

                for c in chosen do
                    for p in 0 .. sizes[c] - 1 do
                        ok <- ok && voted a sizeOf (uint64 c) (uint64 p) = Ok bits[offset + p]

                    offset <- offset + sizes[c]
                // A committee not in the aggregate has no vote in it.
                for c in 0 .. preset.MaxCommitteesPerSlot - 1 do
                    if not (List.contains c chosen) then
                        ok <- ok && voted a sizeOf (uint64 c) 0UL = Ok false

                ok)

            test "committee sizes" {
                let one =
                    {
                        Slot = 3UL
                        Committees = [| 2UL |]
                        Bits = [| false; true; false |]
                    }

                Expect.equal (voted one (fun _ -> ValueNone) 2UL 1UL) (Ok true) "one committee needs no sizes"
                Expect.isError (voted one (fun _ -> ValueNone) 2UL 3UL) "position past the bits"

                let two =
                    {
                        Slot = 3UL
                        Committees = [| 0UL; 2UL |]
                        Bits = Array.create 5 false
                    }

                Expect.isError (voted two (fun _ -> ValueNone) 2UL 0UL) "two committees need sizes"
                Expect.isError (voted two (fun _ -> ValueSome 2) 2UL 0UL) "sizes that do not add up"

                Expect.isError
                    (voted two (fun c -> ValueSome(if c = 0UL then 2 else 3)) 2UL 3UL)
                    "position past the committee"

                Expect.equal (voted two (fun c -> ValueSome(if c = 0UL then 2 else 3)) 2UL 2UL) (Ok false) "in range"
                Expect.equal (distance 10UL 11UL) 1UL "next slot"
                Expect.equal (distance 10UL 42UL) 32UL "an epoch later"
            }

            test "blocks of Electra, Fulu and Gloas" {
                let sync = Array.init preset.SyncCommitteeSize (fun i -> i % 3 = 0)

                for version in [ "electra"; "fulu"; "gloas" ] do
                    let atts =
                        [
                            6UL, [| true; false; true; true |], committeeBits [ 1; 3 ]
                            5UL, [| true |], committeeBits [ 0 ]
                        ]

                    match read (blockJson version 7UL 42UL atts sync) with
                    | BlockRead.Block b ->
                        Expect.equal b.Slot 7UL $"{version}: slot"
                        Expect.equal b.ProposerIndex 42UL $"{version}: proposer"
                        Expect.equal b.Attestations.Length 2 $"{version}: attestations"

                        Expect.equal
                            b.Attestations[0]
                            {
                                Slot = 6UL
                                Committees = [| 1UL; 3UL |]
                                Bits = [| true; false; true; true |]
                            }
                            version

                        Expect.equal b.Attestations[1].Committees [| 0UL |] version
                        Expect.equal b.SyncBits (ValueSome sync) $"{version}: sync bits"
                    | BlockRead.Unknown why -> failtestf "%s: %s" version why
            }

            test "a block before Electra names its committee in data.index" {
                let json =
                    """{ "version": "deneb", "data": { "message": { "slot": "9", "proposer_index": "4", "body": {
                       "attestations": [ { "aggregation_bits": "0x0d", "data": { "slot": "8", "index": "3" } } ],
                       "sync_aggregate": { "sync_committee_bits": "0x01000000" } } } } }"""

                match read (Text.Encoding.UTF8.GetBytes json) with
                | BlockRead.Block b ->
                    Expect.equal
                        b.Attestations[0]
                        {
                            Slot = 8UL
                            Committees = [| 3UL |]
                            Bits = [| true; false; true |]
                        }
                        "committee from data.index"
                | BlockRead.Unknown why -> failtest why
            }

            test "an unknown block format is skipped, not an error" {
                let sync = Array.zeroCreate preset.SyncCommitteeSize

                let next =
                    (Text.Encoding.UTF8.GetString(blockJson "fulu" 7UL 1UL [] sync)).Replace("\"fulu\"", "\"heze\"")

                match read (Text.Encoding.UTF8.GetBytes next) with
                | BlockRead.Unknown why -> Expect.stringContains why "heze" "names the version"
                | _ -> failtest "a later fork must not decode"

                let noBody = """{ "version": "fulu", "data": { "message": { "slot": "1", "proposer_index": "2" } } }"""

                Expect.isTrue
                    (match read (Text.Encoding.UTF8.GetBytes noBody) with
                     | BlockRead.Unknown _ -> true
                     | _ -> false)
                    "missing body"

                let badBits =
                    """{ "version": "fulu", "data": { "message": { "slot": "1", "proposer_index": "2", "body": {
                       "attestations": [ { "aggregation_bits": "0x00", "committee_bits": "0x01", "data": { "slot": "0" } } ] } } } }"""

                Expect.isTrue
                    (match read (Text.Encoding.UTF8.GetBytes badBits) with
                     | BlockRead.Unknown _ -> true
                     | _ -> false)
                    "bad bitlist"
            }

            test "votes from attestation rewards" {
                Expect.equal
                    (votes
                        false
                        {
                            Head = 10L
                            Target = 20L
                            Source = 15L
                        })
                    {
                        Head = ValueSome true
                        Target = true
                        Source = true
                    }
                    "all earned"

                Expect.equal
                    (votes
                        false
                        {
                            Head = 0L
                            Target = -20L
                            Source = -15L
                        })
                    {
                        Head = ValueSome false
                        Target = false
                        Source = false
                    }
                    "all missed"

                Expect.equal
                    (votes true { Head = 0L; Target = 0L; Source = 0L })
                    {
                        Head = ValueNone
                        Target = true
                        Source = true
                    }
                    "leak: met earns 0"

                Expect.equal
                    (votes
                        true
                        {
                            Head = 0L
                            Target = -20L
                            Source = 0L
                        })
                    {
                        Head = ValueNone
                        Target = false
                        Source = true
                    }
                    "leak: missed target"

                let json =
                    """{ "data": { "ideal_rewards": [ { "effective_balance": "32000000000", "head": "0", "target": "0", "source": "0", "inactivity": "0" } ],
                       "total_rewards": [ { "validator_index": "7", "head": "0", "target": "-5", "source": "0", "inactivity": "-3" } ] } }"""

                match decodeString readRewards json with
                | Ok r ->
                    Expect.isTrue r.Leak "no ideal head reward: a leak"
                    Expect.equal r.Totals[7UL] { Head = 0L; Target = -5L; Source = 0L } "signed values"
                | Error e -> failtest e
            }

            testProp "balance deltas are the change of the keys read twice"
            <| fun (before: Map<uint64, uint32>) (now: Map<uint64, uint32>) ->
                let before = before |> Map.map (fun _ v -> uint64 v)
                let now = now |> Map.toArray |> Array.map (fun (i, v) -> i, uint64 v)
                let deltas = balanceDeltas before now

                deltas.Length = (now |> Array.filter (fun (i, _) -> before.ContainsKey i)).Length
                && deltas
                   |> Array.forall (fun (i, d) ->
                       d = int64 (snd (now |> Array.find (fun (j, _) -> j = i))) - int64 before[i])

            test "config" {
                Expect.equal
                    (MonitorModule.parse
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok MonitorModule.defaults)
                    "defaults"

                Expect.equal MonitorModule.defaults { Enabled = true; PerValidator = false } "on, totals only"

                Expect.equal
                    (MonitorModule.parse (section """{ "enabled": false, "per_validator": true }"""))
                    (Ok { Enabled = false; PerValidator = true })
                    "set"

                Expect.isError (MonitorModule.parse (section """{ "per_key": true }""")) "unknown field"
                Expect.isError (MonitorModule.parse (section """{ "enabled": "yes" }""")) "not a boolean"
            }

            testSequenced
            <| testT "the VC exports inclusion, votes, proposals, sync messages and balances" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                    // Validator 3 attestation at slot 11 and validator 2 sync message at slot 20 never land.
                    h.Node.Exclude <- fun s i -> (s = 11UL && i = 3UL) || (s = 20UL && i = 2UL)
                    // The block of slot 9 (with the slot 8 vote of validator 0) comes in an unknown format.
                    h.Node.UnknownBlockSlots <- set [ 9UL ]
                    h.Node.Proposals[10UL] <- 1UL
                    h.Node.Proposals[13UL] <- 2UL
                    h.Node.MissingBlocks <- set [ 13UL ]
                    h.Node.SyncSeats[0UL] <- [| 0UL |]
                    h.Node.SyncSeats[2UL] <- [| 5UL; 6UL |]
                    h.Node.WrongHead <- fun i -> i = 1UL
                    h.Node.WaitForSyncMessages <- true
                    let port = freePort ()

                    let! _, run, cts, lines =
                        startVc
                            h
                            dir
                            [ 0..3 ]
                            $$""", "metrics": { "port": {{port}} }, "monitor": { "per_validator": true }"""
                            [ LocalModule.create (); MetricsModule.create (); MonitorModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, uint64 (4 * slotsPerEpoch - 1))
                    use client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")
                    // The monitor runs in the background: scrape until the last epoch's balances and inclusions are in.
                    let key = (pubkeyOf 1).Hex
                    let mutable text = ""
                    let mutable tries = 0

                    while tries < 100
                          && (seriesValue text $$"""eplix_monitor_validator_balance_gwei{key="{{key}}"}"""
                              <> Some 32000003000.0
                              || seriesValue text """eplix_monitor_votes_total{correct="true",vote="target"}"""
                                 <> Some 6.0
                              || seriesValue text """eplix_monitor_attestations_total{outcome="included"}"""
                                 <> Some 14.0) do
                        let! t = client.GetStringAsync "/metrics"
                        text <- t
                        tries <- tries + 1

                        if tries > 1 then
                            do! Task.Delay 50

                    let value series =
                        match seriesValue text series with
                        | Some v -> v
                        | None -> failtestf "no series %s in:\n%s\nlog:\n%s" series text (String.Join("\n", lines))

                    Expect.equal
                        (value """eplix_monitor_attestations_total{outcome="included"}""")
                        14.0
                        "16 duties, one excluded, one in an unread block"

                    Expect.equal
                        (value """eplix_monitor_attestations_total{outcome="missed"}""")
                        1.0
                        "the excluded vote"

                    Expect.equal
                        (value """eplix_monitor_attestations_total{outcome="unknown"}""")
                        1.0
                        "the vote in the unread block"

                    Expect.equal (value "eplix_monitor_inclusion_distance_slots_count") 14.0 "a distance per inclusion"

                    Expect.equal
                        (value """eplix_monitor_inclusion_distance_slots_bucket{le="1"}""")
                        14.0
                        "every vote in the next block"

                    Expect.equal
                        (value """eplix_monitor_votes_total{correct="true",vote="head"}""")
                        4.0
                        "head of epochs 0 and 1"

                    Expect.equal
                        (value """eplix_monitor_votes_total{correct="false",vote="head"}""")
                        2.0
                        "validator 1 has the wrong head"

                    Expect.equal (value """eplix_monitor_votes_total{correct="true",vote="source"}""") 6.0 "source"
                    Expect.equal (value """eplix_monitor_proposals_total{outcome="included"}""") 1.0 "slot 10"

                    Expect.equal
                        (value """eplix_monitor_proposals_total{outcome="missed"}""")
                        1.0
                        "slot 13 has no block"

                    Expect.equal
                        (value """eplix_monitor_sync_messages_total{outcome="missed"}""")
                        1.0
                        "the excluded message"

                    Expect.isGreaterThanOrEqual
                        (value """eplix_monitor_sync_messages_total{outcome="included"}""")
                        50.0
                        "two keys, about 28 blocks"

                    Expect.equal (value "eplix_monitor_balance_change_gwei") 4000.0 "four keys gain 1000 Gwei each"

                    Expect.equal
                        (value """eplix_monitor_errors_total{call="block",reason="format"}""")
                        1.0
                        "the unknown block"

                    let k0 = (pubkeyOf 0).Hex
                    let k3 = (pubkeyOf 3).Hex

                    Expect.equal
                        (value $$"""eplix_monitor_validator_attestations_total{key="{{k3}}",outcome="missed"}""")
                        1.0
                        "per key"

                    Expect.equal
                        (value $$"""eplix_monitor_validator_votes_total{correct="false",key="{{key}}",vote="head"}""")
                        2.0
                        "per key votes"

                    Expect.equal
                        (value $$"""eplix_monitor_validator_inclusion_distance_slots{key="{{k0}}"}""")
                        1.0
                        "last distance"

                    Expect.equal
                        (value $$"""eplix_monitor_validator_proposals_total{key="{{key}}",outcome="included"}""")
                        1.0
                        "per key proposals"

                    Expect.equal
                        (value $$"""eplix_monitor_validator_balance_change_gwei{key="{{k0}}"}""")
                        1000.0
                        "per key change"
                    // The committees endpoint was asked: the aggregates span both committees of a slot.
                    Expect.exists h.Node.Requests (fun r -> r.Contains "/committees") "committee sizes read"
                    Expect.isGreaterThan (value "eplix_process_working_set_bytes") 0.0 "runtime meters"
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "run"
                })

            testSequenced
            <| testT "off: no block reads" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                    let port = freePort ()

                    let! _, run, cts, _ =
                        startVc
                            h
                            dir
                            [ 0 ]
                            $$""", "metrics": { "port": {{port}} }, "monitor": { "enabled": false }"""
                            [ LocalModule.create (); MetricsModule.create (); MonitorModule.create () ]

                    use _ = cts
                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch + 2))

                    Expect.isFalse
                        (h.Node.Requests |> Seq.exists (fun r -> r.Contains "/eth/v2/beacon/blocks/"))
                        "no block read"

                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "run"
                })
        ]
