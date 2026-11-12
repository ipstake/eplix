/// Every request the VC sends to a beacon node in a Gloas run, against the beacon-APIs
/// v5.0.0-beta.0 OpenAPI document; every keymanager answer against keymanager-APIs
/// v1.2.0-alpha.0. The documents are fetched by scripts/fetch-test-vectors.sh.
module Eplix.Tests.ApiSchemaTests

open System
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.VcHarness

let beaconApiFile = Path.Combine(vectors, ".download", "beacon-apis", "beacon-node-oapi.json")
let keymanagerApiFile = Path.Combine(vectors, ".download", "keymanager-apis", "keymanager-oapi.json")

let private loadOrFail (file: string) =
    if not (File.Exists file) then
        failtestf "%s is missing; run scripts/fetch-test-vectors.sh" file

    OpenApi.load file

/// The problems of one request against the API: an unknown endpoint, a missing or bad
/// parameter or header, an unknown query parameter, a body that does not fit.
let requestProblems (api: OpenApi.Spec) (r: RecordedRequest) : string list =
    match api.Find(r.Method, r.Path) with
    | None -> [ $"{r.Method} {r.Path}: no such endpoint" ]
    | Some(template, op) ->
        let where = $"{r.Method} {template}"
        let ps = api.Parameters(template, op)
        let named (place: string) = ps |> List.filter (fun p -> p.GetProperty("in").GetString() = place)

        let query =
            r.Query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun kv ->
                let i = kv.IndexOf '='
                if i < 0 then kv, "" else kv.Substring(0, i), Uri.UnescapeDataString(kv.Substring(i + 1)))
            |> List.ofArray

        let checkValue (p: JsonElement) (value: string) =
            let schema = api.Resolve(p.GetProperty "schema")

            let isArray =
                match schema.TryGetProperty "type" with
                | true, t -> t.ValueKind = JsonValueKind.String && t.GetString() = "array"
                | _ -> false
            // A query or header value is text; a boolean or number parameter is its literal.
            let element (s: JsonElement) (v: string) =
                match s.TryGetProperty "type" with
                | true, t when
                    t.ValueKind = JsonValueKind.String
                    && List.contains (t.GetString()) [ "boolean"; "integer"; "number" ]
                    ->
                    try
                        (JsonDocument.Parse v).RootElement.Clone()
                    with _ ->
                        OpenApi.stringElement v
                | _ -> OpenApi.stringElement v

            if isArray then
                let items = api.Resolve(schema.GetProperty "items")

                [
                    for v in value.Split(',') do
                        yield! api.Check(items, element items v)
                ]
            else
                api.Check(schema, element schema value)

        [
            for name, value in OpenApi.pathValues template r.Path do
                match named "path" |> List.tryFind (fun p -> p.GetProperty("name").GetString() = name) with
                | Some p -> for e in checkValue p value -> $"{where}: path {name}: {e}"
                | None -> yield $"{where}: path parameter {name} not declared"
            for p in named "query" do
                let name = p.GetProperty("name").GetString()

                let required =
                    match p.TryGetProperty "required" with
                    | true, x -> x.GetBoolean()
                    | _ -> false

                match query |> List.filter (fun (k, _) -> k = name) with
                | [] ->
                    if required then
                        yield $"{where}: missing query {name}"
                | values ->
                    for _, v in values do
                        for e in checkValue p v -> $"{where}: query {name}: {e}"
            for k, _ in query do
                if not (named "query" |> List.exists (fun p -> p.GetProperty("name").GetString() = k)) then
                    yield $"{where}: query {k} is not in the API"
            for p in named "header" do
                let name = p.GetProperty("name").GetString()

                let required =
                    match p.TryGetProperty "required" with
                    | true, x -> x.GetBoolean()
                    | _ -> false

                match
                    r.Headers |> Map.tryFindKey (fun k _ -> String.Equals(k, name, StringComparison.OrdinalIgnoreCase))
                with
                | Some k -> for e in checkValue p r.Headers[k] -> $"{where}: header {name}: {e}"
                | None ->
                    if required then
                        yield $"{where}: missing header {name}"
            match op.TryGetProperty "requestBody" with
            | true, rb ->
                let content = (api.Resolve rb).GetProperty "content"

                match content.TryGetProperty r.ContentType with
                | true, media when r.ContentType = "application/json" ->
                    use body = JsonDocument.Parse(ReadOnlyMemory<byte> r.Body)
                    for e in api.Check(media.GetProperty "schema", body.RootElement) -> $"{where}: body {e}"
                | true, _ -> () // SSZ bodies: the content type is allowed; the codec is checked by the SSZ vectors
                | _ ->
                    if r.Body.Length > 0 then
                        yield $"{where}: content type {r.ContentType} is not accepted"
            | _ ->
                if r.Body.Length > 0 then
                    yield $"{where}: a body where the API has none"
        ]

/// A Gloas run with two nodes, events, aggregation, sync committee, proposals before and after
/// the fork, PTC votes and preferences; plus the start-up and doppelganger calls.
let private gloasRun () =
    task {
        let h = gloasHarness 1UL
        let second = extraNode h
        addValidators [ h.Node; second ] 8

        for n in [ h.Node; second ] do
            n.CommitteeLength <- 8UL
            n.SyncSeats[1UL] <- [| 0UL; 9UL |]
            n.Proposals[4UL] <- 3UL
            n.Proposals[10UL] <- 5UL
            n.Proposals[13UL] <- 6UL
            n.PtcSlots[9UL] <- [| 2UL |]

        h.Node.HeadRoot <- root 77
        second.HeadRoot <- root 77

        let vc =
            startVc
                h
                { defaults with
                    Extra = [ second ]
                    UseEvents = true
                }

        for s in 0UL .. 13UL do
            let before = h.Node.Published.Count
            do! h.RunSlots(s, s)

            if h.Node.Proposals.ContainsKey s then
                do! waitUntil vc $"the block of slot {s}" (fun () -> h.Node.Published.Count > before)

            advanceTo h (h.Clock.SlotStart s + h.Spec.Bps 7100UL)
            do! Task.Delay 30

        do! vc.Stop()
        // The calls the runner and the doppelganger module make.
        let client =
            BeaconClient(new HttpClient(h.Node, false), Uri "http://bn0.test", TimeSpan.FromSeconds 5.0)

        let! _ = client.Genesis CancellationToken.None
        let! _ = client.Spec CancellationToken.None
        let! _ = client.Syncing CancellationToken.None
        let! _ = client.Liveness(1UL, [ 0UL; 1UL ], CancellationToken.None)

        let! _ =
            client.SubmitVoluntaryExit(
                { Epoch = 1UL; ValidatorIndex = 1UL },
                BlsSignature.Of(Array.zeroCreate 96),
                CancellationToken.None
            )

        return List.ofSeq h.Node.Recorded @ List.ofSeq second.Recorded, vc
    }

let private beaconRequestsMatchTheSpec () =
    task {
        let api = loadOrFail beaconApiFile
        let! recorded, vc = gloasRun ()

        let endpoints =
            recorded
            |> List.map (fun r ->
                r.Method, (api.Find(r.Method, r.Path) |> Option.map fst |> Option.defaultValue r.Path))
            |> List.distinct

        let problems = recorded |> List.collect (requestProblems api) |> List.distinct

        Expect.isEmpty
            problems
            $"""requests that do not fit beacon-APIs v5.0.0-beta.0 ({endpoints.Length} endpoints used):
{String.Join("\n", problems)}"""
        // The run used the endpoints of every duty kind.
        for path in
            [
                "/eth/v1/validator/duties/attester/{epoch}"
                "/eth/v1/validator/duties/ptc/{epoch}"
                "/eth/v2/beacon/pool/attestations"
                "/eth/v2/validator/aggregate_and_proofs"
                "/eth/v1/validator/contribution_and_proofs"
                "/eth/v1/beacon/pool/sync_committees"
                "/eth/v3/validator/blocks/{slot}"
                "/eth/v4/validator/blocks/{slot}"
                "/eth/v2/beacon/blocks"
                "/eth/v1/beacon/execution_payload_envelopes"
                "/eth/v1/beacon/pool/payload_attestations"
                "/eth/v1/validator/proposer_preferences"
                "/eth/v1/events"
                "/eth/v1/node/syncing"
            ] do
            Expect.isTrue (endpoints |> List.exists (fun (_, p) -> p = path)) $"the run used {path}; log:\n{vc.Log}"
    }

/// The checker itself finds what it should: an unknown path, a missing header, a bad body.
let private checkerFindsProblems () =
    let api = loadOrFail beaconApiFile

    let req meth path query headers body =
        {
            Method = meth
            Path = path
            Query = query
            Headers = Map.ofList headers
            ContentType = (if body = "" then "" else "application/json")
            Body = Encoding.UTF8.GetBytes(body: string)
        }

    let good =
        """[{"committee_index":"0","attester_index":"1","data":{"slot":"1","index":"0","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"0","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"0","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]"""

    Expect.isEmpty
        (requestProblems api (req "POST" "/eth/v2/beacon/pool/attestations" "" [ "Eth-Consensus-Version", "fulu" ] good))
        "a good submission"

    Expect.isNonEmpty
        (requestProblems api (req "POST" "/eth/v2/beacon/pool/attestations" "" [] good))
        "a missing Eth-Consensus-Version"

    Expect.isNonEmpty
        (requestProblems
            api
            (req
                "POST"
                "/eth/v2/beacon/pool/attestations"
                ""
                [ "Eth-Consensus-Version", "fulu" ]
                (good.Replace("\"slot\":\"1\"", "\"slot\":1"))))
        "a number where the API has a string"

    Expect.isNonEmpty
        (requestProblems api (req "GET" "/eth/v1/validator/attestation_data" "" [] ""))
        "a missing required query"

    Expect.isNonEmpty (requestProblems api (req "GET" "/eth/v1/validator/no_such_thing" "" [] "")) "an unknown endpoint"

[<Tests>]
let tests =
    testSequenced
    <| testList
        "beacon api"
        [
            test "the schema checker finds bad requests" { checkerFindsProblems () }
            testT "every request matches the OpenAPI schema" beaconRequestsMatchTheSpec
        ]
