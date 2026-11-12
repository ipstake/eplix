/// The Beacon API client against recorded responses (tests/fixtures/beacon).
module Eplix.Tests.BeaconApiTests

open System
open System.IO
open System.Net
open System.Net.Http
open System.Text
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Beacon
open Eplix.Tests.TestUtil

/// Serves one fixture file per path and records the requests.
type FixtureHandler(routes: Map<string, int * string>) =
    inherit HttpMessageHandler()
    member val Seen = ResizeArray<HttpRequestMessage * string>() with get

    override this.SendAsync(req, ct) =
        task {
            let! body =
                match req.Content with
                | null -> Task.FromResult ""
                | c -> c.ReadAsStringAsync ct

            this.Seen.Add((req, body))
            let key = (nonNull req.RequestUri).PathAndQuery

            match routes.TryFind key with
            | Some(status, file) ->
                let resp = new HttpResponseMessage(enum<HttpStatusCode> status)

                resp.Content <-
                    new StringContent(File.ReadAllText(Path.Combine(fixtures, "beacon", file)), Encoding.UTF8)

                return resp
            | None -> return new HttpResponseMessage(HttpStatusCode.NotFound)
        }

let private client routes =
    let h = new FixtureHandler(Map.ofList routes)
    let http = new HttpClient(h)
    h, BeaconClient(http, Uri "http://bn.test:5052", TimeSpan.FromSeconds 5.0)

let private ok r =
    match r with
    | Ok v -> v
    | Error(e: ApiError) -> failtestf "API error: %s" e.Describe

/// A body without a length, read in small pieces, as a chunked answer arrives.
type private Trickle(bytes: byte[]) =
    inherit Stream()
    let mutable pos = 0
    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = raise (NotSupportedException())

    override _.Position
        with get () = int64 pos
        and set _ = raise (NotSupportedException())

    override _.Flush() = ()
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength _ = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())

    override _.Read(buffer: byte[], offset: int, count: int) =
        let n = min (min count 1000) (bytes.Length - pos)
        Buffer.BlockCopy(bytes, pos, buffer, offset, n)
        pos <- pos + n
        n

/// Answers every request with `status` and `body`, with or without a Content-Length.
type private OneAnswer(status: int, body: byte[], withLength: bool) =
    inherit HttpMessageHandler()

    override _.SendAsync(_, _) =
        let resp = new HttpResponseMessage(enum<HttpStatusCode> status)

        resp.Content <-
            if withLength then
                new ByteArrayContent(body) :> HttpContent
            else
                new StreamContent(new Trickle(body)) :> HttpContent

        Task.FromResult resp

[<Tests>]
let tests =
    testList
        "beacon api"
        [
            testT
                "GetJsonBytes hands the decoder the whole body, with or without a length; 404 is none, errors as GetJson"
                (fun () ->
                    task {
                        // 300 KB, more than the first pooled buffer when no length is sent.
                        let big =
                            Encoding.UTF8.GetBytes(
                                "[" + String.Join(",", Array.init 50_000 (fun i -> $"\"{i % 10}\"")) + "]"
                            )

                        for withLength in [ true; false ] do
                            let c =
                                BeaconClient(
                                    new HttpClient(new OneAnswer(200, big, withLength)),
                                    Uri "http://bn.test:5052",
                                    TimeSpan.FromSeconds 5.0
                                )

                            let! r = c.GetJsonBytes("/x", (fun m -> m.ToArray()), CancellationToken.None)

                            match r with
                            | Ok(ValueSome got) -> Expect.equal got big $"the whole body (length sent: {withLength})"
                            | other -> failtestf "%A" other

                        let answer status (body: string) =
                            task {
                                let c =
                                    BeaconClient(
                                        new HttpClient(new OneAnswer(status, Encoding.UTF8.GetBytes body, false)),
                                        Uri "http://bn.test:5052",
                                        TimeSpan.FromSeconds 5.0
                                    )

                                let! bytes = c.GetJsonBytes("/x", (fun m -> m.Length), CancellationToken.None)
                                let! doc = c.GetJson("/x", (fun e -> e.ValueKind), CancellationToken.None)
                                return bytes, doc
                            }

                        let! bytes, doc = answer 404 """{"code":404,"message":"no block"}"""
                        Expect.equal bytes (Ok ValueNone) "404: none"
                        Expect.equal doc (Ok ValueNone) "404 with GetJson: none"

                        for status, body in
                            [
                                400, File.ReadAllText(Path.Combine(fixtures, "beacon", "submit_attestations_400.json"))
                                500, "not json"
                                503, """{"code":503,"message":"syncing"}"""
                            ] do
                            let! bytes, doc = answer status body

                            Expect.equal
                                (Result.map ignore bytes)
                                (Result.map ignore doc)
                                $"{status}: the same error as GetJson"

                            Expect.isError bytes $"{status} is an error"

                        let c =
                            BeaconClient(
                                new HttpClient(new OneAnswer(200, "{ broken"B, false)),
                                Uri "http://bn.test:5052",
                                TimeSpan.FromSeconds 5.0
                            )

                        let! r =
                            c.GetJsonBytes(
                                "/x",
                                (fun m -> Eplix.Monitor.Chain.readCommittees m),
                                CancellationToken.None
                            )

                        Expect.isTrue
                            (match r with
                             | Error(Decode _) -> true
                             | _ -> false)
                            $"malformed JSON is a decode error: %A{r}"
                    })

            testT
                "a node's error text is cut and cleaned, with at most 16 failures; the console log escapes line breaks"
                (fun () ->
                    task {
                        let long = String('x', 10_000) + "\n2026-11-12T00:00:00.000Z INFO forged line"

                        let failures =
                            String.Join(
                                ",",
                                [
                                    for i in 0..999 -> $"""{{"index":"{i}","message":"bad\r\nINFO forged {i}"}}"""
                                ]
                            )

                        let get status (body: string) =
                            let c =
                                BeaconClient(
                                    new HttpClient(new OneAnswer(status, Encoding.UTF8.GetBytes body, true)),
                                    Uri "http://bn.test:5052",
                                    TimeSpan.FromSeconds 5.0
                                )

                            c.GetJson("/x", (fun e -> e.ValueKind), CancellationToken.None)

                        let clean (m: string) =
                            m.Length <= Threshold.MaxReason + 3 && not (m.Contains '\n') && not (m.Contains '\r')

                        match!
                            get
                                400
                                $"""{{"code":400,"message":"{long.Replace("\n", "\\n")}","failures":[{failures.Replace("\r\n", "\\r\\n")}]}}"""
                        with
                        | Error(Rejected fs) ->
                            Expect.equal fs.Length Decoders.MaxFailures "16 failures kept"
                            Expect.isTrue (fs |> List.forall (fun f -> clean f.Message)) $"%A{fs}"
                        | r -> failtestf "%A" r

                        match! get 500 $"""{{"code":500,"message":"{long.Replace("\n", "\\n")}"}}""" with
                        | Error(Http(500, m)) -> Expect.isTrue (clean m) m
                        | r -> failtestf "%A" r

                        match! get 503 ("not json\n" + long) with
                        | Error(Http(503, m)) -> Expect.isTrue (clean m) m
                        | r -> failtestf "%A" r

                        Expect.equal
                            (Log.escape "a\r\nINFO b\u001b[31m\tc")
                            "a\\r\\nINFO b\\u001b[31m\tc"
                            "CR, LF and ESC escaped, tab kept"

                        Expect.equal (Log.escape "plain text") "plain text" "unchanged"
                    })

            testT "a 3xx from a node is an error, and neither headers nor bodies reach the redirect target" (fun () ->
                task {
                    use server = new RedirectServer()

                    for http in [ BeaconClient.createHttp () ] do
                        let c =
                            BeaconClient(
                                http,
                                server.Url,
                                TimeSpan.FromSeconds 5.0,
                                headers = [ "X-API-Key", "secret" ]
                            )

                        let! r = c.GetJson("/eth/v1/node/version", (fun e -> e.ValueKind), CancellationToken.None)

                        Expect.isTrue
                            (match r with
                             | Error(Http(307, m)) -> m.Contains "redirect"
                             | _ -> false)
                            $"%A{r}"

                    Expect.equal server.Reached 0 "nothing reached the target"
                })

            testT "genesis" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/beacon/genesis", (200, "genesis.json") ]
                    let! g = c.Genesis CancellationToken.None
                    let g = ok g
                    Expect.equal g.GenesisTime 1590832934UL "genesis time"

                    Expect.equal
                        g.GenesisValidatorsRoot.Hex
                        "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                        "gvr"

                    Expect.equal g.GenesisForkVersion.Hex "0x00000000" "fork version"
                })

            testT
                "a node URL with a path keeps it as a prefix, with or without the last slash, for calls and events"
                (fun () ->
                    task {
                        for baseUrl in
                            [
                                "http://bn.test:5052/prefix/"
                                "http://bn.test:5052/prefix"
                                "http://bn.test:5052/a/b/"
                            ] do
                            let prefix = Uri(baseUrl).AbsolutePath.TrimEnd('/')

                            let h =
                                new FixtureHandler(
                                    Map.ofList [ prefix + "/eth/v1/beacon/genesis", (200, "genesis.json") ]
                                )

                            let c = BeaconClient(new HttpClient(h), Uri baseUrl, TimeSpan.FromSeconds 5.0)
                            let! g = c.Genesis CancellationToken.None
                            Expect.isOk g $"{baseUrl}: genesis under the prefix"
                            use cts = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)
                            let! _ = c.Events([ "head" ], ignore, cts.Token)

                            let paths =
                                h.Seen |> Seq.map (fun (r, _) -> (nonNull r.RequestUri).PathAndQuery) |> List.ofSeq

                            Expect.equal
                                paths
                                [ prefix + "/eth/v1/beacon/genesis"; prefix + "/eth/v1/events?topics=head" ]
                                $"{baseUrl}: both under the prefix"
                        // Without a path, as before.
                        let h, c = client [ "/eth/v1/beacon/genesis", (200, "genesis.json") ]
                        let! g = c.Genesis CancellationToken.None
                        Expect.isOk g "no prefix"

                        Expect.equal
                            (nonNull (fst h.Seen[0]).RequestUri).PathAndQuery
                            "/eth/v1/beacon/genesis"
                            "the plain path"
                    })

            testT "spec skips nested values and parses into a chain spec" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/config/spec", (200, "spec.json") ]
                    let! s = c.Spec CancellationToken.None
                    let values = ok s
                    Expect.isFalse (values.ContainsKey "BLOB_SCHEDULE") "nested value skipped"

                    match ChainSpec.parse values with
                    | Error e -> failtest e
                    | Ok spec ->
                        Expect.equal spec.SlotsPerEpoch 32UL "slots per epoch"
                        Expect.equal spec.SlotDuration (TimeSpan.FromSeconds 12.0) "slot duration"
                        Expect.equal (spec.ForkAt 411392UL).Name Fulu "Fulu at its epoch"
                        Expect.equal (spec.ForkAt 411391UL).Name Electra "Electra before"
                        Expect.isFalse (spec.IsScheduled Gloas) "Gloas at FAR_FUTURE is not scheduled"
                        Expect.equal (spec.AttestationDue 0UL) (TimeSpan.FromMilliseconds 3999.6) "3333 bps of 12 s"
                })

            testT "fork" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/beacon/states/head/fork", (200, "fork.json") ]
                    let! f = c.StateFork("head", CancellationToken.None)
                    let f = ok f
                    Expect.equal f.CurrentVersion.Hex "0x06000000" "current"
                    Expect.equal f.Epoch 411392UL "epoch"
                })

            testT "validators by pubkey" (fun () ->
                task {
                    let h, c = client [ "/eth/v1/beacon/states/head/validators", (200, "validators.json") ]

                    let pk =
                        "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"

                    let! v = c.Validators("head", [ pk ], CancellationToken.None)
                    let v = ok v
                    Expect.equal v.Length 2 "two validators"
                    Expect.equal v[0].Index 1UL "index"
                    Expect.equal v[1].Status "pending_queued" "status"
                    let req, body = h.Seen[0]
                    Expect.equal req.Method HttpMethod.Post "POST"
                    Expect.equal body $"""{{"ids":["{pk}"]}}""" "request body"
                })

            testT "attester duties" (fun () ->
                task {
                    let h, c = client [ "/eth/v1/validator/duties/attester/1", (200, "attester_duties.json") ]
                    let! d = c.AttesterDuties(1UL, [ 1UL; 7UL ], CancellationToken.None)
                    let d = ok d
                    Expect.equal d.Data.Length 1 "one duty"
                    Expect.equal d.Data[0].ValidatorCommitteeIndex 17UL "committee position"
                    Expect.equal d.Data[0].CommitteesAtSlot 64UL "committees"
                    Expect.equal (snd h.Seen[0]) """["1","7"]""" "indices as strings"
                })

            testT "proposer duties" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/validator/duties/proposer/1", (200, "proposer_duties.json") ]
                    let! d = c.ProposerDuties(1UL, CancellationToken.None)
                    Expect.equal (ok d).Data[0].Slot 1UL "slot"
                })

            testT "attestation data" (fun () ->
                task {
                    let _, c =
                        client
                            [
                                "/eth/v1/validator/attestation_data?slot=1&committee_index=0",
                                (200, "attestation_data.json")
                            ]

                    let! d = c.AttestationData(1UL, 0UL, CancellationToken.None)
                    let d = ok d
                    Expect.equal d.Slot 1UL "slot"
                    Expect.equal d.Target.Epoch 1UL "target"
                })

            testT "syncing" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/node/syncing", (200, "syncing.json") ]
                    let! s = c.Syncing CancellationToken.None
                    Expect.isTrue (ok s).IsSyncing "syncing"
                })

            testT "submit attestations sends SingleAttestation JSON with the fork header" (fun () ->
                task {
                    let h, c = client [ "/eth/v2/beacon/pool/attestations", (200, "error_400.json") ]

                    let data =
                        {
                            Slot = 1UL
                            Index = 0UL
                            BeaconBlockRoot = root 1
                            Source = { Epoch = 0UL; Root = root 2 }
                            Target = { Epoch = 1UL; Root = root 3 }
                        }

                    let att =
                        {
                            CommitteeIndex = 3UL
                            AttesterIndex = 9UL
                            Data = data
                            Signature = BlsSignature.Of(Array.create 96 0xABuy)
                        }

                    let! r = c.SubmitAttestations(Fulu, [ att ], CancellationToken.None)
                    ok r
                    let req, body = h.Seen[0]
                    Expect.equal (Seq.head (req.Headers.GetValues "Eth-Consensus-Version")) "fulu" "header"
                    Expect.stringContains body "\"committee_index\":\"3\"" "committee index"
                    Expect.stringContains body "\"attester_index\":\"9\"" "attester index"
                    Expect.stringContains body $"\"beacon_block_root\":\"{(root 1).Hex}\"" "data"
                })

            testT "a 400 with failures is a typed rejection" (fun () ->
                task {
                    let _, c = client [ "/eth/v2/beacon/pool/attestations", (400, "submit_attestations_400.json") ]
                    let! r = c.SubmitAttestations(Fulu, [], CancellationToken.None)

                    match r with
                    | Error(Rejected [ f ]) ->
                        Expect.equal f.Index 3 "index"
                        Expect.equal f.Message "invalid signature" "message"
                    | other -> failtestf "expected a rejection, got %A" other
                })

            testT "a 400 without failures is an HTTP error" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/validator/duties/attester/1", (400, "error_400.json") ]
                    let! r = c.AttesterDuties(1UL, [ 1UL ], CancellationToken.None)

                    match r with
                    | Error(Http(400, m)) -> Expect.equal m "Invalid epoch: -2" "message"
                    | other -> failtestf "expected HTTP 400, got %A" other
                })

            testT "a missing route is an HTTP 404 error" (fun () ->
                task {
                    let _, c = client []
                    let! r = c.Genesis CancellationToken.None
                    Expect.isError r "404"
                })

            testT "event stream: head and head_v2" (fun () ->
                task {
                    let _, c = client [ "/eth/v1/events?topics=head", (200, "events.txt") ]
                    let events = ResizeArray<SseEvent>()
                    let! r = c.Events([ "head" ], events.Add, CancellationToken.None)
                    ok r
                    Expect.equal [ for e in events -> e.Event ] [ "head"; "head_v2" ] "two events"

                    for e in events do
                        match Json.decodeString (Decoders.headEvent e.Event) e.Data with
                        | Ok h ->
                            Expect.equal h.Slot 10UL "slot"

                            Expect.equal
                                h.CurrentDutyDependentRoot.Hex
                                "0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91"
                                "root"
                        | Error err -> failtest err
                })

            test "decode errors are values, not exceptions" {
                Expect.isError (Json.decodeString Decoders.genesis "{\"data\":{}}") "missing field"
                Expect.isError (Json.decodeString Decoders.genesis "not json") "bad json"

                Expect.isError
                    (Json.decodeString
                        Decoders.genesis
                        """{"data":{"genesis_time":"-1","genesis_validators_root":"0x00","genesis_fork_version":"0x00000000"}}""")
                    "bad number"
            }
        ]

/// Gives `bytes`, then waits until the reader gives up (a stream the node keeps open).
type private ThenHang(bytes: byte[]) =
    inherit Stream()
    let mutable pos = 0
    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = raise (NotSupportedException())

    override _.Position
        with get () = int64 pos
        and set _ = raise (NotSupportedException())

    override _.Flush() = ()
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength _ = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())
    override _.Read(_: byte[], _: int, _: int) = raise (NotSupportedException())

    override _.ReadAsync(buffer: Memory<byte>, ct: CancellationToken) =
        if pos < bytes.Length then
            let n = min buffer.Length (bytes.Length - pos)
            bytes.AsMemory(pos, n).CopyTo buffer
            pos <- pos + n
            ValueTask<int>(n)
        else
            ValueTask<int>(
                task {
                    do! Task.Delay(Timeout.Infinite, ct)
                    return 0
                }
            )

/// An event stream: `body`, then the stream stays open (`hang`) or ends. Counts the connections.
type private EventAnswer(body: string, hang: bool) =
    inherit HttpMessageHandler()
    member val Connections = 0 with get, set

    override this.SendAsync(_, _) =
        this.Connections <- this.Connections + 1
        let bytes = Encoding.UTF8.GetBytes body
        let resp = new HttpResponseMessage(HttpStatusCode.OK)

        resp.Content <-
            if hang then
                new StreamContent(new ThenHang(bytes)) :> HttpContent
            else
                new StreamContent(new Trickle(bytes)) :> HttpContent

        Task.FromResult resp

let private limited (handler: HttpMessageHandler) (maxBody: int) =
    BeaconClient(new HttpClient(handler), Uri "http://bn.test:5052", TimeSpan.FromSeconds 5.0, maxBody = maxBody)

[<Tests>]
let limitTests =
    testList
        "beacon limits"
        [
            testT
                "an answer over the size limit is a transport error, with or without a length, on every read path"
                (fun () ->
                    task {
                        let body =
                            Encoding.UTF8.GetBytes(
                                """{"data":{"genesis_time":"1","genesis_validators_root":"0x"""
                                + String('0', 64)
                                + """","genesis_fork_version":"0x00000000"},"pad":" """
                                + String(' ', 2000)
                                + "\"}"
                            )

                        for withLength in [ true; false ] do
                            let small = limited (new OneAnswer(200, body, withLength)) 1024
                            let! g = small.Genesis CancellationToken.None
                            // Without a length the buffer limit of HttpContent words the error.
                            Expect.isTrue
                                (match g with
                                 | Error(Transport m) -> m.Contains "limit" || m.Contains "maximum buffer size"
                                 | _ -> false)
                                $"send, length {withLength}: %A{g}"

                            let! b = small.GetJsonBytes("/x", (fun m -> m.Length), CancellationToken.None)

                            Expect.isTrue
                                (match b with
                                 | Error(Transport m) -> m.Contains "limit"
                                 | _ -> false)
                                $"sendPooled, length {withLength}: %A{b}"

                            let! p = small.PayloadAttestationData(1UL, CancellationToken.None)

                            Expect.isTrue
                                (match p with
                                 | Error(Transport _) -> true
                                 | _ -> false)
                                $"getRaw, length {withLength}: %A{p}"

                            let! e = small.Genesis CancellationToken.None
                            Expect.isError e "and again"
                            // The same answer under the limit reads.
                            let big = limited (new OneAnswer(200, body, withLength)) 4096
                            let! g = big.Genesis CancellationToken.None
                            Expect.isOk g $"under the limit, length {withLength}"
                            let! b = big.GetJsonBytes("/x", (fun m -> m.Length), CancellationToken.None)

                            Expect.equal
                                b
                                (Ok(ValueSome body.Length))
                                $"sendPooled under the limit, length {withLength}"
                        // A pooled read at exactly the limit still reads; one byte more does not.
                        for size, okay in [ 4096, true; 4097, false ] do
                            let exact = Array.create size (byte ' ')
                            exact[0] <- byte '1'
                            let c = limited (new OneAnswer(200, exact, false)) 4096
                            let! b = c.GetJsonBytes("/x", (fun m -> m.Length), CancellationToken.None)
                            Expect.equal (Result.isOk b) okay $"{size} bytes against a 4096 limit: %A{b}"
                    })

            testT "an event line or event data over the limit ends the stream with an error" (fun () ->
                task {
                    let long = String('x', 5000)

                    for body, what in
                        [
                            $"event: head\ndata: {long}\n\n", "one long line"
                            "event: head\n" + String.replicate 10 $"data: {String('y', 900)}\n" + "\n",
                            "data over several lines"
                            long, "a line that never ends"
                        ] do
                        let c = limited (new EventAnswer(body, false)) 1024
                        let seen = ResizeArray<SseEvent>()
                        let! r = c.Events([ "head" ], seen.Add, CancellationToken.None, maxEvent = 4096)

                        Expect.isTrue
                            (match r with
                             | Error(Transport m) -> m.Contains "4096"
                             | _ -> false)
                            $"{what}: %A{r}"

                        Expect.isEmpty seen $"{what}: no event"
                })

            testT "events end in LF, CRLF or CR" (fun () ->
                task {
                    let c =
                        limited
                            (new EventAnswer(
                                "event: head\r\ndata: a\r\n\r\nevent: head\rdata: b\r\rdata: c\n\n",
                                false
                            ))
                            1024

                    let seen = ResizeArray<SseEvent>()
                    let! r = c.Events([ "head" ], seen.Add, CancellationToken.None)
                    Expect.isOk r "ends"

                    Expect.equal
                        [ for e in seen -> e.Event, e.Data ]
                        [ "head", "a"; "head", "b"; "message", "c" ]
                        "three events"
                })

            testT "a silent event stream ends after the idle time" (fun () ->
                task {
                    let c = limited (new EventAnswer("event: head\ndata: a\n\n", true)) 1024
                    let seen = ResizeArray<SseEvent>()
                    let sw = Diagnostics.Stopwatch.StartNew()

                    let! r =
                        c.Events([ "head" ], seen.Add, CancellationToken.None, idle = TimeSpan.FromMilliseconds 300.0)

                    Expect.equal r (Error Timeout) "a timeout, which the node set does not score"
                    Expect.equal seen.Count 1 "the event before the silence"
                    Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 10.0) "ended"
                    // The caller's token is not an error.
                    use cts = new CancellationTokenSource(TimeSpan.FromMilliseconds 200.0)
                    let! r = c.Events([ "head" ], ignore, cts.Token)
                    Expect.isOk r "cancelled by the caller"
                })

            testT "an exception in the event handler does not end the node's events for good" (fun () ->
                task {
                    let handler = new EventAnswer("event: head\ndata: a\n\n", false)
                    let c = BeaconClient(new HttpClient(handler), Uri "http://bn.test:5052", TimeSpan.FromSeconds 5.0)
                    let nodes = BeaconNodes([ c ], 1, TimeProvider.System, Log.none)
                    use cts = new CancellationTokenSource()
                    let run = nodes.RunEvents([ "head" ], (fun _ -> failwith "handler bug"), cts.Token)
                    let sw = Diagnostics.Stopwatch.StartNew()

                    while handler.Connections < 2 && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                        do! Task.Delay 20

                    Expect.isGreaterThanOrEqual handler.Connections 2 "the stream opened again"
                    Expect.isFalse run.IsFaulted "RunEvents still runs"
                    cts.Cancel()
                    do! run
                })
        ]
