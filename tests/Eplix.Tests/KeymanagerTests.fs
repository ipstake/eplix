/// The keymanager API over real HTTP (Kestrel on a loopback port) against the whole VC.
module Eplix.Tests.KeymanagerTests

open System
open System.IO
open System.Net
open System.Net.Http
open System.Net.Sockets
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Keymanager
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private freePort () =
    let l = new TcpListener(IPAddress.Loopback, 0)
    l.Start()
    let p = (l.LocalEndpoint :?> IPEndPoint).Port
    l.Stop()
    p

let private keystore (i: int) (pw: string) =
    Keystore.encrypt (secretOf i) pw (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) $"m/12381/3600/{i}/0/0"

[<Tests>]
let tests =
    testSequenced
    <| testList
        "keymanager"
        [
            testT "keystores, settings and exits through the API while the VC runs" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                    for i in 0..2 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    File.WriteAllText(Path.Combine(ksDir, "k0.json"), keystore 0 "pw")
                    File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
                    let port = freePort ()

                    let configText =
                        $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                       "allow_start_without_history": ["{{(pubkeyOf 0).Hex}}"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
                                    "keymanager": { "port": {{port}} } } }"""

                    let modules = [ LocalModule.create (); KeymanagerModule.create () ]

                    match
                        Config.parse configText dir [ "local"; "keymanager" ]
                        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                    with
                    | Error es -> failtestf "%A" es
                    | Ok config ->
                        use cts = new CancellationTokenSource()
                        let log, lines = Log.memory ()
                        let ready = TaskCompletionSource<CoreServices>()

                        let run =
                            Runner.run
                                {
                                    Config = config
                                    Modules = modules
                                    Http = new HttpClient(h.Node, false)
                                    Time = h.Time
                                    Log = log
                                    OnSlotDone = h.Waiter.Done
                                    OnReady = fun core _ -> ready.TrySetResult core |> ignore
                                }
                                cts.Token

                        let! core = ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                        let token = File.ReadAllText(Path.Combine(dir, "data", "api-token.txt")).Trim()
                        use client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")

                        let call (meth: string) (path: string) (body: string option) (auth: string option) =
                            task {
                                use req = new HttpRequestMessage(HttpMethod meth, path)

                                auth
                                |> Option.iter (fun t ->
                                    req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", t))

                                body
                                |> Option.iter (fun b ->
                                    req.Content <- new StringContent(b, Encoding.UTF8, "application/json"))

                                use! resp = client.SendAsync req
                                let! text = resp.Content.ReadAsStringAsync()
                                return int resp.StatusCode, text
                            }

                        let! s, _ = call "GET" "/eth/v1/keystores" None None
                        Expect.equal s 401 "no token"
                        let! s, _ = call "GET" "/eth/v1/keystores" None (Some "nope")
                        Expect.equal s 403 "wrong token"
                        let auth = Some token
                        // Import key 1 with its slashing history (a vote for target 0 already made elsewhere).
                        let interchange =
                            Slashing.Interchange.write
                                {
                                    GenesisValidatorsRoot = gvr
                                    Data =
                                        [
                                            {
                                                PubKey = pubkeyOf 1
                                                SignedBlocks = []
                                                SignedAttestations =
                                                    [
                                                        {
                                                            SourceEpoch = 0UL
                                                            TargetEpoch = 0UL
                                                            SigningRoot = ValueNone
                                                        }
                                                    ]
                                            }
                                        ]
                                }

                        let body =
                            Json.toBytes (fun w ->
                                w.WriteStartObject()
                                w.WriteStartArray "keystores"
                                w.WriteStringValue(keystore 1 "one")
                                w.WriteStringValue(keystore 0 "pw")
                                w.WriteStringValue("{ not a keystore")
                                w.WriteEndArray()
                                w.WriteStartArray "passwords"
                                w.WriteStringValue "one"
                                w.WriteStringValue "pw"
                                w.WriteStringValue "x"
                                w.WriteEndArray()
                                w.WriteString("slashing_protection", Encoding.UTF8.GetString interchange)
                                w.WriteEndObject())

                        let! s, text = call "POST" "/eth/v1/keystores" (Some(Encoding.UTF8.GetString body)) auth
                        Expect.equal s 200 text

                        let statuses =
                            [
                                for x in JsonDocument.Parse(text).RootElement.GetProperty("data").EnumerateArray() ->
                                    x.GetProperty("status").GetString()
                            ]

                        Expect.equal statuses [ "imported"; "duplicate"; "error" ] text
                        let! _, text = call "GET" "/eth/v1/keystores" None auth

                        let listed =
                            [
                                for x in JsonDocument.Parse(text).RootElement.GetProperty("data").EnumerateArray() ->
                                    x.GetProperty("validating_pubkey").GetString(),
                                    x.GetProperty("readonly").GetBoolean()
                            ]
                            |> Set.ofList

                        Expect.equal
                            listed
                            (set [ (pubkeyOf 0).Hex, true; (pubkeyOf 1).Hex, false ])
                            "configured key read-only, imported key not"
                        // Fee recipient.
                        let fr = $"/eth/v1/validator/{(pubkeyOf 1).Hex}/feerecipient"

                        let! s, _ =
                            call
                                "POST"
                                fr
                                (Some """{"ethaddress":"0x00000000000000000000000000000000000000bb"}""")
                                auth

                        Expect.equal s 202 "set"
                        let! _, text = call "GET" fr None auth
                        Expect.stringContains text "0x00000000000000000000000000000000000000bb" "read back"

                        Expect.stringContains
                            (File.ReadAllText(Path.Combine(dir, "data", "key-settings.json")))
                            "00bb"
                            "persisted"

                        let! s, _ =
                            call
                                "POST"
                                $"/eth/v1/validator/{(pubkeyOf 1).Hex}/graffiti"
                                (Some """{"graffiti":"eplix test"}""")
                                auth

                        Expect.equal s 202 "graffiti"
                        // The proposer config file's gas limit rule: above 0.
                        let! s, text =
                            call
                                "POST"
                                $"/eth/v1/validator/{(pubkeyOf 1).Hex}/gas_limit"
                                (Some """{"gas_limit":"0"}""")
                                auth

                        Expect.equal s 400 text
                        Expect.stringContains text "above 0" "why"
                        // A key the VC does not hold: 404 on every method, and nothing stored.
                        let other = $"/eth/v1/validator/{(pubkeyOf 2).Hex}"

                        let! s, text =
                            call
                                "POST"
                                $"{other}/feerecipient"
                                (Some """{"ethaddress":"0x00000000000000000000000000000000000000cc"}""")
                                auth

                        Expect.equal s 404 text
                        let! s, text = call "DELETE" $"{other}/graffiti" None auth
                        Expect.equal s 404 text
                        let! s, text = call "GET" $"{other}/gas_limit" None auth
                        Expect.equal s 404 text

                        Expect.isFalse
                            ((File.ReadAllText(Path.Combine(dir, "data", "key-settings.json")))
                                .Contains((pubkeyOf 2).Hex))
                            "no settings stored for a key the VC does not hold"
                        // Two epochs: key 1 attests from epoch 1 (its target 0 is already taken).
                        do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))

                        let by i =
                            h.Node.Submissions
                            |> Seq.filter (fun x -> x.AttesterIndex = uint64 i)
                            |> Seq.map (fun x -> x.Data.Target.Epoch)
                            |> List.ofSeq

                        Expect.equal
                            (by 1)
                            [ 1UL ]
                            $"imported key attests after its history; log: {String.Join('\n', lines)}"
                        // Exit.
                        let! s, text =
                            call "POST" $"/eth/v1/validator/{(pubkeyOf 1).Hex}/voluntary_exit?epoch=1" None auth

                        Expect.equal s 200 text
                        let d = JsonDocument.Parse(text).RootElement.GetProperty("data")

                        let x =
                            {
                                Epoch = 1UL
                                ValidatorIndex =
                                    UInt64.Parse(d.GetProperty("message").GetProperty("validator_index").GetString())
                            }

                        let sg = BlsSignature.TryParse(d.GetProperty("signature").GetString()) |> ValueOption.get
                        let capella = h.Spec.Forks |> Array.find (fun f -> f.Name = Capella)

                        let root =
                            Signing.computeSigningRoot
                                (Codec.hashVoluntaryExit x)
                                (Signing.computeDomain h.Spec.DomainVoluntaryExit capella.Version gvr)

                        Expect.isTrue
                            (Bls.verify
                                (ReadOnlySpan (pubkeyOf 1).Bytes)
                                (ReadOnlySpan root.Bytes)
                                (ReadOnlySpan sg.Bytes))
                            "exit signature"
                        // Delete key 1 (exports its history) and try the read-only key 0.
                        let! s, text =
                            call
                                "DELETE"
                                "/eth/v1/keystores"
                                (Some
                                    $"""{{"pubkeys":["{(pubkeyOf 1).Hex}","{(pubkeyOf 0).Hex}","{(pubkeyOf 2).Hex}"]}}""")
                                auth

                        Expect.equal s 200 text
                        let doc = JsonDocument.Parse(text).RootElement

                        let statuses =
                            [
                                for x in doc.GetProperty("data").EnumerateArray() ->
                                    x.GetProperty("status").GetString()
                            ]

                        Expect.equal statuses [ "deleted"; "error"; "not_found" ] text

                        match
                            Slashing.Interchange.parse (
                                Encoding.UTF8.GetBytes(doc.GetProperty("slashing_protection").GetString())
                            )
                        with
                        | Ok x ->
                            let e = x.Data |> List.find (fun e -> e.PubKey = pubkeyOf 1)

                            Expect.equal
                                e.SignedAttestations.Head.TargetEpoch
                                1UL
                                "exported mark includes the vote this VC made"
                        | Error e -> failtest e

                        Expect.isFalse
                            (File.Exists(
                                LocalModule.ManagedStore.keystoreFile (Path.Combine(dir, "data")) (pubkeyOf 1)
                            ))
                            "keystore file gone"

                        Expect.equal (core.Registry.TryGet(pubkeyOf 1)).Value.State KeyState.Removed "tombstone"
                        h.Node.Submissions.Clear()
                        do! h.RunSlots(uint64 (2 * slotsPerEpoch), uint64 (3 * slotsPerEpoch - 1))
                        Expect.isEmpty (by 1) "a deleted key signs nothing"
                        cts.Cancel()
                        let! result = run
                        Expect.isOk result "run"
                })
            testT
                "the token is checked before the body is read; each route has a body limit; the import streams"
                (fun () ->
                    task {
                        let h = harness ()
                        let dir = tempDir ()
                        let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName
                        h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
                        File.WriteAllText(Path.Combine(ksDir, "k0.json"), keystore 0 "pw")
                        File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
                        let port = freePort ()

                        let configText =
                            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                       "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
                                    "keymanager": { "port": {{port}}, "max_import_bytes": 1048576, "max_import_keys": 1000 } } }"""

                        let modules = [ LocalModule.create (); KeymanagerModule.create () ]

                        match
                            Config.parse configText dir [ "local"; "keymanager" ]
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok config ->
                            use cts = new CancellationTokenSource()
                            let ready = TaskCompletionSource<CoreServices>()

                            let run =
                                Runner.run
                                    {
                                        Config = config
                                        Modules = modules
                                        Http = new HttpClient(h.Node, false)
                                        Time = h.Time
                                        Log = Log.none
                                        OnSlotDone = h.Waiter.Done
                                        OnReady = fun core _ -> ready.TrySetResult core |> ignore
                                    }
                                    cts.Token

                            let! core = ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                            let token = File.ReadAllText(Path.Combine(dir, "data", "api-token.txt")).Trim()
                            // Sends the head and the first bytes of a body that never completes, then reads
                            // the status line; "" when none comes in 5 s.
                            let statusOf (head: string) (body: byte[]) =
                                task {
                                    use tcp = new TcpClient()
                                    do! tcp.ConnectAsync(IPAddress.Loopback, port)
                                    let s = tcp.GetStream()
                                    let bytes = Encoding.ASCII.GetBytes head
                                    do! s.WriteAsync(bytes, 0, bytes.Length)
                                    do! s.WriteAsync(body, 0, body.Length)
                                    let buf = Array.zeroCreate<byte> 64
                                    use wait = new CancellationTokenSource(TimeSpan.FromSeconds 5.0)

                                    try
                                        let! n = s.ReadAsync(buf.AsMemory(), wait.Token)
                                        let line = Encoding.ASCII.GetString(buf, 0, n)
                                        return line.Split("\r\n")[0]
                                    with :? OperationCanceledException ->
                                        return ""
                                }

                            let head (meth: string) (path: string) (auth: string) (length: string) =
                                $"{meth} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{auth}{length}\r\n"

                            let bearer t = $"Authorization: Bearer {t}\r\n"
                            let big = "Content-Length: 20000000\r\n"
                            let some = Array.create 1000 (byte 'x')
                            let! s = statusOf (head "POST" "/eth/v1/keystores" "" big) some
                            Expect.stringStarts s "HTTP/1.1 401" "no token: 401 before the body"
                            let! s = statusOf (head "POST" "/eth/v1/keystores" "" big) [||]
                            Expect.stringStarts s "HTTP/1.1 401" "no token: 401 with no body byte sent"
                            let! s = statusOf (head "POST" "/eth/v1/keystores" (bearer "nope") big) some
                            Expect.stringStarts s "HTTP/1.1 403" "wrong token: 403 before the body"

                            let! s =
                                statusOf
                                    (head "DELETE" "/eth/v1/keystores" (bearer token) "Content-Length: 2000000\r\n")
                                    some

                            Expect.stringStarts s "HTTP/1.1 413" "a delete body over its limit, by Content-Length"
                            let fr = $"/eth/v1/validator/{(pubkeyOf 0).Hex}/feerecipient"

                            let chunk =
                                Array.concat [ Encoding.ASCII.GetBytes "2000\r\n"; Array.create 0x2000 (byte ' ') ]

                            let! s = statusOf (head "POST" fr (bearer token) "Transfer-Encoding: chunked\r\n") chunk
                            Expect.stringStarts s "HTTP/1.1 413" "a chunked settings body over its limit"
                            // The import has its own limit, max_import_bytes, here 1 MiB.
                            let! s =
                                statusOf
                                    (head "POST" "/eth/v1/keystores" (bearer token) "Content-Length: 1048577\r\n")
                                    some

                            Expect.stringStarts
                                s
                                "HTTP/1.1 413"
                                "an import body over max_import_bytes, by Content-Length"
                            // Sends the head and body in the background (the server may stop reading) and
                            // returns what comes back within `seconds`.
                            let exchange (head: string) (body: byte[]) (seconds: float) =
                                task {
                                    use tcp = new TcpClient()
                                    do! tcp.ConnectAsync(IPAddress.Loopback, port)
                                    let s = tcp.GetStream()

                                    let sending =
                                        task {
                                            try
                                                let h = Encoding.ASCII.GetBytes head
                                                do! s.WriteAsync(h, 0, h.Length)
                                                do! s.WriteAsync(body, 0, body.Length)
                                            with _ ->
                                                ()
                                        }

                                    let got = StringBuilder()
                                    let buf = Array.zeroCreate<byte> 4096
                                    use wait = new CancellationTokenSource(TimeSpan.FromSeconds seconds)

                                    try
                                        let mutable reading = true

                                        while reading do
                                            let! n = s.ReadAsync(buf.AsMemory(), wait.Token)

                                            if n = 0 then
                                                reading <- false
                                            else
                                                got.Append(Encoding.ASCII.GetString(buf, 0, n)) |> ignore
                                    with _ ->
                                        ()

                                    do! sending
                                    return got.ToString()
                                }
                            // A chunked import whose body passes 1 MiB inside slashing_protection: 413 with
                            // the hint, while the body streams.
                            let chunked (data: byte[]) =
                                Array.concat
                                    [
                                        Encoding.ASCII.GetBytes $"{data.Length:x}\r\n"
                                        data
                                        Encoding.ASCII.GetBytes "\r\n"
                                    ]

                            let opening =
                                Encoding.ASCII.GetBytes "{\"keystores\":[],\"passwords\":[],\"slashing_protection\":\""

                            let spaces = Array.create 65536 (byte ' ')
                            let overLimit = Array.concat [ chunked opening; yield! List.replicate 17 (chunked spaces) ]

                            let! answer =
                                exchange
                                    (head "POST" "/eth/v1/keystores" (bearer token) "Transfer-Encoding: chunked\r\n")
                                    overLimit
                                    10.0

                            Expect.stringStarts answer "HTTP/1.1 413" "a chunked import over max_import_bytes"
                            Expect.stringContains answer "split the import" "the 413 says what to do"
                            // An import whose history holds 1,001 distinct keys, over max_import_keys (here
                            // 1,000): 413, and none of the keys gets a record.
                            let gvrHex = core.Genesis.GenesisValidatorsRoot.Hex
                            let manyKey (i: int) = "0xc0000000" + (1_000_000 + i).ToString("x8") + String('0', 80)

                            let manyEntries =
                                String.Join(
                                    ",",
                                    [
                                        for i in 0..1000 ->
                                            $$$"""{"pubkey":"{{{manyKey i}}}","signed_blocks":[{"slot":"3"}],"signed_attestations":[]}"""
                                    ]
                                )

                            let manyInterchange =
                                $$$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{{gvrHex}}}"},"data":[{{{manyEntries}}}]}"""

                            let manyBody =
                                Json.toBytes (fun w ->
                                    w.WriteStartObject()
                                    w.WriteStartArray "keystores"
                                    w.WriteEndArray()
                                    w.WriteStartArray "passwords"
                                    w.WriteEndArray()
                                    w.WriteString("slashing_protection", manyInterchange)
                                    w.WriteEndObject())

                            let manyChunks = Array.append (chunked manyBody) (Encoding.ASCII.GetBytes "0\r\n\r\n")

                            let! answer =
                                exchange
                                    (head "POST" "/eth/v1/keystores" (bearer token) "Transfer-Encoding: chunked\r\n")
                                    manyChunks
                                    10.0

                            Expect.stringStarts answer "HTTP/1.1 413" "an import over max_import_keys"
                            Expect.stringContains answer "too many keys in one import" "the 413 names the cap"
                            Expect.stringContains answer "split it" "the 413 says what to do"
                            let firstKey = PubKey.TryParse(manyKey 0) |> ValueOption.get
                            Expect.isFalse (core.Slashing.HasRecord firstKey) "nothing imported"
                            // A body that stops coming: Kestrel's minimum data rate ends it with 408.
                            let! answer =
                                exchange
                                    (head "POST" "/eth/v1/keystores" (bearer token) "Content-Length: 100000\r\n")
                                    opening
                                    20.0

                            Expect.stringStarts answer "HTTP/1.1 408" "a stalled import body times out"
                            // A chunked import with its history (HttpClient sends a body of unknown length
                            // chunked) goes into the slashing DB.
                            let gvr = core.Genesis.GenesisValidatorsRoot

                            let interchange =
                                $$$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{{gvr.Hex}}}"},"data":[{"pubkey":"{{{(pubkeyOf 5).Hex}}}","signed_blocks":[{"slot":"3"}],"signed_attestations":[{"source_epoch":"1","target_epoch":"2"}]}]}"""

                            let importBody =
                                Json.toBytes (fun w ->
                                    w.WriteStartObject()
                                    w.WriteStartArray "keystores"
                                    w.WriteEndArray()
                                    w.WriteStartArray "passwords"
                                    w.WriteEndArray()
                                    w.WriteString("slashing_protection", interchange)
                                    w.WriteEndObject())

                            use importClient = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")
                            use importReq = new HttpRequestMessage(HttpMethod.Post, "/eth/v1/keystores")
                            importReq.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", token)
                            importReq.Headers.TransferEncodingChunked <- Nullable true
                            importReq.Content <- new StreamContent(new ChunkStream(importBody, (fun () -> 17)))
                            importReq.Content.Headers.ContentType <- Headers.MediaTypeHeaderValue("application/json")
                            use! importResp = importClient.SendAsync importReq
                            let! importText = importResp.Content.ReadAsStringAsync()
                            Expect.equal (int importResp.StatusCode) 200 importText
                            Expect.isTrue (core.Slashing.HasRecord(pubkeyOf 5)) "the history is in the DB"
                            // A request within the limits still works.
                            use client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")
                            use req = new HttpRequestMessage(HttpMethod.Post, fr)
                            req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", token)

                            req.Content <-
                                new StringContent(
                                    """{"ethaddress":"0x00000000000000000000000000000000000000bb"}""",
                                    Encoding.UTF8,
                                    "application/json"
                                )

                            use! resp = client.SendAsync req
                            Expect.equal (int resp.StatusCode) 202 "set"
                            cts.Cancel()
                            let! result = run
                            Expect.isOk result "run"
                    })
            testT "proposer config file: read-only keys in the API, prepare_beacon_proposer, reload" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

                    for i in 0..1 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore
                        File.WriteAllText(Path.Combine(ksDir, $"k{i}.json"), keystore i "pw")

                    File.WriteAllText(Path.Combine(dir, "password.txt"), "pw")
                    File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
                    let addr (c: string) = "0x" + String('0', 38) + c
                    let proposers = Path.Combine(dir, "proposers.json")

                    let writeProposers (key0: string) =
                        File.WriteAllText(
                            proposers,
                            $$"""{ "proposer_config": { "{{(pubkeyOf 0).Hex}}": { "fee_recipient": "{{addr key0}}", "graffiti": "from the file" },
                                                  "{{(pubkeyOf 5).Hex}}": { "fee_recipient": "{{addr "99"}}" } },
                             "default_config": { "fee_recipient": "{{addr "dd"}}", "gas_limit": "30000000" } }"""
                        )

                    writeProposers "cc"
                    let port = freePort ()

                    let configText (proposerFile: string) =
                        $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                       "fee_recipient": "{{addr "aa"}}", "proposer_config": "{{proposerFile}}",
                       "allow_start_without_history": ["all"],
                       "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ], "reload_interval_seconds": 0 },
                                    "keymanager": { "port": {{port}} } } }"""

                    let modules = [ LocalModule.create (); KeymanagerModule.create () ]

                    let options config log ready =
                        {
                            Config = config
                            Modules = modules
                            Http = new HttpClient(h.Node, false)
                            Time = h.Time
                            Log = log
                            OnSlotDone = h.Waiter.Done
                            OnReady = fun core _ -> ready core
                        }

                    let parse text =
                        match
                            Config.parse text dir [ "local"; "keymanager" ]
                            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
                        with
                        | Error es -> failtestf "%A" es
                        | Ok c -> c
                    // A broken file fails the start.
                    File.WriteAllText(
                        Path.Combine(dir, "broken.json"),
                        """{ "default_config": { "builder": { "relays": [] } } }"""
                    )

                    let! failed =
                        Runner.run (options (parse (configText "broken.json")) Log.none ignore) CancellationToken.None

                    match failed with
                    | Error e -> Expect.stringContains e "unknown field 'relays'" "start refused"
                    | Ok() -> failtest "started with a broken proposer config"

                    use cts = new CancellationTokenSource()
                    let log, lines = Log.memory ()
                    let ready = TaskCompletionSource<CoreServices>()

                    let run =
                        Runner.run
                            (options (parse (configText "proposers.json")) log (fun core ->
                                ready.TrySetResult core |> ignore))
                            cts.Token

                    let! _ = ready.Task.WaitAsync(TimeSpan.FromSeconds 20.0)
                    let token = File.ReadAllText(Path.Combine(dir, "data", "api-token.txt")).Trim()
                    use client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")

                    let call (meth: string) (path: string) (body: string option) =
                        task {
                            use req = new HttpRequestMessage(HttpMethod meth, path)
                            req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", token)

                            body
                            |> Option.iter (fun b ->
                                req.Content <- new StringContent(b, Encoding.UTF8, "application/json"))

                            use! resp = client.SendAsync req
                            let! text = resp.Content.ReadAsStringAsync()
                            return int resp.StatusCode, text
                        }

                    let url i what = $"/eth/v1/validator/{(pubkeyOf i).Hex}/{what}"
                    // Key 0 is in the file: GET reports the file's values, writes answer 403.
                    let! _, text = call "GET" (url 0 "feerecipient") None
                    Expect.stringContains text (addr "cc") "file entry"
                    let! _, text = call "GET" (url 0 "gas_limit") None
                    Expect.stringContains text "30000000" "file default"
                    let! _, text = call "GET" (url 0 "graffiti") None
                    Expect.stringContains text "from the file" "file graffiti"
                    let! s, text = call "POST" (url 0 "feerecipient") (Some $$"""{"ethaddress":"{{addr "ee"}}"}""")
                    Expect.equal s 403 text
                    let! s, text = call "DELETE" (url 0 "graffiti") None
                    Expect.equal s 403 text
                    let! s, _ = call "POST" (url 0 "gas_limit") (Some """{"gas_limit":"1"}""")
                    Expect.equal s 403 "gas limit read-only too"
                    // Key 1 is not: the file default applies until the API sets a value, which wins.
                    let! _, text = call "GET" (url 1 "feerecipient") None
                    Expect.stringContains text (addr "dd") "file default"
                    let! s, _ = call "POST" (url 1 "feerecipient") (Some $$"""{"ethaddress":"{{addr "ee"}}"}""")
                    Expect.equal s 202 "API write for a key not in the file"
                    let! _, text = call "GET" (url 1 "feerecipient") None
                    Expect.stringContains text (addr "ee") "API over the file default"
                    let! s, _ = call "DELETE" (url 1 "graffiti") None
                    Expect.equal s 204 "delete for a key not in the file"

                    let lastPrepare () =
                        h.Node.Posts
                        |> Seq.filter (fun (p, _) -> p.EndsWith "prepare_beacon_proposer")
                        |> Seq.map snd
                        |> Seq.tryLast
                        |> Option.defaultValue ""

                    do! h.RunSlots(0UL, uint64 (slotsPerEpoch - 1))
                    let sent = lastPrepare ()
                    Expect.stringContains sent (addr "cc") "key 0: the file's fee recipient"
                    Expect.stringContains sent (addr "ee") "key 1: the API's fee recipient"
                    Expect.isFalse (sent.Contains(addr "aa")) "no core default"
                    // A change on disk is checked 500 ms before the next epoch and in place at its start.
                    writeProposers "c1"
                    let boundary = h.Clock.SlotStart(uint64 slotsPerEpoch)
                    h.Time.Advance(boundary - TimeSpan.FromMilliseconds 400.0 - h.Time.GetUtcNow())
                    let mutable seen = false
                    let sw = Diagnostics.Stopwatch.StartNew()

                    while not seen && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                        let! _, text = call "GET" (url 0 "feerecipient") None
                        seen <- text.Contains(addr "c1")

                        if not seen then
                            do! Task.Delay 10

                    Expect.isTrue seen "in place before the epoch starts"
                    do! h.RunSlots(uint64 slotsPerEpoch, uint64 (2 * slotsPerEpoch - 1))
                    Expect.stringContains (lastPrepare ()) (addr "c1") "reloaded"
                    let! _, text = call "GET" (url 0 "feerecipient") None
                    Expect.stringContains text (addr "c1") "API sees the reload"
                    // A broken file keeps the last good one.
                    File.WriteAllText(proposers, """{ "default_config": { "fee_recipient": "0x12" } }""")
                    do! h.RunSlots(uint64 (2 * slotsPerEpoch), uint64 (3 * slotsPerEpoch - 1))
                    Expect.stringContains (lastPrepare ()) (addr "c1") "last good file kept"
                    // The reload runs in the background, so its log line can land after RunSlots returns.
                    let waitForLine (matches: string -> bool) =
                        task {
                            let sw = Diagnostics.Stopwatch.StartNew()

                            while not (lines |> Seq.exists matches) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
                                do! Task.Delay 10

                            return lines |> Seq.exists matches
                        }

                    let! logged = waitForLine (fun l -> l.StartsWith "ERROR" && l.Contains "keeping the last good one")
                    Expect.isTrue logged "error logged"
                    let! noted = waitForLine (fun l -> l.Contains "1 listed keys are not held")
                    Expect.isTrue noted "key 5 noted"
                    cts.Cancel()
                    let! result = run
                    Expect.isOk result "run"
                })
        ]

/// The token file and the data dir: modes at create, and loose or empty token files refused.
[<Tests>]
let tokenTests =
    let owner = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let ownerDir = owner ||| UnixFileMode.UserExecute

    testList
        "keymanager token file"
        [
            test "a new token file is 0600 in a new 0700 dir" {
                if not (OperatingSystem.IsWindows()) then
                    let file = Path.Combine(tempDir (), "sub", "api-token.txt")

                    match KeymanagerModule.loadOrCreateToken file with
                    | Ok token ->
                        Expect.equal token.Length 64 "32 bytes as hex"
                        Expect.equal (File.GetUnixFileMode file) owner "file 0600"
                        Expect.equal (File.GetUnixFileMode(Path.GetDirectoryName file)) ownerDir "dir 0700"
                        Expect.equal (KeymanagerModule.loadOrCreateToken file) (Ok token) "read back"
                    | Error e -> failtest e
            }
            test "a token file the group or others can read is refused" {
                if not (OperatingSystem.IsWindows()) then
                    let file = Path.Combine(tempDir (), "api-token.txt")
                    File.WriteAllText(file, "secret\n")

                    for loose in [ UnixFileMode.GroupRead; UnixFileMode.OtherRead; UnixFileMode.OtherWrite ] do
                        File.SetUnixFileMode(file, owner ||| loose)
                        Expect.isError (KeymanagerModule.loadOrCreateToken file) $"{loose}"

                    File.SetUnixFileMode(file, owner)
                    Expect.equal (KeymanagerModule.loadOrCreateToken file) (Ok "secret") "0600 is read"
            }
            test "an empty token file is refused" {
                let file = Path.Combine(tempDir (), "api-token.txt")
                File.WriteAllText(file, " \n")

                if not (OperatingSystem.IsWindows()) then
                    File.SetUnixFileMode(file, owner)

                Expect.isError (KeymanagerModule.loadOrCreateToken file) "empty"
            }
            test "a new data dir is 0700" {
                if not (OperatingSystem.IsWindows()) then
                    let path = Path.Combine(tempDir (), "data")

                    match DataDir.Acquire(path, Log.none) with
                    | Ok d ->
                        (d :> IDisposable).Dispose()
                        Expect.equal (File.GetUnixFileMode path) ownerDir "0700"
                    | Error e -> failtest e
            }
            test "a data dir made with a looser mode is set to 0700 at open" {
                if not (OperatingSystem.IsWindows()) then
                    let path = Path.Combine(tempDir (), "data")
                    Directory.CreateDirectory path |> ignore

                    File.SetUnixFileMode(
                        path,
                        ownerDir
                        ||| UnixFileMode.GroupRead
                        ||| UnixFileMode.GroupExecute
                        ||| UnixFileMode.OtherRead
                        ||| UnixFileMode.OtherExecute
                    )

                    let log, lines = Log.memory ()

                    for _ in 1..2 do
                        match DataDir.Acquire(path, log) with
                        | Ok d ->
                            (d :> IDisposable).Dispose()
                            Expect.equal (File.GetUnixFileMode path) ownerDir "0700"
                        | Error e -> failtest e

                    Expect.equal lines.Count 1 $"one line, at the first open only: {List.ofSeq lines}"
                    let line = Seq.head lines
                    Expect.isTrue (line.StartsWith "INFO ") "at info"
                    Expect.stringContains line "mode 755" "names the old mode"
                    Expect.stringContains line "set to 700" "and the new one"

                    // As eplix switch makes it before the first start.
                    let fresh = Path.Combine(tempDir (), "switch-data")
                    let log, lines = Log.memory ()
                    DataDir.Prepare(fresh, log)
                    Expect.equal (File.GetUnixFileMode fresh) ownerDir "a new dir is 0700"
                    Expect.isEmpty lines "a new dir changes no mode"
            }
        ]

/// The per-key settings file under concurrent API writes.
[<Tests>]
let settingsFileTests =
    testList
        "keymanager settings file"
        [
            test "concurrent saves keep every key's setting and leave no temporary file" {
                let dir = tempDir ()
                let file = KeymanagerModule.settingsFile dir
                let registry = KeyRegistry()
                let save = KeymanagerModule.settingsWriter file (fun () -> registry.AllSettings)
                let fee (i: int) = ValueSome(sprintf "0x%040x" (i + 1))

                Threading.Tasks.Parallel.For(
                    0,
                    64,
                    fun i ->
                        registry.SetSettings(pubkeyOf i, fun s -> { s with FeeRecipient = fee i })
                        save ()
                )
                |> ignore

                match KeymanagerApi.settingsOfJson (File.ReadAllBytes file) with
                | Ok all ->
                    let m = Map.ofList all

                    for i in 0..63 do
                        Expect.equal
                            (m.TryFind(pubkeyOf i) |> Option.map (fun s -> s.FeeRecipient))
                            (Some(fee i))
                            $"key {i}"
                | Error e -> failtest e

                Expect.isFalse (File.Exists(file + ".tmp")) "no temporary file"

                if not (OperatingSystem.IsWindows()) then
                    Expect.equal (File.GetUnixFileMode file) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite) "0600"
            }

            test "the settings file takes only values the API takes, and names the key of a bad one" {
                let pk = (pubkeyOf 3).Hex

                let read (fields: string) =
                    KeymanagerApi.settingsOfJson (Text.Encoding.UTF8.GetBytes $$"""{ "{{pk}}": { {{fields}} } }""")

                for fields, what in
                    [
                        "\"fee_recipient\": \"0x12\"", "fee_recipient"
                        "\"fee_recipient\": 5", "fee_recipient"
                        "\"gas_limit\": \"-1\"", "gas_limit"
                        "\"gas_limit\": \"0\"", "gas_limit"
                        "\"gas_limit\": \"lots\"", "gas_limit"
                        $"\"graffiti\": \"{String('g', 33)}\"", "graffiti"
                    ] do
                    match read fields with
                    | Ok _ -> failtestf "accepted %s" fields
                    | Error e ->
                        Expect.stringContains e pk $"names the key: {fields}"
                        Expect.stringContains e what $"names the field: {fields}"

                match
                    read
                        "\"fee_recipient\": \"0x00000000000000000000000000000000000000AB\", \"gas_limit\": \"30000000\", \"graffiti\": \"ok\""
                with
                | Ok [ k, s ] ->
                    Expect.equal k (pubkeyOf 3) "key"

                    Expect.equal
                        s.FeeRecipient
                        (ValueSome "0x00000000000000000000000000000000000000ab")
                        "fee recipient as the API stores it"

                    Expect.equal s.GasLimit (ValueSome 30_000_000UL) "gas limit"
                    Expect.equal s.Graffiti (ValueSome "ok") "graffiti"
                | other -> failtestf "%A" other

                let file = KeymanagerModule.settingsFile (tempDir ())
                Expect.equal (KeymanagerModule.loadSettings file) (Ok []) "no file, no settings"
                File.WriteAllText(file, "{ not json")

                match KeymanagerModule.loadSettings file with
                | Ok _ -> failtest "a broken file loaded"
                | Error e -> Expect.stringContains e file "names the file"
            }

        ]
