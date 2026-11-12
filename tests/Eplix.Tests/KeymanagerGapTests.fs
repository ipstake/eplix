/// Keymanager paths that move slashing history while keys sign: a delete racing a burst of
/// signatures, a key moved from one VC to another, and history imported over a running key.
module Eplix.Tests.KeymanagerGapTests

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
open Eplix.Slashing
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

/// A whole VC (local and keymanager modules) on its own data dir with no configured keys.
type private RunningVc =
    {
        Core: CoreServices
        Run: Task<Result<unit, string>>
        Cts: CancellationTokenSource
        Lines: Collections.Concurrent.ConcurrentQueue<string>
        Call: string -> string -> string option -> Task<int * string>
    }

    member v.Stop() =
        task {
            v.Cts.Cancel()
            let! r = v.Run.WaitAsync(TimeSpan.FromSeconds 20.0)
            Expect.isOk r $"""run; log: {String.Join('\n', v.Lines)}"""
        }

/// startVc with `first` modules started before the local module, and `prepare` run on the data
/// dir before the start.
let private startVcWith (h: Harness) (allow: string) (first: Module list) (prepare: string -> unit) =
    task {
        let dir = tempDir ()
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
        prepare (Path.Combine(dir, "data"))
        let port = freePort ()

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "allow_start_without_history": [{{allow}}],
                 "modules": { "local": { "reload_interval_seconds": 0 }, "keymanager": { "port": {{port}} } } }"""

        let modules = first @ [ LocalModule.create (); KeymanagerModule.create () ]

        match
            Config.parse configText dir [ "local"; "keymanager" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> return failtestf "%A" es
        | Ok config ->
            let cts = new CancellationTokenSource()
            let log, lines = Log.memory ()
            let ready = TaskCompletionSource<CoreServices>()

            let run =
                runSeeded
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
            let client = new HttpClient(BaseAddress = Uri $"http://127.0.0.1:{port}")

            let call (meth: string) (path: string) (body: string option) =
                task {
                    use req = new HttpRequestMessage(HttpMethod meth, path)
                    req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Bearer", token)

                    body
                    |> Option.iter (fun b -> req.Content <- new StringContent(b, Encoding.UTF8, "application/json"))

                    use! resp = client.SendAsync req
                    let! text = resp.Content.ReadAsStringAsync()
                    return int resp.StatusCode, text
                }

            return
                {
                    Core = core
                    Run = run
                    Cts = cts
                    Lines = lines
                    Call = call
                }
    }

let private startVc (h: Harness) (allow: string) = startVcWith h allow [] ignore

let private importBody (keys: (int * string) list) (interchange: byte[] option) =
    Encoding.UTF8.GetString(
        Json.toBytes (fun w ->
            w.WriteStartObject()
            w.WriteStartArray "keystores"

            for i, pw in keys do
                w.WriteStringValue(keystore i pw)

            w.WriteEndArray()
            w.WriteStartArray "passwords"

            for _, pw in keys do
                w.WriteStringValue pw

            w.WriteEndArray()

            interchange
            |> Option.iter (fun x -> w.WriteString("slashing_protection", Encoding.UTF8.GetString x))

            w.WriteEndObject())
    )

let private statusesOf (text: string) =
    [
        for x in JsonDocument.Parse(text).RootElement.GetProperty("data").EnumerateArray() ->
            x.GetProperty("status").GetString()
    ]

let private interchangeOf (text: string) =
    match
        Interchange.parse (
            Encoding.UTF8.GetBytes(JsonDocument.Parse(text).RootElement.GetProperty("slashing_protection").GetString())
        )
    with
    | Ok x -> x
    | Error e -> failtest e

let private vote (h: Harness) (slot: Slot) (target: Epoch) (rootTag: int) =
    {
        Slot = slot
        Index = 0UL
        BeaconBlockRoot = root rootTag
        Source =
            {
                Epoch = 0UL
                Root = h.Node.BlockRoot 0UL
            }
        Target =
            {
                Epoch = target
                Root = root (1000 + int target)
            }
    }

/// S5: a burst of signatures for one key on many threads while DELETE runs. Every signature made
/// is in the returned interchange (its target at or below the exported mark), and nothing signs
/// once the response is back.
let private deleteDuringSigning () =
    task {
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
        let! vc = startVc h $"\"{(pubkeyOf 1).Hex}\""
        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] None))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        do! h.RunSlots(0UL, uint64 slotsPerEpoch)
        Expect.equal (vc.Core.Registry.TryGet(pubkeyOf 1)).Value.State KeyState.Active "the key signs"
        let pk = pubkeyOf 1
        let spec = vc.Core.Spec
        let gvr' = vc.Core.Genesis.GenesisValidatorsRoot
        let signedTargets = Collections.Concurrent.ConcurrentBag<Epoch * int64>()
        let clock = Diagnostics.Stopwatch.StartNew()
        let mutable responseAt = Int64.MaxValue
        use stop = new CancellationTokenSource()
        // 8 signers, each with its own increasing targets, until the delete has answered.
        let signers =
            [
                for t in 0..7 ->
                    Task.Run(fun () ->
                        task {
                            let mutable target = 10UL + uint64 t

                            while not stop.IsCancellationRequested && target < 100_000UL do
                                let req =
                                    Duty.request
                                        spec
                                        gvr'
                                        pk
                                        Priority.High
                                        DateTimeOffset.MaxValue
                                        (Duty.Attestation(vote h 1UL target t))

                                match! vc.Core.Pipeline.Sign(req, CancellationToken.None) with
                                | Signed _ -> signedTargets.Add((target, clock.ElapsedTicks))
                                | _ -> ()

                                target <- target + 8UL
                        }
                        :> Task)
            ]
        // Delete once more than one signature per signer is in, not after a fixed delay: under load
        // with 3 suites on 8 cores the first 50 ms held only 8 signatures.
        let wait = Diagnostics.Stopwatch.StartNew()

        while signedTargets.Count <= 8 && wait.Elapsed < TimeSpan.FromSeconds 10.0 do
            do! Task.Delay 5

        let! s, text = vc.Call "DELETE" "/eth/v1/keystores" (Some $"""{{"pubkeys":["{pk.Hex}"]}}""")
        responseAt <- clock.ElapsedTicks
        do! Task.Delay 100
        stop.Cancel()
        do! Task.WhenAll(signers).WaitAsync(TimeSpan.FromSeconds 20.0)
        Expect.equal (s, statusesOf text) (200, [ "deleted" ]) text
        let exported = interchangeOf text
        let e = exported.Data |> List.find (fun d -> d.PubKey = pk)
        let mark = e.SignedAttestations |> List.map (fun a -> a.TargetEpoch) |> List.max
        let signed = List.ofSeq signedTargets
        Expect.isGreaterThan signed.Length 8 "the burst signed before the delete"

        for target, _ in signed do
            Expect.isLessThanOrEqual target mark $"signature for target {target} covered by the exported mark {mark}"

        for target, at in signed do
            Expect.isLessThan at responseAt $"signature for target {target} made after the delete answered"

        let! after =
            vc.Core.Pipeline.Sign(
                Duty.request
                    spec
                    gvr'
                    pk
                    Priority.High
                    DateTimeOffset.MaxValue
                    (Duty.Attestation(vote h 1UL 200_000UL 1)),
                CancellationToken.None
            )

        Expect.isFalse
            (match after with
             | Signed _ -> true
             | _ -> false)
            "a deleted key signs nothing"

        do! vc.Stop()
    }

/// S6: key 1 signs epochs 0 to 3 in VC A, moves to VC B through DELETE and POST with the returned
/// interchange; B refuses A's old messages and attests in epoch 4.
let private migrateBetweenVcs () =
    task {
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 0, "active_ongoing") |> ignore
        h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
        let pk = pubkeyOf 1
        let! a = startVc h $"\"{pk.Hex}\""
        let! s, text = a.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] None))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        do! h.RunSlots(0UL, uint64 (4 * slotsPerEpoch - 1))
        let fromA = h.Node.Submissions |> Seq.filter (fun x -> x.AttesterIndex = 1UL) |> List.ofSeq
        Expect.equal (fromA |> List.map (fun x -> x.Data.Target.Epoch)) [ 0UL .. 3UL ] "A signed epochs 0 to 3"
        let! s, text = a.Call "DELETE" "/eth/v1/keystores" (Some $"""{{"pubkeys":["{pk.Hex}"]}}""")
        Expect.equal (s, statusesOf text) (200, [ "deleted" ]) text
        let interchange = JsonDocument.Parse(text).RootElement.GetProperty("slashing_protection").GetString()
        do! a.Stop()
        // B: a fresh data dir, no key allowed to start without history.
        let! b = startVc h ""

        let! s, text =
            b.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw2" ] (Some(Encoding.UTF8.GetBytes interchange))))

        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        // A's last vote again with another root, and an older one: refused.
        let last = fromA |> List.last

        for data, what in
            [
                { last.Data with
                    BeaconBlockRoot = root 777
                },
                "a double vote of epoch 3"
                fromA[1].Data, "epoch 1 again"
            ] do
            let req = Duty.request b.Core.Spec gvr pk Priority.High DateTimeOffset.MaxValue (Duty.Attestation data)
            let! outcome = b.Core.Pipeline.Sign(req, CancellationToken.None)

            Expect.isFalse
                (match outcome with
                 | Signed _ -> true
                 | _ -> false)
                $"B refuses {what}"

        h.Node.Submissions.Clear()
        do! h.RunSlots(uint64 (4 * slotsPerEpoch), uint64 (5 * slotsPerEpoch - 1))

        Expect.equal
            (h.Node.Submissions
             |> Seq.filter (fun x -> x.AttesterIndex = 1UL)
             |> Seq.map (fun x -> x.Data.Target.Epoch)
             |> List.ofSeq)
            [ 4UL ]
            $"""B attests in epoch 4; log: {String.Join('\n', b.Lines)}"""

        do! b.Stop()
    }

/// K2: history imported through the keymanager for a key that is running only raises its marks.
let private importOverRunningKey () =
    task {
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
        let pk = pubkeyOf 1
        let! vc = startVc h $"\"{pk.Hex}\""
        let! _ = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] None))
        do! h.RunSlots(0UL, uint64 (2 * slotsPerEpoch - 1))
        let marksOf () = (vc.Core.Slashing.Marks pk).Value
        Expect.equal (marksOf ()).Attestation.Value.Target 1UL "signed epochs 0 and 1"

        let history (source: Epoch) (target: Epoch) (slot: Slot) =
            Interchange.write
                {
                    GenesisValidatorsRoot = gvr
                    Data =
                        [
                            {
                                PubKey = pk
                                SignedBlocks = [ { Slot = slot; SigningRoot = ValueNone } ]
                                SignedAttestations =
                                    [
                                        {
                                            SourceEpoch = source
                                            TargetEpoch = target
                                            SigningRoot = ValueNone
                                        }
                                    ]
                            }
                        ]
                }
        // Another client's history, ahead of this VC: the marks go up.
        let! s, text =
            vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] (Some(history 2UL 4UL 30UL))))

        Expect.equal (s, statusesOf text) (200, [ "duplicate" ]) text
        let m = marksOf ()
        Expect.equal (m.Attestation.Value.Source, m.Attestation.Value.Target) (2UL, 4UL) "attestation marks raised"
        Expect.equal m.Block.Value.Slot 30UL "block mark raised"
        // History behind the VC: nothing goes down.
        let! s, _ = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] (Some(history 0UL 1UL 3UL))))
        Expect.equal s 200 "accepted"
        let m2 = marksOf ()

        Expect.equal
            (m2.Attestation.Value.Source, m2.Attestation.Value.Target, m2.Block.Value.Slot)
            (2UL, 4UL, 30UL)
            "never lower"
        // Epochs 2 to 4 are at or below the imported target: refused; epoch 5 signs.
        h.Node.Submissions.Clear()
        do! h.RunSlots(uint64 (2 * slotsPerEpoch), uint64 (6 * slotsPerEpoch - 1))

        Expect.equal
            (h.Node.Submissions |> Seq.map (fun x -> x.Data.Target.Epoch) |> List.ofSeq)
            [ 5UL ]
            $"""only epoch 5 signs; log: {String.Join('\n', vc.Lines)}"""

        do! vc.Stop()
    }

/// V8: the answers of every keymanager endpoint Eplix serves, success and error, against the
/// keymanager-APIs v1.2.0-alpha.0 OpenAPI document (fetched by scripts/fetch-test-vectors.sh).
let private responsesMatchTheSpec () =
    task {
        let file = Path.Combine(vectors, ".download", "keymanager-apis", "keymanager-oapi.json")

        if not (File.Exists file) then
            failtestf "%s is missing; run scripts/fetch-test-vectors.sh" file

        let api = OpenApi.load file
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
        h.Node.AddValidator(pubkeyOf 2, "active_ongoing") |> ignore
        let pk = pubkeyOf 1
        let! vc = startVc h $"\"{pk.Hex}\""
        let answers = Collections.Generic.List<string * string * int * string>()

        let call meth (path: string) body =
            task {
                let! s, text = vc.Call meth path body
                answers.Add((meth, path, s, text))
                return s
            }

        let v what = $"/eth/v1/validator/{pk.Hex}/{what}"
        let other = $"/eth/v1/validator/{(pubkeyOf 9).Hex}/feerecipient"
        let! _ = call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] None))
        let! _ = call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw"; 2, "pw2" ] None))
        let! _ = call "POST" "/eth/v1/keystores" (Some """{ "keystores": [] }""")
        let! _ = call "GET" "/eth/v1/keystores" None
        do! h.RunSlots(0UL, uint64 slotsPerEpoch)

        for what, body in
            [
                "feerecipient", """{"ethaddress":"0x00000000000000000000000000000000000000bb"}"""
                "gas_limit", """{"gas_limit":"30000000"}"""
                "graffiti", """{"graffiti":"eplix"}"""
            ] do
            let! _ = call "GET" (v what) None
            let! _ = call "POST" (v what) (Some body)
            let! _ = call "POST" (v what) (Some "{}")
            let! _ = call "GET" (v what) None
            let! _ = call "DELETE" (v what) None
            ()

        let! _ = call "GET" other None
        let! _ = call "POST" (v "voluntary_exit" + "?epoch=1") None
        let! _ = call "GET" "/eth/v1/remotekeys" None

        let! _ =
            call
                "DELETE"
                "/eth/v1/keystores"
                (Some $"""{{"pubkeys":["{pk.Hex}","{(pubkeyOf 2).Hex}","{(pubkeyOf 9).Hex}"]}}""")

        let! _ = call "DELETE" "/eth/v1/keystores" (Some "{")
        do! vc.Stop()

        let problems =
            [
                for meth, path, status, text in answers do
                    let p = path.Split('?')[0]

                    match api.Find(meth, p) with
                    | None ->
                        // voluntary_exit is in keymanager-APIs v1.1.0 and later under the same path.
                        yield $"{meth} {p}: not in keymanager-APIs v1.2.0-alpha.0"
                    | Some(template, op) ->
                        let responses = op.GetProperty "responses"

                        let declared =
                            match responses.TryGetProperty(string status) with
                            | true, r -> Some r
                            | _ ->
                                match responses.TryGetProperty "default" with
                                | true, r -> Some r
                                | _ -> None

                        match declared with
                        | None -> yield $"{meth} {template}: status {status} is not declared"
                        | Some r ->
                            match (api.Resolve r).TryGetProperty "content" with
                            | true, content ->
                                match content.TryGetProperty "application/json" with
                                | true, media when text.Length > 0 ->
                                    use doc = JsonDocument.Parse text

                                    for e in api.Check(media.GetProperty "schema", doc.RootElement) do
                                        yield $"{meth} {template} {status}: {e}"
                                | true, _ -> yield $"{meth} {template} {status}: an empty body where the API has JSON"
                                | _ -> ()
                            | _ ->
                                if text.Length > 0 && status <> 204 then
                                    ()
            ]

        let statuses =
            answers |> Seq.map (fun (m, p, s, _) -> $"{m} {p.Split('?')[0]} {s}") |> Seq.distinct |> List.ofSeq

        Expect.isEmpty
            problems
            $"""answers that do not fit keymanager-APIs v1.2.0-alpha.0:
{String.Join("\n", problems)}
answers: {String.Join("; ", statuses)}"""

        Expect.isGreaterThanOrEqual
            (answers |> Seq.map (fun (_, _, s, _) -> s) |> Seq.distinct |> Seq.length)
            4
            "several statuses checked"
    }

/// Finding 12: an import with a slow keystore decrypts outside the store's lock, so the key list
/// answers while it runs.
let private slowImportDoesNotBlockList () =
    task {
        let h = harness ()
        let! vc = startVc h "\"all\""
        // Twice a standard keystore's scrypt work: a quarter of a second in Release, seconds in
        // Debug. Encrypting takes as long as the import's decrypt, so it sets the wait below.
        let sw = Diagnostics.Stopwatch.StartNew()

        let slow =
            Keystore.encrypt (secretOf 4) "pw" (Keystore.Scrypt(1 <<< 16, 8, 1, Array.create 32 4uy, 32)) ""

        let decryptTime = sw.Elapsed

        let body =
            Encoding.UTF8.GetString(
                Json.toBytes (fun w ->
                    w.WriteStartObject()
                    w.WriteStartArray "keystores"
                    w.WriteStringValue slow
                    w.WriteEndArray()
                    w.WriteStartArray "passwords"
                    w.WriteStringValue "pw"
                    w.WriteEndArray()
                    w.WriteEndObject())
            )

        let import = vc.Call "POST" "/eth/v1/keystores" (Some body)
        // A head start only: the check below does not depend on how long anything takes.
        do! Task.Delay(decryptTime / 4.0)
        let! s, _ = vc.Call "GET" "/eth/v1/keystores" None
        Expect.equal s 200 "list"
        // Behind the lock the list would answer only after the import.
        Expect.isFalse import.IsCompleted "the list answered while the import was still running"
        let! s, text = import
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        do! vc.Stop()
    }

/// Finding 15: keys another backend routes. A keystore import of such a key is a duplicate and
/// saves nothing; a delete of a local copy that does not sign leaves the other backend's key alone.
let private keysOfAnotherBackend () =
    task {
        let h = harness ()

        for i in 2..3 do
            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

        let other =
            LocalBackend.create "other" [ for i in 2..3 -> pubkeyOf i, SecretKey.Copy(ReadOnlySpan(secretOf i)) ]

        let otherModule =
            {
                Name = "other"
                Configure = fun _ -> Ok()
                Check = fun _ -> Ok ""
                Start =
                    fun core _ ->
                        for i in 2..3 do
                            core.Registry.Add(pubkeyOf i, other) |> ignore

                        Task.FromResult(Ok { Stop = fun () -> Task.CompletedTask })
            }
        // A local copy of key 2 in the data dir, loaded after the other module took the key.
        let prepare (data: string) = LocalModule.ManagedStore.save data (pubkeyOf 2) (keystore 2 "pw") "pw"
        let! vc = startVcWith h "\"all\"" [ otherModule ] prepare
        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 3, "pw" ] None))
        Expect.equal (s, statusesOf text) (200, [ "duplicate" ]) text
        Expect.isFalse (File.Exists(LocalModule.ManagedStore.keystoreFile vc.Core.DataDir (pubkeyOf 3))) "nothing saved"
        let! s, text = vc.Call "DELETE" "/eth/v1/keystores" (Some $"""{{"pubkeys":["{(pubkeyOf 2).Hex}"]}}""")
        Expect.equal (s, statusesOf text) (200, [ "error" ]) text
        Expect.stringContains text "other" "names the backend"
        let k = (vc.Core.Registry.TryGet(pubkeyOf 2)).Value
        Expect.equal k.Backend.Name "other" "route kept"
        Expect.notEqual k.State KeyState.Removed "the other backend's key is not retired"

        Expect.isTrue
            (File.Exists(LocalModule.ManagedStore.keystoreFile vc.Core.DataDir (pubkeyOf 2)))
            "local copy kept"
        // Once the other backend retired the key, nothing signs it: the local copy can go.
        vc.Core.Registry.SetState(pubkeyOf 2, KeyState.Removed)
        let! s, text = vc.Call "DELETE" "/eth/v1/keystores" (Some $"""{{"pubkeys":["{(pubkeyOf 2).Hex}"]}}""")
        Expect.equal (s, statusesOf text) (200, [ "deleted" ]) text

        Expect.isFalse
            (File.Exists(LocalModule.ManagedStore.keystoreFile vc.Core.DataDir (pubkeyOf 2)))
            "local copy deleted"

        do! vc.Stop()
    }

/// One import request takes at most KeymanagerApi.maxImport keystores; the check comes before
/// any decrypt.
let private importLimit () =
    task {
        let h = harness ()
        let! vc = startVc h ""
        let n = KeymanagerApi.maxImport + 1
        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ for _ in 1..n -> 2, "pw" ] None))
        Expect.equal s 400 text
        Expect.stringContains text "at most" "why"

        Expect.isFalse
            (File.Exists(LocalModule.ManagedStore.keystoreFile vc.Core.DataDir (pubkeyOf 2)))
            "nothing imported"

        do! vc.Stop()
    }

/// An API import without slashing_protection leaves the key discovered, with the
/// reason in the response, even when the node shows it pending. With an interchange in the same
/// request the key starts as before.
let private importWithoutHistory () =
    task {
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 2, "pending_queued") |> ignore
        h.Node.AddValidator(pubkeyOf 3, "active_ongoing") |> ignore
        let! vc = startVc h ""

        let messageOf (text: string) =
            let data = JsonDocument.Parse(text).RootElement.GetProperty "data"
            data[0].GetProperty("message").GetString()

        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 2, "pw" ] None))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        Expect.stringContains (messageOf text) "no slashing history" "the response says why"

        Expect.equal
            (vc.Core.Registry.TryGet(pubkeyOf 2)).Value.State
            KeyState.Discovered
            "no start from a pending status"

        Expect.isFalse (vc.Core.Slashing.HasRecord(pubkeyOf 2)) "no record, no floor"
        // An empty entry is no history: no record, no start.
        let x =
            Interchange.write
                {
                    GenesisValidatorsRoot = gvr
                    Data =
                        [
                            {
                                PubKey = pubkeyOf 3
                                SignedBlocks = []
                                SignedAttestations = []
                            }
                        ]
                }

        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 3, "pw" ] (Some x)))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        Expect.stringContains (messageOf text) "no slashing history" "the response says why"
        Expect.equal (vc.Core.Registry.TryGet(pubkeyOf 3)).Value.State KeyState.Discovered "empty entry: no start"
        Expect.isFalse (vc.Core.Slashing.HasRecord(pubkeyOf 3)) "empty entry: no record"

        let x =
            Interchange.write
                {
                    GenesisValidatorsRoot = gvr
                    Data =
                        [
                            {
                                PubKey = pubkeyOf 4
                                SignedBlocks = [ { Slot = 1UL; SigningRoot = ValueNone } ]
                                SignedAttestations = []
                            }
                        ]
                }

        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 4, "pw" ] (Some x)))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        Expect.equal (messageOf text) "" "nothing to explain"

        Expect.notEqual
            (vc.Core.Registry.TryGet(pubkeyOf 4)).Value.State
            KeyState.Discovered
            "history imported: the key goes on"

        do! vc.Stop()
    }

/// A keystore DELETE runs to the end under the VC's token: a client that gives up (its request
/// token cancelled) still gets the keys deleted and their slashing_protection, never a half
/// done delete with no history returned.
let private deleteOutlivesTheRequest () =
    task {
        let h = harness ()
        h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
        let pk = pubkeyOf 1
        let! vc = startVc h $"\"{pk.Hex}\""
        let! s, text = vc.Call "POST" "/eth/v1/keystores" (Some(importBody [ 1, "pw" ] None))
        Expect.equal (s, statusesOf text) (200, [ "imported" ]) text
        do! h.RunSlots(0UL, uint64 slotsPerEpoch)

        let ctx: KeymanagerApi.Context =
            {
                Core = vc.Core
                Token = "t"
                SaveSettings = ignore
            }

        use gone = new CancellationTokenSource()
        gone.Cancel()

        let req: KeymanagerApi.Request =
            {
                Method = "DELETE"
                Path = "/eth/v1/keystores"
                Query = Map.empty
                Authorization = "Bearer t"
                Body = Encoding.UTF8.GetBytes $"""{{"pubkeys":["{pk.Hex}"]}}"""
            }

        let! resp = KeymanagerApi.handle ctx req gone.Token
        let text = Encoding.UTF8.GetString resp.Body
        Expect.equal (resp.Status, statusesOf text) (200, [ "deleted" ]) text

        Expect.isNonEmpty
            ((interchangeOf text).Data |> List.filter (fun d -> d.PubKey = pk))
            "the key's history is returned"

        do! vc.Stop()
    }

/// A settings file the API would not have written (a bad fee recipient) fails the start and
/// names the file and the key, as a bad proposer config does.
let private badSettingsFileFailsTheStart () =
    task {
        let h = harness ()
        let dir = tempDir ()
        File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)
        let data = Path.Combine(dir, "data")

        if OperatingSystem.IsWindows() then
            Directory.CreateDirectory data |> ignore
        else
            Directory.CreateDirectory(
                data,
                UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
            )
            |> ignore

        let pk = (pubkeyOf 1).Hex
        File.WriteAllText(KeymanagerModule.settingsFile data, $$"""{ "{{pk}}": { "fee_recipient": "0x1234" } }""")

        let configText =
            $$"""{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
                 "modules": { "local": { "reload_interval_seconds": 0 }, "keymanager": { "port": {{freePort ()}} } } }"""

        let modules = [ LocalModule.create (); KeymanagerModule.create () ]

        match
            Config.parse configText dir [ "local"; "keymanager" ]
            |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
        with
        | Error es -> failtestf "%A" es
        | Ok config ->
            use cts = new CancellationTokenSource()
            let ready = TaskCompletionSource()

            let run =
                runSeeded
                    {
                        Config = config
                        Modules = modules
                        Http = new HttpClient(h.Node, false)
                        Time = h.Time
                        Log = Log.none
                        OnSlotDone = h.Waiter.Done
                        OnReady = fun _ _ -> ready.TrySetResult() |> ignore
                    }
                    cts.Token

            let! first = Task.WhenAny(run :> Task, ready.Task, Task.Delay(TimeSpan.FromSeconds 20.0))

            if first <> (run :> Task) then
                cts.Cancel()
                let! _ = run.WaitAsync(TimeSpan.FromSeconds 20.0)
                failtest "started with a bad settings file"

            match run.Result with
            | Ok() -> failtest "started with a bad settings file"
            | Error e ->
                Expect.stringContains e "key-settings.json" "names the file"
                Expect.stringContains e pk "names the key"
                Expect.stringContains e "fee_recipient" "names the field"
    }

[<Tests>]
let tests =
    testSequenced
    <| testList
        "keymanager"
        [
            testT "responses match the OpenAPI schema" responsesMatchTheSpec
            testT "delete during signing exports every signature" deleteDuringSigning
            testT "migrate a key between two VCs" migrateBetweenVcs
            testT "importing history for a running key only raises marks" importOverRunningKey
            testT "a slow import does not block the key list" slowImportDoesNotBlockList
            testT "keys another backend routes are not imported or retired" keysOfAnotherBackend
            testT "an import without slashing protection leaves the key discovered and says why" importWithoutHistory
            testT "one import request takes at most maxImport keystores" importLimit
            testT "a keystore delete outlives a client that gives up" deleteOutlivesTheRequest
            testT "a bad settings file fails the start" badSettingsFileFailsTheStart
        ]
