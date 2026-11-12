/// The keymanager API's /eth/v1/remotekeys over the Web3Signer module's remote key store, with
/// fake signers: list, import, delete, the restart, and a build without the module.
module Eplix.Tests.RemoteKeysTests

open System
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Web3Signer
open Eplix.Beacon
open Eplix.Keymanager
open Eplix.Slashing
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.ThresholdTests
open Eplix.Tests.Web3SignerTests

/// The core services a module and the keymanager API need, over the harness's fake beacon node.
/// Keys start without slashing history (the operator override), so a refresh makes them active.
type TestCore(h: Harness, dataDir: string) =
    let nodes =
        BeaconNodes(
            [
                BeaconClient(new HttpClient(h.Node, false), Uri "http://bn.test", TimeSpan.FromSeconds 5.0)
            ],
            1,
            h.Time,
            Log.none
        )

    let db =
        match SlashingDb.Open(new FileMarkFile(Path.Combine(dataDir, "slashing.db")), gvr) with
        | Ok db -> db
        | Error e -> failwith e

    let registry = KeyRegistry()
    let log, lines = Log.memory ()
    let pipeline = Pipeline(db, registry, h.Time, log)
    let mutable remote: RemoteKeyStore voption = ValueNone

    member _.Lines = lines
    member _.Db = db

    member _.Services: CoreServices =
        {
            Spec = h.Spec
            Genesis =
                {
                    GenesisTime = genesisTime
                    GenesisValidatorsRoot = gvr
                    GenesisForkVersion = h.Spec.Forks[0].Version
                }
            Clock = h.Clock
            Nodes = nodes
            Registry = registry
            Pipeline = pipeline
            Slashing = db
            Defaults =
                {
                    FeeRecipient = ValueNone
                    Graffiti = ""
                    GasLimit = 60_000_000UL
                }
            Graffiti = GraffitiService.Plain(registry, "")
            Log = log
            DataDir = dataDir
            RegisterBackend = fun _ -> Task.FromResult()
            RefreshKeys =
                fun ct ->
                    task {
                        let! _ = refreshEmpty ValueNone nodes registry db log ct
                        ()
                    }
            OnEpoch = ignore
            Shutdown = ignore
            Stopping = CancellationToken.None
            SetKeystores = ignore
            Keystores = fun () -> ValueNone
            SetRemoteKeys = fun s -> remote <- ValueSome s
            RemoteKeys = fun () -> remote
            AddDutyExtension = ignore
            SetBuilder = ignore
            Builder = fun () -> ValueNone
            SetSelections = ignore
            HaPeer = false
        }

    interface IDisposable with
        member _.Dispose() = (db :> IDisposable).Dispose()

/// Calls the keymanager API in process. Returns the status and the parsed body.
let callApi (core: CoreServices) (meth: string) (body: string) =
    task {
        let ctx: KeymanagerApi.Context =
            {
                Core = core
                Token = "t"
                SaveSettings = ignore
            }

        let req: KeymanagerApi.Request =
            {
                Method = meth
                Path = "/eth/v1/remotekeys"
                Query = Map.empty
                Authorization = "Bearer t"
                Body = Encoding.UTF8.GetBytes body
            }

        let! r = KeymanagerApi.handle ctx req CancellationToken.None
        let text = Encoding.UTF8.GetString r.Body
        return r.Status, text
    }

let dataOf (text: string) =
    use d = JsonDocument.Parse text
    [ for x in d.RootElement.GetProperty("data").EnumerateArray() -> x.Clone() ]

let statusesOf (text: string) = dataOf text |> List.map (fun x -> x.GetProperty("status").GetString())

/// (pubkey, url, readonly) of a GET answer.
let listedOf (text: string) =
    dataOf text
    |> List.map (fun x ->
        x.GetProperty("pubkey").GetString(), x.GetProperty("url").GetString(), x.GetProperty("readonly").GetBoolean())
    |> Set.ofList

let importBody (keys: (PubKey * string option) list) =
    let items =
        [
            for k, u in keys ->
                match u with
                | Some u -> $"""{{ "pubkey": "{k.Hex}", "url": "{u}" }}"""
                | None -> $"""{{ "pubkey": "{k.Hex}" }}"""
        ]

    $"""{{ "remote_keys": [ {String.Join(", ", items)} ] }}"""

let deleteBody (keys: PubKey list) =
    let items = [ for k in keys -> $"\"{k.Hex}\"" ]
    $"""{{ "pubkeys": [ {String.Join(", ", items)} ] }}"""

let private urlA = "http://w3s-a.test:9000/"
let private urlB = "http://w3s-b.test:9000/"
let private urlBTls = "https://w3s-b.test:9000/"

/// Signer A is configured and holds keys 0 and 1; signer B holds keys 2 and 3 and is known only
/// through the API, over http or https.
let private fakes () =
    let a = FakeSigner(urlA, [ for i in 0..1 -> pubkeyOf i, secretOf i ])
    let b = FakeSigner(urlB, [ for i in 2..3 -> pubkeyOf i, secretOf i ])

    let connect (e: EndpointSettings) =
        match e.Url.AbsoluteUri with
        | u when u = urlA -> a.Api
        | u when u = urlB || u = urlBTls -> b.Api
        | u -> failtestf "no fake signer at %s" u

    a, b, connect

let private configured: Web3SignerModule.Settings =
    { Web3SignerModule.apiOnly with
        Signers =
            [
                {
                    Url = Uri urlA
                    Tls = TlsSettings.None
                    Attestation = ValueNone
                }
            ]
    }

/// Discovers the configured keys, routes them, and starts the remote key store.
let private startStore (core: CoreServices) (set: Web3SignerModule.Web3SignerSet) =
    task {
        let! found, _ = set.Discover CancellationToken.None

        for k, b in found do
            core.Registry.Add(k, b) |> ignore

        core.SetRemoteKeys(Web3SignerModule.RemoteKeys.start false core set)
    }

let private signRandao (core: CoreServices) (h: Harness) (k: PubKey) =
    core.Pipeline.Sign(
        Duty.request h.Spec gvr k Priority.High (h.Time.GetUtcNow().AddSeconds 10.0) (Duty.RandaoReveal 1UL),
        CancellationToken.None
    )

[<Tests>]
let tests =
    testSequenced
    <| testList
        "remotekeys"
        [
            testT "list, import, sign through the given URL, restart, delete" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()
                    let _, b, connect = fakes ()
                    use tc = new TestCore(h, dir)
                    let core = tc.Services
                    let ws = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    do! startStore core ws
                    let! s, text = callApi core "GET" ""
                    Expect.equal s 200 text

                    Expect.equal
                        (listedOf text)
                        (set [ (pubkeyOf 0).Hex, urlA, true; (pubkeyOf 1).Hex, urlA, true ])
                        "configured keys, read-only"
                    // New key, a configured key, a bad URL.
                    let! s, text =
                        callApi
                            core
                            "POST"
                            (importBody
                                [
                                    pubkeyOf 2, Some urlB
                                    pubkeyOf 0, Some urlB
                                    pubkeyOf 3, Some "ftp://w3s.test"
                                ])

                    Expect.equal s 200 text
                    Expect.equal (statusesOf text) [ "imported"; "duplicate"; "error" ] text
                    // The same key twice in one request.
                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 3, Some urlB; pubkeyOf 3, Some urlB ])
                    Expect.equal (statusesOf text) [ "imported"; "duplicate" ] text

                    Expect.equal
                        (core.Registry.TryGet(pubkeyOf 2)).Value.State
                        KeyState.Active
                        "the import ran the history check"

                    Expect.equal
                        (core.Registry.TryGet(pubkeyOf 2)).Value.Backend.Name
                        $"web3signer {urlB}"
                        "routed to signer B"

                    let before = b.Bodies.Count

                    match! signRandao core h (pubkeyOf 2) with
                    | Signed sg ->
                        let r =
                            Duty.request
                                h.Spec
                                gvr
                                (pubkeyOf 2)
                                Priority.High
                                DateTimeOffset.MaxValue
                                (Duty.RandaoReveal 1UL)

                        Expect.isTrue
                            (Bls.verify
                                (ReadOnlySpan (pubkeyOf 2).Bytes)
                                (ReadOnlySpan r.SigningRoot.Bytes)
                                (ReadOnlySpan sg.Bytes))
                            "signature"
                    | o -> failtestf "remote key did not sign: %s" o.Describe

                    Expect.equal b.Bodies.Count (before + 1) "signed by signer B"
                    let! _, text = callApi core "GET" ""

                    Expect.equal
                        (listedOf text)
                        (set
                            [
                                (pubkeyOf 0).Hex, urlA, true
                                (pubkeyOf 1).Hex, urlA, true
                                (pubkeyOf 2).Hex, urlB, false
                                (pubkeyOf 3).Hex, urlB, false
                            ])
                        "API keys are not read-only"
                    // A restart loads the API keys from the data dir.
                    do
                        use tc2 = new TestCore(h, dir)
                        let set2 = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                        startStore tc2.Services set2 |> fun t -> t.GetAwaiter().GetResult()

                        Expect.equal
                            (tc2.Services.Registry.TryGet(pubkeyOf 2)).Value.Backend.Name
                            $"web3signer {urlB}"
                            "key 2 after a restart"

                        Expect.equal
                            (tc2.Services.Registry.TryGet(pubkeyOf 3)).Value.Backend.Name
                            $"web3signer {urlB}"
                            "key 3 after a restart"
                    // Delete: an API key, a configured key, an unknown key.
                    let! s, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2; pubkeyOf 0; pubkeyOf 7 ])
                    Expect.equal s 200 text
                    Expect.equal (statusesOf text) [ "deleted"; "error"; "not_found" ] text
                    use doc = JsonDocument.Parse text

                    Expect.isFalse
                        (doc.RootElement.TryGetProperty "slashing_protection" |> fst)
                        "no slashing protection in a remote key delete"

                    Expect.equal (core.Registry.TryGet(pubkeyOf 2)).Value.State KeyState.Removed "tombstone"
                    Expect.isTrue (tc.Db.HasRecord(pubkeyOf 2)) "the slashing record stays"
                    let! o = signRandao core h (pubkeyOf 2)

                    Expect.isFalse
                        (match o with
                         | Signed _ -> true
                         | _ -> false)
                        $"a deleted key signs nothing ({o.Describe})"

                    let saved = File.ReadAllText(Web3SignerModule.RemoteKeys.fileOf dir)
                    Expect.isFalse (saved.Contains (pubkeyOf 2).Hex) "gone from the file"
                    Expect.stringContains saved (pubkeyOf 3).Hex "key 3 stays in the file"
                    let! _, text = callApi core "GET" ""
                    Expect.isFalse (listedOf text |> Set.exists (fun (k, _, _) -> k = (pubkeyOf 2).Hex)) "not listed"
                    // An import brings a deleted key back.
                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.equal (statusesOf text) [ "imported" ] text
                    Expect.equal (core.Registry.TryGet(pubkeyOf 2)).Value.State KeyState.Active "active again"
                    // Malformed bodies.
                    let! s, _ = callApi core "POST" """{ "remote_keys": [ { "pubkey": "0x12" } ] }"""
                    Expect.equal s 400 "bad pubkey"
                    let! s, _ = callApi core "DELETE" "{}"
                    Expect.equal s 400 "no pubkeys"
                    ws.Stop()
                })

            testT "a halted API key is not deleted, and an import does not bring it back fresh" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let _, _, connect = fakes ()
                    use tc = new TestCore(h, tempDir ())
                    let core = tc.Services
                    let ws = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    do! startStore core ws
                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.equal (statusesOf text) [ "imported" ] text
                    core.Registry.SetState(pubkeyOf 2, KeyState.Halted "412 for a vote")

                    let halted () =
                        match (core.Registry.TryGet(pubkeyOf 2)).Value.State with
                        | KeyState.Halted _ -> true
                        | _ -> false

                    let! s, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2 ])
                    Expect.equal s 200 text
                    Expect.equal (statusesOf text) [ "error" ] text
                    Expect.stringContains text "halted" "the reason"
                    Expect.isTrue (halted ()) "still halted"
                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.notEqual (statusesOf text) [ "imported" ] text
                    Expect.isTrue (halted ()) "halted after the import"
                    ws.Stop()
                })

            testT "the saved file is 0600, written atomically, with no temporary file left" (fun () ->
                task {
                    let h = harness ()
                    h.Node.AddValidator(pubkeyOf 2, "active_ongoing") |> ignore
                    let dir = tempDir ()
                    let _, _, connect = fakes ()
                    use tc = new TestCore(h, dir)
                    let ws = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    do! startStore tc.Services ws
                    let! _, text = callApi tc.Services "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.equal (statusesOf text) [ "imported" ] text
                    let file = Web3SignerModule.RemoteKeys.fileOf dir
                    Expect.equal (File.GetUnixFileMode file) (UnixFileMode.UserRead ||| UnixFileMode.UserWrite) "0600"
                    Expect.isFalse (File.Exists(file + ".tmp")) "no temporary file"
                    ws.Stop()
                })

            testT "a 500 answer carries a fixed text; the exception goes to the VC log" (fun () ->
                task {
                    let h = harness ()
                    use tc = new TestCore(h, tempDir ())

                    let failing: RemoteKeyStore =
                        {
                            List = fun () -> failwith "/srv/secret/remote-keys.json: permission denied"
                            Import = fun _ _ -> Task.FromResult []
                            Delete = fun _ _ -> Task.FromResult []
                        }

                    tc.Services.SetRemoteKeys failing
                    let! s, text = callApi tc.Services "GET" ""
                    Expect.equal s 500 text
                    Expect.isFalse (text.Contains "/srv/secret") $"no path in the answer: {text}"

                    Expect.isTrue
                        (tc.Lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "/srv/secret"))
                        "the exception is logged"
                })

            testT "a saved file that does not parse fails the start and stays as it is" (fun () ->
                task {
                    let h = harness ()
                    let dir = tempDir ()
                    let file = Web3SignerModule.RemoteKeys.fileOf dir

                    let broken =
                        $"""[ {{ "pubkey": "{(pubkeyOf 2).Hex}", "url": "{urlB}" }}, {{ "pubkey": "0x12" }} ]"""

                    File.WriteAllText(file, broken)
                    use tc = new TestCore(h, dir)
                    let m = Web3SignerModule.create ()

                    Expect.equal
                        (m.Configure
                            {
                                Element = ValueNone
                                BaseDir = dir
                                Mainnet = false
                            })
                        (Ok())
                        "configured"

                    let! r = m.Start tc.Services CancellationToken.None

                    match r with
                    | Error e -> Expect.stringContains e "remote-keys.json" "names the file"
                    | Ok _ -> failtest "started with a broken remote-keys.json"

                    Expect.equal (File.ReadAllText file) broken "the file is not rewritten"
                })

            testT "without a URL the only configured signer is used; without signers it is an error" (fun () ->
                task {
                    let h = harness ()
                    h.Node.AddValidator(pubkeyOf 1, "active_ongoing") |> ignore
                    let _, _, connect = fakes ()
                    use one = new TestCore(h, tempDir ())
                    // No discovery: the registry is empty, so key 1 is new to the VC.
                    let ws = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    one.Services.SetRemoteKeys(Web3SignerModule.RemoteKeys.start false one.Services ws)
                    let! _, text = callApi one.Services "POST" (importBody [ pubkeyOf 1, None ])
                    Expect.equal (statusesOf text) [ "imported" ] text

                    Expect.equal
                        (one.Services.Registry.TryGet(pubkeyOf 1)).Value.Backend.Name
                        $"web3signer {urlA}"
                        "signer A"

                    use none = new TestCore(h, tempDir ())
                    let bare = Web3SignerModule.Web3SignerSet(connect, Web3SignerModule.apiOnly, h.Time, Log.none)
                    none.Services.SetRemoteKeys(Web3SignerModule.RemoteKeys.start false none.Services bare)
                    let! _, text = callApi none.Services "POST" (importBody [ pubkeyOf 1, None ])
                    Expect.equal (statusesOf text) [ "error" ] text
                    ws.Stop()
                    bare.Stop()
                })

            testT "a build without the Web3Signer module answers with an empty list and per-key statuses" (fun () ->
                task {
                    let h = harness ()
                    use tc = new TestCore(h, tempDir ())
                    let core = tc.Services
                    let! s, text = callApi core "GET" ""
                    Expect.equal (s, dataOf text) (200, []) "empty list"
                    let! s, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.equal s 200 text
                    Expect.equal (statusesOf text) [ "error" ] text
                    let! s, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2 ])
                    Expect.equal s 200 text
                    Expect.equal (statusesOf text) [ "not_found" ] text
                })

            testT "a saved key another module refused first is skipped at the start; the other keys load" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..3 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    let dir = tempDir ()
                    let _, _, connect = fakes ()
                    let tc = new TestCore(h, dir)
                    let ws = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    do! startStore tc.Services ws

                    let! _, text =
                        callApi tc.Services "POST" (importBody [ pubkeyOf 2, Some urlB; pubkeyOf 3, Some urlB ])

                    Expect.equal (statusesOf text) [ "imported"; "imported" ] text
                    ws.Stop()
                    (tc :> IDisposable).Dispose()
                    // The restart: a TEE or Dirk module refused key 2 before this module starts, so the
                    // registry never added it.
                    use tc2 = new TestCore(h, dir)
                    let core = tc2.Services
                    core.Registry.Refuse(pubkeyOf 2, "test: refused by another module")
                    Expect.isTrue (core.Registry.TryGet(pubkeyOf 2)).IsNone "never added"
                    let ws2 = Web3SignerModule.Web3SignerSet(connect, configured, h.Time, Log.none)
                    do! startStore core ws2

                    Expect.equal
                        (core.Registry.TryGet(pubkeyOf 3)).Value.Backend.Name
                        $"web3signer {urlB}"
                        "key 3 is routed"

                    Expect.isTrue (core.Registry.TryGet(pubkeyOf 2)).IsNone "key 2 is not"

                    Expect.isTrue
                        (tc2.Lines
                         |> Seq.exists (fun l ->
                             l.Contains (pubkeyOf 2).Short
                             && l.Contains "refused until restart, see the earlier error"))
                        "logged"

                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                    Expect.equal (statusesOf text) [ "error" ] text
                    ws2.Stop()
                })

            testT
                "mainnet: an http URL is refused at import; a saved one does not sign, stays listed and can be deleted"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 2..3 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        let dir = tempDir ()
                        let _, _, connect = fakes ()
                        // Saved off mainnet: key 2 through the http signer B.
                        File.WriteAllBytes(
                            Web3SignerModule.RemoteKeys.fileOf dir,
                            Web3SignerModule.RemoteKeys.toJson [ pubkeyOf 2, Uri urlB ]
                        )

                        use tc = new TestCore(h, dir)
                        let core = tc.Services
                        let ws = Web3SignerModule.Web3SignerSet(connect, Web3SignerModule.apiOnly, h.Time, Log.none)
                        core.SetRemoteKeys(Web3SignerModule.RemoteKeys.start true core ws)
                        Expect.isTrue (core.Registry.TryGet(pubkeyOf 2)).IsNone "the saved http key is not routed"
                        let! _, text = callApi core "GET" ""

                        Expect.equal
                            (listedOf text)
                            (set [ (pubkeyOf 2).Hex, urlB, false ])
                            "listed, so it can be deleted"

                        let! _, text = callApi core "POST" (importBody [ pubkeyOf 3, Some urlB ])
                        Expect.equal (statusesOf text) [ "error" ] text
                        Expect.stringContains text "refused on mainnet" "names the reason"
                        Expect.isTrue (core.Registry.TryGet(pubkeyOf 3)).IsNone "not routed"

                        Expect.stringContains
                            (File.ReadAllText(Web3SignerModule.RemoteKeys.fileOf dir))
                            (pubkeyOf 2).Hex
                            "the saved key stays in the file"

                        let! _, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2 ])
                        Expect.equal (statusesOf text) [ "deleted" ] text

                        Expect.isFalse
                            ((File.ReadAllText(Web3SignerModule.RemoteKeys.fileOf dir)).Contains (pubkeyOf 2).Hex)
                            "gone from the file"

                        let! _, text = callApi core "GET" ""
                        Expect.isEmpty (listedOf text) "nothing listed"
                        ws.Stop()
                    })

            testT "mainnet: a refused http key stays listed when saving the file fails" (fun () ->
                task {
                    let h = harness ()
                    h.Node.AddValidator(pubkeyOf 2, "active_ongoing") |> ignore
                    let dir = tempDir ()
                    let _, _, connect = fakes ()
                    let file = Web3SignerModule.RemoteKeys.fileOf dir
                    File.WriteAllBytes(file, Web3SignerModule.RemoteKeys.toJson [ pubkeyOf 2, Uri urlB ])
                    use tc = new TestCore(h, dir)
                    let core = tc.Services
                    let ws = Web3SignerModule.Web3SignerSet(connect, Web3SignerModule.apiOnly, h.Time, Log.none)
                    core.SetRemoteKeys(Web3SignerModule.RemoteKeys.start true core ws)
                    // A directory where save writes its temp file makes every save fail.
                    Directory.CreateDirectory(file + ".tmp") |> ignore
                    let listed = set [ (pubkeyOf 2).Hex, urlB, false ]
                    let! _, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2 ])
                    Expect.equal (statusesOf text) [ "error" ] text
                    let! _, text = callApi core "GET" ""
                    Expect.equal (listedOf text) listed "still listed after a failed delete"
                    let! _, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlBTls ])
                    Expect.equal (statusesOf text) [ "error" ] text
                    let! _, text = callApi core "GET" ""
                    Expect.equal (listedOf text) listed "still listed with its old URL after a failed import"
                    Directory.Delete(file + ".tmp")
                    let! _, text = callApi core "DELETE" (deleteBody [ pubkeyOf 2 ])
                    Expect.equal (statusesOf text) [ "deleted" ] text
                    Expect.isFalse ((File.ReadAllText file).Contains (pubkeyOf 2).Hex) "gone from the file"
                    ws.Stop()
                })
        ]
