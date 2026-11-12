/// Graffiti: the layers, client codes, the graffiti file module, and the whole VC with both.
module Eplix.Tests.GraffitiTests

open System
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Backend.Local
open Eplix.Graffiti
open Eplix.Graffiti.GraffitiFile
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests

let private bytes (s: string) = Encoding.UTF8.GetByteCount s
let private cv code commit = { Code = code; Commit = commit }
let private el, cl, vc = cv "NM" "c066aee2", cv "LH" "ced49dd2", cv "EX" "ab12cd34"

let private ctx slot index =
    {
        Key = pubkeyOf 1
        Index = index
        Slot = slot
        Epoch = slot / 8UL
    }

let private parseJson (text: string) (decode: JsonElement -> 'T) =
    use d = JsonDocument.Parse text
    decode d.RootElement

let private textOfRoot (r: Root) = Encoding.UTF8.GetString(r.Bytes).TrimEnd('\000')

let private configText (extra: string) =
    $$"""{ "beacon_node": "http://bn.test", "chain_config": "c.yaml", "data_dir": "d"{{extra}} }"""

let private fileOf (text: string) =
    match parse text with
    | Ok f -> f
    | Error es -> failtestf "parse: %s" (String.Join("; ", es))

let private refusedFile (text: string) (fragment: string) =
    match parse text with
    | Ok _ -> failtestf "accepted: %s" text
    | Error es ->
        Expect.isTrue (es |> List.exists (fun e -> e.Contains fragment)) $"""'{fragment}' in {String.Join("; ", es)}"""

/// A text of mixed one- to four-byte characters, up to 40 characters.
let private anyText =
    gen {
        let! n = Gen.choose (0, 40)
        let! parts = Gen.listOfLength n (Gen.elements [ "a"; "Z"; " "; "é"; "ж"; "€"; "中"; "😀"; "{"; "}" ])
        return String.concat "" parts
    }

let private anyParts =
    gen {
        let! code = Gen.elements [ "NM"; "LH"; "EX"; "GE" ]
        let! digits = Gen.choose (0, 8)
        let! commit = Gen.listOfLength digits (Gen.elements [ '0'; '7'; 'a'; 'f' ])
        return cv code (String(Array.ofList commit))
    }
    |> Gen.listOfLength 3
    |> Gen.zip (Gen.choose (0, 3))
    |> Gen.map (fun (n, ps) -> List.truncate n ps)

let private coreTests =
    testList
        "core"
        [
            test "fit cuts at a character boundary, never inside one" {
                Expect.equal (Graffiti.fit 32 "short") "short" "fits"
                Expect.equal (Graffiti.fit 4 "ééé") "éé" "two-byte characters"
                Expect.equal (Graffiti.fit 5 "ab😀c") "ab" "a surrogate pair is one character of 4 bytes"
                Expect.equal (Graffiti.fit 6 "ab😀c") "ab😀" "the pair fits"
            }

            test "toRoot pads with zeros as before for ASCII" {
                let r = Graffiti.toRoot "eplix"
                Expect.equal r.Bytes[0..4] (Encoding.ASCII.GetBytes "eplix") "text"
                Expect.isTrue (r.Bytes[5..] |> Array.forall ((=) 0uy)) "zero padded"
            }

            test "codes: four digits, then two, then codes alone, then none" {
                let parts = [ el; cl; vc ]
                Expect.equal (Graffiti.codes parts 32) "NMc066LHced4EXab12" "18 bytes"
                Expect.equal (Graffiti.codes parts 17) "NMc0LHceEXab" "12 bytes"
                Expect.equal (Graffiti.codes parts 11) "NMLHEX" "6 bytes"
                Expect.equal (Graffiti.codes parts 5) "" "no room"
                Expect.equal (Graffiti.codes [ vc ] 32) "EXab12" "VC only"
                Expect.equal (Graffiti.codes [ cv "LH" "" ] 32) "LH" "no commit"
            }

            test "append: a space after the text, nothing cut from the operator's text" {
                Expect.equal (Graffiti.append "" [ el; cl; vc ]) "NMc066LHced4EXab12" "no space without text"
                Expect.equal (Graffiti.append "hello" [ vc ]) "hello EXab12" "space"
                let text31 = String('x', 31)
                Expect.equal (Graffiti.append text31 [ vc ]) text31 "no room left: no codes"
                let text25 = String('x', 25)
                Expect.equal (Graffiti.append text25 [ el; cl; vc ]) (text25 + " NMLHEX") "codes alone in 6 bytes"
                Expect.equal (Graffiti.append "hi" []) "hi" "off"
            }

            testProp
                "append: at most 32 bytes, starts with the text cut to 32 bytes, codes in ASCII after it"
                (Prop.forAll (Arb.fromGen (Gen.zip anyText anyParts)) (fun (text, parts) ->
                    let r = Graffiti.append text parts
                    let t = Graffiti.fit 32 text
                    let rest = r.Substring t.Length

                    bytes r <= 32
                    && r.StartsWith(t, StringComparison.Ordinal)
                    && rest |> Seq.forall (fun c -> c < '\128')
                    && (parts.IsEmpty |> not || r = t)
                    && bytes (Encoding.UTF8.GetString((Graffiti.toRoot r).Bytes).TrimEnd('\000')) = bytes r))

            test "node version v2: both clients, a missing execution client, a bad code" {
                let full =
                    """{"data":{"beacon_node":{"code":"LH","name":"Lighthouse","version":"v8.0.1","commit":"0xced49dd2"},
                      "execution_client":{"code":"NM","name":"Nethermind","version":"v1.35.8","commit":"0xC066AEE2"}}}"""

                let n = parseJson full Graffiti.decodeV2
                Expect.equal n.BeaconNode (ValueSome(cv "LH" "ced49dd2")) "beacon node"
                Expect.equal n.ExecutionClient (ValueSome(cv "NM" "c066aee2")) "execution client, lower case"

                let noEl =
                    parseJson
                        """{"data":{"beacon_node":{"code":"tk","name":"Teku","version":"1","commit":"zz"}}}"""
                        Graffiti.decodeV2

                Expect.equal
                    noEl
                    {
                        BeaconNode = ValueSome(cv "TK" "")
                        ExecutionClient = ValueNone
                    }
                    "upper-cased code, non-hex commit dropped"

                let bad = parseJson """{"data":{"beacon_node":{"code":"LHX","commit":"0x00"}}}""" Graffiti.decodeV2
                Expect.equal bad.BeaconNode ValueNone "three letters is not a code"
            }

            test "node version v2: a commit is cut to 8 digits; one longer than 64 digits is dropped" {
                let answer (commit: string) =
                    let json = """{"data":{"beacon_node":{"code":"LH","version":"v8","commit":"COMMIT"}}}"""
                    parseJson (json.Replace("COMMIT", commit)) Graffiti.decodeV2

                let sha256 = "0x" + String.replicate 8 "ABCDEF01"
                Expect.equal (answer sha256).BeaconNode (ValueSome(cv "LH" "abcdef01")) "64 digits: the first 8"
                let huge = "0x" + String('a', 1_000_000)
                Expect.equal (answer huge).BeaconNode (ValueSome(cv "LH" "")) "a million digits: no commit"
            }

            test "node version v1: known names, unknown ones" {
                Expect.equal (Graffiti.ofV1 "Lighthouse/v8.3.2-abc/x86_64-linux") (ValueSome(cv "LH" "")) "Lighthouse"

                Expect.equal
                    (Graffiti.ofV1 "teku/v26.10.2/linux-x86_64/-eclipseadoptium-openjdk64bitservervm-java-21")
                    (ValueSome(cv "TK" ""))
                    "Teku"

                Expect.equal (Graffiti.ofV1 "Nimbus/v26.10.2-0-g/linux-amd64") (ValueSome(cv "NB" "")) "Nimbus"
                Expect.equal (Graffiti.ofV1 "Caplin/1") ValueNone "unknown"
            }

            test "config: graffiti_append and graffiti_vc_code" {
                match Config.parse (configText "") "/tmp" [] with
                | Ok c ->
                    Expect.equal (c.GraffitiAppend, c.GraffitiVcCode) (GraffitiAppend.Off, ValueNone) "default off"
                | Error es -> failtestf "%A" es

                match
                    Config.parse (configText """, "graffiti_append": "all", "graffiti_vc_code": "ex" """) "/tmp" []
                with
                | Ok c -> Expect.equal (c.GraffitiAppend, c.GraffitiVcCode) (GraffitiAppend.All, ValueSome "EX") "on"
                | Error es -> failtestf "%A" es

                let refused (extra: string) (fragment: string) =
                    match Config.parse (configText extra) "/tmp" [] with
                    | Ok _ -> failtestf "accepted %s" extra
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains fragment)) $"%A{es}"

                refused """, "graffiti_append": "vc" """ "needs graffiti_vc_code"
                refused """, "graffiti_append": "yes", "graffiti_vc_code": "EX" """ "not off, vc or all"
                refused """, "graffiti_vc_code": "E1" """ "two ASCII letters"
                refused """, "graffiti_vc_code": "EXX" """ "two ASCII letters"
            }

            testProp
                "layers: key file entry, keymanager, module source, file default, core"
                (Prop.forAll (Arb.fromGen (Gen.listOfLength 5 (Gen.elements [ true; false ]))) (fun sets ->
                    let fileKey, api, source, fileDefault, registered = sets[0], sets[1], sets[2], sets[3], sets[4]
                    let key = pubkeyOf 1
                    let registry = KeyRegistry()

                    if registered then
                        registry.Add(key, LocalBackend.create "local" []) |> ignore

                    if api then
                        registry.SetSettings(key, fun s -> { s with Graffiti = ValueSome "api" })

                    registry.SetProposerFile
                        {
                            Defaults =
                                { KeySettings.Default with
                                    Graffiti = (if fileDefault then ValueSome "file default" else ValueNone)
                                }
                            Keys =
                                if fileKey then
                                    Map.ofList
                                        [
                                            key,
                                            { KeySettings.Default with
                                                Graffiti = ValueSome "file key"
                                            }
                                        ]
                                else
                                    Map.empty
                        }

                    let g = GraffitiService.Plain(registry, "core")

                    if source then
                        g.SetSource(fun _ -> ValueSome "module")

                    let expected =
                        [
                            fileKey, "file key"
                            api, "api"
                            source, "module"
                            fileDefault, "file default"
                            true, "core"
                        ]
                        |> List.find fst
                        |> snd

                    g.Text(ctx 5UL 1UL) = expected))

            testT "client codes per node from the cache: v2, v1 fallback, mode vc and off" (fun () ->
                task {
                    use node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

                    let client =
                        Beacon.BeaconClient(
                            new HttpClient(node, false),
                            Uri "http://bn.test",
                            TimeSpan.FromSeconds 5.0
                        )

                    let registry = KeyRegistry()
                    let all = GraffitiService(registry, "x", GraffitiAppend.All, ValueSome "EX", Log.none)
                    Expect.equal (all.Parts client |> List.map _.Code) [ "EX" ] "before a refresh: the VC's code only"

                    node.VersionV2 <-
                        Some
                            """{"data":{"beacon_node":{"code":"LH","name":"Lighthouse","version":"v8","commit":"0xced49dd2"},"execution_client":{"code":"NM","name":"Nethermind","version":"v1","commit":"0xc066aee2"}}}"""

                    do! all.RefreshCodes([ client ], CancellationToken.None)

                    Expect.equal
                        (all.Parts client |> List.map _.Code)
                        [ "NM"; "LH"; "EX" ]
                        "execution client, beacon node, VC"

                    let r = textOfRoot (all.For(ctx 3UL 1UL, client))
                    Expect.isTrue (r.StartsWith "x NMc066LHced4EX") r
                    node.VersionV2 <- None
                    node.VersionV1 <- Some "Teku/v26.10.2/linux"
                    do! all.RefreshCodes([ client ], CancellationToken.None)
                    Expect.equal (all.Parts client |> List.map _.Code) [ "TK"; "EX" ] "v1: the beacon node's code only"
                    let calls = ref 0

                    node.Fail <-
                        fun p ->
                            (if p.Contains "/node/version" then
                                 calls.Value <- calls.Value + 1)

                            false

                    let vcOnly = GraffitiService(registry, "x", GraffitiAppend.Vc, ValueSome "EX", Log.none)
                    do! vcOnly.RefreshCodes([ client ], CancellationToken.None)
                    Expect.equal (vcOnly.Parts client |> List.map _.Code) [ "EX" ] "vc mode: the VC's code only"
                    Expect.equal calls.Value 0 "vc mode asks no node"
                    do! all.RefreshCodes([ client ], CancellationToken.None)
                    Expect.equal calls.Value 2 "mode all: v2 (404), then v1"
                    Expect.equal (textOfRoot (GraffitiService.Plain(registry, "x").For(ctx 3UL 1UL, client))) "x" "off"
                })

            testT "with roles set, only block_data nodes are asked for their version" (fun () ->
                task {
                    use dataNode = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    use blockNode = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

                    let dataClient =
                        Beacon.BeaconClient(
                            new HttpClient(dataNode, false),
                            Uri "http://data.test",
                            TimeSpan.FromSeconds 5.0
                        )

                    let blockClient =
                        Beacon.BeaconClient(
                            new HttpClient(blockNode, false),
                            Uri "http://block.test",
                            TimeSpan.FromSeconds 5.0
                        )

                    let block = Beacon.NodeRole.BlockData ||| Beacon.NodeRole.BlockPublish

                    let nodes =
                        Beacon.BeaconNodes(
                            [ dataClient; blockClient ],
                            1,
                            TimeProvider.System,
                            Log.none,
                            roles = [ Beacon.NodeRole.All &&& ~~~block; block ]
                        )

                    Expect.equal (GraffitiService.CodeNodes nodes) [ blockClient ] "the block node only"
                    let g = GraffitiService(KeyRegistry(), "x", GraffitiAppend.All, ValueSome "EX", Log.none)
                    do! g.RefreshCodes(nodes, CancellationToken.None)

                    let versionCalls (n: FakeBeaconNode) =
                        n.Requests |> Seq.filter (fun r -> r.Contains "/node/version") |> Seq.length

                    Expect.equal (versionCalls dataNode) 0 "the data node is not asked"
                    Expect.isGreaterThan (versionCalls blockNode) 0 "the block node is asked"
                    Expect.equal (g.Parts blockClient |> List.map _.Code) [ "LH"; "EX" ] "the block node's codes"
                    Expect.equal (g.NodeClients dataClient) ValueNone "nothing cached for the data node"
                })

            testT "without roles every node is asked for its version" (fun () ->
                task {
                    use a = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    use b = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)
                    b.VersionV1 <- Some "Teku/v26.10.2/linux"

                    let ca =
                        Beacon.BeaconClient(new HttpClient(a, false), Uri "http://a.test", TimeSpan.FromSeconds 5.0)

                    let cb =
                        Beacon.BeaconClient(new HttpClient(b, false), Uri "http://b.test", TimeSpan.FromSeconds 5.0)

                    let nodes = Beacon.BeaconNodes([ ca; cb ], 1, TimeProvider.System, Log.none)
                    Expect.equal (GraffitiService.CodeNodes nodes) [ ca; cb ] "every node"
                    let g = GraffitiService(KeyRegistry(), "x", GraffitiAppend.All, ValueSome "EX", Log.none)
                    do! g.RefreshCodes(nodes, CancellationToken.None)
                    Expect.equal (g.Parts ca |> List.map _.Code) [ "LH"; "EX" ] "node a's codes"
                    Expect.equal (g.Parts cb |> List.map _.Code) [ "TK"; "EX" ] "node b's codes"
                })

            testT "a node that stays down logs one warning, not one per epoch" (fun () ->
                task {
                    use node = new FakeBeaconNode(genesisTime, secondsPerSlot, slotsPerEpoch)

                    let client =
                        Beacon.BeaconClient(
                            new HttpClient(node, false),
                            Uri "http://bn.test",
                            TimeSpan.FromSeconds 5.0
                        )

                    let lines = Collections.Concurrent.ConcurrentQueue<LogLevel * string>()

                    let log =
                        {
                            Write = (fun l m -> lines.Enqueue(l, m))
                            MinLevel = LogLevel.Debug
                        }

                    let g = GraffitiService(KeyRegistry(), "x", GraffitiAppend.All, ValueSome "EX", log)
                    let count level = lines |> Seq.filter (fun (l, _) -> l = level) |> Seq.length
                    do! g.RefreshCodes([ client ], CancellationToken.None)
                    Expect.equal (g.Parts client |> List.map _.Code) [ "LH"; "EX" ] "up: its codes"
                    node.Fail <- fun p -> p.Contains "/node/version"

                    for _ in 1..5 do
                        do! g.RefreshCodes([ client ], CancellationToken.None)

                    Expect.equal (count LogLevel.Warn) 1 "one warning for five failed epochs"
                    Expect.equal (count LogLevel.Error) 0 "no error"
                    Expect.equal (count LogLevel.Debug) 4 "the other failures at debug level"
                    Expect.equal (g.Parts client |> List.map _.Code) [ "LH"; "EX" ] "down: its last codes"
                    node.Fail <- fun _ -> false
                    do! g.RefreshCodes([ client ], CancellationToken.None)

                    Expect.isTrue
                        (lines |> Seq.exists (fun (l, m) -> l = LogLevel.Info && m.Contains "again"))
                        "back up: one info line"

                    node.Fail <- fun p -> p.Contains "/node/version"
                    do! g.RefreshCodes([ client ], CancellationToken.None)
                    Expect.equal (count LogLevel.Warn) 2 "down again: a new warning"
                })
        ]

let private fileTests =
    testList
        "file"
        [
            test "a Lighthouse graffiti file reads as it is" {
                let k = pubkeyOf 2
                let f = fileOf $"default: Lighthouse default\n{k.Hex}: key two\n"
                Expect.equal (pick Rotation.Slot f (ctx 1UL 1UL)) (ValueSome "Lighthouse default") "default"
                Expect.equal (pick Rotation.Slot f { ctx 1UL 2UL with Key = k }) (ValueSome "key two") "per key"
            }

            test "templates, comments, blank lines, upper-case keys, rotation by slot" {
                let k = pubkeyOf 2
                let upper = "0x" + k.Hex.Substring(2).ToUpperInvariant()

                let f =
                    fileOf
                        $"# comment\n\ndefault: s{{{{SLOT}}}} e{{{{EPOCH}}}} v{{{{VALIDATORINDEX}}}}\r\ndefault: second\n{upper}: k1\n{k.Hex}: k2\n"

                Expect.equal (pick Rotation.Slot f (ctx 16UL 7UL)) (ValueSome "s16 e2 v7") "slot 16: line 0"
                Expect.equal (pick Rotation.Slot f (ctx 17UL 7UL)) (ValueSome "second") "slot 17: line 1"
                Expect.equal (pick Rotation.Slot f { ctx 4UL 2UL with Key = k }) (ValueSome "k1") "key lines, slot 4"
                Expect.equal (pick Rotation.Slot f { ctx 5UL 2UL with Key = k }) (ValueSome "k2") "key lines, slot 5"

                for _ in 1..20 do
                    let r = pick Rotation.Random f (ctx 1UL 1UL)
                    Expect.isTrue (r = ValueSome "s1 e0 v1" || r = ValueSome "second") "random picks a default line"
            }

            test "no line for the key and no default: the next layer decides" {
                Expect.equal (pick Rotation.Slot (fileOf "# nothing\n") (ctx 1UL 1UL)) ValueNone "empty file"

                Expect.equal
                    (pick Rotation.Slot (fileOf $"{(pubkeyOf 3).Hex}: other\n") (ctx 1UL 1UL))
                    ValueNone
                    "another key only"
            }

            test "an empty text is a value" {
                Expect.equal (pick Rotation.Slot (fileOf "default:\n") (ctx 1UL 1UL)) (ValueSome "") "empty"
            }

            test "refused: unknown or unclosed templates, long text, bad names and lines" {
                refusedFile "default: {{SLOTS}}\n" "unknown template {{SLOTS}}"
                refusedFile "default: {{SLOT\n" "without"
                refusedFile $"default: {String('x', 33)}\n" "longer than 32 bytes"
                refusedFile $"default: {String('é', 17)}\n" "longer than 32 bytes"
                refusedFile "0x1234: short key\n" "not default or a 0x-hex public key"
                refusedFile $"{(pubkeyOf 1).Hex.Substring 2}: no prefix\n" "not default or a 0x-hex public key"
                refusedFile "just text\n" "line 1: not 'default: text'"
                refusedFile "default: ok\nfoo: bar\n" "line 2"
            }

            testProp
                "a rendered line is at most 32 bytes and keeps its literal text"
                (Prop.forAll
                    (Arb.fromGen (
                        Gen.zip
                            (Gen.choose (0, 20))
                            (Gen.zip (Gen.choose (0, Int32.MaxValue)) (Gen.choose (0, Int32.MaxValue)))
                    ))
                    (fun (n, (slot, index)) ->
                        let lit = String('a', n)

                        let t =
                            match parseTemplate $"{lit}{{{{SLOT}}}}-{{{{VALIDATORINDEX}}}}" with
                            | Ok t -> t
                            | Error e -> failwith e

                        let r = render (ctx (uint64 slot * 1000UL) (uint64 index)) t
                        let full = $"{lit}{uint64 slot * 1000UL}-{index}"
                        bytes r <= 32 && full.StartsWith r && (bytes full > 32 || r = full)))

            test "module settings" {
                let section (json: string) =
                    {
                        Element = ValueSome(JsonDocument.Parse(json).RootElement.Clone())
                        BaseDir = "/base"
                        Mainnet = false
                    }

                Expect.equal
                    (GraffitiModule.parseSettings
                        {
                            Element = ValueNone
                            BaseDir = "/"
                            Mainnet = false
                        })
                    (Ok ValueNone)
                    "absent: off"

                Expect.equal
                    (GraffitiModule.parseSettings (section """{ "file": "g.txt" }"""))
                    (Ok(
                        ValueSome
                            {
                                File = "/base/g.txt"
                                Rotation = Rotation.Slot
                            }
                    ))
                    "relative path, slot rotation"

                Expect.equal
                    (GraffitiModule.parseSettings (section """{ "file": "/g.txt", "rotation": "random" }"""))
                    (Ok(
                        ValueSome
                            {
                                File = "/g.txt"
                                Rotation = Rotation.Random
                            }
                    ))
                    "random"

                Expect.isError (GraffitiModule.parseSettings (section """{ }""")) "file required"

                Expect.isError
                    (GraffitiModule.parseSettings (section """{ "file": "g", "rotate": "slot" }"""))
                    "unknown field"

                Expect.isError
                    (GraffitiModule.parseSettings (section """{ "file": "g", "rotation": "ordered" }"""))
                    "bad rotation"
            }

            test "watcher: a missing or broken file fails the load; at reload the last good content stays" {
                let dir = tempDir ()
                let path = Path.Combine(dir, "g.txt")
                Expect.isError (GraffitiModule.Watcher(path, Log.none).Load()) "missing"
                File.WriteAllText(path, "default: {{NOPE}}\n")
                Expect.isError (GraffitiModule.Watcher(path, Log.none).Load()) "broken"
                File.WriteAllText(path, "default: one\n")
                let w = GraffitiModule.Watcher(path, Log.none)
                Expect.isOk (w.Load()) "good"
                File.WriteAllText(path, "default: {{NOPE}}\n")
                Expect.isFalse (w.Reload()) "broken at reload"
                Expect.equal (pick Rotation.Slot w.Current (ctx 1UL 1UL)) (ValueSome "one") "last good kept"
                Expect.equal w.Errors 1L "counted"
                File.Delete path
                Expect.isFalse (w.Reload()) "deleted"
                Expect.equal (pick Rotation.Slot w.Current (ctx 1UL 1UL)) (ValueSome "one") "still the last good one"
                File.WriteAllText(path, "default: two\n")
                Expect.isTrue (w.Reload()) "fixed"
                Expect.equal (pick Rotation.Slot w.Current (ctx 1UL 1UL)) (ValueSome "two") "new content"
            }

            test "watcher: a file over 1 MiB is refused at load and at reload, the last good content stays" {
                let dir = tempDir ()
                let path = Path.Combine(dir, "g.txt")
                // Valid content padded with comment lines past the limit.
                let big =
                    "default: big\n"
                    + String.replicate (GraffitiModule.MaxFileBytes / 64 + 1) ("#" + String('x', 62) + "\n")

                File.WriteAllText(path, big)

                match GraffitiModule.Watcher(path, Log.none).Load() with
                | Ok _ -> failtest "a file over the limit loaded"
                | Error e -> Expect.stringContains e "over 1048576 bytes" "why"

                File.WriteAllText(path, "default: one\n")
                let w = GraffitiModule.Watcher(path, Log.none)
                Expect.isOk (w.Load()) "good"
                File.WriteAllText(path, big)
                Expect.isFalse (w.Reload()) "refused at reload"
                Expect.equal w.Errors 1L "counted"
                Expect.equal (pick Rotation.Slot w.Current (ctx 1UL 1UL)) (ValueSome "one") "last good kept"
            }

            test "the module fails the start on a bad file, eplix check reports it" {
                let dir = tempDir ()
                File.WriteAllText(Path.Combine(dir, "g.txt"), "default: {{X}}\n")
                let m = GraffitiModule.create ()

                let section =
                    {
                        Element = ValueSome(JsonDocument.Parse("""{ "file": "g.txt" }""").RootElement.Clone())
                        BaseDir = dir
                        Mainnet = false
                    }

                Expect.isError (m.Configure section) "configure fails"
                File.WriteAllText(Path.Combine(dir, "g.txt"), "default: fine\n")
                let m2 = GraffitiModule.create ()
                Expect.isOk (m2.Configure section) "configure"

                match m2.Check Log.none with
                | Ok s -> Expect.stringContains s "0 keys, 1 default lines" "summary"
                | Error e -> failtestf "%A" e
            }
        ]

/// The whole VC: local keys, the graffiti module, client codes from the node.
let private wholeVc =
    testT "the whole VC: file graffiti with templates, a keymanager-style per-key setting, client codes" (fun () ->
        task {
            let h = harness ()
            let dir = tempDir ()
            let ksDir = Directory.CreateDirectory(Path.Combine(dir, "keys")).FullName

            for i in 0..3 do
                h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                File.WriteAllText(
                    Path.Combine(ksDir, $"keystore-{i}.json"),
                    Keystore.encrypt (secretOf i) "secret" (Keystore.Pbkdf2(16, Array.create 32 (byte i), 32)) ""
                )

            h.Node.Proposals[2UL] <- 1UL
            h.Node.Proposals[3UL] <- 2UL
            h.Node.Proposals[4UL] <- 3UL

            h.Node.VersionV2 <-
                Some
                    """{"data":{"beacon_node":{"code":"LH","name":"Lighthouse","version":"v8","commit":"0xced49dd2"},"execution_client":{"code":"NM","name":"Nethermind","version":"v1","commit":"0xc066aee2"}}}"""

            File.WriteAllText(Path.Combine(dir, "password.txt"), "secret\n")
            File.WriteAllText(Path.Combine(dir, "chain.yaml"), configYaml secondsPerSlot slotsPerEpoch)

            File.WriteAllText(
                Path.Combine(dir, "graffiti.txt"),
                $"default: s{{{{SLOT}}}} v{{{{VALIDATORINDEX}}}}\n{(pubkeyOf 2).Hex}: key two\n"
            )

            File.WriteAllText(
                Path.Combine(dir, "proposers.json"),
                $$"""{ "proposer_config": { "{{(pubkeyOf 3).Hex}}": { "graffiti": "from proposer file" } } }"""
            )

            let configText =
                """{ "beacon_node": "http://bn.test", "chain_config": "chain.yaml", "data_dir": "data",
                 "use_events": false, "allow_start_without_history": ["all"], "graffiti": "core",
                 "graffiti_append": "all", "graffiti_vc_code": "EX", "proposer_config": "proposers.json",
                 "modules": { "local": { "keystores": [ { "path": "keys", "password_file": "password.txt" } ] },
                              "graffiti": { "file": "graffiti.txt" } } }"""

            let modules = [ LocalModule.create (); GraffitiModule.create () ]

            match
                Config.parse configText dir (modules |> List.map (fun m -> m.Name))
                |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
            with
            | Error es -> failtestf "%A" es
            | Ok config ->
                use cts = new CancellationTokenSource()
                let log, lines = Log.memory ()

                let run =
                    Runner.run
                        {
                            Config = config
                            Modules = modules
                            Http = new HttpClient(h.Node, false)
                            Time = h.Time
                            Log = log
                            OnSlotDone = h.Waiter.Done
                            OnReady = fun _ _ -> ()
                        }
                        cts.Token

                let sw = Diagnostics.Stopwatch.StartNew()

                while not (lines |> Seq.exists (fun l -> l.Contains "graffiti codes"))
                      && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                    do! Task.Delay 10

                for s in 0UL .. 5UL do
                    do! h.RunSlots(s, s)

                    if s >= 2UL && s <= 4UL then
                        let sw = Diagnostics.Stopwatch.StartNew()

                        while not (h.Node.Graffitis.ContainsKey s) && sw.Elapsed < TimeSpan.FromSeconds 20.0 do
                            do! Task.Delay 10

                cts.Cancel()
                let! result = run
                Expect.isOk result $"""run; log: {String.Join('\n', lines)}"""
                let g s = Encoding.UTF8.GetString(h.Node.Graffitis[s]).TrimEnd('\000')
                Expect.stringStarts (g 2UL) "s2 v1 NMc066LHced4EX" "default line with templates, then the codes"
                Expect.stringStarts (g 3UL) "key two NMc066LHced4EX" "the key's line"

                Expect.stringStarts
                    (g 4UL)
                    "from proposer file NMc0LHceEX"
                    "a per-key setting beats the file; two digits fit"

                for s in 2UL .. 4UL do
                    Expect.isLessThanOrEqual h.Node.Graffitis[s].Length 32 "32 bytes"
        })

[<Tests>]
let tests = testList "graffiti" [ coreTests; fileTests; wholeVc ]
