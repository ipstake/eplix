/// The proposer config file: parsing, the four layers of settings, reload.
module Eplix.Tests.ProposerConfigTests

open System
open System.IO
open System.Text
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Tests.TestUtil
open Eplix.Tests.SchedulerTests

let private parseText (s: string) = ProposerConfig.parse (Encoding.UTF8.GetBytes s)

let private address (n: byte) = Hex.encodeArray (Array.init 20 (fun i -> if i = 19 then n else 0uy))

let private upper (pk: PubKey) = "0x" + pk.Hex.Substring(2).ToUpperInvariant()

let private refused (text: string) (fragment: string) =
    match parseText text with
    | Ok _ -> failtestf "accepted: %s" text
    | Error es ->
        Expect.isTrue (es |> List.exists (fun e -> e.Contains fragment)) $"""'{fragment}' in {String.Join("; ", es)}"""

let private good =
    $$"""{
  "proposer_config": {
    "{{(pubkeyOf 1).Hex}}": { "fee_recipient": "0x50155530FCE8a85ec7055A5F8b2bE214B3DaeFd3", "graffiti": "key one" },
    "{{upper (pubkeyOf 2)}}": { "gas_limit": 36000000 }
  },
  "default_config": { "fee_recipient": "0x6e35733c5af9B61374A128e6F85f553aF09ff89A", "gas_limit": "30000000", "graffiti": "" }
}"""

let private feeFile (n: byte) = $$"""{ "default_config": { "fee_recipient": "{{address n}}" } }"""
let private lead = TimeSpan.FromMilliseconds 500.0

/// Moves the fake clock forward to `t`.
let private advanceTo (h: Harness) (t: DateTimeOffset) =
    let now = h.Time.GetUtcNow()

    if t > now then
        h.Time.Advance(t - now)

/// Waits up to 10 s of real time for `f`, then checks it.
let private eventually (what: string) (f: unit -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (f ()) && sw.Elapsed < TimeSpan.FromSeconds 10.0 do
            do! Task.Delay 5

        Expect.isTrue (f ()) what
    }

type private RefresherSetup =
    {
        H: Harness
        Path: string
        Watcher: ProposerConfig.Watcher
        Registry: KeyRegistry
        Boundary: DateTimeOffset
        Fee: unit -> string voption
    }

/// A file with the default fee recipient 1, loaded, a registry with key 1, and the clock in epoch 0.
let private refresherSetup () =
    let h = harness ()
    let path = Path.Combine(tempDir (), "proposers.json")
    File.WriteAllText(path, feeFile 1uy)
    let w = ProposerConfig.Watcher(path, Log.none)

    match w.Load() with
    | Ok _ -> ()
    | Error e -> failtest e

    let registry = KeyRegistry()
    registry.SetProposerFile w.Current
    registry.Add(pubkeyOf 1, LocalBackend.create "local" []) |> ignore

    {
        H = h
        Path = path
        Watcher = w
        Registry = registry
        Boundary = h.Clock.SlotStart(h.Clock.FirstSlot 1UL)
        Fee = fun () -> (registry.TryGet(pubkeyOf 1)).Value.Settings.FeeRecipient
    }

[<Tests>]
let tests =
    testList
        "proposer config"
        [
            test "a good file: defaults, per-key entries, addresses in lower case" {
                match parseText good with
                | Error es -> failtestf "%A" es
                | Ok f ->
                    Expect.equal
                        f.Defaults.FeeRecipient
                        (ValueSome "0x6e35733c5af9b61374a128e6f85f553af09ff89a")
                        "default fee recipient"

                    Expect.equal f.Defaults.GasLimit (ValueSome 30_000_000UL) "gas limit as a string"
                    Expect.equal f.Defaults.Graffiti (ValueSome "") "empty graffiti is a value"
                    Expect.equal f.Keys.Count 2 "two keys"

                    Expect.equal
                        f.Keys[pubkeyOf 1].FeeRecipient
                        (ValueSome "0x50155530fce8a85ec7055a5f8b2be214b3daefd3")
                        "key fee recipient"

                    Expect.equal f.Keys[pubkeyOf 1].GasLimit ValueNone "unset field"

                    Expect.equal
                        f.Keys[pubkeyOf 2].GasLimit
                        (ValueSome 36_000_000UL)
                        "gas limit as a number, key in upper case"

                    Expect.stringContains (ProposerConfig.summary f) "2 keys" "summary"
            }

            test "builder blocks: enabled, boost factor, and Teku's builder gas_limit" {
                let text =
                    $$"""{ "default_config": { "fee_recipient": "{{address 1uy}}", "builder": { "enabled": true, "gas_limit": "36000000" } },
                        "proposer_config": { "{{(pubkeyOf 1).Hex}}": { "builder": { "enabled": false } },
                                             "{{(pubkeyOf 2).Hex}}": { "builder": { "boost_factor": "250" } } } }"""

                match parseText text with
                | Error es -> failtestf "%A" es
                | Ok f ->
                    Expect.equal f.Defaults.BuilderEnabled (ValueSome true) "default on"
                    Expect.equal f.Defaults.GasLimit (ValueSome 36_000_000UL) "builder.gas_limit is the gas limit"
                    Expect.equal f.Keys[pubkeyOf 1].BuilderEnabled (ValueSome false) "key 1 off"
                    Expect.equal f.Keys[pubkeyOf 2].BuilderBoostFactor (ValueSome 250UL) "key 2 factor"
                    Expect.equal f.Keys[pubkeyOf 2].BuilderEnabled ValueNone "key 2 takes the default"
                    let registry = KeyRegistry()
                    registry.SetProposerFile f
                    let s2 = registry.SettingsOf(pubkeyOf 2)

                    Expect.equal
                        (s2.BuilderEnabled, s2.BuilderBoostFactor, s2.GasLimit)
                        (ValueSome true, ValueSome 250UL, ValueSome 36_000_000UL)
                        "key 2 merged"

                    Expect.equal (registry.SettingsOf(pubkeyOf 1)).BuilderEnabled (ValueSome false) "key 1 merged"
            }

            test "an empty object and a file with only keys parse" {
                Expect.equal (parseText "{}") (Ok ProposerFile.Empty) "empty"
                Expect.isOk (parseText $$"""{ "proposer_config": { "{{(pubkeyOf 1).Hex}}": {} } }""") "no defaults"
            }

            test "refusals" {
                let pk = (pubkeyOf 1).Hex

                refused
                    """{ "default_config": { "fee_recipient": "0x1234" } }"""
                    "default_config.fee_recipient: must be a 20-byte"

                refused
                    """{ "default_config": { "fee_recipient": "6e35733c5af9B61374A128e6F85f553aF09ff89A" } }"""
                    "20-byte"

                refused """{ "default_config": { "gas_limit": "lots" } }""" "default_config.gas_limit"
                refused """{ "default_config": { "gas_limit": 0 } }""" "must be above 0"
                refused """{ "default_config": { "gas_limit": -1 } }""" "default_config.gas_limit"

                refused
                    $$"""{ "proposer_config": { "{{pk}}": { "graffiti": "{{String('x', 33)}}" } } }"""
                    "at most 32 bytes"

                refused $$"""{ "default_config": { "graffiti": "{{String('é', 17)}}" } }""" "at most 32 bytes"
                refused """{ "proposer_config": { "0x1234": {} } }""" "is not a 48-byte"
                refused $$"""{ "proposer_config": { "{{pk.Substring 2}}": {} } }""" "is not a 48-byte"
                refused """{ "default_config": {}, "fee_recipient": "0x00" }""" "unknown field 'fee_recipient'"

                refused
                    """{ "default_config": { "feeRecipient": "0x00" } }"""
                    "default_config: unknown field 'feeRecipient'"

                refused
                    """{ "default_config": { "builder": { "enabled": "yes" } } }"""
                    "default_config.builder.enabled: must be true or false"

                refused
                    """{ "default_config": { "builder": { "registration_overrides": {} } } }"""
                    "builder: unknown field 'registration_overrides'"

                refused """{ "default_config": { "builder": [] } }""" "default_config.builder must be an object"

                refused
                    """{ "default_config": { "builder": { "gas_limit": 0 } } }"""
                    "default_config.builder.gas_limit: must be above 0"

                refused
                    $$"""{ "proposer_config": { "{{pk}}": { "gas_limit": "2", "builder": { "gas_limit": "1" } } } }"""
                    "gas_limit is set both"

                refused $$"""{ "proposer_config": { "{{pk}}": {}, "{{upper (pubkeyOf 1)}}": {} } }""" "listed twice"
                refused """{ "proposer_config": [] }""" "must be an object"
                refused """{ "default_config": "x" }""" "must be an object"
                refused """[]""" "must be an object"
                refused """{ "default_config": """ "not valid JSON"
            }

            test "proposer_config in the core config is optional and resolves against the config dir" {
                let text (extra: string) =
                    """{ "beacon_node": "http://bn.test", "chain_config": "c.yaml", "data_dir": "d" """ + extra + "}"

                match
                    Config.parse (text "") "/base" [],
                    Config.parse (text """, "proposer_config": "p/proposers.json" """) "/base" []
                with
                | Ok a, Ok b ->
                    Expect.equal a.ProposerConfig ValueNone "absent"
                    Expect.equal b.ProposerConfig (ValueSome(Path.GetFullPath("p/proposers.json", "/base"))) "resolved"
                | x -> failtestf "%A" x
            }

            // Each layer sets each field or not. The effective value is the first one set, in the
            // order file entry, API, file default, core default.
            testProp
                "precedence: file entry, then API, then file default, then core default"
                (fun
                    (fileKey: byte option * uint32 option * byte option)
                    (api: byte option * uint32 option * byte option)
                    (fileDefault: byte option * uint32 option * byte option)
                    (registered: bool)
                    (listed: bool) ->
                    let settings (fee: byte option, gas: uint32 option, graffiti: byte option) =
                        { KeySettings.Default with
                            FeeRecipient = fee |> Option.map address |> ValueOption.ofOption
                            GasLimit = gas |> Option.map uint64 |> ValueOption.ofOption
                            Graffiti = graffiti |> Option.map (fun g -> $"g{g}") |> ValueOption.ofOption
                        }

                    let key = pubkeyOf 3
                    let coreFee, coreGas, coreGraffiti = address 255uy, 1UL, "core"
                    let registry = KeyRegistry()

                    if registered then
                        registry.Add(key, LocalBackend.create "local" []) |> ignore

                    registry.SetSettings(key, fun _ -> settings api)
                    let keys = if listed then Map.ofList [ key, settings fileKey ] else Map.empty

                    registry.SetProposerFile
                        {
                            Defaults = settings fileDefault
                            Keys = keys
                        }

                    let first (xs: 'T voption list) (fallback: 'T) =
                        xs |> List.tryPick ValueOption.toOption |> Option.defaultValue fallback

                    let layers =
                        [
                            (if listed then settings fileKey else KeySettings.Default)
                            settings api
                            settings fileDefault
                        ]

                    let s = registry.SettingsOf key

                    first [ s.FeeRecipient ] coreFee = first (layers |> List.map _.FeeRecipient) coreFee
                    && first [ s.GasLimit ] coreGas = first (layers |> List.map _.GasLimit) coreGas
                    && first [ s.Graffiti ] coreGraffiti = first (layers |> List.map _.Graffiti) coreGraffiti
                    && registry.StoredSettingsOf key = settings api
                    && registry.InProposerFile key = listed
                    && (not registered || (registry.TryGet key).Value.Settings = s))

            test "a key added after the file gets the file's settings; a new file updates it" {
                let registry = KeyRegistry()

                registry.SetProposerFile
                    {
                        Defaults =
                            { KeySettings.Default with
                                Graffiti = ValueSome "d"
                            }
                        Keys =
                            Map.ofList
                                [
                                    pubkeyOf 1,
                                    { KeySettings.Default with
                                        FeeRecipient = ValueSome(address 1uy)
                                    }
                                ]
                    }

                registry.Add(pubkeyOf 1, LocalBackend.create "local" []) |> ignore
                let k = (registry.TryGet(pubkeyOf 1)).Value

                Expect.equal
                    k.Settings
                    { KeySettings.Default with
                        FeeRecipient = ValueSome(address 1uy)
                        Graffiti = ValueSome "d"
                    }
                    "effective"

                registry.SetProposerFile ProposerFile.Empty
                Expect.equal k.Settings KeySettings.Default "file emptied"
            }

            test "watcher: start fails on a bad or missing file; reload keeps the last good file" {
                let dir = tempDir ()
                let path = Path.Combine(dir, "proposers.json")
                let log, lines = Log.memory ()
                let w = ProposerConfig.Watcher(path, log)
                let write (text: string) = File.WriteAllText(path, text)
                let defaultFee (n: byte) = $$"""{ "default_config": { "fee_recipient": "{{address n}}" } }"""
                Expect.isError (w.Load()) "missing file"
                write """{ "default_config": { "builder": { "relays": [] } } }"""
                Expect.isError (w.Load()) "unknown builder field"
                write (defaultFee 1uy)
                Expect.isOk (w.Load()) "good file"
                Expect.equal (w.Reload()) ValueNone "unchanged"
                write (defaultFee 2uy)

                match w.Reload() with
                | ValueSome f -> Expect.equal f.Defaults.FeeRecipient (ValueSome(address 2uy)) "changed"
                | ValueNone -> failtest "change not seen"

                write """{ "default_config": { "fee_recipient": "0x12" } }"""
                Expect.equal (w.Reload()) ValueNone "broken file"
                Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 2uy)) "last good kept"

                Expect.isTrue
                    (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "keeping the last good one"))
                    "error logged"

                File.Delete path
                Expect.equal (w.Reload()) ValueNone "deleted file"
                Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 2uy)) "still the last good one"
                write (defaultFee 3uy)
                Expect.isTrue (w.Reload()).IsSome "fixed"
                Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 3uy)) "new content"
            }
            test "watcher: an unchanged file is not read again; a recent write time is not trusted" {
                let dir = tempDir ()
                let path = Path.Combine(dir, "proposers.json")
                let w = ProposerConfig.Watcher(path, Log.none)
                let defaultFee (n: byte) = $$"""{ "default_config": { "fee_recipient": "{{address n}}" } }"""
                File.WriteAllText(path, defaultFee 1uy)
                let recent = File.GetLastWriteTimeUtc path
                Expect.isOk (w.Load()) "good file"
                // Same size and write time, other bytes, and the write time under 2 s old: read again.
                File.WriteAllText(path, defaultFee 2uy)
                File.SetLastWriteTimeUtc(path, recent)
                Expect.isTrue (w.Reload()).IsSome "a recent stamp is not trusted"
                let old = DateTime.UtcNow.AddMinutes -5.0
                File.SetLastWriteTimeUtc(path, old)
                Expect.equal (w.Reload()) ValueNone "same bytes, an old write time: stamp kept"
                // Other bytes with the same size and write time: the stamp says unchanged, no read.
                File.WriteAllText(path, defaultFee 3uy)
                File.SetLastWriteTimeUtc(path, old)
                Expect.equal (w.Reload()) ValueNone "not read"
                Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 2uy)) "content as last read"
                File.SetLastWriteTimeUtc(path, old.AddSeconds 1.0)

                match w.Reload() with
                | ValueSome f -> Expect.equal f.Defaults.FeeRecipient (ValueSome(address 3uy)) "a new write time: read"
                | ValueNone -> failtest "change not seen"

                File.Delete path
                Expect.equal (w.Reload()) ValueNone "deleted file"
                Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 3uy)) "last good kept"
            }
            testT
                "refresher: a change made before the check is in place from the first slot of the next epoch"
                (fun () ->
                    task {
                        let s = refresherSetup ()

                        let r =
                            ProposerConfig.Refresher(
                                s.Watcher.Reload,
                                s.H.Clock,
                                lead,
                                ValueOption.iter s.Registry.SetProposerFile,
                                Log.none
                            )

                        use cts = new CancellationTokenSource()
                        let run = r.Run cts.Token
                        File.WriteAllText(s.Path, feeFile 2uy)
                        advanceTo s.H (s.Boundary - TimeSpan.FromMilliseconds 600.0)
                        do! Task.Delay 50
                        Expect.equal r.Checks 0L "no check before the lead"
                        Expect.equal (s.Fee()) (ValueSome(address 1uy)) "old content before the check"
                        advanceTo s.H (s.Boundary - lead)
                        do! eventually "the check ends" (fun () -> r.Checks = 1L)
                        Expect.isLessThan (s.H.Time.GetUtcNow()) s.Boundary "still the epoch before"

                        Expect.equal
                            (s.Fee())
                            (ValueSome(address 2uy))
                            "the new content is in place before the boundary"

                        Expect.equal r.Late 0L "not late"
                        cts.Cancel()
                        do! run
                    })

            testT "refresher: a bad file keeps the content in place, logs and counts the error" (fun () ->
                task {
                    let log, lines = Log.memory ()
                    let s = refresherSetup ()
                    let w = ProposerConfig.Watcher(s.Path, log)
                    Expect.isOk (w.Load()) "start"

                    let r =
                        ProposerConfig.Refresher(
                            w.Reload,
                            s.H.Clock,
                            lead,
                            ValueOption.iter s.Registry.SetProposerFile,
                            log
                        )

                    use cts = new CancellationTokenSource()
                    let run = r.Run cts.Token
                    File.WriteAllText(s.Path, """{ "default_config": { "fee_recipient": "0x12" } }""")
                    advanceTo s.H (s.Boundary - lead)
                    do! eventually "the check ends" (fun () -> r.Checks = 1L)
                    Expect.equal (s.Fee()) (ValueSome(address 1uy)) "old content kept"
                    Expect.equal w.Current.Defaults.FeeRecipient (ValueSome(address 1uy)) "the watcher keeps it too"
                    Expect.equal w.Errors 1L "counted"

                    Expect.isTrue
                        (lines |> Seq.exists (fun l -> l.StartsWith "ERROR" && l.Contains "keeping the last good one"))
                        "logged"

                    cts.Cancel()
                    do! run
                })

            testT
                "refresher: a check that overruns its lead never blocks the duties; its content applies when ready"
                (fun () ->
                    task {
                        let s = refresherSetup ()
                        use gate = new ManualResetEventSlim(false)
                        // A parse that takes until the test lets it go.
                        let slow () =
                            gate.Wait()
                            s.Watcher.Reload()

                        let r =
                            ProposerConfig.Refresher(
                                slow,
                                s.H.Clock,
                                lead,
                                ValueOption.iter s.Registry.SetProposerFile,
                                Log.none
                            )

                        use cts = new CancellationTokenSource()
                        let run = r.Run cts.Token
                        File.WriteAllText(s.Path, feeFile 2uy)
                        advanceTo s.H (s.Boundary - lead)
                        advanceTo s.H (s.Boundary + TimeSpan.FromSeconds 1.0)
                        // The check holds until the gate opens, so reads that waited for it would never end.
                        // The 10 s limit only turns such a hang into a failure.
                        let key = pubkeyOf 1

                        let reads =
                            Task.Run(fun () ->
                                for _ in 1..1000 do
                                    (s.Registry.TryGet key).Value.Settings.FeeRecipient |> ignore
                                    s.Registry.InProposerFile key |> ignore)

                        let! first = Task.WhenAny(reads, Task.Delay(TimeSpan.FromSeconds 10.0))

                        Expect.isTrue
                            (obj.ReferenceEquals(first, reads) && reads.IsCompletedSuccessfully)
                            "the duty path reads without waiting"

                        Expect.equal (s.Fee()) (ValueSome(address 1uy)) "old content while the check runs"
                        Expect.equal r.Checks 0L "the check still runs"
                        gate.Set()
                        do! eventually "the check ends" (fun () -> r.Checks = 1L)
                        Expect.equal (s.Fee()) (ValueSome(address 2uy)) "the new content applies when ready"
                        Expect.equal r.Late 1L "counted late"
                        cts.Cancel()
                        do! run
                    })
        ]
