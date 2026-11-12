/// Flags and environment variables over the config file, and JSON log lines.
module Eplix.Tests.ConfigSourcesTests

open System
open System.IO
open System.Text.Json
open Expecto
open Eplix
open Eplix.Tests.TestUtil

let private fileText =
    """{ // comments stay allowed
         "beacon_node": "http://file:5052", "chain_config": "c.yaml", "data_dir": "d",
         "graffiti": "from-file", "modules": { "local": { "keystores": [] } } }"""

let private ok r =
    match r with
    | Ok v -> v
    | Error(es: string list) -> failtestf "%A" es

let private load (env: (string * string) list) (flags: (string * string) list) (modules: string list) =
    let dir = tempDir ()
    let f = Path.Combine(dir, "eplix.json")
    File.WriteAllText(f, fileText)

    match ConfigSources.fromEnv env, ConfigSources.fromFlags flags with
    | Ok e, Ok fl -> ConfigSources.load (ValueSome f) (e @ fl) modules
    | Error es, _
    | _, Error es -> Error es

let private addr (b: byte) = "0x" + String.replicate 20 (b.ToString "x2")

[<Tests>]
let tests =
    testList
        "config-sources"
        [
            test "a flag wins over the environment, the environment over the file" {
                let c = ok (load [ "EPLIX_GRAFFITI", "from-env" ] [ "graffiti", "from-flag" ] [ "local" ])
                Expect.equal c.Graffiti "from-flag" "flag"
                let c = ok (load [ "EPLIX_GRAFFITI", "from-env" ] [] [ "local" ])
                Expect.equal c.Graffiti "from-env" "environment"
                let c = ok (load [] [] [ "local" ])
                Expect.equal c.Graffiti "from-file" "file"
            }

            test "flag names map to keys: dashes, dots and --set" {
                let c =
                    ok (
                        load
                            []
                            [
                                "fee-recipient", addr 0xabuy
                                "gas-limit", "30000000"
                                "use-events", "false"
                                "set", "log_level=debug"
                                "log-format", "json"
                            ]
                            [ "local" ]
                    )

                Expect.equal c.FeeRecipient (ValueSome(addr 0xabuy)) "fee recipient"
                Expect.equal c.GasLimit 30_000_000UL "number from a string"
                Expect.isFalse c.UseEvents "boolean"
                Expect.equal c.LogLevel LogLevel.Debug "--set"
                Expect.equal c.LogFormat LogFormat.Json "log format"
            }

            test "module keys come from flags and EPLIX_MODULES__<MODULE>__<KEY>" {
                let c =
                    ok (
                        load
                            [ "EPLIX_MODULES__METRICS__PORT", "6000" ]
                            [ "modules.metrics.address", "0.0.0.0" ]
                            [ "local"; "metrics" ]
                    )

                let m = c.Modules["metrics"].Element.Value
                Expect.equal (m.GetProperty("port").GetString()) "6000" "env"
                Expect.equal (m.GetProperty("address").GetString()) "0.0.0.0" "flag"
                Expect.isTrue (c.Modules.ContainsKey "local") "the file's module stays"
            }

            test "a list or an object goes as JSON; beacon nodes also as a comma list" {
                let c =
                    ok (
                        load
                            [ "EPLIX_BEACON_NODE", "null"; "EPLIX_BEACON_NODES", "http://a:1,http://b:2" ]
                            []
                            [ "local" ]
                    )

                Expect.equal c.BeaconNodes.Length 2 "two nodes"

                let c =
                    ok (
                        load
                            [ "EPLIX_BEACON_NODE", "null" ]
                            [
                                "beacon-nodes", """["http://x:1", {"url": "http://y:2", "headers": {"X-K": "v"}}]"""
                            ]
                            [ "local" ]
                    )

                Expect.equal c.BeaconNodes[1].Headers [ "X-K", "v" ] "object entry"
                let c = ok (load [] [ "allow-start-without-history", """["all"]""" ] [ "local" ])
                Expect.equal c.AllowStartWithoutHistory AllowStartWithoutHistory.All "list"
            }

            test "a whole module object from the environment, then one key of it from a flag" {
                let c =
                    ok (
                        load
                            [ "EPLIX_MODULES__METRICS", """{ "address": "127.0.0.2", "port": 7000 }""" ]
                            [ "modules.metrics.port", "7001" ]
                            [ "local"; "metrics" ]
                    )

                let m = c.Modules["metrics"].Element.Value
                Expect.equal (m.GetProperty("address").GetString()) "127.0.0.2" "from the env object"
                Expect.equal (m.GetProperty("port").GetString()) "7001" "the flag wins"
            }

            test "unknown keys fail from every source, and name the source" {
                let refused env flags (part: string) =
                    match load env flags [ "local" ] with
                    | Ok _ -> failtestf "accepted %A %A" env flags
                    | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains part)) $"{part} in %A{es}"

                refused [ "EPLIX_COLOUR", "blue" ] [] "environment variable EPLIX_COLOUR: 'colour' is not a config key"
                refused [] [ "colour", "blue" ] "--colour: 'colour' is not a config key"
                refused [] [ "set", "colour=blue" ] "--set colour"
                // A module checks its own section, also when a flag filled it.
                let c = ok (load [] [ "modules.local.keystore", "[]" ] [ "local" ])

                Expect.isError
                    (Runner.configure c [ Eplix.Backend.Local.LocalModule.create () ] "/tmp")
                    "module key typo"

                refused [] [ "modules.dirk.endpoints", "[]" ] "'dirk' is not a module in this build"
                refused [] [ "graffiti", "[not json" ] "--graffiti"
                refused [] [ "set", "=x" ] "empty key"
            }

            test "the test harness's EPLIX_ variables and EPLIX_CONFIG are not config keys" {
                let env = [ for n in ConfigSources.ignoredEnv -> n, "1" ]
                Expect.equal (ConfigSources.fromEnv env) (Ok []) "ignored"
                Expect.equal (ConfigSources.fromEnv [ "PATH", "/bin"; "EPLIXFOO", "x" ]) (Ok []) "other variables"
            }

            test "without a file the settings alone make the config" {
                let dir = tempDir ()

                let settings =
                    ok (
                        ConfigSources.fromFlags
                            [
                                "beacon-nodes", "http://a:5052"
                                "chain-config", Path.Combine(dir, "c.yaml")
                                "data-dir", Path.Combine(dir, "d")
                            ]
                    )

                let c = ok (ConfigSources.load ValueNone settings [])
                Expect.equal c.DataDir (Path.Combine(dir, "d")) "data dir"
            }

            testProp "precedence holds for any mix of sources" (fun (inFile: bool) (inEnv: bool) (inFlag: bool) ->
                let text =
                    if inFile then
                        """{ "graffiti": "f", "beacon_node": "http://a:1", "chain_config": "c", "data_dir": "d" }"""
                    else
                        """{ "beacon_node": "http://a:1", "chain_config": "c", "data_dir": "d" }"""

                let env = if inEnv then [ "EPLIX_GRAFFITI", "e" ] else []
                let flags = if inFlag then [ "graffiti", "g" ] else []
                let settings = ok (ConfigSources.fromEnv env) @ ok (ConfigSources.fromFlags flags)
                let merged = ok (ConfigSources.apply text settings)
                let c = ok (Config.parse merged "/tmp" [])

                let expected =
                    if inFlag then "g"
                    elif inEnv then "e"
                    elif inFile then "f"
                    else ""

                c.Graffiti = expected)

            testProp "any string value reaches a string key unchanged" (fun (s: FsCheck.NonNull<string>) ->
                let v = s.Get
                let t = v.Trim()
                let looksJson = t = "true" || t = "false" || t = "null" || t.StartsWith '[' || t.StartsWith '{'

                looksJson
                || (match ConfigSources.jsonValue v with
                    | Ok raw -> JsonDocument.Parse(raw).RootElement.GetString() = v
                    | Error _ -> false))

            testProp "JSON log lines parse and keep the message" (fun (s: FsCheck.NonNull<string>) ->
                let line = Log.jsonLine (DateTimeOffset(2026, 10, 25, 12, 0, 0, TimeSpan.Zero)) LogLevel.Warn s.Get
                let e = JsonDocument.Parse(line).RootElement

                e.GetProperty("msg").GetString() = s.Get
                && e.GetProperty("level").GetString() = "warn"
                && e.GetProperty("time").GetString() = "2026-10-25T12:00:00.000Z"
                && not (line.Contains '\n'))

            test "gas_limit 0 is refused, from the file and from a flag" {
                let text (gas: string) =
                    $$"""{ "beacon_node": "http://a:1", "chain_config": "c", "data_dir": "d", "gas_limit": {{gas}} }"""

                for gas in [ "0"; "\"0\"" ] do
                    match Config.parse (text gas) "/tmp" [] with
                    | Ok _ -> failtestf "gas_limit %s accepted" gas
                    | Error es -> Expect.contains es "gas_limit: must be above 0" $"%A{es}"

                match Config.parse (text "\"30000000\"") "/tmp" [] with
                | Ok c -> Expect.equal c.GasLimit 30_000_000UL "above 0"
                | Error es -> failtestf "%A" es

                match ConfigSources.fromFlags [ "gas-limit", "0" ] with
                | Error es -> failtestf "%A" es
                | Ok settings ->
                    match ConfigSources.apply (text "\"30000000\"") settings with
                    | Error es -> failtestf "%A" es
                    | Ok merged ->
                        match Config.parse merged "/tmp" [] with
                        | Ok _ -> failtest "--gas-limit 0 accepted"
                        | Error es -> Expect.contains es "gas_limit: must be above 0" $"%A{es}"
            }

            test "log_format refuses other values" {
                let text =
                    """{ "beacon_node": "http://a:1", "chain_config": "c", "data_dir": "d", "log_format": "xml" }"""

                match Config.parse text "/tmp" [] with
                | Ok _ -> failtest "xml accepted"
                | Error es -> Expect.isTrue (es |> List.exists (fun e -> e.Contains "log_format")) $"%A{es}"
            }

            test "a headers_file that cannot be read is a config error, not an exception" {
                if not (OperatingSystem.IsWindows()) then
                    let dir = tempDir ()
                    let file = Path.Combine(dir, "bn.headers")
                    File.WriteAllText(file, "X-Api-Key: k\n")
                    File.SetUnixFileMode(file, UnixFileMode.None)

                    let readable =
                        try
                            File.ReadAllText file |> ignore
                            true
                        with :? UnauthorizedAccessException ->
                            false
                    // Root reads a file of mode 000; the check needs a user it stops.
                    if readable then
                        skiptest "the file stays readable (running as root)"

                    let text =
                        """{ "beacon_nodes": [ { "url": "http://a:5052", "headers_file": "bn.headers" } ], "chain_config": "c", "data_dir": "d" }"""

                    match Config.parse text dir [] with
                    | Ok _ -> failtest "an unreadable headers_file accepted"
                    | Error es ->
                        Expect.isTrue
                            (es |> List.exists (fun e -> e.Contains "headers_file" && e.Contains file))
                            $"%A{es}"
            }
        ]
