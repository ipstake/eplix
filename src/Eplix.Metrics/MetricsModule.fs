/// The metrics endpoint as a module. Config section "metrics":
///   { "address": "127.0.0.1", "port": 5064 }
/// GET /metrics answers in the Prometheus text format: the core's instruments (duties, signing
/// latency, slashing DB, beacon node requests, denials), the instruments of other modules on the
/// core meter (the monitor), the runtime meters (Runtime.fs) and gauges read at scrape time (key
/// states, beacon node scores, slashing DB size, current slot). Plain HTTP with no token: keep it
/// on loopback or a private network.
module Eplix.Metrics.MetricsModule

open System
open System.IO
open System.Reflection
open System.Net
open System.Text
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Logging
open Eplix
open Eplix.Json
open Eplix.Metrics.Prometheus

let name = "metrics"

type Settings = { Address: IPAddress; Port: int }

let defaults =
    {
        Address = IPAddress.Loopback
        Port = 5064
    }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok defaults
    | ValueSome e ->
        match checkFields e "modules.metrics" [ "address"; "port" ] with
        | [] ->
            try
                let address =
                    match tryProp e "address" with
                    | ValueSome a ->
                        match IPAddress.TryParse(str a) with
                        | true, NonNull ip -> ip
                        | _ -> fail "address must be an IP address"
                    | ValueNone -> defaults.Address

                let port =
                    match tryProp e "port" with
                    | ValueSome p -> boundedInt "port" 1 65535 p
                    | ValueNone -> defaults.Port

                Ok { Address = address; Port = port }
            with :? JsonDecodeError as x ->
                Error [ $"modules.metrics: {x.Message}" ]
        | errs -> Error errs

let private version =
    match typeof<KeyRegistry>.Assembly.GetCustomAttribute<Reflection.AssemblyInformationalVersionAttribute>() with
    | null -> "unknown"
    | a -> a.InformationalVersion

/// The key state as a label value.
let stateLabel (s: KeyState) =
    match s with
    | KeyState.Discovered -> "discovered"
    | KeyState.HistoryChecked -> "history_checked"
    | KeyState.DoppelgangerWait -> "doppelganger_wait"
    | KeyState.Active -> "active"
    | KeyState.Draining -> "draining"
    | KeyState.Removed -> "removed"
    | KeyState.Halted _ -> "halted"
    | KeyState.Slashed _ -> "slashed"

let private allStates =
    [
        "discovered"
        "history_checked"
        "doppelganger_wait"
        "active"
        "draining"
        "removed"
        "halted"
        "slashed"
    ]

/// Gauges read from the running VC at scrape time.
let gauges (core: CoreServices) : GaugeFamily list =
    let byState = core.Registry.All |> List.countBy (fun k -> stateLabel k.State) |> Map.ofList
    let nodes = core.Nodes.Scores

    let dbBytes =
        let f = FileInfo(Path.Combine(core.DataDir, "slashing.db"))
        if f.Exists then float f.Length else 0.0

    let sample labels value = { Labels = labels; Value = value }

    [
        {
            Name = "eplix_keys"
            Help = "Validator keys by state"
            Samples =
                [
                    for s in allStates -> sample [ "state", s ] (float (defaultArg (byState.TryFind s) 0))
                ]
        }
        {
            Name = "eplix_keys_refused"
            Help = "Keys refused until restart: shares not on one split, or whole and split at once"
            Samples = [ sample [] (float core.Registry.Refused.Length) ]
        }
        {
            Name = "eplix_beacon_node_score"
            Help = "Beacon node health score, 0 to 100"
            Samples = [ for n, score, _ in nodes -> sample [ "node", n ] (float score) ]
        }
        {
            Name = "eplix_beacon_node_ready"
            Help = "1 when the beacon node passed the start checks"
            Samples =
                [
                    for n, _, ready in nodes -> sample [ "node", n ] (if ready then 1.0 else 0.0)
                ]
        }
        {
            Name = "eplix_beacon_node_dropped"
            Help = "1 when a check took the beacon node out of use until the VC restarts"
            Samples =
                [
                    for n, dropped in core.Nodes.Dropped -> sample [ "node", n ] (if dropped then 1.0 else 0.0)
                ]
        }
        {
            Name = "eplix_slashing_db_keys"
            Help = "Keys with a slashing record"
            Samples = [ sample [] (float core.Slashing.Keys.Length) ]
        }
        {
            Name = "eplix_slashing_db_bytes"
            Help = "Size of the slashing DB log file"
            Samples = [ sample [] dbBytes ]
        }
        {
            Name = "eplix_slot"
            Help = "Current slot by the VC's clock"
            Samples =
                match core.Clock.CurrentSlot with
                | ValueSome s -> [ sample [] (float s) ]
                | ValueNone -> []
        }
        {
            Name = "eplix_build_info"
            Help = "The build, as labels"
            Samples = [ sample [ "version", version ] 1.0 ]
        }
    ]

/// A web application builder that reads no host configuration: no appsettings.json from the
/// working directory, no environment variables, no command line. Kestrel binds its "Kestrel"
/// section from this configuration, so an environment variable such as
/// Kestrel__Endpoints__X__Url would add a listener beside the one Listen sets.
let webBuilder () : WebApplicationBuilder =
    let builder =
        WebApplication.CreateSlimBuilder(
            WebApplicationOptions(
                Args = [||],
                ContentRootPath = AppContext.BaseDirectory,
                EnvironmentName = "Production"
            )
        )

    builder.Configuration.Sources.Clear()
    builder.Logging.ClearProviders() |> ignore
    builder

let create () : Module =
    let settings = ref defaults

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check = fun _ -> Ok $"listens on {settings.Value.Address}:{settings.Value.Port}"
        Start =
            fun core _ ->
                task {
                    let s = settings.Value
                    Runtime.ensure ()
                    let collector = new Collector([ Metrics.MeterName ])
                    let builder = webBuilder ()
                    builder.WebHost.ConfigureKestrel(fun o -> o.Listen(s.Address, s.Port)) |> ignore
                    let app = builder.Build()

                    app.Run(
                        RequestDelegate(fun http ->
                            task {
                                if http.Request.Method = "GET" && http.Request.Path.Value = "/metrics" then
                                    let text = collector.Render(gauges core)
                                    http.Response.StatusCode <- 200
                                    http.Response.ContentType <- "text/plain; version=0.0.4; charset=utf-8"
                                    let bytes = Encoding.UTF8.GetBytes text
                                    do! http.Response.Body.WriteAsync(ReadOnlyMemory bytes, http.RequestAborted)
                                else
                                    http.Response.StatusCode <- 404
                            }
                            :> Task)
                    )

                    try
                        do! app.StartAsync()
                        core.Log.Info $"metrics on http://{s.Address}:{s.Port}/metrics"

                        return
                            Ok
                                {
                                    Stop =
                                        fun () ->
                                            task {
                                                do! app.StopAsync()
                                                (collector :> IDisposable).Dispose()
                                            }
                                            :> Task
                                }
                    with e ->
                        (collector :> IDisposable).Dispose()
                        return Error $"metrics endpoint cannot listen on {s.Address}:{s.Port}: {e.Message}"
                }
    }
