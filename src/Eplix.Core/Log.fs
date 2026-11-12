/// A small structured-enough logger: one line per event on stderr. No logging framework.
namespace Eplix

open System

type LogLevel =
    | Debug = 0
    | Info = 1
    | Warn = 2
    | Error = 3

/// How log lines look: plain text, or one JSON object per line for log shippers.
type LogFormat =
    | Text = 0
    | Json = 1

type Log =
    {
        Write: LogLevel -> string -> unit
        MinLevel: LogLevel
    }

    member this.Debug msg =
        if this.MinLevel <= LogLevel.Debug then
            this.Write LogLevel.Debug msg

    member this.Info msg =
        if this.MinLevel <= LogLevel.Info then
            this.Write LogLevel.Info msg

    member this.Warn msg =
        if this.MinLevel <= LogLevel.Warn then
            this.Write LogLevel.Warn msg

    member this.Error msg = this.Write LogLevel.Error msg

module Log =
    let private name level =
        match level with
        | LogLevel.Debug -> "DEBUG"
        | LogLevel.Info -> "INFO "
        | LogLevel.Warn -> "WARN "
        | _ -> "ERROR"

    let private breaksLine (c: char) = (Char.IsControl c && c <> '\t') || c = ' ' || c = ' '

    /// The text with CR and LF as \r and \n and other control characters (ESC too) as \uXXXX,
    /// so a message from a beacon node or a signer cannot start a forged log line or send
    /// terminal escapes. Tabs stay.
    let escape (msg: string) =
        if not (msg |> Seq.exists breaksLine) then
            msg
        else
            let b = Text.StringBuilder(msg.Length + 16)

            for c in msg do
                match c with
                | '\r' -> b.Append "\\r" |> ignore
                | '\n' -> b.Append "\\n" |> ignore
                | c when breaksLine c -> b.Append("\\u").Append((int c).ToString("x4")) |> ignore
                | c -> b.Append c |> ignore

            b.ToString()

    let console (time: TimeProvider) (minLevel: LogLevel) : Log =
        let gate = obj ()

        {
            MinLevel = minLevel
            Write =
                fun level msg ->
                    let line = $"""{time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")} {name level} {escape msg}"""
                    lock gate (fun () -> Console.Error.WriteLine line)
        }

    let private jsonName level =
        match level with
        | LogLevel.Debug -> "debug"
        | LogLevel.Info -> "info"
        | LogLevel.Warn -> "warn"
        | _ -> "error"

    /// One JSON object per line: {"time": ..., "level": ..., "msg": ...}.
    let jsonLine (time: DateTimeOffset) (level: LogLevel) (msg: string) =
        use ms = new IO.MemoryStream()

        (use w = new Text.Json.Utf8JsonWriter(ms)
         w.WriteStartObject()
         w.WriteString("time", time.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", Globalization.CultureInfo.InvariantCulture))
         w.WriteString("level", jsonName level)
         w.WriteString("msg", msg)
         w.WriteEndObject())

        Text.Encoding.UTF8.GetString(ms.ToArray())

    /// JSON lines on stderr.
    let json (time: TimeProvider) (minLevel: LogLevel) : Log =
        let gate = obj ()

        {
            MinLevel = minLevel
            Write =
                fun level msg ->
                    let line = jsonLine (time.GetUtcNow()) level msg
                    lock gate (fun () -> Console.Error.WriteLine line)
        }

    let create (time: TimeProvider) (minLevel: LogLevel) (format: LogFormat) : Log =
        match format with
        | LogFormat.Json -> json time minLevel
        | _ -> console time minLevel

    let none: Log =
        {
            MinLevel = LogLevel.Error
            Write = fun _ _ -> ()
        }

    /// Collects lines in memory, for tests.
    let memory () =
        let lines = Collections.Concurrent.ConcurrentQueue<string>()

        {
            MinLevel = LogLevel.Debug
            Write = fun level msg -> lines.Enqueue $"{name level} {msg}"
        },
        lines
