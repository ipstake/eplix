/// The VC's spans, on System.Diagnostics.Activity. With no listener (the tracing module off or
/// not linked) `ActivitySource.StartActivity` returns null after one check, and the helpers here
/// do nothing else: no name is formatted and no tag is boxed. The tracing module listens and
/// exports the spans over OTLP.
namespace Eplix

open System
open System.Diagnostics

module Tracing =
    /// Duty spans and their children: signing bursts, slashing checks, beacon node calls, submits.
    [<Literal>]
    let SourceName = "Eplix"

    /// One span per signing request. A burst of 10,000 attestations makes 10,000 of them, so the
    /// tracing module listens to this source only when asked (`sign_spans`).
    [<Literal>]
    let SignSourceName = "Eplix.Sign"

    let source = new ActivitySource(SourceName)
    let signSource = new ActivitySource(SignSourceName)

    /// A child span of whatever span is current, or a root span when none is. Null when nothing
    /// listens or the sampler drops it.
    let inline start (name: string) : Activity | null = source.StartActivity(name, ActivityKind.Internal)

    let private rootSpan (name: string) (unit: string) (at: uint64) (count: int) : Activity | null =
        if source.HasListeners() then
            match source.StartActivity(name, ActivityKind.Internal) with
            | null -> null
            | a ->
                a.SetTag(unit, box at).SetTag("eplix.duties", box count) |> ignore
                a
        else
            null

    /// The span of one duty kind for one slot with work: the root of a trace.
    let duty (name: string) (slot: uint64) (count: int) = rootSpan name "eplix.slot" slot count

    /// The span of one duty kind for one epoch with work (selection proofs).
    let dutyOfEpoch (name: string) (epoch: uint64) (count: int) = rootSpan name "eplix.epoch" epoch count

    let inline setInt (a: Activity | null) (key: string) (value: int) =
        match a with
        | null -> ()
        | a -> a.SetTag(key, box value) |> ignore

    let inline setText (a: Activity | null) (key: string) (value: string) =
        match a with
        | null -> ()
        | a -> a.SetTag(key, value) |> ignore

    let inline setBool (a: Activity | null) (key: string) (value: bool) =
        match a with
        | null -> ()
        | a -> a.SetTag(key, box value) |> ignore

    /// Marks the span failed with a reason (OTLP status ERROR).
    let inline fail (a: Activity | null) (why: string) =
        match a with
        | null -> ()
        | a -> a.SetStatus(ActivityStatusCode.Error, why) |> ignore

    /// A request path with its variable parts (numbers, 0x values) as {id} and the query left
    /// out, so a span name has few values: "/eth/v1/validator/duties/attester/{id}".
    let pathTemplate (path: string) =
        let path =
            match path.IndexOf '?' with
            | -1 -> path
            | i -> path.Substring(0, i)

        let parts = path.Split '/'

        for i in 0 .. parts.Length - 1 do
            let p = parts[i]

            if p.Length > 0 && (p.StartsWith("0x", StringComparison.Ordinal) || Seq.forall Char.IsAsciiDigit p) then
                parts[i] <- "{id}"

        String.Join('/', parts)
