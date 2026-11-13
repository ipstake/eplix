/// A Prometheus text-format exporter for System.Diagnostics.Metrics instruments (format 0.0.4).
/// A MeterListener sums counters and fills histogram buckets per label set, and keeps the last
/// value of gauges and observable instruments; Render asks the observable instruments for their
/// values and writes everything with the gauges the caller reads at scrape time. No OpenTelemetry
/// packages.
module Eplix.Metrics.Prometheus

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Diagnostics.Metrics
open System.Globalization
open System.Text

/// Bucket bounds for a histogram that gives no advice: 5 ms to 10 s, as the Prometheus clients use.
let defaultBuckets = [| 0.005; 0.01; 0.025; 0.05; 0.1; 0.25; 0.5; 1.0; 2.5; 5.0; 10.0 |]

[<RequireQualifiedAccess>]
type Kind =
    | Counter
    | Gauge
    | Histogram

/// One metric name with its help text and type.
type Family =
    {
        Name: string
        Help: string
        Kind: Kind
        Buckets: float[]
        /// A measurement replaces the value instead of adding to it: gauges, and observable
        /// instruments, which report their total at each scrape.
        Replace: bool
    }

/// A value read at scrape time: labels and value.
type GaugeSample =
    {
        Labels: (string * string) list
        Value: float
    }

/// Gauges the caller computes at scrape time (key states, node scores).
type GaugeFamily =
    {
        Name: string
        Help: string
        Samples: GaugeSample list
    }

/// Replaces characters Prometheus does not allow in a metric or label name with '_'.
let sanitize (name: string) =
    let sb = StringBuilder(name.Length)

    for i in 0 .. name.Length - 1 do
        let c = name[i]
        let ok = Char.IsAsciiLetter c || c = '_' || c = ':' || (i > 0 && Char.IsAsciiDigit c)
        sb.Append(if ok then c else '_') |> ignore

    sb.ToString()

/// Escapes a label value: backslash, double quote and line feed.
let escape (value: string) = value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n")

let formatValue (v: float) =
    match v with
    | Double.PositiveInfinity -> "+Inf"
    | Double.NegativeInfinity -> "-Inf"
    | _ when Double.IsNaN v -> "NaN"
    | _ -> v.ToString("R", CultureInfo.InvariantCulture)

/// `{a="x",b="y"}`, labels sorted by name; empty for no labels.
let renderLabels (labels: (string * string) seq) =
    let parts =
        labels |> Seq.sortBy fst |> Seq.map (fun (k, v) -> $"{sanitize k}=\"{escape v}\"") |> Array.ofSeq

    if parts.Length = 0 then "" else "{" + String.Join(",", parts) + "}"

/// The running sum of one counter, or the buckets of one histogram, for one label set.
type private Series(buckets: int) =
    member val Labels: (string * string) list = [] with get, set
    /// The labels as rendered, `{a="x"}`; the order of the exposition.
    member val Key = "" with get, set
    member val Sum = 0.0 with get, set
    member val Count = 0L with get, set
    /// Per-bucket counts (not cumulative); the last one is +Inf.
    member val Counts: int64[] = Array.zeroCreate (buckets + 1) with get

/// The label set of one measurement, sorted by name, as the lookup key of its series. Up to four
/// labels sit in the fields, so a lookup copies and allocates nothing; a measurement
/// with more labels keys on its rendered labels in `Long`.
[<Struct; CustomEquality; NoComparison>]
type LabelKey =
    val Count: int
    val K0: string
    val V0: string
    val K1: string
    val V1: string
    val K2: string
    val V2: string
    val K3: string
    val V3: string
    val Long: string

    new(count, k0, v0, k1, v1, k2, v2, k3, v3, long) =
        {
            Count = count
            K0 = k0
            V0 = v0
            K1 = k1
            V1 = v1
            K2 = k2
            V2 = v2
            K3 = k3
            V3 = v3
            Long = long
        }

    member k.Same(o: LabelKey) =
        k.Count = o.Count
        && String.Equals(k.K0, o.K0)
        && String.Equals(k.V0, o.V0)
        && String.Equals(k.K1, o.K1)
        && String.Equals(k.V1, o.V1)
        && String.Equals(k.K2, o.K2)
        && String.Equals(k.V2, o.V2)
        && String.Equals(k.K3, o.K3)
        && String.Equals(k.V3, o.V3)
        && String.Equals(k.Long, o.Long)

    override k.Equals(o: obj) =
        match o with
        | :? LabelKey as o -> k.Same o
        | _ -> false

    override k.GetHashCode() =
        let mutable h = HashCode()
        h.Add k.Count
        h.Add k.K0
        h.Add k.V0
        h.Add k.K1
        h.Add k.V1
        h.Add k.K2
        h.Add k.V2
        h.Add k.K3
        h.Add k.V3
        h.Add k.Long
        h.ToHashCode()

    interface IEquatable<LabelKey> with
        member k.Equals(o: LabelKey) = k.Same o

/// A tag value as label text: a string as it is, anything else through ToString, null as "".
let private labelValue (v: objnull) : string =
    match v with
    | null -> ""
    | :? string as s -> s
    | v -> defaultArg (Option.ofObj (v.ToString())) ""

/// The position of tag `j` when the tags are sorted by name (ordinal; equal names keep their order).
let private rank (tags: ReadOnlySpan<KeyValuePair<string, objnull>>) (j: int) =
    let mutable r = 0

    for i in 0 .. tags.Length - 1 do
        let c = String.CompareOrdinal(tags[i].Key, tags[j].Key)

        if c < 0 || (c = 0 && i < j) then
            r <- r + 1

    r

/// The tag at sorted position `p`.
let private sortedAt (tags: ReadOnlySpan<KeyValuePair<string, objnull>>) (p: int) : KeyValuePair<string, objnull> =
    let mutable j = 0

    while rank tags j <> p do
        j <- j + 1

    tags[j]

/// The tags as (name, value) pairs sorted by name.
let private sortedLabels (tags: ReadOnlySpan<KeyValuePair<string, objnull>>) : (string * string) list =
    let pairs = Array.zeroCreate<string * string> tags.Length

    for j in 0 .. tags.Length - 1 do
        pairs[j] <- (tags[j].Key, labelValue tags[j].Value)

    pairs |> Array.sortBy fst |> List.ofArray

/// The lookup key of a measurement's tags. Allocates nothing for up to four tags with string
/// values, which is every instrument of the VC.
let labelKey (tags: ReadOnlySpan<KeyValuePair<string, objnull>>) : LabelKey =
    let n = tags.Length

    if n = 0 then
        LabelKey(0, "", "", "", "", "", "", "", "", "")
    elif n > 4 then
        LabelKey(n, "", "", "", "", "", "", "", "", renderLabels (sortedLabels tags))
    else
        let a = sortedAt tags 0

        let struct (bk, bv) =
            if n > 1 then (let x = sortedAt tags 1 in struct (x.Key, labelValue x.Value)) else struct ("", "")

        let struct (ck, cv) =
            if n > 2 then (let x = sortedAt tags 2 in struct (x.Key, labelValue x.Value)) else struct ("", "")

        let struct (dk, dv) =
            if n > 3 then (let x = sortedAt tags 3 in struct (x.Key, labelValue x.Value)) else struct ("", "")

        LabelKey(n, a.Key, labelValue a.Value, bk, bv, ck, cv, dk, dv, "")

type private Tracked =
    {
        Family: Family
        Series: ConcurrentDictionary<LabelKey, Series>
    }

/// Listens to the meters named in `meterNames` until disposed.
type Collector(meterNames: string list) =
    let tracked = ConcurrentDictionary<Instrument, Tracked>()
    let listener = new MeterListener()

    let familyOf (i: Instrument) : Family voption =
        let help = defaultArg (Option.ofObj i.Description) i.Name
        let name = sanitize i.Name

        match i with
        | :? Counter<int64>
        | :? Counter<float> ->
            ValueSome
                {
                    Name = (if name.EndsWith "_total" then name else name + "_total")
                    Help = help
                    Kind = Kind.Counter
                    Buckets = [||]
                    Replace = false
                }
        | :? ObservableCounter<int64>
        | :? ObservableCounter<float> ->
            ValueSome
                {
                    Name = (if name.EndsWith "_total" then name else name + "_total")
                    Help = help
                    Kind = Kind.Counter
                    Buckets = [||]
                    Replace = true
                }
        | :? UpDownCounter<int64>
        | :? UpDownCounter<float> ->
            ValueSome
                {
                    Name = name
                    Help = help
                    Kind = Kind.Gauge
                    Buckets = [||]
                    Replace = false
                }
        | :? Gauge<int64>
        | :? Gauge<float>
        | :? ObservableGauge<int64>
        | :? ObservableGauge<float>
        | :? ObservableUpDownCounter<int64>
        | :? ObservableUpDownCounter<float> ->
            ValueSome
                {
                    Name = name
                    Help = help
                    Kind = Kind.Gauge
                    Buckets = [||]
                    Replace = true
                }
        | :? Histogram<float> as h ->
            let advice =
                match h.Advice with
                | null -> ValueNone
                | a ->
                    match a.HistogramBucketBoundaries with
                    | null -> ValueNone
                    | b -> ValueSome(Array.ofSeq b)

            ValueSome
                {
                    Name = name
                    Help = help
                    Kind = Kind.Histogram
                    Buckets = defaultValueArg advice defaultBuckets
                    Replace = false
                }
        | :? Histogram<int64> as h ->
            let advice =
                match h.Advice with
                | null -> ValueNone
                | a ->
                    match a.HistogramBucketBoundaries with
                    | null -> ValueNone
                    | b -> ValueSome(b |> Seq.map float |> Array.ofSeq)

            ValueSome
                {
                    Name = name
                    Help = help
                    Kind = Kind.Histogram
                    Buckets = defaultValueArg advice defaultBuckets
                    Replace = false
                }
        | _ -> ValueNone

    let record (i: Instrument) (value: float) (tags: ReadOnlySpan<KeyValuePair<string, objnull>>) =
        // The lookups allocate nothing (out arguments, not tuple patterns, which a Debug build
        // allocates); only the first measurement of a label set builds its series.
        let mutable t = Unchecked.defaultof<Tracked>

        if tracked.TryGetValue(i, &t) then
            let key = labelKey tags
            let mutable s = Unchecked.defaultof<Series>

            if not (t.Series.TryGetValue(key, &s)) then
                let labels = sortedLabels tags
                s <- t.Series.GetOrAdd(key, Series(t.Family.Buckets.Length, Labels = labels, Key = renderLabels labels))
            // Monitor directly: `lock` with a lambda allocates a closure per measurement.
            Threading.Monitor.Enter s

            try
                match t.Family.Kind with
                | Kind.Histogram ->
                    let mutable b = 0

                    while b < t.Family.Buckets.Length && value > t.Family.Buckets[b] do
                        b <- b + 1

                    s.Counts[b] <- s.Counts[b] + 1L
                    s.Sum <- s.Sum + value
                    s.Count <- s.Count + 1L
                | _ when t.Family.Replace -> s.Sum <- value
                | _ -> s.Sum <- s.Sum + value
            finally
                Threading.Monitor.Exit s

    do
        listener.InstrumentPublished <-
            fun i l ->
                if List.contains i.Meter.Name meterNames then
                    match familyOf i with
                    | ValueSome f ->
                        tracked[i] <-
                            {
                                Family = f
                                Series = ConcurrentDictionary()
                            }

                        l.EnableMeasurementEvents(i, null)
                    | ValueNone -> ()

        listener.MeasurementsCompleted <- fun i _ -> tracked.TryRemove i |> ignore
        listener.SetMeasurementEventCallback<int64>(fun i v tags _ -> record i (float v) tags)
        listener.SetMeasurementEventCallback<float>(fun i v tags _ -> record i v tags)
        listener.Start()

    /// The exposition text: the instruments' series, then the gauges.
    member _.Render(gauges: GaugeFamily list) : string =
        listener.RecordObservableInstruments()
        let sb = StringBuilder()

        let header (name: string) (help: string) (kind: string) =
            sb
                .Append("# HELP ")
                .Append(name)
                .Append(' ')
                .Append(help.Replace("\\", "\\\\").Replace("\n", "\\n"))
                .Append('\n')
            |> ignore

            sb.Append("# TYPE ").Append(name).Append(' ').Append(kind).Append('\n') |> ignore

        let line (name: string) (labels: string) (value: string) =
            sb.Append(name).Append(labels).Append(' ').Append(value).Append('\n') |> ignore
        // Two instruments with one name (two meters) merge into one family.
        let families = tracked.Values |> Seq.groupBy (fun t -> t.Family.Name) |> Seq.sortBy fst

        for name, ts in families do
            let family = (Seq.head ts).Family

            header
                name
                family.Help
                (match family.Kind with
                 | Kind.Counter -> "counter"
                 | Kind.Gauge -> "gauge"
                 | Kind.Histogram -> "histogram")

            let series =
                ts
                |> Seq.collect (fun t -> t.Series.Values |> Seq.map (fun s -> s.Key, t.Family, s))
                |> Seq.sortBy (fun (k, _, _) -> k)

            for key, f, s in series do
                lock s (fun () ->
                    match f.Kind with
                    | Kind.Histogram ->
                        let mutable cumulative = 0L

                        for b in 0 .. f.Buckets.Length do
                            cumulative <- cumulative + s.Counts[b]
                            let le = if b < f.Buckets.Length then formatValue f.Buckets[b] else "+Inf"
                            line (name + "_bucket") (renderLabels (("le", le) :: s.Labels)) (string cumulative)

                        line (name + "_sum") key (formatValue s.Sum)
                        line (name + "_count") key (string s.Count)
                    | _ -> line name key (formatValue s.Sum))

        for g in gauges |> List.sortBy (fun g -> g.Name) do
            let name = sanitize g.Name
            header name g.Help "gauge"

            for s in g.Samples do
                line name (renderLabels s.Labels) (formatValue s.Value)

        sb.ToString()

    interface IDisposable with
        member _.Dispose() = listener.Dispose()
