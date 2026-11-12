/// The runtime's own meters: GC, CPU time, process memory and the thread pool, as
/// observable instruments on the core meter. The exporter reads them at each scrape; without a
/// listener nothing calls them.
module Eplix.Metrics.Runtime

open System
open System.Collections.Generic
open System.Diagnostics.Metrics
open System.Threading
open Eplix

let private tag (name: string) (value: string) = KeyValuePair<string, objnull>(name, box value)

let private create () =
    let m = Metrics.meter

    [
        m.CreateObservableCounter<int64>(
            "eplix_gc_collections",
            Func<IEnumerable<Measurement<int64>>>(fun () ->
                [
                    for g in 0 .. GC.MaxGeneration ->
                        Measurement<int64>(int64 (GC.CollectionCount g), tag "generation" (string g))
                ]
                :> IEnumerable<_>),
            description = "Garbage collections since the start, by generation"
        )
        :> Instrument
        m.CreateObservableGauge<int64>(
            "eplix_gc_heap_bytes",
            Func<int64>(fun () -> GC.GetTotalMemory false),
            unit = "By",
            description = "Bytes on the GC heap: live objects and garbage not yet collected"
        )
        m.CreateObservableCounter<int64>(
            "eplix_gc_allocated_bytes",
            Func<int64>(fun () -> GC.GetTotalAllocatedBytes false),
            unit = "By",
            description = "Bytes allocated on the GC heap since the start"
        )
        m.CreateObservableCounter<float>(
            "eplix_gc_pause_seconds",
            Func<float>(fun () -> GC.GetTotalPauseDuration().TotalSeconds),
            unit = "s",
            description = "Time the GC paused the process since the start"
        )
        m.CreateObservableCounter<float>(
            "eplix_process_cpu_seconds",
            Func<IEnumerable<Measurement<float>>>(fun () ->
                let u = Environment.CpuUsage

                [
                    Measurement<float>(u.UserTime.TotalSeconds, tag "mode" "user")
                    Measurement<float>(u.PrivilegedTime.TotalSeconds, tag "mode" "system")
                ]
                :> IEnumerable<_>),
            unit = "s",
            description = "CPU time of the process, by mode"
        )
        m.CreateObservableGauge<int64>(
            "eplix_process_working_set_bytes",
            Func<int64>(fun () -> Environment.WorkingSet),
            unit = "By",
            description = "Physical memory of the process (resident set on Linux)"
        )
        m.CreateObservableGauge<int64>(
            "eplix_threadpool_threads",
            Func<int64>(fun () -> int64 ThreadPool.ThreadCount),
            description = "Thread pool threads"
        )
        m.CreateObservableGauge<int64>(
            "eplix_threadpool_queue_length",
            Func<int64>(fun () -> ThreadPool.PendingWorkItemCount),
            description = "Work items waiting in the thread pool"
        )
        m.CreateObservableCounter<int64>(
            "eplix_threadpool_completed_items",
            Func<int64>(fun () -> ThreadPool.CompletedWorkItemCount),
            description = "Work items the thread pool completed since the start"
        )
    ]

let private instruments = lazy (create ())

/// Creates the instruments once per process (a second set would print every series twice).
let ensure () = instruments.Force() |> ignore
