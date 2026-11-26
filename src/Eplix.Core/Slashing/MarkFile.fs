/// The file under the slashing DB: append, fsync, truncate a torn tail, replace atomically.
/// An interface so the crash tests can model which bytes survive.
namespace Eplix.Slashing

open System
open System.IO
open System.Runtime.InteropServices
open Eplix

type IMarkFile =
    inherit IDisposable
    abstract ReadAll: unit -> byte[]
    abstract Append: byte[] -> unit
    /// fsync. After it returns, every appended byte is durable.
    abstract Sync: unit -> unit
    /// Cuts the file to `length` bytes and makes that durable.
    abstract Truncate: length: int64 -> unit
    /// Replaces the whole content atomically: write a temporary file, fsync, rename, fsync the directory.
    abstract Replace: byte[] -> unit

type internal WriteOutage =
    {
        /// The last failure.
        Reason: string
        Since: DateTimeOffset
        Failures: int
        NextTry: DateTimeOffset
        /// The first failure, or the last "still down" warning.
        WarnedAt: DateTimeOffset
    }

/// After a failed write a store (the slashing DB, the slot marks file) refuses every request
/// until a write succeeds again. A request that comes after the backoff tries again: 1 s after
/// the failure, then 2, 4 and 8 s later, then every 12 s. A try rewrites the whole file, so
/// trying on every request would rewrite it many times a slot while the disk stays full; the
/// 12 s cap, one mainnet slot, keeps the time from a freed disk to the next signature near a slot.
/// While the writes keep failing, a warning every 10 minutes says since when.
type internal WriteRetry(store: string) =
    let maxBackoff = TimeSpan.FromSeconds 12.0
    let warnEvery = TimeSpan.FromMinutes 10.0
    // Swapped whole, never changed in place, so a reader without the store's gate never sees
    // half an update.
    let mutable outage: WriteOutage option = None

    member val Time: TimeProvider = TimeProvider.System with get, set
    member val Log: Log voption = ValueNone with get, set

    /// When the first write of the current outage failed; ValueNone while writes succeed.
    member _.DownSince =
        match outage with
        | Some o -> ValueSome o.Since
        | None -> ValueNone

    /// True after a failed write, until a write succeeds.
    member _.IsDown = outage.IsSome

    /// The last failure while the next try is not due: refuse without touching the file.
    member this.Waiting: string voption =
        match outage with
        | Some o when this.Time.GetUtcNow() < o.NextTry -> ValueSome o.Reason
        | _ -> ValueNone

    /// Notes a failed write. The first failure of an outage logs an error, later ones a debug line.
    member this.Failed(reason: string) =
        let now = this.Time.GetUtcNow()

        let failures, since, warnedAt =
            match outage with
            | Some o -> o.Failures + 1, o.Since, o.WarnedAt
            | None -> 1, now, now

        let warn = failures > 1 && now - warnedAt >= warnEvery

        let wait = min maxBackoff (TimeSpan.FromSeconds(2.0 ** float (min (failures - 1) 8)))

        outage <-
            Some
                {
                    Reason = reason
                    Since = since
                    Failures = failures
                    NextTry = now + wait
                    WarnedAt = if warn then now else warnedAt
                }

        match this.Log with
        | ValueSome log when failures = 1 ->
            log.Error
                $"{store} write failed: {reason}. Nothing signs until a write succeeds; next try in {wait.TotalSeconds} s"
        | ValueSome log when warn ->
            log.Warn
                $"{store} still cannot write, since {since:u} ({failures} failed writes): {reason}. Nothing signs until a write succeeds"
        | ValueSome log -> log.Debug $"{store} write failed again: {reason}; next try in {wait.TotalSeconds} s"
        | ValueNone -> ()

    /// Notes a write that succeeded. Logs the end of an outage.
    member this.Succeeded() =
        match outage with
        | None -> ()
        | Some o ->
            outage <- None
            let down = this.Time.GetUtcNow() - o.Since

            this.Log
            |> ValueOption.iter (fun log ->
                log.Info
                    $"{store} write succeeded after {o.Failures} failed writes in {int down.TotalSeconds} s; signing resumes")

module private Native =
    [<DllImport("libc.so.6", EntryPoint = "open", SetLastError = true)>]
    extern int sysOpen(byte[] path, int flags)

    [<DllImport("libc.so.6", EntryPoint = "fsync", SetLastError = true)>]
    extern int sysFsync(int fd)

    [<DllImport("libc.so.6", EntryPoint = "close", SetLastError = true)>]
    extern int sysClose(int fd)

module FileSync =
    /// fsync on a directory, so a create or rename in it is durable. Linux only; a no-op elsewhere.
    let syncDirectory (dir: string) =
        if OperatingSystem.IsLinux() then
            let path = Text.Encoding.UTF8.GetBytes(dir + "\000")
            let fd = Native.sysOpen (path, 0) // O_RDONLY

            if fd < 0 then
                raise (IOException $"open {dir} for fsync failed: errno {Marshal.GetLastPInvokeError()}")

            try
                if Native.sysFsync fd <> 0 then
                    raise (IOException $"fsync {dir} failed: errno {Marshal.GetLastPInvokeError()}")
            finally
                Native.sysClose fd |> ignore

    /// Writes a whole file atomically and durably: a temporary file created with `mode`, fsync,
    /// rename over the target, fsync of the directory. A crash leaves the old file or the new
    /// one, never part of either.
    let writeAtomic (path: string) (content: byte[]) (mode: UnixFileMode) =
        let dir = nonNull (Path.GetDirectoryName(Path.GetFullPath path))
        let tmp = path + ".tmp"

        let options =
            FileStreamOptions(Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None)

        if not (OperatingSystem.IsWindows()) then
            options.UnixCreateMode <- Nullable mode

        try
            // A temporary file left by a crash may be open elsewhere with an older mode: write a
            // new inode, created with `mode`, never into the old one.
            File.Delete tmp

            (use f = new FileStream(tmp, options)

             if not (OperatingSystem.IsWindows()) then
                 File.SetUnixFileMode(tmp, mode)

             f.Write(content, 0, content.Length)
             f.Flush true)

            File.Move(tmp, path, true)
        with _ ->
            (try
                File.Delete tmp
             with _ ->
                 ())

            reraise ()

        syncDirectory dir

/// The real file. One writer: the VC holds a lock file next to it (see DataDir).
/// `wrap` wraps each stream the file opens; the tests use it to fail writes. Writes and flushes
/// go through the wrapped stream, the fsync and the length through the file itself.
type FileMarkFile internal (path: string, wrap: Stream -> Stream) =
    let dir = Path.GetDirectoryName(Path.GetFullPath path) |> nonNull
    let created = not (File.Exists path)

    // No buffer (size 0): Append hands the OS a whole burst in one write, and a buffer could keep
    // part of a failed write and flush it to the file later, when the stream closes.
    let openFile (mode: FileMode) =
        new FileStream(path, mode, FileAccess.ReadWrite, FileShare.Read, 0, FileOptions.None)

    let mutable file = openFile FileMode.OpenOrCreate
    let mutable stream = wrap file

    do
        if created then
            file.Flush(true)
            FileSync.syncDirectory dir

    // The length after the last write that succeeded: the open, a sync, a truncate, a replace.
    let mutable goodLength = file.Length

    /// After a failed append or sync: cuts the bytes of that write the OS may already hold, so
    /// neither a later close nor a restart finds part of it in the file. Shrinking a file needs
    /// no free space. If the cut fails too, the bytes stay; the DB rewrites the file before its
    /// next append, and a restart cuts a torn tail.
    let cutBack () =
        try
            file.SetLength goodLength
            file.Flush(true)
        with _ ->
            ()

    new(path: string) = new FileMarkFile(path, id)

    member _.Path = path

    interface IMarkFile with
        member _.ReadAll() =
            file.Position <- 0L
            let buf = Array.zeroCreate<byte>(int file.Length)
            file.ReadExactly(buf, 0, buf.Length)
            buf

        member _.Append(bytes) =
            try
                file.Seek(0L, SeekOrigin.End) |> ignore
                stream.Write(bytes, 0, bytes.Length)
            with _ ->
                cutBack ()
                reraise ()

        member _.Sync() =
            try
                stream.Flush()
                file.Flush(true)
                goodLength <- file.Length
            with _ ->
                cutBack ()
                reraise ()

        member _.Truncate(length) =
            file.SetLength length
            file.Flush(true)
            goodLength <- length

        member _.Replace(bytes) =
            let tmp = path + ".tmp"

            try
                (use t = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None)
                 t.Write(bytes, 0, bytes.Length)
                 t.Flush(true))

                // The stream has no buffer, so closing it writes nothing; a close that fails
                // still frees the handle, and the old file is about to be replaced.
                (try
                    stream.Dispose()
                 with _ ->
                     ())

                File.Move(tmp, path, true)
                FileSync.syncDirectory dir
                file <- openFile FileMode.Open
                stream <- wrap file
                goodLength <- int64 bytes.Length
            with _ ->
                // A part-written temporary file would keep a full disk full. If the stream is
                // closed now, the next Replace opens it again; an append before that fails.
                (try
                    File.Delete tmp
                 with _ ->
                     ())

                reraise ()

        member _.Dispose() = stream.Dispose()
