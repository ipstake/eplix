/// The file under the slashing DB: append, fsync, truncate a torn tail, replace atomically.
/// An interface so the crash tests can model which bytes survive.
namespace Eplix.Slashing

open System
open System.IO
open System.Runtime.InteropServices

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
type FileMarkFile(path: string) =
    let dir = Path.GetDirectoryName(Path.GetFullPath path) |> nonNull
    let created = not (File.Exists path)

    let mutable stream =
        new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.None)

    do
        if created then
            stream.Flush(true)
            FileSync.syncDirectory dir

    member _.Path = path

    interface IMarkFile with
        member _.ReadAll() =
            stream.Position <- 0L
            let buf = Array.zeroCreate<byte>(int stream.Length)
            stream.ReadExactly(buf, 0, buf.Length)
            buf

        member _.Append(bytes) =
            stream.Seek(0L, SeekOrigin.End) |> ignore
            stream.Write(bytes, 0, bytes.Length)

        member _.Sync() = stream.Flush(true)

        member _.Truncate(length) =
            stream.SetLength length
            stream.Flush(true)

        member _.Replace(bytes) =
            let tmp = path + ".tmp"

            (use t = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None)
             t.Write(bytes, 0, bytes.Length)
             t.Flush(true))

            stream.Dispose()
            File.Move(tmp, path, true)
            FileSync.syncDirectory dir
            stream <- new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.None)

        member _.Dispose() = stream.Dispose()
