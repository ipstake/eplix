/// PubKey's hash code: keys that share bytes 4 to 7, as a crafted interchange
/// can hold, still spread over the dictionary, so the streamed import reader and the slashing
/// merge stay linear; and their output does not depend on the per-process hash seed.
module Eplix.Tests.PubKeyHashTests

open System
open System.Diagnostics
open System.IO
open System.Security.Cryptography
open System.Text
open Expecto
open Eplix
open Eplix.Slashing
open Eplix.Tests.SlashingTests

let private gvr = Root.Of(Array.create 32 5uy)

/// Keys equal in bytes 0 to 7 (the bytes the old hash code read), distinct in bytes 8 to 11.
let private collidingHex (i: int) = "0xc000000000000000" + i.ToString("x8") + String('0', 72)

/// An interchange with one entry and one block for each key `keyHex 0` .. `keyHex (n - 1)`.
let private interchange (keyHex: int -> string) (n: int) =
    let sb = StringBuilder()

    sb.Append($$"""{"metadata":{"interchange_format_version":"5","genesis_validators_root":"{{gvr.Hex}}"},"data":[""")
    |> ignore

    for i in 0 .. n - 1 do
        if i > 0 then
            sb.Append ',' |> ignore

        sb.Append($$"""{"pubkey":"{{keyHex i}}","signed_blocks":[{"slot":"{{i + 1}}"}],"signed_attestations":[]}""")
        |> ignore

    sb.Append "]}" |> ignore
    Encoding.UTF8.GetBytes(sb.ToString())

let private openDb (file: IMarkFile) =
    match SlashingDb.Open(file, gvr) with
    | Ok db -> db
    | Error e -> failwith e

/// Reads n colliding keys through InterchangeStream.read, then merges them into an empty DB.
/// Returns the time of each step.
let private collidingImport (n: int) =
    let bytes = interchange collidingHex n
    let sw = Stopwatch.StartNew()

    let marks =
        use ms = new MemoryStream(bytes, false)

        match InterchangeStream.read ms with
        | Ok m -> m
        | Error e -> failwith e

    let read = sw.Elapsed
    Expect.equal marks.Marks.Length n "every key read"
    let db = openDb (new ModelFile([||]))
    sw.Restart()
    let r = db.ImportMarks marks
    let merge = sw.Elapsed
    Expect.isOk r "imported"
    Expect.equal db.Keys.Length n "every key has a record"
    read, merge

[<Tests>]
let tests =
    testList
        "pubkey hash"
        [
            test "keys equal in bytes 0 to 7 get distinct hash codes" {
                let codes = [ for i in 0..99_999 -> (PubKey.TryParse(collidingHex i)).Value.GetHashCode() ]
                // 100,000 random 32-bit codes collide about once.
                Expect.isGreaterThan (List.distinct codes |> List.length) 99_900 "distinct codes"
            }
            test "100,000 colliding keys: the stream reader and the merge in bounded time" {
                collidingImport 1_000 |> ignore
                let read, merge = collidingImport 100_000

                printfn
                    $"pubkey hash: 100,000 colliding keys read in {read.TotalMilliseconds:F0} ms, merged in {merge.TotalMilliseconds:F0} ms"
                // With the old hash code (bytes 4 to 7) every key fell in one bucket: 100,000 keys
                // took 64 s to read and 95 s to merge on a Release build. Now each takes well under a second.
                Expect.isLessThan read (TimeSpan.FromSeconds 5.0) "the reader in under 5 s"
                Expect.isLessThan merge (TimeSpan.FromSeconds 5.0) "the merge in under 5 s"
            }
            test "the import's records and export do not depend on the hash seed" {
                // A fixed input with repeated keys, read and merged; the digest of the mark file and
                // of the export matches a fixed digest, so every run checks it with its own seed.
                let rng = Random 524

                let keys =
                    Array.init 3_000 (fun _ ->
                        let b = Array.zeroCreate<byte> 48
                        rng.NextBytes b
                        Hex.encodeArray b)

                let order = Array.init 6_000 (fun _ -> rng.Next keys.Length)
                let bytes = interchange (fun i -> keys[order[i]]) order.Length

                let marks =
                    use ms = new MemoryStream(bytes, false)

                    match InterchangeStream.read ms with
                    | Ok m -> m
                    | Error e -> failwith e

                let file = new ModelFile([||])
                let db = openDb file
                Expect.isOk (db.ImportMarks marks) "imported"

                let digest =
                    Array.append ((file :> IMarkFile).ReadAll()) (Interchange.write (db.Export ValueNone))
                    |> SHA256.HashData
                    |> Convert.ToHexStringLower

                Expect.equal
                    digest
                    "ce6a7506a230d0bb0df2a69ec59eb0360289cc95a6a8197c1e8bed3da0780a30"
                    "the same records and export as with the old hash code"
            }
        ]
