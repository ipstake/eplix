module Eplix.Tests.SszTests

open System.IO
open Expecto
open Eplix
open Eplix.Ssz
open Eplix.Tests.TestUtil

let private readRoot (file: string) =
    let line = File.ReadAllText(file).Trim()
    // roots.yaml holds one line: root: '0x...'
    line.Substring(line.IndexOf("0x")).TrimEnd('\'', '"')

/// consensus-spec-tests ssz_static, minimal preset: decode, encode again, compare root, and the
/// Beacon API JSON round trip. Fulu cases from v1.6.1 in ssz_static/, Gloas cases from
/// v1.7.0-beta.4 in ssz_static_gloas/.
let private staticCasesIn (dir: string) (schemas: Map<string, SszType>) =
    [
        for containerDir in Directory.GetDirectories dir do
            let name = Path.GetFileName containerDir

            match schemas.TryFind name with
            | None -> ()
            | Some schema ->
                for caseDir in Directory.GetDirectories(containerDir, "case_*", SearchOption.AllDirectories) do
                    let label = Path.GetRelativePath(dir, caseDir)

                    test label {
                        let bytes =
                            Snappy.decompress (File.ReadAllBytes(Path.Combine(caseDir, "serialized.ssz_snappy")))

                        let expected = readRoot (Path.Combine(caseDir, "roots.yaml"))

                        match deserialize schema bytes with
                        | Error e -> failtestf "decode failed: %s" e
                        | Ok v ->
                            Expect.equal (serialize schema v) bytes "re-encoding gives the same bytes"
                            Expect.equal (Hex.encodeArray (hashTreeRoot schema v)) expected "hash_tree_root"
                            // The Beacon API JSON form gives the same value back.
                            let json = SszJson.toBytes schema v

                            match Json.decode (SszJson.read schema) (System.ReadOnlyMemory json) with
                            | Error e -> failtestf "JSON decode failed: %s" e
                            | Ok v2 -> Expect.equal (serialize schema v2) bytes "JSON round trip"
                    }
    ]

/// The whole ssz_static directory of a release, when the variable points to one (the nightly
/// run). A path that does not exist fails the run.
let private fullRelease (variable: string) (schemas: Map<string, SszType>) =
    [
        match System.Environment.GetEnvironmentVariable variable with
        | null
        | "" -> ()
        | full when Directory.Exists full ->
            let cases = staticCasesIn full schemas

            yield
                testList
                    "full"
                    (if cases.IsEmpty then
                         [ test "cases" { failtestf "%s has no case for any Eplix schema" full } ]
                     else
                         cases)
        | full -> yield test "full" { failtestf "%s=%s does not exist" variable full }
    ]

let private staticCases () =
    let schemas = Schemas.byName Preset.Minimal

    [
        yield! staticCasesIn (Path.Combine(vectors, "ssz_static")) schemas
        yield! fullRelease "EPLIX_FULU_SSZ_STATIC" schemas
    ]

let private gloasCases () =
    let schemas = Schemas.Gloas.byName Preset.Minimal

    [
        yield! staticCasesIn (Path.Combine(vectors, "ssz_static_gloas")) schemas
        yield! fullRelease "EPLIX_GLOAS_SSZ_STATIC" schemas
    ]

[<Tests>]
let tests =
    testList
        "ssz"
        [
            testList "ssz_static" (staticCases ())
            testList "ssz_static gloas" (gloasCases ())
            // Mainnet limits differ from minimal ones (committee bits, sync committee, PTC size).
            testList
                "ssz_static mainnet fulu"
                (staticCasesIn (Path.Combine(vectors, "ssz_static_mainnet_fulu")) (Schemas.byName Preset.Mainnet))
            testList
                "ssz_static mainnet gloas"
                (staticCasesIn (Path.Combine(vectors, "ssz_static_mainnet_gloas")) (Schemas.Gloas.byName Preset.Mainnet))

            test "decoder refuses trailing bytes" {
                let bytes = Array.zeroCreate<byte> 41
                Expect.isError (deserialize Schemas.checkpoint bytes) "41 bytes is not a Checkpoint"
            }

            test "decoder refuses a bitlist without delimiter" {
                Expect.isError (deserialize (Bitlist 16) [| 0xffuy; 0uy |]) "no delimiter"
            }

            test "decoder refuses a bitlist over its limit" {
                Expect.isError (deserialize (Bitlist 4) [| 0b0011_1111uy |]) "5 bits over a limit of 4"
            }

            test "decoder refuses a bad boolean" { Expect.isError (deserialize Boolean [| 2uy |]) "2 is not a boolean" }

            test "JSON uint256: at most 78 digits, checked before the parse" {
                let read (s: string) =
                    Json.decode
                        (SszJson.read Uint256)
                        (System.ReadOnlyMemory(System.Text.Encoding.UTF8.GetBytes $"\"{s}\""))

                let max = string (System.Numerics.BigInteger.Pow(2I, 256) - 1I)
                Expect.equal max.Length 78 "2^256 - 1 has 78 digits"
                Expect.isOk (read max) "the largest uint256"
                Expect.isError (read (string (System.Numerics.BigInteger.Pow(2I, 256)))) "2^256"
                // Small values, but too many digits: refused by length alone.
                Expect.isError (read (String.replicate 78 "0" + "1")) "79 digits"
                Expect.isError (read (String.replicate 1_000_000 "0" + "1")) "a million digits"
                Expect.equal (SszJson.tryUint256 (String.replicate 79 "0")) ValueNone "79 zeros"
            }

            test "decoder checks a list limit of variable items before it reads any item" {
                // Three items of 2 bytes in a List[ByteList[1], 2]: the count is over the limit,
                // and each item is over its own limit too. The count must fail first.
                let offsets = [| 12; 14; 16 |] |> Array.collect (fun o -> [| byte o; 0uy; 0uy; 0uy |])
                let bytes = Array.append offsets [| 0xaauy; 0xbbuy; 0xccuy; 0xdduy; 0xeeuy; 0xffuy |]

                match deserialize (List(ByteList 1, 2)) bytes with
                | Ok _ -> failtest "3 items over a limit of 2"
                | Error e -> Expect.stringContains e "List limit 2 got 3" "refused by the count, before any item"
            }

            test "decoder caps a ProgressiveList of variable items at 2^20" {
                // An offset table alone: every offset points at the table's end, so each item is
                // empty and the input costs 4 bytes an item.
                let table (count: int) =
                    let b = Array.zeroCreate<byte>(4 * count)

                    for i in 0 .. count - 1 do
                        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
                            System.Span(b, 4 * i, 4),
                            uint32 (4 * count)
                        )

                    b

                let schema = ProgressiveList ProgressiveByteList
                Expect.isOk (deserialize schema (table 1000)) "1000 empty items"
                Expect.isError (deserialize schema (table (Ssz.progressiveLimit + 1))) "2^20 + 1 items"
            }

            test "decoder refuses a first offset that skips bytes" {
                let schema = Container [| "a", Uint 8; "b", ByteList 10 |]
                let good = serialize schema (Fields [| U 1UL; Bytes [| 1uy; 2uy |] |])
                Expect.isOk (deserialize schema good) "valid encoding"
                let bad = Array.copy good
                bad[8] <- 13uy
                Expect.isError (deserialize schema bad) "offset 13 instead of 12"
            }

            testProp "AttestationData round trip"
            <| fun (slot: uint64) (index: uint64) (e1: uint64) (e2: uint64) (seed: byte) ->
                let r n = Root.Of(Array.init 32 (fun i -> byte i ^^^ seed ^^^ byte n))

                let d =
                    {
                        Slot = slot
                        Index = index
                        BeaconBlockRoot = r 1
                        Source = { Epoch = e1; Root = r 2 }
                        Target = { Epoch = e2; Root = r 3 }
                    }

                let bytes = serialize Schemas.attestationData (Codec.attestationDataValue d)

                bytes.Length = 128
                && (match deserialize Schemas.attestationData bytes with
                    | Ok v -> Codec.attestationDataOf v = d
                    | Error _ -> false)
        ]
