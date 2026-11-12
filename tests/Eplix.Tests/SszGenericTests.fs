/// consensus-spec-tests v1.6.1 ssz_generic (general.tar.gz, phase0): every valid case decodes,
/// encodes back to the same bytes and has the given root; every invalid case is an Error. The
/// codec reads untrusted SSZ from beacon nodes and remote signers. tests/vectors/ssz_generic holds
/// the cases up to 32 KiB; EPLIX_SSZ_GENERIC=<dir of ssz_generic> runs a whole unpacked release.
module Eplix.Tests.SszGenericTests

open System
open System.IO
open Expecto
open Eplix
open Eplix.Ssz
open Eplix.Tests.TestUtil

let private uintOf (bits: string) =
    match bits with
    | "8" -> ValueSome(Uint 1)
    | "16" -> ValueSome(Uint 2)
    | "32" -> ValueSome(Uint 4)
    | "64" -> ValueSome(Uint 8)
    | "256" -> ValueSome Uint256
    | _ -> ValueNone

let private basicOf (name: string) =
    match name with
    | "bool" -> ValueSome Boolean
    | n when n.StartsWith "uint" -> uintOf (n.Substring 4)
    | _ -> ValueNone

// The test containers of the ssz_generic generator (consensus-specs v1.6.1,
// tests/generators/ssz_generic). The valid cases' roots check these definitions.
let private small = Container [| "A", Uint 2; "B", Uint 2 |]
let private fixedStruct = Container [| "A", Uint 1; "B", Uint 8; "C", Uint 4 |]
let private varStruct = Container [| "A", Uint 2; "B", List(Uint 2, 1024); "C", Uint 1 |]

let private containers =
    Map.ofList
        [
            "SingleFieldTestStruct", Container [| "A", Uint 1 |]
            "SmallTestStruct", small
            "FixedTestStruct", fixedStruct
            "VarTestStruct", varStruct
            "ComplexTestStruct",
            Container
                [|
                    "A", Uint 2
                    "B", List(Uint 2, 128)
                    "C", Uint 1
                    "D", ByteList 256
                    "E", varStruct
                    "F", Vector(fixedStruct, 4)
                    "G", Vector(varStruct, 2)
                |]
            "BitsStruct",
            Container
                [|
                    "A", Bitlist 5
                    "B", Bitvector 2
                    "C", Bitvector 1
                    "D", Bitlist 6
                    "E", Bitvector 8
                |]
            "ProgressiveTestStruct",
            Container
                [|
                    "A", ProgressiveList(Uint 1)
                    "B", ProgressiveList(Uint 8)
                    "C", ProgressiveList small
                    "D", ProgressiveList(ProgressiveList varStruct)
                |]
            "ProgressiveBitsStruct",
            Container
                [|
                    "A", Bitvector 256
                    "B", Bitlist 256
                    "C", ProgressiveBitlist
                    "D", Bitvector 257
                    "E", Bitlist 257
                    "F", ProgressiveBitlist
                    "G", Bitvector 1280
                    "H", Bitlist 1280
                    "I", ProgressiveBitlist
                    "J", Bitvector 1281
                    "K", Bitlist 1281
                    "L", ProgressiveBitlist
                |]
            // active_fields [1]: every field active, the only form Eplix's ProgressiveContainer has.
            "ProgressiveSingleFieldContainerTestStruct", ProgressiveContainer [| "A", Uint 1 |]
        ]

/// Types Eplix's codec does not have, and why. The test fails if any other case has no type.
let private unsupported =
    Map.ofList
        [
            "uint128", "no uint128 in any container Eplix reads"
            "CompatibleUnion", "no CompatibleUnion in any container Eplix reads"
            "ProgressiveContainer with inactive fields",
            "Eplix's ProgressiveContainer has every field active (Gloas uses no other)"
        ]

type private Mapped =
    | Type of SszType
    | Unsupported of string
    /// A type the spec itself forbids (a Vector or Bitvector of length 0): any input is invalid.
    | IllegalType

/// The type of a case from its handler and name.
let private typeOf (handler: string) (case: string) : Mapped =
    let parts = case.Split '_'

    let num (s: string) =
        Int32.TryParse s
        |> function
            | true, n -> ValueSome n
            | _ -> ValueNone

    match handler with
    | "uints" ->
        if parts[1] = "128" then
            Unsupported "uint128"
        else
            match uintOf parts[1] with
            | ValueSome t -> Type t
            | ValueNone -> failwithf "uint %s" case
    | "boolean" -> Type Boolean
    | "bitvector" ->
        match num parts[1] with
        | ValueSome 0 -> IllegalType
        | ValueSome n -> Type(Bitvector n)
        | ValueNone -> failwithf "bitvector %s" case
    | "bitlist" ->
        match num parts[1] with
        | ValueSome n -> Type(Bitlist n)
        | ValueNone -> failwithf "bitlist %s" case
    | "basic_vector" ->
        match parts[1], num parts[2] with
        | "uint128", _ -> Unsupported "uint128"
        | _, ValueSome 0 -> IllegalType
        | e, ValueSome n ->
            match basicOf e with
            | ValueSome t -> Type(Vector(t, n))
            | ValueNone -> failwithf "vector %s" case
        | _ -> failwithf "vector %s" case
    | "basic_progressive_list" ->
        match parts[1] with
        | "uint128" -> Unsupported "uint128"
        | e ->
            match basicOf e with
            | ValueSome t -> Type(ProgressiveList t)
            | ValueNone -> failwithf "progressive list %s" case
    | "progressive_bitlist" -> Type ProgressiveBitlist
    | "compatible_unions" -> Unsupported "CompatibleUnion"
    | "containers"
    | "progressive_containers" ->
        match containers.TryFind parts[0] with
        | Some t -> Type t
        | None when parts[0].StartsWith "Progressive" -> Unsupported "ProgressiveContainer with inactive fields"
        | None -> failwithf "no definition for container %s" parts[0]
    | h -> failwithf "unknown handler %s" h

let private readMetaRoot (file: string) =
    let line = File.ReadAllLines file |> Array.find (fun l -> l.StartsWith "root:")
    line.Substring(line.IndexOf("0x")).TrimEnd('\'', '"')

let private casesIn (root: string) =
    [
        for handlerDir in Directory.GetDirectories root |> Array.sort do
            let handler = Path.GetFileName handlerDir

            for validity in [ "valid"; "invalid" ] do
                let dir = Path.Combine(handlerDir, validity)

                if Directory.Exists dir then
                    for caseDir in Directory.GetDirectories dir |> Array.sort do
                        handler, validity = "valid", caseDir
    ]

/// The roots of progressive types in v1.6.1 predate the merkleization of EIP-7495/7916 that
/// consensus-specs v1.7.0 (and Eplix, checked by the Gloas ssz_static cases) use. For these types
/// the v1.6.1 cases check encoding and refusal only; ssz-specs v0.1.0 checks the current roots.
let rec private hasProgressive (t: SszType) =
    match t with
    | ProgressiveList _
    | ProgressiveByteList
    | ProgressiveBitlist
    | ProgressiveContainer _ -> true
    | Vector(e, _)
    | List(e, _) -> hasProgressive e
    | Container fields -> fields |> Array.exists (snd >> hasProgressive)
    | _ -> false

let private caseTest (handler: string) (valid: bool) (caseDir: string) =
    let case = Path.GetFileName caseDir

    test $"""{handler}/{(if valid then "valid" else "invalid")}/{case}""" {
        let bytes = Snappy.decompress (File.ReadAllBytes(Path.Combine(caseDir, "serialized.ssz_snappy")))

        match typeOf handler case with
        | Unsupported _ -> ()
        | IllegalType -> Expect.isFalse valid "a zero-length vector type has no valid case"
        | Type t ->
            match deserialize t bytes, valid with
            | Ok v, true ->
                Expect.equal (serialize t v) bytes "re-encoding gives the same bytes"

                if not (hasProgressive t) then
                    Expect.equal
                        (Hex.encodeArray (hashTreeRoot t v))
                        (readMetaRoot (Path.Combine(caseDir, "meta.yaml")))
                        "hash_tree_root"
            | Error e, true -> failtestf "a valid case failed to decode: %s" e
            | Ok _, false -> failtest "an invalid case decoded"
            | Error _, false -> ()
    }

/// Every case maps to a type, or to one of the documented unsupported types.
let private coverage (root: string) =
    test "every case has a type or a documented reason" {
        let reasons =
            casesIn root
            |> List.choose (fun (h, _, d) ->
                match typeOf h (Path.GetFileName d) with
                | Unsupported why -> Some why
                | _ -> None)
            |> List.distinct
            |> List.sort

        Expect.equal reasons (unsupported |> Map.toList |> List.map fst |> List.sort) "unsupported types"
    }

let private suite (root: string) =
    if not (Directory.Exists root) then
        [ test "vectors present" { failtestf "%s is missing" root } ]
    else
        let cases = casesIn root

        [
            coverage root
            yield!
                cases
                |> List.groupBy (fun (h, _, _) -> h)
                |> List.map (fun (h, cs) -> testList h [ for _, valid, d in cs -> caseTest h valid d ])
        ]

// ---- ethereum/ssz-specs v0.1.0 (the successor of ssz_generic, current EIP-7495/7916) ----

/// tests/vectors/.download/ssz-specs (scripts/fetch-test-vectors.sh; MIT, not committed), or
/// EPLIX_SSZ_SPECS_DIR.
let private sszSpecsDir =
    match Environment.GetEnvironmentVariable "EPLIX_SSZ_SPECS_DIR" with
    | null
    | "" -> Path.Combine(vectors, ".download", "ssz-specs")
    | d -> d

let private sszSpecsFiles = 117

/// The fixtures name their types only; these are the types from the fixtures' descriptions and
/// sizes, which the roots confirm. Keyed by test file directory and type name (one name means
/// different types in two files).
let private sszSpecsTypes =
    let square = "a progressive container with a gap"

    Map.ofList
        [
            ("test_basic_types", "Boolean"), Type Boolean
            ("test_basic_types", "Uint8"), Type(Uint 1)
            ("test_basic_types", "Uint16"), Type(Uint 2)
            ("test_basic_types", "Uint32"), Type(Uint 4)
            ("test_basic_types", "Uint64"), Type(Uint 8)
            ("test_basic_types", "Uint128"), Unsupported "uint128"
            ("test_basic_types", "Uint256"), Type Uint256
            ("test_basic_types", "Bytes4"), Type(ByteVector 4)
            ("test_basic_types", "Bytes32"), Type(ByteVector 32)
            ("test_basic_types", "Bytes52"), Type(ByteVector 52)
            ("test_basic_types", "Bytes64"), Type(ByteVector 64)
            ("test_basic_types", "ByteList512KiB"), Type(ByteList(512 * 1024))
            ("test_basic_types", "SampleBitList16"), Type(Bitlist 16)
            ("test_basic_types", "SampleBitVector8"), Type(Bitvector 8)
            ("test_basic_types", "SampleBitVector64"), Type(Bitvector 64)
            ("test_basic_types", "SampleBytes32List8"), Type(List(ByteVector 32, 8))
            ("test_basic_types", "SampleUint16Vector3"), Type(Vector(Uint 2, 3))
            ("test_basic_types", "SampleUint32List16"), Type(List(Uint 4, 16))
            ("test_basic_types", "SampleUint64Vector4"), Type(Vector(Uint 8, 4))
            ("test_decode_failure_smoke", "SmokeBitList8"), Type(Bitlist 8)
            ("test_merkleization_boundaries", "BoundaryBitList256"), Type(Bitlist 256)
            ("test_merkleization_boundaries", "BoundaryBitVector1"), Type(Bitvector 1)
            ("test_merkleization_boundaries", "BoundaryBitVector7"), Type(Bitvector 7)
            ("test_merkleization_boundaries", "BoundaryBitVector9"), Type(Bitvector 9)
            ("test_merkleization_boundaries", "BoundaryBitVector255"), Type(Bitvector 255)
            ("test_merkleization_boundaries", "BoundaryBitVector256"), Type(Bitvector 256)
            ("test_merkleization_boundaries", "BoundaryBitVector257"), Type(Bitvector 257)
            ("test_merkleization_boundaries", "BoundaryUint64List32"), Type(List(Uint 8, 32))
            ("test_progressive_types", "ProgressiveBitList"), Type ProgressiveBitlist
            ("test_progressive_types", "SampleUint64ProgressiveList"), Type(ProgressiveList(Uint 8))
            ("test_progressive_types", "SampleBytes32ProgressiveList"), Type(ProgressiveList(ByteVector 32))
            ("test_progressive_types", "SampleNestedProgressiveList"), Type(ProgressiveList(ProgressiveList(Uint 2)))
            ("test_progressive_types", "SampleContainerWithProgressiveList"),
            Type(Container [| "a", Uint 2; "b", ProgressiveList(Uint 8); "c", Uint 1 |])
            ("test_progressive_containers", "SampleOneField"), Type(ProgressiveContainer [| "a", Uint 2 |])
            ("test_progressive_containers", "SampleProgressiveFields"),
            Type(
                ProgressiveContainer
                    [|
                        "head", Uint 8
                        "numbers", ProgressiveList(Uint 8)
                        "flags", ProgressiveBitlist
                    |]
            )
            for name in
                [
                    "SampleSquare"
                    "SampleCircle"
                    "SampleLeadingGaps"
                    "SampleMultipleGaps"
                    "SampleLevelBoundary"
                    "SampleWidestLayout"
                    "SampleBoundedListField"
                    "SampleOuterShape"
                    "SampleShapeContainer"
                    "SampleSquareProgressiveList"
                ] do
                ("test_progressive_containers", name), Unsupported square
        ]

let private sszSpecsCase (dir: string) (file: string) =
    let name = Path.GetFileNameWithoutExtension file

    test $"{dir}/{name}" {
        use doc = Text.Json.JsonDocument.Parse(File.ReadAllText file)
        let case = (doc.RootElement.EnumerateObject() |> Seq.head).Value
        let typeName = case.GetProperty("typeName").GetString()

        let reject =
            match case.TryGetProperty "rejectionReason" with
            | true, r -> Some(r.GetString())
            | _ -> None

        let mapped =
            if dir = "test_compatible_unions" then
                Unsupported "CompatibleUnion"
            else
                match sszSpecsTypes.TryFind(dir, typeName) with
                | Some m -> m
                | None -> failtestf "no type for %s in %s" typeName dir

        match mapped, reject with
        | Unsupported _, _ -> ()
        | IllegalType, _ -> ()
        | Type t, Some why ->
            let raw = hex (case.GetProperty("rawBytes").GetString())
            Expect.isError (deserialize t raw) $"decoding is refused ({why})"
        | Type t, None ->
            let bytes = hex (case.GetProperty("serialized").GetString())

            match deserialize t bytes with
            | Error e -> failtestf "decode failed: %s" e
            | Ok v ->
                Expect.equal (serialize t v) bytes "re-encoding gives the same bytes"

                Expect.equal
                    (Hex.encodeArray (hashTreeRoot t v))
                    (case.GetProperty("root").GetString())
                    "hash_tree_root"
    }

let private sszSpecsSuite () =
    let files =
        if Directory.Exists sszSpecsDir then
            Directory.GetFiles(sszSpecsDir, "*.json", SearchOption.AllDirectories) |> Array.sort
        else
            [||]

    if files.Length <> sszSpecsFiles then
        [
            test "vectors present" {
                failtestf
                    "%s holds %d of the %d ssz-specs v0.1.0 fixtures; run scripts/fetch-test-vectors.sh"
                    sszSpecsDir
                    files.Length
                    sszSpecsFiles
            }
        ]
    else
        [
            for dir, fs in files |> Array.groupBy (fun f -> Path.GetFileName(Path.GetDirectoryName f)) ->
                testList dir [ for f in fs -> sszSpecsCase dir f ]
        ]

[<Tests>]
let tests =
    testList
        "ssz"
        [
            testList
                "ssz_generic v1.6.1"
                [
                    yield! suite (Path.Combine(vectors, "ssz_generic"))
                    match Environment.GetEnvironmentVariable "EPLIX_SSZ_GENERIC" with
                    | null
                    | "" -> ()
                    | full -> yield testList "full" (suite full)
                ]
            testList "ssz-specs v0.1.0" (sszSpecsSuite ())
        ]
