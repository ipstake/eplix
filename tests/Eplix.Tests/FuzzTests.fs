/// Fuzz campaign: property tests that feed random and mutated input to the
/// decoders that read data from outside the VC. Each decoder must answer Ok or Error, never
/// throw, and must round-trip where a round trip is defined:
/// - SSZ: every container schema, from random bytes, from mutated consensus-spec-tests vectors and
///   from generated values; a decoded value encodes back to the same bytes (the codec is strict)
///   and its JSON form decodes to the same value.
/// - Beacon API JSON decoders: random JSON and structural mutations of the recorded responses.
/// - EIP-2335 keystores: parsing of random and mutated keystores; decryption of mutated keystores
///   either fails or gives the original secret.
/// - EIP-3076 interchange: parsing of random and mutated files; a parsed file imports into the
///   slashing DB, exports and imports again to the same marks, and survives a reopen.
/// - Config files: eplix.json through Config.parse and every module's Configure, config.yaml,
///   the proposer config, switches.json and header files.
/// EPLIX_FUZZ_CASES sets the cases per property (default 200).
module Eplix.Tests.FuzzTests

open System
open System.Collections.Generic
open System.IO
open System.Text
open System.Text.Json
open Expecto
open FsCheck
open FsCheck.FSharp
open Eplix
open Eplix.Ssz
open Eplix.Backend.Local
open Eplix.Slashing
open Eplix.Tests.TestUtil

let cases = fuzzCases

/// Time one case may take before it counts as a hang.
let private caseTimeout = TimeSpan.FromSeconds 5.0

let private show (x: obj) =
    match x with
    | :? (byte[]) as b -> Encoding.UTF8.GetString b
    | _ -> sprintf "%A" x

// FsCheck's console runner also writes a progress counter with backspaces after every case, and
// Expecto's ANSI console writer slows down with each write: 2,000 cases took a second, 200,000 did
// not finish in 2 hours. The fuzz properties use TestUtil.quietThrowingRunner, which writes nothing.

/// Runs a property over `cases` generated inputs; a throw is a failure, with FsCheck's seed and
/// the input. A watchdog prints the input and stops the process when one case runs longer than
/// caseTimeout, so a hang shows its input instead of stalling the run.
let private fuzz name (gen: Gen<'T>) (body: 'T -> unit) =
    test $"{name} ({cases} cases)" {
        let started = ref DateTime.MaxValue
        let current = ref (box ())

        use _watchdog =
            new Threading.Timer(
                (fun _ ->
                    let t = started.Value

                    if t <> DateTime.MaxValue && DateTime.UtcNow - t > caseTimeout then
                        eprintfn
                            "%s: one case ran more than %.0f s (a hang); input:\n%s"
                            name
                            caseTimeout.TotalSeconds
                            (show current.Value)

                        Environment.Exit 3),
                null,
                1000,
                1000
            )

        let config =
            fuzzReplay (Config.QuickThrowOnFailure.WithMaxTest(cases).WithEndSize(200).WithRunner(quietThrowingRunner))

        Check.One(
            config,
            Prop.forAll (Arb.fromGen gen) (fun x ->
                current.Value <- box x
                started.Value <- DateTime.UtcNow
                body x
                started.Value <- DateTime.MaxValue
                true)
        )
    }

// ---- Generators ----

let private genByte = Gen.choose (0, 255) |> Gen.map byte
let private genBytes n = Gen.arrayOfLength n genByte

let private genU64 =
    Gen.frequency
        [
            3,
            Gen.elements
                [
                    0UL
                    1UL
                    2UL
                    31UL
                    32UL
                    255UL
                    256UL
                    65535UL
                    uint64 Int32.MaxValue
                    uint64 UInt32.MaxValue
                    UInt64.MaxValue - 1UL
                    UInt64.MaxValue
                ]
            // Any 64-bit value, from four 16-bit draws.
            5,
            Gen.collectToArray id [| for _ in 1..4 -> Gen.choose (0, 65535) |]
            |> Gen.map (Array.fold (fun acc (x: int) -> (acc <<< 16) ||| uint64 x) 0UL)
            2, Gen.choose (0, 1000) |> Gen.map uint64
        ]

/// A value that fits the schema; lists are kept short so nested schemas stay small.
let rec genValue (t: SszType) : Gen<SszValue> =
    match t with
    | Uint n -> genU64 |> Gen.map (fun x -> U(if n >= 8 then x else x &&& ((1UL <<< (8 * n)) - 1UL)))
    | Uint256 -> genBytes 32 |> Gen.map Bytes
    | Boolean -> Gen.elements [ true; false ] |> Gen.map Bool
    | ByteVector n -> genBytes n |> Gen.map Bytes
    | ByteList n -> Gen.choose (0, min n 64) |> Gen.bind genBytes |> Gen.map Bytes
    | Bitvector n -> Gen.arrayOfLength n (Gen.elements [ true; false ]) |> Gen.map Bits
    | Bitlist n ->
        Gen.choose (0, min n 80)
        |> Gen.bind (fun k -> Gen.arrayOfLength k (Gen.elements [ true; false ]))
        |> Gen.map Bits
    | Vector(e, n) -> Gen.arrayOfLength n (genValue e) |> Gen.map Items
    | List(e, n) ->
        let most =
            match e with
            | Uint _
            | Boolean -> 16
            | _ -> 2

        Gen.choose (0, min n most) |> Gen.bind (fun k -> Gen.arrayOfLength k (genValue e)) |> Gen.map Items
    | Container fields
    | ProgressiveContainer fields -> fields |> Array.map (snd >> genValue) |> Gen.collectToArray id |> Gen.map Fields
    | ProgressiveList e ->
        let most =
            match e with
            | Uint _
            | Boolean -> 16
            | _ -> 2

        Gen.choose (0, most) |> Gen.bind (fun k -> Gen.arrayOfLength k (genValue e)) |> Gen.map Items
    | ProgressiveByteList -> Gen.choose (0, 64) |> Gen.bind genBytes |> Gen.map Bytes
    | ProgressiveBitlist ->
        Gen.choose (0, 80)
        |> Gen.bind (fun k -> Gen.arrayOfLength k (Gen.elements [ true; false ]))
        |> Gen.map Bits

/// Byte-level mutations: bit flips, random bytes, inserts, deletes, truncation, and 4-byte
/// little-endian values at random places (SSZ offsets are 4 bytes).
let private mutateBytes (input: byte[]) : Gen<byte[]> =
    let one (b: byte[]) : Gen<byte[]> =
        let len = b.Length
        let at = if len = 0 then Gen.constant 0 else Gen.choose (0, len - 1)

        let offsetValues =
            [
                0u
                1u
                4u
                uint32 len
                uint32 (max 0 (len - 1))
                uint32 (len + 1)
                uint32 (max 0 (len - 4))
                0x7FFFFFFFu
                0x80000000u
                UInt32.MaxValue
            ]

        Gen.oneof
            [
                (if len = 0 then
                     Gen.constant b
                 else
                     Gen.map2
                         (fun i (bit: int) ->
                             let c = Array.copy b in
                             c[i] <- c[i] ^^^ (1uy <<< bit)
                             c)
                         at
                         (Gen.choose (0, 7)))
                (if len = 0 then
                     Gen.constant b
                 else
                     Gen.map2
                         (fun i v ->
                             let c = Array.copy b in
                             c[i] <- v
                             c)
                         at
                         genByte)
                Gen.map2
                    (fun i (ins: byte[]) -> Array.concat [ b[.. i - 1]; ins; b[i..] ])
                    (Gen.choose (0, len))
                    (Gen.choose (1, 8) |> Gen.bind genBytes)
                (if len = 0 then
                     Gen.constant b
                 else
                     Gen.map2 (fun i n -> Array.append b[.. i - 1] b[min len (i + n) ..]) at (Gen.choose (1, 8)))
                (if len = 0 then Gen.constant b else Gen.choose (0, len - 1) |> Gen.map (fun n -> b[.. n - 1]))
                (if len < 4 then
                     Gen.constant b
                 else
                     Gen.map2
                         (fun i (v: uint32) ->
                             let c = Array.copy b
                             Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Span(c, i, 4), v)
                             c)
                         (Gen.choose (0, len - 4))
                         (Gen.elements offsetValues))
            ]

    Gen.choose (1, 6)
    |> Gen.bind (fun n ->
        let rec go k (acc: Gen<byte[]>) = if k = 0 then acc else go (k - 1) (acc |> Gen.bind one)
        go n (Gen.constant input))

// ---- A small JSON tree for structural mutations ----

type J =
    | JNull
    | JBool of bool
    | JNum of string
    | JStr of string
    | JArr of J list
    | JObj of (string * J) list

let rec private ofElement (e: JsonElement) =
    match e.ValueKind with
    | JsonValueKind.Object -> JObj [ for p in e.EnumerateObject() -> p.Name, ofElement p.Value ]
    | JsonValueKind.Array -> JArr [ for x in e.EnumerateArray() -> ofElement x ]
    | JsonValueKind.String -> JStr(e.GetString())
    | JsonValueKind.Number -> JNum(e.GetRawText())
    | JsonValueKind.True -> JBool true
    | JsonValueKind.False -> JBool false
    | _ -> JNull

let private parseJ (text: string) =
    use d = JsonDocument.Parse text
    ofElement d.RootElement

let rec private writeJ (w: Utf8JsonWriter) (j: J) =
    match j with
    | JNull -> w.WriteNullValue()
    | JBool b -> w.WriteBooleanValue b
    | JNum n -> w.WriteRawValue n
    | JStr s -> w.WriteStringValue s
    | JArr xs ->
        w.WriteStartArray()

        for x in xs do
            writeJ w x

        w.WriteEndArray()
    | JObj ps ->
        w.WriteStartObject()

        for k, v in ps do
            w.WritePropertyName k
            writeJ w v

        w.WriteEndObject()

let private bytesOfJ (j: J) = Json.toBytes (fun w -> writeJ w j)

/// Field names the decoders look for, so random objects reach past the first `prop`.
let private knownNames =
    [
        "data"
        "metadata"
        "index"
        "validator_index"
        "pubkey"
        "slot"
        "epoch"
        "root"
        "block"
        "state"
        "status"
        "validator"
        "balance"
        "is_live"
        "dependent_root"
        "execution_optimistic"
        "genesis_time"
        "genesis_validators_root"
        "genesis_fork_version"
        "previous_version"
        "current_version"
        "committee_index"
        "committee_length"
        "committees_at_slot"
        "validator_committee_index"
        "beacon_block_root"
        "source"
        "target"
        "head_slot"
        "sync_distance"
        "is_syncing"
        "is_optimistic"
        "el_offline"
        "validator_sync_committee_indices"
        "message"
        "code"
        "failures"
        "version"
        "crypto"
        "kdf"
        "function"
        "params"
        "n"
        "r"
        "p"
        "c"
        "dklen"
        "salt"
        "prf"
        "checksum"
        "cipher"
        "iv"
        "path"
        "uuid"
        "interchange_format_version"
        "signed_blocks"
        "signed_attestations"
        "source_epoch"
        "target_epoch"
        "signing_root"
        "previous_duty_dependent_root"
        "current_duty_dependent_root"
        "epoch_transition"
    ]

let private interestingStrings =
    [
        ""
        "0"
        "1"
        "-1"
        "18446744073709551615"
        "18446744073709551616"
        "4294967296"
        "2147483648"
        "1e3"
        " 1"
        "0x"
        "0x0"
        "0x00"
        "0X00"
        "0xzz"
        "0x" + String('0', 64)
        "0x" + String('f', 96)
        "0x" + String('a', 192)
        "0x" + String('0', 8)
        "head"
        "active_ongoing"
        "pending_queued"
        "hmac-sha256"
        "sha256"
        "aes-128-ctr"
        "scrypt"
        "pbkdf2"
        "5"
        "\u0000"
        "é"
    ]

let private genJ: Gen<J> =
    let scalar =
        Gen.oneof
            [
                Gen.constant JNull
                Gen.elements [ true; false ] |> Gen.map JBool
                Gen.elements
                    [
                        "0"
                        "1"
                        "-1"
                        "1.5"
                        "1e400"
                        "18446744073709551615"
                        "18446744073709551616"
                        "-0"
                        "4294967296"
                    ]
                |> Gen.map JNum
                Gen.elements interestingStrings |> Gen.map JStr
            ]

    let rec tree depth =
        if depth = 0 then
            scalar
        else
            Gen.frequency
                [
                    3, scalar
                    2, Gen.choose (0, 4) |> Gen.bind (fun n -> Gen.listOfLength n (tree (depth - 1))) |> Gen.map JArr
                    3,
                    Gen.choose (0, 5)
                    |> Gen.bind (fun n -> Gen.listOfLength n (Gen.zip (Gen.elements knownNames) (tree (depth - 1))))
                    |> Gen.map JObj
                ]

    tree 5

/// Structural mutations: replace a node with a random one, drop or duplicate a field, empty an
/// array, wrap a node in an array.
let rec private mutateJ (j: J) : Gen<J> =
    match j with
    | JObj ps when not ps.IsEmpty ->
        Gen.choose (0, ps.Length - 1)
        |> Gen.bind (fun i ->
            let k, v = ps[i]

            Gen.frequency
                [
                    4, mutateJ v |> Gen.map (fun v2 -> JObj(List.updateAt i (k, v2) ps))
                    1, Gen.constant (JObj(List.removeAt i ps))
                    1, Gen.constant (JObj(ps @ [ k, v ]))
                    1, genJ
                ])
    | JArr xs when not xs.IsEmpty ->
        Gen.choose (0, xs.Length - 1)
        |> Gen.bind (fun i ->
            Gen.frequency
                [
                    4, mutateJ xs[i] |> Gen.map (fun v2 -> JArr(List.updateAt i v2 xs))
                    1, Gen.constant (JArr [])
                    1, Gen.constant (JArr(xs @ xs))
                    1, genJ
                ])
    | other -> Gen.frequency [ 3, genJ; 1, Gen.constant (JArr [ other ]) ]

let private mutateJMany (j: J) =
    Gen.choose (1, 4)
    |> Gen.bind (fun n ->
        let rec go k (acc: Gen<J>) = if k = 0 then acc else go (k - 1) (acc |> Gen.bind mutateJ)
        go n (Gen.constant j))

/// Random JSON, structural mutations of the seeds, and byte mutations of the seeds.
let private genJsonInput (seeds: J list) : Gen<byte[]> =
    Gen.frequency
        [
            2, genJ |> Gen.map bytesOfJ
            5, Gen.elements seeds |> Gen.bind mutateJMany |> Gen.map bytesOfJ
            1, Gen.elements seeds |> Gen.map bytesOfJ |> Gen.bind mutateBytes
        ]

let private decodeNoThrow (decoder: JsonElement -> 'T) (bytes: byte[]) : Result<'T, string> =
    try
        Json.decode decoder (ReadOnlyMemory bytes)
    with e ->
        failwithf "decoder threw %s: %s\ninput: %s" (e.GetType().Name) e.Message (Encoding.UTF8.GetString bytes)

// ---- SSZ ----

let private schemas =
    [
        for KeyValue(name, t) in Schemas.byName Preset.Minimal -> $"minimal {name}", t
    ]
    @ [
        for KeyValue(name, t) in Schemas.Gloas.byName Preset.Minimal -> $"gloas minimal {name}", t
    ]
    @ [
        "mainnet BeaconBlockBody", Schemas.beaconBlockBody Preset.Mainnet
        "mainnet SignedBlockContents", Schemas.signedBlockContents Preset.Mainnet
        "mainnet Attestation", Schemas.attestation Preset.Mainnet
    ]

/// Decodes; if the bytes decode, they must be canonical and the value must hash and go through JSON.
let private checkSsz (t: SszType) (bytes: byte[]) =
    let fail' (what: string) = failwithf "%s\ninput: %s" what (Convert.ToHexString bytes)

    let decoded =
        try
            deserialize t bytes
        with e ->
            fail' $"deserialize threw {e.GetType().Name}: {e.Message}"

    match decoded with
    | Error _ -> ()
    | Ok v ->
        let again = serialize t v

        if again <> bytes then
            fail' "decoded value encodes to other bytes (non-canonical input accepted)"

        hashTreeRoot t v |> ignore
        let json = SszJson.toBytes t v

        match Json.decode (SszJson.read t) (ReadOnlyMemory json) with
        | Ok v2 when v2 = v -> ()
        | Ok _ -> fail' "JSON round trip changed the value"
        | Error e -> fail' $"JSON round trip failed: {e}"

let private vectorSeeds =
    lazy
        (let dir = Path.Combine(vectors, "ssz_static")
         let minimal = Schemas.byName Preset.Minimal

         [
             for containerDir in Directory.GetDirectories dir do
                 let name = Path.GetFileName containerDir

                 match minimal.TryFind name with
                 | Some t ->
                     for f in
                         Directory.GetFiles(containerDir, "serialized.ssz_snappy", SearchOption.AllDirectories)
                         |> Array.truncate 3 do
                         name, t, Snappy.decompress (File.ReadAllBytes f)
                 | None -> ()
         ])

let private sszTests =
    [
        for name, t in schemas do
            fuzz $"{name}: random bytes" (Gen.choose (0, 300) |> Gen.bind genBytes) (checkSsz t)

            fuzz $"{name}: generated values round trip" (genValue t) (fun v ->
                let bytes = serialize t v

                match deserialize t bytes with
                | Ok v2 when v2 = v -> checkSsz t bytes
                | Ok _ -> failwithf "round trip changed the value: %s" (Convert.ToHexString bytes)
                | Error e -> failwithf "own encoding refused: %s: %s" e (Convert.ToHexString bytes))

            fuzz $"{name}: mutated encodings" (genValue t |> Gen.map (serialize t) |> Gen.bind mutateBytes) (checkSsz t)
        fuzz
            "mutated consensus-spec-tests vectors"
            (Gen.delay (fun () -> Gen.elements (vectorSeeds.Force()))
             |> Gen.bind (fun (n, t, b) -> mutateBytes b |> Gen.map (fun m -> n, t, m)))
            (fun (_, t, bytes) -> checkSsz t bytes)
        fuzz
            "JSON form: random and mutated JSON"
            (Gen.zip
                (Gen.elements schemas)
                (Gen.oneof
                    [
                        genJ |> Gen.map bytesOfJ
                        Gen.elements schemas
                        |> Gen.bind (fun (_, t) ->
                            genValue t |> Gen.map (fun v -> parseJ (Encoding.UTF8.GetString(SszJson.toBytes t v))))
                        |> Gen.bind mutateJMany
                        |> Gen.map bytesOfJ
                    ]))
            (fun ((_, t), bytes) ->
                match decodeNoThrow (SszJson.read t) bytes with
                | Ok v ->
                    // What JSON accepts must be a value the schema can encode.
                    let b =
                        try
                            serialize t v
                        with e ->
                            failwithf
                                "JSON gave a value the schema cannot encode (%s): %s"
                                e.Message
                                (Encoding.UTF8.GetString bytes)

                    match deserialize t b with
                    | Ok v2 when v2 = v -> ()
                    | _ -> failwithf "JSON gave a value that does not round-trip: %s" (Encoding.UTF8.GetString bytes)
                | Error _ -> ())
    ]

// ---- Beacon API JSON ----

let private beaconSeeds =
    lazy
        ([
            for f in Directory.GetFiles(Path.Combine(fixtures, "beacon"), "*.json") -> parseJ (File.ReadAllText f)
         ]
         @ [
             parseJ """{"data":[{"index":"1","is_live":true},{"index":"2","is_live":false}]}"""
             parseJ (
                 """{"data":[{"validator_index":"1","slot":"2","subcommittee_index":"0","selection_proof":"0x"""
                 + String('a', 192)
                 + "\"}]}"
             )
             parseJ
                 """{"slot":"10","block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf","state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9","epoch_transition":false,"previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91","current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91","execution_optimistic":false}"""
         ])

let private beaconDecoders: (string * (byte[] -> bool)) list =
    let d name (f: JsonElement -> 'T) = name, (fun b -> decodeNoThrow f b |> Result.isOk)

    [
        d "genesis" Beacon.Decoders.genesis
        d "spec" Beacon.Decoders.spec
        d "fork" Beacon.Decoders.fork
        d "validators" Beacon.Decoders.validators
        d "attesterDuties" Beacon.Decoders.attesterDuties
        d "proposerDuties" Beacon.Decoders.proposerDuties
        d "attestationData" Beacon.Decoders.attestationData
        d "syncDuties" Beacon.Decoders.syncDuties
        d "blockRoot" Beacon.Decoders.blockRoot
        d "syncing" Beacon.Decoders.syncing
        d "liveness" Beacon.Decoders.liveness
        d "headEvent head" (Beacon.Decoders.headEvent "head")
        d "headEvent head_v2" (Beacon.Decoders.headEvent "head_v2")
        d "error" Beacon.Decoders.error
        d "beaconCommitteeSelections" Obol.Selections.decodeBeaconCommittee
        d "syncCommitteeSelections" Obol.Selections.decodeSyncCommittee
    ]

let private beaconTests =
    [
        fuzz
            "decoders: random and mutated responses"
            (Gen.zip (Gen.elements beaconDecoders) (Gen.delay (fun () -> genJsonInput (beaconSeeds.Force()))))
            (fun ((_, decode), bytes) -> decode bytes |> ignore)
        test "the seeds decode" {
            let seeds = beaconSeeds.Force() |> List.map bytesOfJ
            // No recorded response for sync duties, head roots and head_v2.
            let recorded =
                beaconDecoders
                |> List.filter (fun (n, _) -> n <> "syncDuties" && n <> "blockRoot" && n <> "headEvent head_v2")

            for name, decode in recorded do
                Expect.isTrue (seeds |> List.exists decode) $"no seed decodes with {name}"
        }
    ]

// ---- EIP-2335 keystores ----

let private keystoreSeeds =
    lazy
        ([
            for f in [ "eip2335/pbkdf2.json"; "eip2335/scrypt.json" ] ->
                parseJ (File.ReadAllText(Path.Combine(fixtures, f)))
         ]
         @ [
             for f in Directory.GetFiles(Path.Combine(fixtures, "layouts"), "*.json", SearchOption.AllDirectories) do
                 if (Path.GetFileName f).Contains "keystore" then
                     parseJ (File.ReadAllText f)
         ])

/// A cheap keystore (PBKDF2 with c = 2) for decryption fuzzing.
let private cheapSecret =
    Array.init 32 (fun i ->
        if i = 31 then 7uy
        elif i = 0 then 0x1Fuy
        else byte i)

let private cheapKeystore =
    lazy (Keystore.encrypt cheapSecret "pw" (Keystore.Pbkdf2(2, Array.create 32 1uy, 32)) "m/12381/3600/0/0/0")

let rec private setField (name: string) (value: J) (j: J) =
    match j with
    | JObj ps -> JObj [ for k, v in ps -> k, (if k = name then value else setField name value v) ]
    | JArr xs -> JArr(xs |> List.map (setField name value))
    | x -> x

let private keystoreTests =
    [
        fuzz
            "parse: random and mutated keystores"
            (Gen.delay (fun () -> genJsonInput (keystoreSeeds.Force())))
            (fun bytes ->
                let text = Encoding.UTF8.GetString bytes

                try
                    Keystore.parse text |> ignore
                with e ->
                    failwithf "parse threw %s: %s\ninput: %s" (e.GetType().Name) e.Message text)
        fuzz
            "decrypt: mutated keystores fail or give the original secret"
            (Gen.delay (fun () ->
                let ks = parseJ (cheapKeystore.Force())
                Gen.frequency [ 3, mutateJMany ks; 1, Gen.constant ks ] |> Gen.map bytesOfJ))
            (fun bytes ->
                let text = Encoding.UTF8.GetString bytes

                match Keystore.parse text with
                | Error _ -> ()
                | Ok ks ->
                    // Mutations can make the KDF slow (c up to the parser's cap); skip those.
                    let costly =
                        match ks.Kdf with
                        | Keystore.Pbkdf2(c, _, _) -> c > (1 <<< 12)
                        | Keystore.Scrypt(n, r, p, _, _) -> int64 n * int64 r * int64 p > (1L <<< 14)

                    if not costly then
                        let result =
                            try
                                Keystore.decrypt ks "pw"
                            with e ->
                                failwithf "decrypt threw %s: %s\ninput: %s" (e.GetType().Name) e.Message text

                        match result with
                        | Ok s when s <> cheapSecret -> failwithf "decrypt gave another secret\ninput: %s" text
                        | _ -> ())
        test "parse: costly KDF parameters are refused" {
            let ks = parseJ (cheapKeystore.Force())
            let parse j = Keystore.parse (Encoding.UTF8.GetString(bytesOfJ j))
            Expect.isError (parse (setField "dklen" (JNum "2147483647") ks)) "dklen 2^31 - 1"
            Expect.isError (parse (setField "c" (JNum "2147483647") ks)) "c 2^31 - 1"
            Expect.isOk (parse (setField "c" (JNum "262144") ks)) "c 2^18, as the deposit tools write"
        }
    ]

// ---- EIP-3076 interchange ----

type private MemoryMarkFile() =
    let data = ResizeArray<byte>()
    member _.Bytes = data.ToArray()

    interface IMarkFile with
        member _.ReadAll() = data.ToArray()
        member _.Append(bytes) = data.AddRange bytes
        member _.Sync() = ()
        member _.Truncate(length) = data.RemoveRange(int length, data.Count - int length)

        member _.Replace(bytes) =
            data.Clear()
            data.AddRange bytes

        member _.Dispose() = ()

let private openMemory (bytes: byte[]) (gvr: Root) =
    let f = new MemoryMarkFile()
    (f :> IMarkFile).Replace bytes

    match SlashingDb.Open(f, gvr) with
    | Ok db -> f, db
    | Error e -> failwithf "open: %s" e

let private marksOf (db: SlashingDb) = db.Keys |> List.map (fun k -> k.Hex, db.Marks k) |> List.sortBy fst

let private interchangeSeeds =
    lazy
        [
            for f in
                Directory.GetFiles(Path.Combine(fixtures, "layouts"), "interchange.json", SearchOption.AllDirectories) ->
                parseJ (File.ReadAllText f)
        ]

let private genInterchange: Gen<Interchange> =
    let genRoot =
        Gen.frequency
            [
                1, Gen.constant ValueNone
                3,
                genBytes 32
                |> Gen.map (fun b ->
                    b[0] <- b[0] ||| 1uy
                    ValueSome(Root.Of b))
            ]

    let genKey =
        Gen.choose (0, 3)
        |> Gen.map (fun n -> PubKey.Of(Array.init 48 (fun i -> if i = 0 then byte (n + 1) else 0xA5uy)))

    let genEntry =
        Gen.map3
            (fun k blocks atts ->
                {
                    PubKey = k
                    SignedBlocks = blocks
                    SignedAttestations = atts
                })
            genKey
            (Gen.choose (0, 3)
             |> Gen.bind (fun n ->
                 Gen.listOfLength n (Gen.map2 (fun s r -> { Slot = s; SigningRoot = r }) genU64 genRoot)))
            (Gen.choose (0, 3)
             |> Gen.bind (fun n ->
                 Gen.listOfLength
                     n
                     (Gen.map3
                         (fun s t r ->
                             {
                                 SourceEpoch = s
                                 TargetEpoch = t
                                 SigningRoot = r
                             })
                         genU64
                         genU64
                         genRoot)))

    Gen.map2
        (fun gvr data ->
            {
                GenesisValidatorsRoot = gvr
                Data = data
            })
        (genBytes 32 |> Gen.map Root.Of)
        (Gen.choose (0, 4) |> Gen.bind (fun n -> Gen.listOfLength n genEntry))

/// Imports into a fresh DB; export, import again into another DB and reopen the first: same marks.
let private checkImport (x: Interchange) =
    let fileA, a = openMemory [||] x.GenesisValidatorsRoot
    use _ = a

    match a.Import x with
    | Error e -> failwithf "import refused: %s" e
    | Ok _ ->
        let exported = a.Export ValueNone

        let reparsed =
            match Interchange.parse (Interchange.write exported) with
            | Ok y -> y
            | Error e -> failwithf "own export does not parse: %s" e

        let _, b = openMemory [||] x.GenesisValidatorsRoot
        use _ = b

        match b.Import reparsed with
        | Error e -> failwithf "re-import refused: %s" e
        | Ok _ -> ()
        // The minimal export keeps every mark; it may drop a vote root that does not belong to the
        // source mark, which only makes the re-imported DB stricter.
        let same (ka, ma: KeyMarks voption) (kb, mb: KeyMarks voption) =
            ka = kb
            && match ma, mb with
               | ValueSome x, ValueSome y ->
                   let blocks =
                       match x.Block, y.Block with
                       | ValueSome p, ValueSome q -> p.Slot = q.Slot && (q.Root = p.Root || q.Root.IsNone)
                       | ValueNone, ValueNone -> true
                       | _ -> false

                   let atts =
                       match x.Attestation, y.Attestation with
                       | ValueSome p, ValueSome q ->
                           p.Source = q.Source
                           && p.Target = q.Target
                           && (q.Root.IsNone || (q.Root = p.Root && q.RootSource = p.RootSource))
                       | ValueNone, ValueNone -> true
                       | _ -> false

                   blocks && atts
               | ValueNone, ValueNone -> true
               | _ -> false

        let ma, mb = marksOf a, marksOf b

        if ma.Length <> mb.Length || not (List.forall2 same ma mb) then
            failwith "export and re-import changed the marks"

        let _, reopened = openMemory fileA.Bytes x.GenesisValidatorsRoot
        use _ = reopened

        if marksOf reopened <> marksOf a then
            failwith "reopen changed the marks"

let private interchangeTests =
    [
        fuzz
            "parse and import: random and mutated files"
            (Gen.delay (fun () -> genJsonInput (interchangeSeeds.Force())))
            (fun bytes ->
                let parsed =
                    try
                        Interchange.parse bytes
                    with e ->
                        failwithf
                            "parse threw %s: %s\ninput: %s"
                            (e.GetType().Name)
                            e.Message
                            (Encoding.UTF8.GetString bytes)

                match parsed with
                | Ok x ->
                    // Whatever parses must import, export and survive a reopen.
                    try
                        checkImport x
                    with e ->
                        failwithf "%s\ninput: %s" e.Message (Encoding.UTF8.GetString bytes)
                | Error _ -> ())
        fuzz "generated files round trip and import" genInterchange (fun x ->
            match Interchange.parse (Interchange.write x) with
            | Ok y when y = x -> checkImport x
            | Ok _ -> failwith "write then parse changed the file"
            | Error e -> failwithf "own output does not parse: %s" e)
    ]

// ---- Config files ----

/// One config with a section for every linked module; mutations start from it.
let private configSeed =
    """{ "beacon_nodes": [ { "url": "http://127.0.0.1:5052", "roles": ["duties", "publish"], "headers": { "X-A": "b" } },
                         { "url": "https://bn2:5052", "ca_cert": "ca.pem" } ],
  "attestation_consensus_threshold": 1, "broadcast": ["attestations"], "fee_recipient": "0x0000000000000000000000000000000000000001",
  "graffiti": "eplix", "graffiti_append": "vc", "graffiti_vc_code": "EX", "gas_limit": "60000000", "snapshot_interval_epochs": 8,
  "network": "hoodi", "data_dir": "data", "log_level": "info", "log_format": "json",
  "allow_start_without_history": ["all"], "request_timeout_ms": 2000, "use_events": true,
  "stop_signing": false, "paused_duties": ["sync_committee_message"],
  "modules": {
    "local": { "keystores": [ { "path": "keys", "password_file": "password.txt", "layout": "lighthouse" } ], "decrypt_parallelism": 2, "reload_interval_seconds": 0 },
    "dirk": { "endpoints": ["dirk1:13141"], "accounts": ["wallet/acc"], "ca_cert": "ca.pem", "client_cert": "c.pem", "client_key": "c.key", "timeout_ms": 2000, "batch_attestations": true, "gloas_calls": "native" },
    "web3signer": { "signers": [ { "url": "https://w3s:9000", "ca_cert": "ca.pem" } ],
                    "groups": [ { "threshold": 2, "members": [ { "index": 1, "url": "https://w3s-1:9000" }, { "index": 2, "url": "https://w3s-2:9000" } ],
                                  "keys": [ { "pubkey": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c", "shares": { "1": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c" } } ] } ],
                    "timeout_ms": 2000, "max_connections": 64, "refresh_interval_seconds": 384 },
    "tee": { "runners": [ { "name": "r1", "address": "tcp:192.0.2.1:7000", "client_cert": "c.pem", "client_key": "c.key", "tls_key_pin": "sha256:00", "connections": 2 } ],
             "timeout_ms": 2000, "dial_timeout_ms": 1000 },
    "keymanager": { "address": "127.0.0.1", "port": 7500, "token_file": "token" },
    "gloas": { "include_payload": true, "p2p_min_bid": "0", "p2p_builder_boost_factor": "100" },
    "builder": { "builders": [ { "url": "http://builder:18550", "min_bid": "0" } ] },
    "metrics": { "address": "127.0.0.1", "port": 8008 },
    "doppelganger": { "enabled": true, "epochs": 2 },
    "obol": { "enabled": false },
    "monitor": { "enabled": true, "per_validator": false },
    "graffiti": { "file": "graffiti.txt", "rotation": "slot" },
    "tracing": { "enabled": false, "endpoint": "http://127.0.0.1:4318", "sample_ratio": 0.1 } } }"""

let private configModules () =
    [
        LocalModule.create ()
        Eplix.Backend.Dirk.DirkModule.create ()
        Eplix.Backend.Web3Signer.Web3SignerModule.create ()
        Eplix.Backend.Tee.TeeModule.create ()
        Eplix.Keymanager.KeymanagerModule.create ()
        Eplix.Gloas.GloasModule.create ()
        Eplix.Builder.BuilderModule.create ()
        Eplix.Metrics.MetricsModule.create ()
        Eplix.Doppelganger.DoppelgangerModule.create ()
        Eplix.Obol.ObolModule.create ()
        Eplix.Monitor.MonitorModule.create ()
        Eplix.Graffiti.GraffitiModule.create ()
        Eplix.Tracing.TracingModule.create ()
    ]

let private proposerSeed =
    """{ "default_config": { "fee_recipient": "0x0000000000000000000000000000000000000001", "gas_limit": "60000000", "graffiti": "g" },
  "proposer_config": { "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c": { "fee_recipient": "0x0000000000000000000000000000000000000002" } } }"""

let private switchesSeed =
    """{ "stop_signing": true, "paused_duties": ["attestation", "sync_committee"] }"""

/// Line mutations for the line-based files (config.yaml, header files), then byte mutations.
let private genTextInput (seeds: string list) : Gen<byte[]> =
    let lineMutation (text: string) =
        let lines = text.Split('\n')

        Gen.choose (0, lines.Length - 1)
        |> Gen.bind (fun i ->
            Gen.oneof
                [
                    Gen.constant (String.Join("\n", Array.removeAt i lines))
                    Gen.constant (String.Join("\n", Array.insertAt i lines[i] lines))
                    Gen.elements interestingStrings
                    |> Gen.map (fun v ->
                        let l = lines[i]
                        let c = l.IndexOf ':'
                        let l2 = if c > 0 then l.Substring(0, c + 1) + " " + v else v
                        String.Join("\n", Array.updateAt i l2 lines))
                ])

    Gen.frequency
        [
            4,
            Gen.elements seeds
            |> Gen.bind lineMutation
            |> Gen.bind (fun t -> Gen.frequency [ 2, Gen.constant t; 1, lineMutation t ])
            |> Gen.map Encoding.UTF8.GetBytes
            2, Gen.elements seeds |> Gen.map Encoding.UTF8.GetBytes |> Gen.bind mutateBytes
            1, Gen.choose (0, 300) |> Gen.bind genBytes
        ]

let private noThrow (what: string) (bytes: byte[]) (f: unit -> 'T) =
    try
        f () |> ignore
    with e ->
        failwithf
            "%s threw %s: %s\n%s\ninput: %s"
            what
            (e.GetType().Name)
            e.Message
            e.StackTrace
            (Encoding.UTF8.GetString bytes)

/// The errors of Config.parse, then of every module's Configure; [] when both pass. A throw
/// passes through, so a test sees it as a failure.
let private configErrors (baseDir: string) (text: string) : string list =
    let modules = configModules ()

    match Config.parse text baseDir (modules |> List.map (fun m -> m.Name)) with
    | Error es -> es
    | Ok c ->
        match Runner.configure c modules baseDir with
        | Ok() -> []
        | Error es -> es

/// A TEE section that configures, so a bad value in it is the only error.
let private teeSection =
    """{ "runners": [ { "name": "r1", "address": "tcp:192.0.2.1:7000", "client_cert": "c.pem", "client_key": "c.key", "attestation": { "verifier": "dev" } } ],
         "groups": [ { "threshold": 1, "members": [ { "runner": "r1", "index": 1 } ] } ],
         "keys": [ "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c" ],
         "timeout_ms": 2000, "dial_timeout_ms": 1000 }"""

/// The config seed with the TEE section above and `raw` (JSON text) at `path`.
let private seedWith (path: string list) (raw: string) =
    let root = Nodes.JsonNode.Parse(configSeed) |> nonNull
    (root["modules"] |> nonNull)["tee"] <- Nodes.JsonNode.Parse teeSection

    let rec set (node: Nodes.JsonNode) (path: string list) =
        match path with
        | [ last ] -> node[last] <- Nodes.JsonNode.Parse raw
        | p :: rest ->
            match Int32.TryParse p with
            | true, i -> set (node[i] |> nonNull) rest
            | _ -> set (node[p] |> nonNull) rest
        | [] -> ()

    set root path
    root.ToJsonString()

/// Over 2^64 - 1, 2^64 - 1, 2^32 + 1 (1 after a cast to int), negative, fractional and an exponent.
let private notInRange =
    [
        "18446744073709551616"
        "18446744073709551615"
        "4294967297"
        "-1"
        "1.5"
        "1e3"
        "\"12x\""
    ]

/// One test per bounded key: each value out of range gives an error that names the key and
/// the range, and the bounds themselves pass.
let private boundTests (dir: Lazy<string>) =
    let cases =
        // path in the config, low, high, values out of range besides notInRange
        [
            [ "request_timeout_ms" ], 1UL, 600_000UL, [ "0"; "600001" ]
            [ "proposer_config_lead_ms" ], 1UL, 600_000UL, [ "0"; "600001" ]
            [ "modules"; "web3signer"; "timeout_ms" ], 1UL, 60_000UL, [ "0"; "60001" ]
            [ "modules"; "web3signer"; "max_connections" ], 1UL, 4096UL, [ "0"; "4097" ]
            [ "modules"; "web3signer"; "refresh_interval_seconds" ], 0UL, 86_400UL, [ "86401" ]
            [ "modules"; "web3signer"; "groups"; "0"; "threshold" ], 1UL, 2UL, [ "0"; "3" ]
            [ "modules"; "dirk"; "timeout_ms" ], 1UL, 60_000UL, [ "0"; "60001" ]
            [ "modules"; "dirk"; "refresh_interval_seconds" ], 0UL, 86_400UL, [ "86401" ]
            [ "modules"; "tee"; "timeout_ms" ], 1UL, 60_000UL, [ "0"; "60001" ]
            [ "modules"; "tee"; "dial_timeout_ms" ], 100UL, 600_000UL, [ "0"; "99"; "600001" ]
            [ "modules"; "tee"; "priority_low_every" ], 0UL, 1000UL, [ "1"; "1001" ]
            [ "modules"; "tee"; "refresh_interval_seconds" ], 0UL, 86_400UL, [ "86401" ]
            [ "modules"; "tee"; "runners"; "0"; "connections" ], 1UL, 64UL, [ "0"; "65" ]
            [ "modules"; "tee"; "groups"; "0"; "threshold" ], 1UL, 1UL, [ "0"; "2" ]
            [ "modules"; "local"; "decrypt_parallelism" ], 1UL, 64UL, [ "0"; "65" ]
            [ "modules"; "local"; "reload_interval_seconds" ], 0UL, 86_400UL, [ "86401" ]
            [ "modules"; "keymanager"; "port" ], 1UL, 65_535UL, [ "0"; "65536" ]
            [ "modules"; "keymanager"; "max_import_keys" ], 1_000UL, 1_000_000UL, [ "0"; "999"; "1000001" ]
            [ "modules"; "metrics"; "port" ], 1UL, 65_535UL, [ "0"; "65536" ]
            [ "modules"; "doppelganger"; "epochs" ], 1UL, 64UL, [ "0"; "65" ]
            [ "modules"; "tracing"; "queue_size" ], 1UL, 1_000_000UL, [ "0"; "1000001" ]
            [ "modules"; "tracing"; "batch_size" ], 1UL, 100_000UL, [ "0"; "100001" ]
            [ "modules"; "tracing"; "flush_interval_ms" ], 10UL, 600_000UL, [ "9"; "600001" ]
            [ "modules"; "tracing"; "timeout_ms" ], 100UL, 600_000UL, [ "99"; "600001" ]
        ]

    [
        for path, lo, hi, extra in cases do
            let key = List.last path

            let want =
                if key = "priority_low_every" then
                    "priority_low_every must be 0 (no priority) or between 2 and 1000"
                else
                    $"{key} must be between {lo} and {hi}"

            yield
                test $"""bounds: {String.Join(".", path)} is {lo} to {hi}""" {
                    for v in extra @ notInRange do
                        let es = configErrors (dir.Force()) (seedWith path v)
                        Expect.exists es (fun e -> e.Contains want) $"{key} = {v}: %A{es}"

                    for v in [ lo; hi ] do
                        let es = configErrors (dir.Force()) (seedWith path (string v))
                        Expect.all es (fun e -> not (e.Contains $"{key} must be")) $"{key} = {v} passes: %A{es}"
                }
        // The attestation block of a Web3Signer endpoint; its refresh read through u64 and
        // TimeSpan.FromSeconds, so 2^64 - 1 threw.
        yield
            test "bounds: modules.web3signer.signers.0.attestation.refresh_interval_seconds is 1 to 86400" {
                let at v = $$"""{ "source": "pinned", "tls_key_pin": "sha256:00", "refresh_interval_seconds": {{v}} }"""
                let path = [ "modules"; "web3signer"; "signers"; "0"; "attestation" ]
                let want = "refresh_interval_seconds must be between 1 and 86400"

                for v in [ "0"; "86401" ] @ notInRange do
                    let es = configErrors (dir.Force()) (seedWith path (at v))
                    Expect.exists es (fun e -> e.Contains want) $"refresh_interval_seconds = {v}: %A{es}"

                for v in [ "1"; "86400" ] do
                    let es = configErrors (dir.Force()) (seedWith path (at v))

                    Expect.all
                        es
                        (fun e -> not (e.Contains "refresh_interval_seconds must be"))
                        $"refresh_interval_seconds = {v} passes: %A{es}"
            }
        yield
            test "bounds: modules.tracing.sample_ratio is 0 to 1" {
                for v in [ "1e999"; "-1e999"; "\"NaN\""; "\"Infinity\""; "-0.1"; "1.0000001"; "true" ] do
                    let es = configErrors (dir.Force()) (seedWith [ "modules"; "tracing"; "sample_ratio" ] v)

                    Expect.exists
                        es
                        (fun e -> e.Contains "sample_ratio must be a number between 0 and 1")
                        $"sample_ratio = {v}: %A{es}"

                for v in [ "0"; "1"; "0.5"; "1e-300" ] do
                    let es = configErrors (dir.Force()) (seedWith [ "modules"; "tracing"; "sample_ratio" ] v)
                    Expect.all es (fun e -> not (e.Contains "sample_ratio")) $"sample_ratio = {v} passes: %A{es}"
            }
        yield
            test "bounds: chain spec values that time the slot, the epoch and the duties" {
                let mainnet () = ChainSpec.parseConfigYaml (Networks.configYaml "mainnet").Value

                let bad =
                    [
                        "SLOTS_PER_EPOCH", [ "0"; "1025"; "18446744073709551615" ]
                        "ATTESTATION_DUE_BPS_GLOAS", [ "10001"; "18446744073709551615" ]
                        "ATTESTATION_DUE_BPS", [ "10001" ]
                        "PAYLOAD_DUE_BPS", [ "10001" ]
                        "TARGET_AGGREGATORS_PER_COMMITTEE", [ "0" ]
                        "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE", [ "0" ]
                        "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", [ "0" ]
                    ]

                for k, values in bad do
                    for v in values do
                        match ChainSpec.parse (mainnet () |> Map.add k v) with
                        | Ok _ -> failtestf "%s = %s passed" k v
                        | Error e -> Expect.stringContains e $"{k} must be between" $"{k} = {v}"

                for k, v in
                    [
                        "SLOTS_PER_EPOCH", "1"
                        "SLOTS_PER_EPOCH", "1024"
                        "ATTESTATION_DUE_BPS_GLOAS", "10000"
                    ] do
                    Expect.isOk (ChainSpec.parse (mainnet () |> Map.add k v)) $"{k} = {v}"
            }
    ]

let private configTests =
    // The files the seed names exist (empty), so mutations reach the module checks.
    let dir =
        lazy
            (let d = tempDir ()

             for f in [ "ca.pem"; "c.pem"; "c.key"; "token"; "password.txt"; "graffiti.txt" ] do
                 File.WriteAllText(Path.Combine(d, f), "")

             Directory.CreateDirectory(Path.Combine(d, "keys")) |> ignore
             d)

    [
        fuzz
            "eplix.json: parse and configure every module"
            (Gen.delay (fun () -> genJsonInput [ parseJ configSeed ]))
            (fun bytes ->
                noThrow "config" bytes (fun () ->
                    let modules = configModules ()

                    match
                        Config.parse
                            (Encoding.UTF8.GetString bytes)
                            (dir.Force())
                            (modules |> List.map (fun m -> m.Name))
                    with
                    | Ok c -> Runner.configure c modules (dir.Force()) |> ignore
                    | Error _ -> ()))
        fuzz
            "config.yaml: parse and read the chain spec"
            (Gen.delay (fun () -> genTextInput [ for n in Networks.names -> (Networks.configYaml n).Value ]))
            (fun bytes ->
                noThrow "chain config" bytes (fun () ->
                    ChainSpec.parseConfigYaml (Encoding.UTF8.GetString bytes) |> ChainSpec.parse))
        fuzz "proposer config" (Gen.delay (fun () -> genJsonInput [ parseJ proposerSeed ])) (fun bytes ->
            noThrow "proposer config" bytes (fun () -> ProposerConfig.parse bytes))
        fuzz "switches.json" (Gen.delay (fun () -> genJsonInput [ parseJ switchesSeed ])) (fun bytes ->
            noThrow "switches" bytes (fun () -> Switches.parseFile bytes))
        fuzz
            "headers file"
            (Gen.delay (fun () -> genTextInput [ "# auth\nAuthorization: Bearer abc\nX-Client: eplix\n" ]))
            (fun bytes -> noThrow "headers" bytes (fun () -> Headers.parseFile (Encoding.UTF8.GetString bytes)))
        // Inputs the config fuzz found; each must give an error, not an exception.
        test "regression: invalid UTF-8 in a JSON string" {
            let bad (prefix: string) (suffix: string) =
                Array.concat [ Encoding.UTF8.GetBytes prefix; [| 0xFFuy |]; Encoding.UTF8.GetBytes suffix ]

            Expect.isError
                (ProposerConfig.parse (bad """{ "default_config": { "graffiti": "a""" """" } }"""))
                "proposer config"

            Expect.isError (Switches.parseFile (bad """{ "paused_duties": ["a""" """"] }""")) "switches.json"
        }
        test "regression: a slot duration too long for TimeSpan" {
            let yaml = (Networks.configYaml "mainnet").Value

            for k in [ "SECONDS_PER_SLOT"; "SLOT_DURATION_MS" ] do
                let values =
                    ChainSpec.parseConfigYaml yaml |> Map.remove "SLOT_DURATION_MS" |> Map.add k "18446744073709551615"

                Expect.isError (ChainSpec.parse values) k
        }
        test "regression: a NUL character in a path" {
            let nul = string (char 92) + "u0000"
            let modules = configModules ()
            let names = modules |> List.map (fun m -> m.Name)

            let core =
                $$"""{ "beacon_node": "http://127.0.0.1:5052", "network": "hoodi", "data_dir": "d{{nul}}", "modules": { "local": { "keystores": [ { "path": "keys" } ] } } }"""

            Expect.isError (Config.parse core (dir.Force()) names) "data_dir"

            let inModule =
                $$"""{ "beacon_node": "http://127.0.0.1:5052", "network": "hoodi", "data_dir": "data", "modules": { "local": { "keystores": [ { "path": "k{{nul}}" } ] } } }"""

            match Config.parse inModule (dir.Force()) names with
            | Error _ -> ()
            | Ok c -> Expect.isError (Runner.configure c [ LocalModule.create () ] (dir.Force())) "a module path"
        }
        // Round 2 of the fuzz week, seed 16714527192738384879, step (13368434580550723187,6497012287330786431,189):
        // a Web3Signer refresh_interval_seconds of 2^64 - 1 threw OverflowException from TimeSpan.
        test "regression: a Web3Signer refresh interval too long for TimeSpan" {
            let input =
                """{"beacon_nodes":[{"url":"http://127.0.0.1:5052","roles":["duties","publish"],"headers":{"X-A":"b"}},{"url":"https://bn2:5052","ca_cert":"ca.pem"}],"attestation_consensus_threshold":1,"broadcast":["attestations"],"fee_recipient":"0x0000000000000000000000000000000000000001","graffiti":"eplix","graffiti_append":"vc","graffiti_vc_code":"EX","gas_limit":"60000000","snapshot_interval_epochs":8,"network":"hoodi","data_dir":"data","log_level":"info","log_format":"json","allow_start_without_history":["all"],"request_timeout_ms":2000,"use_events":true,"stop_signing":false,"paused_duties":["sync_committee_message"],"modules":{"local":{"keystores":[{"path":"keys","password_file":"password.txt","layout":"lighthouse"}],"decrypt_parallelism":2,"reload_interval_seconds":0},"dirk":{"endpoints":["dirk1:13141"],"accounts":["wallet/acc"],"ca_cert":"ca.pem","client_cert":"c.pem","client_key":"c.key","timeout_ms":2000,"batch_attestations":true,"gloas_calls":"native"},"web3signer":{"signers":[{"url":"https://w3s:9000","ca_cert":"ca.pem"}],"groups":[{"threshold":2,"members":[{"index":1,"url":"https://w3s-1:9000"},{"index":2,"url":"https://w3s-2:9000"}],"keys":[{"pubkey":"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","shares":{"1":"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"}}]}],"timeout_ms":2000,"max_connections":64,"refresh_interval_seconds":18446744073709551615},"tee":{"runners":[{"name":"r1","address":"tcp:192.0.2.1:7000","client_cert":"c.pem","client_key":"c.key","tls_key_pin":"sha256:00","connections":2}],"timeout_ms":2000,"dial_timeout_ms":1000},"keymanager":{"address":"127.0.0.1","port":7500,"token_file":"token"},"gloas":{"include_payload":true,"p2p_min_bid":"0","p2p_builder_boost_factor":"100"},"builder":{"builders":[{"url":"http://builder:18550","min_bid":"0"}]},"metrics":{"address":"127.0.0.1","port":8008},"doppelganger":{"enabled":true,"epochs":2},"obol":{"enabled":{}},"monitor":{"enabled":true,"per_validator":false},"graffiti":{"file":"graffiti.txt","rotation":"slot"},"tracing":{"enabled":false,"endpoint":"http://127.0.0.1:4318","sample_ratio":0.1}},"beacon_nodes":[{"url":"http://127.0.0.1:5052","roles":["duties","publish"],"headers":{"X-A":"b"}},{"url":"https://bn2:5052","ca_cert":"ca.pem"}]}"""

            match configErrors (dir.Force()) input with
            | [] -> failtest "the config passed"
            | es ->
                let want = "refresh_interval_seconds must be between 0 and 86400"

                Expect.exists
                    es
                    (fun e -> e.Contains "module web3signer" && e.Contains want)
                    $"an error names the key and the range: %A{es}"
        }
        test "the config seed parses" {
            let modules = configModules ()

            match Config.parse configSeed (dir.Force()) (modules |> List.map (fun m -> m.Name)) with
            | Ok _ -> ()
            | Error es -> failtestf "seed: %A" es
        }
    ]
    @ boundTests dir

[<Tests>]
let tests =
    testList
        "fuzz"
        [
            testList "ssz" sszTests
            testList "beacon api" beaconTests
            testList "eip-2335" keystoreTests
            testList "eip-3076" interchangeTests
            testList "config" configTests
        ]
