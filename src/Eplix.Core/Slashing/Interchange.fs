/// EIP-3076 slashing protection interchange, format version 5. Reads the complete and the
/// minimal form; writes the minimal form.
namespace Eplix.Slashing

open System.Text.Json
open Eplix
open Eplix.Json

type InterchangeBlock =
    {
        Slot: Slot
        SigningRoot: Root voption
    }

type InterchangeAttestation =
    {
        SourceEpoch: Epoch
        TargetEpoch: Epoch
        SigningRoot: Root voption
    }

type InterchangeEntry =
    {
        PubKey: PubKey
        SignedBlocks: InterchangeBlock list
        SignedAttestations: InterchangeAttestation list
    }

type Interchange =
    {
        GenesisValidatorsRoot: Root
        Data: InterchangeEntry list
    }

module Interchange =
    let formatVersion = "5"

    /// A missing or all-zero signing root is unknown. Nimbus v26.10.2 exports attestations whose
    /// root it does not have as 0x00...00.
    let private optRoot (e: JsonElement) =
        match tryProp e "signing_root" with
        | ValueSome r ->
            let x = root r
            if x = Root.Zero then ValueNone else ValueSome x
        | ValueNone -> ValueNone

    let private decoder (e: JsonElement) : Interchange =
        let meta = prop e "metadata"
        let version = strField meta "interchange_format_version"

        if version <> formatVersion then
            fail $"interchange_format_version {version} is not supported"

        {
            GenesisValidatorsRoot = rootField meta "genesis_validators_root"
            Data =
                [
                    for d in array (prop e "data") ->
                        {
                            PubKey = pubkeyField d "pubkey"
                            SignedBlocks =
                                [
                                    for b in array (prop d "signed_blocks") ->
                                        {
                                            Slot = u64Field b "slot"
                                            SigningRoot = optRoot b
                                        }
                                ]
                            SignedAttestations =
                                [
                                    for a in array (prop d "signed_attestations") ->
                                        {
                                            SourceEpoch = u64Field a "source_epoch"
                                            TargetEpoch = u64Field a "target_epoch"
                                            SigningRoot = optRoot a
                                        }
                                ]
                        }
                ]
        }

    let parse (bytes: byte[]) : Result<Interchange, string> = decode decoder (System.ReadOnlyMemory bytes)

    let write (x: Interchange) : byte[] =
        toBytes (fun w ->
            w.WriteStartObject()
            w.WriteStartObject "metadata"
            w.WriteString("interchange_format_version", formatVersion)
            w.WriteString("genesis_validators_root", x.GenesisValidatorsRoot.Hex)
            w.WriteEndObject()
            w.WriteStartArray "data"

            for d in x.Data do
                w.WriteStartObject()
                w.WriteString("pubkey", d.PubKey.Hex)
                w.WriteStartArray "signed_blocks"

                for b in d.SignedBlocks do
                    w.WriteStartObject()
                    writeU64 w "slot" b.Slot
                    b.SigningRoot |> ValueOption.iter (fun r -> w.WriteString("signing_root", r.Hex))
                    w.WriteEndObject()

                w.WriteEndArray()
                w.WriteStartArray "signed_attestations"

                for a in d.SignedAttestations do
                    w.WriteStartObject()
                    writeU64 w "source_epoch" a.SourceEpoch
                    writeU64 w "target_epoch" a.TargetEpoch
                    a.SigningRoot |> ValueOption.iter (fun r -> w.WriteString("signing_root", r.Hex))
                    w.WriteEndObject()

                w.WriteEndArray()
                w.WriteEndObject()

            w.WriteEndArray()
            w.WriteEndObject())

    /// `eplix slashing export`: writes the interchange of the `pubkeys` (every key when None) to
    /// `file` and returns the number of keys written. `hasRecord` and `export` come from the
    /// slashing DB. Every pubkey must parse and have a record: a key left out of the file
    /// without a word would look exported to whoever imports it. The write is atomic: a crash or
    /// a full disk leaves the old file or none, never a truncated interchange.
    let exportTo
        (hasRecord: PubKey -> bool)
        (export: PubKey list voption -> Interchange)
        (pubkeys: string list option)
        (file: string)
        : Result<int, string> =
        let keys =
            match pubkeys with
            | None -> Ok ValueNone
            | Some ks ->
                let parsed = ks |> List.map (fun k -> k, PubKey.TryParse k)

                match parsed |> List.tryFind (fun (_, pk) -> pk.IsNone) with
                | Some(k, _) -> Error $"'{k}' is not a public key"
                | None ->
                    let pks = parsed |> List.map (fun (_, pk) -> pk.Value)

                    match pks |> List.filter (fun pk -> not (hasRecord pk)) with
                    | [] -> Ok(ValueSome pks)
                    | missing ->
                        let names = System.String.Join(", ", missing |> List.map (fun pk -> pk.Hex))
                        Error $"no slashing record for {names}; nothing exported"

        match keys with
        | Error e -> Error e
        | Ok keys ->
            let x = export keys

            let mode =
                System.IO.UnixFileMode.UserRead
                ||| System.IO.UnixFileMode.UserWrite
                ||| System.IO.UnixFileMode.GroupRead
                ||| System.IO.UnixFileMode.OtherRead

            try
                FileSync.writeAtomic file (write x) mode
                Ok x.Data.Length
            with
            | :? System.IO.IOException
            | :? System.UnauthorizedAccessException as e -> Error $"writing {file}: {e.Message}"

    /// The marks an entry implies: the maximum block and the maximum source and target.
    let marksOf (entry: InterchangeEntry) : KeyMarks =
        let withBlocks =
            entry.SignedBlocks
            |> List.fold (fun m b -> Marks.mergeBlock m { Slot = b.Slot; Root = b.SigningRoot }) KeyMarks.Empty

        entry.SignedAttestations
        |> List.fold
            (fun m a ->
                Marks.mergeAttestation
                    m
                    {
                        Source = a.SourceEpoch
                        Target = a.TargetEpoch
                        Root = a.SigningRoot
                        RootSource = a.SourceEpoch
                    })
            withBlocks

    /// The minimal entry for a key's marks. The attestation carries a signing root only when
    /// the root belongs to a vote with exactly that source and target.
    let entryOf (key: PubKey) (m: KeyMarks) : InterchangeEntry =
        {
            PubKey = key
            SignedBlocks =
                [
                    match m.Block with
                    | ValueSome b -> { Slot = b.Slot; SigningRoot = b.Root }
                    | ValueNone -> ()
                ]
            SignedAttestations =
                [
                    match m.Attestation with
                    | ValueSome a ->
                        {
                            SourceEpoch = a.Source
                            TargetEpoch = a.Target
                            SigningRoot = (if a.RootSource = a.Source then a.Root else ValueNone)
                        }
                    | ValueNone -> ()
                ]
        }
