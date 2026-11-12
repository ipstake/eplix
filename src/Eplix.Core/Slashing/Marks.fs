/// Slashing protection rules on high-water marks (design section 6.1, EIP-3076 "minimal").
/// Pure functions; storage is in SlashingDb.fs.
namespace Eplix.Slashing

open Eplix

/// The highest signed block slot and the signing root of that block.
/// Root is ValueNone when it is unknown, so no block at that slot counts as a repeat.
[<Struct>]
type BlockMark = { Slot: Slot; Root: Root voption }

/// The highest source and target epochs, and the signing root of the vote at the target mark.
/// RootSource is the source epoch of that vote; it differs from Source only after an import.
[<Struct>]
type AttestationMark =
    {
        Source: Epoch
        Target: Epoch
        Root: Root voption
        RootSource: Epoch
    }

type KeyMarks =
    {
        Block: BlockMark voption
        Attestation: AttestationMark voption
    }

    static member Empty =
        {
            Block = ValueNone
            Attestation = ValueNone
        }

[<RequireQualifiedAccess>]
type Check =
    /// Not slashable; the mark moves up.
    | Allow
    /// The same message as the last one at the mark; signing it again is safe and writes nothing.
    | Repeat
    | Refuse of reason: string

module Marks =
    let checkBlock (m: KeyMarks) (slot: Slot) (root: Root) : Check =
        match m.Block with
        | ValueNone -> Check.Allow
        | ValueSome b when slot > b.Slot -> Check.Allow
        | ValueSome b when slot = b.Slot && b.Root = ValueSome root -> Check.Repeat
        | ValueSome b when slot = b.Slot -> Check.Refuse $"double proposal at slot {slot}"
        | ValueSome b -> Check.Refuse $"slot {slot} is below the block mark {b.Slot}"

    let checkAttestation (m: KeyMarks) (source: Epoch) (target: Epoch) (root: Root) : Check =
        if source > target then
            Check.Refuse $"source {source} is after target {target}"
        else
            match m.Attestation with
            | ValueNone -> Check.Allow
            // A source mark above the vote's own source means another vote (from an import) sits
            // inside this one. If this vote is on disk but was never signed (a crash before fsync),
            // signing it now would surround that vote, so it is not a repeat.
            | ValueSome a when
                target = a.Target && source = a.RootSource && a.Source = a.RootSource && a.Root = ValueSome root
                ->
                Check.Repeat
            | ValueSome a when source >= a.Source && target > a.Target -> Check.Allow
            | ValueSome a when target = a.Target -> Check.Refuse $"double vote for target {target}"
            | ValueSome a when source < a.Source -> Check.Refuse $"source {source} is below the source mark {a.Source}"
            | ValueSome a -> Check.Refuse $"target {target} is below the target mark {a.Target}"

    /// Takes the maximum. Two different roots at the same slot leave the root unknown.
    let mergeBlock (m: KeyMarks) (x: BlockMark) : KeyMarks =
        match m.Block with
        | ValueNone -> { m with Block = ValueSome x }
        | ValueSome b when x.Slot > b.Slot -> { m with Block = ValueSome x }
        | ValueSome b when x.Slot = b.Slot && b.Root <> x.Root ->
            { m with
                Block = ValueSome { b with Root = ValueNone }
            }
        | ValueSome _ -> m

    /// Takes the maximum of source and target separately. The root follows the highest target.
    let mergeAttestation (m: KeyMarks) (x: AttestationMark) : KeyMarks =
        match m.Attestation with
        | ValueNone -> { m with Attestation = ValueSome x }
        | ValueSome a ->
            let source = max a.Source x.Source

            let merged =
                if x.Target > a.Target then
                    { x with Source = source }
                elif x.Target = a.Target then
                    let sameVote = a.Root = x.Root && a.RootSource = x.RootSource

                    { a with
                        Source = source
                        Root = (if sameVote then a.Root else ValueNone)
                    }
                else
                    { a with Source = source }

            { m with
                Attestation = ValueSome merged
            }

    let vote (source: Epoch) (target: Epoch) (root: Root) : AttestationMark =
        {
            Source = source
            Target = target
            Root = ValueSome root
            RootSource = source
        }

    /// True when every field of `later` is at or above `earlier`. Marks never go down.
    let atLeast (earlier: KeyMarks) (later: KeyMarks) : bool =
        let blockOk =
            match earlier.Block, later.Block with
            | ValueNone, _ -> true
            | ValueSome _, ValueNone -> false
            | ValueSome e, ValueSome l -> l.Slot >= e.Slot

        let attOk =
            match earlier.Attestation, later.Attestation with
            | ValueNone, _ -> true
            | ValueSome _, ValueNone -> false
            | ValueSome e, ValueSome l -> l.Source >= e.Source && l.Target >= e.Target

        blockOk && attOk
