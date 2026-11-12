/// Floor records for keys with no signing history. E is the epoch now;
/// the floor is source = target = E + 1 and a block mark at the last slot of epoch E + 1, with no
/// root. Any signature the key made before, on another machine or before a disk loss, is at or
/// below E, so nothing the VC signs above the floor is slashable with it, as long as no other
/// machine signs with the key now. No path starts a key with an empty record.
namespace Eplix.Slashing

open Eplix

module Floor =
    /// The floor's source and target epoch. Throws OverflowException rather than wrap.
    let target (e: Epoch) : Epoch = Checked.(+) e 1UL

    /// The last slot of epoch E + 1: the floor's block mark, and its PTC vote and envelope marks.
    /// Throws OverflowException rather than wrap: a wrapped slot would be a low mark.
    let slot (slotsPerEpoch: uint64) (e: Epoch) : Slot = Checked.(-) (Checked.(*) (Checked.(+) e 2UL) slotsPerEpoch) 1UL

    let marks (slotsPerEpoch: uint64) (e: Epoch) : KeyMarks =
        {
            Block =
                ValueSome
                    {
                        Slot = slot slotsPerEpoch e
                        Root = ValueNone
                    }
            Attestation =
                ValueSome
                    {
                        Source = target e
                        Target = target e
                        Root = ValueNone
                        RootSource = target e
                    }
        }

    /// E: the clock's epoch, raised to the epoch of the highest head slot a beacon node reports.
    /// A node's head only raises the floor.
    let epoch (slotsPerEpoch: uint64) (clockEpoch: Epoch) (headSlots: Slot seq) : Epoch =
        headSlots |> Seq.fold (fun e s -> max e (s / slotsPerEpoch)) clockEpoch

    /// Floor.epoch, refused when a head is more than one epoch past the clock: no honest node is
    /// ahead of the wall clock by that much, and a floor far ahead would stop the key for good.
    /// The whole floor is refused, not just that head: when the system clock is behind, the head
    /// past it is the true one, and a floor without it would sit below epochs the key may have
    /// signed elsewhere.
    let epochChecked (slotsPerEpoch: uint64) (clockEpoch: Epoch) (headSlots: Slot seq) : Result<Epoch, string> =
        let e = epoch slotsPerEpoch clockEpoch headSlots

        if e > clockEpoch + 1UL then
            Error
                $"a beacon node's head is in epoch {e}, the clock in epoch {clockEpoch}; no floor written. Check the system clock and the beacon nodes"
        else
            Ok e

    /// Writes the floor at E for `keys`: the slot marks first, then the slashing DB, whose record
    /// is what lets a key start. A key that has marks keeps the higher of each.
    let write
        (db: SlashingDb)
        (slotMarks: SlotMarks voption)
        (slotsPerEpoch: uint64)
        (e: Epoch)
        (origin: KeyOrigin)
        (keys: PubKey list)
        =
        if keys.IsEmpty then
            Ok()
        else
            let values =
                try
                    Ok(slot slotsPerEpoch e, marks slotsPerEpoch e)
                with :? System.OverflowException ->
                    Error $"a floor at epoch {e} is out of range"

            match values with
            | Error why -> Error why
            | Ok(floorSlot, floorMarks) ->
                let slotResult =
                    match slotMarks with
                    | ValueSome m -> m.RaiseFloor(keys, floorSlot)
                    | ValueNone -> Ok()

                slotResult |> Result.bind (fun () -> db.RaiseFloor(keys, origin, floorMarks))
