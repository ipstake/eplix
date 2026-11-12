/// Slot and epoch from genesis time and slot duration. Every read goes through TimeProvider,
/// so tests run on a fake clock.
namespace Eplix

open System
open System.Threading
open System.Threading.Tasks

type SlotClock(genesisTime: DateTimeOffset, slotDuration: TimeSpan, slotsPerEpoch: uint64, time: TimeProvider) =
    do
        if slotDuration <= TimeSpan.Zero then
            invalidArg "slotDuration" "must be positive"

        if slotsPerEpoch = 0UL then
            invalidArg "slotsPerEpoch" "must be positive"

    member _.Time = time
    member _.GenesisTime = genesisTime
    member _.SlotDuration = slotDuration
    member _.SlotsPerEpoch = slotsPerEpoch
    member _.Now = time.GetUtcNow()

    member _.SlotStart(slot: Slot) : DateTimeOffset =
        genesisTime + TimeSpan.FromTicks(Checked.(*) (int64 slot) slotDuration.Ticks)

    /// The slot at time t, or ValueNone before genesis.
    member _.SlotAt(t: DateTimeOffset) : Slot voption =
        if t < genesisTime then ValueNone else ValueSome(uint64 ((t - genesisTime).Ticks / slotDuration.Ticks))

    member this.CurrentSlot = this.SlotAt this.Now
    member _.EpochOf(slot: Slot) : Epoch = slot / slotsPerEpoch
    member _.FirstSlot(epoch: Epoch) : Slot = epoch * slotsPerEpoch

    /// Waits until t on this clock. Returns at once if t has passed. A timer can fire a little
    /// early (the system clock and the timer clock differ); then it waits for the rest, so the
    /// clock reads t or later on return. Each wait is at most a day: Task.Delay refuses more
    /// than about 49.7 days, and genesis can be further away.
    member _.WaitUntil(t: DateTimeOffset, ct: CancellationToken) : Task =
        let delay = t - time.GetUtcNow()

        if delay <= TimeSpan.Zero then
            Task.CompletedTask
        else
            task {
                let mutable left = delay

                while left > TimeSpan.Zero do
                    do! Task.Delay(min left (TimeSpan.FromDays 1.0), time, ct)
                    left <- t - time.GetUtcNow()
            }
