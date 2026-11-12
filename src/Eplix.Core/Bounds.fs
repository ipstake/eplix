/// The range check for config numbers. A value from a config file or a beacon node's spec that
/// becomes a TimeSpan, a delay, a factor of a duration or an int goes through `check` first, so
/// a huge value is a config error that names the key and the range instead of an
/// OverflowException later. A fuzz run found a refresh interval of 2^64 - 1 that threw.
module Eplix.Bounds

open System

/// The error for a value outside lo..hi.
let message (key: string) (lo: uint64) (hi: uint64) = $"{key} must be between {lo} and {hi}"

/// `v` when it is within lo..hi, else the error naming the key and the range.
let check (key: string) (lo: uint64) (hi: uint64) (v: uint64) : Result<uint64, string> =
    if v >= lo && v <= hi then Ok v else Error(message key lo hi)

/// The longest delay a timer takes (Task.Delay and ITimer refuse more than 2^32 - 2 ms).
let maxDelay = TimeSpan.FromMilliseconds(float (UInt32.MaxValue - 1u))

/// A day in seconds: the upper bound of the refresh and reload intervals.
[<Literal>]
let Day = 86_400UL
