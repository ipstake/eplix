/// Hex strings in the Beacon API form: "0x" followed by lower-case digits.
module Eplix.Hex

open System

let encode (bytes: ReadOnlySpan<byte>) : string = "0x" + Convert.ToHexStringLower bytes

let encodeArray (bytes: byte[]) : string = encode (ReadOnlySpan bytes)

/// Decodes "0x..." of any even length. Refuses a missing prefix and bad digits.
let tryDecode (s: string) : byte[] voption =
    if s.Length < 2 || s[0] <> '0' || (s[1] <> 'x' && s[1] <> 'X') || s.Length % 2 <> 0 then
        ValueNone
    else
        try
            ValueSome(Convert.FromHexString(s.AsSpan 2))
        with :? FormatException ->
            ValueNone

/// Decodes "0x..." and checks that the result has exactly `length` bytes.
let tryDecodeFixed (length: int) (s: string) : byte[] voption =
    match tryDecode s with
    | ValueSome b when b.Length = length -> ValueSome b
    | _ -> ValueNone
