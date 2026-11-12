/// Basic consensus types. Fixed-size byte types check their length on construction.
namespace Eplix

open System

type Slot = uint64
type Epoch = uint64
type ValidatorIndex = uint64
type CommitteeIndex = uint64

module internal Bytes =
    let check (name: string) (length: int) (b: byte[]) =
        if b.Length <> length then
            invalidArg name $"expected {length} bytes"

        b

[<Struct; CustomEquality; CustomComparison>]
type Root =
    private
    | Root of byte[]

    member this.Bytes = let (Root b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    override this.ToString() = this.Hex
    static member Of(b: byte[]) = Root(Bytes.check "root" 32 b)
    static member Zero = Root(Array.zeroCreate 32)
    static member TryParse(s: string) = Hex.tryDecodeFixed 32 s |> ValueOption.map Root

    override this.Equals(o) =
        match o with
        | :? Root as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 0)

    interface IEquatable<Root> with
        member this.Equals(r) = this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)

    interface IComparable with
        member this.CompareTo(o) =
            match o with
            | :? Root as r -> this.Bytes.AsSpan().SequenceCompareTo(ReadOnlySpan r.Bytes)
            | _ -> invalidArg "o" "not a Root"

[<Struct; CustomEquality; CustomComparison>]
type PubKey =
    private
    | PubKey of byte[]

    member this.Bytes = let (PubKey b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    /// First 4 bytes in hex, for log lines.
    member this.Short = Hex.encode (ReadOnlySpan(this.Bytes, 0, 4))
    override this.ToString() = this.Hex
    static member Of(b: byte[]) = PubKey(Bytes.check "pubkey" 48 b)
    static member TryParse(s: string) = Hex.tryDecodeFixed 48 s |> ValueOption.map PubKey

    override this.Equals(o) =
        match o with
        | :? PubKey as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false
    // All 48 bytes, with HashCode's per-process random seed: keys come from interchange files
    // and API requests, and a hash over a few fixed bytes lets crafted keys share one bucket.
    override this.GetHashCode() =
        let mutable h = HashCode()
        h.AddBytes(ReadOnlySpan this.Bytes)
        h.ToHashCode()

    interface IEquatable<PubKey> with
        member this.Equals(r) = this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)

    interface IComparable with
        member this.CompareTo(o) =
            match o with
            | :? PubKey as r -> this.Bytes.AsSpan().SequenceCompareTo(ReadOnlySpan r.Bytes)
            | _ -> invalidArg "o" "not a PubKey"

[<Struct; CustomEquality; NoComparison>]
type BlsSignature =
    private
    | BlsSignature of byte[]

    member this.Bytes = let (BlsSignature b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    override this.ToString() = this.Hex
    static member Of(b: byte[]) = BlsSignature(Bytes.check "signature" 96 b)
    static member TryParse(s: string) = Hex.tryDecodeFixed 96 s |> ValueOption.map BlsSignature

    override this.Equals(o) =
        match o with
        | :? BlsSignature as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 0)

/// A 4-byte fork version.
[<Struct; CustomEquality; NoComparison>]
type ForkVersion =
    private
    | ForkVersion of byte[]

    member this.Bytes = let (ForkVersion b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    override this.ToString() = this.Hex
    static member Of(b: byte[]) = ForkVersion(Bytes.check "version" 4 b)
    static member TryParse(s: string) = Hex.tryDecodeFixed 4 s |> ValueOption.map ForkVersion

    override this.Equals(o) =
        match o with
        | :? ForkVersion as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 0)

/// A 4-byte domain type such as DOMAIN_BEACON_ATTESTER.
[<Struct; CustomEquality; NoComparison>]
type DomainType =
    private
    | DomainType of byte[]

    member this.Bytes = let (DomainType b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    static member Of(b: byte[]) = DomainType(Bytes.check "domain type" 4 b)
    static member TryParse(s: string) = Hex.tryDecodeFixed 4 s |> ValueOption.map DomainType

    override this.Equals(o) =
        match o with
        | :? DomainType as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 0)

/// A 32-byte signing domain.
[<Struct; CustomEquality; NoComparison>]
type Domain =
    private
    | Domain of byte[]

    member this.Bytes = let (Domain b) = this in b
    member this.Hex = Hex.encodeArray this.Bytes
    override this.ToString() = this.Hex
    static member Of(b: byte[]) = Domain(Bytes.check "domain" 32 b)

    override this.Equals(o) =
        match o with
        | :? Domain as r -> this.Bytes.AsSpan().SequenceEqual(ReadOnlySpan r.Bytes)
        | _ -> false

    override this.GetHashCode() = BitConverter.ToInt32(this.Bytes, 0)
