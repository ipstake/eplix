/// Lagrange combination and the threshold combinator, with fake members.
module Eplix.Tests.ThresholdTests

open System
open System.Numerics
open System.Threading
open System.Threading.Tasks
open Expecto
open Microsoft.Extensions.Time.Testing
open Eplix
open Eplix.Tests.TestUtil

let r = BigInteger.Parse "52435875175126190479447740508185965837690552500527637822603658699938581184513"

let private modR (x: BigInteger) =
    let m = BigInteger.Remainder(x, r)
    if m.Sign < 0 then m + r else m

let scalar32 (x: BigInteger) =
    let b = x.ToByteArray(isUnsigned = true, isBigEndian = true)
    Array.append (Array.zeroCreate (32 - b.Length)) b

/// A secret and its Shamir shares at the given ids, from a polynomial of degree m - 1 whose
/// coefficients come from `seed`.
let shamir (seed: int) (m: int) (ids: uint64 list) =
    let rnd = Random seed

    let next () =
        let b = Array.zeroCreate<byte> 40
        rnd.NextBytes b
        modR (BigInteger(ReadOnlySpan b, isUnsigned = true)) + BigInteger.One

    let coeffs = [ for _ in 1..m -> next () ]
    let eval (x: uint64) = coeffs |> List.rev |> List.fold (fun acc c -> modR (acc * BigInteger x + c)) BigInteger.Zero
    let secret = scalar32 coeffs.Head
    secret, [ for id in ids -> id, scalar32 (eval id) ]

/// Shares at the given ids of another polynomial of degree m - 1 through `secret`, with the
/// other coefficients from `seed`: a second split of the same key.
let resplit (seed: int) (secret: byte[]) (m: int) (ids: uint64 list) =
    let rnd = Random seed

    let next () =
        let b = Array.zeroCreate<byte> 40
        rnd.NextBytes b
        modR (BigInteger(ReadOnlySpan b, isUnsigned = true)) + BigInteger.One

    let coeffs =
        BigInteger(ReadOnlySpan secret, isUnsigned = true, isBigEndian = true)
        :: [ for _ in 2..m -> next () ]

    let eval (x: uint64) = coeffs |> List.rev |> List.fold (fun acc c -> modR (acc * BigInteger x + c)) BigInteger.Zero
    [ for id in ids -> id, scalar32 (eval id) ]

let pk (secret: byte[]) = PubKey.Of(Bls.publicKey (ReadOnlySpan secret))
let sign (secret: byte[]) (root: Root) = BlsSignature.Of(Bls.sign (ReadOnlySpan secret) (ReadOnlySpan root.Bytes))

let caps =
    {
        Duties = set [ DutyKind.Attestation; DutyKind.RandaoReveal; DutyKind.Block ]
        TypedOnly = false
        EnforcesSlashing = true
        ReturnsPartials = true
        MaxInFlight = 64
    }

/// A member that answers with `answer` after `delay`; it records whether it ran to the end.
type FakeMember(index: uint64, key: PubKey, share: byte[], answer: SignRequest -> SignOutcome, delay: TimeSpan) =
    let mutable finished = 0
    let mutable cancelled = 0
    let gate = obj ()
    member _.Finished = finished
    member _.Cancelled = cancelled

    member _.Backend: Backend =
        {
            Name = $"fake {index}"
            Capabilities = caps
            Keys =
                fun _ ->
                    Task.FromResult
                        [
                            {
                                Key = key
                                Share = ValueSome(struct (index, pk share))
                            }
                        ]
            Health = fun _ -> Task.FromResult Up
            Sign =
                fun req ct ->
                    task {
                        try
                            if delay > TimeSpan.Zero then
                                do! Task.Delay(delay, ct)

                            lock gate (fun () -> finished <- finished + 1)
                            return answer req
                        with :? OperationCanceledException ->
                            lock gate (fun () -> cancelled <- cancelled + 1)
                            return Failed SignFailure.Timeout
                    }
            Dispose = fun () -> ValueTask.CompletedTask
        }

/// A member's DENIED, as the Dirk module reports it.
let denied (who: string) =
    Denied(
        $"{who} denied",
        {
            Signed = 0
            Denied = 1
            Failed = 0
            Errored = 0
        }
    )

let partialOf (index: uint64) (share: byte[]) = fun (req: SignRequest) -> Partial(index, sign share req.SigningRoot)

let private spec = lazy ((Eplix.Tests.SchedulerTests.harness ()).Spec)

let request (key: PubKey) (duty: Duty) =
    let gvr = root 1
    let spec = spec.Value
    Duty.request spec gvr key Priority.High (DateTimeOffset.UtcNow.AddSeconds 10.0) duty

let attestation =
    Duty.Attestation
        {
            Slot = 9UL
            Index = 0UL
            BeaconBlockRoot = root 3
            Source = { Epoch = 0UL; Root = root 4 }
            Target = { Epoch = 1UL; Root = root 5 }
        }

let group (members: FakeMember list) (m: int) =
    let b =
        Threshold.create
            "test"
            m
            [
                for x, i in List.zip members [ 1UL .. uint64 members.Length ] ->
                    {
                        Backend = x.Backend
                        Index = i
                        Budget = TimeSpan.FromSeconds 5.0
                    }
            ]
            TimeProvider.System
            Log.none

    b.Keys CancellationToken.None |> fun t -> t.Wait()
    b

/// A group over the given backends at the given indices; reads the key lists once.
let groupAt (members: (Backend * uint64) list) (m: int) =
    let b =
        Threshold.create
            "test"
            m
            [
                for x, i in members ->
                    {
                        Backend = x
                        Index = i
                        Budget = TimeSpan.FromSeconds 5.0
                    }
            ]
            TimeProvider.System
            Log.none

    b.Keys CancellationToken.None |> fun t -> t.Wait()
    b

/// A group whose members carry the given backend names, with its own clock and log.
let named (time: TimeProvider) (log: Log) (groupName: string) (members: (FakeMember * string) list) (m: int) =
    let b =
        Threshold.create
            groupName
            m
            [
                for (x, backendName), i in List.zip members [ 1UL .. uint64 members.Length ] ->
                    {
                        Backend = { x.Backend with Name = backendName }
                        Index = i
                        Budget = TimeSpan.FromSeconds 5.0
                    }
            ]
            time
            log

    b.Keys CancellationToken.None |> fun t -> t.Wait()
    b

/// Waits up to 3 s for a log line that matches.
let waitForLine (lines: Collections.Concurrent.ConcurrentQueue<string>) (p: string -> bool) =
    task {
        let sw = Diagnostics.Stopwatch.StartNew()

        while not (Seq.exists p lines) && sw.Elapsed < TimeSpan.FromSeconds 3.0 do
            do! Task.Delay 10

        return lines |> Seq.tryFind p
    }

/// Every line in the log is a Warn line, and there is at least one.
let expectWarn (lines: Collections.Concurrent.ConcurrentQueue<string>) =
    Expect.isNonEmpty lines "lines written"

    for l in lines do
        Expect.stringStarts l "WARN " $"a Warn line: {l}"

/// True when every surrogate in the text is part of a pair.
let pairsWhole (s: string) =
    let mutable ok = true

    for i in 0 .. s.Length - 1 do
        if Char.IsHighSurrogate s[i] && not (i + 1 < s.Length && Char.IsLowSurrogate s[i + 1]) then
            ok <- false

        if Char.IsLowSurrogate s[i] && not (i > 0 && Char.IsHighSurrogate s[i - 1]) then
            ok <- false

    ok

let verifies (key: PubKey) (req: SignRequest) (o: SignOutcome) =
    match o with
    | Signed s -> Bls.verify (ReadOnlySpan key.Bytes) (ReadOnlySpan req.SigningRoot.Bytes) (ReadOnlySpan s.Bytes)
    | _ -> false

[<Tests>]
let tests =
    testList
        "threshold"
        [
            testPropN
                "any m of n shares combine to the whole key's signature"
                25
                (fun (seed: int) (nRaw: byte) (mRaw: byte) ->
                    let n = 1 + int nRaw % 7
                    let m = 1 + int mRaw % n
                    let ids = [ for i in 1..n -> uint64 (i * 3 + abs (seed % 5) + 1) ]
                    let secret, shares = shamir seed m ids
                    let message = root (seed &&& 0xFFFF)

                    let chosen =
                        shares
                        |> List.sortBy (fun (id, _) -> (int id * 7919 + abs (seed % 1000)) % 101)
                        |> List.truncate m

                    let chosenIds = chosen |> List.map fst |> Array.ofList
                    let c = (Bls.lagrangeCoefficients chosenIds).Value
                    let combined = Bls.combineShares c [| for _, s in chosen -> (sign s message).Bytes |]

                    Expect.equal
                        (combined |> ValueOption.map Hex.encodeArray)
                        (ValueSome (sign secret message).Hex)
                        "combined equals whole")

            test "fewer than m shares do not give the whole key's signature" {
                let secret, shares = shamir 7 3 [ 1UL; 2UL; 3UL; 4UL ]
                let message = root 9
                let two = shares |> List.take 2
                let c = (Bls.lagrangeCoefficients [| for id, _ in two -> id |]).Value
                let combined = (Bls.combineShares c [| for _, s in two -> (sign s message).Bytes |]).Value
                Expect.notEqual (Hex.encodeArray combined) (sign secret message).Hex "2 of a 3-threshold key"
            }

            test "Lagrange coefficients refuse id 0 and repeated ids" {
                Expect.isTrue (Bls.lagrangeCoefficients [| 0UL; 1UL |]).IsNone "id 0"
                Expect.isTrue (Bls.lagrangeCoefficients [| 2UL; 2UL |]).IsNone "repeat"
                Expect.isTrue (Bls.lagrangeCoefficients [||]).IsNone "empty"
            }

            testPropN
                "the small-fraction combination equals the full-scalar one"
                25
                (fun (seed: int) (nRaw: byte) (mRaw: byte) (big: bool) ->
                    let n = 1 + int nRaw % 7
                    let m = 1 + int mRaw % n
                    // Small ids (every real group) and, sometimes, ids too large for the short form.
                    let ids =
                        [
                            for i in 1..n ->
                                if big then
                                    uint64 i * 0x1_0000_0001UL + uint64 (abs (seed % 97))
                                else
                                    uint64 (i * 2 + abs (seed % 3))
                        ]

                    let _, shares = shamir seed m ids
                    let message = root (seed &&& 0xFF)
                    let chosen = shares |> List.truncate m
                    let l = (Bls.lagrange [| for id, _ in chosen -> id |]).Value
                    let parts = [| for _, s in chosen -> (sign s message).Bytes |]
                    let fast = Bls.combine l parts |> ValueOption.map Hex.encodeArray
                    let full = Bls.combineShares l.Coefficients parts |> ValueOption.map Hex.encodeArray
                    Expect.equal fast full "same signature"

                    if not big && m <= 3 then
                        Expect.isTrue l.Numerators.IsSome "small ids give the short form")

            test "the short form of 2 of 3: numerators and denominators as expected" {
                let l12 = (Bls.lagrange [| 1UL; 2UL |]).Value
                Expect.isTrue l12.InverseDenominator.IsNone "ids 1 and 2: 2 s1 - s2, no division"
                let l13 = (Bls.lagrange [| 1UL; 3UL |]).Value
                Expect.isTrue l13.InverseDenominator.IsSome "ids 1 and 3: (3 s1 - s3) / 2"
            }

            test "a batch check accepts valid signatures over several messages and refuses one bad one" {
                let keys = [| for i in 1..70 -> scalar32 (BigInteger(1000 + i)) |]

                let item (i: int) (msg: Root) : Bls.BatchItem =
                    {
                        Key = pk (keys[i])
                        Message = msg
                        Signature = (sign (keys[i]) msg).Bytes
                    }

                let good = [| for i in 0..69 -> item i (root (i % 3)) |]
                Expect.isTrue (Bls.verifyBatch good) "70 valid signatures over 3 messages"
                Expect.isTrue (Bls.verifyBatch good[0..0]) "one"
                Expect.isTrue (Bls.verifyBatch [||]) "none"
                // A valid signature by another key, a signature over another message, garbage.
                let swapped = Array.copy good

                swapped[40] <-
                    { good[40] with
                        Signature = good[41].Signature
                    }

                Expect.isFalse (Bls.verifyBatch swapped) "a signature by another key"
                let otherMsg = Array.copy good
                otherMsg[5] <- item 5 (root 99)
                otherMsg[5] <- { otherMsg[5] with Message = root 2 }
                Expect.isFalse (Bls.verifyBatch otherMsg) "a signature over another message"
                let garbage = Array.copy good

                garbage[69] <-
                    { good[69] with
                        Signature = Array.create 96 0x11uy
                    }

                Expect.isFalse (Bls.verifyBatch garbage) "not a point"
                // Two signatures that are each wrong but whose sum is right still fail.
                let a, b = good[10], good[11]
                let sum = (Bls.aggregate [ a.Signature; b.Signature ]).Value
                let infinity = Array.init 96 (fun i -> if i = 0 then 0xC0uy else 0uy)
                let pair = Array.copy good
                pair[10] <- { a with Signature = sum }
                pair[11] <- { b with Signature = infinity }
                Expect.isFalse (Bls.verifyBatch pair) "an aggregate split across two entries"
            }

            testT "the batch verifier answers each signature, also when a batch holds a bad one" (fun () ->
                task {
                    let v = BatchVerifier(64)
                    let keys = [| for i in 1..200 -> scalar32 (BigInteger(5000 + i)) |]
                    let msg = root 7

                    let checks =
                        [|
                            for i in 0..199 ->
                                let s = if i % 50 = 13 then sign (keys[(i + 1) % 200]) msg else sign (keys[i]) msg
                                v.Verify(pk (keys[i]), msg, s.Bytes)
                        |]

                    let! results = Task.WhenAll checks

                    for i in 0..199 do
                        Expect.equal results[i] (i % 50 <> 13) $"signature {i}"
                })

            testT "2 of 3 with one member down signs" (fun () ->
                task {
                    let secret, shares = shamir 11 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(id, key, s, (fun _ -> Failed(Transport "down")), TimeSpan.Zero)
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                        ]

                    let b = group ms 2
                    let req = request key attestation
                    let! o = b.Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed: {o.Describe}"
                    let! keys = b.Keys CancellationToken.None

                    Expect.equal
                        (keys |> List.map (fun k -> k.Key))
                        [ key ]
                        "the validator key, listed by every member"
                })

            testT "a bad partial is dropped and the next member's partial used" (fun () ->
                task {
                    let secret, shares = shamir 12 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let wrong = scalar32 (BigInteger 12345)

                    let ms =
                        [
                            for id, s in shares ->
                                match id with
                                | 1UL -> FakeMember(id, key, s, partialOf id wrong, TimeSpan.Zero)
                                | 2UL -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                                | _ -> FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 100.0)
                        ]

                    let b = group ms 2
                    let req = request key attestation
                    let! o = b.Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed with members 2 and 3: {o.Describe}"
                })

            testT "1 of 3 denied: the other two sign" (fun () ->
                task {
                    let secret, shares = shamir 13 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 1UL then
                                    FakeMember(id, key, s, (fun _ -> Refused(denied "dirk1")), TimeSpan.Zero)
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 30.0)
                        ]

                    let req = request key attestation
                    let! o = (group ms 2).Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed: {o.Describe}"
                })

            testT "2 of 3 denied: Denied with the counts" (fun () ->
                task {
                    let secret, shares = shamir 17 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    // Member 3 signs first, so the tally is the same on every run.
                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                                else
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ -> Refused(denied $"dirk{id}")),
                                        TimeSpan.FromMilliseconds(30.0 * float id)
                                    )
                        ]

                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Refused(Denied(_, t)) ->
                        Expect.equal
                            t
                            {
                                Signed = 1
                                Denied = 2
                                Failed = 0
                                Errored = 0
                            }
                            "tally"
                    | x -> failtestf "expected Denied, got %s" x.Describe
                })

            testT "2 of 3 refused only by policy: PolicyDenied, as one signer would answer" (fun () ->
                task {
                    let secret, shares = shamir 19 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                                else
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ -> Refused(PolicyDenied $"dirk{id} rejected the client certificate")),
                                        TimeSpan.FromMilliseconds(30.0 * float id)
                                    )
                        ]

                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Refused(PolicyDenied why) ->
                        Expect.stringContains why "1 signed, 2 denied" "the counts are in the reason"
                    | x -> failtestf "expected PolicyDenied, got %s" x.Describe
                })

            testT "one plain denial among policy refusals: still Denied" (fun () ->
                task {
                    let secret, shares = shamir 20 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let answers =
                        Map
                            [
                                1UL, (fun _ -> Refused(denied "dirk1"))
                                2UL, (fun _ -> Refused(PolicyDenied "dirk2 rejected the client certificate"))
                                3UL, partialOf 3UL (snd shares[2])
                            ]

                    let ms =
                        [
                            for id, s in shares ->
                                FakeMember(id, key, s, answers[id], TimeSpan.FromMilliseconds(30.0 * float (3UL - id)))
                        ]

                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Refused(Denied(_, t)) ->
                        Expect.equal
                            t
                            {
                                Signed = 1
                                Denied = 2
                                Failed = 0
                                Errored = 0
                            }
                            "tally"
                    | x -> failtestf "expected Denied, got %s" x.Describe
                })

            testT "denied, failed and errored members: Denied counts each" (fun () ->
                task {
                    let secret, shares = shamir 18 2 [ 1UL; 2UL; 3UL; 4UL ]
                    let key = pk secret

                    let answers =
                        Map
                            [
                                1UL, partialOf 1UL (snd shares[0])
                                2UL, (fun _ -> Refused(denied "dirk2"))
                                3UL, (fun _ -> Failed(Internal "dirk3 failed to sign"))
                                4UL, (fun _ -> Failed(Transport "dirk4 down"))
                            ]

                    let ms =
                        [
                            for id, s in shares ->
                                FakeMember(id, key, s, answers[id], TimeSpan.FromMilliseconds(30.0 * float (id - 1UL)))
                        ]

                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Refused(Denied(_, t)) ->
                        Expect.equal
                            t
                            {
                                Signed = 1
                                Denied = 1
                                Failed = 1
                                Errored = 1
                            }
                            "tally"
                    | x -> failtestf "expected Denied, got %s" x.Describe
                })

            testT "one member says slashable but m sign: the group signs" (fun () ->
                task {
                    let secret, shares = shamir 19 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 1UL then
                                    FakeMember(id, key, s, (fun _ -> Refused(Slashable "double vote")), TimeSpan.Zero)
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 30.0)
                        ]

                    let req = request key attestation
                    let! o = (group ms 2).Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed: {o.Describe}"
                })

            testT "too few signed and one member says slashable: Slashable, not Denied" (fun () ->
                task {
                    let secret, shares = shamir 20 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let answers =
                        Map
                            [
                                1UL, (fun _ -> Refused(denied "dirk1"))
                                2UL, (fun _ -> Refused(Slashable "double vote"))
                                3UL, partialOf 3UL (snd shares[2])
                            ]

                    let ms = [ for id, s in shares -> FakeMember(id, key, s, answers[id], TimeSpan.Zero) ]
                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Refused(Slashable why) -> Expect.equal why "double vote" "the member's reason"
                    | x -> failtestf "expected Slashable, got %s" x.Describe
                })

            testT "the pipeline halts a key on a remote Slashable and only skips on Denied" (fun () ->
                task {
                    let keyOf (i: int) = pk (scalar32 (BigInteger(4000 + i)))
                    let slashKey, denyKey = keyOf 1, keyOf 2

                    let answer (req: SignRequest) =
                        if req.Key = slashKey then
                            Refused(Slashable "remote signer: surround vote")
                        else
                            Refused(denied "dirk")

                    let backend =
                        {
                            Name = "remote"
                            Capabilities = caps
                            Keys = fun _ -> Task.FromResult []
                            Health = fun _ -> Task.FromResult Up
                            Sign = fun req _ -> Task.FromResult(answer req)
                            Dispose = fun () -> ValueTask.CompletedTask
                        }

                    use db =
                        match
                            Eplix.Slashing.SlashingDb.Open(
                                new Eplix.Slashing.FileMarkFile(IO.Path.Combine(tempDir (), "s.db")),
                                root 1
                            )
                        with
                        | Ok db -> db
                        | Error err -> failwith err

                    db.RegisterKeys [ for k in [ slashKey; denyKey ] -> k, Eplix.Slashing.KeyOrigin.StartedEmpty ]
                    |> ignore

                    let registry = KeyRegistry()

                    for k in [ slashKey; denyKey ] do
                        registry.Add(k, backend) |> ignore
                        registry.SetState(k, KeyState.Active)

                    let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none)

                    let! outs =
                        pipeline.SignBurst(
                            [| request slashKey attestation; request denyKey attestation |],
                            CancellationToken.None
                        )

                    Expect.isTrue
                        (match outs[0] with
                         | Refused(Slashable _) -> true
                         | _ -> false)
                        $"slashable: {outs[0].Describe}"

                    Expect.isTrue
                        (match (registry.TryGet slashKey).Value.State with
                         | KeyState.Halted _ -> true
                         | _ -> false)
                        "an explicit Slashable halts the key"

                    Expect.isTrue
                        (match outs[1] with
                         | Refused(Denied _) -> true
                         | _ -> false)
                        $"denied: {outs[1].Describe}"

                    Expect.equal (registry.TryGet denyKey).Value.State KeyState.Active "a Denied leaves the key active"
                    Expect.equal (registry.Denials denyKey) 1L "the denial is counted"
                })

            testT "two of three down: a transport failure" (fun () ->
                task {
                    let secret, shares = shamir 14 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 1UL then
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                                else
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ -> Failed(Transport $"dirk{id} down")),
                                        TimeSpan.Zero
                                    )
                        ]

                    let! o = (group ms 2).Sign (request key attestation) CancellationToken.None

                    match o with
                    | Failed(Transport _) -> ()
                    | x -> failtestf "expected a transport failure, got %s" x.Describe
                })

            testT "slashable kinds let stragglers finish; other kinds cancel them" (fun () ->
                task {
                    let secret, shares = shamir 15 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let mk () =
                        [
                            for id, s in shares ->
                                FakeMember(
                                    id,
                                    key,
                                    s,
                                    partialOf id s,
                                    (if id = 3UL then TimeSpan.FromMilliseconds 300.0 else TimeSpan.Zero)
                                )
                        ]

                    let ms = mk ()
                    let req = request key attestation
                    let! o = (group ms 2).Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) "attestation signed by two"
                    do! Task.Delay 600
                    Expect.equal ms[2].Finished 1 "the slow member still signed the attestation"
                    let ms2 = mk ()
                    let req2 = request key (Duty.RandaoReveal 1UL)
                    let! o2 = (group ms2 2).Sign req2 CancellationToken.None
                    Expect.isTrue (verifies key req2 o2) "RANDAO signed by two"
                    do! Task.Delay 600
                    Expect.equal ms2[2].Cancelled 1 "the slow member's RANDAO request was cancelled"
                })

            testPropN
                "a group of n members signs with the whole key's signature exactly when m give good partials"
                60
                (fun (seed: int) (nRaw: byte) (mRaw: byte) ->
                    let n = 2 + int nRaw % 6
                    let m = 1 + int mRaw % n
                    let ids = [ for i in 1..n -> uint64 (i + abs (seed % 4)) ]
                    let secret, shares = shamir seed m ids
                    let key = pk secret
                    let rnd = Random seed
                    let wrong = scalar32 (BigInteger(rnd.Next(1, Int32.MaxValue)))
                    // 0: a good partial, 1: a partial by another key, 2: a refusal, 3: down.
                    let kinds = [ for _ in 1..n -> if rnd.Next 3 = 0 then rnd.Next(1, 4) else 0 ]

                    let ms =
                        [
                            for (id, s), k in List.zip shares kinds ->
                                let answer =
                                    match k with
                                    | 0 -> partialOf id s
                                    | 1 -> partialOf id wrong
                                    | 2 -> fun _ -> Refused(PolicyDenied "no")
                                    | _ -> fun _ -> Failed(Transport "down")

                                FakeMember(id, key, s, answer, TimeSpan.FromMilliseconds(float (rnd.Next 5)))
                        ]

                    let b = groupAt [ for x, (id, _) in List.zip ms shares -> x.Backend, id ] m
                    let req = request key (Duty.RandaoReveal(uint64 (abs (seed % 1000))))
                    let o = (b.Sign req CancellationToken.None).Result
                    let good = kinds |> List.filter ((=) 0) |> List.length

                    match o with
                    | Signed s ->
                        Expect.isGreaterThanOrEqual good m "signed only with m good partials"
                        Expect.equal s.Hex (sign secret req.SigningRoot).Hex "the whole key's signature"
                    | o -> Expect.isLessThan good m $"{good} good of {n}, {m} needed, yet: {o.Describe}")

            testT "a member at the wrong index: another set of m partials verifies" (fun () ->
                task {
                    let secret, shares = shamir 31 3 [ 1UL .. 5UL ]
                    let key = pk secret
                    // Member 3 holds the share at x = 3 but is configured at index 6. Its share check
                    // passes (the share key is its own), so only another index set finds the signature.
                    let ms =
                        [
                            for id, s in shares ->
                                FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds(10.0 * float id))
                        ]

                    let indices = [ 1UL; 2UL; 6UL; 4UL; 5UL ]
                    let b = groupAt [ for x, i in List.zip ms indices -> x.Backend, i ] 3
                    let req = request key attestation
                    let! o = b.Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed by 1, 2 and 4: {o.Describe}"
                })

            testT "no share keys known and one bad partial: another set verifies" (fun () ->
                task {
                    let secret, shares = shamir 32 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let wrong = scalar32 (BigInteger 777)

                    let blind (x: FakeMember) =
                        { x.Backend with
                            Keys = fun _ -> Task.FromResult [ { Key = key; Share = ValueNone } ]
                        }

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 1UL then
                                    FakeMember(id, key, s, partialOf id wrong, TimeSpan.Zero)
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds(20.0 * float id))
                        ]

                    let b = groupAt [ for x, i in List.zip ms [ 1UL; 2UL; 3UL ] -> blind x, i ] 2
                    let req = request key attestation
                    let! o = b.Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed by 2 and 3: {o.Describe}"
                })

            testT "when no set of m combines, the group fails once every member answered" (fun () ->
                task {
                    let secret, shares = shamir 33 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let ms = [ for id, s in shares -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero) ]
                    // Every index is wrong: the shares sit at 1, 2, 3.
                    let b = groupAt [ for x, i in List.zip ms [ 7UL; 8UL; 9UL ] -> x.Backend, i ] 2

                    match! b.Sign (request key attestation) CancellationToken.None with
                    | Failed(Internal why) -> Expect.stringContains why "combine" "names the combination"
                    | o -> failtestf "expected an internal failure, got %s" o.Describe
                })

            test "a group refuses two members at one index, index 0 and a threshold above n" {
                let secret, shares = shamir 34 2 [ 1UL; 2UL; 3UL ]
                let key = pk secret

                let bs =
                    [
                        for id, s in shares -> (FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)).Backend
                    ]

                let mk (ids: uint64 list) m () =
                    Threshold.create
                        "t"
                        m
                        [
                            for b, i in List.zip bs ids ->
                                {
                                    Backend = b
                                    Index = i
                                    Budget = TimeSpan.FromSeconds 1.0
                                }
                        ]
                        TimeProvider.System
                        Log.none
                    |> ignore

                Expect.throws (mk [ 1UL; 2UL; 2UL ] 2) "duplicate index"
                Expect.throws (mk [ 1UL; 2UL; 3UL ] 4) "4 of 3"
                Expect.throws (mk [ 1UL; 2UL; 3UL ] 0) "0 of 3"
            }

            testT "a partial reported under another index is combined at the member's configured index" (fun () ->
                task {
                    let secret, shares = shamir 35 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                // Member 2 claims index 9 for its partial; the config says 2, which is right.
                                let claimed = if id = 2UL then 9UL else id

                                FakeMember(
                                    id,
                                    key,
                                    s,
                                    (fun req -> Partial(claimed, sign s req.SigningRoot)),
                                    TimeSpan.FromMilliseconds(10.0 * float id)
                                )
                        ]

                    let req = request key (Duty.RandaoReveal 3UL)
                    let! o = (group ms 2).Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) $"signed: {o.Describe}"
                })

            testT "a member's queue serves the high class first and every Nth slot to a low request" (fun () ->
                task {
                    let g = MemberGate(1, 3)
                    let! first = g.Enter(Priority.High, CancellationToken.None)
                    Expect.isTrue first "a free slot"
                    let order = Collections.Concurrent.ConcurrentQueue<string>()

                    let wait (p: Priority) (tag: string) (ct: CancellationToken) =
                        task {
                            let! ok = g.Enter(p, ct)

                            if ok then
                                order.Enqueue tag
                                g.Leave()

                            return ok
                        }

                    use gone = new CancellationTokenSource()

                    let waiting =
                        [
                            wait Priority.Low "l1" CancellationToken.None
                            wait Priority.Low "dropped" gone.Token
                            wait Priority.Low "l2" CancellationToken.None
                            wait Priority.High "h1" CancellationToken.None
                            wait Priority.High "h2" CancellationToken.None
                            wait Priority.High "h3" CancellationToken.None
                            wait Priority.High "h4" CancellationToken.None
                        ]

                    gone.Cancel()
                    g.Leave()
                    let! oks = Task.WhenAll waiting

                    Expect.equal
                        (List.ofSeq order)
                        [ "h1"; "h2"; "l1"; "h3"; "h4"; "l2" ]
                        "two high, then the oldest low (every 3rd), the rest"

                    Expect.equal
                        oks
                        [| true; false; true; true; true; true; true |]
                        "the cancelled waiter never got a slot"

                    Expect.equal g.InFlight 0 "every slot back"
                })

            testT
                "a busy member's queued non-slashable request is dropped once m are in; votes still reach it"
                (fun () ->
                    task {
                        let secret, shares = shamir 36 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret

                        let one (x: FakeMember) =
                            { x.Backend with
                                Capabilities =
                                    { x.Backend.Capabilities with
                                        MaxInFlight = 1
                                    }
                            }

                        let mk (slow: float) =
                            [
                                for id, s in shares ->
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        partialOf id s,
                                        TimeSpan.FromMilliseconds(if id = 3UL then slow else 10.0)
                                    )
                            ]

                        let ms = mk 200.0
                        let b = groupAt [ for x, i in List.zip ms [ 1UL; 2UL; 3UL ] -> one x, i ] 2
                        // A vote holds the slow member's only slot; two RANDAO requests queue behind it.
                        let vote = request key attestation
                        let voteTask = b.Sign vote CancellationToken.None
                        do! Task.Delay 30
                        let reqs = [ for e in 1UL .. 2UL -> request key (Duty.RandaoReveal e) ]
                        let! outs = reqs |> List.map (fun r -> b.Sign r CancellationToken.None) |> Task.WhenAll

                        for r, o in List.zip reqs (List.ofArray outs) do
                            Expect.isTrue (verifies key r o) $"RANDAO signed: {o.Describe}"

                        let! v = voteTask
                        Expect.isTrue (verifies key vote v) "vote signed"
                        do! Task.Delay 400

                        Expect.equal
                            (ms[2].Finished, ms[2].Cancelled)
                            (1, 0)
                            "only the vote reached the slow member; the queued RANDAO requests were dropped"
                        // Votes keep their stragglers: all three reach the slow member, one after the other.
                        let ms2 = mk 100.0
                        let b2 = groupAt [ for x, i in List.zip ms2 [ 1UL; 2UL; 3UL ] -> one x, i ] 2

                        let data =
                            match attestation with
                            | Duty.Attestation d -> d
                            | _ -> failwith "an attestation"

                        let votes =
                            [
                                for slot in 1UL .. 3UL -> request key (Duty.Attestation { data with Slot = slot })
                            ]

                        let! _ = votes |> List.map (fun r -> b2.Sign r CancellationToken.None) |> Task.WhenAll
                        // Three 100 ms signatures one after the other; under load they take longer, so wait
                        // for them (5 s at most) instead of a fixed 600 ms.
                        let sw = Diagnostics.Stopwatch.StartNew()

                        while ms2[2].Finished < 3 && sw.Elapsed < TimeSpan.FromSeconds 5.0 do
                            do! Task.Delay 20

                        Expect.equal ms2[2].Finished 3 "every vote reached the slow member"
                    })

            testT
                "members in their restart floor: degraded, then not ready until the floor ends, then up again"
                (fun () ->
                    task {
                        let secret, shares = shamir 37 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret
                        let floors = Collections.Concurrent.ConcurrentDictionary<uint64, uint64>()

                        let answer (id: uint64) (s: byte[]) =
                            fun (req: SignRequest) ->
                                match floors.TryGetValue id with
                                | true, e when req.Duty.IsSlashable -> Refused(Refusal.NotReadyUntil(ValueSome e))
                                | _ -> Partial(id, sign s req.SigningRoot)

                        let ms = [ for id, s in shares -> FakeMember(id, key, s, answer id s, TimeSpan.Zero) ]
                        let b = group ms 2

                        let vote () =
                            task {
                                let! _ = b.Sign (request key attestation) CancellationToken.None
                                do! Task.Delay 50
                            }

                        floors[3UL] <- 12UL
                        do! vote ()
                        let! h1 = b.Health CancellationToken.None

                        Expect.isTrue
                            (match h1 with
                             | Degraded _ -> true
                             | _ -> false)
                            "one member in its floor: degraded"

                        floors[2UL] <- 15UL
                        do! vote ()
                        let! h2 = b.Health CancellationToken.None

                        Expect.equal
                            h2
                            (Health.NotReadyUntil 12UL)
                            "two in their floors: votes wait for the first floor to end"

                        let! r = b.Sign (request key (Duty.RandaoReveal 2UL)) CancellationToken.None

                        Expect.isTrue
                            (match r with
                             | Signed _ -> true
                             | _ -> false)
                            "RANDAO still signs"

                        floors.Clear()
                        do! vote ()
                        let! h3 = b.Health CancellationToken.None
                        Expect.equal h3 Up "a signed vote clears the floor"
                    })

            testT "health follows the number of members up" (fun () ->
                task {
                    let secret, shares = shamir 16 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let down (x: FakeMember) =
                        { x.Backend with
                            Health = fun _ -> Task.FromResult(Down "off")
                        }

                    let ms = [ for id, s in shares -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero) ]

                    let mk (backends: Backend list) =
                        Threshold.create
                            "h"
                            2
                            [
                                for b, i in List.zip backends [ 1UL; 2UL; 3UL ] ->
                                    {
                                        Backend = b
                                        Index = i
                                        Budget = TimeSpan.FromSeconds 1.0
                                    }
                            ]
                            TimeProvider.System
                            Log.none

                    let! all = (mk [ for x in ms -> x.Backend ]).Health CancellationToken.None
                    Expect.equal all Up "3 of 3"
                    let! one = (mk [ ms[0].Backend; ms[1].Backend; down ms[2] ]).Health CancellationToken.None

                    Expect.isTrue
                        (match one with
                         | Degraded _ -> true
                         | _ -> false)
                        "2 of 3: degraded"

                    let! two = (mk [ ms[0].Backend; down ms[1]; down ms[2] ]).Health CancellationToken.None

                    Expect.isTrue
                        (match two with
                         | Down _ -> true
                         | _ -> false)
                        "1 of 3: down"
                })

            test "the registry routes a key whole and split nowhere, in either order" {
                let secret, shares = shamir 970 2 [ 1UL; 2UL; 3UL ]
                let key = pk secret
                let ms = [ for i, s in shares -> FakeMember(i, key, s, partialOf i s, TimeSpan.Zero) ]
                let whole = { ms[0].Backend with Name = "whole" }

                for first, second in [ whole, group ms 2; group ms 2, whole ] do
                    let registry = KeyRegistry()
                    Expect.isTrue (registry.Add(key, first)) "the first route"
                    Expect.isFalse (registry.Add(key, second)) "the second route is not added"

                    match registry.TryGet key with
                    | ValueSome k ->
                        Expect.equal k.State KeyState.Removed $"{first.Name} then {second.Name}: neither route signs"
                    | ValueNone -> ()

                    Expect.isFalse (registry.Revive(key, first)) "nor comes back"
                    Expect.equal (registry.Refused |> List.map fst) [ key ] "listed as refused"
            }

            test "a refused key is taken out and stays out; another backend of the same kind does not refuse" {
                let secret, shares = shamir 971 2 [ 1UL; 2UL; 3UL ]
                let key = pk secret
                let ms = [ for i, s in shares -> FakeMember(i, key, s, partialOf i s, TimeSpan.Zero) ]
                let registry = KeyRegistry()
                Expect.isTrue (registry.Add(key, group ms 2)) "added"
                Expect.isFalse (registry.Add(key, group ms 2)) "a second group keeps the first route"
                Expect.equal (registry.TryGet key).Value.State KeyState.Discovered "two groups are no conflict"
                registry.Refuse(key, "test")
                Expect.equal (registry.TryGet key).Value.State KeyState.Removed "taken out"
                Expect.isFalse (registry.Revive(key, group ms 2)) "an import does not bring it back"
                Expect.equal registry.Refused [ key, "test" ] "the reason"
            }

            test "a refused key stays removed whatever state a caller sets" {
                let secret, shares = shamir 972 2 [ 1UL; 2UL; 3UL ]
                let key = pk secret
                let ms = [ for i, s in shares -> FakeMember(i, key, s, partialOf i s, TimeSpan.Zero) ]
                let registry = KeyRegistry()
                registry.Add(key, group ms 2) |> ignore
                registry.Refuse(key, "test")

                for state in
                    [
                        KeyState.HistoryChecked
                        KeyState.DoppelgangerWait
                        KeyState.Active
                        KeyState.Halted "x"
                        KeyState.Slashed "x"
                        KeyState.Draining
                    ] do
                    registry.SetState(key, state)
                    Expect.equal (registry.TryGet key).Value.State KeyState.Removed $"{state}: still removed"
                // An unrefused removed key still takes a state, as a drain's callers expect.
                let other = pk (fst (shamir 973 2 [ 1UL; 2UL; 3UL ]))
                registry.Add(other, group ms 2) |> ignore
                registry.SetState(other, KeyState.Removed)
                registry.SetState(other, KeyState.Active)
                Expect.equal (registry.TryGet other).Value.State KeyState.Active "not refused: the state changes"
            }

            test "ShareChecks: an unchanged share set is not checked again; a changed set or threshold is" {
                let secret, shares = shamir 974 2 [ 1UL; 2UL; 3UL ]
                let key = pk secret
                let keys = [ for i, s in shares -> i, pk s ]
                let checks = Threshold.ShareChecks()
                Expect.equal (checks.Check(2, key, keys)) (Ok()) "one split"
                Expect.equal checks.Runs 1L "checked"
                Expect.equal (checks.Check(2, key, List.rev keys)) (Ok()) "same set, other order"
                Expect.equal checks.Runs 1L "cached within a round"
                checks.Sweep()
                Expect.equal (checks.Check(2, key, keys)) (Ok()) "next round"
                Expect.equal checks.Runs 1L "cached across a round"
                let other = resplit 975 secret 2 [ 3UL ]
                let mixed = [ for i, s in keys -> if i = 3UL then i, pk (snd other.Head) else i, s ]

                match checks.Check(2, key, mixed) with
                | Error e -> Expect.stringContains e "member 3:" "a changed share is checked"
                | Ok() -> failtest "a share of another split passed"

                Expect.equal checks.Runs 2L "checked again"
                Expect.isError (checks.Check(2, key, mixed)) "the error is kept"
                Expect.equal checks.Runs 2L "and cached"
                Expect.equal (checks.Check(2, key, keys |> List.truncate 2)) (Ok()) "a share gone"
                Expect.equal checks.Runs 3L "a smaller set is checked"
                checks.Check(3, key, keys) |> ignore
                Expect.equal checks.Runs 4L "a changed threshold is checked"
                checks.Sweep()
                checks.Sweep()
                checks.Check(3, key, keys) |> ignore
                Expect.equal checks.Runs 5L "a key no round asked about is dropped"
            }

            testPropN
                "checkShares: every share of one split passes; one share of another split is named"
                40
                (fun (seed: int) (nRaw: byte) (mRaw: byte) (pick: byte) ->
                    let n = 1 + int nRaw % 7
                    let m = 1 + int mRaw % n
                    let ids = [ for i in 1..n -> uint64 (i * 2 + abs (seed % 3)) ]
                    let secret, shares = shamir seed m ids
                    let key = pk secret
                    let keys = [ for i, s in shares -> i, pk s ]
                    Expect.equal (Threshold.checkShares m key keys) (Ok()) $"{m} of {n}: one split"
                    // A share of another split at one index. With m = 1 every split is the key itself;
                    // with m = n no m shares are left without it, and the error names no member.
                    if 1 < m && m < n then
                        let bad = ids[int pick % n]
                        let other = resplit (seed + 1) secret m [ bad ]
                        let mixed = [ for i, s in keys -> if i = bad then i, pk (snd other.Head) else i, s ]

                        match Threshold.checkShares m key mixed with
                        | Error e -> Expect.stringContains e $"member {bad}:" $"{m} of {n}: names member {bad}"
                        | r -> failtestf "%d of %d, member %d off: %A" m n bad r
                    // Fewer than m shares: nothing to check.
                    Expect.equal (Threshold.checkShares m key (List.truncate (m - 1) keys)) (Ok()) "fewer than m"
                    // Shares of a different key never pass. Random takes |seed|, so seed + 2 can repeat it.
                    let another = fst (shamir (seed + 2) m ids)

                    if another <> secret then
                        Expect.isError (Threshold.checkShares m (pk another) keys) "another key")

            test "checkShares: a bad share at the lowest index of a large group is named" {
                // 6 of 11: the first 64 index sets in lexicographic order all hold the lowest index.
                let ids = [ 1UL .. 11UL ]
                let secret, shares = shamir 4242 6 ids
                let key = pk secret
                let keys = [ for i, s in shares -> i, pk s ]
                Expect.equal (Threshold.checkShares 6 key keys) (Ok()) "one split"

                for bad in [ 1UL; 4UL; 7UL; 11UL ] do
                    let other = resplit 4243 secret 6 [ bad ]
                    let mixed = [ for i, s in keys -> if i = bad then i, pk (snd other.Head) else i, s ]

                    match Threshold.checkShares 6 key mixed with
                    | Error e -> Expect.stringContains e $"member {bad}:" $"names member {bad}"
                    | r -> failtestf "member %d off: %A" bad r
            }

            test "checkSharesAll and ShareChecks.CheckAll: parallel gives the results of a check one by one" {
                // Good keys, a share of another split, a wrong share, fewer than m, shares of another key.
                let items =
                    [|
                        for seed in 980..1003 do
                            let m, ids = if seed % 2 = 0 then 2, [ 1UL; 2UL; 3UL ] else 3, [ 1UL .. 5UL ]
                            let secret, shares = shamir seed m ids
                            let key = pk secret
                            let keys = [ for i, s in shares -> i, pk s ]

                            match seed % 6 with
                            | 0
                            | 1 -> struct (m, key, keys)
                            | 2 ->
                                let other = resplit (seed + 100) secret m [ 3UL ]
                                struct (m, key, [ for i, s in keys -> if i = 3UL then i, pk (snd other.Head) else i, s ])
                            | 3 ->
                                struct (m,
                                        key,
                                        [
                                            for i, s in keys ->
                                                if i = 2UL then i, pk (fst (shamir (seed + 200) 1 [ 1UL ])) else i, s
                                        ])
                            | 4 -> struct (m, key, List.truncate (m - 1) keys)
                            | _ -> struct (m, pk (fst (shamir (seed + 300) m ids)), keys)
                    |]

                let oneByOne = items |> Array.map (fun struct (m, key, shares) -> Threshold.checkShares m key shares)
                Expect.equal (oneByOne |> Array.filter Result.isError |> Array.length) 12 "the mix has errors"

                for width in [ 1; 2; 8 ] do
                    Expect.equal
                        (Threshold.checkSharesAll width CancellationToken.None items)
                        oneByOne
                        $"checkSharesAll at {width}"

                    let checks = Threshold.ShareChecks(width, width)
                    Expect.equal (checks.CheckAll(items, CancellationToken.None)) oneByOne $"CheckAll at {width}"
                    Expect.equal checks.Runs (int64 items.Length) "each key checked once"
                    checks.Sweep()

                    Expect.equal
                        (checks.CheckAll(Array.rev items, CancellationToken.None))
                        (Array.rev oneByOne)
                        "cached, in the order asked"

                    Expect.equal checks.Runs (int64 items.Length) "nothing checked again"
                // After the first Sweep the refresh width applies; the results stay the same.
                let checks = Threshold.ShareChecks(8, 1)
                checks.Sweep()
                Expect.equal (checks.CheckAll(items, CancellationToken.None)) oneByOne "refresh width"
            }

            test "checkSharesAll and ShareChecks.CheckAll: shutdown cancels the checks" {
                let secret, shares = shamir 990 3 [ 1UL .. 5UL ]
                let item = struct (3, pk secret, [ for i, s in shares -> i, pk s ])
                use cancelled = new CancellationTokenSource()
                cancelled.Cancel()

                for width in [ 1; 8 ] do
                    Expect.throwsT<OperationCanceledException>
                        (fun () -> Threshold.checkSharesAll width cancelled.Token [| item; item |] |> ignore)
                        $"cancelled at {width}"

                    let checks = Threshold.ShareChecks(width, width)

                    Expect.throwsT<OperationCanceledException>
                        (fun () -> checks.CheckAll([| item; item |], cancelled.Token) |> ignore)
                        $"CheckAll cancelled at {width}"

                    Expect.equal checks.Runs 0L "no result kept"

                    Expect.equal
                        (checks.CheckAll([| item |], CancellationToken.None))
                        [| Ok() |]
                        "checked on the next call"
                // Cancelled while the checks run: the call stops early with the cancellation.
                use later = new CancellationTokenSource()
                let many = Array.replicate 5000 item
                later.CancelAfter(TimeSpan.FromMilliseconds 20.0)
                let sw = Diagnostics.Stopwatch.StartNew()

                Expect.throwsT<OperationCanceledException>
                    (fun () -> Threshold.checkSharesAll 8 later.Token many |> ignore)
                    "cancelled mid-way"

                Expect.isLessThan sw.Elapsed (TimeSpan.FromSeconds 5.0) "stops before the rest"
            }

            testT
                "not enough signatures: the line names each member with its answer; each failed member gets a line"
                (fun () ->
                    task {
                        let secret, shares = shamir 41 3 [ 1UL .. 4UL ]
                        let key = pk secret
                        let log, lines = Log.memory ()

                        let answer (id: uint64) (s: byte[]) =
                            match id with
                            | 1UL ->
                                FakeMember(
                                    id,
                                    key,
                                    s,
                                    (fun _ -> Failed(Transport "connection refused")),
                                    TimeSpan.Zero
                                )
                            | 2UL -> FakeMember(id, key, s, (fun _ -> Refused(denied "dirk2")), TimeSpan.Zero)
                            | 3UL -> FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0)
                            | _ ->
                                FakeMember(
                                    id,
                                    key,
                                    s,
                                    (fun _ -> Failed(Internal "enclave error")),
                                    TimeSpan.FromMilliseconds 200.0
                                )

                        let ms = [ for id, s in shares -> answer id s, $"mn-{id}" ]
                        let b = named TimeProvider.System log "tee 3 of 4" ms 3
                        let! o = b.Sign (request key attestation) CancellationToken.None

                        Expect.isTrue
                            (match o with
                             | Refused(Denied _) -> true
                             | _ -> false)
                            $"denied: {o.Describe}"

                        let line = lines |> Seq.find (fun l -> l.Contains "not enough signatures")

                        Expect.stringContains
                            line
                            "tee 3 of 4: not enough signatures for the attestation of"
                            "group and duty"

                        Expect.stringContains line "0 signed, 1 denied, 0 failed, 1 errored" "tally"

                        Expect.stringContains
                            line
                            "mn-1 errored (transport: connection refused)"
                            "member 1 by name and reason"

                        Expect.stringContains line "mn-2 denied (dirk2 denied)" "member 2 by name and reason"
                        Expect.stringContains line "mn-3 pending, mn-4 pending" "members still out"
                        let! one = waitForLine lines (fun l -> l.Contains "member mn-1 did not sign")

                        Expect.stringContains
                            (defaultArg one "")
                            $"did not sign the attestation of {key.Short}, errored: transport: connection refused"
                            "member 1 line"

                        let! two = waitForLine lines (fun l -> l.Contains "member mn-2 did not sign")
                        Expect.stringContains (defaultArg two "") "denied: dirk2 denied" "member 2 line"
                        // Attestations keep stragglers: member 4 fails after the result and is logged too.
                        let! four = waitForLine lines (fun l -> l.Contains "member mn-4 did not sign")

                        Expect.stringContains
                            (defaultArg four "")
                            "failed: internal: enclave error, after the group's result"
                            "member 4 line"

                        Expect.isFalse
                            (lines |> Seq.exists (fun l -> l.Contains "member mn-3 did not sign"))
                            "member 3 has not failed"

                        expectWarn lines
                    })

            testT "when no set of m combines, the line names each member" (fun () ->
                task {
                    let secret, shares = shamir 42 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()
                    let ms = [ for id, s in shares -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero) ]

                    let b =
                        Threshold.create
                            "g"
                            2
                            [
                                for x, i in List.zip ms [ 7UL; 8UL; 9UL ] ->
                                    {
                                        Backend = { x.Backend with Name = $"s{i}" }
                                        Index = i
                                        Budget = TimeSpan.FromSeconds 5.0
                                    }
                            ]
                            TimeProvider.System
                            log

                    let! _ = b.Keys CancellationToken.None
                    let! _ = b.Sign (request key attestation) CancellationToken.None
                    let line = lines |> Seq.find (fun l -> l.Contains "combine to the key")
                    Expect.stringContains line "s7 signed, s8 signed, s9 signed" "every member by name"
                    expectWarn lines
                })

            testT "member failure lines: one per member, kind and reason per 5 minutes, then the count" (fun () ->
                task {
                    let secret, shares = shamir 43 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let time = FakeTimeProvider(DateTimeOffset.UtcNow)
                    let log, lines = Log.memory ()

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(id, key, s, (fun _ -> Failed(Transport "down")), TimeSpan.Zero), "m3"
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 20.0), $"m{id}"
                        ]

                    let b = named time log "g" ms 2
                    // Deadlines on the test clock, which the test moves on by minutes.
                    let request key duty =
                        { request key duty with
                            Deadline = time.GetUtcNow().AddSeconds 10.0
                        }

                    let memberLines () = lines |> Seq.filter (fun l -> l.Contains "member m3") |> List.ofSeq

                    let signRandao () =
                        task {
                            let req = request key (Duty.RandaoReveal 1UL)
                            let! o = b.Sign req CancellationToken.None
                            Expect.isTrue (verifies key req o) $"the group still signs: {o.Describe}"
                        }

                    for _ in 1..5 do
                        do! signRandao ()

                    Expect.equal (memberLines ()).Length 1 "one line for five failures"

                    Expect.stringContains
                        (memberLines ()).Head
                        "g: member m3 did not sign the randao_reveal of"
                        "names member and kind"

                    Expect.stringContains (memberLines ()).Head "errored: transport: down" "the reason"
                    // Another duty kind is another key of the limit.
                    let! _ = b.Sign (request key attestation) CancellationToken.None
                    let! _ = waitForLine lines (fun l -> l.Contains "m3 did not sign the attestation")
                    Expect.equal (memberLines ()).Length 2 "the attestation has its own line"
                    time.Advance(TimeSpan.FromMinutes 5.0)
                    do! signRandao ()
                    Expect.equal (memberLines ()).Length 3 "a line again after 5 minutes"

                    Expect.stringContains
                        (List.last (memberLines ()))
                        "; 4 more transport answers since"
                        "the count of lines not written"

                    for _ in 1..3 do
                        do! signRandao ()

                    Expect.equal (memberLines ()).Length 3 "suppressed again"
                    // No more randao failures; the next failure of another kind reports the 3 left over.
                    time.Advance(TimeSpan.FromMinutes 6.0)
                    let! _ = b.Sign (request key attestation) CancellationToken.None
                    let! left = waitForLine lines (fun l -> l.Contains "3 more transport answers on")

                    Expect.stringContains
                        (defaultArg left "")
                        "g: member m3: 3 more transport answers on the randao_reveal since"
                        "the left-over count"

                    expectWarn lines
                })

            testT "a member stopped because m were in gets no failure line" (fun () ->
                task {
                    let secret, shares = shamir 44 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()

                    let ms =
                        [
                            for id, s in shares ->
                                FakeMember(
                                    id,
                                    key,
                                    s,
                                    partialOf id s,
                                    (if id = 3UL then TimeSpan.FromMilliseconds 300.0 else TimeSpan.Zero)
                                ),
                                $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 2
                    let req = request key (Duty.RandaoReveal 1UL)
                    let! o = b.Sign req CancellationToken.None
                    Expect.isTrue (verifies key req o) "signed by two"
                    do! Task.Delay 500
                    Expect.equal (fst ms[2]).Cancelled 1 "member 3 was stopped"

                    Expect.isEmpty
                        (lines |> Seq.filter (fun l -> l.Contains "did not sign") |> List.ofSeq)
                        "no failure line"

                    Expect.isEmpty lines "no line at any level"
                })

            test "cleanReason: one line, at most 200 units, whole surrogate pairs" {
                Expect.equal (Threshold.cleanReason "plain") "plain" "short text unchanged"

                Expect.equal
                    (Threshold.cleanReason "a\r\nWARN  forged\tx")
                    "a  WARN  forged x"
                    "control characters become spaces"

                Expect.equal (Threshold.cleanReason "x\uD800y\uDC00") "x\uFFFDy\uFFFD" "lone surrogates replaced"
                let long = Threshold.cleanReason (String('x', 1 <<< 20))
                Expect.equal long (String('x', 200) + "...") "cut at 200 and marked"
                // The pair starts at unit 199 and does not fit: it is left out, not split.
                let cut = Threshold.cleanReason (String('a', 199) + "\U0001F600" + "tail")
                Expect.equal cut (String('a', 199) + "...") "pair left out at the cut"
                Expect.isTrue (pairsWhole cut) "no lone surrogate"
                let fits = Threshold.cleanReason (String('a', 198) + "\U0001F600" + "tail")
                Expect.equal fits (String('a', 198) + "\U0001F600" + "...") "pair kept when it fits"
            }

            testT "a member's reason text is cut and kept on one line, in its own line and the group line" (fun () ->
                task {
                    let secret, shares = shamir 46 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()
                    let evil = "refused\nWARN  tee: forged line\r" + String('z', 2_000_000) + "\U0001F600"

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0), "m3"
                                else
                                    FakeMember(id, key, s, (fun _ -> Failed(Transport evil)), TimeSpan.Zero), $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 2
                    let! _ = b.Sign (request key attestation) CancellationToken.None
                    let! _ = waitForLine lines (fun l -> l.Contains "member m2 did not sign")

                    let ours =
                        lines
                        |> Seq.filter (fun l -> l.Contains "did not sign" || l.Contains "not enough")
                        |> List.ofSeq

                    Expect.equal ours.Length 3 "two member lines and the group line"

                    for l in ours do
                        Expect.isFalse (l.Contains '\n' || l.Contains '\r') $"one line: {l.Substring(0, 80)}"
                        Expect.stringContains l "transport: refused WARN  tee: forged line zzz" "the text, flattened"
                        Expect.isLessThan l.Length 700 "the text is cut"
                        Expect.isTrue (pairsWhole l) "valid UTF-16"

                    expectWarn lines
                })

            testT "a reason text that changes on every answer still gives one line per window" (fun () ->
                task {
                    let secret, shares = shamir 47 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()
                    let k = ref 0

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ ->
                                            k.Value <- k.Value + 1
                                            Failed(Transport $"request {k.Value}: connection reset")),
                                        TimeSpan.Zero
                                    ),
                                    "m3"
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 20.0), $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 2

                    for _ in 1..5 do
                        let! _ = b.Sign (request key (Duty.RandaoReveal 1UL)) CancellationToken.None
                        ()

                    let mine = lines |> Seq.filter (fun l -> l.Contains "member m3") |> List.ofSeq
                    Expect.equal mine.Length 1 "one line for five answers with different texts"
                    Expect.stringContains mine.Head "request 1: connection reset" "the first text is in the line"
                    expectWarn lines
                })

            testT "one member with many kinds of failure cannot hide another member's first line" (fun () ->
                task {
                    let secret, shares = shamir 48 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()
                    let round = ref 0

                    let first (_: SignRequest) =
                        match round.Value with
                        | 1 -> Failed(Transport "down")
                        | 2 -> Failed(Internal "broken")
                        | 3 -> Failed(Unavailable "busy")
                        | _ -> Failed(Gone "handed over")

                    let ms =
                        [
                            for id, s in shares ->
                                match id with
                                | 1UL -> FakeMember(id, key, s, first, TimeSpan.Zero), "m1"
                                | 2UL ->
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun req ->
                                            if round.Value = 4 then
                                                Failed(Transport "m2 down")
                                            else
                                                partialOf id s req),
                                        TimeSpan.Zero
                                    ),
                                    "m2"
                                | _ -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero), "m3"
                        ]
                    // Two keys per member: member 1's third kind of failure finds its table full.
                    let b =
                        Threshold.createWith
                            2
                            "g"
                            2
                            [
                                for (x, n), i in List.zip ms [ 1UL; 2UL; 3UL ] ->
                                    {
                                        Backend = { x.Backend with Name = n }
                                        Index = i
                                        Budget = TimeSpan.FromSeconds 5.0
                                    }
                            ]
                            TimeProvider.System
                            log

                    let! _ = b.Keys CancellationToken.None

                    for r in 1..4 do
                        round.Value <- r
                        let! _ = b.Sign (request key (Duty.RandaoReveal 1UL)) CancellationToken.None
                        ()

                    let m1 = lines |> Seq.filter (fun l -> l.Contains "member m1 did not sign") |> List.ofSeq
                    Expect.equal m1.Length 2 "member 1: two keys, the rest over its cap"
                    let m2 = lines |> Seq.filter (fun l -> l.Contains "member m2 did not sign") |> List.ofSeq
                    Expect.equal m2.Length 1 "member 2's first failure is logged"
                    Expect.stringContains m2.Head "errored: transport: m2 down" "with its reason"
                    expectWarn lines
                })

            testT "the member whose answer decides the result is never labelled late or dropped" (fun () ->
                task {
                    let secret, shares = shamir 49 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let bad = ResizeArray<string>()

                    for round in 1..300 do
                        let log, lines = Log.memory ()
                        // Members 1 and 2 fail on timer threads at about the same time; whichever the
                        // group reads second decides. Member 3 would sign, too late to matter.
                        let ms =
                            [
                                for id, s in shares ->
                                    if id = 3UL then
                                        FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 200.0), "m3"
                                    else
                                        FakeMember(
                                            id,
                                            key,
                                            s,
                                            (fun _ -> Failed(Transport "down")),
                                            TimeSpan.FromMilliseconds 1.0
                                        ),
                                        $"m{id}"
                            ]

                        let b = named TimeProvider.System log "g" ms 2
                        let duty = if round % 2 = 0 then attestation else Duty.RandaoReveal 1UL
                        let! _ = b.Sign (request key duty) CancellationToken.None

                        for name in [ "m1"; "m2" ] do
                            let! l = waitForLine lines (fun l -> l.Contains $"member {name} did not sign")

                            match l with
                            | None -> bad.Add $"round {round}: no line for {name}"
                            | Some l when l.Contains "after the group's result" ->
                                bad.Add $"round {round}: {name} labelled late"
                            | Some _ -> ()

                    Expect.isEmpty (List.ofSeq bad) "every deciding answer logged, none labelled late"
                })

            testT
                "an answer that comes after the result is decided is labelled late, even before sign returns"
                (fun () ->
                    task {
                        let secret, shares = shamir 50 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret
                        let lines = Collections.Concurrent.ConcurrentQueue<string>()

                        let release =
                            TaskCompletionSource<SignOutcome>(TaskCreationOptions.RunContinuationsAsynchronously)

                        use seen = new ManualResetEventSlim(false)
                        // The group line is written after the result is decided and before sign returns.
                        // While it is written, member 3 answers; its line must say it came after the result.
                        let log =
                            {
                                MinLevel = LogLevel.Debug
                                Write =
                                    fun level msg ->
                                        lines.Enqueue $"{level} {msg}"

                                        if msg.Contains "member m3 did not sign" then
                                            seen.Set()

                                        if msg.Contains "not enough signatures" then
                                            release.TrySetResult(Failed(Transport "late answer")) |> ignore
                                            seen.Wait(TimeSpan.FromSeconds 2.0) |> ignore
                            }

                        let ms =
                            [
                                for id, s in shares ->
                                    let x = FakeMember(id, key, s, (fun _ -> Failed(Transport "down")), TimeSpan.Zero)

                                    if id = 3UL then
                                        { x.Backend with
                                            Name = "m3"
                                            Sign = fun _ _ -> release.Task
                                        }
                                    else
                                        { x.Backend with Name = $"m{id}" }
                            ]

                        let b =
                            Threshold.create
                                "g"
                                2
                                [
                                    for x, i in List.zip ms [ 1UL; 2UL; 3UL ] ->
                                        {
                                            Backend = x
                                            Index = i
                                            Budget = TimeSpan.FromSeconds 5.0
                                        }
                                ]
                                TimeProvider.System
                                log

                        let! _ = b.Keys CancellationToken.None
                        let! _ = b.Sign (request key attestation) CancellationToken.None
                        let! late = waitForLine lines (fun l -> l.Contains "member m3 did not sign")

                        Expect.stringContains
                            (defaultArg late "")
                            "errored: transport: late answer, after the group's result"
                            "member 3 answered after the result"

                        let group = lines |> Seq.find (fun l -> l.Contains "not enough signatures")
                        Expect.stringContains group "m3 pending" "the group line lists it as pending"

                        for name in [ "m1"; "m2" ] do
                            let l = lines |> Seq.find (fun l -> l.Contains $"member {name} did not sign")
                            Expect.isFalse (l.Contains "after the group's result") $"{name} decided the result"
                    })

            test "cleanReason: line separators and format characters become spaces" {
                Expect.equal
                    (Threshold.cleanReason "a\u2028b\u2029c\u202Ed\u200Be\uFEFFf")
                    "a b c d e f"
                    "separators, bidi override, zero width"

                Expect.equal (Threshold.cleanReason "x\U000E0041y") "x y" "a format character outside the BMP"
                Expect.equal (Threshold.cleanReason "ok \U0001F600") "ok \U0001F600" "other pairs stay"
            }

            testT "member text in the group's answer is cut and on one line; the refusal kind stays" (fun () ->
                task {
                    let long (what: string) = what + "\nWARN  forged\u202E" + String('q', 1_000_000)
                    let one (s: string) = not (s.Contains '\n') && not (s.Contains '\u202E') && s.Length < 500

                    let groupOf (answers: Map<uint64, SignRequest -> SignOutcome>) seed =
                        let secret, shares = shamir seed 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret

                        let ms =
                            [
                                for id, s in shares ->
                                    FakeMember(id, key, s, answers[id], TimeSpan.FromMilliseconds(10.0 * float id))
                            ]

                        (group ms 2).Sign (request key attestation) CancellationToken.None
                    // Slashable from one member decides; its kind must stay Slashable.
                    let! o =
                        groupOf
                            (Map
                                [
                                    1UL, (fun _ -> Refused(Slashable(long "double vote")))
                                    2UL, (fun _ -> Refused(denied "d2"))
                                    3UL, (fun _ -> Failed(Transport "x"))
                                ])
                            51

                    match o with
                    | Refused(Slashable why) ->
                        Expect.isTrue (one why) "slashable reason cut, one line"
                        Expect.stringStarts why "double vote WARN  forged" "the text kept"
                    | x -> failtestf "expected Slashable, got %s" (x.Describe.Substring(0, 60))
                    // No denial: the merged refusal.
                    let! o =
                        groupOf
                            (Map
                                [
                                    1UL, (fun _ -> Refused(BadRequest(long "bad")))
                                    2UL, (fun _ -> Refused(BadRequest(long "bad")))
                                    3UL, (fun _ -> Failed(Transport "x"))
                                ])
                            52

                    match o with
                    | Refused(BadRequest why) -> Expect.isTrue (one why) "refusal reason cut, one line"
                    | x -> failtestf "expected BadRequest, got %s" (x.Describe.Substring(0, 60))
                    // Only failures: the merged failure.
                    let! o =
                        groupOf
                            (Map
                                [
                                    1UL, (fun _ -> Failed(Transport(long "a")))
                                    2UL, (fun _ -> Failed(Unavailable(long "b")))
                                    3UL, (fun _ -> Failed(Gone(long "c")))
                                ])
                            53

                    match o with
                    | Failed(Transport why) ->
                        Expect.isTrue (not (why.Contains '\n') && why.Length < 1000) "merged failure cut, one line"
                    | x -> failtestf "expected a transport failure, got %s" (x.Describe.Substring(0, 60))
                })

            testT
                "not enough signatures: an answer written before the result is decided is named, not pending"
                (fun () ->
                    task {
                        let secret, shares = shamir 54 3 [ 1UL .. 4UL ]
                        let key = pk secret
                        let log, lines = Log.memory ()
                        // Members 1 to 3 answer at once, before the group reads any answer; the group
                        // decides after reading two, with member 3's answer still in its queue.
                        let ms =
                            [
                                for id, s in shares ->
                                    if id = 4UL then
                                        FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0), "m4"
                                    else
                                        FakeMember(
                                            id,
                                            key,
                                            s,
                                            (fun _ -> Failed(Transport $"m{id} down")),
                                            TimeSpan.Zero
                                        ),
                                        $"m{id}"
                            ]

                        let b = named TimeProvider.System log "g" ms 3
                        let! _ = b.Sign (request key attestation) CancellationToken.None
                        let line = lines |> Seq.find (fun l -> l.Contains "not enough signatures")
                        Expect.stringContains line "0 signed, 0 denied, 0 failed, 3 errored" "member 3 counted"
                        Expect.stringContains line "m3 errored (transport: m3 down)" "member 3 named with its answer"
                        Expect.stringContains line "m4 pending" "member 4 still out"
                    })

            testT "not enough signatures: a slashable refusal still in the queue at the decision wins" (fun () ->
                task {
                    let secret, shares = shamir 55 3 [ 1UL .. 4UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()
                    // Members 1 to 3 answer at once; the group decides after reading members 1 and 2,
                    // with member 3's slashable refusal still in its queue.
                    let ms =
                        [
                            for id, s in shares ->
                                match id with
                                | 3UL ->
                                    FakeMember(id, key, s, (fun _ -> Refused(Slashable "double vote")), TimeSpan.Zero),
                                    "m3"
                                | 4UL -> FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0), "m4"
                                | _ ->
                                    FakeMember(id, key, s, (fun _ -> Failed(Transport $"m{id} down")), TimeSpan.Zero),
                                    $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 3

                    match! b.Sign (request key attestation) CancellationToken.None with
                    | Refused(Slashable why) -> Expect.equal why "double vote" "member 3's reason"
                    | o -> failtestf "expected Slashable, got %s" o.Describe

                    let line = lines |> Seq.find (fun l -> l.Contains "not enough signatures")
                    Expect.stringContains line "m3 denied (slashable: double vote)" "member 3 named"
                })

            testT
                "not enough signatures: a partial still in the queue counts as signed and changes nothing else"
                (fun () ->
                    task {
                        let secret, shares = shamir 56 3 [ 1UL .. 4UL ]
                        let key = pk secret
                        let log, lines = Log.memory ()

                        let ms =
                            [
                                for id, s in shares ->
                                    match id with
                                    | 3UL -> FakeMember(id, key, s, partialOf id s, TimeSpan.Zero), "m3"
                                    | 4UL -> FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0), "m4"
                                    | _ ->
                                        FakeMember(
                                            id,
                                            key,
                                            s,
                                            (fun _ -> Failed(Transport $"m{id} down")),
                                            TimeSpan.Zero
                                        ),
                                        $"m{id}"
                            ]

                        let b = named TimeProvider.System log "g" ms 3

                        match! b.Sign (request key attestation) CancellationToken.None with
                        | Failed(Transport why) ->
                            Expect.equal why "m1 down; m2 down" "the members' failures, as before the drain"
                        | o -> failtestf "expected a transport failure, got %s" o.Describe

                        let line = lines |> Seq.find (fun l -> l.Contains "not enough signatures")
                        Expect.stringContains line "1 signed, 0 denied, 0 failed, 2 errored" "the partial counted"
                        Expect.stringContains line "m3 signed, m4 pending" "member 3 named as signed"
                    })

            testT
                "a member in its floor: an Info line once per floor epoch, no failure Warn, and it never outweighs partials"
                (fun () ->
                    task {
                        let secret, shares = shamir 57 2 [ 1UL; 2UL; 3UL ]
                        let key = pk secret
                        let log, lines = Log.memory ()
                        let until = ref 20UL

                        let ms =
                            [
                                for id, s in shares ->
                                    if id = 3UL then
                                        FakeMember(
                                            id,
                                            key,
                                            s,
                                            (fun _ -> Refused(Refusal.NotReadyUntil(ValueSome until.Value))),
                                            TimeSpan.Zero
                                        ),
                                        "m3"
                                    else
                                        FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 10.0),
                                        $"m{id}"
                            ]

                        let b = named TimeProvider.System log "g" ms 2

                        for _ in 1..4 do
                            let req = request key attestation
                            let! o = b.Sign req CancellationToken.None
                            Expect.isTrue (verifies key req o) $"the other two sign: {o.Describe}"

                        let notReady () =
                            lines |> Seq.filter (fun l -> l.Contains "member m3 waits for the floor") |> List.ofSeq

                        Expect.equal (notReady ()).Length 1 "one line for four refusals"
                        Expect.stringStarts (notReady ()).Head "INFO " "at Info"

                        Expect.stringContains
                            (notReady ()).Head
                            $"of {key.Short} until epoch 20: the attestation is skipped"
                            "key and epoch"

                        until.Value <- 21UL
                        let! _ = b.Sign (request key attestation) CancellationToken.None
                        Expect.equal (notReady ()).Length 2 "a new floor epoch gets a line"
                        Expect.isFalse (lines |> Seq.exists (fun l -> l.Contains "did not sign")) "no failure Warn"
                    })

            testT "floors per key: keys with different floors each get one Info line, not one per duty" (fun () ->
                task {
                    let secret, shares = shamir 59 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let other = pk (scalar32 (BigInteger 9999))
                    let log, lines = Log.memory ()
                    // Member 3 holds an import floor per key: 20 for one key, 30 for the other.
                    let floorOf (req: SignRequest) = if req.Key = key then 20UL else 30UL

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun req -> Refused(Refusal.NotReadyUntil(ValueSome(floorOf req)))),
                                        TimeSpan.Zero
                                    ),
                                    "m3"
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 10.0), $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 2

                    for _ in 1..3 do
                        for k in [ key; other ] do
                            let! _ = b.Sign (request k attestation) CancellationToken.None
                            ()

                    let floorLines =
                        lines |> Seq.filter (fun l -> l.Contains "member m3 waits for the floor") |> List.ofSeq

                    Expect.equal floorLines.Length 2 "one line per key for six refusals"

                    Expect.isTrue
                        (floorLines |> List.exists (fun l -> l.Contains $"{key.Short} until epoch 20"))
                        "the first key"

                    Expect.isTrue
                        (floorLines |> List.exists (fun l -> l.Contains $"{other.Short} until epoch 30"))
                        "the second key"

                    for l in floorLines do
                        Expect.stringStarts l "INFO " "at Info"
                })

            testT "not ready with no epoch (no trusted time) is a rate-limited failure Warn" (fun () ->
                task {
                    let secret, shares = shamir 60 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let log, lines = Log.memory ()

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 3UL then
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ -> Refused(Refusal.NotReadyUntil ValueNone)),
                                        TimeSpan.Zero
                                    ),
                                    "m3"
                                else
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.FromMilliseconds 10.0), $"m{id}"
                        ]

                    let b = named TimeProvider.System log "g" ms 2

                    for _ in 1..3 do
                        let req = request key attestation
                        let! o = b.Sign req CancellationToken.None
                        Expect.isTrue (verifies key req o) $"the other two sign: {o.Describe}"

                    let mine = lines |> Seq.filter (fun l -> l.Contains "member m3") |> List.ofSeq
                    Expect.equal mine.Length 1 "one line for three refusals"
                    Expect.stringStarts mine.Head "WARN " "at Warn"
                    Expect.stringContains mine.Head "did not sign the attestation" "the failure line"
                    Expect.stringContains mine.Head "failed: not ready" "the reason"
                })

            testT "too few signed and members in their floor: not ready, not denied or slashable" (fun () ->
                task {
                    let secret, shares = shamir 58 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let ms =
                        [
                            for id, s in shares ->
                                if id = 1UL then
                                    FakeMember(id, key, s, partialOf id s, TimeSpan.Zero)
                                else
                                    FakeMember(
                                        id,
                                        key,
                                        s,
                                        (fun _ -> Refused(Refusal.NotReadyUntil(ValueSome 30UL))),
                                        TimeSpan.Zero
                                    )
                        ]

                    match! (group ms 2).Sign (request key attestation) CancellationToken.None with
                    | Refused(Refusal.NotReadyUntil(ValueSome 30UL)) -> ()
                    | o -> failtestf "expected not ready until 30, got %s" o.Describe
                })

            testT
                "precedence with the drain: a slashable refusal wins over policy; policy and not ready answer PolicyDenied"
                (fun () ->
                    task {
                        let secret, shares = shamir 61 3 [ 1UL .. 4UL ]
                        let key = pk secret
                        // Members 1 to 3 answer at once; the group decides after members 1 and 2, member 3's
                        // answer is drained. Not ready is never a denial.
                        let run (third: SignOutcome) =
                            let ms =
                                [
                                    for id, s in shares ->
                                        match id with
                                        | 1UL ->
                                            FakeMember(
                                                id,
                                                key,
                                                s,
                                                (fun _ -> Refused(PolicyDenied "certificate rejected")),
                                                TimeSpan.Zero
                                            )
                                        | 2UL ->
                                            FakeMember(
                                                id,
                                                key,
                                                s,
                                                (fun _ -> Refused(Refusal.NotReadyUntil(ValueSome 30UL))),
                                                TimeSpan.Zero
                                            )
                                        | 3UL -> FakeMember(id, key, s, (fun _ -> third), TimeSpan.Zero)
                                        | _ -> FakeMember(id, key, s, partialOf id s, TimeSpan.FromSeconds 2.0)
                                ]

                            (group ms 3).Sign (request key attestation) CancellationToken.None

                        match! run (Refused(Slashable "double vote")) with
                        | Refused(Slashable why) -> Expect.equal why "double vote" "the drained slashable refusal wins"
                        | o -> failtestf "expected Slashable, got %s" o.Describe

                        match! run (Refused(PolicyDenied "rate limited")) with
                        | Refused(PolicyDenied _) -> ()
                        | o -> failtestf "expected PolicyDenied, got %s" o.Describe

                        match! run (Refused(denied "dirk3")) with
                        | Refused(Denied _) -> ()
                        | o -> failtestf "expected Denied, got %s" o.Describe

                        match! run (Failed(Transport "down")) with
                        | Refused(PolicyDenied _) -> ()
                        | o -> failtestf "expected PolicyDenied, got %s" o.Describe
                    })

            test "checkShares: a group size needs 2m > n" {
                for m, n in [ 1, 1; 2, 2; 2, 3; 3, 4; 3, 5; 4, 7; 5, 7 ] do
                    Expect.equal (Threshold.checkSize m n) (Ok()) $"{m} of {n}"

                for m, n in [ 0, 3; 4, 3; 1, 2; 2, 4; 3, 6; 3, 7 ] do
                    Expect.isError (Threshold.checkSize m n) $"{m} of {n}"
            }
        ]
