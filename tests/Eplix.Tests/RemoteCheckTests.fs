/// The background check of Dirk and Web3Signer whole-key signatures: a bad
/// signature comes back at once and is counted, three in a row stop the key at that endpoint, a
/// probe or a key list change resumes it, a full queue drops checks, partials are not checked.
module Eplix.Tests.RemoteCheckTests

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Diagnostics.Metrics
open System.Numerics
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Dirk
open Eplix.Backend.Dirk.Messages
open Eplix.Backend.Web3Signer
open Eplix.Tests.TestUtil
open Eplix.Tests.ThresholdTests
open Eplix.Tests.DirkTests
open Eplix.Tests.Web3SignerTests

/// Counts one counter's measurements per endpoint label, as (endpoint, reason) pairs.
type private Counted(name: string) =
    let seen = ConcurrentQueue<string * string>()
    let listener = new MeterListener()

    do
        listener.InstrumentPublished <-
            fun i l ->
                if i.Meter.Name = Metrics.MeterName && i.Name = name then
                    l.EnableMeasurementEvents i

        listener.SetMeasurementEventCallback<int64>(fun _ v tags _ ->
            let mutable e = ""
            let mutable r = ""

            for t in tags do
                if t.Key = "endpoint" then
                    e <- string t.Value

                if t.Key = "reason" then
                    r <- string t.Value

            for _ in 1L .. v do
                seen.Enqueue((e, r)))

        listener.Start()

    member _.For(endpoint: string) = seen |> Seq.filter (fun (e, _) -> e = endpoint) |> Seq.length

    member _.Reasons(endpoint: string) =
        [
            for e, r in seen do
                if e = endpoint then
                    r
        ]

    interface IDisposable with
        member _.Dispose() = listener.Dispose()

let private secret = scalar32 (BigInteger 5551)
let private key = pk secret
let private shareSecret = scalar32 (BigInteger 5552)
let private shareKey = pk shareSecret

let private att (target: Epoch) =
    Duty.Attestation
        {
            Slot = target * 8UL
            Index = 0UL
            BeaconBlockRoot = root 7
            Source = { Epoch = target - 1UL; Root = root 4 }
            Target = { Epoch = target; Root = root 5 }
        }

/// A probe chain whose wall-clock epoch the test sets.
let private chainAt (epoch: Epoch ref) : ProbeChain =
    {
        Spec = Web3SignerTests.spec.Value
        CurrentEpoch = fun () -> ValueSome epoch.Value
    }

let private listingOf (name: string) =
    {
        State = ResponseState.Succeeded
        Accounts = [ { Name = name; PublicKey = key.Bytes } ]
        DistributedAccounts = []
    }

let private dirkWith (fake: FakeDirk) (watch: SignatureWatch) =
    let e = DirkEndpoint(fake.Api, false, TimeSpan.FromSeconds 5.0, Log.none, GloasCalls.Auto, watch)
    e.SetAccount(key, { Name = "W/A"; Share = ValueNone }) |> ignore
    e

let private badAnswer =
    fun (_: DirkCall) ->
        ValueSome
            {
                State = ResponseState.Succeeded
                Signature = (sign secret (root 99)).Bytes
            }

let private settle (w: SignatureWatch) = TestUtil.settle w

let private verifies (r: SignRequest) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan key.Bytes) (ReadOnlySpan r.SigningRoot.Bytes) (ReadOnlySpan s.Bytes)

let private unavailable (o: SignOutcome) =
    match o with
    | Failed(Unavailable m) -> m.Contains "not used for"
    | _ -> false

[<Tests>]
let tests =
    testSequenced
    <| testList
        "remote signature checks"
        [
            testT
                "Dirk: a bad whole-key signature comes back at once and is counted; a good one resets the count"
                (fun () ->
                    task {
                        use invalid = new Counted("eplix_remote_signature_invalid")
                        let fake = FakeDirk("rc-dirk-1:1", ValueSome(listingOf "W/A"), Map [ "W/A", secret ])
                        let w = SignatureWatch("dirk", "rc-dirk-1:1", Log.none)
                        let e = dirkWith fake w
                        let backend = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)
                        fake.Answer <- badAnswer
                        let r = request key (att 3UL)

                        match! backend.Sign r CancellationToken.None with
                        | Signed s ->
                            Expect.equal s.Bytes (sign secret (root 99)).Bytes "the signer's answer, unchanged"
                        | o -> failtestf "expected the signature: %s" o.Describe

                        do! settle w
                        Expect.equal (w.Fails key) 1 "one failed check"
                        Expect.equal (invalid.For "rc-dirk-1:1") 1 "counted once"
                        Expect.isFalse (w.IsStopped key) "one is not enough to stop"
                        fake.Answer <- fun _ -> ValueNone
                        let! good = backend.Sign (request key (att 4UL)) CancellationToken.None

                        Expect.isTrue
                            (match good with
                             | Signed _ -> true
                             | _ -> false)
                            good.Describe

                        do! settle w
                        Expect.equal (w.Fails key) 0 "a good signature resets the count"
                        Expect.isFalse w.Tracking "nothing left on record"
                        e.Stop()
                    })

            testT
                "Dirk: three bad signatures in a row stop the key at that instance only, as a not-serving refusal that halts nothing"
                (fun () ->
                    task {
                        use stops = new Counted("eplix_remote_signer_key_stops")
                        let fake = FakeDirk("rc-dirk-2:1", ValueSome(listingOf "W/A"), Map [ "W/A", secret ])
                        let other = FakeDirk("rc-dirk-3:1", ValueSome(listingOf "W/A"), Map [ "W/A", secret ])
                        let w = SignatureWatch("dirk", "rc-dirk-2:1", Log.none)
                        let e = dirkWith fake w
                        let e2 = dirkWith other (SignatureWatch("dirk", "rc-dirk-3:1", Log.none))
                        let backend = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)
                        fake.Answer <- badAnswer

                        for t in 2UL .. 4UL do
                            let! o = backend.Sign (request key (att t)) CancellationToken.None

                            Expect.isTrue
                                (match o with
                                 | Signed _ -> true
                                 | _ -> false)
                                $"returned as signed: {o.Describe}"

                            do! settle w

                        Expect.isTrue (w.IsStopped key) "stopped after three"
                        Expect.equal (stops.For "rc-dirk-2:1") 1 "the stop is counted"
                        let calls = fake.Calls.Length
                        // Through the pipeline: the VC's slashing DB allows it, the instance is not asked,
                        // and the key stays active (no slashing refusal, no halt).
                        use db =
                            match
                                Eplix.Slashing.SlashingDb.Open(
                                    new Eplix.Slashing.FileMarkFile(IO.Path.Combine(tempDir (), "s.db")),
                                    root 1
                                )
                            with
                            | Ok db -> db
                            | Error err -> failwith err

                        db.RegisterKeys [ key, Eplix.Slashing.KeyOrigin.StartedEmpty ] |> ignore
                        let registry = KeyRegistry()
                        registry.Add(key, backend) |> ignore
                        registry.SetState(key, KeyState.Active)
                        let pipeline = Pipeline(db, registry, TimeProvider.System, Log.none)
                        let! refused = pipeline.Sign(request key (att 10UL), CancellationToken.None)
                        Expect.isTrue (unavailable refused) $"a not-serving refusal: {refused.Describe}"
                        Expect.equal fake.Calls.Length calls "the instance got no request"
                        Expect.equal (registry.TryGet key).Value.State KeyState.Active "the key is not halted"
                        // Another instance with its own record signs the key as before.
                        let! elsewhere =
                            (e2.Backend "dirk2" false (fun _ _ -> true)).Sign
                                (request key (att 11UL))
                                CancellationToken.None

                        Expect.isTrue
                            (match elsewhere with
                             | Signed s -> verifies (request key (att 11UL)) s
                             | _ -> false)
                            elsewhere.Describe

                        e.Stop()
                        e2.Stop()
                    })

            testT "Dirk: a probe runs once an epoch; a bad one keeps the key stopped, a good one resumes it" (fun () ->
                task {
                    use resumes = new Counted("eplix_remote_signer_key_resumes")
                    use invalid = new Counted("eplix_remote_signature_invalid")
                    let epoch = ref 5UL
                    let fake = FakeDirk("rc-dirk-4:1", ValueSome(listingOf "W/A"), Map [ "W/A", secret ])
                    let w = SignatureWatch("dirk", "rc-dirk-4:1", Log.none, chainAt epoch)
                    let e = dirkWith fake w
                    let backend = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)
                    fake.Answer <- badAnswer

                    for t in 2UL .. 4UL do
                        let! _ = backend.Sign (request key (att t)) CancellationToken.None
                        do! settle w

                    Expect.isTrue (w.IsStopped key) "stopped at epoch 5"
                    let calls () = fake.Calls.Length
                    let n0 = calls ()
                    let! o = backend.Sign (request key (att 5UL)) CancellationToken.None
                    Expect.isTrue (unavailable o) $"refused in the epoch of the stop: {o.Describe}"
                    Expect.equal (calls ()) n0 "no probe in the epoch of the stop"
                    // Epoch 6: the probe goes out, its signature is bad, the request is refused.
                    epoch.Value <- 6UL
                    let! o = backend.Sign (request key (att 6UL)) CancellationToken.None
                    Expect.isTrue (unavailable o) $"refused after a bad probe: {o.Describe}"
                    Expect.equal (calls ()) (n0 + 1) "one probe, and not the request"
                    Expect.equal (invalid.For "rc-dirk-4:1") 4 "the bad probe is counted"
                    let! o = backend.Sign (request key (att 6UL)) CancellationToken.None
                    Expect.isTrue (unavailable o) o.Describe
                    Expect.equal (calls ()) (n0 + 1) "one probe an epoch"
                    // Epoch 7: the instance signs right again; the probe passes and the request goes.
                    epoch.Value <- 7UL
                    fake.Answer <- fun _ -> ValueNone
                    let r = request key (att 7UL)
                    let! o = backend.Sign r CancellationToken.None

                    Expect.isTrue
                        (match o with
                         | Signed s -> verifies r s
                         | _ -> false)
                        $"signed after a good probe: {o.Describe}"

                    Expect.isFalse (w.IsStopped key) "resumed"
                    Expect.equal (resumes.Reasons "rc-dirk-4:1") [ "probe" ] "the resume is counted"

                    let probes =
                        fake.Calls
                        |> List.skip n0
                        |> List.filter (fun c ->
                            match c with
                            | DirkCall.Generic _ -> true
                            | _ -> false)

                    Expect.equal probes.Length 2 "two probes"

                    match probes[1] with
                    | DirkCall.Generic(_, objectRoot, domain) ->
                        Expect.equal objectRoot (Codec.hashEpoch 7UL) "a RANDAO reveal for the current epoch"
                        Expect.equal (domain.Bytes[0..3]) DomainTypes.Randao.Bytes "under the RANDAO domain"
                    | c -> failtestf "not a generic call: %A" c

                    e.Stop()
                })

            testT "Web3Signer: a stopped key resumes when the key list lists it again, and by a probe" (fun () ->
                task {
                    use resumes = new Counted("eplix_remote_signer_key_resumes")
                    let epoch = ref 9UL
                    let signer = FakeSigner("http://rc-w3s-1", [ key, secret ])
                    let w = SignatureWatch("web3signer", "http://rc-w3s-1", Log.none, chainAt epoch)
                    let x = SignerEndpoint(signer.Api, TimeSpan.FromSeconds 1.0, Log.none, w)
                    let! _ = x.Refresh CancellationToken.None
                    let backend = x.WholeKeys "w"

                    let stop () =
                        task {
                            signer.Override <- fun _ -> Some(Answer.Signature(sign secret (root 99)))

                            for i in 1..3 do
                                let! o = backend.Sign (req key (att (uint64 (10 + i)))) CancellationToken.None

                                Expect.isTrue
                                    (match o with
                                     | Signed _ -> true
                                     | _ -> false)
                                    $"returned as signed: {o.Describe}"

                                do! settle w

                            Expect.isTrue (w.IsStopped key) "stopped"
                        }

                    do! stop ()
                    let bodies = signer.Bodies.Count
                    let! o = backend.Sign (req key (att 20UL)) CancellationToken.None
                    Expect.isTrue (unavailable o) o.Describe
                    Expect.equal signer.Bodies.Count bodies "the signer got no request"
                    // A refresh that still lists the key changes nothing; one after it was gone resumes it.
                    let! _ = x.Refresh CancellationToken.None
                    Expect.isTrue (w.IsStopped key) "still listed: still stopped"
                    signer.Keys.Remove key |> ignore
                    let! _ = x.Refresh CancellationToken.None
                    signer.Keys[key] <- secret
                    let! _ = x.Refresh CancellationToken.None
                    Expect.isFalse (w.IsStopped key) "listed again: resumed"
                    signer.Override <- fun _ -> None
                    let r = req key (att 21UL)
                    let! o = backend.Sign r CancellationToken.None

                    Expect.isTrue
                        (match o with
                         | Signed s -> verifies r s
                         | _ -> false)
                        o.Describe
                    // Its pass must land before the next failures, or it clears them.
                    do! settle w
                    // Stopped again; the next epoch's probe is a RANDAO_REVEAL that verifies.
                    do! stop ()
                    signer.Override <- fun _ -> None
                    epoch.Value <- 10UL
                    let before = signer.Bodies.Count
                    let r = req key (att 22UL)
                    let! o = backend.Sign r CancellationToken.None

                    Expect.isTrue
                        (match o with
                         | Signed s -> verifies r s
                         | _ -> false)
                        $"signed after a good probe: {o.Describe}"

                    let sent = signer.Bodies |> Seq.skip before |> List.ofSeq
                    Expect.equal sent.Length 2 "the probe, then the request"
                    Expect.stringContains sent[0] "RANDAO_REVEAL" "the probe is a RANDAO reveal"
                    Expect.equal (resumes.Reasons "http://rc-w3s-1") [ "key_list"; "probe" ] "both resumes counted"
                })

            testT "a full check queue drops checks and never blocks signing" (fun () ->
                task {
                    use dropped = new Counted("eplix_remote_signature_checks_dropped")
                    let release = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
                    let fake = FakeDirk("rc-dirk-5:1", ValueSome(listingOf "W/A"), Map [ "W/A", secret ])

                    let w =
                        SignatureWatch(
                            "dirk",
                            "rc-dirk-5:1",
                            Log.none,
                            verify = (fun _ _ _ -> release.Task),
                            capacity = 4
                        )

                    let e = dirkWith fake w
                    let backend = e.Backend "dirk" false (fun _ a -> a.Share.IsNone)

                    let all =
                        [|
                            for t in 2UL .. 11UL -> backend.Sign (request key (att t)) CancellationToken.None
                        |]

                    let! outs = (Task.WhenAll all).WaitAsync(TimeSpan.FromSeconds 5.0)

                    Expect.isTrue
                        (outs
                         |> Array.forall (fun o ->
                             match o with
                             | Signed _ -> true
                             | _ -> false))
                        "every request signed while the checks wait"

                    Expect.equal w.Pending 4 "the queue holds its capacity"
                    Expect.equal (dropped.For "rc-dirk-5:1") 6 "the rest are dropped and counted"
                    release.SetResult true
                    do! settle w
                    Expect.isFalse w.Tracking "the queued checks passed"
                    e.Stop()
                })

            testT "Settled completes only after every queued check has changed the watch" (fun () ->
                task {
                    let gates = ConcurrentQueue<TaskCompletionSource<bool>>()

                    let verify _ _ _ =
                        let g = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
                        gates.Enqueue g
                        g.Task

                    let w = SignatureWatch("dirk", "rc-dirk-7:1", Log.none, verify = verify)
                    do! (w.Settled()).WaitAsync(TimeSpan.FromSeconds 5.0)
                    let s = sign secret (root 99)
                    w.Check(request key (att 2UL), s)
                    w.Check(request key (att 3UL), s)
                    let settled = w.Settled()

                    let first, second =
                        (match gates.ToArray() with
                         | [| a; b |] -> a, b
                         | g -> failtestf "%d checks" g.Length)

                    first.SetResult false
                    do! Task.Delay 50
                    Expect.isFalse settled.IsCompleted "one check still waits"
                    second.SetResult false
                    do! settled.WaitAsync(TimeSpan.FromSeconds 5.0)
                    Expect.equal (w.Fails key) 2 "both results are on record once settled"
                })

            testT "partial signatures are not checked in the background (threshold paths unchanged)" (fun () ->
                task {
                    let fake = FakeDirk("rc-dirk-6:1", ValueNone, Map [ "G/A", shareSecret ])
                    let w = SignatureWatch("dirk", "rc-dirk-6:1", Log.none)
                    let e = DirkEndpoint(fake.Api, false, TimeSpan.FromSeconds 5.0, Log.none, GloasCalls.Auto, w)

                    e.SetAccount(
                        key,
                        {
                            Name = "G/A"
                            Share = ValueSome(struct (1UL, ValueSome shareKey))
                        }
                    )
                    |> ignore

                    fake.Answer <-
                        fun _ ->
                            ValueSome
                                {
                                    State = ResponseState.Succeeded
                                    Signature = (sign shareSecret (root 99)).Bytes
                                }

                    let shares = e.Backend "dirk-g" true (fun _ a -> a.Share.IsSome)

                    for t in 2UL .. 5UL do
                        let! o = shares.Sign (request key (att t)) CancellationToken.None

                        Expect.isTrue
                            (match o with
                             | Partial(1UL, _) -> true
                             | _ -> false)
                            o.Describe

                    Expect.equal w.Pending 0 "no check queued"
                    Expect.isFalse w.Tracking "no failed check on record"
                    e.Stop()
                    let signer = FakeSigner("http://rc-w3s-2", [ shareKey, shareSecret ])
                    let w2 = SignatureWatch("web3signer", "http://rc-w3s-2", Log.none)
                    let x = SignerEndpoint(signer.Api, TimeSpan.FromSeconds 1.0, Log.none, w2)
                    let! _ = x.Refresh CancellationToken.None
                    signer.Override <- fun _ -> Some(Answer.Signature(sign shareSecret (root 99)))
                    let member' = x.Shares "w-g" 2UL (Dictionary<PubKey, PubKey>(dict [ key, shareKey ]))

                    for t in 2UL .. 5UL do
                        let! o = member'.Sign (req key (att t)) CancellationToken.None

                        Expect.isTrue
                            (match o with
                             | Partial(2UL, _) -> true
                             | _ -> false)
                            o.Describe

                    Expect.equal w2.Pending 0 "no check queued"
                    Expect.isFalse w2.Tracking "no failed check on record"
                })
        ]
