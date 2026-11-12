/// Retiring keys a remote signer no longer lists: the absence count (unit and property tests)
/// and the Dirk, Web3Signer and TEE modules over their fakes.
module Eplix.Tests.RetirementTests

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Dirk
open Eplix.Backend.Dirk.Messages
open Eplix.Backend.Tee
open Eplix.Backend.Web3Signer
open Eplix.Tests.TestUtil
open Eplix.Tests.FakeBeaconNode
open Eplix.Tests.SchedulerTests
open Eplix.Tests.ThresholdTests
open Eplix.Tests.DirkTests
open Eplix.Tests.Web3SignerTests
open Eplix.Tests.RemoteKeysTests
open Eplix.Tests.TeeTests

/// A cheap distinct key for the pure tests (no BLS).
let private keyN (i: int) = PubKey.Of(Array.init 48 (fun j -> if j = 0 then byte i else 0x11uy))

let private listed (m: string) (keys: PubKey list) =
    {
        Member = m
        Keys = ValueSome(keys :> IReadOnlyCollection<_>)
    }

let private down (m: string) = { Member = m; Keys = ValueNone }

/// Runs the polls through a fresh tracker; returns the keys retired at each poll.
let private run (polls: int) (answers: MemberAnswer list list) =
    let t = AbsenceTracker()
    [ for a in answers -> t.Step(polls, a) |> List.map fst ]

/// Per poll and member: down, or the subset of four keys a bit mask names (0 is empty).
let private decode (b: byte) =
    if b % 20uy >= 16uy then
        ValueNone
    else
        ValueSome(
            [
                for i in 0..3 do
                    if (int b >>> i) &&& 1 = 1 then
                        keyN i
            ]
            :> IReadOnlyCollection<_>
        )

/// The rule the property checks, written apart from the tracker: a key retired at poll t was
/// listed at some poll s > its previous retirement, no answer listed it after s, and in each of
/// the last n polls every member that listed it at s answered with a non-empty list.
let private retiredRightly (n: int) (polls: MemberAnswer list[]) (retired: PubKey list list) =
    let lists (p: MemberAnswer list) k =
        p
        |> List.exists (fun a ->
            match a.Keys with
            | ValueSome s -> Seq.contains k s
            | ValueNone -> false)

    let mutable ok = true
    let lastRetired = Collections.Generic.Dictionary<PubKey, int>()

    for t, keys in List.indexed retired do
        for k in keys do
            let s = [ 0..t ] |> List.filter (fun i -> lists polls[i] k) |> List.tryLast

            match s with
            | None -> ok <- false
            | Some s ->
                let before =
                    match lastRetired.TryGetValue k with
                    | true, r -> r
                    | _ -> -1

                let holders =
                    [
                        for a in polls[s] do
                            match a.Keys with
                            | ValueSome x when Seq.contains k x -> a.Member
                            | _ -> ()
                    ]

                let answeredFine (p: MemberAnswer list) m =
                    let mine = p |> List.filter (fun a -> a.Member = m)

                    not mine.IsEmpty
                    && mine
                       |> List.forall (fun a ->
                           match a.Keys with
                           | ValueSome x -> x.Count > 0
                           | ValueNone -> false)

                if s <= before || t - s < n then
                    ok <- false

                for i in t - n + 1 .. t do
                    if i <= s || not (holders |> List.forall (answeredFine polls[i])) then
                        ok <- false

            lastRetired[k] <- t

    ok

/// The old tracker (a Map and a Set per key rebuilt each poll), kept as the reference
/// the dictionary tracker must match.
type private RefTracker =
    {
        RefHolders: Map<PubKey, Set<string>>
        RefMisses: Map<PubKey, int>
    }

let private refStep (polls: int) (answers: MemberAnswer list) (t: RefTracker) =
    let polls = max 1 polls

    let failed =
        answers
        |> List.filter (fun a ->
            match a.Keys with
            | ValueSome k -> k.Count = 0
            | ValueNone -> true)
        |> List.map (fun a -> a.Member)
        |> set

    let answered =
        answers
        |> List.choose (fun a ->
            match a.Keys with
            | ValueSome k when k.Count > 0 && not (failed.Contains a.Member) -> Some(a.Member, k)
            | _ -> None)

    let answeredSet = answered |> List.map fst |> set
    let listers = Collections.Generic.Dictionary<PubKey, Set<string>>()

    for m, keys in answered do
        for k in keys do
            listers[k] <-
                (match listers.TryGetValue k with
                 | true, s -> s
                 | _ -> Set.empty)
                    .Add
                    m

    let mutable holders = Map.empty
    let mutable misses = Map.empty
    let gone = ResizeArray()

    for KeyValue(k, now) in listers do
        let silent =
            match t.RefHolders.TryFind k with
            | Some old -> old |> Set.filter (fun m -> not (answeredSet.Contains m))
            | None -> Set.empty

        holders <- holders.Add(k, Set.union now silent)

    for KeyValue(k, old) in t.RefHolders do
        if not (listers.ContainsKey k) then
            if not old.IsEmpty && old |> Set.forall answeredSet.Contains then
                let n = (t.RefMisses.TryFind k |> Option.defaultValue 0) + 1

                if n >= polls then
                    gone.Add(k, old)
                else
                    holders <- holders.Add(k, old)
                    misses <- misses.Add(k, n)
            else
                holders <- holders.Add(k, old)

    {
        RefHolders = holders
        RefMisses = misses
    },
    List.ofSeq gone

/// Steps both trackers through the polls; true when each poll retires the same keys with the same
/// holders and leaves the same holders and counts.
let private sameAsReference (polls: int) (answers: MemberAnswer list list) =
    let t = AbsenceTracker()

    let mutable r =
        {
            RefHolders = Map.empty
            RefMisses = Map.empty
        }

    answers
    |> List.forall (fun a ->
        let gone = t.Step(polls, a)
        let next, refGone = refStep polls a r
        r <- next

        let refState =
            next.RefHolders |> Map.map (fun k h -> h, (next.RefMisses.TryFind k |> Option.defaultValue 0))

        gone = refGone && t.Snapshot() = refState)

/// One answer from a byte and a mask: the member (m1 to m3, one answer in six down) and the keys
/// of eight the mask names; bit 14 makes the list empty, bit 15 lists each key twice.
let private answerOf (who: byte, mask: uint16) =
    let m = $"m{1 + int who % 3}"

    if (int who / 3) % 6 = 0 then
        { Member = m; Keys = ValueNone }
    else
        let keys =
            if mask &&& 0x4000us <> 0us then
                []
            else
                [
                    for i in 0..7 do
                        if (int mask >>> i) &&& 1 = 1 then
                            keyN i
                ]

        let keys = if mask &&& 0x8000us <> 0us then keys @ keys else keys

        {
            Member = m
            Keys = ValueSome(keys :> IReadOnlyCollection<_>)
        }

let private pureTests =
    let a, b, c = keyN 1, keyN 2, keyN 3

    testList
        "absence count"
        [
            test "a key gone from every member is retired at the second poll without it" {
                let polls =
                    [
                        [ listed "m1" [ a; b ]; listed "m2" [ b ] ]
                        [ listed "m1" [ b ]; listed "m2" [ b ] ]
                        [ listed "m1" [ b ]; listed "m2" [ b ] ]
                        [ listed "m1" [ b ]; listed "m2" [ b ] ]
                    ]

                Expect.equal (run 2 polls) [ []; []; [ a ]; [] ] "retired once, at poll 3"
                Expect.equal (run 1 polls) [ []; [ a ]; []; [] ] "with one poll"
            }

            test "a key another member still lists stays" {
                let polls = [ for _ in 1..5 -> [ listed "m1" [ b ]; listed "m2" [ a; b ] ] ]
                Expect.equal (run 2 polls) [ for _ in 1..5 -> [] ] "never retired"
            }

            test "a holder that is down, or answers an empty list, stops the count" {
                let polls =
                    [
                        [ listed "m1" [ a; b ]; listed "m2" [ a; c ] ]
                        [ listed "m1" [ b ]; down "m2" ]
                        [ listed "m1" [ b ]; down "m2" ]
                        [ listed "m1" [ b ]; listed "m2" [] ]
                        [ listed "m1" [ b ]; listed "m2" [ c ] ]
                        [ down "m1"; listed "m2" [ c ] ]
                        [ listed "m1" [ b ]; listed "m2" [ c ] ]
                        [ listed "m1" [ b ]; listed "m2" [ c ] ]
                    ]

                Expect.equal
                    (run 2 polls)
                    [ []; []; []; []; []; []; []; [ a ] ]
                    "only after two polls in which both holders answered"
            }

            test "a member down since the start holds nothing; one that left the key stops holding it" {
                let polls =
                    [
                        [ listed "m1" [ a; b ]; down "m2" ]
                        [ listed "m1" [ b ]; down "m2" ]
                        [ listed "m1" [ b ]; down "m2" ]
                    ]

                Expect.equal (run 2 polls) [ []; []; [ a ] ] "m2 never listed the key"

                let moved =
                    [
                        [ listed "m1" [ a; b ]; listed "m2" [ c ] ]
                        [ listed "m1" [ b ]; listed "m2" [ a; c ] ]
                        [ listed "m1" [ b ]; listed "m2" [ c ] ]
                        [ down "m1"; listed "m2" [ c ] ]
                        [ down "m1"; listed "m2" [ c ] ]
                    ]

                Expect.equal (run 2 moved) [ []; []; []; [ a ]; [] ] "m2 holds the key alone after the move"
            }

            test "nothing is retired while every answer is failed or empty" {
                let polls =
                    [ [ listed "m1" [ a ] ] ]
                    @ [ for i in 1..6 -> [ (if i % 2 = 0 then down "m1" else listed "m1" []) ] ]

                Expect.equal (run 2 polls |> List.concat) [] "no retirement"
            }

            test "a retired key that is listed again is counted afresh" {
                let gone = [ listed "m1" [ b ] ]
                let back = [ listed "m1" [ a; b ] ]

                Expect.equal
                    (run 2 [ back; gone; gone; gone; back; gone; gone ])
                    [ []; []; [ a ]; []; []; []; [ a ] ]
                    "twice, each after two polls"
            }

            testPropN
                "no key is retired while an answer lists it, before n polls, or on failed or empty answers"
                300
                (fun (raw: (byte * byte * byte) list) (nRaw: byte) ->
                    let n = 1 + int nRaw % 3

                    let polls =
                        [|
                            for x, y, z in raw ->
                                [ for m, b in [ "m1", x; "m2", y; "m3", z ] -> { Member = m; Keys = decode b } ]
                        |]

                    let retired = run n (List.ofArray polls)
                    retiredRightly n polls retired)
            testPropN
                "the dictionary tracker retires and holds as the Map tracker did"
                500
                (fun (raw: (byte * uint16) list list) (nRaw: byte) ->
                    sameAsReference (1 + int nRaw % 3) (raw |> List.map (List.map answerOf)))

            test "10,000 keys over 3 members: the same as the Map tracker, poll by poll" {
                let keys =
                    [|
                        for i in 0..9999 ->
                            PubKey.Of(
                                Array.init 48 (fun j ->
                                    if j = 4 then byte i
                                    elif j = 5 then byte (i >>> 8)
                                    else 0x22uy)
                            )
                    |]

                let from (n: int) = keys[n..] :> IReadOnlyCollection<_>
                let all = from 0

                let polls =
                    [
                        [
                            { Member = "m1"; Keys = ValueSome all }
                            { Member = "m2"; Keys = ValueSome all }
                            { Member = "m3"; Keys = ValueSome all }
                        ]
                        [
                            { Member = "m1"; Keys = ValueSome all }
                            down "m2"
                            {
                                Member = "m3"
                                Keys = ValueSome(from 100)
                            }
                        ]
                        [
                            {
                                Member = "m1"
                                Keys = ValueSome(from 100)
                            }
                            {
                                Member = "m2"
                                Keys = ValueSome(from 200)
                            }
                            {
                                Member = "m3"
                                Keys = ValueSome(from 100)
                            }
                        ]
                        [
                            {
                                Member = "m1"
                                Keys = ValueSome(from 100)
                            }
                            {
                                Member = "m2"
                                Keys = ValueSome(from 200)
                            }
                            {
                                Member = "m3"
                                Keys = ValueSome(from 100)
                            }
                        ]
                        [
                            {
                                Member = "m1"
                                Keys = ValueSome(from 100)
                            }
                            {
                                Member = "m2"
                                Keys = ValueSome(from 200)
                            }
                            {
                                Member = "m3"
                                Keys = ValueSome(from 100)
                            }
                        ]
                        [
                            { Member = "m1"; Keys = ValueSome all }
                            { Member = "m2"; Keys = ValueSome all }
                            { Member = "m3"; Keys = ValueSome all }
                        ]
                    ]

                Expect.isTrue (sameAsReference 2 polls) "same retirements, holders and counts"
                let t = AbsenceTracker()
                let counts = polls |> List.map (fun a -> t.Step(2, a).Length)

                Expect.equal
                    counts
                    [ 0; 0; 0; 100; 0; 0 ]
                    "the 100 keys no member lists go at the second poll without them"
            }
        ]

/// A RANDAO reveal for the key, through the pipeline.
let private signWith (core: CoreServices) (h: Harness) (k: PubKey) =
    let req =
        Duty.request h.Spec gvr k Priority.High (h.Time.GetUtcNow().AddSeconds 10.0) (Duty.RandaoReveal 1UL)

    req, core.Pipeline.Sign(req, CancellationToken.None)

let private isSigned (o: SignOutcome) =
    match o with
    | Signed _ -> true
    | _ -> false

let private stateOf (core: CoreServices) (k: PubKey) = (core.Registry.TryGet k).Value.State

/// One poll as the modules run it: register what was found, then count the absences.
let private poll
    (keys: ListedKeys)
    (core: CoreServices)
    (found: (PubKey * Backend) list)
    (answers: MemberAnswer list)
    (retirable: PubKey -> bool)
    =
    task {
        let added = keys.Register found
        let! gone = keys.Retire(answers, retirable, CancellationToken.None)

        if added > 0 then
            do! core.RefreshKeys CancellationToken.None

        return gone
    }

let private dirkSettings (endpoints: string list) : DirkModule.Settings =
    {
        Endpoints = endpoints
        Accounts = [ "W"; "Dist" ]
        Tls =
            {
                CaCert = ""
                ClientCert = ""
                ClientKey = ""
            }
        Timeout = TimeSpan.FromSeconds 2.0
        BatchAttestations = false
        RefreshInterval = TimeSpan.Zero
        GloasCalls = GloasCalls.Auto
        ReloadInterval = TimeSpan.Zero
    }

let private plain (accounts: (string * int) list) =
    ValueSome
        {
            State = ResponseState.Succeeded
            Accounts =
                [
                    for n, i in accounts ->
                        {
                            Name = n
                            PublicKey = (pubkeyOf i).Bytes
                        }
                ]
            DistributedAccounts = []
        }

let private dirkTests =
    testList
        "dirk"
        [
            testT "a key no endpoint lists is retired after two polls and signs again once listed" (fun () ->
                task {
                    let h = harness ()

                    for i in 0..2 do
                        h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                    use tc = new TestCore(h, tempDir ())
                    let core = tc.Services
                    let both = plain [ "W/0", 0; "W/1", 1 ]
                    let d1 = FakeDirk("dirk1:1", both, Map [ "W/0", secretOf 0; "W/1", secretOf 1 ])
                    let d2 = FakeDirk("dirk2:2", plain [ "W/2", 2 ], Map [ "W/2", secretOf 2 ])
                    let fakes = Map [ "dirk1:1", d1; "dirk2:2", d2 ]

                    let set =
                        DirkModule.DirkSet(
                            (fun a -> fakes[a].Api),
                            dirkSettings [ "dirk1:1"; "dirk2:2" ],
                            TimeProvider.System,
                            Log.none
                        )

                    let keys = ListedKeys("dirk", core.Registry, core.Pipeline, Log.none)

                    let pollDirk () =
                        task {
                            let! found, _ = set.Discover CancellationToken.None
                            return! poll keys core found set.LastAnswers (fun _ -> true)
                        }

                    let! gone = pollDirk ()
                    Expect.isEmpty gone "first poll"
                    let _, o = signWith core h (pubkeyOf 0)
                    let! o = o
                    Expect.isTrue (isSigned o) $"key 0 signs ({o.Describe})"
                    d1.Listing <- plain [ "W/1", 1 ]
                    let! gone = pollDirk ()
                    Expect.isEmpty gone "one poll without key 0"
                    Expect.equal (stateOf core (pubkeyOf 0)) KeyState.Active "still active"
                    let! gone = pollDirk ()
                    Expect.equal gone [ pubkeyOf 0 ] "two polls without key 0"
                    Expect.equal (stateOf core (pubkeyOf 0)) KeyState.Removed "removed"
                    let _, o = signWith core h (pubkeyOf 0)
                    let! o = o
                    Expect.isFalse (isSigned o) "a retired key signs nothing"
                    // Dirk 2 down: its key stays, however many polls.
                    d2.Down <- true

                    for _ in 1..4 do
                        let! gone = pollDirk ()
                        Expect.isEmpty gone "an endpoint that is down retires nothing"

                    Expect.equal (stateOf core (pubkeyOf 2)) KeyState.Active "key 2 stays active"
                    // Key 0 comes back: the history check runs again and it signs.
                    d1.Listing <- both
                    let! _ = pollDirk ()
                    Expect.equal (stateOf core (pubkeyOf 0)) KeyState.Active "active again after the history check"
                    let _, o = signWith core h (pubkeyOf 0)
                    let! o = o
                    Expect.isTrue (isSigned o) $"key 0 signs again ({o.Describe})"
                    set.Stop()
                })

            testT "a distributed account stays while a participant that held it is down" (fun () ->
                task {
                    let h = harness ()
                    use tc = new TestCore(h, tempDir ())
                    let core = tc.Services
                    let secret, shares = shamir 31 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret

                    let participants =
                        [
                            for i in 1UL .. 3UL ->
                                {
                                    Id = i
                                    Name = $"dirk{i}"
                                    Port = uint32 i
                                }
                        ]

                    let withDist (id: uint64) (share: byte[]) =
                        ValueSome
                            {
                                State = ResponseState.Succeeded
                                Accounts =
                                    [
                                        {
                                            Name = $"W/{id}"
                                            PublicKey = (pubkeyOf (int id)).Bytes
                                        }
                                    ]
                                DistributedAccounts =
                                    [
                                        {
                                            Name = "Dist/V1"
                                            PublicKey = (pk share).Bytes
                                            Participants = participants
                                            SigningThreshold = 2u
                                            CompositePublicKey = key.Bytes
                                        }
                                    ]
                            }

                    let fakes =
                        [
                            for id, share in shares ->
                                $"dirk{id}:{id}", FakeDirk($"dirk{id}:{id}", withDist id share, Map.empty)
                        ]
                        |> Map.ofList

                    let set =
                        DirkModule.DirkSet(
                            (fun a -> fakes[a].Api),
                            dirkSettings [ "dirk1:1"; "dirk2:2"; "dirk3:3" ],
                            TimeProvider.System,
                            Log.none
                        )

                    let keys = ListedKeys("dirk", core.Registry, core.Pipeline, Log.none)

                    let pollDirk () =
                        task {
                            let! found, _ = set.Discover CancellationToken.None
                            return! poll keys core found set.LastAnswers (fun _ -> true)
                        }

                    let! _ = pollDirk ()
                    Expect.isSome (core.Registry.TryGet key |> ValueOption.toOption) "the composite key is registered"
                    fakes["dirk3:3"].Down <- true

                    for id in 1..2 do
                        fakes[$"dirk{id}:{id}"].Listing <- plain [ $"W/{id}", id ]

                    for _ in 1..3 do
                        let! gone = pollDirk ()
                        Expect.isEmpty gone "dirk3 held the account and did not answer"

                    Expect.notEqual (stateOf core key) KeyState.Removed "not retired"
                    fakes["dirk3:3"].Down <- false
                    fakes["dirk3:3"].Listing <- plain [ "W/3", 3 ]
                    let! gone = pollDirk ()
                    Expect.isEmpty gone "one poll with every participant answering"
                    let! gone = pollDirk ()
                    Expect.equal gone [ key ] "retired after two"
                    set.Stop()
                })

            testT
                "a Dirk account the instance is not in is ignored; one it is in meets the whole key and is refused"
                (fun () ->
                    task {
                        let h = harness ()
                        use tc = new TestCore(h, tempDir ())
                        let core = tc.Services
                        let key = pubkeyOf 0

                        let local =
                            Eplix.Backend.Local.LocalBackend.create
                                "local"
                                [ key, Eplix.Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                        Expect.isTrue (core.Registry.Add(key, local)) "the whole key on the local backend"

                        // A 1 of 1 distributed account of the key: at another participant's address,
                        // then at the listing instance's own.
                        let listing (participant: string) =
                            ValueSome
                                {
                                    State = ResponseState.Succeeded
                                    Accounts = []
                                    DistributedAccounts =
                                        [
                                            {
                                                Name = "Dist/K"
                                                PublicKey = key.Bytes
                                                Participants =
                                                    [
                                                        {
                                                            Id = 1UL
                                                            Name = participant
                                                            Port = 1u
                                                        }
                                                    ]
                                                SigningThreshold = 1u
                                                CompositePublicKey = key.Bytes
                                            }
                                        ]
                                }

                        let d1 = FakeDirk("dirk1:1", listing "elsewhere", Map.empty)
                        let log, lines = Log.memory ()

                        let set =
                            DirkModule.DirkSet((fun _ -> d1.Api), dirkSettings [ "dirk1:1" ], TimeProvider.System, log)

                        let keys = ListedKeys("dirk", core.Registry, core.Pipeline, log)

                        let pollDirk () =
                            task {
                                let! found, _ = set.Discover CancellationToken.None
                                let! _ = poll keys core found set.LastAnswers (fun _ -> true)
                                return found
                            }

                        for _ in 1..2 do
                            let! found = pollDirk ()
                            Expect.isEmpty found "a group the instance is not in is not routed"

                        Expect.isEmpty core.Registry.Refused "an ignored listing refuses nothing"
                        Expect.equal (stateOf core key) KeyState.Discovered "the local route stays in use"
                        Expect.equal (core.Registry.TryGet key).Value.Backend.Name "local" "on the local backend"

                        Expect.isTrue
                            (lines |> Seq.exists (fun l -> l.Contains "no participant at this address"))
                            "a warning says why"

                        d1.Listing <- listing "dirk1"
                        let! found = pollDirk ()
                        Expect.equal (List.map fst found) [ key ] "a group the instance is in is listed"
                        Expect.equal (core.Registry.Refused |> List.map fst) [ key ] "whole and split: refused"
                        let reason = core.Registry.Refused |> List.head |> snd
                        Expect.stringContains reason "whole on local" "names the local module"
                        Expect.stringContains reason "split in dirk" "names the dirk module"
                        Expect.equal (stateOf core key) KeyState.Removed "signs on no route"
                        set.Stop()
                    })

            testT "a key whole in one module and split in another is refused in every module order" (fun () ->
                task {
                    let h = harness ()
                    use tc = new TestCore(h, tempDir ())
                    let secret, shares = shamir 972 2 [ 1UL; 2UL; 3UL ]
                    let key = pk secret
                    let ms = [ for i, s in shares -> FakeMember(i, key, s, partialOf i s, TimeSpan.Zero) ]

                    let groupNamed (name: string) =
                        Threshold.create
                            name
                            2
                            [
                                for x, i in List.zip ms [ 1UL; 2UL; 3UL ] ->
                                    {
                                        Backend = x.Backend
                                        Index = i
                                        Budget = TimeSpan.FromSeconds 5.0
                                    }
                            ]
                            TimeProvider.System
                            Log.none

                    let whole =
                        [
                            "local", { ms[0].Backend with Name = "local" }
                            "web3signer",
                            { ms[0].Backend with
                                Name = "web3signer http://w3s.test/"
                            }
                        ]

                    let split =
                        [
                            "dirk", groupNamed "dirk 2 of 3 (1,2,3)"
                            "web3signer", groupNamed "web3signer 2 of 3 (a,b,c)"
                            "tee", groupNamed "tee 2 of 3 (r1,r2,r3)"
                        ]

                    // A route as its module offers it: the local module's keys through the
                    // runner's registry.Add (a keymanager import through Revive), a remote signer
                    // module's through its ListedKeys.
                    let offer (registry: KeyRegistry) (lists: Dictionary<string, ListedKeys>) (m: string, b: Backend) =
                        if m = "local" then
                            if registry.TryGet key |> ValueOption.isSome then
                                registry.Revive(key, b) |> ignore
                            else
                                registry.Add(key, b) |> ignore
                        else
                            let keys =
                                match lists.TryGetValue m with
                                | true, k -> k
                                | _ ->
                                    let k = ListedKeys(m, registry, tc.Services.Pipeline, Log.none)
                                    lists[m] <- k
                                    k

                            keys.Register [ key, b ] |> ignore

                    for w in whole do
                        for s in split do
                            for first, second in [ w, s; s, w ] do
                                // At start (activation closed until every module started), and
                                // at a later key list with the first route already active.
                                for atStart in [ true; false ] do
                                    let what =
                                        $"""{fst first} then {fst second} {if atStart then "at start" else "later"}"""

                                    let registry = KeyRegistry()
                                    let lists = Dictionary<string, ListedKeys>()

                                    if atStart then
                                        registry.CloseActivation()

                                    offer registry lists first

                                    if not atStart then
                                        registry.SetState(key, KeyState.Active)

                                    offer registry lists second
                                    // The next key lists offer both again; the start then opens activation.
                                    offer registry lists first
                                    offer registry lists second
                                    registry.SetState(key, KeyState.HistoryChecked)
                                    registry.OpenActivation()
                                    Expect.equal (registry.Refused |> List.map fst) [ key ] $"{what}: refused"
                                    let reason = registry.Refused |> List.head |> snd
                                    Expect.stringContains reason (snd w).Name $"{what}: names the whole route"
                                    Expect.stringContains reason (snd s).Name $"{what}: names the group"

                                    Expect.equal
                                        (registry.TryGet key).Value.State
                                        KeyState.Removed
                                        $"{what}: signs on no route"
                })
        ]

let private urlA = "http://w3s-ra.test:9000/"
let private urlB = "http://w3s-rb.test:9000/"
let private urlC = "http://w3s-rc.test:9000/"

let private web3signerTests =
    testList
        "web3signer"
        [
            testT
                "a key the signer drops is retired after two polls; API and group keys stay; a key that comes back signs"
                (fun () ->
                    task {
                        let h = harness ()

                        for i in 0..2 do
                            h.Node.AddValidator(pubkeyOf i, "active_ongoing") |> ignore

                        use tc = new TestCore(h, tempDir ())
                        let core = tc.Services
                        let a = FakeSigner(urlA, [ for i in 0..1 -> pubkeyOf i, secretOf i ])
                        let b = FakeSigner(urlB, [ pubkeyOf 2, secretOf 2 ])
                        let c = FakeSigner(urlC, [ pubkeyOf 6, secretOf 6 ])

                        let connect (e: EndpointSettings) =
                            match e.Url.AbsoluteUri with
                            | u when u = urlA -> a.Api
                            | u when u = urlB -> b.Api
                            | u when u = urlC -> c.Api
                            | u -> failtestf "no fake signer at %s" u

                        let settings =
                            { Web3SignerModule.apiOnly with
                                Signers =
                                    [
                                        {
                                            Url = Uri urlA
                                            Tls = TlsSettings.None
                                            Attestation = ValueNone
                                        }
                                    ]
                                Groups =
                                    [
                                        {
                                            Threshold = 1
                                            Members =
                                                [
                                                    1UL,
                                                    {
                                                        Url = Uri urlC
                                                        Tls = TlsSettings.None
                                                        Attestation = ValueNone
                                                    }
                                                ]
                                            Keys =
                                                [
                                                    {
                                                        PubKey = pubkeyOf 5
                                                        Shares = Map [ 1UL, pubkeyOf 6 ]
                                                    }
                                                ]
                                        }
                                    ]
                            }

                        let set = Web3SignerModule.Web3SignerSet(connect, settings, h.Time, Log.none)
                        let keys = ListedKeys("web3signer", core.Registry, core.Pipeline, Log.none)
                        let! found, _ = set.Discover CancellationToken.None
                        keys.Register found |> ignore
                        let store = Web3SignerModule.RemoteKeys.start false core set
                        core.SetRemoteKeys store
                        let retirable = Web3SignerModule.RemoteKeys.retirable set store

                        let pollW3s () =
                            task {
                                let! found, _ = set.Discover CancellationToken.None
                                return! poll keys core found set.LastAnswers retirable
                            }

                        let! _ = pollW3s ()
                        let! st, text = callApi core "POST" (importBody [ pubkeyOf 2, Some urlB ])
                        Expect.equal st 200 text
                        Expect.equal (stateOf core (pubkeyOf 0)) KeyState.Active "configured key active"
                        Expect.equal (stateOf core (pubkeyOf 2)) KeyState.Active "API key active"
                        Expect.isTrue (core.Registry.TryGet(pubkeyOf 5)).IsSome "group key registered"
                        Expect.isFalse (retirable (pubkeyOf 2)) "an API key is not retired"
                        Expect.isFalse (retirable (pubkeyOf 5)) "a group key is not retired"

                        Expect.equal
                            (set.LastAnswers |> List.map (fun x -> x.Member))
                            [ a.Api.Url ]
                            "only the configured whole-key signer counts"

                        a.Keys.Remove(pubkeyOf 1) |> ignore
                        b.Keys.Clear()
                        c.Keys.Clear()
                        let! gone = pollW3s ()
                        Expect.isEmpty gone "one poll"
                        let! gone = pollW3s ()
                        Expect.equal gone [ pubkeyOf 1 ] "key 1 retired after two polls"
                        Expect.equal (stateOf core (pubkeyOf 1)) KeyState.Removed "removed"
                        Expect.equal (stateOf core (pubkeyOf 2)) KeyState.Active "the API key stays"
                        Expect.notEqual (stateOf core (pubkeyOf 5)) KeyState.Removed "the group key stays"
                        // The signer is down: key 0 stays.
                        a.Up <- false

                        for _ in 1..3 do
                            let! gone = pollW3s ()
                            Expect.isEmpty gone "a signer that is down retires nothing"

                        Expect.equal (stateOf core (pubkeyOf 0)) KeyState.Active "key 0 stays"
                        a.Up <- true
                        a.Keys[pubkeyOf 1] <- secretOf 1
                        let! _ = pollW3s ()

                        Expect.equal
                            (stateOf core (pubkeyOf 1))
                            KeyState.Active
                            "key 1 is back after the history check"

                        let _, o = signWith core h (pubkeyOf 1)
                        let! o = o
                        Expect.isTrue (isSigned o) $"key 1 signs again ({o.Describe})"
                        set.Stop()
                    })
        ]

let private runnerConfig (n: string) : TeeModule.RunnerConfig =
    {
        Name = n
        Host = "127.0.0.1"
        Port = 1
        ClientCert = ""
        ClientKey = ""
        TlsKeyPin = ValueNone
        AllowTestnetBuild = false
        Connections = 1
        Attestation = Attest.Settings.Empty
    }

/// Makes a fake runner list these (validator key, share secret) pairs, or fail when down.
let private listsOnly (r: FakeRunner) (keys: (PubKey * byte[]) list) =
    let body =
        Wire.encodeKeys
            [
                for v, s in keys ->
                    {
                        PubKey = v
                        SharePubKey = pk s
                        Index = Wire.IndexUnknown
                    }
            ]

    r.Behave(fun p -> if p.Length = 0 then ValueSome(Reply.Body body) else ValueNone)

let private runnerDown (r: FakeRunner) =
    r.Behave(fun p -> if p.Length = 0 then ValueSome(Reply.Failure(Transport "connection refused")) else ValueNone)

let private teeTests =
    testList
        "tee"
        [
            testT
                "an allowlisted key stays while a runner that held it is down, goes after two polls, and signs once back"
                (fun () ->
                    task {
                        let h = harness ()
                        let secret, shares = shamir 77 2 [ 1UL; 2UL; 3UL ]
                        let g = pk secret
                        let w = pubkeyOf 3
                        let others = [ for i in 50..51 -> pubkeyOf i, secretOf i ]

                        for k in [ g; w ] do
                            h.Node.AddValidator(k, "active_ongoing") |> ignore

                        use tc = new TestCore(h, tempDir ())
                        let core = tc.Services
                        let share m = g, snd shares[m]
                        let r1 = FakeRunner("r1", [ w, secretOf 3; share 0 ])
                        let r2 = FakeRunner("r2", [ share 1; others[0] ])
                        let r3 = FakeRunner("r3", [ share 2; others[1] ])
                        let runners = [ r1; r2; r3 ]

                        let settings: TeeModule.Settings =
                            {
                                Runners = [ for n in [ "r1"; "r2"; "r3" ] -> runnerConfig n ]
                                Groups =
                                    [
                                        {
                                            Threshold = 2
                                            Members = [ "r1", 1UL; "r2", 2UL; "r3", 3UL ]
                                        }
                                    ]
                                Timeout = TimeSpan.FromSeconds 2.0
                                DialTimeout = TimeSpan.FromSeconds 5.0
                                LowEvery = 8
                                RefreshInterval = TimeSpan.Zero
                                Keys =
                                    TeeModule.KeyFilter.Only(
                                        set [ g.Hex.ToLowerInvariant(); w.Hex.ToLowerInvariant() ]
                                    )
                                AttestationCaFile = ValueNone
                                ReloadInterval = TimeSpan.Zero
                                RotateWithin = TimeSpan.FromSeconds 300.0
                                HaPeer = false
                                Network = Attest.NetworkKind.Testnet
                            }

                        let set =
                            TeeModule.TeeSet(
                                [ for cfg, r in List.zip settings.Runners runners -> cfg, r.Api ],
                                settings,
                                h.Time,
                                Log.none
                            )

                        let keys = ListedKeys("tee", core.Registry, core.Pipeline, Log.none)

                        let pollTee () =
                            task {
                                let! found, _ = set.Discover CancellationToken.None
                                return! poll keys core found set.LastAnswers (fun _ -> true)
                            }

                        let! _ = pollTee ()
                        Expect.equal (stateOf core g) KeyState.Active "group key active"
                        Expect.equal (stateOf core w) KeyState.Active "whole key active"

                        Expect.isNone
                            (core.Registry.TryGet(fst others[0]) |> ValueOption.toOption)
                            "keys outside the allowlist are not used"
                        // r3 is down; r1 and r2 drop the group key.
                        runnerDown r3
                        listsOnly r1 [ w, secretOf 3 ]
                        listsOnly r2 [ others[0] ]

                        for _ in 1..3 do
                            let! gone = pollTee ()
                            Expect.isEmpty gone "r3 held a share and did not answer"

                        Expect.equal (stateOf core g) KeyState.Active "the group key stays"
                        listsOnly r3 [ others[1] ]
                        let! gone = pollTee ()
                        Expect.isEmpty gone "one poll with every runner answering"
                        let! gone = pollTee ()
                        Expect.equal gone [ g ] "retired after two"
                        Expect.equal (stateOf core g) KeyState.Removed "removed"
                        // r1 down: the whole key stays.
                        runnerDown r1

                        for _ in 1..3 do
                            let! gone = pollTee ()
                            Expect.isEmpty gone "the runner of the whole key is down"

                        Expect.equal (stateOf core w) KeyState.Active "the whole key stays"
                        // Everything listed again: the group key passes the history check and signs.
                        for r in runners do
                            r.Behave(fun _ -> ValueNone)

                        let! _ = pollTee ()
                        Expect.equal (stateOf core g) KeyState.Active "active again"

                        let req =
                            Duty.request
                                h.Spec
                                gvr
                                g
                                Priority.High
                                (h.Time.GetUtcNow().AddSeconds 10.0)
                                (Duty.RandaoReveal 1UL)

                        for r in runners do
                            r.Expect req

                        let! o = core.Pipeline.Sign(req, CancellationToken.None)
                        Expect.isTrue (isSigned o) $"the group key signs again ({o.Describe})"
                        set.Stop()
                    })
        ]

let private drainTests =
    testList
        "drain"
        [
            testT "a request inside the slashing check when the drain starts never reaches the backend" (fun () ->
                task {
                    let h = harness ()

                    let local =
                        Backend.Local.LocalBackend.create
                            "remote"
                            [ pubkeyOf 0, Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                    let calls = ref 0

                    let backend =
                        { local with
                            Sign =
                                fun r ct ->
                                    Interlocked.Increment &calls.contents |> ignore
                                    local.Sign r ct
                        }

                    let registry = KeyRegistry()
                    registry.Add(pubkeyOf 0, backend) |> ignore
                    registry.SetState(pubkeyOf 0, KeyState.Active)
                    let gated = new SlashingTests.GatedFile(new SlashingTests.ModelFile([||]))

                    let db =
                        match Slashing.SlashingDb.Open(gated, gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    db.RegisterKeys [ pubkeyOf 0, Slashing.KeyOrigin.Imported ] |> ignore
                    let pipeline = Pipeline(db, registry, h.Time, Log.none)

                    let data =
                        {
                            Slot = h.Spec.SlotsPerEpoch
                            Index = 0UL
                            BeaconBlockRoot = Root.Zero
                            Source = { Epoch = 0UL; Root = Root.Zero }
                            Target = { Epoch = 1UL; Root = Root.Zero }
                        }

                    let req =
                        Duty.request
                            h.Spec
                            gvr
                            (pubkeyOf 0)
                            Priority.High
                            DateTimeOffset.MaxValue
                            (Duty.Attestation data)
                    // The request passes the state check and waits in the slashing DB's append.
                    gated.Armed <- true

                    let signing =
                        Task.Run<SignOutcome>(
                            Func<Task<SignOutcome>>(fun () -> pipeline.Sign(req, CancellationToken.None))
                        )

                    Expect.isTrue (gated.Entered.Wait(TimeSpan.FromSeconds 10.0)) "in the slashing check"
                    let cleaned = ref false

                    let drain =
                        KeyRetirement.drain
                            registry
                            pipeline
                            Log.none
                            (pubkeyOf 0)
                            (fun () -> cleaned.Value <- true)
                            CancellationToken.None

                    do! Task.Delay 200
                    Expect.isFalse cleaned.Value "the drain waits for the request in the slashing check"
                    gated.Release.Set()
                    let! outcome = signing
                    let! drained = drain
                    Expect.isTrue drained "the drain ran"
                    Expect.isTrue cleaned.Value "drained"
                    Expect.equal calls.Value 0 $"nothing reached the backend: %A{outcome}"
                    Expect.equal outcome (Refused(PolicyDenied "key is not active")) "refused"
                    Expect.equal (registry.TryGet(pubkeyOf 0)).Value.State KeyState.Removed "removed"
                })
            testT "a slow backend call of one key does not hold the drain of another key of the burst" (fun () ->
                task {
                    let h = harness ()

                    let local =
                        Backend.Local.LocalBackend.create
                            "remote"
                            [
                                for i in 0..1 -> pubkeyOf i, Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf i))
                            ]

                    let release = TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)
                    let key1Done = new ManualResetEventSlim(false)

                    let backend =
                        { local with
                            Sign =
                                fun r ct ->
                                    task {
                                        if r.Key = pubkeyOf 0 then
                                            let! _ = release.Task
                                            ()

                                        let! o = local.Sign r ct

                                        if r.Key = pubkeyOf 1 then
                                            key1Done.Set()

                                        return o
                                    }
                        }

                    let registry = KeyRegistry()

                    for i in 0..1 do
                        registry.Add(pubkeyOf i, backend) |> ignore
                        registry.SetState(pubkeyOf i, KeyState.Active)

                    let db =
                        match Slashing.SlashingDb.Open(new SlashingTests.ModelFile([||]), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, h.Time, Log.none)

                    let reqs =
                        [|
                            for i in 0..1 ->
                                Duty.request
                                    h.Spec
                                    gvr
                                    (pubkeyOf i)
                                    Priority.High
                                    DateTimeOffset.MaxValue
                                    (Duty.RandaoReveal 1UL)
                        |]

                    let signing = pipeline.SignBurst(reqs, CancellationToken.None)
                    Expect.isTrue (key1Done.Wait(TimeSpan.FromSeconds 10.0)) "key 1 signed"
                    let! idle = pipeline.WaitIdle([ pubkeyOf 1 ], TimeSpan.FromSeconds 1.0, CancellationToken.None)
                    Expect.isTrue idle "key 1 is idle while key 0's backend call still runs"

                    let! busy =
                        pipeline.WaitIdle([ pubkeyOf 0 ], TimeSpan.FromMilliseconds 50.0, CancellationToken.None)

                    Expect.isFalse busy "key 0 is still in flight"
                    release.SetResult true
                    let! outcomes = signing
                    Expect.isTrue (outcomes |> Array.forall isSigned) $"both signed: %A{outcomes}"
                    let! idle0 = pipeline.WaitIdle([ pubkeyOf 0 ], TimeSpan.FromSeconds 1.0, CancellationToken.None)
                    Expect.isTrue idle0 "key 0 idle after its call"
                })
            testT
                "a slashable refusal that ends after the drain removed the key leaves it removed, not halted"
                (fun () ->
                    task {
                        let h = harness ()

                        let local =
                            Backend.Local.LocalBackend.create
                                "remote"
                                [ pubkeyOf 0, Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                        let entered = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                        let release = TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)

                        let backend =
                            { local with
                                Sign =
                                    fun _ _ ->
                                        task {
                                            entered.TrySetResult() |> ignore
                                            do! release.Task
                                            return Refused(Slashable "the remote DB has a later vote")
                                        }
                            }

                        let registry = KeyRegistry()
                        registry.Add(pubkeyOf 0, backend) |> ignore
                        registry.SetState(pubkeyOf 0, KeyState.Active)

                        let db =
                            match Slashing.SlashingDb.Open(new SlashingTests.ModelFile([||]), gvr) with
                            | Ok db -> db
                            | Error e -> failwith e

                        db.RegisterKeys [ pubkeyOf 0, Slashing.KeyOrigin.Imported ] |> ignore
                        let pipeline = Pipeline(db, registry, h.Time, Log.none)

                        let data =
                            {
                                Slot = h.Spec.SlotsPerEpoch
                                Index = 0UL
                                BeaconBlockRoot = Root.Zero
                                Source = { Epoch = 0UL; Root = Root.Zero }
                                Target = { Epoch = 1UL; Root = Root.Zero }
                            }

                        let req =
                            Duty.request
                                h.Spec
                                gvr
                                (pubkeyOf 0)
                                Priority.High
                                DateTimeOffset.MaxValue
                                (Duty.Attestation data)

                        let signing = pipeline.Sign(req, CancellationToken.None)
                        do! entered.Task.WaitAsync(TimeSpan.FromSeconds 10.0)
                        // The drain's 5 s ran out with the call still in flight: draining, then removed.
                        registry.SetState(pubkeyOf 0, KeyState.Draining)
                        registry.SetState(pubkeyOf 0, KeyState.Removed)
                        release.SetResult()
                        let! outcome = signing

                        Expect.equal
                            outcome
                            (Refused(Slashable "the remote DB has a later vote"))
                            "the refusal comes back"

                        Expect.equal
                            (registry.TryGet(pubkeyOf 0)).Value.State
                            KeyState.Removed
                            "the removed key stays removed"
                        // Non-slashable duties would run for a halted key; a removed one signs nothing.
                        let! o =
                            pipeline.Sign(
                                Duty.request
                                    h.Spec
                                    gvr
                                    (pubkeyOf 0)
                                    Priority.High
                                    DateTimeOffset.MaxValue
                                    (Duty.RandaoReveal 1UL),
                                CancellationToken.None
                            )

                        Expect.equal o (Refused(PolicyDenied "key is not active")) "refused"
                    })
            testT "a slashable refusal of an active key still halts it" (fun () ->
                task {
                    let h = harness ()

                    let local =
                        Backend.Local.LocalBackend.create
                            "remote"
                            [ pubkeyOf 0, Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                    let backend =
                        { local with
                            Sign = fun _ _ -> Task.FromResult(Refused(Slashable "later vote"))
                        }

                    let registry = KeyRegistry()
                    registry.Add(pubkeyOf 0, backend) |> ignore
                    registry.SetState(pubkeyOf 0, KeyState.Active)

                    let db =
                        match Slashing.SlashingDb.Open(new SlashingTests.ModelFile([||]), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    db.RegisterKeys [ pubkeyOf 0, Slashing.KeyOrigin.Imported ] |> ignore
                    let pipeline = Pipeline(db, registry, h.Time, Log.none)

                    let data =
                        {
                            Slot = h.Spec.SlotsPerEpoch
                            Index = 0UL
                            BeaconBlockRoot = Root.Zero
                            Source = { Epoch = 0UL; Root = Root.Zero }
                            Target = { Epoch = 1UL; Root = Root.Zero }
                        }

                    let! _ =
                        pipeline.Sign(
                            Duty.request
                                h.Spec
                                gvr
                                (pubkeyOf 0)
                                Priority.High
                                DateTimeOffset.MaxValue
                                (Duty.Attestation data),
                            CancellationToken.None
                        )

                    match (registry.TryGet(pubkeyOf 0)).Value.State with
                    | KeyState.Halted _ -> ()
                    | s -> failtestf "expected halted, got %A" s
                })
            testT "a halted key is not drained, and an import of it does not bring it back" (fun () ->
                task {
                    let h = harness ()

                    let backend =
                        Backend.Local.LocalBackend.create
                            "local"
                            [ pubkeyOf 0, Backend.Local.SecretKey.Copy(ReadOnlySpan(secretOf 0)) ]

                    let registry = KeyRegistry()
                    registry.Add(pubkeyOf 0, backend) |> ignore
                    registry.SetState(pubkeyOf 0, KeyState.Active)
                    registry.SetState(pubkeyOf 0, KeyState.Halted "the signer refused a vote as slashable")

                    let db =
                        match Slashing.SlashingDb.Open(new SlashingTests.ModelFile([||]), gvr) with
                        | Ok db -> db
                        | Error e -> failwith e

                    let pipeline = Pipeline(db, registry, h.Time, Log.none)
                    let cleaned = ref false

                    let! drained =
                        KeyRetirement.drain
                            registry
                            pipeline
                            Log.none
                            (pubkeyOf 0)
                            (fun () -> cleaned.Value <- true)
                            CancellationToken.None

                    Expect.isFalse drained "the drain refuses a halted key"
                    Expect.isFalse cleaned.Value "the cleanup did not run"

                    let halted () =
                        match (registry.TryGet(pubkeyOf 0)).Value.State with
                        | KeyState.Halted _ -> true
                        | _ -> false

                    Expect.isTrue (halted ()) "still halted"
                    Expect.isFalse (registry.Revive(pubkeyOf 0, backend)) "a new import does not revive it"
                    Expect.isTrue (halted ()) "halted after the import"
                })
        ]

[<Tests>]
let tests =
    testSequenced
    <| testList "retirement" [ pureTests; dirkTests; web3signerTests; teeTests; drainTests ]
