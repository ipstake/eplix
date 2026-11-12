/// Obol mode against a real local Charon cluster (scripts/charon-local.sh): 4 Charon v1.11.2
/// nodes, threshold 3, on Charon's beacon mock in real time. Four whole VCs run in this process,
/// VC i with node i's key shares and node i's validator API as its beacon node, Obol mode on.
/// Checks that every VC gets combined beacon and sync committee selection proofs (each verifies
/// against the group key, the VC's own is a partial of its share), that the aggregates and
/// contributions the VCs send carry exactly the combined proofs Charon returned, and that Charon
/// combined the partial aggregates and contributions and submitted them. Runs only when
/// EPLIX_CHARON_NET names the cluster directory with the cluster running; scripts/charon-it.sh
/// does both. Two workarounds for the beacon mock: see committeeZero and asAsked.
module Eplix.Tests.CharonIntegrationTests

open System
open System.Collections.Concurrent
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Expecto
open Eplix
open Eplix.Backend.Local
open Eplix.Obol
open Eplix.Tests.TestUtil

let netDir = Environment.GetEnvironmentVariable "EPLIX_CHARON_NET"
let enabled = not (String.IsNullOrEmpty netDir)

let private nodes = [ 0..3 ]
let private apiUrl (i: int) = $"http://127.0.0.1:{3600 + i}"

/// The test gives up after this long, pass or fail.
let private limit = TimeSpan.FromMinutes 5.0

/// One call from a VC to its Charon node, request and answer.
type private Call =
    {
        Node: int
        Path: string
        Request: string
        Status: int
        Response: string
    }

let private watched =
    [
        Selections.BeaconCommitteePath
        Selections.SyncCommitteePath
        "/aggregate_and_proofs"
        "/contribution_and_proofs"
    ]

/// Charon v1.11.2 on its beacon mock answers GET /eth/v2/validator/aggregate_attestation only
/// for committee_index=0, whatever the aggregator's committee: other committees wait until the
/// VC gives up. The mock's aggregates carry committee 0's bit and an empty aggregation_bits list,
/// so Charon files each under committee 0, and the mock gives committee 0 to one validator only.
/// The VC asks with its duty's committee, as the Beacon API says; this rewrites the query to 0 so
/// every aggregation duty can complete. Returns the URI unchanged for any other request.
let private committeeZero (uri: Uri) =
    if uri.AbsolutePath.EndsWith "/aggregate_attestation" then
        let query =
            uri.Query.TrimStart('?').Split('&')
            |> Array.map (fun kv -> if kv.StartsWith "committee_index=" then "committee_index=0" else kv)

        UriBuilder(uri, Query = String.Join("&", query)).Uri
    else
        uri

let private queryValue (uri: Uri) (name: string) =
    uri.Query.TrimStart('?').Split('&')
    |> Array.pick (fun kv -> if kv.StartsWith(name + "=") then Some(kv.Substring(name.Length + 1)) else None)

/// Committee lengths by (slot, committee index), from the attester duties the VCs fetched.
let private committeeLengths = ConcurrentDictionary<struct (uint64 * uint64), uint64>()

let private noteDuties (json: string) =
    for d in JsonDocument.Parse(json).RootElement.GetProperty("data").EnumerateArray() do
        let field (name: string) = UInt64.Parse(d.GetProperty(name).GetString())
        committeeLengths[struct (field "slot", field "committee_index")] <- field "committee_length"

let private hex (bytes: byte array) = "0x" + Convert.ToHexString(bytes).ToLowerInvariant()

/// The VC refuses the mock's aggregate as it comes: an Electra aggregate for committee c carries
/// c's bit alone and one aggregation bit per member of c (consensus-specs, the
/// beacon_aggregate_and_proof checks), and the query rewrite above makes the answer committee
/// 0's. This gives the answer the shape a beacon node gives for the committee the VC asked: that
/// committee's bit alone and an aggregation_bits list of its length, no bit set, as the mock's.
/// The attestation data stays as Charon sent it, so all four VCs sign the same aggregate.
let private asAsked (asked: Uri) (json: string) =
    let slot = UInt64.Parse(queryValue asked "slot")
    let committee = UInt64.Parse(queryValue asked "committee_index")

    match committeeLengths.TryGetValue(struct (slot, committee)) with
    | false, _ -> json
    | true, length ->
        let root = Nodes.JsonNode.Parse json
        let data = root["data"]
        let width = Convert.FromHexString(data["committee_bits"].GetValue<string>().Substring 2).Length
        let committees = Array.zeroCreate<byte> width
        committees[int committee / 8] <- byte (1 <<< int committee % 8)
        // An SSZ bitlist: `length` bits, then the bit that marks the end.
        let members = Array.zeroCreate<byte>(int length / 8 + 1)
        members[int length / 8] <- byte (1 <<< int length % 8)
        data["committee_bits"] <- Nodes.JsonValue.Create(hex committees)
        data["aggregation_bits"] <- Nodes.JsonValue.Create(hex members)
        root.ToJsonString()

/// Records the selection and aggregation calls a VC makes to its node, and applies the two
/// beacon mock workarounds above.
type private Recorder(node: int, calls: ConcurrentQueue<Call>) =
    inherit DelegatingHandler(new SocketsHttpHandler())

    member private _.Pass(req: HttpRequestMessage, ct: CancellationToken) = base.SendAsync(req, ct)

    override this.SendAsync(req, ct) =
        let asked = nonNull req.RequestUri
        let uri = committeeZero asked
        req.RequestUri <- uri
        let path = uri.AbsolutePath

        if path.EndsWith "/aggregate_attestation" then
            task {
                let! resp = this.Pass(req, ct)

                if resp.IsSuccessStatusCode then
                    let! text = resp.Content.ReadAsStringAsync ct
                    resp.Content <- new StringContent(asAsked asked text, Encoding.UTF8, "application/json")

                return resp
            }
        elif path.Contains "/validator/duties/attester/" then
            task {
                let! resp = this.Pass(req, ct)

                if resp.IsSuccessStatusCode then
                    do! resp.Content.LoadIntoBufferAsync ct
                    let! text = resp.Content.ReadAsStringAsync ct
                    noteDuties text

                return resp
            }
        elif watched |> List.exists path.EndsWith then
            task {
                let! body =
                    match req.Content with
                    | null -> Task.FromResult ""
                    | c -> c.ReadAsStringAsync ct

                let! resp = this.Pass(req, ct)
                do! resp.Content.LoadIntoBufferAsync ct
                let! text = resp.Content.ReadAsStringAsync ct

                calls.Enqueue
                    {
                        Node = node
                        Path = path
                        Request = body
                        Status = int resp.StatusCode
                        Response = text
                    }

                return resp
            }
        else
            this.Pass(req, ct)

let private getJson (http: HttpClient) (url: string) =
    task {
        let! text = http.GetStringAsync(url: string)
        return JsonDocument.Parse(text).RootElement.Clone()
    }

let private str (e: JsonElement) (name: string) = e.GetProperty(name).GetString() |> nonNull
let private u64 (e: JsonElement) (name: string) = UInt64.Parse(str e name)
let private sigOf (e: JsonElement) (name: string) = BlsSignature.TryParse(str e name) |> ValueOption.get
let private pkOf (s: string) = PubKey.TryParse s |> ValueOption.get

let private items (json: string) (wrapped: bool) =
    if String.IsNullOrWhiteSpace json then
        []
    else
        let root = JsonDocument.Parse(json).RootElement
        let arr = if wrapped then root.GetProperty "data" else root
        [ for x in arr.EnumerateArray() -> x.Clone() ]

let private verify (pk: PubKey) (root: Root) (s: BlsSignature) =
    Bls.verify (ReadOnlySpan pk.Bytes) (ReadOnlySpan root.Bytes) (ReadOnlySpan s.Bytes)

/// What the cluster lock and node 0 tell about the chain and the keys.
type private Cluster =
    {
        Spec: ChainSpec
        Gvr: Root
        /// Validator index: the distributed (group) key and the share of each node.
        Keys: Map<uint64, PubKey * PubKey[]>
    }

let private readCluster (http: HttpClient) =
    task {
        let! spec = getJson http (apiUrl 0 + "/eth/v1/config/spec")

        let values =
            [
                for p in spec.GetProperty("data").EnumerateObject() -> p.Name, p.Value.ToString()
            ]
            |> Map.ofList

        let! genesis = getJson http (apiUrl 0 + "/eth/v1/beacon/genesis")
        let gvr = Root.TryParse(str (genesis.GetProperty "data") "genesis_validators_root") |> ValueOption.get

        let lock =
            JsonDocument.Parse(File.ReadAllText(Path.Combine(netDir, "node0", "cluster-lock.json"))).RootElement

        let dvs =
            [
                for dv in lock.GetProperty("distributed_validators").EnumerateArray() ->
                    pkOf (str dv "distributed_public_key"),
                    [|
                        for s in dv.GetProperty("public_shares").EnumerateArray() -> pkOf (nonNull (s.GetString()))
                    |]
            ]
        // Node 0 reports each validator with node 0's share.
        let! vals = getJson http (apiUrl 0 + "/eth/v1/beacon/states/head/validators")

        let keys =
            [
                for v in vals.GetProperty("data").EnumerateArray() do
                    let share = pkOf (str (v.GetProperty "validator") "pubkey")

                    match dvs |> List.tryFind (fun (_, shares) -> shares[0] = share) with
                    | Some dv -> u64 v "index", dv
                    | None -> ()
            ]
            |> Map.ofList

        match ChainSpec.parse values with
        | Error e -> return failtestf "Charon's spec: %s" e
        | Ok s -> return values, { Spec = s; Gvr = gvr; Keys = keys }
    }

let private startVc (i: int) (values: Map<string, string>) (calls: ConcurrentQueue<Call>) (ct: CancellationToken) =
    let dir = tempDir ()
    let yaml = StringBuilder()

    for KeyValue(k, v) in values do
        yaml.Append($"{k}: {v}\n") |> ignore

    File.WriteAllText(Path.Combine(dir, "chain.yaml"), yaml.ToString())
    let keys = Path.Combine(netDir, $"node{i}", "validator_keys")

    let configText =
        $$"""{ "beacon_node": "{{apiUrl i}}", "chain_config": "chain.yaml", "data_dir": "data", "use_events": false,
               "allow_start_without_history": ["all"],
               "modules": { "local": { "keystores": [ { "path": "{{keys}}" } ], "reload_interval_seconds": 0 },
                            "obol": { "enabled": true } } }"""

    let modules = [ LocalModule.create (); ObolModule.create () ]

    match
        Config.parse configText dir (modules |> List.map (fun m -> m.Name))
        |> Result.bind (fun c -> Runner.configure c modules dir |> Result.map (fun () -> c))
    with
    | Error es -> failtestf "VC %d config: %A" i es
    | Ok config ->
        let log, lines = Log.memory ()

        let run =
            Runner.run
                {
                    Config = config
                    Modules = modules
                    Http = new HttpClient(new Recorder(i, calls))
                    Time = TimeProvider.System
                    Log = log
                    OnSlotDone = ignore
                    OnReady = fun _ _ -> ()
                }
                ct

        run, lines

/// What Charon v1.11.2 logs once it has combined the partials and submitted the result.
let private submittedAggregates = "Successfully submitted v2 attestation aggregations to beacon node"

let private submittedContributions =
    "Successfully submitted sync committee contributions to beacon node"

/// Whether a node's log (scripts/charon-local.sh writes node<i>/charon.log) has the line.
let private charonLogged (text: string) =
    nodes
    |> List.exists (fun i ->
        let file = Path.Combine(netDir, $"node{i}", "charon.log")

        File.Exists file
        && (use s = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)
            use r = new StreamReader(s)
            r.ReadToEnd().Contains text))

let private ofNode (calls: Call list) (suffix: string) = calls |> List.filter (fun c -> c.Path.EndsWith suffix)

let private integration =
    testSequenced
    <| testList
        "charon-integration"
        [
            testT
                "obol/selections through Charon: combined proofs come back and go into aggregates and contributions"
                (fun () ->
                    task {
                        use http = new HttpClient(Timeout = TimeSpan.FromSeconds 5.0)
                        let! values, cluster = readCluster http
                        Expect.isGreaterThan cluster.Keys.Count 0 "node 0 reports the cluster's validators"
                        let spec = cluster.Spec
                        let calls = ConcurrentQueue<Call>()
                        use cts = new CancellationTokenSource(limit)
                        let vcs = [ for i in nodes -> startVc i values calls cts.Token ]
                        let snapshot () = List.ofSeq calls

                        let has suffix =
                            fun (cs: Call list) ->
                                ofNode cs suffix |> List.exists (fun c -> c.Status = 200 && c.Request.Length > 2)
                        // Done when every VC got combined proofs for attester and sync duties, the VCs sent
                        // an aggregate and a contribution, and Charon combined the partial aggregates and
                        // contributions and submitted them to its beacon mock (it logs each submission).
                        let isDone () =
                            let cs = snapshot ()

                            nodes
                            |> List.forall (fun i ->
                                cs |> List.filter (fun c -> c.Node = i) |> has Selections.BeaconCommitteePath)
                            && nodes
                               |> List.forall (fun i ->
                                   cs |> List.filter (fun c -> c.Node = i) |> has Selections.SyncCommitteePath)
                            && has "/aggregate_and_proofs" cs
                            && has "/contribution_and_proofs" cs
                            && charonLogged submittedAggregates
                            && charonLogged submittedContributions

                        let sw = Diagnostics.Stopwatch.StartNew()

                        while not (isDone ())
                              && not cts.IsCancellationRequested
                              && not (vcs |> List.exists (fun (r, _) -> r.IsCompleted)) do
                            do! Task.Delay 500

                        let elapsed = sw.Elapsed
                        cts.Cancel()

                        for i, (run, _) in List.indexed vcs do
                            let! winner = Task.WhenAny(run :> Task, Task.Delay(TimeSpan.FromSeconds 30.0))
                            Expect.isTrue (winner = (run :> Task)) $"VC {i} stops within 30 s"

                        for i, (_, lines) in List.indexed vcs do
                            File.WriteAllLines(Path.Combine(netDir, $"node{i}", "eplix.log"), lines)

                        let logs () =
                            String.Join(
                                "\n",
                                [
                                    for i, (_, lines) in List.indexed vcs ->
                                        $"--- VC {i}\n" + String.Join("\n", lines |> Seq.truncate 400)
                                ]
                            )

                        for i, (run, _) in List.indexed vcs do
                            Expect.isOk run.Result $"VC {i} ran; logs:\n{logs ()}"

                        let cs = snapshot ()

                        let summary =
                            String.Join(
                                "\n",
                                cs
                                |> List.countBy (fun c -> c.Node, c.Path, c.Status)
                                |> List.map (fun ((n, p, s), k) -> $"VC {n} {p} {s}: {k}")
                            )

                        let failed = not (isDone ())

                        if failed then
                            failtestf
                                "not done after %O; Charon submitted aggregates: %b, contributions: %b; calls:\n%s\nlogs:\n%s"
                                elapsed
                                (charonLogged submittedAggregates)
                                (charonLogged submittedContributions)
                                summary
                                (logs ())
                        // Combined proofs by VC, validator, slot (and subcommittee).
                        let combined = Collections.Generic.HashSet<int * uint64 * uint64 * uint64 * string>()
                        let mutable beaconChecked = 0
                        let mutable syncChecked = 0

                        for c in cs do
                            let isBeacon = c.Path.EndsWith Selections.BeaconCommitteePath
                            let isSync = c.Path.EndsWith Selections.SyncCommitteePath

                            if (isBeacon || isSync) && c.Status = 200 then
                                let partials =
                                    items c.Request false
                                    |> List.map (fun x ->
                                        let sub = if isSync then u64 x "subcommittee_index" else 0UL
                                        (u64 x "validator_index", u64 x "slot", sub), sigOf x "selection_proof")
                                    |> Map.ofList

                                for x in items c.Response true do
                                    let index = u64 x "validator_index"
                                    let slot = u64 x "slot"
                                    let sub = if isSync then u64 x "subcommittee_index" else 0UL
                                    let proof = sigOf x "selection_proof"
                                    let group, shares = cluster.Keys[index]

                                    let root =
                                        if isBeacon then
                                            Signing.computeSigningRoot
                                                (Codec.hashSlot slot)
                                                (Signing.domainAt
                                                    spec
                                                    cluster.Gvr
                                                    spec.DomainSelectionProof
                                                    (spec.EpochOf slot))
                                        else
                                            Signing.computeSigningRoot
                                                (Codec.hashSyncAggregatorSelectionData
                                                    { Slot = slot; SubcommitteeIndex = sub })
                                                (Signing.domainAt
                                                    spec
                                                    cluster.Gvr
                                                    spec.DomainSyncCommitteeSelectionProof
                                                    (spec.EpochOf slot))

                                    Expect.isTrue
                                        (verify group root proof)
                                        $"VC {c.Node}: the proof Charon returned for validator {index} slot {slot} verifies against the group key"

                                    match partials.TryFind(index, slot, sub) with
                                    | Some partial ->
                                        Expect.isTrue
                                            (verify shares[c.Node] root partial)
                                            $"VC {c.Node}: its proof for validator {index} slot {slot} is a partial of its share"

                                        Expect.notEqual partial proof "the combined proof is not the partial"
                                    | None ->
                                        failtestf
                                            "VC %d: Charon answered for validator %d slot %d, which the VC did not ask about"
                                            c.Node
                                            index
                                            slot

                                    combined.Add((c.Node, index, slot, sub, proof.Hex)) |> ignore

                                    if isBeacon then
                                        beaconChecked <- beaconChecked + 1
                                    else
                                        syncChecked <- syncChecked + 1

                        let mutable aggregates = 0

                        for c in ofNode cs "/aggregate_and_proofs" do
                            Expect.equal c.Status 200 $"VC {c.Node}: Charon takes the aggregate ({c.Response})"

                            for a in items c.Request false do
                                let msg = a.GetProperty "message"
                                let index = u64 msg "aggregator_index"
                                let slot = u64 (msg.GetProperty("aggregate").GetProperty "data") "slot"
                                let proof = sigOf msg "selection_proof"

                                Expect.isTrue
                                    (combined.Contains((c.Node, index, slot, 0UL, proof.Hex)))
                                    $"VC {c.Node}: the aggregate of validator {index} slot {slot} carries the combined proof Charon returned"

                                aggregates <- aggregates + 1

                        let mutable contributions = 0

                        for c in ofNode cs "/contribution_and_proofs" do
                            Expect.equal c.Status 200 $"VC {c.Node}: Charon takes the contribution ({c.Response})"

                            for x in items c.Request false do
                                let msg = x.GetProperty "message"
                                let index = u64 msg "aggregator_index"
                                let contribution = msg.GetProperty "contribution"
                                let slot = u64 contribution "slot"
                                let sub = u64 contribution "subcommittee_index"
                                let proof = sigOf msg "selection_proof"

                                Expect.isTrue
                                    (combined.Contains((c.Node, index, slot, sub, proof.Hex)))
                                    $"VC {c.Node}: the contribution of validator {index} slot {slot} carries the combined proof Charon returned"

                                contributions <- contributions + 1

                        Expect.isGreaterThan aggregates 0 "aggregates checked"
                        Expect.isGreaterThan contributions 0 "contributions checked"

                        printfn
                            "charon-integration: %O; %d beacon and %d sync committee proofs, %d aggregates, %d contributions checked\n%s"
                            elapsed
                            beaconChecked
                            syncChecked
                            aggregates
                            contributions
                            summary
                    })
        ]

[<Tests>]
let tests =
    if enabled then
        integration
    else
        testList
            "charon-integration"
            [
                ptest "set EPLIX_CHARON_NET to a running cluster from scripts/charon-local.sh" { () }
            ]
