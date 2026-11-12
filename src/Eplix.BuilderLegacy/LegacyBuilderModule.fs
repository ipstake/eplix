/// The legacy builder module: the pre-Gloas builder flow of builder-specs, which MEV-Boost serves
/// behind the beacon node. Each epoch it signs a ValidatorRegistrationV1 per enabled key (once,
/// and again only when the fee recipient or gas limit changes) and sends the registrations to
/// every node with block_data, in batches. For a proposal of an enabled key it gives the
/// scheduler the key's builder_boost_factor; the scheduler signs a blinded answer, publishes it
/// to the blinded endpoint, and asks again for a local block when the builder request fails.
/// From the Gloas fork epoch on the module does nothing (Gloas has its own builder flow).
/// Config section "builder_legacy":
///   { "enabled": false, "boost_factor": "100", "registration_batch_size": 500 }
/// `enabled` and `boost_factor` are the defaults for keys whose proposer config entry has no
/// `builder` block. -p:EplixBuilderLegacy=false drops the module.
module Eplix.BuilderLegacy.LegacyBuilderModule

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Eplix
open Eplix.Beacon
open Eplix.Json

let name = "builder_legacy"

type Settings =
    {
        /// The builder flow for keys without their own setting.
        Enabled: bool
        /// builder_boost_factor for keys without their own setting: 100 compares the builder's
        /// value with the local one as is, 0 builds locally, 2^64 - 1 always takes the builder.
        BoostFactor: uint64
        /// Registrations per register_validator request.
        BatchSize: int
    }

    static member Default =
        {
            Enabled = false
            BoostFactor = 100UL
            BatchSize = 500
        }

let parse (section: ConfigSection) : Result<Settings, string list> =
    match section.Element with
    | ValueNone -> Ok Settings.Default
    | ValueSome e ->
        match checkFields e $"modules.{name}" [ "enabled"; "boost_factor"; "registration_batch_size" ] with
        | [] ->
            try
                let d = Settings.Default

                let batch =
                    match tryProp e "registration_batch_size" with
                    | ValueSome v ->
                        let n = u64 v

                        if n < 1UL || n > 10000UL then
                            fail "registration_batch_size must be 1 to 10000"

                        int n
                    | ValueNone -> d.BatchSize

                Ok
                    {
                        Enabled =
                            (match tryProp e "enabled" with
                             | ValueSome _ -> boolField e "enabled"
                             | ValueNone -> d.Enabled)
                        BoostFactor =
                            (match tryProp e "boost_factor" with
                             | ValueSome v -> u64 v
                             | ValueNone -> d.BoostFactor)
                        BatchSize = batch
                    }
            with :? JsonDecodeError as x ->
                Error [ $"modules.{name}: {x.Message}" ]
        | errs -> Error errs

/// What one key registers: fee recipient (20 bytes) and gas limit.
type private Wanted = { Fee: byte[]; GasLimit: uint64 }

/// Signs and caches the registrations, sends them each epoch, and answers the boost factor.
type Registrations(core: CoreServices, settings: Settings) =
    let spec = core.Spec
    let gvr = core.Genesis.GenesisValidatorsRoot
    let log = core.Log
    let gate = obj ()
    /// The signed registration of each key, as last signed.
    let cache = Dictionary<PubKey, struct (ValidatorRegistration * BlsSignature)>()
    /// Keys without a fee recipient, warned once.
    let noFee = HashSet<PubKey>()
    let runGate = new SemaphoreSlim(1, 1)
    let mutable lastEpoch: Epoch voption = ValueNone
    let mutable signings = 0L

    let builderOn (s: KeySettings) = defaultValueArg s.BuilderEnabled settings.Enabled

    let wanted (k: RegisteredKey) : Wanted voption =
        let s = k.Settings

        let fee =
            match s.FeeRecipient with
            | ValueSome f -> ValueSome f
            | ValueNone -> core.Defaults.FeeRecipient
            |> ValueOption.bind (Hex.tryDecodeFixed 20)

        match fee with
        | ValueSome f ->
            ValueSome
                {
                    Fee = f
                    GasLimit = defaultValueArg s.GasLimit core.Defaults.GasLimit
                }
        | ValueNone ->
            if lock gate (fun () -> noFee.Add k.Key) then
                log.Warn $"key {k.Key.Short}: no fee recipient; no validator registration"

            ValueNone

    /// The keys to register: active, with an index (relays know only validators on chain), the
    /// builder flow on, and a fee recipient.
    let candidates () =
        core.Registry.Active
        |> List.choose (fun k ->
            if k.Index.IsSome && builderOn k.Settings then
                match wanted k with
                | ValueSome w -> Some(k.Key, w)
                | ValueNone -> None
            else
                None)

    let send (regs: (ValidatorRegistration * BlsSignature)[]) (ct: CancellationToken) =
        task {
            let nodes = core.Nodes.NodesWith NodeRole.BlockData |> Array.ofList
            let mutable accepted = 0

            for batch in Array.chunkBySize settings.BatchSize regs do
                let! answers = core.Nodes.AskAll((fun n -> n.RegisterValidator(batch, ct)), NodeRole.BlockData)
                let mutable any = false

                answers
                |> Array.iteri (fun i a ->
                    let node = nodes[i].Name

                    match a with
                    | Ok() ->
                        any <- true
                        Metrics.registrations node "accepted" batch.Length
                    | Error e ->
                        Metrics.registrations node "failed" batch.Length
                        log.Warn $"beacon node {node}: register_validator ({batch.Length} registrations): {e.Describe}")

                if any then
                    accepted <- accepted + batch.Length

            return accepted
        }

    /// One epoch: sign what is new or changed, then send every registration.
    member _.RunEpoch(epoch: Epoch, ct: CancellationToken) : Task =
        task {
            let keys = candidates ()

            let stale =
                lock gate (fun () ->
                    keys
                    |> List.filter (fun (pk, w) ->
                        match cache.TryGetValue pk with
                        | true, struct (r, _) ->
                            r.GasLimit <> w.GasLimit
                            || not (r.FeeRecipient.AsSpan().SequenceEqual(ReadOnlySpan w.Fee))
                        | _ -> true))

            if not stale.IsEmpty then
                let now = uint64 (core.Clock.Time.GetUtcNow().ToUnixTimeSeconds())
                let deadline = core.Clock.SlotStart(spec.FirstSlot(epoch + 1UL))

                let regs =
                    stale
                    |> List.map (fun (pk, w) ->
                        {
                            FeeRecipient = w.Fee
                            GasLimit = w.GasLimit
                            Timestamp = now
                            PubKey = pk
                        })
                    |> Array.ofList

                let reqs =
                    regs
                    |> Array.map (fun r ->
                        Duty.request spec gvr r.PubKey Priority.Low deadline (Duty.ValidatorRegistration r))

                let! outcomes = core.Pipeline.SignBurst(reqs, ct)
                let mutable failed = 0
                let mutable firstFailure = ""

                lock gate (fun () ->
                    for i in 0 .. regs.Length - 1 do
                        match outcomes[i] with
                        | Signed s -> cache[regs[i].PubKey] <- struct (regs[i], s)
                        | o ->
                            failed <- failed + 1

                            if firstFailure = "" then
                                firstFailure <- $"{regs[i].PubKey.Short}: {o.Describe}")

                let signed = regs.Length - failed
                Interlocked.Add(&signings, int64 signed) |> ignore
                Metrics.registrationSigned "signed" signed

                if failed > 0 then
                    Metrics.registrationSigned "failed" failed

                    log.Warn
                        $"epoch {epoch}: {failed} of {regs.Length} validator registrations not signed (first: {firstFailure}); tried again next epoch"

            let toSend =
                lock gate (fun () ->
                    [|
                        for pk, _ in keys do
                            match cache.TryGetValue pk with
                            | true, struct (r, s) -> r, s
                            | _ -> ()
                    |])

            if toSend.Length > 0 then
                let! accepted = send toSend ct
                log.Debug $"epoch {epoch}: {toSend.Length} validator registrations sent, {accepted} accepted by a node"
        }

    /// Registrations signed since the start.
    member _.Signings = Interlocked.Read &signings

    /// builder_boost_factor for a proposal: the key's factor when its builder flow is on, 0 when
    /// off. ValueNone from the Gloas fork on.
    member _.BoostFor(d: ProposerDuty) : uint64 voption =
        if spec.IsGloasAt(spec.EpochOf d.Slot) then
            ValueNone
        else
            match core.Registry.TryGet d.PubKey with
            | ValueSome k when builderOn k.Settings ->
                ValueSome(defaultValueArg k.Settings.BuilderBoostFactor settings.BoostFactor)
            | _ -> ValueSome 0UL

    member this.Extension: DutyExtension =
        { DutyExtension.empty name with
            PrepareEpochs =
                fun _ epoch ct ->
                    task {
                        // Once per epoch, before the Gloas fork. A run still going skips the call.
                        let due =
                            not (spec.IsGloasAt epoch)
                            && (match lastEpoch with
                                | ValueSome e -> epoch > e
                                | ValueNone -> true)

                        if due && runGate.Wait 0 then
                            try
                                lastEpoch <- ValueSome epoch
                                do! this.RunEpoch(epoch, ct)
                            finally
                                runGate.Release() |> ignore
                    }
            BuilderBoost = this.BoostFor
        }

let create () : Module =
    let settings = ref Settings.Default

    {
        Name = name
        Configure =
            fun section ->
                match parse section with
                | Ok s ->
                    settings.Value <- s
                    Ok()
                | Error e -> Error e
        Check =
            fun _ ->
                let s = settings.Value
                Ok $"""builder flow {(if s.Enabled then "on" else "off")} by default, boost factor {s.BoostFactor}"""
        Start =
            fun core _ ->
                task {
                    let r = Registrations(core, settings.Value)
                    core.AddDutyExtension r.Extension
                    let s = settings.Value

                    core.Log.Info
                        $"""pre-Gloas builder flow: {(if s.Enabled then "on" else "off")} by default, boost factor {s.BoostFactor}"""

                    return Ok { Stop = fun () -> Task.CompletedTask }
                }
    }
