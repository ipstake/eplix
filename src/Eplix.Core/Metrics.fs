/// The VC's instruments, on System.Diagnostics.Metrics. They cost a branch while
/// nothing listens; the metrics module (Eplix.Metrics) listens and serves them in the Prometheus
/// text format. Names follow Prometheus conventions: base units (seconds), snake case, and the
/// exporter adds `_total` to counters. Values that are a state, not an event (key states, node
/// scores), are read by the exporter at scrape time instead.
namespace Eplix

open System.Collections.Generic
open System.Diagnostics.Metrics

module Metrics =
    /// The meter every core instrument is on. The exporter listens to it by name.
    [<Literal>]
    let MeterName = "Eplix"

    let meter = new Meter(MeterName)

    /// Bucket bounds in seconds for signing and slashing DB latency: 0.5 ms to 10 s.
    let latencyBuckets: IReadOnlyList<float> =
        [|
            0.0005
            0.001
            0.0025
            0.005
            0.01
            0.025
            0.05
            0.1
            0.25
            0.5
            1.0
            2.5
            5.0
            10.0
        |]
        :> IReadOnlyList<float>

    /// Bucket bounds in seconds for signing latency: every bound of latencyBuckets, so a query on
    /// one `le` keeps its series, plus 10 to 50 ms steps from 20 ms to 200 ms and 400 and 600 ms.
    /// Remote signers answer in that range, and queueing behind another client's requests shows
    /// there as tens of milliseconds.
    let signingBuckets: IReadOnlyList<float> =
        [|
            0.0005
            0.001
            0.0025
            0.005
            0.01
            0.02
            0.025
            0.03
            0.04
            0.05
            0.06
            0.075
            0.1
            0.125
            0.15
            0.2
            0.25
            0.4
            0.5
            0.6
            1.0
            2.5
            5.0
            10.0
        |]
        :> IReadOnlyList<float>

    let private histogramWith (buckets: IReadOnlyList<float>) (name: string) (description: string) =
        meter.CreateHistogram<float>(
            name,
            unit = "s",
            description = description,
            tags = null,
            advice = InstrumentAdvice<float>(HistogramBucketBoundaries = buckets)
        )

    let private histogram = histogramWith latencyBuckets

    /// The duty kind as a label value.
    let dutyLabel (kind: DutyKind) =
        match kind with
        | DutyKind.Attestation -> "attestation"
        | DutyKind.Block -> "block"
        | DutyKind.RandaoReveal -> "randao_reveal"
        | DutyKind.AggregationSlot -> "aggregation_slot"
        | DutyKind.AggregateAndProof -> "aggregate_and_proof"
        | DutyKind.SyncCommitteeMessage -> "sync_committee_message"
        | DutyKind.SyncSelectionProof -> "sync_selection_proof"
        | DutyKind.ContributionAndProof -> "contribution_and_proof"
        | DutyKind.VoluntaryExit -> "voluntary_exit"
        | DutyKind.PayloadAttestation -> "payload_attestation"
        | DutyKind.PayloadEnvelope -> "payload_envelope"
        | DutyKind.ProposerPreferences -> "proposer_preferences"
        | DutyKind.BuilderRequestAuth -> "builder_request_auth"
        | DutyKind.ValidatorRegistration -> "validator_registration"

    /// What a backend answered, as a label value.
    let outcomeLabel (o: SignOutcome) =
        match o with
        | Signed _
        | Partial _ -> "signed"
        | Refused _ -> "refused"
        | Failed _ -> "failed"

    /// Requests a remote signer denied without a reason (Dirk's DENIED), by key and duty kind.
    let signerDenied =
        meter.CreateCounter<int64>(
            "eplix_signer_denied",
            description = "Requests a remote signer denied without a reason"
        )

    /// Time a backend took for one request, by backend and duty kind.
    let signingDuration =
        histogramWith
            signingBuckets
            "eplix_signing_duration_seconds"
            "Time a backend took to answer one signing request"

    /// Backend answers by backend, duty kind and outcome (signed, refused, failed).
    let signRequests =
        meter.CreateCounter<int64>(
            "eplix_sign_requests",
            description = "Signing requests sent to a backend, by outcome"
        )

    /// Time slashing protection took for one burst: check, append and fsync.
    let slashingCheckDuration =
        histogram
            "eplix_slashing_check_duration_seconds"
            "Time the slashing DB took to check and record one burst, fsync included"

    /// Requests the VC's own slashing DB refused, by duty kind.
    let slashingRefused =
        meter.CreateCounter<int64>("eplix_slashing_refused", description = "Requests the slashing DB refused")

    /// Duties done, per validator: an attestation or sync message submitted, a block published, an
    /// aggregate or contribution submitted.
    let dutiesCompleted =
        meter.CreateCounter<int64>("eplix_duties_completed", description = "Duties done, per validator")

    /// Duties missed, per validator, by duty and reason.
    let dutiesMissed =
        meter.CreateCounter<int64>("eplix_duties_missed", description = "Duties missed, per validator, by reason")

    /// Beacon node answers by node and result (ok, error).
    let beaconRequests =
        meter.CreateCounter<int64>(
            "eplix_beacon_node_requests",
            description = "Beacon API requests, by node and result"
        )

    /// Doppelganger checks that found a key live on the chain, by key.
    let doppelgangerDetected =
        meter.CreateCounter<int64>(
            "eplix_doppelganger_detected",
            description = "Liveness checks that found a waiting key live"
        )

    /// Keys stopped because the chain showed them slashed, by key.
    let slashedOnChainDetected =
        meter.CreateCounter<int64>(
            "eplix_slashed_on_chain",
            description = "Keys stopped because the chain showed them slashed"
        )

    /// Keys retired because no member of their remote signer lists them any more, by module.
    let keysRetired =
        meter.CreateCounter<int64>(
            "eplix_keys_retired",
            description = "Keys retired because no member of their signer lists them"
        )

    /// Time from the start of a proposer config file check to its result in place: the size and
    /// write time, and a read and parse when they changed.
    let proposerConfigCheckDuration =
        histogram
            "eplix_proposer_config_check_duration_seconds"
            "Time from the start of a proposer config file check to its result in place"

    /// Proposer config reloads that failed to read or parse; the last good content stays.
    let proposerConfigErrors =
        meter.CreateCounter<int64>(
            "eplix_proposer_config_errors",
            description = "Proposer config reloads that failed to read or parse"
        )

    /// Proposer config checks that ended after the epoch boundary they ran before.
    let proposerConfigLate =
        meter.CreateCounter<int64>(
            "eplix_proposer_config_late",
            description = "Proposer config checks that ended after their epoch boundary"
        )

    let inline private tag (name: string) (value: string) = KeyValuePair<string, objnull>(name, box value)

    /// Reasons a duty was missed. The label values are fixed so dashboards can rely on them.
    module Reason =
        /// No attestation data, block or aggregate from the beacon nodes (or no consensus).
        [<Literal>]
        let BeaconNode = "beacon_node"

        /// The VC's own slashing DB refused.
        [<Literal>]
        let SlashingProtection = "slashing_protection"

        /// A backend or the key state refused (policy, denied, unknown key, not active).
        [<Literal>]
        let Refused = "refused"

        /// The backend did not answer in time, or failed.
        [<Literal>]
        let SignerError = "signer_error"

        /// Signed, but no beacon node accepted the submission.
        [<Literal>]
        let Submit = "submit"

        /// An emergency switch of the operator stopped the duty (stop_signing, paused_duties).
        [<Literal>]
        let Paused = "paused"

        /// tee-signer refused because an HA peer signed the duty first (modules.tee.ha_peer).
        /// The pair did the duty, so the shipped alerts leave these out.
        [<Literal>]
        let LostToPeer = "lost_to_peer"

    /// The miss reason for a signing outcome that is not a signature.
    let missReason (o: SignOutcome) =
        match o with
        | Refused(Slashable _) -> Reason.SlashingProtection
        | Refused(Paused _) -> Reason.Paused
        | Refused(LostToPeer _) -> Reason.LostToPeer
        | Refused _ -> Reason.Refused
        | Failed _ -> Reason.SignerError
        | Signed _
        | Partial _ -> Reason.Submit

    let completed (duty: string) (count: int) =
        if count > 0 then
            dutiesCompleted.Add(int64 count, tag "duty" duty)

    let missed (duty: string) (reason: string) (count: int) =
        if count > 0 then
            dutiesMissed.Add(int64 count, tag "duty" duty, tag "reason" reason)

    /// Counts the unsigned outcomes of a burst as misses, by reason.
    let missedOutcomes (duty: string) (outcomes: SignOutcome seq) =
        for reason, n in
            outcomes
            |> Seq.filter (fun o ->
                match o with
                | Signed _
                | Partial _ -> false
                | _ -> true)
            |> Seq.countBy missReason do
            missed duty reason n

    let signed (backend: string) (kind: DutyKind) (outcome: SignOutcome) (seconds: float) =
        let duty = dutyLabel kind
        signingDuration.Record(seconds, tag "backend" backend, tag "duty" duty)
        signRequests.Add(1L, tag "backend" backend, tag "duty" duty, tag "outcome" (outcomeLabel outcome))

    let denied (key: PubKey) (kind: DutyKind) = signerDenied.Add(1L, tag "key" key.Hex, tag "duty" (dutyLabel kind))

    let refusedBySlashing (kind: DutyKind) = slashingRefused.Add(1L, tag "duty" (dutyLabel kind))

    let slashedOnChain (key: PubKey) = slashedOnChainDetected.Add(1L, tag "key" key.Hex)

    /// Duties tee-signer refused because an HA peer signed them first (modules.tee.ha_peer), by duty.
    let haPeerLost =
        meter.CreateCounter<int64>(
            "eplix_ha_peer_lost",
            description = "Duties an HA peer signed first; skipped, the key keeps signing"
        )

    let lostToPeer (kind: DutyKind) = haPeerLost.Add(1L, tag "duty" (dutyLabel kind))

    let beaconRequest (node: string) (ok: bool) =
        beaconRequests.Add(1L, tag "node" node, tag "result" (if ok then "ok" else "error"))

    /// Publish sends to beacon nodes, each counted when it ends, by node, broadcast topic and
    /// result: `accepted`, `failed`, or `skipped` (the node had MaxBackground sends running).
    let beaconSubmissions =
        meter.CreateCounter<int64>(
            "eplix_beacon_node_submissions",
            description = "Publish sends to beacon nodes, by node, topic and result"
        )

    /// The result labels of beaconSubmissions.
    module Send =
        [<Literal>]
        let Accepted = "accepted"

        [<Literal>]
        let Failed = "failed"

        [<Literal>]
        let Skipped = "skipped"

    let beaconSubmission (node: string) (topic: string) (result: string) =
        beaconSubmissions.Add(1L, tag "node" node, tag "topic" topic, tag "result" result)

    let retired (backend: string) = keysRetired.Add(1L, tag "backend" backend)

    /// Whole-key signatures from Dirk or Web3Signer that did not verify in the background check,
    /// probes included, by backend and endpoint.
    let remoteSignatureInvalidTotal =
        meter.CreateCounter<int64>(
            "eplix_remote_signature_invalid",
            description = "Whole-key signatures from a remote signer that did not verify"
        )

    /// Background checks dropped because the endpoint's check queue was full.
    let remoteSignatureChecksDropped =
        meter.CreateCounter<int64>(
            "eplix_remote_signature_checks_dropped",
            description = "Background signature checks dropped on a full queue"
        )

    /// Keys stopped at an endpoint after failed checks in a row.
    let remoteSignerKeyStops =
        meter.CreateCounter<int64>(
            "eplix_remote_signer_key_stops",
            description = "Keys no longer sent to an endpoint whose signatures for them did not verify"
        )

    /// Stopped keys sent to their endpoint again, by reason (probe, key_list).
    let remoteSignerKeyResumes =
        meter.CreateCounter<int64>(
            "eplix_remote_signer_key_resumes",
            description = "Stopped keys sent to their endpoint again, by reason"
        )

    let remoteSignatureInvalid (backend: string) (endpoint: string) =
        remoteSignatureInvalidTotal.Add(1L, tag "backend" backend, tag "endpoint" endpoint)

    let remoteSignatureCheckDropped (backend: string) (endpoint: string) =
        remoteSignatureChecksDropped.Add(1L, tag "backend" backend, tag "endpoint" endpoint)

    let remoteSignerKeyStopped (backend: string) (endpoint: string) =
        remoteSignerKeyStops.Add(1L, tag "backend" backend, tag "endpoint" endpoint)

    let remoteSignerKeyResumed (backend: string) (endpoint: string) (reason: string) =
        remoteSignerKeyResumes.Add(1L, tag "backend" backend, tag "endpoint" endpoint, tag "reason" reason)

    /// Times a TEE runner's HEALTH state turned to log_lost (its slashing mark log is lost), by
    /// signer. Read at scrape time from a table that holds each runner at 0 from its start, so
    /// the first loss is a rise: increase() over a series that starts at 1 gives 0.
    let private markLogLosses = System.Collections.Concurrent.ConcurrentDictionary<string, int64>()

    let private signerMarkLogLost =
        meter.CreateObservableCounter<int64>(
            "eplix_signer_mark_log_lost",
            System.Func<IEnumerable<Measurement<int64>>>(fun () ->
                [ for KeyValue(s, n) in markLogLosses -> Measurement<int64>(n, tag "signer" s) ] :> IEnumerable<_>),
            description = "Times a signer's HEALTH state turned to log_lost: its slashing mark log is lost"
        )

    /// Adds a signer to the table at 0; a signer already in it keeps its count.
    let markLogLostWatch (signer: string) =
        ignore signerMarkLogLost
        markLogLosses.TryAdd(signer, 0L) |> ignore

    /// Counts one change of the signer's HEALTH state to log_lost.
    let markLogLost (signer: string) =
        ignore signerMarkLogLost
        markLogLosses.AddOrUpdate(signer, 1L, fun _ n -> n + 1L) |> ignore

    /// The counts, as (signer, count) pairs.
    let markLogLostNow () = [ for KeyValue(s, n) in markLogLosses -> s, n ]

    /// tee-signer FLOOR_UNPROVEN answers by signer: refused at or below a floor where the
    /// runner's mark log, not the key's own history, refuses it. The operator checks the key.
    let teeFloorUnproven =
        meter.CreateCounter<int64>(
            "eplix_tee_floor_unproven",
            description = "tee-signer floor refusals its mark log, not the key's own history, refused"
        )

    let floorUnproven (signer: string) = teeFloorUnproven.Add(1L, tag "signer" signer)

    /// When each TLS certificate and CA file in use expires, as Unix seconds,
    /// by use and name. Read at scrape time: modules load their files at start, which can come
    /// before the metrics module listens, and a pushed gauge value would be lost.
    let private tlsNotAfters =
        System.Collections.Concurrent.ConcurrentDictionary<struct (string * string), int64>()

    let private tlsCertNotAfter =
        meter.CreateObservableGauge<int64>(
            "eplix_tls_cert_not_after_seconds",
            System.Func<IEnumerable<Measurement<int64>>>(fun () ->
                [
                    for KeyValue(struct (u, n), t) in tlsNotAfters -> Measurement<int64>(t, tag "use" u, tag "name" n)
                ]
                :> IEnumerable<_>),
            unit = "s",
            description =
                "When the TLS certificate or CA file in use expires (the earliest certificate in it), Unix time"
        )

    /// Reloads of TLS certificate and CA files while running, by use, name and result.
    let tlsCertReloads =
        meter.CreateCounter<int64>(
            "eplix_tls_cert_reloads",
            description = "Reloads of a changed TLS certificate or CA file, by result (ok, error)"
        )

    let tlsNotAfter (use': string) (name: string) (notAfter: System.DateTimeOffset) =
        ignore tlsCertNotAfter
        tlsNotAfters[struct (use', name)] <- notAfter.ToUnixTimeSeconds()

    let tlsReload (use': string) (name: string) (ok: bool) =
        tlsCertReloads.Add(1L, tag "use" use', tag "name" name, tag "result" (if ok then "ok" else "error"))

    /// Each signer's state from its HEALTH answer (ready, a refusal or gone state, or unknown),
    /// read at scrape time: 1 for the state it is in.
    let private signerStates = System.Collections.Concurrent.ConcurrentDictionary<string, string>()

    let private signerStateGauge =
        meter.CreateObservableGauge<int64>(
            "eplix_signer_state",
            System.Func<IEnumerable<Measurement<int64>>>(fun () ->
                [
                    for KeyValue(s, st) in signerStates -> Measurement<int64>(1L, tag "signer" s, tag "state" st)
                ]
                :> IEnumerable<_>),
            description = "The state each signer's HEALTH answer puts it in; 1 for the current state"
        )

    let setSignerState (signer: string) (state: string) =
        ignore signerStateGauge
        signerStates[signer] <- state

    /// The states the gauge reports, as (signer, state) pairs.
    let signerStatesNow () = [ for KeyValue(s, st) in signerStates -> s, st ]

    // ---- Pre-Gloas builder flow (the legacy builder module) ----

    /// Proposals whose builder request failed or timed out, asked again for a local block.
    let builderFallbacks =
        meter.CreateCounter<int64>(
            "eplix_builder_fallbacks",
            description = "Builder block requests that failed, asked again for a local block"
        )

    /// Signed blinded blocks by result: `published` or `refused` (no node took it).
    let blindedBlocks =
        meter.CreateCounter<int64>("eplix_blinded_blocks", description = "Signed blinded blocks, by publish result")

    let blindedBlock (result: string) = blindedBlocks.Add(1L, tag "result" result)

    /// Validator registrations sent to beacon nodes, per registration and node, by result
    /// (`accepted`, `failed`).
    let registrationsSent =
        meter.CreateCounter<int64>(
            "eplix_validator_registrations",
            description = "Validator registrations sent to beacon nodes, by node and result"
        )

    let registrations (node: string) (result: string) (count: int) =
        registrationsSent.Add(int64 count, tag "node" node, tag "result" result)

    /// Registrations signed, by result: `signed` (a new fee recipient, gas limit or key) or
    /// `failed` (tried again next epoch).
    let registrationSignings =
        meter.CreateCounter<int64>(
            "eplix_validator_registration_signings",
            description = "Validator registrations signed, by result"
        )

    let registrationSigned (result: string) (count: int) = registrationSignings.Add(int64 count, tag "result" result)
