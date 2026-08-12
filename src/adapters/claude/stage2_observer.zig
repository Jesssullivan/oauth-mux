//! Typed, value-free observations for the authoritative Claude fake-upstream lane.
//!
//! This test artifact records only fixed fact identifiers and pass/fail states.
//! It never persists request bytes, headers, capability values, model names, paths,
//! account identifiers, or provider data.

const std = @import("std");
const builtin = @import("builtin");
const capability_mod = @import("session_capability.zig");
const fake_upstream_mod = @import("fake_upstream.zig");
const wire_proxy = @import("wire_proxy.zig");
const advisory_usage = @import("../../quota/advisory_usage.zig");
const broker_decision = @import("../../broker/decision.zig");
const broker_lease_state = @import("../../broker/lease_state.zig");
const broker_lease_store = @import("../../broker/lease_store.zig");
const broker_lease_runtime = @import("../../broker/lease_runtime.zig");
const broker_model_demand = @import("../../broker/model_demand.zig");
const broker_route_observation = @import("../../broker/route_observation.zig");
const lock_wait = @import("../../lock_wait.zig");
// §8.8 refresh-predicate OBSERVATION family (TIN-2400, PR C). The observer
// drives the landed TIN-2990 flock-owned locked-lineage refresh engine directly
// over synthetic stores/credentials in isolated temp dirs. No provider-
// authenticated call, real store, or keychain is ever touched.
const repair_state = @import("../../repair_state.zig");
const types = @import("../../types.zig");
const provider_schema = @import("../../provider_schema.zig");

const SessionCapability = capability_mod.SessionCapability;
const FakeUpstream = fake_upstream_mod.FakeUpstream;

const Status = enum { pass, fail };

pub const BuildIdentity = struct {
    candidate_sha: []const u8,
    candidate_tree: []const u8,
    workflow_run_id: []const u8,
    workflow_run_attempt: []const u8,
    gf_target_class: []const u8,
};

const FactId = enum {
    listener_bound_ipv4_loopback,
    carrier_is_canonical_256bit_base64url,
    valid_capability_reaches_fake_once,
    invalid_capability_returns_401,
    invalid_capability_adds_zero_fake_calls,
    invalid_capability_observation_is_fresh,
    aggregate_accepted_request_count_is_one,
    aggregate_rejected_request_count_is_one,
    aggregate_request_counts_reconcile_with_ids,
    caller_auth_headers_absent_upstream,
    forwarding_identity_headers_absent_upstream,
    hop_headers_absent_upstream,
    required_safe_headers_present_upstream,
    invalid_origin_requests_return_400,
    forward_proxy_requests_return_400,
    invalid_origin_and_proxy_requests_add_zero_fake_calls,
    redirect_returns_local_502,
    redirect_is_not_followed,
    streaming_prefix_arrives_before_upstream_completion,
    streaming_body_arrives_byte_preserved,
    streaming_uses_one_fake_call,
    provider_5xx_status_and_body_pass_through,
    provider_5xx_uses_one_fake_call,
    // §2.2 single-alternate retry machine (routed synthetic seam, #494).
    prebody_401_consumes_one_alternate,
    alternate_success_records_two_attempts,
    first_attempt_body_forwarded_byte_exact,
    alternate_replay_body_byte_exact,
    prebody_403_consumes_one_alternate,
    prebody_429_consumes_alternate_after_wait,
    pre_alternate_wait_within_bound,
    wait_beyond_max_returns_local_429,
    wait_beyond_deadline_returns_local_429,
    presend_fault_consumes_one_same_route_retry,
    transport_failure_never_contacts_alternate,
    same_identity_alternate_delivers_original,
    alternate_slot_transport_fail_adds_no_retry,
    same_route_retry_401_adds_no_alternate,
    alternate_failure_no_third_attempt,
    started_response_never_replayed,
    // TIN-1790 mapping-only shared-core consumption (fake upstream only).
    route_identity_admission,
    identity_conflict_fail_closed,
    route_readiness_ordering,
    lease_state_redaction,
    stale_lease_reactive_routing,
    unavailable_lease_reactive_routing,
    sticky_least_loaded_selection,
    deterministic_shared_leases,
    stale_lease_owner_cleanup,
    // §2.2 replay reservation / cancellation / stream-once.
    cancellation_releases_reservation_to_zero,
    cancellation_makes_no_replay,
    streaming_cancellation_single_attempt,
    stream_once_cancellation_keeps_latch_no_replay,
    stream_once_cancellation_releases_reservation,
    oversize_body_streams_once_refuses_alternate,
    sidecar_budget_exhaustion_forces_stream_once,
    overflow_releases_reservation_next_unaffected,
    // Bounded all-exhausted terminal (plan §7, ladder G10).
    all_exhausted_returns_bounded_429,
    all_exhausted_propagates_minimum_trusted_reset,
    all_exhausted_without_reset_omits_retry_after,
    all_exhausted_delivers_typed_429_not_200,
    all_exhausted_ignores_malformed_reset,
    no_alternate_emits_single_uniform_terminal,
    same_identity_pool_emits_single_uniform_terminal,
    // Teardown / resident-absence (ladder §9 Stage 2, G5/G6).
    routed_alternate_completes_with_no_resident,
    abrupt_death_mid_alternate_reclaims_to_zero,
    teardown_holds_then_releases_reservation,
    teardown_converges_within_bound,
    partial_request_teardown_no_replay_bounded,
    sequential_routed_requests_release_each_time,
    // §8.8 advisory-usage OBSERVATION family (TIN-2400, observation-only, PR B).
    // Every fact below is read from the value-free `AdvisoryObservation` the #505
    // wiring folds through the pure `advisory_usage` core and exposes on the
    // request observation surface; advisory data never touches a routing decision.
    advisory_observed_on_every_routed_response,
    advisory_capped_at_inferred_never_proven,
    advisory_changes_no_routing_decision,
    advisory_fresh_window_boundary_exact,
    advisory_valid_empty_arms_negative_cache,
    advisory_records_normalized_typed_observation,
    advisory_surface_and_event_value_free,
    advisory_tolerates_unknown_fields,
    advisory_excludes_row_missing_scope,
    advisory_excludes_row_missing_window,
    advisory_excludes_row_unbounded_value,
    advisory_excludes_row_non_absolute_reset,
    advisory_model_scope_requires_exact_model,
    advisory_invalid_row_excluded_never_fabricated,
    advisory_schema_event_redacted_value_free,
    advisory_one_schema_event_per_fingerprint,
    advisory_missing_structure_trips_kill,
    advisory_unsupported_schema_trips_kill,
    advisory_stale_falls_back_to_reactive,
    advisory_missing_falls_back_to_reactive,
    advisory_contradictory_falls_back_to_reactive,
    advisory_killed_falls_back_to_reactive,
    advisory_failure_never_blocks_serving,
    advisory_absent_invents_no_route_readiness,
    advisory_mismatch_invents_no_model_readiness,
    reactive_outranks_fresh_advisory,
    advisory_observation_adds_no_upstream_call,
    advisory_exhaustion_trusted_through_reset,
    advisory_availability_expires_at_deadline,
    // §8.8 refresh-predicate OBSERVATION family (TIN-2400, PR C). Every fact
    // below is read from the typed `LockedRefreshAttempt` / quarantine-marker
    // state the TIN-2990 flock-owned refresh engine produces on synthetic
    // stores; refresh values, tokens, paths, and accounts never enter the
    // artifact.
    refresh_requires_owned_account_flock,
    account_flock_serializes_cross_actor,
    account_flock_reentrant_same_actor,
    transient_lock_failure_skips_endpoint,
    transient_lock_failure_leaves_no_quarantine,
    transient_store_failure_skips_endpoint,
    transient_store_failure_leaves_no_quarantine,
    invalid_grant_lineage_hard_quarantined,
    invalid_grant_hard_quarantine_blocks_before_endpoint,
    hard_tag_refused_without_locked_lineage_proof,
    hard_quarantine_refuses_reenroll_clearance,
    indeterminate_quarantine_clears_via_reenroll,
    quarantine_marker_forbids_stale_backup_restore,
    stale_backup_restore_marker_rejected,
    quarantine_recovery_is_provider_reenroll_only,
};

const fact_ids = [_]FactId{
    .listener_bound_ipv4_loopback,
    .carrier_is_canonical_256bit_base64url,
    .valid_capability_reaches_fake_once,
    .invalid_capability_returns_401,
    .invalid_capability_adds_zero_fake_calls,
    .invalid_capability_observation_is_fresh,
    .aggregate_accepted_request_count_is_one,
    .aggregate_rejected_request_count_is_one,
    .aggregate_request_counts_reconcile_with_ids,
    .caller_auth_headers_absent_upstream,
    .forwarding_identity_headers_absent_upstream,
    .hop_headers_absent_upstream,
    .required_safe_headers_present_upstream,
    .invalid_origin_requests_return_400,
    .forward_proxy_requests_return_400,
    .invalid_origin_and_proxy_requests_add_zero_fake_calls,
    .redirect_returns_local_502,
    .redirect_is_not_followed,
    .streaming_prefix_arrives_before_upstream_completion,
    .streaming_body_arrives_byte_preserved,
    .streaming_uses_one_fake_call,
    .provider_5xx_status_and_body_pass_through,
    .provider_5xx_uses_one_fake_call,
    .prebody_401_consumes_one_alternate,
    .alternate_success_records_two_attempts,
    .first_attempt_body_forwarded_byte_exact,
    .alternate_replay_body_byte_exact,
    .prebody_403_consumes_one_alternate,
    .prebody_429_consumes_alternate_after_wait,
    .pre_alternate_wait_within_bound,
    .wait_beyond_max_returns_local_429,
    .wait_beyond_deadline_returns_local_429,
    .presend_fault_consumes_one_same_route_retry,
    .transport_failure_never_contacts_alternate,
    .same_identity_alternate_delivers_original,
    .alternate_slot_transport_fail_adds_no_retry,
    .same_route_retry_401_adds_no_alternate,
    .alternate_failure_no_third_attempt,
    .started_response_never_replayed,
    .route_identity_admission,
    .identity_conflict_fail_closed,
    .route_readiness_ordering,
    .lease_state_redaction,
    .stale_lease_reactive_routing,
    .unavailable_lease_reactive_routing,
    .sticky_least_loaded_selection,
    .deterministic_shared_leases,
    .stale_lease_owner_cleanup,
    .cancellation_releases_reservation_to_zero,
    .cancellation_makes_no_replay,
    .streaming_cancellation_single_attempt,
    .stream_once_cancellation_keeps_latch_no_replay,
    .stream_once_cancellation_releases_reservation,
    .oversize_body_streams_once_refuses_alternate,
    .sidecar_budget_exhaustion_forces_stream_once,
    .overflow_releases_reservation_next_unaffected,
    .all_exhausted_returns_bounded_429,
    .all_exhausted_propagates_minimum_trusted_reset,
    .all_exhausted_without_reset_omits_retry_after,
    .all_exhausted_delivers_typed_429_not_200,
    .all_exhausted_ignores_malformed_reset,
    .no_alternate_emits_single_uniform_terminal,
    .same_identity_pool_emits_single_uniform_terminal,
    .routed_alternate_completes_with_no_resident,
    .abrupt_death_mid_alternate_reclaims_to_zero,
    .teardown_holds_then_releases_reservation,
    .teardown_converges_within_bound,
    .partial_request_teardown_no_replay_bounded,
    .sequential_routed_requests_release_each_time,
    .advisory_observed_on_every_routed_response,
    .advisory_capped_at_inferred_never_proven,
    .advisory_changes_no_routing_decision,
    .advisory_fresh_window_boundary_exact,
    .advisory_valid_empty_arms_negative_cache,
    .advisory_records_normalized_typed_observation,
    .advisory_surface_and_event_value_free,
    .advisory_tolerates_unknown_fields,
    .advisory_excludes_row_missing_scope,
    .advisory_excludes_row_missing_window,
    .advisory_excludes_row_unbounded_value,
    .advisory_excludes_row_non_absolute_reset,
    .advisory_model_scope_requires_exact_model,
    .advisory_invalid_row_excluded_never_fabricated,
    .advisory_schema_event_redacted_value_free,
    .advisory_one_schema_event_per_fingerprint,
    .advisory_missing_structure_trips_kill,
    .advisory_unsupported_schema_trips_kill,
    .advisory_stale_falls_back_to_reactive,
    .advisory_missing_falls_back_to_reactive,
    .advisory_contradictory_falls_back_to_reactive,
    .advisory_killed_falls_back_to_reactive,
    .advisory_failure_never_blocks_serving,
    .advisory_absent_invents_no_route_readiness,
    .advisory_mismatch_invents_no_model_readiness,
    .reactive_outranks_fresh_advisory,
    .advisory_observation_adds_no_upstream_call,
    .advisory_exhaustion_trusted_through_reset,
    .advisory_availability_expires_at_deadline,
    .refresh_requires_owned_account_flock,
    .account_flock_serializes_cross_actor,
    .account_flock_reentrant_same_actor,
    .transient_lock_failure_skips_endpoint,
    .transient_lock_failure_leaves_no_quarantine,
    .transient_store_failure_skips_endpoint,
    .transient_store_failure_leaves_no_quarantine,
    .invalid_grant_lineage_hard_quarantined,
    .invalid_grant_hard_quarantine_blocks_before_endpoint,
    .hard_tag_refused_without_locked_lineage_proof,
    .hard_quarantine_refuses_reenroll_clearance,
    .indeterminate_quarantine_clears_via_reenroll,
    .quarantine_marker_forbids_stale_backup_restore,
    .stale_backup_restore_marker_rejected,
    .quarantine_recovery_is_provider_reenroll_only,
};

const Fact = struct {
    id: FactId,
    status: Status,
};

const RequestCounters = struct {
    accepted: usize = 0,
    rejected: usize = 0,
    observed: usize = 0,
    request_ids_complete: bool = true,
    classifications_complete: bool = true,

    fn record(self: *RequestCounters, observation: wire_proxy.RequestObservation) void {
        const next_observed = std.math.add(usize, self.observed, 1) catch {
            self.request_ids_complete = false;
            self.classifications_complete = false;
            return;
        };
        const expected_request_id = std.math.cast(u64, next_observed) orelse {
            self.request_ids_complete = false;
            self.classifications_complete = false;
            return;
        };
        if (observation.request_id != expected_request_id) {
            self.request_ids_complete = false;
        }
        self.observed = next_observed;

        if (observation.outcome == .upstream_response and observation.upstream_attempted) {
            self.accepted = std.math.add(usize, self.accepted, 1) catch {
                self.classifications_complete = false;
                return;
            };
        } else if (observation.outcome == .capability_rejected and !observation.upstream_attempted) {
            self.rejected = std.math.add(usize, self.rejected, 1) catch {
                self.classifications_complete = false;
                return;
            };
        } else {
            self.classifications_complete = false;
        }
    }

    fn reconciles(self: RequestCounters) bool {
        const classified = std.math.add(usize, self.accepted, self.rejected) catch return false;
        return self.observed != 0 and
            self.request_ids_complete and
            self.classifications_complete and
            classified == self.observed;
    }
};

const Artifact = struct {
    schema_version: u8 = 1,
    target: []const u8 = "v02-stage2-conformance",
    candidate_sha: []const u8,
    candidate_tree: []const u8,
    workflow_run_id: u64,
    workflow_run_attempt: u64,
    gf_target_class: []const u8,
    facts: []const Fact,
};

pub fn emit(identity: BuildIdentity) !void {
    try validateBuildIdentity(identity);
    try runLeaseChildDeadlineControl();

    var facts: [fact_ids.len]Fact = undefined;
    for (&facts, fact_ids) |*fact, id| fact.* = .{ .id = id, .status = .fail };

    runCapabilityScenario(&facts) catch {};
    runHeaderBoundaryScenario(&facts) catch {};
    runOriginBoundaryScenario(&facts) catch {};
    runRedirectScenario(&facts) catch {};
    runStreamingScenario(&facts) catch {};
    runProvider5xxScenario(&facts) catch {};
    // §2.2 single-alternate retry machine + bounded terminal (routed seam #494).
    runAlternate401Scenario(&facts) catch {};
    runAlternate403Scenario(&facts) catch {};
    runAlternate429WaitScenario(&facts) catch {};
    runWaitBeyondMaxScenario(&facts) catch {};
    runWaitBeyondDeadlineScenario(&facts) catch {};
    runSameRouteRetryScenario(&facts) catch {};
    runSameIdentityRefusalScenario(&facts) catch {};
    runSlotExclusivityScenario(&facts) catch {};
    runAlternateFailureNoThirdScenario(&facts) catch {};
    runStartedResponseScenario(&facts) catch {};
    runBrokerMappingScenario(&facts) catch {};
    runCrossProcessLeaseScenario(&facts) catch {};
    runCancellationReplayableScenario(&facts) catch {};
    runStreamOnceCancellationScenario(&facts) catch {};
    runOverflowNoAlternateScenario(&facts) catch {};
    runOverflowReleaseScenario(&facts) catch {};
    runAllExhaustedMinResetScenario(&facts) catch {};
    runAllExhaustedNoResetScenario(&facts) catch {};
    runAllExhaustedMalformedResetScenario(&facts) catch {};
    runNoAlternateTerminalScenario(&facts) catch {};
    runSameIdentityTerminalScenario(&facts) catch {};
    runResidentAbsenceScenario(&facts) catch {};
    runAbruptDeathScenario(&facts) catch {};
    runPartialSendTeardownScenario(&facts) catch {};
    runSequentialReleaseScenario(&facts) catch {};
    // §8.8 advisory-usage OBSERVATION family (observation-only, PR B).
    runAdvisoryDefaultOnScenario(&facts) catch {};
    runAdvisoryNonAuthoritativeScenario(&facts) catch {};
    runAdvisoryFreshnessBoundaryScenario(&facts) catch {};
    runAdvisoryNegativeCacheScenario(&facts) catch {};
    runAdvisoryNormalizedValueFreeScenario(&facts) catch {};
    runAdvisoryUnknownFieldToleranceScenario(&facts) catch {};
    runAdvisoryRequiredFieldExclusionScenario(&facts) catch {};
    runAdvisoryExactModelScopeScenario(&facts) catch {};
    runAdvisoryInvalidRowExclusionScenario(&facts) catch {};
    runAdvisorySchemaKillScenario(&facts) catch {};
    runAdvisoryStaleFallbackScenario(&facts) catch {};
    runAdvisoryMissingFallbackScenario(&facts) catch {};
    runAdvisoryContradictoryFallbackScenario(&facts) catch {};
    runAdvisoryKilledFallbackScenario(&facts) catch {};
    runAdvisoryNonBlockingScenario(&facts) catch {};
    runAdvisoryNoInventedRouteScenario(&facts) catch {};
    runAdvisoryNoInventedModelScenario(&facts) catch {};
    runAdvisoryReactivePrecedenceScenario(&facts) catch {};
    runAdvisoryNoPollScenario(&facts) catch {};
    runAdvisoryThroughResetScenario(&facts) catch {};
    runAdvisoryDeadlineScenario(&facts) catch {};
    // §8.8 refresh-predicate OBSERVATION family (TIN-2400, PR C).
    runRefreshSharedAccountFlockScenario(&facts) catch {};
    runRefreshLockNoDeadlockScenario(&facts) catch {};
    runRefreshTransientLockFailureScenario(&facts) catch {};
    runRefreshTransientStoreFailureScenario(&facts) catch {};
    runRefreshInvalidLineageQuarantineScenario(&facts) catch {};
    runRefreshProviderEvidenceScenario(&facts) catch {};
    runRefreshReenrollmentScenario(&facts) catch {};
    runRefreshNoStaleBackupRestoreScenario(&facts) catch {};
    runRefreshNoForensicBackupRestoreScenario(&facts) catch {};

    const artifact = Artifact{
        .candidate_sha = identity.candidate_sha,
        .candidate_tree = identity.candidate_tree,
        .workflow_run_id = try parsePositiveInteger(identity.workflow_run_id),
        .workflow_run_attempt = try parsePositiveInteger(identity.workflow_run_attempt),
        .gf_target_class = identity.gf_target_class,
        .facts = &facts,
    };
    try writeArtifactAtomic(artifact);

    for (facts) |fact| {
        if (fact.status != .pass) {
            std.log.err("Stage 2 fact failed: {s}", .{@tagName(fact.id)});
            return error.Stage2ObservationFailed;
        }
    }
}

fn validateBuildIdentity(identity: BuildIdentity) !void {
    if (!isLowerHexSha(identity.candidate_sha)) return error.InvalidCandidateSha;
    if (!isLowerHexSha(identity.candidate_tree)) return error.InvalidCandidateTree;
    _ = try parsePositiveInteger(identity.workflow_run_id);
    _ = try parsePositiveInteger(identity.workflow_run_attempt);
    if (!std.mem.eql(u8, identity.gf_target_class, "tinyland-nix")) {
        return error.InvalidGfTargetClass;
    }
}

fn isLowerHexSha(value: []const u8) bool {
    if (value.len != 40) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn parsePositiveInteger(value: []const u8) !u64 {
    const parsed = try std.fmt.parseInt(u64, value, 10);
    if (parsed == 0) return error.ExpectedPositiveInteger;
    return parsed;
}

fn setFact(facts: []Fact, id: FactId, passed: bool) void {
    for (facts) |*fact| {
        if (fact.id != id) continue;
        fact.status = if (passed) .pass else .fail;
        return;
    }
    unreachable;
}

fn strengthenFact(facts: []Fact, id: FactId, passed: bool) void {
    for (facts) |*fact| {
        if (fact.id != id) continue;
        fact.status = if (fact.status == .pass and passed) .pass else .fail;
        return;
    }
    unreachable;
}

fn copyCarrier(capability: *SessionCapability) ![capability_mod.carrier_len]u8 {
    var carrier: [capability_mod.carrier_len]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &carrier);
    try capability.copyCarrier(&carrier);
    return carrier;
}

fn canonicalCarrier(carrier: *const [capability_mod.carrier_len]u8) bool {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(carrier) catch return false;
    if (decoded_len != capability_mod.entropy_len) return false;
    var decoded: [capability_mod.entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    decoder.decode(&decoded, carrier) catch return false;
    var reencoded: [capability_mod.carrier_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &reencoded);
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&reencoded, &decoded);
    return std.mem.eql(u8, carrier, encoded);
}

fn runCapabilityScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const expected = try std.net.Address.parseIp("127.0.0.1", listener.port());
    setFact(facts, .listener_bound_ipv4_loopback, expected.eql(listener.address()));
    setFact(facts, .carrier_is_canonical_256bit_base64url, canonicalCarrier(&carrier));

    const accepted = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(accepted);
    const accepted_response = try requestRawAlloc(listener.address(), accepted);
    defer std.testing.allocator.free(accepted_response);
    setFact(
        facts,
        .valid_capability_reaches_fake_once,
        hasStatus(accepted_response, "204 No Content") and upstream.snapshot().call_count == 1,
    );
    const accepted_observation = wire_proxy.testing.requestObservation(listener);
    var counters = RequestCounters{};
    counters.record(accepted_observation);

    var wrong = [_]u8{'A'} ** capability_mod.carrier_len;
    defer std.crypto.secureZero(u8, &wrong);
    if (std.mem.eql(u8, &wrong, &carrier)) wrong[0] = 'B';
    const rejected = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), wrong },
    );
    defer std.testing.allocator.free(rejected);
    const before_rejection_calls = upstream.snapshot().call_count;
    const rejected_response = try requestRawAlloc(listener.address(), rejected);
    defer std.testing.allocator.free(rejected_response);
    const rejected_observation = wire_proxy.testing.requestObservation(listener);
    counters.record(rejected_observation);
    setFact(facts, .invalid_capability_returns_401, hasStatus(rejected_response, "401 Unauthorized"));
    setFact(
        facts,
        .invalid_capability_adds_zero_fake_calls,
        upstream.snapshot().call_count == before_rejection_calls,
    );
    setFact(
        facts,
        .invalid_capability_observation_is_fresh,
        rejected_observation.request_id == accepted_observation.request_id + 1 and
            rejected_observation.outcome == .capability_rejected and
            !rejected_observation.upstream_attempted,
    );
    setFact(facts, .aggregate_accepted_request_count_is_one, counters.accepted == 1);
    setFact(facts, .aggregate_rejected_request_count_is_one, counters.rejected == 1);
    setFact(
        facts,
        .aggregate_request_counts_reconcile_with_ids,
        counters.reconciles(),
    );
}

test "request counters require a complete fresh-listener id range and classification" {
    var counters = RequestCounters{};
    counters.record(.{
        .request_id = 1,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    counters.record(.{
        .request_id = 2,
        .outcome = .capability_rejected,
        .upstream_attempted = false,
    });

    try std.testing.expectEqual(@as(usize, 1), counters.accepted);
    try std.testing.expectEqual(@as(usize, 1), counters.rejected);
    try std.testing.expect(counters.reconciles());

    var offset = RequestCounters{};
    offset.record(.{
        .request_id = 41,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    offset.record(.{
        .request_id = 42,
        .outcome = .capability_rejected,
        .upstream_attempted = false,
    });
    try std.testing.expect(!offset.reconciles());

    var zero = RequestCounters{};
    zero.record(.{
        .request_id = 0,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    try std.testing.expect(!zero.reconciles());

    var skipped = RequestCounters{};
    skipped.record(.{
        .request_id = 1,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    skipped.record(.{
        .request_id = 3,
        .outcome = .capability_rejected,
        .upstream_attempted = false,
    });
    try std.testing.expect(!skipped.reconciles());

    var duplicate = RequestCounters{};
    duplicate.record(.{
        .request_id = 1,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    duplicate.record(.{
        .request_id = 1,
        .outcome = .capability_rejected,
        .upstream_attempted = false,
    });
    try std.testing.expect(!duplicate.reconciles());

    var overflow = RequestCounters{
        .accepted = std.math.maxInt(usize),
        .rejected = 1,
        .observed = std.math.maxInt(usize),
    };
    try std.testing.expect(!overflow.reconciles());
    overflow.record(.{
        .request_id = 0,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    try std.testing.expect(!overflow.reconciles());

    var unclassified = RequestCounters{};
    unclassified.record(.{
        .request_id = 1,
        .outcome = .upstream_response,
        .upstream_attempted = true,
    });
    unclassified.record(.{
        .request_id = 2,
        .outcome = .proxy_error,
        .upstream_attempted = false,
    });
    try std.testing.expect(!unclassified.reconciles());
}

fn runHeaderBoundaryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nX-Api-Key: synthetic\r\nCookie: synthetic\r\nForwarded: host=synthetic.invalid\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-Host: synthetic.invalid\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 192.0.2.2\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic synthetic\r\nProxy-Authorization: Basic synthetic\r\nProxy-Connection: keep-alive\r\nConnection: {s}, close\r\n{s}: remove\r\nTE: trailers\r\nTrailer: X-Result\r\nTrailers: X-Result\r\nUpgrade: websocket\r\nAnthropic-Version: 2023-06-01\r\n\r\n",
        .{
            listener.port(),
            carrier,
            fake_upstream_mod.connection_nominated_canary,
            fake_upstream_mod.connection_nominated_canary,
        },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    if (!hasStatus(response, "204 No Content") or upstream.snapshot().call_count != 1) return;

    const presence = upstream.requestHeaderPresenceSnapshot();
    setFact(
        facts,
        .caller_auth_headers_absent_upstream,
        !presence.authorization and !presence.x_api_key and !presence.cookie,
    );
    setFact(
        facts,
        .forwarding_identity_headers_absent_upstream,
        !presence.forwarded and !presence.x_forwarded_for and
            !presence.x_forwarded_host and !presence.x_forwarded_port and
            !presence.x_forwarded_proto and !presence.x_real_ip,
    );
    setFact(
        facts,
        .hop_headers_absent_upstream,
        !presence.keep_alive and !presence.proxy_authenticate and
            !presence.proxy_authorization and !presence.proxy_connection and
            !presence.x_private_hop_canary and !presence.te and !presence.trailer and
            !presence.trailers and !presence.upgrade and !presence.expect,
    );
    setFact(
        facts,
        .required_safe_headers_present_upstream,
        presence.accept_encoding and presence.anthropic_version,
    );
}

fn runOriginBoundaryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const invalid_origin = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (invalid_origin) |request| std.testing.allocator.free(request);
    var origin_ok = true;
    for (invalid_origin) |request| {
        const response = try requestRawAlloc(listener.address(), request);
        defer std.testing.allocator.free(response);
        origin_ok = origin_ok and hasStatus(response, "400 Bad Request");
    }
    setFact(facts, .invalid_origin_requests_return_400, origin_ok);

    const proxy_forms = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "GET https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (proxy_forms) |request| std.testing.allocator.free(request);
    var proxy_ok = true;
    for (proxy_forms) |request| {
        const response = try requestRawAlloc(listener.address(), request);
        defer std.testing.allocator.free(response);
        proxy_ok = proxy_ok and hasStatus(response, "400 Bad Request");
    }
    setFact(facts, .forward_proxy_requests_return_400, proxy_ok);
    setFact(
        facts,
        .invalid_origin_and_proxy_requests_add_zero_fake_calls,
        upstream.snapshot().isZero(),
    );
}

fn runRedirectScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var redirect_trap = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer redirect_trap.deinit();
    const redirect_location = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/blocked",
        .{redirect_trap.baseUrl()},
    );
    defer std.testing.allocator.free(redirect_location);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .found,
        .headers = &.{.{ .name = "Location", .value = redirect_location }},
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const request = try basicGetRequest(listener.port(), &carrier);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    setFact(facts, .redirect_returns_local_502, hasStatus(response, "502 Bad Gateway"));
    setFact(
        facts,
        .redirect_is_not_followed,
        upstream.snapshot().call_count == 1 and redirect_trap.snapshot().isZero(),
    );
}

fn runStreamingScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const first = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .pause_after_bytes = first.len,
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const body = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequest(listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, first);
    setFact(
        facts,
        .streaming_prefix_arrives_before_upstream_completion,
        hasStatus(response.items, "200 OK") and
            std.mem.indexOf(u8, response.items, first) != null and
            std.mem.indexOf(u8, response.items, rest) == null,
    );
    upstream.releasePausedResponse();
    try readResponseRemainder(&stream, &response);
    const body_start = std.mem.indexOf(u8, response.items, "\r\n\r\n");
    setFact(
        facts,
        .streaming_body_arrives_byte_preserved,
        body_start != null and
            std.mem.eql(u8, response.items[body_start.? + 4 ..], first ++ rest),
    );
    setFact(facts, .streaming_uses_one_fake_call, upstream.snapshot().call_count == 1);
}

fn runProvider5xxScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const body = "{\"type\":\"error\",\"error\":{\"type\":\"api_error\"}}";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .internal_server_error,
        .body = body,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try wire_proxy.testing.startWithFake(
        std.testing.allocator,
        capability,
        &upstream,
        std.io.null_writer.any(),
    );
    defer listener.deinit();
    const request_body = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequest(listener.port(), &carrier, request_body);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    setFact(
        facts,
        .provider_5xx_status_and_body_pass_through,
        hasStatus(response, "500 Internal Server Error") and std.mem.endsWith(u8, response, body),
    );
    setFact(facts, .provider_5xx_uses_one_fake_call, upstream.snapshot().call_count == 1);
}

fn basicGetRequest(port: u16, carrier: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ port, carrier },
    );
}

fn postRequest(port: u16, carrier: []const u8, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ port, carrier, body.len, body },
    );
}

fn requestRawAlloc(address: std.net.Address, bytes: []const u8) ![]u8 {
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(bytes);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    errdefer response.deinit();
    var buffer: [1024]u8 = undefined;
    while (true) {
        const count = try stream.read(&buffer);
        if (count == 0) break;
        try response.appendSlice(buffer[0..count]);
    }
    return response.toOwnedSlice();
}

fn hasStatus(response: []const u8, status: []const u8) bool {
    return std.mem.startsWith(u8, response, "HTTP/1.1 ") and
        std.mem.indexOf(u8, response[9..], status) == 0;
}

fn waitForResponsePrefix(upstream: *FakeUpstream) !void {
    var timer = try std.time.Timer.start();
    while (!upstream.responsePrefixWritten()) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn readUntilContains(
    stream: *std.net.Stream,
    response: *std.ArrayList(u8),
    needle: []const u8,
) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (std.mem.indexOf(u8, response.items, needle) == null) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return error.EndOfStream;
        try response.appendSlice(buffer[0..count]);
    }
}

fn readResponseRemainder(stream: *std.net.Stream, response: *std.ArrayList(u8)) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (true) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return;
        try response.appendSlice(buffer[0..count]);
    }
}

// ===========================================================================
// §2.2 single-alternate retry machine + bounded terminal + teardown/resident
// OBSERVATION (routed synthetic seam #494). Every scenario drives the routed
// test seam over caller-supplied synthetic routes and deterministic fakes, then
// records only value-free pass/fail facts. Production upstream selection and
// automatic alternates stay compile-fixed and unreachable through this seam.
// ===========================================================================

const routed_model = "claude-opus-4-20250514";
const routed_json = "{\"model\":\"" ++ routed_model ++ "\",\"max_tokens\":16}";
const max_wait_ns_bound: u64 = 30 * std.time.ns_per_s;

/// Virtual clock for the injected-wait scenarios: `sleep` advances a purely
/// in-memory timestamp and records the wait, so no real time passes and the
/// bounded-wait observation is deterministic.
const VirtualClock = struct {
    now_ns: i128 = 0,
    sleep_calls: usize = 0,
    last_sleep_ns: u64 = 0,

    fn nowNs(ctx: ?*anyopaque) i128 {
        const self: *VirtualClock = @ptrCast(@alignCast(ctx.?));
        return self.now_ns;
    }

    fn sleepNs(ctx: ?*anyopaque, ns: u64) void {
        const self: *VirtualClock = @ptrCast(@alignCast(ctx.?));
        self.sleep_calls += 1;
        self.last_sleep_ns = ns;
        self.now_ns += @intCast(ns);
    }

    fn clock(self: *VirtualClock) wire_proxy.testing.Clock {
        return .{ .ctx = self, .nowFn = nowNs, .sleepFn = sleepNs };
    }

    fn leaseWorkClock(self: *VirtualClock) broker_lease_runtime.WorkClock {
        return .{ .ctx = self, .nowFn = nowNs };
    }
};

fn routedRequestBody(
    listener: *wire_proxy.Listener,
    carrier: []const u8,
    body: []const u8,
) ![]u8 {
    const request = try postRequest(listener.port(), carrier, body);
    defer std.testing.allocator.free(request);
    return requestRawAlloc(listener.address(), request);
}

fn routedRequest(listener: *wire_proxy.Listener, carrier: []const u8) ![]u8 {
    return routedRequestBody(listener, carrier, routed_json);
}

fn responseHasRetryAfter(response: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(response, "retry-after") != null;
}

fn waitForConnectionActive(listener: *wire_proxy.Listener) !void {
    var timer = try std.time.Timer.start();
    while (!wire_proxy.testing.connectionActive(listener)) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn waitForListenerIdle(listener: *wire_proxy.Listener) !void {
    var timer = try std.time.Timer.start();
    while (wire_proxy.testing.connectionActive(listener)) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn runAlternate401Scenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "{\"ok\":true}" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "route-1-secret", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "route-2-secret", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);

    const alt_success = hasStatus(response, "200 OK") and
        std.mem.endsWith(u8, response, "\r\n\r\n{\"ok\":true}");
    setFact(facts, .prebody_401_consumes_one_alternate, alt_success and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1 and
        obs.alternate_count == 1 and obs.same_route_retry_count == 0);
    setFact(facts, .alternate_success_records_two_attempts, obs.attempts_total == 2 and
        obs.third_attempt_count == 0);

    var first_sent: [256]u8 = undefined;
    const first_len = primary.capturedRequestBody(&first_sent);
    var alt_sent: [256]u8 = undefined;
    const alt_len = alternate.capturedRequestBody(&alt_sent);
    setFact(facts, .first_attempt_body_forwarded_byte_exact, obs.model_present and
        std.mem.eql(u8, first_sent[0..first_len], routed_json));
    setFact(facts, .alternate_replay_body_byte_exact, std.mem.eql(u8, alt_sent[0..alt_len], routed_json) and
        std.mem.eql(u8, alt_sent[0..alt_len], first_sent[0..first_len]));
}

fn runAlternate403Scenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .forbidden, .body = "forbidden" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .prebody_403_consumes_one_alternate, hasStatus(response, "200 OK") and std.mem.endsWith(u8, response, "\r\n\r\nalt-ok") and
        obs.alternate_count == 1 and obs.attempts_total == 2 and obs.third_attempt_count == 0);
}

fn runAlternate429WaitScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .prebody_429_consumes_alternate_after_wait, hasStatus(response, "200 OK") and std.mem.endsWith(u8, response, "\r\n\r\nalt-ok") and
        obs.alternate_count == 1 and obs.attempts_total == 2);
    setFact(facts, .pre_alternate_wait_within_bound, vclock.sleep_calls == 1 and
        vclock.last_sleep_ns == 5 * std.time.ns_per_s and vclock.last_sleep_ns <= max_wait_ns_bound);
}

fn runWaitBeyondMaxScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "40" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .wait_beyond_max_returns_local_429, hasStatus(response, "429 Too Many Requests") and vclock.sleep_calls == 0 and
        alternate.snapshot().isZero() and obs.alternate_count == 0);
}

fn runWaitBeyondDeadlineScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
        .request_deadline_ns = 2 * std.time.ns_per_s,
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    setFact(facts, .wait_beyond_deadline_returns_local_429, hasStatus(response, "429 Too Many Requests") and vclock.sleep_calls == 0 and
        alternate.snapshot().isZero());
}

fn runSameRouteRetryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "retried-ok" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-must-not-run" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1", .presend_faults = 1 },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .presend_fault_consumes_one_same_route_retry, hasStatus(response, "200 OK") and std.mem.endsWith(u8, response, "\r\n\r\nretried-ok") and
        primary.snapshot().call_count == 1 and obs.same_route_retry_count == 1 and
        obs.alternate_count == 0 and obs.attempts_total == 2);
    setFact(facts, .transport_failure_never_contacts_alternate, alternate.snapshot().isZero());
}

fn runSameIdentityRefusalScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .same_identity_alternate_delivers_original, hasStatus(response, "401 Unauthorized") and std.mem.endsWith(u8, response, "\r\n\r\ndenied") and
        alternate.snapshot().isZero() and obs.same_identity_alternate_refused and
        obs.attempts_total == 1 and obs.alternate_count == 0);
}

fn runSlotExclusivityScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Order A: a pre-body 401 consumes the alternate slot; the alternate then
    // transport-fails. No same-route retry may be added.
    {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
        defer primary.deinit();
        var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
        defer alternate.deinit();

        const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
            .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
            .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2", .presend_faults = 1 },
        });
        defer listener.deinit();

        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        const obs = wire_proxy.testing.requestObservation(listener);
        setFact(facts, .alternate_slot_transport_fail_adds_no_retry, hasStatus(response, "502 Bad Gateway") and primary.snapshot().call_count == 1 and
            alternate.snapshot().isZero() and obs.alternate_count == 1 and
            obs.same_route_retry_count == 0 and obs.attempts_total == 2);
    }

    // Order B: a proven pre-send fault consumes the same-route retry; the retry
    // then returns 401. No alternate may be added.
    {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied-on-retry" }});
        defer primary.deinit();
        var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
        defer alternate.deinit();

        const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
            .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1", .presend_faults = 1 },
            .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        });
        defer listener.deinit();

        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        const obs = wire_proxy.testing.requestObservation(listener);
        setFact(facts, .same_route_retry_401_adds_no_alternate, hasStatus(response, "401 Unauthorized") and std.mem.endsWith(u8, response, "\r\n\r\ndenied-on-retry") and
            primary.snapshot().call_count == 1 and alternate.snapshot().isZero() and
            obs.same_route_retry_count == 1 and obs.alternate_count == 0 and obs.attempts_total == 2);
    }
}

fn runAlternateFailureNoThirdScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .internal_server_error, .body = "alt-boom" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .alternate_failure_no_third_attempt, hasStatus(response, "500 Internal Server Error") and std.mem.endsWith(u8, response, "\r\n\r\nalt-boom") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1 and
        obs.attempts_total == 2 and obs.alternate_count == 1 and obs.third_attempt_count == 0);
}

fn runStartedResponseScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\"}}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .truncate_after_bytes = first.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .started_response_never_replayed, hasStatus(response, "200 OK") and
        std.mem.indexOf(u8, response, first) != null and std.mem.indexOf(u8, response, rest) == null and
        primary.snapshot().call_count == 1 and alternate.snapshot().isZero() and
        obs.attempts_total == 1 and obs.alternate_count == 0 and obs.same_route_retry_count == 0 and
        wire_proxy.testing.reservationOutstanding(listener) == 0);
}

fn runCancellationReplayableScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const request = try postRequest(listener.port(), &carrier, routed_json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);
    const prefix_seen = std.mem.indexOf(u8, response.items, prefix) != null;

    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    primary.releasePausedResponse();
    try waitForListenerIdle(listener);

    setFact(facts, .cancellation_releases_reservation_to_zero, wire_proxy.testing.reservationOutstanding(listener) == 0);
    setFact(facts, .cancellation_makes_no_replay, alternate.snapshot().isZero() and primary.snapshot().call_count == 1);
    setFact(facts, .streaming_cancellation_single_attempt, prefix_seen and
        primary.snapshot().call_count == 1 and primary.snapshot().attempt_count == 1);
}

fn runStreamOnceCancellationScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    // Budget below the request body: the request is IRREVOCABLY stream-once
    // before the primary is contacted.
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 4096,
    });
    defer listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 8 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const body = try std.fmt.allocPrint(std.testing.allocator, "{{\"model\":\"{s}\",\"pad\":\"{s}\"}}", .{ routed_model, pad });
    defer std.testing.allocator.free(body);
    const request = try postRequest(listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);

    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&primary);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    primary.releasePausedResponse();
    try waitForListenerIdle(listener);

    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .stream_once_cancellation_keeps_latch_no_replay, obs.replay_mode == .stream_once and alternate.snapshot().isZero() and
        primary.snapshot().call_count == 1);
    setFact(facts, .stream_once_cancellation_releases_reservation, wire_proxy.testing.reservationOutstanding(listener) == 0);
}

fn runOverflowNoAlternateScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 4096,
    });
    defer listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 8 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const body = try std.fmt.allocPrint(std.testing.allocator, "{{\"pad\":\"{s}\",\"model\":\"{s}\"}}", .{ pad, routed_model });
    defer std.testing.allocator.free(body);
    const request = try postRequest(listener.port(), &carrier, body);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(listener.address(), request);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);

    setFact(facts, .oversize_body_streams_once_refuses_alternate, hasStatus(response, "401 Unauthorized") and alternate.snapshot().isZero() and
        obs.replay_mode == .stream_once and obs.attempts_total == 1 and obs.alternate_count == 0 and
        wire_proxy.testing.reservationOutstanding(listener) == 0);
    setFact(facts, .sidecar_budget_exhaustion_forces_stream_once, obs.replay_mode == .stream_once and wire_proxy.testing.reservationOutstanding(listener) == 0);
}

fn runOverflowReleaseScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .unauthorized, .body = "denied" },
        .{ .status = .unauthorized, .body = "denied" },
    });
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "{\"ok\":true}" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .reservation_budget_bytes = 8192,
    });
    defer listener.deinit();

    const pad = try std.testing.allocator.alloc(u8, 32 * 1024);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const overflow_body = try std.fmt.allocPrint(std.testing.allocator, "{{\"model\":\"{s}\",\"pad\":\"{s}\"}}", .{ routed_model, pad });
    defer std.testing.allocator.free(overflow_body);

    var overflow_ok = false;
    {
        const request = try postRequest(listener.port(), &carrier, overflow_body);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(listener.address(), request);
        defer std.testing.allocator.free(response);
        overflow_ok = hasStatus(response, "401 Unauthorized") and
            wire_proxy.testing.reservationOutstanding(listener) == 0 and
            alternate.snapshot().isZero();
    }

    var followup_ok = false;
    {
        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        followup_ok = hasStatus(response, "200 OK") and
            wire_proxy.testing.reservationOutstanding(listener) == 0 and
            alternate.snapshot().call_count == 1 and primary.snapshot().call_count == 2;
    }
    setFact(facts, .overflow_releases_reservation_next_unaffected, overflow_ok and followup_ok);
}

fn runAllExhaustedMinResetScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "p-limit",
        .headers = &.{.{ .name = "Retry-After", .value = "10" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "a-limit",
        .headers = &.{.{ .name = "Retry-After", .value = "30" }},
    }});
    defer alternate.deinit();

    var vclock = VirtualClock{};
    var event_buffer: [2048]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
        .clock = vclock.clock(),
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .all_exhausted_returns_bounded_429, hasStatus(response, "429 Too Many Requests") and primary.snapshot().call_count == 1 and
        alternate.snapshot().call_count == 1 and obs.attempts_total == 2 and
        obs.third_attempt_count == 0 and wire_proxy.testing.reservationOutstanding(listener) == 0);
    setFact(facts, .all_exhausted_propagates_minimum_trusted_reset, std.mem.indexOf(u8, response, "Retry-After: 10\r\n") != null and
        std.mem.indexOf(u8, response, "Retry-After: 30\r\n") == null and
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted") == 1);
}

fn runAllExhaustedNoResetScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .forbidden, .body = "forbidden" }});
    defer alternate.deinit();

    var event_buffer: [2048]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .all_exhausted_without_reset_omits_retry_after, hasStatus(response, "429 Too Many Requests") and !responseHasRetryAfter(response) and
        obs.attempts_total == 2 and obs.alternate_count == 1);
    setFact(facts, .all_exhausted_delivers_typed_429_not_200, hasStatus(response, "429 Too Many Requests") and
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted") == 1);
}

fn runAllExhaustedMalformedResetScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{.{ .name = "Retry-After", .value = "soon" }},
    }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .all_exhausted_ignores_malformed_reset, hasStatus(response, "429 Too Many Requests") and !responseHasRetryAfter(response) and
        obs.attempts_total == 2 and obs.alternate_count == 1);
}

fn runNoAlternateTerminalScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "denied",
        .headers = &.{.{ .name = "Retry-After", .value = "9" }},
    }});
    defer primary.deinit();

    var event_buffer: [2048]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .no_alternate_emits_single_uniform_terminal, hasStatus(response, "429 Too Many Requests") and obs.attempts_total == 1 and
        obs.alternate_count == 0 and
        std.mem.count(u8, event_stream.getWritten(), "claude_proxy_all_exhausted") == 1);
}

fn runSameIdentityTerminalScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "never" }});
    defer alternate.deinit();

    var event_buffer: [2048]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, event_stream.writer().any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-1" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    const written = event_stream.getWritten();
    setFact(facts, .same_identity_pool_emits_single_uniform_terminal, hasStatus(response, "401 Unauthorized") and alternate.snapshot().isZero() and
        obs.same_identity_alternate_refused and obs.attempts_total == 1 and obs.alternate_count == 0 and
        std.mem.count(u8, written, "claude_proxy_all_exhausted") == 1);
}

fn runResidentAbsenceScenario(facts: []Fact) !void {
    // Behavioral leg of the G6 sidecar-half resident-absence invariant: a full
    // routed alternate flow completes with no resident to construct or consult,
    // so its absence cannot alter routing or the terminal outcome. (The
    // structural grep-as-test over the sidecar State is compiled into wire_proxy.)
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "alt-ok" }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const obs = wire_proxy.testing.requestObservation(listener);
    setFact(facts, .routed_alternate_completes_with_no_resident, hasStatus(response, "200 OK") and std.mem.endsWith(u8, response, "\r\n\r\nalt-ok") and
        obs.alternate_count == 1);
}

fn runAbruptDeathScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Route 1 fails pre-body 401 (buffered); the alternate is a large 2xx that
    // pauses mid-stream, parking attempt 2 with its replay reservation live.
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .unauthorized, .body = "denied" }});
    defer primary.deinit();
    const big = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'y');
    const prefix = "alt-streamed-prefix";
    @memcpy(big[0..prefix.len], prefix);
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = big,
        .pause_after_bytes = prefix.len,
    }});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const request = try postRequest(listener.port(), &carrier, routed_json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&alternate);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    const held = wire_proxy.testing.reservationOutstanding(listener) > 0;

    var shutdown_timer = try std.time.Timer.start();
    const outstanding = try wire_proxy.testing.teardownReclaim(listener);
    listener_live = false;
    const bounded = shutdown_timer.read() < std.time.ns_per_s;

    setFact(facts, .abrupt_death_mid_alternate_reclaims_to_zero, outstanding == 0 and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1);
    setFact(facts, .teardown_holds_then_releases_reservation, held and outstanding == 0);
    setFact(facts, .teardown_converges_within_bound, bounded);
}

fn runPartialSendTeardownScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &.{});
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    // A partial head parks the serve thread in receiveHead — before the
    // capability check and before any reservation is taken. This request is
    // never fully sent, so it can never be replayed.
    try stream.writeAll("POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1");
    try waitForConnectionActive(listener);

    var shutdown_timer = try std.time.Timer.start();
    const outstanding = try wire_proxy.testing.teardownReclaim(listener);
    listener_live = false;
    const bounded = shutdown_timer.read() < std.time.ns_per_s;

    setFact(facts, .partial_request_teardown_no_replay_bounded, outstanding == 0 and
        primary.snapshot().isZero() and alternate.snapshot().isZero() and bounded);
}

fn runSequentialReleaseScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const iterations = 5;
    const primary_script = [_]fake_upstream_mod.ScriptedResponse{.{ .status = .unauthorized, .body = "denied" }} ** iterations;
    const alternate_script = [_]fake_upstream_mod.ScriptedResponse{.{ .status = .ok, .body = "ok" }} ** iterations;
    var primary = try FakeUpstream.start(std.testing.allocator, &primary_script);
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &alternate_script);
    defer alternate.deinit();

    const listener = try wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, std.io.null_writer.any(), .{
        .primary = .{ .upstream = &primary, .bearer = "r1", .identity = "acct-1" },
        .alternate = .{ .upstream = &alternate, .bearer = "r2", .identity = "acct-2" },
    });
    defer listener.deinit();

    var all_ok = true;
    var index: usize = 0;
    while (index < iterations) : (index += 1) {
        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        all_ok = all_ok and hasStatus(response, "200 OK") and
            wire_proxy.testing.reservationOutstanding(listener) == 0;
    }
    setFact(facts, .sequential_routed_requests_release_each_time, all_ok and
        wire_proxy.testing.reservationOutstanding(listener) == 0 and
        alternate.snapshot().call_count == iterations);
}

// ===========================================================================
// TIN-1790 shared-core adapter mapping OBSERVATION. These cases use only the
// optional in-process broker snapshot and deterministic fake upstreams. Every
// positive route choice has a nearby input mutation that must change or suppress
// selection, preventing a hardcoded fake slot from producing green evidence.
// ===========================================================================

const BrokerMappingRun = struct {
    ok: bool,
    bad_gateway: bool,
    server_error: bool,
    primary_attempts: usize,
    primary_calls: usize,
    alternate_attempts: usize,
    alternate_calls: usize,
    attempts_total: usize,
    alternate_count: usize,
    admitted_model_exact: bool,
    primary_body_exact: bool,
    alternate_body_exact: bool,
    server_error_event_exact: bool,
    events_value_free: bool,

    fn selectedOnly(self: BrokerMappingRun, slot: enum { primary, alternate }) bool {
        if (!self.ok or self.attempts_total != 1 or self.alternate_count != 0) return false;
        return switch (slot) {
            .primary => self.primary_attempts == 1 and self.primary_calls == 1 and
                self.alternate_attempts == 0 and self.alternate_calls == 0,
            .alternate => self.primary_attempts == 0 and self.primary_calls == 0 and
                self.alternate_attempts == 1 and self.alternate_calls == 1,
        };
    }

    fn refusedBeforeUpstream(self: BrokerMappingRun) bool {
        return self.bad_gateway and self.primary_attempts == 0 and
            self.primary_calls == 0 and self.alternate_attempts == 0 and
            self.alternate_calls == 0 and self.attempts_total == 0;
    }

    fn failedOnly(self: BrokerMappingRun, slot: enum { primary, alternate }) bool {
        if (!self.server_error or self.attempts_total != 1 or self.alternate_count != 0) return false;
        return switch (slot) {
            .primary => self.primary_attempts == 1 and self.primary_calls == 1 and
                self.alternate_attempts == 0 and self.alternate_calls == 0,
            .alternate => self.primary_attempts == 0 and self.primary_calls == 0 and
                self.alternate_attempts == 1 and self.alternate_calls == 1,
        };
    }
};

const broker_mapping_primary_bearer = "lease-redaction-token-z-canary";
const broker_mapping_alternate_bearer = "lease-redaction-token-a-canary";
const broker_server_error_event = "{\"kind\":\"claude_proxy_upstream_server_error\"}\n";

fn brokerRouteHandle(text: []const u8) broker_route_observation.RouteHandle {
    return broker_route_observation.RouteHandle.parse(text) catch unreachable;
}

fn brokerRouteObservation(
    route_text: []const u8,
    identity: []const u8,
    admission: broker_route_observation.RouteAdmission,
    readiness: broker_route_observation.Readiness,
) broker_route_observation.RouteObservation {
    return brokerRouteObservationForModel(
        route_text,
        identity,
        routed_model,
        admission,
        readiness,
    );
}

fn brokerRouteObservationForModel(
    route_text: []const u8,
    identity: []const u8,
    model: []const u8,
    admission: broker_route_observation.RouteAdmission,
    readiness: broker_route_observation.Readiness,
) broker_route_observation.RouteObservation {
    return .{
        .route = brokerRouteHandle(route_text),
        .identity = broker_route_observation.IdentityEvidence.fromBorrowed(identity),
        .exact_model = broker_model_demand.ExactModel.init(model) catch unreachable,
        .admission = admission,
        .reactive = switch (readiness) {
            .available, .exhausted => .{
                .readiness = readiness,
                .resets_at_s = 200,
            },
            .unknown => null,
        },
    };
}

fn brokerSnapshot(
    observations: []const broker_route_observation.RouteObservation,
    projection: broker_lease_state.Projection,
) wire_proxy.testing.BrokerSnapshot {
    return brokerSnapshotForRoutes(
        "route-z",
        "route-a",
        observations,
        projection,
    );
}

fn brokerSnapshotForRoutes(
    primary_route: []const u8,
    alternate_route: []const u8,
    observations: []const broker_route_observation.RouteObservation,
    projection: broker_lease_state.Projection,
) wire_proxy.testing.BrokerSnapshot {
    return .{
        .now_s = 100,
        .primary_route = brokerRouteHandle(primary_route),
        .alternate_route = brokerRouteHandle(alternate_route),
        .observations = observations,
        .lease_projection = projection,
    };
}

fn runBrokerMappedRequest(
    snapshot: wire_proxy.testing.BrokerSnapshot,
    primary_response: fake_upstream_mod.ScriptedResponse,
    alternate_response: fake_upstream_mod.ScriptedResponse,
) !BrokerMappingRun {
    return runBrokerMappedRequestBody(
        snapshot,
        routed_json,
        routed_model,
        &.{},
        primary_response,
        alternate_response,
    );
}

fn runBrokerMappedRequestBody(
    snapshot: wire_proxy.testing.BrokerSnapshot,
    request_body: []const u8,
    expected_model: []const u8,
    event_canaries: []const []const u8,
    primary_response: fake_upstream_mod.ScriptedResponse,
    alternate_response: fake_upstream_mod.ScriptedResponse,
) !BrokerMappingRun {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const primary_script = [_]fake_upstream_mod.ScriptedResponse{primary_response};
    const alternate_script = [_]fake_upstream_mod.ScriptedResponse{alternate_response};
    var primary = try FakeUpstream.start(std.testing.allocator, &primary_script);
    defer primary.deinit();
    var alternate = try FakeUpstream.start(std.testing.allocator, &alternate_script);
    defer alternate.deinit();

    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try wire_proxy.testing.startWithRoutes(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{
            .primary = .{
                .upstream = &primary,
                .bearer = broker_mapping_primary_bearer,
                .identity = "fake-slot-z",
            },
            .alternate = .{
                .upstream = &alternate,
                .bearer = broker_mapping_alternate_bearer,
                .identity = "fake-slot-a",
            },
            .broker_snapshot = snapshot,
        },
    );
    defer listener.deinit();

    const response = try routedRequestBody(listener, &carrier, request_body);
    defer std.testing.allocator.free(response);
    const observation = wire_proxy.testing.requestObservation(listener);
    var primary_body: [1024]u8 = undefined;
    const primary_body_len = primary.capturedRequestBody(&primary_body);
    var alternate_body: [1024]u8 = undefined;
    const alternate_body_len = alternate.capturedRequestBody(&alternate_body);
    const events = event_stream.getWritten();
    var events_value_free = true;
    for (event_canaries) |canary| {
        if (std.mem.indexOf(u8, events, canary) != null) events_value_free = false;
    }
    const primary_snapshot = primary.snapshot();
    const alternate_snapshot = alternate.snapshot();
    return .{
        .ok = hasStatus(response, "200 OK"),
        .bad_gateway = hasStatus(response, "502 Bad Gateway"),
        .server_error = hasStatus(response, "500 Internal Server Error"),
        .primary_attempts = primary_snapshot.attempt_count,
        .primary_calls = primary_snapshot.call_count,
        .alternate_attempts = alternate_snapshot.attempt_count,
        .alternate_calls = alternate_snapshot.call_count,
        .attempts_total = observation.attempts_total,
        .alternate_count = observation.alternate_count,
        .admitted_model_exact = observation.model_present and
            std.mem.eql(
                u8,
                expected_model,
                observation.admitted_model_buf[0..observation.admitted_model_len],
            ),
        .primary_body_exact = std.mem.eql(u8, request_body, primary_body[0..primary_body_len]),
        .alternate_body_exact = std.mem.eql(u8, request_body, alternate_body[0..alternate_body_len]),
        .server_error_event_exact = std.mem.eql(u8, events, broker_server_error_event),
        .events_value_free = events_value_free,
    };
}

fn brokerAcquireInput(
    lease_text: []const u8,
    session_text: []const u8,
    account_text: []const u8,
    route_text: []const u8,
    owner_pid: broker_lease_state.OwnerPid,
    expected_revision: broker_lease_state.Revision,
    selected_at_ms: i64,
    expires_at_ms: i64,
) !broker_lease_state.AcquireInput {
    return .{
        .lease = try broker_lease_state.LeaseHandle.parse(lease_text),
        .session = try broker_lease_state.SessionHandle.parse(session_text),
        .account = try broker_lease_state.AccountHandle.parse(account_text),
        .route = try broker_lease_state.RouteHandle.parse(route_text),
        .exact_model = try broker_model_demand.ExactModel.init(routed_model),
        .owner_pid = owner_pid,
        .expected_revision = expected_revision,
        .now_ms = selected_at_ms,
        .selected_at_ms = selected_at_ms,
        .heartbeat_at_ms = selected_at_ms,
        .expires_at_ms = expires_at_ms,
    };
}

fn runBrokerMappingScenario(facts: []Fact) !void {
    if (wire_proxy.production_forwarding_enabled) {
        return error.ProductionForwardingUnexpectedlyEnabled;
    }
    const ok = fake_upstream_mod.ScriptedResponse{ .status = .ok, .body = "ok" };

    // The mapped demand must come from the admitted request bytes. A distinct
    // exact model reaches the selected fake byte-for-byte; changing only the
    // request model makes the same snapshot ineligible before either fake.
    const exact_model = "claude-mapping-exact-model-canary";
    const exact_body =
        "{\"model\":\"" ++ exact_model ++ "\",\"max_tokens\":17," ++
        "\"metadata\":{\"trace_id\":\"mapping-body-canary\"}}";
    const mismatch_model = "claude-mapping-mismatch-model-canary";
    const mismatch_body =
        "{\"model\":\"" ++ mismatch_model ++ "\",\"max_tokens\":17}";
    const exact_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservationForModel("route-z", "identity-z", exact_model, .admitted, .unknown),
        brokerRouteObservationForModel("route-a", "identity-a", exact_model, .admitted, .available),
    };
    const exact_selection = try runBrokerMappedRequestBody(
        brokerSnapshot(&exact_rows, broker_lease_state.missingProjection()),
        exact_body,
        exact_model,
        &.{},
        ok,
        ok,
    );
    const exact_mismatch = try runBrokerMappedRequestBody(
        brokerSnapshot(&exact_rows, broker_lease_state.missingProjection()),
        mismatch_body,
        mismatch_model,
        &.{},
        ok,
        ok,
    );
    strengthenFact(facts, .first_attempt_body_forwarded_byte_exact, exact_selection.selectedOnly(.alternate) and
        exact_selection.admitted_model_exact and
        exact_selection.alternate_body_exact and
        exact_mismatch.refusedBeforeUpstream());

    // Admission must beat readiness. Making the blocked route admitted is the
    // mutation: selection must move back to the known-good primary fake.
    var admission_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .unavailable, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const admitted = try runBrokerMappedRequest(
        brokerSnapshot(&admission_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    admission_rows[0].admission = .admitted;
    const admission_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&admission_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );

    // Dead admission remains ineligible even with known-good readiness, while
    // an admitted unknown route remains eligible. Re-admitting the dead route
    // is the mutation and must move the wire call to the primary fake.
    var dead_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .dead, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const dead = try runBrokerMappedRequest(
        brokerSnapshot(&dead_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    dead_rows[0].admission = .admitted;
    const dead_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&dead_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    setFact(facts, .route_identity_admission, admitted.selectedOnly(.alternate) and
        admission_mutation.selectedOnly(.primary) and
        dead.selectedOnly(.alternate) and
        dead_mutation.selectedOnly(.primary));

    // Duplicate exact-model identities fail before either fake. Distinguishing
    // the second opaque identity is the mutation and must restore one route.
    var identity_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-shared", .admitted, .available),
        brokerRouteObservation("route-a", "identity-shared", .admitted, .available),
    };
    const identity_conflict = try runBrokerMappedRequest(
        brokerSnapshot(&identity_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    identity_rows[1].identity = broker_route_observation.IdentityEvidence.fromBorrowed("identity-a");
    const identity_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&identity_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    setFact(facts, .identity_conflict_fail_closed, identity_conflict.refusedBeforeUpstream() and identity_mutation.selectedOnly(.alternate));

    // Known-good outranks unknown; swapping readiness swaps the fake. With both
    // known-good, reversing input rows still elects the lower opaque handle.
    var readiness_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .unknown),
        brokerRouteObservation("route-a", "identity-a", .admitted, .available),
    };
    const readiness = try runBrokerMappedRequest(
        brokerSnapshot(&readiness_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    readiness_rows[0].reactive = readiness_rows[1].reactive;
    readiness_rows[1].reactive = null;
    const readiness_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&readiness_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    readiness_rows[1].reactive = readiness_rows[0].reactive;
    const reversed_readiness = [_]broker_route_observation.RouteObservation{
        readiness_rows[1],
        readiness_rows[0],
    };
    const ordering = try runBrokerMappedRequest(
        brokerSnapshot(&reversed_readiness, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    setFact(facts, .route_readiness_ordering, readiness.selectedOnly(.alternate) and
        readiness_mutation.selectedOnly(.primary) and
        ordering.selectedOnly(.alternate));

    // Route a real request through a complete lease projection and force a
    // value-free event. The load mutation must switch the only contacted fake,
    // while neither event may contain a route, identity, lease fact, synthetic
    // bearer, model, or request prompt canary.
    const redaction_primary_handle = "lease-redaction-route-z-canary";
    const redaction_alternate_handle = "lease-redaction-route-a-canary";
    const redaction_primary_identity = "lease-redaction-identity-z-canary";
    const redaction_alternate_identity = "lease-redaction-identity-a-canary";
    const redaction_model = "claude-lease-redaction-model-canary";
    const redaction_prompt = "lease-session-prompt-canary";
    const redaction_body =
        "{\"model\":\"" ++ redaction_model ++ "\",\"max_tokens\":16," ++
        "\"messages\":[{\"role\":\"user\",\"content\":\"" ++ redaction_prompt ++ "\"}]}";
    const redaction_observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservationForModel(
            redaction_primary_handle,
            redaction_primary_identity,
            redaction_model,
            .admitted,
            .available,
        ),
        brokerRouteObservationForModel(
            redaction_alternate_handle,
            redaction_alternate_identity,
            redaction_model,
            .admitted,
            .available,
        ),
    };
    var redaction_lease_rows = [_]broker_decision.LeaseObservation{
        .{
            .route = brokerRouteHandle(redaction_primary_handle),
            .active_leases = 0,
            .last_selected_at = 313371234,
        },
        .{
            .route = brokerRouteHandle(redaction_alternate_handle),
            .active_leases = 42424291,
            .last_selected_at = 313371235,
        },
    };
    const redaction_canaries = [_][]const u8{
        redaction_primary_handle,
        redaction_alternate_handle,
        redaction_primary_identity,
        redaction_alternate_identity,
        redaction_model,
        redaction_prompt,
        broker_mapping_primary_bearer,
        broker_mapping_alternate_bearer,
        "42424290",
        "42424291",
        "313371234",
    };
    const server_error = fake_upstream_mod.ScriptedResponse{
        .status = .internal_server_error,
        .body = "redaction-error",
    };
    const redaction = try runBrokerMappedRequestBody(
        brokerSnapshotForRoutes(
            redaction_primary_handle,
            redaction_alternate_handle,
            &redaction_observations,
            .{
                .revision = 42424290,
                .quality = .complete,
                .view = .{ .routes = &redaction_lease_rows },
            },
        ),
        redaction_body,
        redaction_model,
        &redaction_canaries,
        server_error,
        server_error,
    );
    redaction_lease_rows[0].active_leases = 42424292;
    redaction_lease_rows[1].active_leases = 0;
    const redaction_mutation = try runBrokerMappedRequestBody(
        brokerSnapshotForRoutes(
            redaction_primary_handle,
            redaction_alternate_handle,
            &redaction_observations,
            .{
                .revision = 42424290,
                .quality = .complete,
                .view = .{ .routes = &redaction_lease_rows },
            },
        ),
        redaction_body,
        redaction_model,
        &redaction_canaries,
        server_error,
        server_error,
    );
    setFact(facts, .lease_state_redaction, wire_proxy.testing.brokerLeaseProjectionIsRedacted() and
        wire_proxy.testing.brokerLeaseProjectionRejectsLeakyShape() and
        redaction.failedOnly(.primary) and
        redaction.admitted_model_exact and
        redaction.primary_body_exact and
        redaction.server_error_event_exact and
        redaction.events_value_free and
        redaction_mutation.failedOnly(.alternate) and
        redaction_mutation.admitted_model_exact and
        redaction_mutation.alternate_body_exact and
        redaction_mutation.server_error_event_exact and
        redaction_mutation.events_value_free);

    const lease_route_rows = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .available),
    };

    // Build the stale case through the actual Group 2 in-process state. The
    // expired route-z owner has unknown liveness and is absent from projected
    // load while live route-a contributes one. A proven-live owner would remain
    // sticky beyond this timestamp. Reintroducing stale load is the mutation.
    var lease_state = broker_lease_state.LeaseState(2, 2).init();
    const demand = try broker_model_demand.ModelDemand.init(routed_model);
    try lease_state.registerRoute(.{
        .route = brokerRouteHandle("route-z"),
        .exact_model = demand.exact_model,
    });
    try lease_state.registerRoute(.{
        .route = brokerRouteHandle("route-a"),
        .exact_model = demand.exact_model,
    });
    const owners = [_]broker_lease_state.OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
        .{ .owner_pid = 2, .liveness = .alive },
    };
    const projected_owners = [_]broker_lease_state.OwnerObservation{
        .{ .owner_pid = 1, .liveness = .alive },
    };
    _ = try lease_state.acquire(try brokerAcquireInput(
        "lease-a",
        "session-a",
        "account-a",
        "route-a",
        1,
        lease_state.currentRevision(),
        1,
        100,
    ), &owners);
    _ = try lease_state.acquire(try brokerAcquireInput(
        "lease-z",
        "session-z",
        "account-z",
        "route-z",
        2,
        lease_state.currentRevision(),
        2,
        10,
    ), &owners);
    var stale_scratch: [2]broker_decision.LeaseObservation = undefined;
    const stale_projection = try lease_state.project(
        try broker_lease_state.SessionHandle.parse("session-observer"),
        demand,
        20,
        &projected_owners,
        &stale_scratch,
    );
    const stale = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, stale_projection),
        ok,
        ok,
    );
    const stale_retained_rows = [_]broker_decision.LeaseObservation{
        .{ .route = brokerRouteHandle("route-z"), .active_leases = 2, .last_selected_at = 2 },
        .{ .route = brokerRouteHandle("route-a"), .active_leases = 1, .last_selected_at = 1 },
    };
    const stale_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, .{
            .revision = stale_projection.revision,
            .quality = .complete,
            .view = .{ .routes = &stale_retained_rows },
        }),
        ok,
        ok,
    );
    setFact(facts, .stale_lease_reactive_routing, stale.selectedOnly(.primary) and stale_mutation.selectedOnly(.alternate));

    // Missing/unavailable lease state is the Group 2 empty advisory view and
    // cannot block route election. A complete projection with unequal load is
    // the mutation proving the adapter actually consumes lease ranking.
    const unavailable = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, broker_lease_state.missingProjection()),
        ok,
        ok,
    );
    const complete_rows = [_]broker_decision.LeaseObservation{
        .{ .route = brokerRouteHandle("route-z"), .active_leases = 0, .last_selected_at = null },
        .{ .route = brokerRouteHandle("route-a"), .active_leases = 1, .last_selected_at = null },
    };
    const unavailable_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, .{
            .revision = 1,
            .quality = .complete,
            .view = .{ .routes = &complete_rows },
        }),
        ok,
        ok,
    );
    setFact(facts, .unavailable_lease_reactive_routing, unavailable.selectedOnly(.alternate) and unavailable_mutation.selectedOnly(.primary));

    // Sticky route-a wins despite higher load, then its pre-body failure causes
    // the same reducer to exclude attempt 1 and elect route-z exactly once. With
    // stickiness removed, least-loaded route-z is selected first; reversing the
    // loads moves selection back to route-a.
    const sticky_projection = broker_lease_state.Projection{
        .revision = 2,
        .quality = .complete,
        .view = .{
            .sticky_route = brokerRouteHandle("route-a"),
            .routes = &complete_rows,
        },
    };
    const sticky = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, sticky_projection),
        ok,
        .{ .status = .unauthorized, .body = "denied" },
    );
    const least_loaded = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, .{
            .revision = 3,
            .quality = .complete,
            .view = .{ .routes = &complete_rows },
        }),
        ok,
        ok,
    );
    const reversed_load_rows = [_]broker_decision.LeaseObservation{
        .{ .route = brokerRouteHandle("route-z"), .active_leases = 2, .last_selected_at = null },
        .{ .route = brokerRouteHandle("route-a"), .active_leases = 1, .last_selected_at = null },
    };
    const load_mutation = try runBrokerMappedRequest(
        brokerSnapshot(&lease_route_rows, .{
            .revision = 4,
            .quality = .complete,
            .view = .{ .routes = &reversed_load_rows },
        }),
        ok,
        ok,
    );
    setFact(facts, .sticky_least_loaded_selection, sticky.ok and sticky.primary_calls == 1 and sticky.alternate_calls == 1 and
        sticky.attempts_total == 2 and sticky.alternate_count == 1 and
        least_loaded.selectedOnly(.primary) and load_mutation.selectedOnly(.alternate));
}

const LeaseChildReport = extern struct {
    selected_slot: u8 = 0,
    exact_model_preserved: u8 = 0,
    exactly_one_fake: u8 = 0,
    reprojected: u8 = 0,
    pre_projection_present: u8 = 0,
    pre_route_z_load: u16 = 0,
    pre_route_a_load: u16 = 0,
    pid: u32 = 0,
    incarnation: u64 = 0,
    generation: u64 = 0,
};

const SpawnedLeaseChild = struct {
    process: std.process.Child,
};

const lease_child_deadline_ns: u64 = 5 * std.time.ns_per_s;

const LeaseChildMode = enum {
    once,
    revision,
    hold,
    wedge,

    fn text(self: LeaseChildMode) []const u8 {
        return switch (self) {
            .once => "once",
            .revision => "revision",
            .hold => "hold",
            .wedge => "wedge",
        };
    }
};

const LeaseAdmissionHookContext = struct {
    root: []const u8,

    fn run(raw: *anyopaque) !void {
        const self: *LeaseAdmissionHookContext = @ptrCast(@alignCast(raw));
        try writeLeaseGate(self.root, "revision-ready");
        try waitForLeaseGate(self.root, "revision-continue");
    }
};

fn requestedLeaseTime(
    _: ?*const anyopaque,
    requested_ms: ?broker_lease_state.TimestampMs,
) !broker_lease_state.TimestampMs {
    return requested_ms orelse 0;
}

fn leaseRuntimeOptions(hook: ?broker_lease_runtime.AdmissionHook) broker_lease_runtime.Options {
    return .{
        .store = .{ .time = .{ .read = requestedLeaseTime } },
        .before_first_admission = hook,
    };
}

fn leaseRuntimeAttemptOptions(
    hook: broker_lease_runtime.AdmissionHook,
) broker_lease_runtime.Options {
    return .{
        .store = .{ .time = .{ .read = requestedLeaseTime } },
        .before_admission_attempt = hook,
    };
}

fn runLeaseChildFallible(
    root: []const u8,
    report_fd: std.posix.fd_t,
    with_hook: bool,
    hold_forever: bool,
) !void {
    const allocator = std.heap.page_allocator;
    var hook_context: LeaseAdmissionHookContext = undefined;
    const hook: ?broker_lease_runtime.AdmissionHook = if (with_hook) .{
        .ctx = @ptrCast(&hook_context),
        .run = LeaseAdmissionHookContext.run,
    } else null;
    if (with_hook) hook_context = .{ .root = root };

    var runtime = broker_lease_runtime.LeaseRuntime.init(
        allocator,
        root,
        leaseRuntimeOptions(hook),
    ) catch return error.LeaseChildRuntimeInitFailed;
    var runtime_live = true;
    defer if (runtime_live) runtime.deinit();
    const owner = runtime.ownerIdentityForTest();
    const demand = try broker_model_demand.ModelDemand.init(routed_model);
    const preloads = try projectedRuntimeLoadsForProof(&runtime, demand, 100_000);

    const capability = try SessionCapability.generate(allocator);
    var capability_live = true;
    defer if (capability_live) capability.deinit();
    var carrier = try copyCarrier(capability);
    var carrier_live = true;
    defer if (carrier_live) std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "ok" }});
    var primary_live = true;
    defer if (primary_live) primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "ok" }});
    var alternate_live = true;
    defer if (alternate_live) alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .available),
    };
    const listener = wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .bearer = "synthetic-z", .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .bearer = "synthetic-a", .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    ) catch return error.LeaseChildListenerStartFailed;
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const response = routedRequestBody(listener, &carrier, routed_json) catch
        return error.LeaseChildRequestFailed;
    defer std.testing.allocator.free(response);
    if (!hasStatus(response, "200 OK")) return error.LeaseChildRequestFailed;
    const primary_snapshot = primary.snapshot();
    const alternate_snapshot = alternate.snapshot();
    const observation = wire_proxy.testing.requestObservation(listener);
    var primary_body: [1024]u8 = undefined;
    const primary_len = primary.capturedRequestBody(&primary_body);
    var alternate_body: [1024]u8 = undefined;
    const alternate_len = alternate.capturedRequestBody(&alternate_body);
    const selected_slot: u8 = if (primary_snapshot.call_count == 1 and alternate_snapshot.call_count == 0)
        'z'
    else if (primary_snapshot.call_count == 0 and alternate_snapshot.call_count == 1)
        'a'
    else
        0;
    const selected_body = if (selected_slot == 'z') primary_body[0..primary_len] else alternate_body[0..alternate_len];
    var report = LeaseChildReport{
        .selected_slot = selected_slot,
        .exact_model_preserved = @intFromBool(observation.model_present and
            std.mem.eql(u8, observation.admitted_model_buf[0..observation.admitted_model_len], routed_model) and
            std.mem.eql(u8, selected_body, routed_json)),
        .exactly_one_fake = @intFromBool(primary_snapshot.call_count + alternate_snapshot.call_count == 1),
        .reprojected = @intFromBool(runtime.reprojectionCount() != 0),
        .pre_projection_present = @intFromBool(preloads != null),
        .pre_route_z_load = @intCast(if (preloads) |loads| loads[0] else 0),
        .pre_route_a_load = @intCast(if (preloads) |loads| loads[1] else 0),
        .pid = owner.pid,
        .incarnation = owner.incarnation,
        .generation = owner.generation,
    };
    if (hold_forever) {
        writeAllFd(report_fd, std.mem.asBytes(&report)) catch
            return error.LeaseChildReportFailed;
        var parked = std.atomic.Value(u32).init(0);
        while (true) std.Thread.Futex.wait(&parked, 0);
    }

    listener.deinit();
    listener_live = false;
    alternate.deinit();
    alternate_live = false;
    primary.deinit();
    primary_live = false;
    std.crypto.secureZero(u8, &carrier);
    carrier_live = false;
    capability.deinit();
    capability_live = false;
    runtime.deinit();
    runtime_live = false;
    writeAllFd(report_fd, std.mem.asBytes(&report)) catch
        return error.LeaseChildReportFailed;
}

pub fn runLeaseChildSubprocessIfRequested() !bool {
    const allocator = std.testing.allocator;
    const root = std.process.getEnvVarOwned(allocator, "OMUX_STAGE2_LEASE_CHILD_ROOT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(root);
    const mode = try std.process.getEnvVarOwned(allocator, "OMUX_STAGE2_LEASE_CHILD_MODE");
    defer allocator.free(mode);
    const child_mode: LeaseChildMode = if (std.mem.eql(u8, mode, "revision"))
        .revision
    else if (std.mem.eql(u8, mode, "hold"))
        .hold
    else if (std.mem.eql(u8, mode, "once"))
        .once
    else if (std.mem.eql(u8, mode, "wedge"))
        .wedge
    else
        return error.InvalidLeaseChildMode;
    if (child_mode == .wedge) {
        var parked = std.atomic.Value(u32).init(0);
        while (true) std.Thread.Futex.wait(&parked, 0);
    }
    const stdout = std.io.getStdOut();
    runLeaseChildFallible(
        root,
        stdout.handle,
        child_mode == .revision,
        child_mode == .hold,
    ) catch |err| {
        std.debug.print("local lease child diagnostic: {s}\n", .{@errorName(err)});
        std.process.exit(91);
    };
    std.process.exit(0);
}

fn spawnLeaseChild(root: []const u8, with_hook: bool, hold_forever: bool) !SpawnedLeaseChild {
    return spawnLeaseChildMode(
        root,
        if (with_hook) .revision else if (hold_forever) .hold else .once,
    );
}

fn spawnLeaseChildMode(root: []const u8, mode: LeaseChildMode) !SpawnedLeaseChild {
    const allocator = std.testing.allocator;
    const executable = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable);
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("OMUX_STAGE2_LEASE_CHILD_ROOT", root);
    try env_map.put("OMUX_STAGE2_LEASE_CHILD_MODE", mode.text());
    const argv = [_][]const u8{executable};
    var process = std.process.Child.init(&argv, allocator);
    process.stdin_behavior = .Ignore;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Inherit;
    process.env_map = &env_map;
    try process.spawn();
    return .{ .process = process };
}

fn readLeaseChildReport(child: *SpawnedLeaseChild) !LeaseChildReport {
    return readLeaseChildReportWithin(child, lease_child_deadline_ns);
}

fn readLeaseChildReportWithin(
    child: *SpawnedLeaseChild,
    timeout_ns: u64,
) !LeaseChildReport {
    var report = std.mem.zeroes(LeaseChildReport);
    var watchdog = LeaseChildWatchdog{ .child = &child.process, .timeout_ns = timeout_ns };
    const watchdog_thread = try std.Thread.spawn(.{}, LeaseChildWatchdog.run, .{&watchdog});
    const read_result: anyerror!void = readExactFd(
        child.process.stdout.?.handle,
        std.mem.asBytes(&report),
    );
    watchdog.done.set();
    watchdog_thread.join();
    if (watchdog.timed_out.load(.acquire)) return error.LeaseChildReportTimeout;
    try read_result;
    return report;
}

fn finishLeaseChild(child: *SpawnedLeaseChild) !void {
    return finishLeaseChildWithin(child, lease_child_deadline_ns);
}

fn finishLeaseChildWithin(child: *SpawnedLeaseChild, timeout_ns: u64) !void {
    var watchdog = LeaseChildWatchdog{ .child = &child.process, .timeout_ns = timeout_ns };
    const watchdog_thread = try std.Thread.spawn(.{}, LeaseChildWatchdog.run, .{&watchdog});
    const term_result: anyerror!std.process.Child.Term = child.process.wait();
    watchdog.done.set();
    watchdog_thread.join();
    if (watchdog.timed_out.load(.acquire)) return error.LeaseChildWaitTimeout;
    const term = try term_result;
    switch (term) {
        .Exited => |code| if (code != 0) return error.LeaseChildFailed,
        else => return error.LeaseChildFailed,
    }
}

const LeaseChildWatchdog = struct {
    child: *std.process.Child,
    timeout_ns: u64,
    done: std.Thread.ResetEvent = .{},
    timed_out: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *LeaseChildWatchdog) void {
        self.done.timedWait(self.timeout_ns) catch {
            self.timed_out.store(true, .release);
            switch (builtin.os.tag) {
                .macos, .linux => std.posix.kill(self.child.id, std.posix.SIG.KILL) catch {},
                else => {},
            }
        };
    }
};

fn runLeaseChildDeadlineControl() !void {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    var tmp = try repair_state.TestRuntimeDirScope.init(allocator);
    defer tmp.deinit(allocator);
    const root = tmp.root;

    var report_wedge = try spawnLeaseChildMode(root, .wedge);
    try std.testing.expectError(
        error.LeaseChildReportTimeout,
        readLeaseChildReportWithin(&report_wedge, 200 * std.time.ns_per_ms),
    );
    _ = report_wedge.process.wait() catch {};

    var wait_wedge = try spawnLeaseChildMode(root, .hold);
    _ = try readLeaseChildReport(&wait_wedge);
    try std.testing.expectError(
        error.LeaseChildWaitTimeout,
        finishLeaseChildWithin(&wait_wedge, 200 * std.time.ns_per_ms),
    );
}

fn killLeaseChild(child: *SpawnedLeaseChild) void {
    _ = child.process.kill() catch {
        _ = child.process.wait() catch {};
    };
}

fn readExactFd(fd: std.posix.fd_t, destination: []u8) !void {
    var offset: usize = 0;
    while (offset < destination.len) {
        const count = try std.posix.read(fd, destination[offset..]);
        if (count == 0) return error.UnexpectedEndOfStream;
        offset += count;
    }
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) offset += try std.posix.write(fd, bytes[offset..]);
}

fn leaseGatePath(allocator: std.mem.Allocator, root: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, name });
}

fn writeLeaseGate(root: []const u8, name: []const u8) !void {
    const allocator = std.heap.page_allocator;
    const path = try leaseGatePath(allocator, root, name);
    defer allocator.free(path);
    const file = try std.fs.createFileAbsolute(path, .{ .exclusive = true, .mode = 0o600 });
    defer file.close();
    try file.sync();
}

fn waitForLeaseGate(root: []const u8, name: []const u8) !void {
    const allocator = std.heap.page_allocator;
    const path = try leaseGatePath(allocator, root, name);
    defer allocator.free(path);
    var timer = try std.time.Timer.start();
    while (true) {
        std.fs.accessAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                if (timer.read() > 5 * std.time.ns_per_s) return error.LeaseGateTimeout;
                std.Thread.yield() catch {};
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn childRoot(allocator: std.mem.Allocator, parent: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ parent, name });
}

const RuntimeSelectJob = struct {
    runtime: *broker_lease_runtime.LeaseRuntime,
    candidates: []const broker_lease_runtime.Candidate,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
    result: ?broker_lease_runtime.Selection = null,
    failure: ?anyerror = null,

    fn run(self: *RuntimeSelectJob) void {
        self.result = self.runtime.selectAndAcquire(self.candidates, self.demand, self.now_ms) catch |err| {
            self.failure = err;
            return;
        };
    }
};

fn selectRuntimeForProof(
    runtime: *broker_lease_runtime.LeaseRuntime,
    candidates: []const broker_lease_runtime.Candidate,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
) !broker_lease_runtime.Selection {
    var job = RuntimeSelectJob{
        .runtime = runtime,
        .candidates = candidates,
        .demand = demand,
        .now_ms = now_ms,
    };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RuntimeSelectJob.run, .{&job});
    thread.join();
    if (job.failure) |err| return err;
    return job.result orelse error.LeaseProofSelectionMissing;
}

const RuntimeReleaseJob = struct {
    runtime: *broker_lease_runtime.LeaseRuntime,
    failure: ?anyerror = null,

    fn run(self: *RuntimeReleaseJob) void {
        self.runtime.releaseAll() catch |err| {
            self.failure = err;
        };
    }
};

fn releaseRuntimeForProof(runtime: *broker_lease_runtime.LeaseRuntime) !void {
    var job = RuntimeReleaseJob{ .runtime = runtime };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RuntimeReleaseJob.run, .{&job});
    thread.join();
    if (job.failure) |err| return err;
}

const RuntimeProjectionJob = struct {
    runtime: *broker_lease_runtime.LeaseRuntime,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
    result: ?u64 = null,

    fn run(self: *RuntimeProjectionJob) void {
        self.result = self.runtime.projectedActiveLeaseCount(self.demand, self.now_ms);
    }
};

const RuntimeRouteLoadsJob = struct {
    runtime: *broker_lease_runtime.LeaseRuntime,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
    result: ?[2]u64 = null,

    fn run(self: *RuntimeRouteLoadsJob) void {
        self.result = broker_lease_runtime.testing.projectedLoadsForRoutes(
            self.runtime,
            self.demand,
            self.now_ms,
            .{
                brokerRouteHandle("route-z"),
                brokerRouteHandle("route-a"),
            },
        );
    }
};

fn projectedRuntimeLoadsForProof(
    runtime: *broker_lease_runtime.LeaseRuntime,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
) !?[2]u64 {
    var job = RuntimeRouteLoadsJob{ .runtime = runtime, .demand = demand, .now_ms = now_ms };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RuntimeRouteLoadsJob.run, .{&job});
    thread.join();
    return job.result;
}

const RuntimeCleanupJob = struct {
    runtime: *broker_lease_runtime.LeaseRuntime,
    now_ms: broker_lease_state.TimestampMs,
    result: ?usize = null,
    failure: ?anyerror = null,

    fn run(self: *RuntimeCleanupJob) void {
        self.result = self.runtime.cleanupStale(self.now_ms) catch |err| {
            self.failure = err;
            return;
        };
    }
};

const RevisionMutationJob = struct {
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
    failure: ?anyerror = null,

    fn run(self: *RevisionMutationJob) void {
        var store = broker_lease_runtime.Store.init(
            std.heap.page_allocator,
            self.root,
            leaseRuntimeOptions(null).store,
        ) catch |err| {
            self.failure = err;
            return;
        };
        defer store.deinit();
        store.registerRoute(.{
            .route = broker_lease_state.RouteHandle.parse("route-revision-fence") catch unreachable,
            .exact_model = self.demand.exact_model,
        }) catch |err| {
            self.failure = err;
        };
    }
};

fn registerRevisionMutationForProof(
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
) !void {
    var job = RevisionMutationJob{ .root = root, .demand = demand };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RevisionMutationJob.run, .{&job});
    thread.join();
    if (job.failure) |err| return err;
}

fn cleanupRuntimeForProof(
    runtime: *broker_lease_runtime.LeaseRuntime,
    now_ms: broker_lease_state.TimestampMs,
) !usize {
    var job = RuntimeCleanupJob{ .runtime = runtime, .now_ms = now_ms };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RuntimeCleanupJob.run, .{&job});
    thread.join();
    if (job.failure) |err| return err;
    return job.result orelse error.LeaseProofCleanupMissing;
}

fn projectedRuntimeCountForProof(
    runtime: *broker_lease_runtime.LeaseRuntime,
    demand: broker_model_demand.ModelDemand,
    now_ms: broker_lease_state.TimestampMs,
) !?u64 {
    var job = RuntimeProjectionJob{ .runtime = runtime, .demand = demand, .now_ms = now_ms };
    const thread = try std.Thread.spawn(.{ .stack_size = 32 * 1024 * 1024 }, RuntimeProjectionJob.run, .{&job});
    thread.join();
    return job.result;
}

fn runCrossProcessLeaseScenario(facts: []Fact) !void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
    const allocator = std.testing.allocator;
    var tmp = try repair_state.TestRuntimeDirScope.init(allocator);
    defer tmp.deinit(allocator);
    const root = tmp.root;
    const demand = try broker_model_demand.ModelDemand.init(routed_model);

    const shared = try runSharedLeaseControl(allocator, root, demand);
    const reprojection = try runRevisionReprojectionControl(allocator, root, demand);
    const locked_fallback = try runLockedLeaseFallbackControl(allocator, root);
    const contention_races = try runLeaseContentionRaceControls(allocator, root);
    const cumulative_budget = try runCumulativeLeaseBudgetControl(allocator, root);
    const focused_diagnostics = try broker_lease_runtime.testing.runFocusedDiagnostics(root);
    const duplicate_identity = try runDuplicateSlotIdentityControl(allocator, root);
    const corrupt_snapshot = try runCorruptLeaseSnapshotControl(allocator, root);
    const idle_live_owner = try runIdleLiveOwnerControl(allocator, root, demand);
    const teardown_release = try runTeardownReleaseFailureControl(allocator, root);
    const controls = [_]struct { name: []const u8, passed: bool }{
        .{ .name = "cross_process_pressure", .passed = shared },
        .{ .name = "bounded_reprojection", .passed = reprojection },
        .{ .name = "locked_advisory_fallback", .passed = locked_fallback },
        .{ .name = "contention_race_fallback", .passed = contention_races },
        .{ .name = "cumulative_budget_deadline_separation", .passed = cumulative_budget },
        .{ .name = "mutation_sensitive_second_review", .passed = focused_diagnostics },
        .{ .name = "credential_slot_identity", .passed = duplicate_identity },
        .{ .name = "corrupt_snapshot_fail_closed", .passed = corrupt_snapshot },
        .{ .name = "idle_live_owner_sticky", .passed = idle_live_owner },
        .{ .name = "teardown_release_diagnostic", .passed = teardown_release },
    };
    var deterministic = true;
    for (controls) |control| {
        if (!control.passed) {
            std.log.err("Stage 2 shared-lease control failed: {s}", .{control.name});
            deterministic = false;
        }
    }
    setFact(facts, .deterministic_shared_leases, deterministic);
    setFact(
        facts,
        .stale_lease_owner_cleanup,
        try runStaleOwnerControl(allocator, root, demand),
    );
}

fn runSharedLeaseControl(
    allocator: std.mem.Allocator,
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
) !bool {
    const shared_root = try childRoot(allocator, root, "shared");
    defer allocator.free(shared_root);
    var shared_a = try spawnLeaseChild(shared_root, false, true);
    errdefer killLeaseChild(&shared_a);
    const report_a = try readLeaseChildReport(&shared_a);
    var shared_b = try spawnLeaseChild(shared_root, false, false);
    errdefer killLeaseChild(&shared_b);
    const report_b = try readLeaseChildReport(&shared_b);
    try finishLeaseChild(&shared_b);
    killLeaseChild(&shared_a);

    const shared_observer = try allocator.create(broker_lease_runtime.LeaseRuntime);
    shared_observer.* = broker_lease_runtime.LeaseRuntime.init(
        allocator,
        shared_root,
        leaseRuntimeOptions(null),
    ) catch |err| {
        allocator.destroy(shared_observer);
        return err;
    };
    defer {
        shared_observer.deinit();
        allocator.destroy(shared_observer);
    }
    const shared_removed = try cleanupRuntimeForProof(shared_observer, 100_010);
    const shared_clean = try projectedRuntimeCountForProof(shared_observer, demand, 100_011) == 0;

    const isolated_a_root = try childRoot(allocator, root, "isolated-a");
    defer allocator.free(isolated_a_root);
    const isolated_b_root = try childRoot(allocator, root, "isolated-b");
    defer allocator.free(isolated_b_root);
    var isolated_a = try spawnLeaseChild(isolated_a_root, false, false);
    errdefer killLeaseChild(&isolated_a);
    const isolated_report_a = try readLeaseChildReport(&isolated_a);
    try finishLeaseChild(&isolated_a);
    var isolated_b = try spawnLeaseChild(isolated_b_root, false, false);
    errdefer killLeaseChild(&isolated_b);
    const isolated_report_b = try readLeaseChildReport(&isolated_b);
    try finishLeaseChild(&isolated_b);

    const shared_selected_load = if (report_a.selected_slot == 'z')
        report_b.pre_route_z_load
    else
        report_b.pre_route_a_load;
    const shared_other_load = if (report_a.selected_slot == 'z')
        report_b.pre_route_a_load
    else
        report_b.pre_route_z_load;
    const shared_pressure_mapped = report_b.pre_projection_present == 1 and
        shared_selected_load == 1 and shared_other_load == 0;
    const isolated_pressure_absent = isolated_report_a.pre_projection_present == 0 and
        isolated_report_b.pre_projection_present == 0;
    const actual_spread = sharedSelectionSpreads(report_a.selected_slot, report_b.selected_slot);
    // Targeted broken form: a load-blind second process repeats the first
    // lexical choice. The promoted fact is invalid unless this mutation fails.
    const load_blind_spread = sharedSelectionSpreads(report_a.selected_slot, report_a.selected_slot);
    return actual_spread and !load_blind_spread and
        shared_pressure_mapped and isolated_pressure_absent and
        isolated_report_a.selected_slot != 0 and
        isolated_report_a.selected_slot == isolated_report_b.selected_slot and
        report_a.exact_model_preserved == 1 and report_b.exact_model_preserved == 1 and
        isolated_report_a.exact_model_preserved == 1 and isolated_report_b.exact_model_preserved == 1 and
        report_a.exactly_one_fake == 1 and report_b.exactly_one_fake == 1 and
        shared_removed == 1 and shared_clean;
}

fn sharedSelectionSpreads(first: u8, second: u8) bool {
    return first != 0 and second != 0 and first != second;
}

fn runRevisionReprojectionControl(
    allocator: std.mem.Allocator,
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
) !bool {
    const revision_root = try childRoot(allocator, root, "revision");
    defer allocator.free(revision_root);
    var revision_child = try spawnLeaseChild(revision_root, true, false);
    errdefer killLeaseChild(&revision_child);
    try waitForLeaseGate(revision_root, "revision-ready");
    try registerRevisionMutationForProof(revision_root, demand);
    try writeLeaseGate(revision_root, "revision-continue");
    const revision_report = try readLeaseChildReport(&revision_child);
    try finishLeaseChild(&revision_child);

    return revision_report.reprojected == 1 and
        revision_report.exactly_one_fake == 1 and
        revision_report.exact_model_preserved == 1 and
        try runReprojectionLimitControl(allocator, root);
}

fn runLockedLeaseFallbackControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const locked_root = try childRoot(allocator, root, "locked-fallback");
    defer allocator.free(locked_root);
    std.fs.makeDirAbsolute(locked_root) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const log_path = try std.fs.path.join(allocator, &.{ locked_root, "lock-wait.log" });
    defer allocator.free(log_path);
    const log_file = try std.fs.createFileAbsolute(log_path, .{ .read = true, .mode = 0o600 });
    defer log_file.close();
    var options = leaseRuntimeOptions(null);
    options.store.log_file = log_file;
    options.advisory_wait = .{
        .poll_interval_ns = 0,
        .heartbeat_ns = std.time.ns_per_hour,
        .timeout_ns = 0,
    };
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, locked_root, options);
    defer runtime.deinit();

    const lock_path = try std.fs.path.join(allocator, &.{ locked_root, "broker-leases-v2.lock" });
    defer allocator.free(lock_path);
    var holder = try std.fs.createFileAbsolute(lock_path, .{ .read = true, .truncate = false, .mode = 0o600 });
    defer holder.close();
    if (!(try lock_wait.tryLockFile(holder))) return false;
    defer holder.unlock();

    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "locked-reactive" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "locked-reactive" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    return hasStatus(response, "200 OK") and
        primary.snapshot().call_count + alternate.snapshot().call_count == 1 and
        runtime.activeLeaseCount() == 0 and
        options.advisory_wait.timeout_ns == 0 and
        broker_lease_runtime.advisory_lock_timeout_ns < wire_proxy.testing.defaultRequestDeadlineNs();
}

const LeaseLockRaceHook = struct {
    root: []const u8,
    target_call: usize,
    calls: usize = 0,
    holder: ?std.fs.File = null,

    fn run(raw: *anyopaque) !void {
        const self: *LeaseLockRaceHook = @ptrCast(@alignCast(raw));
        self.calls += 1;
        if (self.calls != self.target_call) return;
        if (self.holder != null) return error.LeaseRaceHookAlreadyArmed;
        const allocator = std.heap.page_allocator;
        const path = try std.fs.path.join(allocator, &.{ self.root, "broker-leases-v2.lock" });
        defer allocator.free(path);
        var holder = try std.fs.createFileAbsolute(path, .{
            .read = true,
            .truncate = false,
            .mode = 0o600,
        });
        errdefer holder.close();
        if (!(try lock_wait.tryLockFile(holder))) return error.LeaseRaceHookLockUnavailable;
        self.holder = holder;
    }

    fn release(self: *LeaseLockRaceHook) void {
        if (self.holder) |holder| {
            holder.unlock();
            holder.close();
            self.holder = null;
        }
    }
};

fn immediateLeaseOptions() broker_lease_runtime.Options {
    var options = leaseRuntimeOptions(null);
    options.advisory_wait = .{
        .poll_interval_ns = 0,
        .heartbeat_ns = std.time.ns_per_hour,
        .timeout_ns = 0,
    };
    return options;
}

fn runLeaseContentionRaceControls(allocator: std.mem.Allocator, root: []const u8) !bool {
    return try runInitialProjectionContentionControl(allocator, root) and
        try runAlternateContentionControl(allocator, root, true) and
        try runAlternateContentionControl(allocator, root, false);
}

fn runInitialProjectionContentionControl(
    allocator: std.mem.Allocator,
    root: []const u8,
) !bool {
    const race_root = try childRoot(allocator, root, "projection-contention");
    defer allocator.free(race_root);
    var hook = LeaseLockRaceHook{ .root = race_root, .target_call = 1 };
    defer hook.release();
    var options = immediateLeaseOptions();
    options.before_projection = .{ .ctx = @ptrCast(&hook), .run = LeaseLockRaceHook.run };
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, race_root, options);
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "projection-reactive" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "unused" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    errdefer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    const passed = hasStatus(response, "200 OK") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 0 and
        runtime.activeLeaseCount() == 0 and hook.holder != null;
    hook.release();
    _ = try listener.deinitChecked();
    return passed;
}

fn runAlternateContentionControl(
    allocator: std.mem.Allocator,
    root: []const u8,
    during_projection: bool,
) !bool {
    const name = if (during_projection) "alternate-projection-contention" else "transition-contention";
    const race_root = try childRoot(allocator, root, name);
    defer allocator.free(race_root);
    var hook = LeaseLockRaceHook{ .root = race_root, .target_call = 2 };
    defer hook.release();
    var options = immediateLeaseOptions();
    if (during_projection) {
        options.before_projection = .{ .ctx = @ptrCast(&hook), .run = LeaseLockRaceHook.run };
    } else {
        options.before_admission_attempt = .{ .ctx = @ptrCast(&hook), .run = LeaseLockRaceHook.run };
    }
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, race_root, options);
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .unauthorized, .body = "route-z-exhausted" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "alternate-reactive" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    errdefer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    const observed = wire_proxy.testing.requestObservation(listener);
    const passed = hasStatus(response, "200 OK") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1 and
        observed.alternate_count == 1 and runtime.activeLeaseCount() == 1 and
        hook.holder != null;
    hook.release();
    _ = try listener.deinitChecked();
    return passed;
}

const LeaseBudgetAdvanceHook = struct {
    clock: *VirtualClock,
    amount_ns: u64,
    calls: usize = 0,

    fn run(raw: *anyopaque) !void {
        const self: *LeaseBudgetAdvanceHook = @ptrCast(@alignCast(raw));
        self.calls += 1;
        self.clock.now_ns += @intCast(self.amount_ns);
    }
};

fn runCumulativeLeaseBudgetControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    return try runExactLeaseBudgetExhaustionControl(allocator, root) and
        try runProviderTimeExcludedFromLeaseBudgetControl(allocator, root);
}

fn runExactLeaseBudgetExhaustionControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const budget_root = try childRoot(allocator, root, "cumulative-lease-budget");
    defer allocator.free(budget_root);
    var vclock = VirtualClock{};
    var hook = LeaseBudgetAdvanceHook{
        .clock = &vclock,
        .amount_ns = broker_lease_runtime.advisory_lock_timeout_ns,
    };
    var options = leaseRuntimeOptions(.{ .ctx = @ptrCast(&hook), .run = LeaseBudgetAdvanceHook.run });
    options.work_clock = vclock.leaseWorkClock();
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, budget_root, options);
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{
        .status = .too_many_requests,
        .body = "route-z-exhausted",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "budget-separated" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .request_deadline_ns = 5 * std.time.ns_per_s,
            .clock = vclock.clock(),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    const observed = wire_proxy.testing.requestObservation(listener);
    return hasStatus(response, "200 OK") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1 and
        observed.alternate_count == 1 and runtime.activeLeaseCount() == 0 and
        hook.calls == 1 and vclock.sleep_calls == 1 and
        vclock.last_sleep_ns == 5 * std.time.ns_per_s and
        vclock.now_ns == @as(i128, @intCast(broker_lease_runtime.advisory_lock_timeout_ns +
            5 * std.time.ns_per_s));
}

fn runProviderTimeExcludedFromLeaseBudgetControl(
    allocator: std.mem.Allocator,
    root: []const u8,
) !bool {
    const budget_root = try childRoot(allocator, root, "paused-lease-budget");
    defer allocator.free(budget_root);
    var vclock = VirtualClock{};
    const initial_lease_work_ns = 100 * std.time.ns_per_ms;
    var hook = LeaseBudgetAdvanceHook{
        .clock = &vclock,
        .amount_ns = initial_lease_work_ns,
    };
    var options = leaseRuntimeOptions(.{ .ctx = @ptrCast(&hook), .run = LeaseBudgetAdvanceHook.run });
    options.work_clock = vclock.leaseWorkClock();
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, budget_root, options);
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{
        .status = .too_many_requests,
        .body = "route-z-exhausted",
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
    }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "budget-paused" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .request_deadline_ns = 5 * std.time.ns_per_s,
            .clock = vclock.clock(),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    const demand = try broker_model_demand.ModelDemand.init(routed_model);
    const loads = try projectedRuntimeLoadsForProof(&runtime, demand, 100_000);
    return hasStatus(response, "200 OK") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 1 and
        runtime.activeLeaseCount() == 1 and hook.calls == 1 and
        vclock.sleep_calls == 1 and vclock.last_sleep_ns == 5 * std.time.ns_per_s and
        vclock.now_ns == @as(i128, initial_lease_work_ns + 5 * std.time.ns_per_s) and
        loads != null and loads.?[0] == 0 and loads.?[1] == 1;
}

fn runDuplicateSlotIdentityControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const identity_root = try childRoot(allocator, root, "duplicate-slot-identity");
    defer allocator.free(identity_root);
    var runtime = try broker_lease_runtime.LeaseRuntime.init(
        allocator,
        identity_root,
        leaseRuntimeOptions(null),
    );
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .unauthorized, .body = "account-a-exhausted" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "must-not-run" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-shared", .admitted, .available),
        brokerRouteObservation("route-a", "identity-claimed-distinct", .admitted, .unknown),
    };
    const demand = try broker_model_demand.ModelDemand.init(routed_model);
    const seed_candidates = [_]broker_lease_runtime.Candidate{
        .{
            .observation = observations[0],
            .account = try broker_lease_state.AccountHandle.parse("account-z"),
        },
        .{
            .observation = observations[1],
            .account = try broker_lease_state.AccountHandle.parse("account-a"),
        },
    };
    const seeded = try selectRuntimeForProof(&runtime, &seed_candidates, demand, 100_000);
    if (!std.mem.eql(u8, seeded.route().text, "route-z")) return false;
    const before = try broker_lease_runtime.testing.snapshotBytesAlloc(&runtime, allocator);
    defer allocator.free(before);
    var events = std.ArrayList(u8).init(allocator);
    defer events.deinit();
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        events.writer().any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-shared" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-shared" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    const observed = wire_proxy.testing.requestObservation(listener);
    const after = try broker_lease_runtime.testing.snapshotBytesAlloc(&runtime, allocator);
    defer allocator.free(after);
    return hasStatus(response, "401 Unauthorized") and
        primary.snapshot().call_count == 1 and alternate.snapshot().call_count == 0 and
        observed.same_identity_alternate_refused and observed.alternate_count == 0 and
        runtime.activeLeaseCount() == 1 and std.mem.eql(u8, before, after);
}

fn runCorruptLeaseSnapshotControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const corrupt_root = try childRoot(allocator, root, "corrupt-snapshot");
    defer allocator.free(corrupt_root);
    var runtime = try broker_lease_runtime.LeaseRuntime.init(
        allocator,
        corrupt_root,
        leaseRuntimeOptions(null),
    );
    defer runtime.deinit();
    const state_path = try std.fs.path.join(allocator, &.{ corrupt_root, "broker-leases-v2.json" });
    defer allocator.free(state_path);
    const state = try std.fs.createFileAbsolute(state_path, .{ .truncate = true, .mode = 0o600 });
    try state.writeAll("{malformed-lease-state}");
    state.close();

    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "must-not-run" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "must-not-run" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    return hasStatus(response, "502 Bad Gateway") and
        primary.snapshot().isZero() and alternate.snapshot().isZero() and
        runtime.activeLeaseCount() == 0;
}

fn runIdleLiveOwnerControl(
    allocator: std.mem.Allocator,
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
) !bool {
    const idle_root = try childRoot(allocator, root, "idle-live-owner");
    defer allocator.free(idle_root);
    var runtime = try broker_lease_runtime.LeaseRuntime.init(
        allocator,
        idle_root,
        leaseRuntimeOptions(null),
    );
    defer runtime.deinit();
    const candidates = [_]broker_lease_runtime.Candidate{
        .{
            .observation = brokerRouteObservation("route-z", "identity-z", .admitted, .available),
            .account = try broker_lease_state.AccountHandle.parse("account-z"),
        },
        .{
            .observation = brokerRouteObservation("route-a", "identity-a", .admitted, .available),
            .account = try broker_lease_state.AccountHandle.parse("account-a"),
        },
    };
    const initial = try selectRuntimeForProof(&runtime, &candidates, demand, 100_000);
    const after_idle = try selectRuntimeForProof(&runtime, &candidates, demand, 220_001);
    return initial.persisted and after_idle.persisted and
        std.mem.eql(u8, initial.route().text, after_idle.route().text) and
        runtime.activeLeaseCount() == 1 and
        try projectedRuntimeCountForProof(&runtime, demand, 220_001) == 1;
}

const ArmedPostRenameFailure = struct {
    armed: bool = false,

    fn run(raw: *anyopaque) !void {
        const self: *ArmedPostRenameFailure = @ptrCast(@alignCast(raw));
        if (self.armed) return error.InjectedPostRenameFailure;
    }
};

fn runTeardownReleaseFailureControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const teardown_root = try childRoot(allocator, root, "teardown-release-failure");
    defer allocator.free(teardown_root);
    var failure = ArmedPostRenameFailure{};
    var options = leaseRuntimeOptions(null);
    options.store.post_rename_hook = .{
        .ctx = @ptrCast(&failure),
        .run = ArmedPostRenameFailure.run,
    };
    var runtime = try broker_lease_runtime.LeaseRuntime.init(allocator, teardown_root, options);
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "release-proof" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "unused" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    var events = std.ArrayList(u8).init(allocator);
    defer events.deinit();
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        events.writer().any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    failure.armed = true;
    const failed_closed = if (listener.deinitChecked()) |_| false else |err| err == error.LeaseReleaseFailed;
    failure.armed = false;
    return hasStatus(response, "200 OK") and failed_closed and
        std.mem.indexOf(u8, events.items, "claude_proxy_lease_release_failed") != null;
}

const ReprojectionLimitHook = struct {
    store: *broker_lease_runtime.Store,
    demand: broker_model_demand.ModelDemand,
    calls: usize = 0,

    fn run(raw: *anyopaque) !void {
        const self: *ReprojectionLimitHook = @ptrCast(@alignCast(raw));
        self.calls += 1;
        if (self.calls > 4) return;
        var route_buf: [64]u8 = undefined;
        const route = try std.fmt.bufPrint(&route_buf, "route-reprojection-limit-{d}", .{self.calls});
        try self.store.registerRoute(.{
            .route = try broker_lease_state.RouteHandle.parse(route),
            .exact_model = self.demand.exact_model,
        });
    }
};

fn runReprojectionLimitControl(allocator: std.mem.Allocator, root: []const u8) !bool {
    const limit_root = try childRoot(allocator, root, "reprojection-limit");
    defer allocator.free(limit_root);
    const demand = try broker_model_demand.ModelDemand.init(routed_model);
    var mutator = try broker_lease_runtime.Store.init(
        allocator,
        limit_root,
        leaseRuntimeOptions(null).store,
    );
    defer mutator.deinit();
    var hook = ReprojectionLimitHook{ .store = &mutator, .demand = demand };
    var runtime = try broker_lease_runtime.LeaseRuntime.init(
        allocator,
        limit_root,
        leaseRuntimeAttemptOptions(.{ .ctx = @ptrCast(&hook), .run = ReprojectionLimitHook.run }),
    );
    defer runtime.deinit();
    const capability = try SessionCapability.generate(allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var primary = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "must-not-run" }});
    defer primary.deinit();
    var alternate = try FakeUpstream.start(allocator, &.{.{ .status = .ok, .body = "must-not-run" }});
    defer alternate.deinit();
    const observations = [_]broker_route_observation.RouteObservation{
        brokerRouteObservation("route-z", "identity-z", .admitted, .available),
        brokerRouteObservation("route-a", "identity-a", .admitted, .unknown),
    };
    const listener = try wire_proxy.testing.startWithRoutes(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{
            .primary = .{ .upstream = &primary, .identity = "identity-z" },
            .alternate = .{ .upstream = &alternate, .identity = "identity-a" },
            .broker_snapshot = brokerSnapshot(&observations, broker_lease_state.missingProjection()),
            .lease_runtime = &runtime,
        },
    );
    defer listener.deinit();
    const response = try routedRequest(listener, &carrier);
    defer allocator.free(response);
    return hasStatus(response, "502 Bad Gateway") and
        primary.snapshot().isZero() and alternate.snapshot().isZero() and
        hook.calls == 4 and runtime.reprojectionCount() == 4 and
        runtime.activeLeaseCount() == 0;
}

fn runStaleOwnerControl(
    allocator: std.mem.Allocator,
    root: []const u8,
    demand: broker_model_demand.ModelDemand,
) !bool {
    const stale_root = try childRoot(allocator, root, "stale");
    defer allocator.free(stale_root);
    var stale_child = try spawnLeaseChild(stale_root, false, true);
    errdefer killLeaseChild(&stale_child);
    const stale_report = try readLeaseChildReport(&stale_child);
    const stale_owner = broker_lease_store.OwnerIdentity{
        .pid = stale_report.pid,
        .incarnation = stale_report.incarnation,
        .generation = stale_report.generation,
    };
    const stale_observer = try allocator.create(broker_lease_runtime.LeaseRuntime);
    stale_observer.* = broker_lease_runtime.LeaseRuntime.init(
        allocator,
        stale_root,
        leaseRuntimeOptions(null),
    ) catch |err| {
        allocator.destroy(stale_observer);
        return err;
    };
    defer {
        stale_observer.deinit();
        allocator.destroy(stale_observer);
    }
    const custody_before = try broker_lease_runtime.testing.ownerCustodyExists(stale_observer, stale_owner);
    const alive_removed = try cleanupRuntimeForProof(stale_observer, 100_001);
    const custody_while_alive = try broker_lease_runtime.testing.ownerCustodyExists(stale_observer, stale_owner);
    killLeaseChild(&stale_child);
    const dead_removed = try cleanupRuntimeForProof(stale_observer, 100_002);
    const dead_custody_removed = !(try broker_lease_runtime.testing.ownerCustodyExists(stale_observer, stale_owner));
    const repeated_removed = try cleanupRuntimeForProof(stale_observer, 100_003);
    const reclaimed = try projectedRuntimeCountForProof(stale_observer, demand, 100_004) == 0;

    const max_generation: u64 = @intCast(broker_lease_state.max_timestamp_ms);
    const replacement_incarnation = if (stale_report.incarnation < max_generation)
        stale_report.incarnation + 1
    else
        stale_report.incarnation - 1;
    const replacement_generation = if (stale_report.generation < max_generation)
        stale_report.generation + 1
    else
        stale_report.generation - 1;
    const replacement = try allocator.create(broker_lease_runtime.LeaseRuntime);
    replacement.* = broker_lease_runtime.testing.initWithOwner(
        allocator,
        stale_root,
        leaseRuntimeOptions(null),
        .{
            .pid = stale_report.pid,
            .incarnation = replacement_incarnation,
            .generation = replacement_generation,
        },
        "replacement-session",
    ) catch |err| {
        allocator.destroy(replacement);
        return err;
    };
    defer {
        replacement.deinit();
        allocator.destroy(replacement);
    }
    const replacement_started_empty = replacement.activeLeaseCount() == 0;
    const replacement_candidates = [_]broker_lease_runtime.Candidate{
        .{
            .observation = brokerRouteObservation("route-z", "identity-z", .admitted, .available),
            .account = try broker_lease_state.AccountHandle.parse("account-z"),
        },
        .{
            .observation = brokerRouteObservation("route-a", "identity-a", .admitted, .available),
            .account = try broker_lease_state.AccountHandle.parse("account-a"),
        },
    };
    const replacement_selection = try selectRuntimeForProof(
        replacement,
        &replacement_candidates,
        demand,
        100_005,
    );
    const replacement_fresh = replacement_selection.persisted and replacement.activeLeaseCount() == 1;
    try releaseRuntimeForProof(replacement);
    const replacement_clean = try projectedRuntimeCountForProof(replacement, demand, 100_006) == 0;
    const actual_cleanup = staleOwnerCleanupOutcome(
        custody_before,
        custody_while_alive,
        dead_custody_removed,
        alive_removed,
        dead_removed,
        repeated_removed,
    );
    // Targeted broken form: canonical lease cleanup succeeds but exact-owner
    // custody retirement is skipped. The fact must become false.
    const skipped_retirement = staleOwnerCleanupOutcome(
        custody_before,
        custody_while_alive,
        false,
        alive_removed,
        0,
        repeated_removed,
    );
    return actual_cleanup and !skipped_retirement and
        reclaimed and replacement_started_empty and replacement_fresh and replacement_clean;
}

fn staleOwnerCleanupOutcome(
    custody_before: bool,
    custody_while_alive: bool,
    dead_custody_removed: bool,
    alive_removed: usize,
    dead_removed: usize,
    repeated_removed: usize,
) bool {
    return custody_before and custody_while_alive and dead_custody_removed and
        alive_removed == 0 and dead_removed == 1 and repeated_removed == 0;
}

// ===========================================================================
// §8.8 advisory-usage OBSERVATION family (TIN-2400, observation-only, PR B).
//
// Every scenario drives the routed synthetic seam (#494) with the #505 advisory
// wiring: a canned advisory usage document is threaded through the response's
// `anthropic-ratelimit-usage` header on the deterministic `FakeUpstream`, folded
// through the pure `advisory_usage` core, and read back from the value-free
// `AdvisoryObservation` on the request observation surface. The documents are the
// core's OWN synthetic schema (the core is the sole schema authority). Advisory
// state NEVER touches a routing/retry/terminal decision — these facts only prove
// the §8.8 behaviors are observable at the wire boundary. A deterministic
// `VirtualClock` pins the 300 s freshness window and negative cache to the exact
// second, and all values stay value-free (fixed ids + pass/fail only).
// ===========================================================================

const adv_header = wire_proxy.advisory_usage_header;

// Canonical synthetic advisory documents (the core's own schema grammar). Each
// is a fixed byte string carried by the `anthropic-ratelimit-usage` header.
const adv_fresh_available = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400}]}";
const adv_empty = "{\"schema_version\":1,\"usage\":[]}";
const adv_v2 = "{\"schema_version\":2,\"usage\":[]}";
const adv_v3 = "{\"schema_version\":3,\"usage\":[]}";
const adv_missing_usage_array = "{\"schema_version\":1}";
const adv_unknown_fields = "{\"schema_version\":1,\"telemetry\":\"x\",\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400,\"nonce\":\"y\",\"weight\":7}]}";
const adv_row_missing_scope = "{\"schema_version\":1,\"usage\":[{\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400}]}";
const adv_row_missing_window = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"utilization\":0.42,\"resets_at\":1783652400}]}";
const adv_row_unbounded_value = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":1.7,\"resets_at\":1783652400}]}";
const adv_row_non_absolute_reset = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":-5}]}";
const adv_model_match = "{\"schema_version\":1,\"usage\":[{\"scope\":\"model\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400,\"model\":\"" ++ routed_model ++ "\"}]}";
const adv_model_missing_id = "{\"schema_version\":1,\"usage\":[{\"scope\":\"model\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400}]}";
const adv_model_mismatch = "{\"schema_version\":1,\"usage\":[{\"scope\":\"model\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400,\"model\":\"claude-sonnet-4-20250514\"}]}";
const adv_contradiction = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1783652400},{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":1.0,\"resets_at\":1783652400}]}";
// Exhausted / available rows whose absolute reset (epoch second 1100) falls
// INSIDE the freshness window after an observation at now_s = 1000, so a later
// query crosses the reset boundary while the row is still fresh.
const adv_exhausted_reset_1100 = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":1.0,\"resets_at\":1100}]}";
const adv_available_deadline_1100 = "{\"schema_version\":1,\"usage\":[{\"scope\":\"account\",\"window\":\"5h\",\"utilization\":0.42,\"resets_at\":1100}]}";

fn advHeader(doc: []const u8) fake_upstream_mod.Header {
    return .{ .name = adv_header, .value = doc };
}

fn advisoryObs(listener: *wire_proxy.Listener) wire_proxy.AdvisoryObservation {
    return wire_proxy.testing.requestObservation(listener).advisory;
}

/// Populate the per-account cache once with an advisory-carrying 2xx, then serve
/// `follow` further header-less 2xx responses so later requests re-query the
/// SAME cached window (proving "no re-fetch"). `now_ns` is the injected clock.
const AdvisoryScript = struct {
    fn oneRoute(
        capability: *SessionCapability,
        upstream: *FakeUpstream,
        vclock: *VirtualClock,
        event_writer: std.io.AnyWriter,
    ) !*wire_proxy.Listener {
        return wire_proxy.testing.startWithRoutes(std.testing.allocator, capability, event_writer, .{
            .primary = .{ .upstream = upstream, .bearer = "r1", .identity = "acct-1" },
            .clock = vclock.clock(),
        });
    }
};

/// advisory_usage_default_on: the sidecar usage reader runs UNCONDITIONALLY on
/// every routed response — there is no enable flag; a fresh advisory on a routed
/// 2xx is admitted, classified fresh/available, and never latched killed.
fn runAdvisoryDefaultOnScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_fresh_available)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_observed_on_every_routed_response, hasStatus(response, "200 OK") and
        adv.present and adv.freshness == .populated_fresh and adv.readiness == .available and
        !adv.killed and primary.snapshot().call_count == 1);
}

/// advisory_usage_non_authoritative: a fresh advisory is capped at `.inferred`
/// (never `.proven`), and an advisory header changes NO routing/attempt decision
/// (byte-identical accounting with vs without the header).
fn runAdvisoryNonAuthoritativeScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var with_adv = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_fresh_available)},
    }});
    defer with_adv.deinit();
    var without_adv = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "ok" }});
    defer without_adv.deinit();

    var vclock_a = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener_a = try AdvisoryScript.oneRoute(capability, &with_adv, &vclock_a, std.io.null_writer.any());
    defer listener_a.deinit();
    var vclock_b = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener_b = try AdvisoryScript.oneRoute(capability, &without_adv, &vclock_b, std.io.null_writer.any());
    defer listener_b.deinit();

    std.testing.allocator.free(try routedRequest(listener_a, &carrier));
    std.testing.allocator.free(try routedRequest(listener_b, &carrier));
    const a = wire_proxy.testing.requestObservation(listener_a);
    const b = wire_proxy.testing.requestObservation(listener_b);

    setFact(facts, .advisory_capped_at_inferred_never_proven, a.advisory.present and a.advisory.provenance == .inferred and a.advisory.provenance != .proven);
    setFact(facts, .advisory_changes_no_routing_decision, a.advisory.present and !b.advisory.present and
        a.attempts_total == b.attempts_total and a.alternate_count == b.alternate_count and
        a.same_route_retry_count == b.same_route_retry_count and
        a.third_attempt_count == b.third_attempt_count and
        a.upstream_status == b.upstream_status and a.replay_mode == b.replay_mode and
        with_adv.snapshot().call_count == without_adv.snapshot().call_count);
}

/// advisory_usage_five_minute_freshness: fresh WHILE age < 300 s (reused with no
/// re-fetch), stale at the EXACT 300 s boundary.
fn runAdvisoryFreshnessBoundaryScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_fresh_available)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const populated = advisoryObs(listener).freshness == .populated_fresh;

    vclock.now_ns = 1299 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const inside = advisoryObs(listener);
    const still_fresh = !inside.present and inside.freshness == .populated_fresh;

    vclock.now_ns = 1300 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const boundary = advisoryObs(listener);
    const stale_at_boundary = boundary.freshness == .populated_stale and
        boundary.readiness == .unknown and boundary.provenance == .unobserved;

    setFact(facts, .advisory_fresh_window_boundary_exact, populated and still_fresh and stale_at_boundary);
}

/// advisory_usage_valid_empty_negative_cache: a valid-empty result arms the
/// negative cache; active while age < 300 s, expired at the exact boundary.
fn runAdvisoryNegativeCacheScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_empty)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 500 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const armed = advisoryObs(listener).freshness == .negative_active;

    vclock.now_ns = 799 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const inside = advisoryObs(listener);
    const active = !inside.present and inside.freshness == .negative_active;

    vclock.now_ns = 800 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const expired = advisoryObs(listener).freshness == .negative_expired;

    setFact(facts, .advisory_valid_empty_arms_negative_cache, armed and active and expired);
}

/// advisory_usage_normalized_observations_only + advisory_usage_no_raw_response_
/// persistence: a well-formed account row folds to a fully NORMALIZED typed
/// observation (typed freshness/readiness/provenance, no raw text), and neither
/// the event nor the surface carries any provider payload value.
fn runAdvisoryNormalizedValueFreeScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_fresh_available)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, event_stream.writer().any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    const written = event_stream.getWritten();

    setFact(facts, .advisory_records_normalized_typed_observation, adv.present and adv.freshness == .populated_fresh and adv.readiness == .available and
        adv.provenance == .inferred and !adv.killed and adv.reactive_present);
    setFact(facts, .advisory_surface_and_event_value_free, std.mem.indexOf(u8, written, "claude_proxy_advisory_observed") != null and
        std.mem.indexOf(u8, written, "1783652400") == null and
        std.mem.indexOf(u8, written, "0.42") == null and
        std.mem.indexOf(u8, written, "utilization") == null and
        std.mem.indexOf(u8, written, "resets_at") == null and
        std.mem.indexOf(u8, written, "schema_version") == null);
}

/// advisory_usage_unknown_field_tolerance: unknown JSON fields (top-level and
/// per-row) are tolerated — the valid row is still admitted.
fn runAdvisoryUnknownFieldToleranceScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_unknown_fields)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_tolerates_unknown_fields, adv.present and adv.freshness == .populated_fresh and adv.readiness == .available and
        adv.provenance == .inferred and !adv.killed);
}

/// Drive one advisory doc and return its value-free observation at now_s = 1000.
fn observeAdvisoryDoc(capability: *SessionCapability, carrier: []const u8, doc: []const u8) !wire_proxy.AdvisoryObservation {
    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(doc)},
    }});
    defer primary.deinit();
    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();
    std.testing.allocator.free(try routedRequest(listener, carrier));
    return advisoryObs(listener);
}

/// A row is EXCLUDED (not fabricated) exactly when it violates a required field:
/// the sole invalid row leaves a valid-empty result → negative cache, no
/// populated readiness. Proven per required field (scope/window/value/reset).
fn runAdvisoryRequiredFieldExclusionScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const excluded = struct {
        fn ok(adv: wire_proxy.AdvisoryObservation) bool {
            // No row survived: valid-empty → negative cache, nothing invented.
            return adv.present and adv.freshness == .negative_active and
                adv.readiness == .unknown and adv.provenance == .unobserved;
        }
    }.ok;

    setFact(facts, .advisory_excludes_row_missing_scope, excluded(try observeAdvisoryDoc(capability, &carrier, adv_row_missing_scope)));
    setFact(facts, .advisory_excludes_row_missing_window, excluded(try observeAdvisoryDoc(capability, &carrier, adv_row_missing_window)));
    setFact(facts, .advisory_excludes_row_unbounded_value, excluded(try observeAdvisoryDoc(capability, &carrier, adv_row_unbounded_value)));
    setFact(facts, .advisory_excludes_row_non_absolute_reset, excluded(try observeAdvisoryDoc(capability, &carrier, adv_row_non_absolute_reset)));
}

/// advisory_usage_exact_model_scope: a model-scoped row applies ONLY to its exact
/// model (admitted for the routed model), and a model-scoped row missing its
/// model identifier is excluded.
fn runAdvisoryExactModelScopeScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const match = try observeAdvisoryDoc(capability, &carrier, adv_model_match);
    const missing_id = try observeAdvisoryDoc(capability, &carrier, adv_model_missing_id);
    setFact(facts, .advisory_model_scope_requires_exact_model, match.present and match.freshness == .populated_fresh and match.readiness == .available and
        match.provenance == .inferred and
        missing_id.present and missing_id.freshness == .negative_active and
        missing_id.readiness == .unknown and missing_id.provenance == .unobserved);
}

/// advisory_usage_invalid_row_exclusion: an invalid row is never fabricated into
/// a default — the result degrades to valid-empty with no populated readiness.
fn runAdvisoryInvalidRowExclusionScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const adv = try observeAdvisoryDoc(capability, &carrier, adv_row_missing_scope);
    setFact(facts, .advisory_invalid_row_excluded_never_fabricated, adv.present and adv.freshness == .negative_active and adv.readiness == .unknown and
        adv.provenance == .unobserved and !adv.killed);
}

/// advisory_usage_schema_event_{redaction,deduplication} + the two kill switches:
/// an unsupported version and a missing top-level structure each latch the
/// per-account process-lifetime kill; the redacted event surface is value-free;
/// and exactly one event fires per distinct schema fingerprint.
fn runAdvisorySchemaKillScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    // Unsupported-version kill + value-free redacted event.
    {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .ok,
            .body = "ok",
            .headers = &.{advHeader(adv_v2)},
        }});
        defer primary.deinit();
        var event_buffer: [1024]u8 = undefined;
        var event_stream = std.io.fixedBufferStream(&event_buffer);
        var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
        const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, event_stream.writer().any());
        defer listener.deinit();
        std.testing.allocator.free(try routedRequest(listener, &carrier));
        const adv = advisoryObs(listener);
        const written = event_stream.getWritten();
        setFact(facts, .advisory_unsupported_schema_trips_kill, adv.present and adv.killed and adv.freshness == .killed and
            std.mem.count(u8, written, "claude_proxy_advisory_schema_rejected") == 1);
        setFact(facts, .advisory_schema_event_redacted_value_free, std.mem.indexOf(u8, written, "claude_proxy_advisory_schema_rejected") != null and
            std.mem.indexOf(u8, written, "schema_version") == null and
            std.mem.indexOf(u8, written, "usage") == null);
    }

    // Missing top-level structure (no `usage` array) kill.
    {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .ok,
            .body = "ok",
            .headers = &.{advHeader(adv_missing_usage_array)},
        }});
        defer primary.deinit();
        var event_buffer: [1024]u8 = undefined;
        var event_stream = std.io.fixedBufferStream(&event_buffer);
        var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
        const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, event_stream.writer().any());
        defer listener.deinit();
        std.testing.allocator.free(try routedRequest(listener, &carrier));
        const adv = advisoryObs(listener);
        setFact(facts, .advisory_missing_structure_trips_kill, adv.present and adv.killed and adv.freshness == .killed and
            std.mem.count(u8, event_stream.getWritten(), "claude_proxy_advisory_schema_rejected") == 1);
    }

    // Dedup: two distinct fingerprints (v2, v3), each seen twice → exactly 2.
    {
        var primary = try FakeUpstream.start(std.testing.allocator, &.{
            .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_v2)} },
            .{ .status = .ok, .body = "b", .headers = &.{advHeader(adv_v2)} },
            .{ .status = .ok, .body = "c", .headers = &.{advHeader(adv_v3)} },
            .{ .status = .ok, .body = "d", .headers = &.{advHeader(adv_v3)} },
        });
        defer primary.deinit();
        var event_buffer: [2048]u8 = undefined;
        var event_stream = std.io.fixedBufferStream(&event_buffer);
        var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
        const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, event_stream.writer().any());
        defer listener.deinit();
        var i: usize = 0;
        while (i < 4) : (i += 1) std.testing.allocator.free(try routedRequest(listener, &carrier));
        setFact(facts, .advisory_one_schema_event_per_fingerprint, std.mem.count(u8, event_stream.getWritten(), "claude_proxy_advisory_schema_rejected") == 2);
    }
}

/// advisory_stale_reactive_fallback: once the advisory window elapses, advisory
/// state degrades and the direct request-path (reactive) evidence is elected.
fn runAdvisoryStaleFallbackScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_fresh_available)} },
        .{ .status = .ok, .body = "b" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    vclock.now_ns = 1300 * std.time.ns_per_s;
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_stale_falls_back_to_reactive, adv.freshness == .populated_stale and adv.provenance == .unobserved and
        adv.reactive_present and adv.elected_provenance == .proven and
        adv.elected_readiness == .available);
}

/// advisory_missing_reactive_fallback: with no advisory header the election comes
/// purely from the direct request-path evidence.
fn runAdvisoryMissingFallbackScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "ok" }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_missing_falls_back_to_reactive, !adv.present and adv.freshness == .never and adv.provenance == .unobserved and
        adv.reactive_present and adv.elected_provenance == .proven and
        adv.elected_readiness == .available);
}

/// advisory_contradictory_reactive_fallback: two same-key rows disagreeing on
/// readiness make the advisory state contradictory → it degrades to reactive.
fn runAdvisoryContradictoryFallbackScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_contradiction)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_contradictory_falls_back_to_reactive, adv.present and adv.freshness == .populated_fresh and adv.readiness == .unknown and
        adv.provenance == .unobserved and adv.reactive_present and
        adv.elected_provenance == .proven and adv.elected_readiness == .available);
}

/// advisory_killed_reactive_fallback: a killed account still yields honest
/// reactive evidence (a later 2xx elects proven-available), advisory ignored.
fn runAdvisoryKilledFallbackScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_v2)} },
        .{ .status = .ok, .body = "b", .headers = &.{advHeader(adv_fresh_available)} },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_killed_falls_back_to_reactive, adv.killed and adv.freshness == .killed and adv.provenance == .unobserved and
        adv.reactive_present and adv.elected_provenance == .proven and
        adv.elected_readiness == .available);
}

/// advisory_failure_nonblocking: a per-account kill NEVER stops the harness — the
/// sidecar keeps serving every routed request with honest reactive evidence.
fn runAdvisoryNonBlockingScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const iterations = 3;
    const script = [_]fake_upstream_mod.ScriptedResponse{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_v2)},
    }} ** iterations;
    var primary = try FakeUpstream.start(std.testing.allocator, &script);
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    var all_served = true;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const response = try routedRequest(listener, &carrier);
        defer std.testing.allocator.free(response);
        all_served = all_served and hasStatus(response, "200 OK");
    }
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_failure_never_blocks_serving, all_served and adv.killed and adv.elected_provenance == .proven and
        primary.snapshot().call_count == iterations);
}

/// advisory_no_invented_route_readiness: with no advisory and a response class
/// that carries no reactive readiness (a 5xx pass-through), the election is an
/// honest `.unobserved`/`unknown` — never an invented route readiness.
fn runAdvisoryNoInventedRouteScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .internal_server_error,
        .body = "boom",
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_absent_invents_no_route_readiness, hasStatus(response, "500 Internal Server Error") and !adv.present and
        adv.freshness == .never and !adv.reactive_present and
        adv.provenance == .unobserved and adv.elected_provenance == .unobserved and
        adv.elected_readiness == .unknown);
}

/// advisory_no_invented_model_readiness: a fresh advisory row for a DIFFERENT
/// model does not apply to the admitted model — no model readiness is invented.
fn runAdvisoryNoInventedModelScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const adv = try observeAdvisoryDoc(capability, &carrier, adv_model_mismatch);
    setFact(facts, .advisory_mismatch_invents_no_model_readiness, adv.present and adv.freshness == .populated_fresh and adv.readiness == .unknown and
        adv.provenance == .unobserved);
}

/// request_path_evidence_precedence: a direct request-path 429 OUTRANKS a fresh
/// advisory that claims availability.
fn runAdvisoryReactivePrecedenceScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .too_many_requests,
        .body = "limit",
        .headers = &.{ .{ .name = "Retry-After", .value = "5" }, advHeader(adv_fresh_available) },
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    const response = try routedRequest(listener, &carrier);
    defer std.testing.allocator.free(response);
    const adv = advisoryObs(listener);
    setFact(facts, .reactive_outranks_fresh_advisory, hasStatus(response, "429 Too Many Requests") and adv.present and
        adv.readiness == .available and adv.provenance == .inferred and
        adv.reactive_present and adv.elected_readiness == .exhausted and
        adv.elected_provenance == .proven);
}

/// sidecar_no_proactive_usage_polling: the observation is response-driven only —
/// it piggybacks the single upstream call and never opens a second polling read.
fn runAdvisoryNoPollScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "ok",
        .headers = &.{advHeader(adv_fresh_available)},
    }});
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const adv = advisoryObs(listener);
    setFact(facts, .advisory_observation_adds_no_upstream_call, adv.present and primary.snapshot().call_count == 1 and primary.snapshot().attempt_count == 1);
}

/// observed_exhaustion_trusted_through_reset: an observed exhaustion is trusted
/// (`.inferred`) WHILE now_s < its reset, then the advisory election degrades to
/// `.unobserved` at the reset — it never invents availability. The advisory row
/// stays fresh across the crossing (reset 1100 is inside the 300 s window).
fn runAdvisoryThroughResetScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_exhausted_reset_1100)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const at_observe = advisoryObs(listener);

    vclock.now_ns = 1099 * std.time.ns_per_s; // still before the reset
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const before_reset = advisoryObs(listener);

    vclock.now_ns = 1100 * std.time.ns_per_s; // exactly the reset boundary
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const at_reset = advisoryObs(listener);

    setFact(facts, .advisory_exhaustion_trusted_through_reset,
        // Trusted through the reset: exhausted/inferred while now_s < reset ...
        at_observe.freshness == .populated_fresh and at_observe.readiness == .exhausted and
            at_observe.provenance == .inferred and
            before_reset.freshness == .populated_fresh and before_reset.provenance == .inferred and
            // ... then no invention at the reset: the advisory election degrades
            // to unobserved (still fresh, so this is the reset — not staleness).
            at_reset.freshness == .populated_fresh and at_reset.provenance == .unobserved);
}

/// availability_expires_at_deadline: an availability observation is trusted
/// (`.inferred`) WHILE now_s < its deadline, then EXPIRES to `.unobserved` at the
/// deadline (still fresh, so the transition is the deadline, not staleness).
fn runAdvisoryDeadlineScenario(facts: []Fact) !void {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    var primary = try FakeUpstream.start(std.testing.allocator, &.{
        .{ .status = .ok, .body = "a", .headers = &.{advHeader(adv_available_deadline_1100)} },
        .{ .status = .ok, .body = "b" },
        .{ .status = .ok, .body = "c" },
    });
    defer primary.deinit();

    var vclock = VirtualClock{ .now_ns = 1000 * std.time.ns_per_s };
    const listener = try AdvisoryScript.oneRoute(capability, &primary, &vclock, std.io.null_writer.any());
    defer listener.deinit();

    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const at_observe = advisoryObs(listener);

    vclock.now_ns = 1099 * std.time.ns_per_s; // before the deadline
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const before_deadline = advisoryObs(listener);

    vclock.now_ns = 1100 * std.time.ns_per_s; // exactly the deadline
    std.testing.allocator.free(try routedRequest(listener, &carrier));
    const at_deadline = advisoryObs(listener);

    setFact(facts, .advisory_availability_expires_at_deadline, at_observe.freshness == .populated_fresh and at_observe.readiness == .available and
        at_observe.provenance == .inferred and
        before_deadline.freshness == .populated_fresh and before_deadline.provenance == .inferred and
        at_deadline.freshness == .populated_fresh and at_deadline.provenance == .unobserved);
}

fn writeArtifactAtomic(artifact: Artifact) !void {
    const output = "v02-stage2-observations.json";
    const temporary = "v02-stage2-observations.json.tmp";
    const cwd = std.fs.cwd();
    cwd.deleteFile(temporary) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var file = try cwd.createFile(temporary, .{ .exclusive = true });
    var file_open = true;
    errdefer {
        if (file_open) file.close();
        cwd.deleteFile(temporary) catch {};
    }
    var buffered = std.io.bufferedWriter(file.writer());
    try std.json.stringify(artifact, .{}, buffered.writer());
    try buffered.writer().writeByte('\n');
    try buffered.flush();
    try file.sync();
    file.close();
    file_open = false;
    try cwd.rename(temporary, output);
}

// ===========================================================================
// §8.8 refresh-predicate OBSERVATION family (TIN-2400, PR C). Every scenario
// drives the landed TIN-2990 flock-owned locked-lineage refresh engine
// (repair_state.zig) directly, over a synthetic credential file in an isolated
// runtime dir, and records only value-free pass/fail facts. There is no
// provider-authenticated call: transient scenarios never contact any endpoint,
// and the single hard-lineage scenario uses the production
// `establishHardRefreshQuarantineForTest` fixture, which spins its own loopback
// invalid_grant responder. The observation is the exact typed
// `LockedRefreshAttempt` / quarantine-marker state the product persists.
//
// Deterministic by construction: refusals return synchronously (no sleeps), the
// one cross-actor contention probe uses a nonblocking acquire that returns
// immediately, and every synthetic store lives in its own temp dir.
// ===========================================================================

const synthetic_unused_token_url = "http://127.0.0.1:1/token";
const synthetic_refresh_token = "synthetic-refresh";
const synthetic_credential_json =
    "{\"access_token\":\"synthetic-access\"," ++
    "\"refresh_token\":\"" ++ synthetic_refresh_token ++ "\"," ++
    "\"account_id\":\"synthetic-identity\"}";

fn syntheticProviderDef() provider_schema.ProviderDefinition {
    return .{
        .name = "toy",
        .credential = .{
            .access_token_path = "access_token",
            .refresh_token_path = "refresh_token",
            .identity_claim_path = "account_id",
        },
        .repair = .{
            .owner = .oauth_mux_refresh,
            .proactive_refresh = .oauth_refresh_token,
        },
    };
}

/// Write a synthetic canonical-store credential under the active runtime dir and
/// return its absolute path (caller frees). The bytes are inert placeholders,
/// never real provider secrets.
fn writeSyntheticCredential(
    allocator: std.mem.Allocator,
    root: []const u8,
    file_name: []const u8,
) ![]const u8 {
    const path = try std.fs.path.join(allocator, &.{ root, file_name });
    errdefer allocator.free(path);
    const file = try std.fs.createFileAbsolute(path, .{ .mode = 0o600 });
    defer file.close();
    try file.writeAll(synthetic_credential_json);
    return path;
}

fn syntheticFileBackend(path: []const u8) types.SecretBackend {
    return .{ .file = .{ .path = path } };
}

/// Release and free a `LockedRefreshSuccess` that a transient scenario did not
/// expect: keeps the synthetic runtime dir clean and the allocator leak-free.
fn discardUnexpectedRefreshSuccess(
    allocator: std.mem.Allocator,
    success: *repair_state.LockedRefreshSuccess,
) void {
    success.releaseStoreLock();
    allocator.free(success.result.access_token);
    if (success.result.refresh_token) |refresh_token| allocator.free(refresh_token);
}

/// Cross-actor (separate thread) nonblocking probe of a per-account repair
/// flock. A different actor must be refused (`RepairInProgress`) while the flock
/// is held, proving a single shared flock serializes the account.
const AccountFlockProbe = struct {
    const blocked: u8 = 1;
    const acquired: u8 = 2;
    const failed: u8 = 3;

    fn run(
        provider: []const u8,
        account: []const u8,
        outcome: *std.atomic.Value(u8),
    ) void {
        var lock = repair_state.acquireRepairLock(
            std.heap.page_allocator,
            provider,
            account,
        ) catch |err| {
            outcome.store(
                if (err == error.RepairInProgress) blocked else failed,
                .seq_cst,
            );
            return;
        };
        lock.release();
        outcome.store(acquired, .seq_cst);
    }
};

fn readMarkerAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, 4 * 1024);
}

fn runRefreshSharedAccountFlockScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try writeSyntheticCredential(a, scope.root, "shared-flock.json");
    defer a.free(path);
    const def = syntheticProviderDef();
    const backend = syntheticFileBackend(path);

    // (a) The locked-lineage refresh refuses to arm or contact the endpoint
    // unless the current actor owns the shared per-account flock.
    const unowned = try repair_state.refreshTokenWithLockedLineage(
        a,
        "toy",
        "shared",
        backend,
        def,
        synthetic_unused_token_url,
        synthetic_refresh_token,
        null,
        .{},
    );
    switch (unowned) {
        .failed => |failure| setFact(
            facts,
            .refresh_requires_owned_account_flock,
            failure.outcome == .transient_lock and !failure.endpoint_executed,
        ),
        .refreshed => |value| {
            var success = value;
            discardUnexpectedRefreshSuccess(a, &success);
        },
    }

    // (b) Exactly one shared flock serializes the account: while this actor
    // holds it, a cross-actor nonblocking acquire of the same key is refused.
    var held = try repair_state.acquireRepairLock(a, "toy", "shared");
    defer held.release();
    var probe_outcome = std.atomic.Value(u8).init(0);
    const probe = try std.Thread.spawn(
        .{},
        AccountFlockProbe.run,
        .{ "toy", "shared", &probe_outcome },
    );
    probe.join();
    setFact(
        facts,
        .account_flock_serializes_cross_actor,
        probe_outcome.load(.seq_cst) == AccountFlockProbe.blocked,
    );
}

fn runRefreshLockNoDeadlockScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    // Re-entrant single-flock-per-key: the resident tick and an in-process
    // request-boundary refresh are the same actor for one (provider,account),
    // so nested acquires must NOT self-deadlock on the per-fd flock.
    var l1 = try repair_state.acquireRepairLockBlocking(a, "toy", "reentrant");
    var l2 = try repair_state.acquireRepairLockBlocking(a, "toy", "reentrant");
    var l3 = try repair_state.acquireRepairLock(a, "toy", "reentrant");
    l3.release();
    l2.release();
    l1.release();
    // Fully released: a fresh acquire still succeeds (registry entry cleared).
    var l4 = try repair_state.acquireRepairLockBlocking(a, "toy", "reentrant");
    l4.release();
    setFact(facts, .account_flock_reentrant_same_actor, true);
}

fn runRefreshTransientLockFailureScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try writeSyntheticCredential(a, scope.root, "lock-fail.json");
    defer a.free(path);
    const def = syntheticProviderDef();
    const backend = syntheticFileBackend(path);

    // No account-flock ownership → typed transient_lock, before the boundary
    // arms: the endpoint is never executed and no lineage is quarantined.
    const attempt = try repair_state.refreshTokenWithLockedLineage(
        a,
        "toy",
        "lock-fail",
        backend,
        def,
        synthetic_unused_token_url,
        synthetic_refresh_token,
        null,
        .{},
    );
    switch (attempt) {
        .failed => |failure| setFact(
            facts,
            .transient_lock_failure_skips_endpoint,
            failure.outcome == .transient_lock and
                !failure.endpoint_executed and
                !failure.lineage_quarantined,
        ),
        .refreshed => |value| {
            var success = value;
            discardUnexpectedRefreshSuccess(a, &success);
        },
    }
    const quarantine = try repair_state.refreshQuarantineForRoute(a, "toy", "lock-fail");
    setFact(facts, .transient_lock_failure_leaves_no_quarantine, quarantine == null);
}

fn runRefreshTransientStoreFailureScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try writeSyntheticCredential(a, scope.root, "store-fail.json");
    defer a.free(path);
    const def = syntheticProviderDef();
    const backend = syntheticFileBackend(path);

    var lock = try repair_state.acquireRepairLock(a, "toy", "store-fail");
    defer lock.release();

    // The submitted token no longer matches the canonical store lineage →
    // typed transient_store, before the boundary arms: no endpoint contact and
    // no quarantine.
    const attempt = try repair_state.refreshTokenWithLockedLineage(
        a,
        "toy",
        "store-fail",
        backend,
        def,
        synthetic_unused_token_url,
        "stale-mismatched-refresh",
        null,
        .{},
    );
    switch (attempt) {
        .failed => |failure| setFact(
            facts,
            .transient_store_failure_skips_endpoint,
            failure.outcome == .transient_store and
                !failure.endpoint_executed and
                !failure.lineage_quarantined,
        ),
        .refreshed => |value| {
            var success = value;
            discardUnexpectedRefreshSuccess(a, &success);
        },
    }
    const quarantine = try repair_state.refreshQuarantineForRoute(a, "toy", "store-fail");
    setFact(facts, .transient_store_failure_leaves_no_quarantine, quarantine == null);
}

fn runRefreshInvalidLineageQuarantineScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try writeSyntheticCredential(a, scope.root, "invalid-grant.json");
    defer a.free(path);
    const def = syntheticProviderDef();
    const backend = syntheticFileBackend(path);

    // Hard provider evidence (an OAuth invalid_grant response, the sole hard
    // signal) drives the full locked-lineage proof to a sticky hard quarantine.
    try repair_state.establishHardRefreshQuarantineForTest(
        a,
        "toy",
        "invalid",
        backend,
        def,
    );
    const effective = try repair_state.effectiveRefreshQuarantineForRoute(a, "toy", "invalid");
    setFact(
        facts,
        .invalid_grant_lineage_hard_quarantined,
        effective == .hard_lineage_invalidated,
    );

    // The sticky hard tag blocks a fresh locked-lineage attempt before the
    // boundary arms — the closed lineage is never re-submitted to any endpoint.
    var lock = try repair_state.acquireRepairLock(a, "toy", "invalid");
    defer lock.release();
    const restart = try repair_state.refreshTokenWithLockedLineage(
        a,
        "toy",
        "invalid",
        backend,
        def,
        synthetic_unused_token_url,
        synthetic_refresh_token,
        null,
        .{},
    );
    switch (restart) {
        .failed => |failure| setFact(
            facts,
            .invalid_grant_hard_quarantine_blocks_before_endpoint,
            failure.outcome == .hard_lineage_invalidated and
                !failure.endpoint_executed and
                failure.lineage_quarantined,
        ),
        .refreshed => |value| {
            var success = value;
            discardUnexpectedRefreshSuccess(a, &success);
        },
    }
}

fn runRefreshProviderEvidenceScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    // The hard tag is not a proof primitive: an ordinary journal appender
    // cannot manufacture it without the flock-owned locked-lineage proof, so
    // only real provider evidence can quarantine a lineage.
    const event = repair_state.refreshEvent(.{
        .provider = "toy",
        .account = "evidence",
        .outcome = .hard_lineage_invalidated,
        .executed = true,
    });
    if (repair_state.appendEvent(a, event)) |_| {
        // Unexpected success leaves the fact failed by default.
    } else |err| {
        setFact(
            facts,
            .hard_tag_refused_without_locked_lineage_proof,
            err == error.HardRefreshRequiresLockedLineageProof,
        );
    }
}

fn runRefreshReenrollmentScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    const path = try writeSyntheticCredential(a, scope.root, "reenroll.json");
    defer a.free(path);
    const def = syntheticProviderDef();
    const backend = syntheticFileBackend(path);

    // A hard-invalidated lineage is sticky: provider re-enrollment recovery
    // refuses to clear it, so recovery requires provider-owned re-enrollment
    // (the hard journal authority is never erased by the recovery path).
    try repair_state.establishHardRefreshQuarantineForTest(
        a,
        "toy",
        "hard",
        backend,
        def,
    );
    {
        var lock = try repair_state.acquireRepairLock(a, "toy", "hard");
        defer lock.release();
        if (repair_state.resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
            a,
            "toy",
            "hard",
        )) |_| {
            // Unexpected clearance leaves the fact failed by default.
        } else |err| {
            setFact(
                facts,
                .hard_quarantine_refuses_reenroll_clearance,
                err == error.HardRefreshQuarantineCannotBeCleared,
            );
        }
    }

    // The clearable (indeterminate) tier resolves only through the explicit
    // provider re-enrollment recovery, and only then becomes selectable again.
    try repair_state.persistIndeterminateRefreshQuarantine(a, "toy", "soft");
    {
        var lock = try repair_state.acquireRepairLock(a, "toy", "soft");
        defer lock.release();
        const cleared = try repair_state.resolveIndeterminateRefreshQuarantineAfterProviderReenroll(
            a,
            "toy",
            "soft",
        );
        const after = try repair_state.refreshQuarantineForRoute(a, "toy", "soft");
        setFact(
            facts,
            .indeterminate_quarantine_clears_via_reenroll,
            cleared and after == null,
        );
    }
}

fn runRefreshNoStaleBackupRestoreScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    // Every persisted quarantine marker hard-codes the stale-backup-restore
    // invariant to false: no stale credential backup is ever restored.
    try repair_state.persistIndeterminateRefreshQuarantine(a, "toy", "marker");
    const marker_path = try repair_state.refreshQuarantineMarkerPathForTest(a, "toy", "marker");
    defer a.free(marker_path);
    const bytes = try readMarkerAlloc(a, marker_path);
    defer a.free(bytes);
    setFact(
        facts,
        .quarantine_marker_forbids_stale_backup_restore,
        std.mem.indexOf(u8, bytes, "\"stale_backup_restore_allowed\":false") != null,
    );

    // A tampered marker that asserts stale-backup restore is refused as invalid,
    // so no read path can turn the invariant on.
    const tampered_path = try repair_state.refreshQuarantineMarkerPathForTest(a, "toy", "tampered");
    defer a.free(tampered_path);
    {
        const file = try std.fs.createFileAbsolute(tampered_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(
            "{\"version\":1,\"provider\":\"toy\",\"account\":\"tampered\"," ++
                "\"state\":\"indeterminate_lineage\",\"outcome\":null," ++
                "\"recovery\":\"provider_reenroll\"," ++
                "\"stale_backup_restore_allowed\":true," ++
                "\"store_fingerprint\":null,\"identity_fingerprint\":null}\n",
        );
    }
    if (repair_state.refreshQuarantineForRoute(a, "toy", "tampered")) |_| {
        // Unexpected acceptance leaves the fact failed by default.
    } else |err| {
        setFact(
            facts,
            .stale_backup_restore_marker_rejected,
            err == error.InvalidRefreshQuarantine,
        );
    }
}

fn runRefreshNoForensicBackupRestoreScenario(facts: []Fact) !void {
    const a = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    // The only sanctioned recovery is provider re-enrollment. No forensic or
    // automatic backup-restore recovery is encoded anywhere in the marker, and
    // no such restore path exists in the engine.
    try repair_state.persistIndeterminateRefreshQuarantine(a, "toy", "forensic");
    const marker_path = try repair_state.refreshQuarantineMarkerPathForTest(a, "toy", "forensic");
    defer a.free(marker_path);
    const bytes = try readMarkerAlloc(a, marker_path);
    defer a.free(bytes);
    setFact(
        facts,
        .quarantine_recovery_is_provider_reenroll_only,
        std.mem.indexOf(u8, bytes, "\"recovery\":\"provider_reenroll\"") != null and
            std.mem.indexOf(u8, bytes, "\"stale_backup_restore_allowed\":false") != null,
    );
}
