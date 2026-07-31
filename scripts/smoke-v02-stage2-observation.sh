#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OBSERVATION="$ROOT/v02-stage2-observations.json"
VERIFY="$ROOT/scripts/v02-stage2-observation-local.sh"
PREDICATES="$ROOT/scripts/v02-proof-predicate-manifest-local.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/omux-stage2-observation.XXXXXX")
trap 'rm -f "$OBSERVATION" "$ROOT/v02-stage2-observations.json.tmp"; rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
  echo "smoke-v02-stage2-observation: $*" >&2
  exit 1
}

expect_rejected() {
  if "$@" >/dev/null 2>&1; then
    fail "expected command to reject: $*"
  fi
}

require_unproven_predicates_missing() {
  jq -e '
    [
      "provider_egress_denial",
      "provider_call_count_zero",
      "one_sidecar_per_managed_child",
      "capability_memory_only",
      "capability_constant_time_validation",
      "capability_revocation_on_teardown",
      "elected_oauth_credential_injection",
      "managed_launch_fail_closed",
      "explicit_direct_fallback_policy",
      "fixed_origin_enforcement",
      "system_tls_verification",
      "resident_request_body_forwarding_rejection",
      "evidence_allowlist_redaction",
      "no_request_disk_spooling"
    ] as $must_remain_missing
    | [.predicates[] | select(.status == "missing") | .id] as $missing
    | (($must_remain_missing - $missing) | length) == 0
  ' "$1" >/dev/null
}

require_deferred_lease_predicates_missing() {
  jq -e '
    [
      "deterministic_shared_leases",
      "stale_lease_owner_cleanup"
    ] as $must_remain_missing
    | [.predicates[] | select(.status == "missing") | .id] as $missing
    | (($must_remain_missing - $missing) | length) == 0
  ' "$1" >/dev/null
}

lease_redaction_canaries='lease-redaction-route-z-canary
lease-redaction-route-a-canary
lease-redaction-identity-z-canary
lease-redaction-identity-a-canary
claude-lease-redaction-model-canary
lease-session-prompt-canary
lease-redaction-token-z-canary
lease-redaction-token-a-canary
42424290
42424291
42424292
313371234
313371235'

require_lease_redaction_artifact_clean() {
  while IFS= read -r canary; do
    if LC_ALL=C grep -Fq -- "$canary" "$1"; then
      return 1
    fi
  done <<<"$lease_redaction_canaries"
}

cd "$ROOT"
candidate_sha=$(git rev-parse --verify 'HEAD^{commit}')
candidate_tree=$(git rev-parse --verify 'HEAD^{tree}')
workflow_run_id=17
workflow_run_attempt=2
gf_target_class=tinyland-nix

zig build v02-stage2-observe \
  -Dv02-candidate-sha="$candidate_sha" \
  -Dv02-candidate-tree="$candidate_tree" \
  -Dv02-workflow-run-id="$workflow_run_id" \
  -Dv02-workflow-run-attempt="$workflow_run_attempt" \
  -Dv02-gf-target-class="$gf_target_class"

"$VERIFY" verify \
  "$OBSERVATION" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$workflow_run_id" \
  "$workflow_run_attempt" \
  "$gf_target_class"
"$VERIFY" require-pass \
  "$OBSERVATION" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$workflow_run_id" \
  "$workflow_run_attempt" \
  "$gf_target_class"
require_lease_redaction_artifact_clean "$OBSERVATION" ||
  fail "Stage 2 artifact leaked a routed lease redaction canary"
leaked_artifact="$TMP/lease-redaction-leaked-artifact.json"
jq '.lease_redaction_leak = "lease-session-prompt-canary"' \
  "$OBSERVATION" >"$leaked_artifact"
if require_lease_redaction_artifact_clean "$leaked_artifact"; then
  fail "lease redaction artifact scan accepted an injected prompt leak"
fi

manifest="$TMP/manifest.json"
"$PREDICATES" reduce-stage2 \
  "$OBSERVATION" \
  "$manifest" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$workflow_run_id" \
  "$workflow_run_attempt" \
  "$gf_target_class"
"$PREDICATES" require-incomplete v02-stage2-conformance "$manifest"
"$PREDICATES" require-stage2-slice v02-stage2-conformance "$manifest"

[ "$(jq '[.predicates[] | select(.status == "pass")] | length' "$manifest")" -eq 80 ] ||
  fail "expected exactly 80 exercised predicates"
[ "$(jq '[.predicates[] | select(.status == "missing")] | length' "$manifest")" -eq 44 ] ||
  fail "expected exactly 44 unexercised predicates"
[ "$(jq '[.predicates[] | select(.status == "fail")] | length' "$manifest")" -eq 0 ] ||
  fail "successful fake-upstream scenarios must not emit failed predicates"
require_unproven_predicates_missing "$manifest" ||
  fail "predicate without canonical evidence moved out of missing"
require_deferred_lease_predicates_missing "$manifest" ||
  fail "cross-process lease predicate moved out of missing"
withdrawn_predicates='one_sidecar_per_managed_child
capability_memory_only
capability_constant_time_validation
capability_revocation_on_teardown
managed_launch_fail_closed
evidence_allowlist_redaction
no_request_disk_spooling'
while IFS= read -r predicate_id; do
  unproven_promoted="$TMP/${predicate_id}-promoted.json"
  jq --arg predicate_id "$predicate_id" \
    '(.predicates[] | select(.id == $predicate_id)).status = "pass"' \
    "$manifest" >"$unproven_promoted"
  if require_unproven_predicates_missing "$unproven_promoted"; then
    fail "missing-predicate guard accepted false promotion: ${predicate_id}"
  fi
done <<<"$withdrawn_predicates"

deferred_lease_predicates='deterministic_shared_leases
stale_lease_owner_cleanup'
while IFS= read -r predicate_id; do
  deferred_promoted="$TMP/${predicate_id}-promoted.json"
  jq --arg predicate_id "$predicate_id" \
    '(.predicates[] | select(.id == $predicate_id)).status = "pass"' \
    "$manifest" >"$deferred_promoted"
  if require_deferred_lease_predicates_missing "$deferred_promoted"; then
    fail "deferred lease guard accepted false promotion: ${predicate_id}"
  fi
done <<<"$deferred_lease_predicates"

expected_passes='capability_carrier
loopback_sidecar_bind
capability_256bit_base64url
bad_token_zero_call_rejection
inbound_auth_header_stripping
origin_form_request_enforcement
redirect_ssrf_rejection
generic_forward_proxy_rejection
byte_preserving_streaming
streaming_cancellation
two_attempt_limit
safe_same_route_retry_not_sent
prebody_401_alternate
prebody_403_alternate
prebody_429_alternate
single_retry_slot_exclusivity
provider_5xx_pass_through
partial_send_no_replay
cancellation_no_replay
started_response_no_replay
transport_failure_no_cross_account
replay_budget_overflow_no_alternate
sidecar_memory_budget
reservation_release_on_cancellation
reservation_release_on_overflow
reservation_release_on_teardown
exact_model_preservation
route_identity_admission
identity_conflict_fail_closed
route_readiness_ordering
lease_state_redaction
stale_lease_reactive_routing
unavailable_lease_reactive_routing
sticky_least_loaded_selection
graceful_teardown
abrupt_death_reclamation
resident_absence
bounded_reset_wait
typed_all_exhausted_429
trusted_retry_after
all_exhausted_no_loop
all_exhausted_no_invented_capacity
accepted_rejected_counter_reconciliation
advisory_usage_default_on
advisory_usage_non_authoritative
sidecar_no_proactive_usage_polling
advisory_usage_five_minute_freshness
advisory_usage_valid_empty_negative_cache
advisory_usage_normalized_observations_only
advisory_usage_no_raw_response_persistence
advisory_usage_unknown_field_tolerance
advisory_usage_required_scope
advisory_usage_required_window
advisory_usage_bounded_value
advisory_usage_absolute_reset
advisory_usage_exact_model_scope
advisory_usage_invalid_row_exclusion
advisory_usage_schema_event_redaction
advisory_usage_schema_event_deduplication
advisory_usage_missing_structure_kill_switch
advisory_usage_unsupported_schema_kill_switch
advisory_stale_reactive_fallback
advisory_missing_reactive_fallback
advisory_contradictory_reactive_fallback
advisory_killed_reactive_fallback
advisory_failure_nonblocking
advisory_no_invented_route_readiness
advisory_no_invented_model_readiness
observed_exhaustion_trusted_through_reset
availability_expires_at_deadline
request_path_evidence_precedence
refresh_shared_account_flock
refresh_lock_no_deadlock
refresh_transient_lock_failure_no_quarantine
refresh_transient_store_failure_no_quarantine
refresh_invalid_lineage_quarantine
refresh_quarantine_requires_provider_evidence
refresh_quarantine_requires_reenrollment
refresh_no_stale_backup_restore
refresh_no_forensic_backup_restore'
actual_passes=$(jq -r '.predicates[] | select(.status == "pass") | .id' "$manifest")
[ "$actual_passes" = "$expected_passes" ] || fail "predicate reduction drifted"

counter_fact_ids='aggregate_accepted_request_count_is_one
aggregate_rejected_request_count_is_one
aggregate_request_counts_reconcile_with_ids'
while IFS= read -r fact_id; do
  failed_observation="$TMP/${fact_id}-failed.json"
  failed_counter_manifest="$TMP/${fact_id}-manifest.json"
  jq --arg fact_id "$fact_id" \
    '(.facts[] | select(.id == $fact_id)).status = "fail"' \
    "$OBSERVATION" >"$failed_observation"
  "$PREDICATES" reduce-stage2 \
    "$failed_observation" \
    "$failed_counter_manifest" \
    "$candidate_sha" \
    "$candidate_tree" \
    "$workflow_run_id" \
    "$workflow_run_attempt" \
    "$gf_target_class"
  jq -e --slurpfile positive_manifest "$manifest" '
    [.predicates[] | {id: .id, status: .status}]
    ==
    (
      $positive_manifest[0].predicates
      | map({id: .id, status: .status})
      | .[69].status = "fail"
    )
  ' "$failed_counter_manifest" >/dev/null ||
    fail "${fact_id} did not exclusively fail counter reconciliation"
done <<<"$counter_fact_ids"

broker_mapping_fact_ids='route_identity_admission
identity_conflict_fail_closed
route_readiness_ordering
lease_state_redaction
stale_lease_reactive_routing
unavailable_lease_reactive_routing
sticky_least_loaded_selection'
while IFS= read -r fact_id; do
  failed_observation="$TMP/${fact_id}-failed.json"
  failed_mapping_manifest="$TMP/${fact_id}-manifest.json"
  jq --arg fact_id "$fact_id" \
    '(.facts[] | select(.id == $fact_id)).status = "fail"' \
    "$OBSERVATION" >"$failed_observation"
  "$PREDICATES" reduce-stage2 \
    "$failed_observation" \
    "$failed_mapping_manifest" \
    "$candidate_sha" \
    "$candidate_tree" \
    "$workflow_run_id" \
    "$workflow_run_attempt" \
    "$gf_target_class"
  jq -e --arg predicate_id "$fact_id" --slurpfile positive_manifest "$manifest" '
    [.predicates[] | {id: .id, status: .status}]
    ==
    (
      $positive_manifest[0].predicates
      | map({id: .id, status: .status})
      | map(if .id == $predicate_id then .status = "fail" else . end)
    )
  ' "$failed_mapping_manifest" >/dev/null ||
    fail "${fact_id} did not exclusively fail its broker mapping predicate"
done <<<"$broker_mapping_fact_ids"

expect_rejected "$VERIFY" verify \
  "$TMP/missing.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

printf '%s\n' '{not-json' >"$TMP/malformed.json"
expect_rejected "$VERIFY" verify \
  "$TMP/malformed.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

expect_rejected "$VERIFY" verify \
  "$OBSERVATION" 0000000000000000000000000000000000000000 "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
expect_rejected "$VERIFY" verify \
  "$OBSERVATION" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" 3 "$gf_target_class"

jq '.facts[1].id = .facts[0].id' "$OBSERVATION" >"$TMP/duplicate.json"
expect_rejected "$VERIFY" verify \
  "$TMP/duplicate.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

jq '.facts[0].id = "unknown_fact"' "$OBSERVATION" >"$TMP/unknown.json"
expect_rejected "$VERIFY" verify \
  "$TMP/unknown.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

jq 'del(.facts[0])' "$OBSERVATION" >"$TMP/missing-fact.json"
expect_rejected "$VERIFY" verify \
  "$TMP/missing-fact.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

jq '.unexpected = true' "$OBSERVATION" >"$TMP/extra-field.json"
expect_rejected "$VERIFY" verify \
  "$TMP/extra-field.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

ln -s "$OBSERVATION" "$TMP/symlink.json"
expect_rejected "$VERIFY" verify \
  "$TMP/symlink.json" "$candidate_sha" "$candidate_tree" \
  "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"

jq '(.facts[] | select(.id == "listener_bound_ipv4_loopback")).status = "fail"' \
  "$OBSERVATION" >"$TMP/one-failed-fact.json"
expect_rejected "$VERIFY" require-pass \
  "$TMP/one-failed-fact.json" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$workflow_run_id" \
  "$workflow_run_attempt" \
  "$gf_target_class"
failed_manifest="$TMP/failed-manifest.json"
"$PREDICATES" reduce-stage2 \
  "$TMP/one-failed-fact.json" \
  "$failed_manifest" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$workflow_run_id" \
  "$workflow_run_attempt" \
  "$gf_target_class"
jq -e '.predicates[] | select(.id == "loopback_sidecar_bind" and .status == "fail")' \
  "$failed_manifest" >/dev/null || fail "failed fact did not fail its owning predicate"
expect_rejected "$PREDICATES" require-stage2-slice \
  v02-stage2-conformance "$failed_manifest"

echo "smoke-v02-stage2-observation: ok"
