#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/v02-stage2-observation-local.sh verify <observations.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
  scripts/v02-stage2-observation-local.sh require-pass <observations.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
USAGE
}

fail() {
  echo "v02-stage2-observation: $*" >&2
  exit 1
}

require_sha() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] ||
    fail "${label} must be exactly 40 lowercase hexadecimal characters"
}

require_positive_integer() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "${label} must be a positive integer"
}

expected_facts_json() {
  cat <<'EOF' | jq -R -s 'split("\n") | map(select(length > 0))'
listener_bound_ipv4_loopback
carrier_is_canonical_256bit_base64url
valid_capability_reaches_fake_once
invalid_capability_returns_401
invalid_capability_adds_zero_fake_calls
invalid_capability_observation_is_fresh
aggregate_accepted_request_count_is_one
aggregate_rejected_request_count_is_one
aggregate_request_counts_reconcile_with_ids
caller_auth_headers_absent_upstream
forwarding_identity_headers_absent_upstream
hop_headers_absent_upstream
required_safe_headers_present_upstream
invalid_origin_requests_return_400
forward_proxy_requests_return_400
invalid_origin_and_proxy_requests_add_zero_fake_calls
redirect_returns_local_502
redirect_is_not_followed
streaming_prefix_arrives_before_upstream_completion
streaming_body_arrives_byte_preserved
streaming_uses_one_fake_call
provider_5xx_status_and_body_pass_through
provider_5xx_uses_one_fake_call
prebody_401_consumes_one_alternate
alternate_success_records_two_attempts
first_attempt_body_forwarded_byte_exact
alternate_replay_body_byte_exact
prebody_403_consumes_one_alternate
prebody_429_consumes_alternate_after_wait
pre_alternate_wait_within_bound
wait_beyond_max_returns_local_429
wait_beyond_deadline_returns_local_429
presend_fault_consumes_one_same_route_retry
transport_failure_never_contacts_alternate
same_identity_alternate_delivers_original
alternate_slot_transport_fail_adds_no_retry
same_route_retry_401_adds_no_alternate
alternate_failure_no_third_attempt
started_response_never_replayed
cancellation_releases_reservation_to_zero
cancellation_makes_no_replay
streaming_cancellation_single_attempt
stream_once_cancellation_keeps_latch_no_replay
stream_once_cancellation_releases_reservation
oversize_body_streams_once_refuses_alternate
sidecar_budget_exhaustion_forces_stream_once
overflow_releases_reservation_next_unaffected
all_exhausted_returns_bounded_429
all_exhausted_propagates_minimum_trusted_reset
all_exhausted_without_reset_omits_retry_after
all_exhausted_delivers_typed_429_not_200
all_exhausted_ignores_malformed_reset
no_alternate_emits_single_uniform_terminal
same_identity_pool_emits_single_uniform_terminal
routed_alternate_completes_with_no_resident
abrupt_death_mid_alternate_reclaims_to_zero
teardown_holds_then_releases_reservation
teardown_converges_within_bound
capability_revoked_after_teardown_rejects
partial_request_teardown_no_replay_bounded
sequential_routed_requests_release_each_time
EOF
}

verify_observations() {
  local observations="$1"
  local candidate_sha="$2"
  local candidate_tree="$3"
  local workflow_run_id="$4"
  local workflow_run_attempt="$5"
  local gf_target_class="$6"
  local expected_facts

  [ -f "$observations" ] && [ ! -L "$observations" ] ||
    fail "observation artifact must be a regular non-symlink file"
  require_sha candidate_sha "$candidate_sha"
  require_sha candidate_tree "$candidate_tree"
  require_positive_integer workflow_run_id "$workflow_run_id"
  require_positive_integer workflow_run_attempt "$workflow_run_attempt"
  [ "$gf_target_class" = "tinyland-nix" ] || fail "unexpected gf_target_class"
  expected_facts="$(expected_facts_json)"

  jq -s -e \
    --arg candidate_sha "$candidate_sha" \
    --arg candidate_tree "$candidate_tree" \
    --argjson workflow_run_id "$workflow_run_id" \
    --argjson workflow_run_attempt "$workflow_run_attempt" \
    --arg gf_target_class "$gf_target_class" \
    --argjson expected_facts "$expected_facts" \
    '
      if length != 1 then
        false
      else
        .[0] as $artifact
        | (
            (($artifact | type) == "object")
            and (($artifact | keys) == [
              "candidate_sha",
              "candidate_tree",
              "facts",
              "gf_target_class",
              "schema_version",
              "target",
              "workflow_run_attempt",
              "workflow_run_id"
            ])
            and ($artifact.schema_version == 1)
            and ($artifact.target == "v02-stage2-conformance")
            and ($artifact.candidate_sha == $candidate_sha)
            and ($artifact.candidate_tree == $candidate_tree)
            and ($artifact.workflow_run_id == $workflow_run_id)
            and (($artifact.workflow_run_id | type) == "number")
            and ($artifact.workflow_run_attempt == $workflow_run_attempt)
            and (($artifact.workflow_run_attempt | type) == "number")
            and ($artifact.gf_target_class == $gf_target_class)
            and (($artifact.facts | type) == "array")
            and all(
              $artifact.facts[];
              (
                ((. | type) == "object")
                and ((. | keys) == ["id", "status"])
                and ((.id | type) == "string")
                and ((.status == "pass") or (.status == "fail"))
              )
            )
            and (($artifact.facts | map(.id)) == $expected_facts)
            and (($artifact.facts | map(.id) | unique | length) == ($expected_facts | length))
          )
      end
    ' "$observations" >/dev/null ||
    fail "observation artifact does not match the exact candidate-bound schema"
}

require_observations_pass() {
  verify_observations "$@"
  jq -e 'all(.facts[]; .status == "pass")' "$1" >/dev/null ||
    fail "Stage 2 observer did not exercise every fixed fact successfully"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

case "${1:-}" in
  verify)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    verify_observations "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  require-pass)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    require_observations_pass "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
