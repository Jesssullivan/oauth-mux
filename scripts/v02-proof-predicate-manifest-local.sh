#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/v02-proof-predicate-manifest-local.sh emit-missing <target> <output.json>
  scripts/v02-proof-predicate-manifest-local.sh verify <target> <manifest.json>
  scripts/v02-proof-predicate-manifest-local.sh require-pass <target> <manifest.json>
  scripts/v02-proof-predicate-manifest-local.sh require-incomplete <target> <manifest.json>
  scripts/v02-proof-predicate-manifest-local.sh require-all-missing <target> <manifest.json>
USAGE
}

fail() {
  echo "v02-proof-predicate-manifest: $*" >&2
  exit 1
}

canonical_predicates() {
  case "$1" in
    v02-stage2-conformance)
      cat <<'EOF'
provider_egress_denial
provider_call_count_zero
one_sidecar_per_managed_child
capability_carrier
loopback_sidecar_bind
capability_memory_only
capability_256bit_base64url
capability_constant_time_validation
capability_revocation_on_teardown
bad_token_zero_call_rejection
inbound_auth_header_stripping
elected_oauth_credential_injection
managed_launch_fail_closed
explicit_direct_fallback_policy
origin_form_request_enforcement
fixed_origin_enforcement
system_tls_verification
redirect_ssrf_rejection
generic_forward_proxy_rejection
resident_request_body_forwarding_rejection
evidence_allowlist_redaction
byte_preserving_streaming
streaming_cancellation
two_attempt_limit
safe_same_route_retry_not_sent
prebody_401_alternate
prebody_403_alternate
prebody_429_alternate
single_retry_slot_exclusivity
provider_5xx_pass_through
ambiguous_send_no_replay
partial_send_no_replay
cancellation_no_replay
started_response_no_replay
transport_failure_no_cross_account
replay_budget_overflow_no_alternate
request_memory_budget
sidecar_memory_budget
host_memory_budget
atomic_memory_reservations
stale_reservation_reclamation
reservation_release_on_cancellation
reservation_release_on_overflow
reservation_release_on_teardown
known_oversize_stream_once
chunked_unknown_stream_once_transition
stream_once_backpressure
no_request_disk_spooling
exact_model_preservation
route_identity_admission
identity_conflict_fail_closed
route_readiness_ordering
deterministic_shared_leases
lease_state_redaction
stale_lease_owner_cleanup
stale_lease_reactive_routing
unavailable_lease_reactive_routing
sticky_least_loaded_selection
graceful_teardown
abrupt_death_reclamation
resident_absence
resident_restart_session_independence
resident_not_session_proxy
bounded_reset_wait
typed_all_exhausted_429
trusted_retry_after
all_exhausted_no_loop
all_exhausted_no_harness_restart
all_exhausted_no_invented_capacity
accepted_rejected_counter_reconciliation
advisory_usage_default_on
advisory_usage_non_authoritative
advisory_usage_reader_resident_owned
advisory_usage_fixed_endpoint
advisory_usage_polling_resident_owned
advisory_usage_cache_resident_owned
sidecar_no_proactive_usage_polling
advisory_usage_read_coalescing
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
advisory_resident_unavailable_reactive_fallback
advisory_failure_nonblocking
advisory_no_invented_route_readiness
advisory_no_invented_model_readiness
observed_exhaustion_trusted_through_reset
availability_expires_at_deadline
request_path_evidence_precedence
refresh_elected_account_only
refresh_request_boundary_lead_window
proactive_refresh_resident_owned
refresh_shared_account_flock
refresh_lock_bounded_acquisition
refresh_lock_no_deadlock
refresh_lock_no_starvation
refresh_single_writer
refresh_transient_lock_failure_no_quarantine
refresh_transient_transport_failure_no_quarantine
refresh_transient_endpoint_failure_no_quarantine
refresh_transient_store_failure_no_quarantine
refresh_expired_lineage_quarantine
refresh_reused_lineage_quarantine
refresh_revoked_lineage_quarantine
refresh_invalid_lineage_quarantine
refresh_quarantine_requires_provider_evidence
refresh_quarantine_requires_reenrollment
refresh_no_stale_backup_restore
refresh_no_forensic_backup_restore
EOF
      ;;
    v02-benchmark)
      cat <<'EOF'
routing_auth_latency
streaming_throughput
idle_rss
replay_memory_pressure
stale_reservation_cleanup
fairness_20_sessions_50_accounts
EOF
      ;;
    *)
      fail "unsupported v0.2 proof target: $1"
      ;;
  esac
}

expected_predicates_json() {
  canonical_predicates "$1" | jq -R -s 'split("\n") | map(select(length > 0))'
}

verify_manifest() {
  local target="$1"
  local manifest="$2"
  local expected

  [ -f "$manifest" ] || fail "predicate manifest is missing"
  expected="$(expected_predicates_json "$target")"

  jq -s -e \
    --arg target "$target" \
    --argjson expected "$expected" \
    '
      if length != 1 then
        false
      else
        .[0] as $manifest
        | (
            (($manifest | type) == "object")
            and (($manifest | keys) == ["predicates", "schema_version", "target"])
            and ($manifest.schema_version == 1)
            and ($manifest.target == $target)
            and (($manifest.predicates | type) == "array")
            and all(
              $manifest.predicates[];
              (
                ((. | type) == "object")
                and ((. | keys) == ["id", "status"])
                and ((.id | type) == "string")
                and ((.status | type) == "string")
                and ((.status == "pass") or (.status == "fail") or (.status == "missing"))
              )
            )
            and (($manifest.predicates | map(.id)) == $expected)
            and (($manifest.predicates | map(.id) | unique | length) == ($expected | length))
          )
      end
    ' "$manifest" >/dev/null ||
    fail "predicate manifest does not match the canonical ${target} contract"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

mode="${1:-}"
target="${2:-}"
manifest="${3:-}"

case "$mode" in
  emit-missing)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    expected="$(expected_predicates_json "$target")"
    tmp_manifest="${manifest}.tmp.$$"
    trap 'rm -f "$tmp_manifest"' EXIT HUP INT TERM
    jq -n \
      --arg target "$target" \
      --argjson expected "$expected" \
      '{
        schema_version: 1,
        target: $target,
        predicates: [$expected[] | {id: ., status: "missing"}]
      }' >"$tmp_manifest"
    mv "$tmp_manifest" "$manifest"
    trap - EXIT HUP INT TERM
    verify_manifest "$target" "$manifest"
    ;;

  verify)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    verify_manifest "$target" "$manifest"
    ;;

  require-pass)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    verify_manifest "$target" "$manifest"
    if jq -e 'all(.predicates[]; .status == "pass")' "$manifest" >/dev/null; then
      exit 0
    fi
    jq -c '
      {
        schema_version: .schema_version,
        target: .target,
        result: "incomplete",
        predicates: [.predicates[] | select(.status != "pass")]
      }
    ' "$manifest" >&2
    exit 3
    ;;

  require-incomplete)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    verify_manifest "$target" "$manifest"
    jq -e '
      any(
        .predicates[];
        ((.status == "fail") or (.status == "missing"))
      )
    ' "$manifest" >/dev/null ||
      fail "failed ${target} run must contain at least one fail or missing predicate"
    ;;

  require-all-missing)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    verify_manifest "$target" "$manifest"
    jq -e 'all(.predicates[]; .status == "missing")' "$manifest" >/dev/null ||
      fail "current ${target} manifest must mark every predicate missing"
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage
    exit 2
    ;;
esac
