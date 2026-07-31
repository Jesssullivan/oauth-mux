#!/usr/bin/env sh
# Deterministic fake-gh guard for generic and immutable-candidate validation.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/remote-validate.sh"
PROVENANCE="$ROOT/scripts/v02-proof-provenance-local.sh"
PREDICATES="$ROOT/scripts/v02-proof-predicate-manifest-local.sh"
OBSERVATIONS="$ROOT/scripts/v02-stage2-observation-local.sh"
METRICS="$ROOT/scripts/v02-benchmark-metrics-local.sh"
READINESS="$ROOT/scripts/v02-prerelease-readiness-local.sh"
READINESS_GENERATOR="$ROOT/scripts/v02-prerelease-bundle.zig"
WORKFLOW="$ROOT/.github/workflows/remote-validate.yml"
JUSTFILE="$ROOT/justfile"

fail() {
  echo "smoke-remote-validate-contract: $*" >&2
  exit 1
}

assert_status() {
  expected="$1"
  actual="$2"
  label="$3"
  [ "$actual" -eq "$expected" ] ||
    fail "$label: expected status $expected, got $actual"
}

expect_fake_status() (
  expected="$1"
  label="$2"
  shift 2
  set +e
  "$@" >"$tmp_dir/${label}.out" 2>&1
  actual=$?
  set -e
  assert_status "$expected" "$actual" "$label"
)

bash -n "$SCRIPT"
bash -n "$PROVENANCE"
bash -n "$PREDICATES"
bash -n "$OBSERVATIONS"
bash -n "$METRICS"
bash -n "$READINESS"
zig fmt --check "$READINESS_GENERATOR"
grep -F 'release_manifest.v0_2_prerelease_targets' "$READINESS_GENERATOR" >/dev/null ||
  fail "readiness fixture generator must consume the Zig target authority"
grep -F 'release_manifest.renderV02PrereleaseResolved' "$READINESS_GENERATOR" >/dev/null ||
  fail "readiness fixture generator must use the Zig resolved-manifest renderer"
if grep -F 'release_assets:' "$READINESS" >/dev/null; then
  fail "readiness shell must not duplicate the Zig release asset table"
fi

grep -F 'candidate_sha:' "$WORKFLOW" >/dev/null ||
  fail "workflow must expose candidate_sha"
grep -F 'candidate_ref:' "$WORKFLOW" >/dev/null ||
  fail "workflow must expose canonical candidate_ref"
grep -F 'OMUX_V02_WORKFLOW_EVENT_REF: ${{ github.ref }}' "$WORKFLOW" >/dev/null ||
  fail "workflow must bind candidate_ref to github.ref"
grep -F 'ref: ${{ inputs.candidate_sha }}' "$WORKFLOW" >/dev/null ||
  fail "v0.2 checkout must use candidate_sha"
[ "$(grep -Fc 'uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4' "$WORKFLOW")" -eq 2 ] ||
  fail "workflow must pin both official checkout actions"
[ "$(grep -Fc 'uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4' "$WORKFLOW")" -eq 5 ] ||
  fail "workflow must pin every artifact upload action"
grep -F 'name: Checkout generic validation ref' "$WORKFLOW" >/dev/null ||
  fail "generic validation must retain default checkout behavior"
grep -F "OMUX_REMOTE_TARGET: \${{ inputs.target || 'e2e' }}" "$WORKFLOW" >/dev/null ||
  fail "scheduled validation must retain the e2e default"
grep -F 'set -euo pipefail' "$WORKFLOW" >/dev/null ||
  fail "workflow commands must use strict mode without xtrace"
if grep -F 'set -euxo pipefail' "$WORKFLOW" >/dev/null; then
  fail "workflow must disable xtrace before endpoint/config expansion"
fi
grep -F 'name: v02-proof-provenance-${{ github.run_attempt }}' "$WORKFLOW" >/dev/null ||
  fail "provenance artifact must be attempt-scoped"
grep -F 'name: v02-proof-predicates-${{ inputs.target }}-${{ github.run_attempt }}' "$WORKFLOW" >/dev/null ||
  fail "predicate artifact must be separate and attempt-scoped"
grep -F 'name: v02-stage2-observations-${{ github.run_attempt }}' "$WORKFLOW" >/dev/null ||
  fail "Stage 2 observation artifact must be separate and attempt-scoped"
grep -F 'path: v02-stage2-observations.json' "$WORKFLOW" >/dev/null ||
  fail "workflow must upload the typed Stage 2 observation artifact"
grep -F 'return "$observer_status"' "$WORKFLOW" >/dev/null ||
  fail "a failed Stage 2 observer must fail the proof run"
grep -F 'OMUX_REMOTE_STAGE2_TIMEOUT:-20m' "$WORKFLOW" >/dev/null ||
  fail "the Stage 2 observer must run under a bounded timeout"
grep -F 'rm -f "${GITHUB_WORKSPACE}/v02-stage2-observations.json.tmp"' "$WORKFLOW" >/dev/null ||
  fail "a killed Stage 2 observer must not strand its atomic-write temporary"
grep -F 'name: v02-proof-benchmark-metrics-${{ github.run_attempt }}' "$WORKFLOW" >/dev/null ||
  fail "benchmark metrics artifact must be attempt-scoped"
grep -F 'path: v02-benchmark-metrics.json' "$WORKFLOW" >/dev/null ||
  fail "workflow must upload the strict benchmark metrics file"
grep -F "if: \${{ always() && inputs.target == 'v02-benchmark' }}" "$WORKFLOW" >/dev/null ||
  fail "only benchmark runs may upload benchmark metrics"
grep -F 'v02-proof-predicate-manifest-local.sh require-pass' "$WORKFLOW" >/dev/null ||
  fail "v0.2 targets must fail while predicates are missing"
grep -F 'v02-proof-predicate-manifest-local.sh emit-missing' "$WORKFLOW" >/dev/null ||
  fail "v0.2 targets must emit the canonical predicate manifest"
grep -F 'v02-benchmark-metrics-local.sh emit-missing' "$WORKFLOW" >/dev/null ||
  fail "benchmark target must emit strict metrics before failing closed"
grep -F 'name: v02-prerelease-readiness-${{ github.run_attempt }}' "$WORKFLOW" >/dev/null ||
  fail "prerelease readiness artifact must be attempt-scoped"
grep -F 'path: ${{ runner.temp }}/v02-prerelease-readiness' "$WORKFLOW" >/dev/null ||
  fail "prerelease readiness output must stay outside the candidate checkout"
grep -F 'bash ./scripts/v02-prerelease-readiness-local.sh run' "$WORKFLOW" >/dev/null ||
  fail "workflow must execute the bounded readiness bundle producer"
grep -F 'OMUX_REMOTE_PRERELEASE_TIMEOUT:-20m' "$WORKFLOW" >/dev/null ||
  fail "prerelease readiness must run under a bounded timeout"
grep -F 'OMUX_V02_GF_ACTION_SHA: 2357988536f1f6258291c363e1428962b6cced1b' "$WORKFLOW" >/dev/null ||
  fail "workflow must bind provenance to the audited GF action commit"
if grep -F 'missing_predicates=' "$WORKFLOW" >/dev/null; then
  fail "workflow must use machine-readable predicate manifests"
fi

grep -F 'v02-stage1-local CANDIDATE_SHA:' "$JUSTFILE" >/dev/null ||
  fail "Stage 1 signature must require CANDIDATE_SHA"
grep -F 'assert-local-candidate "{{CANDIDATE_SHA}}"' "$JUSTFILE" >/dev/null ||
  fail "Stage 1 must bind local HEAD to CANDIDATE_SHA"
grep -F 'local_debug_only' "$JUSTFILE" >/dev/null ||
  fail "Stage 1 must remain local_debug_only"
for target in v02-stage2-conformance v02-benchmark v02-prerelease-readiness; do
  grep -F "${target} \$CANDIDATE_SHA \$REF:" "$JUSTFILE" >/dev/null ||
    fail "$target recipe must export candidate SHA and ref"
  grep -F "remote-validate.sh ${target} \"\$REF\" --candidate-sha \"\$CANDIDATE_SHA\"" "$JUSTFILE" >/dev/null ||
    fail "$target recipe must pass exported parameters to the immutable-candidate dispatcher"
done
if grep -E 'remote-validate\.sh v02-(stage2-conformance|benchmark|prerelease-readiness).*\{\{(REF|CANDIDATE_SHA)\}\}' "$JUSTFILE" >/dev/null; then
  fail "v0.2 remote recipes must not interpolate caller-controlled parameters into shell source"
fi

grep -F -- '--include' "$SCRIPT" >/dev/null ||
  fail "ref lookup must inspect HTTP status"
grep -F 'http_status" = "404"' "$SCRIPT" >/dev/null ||
  fail "ref lookup must distinguish 404 absence"
grep -F -- '-f "candidate_ref=$candidate_ref"' "$SCRIPT" >/dev/null ||
  fail "dispatcher must carry canonical candidate_ref"
grep -F 'assert_exact_regular_file' "$SCRIPT" >/dev/null ||
  fail "downloaded artifacts must have exact regular file sets"
grep -F 'v02-proof-predicate-manifest-local.sh" require-incomplete' "$SCRIPT" >/dev/null ||
  fail "failed runs must reconcile canonical incomplete predicate manifests"
grep -F 'v02-proof-predicate-manifest-local.sh" reduce-stage2' "$SCRIPT" >/dev/null ||
  fail "the auditor must independently reduce Stage 2 observations"
grep -F 'v02-proof-predicate-manifest-local.sh" require-stage2-slice' "$SCRIPT" >/dev/null ||
  fail "the auditor must enforce the exact observed Stage 2 slice"
grep -F -- '--name "v02-prerelease-readiness-${workflow_run_attempt}"' "$SCRIPT" >/dev/null ||
  fail "dispatcher must download the attempt-scoped readiness bundle"
grep -F 'v02-prerelease-readiness-local.sh" verify' "$SCRIPT" >/dev/null ||
  fail "dispatcher must independently verify the downloaded readiness bundle"
grep -F 'nix develop "$repo_root" --command bash "${script_dir}/v02-prerelease-readiness-local.sh" verify' "$SCRIPT" >/dev/null ||
  fail "dispatcher must prefer the repository-managed verifier toolchain"
if grep -F 'v02-proof-predicate-manifest-local.sh" require-all-missing' "$SCRIPT" >/dev/null; then
  fail "failed-run reconciliation must not require every predicate to be missing"
fi
if grep -F -- '--ref "$candidate_sha"' "$SCRIPT" >/dev/null; then
  fail "v0.2 workflow dispatch must never use a raw SHA ref"
fi
grep -F 'fromdateiso8601' "$PROVENANCE" >/dev/null ||
  fail "provenance timestamps must be parsed as UTC instants"
grep -F -- '--ignored=matching' "$PROVENANCE" >/dev/null ||
  fail "checkout verification must reject ignored as well as tracked and untracked dirt"
grep -F 'assert-post-run' "$WORKFLOW" >/dev/null ||
  fail "workflow must verify post-run candidate and GF bytes before provenance"
grep -F 'gf_action_sha' "$PROVENANCE" >/dev/null ||
  fail "provenance must carry the audited GF action commit"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/omux-remote-contract.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"

# Zig 0.14.1 creates an empty repo-local .zig-cache/tmp even when explicit
# cache roots are supplied. Readiness may remove only that owned empty shape.
readiness_cache_root="$tmp_dir/readiness-cache-contract"
readiness_cache_bin="$readiness_cache_root/bin"
mkdir -p "$readiness_cache_root/scripts" "$readiness_cache_bin"
cp "$READINESS" "$readiness_cache_root/scripts/v02-prerelease-readiness-local.sh"
cat >"$readiness_cache_bin/jq" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod +x "$readiness_cache_bin/jq"
cat >"$readiness_cache_bin/zig" <<'EOF'
#!/usr/bin/env sh
set -eu
mkdir -p .zig-cache/tmp
if [ "${FAKE_ZIG_EXTRA_RESIDUE:-0}" = 1 ]; then
  printf 'unexpected\n' >.zig-cache/unexpected
fi
case "${1:-}" in
  run)
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
      shift
    done
    [ "${1:-}" = "--" ]
    shift
    mkdir -p "$1/artifacts"
    printf '{}\n' >"$1/resolved-manifest.json"
    ;;
  build)
    if [ -n "${FAKE_ZIG_BUILD_STATUS:-}" ]; then
      exit "$FAKE_ZIG_BUILD_STATUS"
    fi
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod +x "$readiness_cache_bin/zig"
(
  cd "$readiness_cache_root"
  PATH="$readiness_cache_bin:$PATH" \
    bash scripts/v02-prerelease-readiness-local.sh emit \
      "$readiness_cache_root/bundle-clean" \
      1111111111111111111111111111111111111111 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      424242 2 tinyland-nix
  [ ! -e .zig-cache ] && [ ! -L .zig-cache ] ||
    fail "readiness must remove the exact empty repo-local Zig cache it owns"

  set +e
  FAKE_ZIG_EXTRA_RESIDUE=1 PATH="$readiness_cache_bin:$PATH" \
    bash scripts/v02-prerelease-readiness-local.sh emit \
      "$readiness_cache_root/bundle-extra" \
      1111111111111111111111111111111111111111 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      424242 2 tinyland-nix \
      >"$readiness_cache_root/extra-residue.out" 2>&1
  readiness_extra_status=$?
  set -e
  [ "$readiness_extra_status" -ne 0 ] ||
    fail "readiness must fail when repo-local Zig cache contains extra residue"
  [ -f .zig-cache/unexpected ] ||
    fail "readiness must not delete unexpected repo-local Zig cache residue"

  set +e
  PATH="$readiness_cache_bin:$PATH" \
    bash scripts/v02-prerelease-readiness-local.sh emit \
      "$readiness_cache_root/bundle-preexisting" \
      1111111111111111111111111111111111111111 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      424242 2 tinyland-nix \
      >"$readiness_cache_root/preexisting-cache.out" 2>&1
  readiness_preexisting_status=$?
  set -e
  [ "$readiness_preexisting_status" -eq 0 ] ||
    fail "readiness must succeed when repo-local Zig cache predates the invocation"
  [ -f .zig-cache/unexpected ] ||
    fail "readiness must preserve a pre-existing repo-local Zig cache"

  rm -rf .zig-cache
  set +e
  FAKE_ZIG_BUILD_STATUS=42 PATH="$readiness_cache_bin:$PATH" \
    bash scripts/v02-prerelease-readiness-local.sh emit \
      "$readiness_cache_root/bundle-failed" \
      1111111111111111111111111111111111111111 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      424242 2 tinyland-nix \
      >"$readiness_cache_root/failed-gate.out" 2>&1
  readiness_failed_status=$?
  set -e
  [ "$readiness_failed_status" -eq 42 ] ||
    fail "readiness must preserve the exact failed manifest-gate status"
  [ ! -e .zig-cache ] && [ ! -L .zig-cache ] ||
    fail "readiness must remove invocation-owned cache after a failed gate"
  [ ! -e "$readiness_cache_root/bundle-failed" ] &&
    [ ! -L "$readiness_cache_root/bundle-failed" ] ||
    fail "readiness must not publish a bundle after a failed gate"
  if find "$readiness_cache_root" -maxdepth 1 \
    -name 'bundle-failed.tmp.*' -print -quit | grep -q .; then
    fail "readiness must remove its temporary bundle after a failed gate"
  fi

  set +e
  FAKE_ZIG_BUILD_STATUS=42 FAKE_ZIG_EXTRA_RESIDUE=1 \
    PATH="$readiness_cache_bin:$PATH" \
    bash scripts/v02-prerelease-readiness-local.sh emit \
      "$readiness_cache_root/bundle-failed-residue" \
      1111111111111111111111111111111111111111 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      424242 2 tinyland-nix \
      >"$readiness_cache_root/failed-gate-residue.out" 2>&1
  readiness_failed_residue_status=$?
  set -e
  [ "$readiness_failed_residue_status" -eq 42 ] ||
    fail "cache-cleanup failure must not mask the manifest-gate status"
  [ -f .zig-cache/unexpected ] ||
    fail "failed cleanup must preserve unexpected repo-local cache residue"
  grep -F 'repo-local .zig-cache contains files outside the owned tmp directory' \
    "$readiness_cache_root/failed-gate-residue.out" >/dev/null ||
    fail "failed cleanup must emit a cache-residue diagnostic"
  if find "$readiness_cache_root" -maxdepth 1 \
    -name 'bundle-failed-residue.tmp.*' -print -quit | grep -q .; then
    fail "failed cleanup must still remove the temporary bundle"
  fi
)

candidate_sha=1111111111111111111111111111111111111111
candidate_tree=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
moved_sha=2222222222222222222222222222222222222222
moved_tree=cccccccccccccccccccccccccccccccccccccccc
tag_object_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
gf_action_sha=2357988536f1f6258291c363e1428962b6cced1b
run_id=424242
run_attempt=2
gh_log="$tmp_dir/gh.log"
readiness_fixture="$tmp_dir/readiness-fixture"
ZIG_LOCAL_CACHE_DIR="$tmp_dir/zig-local" \
ZIG_GLOBAL_CACHE_DIR="$tmp_dir/zig-global" \
  bash "$READINESS" emit \
    "$readiness_fixture" \
    "$candidate_sha" \
    "$candidate_tree" \
    "$run_id" \
    "$run_attempt" \
    tinyland-nix

# Just must transport caller values through the environment, not render them
# into shell source. This ref is valid Git syntax and executes `touch` under
# the old interpolation form.
just_transport_root="$tmp_dir/just-transport"
mkdir -p "$just_transport_root/scripts"
cat >"$just_transport_root/scripts/remote-validate.sh" <<'EOF'
#!/usr/bin/env sh
set -eu
{
  printf '%s\n' "$#"
  for arg in "$@"; do
    printf '%s\n' "$arg"
  done
} >"$OMUX_JUST_ARGS_LOG"
EOF
chmod +x "$just_transport_root/scripts/remote-validate.sh"
cat >"$just_transport_root/scripts/project-version.sh" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' '0.0.0-test'
EOF
chmod +x "$just_transport_root/scripts/project-version.sh"

injection_ref='refs/heads/proof$(touch${IFS}just-interpolation-ran)'
git check-ref-format "$injection_ref" ||
  fail "Just transport injection fixture must remain a valid Git ref"
for target in v02-stage2-conformance v02-benchmark v02-prerelease-readiness; do
  args_log="$just_transport_root/${target}.args"
  expected_args="$just_transport_root/${target}.expected"
  rm -f "$just_transport_root/just-interpolation-ran"
  (
    cd "$just_transport_root"
    OMUX_JUST_ARGS_LOG="$args_log" \
      just --justfile "$JUSTFILE" --working-directory "$just_transport_root" \
        "$target" "$candidate_sha" "$injection_ref"
  )
  [ ! -e "$just_transport_root/just-interpolation-ran" ] ||
    fail "$target executed command substitution from REF"
  printf '4\n%s\n%s\n--candidate-sha\n%s\n' \
    "$target" "$injection_ref" "$candidate_sha" >"$expected_args"
  cmp -s "$expected_args" "$args_log" ||
    fail "$target did not preserve ref and candidate SHA bytes"
done

stage2_facts_json="$(cat <<'EOF' | jq -R -s 'split("\n") | map(select(length > 0))'
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
route_identity_admission
identity_conflict_fail_closed
route_readiness_ordering
lease_state_redaction
stale_lease_reactive_routing
unavailable_lease_reactive_routing
sticky_least_loaded_selection
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
partial_request_teardown_no_replay_bounded
sequential_routed_requests_release_each_time
advisory_observed_on_every_routed_response
advisory_capped_at_inferred_never_proven
advisory_changes_no_routing_decision
advisory_fresh_window_boundary_exact
advisory_valid_empty_arms_negative_cache
advisory_records_normalized_typed_observation
advisory_surface_and_event_value_free
advisory_tolerates_unknown_fields
advisory_excludes_row_missing_scope
advisory_excludes_row_missing_window
advisory_excludes_row_unbounded_value
advisory_excludes_row_non_absolute_reset
advisory_model_scope_requires_exact_model
advisory_invalid_row_excluded_never_fabricated
advisory_schema_event_redacted_value_free
advisory_one_schema_event_per_fingerprint
advisory_missing_structure_trips_kill
advisory_unsupported_schema_trips_kill
advisory_stale_falls_back_to_reactive
advisory_missing_falls_back_to_reactive
advisory_contradictory_falls_back_to_reactive
advisory_killed_falls_back_to_reactive
advisory_failure_never_blocks_serving
advisory_absent_invents_no_route_readiness
advisory_mismatch_invents_no_model_readiness
reactive_outranks_fresh_advisory
advisory_observation_adds_no_upstream_call
advisory_exhaustion_trusted_through_reset
advisory_availability_expires_at_deadline
refresh_requires_owned_account_flock
account_flock_serializes_cross_actor
account_flock_reentrant_same_actor
transient_lock_failure_skips_endpoint
transient_lock_failure_leaves_no_quarantine
transient_store_failure_skips_endpoint
transient_store_failure_leaves_no_quarantine
invalid_grant_lineage_hard_quarantined
invalid_grant_hard_quarantine_blocks_before_endpoint
hard_tag_refused_without_locked_lineage_proof
hard_quarantine_refuses_reenroll_clearance
indeterminate_quarantine_clears_via_reenroll
quarantine_marker_forbids_stale_backup_restore
stale_backup_restore_marker_rejected
quarantine_recovery_is_provider_reenroll_only
EOF
)"
passing_observations="$tmp_dir/stage2-observations-pass.json"
jq -n \
  --arg candidate_sha "$candidate_sha" \
  --arg candidate_tree "$candidate_tree" \
  --argjson workflow_run_id "$run_id" \
  --argjson workflow_run_attempt "$run_attempt" \
  --argjson facts "$stage2_facts_json" \
  '{
    schema_version: 1,
    target: "v02-stage2-conformance",
    candidate_sha: $candidate_sha,
    candidate_tree: $candidate_tree,
    workflow_run_id: $workflow_run_id,
    workflow_run_attempt: $workflow_run_attempt,
    gf_target_class: "tinyland-nix",
    facts: [$facts[] | {id: ., status: "pass"}]
  }' >"$passing_observations"
"$OBSERVATIONS" verify \
  "$passing_observations" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix
"$OBSERVATIONS" require-pass \
  "$passing_observations" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix

# Predicate manifests accept exactly the canonical ordered set and status enum.
stage2_manifest="$tmp_dir/stage2.json"
benchmark_manifest="$tmp_dir/benchmark.json"
"$PREDICATES" emit-missing v02-stage2-conformance "$stage2_manifest"
"$PREDICATES" emit-missing v02-benchmark "$benchmark_manifest"
"$PREDICATES" require-all-missing v02-stage2-conformance "$stage2_manifest"
"$PREDICATES" require-all-missing v02-benchmark "$benchmark_manifest"
stage2_slice_manifest="$tmp_dir/stage2-slice.json"
"$PREDICATES" reduce-stage2 \
  "$passing_observations" \
  "$stage2_slice_manifest" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$run_id" \
  "$run_attempt" \
  tinyland-nix
"$PREDICATES" require-stage2-slice \
  v02-stage2-conformance "$stage2_slice_manifest"

expected_stage2_ids='provider_egress_denial
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
refresh_no_forensic_backup_restore'
actual_stage2_ids="$(jq -r '.predicates[].id' "$stage2_manifest")"
[ "$actual_stage2_ids" = "$expected_stage2_ids" ] ||
  fail "Stage 2 manifest must match the independent canonical predicate list"

expected_benchmark_ids='routing_auth_latency
streaming_throughput
idle_rss
replay_memory_pressure
stale_reservation_cleanup
fairness_20_sessions_50_accounts'
actual_benchmark_ids="$(jq -r '.predicates[].id' "$benchmark_manifest")"
[ "$actual_benchmark_ids" = "$expected_benchmark_ids" ] ||
  fail "benchmark manifest must cover each canonical budget exactly once"
if jq -e '.predicates[] | select(.id == "predicate_manifest")' \
  "$stage2_manifest" >/dev/null; then
  fail "Stage 2 manifest must not contain the obsolete predicate_manifest entry"
fi

set +e
"$PREDICATES" require-pass v02-stage2-conformance "$stage2_manifest" \
  >"$tmp_dir/stage2-require-pass.out" 2>&1
status=$?
set -e
assert_status 3 "$status" "all-missing Stage 2"

set +e
"$PREDICATES" require-pass v02-benchmark "$benchmark_manifest" \
  >"$tmp_dir/benchmark-require-pass.out" 2>&1
status=$?
set -e
assert_status 3 "$status" "all-missing benchmark"

mixed_manifest="$tmp_dir/mixed.json"
jq '(.predicates[0].status = "pass") | (.predicates[1].status = "fail")' \
  "$stage2_manifest" >"$mixed_manifest"
"$PREDICATES" verify v02-stage2-conformance "$mixed_manifest"
"$PREDICATES" require-incomplete v02-stage2-conformance "$mixed_manifest"
if "$PREDICATES" require-all-missing v02-stage2-conformance \
  "$mixed_manifest" >/dev/null 2>&1; then
  fail "mixed canonical manifest must not satisfy the all-missing stub contract"
fi

all_pass_manifest="$tmp_dir/all-pass.json"
jq '.predicates |= map(.status = "pass")' "$stage2_manifest" >"$all_pass_manifest"
"$PREDICATES" verify v02-stage2-conformance "$all_pass_manifest"
if "$PREDICATES" require-incomplete v02-stage2-conformance \
  "$all_pass_manifest" >/dev/null 2>&1; then
  fail "failed-run reconciliation must reject an all-pass manifest"
fi

single_fail_manifest="$tmp_dir/single-fail.json"
jq '(.predicates |= map(.status = "pass")) | (.predicates[0].status = "fail")' \
  "$stage2_manifest" >"$single_fail_manifest"
"$PREDICATES" require-incomplete v02-stage2-conformance "$single_fail_manifest"

single_missing_manifest="$tmp_dir/single-missing.json"
jq '(.predicates |= map(.status = "pass")) | (.predicates[0].status = "missing")' \
  "$stage2_manifest" >"$single_missing_manifest"
"$PREDICATES" require-incomplete v02-stage2-conformance "$single_missing_manifest"

old_stage2_ids='provider_egress_denial
zero_call_counters
byte_preserving_streaming_and_cancellation
attempt_policy_401_403_429
pass_through_5xx
no_replay_ambiguous_started_oversize
memory_budgets
exact_model_and_identity_admission
abrupt_death_reclamation
resident_absence
bounded_all_exhausted
shared_leases
advisory_usage_endpoint_wiring_and_live_schema_qualification
refresh_at_boundary'
old_stage2_manifest="$tmp_dir/old-stage2-all-pass.json"
jq -n \
  --arg target v02-stage2-conformance \
  --arg ids "$old_stage2_ids" \
  '{
    schema_version: 1,
    target: $target,
    predicates: [
      $ids
      | split("\n")[]
      | select(length > 0)
      | {id: ., status: "pass"}
    ]
  }' >"$old_stage2_manifest"
[ "$(jq '.predicates | length' "$old_stage2_manifest")" -eq 14 ] ||
  fail "legacy Stage 2 regression fixture must contain exactly 14 predicates"
if "$PREDICATES" verify v02-stage2-conformance \
  "$old_stage2_manifest" >/dev/null 2>&1; then
  fail "legacy 14-entry all-pass manifest must be rejected as incomplete"
fi

reject_manifest() {
  label="$1"
  filter="$2"
  variant="$tmp_dir/manifest-${label}.json"
  jq "$filter" "$stage2_manifest" >"$variant"
  if "$PREDICATES" verify v02-stage2-conformance "$variant" >/dev/null 2>&1; then
    fail "predicate manifest must reject ${label}"
  fi
}

reject_manifest unknown-id '.predicates[0].id = "unknown_predicate"'
reject_manifest duplicate-id '.predicates[1].id = .predicates[0].id'
reject_manifest omitted-id '.predicates |= .[0:-1]'
reject_manifest reordered '.predicates[0:2] |= reverse'
reject_manifest invalid-status '.predicates[0].status = "skipped"'
reject_manifest extra-field '.predicates[0].detail = "forbidden"'

# Benchmark metrics require measured values and pinned thresholds, not booleans.
metrics_manifest="$tmp_dir/benchmark-metrics.json"
"$METRICS" emit-missing \
  "$metrics_manifest" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$run_id" \
  "$run_attempt" \
  tinyland-nix
"$METRICS" verify \
  "$metrics_manifest" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix
"$METRICS" require-incomplete \
  "$metrics_manifest" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix

set +e
"$METRICS" require-pass \
  "$metrics_manifest" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix \
  >"$tmp_dir/metrics-require-pass.out" 2>&1
status=$?
set -e
assert_status 3 "$status" "all-missing benchmark metrics"

passing_metrics="$tmp_dir/benchmark-metrics-pass.json"
jq '
  .clock_source = "CLOCK_MONOTONIC"
  | .workload_id = "tin2989-smoke-v1"
  | .measurements.routing_auth_latency += {
      status: "pass", warmup_count: 1000, sample_count: 10000,
      p95_ms: 5, p99_ms: 10
    }
  | .measurements.streaming_throughput += {
      status: "pass", direct_trial_count: 5, broker_trial_count: 5,
      trial_duration_seconds: 30, direct_median_bytes_per_second: 1000,
      broker_median_bytes_per_second: 950, broker_to_direct_ratio: 0.95
    }
  | .measurements.idle_rss += {
      status: "pass", seconds_after_last_request: 60, sample_count: 5,
      sample_interval_seconds: 1, max_rss_bytes: 20971520
    }
  | .measurements.replay_memory += {
      status: "pass", request_peak_bytes: 33554432,
      sidecar_peak_bytes: 67108864, host_peak_bytes: 268435456,
      budget_exhaustion_stream_once: true, no_request_bytes_persisted: true
    }
  | .measurements.stale_reservation_cleanup += {
      status: "pass", cleanup_completed: true,
      stale_owner_count_after_cleanup: 0
    }
  | .measurements.concurrency_fairness += {
      status: "pass", session_count: 20, account_count: 50,
      cycles_per_session: 100, lock_timeout_count: 0,
      missed_completion_count: 0, stale_owner_count_after_cleanup: 0,
      max_minus_min_active_lease_load: 1
    }
' "$metrics_manifest" >"$passing_metrics"
"$METRICS" require-pass \
  "$passing_metrics" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix

failing_metrics="$tmp_dir/benchmark-metrics-fail.json"
jq '
  .measurements.routing_auth_latency.status = "fail"
  | .measurements.routing_auth_latency.p99_ms = 11
' "$passing_metrics" >"$failing_metrics"
"$METRICS" require-incomplete \
  "$failing_metrics" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix

false_pass_metrics="$tmp_dir/benchmark-metrics-false-pass.json"
jq '.measurements.routing_auth_latency.p99_ms = 11' \
  "$passing_metrics" >"$false_pass_metrics"
if "$METRICS" verify \
  "$false_pass_metrics" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix >/dev/null 2>&1; then
  fail "benchmark metrics must reject threshold-failing values marked pass"
fi

missing_metric="$tmp_dir/benchmark-metrics-missing.json"
jq 'del(.measurements.idle_rss)' "$metrics_manifest" >"$missing_metric"
if "$METRICS" verify \
  "$missing_metric" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix >/dev/null 2>&1; then
  fail "benchmark metrics must reject an omitted measurement"
fi

if "$METRICS" verify \
  "$tmp_dir/does-not-exist.json" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix >/dev/null 2>&1; then
  fail "benchmark metrics must reject a missing file"
fi

old_boolean_metrics="$tmp_dir/benchmark-metrics-old-booleans.json"
jq -n \
  --arg candidate_sha "$candidate_sha" \
  --arg candidate_tree "$candidate_tree" \
  --argjson workflow_run_id "$run_id" \
  --argjson workflow_run_attempt "$run_attempt" \
  '{
    schema_version: 1,
    target: "v02-benchmark",
    candidate_sha: $candidate_sha,
    candidate_tree: $candidate_tree,
    workflow_run_id: $workflow_run_id,
    workflow_run_attempt: $workflow_run_attempt,
    gf_target_class: "tinyland-nix",
    clock_source: "CLOCK_MONOTONIC",
    workload_id: "legacy-six-booleans",
    measurements: {
      routing_auth_latency: true,
      streaming_throughput: true,
      idle_rss: true,
      replay_memory_pressure: true,
      stale_reservation_cleanup: true,
      fairness_20_sessions_50_accounts: true
    }
  }' >"$old_boolean_metrics"
if "$METRICS" verify \
  "$old_boolean_metrics" "$candidate_sha" "$candidate_tree" \
  "$run_id" "$run_attempt" tinyland-nix >/dev/null 2>&1; then
  fail "six all-pass booleans must not satisfy the G4 metrics contract"
fi

cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env sh
set -eu

printf '%s\n' "$*" >>"$FAKE_GH_LOG"

emit_ref_response() {
  mode="$1"
  object_type="$2"
  object_sha="$3"
  case "$mode" in
    present)
      printf 'HTTP/2.0 200 OK\r\ncontent-type: application/json\r\n\r\n%s\t%s\n' \
        "$object_type" "$object_sha"
      ;;
    annotated)
      printf 'HTTP/2.0 200 OK\r\ncontent-type: application/json\r\n\r\ntag\t%s\n' \
        "$FAKE_GH_TAG_OBJECT_SHA"
      ;;
    absent)
      printf 'HTTP/2.0 404 Not Found\r\ncontent-type: application/json\r\n\r\n'
      exit 1
      ;;
    auth)
      printf 'HTTP/2.0 403 Forbidden\r\ncontent-type: application/json\r\n\r\n'
      exit 1
      ;;
    transport)
      echo 'fake transport failure' >&2
      exit 1
      ;;
    malformed)
      printf 'HTTP/2.0 200 OK\r\ncontent-type: application/json\r\n\r\ninvalid\n'
      ;;
    *)
      echo "fake gh: unsupported ref mode: $mode" >&2
      exit 2
      ;;
  esac
}

case "${1:-} ${2:-}" in
  "repo view")
    printf '%s\n' 'Jesssullivan/oauth-mux'
    ;;

  "api "*)
    endpoint="${2:-}"
    case "$endpoint" in
      */git/ref/heads/*)
        emit_ref_response "$FAKE_GH_BRANCH_MODE" commit "$FAKE_GH_REF_SHA"
        ;;
      */git/ref/tags/*)
        emit_ref_response "$FAKE_GH_TAG_MODE" commit "$FAKE_GH_REF_SHA"
        ;;
      */git/tags/*)
        if [ "${FAKE_GH_TAG_PEEL_MODE:-present}" != "present" ]; then
          exit 1
        fi
        printf 'commit\t%s\n' "$FAKE_GH_REF_SHA"
        ;;
      */commits/*)
        printf '%s\t%s\n' "$FAKE_GH_RESOLVED_SHA" "$FAKE_GH_RESOLVED_TREE"
        ;;
      */actions/runs/*)
        printf '%s\t%s\n' "$FAKE_GH_RUN_HEAD_SHA" "$FAKE_GH_RUN_ATTEMPT"
        ;;
      *)
        echo "fake gh: unsupported api endpoint: $endpoint" >&2
        exit 2
        ;;
    esac
    ;;

  "workflow run")
    ;;

  "run list")
    printf '%s\n' "$FAKE_GH_RUN_ID"
    ;;

  "run watch")
    exit "$FAKE_GH_WATCH_STATUS"
    ;;

  "run download")
    artifact_name=""
    output_dir=""
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --name)
          shift
          artifact_name="${1:-}"
          ;;
        --dir)
          shift
          output_dir="${1:-}"
          ;;
      esac
      shift || true
    done
    [ -n "$artifact_name" ] || exit 2
    [ -n "$output_dir" ] || exit 2
    mkdir -p "$output_dir"

    case "$artifact_name" in
      "v02-proof-provenance-${FAKE_GH_RUN_ATTEMPT}")
        mode="$FAKE_GH_PROVENANCE_ARTIFACT"
        [ "$mode" != "download-error" ] || exit 1
        [ "$mode" != "missing-file" ] || exit 0

        artifact_tree="$FAKE_GH_RESOLVED_TREE"
        artifact_gf_action_sha="$FAKE_GH_GF_ACTION_SHA"
        started_at_utc=2026-07-17T12:00:00Z
        finished_at_utc=2026-07-17T12:00:01Z
        artifact_fallback=false
        if [ "$FAKE_GH_WATCH_STATUS" -eq 0 ]; then
          artifact_result=passed
        else
          artifact_result=failed
        fi
        case "$mode" in
          wrong-tree) artifact_tree="$FAKE_GH_OTHER_TREE" ;;
          wrong-gf-action) artifact_gf_action_sha="$FAKE_GH_OTHER_SHA" ;;
          invalid-time) started_at_utc=2026-02-30T12:00:00Z ;;
          reversed-time) finished_at_utc=2026-07-17T11:59:59Z ;;
          fallback) artifact_fallback=true ;;
          wrong-result)
            if [ "$artifact_result" = passed ]; then artifact_result=failed; else artifact_result=passed; fi
            ;;
        esac

        jq -n \
          --arg candidate_sha "$FAKE_GH_CANDIDATE_SHA" \
          --arg candidate_tree "$artifact_tree" \
          --arg target "$FAKE_GH_TARGET" \
          --argjson workflow_run_id "$FAKE_GH_RUN_ID" \
          --argjson workflow_run_attempt "$FAKE_GH_RUN_ATTEMPT" \
          --arg gf_action_sha "$artifact_gf_action_sha" \
          --arg started_at_utc "$started_at_utc" \
          --arg finished_at_utc "$finished_at_utc" \
          --arg result "$artifact_result" \
          --argjson local_fallback_occurred "$artifact_fallback" \
          '{
            schema_version: 1,
            candidate_sha: $candidate_sha,
            candidate_tree: $candidate_tree,
            target: $target,
            workflow_run_id: $workflow_run_id,
            workflow_run_attempt: $workflow_run_attempt,
            gf_target_class: "tinyland-nix",
            gf_action_sha: $gf_action_sha,
            started_at_utc: $started_at_utc,
            finished_at_utc: $finished_at_utc,
            result: $result,
            local_fallback_occurred: $local_fallback_occurred
          }' >"$output_dir/v02-proof-provenance.json"
        [ "$mode" != "extra-file" ] || : >"$output_dir/forbidden.txt"
        ;;

      "v02-proof-predicates-${FAKE_GH_TARGET}-${FAKE_GH_RUN_ATTEMPT}")
        mode="$FAKE_GH_PREDICATE_ARTIFACT"
        [ "$mode" != "download-error" ] || exit 1
        [ "$mode" != "missing-file" ] || exit 0

        if [ "$FAKE_GH_TARGET" = "v02-stage2-conformance" ]; then
          "$FAKE_GH_PREDICATE_TOOL" reduce-stage2 \
            "$FAKE_GH_PASSING_OBSERVATIONS" \
            "$output_dir/v02-proof-predicate-manifest.json" \
            "$FAKE_GH_CANDIDATE_SHA" \
            "$FAKE_GH_RESOLVED_TREE" \
            "$FAKE_GH_RUN_ID" \
            "$FAKE_GH_RUN_ATTEMPT" \
            tinyland-nix
        else
          "$FAKE_GH_PREDICATE_TOOL" emit-missing "$FAKE_GH_TARGET" \
            "$output_dir/v02-proof-predicate-manifest.json"
        fi
        case "$mode" in
          unknown)
            filter='.predicates[0].id = "unknown_predicate"'
            ;;
          duplicate)
            filter='.predicates[1].id = .predicates[0].id'
            ;;
          omitted)
            filter='.predicates |= .[0:-1]'
            ;;
          invalid-status)
            filter='.predicates[0].status = "skipped"'
            ;;
          all-pass)
            filter='.predicates |= map(.status = "pass")'
            ;;
          mixed-incomplete)
            filter='(.predicates |= map(.status = "pass")) | (.predicates[1].status = "fail")'
            ;;
          *)
            filter='.'
            ;;
        esac
        jq "$filter" "$output_dir/v02-proof-predicate-manifest.json" \
          >"$output_dir/manifest.tmp"
        mv "$output_dir/manifest.tmp" "$output_dir/v02-proof-predicate-manifest.json"
        [ "$mode" != "extra-file" ] || mkdir "$output_dir/forbidden-directory"
        ;;

      "v02-stage2-observations-${FAKE_GH_RUN_ATTEMPT}")
        mode="$FAKE_GH_OBSERVATION_ARTIFACT"
        [ "$mode" != "download-error" ] || exit 1
        [ "$mode" != "missing-file" ] || exit 0

        observation_file="$output_dir/v02-stage2-observations.json"
        cp "$FAKE_GH_PASSING_OBSERVATIONS" "$observation_file"
        case "$mode" in
          wrong-candidate)
            jq --arg candidate_sha "$FAKE_GH_OTHER_SHA" \
              '.candidate_sha = $candidate_sha' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          stale-attempt)
            jq '.workflow_run_attempt += 1' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          unknown)
            jq '.facts[0].id = "unknown_fact"' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          duplicate)
            jq '.facts[1].id = .facts[0].id' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          omitted)
            jq 'del(.facts[0])' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          invalid-status)
            jq '.facts[0].status = "missing"' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          failed-fact)
            jq '.facts[0].status = "fail"' "$observation_file" \
              >"$output_dir/observation.tmp"
            ;;
          *)
            : >"$output_dir/observation.tmp"
            ;;
        esac
        if [ -s "$output_dir/observation.tmp" ]; then
          mv "$output_dir/observation.tmp" "$observation_file"
        else
          rm -f "$output_dir/observation.tmp"
        fi
        [ "$mode" != "extra-file" ] || : >"$output_dir/forbidden.txt"
        ;;

      "v02-proof-benchmark-metrics-${FAKE_GH_RUN_ATTEMPT}")
        mode="$FAKE_GH_METRICS_ARTIFACT"
        [ "$mode" != "download-error" ] || exit 1
        [ "$mode" != "missing-file" ] || exit 0

        metrics_file="$output_dir/v02-benchmark-metrics.json"
        case "$mode" in
          all-pass)
            cp "$FAKE_GH_PASSING_METRICS" "$metrics_file"
            ;;
          false-pass)
            cp "$FAKE_GH_FALSE_PASS_METRICS" "$metrics_file"
            ;;
          *)
            "$FAKE_GH_METRICS_TOOL" emit-missing \
              "$metrics_file" \
              "$FAKE_GH_CANDIDATE_SHA" \
              "$FAKE_GH_RESOLVED_TREE" \
              "$FAKE_GH_RUN_ID" \
              "$FAKE_GH_RUN_ATTEMPT" \
              tinyland-nix
            ;;
        esac
        case "$mode" in
          malformed)
            jq 'del(.measurements.idle_rss)' "$metrics_file" \
              >"$output_dir/metrics.tmp"
            mv "$output_dir/metrics.tmp" "$metrics_file"
            ;;
          wrong-identity)
            jq --arg candidate_sha "$FAKE_GH_OTHER_SHA" \
              '.candidate_sha = $candidate_sha' "$metrics_file" \
              >"$output_dir/metrics.tmp"
            mv "$output_dir/metrics.tmp" "$metrics_file"
            ;;
        esac
        [ "$mode" != "extra-file" ] || : >"$output_dir/forbidden.txt"
        ;;

      "v02-prerelease-readiness-${FAKE_GH_RUN_ATTEMPT}")
        mode="$FAKE_GH_READINESS_ARTIFACT"
        [ "$mode" != "download-error" ] || exit 1
        cp -R "$FAKE_GH_READINESS_FIXTURE"/. "$output_dir"/
        readiness_manifest="$output_dir/resolved-manifest.json"
        case "$mode" in
          missing-file)
            rm "$readiness_manifest"
            ;;
          extra-file)
            : >"$output_dir/forbidden.txt"
            ;;
          wrong-candidate)
            jq --arg candidate_sha "$FAKE_GH_OTHER_SHA" \
              '.release.source_commit = $candidate_sha' \
              "$readiness_manifest" >"$output_dir/readiness.tmp"
            mv "$output_dir/readiness.tmp" "$readiness_manifest"
            ;;
          wrong-tree)
            jq --arg candidate_tree "$FAKE_GH_OTHER_TREE" \
              '.release.source_tree = $candidate_tree' \
              "$readiness_manifest" >"$output_dir/readiness.tmp"
            mv "$output_dir/readiness.tmp" "$readiness_manifest"
            ;;
          stale-attempt)
            stale_build_id="gf-tinyland-nix-run-${FAKE_GH_RUN_ID}-attempt-$((FAKE_GH_RUN_ATTEMPT + 1))"
            jq --arg build_id "$stale_build_id" \
              '.release.build_id.value = $build_id' \
              "$readiness_manifest" >"$output_dir/readiness.tmp"
            mv "$output_dir/readiness.tmp" "$readiness_manifest"
            ;;
          digest-drift)
            printf 'changed after manifest resolution\n' \
              >>"$output_dir/artifacts/oauth-mux-x86_64-linux.tar.gz"
            ;;
          missing-artifact)
            rm "$output_dir/artifacts/oauth-mux-aarch64-linux.tar.gz"
            ;;
          extra-artifact)
            : >"$output_dir/artifacts/unexpected.txt"
            ;;
        esac
        ;;

      *)
        echo "fake gh: unexpected artifact name: $artifact_name" >&2
        exit 2
        ;;
    esac
    ;;

  *)
    echo "fake gh: unsupported invocation: $*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$fake_bin/gh"

cat >"$fake_bin/nix" <<'EOF'
#!/usr/bin/env sh
set -eu

[ "${1:-}" = develop ] || exit 2
[ "${2:-}" = "$FAKE_NIX_EXPECTED_FLAKE" ] || exit 2
[ "${3:-}" = --command ] || exit 2
shift 3
exec "$@"
EOF
chmod +x "$fake_bin/nix"

run_fake() (
  target="$1"
  shift
  fake_ref_sha="${FAKE_GH_REF_SHA:-$candidate_sha}"
  fake_resolved_sha="${FAKE_GH_RESOLVED_SHA:-$fake_ref_sha}"
  PATH="$fake_bin:$PATH" \
  OMUX_REMOTE_REQUEST_ID=tin2989-contract-smoke \
  FAKE_GH_LOG="$gh_log" \
  FAKE_GH_CANDIDATE_SHA="$candidate_sha" \
  FAKE_GH_REF_SHA="$fake_ref_sha" \
  FAKE_GH_RESOLVED_SHA="$fake_resolved_sha" \
  FAKE_GH_RESOLVED_TREE="${FAKE_GH_RESOLVED_TREE:-$candidate_tree}" \
  FAKE_GH_OTHER_TREE="$moved_tree" \
  FAKE_GH_OTHER_SHA="$moved_sha" \
  FAKE_GH_GF_ACTION_SHA="$gf_action_sha" \
  FAKE_GH_BRANCH_MODE="${FAKE_GH_BRANCH_MODE:-present}" \
  FAKE_GH_TAG_MODE="${FAKE_GH_TAG_MODE:-absent}" \
  FAKE_GH_TAG_OBJECT_SHA="$tag_object_sha" \
  FAKE_GH_RUN_HEAD_SHA="${FAKE_GH_RUN_HEAD_SHA:-$candidate_sha}" \
  FAKE_GH_RUN_ID="$run_id" \
  FAKE_GH_RUN_ATTEMPT="$run_attempt" \
  FAKE_GH_TARGET="${FAKE_GH_TARGET:-$target}" \
  FAKE_GH_WATCH_STATUS="${FAKE_GH_WATCH_STATUS:-3}" \
  FAKE_GH_PROVENANCE_ARTIFACT="${FAKE_GH_PROVENANCE_ARTIFACT:-valid}" \
  FAKE_GH_PREDICATE_ARTIFACT="${FAKE_GH_PREDICATE_ARTIFACT:-valid}" \
  FAKE_GH_PREDICATE_TOOL="$PREDICATES" \
  FAKE_GH_OBSERVATION_ARTIFACT="${FAKE_GH_OBSERVATION_ARTIFACT:-valid}" \
  FAKE_GH_PASSING_OBSERVATIONS="$passing_observations" \
  FAKE_GH_METRICS_ARTIFACT="${FAKE_GH_METRICS_ARTIFACT:-valid}" \
  FAKE_GH_METRICS_TOOL="$METRICS" \
  FAKE_GH_PASSING_METRICS="$passing_metrics" \
  FAKE_GH_FALSE_PASS_METRICS="$false_pass_metrics" \
  FAKE_GH_READINESS_ARTIFACT="${FAKE_GH_READINESS_ARTIFACT:-valid}" \
  FAKE_GH_READINESS_FIXTURE="$readiness_fixture" \
  FAKE_NIX_EXPECTED_FLAKE="$ROOT" \
  ZIG_LOCAL_CACHE_DIR="$tmp_dir/zig-local" \
  ZIG_GLOBAL_CACHE_DIR="$tmp_dir/zig-global" \
    "$SCRIPT" "$target" "$@"
)

# Generic branch/SHA, release version, and no-watch behavior remain unchanged.
: >"$gh_log"
run_fake check generic-branch --no-watch >"$tmp_dir/generic-branch.out"
grep -F 'workflow run remote-validate.yml --repo Jesssullivan/oauth-mux --ref generic-branch' "$gh_log" >/dev/null ||
  fail "generic branch dispatch changed"
if grep -F 'candidate_sha=' "$gh_log" >/dev/null || grep -F '/git/ref/' "$gh_log" >/dev/null; then
  fail "generic dispatch must not enter the v0.2 envelope"
fi

: >"$gh_log"
run_fake check "$candidate_sha" --no-watch >"$tmp_dir/generic-sha.out"
grep -F -- "--ref $candidate_sha" "$gh_log" >/dev/null ||
  fail "generic targets must retain raw SHA dispatch"

: >"$gh_log"
run_fake release-proof release-branch --version 0.1.15 --no-watch >"$tmp_dir/generic-release.out"
grep -F 'target=release-proof' "$gh_log" >/dev/null || fail "generic release target changed"
grep -F 'version=0.1.15' "$gh_log" >/dev/null || fail "generic release version changed"

# Explicit branch uses only branch lookup, dispatches its name, and carries full type.
: >"$gh_log"
(
  FAKE_GH_TAG_MODE=transport \
    expect_fake_status 3 explicit-branch \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
grep -F 'api repos/Jesssullivan/oauth-mux/git/ref/heads/proof-ref --include' "$gh_log" >/dev/null ||
  fail "explicit branch must use status-aware branch lookup"
if grep -F '/git/ref/tags/' "$gh_log" >/dev/null; then
  fail "explicit branch must not depend on tag lookup"
fi
grep -F 'workflow run remote-validate.yml --repo Jesssullivan/oauth-mux --ref proof-ref' "$gh_log" >/dev/null ||
  fail "workflow_dispatch must receive the branch name"
grep -F 'candidate_ref=refs/heads/proof-ref' "$gh_log" >/dev/null ||
  fail "workflow input must carry canonical branch type"
grep -F "run download $run_id --repo Jesssullivan/oauth-mux --name v02-proof-provenance-$run_attempt" "$gh_log" >/dev/null ||
  fail "failed target must download attempt-scoped provenance"
grep -F -- "--name v02-proof-predicates-v02-stage2-conformance-$run_attempt" "$gh_log" >/dev/null ||
  fail "failed target must separately download predicate manifest"
grep -F -- "--name v02-stage2-observations-$run_attempt" "$gh_log" >/dev/null ||
  fail "failed Stage 2 target must separately download typed observations"
grep -F 'verified immutable proof artifacts' "$tmp_dir/explicit-branch.out" >/dev/null ||
  fail "failed target must verify both artifacts before returning"
if grep -F 'v02-proof-benchmark-metrics-' "$gh_log" >/dev/null; then
  fail "Stage 2 must not download benchmark metrics"
fi

# A shape-valid predicate manifest that disagrees with the observations is rejected.
: >"$gh_log"
(
  FAKE_GH_PREDICATE_ARTIFACT=mixed-incomplete \
    expect_fake_status 1 mixed-incomplete-failure \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
grep -F 'does not match the independently reduced observations' \
  "$tmp_dir/mixed-incomplete-failure.out" >/dev/null ||
  fail "observation/manifest drift must fail independent reduction"

: >"$gh_log"
(
  FAKE_GH_OBSERVATION_ARTIFACT=failed-fact \
  FAKE_GH_PREDICATE_ARTIFACT=all-pass \
    expect_fake_status 1 failed-observation-lying-manifest \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
grep -F 'Stage 2 observer did not exercise every fixed fact successfully' \
  "$tmp_dir/failed-observation-lying-manifest.out" >/dev/null ||
  fail "a failed observation must be rejected before a lying all-pass manifest"

: >"$gh_log"
(
  FAKE_GH_PREDICATE_ARTIFACT=all-pass \
    expect_fake_status 1 all-pass-failure \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)

# Explicit annotated tag is independent from branch lookup and is peeled to a commit.
: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=transport \
  FAKE_GH_TAG_MODE=annotated \
  FAKE_GH_TARGET=v02-benchmark \
    expect_fake_status 3 explicit-tag \
    run_fake v02-benchmark refs/tags/proof-tag --candidate-sha "$candidate_sha"
)
if grep -F '/git/ref/heads/' "$gh_log" >/dev/null; then
  fail "explicit tag must not depend on branch lookup"
fi
grep -F "api repos/Jesssullivan/oauth-mux/git/tags/$tag_object_sha" "$gh_log" >/dev/null ||
  fail "annotated tag must be peeled"
grep -F 'candidate_ref=refs/tags/proof-tag' "$gh_log" >/dev/null ||
  fail "workflow input must carry canonical tag type"
grep -F -- "--name v02-proof-benchmark-metrics-$run_attempt" "$gh_log" >/dev/null ||
  fail "benchmark must download the attempt-scoped metrics artifact"
grep -F 'verified immutable proof artifacts' "$tmp_dir/explicit-tag.out" >/dev/null ||
  fail "failed benchmark must verify provenance, predicates, and metrics"

# Unqualified refs query both types; one match is accepted and two are ambiguous.
: >"$gh_log"
expect_fake_status 3 unqualified-branch \
  run_fake v02-stage2-conformance proof-ref --candidate-sha "$candidate_sha"
grep -F '/git/ref/heads/proof-ref' "$gh_log" >/dev/null || fail "branch lookup missing"
grep -F '/git/ref/tags/proof-ref' "$gh_log" >/dev/null || fail "tag lookup missing"

: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=absent \
  FAKE_GH_TAG_MODE=present \
    expect_fake_status 3 unqualified-tag \
    run_fake v02-stage2-conformance proof-tag --candidate-sha "$candidate_sha"
)
grep -F 'candidate_ref=refs/tags/proof-tag' "$gh_log" >/dev/null ||
  fail "unqualified tag must resolve to canonical tag type"

: >"$gh_log"
(
  FAKE_GH_TAG_MODE=present \
    expect_fake_status 2 ambiguous-ref \
    run_fake v02-stage2-conformance proof-ref --candidate-sha "$candidate_sha"
)
if grep -F 'workflow run' "$gh_log" >/dev/null; then
  fail "ambiguous unqualified ref must fail before dispatch"
fi

# Slash refs remain encoded for lookup but use the supported branch name for dispatch.
: >"$gh_log"
expect_fake_status 3 slash-ref \
  run_fake v02-stage2-conformance refs/heads/feature/proof --candidate-sha "$candidate_sha"
grep -F '/git/ref/heads/feature%2Fproof' "$gh_log" >/dev/null ||
  fail "slash branch lookup must be URL encoded"
grep -F -- '--ref feature/proof' "$gh_log" >/dev/null ||
  fail "slash branch dispatch must use the branch name"
grep -F 'candidate_ref=refs/heads/feature/proof' "$gh_log" >/dev/null ||
  fail "slash branch must retain canonical workflow ref"

# Raw SHA is never a v0.2 dispatch ref.
: >"$gh_log"
expect_fake_status 2 raw-sha \
  run_fake v02-stage2-conformance "$candidate_sha" --candidate-sha "$candidate_sha"
if grep -F 'repo view' "$gh_log" >/dev/null || grep -F 'workflow run' "$gh_log" >/dev/null; then
  fail "raw v0.2 SHA must be rejected before GitHub access"
fi

# Only 404 means absence; auth and transport failures remain operational errors.
: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=absent \
  FAKE_GH_TAG_MODE=transport \
    expect_fake_status 1 tag-transport \
    run_fake v02-stage2-conformance proof-ref --candidate-sha "$candidate_sha"
)
if grep -F 'workflow run' "$gh_log" >/dev/null; then fail "transport failure dispatched"; fi

: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=transport \
  FAKE_GH_TAG_MODE=absent \
    expect_fake_status 1 branch-transport \
    run_fake v02-stage2-conformance proof-ref --candidate-sha "$candidate_sha"
)

: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=absent \
    expect_fake_status 2 branch-404 \
    run_fake v02-stage2-conformance refs/heads/missing --candidate-sha "$candidate_sha"
)

: >"$gh_log"
(
  FAKE_GH_BRANCH_MODE=auth \
    expect_fake_status 1 branch-auth \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)

# Mutable ref and workflow-event races fail closed.
: >"$gh_log"
(
  FAKE_GH_REF_SHA="$moved_sha" \
    expect_fake_status 1 moved-ref \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
if grep -F 'workflow run' "$gh_log" >/dev/null; then fail "moved ref dispatched"; fi

: >"$gh_log"
(
  FAKE_GH_RUN_HEAD_SHA="$moved_sha" \
    expect_fake_status 1 moved-event \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)

# Provenance rejects action/tree drift, invalid instants, fallback, wrong result, and file-set drift.
for mode in wrong-tree wrong-gf-action invalid-time reversed-time fallback wrong-result missing-file extra-file download-error; do
  : >"$gh_log"
  (
    FAKE_GH_PROVENANCE_ARTIFACT="$mode" \
      expect_fake_status 1 "provenance-${mode}" \
      run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
  )
done

# Benchmark metrics reject missing/malformed/false-pass evidence and bad cardinality.
for mode in missing-file extra-file download-error malformed false-pass wrong-identity all-pass; do
  : >"$gh_log"
  (
    FAKE_GH_METRICS_ARTIFACT="$mode" \
      expect_fake_status 1 "metrics-${mode}" \
      run_fake v02-benchmark refs/heads/proof-ref --candidate-sha "$candidate_sha"
  )
done

# A future green contract requires all-pass predicates and threshold-valid metrics.
: >"$gh_log"
(
  FAKE_GH_WATCH_STATUS=0 \
  FAKE_GH_PREDICATE_ARTIFACT=all-pass \
  FAKE_GH_METRICS_ARTIFACT=all-pass \
    expect_fake_status 0 benchmark-valid-evidence \
    run_fake v02-benchmark refs/heads/proof-ref --candidate-sha "$candidate_sha"
)

: >"$gh_log"
(
  FAKE_GH_WATCH_STATUS=0 \
  FAKE_GH_PREDICATE_ARTIFACT=all-pass \
    expect_fake_status 3 benchmark-missing-evidence \
    run_fake v02-benchmark refs/heads/proof-ref --candidate-sha "$candidate_sha"
)

# The bounded readiness target reconciles its candidate/run-bound bundle without
# borrowing Stage 2 predicates, observations, or benchmark metrics.
: >"$gh_log"
(
  cd "$tmp_dir"
  FAKE_GH_WATCH_STATUS=0 \
    expect_fake_status 0 prerelease-readiness-valid \
    run_fake v02-prerelease-readiness refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
grep -F -- "--name v02-prerelease-readiness-$run_attempt" "$gh_log" >/dev/null ||
  fail "readiness target must download its attempt-scoped bundle"
if grep -F 'v02-proof-predicates-' "$gh_log" >/dev/null ||
  grep -F 'v02-stage2-observations-' "$gh_log" >/dev/null ||
  grep -F 'v02-proof-benchmark-metrics-' "$gh_log" >/dev/null; then
  fail "readiness target must not borrow Stage 2/G4 evidence"
fi
grep -F 'verified immutable proof artifacts' \
  "$tmp_dir/prerelease-readiness-valid.out" >/dev/null ||
  fail "readiness target must reconcile provenance and resolved artifacts"

for mode in missing-file extra-file download-error wrong-candidate wrong-tree stale-attempt digest-drift missing-artifact extra-artifact; do
  : >"$gh_log"
  (
    FAKE_GH_WATCH_STATUS=0 \
    FAKE_GH_READINESS_ARTIFACT="$mode" \
      expect_fake_status 1 "readiness-${mode}" \
      run_fake v02-prerelease-readiness refs/heads/proof-ref --candidate-sha "$candidate_sha"
  )
done

# Predicate artifacts reject missing/extra members and invalid canonical manifests.
for mode in missing-file extra-file download-error unknown duplicate omitted invalid-status; do
  : >"$gh_log"
  (
    FAKE_GH_PREDICATE_ARTIFACT="$mode" \
      expect_fake_status 1 "predicates-${mode}" \
      run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
  )
done

# Stage 2 observations are exact-candidate, attempt-bound, fixed-cardinality artifacts.
for mode in missing-file extra-file download-error wrong-candidate stale-attempt unknown duplicate omitted invalid-status; do
  : >"$gh_log"
  (
    FAKE_GH_OBSERVATION_ARTIFACT="$mode" \
      expect_fake_status 1 "observations-${mode}" \
      run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
  )
done

# A green run cannot claim Stage 2 while 113 canonical predicates remain missing.
: >"$gh_log"
(
  FAKE_GH_WATCH_STATUS=0 \
    expect_fake_status 3 false-green \
    run_fake v02-stage2-conformance refs/heads/proof-ref --candidate-sha "$candidate_sha"
)
if grep -F 'verified immutable proof artifacts' "$tmp_dir/false-green.out" >/dev/null; then
  fail "the 11/124 slice must not produce a completed Stage 2 claim"
fi

# Stage 1 accepts only exact lowercase local HEAD identity; detachedness is remote-only.
cat >"$fake_bin/git" <<'EOF'
#!/usr/bin/env sh
set -eu
case "${1:-}" in
  rev-parse)
    case "${3:-}" in
      'HEAD^{commit}') printf '%s\n' "$FAKE_GIT_HEAD_SHA" ;;
      'HEAD^{tree}') printf '%s\n' "$FAKE_GIT_TREE" ;;
      *) exit 2 ;;
    esac
    ;;
  symbolic-ref)
    if [ "${FAKE_GIT_ATTACHED:-0}" = "1" ]; then
      printf '%s\n' refs/heads/proof-ref
      exit 0
    fi
    exit 1
    ;;
  status)
    if [ -n "${FAKE_GIT_STATUS:-}" ]; then
      printf '%s\n' "$FAKE_GIT_STATUS"
    fi
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_bin/git"

PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=1 \
  "$PROVENANCE" assert-local-candidate "$candidate_sha"

set +e
PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=1 \
  "$PROVENANCE" assert-local-candidate AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  >"$tmp_dir/stage1-uppercase.out" 2>&1
status=$?
set -e
assert_status 1 "$status" "Stage 1 uppercase SHA"

set +e
PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$moved_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=1 \
  "$PROVENANCE" assert-local-candidate "$candidate_sha" \
  >"$tmp_dir/stage1-moved.out" 2>&1
status=$?
set -e
assert_status 1 "$status" "Stage 1 moved HEAD"

set +e
PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=1 \
  "$PROVENANCE" assert-checkout "$candidate_sha" "$candidate_sha" \
  >"$tmp_dir/remote-attached.out" 2>&1
status=$?
set -e
assert_status 1 "$status" "remote attached checkout"

PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=0 \
FAKE_GIT_STATUS='' \
  "$PROVENANCE" assert-checkout "$candidate_sha" "$candidate_sha"

set +e
PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=0 \
FAKE_GIT_STATUS=' M tracked.txt' \
  "$PROVENANCE" assert-checkout "$candidate_sha" "$candidate_sha" \
  >"$tmp_dir/remote-dirty-tracked.out" 2>&1
status=$?
set -e
assert_status 1 "$status" "remote dirty tracked checkout"

set +e
PATH="$fake_bin:$PATH" \
FAKE_GIT_HEAD_SHA="$candidate_sha" \
FAKE_GIT_TREE="$candidate_tree" \
FAKE_GIT_ATTACHED=0 \
FAKE_GIT_STATUS='?? untracked.txt' \
  "$PROVENANCE" assert-checkout "$candidate_sha" "$candidate_sha" \
  >"$tmp_dir/remote-dirty-untracked.out" 2>&1
status=$?
set -e
assert_status 1 "$status" "remote dirty untracked checkout"

# Post-run proof accepts only a clean pinned GF checkout plus exact target artifacts.
post_run_repo="$tmp_dir/post-run-repo"
post_run_gf="$post_run_repo/.gloriousflywheel"
mkdir -p "$post_run_repo" "$post_run_gf"
(
  cd "$post_run_repo"
  git init -q
  git config user.email smoke@example.invalid
  git config user.name smoke
  printf 'candidate\n' >candidate.txt
  git add candidate.txt
  git commit -q -m candidate
  post_run_candidate_sha="$(git rev-parse HEAD)"
  git checkout -q --detach "$post_run_candidate_sha"

  git -C "$post_run_gf" init -q
  git -C "$post_run_gf" config user.email smoke@example.invalid
  git -C "$post_run_gf" config user.name smoke
  printf 'action\n' >"$post_run_gf/action.yml"
  git -C "$post_run_gf" add action.yml
  git -C "$post_run_gf" commit -q -m action
  post_run_gf_sha="$(git -C "$post_run_gf" rev-parse HEAD)"

  "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-prerelease-readiness "$post_run_gf_sha"

  printf '{"schema_version":1}\n' >v02-proof-predicate-manifest.json
  printf '{"schema_version":1}\n' >v02-stage2-observations.json
  "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-stage2-conformance "$post_run_gf_sha"

  printf 'mutated\n' >>candidate.txt
  if "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-stage2-conformance "$post_run_gf_sha" >/dev/null 2>&1; then
    fail "post-run verification must reject tracked candidate mutation"
  fi
  git checkout -q -- candidate.txt

  printf 'extra\n' >unexpected-output
  if "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-stage2-conformance "$post_run_gf_sha" >/dev/null 2>&1; then
    fail "post-run verification must reject non-allowlisted artifacts"
  fi
  rm unexpected-output

  mkdir .zig-cache
  printf 'stale executable input\n' >.zig-cache/stale
  if "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-stage2-conformance "$post_run_gf_sha" >/dev/null 2>&1; then
    fail "post-run verification must reject ignored build outputs in the candidate workspace"
  fi
  rm -rf .zig-cache

  printf 'mutated\n' >>"$post_run_gf/action.yml"
  if "$PROVENANCE" assert-post-run \
    "$post_run_candidate_sha" "$post_run_candidate_sha" \
    v02-stage2-conformance "$post_run_gf_sha" >/dev/null 2>&1; then
    fail "post-run verification must reject mutated GF action source"
  fi
)

echo "smoke-remote-validate-contract: ok"
