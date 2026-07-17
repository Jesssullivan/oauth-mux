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

[ "$(jq '[.predicates[] | select(.status == "pass")] | length' "$manifest")" -eq 11 ] ||
  fail "expected exactly eleven exercised predicates"
[ "$(jq '[.predicates[] | select(.status == "missing")] | length' "$manifest")" -eq 113 ] ||
  fail "expected exactly 113 unexercised predicates"
[ "$(jq '[.predicates[] | select(.status == "fail")] | length' "$manifest")" -eq 0 ] ||
  fail "successful fake-upstream scenarios must not emit failed predicates"

expected_passes='capability_carrier
loopback_sidecar_bind
capability_256bit_base64url
bad_token_zero_call_rejection
inbound_auth_header_stripping
origin_form_request_enforcement
redirect_ssrf_rejection
generic_forward_proxy_rejection
byte_preserving_streaming
provider_5xx_pass_through
accepted_rejected_counter_reconciliation'
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
