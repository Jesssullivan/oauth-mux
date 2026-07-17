#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/v02-proof-provenance-local.sh assert-local-candidate <candidate_sha>
  scripts/v02-proof-provenance-local.sh assert-checkout <candidate_sha> <workflow_event_sha>
  scripts/v02-proof-provenance-local.sh assert-post-run <candidate_sha> <workflow_event_sha> <target> <gf_action_sha>
  scripts/v02-proof-provenance-local.sh emit <output> <candidate_sha> <workflow_event_sha> <target> <workflow_run_id> <workflow_run_attempt> <gf_target_class> <gf_action_sha> <started_at_utc> <finished_at_utc> <passed|failed>
  scripts/v02-proof-provenance-local.sh verify <provenance.json> <candidate_sha> <candidate_tree> <target> <workflow_run_id> <workflow_run_attempt> <gf_target_class> <gf_action_sha> <passed|failed>
USAGE
}

fail() {
  echo "v02-proof-provenance: $*" >&2
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

require_timestamp() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
    fail "${label} must use YYYY-MM-DDTHH:MM:SSZ"
  jq -e -n --arg value "$value" \
    'try ((($value | fromdateiso8601) | todateiso8601) == $value) catch false' >/dev/null ||
    fail "${label} is not a valid UTC instant"
}

require_target() {
  case "$1" in
    v02-stage2-conformance|v02-benchmark)
      ;;
    *)
      fail "unsupported v0.2 proof target: $1"
      ;;
  esac
}

assert_local_candidate() {
  local candidate_sha="$1"
  local head_sha

  require_sha candidate_sha "$candidate_sha"
  command -v git >/dev/null 2>&1 || fail "git is required to verify the checkout"
  head_sha="$(git rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
    fail "could not resolve checked-out HEAD"
  require_sha checked_out_head "$head_sha"
  [ "$head_sha" = "$candidate_sha" ] ||
    fail "checked-out HEAD does not equal candidate_sha"
}

assert_checkout_identity() {
  local candidate_sha="$1"
  local workflow_event_sha="$2"

  require_sha workflow_event_sha "$workflow_event_sha"
  [ "$workflow_event_sha" = "$candidate_sha" ] ||
    fail "workflow event SHA does not equal candidate_sha"
  assert_local_candidate "$candidate_sha"

  if git symbolic-ref -q HEAD >/dev/null 2>&1; then
    fail "checked-out HEAD must be detached"
  fi
}

assert_checkout() {
  local candidate_sha="$1"
  local workflow_event_sha="$2"
  local checkout_status

  assert_checkout_identity "$candidate_sha" "$workflow_event_sha"
  checkout_status="$(
    git status --porcelain=v1 --untracked-files=all --ignored=matching
  )" ||
    fail "could not inspect candidate checkout cleanliness"
  [ -z "$checkout_status" ] ||
    fail "candidate checkout must contain no tracked, untracked, or ignored files before GloriousFlywheel checkout"
}

assert_post_run() {
  local candidate_sha="$1"
  local workflow_event_sha="$2"
  local target="$3"
  local gf_action_sha="$4"
  local actual_gf_action_sha gf_status candidate_status expected_status

  assert_checkout_identity "$candidate_sha" "$workflow_event_sha"
  require_target "$target"
  require_sha gf_action_sha "$gf_action_sha"

  [ -d .gloriousflywheel/.git ] ||
    fail "pinned GloriousFlywheel checkout is missing after proof execution"
  actual_gf_action_sha="$(git -C .gloriousflywheel rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
    fail "could not resolve the post-run GloriousFlywheel checkout"
  [ "$actual_gf_action_sha" = "$gf_action_sha" ] ||
    fail "post-run GloriousFlywheel checkout does not match gf_action_sha"
  gf_status="$(git -C .gloriousflywheel status --porcelain=v1 --untracked-files=all)" ||
    fail "could not inspect post-run GloriousFlywheel cleanliness"
  [ -z "$gf_status" ] ||
    fail "GloriousFlywheel action source changed during proof execution"

  git diff --quiet --no-ext-diff HEAD -- ||
    fail "tracked candidate bytes changed during proof execution"
  git diff --cached --quiet --no-ext-diff ||
    fail "candidate index changed during proof execution"

  candidate_status="$(
    git status --porcelain=v1 --untracked-files=all --ignored=matching \
      -- . ':(exclude).gloriousflywheel'
  )" || fail "could not inspect post-run candidate artifacts"
  case "$target" in
    v02-stage2-conformance)
      expected_status='?? v02-proof-predicate-manifest.json
?? v02-stage2-observations.json'
      ;;
    v02-benchmark)
      expected_status='?? v02-benchmark-metrics.json
?? v02-proof-predicate-manifest.json'
      ;;
  esac
  [ "$candidate_status" = "$expected_status" ] ||
    fail "post-run checkout contains files outside the proof artifact allowlist"

  [ -f v02-proof-predicate-manifest.json ] &&
    [ ! -L v02-proof-predicate-manifest.json ] ||
    fail "predicate manifest must be a regular non-symlink file"
  if [ "$target" = "v02-benchmark" ]; then
    [ -f v02-benchmark-metrics.json ] &&
      [ ! -L v02-benchmark-metrics.json ] ||
      fail "benchmark metrics must be a regular non-symlink file"
  fi
}

mode="${1:-}"

case "$mode" in
  assert-local-candidate)
    [ "$#" -eq 2 ] || {
      usage
      exit 2
    }
    assert_local_candidate "$2"
    ;;

  assert-checkout)
    [ "$#" -eq 3 ] || {
      usage
      exit 2
    }
    assert_checkout "$2" "$3"
    ;;

  assert-post-run)
    [ "$#" -eq 5 ] || {
      usage
      exit 2
    }
    assert_post_run "$2" "$3" "$4" "$5"
    ;;

  emit)
    [ "$#" -eq 12 ] || {
      usage
      exit 2
    }

    output="$2"
    candidate_sha="$3"
    workflow_event_sha="$4"
    target="$5"
    workflow_run_id="$6"
    workflow_run_attempt="$7"
    gf_target_class="$8"
    gf_action_sha="$9"
    started_at_utc="${10}"
    finished_at_utc="${11}"
    result="${12}"

    command -v jq >/dev/null 2>&1 || fail "jq is required to emit provenance"
    # The explicit pre-GF workflow step already proved cleanliness. The private
    # action checkout is intentionally present by the time provenance is emitted.
    assert_checkout_identity "$candidate_sha" "$workflow_event_sha"
    require_target "$target"
    require_positive_integer workflow_run_id "$workflow_run_id"
    require_positive_integer workflow_run_attempt "$workflow_run_attempt"
    [ "$gf_target_class" = "tinyland-nix" ] || fail "unexpected gf_target_class"
    require_sha gf_action_sha "$gf_action_sha"
    require_timestamp started_at_utc "$started_at_utc"
    require_timestamp finished_at_utc "$finished_at_utc"
    jq -e -n \
      --arg started_at_utc "$started_at_utc" \
      --arg finished_at_utc "$finished_at_utc" \
      '($started_at_utc | fromdateiso8601) <= ($finished_at_utc | fromdateiso8601)' \
      >/dev/null || fail "finished_at_utc precedes started_at_utc"
    case "$result" in
      passed|failed)
        ;;
      *)
        fail "result must be passed or failed"
        ;;
    esac

    candidate_tree="$(git rev-parse --verify 'HEAD^{tree}' 2>/dev/null)" ||
      fail "could not resolve candidate tree"
    require_sha candidate_tree "$candidate_tree"

    tmp_output="${output}.tmp.$$"
    trap 'rm -f "$tmp_output"' EXIT HUP INT TERM
    jq -n \
      --arg candidate_sha "$candidate_sha" \
      --arg candidate_tree "$candidate_tree" \
      --arg target "$target" \
      --argjson workflow_run_id "$workflow_run_id" \
      --argjson workflow_run_attempt "$workflow_run_attempt" \
      --arg gf_target_class "$gf_target_class" \
      --arg gf_action_sha "$gf_action_sha" \
      --arg started_at_utc "$started_at_utc" \
      --arg finished_at_utc "$finished_at_utc" \
      --arg result "$result" \
      '{
        schema_version: 1,
        candidate_sha: $candidate_sha,
        candidate_tree: $candidate_tree,
        target: $target,
        workflow_run_id: $workflow_run_id,
        workflow_run_attempt: $workflow_run_attempt,
        gf_target_class: $gf_target_class,
        gf_action_sha: $gf_action_sha,
        started_at_utc: $started_at_utc,
        finished_at_utc: $finished_at_utc,
        result: $result,
        local_fallback_occurred: false
      }' >"$tmp_output"
    mv "$tmp_output" "$output"
    trap - EXIT HUP INT TERM

    "$0" verify "$output" "$candidate_sha" "$candidate_tree" "$target" \
      "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class" \
      "$gf_action_sha" "$result"
    ;;

  verify)
    [ "$#" -eq 10 ] || {
      usage
      exit 2
    }

    provenance="$2"
    candidate_sha="$3"
    candidate_tree="$4"
    target="$5"
    workflow_run_id="$6"
    workflow_run_attempt="$7"
    gf_target_class="$8"
    gf_action_sha="$9"
    result="${10}"

    command -v jq >/dev/null 2>&1 || fail "jq is required to verify provenance"
    [ -f "$provenance" ] || fail "provenance file is missing"
    require_sha candidate_sha "$candidate_sha"
    require_sha candidate_tree "$candidate_tree"
    require_target "$target"
    require_positive_integer workflow_run_id "$workflow_run_id"
    require_positive_integer workflow_run_attempt "$workflow_run_attempt"
    [ "$gf_target_class" = "tinyland-nix" ] || fail "unexpected gf_target_class"
    require_sha gf_action_sha "$gf_action_sha"
    case "$result" in
      passed|failed)
        ;;
      *)
        fail "result must be passed or failed"
        ;;
    esac

    jq -s -e \
      --arg candidate_sha "$candidate_sha" \
      --arg candidate_tree "$candidate_tree" \
      --arg target "$target" \
      --argjson workflow_run_id "$workflow_run_id" \
      --argjson workflow_run_attempt "$workflow_run_attempt" \
      --arg gf_target_class "$gf_target_class" \
      --arg gf_action_sha "$gf_action_sha" \
      --arg result "$result" \
      '
        if length != 1 then
          false
        else
          .[0] as $p
          | (
              (($p | type) == "object")
              and (($p | keys) == [
                "candidate_sha",
                "candidate_tree",
                "finished_at_utc",
                "gf_action_sha",
                "gf_target_class",
                "local_fallback_occurred",
                "result",
                "schema_version",
                "started_at_utc",
                "target",
                "workflow_run_attempt",
                "workflow_run_id"
              ])
              and ($p.schema_version == 1)
              and ($p.candidate_sha == $candidate_sha)
              and ($p.candidate_sha | test("^[0-9a-f]{40}$"))
              and ($p.candidate_tree == $candidate_tree)
              and ($p.candidate_tree | test("^[0-9a-f]{40}$"))
              and ($p.target == $target)
              and ($p.workflow_run_id == $workflow_run_id)
              and (($p.workflow_run_id | type) == "number")
              and ($p.workflow_run_attempt == $workflow_run_attempt)
              and (($p.workflow_run_attempt | type) == "number")
              and ($p.gf_target_class == $gf_target_class)
              and (($p.gf_action_sha | type) == "string")
              and ($p.gf_action_sha == $gf_action_sha)
              and ($p.gf_action_sha | test("^[0-9a-f]{40}$"))
              and (($p.started_at_utc | type) == "string")
              and (($p.finished_at_utc | type) == "string")
              and (
                try (
                  ($p.started_at_utc | fromdateiso8601) as $started
                  | ($p.finished_at_utc | fromdateiso8601) as $finished
                  | (
                      (($started | todateiso8601) == $p.started_at_utc)
                      and (($finished | todateiso8601) == $p.finished_at_utc)
                      and ($started <= $finished)
                    )
                ) catch false
              )
              and ($p.result == $result)
              and ($p.local_fallback_occurred == false)
            )
        end
      ' "$provenance" >/dev/null || fail "provenance does not match the immutable proof envelope"
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage
    exit 2
    ;;
esac
