#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'USAGE'
usage: scripts/remote-validate.sh <target> [ref] [--candidate-sha <sha>] [--no-watch]

Targets:
  check          Run just check-local on the GloriousFlywheel runner.
  test           Run zig build test on the GloriousFlywheel runner.
  build          Run zig build on the GloriousFlywheel runner.
  build-release  Run zig build -Doptimize=ReleaseSafe on the GloriousFlywheel runner.
  build-small    Run zig build -Doptimize=ReleaseSmall on the GloriousFlywheel runner.
  e2e            Run just e2e-local on the GloriousFlywheel runner.
  first-run-e2e  Run just first-run-e2e-local on the GloriousFlywheel runner.
  release-proof  Run just release-proof-local on the GloriousFlywheel runner.
  v02-stage2-conformance
                 Run the v0.2 fake-upstream conformance target.
  v02-benchmark  Run the v0.2 G4 benchmark target.

The workflow file must already exist on the repository default branch. After
that, generic targets retain branch/SHA [ref] behavior. The v0.2 proof targets
require a branch or tag [ref] plus an exact 40-hex --candidate-sha. Prefer a
fully qualified refs/heads/... or refs/tags/... value. The remote branch/tag is
resolved to that candidate before workflow dispatch; raw SHA dispatch is denied.
USAGE
}

case "${1:-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

target="${1:-check}"
shift || true

watch=1
ref=""
version="${OMUX_REMOTE_RELEASE_VERSION:-}"
request_id="${OMUX_REMOTE_REQUEST_ID:-}"
candidate_sha=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-watch)
      watch=0
      ;;
    --watch)
      watch=1
      ;;
    --version)
      shift
      version="${1:-}"
      if [ -z "$version" ]; then
        echo "remote-validate: --version requires a value" >&2
        exit 2
      fi
      ;;
    --candidate-sha)
      shift
      candidate_sha="${1:-}"
      if [ -z "$candidate_sha" ]; then
        echo "remote-validate: --candidate-sha requires a value" >&2
        exit 2
      fi
      ;;
    --candidate-sha=*)
      candidate_sha="${1#*=}"
      if [ -z "$candidate_sha" ]; then
        echo "remote-validate: --candidate-sha requires a value" >&2
        exit 2
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    "")
      ;;
    *)
      if [ -z "$ref" ]; then
        ref="$1"
      else
        echo "remote-validate: unexpected argument: $1" >&2
        usage
        exit 2
      fi
      ;;
  esac
  shift || true
done

case "$target" in
  check|test|build|build-release|build-small|e2e|first-run-e2e|release-proof)
    v02_proof=0
    ;;
  v02-stage2-conformance|v02-benchmark)
    v02_proof=1
    ;;
  *)
    echo "remote-validate: unsupported target: $target" >&2
    usage
    exit 2
    ;;
esac

if [ "$v02_proof" = "1" ]; then
  if [[ ! "$candidate_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "remote-validate: v0.2 proof targets require --candidate-sha as exactly 40 lowercase hexadecimal characters" >&2
    exit 2
  fi
  if [ -z "$ref" ]; then
    echo "remote-validate: v0.2 proof targets require an explicit branch or tag ref" >&2
    exit 2
  fi
  if [[ "$ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    echo "remote-validate: v0.2 workflow_dispatch ref must be a branch or tag, not a raw SHA" >&2
    exit 2
  fi
  if [ "$watch" != "1" ]; then
    echo "remote-validate: v0.2 proof targets require watch mode for provenance reconciliation" >&2
    exit 2
  fi
else
  if [ -n "$candidate_sha" ]; then
    echo "remote-validate: --candidate-sha is only valid for v0.2 proof targets" >&2
    exit 2
  fi
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "remote-validate: gh is required to dispatch remote validation" >&2
  exit 127
fi

if [ -z "$ref" ]; then
  ref="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [ -z "$ref" ] || [ "$ref" = "HEAD" ]; then
    ref="$(git rev-parse HEAD 2>/dev/null || true)"
  fi
fi

if [ -z "$ref" ]; then
  echo "remote-validate: could not infer git ref; pass one explicitly" >&2
  exit 2
fi

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
workflow="remote-validate.yml"
gf_action_sha=2357988536f1f6258291c363e1428962b6cced1b
dispatch_ref="$ref"
candidate_tree=""
candidate_ref=""
v02_tmp_dir=""

if [ "$v02_proof" = "1" ]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "remote-validate: jq is required to resolve immutable v0.2 candidates" >&2
    exit 127
  fi

  v02_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/omux-v02-remote.XXXXXX")"
  trap 'rm -rf "$v02_tmp_dir"' EXIT HUP INT TERM

  lookup_remote_ref() {
    local kind="$1"
    local name="$2"
    local label encoded_name response_file error_file command_status http_status record

    case "$kind" in
      heads) label=branch ;;
      tags) label=tag ;;
      *) echo "remote-validate: internal ref kind error" >&2; return 1 ;;
    esac

    encoded_name="$(jq -rn --arg value "$name" '$value | @uri')"
    response_file="${v02_tmp_dir}/ref-${kind}.response"
    error_file="${v02_tmp_dir}/ref-${kind}.error"

    set +e
    gh api "repos/${repo}/git/ref/${kind}/${encoded_name}" \
      --include \
      --jq '[.object.type, .object.sha] | @tsv' \
      >"$response_file" 2>"$error_file"
    command_status=$?
    set -e

    http_status="$(awk '/^HTTP\/[0-9.]+ [0-9][0-9][0-9]/ { status=$2 } END { print status }' "$response_file")"
    if [ "$http_status" = "404" ]; then
      return 4
    fi
    if [ "$command_status" -ne 0 ] || [ "$http_status" != "200" ]; then
      echo "remote-validate: ${label} ref lookup failed operationally" >&2
      return 1
    fi

    record="$(awk 'NF { line=$0 } END { print line }' "$response_file" | tr -d '\r')"
    [ -n "$record" ] || {
      echo "remote-validate: ${label} ref lookup returned no git object" >&2
      return 1
    }
    printf '%s\n' "$record"
  }

  ref_kind=""
  ref_name="$ref"
  case "$ref" in
    refs/heads/*)
      ref_kind="heads"
      ref_name="${ref#refs/heads/}"
      ;;
    refs/tags/*)
      ref_kind="tags"
      ref_name="${ref#refs/tags/}"
      ;;
  esac
  if [ -z "$ref_name" ]; then
    echo "remote-validate: v0.2 dispatch ref must name a branch or tag" >&2
    exit 2
  fi

  branch_record=""
  tag_record=""
  case "$ref_kind" in
    heads)
      set +e
      branch_record="$(lookup_remote_ref heads "$ref_name")"
      lookup_status=$?
      set -e
      case "$lookup_status" in
        0) ;;
        4)
          echo "remote-validate: remote branch does not exist: $ref" >&2
          exit 2
          ;;
        *) exit 1 ;;
      esac
      selected_ref_record="$branch_record"
      ;;
    tags)
      set +e
      tag_record="$(lookup_remote_ref tags "$ref_name")"
      lookup_status=$?
      set -e
      case "$lookup_status" in
        0) ;;
        4)
          echo "remote-validate: remote tag does not exist: $ref" >&2
          exit 2
          ;;
        *) exit 1 ;;
      esac
      selected_ref_record="$tag_record"
      ;;
    "")
      set +e
      branch_record="$(lookup_remote_ref heads "$ref_name")"
      branch_status=$?
      tag_record="$(lookup_remote_ref tags "$ref_name")"
      tag_status=$?
      set -e
      case "$branch_status" in 0|4) ;; *) exit 1 ;; esac
      case "$tag_status" in 0|4) ;; *) exit 1 ;; esac

      if [ "$branch_status" -eq 0 ] && [ "$tag_status" -eq 0 ]; then
        echo "remote-validate: unqualified v0.2 ref is ambiguous; use refs/heads/... or refs/tags/..." >&2
        exit 2
      fi
      if [ "$branch_status" -eq 0 ]; then
        ref_kind="heads"
        selected_ref_record="$branch_record"
      elif [ "$tag_status" -eq 0 ]; then
        ref_kind="tags"
        selected_ref_record="$tag_record"
      else
        echo "remote-validate: v0.2 dispatch ref does not resolve to a remote branch or tag: $ref" >&2
        exit 2
      fi
      ;;
  esac

  IFS=$'\t' read -r ref_object_type ref_object_sha <<<"$selected_ref_record"
  if [[ ! "$ref_object_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "remote-validate: remote branch/tag did not resolve to an immutable git object" >&2
    exit 1
  fi
  for _ in 1 2 3 4 5 6 7 8; do
    case "$ref_object_type" in
      commit)
        break
        ;;
      tag)
        if ! selected_ref_record="$(gh api "repos/${repo}/git/tags/${ref_object_sha}" --jq '[.object.type, .object.sha] | @tsv')"; then
          echo "remote-validate: could not peel annotated dispatch tag" >&2
          exit 1
        fi
        IFS=$'\t' read -r ref_object_type ref_object_sha <<<"$selected_ref_record"
        if [[ ! "$ref_object_sha" =~ ^[0-9a-f]{40}$ ]]; then
          echo "remote-validate: annotated dispatch tag returned a malformed git object" >&2
          exit 1
        fi
        ;;
      *)
        echo "remote-validate: branch/tag does not resolve to a commit" >&2
        exit 1
        ;;
    esac
  done
  if [ "$ref_object_type" != "commit" ]; then
    echo "remote-validate: annotated dispatch tag nesting exceeds the supported bound" >&2
    exit 1
  fi
  if ! candidate_record="$(gh api "repos/${repo}/commits/${ref_object_sha}" --jq '[.sha, .commit.tree.sha] | @tsv')"; then
    echo "remote-validate: could not resolve remote branch/tag commit and tree" >&2
    exit 1
  fi
  IFS=$'\t' read -r resolved_candidate_sha candidate_tree <<<"$candidate_record"
  if [[ ! "$resolved_candidate_sha" =~ ^[0-9a-f]{40}$ ]] ||
    [[ ! "$candidate_tree" =~ ^[0-9a-f]{40}$ ]]; then
    echo "remote-validate: remote branch/tag returned malformed commit provenance" >&2
    exit 1
  fi
  if [ "$resolved_candidate_sha" != "$candidate_sha" ]; then
    echo "remote-validate: remote branch/tag resolves to ${resolved_candidate_sha}, not candidate_sha ${candidate_sha}" >&2
    exit 1
  fi

  dispatch_ref="$ref_name"
  candidate_ref="refs/${ref_kind}/${ref_name}"
  echo "remote-validate: resolved ${repo}@${candidate_ref} to candidate_sha=${candidate_sha} candidate_tree=${candidate_tree}"
fi

if [ -z "$request_id" ]; then
  repo_slug="$(printf '%s' "$repo" | sed 's#[/[:space:]]#-#g' | tr -c 'A-Za-z0-9_.:-' '-')"
  target_slug="$(printf '%s' "$target" | tr -c 'A-Za-z0-9_.:-' '-')"
  nonce="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  request_id="omux-remote-${repo_slug}-${target_slug}-${nonce}"
fi
request_id="$(printf '%s' "$request_id" | tr -c 'A-Za-z0-9_.:-' '-')"
request_id="${request_id:0:200}"
dispatch_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "remote-validate: dispatching ${target} on ${repo}@${dispatch_ref} (request_id=${request_id})"

args=(workflow run "$workflow" --repo "$repo" --ref "$dispatch_ref" -f "target=$target" -f "request_id=$request_id")
if [ -n "$version" ]; then
  args+=(-f "version=$version")
fi
if [ "$v02_proof" = "1" ]; then
  args+=(-f "candidate_sha=$candidate_sha" -f "candidate_ref=$candidate_ref")
fi
gh "${args[@]}"

if [ "$watch" != "1" ]; then
  echo "remote-validate: dispatched request_id=${request_id}"
  echo "remote-validate: watch with: gh run list --repo ${repo} --workflow ${workflow}"
  exit 0
fi

echo "remote-validate: locating workflow_dispatch run for request_id=${request_id}"
run_id=""
for _ in $(seq 1 60); do
  run_id="$(gh run list \
    --repo "$repo" \
    --workflow "$workflow" \
    --event workflow_dispatch \
    --json databaseId,createdAt,displayTitle \
    --jq "[.[] | select(.createdAt >= \"${dispatch_time}\") | select((.displayTitle // \"\") | contains(\"${request_id}\"))] | sort_by(.createdAt, .databaseId) | first | .databaseId // empty" \
    --limit 50)" || run_id=""
  if [ -n "$run_id" ]; then
    break
  fi
  sleep 5
done

if [ -z "$run_id" ]; then
  echo "remote-validate: dispatched request_id=${request_id}, but GitHub has not exposed the matching run yet" >&2
  echo "remote-validate: check: gh run list --repo ${repo} --workflow ${workflow}" >&2
  exit 1
fi
if [ "$v02_proof" = "1" ] && [[ ! "$run_id" =~ ^[1-9][0-9]*$ ]]; then
  echo "remote-validate: matched v0.2 workflow run id is malformed" >&2
  exit 1
fi

echo "remote-validate: watching run ${run_id}"
if [ "$v02_proof" != "1" ]; then
  gh run watch "$run_id" --repo "$repo" --exit-status
  exit $?
fi

set +e
gh run watch "$run_id" --repo "$repo" --exit-status
proof_status=$?
set -e
if [ "$proof_status" -eq 0 ]; then
  expected_result=passed
else
  expected_result=failed
fi

if ! run_record="$(gh api "repos/${repo}/actions/runs/${run_id}" --jq '[.head_sha, .run_attempt] | @tsv')"; then
  echo "remote-validate: could not resolve completed v0.2 workflow run metadata" >&2
  exit 1
fi
IFS=$'\t' read -r workflow_event_sha workflow_run_attempt <<<"$run_record"
if [ "$workflow_event_sha" != "$candidate_sha" ]; then
  echo "remote-validate: workflow event SHA ${workflow_event_sha} does not equal candidate_sha ${candidate_sha}" >&2
  exit 1
fi
if [[ ! "$workflow_run_attempt" =~ ^[1-9][0-9]*$ ]]; then
  echo "remote-validate: workflow run attempt is malformed" >&2
  exit 1
fi

assert_exact_regular_file() {
  local directory="$1"
  local expected_name="$2"
  local entries

  shopt -s nullglob dotglob
  entries=("$directory"/*)
  shopt -u nullglob dotglob
  if [ "${#entries[@]}" -ne 1 ]; then
    echo "remote-validate: downloaded artifact must contain exactly ${expected_name}" >&2
    return 1
  fi
  if [ "$(basename "${entries[0]}")" != "$expected_name" ] ||
    [ ! -f "${entries[0]}" ] || [ -L "${entries[0]}" ]; then
    echo "remote-validate: downloaded artifact member is not the expected regular file ${expected_name}" >&2
    return 1
  fi
}

provenance_dir="${v02_tmp_dir}/provenance"
predicate_dir="${v02_tmp_dir}/predicates"
mkdir -p "$provenance_dir" "$predicate_dir"

set +e
gh run download "$run_id" --repo "$repo" \
  --name "v02-proof-provenance-${workflow_run_attempt}" \
  --dir "$provenance_dir"
download_status=$?
set -e
if [ "$download_status" -ne 0 ]; then
  echo "remote-validate: v0.2 proof provenance artifact is unavailable" >&2
  exit 1
fi
assert_exact_regular_file "$provenance_dir" v02-proof-provenance.json

set +e
gh run download "$run_id" --repo "$repo" \
  --name "v02-proof-predicates-${target}-${workflow_run_attempt}" \
  --dir "$predicate_dir"
download_status=$?
set -e
if [ "$download_status" -ne 0 ]; then
  echo "remote-validate: v0.2 proof predicate artifact is unavailable" >&2
  exit 1
fi
assert_exact_regular_file "$predicate_dir" v02-proof-predicate-manifest.json

"${script_dir}/v02-proof-provenance-local.sh" verify \
  "$provenance_dir/v02-proof-provenance.json" \
  "$candidate_sha" \
  "$candidate_tree" \
  "$target" \
  "$run_id" \
  "$workflow_run_attempt" \
  tinyland-nix \
  "$gf_action_sha" \
  "$expected_result"

"${script_dir}/v02-proof-predicate-manifest-local.sh" verify \
  "$target" \
  "$predicate_dir/v02-proof-predicate-manifest.json"
if [ "$expected_result" = "passed" ]; then
  "${script_dir}/v02-proof-predicate-manifest-local.sh" require-pass \
    "$target" \
    "$predicate_dir/v02-proof-predicate-manifest.json"
else
  "${script_dir}/v02-proof-predicate-manifest-local.sh" require-incomplete \
    "$target" \
    "$predicate_dir/v02-proof-predicate-manifest.json"
fi

if [ "$target" = "v02-benchmark" ]; then
  metrics_dir="${v02_tmp_dir}/benchmark-metrics"
  mkdir -p "$metrics_dir"
  set +e
  gh run download "$run_id" --repo "$repo" \
    --name "v02-proof-benchmark-metrics-${workflow_run_attempt}" \
    --dir "$metrics_dir"
  download_status=$?
  set -e
  if [ "$download_status" -ne 0 ]; then
    echo "remote-validate: v0.2 benchmark metrics artifact is unavailable" >&2
    exit 1
  fi
  assert_exact_regular_file "$metrics_dir" v02-benchmark-metrics.json

  "${script_dir}/v02-benchmark-metrics-local.sh" verify \
    "$metrics_dir/v02-benchmark-metrics.json" \
    "$candidate_sha" \
    "$candidate_tree" \
    "$run_id" \
    "$workflow_run_attempt" \
    tinyland-nix
  if [ "$expected_result" = "passed" ]; then
    "${script_dir}/v02-benchmark-metrics-local.sh" require-pass \
      "$metrics_dir/v02-benchmark-metrics.json" \
      "$candidate_sha" \
      "$candidate_tree" \
      "$run_id" \
      "$workflow_run_attempt" \
      tinyland-nix
  else
    "${script_dir}/v02-benchmark-metrics-local.sh" require-incomplete \
      "$metrics_dir/v02-benchmark-metrics.json" \
      "$candidate_sha" \
      "$candidate_tree" \
      "$run_id" \
      "$workflow_run_attempt" \
      tinyland-nix
  fi
fi

echo "remote-validate: verified immutable proof artifacts for run ${run_id}"
if [ "$proof_status" -ne 0 ]; then
  exit "$proof_status"
fi
