#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/v02-prerelease-readiness-local.sh run <bundle-dir> <candidate-sha> <candidate-tree> <workflow-run-id> <workflow-run-attempt> <gf-target-class>
  scripts/v02-prerelease-readiness-local.sh emit <bundle-dir> <candidate-sha> <candidate-tree> <workflow-run-id> <workflow-run-attempt> <gf-target-class>
  scripts/v02-prerelease-readiness-local.sh verify <bundle-dir> <candidate-sha> <candidate-tree> <workflow-run-id> <workflow-run-attempt> <gf-target-class>

The bundle is a candidate-bound synthetic fixture for the bounded TIN-3005
manifest gate. It is not a signed release artifact set.
USAGE
}

fail() {
  echo "v02-prerelease-readiness: $*" >&2
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
  [[ "$value" =~ ^[1-9][0-9]*$ ]] ||
    fail "${label} must be a positive integer"
}

require_inputs() {
  local bundle_dir="$1"
  local candidate_sha="$2"
  local candidate_tree="$3"
  local workflow_run_id="$4"
  local workflow_run_attempt="$5"
  local gf_target_class="$6"

  [[ "$bundle_dir" = /* ]] || fail "bundle-dir must be an absolute path"
  require_sha candidate_sha "$candidate_sha"
  require_sha candidate_tree "$candidate_tree"
  require_positive_integer workflow_run_id "$workflow_run_id"
  require_positive_integer workflow_run_attempt "$workflow_run_attempt"
  [ "$gf_target_class" = "tinyland-nix" ] ||
    fail "gf-target-class must be tinyland-nix"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v zig >/dev/null 2>&1 || fail "zig is required"
}

record_repo_zig_cache_state() {
  repo_zig_cache_owned=false
  if [ ! -e "$repo_root/.zig-cache" ] && [ ! -L "$repo_root/.zig-cache" ]; then
    repo_zig_cache_owned=true
  fi
}

remove_owned_repo_zig_cache() {
  local cache_dir="$repo_root/.zig-cache"
  local tmp_dir="$cache_dir/tmp"

  [ "$repo_zig_cache_owned" = true ] || return 0
  if [ ! -e "$cache_dir" ] && [ ! -L "$cache_dir" ]; then
    return
  fi
  [ -d "$cache_dir" ] && [ ! -L "$cache_dir" ] ||
    fail "repo-local .zig-cache residue is not a regular directory"
  [ -d "$tmp_dir" ] && [ ! -L "$tmp_dir" ] ||
    fail "repo-local .zig-cache residue is not the expected Zig tmp directory"
  rmdir "$tmp_dir" ||
    fail "repo-local .zig-cache/tmp contains unexpected residue"
  rmdir "$cache_dir" ||
    fail "repo-local .zig-cache contains files outside the owned tmp directory"
}

cleanup_on_exit() {
  local original_status="$1"
  local cleanup_status

  trap - EXIT HUP INT TERM
  set +e
  (remove_owned_repo_zig_cache)
  cleanup_status=$?
  set -e
  if [ "$original_status" -ne 0 ]; then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}

build_id_for() {
  local workflow_run_id="$1"
  local workflow_run_attempt="$2"
  local gf_target_class="$3"
  printf 'gf-%s-run-%s-attempt-%s\n' \
    "$gf_target_class" "$workflow_run_id" "$workflow_run_attempt"
}

run_manifest_gate() {
  local bundle_dir="$1"
  local candidate_sha="$2"
  local candidate_tree="$3"

  (
    cd "$repo_root"
    zig build v02-prerelease-manifest-check -Doptimize=Debug -- \
      "$bundle_dir/resolved-manifest.json" \
      "$bundle_dir/artifacts" \
      "$candidate_sha" \
      "$candidate_tree"
  )
}

assert_bundle_layout() {
  local bundle_dir="$1"
  local entries

  [ -d "$bundle_dir" ] && [ ! -L "$bundle_dir" ] ||
    fail "bundle directory is missing or is a symlink"
  shopt -s nullglob dotglob
  entries=("$bundle_dir"/*)
  shopt -u nullglob dotglob
  [ "${#entries[@]}" -eq 2 ] ||
    fail "bundle must contain exactly resolved-manifest.json and artifacts"
  [ -f "$bundle_dir/resolved-manifest.json" ] &&
    [ ! -L "$bundle_dir/resolved-manifest.json" ] ||
    fail "resolved manifest must be a regular non-symlink file"
  [ -d "$bundle_dir/artifacts" ] &&
    [ ! -L "$bundle_dir/artifacts" ] ||
    fail "artifact root must be a non-symlink directory"
}

verify_bundle() {
  local bundle_dir="$1"
  local candidate_sha="$2"
  local candidate_tree="$3"
  local workflow_run_id="$4"
  local workflow_run_attempt="$5"
  local gf_target_class="$6"
  local expected_build_id

  require_inputs "$bundle_dir" "$candidate_sha" "$candidate_tree" \
    "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
  assert_bundle_layout "$bundle_dir"
  expected_build_id="$(
    build_id_for "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
  )"
  jq -e \
    --arg candidate_sha "$candidate_sha" \
    --arg candidate_tree "$candidate_tree" \
    --arg expected_build_id "$expected_build_id" \
    '
      .release.source_commit == $candidate_sha
      and .release.source_tree == $candidate_tree
      and .release.build_id.value == $expected_build_id
    ' "$bundle_dir/resolved-manifest.json" >/dev/null ||
    fail "resolved manifest is not bound to the expected candidate and run"
  run_manifest_gate "$bundle_dir" "$candidate_sha" "$candidate_tree"
}

emit_bundle() (
  local bundle_dir="$1"
  local candidate_sha="$2"
  local candidate_tree="$3"
  local workflow_run_id="$4"
  local workflow_run_attempt="$5"
  local gf_target_class="$6"
  local bundle_parent tmp_dir build_id

  require_inputs "$bundle_dir" "$candidate_sha" "$candidate_tree" \
    "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
  [ ! -e "$bundle_dir" ] && [ ! -L "$bundle_dir" ] ||
    fail "refusing to replace an existing bundle path"

  bundle_parent="$(dirname "$bundle_dir")"
  mkdir -p "$bundle_parent"
  tmp_dir="$(mktemp -d "${bundle_dir}.tmp.XXXXXX")"
  trap 'rm -rf "$tmp_dir"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  mkdir "$tmp_dir/artifacts"
  build_id="$(
    build_id_for "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
  )"

  (
    cd "$repo_root"
    zig run \
      --dep release_manifest \
      -Mroot=scripts/v02-prerelease-bundle.zig \
      -Mrelease_manifest=src/release_manifest.zig \
      -- \
      "$tmp_dir" \
      "$candidate_sha" \
      "$candidate_tree" \
      "$build_id"
  )

  verify_bundle "$tmp_dir" "$candidate_sha" "$candidate_tree" \
    "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
  mv "$tmp_dir" "$bundle_dir"
  trap - EXIT HUP INT TERM
)

mode="${1:-}"
case "$mode" in
  run|emit|verify)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

bundle_dir="$2"
candidate_sha="$3"
candidate_tree="$4"
workflow_run_id="$5"
workflow_run_attempt="$6"
gf_target_class="$7"

record_repo_zig_cache_state
trap 'cleanup_on_exit "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$mode" in
  run)
    require_inputs "$bundle_dir" "$candidate_sha" "$candidate_tree" \
      "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
    (
      cd "$repo_root"
      zig build v02-prerelease-readiness -Doptimize=Debug
    )
    emit_bundle "$bundle_dir" "$candidate_sha" "$candidate_tree" \
      "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
    ;;
  emit)
    emit_bundle "$bundle_dir" "$candidate_sha" "$candidate_tree" \
      "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
    ;;
  verify)
    verify_bundle "$bundle_dir" "$candidate_sha" "$candidate_tree" \
      "$workflow_run_id" "$workflow_run_attempt" "$gf_target_class"
    ;;
esac
