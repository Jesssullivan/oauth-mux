#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/remote-validate.sh <target> [ref] [--no-watch]

Targets:
  check          Run just check-local on the GloriousFlywheel runner.
  test           Run zig build test on the GloriousFlywheel runner.
  build          Run zig build on the GloriousFlywheel runner.
  e2e            Run just e2e-local on the GloriousFlywheel runner.
  release-proof  Run just release-proof-local on the GloriousFlywheel runner.

The workflow file must already exist on the repository default branch. After
that, pass a branch or SHA as [ref] to validate it remotely.
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
  check|test|build|e2e|release-proof)
    ;;
  *)
    echo "remote-validate: unsupported target: $target" >&2
    usage
    exit 2
    ;;
esac

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

echo "remote-validate: dispatching ${target} on ${repo}@${ref}"

args=(workflow run "$workflow" --repo "$repo" --ref "$ref" -f "target=$target")
if [ -n "$version" ]; then
  args+=(-f "version=$version")
fi
gh "${args[@]}"

if [ "$watch" != "1" ]; then
  echo "remote-validate: dispatched; watch with: gh run list --repo ${repo} --workflow ${workflow}"
  exit 0
fi

echo "remote-validate: locating latest workflow_dispatch run"
run_id="$(gh run list \
  --repo "$repo" \
  --workflow "$workflow" \
  --branch "$ref" \
  --event workflow_dispatch \
  --json databaseId,status,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[0].databaseId // empty' \
  --limit 10)"

if [ -z "$run_id" ]; then
  echo "remote-validate: dispatched, but GitHub has not exposed the run yet" >&2
  echo "remote-validate: check: gh run list --repo ${repo} --workflow ${workflow}" >&2
  exit 1
fi

echo "remote-validate: watching run ${run_id}"
gh run watch "$run_id" --repo "$repo" --exit-status
