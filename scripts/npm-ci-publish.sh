#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-0.1.0}}"
version="${version#v}"
out_dir="$repo_root/dist/out/v${version}"
npm_tgz_dir="$out_dir/npm-tarballs"
handoff_dir="$out_dir/handoff"
report="$handoff_dir/npm-ci-publish.md"

platform_tarballs=(
  "oauth-mux-linux-x64-${version}.tgz"
  "oauth-mux-linux-arm64-${version}.tgz"
  "oauth-mux-darwin-x64-${version}.tgz"
  "oauth-mux-darwin-arm64-${version}.tgz"
  "oauth-mux-win32-x64-${version}.tgz"
  "oauth-mux-win32-arm64-${version}.tgz"
)
root_tarball="oauth-mux-${version}.tgz"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

append() {
  printf '%s\n' "$*" >>"$report"
}

require_file() {
  if [ ! -f "$1" ]; then
    printf 'missing npm publication input: %s\n' "$1" >&2
    exit 1
  fi
}

package_field() {
  local tarball="$1"
  local field="$2"
  tar -xOf "$tarball" package/package.json | jq -er ".$field"
}

ensure_ci_boundary() {
  if [ "${OMUX_NPM_PUBLISH_PLAN_ONLY:-0}" = "1" ]; then
    return
  fi
  if [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "${OMUX_NPM_CI_ALLOW_LOCAL:-0}" != "1" ]; then
    cat >&2 <<'EOF'
npm publication is CI-only.

Run through .github/workflows/npm-publish.yml, or set
OMUX_NPM_CI_ALLOW_LOCAL=1 only for a controlled local dry-run.
EOF
    exit 2
  fi
}

ensure_confirmed() {
  if [ "${OMUX_NPM_PUBLISH_PLAN_ONLY:-0}" = "1" ]; then
    return
  fi
  if [ "${OMUX_NPM_PUBLISH_CONFIRM:-}" != "publish-npm" ]; then
    cat >&2 <<EOF
npm publication is disabled.

Re-run in CI with:

  OMUX_NPM_PUBLISH_CONFIRM=publish-npm ./scripts/npm-ci-publish.sh ${version}
EOF
    exit 2
  fi
}

package_exists() {
  local name="$1"
  local pkg_version="$2"
  NPM_CONFIG_USERCONFIG="$npmrc" npm view "${name}@${pkg_version}" version >/dev/null 2>&1
}

publish_one() {
  local tarball="$1"
  local name
  local pkg_version
  name="$(package_field "$tarball" name)"
  pkg_version="$(package_field "$tarball" version)"

  if [ "$pkg_version" != "$version" ]; then
    printf 'tarball version mismatch for %s: expected %s, found %s\n' "$tarball" "$version" "$pkg_version" >&2
    exit 1
  fi

  if [ "${OMUX_NPM_PUBLISH_PLAN_ONLY:-0}" = "1" ]; then
    append "- plan: \`${name}@${pkg_version}\` from \`npm-tarballs/$(basename "$tarball")\`"
    return
  fi

  if [ "${OMUX_NPM_SKIP_EXISTING:-1}" = "1" ] && package_exists "$name" "$pkg_version"; then
    append "- skipped existing: \`${name}@${pkg_version}\`"
    return
  fi

  local args=(publish "$tarball" --provenance)
  case "$name" in
    @oauth-mux/*)
      args+=(--access public)
      ;;
  esac
  if [ "${OMUX_NPM_PUBLISH_DRY_RUN:-0}" = "1" ]; then
    args+=(--dry-run)
  fi

  NPM_CONFIG_USERCONFIG="$npmrc" npm "${args[@]}"
  if [ "${OMUX_NPM_PUBLISH_DRY_RUN:-0}" = "1" ]; then
    append "- dry-run OK: \`${name}@${pkg_version}\`"
  else
    append "- published: \`${name}@${pkg_version}\`"
  fi
}

ensure_ci_boundary
ensure_confirmed

if [ ! -d "$out_dir" ]; then
  printf 'release output does not exist: %s\n' "$out_dir" >&2
  printf 'run in CI after: just release-proof-local %s\n' "$version" >&2
  exit 1
fi

require_command npm
require_command jq
require_command tar

mkdir -p "$handoff_dir"

for tarball in "${platform_tarballs[@]}" "$root_tarball"; do
  require_file "$npm_tgz_dir/$tarball"
done

cat >"$report" <<EOF
# oauth-mux v${version} npm CI Publish

Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Release tree: \`dist/out/v${version}\`

This report records CI-only npm publication from prebuilt tarballs. It must not
include token material.

EOF

if [ "${OMUX_NPM_PUBLISH_PLAN_ONLY:-0}" = "1" ]; then
  append "## plan"
  append
else
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-npm-publish.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  npmrc="$tmp/npmrc"
  "$repo_root/scripts/resolve-npm-token.sh" --npmrc "$npmrc" >/dev/null

  append "## npm identity"
  append
  npm_user="$(NPM_CONFIG_USERCONFIG="$npmrc" npm whoami --registry=https://registry.npmjs.org/)"
  append "- authenticated as: \`${npm_user}\`"
  if [ "${OMUX_NPM_PUBLISH_DRY_RUN:-0}" = "1" ]; then
    append "- mode: dry-run"
  else
    append "- mode: publish"
  fi
  append "- provenance: enabled"
  append
  append "## packages"
  append
fi

for tarball in "${platform_tarballs[@]}"; do
  publish_one "$npm_tgz_dir/$tarball"
done
publish_one "$npm_tgz_dir/$root_tarball"

printf 'npm CI publish report: %s\n' "$report"
