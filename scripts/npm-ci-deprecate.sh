#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-${VERSION:-0.1.1}}"
version="${version#v}"
packages_csv="${OMUX_NPM_DEPRECATE_PACKAGES:-oauth-mux-linux-x64,oauth-mux-linux-arm64,oauth-mux-darwin-x64,oauth-mux-darwin-arm64}"
message="${OMUX_NPM_DEPRECATE_MESSAGE:-oauth-mux 0.1.1 platform package was orphaned by a failed release. Use oauth-mux@0.1.2 or newer.}"
plan_only="${OMUX_NPM_DEPRECATE_PLAN_ONLY:-1}"
overwrite="${OMUX_NPM_DEPRECATE_OVERWRITE:-0}"
out_dir="$repo_root/dist/out/v${version}"
handoff_dir="$out_dir/handoff"
report="$handoff_dir/npm-ci-deprecate.md"

case "$plan_only" in
  1|true|yes|on) plan_only="1" ;;
  0|false|no|off) plan_only="0" ;;
  *)
    printf 'invalid OMUX_NPM_DEPRECATE_PLAN_ONLY: %s\n' "$plan_only" >&2
    exit 2
    ;;
esac

case "$overwrite" in
  1|true|yes|on) overwrite="1" ;;
  0|false|no|off) overwrite="0" ;;
  *)
    printf 'invalid OMUX_NPM_DEPRECATE_OVERWRITE: %s\n' "$overwrite" >&2
    exit 2
    ;;
esac

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

append() {
  printf '%s\n' "$*" >>"$report"
}

ensure_ci_boundary() {
  if [ "$plan_only" = "1" ]; then
    return
  fi
  if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    cat >&2 <<'EOF'
npm deprecation is CI-only.

Run through .github/workflows/npm-deprecate.yml with plan_only=false.
EOF
    exit 2
  fi
}

ensure_confirmed() {
  if [ "$plan_only" = "1" ]; then
    return
  fi
  if [ "${OMUX_NPM_DEPRECATE_CONFIRM:-}" != "deprecate-npm" ]; then
    cat >&2 <<EOF
npm deprecation is disabled.

Re-run in CI with:

  OMUX_NPM_DEPRECATE_CONFIRM=deprecate-npm ./scripts/npm-ci-deprecate.sh ${version}
EOF
    exit 2
  fi
}

package_exists() {
  local spec="$1"
  NPM_CONFIG_USERCONFIG="${npmrc:-}" npm view "$spec" version --registry=https://registry.npmjs.org/ >/dev/null 2>&1
}

current_deprecation() {
  local spec="$1"
  NPM_CONFIG_USERCONFIG="${npmrc:-}" npm view "$spec" deprecated --registry=https://registry.npmjs.org/ 2>/dev/null || true
}

deprecate_one() {
  local package="$1"
  package="${package//[[:space:]]/}"
  if [ -z "$package" ]; then
    return
  fi

  local spec="${package}@${version}"
  if ! package_exists "$spec"; then
    append "- missing, skipped: \`${spec}\`"
    return
  fi

  local existing
  existing="$(current_deprecation "$spec")"
  if [ -n "$existing" ]; then
    if [ "$existing" = "$message" ]; then
      append "- already deprecated: \`${spec}\`"
      return
    fi
    if [ "$overwrite" != "1" ]; then
      append "- already deprecated with different message, skipped: \`${spec}\`"
      return
    fi
  fi

  if [ "$plan_only" = "1" ]; then
    append "- plan: deprecate \`${spec}\`"
    return
  fi

  NPM_CONFIG_USERCONFIG="$npmrc" npm deprecate "$spec" "$message" --registry=https://registry.npmjs.org/
  append "- deprecated: \`${spec}\`"
}

ensure_ci_boundary
ensure_confirmed
require_command npm

mkdir -p "$handoff_dir"

cat >"$report" <<EOF
# oauth-mux v${version} npm CI Deprecate

Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

This report records CI-only npm deprecation planning or mutation. It must not
include token material.

## mode

- plan_only: \`${plan_only}\`
- version: \`${version}\`
- message: \`${message}\`

EOF

if [ "$plan_only" = "0" ]; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-npm-deprecate.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  npmrc="$tmp/npmrc"
  "$repo_root/scripts/resolve-npm-token.sh" --npmrc "$npmrc" >/dev/null

  append "## npm identity"
  append
  npm_user="$(NPM_CONFIG_USERCONFIG="$npmrc" npm whoami --registry=https://registry.npmjs.org/)"
  append "- authenticated as: \`${npm_user}\`"
  append
fi

append "## packages"
append

IFS=',' read -r -a packages <<<"$packages_csv"
for package in "${packages[@]}"; do
  deprecate_one "$package"
done

printf 'npm CI deprecate report: %s\n' "$report"
