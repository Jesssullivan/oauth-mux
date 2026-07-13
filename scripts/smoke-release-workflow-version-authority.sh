#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
resolver="$repo_root/scripts/resolve-release-version.sh"
remote="$repo_root/.github/workflows/remote-validate.yml"
release="$repo_root/.github/workflows/release-proof.yml"
registry="$repo_root/.github/workflows/registry-dry-run.yml"
system_package="$repo_root/.github/workflows/system-package-install-qa.yml"
system_package_script="$repo_root/scripts/system-package-install-qa.sh"

fail() {
  printf 'smoke-release-workflow-version-authority: %s\n' "$*" >&2
  exit 1
}

for file in "$resolver" "$remote" "$release" "$registry" "$system_package" "$system_package_script"; do
  [ -f "$file" ] || fail "missing ${file#"$repo_root"/}"
done

project_version="$("$repo_root"/scripts/project-version.sh)"
[ "$($resolver)" = "$project_version" ] || fail "omitted version must resolve from build.zig.zon"
[ "$($resolver "$project_version")" = "$project_version" ] || fail "exact version must be accepted"
[ "$($resolver "v$project_version")" = "$project_version" ] || fail "v-prefixed exact version must be accepted"
if "$resolver" 9.9.9 >/dev/null 2>&1; then
  fail "an explicit version mismatch must fail closed"
fi
if "$resolver" "$(printf '%s\nuntrusted' "$project_version")" >/dev/null 2>&1; then
  fail "multiline workflow input must fail closed"
fi

for workflow in "$remote" "$release" "$registry"; do
  if grep -A3 '^      version:' "$workflow" | grep -F 'default:' >/dev/null; then
    fail "${workflow#"$repo_root"/} must not duplicate the project version"
  fi
  grep -F 'scripts/resolve-release-version.sh' "$workflow" >/dev/null ||
    fail "${workflow#"$repo_root"/} must resolve version from project authority"
done

# shellcheck disable=SC2016
if grep -F 'just release-proof-local "${{ inputs.version }}"' "$release" "$registry" >/dev/null; then
  fail "workflow input must not be interpolated directly into a shell command"
fi
if grep -F 'github.event.inputs.version' "$system_package" >/dev/null; then
  fail "published-package version must enter through the step environment"
fi
if grep -F 'pull_request:' "$system_package" >/dev/null; then
  fail "published-package QA must not silently select an external release on pull requests"
fi
grep -A4 '^      version:' "$system_package" | grep -F 'required: true' >/dev/null ||
  fail "published-package QA must require an explicit version"
if grep -A4 '^      version:' "$system_package" | grep -F 'default:' >/dev/null; then
  fail "published-package QA must not carry a fallback release version"
fi
# shellcheck disable=SC2016
grep -F 'OMUX_PUBLISHED_RELEASE_VERSION: ${{ inputs.version }}' "$system_package" >/dev/null ||
  fail "published-package version must be passed through the environment"
if "$system_package_script" "$project_version;untrusted" >/dev/null 2>&1; then
  fail "published-package QA must reject unsafe version syntax"
fi

printf 'smoke-release-workflow-version-authority: ok\n'
