#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
resolver="$repo_root/scripts/resolve-release-version.sh"
remote="$repo_root/.github/workflows/remote-validate.yml"
release="$repo_root/.github/workflows/release-proof.yml"
registry="$repo_root/.github/workflows/registry-dry-run.yml"
system_package="$repo_root/.github/workflows/system-package-install-qa.yml"
system_package_script="$repo_root/scripts/system-package-install-qa.sh"
tag_release="$repo_root/.github/workflows/release.yml"
injection_marker="$(mktemp "${TMPDIR:-/tmp}/omux-just-injection-marker.XXXXXX")"
injection_output="$(mktemp "${TMPDIR:-/tmp}/omux-just-injection-output.XXXXXX")"
rm -f "$injection_marker"
trap 'rm -f "$injection_marker" "$injection_output"' EXIT HUP INT TERM

fail() {
  printf 'smoke-release-workflow-version-authority: %s\n' "$*" >&2
  exit 1
}

for file in "$resolver" "$remote" "$release" "$registry" "$system_package" "$system_package_script" "$tag_release"; do
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

manifest_injection="manifest\"; : >\"$injection_marker\"; #"
artifact_root_injection="artifact root\"; : >\"$injection_marker\"; #"
expected_commit_injection="expected commit\"; : >\"$injection_marker\"; #"
expected_tree_injection="expected tree\"; : >\"$injection_marker\"; #"
just --justfile "$repo_root/justfile" --working-directory "$repo_root" \
  zig="printf 'argument=<%s>\\n'" \
  v02-prerelease-manifest-check-local \
  "$manifest_injection" \
  "$artifact_root_injection" \
  "$expected_commit_injection" \
  "$expected_tree_injection" >"$injection_output"
[ ! -e "$injection_marker" ] ||
  fail "v0.2 manifest recipe executed an injection-shaped argument"
grep -F "argument=<$manifest_injection>" "$injection_output" >/dev/null ||
  fail "v0.2 manifest recipe did not preserve the manifest path argument"
grep -F "argument=<$artifact_root_injection>" "$injection_output" >/dev/null ||
  fail "v0.2 manifest recipe did not preserve the artifact root argument"
grep -F "argument=<$expected_commit_injection>" "$injection_output" >/dev/null ||
  fail "v0.2 manifest recipe did not preserve the expected commit argument"
grep -F "argument=<$expected_tree_injection>" "$injection_output" >/dev/null ||
  fail "v0.2 manifest recipe did not preserve the expected tree argument"

is_stable_release_tag() {
  printf '%s' "$1" | awk '
    NR == 1 { valid = ($0 ~ /^v0[.]1[.][0-9]+$/) }
    NR > 1 { valid = 0 }
    END { exit !(NR == 1 && valid) }
  '
}

for tag in v0.1.0 v0.1.15 v0.1.999; do
  is_stable_release_tag "$tag" || fail "stable tag fixture was rejected: $tag"
done
multiline_tag="$(printf 'v0.1.15\nuntrusted')"
for tag in v0.2.0 v0.2.0-rc.1 v0.1.15-rc.1 v1.1.15 0.1.15 \
  'v0.1.15/untrusted' "$multiline_tag"; do
  if is_stable_release_tag "$tag"; then
    fail "non-stable tag fixture was accepted: $tag"
  fi
done

grep -F 'if [[ ! "$RELEASE_TAG" =~ ^v0\.1\.[0-9]+$ ]]; then' "$tag_release" >/dev/null ||
  fail "tag release workflow must fail closed on every non-v0.1.patch tag"
grep -A3 '^  build:' "$tag_release" | grep -F 'needs: authorize-stable-tag' >/dev/null ||
  fail "release staging must depend on stable tag authorization"
release_action_block="$(grep -A12 'softprops/action-gh-release@v2' "$tag_release")"
printf '%s\n' "$release_action_block" | grep -F 'prerelease: false' >/dev/null ||
  fail "stable GitHub releases must set prerelease=false literally"
printf '%s\n' "$release_action_block" | grep -F 'make_latest: true' >/dev/null ||
  fail "stable GitHub releases must set make_latest=true literally"
if printf '%s\n' "$release_action_block" | grep -F 'prerelease: true' >/dev/null; then
  fail "release.yml must not contain a v0.2 prerelease publication lane"
fi

printf 'smoke-release-workflow-version-authority: ok\n'
