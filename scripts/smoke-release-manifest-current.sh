#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/release-manifest-current.sh
source "$repo_root/scripts/release-manifest-current.sh"

version="$("$repo_root/scripts/project-version.sh")"
baseline_manifest="$release_manifest_file"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

release_manifest_require_current_v0_1_15 "$version"

if release_manifest_archive_rows | awk -F '\t' '
  {
    count = split($6, members, ",")
    for (i = 1; i <= count; i++) {
      if (members[i] == "omux" || members[i] == "omux.exe") found = 1
    }
  }
  END { exit found ? 0 : 1 }
'; then
  printf 'current archive projection must not activate v0.2 omux members\n' >&2
  exit 1
fi
if release_manifest_github_attachment_paths | grep -Fxq 'artifacts/release-manifest.json'; then
  printf 'declaration manifest must not enter the current publish set\n' >&2
  exit 1
fi

expect_rejected() {
  local label="$1"
  local filter="$2"
  local requested_version="${3:-$version}"
  local candidate="$tmp/${label}.json"

  jq "$filter" "$baseline_manifest" >"$candidate"
  release_manifest_file="$candidate"
  if release_manifest_require_current_v0_1_15 "$requested_version" >/dev/null 2>&1; then
    printf 'release manifest mutation was accepted: %s\n' "$label" >&2
    exit 1
  fi
}

expect_rejected wrong-version '.release.version = "9.9.9"'
expect_rejected jointly-bumped-v0-2 '.release.version = "0.2.0"' '0.2.0'
expect_rejected activate-v0-2-members \
  '.release_assets[0].current_v0_1_15_members = .release_assets[0].declared_v0_2_members'
expect_rejected path-traversal '.release_assets[0].staged_path = "artifacts/../escape.tar.gz"'
expect_rejected duplicate-asset-id \
  '.release_assets[0].id as $id | .release_assets[1].id = $id'
expect_rejected unknown-target '.release_assets[0].target_id = "missing-target"'
expect_rejected unpublished-target '.targets[0].artifact.published = false'
expect_rejected control-character '.release_assets[0].release_name = "bad\tname"'
expect_rejected publish-declaration-manifest \
  '(.release_assets[] | select(.kind == "manifest") | .materialization_state) = "v0_1_15_present_v0_2_pending_tin_2050"'

release_manifest_file="$baseline_manifest"
printf 'current v0.1.15 release-manifest projection rejects unsafe drift\n'
