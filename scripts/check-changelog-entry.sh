#!/usr/bin/env bash
# TIN-2462 remaining-scope item 3: "the release-proof lane checks the tag's
# version has a CHANGELOG entry (fail the cut, not PRs)."
#
# Usage: scripts/check-changelog-entry.sh <version>   # e.g. 0.1.16 or v0.1.16
#
# Fails closed (nonzero exit) if CHANGELOG.md has no `## v<version>` heading.
# This is a release-proof-lane gate, not a PR gate: it is meant to be called
# from release-proof.yml / release-local.sh right before a cut, never from
# ci.yml on every push/PR.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
changelog="$repo_root/CHANGELOG.md"

version="${1:-}"
if [ -z "$version" ]; then
  printf 'usage: %s <version>\n' "$0" >&2
  exit 2
fi
version="${version#v}"

if [ ! -f "$changelog" ]; then
  printf 'check-changelog-entry: CHANGELOG.md not found at %s\n' "$changelog" >&2
  exit 1
fi

# Match the existing heading shape: "## v0.1.15 — 2026-07-10 — "valet""
# or the bare "## v0.1.13" form. Anchor on the version token so a heading
# for v0.1.16 does not also match v0.1.160+ etc.
pattern="^## v${version}([[:space:]—-]|\$)"
if ! grep -E "$pattern" "$changelog" >/dev/null; then
  printf 'check-changelog-entry: CHANGELOG.md has no "## v%s" entry\n' "$version" >&2
  printf 'a release cut requires a CHANGELOG entry for the version being cut; add one before re-running release proof\n' >&2
  exit 1
fi

printf 'check-changelog-entry: CHANGELOG.md has a v%s entry\n' "$version"
