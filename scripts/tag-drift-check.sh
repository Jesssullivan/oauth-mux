#!/usr/bin/env bash
# TIN-2462 remaining-scope item 1: a cheap job that computes commits-ahead
# and days-ahead of main vs the latest v* tag, and warns (never gates) when
# either crosses a threshold.
#
# Usage: scripts/tag-drift-check.sh [ref]
#   ref defaults to HEAD. Requires a full-depth checkout (fetch-depth: 0)
#   so tag history and commit dates are actually visible.
#
# Env overrides:
#   OMUX_TAG_DRIFT_COMMITS_THRESHOLD (default 20)
#   OMUX_TAG_DRIFT_DAYS_THRESHOLD    (default 14)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

ref="${1:-HEAD}"
commits_threshold="${OMUX_TAG_DRIFT_COMMITS_THRESHOLD:-20}"
days_threshold="${OMUX_TAG_DRIFT_DAYS_THRESHOLD:-14}"

latest_tag="$(git tag --list 'v*' --sort=-v:refname | head -1 || true)"
if [ -z "$latest_tag" ]; then
  printf 'tag-drift-check: no v* tag found; nothing to compare against\n'
  exit 0
fi

commits_ahead="$(git rev-list --count "${latest_tag}..${ref}" 2>/dev/null || echo 0)"

tag_epoch="$(git log -1 --format=%ct "$latest_tag" 2>/dev/null || echo "")"
if [ -z "$tag_epoch" ]; then
  printf 'tag-drift-check: could not resolve commit date for %s; skipping day-based check\n' "$latest_tag" >&2
  days_ahead=0
else
  now_epoch="$(date +%s)"
  days_ahead=$(( (now_epoch - tag_epoch) / 86400 ))
fi

printf 'tag-drift-check: latest tag %s, %s commits ahead, %s days ahead of %s\n' \
  "$latest_tag" "$commits_ahead" "$days_ahead" "$ref"

drifted=0
if [ "$commits_ahead" -ge "$commits_threshold" ]; then
  printf '::warning::release channel is %s commits ahead of %s (threshold %s) — a cut may be owed (TIN-2462)\n' \
    "$commits_ahead" "$latest_tag" "$commits_threshold"
  drifted=1
fi
if [ "$days_ahead" -ge "$days_threshold" ]; then
  printf '::warning::release channel is %s days ahead of %s (threshold %s) — a cut may be owed (TIN-2462)\n' \
    "$days_ahead" "$latest_tag" "$days_threshold"
  drifted=1
fi

if [ "$drifted" -eq 0 ]; then
  printf 'tag-drift-check: within cadence thresholds (commits<%s, days<%s)\n' "$commits_threshold" "$days_threshold"
fi

# Warning-only per TIN-2462 scope ("Warning, never a gate"): always exit 0.
exit 0
