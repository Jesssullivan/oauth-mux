#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"

historical_files='
docs/plans/keepalive-push-2026-07-02.md
docs/productionization-ledger.md
docs/tracker-updates/2026-07-09/tin-2040-m3-park.md
docs/tracker-updates/2026-07-09/tin-2077-e1-claim.md
docs/tracker-updates/2026-07-09/gh-445-valet-ladder.md
'

printf '%s\n' "$historical_files" | while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if ! sed -n '1,10p' "$repo_root/$rel" | grep -q 'Status: SUPERSEDED 2026-07-11'; then
    printf 'historical authority file lacks superseded marker: %s\n' "$rel" >&2
    exit 1
  fi
done

if grep -q 'Status: ACTIVE PLAN' "$repo_root/docs/plans/keepalive-push-2026-07-02.md"; then
  printf 'superseded keepalive plan still declares itself active\n' >&2
  exit 1
fi

if grep -Eq 'productionization-ledger\.md.*(current|feature ledger|release posture)' \
  "$repo_root/README.md" "$repo_root/docs/README.md"; then
  printf 'doc index still presents the superseded productionization ledger as current\n' >&2
  exit 1
fi

printf 'historical authority files remain explicitly superseded\n'
