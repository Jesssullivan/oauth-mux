#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
release_tree="${1:-}"
failed=0

for retired_path in \
  "$repo_root/dist/npm" \
  "$repo_root/scripts/npm-ci-publish.sh" \
  "$repo_root/.github/workflows/npm-publish.yml"; do
  if [ -e "$retired_path" ]; then
    printf 'retired npm publication residue must not exist: %s\n' "$retired_path" >&2
    failed=1
  fi
done

if [ -n "$release_tree" ]; then
  for retired_path in "$release_tree/npm" "$release_tree/npm-tarballs"; do
    if [ -e "$retired_path" ]; then
      printf 'retired npm artifact reappeared in release staging: %s\n' "$retired_path" >&2
      failed=1
    fi
  done
fi

exit "$failed"
