#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

"$repo_root/scripts/check-retired-npm.sh" "$tmp"

mkdir "$tmp/npm"
if "$repo_root/scripts/check-retired-npm.sh" "$tmp" >/dev/null 2>&1; then
  printf 'retired npm workspace was not rejected\n' >&2
  exit 1
fi
rmdir "$tmp/npm"

mkdir "$tmp/npm-tarballs"
if "$repo_root/scripts/check-retired-npm.sh" "$tmp" >/dev/null 2>&1; then
  printf 'retired npm tarball directory was not rejected\n' >&2
  exit 1
fi

printf 'retired npm boundary smoke passed\n'
