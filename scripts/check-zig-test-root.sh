#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname "$0")/.." && pwd)"
expected="$(mktemp "${TMPDIR:-/tmp}/omux-test-root-expected.XXXXXX")"
actual="$(mktemp "${TMPDIR:-/tmp}/omux-test-root-actual.XXXXXX")"
trap 'rm -f "$expected" "$actual"' EXIT HUP INT TERM

cd "$repo_root"

find src -type f -name '*.zig' \
  | sed 's#^src/##' \
  | grep -v '^tests\.zig$' \
  | LC_ALL=C sort >"$expected"

sed -nE 's/^[[:space:]]+pub const [A-Za-z_][A-Za-z0-9_]* = @import\("([^"]+\.zig)"\);$/\1/p' src/tests.zig \
  | LC_ALL=C sort >"$actual"

if ! diff -u "$expected" "$actual"; then
  printf 'src/tests.zig must import every Zig source file exactly once\n' >&2
  exit 1
fi

printf 'Zig test root covers every source file\n'
