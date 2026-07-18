#!/usr/bin/env sh
# Regression: production version --check must never execute a PATH-selected
# binary. Different bytes fail closed from SHA identity alone.

set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
omux_bin="$repo_root/zig-out/bin/oauth-mux"
[ -f "$omux_bin" ] && [ -x "$omux_bin" ] ||
  { printf '%s\n' 'smoke-version-check-stale-path: built oauth-mux is unavailable' >&2; exit 1; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/omux-version-check-stale.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/bin"

path_winner="$tmp/bin/oauth-mux"
cat >"$path_winner" <<'EOF'
#!/bin/sh
script_dir=${0%/*}
: >"$script_dir/path-winner-executed"
printf '%s\n' '{"version":"999.0.0"}'
EOF
chmod +x "$path_winner"
sentinel="$tmp/bin/path-winner-executed"

set +e
PATH="$tmp/bin" "$omux_bin" version --check --json \
  >"$tmp/check.json" 2>"$tmp/check.stderr"
check_status=$?
set -e

[ "$check_status" -eq 1 ] || {
  printf 'smoke-version-check-stale-path: expected exit 1, got %s\n' "$check_status" >&2
  cat "$tmp/check.json" >&2
  cat "$tmp/check.stderr" >&2
  exit 1
}
[ ! -e "$sentinel" ] ||
  { printf '%s\n' 'smoke-version-check-stale-path: PATH winner was executed' >&2; exit 1; }

jq -e \
  '.path_installed.present == true
   and .path_installed.verdict == "diverged"
   and .path_installed.facts.version == null
   and .path_installed.facts.sha256 != .running.sha256
   and .stale == true
   and .exit_code == 1' \
  "$tmp/check.json" >/dev/null ||
  { printf '%s\n' 'smoke-version-check-stale-path: SHA mismatch did not fail closed' >&2; exit 1; }

mkdir "$tmp/matching-bin"
cp "$omux_bin" "$tmp/matching-bin/oauth-mux"
chmod +x "$tmp/matching-bin/oauth-mux"
set +e
PATH="$tmp/matching-bin" "$omux_bin" version --check --json \
  >"$tmp/matching.json" 2>"$tmp/matching.stderr"
matching_status=$?
set -e
[ "$matching_status" -eq 0 ] || [ "$matching_status" -eq 1 ] || {
  printf 'smoke-version-check-stale-path: matching probe exited %s\n' "$matching_status" >&2
  cat "$tmp/matching.json" >&2
  cat "$tmp/matching.stderr" >&2
  exit 1
}
jq -e \
  '.path_installed.present == true
   and .path_installed.verdict == "match"
   and .path_installed.facts.version == .running.version
   and .path_installed.facts.sha256 == .running.sha256' \
  "$tmp/matching.json" >/dev/null ||
  { printf '%s\n' 'smoke-version-check-stale-path: SHA-equivalent version reuse failed' >&2; exit 1; }

printf '%s\n' 'version check PATH smoke passed (SHA-only; selected binary never executed)'
