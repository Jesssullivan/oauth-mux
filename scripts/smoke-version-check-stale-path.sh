#!/usr/bin/env sh
# Regression: production version --check must execute a PATH winner's bounded
# local version query so newer installed bytes cannot degrade to unknown.

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
case "$*" in
  'version --json') printf '%s\n' '{"version":"999.0.0"}' ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$path_winner"

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

jq -e \
  '.path_installed.present == true
   and .path_installed.verdict == "stale"
   and .path_installed.facts.version == "999.0.0"
   and .stale == true
   and .exit_code == 1' \
  "$tmp/check.json" >/dev/null ||
  { printf '%s\n' 'smoke-version-check-stale-path: stale PATH facts were not preserved' >&2; exit 1; }

printf '%s\n' 'version check stale PATH smoke passed (bounded local executable only)'
