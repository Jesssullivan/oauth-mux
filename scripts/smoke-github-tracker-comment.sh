#!/usr/bin/env bash
# Offline smoke for the guarded GitHub tracker-comment fallback.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d -t omux-gh-comment-smoke.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

safe="$TMP/safe.md"
leak="$TMP/leak.md"

printf 'Safe tracker update with redacted status evidence.\n' >"$safe"
printf 'Authorization: Bearer live-token-value-that-should-not-post\n' >"$leak"

PATH="$TMP:$PATH"
cat >"$TMP/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "auth" && "${2:-}" == "status" ]]; then
  exit 0
fi
if [[ "${1:-}" == "issue" && "${2:-}" == "comment" ]]; then
  echo "smoke gh should not be asked to post during --dry-run" >&2
  exit 9
fi
echo "unexpected gh invocation: $*" >&2
exit 9
SH
chmod +x "$TMP/gh"

"$ROOT/scripts/github-tracker-comment.sh" --dry-run --repo Jesssullivan/oauth-mux 198 "$safe" >"$TMP/out.txt"
grep -q 'dry-run ok repo=Jesssullivan/oauth-mux issue=198' "$TMP/out.txt"

"$ROOT/scripts/github-tracker-comment.sh" --help >"$TMP/help.txt"
grep -q 'USAGE' "$TMP/help.txt"
grep -q -- '--ignore-env-token' "$TMP/help.txt"

if "$ROOT/scripts/github-tracker-comment.sh" --dry-run 198 "$leak" >"$TMP/leak.out" 2>"$TMP/leak.err"; then
  echo "smoke-github-tracker-comment: expected secret-like body to fail" >&2
  exit 1
fi
grep -q 'possible unredacted secret' "$TMP/leak.err"

printf 'smoke-github-tracker-comment: all assertions passed.\n'
