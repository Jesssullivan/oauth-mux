#!/usr/bin/env bash
# Child-refresh smoke: when the managed Codex child refreshes the same
# elected account after a 401, the proxy must preserve the child's new
# Authorization header instead of re-signing every request with the stale
# materialized token from oauth-mux config.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-child-refresh: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-child-refresh: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-child-refresh.XXXXXX)"
PORTFILE="$TMP/upstream.port"
UPSTREAM_LOG="$TMP/upstream.log"
NDJSON="$TMP/adapter.ndjson"
ADAPTER_STDERR="$TMP/adapter.stderr"
STUB_REPORT="$TMP/stub-codex.report"

cleanup() {
    if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$TMP/account-B"
ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6ZmFsc2V9fQ.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"MATERIALIZED-STUCK-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"MATERIALIZED-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
EOF

cat >"$TMP/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "$TMP/account-A/auth.json" } },
        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "$TMP/account-B/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
  }
}
EOF

OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$PORTFILE" \
  OMUX_STUB_LOGFILE="$UPSTREAM_LOG" \
  OMUX_STUB_OK_BEFORE_429=99 \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for _ in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
[[ -s "$PORTFILE" ]] || { echo "stub upstream did not bind" >&2; exit 1; }
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-child-refresh: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT"

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_STUB_CODEX_TURNS=2 \
  OMUX_STUB_CODEX_CHATGPT_ACCOUNT_ID="acc-A-id" \
  OMUX_STUB_CODEX_AUTH_TOKENS="CHILD-OLD,CHILD-REFRESHED" \
  OMUX_STUB_CODEX_REPORT="$STUB_REPORT" \
  "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$NDJSON" 2>"$ADAPTER_STDERR" || {
    echo "adapter exited nonzero" >&2
    cat "$NDJSON" >&2 || true
    cat "$ADAPTER_STDERR" >&2 || true
    exit 1
}

echo "smoke-codex-child-refresh: assertions"

assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ✓ $label"
    else
        echo "  ✗ $label" >&2
        echo "    pattern: $pattern" >&2
        cat "$file" >&2
        return 1
    fi
}

assert_no_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ✗ $label (unexpected match for: $pattern)" >&2
        cat "$file" >&2
        return 1
    else
        echo "  ✓ $label"
    fi
}

assert_grep "session_started" '"kind":"session_started"' "$NDJSON"
assert_grep "same-account child auth was preserved" '"kind":"proxy_preserved_child_auth".*"reason":"same_account_child_refresh"' "$NDJSON"
assert_grep "turns stayed 200 ok" '"kind":"proxy_turn".*"status":200.*"classification":"ok"' "$NDJSON"
TURN_COUNT=$(grep -c '"kind":"proxy_turn"' "$NDJSON" | tr -d ' ')
if [[ "$TURN_COUNT" -eq 2 ]]; then
    echo "  ✓ proxy recorded both turns"
else
    echo "  ✗ proxy recorded $TURN_COUNT turns (expected 2)" >&2
    cat "$NDJSON" >&2
    exit 1
fi
assert_no_grep "no account swap fired" '"kind":"proxy_post_swap_turn"' "$NDJSON"
assert_no_grep "no stale 401 loop" '"status":401' "$NDJSON"
assert_grep "session ended broker-owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"

if grep -q '"kind":"session_started"' "$ADAPTER_STDERR"; then
    echo "  ✗ adapter status frames leaked to stderr despite --json-status-file" >&2
    exit 1
else
    echo "  ✓ --json-status-file keeps adapter status frames out of stderr"
fi

REQ_COUNT=$(jq -s 'length' "$UPSTREAM_LOG")
if [[ "$REQ_COUNT" -eq 2 ]]; then
    echo "  ✓ upstream saw both child turns"
else
    echo "  ✗ upstream saw $REQ_COUNT requests (expected 2)" >&2
    cat "$UPSTREAM_LOG" >&2
    exit 1
fi

DISTINCT_AUTH=$(jq -r .auth_prefix "$UPSTREAM_LOG" | sort -u | wc -l | tr -d ' ')
if [[ "$DISTINCT_AUTH" -eq 2 ]]; then
    echo "  ✓ upstream saw refreshed child bearer change"
else
    echo "  ✗ upstream did not see refreshed child bearer; proxy likely reused stale materialized token" >&2
    jq -r .auth_prefix "$UPSTREAM_LOG" >&2
    exit 1
fi

DISTINCT_ACCOUNTS=$(jq -r .account_id "$UPSTREAM_LOG" | sort -u | wc -l | tr -d ' ')
if [[ "$DISTINCT_ACCOUNTS" -eq 1 ]] && [[ "$(jq -r '.[0].account_id' <(jq -s '.' "$UPSTREAM_LOG"))" == "acc-A-id" ]]; then
    echo "  ✓ same elected account stayed selected"
else
    echo "  ✗ account changed unexpectedly" >&2
    jq -r .account_id "$UPSTREAM_LOG" >&2
    exit 1
fi

GOT_200=$(jq -r '.turns | map(select(.status == 200)) | length' "$STUB_REPORT")
if [[ "$GOT_200" -eq 2 ]]; then
    echo "  ✓ stub-codex saw two 200 turns"
else
    echo "  ✗ stub-codex saw $GOT_200 200 turns (expected 2)" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

echo
echo "smoke-codex-child-refresh: all 12 assertions passed."
echo "  full ndjson: $NDJSON"
echo "  stub upstream log: $UPSTREAM_LOG"
