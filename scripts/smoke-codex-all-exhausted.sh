#!/usr/bin/env bash
# Edge-case smoke: when every account in the profile is quota-exhausted,
# the proxy must return a clean no-account-selectable response without
# restart, loop, or crash.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-all-exhausted: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-all-exhausted: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-allexh.XXXXXX)"
PORTFILE="$TMP/upstream.port"
UPLOG="$TMP/upstream.log"
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
ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-allexh-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-allexh-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
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
  OMUX_STUB_OK_BEFORE_429=1 \
  OMUX_STUB_LOGFILE="$UPLOG" \
  OMUX_STUB_429_TYPE=usage_limit_reached \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for _ in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
[[ -s "$PORTFILE" ]] || { echo "stub upstream did not bind" >&2; exit 1; }
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-all-exhausted: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT ok_before_429=1"

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_STUB_CODEX_TURNS=5 \
  OMUX_STUB_CODEX_REPORT="$STUB_REPORT" \
  "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$NDJSON" 2>"$ADAPTER_STDERR" || {
    echo "adapter exited nonzero" >&2
    cat "$NDJSON" >&2 || true
    cat "$ADAPTER_STDERR" >&2 || true
    exit 1
}

echo "smoke-codex-all-exhausted: assertions"

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

assert_grep "account A had at least one 200 ok" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "account B had at least one 200 ok" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "account A returned 429 quota_exhausted" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":429.*"classification":"quota_exhausted"' "$NDJSON"
assert_grep "account B returned 429 quota_exhausted" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":429.*"classification":"quota_exhausted"' "$NDJSON"
assert_grep "proxy_same_turn_retry fired" '"kind":"proxy_same_turn_retry"' "$NDJSON"
assert_grep "fallback quota 429 was not delivered before no-account failure" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":429.*"delivered_to_codex":false' "$NDJSON"
assert_grep "same-turn retry unavailable after all accounts exhausted" '"kind":"proxy_same_turn_retry_unavailable"' "$NDJSON"
assert_grep "proxy_no_account_selectable event fired" '"kind":"proxy_no_account_selectable"' "$NDJSON"

if grep -q '"kind":"session_started"' "$ADAPTER_STDERR"; then
    echo "  ✗ adapter status frames leaked to stderr despite --json-status-file" >&2
    exit 1
else
    echo "  ✓ --json-status-file keeps adapter status frames out of stderr"
fi

GOT_503=$(jq -r '.turns | map(select(.status == 503)) | length' "$STUB_REPORT")
if [[ "$GOT_503" -ge 1 ]]; then
    echo "  ✓ stub-codex saw $GOT_503 503 response(s) on all-exhausted turn(s)"
else
    echo "  ✗ stub-codex did not see any 503" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

PID_STABLE=$(jq -r .pid_stable "$STUB_REPORT")
if [[ "$PID_STABLE" == "true" ]]; then
    echo "  ✓ stub-codex PID stable through all-exhausted state"
else
    echo "  ✗ stub-codex PID changed across all-exhausted" >&2
    exit 1
fi

assert_grep "session_ended final_claim_level broker_owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"

echo
echo "smoke-codex-all-exhausted: all 12 assertions passed."
echo "  full ndjson: $NDJSON"
