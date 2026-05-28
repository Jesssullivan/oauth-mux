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
STATE_DIR="$TMP/state"
PORTFILE="$TMP/upstream.port"
UPLOG="$TMP/upstream.log"
NDJSON="$TMP/adapter.ndjson"
ADAPTER_STDERR="$TMP/adapter.stderr"
STUB_REPORT="$TMP/stub-codex.report"
TRACE_FILE="$TMP/trace.ndjson"

cleanup() {
    if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$TMP/account-B" "$STATE_DIR"
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

cat >"$STATE_DIR/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}},
  {"key":"codex:max-2#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
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
  OMUX_STATE_DIR="$STATE_DIR" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_TRACE=1 \
  OMUX_TRACE_FILE="$TRACE_FILE" \
  OMUX_TRACE_ID="cccccccccccccccccccccccccccccccc" \
  OMUX_SPAN_ID="dddddddddddddddd" \
  OMUX_STUB_CODEX_TURNS=5 \
  OMUX_STUB_CODEX_DISCONNECT_TURNS=2 \
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
assert_grep "no-account response disconnect classified as client disconnect" '"kind":"proxy_client_disconnected".*"status":503.*"err":"(BrokenPipe|ConnectionResetByPeer|EndOfStream|ConnectionTimedOut)".*"retry_attempted":true' "$NDJSON"
if grep -q -E 'proxy: serveOne: (BrokenPipe|ConnectionResetByPeer|EndOfStream|ConnectionTimedOut)' "$ADAPTER_STDERR"; then
    echo "  ✗ no-account disconnect leaked benign proxy close" >&2
    cat "$ADAPTER_STDERR" >&2
    exit 1
else
    echo "  ✓ no-account disconnect did not leak benign proxy close"
fi

jq -e 'select(.name == "codex.managed.overlay" and .attributes.auth_authority == "mux_owned_overlay" and .attributes.config_paths_printed == false)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured managed overlay without config paths"
jq -e 'select(.name == "codex.managed.session_start" and .attributes.claim_level == "broker_owned" and .attributes.codex_home_path_printed == false)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured managed session start without CODEX_HOME path"
jq -e 'select(.name == "codex.proxy.turn" and .attributes.classification == "quota_exhausted" and .attributes.delivered_to_codex == false)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured proxy quota turn"
jq -e 'select(.name == "codex.proxy.retry" and .attributes.reason == "quota_exhausted" and .attributes.raw_account_id_printed == false)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured proxy retry boundary"
jq -e 'select(.name == "codex.proxy.no_account_selectable" and .attributes.pending_failure == "quota_exhausted" and .attributes.rejections_total == 2 and .attributes.quota_exhausted == 2)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured no-account rejection summary"
jq -e 'select(.name == "codex.managed.session_end" and .attributes.terminal_event == "session_ended" and .attributes.synthetic_swap_observed == true)' "$TRACE_FILE" >/dev/null
echo "  ✓ trace captured managed session end"

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
GOT_REPAIR_BODY=$(jq -r '[.turns[] | select(.status == 503 and (.body_head | contains("oauth_mux_no_account_selectable")))] | length' "$STUB_REPORT")
if [[ "$GOT_REPAIR_BODY" -ge 1 ]]; then
    echo "  ✓ all-exhausted 503 carries typed route-repair body"
else
    echo "  ✗ all-exhausted 503 body was not actionable" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

for leak in AT-allexh-A AT-allexh-B RT-A RT-B acc-A-id acc-B-id "$TMP/account-A/auth.json" "$TMP/account-B/auth.json"; do
    if grep -Fq "$leak" "$TRACE_FILE"; then
        echo "  ✗ trace leaked sensitive value: $leak" >&2
        cat "$TRACE_FILE" >&2
        exit 1
    fi
done
echo "  ✓ trace did not leak tokens, raw account ids, or auth paths"

PID_STABLE=$(jq -r .pid_stable "$STUB_REPORT")
if [[ "$PID_STABLE" == "true" ]]; then
    echo "  ✓ stub-codex PID stable through all-exhausted state"
else
    echo "  ✗ stub-codex PID changed across all-exhausted" >&2
    exit 1
fi

assert_grep "session_ended final_claim_level broker_owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"

echo
echo "smoke-codex-all-exhausted: all assertions passed."
echo "  full ndjson: $NDJSON"
