#!/usr/bin/env bash
# Diagnostic trace smoke: global tracing emits redacted, OTEL-friendly JSONL for
# route decisions and transient health normalization.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-trace: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-trace: jq required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-trace.XXXXXX)"
STATE_DIR="$TMP/state"
TRACE_FILE="$TMP/trace.ndjson"
PREFLIGHT_JSON="$TMP/preflight.json"
SESSION_ID="019def98-6b1e-79b1-81a4-985e5242da23"
SECRET_REFRESH="RT-trace-should-not-leak"
RAW_ACCOUNT_ID="acc-trace-raw-id-should-not-leak"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$STATE_DIR"

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"
SECRET_TOKEN="$ID_TOKEN"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$SECRET_TOKEN","refresh_token":"$SECRET_REFRESH","account_id":"$RAW_ACCOUNT_ID"},"auth_mode":"Chatgpt"}
EOF

cat >"$TMP/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "config_dir": "$TMP/account-A", "secret": { "backend": "file", "path": "$TMP/account-A/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max"] }
  }
}
EOF

cat >"$STATE_DIR/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"codex:max-1","last_probe_source":"broker_run_live","last_probe_hint_class":"provider_degraded","last_probe_decision":"try_next_provider","liveness":{"state":"degraded","reason":"provider_degraded","since":1,"retry_at":1}},
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
EOF

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  OMUX_TRACE=1 \
  OMUX_TRACE_FILE="$TRACE_FILE" \
  OMUX_TRACE_ID="11111111111111111111111111111111" \
  OMUX_SPAN_ID="2222222222222222" \
  "$BIN" codex preflight --profile codex-max --capability codex-max --json >"$PREFLIGHT_JSON"

jq -e '.mode == "codex_preflight" and .route_summary.routes_total == 1' "$PREFLIGHT_JSON" >/dev/null

if [[ ! -s "$TRACE_FILE" ]]; then
    echo "smoke-trace: trace file missing or empty" >&2
    exit 1
fi

jq -e 'select(.schema == "oauth-mux.trace.v1" and .trace_id == "11111111111111111111111111111111" and .span_id == "2222222222222222")' "$TRACE_FILE" >/dev/null
jq -e 'select(.name == "health.normalize" and .attributes.before_liveness == "degraded:provider_degraded" and .attributes.after_liveness == "available")' "$TRACE_FILE" >/dev/null
jq -e 'select(.name == "route.evaluate" and .attributes.provider == "codex" and .attributes.account_label == "max-1")' "$TRACE_FILE" >/dev/null
jq -e 'select(.redaction.tokens == false and .redaction.raw_account_ids == false and .redaction.session_ids == false and .redaction.paths == false)' "$TRACE_FILE" >/dev/null

assert_not_leaked() {
    local label=$1 needle=$2
    if grep -Fq "$needle" "$TRACE_FILE"; then
        echo "smoke-trace: leaked $label in trace output" >&2
        cat "$TRACE_FILE" >&2
        exit 1
    fi
    echo "  ✓ did not leak $label"
}

assert_not_leaked "access token" "$SECRET_TOKEN"
assert_not_leaked "refresh token" "$SECRET_REFRESH"
assert_not_leaked "raw account id" "$RAW_ACCOUNT_ID"
assert_not_leaked "auth file path" "$TMP/account-A/auth.json"
assert_not_leaked "session id" "$SESSION_ID"

echo "smoke-trace: all assertions passed."
