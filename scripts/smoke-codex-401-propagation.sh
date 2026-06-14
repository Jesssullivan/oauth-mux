#!/usr/bin/env bash
# 401 auth fallback smoke: the selected account returns 401 while a fallback
# account is healthy. The proxy must classify the selected account as auth
# unhealthy, retry the same request against the fallback before Codex sees the
# 401, and persist account-credential health without claiming quota.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-401-propagation: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build-local" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-401-propagation: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-401.XXXXXX)"
PORTFILE="$TMP/upstream.port"
NDJSON="$TMP/adapter.ndjson"
ADAPTER_STDERR="$TMP/adapter.stderr"
STUB_REPORT="$TMP/stub-codex.report"
STUB_BIN_DIR="$TMP/bin"

cleanup() {
    if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$TMP/account-B" "$STUB_BIN_DIR"
mkdir -p "$TMP/state"
ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$ID_TOKEN","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$ID_TOKEN","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
EOF

cat >"$TMP/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "config_dir": "$TMP/account-A", "secret": { "backend": "file", "path": "$TMP/account-A/auth.json" } },
        "max-2": { "priority": 20, "config_dir": "$TMP/account-B", "secret": { "backend": "file", "path": "$TMP/account-B/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
  }
}
EOF

cat >"$TMP/state/health.json" <<'EOF'
{
  "version": 2,
  "accounts": [
    {
      "key": "codex:max-1#codex-max",
      "last_probe_source": "capability_probe",
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this",
      "liveness": {
        "state": "live",
        "availability": "available"
      }
    },
    {
      "key": "codex:max-1",
      "last_probe_source": "capability_probe",
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this",
      "liveness": {
        "state": "live",
        "availability": "available"
      }
    },
    {
      "key": "codex:max-2#codex-max",
      "last_probe_source": "capability_probe",
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this",
      "liveness": {
        "state": "live",
        "availability": "available"
      }
    }
  ]
}
EOF

cat >"$STUB_BIN_DIR/codex" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod +x "$STUB_BIN_DIR/codex"

OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$PORTFILE" \
  OMUX_STUB_OK_BEFORE_429=99 \
  OMUX_STUB_ACCOUNT_STATUS_JSON='{"acc-A-id":401}' \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for _ in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
[[ -s "$PORTFILE" ]] || { echo "stub upstream did not bind" >&2; exit 1; }
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-401-propagation: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT max-1=401 max-2=200"

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$TMP/state" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_STUB_CODEX_TURNS=4 \
  OMUX_STUB_CODEX_REPORT="$STUB_REPORT" \
  "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$NDJSON" 2>"$ADAPTER_STDERR" || {
    echo "adapter exited nonzero" >&2
    cat "$NDJSON" >&2 || true
    cat "$ADAPTER_STDERR" >&2 || true
    exit 1
}

echo "smoke-codex-401-propagation: assertions"

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
assert_grep "session_started redacts CODEX_HOME path" '"codex_home_path_printed":false' "$NDJSON"
assert_grep "proxy_turn 401 classified auth_unauthorized" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":401.*"classification":"auth_unauthorized".*"delivered_to_codex":false' "$NDJSON"
assert_grep "proxy_auth_same_turn_retry fired" '"kind":"proxy_auth_same_turn_retry".*"from":"codex:max-1".*"to":"codex:max-2".*"reason":"auth_unauthorized"' "$NDJSON"
assert_grep "fallback account returned 200" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "unrecovered 401 recorded as auth health, not quota" '"kind":"auth_health_observed".*"recorded":true.*"reason":"unrecovered_401_no_writeback".*"quota_claim":false' "$NDJSON"

assert_no_grep "401 was not handed to Codex" '"kind":"proxy_observed_401_codex_handles"' "$NDJSON"
assert_no_grep "quota retry did not fire" '"kind":"proxy_same_turn_retry"' "$NDJSON"
assert_no_grep "no quota_exhausted misclassification" '"classification":"quota_exhausted"' "$NDJSON"
assert_no_grep "claim_level not promoted" '"claim_level":"next_turn_seamless"' "$NDJSON"
assert_grep "session_ended final_claim_level remains broker_owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"

if grep -q '"kind":"session_started"' "$ADAPTER_STDERR"; then
    echo "  ✗ adapter status frames leaked to stderr despite --json-status-file" >&2
    exit 1
else
    echo "  ✓ --json-status-file keeps adapter status frames out of stderr"
fi

DISTINCT_ACCT=$(grep -oE '"account":"codex:max-[12]"' "$NDJSON" | sort -u | wc -l | tr -d ' ')
if [[ "$DISTINCT_ACCT" -eq 2 ]]; then
    echo "  ✓ auth fallback used both accounts"
else
    echo "  ✗ expected auth fallback across two accounts; saw distinct=$DISTINCT_ACCT" >&2
    grep -oE '"account":"codex:max-[12]"' "$NDJSON" | sort -u >&2
    exit 1
fi

GOT_200=$(jq -r '.turns | map(select(.status == 200)) | length' "$STUB_REPORT")
if [[ "$GOT_200" -eq 4 ]]; then
    echo "  ✓ stub-codex saw all 4 turns return 200"
else
    echo "  ✗ stub-codex saw $GOT_200 200s (expected 4)" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

PID_STABLE=$(jq -r .pid_stable "$STUB_REPORT")
if [[ "$PID_STABLE" == "true" ]]; then
    echo "  ✓ stub-codex PID stable through auth fallback"
else
    echo "  ✗ PID changed across 401s" >&2
    exit 1
fi

PLAN_AFTER="$(PATH="$STUB_BIN_DIR:$PATH" OMUX_CONFIG="$TMP/oauth-mux.config.json" OMUX_STATE_DIR="$TMP/state" "$BIN" codex broker-session-plan --profile codex-max --capability codex-max --json)"
SELECTED_AFTER="$(jq -r '.selected.account' <<<"$PLAN_AFTER")"
if [[ "$SELECTED_AFTER" == "max-2" ]]; then
    echo "  ✓ next broker-session-plan avoids unrecovered max-1 auth"
else
    echo "  ✗ broker-session-plan selected $SELECTED_AFTER after unrecovered max-1 auth" >&2
    jq . <<<"$PLAN_AFTER" >&2
    exit 1
fi

MAX1_SKIP="$(jq -r '.routes[] | select(.account == "max-1") | .skip_reason' <<<"$PLAN_AFTER")"
if [[ "$MAX1_SKIP" == "token_revoked" ]]; then
    echo "  ✓ max-1 marked as reauth/try-next credential health"
else
    echo "  ✗ max-1 skip_reason after unrecovered auth was $MAX1_SKIP" >&2
    jq .routes <<<"$PLAN_AFTER" >&2
    exit 1
fi

echo
echo "smoke-codex-401-propagation: all assertions passed."
echo "  full ndjson: $NDJSON"
