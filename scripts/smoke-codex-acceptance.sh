#!/usr/bin/env bash
# Synthetic in-session smoke for `oauth-mux codex run` covering the
# adapter/proxy swap structure WITHOUT any real Codex traffic.
#
# Anchor: docs/spec/codex-acceptance-procedure-2026-05-03.md.
#
# Stands up:
#   - scripts/test-stub-upstream.py  : emulates chatgpt.com, returns
#                                      200 then 429 per ChatGPT-Account-ID
#   - scripts/test-stub-codex.py     : emulates the codex CLI; reads
#                                      CODEX_HOME/config.toml, sends N
#                                      POSTs through the proxy, records
#                                      its own PID for stability check
#
# Drives: oauth-mux codex run --profile codex-max --json-status-file with:
#   OMUX_UPSTREAM_HOST=127.0.0.1:<stub-port>
#   OMUX_UPSTREAM_SCHEME=http
#   OMUX_CODEX_BIN=path/to/test-stub-codex.py
#
# Asserts the full NDJSON sequence in the status file:
#   session_started        (account A elected)
#   proxy_turn 200 ok      (account A, multiple times)
#   proxy_turn 429 quota_exhausted (account A, not delivered to Codex)
#   proxy_same_turn_retry  (A -> B, dropped x-codex-turn-state)
#   proxy_turn 200 ok      (account B, claim_level broker_owned)
#   session_ended          (final_claim_level broker_owned, synthetic_swap_observed true,
#                           exit_code 0)
#
# Plus: stub-codex.report.pid_stable == true, proving this smoke did
# not rely on child restart/relaunch behavior.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-acceptance: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-codex-acceptance: jq required" >&2
    exit 64
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-acceptance: python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-acceptance.XXXXXX)"
STATE_DIR="$TMP/state"
PORTFILE="$TMP/upstream.port"
UPLOG="$TMP/upstream.log"
NDJSON="$TMP/adapter.ndjson"
ADAPTER_STDERR="$TMP/adapter.stderr"
STUB_PIDFILE="$TMP/stub-codex.pid"
STUB_REPORT="$TMP/stub-codex.report"
CANONICAL_SESSION_HOME="$TMP/canonical-codex"

cleanup() {
    if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

# 1. Synthetic accounts. id_token JWT payload encodes plan_type=pro
# and chatgpt_account_is_fedramp=true so credential/materialize
# exercises the JWT decode path on each account.
mkdir -p "$TMP/account-A" "$TMP/account-B" "$STATE_DIR"
mkdir -p "$CANONICAL_SESSION_HOME/sessions/2026/05/05" "$CANONICAL_SESSION_HOME/shell_snapshots"
ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"

cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-acceptance-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-acceptance-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
EOF
printf '%s\n' 'preexisting = "account-A"' >"$TMP/account-A/config.toml"
printf '%s\n' 'preexisting = "account-B"' >"$TMP/account-B/config.toml"
printf '%s\n' '{"fixture":"canonical-session"}' >"$CANONICAL_SESSION_HOME/sessions/2026/05/05/session.jsonl"
touch "$CANONICAL_SESSION_HOME/history.jsonl" "$CANONICAL_SESSION_HOME/session_index.jsonl"

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

# 2. Start stub upstream
OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$PORTFILE" \
  OMUX_STUB_OK_BEFORE_429=2 \
  OMUX_STUB_LOGFILE="$UPLOG" \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for i in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
if [[ ! -s "$PORTFILE" ]]; then
    echo "smoke-codex-acceptance: stub upstream did not write port" >&2
    cat "$TMP/upstream.stderr" >&2
    exit 1
fi
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-acceptance: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT"

# 3. Run oauth-mux codex run
echo "smoke-codex-acceptance: running adapter..."
OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CODEX_TURNS=3 \
  OMUX_STUB_CODEX_PIDFILE="$STUB_PIDFILE" \
  OMUX_STUB_CODEX_REPORT="$STUB_REPORT" \
  "$BIN" codex run --profile codex-max --json-status-file "$NDJSON" 2>"$ADAPTER_STDERR" || {
    echo "smoke-codex-acceptance: adapter exited nonzero" >&2
    echo "---NDJSON---" >&2
    cat "$NDJSON" >&2
    echo "---stderr---" >&2
    cat "$ADAPTER_STDERR" >&2
    echo "---upstream log---" >&2
    cat "$UPLOG" >&2 || true
    exit 1
}

# 4. Assertions
assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ✓ $label"
    else
        echo "  ✗ $label" >&2
        echo "    pattern: $pattern" >&2
        echo "    file: $file" >&2
        return 1
    fi
}

echo "smoke-codex-acceptance: assertions"

assert_grep "session_started"           '"kind":"session_started"'           "$NDJSON"
assert_grep "session_started has proxy_port" '"proxy_port":[0-9]+'           "$NDJSON"
assert_grep "session_started has managed_frame_id" '"managed_frame_id":"omux-codex-' "$NDJSON"
assert_grep "session_started has adapter version" '"adapter_version":"[0-9]+\.[0-9]+\.[0-9]+"' "$NDJSON"
assert_grep "session_started redacts CODEX_HOME path" '"codex_home_path_printed":false' "$NDJSON"
assert_grep "session_started records status file" '"status_file_present":true' "$NDJSON"
assert_grep "session_started reports canonical session bridge" '"session_authority":"canonical_bridge"' "$NDJSON"
assert_grep "session_started redacts session paths" '"session_paths_printed":false' "$NDJSON"
assert_grep "session_started records runtime identity" '"runtime_identity":\{' "$NDJSON"
assert_grep "runtime identity marks repo-local binary" '"binary_source":"repo_local"' "$NDJSON"
assert_grep "runtime identity records binary sha" '"binary_sha256":"[0-9a-f]{64}"' "$NDJSON"
assert_grep "runtime identity marks path printed" '"path_printed":true' "$NDJSON"
assert_grep "runtime identity records installed/local mismatch bit" '"installed_local_mismatch_detected":false' "$NDJSON"
assert_grep "proxy_turn 200 ok"         '"kind":"proxy_turn".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "proxy_turn 429 quota_exhausted" '"kind":"proxy_turn".*"status":429.*"classification":"quota_exhausted"' "$NDJSON"
assert_grep "quota 429 was not delivered to Codex" '"kind":"proxy_turn".*"status":429.*"delivered_to_codex":false' "$NDJSON"
assert_grep "proxy_same_turn_retry fired" '"kind":"proxy_same_turn_retry"' "$NDJSON"
assert_grep "same-turn retry dropped x-codex-turn-state" '"dropped":"x-codex-turn-state"' "$NDJSON"
assert_grep "claim_level remains broker_owned" '"claim_level":"broker_owned"' "$NDJSON"
assert_grep "session_ended final_claim_level broker_owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"
assert_grep "session_ended records synthetic swap" '"kind":"session_ended".*"synthetic_swap_observed":true' "$NDJSON"

if grep -q '"kind":"session_started"' "$ADAPTER_STDERR"; then
    echo "  ✗ adapter status frames leaked to stderr despite --json-status-file" >&2
    exit 1
else
    echo "  ✓ --json-status-file keeps adapter status frames out of stderr"
fi

ACCOUNT_HITS=$(grep -oE '"account":"codex:max-[12]"' "$NDJSON" | sort -u | wc -l | tr -d ' ')
if [[ "$ACCOUNT_HITS" -ge 2 ]]; then
    echo "  ✓ both accounts max-1 and max-2 elected"
else
    echo "  ✗ expected both accounts elected; saw distinct=$ACCOUNT_HITS" >&2
    exit 1
fi

if [[ ! -s "$STUB_REPORT" ]]; then
    echo "  ✗ stub-codex report missing" >&2
    exit 1
fi
if [[ "$(jq -r .managed_frame_id_present "$STUB_REPORT")" == "true" \
      && "$(jq -r .claim_level "$STUB_REPORT")" == "broker_owned" \
      && "$(jq -r .status_file_present "$STUB_REPORT")" == "true" ]]; then
    echo "  ✓ child received managed-frame env markers"
else
    echo "  ✗ child managed-frame env marker report failed" >&2
    cat "$STUB_REPORT" >&2
    exit 1
fi
if [[ "$(jq -r .session_bridge.checked "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.sessions_samefile "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.history_samefile "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.session_index_samefile "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.shell_snapshots_samefile "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.canonical_marker_exists "$STUB_REPORT")" == "true" \
      && "$(jq -r .session_bridge.paths_printed "$STUB_REPORT")" == "false" ]]; then
    echo "  ✓ session authority is bridged by reference without path output"
else
    echo "  ✗ session authority bridge report failed" >&2
    cat "$STUB_REPORT" >&2
    exit 1
fi
PID_STABLE=$(jq -r .pid_stable "$STUB_REPORT")
START_PID=$(jq -r .start_pid "$STUB_REPORT")
END_PID=$(jq -r .end_pid "$STUB_REPORT")
if [[ "$PID_STABLE" == "true" ]]; then
    echo "  ✓ stub-codex PID stable across swap (start=$START_PID end=$END_PID)"
else
    echo "  ✗ stub-codex PID changed: start=$START_PID end=$END_PID" >&2
    exit 1
fi

if jq -e 'all(.turns[]; .status == 200)' "$STUB_REPORT" >/dev/null; then
    echo "  ✓ stub-codex saw only 200 turns; quota 429 stayed inside proxy"
else
    echo "  ✗ stub-codex saw a non-200 turn" >&2
    cat "$STUB_REPORT" >&2
    exit 1
fi

UPSTREAM_ACCT_COUNT=$(jq -r .account_id "$UPLOG" 2>/dev/null | sort -u | wc -l | tr -d ' ' || echo 0)
if [[ "$UPSTREAM_ACCT_COUNT" -ge 2 ]]; then
    echo "  ✓ stub upstream saw 2+ distinct ChatGPT-Account-IDs (proxy substituted both)"
else
    echo "  ✗ upstream saw only $UPSTREAM_ACCT_COUNT distinct account-ids" >&2
    cat "$UPLOG" >&2
    exit 1
fi

if [[ "$(cat "$TMP/account-A/config.toml")" == 'preexisting = "account-A"' && "$(cat "$TMP/account-B/config.toml")" == 'preexisting = "account-B"' ]]; then
    echo "  ✓ account-local config.toml files were not clobbered"
else
    echo "  ✗ account-local config.toml was clobbered" >&2
    exit 1
fi

echo
echo "smoke-codex-acceptance: all 23 assertions passed."
echo "  full ndjson: $NDJSON"
echo "  stub upstream log: $UPLOG"
echo "  stub codex report: $STUB_REPORT"
