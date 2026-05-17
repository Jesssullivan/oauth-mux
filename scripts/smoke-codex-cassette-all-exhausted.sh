#!/usr/bin/env bash
# Managed Codex smoke backed by the cassette replay server.
#
# This bridges the standalone cassette replayer and the managed Codex proxy:
# a scrubbed cassette sequence replays 200, quota 429, fallback 200, fallback
# quota 429. The proxy must then return the typed no-account-selectable 503 to
# the same managed child without restarting it.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-cassette-all-exhausted: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-cassette-all-exhausted: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-cassette-managed.XXXXXX)"
CASSETTE="$TMP/cassette"
STATE_DIR="$TMP/state"
PORTFILE="$TMP/cassette.port"
UPLOG="$TMP/cassette.log"
NDJSON="$TMP/adapter.ndjson"
ADAPTER_STDERR="$TMP/adapter.stderr"
STUB_REPORT="$TMP/stub-codex.report"
SERVER_ERR="$TMP/cassette.stderr"

cleanup() {
    if [[ -n "${UPSTREAM_PID:-}" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$CASSETTE" "$TMP/account-A" "$TMP/account-B" "$STATE_DIR"

python3 - "$CASSETTE" <<'PY'
import json
import pathlib
import sys

d = pathlib.Path(sys.argv[1])

ok_body = (
    'event: response.created\n'
    'data: {"type":"response.created","response":{"id":"resp-cassette"}}\n\n'
    'event: response.completed\n'
    'data: {"type":"response.completed","response":{"id":"resp-cassette","output":[]}}\n\n'
)

quota_body = {
    "error": {
        "type": "usage_limit_reached",
        "plan_type": "pro",
        "resets_at": 1788003600,
    }
}

flows = [
    (1788000000.001, 200, "OK", [["Content-Type", "text/event-stream"]], ok_body),
    (1788000000.002, 429, "Too Many Requests", [["Content-Type", "application/json"], ["x-codex-active-limit", "weekly"]], quota_body),
    (1788000000.003, 200, "OK", [["Content-Type", "text/event-stream"]], ok_body),
    (1788000000.004, 429, "Too Many Requests", [["Content-Type", "application/json"], ["x-codex-active-limit", "weekly"]], quota_body),
]

for i, (captured_at, status, reason, headers, body) in enumerate(flows, 1):
    flow = {
        "captured_at": captured_at,
        "host": "chatgpt.com",
        "scheme": "https",
        "method": "POST",
        "path": "/backend-api/codex/responses",
        "request": {
            "headers": [
                ["Authorization", "Bearer synth-<redacted>"],
                ["ChatGPT-Account-ID", "acct-<redacted>"],
            ],
            "body": {"input": "synthetic"},
        },
        "response": {
            "status": status,
            "reason": reason,
            "headers": headers,
            "body": body,
        },
        "timing_ms": 8,
    }
    (d / f"{i:05d}-POST-backend-api-codex-responses.json").write_text(
        json.dumps(flow, indent=2) + "\n",
        encoding="utf-8",
    )
PY

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cassette-A","refresh_token":"RT-A","account_id":"acc-cassette-A"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cassette-B","refresh_token":"RT-B","account_id":"acc-cassette-B"},"auth_mode":"Chatgpt"}
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

OMUX_CASSETTE_DIR="$CASSETTE" \
  OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$PORTFILE" \
  OMUX_STUB_LOGFILE="$UPLOG" \
  python3 "$ROOT/scripts/test-cassette-upstream.py" 2>"$SERVER_ERR" &
UPSTREAM_PID=$!

for _ in {1..80}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
[[ -s "$PORTFILE" ]] || {
    echo "cassette upstream did not bind" >&2
    cat "$SERVER_ERR" >&2 || true
    exit 1
}
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-cassette-all-exhausted: cassette upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT"

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
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

echo "smoke-codex-cassette-all-exhausted: assertions"

assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ok $label"
    else
        echo "  FAIL $label" >&2
        echo "    pattern: $pattern" >&2
        cat "$file" >&2
        return 1
    fi
}

assert_grep "account A saw replayed 200" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "account A saw replayed quota 429" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":429.*"classification":"quota_exhausted".*"body_class":"usage_limit_reached".*"delivered_to_codex":false' "$NDJSON"
assert_grep "same-turn retry fired" '"kind":"proxy_same_turn_retry".*"from":"codex:max-1".*"to":"codex:max-2".*"reason":"quota_exhausted"' "$NDJSON"
assert_grep "fallback account saw replayed 200" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "fallback account saw replayed quota 429" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":429.*"classification":"quota_exhausted".*"body_class":"usage_limit_reached".*"delivered_to_codex":false' "$NDJSON"
assert_grep "same-turn retry unavailable after both cassette quota turns" '"kind":"proxy_same_turn_retry_unavailable"' "$NDJSON"
assert_grep "terminal no-account event fired" '"kind":"quota_handoff_failed_no_account_selectable".*"reason":"quota_exhausted"' "$NDJSON"
assert_grep "session ended as broker-owned" '"kind":"session_ended".*"final_claim_level":"broker_owned"' "$NDJSON"

python3 - "$UPLOG" <<'PY'
import json
import pathlib
import sys
import time

logfile = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 2
while True:
    records = [json.loads(line) for line in logfile.read_text().splitlines() if line.strip()]
    if len(records) >= 4 or time.monotonic() >= deadline:
        break
    time.sleep(0.02)

matches = [r for r in records if r.get("match") is True]
assert [r["status_replayed"] for r in matches] == [200, 429, 200, 429], records
assert [r["cursor"] for r in matches] == [0, 1, 2, 3], records
print("  ok cassette replayed 200,429,200,429 in managed order")
PY

GOT_503=$(jq -r '.turns | map(select(.status == 503)) | length' "$STUB_REPORT")
if [[ "$GOT_503" -ge 1 ]]; then
    echo "  ok stub-codex saw $GOT_503 typed 503 response(s)"
else
    echo "  FAIL stub-codex did not see typed 503" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

GOT_REPAIR_BODY=$(jq -r '[.turns[] | select(.status == 503 and (.body_head | contains("oauth_mux_no_account_selectable")))] | length' "$STUB_REPORT")
if [[ "$GOT_REPAIR_BODY" -ge 1 ]]; then
    echo "  ok no-account 503 carries route-repair body"
else
    echo "  FAIL no-account 503 body was not actionable" >&2
    jq .turns "$STUB_REPORT" >&2
    exit 1
fi

for leak in AT-cassette-A AT-cassette-B RT-A RT-B acc-cassette-A acc-cassette-B "$TMP/account-A/auth.json" "$TMP/account-B/auth.json"; do
    if grep -Fq "$leak" "$NDJSON" "$ADAPTER_STDERR"; then
        echo "  FAIL managed status leaked sensitive value: $leak" >&2
        cat "$NDJSON" >&2
        cat "$ADAPTER_STDERR" >&2
        exit 1
    fi
done
echo "  ok managed status did not leak token material, raw account ids, or auth paths"

PID_STABLE=$(jq -r .pid_stable "$STUB_REPORT")
if [[ "$PID_STABLE" == "true" ]]; then
    echo "  ok stub-codex PID stable through cassette-backed all-exhausted state"
else
    echo "  FAIL stub-codex PID changed across all-exhausted state" >&2
    exit 1
fi

echo
echo "smoke-codex-cassette-all-exhausted: all assertions passed."
echo "  full ndjson: $NDJSON"
