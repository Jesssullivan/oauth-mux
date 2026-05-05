#!/usr/bin/env bash
# Concurrent-session smoke for `oauth-mux codex run`.
#
# This is the current-main version of the old quarry smoke. The old
# boundary was "at least one session gets proxy traffic" because shared
# account-local CODEX_HOME/config.toml mutation could make one child point
# at the other session's proxy. Main now uses a per-session CODEX_HOME
# overlay, so the expected behavior is stronger:
#
#   - two concurrent adapter sessions exit cleanly
#   - each session gets a distinct proxy port
#   - each stub-codex child reads its own proxy port from its overlay
#   - each session independently produces proxy_turn frames
#   - account-local config.toml files are not clobbered
#
# No provider traffic is made. The upstream and codex processes are local
# stubs, and status frames are written to --json-status-file to avoid
# corrupting real harness stderr/stdout.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-concurrent-sessions: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-codex-concurrent-sessions: jq required" >&2
    exit 64
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-concurrent-sessions: python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-concurrent.XXXXXX)"
PORTFILE="$TMP/upstream.port"
UPLOG="$TMP/upstream.log"
NDJSON_A="$TMP/adapter-A.ndjson"
NDJSON_B="$TMP/adapter-B.ndjson"
STDOUT_A="$TMP/adapter-A.stdout"
STDOUT_B="$TMP/adapter-B.stdout"
STDERR_A="$TMP/adapter-A.stderr"
STDERR_B="$TMP/adapter-B.stderr"
PIDFILE_A="$TMP/stub-codex-A.pid"
PIDFILE_B="$TMP/stub-codex-B.pid"
REPORT_A="$TMP/stub-codex-A.report"
REPORT_B="$TMP/stub-codex-B.report"

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
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-concurrent-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-concurrent-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
EOF
printf '%s\n' 'preexisting = "account-A"' >"$TMP/account-A/config.toml"
printf '%s\n' 'preexisting = "account-B"' >"$TMP/account-B/config.toml"

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
  OMUX_STUB_OK_BEFORE_429=100 \
  OMUX_STUB_LOGFILE="$UPLOG" \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for _ in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
if [[ ! -s "$PORTFILE" ]]; then
    echo "smoke-codex-concurrent-sessions: stub upstream did not write port" >&2
    cat "$TMP/upstream.stderr" >&2
    exit 1
fi
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-concurrent-sessions: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT"
echo "smoke-codex-concurrent-sessions: launching two concurrent sessions..."

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_STUB_CODEX_TURNS=6 \
  OMUX_STUB_CODEX_PIDFILE="$PIDFILE_A" \
  OMUX_STUB_CODEX_REPORT="$REPORT_A" \
  "$BIN" codex run --profile codex-max --json-status-file "$NDJSON_A" >"$STDOUT_A" 2>"$STDERR_A" &
PID_A=$!

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_UPSTREAM_HOST="127.0.0.1:$UPSTREAM_PORT" \
  OMUX_UPSTREAM_SCHEME="http" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_STUB_CODEX_TURNS=6 \
  OMUX_STUB_CODEX_PIDFILE="$PIDFILE_B" \
  OMUX_STUB_CODEX_REPORT="$REPORT_B" \
  "$BIN" codex run --profile codex-max --json-status-file "$NDJSON_B" >"$STDOUT_B" 2>"$STDERR_B" &
PID_B=$!

if wait "$PID_A"; then EXIT_A=0; else EXIT_A=$?; fi
if wait "$PID_B"; then EXIT_B=0; else EXIT_B=$?; fi

echo "smoke-codex-concurrent-sessions: assertions"

fail_dump() {
    echo "--- adapter A ndjson ---" >&2
    cat "$NDJSON_A" >&2 || true
    echo "--- adapter A stderr ---" >&2
    cat "$STDERR_A" >&2 || true
    echo "--- adapter B ndjson ---" >&2
    cat "$NDJSON_B" >&2 || true
    echo "--- adapter B stderr ---" >&2
    cat "$STDERR_B" >&2 || true
    echo "--- upstream log ---" >&2
    cat "$UPLOG" >&2 || true
}

assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ✓ $label"
    else
        echo "  ✗ $label" >&2
        echo "    pattern: $pattern" >&2
        echo "    file: $file" >&2
        fail_dump
        return 1
    fi
}

if [[ "$EXIT_A" -eq 0 && "$EXIT_B" -eq 0 ]]; then
    echo "  ✓ both adapter sessions exited 0"
else
    echo "  ✗ exit codes A=$EXIT_A B=$EXIT_B" >&2
    fail_dump
    exit 1
fi

assert_grep "session A session_started" '"kind":"session_started"' "$NDJSON_A"
assert_grep "session B session_started" '"kind":"session_started"' "$NDJSON_B"
assert_grep "session A session_ended" '"kind":"session_ended".*"exit_code":0' "$NDJSON_A"
assert_grep "session B session_ended" '"kind":"session_ended".*"exit_code":0' "$NDJSON_B"
assert_grep "session A redacts CODEX_HOME path" '"codex_home_path_printed":false' "$NDJSON_A"
assert_grep "session B redacts CODEX_HOME path" '"codex_home_path_printed":false' "$NDJSON_B"

PORT_A="$(jq -r 'select(.kind=="session_started") | .proxy_port' "$NDJSON_A" | head -n 1)"
PORT_B="$(jq -r 'select(.kind=="session_started") | .proxy_port' "$NDJSON_B" | head -n 1)"
if [[ -n "$PORT_A" && -n "$PORT_B" && "$PORT_A" != "$PORT_B" ]]; then
    echo "  ✓ sessions used distinct proxy ports (A=$PORT_A, B=$PORT_B)"
else
    echo "  ✗ expected distinct proxy ports; A=$PORT_A B=$PORT_B" >&2
    fail_dump
    exit 1
fi

CHILD_PORT_A="$(sed -nE 's/.*proxy=http:\/\/127\.0\.0\.1:([0-9]+)\/.*/\1/p' "$STDERR_A" | head -n 1)"
CHILD_PORT_B="$(sed -nE 's/.*proxy=http:\/\/127\.0\.0\.1:([0-9]+)\/.*/\1/p' "$STDERR_B" | head -n 1)"
if [[ "$CHILD_PORT_A" == "$PORT_A" && "$CHILD_PORT_B" == "$PORT_B" ]]; then
    echo "  ✓ each stub-codex child read its own session proxy port"
else
    echo "  ✗ child proxy ports did not match session ports; child A=$CHILD_PORT_A session A=$PORT_A child B=$CHILD_PORT_B session B=$PORT_B" >&2
    fail_dump
    exit 1
fi

A_TURNS=$(grep -c '"kind":"proxy_turn"' "$NDJSON_A" || true)
B_TURNS=$(grep -c '"kind":"proxy_turn"' "$NDJSON_B" || true)
if [[ "$A_TURNS" -eq 6 && "$B_TURNS" -eq 6 ]]; then
    echo "  ✓ both sessions independently produced expected proxy_turn frames (A=$A_TURNS, B=$B_TURNS)"
else
    echo "  ✗ expected 6 proxy_turn frames per session; A=$A_TURNS B=$B_TURNS" >&2
    fail_dump
    exit 1
fi

assert_grep "session A proxy_turns are 200 ok" '"kind":"proxy_turn".*"status":200.*"classification":"ok"' "$NDJSON_A"
assert_grep "session B proxy_turns are 200 ok" '"kind":"proxy_turn".*"status":200.*"classification":"ok"' "$NDJSON_B"

if grep -q '"kind":"session_started"' "$STDERR_A" || grep -q '"kind":"session_started"' "$STDERR_B"; then
    echo "  ✗ adapter status frames leaked to stderr despite --json-status-file" >&2
    fail_dump
    exit 1
else
    echo "  ✓ --json-status-file keeps adapter status frames out of stderr"
fi

if [[ ! -s "$REPORT_A" || ! -s "$REPORT_B" ]]; then
    echo "  ✗ stub-codex report missing" >&2
    fail_dump
    exit 1
fi

PID_STABLE_A=$(jq -r .pid_stable "$REPORT_A")
PID_STABLE_B=$(jq -r .pid_stable "$REPORT_B")
START_A=$(jq -r .start_pid "$REPORT_A")
START_B=$(jq -r .start_pid "$REPORT_B")
if [[ "$PID_STABLE_A" == "true" && "$PID_STABLE_B" == "true" && "$START_A" != "$START_B" ]]; then
    echo "  ✓ both child PIDs are stable and distinct (A=$START_A, B=$START_B)"
else
    echo "  ✗ PID check failed: stable A=$PID_STABLE_A stable B=$PID_STABLE_B start A=$START_A start B=$START_B" >&2
    fail_dump
    exit 1
fi

UPSTREAM_TURNS=$(jq -r 'select(.method=="POST") | .path' "$UPLOG" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$UPSTREAM_TURNS" -eq 12 ]]; then
    echo "  ✓ stub upstream received all 12 proxied turns"
else
    echo "  ✗ expected 12 upstream turns, saw $UPSTREAM_TURNS" >&2
    fail_dump
    exit 1
fi

if [[ "$(cat "$TMP/account-A/config.toml")" == 'preexisting = "account-A"' && "$(cat "$TMP/account-B/config.toml")" == 'preexisting = "account-B"' ]]; then
    echo "  ✓ account-local config.toml files were not clobbered"
else
    echo "  ✗ account-local config.toml was clobbered" >&2
    fail_dump
    exit 1
fi

echo
echo "smoke-codex-concurrent-sessions: all 16 assertions passed."
echo "  full ndjson A: $NDJSON_A"
echo "  full ndjson B: $NDJSON_B"
echo "  stub upstream log: $UPLOG"
