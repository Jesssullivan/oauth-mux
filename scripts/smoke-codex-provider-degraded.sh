#!/usr/bin/env bash
# Provider-degraded and stream-disconnect smoke: 5xx responses are provider
# failures, not credential failures. The proxy should retry a selectable
# fallback before Codex sees the 5xx, pass through a no-fallback provider 5xx
# without emitting the route-repair no-account body, and treat downstream Codex
# socket closes as local client disconnects rather than provider degradation.
# Upstream interruptions after partial stream delivery should be recorded as
# provider-degraded evidence, but must not trigger same-turn retry.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-provider-degraded: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-provider-degraded: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-provider-degraded.XXXXXX)"
UPSTREAM_PIDS=()

cleanup() {
    for pid in "${UPSTREAM_PIDS[@]}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ "${OMUX_KEEP_SMOKE_TMP:-0}" == "1" ]]; then
        echo "smoke-codex-provider-degraded: kept temp dir $TMP" >&2
        return
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"

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

wait_for_port() {
    local portfile=$1
    for _ in {1..40}; do
        [[ -s "$portfile" ]] && return 0
        sleep 0.05
    done
    echo "stub upstream did not bind" >&2
    return 1
}

write_two_account_fixture() {
    local dir=$1
    mkdir -p "$dir/account-A" "$dir/account-B" "$dir/state"
    cat >"$dir/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$ID_TOKEN","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
    cat >"$dir/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$ID_TOKEN","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
EOF
    cat >"$dir/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "config_dir": "$dir/account-A", "secret": { "backend": "file", "path": "$dir/account-A/auth.json" } },
        "max-2": { "priority": 20, "config_dir": "$dir/account-B", "secret": { "backend": "file", "path": "$dir/account-B/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
  }
}
EOF
    cat >"$dir/state/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}},
  {"key":"codex:max-2#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
EOF
}

write_one_account_fixture() {
    local dir=$1
    mkdir -p "$dir/account-A" "$dir/state"
    cat >"$dir/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"$ID_TOKEN","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
    cat >"$dir/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "config_dir": "$dir/account-A", "secret": { "backend": "file", "path": "$dir/account-A/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max"] }
  }
}
EOF
    cat >"$dir/state/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
EOF
}

run_fallback_case() {
    local case_dir="$TMP/fallback"
    local portfile="$case_dir/upstream.port"
    local uplog="$case_dir/upstream.log"
    local ndjson="$case_dir/adapter.ndjson"
    local adapter_stderr="$case_dir/adapter.stderr"
    local stub_report="$case_dir/stub-codex.report"
    local trace_file="$case_dir/trace.ndjson"
    mkdir -p "$case_dir"
    write_two_account_fixture "$case_dir"
    mkdir -p "$case_dir/bin"
    cat >"$case_dir/bin/codex" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
    chmod +x "$case_dir/bin/codex"

    OMUX_STUB_PORT=0 \
      OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_OK_BEFORE_429=99 \
      OMUX_STUB_LOGFILE="$uplog" \
      OMUX_STUB_ACCOUNT_STATUS_JSON='{"acc-A-id":503}' \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$case_dir/upstream.stderr" &
    local upstream_pid=$!
    UPSTREAM_PIDS+=("$upstream_pid")
    wait_for_port "$portfile"
    local upstream_port
    upstream_port="$(cat "$portfile" | tr -d '[:space:]')"
    echo "smoke-codex-provider-degraded: fallback stub pid=$upstream_pid port=$upstream_port max-1=503 max-2=200"

    OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$upstream_port" \
      OMUX_UPSTREAM_SCHEME="http" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$trace_file" \
      OMUX_STUB_CODEX_TURNS=3 \
      OMUX_STUB_CODEX_REPORT="$stub_report" \
      "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$ndjson" 2>"$adapter_stderr" || {
        echo "adapter exited nonzero in fallback case" >&2
        cat "$ndjson" >&2 || true
        cat "$adapter_stderr" >&2 || true
        exit 1
    }

    echo "smoke-codex-provider-degraded: fallback assertions"
    assert_grep "max-1 503 classified provider_5xx" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":503.*"classification":"provider_5xx".*"delivered_to_codex":false' "$ndjson"
    assert_grep "provider same-turn retry fired" '"kind":"proxy_provider_same_turn_retry".*"from":"codex:max-1".*"to":"codex:max-2".*"reason":"provider_5xx"' "$ndjson"
    assert_grep "fallback account returned 200" '"kind":"proxy_turn".*"account":"codex:max-2".*"status":200.*"classification":"ok"' "$ndjson"
    assert_no_grep "provider retry did not use quota retry event" '"kind":"proxy_same_turn_retry".*"reason":"provider_5xx"' "$ndjson"
    assert_no_grep "no route-repair body leaked on provider fallback" 'oauth_mux_no_account_selectable' "$stub_report"
    jq -e 'select(.name == "codex.proxy.turn" and .attributes.classification == "provider_5xx" and .attributes.delivered_to_codex == false)' "$trace_file" >/dev/null
    echo "  ✓ trace captured provider 5xx turn"
    jq -e 'select(.name == "codex.proxy.retry" and .attributes.reason == "provider_5xx" and .attributes.raw_account_id_printed == false)' "$trace_file" >/dev/null
    echo "  ✓ trace captured provider retry boundary"

    local got_200
    got_200="$(jq -r '.turns | map(select(.status == 200)) | length' "$stub_report")"
    if [[ "$got_200" -eq 3 ]]; then
        echo "  ✓ stub-codex saw all 3 turns return 200"
    else
        echo "  ✗ stub-codex saw $got_200 200s (expected 3)" >&2
        jq .turns "$stub_report" >&2
        exit 1
    fi

    local plan_after selected_after
    plan_after="$(
      PATH="$case_dir/bin:$PATH" \
      OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      "$BIN" codex broker-session-plan --profile codex-max --capability codex-max --json
    )"
    selected_after="$(jq -r '.selected.account' <<<"$plan_after")"
    if [[ "$selected_after" == "max-2" ]]; then
        echo "  ✓ broker-session-plan avoids provider-degraded max-1"
    else
        echo "  ✗ broker-session-plan selected $selected_after after max-1 provider 503" >&2
        jq . <<<"$plan_after" >&2
        exit 1
    fi
}

run_no_fallback_case() {
    local case_dir="$TMP/no-fallback"
    local portfile="$case_dir/upstream.port"
    local ndjson="$case_dir/adapter.ndjson"
    local adapter_stderr="$case_dir/adapter.stderr"
    local stub_report="$case_dir/stub-codex.report"
    local trace_file="$case_dir/trace.ndjson"
    mkdir -p "$case_dir"
    write_one_account_fixture "$case_dir"

    OMUX_STUB_PORT=0 \
      OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_ALWAYS_STATUS=503 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$case_dir/upstream.stderr" &
    local upstream_pid=$!
    UPSTREAM_PIDS+=("$upstream_pid")
    wait_for_port "$portfile"
    local upstream_port
    upstream_port="$(cat "$portfile" | tr -d '[:space:]')"
    echo "smoke-codex-provider-degraded: no-fallback stub pid=$upstream_pid port=$upstream_port always=503"

    OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$upstream_port" \
      OMUX_UPSTREAM_SCHEME="http" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$trace_file" \
      OMUX_STUB_CODEX_TURNS=1 \
      OMUX_STUB_CODEX_REPORT="$stub_report" \
      "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$ndjson" 2>"$adapter_stderr" || {
        echo "adapter exited nonzero in no-fallback case" >&2
        cat "$ndjson" >&2 || true
        cat "$adapter_stderr" >&2 || true
        exit 1
    }

    echo "smoke-codex-provider-degraded: no-fallback assertions"
    assert_grep "single account 503 classified provider_5xx" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":503.*"classification":"provider_5xx".*"delivered_to_codex":false' "$ndjson"
    assert_grep "provider retry unavailable event fired" '"kind":"proxy_provider_retry_unavailable".*"from":"codex:max-1".*"delivered_to_codex":true' "$ndjson"
    assert_no_grep "no quota all-exhausted event for provider 503" '"kind":"quota_handoff_failed_no_account_selectable"' "$ndjson"
    assert_no_grep "no route-repair response for provider 503" 'oauth_mux_no_account_selectable' "$stub_report"
    jq -e 'select(.name == "codex.proxy.provider_unavailable" and .attributes.transport_error == "NoAccountSelectable" and .attributes.delivered_to_codex == true)' "$trace_file" >/dev/null
    echo "  ✓ trace captured provider-unavailable terminal boundary"

    local got_503
    got_503="$(jq -r '.turns | map(select(.status == 503 and (.body_head | contains("forced status 503")))) | length' "$stub_report")"
    if [[ "$got_503" -eq 1 ]]; then
        echo "  ✓ stub-codex saw original provider 503 body"
    else
        echo "  ✗ stub-codex did not see original provider 503 body" >&2
        jq .turns "$stub_report" >&2
        exit 1
    fi

    for leak in "$ID_TOKEN" RT-A acc-A-id "$case_dir/account-A/auth.json"; do
        if grep -Fq "$leak" "$trace_file"; then
            echo "  ✗ trace leaked sensitive value: $leak" >&2
            cat "$trace_file" >&2
            exit 1
        fi
    done
    echo "  ✓ trace did not leak provider-degraded auth material"
}

run_transport_failure_case() {
    local case_dir="$TMP/transport-failure"
    local ndjson="$case_dir/adapter.ndjson"
    local adapter_stderr="$case_dir/adapter.stderr"
    local stub_report="$case_dir/stub-codex.report"
    local trace_file="$case_dir/trace.ndjson"
    mkdir -p "$case_dir"
    write_one_account_fixture "$case_dir"

    local closed_port
    closed_port="$(
      python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
    )"
    echo "smoke-codex-provider-degraded: transport-failure closed_port=$closed_port"

    OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$closed_port" \
      OMUX_UPSTREAM_SCHEME="http" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$trace_file" \
      OMUX_STUB_CODEX_TURNS=1 \
      OMUX_STUB_CODEX_REPORT="$stub_report" \
      "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$ndjson" 2>"$adapter_stderr" || {
        echo "adapter exited nonzero in transport-failure case" >&2
        cat "$ndjson" >&2 || true
        cat "$adapter_stderr" >&2 || true
        exit 1
    }

    echo "smoke-codex-provider-degraded: transport-failure assertions"
    assert_grep "transport failure recorded upstream failure" '"kind":"proxy_upstream_failed".*"account":"codex:max-1"' "$ndjson"
    assert_grep "transport failure delivered provider unavailable" '"kind":"proxy_provider_retry_unavailable".*"from":"codex:max-1".*"delivered_to_codex":true' "$ndjson"
    jq -e 'select(.name == "codex.proxy.upstream_failure" and .attributes.path_kind == "responses" and .attributes.raw_account_id_printed == false)' "$trace_file" >/dev/null
    echo "  ✓ trace captured upstream transport failure"
    jq -e 'select(.name == "codex.proxy.provider_unavailable" and .attributes.delivered_to_codex == true)' "$trace_file" >/dev/null
    echo "  ✓ trace captured provider-unavailable transport boundary"

    local got_503
    got_503="$(jq -r '[.turns[] | select(.status == 503 and (.body_head | contains("oauth_mux_provider_unavailable")))] | length' "$stub_report")"
    if [[ "$got_503" -eq 1 ]]; then
        echo "  ✓ stub-codex saw oauth_mux_provider_unavailable body"
    else
        echo "  ✗ stub-codex did not see provider-unavailable body" >&2
        jq .turns "$stub_report" >&2
        exit 1
    fi
}

run_upstream_interrupted_case() {
    local case_dir="$TMP/upstream-interrupted"
    local portfile="$case_dir/upstream.port"
    local ndjson="$case_dir/adapter.ndjson"
    local adapter_stderr="$case_dir/adapter.stderr"
    local stub_report="$case_dir/stub-codex.report"
    local trace_file="$case_dir/trace.ndjson"
    mkdir -p "$case_dir"
    write_one_account_fixture "$case_dir"

    OMUX_STUB_PORT=0 \
      OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_OK_BEFORE_429=99 \
      OMUX_STUB_200_BODY_REPEAT=4096 \
      OMUX_STUB_TRUNCATE_200_AFTER_BYTES=128 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$case_dir/upstream.stderr" &
    local upstream_pid=$!
    UPSTREAM_PIDS+=("$upstream_pid")
    wait_for_port "$portfile"
    local upstream_port
    upstream_port="$(cat "$portfile" | tr -d '[:space:]')"
    echo "smoke-codex-provider-degraded: upstream-interrupted stub pid=$upstream_pid port=$upstream_port"

    OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$upstream_port" \
      OMUX_UPSTREAM_SCHEME="http" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$trace_file" \
      OMUX_STUB_CODEX_TURNS=1 \
      OMUX_STUB_CODEX_REPORT="$stub_report" \
      "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$ndjson" 2>"$adapter_stderr" || {
        echo "adapter exited nonzero in upstream-interrupted case" >&2
        cat "$ndjson" >&2 || true
        cat "$adapter_stderr" >&2 || true
        exit 1
    }

    echo "smoke-codex-provider-degraded: upstream-interrupted assertions"
    jq -e 'select(.kind == "proxy_stream_interrupted" and .account == "codex:max-1" and .status == 200 and .bytes_streamed > 0 and .delivered_to_codex == true and .retry_attempted == false)' "$ndjson" >/dev/null
    echo "  ✓ upstream partial stream classified as interrupted"
    assert_no_grep "partial upstream stream did not same-turn retry" '"kind":"proxy_provider_same_turn_retry"|"kind":"proxy_same_turn_retry"|"kind":"proxy_provider_retry_unavailable"' "$ndjson"
    jq -e 'select(.name == "codex.proxy.upstream_failure" and .attributes.path_kind == "responses" and .attributes.raw_account_id_printed == false)' "$trace_file" >/dev/null
    echo "  ✓ trace captured interrupted upstream stream"
    jq -e '[.turns[] | select(.status == 200 and (.body_head | contains("response.created")))] | length == 1' "$stub_report" >/dev/null
    echo "  ✓ stub-codex saw partial 200 stream"
    jq -e '[.accounts[] | select(.key == "codex:max-1#codex-max" and .last_probe_hint_class == "provider_degraded")] | length == 1' "$case_dir/state/health.json" >/dev/null
    echo "  ✓ interrupted upstream stream recorded provider-degraded route health"
}

run_client_disconnect_case() {
    local case_dir="$TMP/client-disconnect"
    local portfile="$case_dir/upstream.port"
    local ndjson="$case_dir/adapter.ndjson"
    local adapter_stderr="$case_dir/adapter.stderr"
    local stub_report="$case_dir/stub-codex.report"
    local trace_file="$case_dir/trace.ndjson"
    mkdir -p "$case_dir"
    write_one_account_fixture "$case_dir"

    OMUX_STUB_PORT=0 \
      OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_OK_BEFORE_429=99 \
      OMUX_STUB_200_BODY_REPEAT=4096 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$case_dir/upstream.stderr" &
    local upstream_pid=$!
    UPSTREAM_PIDS+=("$upstream_pid")
    wait_for_port "$portfile"
    local upstream_port
    upstream_port="$(cat "$portfile" | tr -d '[:space:]')"
    echo "smoke-codex-provider-degraded: client-disconnect stub pid=$upstream_pid port=$upstream_port"

    OMUX_CONFIG="$case_dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$case_dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$upstream_port" \
      OMUX_UPSTREAM_SCHEME="http" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$trace_file" \
      OMUX_STUB_CODEX_TURNS=1 \
      OMUX_STUB_CODEX_DISCONNECT_TURNS=0 \
      OMUX_STUB_CODEX_REPORT="$stub_report" \
      "$BIN" codex run --profile codex-max --isolated-session-store --json-status-file "$ndjson" 2>"$adapter_stderr" || {
        echo "adapter exited nonzero in client-disconnect case" >&2
        cat "$ndjson" >&2 || true
        cat "$adapter_stderr" >&2 || true
        exit 1
    }

    echo "smoke-codex-provider-degraded: client-disconnect assertions"
    assert_grep "downstream close classified as client disconnect" '"kind":"proxy_client_disconnected".*"account":"codex:max-1".*"status":200.*"retry_attempted":false' "$ndjson"
    assert_no_grep "downstream close did not record upstream failure" '"kind":"proxy_upstream_failed"' "$ndjson"
    assert_no_grep "downstream close did not same-turn retry" '"kind":"proxy_provider_same_turn_retry"|"kind":"proxy_same_turn_retry"|"kind":"proxy_provider_retry_unavailable"' "$ndjson"
    assert_no_grep "adapter stderr suppresses benign proxy close" 'proxy: serveOne: (BrokenPipe|ConnectionResetByPeer|EndOfStream)' "$adapter_stderr"
    jq -e '[.turns[] | select(.status == 0 and (.body_head | contains("client_disconnected_before_response")))] | length == 1' "$stub_report" >/dev/null
    echo "  ✓ stub-codex intentionally closed the turn socket"
    jq -e '[.accounts[] | select(.last_probe_hint_class == "provider_degraded")] | length == 0' "$case_dir/state/health.json" >/dev/null
    echo "  ✓ route health was not polluted by downstream disconnect"
}

run_fallback_case
run_no_fallback_case
run_transport_failure_case
run_upstream_interrupted_case
run_client_disconnect_case

echo
echo "smoke-codex-provider-degraded: all assertions passed."
