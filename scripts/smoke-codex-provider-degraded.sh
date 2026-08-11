#!/usr/bin/env bash
# Live-handler contract smoke for Codex provider/transport failures.
#
# Proves against the real managed proxy and fake upstream that:
#   * 5xx status/body streams unchanged, including bodies over 64 KiB;
#   * interrupted 5xx and ambiguous transport never cross accounts;
#   * materialized OAuth identity, not stale pool hashes/labels, fences alternates;
#   * a request gets at most one alternate and preserves exact model/body bytes.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-provider-degraded: oauth-mux binary not built at $BIN" >&2
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
        echo "smoke-codex-provider-degraded: kept $TMP" >&2
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"

assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ok - $label"
    else
        echo "  FAIL - $label ($pattern)" >&2
        cat "$file" >&2 || true
        return 1
    fi
}

assert_no_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  FAIL - $label (unexpected $pattern)" >&2
        cat "$file" >&2 || true
        return 1
    fi
    echo "  ok - $label"
}

wait_for_port() {
    local portfile=$1
    for _ in {1..80}; do
        [[ -s "$portfile" ]] && return 0
        sleep 0.05
    done
    echo "stub upstream did not bind" >&2
    return 1
}

write_fixture() {
    local dir=$1 count=$2
    mkdir -p "$dir/state"
    local accounts_json="" profile_json="" health_json=""
    local labels=(max-1 max-2 max-3)
    local ids=(acc-A-id acc-B-id acc-C-id)
    local tokens=(AT-A AT-B AT-C)
    local priorities=(30 20 10)
    local i label identity
    for ((i = 0; i < count; i++)); do
        label=${labels[$i]}
        identity=${ids[$i]}
        mkdir -p "$dir/$label"
        cat >"$dir/$label/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"${tokens[$i]}","refresh_token":"RT-$i","account_id":"$identity"},"auth_mode":"Chatgpt"}
EOF
        [[ -n "$accounts_json" ]] && accounts_json+=","
        accounts_json+="\"$label\":{\"priority\":${priorities[$i]},\"config_dir\":\"$dir/$label\",\"secret\":{\"backend\":\"file\",\"path\":\"$dir/$label/auth.json\"}}"
        [[ -n "$profile_json" ]] && profile_json+=","
        profile_json+="\"codex:$label#codex-max\""
        [[ -n "$health_json" ]] && health_json+=","
        health_json+="{\"key\":\"codex:$label#codex-max\",\"last_probe_source\":\"capability_probe\",\"last_probe_hint_class\":\"none\",\"last_probe_decision\":\"use_this\",\"liveness\":{\"state\":\"live\",\"availability\":\"available\"}}"
    done
    printf '{"version":1,"providers":{"codex":{"kind":"codex","accounts":{%s}}},"profiles":{"codex-max":{"providers":[%s]}}}\n' \
        "$accounts_json" "$profile_json" >"$dir/oauth-mux.config.json"
    printf '{"version":2,"accounts":[%s]}\n' "$health_json" >"$dir/state/health.json"
}

run_adapter() {
    local dir=$1 port=$2 turns=$3 codex_bin=${4:-$ROOT/scripts/test-stub-codex.py}
    OMUX_CONFIG="$dir/oauth-mux.config.json" \
      OMUX_STATE_DIR="$dir/state" \
      OMUX_UPSTREAM_HOST="127.0.0.1:$port" \
      OMUX_UPSTREAM_SCHEME=http \
      OMUX_CODEX_BIN="$codex_bin" \
      OMUX_TRACE=1 \
      OMUX_TRACE_FILE="$dir/trace.ndjson" \
      OMUX_STUB_CODEX_TURNS="$turns" \
      OMUX_STUB_CODEX_REPORT="$dir/stub-report.json" \
      "$BIN" codex run --profile codex-max --isolated-session-store \
        --json-status-file "$dir/status.ndjson" 2>"$dir/adapter.stderr"
}

run_large_5xx_passthrough() {
    local dir="$TMP/large-5xx" portfile="$TMP/large-5xx/upstream.port"
    mkdir -p "$dir"
    write_fixture "$dir" 2
    OMUX_STUB_PORT=0 OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_LOGFILE="$dir/upstream.ndjson" \
      OMUX_STUB_ACCOUNT_STATUS_JSON='{"acc-A-id":503}' \
      OMUX_STUB_FORCED_BODY_BYTES=131072 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$dir/upstream.stderr" &
    UPSTREAM_PIDS+=("$!")
    wait_for_port "$portfile"
    run_adapter "$dir" "$(tr -d '[:space:]' <"$portfile")" 1

    echo "smoke-codex-provider-degraded: large 5xx pass-through"
    assert_grep "503 streamed directly to Codex" '"kind":"proxy_turn".*"account":"codex:max-1".*"status":503.*"classification":"provider_5xx".*"streamed":true.*"delivered_to_codex":true' "$dir/status.ndjson"
    assert_no_grep "5xx never invokes an alternate" 'proxy_same_turn_retry|proxy_auth_same_turn_retry|proxy_materialized_identity_refused' "$dir/status.ndjson"
    jq -e '.turns | length == 1 and .[0].status == 503 and .[0].response_bytes > 65536 and (.[0].body_head | contains("forced status 503"))' "$dir/stub-report.json" >/dev/null
    echo "  ok - body larger than 64 KiB reached Codex"
    jq -s -e 'length == 1 and .[0].account_id == "acc-A-id"' "$dir/upstream.ndjson" >/dev/null
    echo "  ok - upstream saw no cross-account request"
    assert_no_grep "5xx did not poison route health" 'provider_degraded' "$dir/state/health.json"
}

run_interrupted_5xx() {
    local dir="$TMP/interrupted-5xx" portfile="$TMP/interrupted-5xx/upstream.port"
    mkdir -p "$dir"
    write_fixture "$dir" 2
    OMUX_STUB_PORT=0 OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_LOGFILE="$dir/upstream.ndjson" \
      OMUX_STUB_ACCOUNT_STATUS_JSON='{"acc-A-id":503}' \
      OMUX_STUB_FORCED_BODY_BYTES=131072 \
      OMUX_STUB_ACCOUNT_BODY_STALL_MS_JSON='{"acc-A-id":1000}' \
      OMUX_STUB_ACCOUNT_BODY_STALL_AFTER_BYTES_JSON='{"acc-A-id":128}' \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$dir/upstream.stderr" &
    UPSTREAM_PIDS+=("$!")
    wait_for_port "$portfile"
    OMUX_PROXY_UPSTREAM_BODY_IDLE_TIMEOUT_MS=250 run_adapter "$dir" "$(tr -d '[:space:]' <"$portfile")" 1 || true

    echo "smoke-codex-provider-degraded: interrupted 5xx"
    assert_grep "started 503 interruption is terminal" '"kind":"proxy_stream_interrupted".*"account":"codex:max-1".*"status":503.*"bytes_streamed":[1-9][0-9]*.*"retry_attempted":false' "$dir/status.ndjson"
    assert_no_grep "interrupted 5xx never crosses accounts" 'proxy_same_turn_retry|proxy_auth_same_turn_retry' "$dir/status.ndjson"
    jq -s -e 'map(select(.account_id == "acc-B-id")) | length == 0' "$dir/upstream.ndjson" >/dev/null
    echo "  ok - alternate account was not called"
}

run_ambiguous_transport_terminal() {
    local dir="$TMP/ambiguous" portfile="$TMP/ambiguous/upstream.port"
    mkdir -p "$dir"
    write_fixture "$dir" 2
    OMUX_STUB_PORT=0 OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_LOGFILE="$dir/upstream.ndjson" \
      OMUX_STUB_ACCOUNT_RESET_JSON='{"acc-A-id":"before_response"}' \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$dir/upstream.stderr" &
    UPSTREAM_PIDS+=("$!")
    wait_for_port "$portfile"
    run_adapter "$dir" "$(tr -d '[:space:]' <"$portfile")" 1

    echo "smoke-codex-provider-degraded: ambiguous transport"
    assert_grep "ambiguous transport recorded" '"kind":"proxy_upstream_failed".*"account":"codex:max-1".*"send_state":"ambiguous"' "$dir/status.ndjson"
    assert_no_grep "ambiguous transport never retries" 'proxy_same_route_transport_retry|proxy_same_turn_retry|proxy_auth_same_turn_retry' "$dir/status.ndjson"
    jq -s -e 'length == 1 and .[0].account_id == "acc-A-id"' "$dir/upstream.ndjson" >/dev/null
    echo "  ok - ambiguous request used one account and one attempt"
}

run_stale_hash_identity_fence() {
    local dir="$TMP/stale-hash" portfile="$TMP/stale-hash/upstream.port"
    mkdir -p "$dir"
    write_fixture "$dir" 2
    cat >"$dir/rewrite-and-run-codex" <<EOF
#!/usr/bin/env bash
python3 - '$dir/max-2/auth.json' <<'PY'
import json, sys
p = sys.argv[1]
doc = json.load(open(p))
doc['tokens']['account_id'] = 'acc-A-id'
json.dump(doc, open(p, 'w'))
PY
exec '$ROOT/scripts/test-stub-codex.py' "\$@"
EOF
    chmod +x "$dir/rewrite-and-run-codex"
    OMUX_STUB_PORT=0 OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_LOGFILE="$dir/upstream.ndjson" OMUX_STUB_ALWAYS_STATUS=429 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$dir/upstream.stderr" &
    UPSTREAM_PIDS+=("$!")
    wait_for_port "$portfile"
    run_adapter "$dir" "$(tr -d '[:space:]' <"$portfile")" 1 "$dir/rewrite-and-run-codex"

    echo "smoke-codex-provider-degraded: authoritative identity fence"
    assert_grep "same materialized identity refused before upstream" '"kind":"proxy_materialized_identity_refused".*"err":"SameMaterializedIdentityAlternate".*"alternate":true.*"upstream_called":false' "$dir/status.ndjson"
    assert_no_grep "refused alias never reports a completed retry" 'proxy_same_turn_retry|proxy_auth_same_turn_retry' "$dir/status.ndjson"
    jq -s -e 'length == 1 and .[0].account_id == "acc-A-id"' "$dir/upstream.ndjson" >/dev/null
    echo "  ok - stale distinct pool hashes could not create fake capacity"
}

run_two_attempt_exact_body() {
    local dir="$TMP/two-attempt" portfile="$TMP/two-attempt/upstream.port"
    mkdir -p "$dir"
    write_fixture "$dir" 3
    OMUX_STUB_PORT=0 OMUX_STUB_PORTFILE="$portfile" \
      OMUX_STUB_LOGFILE="$dir/upstream.ndjson" OMUX_STUB_ALWAYS_STATUS=429 \
      python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$dir/upstream.stderr" &
    UPSTREAM_PIDS+=("$!")
    wait_for_port "$portfile"
    run_adapter "$dir" "$(tr -d '[:space:]' <"$portfile")" 1

    echo "smoke-codex-provider-degraded: two-attempt immutable request"
    jq -s -e 'length == 2 and (map(.account_id) | unique | length) == 2 and (map(.request_body_sha256) | unique | length) == 1 and (map(.request_model) | unique) == ["gpt-5.3-codex"]' "$dir/upstream.ndjson" >/dev/null
    echo "  ok - exactly two distinct-account attempts preserved model/body"
    assert_grep "one alternate event" '"kind":"proxy_same_turn_retry".*"reason":"rate_limited"' "$dir/status.ndjson"
    assert_no_grep "no third attempt" 'proxy_attempt_budget_exhausted' "$dir/status.ndjson"
}

run_large_5xx_passthrough
run_interrupted_5xx
run_ambiguous_transport_terminal
run_stale_hash_identity_fence
run_two_attempt_exact_body

echo "smoke-codex-provider-degraded: all live-handler assertions passed."
