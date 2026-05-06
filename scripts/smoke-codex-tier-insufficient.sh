#!/usr/bin/env bash
# Negative-path smoke: usage_not_included is a plan-tier problem, not a
# quota handoff signal. The proxy must classify it as tier_insufficient
# and must not rotate accounts or promote the claim.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-tier-insufficient: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-tier-insufficient: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-tier.XXXXXX)"
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
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-tier-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-tier-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
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
  OMUX_STUB_OK_BEFORE_429=2 \
  OMUX_STUB_LOGFILE="$UPLOG" \
  OMUX_STUB_429_TYPE=usage_not_included \
  python3 "$ROOT/scripts/test-stub-upstream.py" 2>"$TMP/upstream.stderr" &
UPSTREAM_PID=$!

for _ in {1..40}; do
    [[ -s "$PORTFILE" ]] && break
    sleep 0.05
done
[[ -s "$PORTFILE" ]] || { echo "stub upstream did not bind" >&2; exit 1; }
UPSTREAM_PORT="$(cat "$PORTFILE" | tr -d '[:space:]')"
echo "smoke-codex-tier-insufficient: stub upstream pid=$UPSTREAM_PID port=$UPSTREAM_PORT 429_type=usage_not_included"

OMUX_CONFIG="$TMP/oauth-mux.config.json" \
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

echo "smoke-codex-tier-insufficient: assertions"

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
assert_grep "proxy_turn 200 ok at least once" '"kind":"proxy_turn".*"status":200.*"classification":"ok"' "$NDJSON"
assert_grep "proxy_turn 429 classified tier_insufficient" '"kind":"proxy_turn".*"status":429.*"classification":"tier_insufficient"' "$NDJSON"

assert_no_grep "no swap fired" '"kind":"proxy_post_swap_turn"' "$NDJSON"
assert_no_grep "no same-turn retry fired" '"kind":"proxy_same_turn_retry"' "$NDJSON"
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
if [[ "$DISTINCT_ACCT" -eq 1 ]]; then
    echo "  ✓ exactly one account elected throughout"
else
    echo "  ✗ tier_insufficient triggered rotation across $DISTINCT_ACCT accounts" >&2
    grep -oE '"account":"codex:max-[12]"' "$NDJSON" | sort -u >&2
    exit 1
fi

UP_DISTINCT=$(jq -r .account_id "$UPLOG" | sort -u | wc -l | tr -d ' ')
if [[ "$UP_DISTINCT" -eq 1 ]]; then
    echo "  ✓ stub upstream saw exactly 1 ChatGPT-Account-ID"
else
    echo "  ✗ upstream saw $UP_DISTINCT distinct account ids" >&2
    cat "$UPLOG" >&2
    exit 1
fi

echo
echo "smoke-codex-tier-insufficient: all 11 assertions passed."
echo "  full ndjson: $NDJSON"
