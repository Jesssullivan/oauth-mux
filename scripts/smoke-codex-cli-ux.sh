#!/usr/bin/env bash
# No-spend UX smoke for first-class `oauth-mux codex ...` adapter entrypoints.
#
# Covers the daily-use resume shapes that should not require raw
# `codex run -- ...` coercion:
#
#   oauth-mux codex resume --last
#   oauth-mux codex resume <id>
#   oauth-mux codex resume
#   oauth-mux codex run -- resume --last
#
# It also pins the malformed raw-run path:
#
#   oauth-mux codex run resume --last
#
# That path must fail helpfully rather than silently dropping args.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-codex-cli-ux: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-codex-cli-ux: jq required" >&2
    exit 64
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-cli-ux: python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-codex-cli-ux.XXXXXX)"
CANONICAL_SESSION_HOME="$TMP/canonical-codex"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$CANONICAL_SESSION_HOME/sessions/2026/05/06" "$CANONICAL_SESSION_HOME/shell_snapshots"
touch "$CANONICAL_SESSION_HOME/history.jsonl" "$CANONICAL_SESSION_HOME/session_index.jsonl"
printf '%s\n' '{"fixture":"resume"}' >"$CANONICAL_SESSION_HOME/sessions/2026/05/06/rollout-managed-good-session.jsonl"
printf '%s\n' '{"bridge":"preexisting"}' >"$CANONICAL_SESSION_HOME/sessions/omux-session-bridge-smoke.jsonl"

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cli-ux-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
printf '%s\n' 'preexisting = "account-A"' >"$TMP/account-A/config.toml"

cat >"$TMP/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "$TMP/account-A/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max"] }
  }
}
EOF

assert_grep() {
    local label=$1 pattern=$2 file=$3
    if grep -q -E "$pattern" "$file"; then
        echo "  ✓ $label"
    else
        echo "  ✗ $label" >&2
        echo "    pattern: $pattern" >&2
        echo "    file: $file" >&2
        cat "$file" >&2 || true
        exit 1
    fi
}

run_case() {
    local mode=$1 label=$2 expected_argv=$3
    shift 3
    local dir="$TMP/$label"
    local ndjson="$dir/status/nested/adapter.ndjson"
    local stderr="$dir/adapter.stderr"
    local report="$dir/stub.report"
    local -a cmd

    mkdir -p "$dir"
    if [[ "$mode" == "top" ]]; then
        cmd=( "$BIN" codex --profile codex-max --json-status-file "$ndjson" "$@" )
    else
        cmd=( "$BIN" codex run --profile codex-max --json-status-file "$ndjson" -- "$@" )
    fi

    OMUX_CONFIG="$TMP/oauth-mux.config.json" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
      OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
      OMUX_STUB_APPEND_SESSION="sessions/2026/05/06/rollout-managed-good-session.jsonl" \
      OMUX_STUB_CODEX_TURNS=0 \
      OMUX_STUB_CODEX_REPORT="$report" \
      "${cmd[@]}" 2>"$stderr"

    if [[ ! -s "$ndjson" ]]; then
        echo "  ✗ $label status file was not created at nested path" >&2
        cat "$stderr" >&2 || true
        exit 1
    fi
    if [[ ! -s "$report" ]]; then
        echo "  ✗ $label stub report missing" >&2
        cat "$stderr" >&2 || true
        exit 1
    fi

    assert_grep "$label session_started" '"kind":"session_started"' "$ndjson"
    assert_grep "$label canonical session bridge" '"session_authority":"canonical_bridge"' "$ndjson"
    assert_grep "$label resume preflight" '"kind":"resume_preflight"' "$ndjson"
    assert_grep "$label resume writeback" '"kind":"resume_writeback".*"changed_existing":[1-9]' "$ndjson"
    assert_grep "$label resume status redacts paths" '"kind":"resume_writeback".*"session_id_printed":false,"path_printed":false' "$ndjson"
    assert_grep "$label session_ended" '"kind":"session_ended".*"exit_code":0' "$ndjson"

    if grep -q '"kind":"session_started"' "$stderr"; then
        echo "  ✗ $label leaked adapter status frames to stderr" >&2
        cat "$stderr" >&2
        exit 1
    fi

    local actual_argv
    actual_argv="$(jq -c .argv "$report")"
    if [[ "$actual_argv" == "$expected_argv" ]]; then
        echo "  ✓ $label forwarded argv $expected_argv"
    else
        echo "  ✗ $label argv mismatch: expected $expected_argv actual $actual_argv" >&2
        cat "$report" >&2
        exit 1
    fi

    if [[ "$(jq -r .session_bridge.checked "$report")" == "true" \
          && "$(jq -r .session_bridge.sessions_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.history_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.session_index_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.shell_snapshots_samefile "$report")" == "true" ]]; then
        echo "  ✓ $label bridged canonical session authority"
    else
        echo "  ✗ $label session bridge failed" >&2
        cat "$report" >&2
        exit 1
    fi

    if [[ "$(jq -r .session_append.checked "$report")" == "true" \
          && "$(jq -r .session_append.path_printed "$report")" == "false" ]]; then
        echo "  ✓ $label appended through bridged session authority"
    else
        echo "  ✗ $label session append evidence failed" >&2
        cat "$report" >&2
        exit 1
    fi
}

echo "smoke-codex-cli-ux: first-class resume aliases"
run_case top "resume-last" '["resume","--last"]' resume --last
run_case top "resume-id" '["resume","managed-good-session"]' resume managed-good-session
run_case top "resume-chooser" '["resume"]' resume
run_case raw "raw-run" '["resume","--last"]' resume --last

echo "smoke-codex-cli-ux: malformed raw run fails helpfully"
BAD_ERR="$TMP/bad-run.stderr"
BAD_REPORT="$TMP/bad-run.report"
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     OMUX_STUB_CODEX_REPORT="$BAD_REPORT" \
     "$BIN" codex run resume --last 2>"$BAD_ERR"; then
    echo "  ✗ malformed raw run unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "malformed raw run reports unknown option" 'unknown adapter option "resume"' "$BAD_ERR"
if [[ -e "$BAD_REPORT" ]]; then
    echo "  ✗ malformed raw run launched stub unexpectedly" >&2
    cat "$BAD_REPORT" >&2
    exit 1
else
    echo "  ✓ malformed raw run exits before child spawn"
fi

echo "smoke-codex-cli-ux: all assertions passed."
