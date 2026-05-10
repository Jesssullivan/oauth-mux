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
STATE_DIR="$TMP/state"
CANONICAL_SESSION_HOME="$TMP/canonical-codex"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$TMP/claude-personal" "$STATE_DIR" "$CANONICAL_SESSION_HOME/sessions/2026/05/06" "$CANONICAL_SESSION_HOME/shell_snapshots"
touch "$CANONICAL_SESSION_HOME/history.jsonl" "$CANONICAL_SESSION_HOME/session_index.jsonl"
printf '%s\n' '{"fixture":"resume"}' >"$CANONICAL_SESSION_HOME/sessions/2026/05/06/rollout-managed-good-session.jsonl"
printf '%s\n' '{"bridge":"preexisting"}' >"$CANONICAL_SESSION_HOME/sessions/omux-session-bridge-smoke.jsonl"
cat >"$CANONICAL_SESSION_HOME/config.toml" <<'EOF'
model = "gpt-5.5"
model_provider = "user_provider"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
experimental_legacy_flag = true

[features]
apps = true
memories = true
multi_agent = true

[mcp_servers.design]
command = "figma-mcp"

[profiles.work]
model = "gpt-5.5"
model_provider = "profile_provider"
approval_policy = "on-request"

[model_providers.user_provider]
name = "User Provider"
base_url = "https://example.invalid/api"

[model_providers.oauth_mux_openai]
name = "stale mux"
base_url = "https://stale.invalid"
EOF

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cli-ux-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/claude-personal/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cli-ux-claude","refresh_token":"RT-claude","account_id":"acc-claude-id"},"auth_mode":"Chatgpt"}
EOF
printf '%s\n' 'preexisting = "account-A"' >"$TMP/account-A/config.toml"

cat >"$TMP/oauth-mux.config.json" <<EOF
{
  "version": 1,
  "providers": {
    "claude": {
      "kind": "claude",
      "accounts": {
        "personal": { "priority": 100, "secret": { "backend": "file", "path": "$TMP/claude-personal/auth.json" } }
      }
    },
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

cat >"$STATE_DIR/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"claude:personal","last_probe_source":"credential_validation","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}},
  {"key":"codex:max-1","last_probe_source":"credential_validation","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}},
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
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
      OMUX_STATE_DIR="$STATE_DIR" \
      OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
      CODEX_HOME="$CANONICAL_SESSION_HOME" \
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
    assert_grep "$label config passthrough status" '"config_passthrough":true,"user_config_present":true' "$ndjson"
    assert_grep "$label child spawn timing" '"kind":"launch_timing".*"phase":"child_spawn"' "$ndjson"
    assert_grep "$label resume preflight" '"kind":"resume_preflight"' "$ndjson"
    if [[ "$label" == "resume-chooser" ]]; then
        assert_grep "$label resume authority check" '"kind":"resume_authority_check".*"ok":true' "$ndjson"
        assert_grep "$label no chooser rollout scan before spawn" '"kind":"resume_preflight".*"mode":"chooser".*"rollouts_before":0' "$ndjson"
        assert_grep "$label resume writeback" '"kind":"resume_writeback".*"mode":"chooser"' "$ndjson"
    else
        assert_grep "$label resume writeback" '"kind":"resume_writeback".*"changed_existing":[1-9]' "$ndjson"
    fi
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

    if [[ "$(jq -r .config.proxy_provider_selected "$report")" == "true" \
          && "$(jq -r .config.proxy_provider_present "$report")" == "true" \
          && "$(jq -r .config.user_feature_apps "$report")" == "true" \
          && "$(jq -r .config.user_feature_memories "$report")" == "true" \
          && "$(jq -r .config.user_feature_multi_agent "$report")" == "true" \
          && "$(jq -r .config.user_experimental_legacy "$report")" == "true" \
          && "$(jq -r .config.user_mcp_server "$report")" == "true" \
          && "$(jq -r .config.user_approval_policy "$report")" == "true" \
          && "$(jq -r .config.user_sandbox_mode "$report")" == "true" \
          && "$(jq -r .config.profile_model_provider_absent "$report")" == "true" \
          && "$(jq -r .config.stale_mux_provider_absent "$report")" == "true" \
          && "$(jq -r .config.path_printed "$report")" == "false" ]]; then
        echo "  ✓ $label preserved canonical Codex config settings"
    else
        echo "  ✗ $label config passthrough failed" >&2
        cat "$report" >&2
        exit 1
    fi
}

echo "smoke-codex-cli-ux: first-class resume aliases"
run_case top "resume-last" '["resume","--last"]' resume --last
run_case top "resume-id" '["resume","managed-good-session"]' resume managed-good-session
run_case top "resume-chooser" '["resume"]' resume
run_case raw "raw-run" '["resume","--last"]' resume --last

echo "smoke-codex-cli-ux: resume chooser missing authority fails before spawn"
BAD_AUTHORITY_HOME="$TMP/bad-canonical-codex"
BAD_AUTHORITY_NDJSON="$TMP/bad-authority/status.ndjson"
BAD_AUTHORITY_STDERR="$TMP/bad-authority.stderr"
BAD_AUTHORITY_REPORT="$TMP/bad-authority.report"
mkdir -p "$BAD_AUTHORITY_HOME/sessions" "$(dirname "$BAD_AUTHORITY_NDJSON")"
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_STATE_DIR="$STATE_DIR" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     OMUX_CODEX_SESSION_HOME="$BAD_AUTHORITY_HOME" \
     OMUX_STUB_CANONICAL_SESSION_HOME="$BAD_AUTHORITY_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$BAD_AUTHORITY_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$BAD_AUTHORITY_NDJSON" resume 2>"$BAD_AUTHORITY_STDERR"; then
    echo "  ✗ missing authority chooser unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "missing authority diagnostic status" '"kind":"resume_authority_check".*"ok":false' "$BAD_AUTHORITY_NDJSON"
assert_grep "missing authority failed before child spawn" 'resume chooser unavailable' "$BAD_AUTHORITY_STDERR"
if [[ -e "$BAD_AUTHORITY_REPORT" ]]; then
    echo "  ✗ missing authority launched stub unexpectedly" >&2
    cat "$BAD_AUTHORITY_REPORT" >&2
    exit 1
else
    echo "  ✓ missing authority fails before child spawn"
fi
if grep -q -E 'managed-good-session|'"$BAD_AUTHORITY_HOME" "$BAD_AUTHORITY_NDJSON" "$BAD_AUTHORITY_STDERR"; then
    echo "  ✗ missing authority diagnostic leaked path or session id" >&2
    cat "$BAD_AUTHORITY_NDJSON" >&2
    cat "$BAD_AUTHORITY_STDERR" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: forwarded config provider override fails before spawn"
BAD_CONFIG_NDJSON="$TMP/bad-config/status.ndjson"
BAD_CONFIG_STDERR="$TMP/bad-config.stderr"
BAD_CONFIG_REPORT="$TMP/bad-config.report"
mkdir -p "$(dirname "$BAD_CONFIG_NDJSON")"
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_STATE_DIR="$STATE_DIR" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     CODEX_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$BAD_CONFIG_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$BAD_CONFIG_NDJSON" -- --config 'model_provider="openai"' 2>"$BAD_CONFIG_STDERR"; then
    echo "  ✗ forwarded config provider override unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "config override diagnostic status" '"kind":"config_passthrough_check".*"ok":false.*"model_provider_override":true' "$BAD_CONFIG_NDJSON"
assert_grep "config override failed before child spawn" 'forwarded Codex --config attempts to override managed provider settings' "$BAD_CONFIG_STDERR"
if [[ -e "$BAD_CONFIG_REPORT" ]]; then
    echo "  ✗ config override launched stub unexpectedly" >&2
    cat "$BAD_CONFIG_REPORT" >&2
    exit 1
else
    echo "  ✓ config override fails before child spawn"
fi
if grep -q -E 'openai|profile_provider|'"$CANONICAL_SESSION_HOME" "$BAD_CONFIG_NDJSON" "$BAD_CONFIG_STDERR"; then
    echo "  ✗ config override diagnostic leaked value or path" >&2
    cat "$BAD_CONFIG_NDJSON" >&2
    cat "$BAD_CONFIG_STDERR" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: bare codex resolution from PATH"
PATH_STUB_DIR="$TMP/path-bin"
PATH_NDJSON="$TMP/path-resolution/status.ndjson"
PATH_STDERR="$TMP/path-resolution.stderr"
PATH_REPORT="$TMP/path-resolution.report"
mkdir -p "$PATH_STUB_DIR" "$(dirname "$PATH_NDJSON")"
ln -s "$ROOT/scripts/test-stub-codex.py" "$PATH_STUB_DIR/codex"
PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_APPEND_SESSION="sessions/2026/05/06/rollout-managed-good-session.jsonl" \
  OMUX_STUB_CODEX_TURNS=0 \
  OMUX_STUB_CODEX_REPORT="$PATH_REPORT" \
  "$BIN" codex --profile codex-max --json-status-file "$PATH_NDJSON" resume --last 2>"$PATH_STDERR"
assert_grep "path-resolution session_ended" '"kind":"session_ended".*"exit_code":0' "$PATH_NDJSON"
if [[ "$(jq -c .argv "$PATH_REPORT")" == '["resume","--last"]' ]]; then
    echo "  ✓ bare codex resolved from PATH and received resume argv"
else
    echo "  ✗ bare codex PATH resolution report mismatch" >&2
    cat "$PATH_REPORT" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: no-profile codex election is provider-scoped"
NO_PROFILE_NDJSON="$TMP/no-profile/status.ndjson"
NO_PROFILE_STDERR="$TMP/no-profile.stderr"
NO_PROFILE_REPORT="$TMP/no-profile.report"
mkdir -p "$(dirname "$NO_PROFILE_NDJSON")"
PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_APPEND_SESSION="sessions/2026/05/06/rollout-managed-good-session.jsonl" \
  OMUX_STUB_CODEX_TURNS=0 \
  OMUX_STUB_CODEX_REPORT="$NO_PROFILE_REPORT" \
  "$BIN" codex --json-status-file "$NO_PROFILE_NDJSON" resume --last 2>"$NO_PROFILE_STDERR"
assert_grep "no-profile selected codex account" '"kind":"session_started".*"selected_account":"codex:max-1"' "$NO_PROFILE_NDJSON"
assert_grep "no-profile session_ended" '"kind":"session_ended".*"exit_code":0' "$NO_PROFILE_NDJSON"
if [[ "$(jq -c .argv "$NO_PROFILE_REPORT")" == '["resume","--last"]' ]]; then
    echo "  ✓ no-profile resume stayed in codex provider scope"
else
    echo "  ✗ no-profile provider-scoped report mismatch" >&2
    cat "$NO_PROFILE_REPORT" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: default status artifact without extra flags"
DEFAULT_STATUS_DIR="$STATE_DIR/codex/status"
DEFAULT_STDERR="$TMP/default-status.stderr"
DEFAULT_REPORT="$TMP/default-status.report"
rm -rf "$DEFAULT_STATUS_DIR"
PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_APPEND_SESSION="sessions/2026/05/06/rollout-managed-good-session.jsonl" \
  OMUX_STUB_CODEX_TURNS=0 \
  OMUX_STUB_CODEX_REPORT="$DEFAULT_REPORT" \
  "$BIN" codex --profile codex-max resume --last 2>"$DEFAULT_STDERR"
DEFAULT_STATUS_COUNT="$(find "$DEFAULT_STATUS_DIR" -type f -name '*.ndjson' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$DEFAULT_STATUS_COUNT" != "1" ]]; then
    echo "  ✗ default status artifact count: expected 1 actual $DEFAULT_STATUS_COUNT" >&2
    find "$DEFAULT_STATUS_DIR" -type f -name '*.ndjson' 2>/dev/null >&2 || true
    cat "$DEFAULT_STDERR" >&2 || true
    exit 1
fi
DEFAULT_NDJSON="$(find "$DEFAULT_STATUS_DIR" -type f -name '*.ndjson' | head -n 1)"
assert_grep "default status session_started" '"kind":"session_started".*"status_file_present":true' "$DEFAULT_NDJSON"
assert_grep "default status runtime identity" '"runtime_identity":\{' "$DEFAULT_NDJSON"
assert_grep "default status session_ended" '"kind":"session_ended".*"exit_code":0' "$DEFAULT_NDJSON"
if grep -q '"kind":"session_started"' "$DEFAULT_STDERR"; then
    echo "  ✗ default status frames leaked to stderr" >&2
    cat "$DEFAULT_STDERR" >&2
    exit 1
else
    echo "  ✓ default run wrote redacted status artifact"
fi
LATEST_SUMMARY="$TMP/default-status-summary.json"
OMUX_STATE_DIR="$STATE_DIR" "$BIN" codex status-latest --json >"$LATEST_SUMMARY"
if [[ "$(jq -r .path "$LATEST_SUMMARY")" == "$DEFAULT_NDJSON" \
      && "$(jq -r .brokered_session_observed "$LATEST_SUMMARY")" == "true" \
      && "$(jq -r .launch_timing.child_spawn_elapsed_ms "$LATEST_SUMMARY")" != "null" ]]; then
    echo "  ✓ status-latest selected the default managed status artifact"
else
    echo "  ✗ status-latest did not summarize the default status artifact" >&2
    cat "$LATEST_SUMMARY" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: malformed raw run fails helpfully"
BAD_ERR="$TMP/bad-run.stderr"
BAD_REPORT="$TMP/bad-run.report"
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_STATE_DIR="$STATE_DIR" \
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
