#!/usr/bin/env bash
# Diagnostic UX smoke for first-class `oauth-mux codex ...` adapter entrypoints.
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
    if [[ -n "${SQLITE_LOCK_PID:-}" ]]; then
        kill "$SQLITE_LOCK_PID" 2>/dev/null || true
        wait "$SQLITE_LOCK_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/account-A" "$TMP/account-B" "$TMP/claude-personal" "$STATE_DIR" "$CANONICAL_SESSION_HOME/sessions/2026/05/06" "$CANONICAL_SESSION_HOME/shell_snapshots"
touch "$CANONICAL_SESSION_HOME/history.jsonl" "$CANONICAL_SESSION_HOME/session_index.jsonl"
printf '%s\n' '{"fixture":"resume"}' >"$CANONICAL_SESSION_HOME/sessions/2026/05/06/rollout-managed-good-session.jsonl"
printf '%s\n' '{"bridge":"preexisting"}' >"$CANONICAL_SESSION_HOME/sessions/omux-session-bridge-smoke.jsonl"
printf '%s\n' 'managed-good-session' >"$CANONICAL_SESSION_HOME/state_5.sqlite"
printf '%s\n' 'managed-good-session-wal' >"$CANONICAL_SESSION_HOME/state_5.sqlite-wal"
printf '%s\n' 'managed-good-session-shm' >"$CANONICAL_SESSION_HOME/state_5.sqlite-shm"
printf '%s\n' 'managed-good-session' >"$CANONICAL_SESSION_HOME/logs_2.sqlite"
printf '%s\n' 'managed-good-session-logs-wal' >"$CANONICAL_SESSION_HOME/logs_2.sqlite-wal"
printf '%s\n' 'managed-good-session-logs-shm' >"$CANONICAL_SESSION_HOME/logs_2.sqlite-shm"
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
url = "https://figma.invalid/mcp"
bearer_token_env_var = "FIGMA_ACCESS_TOKEN"
command = "figma-mcp"

[mcp_servers.linear]
url = "https://mcp.linear.app/mcp"
bearer_token_env_var = "LINEAR_API_KEY"

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

[tui.model_availability_nux]
"gpt-5.5" = 2
EOF

ID_TOKEN="h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.s"
cat >"$TMP/account-A/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cli-ux-A","refresh_token":"RT-A","account_id":"acc-A-id"},"auth_mode":"Chatgpt"}
EOF
cat >"$TMP/account-B/auth.json" <<EOF
{"OPENAI_API_KEY":null,"tokens":{"id_token":"$ID_TOKEN","access_token":"AT-cli-ux-B","refresh_token":"RT-B","account_id":"acc-B-id"},"auth_mode":"Chatgpt"}
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
      OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
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
    assert_grep "$label canonical sqlite authority" '"sqlite_authority":"canonical_env"' "$ndjson"
    assert_grep "$label config passthrough status" '"config_passthrough":true,"user_config_present":true' "$ndjson"
    assert_grep "$label config layout" '"config_layout":"root_partitioned"' "$ndjson"
    assert_grep "$label experimental defaults injected" '"experimental_feature_defaults_injected":4' "$ndjson"
    assert_grep "$label mcp stdio schema guard" '"mcp_stdio_unsupported_fields_removed":2' "$ndjson"
    assert_grep "$label no pre-spawn network refresh" '"pre_spawn_network_refresh":false' "$ndjson"
    assert_grep "$label child spawn timing" '"kind":"launch_timing".*"phase":"child_spawn"' "$ndjson"
    assert_grep "$label resume preflight" '"kind":"resume_preflight"' "$ndjson"
    if [[ "$label" == "resume-chooser" ]]; then
        assert_grep "$label resume authority check" '"kind":"resume_authority_check".*"ok":true' "$ndjson"
        assert_grep "$label state db authority" '"kind":"resume_authority_check".*"resume_authority_state_db_bridged":true' "$ndjson"
        assert_grep "$label logs db authority" '"kind":"resume_authority_check".*"resume_authority_logs_db_bridged":true' "$ndjson"
        assert_grep "$label legacy provider namespace diagnostic" '"kind":"resume_authority_check".*"legacy_provider_namespace_detected":false.*"legacy_provider_namespace_repair":"operator_explicit_backup_required"' "$ndjson"
        assert_grep "$label no chooser rollout scan before spawn" '"kind":"resume_preflight".*"mode":"chooser".*"rollouts_before":0' "$ndjson"
        assert_grep "$label chooser lookup not scanned" '"kind":"resume_preflight".*"mode":"chooser".*"resume_lookup_source":"not_scanned"' "$ndjson"
        assert_grep "$label resume writeback" '"kind":"resume_writeback".*"mode":"chooser"' "$ndjson"
    elif [[ "$label" == "resume-id" ]]; then
        assert_grep "$label explicit state-db lookup" '"kind":"resume_preflight".*"mode":"explicit".*"resume_lookup_source":"state_db"' "$ndjson"
        assert_grep "$label resume writeback" '"kind":"resume_writeback".*"changed_existing":[1-9]' "$ndjson"
    else
        assert_grep "$label lookup not scanned" '"kind":"resume_preflight".*"resume_lookup_source":"not_scanned"' "$ndjson"
        assert_grep "$label resume writeback" '"kind":"resume_writeback"' "$ndjson"
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
          && "$(jq -r .session_bridge.shell_snapshots_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.state_db_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.state_db_wal_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.state_db_shm_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.logs_db_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.logs_db_wal_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.logs_db_shm_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.sqlite_home_env_set "$report")" == "true" \
          && "$(jq -r .session_bridge.sqlite_home_samefile "$report")" == "true" \
          && "$(jq -r .session_bridge.sqlite_home_path_printed "$report")" == "false" ]]; then
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

    if [[ "$(jq -r .config.native_provider_namespace "$report")" == "true" \
          && "$(jq -r .config.proxy_base_url_present "$report")" == "true" \
          && "$(jq -r .config.shadow_mux_provider_absent "$report")" == "true" \
          && "$(jq -r .config.user_feature_apps "$report")" == "true" \
          && "$(jq -r .config.user_feature_memories "$report")" == "true" \
          && "$(jq -r .config.user_feature_multi_agent "$report")" == "true" \
          && "$(jq -r .config.managed_feature_terminal_resize_reflow "$report")" == "true" \
          && "$(jq -r .config.managed_feature_external_migration "$report")" == "true" \
          && "$(jq -r .config.managed_feature_goals "$report")" == "true" \
          && "$(jq -r .config.managed_feature_prevent_idle_sleep "$report")" == "true" \
          && "$(jq -r .config.user_experimental_legacy "$report")" == "true" \
          && "$(jq -r .config.user_tui_model_availability_nux "$report")" == "true" \
          && "$(jq -r .config.config_layout_root_partitioned "$report")" == "true" \
          && "$(jq -r .config.user_mcp_server "$report")" == "true" \
          && "$(jq -r .config.stdio_mcp_remote_fields_absent "$report")" == "true" \
          && "$(jq -r .config.http_mcp_remote_fields_preserved "$report")" == "true" \
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

echo "smoke-codex-cli-ux: isolated session store keeps sqlite authority local"
ISOLATED_NDJSON="$TMP/isolated-status.ndjson"
ISOLATED_STDERR="$TMP/isolated.stderr"
ISOLATED_REPORT="$TMP/isolated.report"
env \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  CODEX_SQLITE_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CODEX_TURNS=0 \
  OMUX_STUB_CODEX_REPORT="$ISOLATED_REPORT" \
  "$BIN" codex --profile codex-max --isolated-session-store --json-status-file "$ISOLATED_NDJSON" resume --last 2>"$ISOLATED_STDERR"
assert_grep "isolated session authority" '"kind":"session_started".*"session_authority":"isolated"' "$ISOLATED_NDJSON"
assert_grep "isolated sqlite authority" '"kind":"session_started".*"sqlite_authority":"isolated_overlay"' "$ISOLATED_NDJSON"
if [[ "$(jq -r .sqlite_env.codex_sqlite_home_env_set "$ISOLATED_REPORT")" == "false" \
      && "$(jq -r .sqlite_env.path_printed "$ISOLATED_REPORT")" == "false" ]]; then
    echo "  ✓ isolated run scrubbed inherited CODEX_SQLITE_HOME"
else
    echo "  ✗ isolated run leaked CODEX_SQLITE_HOME" >&2
    cat "$ISOLATED_REPORT" >&2
    exit 1
fi

echo "smoke-codex-cli-ux: capability-scoped route election matches broker-session-plan"
MIXED_CONFIG="$TMP/mixed-capability.config.json"
MIXED_STATE="$TMP/mixed-capability-state"
mkdir -p "$MIXED_STATE"
cat >"$MIXED_CONFIG" <<EOF
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
    "mixed": { "providers": ["codex:max-1#codex-mini", "codex:max-1#codex-max", "codex:max-2#codex-max"] }
  }
}
EOF
cat >"$MIXED_STATE/health.json" <<'EOF'
{"version":2,"accounts":[
  {"key":"codex:max-1#codex-mini","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}},
  {"key":"codex:max-1#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"quota_exhausted","last_probe_decision":"try_next_account","liveness":{"state":"live","availability":"quota_exhausted","window_resets_at":1999999999}},
  {"key":"codex:max-2#codex-max","last_probe_source":"capability_probe","last_probe_hint_class":"none","last_probe_decision":"use_this","liveness":{"state":"live","availability":"available"}}
]}
EOF
MIXED_NDJSON="$TMP/mixed-capability/status.ndjson"
MIXED_STDERR="$TMP/mixed-capability.stderr"
MIXED_REPORT="$TMP/mixed-capability.report"
mkdir -p "$(dirname "$MIXED_NDJSON")"
OMUX_CONFIG="$MIXED_CONFIG" \
  OMUX_STATE_DIR="$MIXED_STATE" \
  OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_CANONICAL_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_STUB_APPEND_SESSION="sessions/2026/05/06/rollout-managed-good-session.jsonl" \
  OMUX_STUB_CODEX_TURNS=0 \
  OMUX_STUB_CODEX_REPORT="$MIXED_REPORT" \
  "$BIN" codex --profile mixed --capability codex-max --json-status-file "$MIXED_NDJSON" resume --last 2>"$MIXED_STDERR"
assert_grep "mixed capability selected max-2" '"kind":"session_started".*"selected_account":"codex:max-2"' "$MIXED_NDJSON"
if [[ "$(jq -r .active_account_at_start "$MIXED_REPORT")" == "max-2" ]]; then
    echo "  ✓ mixed capability launch used the codex-max selectable route"
else
    echo "  ✗ mixed capability launch used wrong account" >&2
    cat "$MIXED_REPORT" >&2
    exit 1
fi

PINNED_BLOCKED_NDJSON="$TMP/pinned-blocked/status.ndjson"
PINNED_BLOCKED_STDERR="$TMP/pinned-blocked.stderr"
PINNED_BLOCKED_REPORT="$TMP/pinned-blocked.report"
mkdir -p "$(dirname "$PINNED_BLOCKED_NDJSON")"
if OMUX_CONFIG="$MIXED_CONFIG" \
     OMUX_STATE_DIR="$MIXED_STATE" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     CODEX_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$PINNED_BLOCKED_REPORT" \
     "$BIN" codex --profile mixed --capability codex-max --account codex:max-1 --json-status-file "$PINNED_BLOCKED_NDJSON" resume --last 2>"$PINNED_BLOCKED_STDERR"; then
    echo "  ✗ pinned quota-blocked account unexpectedly launched" >&2
    exit 1
fi
assert_grep "pinned blocked terminal status" '"kind":"session_aborted".*"reason":"no_account_selectable".*"phase":"route_election".*"pre_spawn":true.*"child_spawned":false' "$PINNED_BLOCKED_NDJSON"
assert_grep "pinned blocked stderr" 'is not selectable for the requested profile/capability' "$PINNED_BLOCKED_STDERR"
if [[ -e "$PINNED_BLOCKED_REPORT" ]]; then
    echo "  ✗ pinned quota-blocked account launched stub unexpectedly" >&2
    cat "$PINNED_BLOCKED_REPORT" >&2
    exit 1
else
    echo "  ✓ pinned quota-blocked account fails before child spawn"
fi

AMBIGUOUS_NDJSON="$TMP/ambiguous-capability/status.ndjson"
AMBIGUOUS_STDERR="$TMP/ambiguous-capability.stderr"
AMBIGUOUS_REPORT="$TMP/ambiguous-capability.report"
mkdir -p "$(dirname "$AMBIGUOUS_NDJSON")"
if OMUX_CONFIG="$MIXED_CONFIG" \
     OMUX_STATE_DIR="$MIXED_STATE" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     CODEX_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$AMBIGUOUS_REPORT" \
     "$BIN" codex --profile mixed --json-status-file "$AMBIGUOUS_NDJSON" resume --last 2>"$AMBIGUOUS_STDERR"; then
    echo "  ✗ ambiguous mixed-capability profile unexpectedly launched" >&2
    exit 1
fi
assert_grep "ambiguous capability terminal status" '"kind":"session_aborted".*"reason":"no_account_selectable".*"phase":"route_election".*"pre_spawn":true.*"child_spawned":false' "$AMBIGUOUS_NDJSON"
assert_grep "ambiguous capability stderr" 'pass --capability for managed launch' "$AMBIGUOUS_STDERR"
if [[ -e "$AMBIGUOUS_REPORT" ]]; then
    echo "  ✗ ambiguous mixed-capability profile launched stub unexpectedly" >&2
    cat "$AMBIGUOUS_REPORT" >&2
    exit 1
else
    echo "  ✓ ambiguous mixed-capability profile fails before child spawn"
fi

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
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CANONICAL_SESSION_HOME="$BAD_AUTHORITY_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$BAD_AUTHORITY_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$BAD_AUTHORITY_NDJSON" resume 2>"$BAD_AUTHORITY_STDERR"; then
    echo "  ✗ missing authority chooser unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "missing authority diagnostic status" '"kind":"resume_authority_check".*"ok":false' "$BAD_AUTHORITY_NDJSON"
assert_grep "missing authority terminal status" '"kind":"session_aborted".*"reason":"session_authority_unavailable".*"phase":"resume_authority_check".*"pre_spawn":true.*"child_spawned":false' "$BAD_AUTHORITY_NDJSON"
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

echo "smoke-codex-cli-ux: locked canonical sqlite authority fails before spawn"
SQLITE_AUTH_LOCK_NDJSON="$TMP/sqlite-authority-lock/status.ndjson"
SQLITE_AUTH_LOCK_STDERR="$TMP/sqlite-authority-lock.stderr"
SQLITE_AUTH_LOCK_REPORT="$TMP/sqlite-authority-lock.report"
SQLITE_AUTH_LOCK_HEALTH_BEFORE="$TMP/sqlite-authority-lock.health.before"
SQLITE_LOCK_READY="$TMP/sqlite-authority-lock.ready"
SQLITE_LOCK_RELEASE="$TMP/sqlite-authority-lock.release"
mkdir -p "$(dirname "$SQLITE_AUTH_LOCK_NDJSON")"
cp "$STATE_DIR/health.json" "$SQLITE_AUTH_LOCK_HEALTH_BEFORE"
python3 - "$CANONICAL_SESSION_HOME/state_5.sqlite" "$SQLITE_LOCK_READY" "$SQLITE_LOCK_RELEASE" <<'PY' &
import fcntl
import os
import pathlib
import sys
import time

db = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
release = pathlib.Path(sys.argv[3])
fd = os.open(db, os.O_RDWR)
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 512, 0x40000000, os.SEEK_SET)
ready.write_text("ready\n", encoding="utf-8")
try:
    while not release.exists():
        time.sleep(0.05)
finally:
    os.close(fd)
PY
SQLITE_LOCK_PID=$!
for _ in $(seq 1 100); do
    if [[ -e "$SQLITE_LOCK_READY" ]]; then
        break
    fi
    if ! kill -0 "$SQLITE_LOCK_PID" 2>/dev/null; then
        echo "  ✗ sqlite lock helper exited before ready" >&2
        wait "$SQLITE_LOCK_PID" || true
        exit 1
    fi
    sleep 0.05
done
if [[ ! -e "$SQLITE_LOCK_READY" ]]; then
    echo "  ✗ sqlite lock helper did not become ready" >&2
    exit 1
fi
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_STATE_DIR="$STATE_DIR" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     CODEX_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_REPORT="$SQLITE_AUTH_LOCK_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$SQLITE_AUTH_LOCK_NDJSON" resume 2>"$SQLITE_AUTH_LOCK_STDERR"; then
    echo "  ✗ locked sqlite authority unexpectedly launched" >&2
    exit 1
fi
touch "$SQLITE_LOCK_RELEASE"
wait "$SQLITE_LOCK_PID"
SQLITE_LOCK_PID=""
assert_grep "sqlite authority lock diagnostic" '"kind":"sqlite_authority_check".*"ok":false.*"diagnostic":"database_locked".*"db_basename":"state_5.sqlite".*"sqlite_error_class":"database_locked".*"sqlite_error_code":5' "$SQLITE_AUTH_LOCK_NDJSON"
assert_grep "sqlite authority lock owner pid" '"kind":"sqlite_authority_check".*"lock_owner_pid":[0-9]+' "$SQLITE_AUTH_LOCK_NDJSON"
assert_grep "sqlite authority lock owner pid printed" '"kind":"sqlite_authority_check".*"lock_owner_pid_printed":true' "$SQLITE_AUTH_LOCK_NDJSON"
assert_grep "sqlite authority lock terminal status" '"kind":"session_aborted".*"reason":"session_authority_locked".*"phase":"sqlite_authority_check".*"pre_spawn":true.*"child_spawned":false' "$SQLITE_AUTH_LOCK_NDJSON"
assert_grep "sqlite authority lock stderr" 'canonical Codex sqlite state is locked by another Codex process \(pid [0-9]+\)' "$SQLITE_AUTH_LOCK_STDERR"
if [[ -e "$SQLITE_AUTH_LOCK_REPORT" ]]; then
    echo "  ✗ locked sqlite authority launched stub unexpectedly" >&2
    cat "$SQLITE_AUTH_LOCK_REPORT" >&2
    exit 1
fi
if ! cmp -s "$STATE_DIR/health.json" "$SQLITE_AUTH_LOCK_HEALTH_BEFORE"; then
    echo "  ✗ locked sqlite authority mutated route health" >&2
    diff -u "$SQLITE_AUTH_LOCK_HEALTH_BEFORE" "$STATE_DIR/health.json" >&2 || true
    exit 1
fi
if grep -q -E 'managed-good-session|'"$CANONICAL_SESSION_HOME" "$SQLITE_AUTH_LOCK_NDJSON" "$SQLITE_AUTH_LOCK_STDERR"; then
    echo "  ✗ locked sqlite authority leaked path or session id" >&2
    cat "$SQLITE_AUTH_LOCK_NDJSON" >&2
    cat "$SQLITE_AUTH_LOCK_STDERR" >&2
    exit 1
fi
echo "  ✓ locked canonical sqlite authority fails before child spawn"

echo "smoke-codex-cli-ux: sqlite lock shaped child startup failure records abort"
SQLITE_LOCK_NDJSON="$TMP/sqlite-lock/status.ndjson"
SQLITE_LOCK_STDERR="$TMP/sqlite-lock.stderr"
SQLITE_LOCK_REPORT="$TMP/sqlite-lock.report"
SQLITE_LOCK_HEALTH_BEFORE="$TMP/sqlite-lock.health.before"
mkdir -p "$(dirname "$SQLITE_LOCK_NDJSON")"
cp "$STATE_DIR/health.json" "$SQLITE_LOCK_HEALTH_BEFORE"
if OMUX_CONFIG="$TMP/oauth-mux.config.json" \
     OMUX_STATE_DIR="$STATE_DIR" \
     OMUX_CODEX_BIN="$ROOT/scripts/test-stub-codex.py" \
     CODEX_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_FAIL_MODE="sqlite_locked" \
     OMUX_STUB_CODEX_REPORT="$SQLITE_LOCK_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$SQLITE_LOCK_NDJSON" resume 2>"$SQLITE_LOCK_STDERR"; then
    echo "  ✗ sqlite lock failure unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "sqlite lock session started" '"kind":"session_started".*"sqlite_authority":"canonical_env"' "$SQLITE_LOCK_NDJSON"
assert_grep "sqlite lock terminal abort status" '"kind":"session_aborted".*"reason":"child_exit_nonzero".*"exit_code":1.*"term_kind":"exited".*"term_code":1' "$SQLITE_LOCK_NDJSON"
assert_grep "sqlite lock stderr preserved" 'database is locked' "$SQLITE_LOCK_STDERR"
if grep -q '"kind":"session_ended"' "$SQLITE_LOCK_NDJSON"; then
    echo "  ✗ sqlite lock failure was recorded as a normal session end" >&2
    cat "$SQLITE_LOCK_NDJSON" >&2
    exit 1
fi
if [[ -e "$SQLITE_LOCK_REPORT" ]]; then
    echo "  ✗ sqlite lock startup failure wrote a normal stub report unexpectedly" >&2
    cat "$SQLITE_LOCK_REPORT" >&2
    exit 1
fi
if ! cmp -s "$STATE_DIR/health.json" "$SQLITE_LOCK_HEALTH_BEFORE"; then
    echo "  ✗ sqlite lock failure mutated route health" >&2
    diff -u "$SQLITE_LOCK_HEALTH_BEFORE" "$STATE_DIR/health.json" >&2 || true
    exit 1
fi
if grep -q -E 'managed-good-session|'"$CANONICAL_SESSION_HOME" "$SQLITE_LOCK_NDJSON"; then
    echo "  ✗ sqlite lock status leaked path or session id" >&2
    cat "$SQLITE_LOCK_NDJSON" >&2
    exit 1
fi
echo "  ✓ sqlite lock shaped startup failure records abort without route-health mutation"

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
     OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
     OMUX_STUB_CODEX_TURNS=0 \
     OMUX_STUB_CODEX_REPORT="$BAD_CONFIG_REPORT" \
     "$BIN" codex --profile codex-max --json-status-file "$BAD_CONFIG_NDJSON" -- --config 'model_provider="openai"' 2>"$BAD_CONFIG_STDERR"; then
    echo "  ✗ forwarded config provider override unexpectedly succeeded" >&2
    exit 1
fi
assert_grep "config override diagnostic status" '"kind":"config_passthrough_check".*"ok":false.*"model_provider_override":true' "$BAD_CONFIG_NDJSON"
assert_grep "config override terminal status" '"kind":"session_aborted".*"reason":"config_override_unavailable".*"phase":"config_passthrough_check".*"pre_spawn":true.*"child_spawned":false' "$BAD_CONFIG_NDJSON"
assert_grep "config override failed before child spawn" 'forwarded Codex --config attempts to override managed provider settings' "$BAD_CONFIG_STDERR"
if [[ -e "$BAD_CONFIG_REPORT" ]]; then
    echo "  ✗ config override launched stub unexpectedly" >&2
    cat "$BAD_CONFIG_REPORT" >&2
    exit 1
else
    echo "  ✓ config override fails before child spawn"
fi
if grep -q -E 'model_provider="openai"|profile_provider|https://example.invalid|'"$CANONICAL_SESSION_HOME" "$BAD_CONFIG_NDJSON" "$BAD_CONFIG_STDERR"; then
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
env -u OMUX_CODEX_BIN \
  PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
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

echo "smoke-codex-cli-ux: local dogfood install keeps native codex unshadowed by default"
DOGFOOD_BIN="$TMP/dogfood-bin"
DOGFOOD_TOOL_STUBS="$TMP/dogfood-tool-stubs"
NATIVE_CODEX_DIR="$TMP/native-codex-bin"
NATIVE_CODEX="$NATIVE_CODEX_DIR/codex"
NATIVE_REPORT="$TMP/native-codex.report"
NATIVE_STDOUT="$TMP/native-codex.stdout"
SHIM_TRACE="$TMP/shim-trace.ndjson"
mkdir -p "$DOGFOOD_BIN" "$DOGFOOD_TOOL_STUBS" "$NATIVE_CODEX_DIR"
cat >"$NATIVE_CODEX" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${OMUX_NATIVE_CODEX_REPORT:-}" ]]; then
    printf '%s\n' "$@" >"$OMUX_NATIVE_CODEX_REPORT"
fi
case "${1:-}" in
    --version|-V|version)
        printf '%s\n' 'codex-cli-native-stub 0.0.0'
        ;;
    login)
        printf '%s\n' 'native-login-stub'
        ;;
    *)
        printf '%s\n' 'native-codex-stub'
        ;;
esac
EOF
chmod 0755 "$NATIVE_CODEX"

cat >"$DOGFOOD_TOOL_STUBS/lsof" <<'EOF'
#!/usr/bin/env bash
case " $* " in
    *" 4242 "*)
        printf '%s\n' 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME'
        printf '%s\n' 'oauth-mux 4242 test   7u  IPv4      0      0t0  TCP 127.0.0.1:57257 (LISTEN)'
        ;;
    *" 4243 "*)
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod 0755 "$DOGFOOD_TOOL_STUBS/lsof"

write_dogfood_ps_stub() {
    local mode="$1"
    if [[ "$mode" == "active" ]]; then
        cat >"$DOGFOOD_TOOL_STUBS/ps" <<EOF
#!/usr/bin/env bash
cat <<'PSROWS'
 4242     1 $DOGFOOD_BIN/oauth-mux codex resume --last
 4243  4242 $NATIVE_CODEX resume --last
 5252     1 /usr/bin/zsh
PSROWS
EOF
    else
        cat >"$DOGFOOD_TOOL_STUBS/ps" <<'EOF'
#!/usr/bin/env bash
cat <<'PSROWS'
 5252     1 /usr/bin/zsh
PSROWS
EOF
    fi
    chmod 0755 "$DOGFOOD_TOOL_STUBS/ps"
}

write_dogfood_ps_stub active
if PATH="$DOGFOOD_TOOL_STUBS:$PATH" \
  INSTALL_DIR="$DOGFOOD_BIN" \
  OMUX_DOGFOOD_SKIP_BUILD=1 \
  OMUX_CODEX_BIN="$NATIVE_CODEX" \
  "$ROOT/scripts/install-local-dogfood.sh" >"$TMP/dogfood-install-active.stdout" 2>"$TMP/dogfood-install-active.stderr"; then
    echo "  ✗ default local dogfood install ignored active managed Codex sessions" >&2
    cat "$TMP/dogfood-install-active.stdout" >&2
    cat "$TMP/dogfood-install-active.stderr" >&2
    exit 1
fi
test ! -e "$DOGFOOD_BIN/oauth-mux"
assert_grep "active-session guard refused install" 'status: active_session_guard_failed' "$TMP/dogfood-install-active.stderr"
assert_grep "active-session guard reported parent" 'pid=4242 .*role=oauth_mux_codex_parent.*listener_ports=57257' "$TMP/dogfood-install-active.stderr"
assert_grep "active-session guard reported child" 'pid=4243 .*role=managed_codex_child' "$TMP/dogfood-install-active.stderr"
assert_grep "active-session guard prints explicit force" 'OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1' "$TMP/dogfood-install-active.stderr"
echo "  ✓ default local dogfood install refuses while managed Codex sessions are visible"

PATH="$DOGFOOD_TOOL_STUBS:$PATH" \
  INSTALL_DIR="$DOGFOOD_BIN" \
  OMUX_DOGFOOD_SKIP_BUILD=1 \
  OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1 \
  OMUX_CODEX_BIN="$NATIVE_CODEX" \
  "$ROOT/scripts/install-local-dogfood.sh" >"$TMP/dogfood-install-force.stdout" 2>"$TMP/dogfood-install-force.stderr"
test -x "$DOGFOOD_BIN/oauth-mux"
assert_grep "active-session force reports active state" 'active managed Codex sessions before install: force-allowed' "$TMP/dogfood-install-force.stderr"
assert_grep "force install verifies version" 'oauth-mux version:' "$TMP/dogfood-install-force.stdout"
rm -f "$DOGFOOD_BIN/oauth-mux"
echo "  ✓ explicit force allows local dogfood install with an active-session report"

write_dogfood_ps_stub inactive
INSTALL_DIR="$DOGFOOD_BIN" \
  PATH="$DOGFOOD_TOOL_STUBS:$PATH" \
  OMUX_DOGFOOD_SKIP_BUILD=1 \
  OMUX_CODEX_BIN="$NATIVE_CODEX" \
  "$ROOT/scripts/install-local-dogfood.sh" >"$TMP/dogfood-install.stdout"
test -x "$DOGFOOD_BIN/oauth-mux"
assert_grep "default install reports no active managed sessions" 'active managed Codex sessions before install: none' "$TMP/dogfood-install.stdout"
if [[ -e "$DOGFOOD_BIN/codex" ]]; then
    echo "  ✗ default local dogfood install unexpectedly created a codex shim" >&2
    cat "$TMP/dogfood-install.stdout" >&2
    exit 1
else
    echo "  ✓ default local dogfood install did not shadow codex"
fi

echo "smoke-codex-cli-ux: managed codex shim opt-in passes native admin commands through"
INSTALL_DIR="$DOGFOOD_BIN" \
  PATH="$DOGFOOD_TOOL_STUBS:$PATH" \
  OMUX_DOGFOOD_SKIP_BUILD=1 \
  OMUX_DOGFOOD_INSTALL_CODEX_SHIM=1 \
  OMUX_CODEX_BIN="$NATIVE_CODEX" \
  "$ROOT/scripts/install-local-dogfood.sh" >"$TMP/dogfood-install-shim.stdout"

OMUX_CODEX_BIN="$NATIVE_CODEX" \
  OMUX_NATIVE_CODEX_REPORT="$NATIVE_REPORT" \
  OMUX_TRACE=1 \
  OMUX_TRACE_FILE="$SHIM_TRACE" \
  OMUX_TRACE_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  OMUX_SPAN_ID="bbbbbbbbbbbbbbbb" \
  "$DOGFOOD_BIN/codex" --version >"$NATIVE_STDOUT"
assert_grep "shim --version used native codex" 'codex-cli-native-stub' "$NATIVE_STDOUT"
assert_grep "shim --version argv recorded by native" '^--version$' "$NATIVE_REPORT"
jq -e 'select(.name == "codex.shim.pass_through" and .attributes.first_arg == "--version" and .attributes.native_binary_path_printed == false and .redaction.paths == false)' "$SHIM_TRACE" >/dev/null
echo "  ✓ shim --version emitted redacted pass-through trace"

rm -f "$NATIVE_REPORT" "$NATIVE_STDOUT"
XDG_DATA_HOME="$TMP/native-xdg" \
  OMUX_CODEX_BIN="$NATIVE_CODEX" \
  OMUX_NATIVE_CODEX_REPORT="$NATIVE_REPORT" \
  OMUX_TRACE=1 \
  OMUX_TRACE_FILE="$SHIM_TRACE" \
  "$DOGFOOD_BIN/codex" login --help >"$NATIVE_STDOUT"
assert_grep "shim login used native codex" 'native-login-stub' "$NATIVE_STDOUT"
assert_grep "shim login argv recorded by native" '^login$' "$NATIVE_REPORT"
assert_grep "shim login help argv recorded by native" '^--help$' "$NATIVE_REPORT"
jq -e 'select(.name == "codex.shim.pass_through" and .attributes.first_arg == "login" and .attributes.native_binary_path_printed == false and .redaction.tokens == false)' "$SHIM_TRACE" >/dev/null
echo "  ✓ shim login emitted redacted pass-through trace"
if [[ -e "$TMP/native-xdg/oauth-mux/codex/max-1" ]]; then
    echo "  ✗ shim login created mux account directory instead of passing through native Codex" >&2
    find "$TMP/native-xdg" -maxdepth 4 -print >&2 || true
    exit 1
else
    echo "  ✓ shim login did not bootstrap mux account dirs"
fi
INSTALL_DIR="$DOGFOOD_BIN" "$ROOT/scripts/uninstall-local-dogfood.sh" >"$TMP/dogfood-uninstall.stdout"
test ! -e "$DOGFOOD_BIN/oauth-mux"
test ! -e "$DOGFOOD_BIN/codex"
echo "  ✓ local dogfood uninstall removed only dogfood-managed files"

LOGIN_STATUS_JSON="$TMP/login-status-all.json"
LOGIN_STATUS_LEAKS="$TMP/login-status-all.leaks"
OMUX_CODEX_BIN="$NATIVE_CODEX" \
  "$BIN" codex login-status-all --accounts max-1,max-2 --store-root "$TMP/login-status-root" --json >"$LOGIN_STATUS_JSON"
jq -e '.mode == "codex_login_status_all"
       and .spends_provider_calls == false
       and .mutates_user_config == false
       and .interactive == false
       and .readiness_scope.native_login_status == true
       and .readiness_scope.route_liveness_considered == false
       and .readiness_scope.route_selectability_considered == false
       and .readiness_scope.native_login_status_clears_route_health == false
       and .ok == true
       and (.accounts | length == 2)
       and all(.accounts[];
           .authenticated == true
           and .status == "logged_in"
           and .codex_home_path_printed == false
           and .native_output_printed == false
           and .route_liveness_considered == false
           and .route_selectability_considered == false
           and .native_login_status_clears_route_health == false)' "$LOGIN_STATUS_JSON" >/dev/null
if grep -E 'CODEX_HOME=|native-login-stub|/oauth-mux/codex|max-1/auth.json' "$LOGIN_STATUS_JSON" >"$LOGIN_STATUS_LEAKS"; then
    echo "  ✗ login-status-all --json leaked native text or paths" >&2
    cat "$LOGIN_STATUS_JSON" >&2
    exit 1
else
    echo "  ✓ login-status-all --json is redacted structured inspection"
fi

echo "smoke-codex-cli-ux: no-profile codex election is provider-scoped"
NO_PROFILE_NDJSON="$TMP/no-profile/status.ndjson"
NO_PROFILE_STDERR="$TMP/no-profile.stderr"
NO_PROFILE_REPORT="$TMP/no-profile.report"
mkdir -p "$(dirname "$NO_PROFILE_NDJSON")"
env -u OMUX_CODEX_BIN \
  PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
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
env -u OMUX_CODEX_BIN \
  PATH="$PATH_STUB_DIR:$PATH" \
  OMUX_CONFIG="$TMP/oauth-mux.config.json" \
  OMUX_STATE_DIR="$STATE_DIR" \
  CODEX_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_SESSION_HOME="$CANONICAL_SESSION_HOME" \
  OMUX_CODEX_CONFIG_HOME="$CANONICAL_SESSION_HOME" \
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
