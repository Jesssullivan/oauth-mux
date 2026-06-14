#!/usr/bin/env bash
# Synthetic Claude-shaped broker MCP smoke.
#
# Anchor: GitHub #68 / TIN-736 and
# docs/spec/provider-proof-claude-command-auth-2026-05-01.md.
#
# This is not a Claude stay-afloat proof. It proves the generic broker MCP
# account/session/error contract works for a non-Codex command-adapter route,
# and that Codex-only credential shapes are refused before Claude stores are
# touched.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-broker-claude: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build-local" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-broker-claude: jq required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-smoke-broker-claude.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/state" "$TMP/claude-work" "$TMP/claude-personal"

cat >"$TMP/state/health.json" <<'EOF'
{
  "version": 2,
  "accounts": [
    {
      "key": "claude:work#auth-status",
      "liveness": { "state": "live", "availability": "available" },
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this"
    },
    {
      "key": "claude:personal#auth-status",
      "liveness": { "state": "live", "availability": "available" },
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this"
    }
  ]
}
EOF

cat >"$TMP/config.json" <<EOF
{
  "version": 1,
  "providers": {
    "claude": {
      "kind": "claude",
      "accounts": {
        "work": {
          "priority": 20,
          "config_dir": "$TMP/claude-work",
          "secret": { "backend": "file", "path": "$TMP/claude-work/.credentials.json" }
        },
        "personal": {
          "priority": 10,
          "config_dir": "$TMP/claude-personal",
          "secret": { "backend": "file", "path": "$TMP/claude-personal/.credentials.json" }
        }
      }
    }
  },
  "profiles": {
    "claude": {
      "providers": ["claude:work#auth-status", "claude:personal#auth-status"]
    }
  }
}
EOF

coproc BROKER { OMUX_CONFIG="$TMP/config.json" OMUX_STATE_DIR="$TMP/state" "$BIN" mcp --profile claude --capability auth-status 2>"$TMP/stderr.log"; }
BROKER_OUT=${BROKER[0]}
BROKER_IN=${BROKER[1]}

cleanup_broker() {
    exec {BROKER_IN}>&- 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
}
trap 'cleanup_broker; rm -rf "$TMP"' EXIT

send_rpc() {
    local payload=$1
    printf '%s\n' "$payload" >&"$BROKER_IN"
    local response
    IFS= read -r response <&"$BROKER_OUT"
    printf '%s\n' "$response"
}

assert_eq() {
    local label=$1 expected=$2 actual=$3
    if [[ "$expected" != "$actual" ]]; then
        echo "smoke-broker-claude: FAIL [$label] expected=$expected actual=$actual" >&2
        echo "--- broker stderr ---" >&2
        cat "$TMP/stderr.log" >&2 || true
        exit 1
    fi
    echo "  ✓ $label"
}

# Discovery remains transport-honest.
r=$(send_rpc '{"jsonrpc":"2.0","id":1,"method":"surface/info"}')
assert_eq "surface/info.transports[0]" "stdio" "$(echo "$r" | jq -r .result.transports[0])"
assert_eq "surface/info.daemon_hosts_broker" "false" "$(echo "$r" | jq -r .result.transport_detail.daemon_hosts_broker)"
assert_eq "surface/info.credential_materialize_scope" "adapter_stdio_only" "$(echo "$r" | jq -r .result.capabilities_detail.credential_materialize_scope)"

# Claude-shaped adapter handshake.
r=$(send_rpc '{"jsonrpc":"2.0","id":2,"method":"surface/handshake","params":{"adapter":"claude-smoke","adapter_version":"0","harness_target":"claude","session_pid":1}}')
sid_present=$(echo "$r" | jq -r '.result.session_id | length > 0')
assert_eq "surface/handshake.session_id present" "true" "$sid_present"
assert_eq "surface/handshake.claim_floor" "broker_owned" "$(echo "$r" | jq -r .result.claim_floor)"
sid="$(echo "$r" | jq -r .result.session_id)"

# Route-health-backed account visibility works for Claude-shaped routes.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:3,method:"account/list",params:{session_id:$sid,profile:"claude",capability:"auth-status"}}')")
assert_eq "account/list count" "2" "$(echo "$r" | jq -r '.result.accounts | length')"
assert_eq "account/list[0].id" "claude:work" "$(echo "$r" | jq -r .result.accounts[0].id)"
assert_eq "account/list[0].liveness" "live" "$(echo "$r" | jq -r .result.accounts[0].liveness)"
assert_eq "account/list[1].id" "claude:personal" "$(echo "$r" | jq -r .result.accounts[1].id)"

# Selection is generic broker-owned selection, not a Codex-only path.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:4,method:"account/select",params:{session_id:$sid,profile:"claude",capability:"auth-status"}}')")
assert_eq "account/select.account" "claude:work" "$(echo "$r" | jq -r .result.account)"
assert_eq "account/select.claim.level" "broker_owned" "$(echo "$r" | jq -r .result.claim.level)"
handle="$(echo "$r" | jq -r .result.credential_handle)"

# chatgpt_auth_tokens is Codex-only. A Claude route must fail by shape, before
# trying to parse Claude credential files or inventing a token bridge.
r=$(send_rpc "$(jq -nc --arg sid "$sid" --arg handle "$handle" '{jsonrpc:"2.0",id:5,method:"credential/materialize",params:{session_id:$sid,credential_handle:$handle,shape:"chatgpt_auth_tokens"}}')")
assert_eq "credential/materialize unsupported shape code" "-32015" "$(echo "$r" | jq -r .error.code)"

# Logged-out/unauthorized evidence makes the first account non-selectable.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:6,method:"quota/observe",params:{session_id:$sid,account:"claude:work",kind:"auth_unauthorized"}}')")
assert_eq "quota/observe.recorded" "true" "$(echo "$r" | jq -r .result.recorded)"
assert_eq "quota/observe.now_selectable" "false" "$(echo "$r" | jq -r .result.now_selectable)"

r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:7,method:"account/select",params:{session_id:$sid,profile:"claude",capability:"auth-status"}}')")
assert_eq "account/select-post-auth" "claude:personal" "$(echo "$r" | jq -r .result.account)"

# Exhausting the remaining Claude-shaped route returns typed no-account data
# with Claude-specific diagnostic commands. This is still only broker contract
# proof, not Claude model-call or quota handoff proof.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:8,method:"account/swap",params:{session_id:$sid,profile:"claude",capability:"auth-status",current_account:"claude:personal",reason:"auth_unauthorized",evidence:{http_status:401}}}')")
assert_eq "account/swap-no-replacement.error.code" "-32010" "$(echo "$r" | jq -r .error.code)"
assert_eq "account/swap-no-replacement.error_name" "no_account_selectable" "$(echo "$r" | jq -r .error.data.error_name)"
assert_eq "account/swap-no-replacement.dead_routes" "2" "$(echo "$r" | jq -r .error.data.rejection_summary.dead_routes)"
assert_eq "account/swap-no-replacement.first_action" "oauth-mux route explain --profile claude --capability auth-status --json" "$(echo "$r" | jq -r .error.data.agent_safe_next_actions[0])"

echo
echo "smoke-broker-claude: all assertions passed."
