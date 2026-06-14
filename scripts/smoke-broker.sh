#!/usr/bin/env bash
# Automated end-to-end smoke for oauth-mux mcp (broker MCP server).
#
# Anchor: docs/spec/broker-mcp-contract-2026-05-03.md.
# Replaces the prior manual `echo '{...}' | oauth-mux mcp` pipe
# documented in commit 3152898's body. This is the regression
# catch-net for the broker JSON-RPC dispatch path; it MUST stay
# green or Phase 2 acceptance is invalidated.
#
# Coverage (in order of issue):
#   1. surface/info        — basic dispatch + response writer round-trip
#   2. surface/handshake   — session minting + storage
#   3. account/list        — pool population + JSON shape
#   4. account/select      — election + opaque credential_handle
#   5. credential/materialize — chatgpt_auth_tokens shape, plan_type
#                              extraction from id_token JWT
#   6. quota/observe       — kind=quota_exhausted, resets_at, now_selectable
#   7. account/select again — proves prior account was actually marked
#                             non-selectable in the pool
#   8. account/swap        — replacement selection without premature
#                             next_turn_seamless promotion
#   9. quota/status        — pool snapshot reflects all prior mutations
#
# Exit 0 = all assertions pass. Exit non-zero = which step failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-broker: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build-local" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-broker: jq required" >&2
    exit 64
fi

# Tempdir + cleanup
TMP="$(mktemp -d -t omux-smoke-broker.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/state"

# A minimal codex auth.json shape so credential/materialize can resolve
# fixture token strings. id_token payload encodes plan_type=pro and
# chatgpt_account_is_fedramp=true so the JWT decoder is exercised.
cat >"$TMP/auth.json" <<'EOF'
{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s",
    "access_token": "AT-smoke-1",
    "refresh_token": "RT-smoke",
    "account_id": "acc-smoke-1"
  },
  "auth_mode": "Chatgpt"
}
EOF

cat >"$TMP/state/health.json" <<'EOF'
{
  "version": 2,
  "accounts": [
    {
      "key": "codex:max-1#codex-max",
      "liveness": { "state": "live", "availability": "available" },
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this"
    },
    {
      "key": "codex:max-2#codex-max",
      "liveness": { "state": "live", "availability": "available" },
      "last_probe_hint_class": "none",
      "last_probe_decision": "use_this"
    },
    {
      "key": "codex:max-3#codex-max",
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
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "$TMP/auth.json" } },
        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "$TMP/auth.json" } },
        "max-3": { "priority": 10, "secret": { "backend": "file", "path": "$TMP/auth.json" } }
      }
    }
  },
  "profiles": {
    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max", "codex:max-3#codex-max"] }
  }
}
EOF

coproc BROKER { OMUX_CONFIG="$TMP/config.json" OMUX_STATE_DIR="$TMP/state" "$BIN" mcp --profile codex-max --capability codex-max 2>"$TMP/stderr.log"; }
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
        echo "smoke-broker: FAIL [$label] expected=$expected actual=$actual" >&2
        exit 1
    fi
    echo "  ✓ $label"
}

# 1. surface/info
r=$(send_rpc '{"jsonrpc":"2.0","id":1,"method":"surface/info"}')
assert_eq "surface/info.surface_version" "1" "$(echo "$r" | jq -r .result.surface_version)"
assert_eq "surface/info.transports[0]"   "stdio" "$(echo "$r" | jq -r .result.transports[0])"
assert_eq "surface/info.transports length" "1" "$(echo "$r" | jq -r '.result.transports | length')"
assert_eq "surface/info.unix_broker" "false" "$(echo "$r" | jq -r .result.transport_detail.unix_broker)"
assert_eq "surface/info.daemon_hosts_broker" "false" "$(echo "$r" | jq -r .result.transport_detail.daemon_hosts_broker)"
assert_eq "surface/info.no refresh capability overclaim" "false" "$(echo "$r" | jq -r '.result.capabilities | index("refresh") != null')"
assert_eq "surface/info.no events capability overclaim" "false" "$(echo "$r" | jq -r '.result.capabilities | index("events") != null')"
assert_eq "surface/info.credential_materialize_scope" "adapter_stdio_only" "$(echo "$r" | jq -r .result.capabilities_detail.credential_materialize_scope)"
assert_eq "surface/info.credential_refresh disabled" "false" "$(echo "$r" | jq -r .result.capabilities_detail.credential_refresh)"
assert_eq "surface/info.events_append disabled" "false" "$(echo "$r" | jq -r .result.capabilities_detail.events_append)"

# 1b. session validation rejects unknown ids before handshake.
r=$(send_rpc '{"jsonrpc":"2.0","id":10,"method":"account/list","params":{"session_id":"not-real"}}')
assert_eq "account/list unknown session code" "-32012" "$(echo "$r" | jq -r .error.code)"

# 2. surface/handshake
r=$(send_rpc '{"jsonrpc":"2.0","id":2,"method":"surface/handshake","params":{"adapter":"smoke","adapter_version":"0","harness_target":"codex","session_pid":1}}')
sid_present=$(echo "$r" | jq -r '.result.session_id | length > 0')
assert_eq "surface/handshake.session_id present" "true" "$sid_present"
assert_eq "surface/handshake.claim_floor" "broker_owned" "$(echo "$r" | jq -r .result.claim_floor)"
sid="$(echo "$r" | jq -r .result.session_id)"

# 3. account/list
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:3,method:"account/list",params:{session_id:$sid,profile:"codex-max",capability:"codex-max"}}')")
assert_eq "account/list count" "3" "$(echo "$r" | jq -r '.result.accounts | length')"
assert_eq "account/list[0].id" "codex:max-1" "$(echo "$r" | jq -r .result.accounts[0].id)"
assert_eq "account/list[0].liveness" "live" "$(echo "$r" | jq -r .result.accounts[0].liveness)"

# 4. account/select picks max-1
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:4,method:"account/select",params:{session_id:$sid,profile:"codex-max",capability:"codex-max"}}')")
assert_eq "account/select.account" "codex:max-1" "$(echo "$r" | jq -r .result.account)"
assert_eq "account/select.claim.level" "broker_owned" "$(echo "$r" | jq -r .result.claim.level)"
assert_eq "account/select.claim.spare_fallback_ready" "true" "$(echo "$r" | jq -r .result.claim.spare_fallback_ready)"
handle="$(echo "$r" | jq -r .result.credential_handle)"

# 5. credential/materialize returns the JWT-decoded plan + fedramp
r=$(send_rpc "$(jq -nc --arg sid "$sid" --arg handle "$handle" '{jsonrpc:"2.0",id:5,method:"credential/materialize",params:{session_id:$sid,credential_handle:$handle,shape:"chatgpt_auth_tokens"}}')")
assert_eq "credential/materialize.shape" "chatgpt_auth_tokens" "$(echo "$r" | jq -r .result.shape)"
assert_eq "credential/materialize.access_token" "AT-smoke-1" "$(echo "$r" | jq -r .result.access_token)"
assert_eq "credential/materialize.account_id" "acc-smoke-1" "$(echo "$r" | jq -r .result.account_id)"
assert_eq "credential/materialize.plan_type" "pro" "$(echo "$r" | jq -r .result.plan_type)"
assert_eq "credential/materialize.fedramp" "true" "$(echo "$r" | jq -r .result.fedramp)"

# 6. quota/observe records exhaustion
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:6,method:"quota/observe",params:{session_id:$sid,account:"codex:max-1",kind:"quota_exhausted",http_status:429,body_class:"usage_limit_reached",resets_at:1788000000}}')")
assert_eq "quota/observe.recorded" "true" "$(echo "$r" | jq -r .result.recorded)"
assert_eq "quota/observe.now_selectable" "false" "$(echo "$r" | jq -r .result.now_selectable)"
assert_eq "quota/observe.next_eligible_at" "1788000000" "$(echo "$r" | jq -r .result.next_eligible_at)"

# 7. account/select after observe -> picks max-2 (max-1 is exhausted)
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:7,method:"account/select",params:{session_id:$sid,profile:"codex-max",capability:"codex-max"}}')")
assert_eq "account/select-post-observe" "codex:max-2" "$(echo "$r" | jq -r .result.account)"

# 8. account/swap on max-2 returns max-3, but does not self-promote
# next_turn_seamless until the adapter observes the next turn complete.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:8,method:"account/swap",params:{session_id:$sid,current_account:"codex:max-2",reason:"quota_exhausted",evidence:{http_status:429,resets_at:1788000000}}}')")
assert_eq "account/swap.account" "codex:max-3" "$(echo "$r" | jq -r .result.account)"
assert_eq "account/swap.claim.level" "broker_owned" "$(echo "$r" | jq -r .result.claim.level)"
assert_eq "account/swap.claim.requires_adapter_turn_completion" "true" "$(echo "$r" | jq -r .result.claim.requires_adapter_turn_completion)"
assert_eq "account/swap.claim.next_turn_seamless_claimed" "false" "$(echo "$r" | jq -r .result.claim.next_turn_seamless_claimed)"
assert_eq "account/swap.previous_marked.as" "quota_exhausted" "$(echo "$r" | jq -r .result.previous_marked.as)"

# 9. quota/status reflects two exhausted + one selectable
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:9,method:"quota/status",params:{session_id:$sid}}')")
assert_eq "quota/status.selectable_count" "1" "$(echo "$r" | jq -r .result.selectable_count)"
assert_eq "quota/status.max-1.availability" "quota_exhausted" "$(echo "$r" | jq -r '.result.accounts[] | select(.id=="codex:max-1") | .availability')"
assert_eq "quota/status.max-3.availability" "available" "$(echo "$r" | jq -r '.result.accounts[] | select(.id=="codex:max-3") | .availability')"

# 10. no selectable replacement returns typed JSON-RPC error data.
r=$(send_rpc "$(jq -nc --arg sid "$sid" '{jsonrpc:"2.0",id:11,method:"account/swap",params:{session_id:$sid,profile:"codex-max",capability:"codex-max",current_account:"codex:max-3",reason:"quota_exhausted",evidence:{http_status:429,resets_at:1788000000}}}')")
assert_eq "account/swap-no-replacement.error.code" "-32010" "$(echo "$r" | jq -r .error.code)"
assert_eq "account/swap-no-replacement.error_name" "no_account_selectable" "$(echo "$r" | jq -r .error.data.error_name)"
assert_eq "account/swap-no-replacement.selectable_routes" "0" "$(echo "$r" | jq -r .error.data.rejection_summary.selectable_routes)"
assert_eq "account/swap-no-replacement.first_action" "oauth-mux route explain --profile codex-max --capability codex-max --json" "$(echo "$r" | jq -r .error.data.agent_safe_next_actions[0])"

echo
echo "smoke-broker: all assertions passed."
