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
#   8. account/swap        — full swap chain with claim.level promotion
#   9. quota/status        — pool snapshot reflects all prior mutations
#
# Exit 0 = all assertions pass. Exit non-zero = which step failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/oauth-mux"

if [[ ! -x "$BIN" ]]; then
    echo "smoke-broker: oauth-mux binary not built at $BIN" >&2
    echo "  run: just build" >&2
    exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "smoke-broker: jq required" >&2
    exit 64
fi

# Tempdir + cleanup
TMP="$(mktemp -d -t omux-smoke-broker.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

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

# Build the JSON-RPC request sequence.
REQUESTS=$(cat <<'REQ'
{"jsonrpc":"2.0","id":1,"method":"surface/info"}
{"jsonrpc":"2.0","id":2,"method":"surface/handshake","params":{"adapter":"smoke","adapter_version":"0","harness_target":"codex","session_pid":1}}
{"jsonrpc":"2.0","id":3,"method":"account/list","params":{"session_id":"x"}}
{"jsonrpc":"2.0","id":4,"method":"account/select","params":{"session_id":"x"}}
{"jsonrpc":"2.0","id":5,"method":"credential/materialize","params":{"session_id":"x","credential_handle":"ch:codex:max-1:0","shape":"chatgpt_auth_tokens"}}
{"jsonrpc":"2.0","id":6,"method":"quota/observe","params":{"session_id":"x","account":"codex:max-1","kind":"quota_exhausted","http_status":429,"body_class":"usage_limit_reached","resets_at":1788000000}}
{"jsonrpc":"2.0","id":7,"method":"account/select","params":{"session_id":"x"}}
{"jsonrpc":"2.0","id":8,"method":"account/swap","params":{"session_id":"x","current_account":"codex:max-2","reason":"quota_exhausted","evidence":{"http_status":429,"resets_at":1788000000}}}
{"jsonrpc":"2.0","id":9,"method":"quota/status","params":{"session_id":"x"}}
REQ
)

# Pipe + capture every response on its own line.
RESPONSES="$(printf '%s\n' "$REQUESTS" | OMUX_CONFIG="$TMP/config.json" "$BIN" mcp --profile codex-max 2>"$TMP/stderr.log")"

# Helper: pluck the response with the matching id.
resp_for() {
    local id=$1
    printf '%s\n' "$RESPONSES" | jq -c "select(.id==$id)"
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
r=$(resp_for 1)
assert_eq "surface/info.surface_version" "1" "$(echo "$r" | jq -r .result.surface_version)"
assert_eq "surface/info.transports[0]"   "stdio" "$(echo "$r" | jq -r .result.transports[0])"

# 2. surface/handshake
r=$(resp_for 2)
sid_present=$(echo "$r" | jq -r '.result.session_id | length > 0')
assert_eq "surface/handshake.session_id present" "true" "$sid_present"
assert_eq "surface/handshake.claim_floor" "broker_owned" "$(echo "$r" | jq -r .result.claim_floor)"

# 3. account/list
r=$(resp_for 3)
assert_eq "account/list count" "3" "$(echo "$r" | jq -r '.result.accounts | length')"
assert_eq "account/list[0].id" "codex:max-1" "$(echo "$r" | jq -r .result.accounts[0].id)"

# 4. account/select picks max-1
r=$(resp_for 4)
assert_eq "account/select.account" "codex:max-1" "$(echo "$r" | jq -r .result.account)"
assert_eq "account/select.claim.level" "broker_owned" "$(echo "$r" | jq -r .result.claim.level)"

# 5. credential/materialize returns the JWT-decoded plan + fedramp
r=$(resp_for 5)
assert_eq "credential/materialize.shape" "chatgpt_auth_tokens" "$(echo "$r" | jq -r .result.shape)"
assert_eq "credential/materialize.access_token" "AT-smoke-1" "$(echo "$r" | jq -r .result.access_token)"
assert_eq "credential/materialize.account_id" "acc-smoke-1" "$(echo "$r" | jq -r .result.account_id)"
assert_eq "credential/materialize.plan_type" "pro" "$(echo "$r" | jq -r .result.plan_type)"
assert_eq "credential/materialize.fedramp" "true" "$(echo "$r" | jq -r .result.fedramp)"

# 6. quota/observe records exhaustion
r=$(resp_for 6)
assert_eq "quota/observe.recorded" "true" "$(echo "$r" | jq -r .result.recorded)"
assert_eq "quota/observe.now_selectable" "false" "$(echo "$r" | jq -r .result.now_selectable)"
assert_eq "quota/observe.next_eligible_at" "1788000000" "$(echo "$r" | jq -r .result.next_eligible_at)"

# 7. account/select after observe -> picks max-2 (max-1 is exhausted)
r=$(resp_for 7)
assert_eq "account/select-post-observe" "codex:max-2" "$(echo "$r" | jq -r .result.account)"

# 8. account/swap on max-2 returns max-3 with next_turn_seamless
r=$(resp_for 8)
assert_eq "account/swap.account" "codex:max-3" "$(echo "$r" | jq -r .result.account)"
assert_eq "account/swap.claim.level" "next_turn_seamless" "$(echo "$r" | jq -r .result.claim.level)"
assert_eq "account/swap.previous_marked.as" "quota_exhausted" "$(echo "$r" | jq -r .result.previous_marked.as)"

# 9. quota/status reflects two exhausted + one selectable
r=$(resp_for 9)
assert_eq "quota/status.selectable_count" "1" "$(echo "$r" | jq -r .result.selectable_count)"
assert_eq "quota/status.max-1.availability" "quota_exhausted" "$(echo "$r" | jq -r '.result.accounts[] | select(.id=="codex:max-1") | .availability')"
assert_eq "quota/status.max-3.availability" "available" "$(echo "$r" | jq -r '.result.accounts[] | select(.id=="codex:max-3") | .availability')"

echo
echo "smoke-broker: all 22 assertions passed."
