#!/usr/bin/env bash
# Smoke-test the Codex status summarizer against brokered-only and fallback
# shaped NDJSON artifacts.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v jq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-status-summary: jq and python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-status-summary.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

BROKERED="$TMP/brokered.ndjson"
FALLBACK="$TMP/fallback.ndjson"

cat >"$BROKERED" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true}
{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":false}
EOF

cat >"$FALLBACK" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":429,"classification":"quota_exhausted","body_class":"usage_limit_reached","delivered_to_codex":false}
{"kind":"proxy_same_turn_retry","from":"codex:max-1","to":"codex:max-2","reason":"quota_exhausted","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-2","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true}
{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":true}
EOF

BROKERED_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$BROKERED" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$BROKERED_SUMMARY")" != "brokered_without_fallback" ]]; then
    echo "brokered verdict mismatch" >&2
    echo "$BROKERED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .fallback_sequence.observed <<<"$BROKERED_SUMMARY")" != "false" ]]; then
    echo "brokered-only artifact should not claim fallback" >&2
    echo "$BROKERED_SUMMARY" >&2
    exit 1
fi

FALLBACK_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$FALLBACK" --require-brokered --require-fallback-sequence)"
if [[ "$(jq -r .verdict <<<"$FALLBACK_SUMMARY")" != "fallback_sequence_observed" ]]; then
    echo "fallback verdict mismatch" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .fallback_sequence.fallback_account <<<"$FALLBACK_SUMMARY")" != "codex:max-2" ]]; then
    echo "fallback account mismatch" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .provider_originated_live_fallback_claim <<<"$FALLBACK_SUMMARY")" != "false" ]]; then
    echo "summarizer must not claim provider-originated live fallback from NDJSON shape alone" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi

echo "smoke-codex-status-summary: all assertions passed."
