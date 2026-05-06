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
AUTH_FAILED="$TMP/auth-failed.ndjson"
AUTH_FALLBACK="$TMP/auth-fallback.ndjson"
INCOMPLETE="$TMP/incomplete.ndjson"

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

cat >"$AUTH_FAILED" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_observed_401_codex_handles","account":"codex:max-1"}
{"kind":"proxy_turn","account":"codex:max-1","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"none","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
{"kind":"proxy_observed_401_codex_handles","account":"codex:max-1"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":401,"classification":"auth_unauthorized","body_class":"none","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
{"kind":"auth_health_observed","account":"codex:max-1","auth_unauthorized_turns":2,"responses_401_turns":1,"recovered_after_401":false,"recorded":true,"reason":"unrecovered_401_no_writeback","scope":"account_credential","quota_claim":false,"token_material_printed":false,"path_printed":false}
{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":false}
EOF

cat >"$AUTH_FALLBACK" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-1","to":"codex:max-2","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-2","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
{"kind":"auth_health_observed","account":"codex:max-1","auth_unauthorized_turns":1,"responses_401_turns":1,"recovered_after_401":false,"recorded":true,"reason":"unrecovered_401_no_writeback","scope":"account_credential","quota_claim":false,"token_material_printed":false,"path_printed":false}
{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":true}
EOF

cat >"$INCOMPLETE" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":401,"classification":"auth_unauthorized","body_class":"empty","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
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
if [[ "$(jq -r .terminal_event_observed <<<"$BROKERED_SUMMARY")" != "true" ]]; then
    echo "brokered-only artifact should have terminal evidence" >&2
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

AUTH_FAILED_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$AUTH_FAILED" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$AUTH_FAILED_SUMMARY")" != "brokered_auth_failed" ]]; then
    echo "auth-failed verdict mismatch" >&2
    echo "$AUTH_FAILED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_unauthorized_turns <<<"$AUTH_FAILED_SUMMARY")" != "2" ]]; then
    echo "auth-failed 401 count mismatch" >&2
    echo "$AUTH_FAILED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .responses_401_turns <<<"$AUTH_FAILED_SUMMARY")" != "1" ]]; then
    echo "auth-failed responses 401 count mismatch" >&2
    echo "$AUTH_FAILED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_health_recorded_observed <<<"$AUTH_FAILED_SUMMARY")" != "true" ]]; then
    echo "auth-failed summary should report recorded credential health" >&2
    echo "$AUTH_FAILED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_health_quota_claim_observed <<<"$AUTH_FAILED_SUMMARY")" != "false" ]]; then
    echo "auth-failed summary must not turn auth health into quota evidence" >&2
    echo "$AUTH_FAILED_SUMMARY" >&2
    exit 1
fi

AUTH_FALLBACK_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$AUTH_FALLBACK" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$AUTH_FALLBACK_SUMMARY")" != "auth_fallback_sequence_observed" ]]; then
    echo "auth-fallback verdict mismatch" >&2
    echo "$AUTH_FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_fallback_sequence.fallback_account <<<"$AUTH_FALLBACK_SUMMARY")" != "codex:max-2" ]]; then
    echo "auth-fallback account mismatch" >&2
    echo "$AUTH_FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_health_quota_claim_observed <<<"$AUTH_FALLBACK_SUMMARY")" != "false" ]]; then
    echo "auth-fallback summary must not claim quota" >&2
    echo "$AUTH_FALLBACK_SUMMARY" >&2
    exit 1
fi

INCOMPLETE_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$INCOMPLETE" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$INCOMPLETE_SUMMARY")" != "brokered_incomplete_auth_failed" ]]; then
    echo "incomplete verdict mismatch" >&2
    echo "$INCOMPLETE_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .health_recording_expected_but_missing <<<"$INCOMPLETE_SUMMARY")" != "true" ]]; then
    echo "incomplete summary should flag missing health recording" >&2
    echo "$INCOMPLETE_SUMMARY" >&2
    exit 1
fi

echo "smoke-codex-status-summary: all assertions passed."
