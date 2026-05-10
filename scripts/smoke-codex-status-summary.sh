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
FAILED_QUOTA="$TMP/failed-quota.ndjson"
AUTH_FAILED="$TMP/auth-failed.ndjson"
AUTH_FALLBACK="$TMP/auth-fallback.ndjson"
AUTH_FALLBACK_CHAIN="$TMP/auth-fallback-chain.ndjson"
INCOMPLETE="$TMP/incomplete.ndjson"
SIGNALED="$TMP/signaled.ndjson"

cat >"$BROKERED" <<'EOF'
{"kind":"launch_timing","phase":"config_health_load","duration_ms":4,"elapsed_ms":4,"path_printed":false,"token_material_printed":false,"session_id_printed":false}
{"kind":"launch_timing","phase":"child_spawn","duration_ms":3,"elapsed_ms":19,"path_printed":false,"token_material_printed":false,"session_id_printed":false}
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
{"kind":"proxy_no_account_selectable","attempted":["codex:max-2"],"rejections":[{"account":"codex:max-2","state":"credential_unavailable","reason":"ConnectionResetByPeer"}]}
{"kind":"proxy_turn","account":"codex:max-2","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true}
{"kind":"session_ended","adapter":"codex","exit_code":0,"final_claim_level":"broker_owned","synthetic_swap_observed":true}
EOF

cat >"$FAILED_QUOTA" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-1","to":"codex:max-2","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-2","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-2","to":"codex:max-3","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-3","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-3","to":"codex:max-4","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-4","method":"GET","path_kind":"codex_other","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
{"kind":"proxy_turn","account":"codex:max-4","method":"POST","path_kind":"responses","status":429,"classification":"quota_exhausted","body_class":"usage_limit_reached","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_same_turn_retry_unavailable","account":"codex:max-4","reason":"quota_exhausted","err":"NoAccountSelectable"}
{"kind":"quota_handoff_failed_no_account_selectable","account":"codex:max-4","reason":"quota_exhausted","attempted":["codex:max-4","codex:max-1","codex:max-2","codex:max-3"],"rejections":[{"account":"codex:max-4","state":"quota_exhausted","reason":"usage_limit_reached"},{"account":"codex:max-1","state":"auth_failed","reason":"unauthorized"},{"account":"codex:max-2","state":"auth_failed","reason":"unauthorized"},{"account":"codex:max-3","state":"auth_failed","reason":"unauthorized"}],"user_visible_failure_likely":true}
{"kind":"proxy_no_account_selectable","err":"NoAccountSelectable","path_kind":"responses","attempted":["codex:max-4","codex:max-1","codex:max-2","codex:max-3"]}
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

cat >"$AUTH_FALLBACK_CHAIN" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-1","to":"codex:max-2","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-2","method":"GET","path_kind":"codex_other","status":401,"classification":"auth_unauthorized","body_class":"json_error","claim_level":"broker_owned","streamed":false,"delivered_to_codex":false}
{"kind":"proxy_auth_same_turn_retry","from":"codex:max-2","to":"codex:max-3","reason":"auth_unauthorized","dropped":"x-codex-turn-state"}
{"kind":"proxy_turn","account":"codex:max-3","method":"GET","path_kind":"codex_other","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
EOF

cat >"$INCOMPLETE" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-1","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-1","method":"POST","path_kind":"responses","status":401,"classification":"auth_unauthorized","body_class":"empty","claim_level":"broker_owned","streamed":true,"delivered_to_codex":true}
EOF

cat >"$SIGNALED" <<'EOF'
{"kind":"session_started","selected_account":"codex:max-3","claim_level":"broker_owned","session_authority":"canonical_bridge"}
{"kind":"proxy_turn","account":"codex:max-3","method":"POST","path_kind":"responses","status":200,"classification":"ok","body_class":"none","claim_level":"broker_owned","streamed":true}
{"kind":"session_aborted","adapter":"codex","reason":"child_signal","exit_code":-1,"term_kind":"signal","term_code":9,"signal_name":"SIGKILL","final_claim_level":"broker_owned","synthetic_swap_observed":false}
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
if [[ "$(jq -r .quota_event_observed <<<"$BROKERED_SUMMARY")" != "false" ]]; then
    echo "brokered-only artifact should not report quota evidence" >&2
    echo "$BROKERED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .terminal_event_observed <<<"$BROKERED_SUMMARY")" != "true" ]]; then
    echo "brokered-only artifact should have terminal evidence" >&2
    echo "$BROKERED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .launch_timing.child_spawn_elapsed_ms <<<"$BROKERED_SUMMARY")" != "19" ]]; then
    echo "brokered-only artifact should summarize launch timing" >&2
    echo "$BROKERED_SUMMARY" >&2
    exit 1
fi

FALLBACK_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$FALLBACK" --require-brokered --require-fallback-sequence)"
if [[ "$(jq -r .verdict <<<"$FALLBACK_SUMMARY")" != "successful_live_quota_handoff" ]]; then
    echo "fallback verdict mismatch" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .fallback_sequence.fallback_account <<<"$FALLBACK_SUMMARY")" != "codex:max-2" ]]; then
    echo "fallback account mismatch" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .quota_event_observed <<<"$FALLBACK_SUMMARY")" != "true" ]]; then
    echo "fallback summary should report quota evidence" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .quota_handoff_observed <<<"$FALLBACK_SUMMARY")" != "true" ]]; then
    echo "fallback summary should report quota handoff" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .provider_originated_live_fallback_claim <<<"$FALLBACK_SUMMARY")" != "true" ]]; then
    echo "fallback summary should identify provider-originated live quota handoff" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .quota_handoff_failed_reason <<<"$FALLBACK_SUMMARY")" != "null" ]]; then
    echo "fallback summary should not attach later no-account evidence to an already successful handoff" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .user_visible_failure_likely <<<"$FALLBACK_SUMMARY")" != "false" ]]; then
    echo "fallback summary should not mark successful handoff as user-visible failure" >&2
    echo "$FALLBACK_SUMMARY" >&2
    exit 1
fi

FAILED_QUOTA_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$FAILED_QUOTA" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$FAILED_QUOTA_SUMMARY")" != "quota_handoff_failed" ]]; then
    echo "failed-quota verdict mismatch" >&2
    echo "$FAILED_QUOTA_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .quota_event_observed <<<"$FAILED_QUOTA_SUMMARY")" != "true" ]]; then
    echo "failed-quota summary should report quota evidence" >&2
    echo "$FAILED_QUOTA_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .quota_handoff_failed_reason <<<"$FAILED_QUOTA_SUMMARY")" != "quota_exhausted" ]]; then
    echo "failed-quota reason mismatch" >&2
    echo "$FAILED_QUOTA_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r '.no_account_selectable_rejections | length' <<<"$FAILED_QUOTA_SUMMARY")" != "4" ]]; then
    echo "failed-quota rejection vector mismatch" >&2
    echo "$FAILED_QUOTA_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .user_visible_failure_likely <<<"$FAILED_QUOTA_SUMMARY")" != "true" ]]; then
    echo "failed-quota summary should flag user-visible failure" >&2
    echo "$FAILED_QUOTA_SUMMARY" >&2
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
if [[ "$(jq -r .auth_fallback_sequence.retry.to <<<"$AUTH_FALLBACK_SUMMARY")" != "codex:max-2" ]]; then
    echo "auth-fallback terminal retry mismatch" >&2
    echo "$AUTH_FALLBACK_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_health_quota_claim_observed <<<"$AUTH_FALLBACK_SUMMARY")" != "false" ]]; then
    echo "auth-fallback summary must not claim quota" >&2
    echo "$AUTH_FALLBACK_SUMMARY" >&2
    exit 1
fi

AUTH_FALLBACK_CHAIN_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$AUTH_FALLBACK_CHAIN" --require-brokered)"
if [[ "$(jq -r .verdict <<<"$AUTH_FALLBACK_CHAIN_SUMMARY")" != "auth_fallback_sequence_observed" ]]; then
    echo "auth-fallback-chain verdict mismatch" >&2
    echo "$AUTH_FALLBACK_CHAIN_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_fallback_sequence.fallback_account <<<"$AUTH_FALLBACK_CHAIN_SUMMARY")" != "codex:max-3" ]]; then
    echo "auth-fallback-chain account mismatch" >&2
    echo "$AUTH_FALLBACK_CHAIN_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_fallback_sequence.retry.to <<<"$AUTH_FALLBACK_CHAIN_SUMMARY")" != "codex:max-3" ]]; then
    echo "auth-fallback-chain terminal retry mismatch" >&2
    echo "$AUTH_FALLBACK_CHAIN_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .auth_fallback_sequence.retry_count <<<"$AUTH_FALLBACK_CHAIN_SUMMARY")" != "2" ]]; then
    echo "auth-fallback-chain retry count mismatch" >&2
    echo "$AUTH_FALLBACK_CHAIN_SUMMARY" >&2
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

SIGNALED_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$SIGNALED" --require-brokered)"
if [[ "$(jq -r .session_aborted_observed <<<"$SIGNALED_SUMMARY")" != "true" ]]; then
    echo "signaled artifact should be marked aborted" >&2
    echo "$SIGNALED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .terminal_event.term_kind <<<"$SIGNALED_SUMMARY")" != "signal" ]]; then
    echo "signaled artifact should retain terminal signal kind" >&2
    echo "$SIGNALED_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .terminal_event.signal_name <<<"$SIGNALED_SUMMARY")" != "SIGKILL" ]]; then
    echo "signaled artifact should retain signal name" >&2
    echo "$SIGNALED_SUMMARY" >&2
    exit 1
fi

EVIDENCE="$ROOT/docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson"
if [[ ! -f "$EVIDENCE" ]]; then
    echo "managed quota handoff evidence excerpt missing" >&2
    exit 1
fi
EVIDENCE_SUMMARY="$(python3 "$ROOT/scripts/summarize-codex-status.py" "$EVIDENCE" --require-brokered --require-fallback-sequence)"
if [[ "$(jq -r .verdict <<<"$EVIDENCE_SUMMARY")" != "successful_live_quota_handoff" ]]; then
    echo "managed quota handoff evidence verdict mismatch" >&2
    echo "$EVIDENCE_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .provider_originated_live_fallback_claim <<<"$EVIDENCE_SUMMARY")" != "true" ]]; then
    echo "managed quota handoff evidence should identify provider-originated fallback" >&2
    echo "$EVIDENCE_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .user_visible_failure_likely <<<"$EVIDENCE_SUMMARY")" != "false" ]]; then
    echo "managed quota handoff evidence should not be user-visible failure" >&2
    echo "$EVIDENCE_SUMMARY" >&2
    exit 1
fi
EVIDENCE_NATIVE_SUMMARY="$("$ROOT/zig-out/bin/oauth-mux" codex status-latest --status-file "$EVIDENCE" --json)"
if [[ "$(jq -r .verdict <<<"$EVIDENCE_NATIVE_SUMMARY")" != "successful_live_quota_handoff" ]]; then
    echo "native status-latest evidence verdict mismatch" >&2
    echo "$EVIDENCE_NATIVE_SUMMARY" >&2
    exit 1
fi
if [[ "$(jq -r .provider_originated_live_fallback_claim <<<"$EVIDENCE_NATIVE_SUMMARY")" != "true" ]]; then
    echo "native status-latest should identify provider-originated fallback" >&2
    echo "$EVIDENCE_NATIVE_SUMMARY" >&2
    exit 1
fi

echo "smoke-codex-status-summary: all assertions passed."
