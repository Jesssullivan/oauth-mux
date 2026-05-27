#!/usr/bin/env bash
# Offline smoke for the Codex wire-capture reviewer.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d -t omux-capture-review.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

CAP="$TMP/codex-wire-synth/http"
mkdir -p "$CAP"

cat >"$TMP/codex-wire-synth/capture-preflight-summary.json" <<'JSON'
{
  "ok": true,
  "issues": [],
  "oauth_mux": {
    "version": "0.1.10",
    "build_id": "v0.1.10",
    "binary_source": "homebrew"
  },
  "route_summary": {
    "session_start_ready": true,
    "fallback_ready": true,
    "single_route_at_risk": false
  },
  "process_gate": {
    "process_fd_clean_baseline": true,
    "unannotated_live_claims_admitted": true,
    "quota_cassette_claims_admitted": true,
    "local_release_validation_admitted": true,
    "requires_operator_annotation": false,
    "blocking_reasons": [],
    "caution_reasons": []
  }
}
JSON

cat >"$TMP/codex-wire-synth/meta.json" <<'JSON'
{
  "ts_utc": "20260526T000000Z",
  "kind": "phase_0_wire_capture",
  "addon": "scripts/codex-wire-addon.py",
  "preflight_summary": "capture-preflight-summary.json",
  "host_filter": "chatgpt.com",
  "ports": { "http": 9080, "https": 9080 }
}
JSON

cat >"$CAP/00001-POST-backend-api_codex_responses.json" <<'JSON'
{
  "captured_at": 1788000000.0,
  "host": "chatgpt.com",
  "scheme": "https",
  "method": "POST",
  "path": "/backend-api/codex/responses",
  "request": {
    "headers": [
      ["Authorization", "Bearer abcdef-<0123456789>"],
      ["ChatGPT-Account-ID", "acct-a-<abcdef0123>"]
    ],
    "body": {"model": "gpt-5.5"}
  },
  "response": {
    "status": 429,
    "reason": "Too Many Requests",
    "headers": [["content-type", "application/json"]],
    "body": {
      "error": {
        "type": "usage_limit_reached",
        "plan_type": "pro",
        "resets_at": 1788000000
      }
    }
  },
  "timing_ms": 42
}
JSON

cat >"$CAP/00002-POST-backend-api_codex_responses.json" <<'JSON'
{
  "captured_at": 1788000000.5,
  "host": "chatgpt.com",
  "scheme": "https",
  "method": "POST",
  "path": "/backend-api/codex/responses?captured=query",
  "request": {
    "headers": [
      ["Authorization", "Bearer abcdef-<0123456789>"],
      ["ChatGPT-Account-ID", "acct-a-<abcdef0123>"]
    ],
    "body": {"model": "gpt-5.5"}
  },
  "response": {
    "status": 200,
    "reason": "OK",
    "headers": [
      ["content-type", "text/event-stream"],
      ["set-cookie", "__cf_bm=<redacted>"]
    ],
    "body": {
      "__non_json__": true,
      "len": 62,
      "head_hex": "6576656e743a20726573706f6e73652e636f6d706c657465640a646174613a207b2274797065223a22726573706f6e73652e636f6d706c65746564227d0a0a",
      "text_encoding": "utf-8",
      "body_text": "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"
    }
  },
  "timing_ms": 24
}
JSON

"$ROOT/scripts/capture-codex-wire.sh" review "$TMP/codex-wire-synth" \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-process-gate quota_cassette_claims_admitted \
  --require-path-kind responses \
  --require-status 200 \
  --require-status 429 \
  --require-quota-type usage_limit_reached \
  --json >"$TMP/summary.json"

python3 - "$TMP/summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["flow_count"] == 2, summary
assert summary["preflight"]["present"] is True, summary
assert summary["preflight"]["ok"] is True, summary
assert summary["preflight"]["process_gate"]["quota_cassette_claims_admitted"] is True, summary
assert summary["meta"]["present"] is True, summary
assert summary["meta"]["kind"] == "phase_0_wire_capture", summary
assert summary["meta"]["preflight_summary"] == "capture-preflight-summary.json", summary
assert summary["meta"]["preflight_summary_present"] is True, summary
assert summary["path_counts"]["responses"] == 2, summary
assert summary["status_counts"]["200"] == 1, summary
assert summary["status_counts"]["429"] == 1, summary
shape = summary["quota_shapes"][0]
assert shape["error_type"] == "usage_limit_reached", shape
assert shape["has_resets_at"] is True, shape
assert shape["plan_type"] == "pro", shape
assert summary["requirement_failures"] == [], summary
PY

BAD_PROCESS_GATE="$TMP/codex-wire-bad-process-gate"
mkdir -p "$BAD_PROCESS_GATE/http"
cp "$TMP/codex-wire-synth/meta.json" "$BAD_PROCESS_GATE/meta.json"
cp "$CAP/00001-POST-backend-api_codex_responses.json" "$BAD_PROCESS_GATE/http/00001-POST-backend-api_codex_responses.json"
cat >"$BAD_PROCESS_GATE/capture-preflight-summary.json" <<'JSON'
{
  "ok": true,
  "issues": [],
  "process_gate": {
    "quota_cassette_claims_admitted": false,
    "blocking_reasons": [
      {"reason": "active_oauth_mux_or_codex_processes", "count": 1}
    ],
    "caution_reasons": []
  }
}
JSON

if "$ROOT/scripts/capture-codex-wire.sh" review "$BAD_PROCESS_GATE" \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-process-gate quota_cassette_claims_admitted \
  --json >"$TMP/bad-process-gate-summary.json"; then
  echo "smoke-codex-capture-review: expected blocked process gate to fail" >&2
  exit 1
fi

python3 - "$TMP/bad-process-gate-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert "capture preflight process gate not admitted: quota_cassette_claims_admitted" in summary["requirement_failures"], summary
PY

FIXTURE="$ROOT/test/fixtures/codex-wire/auth-refresh-token-expired"
"$ROOT/scripts/capture-codex-wire.sh" review "$FIXTURE" \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-path-kind responses \
  --require-status 401 \
  --json >"$TMP/auth-failure-fixture-summary.json"

python3 - "$TMP/auth-failure-fixture-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["flow_count"] == 2, summary
assert summary["path_counts"]["oauth_token"] == 1, summary
assert summary["path_counts"]["responses"] == 1, summary
assert summary["status_counts"]["401"] == 2, summary
assert summary["redaction_failures"] == [], summary
PY

WS_FIXTURE="$ROOT/test/fixtures/codex-wire/broker-owned-websocket-success"
"$ROOT/scripts/capture-codex-wire.sh" review "$WS_FIXTURE" \
  --require-preflight-ok \
  --require-proxy-meta \
  --require-path-kind responses \
  --require-status 101 \
  --json >"$TMP/websocket-success-fixture-summary.json"

python3 - "$TMP/websocket-success-fixture-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["flow_count"] == 1, summary
assert summary["path_counts"]["responses"] == 1, summary
assert summary["status_counts"]["101"] == 1, summary
assert summary["redaction_failures"] == [], summary
PY

BAD_META="$TMP/codex-wire-bad-meta"
mkdir -p "$BAD_META/http"
cp "$TMP/codex-wire-synth/capture-preflight-summary.json" "$BAD_META/capture-preflight-summary.json"
cp "$CAP/00001-POST-backend-api_codex_responses.json" "$BAD_META/http/00001-POST-backend-api_codex_responses.json"
cat >"$BAD_META/meta.json" <<'JSON'
{
  "kind": "phase_0_wire_capture",
  "preflight_summary": "wrong-preflight-summary.json"
}
JSON

if "$ROOT/scripts/capture-codex-wire.sh" review "$BAD_META" \
  --require-preflight-ok \
  --require-proxy-meta \
  --json >"$TMP/bad-meta-summary.json"; then
  echo "smoke-codex-capture-review: expected bad proxy metadata to fail" >&2
  exit 1
fi

python3 - "$TMP/bad-meta-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert summary["redaction_failures"] == [], summary
assert "capture meta.json does not point at capture-preflight-summary.json" in summary["requirement_failures"], summary
PY

if "$ROOT/scripts/capture-codex-wire.sh" review "$TMP/codex-wire-synth" \
  --require-quota-type usage_not_included \
  --json >"$TMP/missing-requirement-summary.json"; then
  echo "smoke-codex-capture-review: expected missing requirement to fail" >&2
  exit 1
fi

python3 - "$TMP/missing-requirement-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert summary["redaction_failures"] == [], summary
assert summary["requirement_failures"] == [
    "required quota error.type not observed: usage_not_included"
], summary
PY

cat >"$CAP/00003-POST-secret-leak.json" <<'JSON'
{
  "captured_at": 1788000001.0,
  "host": "chatgpt.com",
  "scheme": "https",
  "method": "POST",
  "path": "/backend-api/codex/responses",
  "request": {
    "headers": [
      ["Authorization", "Bearer live-token-value-that-should-never-be-promoted"]
    ],
    "body": {}
  },
  "response": {
    "status": 200,
    "reason": "OK",
    "headers": [],
    "body": {
      "__non_json__": true,
      "len": 55,
      "head_hex": "6576656e743a20726573706f6e73652e636f6d706c657465640a",
      "text_encoding": "utf-8",
      "body_text": "event: leak\ndata: Bearer live-token-value-that-should-never-be-promoted\n\n"
    }
  },
  "timing_ms": 1
}
JSON

if python3 "$ROOT/scripts/review-codex-wire-capture.py" "$TMP/codex-wire-synth" --json >"$TMP/leak-summary.json"; then
  echo "smoke-codex-capture-review: expected leaked bearer fixture to fail" >&2
  exit 1
fi

python3 - "$TMP/leak-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert summary["redaction_failures"], summary
PY

BAD_COOKIE="$TMP/codex-wire-bad-cookie"
mkdir -p "$BAD_COOKIE/http"
cp "$TMP/codex-wire-synth/capture-preflight-summary.json" "$BAD_COOKIE/capture-preflight-summary.json"
cp "$TMP/codex-wire-synth/meta.json" "$BAD_COOKIE/meta.json"
cat >"$BAD_COOKIE/http/00001-GET-backend-api_codex_responses.json" <<'JSON'
{
  "captured_at": 1788000002.0,
  "host": "chatgpt.com",
  "scheme": "https",
  "method": "GET",
  "path": "/backend-api/codex/responses",
  "request": {
    "headers": [
      ["Cookie", "__Host-next-auth.csrf-token=live-cookie-value-that-should-never-be-promoted"]
    ],
    "body": {}
  },
  "response": {
    "status": 101,
    "reason": "Switching Protocols",
    "headers": [
      ["Set-Cookie", "__cf_bm=live-set-cookie-value-that-should-never-be-promoted; path=/; HttpOnly; Secure"]
    ],
    "body": {}
  },
  "timing_ms": 1
}
JSON

if python3 "$ROOT/scripts/review-codex-wire-capture.py" "$BAD_COOKIE" --json >"$TMP/bad-cookie-summary.json"; then
  echo "smoke-codex-capture-review: expected unredacted cookie headers to fail" >&2
  exit 1
fi

python3 - "$TMP/bad-cookie-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
failures = "\n".join(summary["redaction_failures"])
assert "request Cookie header is not redacted" in failures, summary
assert "response Set-Cookie header is not redacted" in failures, summary
PY

BAD_LOCAL_PATH="$TMP/codex-wire-bad-local-path"
mkdir -p "$BAD_LOCAL_PATH/http"
cp "$TMP/codex-wire-synth/capture-preflight-summary.json" "$BAD_LOCAL_PATH/capture-preflight-summary.json"
cp "$TMP/codex-wire-synth/meta.json" "$BAD_LOCAL_PATH/meta.json"
cat >"$BAD_LOCAL_PATH/http/00001-GET-backend-api_codex_responses.json" <<'JSON'
{
  "captured_at": 1788000003.0,
  "host": "chatgpt.com",
  "scheme": "https",
  "method": "GET",
  "path": "/backend-api/codex/responses",
  "request": {
    "headers": [
      ["x-codex-turn-metadata", "{\"workspaces\":{\"/Users/jess/git/oauth-mux\":{\"has_changes\":false}}}"]
    ],
    "body": {}
  },
  "response": {
    "status": 401,
    "reason": "Unauthorized",
    "headers": [["content-type", "application/json"]],
    "body": {
      "error": {"code": "token_expired"}
    }
  },
  "timing_ms": 1
}
JSON

if python3 "$ROOT/scripts/review-codex-wire-capture.py" "$BAD_LOCAL_PATH" --json >"$TMP/bad-local-path-summary.json"; then
  echo "smoke-codex-capture-review: expected unredacted local path fixture to fail" >&2
  exit 1
fi

python3 - "$TMP/bad-local-path-summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
failures = "\n".join(summary["redaction_failures"])
assert "local path is not redacted" in failures, summary
PY

BIN="$TMP/bin"
mkdir -p "$BIN"

cat >"$BIN/oauth-mux" <<'SH'
#!/usr/bin/env sh
set -eu
if [ "$1" = "version" ] && [ "$2" = "--json" ]; then
  cat <<'JSON'
{"version":"0.1.10","runtime_identity":{"binary_path":"/tmp/fake/oauth-mux","binary_source":"test","binary_sha256":"abc","build_id":"v0.1.10"}}
JSON
  exit 0
fi
if [ "$1" = "codex" ] && [ "$2" = "preflight" ]; then
  if [ "${OMUX_FAKE_PREFLIGHT_FAIL:-0}" = "1" ]; then
    cat <<'JSON'
{"ok":false,"selected":null,"route_summary":{"routes_total":4,"broker_ready_routes":4,"unreadable_routes":0,"selectable_routes":0,"selectable_broker_routes":0,"selectable_fallback_routes":0,"blocked_broker_routes":4,"auth_unready_routes":0,"session_start_ready":false,"fallback_ready":false,"single_route_at_risk":false},"blocked_route_reasons":[{"reason":"network_error","count":4}]}
JSON
    exit 1
  fi
  cat <<'JSON'
{"ok":true,"selected":{"provider":"codex","account":"max-1","capability":"codex-max","health_key":"codex:max-1#codex-max"},"route_summary":{"routes_total":4,"broker_ready_routes":4,"unreadable_routes":0,"selectable_routes":3,"selectable_broker_routes":3,"selectable_fallback_routes":2,"blocked_broker_routes":1,"auth_unready_routes":0,"session_start_ready":true,"fallback_ready":true,"single_route_at_risk":false},"blocked_route_reasons":[{"reason":"quota_exhausted","count":1}]}
JSON
  exit 0
fi
if [ "$1" = "codex" ] && [ "$2" = "status-latest" ]; then
  cat <<'JSON'
{"verdict":"brokered_with_fallback","path":"/tmp/status.ndjson"}
JSON
  exit 0
fi
echo "unexpected oauth-mux args: $*" >&2
exit 2
SH

cat >"$BIN/codex" <<'SH'
#!/usr/bin/env sh
set -eu
if [ "$1" = "--version" ]; then
  echo "codex-cli 0.132.0"
  exit 0
fi
echo "unexpected codex args: $*" >&2
exit 2
SH

cat >"$BIN/mitmdump" <<'SH'
#!/usr/bin/env sh
set -eu
if [ "$1" = "--version" ]; then
  echo "Mitmproxy: 12.0.0"
  exit 0
fi
if [ -n "${OMUX_FAKE_MITMDUMP_LOG:-}" ]; then
  printf '%s\n' "$@" >"$OMUX_FAKE_MITMDUMP_LOG"
  exit 0
fi
echo "unexpected mitmdump args: $*" >&2
exit 2
SH

chmod +x "$BIN/oauth-mux" "$BIN/codex" "$BIN/mitmdump"

MITMPROXY_CA="$TMP/mitmproxy/mitmproxy-ca-cert.cer"
mkdir -p "$(dirname "$MITMPROXY_CA")"
printf 'fake mitmproxy ca\n' >"$MITMPROXY_CA"

OMUX_CAPTURE_DIR="$TMP/captures" OMUX_MITMPROXY_CA="$MITMPROXY_CA" SSL_CERT_FILE="$MITMPROXY_CA" PATH="$BIN:$PATH" \
  "$ROOT/scripts/capture-codex-wire.sh" preflight >"$TMP/preflight.out"

SUMMARY="$(find "$TMP/captures" -name capture-preflight-summary.json -print | head -1)"
test -n "$SUMMARY"

python3 - "$SUMMARY" "$MITMPROXY_CA" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["mitmdump_available"] is True, summary
assert summary["mitmproxy_ca"]["path"] == sys.argv[2], summary
assert summary["mitmproxy_ca"]["exists"] is True, summary
assert summary["mitmproxy_ca"]["ssl_cert_file_matches_ca"] is True, summary
assert summary["route_summary"]["fallback_ready"] is True, summary
assert summary["route_summary"]["single_route_at_risk"] is False, summary
assert summary["process_gate"]["present"] is True, summary
assert isinstance(summary["process_gate"]["blocking_reasons"], list), summary
assert isinstance(summary["process_gate"]["safe_cleanup_review_counts"]["active_codex_or_oauth_mux_processes"], int), summary
assert summary["oauth_mux"]["build_id"] == "v0.1.10", summary
assert summary["status_verdict"] == "brokered_with_fallback", summary
assert summary["blocked_route_reasons"][0]["reason"] == "quota_exhausted", summary
PY

PROXY_MITMDUMP_LOG="$TMP/proxy-mitmdump-args.txt"
OMUX_CAPTURE_DIR="$TMP/proxy-captures" OMUX_MITMPROXY_CA="$MITMPROXY_CA" SSL_CERT_FILE="$MITMPROXY_CA" OMUX_FAKE_MITMDUMP_LOG="$PROXY_MITMDUMP_LOG" PATH="$BIN:$PATH" \
  "$ROOT/scripts/capture-codex-wire.sh" proxy >"$TMP/proxy.out"

PROXY_SUMMARY="$(find "$TMP/proxy-captures" -name capture-preflight-summary.json -print | head -1)"
PROXY_META="$(find "$TMP/proxy-captures" -name meta.json -print | head -1)"
test -n "$PROXY_SUMMARY"
test -n "$PROXY_META"
test -s "$PROXY_MITMDUMP_LOG"

python3 - "$PROXY_SUMMARY" "$PROXY_META" <<'PY'
import json
import pathlib
import sys
summary = json.load(open(sys.argv[1]))
meta = json.load(open(sys.argv[2]))
assert summary["ok"] is True, summary
assert meta["preflight_summary"] == "capture-preflight-summary.json", meta
assert pathlib.Path(sys.argv[1]).parent == pathlib.Path(sys.argv[2]).parent, (sys.argv[1], sys.argv[2])
PY

grep -q -- '--set' "$PROXY_MITMDUMP_LOG"

if OMUX_CAPTURE_DIR="$TMP/captures-missing-ca" OMUX_MITMPROXY_CA="$TMP/missing-mitmproxy-ca.cer" PATH="$BIN:$PATH" \
  "$ROOT/scripts/capture-codex-wire.sh" preflight >"$TMP/preflight-missing-ca.out"; then
  echo "expected missing-CA capture preflight to fail" >&2
  exit 1
fi

MISSING_CA_SUMMARY="$(find "$TMP/captures-missing-ca" -name capture-preflight-summary.json -print | head -1)"
test -n "$MISSING_CA_SUMMARY"

python3 - "$MISSING_CA_SUMMARY" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert summary["mitmdump_available"] is True, summary
assert summary["mitmproxy_ca"]["exists"] is False, summary
assert "mitmproxy CA is missing; run capture init or mitmdump once" in summary["issues"], summary
PY

if OMUX_CAPTURE_DIR="$TMP/captures-failed" OMUX_MITMPROXY_CA="$MITMPROXY_CA" SSL_CERT_FILE="$MITMPROXY_CA" OMUX_FAKE_PREFLIGHT_FAIL=1 PATH="$BIN:$PATH" \
  "$ROOT/scripts/capture-codex-wire.sh" preflight >"$TMP/preflight-failed.out"; then
  echo "expected failing capture preflight" >&2
  exit 1
fi

FAILED_SUMMARY="$(find "$TMP/captures-failed" -name capture-preflight-summary.json -print | head -1)"
test -n "$FAILED_SUMMARY"

python3 - "$FAILED_SUMMARY" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is False, summary
assert "codex preflight is not ok" in summary["issues"], summary
assert "session_start_ready is false" in summary["issues"], summary
assert "fallback_ready is false" in summary["issues"], summary
assert summary["blocked_route_reasons"][0]["reason"] == "network_error", summary
PY

printf 'smoke-codex-capture-review: all assertions passed.\n'
