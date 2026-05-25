#!/usr/bin/env bash
# Offline smoke for the Codex wire-capture reviewer.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d -t omux-capture-review.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

CAP="$TMP/codex-wire-synth/http"
mkdir -p "$CAP"

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
    "headers": [["content-type", "text/event-stream"]],
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

python3 "$ROOT/scripts/review-codex-wire-capture.py" "$TMP/codex-wire-synth" --json >"$TMP/summary.json"

python3 - "$TMP/summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["flow_count"] == 2, summary
assert summary["path_counts"]["responses"] == 2, summary
assert summary["status_counts"]["200"] == 1, summary
assert summary["status_counts"]["429"] == 1, summary
shape = summary["quota_shapes"][0]
assert shape["error_type"] == "usage_limit_reached", shape
assert shape["has_resets_at"] is True, shape
assert shape["plan_type"] == "pro", shape
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
echo "unexpected mitmdump args: $*" >&2
exit 2
SH

chmod +x "$BIN/oauth-mux" "$BIN/codex" "$BIN/mitmdump"

OMUX_CAPTURE_DIR="$TMP/captures" PATH="$BIN:$PATH" \
  "$ROOT/scripts/capture-codex-wire.sh" preflight >"$TMP/preflight.out"

SUMMARY="$(find "$TMP/captures" -name capture-preflight-summary.json -print | head -1)"
test -n "$SUMMARY"

python3 - "$SUMMARY" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1]))
assert summary["ok"] is True, summary
assert summary["mitmdump_available"] is True, summary
assert summary["route_summary"]["fallback_ready"] is True, summary
assert summary["route_summary"]["single_route_at_risk"] is False, summary
assert summary["oauth_mux"]["build_id"] == "v0.1.10", summary
assert summary["status_verdict"] == "brokered_with_fallback", summary
assert summary["blocked_route_reasons"][0]["reason"] == "quota_exhausted", summary
PY

if OMUX_CAPTURE_DIR="$TMP/captures-failed" OMUX_FAKE_PREFLIGHT_FAIL=1 PATH="$BIN:$PATH" \
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
