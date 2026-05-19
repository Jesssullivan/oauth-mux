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

printf 'smoke-codex-capture-review: all assertions passed.\n'
