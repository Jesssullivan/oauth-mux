#!/usr/bin/env bash
# Synthetic replay smoke for the Codex wire cassette layer.
#
# This does not require mitmproxy, real Codex, or provider traffic. It writes
# a tiny scrubbed cassette in the same format as codex-wire-addon.py, starts
# test-cassette-upstream.py, and verifies method/path matching, per-key cursor
# cycling, query stripping, 429 body replay, and diagnostic misses.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "smoke-codex-cassette-replay: python3 required" >&2
    exit 64
fi

TMP="$(mktemp -d -t omux-cassette.XXXXXX)"
CASSETTE="$TMP/cassette"
PORTFILE="$TMP/cassette.port"
LOGFILE="$TMP/cassette.log"
SERVER_ERR="$TMP/cassette.stderr"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$CASSETTE"

python3 - "$CASSETTE" <<'PY'
import json
import pathlib
import sys

d = pathlib.Path(sys.argv[1])

ok_body = 'event: response.completed\ndata: {"type":"response.completed"}\n\n'

flows = [
    {
        "captured_at": 1788000000.001,
        "host": "chatgpt.com",
        "scheme": "https",
        "method": "POST",
        "path": "/backend-api/codex/responses?captured=query",
        "request": {
            "headers": [
                ["Authorization", "Bearer synth-<redacted>"],
                ["ChatGPT-Account-ID", "acct-a-<redacted>"],
            ],
            "body": {"model": "gpt-5.5"},
        },
        "response": {
            "status": 200,
            "reason": "OK",
            "headers": [["Content-Type", "text/event-stream"]],
            "body": {
                "__non_json__": True,
                "len": len(ok_body.encode("utf-8")),
                "head_hex": ok_body.encode("utf-8")[:64].hex(),
                "text_encoding": "utf-8",
                "body_text": ok_body,
            },
        },
        "timing_ms": 12,
    },
    {
        "captured_at": 1788000000.002,
        "host": "chatgpt.com",
        "scheme": "https",
        "method": "POST",
        "path": "/backend-api/codex/responses",
        "request": {
            "headers": [
                ["Authorization", "Bearer synth-<redacted>"],
                ["ChatGPT-Account-ID", "acct-a-<redacted>"],
            ],
            "body": {"model": "gpt-5.5"},
        },
        "response": {
            "status": 429,
            "reason": "Too Many Requests",
            "headers": [
                ["Content-Type", "application/json"],
                ["x-codex-active-limit", "weekly"],
            ],
            "body": {
                "error": {
                    "type": "usage_limit_reached",
                    "plan_type": "pro",
                    "resets_at": 1788003600,
                }
            },
        },
        "timing_ms": 8,
    },
]

for i, flow in enumerate(flows, 1):
    (d / f"{i:05d}-POST-backend-api-codex-responses.json").write_text(
        json.dumps(flow, indent=2) + "\n"
    )
PY

OMUX_CASSETTE_DIR="$CASSETTE" \
  OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$PORTFILE" \
  OMUX_STUB_LOGFILE="$LOGFILE" \
  python3 "$ROOT/scripts/test-cassette-upstream.py" 2>"$SERVER_ERR" &
SERVER_PID=$!

python3 - "$PORTFILE" "$LOGFILE" "$SERVER_ERR" <<'PY'
import http.client
import json
import pathlib
import sys
import time

portfile = pathlib.Path(sys.argv[1])
logfile = pathlib.Path(sys.argv[2])
server_err = pathlib.Path(sys.argv[3])

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    if portfile.exists() and portfile.read_text().strip():
        break
    time.sleep(0.05)
else:
    print("smoke-codex-cassette-replay: cassette server did not write port", file=sys.stderr)
    print(server_err.read_text() if server_err.exists() else "", file=sys.stderr)
    raise SystemExit(1)

port = int(portfile.read_text().strip())

def post(path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            path,
            body=b'{"input":"synthetic"}',
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer not-real",
                "ChatGPT-Account-ID": "not-real",
            },
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, body
    finally:
        conn.close()

status1, body1 = post("/backend-api/codex/responses")
assert status1 == 200, (status1, body1)
assert "response.completed" in body1, body1

status2, body2 = post("/backend-api/codex/responses")
assert status2 == 429, (status2, body2)
err = json.loads(body2)["error"]
assert err["type"] == "usage_limit_reached", err
assert err["plan_type"] == "pro", err
assert err["resets_at"] == 1788003600, err

status3, body3 = post("/backend-api/codex/responses?ignored=query")
assert status3 == 200, (status3, body3)
assert "response.completed" in body3, body3

status4, body4 = post("/backend-api/codex/missing")
assert status4 == 599, (status4, body4)
miss = json.loads(body4)
assert miss["error"] == "no_cassette_match", miss
assert miss["path"] == "/backend-api/codex/missing", miss

deadline = time.monotonic() + 2
while True:
    records = [json.loads(line) for line in logfile.read_text().splitlines() if line.strip()]
    if len(records) >= 4 or time.monotonic() >= deadline:
        break
    time.sleep(0.02)
matches = [r for r in records if r.get("match") is True]
misses = [r for r in records if r.get("match") is False]
assert len(matches) == 3, records
assert [r["status_replayed"] for r in matches] == [200, 429, 200], records
assert len(misses) == 1, records

print("smoke-codex-cassette-replay: all 12 assertions passed.")
print(f"  cassette dir: {portfile.parent / 'cassette'}")
print(f"  replay log: {logfile}")
PY

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
unset SERVER_PID

FIXTURE="$ROOT/test/fixtures/codex-wire/auth-refresh-token-expired/http"
FIXTURE_PORTFILE="$TMP/auth-fixture.port"
FIXTURE_LOGFILE="$TMP/auth-fixture.log"
FIXTURE_ERR="$TMP/auth-fixture.stderr"

OMUX_CASSETTE_DIR="$FIXTURE" \
  OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$FIXTURE_PORTFILE" \
  OMUX_STUB_LOGFILE="$FIXTURE_LOGFILE" \
  python3 "$ROOT/scripts/test-cassette-upstream.py" 2>"$FIXTURE_ERR" &
SERVER_PID=$!

python3 - "$FIXTURE_PORTFILE" "$FIXTURE_LOGFILE" "$FIXTURE_ERR" <<'PY'
import http.client
import json
import pathlib
import sys
import time

portfile = pathlib.Path(sys.argv[1])
logfile = pathlib.Path(sys.argv[2])
server_err = pathlib.Path(sys.argv[3])

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    if portfile.exists() and portfile.read_text().strip():
        break
    time.sleep(0.05)
else:
    print("smoke-codex-cassette-replay: auth fixture server did not write port", file=sys.stderr)
    print(server_err.read_text() if server_err.exists() else "", file=sys.stderr)
    raise SystemExit(1)

port = int(portfile.read_text().strip())

def request(method: str, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=b"{}" if method == "POST" else None)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, body
    finally:
        conn.close()

status1, body1 = request("POST", "/oauth/token")
assert status1 == 401, (status1, body1)
assert json.loads(body1)["error"]["code"] == "redacted_refresh_reused", body1

status2, body2 = request("GET", "/backend-api/codex/responses")
assert status2 == 401, (status2, body2)
err = json.loads(body2)["error"]
assert err["code"] == "token_expired", err

deadline = time.monotonic() + 2
while True:
    records = [json.loads(line) for line in logfile.read_text().splitlines() if line.strip()]
    if len(records) >= 2 or time.monotonic() >= deadline:
        break
    time.sleep(0.02)
assert [r["status_replayed"] for r in records if r.get("match") is True] == [401, 401], records

print("smoke-codex-cassette-replay: auth failure fixture replay passed.")
PY

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
unset SERVER_PID

WS_FIXTURE="$ROOT/test/fixtures/codex-wire/broker-owned-websocket-success/http"
WS_PORTFILE="$TMP/ws-fixture.port"
WS_LOGFILE="$TMP/ws-fixture.log"
WS_ERR="$TMP/ws-fixture.stderr"

OMUX_CASSETTE_DIR="$WS_FIXTURE" \
  OMUX_STUB_PORT=0 \
  OMUX_STUB_PORTFILE="$WS_PORTFILE" \
  OMUX_STUB_LOGFILE="$WS_LOGFILE" \
  python3 "$ROOT/scripts/test-cassette-upstream.py" 2>"$WS_ERR" &
SERVER_PID=$!

python3 - "$WS_PORTFILE" "$WS_LOGFILE" "$WS_ERR" <<'PY'
import http.client
import json
import pathlib
import sys
import time

portfile = pathlib.Path(sys.argv[1])
logfile = pathlib.Path(sys.argv[2])
server_err = pathlib.Path(sys.argv[3])

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    if portfile.exists() and portfile.read_text().strip():
        break
    time.sleep(0.05)
else:
    print("smoke-codex-cassette-replay: websocket fixture server did not write port", file=sys.stderr)
    print(server_err.read_text() if server_err.exists() else "", file=sys.stderr)
    raise SystemExit(1)

port = int(portfile.read_text().strip())
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
try:
    conn.request(
        "GET",
        "/backend-api/codex/responses",
        headers={
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "not-real",
        },
    )
    resp = conn.getresponse()
    body = resp.read()
finally:
    conn.close()

assert resp.status == 101, (resp.status, body)
assert body == b"", body

deadline = time.monotonic() + 2
while True:
    if logfile.exists():
        records = [json.loads(line) for line in logfile.read_text().splitlines() if line.strip()]
    else:
        records = []
    if len(records) >= 1 or time.monotonic() >= deadline:
        break
    time.sleep(0.02)
assert [r["status_replayed"] for r in records if r.get("match") is True] == [101], records

print("smoke-codex-cassette-replay: websocket success fixture replay passed.")
PY

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
unset SERVER_PID
