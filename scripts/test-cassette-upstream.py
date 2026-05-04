#!/usr/bin/env python3
"""Cassette-replay upstream for in-session testing against real
chatgpt.com response shapes.

Bridges the cassette gap identified in
`docs/spec/test-and-coverage-review-2026-05-03.md` section 3: the
synthetic test-stub-upstream.py uses hand-crafted shapes derived
from source review, which can drift if upstream adds fields. This
script replays REAL response bytes captured from chatgpt.com via
`scripts/capture-codex-wire.sh proxy` (which uses the
codex-wire-addon.py mitmproxy filter to redact tokens before
writing).

Cassette format: a directory of JSON files, one per captured flow,
matching what `codex-wire-addon.py` writes. Each file:

    {
      "captured_at": <unix_ts>,
      "host": "chatgpt.com",
      "scheme": "https",
      "method": "POST",
      "path": "/backend-api/codex/responses",
      "request": {
        "headers": [["Name", "redacted-value"], ...],
        "body": <json or {"__non_json__": true, ...}>
      },
      "response": {
        "status": 200,
        "reason": "OK",
        "headers": [["Name", "value"], ...],
        "body": <json or {"__non_json__": true, ...}>
      },
      "timing_ms": <int>
    }

Replay strategy: match incoming requests to captures by
(method, path) tuple. If multiple captures match the same key,
cycle through them in capture-time order so a session that
captured "200, 200, 429" can be replayed in the same sequence.

Env (matching test-stub-upstream.py for harness compatibility):
  OMUX_CASSETTE_DIR        - required, path to directory of flow JSON
  OMUX_STUB_PORT           - bind port (default 0 = ephemeral)
  OMUX_STUB_PORTFILE       - port file (default /tmp/omux-cassette-upstream.port)
  OMUX_STUB_LOGFILE        - per-request log file

Failure modes:
  - No matching cassette for (method, path): returns 599 with body
    {"error":"no_cassette_match","method":...,"path":...}
  - Cassette dir is empty: server starts but every request errors
    (the harness should treat this as a setup failure)

This script does NOT generate cassettes. Use
`scripts/capture-codex-wire.sh proxy` for that. Once captures
exist under captures/codex-wire-<TS>/http/, point OMUX_CASSETTE_DIR
at that path.
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path


CASSETTE_DIR = os.environ.get("OMUX_CASSETTE_DIR")
PORT = int(os.environ.get("OMUX_STUB_PORT", "0"))
PORTFILE = Path(os.environ.get("OMUX_STUB_PORTFILE", "/tmp/omux-cassette-upstream.port"))
LOGFILE = Path(os.environ.get("OMUX_STUB_LOGFILE", "/tmp/omux-cassette-upstream.log"))


def _log(record: dict) -> None:
    record["ts"] = time.time()
    with LOGFILE.open("a") as f:
        f.write(json.dumps(record) + "\n")


def _load_cassettes(d: Path) -> dict[tuple[str, str], list[dict]]:
    """Load all flow JSON files; group by (method, path); sort by ts."""
    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    if not d.is_dir():
        return by_key
    for f in sorted(d.glob("*.json")):
        try:
            flow = json.loads(f.read_text())
        except Exception as e:
            print(f"cassette: skipping malformed {f.name}: {e}", file=sys.stderr)
            continue
        key = (flow.get("method", "GET"), flow.get("path", "/"))
        by_key[key].append(flow)
    for k in by_key:
        by_key[k].sort(key=lambda f: f.get("captured_at", 0))
    return by_key


# Per-key replay cursor. Each (method, path) advances independently;
# wraps around at the end of the captured sequence.
CURSORS: dict[tuple[str, str], int] = defaultdict(int)


class CassetteHandler(http.server.BaseHTTPRequestHandler):
    cassettes: dict[tuple[str, str], list[dict]] = {}

    def log_message(self, format, *args):  # noqa: A002
        return

    def _read_body(self) -> bytes:
        cl = self.headers.get("Content-Length")
        if cl:
            return self.rfile.read(int(cl))
        return b""

    def _serve(self) -> None:
        path = self.path
        # Strip query string for matching
        if "?" in path:
            path = path.split("?", 1)[0]
        body_in = self._read_body()
        _ = body_in

        key = (self.command, path)
        flows = self.cassettes.get(key, [])
        if not flows:
            self._send_error_no_match(key)
            return

        cursor = CURSORS[key] % len(flows)
        CURSORS[key] += 1
        flow = flows[cursor]
        resp = flow.get("response", {})
        status = resp.get("status", 200)
        body_obj = resp.get("body")
        if isinstance(body_obj, str):
            payload = body_obj.encode("utf-8")
            ct = "text/plain"
        elif isinstance(body_obj, dict) and body_obj.get("__non_json__"):
            # Non-JSON original; we have head_hex but not full bytes.
            # For replay we send a minimal body of the same length.
            payload = b"\x00" * body_obj.get("len", 0)
            ct = "application/octet-stream"
        else:
            payload = json.dumps(body_obj or {}).encode("utf-8")
            ct = "application/json"

        self.send_response(status)
        # Replay headers verbatim except framing-related ones we control
        for name, value in resp.get("headers", []):
            n = name.lower()
            if n in ("content-length", "transfer-encoding", "connection", "keep-alive"):
                continue
            self.send_header(name, value)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

        _log({
            "match": True,
            "key": list(key),
            "cursor": cursor,
            "captured_at": flow.get("captured_at"),
            "status_replayed": status,
        })

    def _send_error_no_match(self, key: tuple[str, str]) -> None:
        body = json.dumps({
            "error": "no_cassette_match",
            "method": key[0],
            "path": key[1],
            "available_keys": [list(k) for k in self.cassettes.keys()],
        }).encode("utf-8")
        self.send_response(599)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

        _log({
            "match": False,
            "key": list(key),
            "available": [list(k) for k in self.cassettes.keys()],
        })

    def do_POST(self):  # noqa: N802
        self._serve()

    def do_GET(self):  # noqa: N802
        self._serve()


def main() -> int:
    if not CASSETTE_DIR:
        print("cassette: OMUX_CASSETTE_DIR is required", file=sys.stderr)
        return 64
    d = Path(CASSETTE_DIR)
    cassettes = _load_cassettes(d)
    if not cassettes:
        print(f"cassette: no flows loaded from {d} - server will 599 every request", file=sys.stderr)

    LOGFILE.unlink(missing_ok=True)
    CassetteHandler.cassettes = cassettes
    httpd = http.server.HTTPServer(("127.0.0.1", PORT), CassetteHandler)
    actual_port = httpd.server_address[1]
    PORTFILE.write_text(f"{actual_port}\n")
    print(f"cassette-upstream: listening on 127.0.0.1:{actual_port}", file=sys.stderr, flush=True)
    print(f"cassette-upstream: loaded {sum(len(v) for v in cassettes.values())} flows across {len(cassettes)} (method,path) keys", file=sys.stderr, flush=True)
    print(f"cassette-upstream: portfile={PORTFILE} logfile={LOGFILE}", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
