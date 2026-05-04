#!/usr/bin/env python3
"""Stub upstream HTTP server for in-session Codex acceptance smoke.

Emulates the surface of `chatgpt.com/backend-api/codex/responses`
just enough to drive the wire proxy's classification matrix
through a full quota-exhaust → swap → recover sequence WITHOUT
any real Codex traffic.

Behavior (configurable via env):
  OMUX_STUB_PORT      — bind port (default 0 = ephemeral; written to
                        OMUX_STUB_PORTFILE so the harness can read it)
  OMUX_STUB_PORTFILE  — path to write the chosen port (default
                        /tmp/omux-stub-upstream.port)
  OMUX_STUB_OK_BEFORE_429 — number of 200 responses before 429 fires
                            for ANY GIVEN account-id (default 2)
  OMUX_STUB_LOGFILE   — path to append per-request JSON log lines
                        (default /tmp/omux-stub-upstream.log)

Per request:
  - Logs a JSON line with: ts, path, method, account_id (from
    ChatGPT-Account-ID header), auth_prefix (first 6 chars of the
    Bearer token + sha256 hash[:10] for redacted correlation),
    status_returned, response_classification.
  - If the request count for THIS ChatGPT-Account-ID has not yet
    crossed OMUX_STUB_OK_BEFORE_429, return 200 with a tiny SSE-shaped
    body.
  - Else, return 429 + JSON body
    {"error":{"type":"usage_limit_reached","plan_type":"pro","resets_at":<unix+86400>}}
    once (per account). After one 429 for an account, that account
    stays 429 until process restart.

This is enough for the proxy to:
  1. classify 200 as ok for the elected account
  2. classify 429+usage_limit_reached as quota_exhausted
  3. mark that account in the pool
  4. on next request, elect a different account (the broker's
     account/swap semantics)
  5. proxy_post_swap_turn fires (proxy notices account change,
     drops x-codex-turn-state)
  6. that next request lands on the new account at the stub
  7. stub sees the new account_id, returns 200 (per-account counter)

The harness asserts the NDJSON status frames on stderr from
`oauth-mux codex run` for the right shape + ordering.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


PORT = int(os.environ.get("OMUX_STUB_PORT", "0"))
PORTFILE = Path(os.environ.get("OMUX_STUB_PORTFILE", "/tmp/omux-stub-upstream.port"))
OK_BEFORE_429 = int(os.environ.get("OMUX_STUB_OK_BEFORE_429", "2"))
LOGFILE = Path(os.environ.get("OMUX_STUB_LOGFILE", "/tmp/omux-stub-upstream.log"))

# OMUX_STUB_429_TYPE chooses what the stub returns once an account
# crosses OK_BEFORE_429:
#   "usage_limit_reached" (default) — the swap-eligible quota path
#   "usage_not_included"           — the plan-tier path; MUST NOT swap
#   "rate_limited"                 — bare 429 with no error.type body
ERROR_TYPE = os.environ.get("OMUX_STUB_429_TYPE", "usage_limit_reached")

# OMUX_STUB_ALWAYS_STATUS forces the stub to return this HTTP status
# on every request, regardless of OK_BEFORE_429 / 429_TYPE. Used by
# negative-path smokes that need a steady-state 401 / 5xx / etc to
# verify proxy classification + behavior end-to-end.
ALWAYS_STATUS = os.environ.get("OMUX_STUB_ALWAYS_STATUS", "")


# Per-account request counter. Reset only on process restart.
ACCOUNT_REQ_COUNT: dict[str, int] = {}


def _hash10(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:10]


def _log(record: dict) -> None:
    record["ts"] = time.time()
    with LOGFILE.open("a") as f:
        f.write(json.dumps(record) + "\n")


class StubHandler(http.server.BaseHTTPRequestHandler):
    # Silence default access logging — we do our own structured logs.
    def log_message(self, format, *args):  # noqa: A002
        return

    def _read_body(self) -> bytes:
        cl = self.headers.get("Content-Length")
        if cl:
            return self.rfile.read(int(cl))
        # Chunked is unlikely from the proxy (proxy decodes to
        # Content-Length on its way out). Best-effort.
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            buf = bytearray()
            while True:
                size_line = self.rfile.readline().strip()
                if not size_line:
                    break
                size = int(size_line, 16)
                if size == 0:
                    self.rfile.readline()  # final CRLF
                    break
                buf += self.rfile.read(size)
                self.rfile.readline()  # CRLF
            return bytes(buf)
        return b""

    def _account_id(self) -> str:
        return self.headers.get("ChatGPT-Account-ID", "<missing>")

    def _auth_prefix(self) -> str:
        a = self.headers.get("Authorization", "")
        parts = a.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1][:6] + ":" + _hash10(parts[1])
        return _hash10(a) if a else "<missing>"

    def _classify_for_account(self) -> tuple[int, dict]:
        # OMUX_STUB_ALWAYS_STATUS short-circuits everything: return
        # this exact status with a minimal JSON body. Counters still
        # advance so per-account log records remain unique.
        if ALWAYS_STATUS:
            try:
                code = int(ALWAYS_STATUS)
            except ValueError:
                code = 500
            ACCOUNT_REQ_COUNT[self._account_id()] = ACCOUNT_REQ_COUNT.get(self._account_id(), 0) + 1
            return code, {"detail": f"forced status {code}"}

        acct = self._account_id()
        n = ACCOUNT_REQ_COUNT.get(acct, 0)
        ACCOUNT_REQ_COUNT[acct] = n + 1
        if n < OK_BEFORE_429:
            # Healthy turn: tiny SSE-shaped body
            body = (
                "event: response.created\n"
                'data: {"type":"response.created","response":{"id":"resp-stub"}}\n\n'
                "event: response.completed\n"
                'data: {"type":"response.completed","response":{"id":"resp-stub","output":[]}}\n\n'
            )
            return 200, {"_text": body, "_ct": "text/event-stream"}
        # 429 path. Body shape selected by OMUX_STUB_429_TYPE so the
        # harness can drive the swap-eligible (usage_limit_reached)
        # vs non-swap (usage_not_included, rate_limited) paths through
        # the same fixture surface.
        if ERROR_TYPE == "usage_not_included":
            body = {
                "error": {
                    "type": "usage_not_included",
                    "plan_type": "free",
                },
            }
        elif ERROR_TYPE == "rate_limited":
            body = {"detail": "Too Many Requests"}
        else:
            body = {
                "error": {
                    "type": "usage_limit_reached",
                    "plan_type": "pro",
                    "resets_at": int(time.time()) + 86400,
                },
            }
        return 429, body

    def _serve(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/backend-api/codex"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        body_bytes = self._read_body()
        _ = body_bytes  # request bodies are unused; we don't echo

        status, body = self._classify_for_account()
        if "_text" in body:
            text = body["_text"]
            payload = text.encode("utf-8")
            ct = body["_ct"]
        else:
            payload = json.dumps(body).encode("utf-8")
            ct = "application/json"

        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

        _log({
            "path": path,
            "method": self.command,
            "account_id": self._account_id(),
            "auth_prefix": self._auth_prefix(),
            "status_returned": status,
            "response_classification": "ok" if status == 200 else "quota_exhausted" if status == 429 else "other",
        })

    def do_POST(self):  # noqa: N802
        self._serve()

    def do_GET(self):  # noqa: N802
        self._serve()


def main() -> int:
    LOGFILE.unlink(missing_ok=True)
    httpd = http.server.HTTPServer(("127.0.0.1", PORT), StubHandler)
    actual_port = httpd.server_address[1]
    PORTFILE.write_text(f"{actual_port}\n")
    print(f"stub-upstream: listening on 127.0.0.1:{actual_port}", file=sys.stderr, flush=True)
    print(f"stub-upstream: portfile={PORTFILE}", file=sys.stderr, flush=True)
    print(f"stub-upstream: logfile={LOGFILE}", file=sys.stderr, flush=True)
    print(f"stub-upstream: ok_before_429={OK_BEFORE_429} per account", file=sys.stderr, flush=True)
    print(f"stub-upstream: 429_type={ERROR_TYPE}", file=sys.stderr, flush=True)
    if ALWAYS_STATUS:
        print(f"stub-upstream: always_status={ALWAYS_STATUS} (overrides classification)", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
