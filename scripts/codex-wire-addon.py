"""mitmproxy addon for Phase 0 Codex wire-evidence capture.

Anchor: docs/spec/broker-mcp-contract-2026-05-03.md section 5 Phase 0.

Filters traffic for chatgpt.com/backend-api/codex/* (the target endpoint
of the future Codex adapter wire-layer proxy) and emits a per-flow JSON
file with redacted headers and body shape. Operator-reviewed,
fixture-sized per-flow JSON can be committed as evidence; raw
mitmproxy .flows files must not be committed.

Redactions:
  - Authorization values: keep scheme + first 6 chars + sha256(value)[:10]
  - Cookie and Set-Cookie values: keep names only, replace values with
    "<redacted>"
  - ChatGPT-Account-ID: keep first 6 chars + sha256(value)[:10]
  - Local home/tmp paths: replace with "~" or "<tmp>"
  - Body fields tokens.access_token / refresh_token / id_token: replace
    with sha256(value)[:10] (so swap-correctness can be argued from the
    capture without leaking material)
  - Textual non-JSON response bodies such as text/event-stream are kept
    as body_text for replay fidelity and must be manually reviewed before
    fixture promotion.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http


# Hosts we care about. Anything else we let pass without writing a per-
# flow JSON (the .flows binary still records it).
TARGET_HOST_SUFFIXES = (
    "chatgpt.com",
    "auth.openai.com",
    "auth0.openai.com",
)

# JSON keys whose values we hash-redact instead of removing entirely (so
# we can still argue cross-account swaps by hash equality).
HASH_REDACT_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "chatgptAccountId",
    "chatgpt_account_id",
    "accountId",
    "account_id",
}

TEXTUAL_CONTENT_TYPES = (
    "text/event-stream",
    "text/plain",
    "application/x-ndjson",
)


def _hash10(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:10]


def _redact_text(value: str) -> str:
    out = value
    home = os.environ.get("HOME")
    if home:
        out = out.replace(home, "~")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        out = out.replace(tmpdir.rstrip("/"), "<tmp>")
    return out.replace("/private/tmp/", "<tmp>/").replace("/tmp/", "<tmp>/")


def _redact_header(name: str, value: str) -> str:
    name_low = name.lower()
    if name_low == "authorization":
        # keep scheme + first 6 chars of token + hash
        parts = value.split(" ", 1)
        if len(parts) == 2:
            scheme, tok = parts
            head = tok[:6]
            return f"{scheme} {head}-<{_hash10(tok)}>"
        return f"<{_hash10(value)}>"
    if name_low == "cookie":
        # keep cookie names only
        names = []
        for chunk in value.split(";"):
            kv = chunk.strip().split("=", 1)
            if kv:
                names.append(kv[0])
        return "; ".join(f"{n}=<redacted>" for n in names)
    if name_low == "set-cookie":
        cookie = value.split(";", 1)[0].strip()
        name = cookie.split("=", 1)[0].strip() if cookie else "set-cookie"
        return f"{name}=<redacted>"
    if name_low == "chatgpt-account-id":
        return f"{value[:6]}-<{_hash10(value)}>"
    return _redact_text(value)


def _redact_obj(node: Any) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if isinstance(v, str) and k in HASH_REDACT_KEYS:
                out[k] = f"<{_hash10(v)}>"
            else:
                out[k] = _redact_obj(v)
        return out
    if isinstance(node, list):
        return [_redact_obj(x) for x in node]
    if isinstance(node, str):
        return _redact_text(node)
    return node


def _is_textual_content_type(content_type: str) -> bool:
    low = content_type.split(";", 1)[0].strip().lower()
    if low in TEXTUAL_CONTENT_TYPES:
        return True
    if low.endswith("+json"):
        return True
    return False


def _safe_body(b: bytes, content_type: str) -> Any:
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        out: dict[str, Any] = {
            "__non_json__": True,
            "len": len(b),
            "head_hex": b[:64].hex(),
        }
        if b and _is_textual_content_type(content_type):
            out["text_encoding"] = "utf-8"
            out["body_text"] = b.decode("utf-8", "replace")
        return out


class CodexWireAddon:
    def __init__(self) -> None:
        self.run_dir: Path | None = None
        self.flow_count = 0

    def load(self, loader) -> None:  # mitmproxy lifecycle
        loader.add_option(
            name="capture_run_dir",
            typespec=str,
            default="",
            help="oauth-mux Codex wire capture run directory",
        )

    def configure(self, updated):  # mitmproxy lifecycle
        d = getattr(ctx.options, "capture_run_dir", "") or None
        if not d:
            d = os.environ.get("OMUX_CAPTURE_RUN_DIR")
        if d:
            self.run_dir = Path(d)
            (self.run_dir / "http").mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow) -> None:  # noqa: D401
        # nothing: we record on response so we get full pair
        return

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host or ""
        if not any(host.endswith(s) for s in TARGET_HOST_SUFFIXES):
            return
        if self.run_dir is None:
            return

        self.flow_count += 1
        idx = f"{self.flow_count:05d}"
        path_safe = flow.request.path.replace("/", "_").replace("?", "_").lstrip("_") or "root"
        out = self.run_dir / "http" / f"{idx}-{flow.request.method}-{path_safe[:80]}.json"

        req_headers = [(k, _redact_header(k, v)) for k, v in flow.request.headers.items()]
        resp_headers = [(k, _redact_header(k, v)) for k, v in flow.response.headers.items()]

        req_body = _redact_obj(_safe_body(
            flow.request.raw_content or b"",
            flow.request.headers.get("content-type", ""),
        ))
        resp_body = _redact_obj(_safe_body(
            flow.response.raw_content or b"",
            flow.response.headers.get("content-type", ""),
        ))

        record = {
            "captured_at": time.time(),
            "host": host,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "path": flow.request.path,
            "request": {
                "headers": req_headers,
                "body": req_body,
            },
            "response": {
                "status": flow.response.status_code,
                "reason": flow.response.reason,
                "headers": resp_headers,
                "body": resp_body,
            },
            "timing_ms": int(((flow.response.timestamp_end or 0) - (flow.request.timestamp_start or 0)) * 1000),
        }

        out.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str))
        ctx.log.info(f"codex-wire: recorded {idx} {flow.request.method} {flow.request.path} -> {flow.response.status_code}")


addons = [CodexWireAddon()]
