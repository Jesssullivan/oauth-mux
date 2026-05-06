#!/usr/bin/env python3
"""Review redacted Codex wire captures before fixture promotion.

This is a local/offline safety check for captures produced by
scripts/capture-codex-wire.sh proxy. It does not inspect raw mitmproxy
.flows files. It reads only the addon-produced per-flow JSON and reports
endpoint/status coverage plus obvious redaction failures.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOKEN_PATTERNS = [
    re.compile(r"Bearer\s+(?![A-Za-z0-9_-]{0,8}-<)[A-Za-z0-9._~-]{24,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
]


def _walk_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


def _path_kind(path: str) -> str:
    if path == "/backend-api/codex/responses" or path.startswith("/backend-api/codex/responses?"):
        return "responses"
    if path == "/backend-api/codex/responses/compact" or path.startswith("/backend-api/codex/responses/compact?"):
        return "responses_compact"
    if "/backend-api/codex/memories/trace_summarize" in path:
        return "memories_trace_summarize"
    if path.startswith("/backend-api/codex/"):
        return "codex_other"
    if "/oauth/token" in path:
        return "oauth_token"
    return "other"


def _find_http_dir(path: Path) -> Path:
    if path.is_dir() and (path / "http").is_dir():
        return path / "http"
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture_dir", help="capture run dir or its http/ subdir")
    parser.add_argument("--json", action="store_true", help="emit machine-readable summary")
    args = parser.parse_args()

    http_dir = _find_http_dir(Path(args.capture_dir))
    if not http_dir.is_dir():
        print(f"error: not a directory: {http_dir}", file=sys.stderr)
        return 64

    flows = []
    redaction_failures: list[str] = []
    malformed: list[str] = []
    path_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    quota_shapes: list[dict[str, Any]] = []

    for p in sorted(http_dir.glob("*.json")):
        try:
            record = json.loads(p.read_text())
        except Exception as exc:  # noqa: BLE001
            malformed.append(f"{p.name}: {exc}")
            continue

        flows.append(record)
        path = str(record.get("path", ""))
        kind = _path_kind(path)
        path_counts[kind] = path_counts.get(kind, 0) + 1

        status = record.get("response", {}).get("status")
        status_key = str(status)
        status_counts[status_key] = status_counts.get(status_key, 0) + 1

        response_body = record.get("response", {}).get("body")
        if status == 429 and isinstance(response_body, dict):
            err = response_body.get("error")
            if isinstance(err, dict):
                quota_shapes.append({
                    "path_kind": kind,
                    "error_type": err.get("type"),
                    "has_resets_at": "resets_at" in err,
                    "plan_type": err.get("plan_type"),
                })

        for s in _walk_strings(record):
            for pat in TOKEN_PATTERNS:
                if pat.search(s):
                    redaction_failures.append(f"{p.name}: possible secret-like value matched {pat.pattern}")
                    break

    summary = {
        "ok": not malformed and not redaction_failures,
        "flow_count": len(flows),
        "path_counts": path_counts,
        "status_counts": status_counts,
        "quota_shapes": quota_shapes,
        "malformed": malformed,
        "redaction_failures": redaction_failures,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"flows: {summary['flow_count']}")
        print(f"paths: {json.dumps(path_counts, sort_keys=True)}")
        print(f"statuses: {json.dumps(status_counts, sort_keys=True)}")
        if quota_shapes:
            print(f"quota_shapes: {json.dumps(quota_shapes, sort_keys=True)}")
        if malformed:
            print("malformed:")
            for item in malformed:
                print(f"  - {item}")
        if redaction_failures:
            print("redaction_failures:")
            for item in redaction_failures:
                print(f"  - {item}")

    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
