#!/usr/bin/env python3
"""Validate cross-field route-state relationships JSON Schema cannot express.

Companion to schemas/route-state-v2.schema.json (TIN-1803). Callers should
run that schema against the fixture first -- this script only checks the
semantic rules layered on top, mirroring
scripts/validate-managed-harness-instance.py's structure.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# Anything that looks like a raw email or a bare account-id shape must never
# appear in route_handle -- handles are opaque, per the managed-harness-v2
# idiom this schema reuses.
RAW_LOOKING_HANDLE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class ContractError(ValueError):
    pass


def validate(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise ContractError("route-state record must be an object")

    state = document.get("state")
    provenance = document.get("provenance")
    route_handle = document.get("route_handle")

    if state == "unknown" and provenance != "never_probed":
        raise ContractError(
            "state=unknown must carry provenance=never_probed -- "
            "unknown means never actually probed, not probed and inconclusive"
        )

    if state != "unknown" and provenance == "never_probed":
        raise ContractError(
            "provenance=never_probed is only legal for state=unknown"
        )

    if "trusted_reset_at_ms" in document and state not in ("rate_limited", "quota_exhausted"):
        raise ContractError(
            "trusted_reset_at_ms is only meaningful for rate_limited/quota_exhausted, "
            f"got state={state!r}"
        )

    if isinstance(route_handle, str) and RAW_LOOKING_HANDLE.search(route_handle):
        raise ContractError(
            f"route_handle {route_handle!r} looks like a raw email/account id, "
            "not an opaque handle"
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-route-state-instance.py <fixture.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
