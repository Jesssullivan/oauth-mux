#!/usr/bin/env python3
"""Summarize oauth-mux Codex adapter NDJSON status evidence.

This intentionally distinguishes brokered-session evidence from account-swap
evidence. A status file with many 200s through the proxy is useful, but it is
not live fallback proof unless a quota event and fallback account turn appear
in order.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if isinstance(value, dict):
                events.append(value)
    return events


def event_key_count(events: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for event in events:
        value = event.get(key)
        if value is not None:
            counts[str(value)] += 1
    return dict(sorted(counts.items()))


def find_fallback_sequence(events: list[dict[str, Any]]) -> dict[str, Any]:
    quota_idx: int | None = None
    retry_idx: int | None = None
    quota_account: str | None = None
    retry_event: dict[str, Any] | None = None
    fallback_turn: dict[str, Any] | None = None

    for idx, event in enumerate(events):
        if event.get("kind") != "proxy_turn":
            continue
        if (
            event.get("status") == 429
            and event.get("classification") == "quota_exhausted"
        ):
            quota_idx = idx
            quota_account = event.get("account")
            break

    if quota_idx is None:
        return {
            "observed": False,
            "reason": "no quota_exhausted proxy_turn",
        }

    for idx in range(quota_idx + 1, len(events)):
        event = events[idx]
        if event.get("kind") == "proxy_same_turn_retry":
            retry_idx = idx
            retry_event = event
            break

    if retry_idx is None:
        return {
            "observed": False,
            "reason": "quota_exhausted without proxy_same_turn_retry",
            "quota_account": quota_account,
        }

    for event in events[retry_idx + 1 :]:
        if event.get("kind") != "proxy_turn":
            continue
        if event.get("account") != quota_account and event.get("status") == 200:
            fallback_turn = event
            break

    if fallback_turn is None:
        return {
            "observed": False,
            "reason": "same-turn retry without successful fallback-account turn",
            "quota_account": quota_account,
            "retry": retry_event,
        }

    return {
        "observed": True,
        "quota_account": quota_account,
        "fallback_account": fallback_turn.get("account"),
        "retry": retry_event,
        "fallback_status": fallback_turn.get("status"),
        "fallback_path_kind": fallback_turn.get("path_kind"),
    }


def summarize(path: Path) -> dict[str, Any]:
    events = load_events(path)
    proxy_turns = [e for e in events if e.get("kind") == "proxy_turn"]
    session_started = next((e for e in events if e.get("kind") == "session_started"), {})
    session_ended = next((e for e in reversed(events) if e.get("kind") == "session_ended"), {})
    fallback = find_fallback_sequence(events)

    brokered_session = (
        session_started.get("claim_level") == "broker_owned"
        or session_started.get("claim_level") == "broker_owned_app_server"
        or session_ended.get("final_claim_level") == "broker_owned"
    )

    return {
        "path": str(path),
        "events": len(events),
        "brokered_session_observed": brokered_session,
        "selected_account": session_started.get("selected_account"),
        "session_authority": session_started.get("session_authority"),
        "proxy_turns": len(proxy_turns),
        "proxy_turns_by_account": event_key_count(proxy_turns, "account"),
        "proxy_turns_by_status": event_key_count(proxy_turns, "status"),
        "proxy_turns_by_path_kind": event_key_count(proxy_turns, "path_kind"),
        "proxy_turns_by_body_class": event_key_count(proxy_turns, "body_class"),
        "same_turn_retry_events": sum(1 for e in events if e.get("kind") == "proxy_same_turn_retry"),
        "same_turn_retry_unavailable_events": sum(
            1 for e in events if e.get("kind") == "proxy_same_turn_retry_unavailable"
        ),
        "post_swap_turn_events": sum(1 for e in events if e.get("kind") == "proxy_post_swap_turn"),
        "fallback_sequence": fallback,
        "synthetic_swap_observed": bool(session_ended.get("synthetic_swap_observed")),
        "level4_shape_observed": bool(fallback.get("observed")),
        "provider_originated_live_fallback_claim": False,
        "verdict": (
            "fallback_sequence_observed"
            if fallback.get("observed")
            else "brokered_without_fallback"
            if brokered_session and proxy_turns
            else "insufficient_evidence"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("status_file", type=Path)
    parser.add_argument("--require-brokered", action="store_true")
    parser.add_argument("--require-fallback-sequence", action="store_true")
    args = parser.parse_args()

    summary = summarize(args.status_file)
    print(json.dumps(summary, sort_keys=True))

    if args.require_brokered and not summary["brokered_session_observed"]:
        return 1
    if args.require_fallback_sequence and not summary["fallback_sequence"]["observed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
