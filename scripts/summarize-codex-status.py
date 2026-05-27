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
    quota_turn: dict[str, Any] | None = None
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
            quota_turn = event
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
        "quota_turn": quota_turn,
        "fallback_account": fallback_turn.get("account"),
        "retry": retry_event,
        "fallback_status": fallback_turn.get("status"),
        "fallback_path_kind": fallback_turn.get("path_kind"),
    }


def find_quota_handoff_failure(events: list[dict[str, Any]]) -> dict[str, Any]:
    quota_idx: int | None = None
    quota_account: str | None = None
    failure_event: dict[str, Any] | None = None

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

    for event in events[quota_idx + 1 :]:
        kind = event.get("kind")
        if (
            kind == "proxy_turn"
            and event.get("account") != quota_account
            and event.get("status") == 200
        ):
            return {
                "observed": False,
                "reason": "quota_handoff_succeeded_before_terminal_failure",
                "quota_account": quota_account,
            }
        if kind == "quota_handoff_failed_no_account_selectable":
            failure_event = event
            break
        if kind == "proxy_same_turn_retry_unavailable" and failure_event is None:
            failure_event = event
            continue
        if kind == "proxy_no_account_selectable":
            failure_event = event
            break

    if failure_event is None:
        return {
            "observed": False,
            "reason": "quota_exhausted without terminal no-account evidence",
            "quota_account": quota_account,
        }

    raw_rejections = failure_event.get("rejections")
    rejections = raw_rejections if isinstance(raw_rejections, list) else []
    reason = failure_event.get("reason")
    if not isinstance(reason, str):
        reason = failure_event.get("err")
    if not isinstance(reason, str):
        reason = "no_account_selectable"

    return {
        "observed": True,
        "quota_account": quota_account,
        "reason": reason,
        "event": failure_event,
        "rejections": rejections,
        "user_visible_failure_likely": bool(
            failure_event.get("user_visible_failure_likely")
        )
        or failure_event.get("kind")
        in {"proxy_no_account_selectable", "quota_handoff_failed_no_account_selectable"},
    }


def find_auth_fallback_sequence(events: list[dict[str, Any]]) -> dict[str, Any]:
    auth_idx: int | None = None
    auth_account: str | None = None
    retry_events: list[dict[str, Any]] = []
    terminal_retry_event: dict[str, Any] | None = None
    fallback_turn: dict[str, Any] | None = None

    for idx, event in enumerate(events):
        if event.get("kind") != "proxy_turn":
            continue
        if (
            event.get("status") == 401
            and event.get("classification") == "auth_unauthorized"
        ):
            auth_idx = idx
            auth_account = event.get("account")
            break

    if auth_idx is None:
        return {
            "observed": False,
            "reason": "no auth_unauthorized proxy_turn",
        }

    for event in events[auth_idx + 1 :]:
        if event.get("kind") == "proxy_auth_same_turn_retry":
            retry_events.append(event)
            continue
        if event.get("kind") != "proxy_turn":
            continue
        if event.get("status") != 200:
            continue

        if not retry_events:
            continue
        latest_retry = retry_events[-1]
        if event.get("account") == latest_retry.get("to"):
            fallback_turn = event
            terminal_retry_event = latest_retry
            break

    if not retry_events:
        return {
            "observed": False,
            "reason": "auth_unauthorized without proxy_auth_same_turn_retry",
            "auth_account": auth_account,
        }

    if fallback_turn is None:
        return {
            "observed": False,
            "reason": "auth retry without successful fallback-account turn",
            "auth_account": auth_account,
            "retry": retry_events[-1],
            "retries": retry_events,
        }

    return {
        "observed": True,
        "auth_account": auth_account,
        "fallback_account": fallback_turn.get("account"),
        "retry": terminal_retry_event,
        "retries": retry_events,
        "retry_count": len(retry_events),
        "fallback_status": fallback_turn.get("status"),
        "fallback_path_kind": fallback_turn.get("path_kind"),
    }


def find_transport_recovery_sequence(events: list[dict[str, Any]]) -> dict[str, Any]:
    failure_event: dict[str, Any] | None = None
    retry_event: dict[str, Any] | None = None
    recovery_turn: dict[str, Any] | None = None

    for idx, event in enumerate(events):
        if event.get("kind") != "proxy_upstream_failed":
            continue
        failure_event = event
        failure_account = event.get("account")

        for later in events[idx + 1 :]:
            kind = later.get("kind")
            if kind == "proxy_provider_same_turn_retry":
                retry_event = later
                continue
            if kind != "proxy_turn" or later.get("status") != 200:
                continue
            if retry_event is not None and later.get("account") == retry_event.get("to"):
                recovery_turn = later
                break
            if failure_account is not None and later.get("account") != failure_account:
                recovery_turn = later
                break
        break

    if failure_event is None:
        return {
            "observed": False,
            "reason": "no proxy_upstream_failed event",
        }
    if recovery_turn is None:
        return {
            "observed": False,
            "reason": "upstream failure without successful fallback turn",
            "failure": failure_event,
            "retry": retry_event,
        }
    return {
        "observed": True,
        "failure": failure_event,
        "retry": retry_event,
        "fallback_account": recovery_turn.get("account"),
        "fallback_status": recovery_turn.get("status"),
        "fallback_path_kind": recovery_turn.get("path_kind"),
    }


def find_local_transport_recovery_sequence(events: list[dict[str, Any]]) -> dict[str, Any]:
    retry_event: dict[str, Any] | None = None
    recovered_event: dict[str, Any] | None = None

    for idx, event in enumerate(events):
        if event.get("kind") != "proxy_transport_local_retry":
            continue
        retry_event = event
        retry_account = event.get("account")

        for later in events[idx + 1 :]:
            if later.get("kind") == "proxy_transport_local_retry_recovered":
                if retry_account is None or later.get("account") == retry_account:
                    recovered_event = later
                    break
        break

    if retry_event is None:
        return {
            "observed": False,
            "reason": "no proxy_transport_local_retry event",
        }
    if recovered_event is None:
        return {
            "observed": False,
            "reason": "local transport retry without recovery event",
            "retry": retry_event,
        }
    return {
        "observed": True,
        "retry": retry_event,
        "recovered": recovered_event,
        "account": recovered_event.get("account"),
        "status": recovered_event.get("status"),
        "path_kind": recovered_event.get("path_kind"),
        "attempts": recovered_event.get("attempts"),
    }


def summarize(path: Path) -> dict[str, Any]:
    events = load_events(path)
    proxy_turns = [e for e in events if e.get("kind") == "proxy_turn"]
    launch_timing_events = [e for e in events if e.get("kind") == "launch_timing"]
    session_started = next((e for e in events if e.get("kind") == "session_started"), {})
    session_ended = next((e for e in reversed(events) if e.get("kind") == "session_ended"), {})
    session_aborted = next((e for e in reversed(events) if e.get("kind") == "session_aborted"), {})
    terminal_event = next(
        (
            e
            for e in reversed(events)
            if e.get("kind") in ("session_ended", "session_aborted")
        ),
        {},
    )
    fallback = find_fallback_sequence(events)
    quota_failure = find_quota_handoff_failure(events)
    auth_fallback = find_auth_fallback_sequence(events)
    transport_recovery = find_transport_recovery_sequence(events)
    local_transport_recovery = find_local_transport_recovery_sequence(events)
    auth_health_events = [e for e in events if e.get("kind") == "auth_health_observed"]
    auth_unauthorized_turns = [
        e
        for e in proxy_turns
        if e.get("status") == 401 or e.get("classification") == "auth_unauthorized"
    ]
    ok_turns = [e for e in proxy_turns if e.get("status") == 200]
    responses_401_turns = [
        e
        for e in auth_unauthorized_turns
        if e.get("path_kind") == "responses"
    ]
    quota_turns = [
        e
        for e in proxy_turns
        if e.get("status") == 429 and e.get("classification") == "quota_exhausted"
    ]
    bad_responses_get_405 = [
        e
        for e in proxy_turns
        if e.get("method") == "GET"
        and e.get("path_kind") == "responses"
        and e.get("status") == 405
        and e.get("classification") == "ok"
    ]
    unsupported_transport_events = [e for e in events if e.get("kind") == "proxy_unsupported_transport"]
    local_transport_retry_events = [e for e in events if e.get("kind") == "proxy_transport_local_retry"]
    local_transport_retry_recovered_events = [
        e for e in events if e.get("kind") == "proxy_transport_local_retry_recovered"
    ]
    upstream_failure_events = [e for e in events if e.get("kind") == "proxy_upstream_failed"]
    provider_retry_events = [e for e in events if e.get("kind") == "proxy_provider_same_turn_retry"]
    provider_retry_unavailable_events = [e for e in events if e.get("kind") == "proxy_provider_retry_unavailable"]
    stream_interrupted_events = [e for e in events if e.get("kind") == "proxy_stream_interrupted"]
    client_disconnected_events = [e for e in events if e.get("kind") == "proxy_client_disconnected"]
    transport_failure_observed = bool(
        bad_responses_get_405
        or unsupported_transport_events
        or local_transport_retry_events
        or upstream_failure_events
        or provider_retry_unavailable_events
        or stream_interrupted_events
    )

    brokered_session = (
        session_started.get("claim_level") == "broker_owned"
        or session_started.get("claim_level") == "broker_owned_app_server"
        or session_ended.get("final_claim_level") == "broker_owned"
    )
    auth_failure_observed = bool(auth_unauthorized_turns)
    auth_failed_without_recovery = auth_failure_observed and not ok_turns
    auth_recovered_observed = auth_failure_observed and bool(ok_turns)
    terminal_event_observed = bool(session_ended or session_aborted)
    health_recording_expected_but_missing = (
        auth_failure_observed
        and not auth_health_events
        and not terminal_event_observed
    )
    provider_originated_live_fallback_claim = bool(
        fallback.get("observed")
        and fallback.get("fallback_status") == 200
        and isinstance(fallback.get("quota_turn"), dict)
        and fallback["quota_turn"].get("body_class") == "usage_limit_reached"
    )
    launch_elapsed_values = [
        e.get("elapsed_ms")
        for e in launch_timing_events
        if isinstance(e.get("elapsed_ms"), int)
    ]
    child_spawn_event = next(
        (e for e in launch_timing_events if e.get("phase") == "child_spawn"),
        {},
    )

    if provider_originated_live_fallback_claim:
        verdict = "successful_live_quota_handoff"
        next_action = "capture_or_close_live_quota_acceptance"
    elif fallback.get("observed"):
        verdict = "quota_handoff_observed"
        next_action = "inspect_quota_handoff_origin"
    elif quota_failure.get("observed"):
        verdict = "quota_handoff_failed"
        next_action = "repair_route_health_or_add_fallback_account"
    elif auth_fallback.get("observed"):
        verdict = "auth_fallback_sequence_observed"
        next_action = "continue_managed_dogfood"
    elif bad_responses_get_405:
        verdict = "transport_regression_405_misclassified"
        next_action = "contain_reconnect_get_transport"
    elif local_transport_recovery.get("observed"):
        verdict = "transport_local_retry_recovered"
        next_action = "continue_managed_dogfood"
    elif transport_recovery.get("observed"):
        verdict = "transport_fallback_recovered"
        next_action = "continue_managed_dogfood"
    elif provider_retry_unavailable_events or upstream_failure_events:
        verdict = "transport_failure_unavailable"
        next_action = "inspect_transport_failure_and_route_capacity"
    elif unsupported_transport_events:
        verdict = "transport_unsupported_contained"
        next_action = "continue_managed_dogfood"
    elif stream_interrupted_events:
        verdict = "stream_interrupted_partial"
        next_action = "inspect_provider_stream_stability"
    elif client_disconnected_events:
        verdict = "client_disconnected"
        next_action = "continue_managed_dogfood"
    elif brokered_session and auth_failure_observed and not terminal_event_observed:
        verdict = "brokered_incomplete_auth_failed"
        next_action = "inspect_incomplete_run"
    elif brokered_session and auth_failed_without_recovery:
        verdict = "brokered_auth_failed"
        next_action = "reauth_account"
    elif brokered_session and auth_recovered_observed:
        verdict = "brokered_auth_recovered"
        next_action = "continue_managed_dogfood"
    elif brokered_session and proxy_turns:
        verdict = "brokered_without_fallback"
        next_action = "wait_for_quota_event"
    else:
        verdict = "insufficient_evidence"
        next_action = "retry_managed"

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
        "auth_unauthorized_turns": len(auth_unauthorized_turns),
        "responses_401_turns": len(responses_401_turns),
        "auth_failure_observed": auth_failure_observed,
        "auth_recovered_observed": auth_recovered_observed,
        "auth_health_events": len(auth_health_events),
        "auth_health_recorded_observed": any(e.get("recorded") is True for e in auth_health_events),
        "auth_health_quota_claim_observed": any(e.get("quota_claim") is True for e in auth_health_events),
        "quota_event_observed": bool(quota_turns),
        "quota_handoff_observed": bool(fallback.get("observed")),
        "transport_failure_observed": transport_failure_observed,
        "transport_recovery_observed": bool(transport_recovery.get("observed"))
        or bool(local_transport_recovery.get("observed")),
        "transport_recovery_sequence": transport_recovery,
        "transport_local_recovery_sequence": local_transport_recovery,
        "unsupported_transport_events": len(unsupported_transport_events),
        "transport_local_retry_events": len(local_transport_retry_events),
        "transport_local_retry_recovered_events": len(local_transport_retry_recovered_events),
        "upstream_failure_events": len(upstream_failure_events),
        "provider_same_turn_retry_events": len(provider_retry_events),
        "provider_retry_unavailable_events": len(provider_retry_unavailable_events),
        "stream_interrupted_events": len(stream_interrupted_events),
        "client_disconnected_events": len(client_disconnected_events),
        "responses_get_405_misclassified_ok": len(bad_responses_get_405),
        "quota_handoff_failed_reason": quota_failure.get("reason")
        if quota_failure.get("observed")
        else None,
        "quota_handoff_failure": quota_failure,
        "no_account_selectable_rejections": quota_failure.get("rejections", [])
        if quota_failure.get("observed")
        else [],
        "user_visible_failure_likely": bool(
            quota_failure.get("user_visible_failure_likely")
        ),
        "terminal_event_observed": terminal_event_observed,
        "session_aborted_observed": bool(session_aborted),
        "terminal_event": {
            "kind": terminal_event.get("kind"),
            "exit_code": terminal_event.get("exit_code"),
            "term_kind": terminal_event.get("term_kind"),
            "term_code": terminal_event.get("term_code"),
            "signal_name": terminal_event.get("signal_name"),
        },
        "health_recording_expected_but_missing": health_recording_expected_but_missing,
        "same_turn_retry_events": sum(1 for e in events if e.get("kind") == "proxy_same_turn_retry"),
        "auth_same_turn_retry_events": sum(1 for e in events if e.get("kind") == "proxy_auth_same_turn_retry"),
        "auth_retry_unavailable_events": sum(1 for e in events if e.get("kind") == "proxy_auth_retry_unavailable"),
        "same_turn_retry_unavailable_events": sum(
            1 for e in events if e.get("kind") == "proxy_same_turn_retry_unavailable"
        ),
        "post_swap_turn_events": sum(1 for e in events if e.get("kind") == "proxy_post_swap_turn"),
        "launch_timing": {
            "events": len(launch_timing_events),
            "child_spawn_elapsed_ms": child_spawn_event.get("elapsed_ms")
            if isinstance(child_spawn_event.get("elapsed_ms"), int)
            else None,
            "total_elapsed_ms": max(launch_elapsed_values)
            if launch_elapsed_values
            else None,
        },
        "fallback_sequence": fallback,
        "auth_fallback_sequence": auth_fallback,
        "synthetic_swap_observed": bool(terminal_event.get("synthetic_swap_observed")),
        "level4_shape_observed": bool(fallback.get("observed")),
        "provider_originated_live_fallback_claim": provider_originated_live_fallback_claim,
        "verdict": verdict,
        "next_action": next_action,
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
