#!/usr/bin/env python3
"""Validate cross-element managed-harness relationships outside JSON Schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    pass


def validate_transition(params: dict[str, Any]) -> None:
    attempts = params.get("proxy_attempts")
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= 2:
        raise ContractError("proxy_attempts must contain one or two attempts")

    for attempt in attempts:
        if not isinstance(attempt, dict):
            raise ContractError("attempt must be an object")
        if "model_demand" in attempt:
            raise ContractError("attempt model_demand must inherit from the transition")

    initial = attempts[0]
    if not isinstance(initial.get("account_handle"), str) or not isinstance(initial.get("route_handle"), str):
        raise ContractError("initial attempt must name its opaque account and route")

    if len(attempts) == 1:
        return

    followup = attempts[1]
    relation = followup.get("route_relation")
    if relation == "same_route":
        forbidden = {"account_handle", "route_handle", "alternate_account_handle", "alternate_route_handle"}
        if forbidden.intersection(followup):
            raise ContractError("same-route retry must inherit the initial handles")
        return

    if relation != "alternate_account":
        raise ContractError("followup route relationship is invalid")

    alternate_account = followup.get("alternate_account_handle")
    alternate_route = followup.get("alternate_route_handle")
    if not isinstance(alternate_account, str) or not isinstance(alternate_route, str):
        raise ContractError("alternate attempt must name alternate handles")
    if alternate_account == initial["account_handle"] or alternate_route == initial["route_handle"]:
        raise ContractError("alternate attempt must change both account and route")


def validate_lease_snapshot(result: dict[str, Any]) -> None:
    leases = result.get("leases")
    observed_at = result.get("observed_at_ms")
    snapshot_session = result.get("session_handle")
    if not isinstance(leases, list) or type(observed_at) is not int or not isinstance(snapshot_session, str):
        raise ContractError("lease snapshot must contain typed leases, session, and observation time")

    seen_handles: set[str] = set()
    for lease in leases:
        if not isinstance(lease, dict):
            raise ContractError("lease must be an object")
        lease_handle = lease.get("lease_handle")
        heartbeat = lease.get("heartbeat_at_ms")
        expires = lease.get("expires_at_ms")
        owner_state = lease.get("owner_state")
        if not isinstance(lease_handle, str) or type(heartbeat) is not int or type(expires) is not int:
            raise ContractError("lease identity and timestamps must be typed")
        if lease_handle in seen_handles:
            raise ContractError("lease handles must be unique within a snapshot")
        seen_handles.add(lease_handle)
        if lease.get("session_handle") != snapshot_session:
            raise ContractError("lease session must match its snapshot session")
        if heartbeat > observed_at or heartbeat > expires:
            raise ContractError("lease heartbeat must not follow observation or expiry")
        if owner_state == "active" and not observed_at < expires:
            raise ContractError("active lease must expire after observation")
        if owner_state == "stale" and not expires <= observed_at:
            raise ContractError("stale lease must be expired at observation")
        if owner_state not in {"active", "stale", "exited"}:
            raise ContractError("lease owner state is invalid")


def validate(document: Any) -> None:
    if not isinstance(document, dict):
        raise ContractError("wire instance must be an object")
    if document.get("method") == "session/transition":
        params = document.get("params")
        if not isinstance(params, dict):
            raise ContractError("session/transition params must be an object")
        validate_transition(params)
    result = document.get("result")
    if isinstance(result, dict) and "leases" in result:
        validate_lease_snapshot(result)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-managed-harness-instance.py <fixture.json>", file=sys.stderr)
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
