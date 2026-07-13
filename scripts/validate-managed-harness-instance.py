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


def validate(document: Any) -> None:
    if not isinstance(document, dict):
        raise ContractError("wire instance must be an object")
    if document.get("method") == "session/transition":
        params = document.get("params")
        if not isinstance(params, dict):
            raise ContractError("session/transition params must be an object")
        validate_transition(params)


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
