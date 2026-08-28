"""Golden-JSON contract test for the redacted route-state v0.2 envelope (TIN-1803).

Declaration-only: no Zig reducer exists yet (see
docs/spec/2026-08-28-redacted-route-state-truth-design.md). This proves the
schema + fixtures + semantic validator agree with each other so a future
reducer has an executable acceptance oracle to build against.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "route-state-v2.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
FIXTURES = ROOT / "test" / "fixtures" / "route-state-v2"
SEMANTIC_SCRIPT = ROOT / "scripts" / "validate-route-state-instance.py"


def _semantic_rc(fixture: Path) -> int:
    return subprocess.run(
        [sys.executable, str(SEMANTIC_SCRIPT), str(fixture)],
        capture_output=True,
    ).returncode


@pytest.mark.parametrize("fixture", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.name)
def test_valid_fixture_passes_schema_and_semantics(fixture: Path) -> None:
    doc = json.loads(fixture.read_text())
    errors = list(VALIDATOR.iter_errors(doc))
    assert not errors, f"{fixture.name}: {errors}"
    assert _semantic_rc(fixture) == 0, f"{fixture.name} unexpectedly failed semantic validation"


@pytest.mark.parametrize("fixture", sorted((FIXTURES / "invalid-schema").glob("*.json")), ids=lambda p: p.name)
def test_invalid_schema_fixture_is_rejected(fixture: Path) -> None:
    doc = json.loads(fixture.read_text())
    errors = list(VALIDATOR.iter_errors(doc))
    assert errors, f"{fixture.name} should have failed schema validation"


@pytest.mark.parametrize("fixture", sorted((FIXTURES / "invalid-semantic").glob("*.json")), ids=lambda p: p.name)
def test_invalid_semantic_fixture_passes_schema_but_fails_semantics(fixture: Path) -> None:
    doc = json.loads(fixture.read_text())
    errors = list(VALIDATOR.iter_errors(doc))
    assert not errors, f"{fixture.name}: expected schema-valid, got {errors}"
    assert _semantic_rc(fixture) == 1, f"{fixture.name} should have failed semantic validation"


def test_rank_order_fixture_covers_every_state_exactly_once() -> None:
    rank = json.loads((FIXTURES / "rank-order.json").read_text())
    order = rank["rank_order_best_to_worst"]
    assert len(order) == len(set(order)) == 9
    assert set(order) == set(SCHEMA["$defs"]["route_state"]["enum"])


def test_every_state_in_the_enum_has_a_valid_fixture() -> None:
    have = {json.loads(f.read_text())["state"] for f in (FIXTURES / "valid").glob("*.json")}
    assert have == set(SCHEMA["$defs"]["route_state"]["enum"])
