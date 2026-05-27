#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d -t omux-process-snapshot.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

python3 "$ROOT/scripts/dogfood-process-snapshot.py" --json >"$TMP/snapshot.json"

jq -e '
  .kind == "dogfood_process_snapshot"
  and .schema_version == 1
  and .spends_provider_calls == false
  and .mutates_user_config == false
  and .mutates_route_health == false
  and .mutates_processes == false
  and .kills_processes == false
  and .sleeps == false
  and .foreground_sleep == false
  and .safe_cleanup.automation_may_kill == false
  and .safe_cleanup.requires_operator_approval == true
  and (.process_summary.oauth_mux_processes | type == "number")
  and (.process_summary.active_codex_or_oauth_mux_processes | type == "number")
  and (.summary.live_validation_process_count | type == "number")
  and (.resource_limits.nofile.available | type == "boolean")
  and (.fd_summary.visible_fd_process_count | type == "number")
  and .fd_summary.fd_soft_limit_basis == "collector_process_nofile_soft_limit"
  and (.fd_summary.top_processes | type == "array")
  and (.evidence_gate.process_fd_clean_baseline | type == "boolean")
  and (.evidence_gate.unannotated_live_claims_admitted | type == "boolean")
  and (.evidence_gate.quota_cassette_claims_admitted | type == "boolean")
  and .evidence_gate.local_release_validation_admitted == true
  and (.evidence_gate.requires_operator_annotation | type == "boolean")
  and (.evidence_gate.fd_soft_limit_pct_threshold | type == "number")
  and (.evidence_gate.blocking_reasons | type == "array")
  and (.evidence_gate.caution_reasons | type == "array")
  and (.evidence_gate.next_actions | type == "array")
  and (.agent_trees | type == "array")
  and (.orphan_listener_candidates | type == "array")
  and (.duplicate_helper_groups | type == "array")
  and (.live_validation_processes | type == "array")
' "$TMP/snapshot.json" >/dev/null

ROOT_PATH="$ROOT" python3 - <<'PY'
import importlib.util
import os
from pathlib import Path

module_path = Path(os.environ["ROOT_PATH"]) / "scripts" / "dogfood-process-snapshot.py"
spec = importlib.util.spec_from_file_location("dogfood_process_snapshot", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

assert module.is_numeric_fd_tag("0u") is True
assert module.is_numeric_fd_tag("12r") is True
assert module.is_numeric_fd_tag("cwd") is False
assert module.is_numeric_fd_tag("txt") is False
assert module.is_numeric_fd_tag("mem") is False
assert module.is_numeric_fd_tag("") is False

clean = module.build_evidence_gate(
    {
        "active_codex_or_oauth_mux_processes": 0,
        "oauth_mux_processes": 0,
        "codex_processes": 0,
    },
    {"max_fd_soft_limit_pct": 10.0},
    [],
    [],
    [],
    [],
    [],
)
assert clean["process_fd_clean_baseline"] is True
assert clean["unannotated_live_claims_admitted"] is True
assert clean["quota_cassette_claims_admitted"] is True
assert clean["requires_operator_annotation"] is False

blocked = module.build_evidence_gate(
    {
        "active_codex_or_oauth_mux_processes": 1,
        "oauth_mux_processes": 1,
        "codex_processes": 1,
    },
    {"max_fd_soft_limit_pct": 70.0},
    [],
    [{"pid": 123}],
    [{"signature": "node", "count": 2}],
    [{"pid": 456}],
    [{"pid": 789}],
)
assert blocked["process_fd_clean_baseline"] is False
assert blocked["unannotated_live_claims_admitted"] is False
assert blocked["quota_cassette_claims_admitted"] is False
assert blocked["local_release_validation_admitted"] is True
assert blocked["requires_operator_annotation"] is True
assert {row["reason"] for row in blocked["blocking_reasons"]} == {
    "active_oauth_mux_or_codex_processes",
    "orphan_listener_candidates",
    "live_validation_processes_running",
    "fd_pressure_high",
}
assert {row["reason"] for row in blocked["caution_reasons"]} == {
    "accumulated_sessions_visible",
    "duplicate_helper_groups_visible",
}
PY

python3 "$ROOT/scripts/dogfood-process-snapshot.py" \
  --compare "$TMP/snapshot.json" "$TMP/snapshot.json" \
  --json >"$TMP/comparison.json"

jq -e '
  .kind == "dogfood_process_snapshot_comparison"
  and .schema_version == 1
  and .mode == "agent_process_fanout_comparison"
  and .spends_provider_calls == false
  and .mutates_user_config == false
  and .mutates_route_health == false
  and .mutates_processes == false
  and .kills_processes == false
  and .sleeps == false
  and .foreground_sleep == false
  and .safe_cleanup.automation_may_kill == false
  and .safe_cleanup.requires_operator_approval == true
  and .summary.suspected_rss_growth_count == 0
  and (.summary.stable_or_explained_count | type == "number")
  and (.stable_or_explained | type == "array")
  and (.appeared | type == "array")
  and (.disappeared | type == "array")
' "$TMP/comparison.json" >/dev/null

python3 "$ROOT/scripts/dogfood-process-snapshot.py" --out "$TMP/out" --tag smoke >/dev/null
test -n "$(find "$TMP/out" -name 'process-snapshot-*-smoke.json' -print -quit)"
test -n "$(find "$TMP/out" -name 'process-snapshot-*-smoke.md' -print -quit)"

echo "smoke-dogfood-process-snapshot: all assertions passed."
