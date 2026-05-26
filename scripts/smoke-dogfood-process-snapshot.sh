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
  and (.resource_limits.nofile.available | type == "boolean")
  and (.fd_summary.visible_fd_process_count | type == "number")
  and (.fd_summary.top_processes | type == "array")
  and (.agent_trees | type == "array")
  and (.orphan_listener_candidates | type == "array")
  and (.duplicate_helper_groups | type == "array")
' "$TMP/snapshot.json" >/dev/null

python3 "$ROOT/scripts/dogfood-process-snapshot.py" \
  --compare "$TMP/snapshot.json" "$TMP/snapshot.json" \
  --json >"$TMP/comparison.json"

jq -e '
  .kind == "dogfood_process_snapshot_comparison"
  and .spends_provider_calls == false
  and .mutates_user_config == false
  and .mutates_route_health == false
  and .kills_processes == false
  and .sleeps == false
  and .foreground_sleep == false
  and .safe_cleanup.automation_may_kill == false
  and .summary.suspected_rss_growth_count == 0
' "$TMP/comparison.json" >/dev/null

python3 "$ROOT/scripts/dogfood-process-snapshot.py" --out "$TMP/out" --tag smoke >/dev/null
test -n "$(find "$TMP/out" -name 'process-snapshot-*-smoke.json' -print -quit)"
test -n "$(find "$TMP/out" -name 'process-snapshot-*-smoke.md' -print -quit)"

echo "smoke-dogfood-process-snapshot: all assertions passed."
