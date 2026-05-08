#!/usr/bin/env bash
set -euo pipefail

status_file="${1:-dist/live-qa/managed-resume-dogfood-9/status.ndjson}"
interval_seconds="${2:-60}"
out_dir="${3:-$(dirname "$status_file")}"

mkdir -p "$out_dir"

monitor_log="$out_dir/monitor.log"
event_log="$out_dir/quota-terminal-events.log"

event_pattern='"status":(429|503)|quota_exhausted|usage_limit_reached|proxy_same_turn_retry|proxy_upstream_failed|session_ended|session_aborted|auth_writeback|auth_health_observed|resume_writeback'

while true; do
	printf '\n== %s ==\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$monitor_log"
	python3 scripts/summarize-codex-status.py "$status_file" --require-brokered >>"$monitor_log" 2>&1

	event_tmp="$(mktemp "${TMPDIR:-/tmp}/oauth-mux-codex-events.XXXXXX")"
	if rg -n "$event_pattern" "$status_file" >"$event_tmp" 2>/dev/null; then
		printf '\n== %s ==\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$event_log"
		cat "$event_tmp" >>"$event_log"
		tail -n 80 "$status_file" >>"$event_log"
	fi
	rm -f "$event_tmp"

	sleep "$interval_seconds"
done
