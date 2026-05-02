#!/usr/bin/env bash
set -euo pipefail

doc="docs/stay-afloat-wrappers.md"

expect() {
  local needle="$1"
  if ! grep -Fq "$needle" "$doc"; then
    echo "missing wrapper-doc text: $needle" >&2
    exit 1
  fi
}

test -f "$doc"

expect "oauth-mux daemon run --stay-afloat --profile"
expect "oauth-mux daemon supervise --profile"
expect "oauth-mux daemon status --json"
expect "oauth-mux daemon stop"
expect "production_supported:false"
expect "hosts_stay_afloat:false"
expect "socket:null"
expect "launchctl bootstrap"
expect "systemctl --user"
expect "Task Scheduler"
expect "oauth-mux.exe stay-afloat --loop"
expect "Container Or CI"
expect "GitHub #106 / Linear TIN-900"

echo "stay-afloat wrapper docs smoke passed"
