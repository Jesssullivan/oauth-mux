#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ "${OMUX_LIVE_QA_CONFIRM:-}" != "spend-real-calls" ]; then
  cat >&2 <<'EOF'
live-provider QA is disabled.

This command can spend real provider/subscription calls. Re-run with:

  OMUX_LIVE_QA_CONFIRM=spend-real-calls

Also set one of:

  OMUX_LIVE_QA_PROFILE=<profile>
  OMUX_LIVE_QA_PROVIDER=<provider> OMUX_LIVE_QA_ACCOUNTS=a,b,c
EOF
  exit 2
fi

bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"
if [ ! -x "$bin" ]; then
  printf 'oauth-mux binary not found at %s\n' "$bin" >&2
  printf 'run: just build\n' >&2
  exit 1
fi

stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
out_dir="${OMUX_LIVE_QA_OUT:-$repo_root/dist/live-qa/$stamp}"
state_dir="${OMUX_STATE_DIR:-$out_dir/state}"
mkdir -p "$out_dir" "$state_dir"
export OMUX_STATE_DIR="$state_dir"

profile="${OMUX_LIVE_QA_PROFILE:-}"
provider="${OMUX_LIVE_QA_PROVIDER:-}"
accounts_csv="${OMUX_LIVE_QA_ACCOUNTS:-}"
capabilities_csv="${OMUX_LIVE_QA_CAPABILITIES:-codex-mini}"

IFS=',' read -r -a capabilities <<<"$capabilities_csv"

redact() {
  sed -E \
    -e 's/(access_token|refresh_token|id_token|token)["= :]+[^", ]+/\1=<redacted>/gi' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
}

run_probe() {
  local label="$1"
  shift
  local safe_label
  safe_label="$(printf '%s' "$label" | tr '#:/ ' '____')"
  printf '=== %s ===\n' "$label"
  if "$bin" probe "$@" --json 2>&1 | redact | tee "$out_dir/${safe_label}.json"; then
    return 0
  fi
  printf 'probe failed: %s\n' "$label" >&2
  return 1
}

"$bin" config validate | tee "$out_dir/config-validate.txt"
"$bin" discover --json >"$out_dir/discover.json"

failures=0
if [ -n "$profile" ]; then
  for capability in "${capabilities[@]}"; do
    run_probe "profile:${profile}#${capability}" --profile "$profile" --capability "$capability" || failures=$((failures + 1))
  done
elif [ -n "$provider" ] && [ -n "$accounts_csv" ]; then
  IFS=',' read -r -a accounts <<<"$accounts_csv"
  for account in "${accounts[@]}"; do
    for capability in "${capabilities[@]}"; do
      run_probe "${provider}:${account}#${capability}" --provider "$provider" --account "$account" --capability "$capability" || failures=$((failures + 1))
    done
  done
else
  printf 'set OMUX_LIVE_QA_PROFILE or OMUX_LIVE_QA_PROVIDER plus OMUX_LIVE_QA_ACCOUNTS\n' >&2
  exit 2
fi

"$bin" health --json >"$out_dir/health.json"

printf 'live QA artifacts: %s\n' "$out_dir"
if [ "$failures" -ne 0 ]; then
  printf 'live QA failures: %s\n' "$failures" >&2
  exit 1
fi
