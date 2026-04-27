#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

config_path="${OMUX_CONFIG:-$repo_root/examples/codex-max.config.json}"
accounts_csv="${OMUX_CODEX_ACCOUNTS:-max-1,max-2,max-3}"
capabilities_csv="${OMUX_CODEX_CANARY_CAPABILITIES:-codex-mini,codex-max}"
store_root="${OMUX_CODEX_STORE_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/oauth-mux/codex}"
state_dir="${OMUX_STATE_DIR:-/tmp/oauth-mux-codex-max-health}"
bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"

if [ ! -x "$bin" ]; then
  printf 'oauth-mux binary not found at %s\n' "$bin" >&2
  printf 'run: just build\n' >&2
  exit 1
fi

if ! command -v codex >/dev/null 2>&1; then
  printf 'codex CLI not found on PATH\n' >&2
  exit 1
fi

stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
out_dir="${OMUX_CODEX_CANARY_OUT:-$repo_root/dist/codex-canary/$stamp}"
mkdir -p "$out_dir"

export OMUX_CONFIG="$config_path"
export OMUX_STATE_DIR="$state_dir"

IFS=',' read -r -a accounts <<<"$accounts_csv"
IFS=',' read -r -a capabilities <<<"$capabilities_csv"

redact() {
  sed -E \
    -e 's/(access_token|refresh_token|id_token|token)["= :]+[^", ]+/\1=<redacted>/gi' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
}

summary="$out_dir/summary.txt"

{
  printf 'oauth-mux Codex Max canary\n\n'
  printf 'config:       %s\n' "$config_path"
  printf 'state:        %s\n' "$state_dir"
  printf 'store root:   %s\n' "$store_root"
  printf 'accounts:     %s\n' "$accounts_csv"
  printf 'capabilities: %s\n' "$capabilities_csv"
  printf 'artifacts:    %s\n' "$out_dir"
} | tee "$summary"

printf '\n=== config validate ===\n' | tee -a "$summary"
"$bin" config validate 2>&1 | redact | tee "$out_dir/config-validate.txt"

printf '\n=== agent discovery ===\n' | tee -a "$summary"
"$bin" discover --json >"$out_dir/discover.json"
"$bin" status --json >"$out_dir/status.json"
"$bin" health --json >"$out_dir/health.json"
printf 'wrote discover.json, status.json, health.json\n' | tee -a "$summary"

printf '\n=== codex login status ===\n' | tee -a "$summary"
: >"$out_dir/codex-login-status.txt"
login_failures=0
for account in "${accounts[@]}"; do
  account_dir="$store_root/$account"
  {
    printf '=== %s ===\n' "$account"
    printf 'CODEX_HOME=%s\n' "$account_dir"
    CODEX_HOME="$account_dir" codex login status
  } 2>&1 | redact | tee -a "$out_dir/codex-login-status.txt" || login_failures=$((login_failures + 1))
done

printf '\n=== route liveness snapshot ===\n' | tee -a "$summary"
printf 'No live probes were run by default. Route decisions below come from existing oauth-mux health state.\n' | tee -a "$summary"
for account in "${accounts[@]}"; do
  for capability in "${capabilities[@]}"; do
    key="codex:${account}#${capability}"
    if grep -q "\"key\":\"$key\"" "$out_dir/health.json"; then
      printf '%s: recorded\n' "$key" | tee -a "$summary"
    else
      printf '%s: no recorded health yet\n' "$key" | tee -a "$summary"
    fi
  done
done

confirm="${OMUX_CODEX_CANARY_CONFIRM:-${OMUX_LIVE_QA_CONFIRM:-}}"
if [ "$confirm" = "spend-real-calls" ]; then
  printf '\n=== live QA ===\n' | tee -a "$summary"
  OMUX_CONFIG="$config_path" \
    OMUX_STATE_DIR="$state_dir" \
    OMUX_LIVE_QA_PROVIDER="${OMUX_LIVE_QA_PROVIDER:-codex}" \
    OMUX_LIVE_QA_ACCOUNTS="$accounts_csv" \
    OMUX_LIVE_QA_CAPABILITIES="$capabilities_csv" \
    OMUX_LIVE_QA_CONFIRM=spend-real-calls \
    "$repo_root/scripts/live-provider-qa.sh" 2>&1 | redact | tee "$out_dir/live-qa.txt"
else
  {
    printf '\nLive probes not run.\n'
    printf 'To run bounded route probes, set OMUX_CODEX_CANARY_CONFIRM=spend-real-calls.\n'
  } | tee -a "$summary"
fi

if [ "$login_failures" -ne 0 ]; then
  printf '\nCodex login-status failures: %s\n' "$login_failures" | tee -a "$summary" >&2
  exit 1
fi

printf '\nCodex Max canary artifacts: %s\n' "$out_dir"
