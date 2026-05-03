#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

default_accounts_csv="max-1,max-2,max-3"
accounts_csv="${OMUX_CODEX_ACCOUNTS:-$default_accounts_csv}"
login_mode="${OMUX_CODEX_LOGIN_MODE:-browser}"
config_path="${OMUX_CONFIG:-$repo_root/examples/codex-max.config.json}"
bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"

if [ ! -x "$bin" ]; then
  printf 'oauth-mux binary not found at %s\n' "$bin" >&2
  printf 'run: just build\n' >&2
  exit 1
fi

case "$login_mode" in
  browser|device|status-only) ;;
  *)
    printf 'OMUX_CODEX_LOGIN_MODE must be browser, device, or status-only\n' >&2
    exit 1
    ;;
esac

IFS=',' read -r -a accounts <<<"$accounts_csv"

printf 'oauth-mux Codex Max onboarding\n\n'
printf 'config: %s\n' "$config_path"
if [ "$accounts_csv" = "$default_accounts_csv" ]; then
  printf 'note:   default accounts match the three-route starter config; set OMUX_CODEX_ACCOUNTS=max-1,max-2,max-3,max-4 for the paid cohort\n'
fi
printf 'mode:   %s\n\n' "$login_mode"

export OMUX_CONFIG="$config_path"
"$bin" config validate

for account in "${accounts[@]}"; do
  dir="$HOME/.local/share/oauth-mux/codex/${account}"
  mkdir -p "$dir"
  printf '\n=== %s ===\n' "$account"
  if CODEX_HOME="$dir" codex login status; then
    continue
  fi

  if [ "$login_mode" = "status-only" ]; then
    printf 'not logged in; rerun with OMUX_CODEX_LOGIN_MODE=browser or device\n'
    continue
  fi

  if [ "$login_mode" = "device" ]; then
    CODEX_HOME="$dir" codex login --device-auth
  else
    CODEX_HOME="$dir" codex login
  fi
  CODEX_HOME="$dir" codex login status
done

printf '\n=== oauth-mux inventory ===\n'
"$bin" discover

if [ "${OMUX_LIVE_QA_CONFIRM:-}" = "spend-real-calls" ]; then
  printf '\n=== live QA ===\n'
  OMUX_CONFIG="$config_path" \
    OMUX_LIVE_QA_PROVIDER="${OMUX_LIVE_QA_PROVIDER:-codex}" \
    OMUX_LIVE_QA_ACCOUNTS="$accounts_csv" \
    OMUX_LIVE_QA_CAPABILITIES="${OMUX_LIVE_QA_CAPABILITIES:-codex-mini}" \
    OMUX_LIVE_QA_CONFIRM=spend-real-calls \
    "$repo_root/scripts/live-provider-qa.sh"
else
  printf '\nLive probes not run. Set OMUX_LIVE_QA_CONFIRM=spend-real-calls to run bounded route probes.\n'
fi
