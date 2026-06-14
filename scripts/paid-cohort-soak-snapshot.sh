#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"
provider="${OMUX_SOAK_PROVIDER:-codex}"
profile="${OMUX_SOAK_PROFILE:-codex-max}"
capability="${OMUX_SOAK_CAPABILITY:-$profile}"
loop_iterations="${OMUX_SOAK_LOOP_ITERATIONS:-2}"
loop_interval_ms="${OMUX_SOAK_LOOP_INTERVAL_MS:-0}"
stamp="${OMUX_SOAK_STAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}"
out_dir="${OMUX_SOAK_OUT:-$repo_root/dist/soak/$stamp/$profile}"
state_dir="${OMUX_STATE_DIR:-}"
config_path="${OMUX_CONFIG:-}"

if [ ! -x "$bin" ]; then
  printf 'oauth-mux binary not found at %s\n' "$bin" >&2
  printf 'run: just build-local\n' >&2
  exit 1
fi

mkdir -p "$out_dir"

if [ -n "$config_path" ]; then
  export OMUX_CONFIG="$config_path"
else
  unset OMUX_CONFIG
fi

if [ -n "$state_dir" ]; then
  export OMUX_STATE_DIR="$state_dir"
else
  unset OMUX_STATE_DIR
fi

redact() {
  sed -E \
    -e 's/(access_token|refresh_token|id_token|token)["= :]+[^", ]+/\1=<redacted>/gi' \
    -e 's/(Authorization: Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/gi' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
}

summary="$out_dir/summary.txt"
failures=0

{
  printf 'oauth-mux paid cohort diagnostic soak snapshot\n\n'
  printf 'provider:        %s\n' "$provider"
  printf 'profile:         %s\n' "$profile"
  printf 'capability:      %s\n' "$capability"
  printf 'config:          %s\n' "${config_path:-default oauth-mux config path}"
  printf 'state:           %s\n' "${state_dir:-default oauth-mux state dir}"
  printf 'loop iterations: %s\n' "$loop_iterations"
  printf 'loop interval:   %sms\n' "$loop_interval_ms"
  printf 'artifacts:       %s\n' "$out_dir"
  printf '\nThis helper does not spend provider calls and does not mutate route health.\n'
} | tee "$summary"

run_artifact() {
  local label="$1"
  local output_name="$2"
  shift 2

  local output_file="$out_dir/$output_name"
  local log_file="$out_dir/${output_name}.stderr.log"

  printf '\n=== %s ===\n' "$label" | tee -a "$summary"
  set +e
  "$@" >"$output_file" 2> >(redact >"$log_file")
  local status="$?"
  set -e

  if [ "$status" -eq 0 ]; then
    printf 'wrote %s\n' "$output_name" | tee -a "$summary"
  else
    printf 'failed (%s): %s\n' "$status" "$label" | tee -a "$summary" >&2
    failures=$((failures + 1))
  fi
}

run_confirmation_artifact() {
  local label="$1"
  local output_name="$2"
  shift 2

  local output_file="$out_dir/$output_name"
  local log_file="$out_dir/${output_name}.stderr.log"

  printf '\n=== %s ===\n' "$label" | tee -a "$summary"
  set +e
  "$@" >"$output_file" 2> >(redact >"$log_file")
  local status="$?"
  set -e

  if grep -q '"confirmation_required":true' "$output_file"; then
    printf 'wrote %s (confirmation gate, status %s)\n' "$output_name" "$status" | tee -a "$summary"
  else
    printf 'failed (%s): %s did not report confirmation_required\n' "$status" "$label" | tee -a "$summary" >&2
    failures=$((failures + 1))
  fi
}

run_text_artifact() {
  local label="$1"
  local output_name="$2"
  shift 2

  local output_file="$out_dir/$output_name"

  printf '\n=== %s ===\n' "$label" | tee -a "$summary"
  set +e
  "$@" 2>&1 | redact | tee "$output_file"
  local status="${PIPESTATUS[0]}"
  set -e

  if [ "$status" -ne 0 ]; then
    printf 'failed (%s): %s\n' "$status" "$label" | tee -a "$summary" >&2
    failures=$((failures + 1))
  fi
}

run_text_artifact "config validate" "config-validate.txt" "$bin" config validate
run_artifact "accounts list" "accounts.json" "$bin" accounts list --provider "$provider" --json
run_artifact "providers list" "providers.json" "$bin" providers list --json
run_artifact "route explain" "route-explain.json" "$bin" route explain --profile "$profile" --capability "$capability" --json

if [ "$provider" = "codex" ]; then
  run_artifact "codex broker-session-plan" "broker-session-plan.json" "$bin" codex broker-session-plan --profile "$profile" --capability "$capability" --json
  run_confirmation_artifact "codex revalidate-exhausted spend gate" "revalidate-exhausted.confirmation.json" "$bin" codex revalidate-exhausted --profile "$profile" --capability "$capability" --json
  run_confirmation_artifact "codex broker-run spend gate" "broker-run.confirmation.json" "$bin" codex broker-run --profile "$profile" --capability "$capability" --prompt "oauth-mux soak confirmation gate" --json
else
  printf '\n=== broker-session-plan ===\n' | tee -a "$summary"
  printf 'skipped: broker-session-plan is Codex-specific\n' | tee "$out_dir/broker-session-plan.skipped.txt" | tee -a "$summary" >/dev/null
fi

run_artifact "stay-afloat next" "stay-afloat-next.json" "$bin" stay-afloat next --profile "$profile" --capability "$capability" --json
run_artifact "stay-afloat once" "stay-afloat-once.json" "$bin" stay-afloat --once --profile "$profile" --capability "$capability" --json
run_artifact "stay-afloat loop" "stay-afloat-loop.json" "$bin" stay-afloat --loop --iterations "$loop_iterations" --interval-ms "$loop_interval_ms" --profile "$profile" --capability "$capability" --json

{
  printf '\nSpend-gated commands intentionally not run.\n'
  printf 'The confirmation artifacts prove provider-mutating gates remain closed without --confirm-spend.\n'
  printf 'Use codex revalidate-exhausted, broker-run, or live-provider QA only from an explicit operator-confirmed spend path.\n'
} | tee -a "$summary"

if [ "$failures" -ne 0 ]; then
  printf '\npaid cohort soak snapshot failures: %s\n' "$failures" | tee -a "$summary" >&2
  exit 1
fi

printf '\npaid cohort soak artifacts: %s\n' "$out_dir" | tee -a "$summary"
