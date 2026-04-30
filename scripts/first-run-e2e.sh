#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"

if [ ! -x "$bin" ]; then
  printf 'missing oauth-mux binary: %s\n' "$bin" >&2
  printf 'run `zig build` or `just first-run-e2e` first\n' >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing jq; run through `nix develop --command just first-run-e2e-local`\n' >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-first-run.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

home="$tmp/home"
xdg_config="$tmp/xdg-config"
xdg_state="$tmp/xdg-state"
xdg_data="$tmp/xdg-data"
xdg_runtime="$tmp/xdg-runtime"
operator_home="${HOME:-}"

mkdir -p "$home" "$xdg_config" "$xdg_state" "$xdg_data" "$xdg_runtime"
chmod 0700 "$xdg_runtime"

config_path="$xdg_config/oauth-mux/config.json"
candidate_config_path="$xdg_config/oauth-mux/codex-max.config.json"
store_root="$xdg_data/oauth-mux/codex"
legacy_store_root="$home/.local/share/oauth-mux/codex"

omux() (
  unset OMUX_CONFIG
  unset OMUX_CONFIG_DIR
  unset OMUX_STATE_DIR
  unset OMUX_CODEX_STORE_ROOT
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  "$bin" "$@"
)

expect_contains() {
  haystack="$1"
  needle="$2"
  label="$3"

  case "$haystack" in
    *"$needle"*) ;;
    *)
      printf 'first-run e2e assertion failed: %s\n' "$label" >&2
      printf 'expected to find: %s\n' "$needle" >&2
      printf 'output was:\n%s\n' "$haystack" >&2
      exit 1
      ;;
  esac
}

expect_not_contains() {
  haystack="$1"
  needle="$2"
  label="$3"

  if [ -z "$needle" ]; then
    return
  fi

  case "$haystack" in
    *"$needle"*)
      printf 'first-run e2e assertion failed: %s\n' "$label" >&2
      printf 'did not expect to find: %s\n' "$needle" >&2
      printf 'output was:\n%s\n' "$haystack" >&2
      exit 1
      ;;
  esac
}

run_json() {
  output_file="$1"
  shift

  omux "$@" >"$output_file"
  jq -e type "$output_file" >/dev/null
}

printf 'first-run e2e: version from isolated environment\n'
version_out="$(omux version)"
expect_contains "$version_out" "oauth-mux " "version prints binary version"

printf 'first-run e2e: doctor before config is parseable and actionable\n'
doctor_before="$tmp/doctor-before.json"
run_json "$doctor_before" doctor --json
jq -e '
  .configured == false
  and .ok == false
  and (.next_commands | index("oauth-mux init --codex-max") != null)
' "$doctor_before" >/dev/null

printf 'first-run e2e: init --codex-max writes only temp-home config\n'
init_out="$(omux init --codex-max)"
expect_contains "$init_out" "$config_path" "init reports temp config path"
test -f "$config_path"

config_json="$(cat "$config_path")"
expect_contains "$config_json" "$store_root/max-1" "starter config uses XDG data store root"
expect_contains "$config_json" "$store_root/max-1/auth.json" "starter config uses XDG auth path"
expect_not_contains "$config_json" "$legacy_store_root" "starter config does not fall back to legacy temp-home store when XDG data is set"
expect_not_contains "$config_json" "$operator_home" "starter config does not reference operator home"

printf 'first-run e2e: generated config validates\n'
validate_out="$(omux config validate)"
expect_contains "$validate_out" "config: valid" "config validate succeeds"

printf 'first-run e2e: doctor after config reports ready shape\n'
doctor_after="$tmp/doctor-after.json"
run_json "$doctor_after" doctor --json
jq -e '
  .configured == true
  and .config_valid == true
  and .codex_configured == true
  and .providers == 1
  and .accounts == 3
  and (.next_commands | index("oauth-mux setup codex") != null)
  and (.next_commands | index("oauth-mux repair-plan --json") != null)
' "$doctor_after" >/dev/null

printf 'first-run e2e: discovery is redacted and agent-usable\n'
discover_json="$tmp/discover.json"
run_json "$discover_json" discover --json
jq -e '
  .configured == true
  and (.providers[] | select(.name == "codex") | .accounts | length) == 3
  and (.agent_safe_commands | index("oauth-mux report --redacted --json") != null)
  and (.agent_safe_commands | index("oauth-mux repair-plan --profile <profile> --capability <capability> --json") != null)
' "$discover_json" >/dev/null

printf 'first-run e2e: repair-plan explains generated Codex Max routes without mutation\n'
repair_plan_json="$tmp/repair-plan-codex-max.json"
run_json "$repair_plan_json" repair-plan --profile codex-max --capability codex-max --json
jq -e '
  .profile == "codex-max"
  and (.routes | length) == 3
  and all(.routes[]; .provider == "codex" and .capability == "codex-max" and .action.mutating == false)
  and all(.routes[]; .action.kind == "fix_runtime" or .action.kind == "probe_needed" or .action.kind == "none" or .action.kind == "wait_and_retry" or .action.kind == "wait_for_quota" or .action.kind == "wait_for_cooldown")
' "$repair_plan_json" >/dev/null

printf 'first-run e2e: config-candidate writes sidecar without clobbering active config\n'
config_before="$(cat "$config_path")"
candidate_json="$tmp/config-candidate.json"
run_json "$candidate_json" codex config-candidate --json
jq -e --arg path "$candidate_config_path" '
  .created == true
  and .candidate_config == $path
  and (.next_commands | index("OMUX_CONFIG='\''" + $path + "'\'' oauth-mux repair-plan --profile codex-max --capability codex-max --json") != null)
' "$candidate_json" >/dev/null
test -f "$candidate_config_path"
candidate_config_json="$(cat "$candidate_config_path")"
expect_contains "$candidate_config_json" "$store_root/max-1/auth.json" "candidate config uses XDG auth path"
candidate_again_json="$tmp/config-candidate-again.json"
run_json "$candidate_again_json" codex config-candidate --json
jq -e '
  .created == false
' "$candidate_again_json" >/dev/null
if [ "$(cat "$config_path")" != "$config_before" ]; then
  printf 'first-run e2e assertion failed: config-candidate modified active config\n' >&2
  exit 1
fi

printf 'first-run e2e: support report is redacted JSON\n'
report_json="$tmp/report.json"
run_json "$report_json" report --redacted --json
jq -e '
  .redacted == true
  and .config.configured == true
  and .config.valid == true
  and (.providers[] | select(.name == "codex") | .accounts | length) == 3
' "$report_json" >/dev/null
expect_not_contains "$(cat "$report_json")" "auth.json" "redacted report omits credential file paths"
expect_not_contains "$(cat "$report_json")" "$operator_home" "redacted report does not reference operator home"

printf 'first-run e2e: Codex help remains non-mutating\n'
help_out="$(omux codex canary --help)"
expect_contains "$help_out" "non-mutating" "Codex help declares non-mutating behavior"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e passed\n'
