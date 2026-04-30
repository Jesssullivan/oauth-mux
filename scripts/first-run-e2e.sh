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
  and .codex_max_configured == true
  and .providers == 1
  and .accounts == 3
  and (.next_commands | index("oauth-mux setup codex") != null)
  and (.next_commands | index("oauth-mux codex config-candidate --json") == null)
  and (.next_commands | index("oauth-mux doctor runtime --json") != null)
  and (.next_commands | index("oauth-mux route explain --profile <profile> --capability <capability> --json") != null)
  and (.next_commands | index("oauth-mux route select --profile <profile> --capability <capability> --json") != null)
  and (.next_commands | index("oauth-mux repair-plan --json") != null)
' "$doctor_after" >/dev/null

printf 'first-run e2e: runtime doctor classifies unbootstrapped stores without mutation\n'
runtime_doctor="$tmp/doctor-runtime.json"
run_json "$runtime_doctor" doctor runtime --json
jq -e '
  .configured == true
  and .config_valid == true
  and .ok == false
  and .accounts == 3
  and .action_needed_accounts == 3
  and (.provider_reports[] | select(.name == "codex") | .accounts | length) == 3
  and all(.provider_reports[] | select(.name == "codex") | .accounts[]; .ready == false)
' "$runtime_doctor" >/dev/null
expect_not_contains "$(cat "$runtime_doctor")" "$store_root/max-1" "runtime doctor does not print concrete Codex store paths"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: discovery is redacted and agent-usable\n'
discover_json="$tmp/discover.json"
run_json "$discover_json" discover --json
jq -e '
  .configured == true
  and .codex_max_configured == true
  and (.providers[] | select(.name == "codex") | .accounts | length) == 3
  and (.agent_safe_commands | index("oauth-mux report --redacted --json") != null)
  and (.agent_safe_commands | index("oauth-mux doctor runtime --json") != null)
  and (.agent_safe_commands | index("oauth-mux route explain --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux route select --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux repair-plan --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux codex config-candidate --json") == null)
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

printf 'first-run e2e: route explain reports no recorded health without mutation\n'
route_explain_json="$tmp/route-explain-codex-max.json"
run_json "$route_explain_json" route explain --profile codex-max --capability codex-max --json
jq -e '
  .action == "explain"
  and .profile == "codex-max"
  and .capability == "codex-max"
  and .ok == false
  and .selected == null
  and (.routes | length) == 3
  and all(.routes[]; .provider == "codex" and .capability == "codex-max" and .action.mutating == false)
  and all(.routes[]; .action.kind == "fix_runtime" or .action.kind == "probe_needed")
' "$route_explain_json" >/dev/null

printf 'first-run e2e: route select refuses unrecorded health evidence\n'
route_select_json="$tmp/route-select-codex-max.json"
set +e
omux route select --profile codex-max --capability codex-max --json >"$route_select_json" 2>"$tmp/route-select-codex-max.stderr"
route_select_status=$?
set -e
if [ "$route_select_status" -eq 0 ]; then
  printf 'first-run e2e assertion failed: route select should fail before health is recorded\n' >&2
  exit 1
fi
jq -e '
  .action == "select"
  and .ok == false
  and .selected == null
  and (.routes | length) == 3
' "$route_select_json" >/dev/null

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

printf 'first-run e2e: config-merge backs up drift config and preserves other providers\n'
drift_dir="$tmp/drift"
mkdir -p "$drift_dir"
drift_config="$drift_dir/config.json"
drift_candidate="$drift_dir/codex-max.config.json"
drift_backup="$drift_dir/config.backup.json"
drift_store_root="$tmp/drift-data/codex"
cat >"$drift_config" <<'JSON'
{
  "version": 1,
  "providers": {
    "claude": {
      "kind": "claude",
      "accounts": {
        "personal": {
          "secret": { "backend": "env", "variable": "CLAUDE_TOKEN" }
        }
      }
    },
    "codex": {
      "kind": "codex",
      "config_dir_env": "CODEX_HOME",
      "accounts": {
        "default": {
          "secret": { "backend": "env", "variable": "CODEX_TOKEN" }
        }
      }
    }
  },
  "profiles": {
    "default": {
      "providers": ["claude:personal", "codex:default"],
      "strategy": "health-weighted"
    }
  },
  "strategies": {
    "health-weighted": {
      "kind": "health-weighted",
      "rate_limit_penalty": -10,
      "failure_penalty": -20,
      "success_bonus": 1
    }
  }
}
JSON
drift_omux() (
  unset OMUX_CONFIG_DIR
  unset OMUX_STATE_DIR
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  export OMUX_CONFIG="$drift_config"
  export OMUX_CODEX_STORE_ROOT="$drift_store_root"
  "$bin" "$@"
)
drift_candidate_json="$tmp/drift-config-candidate.json"
drift_omux codex config-candidate --output "$drift_candidate" --json >"$drift_candidate_json"
jq -e --arg path "$drift_candidate" '
  .created == true
  and .candidate_config == $path
  and any(.next_commands[]; contains("oauth-mux codex config-merge --candidate") and contains($path))
' "$drift_candidate_json" >/dev/null
drift_merge_json="$tmp/drift-config-merge.json"
drift_omux codex config-merge --candidate "$drift_candidate" --backup "$drift_backup" --json >"$drift_merge_json"
jq -e --arg backup "$drift_backup" '
  .merged == true
  and .backup_config == $backup
  and .reason == "merged_codex_max_candidate"
' "$drift_merge_json" >/dev/null
test -f "$drift_backup"
jq -e '
  (.providers.claude.accounts.personal.secret.backend == "env")
  and (.providers.codex.accounts.default.secret.backend == "env")
  and (.providers.codex.accounts["max-1"].secret.backend == "file")
  and (.providers.codex.accounts["max-2"].secret.backend == "file")
  and (.providers.codex.accounts["max-3"].secret.backend == "file")
  and (.profiles["codex-max"].providers | length) == 3
  and (.profiles.default.providers | index("claude:personal") != null)
' "$drift_config" >/dev/null
jq -e '
  (.providers.claude.accounts.personal.secret.backend == "env")
  and (.providers.codex.accounts.default.secret.backend == "env")
' "$drift_backup" >/dev/null

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

printf 'first-run e2e: Codex live-qa requires explicit spend confirmation\n'
live_qa_json="$tmp/live-qa-unconfirmed.json"
set +e
omux codex live-qa --json >"$live_qa_json" 2>"$tmp/live-qa-unconfirmed.stderr"
live_qa_status=$?
set -e
if [ "$live_qa_status" -eq 0 ]; then
  printf 'first-run e2e assertion failed: live-qa without confirmation should fail\n' >&2
  exit 1
fi
jq -e '
  .ok == false
  and .error == "confirmation_required"
  and .spends_provider_calls == true
' "$live_qa_json" >/dev/null

printf 'first-run e2e: Codex help remains non-mutating\n'
help_out="$(omux codex canary --help)"
expect_contains "$help_out" "non-mutating" "Codex help declares non-mutating behavior"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e passed\n'
