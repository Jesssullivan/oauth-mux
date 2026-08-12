#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"

if [ ! -x "$bin" ]; then
  printf 'missing oauth-mux binary: %s\n' "$bin" >&2
  printf 'run `zig build` or `just build-local` first\n' >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'missing jq; run through `nix develop --command just first-run-e2e-local`\n' >&2
  exit 1
fi

operator_home="${HOME:-}"
tmp_parent="${TMPDIR:-/tmp}"
if [ -n "$operator_home" ] && { [ "$tmp_parent" = "$operator_home" ] || [[ "$tmp_parent" == "$operator_home/"* ]]; }; then
  tmp_parent="/tmp"
fi
tmp="$(mktemp -d "$tmp_parent/oauth-mux-first-run.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

home="$tmp/home"
xdg_config="$tmp/xdg-config"
xdg_state="$tmp/xdg-state"
xdg_data="$tmp/xdg-data"
xdg_runtime="$tmp/xdg-runtime"

case "$(uname -s)" in
  Darwin) expected_claude_secret_backend="keychain" ;;
  Linux) expected_claude_secret_backend="file" ;;
  *)
    printf 'unsupported first-run e2e platform: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

mkdir -p "$home" "$xdg_config" "$xdg_state" "$xdg_data" "$xdg_runtime"
chmod 0700 "$xdg_runtime"

config_path="$xdg_config/oauth-mux/config.json"
candidate_config_path="$xdg_config/oauth-mux/codex-max.config.json"
store_root="$xdg_data/oauth-mux/codex"
claude_config_root="$xdg_data/oauth-mux/claude"
legacy_store_root="$home/.local/share/oauth-mux/codex"

omux() (
  unset OMUX_CONFIG
  unset OMUX_CONFIG_DIR
  unset OMUX_STATE_DIR
  unset OMUX_CODEX_STORE_ROOT
  unset OMUX_CLAUDE_CONFIG_ROOT
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

sentinel_bin="$tmp/tin3006-bin"
sentinel_log="$tmp/tin3006-executed"
sentinel_trace="$tmp/tin3006-trace"
mkdir -p "$sentinel_bin"
for sentinel_name in claude codex oauth-mux security secret-tool launchctl systemctl brew nix tin3006-credential-sentinel; do
  cat >"$sentinel_bin/$sentinel_name" <<'SENTINEL'
#!/usr/bin/env bash
printf '%s\n' "${0##*/}" >>"${TIN3006_SENTINEL_LOG:?}"
exit 97
SENTINEL
  chmod 0755 "$sentinel_bin/$sentinel_name"
done

planning_omux() (
  export PATH="$sentinel_bin:$PATH"
  export TIN3006_SENTINEL_LOG="$sentinel_log"
  export OMUX_TRACE=1
  export OMUX_TRACE_FILE="$sentinel_trace"
  omux "$@"
)

planning_omux_with_config() (
  config_override="$1"
  shift
  unset OMUX_CONFIG_DIR
  unset OMUX_STATE_DIR
  unset OMUX_CODEX_STORE_ROOT
  unset OMUX_CLAUDE_CONFIG_ROOT
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  export OMUX_CONFIG="$config_override"
  export PATH="$sentinel_bin:$PATH"
  export TIN3006_SENTINEL_LOG="$sentinel_log"
  export OMUX_TRACE=1
  export OMUX_TRACE_FILE="$sentinel_trace"
  "$bin" "$@"
)

planning_omux_with_config_and_state() (
  config_override="$1"
  state_override="$2"
  shift 2
  unset OMUX_CONFIG_DIR
  unset OMUX_CODEX_STORE_ROOT
  unset OMUX_CLAUDE_CONFIG_ROOT
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  export OMUX_CONFIG="$config_override"
  export OMUX_STATE_DIR="$state_override"
  export PATH="$sentinel_bin:$PATH"
  export TIN3006_SENTINEL_LOG="$sentinel_log"
  export OMUX_TRACE=1
  export OMUX_TRACE_FILE="$sentinel_trace"
  "$bin" "$@"
)

snapshot_isolated_roots() {
  output_file="$1"
  {
    for root in "$home" "$xdg_config" "$xdg_state" "$xdg_data" "$xdg_runtime"; do
      printf 'root %s\n' "$root"
      if [ ! -e "$root" ]; then
        printf 'missing\n'
        continue
      fi
      find "$root" -mindepth 1 -print | LC_ALL=C sort | while IFS= read -r path; do
        relative="${path#"$root"/}"
        if [ -L "$path" ]; then
          printf 'link %s -> %s\n' "$relative" "$(readlink "$path")"
        elif [ -d "$path" ]; then
          printf 'dir %s\n' "$relative"
        elif [ -f "$path" ]; then
          printf 'file %s ' "$relative"
          cksum <"$path"
        else
          printf 'other %s\n' "$relative"
        fi
      done
    done
  } >"$output_file"
}

assert_planning_truth() {
  output_file="$1"
  jq -e '
    .execution_available == false
    and .mutates == false
    and .reads_credential_material == false
    and .executes_provider_cli == false
    and .spends_provider_calls == false
    and .managed_claude_forwarding == "compile_disabled"
    and .claim_level == "planning_only"
    and .readiness_claimed == false
    and .binary_observation.metadata_only == true
    and .binary_observation.version_execution == false
    and (.binary_observation.running_version | type == "string")
  ' "$output_file" >/dev/null
}

printf 'first-run e2e: version from isolated environment\n'
version_out="$(omux version)"
expect_contains "$version_out" "oauth-mux " "version prints binary version"

printf 'first-run e2e: setup and repair planning are zero-touch before config\n'
planning_before="$tmp/tin3006-before"
planning_after="$tmp/tin3006-after"
snapshot_isolated_roots "$planning_before"
setup_before="$tmp/tin3006-setup-before.json"
repair_before="$tmp/tin3006-repair-before.json"
planning_omux setup --provider claude --label work --json >"$setup_before"
planning_omux repair claude:work --json >"$repair_before"
setup_login_preview="$tmp/tin2071-setup-login-preview.json"
planning_omux setup login --provider claude --label work --json >"$setup_login_preview"
assert_planning_truth "$setup_before"
assert_planning_truth "$repair_before"
planning_omux setup --provider claude --label work --json >"$tmp/tin3006-setup-before-repeat.json"
planning_omux repair claude:work --json >"$tmp/tin3006-repair-before-repeat.json"
cmp "$setup_before" "$tmp/tin3006-setup-before-repeat.json"
cmp "$repair_before" "$tmp/tin3006-repair-before-repeat.json"
jq -e '
  .command == "setup"
  and .provider == "claude"
  and .label == "work"
  and .mutates == false
  and .status == "config_missing"
  and .config.state == "missing"
  and .next_action.command == "omux init"
  and .next_action.mutates == true
' "$setup_before" >/dev/null
jq -e '
  .command == "repair"
  and .target == "claude:work"
  and .provider == "claude"
  and .label == "work"
  and .status == "config_missing"
  and .config.state == "missing"
' "$repair_before" >/dev/null
jq -e '
  .ok == false
  and .executed == false
  and .confirmation_required == true
  and .requires == "--confirm-login"
  and .experimental == true
  and .browser_isolation_enforced == false
  and .trusted_provider_required == true
  and .attended_proof_required == true
  and .post_spawn_cleanup == "preserved_manual_cleanup"
  and .provider == "claude"
  and .label == "work"
  and .mutates == false
  and .reads_config == false
  and .reads_credentials == false
  and .reads_cookies == false
  and .launches_browser == false
  and .executes_provider_cli == false
  and (.confirm_command | contains("omux setup login --provider claude"))
' "$setup_login_preview" >/dev/null

setup_login_json_confirm="$tmp/tin2071-setup-login-json-confirm.json"
if planning_omux setup login --provider claude --label work --confirm-login --json >"$setup_login_json_confirm"; then
  printf 'first-run e2e assertion failed: interactive setup login accepted --json\n' >&2
  exit 1
fi
jq -e '
  .ok == false
  and .executed == false
  and .error == "interactive_json_conflict"
  and .launches_browser == false
  and .executes_provider_cli == false
' "$setup_login_json_confirm" >/dev/null

help_label_setup="$tmp/tin3006-help-label-setup.json"
planning_omux setup --provider codex --label --help --json >"$help_label_setup"
assert_planning_truth "$help_label_setup"
jq -e '
  .command == "setup"
  and .provider == "codex"
  and .label == "--help"
  and .status == "config_missing"
  and .config.state == "missing"
' "$help_label_setup" >/dev/null

invalid_setup="$tmp/tin3006-invalid-setup.json"
if planning_omux setup --provider --json >"$invalid_setup"; then
  printf 'first-run e2e assertion failed: invalid setup planning returned success\n' >&2
  exit 1
fi
assert_planning_truth "$invalid_setup"
jq -e '
  .ok == false
  and .error == "missing_value"
  and .invalid_argument == "--provider"
  and .status == "invalid_request"
' "$invalid_setup" >/dev/null

adversarial_label=$'work\'"\nnext_action=forged'
setup_adversarial="$tmp/tin3006-setup-adversarial.json"
planning_omux setup --provider claude --label "$adversarial_label" --json >"$setup_adversarial"
assert_planning_truth "$setup_adversarial"
jq -e --arg label "$adversarial_label" '.label == $label' "$setup_adversarial" >/dev/null
setup_adversarial_text="$(planning_omux setup --provider claude --label "$adversarial_label")"
expect_contains "$setup_adversarial_text" 'label="work'\''\"\nnext_action=forged"' "planning text quotes adversarial label"
if printf '%s\n' "$setup_adversarial_text" | grep -q '^next_action=forged$'; then
  printf 'first-run e2e assertion failed: adversarial label injected a text field\n' >&2
  exit 1
fi

snapshot_isolated_roots "$planning_after"
cmp "$planning_before" "$planning_after"
test ! -e "$sentinel_log"
test ! -e "$sentinel_trace"

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

printf 'first-run e2e: configured setup and repair plans remain zero-touch\n'
planning_configured_before="$tmp/tin3006-configured-before"
planning_configured_after="$tmp/tin3006-configured-after"
snapshot_isolated_roots "$planning_configured_before"
setup_configured="$tmp/tin3006-setup-configured.json"
repair_configured="$tmp/tin3006-repair-configured.json"
planning_omux setup --provider codex --label max-1 --json >"$setup_configured"
planning_omux repair codex:max-1 --json >"$repair_configured"
assert_planning_truth "$setup_configured"
assert_planning_truth "$repair_configured"
planning_omux setup --provider codex --label max-1 --json >"$tmp/tin3006-setup-configured-repeat.json"
planning_omux repair codex:max-1 --json >"$tmp/tin3006-repair-configured-repeat.json"
cmp "$setup_configured" "$tmp/tin3006-setup-configured-repeat.json"
cmp "$repair_configured" "$tmp/tin3006-repair-configured-repeat.json"
jq -e '
  .status == "capability_routes_ready_for_inspection"
  and .config.state == "valid"
  and .config.provider_configured == true
  and .config.label_configured == true
  and .config.matching_capabilities == 2
  and .capability == null
  and .capability_probeable == null
  and (.capability_routes | map(.name) | sort) == ["codex-max", "codex-mini"]
  and all(.capability_routes[];
    .probeable == true
    and (.planning_command | startswith("omux repair-plan "))
    and .planning_argv[0:4] == ["omux", "repair-plan", "--json", "--provider"]
  )
  and .health.key_addressable == true
  and .binary_observation.provider_cli_present == null
  and .next_action.command == null
  and (.next_action.instruction | contains("capability_routes"))
' "$setup_configured" >/dev/null
jq -e '
  .status == "capability_ambiguous"
  and .config.state == "valid"
  and .config.label_configured == true
  and .config.matching_capabilities == 2
  and .capability == null
  and (.capability_routes | map(.name) | sort) == ["codex-max", "codex-mini"]
  and all(.capability_routes[];
    .probeable == true
    and (.planning_command | startswith("omux repair-plan "))
    and .planning_argv[0:4] == ["omux", "repair-plan", "--json", "--provider"]
  )
  and .health.recorded == false
  and .repair_action == null
  and .next_action.command == null
  and (.next_action.instruction | contains("capability_routes"))
' "$repair_configured" >/dev/null

codex_max_only_config="$tmp/tin3006-codex-max-only-config.json"
jq '
  .profiles |= with_entries(select(.key == "codex-max"))
  | .profiles["codex-max"].providers |= map(select(endswith("#codex-max")))
  | .profiles["codex-max"].capability_degradation_chain = []
' "$config_path" >"$codex_max_only_config"
codex_max_plan="$tmp/tin3006-codex-max-plan.json"
planning_omux_with_config "$codex_max_only_config" repair codex:max-1 --json >"$codex_max_plan"
assert_planning_truth "$codex_max_plan"
jq -e '
  .status == "probe_needed"
  and .capability == "codex-max"
  and .capability_probeable == true
  and .config.matching_capabilities == 1
  and .health.key_addressable == true
  and .health.recorded == false
  and .repair_action.kind == "probe_needed"
  and .next_action.command == "omux probe --json --provider codex --account '\''max-1'\'' --capability '\''codex-max'\''"
  and .next_action.command_shell == "posix"
  and .next_action.platform_supported == true
  and .next_action.mutates == true
  and .next_action.reads_credential_material == true
  and .next_action.executes_provider_cli == true
  and .next_action.spends_provider_calls == true
' "$codex_max_plan" >/dev/null

adversarial_config="$tmp/tin3006-adversarial-config.json"
jq --arg label "$adversarial_label" '
  .providers.codex.accounts[$label] = .providers.codex.accounts["max-1"]
  | .profiles |= with_entries(select(.key == "codex-max"))
  | .profiles["codex-max"].providers |= map(select(endswith("#codex-max")))
  | .profiles["codex-max"].capability_degradation_chain = []
  | .profiles["codex-max"].providers += ["codex:\($label)#codex-max"]
' "$config_path" >"$adversarial_config"
adversarial_target="codex:$adversarial_label"
repair_adversarial="$tmp/tin3006-repair-adversarial.json"
planning_omux_with_config "$adversarial_config" repair "$adversarial_target" --json >"$repair_adversarial"
assert_planning_truth "$repair_adversarial"
jq -e --arg label "$adversarial_label" '
  .label == $label
  and .capability == "codex-max"
  and (.next_action.command | startswith("omux probe --json --provider codex --account "))
  and (.next_action.command | endswith(" --capability '\''codex-max'\''"))
' "$repair_adversarial" >/dev/null
repair_adversarial_text="$(planning_omux_with_config "$adversarial_config" repair "$adversarial_target")"
if printf '%s\n' "$repair_adversarial_text" | grep -q '^next_action=forged$'; then
  printf 'first-run e2e assertion failed: adversarial label injected a configured planning field\n' >&2
  exit 1
fi

nonexec_bin="$tmp/tin3006-nonexec-bin"
mkdir -p "$nonexec_bin"
printf '#!/bin/sh\nexit 97\n' >"$nonexec_bin/codex"
chmod 0644 "$nonexec_bin/codex"
nonexec_plan="$tmp/tin3006-nonexec-plan.json"
(
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  export PATH="$nonexec_bin"
  OMUX_CONFIG="$codex_max_only_config" "$bin" setup --provider codex --label max-1 --json
) >"$nonexec_plan"
assert_planning_truth "$nonexec_plan"
jq -e '
  .status == "provider_cli_missing"
  and .binary_observation.provider_cli_present == false
  and .next_action.command == null
  and (.next_action.instruction | contains("install"))
' "$nonexec_plan" >/dev/null

ambiguous_config="$tmp/tin3006-ambiguous-config.json"
cat >"$ambiguous_config" <<'JSON'
{
  "version": 1,
  "providers": {
    "claude": {
      "kind": "claude",
      "accounts": {
        "shared": {
          "secret": { "backend": "env", "variable": "TIN3006_CLAUDE_TOKEN" }
        }
      }
    },
    "codex": {
      "kind": "codex",
      "accounts": {
        "shared": {
          "secret": { "backend": "env", "variable": "TIN3006_CODEX_TOKEN" }
        }
      }
    }
  }
}
JSON
http_probe_config="$tmp/tin3006-http-probe-config.json"
jq '
  .provider_definitions = {
    "claude": {
      "name": "claude",
      "repair": { "owner": "upstream_cli_login" },
      "capabilities": [{
        "name": "auth-status",
        "probe": {
          "transport": "http",
          "method": "GET",
          "url": "https://example.invalid/probe",
          "auth": "none",
          "budget": "free_local"
        }
      }],
      "failure_rules": [{
        "status": 401,
        "class": { "dead": "token_revoked" }
      }]
    }
  }
  | .providers = { "claude": .providers.claude }
' "$ambiguous_config" >"$http_probe_config"
http_probe_plan="$tmp/tin3006-http-probe-plan.json"
(
  export HOME="$home"
  export XDG_CONFIG_HOME="$xdg_config"
  export XDG_STATE_HOME="$xdg_state"
  export XDG_DATA_HOME="$xdg_data"
  export XDG_RUNTIME_DIR="$xdg_runtime"
  export PATH="$nonexec_bin"
  OMUX_CONFIG="$http_probe_config" "$bin" repair claude:shared --json
) >"$http_probe_plan"
assert_planning_truth "$http_probe_plan"
if ! jq -e '
  .status == "probe_needed"
  and .capability == "auth-status"
  and .binary_observation.provider_cli_present == null
  and .next_action.reads_credential_material == false
  and .next_action.executes_provider_cli == false
  and .next_action.spends_provider_calls == true
' "$http_probe_plan" >/dev/null; then
  printf 'first-run e2e assertion failed: exact HTTP probe effects were not preserved\n' >&2
  jq . "$http_probe_plan" >&2
  exit 1
fi

ambiguous_plan="$tmp/tin3006-ambiguous-plan.json"
planning_omux_with_config "$ambiguous_config" repair shared --json >"$ambiguous_plan"
assert_planning_truth "$ambiguous_plan"
jq -e '
  .status == "ambiguous_target"
  and .provider == null
  and .config.matching_providers == 2
  and .next_action.command == null
  and (.next_action.instruction | contains("provider-qualified"))
' "$ambiguous_plan" >/dev/null

claude_plan="$tmp/tin3006-claude-plan.json"
planning_omux_with_config "$ambiguous_config" repair claude:shared --json >"$claude_plan"
assert_planning_truth "$claude_plan"
jq -e '
  .status == "probe_needed"
  and .capability == "auth-status"
  and .capability_probeable == true
  and .config.matching_capabilities == 1
  and .next_action.command == "omux probe --json --provider claude --account '\''shared'\'' --capability '\''auth-status'\''"
  and .next_action.mutates == true
  and .next_action.reads_credential_material == true
  and .next_action.executes_provider_cli == true
  and .next_action.spends_provider_calls == false
' "$claude_plan" >/dev/null

claude_haiku_config="$tmp/tin3006-claude-haiku-config.json"
jq '
  .profiles = {
    "claude-haiku": {
      "providers": ["claude:shared#haiku"]
    }
  }
' "$ambiguous_config" >"$claude_haiku_config"
claude_haiku_plan="$tmp/tin3006-claude-haiku-plan.json"
planning_omux_with_config "$claude_haiku_config" repair claude:shared --json >"$claude_haiku_plan"
assert_planning_truth "$claude_haiku_plan"
jq -e '
  .status == "passive_observation_required"
  and .capability == "haiku"
  and .capability_probeable == false
  and .config.matching_capabilities == 1
  and .capability_routes == [{
    "name": "haiku",
    "probeable": false,
    "planning_command": "omux repair-plan --json --provider claude --account '\''shared'\'' --capability '\''haiku'\''",
    "planning_argv": ["omux", "repair-plan", "--json", "--provider", "claude", "--account", "shared", "--capability", "haiku"]
  }]
  and .repair_action == null
  and .next_action.command == null
  and (.next_action.instruction | contains("passive route evidence"))
' "$claude_haiku_plan" >/dev/null

account_only_state="$tmp/tin3006-account-only-state"
mkdir -p "$account_only_state"
cat >"$account_only_state/health.json" <<'JSON'
{
  "version": 2,
  "accounts": [
    {
      "key": "claude:shared",
      "liveness": {
        "state": "live",
        "availability": "available"
      }
    }
  ]
}
JSON
account_only_haiku_plan="$tmp/tin3006-account-only-haiku-plan.json"
planning_omux_with_config_and_state \
  "$claude_haiku_config" \
  "$account_only_state" \
  repair claude:shared --json >"$account_only_haiku_plan"
assert_planning_truth "$account_only_haiku_plan"
jq -e '
  .status == "passive_observation_required"
  and .capability == "haiku"
  and .health.recorded == false
  and .repair_action == null
  and .next_action.command == null
' "$account_only_haiku_plan" >/dev/null

claude_mixed_config="$tmp/tin3006-claude-mixed-config.json"
jq '
  .profiles = {
    "claude-mixed": {
      "providers": [
        "claude:shared#auth-status",
        "claude:shared#haiku"
      ]
    }
  }
' "$ambiguous_config" >"$claude_mixed_config"
claude_mixed_plan="$tmp/tin3006-claude-mixed-plan.json"
planning_omux_with_config "$claude_mixed_config" repair claude:shared --json >"$claude_mixed_plan"
assert_planning_truth "$claude_mixed_plan"
jq -e '
  .status == "capability_ambiguous"
  and .capability == null
  and .capability_probeable == null
  and .config.matching_capabilities == 2
  and (.capability_routes | map(.name)) == ["auth-status", "haiku"]
  and (.capability_routes | map(.probeable)) == [true, false]
  and all(.capability_routes[]; .planning_command != null and .planning_argv != null)
  and .next_action.command == null
' "$claude_mixed_plan" >/dev/null

codex_alias_config="$tmp/tin3006-codex-alias-config.json"
sed 's/#codex-max/#gpt-5.5/g' "$codex_max_only_config" >"$codex_alias_config"
codex_alias_plan="$tmp/tin3006-codex-alias-plan.json"
planning_omux_with_config "$codex_alias_config" repair codex:max-1 --json >"$codex_alias_plan"
assert_planning_truth "$codex_alias_plan"
jq -e '
  .status == "probe_needed"
  and .capability == "gpt-5.5"
  and .capability_probeable == true
  and .config.matching_capabilities == 1
  and .capability_routes[0].name == "gpt-5.5"
  and (.capability_routes[0].planning_command | endswith("--capability '\''gpt-5.5'\''"))
  and .capability_routes[0].planning_argv[-1] == "gpt-5.5"
  and (.next_action.command | endswith("--capability '\''gpt-5.5'\''"))
' "$codex_alias_plan" >/dev/null

quota_state="$tmp/tin3006-quota-state"
mkdir -p "$quota_state"
cat >"$quota_state/health.json" <<'JSON'
{
  "version": 2,
  "accounts": [
    {
      "key": "codex:max-1#codex-max",
      "last_probe_source": "capability_probe",
      "last_probe_hint_class": "quota_exhausted",
      "last_probe_decision": "try_next_account",
      "liveness": {
        "state": "live",
        "availability": "quota_exhausted",
        "window_resets_at": 4102444800,
        "exhausted_at": 1
      }
    }
  ]
}
JSON
cp "$quota_state/health.json" "$tmp/tin3006-quota-health-before.json"
quota_plan="$tmp/tin3006-quota-plan.json"
planning_omux_with_config_and_state "$codex_max_only_config" "$quota_state" repair codex:max-1 --json >"$quota_plan"
assert_planning_truth "$quota_plan"
jq -e '
  .status == "wait_for_quota"
  and .health.recorded == true
  and .health.summary == "quota_exhausted:reset@4102444800"
  and .repair_action.kind == "wait_for_quota"
  and .next_action.command == null
' "$quota_plan" >/dev/null
cmp "$tmp/tin3006-quota-health-before.json" "$quota_state/health.json"

long_label="$(printf '%0300d' 0 | tr '0' x)"
long_label_config="$tmp/tin3006-long-label-config.json"
jq --arg label "$long_label" '
  .providers.codex.accounts[$label] = .providers.codex.accounts["max-1"]
' "$config_path" >"$long_label_config"
long_setup="$tmp/tin3006-long-setup.json"
long_repair="$tmp/tin3006-long-repair.json"
planning_omux_with_config "$long_label_config" setup --provider codex --label "$long_label" --json >"$long_setup"
planning_omux_with_config "$long_label_config" repair "codex:$long_label" --json >"$long_repair"
assert_planning_truth "$long_setup"
assert_planning_truth "$long_repair"
jq -e '
  .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and .next_action.command == null
' "$long_setup" >/dev/null
jq -e '
  .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and .health.recorded == false
  and .repair_action == null
  and .next_action.command == null
' "$long_repair" >/dev/null

boundary_label="$(printf '%0240d' 0 | tr '0' x)"
boundary_label_config="$tmp/tin3006-boundary-label-config.json"
jq --arg label "$boundary_label" '
  .providers.codex.accounts[$label] = .providers.codex.accounts["max-1"]
' "$config_path" >"$boundary_label_config"
boundary_setup="$tmp/tin3006-boundary-setup.json"
boundary_repair="$tmp/tin3006-boundary-repair.json"
boundary_unconfigured_setup="$tmp/tin3006-boundary-unconfigured-setup.json"
boundary_missing_setup="$tmp/tin3006-boundary-missing-setup.json"
boundary_invalid_setup="$tmp/tin3006-boundary-invalid-setup.json"
boundary_invalid_config="$tmp/tin3006-boundary-invalid-config.json"
printf '{\n' >"$boundary_invalid_config"
planning_omux_with_config "$boundary_label_config" setup --provider codex --label "$boundary_label" --json >"$boundary_setup"
planning_omux_with_config "$boundary_label_config" repair "codex:$boundary_label" --json >"$boundary_repair"
planning_omux setup --provider codex --label "$boundary_label" --json >"$boundary_unconfigured_setup"
planning_omux_with_config "$tmp/tin3006-missing-config.json" setup --provider codex --label "$boundary_label" --json >"$boundary_missing_setup"
planning_omux_with_config "$boundary_invalid_config" setup --provider codex --label "$boundary_label" --json >"$boundary_invalid_setup"
assert_planning_truth "$boundary_setup"
assert_planning_truth "$boundary_repair"
assert_planning_truth "$boundary_unconfigured_setup"
assert_planning_truth "$boundary_missing_setup"
assert_planning_truth "$boundary_invalid_setup"
jq -e '
  .config.matching_capabilities == 2
  and .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and all(.capability_routes[]; .planning_command == null and .planning_argv == null)
' "$boundary_setup" >/dev/null
jq -e '
  .config.matching_capabilities == 2
  and .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and all(.capability_routes[]; .planning_command == null and .planning_argv == null)
' "$boundary_repair" >/dev/null
jq -e '
  .config.label_configured == false
  and .config.matching_capabilities == 2
  and .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and .next_action.command == null
' "$boundary_unconfigured_setup" >/dev/null
jq -e '
  .config.state == "missing"
  and .config.matching_capabilities == 2
  and .status == "label_not_health_addressable"
  and .health.key_addressable == false
  and .next_action.command == null
  and all(.capability_routes[]; .planning_command == null and .planning_argv == null)
' "$boundary_missing_setup" >/dev/null
jq -e '
  .config.state == "invalid"
  and .status == "config_invalid"
  and .health.key_addressable == false
  and .next_action.command == "omux config validate"
' "$boundary_invalid_setup" >/dev/null

reserved_label_plan="$tmp/tin3006-reserved-label.json"
if planning_omux repair 'codex:max-1#codex-max' --json >"$reserved_label_plan"; then
  printf 'first-run e2e assertion failed: reserved health-key label returned success\n' >&2
  exit 1
fi
assert_planning_truth "$reserved_label_plan"
jq -e '
  .error == "reserved_character"
  and .status == "invalid_request"
' "$reserved_label_plan" >/dev/null

run_label_config="$tmp/tin3006-run-label-config.json"
jq '
  .providers.codex.accounts.run = .providers.codex.accounts["max-1"]
  | .profiles["codex-max"].providers += ["codex:run#codex-max"]
' "$codex_max_only_config" >"$run_label_config"
run_label_plan="$tmp/tin3006-run-label-plan.json"
planning_omux_with_config "$run_label_config" repair codex:run --json >"$run_label_plan"
assert_planning_truth "$run_label_plan"
jq -e '
  .label == "run"
  and .status == "probe_needed"
  and .capability == "codex-max"
' "$run_label_plan" >/dev/null

for reserved_run_order in before_separator after_separator; do
  reserved_run_plan="$tmp/tin3006-reserved-run-$reserved_run_order.json"
  if [ "$reserved_run_order" = before_separator ]; then
    if planning_omux repair --json run >"$reserved_run_plan"; then
      printf 'first-run e2e assertion failed: bare run label after option returned success\n' >&2
      exit 1
    fi
  elif planning_omux repair --json -- run >"$reserved_run_plan"; then
    printf 'first-run e2e assertion failed: bare run label after separator returned success\n' >&2
    exit 1
  fi
  assert_planning_truth "$reserved_run_plan"
  jq -e '
    .error == "reserved_subcommand"
    and .invalid_argument == "run"
    and .status == "invalid_request"
  ' "$reserved_run_plan" >/dev/null
done

flag_label_config="$tmp/tin3006-flag-label-config.json"
jq '
  .providers.codex.accounts["--json"] = .providers.codex.accounts["max-1"]
' "$config_path" >"$flag_label_config"
flag_repair_plan="$tmp/tin3006-flag-label-repair.json"
planning_omux_with_config "$flag_label_config" repair codex:--json --json >"$flag_repair_plan"
assert_planning_truth "$flag_repair_plan"
jq -e '
  .status == "capability_ambiguous"
  and .label == "--json"
  and .next_action.command == null
  and all(.capability_routes[]; (.planning_command | contains("--account '\''--json'\''")))
  and all(.capability_routes[]; .planning_argv[6] == "--json")
' "$flag_repair_plan" >/dev/null

flag_setup_plan="$tmp/tin3006-flag-label-setup.json"
planning_omux_with_config "$flag_label_config" setup --json --provider=codex --label=--json >"$flag_setup_plan"
assert_planning_truth "$flag_setup_plan"
jq -e '
  .status == "capability_routes_ready_for_inspection"
  and .provider == "codex"
  and .label == "--json"
  and .config.label_configured == true
' "$flag_setup_plan" >/dev/null

flag_capability_plan="$tmp/tin3006-flag-label-capability-plan.json"
planning_omux_with_config "$flag_label_config" repair-plan --json --provider codex --account --json --capability codex-max >"$flag_capability_plan"
jq -e --arg quoted "'--json'" '
  (.routes | length) == 1
  and .routes[0].account == "--json"
  and (
    if .routes[0].action.command != null
    then (.routes[0].action.command | contains($quoted))
    else true
    end
  )
  and (
    if .routes[0].action.diagnostic_command != null
    then (.routes[0].action.diagnostic_command | contains($quoted))
    else true
    end
  )
' "$flag_capability_plan" >/dev/null

flag_enroll_plan="$tmp/tin3006-flag-label-enroll-plan.json"
planning_omux_with_config "$flag_label_config" enroll plan codex --json --account --json >"$flag_enroll_plan"
jq -e --arg quoted "'--json'" '
  .account == "--json"
  and (.steps[] | select(.kind == "provider_login")
    | .command == "oauth-mux codex login-device --account '\''--json'\''")
  and all(.steps[]; if .command != null and (.kind == "provider_login" or .kind == "runtime_proof")
    then (.command | contains($quoted))
    else true
    end)
  and (.future_provider_neutral_command.command | contains($quoted))
' "$flag_enroll_plan" >/dev/null

flag_enroll_preview="$tmp/tin3006-flag-label-enroll-preview.json"
planning_omux_with_config "$flag_label_config" enroll codex --account --json --json >"$flag_enroll_preview"
jq -e '
  .account == "--json"
  and .executed == false
  and .confirmation_required == true
  and .confirm_command == "oauth-mux enroll codex --account '\''--json'\'' --confirm-enroll --json"
' "$flag_enroll_preview" >/dev/null

invalid_secret_env="$tmp/tin3006-invalid-secret-env.json"
planning_omux_with_config "$flag_label_config" enroll figma --account design --mode pat --secret-env 'FIGMA; touch /tmp/forbidden' --json >"$invalid_secret_env"
jq -e '
  .ok == false
  and .executed == false
  and .error == "invalid_secret_env"
  and .mutates == false
  and .spends_provider_calls == false
  and .secret_env == "FIGMA; touch /tmp/forbidden"
  and .requires == "[A-Za-z_][A-Za-z0-9_]*"
' "$invalid_secret_env" >/dev/null

leading_label_config="$tmp/tin3006-leading-label-config.json"
jq '
  .providers.codex.accounts["-work"] = .providers.codex.accounts["max-1"]
' "$config_path" >"$leading_label_config"
leading_repair_plan="$tmp/tin3006-leading-label-repair.json"
planning_omux_with_config "$leading_label_config" repair --json -- -work >"$leading_repair_plan"
assert_planning_truth "$leading_repair_plan"
jq -e '
  .label == "-work"
  and .config.label_configured == true
  and .status == "capability_ambiguous"
' "$leading_repair_plan" >/dev/null

command_secret_config="$tmp/tin3006-command-secret.json"
cat >"$command_secret_config" <<'JSON'
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "command-backed": {
          "secret": {
            "backend": "command",
            "command": ["tin3006-credential-sentinel"]
          }
        }
      }
    }
  }
}
JSON
command_secret_plan="$tmp/tin3006-command-secret-plan.json"
planning_omux_with_config "$command_secret_config" repair codex:command-backed --json >"$command_secret_plan"
assert_planning_truth "$command_secret_plan"
jq -e '
  .config.state == "valid"
  and .config.label_configured == true
  and .reads_credential_material == false
' "$command_secret_plan" >/dev/null

if command -v fish >/dev/null 2>&1; then
  printf 'first-run e2e: fish completion predicates respect command positions\n'
  fish_completions="$tmp/tin3006-completions.fish"
  planning_omux completions fish >"$fish_completions"
  fish_candidates() {
    OMUX_COMPLETIONS="$fish_completions" fish -c \
      'source "$OMUX_COMPLETIONS"; complete -C "$argv[1]"' -- "$1" |
      cut -f1
  }

  repair_root_candidates="$(fish_candidates 'oauth-mux repair ')"
  repair_target_candidates="$(fish_candidates 'oauth-mux repair work ')"
  setup_codex_value_candidates="$(fish_candidates 'oauth-mux setup --provider codex ')"
  setup_claude_value_candidates="$(fish_candidates 'oauth-mux setup --provider claude ')"
  setup_codex_flag_candidates="$(fish_candidates 'oauth-mux setup --provider codex -')"
  setup_claude_flag_candidates="$(fish_candidates 'oauth-mux setup --provider claude -')"
  codex_root_candidates="$(fish_candidates 'oauth-mux codex ')"
  codex_run_candidates="$(fish_candidates 'oauth-mux codex run ')"
  codex_login_candidates="$(fish_candidates 'oauth-mux codex login-device ')"

  expect_contains "$repair_root_candidates" "run" "repair root offers legacy executor"
  if printf '%s\n' "$repair_target_candidates" | grep -Fxq 'run'; then
    printf 'first-run e2e assertion failed: repair target leaked the legacy run completion\n' >&2
    exit 1
  fi
  expect_contains "$setup_codex_flag_candidates" "--label" "setup provider value retains planning flags"
  expect_contains "$setup_claude_flag_candidates" "--label" "setup Claude value retains planning flags"
  if printf '%s\n%s\n' "$setup_codex_value_candidates" "$setup_claude_value_candidates" |
    grep -Eq '^(codex|login-device|broker-run)$'; then
    printf 'first-run e2e assertion failed: setup option value leaked positional/subcommand completions\n' >&2
    exit 1
  fi
  expect_contains "$codex_root_candidates" "login-device" "Codex root offers Codex verbs"
  if printf '%s\n%s\n' "$codex_run_candidates" "$codex_login_candidates" |
    grep -Eq '^(login-device|broker-run|run|setup)$'; then
    printf 'first-run e2e assertion failed: selected Codex verb leaked sibling verb completions\n' >&2
    exit 1
  fi
fi

snapshot_isolated_roots "$planning_configured_after"
cmp "$planning_configured_before" "$planning_configured_after"
test ! -e "$sentinel_log"
test ! -e "$sentinel_trace"

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

printf 'first-run e2e: scoped runtime doctor reports Codex Max route readiness\n'
runtime_doctor_scoped="$tmp/doctor-runtime-codex-max.json"
run_json "$runtime_doctor_scoped" doctor runtime --profile codex-max --capability codex-max --json
jq -e '
  .configured == true
  and .config_valid == true
  and .ok == false
  and .scope.profile == "codex-max"
  and .scope.capability == "codex-max"
  and .accounts == 3
  and .action_needed_accounts == 3
  and (.route_reports | length) == 3
  and all(.route_reports[]; .provider == "codex" and .capability == "codex-max" and .ready == false)
' "$runtime_doctor_scoped" >/dev/null
expect_not_contains "$(cat "$runtime_doctor_scoped")" "$store_root/max-1" "scoped runtime doctor does not print concrete Codex store paths"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: accounts inventory is redacted and non-mutating\n'
accounts_json="$tmp/accounts-codex.json"
run_json "$accounts_json" accounts list --provider codex --json
jq -e '
  .configured == true
  and .filter_provider == "codex"
  and (.accounts | length) == 3
  and all(.accounts[]; .provider == "codex" and .state == "action_needed" and .secret_backend == "file")
  and all(.accounts[]; (.capabilities | length) == 2)
  and all(.accounts[].capabilities[]; .proof_status == "live_proven" and .health_recorded == false and .selectable == false)
  and (.agent_safe_commands | index("oauth-mux accounts list --json") != null)
  and (.agent_safe_commands | index("oauth-mux doctor runtime --provider <provider> --account <account> --json") != null)
' "$accounts_json" >/dev/null
expect_not_contains "$(cat "$accounts_json")" "$store_root/max-1" "accounts list does not print concrete Codex store paths"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: enroll plan is provider-neutral and non-mutating\n'
enroll_plan_json="$tmp/enroll-plan-codex.json"
run_json "$enroll_plan_json" enroll plan codex --account max-4 --json
jq -e '
  .action == "plan"
  and .mutates == false
  and .provider == "codex"
  and .account == "max-4"
  and .provider_configured == true
  and .provider_neutral_mutation_supported == true
  and (.existing_accounts | length) == 3
  and (.steps[] | select(.kind == "inspect_accounts") | .agent_safe == true)
  and (.steps[] | select(.kind == "provider_login") | .command == "oauth-mux codex login-device max-4" and .interactive == true and .agent_safe == false)
  and (.steps[] | select(.kind == "runtime_proof") | .command == "oauth-mux doctor runtime --provider codex --account max-4 --capability codex-max --json" and .agent_safe == true)
  and .future_provider_neutral_command.available == true
  and (.future_provider_neutral_command.command | contains("--confirm-enroll"))
' "$enroll_plan_json" >/dev/null
expect_not_contains "$(cat "$enroll_plan_json")" "$store_root/max-1" "enroll plan does not print concrete Codex store paths"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: enroll codex requires explicit confirmation\n'
enroll_unconfirmed_json="$tmp/enroll-codex-unconfirmed.json"
run_json "$enroll_unconfirmed_json" enroll codex --account max-4 --json
jq -e '
  .ok == false
  and .executed == false
  and .confirmation_required == true
  and .requires == "--confirm-enroll"
  and .mutates == true
  and .spends_provider_calls == false
  and (.confirm_command | contains("oauth-mux enroll codex --account max-4 --confirm-enroll --json"))
' "$enroll_unconfirmed_json" >/dev/null
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
  and (.agent_safe_commands | index("oauth-mux enroll plan <provider> --json") != null)
  and (.agent_safe_commands | index("oauth-mux route explain --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux route select --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux repair-plan --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux repair run --profile <profile> --capability <capability> --json") != null)
  and (.agent_safe_commands | index("oauth-mux codex config-candidate --json") == null)
' "$discover_json" >/dev/null

printf 'first-run e2e: repair-plan explains generated Codex Max routes without mutation\n'
repair_plan_json="$tmp/repair-plan-codex-max.json"
run_json "$repair_plan_json" repair-plan --profile codex-max --capability codex-max --json
jq -e '
  .profile == "codex-max"
  and (.routes | length) == 3
  and all(.routes[]; .provider == "codex" and .capability == "codex-max" and .action.mutating == false)
  and all(.routes[]; .action.kind == "fix_runtime" or .action.kind == "probe_needed" or .action.kind == "revalidation_needed" or .action.kind == "none" or .action.kind == "wait_and_retry" or .action.kind == "wait_for_quota" or .action.kind == "wait_for_cooldown")
  and all(.routes[]; if .action.kind == "fix_runtime" then
    .action.command == null
    and (.action.diagnostic_command | startswith("oauth-mux doctor runtime --provider codex --account "))
    and (.action.diagnostic_command | endswith(" --capability codex-max --json"))
  else true end)
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
  and all(.routes[]; if .action.kind == "fix_runtime" then
    .action.command == null
    and (.action.diagnostic_command | startswith("oauth-mux doctor runtime --provider codex --account "))
    and (.action.diagnostic_command | endswith(" --capability codex-max --json"))
  else true end)
' "$route_explain_json" >/dev/null

printf 'first-run e2e: codex preflight explains blocked route reasons without mutation\n'
codex_preflight_json="$tmp/codex-preflight-codex-max.json"
run_json "$codex_preflight_json" codex preflight --profile codex-max --capability codex-max --json
jq -e '
  .mode == "codex_preflight"
  and .spends_provider_calls == false
  and .mutates_user_config == false
  and .mutates_route_health == false
  and (.install.oauth_mux_candidates | type) == "array"
  and (.install.active_oauth_mux_is_path_first | type) == "boolean"
  and (.install.codex_candidates | type) == "array"
  and (.install.active_codex == null or (.install.active_codex | type) == "string")
  and (.install.active_codex_is_oauth_mux_shim | type) == "boolean"
  and (.install.native_codex_candidate == null or (.install.native_codex_candidate | type) == "string")
  and (.install.native_codex_found | type) == "boolean"
  and (.install.codex_shim_candidates | type) == "number"
  and .install.native_codex_env == "OMUX_CODEX_BIN"
  and (.environment.codex_home_set | type) == "boolean"
  and (.environment.codex_home_managed_overlay | type) == "boolean"
  and (.environment.omux_managed_env_present | type) == "boolean"
  and (.environment.omux_active_account_present | type) == "boolean"
  and (.environment.omux_codex_session_home_present | type) == "boolean"
  and (.environment.omux_codex_config_home_present | type) == "boolean"
  and .environment.path_printed == false
  and .ok == false
  and .route_summary.routes_total == 3
  and .route_summary.selectable_routes == 0
  and (.blocked_route_reasons | length) == 1
  and (.blocked_route_reasons[] | select(.reason == "auth_broker_unready" and .count == 3))
  and .repair_summary.route_repair_required == true
  and .repair_summary.agent_safe_inspection_available == true
  and .repair_summary.blocked_routes == 3
  and .repair_summary.dominant_blocker == "auth_broker_unready"
  and .repair_summary.dominant_blocker_count == 3
  and .repair_summary.auth_broker_unready_routes == 3
  and .repair_summary.revalidation_needed_routes == 0
  and .repair_summary.user_handoff_required == false
  and (.blocked_routes | length) == 3
  and all(.blocked_routes[]; .provider == "codex" and .capability == "codex-max" and .selectable == false and .broker_ready == false and .blocked_reason == "auth_broker_unready" and .action.mutating == false)
  and (.next_actions | length) == 1
  and (.next_actions | index("oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json") != null)
  and (.agent_safe_next_actions | length) == 1
  and .agent_safe_next_actions[0].command == "oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json"
  and .agent_safe_next_actions[0].agent_safe == true
  and .agent_safe_next_actions[0].may_spend_provider_calls == false
  and .agent_safe_next_actions[0].mutates_route_health == false
  and (.spend_confirmed_next_actions | length) == 0
  and (.user_mediated_next_actions | length) == 0
' "$codex_preflight_json" >/dev/null
expect_not_contains "$(cat "$codex_preflight_json")" "$store_root/max-1" "codex preflight does not print concrete Codex store paths"
test ! -e "$store_root"
test ! -e "$legacy_store_root"
codex_preflight_text="$(omux codex preflight --profile codex-max --capability codex-max)"
expect_contains "$codex_preflight_text" "  install:" "codex preflight text reports install diagnostics"
expect_contains "$codex_preflight_text" "    active oauth-mux:" "codex preflight text reports active oauth-mux"
expect_contains "$codex_preflight_text" "    oauth-mux path first:" "codex preflight text reports oauth-mux path ordering"
expect_contains "$codex_preflight_text" "    active codex:" "codex preflight text reports active codex"
expect_contains "$codex_preflight_text" "    active codex is oauth-mux shim:" "codex preflight text reports codex shim classification"
expect_contains "$codex_preflight_text" "    native codex:" "codex preflight text reports native codex"
expect_contains "$codex_preflight_text" "    native codex env: OMUX_CODEX_BIN" "codex preflight text reports native codex env override"
expect_contains "$codex_preflight_text" "  environment:" "codex preflight text reports shell environment diagnostics"
expect_contains "$codex_preflight_text" "    CODEX_HOME is oauth-mux overlay:" "codex preflight text reports managed overlay detection"
expect_contains "$codex_preflight_text" "  config valid: yes" "codex preflight text still reports route readiness"
expect_contains "$codex_preflight_text" "Local diagnostics:" "codex preflight text labels local diagnostics"
expect_contains "$codex_preflight_text" "oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json" "codex preflight text reports local broker plan"
expect_not_contains "$codex_preflight_text" "Spend-confirmed repair:" "codex preflight text omits unavailable spend repair"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: stay-afloat exposes runtime diagnostics without automatic repair\n'
stay_afloat_json="$tmp/stay-afloat-codex-max.json"
run_json "$stay_afloat_json" stay-afloat --once --profile codex-max --capability codex-max --json
jq -e '
  .mode == "once"
  and .execution_mode == "plan"
  and .executed == false
  and .afloat == false
  and .selected == null
  and (.routes | length) == 3
  and all(.routes[]; .route.provider == "codex" and .route.capability == "codex-max")
  and all(.routes[]; if .route.action.kind == "fix_runtime" then
    .route.action.command == null
    and (.route.action.diagnostic_command | startswith("oauth-mux doctor runtime --provider codex --account "))
    and (.route.action.diagnostic_command | endswith(" --capability codex-max --json"))
  else true end)
' "$stay_afloat_json" >/dev/null
test ! -e "$store_root"
test ! -e "$legacy_store_root"

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

printf 'first-run e2e: repair run refuses to mutate without admitted repair\n'
repair_run_json="$tmp/repair-run-codex-max.json"
run_json "$repair_run_json" repair run --profile codex-max --capability codex-max --json
jq -e '
  .ok == true
  and .executed == false
  and .confirmation_required == false
  and .reason == "no_admitted_repair"
' "$repair_run_json" >/dev/null
test ! -e "$store_root"
test ! -e "$legacy_store_root"

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
  and (.profiles["codex-max"].providers | length) == 6
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
help_out="$(planning_omux codex canary --help)"
expect_contains "$help_out" "non-mutating" "Codex help declares non-mutating behavior"
separator_help_out="$(planning_omux codex setup -- --account --help)"
expect_contains "$separator_help_out" "non-mutating" "Codex help after a legacy separator remains non-mutating"
test ! -e "$sentinel_log"
test ! -e "$store_root"
test ! -e "$legacy_store_root"

printf 'first-run e2e: confirmed enroll codex adds N+1 account without login\n'
enroll_confirmed_json="$tmp/enroll-codex-confirmed.json"
run_json "$enroll_confirmed_json" enroll codex --account max-4 --confirm-enroll --json
jq -e '
  .ok == true
  and .executed == true
  and .provider == "codex"
  and .account == "max-4"
  and .config_changed == true
  and .store_bootstrapped == true
  and .ran_provider_login == false
  and .spends_provider_calls == false
  and .backup_config != null
  and (.next_commands | index("oauth-mux codex login-device max-4") != null)
  and (.next_commands | index("oauth-mux doctor runtime --provider codex --account max-4 --capability codex-max --json") != null)
' "$enroll_confirmed_json" >/dev/null
test -d "$store_root/max-4"
jq -e '
  (.providers.codex.accounts["max-4"].secret.backend == "file")
  and (.providers.codex.accounts["max-4"].config_dir | contains("max-4"))
  and (.profiles["codex-max"].providers | index("codex:max-4#codex-max") != null)
  and (.profiles["codex-mini"].providers | index("codex:max-4#codex-mini") != null)
' "$config_path" >/dev/null
accounts_after_enroll_json="$tmp/accounts-after-enroll.json"
run_json "$accounts_after_enroll_json" accounts list --provider codex --json
jq -e '
  (.accounts | length) == 4
  and any(.accounts[]; .account == "max-4" and .state == "action_needed")
' "$accounts_after_enroll_json" >/dev/null

printf 'first-run e2e: enroll claude requires explicit confirmation\n'
enroll_claude_preview_json="$tmp/enroll-claude-preview.json"
run_json "$enroll_claude_preview_json" enroll claude --account work --json
jq -e --arg root "$claude_config_root" '
  .ok == false
  and .confirmation_required == true
  and .requires == "--confirm-enroll"
  and .provider == "claude"
  and .account == "work"
  and .config_root == $root
  and .spends_provider_calls == false
  and (.confirm_command | contains("oauth-mux enroll claude --account work --confirm-enroll"))
  and .plan.provider_neutral_mutation_supported == true
' "$enroll_claude_preview_json" >/dev/null
test ! -d "$claude_config_root/work"

printf 'first-run e2e: confirmed enroll claude adds isolated config dir without login\n'
enroll_claude_confirmed_json="$tmp/enroll-claude-confirmed.json"
run_json "$enroll_claude_confirmed_json" enroll claude --account work --confirm-enroll --json
jq -e '
  .ok == true
  and .executed == true
  and .provider == "claude"
  and .account == "work"
  and .config_changed == true
  and .config_bootstrapped == true
  and .ran_provider_login == false
  and .spends_provider_calls == false
  and .backup_config != null
  and any(.next_commands[]; startswith("omux setup login --provider claude") and contains("--confirm-login"))
  and (.next_commands | index("oauth-mux doctor runtime --provider claude --account work --capability auth-status --json") != null)
' "$enroll_claude_confirmed_json" >/dev/null
test -d "$claude_config_root/work"
jq -e --arg backend "$expected_claude_secret_backend" '
  (.providers.claude.kind == "claude")
  and (.providers.claude.config_dir_env == "CLAUDE_CONFIG_DIR")
  and (.providers.claude.accounts.work.secret.backend == $backend)
  and (
    if $backend == "keychain"
    then (.providers.claude.accounts.work.secret.path == null)
    else (.providers.claude.accounts.work.secret.path | contains(".credentials.json"))
    end
  )
  and (.providers.claude.accounts.work.config_dir | contains("work"))
  and (.profiles.claude.providers | index("claude:work#auth-status") != null)
' "$config_path" >/dev/null
accounts_after_claude_json="$tmp/accounts-after-claude.json"
run_json "$accounts_after_claude_json" accounts list --provider claude --json
jq -e --arg backend "$expected_claude_secret_backend" '
  (.accounts | length) == 1
  and any(.accounts[]; .account == "work" and .secret_backend == $backend)
' "$accounts_after_claude_json" >/dev/null

printf 'first-run e2e: confirmed Claude setup login uses an owned synthetic helper and retained profile workspace\n'
login_bin="$tmp/tin2071-login-bin"
login_trace="$home/tin2071-login-trace"
browser_trace="$home/tin2071-browser-trace"
profile_trace="$home/tin2071-profile-trace"
mkdir -p "$login_bin"
cat >"$login_bin/claude" <<'CLAUDE_SENTINEL'
#!/usr/bin/env bash
set -euo pipefail
effective_user="$(id -un)"
test "${USER:?}" = "$effective_user"
test "${LOGNAME:?}" = "$effective_user"
printf 'argv=%q %q %q\n' "$1" "$2" "${3-}" >"${HOME:?}/tin2071-login-trace"
printf '%s\n' "${CLAUDE_CONFIG_DIR:?}" >"${HOME:?}/tin2071-profile-trace.config"
printf '%s\n' "${OMUX_CLAUDE_BROWSER_PROFILE:?}" >"${HOME:?}/tin2071-profile-trace"
open 'https://example.invalid/claude-oauth'
i=0
while [ "$i" -lt 100000 ]; do
  [ -s "${HOME:?}/tin2071-browser-trace" ] && exit 0
  i=$((i + 1))
done
printf 'synthetic browser shim did not execute\n' >&2
exit 98
CLAUDE_SENTINEL
cat >"$login_bin/google-chrome" <<'BROWSER_SENTINEL'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1-}" = "--version" ]; then
  printf 'Google Chrome synthetic-test-only\n'
  exit 0
fi
test -d "${OMUX_CLAUDE_BROWSER_PROFILE:?}"
printf '%s\n' "$@" >"${HOME:?}/tin2071-browser-trace"
BROWSER_SENTINEL
chmod 0755 "$login_bin/claude" "$login_bin/google-chrome"

login_out="$(
  export PATH="$login_bin:/usr/bin:/bin"
  export USER="spoofed-login-user"
  export LOGNAME="spoofed-login-logname"
  omux setup login --provider claude --label work --confirm-login
)"
expect_contains "$login_out" "experimental trusted-provider launcher" "login remains explicitly experimental"
expect_contains "$login_out" "workspace disposition: preserved_manual_cleanup" "post-spawn cleanup stays manual"
expect_contains "$login_out" "owned browser helper: observed returning" "owned helper observation is reported narrowly"
expect_contains "$login_out" "browser isolation, and cleanup are not independently verified" "successful provider exit does not overclaim"
expect_contains "$(cat "$login_trace")" "argv=auth login" "provider argv is fixed data"
test "$(cat "$profile_trace.config")" = "$claude_config_root/work"
isolated_profile="$(cat "$profile_trace")"
test -d "$isolated_profile"
expect_contains "$login_out" "${isolated_profile%/profile}" "preserved workspace path is explicit"
grep -Fx -- '--incognito' "$browser_trace" >/dev/null
grep -Fx -- '--new-window' "$browser_trace" >/dev/null
grep -Fx -- '--disable-background-mode' "$browser_trace" >/dev/null
grep -Fx -- 'https://example.invalid/claude-oauth' "$browser_trace" >/dev/null

printf 'first-run e2e: provider nonzero status survives missing owned-helper marker\n'
cat >"$login_bin/claude" <<'CLAUDE_NONZERO_SENTINEL'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = auth
test "$2" = login
exit 37
CLAUDE_NONZERO_SENTINEL
chmod 0755 "$login_bin/claude"
set +e
login_nonzero_out="$(
  export PATH="$login_bin:/usr/bin:/bin"
  omux setup login --provider claude --label work --confirm-login
  exit $?
)"
login_nonzero_status=$?
set -e
test "$login_nonzero_status" -eq 37
expect_contains "$login_nonzero_out" "owned browser helper: NOT observed" "missing helper observation is explicit"
expect_contains "$login_nonzero_out" "provider login exited with status 37" "provider nonzero status is preserved"
expect_contains "$login_nonzero_out" "workspace disposition: preserved_manual_cleanup" "failed run workspace remains quarantined"

printf 'first-run e2e: enroll figma requires explicit confirmation and mode truth\n'
enroll_figma_preview_json="$tmp/enroll-figma-preview.json"
run_json "$enroll_figma_preview_json" enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --json
jq -e '
  .ok == false
  and .confirmation_required == true
  and .requires == "--confirm-enroll"
  and .provider == "figma"
  and .account == "design"
  and .mode == "pat"
  and .config_provider == "figma-pat"
  and .capability == "identity-pat"
  and .secret_backend == "env"
  and .secret_env == "OMUX_FIGMA_DESIGN_PAT"
  and .spends_provider_calls == false
  and (.confirm_command | contains("oauth-mux enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --confirm-enroll"))
  and (.proof_command == "oauth-mux probe --provider figma-pat --account design --capability identity-pat --json")
  and .plan.provider_neutral_mutation_supported == true
' "$enroll_figma_preview_json" >/dev/null
jq -e '
  (.providers["figma-pat"] == null)
  and (.profiles["figma-pat"] == null)
' "$config_path" >/dev/null

printf 'first-run e2e: confirmed enroll figma adds env-backed route without token creation\n'
enroll_figma_confirmed_json="$tmp/enroll-figma-confirmed.json"
run_json "$enroll_figma_confirmed_json" enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --confirm-enroll --json
jq -e '
  .ok == true
  and .executed == true
  and .provider == "figma"
  and .account == "design"
  and .mode == "pat"
  and .config_provider == "figma-pat"
  and .capability == "identity-pat"
  and .secret_backend == "env"
  and .secret_env == "OMUX_FIGMA_DESIGN_PAT"
  and .config_changed == true
  and .created_secret == false
  and .ran_provider_login == false
  and .spends_provider_calls == false
  and .backup_config != null
  and (.next_commands | index("export OMUX_FIGMA_DESIGN_PAT=<figma-token>") != null)
  and (.next_commands | index("oauth-mux probe --provider figma-pat --account design --capability identity-pat --json") != null)
' "$enroll_figma_confirmed_json" >/dev/null
jq -e '
  (.providers["figma-pat"].kind == "figma")
  and (.providers["figma-pat"].accounts.design.secret.backend == "env")
  and (.providers["figma-pat"].accounts.design.secret.variable == "OMUX_FIGMA_DESIGN_PAT")
  and (.profiles["figma-pat"].providers | index("figma-pat:design#identity-pat") != null)
' "$config_path" >/dev/null
accounts_after_figma_json="$tmp/accounts-after-figma.json"
run_json "$accounts_after_figma_json" accounts list --provider figma --json
jq -e '
  any(.accounts[]; .provider == "figma-pat" and .account == "design" and .secret_backend == "env")
' "$accounts_after_figma_json" >/dev/null

printf 'first-run e2e passed\n'
