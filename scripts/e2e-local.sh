#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bin="${OMUX_BIN:-$repo_root/zig-out/bin/oauth-mux}"

if [ ! -x "$bin" ]; then
  printf 'missing oauth-mux binary: %s\n' "$bin" >&2
  printf 'run `zig build` or `just e2e` first\n' >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-e2e.XXXXXX")"
daemon_pid=""
short_runtime_dirs=""
cleanup() {
  if [ -n "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
  if [ -n "$short_runtime_dirs" ]; then
    rm -rf $short_runtime_dirs
  fi
}
trap cleanup EXIT

short_runtime_dir() {
  dir="$(mktemp -d "/tmp/oauth-mux-e2e-runtime.XXXXXX")"
  short_runtime_dirs="${short_runtime_dirs}${short_runtime_dirs:+ }$dir"
  printf '%s\n' "$dir"
}

config="$tmp/config.json"
state_dir="$tmp/state"
exec_out="$tmp/exec.out"
probe_cmd="$tmp/probe-harness.sh"
probe_mode_file="$tmp/probe-mode"
reauth_probe_cmd="$tmp/reauth-probe-harness.sh"

mkdir -p "$state_dir" "$tmp/a1-home" "$tmp/a2-home"

cat >"$probe_cmd" <<'EOF'
#!/usr/bin/env sh
set -eu

capability="${1:-}"

case "${capability}:${OMUX_ACTIVE_ACCOUNT:-}" in
  expensive:a1)
    if [ -n "${OMUX_E2E_PROBE_MODE_FILE:-}" ] &&
      [ -f "$OMUX_E2E_PROBE_MODE_FILE" ] &&
      grep -q '^expensive:a1:ok$' "$OMUX_E2E_PROBE_MODE_FILE"; then
      printf 'ok provider=%s account=%s capability=%s\n' \
        "${OMUX_ACTIVE_PROVIDER:-}" \
        "${OMUX_ACTIVE_ACCOUNT:-}" \
        "${OMUX_ACTIVE_CAPABILITY:-}"
      exit 0
    fi
    printf '%s\n' 'quota_exhausted: simulated monthly route limit'
    exit 1
    ;;
  cheap:a1|cheap:a2|expensive:a2)
    printf 'ok provider=%s account=%s capability=%s\n' \
      "${OMUX_ACTIVE_PROVIDER:-}" \
      "${OMUX_ACTIVE_ACCOUNT:-}" \
      "${OMUX_ACTIVE_CAPABILITY:-}"
    exit 0
    ;;
  *)
    printf 'unexpected probe route: capability=%s account=%s\n' \
      "${capability}" \
      "${OMUX_ACTIVE_ACCOUNT:-}" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$probe_cmd"

cat >"$reauth_probe_cmd" <<'EOF'
#!/usr/bin/env sh
set -eu

if [ "${OMUX_ACTIVE_PROVIDER:-}" = "codex" ] && [ "${OMUX_ACTIVE_ACCOUNT:-}" = "max-1" ]; then
  printf 'ok provider=%s account=%s capability=%s\n' \
    "${OMUX_ACTIVE_PROVIDER:-}" \
    "${OMUX_ACTIVE_ACCOUNT:-}" \
    "${OMUX_ACTIVE_CAPABILITY:-}"
  exit 0
fi

printf 'unexpected reauth probe route: provider=%s account=%s capability=%s\n' \
  "${OMUX_ACTIVE_PROVIDER:-}" \
  "${OMUX_ACTIVE_ACCOUNT:-}" \
  "${OMUX_ACTIVE_CAPABILITY:-}" >&2
exit 1
EOF
chmod 0755 "$reauth_probe_cmd"

cat >"$config" <<EOF
{
  "version": 1,
  "defaults": {
    "provider": "toy",
    "strategy": "health-weighted",
    "shell": "bash"
  },
  "provider_definitions": {
    "toy": {
      "name": "toy",
      "display_name": "Toy E2E Harness",
      "credential": {
        "access_token_path": "access_token"
      },
      "injection": {
        "config_dir_env": "TOY_HOME",
        "credential_filename": "auth.json",
        "direct_env": [
          ["TOY_TOKEN", "access_token"]
        ]
      },
      "capabilities": [
        {
          "name": "cheap",
          "probe": {
            "transport": "command",
            "auth": "none",
            "timeout_ms": 5000,
            "command": ["$probe_cmd", "cheap"]
          }
        },
        {
          "name": "expensive",
          "probe": {
            "transport": "command",
            "auth": "none",
            "timeout_ms": 5000,
            "command": ["$probe_cmd", "expensive"]
          }
        }
      ],
      "failure_rules": [
        {
          "status": 400,
          "hint_contains": "quota_exhausted",
          "class": {
            "quota_exhausted": {}
          }
        },
        {
          "status": 400,
          "class": {
            "degraded": "unknown_4xx"
          }
        }
      ]
    }
  },
  "providers": {
    "toy": {
      "kind": "toy",
      "config_dir_env": "TOY_HOME",
      "accounts": {
        "a1": {
          "priority": 20,
          "config_dir": "$tmp/a1-home",
          "secret": {
            "backend": "env",
            "variable": "OMUX_E2E_A1_AUTH"
          }
        },
        "a2": {
          "priority": 10,
          "config_dir": "$tmp/a2-home",
          "secret": {
            "backend": "env",
            "variable": "OMUX_E2E_A2_AUTH"
          }
        }
      }
    }
  },
  "profiles": {
    "cheap": {
      "providers": [
        "toy:a1#cheap",
        "toy:a2#cheap"
      ],
      "strategy": "health-weighted"
    },
    "expensive": {
      "providers": [
        "toy:a1#expensive",
        "toy:a2#expensive"
      ],
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
EOF

auth_a1='{"access_token":"omux-e2e-a1"}'
auth_a2='{"access_token":"omux-e2e-a2"}'

omux() {
  OMUX_CONFIG="$config" \
    OMUX_STATE_DIR="$state_dir" \
    OMUX_E2E_A1_AUTH="$auth_a1" \
    OMUX_E2E_A2_AUTH="$auth_a2" \
    OMUX_E2E_PROBE_MODE_FILE="$probe_mode_file" \
    "$bin" "$@"
}

expect_contains() {
  haystack="$1"
  needle="$2"
  label="$3"

  case "$haystack" in
    *"$needle"*) ;;
    *)
      printf 'e2e assertion failed: %s\n' "$label" >&2
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
      printf 'e2e assertion failed: %s\n' "$label" >&2
      printf 'did not expect to find: %s\n' "$needle" >&2
      printf 'output was:\n%s\n' "$haystack" >&2
      exit 1
      ;;
  esac
}

printf 'e2e: validate generated config\n'
omux config validate >/dev/null

printf 'e2e: doctor reports configured readiness\n'
doctor_json="$(omux doctor --json)"
expect_contains "$doctor_json" '"ok":true' "doctor reports ready config"
expect_contains "$doctor_json" '"providers":1' "doctor counts configured provider"
expect_contains "$doctor_json" '"accounts":2' "doctor counts configured accounts"
expect_contains "$doctor_json" '"oauth-mux discover --json"' "doctor recommends agent discovery"
expect_contains "$doctor_json" '"oauth-mux doctor runtime --json"' "doctor recommends runtime diagnostics"
expect_contains "$doctor_json" '"oauth-mux report --redacted --json"' "doctor recommends redacted report"

printf 'e2e: runtime doctor reports local account stores ready\n'
runtime_json="$(omux doctor runtime --json)"
expect_contains "$runtime_json" '"ok":true' "runtime doctor reports ready"
expect_contains "$runtime_json" '"ready_accounts":2' "runtime doctor counts ready accounts"
expect_contains "$runtime_json" '"config_dir_writable":true' "runtime doctor verifies writable config dirs"

printf 'e2e: scoped runtime doctor reports route readiness\n'
runtime_scoped_json="$(omux doctor runtime --profile expensive --capability expensive --json)"
expect_contains "$runtime_scoped_json" '"ok":true' "scoped runtime doctor reports ready profile"
expect_contains "$runtime_scoped_json" '"scope":{"profile":"expensive"' "scoped runtime doctor reports profile scope"
expect_contains "$runtime_scoped_json" '"route_reports":[' "scoped runtime doctor reports routes"
expect_contains "$runtime_scoped_json" '"ready_accounts":2' "scoped runtime doctor counts profile routes"

printf 'e2e: redacted report does not expose secret values\n'
report_json="$(omux report --redacted --json)"
expect_contains "$report_json" '"redacted":true' "report is redacted"
expect_contains "$report_json" '"secret_backend":"env"' "report includes secret backend class"
expect_contains "$report_json" '"secret_location":"redacted"' "report redacts secret location by default"
expect_contains "$report_json" '"health":[]' "report includes empty health array before probes"

printf 'e2e: providers list reports schema-modeled custom provider\n'
providers_json="$(omux providers list --json)"
expect_contains "$providers_json" '"name":"toy"' "providers list includes custom toy provider"
expect_contains "$providers_json" '"support_status":"schema_modeled"' "providers list classifies custom provider"
expect_contains "$providers_json" '"proof_status":"needs_operator_proof"' "providers list marks custom provider proof state"
expect_contains "$providers_json" '"name":"cheap","proof_status":"needs_operator_proof"' "providers list marks custom capability proof state"
expect_contains "$providers_json" '"name":"codex-max","proof_status":"live_proven"' "providers list marks Codex capability proof state"
expect_contains "$providers_json" '"configured_accounts":2' "providers list counts custom provider accounts"

printf 'e2e: accounts list reports redacted account inventory before probes\n'
accounts_json="$(omux accounts list --provider toy --json)"
expect_contains "$accounts_json" '"configured":true' "accounts list reports configured state"
expect_contains "$accounts_json" '"filter_provider":"toy"' "accounts list reports provider filter"
expect_contains "$accounts_json" '"provider":"toy"' "accounts list includes toy provider"
expect_contains "$accounts_json" '"account":"a1"' "accounts list includes account a1"
expect_contains "$accounts_json" '"account":"a2"' "accounts list includes account a2"
expect_contains "$accounts_json" '"state":"configured"' "accounts list distinguishes configured without liveness evidence"
expect_contains "$accounts_json" '"runtime":{"state":"ready"}' "accounts list includes runtime readiness"
expect_contains "$accounts_json" '"name":"cheap","proof_status":"needs_operator_proof"' "accounts list reports capability proof status"
expect_contains "$accounts_json" '"health_recorded":false' "accounts list reports missing liveness evidence"
expect_contains "$accounts_json" '"selectable":false' "accounts list refuses selection without recorded health"
expect_contains "$accounts_json" '"oauth-mux repair-plan --provider <provider> --account <account> --capability <capability> --json"' "accounts list advertises safe repair plan"
expect_not_contains "$accounts_json" "omux-e2e-a1" "accounts list does not expose env secret value"
expect_not_contains "$accounts_json" "omux-e2e-a2" "accounts list does not expose env secret value"

printf 'e2e: enroll plan reports non-mutating provider-neutral setup plan\n'
enroll_plan_json="$(omux enroll plan toy --account a3 --json)"
expect_contains "$enroll_plan_json" '"action":"plan"' "enroll plan reports plan action"
expect_contains "$enroll_plan_json" '"mutates":false' "enroll plan is non-mutating"
expect_contains "$enroll_plan_json" '"provider":"toy"' "enroll plan reports provider"
expect_contains "$enroll_plan_json" '"account":"a3"' "enroll plan reports target account"
expect_contains "$enroll_plan_json" '"provider_configured":true' "enroll plan sees configured provider"
expect_contains "$enroll_plan_json" '"account":"a1"' "enroll plan includes existing account a1"
expect_contains "$enroll_plan_json" '"kind":"runtime_proof"' "enroll plan includes runtime proof step"
expect_contains "$enroll_plan_json" '"command":"oauth-mux doctor runtime --provider toy --account a3 --json"' "enroll plan builds account-scoped runtime command"
expect_contains "$enroll_plan_json" '"provider_neutral_mutation_supported":false' "enroll plan refuses to claim mutation support"
expect_not_contains "$enroll_plan_json" "omux-e2e-a1" "enroll plan does not expose env secret value"
expect_not_contains "$enroll_plan_json" "omux-e2e-a2" "enroll plan does not expose env secret value"

printf 'e2e: cheap route selects first healthy account\n'
cheap_env="$(omux env --profile cheap --capability cheap --shell bash)"
expect_contains "$cheap_env" "export TOY_TOKEN='omux-e2e-a1'" "cheap env injects account a1 token"
expect_contains "$cheap_env" "export TOY_HOME='$tmp/a1-home'" "cheap env injects account a1 config dir"
expect_contains "$cheap_env" "export OMUX_ACTIVE_ACCOUNT='a1'" "cheap env marks active account a1"

printf 'e2e: expensive route falls back after route-scoped quota exhaustion\n'
expensive_probe="$(omux probe --profile expensive --capability expensive --json)"
expect_contains "$expensive_probe" '"account":"a2"' "expensive probe falls back to account a2"
expect_contains "$expensive_probe" '"probe_executed":true' "expensive probe executes capability probe"
expect_contains "$expensive_probe" '"health_key":"toy:a2#expensive"' "expensive probe records selected route health"

health_json="$(omux health --json)"
expect_contains "$health_json" '"key":"toy:a1#expensive"' "health includes failed route key"
expect_contains "$health_json" '"availability":"quota_exhausted"' "health records quota exhausted route availability"
expect_contains "$health_json" '"decision":"try_next_account"' "health records fallback decision"

printf 'e2e: route explain reports selected fallback without probing\n'
route_explain="$(omux route explain --profile expensive --capability expensive --json)"
expect_contains "$route_explain" '"action":"explain"' "route explain reports action"
expect_contains "$route_explain" '"ok":true' "route explain reports available selection"
expect_contains "$route_explain" '"selected":{"provider":"toy","account":"a2"' "route explain selects fallback account a2"
expect_contains "$route_explain" '"skip_reason":"quota_exhausted"' "route explain keeps exhausted reason"
expect_contains "$route_explain" '"skip_reason":"available"' "route explain marks available selected route"
expect_contains "$route_explain" '"writeback":{"capability":"readonly","automatic_refresh_admitted":false,"reason":"provider_repair_is_manual_only"}' "route explain reports readonly writeback boundary"

printf 'e2e: route select chooses selected fallback without probing\n'
route_select="$(omux route select --profile expensive --capability expensive --json)"
expect_contains "$route_select" '"action":"select"' "route select reports action"
expect_contains "$route_select" '"ok":true' "route select reports available selection"
expect_contains "$route_select" '"selected":{"provider":"toy","account":"a2"' "route select selects fallback account a2"

printf 'e2e: stay-afloat next returns exact executable mediation for selected fallback\n'
stay_next="$(omux stay-afloat next --profile expensive --capability expensive --json)"
expect_contains "$stay_next" '"action":"next"' "stay-afloat next reports action"
expect_contains "$stay_next" '"ready_for_exec":true' "stay-afloat next reports executable route"
expect_contains "$stay_next" '"selected":{"provider":"toy","account":"a2"' "stay-afloat next selects fallback account a2"
expect_contains "$stay_next" '"claim":{"claim_version":1,"level":"prepared_fallback"' "stay-afloat next reports prepared fallback claim"
expect_contains "$stay_next" '"current_process_hotswap":false' "stay-afloat next refuses current-process hot swap claim"
expect_contains "$stay_next" '"launch_argv":["oauth-mux","stay-afloat","launch","--profile","expensive","--capability","expensive","--","<command>"]' "stay-afloat next returns launch argv claim"
expect_contains "$stay_next" '"next_action":{"kind":"exec"' "stay-afloat next returns exec mediation"
expect_contains "$stay_next" '"exec_argv":["oauth-mux","exec","--provider","toy","--account","a2","--capability","expensive","--","<command>"]' "stay-afloat next returns exact exec argv"

printf 'e2e: stay-afloat launch executes target with selected fallback account\n'
launch_out="$tmp/stay-launch.out"
OMUX_E2E_EXEC_OUT="$launch_out" omux stay-afloat launch --profile expensive --capability expensive -- sh -c 'printf "%s:%s" "$OMUX_ACTIVE_ACCOUNT" "$TOY_TOKEN" > "$OMUX_E2E_EXEC_OUT"'
launch_result="$(cat "$launch_out")"
expect_contains "$launch_result" 'a2:omux-e2e-a2' "stay-afloat launch target receives selected fallback account"

printf 'e2e: stay-afloat launch retries next route when exec reclassifies selected account\n'
printf '%s\n' 'expensive:a1:ok' >"$probe_mode_file"
omux health --reset toy:a1#expensive >/dev/null
omux health --reset toy:a2#expensive >/dev/null
stale_a1_probe="$(omux probe --provider toy --account a1 --capability expensive --json)"
expect_contains "$stale_a1_probe" '"account":"a1"' "stale launch setup records a1 as available"
stale_a2_probe="$(omux probe --provider toy --account a2 --capability expensive --json)"
expect_contains "$stale_a2_probe" '"account":"a2"' "stale launch setup records a2 as available"
rm -f "$probe_mode_file"
stale_next="$(omux stay-afloat next --profile expensive --capability expensive --json)"
expect_contains "$stale_next" '"selected":{"provider":"toy","account":"a1"' "stale launch preflight selects a1 from recorded evidence"
stale_launch_out="$tmp/stay-launch-stale.out"
OMUX_E2E_EXEC_OUT="$stale_launch_out" omux stay-afloat launch --profile expensive --capability expensive -- sh -c 'printf "%s:%s" "$OMUX_ACTIVE_ACCOUNT" "$TOY_TOKEN" > "$OMUX_E2E_EXEC_OUT"'
stale_launch_result="$(cat "$stale_launch_out")"
expect_contains "$stale_launch_result" 'a2:omux-e2e-a2' "stay-afloat launch falls through to a2 after a1 reclassification"

printf 'e2e: daemon tick plans stay-afloat without executing work\n'
daemon_tick="$(omux daemon tick --once --profile expensive --capability expensive --json)"
expect_contains "$daemon_tick" '"mode":"once"' "daemon tick reports one-shot mode"
expect_contains "$daemon_tick" '"executed":false' "daemon tick does not execute probes or repair"
expect_contains "$daemon_tick" '"afloat":true' "daemon tick reports profile afloat"
expect_contains "$daemon_tick" '"selected":{"provider":"toy","account":"a2"' "daemon tick selects fallback account a2"
expect_contains "$daemon_tick" '"claim":{"claim_version":1,"level":"prepared_fallback"' "daemon tick reports prepared fallback claim"
expect_contains "$daemon_tick" '"max_supported_level":"prepared_fallback"' "daemon tick reports maximum supported claim level"
expect_contains "$daemon_tick" '"current_process_hotswap":false' "daemon tick refuses current-process hot-swap claim"
expect_contains "$daemon_tick" '"per_request_muxing":false' "daemon tick refuses per-request muxing claim"
expect_contains "$daemon_tick" '"launch_argv":["oauth-mux","stay-afloat","launch","--profile","expensive","--capability","expensive","--","<command>"]' "daemon tick reports wrapper launch argv"
expect_contains "$daemon_tick" '"action":"wait_for_quota"' "daemon tick includes wait action for exhausted route"
expect_contains "$daemon_tick" '"schedule_reason":"wait_until"' "daemon tick exposes quota reset schedule reason"
expect_contains "$daemon_tick" '"next_tick_reason":"wait_until"' "daemon tick summary exposes earliest schedule reason"
expect_contains "$daemon_tick" '"reason":"route_selectable"' "daemon tick marks selectable route as no-op"
expect_contains "$daemon_tick" '"schedule_reason":"route_selectable"' "daemon tick marks selectable route as unscheduled"

printf 'e2e: stay-afloat aliases daemon tick planning\n'
stay_afloat="$(omux stay-afloat --once --profile expensive --capability expensive --json)"
expect_contains "$stay_afloat" '"mode":"once"' "stay-afloat reports one-shot mode"
expect_contains "$stay_afloat" '"executed":false' "stay-afloat remains planning-only by default"
expect_contains "$stay_afloat" '"afloat":true' "stay-afloat reports profile afloat"
expect_contains "$stay_afloat" '"selected":{"provider":"toy","account":"a2"' "stay-afloat selects fallback account a2"
expect_contains "$stay_afloat" '"next_tick_reason":"wait_until"' "stay-afloat exposes scheduler summary"

printf 'e2e: daemon status exposes latest stay-afloat snapshot without promoting socket daemon\n'
daemon_status_snapshot="$(omux daemon status --json)"
expect_contains "$daemon_status_snapshot" '"status":"not_running"' "daemon status remains stopped after foreground tick"
expect_contains "$daemon_status_snapshot" '"hosts_stay_afloat":false' "daemon status still does not claim to host stay-afloat"
expect_contains "$daemon_status_snapshot" '"stay_afloat":{"version":' "daemon status includes latest stay-afloat snapshot"
expect_contains "$daemon_status_snapshot" '"stay_afloat_snapshot":{"present":true,"parseable":true' "daemon status reports parseable stay-afloat snapshot metadata"
expect_contains "$daemon_status_snapshot" '"stale_after_seconds":300' "daemon status reports snapshot staleness threshold"
expect_contains "$daemon_status_snapshot" '"stale":false' "daemon status reports fresh stay-afloat snapshot"
expect_contains "$daemon_status_snapshot" '"reason":"fresh"' "daemon status reports fresh snapshot reason"
expect_contains "$daemon_status_snapshot" '"loop_started_at":null' "daemon status reports no active loop correlation while stopped"
expect_contains "$daemon_status_snapshot" '"current_loop_observed":null' "daemon status reports no active loop observation while stopped"
expect_contains "$daemon_status_snapshot" '"contract":"foreground_tick_snapshot"' "daemon snapshot reports foreground tick contract"
expect_contains "$daemon_status_snapshot" '"claim":{"claim_version":1,"level":"prepared_fallback"' "daemon status exposes latest stay-afloat claim"
expect_contains "$daemon_status_snapshot" '"current_process_hotswap":false' "daemon status refuses hot-swap claim"
expect_contains "$daemon_status_snapshot" '"selected":{"provider":"toy","account":"a2"' "daemon snapshot carries selected fallback route"

printf 'e2e: bounded daemon tick loop emits repeated planning snapshots\n'
daemon_loop="$(omux daemon tick --loop --iterations 2 --interval-ms 0 --profile expensive --capability expensive --json)"
expect_contains "$daemon_loop" '"mode":"loop"' "daemon tick loop reports loop mode"
expect_contains "$daemon_loop" '"iterations_requested":2' "daemon tick loop reports requested iterations"
expect_contains "$daemon_loop" '"ticks":[' "daemon tick loop returns tick array"
expect_contains "$daemon_loop" '"tick_index":0' "daemon tick loop includes first tick"
expect_contains "$daemon_loop" '"tick_index":1' "daemon tick loop includes second tick"
expect_contains "$daemon_loop" '"executed":false' "daemon tick loop remains planning-only"

printf 'e2e: daemon foreground status and stop stay inside temp runtime\n'
daemon_runtime="$(short_runtime_dir)"
daemon_state="$tmp/daemon-state"
daemon_log="$tmp/daemon.log"
mkdir -p "$daemon_state"
OMUX_CONFIG="$config" \
  OMUX_STATE_DIR="$daemon_state" \
  XDG_RUNTIME_DIR="$daemon_runtime" \
  "$bin" daemon run >"$daemon_log" 2>&1 &
daemon_pid=$!
daemon_status=""
for _ in $(seq 1 200); do
  daemon_status="$(OMUX_STATE_DIR="$daemon_state" XDG_RUNTIME_DIR="$daemon_runtime" "$bin" daemon status --json || true)"
  case "$daemon_status" in
    *'"status":"running"'*) break ;;
  esac
done
expect_contains "$daemon_status" '"status":"running"' "daemon status reports foreground daemon running"
expect_contains "$daemon_status" '"socket":' "daemon status reports socket path"
expect_contains "$daemon_status" '"contract":"experimental_socket_stub"' "daemon status reports socket contract"
expect_contains "$daemon_status" '"hosts_stay_afloat":false' "daemon status does not claim to host stay-afloat"
OMUX_STATE_DIR="$daemon_state" XDG_RUNTIME_DIR="$daemon_runtime" "$bin" daemon stop >/dev/null 2>&1
set +e
wait "$daemon_pid" 2>/dev/null
daemon_wait_status=$?
set -e
daemon_pid=""
case "$daemon_wait_status" in
  0|143) ;;
  *)
    printf 'e2e assertion failed: foreground daemon exited unexpectedly with status %s\n' "$daemon_wait_status" >&2
    printf 'daemon log:\n%s\n' "$(cat "$daemon_log")" >&2
    exit 1
    ;;
esac
daemon_stopped="$(OMUX_STATE_DIR="$daemon_state" XDG_RUNTIME_DIR="$daemon_runtime" "$bin" daemon status --json)"
expect_contains "$daemon_stopped" '"status":"not_running"' "daemon status reports stopped foreground daemon"
expect_contains "$daemon_stopped" '"wrapper_contract":"foreground_tick"' "daemon status reports wrapper contract when stopped"

printf 'e2e: supervised stay-afloat daemon loop reports beta host status\n'
supervised_runtime="$(short_runtime_dir)"
supervised_log="$tmp/supervised-daemon.log"
OMUX_CONFIG="$config" \
  OMUX_STATE_DIR="$state_dir" \
  XDG_RUNTIME_DIR="$supervised_runtime" \
  "$bin" daemon run --stay-afloat --profile expensive --capability expensive --iterations 200 --interval-ms 50 >"$supervised_log" 2>&1 &
daemon_pid=$!
supervised_status=""
for _ in $(seq 1 200); do
  supervised_status="$(OMUX_STATE_DIR="$state_dir" XDG_RUNTIME_DIR="$supervised_runtime" "$bin" daemon status --json || true)"
  case "$supervised_status" in
    *'"status":"running"'*'"stay_afloat_loop":{"hosted":true'*'"stay_afloat":{"version":'*'"current_loop_observed":true'*) break ;;
  esac
done
expect_contains "$supervised_status" '"status":"running"' "supervised daemon status reports running"
expect_contains "$supervised_status" '"contract":"experimental_supervised_loop"' "supervised daemon status reports beta contract"
expect_contains "$supervised_status" '"hosts_stay_afloat":false' "supervised daemon does not claim production stay-afloat"
expect_contains "$supervised_status" '"stay_afloat_loop":{"hosted":true' "supervised daemon reports hosted beta loop"
expect_contains "$supervised_status" '"stay_afloat_snapshot":{"present":true,"parseable":true' "supervised daemon reports parseable stay-afloat snapshot metadata"
expect_contains "$supervised_status" '"current_loop_observed":true' "supervised daemon status proves active loop has written a snapshot"
expect_contains "$supervised_status" '"stale":false' "supervised daemon reports fresh stay-afloat snapshot"
expect_contains "$supervised_status" '"reason":"fresh"' "supervised daemon reports fresh snapshot reason"
expect_contains "$supervised_status" '"selector":{"profile":"expensive","provider":null,"account":null,"capability":"expensive"}' "supervised daemon reports hosted selector"
expect_contains "$supervised_status" '"once":false' "supervised daemon reports loop mode metadata"
expect_contains "$supervised_status" '"iterations":200' "supervised daemon reports requested iteration bound"
expect_contains "$supervised_status" '"interval_ms":50' "supervised daemon reports cadence metadata"
expect_contains "$supervised_status" '"execution_mode":"execute"' "supervised daemon reports execute metadata"
expect_contains "$supervised_status" '"transport":"foreground_supervised_loop"' "supervised daemon status reports foreground loop transport"
expect_contains "$supervised_status" '"socket":null' "supervised daemon does not claim a socket transport"
expect_contains "$supervised_status" '"selected":{"provider":"toy","account":"a2"' "supervised daemon snapshot carries selected fallback route"
OMUX_STATE_DIR="$state_dir" XDG_RUNTIME_DIR="$supervised_runtime" "$bin" daemon stop >/dev/null 2>&1
set +e
wait "$daemon_pid" 2>/dev/null
supervised_wait_status=$?
set -e
daemon_pid=""
case "$supervised_wait_status" in
  0|143) ;;
  *)
    printf 'e2e assertion failed: supervised daemon exited unexpectedly with status %s\n' "$supervised_wait_status" >&2
    printf 'supervised daemon log:\n%s\n' "$(cat "$supervised_log")" >&2
    exit 1
    ;;
esac
supervised_stopped="$(OMUX_STATE_DIR="$state_dir" XDG_RUNTIME_DIR="$supervised_runtime" "$bin" daemon status --json)"
expect_contains "$supervised_stopped" '"status":"not_running"' "supervised daemon status reports stopped"
expect_contains "$supervised_stopped" '"stay_afloat_loop":{"hosted":false' "supervised daemon clears hosted loop metadata after stop"
expect_contains "$supervised_stopped" '"stay_afloat":{"version":' "supervised daemon leaves latest redacted snapshot visible after stop"
expect_contains "$supervised_stopped" '"stay_afloat_snapshot":{"present":true,"parseable":true' "supervised daemon leaves snapshot metadata visible after stop"

printf 'e2e: daemon tick execute runs one admitted command probe\n'
omux health --reset toy:a1 >/dev/null
omux health --reset toy:a2 >/dev/null
omux health --reset toy:a1#cheap >/dev/null
omux health --reset toy:a2#cheap >/dev/null
daemon_execute="$(omux daemon tick --once --execute --profile cheap --capability cheap --json)"
expect_contains "$daemon_execute" '"execution_mode":"execute"' "daemon tick reports execute mode"
expect_contains "$daemon_execute" '"executed":true' "daemon tick execute runs an admitted action"
expect_contains "$daemon_execute" '"phase":"probe"' "daemon tick execute records probe phase"
expect_contains "$daemon_execute" '"command":"oauth-mux probe --provider toy --account a1 --capability cheap --json"' "daemon tick execute reports redacted probe command"
expect_contains "$daemon_execute" '"selected":{"provider":"toy","account":"a1"' "daemon tick execute reselects after probe"

printf 'e2e: repair run no-ops when fallback route is selectable\n'
repair_run="$(omux repair run --profile expensive --capability expensive --json)"
expect_contains "$repair_run" '"ok":true' "repair run reports ok when afloat"
expect_contains "$repair_run" '"executed":false' "repair run does not execute while route is selectable"
expect_contains "$repair_run" '"reason":"route_selectable"' "repair run reports selectable route reason"

printf 'e2e: repair run requires confirmation before upstream reauth\n'
reauth_config="$tmp/reauth-config.json"
mkdir -p "$tmp/reauth-home"
cat >"$reauth_config" <<EOF
{
  "version": 1,
  "provider_definitions": {
    "codex": {
      "name": "codex",
      "display_name": "Codex Test Harness",
      "repair": {
        "owner": "upstream_cli_login"
      },
      "runtime": {
        "writable_paths": ["CODEX_HOME"],
        "session_paths": ["CODEX_HOME/auth.json"]
      },
      "capabilities": [
        {
          "name": "codex-max",
          "probe": {
            "transport": "command",
            "auth": "none",
            "timeout_ms": 5000,
            "budget": "free_command",
            "command": ["$reauth_probe_cmd"]
          }
        }
      ],
      "failure_rules": [
        {
          "status": 400,
          "class": {
            "degraded": "unknown_4xx"
          }
        }
      ]
    }
  },
  "providers": {
    "codex": {
      "kind": "codex",
      "config_dir_env": "CODEX_HOME",
      "accounts": {
        "max-1": {
          "config_dir": "$tmp/reauth-home",
          "secret": {
            "backend": "file",
            "path": "$tmp/reauth-home/auth.json"
          }
        }
      }
    }
  },
  "profiles": {
    "needs-reauth": {
      "providers": ["codex:max-1#codex-max"]
    }
  },
  "strategies": {}
}
EOF

printf 'e2e: codex broker-plan reports redacted app-server auth readiness\n'
broker_auth="$tmp/broker-auth.json"
broker_config="$tmp/broker-config.json"
broker_jwt='hdr.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC10ZXN0IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8ifX0.sig'
cat >"$broker_auth" <<EOF
{
  "auth_mode": "chatgpt",
  "tokens": {
    "id_token": "$broker_jwt",
    "access_token": "$broker_jwt",
    "refresh_token": "broker-refresh-token",
    "account_id": "acct-test"
  }
}
EOF
cat >"$broker_config" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": {
          "secret": {
            "backend": "file",
            "path": "$broker_auth"
          }
        }
      }
    }
  },
  "profiles": {
    "codex-max": {
      "providers": ["codex:max-1#codex-max"]
    }
  },
  "strategies": {}
}
EOF
broker_plan="$(OMUX_CONFIG="$broker_config" OMUX_STATE_DIR="$state_dir" "$bin" codex broker-plan --profile codex-max --capability codex-max --json)"
expect_contains "$broker_plan" '"mode":"codex_app_server_auth_broker_plan"' "broker-plan reports broker mode"
expect_contains "$broker_plan" '"requires_experimental_api":true' "broker-plan reports Codex app-server experimental API gate"
expect_contains "$broker_plan" '"login_method":"account/login/start.chatgptAuthTokens"' "broker-plan reports external-auth login method"
expect_contains "$broker_plan" '"refresh_method":"account/chatgptAuthTokens/refresh"' "broker-plan reports external-auth refresh method"
expect_contains "$broker_plan" '"level":"current_process_auth_broker"' "broker-plan reports proof target claim"
expect_contains "$broker_plan" '"proof_status":"planning_only"' "broker-plan refuses public proof claim"
expect_contains "$broker_plan" '"ok":true' "broker-plan reports ready route"
expect_contains "$broker_plan" '"ready_routes":1' "broker-plan counts ready routes"
expect_contains "$broker_plan" '"selected":{"provider":"codex","account":"max-1","capability":"codex-max"' "broker-plan selects ready route"
expect_contains "$broker_plan" '"can_supply":true' "broker-plan marks route as supply-capable"
expect_contains "$broker_plan" '"chatgpt_account_id":true' "broker-plan proves account id presence"
expect_contains "$broker_plan" '"chatgpt_account_id_source":"tokens.account_id"' "broker-plan reports redacted account id source"
expect_contains "$broker_plan" '"chatgpt_plan_type":true' "broker-plan proves plan type presence"
expect_not_contains "$broker_plan" 'acct-test' "broker-plan does not expose account id value"
expect_not_contains "$broker_plan" "$broker_jwt" "broker-plan does not expose token value"
expect_not_contains "$broker_plan" 'broker-refresh-token' "broker-plan does not expose refresh token value"

printf 'e2e: codex broker-smoke verifies app-server stdio login without leaking tokens\n'
mock_codex_app_server="$tmp/mock-codex-app-server"
cat >"$mock_codex_app_server" <<'EOF'
#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"id":1,"result":{}}'
      ;;
    *'"method":"account/login/start"'*)
      printf '%s\n' '{"id":2,"result":{"type":"chatgptAuthTokens"}}'
      printf '%s\n' '{"method":"account/login/completed","params":{"success":true}}'
      printf '%s\n' '{"method":"account/updated","params":{"authMode":"chatgptAuthTokens","planType":"pro"}}'
      ;;
  esac
done
EOF
chmod +x "$mock_codex_app_server"
broker_smoke="$(OMUX_CONFIG="$broker_config" OMUX_STATE_DIR="$state_dir" OMUX_CODEX_APP_SERVER="$mock_codex_app_server" "$bin" codex broker-smoke --profile codex-max --capability codex-max --confirm-broker --json)"
expect_contains "$broker_smoke" '"mode":"codex_app_server_stdio_broker_smoke"' "broker-smoke reports broker stdio mode"
expect_contains "$broker_smoke" '"ok":true' "broker-smoke reports success"
expect_contains "$broker_smoke" '"proof_status":"local_protocol_smoke"' "broker-smoke reports local protocol proof status"
expect_contains "$broker_smoke" '"initialized":true' "broker-smoke observes initialize response"
expect_contains "$broker_smoke" '"login_response":true' "broker-smoke observes external-auth login response"
expect_contains "$broker_smoke" '"login_completed":true' "broker-smoke observes login completed notification"
expect_contains "$broker_smoke" '"account_updated":true' "broker-smoke observes chatgptAuthTokens account update"
expect_contains "$broker_smoke" '"tokens_printed":false' "broker-smoke redaction reports token suppression"
expect_contains "$broker_smoke" '"raw_protocol_printed":false' "broker-smoke redaction reports raw protocol suppression"
expect_not_contains "$broker_smoke" 'acct-test' "broker-smoke does not expose account id value"
expect_not_contains "$broker_smoke" "$broker_jwt" "broker-smoke does not expose token value"
expect_not_contains "$broker_smoke" 'broker-refresh-token' "broker-smoke does not expose refresh token value"

printf 'e2e: codex broker-refresh-smoke answers app-server auth refresh without leaking tokens\n'
broker_auth_fallback="$tmp/broker-auth-fallback.json"
broker_switch_config="$tmp/broker-switch-config.json"
cat >"$broker_auth_fallback" <<EOF
{
  "auth_mode": "chatgpt",
  "tokens": {
    "id_token": "$broker_jwt",
    "access_token": "$broker_jwt",
    "refresh_token": "broker-refresh-token-fallback",
    "account_id": "acct-fallback"
  }
}
EOF
cat >"$broker_switch_config" <<EOF
{
  "version": 1,
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": {
          "priority": 20,
          "secret": {
            "backend": "file",
            "path": "$broker_auth"
          }
        },
        "max-2": {
          "priority": 10,
          "secret": {
            "backend": "file",
            "path": "$broker_auth_fallback"
          }
        }
      }
    }
  },
  "profiles": {
    "codex-max": {
      "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"]
    }
  },
  "strategies": {}
}
EOF
mock_codex_refresh_app_server="$tmp/mock-codex-refresh-app-server"
cat >"$mock_codex_refresh_app_server" <<'EOF'
#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"id":1,"result":{}}'
      ;;
    *'"method":"account/login/start"'*)
      printf '%s\n' '{"id":2,"result":{"type":"chatgptAuthTokens"}}'
      printf '%s\n' '{"method":"account/login/completed","params":{"success":true}}'
      printf '%s\n' '{"method":"account/updated","params":{"authMode":"chatgptAuthTokens","planType":"pro"}}'
      printf '%s\n' '{"id":99,"method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized"}}'
      ;;
    *'"id":99'*'"result"'*'acct-fallback'*)
      printf '%s\n' '{"method":"account/updated","params":{"authMode":"chatgptAuthTokens","planType":"pro"}}'
      ;;
    *'"id":99'*'"result"'*)
      exit 17
      ;;
  esac
done
EOF
chmod +x "$mock_codex_refresh_app_server"
broker_refresh_smoke="$(OMUX_CONFIG="$broker_switch_config" OMUX_STATE_DIR="$state_dir" OMUX_CODEX_APP_SERVER="$mock_codex_refresh_app_server" "$bin" codex broker-refresh-smoke --profile codex-max --capability codex-max --confirm-broker --json)"
expect_contains "$broker_refresh_smoke" '"mode":"codex_app_server_stdio_broker_refresh_smoke"' "broker-refresh-smoke reports refresh broker mode"
expect_contains "$broker_refresh_smoke" '"ok":true' "broker-refresh-smoke reports success"
expect_contains "$broker_refresh_smoke" '"proof_status":"local_refresh_protocol_smoke"' "broker-refresh-smoke reports refresh protocol proof status"
expect_contains "$broker_refresh_smoke" '"selected":{"provider":"codex","account":"max-1","capability":"codex-max"' "broker-refresh-smoke starts from first ready route"
expect_contains "$broker_refresh_smoke" '"refresh_selected":{"provider":"codex","account":"max-2","capability":"codex-max"' "broker-refresh-smoke answers refresh with fallback route"
expect_contains "$broker_refresh_smoke" '"refresh_route_is_fallback":true' "broker-refresh-smoke marks refresh route as fallback"
expect_contains "$broker_refresh_smoke" '"refresh_request_seen":true' "broker-refresh-smoke observes refresh request"
expect_contains "$broker_refresh_smoke" '"refresh_reason_unauthorized":true' "broker-refresh-smoke classifies unauthorized refresh reason"
expect_contains "$broker_refresh_smoke" '"refresh_response_sent":true' "broker-refresh-smoke sends refresh response"
expect_contains "$broker_refresh_smoke" '"tokens_printed":false' "broker-refresh-smoke redaction reports token suppression"
expect_contains "$broker_refresh_smoke" '"raw_protocol_printed":false' "broker-refresh-smoke redaction reports raw protocol suppression"
expect_not_contains "$broker_refresh_smoke" 'acct-test' "broker-refresh-smoke does not expose account id value"
expect_not_contains "$broker_refresh_smoke" 'acct-fallback' "broker-refresh-smoke does not expose fallback account id value"
expect_not_contains "$broker_refresh_smoke" "$broker_jwt" "broker-refresh-smoke does not expose token value"
expect_not_contains "$broker_refresh_smoke" 'broker-refresh-token' "broker-refresh-smoke does not expose refresh token value"

printf 'e2e: codex broker-401-smoke requires explicit confirmation before starting app-server\n'
broker_401_prompt="$(OMUX_CONFIG="$broker_switch_config" OMUX_STATE_DIR="$state_dir" "$bin" codex broker-401-smoke --profile codex-max --capability codex-max --json)"
expect_contains "$broker_401_prompt" '"mode":"codex_app_server_401_broker_smoke"' "broker-401-smoke reports 401 broker mode"
expect_contains "$broker_401_prompt" '"confirmation_required":true' "broker-401-smoke requires confirmation"
expect_contains "$broker_401_prompt" '"requires":"--confirm-broker"' "broker-401-smoke reports required confirmation flag"
expect_contains "$broker_401_prompt" '"spends_provider_calls":false' "broker-401-smoke confirmation prompt reports no provider spend"

printf 'e2e: codex broker-quota-smoke requires explicit confirmation before starting app-server\n'
broker_quota_prompt="$(OMUX_CONFIG="$broker_switch_config" OMUX_STATE_DIR="$state_dir" "$bin" codex broker-quota-smoke --profile codex-max --capability codex-max --json)"
expect_contains "$broker_quota_prompt" '"mode":"codex_app_server_quota_broker_smoke"' "broker-quota-smoke reports quota broker mode"
expect_contains "$broker_quota_prompt" '"confirmation_required":true' "broker-quota-smoke requires confirmation"
expect_contains "$broker_quota_prompt" '"requires":"--confirm-broker"' "broker-quota-smoke reports required confirmation flag"
expect_contains "$broker_quota_prompt" '"spends_provider_calls":false' "broker-quota-smoke confirmation prompt reports no provider spend"

repair_reauth_json="$tmp/repair-run-reauth.json"
set +e
OMUX_CONFIG="$reauth_config" \
  OMUX_STATE_DIR="$state_dir" \
  OMUX_E2E_REAUTH='{}' \
  "$bin" repair run --profile needs-reauth --capability codex-max --json >"$repair_reauth_json" 2>"$tmp/repair-run-reauth.stderr"
repair_reauth_status=$?
set -e
if [ "$repair_reauth_status" -eq 0 ]; then
  printf 'e2e assertion failed: repair run should require confirmation before reauth\n' >&2
  exit 1
fi
repair_reauth="$(cat "$repair_reauth_json")"
expect_contains "$repair_reauth" '"confirmation_required":true' "repair run requires confirmation"
expect_contains "$repair_reauth" '"requires":"--confirm-repair"' "repair run reports required flag"
expect_contains "$repair_reauth" '"command":"oauth-mux codex login-device max-1"' "repair run reports upstream command"
expect_contains "$repair_reauth" '"daemon_repair":{"admitted":false,"reason":"interactive_not_allowed","budget":"interactive"}' "repair run reports daemon policy refusal"
expect_contains "$repair_reauth" '"writeback":{"capability":"replace_file","automatic_refresh_admitted":false,"reason":"provider_repair_owned_by_upstream_cli"}' "repair run reports upstream-owned file writeback boundary"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: stay-afloat next returns provider-mediated handoff when not afloat\n'
stay_next_reauth="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat next --profile needs-reauth --capability codex-max --json)"
expect_contains "$stay_next_reauth" '"action":"next"' "stay-afloat next reauth reports action"
expect_contains "$stay_next_reauth" '"ready_for_exec":false' "stay-afloat next reauth refuses exec readiness"
expect_contains "$stay_next_reauth" '"claim":{"claim_version":1,"level":"mediation_required"' "stay-afloat next reauth reports mediation claim"
expect_contains "$stay_next_reauth" '"prepared_fallback":false' "stay-afloat next reauth refuses prepared fallback claim"
expect_contains "$stay_next_reauth" '"launch_argv":["oauth-mux","stay-afloat","launch","--profile","needs-reauth","--capability","codex-max","--","<command>"]' "stay-afloat next reauth reports launch argv boundary"
expect_contains "$stay_next_reauth" '"next_action":{"kind":"repair"' "stay-afloat next reauth returns repair mediation"
expect_contains "$stay_next_reauth" '"kind":"reauth"' "stay-afloat next reauth reports reauth action"
expect_contains "$stay_next_reauth" '"mediation":"user_handoff"' "stay-afloat next reauth reports user handoff"
expect_contains "$stay_next_reauth" '"repair_owner":"upstream_cli_login"' "stay-afloat next reauth reports upstream owner"
expect_contains "$stay_next_reauth" '"command":"oauth-mux codex login-device max-1"' "stay-afloat next reauth reports upstream command"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: stay-afloat launch refuses target when user-mediated reauth is needed\n'
stay_launch_reauth_out="$tmp/stay-launch-reauth.out"
stay_launch_should_not_run="$tmp/stay-launch-should-not-run"
set +e
OMUX_CONFIG="$reauth_config" \
  OMUX_STATE_DIR="$state_dir" \
  "$bin" stay-afloat launch --profile needs-reauth --capability codex-max -- sh -c "touch '$stay_launch_should_not_run'" >"$stay_launch_reauth_out" 2>"$tmp/stay-launch-reauth.stderr"
stay_launch_reauth_status=$?
set -e
if [ "$stay_launch_reauth_status" -eq 0 ]; then
  printf 'e2e assertion failed: stay-afloat launch should refuse a reauth-needed route\n' >&2
  exit 1
fi
stay_launch_reauth="$(cat "$stay_launch_reauth_out")"
expect_contains "$stay_launch_reauth" 'ready_for_exec: false' "stay-afloat launch refusal reports not ready"
expect_contains "$stay_launch_reauth" 'next_action: reauth' "stay-afloat launch refusal reports reauth action"
expect_contains "$stay_launch_reauth" 'command: oauth-mux codex login-device max-1' "stay-afloat launch refusal reports upstream command"
test ! -e "$stay_launch_should_not_run"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: daemon tick execute queues interactive reauth handoff\n'
daemon_handoff="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" daemon tick --once --execute --profile needs-reauth --capability codex-max --json)"
expect_contains "$daemon_handoff" '"execution_mode":"execute"' "daemon handoff reports execute mode"
expect_contains "$daemon_handoff" '"handoff_queued":true' "daemon handoff queues user action"
expect_contains "$daemon_handoff" '"phase":"handoff"' "daemon handoff reports handoff phase"
expect_contains "$daemon_handoff" '"admitted":false' "daemon handoff preserves daemon policy refusal"
expect_contains "$daemon_handoff" '"command":"oauth-mux codex login-device max-1"' "daemon handoff reports upstream login command"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: stay-afloat execute reports existing handoff without duplicating it\n'
stay_afloat_handoff_pending="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat --once --execute --profile needs-reauth --capability codex-max --json)"
expect_contains "$stay_afloat_handoff_pending" '"handoff_queued":false' "stay-afloat pending handoff does not queue a duplicate"
expect_contains "$stay_afloat_handoff_pending" '"handoff_pending":true' "stay-afloat reports pending handoff"
expect_contains "$stay_afloat_handoff_pending" '"reason":"handoff_pending"' "stay-afloat reports pending handoff reason"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: daemon handoffs exposes queued user-mediated repair actions\n'
daemon_handoffs="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json)"
expect_contains "$daemon_handoffs" '"handoffs":[' "daemon handoffs returns json handoff list"
expect_contains "$daemon_handoffs" '"kind":"daemon_handoff"' "daemon handoffs includes handoff events"
expect_contains "$daemon_handoffs" '"outcome":"handoff_queued"' "daemon handoffs includes queued outcome"
expect_contains "$daemon_handoffs" '"command":"oauth-mux codex login-device max-1"' "daemon handoffs includes upstream command"
stay_afloat_handoffs="$(OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat handoffs --json)"
expect_contains "$stay_afloat_handoffs" '"kind":"daemon_handoff"' "stay-afloat handoffs aliases pending handoff queue"

printf 'e2e: stay-afloat handoff ack records user acknowledgement without clearing pending work\n'
stay_afloat_ack="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat handoff ack --profile needs-reauth --provider codex --account max-1 --capability codex-max --json)"
expect_contains "$stay_afloat_ack" '"handoff_acknowledged":true' "stay-afloat handoff ack records acknowledgement"
expect_contains "$stay_afloat_ack" '"handoff_pending":true' "stay-afloat handoff ack leaves route pending"
expect_contains "$stay_afloat_ack" '"event_recorded":true' "stay-afloat handoff ack records an event"
daemon_handoffs_after_ack="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json)"
expect_contains "$daemon_handoffs_after_ack" '"outcome":"handoff_queued"' "daemon handoffs still shows pending queue after acknowledgement"
daemon_handoffs_all_after_ack="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json --all)"
expect_contains "$daemon_handoffs_all_after_ack" '"outcome":"handoff_acknowledged"' "daemon handoffs --all shows acknowledgement history"

printf 'e2e: stay-afloat handoff clear dismisses stale pending work explicitly\n'
stay_afloat_clear="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat handoff clear --profile needs-reauth --provider codex --account max-1 --capability codex-max --json)"
expect_contains "$stay_afloat_clear" '"handoff_resolved":true' "stay-afloat handoff clear records resolution"
expect_contains "$stay_afloat_clear" '"handoff_pending":false' "stay-afloat handoff clear removes pending route"
daemon_handoffs_after_clear="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json)"
expect_contains "$daemon_handoffs_after_clear" '"handoffs":[]' "daemon handoffs clears after explicit handoff clear"
daemon_handoffs_all_after_clear="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json --all)"
expect_contains "$daemon_handoffs_all_after_clear" '"outcome":"handoff_resolved"' "daemon handoffs --all shows explicit handoff resolution"

daemon_handoff_requeued="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" daemon tick --once --execute --profile needs-reauth --capability codex-max --json)"
expect_contains "$daemon_handoff_requeued" '"handoff_queued":true' "daemon tick can requeue handoff after explicit clear"

repair_reauth_confirmed_json="$tmp/repair-run-reauth-confirmed.json"
set +e
OMUX_CONFIG="$reauth_config" \
  OMUX_STATE_DIR="$state_dir" \
  OMUX_E2E_REAUTH='{}' \
  "$bin" repair run --profile needs-reauth --capability codex-max --confirm-repair --json >"$repair_reauth_confirmed_json" 2>"$tmp/repair-run-reauth-confirmed.stderr"
repair_reauth_confirmed_status=$?
set -e
if [ "$repair_reauth_confirmed_status" -eq 0 ]; then
  printf 'e2e assertion failed: repair run --json should refuse confirmed interactive repair\n' >&2
  exit 1
fi
repair_reauth_confirmed="$(cat "$repair_reauth_confirmed_json")"
expect_contains "$repair_reauth_confirmed" '"error":"interactive_json_unsupported"' "repair run json refuses interactive execution"
expect_contains "$repair_reauth_confirmed" '"executed":false' "repair run json does not execute interactive repair"
test ! -e "$tmp/reauth-home/auth.json"

printf 'e2e: daemon handoffs clears after route evidence refresh\n'
printf '%s\n' '{"access_token":"reauth-e2e"}' >"$tmp/reauth-home/auth.json"
daemon_repaired="$(OMUX_CONFIG="$reauth_config" OMUX_STATE_DIR="$state_dir" "$bin" stay-afloat refresh --profile needs-reauth --capability codex-max --json)"
expect_contains "$daemon_repaired" '"execution_mode":"execute"' "stay-afloat refresh runs execute tick"
expect_contains "$daemon_repaired" '"executed":true' "stay-afloat refresh runs probe after user-mediated login"
expect_contains "$daemon_repaired" '"phase":"probe"' "stay-afloat refresh records probe phase"
daemon_handoffs_cleared="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json)"
expect_contains "$daemon_handoffs_cleared" '"handoffs":[]' "daemon handoffs clears resolved handoff"
daemon_handoffs_all="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon handoffs --json --all)"
expect_contains "$daemon_handoffs_all" '"kind":"daemon_handoff"' "daemon handoffs --all preserves historical handoff events"
expect_contains "$daemon_handoffs_all" '"outcome":"handoff_acknowledged"' "daemon handoffs --all preserves acknowledgement events"

printf 'e2e: daemon events exposes redacted repair run audit trail\n'
repair_events="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon events --json)"
expect_contains "$repair_events" '"events":[' "daemon events returns json event list"
expect_contains "$repair_events" '"outcome":"noop"' "repair events record selectable no-op"
expect_contains "$repair_events" '"outcome":"confirmation_required"' "repair events record confirmation gate"
expect_contains "$repair_events" '"outcome":"interactive_json_unsupported"' "repair events record json boundary refusal"
expect_contains "$repair_events" '"profile":"needs-reauth"' "repair events record profile"
expect_contains "$repair_events" '"provider":"codex"' "repair events record provider"
expect_contains "$repair_events" '"account":"max-1"' "repair events record account"
expect_contains "$repair_events" '"kind":"daemon_handoff"' "repair events record daemon handoff"
expect_contains "$repair_events" '"outcome":"handoff_queued"' "repair events record daemon handoff outcome"

printf 'e2e: refresh admission refusal records redacted token_refresh event\n'
refresh_config="$tmp/refresh-config.json"
refresh_auth="$tmp/refresh-auth.json"
cat >"$refresh_auth" <<'EOF'
{"tokens":{"access_token":"expired-access-token","refresh_token":"expired-refresh-token","expires_at":1}}
EOF
cat >"$refresh_config" <<EOF
{
  "version": 1,
  "provider_definitions": {
    "toy": {
      "name": "toy",
      "repair": {
        "owner": "upstream_cli_login"
      },
      "credential": {
        "access_token_path": "tokens.access_token",
        "refresh_token_path": "tokens.refresh_token",
        "expires_at_path": "tokens.expires_at"
      },
      "injection": {
        "direct_env": [["TOY_TOKEN", "access_token"]]
      }
    }
  },
  "providers": {
    "toy": {
      "kind": "toy",
      "accounts": {
        "expired": {
          "secret": {
            "backend": "file",
            "path": "$refresh_auth"
          }
        }
      }
    }
  },
  "profiles": {
    "refresh-refused": {
      "providers": ["toy:expired"]
    }
  },
  "strategies": {}
}
EOF
refresh_refused_json="$tmp/refresh-refused.json"
if OMUX_CONFIG="$refresh_config" OMUX_STATE_DIR="$state_dir" "$bin" env --profile refresh-refused --shell bash >"$refresh_refused_json" 2>"$tmp/refresh-refused.stderr"; then
  printf 'e2e assertion failed: expired refresh route should fail closed before token endpoint\n' >&2
  exit 1
fi
refresh_events="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon events --json)"
expect_contains "$refresh_events" '"kind":"token_refresh"' "refresh event records event kind"
expect_contains "$refresh_events" '"outcome":"not_admitted"' "refresh event records admission refusal"
expect_contains "$refresh_events" '"writeback_capability":"replace_file"' "refresh event records writeback capability"
expect_contains "$refresh_events" '"automatic_refresh_admitted":false' "refresh event records admission boolean"
expect_contains "$refresh_events" '"reason":"provider_repair_owned_by_upstream_cli"' "refresh event records redacted refusal reason"

printf 'e2e: route health does not poison unrelated capability\n'
cheap_after_quota="$(omux env --profile cheap --capability cheap --shell bash)"
expect_contains "$cheap_after_quota" "export OMUX_ACTIVE_ACCOUNT='a1'" "cheap route still uses a1 after expensive quota"

printf 'e2e: env command skips known exhausted route\n'
expensive_env="$(omux env --profile expensive --capability expensive --shell bash)"
expect_contains "$expensive_env" "export TOY_TOKEN='omux-e2e-a2'" "expensive env uses fallback account a2"
expect_contains "$expensive_env" "export OMUX_ACTIVE_ACCOUNT='a2'" "expensive env marks active account a2"

printf 'e2e: exec injects selected account into target process\n'
OMUX_E2E_EXEC_OUT="$exec_out" omux exec --profile cheap --capability cheap -- sh -c 'printf "%s:%s" "$OMUX_ACTIVE_ACCOUNT" "$TOY_TOKEN" > "$OMUX_E2E_EXEC_OUT"'
exec_result="$(cat "$exec_out")"
expect_contains "$exec_result" 'a1:omux-e2e-a1' "exec target receives selected account env"

printf 'e2e-local passed\n'
