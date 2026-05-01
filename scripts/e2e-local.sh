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
cleanup() {
  if [ -n "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

config="$tmp/config.json"
state_dir="$tmp/state"
exec_out="$tmp/exec.out"
probe_cmd="$tmp/probe-harness.sh"
reauth_probe_cmd="$tmp/reauth-probe-harness.sh"

mkdir -p "$state_dir" "$tmp/a1-home" "$tmp/a2-home"

cat >"$probe_cmd" <<'EOF'
#!/usr/bin/env sh
set -eu

capability="${1:-}"

case "${capability}:${OMUX_ACTIVE_ACCOUNT:-}" in
  expensive:a1)
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

printf 'e2e: daemon tick plans stay-afloat without executing work\n'
daemon_tick="$(omux daemon tick --once --profile expensive --capability expensive --json)"
expect_contains "$daemon_tick" '"mode":"once"' "daemon tick reports one-shot mode"
expect_contains "$daemon_tick" '"executed":false' "daemon tick does not execute probes or repair"
expect_contains "$daemon_tick" '"afloat":true' "daemon tick reports profile afloat"
expect_contains "$daemon_tick" '"selected":{"provider":"toy","account":"a2"' "daemon tick selects fallback account a2"
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

printf 'e2e: bounded daemon tick loop emits repeated planning snapshots\n'
daemon_loop="$(omux daemon tick --loop --iterations 2 --interval-ms 0 --profile expensive --capability expensive --json)"
expect_contains "$daemon_loop" '"mode":"loop"' "daemon tick loop reports loop mode"
expect_contains "$daemon_loop" '"iterations_requested":2' "daemon tick loop reports requested iterations"
expect_contains "$daemon_loop" '"ticks":[' "daemon tick loop returns tick array"
expect_contains "$daemon_loop" '"tick_index":0' "daemon tick loop includes first tick"
expect_contains "$daemon_loop" '"tick_index":1' "daemon tick loop includes second tick"
expect_contains "$daemon_loop" '"executed":false' "daemon tick loop remains planning-only"

printf 'e2e: daemon foreground status and stop stay inside temp runtime\n'
daemon_runtime="$tmp/daemon-runtime"
daemon_state="$tmp/daemon-state"
daemon_log="$tmp/daemon.log"
mkdir -p "$daemon_runtime" "$daemon_state"
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
