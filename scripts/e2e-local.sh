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
trap 'rm -rf "$tmp"' EXIT

config="$tmp/config.json"
state_dir="$tmp/state"
exec_out="$tmp/exec.out"
probe_cmd="$tmp/probe-harness.sh"

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
expect_contains "$providers_json" '"configured_accounts":2' "providers list counts custom provider accounts"

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
expect_contains "$daemon_tick" '"reason":"route_selectable"' "daemon tick marks selectable route as no-op"

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
      }
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
            "backend": "env",
            "variable": "OMUX_E2E_REAUTH"
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
test ! -e "$tmp/reauth-home/auth.json"

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

printf 'e2e: daemon events exposes redacted repair run audit trail\n'
repair_events="$(OMUX_STATE_DIR="$state_dir" "$bin" daemon events --json)"
expect_contains "$repair_events" '"events":[' "daemon events returns json event list"
expect_contains "$repair_events" '"outcome":"noop"' "repair events record selectable no-op"
expect_contains "$repair_events" '"outcome":"confirmation_required"' "repair events record confirmation gate"
expect_contains "$repair_events" '"outcome":"interactive_json_unsupported"' "repair events record json boundary refusal"
expect_contains "$repair_events" '"profile":"needs-reauth"' "repair events record profile"
expect_contains "$repair_events" '"provider":"codex"' "repair events record provider"
expect_contains "$repair_events" '"account":"max-1"' "repair events record account"

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
