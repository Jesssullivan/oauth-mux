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
expect_contains "$doctor_json" '"oauth-mux report --redacted --json"' "doctor recommends redacted report"

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
