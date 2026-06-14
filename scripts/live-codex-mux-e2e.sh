#!/usr/bin/env bash
# Live oauth-mux Codex e2e harness for TIN-1852.
#
# This is intentionally a live-provider lane. It proves a real managed Codex
# transaction through oauth-mux, records status evidence, and checks that the
# canonical Codex sqlite store is not poisoned by transient managed homes.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OMUX_LIVE_E2E_BIN:-$ROOT/zig-out/bin/oauth-mux}"
NATIVE_CODEX="${OMUX_CODEX_BIN:-$(command -v codex || true)}"
PROFILE="${OMUX_LIVE_E2E_PROFILE:-codex-max}"
CAPABILITY="${OMUX_LIVE_E2E_CAPABILITY:-codex-max}"
CONFIRM="${OMUX_LIVE_CODEX_E2E_CONFIRM:-}"
TOKEN="${OMUX_LIVE_E2E_TOKEN:-OMUX_TIN1852_EXEC_OK}"
PROMPT="${OMUX_LIVE_E2E_PROMPT:-Reply with exactly this token and nothing else: $TOKEN}"
# TIN-1851: the default mux mode is home-is-store, whose session authority is
# "isolated". A shared_canonical opt-in run emits "canonical_bridge"; override
# this to match when exercising that legacy mode.
EXPECT_AUTHORITY="${OMUX_LIVE_E2E_EXPECT_AUTHORITY:-isolated}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${OMUX_LIVE_E2E_DIR:-$ROOT/dist/live-qa/tin1852-$STAMP}"
NDJSON="$EVIDENCE_DIR/status.ndjson"
STDOUT_FILE="$EVIDENCE_DIR/stdout.txt"
STDERR_FILE="$EVIDENCE_DIR/stderr.txt"
PREFLIGHT_FILE="$EVIDENCE_DIR/preflight-before.json"
VERSION_FILE="$EVIDENCE_DIR/version.json"
SUMMARY_FILE="$EVIDENCE_DIR/status-summary.json"
COUNTS_FILE="$EVIDENCE_DIR/sqlite-counts.json"
SCRUB_FILE="$EVIDENCE_DIR/scrub-check.json"
ROUTE_HOME_SHAPE_FILE="$EVIDENCE_DIR/route-home-shape.json"

if [[ "$CONFIRM" != "real-provider-calls" ]]; then
    cat >&2 <<'EOF'
live-codex-mux-e2e: refusing to run live Codex traffic without confirmation.

Set:
  OMUX_LIVE_CODEX_E2E_CONFIRM=real-provider-calls

Optional:
  OMUX_LIVE_E2E_BIN=/path/to/oauth-mux
  OMUX_CODEX_BIN=/path/to/native/codex
  OMUX_LIVE_E2E_PROFILE=codex-max
  OMUX_LIVE_E2E_CAPABILITY=codex-max
  OMUX_LIVE_E2E_DIR=dist/live-qa/tin1852-custom
EOF
    exit 64
fi

if [[ ! -x "$BIN" ]]; then
    echo "live-codex-mux-e2e: oauth-mux binary not executable: $BIN" >&2
    exit 64
fi

if [[ -z "$NATIVE_CODEX" || ! -x "$NATIVE_CODEX" ]]; then
    echo "live-codex-mux-e2e: native Codex binary not executable; set OMUX_CODEX_BIN" >&2
    exit 64
fi

for tool in jq sqlite3 python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "live-codex-mux-e2e: required tool missing: $tool" >&2
        exit 64
    fi
done

mkdir -p "$EVIDENCE_DIR"

sqlite_counts() {
    sqlite3 "$HOME/.codex/state_5.sqlite" <<'SQL'
select json_object(
  'old_oauth_mux_codex', (select count(*) from threads where rollout_path like '%oauth-mux-codex%'),
  'managed_bridge', (select count(*) from threads where rollout_path like '%omux-managed-codex%'),
  'total_threads', (select count(*) from threads),
  'integrity_check', (select integrity_check from pragma_integrity_check)
);
SQL
}

scrub_check() {
    python3 - "$HOME/.codex/.oauth-mux/managed-codex-homes" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
leaks = []
bridges = 0
if root.exists():
    for path in root.rglob("*"):
        if path.name in {"auth.json", "config.toml", "installation_id"} and path.is_file():
            leaks.append(str(path))
        if path.name == "sessions" and path.is_symlink():
            bridges += 1
print(json.dumps({
    "root": str(root),
    "root_exists": root.exists(),
    "token_or_config_leaks": len(leaks),
    "durable_session_bridges": bridges,
    "ok": len(leaks) == 0,
}, sort_keys=True))
PY
}

# Resolve the route-local persistent home (home-is-store CODEX_HOME) for the
# elected account by mirroring the binary's config resolution order:
# OMUX_CONFIG, then OMUX_CONFIG_DIR, then XDG config dir / macOS Application
# Support. Prints the dirname of the account's secret.path.
resolve_route_home() {
    local selected="$1"
    local acct="${selected#codex:}"
    local cfg="${OMUX_CONFIG:-}"
    if [[ -z "$cfg" ]]; then
        local cfg_dir="${OMUX_CONFIG_DIR:-}"
        if [[ -z "$cfg_dir" ]]; then
            # Mirror the binary's xdgOrMacOS order (src/paths.zig): explicit
            # XDG_CONFIG_HOME wins; otherwise macOS uses Application Support
            # (never ~/.config); other platforms use ~/.config.
            if [[ -n "${XDG_CONFIG_HOME:-}" && -f "$XDG_CONFIG_HOME/oauth-mux/config.json" ]]; then
                cfg_dir="$XDG_CONFIG_HOME/oauth-mux"
            elif [[ "$(uname -s)" == "Darwin" && -f "$HOME/Library/Application Support/oauth-mux/config.json" ]]; then
                cfg_dir="$HOME/Library/Application Support/oauth-mux"
            elif [[ -f "$HOME/.config/oauth-mux/config.json" ]]; then
                cfg_dir="$HOME/.config/oauth-mux"
            fi
        fi
        [[ -n "$cfg_dir" ]] || return 1
        cfg="$cfg_dir/config.json"
    fi
    [[ -f "$cfg" ]] || return 1
    local auth
    auth="$(jq -r --arg a "$acct" '.providers.codex.accounts[$a].secret.path // empty' "$cfg")"
    [[ -n "$auth" ]] || return 1
    auth="${auth/#\~/$HOME}"
    printf '%s\n' "${auth%/*}"
}

# home-is-store shape check for the route-local persistent home: auth.json must
# persist, and no stray managed config.toml pointing at a dead proxy port may
# survive the exit (a live port means another managed session legitimately owns
# the home right now).
route_home_shape_check() {
    python3 - "$1" <<'PY'
import json
import pathlib
import re
import socket
import sys

home = pathlib.Path(sys.argv[1])
result = {
    "route_home_exists": home.is_dir(),
    "auth_json_present": (home / "auth.json").is_file(),
    "stray_config_toml": False,
    "stray_config_proxy_port_dead": False,
}
cfg = home / "config.toml"
if cfg.is_file():
    text = cfg.read_text(encoding="utf-8", errors="replace")
    m = re.search(r'openai_base_url\s*=\s*"http://127\.0\.0\.1:(\d+)', text)
    if m:
        result["stray_config_toml"] = True
        port = int(m.group(1))
        s = socket.socket()
        s.settimeout(0.5)
        try:
            alive = s.connect_ex(("127.0.0.1", port)) == 0
        finally:
            s.close()
        result["stray_config_proxy_port_dead"] = not alive
result["ok"] = (
    result["route_home_exists"]
    and result["auth_json_present"]
    and not result["stray_config_proxy_port_dead"]
)
print(json.dumps(result, sort_keys=True))
PY
}

"$BIN" version --json >"$VERSION_FILE"
"$BIN" codex preflight --profile "$PROFILE" --capability "$CAPABILITY" --json >"$PREFLIGHT_FILE" || true

BEFORE_COUNTS="$(sqlite_counts)"
BEFORE_SCRUB="$(scrub_check)"

set +e
OMUX_CODEX_BIN="$NATIVE_CODEX" \
    "$BIN" codex \
    --profile "$PROFILE" \
    --capability "$CAPABILITY" \
    --json-status-file "$NDJSON" \
    -- \
    exec --skip-git-repo-check "$PROMPT" \
    >"$STDOUT_FILE" 2>"$STDERR_FILE"
EXIT_CODE=$?
set -e

AFTER_COUNTS="$(sqlite_counts)"
AFTER_SCRUB="$(scrub_check)"

python3 - "$COUNTS_FILE" "$BEFORE_COUNTS" "$AFTER_COUNTS" <<'PY'
import json
import sys

out = sys.argv[1]
before = json.loads(sys.argv[2])
after = json.loads(sys.argv[3])
payload = {"before": before, "after": after}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY

python3 - "$SCRUB_FILE" "$BEFORE_SCRUB" "$AFTER_SCRUB" <<'PY'
import json
import sys

out = sys.argv[1]
before = json.loads(sys.argv[2])
after = json.loads(sys.argv[3])
payload = {"before": before, "after": after}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY

if [[ -s "$NDJSON" ]]; then
    "$ROOT/scripts/summarize-codex-status.py" "$NDJSON" >"$SUMMARY_FILE" || true
fi

if [[ -s "$SUMMARY_FILE" && -s "$STDERR_FILE" ]]; then
    python3 - "$SUMMARY_FILE" "$STDERR_FILE" <<'PY'
import json
import re
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
stderr_path = Path(sys.argv[2])

try:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)

observed_model = None
for line in stderr_path.read_text(encoding="utf-8", errors="replace").splitlines():
    match = re.match(r"\s*model:\s*([^\s]+)\s*$", line)
    if match:
        observed_model = match.group(1)
        break

if observed_model:
    summary["observed_child_model"] = observed_model
    summary["observed_child_model_source"] = "codex_stderr"
    summary["route_capability_is_child_model"] = False

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

echo "live-codex-mux-e2e: evidence_dir=$EVIDENCE_DIR"
echo "live-codex-mux-e2e: exit_code=$EXIT_CODE"

if [[ "$EXIT_CODE" -ne 0 ]]; then
    echo "live-codex-mux-e2e: managed Codex command failed; see $STDERR_FILE" >&2
    exit "$EXIT_CODE"
fi

if ! grep -q "$TOKEN" "$STDOUT_FILE"; then
    echo "live-codex-mux-e2e: expected token not found in stdout: $TOKEN" >&2
    exit 1
fi

if grep -q "SessionAuthorityLocked" "$STDERR_FILE" "$STDOUT_FILE"; then
    echo "live-codex-mux-e2e: SessionAuthorityLocked appeared in command output" >&2
    exit 1
fi

if [[ "$(jq -r '.after.old_oauth_mux_codex' "$COUNTS_FILE")" != "$(jq -r '.before.old_oauth_mux_codex' "$COUNTS_FILE")" ]]; then
    echo "live-codex-mux-e2e: old oauth-mux-codex sqlite poison count changed" >&2
    exit 1
fi

if [[ "$(jq -r '.after.integrity_check' "$COUNTS_FILE")" != "ok" ]]; then
    echo "live-codex-mux-e2e: sqlite integrity check failed" >&2
    exit 1
fi

if [[ "$(jq -r '.after.ok' "$SCRUB_FILE")" != "true" ]]; then
    echo "live-codex-mux-e2e: durable managed home retained token/config material" >&2
    exit 1
fi

if [[ "$EXPECT_AUTHORITY" == "isolated" ]]; then
    # TIN-1851/TIN-1852 default-mode gate: a home-is-store run must not record
    # any new canonical threads through managed bridge homes (rollout_path like
    # '%omux-managed-codex%' is the exact TIN-1851 poisoning signature) and must
    # not (re)create the legacy bridge root under ~/.codex/.oauth-mux.
    if [[ "$(jq -r '.after.managed_bridge' "$COUNTS_FILE")" != "$(jq -r '.before.managed_bridge' "$COUNTS_FILE")" ]]; then
        echo "live-codex-mux-e2e: managed-bridge sqlite thread count changed during an isolated run (TIN-1851 poisoning signature)" >&2
        exit 1
    fi
    if [[ "$(jq -r '.before.root_exists' "$SCRUB_FILE")" != "$(jq -r '.after.root_exists' "$SCRUB_FILE")" ]]; then
        echo "live-codex-mux-e2e: legacy bridge root was created during an isolated run" >&2
        exit 1
    fi
    if [[ "$(jq -r '.after.root_exists' "$SCRUB_FILE")" == "true" ]]; then
        echo "live-codex-mux-e2e: warning: legacy bridge root pre-exists from older shared_canonical runs (unchanged by this run)" >&2
    fi
fi

if [[ -s "$NDJSON" ]]; then
    jq -e 'select(.kind == "session_started") | .runtime_identity.binary_sha256' "$NDJSON" >/dev/null
    jq -e --arg a "$EXPECT_AUTHORITY" 'select(.kind == "session_started") | select(.session_authority == $a)' "$NDJSON" >/dev/null
    jq -e 'select(.kind == "session_ended") | select(.exit_code == 0)' "$NDJSON" >/dev/null
    if [[ "$EXPECT_AUTHORITY" == "isolated" ]]; then
        jq -e 'select(.kind == "session_started") | select(.sqlite_authority == "isolated_overlay")' "$NDJSON" >/dev/null

        # Route-local persistent home shape: auth.json persists, and no stray
        # managed config.toml with a dead proxy port survives the exit.
        SELECTED_ACCOUNT="$(jq -r 'select(.kind == "session_started") | .selected_account // empty' "$NDJSON" | head -n 1)"
        if [[ -z "$SELECTED_ACCOUNT" ]]; then
            echo "live-codex-mux-e2e: session_started carried no selected_account; cannot verify route home" >&2
            exit 1
        fi
        if ! ROUTE_HOME="$(resolve_route_home "$SELECTED_ACCOUNT")"; then
            echo "live-codex-mux-e2e: could not resolve the route-local persistent home for the elected account" >&2
            exit 1
        fi
        route_home_shape_check "$ROUTE_HOME" >"$ROUTE_HOME_SHAPE_FILE"
        if [[ "$(jq -r '.ok' "$ROUTE_HOME_SHAPE_FILE")" != "true" ]]; then
            echo "live-codex-mux-e2e: route-local persistent home shape check failed (auth.json missing or stray managed config.toml with dead proxy port)" >&2
            cat "$ROUTE_HOME_SHAPE_FILE" >&2
            exit 1
        fi
    else
        # Legacy bridge runs keep the canonical sqlite authority.
        jq -e 'select(.kind == "session_started") | select(.sqlite_authority == "canonical_env")' "$NDJSON" >/dev/null
    fi
fi

echo "live-codex-mux-e2e: PASS"
