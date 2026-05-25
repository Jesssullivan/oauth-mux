#!/usr/bin/env bash
# Capture Codex wire traffic for the broker MCP contract.
#
# Anchor: docs/spec/broker-mcp-contract-2026-05-03.md section 5 Phase 0.
# Goal:   replace assumptions with observed traffic and validate the
#         implemented same-turn quota retry shape against provider reality.
#
# Captures HTTP traffic, including any WebSocket upgrade request metadata,
# to chatgpt.com/backend-api/codex via mitmdump.
#
# Outputs land under captures/codex-wire-<UTC-timestamp>/ with:
#   - http/   - mitmdump flows (.flows binary + per-flow redacted JSON)
#   - meta.json - codex version, plan_type, capture metadata
#
# Captured evidence fills in docs/spec/codex-wire-evidence-2026-05-03.md.

set -euo pipefail

cmd="${1:-help}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP_DIR="${OMUX_CAPTURE_DIR:-$ROOT/captures}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$CAP_DIR/codex-wire-$TS"

usage() {
  cat <<'__USAGE_END__'
capture-codex-wire.sh - Phase 0 evidence capture for the Codex adapter.

USAGE
  scripts/capture-codex-wire.sh init             # one-time mitmproxy CA install check
  scripts/capture-codex-wire.sh preflight        # no-spend capture readiness report
  scripts/capture-codex-wire.sh proxy            # start the HTTP capture proxy in foreground
  scripts/capture-codex-wire.sh review DIR [REVIEW_FLAGS...]
                                              # summarize/redaction-check a capture
  scripts/capture-codex-wire.sh help

WORKFLOW
  1. Run `init` once. If your system trust store does not yet have the
     mitmproxy CA, follow the instructions it prints. macOS:
       security add-trusted-cert -d -r trustRoot \
         -k ~/Library/Keychains/login.keychain-db ~/.mitmproxy/mitmproxy-ca-cert.cer
  2. Run the no-spend capture preflight:
       scripts/capture-codex-wire.sh preflight
     It records installed binary identity, Codex version, mitmproxy
     availability, route fallback readiness, latest status summary, and
     active oauth-mux/Codex process hints under captures/.
  3. In one shell:
       scripts/capture-codex-wire.sh proxy
     The proxy listens on 127.0.0.1:9080 as a normal HTTP proxy.
  4. In another shell:
       export HTTPS_PROXY=http://127.0.0.1:9080
       export HTTP_PROXY=http://127.0.0.1:9080
       export NO_PROXY=
       codex
     Drive a normal turn, force a 401 (revoke a token externally), and
     drive an account to weekly quota exhaustion to capture the 429 +
     usage_limit_reached body.
  5. Stop the proxy with ^C. Find captures under captures/.
  6. Run:
       scripts/capture-codex-wire.sh review captures/codex-wire-<TS>
  7. Distill findings into docs/spec/codex-wire-evidence-2026-05-03.md.

REDACTION
  The mitmproxy addon redacts Authorization, Cookie, and ChatGPT-Account-
  ID values, and replaces tokens.access_token/refresh_token/id_token in
  any JSON body with the SHA-256 prefix of their bytes. Raw capture
  directories are ignored by git. Commit only operator-reviewed,
  scrubbed, fixture-sized per-flow JSON evidence; do NOT commit the
  .flows binary, which retains raw bytes.
__USAGE_END__
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing dependency '$1'." >&2
    echo "       hint: $2" >&2
    exit 64
  fi
}

cmd_init() {
  require_cmd mitmdump "install mitmproxy via 'brew install mitmproxy' or 'pipx install mitmproxy'"
  echo "mitmdump: $(mitmdump --version | head -1)"

  local ca="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"
  if [[ ! -f "$ca" ]]; then
    echo "info: mitmproxy CA not yet generated. Run 'mitmdump' once briefly to mint it." >&2
    exit 1
  fi

  echo "ca: $ca"
  echo
  echo "Verify trust:"
  echo "  macOS:  security verify-cert -c $ca || (you must add it to login.keychain-db)"
  echo "  Linux:  sudo cp $ca /usr/local/share/ca-certificates/mitmproxy-ca.crt && sudo update-ca-certificates"
  echo "  rustls clients (codex CLI is rustls): also export"
  echo "    SSL_CERT_FILE=$ca"
  echo "  before running codex behind the proxy."
}

cmd_preflight() {
  local profile="${OMUX_CAPTURE_PROFILE:-codex-max}"
  local capability="${OMUX_CAPTURE_CAPABILITY:-codex-max}"
  local require_fallback="${OMUX_CAPTURE_REQUIRE_FALLBACK:-1}"
  local report_dir="${OMUX_CAPTURE_PREFLIGHT_DIR:-$RUN_DIR}"

  require_cmd python3 "install python3"
  require_cmd oauth-mux "install oauth-mux or put the intended binary on PATH"
  require_cmd codex "install Codex CLI or put the intended binary on PATH"

  mkdir -p "$report_dir"

  local version_json="$report_dir/oauth-mux-version.json"
  local preflight_json="$report_dir/codex-preflight.json"
  local status_json="$report_dir/codex-status-latest.json"
  local codex_version_txt="$report_dir/codex-version.txt"
  local commands_txt="$report_dir/commands.txt"
  local processes_txt="$report_dir/processes.txt"
  local summary_json="$report_dir/capture-preflight-summary.json"

  {
    echo "oauth-mux:"
    type -a oauth-mux 2>/dev/null || command -v oauth-mux || true
    echo
    echo "codex:"
    type -a codex 2>/dev/null || command -v codex || true
    echo
    echo "mitmdump:"
    command -v mitmdump 2>/dev/null || true
  } >"$commands_txt"

  oauth-mux version --json >"$version_json"
  codex --version >"$codex_version_txt" 2>&1 || true
  oauth-mux codex preflight --profile "$profile" --capability "$capability" --json >"$preflight_json" || true
  oauth-mux codex status-latest --json >"$status_json" 2>/dev/null || printf '{}\n' >"$status_json"
  ps -o pid,ppid,stat,lstart,etime,command -ax 2>/dev/null | grep -E 'oauth-mux codex|oauth-mux|codex' >"$processes_txt" || true

  if command -v mitmdump >/dev/null 2>&1; then
    mitmdump --version >"$report_dir/mitmdump-version.txt" 2>&1 || true
  fi

  python3 - "$version_json" "$preflight_json" "$status_json" "$commands_txt" "$processes_txt" "$summary_json" "$profile" "$capability" "$require_fallback" <<'PY'
import json
import pathlib
import sys

version_path, preflight_path, status_path, commands_path, processes_path, out_path, profile, capability, require_fallback = sys.argv[1:]


def load_json(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except Exception:
        return {}


version = load_json(version_path)
preflight = load_json(preflight_path)
status = load_json(status_path)
commands = pathlib.Path(commands_path).read_text(errors="replace")
processes = pathlib.Path(processes_path).read_text(errors="replace")

route_summary = preflight.get("route_summary") or {}
selected = preflight.get("selected")
runtime_identity = version.get("runtime_identity") or {}
mitmdump_available = bool([line for line in commands.splitlines() if line.strip().endswith("mitmdump") or "/mitmdump" in line])
stale_mux_process_hints = [
    line for line in processes.splitlines()
    if "oauth-mux" in line and ("0.1.9" in line or ".reinstall" in line)
]

issues = []
if not preflight.get("ok"):
    issues.append("codex preflight is not ok")
if not route_summary.get("session_start_ready"):
    issues.append("session_start_ready is false")
if require_fallback != "0" and not route_summary.get("fallback_ready"):
    issues.append("fallback_ready is false")
if route_summary.get("single_route_at_risk"):
    issues.append("single_route_at_risk is true")
if not mitmdump_available:
    issues.append("mitmdump is not installed or not on PATH")
if stale_mux_process_hints:
    issues.append("stale oauth-mux process hints found")

summary = {
    "ok": not issues,
    "profile": profile,
    "capability": capability,
    "issues": issues,
    "oauth_mux": {
        "version": version.get("version"),
        "binary_path": runtime_identity.get("binary_path"),
        "binary_source": runtime_identity.get("binary_source"),
        "build_id": runtime_identity.get("build_id"),
        "binary_sha256": runtime_identity.get("binary_sha256"),
    },
    "codex_version_file": pathlib.Path(status_path).with_name("codex-version.txt").name,
    "mitmdump_available": mitmdump_available,
    "selected": selected,
    "route_summary": route_summary,
    "blocked_route_reasons": preflight.get("blocked_route_reasons") or [],
    "status_verdict": status.get("verdict"),
    "status_path": status.get("path"),
    "stale_mux_process_hints": stale_mux_process_hints,
    "report_files": {
        "oauth_mux_version": pathlib.Path(version_path).name,
        "codex_preflight": pathlib.Path(preflight_path).name,
        "codex_status_latest": pathlib.Path(status_path).name,
        "commands": pathlib.Path(commands_path).name,
        "processes": pathlib.Path(processes_path).name,
    },
}

pathlib.Path(out_path).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

print(f"capture preflight report: {out_path}")
print(f"ok: {str(summary['ok']).lower()}")
print(f"oauth-mux: {summary['oauth_mux'].get('version')} {summary['oauth_mux'].get('build_id')} {summary['oauth_mux'].get('binary_source')}")
print(f"selected: {selected}")
print(f"route_summary: {json.dumps(route_summary, sort_keys=True)}")
if issues:
    print("issues:")
    for issue in issues:
        print(f"  - {issue}")

sys.exit(0 if summary["ok"] else 1)
PY
}

cmd_proxy() {
  require_cmd mitmdump "install mitmproxy via 'brew install mitmproxy'"
  mkdir -p "$RUN_DIR/http"
  local addon="$ROOT/scripts/codex-wire-addon.py"
  if [[ ! -f "$addon" ]]; then
    echo "error: missing $addon" >&2
    exit 65
  fi
  cat >"$RUN_DIR/meta.json" <<META
{
  "ts_utc": "$TS",
  "kind": "phase_0_wire_capture",
  "addon": "scripts/codex-wire-addon.py",
  "host_filter": "chatgpt.com",
  "ports": { "http": 9080, "https": 9080 }
}
META
  echo "capture run dir: $RUN_DIR"
  echo "proxy listening on 127.0.0.1:9080 (combined HTTP+HTTPS)"
  echo "stop with ^C"
  exec mitmdump \
    --listen-host 127.0.0.1 \
    --listen-port 9080 \
    --set "confdir=$HOME/.mitmproxy" \
    --set "capture_run_dir=$RUN_DIR" \
    -s "$addon" \
    -w "$RUN_DIR/http/flows.binary"
}

cmd_review() {
  local dir="${1:-}"
  if [[ -z "$dir" ]]; then
    echo "error: review requires a capture directory" >&2
    exit 64
  fi
  shift || true
  require_cmd python3 "install python3"
  exec python3 "$ROOT/scripts/review-codex-wire-capture.py" "$dir" "$@"
}

case "$cmd" in
  help|-h|--help) usage ;;
  init)           cmd_init ;;
  preflight)      cmd_preflight ;;
  proxy)          cmd_proxy ;;
  review)         shift; cmd_review "$@" ;;
  *)              usage; exit 64 ;;
esac
