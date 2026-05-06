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
CAP_DIR="$ROOT/captures"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$CAP_DIR/codex-wire-$TS"

usage() {
  cat <<'__USAGE_END__'
capture-codex-wire.sh - Phase 0 evidence capture for the Codex adapter.

USAGE
  scripts/capture-codex-wire.sh init             # one-time mitmproxy CA install check
  scripts/capture-codex-wire.sh proxy            # start the HTTP capture proxy in foreground
  scripts/capture-codex-wire.sh review DIR       # summarize/redaction-check a capture
  scripts/capture-codex-wire.sh help

WORKFLOW
  1. Run `init` once. If your system trust store does not yet have the
     mitmproxy CA, follow the instructions it prints. macOS:
       security add-trusted-cert -d -r trustRoot \
         -k ~/Library/Keychains/login.keychain-db ~/.mitmproxy/mitmproxy-ca-cert.cer
  2. In one shell:
       scripts/capture-codex-wire.sh proxy
     The proxy listens on 127.0.0.1:9080 as a normal HTTP proxy.
  3. In another shell:
       export HTTPS_PROXY=http://127.0.0.1:9080
       export HTTP_PROXY=http://127.0.0.1:9080
       export NO_PROXY=
       codex
     Drive a normal turn, force a 401 (revoke a token externally), and
     drive an account to weekly quota exhaustion to capture the 429 +
     usage_limit_reached body.
  4. Stop the proxy with ^C. Find captures under captures/.
  5. Run:
       scripts/capture-codex-wire.sh review captures/codex-wire-<TS>
  6. Distill findings into docs/spec/codex-wire-evidence-2026-05-03.md.

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
  require_cmd python3 "install python3"
  exec python3 "$ROOT/scripts/review-codex-wire-capture.py" "$dir"
}

case "$cmd" in
  help|-h|--help) usage ;;
  init)           cmd_init ;;
  proxy)          cmd_proxy ;;
  review)         shift; cmd_review "${1:-}" ;;
  *)              usage; exit 64 ;;
esac
