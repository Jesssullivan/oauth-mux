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

if [[ -s "$NDJSON" ]]; then
    jq -e 'select(.kind == "session_started") | .runtime_identity.binary_sha256' "$NDJSON" >/dev/null
    jq -e 'select(.kind == "session_started") | select(.session_authority == "canonical_bridge")' "$NDJSON" >/dev/null
    jq -e 'select(.kind == "session_ended") | select(.exit_code == 0)' "$NDJSON" >/dev/null
fi

echo "live-codex-mux-e2e: PASS"
