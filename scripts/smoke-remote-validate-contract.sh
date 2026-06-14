#!/usr/bin/env sh
# Textual guard for the remote validation dispatch contract.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/remote-validate.sh"
WORKFLOW="$ROOT/.github/workflows/remote-validate.yml"

fail() {
  echo "smoke-remote-validate-contract: $*" >&2
  exit 1
}

bash -n "$SCRIPT"

grep -F 'request_id:' "$WORKFLOW" >/dev/null ||
  fail "remote-validate workflow must expose a request_id input"
grep -F 'inputs.request_id' "$WORKFLOW" >/dev/null ||
  fail "remote-validate run-name must include inputs.request_id"
grep -F 'OMUX_REMOTE_REQUEST_ID' "$WORKFLOW" >/dev/null ||
  fail "remote-validate workflow must pass request id into the job environment"

grep -F 'request_id=' "$SCRIPT" >/dev/null ||
  fail "remote-validate script must generate or accept a request_id"
grep -F -- '-f "request_id=$request_id"' "$SCRIPT" >/dev/null ||
  fail "remote-validate script must dispatch request_id to the workflow"
grep -F 'contains(\"${request_id}\")' "$SCRIPT" >/dev/null ||
  fail "remote-validate script must discover runs by request id"

if grep -F 'locating latest workflow_dispatch run' "$SCRIPT" >/dev/null; then
  fail "remote-validate script must not discover the latest workflow_dispatch run"
fi

echo "smoke-remote-validate-contract: ok"
