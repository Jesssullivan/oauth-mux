#!/usr/bin/env sh
# Canonical local validation chain used by `just check-local`.

set -eu

PYTHON_CACHE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-pycache.XXXXXX")
trap 'rm -rf "$PYTHON_CACHE_ROOT"' EXIT HUP INT TERM
export PYTHONPYCACHEPREFIX="$PYTHON_CACHE_ROOT"

zig build test
zig build
zig build check-managed-harness-schema
./zig-out/bin/oauth-mux version --json | jq -e '.version and .runtime_identity.binary_path and .runtime_identity.binary_sha256 and .runtime_identity.path_printed == true' >/dev/null
./scripts/test-executable-compat.sh
bash -n ./scripts/install-local-dogfood.sh
bash -n ./scripts/uninstall-local-dogfood.sh
bash -n ./scripts/release-local.sh
bash -n ./scripts/release-manifest-current.sh
bash -n ./scripts/release-smoke.sh
bash -n ./scripts/release-handoff.sh
bash -n ./scripts/smoke-release-manifest-current.sh
bash -n ./scripts/system-package-install-qa.sh
bash -n ./scripts/remote-validate.sh
sh -n ./scripts/resolve-release-version.sh
sh -n ./scripts/smoke-release-workflow-version-authority.sh
sh -n ./scripts/check-retired-npm.sh
sh -n ./scripts/smoke-retired-npm-boundary.sh
sh -n ./scripts/check-authority-drift.sh
sh -n ./scripts/smoke-gf-checkout-auth-contract.sh
sh -n ./scripts/endpoint-free-check.sh
sh -n ./scripts/secrets-scan-dir.sh
bash -n ./scripts/check-zig-test-root.sh
sh -n ./scripts/check-v0.1.15-characterization.sh
sh -n ./scripts/check-managed-harness-instances.sh
bash -n ./scripts/public-source-check.sh
sh -n ./scripts/smoke-public-source-workflow.sh
python3 -m py_compile ./scripts/validate-managed-harness-instance.py
python3 -m py_compile ./scripts/dogfood-process-snapshot.py
python3 -m py_compile ./scripts/test-refresh-exactly-once.py
sh -n ./dist/codex-shim.sh
sh -n ./dist/install.sh
sh -n ./scripts/test-executable-compat.sh

./scripts/endpoint-free-check.sh
./scripts/secrets-scan-dir.sh
./scripts/smoke-retired-npm-boundary.sh
./scripts/check-authority-drift.sh
./scripts/smoke-gf-checkout-auth-contract.sh
./scripts/check-zig-test-root.sh
./scripts/check-v0.1.15-characterization.sh
./scripts/check-managed-harness-instances.sh
./scripts/smoke-public-source-workflow.sh
./scripts/smoke-release-manifest-current.sh
./scripts/smoke-release-workflow-version-authority.sh

for cfg in examples/*.config.json; do
  OMUX_CONFIG="$PWD/$cfg" ./zig-out/bin/oauth-mux config validate
done

./scripts/e2e-local.sh
./scripts/first-run-e2e.sh
./scripts/stay-afloat-wrapper-doc-smoke.sh
./scripts/smoke-trace.sh
./scripts/smoke-remote-validate-contract.sh
./scripts/smoke-bazel-remote-contract.sh
./scripts/smoke-dogfood-process-snapshot.sh
./scripts/smoke-broker.sh
./scripts/smoke-broker-claude.sh
./scripts/smoke-codex-cli-ux.sh
./scripts/smoke-codex-acceptance.sh
./scripts/smoke-codex-concurrent-sessions.sh
./scripts/smoke-codex-refresh-exactly-once.sh
./scripts/smoke-codex-child-refresh.sh
./scripts/smoke-codex-tier-insufficient.sh
./scripts/smoke-codex-all-exhausted.sh
./scripts/smoke-codex-401-propagation.sh
./scripts/smoke-codex-provider-degraded.sh
./scripts/smoke-codex-cassette-replay.sh
./scripts/smoke-codex-cassette-all-exhausted.sh
./scripts/smoke-codex-capture-review.sh
./scripts/smoke-codex-status-summary.sh
./scripts/smoke-github-tracker-comment.sh
