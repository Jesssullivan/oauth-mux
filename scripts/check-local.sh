#!/usr/bin/env sh
# Canonical local validation chain used by `just check-local`.

set -eu

zig build test
zig build
./zig-out/bin/oauth-mux version --json | jq -e '.version and .runtime_identity.binary_path and .runtime_identity.binary_sha256 and .runtime_identity.path_printed == true' >/dev/null
bash -n ./scripts/install-local-dogfood.sh
bash -n ./scripts/uninstall-local-dogfood.sh
bash -n ./scripts/release-local.sh
bash -n ./scripts/release-smoke.sh
bash -n ./scripts/release-handoff.sh
bash -n ./scripts/remote-validate.sh
sh -n ./scripts/check-retired-npm.sh
sh -n ./scripts/smoke-retired-npm-boundary.sh
sh -n ./scripts/endpoint-free-check.sh
sh -n ./scripts/secrets-scan-dir.sh
python3 -m py_compile ./scripts/dogfood-process-snapshot.py
python3 -m py_compile ./scripts/test-refresh-exactly-once.py
sh -n ./dist/codex-shim.sh
sh -n ./dist/install.sh

./scripts/endpoint-free-check.sh
./scripts/secrets-scan-dir.sh
./scripts/smoke-retired-npm-boundary.sh

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
