#!/usr/bin/env sh
# Canonical local validation chain used by `just check-local`.

set -eu

zig build test
zig build
./zig-out/bin/oauth-mux version --json | jq -e '.version and .runtime_identity.binary_path and .runtime_identity.binary_sha256 and .runtime_identity.path_printed == true' >/dev/null
bash -n ./scripts/install-local-dogfood.sh
bash -n ./scripts/uninstall-local-dogfood.sh
python3 -m py_compile ./scripts/dogfood-process-snapshot.py
sh -n ./dist/codex-shim.sh
sh -n ./dist/install.sh

for cfg in examples/*.config.json; do
  OMUX_CONFIG="$PWD/$cfg" ./zig-out/bin/oauth-mux config validate
done

./scripts/e2e-local.sh
./scripts/first-run-e2e.sh
./scripts/stay-afloat-wrapper-doc-smoke.sh
./scripts/smoke-trace.sh
./scripts/smoke-dogfood-process-snapshot.sh
./scripts/smoke-broker.sh
./scripts/smoke-broker-claude.sh
./scripts/smoke-codex-cli-ux.sh
./scripts/smoke-codex-acceptance.sh
./scripts/smoke-codex-concurrent-sessions.sh
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
