#!/usr/bin/env sh
# Canonical local validation chain used by `just check-local`.

set -eu

bind_python_cache_custody() {
  PYTHON_CACHE_ROOT="${PYTHON_CACHE_ROOT:?descriptor-owned Python cache root is required}"
  case "$PYTHON_CACHE_ROOT" in
    /*) ;;
    *)
      printf 'check-local Python cache root is not absolute: %s\n' "$PYTHON_CACHE_ROOT" >&2
      exit 2
      ;;
  esac
  [ -d "$PYTHON_CACHE_ROOT" ] && [ ! -L "$PYTHON_CACHE_ROOT" ] || {
    printf 'check-local Python cache root lost directory custody: %s\n' "$PYTHON_CACHE_ROOT" >&2
    exit 2
  }

  PYTHONPYCACHEPREFIX="$PYTHON_CACHE_ROOT/bytecode"
  XDG_CACHE_HOME="$PYTHON_CACHE_ROOT/xdg-cache"
  PYTHON_CACHE_SENTINEL="$PYTHON_CACHE_ROOT/.omux-check-local-cache-root"
  export PYTHONPYCACHEPREFIX XDG_CACHE_HOME
  readonly PYTHON_CACHE_ROOT PYTHONPYCACHEPREFIX XDG_CACHE_HOME PYTHON_CACHE_SENTINEL

  mkdir -m 0700 "$PYTHONPYCACHEPREFIX" "$XDG_CACHE_HOME"
  printf 'omux-check-local-cache-v2\n' >"$PYTHON_CACHE_SENTINEL"
  chmod 0600 "$PYTHON_CACHE_SENTINEL"
}

bind_python_cache_custody

run_python() {
  python3 -I -B "$@"
}

check_python_source() {
  run_python -c \
    'from pathlib import Path; import sys; path = Path(sys.argv[1]); compile(path.read_bytes(), str(path), "exec")' \
    "$1"
}

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
bash -n ./scripts/v02-stage2-observation-local.sh
bash -n ./scripts/smoke-v02-stage2-observation.sh
bash -n ./scripts/v02-posix-install-contract-local.sh
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
sh -n ./scripts/keepalive-service.sh
sh -n ./scripts/smoke-keepalive-service-containment.sh
sh -n ./scripts/smoke-version-check-stale-path.sh
bash -n ./scripts/public-source-check.sh
sh -n ./scripts/smoke-public-source-workflow.sh
check_python_source ./scripts/validate-managed-harness-instance.py
check_python_source ./scripts/dogfood-process-snapshot.py
check_python_source ./scripts/test-refresh-exactly-once.py
check_python_source ./scripts/v02_posix_candidate.py
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
./scripts/smoke-keepalive-service-containment.sh
./scripts/smoke-version-check-stale-path.sh
./scripts/smoke-public-source-workflow.sh
./scripts/smoke-release-manifest-current.sh
./scripts/smoke-release-workflow-version-authority.sh
run_python -m unittest discover -s test -p 'test_v02_posix_candidate.py'
./scripts/v02-posix-install-contract-local.sh

for cfg in examples/*.config.json; do
  OMUX_CONFIG="$PWD/$cfg" ./zig-out/bin/oauth-mux config validate
done

./scripts/e2e-local.sh
./scripts/first-run-e2e.sh
./scripts/stay-afloat-wrapper-doc-smoke.sh
./scripts/smoke-trace.sh
./scripts/smoke-v02-stage2-observation.sh
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
