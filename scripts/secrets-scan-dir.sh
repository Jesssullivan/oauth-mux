#!/usr/bin/env sh
# secrets-scan-dir — gitleaks over the working tree (directory scan, not git
# history), using the repo's .gitleaks.toml (house tinyland config shape).
#
# Once the ci-templates latch lands (tinyland.repo.json:
# contracts.secrets_scan), the spoke-ci secrets-scan action will run
# `gitleaks detect` (history) with this same config; today this recipe is
# the only armed gitleaks gate, catching a leak before it is committed.
#
# Tooling: gitleaks is provided by the nix devShell (flake.nix). If it is
# missing from PATH we re-exec under `nix develop`; if nix is also missing
# we fail closed with a clear message — a secrets gate must never
# silently pass because the scanner is absent.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v gitleaks >/dev/null 2>&1; then
  if [ -z "${OMUX_SECRETS_SCAN_NIX_REEXEC:-}" ] && command -v nix >/dev/null 2>&1; then
    echo "secrets-scan-dir: gitleaks not on PATH; re-executing under nix develop" >&2
    OMUX_SECRETS_SCAN_NIX_REEXEC=1 exec nix develop --command "$0" "$@"
  fi
  echo "secrets-scan-dir: FAIL — gitleaks is not installed and nix is unavailable." >&2
  echo "  install: enter the devShell (nix develop) or install gitleaks >= 8.19" >&2
  exit 1
fi

echo "secrets-scan-dir: gitleaks $(gitleaks version 2>/dev/null || true) scanning working tree at $ROOT"

exec gitleaks dir . \
  --config .gitleaks.toml \
  --redact \
  --verbose \
  --exit-code 1
