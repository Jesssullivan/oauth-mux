#!/usr/bin/env bash
# Public-source build contract: no Tinyland/GF credential or endpoint input.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

private_names=(
  ATTIC_TOKEN
  ATTIC_SERVER
  ATTIC_CACHE
  GF_ACTIONS_APP_ID
  GF_ACTIONS_APP_PRIVATE_KEY
  GF_ACTIONS_TOKEN
  GF_BAZEL_SUBSTRATE_MODE
  GF_BAZEL_REMOTE_UPLOAD
  BAZEL_REMOTE_CACHE
  BAZEL_REMOTE_EXECUTOR
)

for name in "${private_names[@]}"; do
  if [ -n "${!name:-}" ]; then
    printf 'public-source-check: private input is present: %s\n' "$name" >&2
    exit 1
  fi
done

case "${NIX_CONFIG:-}" in
  *tinyland* | *ATTIC* | *attic* | *ssh-ng://* | *ssh://*)
    printf '%s\n' 'public-source-check: NIX_CONFIG contains a private cache or builder input' >&2
    exit 1
    ;;
esac

command -v nix >/dev/null
command -v zig >/dev/null
command -v just >/dev/null
command -v actionlint >/dev/null
command -v git >/dev/null

actionlint -version
actionlint
git diff --check
./scripts/endpoint-free-check.sh
just check-local
zig build -Doptimize=ReleaseSafe
nix build .# --no-link

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  printf '%s\n' 'public-source-check: validation changed the source tree' >&2
  git status --short >&2
  exit 1
fi

printf '%s\n' 'public-source-check: clean Just/Nix source build passed without private inputs'
