#!/usr/bin/env sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW="$ROOT/.github/workflows/public-source.yml"
SCRIPT="$ROOT/scripts/public-source-check.sh"
CHECK_LOCAL="$ROOT/scripts/check-local.sh"
JUSTFILE="$ROOT/justfile"

fail() {
  printf 'smoke-public-source-workflow: %s\n' "$*" >&2
  exit 1
}

[ -f "$WORKFLOW" ] || fail 'public source workflow is missing'
[ -x "$SCRIPT" ] || fail 'public source check is not executable'

grep -F 'runs-on: ubuntu-latest' "$WORKFLOW" >/dev/null || fail 'workflow must use a public hosted runner'
grep -F 'cachix/install-nix-action@v30' "$WORKFLOW" >/dev/null || fail 'workflow must install Nix from the existing public action'
grep -F 'nix develop --command just public-source-check-local' "$WORKFLOW" >/dev/null || fail 'workflow must use the checked Just/Nix entrypoint'
grep -F 'public-source-check-local:' "$JUSTFILE" >/dev/null || fail 'Just entrypoint is missing'
grep -F './scripts/public-source-check.sh' "$JUSTFILE" >/dev/null || fail 'Just entrypoint must call the checked script'

if grep -E '(tinyland-nix|checkout-gloriousflywheel|\.gloriousflywheel|secrets\.|ATTIC_|GF_ACTIONS_|BAZEL_REMOTE_)' "$WORKFLOW" >/dev/null; then
  fail 'workflow contains a private runner, checkout, secret, or endpoint input'
fi

for required in 'actionlint' 'git diff --check' 'git status --porcelain --untracked-files=all' 'just check-local' 'zig build -Doptimize=ReleaseSafe' 'nix build .# --no-link'; do
  grep -F "$required" "$SCRIPT" >/dev/null || fail "public source script is missing: $required"
done

grep -F 'GF_ACTIONS_TOKEN' "$SCRIPT" >/dev/null || fail 'retired static GF token must be rejected'
grep -F 'PYTHONPYCACHEPREFIX' "$CHECK_LOCAL" >/dev/null || fail 'local checks must keep Python bytecode outside the source tree'

printf '%s\n' 'public source workflow contract: ok'
