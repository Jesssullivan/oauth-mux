#!/usr/bin/env sh
# Guard the private GloriousFlywheel checkout authority used by remote proof lanes.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="$ROOT/.github/actions/checkout-gloriousflywheel/action.yml"
CI="$ROOT/.github/workflows/ci.yml"
REMOTE="$ROOT/.github/workflows/remote-validate.yml"
RELEASE="$ROOT/.github/workflows/release-proof.yml"

fail() {
  echo "smoke-gf-checkout-auth-contract: $*" >&2
  exit 1
}

for file in "$ACTION" "$CI" "$REMOTE" "$RELEASE"; do
  [ -f "$file" ] || fail "missing ${file#"$ROOT"/}"
done

grep -F 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3' "$ACTION" >/dev/null ||
  fail "checkout action must pin the audited v3 GitHub App token action"
grep -F 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4' "$ACTION" >/dev/null ||
  fail "private checkout must pin the audited v4 checkout action"
grep -F 'owner: tinyland-inc' "$ACTION" >/dev/null ||
  fail "checkout token must be restricted to the tinyland-inc owner"
grep -F 'repositories: GloriousFlywheel' "$ACTION" >/dev/null ||
  fail "checkout token must be restricted to GloriousFlywheel"
grep -F 'permission-contents: read' "$ACTION" >/dev/null ||
  fail "checkout token must request contents read only"
grep -F 'persist-credentials: false' "$ACTION" >/dev/null ||
  fail "private checkout credentials must not persist"
grep -F 'token: ${{ steps.token.outputs.token }}' "$ACTION" >/dev/null ||
  fail "private checkout must consume only the minted installation token"
if grep -F 'skip-token-revoke:' "$ACTION" >/dev/null; then
  fail "scoped installation tokens must retain automatic post-job revocation"
fi
[ "$(grep -Fc 'permission-' "$ACTION")" -eq 1 ] ||
  fail "checkout action must request only the contents permission"
[ "$(grep -Fc 'owner: tinyland-inc' "$ACTION")" -eq 1 ] ||
  fail "checkout action must declare exactly one token owner"
[ "$(grep -Fc 'repositories: GloriousFlywheel' "$ACTION")" -eq 1 ] ||
  fail "checkout action must declare exactly one token repository"

for workflow in "$CI" "$REMOTE" "$RELEASE"; do
  grep -F 'uses: ./.github/actions/checkout-gloriousflywheel' "$workflow" >/dev/null ||
    fail "${workflow#"$ROOT"/} must use the scoped checkout action"
  grep -F 'app-id: ${{ secrets.GF_ACTIONS_APP_ID }}' "$workflow" >/dev/null ||
    fail "${workflow#"$ROOT"/} must use the App id secret"
  grep -F 'private-key: ${{ secrets.GF_ACTIONS_APP_PRIVATE_KEY }}' "$workflow" >/dev/null ||
    fail "${workflow#"$ROOT"/} must use the App private-key secret"
  if grep -F 'GF_ACTIONS_TOKEN' "$workflow" >/dev/null; then
    fail "${workflow#"$ROOT"/} must not fall back to the retired static checkout token"
  fi
done

[ "$(grep -Fc 'uses: ./.github/actions/checkout-gloriousflywheel' "$CI")" -eq 4 ] ||
  fail "CI must route all four proof jobs through the scoped checkout action"
[ "$(grep -Fc "if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository" "$CI")" -eq 4 ] ||
  fail "every self-hosted CI job must reject fork pull requests"
grep -A1 '^permissions:' "$CI" | grep -F 'contents: read' >/dev/null ||
  fail "CI must declare read-only GITHUB_TOKEN permissions"
[ "$(grep -Fc 'uses: ./.github/actions/checkout-gloriousflywheel' "$REMOTE")" -eq 1 ] ||
  fail "remote validation must use exactly one scoped checkout action"
grep -A2 'uses: actions/checkout@v4' "$REMOTE" | grep -F 'fetch-depth: 0' >/dev/null ||
  fail "remote validation must fetch full history for baseline characterization"
[ "$(grep -Fc 'uses: ./.github/actions/checkout-gloriousflywheel' "$RELEASE")" -eq 1 ] ||
  fail "release proof must use exactly one scoped checkout action"

echo "smoke-gf-checkout-auth-contract: ok"
