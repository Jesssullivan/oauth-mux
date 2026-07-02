#!/usr/bin/env sh
# Textual guard for the bounded Bazel/GloriousFlywheel REAPI candidate.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WRAPPER="$ROOT/scripts/gloriousflywheel-bazel.sh"
ACTION="$ROOT/scripts/bazel/zig-build-action.sh"
DISPATCH="$ROOT/scripts/dispatch-zig-reapi-proof.sh"
VERIFY="$ROOT/scripts/verify-zig-reapi-proof.sh"
BAZELRC="$ROOT/.bazelrc"
FLYWHEEL_RC="$ROOT/.bazelrc.flywheel"
BUILD_FILE="$ROOT/BUILD.bazel"
MODULE_FILE="$ROOT/MODULE.bazel"
BAZELIGNORE="$ROOT/.bazelignore"
JUSTFILE="$ROOT/justfile"

fail() {
  echo "smoke-bazel-remote-contract: $*" >&2
  exit 1
}

bash -n "$WRAPPER"
bash -n "$ACTION"
bash -n "$DISPATCH"
bash -n "$VERIFY"

for rc in "$BAZELRC" "$FLYWHEEL_RC"; do
  [ -f "$rc" ] || fail "missing $(basename "$rc")"
  if grep -E -- '--remote_(cache|executor)=(grpc|grpcs|http|https)://' "$rc" >/dev/null; then
    fail "$(basename "$rc") must not contain concrete remote endpoints"
  fi
  if grep -E 'attic-cache-dev|fuzzy-dev|attic\.dev-cluster|attic\.tinyland' "$rc" >/dev/null; then
    fail "$(basename "$rc") must not contain stale GloriousFlywheel endpoints"
  fi
done

grep -F -- '--enable_bzlmod' "$BAZELRC" >/dev/null ||
  fail "Bzlmod-only posture requires --enable_bzlmod in .bazelrc"
grep -F -- '--noenable_workspace' "$BAZELRC" >/dev/null ||
  fail "Bzlmod-only posture requires --noenable_workspace in .bazelrc"
if [ -e "$ROOT/WORKSPACE.bazel" ] || [ -e "$ROOT/WORKSPACE" ]; then
  fail "WORKSPACE must not exist; MODULE.bazel is the sole module authority"
fi
[ -f "$MODULE_FILE" ] || fail "missing MODULE.bazel"
if grep -F 'bazel_dep' "$MODULE_FILE" >/dev/null; then
  fail "dependency-free candidate graph must not declare checked-in bazel_dep entries"
fi
grep -F 'build:ci-cached --config=flywheel-executor' "$BAZELRC" >/dev/null ||
  fail "GF proof workflow invokes --config=ci-cached; it must map to the candidate executor config"

grep -F 'BAZEL_REMOTE_CACHE' "$WRAPPER" >/dev/null ||
  fail "wrapper must read BAZEL_REMOTE_CACHE"
grep -F 'BAZEL_REMOTE_EXECUTOR' "$WRAPPER" >/dev/null ||
  fail "wrapper must read BAZEL_REMOTE_EXECUTOR"
grep -F 'BAZEL_CREDENTIAL_HELPER' "$WRAPPER" >/dev/null ||
  fail "wrapper must pass credential helpers from env"
grep -F 'BAZEL_REMOTE_HEADER' "$WRAPPER" >/dev/null ||
  fail "wrapper must pass common remote headers from env"
grep -F 'BAZEL_REMOTE_CACHE_HEADER' "$WRAPPER" >/dev/null ||
  fail "wrapper must pass cache-specific remote headers from env"
grep -F 'BAZEL_REMOTE_EXEC_HEADER' "$WRAPPER" >/dev/null ||
  fail "wrapper must pass executor-specific remote headers from env"
grep -F -- '--remote_local_fallback=false' "$WRAPPER" >/dev/null ||
  fail "executor-backed wrapper must disable local fallback"
grep -F -- '--spawn_strategy=remote' "$WRAPPER" >/dev/null ||
  fail "executor-backed wrapper must force remote spawn strategy"
grep -F -- '--remote_accept_cached=false' "$WRAPPER" >/dev/null ||
  fail "wrapper must expose a forced-execution proof mode"

grep -F 'gh workflow run gf-reapi-cell-proof.yml' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must delegate to GF REAPI Cell Proof"
grep -F 'workspace_path=consumer-workspace' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must use the GF consumer workspace checkout"
grep -F 'consumer_repository=${consumer_repository}' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must pass consumer repository"
grep -F 'force_execution=${force_execution}' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must pass forced execution"
grep -F 'apply=${apply}' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must pass apply/skip-apply explicitly"
grep -F 'does not itself' "$DISPATCH" >/dev/null ||
  fail "Zig proof dispatcher must not claim proof authority"

grep -F 'download-gf-reapi-proof-artifact.sh' "$VERIFY" >/dev/null ||
  fail "Zig proof verifier must delegate artifact validation to GF"
grep -F -- '--require-force-execution' "$VERIFY" >/dev/null ||
  fail "Zig proof verifier must require countable forced execution"
grep -F 'GF_REAPI_TOOLS_DIR' "$VERIFY" >/dev/null ||
  fail "Zig proof verifier must allow an explicit GF tools checkout"

grep -F 'name = "zig_build"' "$BUILD_FILE" >/dev/null ||
  fail "BUILD.bazel must define //:zig_build"
grep -F 'name = "zig_build_test"' "$BUILD_FILE" >/dev/null ||
  fail "BUILD.bazel must define //:zig_build_test"
grep -F 'gloriousflywheel-rbe-candidate' "$BUILD_FILE" >/dev/null ||
  fail "candidate labels must carry the candidate tag"
if grep -F 'flywheel-eligible' "$BUILD_FILE" >/dev/null; then
  fail "candidate labels must not claim flywheel eligibility before proof"
fi

grep -F 'flywheel-zig-proof-dispatch' "$JUSTFILE" >/dev/null ||
  fail "Justfile must expose the Zig REAPI proof dispatcher"
grep -F 'flywheel-zig-proof-verify' "$JUSTFILE" >/dev/null ||
  fail "Justfile must expose the Zig REAPI proof verifier"

grep -F 'ZIG_GLOBAL_CACHE_DIR' "$ACTION" >/dev/null ||
  fail "zig action must isolate global Zig cache"
grep -F 'ZIG_LOCAL_CACHE_DIR' "$ACTION" >/dev/null ||
  fail "zig action must isolate local Zig cache"
grep -F 'XDG_CONFIG_HOME' "$ACTION" >/dev/null ||
  fail "zig action must isolate config home"

grep -Fx '.zig-cache' "$BAZELIGNORE" >/dev/null ||
  fail ".bazelignore must exclude Zig cache output"
grep -Fx 'zig-out' "$BAZELIGNORE" >/dev/null ||
  fail ".bazelignore must exclude Zig install output"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/omux-bazel-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
fake_bazel="$tmp_dir/bazelisk"
cat >"$fake_bazel" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$@"
EOF
chmod +x "$fake_bazel"

wrapper_plan="$(
  BAZEL_BIN="$fake_bazel" \
  BAZEL_REMOTE_CACHE=grpc://cache.example \
  BAZEL_REMOTE_EXECUTOR=grpc://executor.example \
  GF_BAZEL_SUBSTRATE_MODE=executor-backed \
  GF_BAZEL_FORCE_EXECUTION=true \
  BAZEL_CREDENTIAL_HELPER=/bin/true \
  BAZEL_REMOTE_HEADER='x-common=true' \
  BAZEL_REMOTE_CACHE_HEADER='x-cache=true' \
  BAZEL_REMOTE_EXEC_HEADER='x-exec=true' \
  "$WRAPPER" test //:zig_build_test
)"
printf '%s\n' "$wrapper_plan" | grep -Fx 'build' >/dev/null ||
  fail "wrapper test verb must execute a Bazel build action"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--config=flywheel-executor' >/dev/null ||
  fail "executor-backed wrapper must select flywheel-executor config"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--remote_accept_cached=false' >/dev/null ||
  fail "forced proof mode must bypass remote cache hits"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--remote_local_fallback=false' >/dev/null ||
  fail "executor-backed dry run must disable local fallback"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--remote_header=x-common=true' >/dev/null ||
  fail "wrapper dry run must pass common remote header"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--remote_cache_header=x-cache=true' >/dev/null ||
  fail "wrapper dry run must pass cache remote header"
printf '%s\n' "$wrapper_plan" | grep -Fx -- '--remote_exec_header=x-exec=true' >/dev/null ||
  fail "wrapper dry run must pass executor remote header"

if BAZEL_BIN="$fake_bazel" \
  BAZEL_REMOTE_CACHE=grpc://attic-cache-dev.example \
  GF_BAZEL_SUBSTRATE_MODE=shared-cache-backed \
  "$WRAPPER" info >/dev/null 2>&1; then
  fail "wrapper must reject stale GloriousFlywheel endpoints"
fi

digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
dispatch_plan="$(
  GF_REAPI_CONSUMER_REF=test-branch \
  "$DISPATCH" --image-digest "$digest" --request-id tin2105-static --dry-run
)"
printf '%s\n' "$dispatch_plan" | grep -F 'gh workflow run gf-reapi-cell-proof.yml' >/dev/null ||
  fail "dispatch dry run must call GF proof workflow"
printf '%s\n' "$dispatch_plan" | grep -F -- '--repo tinyland-inc/GloriousFlywheel' >/dev/null ||
  fail "dispatch dry run must target the GF workflow repo"
printf '%s\n' "$dispatch_plan" | grep -F 'request_id=tin2105-static' >/dev/null ||
  fail "dispatch dry run must pass request id"
printf '%s\n' "$dispatch_plan" | grep -F "image_digest=$digest" >/dev/null ||
  fail "dispatch dry run must pass image digest"
printf '%s\n' "$dispatch_plan" | grep -F 'target=//:zig_build_test' >/dev/null ||
  fail "dispatch dry run must pass the Zig candidate target"
printf '%s\n' "$dispatch_plan" | grep -F 'bazel_command=build' >/dev/null ||
  fail "dispatch dry run must use Bazel build for the genrule-backed test target"
printf '%s\n' "$dispatch_plan" | grep -F 'consumer_repository=Jesssullivan/oauth-mux' >/dev/null ||
  fail "dispatch dry run must pass oauth-mux as consumer repository"
printf '%s\n' "$dispatch_plan" | grep -F 'consumer_ref=test-branch' >/dev/null ||
  fail "dispatch dry run must pass consumer ref"
printf '%s\n' "$dispatch_plan" | grep -F 'workspace_path=consumer-workspace' >/dev/null ||
  fail "dispatch dry run must pass consumer workspace path"
printf '%s\n' "$dispatch_plan" | grep -F 'apply=true' >/dev/null ||
  fail "dispatch dry run must apply the Linux proof endpoint by default"
printf '%s\n' "$dispatch_plan" | grep -F 'force_execution=true' >/dev/null ||
  fail "dispatch dry run must force execution by default"

if "$DISPATCH" --image-digest sha256:bad --dry-run >/dev/null 2>&1; then
  fail "dispatch must reject malformed image digests"
fi

fake_gf="$tmp_dir/gf"
mkdir -p "$fake_gf/scripts"
cat >"$fake_gf/scripts/download-gf-reapi-proof-artifact.sh" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$@"
EOF
chmod +x "$fake_gf/scripts/download-gf-reapi-proof-artifact.sh"
verify_plan="$(
  GF_REAPI_TOOLS_DIR="$fake_gf" \
  "$VERIFY" --run-id 123456 --image-digest "$digest"
)"
printf '%s\n' "$verify_plan" | grep -Fx -- '--repo' >/dev/null ||
  fail "verify dry fake must pass repo flag"
printf '%s\n' "$verify_plan" | grep -Fx 'tinyland-inc/GloriousFlywheel' >/dev/null ||
  fail "verify dry fake must pass GF workflow repo"
printf '%s\n' "$verify_plan" | grep -Fx -- '--target' >/dev/null ||
  fail "verify dry fake must pass target flag"
printf '%s\n' "$verify_plan" | grep -Fx '//:zig_build_test' >/dev/null ||
  fail "verify dry fake must require the Zig candidate target"
printf '%s\n' "$verify_plan" | grep -Fx -- '--require-force-execution' >/dev/null ||
  fail "verify dry fake must require forced execution"
printf '%s\n' "$verify_plan" | grep -Fx -- '--require-image-digest' >/dev/null ||
  fail "verify dry fake must pass image digest requirement when supplied"

echo "smoke-bazel-remote-contract: ok"
