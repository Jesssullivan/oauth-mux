#!/usr/bin/env sh
# Textual guard for the bounded Bazel/GloriousFlywheel REAPI candidate.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WRAPPER="$ROOT/scripts/gloriousflywheel-bazel.sh"
ACTION="$ROOT/scripts/bazel/zig-build-action.sh"
BAZELRC="$ROOT/.bazelrc"
FLYWHEEL_RC="$ROOT/.bazelrc.flywheel"
BUILD_FILE="$ROOT/BUILD.bazel"
BAZELIGNORE="$ROOT/.bazelignore"

fail() {
  echo "smoke-bazel-remote-contract: $*" >&2
  exit 1
}

bash -n "$WRAPPER"
bash -n "$ACTION"

for rc in "$BAZELRC" "$FLYWHEEL_RC"; do
  [ -f "$rc" ] || fail "missing $(basename "$rc")"
  if grep -E -- '--remote_(cache|executor)=(grpc|grpcs|http|https)://' "$rc" >/dev/null; then
    fail "$(basename "$rc") must not contain concrete remote endpoints"
  fi
  if grep -E 'attic-cache-dev|fuzzy-dev|attic\.dev-cluster|attic\.tinyland' "$rc" >/dev/null; then
    fail "$(basename "$rc") must not contain stale GloriousFlywheel endpoints"
  fi
done

grep -F -- '--noenable_bzlmod' "$BAZELRC" >/dev/null ||
  fail "dependency-free candidate graph must not opt into checked-in Bzlmod deps"

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

grep -F 'name = "zig_build"' "$BUILD_FILE" >/dev/null ||
  fail "BUILD.bazel must define //:zig_build"
grep -F 'name = "zig_build_test"' "$BUILD_FILE" >/dev/null ||
  fail "BUILD.bazel must define //:zig_build_test"
grep -F 'gloriousflywheel-rbe-candidate' "$BUILD_FILE" >/dev/null ||
  fail "candidate labels must carry the candidate tag"
if grep -F 'flywheel-eligible' "$BUILD_FILE" >/dev/null; then
  fail "candidate labels must not claim flywheel eligibility before proof"
fi

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

echo "smoke-bazel-remote-contract: ok"
