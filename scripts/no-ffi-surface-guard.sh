#!/usr/bin/env bash
# Fail-closed proof for TIN-1798 acceptance item 5: "No C header, shared
# library, FFI ownership model, or raw credential response is shipped."
#
# The v0.2 harness adapter contract is explicitly a versioned JSON-RPC
# subprocess boundary, not a C ABI / shared-library SDK. This script proves
# that boundary stays true by scanning the tree for the concrete artifacts
# a C ABI or shared-library surface would leave behind, and fails closed if
# any appear. It does not build or link anything, so it is safe to run
# without zig/nfpm/bazel.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0

fail_with() {
  printf 'no-ffi-surface-guard: %s\n' "$1" >&2
  fail=1
}

# 1. No shipped C headers or shared/dynamic libraries anywhere in the
#    tracked tree (build outputs under zig-out/ and dist/out/ are untracked
#    and excluded on purpose; this guard is about what the repo *ships*,
#    not transient local build artifacts).
while IFS= read -r -d '' path; do
  fail_with "tracked C header or shared-library artifact found: $path"
done < <(git ls-files -z -- '*.h' '*.so' '*.so.*' '*.dylib' '*.dll' '*.a' '*.lib')

# 2. No Zig source exports a C-callconv symbol or builds a shared library.
if git ls-files -- 'src/*.zig' 'build.zig' | xargs grep -lE 'callconv\s*\(\s*\.c\s*\)|callconv\s*\(\s*\.C\s*\)|export\s+fn\b' 2>/dev/null | grep -v -E '^test/' ; then
  fail_with "a Zig source exports a C-callconv symbol (grep above); this is the concrete signature of a C ABI surface"
fi

if grep -nE '\baddSharedLibrary\b|\.linkage\s*=\s*\.dynamic\b' build.zig >/dev/null 2>&1; then
  fail_with "build.zig declares a shared/dynamic library target"
fi

# 3. No raw credential response type: the adapter contract's "opaque
#    session and route handles; no token bytes cross the adapter boundary"
#    clause means adapter-facing JSON-RPC types must not carry raw
#    access_token/refresh_token/id_token/api_key/secret fields. This is a
#    coarse lexical check on the checked-in adapter schema(s), not a
#    runtime proof; it exists to catch an obvious regression early.
schema_dir="schemas"
if [ -d "$schema_dir" ]; then
  while IFS= read -r -d '' schema; do
    if grep -nE '"(access_token|refresh_token|id_token|api_key|client_secret)"' "$schema" >/dev/null 2>&1; then
      fail_with "adapter schema $schema declares a raw credential field name; adapter responses must stay redacted/opaque"
    fi
  done < <(find "$schema_dir" -iname '*adapter*' -o -iname '*managed-harness*' -print0 2>/dev/null)
fi

if [ "$fail" -eq 0 ]; then
  printf 'no-ffi-surface-guard: passed (no C header, shared library, C-callconv export, or raw-credential adapter field found)\n'
fi

exit "$fail"
