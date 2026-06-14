#!/usr/bin/env bash
# Bounded Zig action used by Bazel candidate labels.

set -euo pipefail

mode="${1:-}"
marker="${2:-}"

if [[ -n "${TEST_SRCDIR:-}" && -n "${TEST_WORKSPACE:-}" && -d "${TEST_SRCDIR}/${TEST_WORKSPACE}" ]]; then
  cd "${TEST_SRCDIR}/${TEST_WORKSPACE}"
fi

case "${mode}" in
build | test) ;;
*)
  echo "usage: zig-build-action.sh build [marker] | test" >&2
  exit 2
  ;;
esac

if [[ -n "${TEST_TMPDIR:-}" ]]; then
  scratch="${TEST_TMPDIR}"
else
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mux-bazel-zig.XXXXXX")"
  trap 'rm -rf "${scratch}"' EXIT HUP INT TERM
fi
mkdir -p "${scratch}/home" "${scratch}/xdg-cache" "${scratch}/xdg-config" \
  "${scratch}/zig-global-cache" "${scratch}/zig-local-cache" "${scratch}/zig-prefix"

export HOME="${scratch}/home"
export XDG_CACHE_HOME="${scratch}/xdg-cache"
export XDG_CONFIG_HOME="${scratch}/xdg-config"
export ZIG_GLOBAL_CACHE_DIR="${scratch}/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="${scratch}/zig-local-cache"

zig_bin="${ZIG_BIN:-zig}"

case "${mode}" in
build)
  "${zig_bin}" build --prefix "${scratch}/zig-prefix"
  ;;
test)
  "${zig_bin}" build test
  ;;
esac

if [[ -n "${marker}" ]]; then
  printf 'ok\n' >"${marker}"
fi
