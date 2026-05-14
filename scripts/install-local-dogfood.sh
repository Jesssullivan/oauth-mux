#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
install_codex_shim="${OMUX_DOGFOOD_INSTALL_CODEX_SHIM:-1}"
replace_existing_codex="${OMUX_DOGFOOD_REPLACE_CODEX:-0}"
binary_src="$repo_root/zig-out/bin/oauth-mux"
oauth_mux_target="$install_dir/oauth-mux"
codex_target="$install_dir/codex"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

real_path() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  else
    local dir base
    dir="$(dirname "$1")"
    base="$(basename "$1")"
    printf '%s/%s\n' "$(cd "$dir" 2>/dev/null && pwd -P)" "$base"
  fi
}

is_omux_codex_shim() {
  grep -q 'OMUX_CODEX_SHIM' "$1" 2>/dev/null
}

find_native_codex() {
  if [ -n "${OMUX_CODEX_BIN:-}" ]; then
    if [ -x "$OMUX_CODEX_BIN" ] && ! is_omux_codex_shim "$OMUX_CODEX_BIN"; then
      printf '%s\n' "$OMUX_CODEX_BIN"
      return 0
    fi
  fi

  local self_real candidate candidate_real
  self_real=""
  if [ -e "$codex_target" ]; then
    self_real="$(real_path "$codex_target")"
  fi

  IFS=: read -r -a path_entries <<<"${PATH:-}"
  for dir in "${path_entries[@]}"; do
    [ -n "$dir" ] || continue
    candidate="$dir/codex"
    [ -x "$candidate" ] || continue
    candidate_real="$(real_path "$candidate")"
    [ -z "$self_real" ] || [ "$candidate_real" != "$self_real" ] || continue
    if is_omux_codex_shim "$candidate"; then
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done

  return 1
}

write_codex_shim() {
  cat >"$codex_target" <<EOF
#!/bin/sh
# OMUX_CODEX_SHIM
set -eu

oauth_mux_bin="${oauth_mux_target}"

real_path() {
    if command -v realpath >/dev/null 2>&1; then
        realpath "\$1"
    else
        dir=\$(dirname "\$1")
        base=\$(basename "\$1")
        printf '%s/%s\n' "\$(cd "\$dir" 2>/dev/null && pwd -P)" "\$base"
    fi
}

is_omux_codex_shim() {
    grep -q 'OMUX_CODEX_SHIM' "\$1" 2>/dev/null
}

find_native_codex() {
    self=\$(real_path "\$0")
    old_ifs=\$IFS
    IFS=:
    for dir in \$PATH; do
        [ -n "\$dir" ] || continue
        candidate="\$dir/codex"
        [ -x "\$candidate" ] || continue
        candidate_real=\$(real_path "\$candidate")
        [ "\$candidate_real" != "\$self" ] || continue
        if is_omux_codex_shim "\$candidate"; then
            continue
        fi
        IFS=\$old_ifs
        printf '%s\n' "\$candidate"
        return 0
    done
    IFS=\$old_ifs
    return 1
}

native_codex="\${OMUX_CODEX_BIN:-}"
if [ -z "\$native_codex" ]; then
    native_codex=\$(find_native_codex || true)
fi
if [ -z "\$native_codex" ]; then
    echo "codex: native Codex CLI not found; set OMUX_CODEX_BIN to the upstream Codex executable" >&2
    exit 127
fi

should_pass_native() {
    case "\${1:-}" in
        --help|-h|help|--version|-V|version|login|logout|auth|mcp|completion|completions)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

if should_pass_native "\${1:-}"; then
    exec "\$native_codex" "\$@"
fi

OMUX_CODEX_BIN="\$native_codex" OMUX_CODEX_SHIM=1 OMUX_COMMAND_SPELLING=codex exec "\$oauth_mux_bin" codex "\$@"
EOF
  chmod 0755 "$codex_target"
}

if [ "${OMUX_DOGFOOD_SKIP_BUILD:-0}" != "1" ]; then
  zig build
fi

if [ ! -x "$binary_src" ]; then
  printf 'missing built oauth-mux binary at %s\n' "$binary_src" >&2
  exit 1
fi

mkdir -p "$install_dir"

native_codex=""
if [ "$install_codex_shim" != "0" ]; then
  native_codex="$(find_native_codex || true)"
  if [ -z "$native_codex" ]; then
    printf 'native Codex CLI not found before shim install; set OMUX_CODEX_BIN or run with OMUX_DOGFOOD_INSTALL_CODEX_SHIM=0\n' >&2
    exit 1
  fi
  if [ -e "$codex_target" ] && ! is_omux_codex_shim "$codex_target" && [ "$replace_existing_codex" != "1" ]; then
    printf 'refusing to replace non-oauth-mux codex at %s\n' "$codex_target" >&2
    printf 'set OMUX_DOGFOOD_REPLACE_CODEX=1 to replace it, or OMUX_DOGFOOD_INSTALL_CODEX_SHIM=0 to skip the shim\n' >&2
    exit 1
  fi
fi

rm -f "$oauth_mux_target"
cp "$binary_src" "$oauth_mux_target"
chmod 0755 "$oauth_mux_target"

src_hash="$(hash_file "$binary_src")"
installed_hash="$(hash_file "$oauth_mux_target")"
if [ "$src_hash" != "$installed_hash" ]; then
  printf 'installed binary hash mismatch\nsource:    %s  %s\ninstalled: %s  %s\n' "$src_hash" "$binary_src" "$installed_hash" "$oauth_mux_target" >&2
  exit 1
fi

if [ "$install_codex_shim" != "0" ]; then
  rm -f "$codex_target"
  write_codex_shim
fi

printf 'installed oauth-mux dogfood binary: %s\n' "$oauth_mux_target"
printf 'oauth-mux sha256: %s\n' "$installed_hash"
if [ "$install_codex_shim" != "0" ]; then
  printf 'installed managed codex shim: %s\n' "$codex_target"
  printf 'native Codex CLI resolved before install: %s\n' "$native_codex"
fi
printf 'PATH oauth-mux: %s\n' "$(command -v oauth-mux || true)"
printf 'PATH codex: %s\n' "$(command -v codex || true)"
