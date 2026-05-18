#!/usr/bin/env bash
set -euo pipefail

install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
oauth_mux_target="$install_dir/oauth-mux"
codex_target="$install_dir/codex"

is_omux_codex_shim() {
  grep -q 'OMUX_CODEX_SHIM' "$1" 2>/dev/null
}

removed_any=0

if [ -e "$oauth_mux_target" ]; then
  rm -f "$oauth_mux_target"
  printf 'removed oauth-mux dogfood binary: %s\n' "$oauth_mux_target"
  removed_any=1
fi

if [ -e "$codex_target" ]; then
  if is_omux_codex_shim "$codex_target"; then
    rm -f "$codex_target"
    printf 'removed managed codex shim: %s\n' "$codex_target"
    removed_any=1
  else
    printf 'left non-oauth-mux codex untouched: %s\n' "$codex_target" >&2
  fi
fi

if [ "$removed_any" = "0" ]; then
  printf 'no oauth-mux dogfood files found in %s\n' "$install_dir"
fi

printf 'PATH oauth-mux: %s\n' "$(command -v oauth-mux || true)"
printf 'PATH codex: %s\n' "$(command -v codex || true)"
