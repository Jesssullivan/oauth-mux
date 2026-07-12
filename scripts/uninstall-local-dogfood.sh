#!/usr/bin/env bash
set -euo pipefail

install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
omux_target="$install_dir/omux"
oauth_mux_target="$install_dir/oauth-mux"
codex_target="$install_dir/codex"

is_omux_codex_shim() {
  grep -q 'OMUX_CODEX_SHIM' "$1" 2>/dev/null
}

removed_any=0

if [ -e "$oauth_mux_target" ] || [ -L "$oauth_mux_target" ]; then
  rm -f "$oauth_mux_target"
  printf 'removed oauth-mux compatibility entrypoint: %s\n' "$oauth_mux_target"
  removed_any=1
fi

if [ -e "$omux_target" ]; then
  rm -f "$omux_target"
  printf 'removed omux dogfood binary: %s\n' "$omux_target"
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
  printf 'no omux dogfood files found in %s\n' "$install_dir"
fi

printf 'PATH omux: %s\n' "$(command -v omux || true)"
printf 'PATH oauth-mux: %s\n' "$(command -v oauth-mux || true)"
printf 'PATH codex: %s\n' "$(command -v codex || true)"
