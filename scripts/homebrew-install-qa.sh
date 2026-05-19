#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

version="${1:-}"
if [ -z "$version" ] || [ "$version" = "--help" ] || [ "$version" = "-h" ]; then
  cat <<'EOF'
Usage: scripts/homebrew-install-qa.sh <version>

Installs oauth-mux from the configured Homebrew tap, runs brew audit/test,
verifies the installed binary version, and proves the formula does not shadow
native Codex with an oauth-mux shim.

Environment:
  OMUX_HOMEBREW_TAP_NAME       Homebrew tap name. Default: jesssullivan/omux
  OMUX_HOMEBREW_TAP_GIT_URL    Tap git URL. Default: https://github.com/Jesssullivan/homebrew-omux.git
  OMUX_BREW_BIN                brew executable. Default: brew
  OMUX_HOMEBREW_KEEP_INSTALLED Keep oauth-mux installed after QA. Default: preserve prior state
  OMUX_HOMEBREW_KEEP_TAP       Keep tap after QA. Default: preserve prior state
  OMUX_HOMEBREW_CODEX_CANARY   Run oauth-mux codex canary from installed binary. Default: 0
  OMUX_HOMEBREW_CODEX_LIVE     Add --live to the Codex canary. Requires OMUX_LIVE_QA_CONFIRM=spend-real-calls.
EOF
  exit 0
fi

brew_cmd="${OMUX_BREW_BIN:-brew}"
tap_name="${OMUX_HOMEBREW_TAP_NAME:-jesssullivan/omux}"
tap_url="${OMUX_HOMEBREW_TAP_GIT_URL:-https://github.com/Jesssullivan/homebrew-omux.git}"
formula="${tap_name}/oauth-mux"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_command "$brew_cmd"

resolve_command() {
  command -v "$1" 2>/dev/null || true
}

codex_before="$(resolve_command codex)"

was_tapped=0
if "$brew_cmd" tap | grep -Fxq "$tap_name"; then
  was_tapped=1
fi

was_installed=0
if [ -n "$("$brew_cmd" list --versions "$formula" 2>/dev/null)" ]; then
  was_installed=1
fi

keep_installed="${OMUX_HOMEBREW_KEEP_INSTALLED:-$was_installed}"
keep_tap="${OMUX_HOMEBREW_KEEP_TAP:-$was_tapped}"

cleanup() {
  if [ "$keep_installed" != "1" ] && [ "$was_installed" != "1" ]; then
    "$brew_cmd" uninstall "$formula" >/dev/null 2>&1 || true
  fi
  if [ "$keep_tap" != "1" ] && [ "$was_tapped" != "1" ]; then
    "$brew_cmd" untap "$tap_name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

export HOMEBREW_NO_AUTO_UPDATE="${HOMEBREW_NO_AUTO_UPDATE:-1}"

if [ "$was_tapped" != "1" ]; then
  "$brew_cmd" tap "$tap_name" "$tap_url"
fi

"$brew_cmd" audit --formula --strict "$formula"
"$repo_root/scripts/homebrew-version-check.sh" "$version" "$formula"

if [ "$was_installed" = "1" ]; then
  "$brew_cmd" reinstall "$formula"
else
  "$brew_cmd" install "$formula"
fi

"$brew_cmd" test "$formula"

prefix="$("$brew_cmd" --prefix "$formula")"
bin="$prefix/bin/oauth-mux"
if [ ! -x "$bin" ]; then
  printf 'installed binary not executable: %s\n' "$bin" >&2
  exit 1
fi

actual="$("$bin" version)"
expected="oauth-mux $version"
if [ "$actual" != "$expected" ]; then
  printf 'unexpected oauth-mux version: got %s, expected %s\n' "$actual" "$expected" >&2
  exit 1
fi

"$bin" doctor --json >/dev/null

if [ -e "$prefix/bin/codex" ]; then
  printf 'Homebrew oauth-mux formula must not install a formula-local codex shim: %s\n' "$prefix/bin/codex" >&2
  exit 1
fi

brew_prefix="$("$brew_cmd" --prefix)"
homebrew_codex="$brew_prefix/bin/codex"
if [ -e "$homebrew_codex" ] && grep -q 'OMUX_CODEX_SHIM' "$homebrew_codex" 2>/dev/null; then
  printf 'Homebrew oauth-mux formula must not link OMUX_CODEX_SHIM into PATH: %s\n' "$homebrew_codex" >&2
  exit 1
fi

codex_after="$(resolve_command codex)"
if [ "$codex_before" != "$codex_after" ]; then
  printf 'Homebrew oauth-mux install changed codex resolution: before=%s after=%s\n' "${codex_before:-<not found>}" "${codex_after:-<not found>}" >&2
  exit 1
fi

if [ "${OMUX_HOMEBREW_CODEX_CANARY:-0}" = "1" ]; then
  canary_args=(codex canary)
  if [ "${OMUX_HOMEBREW_CODEX_LIVE:-0}" = "1" ]; then
    if [ "${OMUX_LIVE_QA_CONFIRM:-}" != "spend-real-calls" ]; then
      printf 'live Codex canary requires OMUX_LIVE_QA_CONFIRM=spend-real-calls\n' >&2
      exit 2
    fi
    canary_args+=(--live)
  fi
  "$bin" "${canary_args[@]}"
fi

printf 'Homebrew install QA passed for oauth-mux %s via %s\n' "$version" "$formula"
