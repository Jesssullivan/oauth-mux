#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  cat >&2 <<'EOF'
Usage: scripts/homebrew-version-check.sh <expected-version> <formula-file-or-ref>

Checks either:
  - a rendered formula file contains an explicit Homebrew version line, or
  - a tapped formula reference reports the expected stable version via
    `brew info --json=v2`.
EOF
  exit 2
fi

expected="$1"
target="$2"

if [ -f "$target" ]; then
  if ! grep -Fqx "  version \"$expected\"" "$target"; then
    printf 'Homebrew formula %s does not contain expected explicit version "%s"\n' "$target" "$expected" >&2
    exit 1
  fi
  exit 0
fi

brew_cmd="${OMUX_BREW_BIN:-brew}"
if ! command -v "$brew_cmd" >/dev/null 2>&1; then
  printf 'required command not found for Homebrew version check: %s\n' "$brew_cmd" >&2
  exit 1
fi

info_json="$("$brew_cmd" info --json=v2 "$target")"
if command -v jq >/dev/null 2>&1; then
  actual="$(printf '%s\n' "$info_json" | jq -r '.formulae[0].versions.stable')"
else
  actual="$(printf '%s\n' "$info_json" | sed -n 's/.*"stable"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi

if [ "$actual" != "$expected" ]; then
  printf 'unexpected Homebrew stable version for %s: got %s, expected %s\n' "$target" "${actual:-<empty>}" "$expected" >&2
  exit 1
fi
