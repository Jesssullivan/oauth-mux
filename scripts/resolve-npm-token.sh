#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: resolve-npm-token.sh --npmrc <path>

Resolves npm auth without printing token material. Resolution order:

  1. NPM_TOKEN
  2. NODE_AUTH_TOKEN
  3. NPM_TOKEN_FILE
  4. NODE_AUTH_TOKEN_FILE
  5. OMUX_NPM_TOKEN_SOPS_FILE + OMUX_NPM_TOKEN_SOPS_KEY

OMUX_NPM_TOKEN_SOPS_KEY is a jq expression. Default candidates are:
  .api.npm_token
  .api.npm
  .infrastructure.npm_token
  .npm.token
EOF
}

npmrc=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --npmrc)
      npmrc="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$npmrc" ]; then
  usage
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

trim_token() {
  tr -d '\r\n'
}

read_token_file() {
  local file="$1"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    return 1
  fi
  trim_token <"$file"
}

mask_token() {
  local token="$1"
  if [ "${GITHUB_ACTIONS:-}" = "true" ] && [ -n "$token" ]; then
    printf '::add-mask::%s\n' "$token"
  fi
}

extract_sops_token() {
  local file="${OMUX_NPM_TOKEN_SOPS_FILE:-}"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    return 1
  fi

  require_command sops
  require_command jq

  local decrypted
  decrypted="$(sops -d --output-type json "$file")"

  if [ -n "${OMUX_NPM_TOKEN_SOPS_KEY:-}" ]; then
    printf '%s' "$decrypted" | jq -er "${OMUX_NPM_TOKEN_SOPS_KEY}" | trim_token
    return
  fi

  local key
  for key in '.api.npm_token' '.api.npm' '.infrastructure.npm_token' '.npm.token'; do
    if token="$(printf '%s' "$decrypted" | jq -er "$key // empty" 2>/dev/null | trim_token)" && [ -n "$token" ]; then
      printf '%s' "$token"
      return
    fi
  done

  return 1
}

token="${NPM_TOKEN:-}"
if [ -z "$token" ]; then
  token="${NODE_AUTH_TOKEN:-}"
fi
if [ -z "$token" ]; then
  token="$(read_token_file "${NPM_TOKEN_FILE:-}" || true)"
fi
if [ -z "$token" ]; then
  token="$(read_token_file "${NODE_AUTH_TOKEN_FILE:-}" || true)"
fi
if [ -z "$token" ]; then
  token="$(extract_sops_token || true)"
fi

if [ -z "$token" ] || [ "$token" = "null" ]; then
  cat >&2 <<'EOF'
could not resolve npm token.

Set NPM_TOKEN, NODE_AUTH_TOKEN, NPM_TOKEN_FILE, NODE_AUTH_TOKEN_FILE, or
OMUX_NPM_TOKEN_SOPS_FILE plus optional OMUX_NPM_TOKEN_SOPS_KEY.
EOF
  exit 1
fi

mask_token "$token"
mkdir -p "$(dirname "$npmrc")"
{
  printf 'registry=https://registry.npmjs.org/\n'
  printf '//registry.npmjs.org/:_authToken=%s\n' "$token"
} >"$npmrc"
chmod 0600 "$npmrc"
printf 'npm auth written to %s\n' "$npmrc"
