#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
install_codex_shim="${OMUX_DOGFOOD_INSTALL_CODEX_SHIM:-0}"
replace_existing_codex="${OMUX_DOGFOOD_REPLACE_CODEX:-0}"
allow_active_sessions="${OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS:-0}"
binary_src="$repo_root/zig-out/bin/oauth-mux"
oauth_mux_target="$install_dir/oauth-mux"
codex_target="$install_dir/codex"
install_tmp=""

cleanup_install_tmp() {
  if [ -n "$install_tmp" ] && [ -e "$install_tmp" ]; then
    rm -f "$install_tmp"
  fi
}
trap cleanup_install_tmp EXIT

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

redact_for_report() {
  local value="$1"
  if [ -n "${HOME:-}" ]; then
    value="${value//$HOME/~}"
  fi
  printf '%s\n' "$value" | sed -E \
    -e 's/(Authorization:[[:space:]]*[Bb]earer[[:space:]]+)[^[:space:]]+/\1<redacted>/g' \
    -e 's/([Bb]earer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/g' \
    -e 's/((access|refresh|id)_token[=:][[:space:]]*)[^[:space:],]+/\1<redacted>/Ig' \
    -e 's/((api[_-]?key|token)[=:][[:space:]]*)[^[:space:],]+/\1<redacted>/Ig'
}

listener_ports_for_pid() {
  local pid="$1"
  if ! command -v lsof >/dev/null 2>&1; then
    printf 'unknown'
    return 0
  fi
  local ports
  ports="$( (lsof -nP -a -p "$pid" -iTCP -sTCP:LISTEN 2>/dev/null || true) | sed -nE 's/.*:([0-9]+)[[:space:]]+\(LISTEN\).*/\1/p' | sort -u | paste -sd, -)"
  if [ -n "$ports" ]; then
    printf '%s' "$ports"
  else
    printf 'none'
  fi
}

is_managed_oauth_mux_codex_command() {
  local command_lc
  command_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case " $command_lc " in
    *" oauth-mux codex"*|*"/oauth-mux codex"*) ;;
    *) return 1 ;;
  esac
  case " $command_lc " in
    *" codex preflight"*|*" codex status"*|*" codex broker-session-plan"*|*" codex login-status"*|*" codex login-device"*|*" codex canary"*)
      return 1
      ;;
  esac
  return 0
}

is_codex_child_command() {
  local first command_lc
  first="${1%% *}"
  command_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  if [ "$(basename "$first")" = "codex" ]; then
    return 0
  fi
  case " $command_lc " in
    *" /codex "*|*" codex "*) return 0 ;;
  esac
  return 1
}

pid_in_list() {
  local needle="$1"
  shift
  local pid
  for pid in "$@"; do
    if [ "$pid" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

collect_active_managed_sessions() {
  local ps_output line pid ppid command
  ps_output="$(ps -axo pid=,ppid=,command= 2>/dev/null)" || return 3
  [ -n "$ps_output" ] || return 0

  local rows=()
  local parent_pids=()
  while IFS=$'\t' read -r pid ppid command; do
    [ -n "${pid:-}" ] || continue
    case "$pid" in
      *[!0-9]*) continue ;;
    esac
    if is_managed_oauth_mux_codex_command "$command"; then
      parent_pids+=("$pid")
      rows+=("pid=$pid ppid=$ppid role=oauth_mux_codex_parent listener_ports=$(listener_ports_for_pid "$pid") command=$(redact_for_report "$command")")
    fi
  done < <(printf '%s\n' "$ps_output" | awk '{ pid=$1; ppid=$2; $1=""; $2=""; sub(/^[[:space:]]+/, "", $0); print pid "\t" ppid "\t" $0 }')

  if [ "${#parent_pids[@]}" -gt 0 ]; then
    while IFS=$'\t' read -r pid ppid command; do
      [ -n "${pid:-}" ] || continue
      case "$pid" in
        *[!0-9]*) continue ;;
      esac
      if pid_in_list "$ppid" "${parent_pids[@]}" && is_codex_child_command "$command"; then
        rows+=("pid=$pid ppid=$ppid role=managed_codex_child listener_ports=$(listener_ports_for_pid "$pid") command=$(redact_for_report "$command")")
      fi
    done < <(printf '%s\n' "$ps_output" | awk '{ pid=$1; ppid=$2; $1=""; $2=""; sub(/^[[:space:]]+/, "", $0); print pid "\t" ppid "\t" $0 }')
  fi

  if [ "${#rows[@]}" -gt 0 ]; then
    printf '%s\n' "${rows[@]}"
  fi
}

binary_version_line() {
  "$1" version 2>/dev/null | head -n 1 || true
}

enforce_active_session_guard() {
  local report count version_line collect_status
  collect_status=0
  report="$(collect_active_managed_sessions)" || collect_status=$?
  if [ -n "$report" ]; then
    count="$(printf '%s\n' "$report" | wc -l | tr -d ' ')"
  else
    count="0"
  fi
  version_line="$(binary_version_line "$binary_src")"

  if [ "$collect_status" != "0" ]; then
    if [ "$allow_active_sessions" = "1" ]; then
      printf 'active managed Codex session guard unavailable: force-allowed (ps status %s)\n' "$collect_status" >&2
      return 0
    fi
    printf 'oauth-mux dogfood install refused: active managed Codex session guard unavailable\n' >&2
    printf 'status: active_session_guard_unavailable\n' >&2
    printf 'source binary: %s\n' "$binary_src" >&2
    printf 'target binary: %s\n' "$oauth_mux_target" >&2
    if [ -n "$version_line" ]; then
      printf 'source version: %s\n' "$version_line" >&2
    fi
    printf 'rerun with OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1 only after explicitly checking active oauth-mux codex sessions yourself\n' >&2
    return 2
  fi

  if [ "$count" != "0" ]; then
    if [ "$allow_active_sessions" = "1" ]; then
      printf 'active managed Codex sessions before install: force-allowed (%s processes)\n' "$count" >&2
      printf '%s\n' "$report" | sed 's/^/  /' >&2
      return 0
    fi
    printf 'oauth-mux dogfood install refused: active managed Codex sessions detected\n' >&2
    printf 'status: active_session_guard_failed\n' >&2
    printf 'source binary: %s\n' "$binary_src" >&2
    printf 'target binary: %s\n' "$oauth_mux_target" >&2
    if [ -n "$version_line" ]; then
      printf 'source version: %s\n' "$version_line" >&2
    fi
    printf 'active managed sessions:\n' >&2
    printf '%s\n' "$report" | sed 's/^/  /' >&2
    printf 'rerun with OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1 only after explicitly accepting that already-running sessions keep their current process image\n' >&2
    return 2
  fi

  printf 'active managed Codex sessions before install: none\n'
}

install_file_atomically() {
  local src="$1"
  local target="$2"
  local mode="$3"
  local dir base
  dir="$(dirname "$target")"
  base="$(basename "$target")"
  install_tmp="$(mktemp "$dir/.${base}.tmp.XXXXXX")"
  cp "$src" "$install_tmp"
  chmod "$mode" "$install_tmp"
  mv -f "$install_tmp" "$target"
  install_tmp=""
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

if [ "${OMUX_DOGFOOD_SKIP_BUILD:-0}" != "1" ]; then
  zig build
fi

if [ ! -x "$binary_src" ]; then
  printf 'missing built oauth-mux binary at %s\n' "$binary_src" >&2
  exit 1
fi

mkdir -p "$install_dir"
enforce_active_session_guard

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

install_file_atomically "$binary_src" "$oauth_mux_target" 0755

src_hash="$(hash_file "$binary_src")"
installed_hash="$(hash_file "$oauth_mux_target")"
if [ "$src_hash" != "$installed_hash" ]; then
  printf 'installed binary hash mismatch\nsource:    %s  %s\ninstalled: %s  %s\n' "$src_hash" "$binary_src" "$installed_hash" "$oauth_mux_target" >&2
  exit 1
fi

if [ "$install_codex_shim" != "0" ]; then
  install_file_atomically "$repo_root/dist/codex-shim.sh" "$codex_target" 0755
fi

printf 'installed oauth-mux dogfood binary: %s\n' "$oauth_mux_target"
printf 'oauth-mux sha256: %s\n' "$installed_hash"
installed_version="$(binary_version_line "$oauth_mux_target")"
if [ -n "$installed_version" ]; then
  printf 'oauth-mux version: %s\n' "$installed_version"
fi
if [ "$install_codex_shim" != "0" ]; then
  printf 'installed managed codex shim: %s\n' "$codex_target"
  printf 'native Codex CLI resolved before install: %s\n' "$native_codex"
else
  printf 'skipped managed codex shim: set OMUX_DOGFOOD_INSTALL_CODEX_SHIM=1 to shadow codex for managed-shim dogfood\n'
fi
path_oauth_mux="$(command -v oauth-mux || true)"
path_codex="$(command -v codex || true)"
printf 'PATH oauth-mux: %s\n' "$path_oauth_mux"
if [ -n "$path_oauth_mux" ] && [ "$(real_path "$path_oauth_mux")" != "$(real_path "$oauth_mux_target")" ]; then
  printf 'warning: installed dogfood oauth-mux is shadowed on PATH by %s\n' "$path_oauth_mux" >&2
  printf 'warning: put %s before that directory or invoke %s directly for source dogfood\n' "$install_dir" "$oauth_mux_target" >&2
fi
printf 'PATH codex: %s\n' "$path_codex"
