#!/bin/sh
# OMUX_CODEX_SHIM
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd -P)
oauth_mux_bin="$script_dir/oauth-mux"

real_path() {
    if command -v realpath >/dev/null 2>&1; then
        realpath "$1"
    else
        dir=$(dirname "$1")
        base=$(basename "$1")
        printf '%s/%s\n' "$(cd "$dir" 2>/dev/null && pwd -P)" "$base"
    fi
}

is_omux_codex_shim() {
    grep -q 'OMUX_CODEX_SHIM' "$1" 2>/dev/null
}

find_native_codex() {
    self=$(real_path "$0")
    old_ifs=$IFS
    IFS=:
    for dir in $PATH; do
        [ -n "$dir" ] || continue
        candidate="$dir/codex"
        [ -x "$candidate" ] || continue
        candidate_real=$(real_path "$candidate")
        [ "$candidate_real" != "$self" ] || continue
        if is_omux_codex_shim "$candidate"; then
            continue
        fi
        IFS=$old_ifs
        printf '%s\n' "$candidate"
        return 0
    done
    IFS=$old_ifs
    return 1
}

native_codex="${OMUX_CODEX_BIN:-}"
if [ -z "$native_codex" ]; then
    native_codex=$(find_native_codex || true)
fi
if [ -z "$native_codex" ]; then
    echo "codex: native Codex CLI not found; set OMUX_CODEX_BIN to the upstream Codex executable" >&2
    exit 127
fi

trace_enabled() {
    case "${OMUX_TRACE:-}" in
        ""|0|false|FALSE|off|OFF|no|NO)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

trace_file_path() {
    if [ -n "${OMUX_TRACE_FILE:-}" ]; then
        printf '%s\n' "$OMUX_TRACE_FILE"
        return 0
    fi
    if [ -n "${OMUX_STATE_DIR:-}" ]; then
        printf '%s/trace.ndjson\n' "$OMUX_STATE_DIR"
        return 0
    fi
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            printf '%s/Library/Application Support/oauth-mux/trace.ndjson\n' "${HOME:-/tmp}"
            ;;
        *)
            printf '%s/.local/state/oauth-mux/trace.ndjson\n' "${HOME:-/tmp}"
            ;;
    esac
}

trace_shim_event() {
    trace_enabled || return 0
    trace_file=$(trace_file_path)
    trace_dir=$(dirname "$trace_file")
    mkdir -p "$trace_dir" 2>/dev/null || return 0
    ts="$(date +%s)000"
    case "${1:-none}" in
        --help|-h|help|--version|-V|version|login|logout|auth|mcp|completion|completions|resume|run)
            first_arg="${1:-none}"
            ;;
        *)
            first_arg="other"
            ;;
    esac
    trace_id="${OMUX_TRACE_ID:-00000000000000000000000000000000}"
    span_id="${OMUX_SPAN_ID:-0000000000000000}"
    case "$trace_id" in *[!0123456789abcdefABCDEF]*|"") trace_id="00000000000000000000000000000000" ;; esac
    case "$span_id" in *[!0123456789abcdefABCDEF]*|"") span_id="0000000000000000" ;; esac
    printf '{"schema":"oauth-mux.trace.v1","ts_unix_ms":%s,"name":"%s","severity":"info","trace_id":"%s","span_id":"%s","parent_span_id":null,"attributes":{"first_arg":"%s","native_binary_path_printed":false,"path_printed":false},"redaction":{"tokens":false,"raw_account_ids":false,"session_ids":false,"paths":false}}\n' "$ts" "$2" "$trace_id" "$span_id" "$first_arg" >>"$trace_file" 2>/dev/null || true
}

should_pass_native() {
    case "${1:-}" in
        --help|-h|help|--version|-V|version|login|logout|auth|mcp|completion|completions)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

if should_pass_native "${1:-}"; then
    trace_shim_event "${1:-none}" "codex.shim.pass_through"
    exec "$native_codex" "$@"
fi

trace_shim_event "${1:-none}" "codex.shim.managed_entry"
OMUX_CODEX_BIN="$native_codex" OMUX_CODEX_SHIM=1 OMUX_COMMAND_SPELLING=codex exec "$oauth_mux_bin" codex "$@"
