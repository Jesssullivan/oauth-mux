#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
primary="${1:-$repo_root/zig-out/bin/omux}"
compatibility="${2:-$repo_root/zig-out/bin/oauth-mux}"
version="$($repo_root/scripts/project-version.sh)"

fail() {
  printf 'executable compatibility check failed: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -x "$primary" ] || fail "primary executable is missing: $primary"
[ -x "$compatibility" ] || fail "compatibility executable is missing: $compatibility"
cmp -s "$primary" "$compatibility" || fail "entrypoints are not byte-identical"

primary_version="$($primary version)"
compatibility_version="$($compatibility version)"
[ "$primary_version" = "omux $version" ] || fail "unexpected primary version line: $primary_version"
[ "$compatibility_version" = "oauth-mux $version" ] || fail "unexpected compatibility version line: $compatibility_version"

primary_json="$($primary version --json)"
compatibility_json="$($compatibility version --json)"
primary_identity=$(printf '%s\n' "$primary_json" | jq -cS '{version, build_id: .runtime_identity.build_id, binary_sha256: .runtime_identity.binary_sha256, binary_source: .runtime_identity.binary_source}')
compatibility_identity=$(printf '%s\n' "$compatibility_json" | jq -cS '{version, build_id: .runtime_identity.build_id, binary_sha256: .runtime_identity.binary_sha256, binary_source: .runtime_identity.binary_source}')
[ "$primary_identity" = "$compatibility_identity" ] || fail "version/build identities differ"
printf '%s\n' "$primary_json" | jq -e '.runtime_identity.binary_sha256_available == true' >/dev/null

primary_help="$($primary --help)"
compatibility_help="$($compatibility --help)"
[ "$primary_help" = "$compatibility_help" ] || fail "help differs by entrypoint"
printf '%s\n' "$primary_help" | grep -q '^Usage: omux ' || fail "help does not prefer omux"

fish_completions="$($primary completions fish)"
printf '%s\n' "$fish_completions" | grep -q '^complete -c omux ' || fail "fish completions omit omux"
printf '%s\n' "$fish_completions" | grep -q '^complete -c oauth-mux ' || fail "fish completions omit oauth-mux"
zsh_completions="$($primary completions zsh)"
printf '%s\n' "$zsh_completions" | grep -q '^#compdef omux oauth-mux$' || fail "zsh completions omit an entrypoint"
bash_completions="$($primary completions bash)"
printf '%s\n' "$bash_completions" | grep -q '^complete -F _oauth_mux_completions omux oauth-mux$' || fail "bash completions omit an entrypoint"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/omux-executable-compat.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/home" "$tmp/config" "$tmp/state" "$tmp/runtime"

isolated() {
  env \
    -u OMUX_CONFIG \
    -u OMUX_CONFIG_DIR \
    -u OMUX_STATE_DIR \
    -u OMUX_RUNTIME_DIR \
    HOME="$tmp/home" \
    XDG_CONFIG_HOME="$tmp/config" \
    XDG_STATE_HOME="$tmp/state" \
    XDG_RUNTIME_DIR="$tmp/runtime" \
    PATH="$repo_root/zig-out/bin:$PATH" \
    "$@"
}

primary_config=$(isolated "$primary" config path)
compatibility_config=$(isolated "$compatibility" config path)
expected_config="$tmp/config/oauth-mux/config.json"
[ "$primary_config" = "$compatibility_config" ] || fail "config roots differ"
[ "$primary_config" = "$expected_config" ] || fail "persistent config namespace changed: $primary_config"

primary_doctor=$(isolated "$primary" doctor --json)
compatibility_doctor=$(isolated "$compatibility" doctor --json)
primary_roots=$(printf '%s\n' "$primary_doctor" | jq -cS '{config_path, state_dir, health_path}')
compatibility_roots=$(printf '%s\n' "$compatibility_doctor" | jq -cS '{config_path, state_dir, health_path}')
[ "$primary_roots" = "$compatibility_roots" ] || fail "config/state identities differ"
printf '%s\n' "$primary_doctor" | jq -e \
  --arg config "$expected_config" \
  --arg state "$tmp/state/oauth-mux" \
  '.config_path == $config and .state_dir == $state and .health_path == ($state + "/health.json")' \
  >/dev/null || fail "persistent config/state namespace changed"

dogfood_bin="$tmp/dogfood-bin"
dogfood_tools="$tmp/dogfood-tools"
mkdir -p "$dogfood_bin" "$dogfood_tools"
for tool in ps omux oauth-mux; do
  cat >"$dogfood_tools/$tool" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
  chmod 0755 "$dogfood_tools/$tool"
done
env \
  INSTALL_DIR="$dogfood_bin" \
  OMUX_DOGFOOD_SKIP_BUILD=1 \
  OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1 \
  PATH="$dogfood_tools:$PATH" \
  "$repo_root/scripts/install-local-dogfood.sh" \
  >"$tmp/dogfood-install.out" \
  2>"$tmp/dogfood-install.err"
[ -x "$dogfood_bin/omux" ] || fail "dogfood install omitted omux"
[ -L "$dogfood_bin/oauth-mux" ] || fail "dogfood compatibility entrypoint is not a symlink"
[ "$(readlink "$dogfood_bin/oauth-mux")" = "omux" ] || fail "dogfood compatibility link is not relative to omux"
[ "$($dogfood_bin/omux version)" = "omux $version" ] || fail "dogfood primary version identity changed"
[ "$($dogfood_bin/oauth-mux version)" = "oauth-mux $version" ] || fail "dogfood compatibility version identity changed"
grep -q 'warning: installed dogfood omux is shadowed on PATH' "$tmp/dogfood-install.err" || fail "dogfood install omitted omux PATH-shadow warning"
grep -q 'warning: installed oauth-mux compatibility entrypoint is shadowed on PATH' "$tmp/dogfood-install.err" || fail "dogfood install omitted oauth-mux PATH-shadow warning"

env INSTALL_DIR="$dogfood_bin" "$repo_root/scripts/uninstall-local-dogfood.sh" >"$tmp/dogfood-uninstall.out"
[ ! -e "$dogfood_bin/omux" ] || fail "dogfood uninstall left omux behind"
[ ! -e "$dogfood_bin/oauth-mux" ] && [ ! -L "$dogfood_bin/oauth-mux" ] || fail "dogfood uninstall left oauth-mux behind"

printf 'executable compatibility check passed: omux + oauth-mux (%s)\n' "$version"
