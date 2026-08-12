#!/usr/bin/env -S PATH=/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin bash -p
set -eu
unset BASH_ENV ENV CDPATH GLOBIGNORE
PATH=/usr/bin:/bin
export PATH
readonly PATH

[ "$#" -eq 0 ] || {
  printf 'usage: %s\n' "$0" >&2
  exit 2
}

script_path="$0"
case "$script_path" in
  /*) ;;
  *) script_path="$(pwd -P)/$script_path" ;;
esac
[ -f "$script_path" ] && [ ! -L "$script_path" ] || {
  printf 'source contract entrypoint must be one regular, non-symlink file\n' >&2
  exit 2
}
script_dir="${script_path%/*}"
[ "$script_dir" != "$script_path" ] || script_dir=.
repo_root="$(cd "$script_dir/.." && pwd -P)"
cd "$repo_root"

realpath_bin=
for entry in \
  /run/current-system/sw/bin/realpath \
  /nix/var/nix/profiles/default/bin/realpath \
  /usr/bin/realpath \
  /bin/realpath
do
  [ -x "$entry" ] || continue
  resolved="$("$entry" "$entry" 2>/dev/null)" || continue
  case "$resolved" in
    /nix/store/*/bin/realpath|/usr/bin/realpath|/bin/realpath) ;;
    *) continue ;;
  esac
  [ -x "$resolved" ] && [ ! -L "$resolved" ] || continue
  realpath_bin="$resolved"
  break
done
[ -n "$realpath_bin" ] || {
  printf 'a fixed system realpath utility is required\n' >&2
  exit 2
}
readonly realpath_bin

resolve_nix() {
  for entry in \
    /nix/var/nix/profiles/default/bin/nix \
    /run/current-system/sw/bin/nix
  do
    [ -x "$entry" ] || continue
    resolved="$("$realpath_bin" "$entry" 2>/dev/null)" || continue
    case "$resolved" in
      /nix/store/*/bin/nix) ;;
      *) continue ;;
    esac
    [ -x "$resolved" ] && [ ! -L "$resolved" ] || continue
    version_output="$("$resolved" --version 2>/dev/null)" || continue
    case "$version_output" in
      nix\ *) printf '%s\n' "$resolved"; return 0 ;;
    esac
  done
  printf 'a validated system-profile Nix executable is required\n' >&2
  return 2
}

nix_bin="$(resolve_nix)"
readonly nix_bin

# Root custody starts inside the pinned Nix closure. A failed `nix develop`
# therefore creates no contract state, and the descriptor-owned runner handles
# process-group signals plus fd-relative cleanup for every created root.
exec "$nix_bin" develop --command \
  omux-owned-temp-runner \
  --root OMUX_V02_WRAPPER_TEMP_ROOT:omux-v02-posix-wrapper \
  -- omux-v02-posix-install-contract-inner
