#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v nix >/dev/null 2>&1; then
  printf 'missing required command for Home Manager lane smoke: nix\n' >&2
  exit 1
fi

binary_only="$(nix build --no-link --print-out-paths .#oauth-mux)"
with_shim="$(nix build --no-link --print-out-paths .#withCodexShim)"
expected_version="$($repo_root/scripts/project-version.sh)"

test -x "$binary_only/bin/oauth-mux"
test ! -e "$binary_only/bin/codex"
"$binary_only/bin/oauth-mux" version | grep -qx "oauth-mux $expected_version"

test -x "$with_shim/bin/oauth-mux"
test -x "$with_shim/bin/codex"
grep -q OMUX_CODEX_SHIM "$with_shim/bin/codex"
"$with_shim/bin/oauth-mux" version | grep -qx "oauth-mux $expected_version"

native_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$native_dir"
}
trap cleanup EXIT

native_codex="$native_dir/codex"
cat >"$native_codex" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo "native-codex-stub 0.0.0" ;;
  *) echo "native-codex-stub" ;;
esac
EOF
chmod 0755 "$native_codex"

OMUX_CODEX_BIN="$native_codex" "$with_shim/bin/codex" --version \
  | grep -qx "native-codex-stub 0.0.0"

module_pnames="$(nix eval --impure --raw --expr "
let
  flake = builtins.getFlake \"path:$repo_root\";
  system = builtins.currentSystem;
  pkgs = import flake.inputs.nixpkgs {
    inherit system;
    overlays = [ flake.inputs.zig-overlay.overlays.default ];
  };
  lib = pkgs.lib;
  base = { lib, ... }: {
    options.home.packages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
    };
  };
  eval = module:
    (lib.evalModules {
      specialArgs = { inherit pkgs; };
      modules = [ base flake.homeManagerModules.default module ];
    }).config.home.packages;
  binaryOnly = builtins.head (eval ({ ... }: { programs.oauth-mux.enable = true; }));
  withShimPackage = builtins.head (eval ({ ... }: {
    programs.oauth-mux.enable = true;
    programs.oauth-mux.codexShim.enable = true;
  }));
in binaryOnly.pname + \" \" + withShimPackage.pname
")"
test "$module_pnames" = "oauth-mux oauth-mux-with-codex-shim"

nix flake show --json . >/dev/null

printf 'Home Manager lane smoke passed\n'
