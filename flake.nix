{
  description = "oauth-mux — OAuth fallback muxing for AI harness subscriptions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay.url = "github:mitchellh/zig-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay }:
    let
      releaseManifest =
        let
          manifest = builtins.fromJSON (builtins.readFile ./release-manifest.json);
        in
        assert manifest.schema_version == 1;
        assert manifest.phase == "declaration";
        manifest;
      version = releaseManifest.release.version;
      packageName = releaseManifest.product.package_name;
      primaryExecutable = releaseManifest.product.primary_executable;
      compatibilityLink =
        assert builtins.length releaseManifest.product.compatibility_links == 1;
        builtins.head releaseManifest.product.compatibility_links;
      compatibilityExecutable =
        assert compatibilityLink.target == primaryExecutable;
        assert compatibilityLink.materialization == "same_bytes";
        compatibilityLink.name;
      homeModule = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.oauth-mux;
          system = pkgs.stdenv.hostPlatform.system;
          packageSet = self.packages.${system};
        in
        {
          options.programs.oauth-mux = {
            enable = lib.mkEnableOption "oauth-mux";

            package = lib.mkOption {
              type = lib.types.package;
              default =
                if cfg.codexShim.enable
                then packageSet.withCodexShim
                else packageSet.oauth-mux;
              defaultText = lib.literalExpression ''
                if config.programs.oauth-mux.codexShim.enable
                then inputs.oauth-mux.packages.''${pkgs.stdenv.hostPlatform.system}.withCodexShim
                else inputs.oauth-mux.packages.''${pkgs.stdenv.hostPlatform.system}.oauth-mux
              '';
              description = ''
                oauth-mux package installed into the user profile.
              '';
            };

            codexShim.enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Install the managed Codex shim as `codex`. This is opt-in so
                Home Manager users do not unexpectedly shadow an existing
                upstream Codex CLI in their profile.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];
          };
        };
    in
    {
      homeModules.default = homeModule;
      homeManagerModules.default = homeModule;
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ zig-overlay.overlays.default ];
        };
        zig = pkgs.zigpkgs."0.14.1";
        ownedTempRunner = pkgs.writeShellApplication {
          name = "omux-owned-temp-runner";
          text = ''
            repo_root="$(pwd -P)"
            runner="$repo_root/scripts/owned_temp_runner.py"
            test -f "$runner" && test ! -L "$runner" || {
              printf 'descriptor-owned temporary-root runner is unavailable\n' >&2
              exit 2
            }
            exec ${pkgs.python3}/bin/python3 -I -B "$runner" "$@"
          '';
        };
        v02ExactPromoter = pkgs.writeShellApplication {
          name = "omux-v02-posix-exact-promote";
          text = ''
            if test "$#" -eq 1 && test "$1" = "--authority-probe"; then
              printf 'python=%s\ngit=%s\nzig=%s\n' \
                ${pkgs.python3}/bin/python3 \
                ${pkgs.git}/bin/git \
                ${zig}/bin/zig
              exit 0
            fi
            repo_root="$(pwd -P)"
            candidate="$repo_root/scripts/v02_posix_candidate.py"
            test -f "$candidate" && test ! -L "$candidate" || {
              printf 'exact promoter source oracle is unavailable\n' >&2
              exit 2
            }
            exec ${pkgs.python3}/bin/python3 -I -B -c '
import importlib.util
import sys
from pathlib import Path

candidate_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("omux_v02_exact_candidate", candidate_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load exact promoter source oracle")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
tools = module.ExactToolAuthority(
    python=Path("${pkgs.python3}/bin/python3"),
    git=Path("${pkgs.git}/bin/git"),
    zig=Path("${zig}/bin/zig"),
)
raise SystemExit(module.exact_closure_main(sys.argv[2:], tools))
' "$candidate" "$@"
          '';
        };
        v02ContractInner = pkgs.writeShellApplication {
          name = "omux-v02-posix-install-contract-inner";
          excludeShellChecks = [ "SC2016" ];
          text = ''
            if test "$#" -eq 1 && test "$1" = "--authority-probe"; then
              printf 'python=%s\ngit=%s\nzig=%s\n' \
                ${pkgs.python3}/bin/python3 \
                ${pkgs.git}/bin/git \
                ${zig}/bin/zig
              exit 0
            fi
            test "$#" -eq 0 || {
              printf 'generated contract helper accepts no arguments\n' >&2
              exit 2
            }
            repo_root="$(pwd -P)"
            wrapper_root="''${OMUX_V02_WRAPPER_TEMP_ROOT:-}"
            wrapper_fd="''${OMUX_V02_WRAPPER_TEMP_ROOT_FD:-}"
            test -n "$wrapper_root" && test -n "$wrapper_fd" || {
              printf 'generated contract helper requires descriptor-owned wrapper custody\n' >&2
              exit 2
            }
            case "$wrapper_fd" in
              *[!0-9]*)
                printf 'generated contract helper requires descriptor-owned wrapper custody\n' >&2
                exit 2
                ;;
            esac
            test "$wrapper_fd" -ge 3 || {
              printf 'generated contract helper requires descriptor-owned wrapper custody\n' >&2
              exit 2
            }
            if ${pkgs.python3}/bin/python3 -I -B - "$wrapper_root" "$wrapper_fd" <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    descriptor = os.fstat(int(sys.argv[2], 10))
    current = os.stat(path, follow_symlinks=False)
except (OSError, ValueError):
    raise SystemExit(1)

descriptor_identity = (
    descriptor.st_dev,
    descriptor.st_ino,
    descriptor.st_uid,
    stat.S_IMODE(descriptor.st_mode),
)
path_identity = (
    current.st_dev,
    current.st_ino,
    current.st_uid,
    stat.S_IMODE(current.st_mode),
)
if (
    not path.is_absolute()
    or not stat.S_ISDIR(descriptor.st_mode)
    or not stat.S_ISDIR(current.st_mode)
    or descriptor.st_uid != os.getuid()
    or stat.S_IMODE(descriptor.st_mode) != 0o700
    or descriptor_identity != path_identity
):
    raise SystemExit(1)
PY
            then
              :
            else
              printf 'generated contract helper requires descriptor-owned wrapper custody\n' >&2
              exit 2
            fi
            template="$repo_root/scripts/v02-posix-install-contract-inner.sh.in"
            test -f "$template" && test ! -L "$template" && test ! -x "$template" || {
              printf 'non-executable inner contract template is unavailable\n' >&2
              exit 2
            }
            exec ${ownedTempRunner}/bin/omux-owned-temp-runner \
              --adopt-root OMUX_V02_WRAPPER_TEMP_ROOT "$wrapper_fd" "$wrapper_root" \
              --root OMUX_V02_CONTRACT_TEMP_ROOT:omux-v02-posix-contract \
              -- ${pkgs.coreutils}/bin/env \
                OMUX_V02_REPO_ROOT="$repo_root" \
                OMUX_V02_EMBEDDED_PYTHON=${pkgs.python3}/bin/python3 \
                OMUX_V02_EMBEDDED_GIT=${pkgs.git}/bin/git \
                OMUX_V02_EMBEDDED_ZIG=${zig}/bin/zig \
                OMUX_V02_EMBEDDED_BASH=${pkgs.bash}/bin/bash \
                OMUX_V02_EMBEDDED_SED=${pkgs.gnused}/bin/sed \
                ${pkgs.bash}/bin/bash -c '
                  set -euo pipefail
                  generated="$OMUX_V02_CONTRACT_TEMP_ROOT/generated-inner.sh"
                  "$OMUX_V02_EMBEDDED_SED" \
                    -e "s|@python@|$OMUX_V02_EMBEDDED_PYTHON|g" \
                    -e "s|@git@|$OMUX_V02_EMBEDDED_GIT|g" \
                    -e "s|@zig@|$OMUX_V02_EMBEDDED_ZIG|g" \
                    "$OMUX_V02_REPO_ROOT/scripts/v02-posix-install-contract-inner.sh.in" \
                    >"$generated"
                  chmod 0500 "$generated"
                  exec "$OMUX_V02_EMBEDDED_BASH" "$generated"
                '
          '';
        };
        manifestContract =
          assert builtins.isString version && version != "";
          assert builtins.isString packageName && packageName != "";
          assert builtins.isString primaryExecutable && primaryExecutable != "";
          assert builtins.isString compatibilityExecutable && compatibilityExecutable != "";
          true;
        mkPackage = { installCodexShim }:
          assert manifestContract;
          pkgs.stdenvNoCC.mkDerivation {
            pname = if installCodexShim then "${packageName}-with-codex-shim" else packageName;
            inherit version;
            src = ./.;

            nativeBuildInputs = [ zig ];

            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
              export ZIG_LOCAL_CACHE_DIR="$TMPDIR/zig-local"
              mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
              zig build \
                --release=safe \
                --prefix "$out" \
                -Doptimize=ReleaseSafe
            '' + pkgs.lib.optionalString installCodexShim ''
              cp dist/codex-shim.sh "$out/bin/codex"
              chmod 0755 "$out/bin/codex"
            '';

            passthru.codexShim = installCodexShim;

            meta = with pkgs.lib; {
              description = "OAuth fallback muxing for AI harness subscriptions";
              license = licenses.mit;
              platforms = platforms.unix;
              mainProgram = primaryExecutable;
            };
          };
      in
      {
        packages = rec {
          omux = mkPackage { installCodexShim = false; };
          oauth-mux = omux;
          withCodexShim = mkPackage { installCodexShim = true; };
          default = withCodexShim;
        };

        devShells.default = pkgs.mkShell {
          packages = [ zig pkgs.bash pkgs.coreutils pkgs.python3 pkgs.git pkgs.just pkgs.nodejs pkgs.nfpm pkgs.sops pkgs.age pkgs.jq pkgs.gitleaks pkgs.check-jsonschema pkgs.actionlint ownedTempRunner v02ExactPromoter v02ContractInner ];

          shellHook = ''
            echo "oauth-mux dev shell — zig $(zig version)"
          '';
        };

        checks = {
          build = self.packages.${system}.default;
          binary-only = pkgs.runCommand "${packageName}-binary-only-smoke-${version}" {
            nativeBuildInputs = [ pkgs.diffutils ];
          } ''
            set -eu

            package="${self.packages.${system}.omux}"
            primary="$package/bin/${primaryExecutable}"
            compatibility="$package/bin/${compatibilityExecutable}"
            test "${self.packages.${system}.oauth-mux}" = "$package"
            test -x "$primary"
            test -x "$compatibility"
            cmp -s "$primary" "$compatibility"
            test "$("$primary" version)" = "${primaryExecutable} ${version}"
            test "$("$compatibility" version)" = "${compatibilityExecutable} ${version}"
            test ! -e "$package/bin/codex"

            touch "$out"
          '';
          smoke = pkgs.runCommand "${packageName}-smoke-${version}" {
            nativeBuildInputs = [ pkgs.jq ];
          } ''
            set -eu

            package="${self.packages.${system}.default}"
            primary="$package/bin/${primaryExecutable}"
            compatibility="$package/bin/${compatibilityExecutable}"
            codex_shim="$package/bin/codex"
            test "${self.packages.${system}.withCodexShim}" = "$package"
            test -x "$primary"
            test -x "$compatibility"
            test "$("$primary" version)" = "${primaryExecutable} ${version}"
            test "$("$compatibility" version)" = "${compatibilityExecutable} ${version}"
            "$primary" version --json \
              | jq -e \
                '.version == "${version}"
                 and .runtime_identity.binary_path
                 and .runtime_identity.binary_sha256
                 and .runtime_identity.binary_sha256_available == true' \
              >/dev/null
            test -x "$codex_shim"
            grep -q OMUX_CODEX_SHIM "$codex_shim"
            native_codex="$TMPDIR/native-codex"
            cat > "$native_codex" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo "native-codex-stub 0.0.0" ;;
  *) echo "native-codex-stub" ;;
esac
EOF
            chmod 0755 "$native_codex"
            test "$(OMUX_CODEX_BIN="$native_codex" "$codex_shim" --version)" = "native-codex-stub 0.0.0"

            for cfg in ${./examples}/*.config.json; do
              OMUX_CONFIG="$cfg" "$primary" config validate
            done

            touch "$out"
          '';
        };
      }
    );
}
