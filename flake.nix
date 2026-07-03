{
  description = "oauth-mux — OAuth fallback muxing for AI harness subscriptions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay.url = "github:mitchellh/zig-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay }:
    let
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
        version =
          let
            lines = pkgs.lib.splitString "\n" (builtins.readFile ./build.zig.zon);
            matches = builtins.filter (match: match != null)
              (map (line: builtins.match ".*\\.version[[:space:]]*=[[:space:]]*\"([^\"]+)\".*" line) lines);
          in
          builtins.head (builtins.head matches);
        mkPackage = { installCodexShim }:
          pkgs.stdenvNoCC.mkDerivation {
            pname = if installCodexShim then "oauth-mux-with-codex-shim" else "oauth-mux";
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
              mainProgram = "oauth-mux";
            };
          };
      in
      {
        packages = rec {
          oauth-mux = mkPackage { installCodexShim = false; };
          withCodexShim = mkPackage { installCodexShim = true; };
          default = withCodexShim;
        };

        devShells.default = pkgs.mkShell {
          packages = [ zig pkgs.just pkgs.nodejs pkgs.nfpm pkgs.sops pkgs.age pkgs.jq pkgs.gitleaks ];

          shellHook = ''
            echo "oauth-mux dev shell — zig $(zig version)"
          '';
        };

        checks = {
          build = self.packages.${system}.default;
          binary-only = pkgs.runCommand "oauth-mux-binary-only-smoke-${version}" { } ''
            set -eu

            binary="${self.packages.${system}.oauth-mux}/bin/oauth-mux"
            test "$($binary version)" = "oauth-mux ${version}"
            test ! -e "${self.packages.${system}.oauth-mux}/bin/codex"

            touch "$out"
          '';
          smoke = pkgs.runCommand "oauth-mux-smoke-${version}" {
            nativeBuildInputs = [ pkgs.jq ];
          } ''
            set -eu

            binary="${self.packages.${system}.default}/bin/oauth-mux"
            codex_shim="${self.packages.${system}.default}/bin/codex"
            test "$($binary version)" = "oauth-mux ${version}"
            $binary version --json \
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
              OMUX_CONFIG="$cfg" $binary config validate
            done

            touch "$out"
          '';
        };
      }
    );
}
