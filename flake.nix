{
  description = "oauth-mux — OAuth fallback muxing for AI harness subscriptions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay.url = "github:mitchellh/zig-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
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
      in
      {
        packages = {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "oauth-mux";
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
            '';

            meta = with pkgs.lib; {
              description = "OAuth fallback muxing for AI harness subscriptions";
              license = licenses.mit;
              platforms = platforms.unix;
              mainProgram = "oauth-mux";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ zig pkgs.just pkgs.nodejs pkgs.nfpm pkgs.sops pkgs.age pkgs.jq ];

          shellHook = ''
            echo "oauth-mux dev shell — zig $(zig version)"
          '';
        };

        checks = {
          build = self.packages.${system}.default;
          smoke = pkgs.runCommand "oauth-mux-smoke-${version}" {
            nativeBuildInputs = [ pkgs.jq ];
          } ''
            set -eu

            binary="${self.packages.${system}.default}/bin/oauth-mux"
            test "$($binary version)" = "oauth-mux ${version}"
            $binary version --json \
              | jq -e \
                '.version == "${version}"
                 and .runtime_identity.binary_path
                 and .runtime_identity.binary_sha256
                 and .runtime_identity.binary_sha256_available == true' \
              >/dev/null

            for cfg in ${./examples}/*.config.json; do
              OMUX_CONFIG="$cfg" $binary config validate
            done

            touch "$out"
          '';
        };
      }
    );
}
