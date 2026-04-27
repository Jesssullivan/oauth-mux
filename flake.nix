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
        version = "0.1.0";
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
          packages = [ zig pkgs.just pkgs.nodejs pkgs.nfpm ];

          shellHook = ''
            echo "oauth-mux dev shell — zig $(zig version)"
          '';
        };

        checks = {
          build = self.packages.${system}.default;
        };
      }
    );
}
