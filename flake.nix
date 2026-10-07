{
  description = "Omux native account daemon — Bazel-only local execution";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        # Linux operator configs may use distro GSSAPI crypto-policy options.
        # This locked variant understands them rather than bypassing policy.
        operatorSsh = if pkgs.stdenv.isLinux then pkgs.openssh_gssapi else pkgs.openssh;
        bazelisk = pkgs.writeShellScriptBin "bazelisk" ''exec ${pkgs.bazel_9}/bin/bazel "$@"'';
        zigIndex = builtins.fromJSON (builtins.readFile ./tools/zig-index.json);
        zigPlatform = { x86_64-linux = "x86_64-linux"; aarch64-linux = "aarch64-linux"; x86_64-darwin = "x86_64-macos"; aarch64-darwin = "aarch64-macos"; }.${system};
        zigAsset = zigIndex."0.17.0".${zigPlatform};
        # Preserve the native upstream graph's compiler bytes while placing its
        # audited download inputs under Nix custody. The manifest is deliberately
        # scoped to the Linux x86_64 proof, not optional upstream lint platforms.
        codexToolManifest = builtins.fromJSON (builtins.readFile ./tools/codex_upstream_archives.json);
        codexToolArchives = pkgs.linkFarm "omux-codex-upstream-tool-archives" (map (archive: {
          name = archive.name;
          path = pkgs.fetchurl { inherit (archive) name url sha256; };
        }) codexToolManifest.archives);
        codexTestPath = pkgs.lib.makeBinPath [ pkgs.bash pkgs.coreutils pkgs.python3 pkgs.git pkgs.gawk pkgs.gnugrep pkgs.gnused pkgs.findutils ];
        codexSupplementalRc = pkgs.writeText "omux-codex-upstream.bazelrc" ''
          common --distdir=${codexToolArchives}
          test --test_env=PATH=${codexTestPath}
        '';
        nativeSqlite = pkgs.sqlite.overrideAttrs (old: {
          version = "3.53.4";
          doCheck = false; # Application acceptance is executed through Bazel.
          src = pkgs.fetchurl { url = "https://sqlite.org/2026/sqlite-src-3530400.zip"; sha256 = "d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b"; };
          # SQLite 3.53 defaults to no SONAME. Keep its documented legacy ABI
          # alias so direct declared DSO links remain relocatable.
          configureFlags = (old.configureFlags or []) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ "--soname=legacy" ];
        });
        nativeOpenSSL = pkgs.openssl.overrideAttrs (old: {
          patches = builtins.filter (patch: !(pkgs.lib.hasInfix "aes-gcm-ppc" (toString patch))) old.patches;
          version = "3.5.9";
          doCheck = false;
          src = pkgs.fetchurl { url = "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"; sha256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"; };
        });
        nativeNghttp2 = pkgs.nghttp2.overrideAttrs (_: {
          version = "1.70.0";
          doCheck = false;
          src = pkgs.fetchurl { url = "https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz"; sha256 = "e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2"; };
        });
        nativeCurl = (pkgs.curlMinimal.override { openssl = nativeOpenSSL; nghttp2 = nativeNghttp2; gssSupport = false; scpSupport = false; http2Support = true; http3Support = false; opensslSupport = true; zlibSupport = false; }).overrideAttrs (old: {
          version = "8.22.0";
          doCheck = false;
          src = pkgs.fetchurl { url = "https://curl.se/download/curl-8.22.0.tar.xz"; sha256 = "f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7"; };
          configureFlags = old.configureFlags ++ [ "--enable-websockets" "--enable-threaded-resolver" "--disable-ftp" "--disable-file" "--disable-rtsp" "--disable-dict" "--disable-telnet" "--disable-tftp" "--disable-pop3" "--disable-imap" "--disable-smtp" "--disable-gopher" "--disable-mqtt" ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ "--with-apple-sectrust" ];
        });
        runtimeClosure = pkgs.closureInfo { rootPaths = [ nativeSqlite.out nativeCurl.out ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.libsecret.out ]; };
        qtRuntimeClosure = pkgs.closureInfo { rootPaths = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.qt6.qtbase.out pkgs.qt6.qtwayland.out ]; };
        packages = {
          sqlite = { out = "${nativeSqlite.out}"; dev = "${nativeSqlite.dev}"; };
          curl = { out = "${nativeCurl.out}"; dev = "${nativeCurl.dev}"; };
          openssl = { out = "${nativeOpenSSL.out}"; dev = "${nativeOpenSSL.dev}"; bin = "${nativeOpenSSL.bin}"; };
          nghttp2 = { out = "${nativeNghttp2.lib}"; dev = "${nativeNghttp2.dev}"; };
          node = { out = "${pkgs.nodejs}"; };
          python = { out = "${pkgs.python3}"; };
          bash = { out = "${pkgs.bash}"; };
          coreutils = { out = "${pkgs.coreutils}"; };
          cacert = { out = "${pkgs.cacert}"; };
          openssh = { out = "${operatorSsh}"; };
          bazel_jdk = { out = "${pkgs.jdk_headless}"; };
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          swift = { out = "${pkgs.swift}"; };
          apple_sdk = { out = "${pkgs.apple-sdk_14}"; };
          darwin_binutils = { out = "${pkgs.darwin.binutils-unwrapped}"; };
          cctools = { out = "${pkgs.cctools}"; };
          rcodesign = { out = "${pkgs.rcodesign}"; };
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          patchelf = { out = "${pkgs.patchelf}"; };
          dbus = { out = "${pkgs.dbus}"; };
          gnome_keyring = { out = "${pkgs.gnome-keyring}"; };
          systemctl = { out = "${pkgs.systemd.out}"; };
          libsecret = { out = "${pkgs.libsecret.out}"; dev = "${pkgs.libsecret.dev}"; };
          glib = { out = "${pkgs.glib.out}"; dev = "${pkgs.glib.dev}"; };
          qt = { out = "${pkgs.qt6.qtbase.out}"; dev = "${pkgs.qt6.qtbase.dev}"; };
          qtwayland = { out = "${pkgs.qt6.qtwayland.out}"; };
          libc = { out = "${pkgs.stdenv.cc.libc.out}"; dev = "${pkgs.stdenv.cc.libc.dev}"; };
        };
        nativeManifest = pkgs.writeText "native.json" (builtins.toJSON {
          inherit system packages;
          libc_abi = if pkgs.stdenv.isLinux then pkgs.stdenv.cc.libc.version else null;
          runtime_store_paths = "${runtimeClosure}/store-paths";
          qt_runtime_store_paths = "${qtRuntimeClosure}/store-paths";
          dynamic_linker = if pkgs.stdenv.isLinux then "${pkgs.stdenv.cc.libc.out}/lib/" + (if pkgs.stdenv.hostPlatform.isAarch64 then "ld-linux-aarch64.so.1" else "ld-linux-x86-64.so.2") else null;
          tools = { ssh = "${operatorSsh}/bin/ssh"; }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
              patchelf = "${pkgs.patchelf}/bin/patchelf"; systemctl = "${pkgs.systemd.out}/bin/systemctl";
              dbus_daemon = "${pkgs.dbus}/bin/dbus-daemon";
              dbus_run_session = "${pkgs.dbus}/bin/dbus-run-session";
              gnome_keyring_daemon = "${pkgs.gnome-keyring}/bin/gnome-keyring-daemon";
              secret_tool = "${pkgs.libsecret}/bin/secret-tool";
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin { otool = "${pkgs.darwin.binutils-unwrapped}/bin/otool"; install_name_tool = "${pkgs.cctools}/bin/install_name_tool"; rcodesign = "${pkgs.rcodesign}/bin/rcodesign"; };
          apple = if pkgs.stdenv.isDarwin then {
            sdk = "${pkgs.apple-sdk_14}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
            sdk_version = "14.4"; swiftc = "${pkgs.swift}/bin/swiftc"; swift_version = pkgs.swift.version;
          } else null;
          cc = "${pkgs.stdenv.cc}/bin/cc";
          cxx = "${pkgs.stdenv.cc}/bin/c++";
          ar = "${pkgs.stdenv.cc.bintools}/bin/ar";
          linker = "${pkgs.stdenv.cc}/bin/c++";
          nm = "${pkgs.stdenv.cc.bintools}/bin/nm";
          strip = "${pkgs.stdenv.cc.bintools}/bin/strip";
          objcopy = "${pkgs.stdenv.cc.bintools}/bin/objcopy";
          objdump = "${pkgs.stdenv.cc.bintools}/bin/objdump";
          builtin_include_directories = pkgs.lib.optionals pkgs.stdenv.isLinux [
            "${pkgs.stdenv.cc.libc.dev}/include"
            "${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.stdenv.cc.cc.version}/include"
            "${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.stdenv.cc.cc.version}/include-fixed"
            "${pkgs.stdenv.cc.cc}/include/c++/${pkgs.stdenv.cc.cc.version}"
            "${pkgs.stdenv.cc.cc}/include/c++/${pkgs.stdenv.cc.cc.version}/${pkgs.stdenv.hostPlatform.config}"
           ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            "${pkgs.apple-sdk_14}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include"
            "${pkgs.apple-sdk_14}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks"
            "${pkgs.lib.getLib pkgs.stdenv.cc.cc}/lib/clang/${pkgs.lib.versions.major pkgs.stdenv.cc.cc.version}/include"
            "${pkgs.lib.getDev pkgs.darwin.libcxx}/include/c++/v1"
          ];
        });
        toolClosure = pkgs.closureInfo { rootPaths = [ nativeManifest pkgs.stdenv.cc pkgs.stdenv.cc.bintools pkgs.python3 pkgs.nodejs pkgs.bash pkgs.coreutils ]
          ++ builtins.concatMap (p: builtins.attrValues p) (builtins.attrValues packages); };
        bazelClosure = pkgs.linkFarm "omux-bazel-closure" [
          { name = "native.json"; path = nativeManifest; }
          { name = "store-paths"; path = "${toolClosure}/store-paths"; }
          { name = "registration"; path = "${toolClosure}/registration"; }
        ];
        # Repository setup and explicit operator tools run on the coordinator,
        # even when the execution closure contains Darwin binaries.
        bootstrapManifest = pkgs.writeText "native.json" (builtins.toJSON {
          inherit system;
          packages = {
            python = { out = "${pkgs.python3}"; };
            bash = { out = "${pkgs.bash}"; };
            coreutils = { out = "${pkgs.coreutils}"; };
            nix = { out = "${pkgs.nix}"; };
            openssh = { out = "${operatorSsh}"; };
            git = { out = "${pkgs.git}"; };
            cacert = { out = "${pkgs.cacert}"; };
          };
          tools = { nix = "${pkgs.nix}/bin/nix"; ssh = "${operatorSsh}/bin/ssh"; git = "${pkgs.git}/bin/git"; };
        });
        bootstrapTools = pkgs.closureInfo { rootPaths = [ bootstrapManifest pkgs.python3 pkgs.bash pkgs.coreutils pkgs.nix operatorSsh pkgs.git pkgs.cacert ]; };
        bootstrapClosure = pkgs.linkFarm "omux-bazel-bootstrap-closure" [
          { name = "native.json"; path = bootstrapManifest; }
          { name = "store-paths"; path = "${bootstrapTools}/store-paths"; }
          { name = "registration"; path = "${bootstrapTools}/registration"; }
        ];
        zigSdk = pkgs.stdenvNoCC.mkDerivation {
          pname = "zig-sdk"; version = "0.17.0";
          src = pkgs.fetchurl { url = zigAsset.tarball; sha256 = zigAsset.shasum; };
          dontConfigure = true; dontBuild = true; dontFixup = true;
          installPhase = "mkdir -p $out; cp -r zig lib $out/; mkdir -p $out/bin; ln -s ../zig $out/bin/zig";
        };
      in {
        packages.zig-sdk = zigSdk;
        packages.bazel-closure = bazelClosure;
        packages.bazel-bootstrap-closure = bootstrapClosure;
        packages.codex-upstream-tool-archives = codexToolArchives;
        devShells = {
          default = pkgs.mkShell {
            JAVA_HOME = "${pkgs.jdk_headless}";
            packages = [ bazelisk pkgs.bazel_9 pkgs.bash pkgs.coreutils pkgs.python3 pkgs.git pkgs.nodejs pkgs.zip pkgs.unzip pkgs.pkg-config pkgs.stdenv.cc ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.qt6.qtbase ];
            shellHook = ''
              export USE_BAZEL_VERSION="${pkgs.bazel_9.version}"
              export OMUX_ZIG_SDK="${zigSdk}"
              export OMUX_BAZEL_CLOSURE="${bazelClosure}"
              export OMUX_BAZEL_BOOTSTRAP_CLOSURE="${bootstrapClosure}"
            '';
          };
        } // pkgs.lib.optionalAttrs (system == codexToolManifest.system) {
          codex-upstream = pkgs.mkShell {
            JAVA_HOME = "${pkgs.jdk_headless}";
            packages = [ (pkgs.writeShellScriptBin "bazelisk" ''exec ${pkgs.bazel_9}/bin/bazel --bazelrc=${codexSupplementalRc} "$@"'') pkgs.bazel_9 pkgs.bash pkgs.coreutils pkgs.python3 pkgs.git pkgs.gawk pkgs.gnugrep pkgs.gnused pkgs.findutils ];
            shellHook = ''
              export USE_BAZEL_VERSION="${pkgs.bazel_9.version}"
              export OMUX_CODEX_TEST_PATH="${codexTestPath}"
              export OMUX_CODEX_TOOL_ARCHIVES="${codexToolArchives}"
              export OMUX_CODEX_BAZELRC="${codexSupplementalRc}"
            '';
          };
        };
      }) // {
        homeManagerModules.omux = import ./nix/home-manager.nix;
        lib.consumeBazelArtifact = args: import ./nix/consume-bazel-artifact.nix args;
      };
}
