# Real Home Manager module evaluation only. Caller must first verify BOTH locked
# source NARs through declared Bazel actions. No activation package is forced,
# no generated file is read, and no derivation is realized.
{ pkgs, homeManagerSource, artifactDirectory, artifactNarHash,
  artifactSourceRevision, channel ? "development" }:
let
  lib = pkgs.lib;
  package = (import ./consume-bazel-artifact.nix { inherit pkgs lib; }) {
    inherit artifactDirectory channel;
    narHash = artifactNarHash;
    sourceRevision = artifactSourceRevision;
  };
  identity = if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  unitName = "${identity}.service";
  evaluation = import (homeManagerSource + "/modules") {
    inherit pkgs;
    configuration = {
      imports = [ ./home-manager.nix ];
      home.username = "omux-evaluation";
      home.homeDirectory = "/home/omux-evaluation";
      home.stateVersion = "26.05";
      programs.omux.enable = true;
      programs.omux.instances.${channel} = {
        enable = true;
        inherit package;
        # Synthetic exact extension ID; never enrolls a source or calls provider.
        extensionId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      };
    };
  };
  config = evaluation.config;
  desktop = config.xdg.desktopEntries.${identity};
  host = builtins.fromJSON config.xdg.configFile."chromium/NativeMessagingHosts/${identity}.json".text;
  suffix = if channel == "development" then "-dev" else "";
  launcherRoot = lib.removeSuffix "/bin/omux-native-host${suffix}" host.path;
  unit = config.systemd.user.services.${identity};
  witness = import ./service-witness.nix {
    inherit lib channel unitName unit;
    artifactManifestSha256 = package.manifestSha256;
    installedPath = "${config.xdg.configHome}/systemd/user/${unitName}";
    sourcePath = config.xdg.configFile."systemd/user/${unitName}".source;
    loginPath = "${config.xdg.configHome}/systemd/user/default.target.wants/${unitName}";
  };
in
assert builtins.elem channel [ "development" "release" ];
assert config.xdg.configFile."systemd/user/default.target.wants/${unitName}".source
  == config.xdg.configFile."systemd/user/${unitName}".source;
assert config.xdg.configFile ? "omux/instances/${channel}/service.json";
assert desktop.name == (if channel == "development" then "Omux (Development)" else "Omux");
assert desktop.exec == "${launcherRoot}/bin/omux-control${suffix}";
assert desktop.icon == "network-server" && desktop.terminal == false
  && desktop.categories == [ "Utility" "Network" ];
{
  scope = "genuine-module-evaluation-only";
  activation = "unproved";
  generatedBytes = "unrealized-unverified";
  inherit channel unitName;
  serviceWitness = witness.record;
  artifactManifestSha256 = package.manifestSha256;
  # Preserve source context/dependencies; do not discard it in production data.
  recordSource = config.xdg.configFile."omux/instances/${channel}/service.json".source;
}
