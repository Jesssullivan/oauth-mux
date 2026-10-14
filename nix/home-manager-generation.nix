# Derive the first actual HM activation proposal. This expression neither activates
# it nor establishes an installed account, service manager or browser journey.
{ nixpkgsSource, homeManagerSource, artifactDirectory, artifactNarHash,
  artifactSourceRevision, channel, modules }:
let
  pkgs = import nixpkgsSource { system = "x86_64-linux"; config = {}; overlays = []; };
  package = (import (modules + "/consume-bazel-artifact.nix") { inherit pkgs; }) {
    inherit artifactDirectory channel;
    narHash = artifactNarHash;
    sourceRevision = artifactSourceRevision;
  };
  evaluation = import (homeManagerSource + "/modules") {
    inherit pkgs;
    configuration = {
      imports = [ (modules + "/home-manager.nix") ];
      home.username = "omux-generation-proof";
      home.homeDirectory = "/home/omux-generation-proof";
      home.stateVersion = "26.05";
      programs.omux.enable = true;
      programs.omux.instances.${channel} = {
        enable = true;
        inherit package;
        extensionId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      };
    };
  };
  config = evaluation.config;
  identity = if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  generation = config.home.activationPackage;
in
assert builtins.elem channel [ "development" "release" ];
assert config.xdg.configFile."systemd/user/default.target.wants/${identity}.service".source
  == config.xdg.configFile."systemd/user/${identity}.service".source;
assert config.xdg.configFile ? "omux/instances/${channel}/service.json";
{
  drvPath = generation.drvPath;
  outputPath = generation.outPath;
  inherit channel identity;
  scope = "isolated-home-manager-generation-derivation-only";
}
