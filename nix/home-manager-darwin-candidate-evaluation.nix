# Real pinned Home Manager evaluation candidate. Input NARs and the signed
# artifact consumer must be qualified by declared actions before this entry.
# No activationPackage is realized or activated by evaluating this expression.
{ nixpkgsSource, homeManagerSource, artifactDirectory, artifactNarHash,
  artifactSourceRevision, channel ? "development",
  extensionId, homeDirectory ? "/Users/omux-evaluation" }:
let
  # Same exact root-followed Lab pair as home_manager_inputs.py; a locator or
  # metadata boolean does not substitute for these actual imported NAR pins.
  nixpkgsRoot = builtins.path {
    path = nixpkgsSource; name = "omux-darwin-pinned-nixpkgs";
    sha256 = "sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s=";
  };
  homeManagerRoot = builtins.path {
    path = homeManagerSource; name = "omux-darwin-pinned-home-manager";
    sha256 = "sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM=";
  };
  pkgs = import nixpkgsRoot { system = "aarch64-darwin"; config = {}; overlays = []; };
  lib = pkgs.lib;
  package = (import ./consume-darwin-bazel-artifact.nix { inherit pkgs; }) {
    inherit artifactDirectory channel;
    narHash = artifactNarHash;
    sourceRevision = artifactSourceRevision;
  };
  identity = if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  recordDirectory = "Library/Preferences/Omux/instances/${channel}";
  browserPath = "Library/Application Support/Google/Chrome/NativeMessagingHosts/${identity}.json";
  evaluation = import (homeManagerRoot + "/modules") {
    inherit pkgs;
    configuration = {
      imports = [ ./home-manager-darwin-candidate.nix ];
      home.username = "omux-evaluation";
      home.homeDirectory = homeDirectory;
      home.stateVersion = "26.05";
      programs.omuxDarwinCandidate.enable = true;
      programs.omuxDarwinCandidate.instances.${channel} = {
        enable = true; inherit package extensionId;
      };
    };
  };
  config = evaluation.config;
  definitions = import ./darwin-launchd-definition.nix {
    inherit lib pkgs; agents = config.launchd.agents;
  };
  # ONLY this outer evaluation result references actual generation objects.
  # A home.file witness never depends on activationPackage, avoiding a cycle.
  generation = config.home.activationPackage;
  homeRows = lib.genAttrs [ browserPath
    "${recordDirectory}/darwin-installation.json" "${recordDirectory}/darwin-service.json" ]
    (name: {
      source = toString config.home.file.${name}.source;
      text = config.home.file.${name}.text;
      kind = "regular";
    }) // {
      "Applications/Omux${if channel == "development" then "-dev" else ""}.app" = {
        source = package.app; text = null; kind = "directory";
      };
    };
in
assert pkgs.stdenv.hostPlatform.system == "aarch64-darwin";
assert builtins.elem channel [ "development" "release" ];
assert builtins.match "[a-p]{32}" extensionId != null;
assert builtins.hashString "sha256" (builtins.readFile (homeManagerRoot + "/modules/launchd/default.nix"))
  == "ea01f4bf0c66983fd45fa32f2ea49a2b00088d0653d77ebd94cf6f4e9029fb71";
assert lib.hasInfix ''ln -s "${definitions.agentsDrv}" $out/LaunchAgents'' config.home.extraBuilderCommands;
assert builtins.all (entry: entry.assertion) config.assertions;
{
  schemaVersion = 1;
  kind = "omux-darwin-home-manager-generation-definition-v1";
  scope = "genuine-pinned-darwin-home-manager-evaluation-only";
  activation = "unproved";
  generatedBytes = "unrealized-unverified";
  appleAcceptance = "unproved";
  runtimeCollector = "darwin-live-binding-unimplemented";
  # Both paths are ACTUAL public final HM objects, not manufactured home.file
  # LaunchAgent source attributes. Realization and link/byte inspection follow.
  generationPath = toString generation;
  generationDerivation = generation.drvPath;
  homeFilesPath = toString config.home-files;
  agentsPath = toString definitions.agentsDrv;
  agentSourcePath = toString definitions.agentPlists."${identity}.plist";
  agentText = definitions.texts.${identity};
  homeFiles = homeRows;
  inherit channel identity homeDirectory;
  desiredProgramArguments = config.launchd.agents.${identity}.config.ProgramArguments;
  generatedProgramArguments = definitions.wrapped.${identity}.ProgramArguments;
  artifact = { root = toString package.root; inherit (package) manifestSha256 narHash sourceRevision; };
  predicates = {
    actualPinnedAgentGenerationContext = lib.hasInfix
      ''ln -s "${definitions.agentsDrv}" $out/LaunchAgents'' config.home.extraBuilderCommands;
    exactNativeHostOrigin = (builtins.fromJSON config.home.file.${browserPath}.text).allowed_origins
      == [ "chrome-extension://${extensionId}/" ];
    exactSignedHostEntrypoint = (builtins.fromJSON config.home.file.${browserPath}.text).path == package.nativeHost;
    managedHomeFilesNoForce = builtins.all (name: !config.home.file.${name}.force) (builtins.attrNames homeRows);
    privateAndThrottled = config.launchd.agents.${identity}.config.Umask == 63
      && config.launchd.agents.${identity}.config.ThrottleInterval == 10;
    realGeneratedStoreWaitWrapper = definitions.wrapped.${identity}.ProgramArguments ==
      [ "/bin/sh" "-c" "/bin/wait4path /nix/store && exec ${lib.escapeShellArgs [ package.daemon "daemon" ]}" ];
  };
}
