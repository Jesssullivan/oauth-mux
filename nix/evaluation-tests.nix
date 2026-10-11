# Evaluation only; caller supplies the locked nixpkgs package set. Execute via a
# declared Bazel action, never as a standalone developer check.
{ pkgs }:
let
  lib = pkgs.lib;
  inherit (lib) mkOption types;
  package = channel: pkgs.runCommandNoCC "omux-evaluation-fixture-${channel}" {
    passthru = {
      inherit channel;
      omuxBazelArtifactSchemaVersion = 1;
      root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-omux-evaluation-artifact";
      narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      manifestSha256 = lib.concatStrings (lib.replicate 64 "b");
      sourceRevision = lib.concatStrings (lib.replicate 40 "c");
      manifest = {
        inherit channel;
        target = pkgs.stdenv.hostPlatform.system;
        distribution = "portable-linux";
        product.status = "experimental";
        provenance.sourceDirty = false;
        artifacts = [ { path = "bin/omux"; sha256 = lib.concatStrings (lib.replicate 64 "d"); mode = "0755"; size = 1; } ];
      };
    };
  } "mkdir -p $out";
  base = {
    options = {
      assertions = mkOption { type = types.listOf types.anything; default = []; };
      home.packages = mkOption { type = types.listOf types.package; default = []; };
      xdg.configFile = mkOption { type = types.attrsOf types.anything; default = {}; };
      xdg.stateHome = mkOption { type = types.str; default = "/home/evaluation/.local/state"; };
      xdg.configHome = mkOption { type = types.str; default = "/home/evaluation/.config"; };
      xdg.dataHome = mkOption { type = types.str; default = "/home/evaluation/.local/share"; };
      systemd.user.services = mkOption { type = types.attrsOf types.anything; default = {}; };
    };
  };
  defaults = {
    programs.omux.enable = true;
    programs.omux.instances = {
      development = { enable = true; package = package "development"; extensionId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; };
      release = { enable = true; package = package "release"; extensionId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; };
    };
  };
  # Synthetic generated sources model Home Manager's option surface only.
  # No derivation is realized and no service activation is represented here.
  modeledGeneratedUnits = { config, ... }: {
    xdg.configFile = lib.mapAttrs' (name: _: lib.nameValuePair "systemd/user/${name}.service" {
      source = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-modeled-unit/${name}.service";
    }) config.systemd.user.services;
  };
  evaluate = overrides: (lib.evalModules {
    specialArgs = { inherit pkgs; };
    modules = [ base ./home-manager.nix defaults modeledGeneratedUnits overrides ];
  }).config;
  config = evaluate {};
  literalConfigHome = "/home/evaluation/space 'quote\" percent%t";
  literalConfig = evaluate { xdg.configHome = lib.mkForce literalConfigHome; };
  literalScripts = (builtins.head literalConfig.home.packages).omuxLauncherScripts;
  allAssertions = config: builtins.all (item: item.assertion) config.assertions;
  # Test comparisons discard context only after production JSON construction.
  # Home Manager's actual text keeps its store dependency context intact.
  developmentHost = builtins.fromJSON (builtins.unsafeDiscardStringContext config.xdg.configFile."chromium/NativeMessagingHosts/ai.xoxd.omux.dev.json".text);
  releaseHost = builtins.fromJSON (builtins.unsafeDiscardStringContext config.xdg.configFile."chromium/NativeMessagingHosts/ai.xoxd.omux.json".text);
  rejectsDirectory = path: !(builtins.tryEval (builtins.deepSeq
    (evaluate { programs.omux.instances.development.chromiumConfigDirectories = lib.mkForce [ path ]; }).xdg.configFile true)).success;
  witness = import ./ownership-witness.nix {
    package = package "development";
    channel = "development";
    serviceName = "ai.xoxd.omux.dev";
    nativeHostName = "ai.xoxd.omux.dev";
    extensionId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    chromiumConfigDirectories = [ "chromium" ];
  };
  serviceWitness = import ./service-witness.nix {
    inherit lib;
    channel = "development";
    artifactManifestSha256 = (package "development").manifestSha256;
    unitName = "ai.xoxd.omux.dev.service";
    unit = config.systemd.user.services."ai.xoxd.omux.dev";
    installedPath = "/home/evaluation/.config/systemd/user/ai.xoxd.omux.dev.service";
    sourcePath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-modeled-unit/ai.xoxd.omux.dev.service";
    loginPath = "/home/evaluation/.config/systemd/user/default.target.wants/ai.xoxd.omux.dev.service";
  };
  deploymentConfig = evaluate {
    programs.omux.instances.development.nativeDeployment = {
      registeredPackageRoot = "/nix/store/registered-native-package";
      installationRoot = "/configured/space \"quote\" percent%t dollar$HOME";
    };
  };
  rejectsDeployment = value: !(builtins.tryEval (builtins.deepSeq
    (evaluate { programs.omux.instances.development.nativeDeployment = lib.mkForce value; })
    true)).success;
  tests = {
    explicitNativeDeploymentArguments = lib.hasSuffix
      '' daemon --native-package-root "/nix/store/registered-native-package" --native-installation-root "/configured/space \"quote\" percent%%t dollar$$HOME"''
      deploymentConfig.systemd.user.services."ai.xoxd.omux.dev".Service.ExecStart;
    nativeDeploymentIsInstanceScoped = deploymentConfig.systemd.user.services."ai.xoxd.omux".Service.ExecStart
      == config.systemd.user.services."ai.xoxd.omux".Service.ExecStart;
    nativeDeploymentNeverEntersEnvironment = deploymentConfig.systemd.user.services."ai.xoxd.omux.dev".Service.Environment
      == [ "XDG_RUNTIME_DIR=%t" ];
    nativeDeploymentDoesNotChangeLaunchers = builtins.map (item: item.omuxLauncherScripts) deploymentConfig.home.packages
      == builtins.map (item: item.omuxLauncherScripts) config.home.packages;
    oversizedNativeDeploymentRejected = rejectsDeployment {
      registeredPackageRoot = "/" + lib.concatStrings (lib.replicate 4096 "a");
      installationRoot = "/install";
    };
    partialNativeDeploymentRejected = rejectsDeployment { registeredPackageRoot = "/package"; };
    relativeNativeDeploymentRejected = rejectsDeployment { registeredPackageRoot = "relative"; installationRoot = "/install"; };
    traversalNativeDeploymentRejected = rejectsDeployment { registeredPackageRoot = "/package"; installationRoot = "/install/../other"; };
    delimiterNativeDeploymentRejected = rejectsDeployment { registeredPackageRoot = "/package"; installationRoot = "/install\nother"; };

    literalDaemonServiceRecord = lib.hasInfix
      "export OMUX_INSTALL_SERVICE_RECORD=${lib.escapeShellArg "${literalConfigHome}/omux/instances/development/service.json"}"
      literalScripts.omuxd;
    literalDaemonServicePath = lib.hasInfix
      "export OMUX_INSTALL_SERVICE_PATH=${lib.escapeShellArg "${literalConfigHome}/systemd/user/ai.xoxd.omux.dev.service"}"
      literalScripts.omuxd;
    literalPathsNeverEnterSystemdEnvironment = literalConfig.systemd.user.services."ai.xoxd.omux.dev".Service.Environment
      == [ "XDG_RUNTIME_DIR=%t" ];
    thinLaunchersDiscardServiceSelectors = builtins.all (binary:
      lib.hasInfix "unset OMUX_INSTALL_SERVICE_PATH OMUX_INSTALL_SERVICE_RECORD" literalScripts.${binary}
      && !(lib.hasInfix "export OMUX_INSTALL_SERVICE_PATH=" literalScripts.${binary}))
      [ "omux" "omux-native-host" "omux-control" ];
    automaticModeledServiceWitness = config.xdg.configFile ? "omux/instances/development/service.json"
      && config.xdg.configFile ? "omux/instances/release/service.json";
    modeledServiceWitnessScope = serviceWitness.record.scope == "definition-only-not-activation"
      && serviceWitness.record.instance == "dev" && serviceWitness.record.unit.mode == 420;
    modeledServiceDigest = serviceWitness.record.unit.sha256 == builtins.hashString "sha256" serviceWitness.unitText;
    modeledServiceManifestBinding = serviceWitness.record.artifactManifestSha256 == witness.record.artifact.manifestSha256;
    platformGate = if pkgs.stdenv.isLinux then allAssertions config else !allAssertions config;
    exactDevelopmentOrigin = developmentHost.allowed_origins == [ "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/" ];
    exactReleaseOrigin = releaseHost.allowed_origins == [ "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/" ];
    isolatedHostPaths = developmentHost.path != releaseHost.path && lib.hasSuffix "/omux-native-host-dev" developmentHost.path;
    isolatedServices = builtins.attrNames config.systemd.user.services == [ "ai.xoxd.omux" "ai.xoxd.omux.dev" ];
    explicitDaemonCommand = lib.hasSuffix "/omuxd-dev daemon" config.systemd.user.services."ai.xoxd.omux.dev".Service.ExecStart;
    privateServiceMask = config.systemd.user.services."ai.xoxd.omux.dev".Service.UMask == "0077";
    duplicateExtensionRejected = !allAssertions (evaluate {
      programs.omux.instances.release.extensionId = lib.mkForce "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    });
    channelMismatchRejected = !allAssertions (evaluate {
      programs.omux.instances.development.package = lib.mkForce (package "release");
    });
    parentComponentRejected = rejectsDirectory "chromium/../other";
    currentComponentRejected = rejectsDirectory "chromium/./other";
    absoluteDirectoryRejected = rejectsDirectory "/chromium";
    witnessHasAbsolutePayload = (builtins.head witness.record.files).path == "${(package "development").root}/bin/omux";
    witnessBindsManifestDigest = witness.record.artifact.manifestSha256 == (package "development").manifestSha256;
    witnessBindsChannelAndSource = witness.record.artifact.channel == "development"
      && witness.record.artifact.sourceRevision == (package "development").sourceRevision;
    witnessIncludesManifestFile = builtins.length witness.record.files == 2
      && (builtins.elemAt witness.record.files 1).path == "${(package "development").root}/release-manifest.json";
    witnessDoesNotClaimObservedService = witness.record.userService == null
      && witness.record.desired.installedBindings == "require-independent-inspection";
    witnessInspectableBothChannels = config.xdg.configFile ? "omux/instances/development/installation.json"
      && config.xdg.configFile ? "omux/instances/release/installation.json";
  };
in
assert lib.assertMsg (builtins.all (result: result) (builtins.attrValues tests))
  "Omux declarative module evaluation predicates failed";
tests
