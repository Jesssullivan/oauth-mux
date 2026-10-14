# Isolated experimental Darwin definition. Deliberately not exported as
# homeManagerModules.omux; its Linux gate remains unchanged until actual proof.
{ config, lib, pkgs, ... }:
let
  inherit (lib) mkOption mkEnableOption types mkIf;
  cfg = config.programs.omuxDarwinCandidate;
  channels = lib.filterAttrs (_: instance: instance.enable) cfg.instances;
  identity = channel: if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  suffix = channel: if channel == "development" then "-dev" else "";
  recordDirectory = channel: "Library/Preferences/Omux/instances/${channel}";
  browserRelative = browser: "Library/Application Support/${browser}/NativeMessagingHosts";
  definitions = import ./darwin-launchd-definition.nix { inherit lib pkgs; agents = config.launchd.agents; };
  installations = lib.mapAttrs (channel: instance: import ./darwin-ownership-witness.nix {
    inherit channel;
    inherit (instance) package extensionId browserDirectories;
    homeDirectory = config.home.homeDirectory;
    identity = identity channel;
  }) channels;
  services = lib.mapAttrs (channel: instance: import ./darwin-service-witness.nix {
    inherit channel;
    homeDirectory = config.home.homeDirectory;
    artifactManifestSha256 = instance.package.manifestSha256;
    agent = config.launchd.agents.${identity channel}.config;
    sourcePath = definitions.agentPlists."${identity channel}.plist";
    plistText = definitions.texts.${identity channel};
    wrapped = definitions.wrapped.${identity channel};
    postExecImage = instance.package.daemonRuntime;
  }) channels;
  registration = channel: instance: {
    name = identity channel;
    description = "Omux ${channel} restricted host (experimental Darwin Home Manager candidate)";
    # A genuinely channel-bound Mach-O launcher, with exact native-host mode.
    # JSON has no argv/env facility; a browser's environment is not authority.
    path = instance.package.nativeHost;
    type = "stdio";
    allowed_origins = [ "chrome-extension://${instance.extensionId}/" ];
  };
  browserFiles = lib.foldlAttrs (acc: channel: instance:
    acc // lib.listToAttrs (map (browser: {
      name = "${browserRelative browser}/${identity channel}.json";
      value = { text = builtins.toJSON (registration channel instance); force = false; };
    }) instance.browserDirectories)) {} channels;
  recordFiles = lib.foldlAttrs (acc: channel: _: acc // {
    "${recordDirectory channel}/darwin-installation.json" = {
      text = installations.${channel}.jsonText; force = false;
    };
    "${recordDirectory channel}/darwin-service.json" = {
      text = services.${channel}.jsonText; force = false;
    };
  }) {} channels;
  appFiles = lib.mapAttrs' (channel: instance:
    lib.nameValuePair "Applications/Omux${suffix channel}.app" {
      source = instance.package.app; recursive = false; force = false;
    }) channels;
  # Pinned HM preserves changed removal copies, but its update path copies a
  # changed target. Check our own old-generation custody BEFORE writeBoundary
  # and before any HM bootout/install. This is a preflight snapshot, not an
  # atomic protection against a concurrent same-user mutation or activation proof.
  custody = lib.concatMapStringsSep "\n" (channel:
    let
      label = identity channel;
      selected = cfg.enable && builtins.hasAttr channel channels;
      installed = "${config.home.homeDirectory}/Library/LaunchAgents/${label}.plist";
      marker = "${recordDirectory channel}/darwin-installation.json";
    in ''
      (
        oldAgent=""
        if [[ -n "''${oldGenPath:-}" && -e "$oldGenPath/home-files/${marker}" ]]; then
          oldAgent="$oldGenPath/LaunchAgents/${label}.plist"
          if [[ ! -f "$oldAgent" ]]; then
            echo "Omux Darwin candidate old generated agent is missing; refusing activation" >&2
            exit 1
          fi
        fi
        if [[ ${if selected then "1" else "0"} == 1 || -n "$oldAgent" ]]; then
          installed=${lib.escapeShellArg installed}
          if [[ -e "$installed" || -L "$installed" ]]; then
            if [[ -L "$installed" || ! -f "$installed" || -z "$oldAgent" ]] ||
              [[ "$(${pkgs.coreutils}/bin/stat -c '%u %a %h' -- "$installed")" != "$UID 444 1" ]] ||
              ! ${pkgs.diffutils}/bin/cmp -s -- "$oldAgent" "$installed"; then
              echo "Omux Darwin candidate LaunchAgent is unmanaged or changed; refusing activation" >&2
              exit 1
            fi
          fi
        fi
      )
    '') [ "release" "development" ];
in {
  options.programs.omuxDarwinCandidate = {
    enable = mkEnableOption "isolated unqualified Darwin Omux Home Manager candidate";
    instances = lib.genAttrs [ "release" "development" ] (_: mkOption {
      default = {};
      type = types.submodule {
        options = {
          enable = mkEnableOption "this channel-bound Darwin candidate instance";
          package = mkOption {
            type = types.package;
            description = "Unmodified digest/NAR-bound consume-darwin-bazel-artifact.nix result with compiled channel-bound signed entrypoints. Apple acceptance remains separately unproved.";
          };
          extensionId = mkOption {
            type = types.strMatching "[a-p]{32}";
            description = "One exact authorized channel Chromium extension ID; no wildcard origins.";
          };
          browserDirectories = mkOption {
            type = types.listOf (types.enum [ "Google/Chrome" "Chromium" ]);
            default = [ "Google/Chrome" ];
            description = "Explicit macOS user browser locations beneath Library/Application Support; actual selected-browser proof is separate.";
          };
        };
      };
    });
  };
  config = lib.mkMerge [
    {
      # Retain a removed generation's own check while the module remains imported.
      home.activation.omuxDarwinCandidateCustody = lib.hm.dag.entryBefore [ "writeBoundary" ] custody;
    }
    (mkIf cfg.enable {
      assertions = [ {
        assertion = pkgs.stdenv.hostPlatform.system == "aarch64-darwin";
        message = "The isolated Omux Darwin candidate starts with aarch64-darwin; no other platform is qualified by this module.";
      } {
        assertion = !(config.programs.omux.enable or false);
        message = "Darwin candidate must remain separate from the exported Linux Omux module.";
      } {
        assertion = !(channels ? release && channels ? development)
          || channels.release.extensionId != channels.development.extensionId;
        message = "Darwin development and release require different exact extension IDs.";
      } ] ++ lib.mapAttrsToList (channel: instance:
        let root = toString instance.package.root;
          binary = "${root}/Omux.app/Contents/MacOS/";
          agent = config.launchd.agents.${identity channel}.config;
        in {
          assertion = (instance.package.omuxDarwinArtifactSchemaVersion or null) == 1
            && instance.package.channel == channel && instance.package.manifest.channel == channel
            && instance.package.manifest.target == "aarch64-darwin"
            && instance.package.manifest.distribution == "experimental-darwin-app"
            && instance.package.manifest.stage == "final-post-sign-inventory"
            && instance.package.manifest.channelBinding.kind == "compiled-entrypoints-v1"
            && instance.package.manifest.channelBinding.instance == (if channel == "development" then "dev" else "default")
            && instance.package.manifest.channelBinding.roles == {
              Omux = "OmuxControls"; omux = "omux-runtime";
              omuxd = "omux-daemon-runtime"; "omux-native-host" = "omux-runtime";
            }
            && instance.package.cli == binary + "omux"
            && instance.package.daemon == binary + "omuxd"
            && instance.package.nativeHost == binary + "omux-native-host"
            && instance.package.control == binary + "Omux"
            && instance.package.cliRuntime == binary + "omux-runtime"
            && instance.package.daemonRuntime == binary + "omux-daemon-runtime"
            && instance.package.controlRuntime == binary + "OmuxControls"
            && instance.package.app == "${root}/Omux.app"
            && agent.Label == identity channel && agent.Program == null
            && agent.ProgramArguments == [ instance.package.daemon "daemon" ]
            && agent.EnvironmentVariables == {
              HOME = config.home.homeDirectory;
              OMUX_INSTANCE = if channel == "development" then "dev" else "default";
            }
            && agent.RunAtLoad == true && builtins.isAttrs agent.KeepAlive
            && lib.filterAttrs (_: value: value != null) agent.KeepAlive == { SuccessfulExit = false; }
            && agent.ThrottleInterval == 10 && agent.Umask == 63
            && agent.ProcessType == "Background" && config.launchd.enable
            && builtins.length instance.browserDirectories > 0
            && builtins.length (lib.unique instance.browserDirectories) == builtins.length instance.browserDirectories;
          message = "Darwin ${channel} requires exact channel artifact, entrypoints, private LaunchAgent and browser definitions; metadata is not Apple or activation proof.";
        }) channels;
      # Retain the consumer DERIVATION, not just its raw root passthru paths.
      # Realizing the HM generation must run its full byte/Mach-O validator.
      # The consumer already exposes collision-free -dev bin aliases.
      home.packages = lib.mapAttrsToList (_: instance: instance.package) channels;
      home.file = browserFiles // recordFiles // appFiles;
      launchd.agents = lib.mapAttrs' (channel: instance:
        lib.nameValuePair (identity channel) {
          enable = true;
          config = {
            Label = identity channel;
            ProgramArguments = [ instance.package.daemon "daemon" ];
            EnvironmentVariables = {
              HOME = config.home.homeDirectory;
              OMUX_INSTANCE = if channel == "development" then "dev" else "default";
            };
            RunAtLoad = true;
            KeepAlive.SuccessfulExit = false;
            ThrottleInterval = 10;
            Umask = 63;
            ProcessType = "Background";
          };
        }) channels;
    })
  ];
}
