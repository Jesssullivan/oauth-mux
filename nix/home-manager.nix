{ config, lib, pkgs, ... }:
let
  inherit (lib) mkOption mkEnableOption types mkIf;
  cfg = config.programs.omux;
  channels = lib.filterAttrs (_: instance: instance.enable) cfg.instances;
  identity = channel: if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  witnesses = lib.mapAttrs (channel: instance:
    let witness = import ./ownership-witness.nix {
      package = instance.package;
      inherit channel;
      serviceName = identity channel;
      nativeHostName = identity channel;
      inherit (instance) extensionId chromiumConfigDirectories;
    };
    in pkgs.writeText "omux-${channel}-installation.json" witness.jsonText) channels;
  launchers = lib.mapAttrs (channel: instance:
    let
      suffix = if channel == "development" then "-dev" else "";
      selected = if channel == "development" then "dev" else "default";
      script = binary: ''
        # Immutable instance binding; native history and HOME stay in place.
        export OMUX_INSTANCE=${selected}
        # Non-authoritative startup hints: the daemon collector verifies the
        # immutable witness, payload bytes and its executable before readiness.
        export OMUX_INSTALL_PREFIX=${lib.escapeShellArg (toString instance.package.root)}
        export OMUX_INSTALL_RECORD=${lib.escapeShellArg (toString witnesses.${channel})}
        ${if binary == "omuxd" then ''
          # Literal paths belong in the immutable launcher: systemd Environment
          # tokenization and percent specifiers must not rewrite selectors.
          export OMUX_INSTALL_SERVICE_RECORD=${lib.escapeShellArg "${config.xdg.configHome}/omux/instances/${channel}/service.json"}
          export OMUX_INSTALL_SERVICE_PATH=${lib.escapeShellArg "${config.xdg.configHome}/systemd/user/${identity channel}.service"}
        '' else "unset OMUX_INSTALL_SERVICE_PATH OMUX_INSTALL_SERVICE_RECORD"}
        export XDG_STATE_HOME=${lib.escapeShellArg config.xdg.stateHome}
        export XDG_CONFIG_HOME=${lib.escapeShellArg config.xdg.configHome}
        export XDG_DATA_HOME=${lib.escapeShellArg config.xdg.dataHome}
        exec ${instance.package}/bin/${binary} "$@"
      '';
      scripts = lib.genAttrs [ "omux" "omuxd" "omux-native-host" "omux-control" ] script;
    in pkgs.symlinkJoin {
      name = "omux-${channel}-instance-launchers";
      paths = lib.mapAttrsToList (binary: text: pkgs.writeShellScriptBin "${binary}${suffix}" text) scripts;
      passthru.omuxLauncherScripts = scripts;
    }) channels;
  registration = channel: instance: {
    name = identity channel;
    description = "Omux ${channel} native messaging host (Home Manager owned)";
    path = "${launchers.${channel}}/bin/omux-native-host${if channel == "development" then "-dev" else ""}";
    type = "stdio";
    allowed_origins = [ "chrome-extension://${instance.extensionId}/" ];
  };
  browserFiles = lib.foldlAttrs (acc: channel: instance:
    acc // lib.listToAttrs (map (browser: {
      name = "${browser}/NativeMessagingHosts/${identity channel}.json";
      value.text = builtins.toJSON (registration channel instance);
    }) instance.chromiumConfigDirectories)) {} channels;
  witnessFiles = lib.mapAttrs' (channel: _:
    lib.nameValuePair "omux/instances/${channel}/installation.json" {
      source = witnesses.${channel};
    }) channels;
  serviceRecordFiles = lib.mapAttrs' (channel: instance:
    let
      unitName = "${identity channel}.service";
      installedPath = "${config.xdg.configHome}/systemd/user/${unitName}";
      witness = import ./service-witness.nix {
        inherit lib channel unitName installedPath;
        artifactManifestSha256 = instance.package.manifestSha256;
        unit = config.systemd.user.services.${identity channel};
        # This source is supplied by the genuine Home Manager systemd module.
        # The lightweight evaluation harness must not manufacture that proof.
        sourcePath = config.xdg.configFile."systemd/user/${unitName}".source;
        loginPath = "${config.xdg.configHome}/systemd/user/default.target.wants/${unitName}";
      };
    in lib.nameValuePair "omux/instances/${channel}/service.json" {
      source = pkgs.writeText "omux-${channel}-service.json" witness.jsonText;
    }) channels;
in {
  options.programs.omux = {
    enable = mkEnableOption "declarative Omux fleet installation";
    instances = lib.genAttrs [ "release" "development" ] (_: mkOption {
      default = {};
      type = types.submodule {
        options = {
          enable = mkEnableOption "this isolated Omux instance";
          package = mkOption {
            type = types.package;
            description = "Digest-bound package returned by consume-bazel-artifact.nix; no source builds.";
          };
          extensionId = mkOption {
            type = types.strMatching "[a-p]{32}";
            description = "One exact Chromium extension ID; no wildcard origin enrollment.";
          };
          chromiumConfigDirectories = mkOption {
            type = types.listOf (types.addCheck
              (types.strMatching "[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")
              (path: builtins.all (part: part != "." && part != "..") (lib.splitString "/" path)));
            default = [ "chromium" ];
            description = "Browser directories relative to XDG_CONFIG_HOME; registration is declaratively owned.";
          };
        };
      };
    });
  };
  config = mkIf cfg.enable {
    assertions = [ {
      assertion = pkgs.stdenv.isLinux;
      message = "Omux Home Manager delivery currently supports Linux only; Darwin activation remains unproved.";
    } {
      assertion = !(channels ? development && channels ? release) || channels.development.extensionId != channels.release.extensionId;
      message = "Omux development and release must use different exact Chromium extension IDs.";
    } ] ++ lib.mapAttrsToList (channel: instance: {
      assertion = (instance.package.channel or null) == channel
        && (instance.package.omuxBazelArtifactSchemaVersion or null) == 1;
      message = "Omux ${channel} package must come from the matching digest-bound Bazel consumer.";
    }) channels;
    home.packages = builtins.attrValues launchers;
    xdg.configFile = browserFiles // witnessFiles // serviceRecordFiles;
    systemd.user.services = lib.mapAttrs' (channel: instance:
      lib.nameValuePair (identity channel) {
        Unit = { Description = "Omux ${channel} resident account daemon"; After = [ "dbus.service" ]; };
        Service = {
          ExecStart = "${launchers.${channel}}/bin/omuxd${if channel == "development" then "-dev" else ""} daemon";
          Restart = "on-failure";
          RestartSec = 3;
          UMask = "0077";
          Environment = [ "XDG_RUNTIME_DIR=%t" ];
        };
        Install.WantedBy = [ "default.target" ];
      }) channels;
  };
}
