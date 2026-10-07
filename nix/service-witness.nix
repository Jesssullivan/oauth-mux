# Mirrors the observed Home Manager systemd unit serializer. The caller passes
# FINAL merged module fields and its ACTUAL generated source path. Runtime byte
# verification, not this serializer assumption, establishes a matching unit.
{ lib, channel, artifactManifestSha256, unitName, unit, installedPath, sourcePath, loginPath }:
let
  identity = if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  filtered = lib.filterAttrs (_: section: section != {})
    (lib.mapAttrs (_: section: lib.filterAttrs (_: value: value != null && value != []) section) unit);
  unitText = lib.generators.toINI {
    listsAsDuplicateKeys = true;
    mkKeyValue = key: value:
      "${key}=${if builtins.isBool value then (if value then "true" else "false") else toString value}";
  } filtered;
  record = {
    schemaVersion = 1;
    owner = "home-manager";
    inherit channel artifactManifestSha256;
    instance = if channel == "development" then "dev" else "default";
    unit = {
      name = unitName;
      inherit installedPath sourcePath;
      sha256 = builtins.hashString "sha256" unitText;
      mode = 420;
    };
    login = { installedPath = loginPath; inherit sourcePath; };
    scope = "definition-only-not-activation";
  };
  jsonText = builtins.toJSON record;
in
assert builtins.elem channel [ "development" "release" ];
assert unitName == "${identity}.service";
assert builtins.match "[0-9a-f]{64}" artifactManifestSha256 != null;
assert builtins.baseNameOf (toString sourcePath) == unitName;
assert builtins.match "/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+" (builtins.dirOf (toString sourcePath)) != null;
assert builtins.stringLength unitText <= 65536 && builtins.stringLength jsonText <= 8192;
{ inherit unitText record jsonText; }
