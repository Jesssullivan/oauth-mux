# Final merged HM definition plus the real pinned serializer's expected object.
# Actual agentsDrv/plist bytes and installed user copy require separate inspection.
{ channel, artifactManifestSha256, homeDirectory, agent, sourcePath, plistText, wrapped, postExecImage }:
let
  identity = if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux";
  record = {
    schemaVersion = 1;
    kind = "omux-darwin-home-manager-launchagent-definition-v1";
    owner = "home-manager";
    scope = "expected-generated-definition-not-realized-or-activation";
    inherit channel artifactManifestSha256;
    instance = if channel == "development" then "dev" else "default";
    launchDomain = "gui/current-user-requires-live-inspection";
    plist = {
      name = "${identity}.plist";
      installedPath = "${homeDirectory}/Library/LaunchAgents/${identity}.plist";
      expectedSourcePath = toString sourcePath;
      expectedSha256 = builtins.hashString "sha256" plistText;
      expectedBytes = builtins.stringLength plistText;
      installedMode = 292; # Pinned HM copies a user-owned regular0444 file.
      generatedObject = "pinned-hm-serializer-derived-unrealized";
    };
    desiredAgent = agent;
    generatedAgent = wrapped;
    desiredPostExecImage = postExecImage;
    observedJob = null;
    signedPostExecImage = "requires-independent-live-inspection";
    readiness = "unproved";
  };
  jsonText = builtins.toJSON record;
in
assert builtins.elem channel [ "development" "release" ];
assert agent.Label == identity;
assert builtins.match "[0-9a-z]{32}-${builtins.replaceStrings [ "." ] [ "[.]" ] identity}[.]plist"
  (builtins.baseNameOf (toString sourcePath)) != null;
assert builtins.match "[0-9a-f]{64}" artifactManifestSha256 != null;
assert builtins.stringLength plistText <= 65536 && builtins.stringLength jsonText <= 32768;
{ inherit record jsonText; }
