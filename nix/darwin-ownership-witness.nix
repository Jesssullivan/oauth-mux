# A distinct Darwin desired-definition record, never a Linux ownership proof.
{ package, channel, homeDirectory, extensionId, browserDirectories, identity }:
let
  root = toString package.root;
  instance = if channel == "development" then "dev" else "default";
  state = "${homeDirectory}/Library/Application Support/Omux${if channel == "development" then "-dev" else ""}";
  record = {
    schemaVersion = 1;
    kind = "omux-darwin-home-manager-definition-v1";
    owner = "home-manager";
    scope = "definition-only-not-installed-or-activation";
    inherit channel instance;
    artifact = {
      inherit root;
      packageInterfacePath = toString package;
      inherit (package) narHash manifestSha256 sourceRevision;
      target = package.manifest.target;
      appleAcceptance = "unproved";
    };
    entrypoints = { inherit (package) cli daemon nativeHost control app; };
    postExecImages = { inherit (package) cliRuntime daemonRuntime controlRuntime; };
    desired = {
      label = identity;
      nativeHostName = identity;
      inherit extensionId browserDirectories state;
      sockets = map (name: "${state}/run/${name}.sock") [ "control" "browser" "adapter" ];
      keychainRoot = if instance == "dev" then "installation-dev-v1" else "installation-v1";
      configurationOwner = "home-manager";
      runtimeAuthority = "daemon-only";
      generationRollback = "deployment-only";
      removal = "installation-objects-only-separate-from-secret-deletion";
    };
    observedService = null;
    runtimeCollector = "darwin-live-binding-unimplemented";
  };
  jsonText = builtins.toJSON record;
in
assert builtins.elem channel [ "development" "release" ];
assert (package.omuxDarwinArtifactSchemaVersion or null) == 1;
assert package.channel == channel && package.manifest.channel == channel;
assert builtins.match "/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+" root != null;
assert identity == (if channel == "development" then "ai.xoxd.omux.dev" else "ai.xoxd.omux");
assert builtins.stringLength jsonText <= 16384;
{ inherit record jsonText; }
