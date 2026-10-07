# Pure metadata construction, not an installed ownership or activation proof.
# The caller supplies the digest-bound consumer package. Runtime collection must
# validate immutable record custody, actual payload hashes and the executable.
{ package, channel, serviceName, nativeHostName, extensionId, chromiumConfigDirectories }:
let
  root = toString package.root;
  manifest = package.manifest;
  numericMode = mode:
    if mode == "0755" then 493
    else if mode == "0644" then 420
    else throw "Omux witness only accepts declared delivery executable/data modes";
  record = {
    schemaVersion = 1;
    owner = "home-manager";
    prefix = root;
    artifact = {
      inherit channel;
      inherit (package) narHash manifestSha256 sourceRevision;
      inherit (manifest) target distribution;
      sourceDirty = manifest.provenance.sourceDirty;
      status = manifest.product.status;
    };
    files = map (entry: {
      path = "${root}/${entry.path}";
      inherit (entry) sha256 size;
      mode = numericMode entry.mode;
    }) manifest.artifacts ++ [ {
      path = "${root}/release-manifest.json";
      sha256 = package.manifestSha256;
      mode = 420;
    } ];
    # Home Manager's live service unit is a separate installed inspection gate;
    # no desired definition is promoted into observed service ownership here.
    userService = null;
    desired = {
      inherit serviceName nativeHostName extensionId chromiumConfigDirectories;
      configurationOwner = "home-manager";
      runtimeAuthority = "daemon-only";
      generationRollback = "deployment-only";
      installedBindings = "require-independent-inspection";
    };
  };
  jsonText = builtins.toJSON record;
in
assert builtins.match "/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+" root != null;
assert (package.omuxBazelArtifactSchemaVersion or null) == 1;
assert manifest.channel == channel && package.channel == channel;
assert builtins.length record.files <= 257;
assert builtins.stringLength jsonText <= 65536;
{ inherit record jsonText; }
