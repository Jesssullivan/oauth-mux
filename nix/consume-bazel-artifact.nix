# Consume an already verified, extracted Bazel delivery bundle. No compiler,
# download, archive extraction or recursive Bazel bootstrap runs here.
{ pkgs, lib ? pkgs.lib }:
{ artifactDirectory, narHash, sourceRevision, channel ? "development" }:
let
  root = builtins.path {
    path = artifactDirectory;
    name = "omux-bazel-artifact";
    sha256 = narHash;
  };
  manifest = builtins.fromJSON (builtins.readFile (root + "/release-manifest.json"));
  manifestSha256 = builtins.hashString "sha256" (builtins.readFile (root + "/release-manifest.json"));
  required = [ "bin/omux" "bin/omuxd" "bin/omux-native-host" "bin/omux-control" ];
  paths = map (entry: entry.path) manifest.artifacts;
  checkedEntry = entry:
    builtins.match "[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*" entry.path != null
    && builtins.all (part: part != "." && part != "..") (lib.splitString "/" entry.path)
    && builtins.match "[0-9a-f]{64}" entry.sha256 != null
    && builtins.elem entry.mode [ "0755" "0644" ]
    && builtins.pathExists (root + "/${entry.path}");
  valid = manifest.schemaVersion == 1
    && (manifest.channel or null) == channel
    && builtins.length manifest.artifacts <= 256
    && manifest.target == pkgs.stdenv.hostPlatform.system
    && manifest.distribution == "portable-linux"
    && manifest.product.status == "experimental"
    && manifest.provenance.sourceRevision == sourceRevision
    && builtins.match "[0-9a-f]{40,64}" sourceRevision != null
    && builtins.all checkedEntry manifest.artifacts
    && builtins.length (lib.unique paths) == builtins.length paths
    && builtins.all (path: builtins.elem path paths && builtins.pathExists (root + "/${path}")) required
    && builtins.elem channel [ "development" "release" ]
    && (channel == "development" || manifest.provenance.sourceDirty == false);
in
assert lib.assertMsg valid "Omux requires a digest-bound portable Linux Bazel bundle, matching source revision and explicit channel; release inputs must be clean.";
pkgs.runCommandNoCC "omux-bazel-${channel}-${builtins.substring 0 12 sourceRevision}" {
  # Nix only gives the immutable Bazel output a package interface. Portable
  # loaders and library layout remain byte-for-byte inside the imported root.
  passthru = {
    inherit manifest root channel sourceRevision narHash manifestSha256;
    omuxBazelArtifactSchemaVersion = 1;
  };
} ''
  mkdir -p "$out"
  ln -s ${root}/bin "$out/bin"
  ln -s ${root}/lib "$out/lib"
  ln -s ${root}/share "$out/share"
  ln -s ${root}/release-manifest.json "$out/release-manifest.json"
''
