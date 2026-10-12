# PRIVATE CANDIDATE INTERFACE. Not exported by flake.nix; no Darwin support claim.
# Import final post-sign app bytes and verify the whole envelope. No compiler,
# app rewrite, resigning, download, extraction or Home Manager activation.
{ pkgs, lib ? pkgs.lib }:
{ artifactDirectory, narHash, sourceRevision, channel ? "development" }:
let
  root = builtins.path {
    path = artifactDirectory;
    name = "omux-darwin-final-${channel}";
    sha256 = narHash;
  };
  manifestText = builtins.readFile (root + "/darwin-artifact.json");
  manifest = builtins.fromJSON manifestText;
  manifestSha256 = builtins.hashString "sha256" manifestText;
  app = "${root}/Omux.app";
  cli = "${app}/Contents/MacOS/omux";
  daemon = "${app}/Contents/MacOS/omuxd";
  nativeHost = "${app}/Contents/MacOS/omux-native-host";
  control = "${app}/Contents/MacOS/Omux";
  cliRuntime = "${app}/Contents/MacOS/omux-runtime";
  daemonRuntime = "${app}/Contents/MacOS/omux-daemon-runtime";
  controlRuntime = "${app}/Contents/MacOS/OmuxControls";
  suffix = if channel == "development" then "-dev" else "";
  validator = pkgs.writeText "omux-darwin-artifact-validator.py"
    (builtins.readFile ../tools/darwin_artifact/artifact.py);
  macho = pkgs.writeText "omux-declared-macho.py" (builtins.readFile ../tools/macho.py);
  valid = pkgs.stdenv.hostPlatform.system == "aarch64-darwin"
    && builtins.elem channel [ "development" "release" ]
    && builtins.match "[0-9a-f]{40}" sourceRevision != null
    && builtins.match "sha256-[A-Za-z0-9+/]{43}=" narHash != null
    && manifest.schemaVersion == 1
    && manifest.distribution == "experimental-darwin-app"
    && manifest.target == "aarch64-darwin"
    && manifest.channel == channel
    && manifest.stage == "final-post-sign-inventory"
    && manifest.channelBinding.kind == "compiled-entrypoints-v1"
    && manifest.channelBinding.instance == (if channel == "development" then "dev" else "default")
    && manifest.source.revision == sourceRevision
    && (channel == "development" || manifest.source.dirty == false)
    && manifest.capabilityLimits.appleAcceptance == "unproved"
    && manifest.capabilityLimits.installedPlatform == "unproved"
    && manifest.capabilityLimits.nativePeer == "unsupported"
    && manifest.capabilityLimits.serviceObservation == "unsupported";
in
assert lib.assertMsg valid "Omux Darwin candidate requires final post-sign aarch64 app bytes, exact NAR/source/channel and honest unproved platform limits.";
pkgs.runCommandNoCC "omux-darwin-candidate-${channel}-${builtins.substring 0 12 sourceRevision}" {
  passthru = {
    inherit root manifest manifestSha256 narHash sourceRevision channel app cli daemon nativeHost control
      cliRuntime daemonRuntime controlRuntime;
    omuxDarwinArtifactSchemaVersion = 1;
    artifactQualificationScope = "artifact-bytes-only-not-platform-proof";
  };
} ''
  ${pkgs.python3}/bin/python3 -I -B ${validator} \
    --macho ${macho} --root ${root} --nar-hash ${lib.escapeShellArg narHash} \
    --source-revision ${lib.escapeShellArg sourceRevision} --channel ${lib.escapeShellArg channel} \
    > "$TMPDIR/omux-darwin-byte-validation.json"
  mkdir -p "$out/bin" "$out/Applications" "$out/share/omux"
  ln -s ${cli} "$out/bin/omux${suffix}"
  ln -s ${daemon} "$out/bin/omuxd${suffix}"
  ln -s ${nativeHost} "$out/bin/omux-native-host${suffix}"
  ln -s ${control} "$out/bin/omux-control${suffix}"
  ln -s ${app} "$out/Applications/Omux${suffix}.app"
  ln -s ${root}/darwin-artifact.json "$out/share/omux/darwin-artifact.json"
  cp "$TMPDIR/omux-darwin-byte-validation.json" "$out/share/omux/artifact-byte-validation.json"
''
