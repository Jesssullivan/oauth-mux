"""Declared ad-hoc candidate producer. Operator Developer ID signing is separate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    for name in ["output", "receipt", "channel", "revision", "dirty", "artifact-module", "macho-module",
                 "bundle-module", "info", "helper", "product", "custody", "launcher-source",
                 "control-launcher", "cli-launcher", "daemon-launcher", "host-launcher", "control", "cli", "daemon"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    artifact = module("darwin_artifact", args.artifact_module)
    macho = module("macho", args.macho_module)
    bundle = module("declared_macos_bundle", args.bundle_module)
    artifact.require(args.channel in ("development", "release") and args.dirty in ("true", "false"), "selectors")
    custody = artifact.decode(Path(args.custody).read_bytes())
    bundle.validate_custody(custody)
    artifact.require(custody["system"] == "aarch64-darwin", "fixed architecture")
    version, numeric = bundle.product_version(args.product)
    roots = {"Omux": args.control_launcher, "omux": args.cli_launcher, "omuxd": args.daemon_launcher}
    extra = {"omux-native-host": args.host_launcher, "OmuxControls": args.control,
             "omux-runtime": args.cli, "omux-daemon-runtime": args.daemon}
    plan = bundle.plan_relocation(roots, custody, "arm64", channel_entrypoints=extra)
    with tempfile.TemporaryDirectory(prefix="omux-channel-app-") as temporary:
        app = Path(temporary) / "Omux.app"
        for directory in ("MacOS", "Resources", "Library/LaunchAgents"):
            (app / "Contents" / directory).mkdir(parents=True)
        info = plistlib.loads(Path(args.info).read_bytes())
        helper = plistlib.loads(Path(args.helper).read_bytes())
        identifier = "ai.xoxd.omux.dev.controls" if args.channel == "development" else "ai.xoxd.omux.controls"
        label = "ai.xoxd.omux.dev.daemon" if args.channel == "development" else "ai.xoxd.omux.daemon"
        info.update(CFBundleIdentifier=identifier, CFBundleExecutable="Omux",
                    CFBundleShortVersionString=numeric, OmuxProductVersion=version)
        helper.update(Label=label, AssociatedBundleIdentifiers=[identifier])
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info, sort_keys=True))
        (app / "Contents/Library/LaunchAgents" / (label + ".plist")).write_bytes(plistlib.dumps(helper, sort_keys=True))
        for name, source in (roots | extra).items():
            shutil.copyfile(source, app / "Contents/MacOS" / name)
            (app / "Contents/MacOS" / name).chmod(0o755)
        (app / "Contents/Resources/apple-toolchain-custody.json").write_bytes(Path(args.custody).read_bytes())
        binding = {"kind": "compiled-entrypoints-v1", "instance": "dev" if args.channel == "development" else "default",
                   "roles": artifact.ROLES, "sourceSha256": hashlib.sha256(Path(args.launcher_source).read_bytes()).hexdigest()}
        (app / "Contents/Resources/channel-binding.json").write_bytes(artifact.encoded(binding))
        bundle.relocate_and_sign(app, plan, custody)
        receipt = artifact.seal(str(app), args.output, args.revision, args.dirty == "true", args.channel,
                                version, macho.parse_macho)
    # This receipt is outside the NAR envelope; pin it independently. It contains
    # no signing key or account data and confers no activation/support authority.
    Path(args.receipt).write_bytes(artifact.encoded(receipt))


if __name__ == "__main__":
    main()
