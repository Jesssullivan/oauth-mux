"""Inert Mach-O byte models for the real seal/consumer. Darwin execution UNRUN."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import stat
import sys
import tempfile
import time
import unittest

import artifact

MACHO_PATH, BUNDLE_PATH, LAUNCHER_PATH = sys.argv[1:4]
del sys.argv[1:4]
PARSE = artifact.load_macho(MACHO_PATH)
_spec = importlib.util.spec_from_file_location("macho", MACHO_PATH)
_macho = importlib.util.module_from_spec(_spec)
sys.modules["macho"] = _macho
_spec.loader.exec_module(_macho)
_spec = importlib.util.spec_from_file_location("bundle_fixture", BUNDLE_PATH)
BUNDLE = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = BUNDLE
_spec.loader.exec_module(BUNDLE)
REVISION = "1" * 40


def macho(marker=b"", dependency="/usr/lib/libSystem.B.dylib", *, cpu=0x0100000C, version=14, filetype=2, install_id=None):
    name = dependency.encode() + b"\0"
    name += b"\0" * (-len(name) % 8)
    commands = struct.pack("<6I", 0xC, 24 + len(name), 24, 0, 0, 0) + name
    if install_id is not None:
        identity = install_id.encode() + b"\0"
        identity += b"\0" * (-len(identity) % 8)
        commands += struct.pack("<6I", 0xD, 24 + len(identity), 24, 0, 0, 0) + identity
    commands += struct.pack("<6I", 0x32, 24, 1, version << 16, version << 16, 0)
    offset = 32 + len(commands) + 16
    commands += struct.pack("<4I", 0x1D, 16, offset, 8)
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, filetype, 3 + int(install_id is not None), len(commands), 0, 0) + commands + b"FAKESIGN" + marker


class ArtifactModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.app = self.root / "selected.app"
        self.output = self.root / "sealed"
        self.channel = "development"
        self.make_app()

    def put(self, path, raw, mode=0o644):
        target = self.app / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        target.write_bytes(raw)
        target.chmod(mode)

    def make_app(self, channel="development"):
        instance = "dev" if channel == "development" else "default"
        identifier = "ai.xoxd.omux.dev.controls" if channel == "development" else "ai.xoxd.omux.controls"
        label = "ai.xoxd.omux.dev.daemon" if channel == "development" else "ai.xoxd.omux.daemon"
        for role, backend in artifact.ROLES.items():
            marker = f"OMUX_CHANNEL_BINDING_V1:{instance}:{role}:{backend}".encode()
            self.put("Contents/MacOS/" + role, macho(marker), 0o755)
        for backend in set(artifact.ROLES.values()):
            self.put("Contents/MacOS/" + backend, macho(), 0o755)
        self.put("Contents/Info.plist", plistlib.dumps({"CFBundleIdentifier": identifier,
            "CFBundleExecutable": "Omux", "LSMinimumSystemVersion": "14.0",
            "CFBundleShortVersionString": "0.2.0", "OmuxProductVersion": "0.2.0-dev"}))
        self.put("Contents/Library/LaunchAgents/" + label + ".plist", plistlib.dumps({"Label": label,
            "BundleProgram": "Contents/MacOS/omux", "ProgramArguments": ["omux", "daemon"],
            "AssociatedBundleIdentifiers": [identifier], "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 3, "Umask": 63}))
        self.put("Contents/_CodeSignature/CodeResources", plistlib.dumps({"fixture": "not a valid Apple signature"}))
        self.put("Contents/Resources/apple-toolchain-custody.json", artifact.encoded({"available": True,
            "system": "aarch64-darwin", "apple": {"sdk_version": "14.4", "swift_version": "5.10.1"}}))
        self.put("Contents/Resources/channel-binding.json", artifact.encoded({"kind": "compiled-entrypoints-v1",
            "instance": instance, "roles": artifact.ROLES, "sourceSha256": artifact.sha(Path(LAUNCHER_PATH).read_bytes())}))

    def seal(self, **options):
        args = dict(revision=REVISION, dirty=True, channel=self.channel, version="0.2.0-dev", parse_macho=PARSE)
        args.update(options)
        return artifact.seal(str(self.app), str(self.output), **args)

    def test_valid_final_bytes_and_wrong_selectors(self):
        receipt = self.seal()
        self.assertEqual(receipt["scope"], "artifact-bytes-only-not-platform-proof")
        self.assertEqual(receipt["signing"]["kind"], "ad-hoc-development")
        for nar, revision, channel in [("sha256-" + "A" * 43 + "=", REVISION, self.channel),
                                       (receipt["narHash"], "2" * 40, self.channel),
                                       (receipt["narHash"], REVISION, "release")]:
            with self.assertRaises(ValueError):
                artifact.verify(str(self.output), nar, revision, channel, PARSE)

    def test_each_entrypoint_channel_is_bound(self):
        for role, backend in artifact.ROLES.items():
            with self.subTest(role=role):
                target = self.app / "Contents/MacOS" / role
                before = target.read_bytes()
                target.write_bytes(macho(f"OMUX_CHANNEL_BINDING_V1:default:{role}:{backend}".encode()))
                with self.assertRaises(ValueError):
                    self.seal()
                target.write_bytes(before)
        self.assertFalse(self.output.exists())

    def test_tampered_byte_inventory_and_extra_object_refuse(self):
        receipt = self.seal()
        selected = self.output / "Omux.app/Contents/MacOS/omux-runtime"
        selected.write_bytes(selected.read_bytes() + b"changed after signing")
        with self.assertRaises(ValueError):
            artifact.verify(str(self.output), receipt["narHash"], REVISION, self.channel, PARSE)

    def test_unrecorded_empty_directory_and_symlink_refuse(self):
        receipt = self.seal()
        extra = self.output / "unexpected"
        extra.mkdir()
        with self.assertRaises(ValueError):
            artifact.verify(str(self.output), receipt["narHash"], REVISION, self.channel, PARSE)
        extra.rmdir()
        (self.output / "linked").symlink_to("Omux.app")
        with self.assertRaises(ValueError):
            artifact.verify(str(self.output), receipt["narHash"], REVISION, self.channel, PARSE)

    def test_external_dependency_architecture_and_target_refuse(self):
        target = "Contents/MacOS/omux-runtime"
        for raw in (macho(dependency="/nix/store/undeclared/lib.dylib"),
                    macho(cpu=0x01000007), macho(version=15), macho(dependency="@loader_path/../../outside")):
            with self.subTest(raw=artifact.sha(raw)):
                self.put(target, raw, 0o755)
                with self.assertRaises(ValueError):
                    self.seal()

    def test_relocated_dependency_and_signed_dylib(self):
        self.put("Contents/MacOS/omux-runtime", macho(dependency="@loader_path/../Frameworks/libfixture.dylib"), 0o755)
        self.put("Contents/Frameworks/libfixture.dylib", macho(filetype=6, install_id="@rpath/libfixture.dylib"), 0o755)
        self.seal()

    def test_release_dirty_refusal(self):
        self.make_app("release")
        # Remove the deliberately separate old development helper, since the
        # closed final app may contain only its selected channel's helper.
        (self.app / "Contents/Library/LaunchAgents/ai.xoxd.omux.dev.daemon.plist").unlink()
        with self.assertRaises(ValueError):
            self.seal(channel="release", dirty=True)
        self.seal(channel="release", dirty=False)

    def signing_receipt(self):
        nodes, _ = artifact.scan(str(self.app), time.monotonic() + artifact.MAX_SECONDS)
        nodes = [{"path": "Omux.app", "type": "directory", "mode": "0755"}] + [
            dict(n, path="Omux.app/" + n["path"]) for n in nodes]
        nodes.sort(key=lambda n: os.fsencode(n["path"]))
        result = {key: "3" * 64 for key in artifact.SIGNING_FIELDS}
        result.update(schemaVersion=1, kind="developer-id", teamIdentifier="ABCDEFGHIJ",
                      signingIdentifier="ai.xoxd.omux.dev.controls",
                      signedAppInventorySha256=artifact.sha(artifact.encoded(nodes)),
                      notarizationReceiptSha256=None, staplingReceiptSha256=None, gatekeeperReceiptSha256=None)
        return result

    def test_reported_signing_does_not_promote_apple_trust(self):
        receipt = self.seal(signing_receipt=artifact.encoded(self.signing_receipt()))
        self.assertEqual(receipt["signing"]["kind"], "developer-id-reported")
        manifest = artifact.decode((self.output / artifact.MANIFEST).read_bytes())
        self.assertEqual(manifest["capabilityLimits"]["appleAcceptance"], "unproved")
        self.assertEqual(manifest["capabilityLimits"]["nativePeer"], "unsupported")

    def test_pre_sign_inventory_cannot_authorize_changed_signed_output(self):
        receipt = self.signing_receipt()
        self.put("Contents/MacOS/omux-runtime", macho() + b"new signature bytes", 0o755)
        with self.assertRaises(ValueError):
            self.seal(signing_receipt=artifact.encoded(receipt))
        self.assertFalse(self.output.exists())

    def test_duplicate_metadata_fields_and_wrong_typed_dirty_refuse(self):
        with self.assertRaises(ValueError):
            artifact.decode(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises(ValueError):
            self.seal(dirty=1)

    def test_bool_size_cannot_impersonate_empty_file_inventory(self):
        self.put("Contents/Resources/empty.txt", b"")
        self.seal()
        target = self.output / artifact.MANIFEST
        manifest = artifact.decode(target.read_bytes())
        node = next(n for n in manifest["inventory"] if n["path"].endswith("/empty.txt"))
        node["size"] = False
        target.write_bytes(artifact.encoded(manifest))
        nodes, payloads = artifact.scan(str(self.output), time.monotonic() + artifact.MAX_SECONDS)
        altered_nar, _ = artifact.nar_hash(nodes, payloads)
        with self.assertRaises(ValueError):
            artifact.verify(str(self.output), altered_nar, REVISION, self.channel, PARSE)

    def test_existing_output_never_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"retain")
        with self.assertRaises(FileExistsError):
            self.seal()
        self.assertEqual(sentinel.read_bytes(), b"retain")

    def test_canonical_nar_empty_directory_vector(self):
        # Independent small canonical NAR vector, rather than asking the same
        # producer twice. Executable metadata is separately covered by tamper.
        words = [b"nix-archive-1", b"(", b"type", b"directory", b")"]
        raw = b"".join(struct.pack("<Q", len(w)) + w + b"\0" * (-len(w) % 8) for w in words)
        expected = "sha256-" + __import__("base64").b64encode(__import__("hashlib").sha256(raw).digest()).decode()
        self.assertEqual(artifact.nar_hash([], {}), (expected, len(raw)))

    def test_real_planner_legacy_alias_and_seven_independent_roots(self):
        sdk = "/nix/store/" + "0" * 32 + "-sdk"
        swift = "/nix/store/" + "1" * 32 + "-swift"
        custody = {"available": True, "system": "aarch64-darwin", "developer_dir": sdk,
            "apple": {"sdk": sdk + BUNDLE.SDK_SUFFIX, "swiftc": swift + "/bin/swiftc",
                      "sdk_version": "14.4", "swift_version": "5.10.1"},
            "store_paths": [sdk, swift], "tools": {}}
        for index, name in enumerate(("otool", "install_name_tool", "rcodesign"), 2):
            root = "/nix/store/" + str(index) * 32 + "-" + name
            custody["store_paths"].append(root)
            custody["tools"][name] = root + "/bin/" + name
        roots = {name: "/declared/" + name for name in ("Omux", "omux", "omuxd")}
        extra = {name: "/declared/" + name for name in ("omux-native-host", "OmuxControls", "omux-runtime", "omux-daemon-runtime")}
        read = lambda path: macho()
        canonical = lambda path: path
        legacy = BUNDLE.plan_relocation(roots, custody, "arm64", read_binary=read, canonicalize=canonical)
        alias = next(entry for entry in legacy.entries if entry.destination.endswith("/omux-native-host"))
        self.assertEqual(alias.source, roots["omux"])
        selected = BUNDLE.plan_relocation(roots, custody, "arm64", read_binary=read, canonicalize=canonical,
                                         channel_entrypoints=extra)
        self.assertEqual({entry.destination for entry in selected.entries},
                         {"Contents/MacOS/" + name for name in roots | extra})
        alias = next(entry for entry in selected.entries if entry.destination.endswith("/omux-native-host"))
        self.assertEqual(alias.source, extra["omux-native-host"])
        with self.assertRaises(ValueError):
            BUNDLE.plan_relocation(roots, custody, "arm64", channel_entrypoints={})

    def test_group_or_other_execute_never_promotes_owner_execute(self):
        pins = []
        for mode in (0o645, 0o654):
            with self.subTest(mode=oct(mode)):
                self.put("Contents/Resources/mode.txt", b"public mode fixture", mode)
                nodes, _ = artifact.scan(str(self.app), time.monotonic() + artifact.MAX_SECONDS)
                node = next(n for n in nodes if n["path"] == "Contents/Resources/mode.txt")
                self.assertEqual(node["mode"], "0644")
                self.output = self.root / ("sealed-mode-" + str(mode))
                receipt = self.seal()
                self.assertFalse((self.output / "Omux.app/Contents/Resources/mode.txt").stat().st_mode & stat.S_IXUSR)
                pins.append(receipt["narHash"])
        self.assertEqual(pins[0], pins[1])
        self.output = self.root / "not-owner-executable-host"
        (self.app / "Contents/MacOS/omux-native-host").chmod(0o645)
        with self.assertRaises(ValueError):
            self.seal()
        self.assertFalse(self.output.exists())

    def test_independent_regular_nonexec_and_exec_nar_vectors(self):
        import hashlib
        import base64
        for mode in ("0644", "0755"):
            with self.subTest(mode=mode):
                payload = b"regular fixture"
                words = [b"nix-archive-1", b"(", b"type", b"directory", b"entry", b"(",
                         b"name", b"payload", b"node", b"(", b"type", b"regular"]
                if mode == "0755":
                    words += [b"executable", b""]
                words += [b"contents", payload, b")", b")", b")"]
                raw = b"".join(struct.pack("<Q", len(w)) + w + b"\0" * (-len(w) % 8) for w in words)
                expected = "sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode()
                nodes = [{"path": "payload", "type": "regular", "mode": mode,
                          "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}]
                self.assertEqual(artifact.nar_hash(nodes, {"payload": payload}), (expected, len(raw)))


if __name__ == "__main__":
    unittest.main()
