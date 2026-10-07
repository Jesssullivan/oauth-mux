"""Linux-capable package contract tests; these do not compile or run SwiftUI."""

import copy
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile
import unittest
import zipfile

from macos_bundle import SDK_SUFFIX, archive_application, assemble, plan_relocation, product_version, validate_custody


SOURCE_INFO, SOURCE_HELPER, SOURCE_PRODUCT = sys.argv[1:]
sys.argv[1:] = []


class BundleContractTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "Omux.app"
        sdk = "/nix/store/00000000000000000000000000000000-apple-sdk-14.4"
        swift = "/nix/store/11111111111111111111111111111111-swift-wrapper-5.10.1"
        self.custody = {
            "system": "aarch64-darwin", "available": True, "developer_dir": sdk,
            "apple": {"sdk": sdk + SDK_SUFFIX, "sdk_version": "14.4", "swiftc": swift + "/bin/swiftc", "swift_version": "5.10.1"},
            "store_paths": [sdk, swift],
        }
        self.custody["tools"] = {}
        for index, name in enumerate(("otool", "install_name_tool", "rcodesign"), start=2):
            root = "/nix/store/" + str(index) * 32 + "-" + name
            self.custody["store_paths"].append(root)
            self.custody["tools"][name] = root + "/bin/" + name
        self.custody_path = self.root / "custody.json"
        self.custody_path.write_text(json.dumps(self.custody), encoding="utf-8")
        self.binaries = []
        for name in ("controls", "cli", "daemon"):
            path = self.root / name
            path.write_bytes(("declared-" + name).encode("ascii"))
            self.binaries.append(path)

    def build(self, helper=SOURCE_HELPER, product=SOURCE_PRODUCT, custody=None):
        assemble(self.output, *self.binaries, SOURCE_INFO, helper, product, custody or self.custody_path)

    def test_real_source_plists_and_product_assemble(self):
        self.build()
        contents = self.output / "Contents"
        with open(contents / "Info.plist", "rb") as handle:
            info = plistlib.load(handle)
        version, numeric = product_version(SOURCE_PRODUCT)
        self.assertEqual(info["OmuxProductVersion"], version)
        self.assertEqual(info["CFBundleShortVersionString"], numeric)
        self.assertEqual(info["CFBundleExecutable"], "Omux")
        self.assertEqual(info["LSMinimumSystemVersion"], "14.0")
        for source, name in zip(self.binaries, ("Omux", "omux", "omuxd")):
            installed = contents / "MacOS" / name
            self.assertEqual(installed.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o755)
            self.assertEqual(installed.stat().st_mtime, 0)
        helper = contents / "Library" / "LaunchAgents" / Path(SOURCE_HELPER).name
        with open(helper, "rb") as handle:
            self.assertEqual(plistlib.load(handle)["ProgramArguments"], ["omux", "daemon"])
        self.assertEqual((contents / "Resources" / "apple-toolchain-custody.json").read_bytes(), self.custody_path.read_bytes())
        self.assertIn("Assembly fixture", (contents / "Resources" / "development-bundle.txt").read_text())
        self.assertFalse((contents / "_CodeSignature").exists())

    def test_version_suffix_is_preserved_with_numeric_apple_version(self):
        product = self.root / "product.zig"
        product.write_text('pub const version = "8.7.6-dev+proof.2";\n', encoding="utf-8")
        self.build(product=product)
        with open(self.output / "Contents" / "Info.plist", "rb") as handle:
            info = plistlib.load(handle)
        self.assertEqual(info["CFBundleShortVersionString"], "8.7.6")
        self.assertEqual(info["OmuxProductVersion"], "8.7.6-dev+proof.2")

    def test_missing_or_invalid_version_cannot_emit_bundle(self):
        product = self.root / "product.zig"
        for source in ('// pub const version = "1.2.3";', 'pub const version = "future";'):
            with self.subTest(source=source):
                product.write_text(source, encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.build(product=product)
                self.assertFalse(self.output.exists())

    def test_helper_cannot_launch_an_unbundled_program(self):
        with open(SOURCE_HELPER, "rb") as handle:
            agent = plistlib.load(handle)
        agent["BundleProgram"] = "/usr/local/bin/omux"
        helper = self.root / Path(SOURCE_HELPER).name
        with open(helper, "wb") as handle:
            plistlib.dump(agent, handle)
        with self.assertRaisesRegex(ValueError, "bundled"):
            self.build(helper=helper)
        self.assertFalse(self.output.exists())


def fixture_macho(dependencies=(), rpaths=(), *, library=False, architecture="arm64", minimum=(14, 0, 0)):
    """Synthesize real load-command layouts independently of the planner."""
    commands = []
    if minimum is not None:
        version = minimum[0] << 16 | minimum[1] << 8 | minimum[2]
        commands.append(struct.pack("<6I", 0x32, 24, 1, version, 0x0E0400, 0))
    if library:
        dependencies = ("fixture-install-id",) + tuple(dependencies)
    for index, name in enumerate(dependencies):
        text = name.encode("utf-8") + b"\0"
        text += b"\0" * (-len(text) % 8)
        command = 0xD if library and index == 0 else 0xC
        commands.append(struct.pack("<6I", command, 24 + len(text), 24, 0, 0, 0) + text)
    for name in rpaths:
        text = name.encode("utf-8") + b"\0"
        size = (12 + len(text) + 7) & ~7
        commands.append(struct.pack("<3I", 0x8000001C, size, 12) + text + b"\0" * (size - 12 - len(text)))
    cpu = 0x0100000C if architecture == "arm64" else 0x01000007
    subtype = 0 if architecture == "arm64" else 3
    body = b"".join(commands)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 6 if library else 2, len(commands), len(body), 0, 0) + body


def fixture_universal(arm, intel):
    offset = 48
    return (struct.pack(">2I", 0xCAFEBABE, 2)
            + struct.pack(">5I", 0x0100000C, 0, offset, len(arm), 0)
            + struct.pack(">5I", 0x01000007, 3, offset + len(arm), len(intel), 0)
            + arm + intel)


class RelocationPlanningTest(unittest.TestCase):
    def setUp(self):
        BundleContractTest.setUp(self)
        self.roots = {name: "/declared/build/" + name for name in ("Omux", "omux", "omuxd")}
        self.files = {path: fixture_macho() for path in self.roots.values()}
        self.library_root = "/nix/store/" + "5" * 32 + "-runtime-a"
        self.other_root = "/nix/store/" + "6" * 32 + "-runtime-b"
        self.custody["store_paths"].extend((self.library_root, self.other_root))
        self.a = self.library_root + "/lib/liba.dylib"
        self.b = self.other_root + "/lib/libb.dylib"

    def canonical(self, path):
        if path not in self.files:
            raise FileNotFoundError("Synthetic fixture has no such input")
        return path

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError("Synthetic fixture has no such input")
        return self.files[path]

    def plan(self, sdk_exists=lambda path: False):
        return plan_relocation(self.roots, self.custody, "arm64", read_binary=self.read, canonicalize=self.canonical, sdk_file_exists=sdk_exists)

    def test_transitive_nix_dependencies_are_closed_and_deduplicated(self):
        self.files.update({path: fixture_macho((self.a,)) for path in self.roots.values()})
        self.files[self.a] = fixture_macho((self.b,), library=True)
        self.files[self.b] = fixture_macho(("/usr/lib/libSystem.B.dylib",), library=True)
        plan = self.plan()
        self.assertEqual(len(plan.entries), 5)
        self.assertEqual(plan.system_dependencies, ("/usr/lib/libSystem.B.dylib",))
        roots = [item for item in plan.entries if "/MacOS/" in item.destination]
        libraries = [item for item in plan.entries if "/Frameworks/" in item.destination]
        self.assertEqual(len(libraries), 2)
        self.assertTrue(all(item.changes[0][1].startswith("@loader_path/../Frameworks/") for item in roots))
        self.assertTrue(next(item for item in libraries if item.source == self.a).changes[0][1].startswith("@loader_path/"))
        self.assertTrue(all(item.install_id.startswith("@rpath/") for item in libraries))

    def test_rpath_lookup_inherits_the_executable_loader_chain(self):
        root_rpaths = (self.library_root + "/lib", self.other_root + "/lib")
        self.files.update({path: fixture_macho(("@rpath/liba.dylib",), root_rpaths) for path in self.roots.values()})
        self.files[self.a] = fixture_macho(("@rpath/libb.dylib",), library=True)
        self.files[self.b] = fixture_macho(library=True)
        plan = self.plan()
        self.assertEqual(len(plan.entries), 5)
        self.assertTrue(all(item.remove_rpaths == tuple(sorted(root_rpaths)) for item in plan.entries if "/MacOS/" in item.destination))

    def test_loader_relative_dependencies_are_resolved_before_relocation(self):
        nearby = self.library_root + "/lib/libnearby.dylib"
        self.files[self.roots["Omux"]] = fixture_macho((self.a,))
        self.files[self.a] = fixture_macho(("@loader_path/libnearby.dylib",), ("@loader_path",), library=True)
        self.files[nearby] = fixture_macho(library=True)
        self.assertEqual(len(self.plan().entries), 5)

    def test_dependency_cycles_are_finite(self):
        self.files[self.roots["Omux"]] = fixture_macho((self.a,))
        self.files[self.a] = fixture_macho((self.b,), library=True)
        self.files[self.b] = fixture_macho((self.a,), library=True)
        self.assertEqual(len(self.plan().entries), 5)

    def test_system_frameworks_are_retained_without_sdk_redistribution(self):
        framework = "/System/Library/Frameworks/SwiftUI.framework/Versions/A/SwiftUI"
        self.files[self.roots["Omux"]] = fixture_macho((framework,))
        plan = self.plan()
        self.assertEqual(len(plan.entries), 3)
        self.assertEqual(plan.system_dependencies, (framework,))

    def test_swift_runtime_fallback_requires_the_declared_sdk_stub(self):
        self.files[self.roots["Omux"]] = fixture_macho(("@rpath/libswiftCore.dylib",))
        with self.assertRaisesRegex(ValueError, "cannot be resolved"):
            self.plan()
        expected = self.custody["apple"]["sdk"] + "/usr/lib/swift/libswiftCore.tbd"
        plan = self.plan(sdk_exists=lambda path: path == expected)
        self.assertEqual(plan.system_dependencies, ("/usr/lib/swift/libswiftCore.dylib",))
        self.assertEqual(next(item for item in plan.entries if item.destination.endswith("/Omux")).changes,
                         (("@rpath/libswiftCore.dylib", "/usr/lib/swift/libswiftCore.dylib"),))

    def test_undeclared_or_mutable_runtime_libraries_are_rejected(self):
        for path in ("/opt/lib/library.dylib", "/nix/store/" + "7" * 32 + "-undeclared/lib/library.dylib", "/usr/lib/../../private/lib/library.dylib"):
            with self.subTest(path=path):
                self.files[path] = fixture_macho(library=True)
                self.files[self.roots["Omux"]] = fixture_macho((path,))
                with self.assertRaises(ValueError):
                    self.plan()

    def test_sdk_artifacts_cannot_be_bundled_as_runtime_libraries(self):
        path = self.custody["apple"]["sdk"] + "/usr/lib/libSynthetic.dylib"
        self.files[path] = fixture_macho(library=True)
        self.files[self.roots["Omux"]] = fixture_macho((path,))
        with self.assertRaisesRegex(ValueError, "SDK artifacts"):
            self.plan()

    def test_architecture_and_minimum_os_are_checked_for_each_dependency(self):
        self.files[self.roots["Omux"]] = fixture_macho((self.a,))
        for arguments, expected in (({"architecture": "x86_64"}, "architectures"), ({"minimum": (14, 1, 0)}, "deployment"), ({"minimum": None}, "deployment")):
            with self.subTest(arguments=arguments):
                self.files[self.a] = fixture_macho(library=True, **arguments)
                with self.assertRaisesRegex(ValueError, expected):
                    self.plan()

    def test_macos_14_dependency_and_older_deployment_metadata_are_accepted(self):
        self.files[self.roots["Omux"]] = fixture_macho((self.a,))
        for minimum in ((14, 0, 0), (13, 1, 0)):
            with self.subTest(minimum=minimum):
                self.files[self.a] = fixture_macho(library=True, minimum=minimum)
                plan = self.plan()
                self.assertEqual(len(plan.entries), 4)
                self.assertTrue(any(entry.source == self.a for entry in plan.entries))

    def test_missing_and_unknown_relative_dependencies_are_rejected(self):
        for path in (self.a, "@unknown/libSynthetic.dylib"):
            with self.subTest(path=path):
                self.files[self.roots["Omux"]] = fixture_macho((path,))
                with self.assertRaises(ValueError):
                    self.plan()

    def test_loader_context_conflicts_are_rejected(self):
        third_root = "/nix/store/" + "8" * 32 + "-runtime-c"
        self.custody["store_paths"].append(third_root)
        self.files[self.a] = fixture_macho(("@rpath/libb.dylib",), library=True)
        self.files[self.b] = fixture_macho(library=True)
        self.files[third_root + "/lib/libb.dylib"] = fixture_macho(library=True)
        self.files[self.roots["Omux"]] = fixture_macho((self.a,), (self.other_root + "/lib",))
        self.files[self.roots["omux"]] = fixture_macho((self.a,), (third_root + "/lib",))
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.plan()

    def test_universal_slices_require_architecture_compatible_dependencies(self):
        self.files[self.roots["Omux"]] = fixture_universal(
            fixture_macho((self.a,)), fixture_macho((self.a,), architecture="x86_64"))
        self.files[self.a] = fixture_macho(library=True)
        with self.assertRaisesRegex(ValueError, "architectures"):
            self.plan()
        self.files[self.a] = fixture_universal(
            fixture_macho(library=True), fixture_macho(library=True, architecture="x86_64"))
        self.assertEqual(len(self.plan().entries), 4)

    def test_universal_slices_with_different_rpaths_fail_closed(self):
        self.files[self.roots["Omux"]] = fixture_universal(
            fixture_macho(rpaths=(self.library_root + "/lib",)),
            fixture_macho(rpaths=(self.other_root + "/lib",), architecture="x86_64"))
        with self.assertRaisesRegex(ValueError, "architecture-specific"):
            self.plan()


class ArchiveContractTest(unittest.TestCase):
    setUp = BundleContractTest.setUp
    build = BundleContractTest.build

    def test_archive_rejects_an_assembly_only_fixture(self):
        self.build()
        with self.assertRaisesRegex(ValueError, "resource-sealed"):
            archive_application(self.output, self.root / "Omux.zip")

    def test_archive_preserves_executable_mode_and_stable_member_paths(self):
        self.build()
        seal = self.output / "Contents" / "_CodeSignature" / "CodeResources"
        seal.parent.mkdir()
        seal.write_bytes(plistlib.dumps({"files2": {}}))
        (self.output / "Contents" / "Resources" / "runtime-relocation.json").write_text("{}")
        first, second = self.root / "first.zip", self.root / "second.zip"
        archive_application(self.output, first)
        for file in self.output.rglob("*"):
            if file.is_file():
                os.utime(file, (42, 42))
        archive_application(self.output, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertTrue(all(path.startswith("Omux.app/") for path in archive.namelist()))
            self.assertEqual(stat.S_IMODE(archive.getinfo("Omux.app/Contents/MacOS/omux").external_attr >> 16), 0o755)
            self.assertEqual(archive.getinfo("Omux.app/Contents/MacOS/Omux").date_time, (1980, 1, 1, 0, 0, 0))

    def test_archive_rejects_symlink_escape(self):
        self.build()
        seal = self.output / "Contents" / "_CodeSignature" / "CodeResources"
        seal.parent.mkdir()
        seal.write_bytes(plistlib.dumps({}))
        (self.output / "Contents" / "Resources" / "runtime-relocation.json").write_text("{}")
        (self.output / "Contents" / "Resources" / "escape").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            archive_application(self.output, self.root / "Omux.zip")

    def test_mutable_or_incomplete_custody_is_rejected(self):
        cases = []
        for edit in (
            lambda value: value.update(available=False),
            lambda value: value.update(system="aarch64-linux"),
            lambda value: value["apple"].update(sdk="/Applications/Xcode.app/SDKs/MacOSX.sdk"),
            lambda value: value["apple"].update(swiftc="/usr/bin/swiftc"),
            lambda value: value.update(store_paths=[]),
            lambda value: value.update(developer_dir="/different-sdk"),
        ):
            value = copy.deepcopy(self.custody)
            edit(value)
            cases.append(value)
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                validate_custody(value)
        self.custody_path.write_text(json.dumps(cases[0]), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
