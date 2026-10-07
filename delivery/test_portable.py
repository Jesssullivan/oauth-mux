"""Bounded ELF and dependency-confinement tests; run via Bazel only."""
from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import portable


def elf(needed: tuple[str, ...] = (), rpath: tuple[str, ...] = (), interpreter: str | None = None,
        machine: int = 62) -> bytes:
    """Construct small ELF64 segment fixtures, independent of the host linker."""
    strings = bytearray(b"\0")
    references = []
    for tag, value in [(1, name) for name in needed] + [(29, ":".join(rpath)) for _ in [0] if rpath]:
        references.append((tag, len(strings)))
        strings.extend(value.encode() + b"\0")
    count = 2 + (interpreter is not None)
    dynamic_offset = 64 + 56 * count
    dynamic_size = 16 * (len(references) + 3)
    strings_offset = dynamic_offset + dynamic_size
    interp = b"" if interpreter is None else interpreter.encode() + b"\0"
    interp_offset = strings_offset + len(strings)
    length = interp_offset + len(interp)
    base = 0x400000
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, length, length, 4096)
    dynamic = struct.pack("<IIQQQQQQ", 2, 4, dynamic_offset, base + dynamic_offset, 0,
                          dynamic_size, dynamic_size, 8)
    phdrs = load + dynamic
    if interpreter is not None:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_offset, base + interp_offset, 0,
                             len(interp), len(interp), 1)
    entries = references + [(5, base + strings_offset), (10, len(strings)), (0, 0)]
    return header + phdrs + b"".join(struct.pack("<qQ", tag, value) for tag, value in entries) + strings + interp


class MetadataTest(unittest.TestCase):
    def test_segment_only_runtime_metadata_and_both_architectures(self) -> None:
        for machine in (62, 183):
            data = elf(("libc.so.6", "/declared/lib/libsqlite3.so.0"),
                       ("$ORIGIN", "/declared/lib"), "/declared/ld-linux.so.2", machine)
            self.assertEqual(portable.elf_metadata(data), {
                "needed": ["libc.so.6", "/declared/lib/libsqlite3.so.0"],
                "rpath": ["$ORIGIN", "/declared/lib"],
                "interpreter": "/declared/ld-linux.so.2", "machine": machine,
            })

    def test_non_elf_and_unsupported_class_endianness_and_machine(self) -> None:
        valid = elf()
        for data in (b"text", valid[:63], valid[:4] + b"\x01" + valid[5:],
                     valid[:5] + b"\x02" + valid[6:], elf(machine=40)):
            with self.subTest(prefix=data[:8]), self.assertRaises(ValueError):
                portable.elf_metadata(data)

    def test_truncated_tables_and_segments_are_rejected(self) -> None:
        valid = elf(("libc.so.6",), interpreter="/loader")
        for end in (64, 100, len(valid) - 1):
            with self.subTest(end=end), self.assertRaises(ValueError):
                portable.elf_metadata(valid[:end])
        data = bytearray(valid)
        struct.pack_into("<H", data, 56, 65535)
        with self.assertRaisesRegex(ValueError, "program-header"):
            portable.elf_metadata(data)

    def test_unterminated_and_outside_table_strings_are_rejected(self) -> None:
        data = bytearray(elf(("libc.so.6",)))
        data[-1] = ord("x")
        with self.assertRaisesRegex(ValueError, "unterminated"):
            portable.elf_metadata(data)
        data = bytearray(elf(("libc.so.6",)))
        struct.pack_into("<Q", data, 64 + 112 + 8, 999999)
        with self.assertRaisesRegex(ValueError, "string offset"):
            portable.elf_metadata(data)

    def test_ambiguous_string_table_and_missing_dynamic_terminator_are_rejected(self) -> None:
        data = bytearray(elf(("libc.so.6",)))
        dynamic_offset = 64 + 112
        struct.pack_into("<q", data, dynamic_offset + 32, 5)
        with self.assertRaisesRegex(ValueError, "unique"):
            portable.elf_metadata(data)
        data = bytearray(elf(("libc.so.6",)))
        struct.pack_into("<q", data, dynamic_offset + 48, 1)
        with self.assertRaisesRegex(ValueError, "unterminated"):
            portable.elf_metadata(data)

    def test_interpreter_embedded_terminator_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "termination"):
            portable.elf_metadata(elf(interpreter="/loader\0trailing"))

    def test_auxiliary_audit_and_loader_configuration_tags_are_rejected(self) -> None:
        for tag in (0x7FFFFFFF, 0x7FFFFFFD, 0x6FFFFEFC, 0x6FFFFEFB, 0x6FFFFEFA):
            data = bytearray(elf(("external.so",)))
            struct.pack_into("<q", data, 64 + 112, tag)
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "unsupported ELF auxiliary"):
                portable.elf_metadata(data)

    def test_explicit_file_limit_is_finite_and_does_not_expand_dynamic_strings(self) -> None:
        valid = elf(("libc.so.6",))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_bytes(valid)
            for bound in (None, False, True, 0, -1, 1.5, float("inf"), "512", 512 * 1024 * 1024 + 1):
                with self.subTest(bound=bound):
                    with self.assertRaisesRegex(ValueError, "finite runtime file byte limit"):
                        portable.elf_metadata(valid, max_bytes=bound)
                    with self.assertRaisesRegex(ValueError, "finite runtime file byte limit"):
                        portable._read(path, max_bytes=bound)
        oversized_strings = bytearray(valid)
        struct.pack_into("<Q", oversized_strings, 64 + 112 + 32 + 8, portable._MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, "unique bounded table"):
            portable.elf_metadata(oversized_strings, max_bytes=512 * 1024 * 1024)


class AssemblyTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.loader = self.write("ld-linux-x86-64.so.2", elf())
        self.libc = self.write("libc.so.6", elf(interpreter=str(self.loader)))
        self.sqlite = self.write("libsqlite3.so.0", elf(("libc.so.6",)))
        self.cli = self.write("cli", elf(("libsqlite3.so.0",), interpreter=str(self.loader)))
        self.daemon = self.write("daemon", elf(("libc.so.6",), interpreter=str(self.loader)))
        self.patchelf = self.write("patchelf", b"declared test tool")
        self.ca_bundle = self.write("ca-bundle.crt", b"-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n")
        self.runtime = [self.loader, self.libc, self.sqlite]

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    @staticmethod
    def patch_fixture(path: Path, info: dict, _: Path, backend: bool, rpath: str = "$ORIGIN") -> None:
        interpreter = portable._BACKEND_INTERPRETER if backend or info["interpreter"] is not None else None
        path.write_bytes(elf(tuple(Path(name).name for name in info["needed"]),
                             ("$ORIGIN/../lib" if backend else rpath,), interpreter, info["machine"]))

    def assemble(self, control: Path | None = None, qt_plugins: list[Path] | None = None,
                 resolution_witness: dict | None = None,
                 qt_runtime: list[Path] | None = None, *,
                 backend_max_bytes: int = portable._MAX_FILE, channel: str | None = None) -> tuple[dict, dict]:
        with mock.patch.object(portable, "_patch", side_effect=self.patch_fixture):
            return portable.assemble_linux(self.cli, self.daemon, self.runtime, self.patchelf,
                                             "x86_64-linux", self.ca_bundle, control, qt_plugins, resolution_witness,
                                             (qt_runtime if qt_runtime is not None else self.runtime) if control is not None else None,
                                             backend_max_bytes=backend_max_bytes, channel=channel)

    def enlarge(self, path: Path, size: int) -> None:
        # A sparse trailing region preserves real ELF segments without a large
        # test fixture in source, and default refusal happens before reading it.
        with path.open("r+b") as stream:
            stream.truncate(size)

    def test_backend_over_default_limit_requires_explicit_scoped_opt_in(self) -> None:
        self.enlarge(self.cli, portable._MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, "bounded regular files"):
            portable._read(self.cli)
        with self.assertRaisesRegex(ValueError, "bounded regular files"):
            self.assemble()
        payload = portable._read(self.cli, max_bytes=portable._MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, "bounded ELF"):
            portable.elf_metadata(payload)
        self.assertEqual(portable.elf_metadata(payload, max_bytes=portable._MAX_FILE + 1)["needed"],
                         ["libsqlite3.so.0"])
        del payload
        files, runtime = self.assemble(backend_max_bytes=512 * 1024 * 1024)
        self.assertEqual(portable.elf_metadata(files["lib/omux/libexec/omux.bin"])["needed"],
                         ["libsqlite3.so.0"])
        self.assertIn("lib/omux/lib/libc.so.6", runtime["dependencies"])

    def test_backend_opt_in_does_not_expand_library_loader_ca_or_qt(self) -> None:
        for path in (self.sqlite, self.loader, self.ca_bundle):
            original = path.read_bytes()
            self.enlarge(path, portable._MAX_FILE + 1)
            with self.subTest(role=path.name), self.assertRaisesRegex(ValueError, "bounded regular files"):
                self.assemble(backend_max_bytes=512 * 1024 * 1024)
            path.write_bytes(original)
        control, plugins = self.configure_qt()
        self.enlarge(control, portable._MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, "bounded regular files"):
            self.assemble(control, plugins, backend_max_bytes=512 * 1024 * 1024)

    def test_postpatch_backend_growth_remains_within_explicit_limit(self) -> None:
        def expanding_patch(path, info, tool, backend, rpath="$ORIGIN"):
            self.patch_fixture(path, info, tool, backend, rpath)
            if backend:
                self.enlarge(path, 1025)
        with mock.patch.object(portable, "_patch", side_effect=expanding_patch):
            with self.assertRaisesRegex(ValueError, "bounded regular files"):
                portable.assemble_linux(self.cli, self.daemon, self.runtime, self.patchelf,
                                       "x86_64-linux", self.ca_bundle, backend_max_bytes=1024)

    def test_same_path_backend_cache_cannot_expand_loader_authority(self) -> None:
        self.cli.write_bytes(elf(interpreter=str(self.cli)))
        self.enlarge(self.cli, portable._MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, "bounded regular files"):
            portable.assemble_linux(self.cli, self.cli, [self.cli], self.patchelf,
                                   "x86_64-linux", self.ca_bundle,
                                   backend_max_bytes=512 * 1024 * 1024)

    def test_assembly_rejects_nonfinite_or_overcap_backend_limits(self) -> None:
        for bound in (None, False, 0, -1, 1.5, float("inf"), 512 * 1024 * 1024 + 1):
            with self.subTest(bound=bound), self.assertRaisesRegex(ValueError, "finite runtime file byte limit"):
                self.assemble(backend_max_bytes=bound)

    def all_files(self, control: Path | None = None, qt_plugins: list[Path] | None = None,
                  resolution_witness: dict | None = None,
                  qt_runtime: list[Path] | None = None, channel: str | None = None) -> tuple[dict, dict]:
        files, runtime = self.assemble(control, qt_plugins, resolution_witness, qt_runtime, channel=channel)
        for name in ("share/omux/reference.json", "share/omux/services/omux.service.in",
                     "share/omux/services/dev.xoxd.omux.plist.in", "release-manifest.json", "SHA256SUMS"):
            files[name] = b"metadata"
        manifest = {"target": "x86_64-linux", "runtime": runtime}
        if channel is not None:
            manifest["channel"] = channel
        return files, manifest

    def test_runtime_only_verification_and_full_archive_metadata_remain_distinct(self) -> None:
        files, runtime = self.assemble(channel="development")
        manifest = {"target": "x86_64-linux", "runtime": runtime, "channel": "development"}
        portable.verify_linux_runtime(files, manifest)
        with self.assertRaisesRegex(ValueError, "missing or undeclared"):
            portable.verify_linux(files, manifest)
        complete, manifest = self.all_files(channel="development")
        documents = ("share/omux/reference.json", "share/omux/services/omux.service.in",
                     "share/omux/services/dev.xoxd.omux.plist.in", "release-manifest.json", "SHA256SUMS")
        for name in documents:
            missing = dict(complete)
            del missing[name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "missing or undeclared"):
                portable.verify_linux(missing, manifest)
        with self.assertRaisesRegex(ValueError, "missing or undeclared"):
            portable.verify_linux_runtime({**files, "unexpected": b"extra"}, manifest)
        absent = dict(files)
        del absent[runtime["loader"]]
        with self.assertRaisesRegex(ValueError, "missing or undeclared"):
            portable.verify_linux_runtime(absent, manifest)
        escaping = dict(files)
        escaping["lib/omux/libexec/omux.bin"] = elf(("undeclared.so",), ("$ORIGIN/../lib",), portable._BACKEND_INTERPRETER)
        with self.assertRaisesRegex(ValueError, "outside its process closure"):
            portable.verify_linux_runtime(escaping, manifest)

    def test_channel_relabel_or_unbound_launcher_cannot_pass_archive_verification(self) -> None:
        for channel, other in (("development", "release"), ("release", "development")):
            with self.subTest(channel=channel):
                files, manifest = self.all_files(channel=channel)
                portable.verify_linux(files, manifest)
                with self.assertRaisesRegex(ValueError, "confined launcher"):
                    portable.verify_linux(files, {**manifest, "channel": other})
                files["bin/omuxd"] = portable.linux_launcher(
                    Path(manifest["runtime"]["loader"]).name, "omuxd.bin")
                with self.assertRaisesRegex(ValueError, "confined launcher"):
                    portable.verify_linux(files, manifest)

    def configure_qt(self) -> tuple[Path, list[Path]]:
        core = self.write("libQt6Core.so.6", elf(("libc.so.6",)))
        gui = self.write("libQt6Gui.so.6", elf(("libQt6Core.so.6",)))
        xcb = self.write("libxcb.so.1", elf(("libc.so.6",)))
        self.runtime.extend([core, gui, xcb])
        control = self.write("control", elf(("libQt6Core.so.6",), interpreter=str(self.loader)))
        offscreen = self.write("platforms/libqoffscreen.so", elf(("libQt6Gui.so.6",)))
        platform = self.write("platforms/libqxcb.so", elf(("libQt6Gui.so.6", "libxcb.so.1")))
        return control, [platform, offscreen]

    def configure_qt_witness(self) -> tuple[Path, list[Path], dict]:
        control, plugins = self.configure_qt()
        full = self.write("full/libsystemd.so.0", elf(("libc.so.6", "libm.so.6"), (str(self.root),)))
        minimal = self.write("minimal/libsystemd.so.0", elf(("libc.so.6",), (str(self.root / "minimal"),)))
        self.runtime.extend([full, minimal, self.write("libm.so.6", elf(("libc.so.6",)))])
        control.write_bytes(elf(("libQt6Core.so.6", "libsystemd.so.0"), (str(full.parent),), str(self.loader)))
        plugins[0].write_bytes(elf(("libQt6Gui.so.6", "libxcb.so.1", "libsystemd.so.0"), (str(minimal.parent),)))
        witness = {"schemaVersion": 1, "scope": "native-qt-offscreen-startup-only", "target": "x86_64-linux",
                   "controlSha256": hashlib.sha256(control.read_bytes()).hexdigest(),
                   "libraries": [{"soname": full.name, "sha256": hashlib.sha256(full.read_bytes()).hexdigest(),
                                  "variants": sorted({hashlib.sha256(path.read_bytes()).hexdigest() for path in (full, minimal)})}]}
        return control, plugins, witness

    def test_transitive_closure_patch_and_aliases(self) -> None:
        self.runtime.append(self.write("unused.so", b"not an ELF input in the selected closure"))
        files, manifest = self.all_files()
        self.assertEqual(manifest["runtime"]["dependencies"], sorted("lib/omux/lib/" + path.name for path in self.runtime[:-1]))
        self.assertNotIn("lib/omux/lib/unused.so", files)
        for alias in ("oauth-mux", "omux-native-host", "git-credential-omux"):
            self.assertEqual(files["bin/omux"], files["bin/" + alias])
        self.assertIn(b'--argv0 "$0"', files["bin/omux"])
        self.assertIn(b"unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH", files["bin/omux"])
        self.assertIn(b"export OMUX_CA_BUNDLE", files["bin/omux"])
        self.assertEqual(files[manifest["runtime"]["caBundle"]], self.ca_bundle.read_bytes())
        self.assertNotIn(b"/nix/store", files["bin/omux"])
        portable.verify_linux(files, manifest)

    def test_missing_transitive_dependency_and_conflicting_duplicate_are_rejected(self) -> None:
        self.runtime.remove(self.libc)
        with self.assertRaisesRegex(ValueError, "missing libc"):
            self.assemble()
        self.runtime.append(self.libc)
        duplicate = self.write("other/libsqlite3.so.0", elf(("different.so",)))
        self.runtime.append(duplicate)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.assemble()

    def test_exact_rpath_disambiguates_declared_versions(self) -> None:
        duplicate = self.write("other/libsqlite3.so.0", elf(("different.so",)))
        self.runtime.append(duplicate)
        self.cli.write_bytes(elf(("libsqlite3.so.0",), (str(self.root),), str(self.loader)))
        files, runtime = self.all_files()
        portable.verify_linux(files, runtime)
        self.assertEqual(portable.elf_metadata(files["lib/omux/lib/libsqlite3.so.0"])["needed"], ["libc.so.6"])

    def test_absolute_needed_names_are_replaced(self) -> None:
        self.cli.write_bytes(elf((str(self.sqlite),), interpreter=str(self.loader)))
        files, runtime = self.all_files()
        portable.verify_linux(files, runtime)
        self.assertEqual(portable.elf_metadata(files["lib/omux/libexec/omux.bin"])["needed"], ["libsqlite3.so.0"])

    def test_symlink_dependency_alias_is_retained(self) -> None:
        actual = self.sqlite.with_name("libsqlite3.so.0.8.6")
        self.sqlite.rename(actual)
        self.sqlite.symlink_to(actual.name)
        files, runtime = self.all_files()
        self.assertIn("lib/omux/lib/libsqlite3.so.0", files)
        portable.verify_linux(files, runtime)

    def test_undeclared_absolute_alias_cannot_acquire_dependency_provenance(self) -> None:
        alias = self.root / "undeclared" / self.sqlite.name
        alias.parent.mkdir()
        alias.symlink_to(self.sqlite)
        self.cli.write_bytes(elf((str(alias),), interpreter=str(self.loader)))
        with self.assertRaisesRegex(ValueError, "exact declared runtime dependency is missing"):
            self.assemble()

    def test_undeclared_rpath_alias_cannot_disambiguate_versions(self) -> None:
        duplicate = self.write("other/libsqlite3.so.0", elf(("different.so",)))
        self.runtime.append(duplicate)
        alias = self.root / "undeclared-directory"
        alias.symlink_to(self.sqlite.parent, target_is_directory=True)
        self.cli.write_bytes(elf((self.sqlite.name,), (str(alias),), str(self.loader)))
        with self.assertRaisesRegex(ValueError, "ambiguous declared runtime dependency"):
            self.assemble()

    def test_declared_file_chain_retains_intermediate_library_alias(self) -> None:
        # Mirror linux-sandbox's individual file link to a Nix split-output
        # alias, whose final link points into a separate library output.
        intermediate = self.root / "immutable-gcc-lib" / "lib" / self.sqlite.name
        intermediate.parent.mkdir(parents=True)
        intermediate.symlink_to(self.sqlite)
        declared = self.root / "sandbox-runtime" / self.sqlite.name
        declared.parent.mkdir()
        declared.symlink_to(intermediate)
        duplicate = self.write("other/libsqlite3.so.0", elf(("different.so",)))
        self.runtime = [self.loader, self.libc, declared, duplicate]
        for needed, rpath in ((str(intermediate), ()),
                              (self.sqlite.name, (str(intermediate.parent),))):
            with self.subTest(needed=Path(needed).name, absolute=needed.startswith("/")):
                self.cli.write_bytes(elf((needed,), rpath, str(self.loader)))
                files, runtime = self.all_files()
                portable.verify_linux(files, runtime)
                self.assertEqual(portable.elf_metadata(files["lib/omux/lib/libsqlite3.so.0"])["needed"],
                                 ["libc.so.6"])

    def test_wrong_target_and_library_machine_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "supported Linux"):
            portable.assemble_linux(self.cli, self.daemon, self.runtime, self.patchelf,
                                     "aarch64-macos", self.ca_bundle)
        self.sqlite.write_bytes(elf(("libc.so.6",), machine=183))
        with self.assertRaisesRegex(ValueError, "machine"):
            self.assemble()

    def test_aarch64_closure_has_aarch64_loader_and_machine(self) -> None:
        loader = self.write("ld-linux-aarch64.so.1", elf(machine=183))
        self.libc.write_bytes(elf(interpreter=str(loader), machine=183))
        self.sqlite.write_bytes(elf(("libc.so.6",), machine=183))
        self.cli.write_bytes(elf(("libsqlite3.so.0",), interpreter=str(loader), machine=183))
        self.daemon.write_bytes(elf(("libc.so.6",), interpreter=str(loader), machine=183))
        with mock.patch.object(portable, "_patch", side_effect=self.patch_fixture):
            files, runtime = portable.assemble_linux(self.cli, self.daemon, [loader, self.libc, self.sqlite],
                                                      self.patchelf, "aarch64-linux", self.ca_bundle)
        self.assertEqual(runtime["loader"], "lib/omux/lib/ld-linux-aarch64.so.1")
        for name, data in files.items():
            if name.startswith(("lib/omux/lib/", "lib/omux/libexec/")):
                self.assertEqual(portable.elf_metadata(data)["machine"], 183)

    def test_only_bounded_public_certificate_payloads_enter_the_runtime(self) -> None:
        for payload in (b"", b"not a certificate", b"-----BEGIN PRIVATE KEY-----\ncHVibGlj\n-----END PRIVATE KEY-----\n",
                        b"-----BEGIN CERTIFICATE-----\ninvalid***\n-----END CERTIFICATE-----\n"):
            self.ca_bundle.write_bytes(payload)
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                self.assemble()

    def test_ca_bundle_utf8_comments_preserve_ascii_certificate_payload_validation(self) -> None:
        valid = "# Public certificate: Ångström research\n".encode() + self.ca_bundle.read_bytes()
        self.ca_bundle.write_bytes(valid)
        files, manifest = self.all_files()
        self.assertEqual(files[manifest["runtime"]["caBundle"]], valid)
        portable.verify_linux(files, manifest)
        for invalid in (b"# invalid UTF-8: \xff\n" + valid,
                        valid.replace(b"cHVibGlj", "cHVi\u00c5bGlj".encode()),
                        valid.replace(b"cHVibGlj", "cHVi\u00a0bGlj".encode())):
            self.ca_bundle.write_bytes(invalid)
            with self.subTest(payload=invalid[:30]), self.assertRaises(ValueError):
                self.assemble()

    def test_mixed_plain_and_trusted_public_certificates_preserve_trust_payloads(self) -> None:
        trusted = b"-----BEGIN TRUSTED CERTIFICATE-----\ncHVibGljdHJ1c3Q=\n-----END TRUSTED CERTIFICATE-----\n"
        mixed = self.ca_bundle.read_bytes() + trusted
        self.ca_bundle.write_bytes(mixed)
        files, manifest = self.all_files()
        self.assertEqual(files[manifest["runtime"]["caBundle"]], mixed)
        portable.verify_linux(files, manifest)
        for invalid in (trusted.replace(b"END TRUSTED CERTIFICATE", b"END CERTIFICATE"),
                        trusted.replace(b"BEGIN TRUSTED CERTIFICATE", b"BEGIN CERTIFICATE"),
                        trusted.replace(b"TRUSTED CERTIFICATE", b"PRIVATE KEY"),
                        trusted.replace(b"TRUSTED CERTIFICATE", b"CERTIFICATE REQUEST")):
            self.ca_bundle.write_bytes(invalid)
            with self.subTest(payload=invalid[:40]), self.assertRaises(ValueError):
                self.assemble()

    def test_verifier_rejects_external_lookup_missing_dependency_and_extra_payload(self) -> None:
        for altered in (
            elf(("/nix/store/undeclared/libc.so.6",), ("$ORIGIN",)),
            elf(("missing.so",), ("$ORIGIN",)),
            elf(("libc.so.6",), ("/nix/store/runtime/lib",)),
            elf(("libc.so.6",), ("$ORIGIN",), "/nix/store/runtime/loader"),
        ):
            files, manifest = self.all_files()
            files["lib/omux/lib/libsqlite3.so.0"] = altered
            with self.assertRaises(ValueError):
                portable.verify_linux(files, manifest)
        files, manifest = self.all_files()
        files["lib/omux/lib/extra.so"] = elf()
        with self.assertRaisesRegex(ValueError, "undeclared"):
            portable.verify_linux(files, manifest)

    def test_verifier_rejects_launcher_and_dependency_metadata_tampering(self) -> None:
        files, manifest = self.all_files()
        files["bin/git-credential-omux"] += b"unexpected shell code\n"
        with self.assertRaisesRegex(ValueError, "aliases"):
            portable.verify_linux(files, manifest)
        files, manifest = self.all_files()
        manifest["runtime"]["dependencies"].append("../escaped.so")
        with self.assertRaises(ValueError):
            portable.verify_linux(files, manifest)

    def test_optional_qt_control_includes_plugin_roots_and_their_dependencies(self) -> None:
        control, plugins = self.configure_qt()
        files, manifest = self.all_files(control, plugins)
        qt = manifest["runtime"]["qt"]
        self.assertEqual(qt, {
            "loader": "lib/omux/qt/lib/ld-linux-x86-64.so.2",
            "dependencies": sorted("lib/omux/qt/lib/" + name for name in (
                "ld-linux-x86-64.so.2", "libQt6Core.so.6", "libQt6Gui.so.6", "libc.so.6", "libxcb.so.1")),
            "control": "lib/omux/qt/libexec/omux-control.bin",
            "config": "lib/omux/qt/libexec/qt.conf",
            "plugins": ["lib/omux/qt/plugins/platforms/libqoffscreen.so", "lib/omux/qt/plugins/platforms/libqxcb.so"],
        })
        self.assertIn("lib/omux/qt/lib/libxcb.so.1", qt["dependencies"])
        self.assertNotIn("lib/omux/lib/libxcb.so.1", manifest["runtime"]["dependencies"])
        self.assertIn(b'QT_PLUGIN_PATH="$runtime/plugins"', files["bin/omux-control"])
        self.assertIn(b'QT_QPA_PLATFORM_PLUGIN_PATH="$runtime/plugins/platforms"', files["bin/omux-control"])
        self.assertEqual(files[qt["config"]], portable._QT_CONFIG_BYTES)
        for name in qt["plugins"]:
            self.assertEqual(portable.elf_metadata(files[name])["rpath"], ["$ORIGIN/../../lib"])
        portable.verify_linux(files, manifest)

    def test_qt_inputs_require_platform_plugins_and_a_control_binary(self) -> None:
        control, plugins = self.configure_qt()
        for binary, source_plugins in ((control, None), (None, plugins), (control, []),
                                        (control, plugins + [plugins[0]])):
            with self.subTest(binary=binary, count=len(source_plugins or [])), self.assertRaises(ValueError):
                self.assemble(binary, source_plugins)
        unsupported = self.write("imageformats/libqpng.so", elf(("libQt6Core.so.6",)))
        with self.assertRaisesRegex(ValueError, "category"):
            self.assemble(control, [unsupported])

    def test_missing_qt_plugin_dependency_is_rejected(self) -> None:
        control, plugins = self.configure_qt()
        self.runtime = [path for path in self.runtime if path.name != "libxcb.so.1"]
        with self.assertRaisesRegex(ValueError, "missing libxcb"):
            self.assemble(control, plugins)

    def test_qt_runtime_metadata_configuration_and_elf_lookup_tampering_are_rejected(self) -> None:
        control, plugins = self.configure_qt()
        for field in ("config", "wrapper", "plugin_rpath", "plugin_needed", "undeclared_plugin"):
            files, manifest = self.all_files(control, plugins)
            qt = manifest["runtime"]["qt"]
            if field == "config":
                files[qt["config"]] += b"Plugins=/nix/store/plugins\n"
            elif field == "wrapper":
                files["bin/omux-control"] += b"external plugin search\n"
            elif field == "plugin_rpath":
                files[qt["plugins"][0]] = elf(("libQt6Gui.so.6",), ("/nix/store/plugins",))
            elif field == "plugin_needed":
                files[qt["plugins"][0]] = elf(("undeclared.so",), (portable._QT_PLUGIN_RPATH,))
            else:
                files["lib/omux/qt/plugins/platforms/undeclared.so"] = elf()
            with self.subTest(field=field), self.assertRaises(ValueError):
                portable.verify_linux(files, manifest)

    def test_exact_native_witness_selects_only_the_audited_qt_variant(self) -> None:
        control, plugins, witness = self.configure_qt_witness()
        with self.assertRaisesRegex(ValueError, "conflicting runtime dependency libsystemd"):
            self.assemble(control, plugins)
        files, manifest = self.all_files(control, plugins, witness)
        archived = manifest["runtime"]["qt"]["resolutionWitness"]
        self.assertEqual(archived["controlSha256"], witness["controlSha256"])
        self.assertEqual(archived["scope"], "native-qt-offscreen-startup-only")
        self.assertEqual(archived["controlArtifact"], {
            "path": "lib/omux/qt/libexec/omux-control.bin",
            "sha256": hashlib.sha256(files["lib/omux/qt/libexec/omux-control.bin"]).hexdigest()})
        self.assertEqual(archived["libraries"][0]["sha256"], witness["libraries"][0]["sha256"])
        self.assertEqual(archived["libraries"][0]["artifact"], {
            "path": "lib/omux/qt/lib/libsystemd.so.0",
            "sha256": hashlib.sha256(files["lib/omux/qt/lib/libsystemd.so.0"]).hexdigest()})
        portable.verify_linux(files, manifest)

    def test_witness_rejects_changed_control_scope_target_and_missing_variant(self) -> None:
        for field in ("controlSha256", "scope", "target", "librarySha256"):
            control, plugins, witness = self.configure_qt_witness()
            if field == "controlSha256":
                control.write_bytes(control.read_bytes() + b"changed native control")
            elif field == "scope":
                witness["scope"] = "unproven-interactive-session"
            elif field == "target":
                witness["target"] = "aarch64-linux"
            else:
                witness["libraries"][0]["sha256"] = "0" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.assemble(control, plugins, witness)

    def test_witness_does_not_select_a_variant_for_cli_or_other_internal_collisions(self) -> None:
        control, plugins, witness = self.configure_qt_witness()
        self.cli.write_bytes(elf(("libsystemd.so.0",), (str(self.root / "minimal"),), str(self.loader)))
        files, manifest = self.all_files(control, plugins, witness)
        self.assertEqual(portable.elf_metadata(files["lib/omux/lib/libsystemd.so.0"])["needed"], ["libc.so.6"])
        self.assertEqual(portable.elf_metadata(files["lib/omux/qt/lib/libsystemd.so.0"])["needed"], ["libc.so.6", "libm.so.6"])
        portable.verify_linux(files, manifest)
        self.cli.write_bytes(elf(("libsqlite3.so.0",), interpreter=str(self.loader)))
        full = self.write("full/libextra.so.1", elf(("libc.so.6",), (str(self.root),)))
        minimal = self.write("minimal/libextra.so.1", elf(("libc.so.6",), (str(self.root / "minimal"),)))
        self.runtime.extend([full, minimal])
        control.write_bytes(elf(("libQt6Core.so.6", "libsystemd.so.0", "libextra.so.1"),
                                (str(full.parent),), str(self.loader)))
        plugins[0].write_bytes(elf(("libQt6Gui.so.6", "libsystemd.so.0", "libextra.so.1"), (str(minimal.parent),)))
        witness["controlSha256"] = hashlib.sha256(control.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "conflicting runtime dependency libextra"):
            self.assemble(control, plugins, witness)

    def test_orphan_duplicate_and_startup_abi_witness_entries_are_rejected(self) -> None:
        for soname in ("libc.so.6", "ld-linux-x86-64.so.2", "unused.so"):
            control, plugins, witness = self.configure_qt_witness()
            if soname == "unused.so":
                witness["libraries"].append({**witness["libraries"][0], "soname": soname})
            else:
                witness["libraries"][0]["soname"] = soname
            with self.subTest(soname=soname), self.assertRaises(ValueError):
                self.assemble(control, plugins, witness)
        control, plugins, witness = self.configure_qt_witness()
        witness["libraries"].append(dict(witness["libraries"][0]))
        with self.assertRaises(ValueError):
            self.assemble(control, plugins, witness)

    def test_witness_variant_custody_rejects_unrecorded_or_changed_candidates(self) -> None:
        control, plugins, witness = self.configure_qt_witness()
        unrecorded = self.write("third/libsystemd.so.0", elf(("libc.so.6",), ("/third/variant",)))
        self.runtime.append(unrecorded)
        with self.assertRaisesRegex(ValueError, "audited custody"):
            self.assemble(control, plugins, witness)
        self.runtime.remove(unrecorded)
        for variants in (["0" * 64], list(reversed(witness["libraries"][0]["variants"])),
                         witness["libraries"][0]["variants"] + ["0" * 64]):
            changed = {**witness, "libraries": [{**witness["libraries"][0], "variants": variants}]}
            with self.subTest(variants=variants), self.assertRaises(ValueError):
                self.assemble(control, plugins, changed)

    def test_archived_witness_binds_packaged_artifacts_without_replaying_native_audit(self) -> None:
        for field in ("controlArtifact", "libraryArtifact", "scope"):
            control, plugins, witness = self.configure_qt_witness()
            files, manifest = self.all_files(control, plugins, witness)
            archived = manifest["runtime"]["qt"]["resolutionWitness"]
            if field == "controlArtifact":
                archived["controlArtifact"]["sha256"] = "0" * 64
            elif field == "libraryArtifact":
                archived["libraries"][0]["artifact"]["sha256"] = "0" * 64
            else:
                archived["scope"] = "interactive-distro-proof"
            with self.subTest(field=field), self.assertRaises(ValueError):
                portable.verify_linux(files, manifest)

    def test_cli_and_qt_processes_keep_unequal_same_soname_dependencies_separate(self) -> None:
        control, plugins = self.configure_qt()
        cli_curl = self.write("cli-deps/libcurl.so.4", elf(("libc.so.6", "libsqlite3.so.0")))
        qt_curl = self.write("qt-deps/libcurl.so.4", elf(("libc.so.6", "libQt6Core.so.6")))
        self.runtime.extend([cli_curl, qt_curl])
        self.cli.write_bytes(elf(("libcurl.so.4",), (str(cli_curl.parent),), str(self.loader)))
        control.write_bytes(elf(("libcurl.so.4",), (str(qt_curl.parent),), str(self.loader)))
        files, manifest = self.all_files(control, plugins)
        self.assertEqual(portable.elf_metadata(files["lib/omux/lib/libcurl.so.4"])["needed"],
                         ["libc.so.6", "libsqlite3.so.0"])
        self.assertEqual(portable.elf_metadata(files["lib/omux/qt/lib/libcurl.so.4"])["needed"],
                         ["libc.so.6", "libQt6Core.so.6"])
        self.assertIn(b"runtime=$pkg_root/lib/omux/qt\n", files["bin/omux-control"])
        portable.verify_linux(files, manifest)

    def test_qt_edges_cannot_resolve_through_the_cli_dependency_namespace(self) -> None:
        control, plugins, witness = self.configure_qt_witness()
        files, manifest = self.all_files(control, plugins, witness)
        qt_library = "lib/omux/qt/lib/libm.so.6"
        files["lib/omux/lib/libm.so.6"] = files.pop(qt_library)
        manifest["runtime"]["dependencies"].append("lib/omux/lib/libm.so.6")
        manifest["runtime"]["dependencies"].sort()
        manifest["runtime"]["qt"]["dependencies"].remove(qt_library)
        with self.assertRaisesRegex(ValueError, "outside its process closure"):
            portable.verify_linux(files, manifest)

    def test_declared_process_closures_resolve_bare_sqlite_and_curl_sonames_independently(self) -> None:
        control, plugins = self.configure_qt()
        qt_libraries = [path for path in self.runtime if path.name.startswith("libQt") or path.name == "libxcb.so.1"]
        cli_curl = self.write("cli-deps/libcurl.so.4", elf(("libc.so.6",)))
        qt_sqlite = self.write("qt-deps/libsqlite3.so.0", elf(("libc.so.6", "libQt6Core.so.6")))
        qt_curl = self.write("qt-deps/libcurl.so.4", elf(("libc.so.6", "libQt6Core.so.6")))
        self.runtime = [self.loader, self.libc, self.sqlite, cli_curl]
        qt_runtime = [self.loader, self.libc, *qt_libraries, qt_sqlite, qt_curl]
        self.cli.write_bytes(elf(("libsqlite3.so.0", "libcurl.so.4"), interpreter=str(self.loader)))
        control.write_bytes(elf(("libQt6Core.so.6", "libsqlite3.so.0", "libcurl.so.4"), interpreter=str(self.loader)))
        files, manifest = self.all_files(control, plugins, qt_runtime=qt_runtime)
        for soname in ("libsqlite3.so.0", "libcurl.so.4"):
            self.assertEqual(portable.elf_metadata(files["lib/omux/lib/" + soname])["needed"], ["libc.so.6"])
            self.assertEqual(portable.elf_metadata(files["lib/omux/qt/lib/" + soname])["needed"],
                             ["libc.so.6", "libQt6Core.so.6"])
        portable.verify_linux(files, manifest)
        # Missing declared inputs cannot borrow a matching SONAME from the
        # other process, even when that process's closure contains it.
        with self.assertRaisesRegex(ValueError, "missing libsqlite3"):
            self.assemble(control, plugins, qt_runtime=[path for path in qt_runtime if path != qt_sqlite])
        self.runtime.remove(self.sqlite)
        with self.assertRaisesRegex(ValueError, "missing libsqlite3"):
            self.assemble(control, plugins, qt_runtime=qt_runtime)
        self.runtime.extend([self.sqlite, qt_sqlite])
        for reverse in (False, True):
            if reverse:
                self.runtime.reverse()
            with self.assertRaisesRegex(ValueError, "ambiguous declared runtime dependency libsqlite3") as rejected:
                self.assemble(control, plugins, qt_runtime=qt_runtime)
            self.assertNotIn(str(self.root), str(rejected.exception))

    def test_qt_runtime_candidates_must_be_declared_explicitly(self) -> None:
        control, plugins = self.configure_qt()
        for candidates in (None, []):
            with self.subTest(candidates=candidates), self.assertRaisesRegex(ValueError, "declared runtime closure"):
                portable.assemble_linux(self.cli, self.daemon, self.runtime, self.patchelf,
                                       "x86_64-linux", self.ca_bundle, control, plugins,
                                       qt_runtime_files=candidates)

    def test_absolute_dependency_cannot_borrow_another_process_soname(self) -> None:
        control, plugins = self.configure_qt()
        qt_libraries = [path for path in self.runtime if path.name.startswith("libQt") or path.name == "libxcb.so.1"]
        qt_sqlite = self.write("qt-deps/libsqlite3.so.0", elf(("libc.so.6", "libQt6Core.so.6")))
        self.runtime = [self.loader, self.libc, self.sqlite]
        qt_runtime = [self.loader, self.libc, *qt_libraries, qt_sqlite]
        self.cli.write_bytes(elf((str(qt_sqlite),), interpreter=str(self.loader)))
        with self.assertRaisesRegex(ValueError, "exact declared runtime dependency is missing libsqlite3") as rejected:
            self.assemble(control, plugins, qt_runtime=qt_runtime)
        self.assertNotIn(str(self.root), str(rejected.exception))
        self.cli.write_bytes(elf((str(self.sqlite),), interpreter=str(self.loader)))
        control.write_bytes(elf((str(self.sqlite), "libQt6Core.so.6"), interpreter=str(self.loader)))
        with self.assertRaisesRegex(ValueError, "exact declared runtime dependency is missing libsqlite3"):
            self.assemble(control, plugins, qt_runtime=qt_runtime)
        control.write_bytes(elf((str(qt_sqlite), "libQt6Core.so.6"), interpreter=str(self.loader)))
        files, manifest = self.all_files(control, plugins, qt_runtime=qt_runtime)
        portable.verify_linux(files, manifest)


if __name__ == "__main__":
    unittest.main()
