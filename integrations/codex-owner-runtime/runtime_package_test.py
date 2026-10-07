"""Declared synthetic custody/closure predicates; never invoke the SDK or tools."""

import copy
import io
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import runtime_package as runtime
from patch_io import digest
from refresh_artifact import package


def elf(needed=(), interpreter=None, rpath=()):
    strings, references = bytearray(b"\0"), []
    for tag, value in [(1, name) for name in needed] + ([(29, ":".join(rpath))] if rpath else []):
        references.append((tag, len(strings)))
        strings.extend(value.encode() + b"\0")
    count = 2 + (interpreter is not None)
    dynamic_offset = 64 + 56 * count
    dynamic_size = 16 * (len(references) + 3)
    string_offset = dynamic_offset + dynamic_size
    interp = b"" if interpreter is None else interpreter.encode() + b"\0"
    interp_offset = string_offset + len(strings)
    length, base = interp_offset + len(interp), 0x400000
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, length, length, 4096)
    phdrs += struct.pack("<IIQQQQQQ", 2, 4, dynamic_offset, base + dynamic_offset, 0, dynamic_size, dynamic_size, 8)
    if interpreter is not None:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_offset, base + interp_offset, 0, len(interp), len(interp), 1)
    return header + phdrs + b"".join(struct.pack("<qQ", tag, value) for tag, value in
            references + [(5, base + string_offset), (10, len(strings)), (0, 0)]) + strings + interp


class RuntimePackageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(os.environ["TEST_TMPDIR"]).resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.loader = self.write("ld-linux-x86-64.so.2", elf())
        self.libc = self.write("libc.so.6", elf())
        self.ca = self.write("ca-bundle.crt", b"-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n")
        self.strip = self.write("strip", b"declared strip fixture")
        self.patchelf = self.write("patchelf", b"declared patchelf fixture")
        self.candidate = {"upstream_commit": runtime.COMMIT,
                          "current_configuration": "owner-linux-fastbuild",
                          **{key: "a" * 64 for key in ("patch_sha256", "base_sha256", "binary_overlay_sha256", "validation_sha256", "complete_source_inventory_sha256", "current_source_receipt_sha256")},
                          "compile_invocation_id": "12345678-1234-1234-1234-123456789abc",
                          "source_verification_invocation_id": "22345678-1234-1234-1234-123456789abc",
                          "current_compile_invocation_id": "32345678-1234-1234-1234-123456789abc",
                          "current_source_verification_invocation_id": "42345678-1234-1234-1234-123456789abc"}

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    @staticmethod
    def patch_fixture(path, info, tool, backend, rpath="$ORIGIN"):
        path.write_bytes(elf(tuple(Path(name).name for name in info["needed"]),
                             runtime.portable._BACKEND_INTERPRETER if backend or info["interpreter"] else None,
                             ("$ORIGIN/../lib" if backend else rpath,)))

    def assembled(self):
        source = self.write("sdk", elf(("libc.so.6",), str(self.loader)))
        with mock.patch.object(runtime.portable, "_patch", side_effect=self.patch_fixture):
            return runtime.assemble_runtime(source, [self.loader, self.libc], self.patchelf, self.ca)

    def bundle(self, files=None, manifest=None):
        if files is None:
            files, witness = self.assembled()
            backend = files[runtime.BACKEND]
            manifest = {"schema_version": 1, "status": runtime.STATUS, "native_support": False,
                        "target": "x86_64-linux", "candidate": self.candidate, "runtime": witness,
                        "executable": {"backend_max_bytes": runtime.MAX_BACKEND_BYTES,
                                       **{phase + field: value for phase in ("original", "stripped", "packaged")
                                          for field, value in (("_sha256", digest(backend)), ("_bytes", len(backend)))}}}
        manifest = copy.deepcopy(manifest)
        manifest["files"] = {name: {"sha256": digest(value), "bytes": len(value), "mode": 0o644 if name == runtime.CA else 0o755}
                             for name, value in files.items()}
        payload = runtime.archive_bytes(files, manifest)
        receipt = {"status": runtime.STATUS, "native_support": False, "candidate": manifest["candidate"],
                   "executable": manifest["executable"], "archive_sha256": digest(payload), "archive_bytes": len(payload),
                   "manifest_sha256": digest(runtime.json_bytes(manifest))}
        return payload, receipt, manifest, files

    def test_stream_copy_preserves_original_and_rejects_symlink_or_bound(self):
        source = self.write("produced-sdk", b"SDK original bytes")
        destination = io.BytesIO()
        self.assertEqual(runtime.stream_original(source, destination), {"sha256": digest(source.read_bytes()), "bytes": 18})
        self.assertEqual(destination.getvalue(), source.read_bytes())
        with mock.patch.object(runtime, "MAX_ORIGINAL_BYTES", 3), self.assertRaises(ValueError):
            runtime.stream_original(source)
        alias = self.root / "alias"
        alias.symlink_to(source)
        with self.assertRaises(OSError):
            runtime.stream_original(alias)
        self.assertEqual(source.read_bytes(), b"SDK original bytes")

    def test_loader_standard_declared_alias_missing_foreign_and_ambiguous(self):
        metadata = {"interpreter": "/lib64/ld-linux-x86-64.so.2"}
        self.assertEqual(runtime.select_loader(metadata, [self.loader])[0], self.loader)
        self.assertEqual(runtime.select_loader({"interpreter": str(self.loader)}, [self.loader])[0], self.loader)
        for info, paths in ((metadata, []), ({"interpreter": "/foreign/ld-linux-x86-64.so.2"}, [self.loader])):
            with self.assertRaises(ValueError):
                runtime.select_loader(info, paths)
        other = self.write("other/ld-linux-x86-64.so.2", self.loader.read_bytes())
        runtime.select_loader(metadata, [self.loader, other])
        other.write_bytes(elf() + b"different")
        with self.assertRaises(ValueError):
            runtime.select_loader(metadata, [self.loader, other])

    def test_archive_receipt_modes_and_closed_elf_edges(self):
        payload, receipt, manifest, files = self.bundle()
        checked, decoded = runtime.verify_runtime_files(payload, receipt)
        self.assertEqual(checked, manifest)
        self.assertEqual(decoded[runtime.BACKEND], files[runtime.BACKEND])
        with self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, {**receipt, "archive_sha256": "b" * 64})
        for configuration in (None, "local_linux-fastbuild", "owner-linux-dbg"):
            altered = copy.deepcopy(manifest)
            altered["candidate"]["current_configuration"] = configuration
            forged, forged_receipt, _, _ = self.bundle(files, altered)
            with self.subTest(configuration=configuration), self.assertRaises(ValueError):
                runtime.verify_runtime_files(forged, forged_receipt)
        with self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, {**receipt, "candidate": {**self.candidate, "current_configuration": "owner-linux-opt"}})
        for name, value in (("../escape", b"foreign"), ("lib/codex/lib/unused.so", elf())):
            forged, forged_receipt, _, _ = self.bundle({**files, name: value}, manifest)
            with self.assertRaises(ValueError):
                runtime.verify_runtime_files(forged, forged_receipt)
        escaped = {**files, runtime.BACKEND: elf(("/host/lib.so",), runtime.portable._BACKEND_INTERPRETER, ("$ORIGIN/../lib",))}
        altered = copy.deepcopy(manifest)
        altered["executable"]["packaged_sha256"] = digest(escaped[runtime.BACKEND])
        altered["executable"]["packaged_bytes"] = len(escaped[runtime.BACKEND])
        forged, forged_receipt, _, _ = self.bundle(escaped, altered)
        with self.assertRaises(ValueError):
            runtime.verify_runtime_files(forged, forged_receipt)

    def test_original_is_not_stripped_and_packaging_requires_exclusive_epoch(self):
        source = self.write("produced-bin/raw-sdk", elf(("libc.so.6",), "/lib64/ld-linux-x86-64.so.2") + b"debug bytes")
        original = source.read_bytes()
        producer = {"original_sha256": digest(original), "original_bytes": len(original)}
        source_receipt = self.write("source.json", b"source receipt")
        producer_receipt = self.write("producer.json", b"producer receipt")

        def tool(command, tool_path=""):
            target = Path(command[-1])
            self.assertNotEqual(target, source)
            if command[0] == str(self.strip):
                self.assertEqual(command[1], "--strip-all")
                target.write_bytes(elf(("libc.so.6",), "/lib64/ld-linux-x86-64.so.2"))
            else:
                self.assertEqual(command[1], "--set-interpreter")
                target.write_bytes(elf(("libc.so.6",), command[2]))

        output = self.root / "new-runtime"
        with mock.patch.object(runtime, "candidate_inputs", return_value=(self.candidate, producer)), \
                mock.patch.object(runtime, "run_tool", side_effect=tool), \
                mock.patch.object(runtime.portable, "_patch", side_effect=self.patch_fixture):
            receipt = runtime.build_package(source, self.root / "artifact", source_receipt, producer_receipt,
                output, self.strip, self.patchelf, [self.loader, self.libc], self.ca,
                "/nix/store/" + "a" * 32 + "-coreutils/bin")
            with self.assertRaises(FileExistsError):
                runtime.build_package(source, self.root / "artifact", source_receipt, producer_receipt,
                    output, self.strip, self.patchelf, [self.loader, self.libc], self.ca,
                    "/nix/store/" + "a" * 32 + "-coreutils/bin")
        self.assertEqual(source.read_bytes(), original)
        self.assertNotEqual(receipt["executable"]["original_sha256"], receipt["executable"]["stripped_sha256"])
        manifest, _ = runtime.read_runtime_bundle(output / "codex-owner-runtime.tar.gz", output / "runtime-receipt.json")
        self.assertEqual(manifest["transformations"]["strip_option"], "--strip-all")

    def test_candidate_binding_rejects_different_source_or_compile_receipt(self):
        source = self.root / "edited"
        target = source / "codex-rs/core/src/auth_broker.rs"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"new source\n")
        manifest, patch, base, overlay = package({"LICENSE": b"license", "NOTICE": b"notice"}, source,
                                                ["codex-rs/core/src/auth_broker.rs"])
        artifact = self.root / "artifact"
        artifact.mkdir()
        for name, value in ((manifest["patch_file"], patch), ("upstream-base.tar.gz", base), (manifest["binary_overlay_file"], overlay)):
            (artifact / name).write_bytes(value)
        (artifact / "manifest.json").write_text(json.dumps(manifest))
        inventory = {"codex-rs/core/src/auth_broker.rs": {"mode": "100644", "sha256": digest(target.read_bytes())}}
        inventory_hash = digest(json.dumps(inventory, sort_keys=True).encode())
        validation = {"native_support": False, "upstream_commit": runtime.COMMIT,
            "artifact": {**{key: manifest[key] for key in ("patch_sha256", "base_sha256", "binary_overlay_sha256")}, "reviewed_changed_files": 1},
            "checks": {"complete_final_source_verification": {"status": "passed", "complete_inventory_sha256": inventory_hash, "tracked_files": 1,
                         "invocation_id": self.candidate["source_verification_invocation_id"]},
                       "final_source_eight_production_labels": {"status": "passed", "invocation_id": self.candidate["compile_invocation_id"]}}}
        (artifact / "validation.json").write_text(json.dumps(validation))
        source_metadata = {"phase": "verify-prepared", "commit": runtime.COMMIT,
            "patch_sha256": manifest["patch_sha256"], "complete_inventory_sha256": inventory_hash, "files": inventory,
            "tracked_files": 1, "bazel_configuration": "owner-linux-fastbuild"}
        source_receipt = self.write("source-receipt.json", json.dumps(source_metadata).encode())
        producer = {**self.candidate, **{key: manifest[key] for key in ("patch_sha256", "base_sha256", "binary_overlay_sha256")},
            "complete_source_inventory_sha256": inventory_hash, "validation_sha256": digest((artifact / "validation.json").read_bytes()),
            "current_source_receipt_sha256": digest(source_receipt.read_bytes()),
            "target": "//codex-rs/cli:codex", "configuration": "owner-linux-fastbuild", "original_sha256": "c" * 64, "original_bytes": 619050144}
        producer_receipt = self.write("producer-receipt.json", json.dumps(producer).encode())
        for configuration in runtime.PRODUCER_CONFIGURATIONS:
            source_metadata["bazel_configuration"] = configuration
            source_receipt.write_text(json.dumps(source_metadata))
            producer["configuration"] = configuration
            producer["current_source_receipt_sha256"] = digest(source_receipt.read_bytes())
            producer_receipt.write_text(json.dumps(producer))
            bound, _ = runtime.candidate_inputs(artifact, source_receipt, producer_receipt)
            self.assertEqual(bound["current_configuration"], configuration)
            self.assertEqual(bound["compile_invocation_id"], self.candidate["compile_invocation_id"])
            self.assertEqual(bound["source_verification_invocation_id"], self.candidate["source_verification_invocation_id"])
        for configuration in ("owner-linux-fastbuild", "local_linux-fastbuild", "owner-linux-dbg", None):
            producer["configuration"] = configuration
            producer_receipt.write_text(json.dumps(producer))
            with self.subTest(configuration=configuration), self.assertRaises(ValueError):
                runtime.candidate_inputs(artifact, source_receipt, producer_receipt)
        producer["configuration"] = "owner-linux-opt"
        producer["compile_invocation_id"] = "52345678-1234-1234-1234-123456789abc"
        producer_receipt.write_text(json.dumps(producer))
        with self.assertRaises(ValueError):
            runtime.candidate_inputs(artifact, source_receipt, producer_receipt)

    def test_declared_tool_failure_has_no_external_diagnostic_message(self):
        failure = subprocess.CalledProcessError(1, ["fixture"], stderr=b"private fixture diagnostic")
        with mock.patch.object(runtime.subprocess, "run", side_effect=failure):
            with self.assertRaises(ValueError) as caught:
                runtime.run_tool(["declared-tool"])
        self.assertEqual(str(caught.exception), "declared runtime transformation failed")

    def test_response_file_resolves_exact_keys_and_refuses_foreign_or_repeated_selection(self):
        path = self.write("runtime-inputs.json", b"")
        keys = ["declared-repo/runtime_closure/a/lib/libc.so.6", "declared-repo/runtime_closure/b/lib/ld-linux-x86-64.so.2"]
        path.write_text(json.dumps({"schema_version": 1, "runfiles": keys}))
        self.assertEqual(runtime.read_runtime_inputs(path, self.root), [self.root / key for key in keys])
        for selection in ([], [keys[0], keys[0]], ["../escape"], ["/host/lib.so"], ["repo//lib.so"],
                          ["repo/./lib.so"], ["repo/lib\n.so"], ["repo/lib\x01.so"], list(reversed(keys))):
            path.write_text(json.dumps({"schema_version": 1, "runfiles": selection}))
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                runtime.read_runtime_inputs(path, self.root)
        path.write_text('{"schema_version":1,"runfiles":[],"runfiles":[]}')
        with self.assertRaises(ValueError):
            runtime.read_runtime_inputs(path, self.root)
        path.write_text(json.dumps({"schema_version": 1, "runfiles": keys}))
        with mock.patch.object(runtime, "MAX_FILES", 1), self.assertRaises(ValueError):
            runtime.read_runtime_inputs(path, self.root)
        for value in ([], {"schema_version": True, "runfiles": keys}):
            path.write_text(json.dumps(value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                runtime.read_runtime_inputs(path, self.root)

    def test_phase_diagnostics_are_fixed_and_do_not_include_tool_error_content(self):
        output = io.StringIO()
        with mock.patch.object(runtime.sys, "stderr", output):
            runtime.phase_marker("strip")
            runtime.stripped_size_marker(123456)
            for size in (-1, True, runtime.MAX_ORIGINAL_BYTES + 1, "private tool diagnostic"):
                with self.subTest(size=size), self.assertRaises(ValueError):
                    runtime.stripped_size_marker(size)
            with self.assertRaises(ValueError):
                runtime.phase_marker("private external path or diagnostic")
            with mock.patch.object(runtime.subprocess, "run", side_effect=OSError("private tool diagnostic")):
                with self.assertRaises(ValueError) as caught:
                    runtime.run_tool(["private tool argv"])
        self.assertEqual(output.getvalue(), "Runtime import phase: strip\nRuntime import stripped bytes: 123456\n")
        self.assertEqual(str(caught.exception), "declared runtime transformation failed")

    def test_backend_policy_and_archive_size_fences_are_receipt_bound(self):
        payload, receipt, manifest, files = self.bundle()
        for section in ("executable", "runtime"):
            for bound in (None, True, runtime.portable._MAX_FILE, runtime.MAX_BACKEND_BYTES + 1):
                altered = copy.deepcopy(manifest)
                altered[section]["backend_max_bytes"] = bound
                forged, forged_receipt, _, _ = self.bundle(files, altered)
                with self.subTest(section=section, bound=bound), self.assertRaises(ValueError):
                    runtime.verify_runtime_files(forged, forged_receipt)
        altered_receipt = copy.deepcopy(receipt)
        altered_receipt["executable"]["backend_max_bytes"] = runtime.portable._MAX_FILE
        with self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, altered_receipt)
        with mock.patch.object(runtime, "MAX_ARCHIVE_BYTES", len(payload) - 1), self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, receipt)
        with mock.patch.object(runtime, "MAX_RUNTIME_BYTES", sum(map(len, files.values())) - 1), self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, receipt)
        # Reduced fixture budgets exercise each tar member fence without a
        # several-hundred-MiB allocation. Only the exact BACKEND gets its role budget.
        with mock.patch.object(runtime, "MAX_BACKEND_BYTES", len(files[runtime.BACKEND]) - 1), self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, receipt)
        with mock.patch.object(runtime.portable, "_MAX_FILE", len(files[runtime.CA]) - 1), self.assertRaises(ValueError):
            runtime.verify_runtime_files(payload, receipt)
        with mock.patch.object(runtime, "MAX_RUNTIME_BYTES", 1), self.assertRaises(ValueError):
            runtime.archive_bytes(files, manifest)
        with mock.patch.object(runtime, "MAX_METADATA_BYTES", 1), self.assertRaises(ValueError):
            runtime.archive_bytes(files, manifest)


if __name__ == "__main__":
    unittest.main()
