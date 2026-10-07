"""Immutable development selection predicates; no runtime is executed."""
import base64
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import dev_generation
import portable
import portable_launcher_template as trusted
import dev_stage_selected
from dev_generation import GenerationError, select_generation
from dev_stage import HOST, StagedGeneration, digest, inventory, stage, stage_generation
from test_portable import elf


class GenerationTest(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="omux-generation-", dir=Path("/tmp").resolve())
        self.addCleanup(self.workspace.cleanup)
        self.base = Path(self.workspace.name)
        self.root = self.base / "stage"
        self.core, self.daemon, self.extension = (self.base / name for name in ("core", "daemon", "extension.zip"))
        self.core.write_bytes(b"synthetic core: selection only")
        self.daemon.write_bytes(b"synthetic daemon: selection only")
        key = b"synthetic development manifest identity" * 2
        identity = "".join(chr(97 + int(value, 16)) for value in digest(key)[:32])
        with zipfile.ZipFile(self.extension, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"key": base64.b64encode(key).decode(), "version": "0.2.0"}))
            archive.writestr("shared/channel.mjs", 'export const CHANNEL = "development";\n'
                             'export const INSTANCE = "dev";\nexport const NATIVE_HOST = "' + HOST + '";\n')
        extension_bytes = self.extension.read_bytes()
        self.metadata = {"schema_version": 1, "channel": "development", "instance": "dev", "native_host": HOST,
                         "extension": {"id": identity, "browser": "chromium", "version": "0.2.0"},
                         "artifact": {"sha256": digest(extension_bytes), "bytes": len(extension_bytes), "format": "zip"}}
        self.receipt = stage(self.root, self.core, self.daemon, self.extension, self.metadata)
        # Capture once as stage output bookkeeping. select_generation never
        # reads this pointer, including when it is absent, changed or foreign.
        self.generation = os.readlink(self.root / "current").split("/")[1]
        self.directory = self.root / "generations" / self.generation
        self.receipt_path = self.directory / "receipt.json"
        self.receipt_sha256 = digest(self.receipt_path.read_bytes())

    def select(self, **kwargs):
        return select_generation(self.root, self.generation, self.receipt_sha256, **kwargs)

    def repin(self, update_inventory=False):
        if update_inventory:
            self.receipt["files"] = inventory(self.directory)
        self.receipt_path.write_text(json.dumps(self.receipt, sort_keys=True) + "\n")
        self.receipt_sha256 = digest(self.receipt_path.read_bytes())

    def portable_fixture(self):
        # Structurally valid ELF/closure fixture; no compiler, linker, runtime,
        # patchelf or other executable is invoked to manufacture proof.
        loader = "lib/omux/lib/synthetic-loader"
        backend = elf(rpath=("$ORIGIN/../lib",), interpreter="/omux/launch-via-bin-wrapper")
        source = elf(interpreter="/declared/synthetic-loader")
        runtime = {"loader": loader, "dependencies": [loader],
                   "backendInterpreter": "/omux/launch-via-bin-wrapper",
                   "caBundle": "lib/omux/share/ca-bundle.crt",
                   "launcher": {"abi": 1, "target": trusted.TARGET,
                                "templateSha256": trusted.SHA256}}
        payload = {loader: elf(), "lib/omux/libexec/omux.bin": backend,
                   "lib/omux/libexec/omuxd.bin": backend,
                   "lib/omux/share/ca-bundle.crt": b"-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n"}
        for name in ("omux", "oauth-mux", "omux-native-host", "git-credential-omux", "omuxd"):
            payload["bin/" + name] = portable.linux_launcher(
                "synthetic-loader", "omuxd.bin" if name == "omuxd" else "omux.bin", "development")
        for name, data in payload.items():
            path = self.directory / "runtime" / name
            parent = self.directory
            for component in path.relative_to(self.directory).parts[:-1]:
                parent = parent / component
                parent.mkdir(mode=0o700, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o600 if name.endswith(".crt") else 0o700)
        (self.directory / "source").mkdir(mode=0o700)
        for name in ("core", "daemon"):
            path = self.directory / "source" / name
            path.write_bytes(source)
            path.chmod(0o600)
            self.receipt["artifacts"][name] = digest(source)
        for name in ("omux", "omux-native-host", "omuxd"):
            (self.directory / "lib" / name).write_bytes(
                ('#!/bin/sh\nset -eu\ndirectory=${0%/*}\n'
                 'exec "$directory/../runtime/bin/' + name + '" "$@"\n').encode())
        self.receipt["distribution"] = "portable-linux"
        self.receipt["runtime"] = {"target": "x86_64-linux", "details": runtime}
        self.repin(update_inventory=True)

    def declared_portable_inputs(self):
        self.portable_fixture()
        self.core.write_bytes((self.directory / "source/core").read_bytes())
        self.daemon.write_bytes((self.directory / "source/daemon").read_bytes())
        metadata_path = self.base / "selected-metadata.json"
        metadata_path.write_text(json.dumps(self.metadata))
        runtime_directory = self.directory / "runtime"
        payload = {path.relative_to(runtime_directory).as_posix(): path.read_bytes()
                   for path in runtime_directory.rglob("*") if path.is_file()}
        runtime = self.receipt["runtime"]["details"]
        inputs = {"runtime_files": [runtime_directory / runtime["loader"]],
                  "patchelf": self.base / "declared-patchelf",
                  "ca_bundle": runtime_directory / runtime["caBundle"]}
        inputs["patchelf"].write_bytes(b"declared fixture input; never executed")
        return metadata_path, payload, runtime, inputs

    def test_stage_receipt_selects_frozen_exact_generation_paths(self):
        selected = self.select(expected_artifacts=self.receipt["artifacts"])
        self.assertEqual(selected.directory, self.directory)
        self.assertEqual(selected.cli, self.directory / "bin/omux")
        self.assertEqual(selected.native_host, self.directory / "bin/omux-native-host")
        self.assertEqual(selected.daemon, self.directory / "bin/omuxd")
        self.assertEqual(selected.chromium, self.directory / "chromium")
        self.assertEqual(selected.extension_id, self.metadata["extension"]["id"])
        self.assertEqual(selected.extension_version, self.metadata["extension"]["version"])
        self.assertEqual(selected.receipt_sha256, self.receipt_sha256)
        with self.assertRaises(FrozenInstanceError):
            selected.generation = "a" * 32

    def test_retained_selection_survives_atomic_current_replacement(self):
        before = self.select()
        self.daemon.write_bytes(b"new synthetic daemon")
        stage(self.root, self.core, self.daemon, self.extension, self.metadata, replace_owned=True)
        self.assertNotEqual(os.readlink(self.root / "current").split("/")[1], self.generation)
        self.assertEqual(self.select(), before)
        self.assertEqual((before.directory / "lib/omuxd").read_bytes(), b"synthetic daemon: selection only")

    def test_current_and_stable_commands_are_never_consulted(self):
        (self.root / "current").unlink()
        (self.root / "current").symlink_to("/unrelated/not-authorized")
        (self.root / "bin/omuxd").write_bytes(b"unrelated user modification")
        self.assertEqual(self.select().daemon, self.directory / "bin/omuxd")
        self.assertEqual((self.root / "bin/omuxd").read_bytes(), b"unrelated user modification")
        self.assertEqual(os.readlink(self.root / "current"), "/unrelated/not-authorized")

    def test_explicit_generation_and_digest_shapes_are_required(self):
        for generation in ("current", "../" + self.generation, "A" * 32, "", None):
            with self.subTest(generation=generation), self.assertRaisesRegex(GenerationError, "generation-shape"):
                select_generation(self.root, generation, self.receipt_sha256)
        for receipt_digest in ("", "A" * 64, None, "a" * 63):
            with self.subTest(receipt_digest=receipt_digest), self.assertRaisesRegex(GenerationError, "receipt-digest-shape"):
                select_generation(self.root, self.generation, receipt_digest)

    def test_exact_raw_receipt_bytes_are_required(self):
        self.receipt_path.write_bytes(self.receipt_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(GenerationError, "receipt-digest-mismatch"):
            self.select()

    def test_missing_generation_never_creates_directories(self):
        absent = "a" * 32 if self.generation != "a" * 32 else "b" * 32
        with self.assertRaises(GenerationError):
            select_generation(self.root, absent, self.receipt_sha256)
        self.assertFalse((self.root / "generations" / absent).exists())
        missing_root = self.base / "not-created"
        with self.assertRaises(GenerationError):
            select_generation(missing_root, self.generation, self.receipt_sha256)
        self.assertFalse(missing_root.exists())

    def test_symlink_root_and_generation_are_refused(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root)
        with self.assertRaises(GenerationError):
            select_generation(alias, self.generation, self.receipt_sha256)
        real = self.directory.with_name("retained")
        self.directory.rename(real)
        self.directory.symlink_to(real)
        with self.assertRaises(GenerationError):
            self.select()

    def test_payload_modification_and_unrecorded_file_are_refused(self):
        command = self.directory / "lib/omuxd"
        original = command.read_bytes()
        command.write_bytes(b"modified payload")
        with self.assertRaisesRegex(GenerationError, "inventory-mismatch"):
            self.select()
        self.assertEqual(command.read_bytes(), b"modified payload")
        command.write_bytes(original)
        extra = self.directory / "unrelated"
        extra.write_bytes(b"preserve unrelated file")
        extra.chmod(0o600)
        with self.assertRaisesRegex(GenerationError, "inventory-mismatch"):
            self.select()
        self.assertEqual(extra.read_bytes(), b"preserve unrelated file")

    def test_linked_and_special_payloads_are_refused_without_wait(self):
        command = self.directory / "lib/omuxd"
        command.unlink()
        command.symlink_to(self.daemon)
        with self.assertRaises(GenerationError):
            self.select()
        command.unlink()
        os.link(self.daemon, command)
        with self.assertRaisesRegex(GenerationError, "file-custody"):
            self.select()
        command.unlink()
        os.mkfifo(command, 0o600)
        with self.assertRaisesRegex(GenerationError, "file-custody"):
            self.select()

    def test_receipt_symlink_and_unsafe_modes_are_refused(self):
        self.receipt_path.chmod(0o644)
        with self.assertRaisesRegex(GenerationError, "file-custody"):
            self.select()
        self.receipt_path.chmod(0o600)
        copied = self.base / "receipt-copy"
        copied.write_bytes(self.receipt_path.read_bytes())
        self.receipt_path.unlink()
        self.receipt_path.symlink_to(copied)
        with self.assertRaises(GenerationError):
            self.select()

    def test_private_directory_and_ancestor_custody(self):
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(GenerationError, "directory-custody"):
            self.select()
        self.directory.chmod(0o700)
        self.base.chmod(0o777)
        with self.assertRaisesRegex(GenerationError, "ancestor-custody"):
            self.select()

    def test_bounded_receipt_file_count_depth_and_total_bytes(self):
        for setting, bound, reason in (("MAX_RECEIPT", 8, "file-byte-bound"),
                                      ("MAX_ENTRIES", 2, "inventory-entry-bound"),
                                      ("MAX_DEPTH", 0, "inventory-depth-bound"),
                                      ("MAX_TOTAL", 8, "inventory-total-bound")):
            with self.subTest(setting=setting), mock.patch.object(dev_generation, setting, bound):
                with self.assertRaisesRegex(GenerationError, reason):
                    self.select()

    def test_payload_file_byte_bound_with_valid_archive_metadata(self):
        bound = self.metadata["artifact"]["bytes"]
        with mock.patch.object(dev_generation, "MAX_FILE", bound):
            self.assertEqual(self.select().generation, self.generation)
        oversized = self.directory / "oversized-file"
        content = b"x" * (bound + 1)
        oversized.write_bytes(content)
        oversized.chmod(0o600)
        self.repin(update_inventory=True)
        self.assertEqual(self.receipt["files"]["oversized-file"], {"sha256": digest(content), "mode": 0o600})
        self.assertEqual(oversized.stat().st_size, bound + 1)
        with mock.patch.object(dev_generation, "MAX_FILE", bound):
            with self.assertRaisesRegex(GenerationError, "file-byte-bound"):
                self.select()

    def test_duplicate_json_keys_are_refused_even_with_retained_digest(self):
        data = self.receipt_path.read_bytes()
        self.receipt_path.write_bytes(b'{"ownership":null,' + data[1:])
        self.receipt_sha256 = digest(self.receipt_path.read_bytes())
        with self.assertRaisesRegex(GenerationError, "duplicate-json-field"):
            self.select()

    def test_wrong_channel_and_source_artifact_are_refused(self):
        self.receipt["metadata"]["instance"] = "default"
        self.repin()
        with self.assertRaisesRegex(GenerationError, "receipt-channel"):
            self.select()
        self.receipt["metadata"]["instance"] = "dev"
        self.repin()
        wrong = dict(self.receipt["artifacts"], daemon="a" * 64)
        with self.assertRaisesRegex(GenerationError, "source-artifact-mismatch"):
            self.select(expected_artifacts=wrong)
        self.receipt["artifacts"]["daemon"] = "a" * 64
        self.repin()
        with self.assertRaisesRegex(GenerationError, "generation-source-binding"):
            self.select()

    def test_extension_manifest_key_and_channel_are_checked(self):
        manifest_path = self.directory / "chromium/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["key"] = base64.b64encode(b"different synthetic identity").decode()
        manifest_path.write_text(json.dumps(manifest))
        self.repin(update_inventory=True)
        with self.assertRaisesRegex(GenerationError, "extension-identity-mismatch"):
            self.select()
        self.receipt["metadata"]["extension"]["id"] = "".join(
            chr(97 + int(value, 16)) for value in digest(b"different synthetic identity")[:32])
        (self.directory / "chromium/shared/channel.mjs").write_bytes(b"wrong channel")
        self.repin(update_inventory=True)
        with self.assertRaisesRegex(GenerationError, "extension-channel"):
            self.select()

    def test_synthetic_generation_cannot_satisfy_portable_request(self):
        with self.assertRaisesRegex(GenerationError, "portable-generation-required"):
            self.select(require_portable=True)
        self.assertEqual(self.select().distribution, "fixture")

    def test_relabeling_fixture_does_not_supply_portable_runtime_binding(self):
        self.receipt["distribution"] = "portable-linux"
        self.repin()
        with self.assertRaisesRegex(GenerationError, "portable-runtime-shape"):
            self.select(require_portable=True)
        self.receipt["runtime"] = {"target": "x86_64-linux", "details": {"loader": "lib/omux/lib/synthetic-loader"}}
        self.repin()
        with self.assertRaisesRegex(GenerationError, "portable-runtime-binding"):
            self.select(require_portable=True)

    def test_generation_launcher_cannot_redirect_through_current(self):
        (self.directory / "bin/omuxd").write_bytes(b'#!/bin/sh\nexec "../../current/lib/omuxd" "$@"\n')
        self.repin(update_inventory=True)
        with self.assertRaisesRegex(GenerationError, "generation-launcher-binding"):
            self.select()

    def test_earlier_file_changed_during_later_capture_is_refused(self):
        original_read = dev_generation.read_file
        bin_inode = (self.directory / "bin").stat().st_ino
        earlier, changed = None, False

        def racing_read(directory, name, *args, **kwargs):
            nonlocal earlier, changed
            value = original_read(directory, name, *args, **kwargs)
            if earlier is not None and not changed:
                info = earlier.stat()
                content = earlier.read_bytes()
                earlier.write_bytes(bytes([content[0] ^ 1]) + content[1:])
                os.utime(earlier, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                self.assertEqual(earlier.stat().st_size, info.st_size)
                changed = True
            elif earlier is None and os.fstat(directory).st_ino == bin_inode:
                earlier = self.directory / "bin" / name
            return value

        with mock.patch.object(dev_generation, "read_file", side_effect=racing_read):
            with self.assertRaisesRegex(GenerationError, "generation-capture-changed"):
                self.select()
        self.assertTrue(changed, "race injection did not reach a later file read")

    def test_structurally_valid_portable_runtime_selection(self):
        self.portable_fixture()
        selected = self.select(require_portable=True, expected_artifacts=self.receipt["artifacts"])
        self.assertEqual(selected.distribution, "portable-linux")
        self.assertEqual(selected.daemon, self.directory / "bin/omuxd")

    def test_portable_runtime_launcher_redirect_and_channel_override_are_refused(self):
        self.portable_fixture()
        path = self.directory / "runtime/bin/omuxd"
        for data in (b'#!/bin/sh\nexec "../../current/lib/omuxd" "$@"\n',
                     portable.linux_launcher("synthetic-loader", "omuxd.bin", "release")):
            with self.subTest(payload_digest=digest(data)):
                path.write_bytes(data)
                self.repin(update_inventory=True)
                with self.assertRaisesRegex(GenerationError, "portable-runtime-invalid"):
                    self.select(require_portable=True)

    def test_portable_backend_lookup_and_missing_closure_are_refused(self):
        self.portable_fixture()
        backend = self.directory / "runtime/lib/omux/libexec/omuxd.bin"
        original = backend.read_bytes()
        backend.write_bytes(elf(interpreter="/unqualified/host-loader", rpath=("/host/lib",)))
        self.repin(update_inventory=True)
        with self.assertRaisesRegex(GenerationError, "portable-runtime-invalid"):
            self.select(require_portable=True)
        backend.write_bytes(original)
        (self.directory / "runtime/lib/omux/libexec/omux.bin").unlink()
        self.repin(update_inventory=True)
        with self.assertRaisesRegex(GenerationError, "portable-runtime-invalid"):
            self.select(require_portable=True)

    def test_transaction_returns_exact_generation_and_raw_receipt_digest(self):
        root = self.base / "transaction-stage"
        with mock.patch("dev_stage.uuid.uuid4") as identifier:
            identifier.return_value.hex = "a" * 32
            outcome = stage_generation(root, self.core, self.daemon, self.extension, self.metadata)
        self.assertIsInstance(outcome, StagedGeneration)
        self.assertEqual(outcome.generation, "a" * 32)
        retained = root / "generations" / outcome.generation / "receipt.json"
        self.assertEqual(outcome.receipt_sha256, digest(retained.read_bytes()))
        self.assertEqual(outcome.receipt, json.loads(retained.read_bytes()))
        (root / "current").unlink()
        (root / "current").symlink_to("generations/" + "b" * 32)
        selected = select_generation(root, outcome.generation, outcome.receipt_sha256)
        self.assertEqual(selected.generation, outcome.generation)

    def test_selected_producer_uses_transaction_capture_after_current_drifts(self):
        metadata_path, payload, runtime, inputs = self.declared_portable_inputs()
        root = self.base / "selected-stage"
        metadata = json.loads(metadata_path.read_bytes())
        metadata["unselectedExtra"] = "arbitrary metadata stays private"
        metadata_path.write_text(json.dumps(metadata))
        captured = []

        def stage_then_drift(*args, **kwargs):
            outcome = stage_generation(*args, **kwargs)
            captured.append(outcome)
            (root / "current").unlink()
            (root / "current").symlink_to("generations/" + "c" * 32)
            return outcome

        with mock.patch.object(portable, "assemble_linux", return_value=(payload, runtime)), \
                mock.patch.object(dev_stage_selected, "stage_generation", side_effect=stage_then_drift):
            facts = dev_stage_selected.produce(root, self.core, self.daemon, self.extension, metadata_path, **inputs)
        self.assertEqual(facts["generation"], captured[0].generation)
        self.assertEqual(facts["receiptSha256"], captured[0].receipt_sha256)
        self.assertEqual(facts["artifacts"], dev_stage_selected.input_hashes(self.core, self.daemon, self.extension))
        self.assertEqual(facts["scope"], dev_stage_selected.SCOPE)
        self.assertTrue(facts["selectedBytesVerified"])
        self.assertFalse(facts["daemonRestarted"])
        self.assertFalse(facts["chromiumReloaded"])
        self.assertFalse(facts["providerAccess"])
        self.assertFalse(facts["liveExecutableAttributed"])
        self.assertFalse(facts["atomicExecutionWitness"])
        encoded = dev_stage_selected.encode(facts)
        self.assertLessEqual(len(encoded), dev_stage_selected.MAX_OUTPUT)
        self.assertNotIn(b"arbitrary metadata", encoded)
        self.assertNotIn(str(root).encode(), encoded)

    def test_selected_producer_detects_declared_input_drift_after_staging(self):
        metadata_path, payload, runtime, inputs = self.declared_portable_inputs()
        root = self.base / "selected-stage"
        original = self.core.read_bytes()

        def stage_then_modify(*args, **kwargs):
            outcome = stage_generation(*args, **kwargs)
            self.core.write_bytes(original + b"changed declared input")
            return outcome

        with mock.patch.object(portable, "assemble_linux", return_value=(payload, runtime)), \
                mock.patch.object(dev_stage_selected, "stage_generation", side_effect=stage_then_modify):
            with self.assertRaisesRegex(dev_stage_selected.SelectedStageError, "declared-inputs-changed"):
                dev_stage_selected.produce(root, self.core, self.daemon, self.extension, metadata_path, **inputs)

    def test_selected_output_is_bounded(self):
        with self.assertRaisesRegex(dev_stage_selected.SelectedStageError, "selection-output-bound"):
            dev_stage_selected.encode({"unbounded": "x" * dev_stage_selected.MAX_OUTPUT})


if __name__ == "__main__":
    unittest.main()
