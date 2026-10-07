"""Pure byte/custody tests; synthetic ELF fixtures grant no execution authority."""
import json
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import sys
from unittest import mock

import home_manager_artifact as artifact
import portable
import test_portable as fixtures

REVISION = "f5f83c1ad99c2920de6759791b327a99a02a2ec5"


class ArtifactTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()))
        self.base = Path(self.temp.name)
        self.output = self.base / "outputs"
        self.output.mkdir(mode=0o700)
        self.fixture = fixtures.AssemblyTest(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.cleanup)
        self.floor = mock.patch.object(artifact, "FREE_FLOOR", 0)
        self.floor.start()
        self.addCleanup(self.floor.stop)
        self.archive = self.base / "selected.tar.gz"

    def cleanup(self):
        for parent, dirs, _ in os.walk(self.base, followlinks=False):
            os.chmod(parent, 0o700)
            for name in dirs:
                child = Path(parent) / name
                if not child.is_symlink():
                    os.chmod(child, 0o700)
        self.temp.cleanup()

    def bundle(self, *, qt=True, revision=REVISION, dirty=True, channel="development"):
        f = self.fixture
        if qt and not hasattr(self, "qt"):
            self.qt = f.configure_qt()
        control, plugins = self.qt if qt else (None, None)
        reference = f.write("reference.json", artifact.encoded({
            "schemaVersion": 1,
            "product": {"name": "Omux", "version": "0.2.0-dev", "status": "experimental"},
            "provenance": {"sourceRevision": None, "sourceDirty": True},
        }))
        service = f.write("omux.service.in", b"[Service]\nExecStart=@EXEC@\n")
        launchd = f.write("omux.plist.in", b"<plist>@EXEC@</plist>\n")
        with mock.patch.object(portable, "_patch", side_effect=f.patch_fixture):
            return artifact.pack.make_bundle(f.cli, f.daemon, reference, service, launchd,
                       target="x86_64-linux", channel=channel, runtime_files=f.runtime,
                       patchelf=f.patchelf, ca_bundle=f.ca_bundle, control=control,
                       qt_plugins=plugins, qt_runtime_files=f.runtime if qt else None,
                       source_revision=revision, source_dirty=dirty)

    def select(self, payload=None):
        payload = self.bundle() if payload is None else payload
        if self.archive.exists():
            self.archive.unlink()
        self.archive.write_bytes(payload)
        self.archive.chmod(0o444)
        return artifact.sha(payload)

    def export(self):
        digest = self.select()
        return artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))

    def retained(self):
        base = self.output / "home-manager-artifact"
        return base / "artifact", (base / "receipt.json").read_bytes()

    def test_real_packing_and_nar_roundtrip_is_logical_only(self):
        receipt = self.export()
        root, raw = self.retained()
        report = artifact.verify_artifact(str(root), raw, artifact.sha(raw))
        self.assertEqual(receipt["archiveSha256"], artifact.sha(self.archive.read_bytes()))
        self.assertEqual(receipt["manifestSha256"], artifact.sha((root / "release-manifest.json").read_bytes()))
        self.assertEqual(report["narHash"], receipt["narHash"])
        self.assertEqual(report["sourceQualification"], "caller-declared-dirty-development")
        self.assertFalse(report["executionAuthority"])
        self.assertFalse(report["activationPerformed"])
        self.assertNotIn("artifactDirectory", receipt)
        for parent, dirs, files in os.walk(root):
            self.assertEqual(stat.S_IMODE(os.stat(parent).st_mode), 0o555)
            for name in files:
                self.assertIn(stat.S_IMODE(os.stat(Path(parent) / name).st_mode), (0o444, 0o555))

    def test_envelope_publication_preserves_complete_sealed_tree_witness(self):
        digest = self.select()
        original = artifact.ExportTree.seal
        observed = False

        def witness(tree, prefix):
            nonlocal observed
            if prefix == "home-manager-artifact":
                root = str(self.output / "home-manager-artifact/artifact")
                before = artifact.tree_bytes(root, tree.deadline)
                original(tree, prefix)
                after = artifact.tree_bytes(root, tree.deadline)
                self.assertEqual(before, after)
                observed = True
            else:
                original(tree, prefix)

        with mock.patch.object(artifact.ExportTree, "seal", witness):
            artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertTrue(observed)

    def test_external_noop_chmod_of_sealed_directory_is_still_refused(self):
        digest = self.select()
        original = artifact.ExportTree.seal

        def disturb(tree, prefix):
            if prefix == "home-manager-artifact":
                os.chmod(self.output / "home-manager-artifact/artifact", 0o555)
            original(tree, prefix)

        with mock.patch.object(artifact.ExportTree, "seal", disturb):
            with self.assertRaisesRegex(ValueError, "sealed-directory-changed"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))

    def test_main_refusal_has_bounded_diagnostic_without_traceback_or_paths(self):
        private = "/private/caller-selected/archive"
        args = ["home_manager_artifact", "--archive", private,
                "--archive-sha256", "0" * 64, "--source-revision", REVISION]
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", args), mock.patch.dict(os.environ,
                {"TEST_UNDECLARED_OUTPUTS_DIR": str(self.output)}), \
                mock.patch.object(artifact, "export_archive", side_effect=ValueError(private + "x" * 100000)), \
                mock.patch.object(sys, "stderr", stderr):
            self.assertEqual(artifact.main(), 1)
        self.assertLess(len(stderr.getvalue()), 128)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn(private, stderr.getvalue())

    def test_main_success_reports_actual_raw_receipt_digest_without_authority(self):
        digest = self.select()
        alias = self.base / "declared.tar.gz"
        alias.symlink_to(self.archive)
        args = ["home_manager_artifact", "--archive", str(alias), "--declared-archive-alias",
                "--archive-sha256", digest, "--source-revision", REVISION]
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", args), mock.patch.dict(os.environ,
                {"TEST_UNDECLARED_OUTPUTS_DIR": str(self.output)}), \
                mock.patch.object(sys, "stdout", stdout):
            self.assertEqual(artifact.main(), 0)
        report = json.loads(stdout.getvalue())
        _, raw = self.retained()
        receipt = json.loads(raw)
        self.assertEqual(report["receiptSha256"], artifact.sha(raw))
        for key in ("archiveSha256", "narHash", "narSize", "sourceQualification"):
            self.assertEqual(report[key], receipt[key])
        self.assertFalse(report["executionAuthority"])
        self.assertFalse(report["activationPerformed"])
        self.assertLessEqual(len(stdout.getvalue()), 1025)

    def test_rejects_unfrozen_receipt_and_changed_nar(self):
        self.export()
        root, raw = self.retained()
        with self.assertRaisesRegex(ValueError, "frozen-receipt"):
            artifact.verify_artifact(str(root), raw, "0" * 64)
        receipt = json.loads(raw)
        receipt["narHash"] = "sha256-" + "A" * 43 + "="
        altered = artifact.encoded(receipt)
        with self.assertRaisesRegex(ValueError, "tree-receipt-binding"):
            artifact.verify_artifact(str(root), altered, artifact.sha(altered))

    def test_rejects_archive_digest_mismatch_before_output_creation(self):
        self.select()
        with self.assertRaisesRegex(ValueError, "archive-binding"):
            artifact.export_archive(str(self.archive), "0" * 64, REVISION, str(self.output))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_symlink_and_fifo_without_following_or_blocking(self):
        digest = self.select()
        alias = self.base / "alias"
        alias.symlink_to(self.archive)
        with self.assertRaises(OSError):
            artifact.export_archive(str(alias), digest, REVISION, str(self.output))
        fifo = self.base / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ValueError, "archive-custody"):
            artifact.export_archive(str(fifo), digest, REVISION, str(self.output))

    def test_explicit_declared_runfile_alias_exports_bound_physical_archive(self):
        digest = self.select()
        physical = self.base / "declared-inputs"
        physical.mkdir(mode=0o700)
        alias = physical / "archive.tar.gz"
        alias.symlink_to(self.archive)
        runfiles = self.base / "runfiles"
        runfiles.symlink_to(physical, target_is_directory=True)
        receipt = artifact.export_archive(str(runfiles / alias.name), digest, REVISION,
                                          str(self.output), declared_alias=True)
        self.assertEqual(receipt["archiveSha256"], digest)
        root, raw = self.retained()
        self.assertFalse(artifact.verify_artifact(str(root), raw, artifact.sha(raw))["executionAuthority"])

    def test_declared_alias_retargeting_even_to_equal_bytes_is_rejected(self):
        digest = self.select()
        second = self.base / "equal.tar.gz"
        second.write_bytes(self.archive.read_bytes())
        second.chmod(0o444)
        alias = self.base / "declared.tar.gz"
        alias.symlink_to(self.archive)
        original = artifact.pack.verify_bundle

        def retarget(payload):
            result = original(payload)
            alias.unlink()
            alias.symlink_to(second)
            return result

        with mock.patch.object(artifact.pack, "verify_bundle", side_effect=retarget):
            with self.assertRaisesRegex(ValueError, "alias-retargeted"):
                artifact.export_archive(str(alias), digest, REVISION, str(self.output),
                                        declared_alias=True)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_declared_alias_to_fifo_is_nonblocking_and_rejected(self):
        fifo = self.base / "fifo"
        os.mkfifo(fifo, 0o600)
        alias = self.base / "declared.tar.gz"
        alias.symlink_to(fifo)
        with self.assertRaisesRegex(ValueError, "archive-custody"):
            artifact.export_archive(str(alias), "0" * 64, REVISION, str(self.output),
                                    declared_alias=True)

    def test_bazel_output_parent_mode_preserved_and_envelope_exclusive_private(self):
        digest = self.select()
        self.output.chmod(0o755)
        original = artifact.ExportTree.write
        witnessed = False

        def private(tree, path, data, executable=False):
            nonlocal witnessed
            if not witnessed:
                witnessed = True
                self.assertEqual(stat.S_IMODE((self.output / "home-manager-artifact").stat().st_mode),
                                 0o700)
            return original(tree, path, data, executable)

        with mock.patch.object(artifact.ExportTree, "write", private):
            artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertTrue(witnessed)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.output / "home-manager-artifact").stat().st_mode), 0o555)

    def test_group_writable_output_parent_rejected_before_envelope_creation(self):
        digest = self.select()
        self.output.chmod(0o770)
        with self.assertRaisesRegex(ValueError, "ancestor-custody"):
            artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_parent_swap_during_copy_refuses_receipt_publication(self):
        digest = self.select()
        original = artifact.ExportTree.write
        swapped = False

        def replace(tree, path, data, executable=False):
            nonlocal swapped
            original(tree, path, data, executable)
            if not swapped:
                swapped = True
                self.output.rename(self.base / "previous-outputs")
                self.output.mkdir(mode=0o700)

        with mock.patch.object(artifact.ExportTree, "write", replace):
            with self.assertRaisesRegex(ValueError, "ancestor-replaced"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertFalse((self.base / "previous-outputs/home-manager-artifact/receipt.json").exists())

    def test_rejects_partial_qt_clean_release_or_different_caller_base(self):
        for index, kwargs in enumerate(({"qt": False}, {"dirty": False},
                                        {"channel": "release"}, {"revision": "1" * 40})):
            with self.subTest(kwargs=kwargs):
                payload = self.bundle(**kwargs)
                digest = self.select(payload)
                with self.assertRaisesRegex(ValueError, "full-qt|development-provenance"):
                    artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
                self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_source_archive_replacement_after_verification(self):
        digest = self.select()
        original = artifact.pack.verify_bundle

        def replace(payload):
            result = original(payload)
            self.archive.rename(self.base / "prior.tar.gz")
            self.archive.write_bytes(payload)
            self.archive.chmod(0o444)
            return result

        with mock.patch.object(artifact.pack, "verify_bundle", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "archive-replaced"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_full_ancestor_witness_detects_directory_replacement(self):
        child = self.base / "ancestor" / "leaf"
        child.mkdir(parents=True, mode=0o700)
        with artifact.HeldDirectory(str(child)) as selected:
            child.parent.rename(self.base / "previous")
            child.mkdir(parents=True, mode=0o700)
            with self.assertRaisesRegex(ValueError, "ancestor-replaced"):
                selected.check()

    def test_exclusive_export_never_overwrites_existing_output(self):
        digest = self.select()
        existing = self.output / "home-manager-artifact"
        existing.mkdir(mode=0o700)
        marker = existing / "marker"
        marker.write_bytes(b"previous evidence")
        with self.assertRaises(FileExistsError):
            artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertEqual(marker.read_bytes(), b"previous evidence")

    def test_output_leaf_replacement_stops_before_receipt_publication(self):
        digest = self.select()
        original = artifact.ExportTree.write
        changed = False

        def replace(tree, path, data, executable=False):
            nonlocal changed
            original(tree, path, data, executable)
            if not changed:
                changed = True
                leaf = self.output / path
                leaf.unlink()
                leaf.write_bytes(data)
                leaf.chmod(0o555 if executable else 0o444)

        with mock.patch.object(artifact.ExportTree, "write", replace):
            with self.assertRaisesRegex(ValueError, "output-file-replaced"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertFalse((self.output / "home-manager-artifact/receipt.json").exists())

    def test_untracked_output_entry_stops_before_receipt_publication(self):
        digest = self.select()
        original = artifact.ExportTree.write
        changed = False

        def inject(tree, path, data, executable=False):
            nonlocal changed
            original(tree, path, data, executable)
            if not changed:
                changed = True
                (self.output / "home-manager-artifact/rogue").write_bytes(b"undeclared")

        with mock.patch.object(artifact.ExportTree, "write", inject):
            with self.assertRaisesRegex(ValueError, "output-unexpected-entry"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertFalse((self.output / "home-manager-artifact/receipt.json").exists())

    def test_writable_tree_extra_directory_and_symlink_are_rejected(self):
        self.export()
        root, raw = self.retained()
        root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "writable"):
            artifact.verify_artifact(str(root), raw, artifact.sha(raw))
        extra = root / "extra"
        extra.mkdir(mode=0o555)
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "unaccounted-directory"):
            artifact.verify_artifact(str(root), raw, artifact.sha(raw))
        root.chmod(0o755)
        extra.rmdir()
        (root / "escape").symlink_to("/etc/passwd")
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "closed-regular"):
            artifact.verify_artifact(str(root), raw, artifact.sha(raw))

    def test_same_content_leaf_replacement_changes_custody_commitment(self):
        self.export()
        root, raw = self.retained()
        before = artifact.verify_artifact(str(root), raw, artifact.sha(raw))
        leaf = root / "release-manifest.json"
        data = leaf.read_bytes()
        root.chmod(0o755)
        leaf.unlink()
        leaf.write_bytes(data)
        leaf.chmod(0o444)
        root.chmod(0o555)
        after = artifact.verify_artifact(str(root), raw, artifact.sha(raw))
        self.assertEqual(before["narHash"], after["narHash"])
        self.assertNotEqual(before["metadataCommitment"], after["metadataCommitment"])

    def test_disk_floor_and_deadline_bound_before_publication(self):
        digest = self.select()
        with mock.patch.object(artifact, "FREE_FLOOR", 1 << 80):
            with self.assertRaisesRegex(ValueError, "disk-floor"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output))
        self.assertEqual(list(self.output.iterdir()), [])
        for seconds in (0, 301, True):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(ValueError, "deadline-bound"):
                artifact.export_archive(str(self.archive), digest, REVISION, str(self.output),
                                        deadline_seconds=seconds)

    def test_receipt_cannot_add_execution_authority_or_physical_path(self):
        receipt = self.export()
        for field, value in (("executionAuthority", True), ("artifactDirectory", "/untrusted")):
            hostile = artifact.encoded({**receipt, field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "receipt-schema"):
                artifact.validate_receipt(hostile, artifact.sha(hostile))


if __name__ == "__main__":
    unittest.main()
