"""Actual private file staging with a modeled public payload, never a host proof.

The passed payload fixture supplies real archive/authority validation with a
synthetic inventory pin. Its explicit held temporary anchor substitutes only
for production /srv ancestors. No Nix, transport, browser or executable runs.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import time
import unittest
from unittest.mock import Mock, patch

import yoga_stage as stage
import yoga_payload as payload
import test_yoga_payload as payload_fixture


class StageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = payload_fixture.PayloadTests("test_real_proof_validation_deterministic_fixed_members_and_public_projection")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.exported, self.payload_root = self.fixture.export()
        self.archive = self.payload_root / "yoga-payload.tar"
        self.task_id = "12345678-1234-4123-8123-123456789012"
        self.destination = self.root / ("yoga-stage-" + self.task_id)
        self.deadline = time.monotonic_ns() + 900 * 10**9
        self.real_selectors = stage.selectors
        def selected(archive, destination, archive_sha256, manifest_sha256, deadline):
            # Preserve selector shape/deadline/digest tests while qualifying
            # actual metadata through the fixture's held temporary anchor.
            self.real_selectors("/srv/fixture/" + str(Path(archive).relative_to(self.root)),
                "/srv/fixture/" + str(Path(destination).relative_to(self.root)), archive_sha256, manifest_sha256, deadline)
        patcher = patch.object(stage, "selectors", side_effect=selected)
        patcher.start(); self.addCleanup(patcher.stop)

    def receive(self, **changes):
        args = dict(archive_path=str(self.archive), archive_sha256=self.exported["archiveSha256"],
            manifest_sha256=self.exported["manifestSha256"], destination=str(self.destination), deadline_ns=self.deadline)
        args.update(changes)
        return stage.stage(**args)

    def test_actual_staging_keeps_tools_data_and_retains_unproved_store_requirements(self):
        result = self.receive()
        receipt_bytes = (self.destination / "stage-receipt.json").read_bytes()
        receipt = json.loads(receipt_bytes)
        self.assertEqual(result["receiptSha256"], hashlib.sha256(receipt_bytes).hexdigest())
        self.assertEqual(receipt["taskId"], self.task_id)
        self.assertEqual(receipt["archiveSha256"], self.exported["archiveSha256"])
        self.assertEqual(receipt["sourceGraphSha256"], self.fixture.selected["sourceGraphSha256"])
        manifest = json.loads((self.destination / "manifest.json").read_bytes())
        self.assertEqual(receipt["storeRequirements"], manifest["storeRequirements"])
        for key in ("destinationRegistrationVerified", "storePayloadIncluded", "closureImported", "executionAuthority", "activationPerformed", "toolbarConsentProved"):
            self.assertIs(receipt[key], False)
        for name, original in self.fixture.files.items():
            self.assertEqual((self.destination / "source" / name).read_bytes(), original)
        for file in self.destination.rglob("*"):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o700 if file.is_dir() else 0o444)
        self.assertFalse(os.access(self.destination / "inputs/chromium", os.X_OK))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_independent_archive_or_manifest_digest_refuses_before_destination(self):
        for changes in (dict(archive_sha256="0" * 64), dict(manifest_sha256="0" * 64)):
            with self.assertRaises(ValueError):
                self.receive(**changes)
            self.assertFalse(self.destination.exists())

    def test_fifo_and_symlink_input_refuse_before_read_or_output(self):
        fifo, alias = self.root / "input.fifo", self.root / "input-alias"
        os.mkfifo(fifo, 0o600); alias.symlink_to(self.archive)
        for path in (fifo, alias):
            with patch.object(stage.os, "read") as reader:
                with self.assertRaises((ValueError, OSError)):
                    self.receive(archive_path=str(path))
                reader.assert_not_called()
            self.assertFalse(self.destination.exists())

    def test_regular_archive_ceiling_is_checked_before_collection(self):
        with patch.object(stage, "MAX_ARCHIVE", 1), patch.object(stage.os, "read") as reader:
            with self.assertRaisesRegex(stage.StageError, "archive_unqualified"):
                self.receive()
            reader.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_never_adopted_or_removed(self):
        self.destination.mkdir(mode=0o700)
        marker = self.destination / "unrelated"
        marker.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.receive()
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_selected_archive_with_extra_link_is_rejected_before_extraction(self):
        manifest, files = self.fixture.unpack(self.payload_root)
        extra = tarfile.TarInfo("unexpected-link")
        extra.type, extra.linkname = tarfile.SYMTYPE, "/outside"
        data, manifest_sha = payload_fixture.packed(manifest, files, extra=extra)
        changed = self.root / "untrusted-archive.tar"
        changed.write_bytes(data); changed.chmod(0o444)
        with self.assertRaisesRegex(stage.StageError, "payload_invalid"):
            self.receive(archive_path=str(changed), archive_sha256=hashlib.sha256(data).hexdigest(), manifest_sha256=manifest_sha)
        self.assertFalse(self.destination.exists())

    def test_partial_named_extraction_failure_removes_only_owned_task(self):
        unrelated = self.root / "unrelated"; unrelated.mkdir()
        real_write = stage.Task.write
        count = 0
        def refuse(task, *args, **options):
            nonlocal count
            count += 1
            if count == 4:
                raise stage.StageError("byte_bound")
            return real_write(task, *args, **options)
        with patch.object(stage.Task, "write", refuse), self.assertRaisesRegex(stage.StageError, "byte_bound"):
            self.receive()
        self.assertFalse(self.destination.exists()); self.assertTrue(unrelated.exists())

    def test_source_path_traversal_links_and_repeated_names_do_not_create_files(self):
        task = stage.Task(str(self.destination), self.deadline)
        try:
            for name in ("../outside", "/outside", "source/../outside", "source//outside"):
                with self.assertRaises(stage.StageError):
                    task.write(name, io.BytesIO(b"x"), 1)
            task.write("inputs/one", io.BytesIO(b"x"), 1)
            with self.assertRaises(stage.StageError):
                task.write("inputs/one", io.BytesIO(b"x"), 1)
            self.assertFalse((self.root / "outside").exists())
            task.cleanup()
        finally:
            task.close()

    def test_earlier_output_drift_during_later_verification_is_refused(self):
        task = stage.Task(str(self.destination), self.deadline)
        try:
            task.write("first", io.BytesIO(b"a"), 1)
            task.write("second", io.BytesIO(b"b"), 1)
            real_read = os.read
            mutated = False
            def read(descriptor, maximum):
                nonlocal mutated
                data = real_read(descriptor, maximum)
                if data == b"b" and not mutated:
                    first = self.destination / "first"; first.chmod(0o600); first.write_bytes(b"z")
                    mutated = True
                return data
            with patch.object(stage.os, "read", side_effect=read), self.assertRaisesRegex(stage.StageError, "output_changed"):
                task.verify()
            task.cleanup()
        finally:
            task.close()

    def test_replaced_output_inode_is_not_removed_as_owned(self):
        task = stage.Task(str(self.destination), self.deadline)
        try:
            task.write("data", io.BytesIO(b"a"), 1)
            original = self.destination / "data"
            original.rename(self.destination / "retained-own-file")
            original.write_bytes(b"foreign")
            with self.assertRaisesRegex(stage.StageError, "cleanup_incomplete"):
                task.cleanup()
            self.assertEqual(original.read_bytes(), b"foreign")
        finally:
            task.close()

    def test_source_archive_replacement_before_publish_refuses_and_cleans_task(self):
        real_verify = stage.Task.verify
        changed = False
        def replace(task):
            nonlocal changed
            real_verify(task)
            if not changed:
                changed = True
                self.archive.rename(self.payload_root / "retained-original")
                self.archive.write_bytes((self.payload_root / "retained-original").read_bytes())
                self.archive.chmod(0o444)
        with patch.object(stage.Task, "verify", replace), self.assertRaisesRegex(stage.StageError, "archive_changed"):
            self.receive()
        self.assertFalse(self.destination.exists())

    def test_unknown_entry_during_extraction_prevents_success_and_foreign_cleanup(self):
        real_verify = stage.Task.verify
        def insert(task):
            (self.destination / "foreign").write_bytes(b"preserve")
            return real_verify(task)
        with patch.object(stage.Task, "verify", insert), self.assertRaisesRegex(stage.StageError, "cleanup_incomplete"):
            self.receive()
        self.assertEqual((self.destination / "foreign").read_bytes(), b"preserve")

    def test_original_deadline_and_validator_window_never_create_short_budget_task(self):
        with patch.object(stage, "Task") as task:
            for deadline in (0, True, time.monotonic_ns() - 1, time.monotonic_ns() + 10**9,
                             time.monotonic_ns() + 60 * 10**9):
                with self.assertRaises(stage.StageError):
                    self.receive(deadline_ns=deadline)
            task.assert_not_called()

    def test_receipt_write_failure_unwinds_all_prepared_files(self):
        real_write = stage.Task.write
        def refuse(task, name, *args, **options):
            if name == "stage-receipt.json":
                raise OSError("fixed injected failure")
            return real_write(task, name, *args, **options)
        with patch.object(stage.Task, "write", refuse), self.assertRaises(OSError):
            self.receive()
        self.assertFalse(self.destination.exists())

    def test_production_selectors_reject_outside_srv_shared_task_and_bad_digests(self):
        args = ["/srv/inbox/payload.tar", "/srv/tasks/yoga-stage-" + self.task_id, "a" * 64, "b" * 64, self.deadline]
        for index, value in ((0, "/tmp/payload"), (0, "/srv/../payload"), (1, "/srv/tasks/shared"), (2, "bad")):
            changed = args.copy(); changed[index] = value
            with self.assertRaises(stage.StageError):
                self.real_selectors(*changed)


if __name__ == "__main__":
    unittest.main()
