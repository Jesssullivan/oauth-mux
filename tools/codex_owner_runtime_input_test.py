"""Retained copy identity/custody refusals; no native application execution."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_owner_runtime_input as subject


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.archive, self.manifest, self.receipt = [self.root / name for name in ("input", "manifest", "receipt")]
        self.outputs = self.root / "outputs"
        self.outputs.mkdir(mode=0o700)
        self.archive.write_bytes(b"finite retained fixture" * 31)
        self.manifest.write_bytes(b'{"native_support":false}\n')
        self.receipt.write_bytes(b'{"scope":"synthetic byte copy"}\n')
        self.pins = patch.multiple(subject, ARCHIVE_SHA=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                                  ARCHIVE_BYTES=self.archive.stat().st_size,
                                  MANIFEST_SHA=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
                                  EXPECTED_RECEIPT=self.receipt.read_bytes())
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def copy(self):
        return subject.copy_retained(self.archive, self.manifest, self.receipt,
                                     self.outputs, time.monotonic_ns() + 10**9)

    def test_exact_copy_preserves_source_and_separates_receipt(self):
        before = subject.identity(self.archive.stat())
        result = self.copy()
        copied = self.outputs / subject.ARCHIVE_SHA / subject.NAME
        self.assertEqual(copied.read_bytes(), self.archive.read_bytes())
        self.assertEqual(subject.identity(self.archive.stat()), before)
        self.assertEqual(copied.stat().st_mode & 0o777, 0o400)
        self.assertEqual(set((self.outputs / subject.ARCHIVE_SHA).iterdir()), {copied})
        self.assertTrue((self.outputs / "codex-owner-runtime-input-receipt.json").is_file())
        self.assertFalse(result["nativeSupport"])

    def test_existing_digest_leaf_is_never_overwritten(self):
        leaf = self.outputs / subject.ARCHIVE_SHA
        leaf.mkdir()
        sentinel = leaf / "prior"
        sentinel.write_bytes(b"retain")
        with self.assertRaises(FileExistsError):
            self.copy()
        self.assertEqual(sentinel.read_bytes(), b"retain")

    def test_changed_archive_same_size_refuses_without_success(self):
        self.archive.write_bytes(b"x" * subject.ARCHIVE_BYTES)
        with self.assertRaisesRegex(ValueError, "identity"):
            self.copy()
        self.assertFalse((self.outputs / subject.ARCHIVE_SHA).exists())
        self.assertFalse((self.outputs / "codex-owner-runtime-input-receipt.json").exists())

    def test_wrong_metadata_refuses_before_output(self):
        self.manifest.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "metadata-identity"):
            self.copy()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_receipt_requires_exact_serialized_bytes(self):
        self.receipt.write_bytes(self.receipt.read_bytes().rstrip())
        with self.assertRaisesRegex(ValueError, "metadata-identity"):
            self.copy()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_group_writable_input_refuses(self):
        self.archive.chmod(0o620)
        with self.assertRaisesRegex(ValueError, "custody"):
            self.copy()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_hardlinked_input_refuses(self):
        os.link(self.archive, self.root / "other")
        with self.assertRaisesRegex(ValueError, "custody"):
            self.copy()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_expired_deadline_refuses_before_copy(self):
        with self.assertRaisesRegex(ValueError, "deadline"):
            subject.copy_retained(self.archive, self.manifest, self.receipt, self.outputs, time.monotonic_ns())
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_short_write_completes_every_byte(self):
        original = os.write
        with patch.object(subject.os, "write", side_effect=lambda fd, data: original(fd, data[:7])):
            self.copy()
        self.assertEqual((self.outputs / subject.ARCHIVE_SHA / subject.NAME).read_bytes(), self.archive.read_bytes())

    def test_write_failure_has_no_archive_or_success_receipt(self):
        with patch.object(subject.os, "write", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.copy()
        self.assertFalse((self.outputs / subject.ARCHIVE_SHA).exists())
        self.assertFalse((self.outputs / "codex-owner-runtime-input-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
