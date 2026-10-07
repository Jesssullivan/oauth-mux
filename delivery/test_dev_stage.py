"""Provider-free staging ownership and archive-boundary checks."""
import base64
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from dev_stage import HOST, MAX_ARCHIVE_MEMBERS, StageError, artifact, digest, stage


class StageTest(unittest.TestCase):
    def setUp(self):
        # Bazel's TEST_TMPDIR can have writable nonsticky ancestors. Use the
        # platform's root-owned sticky /tmp with our private owned child so the
        # production custody checks remain enabled, rather than chmod/mocking
        # shared execution directories.
        self.workspace = tempfile.TemporaryDirectory(prefix="omux-dev-stage-test-", dir=Path("/tmp").resolve())
        self.addCleanup(self.workspace.cleanup)
        self.path = Path(self.workspace.name)
        self.core = self.path / "core"
        self.daemon = self.path / "daemon"
        self.core.write_bytes(b"synthetic core")
        self.daemon.write_bytes(b"synthetic daemon")
        self.extension = self.path / "extension.zip"
        key = b"synthetic stable development identity" * 2
        extension_id = "".join(chr(ord("a") + int(c, 16)) for c in digest(key)[:32])
        self.metadata = {"schema_version": 1, "channel": "development", "instance": "dev", "native_host": HOST,
                         "extension": {"id": extension_id, "browser": "chromium", "version": "0.2.0"}}
        self.members = {"manifest.json": json.dumps({"key": base64.b64encode(key).decode(), "version": "0.2.0"}).encode(),
                        "shared/protocol.mjs": b'import {NATIVE_HOST} from "./channel.mjs";',
                        "shared/channel.mjs": ('export const CHANNEL = "development";\nexport const INSTANCE = "dev";\nexport const NATIVE_HOST = "' + HOST + '";\n').encode()}
        self.archive()
        self.root = self.path / "private"

    def archive(self):
        with zipfile.ZipFile(self.extension, "w") as archive:
            for name, data in self.members.items():
                archive.writestr(name, data)
        data = self.extension.read_bytes()
        self.metadata["artifact"] = {"sha256": digest(data), "bytes": len(data), "format": "zip"}

    def stage(self, replace=False):
        return stage(self.root, self.core, self.daemon, self.extension, self.metadata, replace)

    def test_stable_paths_explicit_atomic_replacement_and_isolation(self):
        receipt = self.stage()
        old = os.readlink(self.root / "current")
        self.assertEqual(receipt["metadata"]["instance"], "dev")
        self.assertEqual((self.root / "current/lib/omux-native-host").read_bytes(), self.core.read_bytes())
        self.assertIn("export OMUX_INSTANCE=dev", (self.root / "current/bin/omuxd").read_text())
        self.assertFalse((self.root / "bin/omux-native-host").is_symlink())
        launcher = (self.root / "bin/omux-native-host").read_bytes()
        with self.assertRaises(StageError):
            self.stage()
        self.daemon.write_bytes(b"new synthetic daemon")
        self.stage(True)
        self.assertNotEqual(old, os.readlink(self.root / "current"))
        self.assertTrue((self.root / old).is_dir())
        self.assertEqual(launcher, (self.root / "bin/omux-native-host").read_bytes())

    def test_modified_owned_generation_is_retained_and_refused(self):
        self.stage()
        target = self.root / "current/lib/omux"
        target.write_bytes(b"user modification")
        with self.assertRaises(StageError):
            self.stage(True)
        self.assertEqual(target.read_bytes(), b"user modification")

    def test_unowned_and_symlink_roots_are_refused(self):
        self.root.mkdir(mode=0o700)
        (self.root / "unrelated").write_text("keep")
        with self.assertRaises(StageError):
            self.stage()
        alternate = self.path / "alternate"
        alternate.symlink_to(self.root)
        with self.assertRaises(StageError):
            stage(alternate, self.core, self.daemon, self.extension, self.metadata)

    def test_stable_host_launcher_modification_prevents_switch(self):
        self.stage()
        old = os.readlink(self.root / "current")
        launcher = self.root / "bin/omux-native-host"
        launcher.write_bytes(b"user modification")
        with self.assertRaises(StageError):
            self.stage(True)
        self.assertEqual(old, os.readlink(self.root / "current"))
        self.assertEqual(launcher.read_bytes(), b"user modification")

    def test_production_metadata_contract(self):
        from extension_metadata import metadata
        self.metadata = metadata(self.extension, "development", "a" * 40, True)
        receipt = self.stage()
        self.assertEqual(receipt["metadata"]["source"], {"commit": "a" * 40, "dirty": True})
        self.assertEqual(receipt["metadata"]["channel"], "development")
        self.assertTrue((self.root / "bin/omux-native-host").is_file())
        self.assertFalse((self.root / "bin").is_symlink())

    def test_writable_nonsticky_ancestor_is_refused(self):
        parent = self.path / "unsafe"
        parent.mkdir()
        parent.chmod(0o777)
        self.root = parent / "stage"
        with self.assertRaises(StageError):
            self.stage()
        self.assertFalse(self.root.exists())

    def test_archive_escape_never_activates(self):
        self.members["../outside"] = b"bad"
        self.archive()
        with self.assertRaises(StageError):
            self.stage()
        self.assertFalse((self.root / "current").exists())
        self.assertFalse((self.root / "outside").exists())

    def test_empty_archive_members_still_have_a_count_bound(self):
        self.members.update({"empty-" + str(index): b"" for index in range(MAX_ARCHIVE_MEMBERS)})
        self.archive()
        with self.assertRaisesRegex(StageError, "member count"):
            self.stage()
        self.assertFalse((self.root / "current").exists())

    def test_archive_version_and_exact_channel_must_match_metadata(self):
        self.metadata["extension"]["version"] = "9.9.9"
        with self.assertRaisesRegex(StageError, "version"):
            self.stage()
        self.metadata["extension"]["version"] = "0.2.0"
        self.members["shared/channel.mjs"] += b"export const EXTRA = true;\n"
        self.archive()
        with self.assertRaisesRegex(StageError, "channel module"):
            self.stage()
        self.assertFalse((self.root / "current").exists())

    def test_artifact_fifo_is_rejected_without_waiting_for_a_writer(self):
        fifo = self.path / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(StageError, "regular file"):
            artifact(fifo)
        alias = self.path / "core-alias"
        alias.symlink_to(self.core)
        self.assertEqual(artifact(alias), self.core.read_bytes())

    def test_native_elf_requires_complete_declared_runtime_before_staging(self):
        self.core.write_bytes(b'\x7fELF' + b'not a complete ELF fixture')
        with self.assertRaisesRegex(StageError, 'complete declared runtime'):
            self.stage()
        self.assertFalse(self.root.exists())

    def test_wrong_channel_or_identity_never_activates(self):
        self.metadata["channel"] = "release"
        with self.assertRaises(StageError):
            self.stage()
        self.metadata["channel"] = "development"
        self.metadata["extension"]["id"] = "a" * 32
        with self.assertRaises(StageError):
            self.stage()
        self.assertFalse((self.root / "current").exists())

    def test_concurrent_staging_is_refused(self):
        import fcntl
        self.root.mkdir(mode=0o700)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(StageError):
                self.stage()
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
