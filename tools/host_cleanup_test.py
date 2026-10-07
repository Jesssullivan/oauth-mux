import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_cleanup import KNOWN_WORKSPACE, KNOWN_REPAIRS, KNOWN_DIAGNOSTIC, cleanup, category, current_main, diagnose, diagnostic_identities, CleanupRejection, failure_summary, find_sting_workspace, STING_RECOVERY_PROOF, artifact_components, workspace_output_base

LAYOUT = {}
for option in ["--layout-workspace", "--layout-output-base"]:
    if option in sys.argv:
        index = sys.argv.index(option)
        LAYOUT[option] = sys.argv[index + 1]
        del sys.argv[index:index + 2]


class CleanupTest(unittest.TestCase):
    def test_actual_fifo_authority_and_artifact_rejected_without_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "omux-proof"
            base.mkdir(mode=0o700)
            child = base / ".run-Ab12Cd34"
            child.mkdir(mode=0o700)
            os.mkfifo(child / "current.authority", 0o600)
            os.mkfifo(child / "build.log", 0o600)
            parent = child
            for component in artifact_components(child)[:-1]:
                parent = parent / component
                parent.mkdir(mode=0o700)
            os.mkfifo(parent / "release_archive.tar.gz", 0o600)
            started = time.monotonic()
            with patch("host_cleanup.ancestry", return_value=None), self.assertRaises(CleanupRejection):
                find_sting_workspace(base, os.getuid(), ".run-Cust0000", lambda: None)
            self.assertLess(time.monotonic() - started, 2)
    def test_finite_entry_boundary_reports_partial_crossing(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            for name in ["public-a", "public-b", "public-c"]:
                (child / name).write_text("public fixture")
            with patch("host_cleanup.MAX_ENTRIES", 2), self.assertRaises(CleanupRejection) as caught:
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertEqual(caught.exception.code, "entry-bound")
            self.assertEqual(caught.exception.partial_counts["entries"], 3)
            self.assertEqual(len(list(child.iterdir())), 1)

    def test_sting_artifact_exact_layout_content_and_nofollow_custody(self):
        for kind in ["valid", "hash", "shared", "hardlink", "alias", "symlink-file", "duplicate"]:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "omux-proof"
                base.mkdir(mode=0o700)
                child = base / ".run-Ab12Cd34"
                child.mkdir(mode=0o700)
                components = artifact_components(child)
                self.assertEqual(components[1], hashlib.md5(str(child / "source").encode()).hexdigest())
                parent = child
                for component in components[:-1]:
                    parent = parent / component
                    parent.mkdir(mode=0o700)
                archive = parent / components[-1]
                data = b"exact public archive"
                archive.write_bytes(data)
                archive.chmod(0o644)
                if kind == "shared":
                    parent.chmod(0o777)
                if kind == "hardlink":
                    os.link(archive, base / "second-archive-link")
                if kind == "alias":
                    original = child / "bazel"
                    original.rename(base / "outside-cache")
                    original.symlink_to(base / "outside-cache", target_is_directory=True)
                if kind == "symlink-file":
                    archive.rename(base / "outside-archive")
                    archive.symlink_to(base / "outside-archive")
                if kind == "duplicate":
                    duplicate = base / ".run-Ef56Gh78"
                    duplicate.mkdir(mode=0o700)
                    duplicate_parent = duplicate
                    for component in artifact_components(duplicate)[:-1]:
                        duplicate_parent = duplicate_parent / component
                        duplicate_parent.mkdir(mode=0o700)
                    (duplicate_parent / "release_archive.tar.gz").write_bytes(data)
                with patch("host_cleanup.ancestry", return_value=None), patch("host_cleanup.STING_RECOVERY_BYTES", len(data)), patch("host_cleanup.STING_RECOVERY_ARTIFACT", "0" * 64 if kind == "hash" else hashlib.sha256(data).hexdigest()):
                    if kind == "valid":
                        name, identity, evidence = find_sting_workspace(base, os.getuid(), ".run-Cust0000", lambda: None)
                        self.assertEqual((name, evidence), (child.name, "recorded-artifact-hash"))
                    else:
                        with self.assertRaises(CleanupRejection) as caught:
                            find_sting_workspace(base, os.getuid(), ".run-Cust0000", lambda: None)
                        self.assertEqual(caught.exception.code, "recovery-ambiguous" if kind == "duplicate" else "recovery-no-match")
                        self.assertEqual(caught.exception.safe_metadata["match_count"], 2 if kind == "duplicate" else 0)
                self.assertTrue(child.exists())
    def test_sting_recovery_unique_private_marker_and_log_hash(self):
        for evidence in ["marker", "log", "duplicate", "none"]:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "omux-proof"
                base.mkdir(mode=0o700)
                for name in [".run-Ab12Cd34", ".run-Ef56Gh78"]:
                    child = base / name
                    child.mkdir(mode=0o700)
                    metadata = os.lstat(child)
                    if evidence in {"marker", "duplicate"} and (name == ".run-Ab12Cd34" or evidence == "duplicate"):
                        document = child / "current.authority"
                        document.write_text(f"{STING_RECOVERY_PROOF}:{metadata.st_dev}:{metadata.st_ino}\n")
                        document.chmod(0o600)
                    if evidence == "log" and name == ".run-Ab12Cd34":
                        document = child / "build.log"
                        document.write_bytes(b"public failed graph")
                        document.chmod(0o600)
                with patch("host_cleanup.ancestry", return_value=None), patch("host_cleanup.STING_RECOVERY_LOG", hashlib.sha256(b"public failed graph").hexdigest()):
                    if evidence in {"duplicate", "none"}:
                        with self.assertRaises(CleanupRejection):
                            find_sting_workspace(base, os.getuid(), ".run-Cust0000", lambda: None)
                    else:
                        name, identity, authority = find_sting_workspace(base, os.getuid(), ".run-Cust0000", lambda: None)
                        self.assertEqual(name, ".run-Ab12Cd34")
                        self.assertEqual(authority, "proof-marker" if evidence == "marker" else "recorded-log-hash")
                        cleanup(base, name, os.getuid(), lambda: None, validate=lambda *args: None, current_identity=identity)
                        self.assertFalse((base / name).exists())
                        self.assertTrue((base / ".run-Ef56Gh78").exists())

    def test_expired_original_deadline_preserves_root_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "OmuxProof"
            base.mkdir(mode=0o700)
            child = base / ".run-Ab12Cd34"
            child.mkdir(mode=0o700)
            metadata = os.lstat(child)
            proof = "11111111-1111-4111-8111-111111111111"
            marker = child / "current.authority"
            marker.write_text(f"{proof}:{metadata.st_dev}:{metadata.st_ino}\n")
            marker.chmod(0o600)
            deadline = child / "cleanup.deadline"
            deadline.write_text(json.dumps({"proof_id": proof, "deadline": time.monotonic() - 1, "total": 60}))
            deadline.chmod(0o600)
            argv = ["host_cleanup", "--current", "--base", str(base), "--workspace", str(child), "--proof-id", proof]
            with patch("host_cleanup.sys.argv", argv), patch("host_cleanup.ancestry", return_value=None), self.assertRaises(TimeoutError):
                current_main()
            self.assertTrue(marker.exists() and deadline.exists())
    def test_shared_directory_rejection_returns_safe_partial_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            nested = child / "_tmp"
            nested.mkdir(mode=0o700)
            nested.chmod(0o1777)
            with self.assertRaises(CleanupRejection) as caught:
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            summary = failure_summary(caught.exception)
            self.assertEqual(summary["rejection_code"], "shared-write")
            self.assertEqual(summary["metadata"], {"mode": 0o1777, "owner_class": "current", "depth": 1, "scope": "workspace", "entry_kind": "_tmp"})
            self.assertEqual(summary["entries"], 1)
            self.assertEqual(summary["directories"], 1)
            self.assertTrue(nested.exists())
            self.assertEqual(stat.S_IMODE(os.lstat(nested).st_mode), 0o1777)
        self.assertEqual(failure_summary(ValueError("private detail"))["entries"], 0)
        self.assertNotIn("private detail", str(failure_summary(ValueError("private detail"))))
    def test_diagnostic_only_bounded_dependency_candidates(self):
        data = b"successful library libcurl.dylib\nerror: unable to resolve dependency\n    note: libSystem.B.dylib and libobjc.A.dylib\n    /personal/libPrivateAccount.dylib\nnext action libsqlite3.dylib\n"
        identities, categories = diagnostic_identities(data)
        self.assertEqual(identities, ["library:libSystem.B.dylib", "library:libobjc.A.dylib"])
        self.assertEqual(categories, ["unresolved-dependency"])
        self.assertEqual(diagnostic_identities(b"error: unable to resolve dependency\n" + b" " * 5000 + b"\n    libcurl.dylib\n")[0], [])

    def test_diagnostic_log_exact_hash_custody_and_alias_rejection(self):
        for kind in ["valid", "hash", "shared", "symlink", "hardlink", "oversized"]:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "OmuxProof"
                base.mkdir(mode=0o700)
                child = base / KNOWN_DIAGNOSTIC[0]
                child.mkdir(mode=0o700)
                data = b"error: unable to resolve dependency\n    libSystem.B.dylib\n"
                log = child / "build.log"
                if kind == "symlink":
                    log.symlink_to(base / "outside")
                else:
                    log.write_bytes(data)
                    log.chmod(0o644 if kind == "shared" else 0o600)
                    if kind == "hardlink":
                        os.link(log, base / "second-link")
                    if kind == "oversized":
                        with log.open("r+b") as stream:
                            stream.truncate(128 * 1024 * 1024 + 1)
                identity = (KNOWN_DIAGNOSTIC[0], KNOWN_DIAGNOSTIC[1], "0" * 64 if kind == "hash" else hashlib.sha256(data).hexdigest())
                with patch("host_cleanup.KNOWN_DIAGNOSTIC", identity), patch("host_cleanup.ancestry", return_value=None):
                    if kind == "valid":
                        self.assertEqual(diagnose(base, os.getuid(), lambda: None)["identities"], ["library:libSystem.B.dylib"])
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            diagnose(base, os.getuid(), lambda: None)
    def test_current_marker_identity_and_readonly_cleanup(self):
        for corrupt in [False, True]:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "OmuxProof"
                base.mkdir(mode=0o700)
                child = base / ".run-Ab12Cd34"
                child.mkdir(mode=0o700)
                metadata = os.lstat(child)
                proof = "11111111-1111-4111-8111-111111111111"
                marker = child / "current.authority"
                marker.write_text(f"{proof}:{metadata.st_dev}:{metadata.st_ino + int(corrupt)}\n")
                marker.chmod(0o600)
                deadline = child / "cleanup.deadline"
                deadline.write_text(json.dumps({"proof_id": proof, "deadline": time.monotonic() + 60, "total": 60}))
                deadline.chmod(0o600)
                nested = child / "sandbox"
                nested.mkdir(mode=0o555)
                argv = ["host_cleanup", "--current", "--base", str(base), "--workspace", str(child), "--proof-id", proof]
                with patch("host_cleanup.sys.argv", argv), patch("host_cleanup.ancestry", return_value=None):
                    if corrupt:
                        with self.assertRaises(ValueError):
                            current_main()
                        self.assertTrue(child.exists())
                    else:
                        self.assertEqual(current_main(), 0)
                        self.assertFalse(child.exists())

    def test_second_exact_repair_and_current_identity_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            second = base / ".run-UVJycRK3"
            second.mkdir(mode=0o700)
            self.assertEqual(cleanup(base, second.name, os.getuid(), lambda: None, validate=lambda *args: None)[0], "removed")
            self.assertEqual(len(KNOWN_REPAIRS), 4)
            fourth = base / ".run-s9jRDq9y"
            fourth.mkdir(mode=0o700)
            self.assertEqual(KNOWN_REPAIRS[fourth.name], "22412e51-546a-4379-bef2-9b164c552e46")
            self.assertEqual(cleanup(base, fourth.name, os.getuid(), lambda: None, validate=lambda *args: None)[0], "removed")
            third = base / KNOWN_DIAGNOSTIC[0]
            third.mkdir(mode=0o700)
            self.assertEqual(cleanup(base, third.name, os.getuid(), lambda: None, validate=lambda *args: None)[0], "removed")
            (base / ".run-Ab12Cd34").mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                cleanup(base, ".run-Ab12Cd34", os.getuid(), lambda: None, validate=lambda *args: None, current_identity=(0, 0))

    def test_current_marker_missing_shared_or_foreign_proof_rejected(self):
        for kind in ["missing", "shared", "proof", "symlink", "recovery"]:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "OmuxProof"
                base.mkdir(mode=0o700)
                child = base / (KNOWN_WORKSPACE if kind == "recovery" else ".run-Ab12Cd34")
                child.mkdir(mode=0o700)
                metadata = os.lstat(child)
                proof = "11111111-1111-4111-8111-111111111111"
                marker = child / "current.authority"
                if kind == "symlink":
                    marker.symlink_to(base / "outside")
                elif kind != "missing":
                    marker.write_text(f"{'22222222-2222-4222-8222-222222222222' if kind == 'proof' else proof}:{metadata.st_dev}:{metadata.st_ino}\n")
                    marker.chmod(0o666 if kind == "shared" else 0o600)
                argv = ["host_cleanup", "--current", "--base", str(base), "--workspace", str(child), "--proof-id", proof]
                with patch("host_cleanup.sys.argv", argv), patch("host_cleanup.ancestry", return_value=None), self.assertRaises((ValueError, OSError)):
                    current_main()
                self.assertTrue(child.exists())

    def base(self, directory):
        base = Path(directory) / "OmuxProof"
        base.mkdir(mode=0o700)
        child = base / KNOWN_WORKSPACE
        child.mkdir(mode=0o700)
        return base, child

    def test_readonly_owned_tree_repaired_and_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            nested = child / "public-sandbox"
            nested.mkdir(mode=0o700)
            (nested / "public.txt").write_text("public source")
            nested.chmod(0o555)
            outcome, counts = cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertEqual(outcome, "removed")
            self.assertEqual(counts["repaired_directories"], 1)
            self.assertFalse(child.exists())
            self.assertEqual(stat.S_IMODE(os.lstat(base).st_mode), 0o700)

    def test_external_store_style_symlink_never_followed_or_chmodded(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            outside = Path(directory) / "immutable-sdk"
            outside.mkdir(mode=0o755)
            header = outside / "public.h"
            header.write_text("public SDK")
            header.chmod(0o444)
            (child / "sdk").symlink_to(outside, target_is_directory=True)
            cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertEqual(header.read_text(), "public SDK")
            self.assertEqual(stat.S_IMODE(os.lstat(header).st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o755)

    def test_exact_authority_and_private_base_required_without_adoption(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            for name in [".run-other", "../outside", ""]:
                with self.assertRaises(ValueError):
                    cleanup(base, name, os.getuid(), lambda: None, validate=lambda *args: None)
            base.chmod(0o755)
            with self.assertRaises(ValueError):
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertTrue(child.exists())
            self.assertEqual(stat.S_IMODE(os.lstat(base).st_mode), 0o755)

    def test_child_symlink_rejected_and_foreign_owned_directory_not_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            nested = child / "foreign"
            nested.mkdir(mode=0o555)
            original = os.fstat
            def foreign(descriptor):
                data = original(descriptor)
                if data.st_ino == os.lstat(nested).st_ino:
                    return SimpleNamespace(st_uid=os.getuid() + 1, st_mode=data.st_mode, st_dev=data.st_dev, st_ino=data.st_ino)
                return data
            with patch("host_cleanup.os.fstat", side_effect=foreign), self.assertRaises(ValueError):
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertEqual(stat.S_IMODE(os.lstat(nested).st_mode), 0o555)
            nested.chmod(0o700)
            nested.rmdir()
            child.rmdir()
            child.symlink_to(Path(directory), target_is_directory=True)
            with self.assertRaises(ValueError):
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)

    def test_deadline_cancels_before_deletion_and_errors_metadata_only(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            def expired():
                raise TimeoutError("private path never emitted")
            with self.assertRaises(TimeoutError):
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), expired, validate=lambda *args: None)
            self.assertTrue(child.exists())
        self.assertEqual(category(PermissionError(errno.EACCES, "private")), "permissions")
        self.assertEqual(category(OSError(errno.ENOTEMPTY, "private")), "not-empty")
        self.assertEqual(category(TimeoutError("private")), "deadline")

    def test_shared_writable_nested_directory_rejected_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            base, child = self.base(directory)
            nested = child / "shared"
            nested.mkdir(mode=0o700)
            nested.chmod(0o777)
            with self.assertRaises(ValueError):
                cleanup(base, KNOWN_WORKSPACE, os.getuid(), lambda: None, validate=lambda *args: None)
            self.assertEqual(stat.S_IMODE(os.lstat(nested).st_mode), 0o777)


if __name__ == "__main__":
    if LAYOUT:
        def actual_layout(self):
            self.assertEqual(set(LAYOUT), {"--layout-workspace", "--layout-output-base"})
            self.assertEqual(workspace_output_base(Path(LAYOUT["--layout-workspace"])), Path(LAYOUT["--layout-output-base"]).name)
        CleanupTest.test_actual_declared_bazel_output_base_layout = actual_layout
    unittest.main()
