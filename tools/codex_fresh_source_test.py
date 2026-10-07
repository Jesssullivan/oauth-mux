"""Pure/offline source-custody predicates; no SDK or provider invocation."""

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from codex_fresh_source import BASE_PATCH, MANIFEST_SHA, apply_recovery, apply_retirement, materialize, product_delta, read_bound, validate_paths
from restore_pristine_inputs import verified_stream
from codex_recovery_delta import build_delta
from patch_io import digest
from restore_source import COMMIT


def recovery_receipt(before, after, patch, changes):
    return {"status": "scoped-source-delta-awaiting-review", "commit": COMMIT,
            "baseline_manifest_sha256": MANIFEST_SHA, "baseline_patch_sha256": BASE_PATCH,
            "patch_sha256": digest(patch), "changes": changes,
            "selected_inputs": {name: {"before_sha256": digest(value), "after_sha256": digest(after[name])}
                                for name, value in before.items()}}


class FreshSourceTests(unittest.TestCase):
    def test_fifo_inputs_reject_before_read_and_open_nonblocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            real_open = os.open
            def nonblocking_open(path, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_NONBLOCK)
                return real_open(path, flags, *args, **kwargs)
            with patch("os.open", side_effect=nonblocking_open):
                with self.assertRaises(ValueError):
                    read_bound(fifo, 1024)
                with self.assertRaises(ValueError):
                    with verified_stream(fifo, "0" * 64, 1024):
                        self.fail("FIFO accepted")

    def test_writable_nonsticky_ancestor_refuses_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            ancestor = Path(directory) / "shared"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "private"
            parent.mkdir(mode=0o700)
            ancestor.chmod(0o777)
            try:
                with self.assertRaisesRegex(ValueError, "writable without sticky"):
                    materialize(parent / "epoch", {"fixture": ("100644", b"data")})
                self.assertFalse((parent / "epoch").exists())
            finally:
                ancestor.chmod(0o700)

    def test_symlink_ancestor_refuses_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            actual = parent / "actual"
            actual.mkdir(mode=0o700)
            (parent / "link").symlink_to(actual, target_is_directory=True)
            with self.assertRaises(OSError):
                materialize(parent / "link" / "epoch", {"fixture": ("100644", b"data")})
            self.assertFalse((actual / "epoch").exists())

    def test_recovery_replays_exact_reviewed_bytes_and_refuses_drift(self):
        name = "codex-rs/core/src/fixture.rs"
        before, after = {name: b"before\n"}, {name: b"after\n"}
        patch, changes = build_delta(before, after)
        receipt = recovery_receipt(before, after, patch, changes)
        files = {name: ("100644", before[name])}
        self.assertEqual(apply_recovery(files, patch, receipt, [name])[name], ("100644", after[name]))
        with self.assertRaises(ValueError):
            apply_recovery({name: ("100644", b"drift\n")}, patch, receipt, [name])
        with self.assertRaisesRegex(ValueError, "path selection"):
            apply_recovery(files, patch, receipt, [])

    def test_wrong_recovery_after_digest_refuses(self):
        name = "codex-rs/core/src/fixture.rs"
        before, after = {name: b"before\n"}, {name: b"after\n"}
        patch, changes = build_delta(before, after)
        receipt = recovery_receipt(before, after, patch, changes)
        receipt["selected_inputs"][name]["after_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            apply_recovery({name: ("100644", before[name])}, patch, receipt, [name])

    def test_product_delta_excludes_unmodified_validation_paths(self):
        name = "codex-rs/core/src/fixture.rs"
        originals = {name: ("100644", b"before\n"), "MODULE.bazel.lock": ("100644", b"validation original\n")}
        product = {**originals, name: ("100644", b"after\n")}
        patch, _, changes = product_delta(originals, product)
        self.assertEqual(set(changes), {name})
        self.assertNotIn(b"MODULE.bazel.lock", patch)

    def test_symlink_escape_and_file_parent_refuse(self):
        with self.assertRaisesRegex(ValueError, "escapes root"):
            validate_paths({"link": ("120000", b"../outside")})
        with self.assertRaisesRegex(ValueError, "parent path"):
            validate_paths({"parent": ("120000", b"target"), "parent/file": ("100644", b"data")})

    def test_fresh_output_collision_preserves_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "epoch"
            files = {"codex-rs/core/src/fixture.rs": ("100644", b"fixture\n")}
            source = materialize(root, files)
            self.assertEqual((source / "codex-rs/core/src/fixture.rs").read_bytes(), b"fixture\n")
            with self.assertRaises(FileExistsError):
                materialize(root, files)
            self.assertEqual((source / "codex-rs/core/src/fixture.rs").read_bytes(), b"fixture\n")

    def test_retirement_source_drift_refuses_before_transform(self):
        with self.assertRaisesRegex(ValueError, "before digest"):
            apply_retirement({"codex-rs/core/src/thread_manager.rs": ("100644", b"drift")}, "0" * 64)


if __name__ == "__main__":
    unittest.main()
