"""Finite fixture proofs for selected-source identity, bounds and refusal."""

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runtime_source_receipt as source


class RuntimeSourceReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir()
        self.anchor = self.root / "BUILD.bazel"
        self.anchor.write_bytes(b"")
        self.anchor.chmod(0o644)
        (self.root / "src").mkdir()
        self.code = self.root / "src/main.zig"
        self.code.write_bytes(b"abc")
        self.code.chmod(0o644)
        self.files = [str(self.anchor), str(self.code)]

    def collect(self, files=None, **limits):
        return source.collect_inventory(str(self.anchor), self.files if files is None else files,
                                        **limits)

    def test_canonical_protocol_vector_and_selection_order(self):
        inventory = self.collect()
        expected = (b'{"files":[{"executable":false,"path":"BUILD.bazel",'
                    b'"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0},'
                    b'{"executable":false,"path":"src/main.zig",'
                    b'"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3}],'
                    b'"schema":"omux.runtime-source-inventory.v1"}')
        canonical = {key: inventory[key] for key in ("schema", "files")}
        self.assertEqual(source.canonical_bytes(canonical), expected)
        self.assertEqual(inventory["aggregate_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(inventory["aggregate_sha256"],
                         self.collect(list(reversed(self.files)))["aggregate_sha256"])
        self.assertEqual(inventory["total_bytes"], 3)
        self.assertEqual(inventory["file_count"], 2)
        for observation in inventory["observations"]:
            self.assertEqual(observation["before"], observation["after"])
            self.assertIn("ctime_ns", observation["before"])

    def test_changed_contents_and_executable_bit_change_digest(self):
        initial = self.collect()["aggregate_sha256"]
        self.code.write_bytes(b"abd")
        changed = self.collect()["aggregate_sha256"]
        self.assertNotEqual(initial, changed)
        self.code.chmod(0o755)
        self.assertNotEqual(changed, self.collect()["aggregate_sha256"])

    def test_timestamps_are_observations_not_canonical_source_identity(self):
        before = self.collect()
        info = self.code.stat()
        os.utime(self.code, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
        after = self.collect()
        self.assertEqual(before["aggregate_sha256"], after["aggregate_sha256"])
        self.assertNotEqual(before["observations"], after["observations"])

    def test_duplicate_selected_path_and_hardlink_alias_refused(self):
        with self.assertRaisesRegex(source.ReceiptError, "duplicate"):
            self.collect(self.files + [str(self.code)])
        alias = self.root / "src/alias.zig"
        os.link(self.code, alias)
        with self.assertRaisesRegex(source.ReceiptError, "same input"):
            self.collect(self.files + [str(alias)])

    def test_bazel_file_directory_and_intermediate_aliases_preserve_original_paths(self):
        execution = self.base / "execroot"
        runfiles = self.base / "runfiles/_main"
        execution.mkdir()
        runfiles.mkdir(parents=True)
        (execution / "BUILD.bazel").symlink_to(self.anchor)
        (execution / "src").symlink_to(self.root / "src", target_is_directory=True)
        (runfiles / "BUILD.bazel").symlink_to(execution / "BUILD.bazel")
        (runfiles / "src").mkdir()
        (runfiles / "src/main.zig").symlink_to(execution / "src/main.zig")
        observed = source.collect_inventory(str(runfiles / "BUILD.bazel"),
                                            [str(runfiles / "BUILD.bazel"),
                                             str(runfiles / "src/main.zig")])
        self.assertEqual(observed["aggregate_sha256"], self.collect()["aggregate_sha256"])
        self.assertEqual([entry["path"] for entry in observed["files"]],
                         ["BUILD.bazel", "src/main.zig"])

    def test_wrong_file_and_foreign_intermediate_alias_refused_before_open(self):
        runfiles = self.base / "runfiles"
        (runfiles / "src").mkdir(parents=True)
        (runfiles / "BUILD.bazel").symlink_to(self.anchor)
        foreign = self.base / "foreign.zig"
        foreign.write_bytes(b"unselected fixture")
        alias = runfiles / "src/main.zig"
        for target in (foreign, self.anchor):
            with self.subTest(target=target.name):
                alias.symlink_to(target)
                opened = []
                original = os.open
                def tracked(path, *args, **kwargs):
                    opened.append(path)
                    return original(path, *args, **kwargs)
                with patch.object(source.os, "open", tracked):
                    with self.assertRaisesRegex(source.ReceiptError, "changes repository path"):
                        source.collect_inventory(str(runfiles / "BUILD.bazel"),
                                                 [str(runfiles / "BUILD.bazel"), str(alias)])
                self.assertNotIn(foreign, opened)
                alias.unlink()

    def test_source_tree_symlink_is_not_a_bazel_alias(self):
        foreign = self.base / "foreign.zig"
        foreign.write_bytes(b"unselected fixture")
        self.code.unlink()
        self.code.symlink_to(foreign)
        with self.assertRaisesRegex(source.ReceiptError, "source-tree symlink"):
            self.collect()

    def test_fifo_and_directory_refused_without_blocking(self):
        self.code.unlink()
        os.mkfifo(self.code)
        with self.assertRaisesRegex(source.ReceiptError, "regular file"):
            self.collect()
        self.code.unlink()
        self.code.mkdir()
        with self.assertRaisesRegex(source.ReceiptError, "regular file"):
            self.collect()

    def test_bounded_file_count_individual_bytes_and_total_bytes(self):
        with self.assertRaisesRegex(source.ReceiptError, "count"):
            self.collect(max_files=1)
        with self.assertRaisesRegex(source.ReceiptError, "byte limit"):
            self.collect(max_file_bytes=2)
        second = self.root / "src/second.zig"
        second.write_bytes(b"de")
        with self.assertRaisesRegex(source.ReceiptError, "byte limit"):
            self.collect(self.files + [str(second)], max_file_bytes=3, max_total_bytes=4)
        with self.assertRaisesRegex(source.ReceiptError, "bounded policy"):
            self.collect(max_files=source.MAX_FILES + 1)

    def test_input_traversal_foreign_and_historical_scope_refused(self):
        traversal = str(self.root) + "/src/../src/main.zig"
        with self.assertRaisesRegex(source.ReceiptError, "traversal"):
            self.collect([str(self.anchor), traversal])
        foreign = self.base / "other.zig"
        foreign.write_bytes(b"foreign")
        with self.assertRaisesRegex(source.ReceiptError, "foreign input"):
            self.collect(self.files + [str(foreign)])
        for component in ("docs", ".goal", ".git", "evidence", "releases"):
            with self.subTest(component=component):
                with self.assertRaisesRegex(source.ReceiptError, "outside code scope"):
                    self.collect(self.files + [str(self.root / component / "unselected")])
        with self.assertRaisesRegex(source.ReceiptError, "root anchor must also"):
            self.collect([str(self.code)])

    def test_replaced_path_with_stable_open_descriptor_is_refused(self):
        actual = source.os.fstat
        calls = 0
        def replace_before_second_observation(descriptor):
            nonlocal calls
            calls += 1
            # The empty anchor takes calls 1/2; selected code takes 3/4.
            if calls == 4:
                replacement = self.root / "src/replacement.zig"
                replacement.write_bytes(b"abc")
                replacement.replace(self.code)
            return actual(descriptor)
        with patch.object(source.os, "fstat", replace_before_second_observation):
            with self.assertRaises(source.ReceiptError):
                self.collect()

    def test_in_place_same_size_change_with_restored_mtime_is_refused(self):
        actual = source.os.fstat
        calls = 0
        def change_before_second_observation(descriptor):
            nonlocal calls
            calls += 1
            if calls == 4:
                info = self.code.stat()
                self.code.write_bytes(b"xyz")
                os.utime(self.code, ns=(info.st_atime_ns, info.st_mtime_ns))
            return actual(descriptor)
        with patch.object(source.os, "fstat", change_before_second_observation):
            with self.assertRaisesRegex(source.ReceiptError, "changed during hashing"):
                self.collect()

    def test_final_observation_rejects_earlier_input_change(self):
        actual = source._hash_file
        def change_earlier_after_last_hash(path, *args):
            observed = actual(path, *args)
            if path == self.code:
                self.anchor.write_bytes(b"changed")
            return observed
        with patch.object(source, "_hash_file", change_earlier_after_last_hash):
            with self.assertRaisesRegex(source.ReceiptError, "before inventory freeze"):
                self.collect()

    def test_racing_parent_symlink_cannot_be_followed_by_open(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "main.zig").write_bytes(b"unselected fixture")
        actual = source._open_selected
        def replace_parent(root, relative):
            if relative.as_posix() == "src/main.zig":
                (self.root / "src").rename(self.root / "moved-src")
                (self.root / "src").symlink_to(outside, target_is_directory=True)
            return actual(root, relative)
        with patch.object(source, "_open_selected", replace_parent):
            with self.assertRaises(OSError):
                self.collect()

    def test_cli_emits_only_inventory_and_qualified_receipt(self):
        output = self.base / "outputs"
        output.mkdir()
        arguments = ["--root-anchor", str(self.anchor), "--parent-commit", "a" * 40,
                     "--dirty", "true"]
        for path in self.files:
            arguments.extend(["--file", path])
        stdout = io.StringIO()
        with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(output)}):
            with patch("sys.stdout", stdout):
                self.assertEqual(source.main(arguments), 0)
        directory = output / "runtime-source-receipt"
        self.assertEqual(sorted(path.name for path in directory.iterdir()),
                         ["receipt.json", "source-inventory.json"])
        receipt = json.loads((directory / "receipt.json").read_text())
        inventory = json.loads((directory / "source-inventory.json").read_text())
        self.assertEqual(receipt["claim"], "source_inventory_only")
        self.assertFalse(receipt["authentication_performed"])
        self.assertFalse(receipt["payload_output"])
        self.assertFalse(receipt["caller_git_metadata_verified"])
        self.assertEqual(receipt["caller_arguments"],
                         {"--parent-commit": "a" * 40, "--dirty": "true"})
        self.assertEqual(receipt["source_aggregate_sha256"], inventory["aggregate_sha256"])
        rendered = (directory / "receipt.json").read_text() + (directory / "source-inventory.json").read_text()
        self.assertNotIn(str(self.base), rendered)
        self.assertNotIn('"abc"', rendered)
        self.assertIn("no authentication; no payload output", stdout.getvalue())

    def test_expected_frozen_digest_mismatch_publishes_nothing(self):
        output = self.base / "outputs"
        output.mkdir()
        arguments = ["--root-anchor", str(self.anchor), "--parent-commit", "a" * 40,
                     "--dirty", "false", "--expected-source-sha256", "0" * 64]
        for path in self.files:
            arguments.extend(["--file", path])
        with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(output)}):
            with patch("sys.stderr", io.StringIO()):
                self.assertEqual(source.main(arguments), 1)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
