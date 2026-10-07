import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-upstream"))

from codex_pristine_source import copy_bound, write_archive
from restore_pristine_inputs import COMMIT, TREE, original_files, safe_name, verified_stream
from restore_source import parse_arguments


class PristineCustodyTests(unittest.TestCase):
    def test_gzip_consumer_accepts_complete_declared_inventory(self):
        # Synthetic archive parser fixture; no real Git/source provenance claim.
        inventory = {"fixture-" + str(index): {"mode": "100644", "sha256": hashlib.sha256(b"x").hexdigest()}
                     for index in range(8497)}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:") as archive:
            for name in inventory:
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o644, 1
                archive.addfile(member, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "fixture.tar.gz"
            fields = write_archive(buffer.getvalue(), archive)
            report = {"status": "verified-pristine-source", "commit": COMMIT, "tree": TREE,
                      "files": inventory, "tracked_files": len(inventory), "source_bytes": len(inventory),
                      "inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
                      **fields}
            payload = json.dumps(report).encode()
            receipt = root / "receipt.json"
            receipt.write_bytes(payload)
            files, tree = original_files(archive, fields["archive_sha256"], receipt, hashlib.sha256(payload).hexdigest())
            self.assertEqual(tree, TREE)
            self.assertEqual(set(files), set(inventory))
            self.assertEqual(files["fixture-0"], ("100644", b"x"))

    def test_gzip_is_deterministic_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = b"pristine archive fixture\n" * 100
            first, second = root / "one.tar.gz", root / "two.tar.gz"
            left, right = write_archive(value, first), write_archive(value, second)
            self.assertEqual(left, right)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(gzip.decompress(first.read_bytes()), value)
            self.assertEqual(left["archive_format"], "tar.gz")

    def test_restore_pristine_requires_complete_inputs(self):
        base = ["--artifact-dir", "/declared/artifact", "--git", "/declared/git",
                "--ca-file", "/declared/ca", "--root", "/owned/fresh", "--phase", "restore-pristine"]
        with self.assertRaises(SystemExit):
            parse_arguments(base)
        complete = base + ["--pristine-archive", "/declared/source.tar", "--pristine-archive-sha256", "0" * 64,
                           "--pristine-receipt", "/declared/receipt.json", "--pristine-receipt-sha256", "1" * 64]
        self.assertEqual(parse_arguments(complete).phase, "restore-pristine")
        with self.assertRaises(SystemExit):
            parse_arguments(["fetch" if item == "restore-pristine" else item for item in complete])

    def test_declared_pack_drift_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.pack"
            source.write_bytes(b"changed pack")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                copy_bound(source, root / "owned.pack", "0" * 64)

    def test_pack_copy_preserves_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.pack"
            value = b"declared pack fixture"
            source.write_bytes(value)
            output = root / "owned.pack"
            result = copy_bound(source, output, hashlib.sha256(value).hexdigest())
            self.assertEqual(source.read_bytes(), value)
            self.assertEqual(output.read_bytes(), value)
            self.assertEqual(result["bytes"], len(value))

    def test_pristine_path_escape_refuses(self):
        for name in ("../source", "/absolute", "a/../b", "a\\b", "a\n"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_name(name)

    def test_verified_input_digest_and_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "archive.tar"
            value = b"fixture"
            source.write_bytes(value)
            with self.assertRaisesRegex(ValueError, "exceeds bound"):
                verified_stream(source, hashlib.sha256(value).hexdigest(), 1)
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                verified_stream(source, "0" * 64, 100)


if __name__ == "__main__":
    unittest.main()
