"""Pure finite-probe tests; no process trees, manager calls or live sockets."""
import io
from pathlib import Path
import tempfile
import unittest
from execution_guard_probe import OUTPUT_BYTES, overflow, record


class ProbeTest(unittest.TestCase):
    def test_finite_output(self):
        stream = io.BytesIO()
        overflow(stream)
        self.assertEqual(len(stream.getvalue()), OUTPUT_BYTES)

    def test_receipt_is_exclusive_and_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            record(path, {'phase': 'fixture'})
            with self.assertRaises(FileExistsError):
                record(path, {'phase': 'overwrite'})
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                record(link, {'phase': 'redirect'})
            self.assertIn('fixture', path.read_text())


if __name__ == '__main__':
    unittest.main()
