"""Exact retirement scope, custody and preservation regressions."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import retire_browser_cache as r


class RetirementTests(unittest.TestCase):
    def test_wrong_marker_refuses(self):
        with self.assertRaises(ValueError):
            r.verify_binding(b'{"clean":false}', b'{}')

    def test_fixed_scope_has_no_operator_cache_path(self):
        self.assertEqual(r.CACHE, 'cache-v2-' + r.KEY)
        self.assertTrue(r.STATE.startswith('/home/jess/'))
        with self.assertRaises(TypeError):
            r.run(cache_path='/arbitrary/cache')

    def test_boundary_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'actual').mkdir()
            (root / 'output-base').symlink_to(root / 'actual')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    r.directory(fd, 'output-base')
            finally:
                os.close(fd)

    def test_live_process_refuses_exact_bound_receipt(self):
        marker = {'schema': 2, 'clean': True, 'key': r.KEY, 'last_run': r.EPOCH,
                  'cleanup_receipt_sha256': 'fixture-receipt-hash'}
        receipt = {'id': r.EPOCH, 'cache_key': r.KEY, 'descendants_empty': True,
                   'output_base': r.STATE + '/' + r.CACHE + '/output-base',
                   'test_evidence': {'files': 0},
                   'observed_properties': {'MainPID': str(os.getpid())}}
        a = json.dumps(marker).encode()
        b = json.dumps(receipt).encode()
        receipt_hash = hashlib.sha256(b).hexdigest()
        marker['cleanup_receipt_sha256'] = receipt_hash
        a = json.dumps(marker).encode()
        with patch.object(r, 'MARKER_SHA', hashlib.sha256(a).hexdigest()), patch.object(r, 'RECEIPT_SHA', receipt_hash):
            with self.assertRaises(ValueError):
                r.verify_binding(a, b)

    def test_debug_copy_hashes_and_resume_preserve_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, epoch = Path(temporary) / 'base', Path(temporary) / 'epoch'
            base.mkdir()
            epoch.mkdir(mode=0o700)
            for name in r.DEBUG:
                (base / name).write_bytes(name.encode())
            bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            efd = os.open(epoch, os.O_RDONLY | os.O_DIRECTORY)
            try:
                first = r.preserve_debug(bfd, efd)
                for name in r.DEBUG:
                    (base / name).unlink()
                self.assertEqual(r.preserve_debug(bfd, efd), first)
                self.assertEqual(len(first['files']), 5)
            finally:
                os.close(bfd)
                os.close(efd)

    def test_compiled_inventory_skips_runfiles_and_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'omux').write_bytes(b'binary')
            (root / 'omux.runfiles').mkdir()
            (root / 'omux.runfiles' / 'input').write_bytes(b'excluded')
            (root / 'outside-link').symlink_to('/outside-operator-path')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                rows = []
                r.compiled_inventory(fd, 'bin', r.Budget(), rows)
                self.assertEqual(rows, [{'path': 'bin/omux', 'bytes': 6,
                                         'disposition': 'superseded-unshipped-derived-output'}])
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
