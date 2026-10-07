"""Prune boundary regressions: evidence/output preservation and nofollow deletion."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prune_epoch_runfiles as p


class PruneTests(unittest.TestCase):
    def test_only_runfiles_selected_and_link_target_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'omux'
            binary.write_bytes(b'compiled artifact')
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'valuable').write_bytes(b'keep')
            (root / 'app.runfiles').symlink_to(outside, target_is_directory=True)
            real = root / 'other.runfiles'
            real.mkdir()
            (real / 'copied-input').write_bytes(b'regenerable')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            candidates = []
            audit = os.open(root / 'audit', os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                bound = p.Bound()
                p.find_runfiles(fd, 'bin', bound, candidates)
                self.assertEqual({name for _, name, _ in candidates}, {'app.runfiles', 'other.runfiles'})
                for parent, name, path in candidates:
                    p.remove_tree(parent, name, path, bound, p.Audit(audit))
                self.assertEqual(binary.read_bytes(), b'compiled artifact')
                self.assertEqual((outside / 'valuable').read_bytes(), b'keep')
                self.assertFalse(real.exists())
                self.assertFalse((root / 'app.runfiles').is_symlink())
            finally:
                for parent, _, _ in candidates:
                    os.close(parent)
                os.close(fd)
                os.close(audit)

    def test_evidence_inventory_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'test.xml').write_bytes(b'<testsuite/>')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                rows = []
                p.inventory(fd, 'testlogs', p.Bound(), rows)
                self.assertEqual(rows[0]['path'], 'testlogs/test.xml')
                self.assertEqual(rows[0]['bytes'], 12)
                self.assertEqual((root / 'test.xml').read_bytes(), b'<testsuite/>')
            finally:
                os.close(fd)

    def test_public_plan_declared_symlink_and_writable_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'plan.json'
            path.write_bytes(b'{"epochs":[]}')
            link = Path(temporary) / 'declared-plan'
            link.symlink_to(path)
            self.assertEqual(p.read_plan(link), b'{"epochs":[]}')
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                p.read_plan(link)

    def test_current_and_bad_receipt_refused_before_filesystem_access(self):
        epoch = '11111111-1111-4111-8111-111111111111'
        with self.assertRaises(ValueError):
            p.prune(-1, {'uuid': epoch, 'receipt_sha256': '0' * 64}, epoch, True)
        with self.assertRaises(ValueError):
            p.exact_uuid('cache-' + '0' * 64)

    def test_cleanup_unknown_and_live_pid_refused(self):
        with self.assertRaises(ValueError):
            p.verify_dead({'id': 'epoch', 'descendants_empty': False}, 'epoch')
        with self.assertRaises(ValueError):
            p.absent_pid(os.getpid())

    def test_controller_admission_missing_context_refuses(self):
        with self.assertRaises(ValueError):
            p.controller_admission(-1, '/unavailable-private-root',
                                   '11111111-1111-4111-8111-111111111111')

    def test_budget_refuses_without_unbounded_walk(self):
        bound = p.Bound()
        bound.files = p.MAX_FILES
        with self.assertRaises(ValueError):
            bound.tick()

    def test_audit_sync_is_batched_and_root_intent_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            fd = os.open(Path(temporary) / 'audit', os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                journal = p.Audit(fd)
                with patch.object(p.os, 'fsync') as sync:
                    journal.write({'root_intent': 'app.runfiles', 'inode': 1}, durable=True)
                    self.assertEqual(sync.call_count, 1)
                    for _ in range(255):
                        journal.removed_member()
                    self.assertEqual(sync.call_count, 1)
                    journal.removed_member()
                    self.assertEqual(sync.call_count, 2)
                    journal.removed_member()
                    journal.checkpoint()
                    self.assertEqual(sync.call_count, 3)
            finally:
                os.close(fd)

    def test_audit_exhaustion_reserves_partial_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            fd = os.open(Path(temporary) / 'audit', os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                journal = p.Audit(fd)
                journal.bytes = p.MAX_AUDIT_BYTES - 2048
                with self.assertRaises(ValueError):
                    journal.write({'next': 'member'})
                journal.write({'complete': False, 'resumable': True}, durable=True, terminal=True)
                self.assertLessEqual(journal.bytes, p.MAX_AUDIT_BYTES)
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
