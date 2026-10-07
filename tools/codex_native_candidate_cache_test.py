import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from guard_cache import write_marker
from codex_native_candidate_cache import prior_receipt, completion_allowed, valid_attempt
import codex_native_profile as native

class CandidateAdmissionTests(unittest.TestCase):
    def test_completion_requires_positive_integrity_and_cleanup(self):
        self.assertTrue(completion_allowed(True, True))
        for cleanup, integrity in ((True, None), (True, False), (None, True),
                                   (False, True), (True, 1)):
            with self.subTest(cleanup=cleanup, integrity=integrity):
                self.assertFalse(completion_allowed(cleanup, integrity))

    def test_attempt_cap_and_exact_sequence(self):
        valid_attempt(1)
        valid_attempt(6, 5)
        for attempt, previous in ((0, None), (7, 6), (3, 1), (2, None), (True, None), (2, True)):
            with self.subTest(attempt=attempt, previous=previous):
                with self.assertRaises(ValueError):
                    valid_attempt(attempt, previous)

    def test_new_candidate_requires_attempt_one(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            cache = state / ('cache-v2-' + '1' * 64)
            self.assertIsNone(prior_receipt(state, cache, '1' * 64, 1))
            with self.assertRaises(ValueError):
                prior_receipt(state, cache, '1' * 64, 2)

    def test_dirty_cache_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            key = '1' * 64
            cache = state / ('cache-v2-' + key)
            cache.mkdir(mode=0o700)
            fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                write_marker(fd, {'schema': 2, 'key': key, 'clean': False,
                    'last_run': '00000000-0000-0000-0000-000000000001',
                    'cleanup_receipt_sha256': '2' * 64})
            finally:
                os.close(fd)
            with self.assertRaises(ValueError):
                prior_receipt(state, cache, key, 2)

    def test_cache_parent_readonly_and_only_leased_output_writable(self):
        args = SimpleNamespace(native_source_root=Path('/srv/source'), native_export_root=Path('/srv/export'))
        plan = {'cwd': '/srv/cache/native-input/source', 'candidate_cache_root': '/srv/cache',
            'candidate_output_base': '/srv/cache/output-base'}
        actual = {'BindReadOnlyPaths': ' '.join(native.readonly_paths(args, plan)),
            'BindPaths': '/srv/cache/output-base:/srv/cache/output-base:rbind'}
        native.verify_readonly(actual, args, plan)
        actual['BindPaths'] += ' /srv/cache/owner.json'
        with self.assertRaises(ValueError):
            native.verify_readonly(actual, args, plan)
        actual['BindPaths'] = '/srv/cache/output-base:/srv/cache/other:rbind'
        with self.assertRaises(ValueError):
            native.verify_readonly(actual, args, plan)

if __name__ == '__main__':
    unittest.main()
