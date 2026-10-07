import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
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
        with tempfile.TemporaryDirectory() as temp, patch('codex_native_candidate_cache.trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)):
            state = Path(temp)
            cache = state / ('cache-v2-' + '1' * 64)
            self.assertIsNone(prior_receipt(state, cache, '1' * 64, 1))
            with self.assertRaises(ValueError):
                prior_receipt(state, cache, '1' * 64, 2)

    def test_dirty_cache_is_never_adopted(self):
        # Only shared Bazel temporary ancestors are substituted. Marker
        # contents still pass the real held-descriptor owner/shape checks.
        with tempfile.TemporaryDirectory() as temp, patch('codex_native_candidate_cache.trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)):
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

class TransitionAmendmentModels(unittest.TestCase):
    def test_transition_inventory_matches_actual_graph_digest_directory_order(self):
        import hashlib
        import codex_native_candidate_cache as cache
        from guard_cache import graph_digest
        # Actual graph_digest traverses a real tree. Deliberately create paths
        # in reverse order; root files must precede lexical-earlier children.
        selected = ['BUILD.bazel', 'flake.nix', 'a/BUILD.bazel',
                    'a/deep/x.bzl', 'a-peer/BUILD.bazel', 'clients/linux/BUILD.bazel',
                    'tools/a.py', 'tools/z.py', 'tools/nested/a.py']
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in reversed(selected):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('actual declared input:' + name).encode())
            actual = graph_digest(root)
            self.assertEqual(actual[1], selected)
            self.assertNotEqual(actual[1], sorted(selected))
            inventory = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                         for name in reversed(selected)}
            self.assertEqual(cache.transition_graph(inventory), actual)
            with patch('codex_native_candidate_cache.trusted_parent',
                       side_effect=lambda path: os.open(path,
                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)):
                self.assertEqual(cache.controller_inventory(root, actual, None), inventory)
                with self.assertRaisesRegex(ValueError, 'graph inventory mismatch'):
                    cache.controller_inventory(root, (actual[0], sorted(selected)), None)
            # Directory-order correction must not change the graph digest.
            digest = hashlib.sha256()
            for name in sorted(selected):
                digest.update(name.encode() + bytes((0,))
                              + bytes.fromhex(inventory[name]))
            self.assertEqual(actual[0], digest.hexdigest())

    def model(self):
        import copy
        import hashlib
        import codex_native_candidate_cache as cache
        names = sorted(cache.TRANSITION_CHANGED | {'BUILD.bazel', 'tools/guard_cache.py'})
        old_inventory = {name: hashlib.sha256(('before:' + name).encode()).hexdigest() for name in names}
        new_inventory = copy.deepcopy(old_inventory)
        for name in cache.TRANSITION_REQUIRED:
            new_inventory[name] = hashlib.sha256(('after:' + name).encode()).hexdigest()
        before = {'controller_graph': list(cache.transition_graph(old_inventory)),
                  'modes': {'qualification': ['test', [native.CORE, native.CONFIG, native.LOGIN], None],
                            'schema': ['build', ['//bazel/schema:native-config-schema',
                                                 '//bazel/schema:public-schema-bundle'], None]},
                  'source_graph': {'BUILD.bazel': {'sha256': '1' * 64}},
                  'source_inventory_sha256': '2' * 64,
                  'tools': {'bazel': native.BAZEL}, 'limits': {'jobs': 1, 'memory': 4294967296},
                  'export_receipt_sha256': '3' * 64, 'platform': '//codex-rs/core:owner-linux'}
        origin = cache.transition_digest(before)
        after = copy.deepcopy(before)
        after['controller_graph'] = list(cache.transition_graph(new_inventory))
        after['modes']['qualification-cli'] = ['test', [native.CORE, native.CONFIG, native.LOGIN,
                                                       '//codex-rs/cli:codex'], None]
        history = [{'id': '00000000-0000-0000-0000-' + str(number).zfill(12),
                    'sha256': str(number) * 64, 'cache_key': '9' * 64 if number < 3 else origin,
                    'attempt': number if number < 3 else number - 2}
                   for number in range(1, 6)]
        history.append({'id': cache.TRANSITION_PRIOR_EPOCH,
                        'sha256': cache.TRANSITION_PRIOR_RECEIPT, 'cache_key': origin, 'attempt': 4})
        document = {'schema_version': 1, 'scope': 'c26-qualification-cli-controller-only',
            'origin_key': origin, 'old_bindings': before, 'new_bindings': after,
            'old_controller_inventory': old_inventory, 'new_controller_inventory': new_inventory,
            'reviewed_file_changes': [
                {'path': name, 'before_sha256': old_inventory[name], 'after_sha256': new_inventory[name]}
                for name in sorted(cache.TRANSITION_REQUIRED)],
            'old_source_commit': cache.TRANSITION_OLD_COMMIT, 'new_source_commit': 'a' * 40,
            'prior_epoch': cache.TRANSITION_PRIOR_EPOCH,
            'prior_receipt_sha256': cache.TRANSITION_PRIOR_RECEIPT,
            'previous_dispatches': history, 'from_attempt': 4, 'first_attempt': 5, 'max_attempts': 6,
            'aggregate_before': 6, 'aggregate_max': 8}
        args = SimpleNamespace(source_commit='a' * 40, source_dirty='false')
        return cache, document, after, new_inventory, args, origin

    def validate(self, values):
        cache, document, current, inventory, args, origin = values
        with patch.object(cache, 'TRANSITION_KEY', origin), patch.object(
                cache, 'TRANSITION_OLD_GRAPH', document['old_bindings']['controller_graph'][0]):
            return cache.validate_transition_document(document, current, inventory, args)

    def test_exact_reviewed_controller_only_transition_retains_origin_and_counters(self):
        import copy
        values = self.model()
        snapshot = copy.deepcopy(values[1])
        self.assertIs(self.validate(values), values[1])
        self.assertEqual(values[1], snapshot)
        self.assertEqual(values[1]['from_attempt'], 4)
        self.assertEqual(values[1]['aggregate_before'], 6)

    def test_native_source_export_tools_platform_and_caps_cannot_change(self):
        import copy
        for field in ('source_graph', 'source_inventory_sha256', 'export_receipt_sha256',
                      'tools', 'platform', 'limits'):
            values = list(self.model())
            values[2][field] = {'unreviewed': 'value'}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(values)

    def test_prior_epoch_cleanup_pin_and_counter_reset_are_refused(self):
        for field, invalid in (('prior_epoch', '00000000-0000-0000-0000-000000000000'),
                               ('prior_receipt_sha256', '0' * 64), ('from_attempt', 0),
                               ('first_attempt', 1), ('aggregate_before', 0),
                               ('aggregate_max', 9), ('max_attempts', True)):
            values = list(self.model())
            values[1][field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(values)

    def test_duplicate_or_missing_prior_dispatch_does_not_replenish_budget(self):
        for kind in ('duplicate', 'missing'):
            values = list(self.model())
            history = values[1]['previous_dispatches']
            if kind == 'duplicate':
                history[1] = history[0].copy()
            else:
                history.pop(0)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(values)

    def test_extra_mode_or_wrong_combined_cli_target_is_refused(self):
        for kind in ('extra', 'missing-cli'):
            values = list(self.model())
            modes = values[2]['modes']
            if kind == 'extra':
                modes['arbitrary-build'] = ['build', ['//...'], None]
            else:
                modes['qualification-cli'][1].pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(values)

    def test_graph_definition_or_unreviewed_controller_change_is_refused(self):
        for name in ('BUILD.bazel', 'tools/guard_cache.py'):
            values = list(self.model())
            cache, document, current, inventory, args, origin = values
            inventory[name] = 'f' * 64
            current['controller_graph'] = list(cache.transition_graph(inventory))
            document['reviewed_file_changes'].append(
                {'path': name, 'before_sha256': document['old_controller_inventory'][name],
                 'after_sha256': inventory[name]})
            document['reviewed_file_changes'].sort(key=lambda row: row['path'])
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(values)

    def test_missing_origin_refuses_before_any_cache_lease_or_marker_write(self):
        cache, document, current, inventory, args, origin = self.model()
        args.native_cache_attempt = 5
        args.native_cache_transition_sha256 = 'a' * 64
        with patch.object(cache, 'bindings', return_value=current), patch.object(
                cache, 'read_transition', return_value=document), patch.object(
                cache, 'prior_receipt', return_value=None), patch.object(
                cache, 'CacheLease') as lease, patch.object(cache, 'TRANSITION_KEY', origin):
            with self.assertRaises(ValueError):
                cache.Candidate(args, Path('/run/model-epoch'), {}, (), '', 'system', lambda prior: True)
            lease.assert_not_called()

if __name__ == '__main__':
    unittest.main()
