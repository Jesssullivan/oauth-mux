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


class Phase2AmendmentModels(unittest.TestCase):
    def model(self):
        import copy
        import hashlib
        import codex_native_candidate_cache as cache
        names = sorted(cache.TRANSITION_CHANGED | {'BUILD.bazel', 'tools/guard_cache.py'})
        old_inventory = {name: hashlib.sha256(('n3:' + name).encode()).hexdigest()
                         for name in names}
        inventory = copy.deepcopy(old_inventory)
        for name in cache.TRANSITION_REQUIRED:
            inventory[name] = hashlib.sha256(('phase2:' + name).encode()).hexdigest()
        before = {'controller_graph': list(cache.transition_graph(old_inventory)),
            'modes': {'qualification-cli': ['test',
                [native.CORE, native.CONFIG, native.LOGIN, native.CLI], None],
                'schema': ['build', ['//bazel/schema:native-config-schema',
                                    '//bazel/schema:public-schema-bundle'], None]},
            'limits': {'memory': 4294967296, 'tasks': 512, 'cpu_percent': 200,
                'aggregate_seconds': 1200, 'postcheck_reserve_seconds': 120,
                'heap_mib': 768, 'jobs': 1},
            'source_inventory_sha256': '1' * 64, 'export_inventory_sha256': '2' * 64,
            'tools': {'bazel': native.BAZEL}, 'network': 'private', 'remote': False}
        after = copy.deepcopy(before)
        after['controller_graph'] = list(cache.transition_graph(inventory))
        after['limits']['aggregate_seconds'] = 3600
        retained = copy.deepcopy(cache.PHASE2_PRIOR_HISTORY)
        retained[0]['to_controller_graph_sha256'] = before['controller_graph'][0]
        retained[0]['to_provenance_sha256'] = cache.transition_digest(before)
        document = {'schema_version': 2, 'scope': 'c26-native-budget-phase2',
            'origin_key': cache.TRANSITION_KEY,
            'old_bindings': before, 'new_bindings': after,
            'old_controller_inventory': old_inventory, 'new_controller_inventory': inventory,
            'reviewed_file_changes': [{'path': name,
                'before_sha256': old_inventory[name], 'after_sha256': inventory[name]}
                for name in sorted(cache.TRANSITION_REQUIRED)],
            'old_source_commit': cache.PHASE2_OLD_COMMIT, 'new_source_commit': '8' * 40,
            'prior_epoch': cache.PHASE2_PRIOR_EPOCH,
            'prior_receipt_sha256': cache.PHASE2_PRIOR_RECEIPT,
            'prior_amendment_sha256': cache.PHASE2_PRIOR_AMENDMENT,
            'prior_transition_history': retained,
            'previous_dispatches': copy.deepcopy(cache.PHASE2_PREVIOUS_DISPATCHES),
            'from_attempt': 5, 'first_attempt': 6, 'max_attempts': 7,
            'aggregate_before': 7, 'aggregate_max': 9}
        args = SimpleNamespace(source_commit='8' * 40, source_dirty='false',
            native_owned_candidate_cache=True, manager='system',
            native_cache_attempt=6, native_mode='qualification-cli',
            native_cache_phase2=Path('/private/phase2.json'),
            native_cache_phase2_sha256='7' * 64,
            native_cache_transition=None, native_cache_transition_sha256=None,
            native_aggregate_seconds=3600, native_deadline=None,
            native_source_root=Path('/declared/source'),
            native_source_sha256='1' * 64, native_patch_sha256=['2' * 64] * 3)
        return document, args, inventory

    def frozen(self, document):
        import codex_native_candidate_cache as cache
        return patch.multiple(cache,
            PHASE2_OLD_PROVENANCE=cache.transition_digest(document['old_bindings']),
            PHASE2_OLD_GRAPH=document['old_bindings']['controller_graph'][0],
            PHASE2_PRIOR_HISTORY=document['prior_transition_history'])

    def test_closed_phase2_preserves_origin_history_and_only_native_wallclock(self):
        import copy
        import codex_native_candidate_cache as cache
        document, args, inventory = self.model()
        original = copy.deepcopy(document)
        with self.frozen(document):
            self.assertIs(cache.validate_phase2_document(
                document, document['new_bindings'], inventory, args), document)
            rows = cache.phase2_history(document, args.native_cache_phase2_sha256)
            self.assertEqual(rows[0], document['prior_transition_history'][0])
            self.assertEqual(rows[1]['from_provenance_sha256'],
                             rows[0]['to_provenance_sha256'])
            self.assertEqual((rows[1]['from_attempt'], rows[1]['first_attempt'],
                              rows[1]['aggregate_before'], rows[1]['aggregate_max']),
                             (5, 6, 7, 9))
        self.assertEqual(document, original)
        with self.assertRaises(ValueError):
            cache.valid_attempt(7, 6)
        cache.valid_attempt(7, 6, max_attempts=7)
        with self.assertRaises(ValueError):
            cache.valid_attempt(8, 7, max_attempts=8)

    def test_phase2_refuses_counter_reset_missing_failed_epoch_and_relabelled_prior(self):
        import copy
        import codex_native_candidate_cache as cache
        document, args, inventory = self.model()
        mutations = [
            ('from_attempt', 4), ('first_attempt', 5), ('max_attempts', 8),
            ('aggregate_before', 6), ('aggregate_max', 10), ('schema_version', True),
            ('prior_epoch', '00000000-0000-0000-0000-000000000000'),
            ('prior_receipt_sha256', '0' * 64),
            ('prior_amendment_sha256', '0' * 64),
            ('previous_dispatches', document['previous_dispatches'][:-1]),
            ('previous_dispatches', document['previous_dispatches'][1:]),
            ('prior_transition_history', []),
        ]
        with self.frozen(document):
            for field, value in mutations:
                mutated = copy.deepcopy(document)
                mutated[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    cache.validate_phase2_document(
                        mutated, document['new_bindings'], inventory, args)
            mutated = copy.deepcopy(document)
            mutated['unreviewed_extension'] = True
            with self.assertRaises(ValueError):
                cache.validate_phase2_document(
                    mutated, document['new_bindings'], inventory, args)

    def test_phase2_refuses_resource_network_tools_modes_and_unreviewed_graph_changes(self):
        import copy
        import hashlib
        import codex_native_candidate_cache as cache
        document, args, inventory = self.model()
        with self.frozen(document):
            for field, value in (('memory', 8589934592), ('tasks', 1024),
                                 ('cpu_percent', 400), ('heap_mib', 1536),
                                 ('jobs', 2), ('postcheck_reserve_seconds', 0),
                                 ('aggregate_seconds', 7200)):
                mutated = copy.deepcopy(document)
                mutated['new_bindings']['limits'][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    cache.validate_phase2_document(
                        mutated, mutated['new_bindings'], inventory, args)
            for field, value in (('network', 'public'), ('remote', True),
                                 ('tools', {'bazel': '/ambient/bazel'}),
                                 ('modes', {'qualification-cli': ['build', [], None]})):
                mutated = copy.deepcopy(document)
                mutated['new_bindings'][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    cache.validate_phase2_document(
                        mutated, mutated['new_bindings'], inventory, args)
            for name in ('BUILD.bazel', 'tools/guard_cache.py'):
                mutated = copy.deepcopy(document)
                changed = copy.deepcopy(inventory)
                changed[name] = hashlib.sha256(b'unreviewed change').hexdigest()
                mutated['new_controller_inventory'] = changed
                mutated['new_bindings']['controller_graph'] = list(cache.transition_graph(changed))
                mutated['reviewed_file_changes'].append({'path': name,
                    'before_sha256': mutated['old_controller_inventory'][name],
                    'after_sha256': changed[name]})
                mutated['reviewed_file_changes'].sort(key=lambda row: row['path'])
                with self.subTest(path=name), self.assertRaises(ValueError):
                    cache.validate_phase2_document(
                        mutated, mutated['new_bindings'], changed, args)

    def test_phase2_selector_is_paired_and_exclusive(self):
        import codex_native_candidate_cache as cache
        document, args, _ = self.model()
        self.assertTrue(cache.phase2_requested(args))
        for field, value in (('native_cache_phase2_sha256', None),
                             ('native_cache_phase2', None),
                             ('native_cache_transition', Path('/other/v1.json')),
                             ('native_cache_transition_sha256', '1' * 64)):
            with patch.object(args, field, value), self.subTest(field=field):
                with self.assertRaises(ValueError):
                    cache.phase2_requested(args)

    def previous(self, document):
        import copy
        import codex_native_candidate_cache as cache
        return {'id': cache.PHASE2_PRIOR_EPOCH, 'profile': 'codex-native',
            'source_commit': cache.PHASE2_OLD_COMMIT,
            'graph_sha256': document['old_bindings']['controller_graph'][0],
            'exit': 125, 'workload_exit': 124, 'controller_failure': None,
            'descendants_empty': True,
            'native_sdk': {'mode': 'qualification-cli',
                          'source_and_export_verified_after_cleanup': True},
            'native_candidate_cache': {'key': cache.TRANSITION_KEY, 'attempt': 5,
                'max_attempts': 6, 'origin_provenance_sha256': cache.TRANSITION_KEY,
                'provenance_sha256': cache.transition_digest(document['old_bindings']),
                'transition_history': copy.deepcopy(document['prior_transition_history']),
                'transition_verified_after_cleanup': True,
                'aggregate_attempt': 7, 'aggregate_max_attempts': 8,
                'aggregate_previous_dispatches': document['previous_dispatches'][:-1]}}

    def reads(self, document, latest):
        import copy
        records = {}
        for row in document['previous_dispatches']:
            records[row['id']] = {'id': row['id'], 'profile': 'codex-native',
                'native_candidate_cache': {'key': row['cache_key'], 'attempt': row['attempt']},
                'descendants_empty': True,
                'native_sdk': {'source_and_export_verified_after_cleanup': True}}
        records[latest['id']] = copy.deepcopy(latest)
        pins = {row['id']: row['sha256'] for row in document['previous_dispatches']}
        def read(parent, name, digest, **kwargs):
            self.assertEqual(name, 'receipt.json')
            self.assertEqual(digest, pins[parent.name])
            return copy.deepcopy(records[parent.name])
        return read

    def test_phase2_rehashes_all_seven_prior_receipts_before_accepting_failed_fifth(self):
        import codex_native_candidate_cache as cache
        document, args, _ = self.model()
        previous = self.previous(document)
        with self.frozen(document), patch.object(cache, 'trusted_parent', side_effect=lambda p: p), \
                patch.object(cache.os, 'close'), \
                patch.object(cache, 'metadata', side_effect=self.reads(document, previous)) as read:
            self.assertEqual(cache.verify_phase2_previous(
                args, document, previous, args.native_cache_phase2_sha256),
                document['previous_dispatches'])
            self.assertEqual(read.call_count, 7)
            previous['exit'] = 0
            with self.assertRaises(ValueError):
                cache.verify_phase2_previous(
                    args, document, previous, args.native_cache_phase2_sha256)

    def test_phase2_schema_requires_successful_sixth_and_exact_final_clean_marker(self):
        import copy
        import codex_native_candidate_cache as cache
        document, args, _ = self.model()
        previous = self.previous(document)
        previous.update(id='00000000-0000-0000-0000-000000000006',
            source_commit=args.source_commit, graph_sha256=document['new_bindings']['controller_graph'][0],
            exit=0, workload_exit=0)
        candidate = previous['native_candidate_cache']
        candidate.update(attempt=6, max_attempts=7,
            provenance_sha256=cache.transition_digest(document['new_bindings']),
            aggregate_attempt=8, aggregate_max_attempts=9,
            aggregate_previous_dispatches=document['previous_dispatches'],
            phase2_verified_before_launch=True)
        args.native_cache_attempt, args.native_mode = 7, 'schema'
        digest = '6' * 64
        with self.frozen(document):
            candidate['transition_history'] = cache.phase2_history(document, args.native_cache_phase2_sha256)
            read_historical = self.reads(document, self.previous(document))
            def read(parent, name, pin, **kwargs):
                if parent.name == previous['id']:
                    self.assertEqual(pin, digest)
                    return copy.deepcopy(previous)
                return read_historical(parent, name, pin, **kwargs)
            marker = {'clean': True, 'key': cache.TRANSITION_KEY, 'schema': 2,
                'last_run': previous['id'], 'cleanup_receipt_sha256': digest}
            with patch.object(cache, 'trusted_parent', side_effect=lambda p: p), \
                    patch.object(cache, 'trusted_directory', return_value=123), \
                    patch.object(cache.os, 'close'), patch.object(cache, 'metadata', side_effect=read), \
                    patch.object(cache, 'read_marker', return_value=marker):
                actual = cache.verify_phase2_previous(
                    args, document, previous, args.native_cache_phase2_sha256)
                self.assertEqual(actual[:-1], document['previous_dispatches'])
                self.assertEqual(actual[-1], {'id': previous['id'], 'sha256': digest,
                    'cache_key': cache.TRANSITION_KEY, 'attempt': 6})
                for field, value in (('exit', 125), ('workload_exit', 124),
                                     ('controller_failure', {'error': 'failed'}),
                                     ('source_commit', '0' * 40)):
                    with patch.dict(previous, {field: value}), self.subTest(field=field):
                        with self.assertRaises(ValueError):
                            cache.verify_phase2_previous(
                                args, document, previous, args.native_cache_phase2_sha256)
                with patch.dict(marker, {'clean': False}):
                    with self.assertRaises(ValueError):
                        cache.verify_phase2_previous(
                            args, document, previous, args.native_cache_phase2_sha256)

    def test_phase2_readonly_launch_predicate_cannot_be_assigned(self):
        import codex_native_candidate_cache as cache
        instance = cache.Candidate.__new__(cache.Candidate)
        instance._phase2_verified_before_launch = False
        self.assertFalse(instance.phase2_verified_before_launch)
        with self.assertRaises(AttributeError):
            instance.phase2_verified_before_launch = True
        instance._phase2_verified_before_launch = 1
        self.assertFalse(instance.phase2_verified_before_launch)

    def test_phase2_actual_constructor_waits_for_retained_native_inventory_and_cleanup_readback(self):
        import copy
        import codex_native_candidate_cache as cache
        document, args, _ = self.model()
        for integrity_error in (True, False):
            with self.subTest(integrity_error=integrity_error), tempfile.TemporaryDirectory() as temp, \
                    self.frozen(document), \
                    patch.object(cache, 'bindings', return_value=document['new_bindings']), \
                    patch.object(cache, 'read_transition', return_value=None), \
                    patch.object(cache, 'read_phase2', return_value=document) as observed, \
                    patch.object(cache, 'prior_receipt', return_value=self.previous(document)) as previous, \
                    patch.object(cache, 'verify_phase2_previous', return_value=document['previous_dispatches']), \
                    patch.object(cache, 'CacheLease') as lease, \
                    patch.object(native, 'validate_source', return_value={'source_inventory': {}}), \
                    patch.object(native.source_io, 'DEADLINE', None), \
                    patch.object(cache, 'trusted_parent', return_value=123), \
                    patch.object(cache.os, 'close'), \
                    patch.object(cache, 'verify_inventory',
                        side_effect=ValueError('retained inventory changed') if integrity_error else None):
                owned = lease.return_value
                owned.output_base = Path(temp) / 'output-base'
                instance = cache.Candidate.__new__(cache.Candidate)
                if integrity_error:
                    with self.assertRaisesRegex(ValueError, 'retained inventory changed'):
                        instance.__init__(args, Path('/new/epoch'), {}, (), '', 'system', lambda p: True)
                    self.assertFalse(instance.phase2_verified_before_launch)
                    owned.close.assert_called_once()
                    continue
                instance.__init__(args, Path('/new/epoch'), {}, (), '', 'system', lambda p: True)
                self.assertIs(instance.phase2_verified_before_launch, True)
                previous.assert_called_once_with(native.STATE, instance.root, cache.TRANSITION_KEY, 6,
                    max_attempts=7, previous_max_attempts=6)
                facts = instance.facts()
                self.assertEqual((facts['attempt'], facts['max_attempts'],
                                  facts['aggregate_attempt'], facts['aggregate_max_attempts']),
                                 (6, 7, 8, 9))
                self.assertEqual(facts['transition_history'][0],
                                 document['prior_transition_history'][0])
                self.assertFalse(instance.may_complete(True, True))
                changed = copy.deepcopy(document)
                changed['aggregate_max'] = 10
                observed.return_value = changed
                with self.assertRaisesRegex(ValueError, 'changed before terminal'):
                    instance.verify_transition_after_cleanup()
                self.assertFalse(instance.may_complete(True, True))
                observed.return_value = document
                instance.verify_transition_after_cleanup()
                self.assertTrue(instance.may_complete(True, True))
                self.assertFalse(instance.may_complete(False, True))

    def test_phase2_constructor_owned_empty_refusal_precedes_cache_lease(self):
        import codex_native_candidate_cache as cache
        document, args, _ = self.model()
        with patch.object(cache, 'bindings', return_value=document['new_bindings']), \
                patch.object(cache, 'read_transition', return_value=None), \
                patch.object(cache, 'read_phase2', return_value=document), \
                patch.object(cache, 'prior_receipt', return_value=self.previous(document)), \
                patch.object(cache, 'CacheLease') as lease:
            instance = cache.Candidate.__new__(cache.Candidate)
            with self.assertRaisesRegex(ValueError, 'cgroup is not empty'):
                instance.__init__(args, Path('/new/epoch'), {}, (), '', 'system', lambda p: False)
            self.assertFalse(instance.phase2_verified_before_launch)
            lease.assert_not_called()


if __name__ == '__main__':
    unittest.main()
