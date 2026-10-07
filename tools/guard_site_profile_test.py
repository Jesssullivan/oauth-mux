"""Pure source-only site profile predicates; no tool invocation."""
import unittest
import hashlib
import json
import tempfile
from unittest.mock import Mock, patch
from pathlib import Path
from guard_site_profile import (finite_phase, command, MASKS, required_masks, proof_bindings, PROOF_FILES,
    RUNTIME_SOURCE, toolchain_binding, BAZEL, BAZEL_NATIVE, JDK, CANDIDATE_SHA256,
    read_qualification, source_snapshot, verify_source_snapshot, importer_arguments, validate_delivery_metadata,
    phase_isolation, retain_lockfile, SITE_SOURCE, FETCH_LABELS)


class SiteProfileTest(unittest.TestCase):
    def test_only_copyfile_has_local_strategy_for_site_actions(self):
        with patch('guard_site_profile.toolchain_binding'):
            for phase, args in (('qualification', ['test', '//:reference_check']),
                                ('checks', ['test', '//:unit_tests']), ('build', ['build', '//:build']),
                                ('archive', ['build', '//:site_archive'])):
                argv = command(BAZEL_NATIVE, JDK, None, '/owned/output', phase, args)
                self.assertEqual(argv.count('--strategy=CopyFile=local'), 1)
                self.assertIn('--spawn_strategy=sandboxed', argv)
                self.assertIn('--remote_executor=', argv)
                self.assertIn('--sandbox_default_allow_network=false', argv)
                self.assertEqual([item for item in argv if item.startswith('--strategy=') and 'local' in item],
                                 ['--strategy=CopyFile=local'])
            for phase, args in (('lock', ['mod', 'deps', '--lockfile_mode=update']),
                                ('fetch', ['fetch', '//:reference_check'])):
                self.assertNotIn('--strategy=CopyFile=local',
                    command(BAZEL_NATIVE, JDK, None, '/owned/output', phase, args))

    def test_qualification_accepts_only_the_two_canonical_python_test_labels(self):
        canonical = ['test', '//tools:qualified_site_tools_test', '//tools:nix_file_inventory_test']
        self.assertEqual(finite_phase('qualification', canonical), canonical)
        for label in ('//tools:all', '//tools:arbitrary', '//tools/...'):
            with self.assertRaises(ValueError):
                finite_phase('qualification', ['test', label])

    def test_fetch_has_only_nonempty_distinct_existing_finite_labels(self):
        selected = ['fetch'] + sorted(FETCH_LABELS)
        self.assertEqual(finite_phase('fetch', selected), selected)
        for label in FETCH_LABELS:
            self.assertEqual(finite_phase('fetch', ['fetch', label]), ['fetch', label])
        for args in (['fetch'], ['fetch', '//...'], ['fetch', '//:all'], ['fetch', '//:dev'],
                     ['fetch', '//:unit_tests', '//:unit_tests'], ['fetch', '//:unit_tests', '//:unrelated'],
                     ['fetch', '//:build', '--all'], ['fetch', '--repo=@site_nix'],
                     ['fetch', '//:build', '--lockfile_mode=update'], ['fetch', '//:build', '--build'],
                     ['build', '//:build'], ['test', '//:unit_tests']):
            with self.assertRaises(ValueError):
                phase_isolation('fetch', args)

    def test_fetch_is_networked_no_build_without_lock_mutation(self):
        selected = ['fetch', '//:unit_tests', '//:import_extension_delivery']
        self.assertEqual(phase_isolation('fetch', selected), {'PrivateNetwork': 'no'})
        # Command topology only; no fabricated qualification or dispatch.
        with patch('guard_site_profile.toolchain_binding'):
            argv = command(BAZEL_NATIVE, JDK, None, '/owned/output', 'fetch', selected)
            self.assertEqual(argv[0], str(BAZEL_NATIVE))
            self.assertIn('--nobuild', argv)
            self.assertEqual(argv.count('--lockfile_mode=error'), 1)
            self.assertNotIn('--lockfile_mode=update', argv)
            self.assertIn('--loading_phase_threads=2', argv)
            self.assertIn('--sandbox_default_allow_network=false', argv)
            self.assertEqual(argv[-2:], selected[1:])
            self.assertFalse(any(part.startswith('--test_') for part in argv))
        before = {'MODULE.bazel.lock': 'a', 'MODULE.bazel': 'b', 'src/app.svelte': 'c'}
        self.assertEqual(verify_source_snapshot(before, dict(before), 'fetch'), [])
        for name in before:
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, {**before, name: 'changed'}, 'fetch')

    def test_lock_regeneration_requires_exact_command_and_network_exception(self):
        selected = ['mod', 'deps', '--lockfile_mode=update']
        self.assertEqual(finite_phase('lock', selected), selected)
        self.assertEqual(phase_isolation('lock', selected), {'PrivateNetwork': 'no'})
        for args in (['mod', 'deps'], ['mod', 'tidy', '--lockfile_mode=update'],
                     selected + ['--lockfile_mode=update'], selected + ['//:build'],
                     ['mod', 'deps', '--lockfile_mode=error'], ['build', '//:build']):
            with self.assertRaises(ValueError):
                phase_isolation('lock', args)
        for phase, args in (('qualification', ['test', '//:reference_check']),
                            ('checks', ['test', '//:unit_tests']), ('build', ['build', '//:build']),
                            ('archive', ['build', '//:site_archive'])):
            self.assertEqual(phase_isolation(phase, args), {'PrivateNetwork': 'yes'})
            with self.assertRaises(ValueError):
                finite_phase(phase, selected)

    def test_lock_command_has_one_update_flag_and_no_action_options(self):
        # This tests only command topology with admission mocked out, never
        # manufacturing a full qualification receipt or invoking the command.
        with patch('guard_site_profile.toolchain_binding'):
            selected = command(BAZEL_NATIVE, JDK, None, '/owned/output', 'lock',
                               ['mod', 'deps', '--lockfile_mode=update'], run='/owned/run')
            self.assertEqual(selected.count('--lockfile_mode=update'), 1)
            self.assertNotIn('--lockfile_mode=error', selected)
            self.assertEqual(selected[-1], 'deps')
            self.assertIn('--loading_phase_threads=2', selected)
            self.assertFalse(any(part.startswith(('--jobs=', '--spawn_strategy=', '--remote_executor=',
                '--remote_cache=', '--disk_cache=', '--sandbox_default_allow_network=', '--symlink_prefix=')) for part in selected))
            regular = command(BAZEL_NATIVE, JDK, None, '/owned/output', 'checks', ['test', '//:unit_tests'])
            self.assertIn('--lockfile_mode=error', regular)
            self.assertNotIn('--lockfile_mode=update', regular)

    def test_lock_phase_source_fence_allows_only_its_metadata(self):
        before = {'MODULE.bazel.lock': 'a', 'MODULE.bazel': 'b', 'src/app.svelte': 'c'}
        after = {**before, 'MODULE.bazel.lock': 'd'}
        self.assertEqual(verify_source_snapshot(before, after, 'lock'), ['MODULE.bazel.lock'])
        for extra in ('MODULE.bazel', 'src/app.svelte', 'src/lib/content/extension-delivery.json'):
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, {**after, extra: 'changed'}, 'lock')
        for phase in ('qualification', 'checks', 'build', 'archive', 'import'):
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, after, phase)

    def test_lock_evidence_preserves_raw_bytes_exclusively(self):
        content = b'{"lockFileVersion":24}\n'
        digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch('guard_site_profile.bounded_file', return_value=content) as reader:
            run = Path(directory)
            receipt = retain_lockfile(SITE_SOURCE, run, digest, 'before')
            self.assertEqual((run / receipt['file']).read_bytes(), content)
            self.assertEqual(receipt['sha256'], digest)
            self.assertEqual((run / receipt['file']).stat().st_mode & 0o777, 0o600)
            reader.assert_called_once_with(SITE_SOURCE / 'MODULE.bazel.lock', digest, 16 * 1024 * 1024)
            with self.assertRaises(FileExistsError):
                retain_lockfile(SITE_SOURCE, run, digest, 'before')
            with self.assertRaises(ValueError):
                retain_lockfile(SITE_SOURCE, run, None, 'before')
            with self.assertRaises(ValueError):
                retain_lockfile('/unrelated/source', run, digest, 'after')
            with patch('guard_site_profile.file_bytes', return_value=(content, {'sha256': digest})):
                final = retain_lockfile(SITE_SOURCE, run, None, 'after')
            self.assertEqual((run / final['file']).read_bytes(), content)

    def test_proofs_bind_runtime_repository_not_site_source(self):
        validator = Mock(return_value=Path('/owned/inventory.json'))
        with patch('guard_site_profile.bounded_file') as reader:
            values = proof_bindings('/owned/inventory.json', 'a' * 64, validator,
                                    Path('/fast/state'), Path('/home/coordination'))
            for name, (relative, digest) in PROOF_FILES.items():
                self.assertEqual(values['OMUX_SITE_' + name.upper()], str(RUNTIME_SOURCE / relative))
                reader.assert_any_call(RUNTIME_SOURCE / relative, digest, 8 * 1024 * 1024)
        validator.assert_called_once_with('/owned/inventory.json', 'a' * 64,
                                          Path('/fast/state'), Path('/home/coordination'))

    def test_missing_new_mapping_receipt_refuses_old_evidence(self):
        with patch.dict(PROOF_FILES, {'mapping': ('delivery/proofs/mapping-96136df1.log', None)}), self.assertRaises(ValueError):
            proof_bindings('/owned/inventory.json', 'a' * 64, Mock(return_value=Path('/owned/inventory.json')),
                           Path('/fast/state'), Path('/home/coordination'))

    def test_exact_bazel9_version_required(self):
        # A self-labelled dictionary, including the previous version-only
        # receipt, is insufficient. Tests do not invent admission evidence.
        for status in ('candidate-settings-only', 'version-and-byte-qualified-site-coordinator', 'verified-site-toolchain'):
            qualification = {'status': status, 'bazel': str(BAZEL), 'java_home': str(JDK),
                             'bazel_version': '9.0.1', 'receipt_sha256': 'a' * 64}
            with self.assertRaises(ValueError):
                toolchain_binding(BAZEL_NATIVE, JDK, qualification)
            with self.assertRaises(ValueError):
                toolchain_binding(BAZEL, JDK, qualification)

    def test_partial_receipt_cannot_admit_commands(self):
        for status in ('candidate-settings-only', 'version-and-byte-qualified-site-coordinator', 'verified-site-toolchain'):
            payload = json.dumps({'schema_version': 1, 'status': status, 'closure_verified': False}).encode()
            with patch('guard_site_profile.bounded_file', return_value=payload):
                with self.assertRaises(ValueError):
                    read_qualification('/owned/report.json', hashlib.sha256(payload).hexdigest())

    def test_import_and_source_mutation_are_finite(self):
        before = {'BUILD.bazel': 'a', 'src/lib/content/extension-delivery.json': 'b', 'scripts/import.mjs': 'c'}
        changed = {**before, 'src/lib/content/extension-delivery.json': 'd'}
        self.assertEqual(verify_source_snapshot(before, changed, 'import'), ['src/lib/content/extension-delivery.json'])
        for phase in ('qualification', 'checks', 'build', 'archive'):
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, changed, phase)
        with self.assertRaises(ValueError):
            verify_source_snapshot(before, {**changed, 'scripts/import.mjs': 'd'}, 'import')
        with self.assertRaises(ValueError):
            importer_arguments('/owned/arbitrary.json', 'a' * 64, '/owned/selected.json')

    def test_source_fence_includes_scripts_and_application_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'src').mkdir()
            (root / 'BUILD.bazel').write_text('graph')
            (root / 'scripts/import.mjs').write_text('import')
            (root / 'src/app.svelte').write_text('application')
            prior = source_snapshot(root)
            self.assertEqual(set(prior), {'BUILD.bazel', 'scripts/import.mjs', 'src/app.svelte'})
            (root / 'src/app.svelte').write_text('changed')
            with self.assertRaises(ValueError):
                verify_source_snapshot(prior, source_snapshot(root), 'import')

    def test_unknown_delivery_fields_and_overclaim_are_rejected(self):
        for payload in (b'{"secret":"untrusted"}', b'{"schema_version":1,"channel":"release"}',
                        b'{"schema_version":1,"schema_version":1}'):
            with self.assertRaises(ValueError):
                validate_delivery_metadata(payload)

    def test_finite_labels_and_phase_are_required(self):
        self.assertEqual(finite_phase('qualification', ['test', '//:reference_check']), ['test', '//:reference_check'])
        for phase, args in (('qualification', ['test', '//...']), ('build', ['test', '//:build']),
                            ('checks', ['test', '//:dev']), ('build', ['build', '//:site_archive']),
                            ('archive', ['build', '//:build']), ('preview', ['run', '//:preview']),
                            ('checks', ['test', '//:unit_tests', '--jobs=10']),
                            ('qualification', ['test', '//:reference_check', '//:reference_check'])):
            with self.assertRaises(ValueError):
                finite_phase(phase, args)

    def test_missing_tool_qualification_blocks_command(self):
        with self.assertRaises(ValueError):
            command('/nix/store/unqualified/bin/bazel', '/nix/store/unqualified-jdk', None,
                    '/private/output', 'qualification', ['test', '//:reference_check'])
        self.assertEqual(MASKS, ('/etc/bluetooth', '/etc/environment'))
        required_masks(MASKS)
        with self.assertRaises(ValueError):
            required_masks(['/etc/bluetooth'])


if __name__ == '__main__':
    unittest.main()
