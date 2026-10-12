"""Pure source-only site profile predicates; no tool invocation."""
import unittest
import hashlib
import json
import tempfile
from unittest.mock import Mock, patch
from pathlib import Path
from guard_site_profile import (finite_phase, command, MASKS, required_masks, proof_bindings, PROOF_FILES,
    toolchain_binding, BAZEL, BAZEL_NATIVE, JDK, CANDIDATE_SHA256,
    read_qualification, source_snapshot, verify_source_snapshot, importer_arguments, validate_delivery_metadata,
    phase_isolation, retain_lockfile, FETCH_LABELS, source_binding,
    admitted_import, reference_importer_arguments, verify_reference_outputs)


class SiteProfileTest(unittest.TestCase):
    def test_only_copyfile_has_local_strategy_for_site_actions(self):
        with patch('guard_site_profile.toolchain_binding'):
            for phase, args in (('qualification', ['test', '//:reference_check']),
                                ('checks', ['test', '//:unit_tests']), ('build', ['build', '//:build']),
                                ('archive', ['build', '//:site_archive'])):
                argv = command(BAZEL_NATIVE, JDK, None, '/owned/output', phase, args, source='/owned/site')
                self.assertEqual(argv.count('--strategy=CopyFile=local'), 1)
                self.assertIn('--spawn_strategy=sandboxed', argv)
                self.assertIn('--remote_executor=', argv)
                self.assertIn('--sandbox_default_allow_network=false', argv)
                self.assertEqual([item for item in argv if item.startswith('--strategy=') and 'local' in item],
                                 ['--strategy=CopyFile=local'])
            for phase, args in (('lock', ['mod', 'deps', '--lockfile_mode=update']),
                                ('fetch', ['fetch', '//:reference_check'])):
                self.assertNotIn('--strategy=CopyFile=local',
                    command(BAZEL_NATIVE, JDK, None, '/owned/output', phase, args, source='/owned/site'))

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
            argv = command(BAZEL_NATIVE, JDK, None, '/owned/output', 'fetch', selected, source='/owned/site')
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
                               ['mod', 'deps', '--lockfile_mode=update'], run='/owned/run', source='/owned/site')
            self.assertEqual(selected.count('--lockfile_mode=update'), 1)
            self.assertNotIn('--lockfile_mode=error', selected)
            self.assertEqual(selected[-1], 'deps')
            self.assertIn('--loading_phase_threads=2', selected)
            self.assertFalse(any(part.startswith(('--jobs=', '--spawn_strategy=', '--remote_executor=',
                '--remote_cache=', '--disk_cache=', '--sandbox_default_allow_network=', '--symlink_prefix=')) for part in selected))
            regular = command(BAZEL_NATIVE, JDK, None, '/owned/output', 'checks', ['test', '//:unit_tests'], source='/owned/site')
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
            source = run / 'site'
            source.mkdir()
            receipt = retain_lockfile(source, run, digest, 'before')
            self.assertEqual((run / receipt['file']).read_bytes(), content)
            self.assertEqual(receipt['sha256'], digest)
            self.assertEqual((run / receipt['file']).stat().st_mode & 0o777, 0o600)
            reader.assert_called_once_with(source / 'MODULE.bazel.lock', digest, 16 * 1024 * 1024)
            with self.assertRaises(FileExistsError):
                retain_lockfile(source, run, digest, 'before')
            with self.assertRaises(ValueError):
                retain_lockfile(source, run, None, 'before')
            with self.assertRaises(ValueError):
                retain_lockfile('/unrelated/source', run, digest, 'after')
            with patch('guard_site_profile.file_bytes', return_value=(content, {'sha256': digest})):
                final = retain_lockfile(source, run, None, 'after')
            self.assertEqual((run / final['file']).read_bytes(), content)

    def test_proofs_bind_runtime_repository_not_site_source(self):
        validator = Mock(return_value=Path('/owned/inventory.json'))
        with patch('guard_site_profile.bounded_file') as reader:
            values = proof_bindings('/owned/inventory.json', 'a' * 64, validator,
                                    Path('/fast/state'), Path('/home/coordination'), Path('/owned/runtime'))
            for name, (relative, digest) in PROOF_FILES.items():
                self.assertEqual(values['OMUX_SITE_' + name.upper()], str(Path('/owned/runtime') / relative))
                reader.assert_any_call(Path('/owned/runtime') / relative, digest, 8 * 1024 * 1024)
        validator.assert_called_once_with('/owned/inventory.json', 'a' * 64,
                                          Path('/fast/state'), Path('/home/coordination'))

    def test_missing_new_mapping_receipt_refuses_old_evidence(self):
        with patch.dict(PROOF_FILES, {'mapping': ('delivery/proofs/mapping-96136df1.log', None)}), self.assertRaises(ValueError):
            proof_bindings('/owned/inventory.json', 'a' * 64, Mock(return_value=Path('/owned/inventory.json')),
                           Path('/fast/state'), Path('/home/coordination'), Path('/owned/runtime'))

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
                    read_qualification('/owned/report.json', hashlib.sha256(payload).hexdigest(), Path('/owned/site'))

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

    def test_owned_binding_rejects_shared_metadata_parent_and_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            source = parent / 'omux.xoxd.ai'
            source.mkdir()
            git = source / '.git'
            git.mkdir()
            with patch('guard_site_profile.bounded_file', return_value=b'9.0.1\n') as reader:
                self.assertEqual(source_binding(source, 'a' * 64), source)
                reader.assert_called_once_with(source / '.bazelversion', 'a' * 64, 64)
                parent.chmod(0o755)
                with self.assertRaises(ValueError):
                    source_binding(source, 'a' * 64)
                parent.chmod(0o700)
                git.rmdir()
                git.write_text('gitdir: /shared/.git/worktrees/site')
                with self.assertRaises(ValueError):
                    source_binding(source, 'a' * 64)
                git.unlink()
                git.mkdir()
                (git / 'commondir').write_text('/shared/.git')
                with self.assertRaises(ValueError):
                    source_binding(source, 'a' * 64)
                (git / 'commondir').unlink()
                (git / 'objects/info').mkdir(parents=True)
                (git / 'objects/info/alternates').write_text('/shared/.git/objects')
                with self.assertRaises(ValueError):
                    source_binding(source, 'a' * 64)
                alias = parent / 'alias'
                alias.symlink_to(source, target_is_directory=True)
                with self.assertRaises(ValueError):
                    source_binding(alias, 'a' * 64)
                with patch('guard_site_profile.bounded_file', return_value=b'8.4.2\n'):
                    (git / 'objects/info/alternates').unlink()
                    with self.assertRaises(ValueError):
                        source_binding(source, 'a' * 64)

    def test_proof_bindings_use_explicit_owned_runtime(self):
        validator = Mock(return_value=Path('/owned/inventory.json'))
        runtime = Path('/owned/runtime')
        with patch('guard_site_profile.bounded_file') as reader:
            selected = proof_bindings('/owned/inventory.json', 'a' * 64, validator,
                                      Path('/fast/state'), Path('/home/coordination'), runtime)
            for name, (relative, digest) in PROOF_FILES.items():
                reader.assert_any_call(runtime / relative, digest, 8 * 1024 * 1024)
                self.assertEqual(selected['OMUX_SITE_' + name.upper()], str(runtime / relative))

    def test_reference_import_is_exclusive_exact_and_private_networked(self):
        bundle, digest = Path('/owned/reference-bundle.json'), 'a' * 64
        args = ['run', '//:import_reference', '--', '--bundle', str(bundle), '--sha256', digest]
        self.assertEqual(admitted_import('reference-import', args, bundle=bundle, bundle_sha256=digest), args)
        self.assertEqual(phase_isolation('reference-import', args), {'PrivateNetwork': 'yes'})
        for wrong in (args + ['--extra'], ['run', '//:import_reference', '--', '--manifest', str(bundle), '--sha256', digest],
                      ['run', '//:import_extension_delivery', '--', '--manifest', str(bundle), '--sha256', digest]):
            with self.assertRaises(ValueError):
                phase_isolation('reference-import', wrong)
        for values in ({'manifest': bundle}, {'manifest_sha256': digest}, {'bundle': None},
                       {'bundle': Path('/other/bundle')}, {'bundle_sha256': 'b' * 64}, {'bundle_sha256': 'bad'}):
            with self.assertRaises(ValueError):
                admitted_import('reference-import', args, **{'bundle': bundle, 'bundle_sha256': digest, **values})
        with self.assertRaises(ValueError):
            admitted_import('import', ['run', '//:import_extension_delivery', '--', '--manifest', str(bundle), '--sha256', digest],
                            manifest=bundle, manifest_sha256=digest, bundle=bundle)
        with patch('guard_site_profile.bounded_file') as reader:
            self.assertEqual(reference_importer_arguments(bundle, digest, bundle), args)
            reader.assert_called_once_with(bundle, digest, 2 * 1024 * 1024)
        with self.assertRaises(ValueError):
            reference_importer_arguments(bundle, digest, '/different/producer')

    def test_reference_output_fence_preserves_null_dirty_bytes_and_exact_sidecar(self):
        source, bundle = Path('/owned/site'), Path('/owned/reference-bundle.json')
        raw = b'{"schemaVersion":1,"provenance":{"sourceRevision":null,"sourceDirty":true}}\n'
        digest = hashlib.sha256(raw).hexdigest()
        sidecar = (digest + '\n').encode('ascii')
        with patch('guard_site_profile.bounded_file', side_effect=[raw, raw, sidecar]) as reader:
            verify_reference_outputs(source, bundle, digest)
            self.assertEqual(reader.call_args_list[1].args, (source / 'src/lib/content/reference-bundle.json', digest, 2 * 1024 * 1024))
            self.assertEqual(reader.call_args_list[2].args, (source / 'src/lib/content/reference-bundle.sha256', hashlib.sha256(sidecar).hexdigest(), 65))
        for output, digest_output in ((raw.replace(b'null', b'"invented"'), sidecar),
                                     (raw, sidecar.rstrip()), (raw, sidecar + b'\n')):
            with patch('guard_site_profile.bounded_file', side_effect=[raw, output, digest_output]), self.assertRaises(ValueError):
                verify_reference_outputs(source, bundle, digest)
        before = {'BUILD.bazel': 'a', 'src/lib/content/reference-bundle.json': 'old',
                  'src/lib/content/reference-bundle.sha256': 'old digest', 'src/lib/content/extension-delivery.json': 'b'}
        after = {**before, 'src/lib/content/reference-bundle.json': 'new', 'src/lib/content/reference-bundle.sha256': 'new digest'}
        self.assertEqual(verify_source_snapshot(before, after, 'reference-import'),
                         ['src/lib/content/reference-bundle.json', 'src/lib/content/reference-bundle.sha256'])
        for phase in ('import', 'lock', 'checks', 'build', 'archive'):
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, after, phase)
        for name in ('BUILD.bazel', 'src/lib/content/extension-delivery.json', 'scripts/import-reference.mjs'):
            with self.assertRaises(ValueError):
                verify_source_snapshot(before, {**after, name: 'changed'}, 'reference-import')

    def test_reference_command_fences_output_base_to_selected_owned_source(self):
        args = ['run', '//:import_reference', '--', '--bundle', '/owned/reference-bundle.json', '--sha256', 'a' * 64]
        selection = {'reference_bundle': '/owned/reference-bundle.json'}
        with patch('guard_site_profile.toolchain_binding'), patch('guard_site_profile.bounded_file'):
            argv = command(BAZEL_NATIVE, JDK, selection, '/owned/output', 'reference-import', args, source='/owned/site')
            self.assertIn('--remote_executor=', argv)
            self.assertIn('--sandbox_default_allow_network=false', argv)
            self.assertEqual(argv[-6:], args[1:])
            with self.assertRaises(ValueError):
                command(BAZEL_NATIVE, JDK, selection, '/owned/site/output', 'reference-import', args, source='/owned/site')

    def test_source_snapshot_rejects_shared_hardlinks_and_writable_files(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / 'BUILD.bazel'
            build.write_text('graph')
            build.chmod(0o666)
            with self.assertRaises(ValueError):
                source_snapshot(source)
            build.chmod(0o644)
            other = source / 'shared.bzl'
            os.link(build, other)
            with self.assertRaises(ValueError):
                source_snapshot(source)
            other.unlink()
            self.assertEqual(set(source_snapshot(source)), {'BUILD.bazel'})

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
                    '/private/output', 'qualification', ['test', '//:reference_check'], source='/owned/site')
        self.assertEqual(MASKS, ('/etc/bluetooth', '/etc/environment'))
        required_masks(MASKS)
        with self.assertRaises(ValueError):
            required_masks(['/etc/bluetooth'])


class DevelopmentArtifactModels(unittest.TestCase):
    """Tiny owned-filesystem predicates, not an installed package or site proof."""

    def fixture(self, directory, namespace=None, archive_bytes=b'PK\x03\x04public-byte-fixture'):
        import os
        import uuid
        import guard_site_profile as site
        parent = Path(directory)
        roots = [parent / name for name in ('state', 'coordination', 'site')]
        for root in roots:
            root.mkdir(mode=0o700)
        state, coordination, source = roots
        namespace = namespace or 'cache-v2-' + 'a' * 64
        archive = state / namespace / Path(*site.DEVELOPMENT_ARCHIVE_SUFFIX)
        manifest = state / namespace / Path(*site.DEVELOPMENT_MANIFEST_SUFFIX)
        archive.parent.mkdir(parents=True)
        manifest.parent.mkdir(parents=True)
        archive.write_bytes(archive_bytes)
        metadata = {'schema_version': 1, 'channel': 'development', 'instance': 'dev',
            'source': {'commit': 'a' * 40, 'dirty': False},
            'artifact': {'filename': archive.name, 'sha256': hashlib.sha256(archive_bytes).hexdigest(),
                         'bytes': len(archive_bytes), 'format': 'zip'},
            'extension': {'id': 'bggghdafplhajiailkafeihemlalagmm', 'version': '0.1.0', 'browser': 'chromium'},
            'native_host': 'ai.xoxd.omux.dev', 'protocol_version': 1,
            'capability_limits': {'max_message_bytes': 262144, 'max_secret_bytes': 8192, 'max_capsule_bytes': 131072,
                                 'provider_acquisition': 'experimental', 'native_continuity': 'unproved'},
            'signing': {'status': 'unsigned', 'store_publication': 'unpublished'}}
        manifest.write_bytes(json.dumps(metadata, sort_keys=True).encode())
        manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        wrapper = source / 'src/lib/content/extension-delivery.json'
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(json.dumps({'manifest': metadata, 'manifest_sha256': manifest_sha}))
        selection = coordination / str(uuid.uuid4()) / 'site-development-artifact-selection.json'
        selection.parent.mkdir(mode=0o700)
        value = {'schema_version': 1,
            'archive': {'path': str(archive), 'sha256': metadata['artifact']['sha256'], 'bytes': len(archive_bytes)},
            'manifest': {'path': str(manifest), 'sha256': manifest_sha}}
        selection.write_text(json.dumps(value))
        for path in (archive, manifest, wrapper, selection):
            path.chmod(0o600)
        # Isolate only TEST_TMPDIR ancestry. Real selected root ownership/mode,
        # every below-root directory, original named leaf and bytes stay checked.
        def root_fd(root, cutoff):
            if root not in roots:
                raise ValueError('fixture root is outside its selected filesystem')
            return [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)], []
        return {'roots': roots, 'archive': archive, 'manifest': manifest, 'wrapper': wrapper,
                'selection': selection, 'value': value, 'metadata': metadata, 'root_fd': root_fd}

    def read(self, fixture, *, original=None, deadline=None):
        import time
        import guard_site_profile as site
        state, coordination, source = fixture['roots']
        with patch.object(site, '_development_root', side_effect=fixture['root_fd']):
            return site.development_artifact(str(fixture['selection']),
                hashlib.sha256(fixture['selection'].read_bytes()).hexdigest(),
                state, coordination, source, deadline or time.monotonic_ns() + 60 * 10**9,
                original=original)

    def write_selection(self, fixture, value):
        fixture['selection'].write_text(json.dumps(value))

    def test_real_files_match_imported_raw_metadata_and_recheck_original_identity(self):
        import guard_site_profile as site
        for namespace in ('cache-v2-' + 'b' * 64, '5102699b-2ebf-44f1-a454-62b098e49658'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory, namespace)
                before = source_snapshot(fixture['roots'][2])
                result = self.read(fixture)
                self.assertEqual(result, self.read(fixture, original=result))
                self.assertEqual(result['output_base'], str(fixture['archive'].parents[6]))
                self.assertEqual(result['archive_facts']['bytes'], fixture['value']['archive']['bytes'])
                self.assertEqual(result['manifest_facts']['sha256'], fixture['value']['manifest']['sha256'])
                self.assertEqual(result['publication'], 'unpublished')
                self.assertEqual(result['native_continuity'], 'unproved')
                self.assertEqual(source_snapshot(fixture['roots'][2]), before)
                self.assertNotIn('content', result['archive_facts'])
                fixture['roots'][2].chmod(0o755)  # Actual source_binding permits this checkout mode.
                self.assertIsNotNone(self.read(fixture))

    def test_unknown_duplicate_bool_and_oversized_descriptor_fields_refuse(self):
        changes = (lambda value: {**value, 'extra': None},
                   lambda value: {**value, 'schema_version': True},
                   lambda value: {**value, 'archive': {**value['archive'], 'bytes': True}},
                   lambda value: {**value, 'archive': {**value['archive'], 'bytes': 16777217}},
                   lambda value: {**value, 'manifest': {**value['manifest'], 'sha256': 'A' * 64}},
                   lambda value: {**value, 'archive': {**value['archive'], 'extra': 'unused'}},
                   lambda value: {**value, 'manifest': {**value['manifest'], 'extra': 'unused'}})
        for change in changes:
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                self.write_selection(fixture, change(fixture['value']))
                with self.assertRaises(ValueError):
                    self.read(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            raw = fixture['selection'].read_text()
            fixture['selection'].write_text(raw[:-1] + ',"schema_version":1}')
            with self.assertRaises(ValueError):
                self.read(fixture)
            fixture['selection'].write_bytes(b'[' * 1500 + b'0' + b']' * 1500)
            with self.assertRaises(ValueError):
                self.read(fixture)
            fixture['selection'].write_bytes(b' ' * 8193)
            with self.assertRaises(ValueError):
                self.read(fixture)

    def test_exact_roles_same_output_base_and_no_legacy_or_unselected_root(self):
        import guard_site_profile as site
        for field, replacement in (
                ('archive', lambda path: path.replace('cache-v2-', 'cache-')),
                ('manifest', lambda path: path.replace('cache-v2-' + 'a' * 64, 'cache-v2-' + 'b' * 64)),
                ('archive', lambda path: path.replace('/state/', '/unselected/')),
                ('manifest', lambda path: path.replace('/state/', '/coordination/')),
                ('archive', lambda path: path.replace('chromium_dev_package.zip', 'chromium-dev.zip')),
                ('manifest', lambda path: path.replace('/k8-fastbuild/', '/darwin-fastbuild/')),
                ('archive', lambda path: path.replace('/output-base/', '/output-base/../output-base/')),
                ('archive', lambda path: path.replace('/output-base/', '//output-base/'))):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                value = fixture['value']
                value[field]['path'] = replacement(value[field]['path'])
                self.write_selection(fixture, value)
                with self.assertRaises(ValueError):
                    self.read(fixture)
        for value in ('relative', '/owned/./file', '/owned//file', '/owned/../file', '/owned/file name'):
            with self.assertRaises(ValueError):
                site._development_canonical(value)

    def test_imported_snapshot_digest_or_decoded_value_or_shape_cannot_be_substituted(self):
        for change in (lambda value: {**value, 'manifest_sha256': 'f' * 64},
                       lambda value: {**value, 'manifest': {**value['manifest'], 'instance': 'other'}},
                       lambda value: {**value, 'extra': None},
                       lambda value: {**value, 'manifest': {**value['manifest'], 'schema_version': True}},
                       lambda value: {**value, 'manifest': {**value['manifest'], 'source':
                           {**value['manifest']['source'], 'dirty': 0}}}):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                wrapper = json.loads(fixture['wrapper'].read_text())
                fixture['wrapper'].write_text(json.dumps(change(wrapper)))
                with self.assertRaises(ValueError):
                    self.read(fixture)

    def test_raw_metadata_fixed_id_host_browser_and_unsigned_unproved_contract(self):
        changes = (lambda value: value['extension'].update(id='a' * 32),
                   lambda value: value.update(native_host='ai.xoxd.omux'),
                   lambda value: value['extension'].update(browser='firefox'),
                   lambda value: value['signing'].update(status='signed'),
                   lambda value: value['capability_limits'].update(native_continuity='proved'))
        for change in changes:
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                change(fixture['metadata'])
                raw = json.dumps(fixture['metadata']).encode()
                fixture['manifest'].write_bytes(raw)
                sha = hashlib.sha256(raw).hexdigest()
                fixture['value']['manifest']['sha256'] = sha
                self.write_selection(fixture, fixture['value'])
                fixture['wrapper'].write_text(json.dumps({'manifest': fixture['metadata'], 'manifest_sha256': sha}))
                with self.assertRaises(ValueError):
                    self.read(fixture)

    def test_archive_bytes_size_and_manifest_digest_are_original_not_self_attested(self):
        for field in ('archive', 'manifest', 'size'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if field == 'size':
                    fixture['value']['archive']['bytes'] += 1
                    self.write_selection(fixture, fixture['value'])
                else:
                    fixture[field].write_bytes(fixture[field].read_bytes() + b'x')
                with self.assertRaises(ValueError):
                    self.read(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            with fixture['archive'].open('r+b') as stream:
                stream.truncate(16777217)
            with self.assertRaises(ValueError):
                self.read(fixture)

    def test_symlink_shared_hardlink_writable_leaf_and_private_root_refuse(self):
        import os
        for role in ('archive', 'manifest', 'selection', 'wrapper'):
            for action in ('symlink', 'hardlink', 'writable'):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self.fixture(directory)
                    path = fixture[role]
                    if action == 'writable':
                        path.chmod(0o666)
                    elif action == 'hardlink':
                        os.link(path, path.with_name('extra-link'))
                    else:
                        saved = path.with_name('saved-original')
                        path.rename(saved)
                        path.symlink_to(saved)
                    with self.assertRaises((ValueError, OSError)):
                        self.read(fixture)
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            fixture['roots'][0].chmod(0o755)
            with self.assertRaises(ValueError):
                self.read(fixture)

    def test_named_directories_reject_symlink_writes_and_descriptor_cache_namespace(self):
        for action in ('symlink', 'writable', 'descriptor-cache'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if action == 'descriptor-cache':
                    current = fixture['selection'].parent
                    moved = current.with_name('cache-v2-' + 'f' * 64)
                    current.rename(moved)
                    fixture['selection'] = moved / fixture['selection'].name
                elif action == 'writable':
                    fixture['archive'].parent.chmod(0o777)
                else:
                    original = fixture['archive'].parent
                    saved = original.with_name('saved-directory')
                    original.rename(saved)
                    original.symlink_to(saved, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    self.read(fixture)

    def test_same_bytes_replacement_and_directory_replacement_cannot_adopt_new_identity(self):
        import os
        for role in ('archive', 'manifest', 'selection', 'wrapper', 'namespace'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                original = self.read(fixture)
                if role == 'namespace':
                    namespace = fixture['archive'].parents[7]
                    saved = namespace.with_name('saved-namespace')
                    namespace.rename(saved)
                    import shutil
                    shutil.copytree(saved, namespace)
                else:
                    path = fixture[role]
                    replacement = path.with_name('replacement')
                    replacement.write_bytes(path.read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, path)
                with self.assertRaises(ValueError):
                    self.read(fixture, original=original)

    def test_named_leaf_swap_during_stream_refuses_and_stream_chunks_are_bounded(self):
        import os
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory, archive_bytes=b'PK\x03\x04' + b'x' * (3 * 65536))
            original_read = os.read
            archive_inode = fixture['archive'].stat().st_ino
            sizes, changed = [], [False]
            def swapping_read(fd, count):
                sizes.append(count)
                result = original_read(fd, count)
                if os.fstat(fd).st_ino == archive_inode and result and not changed[0]:
                    changed[0] = True
                    replacement = fixture['archive'].with_name('replacement')
                    replacement.write_bytes(fixture['archive'].read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, fixture['archive'])
                return result
            with patch.object(site.os, 'read', side_effect=swapping_read):
                with self.assertRaises(ValueError):
                    self.read(fixture)
            self.assertTrue(changed[0])
            self.assertTrue(all(0 < size <= 65536 for size in sizes))

    def test_exhausted_original_deadline_opens_no_selected_input(self):
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            with patch.object(site.time, 'monotonic_ns', return_value=100), \
                    patch.object(site, '_development_root') as reader:
                state, coordination, source = fixture['roots']
                with self.assertRaises(ValueError):
                    site.development_artifact(str(fixture['selection']),
                        hashlib.sha256(fixture['selection'].read_bytes()).hexdigest(), state, coordination, source, 100)
                reader.assert_not_called()

    def test_stream_cannot_reset_original_deadline_after_partial_zip_read(self):
        import os
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory, archive_bytes=b'PK\x03\x04' + b'x' * 131072)
            clock, reads = [100], [0]
            original_read = os.read
            archive_inode = fixture['archive'].stat().st_ino
            def partial_read(fd, count):
                result = original_read(fd, count)
                if os.fstat(fd).st_ino == archive_inode:
                    reads[0] += 1
                    clock[0] = 1000
                return result
            with patch.object(site.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                    patch.object(site.os, 'read', side_effect=partial_read):
                with self.assertRaises(ValueError):
                    self.read(fixture, deadline=1000)
            self.assertEqual(reads[0], 1)

    def test_all_original_roles_remain_held_and_named_through_last_zip_io_and_rehash(self):
        import os
        import guard_site_profile as site
        for role in ('selection', 'manifest', 'wrapper'):
            for pass_name in ('initial', 'final-rehash'):
                for action in ('replace-same-bytes', 'write-different-bytes'):
                    with tempfile.TemporaryDirectory() as directory:
                        fixture = self.fixture(directory, archive_bytes=b'PK\x03\x04' + b'x' * 131072)
                        baseline = self.read(fixture)
                        before = fixture[role].read_bytes()
                        archive_inode = fixture['archive'].stat().st_ino
                        original_read, original_seek = os.read, os.lseek
                        rehash, changed = [False], [False]
                        def seek(fd, offset, whence):
                            result = original_seek(fd, offset, whence)
                            if os.fstat(fd).st_ino == archive_inode:
                                rehash[0] = True
                            return result
                        def read(fd, count):
                            result = original_read(fd, count)
                            wanted = rehash[0] if pass_name == 'final-rehash' else not rehash[0]
                            if os.fstat(fd).st_ino == archive_inode and result and wanted and not changed[0]:
                                changed[0] = True
                                if action == 'replace-same-bytes':
                                    replacement = fixture[role].with_name('late-replacement')
                                    replacement.write_bytes(before)
                                    replacement.chmod(0o600)
                                    os.replace(replacement, fixture[role])
                                else:
                                    fixture[role].write_bytes(before + b' ')
                            return result
                        with patch.object(site.os, 'read', side_effect=read), \
                                patch.object(site.os, 'lseek', side_effect=seek):
                            with self.assertRaises(ValueError):
                                self.read(fixture, original=baseline)
                        self.assertTrue(changed[0])

    def test_late_gid_changes_in_held_or_named_files_and_role_directories_refuse(self):
        import os
        import guard_site_profile as site
        for target_name in ('selection', 'manifest', 'wrapper', 'archive-parent'):
            for witness in ('held', 'named'):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self.fixture(directory)
                    target = fixture['archive'].parent if target_name == 'archive-parent' else fixture[target_name]
                    target_inode = target.stat().st_ino
                    archive_inode = fixture['archive'].stat().st_ino
                    original_fstat, original_stat, original_read = os.fstat, os.stat, os.read
                    changed = [False]
                    class GidView:
                        def __init__(self, info):
                            self.info = info
                        def __getattr__(self, name):
                            return self.info.st_gid + 1 if name == 'st_gid' else getattr(self.info, name)
                    def fstat(fd):
                        info = original_fstat(fd)
                        return GidView(info) if changed[0] and witness == 'held' and info.st_ino == target_inode else info
                    def named_stat(*args, **kwargs):
                        info = original_stat(*args, **kwargs)
                        return GidView(info) if changed[0] and witness == 'named' and info.st_ino == target_inode else info
                    def read(fd, count):
                        result = original_read(fd, count)
                        if original_fstat(fd).st_ino == archive_inode and result:
                            changed[0] = True
                        return result
                    # Substitute only reported metadata, never change OS ownership.
                    with patch.object(site.os, 'fstat', side_effect=fstat), \
                            patch.object(site.os, 'stat', side_effect=named_stat), \
                            patch.object(site.os, 'read', side_effect=read):
                        with self.assertRaises(ValueError):
                            self.read(fixture)
                    self.assertTrue(changed[0])

    def test_close_errors_attempt_all_once_and_propagate_first_without_retrying_failed_fd(self):
        import os
        import guard_site_profile as site
        for failure in ('before-close', 'after-close', 'interrupt-after-close'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                opened, attempts, unclosed = [], [], []
                original_open, original_close = os.open, os.close
                def open_fd(*args, **kwargs):
                    fd = original_open(*args, **kwargs)
                    opened.append(fd)
                    return fd
                def close_fd(fd):
                    attempts.append(fd)
                    ordinal = len(attempts)
                    if failure == 'before-close' and ordinal <= 2:
                        unclosed.append(fd)
                    else:
                        original_close(fd)
                    if ordinal == 1:
                        if failure == 'interrupt-after-close':
                            raise KeyboardInterrupt('first-close-fault')
                        raise OSError('first-close-fault')
                    if ordinal == 2:
                        raise OSError('later-close-fault')
                try:
                    with patch.object(site.os, 'open', side_effect=open_fd), \
                            patch.object(site.os, 'close', side_effect=close_fd):
                        error_type = KeyboardInterrupt if failure == 'interrupt-after-close' else OSError
                        with self.assertRaisesRegex(error_type, 'first-close-fault'):
                            self.read(fixture)
                    self.assertGreater(len(opened), 4)
                    self.assertEqual(set(attempts), set(opened))
                    self.assertEqual(len(attempts), len(opened))
                    self.assertEqual(len(set(attempts)), len(attempts))
                    for fd in set(opened) - set(unclosed):
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                finally:
                    # Explicit fixture teardown, not a production close retry.
                    for fd in unclosed:
                        original_close(fd)

    def test_original_validation_error_survives_all_attempt_close_failure(self):
        import os
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            self.write_selection(fixture, {**fixture['value'], 'schema_version': True})
            original_open, original_close = os.open, os.close
            opened, attempts = [], []
            def open_fd(*args, **kwargs):
                fd = original_open(*args, **kwargs)
                opened.append(fd)
                return fd
            def close_fd(fd):
                original_close(fd)
                attempts.append(fd)
                if len(attempts) == 1:
                    raise OSError('cleanup-close-fault')
            with patch.object(site.os, 'open', side_effect=open_fd), \
                    patch.object(site.os, 'close', side_effect=close_fd):
                with self.assertRaisesRegex(ValueError, 'schema/digests/bounds') as failure:
                    self.read(fixture)
            self.assertIsInstance(failure.exception.__cause__, OSError)
            self.assertEqual(str(failure.exception.__cause__), 'cleanup-close-fault')
            self.assertEqual(set(attempts), set(opened))
            self.assertEqual(len(attempts), len(opened))

    def test_partial_root_acquisition_attempts_all_close_and_preserves_original_io_failure(self):
        import os
        import time
        import guard_site_profile as site
        with tempfile.TemporaryDirectory() as directory:
            original_open, original_close, original_fstat = os.open, os.close, os.fstat
            opened, attempts, calls = [], [], [0]
            class AncestorView:
                def __init__(self, info):
                    self.info = info
                def __getattr__(self, name):
                    # Only isolate TEST_TMPDIR ancestor write modes, as the main
                    # real-filesystem fixture does; no production trust override.
                    return self.info.st_mode & ~0o022 if name == 'st_mode' else getattr(self.info, name)
            def open_fd(*args, **kwargs):
                calls[0] += 1
                if calls[0] == 3:
                    raise OSError('original-acquisition-fault')
                fd = original_open(*args, **kwargs)
                opened.append(fd)
                return fd
            def close_fd(fd):
                original_close(fd)
                attempts.append(fd)
                if len(attempts) == 1:
                    raise OSError('partial-root-close-fault')
            with patch.object(site.os, 'open', side_effect=open_fd), \
                    patch.object(site.os, 'close', side_effect=close_fd), \
                    patch.object(site.os, 'fstat', side_effect=lambda fd: AncestorView(original_fstat(fd))):
                with self.assertRaisesRegex(OSError, 'original-acquisition-fault') as failure:
                    site._development_root(Path(directory), time.monotonic_ns() + 60 * 10**9)
            self.assertEqual(str(failure.exception.__cause__), 'partial-root-close-fault')
            self.assertEqual(len(opened), 2)
            self.assertEqual(set(attempts), set(opened))
            self.assertEqual(len(attempts), len(opened))

    def test_same_stage_cutoff_is_checked_after_final_validation_and_all_fd_closure(self):
        import os
        import guard_site_profile as site
        for expiry in ('after-final-fence', 'during-close'):
            with tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                clock, opened, attempts = [100], [], []
                original_open, original_close = os.open, os.close
                original_fence = site._DevelopmentOwners.fence
                def open_fd(*args, **kwargs):
                    fd = original_open(*args, **kwargs)
                    opened.append(fd)
                    return fd
                def close_fd(fd):
                    original_close(fd)
                    attempts.append(fd)
                    if expiry == 'during-close':
                        clock[0] = 1000
                def fence(owners):
                    original_fence(owners)
                    if expiry == 'after-final-fence':
                        clock[0] = 1000
                with patch.object(site.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                        patch.object(site.os, 'open', side_effect=open_fd), \
                        patch.object(site.os, 'close', side_effect=close_fd), \
                        patch.object(site._DevelopmentOwners, 'fence', new=fence):
                    with self.assertRaisesRegex(ValueError, 'original deadline exhausted'):
                        self.read(fixture, deadline=1000)
                self.assertEqual(set(attempts), set(opened))
                self.assertEqual(len(attempts), len(opened))

    def test_authorized_root_namespace_and_generated_source_entries_do_not_replace_original_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            baseline = self.read(fixture)
            state, coordination, source = fixture['roots']
            (state / '5102699b-2ebf-44f1-a454-62b098e49658').mkdir(mode=0o700)
            (coordination / 'another-owned-epoch').mkdir(mode=0o700)
            (source / '.svelte-kit').mkdir(mode=0o700)
            self.assertEqual(baseline, self.read(fixture, original=baseline))


    def test_selection_purpose_is_closed_and_absence_stays_metadata_only(self):
        import guard_site_profile as site
        path, sha = '/owned/selection.json', 'a' * 64
        admitted = [('build', ['build', '//:build']), ('archive', ['build', '//:site_archive']),
                    ('checks', ['test', '//:unit_tests', '//:archive_check'])]
        for phase, arguments in admitted:
            self.assertTrue(site.admitted_development_artifact('site', phase, arguments, path, sha))
        for phase, arguments in (('checks', ['test', '//:unit_tests']), ('qualification', ['test', '//:reference_check']),
                ('fetch', ['fetch', '//:build']), ('lock', ['mod', 'deps', '--lockfile_mode=update']),
                ('import', ['run', '//:import_extension_delivery']), ('reference-import', []),
                ('build', ['build', '//:build', '//:site_archive']), ('checks', ['test', '//:archive_check', '//:archive_check'])):
            with self.assertRaises(ValueError):
                site.admitted_development_artifact('site', phase, arguments, path, sha)
        for profile, selection, digest in (('standard', path, sha), ('site', path, None), ('site', None, sha)):
            with self.assertRaises(ValueError):
                site.admitted_development_artifact(profile, 'build', ['build', '//:build'], selection, digest)
        self.assertIsNone(site.development_artifact(None, None, None, None, None, None))
        with self.assertRaises(ValueError):
            site.development_artifact(None, None, None, None, None, None, original={'selected': True})

    def test_actual_site_command_clears_ambient_pair_in_every_phase_and_binds_selected_pair(self):
        import guard_site_profile as site
        vectors = [('qualification', ['test', '//:reference_check']), ('checks', ['test', '//:unit_tests']),
                   ('build', ['build', '//:build']), ('archive', ['build', '//:site_archive']),
                   ('fetch', ['fetch', '//:build']), ('lock', ['mod', 'deps', '--lockfile_mode=update']),
                   ('import', ['run', '//:import_extension_delivery', '--', '--manifest', '/owned/M', '--sha256', 'a' * 64]),
                   ('reference-import', ['run', '//:import_reference', '--', '--bundle', '/owned/R', '--sha256', 'a' * 64])]
        qualification = {'delivery_manifest': '/owned/M', 'reference_bundle': '/owned/R'}
        with patch.object(site, 'toolchain_binding'), patch.object(site, 'bounded_file'), \
                patch.object(site, 'importer_arguments', side_effect=lambda path, sha, selected:
                    ['run', '//:import_extension_delivery', '--', '--manifest', str(path), '--sha256', sha]):
            for phase, arguments in vectors:
                argv = site.command(BAZEL_NATIVE, JDK, qualification, '/owned/output', phase, arguments, source='/owned/site')
                for key in (site.DEVELOPMENT_SELECTION_ENV, site.DEVELOPMENT_SELECTION_SHA_ENV):
                    self.assertEqual([arg for arg in argv if arg.startswith('--repo_env=' + key + '=')],
                                     ['--repo_env=' + key + '='])
            bindings = site.development_artifact_bindings('/owned/selected', 'b' * 64)
            argv = site.command(BAZEL_NATIVE, JDK, qualification, '/owned/output', 'build', ['build', '//:build'],
                                bindings, source='/owned/site')
            for key, value in bindings.items():
                self.assertEqual(argv.count('--repo_env=' + key + '=' + value), 1)
            with self.assertRaises(ValueError):
                site.command(BAZEL_NATIVE, JDK, qualification, '/owned/output', 'fetch', ['fetch', '//:build'],
                             bindings, source='/owned/site')


if __name__ == '__main__':
    unittest.main()
