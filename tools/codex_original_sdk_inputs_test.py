"""Real tiny SDK/registry/JDK/NAR and original declared-custody models.

Private unrun source. The existing fixture changes only the synthetic JDK path;
full SDK and carrier validators run. No source/native admission is modeled.
"""
from contextlib import ExitStack
import copy
import fcntl
import json
import os
from pathlib import Path
import shutil
import io
import sys
import stat
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import codex_original_sdk_inputs as inputs
import codex_original_sdk_declaration as declaration
import codex_native_sdk_carrier_test as fixture_module

core = inputs.carrier


def original_rule_model():
    """Evaluate real rule decisions; Bazel remains the real Starlark parser."""
    raw = Path(__file__).with_name('codex_original_sdk_inputs.bzl').read_text()
    kinds = {str: 'string', int: 'int', dict: 'dict', list: 'list', bool: 'bool'}
    def fail(message):
        raise ValueError(message)
    attrs = SimpleNamespace(**{name: lambda **kwargs: kwargs for name in
                               ('string', 'label', 'label_list', 'bool')})
    namespace = {'type': lambda value: kinds.get(type(value), type(value).__name__),
        'fail': fail, 'attr': attrs, 'Label': lambda name: name,
        'repository_rule': lambda **kwargs: kwargs,
        'json': SimpleNamespace(decode=json.loads)}
    exec(compile(raw.replace('.elems()', ''), '<real original SDK rule>', 'exec'), namespace)
    return namespace


class OriginalSDKInputsModels(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.CarrierModels()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.origin_patch = patch.object(inputs, 'ORIGIN', self.fixture.origin)
        self.pin_patch = patch.object(inputs, 'ORIGIN_PIN', self.fixture.pin)
        self.origin_patch.start()
        self.pin_patch.start()
        self.addCleanup(self.origin_patch.stop)
        self.addCleanup(self.pin_patch.stop)
        self.carrier, self.report, self.carrier_pin = self.fixture.seal()
        self.entry_ns = time.monotonic_ns()
        self.until_ns = self.entry_ns + 1200*10**9
        self.clock = core.Clock((self.entry_ns + 600*10**9)/10**9)
        self.clock.until_ns = self.entry_ns + 600*10**9
        self.context = {'MODE': inputs.MODE, 'ENTRY_NS': str(self.entry_ns),
            'DEADLINE_NS': str(self.until_ns), 'EPOCH': self.fixture.context['epoch'],
            'SOURCE_COMMIT': '1'*40, 'GRAPH_SHA256': '2'*64}
        with ExitStack() as stack:
            self.plan = declaration.catalogue(self.clock, stack, self.context)
        self.repository = self.root / 'declared-sdk'
        self.repository.mkdir(mode=0o700)
        publisher = declaration.Publication(self.repository, self.clock)
        try:
            publisher.publish(self.plan['document'])
            publisher.accepted = True
        finally:
            publisher.close()
        self.manifest = self.repository / inputs.MANIFEST

    def session(self):
        return inputs.HeldOriginalSDK(self.manifest, self.manifest, self.carrier,
            self.carrier_pin, self.entry_ns, self.until_ns, self.context)

    def rewrite_manifest(self, document):
        self.manifest.chmod(0o600)
        self.manifest.write_bytes(core.encoded(document))
        self.manifest.chmod(0o444)

    def change_file(self, path, raw=None):
        parent = path.parent
        parent.chmod(0o700)
        old = path.read_bytes()
        path.unlink()
        self.fixture.write(path, old if raw is None else raw, 0o555 if path.name == 'tool' else 0o444)
        parent.chmod(0o555)

    def test_complete_original_input_reuses_no_extraction_and_matches_full_sdk_mapping(self):
        with self.session() as session:
            expected = core.sdk.validate_export(self.fixture.origin, self.fixture.pin,
                core.sdk.BASELINE_INVENTORY, json.loads(self.fixture.original)['graph_files'],
                on_read=session.clock.tick)
            self.assertEqual(session.mapping(), expected)
            self.assertEqual(session.read_regular('sdk', 'repositories/public+/tool', 4096), b'tool model\x00bytes')
            self.assertFalse((self.repository / 'sdk').exists())
            self.assertEqual(set(session.catalogue.aliases), {
                key for key, row in session.expected.items() if row['kind'] == 'file'})
            session.finish()
        with self.assertRaises(ValueError):
            session.mapping()

    def test_missing_extra_duplicate_and_wrong_source_catalogues_refuse(self):
        original = copy.deepcopy(self.plan['document'])
        for change in ('missing', 'extra', 'duplicate', 'foreign-source', 'alias-order', 'namespace'):
            with self.subTest(change=change):
                value = copy.deepcopy(original)
                if change == 'missing':
                    value['regular_inputs'].pop()
                elif change == 'extra':
                    value['regular_inputs'].append(dict(value['regular_inputs'][-1]))
                elif change == 'duplicate':
                    value['regular_inputs'][-1] = dict(value['regular_inputs'][0])
                elif change == 'foreign-source':
                    value['regular_inputs'][0]['source_path'] = str(self.root / 'undeclared')
                elif change == 'alias-order':
                    value['regular_inputs'][0]['alias'] = 'input-files/1'
                else:
                    value['entries'][-1]['kind'] = 'device'
                self.rewrite_manifest(value)
                with self.assertRaises(ValueError):
                    with self.session():
                        self.fail('unselected catalogue admitted')
        self.rewrite_manifest(original)

    def test_unlisted_physical_regular_read_refuses_before_open(self):
        with self.session() as session:
            with self.assertRaises(ValueError):
                session.read_regular('sdk', 'repositories/public+/undeclared', 4096)
            with self.assertRaises(ValueError):
                session.roots['sdk'].open('repositories/public+/undeclared')
            session.finish()

    def test_named_alias_same_target_new_inode_refuses_and_closes(self):
        with self.assertRaises(ValueError):
            with self.session() as session:
                row = next(row for row in self.plan['document']['regular_inputs']
                           if row['role'] == 'sdk' and row['path'] == 'repositories/public+/tool')
                parent = self.repository / 'input-files'
                parent.chmod(0o700)
                alias = self.repository / row['alias']
                alias.unlink()
                alias.symlink_to(row['source_path'])
                parent.chmod(0o555)
                session.read_regular('sdk', row['path'], 4096)
        self.assertFalse(session.active)
        self.assertEqual(session.catalogue.anchor.chain, [])

    def test_same_byte_regular_replacement_after_initial_full_proof_refuses(self):
        with self.assertRaises(ValueError):
            with self.session() as session:
                self.change_file(self.fixture.origin / 'repositories/public+/tool')
                session.finish()

    def test_late_original_change_during_full_carrier_final_requires_last_fresh_proof(self):
        original = core.HeldCarrier.full_final
        def change(scope):
            original(scope)
            self.change_file(self.fixture.origin / 'repositories/public+/tool', b'changed')
        with patch.object(core.HeldCarrier, 'full_final', new=change), self.assertRaises(ValueError):
            with self.session() as session:
                session.finish()
        self.assertFalse(session.finished)

    def test_chmod_size_and_timestamp_changes_refuse(self):
        tool = self.fixture.origin / 'repositories/public+/tool'
        for change in ('mode', 'size', 'timestamp'):
            with self.subTest(change=change):
                if change == 'mode':
                    with self.assertRaises(ValueError):
                        with self.session() as session:
                            tool.chmod(0o775)
                            session.finish()
                    tool.chmod(0o555)
                elif change == 'size':
                    with self.assertRaises(ValueError):
                        with self.session() as session:
                            tool.chmod(0o600)
                            tool.write_bytes(b'wrong-size')
                            tool.chmod(0o555)
                            session.finish()
                    self.change_file(tool, b'tool model\x00bytes')
                else:
                    with self.assertRaises(ValueError):
                        with self.session() as session:
                            info = tool.stat()
                            os.utime(tool, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                            session.finish()

    def test_complete_namespace_absence_created_refuses(self):
        with self.assertRaises(ValueError):
            with self.session() as session:
                other = self.fixture.origin / 'repositories/other'
                other.chmod(0o700)
                self.fixture.write(other / 'absent', b'created')
                other.chmod(0o555)
                session.finish()

    def test_inert_external_jdk_link_is_never_followed(self):
        opened = []
        real_open = os.open
        def checked(path, *args, **kwargs):
            opened.append(str(path))
            self.assertNotIn('/not-authorized/', str(path))
            return real_open(path, *args, **kwargs)
        with patch.object(os, 'open', side_effect=checked):
            with self.session() as session:
                session.finish()
        self.assertTrue(opened)

    def test_original_root_same_bytes_new_inode_refuses(self):
        with self.assertRaises(ValueError):
            with self.session() as session:
                self.fixture.origin.rename(self.root / 'detached-origin')
                shutil.copytree(self.root / 'detached-origin', self.fixture.origin, symlinks=True)
                session.finish()
        self.assertFalse(session.active)

    def test_symbolic_source_parent_refuses_without_reading_foreign_target(self):
        source = self.fixture.origin / 'repositories'
        foreign = self.root / 'foreign-repositories'
        foreign.mkdir(mode=0o700)
        self.fixture.write(foreign / 'keep', b'foreign')
        with self.assertRaises((ValueError, OSError)):
            with self.session() as session:
                self.fixture.origin.chmod(0o700)
                source.rename(self.fixture.origin / 'detached-repositories')
                source.symlink_to(foreign, target_is_directory=True)
                self.fixture.origin.chmod(0o555)
                session.read_regular('sdk', 'repositories/public+/tool', 4096)
        self.assertEqual((foreign / 'keep').read_bytes(), b'foreign')

    def test_last_late_publication_fence_detects_post_finish_mutation(self):
        with self.assertRaises(ValueError):
            with self.session() as session:
                session.finish()
                self.change_file(self.fixture.origin / 'repositories/public+/tool')
                # Normal exit must itself perform the whole namespace fence.

    def test_no_finish_no_reentry_no_transfer_no_foreign_owner(self):
        session = self.session()
        with self.assertRaises(ValueError):
            with session:
                pass
        with self.assertRaises(ValueError):
            with session:
                pass
        with self.session() as current:
            with self.assertRaises(ValueError):
                copy.copy(current)
            errors = []
            def other_owner():
                try:
                    current.mapping()
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=other_owner)
            worker.start()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            current.finish()

    def test_original_envelope_exact_integer_join_and_expiry_refuse(self):
        for entry, until in ((self.entry_ns, self.until_ns + 1),
                             (time.monotonic_ns() + 10**9, time.monotonic_ns() + 1201*10**9),
                             (True, self.until_ns)):
            with self.assertRaises(ValueError):
                inputs.HeldOriginalSDK(self.manifest, self.manifest, self.carrier,
                    self.carrier_pin, entry, until, self.context)
        with self.assertRaises(ValueError):
            with self.session() as current:
                with patch.object(time, 'monotonic_ns', return_value=current.until_ns):
                    current.finish()
        self.assertFalse(current.active)

    def test_publication_late_alias_leaf_and_parent_replacement_refuse_build_and_preserve_foreign(self):
        for change in ('leaf', 'parent'):
            with self.subTest(change=change):
                root = self.root / ('publication-' + change)
                root.mkdir(mode=0o700)
                foreign = root / 'foreign'
                foreign.mkdir(mode=0o700)
                self.fixture.write(foreign / 'keep', b'foreign')
                changed = False
                def event(phase):
                    nonlocal changed
                    if phase != 'ready-published' or changed:
                        return
                    changed = True
                    parent = root / 'input-files'
                    if change == 'parent':
                        parent.rename(root / 'detached-aliases')
                        shutil.copytree(foreign, parent)
                    else:
                        parent.chmod(0o700)
                        (parent / '0').unlink()
                        (parent / '0').symlink_to(self.root / 'foreign-target')
                        parent.chmod(0o555)
                publication = declaration.Publication(root, self.clock, event)
                try:
                    with self.assertRaises(ValueError):
                        publication.publish(self.plan['document'])
                finally:
                    publication.close()
                self.assertFalse((root / 'BUILD.bazel').exists())
                self.assertEqual((foreign / 'keep').read_bytes(), b'foreign')
                if change == 'parent':
                    self.assertEqual((root / 'input-files/keep').read_bytes(), b'foreign')
                else:
                    self.assertEqual(os.readlink(root / 'input-files/0'), str(self.root / 'foreign-target'))

    def test_production_plan_and_reader_keep_complete_input_group(self):
        raw = declaration.build(self.plan['document'])
        self.assertIn('filegroup(name = "inputs"', raw)
        for record in self.plan['document']['regular_inputs']:
            self.assertIn(repr(record['alias']), raw)
        self.assertIn(repr(inputs.MANIFEST), raw)
        self.assertEqual(self.plan['document']['origin_receipt_sha256'], self.fixture.pin)
        self.assertEqual(self.plan['document']['jdk_root'], str(self.fixture.jdk))

    def test_envelope_retains_original_nonround_integer_cutoff_and_refuses_wrong_join(self):
        entry = 77775041442683
        env = {'OMUX_NATIVE_FILE_WRITER_MODELS_' + key: value for key, value in {
            'MODE': declaration.MODE, 'ENTRY_NS': str(entry),
            'DEADLINE_NS': str(entry + 1200*10**9),
            'EPOCH': self.fixture.context['epoch'], 'SOURCE_COMMIT': '1'*40,
            'GRAPH_SHA256': '2'*64}.items()}
        with patch.object(time, 'monotonic_ns', return_value=entry + 10**9), \
                patch.object(time, 'monotonic', return_value=(entry + 10**9)/10**9):
            actual, clock = declaration.envelope(env)
            self.assertEqual(actual['ENTRY_NS'], str(entry))
            self.assertEqual(clock.until_ns, entry + 600*10**9)
            self.assertEqual(clock.deadline, (entry + 600*10**9)/10**9)
            for field, value in (('MODE', 'native-file-writer-source-reserved'),
                                 ('DEADLINE_NS', str(entry + 1170*10**9)),
                                 ('ENTRY_NS', '0' + str(entry)), ('GRAPH_SHA256', 'g'*64)):
                changed = dict(env)
                changed['OMUX_NATIVE_FILE_WRITER_MODELS_' + field] = value
                with self.assertRaises(ValueError):
                    declaration.envelope(changed)

    def test_real_owned_descriptors_close_on_success_and_content_refusal(self):
        captured = []
        real_open, real_dup = os.open, os.dup
        def tracked(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            captured.append(fd)
            return fd
        def tracked_dup(fd):
            value = real_dup(fd)
            captured.append(value)
            return value
        with patch.object(os, 'open', side_effect=tracked), patch.object(os, 'dup', side_effect=tracked_dup):
            with self.session() as session:
                session.finish()
        # All opened descriptors have been closed; there is no intervening open
        # to reuse a numeric FD before the assertion.
        for fd in set(captured):
            with self.assertRaises(OSError):
                os.fstat(fd)
        captured.clear()
        with patch.object(os, 'open', side_effect=tracked), patch.object(os, 'dup', side_effect=tracked_dup), \
                self.assertRaises(ValueError):
            with self.session() as session:
                self.change_file(self.fixture.origin / 'repositories/public+/tool', b'bad')
                session.finish()
        for fd in set(captured):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_partial_publication_refusal_removes_only_owned_outputs(self):
        root = self.root / 'partial-publication'
        root.mkdir(mode=0o700)
        selected = declaration.Publication(root, self.clock)
        real_symlink = os.symlink
        def fail(target, name, **kwargs):
            if name == '1':
                raise OSError('synthetic second-alias refusal')
            return real_symlink(target, name, **kwargs)
        try:
            with patch.object(os, 'symlink', side_effect=fail), self.assertRaises(OSError):
                selected.publish(self.plan['document'])
        finally:
            selected.close()
        self.assertEqual(list(root.iterdir()), [])
        self.assertTrue((self.fixture.origin / 'receipt.json').exists())
        self.assertEqual((self.fixture.origin / 'repositories/public+/tool').read_bytes(), b'tool model\x00bytes')

    def run_main(self, directory, phase, output, plan_pin=None):
        args = ['declaration', '--phase', phase, '--directory', str(directory)]
        if plan_pin is not None:
            args += ['--plan-sha256', plan_pin]
        env = {'OMUX_NATIVE_FILE_WRITER_MODELS_' + key: value
               for key, value in self.context.items()}
        with patch.object(sys, 'argv', args), patch.dict(os.environ, env), \
                patch.object(sys, 'stdout', output):
            declaration.main()

    def main_plan(self, name):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        output = io.StringIO()
        self.run_main(directory, 'plan', output)
        report = core.decode(output.getvalue().encode('ascii'))
        return directory, report['plan_sha256']

    def test_actual_main_document_retains_context_and_reader_requires_exact_driver_join(self):
        directory, pin = self.main_plan('main-context')
        output = io.StringIO()
        self.run_main(directory, 'materialize', output, pin)
        document = core.decode((directory / inputs.MANIFEST).read_bytes())
        self.assertEqual(document['context'], self.context)
        with inputs.HeldOriginalSDK(directory / inputs.MANIFEST,
                directory / inputs.MANIFEST, self.carrier, self.carrier_pin,
                self.entry_ns, self.until_ns, self.context) as current:
            current.finish()
        for field, replacement in (('MODE', 'foreign'), ('SOURCE_COMMIT', '3'*40),
                ('GRAPH_SHA256', '4'*64), ('DEADLINE_NS', str(self.until_ns + 1))):
            changed = dict(self.context)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                with inputs.HeldOriginalSDK(directory / inputs.MANIFEST,
                        directory / inputs.MANIFEST, self.carrier, self.carrier_pin,
                        self.entry_ns, self.until_ns, changed):
                    self.fail('foreign driver context admitted')
        for change in ('missing', 'extra'):
            document = copy.deepcopy(self.plan['document'])
            if change == 'missing':
                document.pop('context')
            else:
                document['context']['UNDECLARED'] = 'value'
            self.rewrite_manifest(document)
            with self.subTest(change=change), self.assertRaises(ValueError):
                with self.session():
                    self.fail('unbound document context admitted')

    def test_actual_main_late_stdout_flush_refuses_and_rolls_back_readiness(self):
        for clock in ('integer', 'float'):
            directory, pin = self.main_plan('late-flush-' + clock)
            active = False
            real_ns, real_float = time.monotonic_ns, time.monotonic
            output = io.StringIO()
            class LateOutput:
                def write(_, value):
                    return output.write(value)
                def flush(_):
                    nonlocal active
                    active = True
            def ns():
                return self.clock.until_ns if active and clock == 'integer' else real_ns()
            def floating():
                return self.clock.deadline if active and clock == 'float' else real_float()
            with patch.object(time, 'monotonic_ns', side_effect=ns), \
                    patch.object(time, 'monotonic', side_effect=floating), self.assertRaises(ValueError):
                self.run_main(directory, 'materialize', LateOutput(), pin)
            self.assertTrue(output.getvalue())  # Written JSON is not return-code success.
            self.assertFalse((directory / 'BUILD.bazel').exists())
            self.assertFalse((directory / inputs.MANIFEST).exists())
            self.assertFalse((directory / 'input-files').exists())
            self.assertTrue((self.fixture.origin / 'receipt.json').exists())

    def test_actual_main_late_owned_close_refuses_before_stdout_and_rolls_back(self):
        for clock in ('integer', 'float'):
            directory, pin = self.main_plan('late-close-' + clock)
            active = False
            real_ns, real_float = time.monotonic_ns, time.monotonic
            real_close = declaration.Publication.close
            publications = []
            def late(selected, *args, **kwargs):
                nonlocal active
                publications.append(selected)
                real_close(selected, *args, **kwargs)
                active = True
            def ns():
                return self.clock.until_ns if active and clock == 'integer' else real_ns()
            def floating():
                return self.clock.deadline if active and clock == 'float' else real_float()
            output = io.StringIO()
            with patch.object(declaration.Publication, 'close', new=late), \
                    patch.object(time, 'monotonic_ns', side_effect=ns), \
                    patch.object(time, 'monotonic', side_effect=floating), self.assertRaises(ValueError):
                self.run_main(directory, 'materialize', output, pin)
            self.assertEqual(output.getvalue(), '')
            self.assertFalse((directory / 'BUILD.bazel').exists())
            self.assertTrue(publications)
            self.assertTrue(all(not value.accepted and value.root is None and
                value.stage is None and value.aliases is None for value in publications))

    def test_actual_main_stdout_error_and_close_fault_attempt_all_owned_closures(self):
        for failure in ('stdout', 'close'):
            directory, pin = self.main_plan('main-fault-' + failure)
            roots, publications, attempted = [], [], []
            real_root_close, real_pub_init, real_close = core.Root.close, declaration.Publication.__init__, os.close
            target = None
            failed = False
            def root_close(root):
                roots.append(root)
                return real_root_close(root)
            def pub_init(value, *args, **kwargs):
                nonlocal target
                real_pub_init(value, *args, **kwargs)
                publications.append(value)
                target = value.aliases  # aliases are created by publish, not constructor.
            # Publication detaches its attributes before close calls; retain the
            # actual FD selected immediately before terminal close instead.
            real_publication_close = declaration.Publication.close
            def publication_close(value, *args, **kwargs):
                nonlocal target
                target = value.root
                return real_publication_close(value, *args, **kwargs)
            def checked_close(fd):
                nonlocal failed
                attempted.append(fd)
                real_close(fd)
                if failure == 'close' and fd == target and not failed:
                    failed = True
                    raise OSError('actual close completed, synthetic disposition error')
            class Output(io.StringIO):
                def flush(value):
                    if failure == 'stdout':
                        raise OSError('synthetic actual stdout flush refusal')
            with patch.object(core.Root, 'close', new=root_close), \
                    patch.object(declaration.Publication, '__init__', new=pub_init), \
                    patch.object(declaration.Publication, 'close', new=publication_close), \
                    patch.object(os, 'close', side_effect=checked_close), self.assertRaises(OSError):
                self.run_main(directory, 'materialize', Output(), pin)
            self.assertTrue(roots)
            self.assertTrue(all(root.chain == [] for root in roots))
            self.assertTrue(all(value.root is None and value.stage is None and
                value.aliases is None and not value.accepted for value in publications))
            self.assertFalse((directory / 'BUILD.bazel').exists())
            self.assertTrue(attempted)
            for fd in set(attempted):
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_original_mutation_during_last_alias_work_refuses_normal_exit(self):
        real = inputs.Catalogue.check_all
        changed = False
        def alias_work(catalogue):
            nonlocal changed
            real(catalogue)
            if armed and not changed:
                changed = True
                self.change_file(self.fixture.origin / 'repositories/public+/tool')
        armed = False
        with patch.object(inputs.Catalogue, 'check_all', new=alias_work), self.assertRaises(ValueError):
            with self.session() as current:
                current.finish()
                armed = True
        self.assertTrue(changed)
        self.assertFalse(current.active)

    def test_alias_replacement_during_last_original_sweep_refuses_normal_exit(self):
        real = core._fresh_namespace
        armed, changed = False, False
        def original_sweep(roots, expected, clock):
            nonlocal changed
            value = real(roots, expected, clock)
            if armed and not changed:
                changed = True
                parent = self.repository / 'input-files'
                parent.chmod(0o700)
                alias = parent / '0'
                target = os.readlink(alias)
                alias.unlink()
                alias.symlink_to(target)
                parent.chmod(0o555)
            return value
        with patch.object(core, '_fresh_namespace', new=original_sweep), self.assertRaises(ValueError):
            with self.session() as current:
                current.finish()
                armed = True
        self.assertTrue(changed)
        self.assertFalse(current.active)

    def test_wrong_published_context_refuses_before_transport_or_original_reads(self):
        document = copy.deepcopy(self.plan['document'])
        document['context']['GRAPH_SHA256'] = '3'*64
        self.rewrite_manifest(document)
        with patch.object(core.HeldCarrier, '__enter__', side_effect=AssertionError(
                'transport must not open for wrong declared context')), self.assertRaises(ValueError):
            with self.session():
                self.fail('context refused too late')

    def test_initial_semantic_io_requires_last_joint_original_fence(self):
        real = inputs._semantic_export
        def changed(scope, original):
            result = real(scope, original)
            self.change_file(self.fixture.origin / 'repositories/public+/tool')
            return result
        with patch.object(inputs, '_semantic_export', new=changed), self.assertRaises(ValueError):
            with self.session():
                self.fail('initial semantic IO escaped witness fence')

    def test_actual_main_plan_late_flush_cannot_return_success(self):
        root = self.root / 'late-plan-flush'
        root.mkdir(mode=0o700)
        real_ns = time.monotonic_ns
        expired = False
        class Output(io.StringIO):
            def flush(value):
                nonlocal expired
                expired = True
        def now():
            return self.clock.until_ns if expired else real_ns()
        with patch.object(time, 'monotonic_ns', side_effect=now), self.assertRaises(ValueError):
            self.run_main(root, 'plan', Output())
        self.assertFalse((root / 'BUILD.bazel').exists())
        self.assertFalse((root / inputs.MANIFEST).exists())

    def test_actual_reopened_cleanup_root_fstat_fault_is_registered_and_closed(self):
        root = self.root / 'cleanup-root-fault'
        root.mkdir(mode=0o700)
        publication = declaration.Publication(root, self.clock)
        publication.publish(self.plan['document'])
        publication.close(rollback=False)
        real_open, real_fstat = core.sdk.open_dir, os.fstat
        reopened = []
        refused = False
        def open_root(path):
            fd = real_open(path)
            reopened.append(fd)
            return fd
        def fault(fd):
            nonlocal refused
            if reopened and fd == reopened[-1] and not refused:
                refused = True
                self.assertEqual(publication.root, fd)
                raise OSError('synthetic reopened root identity failure')
            return real_fstat(fd)
        with patch.object(core.sdk, 'open_dir', side_effect=open_root), \
                patch.object(os, 'fstat', side_effect=fault), self.assertRaises(OSError):
            publication.cleanup_closed()
        self.assertTrue(refused)
        self.assertEqual(len(reopened), 1)
        self.assertIsNone(publication.root)
        self.assertIsNone(publication.stage)
        self.assertIsNone(publication.aliases)
        with self.assertRaises(OSError):
            real_fstat(reopened[0])
        self.assertFalse(publication.accepted)
        # Ownership was never established: no deletion is authorized by this
        # failed identity read. The enclosing Bazel failure owns final cleanup.
        self.assertTrue((root / 'BUILD.bazel').exists())
        self.assertTrue((self.fixture.origin / 'receipt.json').exists())

    def test_actual_reopened_cleanup_foreign_root_retains_objects_and_closes(self):
        root = self.root / 'cleanup-foreign-root'
        root.mkdir(mode=0o700)
        publication = declaration.Publication(root, self.clock)
        publication.publish(self.plan['document'])
        publication.close(rollback=False)
        detached = self.root / 'detached-cleanup-root'
        root.rename(detached)
        root.mkdir(mode=0o700)
        self.fixture.write(root / 'keep', b'foreign')
        real_open = core.sdk.open_dir
        reopened = []
        def open_root(path):
            fd = real_open(path)
            reopened.append(fd)
            return fd
        with patch.object(core.sdk, 'open_dir', side_effect=open_root), self.assertRaises(ValueError):
            publication.cleanup_closed()
        self.assertEqual((root / 'keep').read_bytes(), b'foreign')
        self.assertEqual(sorted(value.name for value in root.iterdir()), ['keep'])
        self.assertTrue((detached / 'BUILD.bazel').exists())
        self.assertIsNone(publication.root)
        self.assertIsNone(publication.stage)
        self.assertIsNone(publication.aliases)
        for fd in reopened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_real_ordinary_uid_stage_rename_then_seal_precedes_every_public_event(self):
        self.assertNotEqual(os.geteuid(), 0, 'this fixed local gate must exercise ordinary UID permissions')
        root = self.root / 'ordinary-uid-publication'
        root.mkdir(mode=0o700)
        phases, moves = [], []
        publication = None
        def event(phase):
            phases.append(phase)
            parent = root / 'input-files'
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o555)
            self.assertEqual(parent.stat().st_uid, os.getuid())
            self.assertEqual(core.identity(parent.stat(), True), publication.alias_identity)
            if phase != 'ready-published':
                self.assertFalse((root / 'BUILD.bazel').exists())
        publication = declaration.Publication(root, self.clock, event)
        real_rename = os.rename
        def rename(name, target, **kwargs):
            if name == 'input-files':
                self.assertEqual(kwargs, {'src_dir_fd': publication.stage, 'dst_dir_fd': publication.root})
                self.assertEqual(stat.S_IMODE(os.fstat(publication.stage).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.fstat(publication.root).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.fstat(publication.aliases).st_mode), 0o700)
                held = core.identity(os.fstat(publication.aliases), True)
                self.assertEqual(held, core.identity(os.stat(name, dir_fd=publication.stage,
                    follow_symlinks=False), True))
                real_rename(name, target, **kwargs)  # actual kernel permission path
                self.assertEqual(held, core.identity(os.stat(target, dir_fd=publication.root,
                    follow_symlinks=False), True))
                moves.append(held[:2])
            else:
                real_rename(name, target, **kwargs)
        try:
            with patch.object(os, 'rename', side_effect=rename):
                publication.publish(self.plan['document'])
            publication.final(self.plan['document'])
            self.assertEqual(len(moves), 1)
            self.assertEqual(phases, ['metadata-published', 'metadata-published', 'ready-published'])
            self.assertEqual(core.identity((root / 'input-files').stat(), True)[:2], moves[0])
            self.assertEqual(stat.S_IMODE((root / 'BUILD.bazel').stat().st_mode), 0o444)
            publication.accepted = True
        finally:
            publication.close()

    def test_moved_alias_seal_and_sync_refusals_roll_back_only_owned_outputs(self):
        for failure in ('seal', 'sync'):
            root = self.root / ('moved-alias-' + failure)
            root.mkdir(mode=0o700)
            foreign = root / 'keep'
            self.fixture.write(foreign, b'foreign retained')
            phases = []
            publication = declaration.Publication(root, self.clock, phases.append)
            real_chmod, real_sync = os.fchmod, os.fsync
            failed = False
            def chmod(fd, mode):
                nonlocal failed
                if failure == 'seal' and fd == publication.aliases and mode == 0o555 and not failed:
                    self.assertTrue((root / 'input-files').exists())
                    failed = True
                    raise OSError('synthetic moved-directory seal failure')
                real_chmod(fd, mode)
            def sync(fd):
                nonlocal failed
                real_sync(fd)
                if failure == 'sync' and fd == publication.aliases and \
                        (root / 'input-files').exists() and not failed:
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o555)
                    failed = True
                    raise OSError('actual directory sync completed, synthetic refusal')
            try:
                with patch.object(os, 'fchmod', side_effect=chmod), \
                        patch.object(os, 'fsync', side_effect=sync), self.assertRaises(OSError):
                    publication.publish(self.plan['document'])
            finally:
                publication.close()
            self.assertTrue(failed)
            self.assertEqual(phases, [])
            self.assertEqual(foreign.read_bytes(), b'foreign retained')
            self.assertEqual(sorted(value.name for value in root.iterdir()), ['keep'])
            self.assertTrue((self.fixture.origin / 'receipt.json').exists())
            self.assertFalse(publication.accepted)

    def test_actual_metadata_creator_fds_survive_rename_and_authenticate_post_witness(self):
        root = self.root / 'held-file-publication'
        root.mkdir(mode=0o700)
        moved, events = {}, []
        publication = None
        def event(phase):
            events.append(phase)
            for name, post in moved.items():
                fd = publication.file_fds[name]
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                self.assertEqual(core.identity(os.fstat(fd)), publication.records[name])
                self.assertEqual(post, publication.records[name])
                self.assertEqual(post, core.identity(os.stat(root / name, follow_symlinks=False)))
                raw = core.encoded(self.plan['document']) if name == inputs.MANIFEST else \
                    declaration.build(self.plan['document']).encode('utf-8')
                self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
            self.assertLessEqual(len(publication.file_fds), 2)
        publication = declaration.Publication(root, self.clock, event)
        real_rename = os.rename
        def rename(name, target, **kwargs):
            if name == 'input-files':
                return real_rename(name, target, **kwargs)
            fd = publication.file_fds[name]
            before = publication.records[name]
            self.assertEqual(core.identity(os.fstat(fd)), before)
            real_rename(name, target, **kwargs)
            after = core.identity(os.fstat(fd))
            self.assertEqual(before[:8], after[:8])
            self.assertEqual(after, core.identity(os.stat(target, dir_fd=publication.root,
                follow_symlinks=False)))
            moved[name] = after
        try:
            with patch.object(os, 'rename', side_effect=rename):
                publication.publish(self.plan['document'])
            self.assertEqual(set(moved), {inputs.MANIFEST, 'BUILD.bazel'})
            self.assertEqual(events, ['metadata-published', 'metadata-published', 'ready-published'])
            publication.final(self.plan['document'])
            publication.accepted = True
        finally:
            fds = list(publication.file_fds.values())
            publication.close()
        self.assertEqual(publication.file_fds, {})
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_actual_rename_window_replacement_symlink_bytes_mode_size_time_refuse(self):
        for selected in (inputs.MANIFEST, 'BUILD.bazel'):
            for change in ('replacement', 'symlink', 'bytes', 'mode', 'size', 'time'):
                with self.subTest(name=selected, change=change):
                    root = self.root / ('rename-window-' + selected.replace('.', '-') + '-' + change)
                    root.mkdir(mode=0o700)
                    foreign = self.root / ('foreign-' + selected.replace('.', '-') + '-' + change)
                    self.fixture.write(foreign, b'foreign retained')
                    publication = declaration.Publication(root, self.clock)
                    real_rename = os.rename
                    changed = False
                    original = None
                    def rename(name, target, **kwargs):
                        nonlocal changed, original
                        real_rename(name, target, **kwargs)
                        if name != selected or changed:
                            return
                        changed = True
                        path = root / name
                        original = path.read_bytes()
                        info = path.stat()
                        if change == 'replacement':
                            path.unlink()
                            self.fixture.write(path, original, 0o444)
                        elif change == 'symlink':
                            path.unlink()
                            path.symlink_to(foreign)
                        elif change == 'mode':
                            path.chmod(0o400)
                        elif change == 'time':
                            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                        else:
                            path.chmod(0o600)
                            value = (bytes([original[0] ^ 1]) + original[1:]) if change == 'bytes' else original + b'x'
                            path.write_bytes(value)
                            path.chmod(0o444)
                            if change == 'bytes':
                                # Same immutable eight fields; actual-byte proof
                                # must still reject despite the allowed ctime move.
                                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                    try:
                        with patch.object(os, 'rename', side_effect=rename), self.assertRaises(ValueError):
                            publication.publish(self.plan['document'])
                    finally:
                        publication.close()
                    self.assertTrue(changed)
                    self.assertFalse(publication.accepted)
                    self.assertEqual(foreign.read_bytes(), b'foreign retained')
                    if change == 'replacement':
                        self.assertEqual((root / selected).read_bytes(), original)
                    elif change == 'symlink':
                        self.assertEqual(os.readlink(root / selected), str(foreign))
                    else:
                        self.assertFalse((root / selected).exists())
                    if selected != 'BUILD.bazel':
                        self.assertFalse((root / 'BUILD.bazel').exists())
                    self.assertEqual(publication.file_fds, {})

    def test_readonly_metadata_open_is_enrolled_before_fstat_fault_and_drained(self):
        root = self.root / 'reader-enrollment-fault'
        root.mkdir(mode=0o700)
        publication = declaration.Publication(root, self.clock)
        real_open, real_fstat = os.open, os.fstat
        readers, failed = [], False
        def opened(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if name == inputs.MANIFEST and flags & os.O_ACCMODE == os.O_RDONLY \
                    and kwargs.get('dir_fd') == publication.stage:
                readers.append(fd)
            return fd
        def fstat(fd):
            nonlocal failed
            if readers and fd == readers[-1] and not failed:
                failed = True
                self.assertEqual(publication.file_fds[inputs.MANIFEST], fd)
                raise OSError('synthetic held-readonly enrollment fstat refusal')
            return real_fstat(fd)
        try:
            with patch.object(os, 'open', side_effect=opened), \
                    patch.object(os, 'fstat', side_effect=fstat), self.assertRaises(OSError):
                publication.publish(self.plan['document'])
        finally:
            publication.close()
        self.assertTrue(failed)
        self.assertEqual(publication.file_fds, {})
        self.assertEqual(list(root.iterdir()), [])
        for fd in readers:
            with self.assertRaises(OSError):
                real_fstat(fd)

    def test_fresh_final_and_terminal_close_reject_late_same_byte_or_content_mutation(self):
        for boundary in ('final', 'close'):
            for change in ('replacement', 'bytes'):
                root = self.root / ('late-held-' + boundary + '-' + change)
                root.mkdir(mode=0o700)
                publication = declaration.Publication(root, self.clock)
                publication.publish(self.plan['document'])
                path = root / inputs.MANIFEST
                raw = path.read_bytes()
                if change == 'replacement':
                    path.unlink()
                    self.fixture.write(path, raw, 0o444)
                else:
                    path.chmod(0o600)
                    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    path.chmod(0o444)
                if boundary == 'final':
                    try:
                        with self.assertRaises(ValueError):
                            publication.final(self.plan['document'])
                    finally:
                        publication.close()
                else:
                    with self.assertRaises(ValueError):
                        publication.close(rollback=False)
                    publication.cleanup_closed()
                self.assertFalse(publication.accepted)
                self.assertFalse((root / 'BUILD.bazel').exists())
                if change == 'replacement':
                    self.assertEqual(path.read_bytes(), raw)
                else:
                    self.assertFalse(path.exists())
                self.assertEqual(publication.file_fds, {})

    def test_first_held_metadata_close_error_detaches_and_attempts_every_owner_once(self):
        root = self.root / 'held-file-all-close-fault'
        root.mkdir(mode=0o700)
        publication = declaration.Publication(root, self.clock)
        publication.publish(self.plan['document'])
        owners = list(publication.file_fds.values()) + [publication.aliases, publication.stage, publication.root]
        attempted = []
        real_close = os.close
        def close(fd):
            self.assertEqual(publication.file_fds, {})
            self.assertIsNone(publication.root)
            attempted.append(fd)
            real_close(fd)
            if fd == owners[0]:
                raise OSError('actual held metadata close completed, synthetic refusal')
        with patch.object(os, 'close', side_effect=close), self.assertRaises(OSError):
            publication.close(rollback=False)
        self.assertEqual(attempted, owners)
        for fd in owners:
            with self.assertRaises(OSError):
                os.fstat(fd)
        publication.cleanup_closed()
        self.assertFalse((root / 'BUILD.bazel').exists())
        self.assertFalse(publication.accepted)

    def test_original_integer_expiry_during_same_held_post_rename_read_refuses(self):
        root = self.root / 'held-post-rename-expiry'
        root.mkdir(mode=0o700)
        publication = declaration.Publication(root, self.clock)
        real_read, real_ns = os.read, time.monotonic_ns
        expired = False
        def read(fd, count):
            nonlocal expired
            raw = real_read(fd, count)
            if fd == publication.file_fds.get(inputs.MANIFEST) and (root / inputs.MANIFEST).exists():
                expired = True
            return raw
        def ns():
            return self.clock.until_ns if expired else real_ns()
        try:
            with patch.object(os, 'read', side_effect=read), \
                    patch.object(time, 'monotonic_ns', side_effect=ns), self.assertRaises(ValueError):
                publication.publish(self.plan['document'])
        finally:
            publication.close()
        self.assertTrue(expired)
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(publication.file_fds, {})
        self.assertFalse(publication.accepted)


    def watch_policy(self, fresh):
        rule = original_rule_model()
        rule['_ORIGIN'], rule['_PIN'], rule['_JDK'] = str(self.fixture.origin), self.fixture.pin, core.sdk.JDK
        paths = [row['source_path'] for row in self.plan['document']['regular_inputs']]
        watched = [selected for path in paths
                   if (selected := rule['_regular_watch_path'](path, fresh)) is not None]
        return rule, paths, watched

    def test_default_watch_policy_keeps_every_regular_and_fresh_mode_keeps_full_action_data(self):
        rule, paths, watched = self.watch_policy(False)
        self.assertEqual(watched, paths)
        _, fresh_paths, fresh_watched = self.watch_policy(True)
        self.assertEqual(fresh_paths, paths)
        self.assertIn(str(self.fixture.origin / 'receipt.json'), fresh_watched)
        self.assertTrue(all(path in fresh_watched for path in paths if '/graph/' in path or '/registry-cache/' in path))
        payload = str(self.fixture.origin / 'repositories/public+/tool')
        self.assertIn(payload, paths)
        self.assertNotIn(payload, fresh_watched)
        # Actual publication still declares every ordered alias, not just watches.
        build = (self.repository / 'BUILD.bazel').read_text()
        self.assertEqual(build, declaration.build(self.plan['document']))
        for index, record in enumerate(self.plan['document']['regular_inputs']):
            self.assertEqual(os.readlink(self.repository / record['alias']), paths[index])
            self.assertIn(repr(record['alias']), build)
        with self.session() as session:
            self.assertEqual(set(session.catalogue.aliases), {
                key for key, row in session.expected.items() if row['kind'] == 'file'})
            session.finish()
        self.assertFalse(rule['codex_original_sdk_inputs']['attrs']['fresh_epoch_action_inputs']['default'])

    def test_fresh_watch_scope_requires_exact_owned_epoch_root_and_foreign_paths_refuse(self):
        rule, _, _ = self.watch_policy(True)
        epoch = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/11111111-2222-3333-4444-555555555555'
        environment = {'OMUX_NATIVE_FILE_WRITER_MODELS_MODE': inputs.MODE,
                       'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': epoch}
        directory = epoch + '/output-base/external/+codex_original_sdk_inputs+omux_original_native_sdk_inputs'
        ctx = SimpleNamespace(attr=SimpleNamespace(fresh_epoch_action_inputs=True))
        self.assertTrue(rule['_fresh_epoch_action_mode'](ctx, environment, directory))
        for changed_environment, changed_directory in [
            ({**environment, 'OMUX_NATIVE_FILE_WRITER_MODELS_MODE': 'standard'}, directory),
            ({**environment, 'OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH': epoch + '/foreign'}, directory),
            (environment, directory + '/foreign'),
            (environment, '/foreign/output-base/external/+codex_original_sdk_inputs+omux_original_native_sdk_inputs'),
        ]:
            with self.subTest(environment=changed_environment, directory=changed_directory), self.assertRaises(ValueError):
                rule['_fresh_epoch_action_mode'](ctx, changed_environment, changed_directory)
        for fresh in (False, True):
            with self.subTest(fresh=fresh), self.assertRaises(ValueError):
                rule['_regular_watch_path']('/foreign/undeclared', fresh)
        ctx.attr.fresh_epoch_action_inputs = False
        self.assertFalse(rule['_fresh_epoch_action_mode'](ctx, {}, '/legacy-output'))

    def test_unwatched_regular_changed_bytes_still_refuse_fresh_complete_action_proof(self):
        _, _, watched = self.watch_policy(True)
        path = self.fixture.origin / 'repositories/public+/tool'
        self.assertNotIn(str(path), watched)
        self.change_file(path, b'changed selected bytes')
        with self.assertRaises(ValueError):
            with self.session():
                self.fail('changed bytes cannot acquire original SDK authority')

    def test_unwatched_regular_changed_after_initial_proof_refuses_mandatory_final(self):
        _, _, watched = self.watch_policy(True)
        path = self.fixture.origin / 'repositories/public+/tool'
        self.assertNotIn(str(path), watched)
        with self.assertRaises(ValueError):
            with self.session() as session:
                self.change_file(path, b'late changed bytes')
                session.finish()

    def test_new_or_linked_namespace_and_changed_proof_refuse_after_watch_opt_in(self):
        self.watch_policy(True)
        for change in ('extra', 'linked', 'context'):
            with self.subTest(change=change):
                original = self.manifest.read_bytes()
                extra = self.fixture.origin / 'unexpected-watch-mode-entry'
                try:
                    if change == 'context':
                        value = copy.deepcopy(self.plan['document'])
                        value['context']['GRAPH_SHA256'] = '3'*64
                        self.rewrite_manifest(value)
                    else:
                        self.fixture.origin.chmod(0o700)
                        if change == 'extra':
                            self.fixture.write(extra, b'unadmitted', 0o444)
                        else:
                            extra.symlink_to(self.root / 'external-target-not-admitted')
                        self.fixture.origin.chmod(0o555)
                    with self.assertRaises(ValueError):
                        with self.session():
                            self.fail('namespace or proof mutation cannot acquire authority')
                finally:
                    self.fixture.origin.chmod(0o700)
                    if extra.is_symlink() or extra.exists():
                        extra.unlink()
                    self.fixture.origin.chmod(0o555)
                    self.manifest.chmod(0o600)
                    self.manifest.write_bytes(original)
                    self.manifest.chmod(0o444)


if __name__ == '__main__':
    unittest.main()
