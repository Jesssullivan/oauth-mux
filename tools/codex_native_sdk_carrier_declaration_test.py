"""Declared models for the real carrier acquisition/selection definitions.

Python evaluation tests rule decisions, not Starlark syntax or executed origin
authentication. Root must also load this .bzl through the real Bazel parser.
"""
import ast
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_native_sdk_carrier_producer as producer
import codex_native_sdk_carrier_test as fixtures


def rule_model():
    raw = Path(__file__).with_name('codex_native_sdk_carrier_inputs.bzl').read_text()
    kinds = {str: 'string', int: 'int', dict: 'dict', list: 'list', bool: 'bool'}
    def fail(message):
        raise ValueError(message)
    attrs = SimpleNamespace(**{name: lambda **kwargs: kwargs for name in
                               ('string', 'label', 'label_list', 'string_dict')})
    namespace = {'type': lambda value: kinds.get(type(value), type(value).__name__),
                 'fail': fail, 'attr': attrs, 'Label': lambda name: name,
                 'repository_rule': lambda **kwargs: kwargs,
                 'json': SimpleNamespace(decode=json.loads, encode=json.dumps)}
    exec(compile(raw.replace('.elems()', ''), '<real carrier declaration>', 'exec'), namespace)
    return namespace, raw


class Context:
    def __init__(self, model):
        self.model, self.events, self.files, self.symlinks = model, [], {}, []
        self.attr = SimpleNamespace(origin_root=model['_ORIGIN'],
            origin_receipt_sha256=model['_ORIGIN_SHA'], _producer=model['_HELPERS'][0],
            _sources=model['_HELPERS'][1:], bootstrap_closure='unused')
        entry = 10000000000123
        self.os = SimpleNamespace(environ={
            'OMUX_SDK_CARRIER_MODE': producer.MODE,
            'OMUX_SDK_CARRIER_ENTRY_NS': str(entry),
            'OMUX_SDK_CARRIER_DEADLINE_NS': str(entry + 1200 * 10**9),
            'OMUX_SDK_CARRIER_EPOCH': '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/11111111-2222-3333-4444-555555555555',
            'OMUX_SDK_CARRIER_SOURCE_COMMIT': '1' * 40,
            'OMUX_SDK_CARRIER_GRAPH_SHA256': '2' * 64})
        self.report = {'kind': 'omux-native-sdk-carrier-declaration-result-v1',
            'entry_monotonic_ns': entry, 'deadline_monotonic_ns': entry + 1200 * 10**9,
            'origin_receipt_sha256': model['_ORIGIN_SHA'], 'carrier_receipt_sha256': 'a' * 64,
            'files': [{'name': name, 'sha256': 'a' * 64, 'size': 1} for name in model['_FILES']]}
        self.return_code, self.alias_leaf = 0, None

    def path(self, value):
        raw = str(value)
        if not raw.startswith('/'):
            raw = '/repository/' + raw
        return ModelPath(raw, self.alias_leaf)

    def watch(self, path):
        self.events.append(('watch', str(path)))

    def watch_tree(self, path):
        raise AssertionError('mutable origin tree traversal is forbidden')

    def read(self, path, **_):
        return '# declared helper\n'

    def file(self, name, raw, **_):
        self.events.append(('file', name))
        self.files[name] = raw

    def symlink(self, physical, name):
        self.symlinks.append((str(physical), name))

    def report_progress(self, text):
        self.events.append(('progress', text))

    def execute(self, command, **kwargs):
        self.events.append(('execute', command, kwargs))
        return SimpleNamespace(return_code=self.return_code, stdout=json.dumps(self.report))


class ModelPath:
    def __init__(self, raw, alias_leaf):
        self.raw, self.basename, self.exists, self.is_dir = raw, raw.split('/')[-1], True, False
        self.realpath = raw if alias_leaf != raw else '/foreign/file'
    def __str__(self):
        return self.raw


class DeclarationModels(unittest.TestCase):
    def setUp(self):
        self.model, self.raw = rule_model()
        self.model['_python'] = lambda _: '/nix/store/locked-python/bin/python3'
        self.ctx = Context(self.model)

    def test_real_rule_emits_only_four_carrier_source_labels_after_seal(self):
        self.model['_implementation'](self.ctx)
        build = self.ctx.files['BUILD.bazel']
        for name in self.model['_FILES']:
            self.assertIn('carrier-private/carrier/' + name, build)
        self.assertNotIn(self.model['_ORIGIN'], build)
        self.assertEqual(self.ctx.events[-1], ('file', 'BUILD.bazel'))
        invocation = next(item for item in self.ctx.events if item[0] == 'execute')
        self.assertIn('-I', invocation[1])
        self.assertIn('-S', invocation[1])
        self.assertEqual(invocation[2]['environment'], self.ctx.os.environ)
        self.assertEqual(invocation[2]['timeout'], 1170)
        self.assertEqual([item[1] for item in self.ctx.events if item[0] == 'watch'],
                         ['/repository/' + name for name in self.model['_HELPERS']])

    def test_helper_failure_never_publishes_build(self):
        self.ctx.return_code = 1
        with self.assertRaisesRegex(ValueError, 'full-origin-seal'):
            self.model['_implementation'](self.ctx)
        self.assertNotIn('BUILD.bazel', self.ctx.files)

    def test_report_mutations_refuse_before_build(self):
        mutants = [lambda r: r.update(origin_receipt_sha256='b' * 64),
                   lambda r: r.update(entry_monotonic_ns=1),
                   lambda r: r.update(extra=True),
                   lambda r: r['files'][0].update(name='../foreign'),
                   lambda r: r['files'][0].update(size=-1),
                   lambda r: r['files'][0].update(name='receipt.json'),
                   lambda r: r['files'][-1].update(sha256='b' * 64)]
        for mutate in mutants:
            with self.subTest(mutate=mutate):
                ctx = Context(self.model)
                mutate(ctx.report)
                with self.assertRaises(ValueError):
                    self.model['_implementation'](ctx)
                self.assertNotIn('BUILD.bazel', ctx.files)

    def test_final_regular_leaf_substitution_refuses(self):
        self.ctx.alias_leaf = '/repository/carrier-private/carrier/receipt.json'
        with self.assertRaisesRegex(ValueError, 'physical-carrier-leaf'):
            self.model['_implementation'](self.ctx)
        self.assertNotIn('BUILD.bazel', self.ctx.files)

    def test_guard_mode_and_original_join_are_required_before_helper(self):
        for key, value in [('OMUX_SDK_CARRIER_MODE', 'native-sdk-carrier-metadata-reserved'),
                           ('OMUX_SDK_CARRIER_DEADLINE_NS', '1')]:
            ctx = Context(self.model)
            ctx.os.environ[key] = value
            with self.assertRaises(ValueError):
                self.model['_implementation'](ctx)
            self.assertFalse(any(row[0] == 'execute' for row in ctx.events))

    def test_all_guard_keys_are_repository_invalidation_inputs(self):
        attrs = self.model['codex_native_sdk_carrier_inputs']
        self.assertTrue(attrs['local'])
        self.assertTrue(set(self.model['_ENV']).issubset(attrs['environ']))
        tree = ast.parse(self.raw.replace('.elems()', ''))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == 'watch_tree'
                             for node in ast.walk(tree)))

    def selected(self):
        ctx = Context(self.model)
        ctx.attr.carrier_root = (ctx.os.environ['OMUX_SDK_CARRIER_EPOCH'] +
            '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
            'codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/sdk-carrier')
        ctx.attr.digests = {name: 'a' * 64 for name in self.model['_FILES']}
        return ctx

    def test_selected_inputs_are_exact_four_pinned_aliases(self):
        ctx = self.selected()
        self.model['_selected'](ctx)
        self.assertEqual([name for _, name in ctx.symlinks],
                         ['carrier/' + name for name in self.model['_FILES']])
        self.assertEqual(json.loads(ctx.files['selection.json'])['digests'], ctx.attr.digests)
        self.assertEqual(ctx.events[-1], ('file', 'BUILD.bazel'))

    def test_selected_input_digest_namespace_and_alias_mutants_refuse(self):
        for mutation in ('missing', 'invalid', 'foreign', 'alias'):
            ctx = self.selected()
            if mutation == 'missing':
                del ctx.attr.digests['payload.bin']
            elif mutation == 'invalid':
                ctx.attr.digests['payload.bin'] = 'guessed'
            elif mutation == 'foreign':
                ctx.attr.carrier_root = ctx.attr.carrier_root.replace('11111111-2222-3333-4444-555555555555', 'foreign')
            else:
                ctx.alias_leaf = ctx.attr.carrier_root + '/payload.bin'
            with self.assertRaises(ValueError):
                self.model['_selected'](ctx)
            self.assertNotIn('BUILD.bazel', ctx.files)


class OriginalEnvelopeModels(unittest.TestCase):
    def test_actual_context_validator_joins_all_original_guard_fields(self):
        model, _ = rule_model()
        environment = Context(model).os.environ
        entry = int(environment['OMUX_SDK_CARRIER_ENTRY_NS'])
        with patch.object(producer.time, 'monotonic_ns', return_value=entry + 1):
            value, cutoff = producer.context(environment)
        self.assertEqual(set(value), {'mode', 'epoch', 'source_commit', 'graph_sha256',
                                     'entry_monotonic_ns', 'deadline_monotonic_ns',
                                     'work_cutoff_monotonic_ns'})
        self.assertEqual(value['work_cutoff_monotonic_ns'], entry + 1170 * 10**9)
        self.assertEqual(cutoff, value['work_cutoff_monotonic_ns'] / 10**9)
        for field in model['_ENV']:
            mutated = dict(environment)
            del mutated[field]
            with self.subTest(missing=field), patch.object(producer.time, 'monotonic_ns', return_value=entry + 1):
                with self.assertRaises(ValueError):
                    producer.context(mutated)

    def test_large_nonround_original_integer_join_precedes_float(self):
        entry = 10000000000123457
        deadline = entry + 1200 * 10**9
        actual = producer.original_cutoff(entry, deadline, now_ns=entry + 100)
        self.assertEqual(actual, (deadline - 30 * 10**9) / 10**9)

    def test_late_recheck_reuses_cutoff_and_expiry_refuses(self):
        entry = 10000000000123
        deadline = entry + 1200 * 10**9
        early = producer.original_cutoff(entry, deadline, now_ns=entry)
        self.assertEqual(early, producer.original_cutoff(entry, deadline,
                                                       now_ns=deadline - 30 * 10**9 - 1))
        with self.assertRaisesRegex(ValueError, 'expired-envelope'):
            producer.original_cutoff(entry, deadline, now_ns=deadline - 30 * 10**9)

    def test_incorrect_original_join_refuses(self):
        entry = 10000000000123
        for delta in (1170 * 10**9, 1200 * 10**9 + 1):
            with self.assertRaisesRegex(ValueError, 'original-envelope'):
                producer.original_cutoff(entry, entry + delta, now_ns=entry)
        with self.assertRaises(ValueError):
            producer.original_cutoff(True, 1200 * 10**9 + 1, now_ns=1)


class ProducerRetentionModels(unittest.TestCase):
    # Reuse the real tiny SDK/registry/JDK bytes, including an inert external
    # JDK symbolic target and a qualified absence; no genuine selector is edited.
    setUp = fixtures.CarrierModels.setUp
    tearDown = fixtures.CarrierModels.tearDown
    write = staticmethod(fixtures.CarrierModels.write)
    seal_dirs = staticmethod(fixtures.CarrierModels.seal_dirs)

    def retained(self, context=None):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        with patch.object(producer, 'ORIGIN', str(self.origin)), patch.object(producer, 'ORIGIN_SHA', self.pin):
            return outputs, producer.qualify(source / 'receipt.json', outputs,
                                             self.context if context is None else context, self.deadline)

    def test_real_qualifier_retains_all_four_bytes_and_false_promotion_flags(self):
        outputs, program = self.retained()
        expected = {'payload.bin', 'manifest.json', 'origin-receipt.json', 'receipt.json'}
        destination = outputs / 'sdk-private/sdk-carrier'
        self.assertEqual(set(os.listdir(destination)), expected)
        for name in expected:
            self.assertEqual((destination / name).read_bytes(), (self.root / 'carrier' / name).read_bytes())
        self.assertEqual(program['producer_context'], self.context)
        self.assertTrue(program['all_four_leaves_rechecked'])
        for field in ('sdk_execution_qualified', 'metadata_qualified', 'compiler_qualified', 'runtime_qualified'):
            self.assertIs(program[field], False)
        self.assertEqual(json.loads((outputs / 'sdk-private/native-sdk-carrier-producer.json').read_bytes()), program)

    def test_real_qualifier_then_bazel_readonly_retention_reopens_full_transport_without_logical_mode_changes(self):
        outputs, program = self.retained()
        destination = outputs / 'sdk-private/sdk-carrier'
        for name in producer.carrier.FILES:
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o444)
        # A completed model producer releases its writer. Model Bazel9's
        # output metadata normalization only on these own fixture artifacts.
        for path, _, names in os.walk(outputs, topdown=False):
            for name in names:
                (Path(path) / name).chmod(0o555)
            Path(path).chmod(0o555)
        pin = program['carrier_receipt_sha256']
        publication = producer.carrier.publication_report(destination, pin, self.deadline)
        self.assertEqual(publication['files'], program['files'])
        report = producer.carrier.validate_binding(destination, pin, self.deadline)
        self.assertEqual(report['producer_context'], self.context)
        output = self.root / 'retained-consumer-extracted'
        fresh = producer.carrier.extract(destination, pin, output, self.deadline)
        self.assertEqual(fresh['producer_context'], self.context)
        self.assertFalse(fresh['original_inodes_reused'])
        self.assertFalse(fresh['sdk_execution_qualified'])
        self.assertFalse(fresh['metadata_qualified'])
        self.assertEqual(stat.S_IMODE((output / 'sdk/receipt.json').stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((output / 'sdk/repositories/public+/MODULE.bazel').stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((output / 'sdk/repositories/public+/tool').stat().st_mode), 0o555)
        self.assertEqual(producer.carrier.revalidate_extraction(destination, pin, output, self.deadline,
            pinned_extraction_receipt_sha256=producer.carrier.sha(producer.carrier.encoded(fresh))), fresh)
        self.assertEqual(producer.carrier.publication_report(destination, pin, self.deadline), publication)
        for row in program['files']:
            leaf = destination / row['name']
            self.assertEqual((producer.carrier.sha(leaf.read_bytes()), leaf.stat().st_size),
                             (row['sha256'], row['size']))
            self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o555)

    def test_current_qualifier_writer_still_refuses_mode_change_before_accepted_program(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        original = producer.carrier.Output.finish
        def retain_before_writer_readback(output):
            original(output)
            for name in producer.carrier.FILES:
                (output.path / name).chmod(0o555)
        with (patch.object(producer, 'ORIGIN', str(self.origin)),
              patch.object(producer, 'ORIGIN_SHA', self.pin),
              patch.object(producer.carrier.Output, 'finish', new=retain_before_writer_readback)):
            with self.assertRaises(ValueError):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertFalse((outputs / 'sdk-private/native-sdk-carrier-producer.json').exists())

    def test_other_epoch_context_refuses_without_retained_publication(self):
        wrong = dict(self.context, source_commit='4' * 40)
        with self.assertRaisesRegex(ValueError, 'actual-acquisition-context'):
            self.retained(wrong)
        self.assertFalse((self.root / 'test.outputs/sdk-private').exists())

    def test_named_retained_directory_replacement_preserves_foreign_and_refuses(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        original = producer.carrier.Output.finish
        def replace(output):
            original(output)
            output.path.rename(output.path.with_name('detached-owned'))
            output.path.mkdir(mode=0o700)
            (output.path / 'foreign').write_bytes(b'foreign owner data')
            output.path.chmod(0o555)
        with patch.object(producer, 'ORIGIN', str(self.origin)), patch.object(producer, 'ORIGIN_SHA', self.pin), patch.object(producer.carrier.Output, 'finish', new=replace):
            with self.assertRaises((ValueError, FileNotFoundError)):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertEqual((outputs / 'sdk-private/sdk-carrier/foreign').read_bytes(), b'foreign owner data')
        self.assertFalse((outputs / 'sdk-private/native-sdk-carrier-producer.json').exists())

    def test_qualifier_runs_full_binding_once_and_preserves_actual_nar_proof(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        with (patch.object(producer, 'ORIGIN', str(self.origin)),
              patch.object(producer, 'ORIGIN_SHA', self.pin),
              patch.object(producer.carrier, 'binding', wraps=producer.carrier.binding) as full,
              patch.object(producer.carrier.nar, 'hash_descriptor',
                           wraps=producer.carrier.nar.hash_descriptor) as nars):
            program = producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertEqual(full.call_count, 1)
        self.assertEqual(nars.call_count, 2)
        self.assertEqual([row['name'] for row in program['files']], list(producer.carrier.FILES))
        for row in program['files']:
            raw = (outputs / 'sdk-private/sdk-carrier' / row['name']).read_bytes()
            self.assertEqual((producer.carrier.sha(raw), len(raw)), (row['sha256'], row['size']))

    def test_corrupt_initial_payload_refuses_before_retained_root_creation(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        payload = source / 'payload.bin'
        raw = payload.read_bytes()
        payload.chmod(0o600)
        payload.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        payload.chmod(0o444)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        with patch.object(producer, 'ORIGIN', str(self.origin)), patch.object(producer, 'ORIGIN_SHA', self.pin):
            with self.assertRaisesRegex(ValueError, 'payload-file-digest'):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertFalse((outputs / 'sdk-private').exists())

    def test_source_change_during_copy_refuses_with_original_held_descriptors(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        original = producer.carrier.write_all
        mutated = False
        def change(fd, raw, clock):
            nonlocal mutated
            original(fd, raw, clock)
            if not mutated:
                mutated = True
                payload = source / 'payload.bin'
                contents = payload.read_bytes()
                payload.chmod(0o600)
                payload.write_bytes(bytes([contents[0] ^ 1]) + contents[1:])
                payload.chmod(0o444)
        with (patch.object(producer, 'ORIGIN', str(self.origin)),
              patch.object(producer, 'ORIGIN_SHA', self.pin),
              patch.object(producer.carrier, 'write_all', side_effect=change)):
            with self.assertRaises(ValueError):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertTrue(mutated)
        self.assertFalse((outputs / 'sdk-private/native-sdk-carrier-producer.json').exists())

    def test_same_byte_retained_leaf_replacement_refuses_writer_identity_join(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        original = producer.carrier.Output.finish
        def replace(output):
            original(output)
            output.path.chmod(0o700)
            leaf = output.path / 'manifest.json'
            contents = leaf.read_bytes()
            leaf.rename(output.path.with_name('detached-manifest'))
            self.write(leaf, contents)
            output.path.chmod(0o555)
        with (patch.object(producer, 'ORIGIN', str(self.origin)),
              patch.object(producer, 'ORIGIN_SHA', self.pin),
              patch.object(producer.carrier.Output, 'finish', new=replace)):
            with self.assertRaisesRegex(ValueError, 'named-root-leaf'):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertTrue((outputs / 'sdk-private/detached-manifest').exists())
        self.assertFalse((outputs / 'sdk-private/native-sdk-carrier-producer.json').exists())

    def test_late_source_or_destination_change_refuses_after_program_write(self):
        for name in ('source', 'destination'):
            with self.subTest(name=name):
                source, _, _ = fixtures.CarrierModels.seal(self, name + '-carrier')
                outputs = self.root / (name + '-outputs')
                outputs.mkdir(mode=0o700)
                original = producer.carrier.write_all
                changed = False
                def change(fd, raw, clock):
                    nonlocal changed
                    original(fd, raw, clock)
                    if b'"kind":"omux-native-sdk-carrier-producer-v1"' in raw:
                        changed = True
                        root = source if name == 'source' else outputs / 'sdk-private/sdk-carrier'
                        leaf = root / 'payload.bin'
                        contents = leaf.read_bytes()
                        leaf.chmod(0o600)
                        leaf.write_bytes(bytes([contents[0] ^ 1]) + contents[1:])
                        leaf.chmod(0o444)
                with (patch.object(producer, 'ORIGIN', str(self.origin)),
                      patch.object(producer, 'ORIGIN_SHA', self.pin),
                      patch.object(producer.carrier, 'write_all', side_effect=change)):
                    with self.assertRaises(ValueError):
                        producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
                self.assertTrue(changed)

    def test_held_descriptors_close_on_expiry_without_replacing_original_clock(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        clock = producer.carrier.Clock(self.deadline)
        with producer.carrier.Root(source, clock) as root:
            held = producer.HeldLeaves(root)
            descriptors = [fd for fd, _ in held.files.values()]
            with patch.object(producer.carrier.time, 'monotonic', return_value=self.deadline):
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    with held:
                        held.readback()
            self.assertEqual(clock.deadline, self.deadline)
            self.assertEqual(held.files, {})
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_late_source_parent_substitution_preserves_foreign_and_refuses(self):
        source, _, _ = fixtures.CarrierModels.seal(self)
        outputs = self.root / 'test.outputs'
        outputs.mkdir(mode=0o700)
        original = producer.carrier.write_all
        changed = False
        def change(fd, raw, clock):
            nonlocal changed
            original(fd, raw, clock)
            if b'"kind":"omux-native-sdk-carrier-producer-v1"' in raw:
                changed = True
                source.rename(self.root / 'detached-source')
                source.mkdir(mode=0o700)
                self.write(source / 'foreign', b'foreign owner data')
                source.chmod(0o555)
        with (patch.object(producer, 'ORIGIN', str(self.origin)),
              patch.object(producer, 'ORIGIN_SHA', self.pin),
              patch.object(producer.carrier, 'write_all', side_effect=change)):
            with self.assertRaisesRegex(ValueError, 'named-ancestor'):
                producer.qualify(source / 'receipt.json', outputs, self.context, self.deadline)
        self.assertTrue(changed)
        self.assertEqual((source / 'foreign').read_bytes(), b'foreign owner data')


if __name__ == '__main__':
    unittest.main()
