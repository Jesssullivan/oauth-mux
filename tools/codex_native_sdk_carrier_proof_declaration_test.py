"""Decisions of the real proof rule; genuine parser/action gates stay separate.

These synthetic controls cannot select a real producer or attest execution.
Root must load the actual .bzl through Bazel in this declared model graph.
"""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


def rule_model():
    raw = Path(__file__).with_name('codex_native_sdk_carrier_proof_inputs.bzl').read_text()
    kinds = {str: 'string', int: 'int', dict: 'dict', list: 'list', bool: 'bool'}
    def fail(message):
        raise ValueError(message)
    namespace = {'type': lambda value: kinds.get(type(value), type(value).__name__),
                 'fail': fail, 'attr': SimpleNamespace(label=lambda **kwargs: kwargs),
                 'repository_rule': lambda **kwargs: kwargs,
                 'json': SimpleNamespace(decode=json.loads, encode=json.dumps)}
    exec(compile(raw.replace('.elems()', ''), '<real proof declaration>', 'exec'), namespace)
    return namespace


class ModelPath:
    def __init__(self, raw, context):
        self.raw = raw
        self.exists = raw not in context.missing
        self.is_dir = raw in context.directories
        self.realpath = context.redirects.get(raw, raw)
    def __str__(self):
        return self.raw


class Context:
    def __init__(self, model):
        self.model = model
        self.attr = SimpleNamespace(selection='/tracked/native-sdk-carrier-metadata-inputs.json')
        self.epoch = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/11111111-2222-3333-4444-555555555555'
        self.report = (self.epoch + '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
            'codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json')
        self.selector = {'schema_version': 2, 'kind': 'omux-native-sdk-carrier-metadata-input-v2',
            'status': 'selected-qualified-carrier-for-metadata', 'selection': {
                'original_selection': {'synthetic_model_only': True}, 'carrier': {'receipt_sha256': 'a' * 64},
                'qualification': {'producer': {'receipt': self.epoch + '/receipt.json',
                    'sha256': 'b' * 64, 'source_commit': 'c' * 40, 'graph_sha256': 'd' * 64},
                    'report': {'path': self.report, 'sha256': 'e' * 64}}}}
        self.receipt = {'id': self.epoch.split('/')[-1], 'profile': model['_PROFILE'], 'verb': 'test',
            'targets': [model['_TARGET']], 'exit': 0, 'workload_exit': 0, 'controller_failure': None,
            'descendants_empty': True, 'cleanup': {'state': 'empty'}, 'source_dirty': 'false',
            'source_commit': 'c' * 40, 'graph_sha256': 'd' * 64, 'output_base': self.epoch + '/output-base',
            'epoch_start_ns': 1234, 'test_evidence': {'state': 'preserved', 'sha256': 'f' * 64}}
        self.evidence = {'schema': 1, 'bazel_exit': 0, 'epoch_start_ns': 1234,
            'targets': [model['_TARGET']], 'results': [{'target': model['_TARGET'], 'state': 'observed',
                'files': [{'source': member, 'state': 'copied', 'file': digit * 64 + '.evidence',
                          'sha256': digit * 64, 'bytes': 10}
                         for member, digit in [('test.log', '1'), ('test.xml', '2')]]}]}
        self.events, self.generated, self.aliases = [], {}, []
        self.missing, self.directories, self.redirects = set(), set(), {}
        self.on_alias = None
    def path(self, value):
        return ModelPath(str(value), self)
    def watch(self, path):
        self.events.append(('watch', str(path)))
    def watch_tree(self, path):
        raise AssertionError('proof declaration must not traverse mutable trees')
    def read(self, path, **kwargs):
        self.events.append(('read', str(path)))
        controls = {self.attr.selection: self.selector, self.epoch + '/receipt.json': self.receipt,
                    self.epoch + '/test-evidence.json': self.evidence}
        return json.dumps(controls[str(path)])
    def symlink(self, path, alias):
        self.aliases.append((str(path), alias))
        if self.on_alias:
            self.on_alias(self, str(path))
    def file(self, name, raw, **kwargs):
        self.events.append(('file', name))
        self.generated[name] = raw


class ProofDeclarationModels(unittest.TestCase):
    def setUp(self):
        self.model = rule_model()
        self.ctx = Context(self.model)
    def run_rule(self, context=None):
        self.model['_implementation'](context or self.ctx)
    def refused(self, ctx):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.run_rule(ctx)
        self.assertNotIn('BUILD.bazel', ctx.generated)

    def test_exact_five_selected_proofs_and_generated_mapping(self):
        self.run_rule()
        declaration = json.loads(self.ctx.generated['proof-inputs.json'])
        self.assertEqual(set(declaration), {'kind', 'proofs'})
        self.assertEqual(declaration['kind'], 'omux-native-sdk-carrier-proof-inputs-v1')
        self.assertEqual(set(declaration['proofs']), set(self.model['_ROLES']))
        self.assertEqual(self.ctx.aliases, [(declaration['proofs'][role]['path'],
            declaration['proofs'][role]['alias']) for role in self.model['_ROLES']])
        expected_pins = ['b', 'f', '1', '2', 'e']
        for role, digit in zip(self.model['_ROLES'], expected_pins):
            self.assertEqual(set(declaration['proofs'][role]), {'path', 'sha256', 'alias'})
            self.assertEqual(declaration['proofs'][role]['sha256'], digit * 64)
        self.assertEqual(self.ctx.events[-1], ('file', 'BUILD.bazel'))
        watched = {name for kind, name in self.ctx.events if kind == 'watch'}
        self.assertEqual(watched, {self.ctx.attr.selection} |
            {entry['path'] for entry in declaration['proofs'].values()})
        self.assertEqual([name for kind, name in self.ctx.events if kind == 'read'],
            [self.ctx.attr.selection, self.ctx.epoch + '/receipt.json', self.ctx.epoch + '/test-evidence.json'])

    def test_null_and_unselected_controls_never_read_host_proof(self):
        for selector in [None, {'schema_version': 2, 'kind': 'omux-native-sdk-carrier-metadata-input-v2',
                               'status': 'unconfigured', 'selection': None}]:
            ctx = Context(self.model)
            ctx.selector = selector
            self.refused(ctx)
            self.assertEqual([name for kind, name in ctx.events if kind == 'read'], [ctx.attr.selection])
            self.assertEqual(ctx.aliases, [])

    def test_selector_pin_and_namespace_mutations_refuse(self):
        mutations = [lambda q: q['producer'].update(sha256='guessed'),
            lambda q: q['producer'].update(receipt='/foreign/receipt.json'),
            lambda q: q['producer'].update(receipt=self.ctx.epoch + '/subdir/receipt.json'),
            lambda q: q['report'].update(path=self.ctx.report.replace('seal_producer', 'metadata_producer')),
            lambda q: q['report'].update(path=self.ctx.report.replace('k8-fastbuild', '../k8-fastbuild')),
            lambda q: q.update(extra=True)]
        for mutate in mutations:
            ctx = Context(self.model)
            mutate(ctx.selector['selection']['qualification'])
            self.refused(ctx)

    def test_failed_or_mismatched_terminal_receipts_refuse(self):
        for key, value in [('exit', 125), ('workload_exit', 124), ('exit', False),
            ('source_commit', '9' * 40), ('graph_sha256', '9' * 64), ('controller_failure', 'failure'),
            ('profile', 'native-sdk-carrier-metadata-reserved'), ('descendants_empty', False),
            ('output_base', '/foreign/output-base'), ('cleanup', {'state': 'unproved'})]:
            ctx = Context(self.model)
            ctx.receipt[key] = value
            self.refused(ctx)
            self.assertEqual(ctx.aliases, [])

    def test_evidence_failure_epoch_target_and_duplicates_refuse(self):
        mutations = [lambda e: e.update(bazel_exit=1), lambda e: e.update(epoch_start_ns=99),
            lambda e: e.update(targets=['//tools:foreign']),
            lambda e: e['results'].append(copy.deepcopy(e['results'][0])),
            lambda e: e['results'][0]['files'].append(copy.deepcopy(e['results'][0]['files'][0])),
            lambda e: e['results'][0]['files'][0].update(file='../foreign.evidence'),
            lambda e: e['results'][0]['files'][0].update(sha256='missing'),
            lambda e: e['results'][0]['files'][0].update(bytes=0),
            lambda e: e['results'][0]['files'][0].update(file=e['results'][0]['files'][1]['file'])]
        for mutate in mutations:
            ctx = Context(self.model)
            mutate(ctx.evidence)
            self.refused(ctx)
            self.assertEqual(ctx.aliases, [])

    def test_every_missing_directory_or_linked_proof_refuses(self):
        names = [self.ctx.epoch + '/receipt.json', self.ctx.epoch + '/test-evidence.json',
                 self.ctx.epoch + '/test-evidence/' + '1' * 64 + '.evidence',
                 self.ctx.epoch + '/test-evidence/' + '2' * 64 + '.evidence', self.ctx.report]
        for name in names:
            for fault in ['missing', 'directory', 'redirect']:
                ctx = Context(self.model)
                if fault == 'missing':
                    ctx.missing.add(name)
                elif fault == 'directory':
                    ctx.directories.add(name)
                else:
                    ctx.redirects[name] = '/foreign/proof'
                self.refused(ctx)

    def test_late_selected_leaf_rebinding_never_publishes_build(self):
        self.ctx.on_alias = lambda ctx, name: ctx.redirects.update({name: '/foreign/proof'})
        self.refused(self.ctx)
        self.assertNotIn('proof-inputs.json', self.ctx.generated)

    def test_generated_sources_do_not_include_origin_or_acquisition(self):
        self.run_rule()
        build = self.ctx.generated['BUILD.bazel']
        self.assertNotIn('sdk-export', build)
        self.assertNotIn('carrier-private', build)
        for alias in self.model['_ALIASES'] + ['proof-inputs.json']:
            self.assertIn(alias, build)
        attributes = self.model['codex_native_sdk_carrier_proof_inputs']['attrs']
        self.assertEqual(set(attributes), {'selection'})
        self.assertTrue(attributes['selection']['mandatory'])


if __name__ == '__main__':
    unittest.main()
