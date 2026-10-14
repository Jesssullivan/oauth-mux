"""Declared rule/macro and real retirement models; no genuine source qualification.

The literal rule-body translator covers repository predicates only. Actual Bazel
package loading is a separate syntax prerequisite; the production intake owns
nofollow bytes, guardian, identity, namespace, NAR and final custody predicates.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import execution_guard_test as retirement

ROOT = Path(__file__).parent
NEW_TEST = '//tools:codex_native_siwc_catalog_content_source_test'
NEW_PRODUCER = '//tools:codex_native_siwc_catalog_content_source_producer'
COHORT = [NEW_TEST, NEW_PRODUCER]


class RepositoryPath:
    def __init__(self, value): self.value = Path(value)
    def __str__(self): return str(self.value)
    @property
    def exists(self): return self.value.exists()
    @property
    def is_dir(self): return self.value.is_dir()
    @property
    def realpath(self): return RepositoryPath(self.value.resolve(strict=True))
    @property
    def dirname(self): return RepositoryPath(self.value.parent)


def literal_rule(name):
    raw = (ROOT / name).read_text()
    raw = raw[:raw.rindex('\n' + name.removesuffix('.bzl') + ' = repository_rule')]
    # The .elems() iterator and type names are the only language projections.
    raw = raw.replace('value.elems()', 'value')
    types = {str: 'string', dict: 'dict', list: 'list', int: 'int', bool: 'bool', type(None): 'NoneType'}
    def fail(message): raise ValueError(message)
    namespace = {'fail': fail, 'type': lambda value: types.get(type(value), 'unknown'),
                 'json': SimpleNamespace(decode=json.loads, encode=json.dumps)}
    exec(raw, namespace)
    return namespace['_implementation']


class Context:
    def __init__(self, selection):
        self.attr = SimpleNamespace(selection=selection)
        self.watches, self.links, self.outputs, self.reads = [], [], {}, []
    def path(self, value): return value if isinstance(value, RepositoryPath) else RepositoryPath(value)
    def read(self, path):
        self.reads.append(str(path)); return Path(str(path)).read_text()
    def watch(self, path): self.watches.append(str(path))
    def symlink(self, path, name): self.links.append((str(path), name))
    def file(self, name, raw, **kwargs): self.outputs[name] = raw


class ContentGraphModels(unittest.TestCase):
    def fixture(self, *, content=False):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); selected = root / 'selected'; source = selected / 'source'
        source.mkdir(parents=True); epoch = root / 'epoch'; epoch.mkdir(); (epoch / 'test-evidence').mkdir()
        count = 8557 if content else 8553
        inventory = {}
        # Every selected leaf is an actual file. Links exercise the distinct
        # logical-link path and keep the full fixed inventory size.
        for index in range(count - 1):
            name = 'member-' + str(index).zfill(5)
            (source / name).write_bytes(b'public')
            inventory[name] = {'mode': '100755' if index == 0 else '100644', 'sha256': 'a' * 64}
        (source / 'selected-link').symlink_to('member-00000')
        inventory['selected-link'] = {'mode': '120000', 'sha256': 'b' * 64}
        prefix = 'codex_native_siwc_catalog_content_source' if content else 'codex_native_source_file_writer'
        targets = ['//tools:' + prefix + '_test', '//tools:' + prefix + '_producer']
        if not content: targets.append('//tools:' + prefix + '_metadata_producer')
        report = {'kind': 'omux-native-siwc-catalog-content-source-v1' if content else 'omux-native-source-file-writer-boundary-v1',
            'status': 'verified-siwc-catalog-content-source-uncompiled' if content else 'verified-tenth-file-writer-source-uncompiled',
            'inventory_sha256': 'c' * 64, 'source_inventory': inventory, 'patch_sha256': ['d' * 64] * (12 if content else 10)}
        if content:
            report['native_controls_sha256'] = 'e' * 64
            report['generated_hub'] = {name: {'sha256': 'f' * 64, 'bytes': 6} for name in ('BUILD.bazel','defs.bzl','data.bzl')}
            hub = selected / 'hub/source'; hub.mkdir(parents=True)
            for name in report['generated_hub']: (hub / name).write_bytes(b'public')
        receipt = selected / 'source-receipt.json'; receipt.write_text(json.dumps(report))
        outer = {'profile': 'native-siwc-catalog-content-source-reserved' if content else 'native-file-writer-source-reserved',
            'targets': targets, 'exit': 0, 'workload_exit': 0, 'source_commit': '1' * 40, 'graph_sha256': '2' * 64}
        (epoch / 'receipt.json').write_text(json.dumps(outer)); results = []
        for index, target in enumerate(targets):
            files = []
            for offset, kind in enumerate(('test.log','test.xml')):
                # Filename is independent from its pinned content hash.
                name = hashlib.sha256(str(index * 2 + offset).encode()).hexdigest() + '.evidence'
                (epoch / 'test-evidence' / name).write_bytes(b'public')
                files.append({'source': kind, 'state': 'copied', 'file': name, 'sha256': '3' * 64})
            results.append({'target': target, 'state': 'observed', 'files': files})
        (epoch / 'test-evidence.json').write_text(json.dumps({'targets': targets, 'results': results}))
        parent = {'root': str(selected), 'receipt_bytes': receipt.stat().st_size, 'receipt_sha256': '4' * 64,
            'inventory_sha256': 'c' * 64, 'producer': {'receipt': str(epoch / 'receipt.json'), 'sha256': '5' * 64,
                'source_commit': '1' * 40, 'graph_sha256': '2' * 64}}
        config = ({'schema_version': 1, 'kind': 'omux-native-siwc-catalog-model-selection-v1',
            'status': 'qualified-catalog-content-source-hub-uncompiled', 'source': parent, 'catalog_controls_sha256': 'e' * 64}
            if content else {'schema_version': 1, 'kind': 'omux-native-n10-content-input-v1',
                'status': 'selected-N10-content-uncompiled', 'parent': parent})
        selection = root / 'selection.json'; selection.write_text(json.dumps(config))
        return root, selected, epoch, selection, config, report

    def test_complete_n10_aliases_watch_order_logical_modes_and_build_last(self):
        unused, selected, epoch, selection, config, report = self.fixture()
        ctx = Context(selection); literal_rule('codex_native_n10_content_inputs.bzl')(ctx)
        mapping = json.loads(ctx.outputs['source-inputs.json'])
        self.assertEqual(mapping['selection'], config['parent']); self.assertEqual(len(mapping['inputs']), 8562)
        self.assertEqual([row['alias'] for row in mapping['inputs']], ['input/' + str(i) for i in range(8562)])
        paths = [row['path'] for row in mapping['inputs']]
        self.assertEqual(len(set(paths)), 8562); self.assertEqual(ctx.watches, [str(selection)] + paths)
        self.assertEqual(ctx.links, [(path, 'input/' + str(i)) for i, path in enumerate(paths)])
        self.assertEqual(paths[9:], [str(selected / 'source' / name) for name in sorted(report['source_inventory'])])
        self.assertEqual(list(ctx.outputs), ['source-inputs.json', 'BUILD.bazel'])
        self.assertTrue(all(path.startswith(str(selected)) or path.startswith(str(epoch)) or path == str(selection) for path in ctx.reads))

    def test_old_selector_or_wrong_family_refuses_before_any_payload_read(self):
        unused, unused_selected, unused_epoch, selection, config, unused_report = self.fixture()
        for changes in ({'kind':'omux-native-file-writer-model-source-input-v1'}, {'status':'qualified'}, {'schema_version': True}):
            selection.write_text(json.dumps({**config, **changes})); ctx = Context(selection)
            with self.assertRaises(ValueError): literal_rule('codex_native_n10_content_inputs.bzl')(ctx)
            self.assertEqual(ctx.reads, [str(selection)]); self.assertFalse(ctx.outputs)

    def test_missing_proof_and_unselected_symbolic_target_refuse_without_build(self):
        for fault in ('proof', 'link'):
            unused, selected, epoch, selection, config, report = self.fixture()
            if fault == 'proof': next((epoch / 'test-evidence').iterdir()).unlink()
            else:
                link = selected / 'source/selected-link'; link.unlink(); link.symlink_to('/dev/null')
            ctx = Context(selection)
            with self.assertRaises(ValueError): literal_rule('codex_native_n10_content_inputs.bzl')(ctx)
            self.assertFalse(ctx.outputs); self.assertFalse(ctx.links)

    def test_content_model_family_requires_exact_new_report_profile_and_two_target_cohort(self):
        unused, unused_selected, epoch, selection, config, report = self.fixture(content=True)
        rule = literal_rule('codex_native_siwc_catalog_model_inputs.bzl'); ctx = Context(selection); rule(ctx)
        self.assertEqual(len(json.loads(ctx.outputs['source-inputs.json'])['inputs']), 8567)
        raw = (epoch / 'receipt.json').read_text(); outer = json.loads(raw)
        for changes in ({'profile':'native-siwc-catalog-source-reserved'}, {'targets': list(reversed(COHORT))}, {'workload_exit':1}):
            (epoch / 'receipt.json').write_text(json.dumps({**outer, **changes})); ctx = Context(selection)
            with self.assertRaises(ValueError): rule(ctx)
            self.assertFalse(ctx.outputs)
        (epoch / 'receipt.json').write_text(raw)
        receipt = Path(config['source']['root']) / 'source-receipt.json'
        report['kind'] = 'omux-native-siwc-catalog-source-v1'; receipt.write_text(json.dumps(report))
        config['source']['receipt_bytes'] = receipt.stat().st_size; selection.write_text(json.dumps(config))
        with self.assertRaises(ValueError): rule(Context(selection))

    def test_cold_driver_declaration_never_reads_physical_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = Path(temporary) / 'selection.json'
            selection.write_text(json.dumps({'schema_version':1,'kind':'omux-native-siwc-catalog-model-selection-v1',
                'status':'PENDING-GENUINE-SOURCE-QUALIFICATION','source':None,'catalog_controls_sha256':'a'*64}))
            ctx = Context(selection); literal_rule('codex_native_siwc_catalog_model_inputs.bzl')(ctx)
            self.assertEqual(ctx.reads, [str(selection)]); self.assertFalse(ctx.links)
            self.assertIsNone(json.loads(ctx.outputs['source-inputs.json'])['selection'])

    def macros(self):
        calls = []
        class Depset:
            def __init__(self, values): self.values = list(dict.fromkeys(values))
            def to_list(self): return self.values
        namespace = {'depset': Depset, 'python_test': lambda **kwargs: calls.append(kwargs),
            'native': SimpleNamespace(filegroup=lambda **kwargs: calls.append(kwargs)),
            'native_acquisition_source_closure': lambda source, sdk: source + sdk}
        for name in ('codex_native_siwc_catalog_content_source_targets.bzl','codex_native_siwc_catalog_models_targets.bzl'):
            raw = '\n'.join(line for line in (ROOT / name).read_text().splitlines() if not line.startswith('load('))
            exec(raw, namespace)
        return namespace, calls

    def test_actual_macros_exclude_original_leaf_graph_and_keep_complete_packed_sdk_tools(self):
        ns, calls = self.macros(); ns['codex_native_siwc_catalog_content_source_targets'](['source.py'], ['sdk.py'], ['original.py'])
        producer = next(row for row in calls if row['name'].endswith('_producer'))
        expected = {'@omux_native_n10_content_inputs//:inputs',
            '@omux_native_sdk_carrier_inputs//:inputs','@omux_native_sdk_carrier_proof_inputs//:inputs','@omux_protocol_history_query_tools//:inputs'}
        self.assertEqual({row for row in producer['data'] if row.startswith('@')}, expected)
        self.assertEqual(len(producer['data']), len(set(producer['data'])))
        self.assertIn('original.py', producer['srcs']); self.assertEqual(len(producer['env_inherit']), 6)
        calls.clear(); ns['codex_native_siwc_catalog_models_targets'](['source.py'], ['sdk.py'], ['@forbidden_historical_parent//:inputs'], ['original.py'])
        self.assertEqual([row for row in calls if row['name'] == 'codex_native_siwc_catalog_model_inputs_analysis_smoke'],
            [{'name': 'codex_native_siwc_catalog_model_inputs_analysis_smoke',
              'srcs': ['@omux_native_siwc_catalog_model_inputs//:inputs']}])
        driver = next(row for row in calls if row['name'].endswith('_producer'))
        self.assertEqual({row for row in driver['data'] if row.startswith('@')}, expected | {'@omux_native_siwc_catalog_model_inputs//:inputs'})
        self.assertNotIn('@forbidden_historical_parent//:inputs', driver['data'])
        for row in (producer, driver):
            self.assertNotIn('@omux_original_native_sdk_inputs//:inputs', row['data'])
            self.assertIn('codex_transported_sdk_inputs.py', row['srcs'])
            self.assertIn('original.py', row['srcs'])
        model = next(row for row in calls if row['name'] == 'codex_native_siwc_catalog_models_test')
        self.assertIn('original.py', model['srcs'])
        self.assertIn('codex_transported_sdk_inputs_test.py', model['srcs'])
        self.assertIn('codex_native_sdk_carrier_test.py', model['srcs'])
        # Existing historical producers keep their original complete physical
        # SDK declaration; only the explicit content/driver graph changes.
        for name, entry in (('codex_native_file_writer_model_source_targets.bzl', 'native_file_writer_model_source_targets'),
                ('codex_native_siwc_source_targets.bzl', 'codex_native_siwc_source_targets')):
            raw = '\n'.join(line for line in (ROOT / name).read_text().splitlines() if not line.startswith('load('))
            exec(raw, ns); calls.clear()
            ns[entry](['source.py'], ['sdk.py'], ['@original_historical_parent//:inputs'], ['original.py'])
            historical = next(row for row in calls if row['name'].endswith('_producer'))
            self.assertIn('@omux_original_native_sdk_inputs//:inputs', historical['data'])
            self.assertIn('@original_historical_parent//:inputs', historical['data'])

    def test_static_test_data_does_not_instantiate_old_repository(self):
        ns, calls = self.macros(); ns['codex_native_siwc_catalog_content_source_targets']([], [], [])
        model = next(row for row in calls if row['name'].endswith('_test'))
        self.assertFalse(any(row.startswith('@') for row in model['data']))
        self.assertIn('codex_native_siwc_catalog_source_test.py', model['srcs'])
        self.assertIn('codex_native_n10_source_intake_test.py', model['srcs'])
        self.assertIn('codex_transported_sdk_inputs.py', model['srcs'])
        self.assertIn('codex_transported_sdk_inputs_test.py', model['srcs'])
        self.assertIn('codex_native_sdk_carrier_test.py', model['srcs'])
        self.assertIn('codex_native_siwc_catalog_source_targets.bzl', model['data'])

    def test_actual_compact_rules_keep_all_four_transport_and_five_proof_members(self):
        # Actual repository bodies; filesystem shape is an explicit declaration
        # seam. This model does not authenticate a producer, SDK byte or NAR.
        kinds = {str: 'string', dict: 'dict', list: 'list', int: 'int', bool: 'bool'}
        def fail(message): raise ValueError(message)
        def rule(name, selected=False):
            raw = (ROOT / name).read_text()
            if selected:
                head = raw.split('\ncodex_native_sdk_carrier_inputs = repository_rule', 1)[0]
                tail = raw.split('\ndef _selected(ctx):', 1)[1].split('\ncodex_native_sdk_carrier_selected_inputs = repository_rule', 1)[0]
                raw = head + '\ndef _selected(ctx):' + tail
            else:
                raw = raw[:raw.rindex('\n' + name.removesuffix('.bzl') + ' = repository_rule')]
            namespace = {'fail': fail, 'type': lambda value: kinds.get(type(value), 'unknown'),
                'json': SimpleNamespace(decode=json.loads, encode=json.dumps)}
            exec(raw.replace('.elems()', ''), namespace)
            return namespace['_selected' if selected else '_implementation']
        class Leaf:
            def __init__(self, name, present): self.name, self.present = str(name), present
            def __str__(self): return self.name
            @property
            def exists(self): return self.name in self.present
            @property
            def is_dir(self): return False
            @property
            def realpath(self): return self
        class ShapeContext:
            def __init__(self, attr, raw, present):
                self.attr, self.raw, self.present = attr, raw, present
                self.links, self.watches, self.outputs = [], [], {}
            def path(self, name): return Leaf(name, self.present)
            def read(self, path, **kwargs): return self.raw[str(path)]
            def watch(self, path): self.watches.append(str(path))
            def symlink(self, path, alias): self.links.append((str(path), alias))
            def file(self, name, raw, **kwargs): self.outputs[name] = raw
        def group(ctx):
            calls = []
            exec(ctx.outputs['BUILD.bazel'], {'__builtins__': {},
                'package': lambda **kwargs: calls.append(('package', kwargs)),
                'exports_files': lambda files: calls.append(('exports', files)),
                'filegroup': lambda **kwargs: calls.append(('group', kwargs))})
            self.assertEqual(calls[0], ('package', {'default_visibility': ['//visibility:public']}))
            self.assertEqual(calls[1][1], calls[2][1]['srcs'])
            self.assertEqual(calls[2][1]['name'], 'inputs')
            self.assertEqual(len(calls), 3)
            return calls[1][1]
        epoch = '/home/jess/.local/state/omux-execution-20261005/12345678-1234-1234-1234-123456789abc'
        stem = epoch + '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private'
        names = ['payload.bin', 'manifest.json', 'origin-receipt.json', 'receipt.json']
        digests = {name: str(index + 1) * 64 for index, name in enumerate(names)}
        carrier_root = stem + '/sdk-carrier'
        present = {carrier_root + '/' + name for name in names}
        selected = rule('codex_native_sdk_carrier_inputs.bzl', selected=True)
        ctx = ShapeContext(SimpleNamespace(carrier_root=carrier_root, digests=digests), {}, present)
        selected(ctx)
        self.assertEqual(ctx.links, [(carrier_root + '/' + name, 'carrier/' + name) for name in names])
        self.assertEqual(ctx.watches, [carrier_root + '/' + name for name in names])
        self.assertEqual(group(ctx), ['carrier/' + name for name in names] + ['selection.json'])
        self.assertEqual(json.loads(ctx.outputs['selection.json']), {'carrier_root': carrier_root, 'digests': digests})
        ctx = ShapeContext(SimpleNamespace(carrier_root=carrier_root, digests=digests), {}, present - {carrier_root + '/payload.bin'})
        with self.assertRaises(ValueError): selected(ctx)
        self.assertNotIn('BUILD.bazel', ctx.outputs)
        target = '//tools:codex_native_sdk_carrier_seal_producer'
        selector_path = '/private/public-model/selected.json'
        producer = {'receipt': epoch + '/receipt.json', 'sha256': 'a' * 64,
            'source_commit': 'b' * 40, 'graph_sha256': 'c' * 64}
        report = {'path': stem + '/native-sdk-carrier-producer.json', 'sha256': 'd' * 64}
        selector = {'schema_version': 2, 'kind': 'omux-native-sdk-carrier-metadata-input-v2',
            'status': 'selected-qualified-carrier-for-metadata', 'selection':
            {'original_selection': {}, 'carrier': {}, 'qualification': {'producer': producer, 'report': report}}}
        outer = {'id': epoch.split('/')[-1], 'profile': 'native-sdk-carrier-seal-reserved', 'verb': 'test',
            'targets': [target], 'exit': 0, 'workload_exit': 0, 'controller_failure': None,
            'descendants_empty': True, 'cleanup': {'state': 'empty'}, 'source_dirty': 'false',
            'source_commit': producer['source_commit'], 'graph_sha256': producer['graph_sha256'],
            'output_base': epoch + '/output-base', 'epoch_start_ns': 17,
            'test_evidence': {'state': 'preserved', 'sha256': 'e' * 64}}
        entries = [{'source': name, 'state': 'copied', 'file': str(index + 6) * 64 + '.evidence',
            'sha256': str(index + 8) * 64, 'bytes': 1} for index, name in enumerate(('test.log', 'test.xml'))]
        evidence = {'schema': 1, 'bazel_exit': 0, 'epoch_start_ns': 17, 'targets': [target],
            'results': [{'target': target, 'state': 'observed', 'files': entries}]}
        raw = {selector_path: json.dumps(selector), producer['receipt']: json.dumps(outer),
            epoch + '/test-evidence.json': json.dumps(evidence)}
        present = set(raw) | {report['path']} | {epoch + '/test-evidence/' + row['file'] for row in entries}
        proof_rule = rule('codex_native_sdk_carrier_proof_inputs.bzl')
        ctx = ShapeContext(SimpleNamespace(selection=selector_path), raw, present)
        proof_rule(ctx)
        expected = ['proof/outer-receipt.json', 'proof/test-evidence.json', 'proof/test-log.evidence',
            'proof/test-xml.evidence', 'proof/program-report.json']
        self.assertEqual(group(ctx), expected + ['proof-inputs.json'])
        self.assertEqual([alias for path, alias in ctx.links], expected)
        self.assertEqual(set(json.loads(ctx.outputs['proof-inputs.json'])['proofs']),
            {'outer_receipt', 'test_evidence', 'test_log', 'test_xml', 'program_report'})
        ctx = ShapeContext(SimpleNamespace(selection=selector_path), raw,
            present - {epoch + '/test-evidence/' + entries[1]['file']})
        with self.assertRaises(ValueError): proof_rule(ctx)
        self.assertNotIn('BUILD.bazel', ctx.outputs)

    def retention(self):
        fixture = retirement.RunRetirementFilesystemModels('test_exact_reserved_file_writer_vector_holds_its_source_root')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        directory = fixture.producer(NEW_PRODUCER); fixture.receipt['targets'] = COHORT; fixture.save_receipt()
        return fixture, directory

    def test_exact_successful_two_target_retention_keeps_original_source_hub_root(self):
        fixture, directory = self.retention(); before = fixture.output.stat()
        for member in ('source/member','hub/source/data.bzl'):
            leaf = directory / 'native-siwc-catalog-content-source' / member
            leaf.parent.mkdir(parents=True, exist_ok=True); leaf.write_bytes(b'original retained bytes')
        report = fixture.retire()
        self.assertEqual(report['children']['output-base'], 'retained-declared-producer')
        self.assertEqual(report['retained_physical_root'], {'device': before.st_dev, 'inode': before.st_ino})
        self.assertTrue((directory / 'native-siwc-catalog-content-source/source/member').is_file())
        self.assertTrue((directory / 'native-siwc-catalog-content-source/hub/source/data.bzl').is_file())
        self.assertFalse((fixture.run / 'bazel-user-root').exists())

    def test_bare_extra_reversed_and_historical_vectors_never_gain_retention(self):
        for targets in ([NEW_PRODUCER], COHORT + ['//:docs_check'], list(reversed(COHORT)),
                ['//tools:codex_native_siwc_catalog_source_test', NEW_PRODUCER]):
            fixture, unused = self.retention(); fixture.receipt['targets'] = targets; fixture.save_receipt()
            report = fixture.retire(); self.assertEqual(report['retained_output_contract'], [])
            self.assertFalse(fixture.output.exists())

    def test_failed_or_missing_product_never_gains_retention(self):
        for fault in ('failure', 'missing'):
            fixture, directory = self.retention()
            if fault == 'failure': fixture.receipt['workload_exit'] = 1; fixture.save_receipt()
            else: (directory / 'native-siwc-catalog-content-source/source-receipt.json').unlink()
            report = fixture.retire(); self.assertEqual(report['retained_output_contract'], [])
            self.assertFalse(fixture.output.exists())

    def test_retained_root_replacement_refuses_without_promoting_copy(self):
        fixture, unused = self.retention(); fixture.retire()
        fixture.output.rename(fixture.run / 'original-output'); fixture.output.mkdir()
        (fixture.output / 'foreign').write_bytes(b'foreign')
        self.assertEqual(fixture.retire()['state'], 'refused')
        self.assertEqual((fixture.output / 'foreign').read_bytes(), b'foreign')

    def driver_retention(self, *, content=False):
        fixture = retirement.RunRetirementFilesystemModels('test_exact_reserved_file_writer_vector_holds_its_source_root')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        label = '//tools:codex_native_siwc_catalog_models_producer'
        directory = fixture.producer(label)
        fixture.receipt['targets'] = ['//tools:codex_native_siwc_catalog_models_test', label]
        fixture.save_receipt()
        if content:
            (directory / 'native-siwc-catalog-source/source-receipt.json').unlink()
            (directory / 'native-siwc-catalog-source').rmdir()
            path = directory / 'native-siwc-catalog-content-source/source-receipt.json'
            path.parent.mkdir(); path.write_bytes(b'original content source product')
        return fixture, directory

    def test_old_driver_product_tuple_remains_original_retention_contract(self):
        fixture, directory = self.driver_retention(); original = fixture.output.stat()
        report = fixture.retire()
        self.assertEqual(report['children']['output-base'], 'retained-declared-producer')
        self.assertEqual(report['retained_physical_root'], {'device':original.st_dev, 'inode':original.st_ino})
        self.assertTrue((directory / 'native-siwc-catalog-source/source-receipt.json').is_file())
        self.assertFalse((directory / 'native-siwc-catalog-content-source').exists())

    def test_new_driver_exact_tuple_retains_original_models_and_content_leaf(self):
        fixture, directory = self.driver_retention(content=True); original = fixture.output.stat()
        report = fixture.retire()
        self.assertEqual(report['children']['output-base'], 'retained-declared-producer')
        self.assertEqual(report['retained_physical_root'], {'device':original.st_dev, 'inode':original.st_ino})
        self.assertEqual((directory / 'native-siwc-catalog-content-source/source-receipt.json').read_bytes(), b'original content source product')
        self.assertTrue((directory / 'native-siwc-catalog-models/models-receipt.json').is_file())
        self.assertFalse((directory / 'native-siwc-catalog-source').exists())

    def test_driver_both_mixed_partial_missing_and_redirected_sets_refuse_retention(self):
        for fault in ('both','common-missing','source-missing','mixed-empty','redirected','late-mixed','late-common-missing','late-common-replaced'):
            fixture, directory = self.driver_retention(content=True)
            if fault == 'both':
                other = directory / 'native-siwc-catalog-source'; other.mkdir()
                (other / 'source-receipt.json').write_bytes(b'old-family foreign product')
            elif fault == 'common-missing':
                (directory / 'native-siwc-catalog-models/models-receipt.json').unlink()
            elif fault == 'source-missing':
                (directory / 'native-siwc-catalog-content-source/source-receipt.json').unlink()
            elif fault == 'mixed-empty': (directory / 'native-siwc-catalog-source').mkdir()
            elif fault == 'redirected':
                selected = directory / 'native-siwc-catalog-content-source'
                outside = fixture.state / 'foreign-source'; selected.rename(outside)
                selected.symlink_to(outside, target_is_directory=True)
            baseline = set(os.listdir('/proc/self/fd'))
            if fault in ('late-mixed','late-common-missing','late-common-replaced'):
                selected = directory / 'native-siwc-catalog-content-source/source-receipt.json'
                identity = (selected.stat().st_dev, selected.stat().st_ino)
                original = fixture.guard.os.fsync
                injected = []
                def fsync(fd):
                    result = original(fd)
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) == identity and not injected:
                        if fault == 'late-mixed': (directory / 'native-siwc-catalog-source').mkdir()
                        else:
                            common = directory / 'native-siwc-catalog-models/models-receipt.json'
                            if fault == 'late-common-missing': common.unlink()
                            else:
                                replacement = common.parent / 'replacement'
                                replacement.write_bytes(common.read_bytes())
                                replacement.replace(common)
                        injected.append(True)
                    return result
                with retirement.patch.object(fixture.guard.os, 'fsync', side_effect=fsync):
                    report = fixture.retire()
                self.assertEqual(injected, [True])
            else: report = fixture.retire()
            self.assertEqual(set(os.listdir('/proc/self/fd')), baseline)
            self.assertNotEqual(report['children'].get('output-base'), 'retained-declared-producer')
            if fault == 'redirected':
                self.assertEqual((outside / 'source-receipt.json').read_bytes(), b'original content source product')
            else:
                self.assertEqual(report['retained_output_contract'], [])
                self.assertFalse(fixture.output.exists())


if __name__ == '__main__': unittest.main()
