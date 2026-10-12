"""Literal catalog delta/composition predicates; genuine native twenty remain unrun."""
import copy
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import codex_native_siwc_catalog_source as model
source = model.source
ROOT = Path(__file__).parent.parent
BASE = ROOT / model.BASE
OLD = ROOT / model.previous.BASE
GRAPH = {'MODULE.bazel':'graph-preimages/MODULE.bazel',
    'codex-rs/Cargo.lock':'graph-preimages/codex-rs/Cargo.lock',
    'codex-rs/Cargo.toml':'graph-preimages/codex-rs/Cargo.toml',
    'codex-rs/core/BUILD.bazel':'graph-preimages/codex-rs/core/BUILD.bazel.preimage',
    'codex-rs/core/Cargo.toml':'graph-preimages/codex-rs/core/Cargo.toml',
    'defs.bzl':'graph-preimages/defs.bzl'}


class CatalogSourceTests(unittest.TestCase):
    def setUp(self):
        self.deadline = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
        self.control = model.controls()[1]
        self.raw = model.model_patch(self.control)
        self.before = {name: ('100644', (BASE / 'preimages' / name).read_bytes()) for name in model.PATHS - model.NEW}
        self.before.update({name: ('100644', (OLD / physical).read_bytes()) for name, physical in GRAPH.items()})
        self.before['unrelated'] = ('100644', b'public unchanged fixture\n')
    def tearDown(self): source.DEADLINE = self.deadline

    def test_exact_twelve_existing_two_new_and_unchanged_complete_graph(self):
        after = model.transform(self.before, self.raw, self.control)
        self.assertEqual(set(after), set(self.before) | model.NEW)
        self.assertEqual({name for name in self.before if after[name] != self.before[name]}, model.PATHS - model.NEW)
        for name in model.PATHS:
            self.assertEqual(source.sha(after[name][1]), self.control['delta']['paths'][name]['after']['sha256'])
        for name in set(GRAPH) | {'unrelated'}: self.assertEqual(after[name], self.before[name])

    def test_actual_v4_then_catalog_composition_requires_every_exact_intermediate(self):
        v4_control = model.previous.controls()[1]
        n10 = dict(self.before)
        for name in model.previous.PATHS - model.previous.NEW:
            n10[name] = ('100644', (OLD / 'preimages' / name).read_bytes())
        result = model.compose(n10, model.previous.model_patch(v4_control), v4_control)
        self.assertEqual(result, model.transform(self.before, self.raw, self.control) | {
            name: result[name] for name in model.previous.NEW})
        for name in model.PATHS - model.NEW:
            broken = dict(self.before); broken[name] = ('100644', self.before[name][1] + b'changed')
            with self.assertRaises(ValueError): model.transform(broken, self.raw, self.control)
        for name in model.NEW:
            with self.assertRaises(ValueError): model.transform({**self.before, name: ('100644', b'occupied')}, self.raw, self.control)

    def test_rehashed_unknown_duplicate_and_context_drift_refuse(self):
        for raw in (self.raw + self.raw,
                self.raw.replace(b'+++ b/codex-rs/core/src/lib.rs', b'+++ b/codex-rs/core/src/unqualified.rs', 1),
                self.raw.replace(b'     mod tests;', b'     mod unqualified;', 1) + b'unknown trailer\n'):
            control = copy.deepcopy(self.control)
            control['delta']['patch'].update(sha256=source.sha(raw), bytes=len(raw))
            with self.assertRaises(ValueError): model.transform(self.before, raw, control)

    def test_extra_members_modes_graph_and_unrelated_changes_refuse(self):
        after = model.transform(self.before, self.raw, self.control)
        variants = [{**after, 'extra': ('100644', b'extra')}, {**after, 'unrelated': ('100644', b'changed')}]
        variants += [{**after, name: ('100644', b'changed')} for name in model.PATHS | set(GRAPH)]
        variants += [{**after, name: ('100755', after[name][1])} for name in model.PATHS]
        for value in variants:
            with self.assertRaises(ValueError): model.validate_transition(self.before, value, self.control)

    def test_report_preserves_n10_v4_lineage_and_twenty_real_normal_target_names(self):
        config = model.previous.configuration()[1]
        original = {'kind':model.tenth.KIND, 'status':'verified-tenth-file-writer-source-uncompiled',
            'inventory_sha256':config['parent']['inventory_sha256'], 'patch_sha256':['a'*64]*10,
            'patches':[{'patch_sha256':'a'*64,'paths':[]}]*10, 'graph_files':{},
            **{flag:False for flag in model.tenth.FLAGS}}
        after = model.transform(self.before, self.raw, self.control)
        report = model.make_report(original, after, model.previous.controls()[1], config)
        self.assertEqual(report['kind'], model.KIND)
        self.assertEqual(report['patch_sha256'][:-2], original['patch_sha256'])
        self.assertEqual(report['patch_sha256'][-2], model.previous.controls()[1]['delta']['patch']['sha256'])
        self.assertEqual(report['patch_sha256'][-1], source.sha(self.raw))
        expected = report['native_test_contract']
        names = expected['core_unit_tests'] + expected['tui_unit_tests'] + expected['app_server_unit_tests']
        self.assertEqual(len(names), len(set(names))); self.assertEqual(len(names), 20)
        self.assertEqual(len(report['native_v4_test_contract']['expected']), 15)
        self.assertEqual(report['inventory_sha256'], source.sha(source.canonical(report['source_inventory'])))
        self.assertTrue(all(report[name] is False for name in model.previous.FALSE_FLAGS))
        self.assertIsNone(report['generated_hub'])

    def test_additive_entry_uses_existing_owner_lifecycle_and_retains_both_controls(self):
        with patch.object(model.previous, 'main') as run:
            model.main()
        self.assertIs(run.call_args.kwargs['_producer'], model.produce)
        self.assertIs(run.call_args.kwargs['_retainer'], model.retain_controls)
        self.assertEqual(run.call_args.kwargs['_output'], 'native-siwc-catalog-source')
        captured = []
        class Owner:
            def add(self, path, digest, maximum): captured.append((str(path), digest, maximum))
        with patch.object(model.previous, 'retain_model_controls', return_value=('old-config','old-control')):
            self.assertEqual(model.retain_controls(Owner()), ('old-config','old-control'))
        self.assertEqual(len(captured), 4)
        self.assertEqual(captured[0][1], model.CONTROL_SHA)
        self.assertEqual({row[1] for row in captured[1:]}, {self.control['delta'][name]['sha256'] for name in ('patch','manifest')} | {self.control['tests']['sha256']})

    def test_real_declared_inputs_and_inert_fixture_graph_have_no_native_package_boundary(self):
        package = (BASE / 'BUILD.bazel').read_text()
        macro = (ROOT / 'tools/codex_native_siwc_catalog_source_targets.bzl').read_text()
        for name in model.PATHS - model.NEW: self.assertIn('preimages/' + name, package)
        self.assertFalse(any(path.name in ('BUILD','BUILD.bazel') for path in (BASE / 'preimages').rglob('*')))
        self.assertIn('//integrations/codex-upstream/siwc-native-catalog:BUILD.bazel', macro)
        for repo in ('omux_original_native_sdk_inputs','omux_native_file_writer_model_source_inputs',
                'omux_native_sdk_carrier_inputs','omux_native_sdk_carrier_proof_inputs','omux_protocol_history_query_tools'):
            self.assertIn('@' + repo + '//:inputs', macro)
        self.assertIn('"manual", "no-remote", "no-cache"', macro)
        self.assertNotIn('test_arg', macro)


if __name__ == '__main__': unittest.main()
