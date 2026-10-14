"""Actual pinned five-file source delta/model contract; no compiler or provider proof."""
import copy
from pathlib import Path
import time
import unittest
import codex_native_siwc_source as model
source = model.source
ROOT = Path(__file__).parent.parent
BASE = ROOT / 'integrations/codex-upstream/siwc-native'
GRAPH_PREIMAGES = {'MODULE.bazel': 'graph-preimages/MODULE.bazel', 'codex-rs/Cargo.lock': 'graph-preimages/codex-rs/Cargo.lock', 'codex-rs/Cargo.toml': 'graph-preimages/codex-rs/Cargo.toml', 'codex-rs/core/BUILD.bazel': 'graph-preimages/codex-rs/core/BUILD.bazel.preimage', 'codex-rs/core/Cargo.toml': 'graph-preimages/codex-rs/core/Cargo.toml', 'defs.bzl': 'graph-preimages/defs.bzl'}

class SIWCSourceTests(unittest.TestCase):
    def setUp(self):
        self.old = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
        self.raw_control, self.control = model.controls()
        self.raw_patch = model.model_patch(self.control)
        self.before = {name: ('100644', (BASE / 'preimages' / name).read_bytes()) for name in model.PATHS - model.NEW}
        self.before.update({name: ('100644', (BASE / physical).read_bytes()) for name, physical in GRAPH_PREIMAGES.items()})
        self.before['unrelated'] = ('100644', b'unchanged public source fixture\n')
    def tearDown(self): source.DEADLINE = self.old

    def test_exact_reviewed_three_edits_and_two_additions_keep_complete_graph(self):
        after = model.transform(self.before, self.raw_patch, self.control)
        self.assertEqual(set(after), set(self.before) | model.NEW)
        self.assertEqual({name for name in self.before if after[name] != self.before[name]}, model.PATHS - model.NEW)
        for name in GRAPH_PREIMAGES: self.assertEqual(after[name], self.before[name])
        for name in model.PATHS:
            self.assertEqual(source.sha(after[name][1]), self.control['delta']['paths'][name]['after']['sha256'])
        self.assertEqual(after['unrelated'], self.before['unrelated'])

    def test_original_bytes_modes_missing_files_and_existing_additions_refuse(self):
        for name in model.PATHS - model.NEW:
            for before in ({n:r for n,r in self.before.items() if n != name},
                    {**self.before, name: ('100755', self.before[name][1])},
                    {**self.before, name: ('100644', self.before[name][1] + b'changed')}):
                with self.assertRaises(ValueError): model.transform(before, self.raw_patch, self.control)
        for name in model.NEW:
            with self.assertRaises(ValueError): model.transform({**self.before, name: ('100644', b'preexisting')}, self.raw_patch, self.control)

    def test_rehashed_unknown_duplicate_and_bad_hunk_ranges_refuse(self):
        at = self.raw_patch.index(b'@@ -'); end = self.raw_patch.index(b'\n', at)
        for raw in (self.raw_patch + self.raw_patch,
                    self.raw_patch.replace(b'+++ b/codex-rs/core/src/lib.rs', b'+++ b/codex-rs/core/src/unqualified.rs', 1),
                    self.raw_patch[:at] + self.raw_patch[at:end].replace(b'+', b'+999', 1) + self.raw_patch[end:]):
            control = copy.deepcopy(self.control)
            control['delta']['patch'].update(sha256=source.sha(raw), bytes=len(raw))
            with self.assertRaises(ValueError): model.transform(self.before, raw, control)

    def test_extra_members_unrelated_edits_wrong_afterimages_and_graph_drift_refuse(self):
        after = model.transform(self.before, self.raw_patch, self.control)
        variants = [{**after, 'unqualified': ('100644', b'extra')}, {**after, 'unrelated': ('100644', b'changed')}]
        variants += [{**after, name: ('100644', b'changed')} for name in model.PATHS | set(GRAPH_PREIMAGES)]
        for files in variants:
            with self.assertRaises(ValueError): model.validate_transition(self.before, files, self.control)

    def test_report_preserves_ten_parent_patches_and_all_qualification_flags_false(self):
        config = model.configuration()[1]
        original = {'kind':model.tenth.KIND, 'status':'verified-tenth-file-writer-source-uncompiled',
            'inventory_sha256':config['parent']['inventory_sha256'], 'patch_sha256':['a'*64]*10,
            'patches':[{'patch_sha256':'a'*64,'paths':[]}]*10, 'graph_files':{},
            **{flag:False for flag in model.tenth.FLAGS}}
        after = model.transform(self.before, self.raw_patch, self.control)
        report = model.make_report(original, after, self.control, config)
        self.assertEqual(report['patch_sha256'][:-1], original['patch_sha256'])
        self.assertEqual(report['patch_sha256'][-1], source.sha(self.raw_patch))
        self.assertEqual(report['native_test_contract']['expected'], sorted(report['native_test_contract']['expected']))
        self.assertEqual(len(report['native_test_contract']['expected']), 15)
        self.assertEqual(report['tracked_files'], len(after))
        self.assertEqual(report['inventory_sha256'], source.sha(source.canonical(report['source_inventory'])))
        self.assertTrue(all(report[flag] is False for flag in model.FALSE_FLAGS))
        self.assertIsNone(report['generated_hub'])
        original['patch_sha256'] = original['patch_sha256'][:-1]
        with self.assertRaises(ValueError): model.make_report(original, after, self.control, config)

    def test_declared_graph_controls_preimages_and_default_native_targets_are_explicit(self):
        package = (BASE / 'BUILD.bazel').read_text()
        macro = (ROOT / 'tools/codex_native_siwc_source_targets.bzl').read_text()
        snippets = (ROOT / 'tools/codex_native_siwc_source_BUILD.snippet').read_text()
        self.assertIn('native_preimages', package)
        self.assertIn('//tools:__pkg__', package)
        for path in GRAPH_PREIMAGES.values(): self.assertIn(path, package)
        self.assertFalse(any(path.name in ('BUILD', 'BUILD.bazel') for path in (BASE / 'graph-preimages').rglob('*')))
        self.assertIn('//integrations/codex-upstream/siwc-native:BUILD.bazel', macro)
        self.assertIn('codex_native_siwc_source_targets(', snippets)
        self.assertEqual(self.control['native_build_graph']['codex-rs/core/BUILD.bazel']['sha256'], source.sha(self.before['codex-rs/core/BUILD.bazel'][1]))
        expected = model.decode(model.parent.pinned_artifact(self.control['tests']))
        self.assertEqual(expected['target'], '//codex-rs/core:core-unit-tests')
        self.assertEqual(expected['default_regression_target'], expected['target'])
        self.assertEqual(expected['default_build_target'], '//codex-rs/core:core')
        self.assertEqual(len(expected['expected']), len(set(expected['expected'])))

if __name__ == '__main__': unittest.main()
