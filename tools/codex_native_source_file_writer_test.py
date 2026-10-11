"""Actual exact-patch and owned-output IO models; parent proof is an explicit seam."""
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_source_file_writer as family

source = family.source
ROOT = Path(__file__).parent.parent


def cleanup(path):
    for directory, dirs, files in os.walk(path, followlinks=False):
        os.chmod(directory, 0o700)
        for name in files:
            leaf = Path(directory) / name
            if not leaf.is_symlink():
                os.chmod(leaf, 0o600)
    shutil.rmtree(path)


class FileWriterSourceModels(unittest.TestCase):
    def setUp(self):
        self.saved_deadline = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
        self.raw_config, self.config = family.load_config()
        self.raw_patch = family.read_patch(self.config)
        self.files = {}
        for name in family.PATHS - {family.NEW}:
            self.files[name] = ('100644', (ROOT / 'integrations/codex-upstream/file-writer-preimages' / name).read_bytes())
        self.files['unrelated.txt'] = ('100644', b'public unchanged fixture\n')

    def tearDown(self):
        source.DEADLINE = self.saved_deadline

    def report(self):
        return {'kind': family.parent.ninth.KIND,
                'inventory_sha256': self.config['parent']['inventory_sha256'],
                'patch_sha256': list(self.config['parent']['patch_sha256']),
                'patches': [{'patch_sha256': pin, 'paths': []} for pin in self.config['parent']['patch_sha256']],
                'graph_files': {'codex-rs/Cargo.lock': {'sha256': source.sha(self.files['codex-rs/Cargo.lock'][1])}},
                **{name: False for name in family.parent.ninth.FLAGS}}

    def test_real_six_file_patch_preserves_unrelated_and_old_nine_prefix(self):
        result = family.transform(self.files, self.raw_patch, self.config)
        self.assertEqual(set(result), set(self.files) | {family.NEW})
        self.assertEqual(result['unrelated.txt'], self.files['unrelated.txt'])
        for name, row in self.config['storage']['paths'].items():
            self.assertEqual(source.sha(result[name][1]), row['after']['sha256'])
        for metadata in (False, True):
            receipt = family.receipt(self.report(), result, self.config, metadata_only=metadata)
            self.assertEqual(receipt['patch_sha256'][:-1], self.config['parent']['patch_sha256'])
            self.assertEqual(receipt['patch_sha256'][-1], self.config['storage']['patch_sha256'])
            self.assertTrue(all(receipt[name] is False for name in family.FLAGS))
            self.assertEqual('source_inventory' in receipt, not metadata)
            self.assertEqual(receipt['source_materialized'], not metadata)

    def test_missing_wrong_mode_wrong_predecessor_existing_new_refuse(self):
        for name, row in self.files.items():
            if name not in family.PATHS:
                continue
            for bad in ({key: value for key, value in self.files.items() if key != name},
                        {**self.files, name: ('100755', row[1])},
                        {**self.files, name: ('100644', row[1] + b'changed')}):
                with self.assertRaises(ValueError):
                    family.transform(bad, self.raw_patch, self.config)
        with self.assertRaises(ValueError):
            family.transform({**self.files, family.NEW: ('100644', b'exists')}, self.raw_patch, self.config)

    def test_rehashed_duplicate_hunk_wrong_position_and_mode_refuse(self):
        split = self.raw_patch.index(b'diff --git ', 1)
        start = self.raw_patch.index(b'@@ -')
        end = self.raw_patch.index(b'\n', start)
        variants = (self.raw_patch + self.raw_patch[:split],
                    self.raw_patch[:start] + self.raw_patch[start:end].replace(b'+', b'+999', 1) + self.raw_patch[end:],
                    self.raw_patch.replace(b'new file mode 100644', b'new file mode 100755', 1))
        for raw in variants:
            self.assertNotEqual(raw, self.raw_patch)
            config = copy.deepcopy(self.config)
            config['storage']['patch_sha256'] = source.sha(raw)
            config['storage']['patch_bytes'] = len(raw)
            with self.assertRaises(ValueError):
                family.transform(self.files, raw, config)

    def test_changed_after_pin_unrelated_edit_and_extra_member_refuse(self):
        after = family.transform(self.files, self.raw_patch, self.config)
        for bad in ({**after, 'unrelated.txt': ('100644', b'changed')},
                    {**after, 'extra': ('100644', b'extra')},
                    {**after, family.NEW: ('100755', after[family.NEW][1])}):
            with self.assertRaises(ValueError):
                family.validate_transition(self.files, bad, self.config)
        config = copy.deepcopy(self.config)
        config['storage']['paths'][family.NEW]['after']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            family.transform(self.files, self.raw_patch, config)

    def test_old_lineage_and_future_flag_refuse_metadata(self):
        after = family.transform(self.files, self.raw_patch, self.config)
        for field, bad in (('patch_sha256', ['0' * 64] * 9),
                           ('inventory_sha256', '0' * 64),
                           ('native_support', True)):
            report = self.report()
            report[field] = bad
            with self.assertRaises(ValueError):
                family.receipt(report, after, self.config, metadata_only=True)

    def test_real_tree_witness_content_replacement_namespace_and_link_refuse(self):
        files = {'nested/a': ('100644', b'public fixture'), 'link': ('120000', b'nested/a')}
        for fault in ('content', 'replacement', 'extra', 'root', 'link'):
            temporary = Path(tempfile.mkdtemp())
            held = None
            try:
                out = temporary / 'out'
                fd = source.write_source(out, files)
                os.close(fd)
                held = family.TreeWitness(out / 'source', files)
                target = out / 'source/nested/a'
                if fault == 'content':
                    target.chmod(0o600); target.write_bytes(b'public changed'); target.chmod(0o555)
                elif fault == 'replacement':
                    target.parent.chmod(0o700)
                    target.rename(target.with_name('old'))
                    target.write_bytes(b'public fixture'); target.chmod(0o555)
                    target.with_name('old').unlink(); target.parent.chmod(0o555)
                elif fault == 'extra':
                    (out / 'source').chmod(0o700)
                    (out / 'source/extra').write_bytes(b'extra')
                    (out / 'source').chmod(0o555)
                elif fault == 'root':
                    (out / 'source').rename(out / 'old')
                    (out / 'source').mkdir(mode=0o555)
                else:
                    (out / 'source').chmod(0o700)
                    (out / 'source/link').unlink()
                    (out / 'source/link').symlink_to('nested/missing')
                    (out / 'source').chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    held.check()
            finally:
                if held is not None:
                    held.close()
                    self.assertIsNone(held.fd)
                cleanup(temporary)

    def run_producer(self, temporary, *, metadata_only=False, at_finish=None, at_captured_check=None, clock_state=None):
        result = family.transform(self.files, self.raw_patch, self.config)
        original = time.monotonic_ns() + 120 * 1_000_000_000
        cutoff = original / 1_000_000_000
        if clock_state is not None:
            clock_state['cutoff'], clock_state['original_ns'] = cutoff, original
        outer = self
        snapshots = []
        if at_captured_check:
            parent_root = temporary / 'parent'
            fd = source.write_source(parent_root, self.files)
            os.close(fd)
            class Captured:
                root = parent_root
                files = outer.files
                def check(self):
                    at_captured_check()
            snapshots.append(('ninth', Captured()))
        class Proof:
            # Deliberate parent qualification seam: no fake actual N9 success.
            source_files = outer.files
            source_report = outer.report()
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                return None
            def finish(self):
                if at_finish:
                    at_finish()
        Proof.snapshots = snapshots
        selected = {'source': self.config['parent']}
        with patch.object(family, 'admission', return_value=(cutoff, original)), \
                patch.object(family.parent, 'config', return_value=selected), \
                patch.object(family.parent, 'SourceProofSession', Proof):
            receipt = family.produce(temporary / 'out', metadata_only=metadata_only)
        return receipt, result

    def test_actual_owned_source_and_metadata_publication_readbacks(self):
        for metadata in (False, True):
            temporary = Path(tempfile.mkdtemp())
            try:
                receipt, result = self.run_producer(temporary, metadata_only=metadata)
                self.assertEqual((temporary / 'out/source-receipt.json').read_bytes(), source.encoded(receipt))
                self.assertEqual((temporary / 'out').stat().st_mode & 0o777, 0o555)
                self.assertEqual((temporary / 'out/source').exists(), not metadata)
                if not metadata:
                    source.verify_written(temporary / 'out/source', result)
                self.assertIsNone(source.DEADLINE)
            finally:
                cleanup(temporary)
                source.DEADLINE = time.monotonic() + 120

    def test_parent_finish_late_leaf_and_receipt_replacement_never_seal_output(self):
        for fault in ('leaf', 'leaf-replacement', 'receipt'):
            temporary = Path(tempfile.mkdtemp())
            try:
                def mutate():
                    leaf = temporary / ('out/source-receipt.json' if fault == 'receipt' else 'out/source/unrelated.txt')
                    leaf.parent.chmod(0o700)
                    if fault == 'leaf-replacement':
                        leaf.rename(leaf.with_name('old'))
                        leaf.write_bytes(b'public unchanged fixture\n'); leaf.with_name('old').unlink()
                    else:
                        leaf.chmod(0o600); leaf.write_bytes(b'public changed fixture\n')
                    leaf.chmod(0o444 if fault == 'receipt' else 0o555)
                    leaf.parent.chmod(0o700 if fault == 'receipt' else 0o555)
                with self.assertRaises((ValueError, OSError)):
                    self.run_producer(temporary, at_finish=mutate)
                self.assertEqual((temporary / 'out').stat().st_mode & 0o777, 0o700)
                self.assertIsNone(source.DEADLINE)
            finally:
                cleanup(temporary)
                source.DEADLINE = time.monotonic() + 120

    def test_original_cutoff_refusal_does_not_seal_or_replace_parent(self):
        temporary = Path(tempfile.mkdtemp())
        try:
            def expire():
                source.DEADLINE = time.monotonic() - 1
            with self.assertRaises(ValueError):
                self.run_producer(temporary, at_finish=expire)
            self.assertEqual((temporary / 'out').stat().st_mode & 0o777, 0o700)
            self.assertIsNone(source.DEADLINE)
        finally:
            cleanup(temporary)

    def test_last_retained_source_check_content_and_identical_replacement_refuse(self):
        for replacement in (False, True):
            temporary = Path(tempfile.mkdtemp())
            try:
                def mutate():
                    leaf = temporary / 'out/source/unrelated.txt'
                    if replacement:
                        leaf.parent.chmod(0o700)
                        leaf.rename(leaf.with_name('old'))
                        leaf.write_bytes(b'public unchanged fixture\n')
                        leaf.with_name('old').unlink()
                        leaf.parent.chmod(0o555)
                    else:
                        leaf.chmod(0o600)
                        leaf.write_bytes(b'public MUTATION! fixture\n')
                    leaf.chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    self.run_producer(temporary, at_captured_check=mutate)
                self.assertIsNone(source.DEADLINE)
            finally:
                cleanup(temporary)
                source.DEADLINE = time.monotonic() + 120

    def test_final_sealing_and_output_close_expiry_never_returns_success(self):
        real_chmod, real_close = os.fchmod, os.close
        real_float, real_integer = time.monotonic, time.monotonic_ns
        for seam, clock in (('seal', 'both'), ('close', 'both'), ('close', 'integer')):
            temporary = Path(tempfile.mkdtemp())
            state = {'root_fd': None, 'root_closed': False, 'expired': False}
            try:
                def chmod(fd, mode):
                    real_chmod(fd, mode)
                    if mode == 0o555 and Path('/proc/self/fd/' + str(fd)).resolve() == temporary / 'out':
                        state['root_fd'] = fd
                        if seam == 'seal':
                            state['expired'] = True
                def close(fd):
                    is_output = fd == state['root_fd']
                    real_close(fd)
                    if is_output:
                        state['root_closed'] = True
                        if seam == 'close':
                            state['expired'] = True
                def float_now():
                    return state['cutoff'] + 1 if state['expired'] and clock == 'both' else real_float()
                def integer_now():
                    return state['original_ns'] + 1 if state['expired'] else real_integer()
                with patch.object(os, 'fchmod', side_effect=chmod), patch.object(os, 'close', side_effect=close), \
                        patch.object(time, 'monotonic', side_effect=float_now), patch.object(time, 'monotonic_ns', side_effect=integer_now):
                    with self.assertRaises(ValueError):
                        self.run_producer(temporary, clock_state=state)
                self.assertTrue(state['expired'] and state['root_closed'])
                self.assertIsNone(source.DEADLINE)
                # Readonly diagnostic artifacts cannot substitute for a return/guardian success.
                self.assertEqual((temporary / 'out').stat().st_mode & 0o777, 0o555)
            finally:
                cleanup(temporary)
                source.DEADLINE = time.monotonic() + 120

    def test_last_retained_source_check_same_byte_receipt_mutation_refuses_both_outputs(self):
        for metadata in (False, True):
            temporary = Path(tempfile.mkdtemp())
            try:
                def mutate():
                    leaf = temporary / 'out/source-receipt.json'
                    raw = leaf.read_bytes()
                    leaf.chmod(0o600)
                    leaf.write_bytes(raw)
                    leaf.chmod(0o444)
                with self.assertRaises((ValueError, OSError)):
                    self.run_producer(temporary, metadata_only=metadata, at_captured_check=mutate)
                self.assertIsNone(source.DEADLINE)
            finally:
                cleanup(temporary)
                source.DEADLINE = time.monotonic() + 120

    def test_cleanup_error_attempts_remaining_owned_descriptor_closes_and_refuses(self):
        temporary = Path(tempfile.mkdtemp())
        real_close = os.close
        state = {'injected': False, 'later_closes': 0}
        try:
            def close(fd):
                target = str(Path('/proc/self/fd/' + str(fd)).resolve())
                real_close(fd)
                if state['injected']:
                    state['later_closes'] += 1
                elif target == str(temporary / 'out') and family.PHASE == 'terminal':
                    state['injected'] = True
                    raise OSError('synthetic terminal close refusal')
            with patch.object(os, 'close', side_effect=close), self.assertRaises(OSError):
                self.run_producer(temporary)
            self.assertTrue(state['injected'])
            self.assertGreaterEqual(state['later_closes'], 2)
            self.assertIsNone(source.DEADLINE)
        finally:
            cleanup(temporary)
            source.DEADLINE = time.monotonic() + 120

    def test_declarations_keep_models_local_and_old_source_groups_unchanged(self):
        raw = (ROOT / 'tools/codex_native_source_file_writer_targets.bzl').read_text()
        self.assertIn('native_acquisition_source_closure(source_sources, sdk_sources)', raw)
        self.assertIn('@omux_native_carrier_source_inputs//:inputs', raw)
        self.assertIn('native_file_writer_preimages', raw)
        self.assertIn('data = controls +', raw)
        self.assertNotIn('@omux_native_sdk_carrier_inputs', raw)
        self.assertNotIn('@omux_protocol_history_query_tools', raw)
        self.assertIn('OMUX_NATIVE_FILE_WRITER_SOURCE_DEADLINE_NS', raw)
        build = (ROOT / 'tools/BUILD.bazel').read_text()
        self.assertIn('native_file_writer_source_targets(', build)
        self.assertIn('name = "codex_native_source_acquisition_source_producer"', build)
        self.assertIn('name = "codex_native_source_acquisition_source_test"', build)
        upstream = (ROOT / 'integrations/codex-upstream/BUILD.bazel').read_text()
        self.assertIn('file-writer-boundary/native-source-file-writer-boundary-v1.json', upstream)
        self.assertIn('file-writer-boundary/native-file-writer-storage-v3.patch', upstream)
        self.assertNotIn('srcs = ["native-file-writer-storage-v3.patch"]', upstream)
        self.assertIn('filegroup(name = "source_receipt_inputs", srcs = glob(["*.py", "*.bzl", "*.bazel", "*.patch"]', upstream)
        self.assertIn('filegroup(name = "public_sources", srcs = glob(["*.py", "*.bazel", "*.md", "*.json", "*.patch", "*.tar.gz"]', upstream)
        # These original nonrecursive globs cannot acquire any new direct child.
        for control in (family.CONFIG, family.PATCH, 'integrations/codex-upstream/file-writer-boundary/native-file-writer-storage-v3-manifest.json'):
            self.assertTrue(control.startswith('integrations/codex-upstream/file-writer-boundary/'))
            self.assertGreater(len(control.removeprefix('integrations/codex-upstream/').split('/')), 1)

    def test_count_and_depth_refuse_before_any_source_open(self):
        for field, limit in (('MAX_ROWS', 1), ('MAX_DEPTH', 1)):
            with patch.object(family, field, limit), patch.object(source, 'directory') as opened:
                with self.assertRaises(ValueError):
                    family.TreeWitness(Path('/fixture/no-open'), {'one/a': ('100644', b'a'), 'one/b': ('100644', b'b')})
                opened.assert_not_called()

    def test_exact_original_source_admission_never_renews_clock(self):
        source.DEADLINE = None
        entry = time.monotonic_ns() - 1_000_000
        deadline = entry + 1200 * 1_000_000_000
        env = {'OMUX_NATIVE_FILE_WRITER_SOURCE_MODE': 'native-file-writer-source-reserved',
               'OMUX_NATIVE_FILE_WRITER_SOURCE_ENTRY_NS': str(entry),
               'OMUX_NATIVE_FILE_WRITER_SOURCE_DEADLINE_NS': str(deadline),
               'TEST_TIMEOUT': '900', 'TEST_UNDECLARED_OUTPUTS_DIR': '/fixture/declared'}
        with patch.dict(os.environ, env, clear=True):
            cutoff, retained = family.admission()
            self.assertEqual(retained, deadline)
            self.assertLessEqual(cutoff, deadline / 1_000_000_000)
            self.assertIsNone(source.DEADLINE)
        for bad in ({**env, 'OMUX_NATIVE_FILE_WRITER_SOURCE_MODE': 'old-ninth-mode'},
                    {**env, 'OMUX_NATIVE_FILE_WRITER_SOURCE_DEADLINE_NS': str(deadline + 1)},
                    {**env, 'OMUX_NATIVE_FILE_WRITER_SOURCE_ENTRY_NS': str(deadline)},
                    {**env, 'TEST_TIMEOUT': '60'}):
            with patch.dict(os.environ, bad, clear=True), self.assertRaises(ValueError):
                family.admission()
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            family.admission()


if __name__ == '__main__':
    unittest.main()
