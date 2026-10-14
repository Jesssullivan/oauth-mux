"""Pure bounded-copy fixtures; no Bazel subprocess or host-manager calls."""
import json
import contextlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import guard_test_evidence as evidence_capture
from guard_test_evidence import capture, label_path


class EvidenceTest(unittest.TestCase):
    def source_fixture(self, root, label='runtime_source_receipt'):
        base, run = root / 'base', root / 'run'
        base.mkdir(mode=0o700)
        run.mkdir(mode=0o700)
        log = base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools' / label
        output = log / 'test.outputs/runtime-source-receipt'
        output.mkdir(parents=True)
        start = time.time_ns()
        for name, content in (('receipt.json', b'{"claim":"source_inventory_only"}\n'),
                              ('source-inventory.json', b'{"files":[],"aggregate_sha256":"fixture"}\n')):
            path = output / name
            path.write_bytes(content)
            os.utime(path, ns=(start + 1, start + 1))
        return base, run, log, output, start

    def test_source_metadata_survives_cache_overwrite_without_copying_other_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base, run, log, output, start = self.source_fixture(Path(directory))
            (output / 'undeclared.json').write_bytes(b'not selected')
            (log / 'test.outputs/runtime-state').mkdir()
            (log / 'test.outputs/runtime-state/private').write_bytes(b'not selected')
            expected = {name: (output / name).read_bytes() for name in ('receipt.json', 'source-inventory.json')}
            manifest = capture(base, run, ['//tools:runtime_source_receipt'], 3, start)
            copied = [row for row in manifest['results'][0]['files'] if row['state'] == 'copied']
            self.assertEqual({row['source'] for row in copied}, set(evidence_capture.SOURCE_RECEIPT_FILES))
            self.assertEqual(manifest['bazel_exit'], 3)
            self.assertEqual(manifest['copied_files'], 2)
            for row in copied:
                (output / Path(row['source']).name).write_bytes(b'later cache epoch')
                retained = run / 'test-evidence' / row['file']
                self.assertEqual(retained.read_bytes(), expected[Path(row['source']).name])
                self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('private', json.dumps(manifest))

    def test_source_metadata_names_are_not_selected_from_other_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            base, run, _, _, start = self.source_fixture(Path(directory), 'other_producer')
            manifest = capture(base, run, ['//tools:other_producer'], 0, start)
            self.assertEqual(manifest['copied_files'], 0)
            self.assertEqual(len(manifest['results'][0]['files']), len(evidence_capture.FILES))

    def test_source_metadata_shares_aggregate_byte_and_file_budgets(self):
        for budget, expected in (('MAX_BYTES', 'over-budget'), ('MAX_FILES', 'file-budget-exhausted')):
            with self.subTest(budget=budget), tempfile.TemporaryDirectory() as directory:
                base, run, _, output, start = self.source_fixture(Path(directory))
                limit = (output / 'receipt.json').stat().st_size if budget == 'MAX_BYTES' else 1
                with patch.object(evidence_capture, budget, limit):
                    manifest = capture(base, run, ['//tools:runtime_source_receipt'], 0, start)
                rows = manifest['results'][0]['files']
                self.assertEqual(rows[-2]['state'], 'copied')
                self.assertEqual(rows[-1]['state'], expected)
                self.assertEqual(manifest['copied_files'], 1)
                self.assertEqual(manifest['bytes'], (output / 'receipt.json').stat().st_size)

    def test_source_metadata_fifo_and_symlink_directory_are_refused(self):
        for kind in ('fifo', 'symlink-parent'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                base, run, _, output, start = self.source_fixture(Path(directory))
                if kind == 'fifo':
                    (output / 'receipt.json').unlink()
                    os.mkfifo(output / 'receipt.json')
                else:
                    retired = output.parent / 'retired'
                    output.rename(retired)
                    output.symlink_to(retired, target_is_directory=True)
                manifest = capture(base, run, ['//tools:runtime_source_receipt'], 0, start)
                self.assertEqual(manifest['results'][0]['files'][-2]['state'], 'copy-refused')

    def test_source_metadata_replaced_parent_is_not_published_from_old_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            base, run, _, output, start = self.source_fixture(Path(directory))
            original = evidence_capture.descend
            opens = 0
            def selected(parent, relative):
                nonlocal opens
                descriptor = original(parent, relative)
                if str(relative) == 'test.outputs/runtime-source-receipt':
                    opens += 1
                    if opens == 1:
                        output.rename(output.parent / 'old-source-receipt')
                        output.mkdir()
                        (output / 'receipt.json').write_bytes(b'replacement metadata')
                return descriptor
            with patch.object(evidence_capture, 'descend', side_effect=selected):
                manifest = capture(base, run, ['//tools:runtime_source_receipt'], 0, start)
            self.assertEqual(manifest['results'][0]['files'][-2]['state'], 'changed-during-copy')
            self.assertEqual(manifest['copied_files'], 0)

    def test_source_metadata_same_size_rewrite_with_restored_mtime_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base, run, _, output, start = self.source_fixture(Path(directory))
            selected = output / 'receipt.json'
            original = os.fstat
            mutated = False
            def observing(descriptor):
                nonlocal mutated
                info = original(descriptor)
                if info.st_ino == selected.stat().st_ino and not mutated:
                    mutated = True
                    selected.write_bytes(b'x' * info.st_size)
                    os.utime(selected, ns=(info.st_atime_ns, info.st_mtime_ns))
                return info
            with patch.object(evidence_capture.os, 'fstat', side_effect=observing):
                manifest = capture(base, run, ['//tools:runtime_source_receipt'], 0, start)
            self.assertTrue(mutated)
            self.assertEqual(manifest['results'][0]['files'][-2]['state'], 'changed-during-copy')

    def test_failed_epoch_preserves_private_actual_logs_and_explicit_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, run = root / 'base', root / 'run'
            base.mkdir(mode=0o700)
            run.mkdir(mode=0o700)
            log = base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/pkg/proof'
            log.mkdir(parents=True)
            output = base / 'execroot/_main/bazel-out'
            (output / 'stable-status.txt').write_text('BUILD_LABEL fixture')
            (output / 'volatile-status.txt').write_text('BUILD_TIMESTAMP fixture')
            start = time.time_ns()
            (log / 'test.log').write_text('finite fixture failure')
            os.utime(log / 'test.log', ns=(start + 1, start + 1))
            manifest = capture(base, run, ['//pkg:proof', '//pkg:missing'], 1, start)
            self.assertEqual(manifest['bazel_exit'], 1)
            self.assertEqual(manifest['copied_files'], 1)
            self.assertEqual(manifest['results'][1]['state'], 'missing-test-directory')
            self.assertEqual(len(manifest['results']), 2)
            self.assertFalse(any(row['state'] == 'directory-refused' for row in manifest['results']))
            entry = manifest['results'][0]['files'][0]
            evidence = run / 'test-evidence' / entry['file']
            self.assertEqual(evidence.read_text(), 'finite fixture failure')
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((run / 'test-evidence.json').read_text())['targets'], ['//pkg:proof', '//pkg:missing'])
            (log / 'test.log').write_text('later epoch overwrite')
            self.assertEqual(evidence.read_text(), 'finite fixture failure')

    def test_stale_and_symlink_sources_are_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, run = root / 'base', root / 'run'
            base.mkdir(mode=0o700)
            run.mkdir(mode=0o700)
            log = base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/pkg/proof'
            log.mkdir(parents=True)
            (log / 'test.log').write_text('old epoch')
            os.utime(log / 'test.log', ns=(1, 1))
            (log / 'test.xml').symlink_to(log / 'test.log')
            manifest = capture(base, run, ['//pkg:proof'], 0, time.time_ns())
            self.assertEqual(manifest['copied_files'], 0)
            self.assertEqual(manifest['results'][0]['files'][0]['state'], 'stale')
            self.assertEqual(manifest['results'][0]['files'][1]['state'], 'copy-refused')

    def test_only_exact_labels(self):
        self.assertEqual(label_path('//:proof'), Path('proof'))
        for label in ('//...', '//pkg/../private:proof', '@remote//pkg:proof', '//pkg:proof/../../secret'):
            with self.assertRaises(ValueError):
                label_path(label)



class EngineShardEvidenceTest(unittest.TestCase):
    label = '//:engine_sharded_test'
    count = 447

    @staticmethod
    def document(shard, names=None):
        # Independent candidate producer: closed wire format and canonical
        # little-endian digest, not the consumer's inventory/helper functions.
        import hashlib
        names = names or ['fixture-%03d' % index for index in range(447)]
        digest = hashlib.sha256(b'omux.engine-test-inventory.v1\0')
        digest.update((447).to_bytes(4, 'little'))
        for index, name in enumerate(names):
            encoded = name.encode('ascii')
            digest.update(index.to_bytes(4, 'little'))
            digest.update(len(encoded).to_bytes(4, 'little'))
            digest.update(encoded)
        return dict(schema_version=1, kind='omux-engine-test-shard-v1',
            target='//:engine_sharded_test', full_count=447, shard_count=3,
            shard_index=shard, selected_count=149, inventory_sha256=digest.hexdigest(),
            names=names, sdk_version='0.17.0', sdk_log_errors=0, sdk_leaked_tests=0,
            scope='fixture-function-execution-and-original-sdk-teardown',
            user_outcome_measured=False,
            results=[dict(index=index, status='pass' if index % 3 == shard else 'unselected',
                log_errors=0, allocator_leaks=0, fuzz=False,
                elapsed_ns=1 if index % 3 == shard else None) for index in range(447)])

    def fixture(self, root):
        base, run = root / 'base', root / 'run'
        base.mkdir(mode=0o700); run.mkdir(mode=0o700)
        log = base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/engine_sharded_test'
        start = time.time_ns()
        for shard in range(3):
            directory = log / ('shard_%d_of_3' % (shard + 1))
            (directory / 'test.outputs').mkdir(parents=True)
            (directory / 'test.log').write_bytes(b'149 selected functions and SDK teardown returned\n')
            (directory / 'test.xml').write_bytes(
                b'<testsuites><testsuite tests="1" failures="0" errors="0"><testcase name="fixture"/></testsuite></testsuites>')
            self.write(directory, self.document(shard))
            for path in directory.rglob('*'):
                if path.is_file():
                    os.utime(path, ns=(start + 1, start + 1))
        return base, run, log, start

    @staticmethod
    def write(directory, document):
        (directory / 'test.outputs/engine-shard-coverage.json').write_text(json.dumps(document))

    def capture(self, base, run, start, status=0):
        return capture(base, run, [self.label], status, start)

    def test_complete_union_is_retained_without_promoting_reference_or_user_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, run, log, start = self.fixture(Path(temporary))
            extra = log / 'shard_1_of_3/test.outputs/private-database'
            extra.write_bytes(b'not selected')
            manifest = self.capture(base, run, start)
            union = manifest['engine_shards']
            self.assertEqual(union['state'], 'complete')
            self.assertEqual(union['completed_functions'], 447)
            self.assertTrue(union['complete_union']); self.assertTrue(union['all_passed'])
            self.assertFalse(union['unsharded_reference_passed'])
            self.assertFalse(union['user_outcome_measured'])
            self.assertEqual(manifest['copied_files'], 9)
            copied = [entry for row in manifest['results'] for entry in row['files'] if entry['state'] == 'copied']
            original = {entry['file']: (run / 'test-evidence' / entry['file']).read_bytes() for entry in copied}
            for directory in log.glob('shard_*'):
                self.write(directory, {'replaced': True})
            self.assertEqual({entry['file']: (run / 'test-evidence' / entry['file']).read_bytes() for entry in copied}, original)
            self.assertNotIn('private-database', json.dumps(manifest))
            self.assertEqual(json.loads((run / 'test-evidence.json').read_text())['engine_shards'], union)

    def test_complete_failures_skips_logs_leaks_and_fuzz_cannot_become_all_pass(self):
        for fault in ('fail', 'skip', 'log', 'leak', 'global-log', 'fuzz'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base, run, log, start = self.fixture(Path(temporary))
                doc = self.document(0)
                if fault in ('fail', 'skip'): doc['results'][0]['status'] = fault
                if fault == 'log': doc['results'][0]['log_errors'] = 1; doc['sdk_log_errors'] = 1
                if fault == 'leak': doc['results'][0]['allocator_leaks'] = 2; doc['sdk_leaked_tests'] = 1
                if fault == 'global-log': doc['sdk_log_errors'] = 1
                if fault == 'fuzz': doc['results'][0]['fuzz'] = True
                self.write(log / 'shard_1_of_3', doc)
                manifest = self.capture(base, run, start)
                self.assertEqual(manifest['bazel_exit'], 0)
                self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
                self.assertTrue(manifest['engine_shards']['complete_union'])
                self.assertFalse(manifest['engine_shards']['all_passed'])
                self.assertEqual(manifest['copied_files'], 9)

    def test_missing_pending_foreign_and_wrong_geometry_cannot_qualify(self):
        for fault in ('pending', 'foreign', 'missing-index', 'duplicate-index', 'wrong-shard',
                      'bool-count', 'float-time', 'sdk-disagreement', 'extra-field', 'short-results'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base, run, log, start = self.fixture(Path(temporary))
                doc = self.document(0)
                if fault == 'pending': doc['results'][0]['status'] = 'pending'
                if fault == 'foreign': doc['results'][1]['status'] = 'pass'
                if fault == 'missing-index': del doc['results'][0]['index']
                if fault == 'duplicate-index': doc['results'][3]['index'] = 0
                if fault == 'wrong-shard': doc['shard_index'] = 1
                if fault == 'bool-count': doc['full_count'] = True
                if fault == 'float-time': doc['results'][0]['elapsed_ns'] = 1.0
                if fault == 'sdk-disagreement': doc['results'][0]['allocator_leaks'] = 1
                if fault == 'extra-field': doc['unreviewed'] = True
                if fault == 'short-results': doc['results'].pop()
                self.write(log / 'shard_1_of_3', doc)
                manifest = self.capture(base, run, start)
                self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
                self.assertFalse(manifest['engine_shards']['complete_union'])

    def test_mixed_inventory_duplicate_json_xml_failure_and_bazel_failure_are_rejected(self):
        for fault in ('mixed', 'duplicate-json', 'xml-failure', 'xml-skip', 'xml-short', 'bazel-failure'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base, run, log, start = self.fixture(Path(temporary))
                directory = log / 'shard_2_of_3'
                if fault == 'mixed':
                    names = ['fixture-%03d' % index for index in range(447)]; names[0] = 'other-fixture'
                    self.write(directory, self.document(1, names))
                if fault == 'duplicate-json':
                    path = directory / 'test.outputs/engine-shard-coverage.json'
                    path.write_text(path.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
                if fault.startswith('xml'):
                    content = {'xml-failure': b'<testsuite><testcase><failure/></testcase></testsuite>',
                               'xml-skip': b'<testsuite><testcase><skipped/></testcase></testsuite>',
                               'xml-short': b'<testsuite>'}[fault]
                    (directory / 'test.xml').write_bytes(content)
                manifest = self.capture(base, run, start, 3 if fault == 'bazel-failure' else 0)
                self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
                self.assertFalse(manifest['engine_shards']['all_passed'])
                self.assertEqual(manifest['copied_files'], 9)

    def test_incomplete_epoch_custody_and_aggregate_budget_do_not_qualify(self):
        for fault in ('missing', 'stale', 'symlink', 'fifo', 'byte-budget', 'file-budget'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base, run, log, start = self.fixture(Path(temporary))
                receipt = log / 'shard_3_of_3/test.outputs/engine-shard-coverage.json'
                if fault == 'missing': receipt.unlink()
                if fault == 'stale': os.utime(receipt, ns=(1, 1))
                if fault in ('symlink', 'fifo'):
                    receipt.unlink()
                    if fault == 'symlink': receipt.symlink_to(receipt.parent.parent / 'test.log')
                    else: os.mkfifo(receipt)
                with contextlib.ExitStack() as stack:
                    if fault == 'byte-budget': stack.enter_context(patch.object(evidence_capture, 'MAX_BYTES', 128))
                    if fault == 'file-budget': stack.enter_context(patch.object(evidence_capture, 'MAX_FILES', 8))
                    manifest = self.capture(base, run, start)
                self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
                self.assertFalse(manifest['engine_shards']['complete_union'])
                self.assertLess(manifest['copied_files'], 9)

    def test_union_reads_copied_bytes_and_rejects_tampered_retained_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, run, log, start = self.fixture(Path(temporary))
            manifest = self.capture(base, run, start)
            entry = manifest['results'][0]['files'][0]
            (run / 'test-evidence' / entry['file']).write_bytes(b'replaced retained log')
            descriptor = evidence_capture.open_directory(run / 'test-evidence')
            try:
                result = evidence_capture.reconcile_engine_shards(descriptor, manifest['results'], 0)
            finally: os.close(descriptor)
            self.assertEqual(result['state'], 'unqualified')
            self.assertNotIn('fixture-000', json.dumps(result))

    def test_duplicate_rows_and_mixed_configurations_are_not_multiple_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, run, log, start = self.fixture(Path(temporary))
            manifest = self.capture(base, run, start)
            descriptor = evidence_capture.open_directory(run / 'test-evidence')
            try:
                rows = manifest['results']
                for candidate in ([rows[0], rows[0], rows[2]],
                                  [rows[0], dict(rows[1], configuration='foreign'), rows[2]],
                                  rows[:2]):
                    self.assertEqual(evidence_capture.reconcile_engine_shards(descriptor, candidate, 0)['state'], 'unqualified')
            finally: os.close(descriptor)



    def test_closed_wire_bound_sdk_counts_and_json_depth_are_durable_refusals(self):
        for fault in ('sdk-version', 'negative-count', 'bool-log', 'overbound', 'nested', 'malformed'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                base, run, log, start = self.fixture(Path(temporary))
                directory = log / 'shard_1_of_3'
                path = directory / 'test.outputs/engine-shard-coverage.json'
                doc = self.document(0)
                if fault == 'sdk-version': doc['sdk_version'] = 'unsupported'
                if fault == 'negative-count': doc['sdk_log_errors'] = -1
                if fault == 'bool-log': doc['results'][0]['log_errors'] = False
                self.write(directory, doc)
                if fault == 'overbound': path.write_bytes(b' ' * (512 * 1024 + 1))
                if fault == 'nested': path.write_bytes(b'[' * 4096 + b'0' + b']' * 4096)
                if fault == 'malformed': path.write_bytes(b'{')
                manifest = self.capture(base, run, start)
                self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
                self.assertFalse(manifest['engine_shards']['all_passed'])
                self.assertEqual(manifest['copied_files'], 9)
                self.assertEqual(json.loads((run / 'test-evidence.json').read_text())['engine_shards'],
                                 manifest['engine_shards'])

    def test_shard_receipt_parent_replacement_cannot_publish_from_old_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, run, log, start = self.fixture(Path(temporary))
            output = log / 'shard_1_of_3/test.outputs'
            original = evidence_capture.descend
            replaced = False
            def selected(parent, relative):
                nonlocal replaced
                descriptor = original(parent, relative)
                if str(relative) == 'shard_1_of_3/test.outputs' and not replaced:
                    replaced = True
                    output.rename(output.parent / 'retired-outputs')
                    output.mkdir()
                    self.write(output.parent, self.document(0))
                return descriptor
            with patch.object(evidence_capture, 'descend', side_effect=selected):
                manifest = self.capture(base, run, start)
            self.assertTrue(replaced)
            self.assertEqual(manifest['engine_shards']['state'], 'unqualified')
            self.assertEqual(manifest['results'][0]['files'][-1]['state'], 'changed-during-copy')


if __name__ == '__main__':
    unittest.main()
