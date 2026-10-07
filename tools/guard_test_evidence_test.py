"""Pure bounded-copy fixtures; no Bazel subprocess or host-manager calls."""
import json
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


if __name__ == '__main__':
    unittest.main()
