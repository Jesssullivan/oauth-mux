"""Actual log acceptance, exact argv projection and owned real-FD faults."""
import copy
import json
import io
from types import SimpleNamespace
import os
from pathlib import Path
import tempfile
import time
import subprocess
import unittest
from unittest.mock import patch

import codex_native_file_writer_models as driver
from codex_native_source_file_writer_test import cleanup

source = driver.source


class FileWriterDriverTests(unittest.TestCase):
    def setUp(self):
        self.previous = source.DEADLINE
        source.DEADLINE = time.monotonic() + 120
        self.names = driver.expected_tests()

    def tearDown(self): source.DEADLINE = self.previous

    def log(self):
        return ('running 19 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in self.names) +
            'test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 47 filtered out; finished in 0.03s\n').encode()

    def test_actual_expected_names_and_single_19_pass_summary_accept(self):
        result = driver.accept_log(self.log(), self.names)
        self.assertEqual(result['tests'], list(self.names))
        self.assertEqual((result['passed'], result['failed'], result['ignored']), (19, 0, 0))
        self.assertEqual(result['filtered_out'], 47)

    def test_missing_duplicate_failed_ignored_other_names_and_repeated_summary_refuse(self):
        raw = self.log(); first = ('test ' + self.names[0] + ' ... ok\n').encode()
        values = (raw.replace(first, b''), raw.replace(first, first + first),
            raw.replace(first, first.replace(b'... ok', b'... FAILED')),
            raw.replace(first, first.replace(b'... ok', b'... ignored')),
            raw.replace(first, b'test unknown_model ... ok\n'), raw + raw[raw.index(b'test result:'):],
            raw.replace(b'running 19 tests', b'running 20 tests'),
            raw.replace(b'19 passed; 0 failed;', b'18 passed; 1 failed;'))
        for value in values:
            with self.assertRaises(ValueError): driver.accept_log(value, self.names)

    def test_projection_changes_only_the_selected_hub_repository_token(self):
        hub = driver.family.binding.metadata.HUB; root = Path('/public/original')
        mapping = {'repositories': {hub: str(root / 'repositories' / hub), 'other': str(root / 'repositories/other')}}
        plan = {'argv': ['bazel', 'test', '--override_repository=' + hub + '=' + mapping['repositories'][hub],
            '--override_repository=other=' + mapping['repositories']['other'], driver.TARGET], 'environment': {'public': 'value'}}
        before = copy.deepcopy(plan)
        projected = driver.project_hub(plan, mapping, Path('/public/generated/hub'), root)
        self.assertEqual(plan, before)
        self.assertEqual([i for i, pair in enumerate(zip(plan['argv'], projected['argv'])) if pair[0] != pair[1]], [2])
        for bad in ({**mapping, 'repositories': {hub: '/wrong/original'}},):
            with self.assertRaises(ValueError): driver.project_hub(plan, bad, Path('/public/generated/hub'), root)
        for argv in (plan['argv'] + [plan['argv'][2]], plan['argv'][:2] + plan['argv'][3:]):
            with self.assertRaises(ValueError): driver.project_hub({**plan, 'argv': argv}, mapping, Path('/public/generated/hub'), root)

    def test_real_stream_writer_witness_and_zero_byte_stderr_survive_readback(self):
        root = Path(tempfile.mkdtemp()); owner = driver.ChildStreams(root / 'streams')
        held = list(owner.fds.values()) + [owner.parent]
        try:
            os.write(owner.fds['stdout'], b'public stdout'); owner.seal()
            self.assertEqual(owner.bytes('stdout'), b'public stdout')
            self.assertEqual(owner.bytes('stderr'), b'')
            (owner.path / 'stdout').unlink(); (owner.path / 'stdout').write_bytes(b'public stdout'); (owner.path / 'stdout').chmod(0o444)
            with self.assertRaises(ValueError): owner.bytes('stdout')
        finally:
            owner.close()
            for fd in held:
                with self.assertRaises(OSError): os.fstat(fd)
            cleanup(root)

    def test_fixed_role_alias_is_retained_through_late_retarget_and_same_byte_replacement(self):
        for fault in ('none', 'retarget', 'same-byte-alias'):
            root = Path(tempfile.mkdtemp()); owner = driver.family.HeldControls(); held = []
            try:
                selected = root / 'selected-target'; selected.mkdir(mode=0o700)
                sibling = root / 'sibling-target'; sibling.mkdir(mode=0o700)
                body = selected / 'owned-log-body'; body.write_bytes(self.log()); body.chmod(0o444)
                other = sibling / 'test.log'; other.write_bytes(self.log()); other.chmod(0o444)
                alias = selected / 'test.log'; alias.symlink_to(body.name)
                raw, physical = driver.read_actual(alias, owner)
                self.assertEqual((raw, physical), (self.log(), body))
                self.assertEqual(owner.aliases[-1][0:2], (alias, body))
                held.extend(row[1] for row in owner.held.values())
                # Simulate late SDK/source work after the actual role capture.
                if fault != 'none':
                    alias.unlink(); alias.symlink_to(other if fault == 'retarget' else body.name)
                    with self.assertRaises(ValueError): owner.fence()
                    self.assertEqual(physical, body)
                else: owner.full(); owner.fence()
            finally:
                owner.close()
                for fd in held:
                    with self.assertRaises(OSError): os.fstat(fd)
                cleanup(root)

    def test_fixed_role_parent_redirect_and_sibling_leaf_are_refused_before_adoption(self):
        for fault in ('leaf', 'parent'):
            root = Path(tempfile.mkdtemp()); owner = driver.family.HeldControls()
            try:
                selected = root / 'selected-target'; selected.mkdir(mode=0o700)
                sibling = root / 'sibling-target'; sibling.mkdir(mode=0o700)
                other = sibling / 'test.log'; other.write_bytes(self.log()); other.chmod(0o444)
                alias = selected / 'test.log'
                if fault == 'leaf': alias.symlink_to(other)
                else:
                    selected.rmdir(); selected.symlink_to(sibling, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)): driver.read_actual(alias, owner)
                self.assertEqual(owner.held, {})
                self.assertEqual(owner.aliases, [])
            finally: owner.close(); cleanup(root)

    def test_actual_result_writer_pin_and_original_witness_are_retained(self):
        root = Path(tempfile.mkdtemp()); controls = driver.family.HeldControls()
        try:
            row = driver.publish_result(root / 'result', {'public': 'actual writer fixture'}, controls)
            controls.full()
            self.assertEqual(source.sha((root / 'result/models-receipt.json').read_bytes()), row['sha256'])
            leaf = root / 'result/models-receipt.json'; leaf.chmod(0o600); leaf.write_bytes(b'changed public bytes'); leaf.chmod(0o444)
            with self.assertRaises(ValueError): controls.fence()
        finally:
            controls.close(); cleanup(root)

    def test_actual_child_receipt_keeps_real_test_outputs_through_late_owner_refusal(self):
        # Native Bazel/guardian/SDK proofs are explicit seams. Actual driver,
        # original stream writers, held log/XML and receipt owners are real.
        for fault in ('none', 'log', 'receipt', 'child-failed'):
            root = Path(tempfile.mkdtemp()); owner = driver.family.HeldControls()
            calls, observed_fds, phases = [], [], []
            try:
                publication = root / 'publication'; publication.mkdir(mode=0o700)
                logs = root / 'logs'; logs.mkdir(mode=0o700)
                (logs / 'test.log').write_bytes(self.log()); (logs / 'test.log').chmod(0o444)
                (logs / 'test.xml').write_bytes(b'<testsuites tests="19" failures="0" errors="0" skipped="0"><testsuite tests="19" failures="0" errors="0" skipped="0"/></testsuites>')
                (logs / 'test.xml').chmod(0o444)
                pub = SimpleNamespace(path=publication, raw=b'public source report',
                    capture=lambda: calls.append('capture'), fence=lambda: calls.append('source-fence'),
                    terminal=lambda: calls.append('source-terminal'))
                sdk = SimpleNamespace(fence=lambda: calls.append('sdk-fence'))
                inputs = SimpleNamespace(check_all=lambda: calls.append('inputs-full'), check=lambda: calls.append('inputs-fence'))
                report = {'producer_context': {'public': 'original envelope seam'}, 'inventory_sha256': 'a'*64,
                    'patch_sha256': ['b'*64]*11, 'graph_files': {'public': 'graph seam'},
                    'generated_hub': {'public': {'sha256': 'c'*64, 'bytes': 1}},
                    'original_sdk': {'public': 'full SDK seam'}, 'sdk_input_qualification': {'public': 'guardian seam'}}
                tools = {'public': 'actual fixed tools qualification seam'}
                def plan(published, sdk, report, work, cutoff):
                    work.mkdir(mode=0o700)
                    return {'argv': ['declared-bazel-seam', driver.TARGET], 'cwd': str(publication),
                        'environment': {}, 'qualified_query_tools': tools}
                def child(plan, streams, cutoff):
                    self.assertEqual(calls[-1], 'source-terminal')
                    calls.append('child')
                    observed_fds.extend(list(streams.fds.values()) + [streams.parent])
                    if fault == 'child-failed': raise ValueError('actual child refusal seam')
                    os.write(streams.fds['stdout'], b'public child diagnostics'); streams.seal()
                entry = time.monotonic_ns(); until = entry + 1200*10**9
                with patch.dict(os.environ, {'TEST_TMPDIR': str(root)}), patch.object(driver, 'native_plan', plan), patch.object(driver, 'run_once', child), \
                        patch.object(driver, 'actual_test_directory', return_value=logs), \
                        patch.object(driver.family, 'producer_context', return_value=report['producer_context']), \
                        patch.object(driver.family.query_tools, 'verify_repository', return_value=tools):
                    if fault == 'child-failed':
                        with self.assertRaises(ValueError): driver.native_child(pub, sdk, report, owner, inputs, entry, until, source.DEADLINE, _phase=phases.append)
                        self.assertFalse((root / 'native-file-writer-models/models-receipt.json').exists())
                        self.assertEqual(phases[-1], 'child-run')
                    else:
                        row = driver.native_child(pub, sdk, report, owner, inputs, entry, until, source.DEADLINE, _phase=phases.append)
                        actual = json.loads(owner.raws[row['path']])
                        self.assertEqual(actual['actual_libtest']['tests'], list(self.names))
                        self.assertEqual(actual['actual_libtest']['passed'], 19)
                        self.assertEqual(set(actual['retained_evidence']), {'native-test.log', 'native-test.xml', 'native-stdout.log', 'native-stderr.log'})
                        self.assertEqual((root / 'native-file-writer-models/native-test.log').read_bytes(), self.log())
                        self.assertEqual((root / 'native-file-writer-models/native-stderr.log').read_bytes(), b'')
                        self.assertFalse(actual['default_login_regression_passed'])
                        self.assertFalse(actual['ordinary_native_qualified'])
                        owner.full()
                        if fault != 'none':
                            leaf = logs / 'test.log' if fault == 'log' else Path(row['path'])
                            original = leaf.read_bytes(); mode = leaf.parent.stat().st_mode & 0o7777
                            leaf.parent.chmod(0o700); leaf.unlink(); leaf.write_bytes(original); leaf.chmod(0o444); leaf.parent.chmod(mode)
                            with self.assertRaises(ValueError): owner.fence()
                self.assertTrue(all(phase in driver.CHILD_PHASES for phase in phases))
                if fault != 'child-failed': self.assertEqual(phases[-1], 'child-close')
                self.assertLess(calls.index('sdk-fence'), calls.index('source-terminal'))
                self.assertLess(calls.index('source-terminal'), calls.index('child'))
                observed_fds.extend(item[1] for item in owner.held.values())
            finally:
                owner.close()
                for fd in observed_fds:
                    with self.assertRaises(OSError): os.fstat(fd)
                cleanup(root)

    def test_actual_driver_main_requires_final_owner_acceptance_before_its_marker(self):
        for fault in ('none', 'late-bytes', 'late-same-byte-replacement'):
            root = Path(tempfile.mkdtemp()); owner = driver.family.HeldControls()
            held, stdout = [], io.StringIO()
            try:
                entry = time.monotonic_ns(); until = entry + 1200*10**9
                def child(*arguments, **keywords):
                    self.assertEqual(arguments[5:7], (entry, until))
                    row = driver.publish_result(root / 'result', {'public': 'actual held result seam'}, owner)
                    held.extend(item[1] for item in owner.held.values())
                    return row
                def scope(callback, _phase):
                    # Full native source/SDK/child are explicit seams here;
                    # actual main callback, publication and final owner are real.
                    callback(None, None, None, owner, None, entry, until, source.DEADLINE)
                    leaf = root / 'result/models-receipt.json'
                    if fault == 'late-bytes':
                        leaf.chmod(0o600); leaf.write_bytes(b'public changed body'); leaf.chmod(0o444)
                    elif fault == 'late-same-byte-replacement':
                        raw = leaf.read_bytes(); leaf.parent.chmod(0o700)
                        leaf.unlink(); leaf.write_bytes(raw); leaf.chmod(0o444); leaf.parent.chmod(0o555)
                    _phase('final-control-input-read')
                    owner.full(); owner.fence()
                with patch.object(driver.family, 'main', scope), patch.object(driver, 'native_child', child), \
                        patch.object(driver.sys, 'argv', ['native-model-driver']), patch('sys.stdout', stdout):
                    if fault == 'none': driver.main()
                    else:
                        with self.assertRaises(ValueError): driver.main()
                self.assertEqual('actual maintained login storage tests 19 passed' in stdout.getvalue(), fault == 'none')
            finally:
                owner.close()
                for fd in held:
                    with self.assertRaises(OSError): os.fstat(fd)
                cleanup(root)

    def test_actual_driver_refusal_categories_exclude_exception_payloads(self):
        public_canary = 'public-exception-payload-must-not-appear'
        for error, category in ((ValueError(public_canary), 'invariant'),
                (OSError(public_canary), 'os'), (KeyError(public_canary), 'key'),
                (TypeError(public_canary), 'type'), (UnicodeError(public_canary), 'unicode'),
                (IndexError(public_canary), 'index'), (subprocess.SubprocessError(public_canary), 'subprocess')):
            stderr, stdout = io.StringIO(), io.StringIO()
            def scope(callback, _phase):
                _phase('sdk-custody')
                raise error
            with patch.object(driver.family, 'main', scope), patch.object(driver, 'native_child') as child, \
                    patch.object(driver.sys, 'argv', ['native-model-driver']), \
                    patch('sys.stderr', stderr), patch('sys.stdout', stdout):
                with self.assertRaises(type(error)): driver.main()
                child.assert_not_called()
            self.assertEqual(stderr.getvalue(), 'native file-writer models refused; phase=sdk-custody; category=' + category + '\n')
            self.assertEqual(stdout.getvalue(), '')

    def test_diagnostic_writer_failure_preserves_actual_driver_refusal(self):
        original = ValueError('public original refusal canary')
        class RefusingWriter:
            def write(self, unused): raise OSError('public diagnostic IO canary')
        def scope(callback, _phase):
            _phase('final-owner-fences')
            raise original
        with patch.object(driver.family, 'main', scope), patch.object(driver, 'native_child') as child, \
                patch.object(driver.sys, 'argv', ['native-model-driver']), patch('sys.stderr', RefusingWriter()):
            with self.assertRaises(ValueError) as caught: driver.main()
            self.assertIs(caught.exception, original)
            child.assert_not_called()

    def test_one_child_is_not_started_when_original_final_proof_reserve_is_spent(self):
        root = Path(tempfile.mkdtemp()); streams = driver.ChildStreams(root / 'streams')
        previous = source.DEADLINE
        try:
            source.DEADLINE = time.monotonic() + 30
            with patch.object(driver.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError): driver.run_once({'argv': [], 'cwd': str(root), 'environment': {}}, streams, source.DEADLINE)
                spawn.assert_not_called()
        finally:
            source.DEADLINE = previous; streams.close(); cleanup(root)

    def test_owned_child_wait_is_attempted_even_when_deadline_kill_fails(self):
        root = Path(tempfile.mkdtemp()); streams = driver.ChildStreams(root / 'streams')
        cutoff = source.DEADLINE; state = {'kill': False, 'wait': False}
        class Child:
            returncode = None
            def poll(self): return None
            def kill(self): state['kill'] = True; raise OSError('owned kill refusal')
            def wait(self, timeout): state['wait'] = True; self.returncode = 0; return 0
        clock = iter((cutoff - 120, cutoff - 80, cutoff - 80))
        try:
            with patch.object(driver.subprocess, 'Popen', return_value=Child()), \
                    patch.object(driver.time, 'monotonic', side_effect=lambda: next(clock)):
                with self.assertRaises(ValueError): driver.run_once({'argv': [], 'cwd': str(root), 'environment': {}}, streams, cutoff)
            self.assertEqual(state, {'kill': True, 'wait': True})
        finally: streams.close(); cleanup(root)
