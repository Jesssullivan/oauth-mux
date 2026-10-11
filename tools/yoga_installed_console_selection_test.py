"""Real private file/TTY drift models; no installed, seat or consent assertion."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import yoga_installed_console_selection as route
import yoga_installed_console_prepare as launcher


class Models(unittest.TestCase):
    def seed(self):
        return {'schemaVersion': 1, 'scope': route.REQUEST_SCOPE,
            'installedWorkspace': {'path': '/srv/model/workspace/installed-workspace.json', 'sha256': 'a'*64},
            'machineIdSha256': 'b'*64, 'seatSessionId': 'model', 'stateRoot': '/srv/model/state',
            'sourceSocket': '/run/user/1000/wayland-0', 'inputPaths': {}, 'controllerTools': {},
            'controllerInventory': {}, 'controllerNarProof': {}, 'vaultWrapperAuthority': {}}

    def test_public_request_closed_fields_and_duplicate_refusal(self):
        raw = route.qualification.canonical(self.seed())
        self.assertEqual(route.request(raw), self.seed())
        for key in ('token', 'cookie', 'profile', 'deadlineMonotonicNs', 'originalEntryMonotonicNs', 'command'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                route.request(route.qualification.canonical(dict(self.seed(), **{key: 'public-model'})))
        with self.assertRaises(ValueError):
            route.request(raw[:-1]+b',"scope":"duplicate"}')

    def test_real_regular_descriptor_refuses_before_identity_reads(self):
        with tempfile.TemporaryFile() as stream, mock.patch.object(route.guard, 'file_bytes') as read:
            with self.assertRaises(ValueError):
                route.local_facts(self.seed(), time.monotonic_ns()+30*10**9, stream.fileno())
            read.assert_not_called()

    def test_actual_pty_rebinding_during_local_fact_capture_refuses(self):
        first_a, first_b = os.openpty()
        other_a, other_b = os.openpty()
        held = os.dup(first_b)
        seed = self.seed()
        seed['machineIdSha256'] = hashlib.sha256(b'model-machine').hexdigest()
        record = b'SEAT=seat0\n'
        def read(path, *unused, **options):
            return b'model-machine' if path == '/etc/machine-id' else record
        try:
            with mock.patch.object(route.guard, 'file_bytes', side_effect=read), \
                 mock.patch.object(route.qualification, 'identity_capture', side_effect=lambda *args: os.dup2(other_b, held)):
                with self.assertRaises(ValueError):
                    route.local_facts(seed, time.monotonic_ns()+30*10**9, held)
        finally:
            for fd in (first_a, first_b, other_a, other_b, held):
                os.close(fd)

    def test_actual_request_hash_read_rebinding_refuses_before_runtime(self):
        # File predicate only: a synthetic installed capture cannot confer authority.
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as root:
            leaf = Path(root)/'request.json'
            leaf.write_bytes(b'public-model-request')
            leaf.chmod(0o600)
            obj = object.__new__(route.PreparedSelection)
            obj.closed = False
            obj.request_path = str(leaf)
            obj.raw = leaf.read_bytes()
            obj.request_sha256 = hashlib.sha256(obj.raw).hexdigest()
            obj.deadline = time.monotonic_ns()+30*10**9
            obj.selection = {'originalEntryMonotonicNs': obj.deadline-1200*10**9,
                'deadlineMonotonicNs': obj.deadline, 'sourceGraphSha256': 'a'*64}
            obj.capture = mock.Mock()
            leaf.rename(Path(root)/'old.json')
            leaf.write_bytes(b'changed-public-model')
            leaf.chmod(0o600)
            with mock.patch.object(route.guard, 'runtime_qualification') as runtime:
                with self.assertRaises(ValueError):
                    obj.verify()
                runtime.assert_not_called()
                obj.capture.qualify.assert_not_called()

    def test_actual_selection_publication_rolls_back_when_final_verify_detects_change(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as root:
            target = Path(root)/'selection.json'
            calls = []
            def verify():
                calls.append(1)
                if len(calls) == 2:
                    raise ValueError('public-model-drift')
            with self.assertRaises(ValueError):
                route.qualification.publish(str(target), b'{"scope":"public-model"}',
                    time.monotonic_ns()+30*10**9, verify)
            self.assertEqual(calls, [1, 1])
            self.assertFalse(target.exists())

    def test_cli_rejects_caller_clock_and_command_before_envelope(self):
        required = ['--request', '/srv/request.json', '--request-sha256', 'a'*64,
            '--selection-output', '/srv/selection.json', '--qualification-output', '/srv/qualified.json']
        with mock.patch.object(launcher.envelope, 'run') as envelope, \
             mock.patch.object(launcher.selection, 'PreparedSelection') as construct:
            for extra in (['--deadline-monotonic-ns', '1'], ['--command', 'arbitrary']):
                self.assertEqual(launcher.main(required+extra), 125)
            construct.assert_not_called()
            envelope.assert_not_called()

    def test_real_post_guardian_readback_or_release_never_renews_cleanup(self):
        required = ['--request', '/srv/request.json', '--request-sha256', 'a'*64,
            '--selection-output', '/srv/selection.json', '--qualification-output', '/srv/qualified.json']
        for stage in ('verify', 'close'):
            with self.subTest(stage=stage), tempfile.TemporaryFile() as physical:
                now = [time.monotonic_ns()]; context = {}; calls = []
                class Prepared:
                    def __init__(self, *arguments, **keywords):
                        context['entry'], context['deadline'] = arguments[4:6]
                        context['cutoff'] = context['entry'] + 30 * 10**9
                        self.fd = os.dup(physical.fileno()); self.identity = os.fstat(self.fd)
                    def publish(self):
                        return {'selection': '/srv/selection.json', 'selectionSha256': 'a'*64,
                            'qualification': '/srv/qualified.json'}
                    def verify(self):
                        assert os.fstat(self.fd) == self.identity
                        calls.append('verify')
                        if stage == 'verify' and calls.count('verify') == 2:
                            now[0] = context['cutoff']
                    def close(self):
                        if self.fd is not None:
                            os.close(self.fd); self.fd = None; calls.append('close')
                            if stage == 'close': now[0] = context['cutoff']
                def result(*arguments, **keywords):
                    return {'exit': 0, 'originalEntryMonotonicNs': context['entry'],
                        'deadlineMonotonicNs': context['deadline'],
                        'cleanupDeadlineMonotonicNs': context['cutoff'],
                        'cleanupCompletionQualified': True}
                with (mock.patch.object(launcher.time, 'monotonic_ns', side_effect=lambda: now[0]),
                      mock.patch.object(launcher.selection, 'PreparedSelection', Prepared),
                      mock.patch.object(launcher.envelope, 'run', side_effect=result),
                      mock.patch.object(launcher.sys, 'stdin') as terminal,
                      mock.patch('builtins.print')):
                    terminal.fileno.return_value = 0
                    self.assertEqual(launcher.main(required), 125)
                self.assertLess(now[0], context['deadline'])
                self.assertIn('close', calls)

    def test_custody_close_attempts_both_resources_and_cannot_be_used_afterwards(self):
        obj = object.__new__(route.PreparedSelection)
        obj.closed = False
        obj.pin, obj.capture = mock.Mock(), mock.Mock()
        obj.pin.close.side_effect = OSError('public-model')
        with self.assertRaises(OSError):
            obj.close()
        obj.capture.close.assert_called_once_with()
        with self.assertRaises(ValueError):
            obj.verify()


if __name__ == '__main__':
    unittest.main()
