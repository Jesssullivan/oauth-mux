import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from host_closure_transfer import CLOSURE, METADATA_CLOSURE, GateError, registered, store_paths, category, bounded, registration_metadata, diagnostic_flags, public_version, immutable_sibling_cli, local_daemon_comparison, coordinator_info

class ExactClosureCustodyTest(unittest.TestCase):
    def paths(self):
        return ['/nix/store/' + format(index, '032x') + '-declared-input' for index in range(126)]

    def test_exact_member_count_no_duplicates_or_injected_store_path(self):
        paths = self.paths()
        self.assertEqual(store_paths(('\n'.join(paths) + '\n').encode()), paths)
        for altered in (paths[:-1], paths + [paths[0]], paths[:-1] + [paths[0]], paths[:-1] + ['/nix/store/../private'], paths[:-1] + ['/nix/store/' + 'a' * 32 + '-ok\nprivate']):
            with self.subTest(count=len(altered)), self.assertRaises(GateError):
                store_paths(('\n'.join(altered) + '\n').encode())

    def test_complete_registration_requires_root_and_all_declared_members(self):
        paths = self.paths()
        info = {'narHash': 'sha256-' + 'A' * 43 + '=', 'narSize': 10, 'references': []}
        value = {path: info for path in [*paths, CLOSURE, METADATA_CLOSURE]}
        expected = {path: info for path in paths}
        self.assertEqual(registered(json.dumps(value), paths, expected)['registered_path_count'], 128)
        for altered in ({path: data for path, data in value.items() if path != CLOSURE}, {**value, paths[0]: {**info, 'narSize': 0}}, {**value, paths[0]: {**info, 'narHash': 'untrusted'}}, {**value, '/private/operator': info}, {**value, '/nix/store/' + 'a' * 32 + '-unselected-extra': info}, {**value, paths[0]: {**info, 'narSize': 11}}, {**value, paths[0]: {**info, 'references': [CLOSURE]}}):
            with self.assertRaises(GateError):
                registered(json.dumps(altered), paths, expected)

    def test_failure_metadata_never_returns_underlying_diagnostic(self):
        for data, expected in ((b'permission denied /private/operator', 'store-or-ssh-permission'), (b'has no signature SECRET', 'store-signature-or-trust'), (b'unknown SECRET', 'declared-nix-operation-failed')):
            self.assertEqual(category(data), expected)
        for data, expected in ((b'No space left on device /private/SECRET', 'store-capacity'), (b'client is not trusted SECRET', 'destination-trust-refused'), (b'cannot write SECRET', 'store-write'), (b'hash mismatch SECRET', 'hash-or-registration-conflict'), (b'unexpected end-of-file SECRET', 'interrupted-transport'), (b'stdio protocol version mismatch SECRET', 'store-protocol')):
            self.assertEqual(category(data), expected)
            hints = diagnostic_flags(data)
            self.assertTrue(all(type(value) is bool for value in hints.values()))
            self.assertNotIn('SECRET', json.dumps(hints))

    def test_version_metadata_cannot_emit_unframed_or_identifying_output(self):
        self.assertEqual(public_version(b'nix (Nix) 2.31.2\n'), '2.31.2')
        self.assertEqual(public_version(b'nix-daemon (Determinate Nix 3.16.0) 2.33.0'), '2.33.0')
        self.assertIsNone(public_version(b'nix 2.31.2\nprivate'))
        self.assertIsNone(public_version(b'operator-identifying-output'))
        with self.assertRaises(GateError):
            public_version(b'x' * 257)

    def registration(self):
        paths = self.paths()
        records = []
        for index, path in enumerate(paths):
            refs = [paths[(index + offset) % len(paths)] for offset in range(4 if index < 10 else 3)]
            records.extend([path, 'sha256:' + '0' * 52, '10', '', str(len(refs)), *refs])
        return ('\n'.join(records) + '\n').encode()

    def test_fixed_registration_parser_binds_hash_size_references_and_record_set(self):
        paths = self.paths()
        data = self.registration()
        records = registration_metadata(data, paths)
        self.assertEqual(len(records), 126)
        self.assertEqual(records[paths[0]]['narHash'], 'sha256-' + 'A' * 43 + '=')
        for altered in (data + b'private\n', data.replace(paths[0].encode(), b'/private/operator', 1), data.replace(('sha256:' + '0' * 52).encode(), ('sha256:' + 'z' * 52).encode(), 1), data.replace(b'\n10\n', b'\n0\n', 1), data.replace(paths[1].encode(), paths[0].encode(), 1)):
            with self.assertRaises(GateError):
                registration_metadata(altered, paths)

    def test_exited_leader_cannot_leave_stream_holding_descendant(self):
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / 'owned-child'
            code = 'import os,time; child=os.fork(); open(' + repr(str(marker)) + ',"w").write(str(child)) if child else None; os._exit(0) if child else time.sleep(60)'
            with self.assertRaisesRegex(GateError, 'deadline'):
                bounded([sys.executable, '-I', '-S', '-c', code], {}, seconds=0.2)
            child = int(marker.read_text())
            state = Path('/proc') / str(child) / 'stat'
            deadline = time.monotonic() + 2
            while state.exists() and time.monotonic() < deadline:
                try:
                    observed = state.read_text().split(') ', 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if observed == 'Z':
                    break
                time.sleep(0.01)
            try:
                observed = state.read_text().split(') ', 1)[1].split()[0]
            except FileNotFoundError:
                return
            self.assertEqual(observed, 'Z')

    def test_leader_may_close_both_pipes_before_successful_exit(self):
        status, output, error = bounded([sys.executable, '-I', '-S', '-c', 'import os,time; os.close(1); os.close(2); time.sleep(0.15); os._exit(0)'], {}, seconds=2)
        self.assertEqual(status, 0)
        self.assertEqual(output, b'')
        self.assertEqual(error, b'')

    def test_local_daemon_comparison_pins_immutable_entrypoint_and_returns_only_booleans(self):
        daemon = '/nix/store/' + 'a' * 32 + '-nix/bin/nix-daemon'
        self.assertEqual(immutable_sibling_cli(daemon), daemon.rsplit('/', 1)[0] + '/nix')
        for invalid in ('/usr/bin/nix-daemon', daemon + ';private', daemon.replace('/bin/', '/../')):
            with self.assertRaises(GateError):
                immutable_sibling_cli(invalid)
        with patch('host_closure_transfer.bounded', return_value=(0, b'{"trusted":true,"url":"PRIVATE","version":"PRIVATE"}', b'')):
            result = local_daemon_comparison('declared-ssh', [], 'pzm', {}, daemon)
        self.assertEqual(result, {'local_daemon_store_connected': True, 'local_daemon_client_trusted': True})
        with patch('host_closure_transfer.bounded', return_value=(0, b'{"trusted":"PRIVATE"}', b'')):
            with self.assertRaises(GateError):
                local_daemon_comparison('declared-ssh', [], 'pzm', {}, daemon)
        for output in (b'', b'PRIVATE', b'\xff'):
            with patch('host_closure_transfer.bounded', return_value=(0, output, b'')):
                with self.assertRaisesRegex(GateError, 'local-daemon-response-framing') as raised:
                    local_daemon_comparison('declared-ssh', [], 'pzm', {}, daemon)
                self.assertTrue(all(type(value) is bool for value in raised.exception.hints.values()))
                self.assertNotIn('PRIVATE', json.dumps(raised.exception.hints))

    def test_coordinator_info_rejects_missing_or_wrong_trust_metadata(self):
        for output in (b'', b'{"trusted":null}', b'{"trusted":"PRIVATE"}'):
            with patch('host_closure_transfer.bounded', side_effect=[(0, b'nix (Nix) 2.34.6', b''), (0, output, b'')]):
                with self.assertRaises(GateError):
                    coordinator_info('declared-nix', {})
        with patch('host_closure_transfer.bounded', side_effect=[(0, b'nix (Nix) 2.34.6', b''), (0, b'{"trusted":false,"url":"PRIVATE"}', b'')]):
            result = coordinator_info('declared-nix', {})
        self.assertFalse(result['coordinator_daemon_client_trusted'])
        self.assertNotIn('PRIVATE', json.dumps(result))

if __name__ == '__main__':
    unittest.main()
