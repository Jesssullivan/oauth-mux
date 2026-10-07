import hashlib
import errno
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import os

from qualify_site_tools import QualificationError, bound_input, check_private_store, compare_selection, exception_diagnostics, mapping_command, nix_string, public_diagnostics


class SiteToolsTest(unittest.TestCase):
    def test_cleanup_signals_owned_group_before_reaping_leader(self):
        from qualify_site_tools import cleanup_owned_group, wait_unreaped
        process = Mock(pid=12345, returncode=None)
        events = []
        process.wait.side_effect = lambda **kwargs: events.append('reap')
        with (patch('qualify_site_tools.os.waitid', return_value=SimpleNamespace(si_status=0, si_code=os.CLD_EXITED)) as observed,
              patch('qualify_site_tools.os.getpgid', return_value=12345),
              patch('qualify_site_tools.os.killpg', side_effect=lambda *args: events.append('signal'))):
            self.assertEqual(wait_unreaped(process, 100), 0)
            cleanup_owned_group(process)
            self.assertTrue(all(call.args[2] & os.WNOWAIT for call in observed.call_args_list))
        self.assertEqual(events, ['signal', 'reap'])

    def test_changed_group_and_reaped_leader_never_signal(self):
        from qualify_site_tools import cleanup_owned_group
        with (patch('qualify_site_tools.os.killpg') as send,
              patch('qualify_site_tools.os.waitid', return_value=None),
              patch('qualify_site_tools.os.getpgid', return_value=54321)):
            for process in (Mock(pid=12345, returncode=0), Mock(pid=12345, returncode=None)):
                with self.assertRaises(ValueError):
                    cleanup_owned_group(process)
            send.assert_not_called()

    def test_private_eval_store_preserves_dummy_build_store_and_refusals(self):
        command = mapping_command('/declared/nix', 'public-expression', '/private/evaluation-store')
        self.assertEqual(command[command.index('--store') + 1], 'dummy://')
        self.assertEqual(command[command.index('--eval-store') + 1], '/private/evaluation-store')
        self.assertIn('--offline', command)
        self.assertIn('allow-import-from-derivation', command)
        self.assertEqual(command[command.index('max-jobs') + 1], '0')

    def test_private_store_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'public-input').write_bytes(b'bounded')
            with patch('qualify_site_tools.MAX_EVALUATION_BYTES', 2):
                with self.assertRaises(QualificationError) as caught:
                    check_private_store(directory)
            self.assertEqual(caught.exception.code, 'private-store-byte-bound')

    def test_vanished_scan_entry_is_tolerated_and_still_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            walk = [(directory, [], ['transient'])]
            with patch('qualify_site_tools.os.walk', return_value=walk), \
                    patch('qualify_site_tools.os.lstat', side_effect=FileNotFoundError(errno.ENOENT, 'private diagnostic')), \
                    patch('qualify_site_tools.MIN_FREE_BYTES', 0):
                check_private_store(directory)
            with patch('qualify_site_tools.os.walk', return_value=walk), \
                    patch('qualify_site_tools.MAX_EVALUATION_ENTRIES', 0):
                with self.assertRaises(QualificationError) as caught:
                    check_private_store(directory)
            self.assertEqual(caught.exception.code, 'private-store-entry-bound')

    def test_permission_failures_never_disappear_from_store_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            failure = PermissionError(errno.EACCES, 'private diagnostic')
            with patch('qualify_site_tools.os.walk', return_value=[(directory, [], ['payload'])]), \
                    patch('qualify_site_tools.os.lstat', side_effect=failure):
                with self.assertRaises(PermissionError):
                    check_private_store(directory)
            def denied_walk(*args, **kwargs):
                kwargs['onerror'](failure)
                return iter(())
            with patch('qualify_site_tools.os.walk', side_effect=denied_walk):
                with self.assertRaises(PermissionError):
                    check_private_store(directory)

    def test_exception_diagnostics_are_finite_and_never_include_raw_message(self):
        diagnostic = exception_diagnostics(PermissionError(errno.EACCES, 'private payload', '/private/operator'))
        self.assertEqual(diagnostic, {'exceptionType': 'PermissionError', 'errno': errno.EACCES})
        self.assertEqual(exception_diagnostics(TypeError('unserializable private value')), {'exceptionType': 'TypeError'})
    def test_exact_input_digest_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'selection.nix'
            source.write_bytes(b'{ pkgs }: {}')
            self.assertEqual(bound_input(source, hashlib.sha256(source.read_bytes()).hexdigest()), source.read_bytes())
            with self.assertRaises(ValueError):
                bound_input(source, '0' * 64)

    def test_selection_rejects_package_and_helper_changes(self):
        roots = {'packages': {'node': {'out': '/declared'}}, 'helperTools': ['/helper']}
        compare_selection(roots, roots)
        with self.assertRaises(ValueError):
            compare_selection({'packages': {'node': {'out': '/different'}}, 'helperTools': ['/helper']}, roots)
        with self.assertRaises(ValueError):
            compare_selection({'packages': roots['packages'], 'helperTools': []}, roots)

    def test_nix_path_encoding_does_not_interpolate(self):
        self.assertEqual(nix_string('/tmp/${untrusted}'), '"/tmp/\\${untrusted}"')

    def test_diagnostic_never_exports_raw_stderr(self):
        result = public_diagnostics(b'error: syntax error at /private/operator-secret')
        self.assertIn('syntax', result['categories'])
        self.assertNotIn('operator-secret', str(result))

    def test_mismatch_receipt_reports_public_changes(self):
        names = ('node', 'python', 'pnpm', 'bash', 'coreutils', 'chromium')
        packages = {name: {'out': '/nix/store/' + chr(97 + index) * 32 + '-' + name} for index, name in enumerate(names)}
        expected = {'packages': packages, 'helperTools': []}
        actual = {'packages': {name: dict(package) for name, package in packages.items()}, 'helperTools': []}
        actual['packages']['bash']['out'] = '/nix/store/' + 'g' * 32 + '-bash-interactive'
        with self.assertRaises(QualificationError) as caught:
            compare_selection(actual, expected)
        self.assertEqual(caught.exception.phase, 'output-comparison')
        self.assertEqual(caught.exception.details['changedPackages'], ['bash'])
        self.assertIn('actualMappingSha256', caught.exception.details)


if __name__ == '__main__':
    unittest.main()
