"""Pure coordinator version/byte predicates; no program invocation."""
import unittest
import hashlib
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from site_coordinator_qualification import version_command, validate_versions, validate_ancestor, version_diagnostic, BAZEL_NATIVE, JDK, NIX_BAZEL_VERSION, NIX_BAZEL_VERSION_SHA256


class QualificationTest(unittest.TestCase):
    def test_version_diagnostic_does_not_accept_unknown_or_expose_arbitrary_output(self):
        diagnostic = version_diagnostic(b'private diagnostic /secret/path\nbazel no_version\n')
        self.assertIn('reported=bazel no_version;', diagnostic)
        self.assertNotIn('secret', diagnostic)
        self.assertNotIn('private', diagnostic)
        with self.assertRaises(ValueError):
            validate_versions(b'bazel no_version', b'openjdk version "21.0.10" 21.0.10+7')
        self.assertIn('reported=unrecognized;', version_diagnostic(b'bazel 9.0.1\nbazel 8.6.0\n'))
        self.assertIn('reported=bazel 9.0.1- (@non-git);', version_diagnostic(b'bazel 9.0.1- (@non-git)\n'))
        self.assertIn('reported=unrecognized;', version_diagnostic(b'bazel private@example.org\n'))
        self.assertEqual(hashlib.sha256(NIX_BAZEL_VERSION).hexdigest(), NIX_BAZEL_VERSION_SHA256)
        facts = validate_versions(NIX_BAZEL_VERSION, b'openjdk version "21.0.10" 21.0.10+7')
        self.assertEqual(facts['packaging_stamp'], 'Nix exact non-git build stamp')
        for other in (b'bazel 9.0.2- (@non-git)\n', b'bazel 9.0.1- (@other)\n'):
            with self.assertRaises(ValueError):
                validate_versions(other, b'openjdk version "21.0.10" 21.0.10+7')

    def test_exact_sticky_store_parent_only_for_immutable_inputs(self):
        root = SimpleNamespace(st_uid=0, st_mode=0o41775)
        validate_ancestor('/nix/store', root, True)
        validate_ancestor('/nix/store/fixed-package', SimpleNamespace(st_uid=0, st_mode=0o40555), True)
        for path, info, immutable in (
                ('/nix/store', root, False), ('/other/sticky', root, True),
                ('/nix/store/package', root, True),
                ('/nix/store/package', SimpleNamespace(st_uid=0, st_mode=0o40755), True),
                ('/nix/store', SimpleNamespace(st_uid=1, st_mode=0o41775), True),
                ('/nix/store', SimpleNamespace(st_uid=0, st_mode=0o41777), True)):
            with self.assertRaises(ValueError):
                validate_ancestor(path, info, immutable)

    def test_version_commands_have_no_build_or_caller_flags(self):
        self.assertEqual(BAZEL_NATIVE.name, '.bazel-9.0.1-linux-x86_64-wrapped')
        with patch('site_coordinator_qualification.Path.resolve', side_effect=lambda strict: BAZEL_NATIVE):
            self.assertEqual(version_command('bazel'), [str(BAZEL_NATIVE), '--version'])
        with patch('site_coordinator_qualification.Path.resolve', return_value=Path('/nix/store/other/bin/bazel')):
            with self.assertRaises(ValueError):
                version_command('bazel')
        with patch('site_coordinator_qualification.Path.resolve', return_value=JDK / 'lib/openjdk/bin/java'):
            self.assertEqual(version_command('java'), [str(JDK / 'lib/openjdk/bin/java'), '-version'])
        with patch('site_coordinator_qualification.Path.resolve', return_value=Path('/tmp/java')):
            with self.assertRaises(ValueError):
                version_command('java')
        with self.assertRaises(ValueError):
            version_command('build')

    def test_versions_require_actual_binary_output(self):
        validate_versions(b'bazel 9.0.1\n', b'openjdk version "21.0.10"\nOpenJDK Runtime Environment (build 21.0.10+7)')
        for bazel, java in ((b'bazel 8.6.0', b'21.0.10+7'), (b'bazel 9.0.1', b'openjdk version "17"')):
            with self.assertRaises(ValueError):
                validate_versions(bazel, java)


if __name__ == '__main__':
    unittest.main()
