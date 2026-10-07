import unittest
from site_coordinator_settings import candidate, expression, EXPECTED_BAZEL, EXPECTED_JDK


class CandidateTests(unittest.TestCase):
    def mapping(self):
        return {'bazel': EXPECTED_BAZEL, 'java_home': EXPECTED_JDK,
                'bazel_version': '9.0.1', 'java_version': '21.0.10+7'}

    def check(self, mapping, **kwargs):
        defaults = dict(exists=lambda _: True, executable=lambda _: True, canonical=lambda p: p)
        defaults.update(kwargs)
        return candidate(mapping, **defaults)

    def test_candidate_never_authorizes(self):
        result = self.check(self.mapping())
        self.assertTrue(result['runtime_outputs_match'])
        self.assertFalse(result['execution_authority'])
        self.assertFalse(result['binary_versions_verified'])
        self.assertEqual(result['status'], 'candidate-settings-only')

    def test_changed_output_retained_honestly(self):
        mapping = self.mapping()
        mapping['bazel'] = '/nix/store/' + 'a' * 32 + '-bazel-9.0.1'
        result = self.check(mapping)
        self.assertFalse(result['runtime_outputs_match'])
        self.assertEqual(result['bazel'], mapping['bazel'] + '/bin/bazel')

    def test_missing_executable_refused(self):
        with self.assertRaises(ValueError):
            self.check(self.mapping(), exists=lambda _: False)

    def test_alias_refused(self):
        with self.assertRaises(ValueError):
            self.check(self.mapping(), canonical=lambda _: '/nix/store/other')

    def test_packaged_java_alias_accepted(self):
        def resolve(path):
            return EXPECTED_JDK + '/lib/openjdk/bin/java' if path == EXPECTED_JDK + '/bin/java' else path
        self.assertFalse(self.check(self.mapping(), canonical=resolve)['execution_authority'])

    def test_java_escape_refused(self):
        for target in [EXPECTED_BAZEL + '/lib/openjdk/bin/java', '/tmp/java',
                       EXPECTED_JDK + '/../other/bin/java', EXPECTED_JDK + '/lib/other/bin/java']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.check(self.mapping(), canonical=lambda path: target if path.endswith('/bin/java') else path)

    def test_root_alias_refused(self):
        with self.assertRaises(ValueError):
            self.check(self.mapping(), canonical=lambda path: '/tmp/jdk' if path == EXPECTED_JDK else path)

    def test_interpolation_and_wrong_version_refused(self):
        for value in ['${builtins.abort "bad"}', '/nix/store/' + 'a' * 32 + '-bad;value']:
            mapping = self.mapping()
            mapping['bazel'] = value
            with self.assertRaises(ValueError):
                self.check(mapping)
        mapping = self.mapping()
        mapping['java_version'] = '17'
        with self.assertRaises(ValueError):
            self.check(mapping)
        self.assertNotIn('${', expression())


if __name__ == '__main__':
    unittest.main()
