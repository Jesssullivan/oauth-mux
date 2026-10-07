"""Offline mapping and source-contract tests; never invoke Nix."""
import json
import unittest
from codex_sdk_settings import TOOLS, DECLARATION, NAR, REVISION, expression, rc_bytes, validate_inputs, verify_mapping


class SettingsTests(unittest.TestCase):
    def mapping(self):
        value = {tool: '/nix/store/' + 'a' * 32 + '-' + tool for tool in TOOLS}
        value['testPath'] = ':'.join(value[tool] + '/bin' for tool in TOOLS)
        return value

    def test_exact_locked_expression_and_source_declaration(self):
        lock = json.dumps({'nodes': {'nixpkgs': {'locked': {'rev': REVISION, 'narHash': NAR}}}}).encode()
        validate_inputs(DECLARATION.encode(), lock)
        self.assertIn('/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source', expression())
        with self.assertRaisesRegex(ValueError, 'declaration drift'):
            validate_inputs(DECLARATION.replace('pkgs.git ', '').encode(), lock)

    def test_evaluation_alone_cannot_assert_available_tools(self):
        value = self.mapping()
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            verify_mapping(value, exists=lambda path: False)
        path, binaries = verify_mapping(value, exists=lambda path: True, executable=lambda path: True)
        self.assertEqual(path, value['testPath'])
        self.assertEqual(binaries['bash'], value['bash'] + '/bin/bash')
        value['testPath'] += ':/usr/bin'
        with self.assertRaisesRegex(ValueError, 'PATH mismatch'):
            verify_mapping(value, exists=lambda path: True, executable=lambda path: True)

    def test_rc_contains_only_declared_distdir_and_locked_path(self):
        path = self.mapping()['testPath']
        self.assertEqual(rc_bytes('/owned/bundle', path).decode().splitlines(),
                         ['common --distdir=/owned/bundle', 'test --test_env=PATH=' + path])
        for altered in ('/owned/../bundle', '/owned/bundle\ncommon --remote_executor=x', '/owned//bundle'):
            with self.assertRaises(ValueError):
                rc_bytes(altered, path)


if __name__ == '__main__':
    unittest.main()
