import hashlib
import json
import unittest

from cached_site_input_validator import validate


class CandidateValidatorTest(unittest.TestCase):
    def fixture(self):
        names = ('node', 'python', 'pnpm', 'bash', 'coreutils', 'chromium')
        packages = {name: {'out': '/nix/store/' + chr(97 + index) * 32 + '-' + name} for index, name in enumerate(names)}
        dependency = '/nix/store/' + 'g' * 32 + '-shared-config'
        roots = sorted(package['out'] for package in packages.values())
        rows = [{'path': root, 'narHash': 'sha256:' + 'a' * 64, 'narSize': 32, 'references': [dependency]} for root in roots]
        rows.append({'path': dependency, 'narHash': 'sha256:' + 'b' * 64, 'narSize': 16, 'references': []})
        return {'schemaVersion': 1, 'system': 'x86_64-linux', 'mode': 'local-sqlite-readonly-snapshot', 'provenance': {}, 'roots': roots, 'packages': packages, 'helperTools': [packages['bash']['out']], 'paths': rows, 'contentRehashed': False, 'realized': False, 'published': False}

    def run_value(self, value):
        content = json.dumps(value).encode()
        return validate(content, hashlib.sha256(content).hexdigest())

    def test_node_and_browser_are_exact_transitive_subgraphs(self):
        value = self.fixture()
        result = self.run_value(value)
        chromium = value['packages']['chromium']['out']
        node = value['packages']['node']['out']
        dependency = value['paths'][-1]['path']
        self.assertNotIn(chromium, result['nodePaths'])
        self.assertNotIn(node, result['browserPaths'])
        self.assertIn(dependency, result['nodePaths'])
        self.assertIn(dependency, result['browserPaths'])
        self.assertEqual(result['qualification'], 'pending-nar-and-shared-selection-actions')

    def test_rejects_inflated_claim_and_unknown_fields(self):
        for key, replacement in [('contentRehashed', True), ('published', True), ('credential', 'forbidden')]:
            value = self.fixture()
            value[key] = replacement
            with self.assertRaises(ValueError):
                self.run_value(value)

    def test_required_root_cannot_be_omitted(self):
        value = self.fixture()
        value['roots'].pop()
        with self.assertRaises(ValueError):
            self.run_value(value)


if __name__ == '__main__':
    unittest.main()
