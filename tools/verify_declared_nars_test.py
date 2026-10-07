import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nar_descriptor import hash_descriptor
from verify_declared_nars import metadata_alias_roots, open_declared, verify


class DeclaredNarsTest(unittest.TestCase):
    def test_bazel_metadata_derived_alias_namespaces(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            canonical = base / 'canonical-repository'
            (canonical / 'regular').mkdir(parents=True)
            metadata = canonical / 'nar-descriptors.json'
            metadata.write_text('{}')
            original = base / 'immutable-input'
            original.write_bytes(b'abc')
            (canonical / 'regular/00000000').symlink_to(original)
            execroot = base / 'execroot'
            execroot.mkdir()
            (execroot / 'external-repository').symlink_to(canonical, target_is_directory=True)
            logical = execroot / 'external-repository'
            runfiles = base / 'runfiles-repository'
            (runfiles / 'regular').mkdir(parents=True)
            selected = runfiles / 'nar-descriptors.json'
            selected.symlink_to(logical / 'nar-descriptors.json')
            label = runfiles / 'regular/00000000'
            label.symlink_to(logical / 'regular/00000000')
            roots = metadata_alias_roots(selected)
            self.assertIn(logical, roots)
            self.assertIn(canonical, roots)
            with open_declared(label, [root / 'regular/00000000' for root in roots], str(original), {'size': 3, 'executable': False}) as stream:
                self.assertEqual(stream.read(), b'abc')

    def fixture(self):
        root = '/nix/store/' + 'a' * 32 + '-fixture'
        descriptor = {'schemaVersion': 1, 'root': root, 'nodes': [
            {'path': '', 'type': 'directory'},
            {'path': 'data', 'type': 'regular', 'size': 3, 'executable': False},
            {'path': 'inert', 'type': 'symlink', 'target': '/outside/never-read'},
        ]}
        result = hash_descriptor(descriptor, opener=lambda *_: io.BytesIO(b'abc'))
        inventory = {'schemaVersion': 1, 'roots': [root], 'paths': [{'path': root, 'narHash': result['narHash'], 'narSize': result['narSize'], 'references': []}]}
        content = json.dumps(inventory).encode()
        digest = hashlib.sha256(content).hexdigest()
        bundle = {'schemaVersion': 1, 'inventorySha256': digest, 'roots': [{'descriptor': descriptor, 'regularInputs': {'data': 'regular/00000000'}}]}
        return content, digest, bundle

    def test_only_declared_regular_label_is_opened(self):
        content, digest, bundle = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'regular').mkdir()
            (root / 'regular/00000000').write_bytes(b'abc')
            result = verify(content, digest, json.dumps(bundle).encode(), root, root)
            self.assertEqual(result['verifiedRegularInputs'], 1)
            self.assertFalse(result['linkTargetsFollowed'])
            self.assertFalse(result['executionAuthority'])
            bundle['roots'][0]['regularInputs'] = {}
            with self.assertRaises(ValueError):
                verify(content, digest, json.dumps(bundle).encode(), root, root)

    def test_label_escape_refused_before_target_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            label, outside = root / 'label', root / 'private-target'
            label.symlink_to(outside)
            original = os.lstat
            def guard(path, *args, **kwargs):
                if Path(path) == outside:
                    self.fail('undeclared target metadata read')
                return original(path, *args, **kwargs)
            with patch('verify_declared_nars.os.lstat', guard), self.assertRaises(ValueError):
                open_declared(label, label, '/nix/store/' + 'a' * 32 + '-fixture', {'size': 0, 'executable': False})


if __name__ == '__main__':
    unittest.main()
