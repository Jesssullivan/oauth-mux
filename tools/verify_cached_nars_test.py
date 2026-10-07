import base64
import hashlib
import json
import unittest

from verify_cached_nars import MAX_BYTES, confirm_nar, expected_hash, parse_inventory, verify


class VerifyNarsTest(unittest.TestCase):
    def fixture(self):
        path = '/nix/store/' + 'a' * 32 + '-fixture'
        row = {'path': path, 'narHash': 'sha256:' + 'b' * 64, 'narSize': 64, 'references': []}
        return {'schemaVersion': 1, 'roots': [path], 'paths': [row]}

    def encode(self, value):
        content = json.dumps(value).encode()
        return content, hashlib.sha256(content).hexdigest()

    def test_digest_and_graph_fail_closed(self):
        content, digest = self.encode(self.fixture())
        with self.assertRaises(ValueError):
            parse_inventory(content + b' ', digest)
        fixture = self.fixture()
        fixture['paths'][0]['references'] = ['/nix/store/' + 'c' * 32 + '-missing']
        with self.assertRaises(ValueError):
            parse_inventory(*self.encode(fixture))

    def test_aggregate_bound_before_execution(self):
        fixture = self.fixture()
        fixture['paths'][0]['narSize'] = MAX_BYTES + 1
        with self.assertRaises(ValueError):
            parse_inventory(*self.encode(fixture))

    def test_receipt_never_claims_flake_mapping(self):
        calls = []
        def fake(nix, row, deadline):
            calls.append(row['path'])
            return row['narSize']
        content, digest = self.encode(self.fixture())
        result = verify(content, digest, '/declared-nix', stream=fake)
        self.assertEqual(result['inventorySha256'], digest)
        self.assertEqual(result['verifiedNarBytes'], 64)
        self.assertEqual(len(calls), 1)
        self.assertTrue(result['contentRehashed'])
        self.assertFalse(result['flakeMappingVerified'])
        self.assertFalse(result['realized'])

    def test_hash_encoding_and_invalid_hash(self):
        raw = bytes(range(32))
        self.assertEqual(expected_hash('sha256-' + base64.b64encode(raw).decode()), raw.hex())
        with self.assertRaises(ValueError):
            expected_hash('sha256:invalid')

    def test_detects_same_size_corruption_and_truncation(self):
        row = self.fixture()['paths'][0]
        confirm_nar(64, 'b' * 64, row)
        with self.assertRaises(ValueError):
            confirm_nar(64, 'c' * 64, row)
        with self.assertRaises(ValueError):
            confirm_nar(63, 'b' * 64, row)


if __name__ == '__main__':
    unittest.main()
