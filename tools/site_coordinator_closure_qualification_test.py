"""Pure closure/evidence predicates with disposable SQLite and injected NAR streams.

No site coordinator, Nix process, daemon, or real store/database is invoked.
"""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import site_coordinator_closure_qualification as qualification
from cached_nix_inventory import snapshot_inventory
from verify_cached_nars import confirm_nar, verify


DEPENDENCY = '/nix/store/' + 'a' * 32 + '-shared-dependency'
UNRELATED = '/nix/store/' + 'b' * 32 + '-unrelated'


def row(path, references=(), payload=b'fixture-nar'):
    return {'path': path, 'references': sorted(references),
            'narHash': 'sha256:' + hashlib.sha256(payload).hexdigest(), 'narSize': len(payload)}


def rows():
    return sorted([row(qualification.BAZEL_ROOT, [DEPENDENCY]),
                   row(qualification.JDK, [DEPENDENCY, qualification.JDK]),
                   row(DEPENDENCY)], key=lambda value: value['path'])


def nar_receipt(content, digest, nix):
    # Exercise the actual verifier's parsing and coverage, without launching Nix.
    def stream(serializer, item, deadline):
        if serializer != qualification.NIX:
            raise ValueError('unexpected serializer')
        payload = b'fixture-nar'
        confirm_nar(len(payload), hashlib.sha256(payload).hexdigest(), item)
        return len(payload)
    return verify(content, digest, nix, stream=stream)


def evidence(inputs):
    candidate = {'schema_version': 1, 'status': 'candidate-settings-only',
                 'bazel': qualification.BAZEL, 'java_home': qualification.JDK,
                 'bazel_version': '9.0.1', 'java_version': '21.0.10+7',
                 'source': qualification.SOURCE, 'source_revision': qualification.REVISION,
                 'source_nar_hash': qualification.SOURCE_NAR, 'input_sha256': inputs,
                 'runtime_outputs_match': True, 'realization': False,
                 'execution_authority': False, 'closure_verified': False,
                 'binary_versions_verified': False}
    version = {'schema_version': 1, 'status': 'version-and-byte-qualified-site-coordinator',
               'bazel': qualification.BAZEL, 'java_home': qualification.JDK,
               'bazel_version': '9.0.1', 'java_version': '21.0.10+7',
               'candidate': str(qualification.CANDIDATE), 'candidate_sha256': qualification.CANDIDATE_SHA256,
               'binary_versions_verified': True, 'closure_verified': False, 'execution_authority': False,
               'binaries': copy.deepcopy(qualification.BINARIES),
               'site_bazelversion': {'sha256': qualification.SITE_VERSION_SHA256, 'bytes': 6, 'mode': '0o644'},
               **copy.deepcopy(qualification.WRAPPERS)}
    return candidate, version


class ClosureQualificationTest(unittest.TestCase):
    def test_exact_readonly_snapshot_and_shared_cycle_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'db.sqlite'
            connection = sqlite3.connect(database)
            connection.executescript('CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY, path TEXT, hash TEXT, narSize INTEGER); CREATE TABLE Refs(referrer INTEGER, reference INTEGER);')
            expected = rows()
            ids = {item['path']: index + 1 for index, item in enumerate(expected)}
            for item in expected:
                connection.execute('INSERT INTO ValidPaths VALUES (?, ?, ?, ?)',
                                   (ids[item['path']], item['path'], item['narHash'], item['narSize']))
                connection.executemany('INSERT INTO Refs VALUES (?, ?)',
                                       [(ids[item['path']], ids[ref]) for ref in item['references']])
            connection.commit()
            connection.close()
            before = database.read_bytes()
            observed = snapshot_inventory(database, list(qualification.ROOTS), exists=lambda path: True)
            inventory, content, digest, receipt = qualification.qualify_closure(
                observed, qualification.NIX, verifier=nar_receipt, observer=lambda path: ('immutable', path))
            self.assertEqual(observed, expected)
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(inventory['roots'], list(qualification.ROOTS))
            self.assertEqual(receipt['verifiedPaths'], 3)
            self.assertEqual(receipt['verifiedNarBytes'], 3 * len(b'fixture-nar'))
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())
            self.assertFalse(inventory['contentRehashed'])
            self.assertTrue(receipt['contentRehashed'])
            self.assertFalse(receipt['realized'])

    def test_missing_root_reference_extra_path_and_bad_hash_are_rejected(self):
        mutations = []
        mutations.append([item for item in rows() if item['path'] != qualification.JDK])
        mutations.append([item for item in rows() if item['path'] != DEPENDENCY])
        mutations.append(sorted(rows() + [row(UNRELATED)], key=lambda item: item['path']))
        bad_hash = rows()
        bad_hash[0]['narHash'] = 'sha256:' + '0' * 64
        mutations.append(bad_hash)
        duplicates = rows() + [rows()[0]]
        mutations.append(duplicates)
        for selected in mutations:
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                qualification.qualify_closure(selected, qualification.NIX,
                    verifier=nar_receipt, observer=lambda path: ('immutable', path))

    def test_partial_or_invented_verifier_success_cannot_qualify(self):
        for key, replacement in (('passed', False), ('contentRehashed', False), ('realized', True),
                                 ('flakeMappingVerified', True), ('published', True),
                                 ('inventorySha256', '0' * 64), ('verifiedPaths', 2),
                                 ('verifiedPaths', True), ('verifiedNarBytes', 1)):
            def partial(content, digest, nix):
                result = nar_receipt(content, digest, nix)
                result[key] = replacement
                return result
            with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                qualification.qualify_closure(rows(), qualification.NIX,
                    verifier=partial, observer=lambda path: ('immutable', path))
        serializer = Mock()
        with self.assertRaises(ValueError):
            qualification.qualify_closure(rows(), '/usr/bin/nix', verifier=serializer)
        serializer.assert_not_called()

    def test_changed_object_custody_invalidates_completed_hashes(self):
        observations = {}
        def changing(path):
            observations[path] = observations.get(path, 0) + 1
            return observations[path]
        with self.assertRaises(ValueError):
            qualification.qualify_closure(rows(), qualification.NIX, verifier=nar_receipt, observer=changing)

    def test_candidate_inputs_version_and_native_identity_are_independent(self):
        contents = {name: b'public fixture' for name in qualification.INPUTS}
        contents['flake.lock'] = json.dumps({'nodes': {'nixpkgs': {'locked': {
            'rev': qualification.REVISION, 'narHash': qualification.SOURCE_NAR}}}}).encode()
        digests = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
        candidate, version = evidence(digests)
        with patch.object(qualification, 'INPUTS', digests):
            qualification.validate_evidence(candidate, version, contents, b'9.0.1\n')
            for which, key, replacement in (
                    ('candidate', 'bazel', '/nix/store/foreign/bin/bazel'),
                    ('candidate', 'source_revision', '0' * 40),
                    ('candidate', 'runtime_outputs_match', False),
                    ('candidate', 'execution_authority', True),
                    ('version', 'candidate_sha256', '0' * 64),
                    ('version', 'binary_versions_verified', False),
                    ('version', 'closure_verified', True),
                    ('version', 'binaries', {}),
                    ('version', 'status', 'verified-site-toolchain')):
                altered_candidate, altered_version = copy.deepcopy(candidate), copy.deepcopy(version)
                (altered_candidate if which == 'candidate' else altered_version)[key] = replacement
                with self.subTest(which=which, key=key), self.assertRaises(ValueError):
                    qualification.validate_evidence(altered_candidate, altered_version, contents, b'9.0.1\n')
            changed = dict(contents, **{'flake.nix': b'changed source'})
            with self.assertRaises(ValueError):
                qualification.validate_evidence(candidate, version, changed, b'9.0.1\n')
            with self.assertRaises(ValueError):
                qualification.validate_evidence(candidate, version, contents, b'8.6.0\n')

    def test_receipt_selection_never_falls_back_or_accepts_duplicate_keys(self):
        with patch.object(qualification, 'file_bytes') as reader:
            with self.assertRaises(ValueError):
                qualification.selected_receipt(qualification.CANDIDATE, '0' * 64, qualification.CANDIDATE_SHA256)
            reader.assert_not_called()
            reader.return_value = (b'{}', {'sha256': '0' * 64})
            with self.assertRaises(ValueError):
                qualification.selected_receipt(qualification.CANDIDATE,
                    qualification.CANDIDATE_SHA256, qualification.CANDIDATE_SHA256)
            reader.return_value = (b'{"status":"partial","status":"verified"}',
                                   {'sha256': qualification.CANDIDATE_SHA256})
            with self.assertRaises(ValueError):
                qualification.selected_receipt(qualification.CANDIDATE,
                    qualification.CANDIDATE_SHA256, qualification.CANDIDATE_SHA256)

    def test_producer_persists_full_closure_and_keeps_execution_authority_separate(self):
        contents = {name: b'public fixture' for name in qualification.INPUTS}
        contents['flake.lock'] = json.dumps({'nodes': {'nixpkgs': {'locked': {
            'rev': qualification.REVISION, 'narHash': qualification.SOURCE_NAR}}}}).encode()
        digests = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
        candidate, version = evidence(digests)
        def read(path, maximum, immutable=False):
            selected = str(path)
            if selected == qualification.NIX:
                self.assertTrue(immutable)
                payload = b'\x7fELFfixture'
            elif Path(path) == qualification.SITE / '.bazelversion':
                payload = b'9.0.1\n'
            else:
                payload = contents[Path(path).relative_to(qualification.SITE).as_posix()]
            return payload, {'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload),
                             'mode': '0o555' if immutable else '0o644'}
        def receipt(path, selected, expected):
            self.assertEqual(selected, expected)
            return candidate if path == qualification.CANDIDATE else version
        snapshot = Mock(return_value=rows())
        identities = {**copy.deepcopy(qualification.BINARIES), **copy.deepcopy(qualification.WRAPPERS)}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(qualification, 'INPUTS', digests), \
                patch.object(qualification, 'file_bytes', side_effect=read), \
                patch.object(qualification, 'selected_receipt', side_effect=receipt), \
                patch.object(qualification, 'current_binary_identities', return_value=identities), \
                patch.object(qualification.Path, 'resolve', autospec=True, side_effect=lambda path, strict=False: path):
            output = Path(directory) / 'proof'
            result = qualification.produce(qualification.NIX, qualification.CANDIDATE_SHA256,
                qualification.VERSION_RECEIPT_SHA256, output, snapshotter=snapshot,
                verifier=nar_receipt, observer=lambda path: ('immutable', path))
            snapshot.assert_called_once_with(qualification.DATABASE, list(qualification.ROOTS))
            report_bytes = (output / 'site-coordinator-closure-qualification.json').read_bytes()
            report = json.loads(report_bytes)
            inventory_bytes = (output / 'coordinator-inventory.json').read_bytes()
            self.assertEqual(report['status'], 'verified-site-toolchain')
            self.assertTrue(report['closure_verified'])
            self.assertTrue(report['content_rehashed'])
            self.assertFalse(report['execution_authority'])
            self.assertFalse(report['realized'])
            self.assertEqual(report['bazel_executable'], qualification.BAZEL_NATIVE)
            self.assertEqual(report['roots'], list(qualification.ROOTS))
            self.assertEqual(report['verified_paths'], 3)
            self.assertEqual(report['inventory_sha256'], hashlib.sha256(inventory_bytes).hexdigest())
            self.assertEqual(result['receipt_sha256'], hashlib.sha256(report_bytes).hexdigest())
            self.assertEqual(report['binary_qualification_sha256'], qualification.VERSION_RECEIPT_SHA256)
            self.assertNotIn('receipt_sha256', report)

    def test_evidence_write_is_exclusive_private_and_does_not_follow_final_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qualification.write_exclusive(root, 'inventory.json', b'public bytes')
            output = root / 'inventory.json'
            self.assertEqual(output.read_bytes(), b'public bytes')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                qualification.write_exclusive(root, 'inventory.json', b'replacement')
            foreign = root / 'foreign'
            foreign.write_bytes(b'preserve')
            (root / 'link.json').symlink_to(foreign)
            with self.assertRaises(FileExistsError):
                qualification.write_exclusive(root, 'link.json', b'replacement')
            self.assertEqual(foreign.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
