"""Disposable public metadata predicates only; no producer, Nix or coordinator executes."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import site_coordinator_selection as selection
import site_coordinator_qualification as qualification


class SelectionModels(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name).resolve(strict=True)
        # Only the disposable fixture's external ancestry is modeled. The real
        # reader still checks the fixture root/descendants and every file leaf.
        original_ancestor = qualification.validate_ancestor
        external_parents = frozenset(self.state.parents)
        def fixture_ancestor(path, info, immutable):
            if Path(path) in external_parents:
                self.assertFalse(immutable)
                self.assertIn(info.st_uid, (0, os.getuid()))
                return
            return original_ancestor(path, info, immutable)
        ancestry = patch.object(qualification, 'validate_ancestor', side_effect=fixture_ancestor)
        ancestry.start(); self.addCleanup(ancestry.stop)
        roots = patch.object(selection, 'ROOTS', (self.state,))
        roots.start(); self.addCleanup(roots.stop)
        self.epoch = self.state / '55fc1408-1234-4d7d-ade9-1f893fd9b260'
        self.epoch.mkdir(mode=0o700)
        self.candidate = self.epoch / selection.SUFFIXES['candidate']
        self.candidate.parent.mkdir(parents=True)
        self.candidate.write_bytes(b'{"public":"candidate fixture"}\n')
        candidate_pin = patch.object(selection, 'CANDIDATE_SHA256', hashlib.sha256(self.candidate.read_bytes()).hexdigest())
        candidate_pin.start(); self.addCleanup(candidate_pin.stop)
        self.version = self.epoch / selection.SUFFIXES['version']
        self.version.parent.mkdir(parents=True)
        self.version.write_bytes(b'{"public":"version fixture"}\n')
        self.descriptor = self.epoch / 'site-coordinator-inputs.json'
        self.value = {'schema_version': 1, 'candidate': {'path': str(self.candidate), 'sha256': selection.CANDIDATE_SHA256}, 'version': None}

    def write(self):
        self.descriptor.write_text(json.dumps(self.value) + '\n')
        return hashlib.sha256(self.descriptor.read_bytes()).hexdigest()

    def test_exact_version_and_closure_singletons_bind_current_origin_bytes(self):
        pin = self.write()
        label = '//tools:site_coordinator_binary_qualification'
        self.assertTrue(selection.admitted('standard', ['test', label], self.descriptor, pin))
        for profile, vector in [('site', ['test', label]), ('standard', ['build', label]),
                                ('standard', ['test', label, '//:docs_check'])]:
            with self.assertRaises(ValueError):selection.admitted(profile, vector, self.descriptor, pin)
        with self.assertRaises(ValueError):selection.admitted('standard', ['test', label])
        closure = '//tools:site_coordinator_closure_qualification'
        with self.assertRaises(ValueError):selection.admitted('standard', ['test', closure], self.descriptor, pin)
        self.value['version'] = {'path': str(self.version), 'sha256': hashlib.sha256(self.version.read_bytes()).hexdigest()}
        pin = self.write()
        self.assertTrue(selection.admitted('standard', ['test', closure], self.descriptor, pin))
        with self.assertRaises(ValueError):selection.admitted('standard', ['test', label], self.descriptor, pin)
        self.version.write_bytes(b'changed public version')
        with self.assertRaises(ValueError):selection.admitted('standard', ['test', closure], self.descriptor, pin)

    def test_closed_fields_types_duplicate_keys_and_descriptor_digest_fail(self):
        pin = self.write()
        with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, '0' * 64)
        original = dict(self.value)
        for value in [{**original, 'schema_version': True}, {**original, 'unexpected': 1},
                      {**original, 'candidate': None}, {**original, 'candidate': {'path': str(self.candidate), 'sha256': [selection.CANDIDATE_SHA256]}}]:
            self.value = value
            pin = self.write()
            with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, pin)
        self.descriptor.write_text('{"schema_version":1,"schema_version":1,"candidate":{},"version":null}\n')
        with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, hashlib.sha256(self.descriptor.read_bytes()).hexdigest())

    def test_legacy_cache_and_arbitrary_role_paths_do_not_enter_fresh_lane(self):
        for value in [str(self.state / ('cache-v2-' + 'a' * 64) / selection.SUFFIXES['candidate']),
                      str(self.candidate.with_name('arbitrary.json')), str(self.version),
                      str(self.candidate).replace('55fc1408', '55FC1408')]:
            with self.assertRaises(ValueError):selection.location(value, 'candidate')

    def test_declared_projection_preserves_descriptor_origin_and_requires_all_selected_bytes(self):
        pin = self.write()
        projected = self.epoch / 'declared';projected.mkdir()
        descriptor = projected / 'selection.json';descriptor.write_bytes(self.descriptor.read_bytes())
        digest = projected / 'selection.sha256';digest.write_text(pin + '\n')
        candidate = projected / 'candidate.json';candidate.write_bytes(self.candidate.read_bytes())
        self.assertEqual(selection.projected(descriptor, digest, candidate), self.value)
        candidate.write_bytes(b'changed declared bytes')
        with self.assertRaises(ValueError):selection.projected(descriptor, digest, candidate)
        candidate.write_bytes(self.candidate.read_bytes());digest.write_text('0' * 64 + '\n')
        with self.assertRaises(ValueError):selection.projected(descriptor, digest, candidate)

    def test_alias_and_hardlink_descriptor_refuse(self):
        pin = self.write()
        # The fixture seam must not exempt an actual selected ancestor.
        self.epoch.chmod(0o777)
        try:
            with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, pin)
        finally:
            self.epoch.chmod(0o700)
        saved = self.epoch / 'saved.json';os.link(self.descriptor, saved)
        with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, pin)
        saved.unlink()
        raw = self.descriptor.read_bytes();self.descriptor.unlink();saved.write_bytes(raw);self.descriptor.symlink_to(saved)
        with self.assertRaises(ValueError):selection.read_descriptor(self.descriptor, pin)


if __name__ == '__main__':unittest.main()
