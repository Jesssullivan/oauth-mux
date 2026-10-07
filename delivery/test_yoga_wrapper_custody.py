"""Real descriptor refusal boundaries with explicitly modeled /srv/store anchors.

Whole-authority tests model immutable store observations; no Nix/backend,
browser, service, network or executor runs. The helper remains comparison data.
"""
import copy
from contextlib import closing
import hashlib
import os
from pathlib import Path
import stat
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yoga_wrapper_custody as custody
import yoga_wrapper_authority as authority
import test_yoga_wrapper_authority as metadata_fixture


class DescriptorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.path = '/srv/yoga-model/input'
        self.local = self.root / 'input'; self.local.write_bytes(b'fixed'); self.local.chmod(0o600)
        self.deadline = time.monotonic_ns() + 1100 * 10**9
        def parent(path, uid, deadline, now):
            custody.budget(deadline, now)
            relative = Path(path).relative_to('/srv/yoga-model')
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            observations = [custody.parent_witness(os.fstat(descriptor))]
            try:
                for name in relative.parts[:-1]:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        info = os.fstat(child)
                        custody.require(info.st_uid == uid and not info.st_mode & 0o022, 'custody_invalid')
                        observations.append(custody.parent_witness(info))
                    except BaseException:
                        os.close(child); raise
                    os.close(descriptor); descriptor = child
                return descriptor, tuple(observations)
            except BaseException:
                os.close(descriptor); raise
        selected = patch.object(custody, 'parent', side_effect=parent)
        selected.start(); self.addCleanup(selected.stop)

    def capture(self, **changes):
        values = dict(path=self.path, expected=hashlib.sha256(b'fixed').hexdigest(), maximum=8192,
                      deadline=self.deadline, now=time.monotonic_ns)
        values.update(changes)
        return custody.Captured(**values)

    def test_real_regular_input_holds_both_descriptors_until_close(self):
        item = self.capture(); leaf, parent = item.fd, item.directory
        self.assertEqual(item.data, b'fixed'); item.check()
        os.fstat(leaf); os.fstat(parent)
        item.close(); item.close()
        for descriptor in (leaf, parent):
            with self.assertRaises(OSError): os.fstat(descriptor)

    def test_fifo_alias_directory_and_oversize_refuse_before_read(self):
        for kind in ('fifo', 'alias', 'directory', 'oversize'):
            with self.subTest(kind=kind):
                self.local.unlink()
                if kind == 'fifo': os.mkfifo(self.local, 0o600)
                elif kind == 'alias': self.local.symlink_to('target')
                elif kind == 'directory': self.local.mkdir(mode=0o700)
                else: self.local.write_bytes(b'x' * 8193)
                with patch.object(custody.os, 'read') as read, self.assertRaises((ValueError, OSError)):
                    self.capture()
                read.assert_not_called()
                if self.local.is_dir(): self.local.rmdir()
                else: self.local.unlink()
                self.local.write_bytes(b'fixed'); self.local.chmod(0o600)

    def test_wrong_digest_writable_mode_and_nonexecutable_refuse(self):
        with self.assertRaisesRegex(custody.CustodyRefusal, 'digest_mismatch'): self.capture(expected='0' * 64)
        self.local.chmod(0o622)
        with self.assertRaisesRegex(custody.CustodyRefusal, 'custody_invalid'): self.capture()
        self.local.chmod(0o600)
        with self.assertRaisesRegex(custody.CustodyRefusal, 'custody_invalid'): self.capture(executable=True)

    def test_named_replacement_and_earlier_in_place_drift_refuse(self):
        item = self.capture()
        try:
            self.local.rename(self.root / 'old'); self.local.write_bytes(b'fixed'); self.local.chmod(0o600)
            with self.assertRaisesRegex(custody.CustodyRefusal, 'input_changed'): item.check()
        finally: item.close()
        item = self.capture()
        try:
            self.local.write_bytes(b'other')
            with self.assertRaisesRegex(custody.CustodyRefusal, 'input_changed'): item.check()
        finally: item.close()

    def test_parent_replacement_refuses_even_same_leaf_bytes(self):
        directory = self.root / 'child'; directory.mkdir(mode=0o700)
        (directory / 'input').write_bytes(b'fixed')
        item = self.capture(path='/srv/yoga-model/child/input')
        try:
            directory.rename(self.root / 'old-child'); directory.mkdir(mode=0o700)
            (directory / 'input').write_bytes(b'fixed')
            with self.assertRaisesRegex(custody.CustodyRefusal, 'input_changed'): item.check()
        finally: item.close()

    def test_final_sha_reobservation_refuses_content_substitution_with_unchanged_stats(self):
        item = self.capture()
        try:
            with patch.object(custody.os, 'pread', side_effect=(b'other', b'')):
                with self.assertRaisesRegex(custody.CustodyRefusal, 'digest_mismatch'): item.check()
            with patch.object(custody.os, 'pread', side_effect=(b'x' * 8193,)):
                with self.assertRaisesRegex(custody.CustodyRefusal, 'byte_bound'): item.check()
        finally: item.close()

    def test_immutable_executable_capture_keeps_metadata_only_and_no_read(self):
        self.local.chmod(0o500)
        with patch.object(custody.os, 'read') as read, patch.object(custody.os, 'pread') as reread:
            item = self.capture(expected=None, executable=True, read=False)
            try: item.check()
            finally: item.close()
            read.assert_not_called(); reread.assert_not_called()

    def test_fstat_failure_unwinds_new_leaf_and_parent(self):
        real_fstat = os.fstat
        opened = []
        real_open = os.open
        def selected_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs); opened.append(descriptor); return descriptor
        def selected_fstat(descriptor):
            if len(opened) == 2 and descriptor == opened[-1]: raise OSError('injected metadata failure')
            return real_fstat(descriptor)
        with patch.object(custody.os, 'open', side_effect=selected_open), patch.object(custody.os, 'fstat', side_effect=selected_fstat):
            with self.assertRaises(OSError): self.capture()
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError): real_fstat(descriptor)

    def test_original_deadline_refuses_before_open_and_final_expiry(self):
        with patch.object(custody.os, 'open') as opened:
            for deadline in (True, 0, self.deadline):
                with self.assertRaises(custody.CustodyRefusal): self.capture(deadline=deadline, now=lambda: self.deadline)
            opened.assert_not_called()
        clock = [1]
        item = self.capture(deadline=100 * 10**9, now=lambda: clock[0])
        real_stat = os.stat
        def named(*args, **kwargs):
            result = real_stat(*args, **kwargs); clock[0] = item.deadline; return result
        try:
            with patch.object(custody.os, 'stat', side_effect=named):
                with self.assertRaisesRegex(custody.CustodyRefusal, 'deadline_exceeded'): item.check()
        finally: item.close()


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.model = metadata_fixture.WrapperTests(methodName='runTest'); self.model.setUp()
        m = self.model
        self.nar = {'schemaVersion': 1, 'passed': True, 'inventorySha256': m.inventory_sha,
            'descriptorSha256': '4' * 64, 'verifiedPaths': len(m.inventory['paths']), 'verifiedRegularInputs': 1,
            'verifiedNarBytes': sum(row['narSize'] for row in m.inventory['paths']), 'contentRehashed': True,
            **{name: False for name in ('linkTargetsFollowed', 'executionAuthority', 'flakeMappingVerified', 'realized')}}
        self.selected = {
            'companion': {'path': '/srv/yoga-proof/companion', 'sha256': m.companion_sha},
            'nativeManifest': {'path': m.native_path, 'sha256': authority.digest(m.native_bytes)},
            'registeredNativeManifest': {'path': m.roots['native_manifest'], 'sha256': authority.digest(m.registered_bytes)},
            'controllerInventory': {'path': '/srv/yoga-proof/inventory', 'sha256': m.inventory_sha},
            'controllerNarProof': {'path': '/srv/yoga-proof/nar', 'sha256': ''}, 'controllerTools': m.tools}
        self.items = []
        self.refresh()
        self.registry = Mock()
        def capture(path, expected, maximum, deadline, now, **options):
            data = self.data.get(path, b'')
            if expected is not None:
                custody.require(hashlib.sha256(data).hexdigest() == expected, 'digest_mismatch')
            item = SimpleNamespace(path=path, data=data, check=Mock(), close=Mock())
            self.items.append(item); return item
        for selected in (patch.object(custody, 'Captured', side_effect=capture), patch.object(custody, 'parent', return_value=(7, ())),
                         patch.object(custody.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)),
                         patch.object(custody.os, 'readlink', return_value=m.roots['native_manifest']), patch.object(custody.os, 'close')):
            selected.start(); self.addCleanup(selected.stop)

    def refresh(self):
        nar_bytes = authority.canonical(self.nar) + b'\n'
        self.selected['controllerNarProof']['sha256'] = authority.digest(nar_bytes)
        self.data = {self.selected['companion']['path']: self.model.companion_bytes,
            self.selected['nativeManifest']['path']: self.model.native_bytes,
            self.selected['registeredNativeManifest']['path']: self.model.registered_bytes,
            self.selected['controllerInventory']['path']: self.model.inventory_bytes,
            self.selected['controllerNarProof']['path']: nar_bytes, **dict(zip(self.model.paths.values(), self.model.wrappers.values()))}

    def capture(self):
        return custody.AuthorityCapture(self.selected, self.model.paths, self.model.shas, 1000 * 10**9,
            now=lambda: 1, validator=authority, registry=self.registry)

    def test_full_join_requires_receipt_registry_and_capture_wide_reobservation(self):
        with self.capture() as held:
            self.assertEqual(len(held.result.bindings), 3)
            self.assertGreaterEqual(self.registry.call_count, 1)
            self.assertTrue(all(item.check.call_count >= 2 for item in self.items))
            self.assertFalse(any(item.close.called for item in self.items))
        self.assertEqual(self.registry.call_count, 2)
        self.assertTrue(all(item.close.call_count == 1 for item in self.items))

    def test_nar_pass_alone_unknown_fields_and_count_substitutions_refuse(self):
        original = copy.deepcopy(self.nar)
        for change in ({'passed': False}, {'contentRehashed': False}, {'extra': True}, {'verifiedPaths': True},
                       {'verifiedNarBytes': 1}, {'inventorySha256': '0' * 64}, {'executionAuthority': True}):
            with self.subTest(change=change):
                self.nar = dict(original, **change); self.refresh()
                with self.assertRaisesRegex(custody.CustodyRefusal, 'nar_unqualified'): self.capture()
                self.assertTrue(all(item.close.called for item in self.items))

    def test_nar_raw_digest_is_independent_and_not_inferred_from_companion(self):
        self.selected['controllerNarProof']['sha256'] = '0' * 64
        with self.assertRaisesRegex(custody.CustodyRefusal, 'digest_mismatch'): self.capture()
        self.registry.assert_not_called()

    def test_current_registry_or_registered_link_drift_refuses_and_closes_all(self):
        self.registry.side_effect = custody.CustodyRefusal('registry_changed')
        with self.assertRaisesRegex(custody.CustodyRefusal, 'registry_changed'): self.capture()
        self.assertTrue(all(item.close.called for item in self.items))
        self.registry.side_effect = None
        with patch.object(custody.os, 'readlink', return_value='/etc/native.json'):
            with self.assertRaisesRegex(custody.CustodyRefusal, 'registry_changed'): self.capture()
        self.assertTrue(all(item.close.called for item in self.items))

    def test_final_earlier_descriptor_drift_refuses_context_exit_and_closes(self):
        held = self.capture()
        self.items[0].check.side_effect = custody.CustodyRefusal('input_changed')
        with self.assertRaisesRegex(custody.CustodyRefusal, 'input_changed'):
            with held: pass
        self.assertTrue(all(item.close.called for item in self.items))

    def test_envelope_and_helper_source_shapes_are_closed(self):
        for edit in (lambda value: value.pop('controllerNarProof'), lambda value: value.update(extra=True),
                     lambda value: value['nativeManifest'].update(path='/home/user/native.json'),
                     lambda value: value['companion'].update(sha256=True)):
            value = copy.deepcopy(self.selected); edit(value)
            with self.assertRaises(custody.CustodyRefusal): custody.envelope(value)
        for hashes in ({}, {name: '0' * 64 for name in custody.HELPER_FILES} | {'extra': '0' * 64}):
            with self.assertRaises(custody.CustodyRefusal): custody.source_hashes(hashes)

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.model = metadata_fixture.WrapperTests(methodName='runTest'); self.model.setUp()

    def test_actual_readonly_sqlite_registration_and_reference_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'registry.sqlite'
            rows = self.model.inventory['paths']
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute('CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY,path TEXT,hash TEXT,narSize INTEGER)')
                connection.execute('CREATE TABLE Refs(referrer INTEGER,reference INTEGER)')
                ids = {row['path']: index for index, row in enumerate(rows, 1)}
                for row in rows:
                    connection.execute('INSERT INTO ValidPaths VALUES(?,?,?,?)', (ids[row['path']], row['path'], row['narHash'], row['narSize']))
                    for ref in row['references']:
                        connection.execute('INSERT INTO Refs VALUES(?,?)', (ids[row['path']], ids[ref]))
            with patch.object(custody.os, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o555)):
                custody.registered_rows(rows, 1000 * 10**9, now=lambda: 1, database=str(database))
                with closing(sqlite3.connect(database)) as connection, connection:
                    connection.execute('DELETE FROM Refs WHERE referrer=?', (ids[self.model.roots['native']],))
                with self.assertRaisesRegex(custody.CustodyRefusal, 'registry_changed'):
                    custody.registered_rows(rows, 1000 * 10**9, now=lambda: 1, database=str(database))

    def test_registry_query_failure_closes_connection(self):
        connection = Mock(); connection.execute.side_effect = sqlite3.DatabaseError('injected private diagnostic')
        with patch.object(custody.sqlite3, 'connect', return_value=connection):
            with self.assertRaises(sqlite3.DatabaseError):
                custody.registered_rows(self.model.inventory['paths'], 1000 * 10**9, now=lambda: 1)
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
