"""Direct guardian physical ownership and record failures; no systemd calls."""
import json
import os
from pathlib import Path
import select
import signal
import stat
import tempfile
import time
import unittest
from unittest import mock

import yoga_local_parent_envelope as envelope
import yoga_local_console_scope as console
import guard_resident_observation as resident


class DirectGuardianModels(unittest.TestCase):
    def parent(self):
        return mock.Mock(pid=os.getpid(), image=envelope.kernel.process(os.getpid()), group=b'0::/model\n', terminal=(1, 2, 3))

    def operation(self, directory):
        entry = time.monotonic_ns()
        return envelope.OwnedOperation(str(Path(directory) / 'qualification.json'), entry,
            entry + 1200 * 10**9, self.parent(), 'omuxyogaconsole' + 'a' * 32 + '.slice', 'a' * 64, 'b' * 64)

    def test_real_record_created_private_unresolved_and_reader_carries_no_control(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            operation = self.operation(directory)
            try:
                self.assertEqual(stat.S_IMODE(os.stat(operation.path).st_mode), 0o600)
                row = envelope.read_operation(directory, operation.operation_id, operation.deadline)
                self.assertEqual(row['record']['state'], 'unresolved')
                self.assertFalse(row['cleanupControlAuthority']); self.assertFalse(row['executionAuthority'])
                self.assertFalse(row['completionQualified'])
                self.assertIsNone(row['record']['worker']); self.assertIsNone(row['record']['aggregate'])
            finally: operation.close()

    def test_real_record_named_inode_replacement_refuses_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                os.rename(operation.path, str(operation.path) + '.old')
                operation.path.write_bytes(b'foreign')
                with self.assertRaises(ValueError): operation.write()
                self.assertEqual(operation.path.read_bytes(), b'foreign')
            finally: operation.close()

    def test_real_record_symlink_hardlink_and_mode_refuse(self):
        for kind in ('symlink', 'hardlink', 'mode'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700); operation = self.operation(directory)
                try:
                    if kind == 'mode': os.chmod(operation.path, 0o644)
                    else:
                        os.rename(operation.path, str(operation.path) + '.old')
                        if kind == 'symlink': os.symlink(str(operation.path) + '.old', operation.path)
                        else: os.link(str(operation.path) + '.old', operation.path)
                    with self.assertRaises((ValueError, OSError)):
                        envelope.read_operation(directory, operation.operation_id, operation.deadline)
                finally: operation.close()

    def test_real_record_directory_rebind_and_oversize_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / 'selected'; selected.mkdir(mode=0o700)
            operation = self.operation(selected)
            try:
                os.rename(selected, Path(directory) / 'old'); selected.mkdir(mode=0o700)
                with self.assertRaises(ValueError): operation.write()
            finally: operation.close()
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                os.ftruncate(operation.fd, 16385)
                with self.assertRaises(ValueError): envelope.read_operation(directory, operation.operation_id, operation.deadline)
            finally: operation.close()

    def test_real_record_deadline_preserves_unresolved_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                initial = operation.path.read_bytes()
                with mock.patch.object(envelope.time, 'monotonic_ns', return_value=operation.deadline):
                    with self.assertRaises(ValueError): operation.terminal(True, True, True)
                self.assertEqual(initial, operation.path.read_bytes())
            finally: operation.close()

    def test_shared_cleanup_cutoff_refuses_record_with_original_time_remaining(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                initial = operation.path.read_bytes()
                operation.cleanup_cutoff = time.monotonic_ns() - 1
                self.assertLess(operation.cleanup_cutoff, operation.deadline)
                with self.assertRaises(ValueError): operation.terminal(True, True, True)
                self.assertEqual(initial, operation.path.read_bytes())
                self.assertEqual(operation.published_state, 'unresolved')
            finally: operation.close()

    def test_post_fsync_late_return_never_promotes_published_state(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                operation.cleanup_cutoff = time.monotonic_ns() + 30 * 10**9
                actual_fsync = os.fsync
                def late(descriptor):
                    actual_fsync(descriptor)
                    operation.cleanup_cutoff = time.monotonic_ns() - 1
                with mock.patch.object(envelope.os, 'fsync', side_effect=late):
                    with self.assertRaises(ValueError): operation.terminal(True, True, True)
                self.assertEqual(operation.published_state, 'unresolved')
                # Bytes alone remain observation, never completion authority.
                row = envelope.read_operation(directory, operation.operation_id, operation.deadline)
                self.assertFalse(row['cleanupControlAuthority'])
                self.assertFalse(row['executionAuthority'])
            finally: operation.close()

    def test_final_real_identity_readback_return_after_cutoff_never_promotes(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                operation.cleanup_cutoff = time.monotonic_ns() + 30 * 10**9
                actual_recheck = operation.recheck
                calls = []
                def late_identity():
                    actual_recheck()  # actual held/named file and directory checks
                    calls.append(True)
                    if len(calls) == 2:
                        operation.cleanup_cutoff = time.monotonic_ns() - 1
                with mock.patch.object(operation, 'recheck', side_effect=late_identity):
                    with self.assertRaises(ValueError): operation.terminal(True, True, True)
                self.assertEqual(len(calls), 2)
                self.assertEqual(operation.published_state, 'unresolved')
                self.assertFalse(envelope.read_operation(directory, operation.operation_id,
                    operation.deadline)['completionQualified'])
            finally: operation.close()

    def test_real_reader_duplicate_fields_and_false_empty_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                operation.row['state'] = 'empty'; operation.write()
                with self.assertRaises(ValueError): envelope.read_operation(directory, operation.operation_id, operation.deadline)
                os.pwrite(operation.fd, b'{"schemaVersion":1,"schemaVersion":1}', 0)
                os.ftruncate(operation.fd, len(b'{"schemaVersion":1,"schemaVersion":1}'))
                with self.assertRaises(ValueError): envelope.read_operation(directory, operation.operation_id, operation.deadline)
            finally: operation.close()

    def test_real_terminal_record_requires_all_three_empty_predicates(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); operation = self.operation(directory)
            try:
                for reaped, worker, aggregate in ((True, False, True), (False, True, True), (True, True, False)):
                    operation.terminal(reaped, worker, aggregate)
                    self.assertEqual(envelope.read_operation(directory, operation.operation_id, operation.deadline)['record']['state'], 'unresolved')
                operation.terminal(True, True, True)
                self.assertEqual(envelope.read_operation(directory, operation.operation_id, operation.deadline)['record']['state'], 'empty')
            finally: operation.close()

    def test_scope_policy_refuses_delegation_killmode_and_stop_timeout(self):
        facts = {'KillMode': 'control-group', 'SendSIGKILL': 'yes', 'Delegate': 'no', 'TimeoutStopUSec': '10s'}
        self.assertEqual(console.DirectManager.policy(facts), facts)
        for key, value in (('KillMode', 'process'), ('SendSIGKILL', 'no'), ('Delegate', 'yes'), ('TimeoutStopUSec', '20s')):
            with self.subTest(key=key), self.assertRaises(ValueError): console.DirectManager.policy(dict(facts, **{key: value}))

    def test_original_direct_child_is_reaped_nonblocking_before_scope_empty(self):
        child = os.fork()
        if child == 0: os._exit(7)
        pidfd = os.pidfd_open(child, 0)
        marks = []
        try:
            self.assertTrue(select.select([pidfd], [], [], 2)[0])
            scope = mock.Mock(); entry = time.monotonic_ns(); deadline = entry + 1200 * 10**9
            original = os.waitpid
            def wait(pid, options):
                self.assertEqual(pid, child); self.assertEqual(options, os.WNOHANG)
                return original(pid, options)
            with mock.patch.object(console.os, 'waitpid', side_effect=wait):
                self.assertTrue(console.terminate_child(child, pidfd, scope, False, False,
                    entry, deadline, lambda: marks.append(True), wait_timeout=lambda: 1))
            self.assertEqual(marks, [True]); scope.terminal.assert_called_once()
            scope.stop_owned.assert_called_once(); scope.cleanup.assert_called_once()
        finally:
            os.close(pidfd)

    def test_real_no_pidfd_no_go_failure_is_bounded_nonblocking(self):
        read, write = os.pipe2(os.O_CLOEXEC); child = os.fork()
        if child == 0:
            os.close(write); select.select([read], [], [], 5); os._exit(125)
        os.close(read); os.close(write)
        entry = time.monotonic_ns(); deadline = entry + 1200 * 10**9; marks = []
        original = os.waitpid
        try:
            def wait(pid, options):
                self.assertEqual(options, os.WNOHANG); return original(pid, options)
            with mock.patch.object(console.os, 'waitpid', side_effect=wait):
                console.terminate_child(child, None, None, False, False, entry, deadline,
                    lambda: marks.append(True), no_go=True, wait_timeout=lambda: 1)
            self.assertEqual(marks, [True])
        finally:
            if not marks:
                os.kill(child, signal.SIGKILL)
                until = time.monotonic() + 2
                while original(child, os.WNOHANG)[0] == 0:
                    self.assertLess(time.monotonic(), until); select.select([], [], [], 0.01)


if __name__ == '__main__': unittest.main()
