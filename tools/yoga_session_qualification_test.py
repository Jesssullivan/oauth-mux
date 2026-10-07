"""Injected local qualification boundaries; no desktops, stores or executors."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yoga_session_qualification as qualification


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.deadline = time.monotonic_ns() + 1100 * 10**9
        self.proof = "12345678-1234-4123-8123-123456789012"
        self.uid = 1000
        self.source = "/srv/yoga-source"
        self.state = "/srv/yoga-state"
        self.path = "/srv/yoga-selection/selection.json"
        self.output = "/srv/yoga-selection/receipt.json"
        self.selection = {"schemaVersion": 1, "scope": "yoga-local-session-selection-v1", "proofId": self.proof,
            "deadlineMonotonicNs": self.deadline, "host": {"machineIdSha256": "a" * 64, "uid": self.uid},
            "seat": {"sessionId": "3", "seatId": "seat0", "uid": self.uid}, "operatorTerminal": "/dev/pts/4",
            "sourceRoot": self.source, "stateRoot": self.state, "sourceGraphSha256": "b" * 64,
            "sourceFilesSha256": {name: "c" * 64 for name in qualification.guard.SOURCE_FILES},
            "sourceSocket": "/run/user/1000/wayland-0",
            "inputPaths": {name: "/srv/yoga-inputs/" + name for name in qualification.inputs.INPUTS},
            "inputSha256": {name: "d" * 64 for name in qualification.inputs.INPUTS},
            "controllerTools": {name: "/nix/store/" + "a" * 32 + "-controller/" + name for name in qualification.guard.TOOLS},
            "controllerInventory": {"path": "/srv/yoga-inputs/inventory", "sha256": "e" * 64},
            "controllerNarProof": {"path": "/srv/yoga-inputs/nar", "sha256": "f" * 64}}
        self.selection['vaultWrapperAuthority'] = {
            'companion': {'path': '/srv/yoga-inputs/companion', 'sha256': '1' * 64},
            'nativeManifest': {'path': '/srv/yoga-inputs/native.json', 'sha256': '2' * 64},
            'registeredNativeManifest': {'path': '/nix/store/' + 'b' * 32 + '-native.json', 'sha256': '3' * 64},
            **{name: copy.deepcopy(self.selection[name]) for name in ('controllerTools', 'controllerInventory', 'controllerNarProof')}}
        self.host = dict(self.selection["host"], bootIdSha256="0" * 64)
        self.snapshot = {"device": 4, "inode": 5, "uid": self.uid, "mode": 0o700, "pid": 200, "start_ticks": 50}
        self.witness = {"source": self.selection["sourceSocket"], "destination": self.state + "/" + self.proof + "/wayland.sock",
            "proof_root": self.state + "/" + self.proof, "uid": self.uid, "deadline_ns": self.deadline, "snapshot": self.snapshot}
        self.pin = Mock()
        self.pin.check.return_value = self.snapshot

    def produce(self, *, publication=None, **changes):
        with patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir="/home/operator")), \
                patch.object(qualification, "read_selection", return_value=self.selection), \
                patch.object(qualification, "identity_capture", return_value=self.host), \
                patch.object(qualification, "graph_capture", return_value="b" * 64), \
                patch.object(qualification.display, "capture_pinned", return_value=(self.witness, self.pin)), \
                patch.object(qualification.guard, "runtime_qualification") as runtime, \
                patch.object(qualification, "publish", side_effect=publication) as publish:
            if publication is None:
                def capture(path, payload, deadline, verify):
                    verify(); verify()
                    return hashlib.sha256(payload).hexdigest()
                publish.side_effect = capture
            result = qualification.produce(self.path, "1" * 64, self.output, self.deadline, **changes)
            return result, publish.call_args, runtime.call_count

    def test_positive_receipt_is_exact_guard_schema_and_no_admission_claim(self):
        result, call, checks = self.produce()
        receipt = qualification.guard.decode(call.args[1])
        self.assertEqual(set(receipt), qualification.guard.FIELDS)
        self.assertEqual(receipt["scope"], "yoga-local-guard-qualification-v1")
        self.assertEqual(receipt["deadlineMonotonicNs"], self.deadline)
        self.assertEqual(receipt["compositorSnapshot"], self.snapshot)
        self.assertEqual(receipt["host"], self.host)
        self.assertEqual(checks, 3)
        self.assertEqual(result["receiptSha256"], hashlib.sha256(call.args[1]).hexdigest())
        self.assertFalse(result["executionAuthority"]); self.assertFalse(result["toolbarConsentProved"])
        self.assertNotIn("operatorTerminal", result); self.assertNotIn("sourceSocket", result)
        self.pin.close.assert_called_once()

    def test_bad_selection_scope_hashes_deadline_and_ambient_paths_refuse(self):
        for change in (lambda value: value.update(scope="remote"), lambda value: value.update(deadlineMonotonicNs=self.deadline + 1),
                       lambda value: value["host"].update(uid=1001), lambda value: value["host"].update(uid=True),
                       lambda value: value["inputSha256"].pop("node"), lambda value: value.update(sourceRoot="/home/operator/repo"),
                       lambda value: value["controllerTools"].update(python="/usr/bin/python"),
                       lambda value: value.update(sourceSocket="/run/user/1001/wayland-0")):
            selected = copy.deepcopy(self.selection); change(selected)
            with self.assertRaises(ValueError):
                qualification.validate_selection(selected, self.deadline, self.uid, Path("/home/operator"))

    def test_wrapper_authority_requires_same_independent_controller_receipt_and_exact_shape(self):
        for edit in (lambda value: value['vaultWrapperAuthority'].pop('companion'),
                     lambda value: value['vaultWrapperAuthority']['controllerNarProof'].update(sha256='0' * 64),
                     lambda value: value['vaultWrapperAuthority']['registeredNativeManifest'].update(path='/etc/native.json')):
            selected = copy.deepcopy(self.selection); edit(selected)
            with self.assertRaises(ValueError):
                qualification.validate_selection(selected, self.deadline, self.uid, Path('/home/operator'))

    def test_expired_and_short_deadline_no_input_reads(self):
        with patch.object(qualification, "read_selection") as reader:
            for deadline in (0, True, time.monotonic_ns() - 1, time.monotonic_ns() + 10**9):
                with self.assertRaises(ValueError):
                    qualification.produce(self.path, "1" * 64, self.output, deadline)
            reader.assert_not_called()

    def test_hash_selected_receipt_input_is_read_private_without_alias_resolution(self):
        with patch.object(qualification.guard, "file_bytes", return_value=b'{"fixed":1}') as reader:
            self.assertEqual(qualification.read_selection(self.path, "1" * 64, self.deadline), {"fixed": 1})
            reader.assert_called_once_with(self.path, qualification.MAX_SELECTION, self.deadline, private=True, expected="1" * 64)

    def test_actual_host_capture_requires_expected_machine_and_matching_local_identity(self):
        machine, boot = b"machine\n", b"boot\n"
        selected = copy.deepcopy(self.selection)
        selected["host"]["machineIdSha256"] = hashlib.sha256(machine).hexdigest()
        with patch.object(qualification.guard, "file_bytes", side_effect=[machine, boot]), \
                patch.object(qualification.guard, "local_identity") as identity:
            host = qualification.identity_capture(selected, self.deadline, self.uid, 0)
            self.assertEqual(host["bootIdSha256"], hashlib.sha256(boot).hexdigest())
            self.assertEqual(identity.call_args.args[0]["seat"], selected["seat"])
        with patch.object(qualification.guard, "file_bytes", side_effect=[machine, boot]), \
                patch.object(qualification.guard, "local_identity") as identity:
            with self.assertRaises(ValueError):
                qualification.identity_capture(self.selection, self.deadline, self.uid, 0)
            identity.assert_not_called()

    def test_pin_stays_owned_through_publication_and_failure_closes_it(self):
        def failure(path, payload, deadline, verify):
            self.pin.close.assert_not_called()
            verify()
            raise qualification.QualificationError("output_unqualified")
        with self.assertRaises(qualification.QualificationError):
            self.produce(publication=failure)
        self.pin.close.assert_called_once()

    def metadata(self, *, directory=False, **changes):
        result = dict(st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
            st_uid=self.uid, st_dev=2, st_ino=3, st_nlink=1, st_size=2, st_mtime_ns=4, st_ctime_ns=5)
        result.update(changes)
        return SimpleNamespace(**result)

    def graph(self, names, metadata, *, reads=None, opened=None):
        with patch.object(qualification.inputs, "open_parent", return_value=7), \
                patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.os, "fstat", side_effect=lambda descriptor: self.metadata(directory=True) if descriptor == 7 else metadata), \
                patch.object(qualification.os, "stat", side_effect=lambda name, **kwargs: metadata), \
                patch.object(qualification.os, "listdir", return_value=names), \
                patch.object(qualification.os, "open", return_value=8) as opener, \
                patch.object(qualification.os, "read", side_effect=reads or [b"{}", b""]) as reader, \
                patch.object(qualification.os, "close") as close:
            result = qualification.graph_capture(self.source, self.deadline)
            return result, opener, reader, close

    def test_graph_matches_guard_hash_algorithm(self):
        result, opener, reader, close = self.graph(["BUILD.bazel"], self.metadata())
        expected = hashlib.sha256(b"BUILD.bazel\0" + hashlib.sha256(b"{}").digest()).hexdigest()
        self.assertEqual(result, expected)
        self.assertTrue(opener.call_args.args[1] & os.O_NONBLOCK)
        self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [7, 7, 8])

    def test_graph_fifo_refuses_before_read_and_closes_held_file(self):
        with patch.object(qualification.inputs, "open_parent", return_value=7), \
                patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.os, "fstat", side_effect=lambda fd: self.metadata(directory=True) if fd == 7 else self.metadata(st_mode=stat.S_IFIFO | 0o600)), \
                patch.object(qualification.os, "stat", return_value=self.metadata(st_mode=stat.S_IFIFO | 0o600)), \
                patch.object(qualification.os, "listdir", return_value=["BUILD.bazel"]), \
                patch.object(qualification.os, "open", return_value=8), patch.object(qualification.os, "read") as reader, \
                patch.object(qualification.os, "close") as close:
            with self.assertRaises(ValueError):
                qualification.graph_capture(self.source, self.deadline)
            reader.assert_not_called()
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_graph_child_and_file_fstat_failure_closes_new_descriptors(self):
        for directory, name in ((True, "child"), (False, "BUILD.bazel")):
            with patch.object(qualification.inputs, "open_parent", return_value=7), \
                    patch.object(qualification.os, "getuid", return_value=self.uid), \
                    patch.object(qualification.os, "fstat", side_effect=lambda fd: self.metadata(directory=True) if fd == 7 else (_ for _ in ()).throw(OSError())), \
                    patch.object(qualification.os, "stat", return_value=self.metadata(directory=directory)), \
                    patch.object(qualification.os, "listdir", return_value=[name]), \
                    patch.object(qualification.os, "open", return_value=8), patch.object(qualification.os, "close") as close:
                with self.assertRaises(OSError):
                    qualification.graph_capture(self.source, self.deadline)
                self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_graph_earlier_directory_change_refuses_capture(self):
        root = self.metadata(directory=True)
        changed = self.metadata(directory=True, st_mtime_ns=6)
        with patch.object(qualification.inputs, "open_parent", side_effect=[7, 9]), \
                patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.os, "fstat", side_effect=lambda fd: changed if fd == 9 else root if fd == 7 else self.metadata()), \
                patch.object(qualification.os, "stat", return_value=self.metadata()), \
                patch.object(qualification.os, "listdir", return_value=["BUILD.bazel"]), \
                patch.object(qualification.os, "open", return_value=8), \
                patch.object(qualification.os, "read", side_effect=[b"{}", b""]), patch.object(qualification.os, "close"):
            with self.assertRaises(qualification.QualificationError):
                qualification.graph_capture(self.source, self.deadline)

    def publish_context(self, *, fchmod=None, stat_result=None, verifier=None, parent_times_change=False):
        parent = self.metadata(directory=True)
        changed_parent = self.metadata(directory=True, st_mtime_ns=6, st_ctime_ns=7)
        output = self.metadata()
        parent_reads = 0
        def information(descriptor):
            nonlocal parent_reads
            if descriptor == 7:
                parent_reads += 1
                return changed_parent if parent_times_change and parent_reads > 1 else parent
            return output
        with patch.object(qualification.display, "parent_descriptor", return_value=7), \
                patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.os, "fstat", side_effect=information), \
                patch.object(qualification.os, "open", return_value=8) as opener, \
                patch.object(qualification.os, "fchmod", side_effect=fchmod), \
                patch.object(qualification.os, "write", return_value=2), patch.object(qualification.os, "fsync"), \
                patch.object(qualification.os, "stat", return_value=stat_result or output), \
                patch.object(qualification.os, "unlink") as unlink, patch.object(qualification.os, "close") as close:
            result = None
            try:
                result = qualification.publish(self.output, b"{}", self.deadline, verifier or Mock())
            except (ValueError, OSError) as error:
                result = error
            return result, opener, unlink, close

    def test_publication_is_exclusive_private_and_hashes_exact_bytes(self):
        # Creating this receipt changes directory times, never its custody.
        result, opener, unlink, close = self.publish_context(parent_times_change=True)
        self.assertEqual(result, hashlib.sha256(b"{}").hexdigest())
        flags = opener.call_args.args[1]
        self.assertTrue(flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK)
        unlink.assert_not_called()

    def test_publication_chmod_failure_unlinks_only_owned_new_file(self):
        result, opener, unlink, close = self.publish_context(fchmod=OSError())
        self.assertIsInstance(result, OSError)
        unlink.assert_called_once_with("receipt.json", dir_fd=7)
        self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_publication_replaced_output_never_unlinks_foreign_inode(self):
        result, opener, unlink, close = self.publish_context(stat_result=self.metadata(st_ino=4))
        self.assertIsInstance(result, qualification.QualificationError)
        self.assertEqual(result.reason, "cleanup_incomplete")
        unlink.assert_not_called()

    def test_publication_expiry_never_creates_output(self):
        with patch.object(qualification.display, "parent_descriptor") as parent, patch.object(qualification.os, "open") as opener:
            with self.assertRaises(qualification.QualificationError):
                qualification.publish(self.output, b"{}", 1, Mock(), now=lambda: 2)
            parent.assert_not_called(); opener.assert_not_called()

    def test_output_fstat_failure_closes_without_guessing_unlink_authority(self):
        with patch.object(qualification.display, "parent_descriptor", return_value=7), \
                patch.object(qualification.os, "fstat", side_effect=lambda fd: self.metadata(directory=True) if fd == 7 else (_ for _ in ()).throw(OSError())), \
                patch.object(qualification.os, "open", return_value=8), patch.object(qualification.os, "unlink") as unlink, \
                patch.object(qualification.os, "close") as close:
            with self.assertRaises(qualification.QualificationError) as refused:
                qualification.publish(self.output, b"{}", self.deadline, Mock())
            self.assertEqual(refused.exception.reason, "cleanup_incomplete")
            unlink.assert_not_called()
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_graph_earlier_file_drift_during_later_hash_refuses(self):
        stable = self.metadata()
        changed = self.metadata(st_mtime_ns=6)
        reads = 0
        def information(descriptor):
            if descriptor == 7:
                return self.metadata(directory=True)
            return changed if descriptor == 8 and reads >= 3 else stable
        def read(descriptor, size):
            nonlocal reads
            reads += 1
            return b"{}" if reads in (1, 3) else b""
        with patch.object(qualification.inputs, "open_parent", return_value=7), \
                patch.object(qualification.os, "getuid", return_value=self.uid), \
                patch.object(qualification.os, "fstat", side_effect=information), \
                patch.object(qualification.os, "stat", return_value=stable), \
                patch.object(qualification.os, "listdir", return_value=["BUILD.bazel", "MODULE.bazel"]), \
                patch.object(qualification.os, "open", side_effect=[8, 9]), \
                patch.object(qualification.os, "read", side_effect=read), patch.object(qualification.os, "close"):
            with self.assertRaises(qualification.QualificationError) as refused:
                qualification.graph_capture(self.source, self.deadline)
            self.assertEqual(refused.exception.reason, "source_changed")


if __name__ == "__main__":
    unittest.main()
