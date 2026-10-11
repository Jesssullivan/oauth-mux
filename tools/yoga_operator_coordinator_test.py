"""Reviewable injected support tests; no executors, displays or file writes."""
import json
import hashlib
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import yoga_operator_coordinator as support


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_dev=2, st_ino=3)
        self.patches = [patch.object(support.display, "parent_descriptor", return_value=7),
                        patch.object(support.os, "fstat", return_value=self.metadata),
                        patch.object(support.os, "stat", return_value=self.metadata),
                        patch.object(support.os, "close")]
        for selected in self.patches:
            selected.start()
            self.addCleanup(selected.stop)
        self.snapshot = {"device": 4, "inode": 5, "uid": 1000, "mode": 0o700, "pid": 100, "start_ticks": 50}
        self.arguments = dict(profile="yoga-toolbar", manager="system", arguments=["run", support.LABEL],
            proof_id="12345678-1234-4123-8123-123456789012", proof_root="/srv/omux-proof/.run-1",
            source_socket="/run/user/1000/wayland-0", uid=1000, deadline_ns=1000 * 10**9,
            input_digests={name: "a" * 64 for name in support.INPUTS}, now=lambda: 1,
            inspector=Mock(return_value=self.snapshot))
        envelope = {name: {'path': '/srv/yoga-meta/' + ('native.json' if name == 'nativeManifest' else name), 'sha256': 'b' * 64}
                    for name in support.WRAPPER_EVIDENCE}
        envelope['registeredNativeManifest']['path'] = '/nix/store/' + 'b' * 32 + '-native.json'
        envelope['controllerTools'] = {name: '/nix/store/' + 'a' * 32 + '-controller/' + name for name in support.CONTROLLER_TOOLS}
        self.arguments.update(vault_wrapper_authority=envelope, source_root='/srv/yoga-source',
            source_files_sha256={name: 'c' * 64 for name in support.WRAPPER_SOURCE_FILES})
        self.coordinator = support.Coordinator(**self.arguments)
        self.coordinator.write = Mock()

    def admit(self, **changes):
        arguments = dict(properties=support.LIMITS,
            coordinator={"pid": 101, "cgroupPath": "/sys/fs/cgroup/omux-proof.service", "device": 2, "inode": 3},
            source_snapshot=self.snapshot, destination_snapshot=self.snapshot,
            effective_binds=["/run/user/1000/wayland-0:/srv/omux-proof/.run-1/wayland.sock"],
            checked_input_digests=self.arguments["input_digests"],
            checked_wrapper_authority_sha256=hashlib.sha256(json.dumps(self.arguments['vault_wrapper_authority'],
                sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest())
        arguments.update(changes)
        return self.coordinator.admit(**arguments)

    def test_pre_go_admission_produces_exact_private_session(self):
        digest = self.admit()
        self.assertEqual(len(digest), 64)
        calls = self.coordinator.write.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["session.json", "proof-id"])
        session = json.loads(calls[0].args[1])
        self.assertEqual(session["scope"], "yoga-operator-local-toolbar-v1")
        self.assertEqual(session["display"]["socketInode"], 5)
        self.assertEqual(session["inputSha256"], self.arguments["input_digests"])
        self.assertEqual(session['vaultWrapperAuthority'], self.arguments['vault_wrapper_authority'])
        self.assertEqual(session['wrapperSourceSha256'], self.arguments['source_files_sha256'])

    def test_wrapper_ready_digest_refuses_before_private_session_and_retains_copied_metadata(self):
        with self.assertRaises(ValueError): self.admit(checked_wrapper_authority_sha256='0' * 64)
        self.coordinator.write.assert_not_called()
        self.arguments['vault_wrapper_authority']['companion']['sha256'] = '0' * 64
        self.assertNotEqual(self.coordinator.vault_wrapper_authority, self.arguments['vault_wrapper_authority'])
        with self.assertRaises(ValueError): self.admit()
        self.coordinator.write.assert_not_called()

    def test_unqualified_inputs_properties_or_bind_refuse_before_session(self):
        for change in (dict(checked_input_digests={}), dict(properties={}), dict(effective_binds=[]),
                       dict(destination_snapshot=dict(self.snapshot, inode=6))):
            with self.assertRaises(ValueError):
                self.admit(**change)
        self.coordinator.write.assert_not_called()

    def event(self, case):
        return json.dumps({"proofId": self.arguments["proof_id"], "case": case,
                           "observed": support.STATEMENTS[case]}).encode()

    def test_operator_events_order_replay_and_no_browser_claim(self):
        self.admit()
        with self.assertRaises(ValueError):
            self.coordinator.accept_event(self.event("approval"))
        for case in support.STATEMENTS:
            result = self.coordinator.accept_event(self.event(case))
            self.assertFalse(result["observedBrowserProof"])
        with self.assertRaises(ValueError):
            self.coordinator.accept_event(self.event("reload"))
        result = self.coordinator.finish(workload_exit=0, aggregate_empty=True)
        self.assertTrue(result["executionPassed"])
        self.assertFalse(result["toolbarConsentProved"])

    def test_cancelled_nonempty_or_deadline_never_passes(self):
        self.admit()
        result = self.coordinator.finish(workload_exit=0, aggregate_empty=False, cancellation_requested=True)
        self.assertFalse(result["executionPassed"])
        with self.assertRaises(ValueError):
            self.coordinator.accept_event(self.event("denial"))

    def test_profile_and_root_replacement_refuse(self):
        for change in (dict(manager="user"), dict(arguments=["run", "//:other"]), dict(input_digests={})): 
            with self.assertRaises(ValueError):
                support.Coordinator(**dict(self.arguments, **change))
        self.metadata.st_ino = 4
        # Held inode/device are values from admission, never a mutable witness.
        self.coordinator.root_identity = SimpleNamespace(st_dev=2, st_ino=3)
        with self.assertRaises(ValueError):
            self.admit()

    def test_operator_payload_size_duplicates_and_unadmitted_event_refuse(self):
        for payload in (b"x" * 2049, b'{"case":"denial","case":"approval"}', b"[]"):
            with self.assertRaises(ValueError):
                self.coordinator.accept_event(payload)
        for payload in (b"x" * 2049, b'{"case":"denial","case":"approval"}'):
            with self.assertRaises(ValueError):
                support.parse(payload)

    def test_expired_deadline_refuses_admission(self):
        self.coordinator.now = lambda: self.arguments["deadline_ns"]
        with self.assertRaises(ValueError):
            self.admit()
        self.coordinator.write.assert_not_called()

    def test_invalid_selector_and_deadline_do_not_open(self):
        with patch.object(support.display, "parent_descriptor") as opener:
            for change in (dict(source_socket="/tmp/wayland-0"), dict(proof_root="/srv/../private"),
                           dict(uid=0), dict(deadline_ns=0)):
                with self.assertRaises(ValueError):
                    support.Coordinator(**dict(self.arguments, **change))
            opener.assert_not_called()

    def test_constructor_fstat_failure_closes_acquired_root(self):
        with patch.object(support.os, "fstat", side_effect=OSError("metadata unavailable")), patch.object(support.os, "close") as close:
            with self.assertRaises(OSError):
                support.Coordinator(**self.arguments)
            close.assert_called_once_with(7)

    def pipe_info(self, **changes):
        value = dict(st_mode=stat.S_IFIFO | 0o600, st_uid=1000, st_dev=10, st_ino=11, st_nlink=0)
        value.update(changes)
        return SimpleNamespace(**value)

    def test_named_fifo_wrong_end_and_foreign_channel_close_duplicate(self):
        for info, flags in ((self.pipe_info(st_nlink=2), support.os.O_RDONLY),
                            (self.pipe_info(st_uid=1001), support.os.O_RDONLY),
                            (self.pipe_info(), support.os.O_WRONLY)):
            with patch.object(support.os, "dup", return_value=8), patch.object(support.os, "set_inheritable"), \
                    patch.object(support.os, "fstat", return_value=info), \
                    patch.object(support.fcntl, "fcntl", return_value=flags), patch.object(support.os, "close") as close:
                with self.assertRaises(ValueError):
                    self.coordinator.retain_operator_channel(20)
                close.assert_called_once_with(8)
                self.assertIsNone(self.coordinator.operator_descriptor)

    def test_retained_channel_identity_and_readonly_are_rechecked(self):
        self.admit()
        with patch.object(support.os, "dup", return_value=8), patch.object(support.os, "set_inheritable") as inherited, \
                patch.object(support.os, "fstat", return_value=self.pipe_info(st_nlink=1)), \
                patch.object(support.os, "readlink", return_value="pipe:[11]"), \
                patch.object(support.fcntl, "fcntl", return_value=support.os.O_RDONLY):
            self.coordinator.retain_operator_channel(20)
            inherited.assert_called_once_with(8, False)
            with patch.object(support.select, "select", return_value=([8], [], [])), \
                    patch.object(support.os, "read", return_value=self.event("denial") + b"\n") as reader:
                self.coordinator.receive_event()
                reader.assert_called_once_with(8, 2049)
        for info, flags in ((self.pipe_info(st_ino=12), support.os.O_RDONLY),
                            (self.pipe_info(), support.os.O_WRONLY)):
            with patch.object(support.os, "fstat", return_value=info), patch.object(support.fcntl, "fcntl", return_value=flags):
                with self.assertRaises(ValueError):
                    self.coordinator.receive_event()
        with patch.object(support.os, "close") as close:
            self.coordinator.finish(workload_exit=125, aggregate_empty=True)
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])
            with self.assertRaises(ValueError):
                self.coordinator.finish(workload_exit=125, aggregate_empty=True)
            self.assertEqual(close.call_count, 2)

    def test_named_fifo_and_wrong_procfs_inode_refuse(self):
        for link in ("/srv/private/operator.fifo", "pipe:[12]"):
            with patch.object(support.os, "dup", return_value=8), patch.object(support.os, "set_inheritable"), \
                    patch.object(support.os, "fstat", return_value=self.pipe_info(st_nlink=1)), \
                    patch.object(support.os, "readlink", return_value=link), \
                    patch.object(support.fcntl, "fcntl", return_value=support.os.O_RDONLY), patch.object(support.os, "close") as close:
                with self.assertRaises(ValueError):
                    self.coordinator.retain_operator_channel(20)
                close.assert_called_once_with(8)

    def test_partial_and_coalesced_records_preserve_case_order(self):
        self.admit()
        self.coordinator.operator_descriptor = 8
        self.coordinator.operator_identity = (10, 11)
        first = self.event("denial")
        with patch.object(support.os, "fstat", return_value=self.pipe_info()), \
                patch.object(support.fcntl, "fcntl", return_value=support.os.O_RDONLY), \
                patch.object(support.os, "readlink", return_value="pipe:[11]"), \
                patch.object(support.select, "select", return_value=([8], [], [])), \
                patch.object(support.os, "read", side_effect=[first[:10], first[10:] + b"\n" + self.event("approval") + b"\n"]) as reader:
            self.assertEqual(self.coordinator.receive_event()["case"], "denial")
            self.assertEqual(self.coordinator.receive_event()["case"], "approval")
            self.assertEqual(reader.call_count, 2)

    def test_exit_zero_without_operator_cases_does_not_pass(self):
        self.admit()
        self.assertFalse(self.coordinator.finish(workload_exit=0, aggregate_empty=True)["executionPassed"])

    def reserved_coordinator(self):
        import guard_yoga_toolbar_reserved as reservation
        clock=patch.object(reservation.kernel.time, 'monotonic_ns', return_value=200*10**9)
        clock.start();self.addCleanup(clock.stop)
        self.coordinator = support.Coordinator(**dict(self.arguments, profile=reservation.PROFILE,
            deadline_ns=1300*10**9, original_entry_ns=100*10**9, now=lambda:200*10**9))
        self.coordinator.write = Mock()
        self.coordinator.reserved_runtime = 1070
        return {**reservation.properties(support.LIMITS), 'RuntimeMaxUSec':'17min 50s'}

    def test_reserved_caps_keep_exact_session_and_require_human_cases(self):
        values=self.reserved_coordinator()
        original=dict(support.LIMITS)
        self.admit(properties=values)
        session=json.loads(self.coordinator.write.call_args_list[0].args[1])
        self.assertEqual(session['scope'],'yoga-operator-local-toolbar-v1')
        self.assertEqual(session['deadlineMonotonicNs'],1300*10**9)
        self.assertNotIn('reservation',session)
        self.assertEqual(support.LIMITS,original)
        for case in support.STATEMENTS:
            self.coordinator.accept_event(self.event(case))
        result=self.coordinator.finish(workload_exit=0,aggregate_empty=True)
        self.assertTrue(result['executionPassed']);self.assertFalse(result['toolbarConsentProved'])
        self.reserved_coordinator();self.admit(properties=values)
        self.assertFalse(self.coordinator.finish(workload_exit=0,aggregate_empty=True)['executionPassed'])

    def test_reserved_old_caps_clock_or_missing_runtime_refuse_before_session(self):
        import guard_yoga_toolbar_reserved as reservation
        values=self.reserved_coordinator()
        for name,value in (('MemoryMax','4294967296'),('TasksMax','512'),
            ('CPUQuotaPerSecUSec','2s'),('RuntimeMaxUSec','1200s'),('RemainAfterExit','no')):
            with self.assertRaises(ValueError):self.admit(properties={**values,name:value})
        self.coordinator.write.assert_not_called()
        del self.coordinator.reserved_runtime
        with self.assertRaises(ValueError):self.admit(properties=values)
        with patch.object(reservation.kernel.time,'monotonic_ns',return_value=200*10**9):
            with self.assertRaises(ValueError):
                support.Coordinator(**dict(self.arguments,profile=reservation.PROFILE,
                    deadline_ns=1300*10**9,original_entry_ns=200*10**9,now=lambda:200*10**9))
        with self.assertRaises(ValueError):
            support.Coordinator(**dict(self.arguments,original_entry_ns=1))


if __name__ == "__main__":
    unittest.main()
