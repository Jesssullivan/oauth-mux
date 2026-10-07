"""Injected metadata only; no desktop/socket/process execution."""
import unittest
import stat
import struct
from types import SimpleNamespace
from unittest.mock import Mock, patch
import yoga_display_binding as binding


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.uid = 1000
        self.source = "/run/user/1000/wayland-0"
        self.root = "/srv/omux-proof/.run-123"
        self.destination = self.root + "/wayland.sock"
        self.snapshot = {"device": 12, "inode": 34, "uid": self.uid,
                         "mode": 0o700, "pid": 123, "start_ticks": 456}
        self.deadline = 1000 * 10**9
        self.inspect = Mock(return_value=dict(self.snapshot))
        self.witness = binding.capture(self.source, self.destination, self.root, self.uid,
                                       self.deadline, self.inspect, lambda: 1)
        self.binds = [self.source + ":" + self.destination]

    def verify(self, source=None, destination=None, binds=None, now=lambda: 1):
        return binding.verify_binding(self.witness, self.snapshot if source is None else source,
                                      self.snapshot if destination is None else destination,
                                      self.binds if binds is None else binds, now)

    def test_exact_bind_retains_destination_contract(self):
        result = self.verify()
        self.assertEqual(result, {"adapter": "qualified-wayland-unix", "socketPath": self.destination,
                                  "socketDevice": 12, "socketInode": 34, "serverPid": 123})
        self.inspect.assert_called_once_with(self.source, self.uid, self.deadline)

    def test_replacement_owner_mode_pid_and_start_ticks_refuse(self):
        for key, value in (("device", 13), ("inode", 35), ("uid", 1001), ("mode", 0o722),
                           ("pid", 124), ("start_ticks", 457)):
            altered = dict(self.snapshot, **{key: value})
            for side in ("source", "destination"):
                with self.subTest(key=key, side=side), self.assertRaises(binding.BindingError):
                    self.verify(**{side: altered})

    def test_extra_missing_or_different_bind_refuses(self):
        for binds in ([], self.binds * 2, ["/run/user/1000:" + self.root], [self.source + ":/other"]):
            with self.assertRaises(binding.BindingError):
                self.verify(binds=binds)

    def test_timeout_and_invalid_selectors_refuse(self):
        with self.assertRaises(binding.BindingError):
            self.verify(now=lambda: self.deadline)
        for source in ("/run/user/1001/wayland-0", "/run/user/1000/../wayland-0", "/tmp/wayland-0"):
            with self.assertRaises(binding.BindingError):
                binding.capture(source, self.destination, self.root, self.uid, self.deadline, self.inspect, lambda: 1)
        for root in ("/home/user/proof", "/srv/../home", "/srv//proof"):
            with self.assertRaises(binding.BindingError):
                binding.selectors(self.source, root + "/wayland.sock", root, self.uid)

    def test_endpoint_failures_emit_no_paths_or_ids(self):
        with patch.object(binding, "budget", return_value=1), patch.object(binding, "parent_descriptor", side_effect=OSError("private endpoint /run/user/1000")):
            with self.assertRaises(binding.BindingError) as raised:
                binding.inspect_endpoint(self.source, self.uid, self.deadline)
        self.assertEqual(binding.diagnostic(raised.exception), {"passed": False, "gate": "binding_invalid"})
        self.assertEqual(binding.diagnostic(OSError("private /home/user")), {"passed": False, "gate": "binding_invalid"})

    def test_fresh_source_observation_detects_changes_and_deadline(self):
        inspector = Mock(return_value=dict(self.snapshot))
        self.assertEqual(binding.reinspect_source(self.witness, inspector, lambda: 1), self.snapshot)
        inspector.assert_called_once_with(self.source, self.uid, self.deadline)
        inspector.return_value = dict(self.snapshot, start_ticks=457)
        with self.assertRaisesRegex(binding.BindingError, "endpoint_changed"):
            binding.reinspect_source(self.witness, inspector, lambda: 1)
        inspector.reset_mock()
        with self.assertRaises(binding.BindingError):
            binding.reinspect_source(self.witness, inspector, lambda: self.deadline)
        inspector.assert_not_called()

    def test_only_singleton_measured_readonly_binding_is_admitted(self):
        self.assertEqual(binding.verify_readonly_binding(self.witness, self.snapshot, self.snapshot,
                                                        self.binds, [], lambda: 1), self.verify())
        for readonly, writable in (([], self.binds), (self.binds, self.binds),
                                    (self.binds * 2, []), (self.binds, ["/srv:/srv"])):
            with self.assertRaises(binding.BindingError):
                binding.verify_readonly_binding(self.witness, self.snapshot, self.snapshot,
                                               readonly, writable, lambda: 1)

    def test_named_parent_substitution_is_refused_after_peer_capture(self):
        socket_info = SimpleNamespace(st_dev=12, st_ino=34, st_uid=self.uid, st_mode=stat.S_IFSOCK | 0o700)
        held = SimpleNamespace(st_dev=20, st_ino=21, st_uid=self.uid, st_mode=stat.S_IFDIR | 0o700)
        replacement = SimpleNamespace(**dict(vars(held), st_ino=22))
        connection = Mock()
        connection.getsockopt.return_value = struct.pack("3i", 123, self.uid, self.uid)
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with patch.object(binding, "budget", return_value=1), \
                patch.object(binding, "parent_descriptor", side_effect=[7, 8]), \
                patch.object(binding.os, "stat", return_value=socket_info), \
                patch.object(binding.os, "fstat", side_effect=[held, replacement]), \
                patch.object(binding.os, "close") as close, \
                patch.object(binding.socket, "socket", return_value=context), \
                patch.object(binding, "pid_start", return_value=456):
            with self.assertRaisesRegex(binding.BindingError, "endpoint_changed"):
                binding.inspect_endpoint(self.source, self.uid, self.deadline)
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_proc_record_must_match_credential_pid(self):
        information = SimpleNamespace(st_uid=self.uid)
        for payload in (b"124 (compositor) S " + b"0 " * 18 + b"456\n",
                        b"123 (compositor) Z " + b"0 " * 18 + b"456\n"):
            with patch.object(binding.os, "open", side_effect=[7, 8]), \
                    patch.object(binding.os, "fstat", return_value=information), \
                    patch.object(binding.os, "read", return_value=payload), patch.object(binding.os, "close"):
                with self.assertRaises(binding.BindingError):
                    binding.pid_start(123, self.uid)

    def test_pinned_capture_retains_inode_until_explicit_cleanup(self):
        metadata = SimpleNamespace(st_dev=12, st_ino=34, st_uid=self.uid, st_mode=stat.S_IFSOCK | 0o700)
        with patch.object(binding, "parent_descriptor", return_value=7), \
                patch.object(binding.os, "open", return_value=8) as opener, \
                patch.object(binding.os, "fstat", return_value=metadata), patch.object(binding.os, "close") as close:
            witness, pin = binding.capture_pinned(self.source, self.destination, self.root, self.uid,
                                                  self.deadline, self.inspect, lambda: 1)
            self.assertTrue(opener.call_args.args[1] & binding.os.O_PATH)
            self.assertTrue(opener.call_args.args[1] & binding.os.O_NOFOLLOW)
            close.assert_called_once_with(7)
            self.assertEqual(pin.check(witness, self.inspect, lambda: 1), self.snapshot)
            metadata.st_ino = 35
            with self.assertRaisesRegex(binding.BindingError, "endpoint_changed"):
                pin.check(witness, self.inspect, lambda: 1)
            pin.close()
            pin.close()
            self.assertEqual([call.args[0] for call in close.call_args_list], [7, 8])
            with self.assertRaises(binding.BindingError):
                pin.check(witness, self.inspect, lambda: 1)

    def test_pinned_capture_failure_closes_only_owned_descriptors(self):
        metadata = SimpleNamespace(st_dev=12, st_ino=35, st_uid=self.uid, st_mode=stat.S_IFSOCK | 0o700)
        with patch.object(binding, "parent_descriptor", return_value=7), \
                patch.object(binding.os, "open", return_value=8), \
                patch.object(binding.os, "fstat", return_value=metadata), patch.object(binding.os, "close") as close:
            with self.assertRaises(binding.BindingError):
                binding.capture_pinned(self.source, self.destination, self.root, self.uid,
                                       self.deadline, self.inspect, lambda: 1)
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])

    def test_parent_child_fstat_failure_closes_child_and_previous_descriptor(self):
        root = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch.object(binding.os, "open", side_effect=[7, 8]), \
                patch.object(binding.os, "fstat", side_effect=[root, OSError("private metadata unavailable")]), \
                patch.object(binding.os, "close") as close:
            with self.assertRaises(OSError):
                binding.parent_descriptor("/run/user/1000", self.uid)
            self.assertEqual([call.args[0] for call in close.call_args_list], [8, 7])


if __name__ == "__main__":
    unittest.main()
