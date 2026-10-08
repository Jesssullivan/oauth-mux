"""Public namespace/health/refusal models; no service or credential execution."""
import copy
import errno
import os
from pathlib import Path
import unittest
from unittest import mock
import guard_resident_namespace_profile as guard

EPOCH = "11111111-1111-4111-8111-111111111111"

def manifest():
    home = Path("/home/public-model")
    return {"schema_version": 1, "action_epoch": EPOCH,
        "resident": {"ownership": "omux-installation",
            **{key: str(value) for key, value in guard.resident.fixed_paths(home).items()},
            "archive_sha256": "a"*64, "executable_sha256": "b"*64,
            "executable_path": str(home/".local/share/omux/lib/omux/libexec/omuxd.bin"),
            "pid": 314, "start_ticks": 2718, "installation": {
                "archive":{"path":"/home/jess/.local/state/omux-execution-20261005/"+EPOCH+"/output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz","sha256":"a"*64,"bytes":1},
                "manifest_sha256":"c"*64,"qualification":{"path":"/home/jess/.local/state/omux-execution-20261005/"+EPOCH+"/receipt.json","sha256":"d"*64,"bytes":1},
                "source_commit":"e"*40,"graph_sha256":"f"*64}}}

def locked_health():
    return {"protocol_version": 2, "status": "vault_locked", "custody_available": False,
        "metadata_loaded": False, "provider_access": False, "live_handoff_proven": False,
        "recovery_action": "unlock_platform_vault_then_restart_daemon"}

class NamespaceModels(unittest.TestCase):
    def test_exact_separate_target_admission_rejects_live_and_extra_options(self):
        guard.finite(["run", guard.LABEL], "system", "/private/input.json", False)
        for args, manager, reuse, extra in ((["run", "//delivery:resident_codex_live_continuity"], "system", False, ()),
            (["test", guard.LABEL], "system", False, ()), (["run", guard.LABEL], "user", False, ()),
            (["run", guard.LABEL], "system", True, ()), (["run", guard.LABEL], "system", False, ("grant",))):
            with self.assertRaises(ValueError):
                guard.finite(args, manager, "/private/input.json", reuse, extra)

    def test_manifest_has_no_accounts_auth_or_live_permissions(self):
        value = manifest()
        guard.manifest_schema(value, Path("/home/public-model"), EPOCH)
        for key in ("selected_accounts", "permissions", "model", "native_context", "allow_account_wide_drain"):
            wrong = copy.deepcopy(value)
            wrong[key] = True
            with self.assertRaises(ValueError):
                guard.manifest_schema(wrong, Path("/home/public-model"), EPOCH)
        for field, bad in (("pid", 0), ("pid", True), ("start_ticks", 0), ("archive_sha256", "bad")):
            wrong = copy.deepcopy(value)
            wrong["resident"][field] = bad
            with self.assertRaises(ValueError):
                guard.manifest_schema(wrong, Path("/home/public-model"), EPOCH)

    def test_actual_locked_health_projection_does_not_manufacture_custody(self):
        health = guard.health_projection(locked_health())
        result = guard.validate_projection({**guard.FIXED, **health})
        self.assertFalse(result["custody_proven"])
        self.assertFalse(result["account_qualification"])
        self.assertFalse(result["live_handoff_proven"])
        self.assertEqual(result["health_observation"], "vault_locked")
        self.assertEqual(result["health_metadata_loaded"], "false")
        for field in ("provider_access", "metadata_loaded", "custody_available", "live_handoff_proven"):
            wrong = locked_health()
            wrong[field] = True
            with self.assertRaises(ValueError):
                guard.health_projection(wrong)

    def test_old_ready_health_keeps_metadata_unreported(self):
        result = guard.health_projection({"protocol_version": 2, "status": "ready",
            "custody_available": True, "live_handoff_proven": False})
        self.assertEqual(result["health_metadata_loaded"], "not_reported")
        self.assertTrue(result["reported_custody_available"])
        self.assertFalse(guard.FIXED["custody_proven"])

    def test_projection_refuses_unknown_and_inherited_live_success(self):
        value = {**guard.FIXED, **guard.health_projection(locked_health())}
        for field, bad in (("selected_accounts", []), ("live_handoff_proven", True),
            ("carrier_provider_requests", 1), ("custody_proven", True), ("source_contents_read", True),
            ("foreign_present_canary_denied", 1)):
            wrong = {**value, field: bad}
            with self.assertRaises(ValueError):
                guard.validate_projection(wrong)

    def test_canary_denial_accepts_only_kernel_access_denial_and_never_reads(self):
        for denied in (errno.ENOENT, errno.EACCES, errno.EPERM):
            with mock.patch.object(guard.os, "stat", side_effect=OSError(denied, "public denial")), \
                 mock.patch.object(guard.os, "open", side_effect=OSError(denied, "public denial")):
                guard.deny_metadata(Path("/public-host-present-canary"))
        with mock.patch.object(guard.os, "stat", return_value=object()), mock.patch.object(guard.os, "open") as opened:
            with self.assertRaises(ValueError):
                guard.deny_metadata(Path("/public-accessible-canary"))
            opened.assert_not_called()

    def test_actual_peer_requires_nonzero_exact_pid_uid_gid_and_absolute_expiry(self):
        selected = manifest()["resident"]
        info = mock.Mock(st_mode=0o140600, st_uid=os.getuid())
        path = mock.Mock()
        path.stat.return_value = info
        channel = mock.MagicMock()
        channel.__enter__.return_value = channel
        channel.getsockopt.return_value = guard.struct.pack("3i", 0, os.getuid(), os.getgid())
        with mock.patch.object(guard.socket, "socket", return_value=channel), \
             mock.patch.object(guard.time, "monotonic_ns", return_value=10):
            with self.assertRaises(ValueError):
                guard.socket_peer(path, selected, 20)
        with mock.patch.object(guard.socket, "socket") as opened, \
             mock.patch.object(guard.time, "monotonic_ns", return_value=20):
            with self.assertRaises(ValueError):
                guard.socket_peer(path, selected, 20)
            opened.assert_not_called()

    def test_private_manifest_duplicate_keys_refuse(self):
        with self.assertRaises(ValueError):
            guard.resident.unique([("schema_version", 1), ("schema_version", 1)])

    def test_actual_resource_observation_pins_reject_subsequent_bound_drift(self):
        actual = ("268435456", "0", "32", 100000, "10000 100000", (1,2,0o40755,0,0))
        frozen = guard.freeze_bounds(actual, None)
        self.assertEqual(guard.freeze_bounds(actual, frozen), actual)
        changed = (*actual[:2], "31", *actual[3:])
        with self.assertRaises(ValueError):
            guard.freeze_bounds(changed, frozen)

    def test_actual_shadow_recheck_refuses_foreign_entries_at_every_level(self):
        root = Path("/public-inputs")
        user = root/"run/user"/str(os.getuid())
        child = "omux-"+"a"*32
        entries = {root/"run": ["user"], root/"run/user": [str(os.getuid())],
            user: ["bus", "systemd", child], user/"systemd": ["private"], user/child: []}
        with mock.patch.object(guard.os, "listdir", side_effect=lambda path: entries[Path(path)]):
            guard.assert_shadow_shape(root, child)
        for path in entries:
            wrong = copy.deepcopy(entries)
            wrong[path].append("foreign")
            with mock.patch.object(guard.os, "listdir", side_effect=lambda path: wrong[Path(path)]):
                with self.assertRaises(ValueError):
                    guard.assert_shadow_shape(root, child)

    def test_final_schema_and_outer_epoch_producer_output_join(self):
        value = {**guard.FIXED, **guard.health_projection(locked_health()), **guard.FINAL_FIXED,
            **{key: "a"*64 for key in guard.FINAL_PINS}, "producer": guard.LABEL, "action_epoch": EPOCH}
        guard.validate_final(value)
        output = {"sha256": "b"*64, "basename": guard.OUTPUT, "verified_after_controller_exit": True}
        outer = {"id": EPOCH, "profile": guard.PROFILE, "verb": "run", "targets": [guard.LABEL],
            "exit": 0, "workload_exit": 0, "descendants_empty": True, "cleanup": {"state": "empty"},
            "controller_failure": None, "graph_sha256": "a"*64,
            "resident_namespace": {"verified_after_cleanup": True, "output": output}}
        self.assertTrue(guard.validate_guard_join(value, outer, "b"*64))
        for key, bad in (("profile", "resident-continuity"), ("id", "different-epoch"), ("exit", 125),
                         ("targets", ["//delivery:resident_codex_enrollment"]), ("descendants_empty", False)):
            wrong = copy.deepcopy(outer)
            wrong[key] = bad
            with self.assertRaises(ValueError):
                guard.validate_guard_join(value, wrong, "b"*64)
        with self.assertRaises(ValueError):
            guard.validate_guard_join(value, outer, "c"*64)
        with self.assertRaises(ValueError):
            guard.validate_final({**value, "account_handle": "d"*64})

if __name__ == "__main__":
    unittest.main()
