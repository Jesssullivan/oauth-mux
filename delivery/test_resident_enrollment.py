"""Offline resident input/ownership and source selection contract."""
import copy
import json
import unittest
import tempfile
from unittest import mock

import resident_enrollment as resident


class ModelSelector:
    def __init__(self):
        self.keys = {}

    def register(self, stream, events, data):
        key = resident.selectors.SelectorKey(stream, stream.fileno(), events, data)
        self.keys[key.fd] = key

    def unregister(self, stream):
        return self.keys.pop(stream.fileno())

    def get_map(self):
        return self.keys

    def select(self, timeout):
        return [(key, key.events) for key in list(self.keys.values())]

    def close(self):
        self.keys.clear()


class ResidentContract(unittest.TestCase):
    def record_fixture(self):
        prefix = resident.Path("/private/package")
        unit = prefix / "units/ai.xoxd.omux.service"
        files = {"bin/" + name: ("declared-" + name).encode() for name in resident.pack.BINARIES}
        files["lib/omux/libexec/omuxd.bin"] = b"declared-image"
        artifact = {"channel": "release", "distribution": "portable-linux",
                    "artifacts": [{"path": name, "mode": "0755"} for name in files]}
        entries = [{"path": str(prefix / name), "sha256": resident.hashlib.sha256(content).hexdigest(), "mode": 0o755}
                   for name, content in files.items()]
        entries.append({"path": str(unit), "sha256": "a" * 64, "mode": 0o600})
        record = {"userService": str(unit), "artifact": {"archiveSha256": "b" * 64}, "files": entries}
        return prefix, unit, artifact, files, record

    def test_recovery_requires_exact_declared_payload_and_owned_unit_inventory(self):
        prefix, unit, artifact, files, record = self.record_fixture()
        self.assertEqual(resident.owned_record_inventory(record, artifact, files, "b" * 64, prefix, unit), record["files"])
        cases = []
        incomplete = copy.deepcopy(record)
        incomplete["files"].pop(0)
        cases.append(incomplete)
        wrong_member = copy.deepcopy(record)
        wrong_member["files"][0]["sha256"] = "c" * 64
        cases.append(wrong_member)
        wrong_archive = copy.deepcopy(record)
        wrong_archive["artifact"]["archiveSha256"] = "c" * 64
        cases.append(wrong_archive)
        wrong_unit = copy.deepcopy(record)
        wrong_unit["userService"] = "/another/unit.service"
        cases.append(wrong_unit)
        wrong_mode = copy.deepcopy(record)
        wrong_mode["files"][-1]["mode"] = 0o644
        cases.append(wrong_mode)
        duplicated = copy.deepcopy(record)
        duplicated["files"].append(copy.deepcopy(duplicated["files"][0]))
        cases.append(duplicated)
        for changed in cases:
            with self.subTest(record=changed), self.assertRaises(ValueError):
                resident.owned_record_inventory(changed, artifact, files, "b" * 64, prefix, unit)

    def test_recovery_is_explicit_owned_activation_and_never_reinstalls_bad_files(self):
        value = self.manifest()
        value["action"] = "activate-existing-and-enroll"
        self.assertEqual(resident.validate_manifest(value), value)
        for ownership, activate in (("home-manager", True), ("omux-installation", False)):
            changed = copy.deepcopy(value)
            changed["ownership"] = ownership
            changed["permissions"]["activate_service"] = activate
            with self.subTest(ownership=ownership), self.assertRaises(ValueError):
                resident.validate_manifest(changed)
        prefix, unit, artifact, files, record = self.record_fixture()
        record["artifact"]["archiveSha256"] = resident.hashlib.sha256(b"archive").hexdigest()
        value.update(prefix=str(prefix), service_path=str(unit))
        with mock.patch.object(resident, "original_deadline", return_value=resident.time.monotonic_ns() + 120 * 10**9), \
                mock.patch.object(resident, "hold_source_metadata", return_value=(21, 22, None, resident.Path("/native/auth.json"))), \
                mock.patch.object(resident, "empty_first_install_state", return_value=True), \
                mock.patch.object(resident.resident_guard, "observe_existing_session_services", return_value={"broker": {}, "manager": {}, "secret_service": None}), \
                mock.patch.object(resident.pack, "read_bundle", return_value=b"archive"), \
                mock.patch.object(resident.pack, "verify_bundle", return_value=(artifact, files)), \
                mock.patch.object(resident.Path, "is_dir", return_value=True), \
                mock.patch.object(resident.install, "_record", return_value=record), \
                mock.patch.object(resident.install, "_matches", return_value=False), \
                mock.patch.object(resident.install, "install_bundle") as install, \
                mock.patch.object(resident, "bounded") as execute, mock.patch.object(resident.os, "close"):
            with self.assertRaises(ValueError):
                resident.execute(resident.Path("/declared/archive"), resident.Path("/declared/systemctl"), resident.Path("/declared/probe"), value)
        install.assert_not_called()
        execute.assert_not_called()

    def test_effective_activation_readback_requires_enabled_unit_and_qualified_alias(self):
        unit = resident.Path("/private/package/units/ai.xoxd.omux.service")
        values = {"MemoryMax": "268435456", "MemorySwapMax": "0", "TasksMax": "32",
                  "CPUQuotaPerSecUSec": "100ms", "FragmentPath": "/owned/config/systemd/user/ai.xoxd.omux.service",
                  "UnitFileState": "enabled"}
        with mock.patch.object(resident.resident_guard, "resolve_owned_unit_fragment", return_value=unit, create=True) as resolve:
            self.assertEqual(resident.activation_readback(values, unit), unit)
            resolve.assert_called_once_with(resident.Path(values["FragmentPath"]), unit)
        for field, changed in (("UnitFileState", "disabled"), ("MemoryMax", "268435457"),
                               ("MemorySwapMax", "1"), ("TasksMax", "33"), ("CPUQuotaPerSecUSec", "101ms")):
            bad = dict(values)
            bad[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                resident.activation_readback(bad, unit)
        idle = {**values, "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlGroup": ""}
        with mock.patch.object(resident.resident_guard, "resolve_owned_unit_fragment", return_value=unit, create=True):
            self.assertEqual(resident.activation_readback(idle, unit, recovering=True), unit)
        for field, changed in (("ActiveState", "active"), ("SubState", "running"), ("MainPID", "42"), ("ControlGroup", "/active")):
            bad = dict(idle)
            bad[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                resident.activation_readback(bad, unit, recovering=True)

    def test_fresh_state_requires_absence_or_owned_empty_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = resident.Path(temporary)
            root.chmod(0o700)
            state = root / "runtime"
            self.assertTrue(resident.empty_first_install_state(state))
            state.mkdir(mode=0o700)
            self.assertTrue(resident.empty_first_install_state(state))
            state.chmod(0o755)
            with self.assertRaises(ValueError):
                resident.empty_first_install_state(state)
            state.chmod(0o700)
            metadata = state / "retained-metadata"
            metadata.write_bytes(b"model metadata")
            with self.assertRaises(ValueError):
                resident.empty_first_install_state(state)
            metadata.unlink()
            alias = root / "redirected-runtime"
            alias.symlink_to(state, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                resident.empty_first_install_state(alias)

    def test_optional_initial_vault_freezes_only_with_real_owned_readiness(self):
        transport = {"broker": {"pid": 21, "uid": 1000, "start_ticks": 10},
                     "manager": {"owner": ":1.2", "pid": 22, "uid": 1000, "start_ticks": 20},
                     "secret_service": None}
        ready = copy.deepcopy(transport)
        ready["secret_service"] = {"owner": ":1.3", "pid": 23, "uid": 1000, "start_ticks": 30}
        self.assertEqual(resident.session_transition(transport, transport, freeze_secret_service=False), transport)
        with self.assertRaises(ValueError):
            resident.session_transition(transport, transport, freeze_secret_service=True)
        self.assertEqual(resident.session_transition(transport, ready, freeze_secret_service=False), transport)
        frozen = resident.session_transition(transport, ready, freeze_secret_service=True)
        self.assertEqual(frozen, ready)
        for field in ("broker", "manager", "secret_service"):
            replaced = copy.deepcopy(ready)
            replaced[field]["pid"] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                resident.session_transition(frozen, replaced, freeze_secret_service=False)
        missing = copy.deepcopy(ready)
        missing["secret_service"] = None
        with self.assertRaises(ValueError):
            resident.session_transition(frozen, missing, freeze_secret_service=False)

    def child(self, *, running):
        process = mock.Mock()
        for name, fd in (("stdin", 11), ("stdout", 12), ("stderr", 13)):
            getattr(process, name).fileno.return_value = fd
        process.poll.return_value = None if running else 0
        process.returncode = 0
        return process

    def assert_child_streams_closed(self, process):
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close.assert_called()

    def test_selector_constructor_failure_still_reaps_only_its_child(self):
        child = self.child(running=True)
        with mock.patch.object(resident, "remaining", return_value=1), \
                mock.patch.object(resident.subprocess, "Popen", return_value=child), \
                mock.patch.object(resident.selectors, "DefaultSelector", side_effect=OSError("model setup failure")):
            with self.assertRaises(OSError):
                resident.bounded(["declared-control"], {})
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=5)
        self.assert_child_streams_closed(child)

    def test_partial_nonblocking_input_drains_output_and_preserves_exact_bytes(self):
        child = self.child(running=False)
        output = {12: [b"opaque receipt", b""], 13: [b""]}
        written = bytearray()
        first = True

        def write(fd, data):
            nonlocal first
            self.assertEqual(fd, 11)
            if first:
                first = False
                raise BlockingIOError()
            part = bytes(data[:2])
            written.extend(part)
            return len(part)

        with mock.patch.object(resident, "remaining", return_value=1), \
                mock.patch.object(resident.subprocess, "Popen", return_value=child) as spawn, \
                mock.patch.object(resident.selectors, "DefaultSelector", side_effect=ModelSelector), \
                mock.patch.object(resident.os, "set_blocking") as nonblocking, \
                mock.patch.object(resident.os, "write", side_effect=write), \
                mock.patch.object(resident.os, "read", side_effect=lambda fd, count: output[fd].pop(0)):
            self.assertEqual(resident.bounded(["declared-control"], {}, b"input"), b"opaque receipt")
        self.assertEqual(written, b"input")
        self.assertEqual(nonblocking.call_args_list, [mock.call(11, False), mock.call(12, False), mock.call(13, False)])
        self.assertEqual(spawn.call_args.kwargs["bufsize"], 0)
        child.stdin.write.assert_not_called()
        child.terminate.assert_not_called()
        self.assert_child_streams_closed(child)

    def test_input_deadline_expiry_uses_finite_term_kill_and_closes_all_streams(self):
        child = self.child(running=True)
        child.wait.side_effect = [resident.subprocess.TimeoutExpired("owned-control", 5), 0]
        with mock.patch.object(resident, "remaining", side_effect=[1, ValueError("model deadline expired")]), \
                mock.patch.object(resident.subprocess, "Popen", return_value=child), \
                mock.patch.object(resident.selectors, "DefaultSelector", side_effect=ModelSelector), \
                mock.patch.object(resident.os, "set_blocking"), mock.patch.object(resident.os, "write") as write:
            with self.assertRaises(ValueError):
                resident.bounded(["declared-control"], {}, b"waiting input")
        write.assert_not_called()
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=5), mock.call(timeout=5)])
        self.assert_child_streams_closed(child)

    def service(self):
        return {"Id": "ai.xoxd.omux.service", "MainPID": "42", "ActiveState": "active", "SubState": "running",
                "FragmentPath": "/owned/units/ai.xoxd.omux.service", "ControlGroup": "/user.slice/ai.xoxd.omux.service",
                "User": "", "Group": "", "ExecStart": "observed", "MemoryMax": "268435456",
                "MemorySwapMax": "0", "TasksMax": "32", "CPUQuotaPerSecUSec": "100ms"}

    def test_original_deadline_cannot_extend_or_spend_cleanup_reserve(self):
        now = 10**12
        key = "OMUX_RESIDENT_ORIGINAL_DEADLINE_NS"
        self.assertEqual(resident.original_deadline({key: str(now + 60 * 10**9)}, now), now + 60 * 10**9)
        for raw in ("", "inf", "-1", str(now + 30 * 10**9), str(now + 1201 * 10**9)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                resident.original_deadline({key: raw}, now)
        with mock.patch.object(resident, "DEADLINE_NS", now + 60 * 10**9), mock.patch.object(resident.time, "monotonic_ns", return_value=now):
            self.assertEqual(resident.remaining(90), 30)
        with mock.patch.object(resident, "DEADLINE_NS", now + 30 * 10**9), mock.patch.object(resident.time, "monotonic_ns", return_value=now):
            with self.assertRaises(ValueError):
                resident.remaining()

    def test_controller_environment_has_no_ambient_transport_or_injection(self):
        ambient = {"HOME": "/user", "USER": "owned", "LD_PRELOAD": "host-library", "LD_AUDIT": "host-audit",
                   "HTTPS_PROXY": "host-proxy", "ALL_PROXY": "host-proxy", "SSH_AUTH_SOCK": "host-socket",
                   "CODEX_HOME": "/ambient/context", "OMUX_INSTALL_PREFIX": "/unrelated/package",
                   "DBUS_SESSION_BUS_ADDRESS": "unix:path=/ambient/bus", "XDG_RUNTIME_DIR": "/ambient/run",
                   "PATH": "/ambient/commands"}
        selected = resident.controller_environment(ambient, "default")
        self.assertEqual(selected, {"HOME": "/user", "USER": "owned", "OMUX_INSTANCE": "default",
                                     "DBUS_SESSION_BUS_ADDRESS": "unix:path=/omux-resident-inputs/bus",
                                     "XDG_RUNTIME_DIR": "/omux-resident-inputs"})

    def test_service_readback_rejects_wrong_owner_pid_lifecycle_and_cgroup(self):
        unit = "ai.xoxd.omux.service"
        self.assertEqual(resident.validate_service_properties(self.service(), unit, 1000, 1000),
                         (42, "/user.slice/" + unit))
        for field, value in (("User", "0"), ("Group", "0"), ("MainPID", "1"), ("MainPID", "unknown"),
                             ("ActiveState", "inactive"), ("SubState", "exited"), ("Id", "another.service"),
                             ("ControlGroup", "/other.service"), ("ControlGroup", "/user.slice/../" + unit)):
            changed = self.service()
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                resident.validate_service_properties(changed, unit, 1000, 1000)

    def manifest(self):
        return {"schema_version": 1, "ownership": "omux-installation", "action": "install-and-enroll",
                "instance": "default", "prefix": "/private/package", "records": "/private/records",
                "runtime_state": "/private/state", "service_path": "/private/config/systemd/user/ai.xoxd.omux.service",
                "native_context": {"application": "codex", "provenance": "authorized-working-native-context",
                                   "codex_home": "/native/context-at-any-location"},
                "permissions": {"connect_source": True, "activate_service": True, "restart_daemon": True}}

    def test_locations_are_metadata_not_an_email_or_credential_interview(self):
        manifest = self.manifest()
        self.assertEqual(resident.validate_manifest(manifest), manifest)
        other = copy.deepcopy(manifest)
        other["native_context"]["codex_home"] = "/another/authorized/native-context"
        self.assertEqual(resident.validate_manifest(other), other)
        for key in ("email", "access_token", "refresh_token", "auth_path"):
            changed = copy.deepcopy(manifest)
            changed["native_context"][key] = "unneeded"
            with self.subTest(key=key), self.assertRaises(ValueError):
                resident.validate_manifest(changed)

    def test_source_permission_and_ownership_cannot_expand_silently(self):
        for ownership, action, activation in (("home-manager", "install-and-enroll", True),
                                              ("home-manager", "enroll-existing", True)):
            changed = self.manifest()
            changed.update(ownership=ownership, action=action)
            changed["permissions"]["activate_service"] = activation
            with self.subTest(ownership=ownership, action=action), self.assertRaises(ValueError):
                resident.validate_manifest(changed)
        changed = self.manifest()
        changed.update(ownership="home-manager", action="enroll-existing")
        changed["permissions"]["activate_service"] = False
        self.assertEqual(resident.validate_manifest(changed), changed)
        changed["permissions"]["connect_source"] = False
        with self.assertRaises(ValueError):
            resident.validate_manifest(changed)
        with self.assertRaises(ValueError):
            json.loads('{"instance":"dev","instance":"default"}', object_pairs_hook=resident.strict_object)

    def test_repeated_use_reuses_the_exact_authorized_source(self):
        snapshot = {"source_descriptions": [{"provider": "codex", "path": "/native/context/auth.json",
                                             "source_id": "a" * 64}],
                    "sources": [{"id": "a" * 64, "kind": "native_store", "status": "connected"}]}
        self.assertEqual(resident.selected_source(snapshot, resident.Path("/native/context/auth.json")), "a" * 64)
        self.assertIsNone(resident.selected_source(snapshot, resident.Path("/another/context/auth.json")))
        snapshot["source_descriptions"] *= 2
        with self.assertRaises(ValueError):
            resident.selected_source(snapshot, resident.Path("/native/context/auth.json"))


if __name__ == "__main__":
    unittest.main()
