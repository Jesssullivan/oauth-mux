"""Synthetic admission boundaries only; these tests never launch a browser."""
import json
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch, call

import yoga_toolbar_contract as contract
import yoga_toolbar_consent as runner
import yoga_toolbar_native_recorder as recorder
import chromium_native_recorder as native_implementation


NOW = 1000000000
PROOF = "01234567-89ab-4def-8123-0123456789ab"


def session():
    tools = {name: '/nix/store/' + 'a' * 32 + '-controller/' + name for name in runner.wrapper_custody.TOOLS}
    envelope = {name: {'path': '/srv/yoga-meta/' + ('native.json' if name == 'nativeManifest' else name), 'sha256': 'b' * 64}
                for name in runner.wrapper_custody.EVIDENCE}
    envelope['registeredNativeManifest']['path'] = '/nix/store/' + 'b' * 32 + '-native.json'
    envelope['controllerTools'] = tools
    return {"schemaVersion": 1, "scope": "yoga-operator-local-toolbar-v1", "hostAlias": "yoga",
        "proofId": PROOF, "operatorAccess": "local-console", "deadlineMonotonicNs": NOW + 1100 * 10**9,
        "coordinator": {"pid": 123, "cgroupPath": "/sys/fs/cgroup/omux-proof.service", "device": 1, "inode": 2},
        "display": {"adapter": "qualified-wayland-unix", "socketPath": "/tmp/omux-display/wayland-proof",
                    "socketDevice": 1, "socketInode": 3, "serverPid": 456},
        "inputSha256": {name: "0" * 64 for name in contract.INPUTS},
        'vaultWrapperAuthority': envelope,
        'wrapperSourceSha256': {name: 'c' * 64 for name in runner.wrapper_custody.HELPER_FILES}}


def attestation(case):
    interacted = case != "reload"
    return {"schemaVersion": 1, "scope": "human-toolbar-attestation", "proofId": PROOF, "case": case,
        "toolbarOpened": True, "consentChecked": interacted, "connectClicked": interacted,
        "browserPromptSeen": interacted,
        "browserDecision": {"denial": "denied", "approval": "approved", "reload": "not_requested"}[case]}


class AdmissionTest(unittest.TestCase):
    def refused(self, value, reason):
        with self.assertRaises(contract.Refusal) as raised:
            contract.validate_session(value, NOW)
        self.assertEqual(raised.exception.args, (reason,))

    def test_confirmed_wayland_local_console_shape(self):
        self.assertEqual(contract.validate_session(session(), NOW), session())
        self.assertEqual(contract.display_environment(session()["display"]),
                         ({"WAYLAND_DISPLAY": "/tmp/omux-display/wayland-proof"}, "wayland"))

    def test_default_runner_refuses_before_any_child_launch(self):
        with patch("sys.argv", ["runner"]), patch.object(runner.subprocess, "Popen") as launch:
            with self.assertRaises(contract.Refusal) as raised:
                runner.main()
            self.assertEqual(raised.exception.reason, "visible_session_required")
            launch.assert_not_called()

    def test_missing_display_and_boolean_schema_refuse(self):
        for edit in (lambda value: value.pop("display"), lambda value: value.update(schemaVersion=True)):
            value = session(); edit(value)
            self.refused(value, "visible_session_invalid")

    def test_unknown_profile_and_remote_operator_refuse(self):
        for key, replacement in (("hostAlias", "sting"), ("operatorAccess", "ssh-forwarded"),
                                 ("scope", "installed-chromium-synthetic-source-transport")):
            value = session(); value[key] = replacement
            self.refused(value, "visible_session_invalid")

    def test_original_deadline_cannot_be_extended_or_exhausted(self):
        for deadline in (NOW, NOW - 1, NOW + 1200 * 10**9 + 1, True):
            value = session(); value["deadlineMonotonicNs"] = deadline
            self.refused(value, "deadline_exceeded")

    def test_unqualified_and_x11_adapters_refuse(self):
        for adapter in ("wayland", "qualified-x11-unix", "ambient-display"):
            value = session(); value["display"]["adapter"] = adapter
            self.refused(value, "visible_adapter_unsupported")

    def test_no_extra_display_environment_or_parent_escape(self):
        for edit in (lambda display: display.update(DBUS_SESSION_BUS_ADDRESS="private"),
                     lambda display: display.update(socketPath="/tmp/../run/user/1/wayland-0"),
                     lambda display: display.update(socketPath="/tmp/./wayland-0"),
                     lambda display: display.update(socketPath="/tmp/socket\nname"),
                     lambda display: display.update(socketPath="wayland-0"),
                     lambda display: display.update(socketInode=True)):
            value = session(); edit(value["display"])
            self.refused(value, "display_custody_invalid")

    def test_no_cgroup_root_or_alias_or_missing_coordinator(self):
        for edit in (lambda coordinator: coordinator.update(cgroupPath="/sys/fs/cgroup"),
                     lambda coordinator: coordinator.update(cgroupPath="/sys/fs/cgroup/a/../b"),
                     lambda coordinator: coordinator.update(pid=True),
                     lambda coordinator: coordinator.update(inode=0)):
            value = session(); edit(value["coordinator"])
            self.refused(value, "aggregate_unqualified")

    def test_every_declared_input_has_exact_digest(self):
        for edit in (lambda hashes: hashes.pop("observer"), lambda hashes: hashes.update(browser="0" * 64),
                     lambda hashes: hashes.update(bundle="0" * 63), lambda hashes: hashes.update(node=True)):
            value = session(); edit(value["inputSha256"])
            self.refused(value, "visible_session_invalid")

    def test_wrapper_metadata_and_source_hashes_are_required_without_changing_eleven_inputs(self):
        self.assertEqual(len(contract.INPUTS), 11)
        for edit in (lambda value: value.pop('vaultWrapperAuthority'),
                     lambda value: value['vaultWrapperAuthority'].pop('controllerNarProof'),
                     lambda value: value['vaultWrapperAuthority'].update(extra=True),
                     lambda value: value['wrapperSourceSha256'].pop('delivery/yoga_wrapper_custody.py'),
                     lambda value: value['vaultWrapperAuthority']['companion'].update(path='/home/operator/companion')):
            value = session(); edit(value); self.refused(value, 'visible_session_invalid')

    def test_admitted_preserves_selected_vault_wrappers_and_declared_manifest(self):
        value = session()
        root = '/nix/store/' + 'a' * 32 + '-browser'
        paths = {name: '/srv/repository/tool_wrappers/' + name for name in contract.INPUTS}
        paths.update(chromium=root + '/bin/chromium', node=root + '/bin/node')
        arguments = SimpleNamespace(**paths, tool_manifest='/srv/repository/native.json', visible_session='/srv/session',
            visible_session_sha256=hashlib.sha256(json.dumps(value).encode()).hexdigest(), attestation_dir='/srv/attest')
        browser = SimpleNamespace(qualified_runtime=Mock(return_value=[root]), ROOT_METADATA={})
        authority = SimpleNamespace(validate_runtime_roots=Mock())
        def digest(path, **options):
            return 'c' * 64 if Path(path).name in ('yoga_wrapper_authority.py', 'yoga_wrapper_custody.py') else '0' * 64
        with patch.object(contract, 'private_read', side_effect=[json.dumps(value).encode(), PROOF.encode()]), \
                patch.object(contract, 'private_directory', return_value=Path('/srv/attest')), patch.object(contract, 'verify_live'), \
                patch.object(runner.Path, 'resolve', lambda path, strict=True: path), patch.object(runner, 'file_digest', side_effect=digest), \
                patch.object(runner.time, 'monotonic_ns', return_value=NOW), \
                patch.object(runner.sys, 'executable', value['vaultWrapperAuthority']['controllerTools']['python']), \
                patch.dict('sys.modules', {'test_installed_chromium': browser, 'browser_runtime_authority': authority}), \
                patch.object(runner.wrapper_custody, 'AuthorityCapture') as captured, patch.object(runner.subprocess, 'Popen') as child:
            result = runner.admitted(arguments)
        selected, options = captured.call_args
        self.assertEqual(selected[0], value['vaultWrapperAuthority'])
        self.assertEqual(selected[1], {name: paths[name] for name in ('dbus_session', 'dbus_daemon', 'keyring')})
        self.assertEqual(options['native_manifest_path'], arguments.tool_manifest)
        self.assertIs(result[3], captured.return_value)
        child.assert_not_called()

    def test_no_duplicate_json_or_nonfinite_numbers(self):
        for payload in (b'{"display":1,"display":2}', b'{"elapsed":NaN}', b'{"elapsed":Infinity}'):
            with self.assertRaises(contract.Refusal):
                contract.parse(payload)

    def test_effective_limits_refuse_unbounded_or_excessive_values(self):
        self.assertTrue(contract.limits_valid("4294967296", "0", "512", "200000 100000"))
        for values in (("max", "0", "512", "200000 100000"), ("4294967297", "0", "512", "200000 100000"),
                       ("4096", "1", "512", "200000 100000"), ("4096", "0", "max", "200000 100000"),
                       ("4096", "0", "513", "200000 100000"), ("4096", "0", "512", "max 100000"),
                       ("4096", "0", "512", "200001 100000"), ("4096", "0", "512", "0 0")):
            self.assertFalse(contract.limits_valid(*values))


class AttestationTest(unittest.TestCase):
    def test_manual_denial_approval_and_reopened_reload_are_distinct(self):
        for case in contract.CASES:
            self.assertEqual(contract.validate_attestation(attestation(case), PROOF, case), attestation(case))

    def test_no_prompt_inference_or_cross_case_replay(self):
        for key, replacement in (("browserPromptSeen", False), ("connectClicked", False),
                                 ("toolbarOpened", False), ("consentChecked", 1),
                                 ("browserDecision", "approved"), ("case", "approval"), ("proofId", "other")):
            value = attestation("denial"); value[key] = replacement
            with self.assertRaises(contract.Refusal):
                contract.validate_attestation(value, PROOF, "denial")

    def test_reload_must_not_attest_new_permission_request(self):
        value = attestation("reload"); value["browserPromptSeen"] = True
        with self.assertRaises(contract.Refusal):
            contract.validate_attestation(value, PROOF, "reload")

    def test_attestation_cannot_smuggle_identifiers_or_screenshots(self):
        for key in ("email", "screenshot", "rawFrame"):
            value = attestation("approval"); value[key] = "unexpected"
            with self.assertRaises(contract.Refusal):
                contract.validate_attestation(value, PROOF, "approval")


class CustodyTest(unittest.TestCase):
    def test_selector_allocation_failure_precedes_child_creation(self):
        with patch.object(runner.time, "monotonic_ns", return_value=NOW), \
             patch.object(runner.selectors, "DefaultSelector", side_effect=OSError), \
             patch.object(runner.subprocess, "Popen") as launch:
            with self.assertRaises(OSError):
                runner.private_group(["never-executed"], {}, NOW + 1)
            launch.assert_not_called()

    def test_expired_or_invalid_reserved_deadline_never_allocates_or_launches(self):
        for deadline in (NOW, NOW - 1, True, None, float("inf"), NOW + 1200 * 10**9 + 1):
            with patch.object(runner.time, "monotonic_ns", return_value=NOW), \
                 patch.object(runner.selectors, "DefaultSelector") as selected, \
                 patch.object(runner.subprocess, "Popen") as launch:
                with self.assertRaises(contract.Refusal) as raised:
                    runner.private_group(["never-executed"], {}, deadline)
                self.assertEqual(raised.exception.reason, "deadline_exceeded")
                selected.assert_not_called()
                launch.assert_not_called()

    def test_streaming_output_ceiling_stops_and_cleans_owned_group(self):
        process = Mock(pid=123)
        process.stdout.fileno.return_value = 7
        selected = Mock()
        selected.get_map.return_value = {7: "stdout"}
        selected.select.return_value = [(SimpleNamespace(fd=7, fileobj=process.stdout), None)]
        order = Mock()
        with patch.object(runner.selectors, "DefaultSelector", return_value=selected), \
             patch.object(runner.subprocess, "Popen", return_value=process), \
             patch.object(runner.os, "set_blocking"), \
             patch.object(runner.os, "read", side_effect=[b"a" * 4096, b"b" * 4096]) as read, \
             patch.object(runner.os, "waitid"), \
             patch.object(runner.os, "getpgid", return_value=123), \
             patch.object(runner.os, "killpg") as kill, \
             patch.object(runner.time, "monotonic_ns", return_value=NOW):
            order.attach_mock(kill, "kill")
            order.attach_mock(process.wait, "wait")
            with self.assertRaises(contract.Refusal) as raised:
                runner.private_group(["never-executed"], {}, NOW + 1, output_limit=4096)
            self.assertEqual(raised.exception.reason, "private_session_failed")
            self.assertEqual(read.call_count, 2)
            self.assertEqual(order.mock_calls, [call.kill(123, runner.signal.SIGKILL), call.wait(timeout=5)])
            process.stdout.close.assert_called_once()
            selected.close.assert_called_once()

    def test_regular_digest_and_fifo_type_rejection_before_any_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "input"; path.write_bytes(b"declared-input")
            self.assertEqual(runner.file_digest(path), hashlib.sha256(b"declared-input").hexdigest())
            fifo = root / "fifo"; os.mkfifo(fifo, 0o600)
            with patch.object(runner.os, "read") as read:
                with self.assertRaises(contract.Refusal) as raised:
                    runner.file_digest(fifo)
                self.assertEqual(raised.exception.reason, "input_digest_mismatch")
                read.assert_not_called()

    def test_digest_rejects_oversize_and_expired_deadline_before_read_or_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"; path.write_bytes(b"four")
            with patch.object(runner.os, "read") as read:
                with self.assertRaises(contract.Refusal):
                    runner.file_digest(path, maximum=3)
                read.assert_not_called()
            with patch.object(runner.time, "monotonic_ns", return_value=NOW), patch.object(runner.os, "open") as opened:
                with self.assertRaises(contract.Refusal) as raised:
                    runner.file_digest(path, deadline_ns=NOW)
                self.assertEqual(raised.exception.reason, "deadline_exceeded")
                opened.assert_not_called()

    def test_digest_rejects_final_symlink_and_midread_alias_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "input"; path.write_bytes(b"declared-input")
            alias = root / "alias"; alias.symlink_to(path)
            with self.assertRaises(contract.Refusal):
                runner.file_digest(alias)
            actual_read = os.read
            replaced = False
            def replace_after_read(descriptor, count):
                nonlocal replaced
                chunk = actual_read(descriptor, count)
                if chunk and not replaced:
                    replaced = True
                    path.rename(root / "retained-input")
                    path.symlink_to(root / "retained-input")
                return chunk
            with patch.object(runner.os, "read", side_effect=replace_after_read):
                with self.assertRaises(contract.Refusal) as raised:
                    runner.file_digest(path)
                self.assertEqual(raised.exception.reason, "input_digest_mismatch")
            self.assertTrue(replaced)

    def test_digest_deadline_is_rechecked_before_next_chunk(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"; path.write_bytes(b"declared-input")
            with patch.object(runner.time, "monotonic_ns", side_effect=[NOW, NOW, NOW + 2]), patch.object(runner.os, "read") as read:
                with self.assertRaises(contract.Refusal) as raised:
                    runner.file_digest(path, deadline_ns=NOW + 1)
                self.assertEqual(raised.exception.reason, "deadline_exceeded")
                read.assert_not_called()

    def test_digest_cannot_return_after_final_identity_checks_exhaust_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"; path.write_bytes(b"declared-input")
            with patch.object(runner.time, "monotonic_ns", side_effect=[NOW, NOW, NOW, NOW, NOW, NOW + 2]):
                with self.assertRaises(contract.Refusal) as raised:
                    runner.file_digest(path, deadline_ns=NOW + 1)
                self.assertEqual(raised.exception.reason, "deadline_exceeded")

    def test_private_attestation_rejects_alias_public_mode_fifo_and_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "attestation.json"
            path.write_bytes(b"{}"); path.chmod(0o600)
            self.assertEqual(contract.private_read(path), b"{}")
            alias = root / "alias"; alias.symlink_to(path)
            with self.assertRaises(OSError):
                contract.private_read(alias)
            path.chmod(0o644)
            with self.assertRaises(contract.Refusal):
                contract.private_read(path)
            path.chmod(0o600)
            with self.assertRaises(contract.Refusal):
                contract.private_read(path, 1)
            fifo = root / "fifo"; os.mkfifo(fifo, 0o600)
            with self.assertRaises(contract.Refusal):
                contract.private_read(fifo)


class RecorderTest(unittest.TestCase):
    def test_nonhealth_frames_are_redacted_and_never_forwarded(self):
        for method in ("browser.connect", "browser.importGrant", "browser.disconnect", "unknown"):
            project = Mock()
            append = Mock()
            implementation = {"unique_fields": dict, "invalid_constant": lambda _: None,
                              "project": project, "append": append}
            frame = b"\0\0\0\0" + json.dumps({"id": "must-not-be-retained", "method": method,
                "params": {"sourceId": "must-not-be-retained"}}).encode()
            with self.assertRaises(ValueError):
                recorder.health_only(frame, "a" * 32, implementation, "private-journal")
            project.assert_not_called()
            append.assert_called_once_with("private-journal", {"id": "omitted", "method": "unexpected_request", "sourceId": None})

    def test_health_uses_existing_strict_projector(self):
        projected = {"id": "test", "method": "browser.health", "sourceId": None}
        project = Mock(return_value=projected)
        append = Mock()
        implementation = {"unique_fields": dict, "invalid_constant": lambda _: None,
                          "project": project, "append": append}
        frame = b"\0\0\0\0" + b'{"method":"browser.health"}'
        self.assertEqual(recorder.health_only(frame, "a" * 32, implementation, "journal"), projected)
        project.assert_called_once_with(frame, "a" * 32)
        append.assert_not_called()

    def test_invalid_health_provenance_and_duplicate_fields_are_not_forwarded(self):
        append = Mock()
        implementation = {"unique_fields": native_implementation.unique_fields,
            "invalid_constant": native_implementation.invalid_constant, "project": native_implementation.project, "append": append}
        valid = {"version": 1, "id": "chromium-service-health", "method": "browser.health",
                 "params": {"provenance": {"browser": "chromium", "extensionId": "a" * 32, "channel": "development"}}}
        frame = b"\0\0\0\0" + json.dumps(valid).encode()
        self.assertEqual(recorder.health_only(frame, "a" * 32, implementation, "journal")["method"], "browser.health")
        append.assert_not_called()
        valid["params"]["provenance"]["channel"] = "release"
        for payload in (json.dumps(valid).encode(), b'{"method":"browser.health","method":"browser.connect"}'):
            append.reset_mock()
            with self.assertRaises(ValueError):
                recorder.health_only(b"\0\0\0\0" + payload, "a" * 32, implementation, "journal")
            append.assert_called_once_with("journal", {"id": "omitted", "method": "unexpected_request", "sourceId": None})


if __name__ == "__main__":
    unittest.main()
