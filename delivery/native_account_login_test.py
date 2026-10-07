"""Offline private-channel and ownership models; no native/provider execution."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import urllib.parse

import native_account_login as action

def selected():
    return {"authorize_provider_login": True, "no_cancel_build_qualified": True,
        "native_sha256": "a" * 64, "source_receipt_sha256": "b" * 64,
        "state_parent": "/private/fixture-state", "private_ui_fd": 3, "deadline_seconds": 60}

def synthetic_uri():
    return "https://auth.openai.com/oauth/authorize?" + urllib.parse.urlencode({
        "redirect_uri": "http://localhost:1455/auth/callback", "state": "synthetic-state",
        "code_challenge": "synthetic-challenge", "client_id": "synthetic-client"})

class Model:
    def __init__(self, success=True):
        self.sent = []
        self.success = success

    def send(self, method, params, identifier=None, until=None):
        self.sent.append((method, params, identifier))

    def result(self, identifier, until):
        if identifier == 1:
            return {}
        return {"type": "chatgpt", "loginId": "synthetic-login", "authUrl": synthetic_uri()}

    def receive(self, until):
        return {"method": "account/login/completed", "params": {
            "loginId": "synthetic-login", "success": self.success,
            "error": "synthetic-private-error-that-must-not-escape"}}

class Contract(unittest.TestCase):
    def test_device_login_uses_only_device_rpc_and_private_canonical_frame(self):
        native = Model()
        original = native.result
        native.result = lambda identifier, until: original(identifier, until) if identifier == 1 else {
            "type": "chatgptDeviceCode", "loginId": "synthetic-login",
            "verificationUrl": "https://auth.openai.com/codex/device", "userCode": "MODEL-NOT-A-SECRET"}
        reader, writer = os.pipe()
        captured = io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):
                action.device_login(native, writer, time.monotonic() + 1, healthy=lambda: True)
            value = json.loads(os.read(reader, 4096))
            self.assertEqual(value, {"verification_url": "https://auth.openai.com/codex/device", "user_code": "MODEL-NOT-A-SECRET"})
            self.assertEqual([params for method, params, _ in native.sent if method == "account/login/start"], [{"type": "chatgptDeviceCode"}])
            self.assertEqual(captured.getvalue(), "")
        finally:
            os.close(reader)
            os.close(writer)

    def test_device_prompt_refuses_browser_uri_control_code_and_wrong_kind(self):
        started = {"type": "chatgptDeviceCode", "loginId": "synthetic-login", "verificationUrl": "https://auth.openai.com/codex/device", "userCode": "MODEL-NOT-A-SECRET"}
        for field, value in (("type", "chatgpt"), ("verificationUrl", "https://auth.openai.com/oauth/authorize"), ("userCode", "bad\\ncode"), ("userCode", "x" * 129)):
            with self.assertRaises(action.Refusal):
                action.device_prompt({**started, field: value})

    def test_cancelled_device_ui_never_requests_provider_login(self):
        native = Model()
        with self.assertRaisesRegex(action.Refusal, "private_ui_transport_unavailable"):
            action.device_login(native, -1, time.monotonic() + 1, healthy=lambda: False)
        self.assertEqual(native.sent, [])

    def test_device_error_is_fixed_without_provider_message(self):
        native = Model(success=False)
        native.result = lambda identifier, until: {} if identifier == 1 else {
            "type": "chatgptDeviceCode", "loginId": "synthetic-login", "verificationUrl": "https://auth.openai.com/codex/device", "userCode": "MODEL-NOT-A-SECRET"}
        with mock.patch.object(action, "write_private"):
            with self.assertRaisesRegex(action.Refusal, "^native_login_failed$"):
                action.device_login(native, 3, time.monotonic() + 1)
    def test_pidfd_initialization_failure_closes_and_escalates_only_owned_child(self):
        process = mock.Mock()
        process.pid = 43210
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.poll.return_value = None
        process.wait.side_effect = [action.subprocess.TimeoutExpired("owned-fixture", 5),
            action.subprocess.TimeoutExpired("owned-fixture", 5), 0]
        captured = io.StringIO()
        with mock.patch.object(action.subprocess, "Popen", return_value=process), \
             mock.patch.object(action.os, "pidfd_open", side_effect=OSError("fixture failure")), \
             contextlib.redirect_stdout(captured):
            with self.assertRaisesRegex(action.Refusal, "native_initialization_failed"):
                action.Native(3, {}, "/owned-fixture")
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 3)

    def test_selector_initialization_failure_closes_held_pidfd_after_owned_escalation(self):
        process = mock.Mock()
        process.pid = 43210
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.wait.side_effect = [action.subprocess.TimeoutExpired("owned-fixture", 5),
            action.subprocess.TimeoutExpired("owned-fixture", 5), 0]
        captured = io.StringIO()
        with mock.patch.object(action.subprocess, "Popen", return_value=process), \
             mock.patch.object(action.os, "pidfd_open", return_value=987), \
             mock.patch.object(action.selectors, "DefaultSelector", side_effect=OSError("fixture failure")), \
             mock.patch.object(action.signal, "pidfd_send_signal") as sent, \
             mock.patch.object(action.os, "close") as closed, contextlib.redirect_stdout(captured):
            with self.assertRaisesRegex(action.Refusal, "native_initialization_failed"):
                action.Native(3, {}, "/owned-fixture")
        self.assertEqual(sent.call_args_list, [mock.call(987, action.signal.SIGTERM), mock.call(987, action.signal.SIGKILL)])
        closed.assert_called_once_with(987)
        self.assertTrue(process.stdout.closed)

    def test_metadata_input_deadline_applies_before_provider_admission(self):
        read, write = os.pipe()
        try:
            before = fcntl.fcntl(read, fcntl.F_GETFL)
            with self.assertRaisesRegex(action.Refusal, "metadata_input_deadline"):
                action.metadata_input(read, time.monotonic() + 0.05)
            self.assertEqual(fcntl.fcntl(read, fcntl.F_GETFL), before)
        finally:
            os.close(read)
            os.close(write)

    def test_stalled_native_stdin_has_send_deadline_and_restores_flags(self):
        read, write = os.pipe()
        writer = None
        try:
            os.set_blocking(write, False)
            while True:
                try:
                    os.write(write, b"x" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(write, True)
            before = fcntl.fcntl(write, fcntl.F_GETFL)
            writer = os.fdopen(os.dup(write), "wb")
            native = object.__new__(action.Native)
            native.process = type("StalledOwnedChild", (), {"stdin": writer})()
            with self.assertRaisesRegex(action.Refusal, "native_send_deadline"):
                native.send("initialize", {}, 1, until=time.monotonic() + 0.05)
            self.assertEqual(fcntl.fcntl(write, fcntl.F_GETFL), before)
        finally:
            if writer is not None:
                writer.close()
            os.close(read)
            os.close(write)

    def test_provider_opt_in_precedes_every_launch(self):
        value = selected()
        value["authorize_provider_login"] = False
        with self.assertRaisesRegex(action.Refusal, "provider_login_not_authorized"):
            action.configuration(json.dumps(value).encode())

    def test_retained_no_cancel_behavior_cannot_be_assumed(self):
        value = selected()
        value["no_cancel_build_qualified"] = False
        with self.assertRaisesRegex(action.Refusal, "no_cancel_build_required"):
            action.configuration(json.dumps(value).encode())

    def test_regular_file_and_stdio_cannot_receive_native_uri(self):
        with tempfile.TemporaryFile() as sink:
            with self.assertRaisesRegex(action.Refusal, "private_ui_required"):
                action.private_ui(sink.fileno())
        for standard in (0, 1, 2):
            alias = os.dup(standard)
            try:
                with self.assertRaisesRegex(action.Refusal, "private_ui_required"):
                    action.private_ui(alias)
            finally:
                os.close(alias)

    def test_uri_is_delivered_only_to_held_private_channel(self):
        read, write = os.pipe()
        captured = io.StringIO()
        try:
            model = Model()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                action.login(model, write, time.monotonic() + 1)
            self.assertEqual(captured.getvalue(), "")
            self.assertEqual(os.read(read, action.MAX_URI), synthetic_uri().encode() + b"\n")
            self.assertEqual([row[0] for row in model.sent], ["initialize", "initialized", "account/login/start"])
        finally:
            os.close(read)
            os.close(write)

    def test_native_error_text_is_not_a_diagnostic(self):
        read, write = os.pipe()
        try:
            with self.assertRaisesRegex(action.Refusal, "^native_login_failed$"):
                action.login(Model(False), write, time.monotonic() + 1)
        finally:
            os.close(read)
            os.close(write)

    def test_uri_must_use_exact_provider_and_registered_loopback(self):
        for changed in (synthetic_uri().replace("auth.openai.com", "attacker.invalid"),
                        synthetic_uri().replace("localhost%3A1455", "localhost%3A9000")):
            with self.assertRaises(action.Refusal):
                action.authorization_url(changed)

    def test_generated_profile_preserves_existing_active_auth_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            active = parent / "active-profile"
            active.mkdir(mode=0o700)
            sentinel = active / "auth.json"
            sentinel.write_bytes(b"noncredential-owned-preservation-sentinel")
            before = sentinel.stat()
            handle, created, fd = action.profile(str(parent))
            try:
                self.assertEqual(created.name, "native-login-" + handle)
                self.assertNotEqual(created, active)
                self.assertEqual(list(created.iterdir()), [])
                self.assertEqual(sentinel.read_bytes(), b"noncredential-owned-preservation-sentinel")
                after = sentinel.stat()
                self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                                 (after.st_ino, after.st_size, after.st_mtime_ns))
            finally:
                os.close(fd)

    def test_profile_parent_symlink_refuses_without_reading_native_auth(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            destination = parent / "owned"
            destination.mkdir(mode=0o700)
            linked = parent / "linked"
            linked.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(OSError):
                action.profile(str(linked))
            self.assertEqual(list(destination.iterdir()), [])

    def test_duplicate_authorization_and_unbounded_deadline_refuse(self):
        with self.assertRaisesRegex(action.Refusal, "native_duplicate_field"):
            action.configuration(b'{"authorize_provider_login":false,"authorize_provider_login":true}')
        value = selected()
        value["deadline_seconds"] = 901
        with self.assertRaisesRegex(action.Refusal, "deadline_invalid"):
            action.configuration(json.dumps(value).encode())

if __name__ == "__main__":
    unittest.main()
