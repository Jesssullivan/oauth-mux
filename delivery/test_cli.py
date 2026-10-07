"""Built Git-helper framing regressions; execute only via Bazel //delivery:cli_test.

A same-user local test peer isolates CLI forwarding from provider/vault access.
Capabilities and credential payloads are generated only in private temporary
state. Assertions never render those values or captured messages.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


MAX_FRAME = 1024 * 1024
OMUX = Path(sys.argv.pop(1))


class AdapterPeer:
    def __init__(self, path: Path, rejection: str | None = None) -> None:
        self.path = path
        self.rejection = rejection
        self.requests: list[dict] = []
        self.failure = False
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket_identity: tuple[int, int, int, int] | None = None
        try:
            self.listener.bind(str(path))
            information = path.lstat()
            if not stat.S_ISSOCK(information.st_mode) or information.st_uid != os.getuid():
                raise ValueError("test socket ownership changed after bind")
            self.socket_identity = (information.st_dev, information.st_ino, information.st_uid,
                                    stat.S_IFMT(information.st_mode))
            path.chmod(0o600)
            self.listener.listen(4)
            self.listener.settimeout(0.1)
            self.thread = threading.Thread(target=self.serve, daemon=True)
        except BaseException:
            self.listener.close()
            self.unlink_owned_socket()
            raise

    def __enter__(self) -> "AdapterPeer":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stopping.set()
        try:
            self.thread.join(timeout=2)
            self.failure = self.failure or self.thread.is_alive()
        finally:
            self.listener.close()
            if not self.thread.is_alive():
                self.unlink_owned_socket()

    def unlink_owned_socket(self) -> None:
        if self.socket_identity is None:
            return
        try:
            information = self.path.lstat()
            current = (information.st_dev, information.st_ino, information.st_uid,
                       stat.S_IFMT(information.st_mode))
            if current == self.socket_identity:
                self.path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def read_request(connection: socket.socket) -> dict:
        connection.settimeout(5)
        payload = bytearray()
        while len(payload) <= MAX_FRAME:
            chunk = connection.recv(min(4096, MAX_FRAME + 1 - len(payload)))
            if not chunk:
                raise ValueError("incomplete test frame")
            payload.extend(chunk)
            if b"\n" in chunk:
                if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
                    raise ValueError("unexpected test framing")
                value = json.loads(payload[:-1])
                if not isinstance(value, dict):
                    raise ValueError("unexpected test request type")
                return value
        raise ValueError("test frame exceeds limit")

    def serve(self) -> None:
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    request = self.read_request(connection)
                    self.requests.append(request)
                    connection.sendall(self.reply_payload(request))
        except Exception:
            # Captured requests and even peer diagnostics can contain runtime
            # secrets. Report only a fixed failure flag through unittest.
            self.failure = True

    def reply_payload(self, request: dict) -> bytes:
        reply = {"jsonrpc": "2.0", "id": request.get("id")}
        if self.rejection is not None:
            reply["error"] = {"code": -32000, "message": self.rejection}
        elif request.get("method") == "adapter.gitGet":
            reply["error"] = {"code": -32000, "message": "NoEligibleAccount"}
        else:
            reply["result"] = None
        return json.dumps(reply, separators=(",", ":")).encode() + b"\n"


class ControlPeer(AdapterPeer):
    def __init__(self, path: Path, mode: str) -> None:
        super().__init__(path)
        self.mode = mode
        self.effects = 0
        self.operation_id: str | None = None

    def verification_terminal(self) -> dict:
        timed_out = self.mode.startswith("terminal-timeout")
        refusal = self.mode == "terminal-refusal" or timed_out
        return {
            "schema_version": 1, "operation_id": self.operation_id,
            "generation": 0 if refusal and not timed_out else 1, "observed_at": 1,
            "outcome": "safe_refusal" if refusal else "verification_completed",
            "refusal": "collection_timed_out" if timed_out else "installation_selection_required" if refusal else None,
            "phases": [{"outcome": "unknown", "reason": "observation_unknown"} for _ in range(7)],
            "elapsed_ns": None if refusal else 10,
            "timing_scope": "admission_to_terminal_before_commit_process_local",
        }

    def reply_payload(self, request: dict) -> bytes:
        reply = {"jsonrpc": "2.0", "id": request.get("id")}
        method = request.get("method")
        if method == "system.handshake":
            reply["result"] = {"protocol_version": 2}
        elif method == "state.snapshot":
            if self.mode == "read-error":
                reply["error"] = {"code": -32000, "message": "CustodyUnavailable"}
            else:
                reply["result"] = {"revision": 7}
        elif method == "integrations.install":
            self.effects += 1  # The reply fails after the fixture's external effect.
            self.operation_id = request.get("params", {}).get("operation_id")
            if self.mode == "malformed-json":
                return b"invalid-json\n"
            if self.mode == "malformed-result":
                reply["result"] = None
            elif self.mode == "wrong-correlation":
                reply["id"] = 99
                reply["result"] = {"installed": True}
            else:
                reply["error"] = {"code": -32000, "message": "NativeTimeout"}
        elif method == "setup.refresh":
            params = request.get("params") or {}
            if params:
                self.effects += 1
                self.operation_id = params.get("operation_id")
                if self.mode == "lost-reply":
                    return b""
                if self.mode == "malformed-json":
                    return b"invalid-json\n"
                if self.mode == "malformed-result":
                    reply["result"] = None
                elif self.mode == "declared":
                    reply["error"] = {"code": -32000, "message": "CustodyUnavailable"}
                else:
                    reply["result"] = {"schema_version": 1, "operation_id": self.operation_id,
                                       "generation": 1, "status": "pending"}
                    if self.mode == "malformed-object":
                        reply["result"] = {}
                    elif self.mode == "wrong-correlation":
                        reply["id"] = 99
                    elif self.mode == "wrong-identity":
                        reply["result"]["operation_id"] = "another-verification"
                    elif self.mode == "pending-extra-field":
                        reply["result"]["unexpected"] = True
                    elif self.mode == "pending-zero-generation":
                        reply["result"]["generation"] = 0
                    elif self.mode == "pending-float-generation":
                        reply["result"]["generation"] = 1.0
                    elif self.mode == "pending-string-generation":
                        reply["result"]["generation"] = "1"
                    elif self.mode.startswith("terminal-"):
                        terminal = self.verification_terminal()
                        reply["result"] = terminal
                        if self.mode == "terminal-wide":
                            terminal.update(generation=2**64 - 1, observed_at=2**63 - 1,
                                            elapsed_ns=2**64 - 1)
                        elif self.mode == "terminal-wrong-identity":
                            terminal["operation_id"] = "another-verification"
                        elif self.mode == "terminal-missing-field":
                            del terminal["refusal"]
                        elif self.mode == "terminal-short-phases":
                            terminal["phases"].pop()
                        elif self.mode == "terminal-missing-phase-field":
                            del terminal["phases"][0]["reason"]
                        elif self.mode == "terminal-extra-phase-field":
                            terminal["phases"][0]["unexpected"] = True
                        elif self.mode == "terminal-wrong-classification":
                            terminal["phases"][0]["outcome"] = "verified_ready"
                        elif self.mode == "terminal-unknown-reason":
                            terminal["phases"][0]["reason"] = "invented"
                        elif self.mode == "terminal-invalid-timing-scope":
                            terminal["timing_scope"] = "end_to_end"
                        elif self.mode == "terminal-string-generation":
                            terminal["generation"] = "1"
                        elif self.mode == "terminal-negative-observed-at":
                            terminal["observed_at"] = -1
                        elif self.mode == "terminal-overflow-generation":
                            terminal["generation"] = 2**64
                        elif self.mode == "terminal-zero-generation":
                            terminal["generation"] = 0
                        elif self.mode == "terminal-timeout-false-ready":
                            terminal["phases"][0] = {"outcome": "verified_ready", "reason": "ready"}
                        elif self.mode == "terminal-timeout-false-timing":
                            terminal["elapsed_ns"] = 10
                        elif self.mode == "terminal-duplicate-phase-field":
                            encoded = json.dumps(reply, separators=(",", ":"))
                            return encoded.replace('"reason":"observation_unknown"',
                                                   '"reason":"ready","reason":"observation_unknown"', 1).encode() + b"\n"
                    elif self.mode == "duplicate-result-field":
                        encoded = json.dumps(reply, separators=(",", ":"))
                        return encoded.replace('"generation":1', '"generation":0,"generation":1', 1).encode() + b"\n"
                    elif self.mode == "duplicate-envelope-field":
                        encoded = json.dumps(reply, separators=(",", ":"))
                        return encoded.replace('"id":1', '"id":99,"id":1', 1).encode() + b"\n"
            elif self.mode == "declared":
                reply["error"] = {"code": -32000, "message": "CustodyUnavailable"}
            else:
                reply["result"] = {"schema_version": 1, "generation": 1, "status": "pending"}
        elif method == "setup.applicationReadiness":
            if self.mode == "read-error":
                reply["error"] = {"code": -32000, "message": "CustodyUnavailable"}
            else:
                reply["result"] = {"schema_version": 1, "application": "codex",
                                   "ready": False, "reason": "context_required",
                                   "provider_access": False, "seamless_handoff_proven": False}
        elif method == "operation.status":
            if request.get("params", {}).get("operation_id") != self.operation_id:
                raise ValueError("query lost its original identity")
            reply["result"] = {"operation_id": self.operation_id, "status": "indeterminate", "result": None}
        else:
            raise ValueError("unexpected control request")
        return json.dumps(reply, separators=(",", ":")).encode() + b"\n"


class MutationCliTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()))
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.state.chmod(0o700)
        run = self.state / "run"
        run.mkdir(mode=0o700)
        self.socket_path = run / "control.sock"
        self.environment = dict(os.environ)
        self.environment.pop("XDG_RUNTIME_DIR", None)

    def invoke(self, method: str, params: dict) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(OMUX), "--state-dir", str(self.state), "rpc", method, "-"],
            input=json.dumps(params).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.environment, timeout=10, check=False,
        )

    def assert_original_identity_recoverable(self, mode: str, provided_id: str | None = None) -> None:
        params = {"adapter": "codex"}
        if provided_id is not None:
            params.update(operation_id=provided_id, expected_revision=7)
        with ControlPeer(self.socket_path, mode) as peer:
            failed = self.invoke("integrations.install", params)
            self.assertNotEqual(failed.returncode, 0)
            metadata = []
            for line in failed.stderr.splitlines():
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if isinstance(value, dict) and value.get("status") == "unresolved":
                    metadata.append(value)
            self.assertEqual(len(metadata), 1, "failure lost its machine-readable operation guidance")
            guide = metadata[0]
            self.assertTrue(guide["operation_id"] == peer.operation_id, "diagnostic identity differs from issued mutation")
            self.assertTrue(guide["query"]["params"]["operation_id"] == peer.operation_id, "query guidance changed identity")
            self.assertEqual(guide["query"]["method"], "operation.status")
            if provided_id is not None:
                self.assertTrue(peer.operation_id == provided_id, "caller identity changed")
            else:
                self.assertTrue(isinstance(peer.operation_id, str) and len(peer.operation_id) == 64)
                self.assertTrue(all(byte in "0123456789abcdef" for byte in peer.operation_id))
            issued = [request for request in peer.requests if request.get("method") == "integrations.install"]
            self.assertEqual(len(issued), 1)
            self.assertEqual(issued[0]["params"]["expected_revision"], 7)
            self.assertFalse(any(request.get("method") == "operation.status" for request in peer.requests), "CLI performed an automatic outcome query")
            if mode == "declared":
                original = json.loads(failed.stdout)
                self.assertEqual(original["error"]["message"], "NativeTimeout")
                self.assertNotIn("operation_id", original, "stdout JSON shape changed")
            recovered = self.invoke(guide["query"]["method"], guide["query"]["params"])
            self.assertEqual(recovered.returncode, 0)
            outcome = json.loads(recovered.stdout)["result"]
            self.assertTrue(outcome["operation_id"] == peer.operation_id, "later invocation queried another identity")
            self.assertEqual(outcome["status"], "indeterminate")
            self.assertEqual(peer.effects, 1, "the failed external action was replayed")
        self.assertFalse(peer.failure, "test control peer failed")

    def test_declared_failure_preserves_generated_id(self) -> None:
        self.assert_original_identity_recoverable("declared")

    def test_declared_failure_preserves_caller_id(self) -> None:
        self.assert_original_identity_recoverable("declared", "caller-action-1")

    def test_malformed_json_preserves_original_id(self) -> None:
        self.assert_original_identity_recoverable("malformed-json")

    def test_malformed_result_preserves_original_id(self) -> None:
        self.assert_original_identity_recoverable("malformed-result")

    def test_wrong_correlation_preserves_original_id(self) -> None:
        self.assert_original_identity_recoverable("wrong-correlation")

    def test_read_only_error_has_no_mutation_guidance(self) -> None:
        with ControlPeer(self.socket_path, "read-error") as peer:
            failed = self.invoke("state.snapshot", {})
        self.assertFalse(peer.failure, "test control peer failed")
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(json.loads(failed.stdout)["error"]["message"], "CustodyUnavailable")
        self.assertNotIn(b"operation_id", failed.stderr)
        self.assertEqual(peer.effects, 0)

    def invoke_setup(self, action: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(OMUX), "--state-dir", str(self.state), "setup", action],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment,
            timeout=10, check=False,
        )

    def test_application_readiness_routes_declared_context_without_mutation_authority(self) -> None:
        params = {"application": "codex", "expected_revision": 7}
        with ControlPeer(self.socket_path, "success") as peer:
            result = subprocess.run(
                [str(OMUX), "--state-dir", str(self.state), "application-readiness", "-"],
                input=json.dumps(params).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self.environment, timeout=10, check=False,
            )
        self.assertFalse(peer.failure)
        self.assertEqual(result.returncode, 0)
        queries = [request for request in peer.requests if request.get("method") == "setup.applicationReadiness"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]["params"], params)
        self.assertFalse(any(request.get("method") == "state.snapshot" for request in peer.requests))
        self.assertEqual(peer.effects, 0)
        self.assertNotIn(b"operation_id", result.stderr)
        self.assertFalse(json.loads(result.stdout)["result"]["ready"])

    def test_application_readiness_requires_stdin_marker_before_connecting(self) -> None:
        for arguments in ([], ["codex"], ["-", "codex"]):
            result = subprocess.run(
                [str(OMUX), "--state-dir", str(self.state), "application-readiness", *arguments],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment,
                timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"ParametersRequireStdin", result.stderr)

    def test_setup_refresh_preserves_legacy_diagnostic_parameters(self) -> None:
        with ControlPeer(self.socket_path, "success") as peer:
            result = self.invoke_setup("refresh")
        self.assertFalse(peer.failure)
        self.assertEqual(result.returncode, 0)
        refresh = [request for request in peer.requests if request.get("method") == "setup.refresh"]
        self.assertEqual(len(refresh), 1)
        self.assertIsNone(refresh[0].get("params"))
        self.assertFalse(any(request.get("method") == "state.snapshot" for request in peer.requests))
        self.assertIsNone(peer.operation_id)
        self.assertNotIn(b"operation_id", result.stderr)

    def test_setup_verify_uses_stable_identity_and_revision_without_extra_fields(self) -> None:
        with ControlPeer(self.socket_path, "success") as peer:
            result = self.invoke_setup("verify")
        self.assertFalse(peer.failure)
        self.assertEqual(result.returncode, 0)
        refresh = [request for request in peer.requests if request.get("method") == "setup.refresh"]
        self.assertEqual(len(refresh), 1)
        params = refresh[0]["params"]
        self.assertEqual(set(params), {"operation_id", "expected_revision"})
        self.assertEqual(params["expected_revision"], 7)
        self.assertEqual(len(params["operation_id"]), 64)
        self.assertTrue(all(byte in "0123456789abcdef" for byte in params["operation_id"]))
        self.assertEqual(json.loads(result.stdout)["result"]["operation_id"], params["operation_id"])
        self.assertEqual(json.loads(result.stdout)["result"], {
            "schema_version": 1, "operation_id": params["operation_id"],
            "generation": 1, "status": "pending",
        })
        self.assertEqual(result.stderr, b"")
        self.assertEqual(peer.effects, 1)
        self.assertFalse(any(request.get("method") == "operation.status" for request in peer.requests))

    def test_identified_refresh_rpc_preserves_caller_identity(self) -> None:
        with ControlPeer(self.socket_path, "success") as peer:
            result = self.invoke("setup.refresh", {"operation_id": "caller-verification-1", "expected_revision": 7})
        self.assertFalse(peer.failure)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(peer.operation_id, "caller-verification-1")
        self.assertFalse(any(request.get("method") == "state.snapshot" for request in peer.requests))

    def test_verify_lost_or_invalid_reply_retains_query_identity_without_replay(self) -> None:
        for mode in ("lost-reply", "malformed-json", "malformed-result", "declared", "malformed-object",
                     "wrong-correlation", "wrong-identity",
                     "pending-extra-field", "pending-zero-generation", "pending-float-generation",
                     "pending-string-generation", "duplicate-result-field", "duplicate-envelope-field",
                     "terminal-wrong-identity", "terminal-missing-field", "terminal-short-phases",
                     "terminal-missing-phase-field", "terminal-extra-phase-field", "terminal-wrong-classification",
                     "terminal-unknown-reason", "terminal-invalid-timing-scope", "terminal-string-generation",
                     "terminal-negative-observed-at", "terminal-overflow-generation", "terminal-zero-generation",
                     "terminal-duplicate-phase-field", "terminal-timeout-false-ready", "terminal-timeout-false-timing"):
            with self.subTest(mode=mode), ControlPeer(self.socket_path, mode) as peer:
                failed = self.invoke_setup("verify")
                self.assertNotEqual(failed.returncode, 0)
                guidance = []
                for line in failed.stderr.splitlines():
                    try:
                        value = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if isinstance(value, dict) and value.get("status") == "unresolved":
                        guidance.append(value)
                self.assertEqual(len(guidance), 1)
                guide = guidance[0]
                self.assertEqual(guide["operation_id"], peer.operation_id)
                self.assertEqual(guide["query"]["method"], "operation.status")
                self.assertEqual(guide["query"]["params"]["operation_id"], peer.operation_id)
                issued = [request for request in peer.requests if request.get("method") == "setup.refresh"]
                self.assertEqual(len(issued), 1)
                self.assertFalse(any(request.get("method") == "operation.status" for request in peer.requests))
                recovered = self.invoke(guide["query"]["method"], guide["query"]["params"])
                self.assertEqual(recovered.returncode, 0)
                self.assertEqual(json.loads(recovered.stdout)["result"]["operation_id"], peer.operation_id)
                self.assertEqual(peer.effects, 1)
            self.assertFalse(peer.failure)

    def test_identified_refresh_rpc_keeps_caller_identity_after_invalid_terminal(self) -> None:
        with ControlPeer(self.socket_path, "terminal-wrong-identity") as peer:
            result = self.invoke("setup.refresh", {"operation_id": "caller-verification-1", "expected_revision": 7})
        self.assertFalse(peer.failure)
        self.assertNotEqual(result.returncode, 0)
        guidance = [json.loads(line) for line in result.stderr.splitlines() if line.startswith(b"{")]
        self.assertEqual(len(guidance), 1)
        self.assertEqual(guidance[0]["operation_id"], "caller-verification-1")
        self.assertEqual(guidance[0]["query"], {
            "method": "operation.status", "params": {"operation_id": "caller-verification-1"},
        })
        self.assertEqual(peer.effects, 1)
        self.assertFalse(any(request.get("method") == "operation.status" for request in peer.requests))

    def test_verify_accepts_exact_completed_refused_and_wide_terminal_results(self) -> None:
        for mode in ("terminal-completed", "terminal-refusal", "terminal-timeout-refusal", "terminal-wide"):
            with self.subTest(mode=mode), ControlPeer(self.socket_path, mode) as peer:
                result = self.invoke_setup("verify")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b"")
                expected = peer.verification_terminal()
                if mode == "terminal-wide":
                    expected.update(generation=2**64 - 1, observed_at=2**63 - 1,
                                    elapsed_ns=2**64 - 1)
                self.assertEqual(json.loads(result.stdout)["result"], expected)
                self.assertEqual(peer.effects, 1)
                self.assertEqual(len([request for request in peer.requests
                                      if request.get("method") == "setup.refresh"]), 1)
                self.assertFalse(any(request.get("method") == "operation.status" for request in peer.requests))
            self.assertFalse(peer.failure)

    def test_legacy_refresh_refusal_has_no_identified_operation_guidance(self) -> None:
        with ControlPeer(self.socket_path, "declared") as peer:
            result = self.invoke_setup("refresh")
        self.assertFalse(peer.failure)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"operation_id", result.stderr)
        self.assertEqual(peer.effects, 0)


class GitHelperCliTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()))
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.state.chmod(0o700)
        integrations = self.state / "integrations"
        integrations.mkdir(mode=0o700)
        run = self.state / "run"
        run.mkdir(mode=0o700)
        self.capability = secrets.token_hex(32)
        capability_path = integrations / "git.capability"
        capability_path.write_text(self.capability)
        capability_path.chmod(0o600)
        self.password = secrets.token_hex(32)
        self.native_input = (
            "protocol=https\nhost=github.com\npath=fixture/project.git\n"
            "username=synthetic-user\npassword=" + self.password + "\n\n"
        ).encode()
        self.socket_path = run / "adapter.sock"

    def invoke(self, operation: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(OMUX), "--state-dir", str(self.state), "git-credential", operation],
            input=self.native_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

    def assert_silent_success(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout == b"", "credential helper unexpectedly wrote output")
        self.assertTrue(result.stderr == b"", "credential helper unexpectedly wrote diagnostics")

    def assert_context(self, request: dict, method: str) -> dict:
        self.assertTrue(request.get("jsonrpc") == "2.0", "unexpected adapter protocol")
        self.assertTrue(request.get("method") == method, "unexpected adapter method")
        params = request.get("params", {})
        self.assertTrue(params.get("application") == "git", "unexpected adapter application")
        self.assertTrue(params.get("capability") == self.capability, "adapter capability was not forwarded")
        context = params.get("request", {})
        self.assertTrue(context.get("protocol") == "https", "Git protocol changed")
        self.assertTrue(context.get("host") == "github.com", "Git host changed")
        self.assertTrue(context.get("path") == "fixture/project.git", "Git scope changed")
        self.assertTrue(context.get("username") == "synthetic-user", "Git username changed")
        return context

    def test_get_omits_password_and_erase_forwards_rejected_password(self) -> None:
        with AdapterPeer(self.socket_path) as peer:
            self.assert_silent_success(self.invoke("get"))
            self.assert_silent_success(self.invoke("erase"))
        self.assertFalse(peer.failure, "test adapter peer failed")
        self.assertEqual(len(peer.requests), 2)
        get = self.assert_context(peer.requests[0], "adapter.gitGet")
        self.assertTrue("password" not in get, "get forwarded an external credential")
        erase = self.assert_context(peer.requests[1], "adapter.gitErase")
        self.assertTrue(erase.get("password") == self.password, "erase lost the rejected credential")
        peer.requests.clear()

    def test_store_does_not_contact_daemon_or_adopt_external_credential(self) -> None:
        with AdapterPeer(self.socket_path) as peer:
            expected_paths = {path.relative_to(self.state) for path in self.state.rglob("*")}
            self.assert_silent_success(self.invoke("store"))
            actual_paths = {path.relative_to(self.state) for path in self.state.rglob("*")}
            self.assertTrue(actual_paths == expected_paths, "store created unexpected custody state")
        self.assertFalse(peer.failure, "test adapter peer failed")
        self.assertEqual(len(peer.requests), 0)

    def test_adapter_rejection_emits_only_generic_diagnostics(self) -> None:
        rejection = secrets.token_hex(32)
        with AdapterPeer(self.socket_path, rejection=rejection) as peer:
            result = self.invoke("erase")
        self.assertFalse(peer.failure, "test adapter peer failed")
        self.assertEqual(len(peer.requests), 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stdout == b"", "rejection unexpectedly wrote credentials")
        self.assertTrue(b"AdapterRequestRejected" in result.stderr, "rejection lacked a generic diagnostic")
        for value in (self.password, self.capability, rejection):
            self.assertTrue(value.encode() not in result.stdout + result.stderr, "credential appeared in diagnostics")
        peer.requests.clear()


if __name__ == "__main__":
    unittest.main()
