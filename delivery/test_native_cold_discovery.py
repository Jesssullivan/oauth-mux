"""Actual private Unix socket boundaries; no native/provider/process execution."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import test_installed_legacy_native_tui as legacy


def reply(result):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result},
                      separators=(",", ":")).encode() + b"\n"


HELLO = reply({"protocol_version": 2, "service": "omuxd", "native_support": False})


class ColdDiscoverySocketTests(unittest.TestCase):
    @contextmanager
    def server(self, responses, *, no_request=False):
        # One actual listener and a bounded owned thread. Each response belongs
        # to a separate connection, matching the installed CLI implementation.
        with tempfile.TemporaryDirectory(prefix="omux-cd-", dir="/tmp") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            endpoint = directory / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(endpoint))
            endpoint.chmod(0o600)
            listener.listen(2)
            listener.settimeout(2)
            requests, failures = [], []

            def serve():
                try:
                    for response in responses:
                        channel, _ = listener.accept()
                        with channel:
                            channel.settimeout(2)
                            packet = bytearray()
                            while b"\n" not in packet:
                                chunk = channel.recv(8192)
                                if not chunk:
                                    if no_request and not packet:
                                        requests.append("peer-eof-before-request")
                                        break
                                    raise AssertionError("socket model request closed early")
                                packet.extend(chunk)
                                if len(packet) > 8192:
                                    raise AssertionError("socket model request exceeded bound")
                            if no_request:
                                if packet:
                                    raise AssertionError("wrong peer received request bytes")
                                continue
                            requests.append(json.loads(packet))
                            try:
                                channel.sendall(response)
                            except BrokenPipeError:
                                # Refusing clients may close during an oversized
                                # synthetic reply; that refusal is checked below.
                                pass
                except BaseException as error:
                    failures.append(type(error).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                yield endpoint, requests
            finally:
                worker.join(timeout=3)
                listener.close()
                if worker.is_alive():
                    worker.join(timeout=1)
                self.assertFalse(worker.is_alive(), "owned socket model thread did not finish")
                self.assertEqual(failures, [], "owned socket model failed")

    def test_actual_private_peer_handshake_and_discovery_on_separate_connections(self):
        result = {"installed": True, "native_support": False, "hook_compatible": True, "owners": []}
        with self.server([HELLO, reply(result)]) as (endpoint, requests):
            value = legacy.cold_discovery(endpoint, os.getpid(), {"adapter": "codex"})
        self.assertEqual(value, result)
        self.assertEqual([entry["method"] for entry in requests],
                         ["system.handshake", "integrations.discover"])
        self.assertEqual(requests[0]["params"], {"protocol_version": 2, "client": "omux-tui-fixture"})
        self.assertEqual(requests[1]["params"], {"adapter": "codex"})
        self.assertTrue(all(entry["jsonrpc"] == "2.0" and entry["id"] == 1 for entry in requests))

    def test_actual_wrong_peer_pid_is_rejected_before_any_request(self):
        with self.server([b""], no_request=True) as (endpoint, requests):
            with self.assertRaisesRegex(ValueError, "cold discovery control peer changed"):
                legacy.cold_discovery(endpoint, os.getpid() + 1, {"adapter": "codex"})
        self.assertEqual(requests, ["peer-eof-before-request"])

    def test_actual_private_socket_mode_refused_without_connect(self):
        with tempfile.TemporaryDirectory(prefix="omux-cd-", dir="/tmp") as temporary:
            endpoint = Path(temporary) / "control.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(endpoint))
                endpoint.chmod(0o666)
                with mock.patch.object(legacy.socket, "socket") as connect:
                    with self.assertRaisesRegex(ValueError, "cold discovery control socket custody changed"):
                        legacy.cold_discovery(endpoint, os.getpid(), {"adapter": "codex"})
                connect.assert_not_called()

    def test_actual_frame_bound_multiple_frames_and_refusals_are_rejected(self):
        cases = (
            (b"x" * (64 * 1024 + 1), "cold discovery control frame exceeded bound"),
            (reply({}) + reply({}), "cold discovery control frame changed"),
            (b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"synthetic-private"}}\n',
             "cold discovery control response rejected"),
            (b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}\n', "native JSON contains duplicate keys"),
            (b'{"jsonrpc":"2.0","id":2,"result":{}}\n', "cold discovery control response rejected"),
        )
        for response, message in cases:
            with self.subTest(message=message):
                with self.server([HELLO, response]) as (endpoint, requests):
                    with self.assertRaisesRegex(ValueError, message):
                        legacy.cold_discovery(endpoint, os.getpid(), {"adapter": "codex"})
                self.assertEqual(len(requests), 2)

    def test_actual_handshake_version_rejected_without_discovery(self):
        for version in (1, 3, True, "2"):
            with self.subTest(version_type=type(version).__name__):
                with self.server([reply({"protocol_version": version})]) as (endpoint, requests):
                    with self.assertRaisesRegex(ValueError, "cold discovery control handshake rejected"):
                        legacy.cold_discovery(endpoint, os.getpid(), {"adapter": "codex"})
                self.assertEqual([entry["method"] for entry in requests], ["system.handshake"])

    def test_actual_closed_errno_projection_never_formats_private_errors(self):
        class PrivateOSError(OSError):
            def __str__(self):
                raise AssertionError("private exception string requested")

            def __repr__(self):
                raise AssertionError("private exception representation requested")

        cases = ((errno.EAGAIN, "resume-os-busy"), (errno.ENOMEM, "resume-os-memory"),
                 (errno.EPIPE, "resume-os-pipe"), (errno.EMFILE, "resume-os-limit"),
                 (errno.ENFILE, "resume-os-limit"), (errno.EINTR, "resume-os-interrupted"),
                 (errno.ECONNREFUSED, "resume-os-other"), (None, "resume-os-other"))
        for number, expected in cases:
            with self.subTest(expected=expected):
                error = PrivateOSError(number, "synthetic-private-account-bait")
                value = legacy.classify_resume_failure(error)
                self.assertEqual(value, expected)
                self.assertIn(value, legacy.RESUME_FAILURES)
                self.assertNotIn("synthetic", value)


if __name__ == "__main__":
    unittest.main()
