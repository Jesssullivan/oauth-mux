"""Exercise declared build artifacts after relocation through portable launchers."""
from __future__ import annotations

import json
import http.server
import os
import selectors
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import install
import pack
import portable

BUNDLE = Path(sys.argv.pop(1))
OPENSSL = Path(sys.argv.pop(1))
PATCHELF = Path(sys.argv.pop(1))
TLS_PROBE = Path(sys.argv.pop(1))


class RelocationTest(unittest.TestCase):
    @staticmethod
    def probe_failure(stderr: bytes) -> str:
        # Report only fixed test error names, never captured loader paths,
        # commands, environment values or arbitrary subprocess diagnostics.
        tags = ("TlsProbeCanceled", "TlsProbeDeadline", "TlsProbeResponseTooLarge",
                "TlsProbeTransportFailure", "TlsProbeTrustFailure", "TlsProbeAllocationFailure",
                "TlsProbeInvalidJson", "FixtureRejected", "FixtureTimeout", "CurlInit",
                "UnsupportedCurlFeatures", "InvalidTrustConfiguration", "OutOfMemory")
        for tag in tags:
            if ("error: " + tag + "\n").encode() in stderr:
                return tag
        if b"error while loading shared libraries:" in stderr:
            return "loader-library-unavailable"
        if b"undefined symbol:" in stderr:
            return "loader-symbol-unavailable"
        return "unclassified-probe-failure"

    def run_probe(self, command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, start_new_session=True)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 10
        try:
            with selectors.DefaultSelector() as selected:
                selected.register(process.stdout, selectors.EVENT_READ, "stdout")
                selected.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selected.get_map() or process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.fail("portable TLS probe exceeded its subprocess deadline")
                    for item, _ in selected.select(min(0.1, remaining)):
                        data = os.read(item.fileobj.fileno(), 4096)
                        if not data:
                            selected.unregister(item.fileobj)
                            continue
                        buffers[item.data].extend(data)
                        limit = 64 * 1024 if item.data == "stdout" else 2 * 1024 * 1024
                        if len(buffers[item.data]) > limit:
                            self.fail("portable TLS probe exceeded its diagnostic capture bound")
            return subprocess.CompletedProcess(command, process.returncode,
                                               bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        finally:
            # Kill the owned process group even if its leader already exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def https_fixture(self, root: Path, prefix: Path, manifest: dict) -> None:
        key = root / "ephemeral-test-key.pem"
        certificate = root / "ephemeral-test-certificate.pem"
        configuration = root / "ephemeral-openssl.cnf"
        configuration.write_text("[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n"
                                 "[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n"
                                 "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        subprocess.run([str(OPENSSL), "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-noenc",
                        "-config", str(configuration), "-keyout", str(key), "-out", str(certificate)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=True)
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        expected = b'{"fixture":"portable-tls"}\n'

        class Fixture(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == "/identity" else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(expected)))
                self.end_headers()
                self.wfile.write(expected)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        trust_path = prefix / manifest["runtime"]["caBundle"]
        original_trust = trust_path.read_bytes()
        probe = prefix / "lib/omux/libexec/test-tls-probe.bin"
        probe.write_bytes(TLS_PROBE.read_bytes())
        portable._patch(probe, portable.elf_metadata(probe.read_bytes()), PATCHELF, backend=True)
        probe.chmod(0o755)
        environment = {"PATH": "/nonexistent", "LD_DEBUG": "libs", "LANG": "C", "OMUX_CA_BUNDLE": str(trust_path)}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_STATE_HOME", "s"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_DATA_HOME", "d"), ("XDG_CACHE_HOME", "k")):
            environment[name] = str(root / child)
        command = [str(prefix / manifest["runtime"]["loader"]), "--inhibit-cache", "--library-path",
                   str(prefix / "lib/omux/lib"), str(probe), f"https://localhost:{server.server_port}/identity"]
        try:
            rejected = self.run_probe(command, environment)
            self.assertNotEqual(rejected.returncode, 0, "an untrusted ephemeral certificate must fail")
            self.assertEqual(rejected.stdout, b"")
            self.assertEqual(self.probe_failure(rejected.stderr), "TlsProbeTrustFailure",
                             "untrusted certificate must fail at TLS verification")
            trust_path.write_bytes(original_trust + b"\n" + certificate.read_bytes())
            verified = self.run_probe(command, environment)
            self.assertEqual(verified.returncode, 0,
                             "trusted portable TLS probe failed: " + self.probe_failure(verified.stderr))
            self.assertEqual(verified.stdout, expected)
            self.assertTrue(b"/nix/store" not in verified.stderr,
                            "portable TLS probe resolved a source-store path after relocation")
        finally:
            trust_path.write_bytes(original_trust)
            probe.unlink()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            key.unlink()

    def test_portable_launch_and_owned_install_after_relocation(self) -> None:
        payload = pack.read_bundle(BUNDLE)
        manifest, _ = pack.verify_bundle(payload)
        self.assertEqual(manifest["distribution"], "portable-linux")
        with tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve())) as temporary:
            root = Path(temporary)
            prefix = root / "relocated install with spaces"
            records = root / "private records"
            record = install.install_bundle(payload, prefix, records)
            self.assertFalse(record["serviceActivated"])
            environment = {"PATH": "/nonexistent", "LD_DEBUG": "libs", "LANG": "C"}
            if "HOME" in os.environ:
                environment["HOME"] = os.environ["HOME"]
            for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_STATE_HOME", "s"), ("XDG_CONFIG_HOME", "c"),
                                ("XDG_DATA_HOME", "d"), ("XDG_CACHE_HOME", "k")):
                directory = root / child
                directory.mkdir(mode=0o700)
                environment[name] = str(directory)
            for command in ["omux", "oauth-mux", "omuxd"]:
                completed = subprocess.run([str(prefix / "bin" / command), "--version"],
                                           capture_output=True, timeout=20, env=environment, check=True)
                self.assertEqual(completed.stdout.decode().strip(), manifest["product"]["version"])
                self.assertNotIn(b"/nix/store", completed.stderr)
                self.assertIn(str(prefix / "lib/omux/lib").encode(), completed.stderr)
            self.assertIn("qt", manifest["runtime"], "portable Linux product must include its native controls")
            # The hashed Omux child and AF_UNIX filename must fit sun_path.
            # Keep the namespace private and short even under a relocated prefix.
            runtime_directory = root / "r"
            control_environment = environment | {
                "QT_QPA_PLATFORM": "offscreen", "XDG_RUNTIME_DIR": str(runtime_directory),
            }
            completed = subprocess.run([str(prefix / "bin/omux-control"), "--self-check"],
                                       capture_output=True, timeout=10, env=control_environment, check=True)
            self.assertEqual(completed.stdout.strip(), b"OMUX_CONTROL_SELF_CHECK_OK")
            self.assertNotIn(b"/nix/store", completed.stderr)
            self.assertIn(str(prefix / "lib/omux/qt/plugins/platforms").encode(), completed.stderr)
            completed = subprocess.run([str(prefix / "bin/git-credential-omux"), "--state-dir", str(root / "s/omux"), "get"],
                                       input=b"protocol=https\nhost=example.invalid\n\n",
                                       capture_output=True, timeout=20, env=environment, check=True)
            self.assertEqual(completed.stdout, b"")
            self.assertNotIn(b"/nix/store", completed.stderr)
            self.https_fixture(root, prefix, manifest)
            completed = subprocess.run([str(prefix / "bin/omux"), "reference"],
                                       capture_output=True, timeout=20, env=environment, check=True)
            self.assertEqual(json.loads(completed.stdout)["product"], manifest["product"])
            self.assertNotIn(b"/nix/store", completed.stderr)
            captured_reference = root / "captured-reference.json"
            with captured_reference.open("wb") as captured:
                completed = subprocess.run([str(prefix / "bin/omux"), "reference"], stdout=captured,
                                           stderr=subprocess.PIPE, timeout=20, env=environment, check=True)
            self.assertEqual(json.loads(captured_reference.read_bytes())["product"], manifest["product"])
            self.assertNotIn(b"/nix/store", completed.stderr)
            native_request = {
                "version": 1, "id": "request1", "method": "browser.connect",
                "params": {"sourceId": "fixture-source", "adapter": "github", "origin": "https://github.com",
                           "provenance": {"browser": "chromium", "extensionId": "a" * 32, "channel": "release"}},
            }
            native_errors = tempfile.TemporaryFile(dir=root)
            process = subprocess.Popen([str(prefix / "bin/omux-native-host"),
                                        "chrome-extension://" + "a" * 32 + "/",
                                        "--state-dir", str(root / "not-created-state")],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=native_errors,
                                       env=environment)
            try:
                for request_id in ("request1", "request2"):
                    native_request["id"] = request_id
                    message = json.dumps(native_request).encode()
                    process.stdin.write(len(message).to_bytes(4, "little") + message)
                    process.stdin.flush()
                    with selectors.DefaultSelector() as selected:
                        selected.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selected.select(timeout=10), "native host waited for stdin EOF")
                    header = process.stdout.read(4)
                    self.assertEqual(len(header), 4)
                    length = int.from_bytes(header, "little")
                    self.assertLessEqual(length, 1024 * 1024)
                    self.assertGreater(length, 0)
                    response = json.loads(process.stdout.read(length))
                    self.assertEqual(response["id"], request_id)
                    self.assertIn("error", response)
                    self.assertEqual(response["error"]["message"], "Omux browser request was not admitted.")
                    self.assertIsNone(process.poll(), "host should remain available for the next frame")
                process.stdin.close()
                self.assertEqual(process.wait(timeout=5), 0)
                native_errors.seek(0)
                self.assertNotIn(b"/nix/store", native_errors.read())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if not process.stdin.closed:
                    process.stdin.close()
                process.stdout.close()
                native_errors.close()
            result = install.uninstall(prefix, records)
            self.assertEqual(result["preserved"], [])
            self.assertEqual(len(result["removed"]), len(record["files"]))
            self.assertTrue(all(not Path(item["path"]).exists() for item in record["files"]))


if __name__ == "__main__":
    unittest.main()
