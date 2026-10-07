import io
import ast
import contextlib
import json
import os
import sys
import signal
import subprocess
from pathlib import Path
import tarfile
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from deployed_fixture import public_archive, public_graph_diagnostics, provenance_fields, bootstrap_diagnostics, phase_marker, transport, main, cleanup_rejection_fields
from host_closure import evaluate


BASH = None
if "--bash" in sys.argv:
    index = sys.argv.index("--bash")
    BASH = sys.argv[index + 1]
    del sys.argv[index:index + 2]


class ArchiveCustodyTest(unittest.TestCase):
    def test_retired_darwin_recipes_reject_before_archive_custody_or_transport(self):
        for host in ("neo", "pzm"):
            for recipe in ("darwin-build", "darwin-vault"):
                with self.subTest(host=host, recipe=recipe):
                    arguments = ["fixture", "--ssh", "declared", "--source-archive", "public",
                                 "--host", host, "--recipe", recipe]
                    with patch("sys.argv", arguments), contextlib.redirect_stderr(io.StringIO()), \
                            patch("deployed_fixture.public_archive") as archive, \
                            patch("deployed_fixture.operator_config") as configuration, \
                            patch("deployed_fixture.transport") as remote:
                        with self.assertRaises(SystemExit) as rejected:
                            main()
                        self.assertEqual(rejected.exception.code, 2)
                        archive.assert_not_called()
                        configuration.assert_not_called()
                        remote.assert_not_called()

    def test_metadata_eval_exited_leader_descendant_is_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'child.pid'
            code = "import os,time; child=os.fork(); open(" + repr(str(marker)) + ",'w').write(str(child)) if child else None; os._exit(0) if child else time.sleep(60)"
            with patch('host_closure.MAX_SECONDS',0.2), self.assertRaises(ValueError):
                evaluate([sys.executable,'-I','-S','-c',code])
            pid = int(marker.read_text())
            state = Path('/proc') / str(pid) / 'stat'
            deadline = time.monotonic() + 2
            while state.exists() and time.monotonic() < deadline:
                if state.read_text().split(') ',1)[1].split()[0] == 'Z': break
                time.sleep(0.01)
            if state.exists(): self.assertEqual(state.read_text().split(') ',1)[1].split()[0],'Z')
    def test_actual_transport_interrupt_terminates_owned_group(self):
        pids = []
        directory = tempfile.TemporaryDirectory()
        child_marker = Path(directory.name) / "child.pid"
        code = "import os,time; child=os.fork(); open(" + repr(str(child_marker)) + ", 'w').write(str(child)) if child else None; print('phase=nix-bootstrap',flush=True); time.sleep(60)"
        original = subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            pids.append(child.pid)
            return child
        with patch("deployed_fixture.subprocess.Popen", side_effect=spawn):
            timer = threading.Timer(0.2, lambda: os.kill(os.getpid(), signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    transport([sys.executable, "-I", "-S", "-c", code], b"", 10, lambda phase: None)
            finally:
                timer.cancel()
        descendant = int(child_marker.read_text())
        for pid in [pids[0], descendant]:
            state = Path('/proc') / str(pid) / 'stat'
            if state.exists():
                self.assertEqual(state.read_text().split(') ', 1)[1].split()[0], 'Z')
        directory.cleanup()
    def test_failure_metadata_bounds_and_unknown_fields_rejected(self):
        metadata = {"mode": 0o1777, "owner_class": "current", "depth": 5, "scope": "workspace", "entry_kind": "_tmp"}
        result = cleanup_rejection_fields("repair-rejection-code=shared-write\nrepair-entries=8000001\nrepair-metadata=" + json.dumps(metadata) + "\n", "repair")
        self.assertEqual(result["entries"], 8000001)
        for altered in [{**metadata, "mode": 4096}, {**metadata, "depth": 130}, {**metadata, "owner_class": "username"}, {**metadata, "path": "/private/operator"}]:
            with self.assertRaises(ValueError):
                cleanup_rejection_fields("repair-metadata=" + json.dumps(altered) + "\n", "repair")
        for line in ["repair-rejection-code=unknown\n", "repair-entries=8000002\n"]:
            with self.assertRaises(ValueError):
                cleanup_rejection_fields(line, "repair")
    def archive(self, extra=(), gzip=True):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz" if gzip else "w") as archive:
            for name in ["flake.nix", "flake.lock", "MODULE.bazel", "BUILD.bazel"]:
                entry = tarfile.TarInfo(name)
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b"x"))
            for entry in extra:
                archive.addfile(entry)
        return output.getvalue()

    def validate(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "public.tar.gz"
            archive.write_bytes(payload)
            return public_archive(archive)

    def test_accepts_rooted_declared_graph_gzip(self):
        payload = self.archive()
        self.assertEqual(self.validate(payload), payload)

    def test_rejects_uncompressed_stream_before_remote_extraction(self):
        with self.assertRaises(tarfile.ReadError):
            self.validate(self.archive(gzip=False))

    def test_rejects_traversal_absolute_private_and_duplicate_paths(self):
        for name in ["../escape", "/absolute", ".ssh/config", ".codex/state", ".env", "flake.nix"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(self.archive([tarfile.TarInfo(name)]))

    def test_rejects_symlinks_hardlinks_and_devices(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE]:
            entry = tarfile.TarInfo("escape")
            entry.type = kind
            entry.linkname = "flake.nix"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(self.archive([entry]))

    def test_rejects_large_declared_extraction_even_in_small_gzip(self):
        entry = tarfile.TarInfo("oversized")
        entry.size = 512 * 1024 * 1024 + 1
        with self.assertRaises(ValueError):
            self.validate(self.archive([entry]))

    def test_collects_timestamped_bazel_operational_error(self):
        lines = public_graph_diagnostics("(07:04:30) ERROR: Unable to fetch public dependency\n")
        self.assertEqual(lines, ["ERROR: Unable to fetch public dependency"])

    def test_graph_diagnostics_hide_absolute_paths_and_sensitive_lines(self):
        output = "(07:04:30) ERROR: /tmp/owned-workspace/BUILD.bazel:2: missing input\n"
        output += "ERROR: authorization failed\n"
        self.assertEqual(public_graph_diagnostics(output), ["ERROR: [absolute-path] missing input"])

    def test_graph_diagnostics_bound_count_and_line_size(self):
        lines = public_graph_diagnostics("\n".join("ERROR: " + "x" * 2000 for _ in range(20)))
        self.assertEqual(len(lines), 8)
        self.assertTrue(all(len(line) <= 1024 for line in lines))

    def test_collects_lowercase_translate_c_failure(self):
        self.assertEqual(public_graph_diagnostics("error: unable to find header /private/tmp/work/input.h"),
                         ["error: unable to find header [absolute-path]"])

    def test_artifact_provenance_is_exact_and_bounded(self):
        output = "artifact-kind=linux-tar-gz\nartifact-sha256=" + "a" * 64 + "\nartifact-bytes=42\nhost-os=Linux\nhost-kernel=6.12.1\ncleanup=removed\n"
        result = provenance_fields(output, "linux-installed")
        self.assertEqual(result["artifact"]["bytes"], 42)
        for invalid in [output + "artifact-bytes=43\n", output.replace("=42", "=536870913"),
                        output.replace("linux-tar-gz", "unknown"), output.replace("6.12.1", "6.12-personal"),
                        output.replace("a" * 64, "bad"), output.replace("Linux", "personal-host"),
                        output.replace("=42", "=" + "1" * 129)]:
            with self.subTest(invalid=invalid[-60:]), self.assertRaises(ValueError):
                provenance_fields(invalid, "linux-installed")

    def test_failed_graph_does_not_require_unbuilt_artifact(self):
        self.assertEqual(provenance_fields("host-os=Linux\n", "linux-installed", False), {"host_os": "Linux"})
        with self.assertRaises(ValueError):
            provenance_fields("", "linux-installed")

    def test_bootstrap_builder_categories_preserve_public_derivation_only(self):
        output = "error: Cannot build '/nix/store/" + "a" * 32 + "-swift-6.1.drv'.\n"
        output += " > cat: code: No such file or directory\n > error: /Users/person/work/input.h missing\n"
        output += " > password: failed\n > arbitrary personal output\n"
        self.assertEqual(bootstrap_diagnostics(output), ["error: Cannot build '[public-derivation:swift-6.1.drv]'.",
                         " > cat: code: No such file or directory", " > error: [absolute-path] missing"])

    def test_phase_markers_reject_unrecognized_or_oversized_content(self):
        self.assertEqual(phase_marker("phase=nix-bootstrap\n"), "nix-bootstrap")
        for line in ["phase=private-value\n", "phase=nix-bootstrap\n\n", "phase=" + "x" * 5000, "prefix phase=nix-bootstrap\n"]:
            self.assertIsNone(phase_marker(line))

    def test_transport_streams_only_recognized_phases_and_bounds_stdout(self):
        phases = []
        fake = SimpleNamespace(stdout=io.BytesIO(b"phase=nix-bootstrap\npublic fixture\nphase=declared-bazel-graph\n"),
                               pid=12345, stdin=io.BytesIO(), stderr=io.BytesIO(), returncode=0, communicate=lambda *args, **kwargs: (None, b"public bootstrap"), kill=lambda: None)
        with patch("deployed_fixture.os.killpg"), patch("deployed_fixture.subprocess.Popen", return_value=fake):
            result = transport(["declared-tool"], b"public", 30, phases.append)
        self.assertEqual(phases, ["nix-bootstrap", "declared-bazel-graph"])
        self.assertEqual(result.stderr, b"public bootstrap")
        fake.stdout = io.BytesIO(b"x" * 65537)
        with patch("deployed_fixture.os.killpg"), patch("deployed_fixture.subprocess.Popen", return_value=fake), self.assertRaises(ValueError):
            transport(["declared-tool"], b"public", 30, phases.append)

    def test_transport_rejects_collector_callback_failure(self):
        fake = SimpleNamespace(pid=12345, stdout=io.BytesIO(b"phase=nix-bootstrap\n"), returncode=0,
                               communicate=lambda *args, **kwargs: (None, b""))
        def fail(phase):
            raise RuntimeError("fixture")
        with patch("deployed_fixture.os.killpg") as kill, patch("deployed_fixture.subprocess.Popen", return_value=fake), self.assertRaises(ValueError):
            transport(["declared-tool"], b"public", 30, fail)
        kill.assert_called_with(12345, signal.SIGKILL)

    def test_transport_timeout_drain_is_bounded(self):
        calls = []
        def expired(*args, **kwargs):
            calls.append(kwargs.get("timeout"))
            raise subprocess.TimeoutExpired("fixture", kwargs["timeout"])
        fake = SimpleNamespace(pid=12345, stdout=io.BytesIO(), stdin=io.BytesIO(), stderr=io.BytesIO(), communicate=expired)
        with patch("deployed_fixture.os.killpg") as kill, patch("deployed_fixture.subprocess.Popen", return_value=fake), self.assertRaises(subprocess.TimeoutExpired):
            transport(["declared-tool"], b"public", 30, lambda phase: None)
        self.assertEqual(calls, [30, 5])
        self.assertTrue(fake.stdin.closed and fake.stderr.closed)
        kill.assert_called_once_with(12345, signal.SIGKILL)

    def test_actual_declared_bash_outer_and_inner_script_syntax(self):
        self.assertIsNotNone(BASH)
        tree = ast.parse(Path(__file__).with_name("deployed_fixture.py").read_text())
        command = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("set -eu\numask"))
        for key, value in [("PLATFORM", "Linux"), ("TOTAL", "600"), ("VERB", "test"), ("TARGET", "//:vault_realproof"), ("RECIPE", "linux-vault")]:
            command = command.replace(key, value)
        inner = command.split("--command bash -c '\n", 1)[1].split("\n' omux-graph", 1)[0]
        for script in [command, inner]:
            result = subprocess.run([BASH, "-n"], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_remote_recipes_reject_before_archive_policy_or_transport(self):
        for host, recipe in (("sting", "linux-package"), ("neo", "darwin-cleanup"), ("neo", "darwin-diagnose"), ("sting", "linux-recover")):
            arguments = ["fixture", "--ssh", "declared", "--source-archive", "missing",
                         "--host", host, "--recipe", recipe]
            output = io.StringIO()
            with self.subTest(recipe=recipe), patch("sys.argv", arguments), \
                    patch("deployed_fixture.public_archive") as archive, \
                    patch("deployed_fixture.operator_config") as policy, \
                    patch("deployed_fixture.transport") as transport_call, contextlib.redirect_stdout(output):
                self.assertEqual(main(), 2)
                archive.assert_not_called()
                policy.assert_not_called()
                transport_call.assert_not_called()
            result = json.loads(output.getvalue())
            self.assertFalse(result["passed"])
            self.assertEqual(result["gate"], "unsupported-execution-capability")


if __name__ == "__main__":
    unittest.main()
