import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import time
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from host_graph import classify, Progress, private_log, remaining, read_budget, run_graph, GraphSignal, record_cleanup_deadline, main, graph_command


class GraphWorkerTest(unittest.TestCase):
    def test_linux_graph_command_bounds_jobs_and_binds_existing_proof_identity(self):
        proof = "11111111-1111-4111-8111-111111111111"
        for recipe, verb, target in (
            ("linux-package", "build", "//delivery:release_archive"),
            ("linux-installed", "test", "//delivery:installed_custody_test"),
            ("linux-vault", "test", "//:vault_realproof"),
        ):
            with self.subTest(recipe=recipe):
                command = graph_command(Path("/declared/bazelisk"), Path("/private/bazel"), recipe, proof)
                self.assertEqual(command[0], "/declared/bazelisk")
                self.assertEqual(command[command.index(verb) + 1], target)
                self.assertEqual([item for item in command if item.startswith("--jobs=")], ["--jobs=4"])
                self.assertEqual([item for item in command if item.startswith("--invocation_id=")],
                                 ["--invocation_id=" + proof])
                self.assertIn("--batch", command)
                self.assertIn("--output_user_root=/private/bazel", command)
        for recipe in ("darwin-build", "darwin-vault", "darwin-cleanup", "linux-arbitrary"):
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                graph_command("declared", "private", recipe, proof)
        for malformed in ("-" * 36, "a" * 36, proof.upper().replace("1", "A"), proof + " --jobs=99"):
            with self.subTest(proof=malformed), self.assertRaises(ValueError):
                graph_command("declared", "private", "linux-package", malformed)

    def test_retired_darwin_recipes_reject_before_tool_or_private_custody_access(self):
        for recipe in ("darwin-build", "darwin-vault"):
            with self.subTest(recipe=recipe):
                arguments = ["worker", "--recipe", recipe, "--bazelisk", "/declared/bazelisk",
                             "--output-root", "/private/bazel", "--log", "/private/build.log",
                             "--budget-pipe", "/private/graph.deadline", "--total", "600",
                             "--proof-id", "11111111-1111-4111-8111-111111111111"]
                with patch("sys.argv", arguments), contextlib.redirect_stderr(io.StringIO()), \
                        patch("host_graph.Path.resolve") as resolve, \
                        patch("host_graph.os.open") as custody, \
                        patch("host_graph.run_graph") as graph:
                    with self.assertRaises(SystemExit) as rejected:
                        main()
                    self.assertEqual(rejected.exception.code, 2)
                    resolve.assert_not_called()
                    custody.assert_not_called()
                    graph.assert_not_called()

    def test_cleanup_deadline_keeps_admission_anchor_and_private_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cleanup.deadline"
            proof = "11111111-1111-4111-8111-111111111111"
            with patch("host_graph.time.monotonic", return_value=120):
                record_cleanup_deadline(path, proof, 100, 500, 600)
            value = json.loads(path.read_text())
            self.assertEqual(value, {"proof_id": proof, "deadline": 620, "total": 600})
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
            with self.assertRaises(FileExistsError), patch("host_graph.time.monotonic", return_value=120):
                record_cleanup_deadline(path, proof, 100, 500, 600)
            for anchor, budget in [(121, 500), (float("nan"), 500), (100, 581)]:
                with self.assertRaises(ValueError), patch("host_graph.time.monotonic", return_value=120):
                    record_cleanup_deadline(path, proof, anchor, budget, 600)
    def test_phase_classification_excludes_inactive_and_unrecognized_output(self):
        self.assertEqual(classify("(12:34:56) Computing main repo mapping: "), "repository-mapping")
        self.assertEqual(classify("INFO: Analyzed 2 targets"), "analysis-complete")
        self.assertEqual(classify("[2 / 3] Compiling public.c"), "action-execution")
        for line in ["[1 / 1] no actions running", "private@email.invalid password", "x" * 5000, "prefix Loading: "]:
            self.assertIsNone(classify(line))

    def test_progress_is_enum_only_monotonic_bounded_and_chunk_safe(self):
        phases = []
        progress = Progress(phases.append)
        progress.feed(b"Loading: /private/operator/path\nAnaly")
        progress.feed(b"zing: private@email.invalid\nINFO: Analyzed 2 targets\nLoading: later\n")
        progress.feed(b"x" * 100000 + b"\n[2 / 3] Compiling public.c\nINFO: Build completed successfully\n")
        self.assertEqual(phases, ["loading-analysis", "analysis-complete", "action-execution", "graph-complete"])
        self.assertLessEqual(len(progress.pending), 4096)

    def test_deadline_consumes_bootstrap_without_extending_total(self):
        self.assertEqual(remaining(3600, 96), 3483)
        self.assertEqual(remaining(600, 96), 483)
        for total, elapsed in [(3601, 0), (600, -1), (600, 580), (600, 601)]:
            with self.assertRaises(ValueError):
                remaining(total, elapsed)

    def test_private_log_exclusive_nofollow_and_no_permission_adoption(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            path = parent / "public.log"
            with private_log(path) as log:
                log.write(b"public")
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                private_log(path)
            alias = parent / "alias"
            alias.symlink_to(path)
            with self.assertRaises(FileExistsError):
                private_log(alias)
            parent.chmod(0o755)
            with self.assertRaises(ValueError):
                private_log(parent / "other")
            self.assertEqual(stat.S_IMODE(os.lstat(parent).st_mode), 0o755)



    def test_deadline_channel_rejects_malformed_or_extended_budget(self):
        for payload, valid in [(b"483\n", True), (b"9999\n", False), (b"0\n", False), (b"12\nextra", False), (b"abc\n", False)]:
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, payload)
                os.close(write_fd)
                write_fd = None
                if valid:
                    self.assertEqual(read_budget(read_fd, 600), 483)
                else:
                    with self.assertRaises(ValueError):
                        read_budget(read_fd, 600)
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)




    def test_legacy_worker_rejects_before_process_launch(self):
        with patch("host_graph.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "unsupported execution capability"):
                run_graph(["declared-tool"], io.BytesIO(), 30, lambda phase: None)
            launch.assert_not_called()

    def test_linux_dispatch_rejects_before_tool_resolution_or_custody(self):
        arguments = ["worker", "--recipe", "linux-package", "--bazelisk", "/missing/tool",
                     "--output-root", "/missing/bazel", "--log", "/missing/build.log",
                     "--budget-pipe", "/missing/graph.deadline", "--total", "600",
                     "--proof-id", "11111111-1111-4111-8111-111111111111"]
        output = io.StringIO()
        with patch("sys.argv", arguments), contextlib.redirect_stdout(output), \
                patch("host_graph.Path.resolve") as resolve, patch("host_graph.os.open") as custody, \
                patch("host_graph.run_graph") as graph:
            self.assertEqual(main(), 2)
            resolve.assert_not_called()
            custody.assert_not_called()
            graph.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["gate"], "unsupported-execution-capability")


if __name__ == "__main__":
    unittest.main()
