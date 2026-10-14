"""Synthetic public missing plans and real held-FD transport, no Nix child."""
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import native_flake_missing_plan as plan
import nix_private_store_qualification as proof

TARGET = "/nix/store/" + "1" * 32 + "-native-closure.drv"
CHILD = "/nix/store/" + "2" * 32 + "-dependency.drv"
EXTRA = "/nix/store/" + "3" * 32 + "-undeclared.drv"
NIX = "/nix/store/" + "4" * 32 + "-nix"
ALLOWED = frozenset({TARGET, CHILD})


def wire(header, *paths):
    return (header + "\n" + "".join("  " + path + "\n" for path in paths)).encode("ascii")


class MissingPlanModels(unittest.TestCase):
    def parse(self, raw):
        return plan.parse(raw, allowed_drvs=ALLOWED)

    def test_pinned_singular_and_plural_emit_closed_typed_sets(self):
        for raw, expected in (
            (wire("this derivation will be built:", TARGET), frozenset({TARGET})),
            (wire("these 2 derivations will be built:", CHILD, TARGET), ALLOWED),
        ):
            with self.subTest(raw=raw):
                result = self.parse(raw)
                self.assertIs(type(result), plan.MissingPlan)
                self.assertEqual(result.willBuild, expected)
                self.assertIs(type(result.willBuild), frozenset)
                self.assertEqual(result.willSubstitute, frozenset())
                self.assertEqual(result.unknown, frozenset())
                self.assertEqual(result.diagnostics, ())

    def test_empty_plan_and_only_fixed_advisory_have_no_seed_authority(self):
        self.assertEqual(self.parse(b"").willBuild, frozenset())
        raw = (plan.ADVISORY + "\n").encode("ascii")
        result = self.parse(raw)
        self.assertEqual(result.diagnostics, ("unrooted-output-advisory",))
        self.assertEqual(result.willBuild, frozenset())
        self.assertFalse(hasattr(result, "complete_seed"))
        with self.assertRaises(ValueError):
            self.parse(raw + raw)

    def test_counts_require_exact_bounded_plural_and_full_body(self):
        headers = ["these 0 derivations will be built:", "these 1 derivations will be built:",
                   "these 02 derivations will be built:", "these +2 derivations will be built:",
                   "these 4097 derivations will be built:", "these 999999999999 derivations will be built:"]
        for header in headers:
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.parse(wire(header, TARGET, CHILD))
        for raw in (b"this derivation will be built:\n",
                    wire("these 2 derivations will be built:", TARGET),
                    wire("this derivation will be built:", TARGET)[:-1],
                    b"this derivation will be bu"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw)

    def test_duplicate_extra_or_orphan_paths_and_sections_refuse(self):
        one = wire("this derivation will be built:", TARGET)
        for raw in (wire("these 2 derivations will be built:", TARGET, TARGET),
                    one + wire("this derivation will be built:", CHILD),
                    wire("this derivation will be built:", EXTRA),
                    one + ("  " + CHILD + "\n").encode(),
                    ("  " + TARGET + "\n").encode(),
                    wire("this derivation will be built:", TARGET + "/leaf"),
                    wire("this derivation will be built:", TARGET.replace("1" * 32, "e" * 32))):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw)

    def test_every_offline_substitution_or_unknown_section_refuses(self):
        headers = [
            "this path will be fetched (1.00 MiB download, 2.00 MiB unpacked):",
            "these 2 paths will be fetched (0.00 MiB download, 0.00 MiB unpacked):",
            "this path will be fetched (malformed sizes):",
            "these 01 paths will be fetched (malformed sizes):",
            *sorted(plan.UNKNOWN),
        ]
        for header in headers:
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.parse(wire(header, TARGET))
        with self.assertRaises(ValueError):
            self.parse(wire("this derivation will be built:", TARGET)
                       + wire(sorted(plan.UNKNOWN)[0], EXTRA))

    def test_unknown_diagnostics_and_binary_logger_forms_refuse(self):
        one = wire("this derivation will be built:", TARGET)
        for raw in (b"warning: unknown setting 'print-missing'\n" + one,
                    b"error: refused\n", b"unrecognized diagnostic\n", b"\n",
                    b"\x1b[1m" + one, b"<6>" + one, one.replace(b"\n", b"\r\n"),
                    one + b"\x00\n", one + b"\xff\n", one + b"x" * (plan.MAX_LINE + 1) + b"\n"):
            with self.subTest(raw=raw[:120]), self.assertRaises(ValueError):
                self.parse(raw)

    def test_parser_types_and_original_four_mib_bound_refuse(self):
        for raw in ("", bytearray(), b"x" * (proof.MAX_OUTPUT + 1)):
            with self.subTest(type=type(raw)), self.assertRaises(ValueError):
                self.parse(raw)
        for allowed in ({TARGET}, [TARGET], frozenset({True}), frozenset({"/private/unselected"})):
            with self.subTest(type=type(allowed)), self.assertRaises(ValueError):
                plan.parse(b"", allowed_drvs=allowed)

    def test_fixed_query_binds_private_store_output_and_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve(strict=True)
            deadline = float(time.monotonic() + 10)
            tools = {"nix_store": NIX + "/bin/nix-store"}
            with patch.object(proof, "run", return_value=(b"", wire("this derivation will be built:", TARGET))) as run:
                result = plan.query(tools, work, work, TARGET, ALLOWED, deadline, tool_fd=777)
            self.assertEqual(result.willBuild, frozenset({TARGET}))
            command, env, cwd, actual_deadline = run.call_args.args
            self.assertEqual(command, proof.common(tools["nix_store"], work) + [
                "--log-format", "raw", "--option", "print-missing", "true",
                "--realise", "--dry-run", TARGET + "!out"])
            self.assertEqual(command.count("--store"), 1)
            self.assertEqual(command[command.index("--store")+1], "local?root=" + str(work))
            options = {command[i+1]: command[i+2] for i, value in enumerate(command) if value == "--option"}
            self.assertEqual(options["builders"], "")
            self.assertEqual(options["substituters"], "")
            self.assertEqual(options["fallback"], "false")
            self.assertEqual(options["sandbox-fallback"], "false")
            self.assertEqual(options["max-jobs"], "1")
            self.assertEqual(options["cores"], "2")
            self.assertEqual(options["print-missing"], "true")
            for flag in ("--ignore-unknown", "--repair", "--check", "--impure"):
                self.assertNotIn(flag, command)
            self.assertEqual(env, proof.environment(work))
            self.assertNotIn("IN_SYSTEMD", env)
            self.assertEqual((cwd, actual_deadline), (work, deadline))
            self.assertEqual(run.call_args.kwargs,
                {"tool_fd": 777, "output_limit": proof.MAX_OUTPUT, "capture_stderr": True})

    def test_query_zero_exit_unknown_stdout_and_bad_transport_shape_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve(strict=True)
            tools = {"nix_store": NIX + "/bin/nix-store"}
            for value in ((b"", wire(sorted(plan.UNKNOWN)[0], TARGET)), (b"unexpected\n", b""),
                          b"", [b"", b""], (b"", ""), (b"", b"", b"")):
                with self.subTest(value=value), patch.object(proof, "run", return_value=value) as run, self.assertRaises(ValueError):
                    plan.query(tools, work, work, TARGET, ALLOWED, float(time.monotonic()+10), tool_fd=777)
                run.assert_called_once()

    def test_unknown_target_and_expired_original_deadline_precede_child(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve(strict=True)
            with patch.object(proof, "run") as run:
                for target, deadline in ((EXTRA, float(time.monotonic()+10)),
                                         (TARGET, float(time.monotonic()-1))):
                    with self.assertRaises(ValueError):
                        plan.query({"nix_store": NIX+"/bin/nix-store"}, work, work,
                                   target, ALLOWED, deadline, tool_fd=777)
                run.assert_not_called()


class StreamSelector:
    def __init__(self):
        self.rows = {}
        self.closed = False

    def register(self, stream, events, name):
        self.rows[stream] = SimpleNamespace(fileobj=stream, data=name)

    def unregister(self, stream):
        del self.rows[stream]

    def get_map(self):
        return self.rows

    def select(self, timeout):
        return [(row, 1) for row in list(self.rows.values())]

    def close(self):
        self.closed = True


class TransportModels(unittest.TestCase):

    def test_diagnostic_nonzero_exit_keeps_only_code_counts_hash_and_typed_hint(self):
        raw = b"error: path '/public/synthetic-source' does not exist\n"
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(b"partial public stdout", raw, code=1)
            selected = StreamSelector()
            report = {}
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), diagnostics=report)
            spawn.assert_called_once()
            process.wait.assert_called_once()
            self.assertEqual(report, {
                "child_exit": 1, "stdout_bytes": len(b"partial public stdout"), "stderr_bytes": len(raw),
                "stderr_sha256": proof.hashlib.sha256(raw).hexdigest(), "streams_complete": True,
                "transport_reason": "child-exit", "stderr_reason": "path-unavailable",
                "stderr_classification_truncated": False})
            self.assertNotIn("synthetic-source", repr(report))
            self.assertTrue(process.stdout.closed and process.stderr.closed and selected.closed)

    def test_diagnostic_prefix_bounded_but_hash_and_count_cover_all_stderr(self):
        raw = b"x" * 65536 + b"error: hash mismatch beyond classifier bound\n"
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(stderr=raw, code=1)
            selected = StreamSelector()
            report = {}
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process), self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), diagnostics=report)
            self.assertEqual(report["stderr_bytes"], len(raw))
            self.assertEqual(report["stderr_sha256"], proof.hashlib.sha256(raw).hexdigest())
            self.assertEqual(report["stderr_reason"], "unclassified")
            self.assertIs(report["stderr_classification_truncated"], True)

    def test_diagnostic_cleanup_failure_does_not_hide_child_exit_or_leak_bytes(self):
        raw = b"error: store path mismatch public\n"
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(stderr=raw, code=1)
            selected = StreamSelector()
            selected.close = Mock(side_effect=OSError("modeled cleanup fault"))
            report = {}
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process), self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), diagnostics=report)
            self.assertEqual(report["child_exit"], 1)
            self.assertEqual(report["transport_reason"], "owned-client-cleanup-failure")
            self.assertEqual(report["stderr_reason"], "source-store-path-mismatch")
            self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_diagnostic_false_exit_and_nonempty_report_do_not_masquerade_as_success(self):
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(code=False)
            selected = StreamSelector()
            report = {}
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), diagnostics=report)
            spawn.assert_called_once()
            self.assertIsNone(report["child_exit"])
            self.assertEqual(report["transport_reason"], "invalid-child-status")
            for value in (True, [], {"raw": "must refuse"}):
                with patch.object(proof.subprocess, "Popen") as spawn, self.assertRaises(ValueError):
                    proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                              tool_fd=tool.fileno(), diagnostics=value)
                spawn.assert_not_called()

    def process(self, stdout=b"", stderr=b"", *, code=0, running=False):
        process = Mock()
        process.pid = 12345
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            stream = tempfile.TemporaryFile()
            stream.write(data)
            stream.seek(0)
            setattr(process, name, stream)
            self.addCleanup(stream.close)
        process.wait.return_value = code
        process.poll.return_value = None if running else 0
        return process

    def test_default_discards_and_opt_in_captures_with_same_held_fd_and_cleanup(self):
        for capture in (False, True):
            with self.subTest(capture=capture), tempfile.TemporaryFile() as tool:
                os.fchmod(tool.fileno(), 0o555)
                process = self.process(b"public stdout\n", b"public stderr\n")
                selected = StreamSelector()
                with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                     patch.object(proof.subprocess, "Popen", return_value=process) as spawn:
                    kwargs = {"capture_stderr": True} if capture else {}
                    result = proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                                       tool_fd=tool.fileno(), **kwargs)
                self.assertEqual(result, (b"public stdout\n", b"public stderr\n") if capture else b"public stdout\n")
                self.assertEqual(spawn.call_args.kwargs["executable"], "/proc/self/fd/"+str(tool.fileno()))
                self.assertEqual(spawn.call_args.kwargs["pass_fds"], (tool.fileno(),))
                process.wait.assert_called_once()
                self.assertTrue(process.stdout.closed and process.stderr.closed and selected.closed)

    def test_capture_overflow_reaps_only_owned_child_without_partial_return(self):
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(b"x", b"s" * proof.MAX_OUTPUT, running=True)
            selected = StreamSelector()
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, \
                 patch.object(proof.os, "killpg") as kill, self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), capture_stderr=True)
            spawn.assert_called_once()
            kill.assert_called_once_with(12345, proof.signal.SIGTERM)
            process.wait.assert_called_once()
            self.assertTrue(process.stdout.closed and process.stderr.closed and selected.closed)

    def test_capture_post_spawn_registration_fault_still_closes_and_reaps(self):
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(running=True)
            selected = Mock()
            selected.register.side_effect = OSError("modeled registration fault")
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, \
                 patch.object(proof.os, "killpg") as kill, self.assertRaises(OSError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), capture_stderr=True)
            spawn.assert_called_once()
            kill.assert_called_once_with(12345, proof.signal.SIGTERM)
            process.wait.assert_called_once()
            self.assertTrue(process.stdout.closed and process.stderr.closed)
            selected.close.assert_called_once()

    def test_capture_false_exit_is_not_literal_zero_success(self):
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            process = self.process(stderr=b"public plan\n", code=False)
            selected = StreamSelector()
            with patch.object(proof.selectors, "DefaultSelector", return_value=selected), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), capture_stderr=True)
            spawn.assert_called_once()
            process.wait.assert_called_once()
            self.assertTrue(process.stdout.closed and process.stderr.closed and selected.closed)

    def test_capture_type_and_selector_failure_precede_spawn(self):
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            for value in (None, 1, "true"):
                with patch.object(proof.subprocess, "Popen") as spawn, self.assertRaises(ValueError):
                    proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                              tool_fd=tool.fileno(), capture_stderr=value)
                spawn.assert_not_called()
            with patch.object(proof.selectors, "DefaultSelector", side_effect=OSError("modeled selector fault")), \
                 patch.object(proof.subprocess, "Popen") as spawn, self.assertRaises(OSError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10),
                          tool_fd=tool.fileno(), capture_stderr=True)
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
