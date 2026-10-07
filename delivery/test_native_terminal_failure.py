"""Actual failure projection models; no native process or provider execution."""
import ast
import copy
import io
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import test_installed_legacy_native_tui as legacy
import test_installed_native_tui as tui


def terminal(code=os.CLD_EXITED, status=1):
    info = None if code is None else SimpleNamespace(si_code=code, si_status=status)
    return SimpleNamespace(exited=mock.Mock(return_value=info))


class TerminalFailureModels(unittest.TestCase):
    def test_actual_literals_recognized_at_every_packet_boundary(self):
        for category, literals in legacy.TERMINAL_MESSAGES:
            for literal in literals:
                for boundary in range(1, len(literal)):
                    with self.subTest(category=category, boundary=boundary):
                        observed = legacy.TerminalFailureObservation()
                        observed.observe(b"synthetic-private-prefix " + literal[:boundary])
                        observed.observe(literal[boundary:] + b" synthetic-private-suffix")
                        self.assertEqual(observed.record(terminal()),
                                         legacy.TERMINAL_MARKER + "exit-one/" + category + "\n")
                        self.assertEqual(observed.suffix, b"")

    def test_actual_exit_categories_do_not_infer_panic_from_101(self):
        cases = ((os.CLD_EXITED, 0, "exit-zero"), (os.CLD_EXITED, 1, "exit-one"),
                 (os.CLD_EXITED, 2, "exit-two"), (os.CLD_EXITED, 101, "exit-101"),
                 (os.CLD_EXITED, 17, "exit-positive-other"),
                 (os.CLD_KILLED, 9, "exit-signal"), (os.CLD_DUMPED, 11, "exit-core"),
                 (None, 0, "exit-unavailable"), (999, 0, "exit-unavailable"))
        for code, status, category in cases:
            with self.subTest(category=category):
                child = terminal(code, status)
                value = legacy.TerminalFailureObservation().record(child)
                self.assertEqual(value, legacy.TERMINAL_MARKER + category + "/unrecognized\n")
                child.exited.assert_called_once_with()
                self.assertNotIn("panic", value)

    def test_priority_is_finite_and_suffix_remains_bounded(self):
        observed = legacy.TerminalFailureObservation()
        observed.observe(b"panicked at synthetic-private-location\n")
        observed.observe(b"Resource temporarily unavailable (os error 11)\n")
        observed.observe(b"failed to spawn thread\n" + b"x" * 8192)
        for _ in range(10):
            observed.observe(b"y" * 8192)
            self.assertLessEqual(len(observed.suffix), 127)
        self.assertLessEqual(len(observed.seen), len(legacy.TERMINAL_MESSAGES))
        self.assertLessEqual(observed.seen, set(legacy.TERMINAL_CATEGORIES))
        self.assertEqual(observed.record(terminal()),
                         legacy.TERMINAL_MARKER + "exit-one/runtime-thread-spawn\n")

    def test_synthetic_account_and_private_terminal_bait_never_emitted(self):
        observed = legacy.TerminalFailureObservation()
        bait = b"synthetic@example.invalid synthetic-account-id synthetic-cookie-value /private/synthetic"
        observed.observe(bait + b"\nNo saved session found with ID synthetic-private-uuid\n")
        record = observed.record(terminal())
        self.assertEqual(record, legacy.TERMINAL_MARKER + "exit-one/resume-session-missing\n")
        for value in ("synthetic", "@", "/private", "cookie", "uuid"):
            self.assertNotIn(value, record)
        observed = legacy.TerminalFailureObservation()
        observed.observe(bait)
        self.assertEqual(observed.record(terminal()),
                         legacy.TERMINAL_MARKER + "exit-one/unrecognized\n")

    def test_actual_exit_inspection_is_wnowait_and_never_reaps(self):
        child = tui.TerminalProcess.__new__(tui.TerminalProcess)
        child.process = SimpleNamespace(pid=123, poll=mock.Mock(), wait=mock.Mock())
        info = object()
        with mock.patch.object(tui.os, "waitid", return_value=info) as waitid:
            self.assertIs(child.exited(), info)
        waitid.assert_called_once_with(os.P_PID, 123, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        child.process.poll.assert_not_called()
        child.process.wait.assert_not_called()

    def test_actual_pump_observes_one_original_read_after_original_bound(self):
        child = tui.TerminalProcess.__new__(tui.TerminalProcess)
        child.master = 77
        child.total = 0
        child.suffix = b""
        child.selector = SimpleNamespace(select=mock.Mock(return_value=[(None, None)]))
        child.failure_observer = mock.Mock()
        packet = b"synthetic-private-terminal"
        with mock.patch.object(tui.os, "read", return_value=packet) as read:
            child.pump(0.05)
        read.assert_called_once_with(77, 8192)
        child.failure_observer.observe.assert_called_once_with(packet)
        self.assertEqual(child.total, len(packet))
        child.total = tui.OUTPUT_LIMIT
        child.failure_observer.reset_mock()
        with mock.patch.object(tui.os, "read", return_value=packet):
            with self.assertRaisesRegex(ValueError, "native terminal output exceeded bound"):
                child.pump(0.05)
        child.failure_observer.observe.assert_not_called()

    def test_actual_alive_never_admits_an_observed_exit(self):
        child = tui.TerminalProcess.__new__(tui.TerminalProcess)
        child.pump = mock.Mock()
        child.exited = mock.Mock(return_value=SimpleNamespace(si_code=os.CLD_EXITED, si_status=0))
        with self.assertRaisesRegex(ValueError, "ordinary native terminal exited early"):
            child.alive()
        child.pump.assert_called_once_with()
        child.exited.assert_called_once_with()

    def test_actual_outer_projection_rejects_private_suffixes_and_unknown_enums(self):
        module = ast.parse(Path(legacy.__file__).read_text())
        main = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        loop = next(node for node in ast.walk(main) if isinstance(node, ast.For)
                    and any(isinstance(value, ast.Name) and value.id == "TERMINAL_MARKER"
                            for value in ast.walk(node)))
        model = ast.parse("def project(diagnostics):\n    pass\n")
        model.body[0].body = [copy.deepcopy(loop)]
        namespace = dict(legacy.__dict__)
        sink = io.StringIO()
        namespace["sys"] = SimpleNamespace(stderr=sink)
        exec(compile(ast.fix_missing_locations(model), "declared-terminal-projection-model", "exec"), namespace)
        valid = (legacy.TERMINAL_MARKER + "exit-101/runtime-thread-spawn\n").encode()
        invalid = (b"synthetic-private-unrelated\n", valid.rstrip() + b"/synthetic-private\n",
                   valid.replace(b"exit-101", b"synthetic-account"),
                   valid.replace(b"runtime-thread-spawn", b"synthetic-private"),
                   valid.replace(b"runtime-thread-spawn", b"runtime-thread-spawn\xff"))
        for payload in invalid:
            with self.subTest(payload_length=len(payload)):
                sink.seek(0)
                sink.truncate()
                namespace["project"](payload)
                self.assertEqual(sink.getvalue(), "")
        namespace["project"](b"".join(invalid) + valid + valid)
        self.assertEqual(sink.getvalue(), valid.decode("ascii"))

    def test_actual_failure_hook_cannot_replace_primary_or_owned_cleanup(self):
        module = ast.parse(Path(legacy.__file__).read_text())
        inside = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "inside")
        scope = copy.deepcopy(next(node for node in inside.body if isinstance(node, ast.Try) and node.finalbody))
        scope.body = ast.parse("raise primary").body
        model = ast.parse("def fail_scope():\n    pass\n")
        model.body[0].body = [scope]
        for diagnostic_fault in (None, RuntimeError("synthetic-private-fault"), KeyboardInterrupt(), SystemExit()):
            with self.subTest(fault_type=type(diagnostic_fault).__name__):
                events = []
                primary = ValueError("synthetic-private-primary")
                child = SimpleNamespace(close=lambda: events.append("terminal-close"))
                def record(value):
                    self.assertIs(value, child)
                    events.append("terminal-record")
                    if diagnostic_fault is not None:
                        raise diagnostic_fault
                    return legacy.TERMINAL_MARKER + "exit-one/unrecognized\n"
                namespace = dict(legacy.__dict__)
                sink = io.StringIO()
                namespace.update(primary=primary, terminal=child,
                                 terminal_failure=SimpleNamespace(record=record),
                                 bootstrap_native=None, daemon=None, keyring_process=None,
                                 drains=[], census=object(), sys=SimpleNamespace(stderr=sink, exc_info=sys.exc_info),
                                 native_threads=SimpleNamespace(
                                     emit_failure=lambda value, emit: events.append("census-record"),
                                     close=lambda value, primary: events.append(("census-close", primary))))
                exec(compile(ast.fix_missing_locations(model), "declared-terminal-cleanup-model", "exec"), namespace)
                with self.assertRaises(ValueError) as caught:
                    namespace["fail_scope"]()
                self.assertIs(caught.exception, primary)
                self.assertEqual(events, ["terminal-record", "census-record", "terminal-close", ("census-close", True)])
                self.assertNotIn("synthetic", sink.getvalue())


if __name__ == "__main__":
    unittest.main()
