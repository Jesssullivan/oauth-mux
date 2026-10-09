"""Ordinary-first native decisions and cleanup; no real process/provider IO."""
import contextlib
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_installed_retained_ordinary_native_tui as ordinary
import test_installed_legacy_native_tui as legacy


class NativeModel:
    def __init__(self):
        self.endpoint = Path("/owned/omux-owner-" + "a" * 16 + "/owner.sock")
        self.thread = "00000000-0000-0000-0000-000000000001"
        self.reference = {"owner_id": "a" * 64, "adapter_epoch": "1",
            "endpoint_generation": "1", "thread_instance_generation": "1", "attachment_generation": "1"}
        self.owner = {"owner_id": "a" * 64, "process_nonce": "b" * 64,
            "endpoint_generation": "1", "owner_endpoint": str(self.endpoint),
            "support": "compatible_hook", "threads": [{"thread_id": self.thread,
                "thread_instance_generation": "1", "attachment_generation": "1",
                "native_ref": self.reference}]}
        self.process = SimpleNamespace(pid=314)
        self.commands, self.closes, self.rpc = [], [], []
        self.discovery_count = 0
        self.change_attachment = False
        self.discovery_invalid = False
        self.before = ((self.thread, "rollout", "cli", "work", "paginated", "version",
                        legacy.tui.FIXTURE_NAME, 0, 0), (1, 2), b"digest", b"original\n")
        self.after = self.before

    def alive(self):
        pass

    def pump(self, seconds):
        raise AssertionError("immediate model must not wait")

    def send(self, command):
        self.commands.append(command)

    def close(self, *, require_success=False):
        self.closes.append(require_success)

    def cli(self, method, params=None):
        self.rpc.append((method, params))
        if method == "state.snapshot":
            return {"empty": True}
        if method != "integrations.discover":
            raise AssertionError("no owner-status, provider or setup mutation")
        self.discovery_count += 1
        owner = copy.deepcopy(self.owner)
        if self.discovery_invalid:
            owner["process_nonce"] = "not-an-opaque-nonce"
        if self.change_attachment and self.discovery_count > 1:
            owner["threads"][0]["native_ref"]["attachment_generation"] = "2"
            owner["threads"][0]["attachment_generation"] = "2"
        return {"installed": True, "native_support": False, "hook_compatible": True, "owners": [owner]}


class OrdinaryFirstModels(unittest.TestCase):
    def run_checkpoint(self, world, *, wait_failure=None, detach_failure=None, metadata_changed=False,
                       witness_changed=False, failure_observer=None):
        observed_names = []
        witness_calls = 0

        def witness(pid):
            nonlocal witness_calls
            self.assertEqual(pid, 314)
            witness_calls += 1
            return {"actual-model-witness": 2 if witness_changed and witness_calls > 1 else 1}

        def wait(home, thread, terminal, *, expected_name=legacy.tui.FIXTURE_NAME):
            self.assertEqual(thread, world.thread)
            self.assertIs(terminal, world)
            observed_names.append(expected_name)
            if wait_failure:
                raise wait_failure
            return world.before

        def detach(*args):
            if detach_failure:
                raise detach_failure
            if metadata_changed:
                world.after = (world.before[0], (9, 9), b"changed", b"rewritten\n")
            return "c" * 64

        with mock.patch.object(legacy.tui, "TerminalProcess", return_value=world) as terminal, \
                mock.patch.object(legacy.support, "owned_endpoint", return_value=world.endpoint), \
                mock.patch.object(legacy.tui, "process_witness", side_effect=witness), \
                mock.patch.object(legacy, "wait_metadata", side_effect=wait), \
                mock.patch.object(legacy, "detach", side_effect=detach) as selected_detach, \
                mock.patch.object(legacy.tui, "metadata", side_effect=lambda *args: world.after), \
                mock.patch.object(legacy.support, "private_file",
                                  side_effect=lambda path, maximum: b"configured" if path.name == "config" else b"cap"), \
                mock.patch.object(legacy.support, "check_empty_domain") as empty, \
                mock.patch.object(legacy.tui, "native_rpc") as native_status, \
                mock.patch.object(legacy, "native_call") as seeded_history:
            try:
                result = legacy.ordinary_first_history(Path("/public/codex"), {"TOKIO_WORKER_THREADS": "2"},
                    Path("/public/work"), Path("/public/home"), world.cli, Path("/public/config"),
                    b"configured", Path("/public/capability"), b"cap", failure_observer)
                terminal.assert_called_once_with(Path("/public/codex"), {"TOKIO_WORKER_THREADS": "2"},
                    Path("/public/work"), failure_observer=failure_observer)
                self.assertEqual(observed_names, [None, legacy.tui.FIXTURE_NAME])
                selected_detach.assert_called_once()
                self.assertEqual(selected_detach.call_args.args[2], result["attachment"])
                empty.assert_called_once_with({"empty": True})
                return result
            finally:
                native_status.assert_not_called()
                seeded_history.assert_not_called()

    def test_real_discovery_export_rename_detach_and_clean_exit_keep_one_original_pid(self):
        world = NativeModel()
        result = self.run_checkpoint(world)
        self.assertEqual(world.commands, ["/export omux-native-resume-fixture.md\r",
                                         "/rename " + legacy.tui.FIXTURE_NAME + "\r"])
        self.assertEqual(result["pid"], 314)
        self.assertEqual(result["thread"], world.thread)
        self.assertEqual(result["attachment"]["reference"], world.reference)
        self.assertEqual(result["before"], world.before)
        self.assertEqual(world.closes, [True])
        self.assertEqual([method for method, _ in world.rpc],
                         ["integrations.discover", "integrations.discover", "state.snapshot"])

    def test_replaced_actual_commit_after_export_refuses_rename_detach_and_closes_owned_terminal(self):
        world = NativeModel()
        world.change_attachment = True
        with self.assertRaises(ValueError):
            self.run_checkpoint(world)
        self.assertEqual(world.commands, ["/export omux-native-resume-fixture.md\r"])
        self.assertEqual(world.closes, [False])

    def test_replaced_process_witness_after_export_refuses_further_commands(self):
        world = NativeModel()
        with self.assertRaises(ValueError):
            self.run_checkpoint(world, witness_changed=True)
        self.assertEqual(world.commands, ["/export omux-native-resume-fixture.md\r"])
        self.assertEqual(world.closes, [False])

    def test_invalid_discovery_never_exports_or_seeds_history(self):
        world = NativeModel()
        world.discovery_invalid = True
        with self.assertRaises(ValueError):
            self.run_checkpoint(world)
        self.assertEqual(world.commands, [])
        self.assertEqual(world.closes, [False])

    def test_missing_materialized_metadata_refuses_rename_and_closes_owned_terminal(self):
        world = NativeModel()
        with self.assertRaises(ValueError):
            self.run_checkpoint(world, wait_failure=ValueError("public model metadata refusal"))
        self.assertEqual(world.commands, ["/export omux-native-resume-fixture.md\r"])
        self.assertEqual(world.closes, [False])

    def test_changed_history_after_detach_never_returns_success(self):
        world = NativeModel()
        with self.assertRaises(ValueError):
            self.run_checkpoint(world, metadata_changed=True)
        self.assertEqual(world.closes, [False])

    def test_lost_detach_ack_closes_owned_terminal_without_repeating_work(self):
        world = NativeModel()
        with self.assertRaises(TimeoutError):
            self.run_checkpoint(world, detach_failure=TimeoutError("public model lost ACK"))
        self.assertEqual(len(world.commands), 2)
        self.assertEqual(world.closes, [False])

    def test_wrapper_explicitly_selects_ordinary_mode_and_reenters_it_privately(self):
        with mock.patch.object(legacy, "main", return_value=0) as carrier:
            self.assertEqual(ordinary.main(), 0)
            carrier.assert_called_once_with(ordinary_first=True,
                                           entrypoint=Path(ordinary.__file__).absolute())
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            paths = [Path(directory) / str(i) for i in range(6)]
            for path in paths:
                path.write_bytes(b"public model input")
            with mock.patch.object(sys, "argv", ["fixture", *(str(path) for path in paths)]), \
                    mock.patch.object(legacy.subprocess, "Popen") as process, \
                    mock.patch.object(legacy.support, "bounded_private_session",
                                      return_value=(0, legacy.ORDINARY_MARKER, b"")), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(ordinary.main(), 0)
                command = process.call_args.args[0]
                selected = command.index(str(Path(ordinary.__file__).absolute()))
                self.assertEqual(command[selected + 1], "--census-deadline-ns")
                self.assertEqual(command[selected + 3:selected + 8],
                    ["--inside", str(paths[0]), str(paths[1]), str(paths[2]), str(paths[5])])
                self.assertEqual(len(command[selected + 8:]), 1)
                self.assertEqual(output.getvalue(), legacy.ORDINARY_MARKER.decode("ascii"))
                environment = process.call_args.kwargs["env"]
                self.assertEqual(environment["OMUX_ISOLATED_VAULT_PROOF"], "private-bus-private-xdg")
                self.assertEqual(environment["PATH"], "/nonexistent")
                self.assertNotIn("CODEX_HOME", environment)

    def test_seeded_default_and_explicit_ordinary_private_dispatch_are_separate(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            paths = [Path(directory) / str(i) for i in range(5)]
            for path in paths:
                path.write_bytes(b"public model input")
            argv = ["fixture", "--inside", *(str(path) for path in paths)]
            with mock.patch.object(sys, "argv", argv[:]), mock.patch.object(legacy, "inside") as inside:
                self.assertEqual(legacy.main(), 0)
                inside.assert_called_once_with(*paths, census_deadline_ns=None)
            with mock.patch.object(sys, "argv", argv[:]), mock.patch.object(legacy, "inside") as inside:
                self.assertEqual(ordinary.main(), 0)
                inside.assert_called_once_with(*paths, census_deadline_ns=None, ordinary_first=True)
        with mock.patch.object(sys, "argv", ["fixture", "--fd2-observer", "/public/observer"]):
            with self.assertRaises(ValueError):
                ordinary.main()
        self.assertNotEqual(legacy.MARKER, legacy.ORDINARY_MARKER)


    def test_partial_failure_records_before_cleanup_without_repeating_work(self):
        cases = ((ValueError("ordinary native terminal exited early"), "resume-terminal-exited"),
                 (TimeoutError("synthetic-private-timeout"), "resume-os-other"),
                 *((ValueError(message), category) for message, category in legacy.ORDINARY_FAILURE_MESSAGES.items()))
        for primary, category in cases:
            for diagnostic_fault in (None, KeyboardInterrupt(), SystemExit()):
                for cleanup_fault in (False, True):
                    with self.subTest(category=category, diagnostic_fault=type(diagnostic_fault).__name__,
                                      cleanup_fault=cleanup_fault):
                        events = []
                        child = SimpleNamespace(process=SimpleNamespace(pid=314))
                        def close():
                            self.assertIn(legacy.ORDINARY_FAILURE_MARKER + category + "\n", sink.getvalue())
                            events.append("close")
                            if cleanup_fault:
                                raise RuntimeError("synthetic-private-cleanup")
                        child.close = close
                        def record(terminal):
                            self.assertIs(terminal, child)
                            events.append("record")
                            if diagnostic_fault is not None:
                                raise diagnostic_fault
                            return legacy.TERMINAL_MARKER + "exit-one/config-load\n"
                        observer = SimpleNamespace(record=record)
                        with mock.patch.object(legacy.tui, "TerminalProcess", return_value=child) as launch, \
                                mock.patch.object(legacy, "wait_attached", side_effect=primary) as attached, \
                                mock.patch.object(legacy, "detach") as detach, \
                                contextlib.redirect_stderr(io.StringIO()) as sink:
                            with self.assertRaises(type(primary)) as caught:
                                legacy.ordinary_first_history(None, {}, None, None, None,
                                    None, None, None, None, observer)
                        self.assertIs(caught.exception, primary)
                        self.assertEqual(events, ["record", "close"])
                        launch.assert_called_once()
                        attached.assert_called_once()
                        detach.assert_not_called()
                        self.assertIn(legacy.ORDINARY_FAILURE_MARKER + category + "\n", sink.getvalue())
                        self.assertNotIn("synthetic", sink.getvalue())
                        if cleanup_fault:
                            self.assertIn("retained ordinary owned terminal cleanup refused", primary.__notes__)

    def test_terminal_constructor_refusal_retains_primary_without_cleanup_or_record(self):
        primary = PermissionError("synthetic-private-path")
        observer = mock.Mock()
        with mock.patch.object(legacy.tui, "TerminalProcess", side_effect=primary) as launch, \
                mock.patch.object(legacy, "wait_attached") as attached, \
                contextlib.redirect_stderr(io.StringIO()) as sink:
            with self.assertRaises(PermissionError) as caught:
                legacy.ordinary_first_history(None, {}, None, None, None,
                    None, None, None, None, observer)
        self.assertIs(caught.exception, primary)
        launch.assert_called_once()
        attached.assert_not_called()
        observer.record.assert_not_called()
        self.assertEqual(sink.getvalue(), legacy.ORDINARY_FAILURE_MARKER + "resume-permission\n")

    def test_lost_ack_observation_never_repeats_detach_or_terminal_commands(self):
        world = NativeModel()
        primary = TimeoutError("synthetic-private-lost-ACK")
        observer = mock.Mock()
        observer.record.return_value = legacy.TERMINAL_MARKER + "exit-unavailable/unrecognized\n"
        with contextlib.redirect_stderr(io.StringIO()) as sink:
            with self.assertRaises(TimeoutError) as caught:
                self.run_checkpoint(world, detach_failure=primary, failure_observer=observer)
        self.assertIs(caught.exception, primary)
        observer.record.assert_called_once_with(world)
        self.assertEqual(len(world.commands), 2)
        self.assertEqual(world.closes, [False])
        self.assertEqual(world.discovery_count, 2)
        self.assertNotIn("synthetic", sink.getvalue())

    def test_outer_refusal_projection_rejects_suffixes_and_preserves_seed_default(self):
        valid = (legacy.ORDINARY_FAILURE_MARKER + "resume-terminal-exited\n").encode()
        invalid = (valid.rstrip() + b"/synthetic-private\n"
                   + valid.replace(b"resume-terminal-exited", b"synthetic-private"))
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            paths = [Path(directory) / str(i) for i in range(6)]
            for path in paths:
                path.write_bytes(b"public model input")
            for ordinary_mode, diagnostics, expected in ((True, invalid, ""),
                    (True, invalid + valid + valid, valid.decode("ascii")),
                    (False, valid, "")):
                with self.subTest(ordinary_mode=ordinary_mode, expected=expected), \
                        mock.patch.object(sys, "argv", ["fixture", *(str(path) for path in paths)]), \
                        mock.patch.object(legacy.subprocess, "Popen"), \
                        mock.patch.object(legacy.support, "bounded_private_session",
                                          return_value=(1, b"", diagnostics)), \
                        contextlib.redirect_stderr(io.StringIO()) as sink:
                    self.assertEqual(legacy.main(ordinary_first=ordinary_mode,
                        entrypoint=Path(ordinary.__file__).absolute() if ordinary_mode else None), 1)
                    self.assertEqual(sink.getvalue(), expected)

if __name__ == "__main__":
    unittest.main()
