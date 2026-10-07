"""Declared model of actual run_cli; no child executable or mutation is run."""
from contextlib import ExitStack
import errno
import io
import json
import os
import selectors
import subprocess
import unittest
from unittest.mock import patch

import native_run_cli_failure as observation
import test_installed_native_interop as support
import test_installed_legacy_native_tui as legacy

PARAMS = {"operation_id": "0" * 64, "expected_revision": 7}
COMMAND = ["/declared/model/omux", "rpc", "integrations.detach", "-"]
ENVIRONMENT = {"LANG": "C"}
PRIVATE = b"private-token-like-model-payload"


class Input(io.BytesIO):
    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault
        self.saved = None

    def write(self, data):
        if self.fault is not None:
            raise self.fault
        return super().write(data)

    def close(self):
        if not self.closed:
            self.saved = self.getvalue()
        super().close()


class Process:
    def __init__(self, output=b'{"result":{"detached":true}}', diagnostics=b"", code=0,
                 input_fault=None, wait_fault=None):
        self.stdin = Input(input_fault)
        self.stdout = self.pipe(output)
        self.stderr = self.pipe(diagnostics)
        self.returncode = None
        self.code = code
        self.wait_fault = wait_fault
        self.wait_calls = 0
        self.wait_timeout = None

    @staticmethod
    def pipe(data):
        read, write = os.pipe()
        try:
            # All ordinary model streams are much smaller than PIPE_BUF.
            if data:
                os.write(write, data)
        finally:
            os.close(write)
        return os.fdopen(read, "rb", buffering=0)

    def wait(self, timeout):
        self.wait_calls += 1
        self.wait_timeout = timeout
        if self.wait_fault is not None:
            raise self.wait_fault
        self.returncode = self.code
        return self.code

    def close(self):
        self.stdin.close()
        self.stdout.close()
        self.stderr.close()


class HookTests(unittest.TestCase):
    def invoke(self, process, observer=None, *, popen_error=None, read=None, times=None, entry=None):
        self.addCleanup(process.close)
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.popen = stack.enter_context(patch.object(
            support.subprocess, "Popen", side_effect=popen_error, return_value=process))
        self.stopped = stack.enter_context(patch.object(support, "stop"))
        self.selector_instances = []
        self.selector_closed = []
        constructor = selectors.DefaultSelector

        def selector():
            value = constructor()
            self.selector_instances.append(value)
            original_close = value.close

            def close():
                self.selector_closed.append(value)
                original_close()

            value.close = close
            return value

        stack.enter_context(patch.object(support.selectors, "DefaultSelector", side_effect=selector))
        if read is not None:
            stack.enter_context(patch.object(support.os, "read", side_effect=read))
        if times is not None:
            stack.enter_context(patch.object(support.time, "monotonic", side_effect=times))
        def run():
            try:
                if entry is not None:
                    return entry()
                return support.run_cli(COMMAND, ENVIRONMENT, PARAMS, failure_observer=observer)
            finally:
                stack.close()

        return run

    def assert_one_child_and_request(self, process, *, input_sent=True):
        self.assertEqual(self.popen.call_count, 1)
        args, kwargs = self.popen.call_args
        self.assertTrue(args == (COMMAND,) and kwargs == {
            "env": ENVIRONMENT, "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE, "stderr": subprocess.PIPE},
            "declared single invocation changed")
        self.assertEqual(self.stopped.call_count, 1)
        self.assertTrue(process.stdout.closed and process.stderr.closed, "owned streams not closed")
        for selector in self.selector_instances:
            self.assertTrue(selector in self.selector_closed, "selector not closed")
        if input_sent:
            self.assertTrue(process.stdin.saved == json.dumps(PARAMS, separators=(",", ":")).encode(),
                            "mutation input changed or repeated")

    def test_success_preserves_baseline_shape_and_does_not_call_hook(self):
        # Original helper intentionally accepts this result without JSON-RPC
        # envelope validation. This hook must not strengthen that acceptance.
        for observer in (None, lambda data: self.fail("successful helper invoked observer")):
            with self.subTest(enabled=observer is not None):
                process = Process()
                run = self.invoke(process, observer, times=lambda: 100.0)
                self.assertEqual(run(), {"detached": True})
                self.assert_one_child_and_request(process)
                self.assertEqual(process.wait_calls, 1)
                self.assertEqual(process.wait_timeout, 20.0)

    def test_failed_process_private_streams_emit_presence_only(self):
        records = []
        process = Process(output=PRIVATE, diagnostics=PRIVATE, code=3)
        with self.assertRaises(ValueError) as caught:
            self.invoke(process, records.append)()
        self.assertTrue(caught.exception.args == ("installed CLI predicate failed",),
                        "original predicate changed")
        self.assertEqual(records, [
            observation.PREFIX + b"/process/process-predicate/exit-positive/stdout-nonempty/stderr-nonempty\n"])
        self.assert_one_child_and_request(process)

    def test_exit_zero_nonempty_stderr_remains_failure(self):
        records = []
        process = Process(diagnostics=PRIVATE)
        with self.assertRaises(ValueError):
            self.invoke(process, records.append)()
        self.assertEqual(records, [
            observation.PREFIX + b"/process/process-predicate/exit-zero/stdout-nonempty/stderr-nonempty\n"])
        self.assert_one_child_and_request(process)

    def test_launch_errno_record_has_no_child_or_cleanup(self):
        records = []
        original = BlockingIOError(errno.EAGAIN, "private ignored model error", "/private/model/path")
        process = Process()
        with self.assertRaises(BlockingIOError) as caught:
            self.invoke(process, records.append, popen_error=original)()
        self.assertTrue(caught.exception is original, "original launch exception changed")
        self.assertEqual(records, [
            observation.PREFIX + b"/launch/os-busy/exit-unobserved/stdout-empty/stderr-empty\n"])
        self.assertEqual(self.popen.call_count, 1)
        self.assertEqual(self.stopped.call_count, 0)
        self.assertEqual(process.wait_calls, 0)

    def test_input_failure_is_preserved_and_owned_cleanup_runs(self):
        records = []
        original = BrokenPipeError(errno.EPIPE, "private ignored input")
        process = Process(input_fault=original)
        with self.assertRaises(BrokenPipeError) as caught:
            self.invoke(process, records.append)()
        self.assertTrue(caught.exception is original, "original input exception changed")
        self.assertEqual(records, [
            observation.PREFIX + b"/input/os-pipe/exit-unobserved/stdout-empty/stderr-empty\n"])
        self.assert_one_child_and_request(process, input_sent=False)
        self.assertEqual(process.wait_calls, 0)

    def test_output_bound_and_deadline_keep_original_predicates(self):
        for kind in ("output-bound", "stream-deadline"):
            with self.subTest(kind=kind):
                records = []
                process = Process()
                kwargs = ({"read": lambda fd, maximum: (b"x" * (support.FRAME_LIMIT + 1)
                                                     if fd == process.stdout.fileno() else b"")}
                          if kind == "output-bound" else {"times": iter((0.0, 21.0)).__next__})
                with self.assertRaises(ValueError) as caught:
                    self.invoke(process, records.append, **kwargs)()
                message = ("installed CLI output exceeded its bound" if kind == "output-bound"
                           else "installed CLI deadline exceeded")
                self.assertTrue(caught.exception.args == (message,), "original capture predicate changed")
                expected_stdout = b"stdout-nonempty" if kind == "output-bound" else b"stdout-empty"
                self.assertEqual(records, [observation.PREFIX + b"/capture/" + kind.encode()
                                          + b"/exit-unobserved/" + expected_stdout + b"/stderr-empty\n"])
                self.assert_one_child_and_request(process)
                self.assertEqual(process.wait_calls, 0)

    def test_wait_timeout_rethrows_original_and_runs_cleanup(self):
        records = []
        original = subprocess.TimeoutExpired(["private ignored model argv"], 1)
        process = Process(wait_fault=original)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.invoke(process, records.append)()
        self.assertTrue(caught.exception is original, "original wait exception changed")
        self.assertEqual(records, [
            observation.PREFIX + b"/wait/timeout/exit-unobserved/stdout-nonempty/stderr-empty\n"])
        self.assert_one_child_and_request(process)

    def test_json_and_result_failures_remain_original(self):
        for payload, stage, failure in ((PRIVATE, b"json", b"json"),
                                        (b'{"error":{"message":"private-model"}}', b"result", b"result-predicate")):
            with self.subTest(stage=stage):
                records = []
                process = Process(output=payload)
                with self.assertRaises(ValueError):
                    self.invoke(process, records.append)()
                self.assertEqual(records, [observation.PREFIX + b"/" + stage + b"/" + failure
                                          + b"/exit-zero/stdout-nonempty/stderr-empty\n"])
                self.assert_one_child_and_request(process)

    def test_callback_exceptions_cannot_replace_original_failure(self):
        for callback_error in (RuntimeError("private-model"), KeyboardInterrupt(), SystemExit(9)):
            for launch in (False, True):
                with self.subTest(type=type(callback_error).__name__, launch=launch):
                    original = OSError(errno.ENOMEM, "private ignored model")
                    records = []

                    def observer(data):
                        records.append(data)
                        raise callback_error

                    process = Process(wait_fault=original)
                    kwargs = {"popen_error": original} if launch else {}
                    with self.assertRaises(OSError) as caught:
                        self.invoke(process, observer, **kwargs)()
                    self.assertTrue(caught.exception is original, "callback replaced original exception")
                    self.assertEqual(len(records), 1)
                    self.assertEqual(self.popen.call_count, 1)
                    self.assertEqual(self.stopped.call_count, 0 if launch else 1)

    def test_baseline_without_hook_rejects_same_failure(self):
        process = Process(diagnostics=PRIVATE)
        with self.assertRaises(ValueError) as caught:
            self.invoke(process)()
        self.assertTrue(caught.exception.args == ("installed CLI predicate failed",),
                        "disabled helper failure changed")
        self.assert_one_child_and_request(process)

    def test_legacy_diagnostic_hook_is_gated_and_never_repeats_detach(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                process = Process(diagnostics=PRIVATE)
                with patch.object(legacy, "FD2_OBSERVER", object() if enabled else None), \
                     patch.object(legacy, "DETACH_CLI_FAILURE_RECORD", None):
                    run = self.invoke(process, entry=lambda: legacy.run_detach_cli(COMMAND, ENVIRONMENT, PARAMS))
                    with self.assertRaises(ValueError) as caught:
                        run()
                    self.assertTrue(caught.exception.args == ("installed CLI predicate failed",),
                                    "diagnostic wiring changed original failure")
                    if enabled:
                        self.assertEqual(legacy.DETACH_CLI_FAILURE_RECORD, observation.PREFIX
                                         + b"/process/process-predicate/exit-zero/stdout-nonempty/stderr-nonempty\n")
                    else:
                        self.assertIsNone(legacy.DETACH_CLI_FAILURE_RECORD)
                    self.assert_one_child_and_request(process)

    def test_closed_records_unknown_payload_and_parser_negatives(self):
        class NoText(RuntimeError):
            def __str__(self):
                raise AssertionError("exception text must remain unread")

            def __repr__(self):
                raise AssertionError("exception repr must remain unread")

        data = observation.record("launch", NoText("private-model"), True, PRIVATE, PRIVATE)
        self.assertEqual(data, observation.PREFIX
                         + b"/launch/other/exit-unavailable/stdout-nonempty/stderr-nonempty\n")
        self.assertEqual(observation.parse_record(data), data)
        for rejected in (data + PRIVATE, data + b"\n", data.replace(b"/other/", b"/private-model/"),
                         data.replace(b"/launch/", b"/private/path/"), data[:-1],
                         b"x" * (observation.MAX_RECORD + 1)):
            with self.assertRaises(ValueError):
                observation.parse_record(rejected)
        for number, label in ((errno.EAGAIN, b"os-busy"), (errno.EPERM, b"os-permission"),
                              (errno.ENOENT, b"os-missing"), (errno.EMFILE, b"os-limit"),
                              (123456, b"os-other")):
            value = observation.record("launch", OSError(number, "private-model"), None, b"", b"")
            self.assertTrue(b"/" + label + b"/" in value, "closed errno attribution changed")


if __name__ == "__main__":
    unittest.main()
