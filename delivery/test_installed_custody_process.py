"""Owned private-session cleanup ordering; no vault, GUI or provider access."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import unittest
from unittest import mock

import test_installed_custody as custody


class PrivateSessionTest(unittest.TestCase):
    def child(self, source: str) -> subprocess.Popen:
        return subprocess.Popen([sys.executable, "-I", "-B", "-c", source],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True,
                                env={"PATH": "/nonexistent", "LANG": "C"})

    def collect(self, source: str, *, expected_error: str | None = None,
                deadline: float = 5) -> tuple[int, bytes, bytes] | None:
        process = self.child(source)
        original_signal = os.killpg
        signal_observations = []

        def signal_owned(group: int, requested_signal: int) -> None:
            # Observe OS child identity immediately before the real group kill.
            # A reaped leader makes waitid raise ChildProcessError here.
            self.assertEqual(group, process.pid)
            self.assertEqual(requested_signal, signal.SIGKILL)
            self.assertEqual(os.getpgid(group), group)
            status = os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertTrue(status is None or status.si_pid == group)
            self.assertIsNone(process.returncode)
            signal_observations.append(status is not None)
            original_signal(group, requested_signal)

        try:
            with mock.patch.object(custody.os, "killpg", side_effect=signal_owned):
                if expected_error is None:
                    result = custody.bounded_private_session(process, deadline_seconds=deadline)
                else:
                    with self.assertRaisesRegex(ValueError, expected_error):
                        custody.bounded_private_session(process, deadline_seconds=deadline)
                    result = None
            self.assertEqual(len(signal_observations), 1)
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            with self.assertRaises(ChildProcessError):
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if expected_error is None:
                self.assertEqual(signal_observations, [True])
            return result
        finally:
            # If an assertion interrupted the collector, first establish that
            # this exact leader remains our unreaped child before group cleanup.
            if process.returncode is None:
                try:
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    pass
                else:
                    if os.getpgid(process.pid) == process.pid:
                        try:
                            original_signal(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_success_preserves_unreaped_leader_before_group_signal(self) -> None:
        self.assertEqual(self.collect("import os;os.write(1,b'owned-output\\n');os.write(2,b'owned-error\\n')"),
                         (0, b"owned-output\n", b"owned-error\n"))

    def test_output_overflow_cleans_up_owned_group_before_wait(self) -> None:
        self.collect("import os,time;os.write(1,b'x'*(256*1024+1));time.sleep(.2)",
                     expected_error="output exceeded its bound")

    def test_deadline_cleans_up_live_owned_leader_and_pipes(self) -> None:
        self.collect("import time;time.sleep(.2)", expected_error="bounded execution", deadline=.05)


if __name__ == "__main__":
    unittest.main()
