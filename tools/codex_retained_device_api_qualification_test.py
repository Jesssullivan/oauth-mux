"""Actual retained-native cleanup faults with fully mocked child launch."""
import os
import time
import unittest
from unittest.mock import Mock, patch
import codex_retained_device_api_qualification as actual

class CleanupModels(unittest.TestCase):
    def test_actual_native_stdout_close_fault_still_reaps_child_and_closes_stderr_pidfd(self):
        process = Mock(pid=43210)
        process.poll.return_value = None
        process.stdout.close.side_effect = OSError(5,"synthetic-close")
        process.wait.side_effect = [actual.subprocess.TimeoutExpired("model",5),
            actual.subprocess.TimeoutExpired("model",5),0]
        selector = Mock()
        selector.__enter__ = Mock(side_effect=OSError(5,"synthetic-selector"))
        selector.__exit__ = Mock(return_value=False)
        with patch.object(actual,"tick"),patch.object(actual.subprocess,"Popen",return_value=process),\
            patch.object(actual.os,"pidfd_open",return_value=19),patch.object(actual,"DEADLINE",time.monotonic()+60),\
            patch.object(actual.selectors,"DefaultSelector",return_value=selector),\
            patch.object(actual.signal,"pidfd_send_signal") as signals,patch.object(actual.os,"close") as close:
            with self.assertRaisesRegex(ValueError,"^retained-device-api-qualification-refused$"):
                actual.native(11,12,"/declared/public-lib",["--version"],{},"/declared/public-work")
        self.assertEqual([call.args[1] for call in signals.call_args_list],
            [actual.signal.SIGTERM,actual.signal.SIGKILL])
        self.assertEqual(process.wait.call_count,3)
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()
        close.assert_called_once_with(19)

    def test_actual_backend_loader_release_preserves_failure_and_releases_second_descriptor(self):
        def close_fd(fd):
            if fd == 11:
                raise OSError(5,"synthetic-close")
        with patch.object(actual.os,"close",side_effect=close_fd) as close:
            with self.assertRaisesRegex(ValueError,"^retained-device-api-qualification-refused$"):
                actual.release_fds((11,12))
        self.assertEqual([call.args[0] for call in close.call_args_list],[11,12])

if __name__ == "__main__":
    unittest.main()
