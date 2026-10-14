"""Offline loader ABI models; native subprocess launch is mocked."""
import contextlib
import io
import os
import stat
import unittest
from unittest import mock
import native_account_login as action

class LoaderContract(unittest.TestCase):
    def test_held_loader_receives_backend_fd_and_declared_library_path(self):
        process = mock.Mock(pid=43210)
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.poll.return_value = None
        process.wait.side_effect = [action.subprocess.TimeoutExpired("owned-model", 5), 0]
        loader = mock.Mock(st_mode=stat.S_IFREG|0o555,st_uid=os.getuid(),st_nlink=1)
        environment = {"HOME":"/private/owned-profile","PATH":"/nonexistent"}
        with mock.patch.object(action.subprocess,"Popen",return_value=process) as launched, \
             mock.patch.object(action.os,"fstat",return_value=loader), \
             mock.patch.object(action.os,"pidfd_open",side_effect=OSError("model-only")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(action.Refusal):
                action.Native(11,environment,"/private/owned-profile",loader_fd=12,
                              library_path="/private/sealed/runtime/lib/codex/lib")
        args,kwargs = launched.call_args
        self.assertEqual(args[0][:7],["/proc/self/fd/12","--library-path",
            "/private/sealed/runtime/lib/codex/lib","--argv0","codex","/proc/self/fd/11","-c"])
        self.assertEqual(kwargs["executable"],"/proc/self/fd/12")
        self.assertEqual(kwargs["pass_fds"],(11,12))
        self.assertIs(kwargs["env"],environment)
        self.assertEqual(kwargs["stderr"],action.subprocess.DEVNULL)
        process.terminate.assert_called_once_with()

    def test_invalid_loader_layout_refuses_before_any_launch(self):
        for path in ("/private/../lib","relative/lib","/private/lib:extra","/private/lib bad"):
            with mock.patch.object(action.subprocess,"Popen") as launched:
                with self.assertRaises(action.Refusal):
                    action.Native(11,{},"/private",loader_fd=12,library_path=path)
                launched.assert_not_called()
        with mock.patch.object(action.subprocess,"Popen") as launched:
            with self.assertRaises(action.Refusal):
                action.Native(11,{},"/private",library_path="/private/lib")
            launched.assert_not_called()


class CleanupFaults(unittest.TestCase):
    def test_actual_native_close_reaps_and_releases_after_stream_or_selector_fault(self):
        for fault in ("stdin","selector","stdout"):
            with self.subTest(fault=fault):
                native = object.__new__(action.Native)
                native.closed = False
                native.buffer = bytearray(b"synthetic-buffer")
                native.selector = mock.Mock()
                native.pidfd = 19
                native.process = mock.Mock()
                native.process.poll.return_value = None
                native.process.wait.side_effect = [action.subprocess.TimeoutExpired("model",5),
                    action.subprocess.TimeoutExpired("model",5),0]
                selected = native.selector if fault == "selector" else getattr(native.process,fault)
                selected.close.side_effect = OSError(5,"synthetic-close")
                with mock.patch.object(action.signal,"pidfd_send_signal") as signalled,\
                    mock.patch.object(action.os,"close") as closed:
                    with self.assertRaisesRegex(action.Refusal,"^native_cleanup_failed$"):
                        native.close()
                self.assertEqual([row.args[1] for row in signalled.call_args_list],
                    [action.signal.SIGTERM,action.signal.SIGKILL])
                self.assertEqual(native.process.wait.call_count,3)
                native.process.stdout.close.assert_called_once()
                native.selector.close.assert_called_once()
                closed.assert_called_once_with(19)
                self.assertEqual(native.buffer,bytearray(len(b"synthetic-buffer")))
                self.assertIsNone(native.pidfd)
                native.close()  # Completed cleanup cannot reuse a closed pidfd.

if __name__ == "__main__":
    unittest.main()
