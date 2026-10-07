"""Synthetic owned-child syscall observation; no live continuity claim."""
from contextlib import ExitStack
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import tempfile
import unittest

import native_fd2_observer as subject
import portable

OBSERVER = Path(sys.argv.pop(1)).resolve(strict=True)
FIXTURE = Path(sys.argv.pop(1)).resolve(strict=True)
LOADER = Path(sys.argv.pop(1)).resolve(strict=True)
BASH = Path(sys.argv.pop(1)).resolve(strict=True)
RUNTIME_FILES = []
while "--runtime-file" in sys.argv:
    index = sys.argv.index("--runtime-file")
    sys.argv.pop(index)
    RUNTIME_FILES.append(Path(sys.argv.pop(index)).resolve(strict=True))
if len(RUNTIME_FILES) > 4096:
    raise ValueError("declared runtime fixture input bound")


class RecordTests(unittest.TestCase):
    def test_closed_failure_stages_and_errno_classes_never_render_private_values(self):
        for state in subject.ERROR_STATES:
            data = ("OMUX_FD2_OBSERVER_V1/" + state
                    + "/writer-none/image-none/sink-none/call-none/origin-none\n").encode()
            self.assertEqual(subject.parse_record(data).split("/")[0], state)
        for state in ("error-resume-private-secret-like-tail", "error-unknown-task-gone",
                      "error-wait-3", "error-wait-/private-path"):
            data = ("OMUX_FD2_OBSERVER_V1/" + state
                    + "/writer-none/image-none/sink-none/call-none/origin-none\n").encode()
            with self.assertRaisesRegex(ValueError, "^fd2-observer-record$"):
                subject.parse_record(data)

    def test_private_unknown_fields_extra_lines_and_inconsistent_success_refused(self):
        valid = b"OMUX_FD2_OBSERVER_V1/no-write/writer-none/image-none/sink-none/call-none/origin-none\n"
        self.assertEqual(subject.parse_record(valid).split("/")[0], "no-write")
        for data in (valid + b"private-secret-like-tail\n", valid[:-1],
                     valid.replace(b"image-none", b"private-secret-like-image"),
                     valid.replace(b"no-write", b"observed"), b"x" * 225):
            with self.assertRaisesRegex(ValueError, "^fd2-observer-record$"):
                subject.parse_record(data)


class LaunchTests(unittest.TestCase):
    def test_bundle_selected_role_bytes_and_held_fd_cleanup(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            root = Path(directory)
            roles = ("lib/omux/libexec/omux.bin", "lib/omux/lib/loader", "lib/omux/lib/libc.so.6")
            files = {}
            for role in roles:
                path = root / role
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixed diagnostic role bytes")
                files[role] = path.read_bytes()
            launch = subject.Launch(OBSERVER, [str(FIXTURE), "silent"], root, files, roles[1],
                                    time.monotonic_ns() + 3 * 10**9)
            held = launch.pass_fds
            launch.recheck()
            (root / roles[0]).write_bytes(b"other diagnostic role bytes")
            with self.assertRaisesRegex(ValueError, "^fd2-observer-role-changed$"):
                launch.recheck()
            launch.child_started()
            launch.close()
            for fd in held:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_replaced_role_bytes_and_expired_budget_refused_without_paths(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            root = Path(directory)
            role = "lib/omux/libexec/omux.bin"
            path = root / role
            path.parent.mkdir(parents=True)
            path.write_bytes(b"wrong role")
            for deadline in (time.monotonic_ns() + 3 * 10**9, 1):
                with self.assertRaisesRegex(ValueError, "^fd2-observer-role$"):
                    subject.Launch(OBSERVER, [str(FIXTURE), "silent"], root,
                                   {role: b"other role"}, "unused-loader", deadline)


class ChildTests(unittest.TestCase):
    def invoke(self, mode, *, cancel=False, forcekill=False, budget=3,
               launch_command=None, role_paths=None, environment=None):
        # The synthetic executable fills all expected roles; backend precedence
        # makes the model identity literal. Real diagnostic roles independently
        # come from verified installed bundle bytes.
        with ExitStack() as stack:
            held = []
            for path in role_paths or (FIXTURE, FIXTURE, FIXTURE):
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                held.append(fd)
                stack.callback(os.close, fd)
            reading, report = os.pipe2(os.O_CLOEXEC)
            stack.callback(os.close, reading)
            end = time.monotonic_ns() + budget * 10**9
            command = [str(OBSERVER), str(report), *(str(fd) for fd in held), str(end),
                       "--", *(launch_command or [str(FIXTURE), mode])]
            process = subprocess.Popen(command, pass_fds=(report, *held),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=environment)
            os.close(report)
            selector = selectors.DefaultSelector()
            stack.callback(selector.close)
            buffers = [bytearray(), bytearray(), bytearray()]
            for stream, buffer in zip((process.stdout, process.stderr, reading), buffers):
                fd = stream if isinstance(stream, int) else stream.fileno()
                os.set_blocking(fd, False)
                selector.register(stream, selectors.EVENT_READ, buffer)
            sent = False
            try:
                until = time.monotonic() + budget + 1
                while selector.get_map() and time.monotonic() < until:
                    if cancel and not sent and bytes(buffers[0]) == b"owned descendants ready\n":
                        # Cancel the observer itself; all traced descendants
                        # must close inherited output FDs within its own budget.
                        process.send_signal(signal.SIGKILL if forcekill else signal.SIGTERM)
                        sent = True
                    for key, _ in selector.select(0.02):
                        chunk = os.read(key.fd, 4096)
                        if chunk:
                            key.data.extend(chunk)
                            self.assertLessEqual(len(key.data), 65536)
                        else:
                            selector.unregister(key.fileobj)
                self.assertTrue(not selector.get_map(), "owned pipes did not close")
                code = process.wait(timeout=0.2)
                if forcekill:
                    self.assertEqual(bytes(buffers[2]), b"")
                    return code, bytes(buffers[0]), bytes(buffers[1]), None
                record = subject.parse_record(bytes(buffers[2])).split("/")
                self.assertNotIn("unavailable", record, "declared observer kernel profile unavailable")
                return code, bytes(buffers[0]), bytes(buffers[1]), record
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=1)
                process.stdout.close()
                process.stderr.close()

    def test_write_and_writev_preserve_streams_and_identify_kernel_file_and_sink(self):
        for mode, call in (("write", "call-write"), ("writev", "call-writev")):
            code, output, diagnostics, record = self.invoke(mode)
            self.assertEqual((code, output, diagnostics), (0, b"", b"ignored payload\n"))
            self.assertEqual(record[:5], ["observed", "writer-root-task", "image-backend",
                                         "sink-sampled-capture", call])
            self.assertIn(record[5], ("origin-backend", "origin-other"))

    def test_stdout_and_failed_fd2_write_are_not_successful_fd2_observations(self):
        for mode, output in (("silent", b""), ("stdout", b"fixed stdout\n"), ("failed-write", b"")):
            code, captured, diagnostics, record = self.invoke(mode)
            self.assertEqual((code, captured, diagnostics, record[0]), (0, output, b"", "no-write"))

    def test_fork_thread_and_exec_writer_owned_identity(self):
        for mode, writer in (("fork", "writer-other-task"), ("thread", "writer-other-task"),
                             ("exec", "writer-root-task"), ("thread-exec", "writer-root-task"),
                             ("vfork-exec", "writer-other-task")):
            code, output, diagnostics, record = self.invoke(mode)
            self.assertEqual((code, output, diagnostics), (0, b"", b"ignored payload\n"))
            self.assertEqual(record[:3], ["observed", writer, "image-backend"])

    def test_multithreaded_exit_group_preserves_no_write_and_owned_pipe_closure(self):
        code, output, diagnostics, record = self.invoke("thread-exit-group")
        self.assertEqual((code, output, diagnostics, record[0]), (0, b"", b"", "no-write"))

    def test_portable_script_command_substitution_and_explicit_loader_writer(self):
        # Execute unchanged real launcher bytes via declared Bash in POSIX mode.
        # This covers script/command-substitution/explicit-loader topology; it
        # does not cover the product's kernel /bin/sh shebang binding. Every ELF
        # comes from declared data; no host selection or PATH discovery.
        selected = sorted({path for path in RUNTIME_FILES
                           if path == (LOADER.parent / "libc.so.6").resolve(strict=True)})
        self.assertEqual(len(selected), 1, "declared loader libc fixture is absent or ambiguous")
        self.assertTrue(portable.elf_metadata(FIXTURE.read_bytes())["needed"] == ["libc.so.6"],
                        "declared portable fixture dependency shape rejected")
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as directory:
            root = Path(directory)
            binary = root / "lib/omux/libexec/omux.bin"
            loader = root / "lib/omux/lib" / LOADER.name
            libc = root / "lib/omux/lib/libc.so.6"
            launcher = root / "bin/omux"
            for path, source in ((binary, FIXTURE), (loader, LOADER), (libc, selected[0])):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.read_bytes())
                path.chmod(0o755)
            launcher.parent.mkdir()
            launcher.write_bytes(portable.linux_launcher(LOADER.name, "omux.bin", "release"))
            launcher.chmod(0o755)
            code, output, diagnostics, record = self.invoke(
                "write", budget=6, launch_command=[str(BASH), "--noprofile", "--norc", "--posix", str(launcher), "write"],
                role_paths=(binary, loader, libc),
                environment={"PATH": "/nonexistent", "OMUX_INSTANCE": "default"})
            self.assertTrue(code == 0 and output == b"" and diagnostics == b"ignored payload\n",
                            "declared portable observer stream predicate failed")
            self.assertEqual(record, ["observed", "writer-root-task", "image-loader",
                                      "sink-sampled-capture", "call-write", "origin-libc"])

    def test_fd2_replacement_does_not_claim_original_capture(self):
        code, output, diagnostics, record = self.invoke("sink-other")
        self.assertEqual((code, output, diagnostics), (0, b"", b""))
        self.assertEqual((record[0], record[3]), ("observed", "sink-sampled-other"))

    def test_deadline_kills_owned_forked_descendants_and_closes_pipes(self):
        code, output, diagnostics, record = self.invoke("cancel", budget=1)
        self.assertEqual((code, output, diagnostics, record[0]), (125, b"owned descendants ready\n", b"", "deadline"))

    def test_sigkill_observer_exitkill_closes_owned_descendant_pipes(self):
        code, output, diagnostics, record = self.invoke("cancel", cancel=True, forcekill=True)
        self.assertEqual((code, output, diagnostics, record),
                         (-signal.SIGKILL, b"owned descendants ready\n", b"", None))

    def test_cancellation_closes_owned_descendant_pipes(self):
        code, output, diagnostics, record = self.invoke("cancel", cancel=True)
        self.assertEqual((code, output, diagnostics, record[0]), (125, b"owned descendants ready\n", b"", "cancelled"))


if __name__ == "__main__":
    unittest.main()
