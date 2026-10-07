"""Actual compiled launcher boundary predicates; all execution is Bazel-owned.

The recorder substitutes the packaged loader and records the exact exec input.
It does not prove a real loader/backend, account continuity, or stage-tier argv0.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import resource
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import portable
import portable_launcher_template as trusted

_MACHINES = {"x86_64-linux": 62, "aarch64-linux": 183}
_SYSCALLS = {"x86_64-linux": (57, 58, 56, 435), "aarch64-linux": (220, 435)}
_AUDIT_ARCH = {"x86_64-linux": 0xC000003E, "aarch64-linux": 0xC00000B7}
_ROLES = {"omux.bin": 1, "omuxd.bin": 2, "omux-control.bin": 3}
_CHANNELS = {None: 0, "development": 1, "release": 2}
_LAUNCHER: Path
_RECORDER: Path
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.execve.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p),
                        ctypes.POINTER(ctypes.c_char_p))
_LIBC.execve.restype = ctypes.c_int


def expected_record(loader: str, backend: str, channel: str | None) -> bytes:
    # Independent encoder: expected bytes are not obtained from product code.
    record = bytearray(256)
    record[:16] = b"OMUXLNXLAUNCHv1\0"
    record[16:19] = bytes((1, _ROLES[backend], _CHANNELS[channel]))
    struct.pack_into("<H", record, 20, _MACHINES[trusted.TARGET])
    encoded = loader.encode("ascii")
    record[32:32 + len(encoded)] = encoded
    return bytes(record)


class _Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(_Filter))]


def deny_children() -> None:
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, _AUDIT_ARCH[trusted.TARGET]),
                    (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in _SYSCALLS[trusted.TARGET]:
        instructions.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | errno.EPERM)])
    instructions.append((0x06, 0, 0, 0x7FFF0000))
    filters = (_Filter * len(instructions))(*(_Filter(*item) for item in instructions))
    program = _Program(len(filters), filters)
    if _LIBC.prctl(38, 1, 0, 0, 0) != 0 or _LIBC.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "owned seccomp setup failed")


def unhex(values: list[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in values]


class LauncherExecutionTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="omux-launcher-fixture-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.root = self.base / "installation with space"
        self.cwd = self.base / "caller-cwd"
        self.cwd.mkdir()
        st = self.cwd.stat()
        self.cwd_identity = [st.st_dev, st.st_ino]
        self.loader = "fixture-loader"
        self.install()

    def install(self, backend: str = "omux.bin", channel: str | None = None,
                alias: str = "omux") -> Path:
        runtime = self.root / ("lib/omux/qt" if backend == "omux-control.bin" else "lib/omux")
        for directory in (self.root / "bin", runtime / "lib", runtime / "libexec"):
            directory.mkdir(parents=True, exist_ok=True)
        loader = runtime / "lib" / self.loader
        loader.write_bytes(_RECORDER.read_bytes())
        loader.chmod(0o755)
        (runtime / "libexec" / backend).write_bytes(b"owned recorder-only backend sentinel\n")
        path = self.root / "bin" / alias
        path.write_bytes(portable.linux_launcher(self.loader, backend, channel, target=trusted.TARGET))
        path.chmod(0o755)
        return path

    def run_launcher(self, *, alias: str = "omux", argv: tuple[bytes, ...] = (b"custom argv0",),
                     environ: tuple[bytes, ...] = (), close_std: tuple[int, ...] = (),
                     cwd_action: str | None = None, deny: bool = False,
                     stdout_marker: bool = False, stderr_marker: bool = False,
                     exit_code: int = 0, stack_limit: tuple[int, int] | None = None,
                     broken_stderr: bool = False) -> tuple[subprocess.CompletedProcess, dict | None, dict]:
        path = self.root / "bin" / alias
        with tempfile.TemporaryFile() as report, tempfile.TemporaryFile() as extra:
            extra.write(b"owned-extra-stream")
            extra.flush()
            extra.seek(4)
            fcntl.fcntl(extra.fileno(), fcntl.F_SETFL,
                        fcntl.fcntl(extra.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK | os.O_APPEND)
            extra_st = os.fstat(extra.fileno())
            expected = {"extra": {"dev": extra_st.st_dev, "ino": extra_st.st_ino,
                                  "fdflags": 0, "statusflags": fcntl.fcntl(extra.fileno(), fcntl.F_GETFL)},
                        "fds": {report.fileno(), extra.fileno()} | (set(range(3)) - set(close_std))}
            limits = stack_limit if stack_limit is not None else resource.getrlimit(resource.RLIMIT_STACK)
            expected["stack"] = [limit & ((1 << 64) - 1) for limit in limits]
            stderr_target = subprocess.PIPE
            if broken_stderr:
                read_fd, stderr_target = os.pipe()
                os.close(read_fd)
                self.addCleanup(os.close, stderr_target)
            raw_env = (b"LC_ALL=C", b"OMUX_TEST_REPORT_FD=" + str(report.fileno()).encode(),
                       b"OMUX_TEST_EXTRA_FD=" + str(extra.fileno()).encode(),
                       b"OMUX_TEST_EXIT=" + str(exit_code).encode()) + environ
            if deny:
                raw_env += (b"OMUX_TEST_DENY=1",)
            if stdout_marker:
                raw_env += (b"OMUX_TEST_STDOUT=1",)
            if stderr_marker:
                raw_env += (b"OMUX_TEST_STDERR=1",)
            expected["raw_env"] = list(raw_env)
            arg_array = (ctypes.c_char_p * (len(argv) + 1))(*argv, None)
            env_array = (ctypes.c_char_p * (len(raw_env) + 1))(*raw_env, None)

            def prepare_and_exec() -> None:
                os.chdir(self.cwd)
                if stack_limit is not None:
                    resource.setrlimit(resource.RLIMIT_STACK, stack_limit)
                if cwd_action == "rename":
                    os.rename(self.cwd, self.base / "renamed-caller-cwd")
                elif cwd_action == "delete":
                    os.rmdir(self.cwd)
                if deny:
                    deny_children()
                for fd in close_std:
                    os.close(fd)
                _LIBC.execve(os.fsencode(path), arg_array, env_array)
                raise OSError(ctypes.get_errno(), "owned launcher exec failed")

            process = subprocess.Popen([os.fsencode(path)], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=stderr_target,
                                       pass_fds=(report.fileno(), extra.fileno()),
                                       preexec_fn=prepare_and_exec, env={"LC_ALL": "C"})
            self.addCleanup(lambda: process.poll() is None and process.kill())
            expected["pid"] = process.pid
            for fd, stream in enumerate((process.stdin, process.stdout, process.stderr)):
                stream_fd = stream.fileno() if stream is not None else stderr_target
                st = os.fstat(stream_fd)
                flags = fcntl.fcntl(stream_fd, fcntl.F_GETFL)
                mode = os.O_RDONLY if fd == 0 else os.O_WRONLY
                expected[fd] = {"dev": st.st_dev, "ino": st.st_ino,
                                "statusflags": (flags & ~os.O_ACCMODE) | mode}
            try:
                stdout, stderr = process.communicate(b"owned-input\n", timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("owned launcher fixture did not complete")
            report.seek(0)
            payload = report.read()
            record = json.loads(payload) if payload else None
            result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
            return result, record, expected

    def assert_success(self, result: subprocess.CompletedProcess, record: dict | None,
                       expected: dict, *, close_std: tuple[int, ...] = ()) -> None:
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertIsNotNone(record)
        self.assertEqual(record["pid"], expected["pid"])
        self.assertEqual(record["cwd"], self.cwd_identity)
        self.assertEqual(record["stack"], expected["stack"])
        self.assertEqual(set(record["openFds"]), expected["fds"])
        self.assertEqual(record["fds"]["extra"], expected["extra"])
        self.assertEqual(record["extraOffset"], 4)
        for fd in range(3):
            actual = record["fds"][str(fd)]
            if fd in close_std:
                self.assertEqual(actual, {"closed": errno.EBADF})
            else:
                self.assertEqual({key: actual[key] for key in ("dev", "ino", "statusflags")}, expected[fd])
                self.assertEqual(actual["fdflags"], 0)

    def test_declared_compiled_fixture_is_exact_trusted_static_elf(self) -> None:
        self.assertEqual(trusted.ABI, 1)
        self.assertEqual(_LAUNCHER.read_bytes(), trusted.TEMPLATE)
        self.assertEqual(hashlib.sha256(trusted.TEMPLATE).hexdigest(), trusted.SHA256)
        metadata = portable.elf_metadata(trusted.TEMPLATE)
        self.assertEqual(metadata, {"needed": [], "rpath": [], "interpreter": None,
                                    "machine": _MACHINES[trusted.TARGET]})
        phoff = struct.unpack_from("<Q", trusted.TEMPLATE, 32)[0]
        phsize, phnum = struct.unpack_from("<HH", trusted.TEMPLATE, 54)
        stacks = []
        for index in range(phnum):
            ptype, flags, _, _, _, filesz, memsz, _ = struct.unpack_from(
                "<IIQQQQQQ", trusted.TEMPLATE, phoff + index * phsize)
            self.assertNotIn(ptype, (2, 3))
            if ptype == 0x6474E551:
                stacks.append((flags, filesz, memsz))
        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0][0] & 1, 0)
        self.assertEqual(stacks[0][1:], (0, 0))
        self.assertEqual((self.root / "bin/omux").read_bytes(),
                         trusted.TEMPLATE + expected_record(self.loader, "omux.bin", None))

    def test_fresh_isolated_python_imports_declared_sibling_template(self) -> None:
        # This is the same virtual runfiles directory used by private-bus
        # fixture bootstraps. No outer-process sys.modules preload survives.
        script = Path(__file__).absolute()
        bootstrap = ("import hashlib,os,sys; p=sys.argv.pop(1); "
                     "sys.path.insert(0,os.path.dirname(p)); "
                     "import portable,portable_launcher_template as t; "
                     "assert t.SHA256 == sys.argv[1]; "
                     "assert hashlib.sha256(t.TEMPLATE).hexdigest() == t.SHA256; "
                     "assert os.path.dirname(os.path.abspath(t.__file__)) == os.path.dirname(p); "
                     "assert portable.linux_launcher('fixture-loader','omux.bin').startswith(t.TEMPLATE)")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap, str(script), trusted.SHA256],
                                cwd=self.cwd, env={"LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_pid_cwd_arguments_streams_and_extra_fd_survive_without_child_creation(self) -> None:
        argv = (b"invented/custom argv0", b"", b"two words", b"line1\nline2", b"raw-\xff")
        result, record, expected = self.run_launcher(argv=argv, deny=True, stdout_marker=True)
        self.assert_success(result, record, expected)
        self.assertEqual(result.stdout, b"fixture-stdout\n")
        self.assertEqual(bytes.fromhex(record["stdin"]), b"owned-input\n")
        self.assertEqual(record["denied"], [errno.EPERM] * len(_SYSCALLS[trusted.TARGET]))
        runtime = os.fsencode(self.root / "lib/omux")
        self.assertEqual(unhex(record["argv"]), [runtime + b"/lib/" + self.loader.encode(),
                         b"--inhibit-cache", b"--library-path", runtime + b"/lib", b"--argv0",
                         argv[0], runtime + b"/libexec/omux.bin", *argv[1:]])

    def test_inherited_stack_limit_is_preserved(self) -> None:
        current_soft, current_hard = resource.getrlimit(resource.RLIMIT_STACK)
        soft = 2 * 1024 * 1024
        if current_soft != resource.RLIM_INFINITY:
            soft = min(soft, current_soft)
        result, record, expected = self.run_launcher(stack_limit=(soft, current_hard), deny=True)
        self.assert_success(result, record, expected)
        self.assertEqual(result.stdout, b"")

    def test_cli_aliases_preserve_raw_original_argv0_and_backend(self) -> None:
        for alias, original in (("oauth-mux", b""), ("omux-native-host", b"line1\nline2"),
                                ("git-credential-omux", b"other/custom/argv0")):
            with self.subTest(alias=alias):
                self.install(alias=alias)
                result, record, expected = self.run_launcher(alias=alias, argv=(original,), deny=True)
                self.assert_success(result, record, expected)
                self.assertEqual(unhex(record["argv"])[5:7],
                                 [original, os.fsencode(self.root / "lib/omux/libexec/omux.bin")])
                self.assertEqual(result.stdout, b"")

    def test_actual_renamed_and_deleted_cwd_identity_is_preserved(self) -> None:
        for action in ("rename", "delete"):
            with self.subTest(action=action):
                if not self.cwd.exists():
                    self.cwd.mkdir()
                st = self.cwd.stat()
                self.cwd_identity = [st.st_dev, st.st_ino]
                result, record, expected = self.run_launcher(cwd_action=action, deny=True)
                self.assert_success(result, record, expected)
                self.assertEqual(result.stdout, b"")

    def test_closed_standard_descriptors_remain_closed(self) -> None:
        for closed in ((0,), (1,), (2,), (0, 1, 2)):
            with self.subTest(closed=closed):
                result, record, expected = self.run_launcher(close_std=closed, deny=True)
                self.assert_success(result, record, expected, close_std=closed)
                self.assertEqual(bytes.fromhex(record["stdin"]), b"" if 0 in closed else b"owned-input\n")
                self.assertEqual(result.stdout, b"")

    def test_environment_scrubs_all_loader_entries_and_preserves_raw_order_duplicates(self) -> None:
        untouched = (b"SYNTHETIC_DUP=first", b"SYNTHETIC_DUP=second", b"RAW_BYTES=\xff\n",
                     b"PWD=/synthetic/wrong-cwd", b"CDPATH=/synthetic/wrong-root",
                     b"LD_DEBUG=", b"QT_PLUGIN_PATH=caller-qt", b"NO_EQUALS")
        replaced = (b"LD_PRELOAD=/synthetic/untrusted.so", b"LD_AUDIT=/synthetic/audit.so",
                    b"LD_LIBRARY_PATH=/synthetic/lib", b"LD_PRELOAD=another.so",
                    b"LD_AUDIT=", b"LD_LIBRARY_PATH=", b"OMUX_INSTALL_PREFIX=old",
                    b"OMUX_INSTALL_PREFIX=other", b"OMUX_CA_BUNDLE=old-ca", b"OMUX_CA_BUNDLE=")
        incoming = replaced[:2] + untouched[:2] + replaced[2:] + untouched[2:]
        result, record, expected = self.run_launcher(environ=incoming, deny=True)
        self.assert_success(result, record, expected)
        env = unhex(record["environ"])
        self.assertEqual([item for item in env if item in untouched], list(untouched))
        for key in (b"LD_PRELOAD", b"LD_AUDIT", b"LD_LIBRARY_PATH"):
            self.assertFalse(any(item.startswith(key + b"=") for item in env))
        prefix = b"OMUX_INSTALL_PREFIX=" + os.fsencode(self.root)
        ca = b"OMUX_CA_BUNDLE=" + os.fsencode(self.root / "lib/omux/share/ca-bundle.crt")
        self.assertEqual([item for item in env if item.startswith(b"OMUX_INSTALL_PREFIX=")], [prefix])
        self.assertEqual([item for item in env if item.startswith(b"OMUX_CA_BUNDLE=")], [ca])
        self.assertEqual(env[-2:], [prefix, ca])
        self.assertEqual(env, [item for item in expected["raw_env"] if item not in replaced] + [prefix, ca])

    def test_relocation_ignores_argv0_pwd_and_cdpath(self) -> None:
        original = self.root
        self.root = self.base / "relocated installation\nwith-tab\t"
        original.rename(self.root)
        result, record, expected = self.run_launcher(argv=(b"/synthetic/other/bin/omux",),
                                                    environ=(b"PWD=/synthetic", b"CDPATH=/synthetic"), deny=True)
        self.assert_success(result, record, expected)
        env = unhex(record["environ"])
        self.assertIn(b"OMUX_INSTALL_PREFIX=" + os.fsencode(self.root), env)
        self.assertIn(b"OMUX_CA_BUNDLE=" + os.fsencode(self.root / "lib/omux/share/ca-bundle.crt"), env)
        self.assertNotIn(os.fsencode(original), b"\0".join(unhex(record["argv"]) + env))

    def test_qt_namespace_and_only_qt_overrides(self) -> None:
        qt_env = (b"QT_PLUGIN_PATH=old", b"QT_PLUGIN_PATH=duplicate",
                  b"QT_QPA_PLATFORM_PLUGIN_PATH=old-platform", b"QT_QPA_PLATFORM_PLUGIN_PATH=")
        self.install("omux-control.bin", alias="omux-control")
        result, record, expected = self.run_launcher(alias="omux-control", environ=qt_env, deny=True)
        self.assert_success(result, record, expected)
        runtime = os.fsencode(self.root / "lib/omux/qt")
        argv = unhex(record["argv"])
        self.assertEqual(argv[3], runtime + b"/lib")
        self.assertEqual(argv[6], runtime + b"/libexec/omux-control.bin")
        env = unhex(record["environ"])
        self.assertEqual([item for item in env if item.startswith(b"QT_PLUGIN_PATH=")],
                         [b"QT_PLUGIN_PATH=" + runtime + b"/plugins"])
        self.assertEqual([item for item in env if item.startswith(b"QT_QPA_PLATFORM_PLUGIN_PATH=")],
                         [b"QT_QPA_PLATFORM_PLUGIN_PATH=" + runtime + b"/plugins/platforms"])
        self.assertIn(b"OMUX_CA_BUNDLE=" + os.fsencode(self.root / "lib/omux/share/ca-bundle.crt"), env)
        for backend, alias in (("omux.bin", "omux"), ("omuxd.bin", "omuxd")):
            self.install(backend, alias=alias)
            result, record, expected = self.run_launcher(alias=alias, environ=qt_env, deny=True)
            self.assert_success(result, record, expected)
            self.assertEqual([item for item in unhex(record["environ"]) if item.startswith(b"QT_")], list(qt_env))

    def test_bound_channel_presence_duplicates_conflict_empty_and_unbound(self) -> None:
        for channel, bound in (("development", b"dev"), ("release", b"default")):
            self.install(channel=channel)
            for incoming in ((), (b"OMUX_INSTANCE=" + bound,), (b"OMUX_INSTANCE=" + bound,) * 2):
                with self.subTest(channel=channel, incoming=incoming):
                    result, record, expected = self.run_launcher(environ=incoming, deny=True)
                    self.assert_success(result, record, expected)
                    self.assertEqual([item for item in unhex(record["environ"]) if item.startswith(b"OMUX_INSTANCE=")],
                                     [b"OMUX_INSTANCE=" + bound])
            for incoming in ((b"OMUX_INSTANCE=",), (b"OMUX_INSTANCE=conflict",),
                             (b"OMUX_INSTANCE=" + bound, b"OMUX_INSTANCE=conflict"),
                             (b"OMUX_INSTANCE=", b"OMUX_INSTANCE=" + bound)):
                result, record, _ = self.run_launcher(environ=incoming, deny=True)
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"Omux portable launcher refused\n")
                self.assertIsNone(record)
        self.install()
        incoming = (b"OMUX_INSTANCE=", b"OMUX_INSTANCE=synthetic")
        result, record, expected = self.run_launcher(environ=incoming, deny=True)
        self.assert_success(result, record, expected)
        self.assertEqual([item for item in unhex(record["environ"]) if item.startswith(b"OMUX_INSTANCE=")], list(incoming))

    def test_backend_completion_status_and_inherited_stderr(self) -> None:
        result, record, expected = self.run_launcher(exit_code=23, stderr_marker=True, deny=True)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"fixture-stderr\n")
        self.assertEqual(record["pid"], expected["pid"])
        result, record, expected = self.run_launcher(deny=True)
        self.assert_success(result, record, expected)
        self.assertEqual(result.stdout, b"")

    def test_refusal_keeps_status_with_broken_stderr_pipe(self) -> None:
        path = self.root / "bin/omux"
        path.write_bytes(path.read_bytes()[:-1])
        result, record, _ = self.run_launcher(broken_stderr=True, deny=True)
        self.assertEqual(result.returncode, 126)
        self.assertEqual(result.stdout, b"")
        self.assertIsNone(result.stderr)
        self.assertIsNone(record)
        self.install(channel="development")
        result, record, _ = self.run_launcher(environ=(b"OMUX_INSTANCE=conflict",), broken_stderr=True, deny=True)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, b"")
        self.assertIsNone(result.stderr)
        self.assertIsNone(record)

    def test_malformed_trailers_fail_before_loader_exec(self) -> None:
        path = self.root / "bin/omux"
        good = path.read_bytes()
        record = good[-256:]
        changes = {"magic": (0, 0xFF), "version": (16, 2), "role": (17, 255), "role-mismatch": (17, 2),
                   "channel": (18, 255), "reserved19": (19, 1), "machine": (20, 0),
                   "reserved22": (22, 1), "loader-slash": (32, ord('/')),
                   "loader-padding": (32 + len(self.loader) + 1, 1), "reserved161": (161, 1)}
        cases = {}
        for name, (offset, value) in changes.items():
            malformed = bytearray(record)
            malformed[offset] = value
            cases[name] = good[:-256] + malformed
        cases["unterminated-loader"] = good[:-256] + record[:32] + b"x" * 129 + record[161:]
        cases["empty-loader"] = good[:-256] + record[:32] + bytes(129) + record[161:]
        cases["truncated"] = good[:-1]
        cases["extra-tail"] = good + b"unexpected"
        for name, payload in cases.items():
            with self.subTest(case=name):
                path.write_bytes(payload)
                result, actual, _ = self.run_launcher(deny=True)
                self.assertEqual(result.returncode, 126)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"Omux portable launcher refused\n")
                self.assertIsNone(actual)
        path.write_bytes(good)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--recorder", type=Path, required=True)
    options, remaining = parser.parse_known_args()
    _LAUNCHER, _RECORDER = options.launcher.resolve(), options.recorder.resolve()
    if trusted.TARGET not in _MACHINES or sys.platform != "linux":
        parser.error("declared native Linux launcher fixture required")
    unittest.main(argv=[sys.argv[0], *remaining])
