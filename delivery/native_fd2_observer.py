"""Closed FD2 observation records; diagnostic image samples, never continuity."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
import time

PREFIX = b"OMUX_FD2_OBSERVER_V1"
ERROR_STAGES = ("launch-fork", "launch-table", "clock", "wait", "wait-kind",
                "fork-event", "fork-zero", "exec-event", "exec-table",
                "resume", "root-exit-missing")
ERROR_KINDS = ("none", "child", "task-gone", "permission", "argument", "io",
               "unsupported", "interrupted", "busy", "memory", "other")
ERROR_STATES = tuple("error-" + stage + "-" + kind
                     for stage in ERROR_STAGES for kind in ERROR_KINDS)
CHOICES = (
    ("observed", "no-write", "unavailable", "error", "cancelled", "deadline",
     "task-bound", "stop-bound", "cleanup-incomplete", *ERROR_STATES),
    ("writer-none", "writer-root-task", "writer-other-task"),
    ("image-none", "image-backend", "image-loader", "image-other", "image-unavailable"),
    ("sink-none", "sink-sampled-capture", "sink-sampled-other", "sink-unavailable"),
    ("call-none", "call-write", "call-writev"),
    ("origin-none", "origin-backend", "origin-loader", "origin-libc",
     "origin-other", "origin-unavailable"),
)
MAX_RECORD = 224


def parse_record(data):
    if (not isinstance(data, bytes) or len(data) > MAX_RECORD or not data.endswith(b"\n")
            or data.count(b"\n") != 1):
        raise ValueError("fd2-observer-record")
    parts = data[:-1].split(b"/")
    if len(parts) != 7 or parts[0] != PREFIX:
        raise ValueError("fd2-observer-record")
    for part, allowed in zip(parts[1:], CHOICES):
        if part not in tuple(value.encode("ascii") for value in allowed):
            raise ValueError("fd2-observer-record")
    state, writer, image, sink, call, origin = (part.decode("ascii") for part in parts[1:])
    if state == "no-write" and (writer, image, sink, call, origin) != (
            "writer-none", "image-none", "sink-none", "call-none", "origin-none"):
        raise ValueError("fd2-observer-record")
    if state == "observed" and (writer == "writer-none" or image == "image-none"
                               or sink == "sink-none" or call == "call-none" or origin == "origin-none"):
        raise ValueError("fd2-observer-record")
    return "/".join((state, writer, image, sink, call, origin))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Launch:
    """Hold exact bundle-selected installed role bytes before observer launch.

    Caller supplies the already verified portable bundle files and loader name.
    This is diagnostic file identity, not artifact lineage or native authority.
    The kernel image normally matches loader; origin-backend is a sampled map,
    and origin-libc can merely describe the syscall stub.
    """
    def __init__(self, observer, command, prefix, files, loader, deadline_ns):
        self.stack = ExitStack()
        self.read_fd = None
        self.roles = []
        self.deadline_ns = deadline_ns
        try:
            roles = ("lib/omux/libexec/omux.bin", loader, "lib/omux/lib/libc.so.6")
            held = []
            for role in roles:
                expected = files[role]
                if len(expected) > 536870912 or time.monotonic_ns() >= deadline_ns:
                    raise ValueError("fd2-observer-role")
                fd = os.open(Path(prefix) / role, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                self.stack.callback(os.close, fd)
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
                    raise ValueError("fd2-observer-role")
                actual = hashlib.sha256()
                remaining = len(expected)
                while remaining:
                    if time.monotonic_ns() >= deadline_ns:
                        raise ValueError("fd2-observer-deadline")
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        raise ValueError("fd2-observer-role")
                    actual.update(chunk)
                    remaining -= len(chunk)
                if (os.read(fd, 1) or actual.digest() != hashlib.sha256(expected).digest()
                        or identity(os.fstat(fd)) != identity(before)):
                    raise ValueError("fd2-observer-role")
                held.append(fd)
                self.roles.append((fd, identity(before), hashlib.sha256(expected).digest()))
            self.read_fd, report = os.pipe2(os.O_CLOEXEC)
            self.stack.callback(os.close, self.read_fd)
            self.stack.callback(self.close_report)
            self.report_fd = report
            self.pass_fds = (report, *held)
            end = min(deadline_ns, time.monotonic_ns() + 19 * 10**9)
            self.command = [str(observer), str(report), *(str(fd) for fd in held), str(end), "--", *command]
        except BaseException:
            self.stack.close()
            raise

    def recheck(self):
        for fd, original, expected in self.roles:
            info = os.fstat(fd)
            if identity(info) != original or time.monotonic_ns() >= self.deadline_ns:
                raise ValueError("fd2-observer-role-changed")
            os.lseek(fd, 0, os.SEEK_SET)
            actual = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                if time.monotonic_ns() >= self.deadline_ns:
                    raise ValueError("fd2-observer-role-changed")
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise ValueError("fd2-observer-role-changed")
                actual.update(chunk)
                remaining -= len(chunk)
            if (os.read(fd, 1) or actual.digest() != expected
                    or identity(os.fstat(fd)) != original):
                raise ValueError("fd2-observer-role-changed")

    def child_started(self):
        # Close the parent's writer immediately; observer owns the sole record
        # producer and child closes it before exec. Detach callback safely.
        self.close_report()

    def close_report(self):
        report = getattr(self, "report_fd", None)
        if report is not None:
            self.report_fd = None
            os.close(report)

    def close(self):
        self.stack.close()
