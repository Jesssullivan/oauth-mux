"""Failure-only Threads metadata for exactly five fixture-owned processes.

No process selection, child waiting/signalling, scan, output/config/history read
or acceptance authority. A pidfd and held genuine-procfs directory pin the
created process; they do not prove its executable incarnation or native support.
Synchronous verified-procfs operations have cooperative deadline checks, not a
hard realtime cancellation guarantee. Run only through declared Bazel actions.
"""
from __future__ import annotations

import ctypes
import errno
import functools
import os
import platform
import select
import signal
import stat
import subprocess
import threading
import time

PREFIX = b"OMUX_NATIVE_THREADS_V1"
ROLES = ("self", "daemon", "keyring", "native-bootstrap", "native-resume")
STATES = ("observed", "not-created", "retired", "missing", "permission", "identity",
          "profile", "shape", "bound", "deadline", "os-other")
MAX_THREADS = 65536
MAX_STATUS = 16 * 1024
MAX_LINE = 256
MAX_RECORD = 128
SAMPLE_NS = 100_000_000
MAX_OWNED_FDS = 11  # proc root + five directories + four pidfds + one status
_KEYS = (b"Pid", b"PPid", b"Uid", b"NSpid", b"Threads")


class Unavailable(Exception):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason if reason in STATES[1:] else "os-other"


def _number(value, maximum, positive=False):
    if (not value or len(value) > 10 or not value.isdigit()
            or (len(value) > 1 and value[:1] == b"0")):
        raise Unavailable("shape")
    number = int(value)
    if number > maximum:
        raise Unavailable("bound")
    if positive and number == 0:
        raise Unavailable("shape")
    return number


class Projection:
    """Discard unknown field tails while retaining bounded numeric fields."""
    def __init__(self, sample_threads=True):
        self.keys = _KEYS if sample_threads else _KEYS[:-1]
        self.fields = {}
        self.prefix = bytearray()
        self.value = bytearray()
        self.key = None
        self.unknown = False
        self.total = 0
        self.terminated = True

    def feed(self, chunk):
        self.total += len(chunk)
        if self.total > MAX_STATUS:
            raise Unavailable("bound")
        for byte in chunk:
            self.terminated = byte == 10
            if byte == 10:
                if self.key is not None:
                    if self.key in self.fields:
                        raise Unavailable("shape")
                    self.fields[self.key] = bytes(self.value).strip(b" \t")
                self.prefix.clear()
                self.value.clear()
                self.key = None
                self.unknown = False
            elif self.key is not None:
                if len(self.value) >= MAX_LINE - len(self.key) - 1:
                    raise Unavailable("bound")
                self.value.append(byte)
            elif not self.unknown:
                if byte == 58:
                    key = bytes(self.prefix)
                    self.key = key if key in self.keys else None
                    self.unknown = self.key is None
                    self.prefix.clear()
                elif len(self.prefix) < 8:
                    self.prefix.append(byte)
                else:
                    self.unknown = True
                    self.prefix.clear()

    def finish(self):
        if b"NSpid" not in self.fields:
            raise Unavailable("profile")
        if not self.terminated or set(self.fields) != set(self.keys):
            raise Unavailable("shape")
        uids = self.fields[b"Uid"].split()
        if len(uids) != 4:
            raise Unavailable("shape")
        pid = _number(self.fields[b"Pid"], 2**31 - 1, True)
        namespaces = self.fields[b"NSpid"].split()
        try:
            if len(namespaces) != 1 or _number(namespaces[0], 2**31 - 1, True) != pid:
                raise Unavailable("profile")
        except Unavailable:
            raise Unavailable("profile") from None
        return (
            pid,
            _number(self.fields[b"PPid"], 2**31 - 1),
            tuple(_number(value, 2**32 - 1) for value in uids),
            _number(self.fields[b"Threads"], MAX_THREADS, True) if b"Threads" in self.keys else None,
        )

    def clear(self):
        self.prefix.clear()
        self.value.clear()
        self.fields.clear()


def parse_status(payload):
    projection = Projection()
    try:
        projection.feed(payload)
        return projection.finish()
    finally:
        projection.clear()


def record(role, state, count=None):
    if role not in ROLES or state not in STATES:
        raise ValueError("thread census record rejected")
    if state == "observed":
        if type(count) is not int or not 1 <= count <= MAX_THREADS:
            raise ValueError("thread census record rejected")
        value = str(count)
    else:
        if count is not None:
            raise ValueError("thread census record rejected")
        value = "none"
    return PREFIX + b"/failure-before-cleanup/" + f"{role}/{state}/{value}\n".encode("ascii")


def parse_record(payload):
    if (type(payload) is not bytes or len(payload) > MAX_RECORD
            or not payload.endswith(b"\n") or payload.count(b"\n") != 1):
        raise ValueError("thread census record rejected")
    parts = payload[:-1].split(b"/")
    if len(parts) != 5 or parts[:2] != [PREFIX, b"failure-before-cleanup"]:
        raise ValueError("thread census record rejected")
    try:
        role, state = (value.decode("ascii") for value in parts[2:4])
        count = _number(parts[4], MAX_THREADS, True) if state == "observed" else None
        if record(role, state, count) != payload:
            raise ValueError("thread census record rejected")
    except (UnicodeError, Unavailable):
        raise ValueError("thread census record rejected") from None
    return payload


# The declared x86_64 Linux profile has a 120-byte kernel statfs
# structure. ctypes calls the already-loaded interpreter libc; no tool lookup.
class _Statfs(ctypes.Structure):
    _fields_ = [("words", ctypes.c_long * 15)]


def _procfs(fd):
    if (sys_platform() != "linux" or platform.machine() != "x86_64"
            or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(_Statfs) != 120):
        raise Unavailable("profile")
    library = ctypes.CDLL(None, use_errno=True)
    function = library.fstatfs
    function.argtypes = (ctypes.c_int, ctypes.POINTER(_Statfs))
    function.restype = ctypes.c_int
    value = _Statfs()
    if function(fd, ctypes.byref(value)) != 0 or value.words[0] != 0x9FA0:
        raise Unavailable("profile")


def sys_platform():
    import sys
    return sys.platform


def _reason(error):
    if isinstance(error, Unavailable):
        return error.reason
    if isinstance(error, OSError):
        return {errno.ENOENT: "missing", errno.ESRCH: "retired",
                errno.EACCES: "permission", errno.EPERM: "permission",
                errno.ELOOP: "identity", errno.ENOTDIR: "identity"}.get(error.errno, "os-other")
    return "profile"


class Census:
    """Enrollment is private to the immediate creating-Popen wrapper below."""
    def __init__(self, outer_deadline):
        self.creator = (os.getpid(), threading.get_ident())
        self.uid = os.getuid()
        self.outer_deadline = outer_deadline
        self.root = None
        self.entries = {}
        self.states = dict.fromkeys(ROLES, "not-created")
        self.fds = set()
        self.sampled = False
        self.pending_control = None
        try:
            deadline = self._budget()
            self._check(deadline)
            if (signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                    or not hasattr(os, "pidfd_open")):
                raise Unavailable("profile")
            self.root = self._open("/proc", directory=True, deadline=deadline)
            _procfs(self.root)
            self._check(deadline)
            # Self must resolve to our PID and status must have exactly one
            # matching NSpid. This refuses ancestor/ambiguous procfs namespace
            # views before any numeric child directory can be enrolled.
            if os.readlink("self", dir_fd=self.root) != str(self.creator[0]):
                raise Unavailable("profile")
            fd = self._open(str(self.creator[0]), directory=True, parent=self.root, deadline=deadline)
            information = self._status(fd, deadline, sample_threads=False)
            # Projection requires one matching NSpid, including this ownership
            # read (Threads remains discarded until a failed gate).
            if information[:3] != (self.creator[0], os.getppid(), (self.uid,) * 4):
                raise Unavailable("identity")
            self.entries["self"] = (fd, None, None, information[:3], self._witness(fd))
            self.states["self"] = "observed"
        except BaseException as error:
            self.defer_control(error)
            self.close()
            self.states["self"] = _reason(error)
            self.checkpoint()  # No child exists yet; constructor cancellation propagates.

    def defer_control(self, error):
        if isinstance(error, (KeyboardInterrupt, SystemExit)) and self.pending_control is None:
            self.pending_control = error

    def checkpoint(self):
        error = self.pending_control
        self.pending_control = None
        if error is not None:
            raise error

    def _budget(self):
        value = self.outer_deadline
        if type(value) is not int or not 1 <= value <= 2**63 - 1:
            raise Unavailable("deadline")
        return min(value, time.monotonic_ns() + SAMPLE_NS)

    def _check(self, deadline):
        if self.creator != (os.getpid(), threading.get_ident()):
            raise Unavailable("identity")
        if time.monotonic_ns() >= deadline:
            raise Unavailable("deadline")

    def _own(self, fd):
        if len(self.fds) >= MAX_OWNED_FDS:
            os.close(fd)
            raise Unavailable("bound")
        try:
            self.fds.add(fd)
        except BaseException:
            try:
                os.close(fd)
            finally:
                raise
        return fd

    def _close_fd(self, fd):
        if fd in self.fds:
            self.fds.remove(fd)
            try:
                os.close(fd)
            except BaseException as error:
                self.defer_control(error)  # Caller chooses a safe checkpoint.

    def _open(self, path, *, directory=False, parent=None, deadline):
        self._check(deadline)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        return self._own(os.open(path, flags, dir_fd=parent))

    @staticmethod
    def _witness(fd):
        value = os.fstat(fd)
        if not stat.S_ISDIR(value.st_mode):
            raise Unavailable("identity")
        return (value.st_dev, value.st_ino, value.st_uid)

    def _status(self, directory, deadline, *, sample_threads=True):
        self._check(deadline)
        fd = self._open("status", parent=directory, deadline=deadline)
        projection = None
        try:
            projection = Projection(sample_threads)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Unavailable("profile")
            _procfs(fd)
            while True:
                self._check(deadline)
                # Refuse saturation rather than read beyond the 16KiB budget
                # or infer EOF while an unseen duplicate field could follow.
                if projection.total >= MAX_STATUS:
                    raise Unavailable("bound")
                chunk = os.read(fd, min(1024, MAX_STATUS - projection.total))
                self._check(deadline)
                if not chunk:
                    return projection.finish()
                projection.feed(chunk)
        finally:
            if projection is not None:
                projection.clear()
            self._close_fd(fd)

    @staticmethod
    def _live(pidfd):
        # Zero-time readiness inspection, never child poll/wait/reap.
        return not select.select([pidfd], [], [], 0)[0]

    def _capture_created(self, role, process):
        before = set(self.fds)
        try:
            if role not in ROLES[1:]:
                raise Unavailable("identity")
            if self.states[role] != "not-created":
                self.retire(role)
                raise Unavailable("identity")
            deadline = self._budget()
            self._check(deadline)
            if (self.root is None or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                    or type(process.pid) is not int or process.pid <= 0):
                raise Unavailable("profile")
            if process.returncode is not None:
                raise Unavailable("retired")
            pidfd = self._own(os.pidfd_open(process.pid, 0))
            self._check(deadline)
            if os.get_inheritable(pidfd) or not self._live(pidfd):
                raise Unavailable("retired")
            directory = self._open(str(process.pid), directory=True, parent=self.root, deadline=deadline)
            _procfs(directory)
            information = self._status(directory, deadline, sample_threads=False)
            if information[:3] != (process.pid, self.creator[0], (self.uid,) * 4):
                raise Unavailable("identity")
            if not self._live(pidfd) or process.returncode is not None:
                raise Unavailable("retired")
            self.entries[role] = (directory, pidfd, process, information[:3], self._witness(directory))
            self.states[role] = "observed"
        except BaseException as error:
            self.defer_control(error)
            for fd in tuple(self.fds - before):
                self._close_fd(fd)
            if role in ROLES[1:]:
                self.states[role] = _reason(error)

    def retire(self, role):
        if role not in ROLES[1:]:
            return
        entry = self.entries.pop(role, None)
        if entry is not None:
            self._close_fd(entry[0])
            if entry[1] is not None:
                self._close_fd(entry[1])
        self.states[role] = "retired"

    def factory(self, role):
        return functools.partial(owned_popen, self, role)

    def failure_records(self):
        if self.sampled:
            return ()
        self.sampled = True
        try:
            deadline = self._budget()
            self._check(deadline)
        except BaseException:
            return tuple(record(role, "deadline") for role in ROLES)
        result = []
        for role in ROLES:
            state, count = self.states[role], None
            if role in self.entries:
                try:
                    self._check(deadline)
                    directory, pidfd, process, identity, witness = self.entries[role]
                    if process is not None and (process.returncode is not None or not self._live(pidfd)):
                        raise Unavailable("retired")
                    if self._witness(directory) != witness:
                        raise Unavailable("identity")
                    information = self._status(directory, deadline)
                    if information[:3] != identity:
                        raise Unavailable("identity")
                    if process is not None and (process.returncode is not None or not self._live(pidfd)):
                        raise Unavailable("retired")
                    state, count = "observed", information[3]
                except BaseException as error:
                    state = _reason(error)
            result.append(record(role, state, count))
        return tuple(result)

    def close(self):
        for fd in tuple(self.fds):
            try:
                self._close_fd(fd)
            except BaseException as error:
                self.defer_control(error)
        self.entries.clear()
        self.root = None


def owned_popen(census, role, *arguments, **options):
    """Create the original child once; capture never changes launch outcome."""
    process = subprocess.Popen(*arguments, **options)
    if census is not None:
        try:
            census._capture_created(role, process)
        except BaseException as error:
            # Return the created child before deferred cancellation is raised.
            try:
                census.defer_control(error)
                if role in ROLES[1:]:
                    census.retire(role)
                    census.states[role] = "profile"
            except BaseException:
                pass
    return process


def emit_failure(census, writer):
    if census is None:
        return
    try:
        for value in census.failure_records():
            writer(parse_record(value))
    except BaseException:
        pass


def factory(census, role):
    try:
        return census.factory(role) if census is not None else None
    except Exception:
        try:
            census.states[role] = "profile"
        except Exception:
            pass
        return None  # Native constructors retain their original Popen default.


def checkpoint(census):
    if census is not None:
        try:
            census.checkpoint()
        except Exception:
            pass


def retire(census, role):
    if census is not None:
        try:
            census.retire(role)
        except Exception:
            pass
        checkpoint(census)


def close(census, *, primary):
    if census is None:
        return
    try:
        census.close()
    except BaseException as error:
        if not primary and isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
    if not primary:
        checkpoint(census)
    else:
        census.pending_control = None  # Existing primary remains authoritative.
