"""Read-only byte qualification for the eleven explicitly selected Yoga inputs.

The sole guard must first qualify local seat and pinned registered runtime
authority, then resolve its declared runfiles aliases to physical input paths.
This module does not discover paths, resolve aliases, evaluate Nix, establish
package provenance or allocate proof/cache state. Reuse check_inputs before
allocation, before go, and after go; returned hashes are selection facts, not
an atomic executable witness or a browser/product claim.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import time

INPUTS = frozenset(("bundle", "extension", "chromium", "node", "observer", "dbus_session",
                    "dbus_daemon", "keyring", "runtime_authority", "recorder", "recorder_implementation"))
SHA = re.compile(r"[0-9a-f]{64}")
STORE = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}/[A-Za-z0-9+._?=@/-]{1,3800}")
# Recorder and implementation are source data, copied beside an explicitly
# selected interpreter by the runner; their declared bytes need no exec bit.
EXECUTABLES = frozenset(("chromium", "node", "dbus_session", "dbus_daemon", "keyring"))
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
REASONS = frozenset(("input_selector_invalid", "input_unqualified", "input_digest_mismatch",
                     "input_changed", "input_byte_bound", "deadline_exceeded"))


class InputError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "input_unqualified"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise InputError(reason)


def budget(deadline_ns, now):
    require(type(deadline_ns) is int and 0 < deadline_ns - now() <= 1200 * 10**9, "deadline_exceeded")


def witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def valid_path(path):
    require(type(path) is str and 1 <= len(os.fsencode(path)) <= 4096
            and (STORE.fullmatch(path) or re.fullmatch(r"/srv/[A-Za-z0-9+._?=@/-]{1,4090}", path))
            and str(Path(path)) == path and not {".", ".."}.intersection(path.split("/")),
            "input_selector_invalid")


def open_parent(path, uid, deadline_ns, now):
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        root = os.fstat(descriptor)
        require(root.st_uid == 0 and not stat.S_IMODE(root.st_mode) & 0o022, "input_unqualified")
        walked = Path("/")
        for part in Path(path).parts[1:-1]:
            budget(deadline_ns, now)
            walked /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                info = os.fstat(child)
                mode = stat.S_IMODE(info.st_mode)
                if walked == Path("/nix/store"):
                    # Exact sticky publication directory only; never treat a
                    # package or another sticky ancestor as writable custody.
                    require(info.st_uid == 0 and (not mode & 0o022 or mode == 0o1775), "input_unqualified")
                elif walked.is_relative_to("/nix/store"):
                    require(info.st_uid == 0 and not mode & 0o222, "input_unqualified")
                else:
                    require(info.st_uid in (0, uid) and not mode & 0o022, "input_unqualified")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def check_inputs(paths, digests, deadline_ns, *, uid=None, now=time.monotonic_ns):
    """Return exact independently expected hashes after a capture-wide check.

    Each file and its parent remain held until every input is hashed. Reopen
    each named parent/file at the end, so an earlier input's in-place drift or
    ancestor replacement during a later read refuses the whole selection.
    """
    uid = os.getuid() if uid is None else uid
    require(type(uid) is int and uid > 0 and type(paths) is dict and set(paths) == INPUTS
            and type(digests) is dict and set(digests) == INPUTS
            and all(type(value) is str and SHA.fullmatch(value) for value in digests.values()),
            "input_selector_invalid")
    for path in paths.values():
        valid_path(path)
    budget(deadline_ns, now)
    held, checked, total = [], {}, 0
    try:
        for name in sorted(INPUTS):
            path = paths[name]
            budget(deadline_ns, now)
            parent = open_parent(path, uid, deadline_ns, now)
            descriptor = None
            try:
                descriptor = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                     dir_fd=parent)
                before = os.fstat(descriptor)
                require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, uid)
                        and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_nlink >= 1
                        and (name not in EXECUTABLES or stat.S_IMODE(before.st_mode) & 0o111), "input_unqualified")
                if Path(path).is_relative_to("/nix/store"):
                    require(before.st_uid == 0 and not stat.S_IMODE(before.st_mode) & 0o222, "input_unqualified")
                require(0 <= before.st_size <= MAX_FILE and total + before.st_size <= MAX_TOTAL, "input_byte_bound")
                captured = witness(before)
                parent_identity = directory_identity(os.fstat(parent))
                digest, length = hashlib.sha256(), 0
                while True:
                    budget(deadline_ns, now)
                    data = os.read(descriptor, min(1024 * 1024, MAX_FILE - length + 1))
                    if not data:
                        break
                    length += len(data)
                    require(length <= MAX_FILE and total + length <= MAX_TOTAL, "input_byte_bound")
                    digest.update(data)
                require(length == before.st_size and witness(os.fstat(descriptor)) == captured
                        and witness(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)) == captured,
                        "input_changed")
                require(digest.hexdigest() == digests[name], "input_digest_mismatch")
                checked[name] = digest.hexdigest()
                total += length
                held.append((path, parent, descriptor, parent_identity, captured))
                parent, descriptor = None, None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if parent is not None:
                    os.close(parent)
        for path, parent, descriptor, parent_identity, captured in held:
            budget(deadline_ns, now)
            require(directory_identity(os.fstat(parent)) == parent_identity and witness(os.fstat(descriptor)) == captured,
                    "input_changed")
            named_parent = open_parent(path, uid, deadline_ns, now)
            named_file = None
            try:
                require(directory_identity(os.fstat(named_parent)) == parent_identity, "input_changed")
                named_file = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                     dir_fd=named_parent)
                require(witness(os.fstat(named_file)) == captured and witness(os.stat(
                    Path(path).name, dir_fd=named_parent, follow_symlinks=False)) == captured, "input_changed")
            finally:
                if named_file is not None:
                    os.close(named_file)
                os.close(named_parent)
        budget(deadline_ns, now)
        return checked
    except OSError:
        raise InputError("input_unqualified") from None
    finally:
        for _, parent, descriptor, _, _ in held:
            os.close(descriptor)
            os.close(parent)


def diagnostic(error):
    return {"passed": False, "gate": error.reason if isinstance(error, InputError) else "input_unqualified"}
