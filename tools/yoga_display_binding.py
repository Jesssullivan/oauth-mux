"""Private fixed Wayland socket witnesses; never signal a compositor.

Capture source before mounting. Reinspect source in the supervisor namespace
and destination inside the admitted mount namespace; compare both snapshots.
Witnesses contain private endpoint/PID data and must never enter public logs.
"""
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

REASONS = frozenset(("selector_invalid", "parent_invalid", "socket_invalid", "peer_invalid",
                     "pid_invalid", "endpoint_changed", "binding_invalid", "deadline_exceeded"))
SNAPSHOT = frozenset(("device", "inode", "uid", "mode", "pid", "start_ticks"))


class BindingError(ValueError):
    def __init__(self, reason):
        super().__init__(reason if reason in REASONS else "binding_invalid")


def require(value, reason):
    if not value:
        raise BindingError(reason)


def budget(deadline_ns, now=time.monotonic_ns):
    require(type(deadline_ns) is int, "deadline_exceeded")
    left = deadline_ns - now()
    require(0 < left <= 1200 * 10**9, "deadline_exceeded")
    return min(1.0, left / 10**9)


def selectors(source, destination, proof_root, uid):
    require(type(uid) is int and uid > 0, "selector_invalid")
    require(type(source) is str and re.fullmatch(r"/run/user/" + str(uid) + r"/wayland-[0-9]{1,3}", source), "selector_invalid")
    require(type(proof_root) is str and re.fullmatch(r"/srv/[A-Za-z0-9._/-]{1,180}", proof_root)
            and str(Path(proof_root)) == proof_root and not {".", ".."}.intersection(proof_root.split("/")), "selector_invalid")
    require(destination == proof_root + "/wayland.sock" and len(os.fsencode(destination)) <= 107, "selector_invalid")


def parent_descriptor(path, uid):
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        root = os.fstat(descriptor)
        require(root.st_uid == 0 and not stat.S_IMODE(root.st_mode) & 0o022, "parent_invalid")
        for part in Path(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                require(info.st_uid in (0, uid) and not stat.S_IMODE(info.st_mode) & 0o022, "parent_invalid")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, "parent_invalid")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def pid_start(pid, uid):
    require(type(pid) is int and pid > 1, "pid_invalid")
    descriptor = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(os.fstat(descriptor).st_uid == uid, "pid_invalid")
        source = os.open("stat", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            data = os.read(source, 8193)
        finally:
            os.close(source)
        require(len(data) <= 8192, "pid_invalid")
        fields = data.decode("ascii").rsplit(") ", 1)[1].split()
        require(data.split(b" (", 1)[0] == str(pid).encode("ascii")
                and fields[0] in ("R", "S", "D", "T", "t", "W", "K", "P", "I")
                and fields[19].isdecimal(), "pid_invalid")
        ticks = int(fields[19])
        require(ticks > 0, "pid_invalid")
        return ticks
    finally:
        os.close(descriptor)


def inspect_endpoint(path, uid, deadline_ns):
    descriptor = None
    try:
        timeout = budget(deadline_ns)
        require(type(path) is str and path.startswith("/") and str(Path(path)) == path
                and not {".", ".."}.intersection(path.split("/"))
                and len(os.fsencode(path)) <= 107 and type(uid) is int and uid > 0, "selector_invalid")
        endpoint = Path(path)
        descriptor = parent_descriptor(str(endpoint.parent), uid)
        before = os.stat(endpoint.name, dir_fd=descriptor, follow_symlinks=False)
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid == uid
                and stat.S_IMODE(before.st_mode) & 0o200
                and not stat.S_IMODE(before.st_mode) & 0o022, "socket_invalid")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(f"/proc/self/fd/{descriptor}/{endpoint.name}")
            pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer_uid == uid, "peer_invalid")
            ticks = pid_start(pid, uid)
        after = os.stat(endpoint.name, dir_fd=descriptor, follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_uid, before.st_mode) ==
                (after.st_dev, after.st_ino, after.st_uid, after.st_mode), "endpoint_changed")
        require(pid_start(pid, uid) == ticks, "pid_invalid")
        # A held directory pins the read, but must also remain the directory
        # named by the selected absolute path. Refuse ancestor substitution.
        named_parent = parent_descriptor(str(endpoint.parent), uid)
        try:
            held, named = os.fstat(descriptor), os.fstat(named_parent)
            require((held.st_dev, held.st_ino, held.st_uid, held.st_mode) ==
                    (named.st_dev, named.st_ino, named.st_uid, named.st_mode), "endpoint_changed")
            named_socket = os.stat(endpoint.name, dir_fd=named_parent, follow_symlinks=False)
            require((after.st_dev, after.st_ino, after.st_uid, after.st_mode) ==
                    (named_socket.st_dev, named_socket.st_ino, named_socket.st_uid, named_socket.st_mode),
                    "endpoint_changed")
        finally:
            os.close(named_parent)
        budget(deadline_ns)
        return {"device": before.st_dev, "inode": before.st_ino, "uid": uid,
                "mode": stat.S_IMODE(before.st_mode), "pid": pid, "start_ticks": ticks}
    except BindingError:
        raise
    except (OSError, ValueError, IndexError, UnicodeError):
        raise BindingError("binding_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def valid_snapshot(value, uid):
    require(type(value) is dict and set(value) == SNAPSHOT
            and all(type(item) is int for item in value.values())
            and all(value[key] > 0 for key in ("device", "inode", "pid", "start_ticks"))
            and value["pid"] > 1 and value["uid"] == uid and 0 <= value["mode"] <= 0o777
            and value["mode"] & 0o200
            and not value["mode"] & 0o022, "binding_invalid")


def capture(source, destination, proof_root, uid, deadline_ns, inspect=inspect_endpoint, now=time.monotonic_ns):
    selectors(source, destination, proof_root, uid)
    budget(deadline_ns, now)
    snapshot = inspect(source, uid, deadline_ns)
    valid_snapshot(snapshot, uid)
    return {"source": source, "destination": destination, "proof_root": proof_root,
            "uid": uid, "deadline_ns": deadline_ns, "snapshot": snapshot}


def verify_binding(witness, source_snapshot, destination_snapshot, effective_binds, now=time.monotonic_ns):
    require(type(witness) is dict and set(witness) == {"source", "destination", "proof_root", "uid", "deadline_ns", "snapshot"}, "binding_invalid")
    selectors(witness["source"], witness["destination"], witness["proof_root"], witness["uid"])
    budget(witness["deadline_ns"], now)
    for snapshot in (witness["snapshot"], source_snapshot, destination_snapshot):
        valid_snapshot(snapshot, witness["uid"])
    require(effective_binds == [witness["source"] + ":" + witness["destination"]], "binding_invalid")
    require(source_snapshot == witness["snapshot"] == destination_snapshot, "endpoint_changed")
    return {"adapter": "qualified-wayland-unix", "socketPath": witness["destination"],
            "socketDevice": destination_snapshot["device"], "socketInode": destination_snapshot["inode"],
            "serverPid": destination_snapshot["pid"]}


def reinspect_source(witness, inspect=inspect_endpoint, now=time.monotonic_ns):
    """Fresh supervisor-side observation; never follow the masked destination."""
    require(type(witness) is dict and set(witness) == {"source", "destination", "proof_root", "uid", "deadline_ns", "snapshot"}, "binding_invalid")
    selectors(witness["source"], witness["destination"], witness["proof_root"], witness["uid"])
    budget(witness["deadline_ns"], now)
    valid_snapshot(witness["snapshot"], witness["uid"])
    observed = inspect(witness["source"], witness["uid"], witness["deadline_ns"])
    valid_snapshot(observed, witness["uid"])
    require(observed == witness["snapshot"], "endpoint_changed")
    budget(witness["deadline_ns"], now)
    return dict(observed)


def verify_readonly_binding(witness, source_snapshot, destination_snapshot,
                            effective_readonly_binds, effective_writable_binds, now=time.monotonic_ns):
    """Use measured BindReadOnlyPaths and BindPaths, not requested properties.

    Source observation belongs to the supervisor; destination observation must
    be made inside the held worker's admitted mount namespace. The legacy
    display result stays small; the full PID/start-tick witness stays private.
    """
    require(type(effective_readonly_binds) is list and effective_writable_binds == [], "binding_invalid")
    return verify_binding(witness, source_snapshot, destination_snapshot, effective_readonly_binds, now)


class EndpointPin:
    """Supervisor-held inode custody, independent of serialized witnesses.

    O_PATH holds the original source socket inode across publication changes;
    it cannot read protocol data or signal the compositor. Keep this object
    until aggregate cleanup. A worker receives witness data, never this FD.
    """
    def __init__(self, descriptor):
        self.descriptor = descriptor

    def close(self):
        if self.descriptor is not None:
            descriptor, self.descriptor = self.descriptor, None
            os.close(descriptor)

    def check(self, witness, inspect=inspect_endpoint, now=time.monotonic_ns):
        require(self.descriptor is not None, "binding_invalid")
        observed = reinspect_source(witness, inspect, now)
        held = os.fstat(self.descriptor)
        require(stat.S_ISSOCK(held.st_mode)
                and (held.st_dev, held.st_ino, held.st_uid, stat.S_IMODE(held.st_mode)) ==
                (observed["device"], observed["inode"], observed["uid"], observed["mode"]), "endpoint_changed")
        return observed


def capture_pinned(source, destination, proof_root, uid, deadline_ns,
                   inspect=inspect_endpoint, now=time.monotonic_ns):
    """Pin source before peer capture, before any proof-directory allocation."""
    selectors(source, destination, proof_root, uid)
    budget(deadline_ns, now)
    parent, descriptor, pin = None, None, None
    try:
        parent = parent_descriptor(str(Path(source).parent), uid)
        descriptor = os.open(Path(source).name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        pin = EndpointPin(descriptor)
        descriptor = None
        witness = capture(source, destination, proof_root, uid, deadline_ns, inspect, now)
        pin.check(witness, inspect, now)
        return witness, pin
    except BaseException:
        if pin is not None:
            pin.close()
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def diagnostic(error):
    return {"passed": False, "gate": str(error) if isinstance(error, BindingError) else "binding_invalid"}
