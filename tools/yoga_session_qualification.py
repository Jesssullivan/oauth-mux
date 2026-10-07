"""Produce the guard's private local Yoga selection from bounded live facts.

This operator-local producer never realizes tools, launches a unit/browser,
mounts a display, requests permissions, or grants execution authority. Expected
source/artifact hashes come from an independently SHA-selected private input.
The guard reobserves these facts and qualifies effective containment separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time

import guard_yoga_profile as guard
import yoga_display_binding as display
import yoga_proof_inputs as inputs

MAX_SELECTION = 65536
MAX_GRAPH_FILE = 16 * 1024 * 1024
MAX_GRAPH_TOTAL = 64 * 1024 * 1024
SELECTION_FIELDS = frozenset({"schemaVersion", "scope", "proofId", "deadlineMonotonicNs", "host", "seat",
    "operatorTerminal", "sourceRoot", "stateRoot", "sourceGraphSha256", "sourceFilesSha256", "sourceSocket",
    "inputPaths", "inputSha256", "controllerTools", "controllerInventory", "controllerNarProof", "vaultWrapperAuthority"})
REASONS = frozenset({"selection_invalid", "deadline_exceeded", "local_identity_unqualified", "runtime_unqualified",
    "graph_unqualified", "source_changed", "display_unqualified", "output_unqualified", "cleanup_incomplete"})


class QualificationError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "selection_invalid"
        super().__init__(self.reason)


def require(value, reason):
    if not value:
        raise QualificationError(reason)


def checked(reason, operation, *arguments, **options):
    try:
        return operation(*arguments, **options)
    except QualificationError:
        raise
    except Exception:
        raise QualificationError(reason) from None


def budget(deadline_ns, now=time.monotonic_ns):
    require(type(deadline_ns) is int and 0 < deadline_ns - now() <= 1200 * 10**9, "deadline_exceeded")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def selectors(selection, output, deadline_ns):
    budget(deadline_ns)
    for path in (selection, output):
        require(type(path) is str and re.fullmatch(r"/srv/[A-Za-z0-9._/-]{1,3800}", path)
                and str(Path(path)) == path and not {".", ".."}.intersection(path.split("/")), "selection_invalid")
    require(selection != output, "selection_invalid")


def validate_selection(value, deadline_ns, uid, home):
    require(type(value) is dict and set(value) == SELECTION_FIELDS and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and value["scope"] == "yoga-local-session-selection-v1"
            and type(value["deadlineMonotonicNs"]) is int and value["deadlineMonotonicNs"] == deadline_ns
            and type(value["proofId"]) is str and guard.coordinator.UUID.fullmatch(value["proofId"]), "selection_invalid")
    require(type(value["host"]) is dict and set(value["host"]) == {"machineIdSha256", "uid"}
            and type(value["host"]["uid"]) is int and value["host"]["uid"] == uid and uid > 0
            and type(value["host"]["machineIdSha256"]) is str and guard.SHA.fullmatch(value["host"]["machineIdSha256"]), "selection_invalid")
    require(type(value["seat"]) is dict and set(value["seat"]) == {"sessionId", "seatId", "uid"}
            and type(value["seat"]["uid"]) is int and value["seat"]["uid"] == uid
            and type(value["seat"]["sessionId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value["seat"]["sessionId"])
            and type(value["seat"]["seatId"]) is str and re.fullmatch(r"seat[0-9]{1,3}", value["seat"]["seatId"])
            and type(value["operatorTerminal"]) is str and re.fullmatch(r"/dev/(?:tty[0-9]{1,3}|pts/[0-9]{1,6})", value["operatorTerminal"]), "selection_invalid")
    guard.selectors(value["sourceRoot"], value["stateRoot"], value["sourceRoot"], home)
    require(type(value["sourceGraphSha256"]) is str and guard.SHA.fullmatch(value["sourceGraphSha256"])
            and type(value["sourceFilesSha256"]) is dict and set(value["sourceFilesSha256"]) == guard.SOURCE_FILES
            and all(type(digest) is str and guard.SHA.fullmatch(digest) for digest in value["sourceFilesSha256"].values()), "selection_invalid")
    require(type(value["inputPaths"]) is dict and set(value["inputPaths"]) == inputs.INPUTS
            and type(value["inputSha256"]) is dict and set(value["inputSha256"]) == inputs.INPUTS
            and all(type(digest) is str and guard.SHA.fullmatch(digest) for digest in value["inputSha256"].values()), "selection_invalid")
    for path in value["inputPaths"].values():
        inputs.valid_path(path)
        require(not Path(path).is_relative_to(home), "selection_invalid")
    require(type(value["controllerTools"]) is dict and set(value["controllerTools"]) == guard.TOOLS
            and all(type(path) is str and re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}(?:/[A-Za-z0-9+._?=@/-]{1,3800})?", path)
                    and str(Path(path)) == path and not {".", ".."}.intersection(path.split("/"))
                    for path in value["controllerTools"].values()), "selection_invalid")
    for name in ("controllerInventory", "controllerNarProof"):
        evidence = value[name]
        require(type(evidence) is dict and set(evidence) == {"path", "sha256"}
                and type(evidence["sha256"]) is str and guard.SHA.fullmatch(evidence["sha256"]), "selection_invalid")
        inputs.valid_path(evidence["path"])
    guard.wrapper_envelope_schema(value)
    for name in ('companion', 'nativeManifest', 'registeredNativeManifest', 'controllerInventory', 'controllerNarProof'):
        require(not Path(value['vaultWrapperAuthority'][name]['path']).is_relative_to(home), 'selection_invalid')
    proof_root = value["stateRoot"] + "/" + value["proofId"]
    display.selectors(value["sourceSocket"], proof_root + "/wayland.sock", proof_root, uid)
    budget(deadline_ns)
    return value


def read_selection(path, digest, deadline_ns):
    require(type(digest) is str and guard.SHA.fullmatch(digest), "selection_invalid")
    payload = guard.file_bytes(path, MAX_SELECTION, deadline_ns, private=True, expected=digest)
    return guard.decode(payload)


def file_witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_mtime_ns, info.st_ctime_ns)


def graph_capture(repository, deadline_ns, *, now=time.monotonic_ns):
    """Same selector/hash as guard_cache.graph_digest, with descriptor bounds.

    A FIFO, ancestor replacement or capture-wide byte drift cannot block or
    become a graph digest. Original deadline and a 15-second local bound apply.
    Consumer guard_cache independently compares the compatible digest later.
    This producer conservatively rejects unselected file symlinks too.
    """
    root = Path(repository)
    inputs.valid_path(str(root))
    budget(deadline_ns, now)
    until = min(deadline_ns, now() + 15 * 10**9)
    uid = os.getuid()
    held_dirs, held_files, selected = [], [], []
    root_fd = inputs.open_parent(str(root / "placeholder"), uid, until, now)
    try:
        held_dirs.append(("", root_fd, directory_witness(os.fstat(root_fd))))
    except BaseException:
        os.close(root_fd)
        raise
    traversed, path_bytes, total = 0, 0, 0
    fixed = {"BUILD", "BUILD.bazel", "MODULE.bazel", "MODULE.bazel.lock", "WORKSPACE", "WORKSPACE.bazel",
             "flake.nix", "flake.lock", ".bazelrc", ".bazelversion"}
    output_links = {"bazel-bin", "bazel-out", "bazel-testlogs", "bazel-" + root.name}
    try:
        pending = [("", root_fd, 0)]
        while pending:
            relative, directory, depth = pending.pop()
            budget(until, now)
            require(depth <= 128, "graph_unqualified")
            names = sorted(os.listdir(directory))
            traversed += len(names)
            require(traversed <= 200000 and len(held_dirs) <= 8192, "graph_unqualified")
            for name in names:
                budget(until, now)
                require(type(name) is str and name not in (".", "..") and "/" not in name, "graph_unqualified")
                path = name if not relative else relative + "/" + name
                information = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if name == ".git" or (not relative and name == ".direnv"):
                    continue
                if stat.S_ISLNK(information.st_mode):
                    # Graph-cache permits known root output links only; refuse
                    # all other links rather than inspect an external target.
                    require(not relative and name in output_links, "graph_unqualified")
                    continue
                if stat.S_ISDIR(information.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        child_info = os.fstat(child)
                    except BaseException:
                        os.close(child)
                        raise
                    held_dirs.append((path, child, directory_witness(child_info)))
                    require(directory_witness(child_info) == directory_witness(information)
                            and child_info.st_uid in (0, uid) and not stat.S_IMODE(child_info.st_mode) & 0o022, "graph_unqualified")
                    pending.append((path, child, depth + 1))
                    continue
                suffix = Path(name).suffix
                chosen = name in fixed or suffix in (".bzl", ".nix") or (path.split("/", 1)[0] == "tools"
                    and suffix in (".py", ".json", ".patch", ".zig", ".h"))
                if not chosen:
                    continue
                path_bytes += len(path.encode())
                require(len(selected) < 4096 and len(path) <= 4096 and path_bytes <= 128 * 1024, "graph_unqualified")
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                try:
                    info = os.fstat(descriptor)
                except BaseException:
                    os.close(descriptor)
                    raise
                held_files.append((directory, name, descriptor, file_witness(info)))
                require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, uid) and not stat.S_IMODE(info.st_mode) & 0o022
                        and 0 <= info.st_size <= MAX_GRAPH_FILE, "graph_unqualified")
                digest, size = hashlib.sha256(), 0
                while True:
                    budget(until, now)
                    chunk = os.read(descriptor, min(65536, MAX_GRAPH_FILE + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= MAX_GRAPH_FILE and total + size <= MAX_GRAPH_TOTAL, "graph_unqualified")
                    digest.update(chunk)
                total += size
                require(size == info.st_size, "source_changed")
                selected.append((path, digest.digest()))
        require(selected, "graph_unqualified")
        for relative, descriptor, identity in held_dirs:
            budget(until, now)
            named = inputs.open_parent(str(root / relative / "placeholder"), uid, until, now)
            try:
                require(identity == directory_witness(os.fstat(descriptor)) == directory_witness(os.fstat(named)), "source_changed")
            finally:
                os.close(named)
        for directory, name, descriptor, identity in held_files:
            budget(until, now)
            require(identity == file_witness(os.fstat(descriptor)) == file_witness(os.stat(name, dir_fd=directory, follow_symlinks=False)), "source_changed")
        result = hashlib.sha256()
        for path, digest in sorted(selected):
            result.update(path.encode() + b"\0" + digest)
        budget(until, now)
        return result.hexdigest()
    finally:
        for _, _, descriptor, _ in reversed(held_files):
            os.close(descriptor)
        for _, descriptor, _ in reversed(held_dirs):
            os.close(descriptor)


def identity_capture(selection, deadline_ns, uid, terminal_descriptor):
    host = {"machineIdSha256": hashlib.sha256(guard.file_bytes("/etc/machine-id", 128, deadline_ns)).hexdigest(),
            "bootIdSha256": hashlib.sha256(guard.file_bytes("/proc/sys/kernel/random/boot_id", 128, deadline_ns)).hexdigest(), "uid": uid}
    require(host["machineIdSha256"] == selection["host"]["machineIdSha256"], "local_identity_unqualified")
    identity = {"host": host, "seat": selection["seat"], "operatorTerminal": selection["operatorTerminal"]}
    checked("local_identity_unqualified", guard.local_identity, identity, deadline_ns, uid, terminal_descriptor)
    return host


def publish(path, payload, deadline_ns, verify, *, now=time.monotonic_ns):
    """Create only a new owned receipt, retaining named-parent custody."""
    budget(deadline_ns, now)
    require(type(payload) is bytes and 0 < len(payload) <= MAX_SELECTION, "output_unqualified")
    parent, output, created = None, None, None
    endpoint = Path(path)
    try:
        parent = display.parent_descriptor(str(endpoint.parent), os.getuid())
        # Publication intentionally changes directory times; retain namespace
        # identity here while graph capture also witnesses directory times.
        before_parent = directory_witness(os.fstat(parent))[:4]
        verify()
        budget(deadline_ns, now)
        output = os.open(endpoint.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        try:
            created = os.fstat(output)
        except BaseException:
            # A named file cannot be removed without its held inode witness.
            raise QualificationError("cleanup_incomplete") from None
        os.fchmod(output, 0o600)
        offset = 0
        while offset < len(payload):
            budget(deadline_ns, now)
            written = os.write(output, payload[offset:])
            require(written > 0, "output_unqualified")
            offset += written
        os.fsync(output)
        os.fsync(parent)
        verify()
        named_parent = display.parent_descriptor(str(endpoint.parent), os.getuid())
        try:
            require(before_parent == directory_witness(os.fstat(parent))[:4] == directory_witness(os.fstat(named_parent))[:4], "output_unqualified")
            held = os.fstat(output)
            named = os.stat(endpoint.name, dir_fd=named_parent, follow_symlinks=False)
            require(file_witness(held) == file_witness(named) and (held.st_dev, held.st_ino) == (created.st_dev, created.st_ino)
                    and stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and stat.S_IMODE(held.st_mode) == 0o600
                    and held.st_nlink == 1 and held.st_size == len(payload), "output_unqualified")
        finally:
            os.close(named_parent)
        budget(deadline_ns, now)
        return hashlib.sha256(payload).hexdigest()
    except BaseException:
        if created is not None:
            try:
                current = os.stat(endpoint.name, dir_fd=parent, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (created.st_dev, created.st_ino), "cleanup_incomplete")
                os.unlink(endpoint.name, dir_fd=parent)
                os.fsync(parent)
            except (OSError, QualificationError):
                raise QualificationError("cleanup_incomplete") from None
        raise
    finally:
        if output is not None:
            os.close(output)
        if parent is not None:
            os.close(parent)


def produce(selection_path, selection_sha256, output_path, deadline_ns, *, terminal_descriptor=0):
    selectors(selection_path, output_path, deadline_ns)
    require(deadline_ns - time.monotonic_ns() > guard.CLEANUP_RESERVE_NS, "deadline_exceeded")
    uid = os.getuid()
    home = Path(pwd.getpwuid(uid).pw_dir)
    selection = checked("selection_invalid", validate_selection,
        checked("selection_invalid", read_selection, selection_path, selection_sha256, deadline_ns), deadline_ns, uid, home)
    guard.selectors(output_path, selection["stateRoot"], selection["sourceRoot"], home)
    proof_root = selection["stateRoot"] + "/" + selection["proofId"]
    require(not Path(output_path).is_relative_to(proof_root) and not Path(selection_path).is_relative_to(proof_root)
            and not Path(output_path).is_relative_to(selection["sourceRoot"])
            and not Path(selection_path).is_relative_to(selection["sourceRoot"])
            and not Path(selection["stateRoot"]).is_relative_to(selection["sourceRoot"]), "selection_invalid")
    host = checked("local_identity_unqualified", identity_capture, selection, deadline_ns, uid, terminal_descriptor)
    require(checked("graph_unqualified", graph_capture, selection["sourceRoot"], deadline_ns) == selection["sourceGraphSha256"], "graph_unqualified")
    witness, pin = checked("display_unqualified", display.capture_pinned, selection["sourceSocket"], proof_root + "/wayland.sock", proof_root, uid, deadline_ns)
    try:
        receipt = {key: selection[key] for key in guard.FIELDS if key in selection}
        receipt.update(schemaVersion=1, scope="yoga-local-guard-qualification-v1", hostAlias="yoga", host=host,
                       compositorSnapshot=witness["snapshot"])
        guard.schema(receipt, deadline_ns, selection["sourceRoot"], selection["controllerTools"], selection["sourceGraphSha256"], uid)
        checked("runtime_unqualified", guard.runtime_qualification, receipt, deadline_ns)
        def verify():
            budget(deadline_ns)
            require(deadline_ns - time.monotonic_ns() > guard.CLEANUP_RESERVE_NS, "deadline_exceeded")
            require(checked("selection_invalid", read_selection, selection_path, selection_sha256, deadline_ns) == selection, "source_changed")
            require(checked("local_identity_unqualified", identity_capture, selection, deadline_ns, uid, terminal_descriptor) == host, "local_identity_unqualified")
            require(checked("graph_unqualified", graph_capture, selection["sourceRoot"], deadline_ns) == selection["sourceGraphSha256"], "source_changed")
            checked("runtime_unqualified", guard.runtime_qualification, receipt, deadline_ns)
            require(checked("display_unqualified", pin.check, witness) == receipt["compositorSnapshot"], "display_unqualified")
        digest = checked("output_unqualified", publish, output_path, canonical(receipt), deadline_ns, verify)
        return {"scope": "yoga-session-qualification-produced", "receiptSha256": digest, "proofId": selection["proofId"],
            "deadlineMonotonicNs": deadline_ns, "executionAuthority": False, "toolbarConsentProved": False}
    finally:
        pin.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise QualificationError("selection_invalid")


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deadline-monotonic-ns", required=True, type=int)
    args = parser.parse_args()
    result = produce(args.selection, args.selection_sha256, args.output, args.deadline_monotonic_ns,
                     terminal_descriptor=sys.stdin.fileno())
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        reason = error.reason if isinstance(error, QualificationError) else "selection_invalid"
        print(json.dumps({"scope": "yoga-session-qualification-refused", "reason": reason,
                          "executionAuthority": False, "toolbarConsentProved": False}), file=sys.stderr)
        sys.exit(125)
