"""Remove one explicitly authorized private proof workspace without following links."""
import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import runpy
import re
import select
import signal
import stat
import sys
import time

KNOWN_WORKSPACE = ".run-nUi7wZna"
KNOWN_REPAIRS = {KNOWN_WORKSPACE: "14ccacec-4922-486d-a95f-4332d4f531bb", ".run-UVJycRK3": "3ddc3001-8494-4fb1-bfdb-4f3676d15684"}
KNOWN_DIAGNOSTIC = (".run-tIFiJDX7", "e5d3e5f5-7872-4249-926b-de7db20d9632", "8537f74eaf4a9b6913a8721cdaf8dfa3d9d9c640213e19346729e53bb836a346")
KNOWN_REPAIRS[KNOWN_DIAGNOSTIC[0]] = KNOWN_DIAGNOSTIC[1]
KNOWN_REPAIRS[".run-s9jRDq9y"] = "22412e51-546a-4379-bef2-9b164c552e46"
STING_RECOVERY_PROOF = "faf6e1f4-a9c9-4dad-9947-1b9424a6c844"
STING_RECOVERY_LOG = "16a33002b13ba56e2f390ab0903c135294398973ba18fdc621243ec11323aff2"
STING_RECOVERY_ARTIFACT = "a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a"
STING_RECOVERY_BYTES = 59741174
MAX_ENTRIES = 8000000
REJECTION_CODES = {"authority", "ancestry", "type", "owner", "shared-write", "private-mode", "identity-changed", "depth-bound", "entry-bound", "recovery-no-match", "recovery-ambiguous"}


class CleanupRejection(ValueError):
    def __init__(self, code, metadata=None, depth=0, scope="workspace", entry="other"):
        super().__init__("cleanup predicate rejected")
        if code not in REJECTION_CODES:
            raise ValueError("unknown cleanup rejection")
        self.code = code
        self.safe_metadata = {"depth": min(depth, 129), "scope": scope if scope in {"workspace", "source", "state", "runtime"} else "workspace", "entry_kind": entry if entry in {"_tmp", "tmp", "sandbox", "server", "external"} else "other"}
        if metadata is not None:
            self.safe_metadata.update(mode=stat.S_IMODE(metadata.st_mode), owner_class="current" if metadata.st_uid == os.getuid() else "root" if metadata.st_uid == 0 else "other")


def workspace_output_base(workspace):
    return hashlib.md5(str(workspace).encode()).hexdigest()


def artifact_components(child):
    # Source may already have been removed. The admitted canonical parent and
    # fixed recipe's physical source component determine Bazel's layout;
    # MD5 is a workspace directory name, never content/security authority.
    output_base = workspace_output_base(child / "source")
    return ["bazel", output_base, "execroot", "_main", "bazel-out", "k8-fastbuild", "bin", "delivery", "release_archive.tar.gz"]


def artifact_matches(child_fd, child_path, uid, check, aggregate):
    descriptors = [os.dup(child_fd)]
    links = []
    try:
        components = artifact_components(child_path)
        for component in components[:-1]:
            check()
            parent = descriptors[-1]
            expected = os.stat(component, dir_fd=parent, follow_symlinks=False)
            opened = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(opened)
            metadata = os.fstat(opened)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or metadata.st_mode & 0o022 or (metadata.st_dev, metadata.st_ino) != (expected.st_dev, expected.st_ino):
                return False
            links.append((parent, component, metadata.st_dev, metadata.st_ino))
        document = os.open(components[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptors[-1])
        descriptors.append(document)
        before = os.fstat(document)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size != STING_RECOVERY_BYTES:
            return False
        digest = hashlib.sha256()
        size = 0
        while True:
            check()
            block = os.read(document, 65536)
            if not block:
                break
            size += len(block)
            aggregate[0] += len(block)
            if size > STING_RECOVERY_BYTES or aggregate[0] > 256 * 1024 * 1024:
                raise CleanupRejection("entry-bound")
            digest.update(block)
        after = os.fstat(document)
        entry = os.stat(components[-1], dir_fd=descriptors[-2], follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino):
            return False
        for parent, component, device, inode in links:
            metadata = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != (device, inode) or metadata.st_uid != uid or metadata.st_mode & 0o022:
                return False
        return size == STING_RECOVERY_BYTES and digest.hexdigest() == STING_RECOVERY_ARTIFACT
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
            return False
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def find_sting_workspace(base, uid, custodian, check):
    ancestry(base, uid)
    private_directory(base, uid)
    descriptor = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    matches = []
    total_bytes = [0]
    try:
        opened_base = os.fstat(descriptor)
        admitted_base = os.lstat(base)
        if opened_base.st_uid != uid or stat.S_IMODE(opened_base.st_mode) != 0o700 or (opened_base.st_dev, opened_base.st_ino) != (admitted_base.st_dev, admitted_base.st_ino):
            raise CleanupRejection("identity-changed")
        with os.scandir(descriptor) as entries:
            candidates = []
            for entry in entries:
                check()
                candidates.append(entry)
                if len(candidates) > 32:
                    raise CleanupRejection("entry-bound")
        for entry in candidates:
            check()
            if entry.name == custodian or not re.fullmatch(r"\.run-[A-Za-z0-9]{8}", entry.name):
                continue
            metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700:
                continue
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or opened.st_uid != uid or stat.S_IMODE(opened.st_mode) != 0o700 or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise CleanupRejection("identity-changed")
                matched = False
                evidence = None
                for filename in ["current.authority", "build.log"]:
                    try:
                        document = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=child)
                    except FileNotFoundError:
                        continue
                    try:
                        before = os.fstat(document)
                        limit = 160 if filename == "current.authority" else 128 * 1024 * 1024
                        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > limit:
                            continue
                        digest = hashlib.sha256()
                        marker = bytearray()
                        document_bytes = 0
                        while True:
                            check()
                            block = os.read(document, 65536)
                            if not block:
                                break
                            total_bytes[0] += len(block)
                            document_bytes += len(block)
                            if total_bytes[0] > 256 * 1024 * 1024 or document_bytes > limit:
                                raise CleanupRejection("entry-bound")
                            digest.update(block)
                            if filename == "current.authority":
                                marker.extend(block)
                        after = os.fstat(document)
                        current = os.stat(filename, dir_fd=child, follow_symlinks=False)
                        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                            continue
                        if filename == "current.authority":
                            matched = bytes(marker) == f"{STING_RECOVERY_PROOF}:{opened.st_dev}:{opened.st_ino}\n".encode()
                        else:
                            matched = digest.hexdigest() == STING_RECOVERY_LOG
                        if matched:
                            evidence = "proof-marker" if filename == "current.authority" else "recorded-log-hash"
                            break
                    finally:
                        os.close(document)
                if not matched and artifact_matches(child, base / entry.name, uid, check, total_bytes):
                    matched = True
                    evidence = "recorded-artifact-hash"
                if matched:
                    matches.append((entry.name, (opened.st_dev, opened.st_ino), evidence))
            finally:
                os.close(child)
        if len(matches) != 1:
            error = CleanupRejection("recovery-no-match" if not matches else "recovery-ambiguous")
            error.safe_metadata.update(match_count=len(matches), candidate_count=len(candidates))
            raise error
        return matches[0]
    finally:
        os.close(descriptor)


def diagnostic_identities(data):
    identities = set()
    categories = set()
    remaining = 0
    for raw in data.splitlines():
        if len(raw) > 4096:
            remaining = 0
            continue
        line = raw.decode("utf-8", errors="replace")
        if "unable to resolve dependency" in line:
            categories.add("unresolved-dependency")
            remaining = 8
        elif remaining and (line.startswith((" ", "\t")) or line.startswith("note:")):
            remaining -= 1
        else:
            remaining = 0
            continue
        for identity in re.findall(r"(?<![A-Za-z0-9_])lib[A-Za-z0-9_.+\-]{1,120}\.(?:tbd|dylib|a|so(?:\.[0-9.]+)?)\b", line):
            if re.fullmatch(r"lib(?:System|objc|curl|sqlite3|iconv|z|ssl|crypto|c\+\+|c\+\+abi)(?:\.[A-Za-z0-9]+)*\.(?:tbd|dylib|a|so(?:\.[0-9.]+)?)", identity):
                identities.add("library:" + identity)
        for identity in re.findall(r"(?:^|/)([A-Za-z0-9_+\-]{1,80})\.framework(?:/|\b)", line):
            if identity in {"Security", "CoreFoundation", "Foundation", "SystemConfiguration"}:
                identities.add("framework:" + identity)
        for identity in re.findall(r"/MacOSX\.sdk/(usr/lib/[A-Za-z0-9_./+\-]{1,240}\.(?:tbd|dylib)|System/Library/Frameworks/[A-Za-z0-9_./+\-]{1,240}\.(?:tbd|h))(?=[\s:'\"]|$)", line):
            if re.search(r"/nix/store/[a-z0-9]{32}-apple-sdk-14\.4/", line) and ".." not in identity.split("/"):
                identities.add("sdk-relative:" + identity)
    if len(identities) > 32:
        raise ValueError("diagnostic identity bound rejected")
    return sorted(identities), sorted(categories)


def diagnose(base, uid, check):
    name, proof, expected_hash = KNOWN_DIAGNOSTIC
    ancestry(base, uid)
    private_directory(base, uid)
    child = base / name
    ancestry(child, uid)
    private_directory(child, uid)
    child_fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        admitted = os.lstat(child)
        actual = os.fstat(child_fd)
        if (actual.st_dev, actual.st_ino) != (admitted.st_dev, admitted.st_ino) or actual.st_uid != uid or stat.S_IMODE(actual.st_mode) != 0o700:
            raise ValueError("diagnostic workspace changed")
        descriptor = os.open("build.log", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=child_fd)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size > 128 * 1024 * 1024:
                raise ValueError("diagnostic log custody rejected")
            digest = hashlib.sha256()
            content = bytearray()
            while True:
                check()
                block = os.read(descriptor, 65536)
                if not block:
                    break
                content.extend(block)
                digest.update(block)
                if len(content) > 128 * 1024 * 1024:
                    raise ValueError("diagnostic log exceeds bound")
            after = os.fstat(descriptor)
            entry = os.stat("build.log", dir_fd=child_fd, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (metadata.st_dev, metadata.st_ino) or (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or digest.hexdigest() != expected_hash:
                raise ValueError("diagnostic log identity rejected")
            identities, categories = diagnostic_identities(content)
            return {"proof_id": proof, "log_sha256": expected_hash, "identities": identities, "categories": categories}
        finally:
            os.close(descriptor)
    finally:
        os.close(child_fd)


def ancestry(path, uid):
    if not path.is_absolute() or ".." in path.parts or any(char in str(path) for char in "\r\n\0"):
        raise CleanupRejection("ancestry")
    for candidate in reversed([path, *path.parents]):
        metadata = os.lstat(candidate)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CleanupRejection("type", metadata)
        if metadata.st_uid not in {0, uid}:
            raise CleanupRejection("owner", metadata)
        if metadata.st_mode & 0o022:
            raise CleanupRejection("shared-write", metadata)


def private_directory(path, uid):
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise CleanupRejection("type", metadata)
    if metadata.st_uid != uid:
        raise CleanupRejection("owner", metadata)
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CleanupRejection("private-mode", metadata)
    return metadata


def cleanup(base, name, uid, check, validate=ancestry, current_identity=None):
    if (name not in KNOWN_REPAIRS and current_identity is None) or base.name not in {"OmuxProof", "omux-proof"}:
        raise CleanupRejection("authority")
    if current_identity is not None and (not re.fullmatch(r"\.run-[A-Za-z0-9]{8}", name) or len(current_identity) != 2):
        raise CleanupRejection("authority")
    validate(base, uid)
    private_directory(base, uid)
    base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    counts = {"directories": 0, "entries": 0, "repaired_directories": 0}
    try:
        metadata = os.fstat(base_fd)
        expected = os.lstat(base)
        if metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700 or not stat.S_ISDIR(metadata.st_mode):
            raise CleanupRejection("private-mode", metadata)
        if (metadata.st_dev, metadata.st_ino) != (expected.st_dev, expected.st_ino):
            raise CleanupRejection("identity-changed")
        try:
            expected = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "absent", counts
        if not stat.S_ISDIR(expected.st_mode) or expected.st_uid != uid or stat.S_IMODE(expected.st_mode) != 0o700:
            raise CleanupRejection("private-mode", expected)
        if current_identity is not None and (expected.st_dev, expected.st_ino) != current_identity:
            raise CleanupRejection("identity-changed")
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
        try:
            actual = os.fstat(child_fd)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise CleanupRejection("identity-changed")
            def remove_contents(descriptor, depth, scope="workspace", entry_label="other"):
                check()
                if depth > 128:
                    raise CleanupRejection("depth-bound", depth=depth, scope=scope, entry=entry_label)
                metadata = os.fstat(descriptor)
                if metadata.st_uid != uid:
                    raise CleanupRejection("owner", metadata, depth, scope, entry_label)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise CleanupRejection("type", metadata, depth, scope, entry_label)
                if metadata.st_mode & 0o022:
                    raise CleanupRejection("shared-write", metadata, depth, scope, entry_label)
                counts["directories"] += 1
                if stat.S_IMODE(metadata.st_mode) & 0o700 != 0o700:
                    # The descriptor names an admitted owned directory, never
                    # a symlink or the immutable target of a store alias.
                    os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | 0o700)
                    counts["repaired_directories"] += 1
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        check()
                        if depth == 0 and current_identity is not None and entry.name in {"current.authority", "cleanup.deadline"}:
                            continue
                        counts["entries"] += 1
                        if counts["entries"] > MAX_ENTRIES:
                            raise CleanupRejection("entry-bound", depth=depth, scope=scope)
                        try:
                            metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        if stat.S_ISDIR(metadata.st_mode):
                            child_scope = entry.name if depth == 0 and entry.name in {"source", "state", "runtime"} else scope
                            if metadata.st_uid != uid:
                                raise CleanupRejection("owner", metadata, depth + 1, child_scope, entry.name)
                            if metadata.st_mode & 0o022:
                                raise CleanupRejection("shared-write", metadata, depth + 1, child_scope, entry.name)
                            nested = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                            try:
                                actual = os.fstat(nested)
                                if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                                    raise CleanupRejection("identity-changed", depth=depth + 1, scope=child_scope)
                                remove_contents(nested, depth + 1, child_scope, entry.name)
                            finally:
                                os.close(nested)
                            current = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                                raise CleanupRejection("identity-changed", depth=depth + 1, scope=child_scope)
                            os.rmdir(entry.name, dir_fd=descriptor)
                        else:
                            os.unlink(entry.name, dir_fd=descriptor)
            remove_contents(child_fd, 0)
            if current_identity is not None:
                for marker_name in ["cleanup.deadline", "current.authority"]:
                    try:
                        os.unlink(marker_name, dir_fd=child_fd)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(child_fd)
        actual = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise CleanupRejection("identity-changed")
        os.rmdir(name, dir_fd=base_fd)
        return "removed", counts
    except (OSError, ValueError) as error:
        error.partial_counts = dict(counts)
        raise
    finally:
        os.close(base_fd)


def category(error):
    if isinstance(error, TimeoutError):
        return "deadline"
    if isinstance(error, InterruptedError):
        return "custodian-or-signal"
    if isinstance(error, ValueError):
        return "custody"
    return {errno.EACCES: "permissions", errno.EPERM: "permissions", errno.ENOTEMPTY: "not-empty",
            errno.ELOOP: "symlink", errno.ENOENT: "missing", errno.ENOSPC: "storage"}.get(error.errno, "filesystem")


def failure_summary(error):
    counts = getattr(error, "partial_counts", {"directories": 0, "entries": 0, "repaired_directories": 0})
    summary = {"outcome": "failed", "category": category(error), **counts}
    if isinstance(error, CleanupRejection):
        summary.update(rejection_code=error.code, metadata=error.safe_metadata)
    return summary


def current_main():
    parser = argparse.ArgumentParser(description="Remove only this custodian's newly created staging")
    parser.add_argument("--current", action="store_true", required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--proof-id", required=True)
    args = parser.parse_args()
    if args.workspace.parent != args.base or args.workspace.name in {*KNOWN_REPAIRS, KNOWN_DIAGNOSTIC[0]} or not re.fullmatch(r"[0-9a-f-]{36}", args.proof_id):
        raise ValueError("current cleanup authority rejected")
    ancestry(args.workspace, os.getuid())
    private_directory(args.workspace, os.getuid())
    descriptor = os.open(args.workspace / "current.authority", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size > 160:
            raise ValueError("current authority marker rejected")
        payload = os.read(descriptor, 161).decode("ascii")
    finally:
        os.close(descriptor)
    match = re.fullmatch(re.escape(args.proof_id) + r":([0-9]+):([0-9]+)\n", payload)
    if match is None:
        raise ValueError("current authority identity rejected")
    identity = tuple(int(value) for value in match.groups())
    deadline_fd = os.open(args.workspace / "cleanup.deadline", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(deadline_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size > 256:
            raise CleanupRejection("private-mode", metadata)
        recorded = json.loads(os.read(deadline_fd, 257))
    finally:
        os.close(deadline_fd)
    now = time.monotonic()
    if (not isinstance(recorded, dict) or set(recorded) != {"proof_id", "deadline", "total"} or recorded["proof_id"] != args.proof_id
            or type(recorded["total"]) is not int or not 30 <= recorded["total"] <= 3600
            or type(recorded["deadline"]) not in {int, float} or not math.isfinite(recorded["deadline"]) or recorded["deadline"] > now + recorded["total"]):
        raise CleanupRejection("authority")
    deadline = recorded["deadline"] - 3
    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError("current cleanup deadline")
    outcome, counts = cleanup(args.base, args.workspace.name, os.getuid(), check, validate=ancestry, current_identity=identity)
    print("current-cleanup=" + outcome, flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--workspace", choices=[*KNOWN_REPAIRS, "receipt-sting-faf6"], required=True)
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--recover-sting", action="store_true")
    parser.add_argument("--repair-proof", required=True)
    parser.add_argument("--custodian-proof", required=True)
    parser.add_argument("--custodian", type=Path, required=True)
    parser.add_argument("--total", type=int, required=True)
    args = parser.parse_args()
    if args.diagnose and args.workspace != KNOWN_DIAGNOSTIC[0]:
        parser.error("diagnostic authority rejected")
    if args.recover_sting and args.workspace != "receipt-sting-faf6":
        parser.error("recorded Sting authority rejected")
    home = Path(os.environ["HOME"])
    authorized_proof = STING_RECOVERY_PROOF if args.recover_sting and args.workspace == "receipt-sting-faf6" else KNOWN_DIAGNOSTIC[1] if args.diagnose and args.workspace == KNOWN_DIAGNOSTIC[0] else KNOWN_REPAIRS.get(args.workspace)
    platform_base_valid = (sys.platform.startswith("linux") and args.base.name == "omux-proof") if args.recover_sting else (sys.platform == "darwin" and args.base == home / "Library" / "Application Support" / "OmuxProof")
    if not platform_base_valid or not 30 <= args.total <= 3600 or authorized_proof != args.repair_proof or (args.recover_sting and args.diagnose):
        parser.error("fixed cleanup authority rejected")
    ancestry(home, os.getuid())
    if os.lstat(home).st_uid != os.getuid():
        raise ValueError("HOME ownership rejected")
    private_directory(args.custodian, os.getuid())
    ancestry(args.custodian, os.getuid())
    if args.custodian.parent != args.base or not args.custodian.name.startswith(".run-") or args.custodian.name in {*KNOWN_REPAIRS, KNOWN_DIAGNOSTIC[0]}:
        raise ValueError("cleanup custodian rejected")
    control = runpy.run_path("tools/host_graph.py")
    descriptor = os.open(args.custodian / "graph.deadline", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise ValueError("cleanup deadline channel rejected")
        anchor = time.monotonic()
        ready = os.open(args.custodian / "graph.ready", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(ready, b"ready\n")
        finally:
            os.close(ready)
        budget = control["read_budget"](descriptor, args.total)
        control["record_cleanup_deadline"](args.custodian / "cleanup.deadline", args.custodian_proof, anchor, budget, args.total)
        deadline = anchor + budget
        last_check = [0.0]
        def check():
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError("cleanup deadline")
            if now - last_check[0] >= 0.25:
                last_check[0] = now
                if select.select([descriptor], [], [], 0)[0]:
                    raise InterruptedError("cleanup custodian lost")
        def interrupted(signum, frame):
            raise InterruptedError("cleanup signal")
        for signum in [signal.SIGHUP, signal.SIGTERM, signal.SIGINT]:
            signal.signal(signum, interrupted)
        print("phase=private-staging-repair", flush=True)
        if args.diagnose:
            print("diagnostic-summary=" + json.dumps(diagnose(args.base, os.getuid(), check), sort_keys=True), flush=True)
            return 0
        if args.recover_sting:
            name, identity, evidence = find_sting_workspace(args.base, os.getuid(), args.custodian.name, check)
            print("recovered-workspace=" + name, flush=True)
            print("recovery-authority=" + evidence, flush=True)
            outcome, counts = cleanup(args.base, name, os.getuid(), check, current_identity=identity)
        else:
            outcome, counts = cleanup(args.base, args.workspace, os.getuid(), check)
        summary = {"outcome": outcome, **counts}
        print("repair-result=" + outcome)
        for name, value in counts.items():
            print("repair-" + name.replace("_", "-") + "=" + str(value))
        print("repair-summary-sha256=" + hashlib.sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest())
        return 0
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        sys.exit(current_main() if "--current" in sys.argv else main())
    except (OSError, ValueError) as error:
        prefix = "current-cleanup" if "--current" in sys.argv else "repair"
        summary = failure_summary(error)
        print("current-cleanup=failed" if prefix == "current-cleanup" else "repair-result=failed")
        print(prefix + "-error=" + category(error))
        for name in ["directories", "entries", "repaired_directories"]:
            print(prefix + "-" + name.replace("_", "-") + "=" + str(summary[name]))
        if "rejection_code" in summary:
            print(prefix + "-rejection-code=" + summary["rejection_code"])
            print(prefix + "-metadata=" + json.dumps(summary["metadata"], sort_keys=True))
        print(prefix + "-summary-sha256=" + hashlib.sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest())
        sys.exit(3)
