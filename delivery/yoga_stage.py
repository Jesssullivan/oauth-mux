"""Stage one selected public Yoga payload locally; never import or execute it.

The independent archive and manifest hashes select bytes, not live store or
desktop authority. A new owned /srv task directory is complete only when the
digest-selected stage receipt is published. Copied tools remain nonexecutable
comparison data. Partial failures remove only this invocation's witnessed files.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import time

import yoga_payload as payload

MAX_ARCHIVE = min(payload.MAX_ARCHIVE, 1024**3)
MAX_FILES = 10032
MAX_DIRECTORIES = 4096
MAX_DEPTH = 64
MAX_TOTAL = payload.MAX_TOTAL + payload.MAX_FILE + payload.MAX_METADATA
CLEANUP_SECONDS = 30
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
REASONS = frozenset({"selector_invalid", "deadline_exceeded", "archive_unqualified", "digest_mismatch",
    "archive_changed", "payload_invalid", "output_unqualified", "output_changed", "byte_bound", "cleanup_incomplete"})


class StageError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "payload_invalid"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise StageError(reason)


def budget(deadline_ns, now=time.monotonic_ns):
    require(type(deadline_ns) is int and 0 < deadline_ns - now() <= 1200 * 10**9, "deadline_exceeded")


def witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def selectors(archive, destination, archive_sha256, manifest_sha256, deadline_ns):
    budget(deadline_ns)
    require(type(archive) is str and type(destination) is str and archive != destination, "selector_invalid")
    for path in (archive, destination):
        require(path.startswith("/srv/") and str(Path(path)) == path and len(os.fsencode(path)) <= 4096
                and not {".", ".."}.intersection(path.split("/"))
                and not any(ord(character) <= 32 for character in path), "selector_invalid")
    require(re.fullmatch("yoga-stage-(" + UUID + ")", Path(destination).name)
            and not Path(archive).is_relative_to(destination), "selector_invalid")
    require(all(type(value) is str and payload.SHA.fullmatch(value) for value in (archive_sha256, manifest_sha256)), "selector_invalid")


class Archive:
    def __init__(self, path, expected, deadline_ns):
        self.path, self.parent, self.fd = Path(path), None, None
        self.deadline = deadline_ns
        try:
            budget(deadline_ns)
            self.parent = payload.parent(self.path)
            self.parent_identity = directory_identity(os.fstat(self.parent))
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.parent)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
                    and info.st_nlink == 1 and 0 < info.st_size <= MAX_ARCHIVE, "archive_unqualified")
            self.identity, self.size, self.expected = witness(info), info.st_size, expected
            collected = bytearray()
            hashed = hashlib.sha256()
            while True:
                budget(deadline_ns)
                data = os.read(self.fd, min(65536, MAX_ARCHIVE + 1 - len(collected)))
                if not data:
                    break
                collected.extend(data); hashed.update(data)
                require(len(collected) <= MAX_ARCHIVE, "byte_bound")
            require(len(collected) == self.size and hashed.hexdigest() == expected, "digest_mismatch")
            self.check()
            self.data = bytes(collected)
        except BaseException:
            self.close()
            raise

    def check(self):
        budget(self.deadline)
        named = payload.parent(self.path)
        try:
            require(self.parent_identity == directory_identity(os.fstat(self.parent)) == directory_identity(os.fstat(named))
                    and self.identity == witness(os.fstat(self.fd))
                    == witness(os.stat(self.path.name, dir_fd=named, follow_symlinks=False)), "archive_changed")
        finally:
            os.close(named)
        budget(self.deadline)

    def close(self):
        failed = False
        for field in ("fd", "parent"):
            descriptor = getattr(self, field)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        require(not failed, "cleanup_incomplete")


class Task:
    def __init__(self, destination, deadline_ns):
        self.path, self.deadline = Path(destination), deadline_ns
        self.parent, self.root = None, None
        self.root_identity = None
        self.files, self.directories, self.total = {}, {}, 0
        self.created = False
        try:
            budget(deadline_ns)
            self.parent = payload.parent(self.path)
            parent_info = os.fstat(self.parent)
            require(parent_info.st_uid == os.getuid() and stat.S_IMODE(parent_info.st_mode) == 0o700, "output_unqualified")
            self.parent_identity = directory_identity(parent_info)
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent)
            self.created = True
            self.root = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            root_info = os.fstat(self.root)
            self.root_identity = directory_identity(root_info)
            require(root_info.st_uid == os.getuid() and stat.S_IMODE(root_info.st_mode) == 0o700, "output_unqualified")
            self.check_root()
            os.fsync(self.parent)
        except BaseException:
            try:
                self.cleanup()
            finally:
                self.close()
            raise

    def check_root(self, *, deadline=None):
        budget(self.deadline if deadline is None else deadline)
        require(self.root_identity is not None, "output_unqualified")
        named = payload.parent(self.path)
        try:
            require(self.parent_identity == directory_identity(os.fstat(self.parent)) == directory_identity(os.fstat(named))
                    and self.root_identity == directory_identity(os.fstat(self.root))
                    == directory_identity(os.stat(self.path.name, dir_fd=named, follow_symlinks=False)), "output_changed")
        finally:
            os.close(named)

    def directory(self, relative, *, create=False, deadline=None):
        parts = PurePosixPath(relative).parts if relative else ()
        require(len(parts) <= MAX_DEPTH and all(part not in (".", "..") and len(os.fsencode(part)) <= 255 for part in parts), "payload_invalid")
        current = os.dup(self.root)
        walked = []
        try:
            for part in parts:
                budget(self.deadline if deadline is None else deadline)
                walked.append(part); name = "/".join(walked)
                if name not in self.directories:
                    require(create and len(self.directories) < MAX_DIRECTORIES, "output_changed")
                    os.mkdir(part, 0o700, dir_fd=current)
                    # If metadata fails, unknown ownership is not rm authority.
                    self.directories[name] = None
                    information = os.stat(part, dir_fd=current, follow_symlinks=False)
                    self.directories[name] = directory_identity(information)
                    os.fsync(current)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                try:
                    information = os.fstat(child)
                    require(self.directories[name] == directory_identity(information)
                            and information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o700, "output_changed")
                except BaseException:
                    os.close(child)
                    raise
                os.close(current); current = child
            return current
        except BaseException:
            os.close(current)
            raise

    def write(self, relative, stream, size, expected=None):
        budget(self.deadline)
        path = PurePosixPath(relative)
        require(type(relative) is str and relative and str(path) == relative and not path.is_absolute()
                and not {".", ".."}.intersection(path.parts) and len(relative.encode()) <= 4096
                and len(path.parts) <= MAX_DEPTH and relative not in self.files and len(self.files) < MAX_FILES
                and type(size) is int and 0 <= size <= payload.MAX_FILE and self.total + size <= MAX_TOTAL, "byte_bound")
        parent = self.directory(str(path.parent) if str(path.parent) != "." else "", create=True)
        descriptor = None
        try:
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=parent)
            self.files[relative] = None
            first = os.fstat(descriptor)
            self.files[relative] = {"identity": witness(first), "sha256": None, "bytes": size}
            hashed, copied = hashlib.sha256(), 0
            while copied < size:
                budget(self.deadline)
                data = stream.read(min(65536, size - copied))
                require(type(data) is bytes and 0 < len(data) <= size - copied, "payload_invalid")
                offset = 0
                while offset < len(data):
                    budget(self.deadline)
                    written = os.write(descriptor, data[offset:])
                    require(written > 0, "output_unqualified")
                    offset += written
                hashed.update(data); copied += len(data)
            require(not stream.read(1) and (expected is None or hashed.hexdigest() == expected), "digest_mismatch")
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            final = os.fstat(descriptor)
            require(stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid() and stat.S_IMODE(final.st_mode) == 0o444
                    and final.st_nlink == 1 and final.st_size == size and (first.st_dev, first.st_ino) == (final.st_dev, final.st_ino)
                    and witness(final) == witness(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), "output_changed")
            self.files[relative] = {"identity": witness(final), "sha256": hashed.hexdigest(), "bytes": size}
            self.total += copied
            os.fsync(parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def verify(self):
        self.check_root()
        expected_entries = {"": set()}
        for name in (*self.directories, *self.files):
            path = PurePosixPath(name)
            parent = str(path.parent) if str(path.parent) != "." else ""
            expected_entries.setdefault(parent, set()).add(path.name)
            if name in self.directories:
                expected_entries.setdefault(name, set())
        def layout():
            for relative, expected in sorted(expected_entries.items()):
                directory = self.directory(relative)
                try:
                    remaining = set(expected)
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            budget(self.deadline)
                            require(entry.name in remaining, "output_changed")
                            remaining.remove(entry.name)
                    require(not remaining, "output_changed")
                    os.fsync(directory)
                finally:
                    os.close(directory)
        layout()
        for relative, record in sorted(self.files.items()):
            budget(self.deadline)
            require(record is not None, "output_changed")
            path = PurePosixPath(relative)
            parent = self.directory(str(path.parent) if str(path.parent) != "." else "")
            descriptor = None
            try:
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                require(witness(os.fstat(descriptor)) == record["identity"], "output_changed")
                hashed, length = hashlib.sha256(), 0
                while True:
                    budget(self.deadline)
                    data = os.read(descriptor, 65536)
                    if not data:
                        break
                    length += len(data); require(length <= record["bytes"], "byte_bound"); hashed.update(data)
                require(length == record["bytes"] and hashed.hexdigest() == record["sha256"]
                        and witness(os.fstat(descriptor)) == record["identity"], "output_changed")
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(parent)
        # Earlier files must still match after later files were read.
        for relative, record in sorted(self.files.items()):
            path = PurePosixPath(relative)
            parent = self.directory(str(path.parent) if str(path.parent) != "." else "")
            try:
                require(witness(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == record["identity"], "output_changed")
            finally:
                os.close(parent)
        layout(); self.check_root()

    def cleanup(self):
        if not self.created:
            return
        until = min(self.deadline + CLEANUP_SECONDS * 10**9, time.monotonic_ns() + CLEANUP_SECONDS * 10**9)
        require(self.root_identity is not None and self.root is not None, "cleanup_incomplete")
        # Only held-root entries are removed. A substituted named destination
        # cannot cause traversal/deletion through its new target.
        for relative, record in sorted(self.files.items(), key=lambda item: len(PurePosixPath(item[0]).parts), reverse=True):
            require(record is not None, "cleanup_incomplete")
            path = PurePosixPath(relative)
            parent = self.directory(str(path.parent) if str(path.parent) != "." else "", deadline=until)
            try:
                require(time.monotonic_ns() < until, "cleanup_incomplete")
                information = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                initial = record["identity"]
                require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                        and (information.st_dev, information.st_ino) == initial[:2], "cleanup_incomplete")
                os.unlink(path.name, dir_fd=parent); os.fsync(parent)
            finally:
                os.close(parent)
        for relative, identity in sorted(self.directories.items(), key=lambda item: len(PurePosixPath(item[0]).parts), reverse=True):
            require(identity is not None and time.monotonic_ns() < until, "cleanup_incomplete")
            path = PurePosixPath(relative)
            parent = self.directory(str(path.parent) if str(path.parent) != "." else "", deadline=until)
            try:
                require(directory_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == identity, "cleanup_incomplete")
                os.rmdir(path.name, dir_fd=parent); os.fsync(parent)
            finally:
                os.close(parent)
        self.check_root(deadline=until)
        with os.scandir(self.root) as entries:
            require(next(entries, None) is None, "cleanup_incomplete")
        os.rmdir(self.path.name, dir_fd=self.parent); os.fsync(self.parent)

    def close(self):
        failed = False
        for field in ("root", "parent"):
            descriptor = getattr(self, field)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        require(not failed, "cleanup_incomplete")


def stage(archive_path, archive_sha256, manifest_sha256, destination, deadline_ns):
    selectors(archive_path, destination, archive_sha256, manifest_sha256, deadline_ns)
    until = deadline_ns - CLEANUP_SECONDS * 10**9
    budget(until)
    source, task = Archive(archive_path, archive_sha256, until), None
    try:
        # The frozen pure validator has its own 300s ceiling. Reserve that
        # complete window inside the original deadline instead of resetting it.
        require(until - time.monotonic_ns() > (payload.SECONDS + 1) * 10**9, "deadline_exceeded")
        try:
            manifest = payload.validate_archive(source.data, manifest_sha256)
        except payload.PayloadError:
            raise StageError("payload_invalid") from None
        budget(until); source.check()
        task = Task(destination, until)
        source_archive = None
        with tarfile.open(fileobj=io.BytesIO(source.data), mode="r:") as archive:
            for member in archive:
                budget(until)
                expected = manifest_sha256 if member.name == "manifest.json" else manifest["members"][member.name]["sha256"]
                stream = archive.extractfile(member)
                task.write(member.name, stream, member.size, expected)
                if member.name == payload.MEMBERS["source_archive"]:
                    source_archive = source.data[member.offset_data:member.offset_data + member.size]
        require(source_archive is not None, "payload_invalid")
        source_count, source_bytes = 0, 0
        with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:gz") as archive:
            for member in archive:
                budget(until)
                require(member.isfile() and not member.pax_headers and member.size <= payload.MAX_FILE
                        and member.name and not member.name.startswith("/")
                        and str(PurePosixPath(member.name)) == member.name
                        and not {".", ".."}.intersection(PurePosixPath(member.name).parts), "payload_invalid")
                task.write("source/" + member.name, archive.extractfile(member), member.size)
                source_count += 1; source_bytes += member.size
        require(source_count == manifest["source"]["files"] and source_bytes == manifest["source"]["bytes"], "payload_invalid")
        source.check(); task.verify()
        task_id = Path(destination).name.removeprefix("yoga-stage-")
        receipt = {"schemaVersion": 1, "scope": "yoga-public-stage-v1", "taskId": task_id,
            "deadlineMonotonicNs": deadline_ns,
            "archiveSha256": archive_sha256, "manifestSha256": manifest_sha256, "archiveBytes": source.size,
            "sourceGraphSha256": manifest["selection"]["sourceGraphSha256"], "sourceFilesSha256": manifest["selection"]["sourceFilesSha256"],
            "members": manifest["members"], "storeRequirements": manifest["storeRequirements"],
            "source": manifest["source"], "dataFiles": len(task.files), "dataBytes": task.total,
            "destinationRegistrationVerified": False, "storePayloadIncluded": False, "closureImported": False,
            "executionAuthority": False, "activationPerformed": False, "toolbarConsentProved": False}
        encoded = payload.canonical(receipt)
        require(len(encoded) <= payload.MAX_METADATA, "byte_bound")
        task.write("stage-receipt.json", io.BytesIO(encoded), len(encoded), hashlib.sha256(encoded).hexdigest())
        task.verify(); source.check(); os.fsync(task.parent); budget(until)
        return {"scope": "yoga-public-stage-complete", "taskId": task_id, "receiptSha256": hashlib.sha256(encoded).hexdigest(),
            "archiveSha256": archive_sha256, "manifestSha256": manifest_sha256, "dataFiles": receipt["dataFiles"], "dataBytes": receipt["dataBytes"],
            "destinationRegistrationVerified": False, "closureImported": False, "executionAuthority": False, "toolbarConsentProved": False}
    except BaseException:
        if task is not None:
            try:
                task.cleanup()
            except BaseException:
                raise StageError("cleanup_incomplete") from None
        raise
    finally:
        try:
            if task is not None:
                task.close()
        finally:
            source.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise StageError("selector_invalid")


def main():
    parser = Parser(description=__doc__)
    for flag in ("archive", "archive-sha256", "manifest-sha256", "destination"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--deadline-monotonic-ns", required=True, type=int)
    args = parser.parse_args()
    result = stage(args.archive, args.archive_sha256, args.manifest_sha256, args.destination, args.deadline_monotonic_ns)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        reason = error.reason if isinstance(error, StageError) else "payload_invalid"
        print(json.dumps({"scope": "yoga-public-stage-refused", "reason": reason,
            "executionAuthority": False, "toolbarConsentProved": False}), file=sys.stderr)
        sys.exit(125)
