"""Offline retained runtime009 operator input admission; never native authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_owner_runtime_input as runtime

VARIABLE = "OMUX_CODEX_OWNER_RUNTIME_DIRECTORY"
DIAGNOSTIC = "//delivery:installed_legacy_native_fd2_diagnostic_test"
CONSUMERS = frozenset((
    DIAGNOSTIC,
    "//delivery:installed_native_interop_test",
    "//delivery:installed_native_discovery_test",
    "//delivery:installed_legacy_native_tui_test",
    "//tools:codex_owner_runtime_input_copy",
    "//tools:codex_owner_runtime_input_qualification",
))
COMPANIONS = frozenset((
    "//tools:codex_owner_runtime_input_test",
    "//tools:guard_owner_runtime_input_test",
    "//tools:execution_guard_test",
    "//tools:guard_dependency_profile_test",
    "//tools:runtime_source_receipt", "//:docs_check",
))


def finite(profile, arguments, unrelated=()):
    if profile == 'codex-live':
        from guard_codex_live_profile import LABEL, selected
        selected(arguments)
        if arguments != ['test', LABEL] or any(unrelated):
            raise ValueError('retained-input-profile')
        return
    if (DIAGNOSTIC in arguments and set(arguments[1:]) - {DIAGNOSTIC} - COMPANIONS):
        raise ValueError("retained-diagnostic-profile")
    if (profile != "standard" or not arguments or arguments[0] not in ("build", "test")
            or len(arguments) < 2 or len(arguments[1:]) != len(set(arguments[1:]))
            or not set(arguments[1:]) & CONSUMERS
            or not set(arguments[1:]) <= CONSUMERS | COMPANIONS
            or any(unrelated)):
        raise ValueError("retained-input-profile")


def leaf_custody(info):
    """Admit private producer custody or exact Bazel-sealed retained output."""
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in (0o700, 0o555)):
        raise ValueError("retained-directory-custody")


def archive_custody(directory_info, archive_info):
    if (stat.S_IMODE(directory_info.st_mode), stat.S_IMODE(archive_info.st_mode)) not in (
            (0o700, 0o400), (0o555, 0o555)):
        raise ValueError("retained-archive-mode")


def directory(path):
    """Hold the named leaf after a physical no-follow ancestor walk."""
    path = Path(path)
    if (not path.is_absolute() or str(path) == "/" or len(os.fsencode(path)) > 4096
            or any(part in ("", ".", "..") for part in str(path).split("/")[1:])
            or any(char in str(path) for char in "\\\n\r\x00")):
        raise ValueError("retained-directory-selector")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(child)
                if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                    raise ValueError("retained-directory-custody")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        leaf_custody(info)
        return fd
    except BaseException:
        os.close(fd)
        raise


def membership(fd):
    with os.scandir(fd) as entries:
        first = next(entries, None)
        second = next(entries, None)
        if first is None or first.name != runtime.NAME or second is not None:
            raise ValueError("retained-directory-membership")


class Admission:
    def __init__(self, root, manifest, receipt, source_root, deadline_ns):
        self.root = Path(root)
        self.manifest, self.receipt = Path(manifest), Path(receipt)
        self.deadline_ns = deadline_ns
        self.directory_fd = self.archive_fd = None
        try:
            runtime.budget(deadline_ns)
            source_root = Path(source_root).resolve(strict=True)
            if self.root.name != runtime.ARCHIVE_SHA or self.root.is_relative_to(source_root):
                raise ValueError("retained-directory-scope")
            self.directory_fd = directory(self.root)
            self.directory_identity = runtime.identity(os.fstat(self.directory_fd))
            membership(self.directory_fd)
            self.archive_fd = os.open(runtime.NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory_fd)
            archive_custody(os.fstat(self.directory_fd), os.fstat(self.archive_fd))
            self.archive_identity = runtime.stream_digest(self.archive_fd, deadline_ns)
            self.metadata = runtime.pinned_metadata(self.manifest, self.receipt, deadline_ns)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def facts(self):
        return {"archiveSha256": runtime.ARCHIVE_SHA, "archiveBytes": runtime.ARCHIVE_BYTES,
                "manifestSha256": runtime.MANIFEST_SHA, "directory": str(self.root),
                "physicalDirectory": self.directory_identity, "physicalArchive": self.archive_identity,
                "trackedMetadata": self.metadata, "nativeSupport": False,
                "scope": "Retained proof input byte/custody identity; no installed, executable, source lineage or channel authority."}

    def recheck(self):
        runtime.budget(self.deadline_ns)
        named = directory(self.root)
        try:
            membership(named)
            if (runtime.identity(os.fstat(named)) != self.directory_identity
                    or runtime.identity(os.stat(runtime.NAME, dir_fd=named, follow_symlinks=False)) != self.archive_identity
                    or runtime.stream_digest(self.archive_fd, self.deadline_ns) != self.archive_identity
                    or runtime.pinned_metadata(self.manifest, self.receipt, self.deadline_ns) != self.metadata):
                raise ValueError("retained-input-changed")
        finally:
            os.close(named)
        return self.facts()

    def runtime_seconds(self):
        runtime.budget(self.deadline_ns)
        seconds = (self.deadline_ns - time.monotonic_ns() - runtime.CLEANUP_RESERVE_NS) // 10**9
        if seconds < 1:
            raise ValueError("retained-input-deadline")
        return min(1200, seconds)

    def close(self):
        primary = sys.exc_info()[1]
        failure = None
        for name in ("archive_fd", "directory_fd"):
            fd = getattr(self, name, None)
            setattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    failure = failure or error
        if failure is not None:
            if primary is not None:
                primary.add_note("retained-input-close-refused")
            else:
                raise OSError("retained-input-close-refused") from failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if not os.environ.get("OMUX_EXECUTION_GUARD") or not os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"):
        raise ValueError("retained-qualification-requires-declared-test")
    selected = Admission(args.archive.resolve(strict=True).parent, args.manifest, args.receipt,
                         Path.cwd(), time.monotonic_ns() + 600 * 10**9)
    try:
        report = selected.recheck()
        output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
        fd = os.open(output / "retained-runtime-qualification.json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            runtime.write_all(fd, (json.dumps(report, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        selected.close()
    print("OMUX_RETAINED_RUNTIME_INPUT_QUALIFICATION_OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError):
        print("OMUX_RETAINED_RUNTIME_INPUT_QUALIFICATION_REFUSED", file=sys.stderr)
        sys.exit(125)
