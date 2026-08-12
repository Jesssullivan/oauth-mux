#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def fail(message: str) -> None:
    raise RuntimeError(message)


def directory_identity(fd: int) -> tuple[int, int, int, int]:
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or mode != 0o700:
        fail("owned temporary root lost private current-user directory custody")
    return info.st_dev, info.st_ino, info.st_uid, mode


def open_owned_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        directory_identity(fd)
    except Exception:
        os.close(fd)
        raise
    return fd


def trusted_parent_identity(fd: int) -> tuple[int, int, int, int]:
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
        fail("temporary parent is not owned by root or the current user")
    if mode & 0o022 and not (info.st_mode & stat.S_ISVTX):
        fail("temporary parent is writable without sticky-bit custody")
    return info.st_dev, info.st_ino, info.st_uid, mode


def validate_temporary_ancestors(parent: Path) -> None:
    if not parent.is_absolute():
        fail(f"temporary parent is not an absolute regular directory: {parent}")
    current = parent
    while True:
        info = os.stat(current, follow_symlinks=False)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            fail(f"temporary ancestor lacks root/current-user custody: {current}")
        if mode & 0o022 and not (info.st_mode & stat.S_ISVTX):
            fail(f"temporary ancestor is writable without sticky-bit custody: {current}")
        if current.parent == current:
            return
        current = current.parent


def open_temporary_parent(parent: Path) -> tuple[int, tuple[int, int, int, int]]:
    validate_temporary_ancestors(parent)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(parent, flags)
    try:
        identity = trusted_parent_identity(fd)
        current = os.stat(parent, follow_symlinks=False)
        path_identity = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
        )
        if path_identity != identity:
            fail("temporary parent path changed while opening")
    except Exception:
        os.close(fd)
        raise
    return fd, identity


def same_entry(fd: int, name: str, expected: os.stat_result) -> bool:
    try:
        actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError:
        return False
    return (actual.st_dev, actual.st_ino, actual.st_mode) == (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
    )


def clear_directory(fd: int, excluded_names: frozenset[str] = frozenset()) -> None:
    for name in os.listdir(fd):
        if name in excluded_names:
            continue
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            child_fd = os.open(name, flags, dir_fd=fd)
            try:
                child_info = os.fstat(child_fd)
                if (child_info.st_dev, child_info.st_ino, child_info.st_mode) != (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                ):
                    fail(f"owned cleanup directory changed while opening: {name}")
                clear_directory(child_fd)
                if not same_entry(fd, name, info):
                    fail(f"owned cleanup directory changed before removal: {name}")
                os.rmdir(name, dir_fd=fd)
            finally:
                os.close(child_fd)
        else:
            if not same_entry(fd, name, info):
                fail(f"owned cleanup entry changed before removal: {name}")
            os.unlink(name, dir_fd=fd)


@dataclass
class OwnedRoot:
    path: Path
    fd: int
    identity: tuple[int, int, int, int]

    @classmethod
    def create(
        cls,
        parent: Path,
        prefix: str,
        inherited_parent_fd: int | None = None,
    ) -> "OwnedRoot":
        if inherited_parent_fd is None:
            parent_fd, _ = open_temporary_parent(parent)
        else:
            parent_fd = os.dup(inherited_parent_fd)
            try:
                expected_parent = directory_identity(parent_fd)
                current_parent = os.stat(parent, follow_symlinks=False)
                path_identity = (
                    current_parent.st_dev,
                    current_parent.st_ino,
                    current_parent.st_uid,
                    stat.S_IMODE(current_parent.st_mode),
                )
                if path_identity != expected_parent:
                    fail("owned temporary parent path changed before nested creation")
            except Exception:
                os.close(parent_fd)
                raise
        try:
            for _ in range(128):
                name = f"{prefix}.{secrets.token_hex(8)}"
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                break
            else:
                fail("could not allocate a unique owned temporary root")

            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(name, flags, dir_fd=parent_fd)
            except Exception:
                os.rmdir(name, dir_fd=parent_fd)
                raise
            try:
                identity = directory_identity(fd)
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                entry_identity = (
                    current.st_dev,
                    current.st_ino,
                    current.st_uid,
                    stat.S_IMODE(current.st_mode),
                )
                path = parent / name
                try:
                    path_info = os.stat(path, follow_symlinks=False)
                except OSError:
                    fail("owned temporary root path changed during creation")
                path_identity = (
                    path_info.st_dev,
                    path_info.st_ino,
                    path_info.st_uid,
                    stat.S_IMODE(path_info.st_mode),
                )
                if entry_identity != identity or path_identity != identity:
                    fail("owned temporary root path changed during creation")
            except Exception:
                os.close(fd)
                os.rmdir(name, dir_fd=parent_fd)
                raise
            return cls(path=path, fd=fd, identity=identity)
        finally:
            os.close(parent_fd)

    @classmethod
    def adopt(cls, path: Path, inherited_fd: int) -> "OwnedRoot":
        if not path.is_absolute():
            fail("adopted temporary root path is not absolute")
        fd = os.dup(inherited_fd)
        try:
            identity = directory_identity(fd)
            current = os.stat(path, follow_symlinks=False)
            path_identity = (
                current.st_dev,
                current.st_ino,
                current.st_uid,
                stat.S_IMODE(current.st_mode),
            )
            if path_identity != identity:
                fail("adopted temporary root path does not name the inherited directory")
        except Exception:
            os.close(fd)
            raise
        return cls(path=path, fd=fd, identity=identity)

    def cleanup(self, excluded_names: frozenset[str] = frozenset()) -> bool:
        safe = True
        try:
            if directory_identity(self.fd) != self.identity:
                fail("opened temporary root identity changed")
            clear_directory(self.fd, excluded_names)
        except (OSError, RuntimeError) as error:
            print(f"owned temporary root cleanup refused: {error}", file=sys.stderr)
            safe = False

        try:
            current = os.stat(self.path, follow_symlinks=False)
            path_identity = (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode))
        except OSError:
            path_identity = None
        if path_identity != self.identity:
            print(f"owned temporary root path changed; replacement left untouched: {self.path}", file=sys.stderr)
            safe = False

        # There is no race-free pathname operation for removing an opened top
        # directory. Its descriptor-owned contents are gone; intentionally leak
        # the empty root instead of risking deletion of a swapped replacement.
        os.close(self.fd)
        return safe


def parse_root_spec(value: str) -> tuple[str, str]:
    environment_name, separator, prefix = value.partition(":")
    if (
        not separator
        or not environment_name
        or not prefix
        or not environment_name.replace("_", "A").isalnum()
        or not environment_name[0].isalpha()
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for character in prefix)
    ):
        raise argparse.ArgumentTypeError("root specification must be ENVIRONMENT_NAME:portable-prefix")
    return environment_name, prefix


def parse_adopted_root(value: list[str]) -> tuple[str, int, Path]:
    environment_name, fd_text, path_text = value
    parse_root_spec(f"{environment_name}:owned-root")
    try:
        inherited_fd = int(fd_text, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("adopted root descriptor must be an integer") from error
    if inherited_fd < 3:
        raise argparse.ArgumentTypeError("adopted root descriptor must not be a standard stream")
    return environment_name, inherited_fd, Path(path_text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adopt-root", nargs=3, action="append", default=[])
    parser.add_argument("--root", action="append", default=[], type=parse_root_spec)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a child command is required")
    if not arguments.adopt_root and not arguments.root:
        parser.error("at least one adopted or created root is required")

    temporary_parent = Path(os.path.realpath(os.environ.get("TMPDIR", tempfile.gettempdir())))
    roots: list[OwnedRoot] = []
    environment = os.environ.copy()
    child: subprocess.Popen[bytes] | None = None
    received_signal: int | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal received_signal
        received_signal = signum
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    previous_handlers = {signum: signal.signal(signum, forward) for signum in MANAGED_SIGNALS}
    status = 1
    cleanup_ok = True
    try:
        parent = temporary_parent
        for raw_adopted_root in arguments.adopt_root:
            environment_name, inherited_fd, path = parse_adopted_root(raw_adopted_root)
            root = OwnedRoot.adopt(path, inherited_fd)
            roots.append(root)
            environment[environment_name] = str(root.path)
            environment[f"{environment_name}_FD"] = str(root.fd)
            parent = root.path
        for environment_name, prefix in arguments.root:
            inherited_parent_fd = roots[-1].fd if roots else None
            root = OwnedRoot.create(parent, prefix, inherited_parent_fd)
            roots.append(root)
            environment[environment_name] = str(root.path)
            environment[f"{environment_name}_FD"] = str(root.fd)
            parent = root.path
        child = subprocess.Popen(
            command,
            env=environment,
            start_new_session=True,
            pass_fds=tuple(root.fd for root in roots),
        )
        child_status = child.wait()
        status = 128 + received_signal if received_signal is not None else (
            128 - child_status if child_status < 0 else child_status
        )
    except (OSError, RuntimeError) as error:
        print(f"owned temporary root runner failed: {error}", file=sys.stderr)
        status = 1
    finally:
        protected_by_parent: dict[int, set[str]] = {}
        for index in range(len(roots) - 1, -1, -1):
            root = roots[index]
            exclusions = frozenset(protected_by_parent.get(index, set()))
            removed = root.cleanup(exclusions)
            cleanup_ok = cleanup_ok and removed
            if not removed and index > 0:
                protected_by_parent.setdefault(index - 1, set()).add(root.path.name)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if received_signal is not None:
            status = 128 + received_signal
    if status == 0 and not cleanup_ok:
        return 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
