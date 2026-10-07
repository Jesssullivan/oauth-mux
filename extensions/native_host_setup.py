"""Emit or explicitly register Omux's restricted native-messaging host.

The default only prints reviewable JSON. Installation is per-user and never
replaces an unmanaged or changed file. An ownership receipt binds the original
manifest bytes and file identity; registration performs no browser/provider IO.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HOST = "ai.xoxd.omux"
FIREFOX_ID = "browser-sources@omux.xoxd.ai"
MANIFEST_NAME = HOST + ".json"
MAX_FILE_BYTES = 16 * 1024
CHANNEL_HOSTS = {"release": HOST, "development": HOST + ".dev"}
CHANNEL_FIREFOX_IDS = {"release": FIREFOX_ID, "development": "browser-sources-dev@omux.xoxd.ai"}


class SetupError(Exception):
    """Safe registration failure; no credential or provider payload is included."""


def _absolute(path, description):
    value = str(path)
    if not value or any(c in value for c in "\x00\r\n"):
        raise SetupError(description + " must be an explicit absolute path")
    result = Path(value)
    if not result.is_absolute() or ".." in result.parts:
        raise SetupError(description + " must be an explicit absolute path")
    return result


def host_name(channel="release"):
    if channel not in CHANNEL_HOSTS:
        raise SetupError("channel must be release or development")
    return CHANNEL_HOSTS[channel]


def manifest(browser, extension_id, binary, channel="release"):
    """Return the exact browser-specific manifest; binary need not exist yet."""
    binary = _absolute(binary, "host binary")
    if binary.name != "omux-native-host":
        raise SetupError("host binary must be the installed omux-native-host alias")
    output = {
        "name": host_name(channel),
        "description": "Omux restricted browser source bridge",
        "path": str(binary),
        "type": "stdio",
    }
    if browser == "chromium":
        if not isinstance(extension_id, str) or not re.fullmatch(r"[a-p]{32}", extension_id):
            raise SetupError("Chromium extension ID must contain exactly 32 lowercase a-p characters")
        output["allowed_origins"] = ["chrome-extension://" + extension_id + "/"]
    elif browser == "firefox":
        firefox_id = CHANNEL_FIREFOX_IDS[channel]
        if extension_id != firefox_id:
            raise SetupError("Firefox extension ID must equal " + firefox_id)
        output["allowed_extensions"] = [firefox_id]
    else:
        raise SetupError("browser must be chromium or firefox")
    return output


def _bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _destination(path, channel="release"):
    path = _absolute(path, "manifest destination")
    name = host_name(channel) + ".json"
    if path.name != name:
        raise SetupError("manifest destination basename must be " + name)
    return path


@contextmanager
def _directory(destination):
    """Walk without following symlinks, retain the directory FD during mutation."""
    _binary_parents(destination.parent)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in destination.parent.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise SetupError("manifest directory must be user-owned and not writable by other users")
        # Cooperating invocations serialize here; uncooperative same-user
        # changes are detected before mutation, not cryptographically prevented.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield descriptor
    except OSError as error:
        raise SetupError("manifest directory is missing, linked, unsafe, or in use") from error
    finally:
        os.close(descriptor)


@dataclass
class Entry:
    data: bytes
    info: os.stat_result


def _identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _read(directory, name):
    # Inspect the entry without opening or following a generation symlink.
    try:
        target = os.readlink(name, dir_fd=directory)
    except OSError:
        pass
    else:
        if target.startswith("/nix/store/") or target.startswith("/nix/var/nix/profiles/"):
            raise SetupError("registration is declaratively managed; change Home Manager browser host configuration and activate its generation")
        raise SetupError("registration path is linked; preserve it and review Home Manager configuration or manual ownership before changing registration")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SetupError("registration path is linked or unreadable") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise SetupError("registration file owner, type, or permissions changed")
        if info.st_size > MAX_FILE_BYTES:
            raise SetupError("registration file exceeds its size limit")
        data = bytearray()
        while len(data) <= MAX_FILE_BYTES:
            part = os.read(descriptor, MAX_FILE_BYTES + 1 - len(data))
            if not part:
                break
            data.extend(part)
        after = os.fstat(descriptor)
        if len(data) > MAX_FILE_BYTES or _identity(info) != _identity(after):
            raise SetupError("registration file changed while reading")
        return Entry(bytes(data), after)
    finally:
        os.close(descriptor)


def _create(directory, name, data):
    if len(data) > MAX_FILE_BYTES:
        raise SetupError("registration data exceeds its size limit")
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    except OSError as error:
        raise SetupError("registration path already exists or cannot be created") from error
    try:
        # Deliberately never chmod/chown an existing file.
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written == 0:
                raise SetupError("registration write did not complete")
            offset += written
        os.fsync(descriptor)
        return Entry(data, os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SetupError("ownership receipt contains duplicate fields")
        result[key] = value
    return result


def _owned(directory, name, expected):
    current = _read(directory, name)
    receipt = _read(directory, name + ".omux-owner.json")
    if current is None and receipt is None:
        return None
    if current is None or receipt is None:
        raise SetupError("registration has no complete ownership receipt; manual review required")
    try:
        owner = json.loads(receipt.data, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError) as error:
        raise SetupError("ownership receipt is invalid") from error
    expected_owner = {
        "schema": 1,
        "managed_by": json.loads(expected)["name"],
        "manifest": _identity(current.info),
        "sha256": hashlib.sha256(current.data).hexdigest(),
    }
    if owner != expected_owner or receipt.data != _bytes(expected_owner) or current.data != expected:
        raise SetupError("registration or ownership receipt was modified; refusing replacement or removal")
    return current, receipt


def _binary(path):
    try:
        current = path
        seen = set()
        for _ in range(40):
            _binary_parents(current.parent)
            info = current.lstat()
            if info.st_uid not in (0, os.geteuid()):
                raise SetupError("installed host alias is not trusted-owned")
            if stat.S_ISLNK(info.st_mode):
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    raise SetupError("installed host alias contains a symlink cycle")
                seen.add(identity)
                target = Path(os.readlink(current))
                # Do not lexically collapse symlink/.. traversals: the kernel
                # follows their components before handling the parent step.
                # The installed same-directory alias needs no such traversal.
                if ".." in target.parts:
                    raise SetupError("installed host alias must not use parent-directory traversal")
                if not target.is_absolute():
                    target = current.parent / target
                current = Path(os.path.normpath(str(target)))
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022 or not os.access(current, os.X_OK):
                raise SetupError("installed host binary must be executable, trusted-owned, and not writable by other users")
            return
        raise SetupError("installed host alias exceeds its symlink limit")
    except OSError as error:
        raise SetupError("installed host binary is missing or unreadable") from error


def _binary_parents(parent):
    """Protect both a packaged alias location and the resolved executable path."""
    for directory in (parent, *parent.parents):
        try:
            info = directory.lstat()
        except OSError as error:
            raise SetupError("native-host directory is missing or unreadable") from error
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise SetupError("host executable directories must be real and trusted-owned")
        mode = stat.S_IMODE(info.st_mode)
        # System sticky directories preserve ownership of each child entry;
        # fixtures and safe private installations may live below /tmp.
        sticky_system_directory = info.st_uid == 0 and mode & stat.S_ISVTX
        if mode & 0o022 and not sticky_system_directory:
            raise SetupError("host executable directory is writable by other users")


def _unlink_unchanged(directory, name, entry):
    current = _read(directory, name)
    if current is None or _identity(current.info) != _identity(entry.info) or current.data != entry.data:
        raise SetupError("registration changed before removal; refusing deletion")
    os.unlink(name, dir_fd=directory)


def install(browser, extension_id, binary, destination, channel="release"):
    expected = _bytes(manifest(browser, extension_id, binary, channel))
    binary = _absolute(binary, "host binary")
    _binary(binary)
    destination = _destination(destination, channel)
    with _directory(destination) as directory:
        if _owned(directory, destination.name, expected) is not None:
            return "unchanged"
        created = _create(directory, destination.name, expected)
        receipt = _bytes({
            "schema": 1,
            "managed_by": host_name(channel),
            "manifest": _identity(created.info),
            "sha256": hashlib.sha256(expected).hexdigest(),
        })
        try:
            _create(directory, destination.name + ".omux-owner.json", receipt)
        except (OSError, SetupError):
            # Roll back only the unchanged inode this invocation created.
            _unlink_unchanged(directory, destination.name, created)
            os.fsync(directory)
            raise
        os.fsync(directory)
        return "installed"


def remove(browser, extension_id, binary, destination, channel="release"):
    expected = _bytes(manifest(browser, extension_id, binary, channel))
    destination = _destination(destination, channel)
    with _directory(destination) as directory:
        owned = _owned(directory, destination.name, expected)
        if owned is None:
            return "absent"
        current, receipt = owned
        _unlink_unchanged(directory, destination.name, current)
        _unlink_unchanged(directory, destination.name + ".omux-owner.json", receipt)
        os.fsync(directory)
        return "removed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("emit", "install", "remove"), nargs="?", default="emit")
    parser.add_argument("--browser", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--extension-id", required=True)
    parser.add_argument("--channel", choices=tuple(CHANNEL_HOSTS), default="release")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--manifest", help="explicit destination in an existing browser native-host directory")
    args = parser.parse_args(argv)
    try:
        if args.action == "emit":
            if args.manifest:
                _destination(args.manifest, args.channel)
            sys.stdout.write(_bytes(manifest(args.browser, args.extension_id, args.binary, args.channel)).decode("utf-8"))
        else:
            if not args.manifest:
                parser.error("install/remove require --manifest")
            action = install if args.action == "install" else remove
            print(action(args.browser, args.extension_id, args.binary, args.manifest, args.channel))
    except (OSError, SetupError) as error:
        print("Omux host setup: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
