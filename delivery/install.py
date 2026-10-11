"""Explicit, ownership-recorded local installation. No account-store deletion.

Service files are installed only when requested. This tool does not modify
native application configuration, start a service, or claim portable packaging.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from xml.sax.saxutils import escape

from pack import BINARIES, MAX_FILES, digest, json_bytes, read_bundle, verify_bundle

RECORD = "install.json"


def _absolute(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("installation paths must be absolute without traversal")
    return path


def _safe_directory(path: Path, create: bool = False, private: bool = False) -> None:
    _absolute(path)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not current.exists() and not current.is_symlink() and create:
            current.mkdir(mode=0o700)
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, os.getuid()}:
            raise ValueError("unsafe directory type or owner")
        writable = stat.S_IMODE(metadata.st_mode) & 0o022
        root_sticky = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        if writable and not root_sticky:
            raise ValueError("installation directory is writable by another user")
    if private:
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("installation record directory must be private")


def _read_regular(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_size > limit:
            raise ValueError("unsafe installation file")
        with os.fdopen(os.dup(descriptor), "rb") as reader:
            result = reader.read(limit + 1)
        if len(result) > limit:
            raise ValueError("installation file exceeds limit")
        return result
    finally:
        os.close(descriptor)


def _write(path: Path, data: bytes, mode: int) -> None:
    _safe_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".omux-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(data)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def _directory_lock(directory: Path, name: str, private: bool, *, nonblocking=False):
    _safe_directory(directory, create=True, private=private)
    descriptor = os.open(directory / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("unsafe installation lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        yield
    finally:
        os.close(descriptor)


def _lock(state_dir: Path):
    return _directory_lock(state_dir, "install.lock", private=True)


def _prefix_lock(prefix: Path):
    # Serialize competing installers even when they use different record roots.
    return _directory_lock(prefix, ".omux-install.lock", private=False)


def _record(prefix: Path, state_dir: Path) -> dict | None:
    path = state_dir / RECORD
    if not path.exists() and not path.is_symlink():
        return None
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise ValueError("ownership record must be private")
    result = json.loads(_read_regular(path))
    if result.get("schemaVersion") != 1 or result.get("prefix") != str(prefix):
        raise ValueError("ownership record does not match installation")
    known = {str(prefix / "bin" / name) for name in (*BINARIES, "omux-control")}
    if result.get("userService") is not None:
        known.add(result["userService"])
    files = result.get("files", [])
    if len(files) > MAX_FILES or len({item["path"] for item in files}) != len(files):
        raise ValueError("invalid ownership record")
    for item in files:
        path = Path(item["path"])
        try:
            relative = str(path.relative_to(prefix))
        except ValueError:
            relative = ""
        runtime_path = re.fullmatch(r"lib/omux/(?:lib/[A-Za-z0-9_.+-]+|libexec/omuxd?\.bin|share/ca-bundle\.crt|qt/lib/[A-Za-z0-9_.+-]+|qt/libexec/(?:omux-control\.bin|qt\.conf)|qt/plugins/platforms/[A-Za-z0-9_.+-]+\.so)", relative)
        if (item["path"] not in known and not runtime_path) or item["mode"] not in [0o600, 0o644, 0o755]:
            raise ValueError("ownership record contains an unmanaged path")
        _absolute(Path(item["path"]))
    return result


def _matches(path: Path, entry: dict) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    try:
        _safe_directory(path.parent)
        metadata = path.lstat()
        return stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == entry["mode"] and digest(_read_regular(path, 128 * 1024 * 1024)) == entry["sha256"]
    except (OSError, ValueError):
        return False


def installation_plan(manifest, files, prefix, state_dir, user_service=None, platform="linux",
                      *, daemon_state_dir=None):
    """Render exact public placement; callers must independently verify archive bytes."""
    _absolute(prefix)
    _absolute(state_dir)
    if platform not in {"linux", "macos"} or not manifest["target"].endswith("-" + platform):
        raise ValueError("bundle and service platform differ")
    if user_service is not None:
        _absolute(user_service)
    if daemon_state_dir is not None:
        _absolute(daemon_state_dir)
        if user_service is None or platform != "linux":
            raise ValueError("explicit daemon state requires a Linux owned service")
        if any(char in str(daemon_state_dir) for char in "\n\r\x00"):
            raise ValueError("unsafe daemon state path")
    channel = manifest.get("channel")
    instance = {"development": "dev", "release": "default"}.get(channel)
    if user_service is not None and platform == "linux" and instance is not None:
        expected_service = "ai.xoxd.omux.dev.service" if instance == "dev" else "ai.xoxd.omux.service"
        if user_service.name != expected_service:
            raise ValueError("installed service identity does not match artifact channel")
    destinations = [(prefix / "bin" / name, files["bin/" + name], 0o755) for name in BINARIES]
    if "bin/omux-control" in files:
        destinations.append((prefix / "bin/omux-control", files["bin/omux-control"], 0o755))
    artifact_modes = {item["path"]: int(item["mode"], 8) for item in manifest["artifacts"]}
    for name in sorted(files):
        if name.startswith("lib/omux/"):
            destinations.append((prefix / name, files[name], artifact_modes[name]))
    if user_service:
        executable = str(prefix / "bin/omuxd")
        if any(char in executable for char in "\n\r\x00"):
            raise ValueError("unsafe executable path")
        if platform == "linux":
            # systemd expands percent specifiers even inside quoted values.
            escaped = executable.replace("%", "%%").replace("$", "$$").replace("\\", "\\\\").replace('"', '\\"')
            replacement = '"' + escaped + '"'
            if daemon_state_dir is not None:
                state_argument = str(daemon_state_dir).replace("%", "%%").replace("$", "$$").replace("\\", "\\\\").replace('"', '\\"')
                replacement += ' --state-dir "' + state_argument + '"'
            template = files["share/omux/services/omux.service.in"].decode()
            bindings = {"OMUX_INSTALL_PREFIX": str(prefix),
                        "OMUX_INSTALL_RECORD": str(state_dir / RECORD),
                        "OMUX_INSTALL_SERVICE_PATH": str(user_service)}
            if daemon_state_dir is not None:
                runtime = "/run/user/" + str(os.getuid())
                bindings.update(DBUS_SESSION_BUS_ADDRESS="unix:path=" + runtime + "/bus",
                                XDG_RUNTIME_DIR=runtime)
            if instance is not None:
                bindings["OMUX_INSTANCE"] = instance
            template += "\n[Service]\n"
            if daemon_state_dir is not None:
                # Finite resident reservation, independent of proof lifetime.
                template += "MemoryMax=268435456\nMemorySwapMax=0\nTasksMax=32\nCPUQuota=10%\n"
            for key, value in bindings.items():
                if any(char in value for char in "\n\r\x00"):
                    raise ValueError("unsafe installation binding")
                # Environment= performs specifier expansion, not $ expansion.
                quoted = value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
                template += f'Environment="{key}={quoted}"\n'
        else:
            replacement = escape(executable)
            template = files["share/omux/services/dev.xoxd.omux.plist.in"].decode()
        destinations.append((user_service, template.replace("@EXEC@", replacement).encode(), 0o600))
    return destinations


def install_bundle(payload: bytes, prefix: Path, state_dir: Path,
                   user_service: Path | None = None, platform: str = "linux",
                   *, daemon_state_dir: Path | None = None, _owned_update=None, _owned_prepare=None) -> dict:
    if _owned_prepare is not None and _owned_update is not None:
        raise ValueError("owned installation purposes overlap")
    bounded_owned = _owned_update is not None or _owned_prepare is not None
    if _owned_prepare is not None:
        before_prepare, after_prepare, deadline_ns = _owned_prepare
        if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
            raise ValueError("owned preparation deadline expired")
    manifest, files = verify_bundle(payload)
    destinations = installation_plan(manifest, files, prefix, state_dir, user_service, platform,
                                    daemon_state_dir=daemon_state_dir)
    # Validate the complete file layout before creating either custody lock.
    # A service cannot replace a payload, ownership record or active lock, nor
    # can a requested file occupy a directory required by another such file.
    planned = [path for path, _, _ in destinations]
    controls = [state_dir / RECORD, state_dir / "install.lock", prefix / ".omux-install.lock"]
    for index, path in enumerate(planned):
        for other in planned[index + 1:] + controls:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError("installation file paths collide")
    with _directory_lock(state_dir, "install.lock", private=True, nonblocking=bounded_owned), \
            _directory_lock(prefix, ".omux-install.lock", private=False, nonblocking=bounded_owned):
        previous = _record(prefix, state_dir)
        if _owned_prepare is not None:
            if previous is not None or time.monotonic_ns() >= deadline_ns:
                raise ValueError("owned preparation requires new unrecorded placement")
            before_prepare()
        if previous and previous["userService"] != (str(user_service) if user_service else None):
            raise ValueError("remove the owned installation before changing service placement")
        if _owned_update is not None:
            expected_archive, before_replace, after_replace, deadline_ns = _owned_update
            if previous is None or previous["artifact"]["archiveSha256"] != expected_archive:
                raise ValueError("owned update previous archive differs")
            if not all(_matches(Path(entry["path"]), entry) for entry in previous["files"]):
                raise ValueError("owned update previous payload differs")
            before_replace()
        previous_record = _read_regular(state_dir / RECORD) if previous is not None else None
        owned = {item["path"]: item for item in previous["files"]} if previous else {}
        # Preflight all targets before writing any executable or service file.
        for path, _, _ in destinations:
            if _owned_prepare is not None and time.monotonic_ns() >= deadline_ns:
                raise ValueError("owned preparation deadline expired")
            if path.exists() or path.is_symlink():
                if str(path) not in owned or not _matches(path, owned[str(path)]):
                    raise ValueError("refusing to overwrite an unowned or modified file")
            _safe_directory(path.parent, create=True)
        destination_paths = {str(path) for path, _, _ in destinations}
        obsolete = [Path(name) for name, entry in owned.items() if name not in destination_paths
                    and (Path(name).exists() or Path(name).is_symlink())]
        for path in obsolete:
            if not _matches(path, owned[str(path)]):
                raise ValueError("refusing to replace an installation containing modified owned files")
        originals = {str(path): (_read_regular(path, 128 * 1024 * 1024), path.stat().st_mode & 0o777)
                     for path, _, _ in destinations if path.exists()}
        originals.update({str(path): (_read_regular(path, 128 * 1024 * 1024), path.stat().st_mode & 0o777) for path in obsolete})
        written: list[Path] = []
        removed: list[Path] = []
        result = {
            "schemaVersion": 1, "prefix": str(prefix), "product": manifest["product"],
            "userService": str(user_service) if user_service else None,
            "serviceActivated": False,
            # Integrity-bound producer declarations, never release attestation.
            # Older archives omit channel; keep that uncertainty explicit.
            "artifact": {"channel": manifest.get("channel", "unknown"),
                         "target": manifest["target"], "distribution": manifest["distribution"],
                         "provenance": manifest["provenance"],
                         "archiveSha256": digest(payload),
                         "manifestSha256": digest(files["release-manifest.json"])},
            "files": [{"path": str(path), "sha256": digest(data), "mode": mode} for path, data, mode in destinations],
        }
        try:
            for path, data, mode in destinations:
                if bounded_owned and time.monotonic_ns() >= deadline_ns:
                    raise ValueError("owned installation deadline expired")
                _write(path, data, mode)
                written.append(path)
            for path in obsolete:
                if _owned_update is not None and time.monotonic_ns() >= deadline_ns:
                    raise ValueError("owned update deadline expired")
                path.unlink()
                removed.append(path)
            if bounded_owned and time.monotonic_ns() >= deadline_ns:
                raise ValueError("owned installation deadline expired")
            _write(state_dir / RECORD, json_bytes(result), 0o600)
            if _owned_update is not None:
                after_replace(result)
            if _owned_prepare is not None:
                after_prepare(result)
                if time.monotonic_ns() >= deadline_ns:
                    raise ValueError("owned preparation deadline expired")
        except Exception:
            for path in removed:
                data, mode = originals[str(path)]
                _write(path, data, mode)
            for path in reversed(written):
                if str(path) in originals:
                    data, mode = originals[str(path)]
                    _write(path, data, mode)
                else:
                    path.unlink()
            if previous_record is not None:
                _write(state_dir / RECORD, previous_record, 0o600)
            elif (state_dir / RECORD).exists():
                (state_dir / RECORD).unlink()
            raise
        return result


def prepare_bundle(payload, prefix, records, service, runtime_state, before_prepare, after_prepare,
                   *, deadline_ns):
    """One new owned placement; finite locks/writes, no start or registration."""
    if type(deadline_ns) is not int or not time.monotonic_ns() < deadline_ns <= time.monotonic_ns()+1200*10**9:
        raise ValueError("owned preparation original deadline invalid")
    if service is None or runtime_state is None:
        raise ValueError("owned preparation requires exact service and state placement")
    return install_bundle(payload,prefix,records,service,"linux",daemon_state_dir=runtime_state,
        _owned_prepare=(before_prepare,after_prepare,deadline_ns))


def update_bundle(payload, prefix, records, service, runtime_state, previous_archive_sha256,
                  before_replace, after_replace, *, deadline_ns):
    """One owned inactive replacement; no service activation or runtime writes."""
    if type(deadline_ns) is not int or not time.monotonic_ns() < deadline_ns <= time.monotonic_ns()+1200*10**9:
        raise ValueError("owned update original deadline invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", previous_archive_sha256):
        raise ValueError("owned update archive pin invalid")
    return install_bundle(payload, prefix, records, service, "linux", daemon_state_dir=runtime_state,
        _owned_update=(previous_archive_sha256, before_replace, after_replace, deadline_ns))


def uninstall(prefix: Path, state_dir: Path) -> dict:
    _absolute(prefix)
    _absolute(state_dir)
    with _lock(state_dir), _prefix_lock(prefix):
        record = _record(prefix, state_dir)
        result: dict[str, list[str]] = {"removed": [], "preserved": []}
        if record is None:
            return result
        retained = []
        for entry in record["files"]:
            path = Path(entry["path"])
            if _matches(path, entry):
                path.unlink()
                result["removed"].append(str(path))
            elif path.exists() or path.is_symlink():
                retained.append(entry)
                result["preserved"].append(str(path))
        if retained:
            record["files"] = retained
            _write(state_dir / RECORD, json_bytes(record), 0o600)
        else:
            (state_dir / RECORD).unlink()
        # Runtime databases, vault keys, user configurations, native sessions,
        # and even empty installation directories remain under user authority.
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["install", "uninstall"])
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--user-service", type=Path)
    parser.add_argument("--daemon-state-dir", type=Path)
    parser.add_argument("--platform", choices=["linux", "macos"], default="linux")
    args = parser.parse_args()
    if args.operation == "install":
        if args.bundle is None:
            parser.error("install requires --bundle")
        result = install_bundle(read_bundle(args.bundle), args.prefix, args.state_dir, args.user_service, args.platform,
                                daemon_state_dir=args.daemon_state_dir)
    else:
        result = uninstall(args.prefix, args.state_dir)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

