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
def _directory_lock(directory: Path, name: str, private: bool):
    _safe_directory(directory, create=True, private=private)
    descriptor = os.open(directory / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("unsafe installation lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
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


def install_bundle(payload: bytes, prefix: Path, state_dir: Path,
                   user_service: Path | None = None, platform: str = "linux") -> dict:
    manifest, files = verify_bundle(payload)
    _absolute(prefix)
    _absolute(state_dir)
    if platform not in {"linux", "macos"} or not manifest["target"].endswith("-" + platform):
        raise ValueError("bundle and service platform differ")
    if user_service is not None:
        _absolute(user_service)
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
            template = files["share/omux/services/omux.service.in"].decode()
            bindings = {"OMUX_INSTALL_PREFIX": str(prefix),
                        "OMUX_INSTALL_RECORD": str(state_dir / RECORD),
                        "OMUX_INSTALL_SERVICE_PATH": str(user_service)}
            if instance is not None:
                bindings["OMUX_INSTANCE"] = instance
            template += "\n[Service]\n"
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
    # Validate the complete file layout before creating either custody lock.
    # A service cannot replace a payload, ownership record or active lock, nor
    # can a requested file occupy a directory required by another such file.
    planned = [path for path, _, _ in destinations]
    controls = [state_dir / RECORD, state_dir / "install.lock", prefix / ".omux-install.lock"]
    for index, path in enumerate(planned):
        for other in planned[index + 1:] + controls:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError("installation file paths collide")
    with _lock(state_dir), _prefix_lock(prefix):
        previous = _record(prefix, state_dir)
        if previous and previous["userService"] != (str(user_service) if user_service else None):
            raise ValueError("remove the owned installation before changing service placement")
        owned = {item["path"]: item for item in previous["files"]} if previous else {}
        # Preflight all targets before writing any executable or service file.
        for path, _, _ in destinations:
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
                _write(path, data, mode)
                written.append(path)
            for path in obsolete:
                path.unlink()
                removed.append(path)
            _write(state_dir / RECORD, json_bytes(result), 0o600)
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
            raise
        return result


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
    parser.add_argument("--platform", choices=["linux", "macos"], default="linux")
    args = parser.parse_args()
    if args.operation == "install":
        if args.bundle is None:
            parser.error("install requires --bundle")
        result = install_bundle(read_bundle(args.bundle), args.prefix, args.state_dir, args.user_service, args.platform)
    else:
        result = uninstall(args.prefix, args.state_dir)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
