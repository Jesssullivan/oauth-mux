"""Stage explicit Bazel artifacts privately; never register or restart anything."""
import argparse
import base64
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile

HOST = "ai.xoxd.omux.dev"
MARKER = {"owner": "omux-development-stage", "revision": 1}
LIMIT = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2048
COMMANDS = ("omux", "omux-native-host", "omuxd")


class StageError(Exception):
    pass


@dataclass(frozen=True)
class StagedGeneration:
    """Transaction-local retained identity; not recovered from current."""
    receipt: dict
    generation: str
    receipt_sha256: str


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise StageError("development root must be absolute")
    # Walk using held directory descriptors. Foreign-writable ancestors cannot
    # redirect writes; root-owned sticky directories (e.g. /tmp) protect owned
    # children and are the sole writable-ancestor exception.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            parent = os.fstat(descriptor)
            sticky_root = parent.st_uid == 0 and bool(parent.st_mode & stat.S_ISVTX)
            if (parent.st_uid not in (0, os.geteuid()) or
                    (parent.st_mode & 0o022 and not sticky_root)):
                raise StageError("development ancestor is foreign-owned or writable")
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            child = os.fstat(next_descriptor)
            if sticky_root and child.st_uid != os.geteuid():
                os.close(next_descriptor)
                raise StageError("sticky ancestor child must be user-owned")
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
    except OSError as error:
        raise StageError("development directory is linked or inaccessible") from error
    finally:
        os.close(descriptor)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise StageError("development directory must be private and user-owned")
    return path


def artifact(path):
    # Explicit Bazel output symlinks are allowed as inputs, never as destinations.
    try:
        path = Path(path).resolve(strict=True)
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
                raise StageError("artifact is not a bounded regular file")
            data = bytearray()
            while len(data) <= LIMIT:
                chunk = os.read(descriptor, min(1024 * 1024, LIMIT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
            snapshot = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if len(data) > LIMIT or snapshot(before) != snapshot(after):
                raise StageError("artifact exceeds its bound or changed while reading")
            return bytes(data)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise StageError("artifact is missing, linked, or unreadable") from error


def write(path, data, mode=0o600):
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())


def stable_launcher(name):
    return ('#!/bin/sh\nexport OMUX_INSTANCE=dev\ndirectory=${0%/*}\nexec "$directory/../current/lib/' + name + '" "$@"\n').encode()


def stable_commands(root, install=False):
    directory = root / "bin"
    if not directory.exists():
        if not install:
            raise StageError("stable development commands are missing")
        directory.mkdir(mode=0o700)
    private_directory(directory)
    if any(path.name not in COMMANDS for path in directory.iterdir()):
        raise StageError("stable command directory contains unowned files")
    for name in COMMANDS:
        path = directory / name
        if not path.exists() and not path.is_symlink() and install:
            write(path, stable_launcher(name), 0o700)
        if (path.is_symlink() or not path.is_file() or
                path.stat().st_uid != os.geteuid() or
                stat.S_IMODE(path.stat().st_mode) != 0o700 or
                artifact(path) != stable_launcher(name)):
            raise StageError("stable development command changed")


def inventory(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if info.st_uid != os.geteuid() or path.is_symlink():
            raise StageError("staged generation ownership changed")
        if path.is_dir():
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise StageError("staged directory permissions changed")
        elif path.is_file():
            if path != directory / "receipt.json":
                result[path.relative_to(directory).as_posix()] = {
                    "sha256": digest(artifact(path)), "mode": stat.S_IMODE(info.st_mode)}
        else:
            raise StageError("staged generation contains special files")
    return result


def validate_existing(root):
    current = root / "current"
    if not current.is_symlink():
        raise StageError("current development pointer is not owned")
    target = os.readlink(current)
    if not re.fullmatch(r"generations/[a-f0-9]{32}", target):
        raise StageError("current development pointer is not owned")
    directory = root / target
    if directory.is_symlink() or not directory.is_dir():
        raise StageError("current generation is missing or linked")
    private_directory(directory)
    receipt_path = directory / "receipt.json"
    if (receipt_path.is_symlink() or not receipt_path.is_file() or
            receipt_path.stat().st_uid != os.geteuid() or
            stat.S_IMODE(receipt_path.stat().st_mode) != 0o600):
        raise StageError("receipt ownership changed")
    receipt = json.loads(artifact(receipt_path))
    if receipt.get("ownership") != MARKER or receipt.get("files") != inventory(directory):
        raise StageError("owned development generation changed")


def unpack(data, directory, metadata):
    from io import BytesIO
    total = 0
    seen = set()
    with zipfile.ZipFile(BytesIO(data)) as archive:
        if len(archive.infolist()) > MAX_ARCHIVE_MEMBERS:
            raise StageError("extension archive member count exceeds bound")
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            if (not item.filename or name.is_absolute() or ".." in name.parts or
                    "\x00" in item.filename or name.as_posix() in ("", ".") or
                    "\\" in item.filename or item.filename in seen or
                    stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise StageError("unsafe extension archive member")
            seen.add(item.filename)
            total += item.file_size
            if total > LIMIT or item.flag_bits & 1:
                raise StageError("extension archive exceeds bounds or is encrypted")
            destination = directory.joinpath(*name.parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if item.is_dir():
                destination.mkdir(exist_ok=True, mode=0o700)
            else:
                write(destination, archive.read(item))
    manifest = json.loads(artifact(directory / "manifest.json"))
    if manifest.get("version") != metadata["extension"].get("version"):
        raise StageError("extension version does not match metadata")
    try:
        key = base64.b64decode(manifest["key"], validate=True)
    except (KeyError, ValueError) as error:
        raise StageError("development extension needs a stable manifest key") from error
    extension_id = "".join(chr(ord("a") + int(c, 16)) for c in digest(key)[:32])
    if extension_id != metadata["extension"]["id"]:
        raise StageError("development extension identity mismatch")
    channel = artifact(directory / "shared" / "channel.mjs")
    expected = ('export const CHANNEL = "development";\nexport const INSTANCE = "dev";\nexport const NATIVE_HOST = "' + HOST + '";\n').encode()
    if channel != expected:
        raise StageError("extension channel module does not identify development")


def stage_generation(root, core, daemon, extension_zip, metadata, replace_owned=False,
                     runtime_files=None, patchelf=None, ca_bundle=None):
    metadata = dict(metadata)
    if any(metadata.get(k) != v for k, v in {
            "channel": "development", "instance": "dev", "native_host": HOST}.items()):
        raise StageError("metadata must identify the isolated development channel")
    extension = metadata.get("extension", {})
    if not isinstance(extension, dict) or not re.fullmatch(r"[a-p]{32}", extension.get("id", "")):
        raise StageError("invalid development extension identity")
    inputs = {"core": artifact(core), "daemon": artifact(daemon), "extension": artifact(extension_zip)}
    native_elf = any(inputs[name].startswith(b"\x7fELF") for name in ("core", "daemon"))
    portable_requested = bool(runtime_files or patchelf or ca_bundle)
    if native_elf or portable_requested:
        if not native_elf or not runtime_files or patchelf is None or ca_bundle is None:
            raise StageError("native ELF staging requires the complete declared runtime closure, patchelf and CA bundle")
    declared = metadata.get("artifact", {})
    if (metadata.get("schema_version") != 1 or extension.get("browser") != "chromium" or
            not isinstance(declared, dict) or declared.get("sha256") != digest(inputs["extension"]) or
            declared.get("bytes") != len(inputs["extension"]) or declared.get("format") != "zip"):
        raise StageError("extension metadata does not bind the supplied archive")
    root = private_directory(root)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = root / ".omux-stage-owner.json"
        if marker.exists() or marker.is_symlink():
            if (marker.is_symlink() or marker.stat().st_uid != os.geteuid() or
                    stat.S_IMODE(marker.stat().st_mode) != 0o600 or
                    json.loads(artifact(marker)) != MARKER):
                raise StageError("development root ownership mismatch")
        else:
            if any(root.iterdir()):
                raise StageError("refusing unowned development directory")
            write(marker, (json.dumps(MARKER) + "\n").encode())
        current = root / "current"
        if current.exists() or current.is_symlink():
            if not replace_owned:
                raise StageError("replacement requires --replace-owned")
            validate_existing(root)
            stable_commands(root)
        if native_elf:
            from portable import assemble_linux, elf_metadata, verify_linux_runtime
            try:
                machine = elf_metadata(inputs["core"])["machine"]
                target = {62: "x86_64-linux", 183: "aarch64-linux"}[machine]
                runtime_payload, runtime = assemble_linux(Path(core), Path(daemon), list(runtime_files),
                                                         Path(patchelf), target, Path(ca_bundle), channel="development")
                verify_linux_runtime(runtime_payload, {"target": target, "runtime": runtime, "channel": "development"})
                if artifact(core) != inputs["core"] or artifact(daemon) != inputs["daemon"]:
                    raise StageError("native source artifacts changed during runtime assembly")
            except (OSError, ValueError, subprocess.CalledProcessError) as error:
                raise StageError("declared portable development runtime assembly failed") from error
        generations = private_directory(root / "generations")
        generation = uuid.uuid4().hex
        temporary = Path(tempfile.mkdtemp(prefix=".staging-", dir=generations))
        try:
            (temporary / "bin").mkdir(mode=0o700)
            (temporary / "chromium").mkdir(mode=0o700)
            (temporary / "lib").mkdir(mode=0o700)
            if native_elf:
                (temporary / "source").mkdir(mode=0o700)
                write(temporary / "source/core", inputs["core"])
                write(temporary / "source/daemon", inputs["daemon"])
                for name, value in sorted(runtime_payload.items()):
                    destination = temporary / "runtime" / name
                    private_directory(destination.parent)
                    executable = name.startswith("bin/") or "/libexec/" in name or name == runtime["loader"]
                    write(destination, value, 0o700 if executable else 0o600)
            for name, source in (("omux", "core"), ("omux-native-host", "core"), ("omuxd", "daemon")):
                payload = ('#!/bin/sh\nset -eu\ndirectory=${0%/*}\nexec "$directory/../runtime/bin/' + name + '" "$@"\n').encode() if native_elf else inputs[source]
                write(temporary / "lib" / name, payload, 0o700)
                launcher = ('#!/bin/sh\nexport OMUX_INSTANCE=dev\ndirectory=${0%/*}\nexec "$directory/../lib/' + name + '" "$@"\n').encode()
                write(temporary / "bin" / name, launcher, 0o700)
            unpack(inputs["extension"], temporary / "chromium", metadata)
            receipt = {"ownership": MARKER, "metadata": metadata,
                       "artifacts": {k: digest(v) for k, v in inputs.items()},
                       "files": inventory(temporary),
                       "next_steps": ["register development native host explicitly", "reload Chromium extension manually", "restart owned development daemon explicitly"]}
            if native_elf:
                receipt["distribution"] = "portable-linux"
                receipt["runtime"] = {"target": target, "details": runtime}
            receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
            write(temporary / "receipt.json", receipt_bytes)
            os.rename(temporary, generations / generation)
            stable_commands(root, install=True)
            pointer = root / (".current-" + generation)
            pointer.symlink_to("generations/" + generation)
            os.replace(pointer, current)
            os.fsync(descriptor)
            return StagedGeneration(receipt, generation, digest(receipt_bytes))
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise StageError("development staging failed safely") from error
    finally:
        os.close(descriptor)


def stage(root, core, daemon, extension_zip, metadata, replace_owned=False,
          runtime_files=None, patchelf=None, ca_bundle=None):
    # Keep the existing API and CLI receipt bytes unchanged. Only callers of
    # stage_generation receive the identity captured inside the transaction.
    return stage_generation(root, core, daemon, extension_zip, metadata, replace_owned,
                            runtime_files=runtime_files, patchelf=patchelf,
                            ca_bundle=ca_bundle).receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "omux-dev" / "stage"
    parser.add_argument("--root", type=Path, default=default)
    for name in ("core", "daemon", "extension", "metadata"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--replace-owned", action="store_true")
    parser.add_argument("--runtime-file", type=Path, action="append")
    parser.add_argument("--runtime-files", default="")
    parser.add_argument("--patchelf", type=Path)
    parser.add_argument("--ca-bundle", type=Path)
    args = parser.parse_args()
    try:
        if len(args.runtime_files) > 1024 * 1024:
            raise StageError("declared runtime path list exceeds bound")
        runtime_files = list(args.runtime_file or [])
        # Bazel locations expand to one space-separated argument. This is data,
        # never shell text; whitespace-bearing paths use repeated --runtime-file.
        runtime_files.extend(Path(value) for value in args.runtime_files.split())
        if len(runtime_files) > 4096:
            raise StageError("declared runtime path count exceeds bound")
        result = stage(args.root, args.core, args.daemon, args.extension,
                       json.loads(artifact(args.metadata)), args.replace_owned,
                       runtime_files=runtime_files, patchelf=args.patchelf, ca_bundle=args.ca_bundle)
        print(json.dumps(result, sort_keys=True))
    except (StageError, ValueError) as error:
        print("omux dev stage: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
