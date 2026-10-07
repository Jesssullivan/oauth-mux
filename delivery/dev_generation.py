"""Read-only selection of one explicitly retained development generation.

Selection validates captured bytes and a final bounded metadata observation.
Returned paths are selection facts, not live executable attribution or an
atomic execution witness. Consumers must revalidate and use a held descriptor
or bound carrier as applicable, and own any process they restart. Neither
``current`` nor the stable launchers participate in this contract.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HOST = "ai.xoxd.omux.dev"
MARKER = {"owner": "omux-development-stage", "revision": 1}
MAX_RECEIPT = 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 16
SHA256 = re.compile(r"[a-f0-9]{64}")
GENERATION = re.compile(r"[a-f0-9]{32}")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class GenerationError(ValueError):
    """Finite diagnostic codes contain no inspected paths or payloads."""


def require(condition, code):
    if not condition:
        raise GenerationError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def owned_marker(value):
    return (type(value) is dict and set(value) == {"owner", "revision"}
            and value.get("owner") == MARKER["owner"]
            and type(value.get("revision")) is int and value["revision"] == MARKER["revision"])


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def owned_directory(descriptor):
    info = os.fstat(descriptor)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "directory-custody")


def open_root(root):
    require(root.is_absolute() and ".." not in root.parts, "root-shape")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in root.parts[1:]:
            parent = os.fstat(descriptor)
            sticky = parent.st_uid == 0 and bool(parent.st_mode & stat.S_ISVTX)
            require(parent.st_uid in (0, os.geteuid())
                    and (not parent.st_mode & 0o022 or sticky), "ancestor-custody")
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                require(not sticky or os.fstat(child).st_uid == os.geteuid(), "sticky-child-custody")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        owned_directory(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_file(directory, name, maximum, modes=(0o600,)):
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in modes,
                "file-custody")
        require(before.st_size <= maximum, "file-byte-bound")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= maximum and snapshot(before) == snapshot(os.fstat(descriptor))
                and snapshot(before) == snapshot(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                "file-changed-or-bound")
        return bytes(data), stat.S_IMODE(before.st_mode), snapshot(before)
    finally:
        os.close(descriptor)


def parse(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-field")
            result[key] = value
        return result

    def reject_constant(_):
        raise GenerationError("nonfinite-json")

    return json.loads(data, object_pairs_hook=unique, parse_constant=reject_constant)


def inventory(directory):
    result, selected, witnesses, runtime_files = {}, {}, {}, {}
    entries, total = 0, 0
    retained = {"chromium/manifest.json", "chromium/shared/channel.mjs"}
    commands = {"bin/" + name for name in ("omux", "omux-native-host", "omuxd")}

    def walk(descriptor, prefix, depth):
        nonlocal entries, total
        require(depth <= MAX_DEPTH, "inventory-depth-bound")
        owned_directory(descriptor)
        before = snapshot(os.fstat(descriptor))
        witnesses[prefix.rstrip("/")] = before
        # scandir streams entries; a hostile oversized directory never creates
        # an unbounded list before the entry bound is checked.
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.scandir(descriptor) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_ENTRIES, "inventory-entry-bound")
                name = child.name
                require(len(name) <= 255 and "\\" not in name, "inventory-name")
                relative = prefix + name
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    nested = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
                    try:
                        require(snapshot(info) == snapshot(os.fstat(nested)), "directory-changed")
                        walk(nested, relative + "/", depth + 1)
                        require(snapshot(os.fstat(nested)) == snapshot(os.stat(
                            name, dir_fd=descriptor, follow_symlinks=False)), "directory-changed")
                    finally:
                        os.close(nested)
                elif relative != "receipt.json":
                    data, mode, witness = read_file(descriptor, name, MAX_FILE, (0o600, 0o700))
                    witnesses[relative] = witness
                    total += len(data)
                    require(total <= MAX_TOTAL, "inventory-total-bound")
                    result[relative] = {"sha256": digest(data), "mode": mode}
                    if relative.startswith("runtime/"):
                        runtime_files[relative[len("runtime/"):]] = data
                    if relative in retained:
                        require(len(data) <= MAX_RECEIPT, "extension-metadata-bound")
                        selected[relative] = data
                    elif relative in commands:
                        require(len(data) <= 4096, "launcher-byte-bound")
                        selected[relative] = data
                    elif relative in ("source/core", "source/daemon"):
                        selected[relative] = data[:4]
                    elif relative in ("lib/omux", "lib/omux-native-host", "lib/omuxd"):
                        # Portable wrappers are tiny; fixture binaries remain
                        # hash-bound without keeping another large copy.
                        selected[relative] = data if len(data) <= 4096 else None
        require(before == snapshot(os.fstat(descriptor)), "directory-changed")

    walk(directory, "", 0)
    return result, selected, witnesses, runtime_files


def reobserve(directory, witnesses):
    """Reopen every captured entry, retaining the same entry/depth bounds.

    This detects an earlier file changing while later files are captured. It
    does not freeze filesystem contents after the observation completes.
    """
    observed = set()
    entries = 0

    def walk(descriptor, prefix, depth):
        nonlocal entries
        require(depth <= MAX_DEPTH, "inventory-depth-bound")
        relative_directory = prefix.rstrip("/")
        require(relative_directory in witnesses and snapshot(os.fstat(descriptor)) == witnesses[relative_directory],
                "generation-capture-changed")
        observed.add(relative_directory)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.scandir(descriptor) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_ENTRIES, "inventory-entry-bound")
                relative = prefix + child.name
                require(relative in witnesses, "generation-capture-changed")
                witness = witnesses[relative]
                is_directory = stat.S_ISDIR(witness[2])
                flags = DIRECTORY_FLAGS if is_directory else (
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                nested = os.open(child.name, flags, dir_fd=descriptor)
                try:
                    require(snapshot(os.fstat(nested)) == witness, "generation-capture-changed")
                    if is_directory:
                        walk(nested, relative + "/", depth + 1)
                    else:
                        observed.add(relative)
                    require(snapshot(os.fstat(nested)) == witness and snapshot(os.stat(
                        child.name, dir_fd=descriptor, follow_symlinks=False)) == witness,
                        "generation-capture-changed")
                finally:
                    os.close(nested)
        require(snapshot(os.fstat(descriptor)) == witnesses[relative_directory], "generation-capture-changed")

    walk(directory, "", 0)
    require(observed == set(witnesses), "generation-capture-changed")


@dataclass(frozen=True)
class SelectedGeneration:
    generation: str
    receipt_sha256: str
    directory: Path
    cli: Path
    native_host: Path
    daemon: Path
    chromium: Path
    extension_id: str
    extension_version: str
    distribution: str
    artifact_sha256: tuple


def select_generation(root, generation, receipt_sha256, *, expected_artifacts=None, require_portable=False):
    """Select by caller-retained ID and raw receipt SHA256, without side effects.

    ``expected_artifacts`` optionally binds the receipt's core/daemon/extension
    source hashes to separately declared inputs. No receipt field is an identity,
    grant, service-activation, native-support or reload attestation.
    """
    require(type(generation) is str and GENERATION.fullmatch(generation), "generation-shape")
    require(type(receipt_sha256) is str and SHA256.fullmatch(receipt_sha256), "receipt-digest-shape")
    root = Path(root)
    descriptors = []
    try:
        root_fd = open_root(root)
        descriptors.append(root_fd)
        marker, _, marker_witness = read_file(root_fd, ".omux-stage-owner.json", MAX_RECEIPT)
        require(owned_marker(parse(marker)), "root-owner-marker")
        generations_fd = os.open("generations", DIRECTORY_FLAGS, dir_fd=root_fd)
        descriptors.append(generations_fd)
        owned_directory(generations_fd)
        generation_fd = os.open(generation, DIRECTORY_FLAGS, dir_fd=generations_fd)
        descriptors.append(generation_fd)
        owned_directory(generation_fd)
        receipt_bytes, _, receipt_witness = read_file(generation_fd, "receipt.json", MAX_RECEIPT)
        require(digest(receipt_bytes) == receipt_sha256, "receipt-digest-mismatch")
        receipt = parse(receipt_bytes)
        require(type(receipt) is dict and owned_marker(receipt.get("ownership")), "receipt-owner-marker")
        metadata = receipt.get("metadata")
        require(type(metadata) is dict and type(metadata.get("schema_version")) is int
                and metadata["schema_version"] == 1 and metadata.get("channel") == "development"
                and metadata.get("instance") == "dev" and metadata.get("native_host") == HOST,
                "receipt-channel")
        artifacts = receipt.get("artifacts")
        require(type(artifacts) is dict and set(artifacts) == {"core", "daemon", "extension"}
                and all(type(value) is str and SHA256.fullmatch(value) for value in artifacts.values()),
                "receipt-artifact-shape")
        require(expected_artifacts is None or expected_artifacts == artifacts, "source-artifact-mismatch")
        archive = metadata.get("artifact")
        require(type(archive) is dict and archive.get("sha256") == artifacts["extension"]
                and type(archive.get("bytes")) is int and 0 < archive["bytes"] <= MAX_FILE
                and archive.get("format") == "zip", "extension-archive-binding")
        actual, selected, witnesses, runtime_files = inventory(generation_fd)
        witnesses["receipt.json"] = receipt_witness
        require(type(receipt.get("files")) is dict and receipt["files"] == actual, "generation-inventory-mismatch")
        portable = receipt.get("distribution") == "portable-linux"
        require(not require_portable or portable, "portable-generation-required")
        require(receipt.get("distribution") in (None, "portable-linux"), "generation-distribution")
        if portable:
            runtime = receipt.get("runtime")
            require(type(runtime) is dict and runtime.get("target") in ("x86_64-linux", "aarch64-linux")
                    and type(runtime.get("details")) is dict, "portable-runtime-shape")
            loader = runtime["details"].get("loader")
            require(type(loader) is str and re.fullmatch(r"lib/omux/lib/[A-Za-z0-9+._-]{1,255}", loader)
                    and actual.get("runtime/" + loader, {}).get("mode") == 0o700
                    and selected.get("source/core") == b"\x7fELF"
                    and selected.get("source/daemon") == b"\x7fELF", "portable-runtime-binding")
            from portable import verify_linux_runtime
            try:
                verify_linux_runtime(runtime_files, {"target": runtime["target"], "runtime": runtime["details"],
                                                     "channel": "development"})
            except (ValueError, TypeError, KeyError) as error:
                raise GenerationError("portable-runtime-invalid") from error
        for name, source in (("omux", "core"), ("omux-native-host", "core"), ("omuxd", "daemon")):
            for executable in ("bin/" + name, "lib/" + name):
                require(actual.get(executable, {}).get("mode") == 0o700, "generation-command-missing")
            source_path = "source/" + source if portable else "lib/" + name
            require(actual.get(source_path, {}).get("sha256") == artifacts[source], "generation-source-binding")
            launcher = ('#!/bin/sh\nexport OMUX_INSTANCE=dev\ndirectory=${0%/*}\n'
                        'exec "$directory/../lib/' + name + '" "$@"\n').encode()
            require(selected["bin/" + name] == launcher, "generation-launcher-binding")
            if portable:
                wrapper = ('#!/bin/sh\nset -eu\ndirectory=${0%/*}\n'
                           'exec "$directory/../runtime/bin/' + name + '" "$@"\n').encode()
                require(selected.get("lib/" + name) == wrapper
                        and actual.get("runtime/bin/" + name, {}).get("mode") == 0o700,
                        "portable-command-binding")
        extension = metadata.get("extension")
        require(type(extension) is dict and extension.get("browser") == "chromium"
                and type(extension.get("id")) is str and re.fullmatch(r"[a-p]{32}", extension["id"])
                and type(extension.get("version")) is str, "extension-identity-shape")
        require({"chromium/manifest.json", "chromium/shared/channel.mjs"}.issubset(selected), "extension-files-missing")
        manifest = parse(selected["chromium/manifest.json"])
        require(type(manifest) is dict and manifest.get("version") == extension["version"], "extension-version")
        key = base64.b64decode(manifest["key"], validate=True)
        identity = "".join(chr(97 + int(value, 16)) for value in digest(key)[:32])
        require(identity == extension["id"], "extension-identity-mismatch")
        channel = ('export const CHANNEL = "development";\nexport const INSTANCE = "dev";\n'
                   'export const NATIVE_HOST = "' + HOST + '";\n').encode()
        require(selected["chromium/shared/channel.mjs"] == channel, "extension-channel")
        latest_receipt, _, latest_witness = read_file(generation_fd, "receipt.json", MAX_RECEIPT)
        require(latest_receipt == receipt_bytes and latest_witness == receipt_witness, "receipt-changed")
        latest_marker, _, latest_marker_witness = read_file(root_fd, ".omux-stage-owner.json", MAX_RECEIPT)
        require(latest_marker == marker and latest_marker_witness == marker_witness, "root-owner-marker-changed")
        reobserve(generation_fd, witnesses)
        require(snapshot(os.fstat(generation_fd)) == snapshot(os.stat(
            generation, dir_fd=generations_fd, follow_symlinks=False)), "generation-path-changed")
        require(snapshot(os.fstat(generations_fd)) == snapshot(os.stat(
            "generations", dir_fd=root_fd, follow_symlinks=False)), "generations-path-changed")
        require(snapshot(os.fstat(root_fd)) == snapshot(root.lstat()), "root-path-changed")
        directory = root / "generations" / generation
        return SelectedGeneration(generation, receipt_sha256, directory, directory / "bin/omux",
                                  directory / "bin/omux-native-host", directory / "bin/omuxd",
                                  directory / "chromium", identity, extension["version"],
                                  "portable-linux" if portable else "fixture",
                                  tuple(sorted(artifacts.items())))
    except GenerationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise GenerationError("generation-unreadable-or-invalid") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
