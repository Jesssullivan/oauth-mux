"""Deterministic public Yoga data export; no transport or execution authority.

All paths are explicitly declared inputs. Expected digests independently select
their bytes; inventory and prior NAR receipts describe destination requirements,
never current registration/availability. Source archive verification establishes
source inventory only, not Git truth or compiled-artifact correspondence.
Read-only outputs remain content-selected files, not an atomic execution witness.
Tools packaged as data are byte-comparison material, not relocated executable
tools. Yoga must separately qualify original registered store inputs and their
execution modes. Consume projected NAR receipts using their member digests;
the selection's raw-log digests retain historical input provenance only.
"""
import argparse
import base64
import gzip
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

import browser_runtime_authority as authority

INPUTS = frozenset(("bundle", "extension", "chromium", "node", "observer", "dbus_session",
                    "dbus_daemon", "keyring", "runtime_authority", "recorder", "recorder_implementation"))
EVIDENCE = frozenset(("source_archive", "controller_inventory", "controller_nar", "browser_inventory", "browser_nar"))
SOURCE_FILES = frozenset("delivery/" + name for name in ("browser_runtime_authority.py", "yoga_toolbar_consent.py",
    "yoga_toolbar_contract.py", "test_installed_chromium.py", "test_installed_custody.py", "install.py", "pack.py", "portable.py",
    "yoga_wrapper_authority.py", "yoga_wrapper_custody.py"))
MEMBERS = {name: "inputs/" + name for name in INPUTS} | {name: "evidence/" + name for name in EVIDENCE}
MAX_FILE = 512 * 1024 * 1024
MAX_SOURCE = 128 * 1024 * 1024
MAX_SOURCE_EXPANDED = MAX_FILE + 12 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 1024 * 1024
SECONDS = 300
SHA = re.compile(r"[0-9a-f]{64}")
REASONS = frozenset(("selection_invalid", "input_invalid", "input_changed", "digest_mismatch", "byte_bound",
    "deadline_exceeded", "source_invalid", "source_binding", "runtime_binding", "inventory_invalid",
    "archive_invalid", "output_invalid", "cleanup_incomplete"))


class PayloadError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "input_invalid"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise PayloadError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def budget(until):
    require(time.monotonic() < until, "deadline_exceeded")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parent(path):
    require(Path(path).is_absolute() and len(os.fsencode(path)) <= 4096, "input_invalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        information = os.fstat(descriptor)
        require(information.st_uid == 0 and not information.st_mode & 0o022, "input_invalid")
        walked = Path("/")
        for component in Path(path).parts[1:-1]:
            walked /= component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                nix_store = walked == Path("/nix/store") and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1775
                require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or nix_store), "input_invalid")
                if walked != Path("/nix/store") and walked.is_relative_to("/nix/store"):
                    require(info.st_uid == 0 and not info.st_mode & 0o222, "input_invalid")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class Captured:
    def __init__(self, path, expected, maximum, until):
        self.fd, self.parent = None, None
        self.until = until
        budget(until)
        require(type(expected) is str and SHA.fullmatch(expected), "selection_invalid")
        # Resolve only explicitly declared Bazel input aliases, never discover
        # other files. Keep alias target identity through every reobservation.
        self.alias = Path(path).absolute()
        self.path = self.alias.resolve(strict=True)
        try:
            self.parent = parent(self.path)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.parent)
            before = os.fstat(self.fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid())
                    and not before.st_mode & 0o022 and before.st_nlink >= 1, "input_invalid")
            if self.path.is_relative_to("/nix/store"):
                require(before.st_uid == 0 and not before.st_mode & 0o222, "input_invalid")
            require(0 <= before.st_size <= maximum, "byte_bound")
            self.identity, self.size, self.sha = identity(before), before.st_size, expected
            observed, length = hashlib.sha256(), 0
            while True:
                budget(until)
                data = os.read(self.fd, 1024 * 1024)
                if not data:
                    break
                length += len(data)
                require(length <= maximum, "byte_bound")
                observed.update(data)
            require(length == self.size and observed.hexdigest() == expected, "digest_mismatch")
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        budget(self.until)
        require(self.alias.resolve(strict=True) == self.path and identity(os.fstat(self.fd)) == self.identity,
                "input_changed")
        named_parent = parent(self.path)
        try:
            held, named = os.fstat(self.parent), os.fstat(named_parent)
            require((held.st_dev, held.st_ino, held.st_uid, held.st_mode) ==
                    (named.st_dev, named.st_ino, named.st_uid, named.st_mode), "input_changed")
            require(identity(os.stat(self.path.name, dir_fd=named_parent, follow_symlinks=False)) == self.identity,
                    "input_changed")
        finally:
            os.close(named_parent)

    def bytes(self, maximum):
        require(self.size <= maximum, "byte_bound")
        os.lseek(self.fd, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) < self.size:
            budget(self.until)
            block = os.read(self.fd, min(65536, self.size - len(data)))
            require(block, "input_changed")
            data.extend(block)
        self.check()
        require(digest(data) == self.sha, "input_changed")
        return bytes(data)

    def close(self):
        for name in ("fd", "parent"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                os.close(descriptor)


def selection(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "scope", "sourceGraphSha256", "sourceFilesSha256",
        "inputSha256", "evidenceSha256"} and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
        and value["scope"] == "yoga-public-payload-selection-v1", "selection_invalid")
    for key, names in (("sourceFilesSha256", SOURCE_FILES), ("inputSha256", INPUTS), ("evidenceSha256", EVIDENCE)):
        require(type(value[key]) is dict and set(value[key]) == names
                and all(type(item) is str and SHA.fullmatch(item) for item in value[key].values()), "selection_invalid")
    require(type(value["sourceGraphSha256"]) is str and SHA.fullmatch(value["sourceGraphSha256"]), "selection_invalid")
    return value


def source_binding(data, selected, until):
    require(len(data) <= MAX_SOURCE, "byte_bound")
    require(len(data) >= 10 and data[:4] == b"\x1f\x8b\x08\x00" and data[4:8] == b"\0" * 4, "source_invalid")
    fixed = {"BUILD", "BUILD.bazel", "MODULE.bazel", "MODULE.bazel.lock", "WORKSPACE", "WORKSPACE.bazel",
             "flake.nix", "flake.lock", ".bazelrc", ".bazelversion"}
    names, hashes, sizes, total = set(), {}, {}, 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as archive:
            expanded = 0
            def read(count):
                nonlocal expanded
                budget(until)
                block = archive.read(count)
                expanded += len(block)
                require(expanded <= MAX_SOURCE_EXPANDED, "byte_bound")
                return block
            while True:
                header = read(512)
                require(len(header) == 512, "source_invalid")
                if header == b"\0" * 512:
                    offset = expanded - 512
                    while True:
                        block = read(65536)
                        if not block:
                            break
                        require(not any(block), "source_invalid")
                    expected = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
                    require(expanded == expected, "source_invalid")
                    break
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                name = member.name
                parts = PurePosixPath(name).parts
                require(name and len(name) <= 4096 and str(PurePosixPath(name)) == name and not name.startswith("/")
                        and not {".", ".."}.intersection(parts) and name not in names
                        and len(names) < 10000 and member.isfile() and 0 <= member.size <= MAX_FILE
                        and member.mode in (0o644, 0o755) and member.uid == member.gid == member.mtime == 0
                        and not member.uname and not member.gname and header == member.tobuf(format=tarfile.USTAR_FORMAT),
                        "source_invalid")
                require(not any(part in {".git", ".ssh", ".netrc", ".codex", ".claude", "auth.json", "credentials.json"}
                        or part.startswith(".env") for part in parts), "source_invalid")
                require(not any(ord(char) < 32 for char in name), "source_invalid")
                names.add(name)
                total += member.size
                require(total <= MAX_FILE, "byte_bound")
                hashed, count = hashlib.sha256(), 0
                while count < member.size:
                    block = read(min(65536, member.size - count))
                    require(block, "source_invalid")
                    count += len(block)
                    require(count <= member.size, "source_invalid")
                    hashed.update(block)
                require(count == member.size, "source_invalid")
                hashes[name] = hashed.digest()
                sizes[name] = member.size
                padding = -member.size % 512
                if padding:
                    block = read(padding)
                    require(len(block) == padding and not any(block), "source_invalid")
    except (tarfile.TarError, EOFError, OSError, UnicodeError):
        raise PayloadError("source_invalid") from None
    require({"BUILD.bazel", "MODULE.bazel", "flake.nix", "flake.lock"}.issubset(names), "source_binding")
    require(all(name in hashes and hashes[name].hex() == expected for name, expected in selected["sourceFilesSha256"].items()), "source_binding")
    graph, graph_files, graph_bytes, graph_names = hashlib.sha256(), 0, 0, 0
    for name in sorted(names):
        path = PurePosixPath(name)
        if path.name in fixed or path.suffix in (".bzl", ".nix") or (path.parts[0] == "tools"
                        and path.suffix in (".py", ".json", ".patch", ".zig", ".h")):
            graph_files += 1; graph_names += len(name.encode())
            # The graph selector's ordinary bounded-file semantics are part of
            # the shared source selection, even inside a compressed archive.
            graph_bytes += sizes[name]
            require(graph_files <= 4096 and graph_names <= 128 * 1024 and sizes[name] <= MAX_METADATA
                    and graph_bytes <= 64 * 1024 * 1024, "source_binding")
            graph.update(name.encode() + b"\0" + hashes[name])
    require(graph.hexdigest() == selected["sourceGraphSha256"], "source_binding")
    return {"files": len(names), "bytes": total, "scope": "source-inventory-only", "gitMetadataVerified": False,
            "compiledArtifactCorrespondenceVerified": False}


def inventory(content):
    value = authority.parse(content)
    require(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
            and type(value.get("paths")) is list and 1 <= len(value["paths"]) <= 4096, "inventory_invalid")
    minimal = {"schemaVersion", "paths"}
    full = minimal | {"system", "mode", "roots", "contentRehashed", "realized", "published"}
    require(set(value) == minimal or full.issubset(value) and set(value).issubset(full | {"provenance", "packages", "helperTools"}),
            "inventory_invalid")
    if set(value) != minimal:
        require(value["system"] == "x86_64-linux" and value["mode"] == "local-sqlite-readonly-snapshot"
                and all(value[key] is False for key in ("contentRehashed", "realized", "published")), "inventory_invalid")
    rows, seen, edges, total = value["paths"], set(), 0, 0
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "narHash", "narSize", "references"}
                and type(row["path"]) is str and authority.STORE.fullmatch(row["path"])
                and row["path"] not in seen and type(row["narSize"]) is int and row["narSize"] > 0
                and type(row["references"]) is list and all(type(ref) is str for ref in row["references"])
                and row["references"] == sorted(set(row["references"])), "inventory_invalid")
        require(type(row["narHash"]) is str and (re.fullmatch(r"sha256:[a-f0-9]{64}", row["narHash"])
                or re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", row["narHash"])), "inventory_invalid")
        seen.add(row["path"]); total += row["narSize"]; edges += len(row["references"])
    require(total <= 16 * 1024**3 and edges <= 65536 and all(type(ref) is str and ref in seen for row in rows for ref in row["references"]), "inventory_invalid")
    for key in ("roots", "helperTools"):
        if key in value:
            require(type(value[key]) is list and len(value[key]) <= 4096
                    and all(type(item) is str and item in seen for item in value[key]), "inventory_invalid")
    if "packages" in value:
        require(type(value["packages"]) is dict and 1 <= len(value["packages"]) <= 64
                and all(type(name) is str and re.fullmatch(r"[a-z][a-z0-9_+-]{0,63}", name)
                        and type(item) is dict and set(item) in ({"out"}, {"out", "version"})
                        and type(item["out"]) is str and item["out"] in seen
                        and ("version" not in item or type(item["version"]) is str
                             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}", item["version"]))
                        for name, item in value["packages"].items()), "inventory_invalid")
    if "provenance" in value:
        provenance = value["provenance"]
        allowed = {"rootsSha256", "flakeLockSha256", "candidateSha256", "binaryQualificationSha256", "inputSha256"}
        require(type(provenance) is dict and set(provenance).issubset(allowed), "inventory_invalid")
        for name, item in provenance.items():
            if name == "inputSha256":
                require(type(item) is dict and len(item) <= 64 and all(type(label) is str and len(label) <= 256
                        and not label.startswith("/") and str(PurePosixPath(label)) == label
                        and not {".", ".."}.intersection(PurePosixPath(label).parts)
                        and re.fullmatch(r"[A-Za-z0-9_./+-]+", label) and type(sha) is str and SHA.fullmatch(sha)
                        for label, sha in item.items()), "inventory_invalid")
            else:
                require(type(item) is str and SHA.fullmatch(item), "inventory_invalid")
    return sorted(rows, key=lambda row: row["path"]), total


def nar_proof(content, inventory_sha, rows, total):
    value = authority.receipt_from_input(content)
    keys = {"schemaVersion", "passed", "inventorySha256", "descriptorSha256", "verifiedPaths", "verifiedRegularInputs",
            "verifiedNarBytes", "contentRehashed", "linkTargetsFollowed", "executionAuthority", "flakeMappingVerified", "realized"}
    require(type(value) is dict and set(value) == keys and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["passed"] is True and value["inventorySha256"] == inventory_sha
            and type(value["descriptorSha256"]) is str and SHA.fullmatch(value["descriptorSha256"])
            and type(value["verifiedPaths"]) is int and value["verifiedPaths"] == len(rows)
            and type(value["verifiedNarBytes"]) is int and value["verifiedNarBytes"] == total
            and type(value["verifiedRegularInputs"]) is int and value["verifiedRegularInputs"] > 0
            and value["contentRehashed"] is True
            and all(value[name] is False for name in ("linkTargetsFollowed", "executionAuthority", "flakeMappingVerified", "realized")), "runtime_binding")
    return value


def manifest_for(contents, selected, until):
    source = source_binding(contents["source_archive"], selected, until)
    runtime = authority.validate_authority(contents["runtime_authority"])
    require(base64.b64decode(runtime["inventoryBase64"], validate=True) == contents["browser_inventory"], "runtime_binding")
    require(runtime["proofs"]["nar"]["inputSha256"] == selected["evidenceSha256"]["browser_nar"], "runtime_binding")
    requirements, proofs = {}, {}
    for kind in ("browser", "controller"):
        rows, total = inventory(contents[kind + "_inventory"])
        proofs[kind] = nar_proof(contents[kind + "_nar"], selected["evidenceSha256"][kind + "_inventory"], rows, total)
        requirements[kind] = rows
    require(proofs["browser"] == runtime["proofs"]["nar"]["receipt"], "runtime_binding")
    # Prior proof logs may contain arbitrary diagnostics. Export only validated
    # closed-schema JSON receipts, never their raw log text.
    projected = {"controller_nar": canonical(proofs["controller"]), "browser_nar": canonical(proofs["browser"])}
    return source, requirements, projected


class CopyReader:
    def __init__(self, captured, until):
        self.captured, self.until, self.hash, self.length = captured, until, hashlib.sha256(), 0
        os.lseek(captured.fd, 0, os.SEEK_SET)

    def read(self, count):
        budget(self.until)
        data = os.read(self.captured.fd, count)
        self.length += len(data); self.hash.update(data)
        return data

    def finish(self):
        require(self.length == self.captured.size and self.hash.hexdigest() == self.captured.sha, "input_changed")
        self.captured.check()


class HashingWriter:
    """Hash the exact serialization, independently of its later FD readback."""
    def __init__(self, stream, until):
        self.stream, self.until, self.hash, self.length = stream, until, hashlib.sha256(), 0

    def write(self, data):
        budget(self.until)
        self.length += len(data)
        require(self.length <= MAX_ARCHIVE, "byte_bound")
        require(self.stream.write(data) == len(data), "output_invalid")
        self.hash.update(data)
        return len(data)

    def tell(self):
        return self.stream.tell()


def tar_member(archive, name, size, stream):
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.uid, item.gid, item.mtime = size, 0o444, 0, 0, 0
    item.uname = item.gname = ""
    archive.addfile(item, stream)


def produce(paths, selected, output_directory, *, final_check=None, until=None):
    selected = selection(authority.parse(canonical(selection(selected))))
    require(type(paths) is dict and set(paths) == INPUTS | EVIDENCE, "selection_invalid")
    paths = dict(paths)
    until = time.monotonic() + SECONDS if until is None else until
    captured, created, parent_fd = {}, [], None
    try:
        for name in sorted(paths):
            expected = selected["inputSha256" if name in INPUTS else "evidenceSha256"][name]
            maximum = MAX_SOURCE if name == "source_archive" else MAX_METADATA if name in EVIDENCE or name == "runtime_authority" else MAX_FILE
            captured[name] = Captured(paths[name], expected, maximum, until)
        require(sum(item.size for item in captured.values()) <= MAX_TOTAL, "byte_bound")
        metadata = {name: item.bytes(MAX_SOURCE if name == "source_archive" else MAX_METADATA)
                    for name, item in captured.items() if name in EVIDENCE or name == "runtime_authority"}
        source, requirements, projected = manifest_for(metadata, selected, until)
        members = {MEMBERS[name]: {"sha256": digest(projected[name]) if name in projected else item.sha,
                    "bytes": len(projected[name]) if name in projected else item.size, "mode": 0o444}
                   for name, item in captured.items()}
        manifest = {"schemaVersion": 1, "scope": "yoga-public-payload-v1", "platform": "x86_64-linux",
            "selection": selected, "members": members, "source": source, "storeRequirements": requirements,
            "requiredMasks": authority.MASKS, "destinationRegistrationVerified": False, "storePayloadIncluded": False,
            "executionAuthority": False, "activationPerformed": False, "transferPerformed": False}
        encoded = canonical(manifest)
        require(len(encoded) <= MAX_METADATA, "byte_bound")
        root = Path(output_directory).absolute()
        parent_fd = parent(root / "placeholder")
        info = os.fstat(parent_fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "output_invalid")
        root_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        def output(name):
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
            try:
                owned = os.fstat(descriptor)
            except BaseException:
                os.close(descriptor)
                raise PayloadError("cleanup_incomplete") from None
            created.append((name, descriptor, (owned.st_dev, owned.st_ino)))
            return descriptor
        manifest_fd = output("yoga-payload.json")
        with os.fdopen(os.dup(manifest_fd), "wb") as stream:
            stream.write(encoded); stream.flush()
        archive_fd = output("yoga-payload.tar")
        with os.fdopen(os.dup(archive_fd), "wb") as stream:
            writer = HashingWriter(stream, until)
            with tarfile.open(fileobj=writer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                tar_member(archive, "manifest.json", len(encoded), io.BytesIO(encoded))
                for name in sorted(MEMBERS, key=lambda key: MEMBERS[key]):
                    if name in projected:
                        tar_member(archive, MEMBERS[name], len(projected[name]), io.BytesIO(projected[name]))
                    else:
                        reader = CopyReader(captured[name], until)
                        tar_member(archive, MEMBERS[name], captured[name].size, reader)
                        reader.finish()
        for item in captured.values():
            budget(until); item.check()
        named_parent = parent(root / "placeholder")
        output_witnesses = {}
        try:
            current = os.fstat(named_parent)
            require(root_identity == (current.st_dev, current.st_ino, current.st_uid, current.st_mode), "output_invalid")
            for name, descriptor, expected_identity in created:
                os.fchmod(descriptor, 0o444); os.fsync(descriptor)
                held, named = os.fstat(descriptor), os.stat(name, dir_fd=named_parent, follow_symlinks=False)
                require(identity(held) == identity(named) and (held.st_dev, held.st_ino) == expected_identity
                        and held.st_nlink == 1 and held.st_size <= MAX_ARCHIVE, "output_invalid")
                output_witnesses[name] = identity(held)
        finally:
            os.close(named_parent)
        os.fsync(parent_fd)
        for descriptor, expected_sha, expected_length in ((manifest_fd, digest(encoded), len(encoded)),
                (archive_fd, writer.hash.hexdigest(), writer.length)):
            os.lseek(descriptor, 0, os.SEEK_SET)
            hashed, length = hashlib.sha256(), 0
            while True:
                budget(until)
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                length += len(block); hashed.update(block)
                require(length <= MAX_ARCHIVE, "byte_bound")
            require(length == expected_length and hashed.hexdigest() == expected_sha, "output_invalid")
        for item in captured.values():
            item.check()
        if final_check is not None:
            final_check()
        named_parent = parent(root / "placeholder")
        try:
            current = os.fstat(named_parent)
            require(root_identity == (current.st_dev, current.st_ino, current.st_uid, current.st_mode), "output_invalid")
            for name, descriptor, _ in created:
                require(identity(os.fstat(descriptor)) == output_witnesses[name]
                        and identity(os.stat(name, dir_fd=named_parent, follow_symlinks=False)) == output_witnesses[name],
                        "output_invalid")
        finally:
            os.close(named_parent)
        budget(until)
        return {"scope": "yoga-public-payload-exported", "manifestSha256": digest(encoded),
                "archiveSha256": writer.hash.hexdigest(), "archiveBytes": writer.length,
                "sourceInventoryOnly": True, "executionAuthority": False, "transferPerformed": False}
    except BaseException:
        cleanup_ok = True
        for name, descriptor, expected_identity in created:
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                require((named.st_dev, named.st_ino) == expected_identity, "cleanup_incomplete")
                os.unlink(name, dir_fd=parent_fd)
            except (OSError, PayloadError):
                cleanup_ok = False
        if not cleanup_ok:
            raise PayloadError("cleanup_incomplete") from None
        raise
    finally:
        for _, descriptor, _ in created:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
        for item in captured.values():
            item.close()


def validate_archive(data, manifest_sha256):
    """Validate fixed safe extraction members without creating any file.

    The manifest SHA must come from an independently trusted export receipt.
    Validation never authorizes extraction into /nix, registration or execution.
    """
    require(type(data) is bytes and len(data) <= MAX_ARCHIVE and type(manifest_sha256) is str
            and SHA.fullmatch(manifest_sha256), "archive_invalid")
    until, seen, metadata = time.monotonic() + SECONDS, set(), {}
    order, offset = ["manifest.json", *sorted(MEMBERS.values())], 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                budget(until)
                require(member.isfile() and member.name in {"manifest.json", *MEMBERS.values()}
                        and member.name not in seen and member.uid == member.gid == member.mtime == 0
                        and member.mode == 0o444 and not member.uname and not member.gname and not member.pax_headers
                        and 0 <= member.size <= MAX_FILE, "archive_invalid")
                require(len(seen) < len(order) and member.name == order[len(seen)] and member.offset == offset
                        and member.offset_data == offset + 512
                        and data[offset:offset + 512] == member.tobuf(format=tarfile.USTAR_FORMAT), "archive_invalid")
                offset += 512 + ((member.size + 511) // 512) * 512
                require(not any(data[member.offset_data + member.size:offset]), "archive_invalid")
                seen.add(member.name)
                stream = archive.extractfile(member)
                if member.name == "manifest.json":
                    require(len(seen) == 1 and member.size <= MAX_METADATA, "archive_invalid")
                    encoded = stream.read(MAX_METADATA + 1)
                    require(digest(encoded) == manifest_sha256, "digest_mismatch")
                    manifest = authority.parse(encoded)
                    require(canonical(manifest) == encoded, "archive_invalid")
                    require(type(manifest) is dict and type(manifest.get("schemaVersion")) is int
                            and manifest["schemaVersion"] == 1
                            and all(manifest.get(key) is False for key in ("destinationRegistrationVerified",
                                "storePayloadIncluded", "executionAuthority", "activationPerformed", "transferPerformed")),
                            "archive_invalid")
                    selected = selection(manifest["selection"])
                    require(set(manifest["members"]) == set(MEMBERS.values()), "archive_invalid")
                    continue
                record = manifest["members"][member.name]
                require(record == {"sha256": record["sha256"], "bytes": member.size, "mode": 0o444}
                        and type(record["bytes"]) is int and type(record["mode"]) is int
                        and type(record["sha256"]) is str and SHA.fullmatch(record["sha256"]), "archive_invalid")
                key = member.name.split("/", 1)[1]
                if key not in {"controller_nar", "browser_nar"}:
                    require(record["sha256"] == selected["inputSha256" if key in INPUTS else "evidenceSha256"][key],
                            "digest_mismatch")
                hashed, length, collected = hashlib.sha256(), 0, bytearray()
                for block in iter(lambda: stream.read(65536), b""):
                    budget(until); length += len(block); hashed.update(block)
                    if member.name.startswith("evidence/") or member.name == MEMBERS["runtime_authority"]:
                        collected.extend(block)
                        require(len(collected) <= (MAX_SOURCE if member.name == MEMBERS["source_archive"] else MAX_METADATA), "byte_bound")
                require(length == member.size and hashed.hexdigest() == record["sha256"], "digest_mismatch")
                if member.name.startswith("evidence/") or member.name == MEMBERS["runtime_authority"]:
                    metadata[key] = bytes(collected)
        require(seen == {"manifest.json", *MEMBERS.values()}, "archive_invalid")
        archive_length = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
        require(len(data) == archive_length and not any(data[offset:]), "archive_invalid")
        source, requirements, projected = manifest_for(metadata, selected, until)
        require(all(metadata[name] == content for name, content in projected.items()), "archive_invalid")
        require(manifest == {"schemaVersion": 1, "scope": "yoga-public-payload-v1", "platform": "x86_64-linux",
            "selection": selected, "members": manifest["members"], "source": source, "storeRequirements": requirements,
            "requiredMasks": authority.MASKS, "destinationRegistrationVerified": False, "storePayloadIncluded": False,
            "executionAuthority": False, "activationPerformed": False, "transferPerformed": False}, "archive_invalid")
        return manifest
    except (tarfile.TarError, EOFError, OSError, KeyError, TypeError, ValueError) as failure:
        if isinstance(failure, PayloadError):
            raise
        raise PayloadError("archive_invalid") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True); parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    for name in sorted(INPUTS | EVIDENCE):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    until = time.monotonic() + SECONDS
    picked = Captured(args.selection, args.selection_sha256, MAX_METADATA, until)
    try:
        selected = selection(authority.parse(picked.bytes(MAX_METADATA)))
        result = produce({name: getattr(args, name) for name in INPUTS | EVIDENCE}, selected, args.output_dir,
                         final_check=picked.check, until=until)
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        picked.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        reason = failure.reason if isinstance(failure, PayloadError) else "input_invalid"
        print(json.dumps({"scope": "yoga-public-payload-refused", "reason": reason, "executionAuthority": False}), file=sys.stderr)
        sys.exit(125)
