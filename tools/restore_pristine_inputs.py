"""Validate a declared pristine archive and receipt before fresh restoration."""

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import tarfile

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
TREE = "6fa1a3767a92ba5d579fcaf724fdce3049c2070b"
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_RECEIPT = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts and str(path) == name
            and not any(char in name for char in "\\\0\r\n"), "unsafe pristine path")
    return name


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate pristine receipt key")
        result[key] = value
    return result


def verified_stream(path, expected, limit):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "noncanonical pristine digest")
    fd = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "pristine input exceeds bound")
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            require(size <= limit, "pristine input grew beyond bound")
            digest.update(chunk)
        require(size == info.st_size and digest.hexdigest() == expected, "pristine input digest mismatch")
        stream.seek(0)
        return stream
    except BaseException:
        stream.close()
        raise


def original_files(archive, archive_sha256, receipt, receipt_sha256):
    with verified_stream(receipt, receipt_sha256, MAX_RECEIPT) as stream:
        report = json.load(stream, object_pairs_hook=unique_object)
    require(report.get("status") == "verified-pristine-source" and report.get("commit") == COMMIT
            and report.get("tree") == TREE and report.get("archive_sha256") == archive_sha256,
            "pristine receipt authority mismatch")
    inventory = report.get("files")
    require(isinstance(inventory, dict) and len(inventory) == report.get("tracked_files") == 8497,
            "pristine inventory count mismatch")
    require(hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest() == report.get("inventory_sha256"),
            "pristine inventory digest mismatch")
    files = {}
    total = 0
    archive_format = report.get("archive_format", "tar")
    require(archive_format in ("tar", "tar.gz"), "unsupported pristine archive format")
    with verified_stream(archive, archive_sha256, MAX_ARCHIVE) as stream:
        require(os.fstat(stream.fileno()).st_size == report.get("archive_bytes"), "pristine archive size mismatch")
        with tarfile.open(fileobj=stream, mode="r:gz" if archive_format == "tar.gz" else "r:") as source:
            members = 0
            for member in source:
                members += 1
                require(members <= 50000, "pristine tar member count exceeded")
                if member.isdir():
                    safe_name(member.name.rstrip("/"))
                    continue
                name = safe_name(member.name)
                require(name not in files and name in inventory, "pristine archive inventory mismatch")
                expected = inventory[name]
                require(isinstance(expected, dict) and set(expected) == {"mode", "sha256"}, "pristine entry schema mismatch")
                mode = expected["mode"]
                if mode == "120000":
                    require(member.issym(), "pristine symlink type mismatch")
                    value = member.linkname.encode()
                else:
                    require(mode in ("100644", "100755") and member.isfile() and member.size <= MAX_ARCHIVE
                            and (member.mode & 0o777) == (0o755 if mode == "100755" else 0o644),
                            "pristine regular-file mode mismatch")
                    total += member.size
                    require(total <= MAX_ARCHIVE, "pristine expanded bytes exceed bound")
                    with source.extractfile(member) as item:
                        value = item.read(member.size + 1)
                    require(len(value) == member.size, "pristine member size mismatch")
                require(hashlib.sha256(value).hexdigest() == expected["sha256"], "pristine member digest mismatch")
                files[name] = (mode, value)
    require(set(files) == set(inventory), "pristine archive is incomplete")
    # Source writers must never traverse an archive-supplied symlink parent.
    for name in files:
        for parent in PurePosixPath(name).parents:
            require(str(parent) not in files or files[str(parent)][0] != "120000", "pristine symlink parent refused")
    require(sum(len(value) for _, value in files.values()) == report.get("source_bytes"), "pristine source size mismatch")
    return files, TREE
