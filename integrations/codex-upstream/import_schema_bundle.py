"""R-N13: import exact declared Rust schema output bytes, without regeneration."""

import argparse
import json
import os
import stat
import sys
import uuid
from pathlib import Path

from patch_io import digest
from restore_source import private_root, source_directory, write_receipt

MAX_FILES = 8192
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
PREFIX = "codex-rs/app-server-protocol/schema/"


def regular_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES or
                info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError("schema file custody or size differs")
        value = stream.read(MAX_FILE_BYTES + 1)
        if len(value) != info.st_size or len(value) > MAX_FILE_BYTES:
            raise ValueError("schema file changed or exceeds bound")
        return value


def collect(root, allowed):
    source_directory(root)
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        source_directory(parent)
        for name in directories:
            source_directory(parent / name)
        for name in files:
            path = parent / name
            relative = path.relative_to(root).as_posix()
            if any(char in relative for char in "\\\0\r\n\t"):
                raise ValueError("noncanonical schema producer path")
            if not allowed(relative):
                raise ValueError("unexpected schema producer output")
            result[relative] = regular_bytes(path)
            if len(result) > MAX_FILES or sum(map(len, result.values())) > MAX_TOTAL_BYTES:
                raise ValueError("schema producer output exceeds bound")
    if not result:
        raise ValueError("schema producer output is empty")
    return result


def selected_outputs(stable, experimental):
    stable_files = collect(stable, lambda name: (
        name.startswith("typescript/") and name.endswith(".ts") or
        name.startswith("json/") and name.endswith(".json") or
        name == "precomputed/app-server-exports-stable.json.zst"))
    experimental_files = collect(experimental, lambda name:
        name == "precomputed/app-server-exports-experimental.json.zst")
    if ("precomputed/app-server-exports-stable.json.zst" not in stable_files or
            not any(name.startswith("typescript/") for name in stable_files) or
            not any(name.startswith("json/") for name in stable_files)):
        raise ValueError("stable schema producer output is incomplete")
    result = {}
    for mode, files in (("stable", stable_files), ("experimental", experimental_files)):
        for name, value in files.items():
            destination = PREFIX + name
            if destination in result:
                raise ValueError("duplicate schema destination")
            result[destination] = (mode, name, value)
    if len(result) > MAX_FILES or sum(len(item[2]) for item in result.values()) > MAX_TOTAL_BYTES:
        raise ValueError("combined schema producer output exceeds bound")
    return result


def import_bundle(stable, experimental, checkout, receipts, producer_invocation):
    if str(uuid.UUID(producer_invocation)) != producer_invocation:
        raise ValueError("producer invocation is not canonical")
    source_directory(checkout)
    roots = (stable, experimental, checkout, receipts)
    if any(a.resolve() == b.resolve() or a.resolve().is_relative_to(b.resolve()) or
           b.resolve().is_relative_to(a.resolve()) for i, a in enumerate(roots) for b in roots[i + 1:]):
        raise ValueError("schema custody roots overlap")
    selected = selected_outputs(stable, experimental)
    planned = []
    for name, (mode, relative, value) in sorted(selected.items()):
        target = checkout / name
        # All destination parents must already exist, be canonical and owned.
        # No broad directory creation or deletion is part of this import.
        source_directory(target.parent)
        before = regular_bytes(target) if target.exists() or target.is_symlink() else None
        planned.append((target, value, {
            "source_mode": mode, "source_relative_path": relative,
            "destination": name, "before_sha256": digest(before) if before is not None else None,
            "after_sha256": digest(value), "bytes": len(value),
        }))
    private_root(receipts, create=True)
    write_receipt(receipts, "import-intent.json", {
        "ruling_id": "R-N13", "producer_invocation_id": producer_invocation,
        "files": [record for _, _, record in planned], "status": "planned",
    })
    for target, value, record in planned:
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = ".omux-schema-" + str(uuid.uuid4())
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o644, dir_fd=directory_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            current = regular_bytes(target) if target.exists() or target.is_symlink() else None
            if (digest(current) if current is not None else None) != record["before_sha256"]:
                raise ValueError("schema destination changed after preflight")
            os.replace(temporary, target.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)
    for target, _, record in planned:
        if digest(regular_bytes(target)) != record["after_sha256"]:
            raise ValueError("imported schema byte verification differs")
    report = {
        "ruling_id": "R-N13", "phase": "import-schema-bundle", "status": "passed",
        "producer_invocation_id": producer_invocation, "native_support": False,
        "normalization_performed": False, "compression_performed": False,
        "files": [record for _, _, record in planned], "file_count": len(planned),
        "source_bytes": sum(record["bytes"] for _, _, record in planned),
    }
    write_receipt(receipts, "schema-import-receipt.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    for name in ("stable-dir", "experimental-dir", "edited-checkout", "receipt-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--producer-invocation-id", required=True)
    args = parser.parse_args()
    try:
        report = import_bundle(args.stable_dir, args.experimental_dir, args.edited_checkout,
                               args.receipt_directory, args.producer_invocation_id)
    except (ValueError, OSError):
        print("Schema import refused: custody, bounds or byte verification failed.", file=sys.stderr)
        return 1
    print(f"Imported {report['file_count']} exact producer files; native support remains false.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
