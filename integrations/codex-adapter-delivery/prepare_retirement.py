"""Emit reviewed delta bytes into a new private output, never mutate SDK input."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from retirement_delta import MAX_SOURCE_BYTES, transform


def prepare(source, expected_sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("noncanonical before digest")
    before = hashlib.sha256(source).hexdigest()
    if before != expected_sha256:
        raise ValueError("before digest mismatch")
    after = transform(source)
    return after, {"ruling_id": "R-N13", "status": "unapplied-source-delta",
                   "source_path": "codex-rs/core/src/thread_manager.rs",
                   "before_sha256": before, "after_sha256": hashlib.sha256(after).hexdigest(),
                   "source_bytes": len(source), "output_bytes": len(after),
                   "native_support": False, "native_tests_passed": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", type=Path, required=True)
    parser.add_argument("--expected-before-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_file
    if not source.is_absolute() or source.resolve(strict=True) != source or source.parts[-4:] != ("codex-rs", "core", "src", "thread_manager.rs"):
        raise ValueError("source path custody mismatch")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > MAX_SOURCE_BYTES:
            raise ValueError("source file custody mismatch")
        value = stream.read(MAX_SOURCE_BYTES + 1)
    after, receipt = prepare(value, args.expected_before_sha256)
    output = args.output_directory
    if output.is_relative_to(source.parents[3]):
        raise ValueError("output must be outside SDK source tree")
    parent = output.parent
    info = parent.lstat()
    if not output.is_absolute() or parent.resolve(strict=True) != parent or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("output parent custody mismatch")
    output.mkdir(mode=0o700)
    for name, payload in (("thread_manager.rs", after), ("delta-receipt.json", (json.dumps(receipt, indent=2) + "\n").encode())):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())


if __name__ == "__main__":
    main()
