"""Finite regular-file reads for declared public evaluation metadata."""
import json
import os
import stat


def read_regular(path, limit=1048576):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("declared-input-not-bounded-regular-file")
        chunks = []
        count = 0
        while count <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        if count > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("declared-input-bound-or-change")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_json(path):
    return json.loads(read_regular(path))
