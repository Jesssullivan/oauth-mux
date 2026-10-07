"""Retain one exact successful epoch's mapping log; no alternate inputs."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

EPOCH = "96136df1-0d84-4e65-b7eb-59f1787fb600"
ROOT = Path("/home/jess/.local/state/omux-execution-20261005") / EPOCH
DESTINATION = Path("/srv/fast-local/jess/git/oauth-mux/delivery/proofs/mapping-96136df1.log")
TARGET = "//tools:site_tool_mapping_qualification"
FILE = "cda93667453aab054885c3c0ec6cf44254faa264b2bf4f39bb69d9437109e90d.evidence"
LOG_SHA = "d992fe7f4124ce731ae5338b204b993767f3b40b50883d1be1598e3ac367178d"
MANIFEST_SHA = "c21322a5897503d2fd186f91079377caeb503b3e7f64ffe5ac855f04eb228acf"
PROVENANCE = {
    "flakeSha256": "ae04bb4a08b0627ca0c778e1cb8163d8493b60f9caaf65d6b400659afd6f7039",
    "lockSha256": "8bf597bc60b2cf908a5e1772256e178e9593d0474434f4407ee1247bed38197a",
    "selectionSha256": "6ab7f828fcf92df8394869029462541ce0a495bcd14ff7dc9c25c4c469abc2c7",
    "rootsSha256": "0414b0102496d85ec10818d45dc127c605a51a18ae2f7df53db6e5d1e9a72d27",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if info.st_uid not in (0, os.getuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                os.close(child)
                raise ValueError("unsafe evidence parent")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(fd, name, limit=8192):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(source, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                stat.S_IMODE(before.st_mode) & 0o022 or before.st_size > limit):
            raise ValueError("unsafe or oversized evidence")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(data) > limit or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("evidence changed")
        return data


def validate(receipt, manifest_bytes, log):
    if (receipt.get("id") != EPOCH or receipt.get("exit") != 0 or
            receipt.get("workload_exit") != 0 or receipt.get("descendants_empty") is not True):
        raise ValueError("epoch was not successful and cleaned")
    evidence = receipt.get("test_evidence", {})
    if evidence.get("state") != "preserved" or evidence.get("manifest") != "test-evidence.json" or evidence.get("sha256") != MANIFEST_SHA or digest(manifest_bytes) != MANIFEST_SHA:
        raise ValueError("preserved evidence mismatch")
    manifest = json.loads(manifest_bytes)
    rows = [row for row in manifest["results"] if row.get("target") == TARGET]
    if manifest.get("bazel_exit") != 0 or len(rows) != 1 or rows[0].get("state") != "observed":
        raise ValueError("mapping target evidence mismatch")
    files = [row for row in rows[0]["files"] if row.get("source") == "test.log"]
    if len(files) != 1 or files[0] != {"source": "test.log", "state": "copied", "file": FILE, "bytes": 1073, "sha256": LOG_SHA} or len(log) != 1073 or digest(log) != LOG_SHA:
        raise ValueError("mapping log mismatch")
    objects = [json.loads(line) for line in log.decode().splitlines() if line.startswith("{")]
    if len(objects) != 1:
        raise ValueError("exactly one qualification required")
    result = objects[0]
    if (result.get("passed") is not True or result.get("sourceContentRehashed") is not True or
            result.get("selectedOutputsMatched") is not True or result.get("provenance") != PROVENANCE or
            result.get("nixpkgsSourceNarHash") != "sha256-bxrdOn8SCOv8tN4JbTF/TXq7kjo9ag4M+C8yzzIRYbE=" or
            result.get("nixpkgsRevision") != "1c3fe55ad329cbcb28471bb30f05c9827f724c76" or
            result.get("realized") is not False or result.get("browserExecuted") is not False):
        raise ValueError("qualification predicate mismatch")


def main():
    if len(sys.argv) != 1:
        raise ValueError("this fixed retention action accepts no arguments")
    root = directory(ROOT)
    evidence = directory(ROOT / "test-evidence")
    destination = directory(DESTINATION.parent)
    try:
        receipt = json.loads(read(root, "receipt.json", 16384))
        manifest = read(root, "test-evidence.json")
        log = read(evidence, FILE)
        validate(receipt, manifest, log)
        try:
            existing = read(destination, DESTINATION.name)
        except FileNotFoundError:
            output = os.open(DESTINATION.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=destination)
            with os.fdopen(output, "wb") as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(log)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(destination)
        else:
            if existing != log:
                raise ValueError("retained proof replacement refused")
        print(json.dumps({"filename": DESTINATION.name, "sha256": LOG_SHA}, sort_keys=True))
    finally:
        for descriptor in (destination, evidence, root):
            os.close(descriptor)


if __name__ == "__main__":
    main()
