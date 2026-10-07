"""Finite retained runtime009 byte custody; no executable/support authority.

R-HOOK-CONVERGENCE-20261004 / R-N13. Only locked Nix/Bazel declarations run this.
Copy preserves the existing source and publishes one fresh owned digest leaf.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

ARCHIVE_SHA = "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
ARCHIVE_BYTES = 119923125
MANIFEST_SHA = "5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678"
NAME = "codex-owner-runtime.tar.gz"
MAX_METADATA = 16 * 1024 * 1024
CHUNK = 1024 * 1024
EXPECTED_RECEIPT = "{\n  \"schema_version\": 1,\n  \"ruling_id\": \"R-N13\",\n  \"additional_ruling_id\": \"R-HOOK-CONVERGENCE-20261004\",\n  \"status\": \"native-owner-runtime-proof-candidate\",\n  \"native_support\": false,\n  \"candidate\": {\n    \"upstream_commit\": \"00c972ed5d6ff6499317fd41b7f23605b8e6850d\",\n    \"patch_sha256\": \"2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46\",\n    \"base_sha256\": \"a794a67af4b6aecd9e91aeb4281354b90d10e10134e7cf6a6028b33f26a2f9d9\",\n    \"binary_overlay_sha256\": \"9d47862cd9e7e1a911d8512dad0ad0f124c928e139b778cd1e89ecfce17c5703\",\n    \"validation_sha256\": \"1e0f27681a57f4c7d2102d69d01f73586d743341b9baea306e863069c74fc86a\",\n    \"complete_source_inventory_sha256\": \"3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b\",\n    \"compile_invocation_id\": \"185ffba7-9b08-450f-ab29-1d405810892a\",\n    \"source_verification_invocation_id\": \"5a9d8326-5327-4052-8a6e-946dcc4d18ac\",\n    \"current_compile_invocation_id\": \"c9757a04-8de8-4a61-9029-6c312e153ac6\",\n    \"current_configuration\": \"owner-linux-opt\",\n    \"current_source_verification_invocation_id\": \"fe794e5f-a4ae-4edb-8496-7df5b14c8c77\",\n    \"current_source_receipt_sha256\": \"e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273\"\n  },\n  \"executable\": {\n    \"backend_max_bytes\": 536870912,\n    \"original_sha256\": \"4635bbee6d7f19ddcdbaa3247fe197c11c7169f191255baaaa41579f54ca2695\",\n    \"original_bytes\": 405575744,\n    \"stripped_sha256\": \"37e8eaafa9e83e90bc4e804bad37ccdb4660252a1a4804946b776d1e1fe132a3\",\n    \"stripped_bytes\": 318558680,\n    \"packaged_sha256\": \"0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f\",\n    \"packaged_bytes\": 318579008\n  },\n  \"archive_sha256\": \"0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad\",\n  \"archive_bytes\": 119923125,\n  \"manifest_sha256\": \"5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678\",\n  \"scope\": \"Declared transformed runtime proof input; no SDK execution, installation or continuity proof.\"\n}\n".encode("ascii")
CLEANUP_RESERVE_NS = 30 * 10**9


def budget(deadline_ns):
    if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
        raise ValueError("retained-input-deadline")


def identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode), "links": info.st_nlink}


def directory_custody(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("retained-output-directory-custody")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def regular(fd, *, exact=None, maximum=None):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022
            or exact is not None and info.st_size != exact
            or maximum is not None and not 0 < info.st_size <= maximum):
        raise ValueError("retained-input-custody")
    return identity(info)


def open_declared(path):
    # Bazel's declared runfile alias may be linked; its resolved regular input
    # is then opened without following a final link. No caller discovery.
    path = Path(path).resolve(strict=True)
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)


def stream_digest(fd, deadline_ns, *, output=None):
    before = regular(fd, exact=ARCHIVE_BYTES)
    os.lseek(fd, 0, os.SEEK_SET)
    digest, total = hashlib.sha256(), 0
    while True:
        budget(deadline_ns)
        value = os.read(fd, min(CHUNK, ARCHIVE_BYTES - total + 1))
        if not value:
            break
        total += len(value)
        if total > ARCHIVE_BYTES:
            raise ValueError("retained-input-size")
        digest.update(value)
        if output is not None:
            offset = 0
            while offset < len(value):
                budget(deadline_ns)
                written = os.write(output, value[offset:])
                if written <= 0:
                    raise OSError("retained-input-write")
                offset += written
    if total != ARCHIVE_BYTES or digest.hexdigest() != ARCHIVE_SHA or regular(fd, exact=ARCHIVE_BYTES) != before:
        raise ValueError("retained-input-identity")
    return before


def pinned_metadata(manifest, receipt, deadline_ns):
    facts = {}
    for name, path in (("manifest", manifest), ("receipt", receipt)):
        fd = open_declared(path)
        try:
            before = regular(fd, maximum=MAX_METADATA)
            values, total = [], 0
            while True:
                budget(deadline_ns)
                value = os.read(fd, min(CHUNK, MAX_METADATA - total + 1))
                if not value:
                    break
                total += len(value)
                if total > MAX_METADATA:
                    raise ValueError("retained-metadata-size")
                values.append(value)
            value = b"".join(values)
            if len(value) != before["bytes"] or regular(fd, maximum=MAX_METADATA) != before:
                raise ValueError("retained-metadata-changed")
            if ((name == "manifest" and hashlib.sha256(value).hexdigest() != MANIFEST_SHA)
                    or (name == "receipt" and value != EXPECTED_RECEIPT)):
                raise ValueError("retained-metadata-identity")
            facts[name] = {"sha256": hashlib.sha256(value).hexdigest(), **before}
        finally:
            os.close(fd)
    return facts


def write_all(fd, value):
    offset = 0
    while offset < len(value):
        written = os.write(fd, value[offset:])
        if written <= 0:
            raise OSError("retained-receipt-write")
        offset += written


def copy_retained(archive, manifest, receipt, outputs, deadline_ns):
    """Outputs is exclusively Bazel TEST_UNDECLARED_OUTPUTS_DIR in production."""
    facts = pinned_metadata(manifest, receipt, deadline_ns)
    source = open_declared(archive)
    parent = directory = target = receipt_fd = None
    created = False
    complete = False
    output_identity = None
    directory_identity = None
    try:
        parent_path = Path(outputs).resolve(strict=True)
        parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("retained-output-custody")
        os.mkdir(ARCHIVE_SHA, mode=0o700, dir_fd=parent)
        created = True
        directory = os.open(ARCHIVE_SHA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        directory_identity = directory_custody(os.fstat(directory))
        target = os.open(NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        output_identity = identity(os.fstat(target))
        source_identity = stream_digest(source, deadline_ns, output=target)
        os.fsync(target)
        os.fchmod(target, 0o400)
        copied = stream_digest(target, deadline_ns)
        named_source = open_declared(archive)
        try:
            if (regular(source, exact=ARCHIVE_BYTES) != source_identity
                    or regular(named_source, exact=ARCHIVE_BYTES) != source_identity):
                raise ValueError("retained-source-changed-after-copy")
        finally:
            os.close(named_source)
        after_metadata = pinned_metadata(manifest, receipt, deadline_ns)
        if after_metadata != facts:
            raise ValueError("retained-metadata-changed-after-copy")
        if (identity(os.stat(NAME, dir_fd=directory, follow_symlinks=False)) != copied
                or directory_custody(os.stat(ARCHIVE_SHA, dir_fd=parent, follow_symlinks=False)) != directory_identity):
            raise ValueError("retained-output-changed")
        os.fsync(directory)
        os.fsync(parent)
        report = {"schemaVersion": 1, "kind": "omux-retained-runtime-input-copy",
                  "archiveSha256": ARCHIVE_SHA, "archiveBytes": ARCHIVE_BYTES,
                  "manifestSha256": MANIFEST_SHA, "source": source_identity,
                  "copied": copied, "copiedDirectory": directory_identity, "metadata": facts, "nativeSupport": False,
                  "sourceProducerVerification": "retained-pins-only",
                  "scope": "Copied retained runtime byte identity; no ELF execution, install, channel or provider authority.",
                  "authority": ["R-HOOK-CONVERGENCE-20261004", "R-N13"]}
        receipt_fd = os.open("codex-owner-runtime-input-receipt.json",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        write_all(receipt_fd, (json.dumps(report, sort_keys=True) + "\n").encode())
        os.fsync(receipt_fd)
        os.fsync(parent)
        budget(deadline_ns)
        complete = True
        return report
    finally:
        # Only this newly created leaf/file may be removed on refusal. Never
        # touch a pre-existing leaf, source input or another owner's files.
        primary = sys.exc_info()[1]
        cleanup_error = None
        try:
            if not complete and receipt_fd is not None and parent is not None:
                held = os.fstat(receipt_fd)
                named = os.stat("codex-owner-runtime-input-receipt.json", dir_fd=parent, follow_symlinks=False)
                if (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino):
                    os.unlink("codex-owner-runtime-input-receipt.json", dir_fd=parent)
            if not complete and created and directory is not None:
                if output_identity is not None:
                    current = os.stat(NAME, dir_fd=directory, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (output_identity["device"], output_identity["inode"]):
                        os.unlink(NAME, dir_fd=directory)
                with os.scandir(directory) as entries:
                    empty = next(entries, None) is None
                if empty and directory_identity is not None:
                    named_directory = os.stat(ARCHIVE_SHA, dir_fd=parent, follow_symlinks=False)
                    if (named_directory.st_dev, named_directory.st_ino) != (directory_identity["device"], directory_identity["inode"]):
                        raise OSError("retained-copy-cleanup-owner-changed")
                    os.rmdir(ARCHIVE_SHA, dir_fd=parent)
        except OSError as error:
            cleanup_error = error
        finally:
            for fd in (receipt_fd, target, directory, parent, source):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError as error:
                        cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            if primary is not None:
                primary.add_note("retained-copy-cleanup-refused")
            else:
                raise OSError("retained-copy-cleanup-refused") from cleanup_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if not os.environ.get("OMUX_EXECUTION_GUARD") or not os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"):
        raise ValueError("retained-copy-requires-declared-test")
    report = copy_retained(args.archive, args.manifest, args.receipt,
                          os.environ["TEST_UNDECLARED_OUTPUTS_DIR"], time.monotonic_ns() + 600 * 10**9)
    print("OMUX_RETAINED_RUNTIME_INPUT_COPY_OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError):
        print("OMUX_RETAINED_RUNTIME_INPUT_COPY_REFUSED", file=sys.stderr)
        sys.exit(125)
