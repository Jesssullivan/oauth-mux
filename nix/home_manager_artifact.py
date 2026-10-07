"""Export a caller-selected dirty development archive for separate HM evaluation.

This producer never evaluates, activates or executes an archive member. Its
logical receipt must be frozen independently before any consumer trusts it.
All filesystem traversal is nofollow and descriptor-relative.
"""
import argparse
import base64
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time

import home_manager_acquired_inputs as acquired

sys.path.insert(0, str(Path(__file__).absolute().parent.parent / "delivery"))
import pack

MAX_BYTES = pack.MAX_BYTES
MAX_NODES = 2048
MAX_SECONDS = 300
FREE_FLOOR = 2 * 1024 * 1024 * 1024
NATIVE_BINS = ["bin/omux", "bin/omuxd", "bin/omux-native-host", "bin/omux-control"]
FIELDS = {"schemaVersion", "kind", "archiveSha256", "archiveBytes", "manifestSha256",
          "narHash", "narSize", "system", "channel", "sourceRevision", "sourceDirty",
          "fullQt", "nativeBins", "sourceQualification"}
require = acquired.require
snapshot = acquired.snapshot


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def deadline_for(seconds):
    require(type(seconds) is int and 1 <= seconds <= MAX_SECONDS, "artifact-deadline-bound")
    return time.monotonic() + seconds


def identity(info):
    return info.st_dev, info.st_ino, info.st_uid


class HeldDirectory:
    """Keep every ancestor descriptor and check the live pathname before use."""
    def __init__(self, path, owned=True):
        self.path = Path(acquired.physical_path(os.fspath(path)))
        self.chain = []
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.chain.append((None, "", fd, identity(os.fstat(fd))))
            for name in self.path.parts[1:]:
                parent = self.chain[-1][2]
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
                self.chain.append((parent, name, fd, identity(os.fstat(fd))))
            self.fd = fd
            self.check()
            require(not owned or os.fstat(fd).st_uid == os.getuid(), "artifact-directory-owner")
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, fd, witness in self.chain:
            info = os.fstat(fd)
            protected = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(identity(info) == witness and stat.S_ISDIR(info.st_mode)
                    and info.st_uid in (0, os.getuid())
                    and (not info.st_mode & 0o022 or protected), "artifact-ancestor-custody")
            if parent is not None:
                require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == witness,
                        "artifact-ancestor-replaced")

    def close(self):
        for _, _, fd, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class Archive:
    def __init__(self, path, expected, deadline, *, declared_alias=False):
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
                "artifact-archive-digest")
        require(type(declared_alias) is bool, "artifact-declared-alias-selector")
        self.logical = Path(acquired.physical_path(os.fspath(path)))
        self.alias_facts = None
        if declared_alias:
            # The sole alias authority is the explicit action input. Resolve it
            # once, then keep both its logical binding and physical descriptors.
            self.path = self.logical.resolve(strict=True)
            self.alias_facts = self.alias_binding()
        else:
            self.path = self.logical
        self.parent = HeldDirectory(self.path.parent, owned=False)
        self.fd = None
        try:
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=self.parent.fd)
            info = os.fstat(self.fd)
            self.witness = snapshot(info)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
                    and info.st_nlink == 1 and not info.st_mode & 0o6022
                    and 0 < info.st_size <= MAX_BYTES, "artifact-archive-custody-or-bound")
            self.check(deadline)
            payload = bytearray()
            while len(payload) <= MAX_BYTES:
                self.check(deadline)
                chunk = os.read(self.fd, min(65536, MAX_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            self.check(deadline)
            require(len(payload) == info.st_size and sha(payload) == expected,
                    "artifact-archive-binding")
            self.payload = bytes(payload)
        except BaseException:
            self.close()
            raise

    def check(self, deadline):
        acquired.check_deadline(deadline)
        if self.alias_facts is not None:
            require(self.logical.resolve(strict=True) == self.path
                    and self.alias_binding() == self.alias_facts,
                    "artifact-declared-alias-retargeted")
        self.parent.check()
        require(snapshot(os.fstat(self.fd)) == self.witness
                == snapshot(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)),
                "artifact-archive-replaced")

    def alias_binding(self):
        facts = []
        cursor = Path("/")
        for name in self.logical.parts[1:]:
            cursor = cursor / name
            info = cursor.lstat()
            protected = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in (0, os.getuid())
                    and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022 or protected),
                    "artifact-declared-alias-custody")
            if stat.S_ISLNK(info.st_mode):
                facts.append((str(cursor), snapshot(info), os.readlink(cursor)))
            elif stat.S_ISDIR(info.st_mode):
                facts.append((str(cursor), identity(info), stat.S_IMODE(info.st_mode)))
            else:
                facts.append((str(cursor), snapshot(info)))
        return facts

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.parent.close()


def development_manifest(manifest, files, revision):
    require(acquired.decode(files["release-manifest.json"], MAX_BYTES) == manifest,
            "artifact-manifest-json-binding")
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision),
            "artifact-caller-revision")
    require(manifest.get("target") == "x86_64-linux"
            and manifest.get("channel") == "development"
            and manifest.get("distribution") == "portable-linux"
            and manifest.get("provenance") == {"sourceRevision": revision, "sourceDirty": True},
            "artifact-development-provenance")
    qt = manifest.get("runtime", {}).get("qt")
    require(isinstance(qt, dict) and qt.get("plugins") and qt.get("dependencies")
            and all(name in files for name in NATIVE_BINS), "artifact-full-qt-required")


class ExportTree:
    """Exclusive private creation with pinned directory and regular-file leaves."""
    def __init__(self, parent, archive, deadline):
        self.parent, self.archive, self.deadline = parent, archive, deadline
        self.dirs, self.files = {}, {}
        self.sealed = {}
        self.logical_bytes = 0

    def check(self, allocation=0):
        self.archive.check(self.deadline)
        self.parent.check()
        for path, (fd, witness, parent, name) in self.dirs.items():
            info = os.fstat(fd)
            require(identity(info) == witness and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid() and not info.st_mode & 0o7022
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == witness,
                    "artifact-output-directory-replaced")
            if path in self.sealed:
                require(snapshot(info) == self.sealed[path],
                        "artifact-sealed-directory-changed")
            expected = {p.rsplit("/", 1)[-1] for p in (*self.dirs, *self.files)
                        if p != path and p.rsplit("/", 1)[0] == path}
            os.lseek(fd, 0, os.SEEK_SET)
            with os.scandir(fd) as entries:
                actual = set()
                for entry in entries:
                    acquired.check_deadline(self.deadline)
                    require(len(actual) < MAX_NODES, "artifact-output-entry-bound")
                    actual.add(entry.name)
            require(actual == expected, "artifact-output-unexpected-entry")
        for fd, witness, parent, name in self.files.values():
            require(snapshot(os.fstat(fd)) == witness
                    == snapshot(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    "artifact-output-file-replaced")
        disk = os.fstatvfs(self.parent.fd)
        require(disk.f_bavail * disk.f_frsize >= FREE_FLOOR + allocation,
                "artifact-disk-floor")

    def directory(self, path):
        if path in self.dirs:
            return self.dirs[path][0]
        require(len(self.dirs) + len(self.files) < MAX_NODES, "artifact-node-bound")
        parts = path.split("/")
        require(0 < len(parts) <= 64 and all(p not in ("", ".", "..") for p in parts)
                and len(os.fsencode(path)) <= 4096, "artifact-output-path")
        parent = self.parent.fd if len(parts) == 1 else self.directory("/".join(parts[:-1]))
        self.check()
        os.mkdir(parts[-1], 0o700, dir_fd=parent)
        created = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        require(snapshot(os.fstat(fd)) == snapshot(created)
                and stat.S_IMODE(created.st_mode) == 0o700,
                "artifact-created-directory-replaced")
        self.dirs[path] = (fd, identity(os.fstat(fd)), parent, parts[-1])
        self.check()
        return fd

    def write(self, path, payload, executable=False):
        pack.checked_name(path)
        require(path not in self.files and isinstance(payload, bytes)
                and len(self.dirs) + len(self.files) < MAX_NODES
                and self.logical_bytes + len(payload) <= MAX_BYTES + 65536,
                "artifact-output-byte-bound")
        parent_path, name = path.rsplit("/", 1)
        parent = self.directory(parent_path)
        self.check(len(payload))
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=parent)
        self.files[path] = (fd, snapshot(os.fstat(fd)), parent, name)
        self.logical_bytes += len(payload)
        try:
            offset = 0
            while offset < len(payload):
                self.check(len(payload) - offset)
                count = os.write(fd, payload[offset:offset + 65536])
                require(count > 0, "artifact-short-write")
                offset += count
                self.files[path] = (fd, snapshot(os.fstat(fd)), parent, name)
            self.check()
            os.fchmod(fd, 0o555 if executable else 0o444)
            self.files[path] = (fd, snapshot(os.fstat(fd)), parent, name)
            self.check()
            os.fsync(fd)
            self.check()
        except BaseException:
            # Retain failed private evidence; never unlink an unverified path.
            raise

    def seal(self, prefix):
        for path in sorted((p for p in self.dirs if p == prefix or p.startswith(prefix + "/")),
                           key=lambda p: p.count("/"), reverse=True):
            self.check()
            # Resealing the surrounding envelope must not fchmod its already
            # frozen descendants: even fchmod(0555) to 0555 changes ctime.
            # Keep their complete captured metadata witness unchanged.
            if path not in self.sealed:
                require(stat.S_IMODE(os.fstat(self.dirs[path][0]).st_mode) == 0o700,
                        "artifact-unsealed-directory-mode-changed")
                os.fchmod(self.dirs[path][0], 0o555)
                self.sealed[path] = snapshot(os.fstat(self.dirs[path][0]))
                self.check()
            os.fsync(self.dirs[path][0])
            self.check()

    def close(self):
        for fd, *_ in self.files.values():
            os.close(fd)
        for fd, *_ in reversed(list(self.dirs.values())):
            os.close(fd)


def tree_bytes(root, deadline):
    """Rehash every readonly leaf and retain a complete inode/ctime commitment."""
    with HeldDirectory(root) as held:
        held.check()
        nodes, facts = acquired.scan(held.fd, deadline)
        require(len(nodes) <= MAX_NODES and len([n for n in nodes if n["type"] == "regular"])
                <= pack.MAX_FILES and all(n["type"] in ("directory", "regular") for n in nodes),
                "artifact-tree-closed-regular")
        directories = {""}
        for node in nodes:
            if node["type"] == "regular":
                parts = node["path"].split("/")
                directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        require({n["path"] for n in nodes if n["type"] == "directory"} == directories,
                "artifact-tree-unaccounted-directory")
        files = {}
        total = 0
        for node in nodes:
            if node["type"] == "regular":
                total += node["size"]
                require(total <= MAX_BYTES, "artifact-tree-byte-bound")
                held.check()
                with acquired.regular_stream(held.fd, node["path"], facts, deadline) as stream:
                    pieces, size = [], 0
                    while True:
                        held.check()
                        acquired.check_deadline(deadline)
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        require(size <= node["size"], "artifact-tree-file-growth")
                        pieces.append(chunk)
                require(size == node["size"], "artifact-tree-file-size")
                files[node["path"]] = b"".join(pieces)
        descriptor = {"schemaVersion": 1, "root": str(root), "nodes": nodes}
        acquired.validate_descriptor(descriptor)
        digest, nar_size = hashlib.sha256(), 0

        def emit(chunk):
            nonlocal nar_size
            held.check()
            acquired.check_deadline(deadline)
            nar_size += len(chunk)
            require(nar_size <= MAX_BYTES + 4 * 1024 * 1024, "artifact-nar-byte-bound")
            digest.update(chunk)

        @contextmanager
        def opener(unused_root, relative):
            held.check()
            with acquired.regular_stream(held.fd, relative, facts, deadline) as stream:
                yield stream
            held.check()

        acquired.serialize(descriptor, emit, opener=opener, deadline=deadline)
        held.check()
        require(acquired.scan(held.fd, deadline) == (nodes, facts), "artifact-tree-changed")
        return files, nodes, facts, "sha256-" + base64.b64encode(digest.digest()).decode(), nar_size


def verify_copied_bundle(files, nodes):
    # Feed the same bounded archive verifier from the closed actual tree. No
    # native member is executed and no historical source claim is inferred.
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        by_path = {n["path"]: n for n in nodes if n["type"] == "regular"}
        for name, content in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o755 if by_path[name]["executable"] else 0o644
            tar.addfile(member, io.BytesIO(content))
    return pack.verify_bundle(gzip.compress(raw.getvalue(), compresslevel=1, mtime=0))[0]


def validate_receipt(receipt_bytes, frozen_sha):
    require(isinstance(frozen_sha, str) and re.fullmatch(r"[0-9a-f]{64}", frozen_sha)
            and isinstance(receipt_bytes, bytes) and sha(receipt_bytes) == frozen_sha,
            "artifact-frozen-receipt-binding")
    receipt = acquired.decode(receipt_bytes, 65536)
    require(isinstance(receipt, dict) and set(receipt) == FIELDS and type(receipt["schemaVersion"]) is int
            and receipt["schemaVersion"] == 1
            and receipt["kind"] == "omux-home-manager-development-artifact"
            and receipt["system"] == "x86_64-linux" and receipt["channel"] == "development"
            and receipt["sourceDirty"] is True and receipt["fullQt"] is True
            and receipt["nativeBins"] == NATIVE_BINS
            and receipt["sourceQualification"] == "caller-declared-dirty-development",
            "artifact-receipt-schema")
    for field in ("archiveSha256", "manifestSha256"):
        require(isinstance(receipt[field], str) and re.fullmatch(r"[0-9a-f]{64}", receipt[field]),
                "artifact-receipt-digest")
    require(isinstance(receipt["sourceRevision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", receipt["sourceRevision"]), "artifact-receipt-revision")
    for field, maximum in (("archiveBytes", MAX_BYTES), ("narSize", MAX_BYTES + 4 * 1024 * 1024)):
        require(type(receipt[field]) is int and 0 < receipt[field] <= maximum,
                "artifact-receipt-byte-bound")
    require(isinstance(receipt["narHash"], str)
            and re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", receipt["narHash"]),
            "artifact-receipt-nar-hash")
    return receipt


def verify_artifact(root, receipt_bytes, independently_frozen_sha256, *, deadline_seconds=120):
    deadline = deadline_for(deadline_seconds)
    receipt = validate_receipt(receipt_bytes, independently_frozen_sha256)
    root = acquired.physical_path(os.fspath(root))
    files, nodes, facts, nar_hash, nar_size = tree_bytes(root, deadline)
    manifest = verify_copied_bundle(files, nodes)
    development_manifest(manifest, files, receipt["sourceRevision"])
    require(sha(files["release-manifest.json"]) == receipt["manifestSha256"]
            and nar_hash == receipt["narHash"] and nar_size == receipt["narSize"],
            "artifact-tree-receipt-binding")
    # The semantic parser above also has a finite byte budget. Re-scan after it
    # so an evaluator can compare this complete custody commitment across use.
    with HeldDirectory(root) as held:
        held.check()
        require(acquired.scan(held.fd, deadline) == (nodes, facts), "artifact-tree-changed")
    return {**receipt, "executionAuthority": False, "activationPerformed": False,
            "metadataCommitment": sha(encoded(facts))}


def export_archive(path, expected_sha256, revision, output_parent, *, deadline_seconds=300,
                   declared_alias=False):
    deadline = deadline_for(deadline_seconds)
    archive = Archive(path, expected_sha256, deadline, declared_alias=declared_alias)
    try:
        manifest, files = pack.verify_bundle(archive.payload)
        development_manifest(manifest, files, revision)
        archive.check(deadline)
        with HeldDirectory(output_parent) as parent:
            # Bazel owns the surrounding output directory. Only this fresh,
            # exclusive envelope is ours to change and seal to readonly modes.
            tree = ExportTree(parent, archive, deadline)
            try:
                tree.directory("home-manager-artifact")
                tree.directory("home-manager-artifact/artifact")
                for name, content in sorted(files.items()):
                    tree.write("home-manager-artifact/artifact/" + name, content,
                               executable=bool(pack.archive_mode(name, manifest.get("runtime")) & 0o111))
                tree.seal("home-manager-artifact/artifact")
                root = parent.path / "home-manager-artifact/artifact"
                actual, nodes, facts, nar_hash, nar_size = tree_bytes(root, deadline)
                require(actual == files, "artifact-copy-byte-binding")
                receipt = {"schemaVersion": 1, "kind": "omux-home-manager-development-artifact",
                           "archiveSha256": expected_sha256, "archiveBytes": len(archive.payload),
                           "manifestSha256": sha(files["release-manifest.json"]),
                           "narHash": nar_hash, "narSize": nar_size, "system": "x86_64-linux",
                           "channel": "development", "sourceRevision": revision, "sourceDirty": True,
                           "fullQt": True, "nativeBins": NATIVE_BINS,
                           "sourceQualification": "caller-declared-dirty-development"}
                raw_receipt = encoded(receipt)
                tree.check()
                require(tree_bytes(root, deadline)[2] == facts, "artifact-publication-tree-changed")
                tree.write("home-manager-artifact/inventory.json", encoded({"schemaVersion": 1, "nodes": nodes}))
                tree.check()
                tree.write("home-manager-artifact/receipt.json", raw_receipt)
                tree.seal("home-manager-artifact")
                tree.check()
                require(tree_bytes(root, deadline)[2] == facts, "artifact-publication-tree-changed")
                return receipt
            finally:
                tree.close()
    finally:
        archive.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--declared-archive-alias", action="store_true")
    args = parser.parse_args()
    output = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
    try:
        require(output is not None, "artifact-bazel-retained-output-required")
        receipt = export_archive(args.archive, args.archive_sha256, args.source_revision, output,
                                 declared_alias=args.declared_archive_alias)
    except (ValueError, OSError, KeyError, TypeError, EOFError, tarfile.TarError) as error:
        # Retain a finite diagnostic category; never dump a traceback, artifact
        # payload, caller path, or exception string from arbitrary archive JSON.
        message = error.args[0] if error.args else None
        reason = message if isinstance(message, str) and re.fullmatch(
            r"(?:artifact|acquired|descriptor)-[a-z-]{1,80}", message) else type(error).__name__
        print("home-manager-artifact: refused (" + reason + ")", file=sys.stderr)
        return 1
    # This is a producer result for the coordinator to freeze independently.
    # It grants no evaluator authority and leaves the raw receipt byte-stable.
    report = {"receiptSha256": sha(encoded(receipt)),
              "archiveSha256": receipt["archiveSha256"], "narHash": receipt["narHash"],
              "narSize": receipt["narSize"], "sourceQualification": receipt["sourceQualification"],
              "executionAuthority": False, "activationPerformed": False}
    payload = encoded(report)
    require(len(payload) <= 1024, "artifact-success-report-bound")
    print(payload.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
