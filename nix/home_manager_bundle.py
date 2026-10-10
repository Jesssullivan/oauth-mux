"""Finite declared-byte HM bundle import and private offline evaluation.

No fetch, original host-root selector, producer dependency or link-target read.
One namespace writer, existing four-worker per-file fsync owner, original bounds.
"""
import argparse
import ctypes
import errno
import base64
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

import home_manager_acquired_inputs as acquired
import home_manager_acquisition as acquisition
import home_manager_acquired_evaluation as evaluator
import home_manager_artifact as artifact
from evaluation_runner import EvaluationFailure
from home_manager_inputs import paired_lock

MAGIC = b"OMUX-HM-BUNDLE-1\n"
MAX_SECONDS = 900
CLEANUP_SECONDS = 60
MAX_BUNDLE = acquisition.DISK_BUDGET
PAIR_SHA = "9e9c04f6768b4ba7ac4023f54c5ae98c5a585da1642a3fca9c0c153d8a1c30eb"
ARTIFACT_SHA = "aa9c9f0c5808da597294b04d59f1e7111567145e1c3f2790fff07c5e670e2ae8"
SOURCE_WRAPPER = {"epoch": "e3b9e0bc-f473-49f5-be46-4f23e2776a1f",
                  "controllerExit": 3, "workloadExit": 3, "descendantsEmpty": True,
                  "producerSeconds": 617.128,
                  "controllerReceiptSha256": "3356a5660fd73954d33253ec929957c4c47212036280de6c2a4de2ce6eb566f0"}
CONFIG_ROOTS = ("/home/jess/.local/state/omux-execution-20261005/",
                "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/")
require = acquired.require
encoded = acquisition.encoded
sha = acquisition.sha

def close_resources(*descriptors, streams=()):
    """Attempt every owned close, retaining an active primary exception."""
    original, failure = sys.exc_info()[1], None
    for resource in streams:
        if resource is not None:
            try:
                resource.close()
            except BaseException as error:
                failure = failure or error
    for descriptor in descriptors:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                failure = failure or error
    if failure is not None:
        if original is not None:
            original.cleanup_category = "bundle-owned-close-refused"
        else:
            raise failure

def bounds(deadline=None):
    start = time.monotonic()
    end = start + MAX_SECONDS if deadline is None else deadline
    require(type(end) in (int, float) and math.isfinite(end)
            and start + CLEANUP_SECONDS < end <= start + MAX_SECONDS,
            "bundle-enclosing-deadline")
    return end - CLEANUP_SECONDS, end

def action_deadline(operation, environment, *, clock=time.monotonic_ns):
    """Intersect the action's existing 900s cap with the ORIGINAL root end."""
    expected = {"reconstruct": "home-manager-reconstruction-reserved",
                "evaluate": "home-manager-evaluation-reserved"}
    require(operation in expected and environment.get("OMUX_HM_RESERVED_PROFILE") == expected[operation],
            "bundle-reserved-profile")
    entry, end = (environment.get(name, "") for name in
                  ("OMUX_HM_ROOT_ENTRY_NS", "OMUX_HM_ROOT_DEADLINE_NS"))
    require(type(entry) is str and type(end) is str
            and re.fullmatch(r"[0-9]{1,20}", entry) is not None
            and re.fullmatch(r"[0-9]{1,20}", end) is not None, "bundle-original-deadline")
    entry, end, now = int(entry), int(end), clock()
    require(entry > 0 and end - entry == 1200 * 10**9
            and entry <= now < end - (30 + CLEANUP_SECONDS) * 10**9, "bundle-original-deadline")
    # The kernel retains its original 30s reserve. This action retains its own
    # original 60s cleanup allowance inside the already intersected action end.
    return min(end - 30 * 10**9, now + MAX_SECONDS * 10**9) / 10**9

def selected_bundle(configuration):
    """Literal declaration only; evaluate_bundle still proves every authority."""
    acquired.fields(configuration, ("schema_version", "kind", "status", "selection"))
    require(type(configuration["schema_version"]) is int and configuration["schema_version"] == 1
            and configuration["kind"] == "omux-home-manager-compact-input-configuration-v1",
            "bundle-configuration-schema")
    if configuration["status"] == "awaiting-qualified-bundle":
        require(configuration["selection"] is None, "bundle-configuration-schema")
        raise ValueError("bundle-selection-pending")
    require(configuration["status"] == "selected-bundle", "bundle-configuration-schema")
    row = configuration["selection"]
    acquired.fields(row, ("root", "bundle_sha256", "receipt_sha256"))
    root = row["root"]
    require(type(root) is str and len(root) <= 4096
            and root.startswith(CONFIG_ROOTS)
            and all(part not in ("", ".", "..") for part in root.split("/")[1:])
            and not any(char in root for char in ("\\", "\n", "\r", "\t", " ", ":", "\x00")),
            "bundle-selection-root")
    require(all(type(row[key]) is str and re.fullmatch(r"[0-9a-f]{64}", row[key]) is not None
                for key in ("bundle_sha256", "receipt_sha256")), "bundle-selected-digest")
    return row

def evaluate_selection(selection_path, bundle_path, receipt_path, lock_path, nix, modules, scratch, *, deadline):
    work, _ = bounds(deadline)
    raw, facts = evaluator.read_declared(selection_path, 16384, work)
    row = selected_bundle(acquired.decode(raw, 16384))
    # Exact declared aliases must resolve to this literal selected root, never
    # ambient HOME, a neighboring producer, or whichever output is newest.
    require(str(Path(bundle_path).resolve(strict=True)) == row["root"] + "/bundle"
            and str(Path(receipt_path).resolve(strict=True)) == row["root"] + "/receipt.json",
            "bundle-selection-alias")
    result = evaluate_bundle(bundle_path, row["bundle_sha256"], receipt_path,
        row["receipt_sha256"], lock_path, nix, modules, scratch, deadline=deadline)
    require(evaluator.read_declared(selection_path, 16384, work) == (raw, facts),
            "bundle-selection-changed")
    return result

def tick(deadline, directory=None):
    acquired.check_deadline(deadline)
    if directory is not None:
        directory.check()
        info = os.fstatvfs(directory.fd)
        require(info.f_bavail * info.f_frsize >= artifact.FREE_FLOOR, "bundle-free-space")
    # Custody and filesystem reads can block. Recheck the original deadline
    # after that work, before returning to the caller's next effect.
    acquired.check_deadline(deadline)

def relative(path, *, root=False):
    require(isinstance(path, str) and (root or bool(path)) and len(os.fsencode(path)) <= 4096,
            "bundle-relative-name")
    parts = path.split("/") if path else []
    require(len(parts) <= 64 and all(p not in ("", ".", "..") for p in parts)
            and not any(c in path for c in ("\x00", "\n", "\r", "\\")), "bundle-relative-name")
    return parts

def checked_nodes(nodes, root):
    require(isinstance(nodes, list) and 1 <= len(nodes) <= acquired.MAX_NODES,
            "bundle-node-bound")
    descriptor = {"schemaVersion": 1, "root": root, "nodes": nodes}
    by_path, _ = acquired.validate_descriptor(descriptor)
    require(by_path.get("", {}).get("type") == "directory", "bundle-directory-root")
    total = 0
    for node in nodes:
        parts = relative(node["path"], root=True)
        if node["type"] == "regular":
            total += node["size"]
            require(node["size"] <= acquired.MAX_FILE_BYTES and total <= acquired.MAX_TREE_BYTES,
                    "bundle-file-byte-bound")
        elif node["type"] == "symlink":
            target = node["target"]
            require(target and not target.startswith("/") and len(os.fsencode(target)) <= 4096
                    and not any(c in target for c in ("\x00", "\n", "\r", "\\")), "bundle-link-escape")
            stack = parts[:-1]
            for part in target.split("/"):
                if part in ("", "."):
                    continue
                if part == "..":
                    require(stack, "bundle-link-escape")
                    stack.pop()
                else:
                    stack.append(part)
    return descriptor

class Inputs:
    """Only declared relative aliases; no live directory discovery or target walk."""
    def __init__(self, root, deadline):
        self.root, self.deadline, self.facts = Path(root).absolute(), deadline, {}

    @contextmanager
    def open(self, name, *, readonly=True):
        relative(name)
        logical = self.root / name
        selected = logical.resolve(strict=True)
        with acquisition.HeldDirectory(selected.parent, owned_leaf=False) as parent:
            fd = os.open(selected.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent.fd)
            stream = None
            try:
                before = acquired.snapshot(os.fstat(fd))
                require(stat.S_ISREG(before[2]) and before[3] in (0, os.getuid()) and before[5] == 1
                        and 0 <= before[6] <= MAX_BUNDLE and not before[2] & 0o6022
                        and (not readonly or not before[2] & 0o222), "bundle-input-custody")
                witness = (str(selected), before, readonly)
                require(name not in self.facts or self.facts[name] == witness, "bundle-input-changed")
                self.facts[name] = witness
                def check():
                    tick(self.deadline)
                    parent.check()
                    require(logical.resolve(strict=True) == selected and before == acquired.snapshot(os.fstat(fd))
                            == acquired.snapshot(os.stat(selected.name, dir_fd=parent.fd, follow_symlinks=False)),
                            "bundle-input-changed")
                check()
                stream = os.fdopen(fd, "rb", closefd=False)
                yield stream, before, check
                check()
            finally:
                close_resources(fd, streams=(stream,))

    def read(self, name, maximum, *, readonly=True):
        with self.open(name, readonly=readonly) as (stream, info, check):
            require(info[6] <= maximum, "bundle-metadata-bound")
            chunks, size = [], 0
            while True:
                check()
                part = stream.read(min(65536, maximum + 1 - size))
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                require(size <= maximum, "bundle-metadata-bound")
            require(size == info[6], "bundle-input-size")
            return b"".join(chunks)

    def recheck(self):
        for name, (_, _, readonly) in list(self.facts.items()):
            with self.open(name, readonly=readonly):
                pass

def pair_metadata(lock, receipt_bytes, inventory_bytes):
    require(sha(receipt_bytes) == PAIR_SHA, "bundle-pair-receipt")
    receipt = acquired.decode(receipt_bytes, acquired.MAX_RECEIPT_BYTES)
    inventory = acquired.decode(inventory_bytes, acquired.MAX_INVENTORY_BYTES)
    acquired.fields(receipt, ("schemaVersion", "kind", "lockSha256", "inventorySha256", "sources"))
    require(type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["kind"] == "omux-home-manager-acquired-pair"
            and receipt["lockSha256"] == sha(lock) and receipt["inventorySha256"] == sha(inventory_bytes),
            "bundle-pair-binding")
    acquired.fields(inventory, ("schemaVersion", "sources"))
    require(type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1, "bundle-inventory-schema")
    for rows in (receipt["sources"], inventory["sources"]):
        acquired.fields(rows, acquired.NAMES)
    pins = paired_lock(acquired.decode(lock, acquired.MAX_LOCK_BYTES))
    descriptors = {}
    for name in acquired.NAMES:
        row = receipt["sources"][name]
        acquired.fields(row, ("revision", "narHash", "narSize", "url"))
        owner, repo = acquired.REPOSITORIES[name]
        require(row["revision"] == pins[name]["rev"] and row["narHash"] == pins[name]["narHash"]
                and type(row["narSize"]) is int and 0 < row["narSize"] <= acquired.MAX_NAR_BYTES
                and row["url"] == f"https://github.com/{owner}/{repo}/archive/{pins[name]['rev']}.tar.gz",
                "bundle-source-pin")
        acquired.fields(inventory["sources"][name], ("nodes",))
        descriptors[name] = checked_nodes(inventory["sources"][name]["nodes"], "/declared/" + name)
    return receipt, descriptors

def nar_proof(inputs, descriptor, prefix, expected_hash, expected_size):
    digest, size = hashlib.sha256(), 0
    by_path = {node["path"]: node for node in descriptor["nodes"]}
    def emit(part):
        nonlocal size
        tick(inputs.deadline)
        size += len(part)
        require(size <= acquired.MAX_NAR_BYTES, "bundle-nar-bound")
        digest.update(part)
    @contextmanager
    def opener(root, path):
        require(root == descriptor["root"], "bundle-nar-root")
        with inputs.open(prefix + "/" + path) as (stream, info, check):
            node = by_path[path]
            require(info[6] == node["size"] and bool(info[2] & stat.S_IXUSR) == node["executable"],
                    "bundle-regular-metadata")
            # serialize reads <=64 KiB, and emit checks the original deadline.
            yield stream
            check()
    acquired.serialize(descriptor, emit, opener=opener, deadline=inputs.deadline)
    require("sha256-" + base64.b64encode(digest.digest()).decode() == expected_hash and size == expected_size,
            "bundle-nar-mismatch")

def artifact_metadata(inputs, raw_receipt):
    receipt = artifact.validate_receipt(raw_receipt, ARTIFACT_SHA)
    manifest_bytes = inputs.read("artifact/release-manifest.json", 65536)
    require(sha(manifest_bytes) == receipt["manifestSha256"], "bundle-artifact-manifest")
    manifest = acquired.decode(manifest_bytes, 65536)
    items = manifest.get("artifacts", [])
    require(isinstance(items, list) and 0 < len(items) <= artifact.pack.MAX_FILES - 2, "bundle-artifact-files")
    files = {"release-manifest.json": manifest_bytes,
             "SHA256SUMS": inputs.read("artifact/SHA256SUMS", 65536)}
    modes = {"release-manifest.json": False, "SHA256SUMS": False}
    total = sum(map(len, files.values()))
    for item in items:
        name = item["path"]
        relative(name)
        require(name not in files and type(item["size"]) is int and 0 <= item["size"] <= artifact.MAX_BYTES
                and item["mode"] in ("0644", "0755"), "bundle-artifact-file")
        total += item["size"]
        require(total <= artifact.MAX_BYTES, "bundle-artifact-byte-bound")
        data = inputs.read("artifact/" + name, item["size"])
        require(len(data) == item["size"] and sha(data) == item["sha256"], "bundle-artifact-payload")
        files[name], modes[name] = data, item["mode"] == "0755"
    directories = {""}
    for name in files:
        parts = name.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    nodes = ([{"path": p, "type": "directory"} for p in sorted(directories)] +
             [{"path": p, "type": "regular", "size": len(files[p]), "executable": modes[p]} for p in sorted(files)])
    descriptor = checked_nodes(nodes, "/declared/artifact")
    verified = artifact.verify_copied_bundle(files, nodes)
    artifact.development_manifest(verified, files, receipt["sourceRevision"])
    return receipt, descriptor

def entries(descriptors):
    for name in (*acquired.NAMES, "artifact"):
        for node in sorted(descriptors[name]["nodes"], key=lambda n: os.fsencode(n["path"])):
            if node["type"] == "regular":
                yield name, node

def write_all(fd, data, deadline, directory):
    offset = 0
    while offset < len(data):
        tick(deadline, directory)
        amount = os.write(fd, data[offset:offset + 65536])
        require(amount > 0, "bundle-short-write")
        offset += amount

def pack(layout_path, lock_path, outputs, *, deadline=None, disk_account=None):
    work, end = bounds(deadline)
    layout_path = Path(layout_path).absolute()
    inputs = Inputs(layout_path.parent, work)
    raw_layout = inputs.read(layout_path.name, 65536, readonly=False)
    layout = acquired.decode(raw_layout, 65536)
    acquired.fields(layout, ("schemaVersion", "pairReceipt", "pairInventory", "pairReceiptSha256",
                            "artifactReceipt", "artifactManifest", "artifactReceiptSha256", "artifactFiles", "sourceWrapper"))
    require(layout == {**layout, "schemaVersion": 1, "pairReceipt": "pair/receipt.json",
            "pairInventory": "pair/inventory.json", "pairReceiptSha256": PAIR_SHA,
            "artifactReceipt": "artifact-receipt.json", "artifactManifest": "artifact/release-manifest.json",
            "artifactReceiptSha256": ARTIFACT_SHA, "sourceWrapper": SOURCE_WRAPPER}, "bundle-layout-authority")
    lock, lock_facts = evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work)
    raw_pair = inputs.read("pair/receipt.json", acquired.MAX_RECEIPT_BYTES)
    raw_inventory = inputs.read("pair/inventory.json", acquired.MAX_INVENTORY_BYTES)
    raw_artifact = inputs.read("artifact-receipt.json", 65536)
    receipt, descriptors = pair_metadata(lock, raw_pair, raw_inventory)
    artifact_receipt, descriptors["artifact"] = artifact_metadata(inputs, raw_artifact)
    require(layout["artifactFiles"] == sorted(n["path"] for n in descriptors["artifact"]["nodes"] if n["type"] == "regular"),
            "bundle-layout-files")
    def prove():
        for name in acquired.NAMES:
            row = receipt["sources"][name]
            nar_proof(inputs, descriptors[name], "pair/" + name, row["narHash"], row["narSize"])
        nar_proof(inputs, descriptors["artifact"], "artifact", artifact_receipt["narHash"], artifact_receipt["narSize"])
        inputs.recheck()
        require(evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work) == (lock, lock_facts), "bundle-lock-changed")
    prove()
    header = (raw_pair, raw_inventory, raw_artifact, encoded(descriptors["artifact"]["nodes"]))
    predicted = len(MAGIC) + sum(8 + len(part) for part in header) + sum(node["size"] for _, node in entries(descriptors))
    require(predicted <= MAX_BUNDLE, "bundle-output-bound")
    with acquisition.HeldDirectory(outputs) as output:
        tick(work, output)
        if disk_account is not None:
            disk_account.record(os.fstat(output.fd))
        require(not any(os.scandir(output.fd)), "bundle-requires-empty-outputs")
        fd = os.open("bundle", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=output.fd)
        try:
            digest = hashlib.sha256()
            def emit(data):
                digest.update(data)
                write_all(fd, data, work, output)
                if disk_account is not None:
                    disk_account.record(os.fstat(fd))
            emit(MAGIC)
            for part in header:
                emit(struct.pack("<Q", len(part)))
                emit(part)
            for name, node in entries(descriptors):
                prefix = "artifact" if name == "artifact" else "pair/" + name
                with inputs.open(prefix + "/" + node["path"]) as (stream, info, check):
                    require(info[6] == node["size"], "bundle-input-size")
                    remaining = node["size"]
                    while remaining:
                        check()
                        chunk = stream.read(min(65536, remaining))
                        require(chunk, "bundle-input-truncated")
                        emit(chunk)
                        remaining -= len(chunk)
                    require(not stream.read(1), "bundle-input-growth")
            require(os.fstat(fd).st_size == predicted, "bundle-output-size")
            os.fchmod(fd, 0o444)
            os.fsync(fd)
            if disk_account is not None:
                disk_account.record(os.fstat(fd))
            prove()
            before = acquired.snapshot(os.fstat(fd))
            require(before == acquired.snapshot(os.stat("bundle", dir_fd=output.fd, follow_symlinks=False)), "bundle-output-changed")
            os.lseek(fd, 0, os.SEEK_SET)
            readback = hashlib.sha256()
            while True:
                tick(work, output)
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                readback.update(chunk)
            require(readback.digest() == digest.digest() and acquired.snapshot(os.fstat(fd)) == before, "bundle-output-readback")
            if disk_account is not None:
                disk_account.record(os.fstat(fd))
            result = {"schemaVersion": 1, "kind": "omux-home-manager-bundle", "bundleSha256": digest.hexdigest(),
                      "bundleBytes": predicted, "pairReceiptSha256": PAIR_SHA, "artifactReceiptSha256": ARTIFACT_SHA,
                      "sourceWrapper": SOURCE_WRAPPER, "activation": "unproved", "evaluationExecuted": False}
            raw = encoded(result)
            out = os.open("receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=output.fd)
            try:
                write_all(out, raw, work, output)
                os.fchmod(out, 0o444)
                os.fsync(out)
                if disk_account is not None:
                    disk_account.record(os.fstat(out))
                require(acquired.snapshot(os.fstat(out)) == acquired.snapshot(os.stat("receipt.json", dir_fd=output.fd, follow_symlinks=False)),
                        "bundle-receipt-changed")
            finally:
                close_resources(out)
            os.fsync(output.fd)
            tick(work, output)
            if disk_account is not None:
                disk_account.record(os.fstat(output.fd))
            return {**result, "receiptSha256": sha(raw)}
        finally:
            close_resources(fd)

def parent_fd(root, path):
    parts = relative(path)
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            previous, fd = fd, child
            close_resources(previous)
        return fd, parts[-1]
    except BaseException:
        close_resources(fd)
        raise

def remove_owned(fd, deadline, count):
    tick(deadline)
    before = os.fstat(fd)
    require(before.st_uid == os.getuid(), "bundle-cleanup-owner")
    os.fchmod(fd, 0o700)
    os.lseek(fd, 0, os.SEEK_SET)
    with os.scandir(fd) as listing:
        for entry in listing:
            tick(deadline)
            count[0] += 1
            require(count[0] <= 3 * acquired.MAX_NODES, "bundle-cleanup-bound")
            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid() and (stat.S_ISDIR(info.st_mode) or
                    stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)), "bundle-cleanup-custody")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    require(acquisition.directory_identity(os.fstat(child)) == acquisition.directory_identity(info), "bundle-cleanup-changed")
                    remove_owned(child, deadline, count)
                    require(acquisition.directory_identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) == acquisition.directory_identity(info),
                            "bundle-cleanup-changed")
                finally:
                    close_resources(child)
                os.rmdir(entry.name, dir_fd=fd)
            else:
                require(acquired.snapshot(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) == acquired.snapshot(info), "bundle-cleanup-changed")
                os.unlink(entry.name, dir_fd=fd)
    tick(deadline)

@contextmanager
def private_tree(scratch, deadline, *, admission_deadline=None):
    admission = deadline if admission_deadline is None else admission_deadline
    require(type(admission) in (int, float) and math.isfinite(admission)
            and admission <= deadline, "bundle-enclosing-deadline")
    tick(admission)
    with acquisition.HeldDirectory(scratch) as parent:
        name = "omux-hm-bundle-" + uuid.uuid4().hex
        parent.check()
        tick(admission)
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        created, worker, primary, cleanup_error = None, None, None, None
        try:
            tick(deadline)
            created = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            require(stat.S_ISDIR(created.st_mode) and created.st_uid == os.getuid()
                    and stat.S_IMODE(created.st_mode) == 0o700, "bundle-private-root-custody")
            worker = acquisition.HeldDirectory(parent.path / name, parent_anchor=parent)
            require(acquisition.directory_identity(os.fstat(worker.fd)) == acquisition.directory_identity(created),
                    "bundle-private-root-replaced")
            yield worker
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                tick(deadline)
                parent.check()
                require(created is not None, "bundle-private-root-unqualified")
                require(acquisition.directory_identity(os.stat(name, dir_fd=parent.fd, follow_symlinks=False))
                        == acquisition.directory_identity(created), "bundle-private-root-replaced")
                if worker is not None:
                    worker.check()
                    remove_owned(worker.fd, deadline, [0])
                    worker.check()
                # If construction failed before admission the new directory is
                # empty; rmdir refuses unexpected contents without traversing.
                tick(deadline)
                parent.check()
                os.rmdir(name, dir_fd=parent.fd)
                tick(deadline)
            except BaseException as error:
                cleanup_error = error
            finally:
                if worker is not None:
                    try:
                        worker.close()
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
            if cleanup_error is not None:
                if primary is not None:
                    primary.cleanup_category = "bundle-owned-cleanup-refused"
                else:
                    raise EvaluationFailure("bundle-materialization", "bundle-owned-cleanup-refused") from None

def exact(stream, count, check):
    parts = []
    remaining = count
    while remaining:
        check()
        part = stream.read(min(65536, remaining))
        require(part, "bundle-truncated")
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)

def materialize(stream, check, worker, lock, compact, work, *, disk_account=None):
    require(exact(stream, len(MAGIC), check) == MAGIC, "bundle-magic")
    metadata = []
    for maximum in (acquired.MAX_RECEIPT_BYTES, acquired.MAX_INVENTORY_BYTES, 65536, 1024 * 1024):
        length = struct.unpack("<Q", exact(stream, 8, check))[0]
        require(0 < length <= maximum, "bundle-header-bound")
        metadata.append(exact(stream, length, check))
    raw_pair, raw_inventory, raw_artifact, raw_nodes = metadata
    receipt, descriptors = pair_metadata(lock, raw_pair, raw_inventory)
    artifact_receipt = artifact.validate_receipt(raw_artifact, ARTIFACT_SHA)
    descriptors["artifact"] = checked_nodes(acquired.decode(raw_nodes, 1024 * 1024), "/declared/artifact")
    require(len(descriptors["artifact"]["nodes"]) <= artifact.MAX_NODES and
            all(n["type"] != "symlink" for n in descriptors["artifact"]["nodes"]), "bundle-artifact-node-bound")
    artifact_files = [n for n in descriptors["artifact"]["nodes"] if n["type"] == "regular"]
    require(len(artifact_files) <= artifact.pack.MAX_FILES
            and sum(n["size"] for n in artifact_files) <= artifact.MAX_BYTES, "bundle-artifact-byte-bound")
    logical_bytes = sum(node["size"] for _, node in entries(descriptors)) + len(raw_pair) + len(raw_inventory)
    require(logical_bytes <= acquisition.DISK_BUDGET, "bundle-private-disk-budget")
    require(compact["pairReceiptSha256"] == PAIR_SHA and compact["artifactReceiptSha256"] == ARTIFACT_SHA,
            "bundle-component-binding")
    def local_tick():
        tick(work, worker)
        check()
        acquired.check_deadline(work)
    allocated = [0]
    def charge_blocks(info, previous):
        local_tick()
        if disk_account is not None:
            disk_account.record(info)
        allocated[0] += max(0, info.st_blocks * 512 - previous)
        require(max(logical_bytes, allocated[0]) <= acquisition.DISK_BUDGET, "bundle-private-disk-budget")
    with acquisition.FileSyncOwner(local_tick, charge_blocks) as sync:
        for name in ("pair", "artifact", "home"):
            worker.check()
            local_tick()
            os.mkdir(name, 0o700, dir_fd=worker.fd)
        pair = worker.path / "pair"
        roots = {name: pair / name for name in acquired.NAMES}
        roots["artifact"] = worker.path / "artifact"
        with acquisition.HeldDirectory(pair, parent_anchor=worker) as pair_owner:
            for name in acquired.NAMES:
                local_tick()
                pair_owner.check()
                local_tick()
                os.mkdir(name, 0o700, dir_fd=pair_owner.fd)
        for name, descriptor in descriptors.items():
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                for node in sorted(descriptor["nodes"], key=lambda n: (n["path"].count("/"), os.fsencode(n["path"]))):
                    if node["type"] != "directory" or not node["path"]:
                        continue
                    local_tick()
                    parent, leaf = parent_fd(root.fd, node["path"])
                    try:
                        local_tick()
                        os.mkdir(leaf, 0o700, dir_fd=parent)
                    finally:
                        close_resources(parent)
        for name, node in entries(descriptors):
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                parent, leaf = parent_fd(root.fd, node["path"])
                fd = None
                try:
                    local_tick()
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    remaining = node["size"]
                    while remaining:
                        data = exact(stream, min(65536, remaining), check)
                        write_all(fd, data, work, worker)
                        remaining -= len(data)
                    local_tick()
                    os.fchmod(fd, 0o555 if node["executable"] else 0o444)
                    sync.submit(fd, parent, leaf, 0)
                finally:
                    close_resources(fd, parent)
        sync.drain()
        require(not stream.read(1), "bundle-trailing-byte")
        check()
        for name, descriptor in descriptors.items():
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                for node in descriptor["nodes"]:
                    if node["type"] != "symlink":
                        continue
                    local_tick()
                    parent, leaf = parent_fd(root.fd, node["path"])
                    try:
                        local_tick()
                        os.symlink(node["target"], leaf, dir_fd=parent)
                        charge_blocks(os.stat(leaf, dir_fd=parent, follow_symlinks=False), 0)
                    finally:
                        close_resources(parent)
                for node in sorted((n for n in descriptor["nodes"] if n["type"] == "directory"),
                                   key=lambda n: (n["path"].count("/"), os.fsencode(n["path"])), reverse=True):
                    local_tick()
                    fd, parent = None, None
                    try:
                        if not node["path"]:
                            fd = os.dup(root.fd)
                        else:
                            parent, leaf = parent_fd(root.fd, node["path"])
                            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        local_tick()
                        os.fchmod(fd, 0o555)
                        local_tick()
                        os.fsync(fd)
                        charge_blocks(os.fstat(fd), 0)
                    finally:
                        close_resources(fd, parent)
        with acquisition.HeldDirectory(pair, parent_anchor=worker) as held:
            for name, payload in (("receipt.json", raw_pair), ("inventory.json", raw_inventory)):
                held.check()
                local_tick()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=held.fd)
                try:
                    write_all(fd, payload, work, worker)
                    local_tick()
                    os.fchmod(fd, 0o444)
                    sync.submit(fd, held.fd, name, 0)
                finally:
                    close_resources(fd)
            sync.drain()
            # Preserve HeldDirectory.mode's custody/mode/postcheck predicates,
            # inserting the deadline fence after its blocking custody check.
            held.check()
            local_tick()
            os.fchmod(held.fd, 0o555)
            require(stat.S_IMODE(os.fstat(held.fd).st_mode) == 0o555,
                    "acquisition-held-directory-mode")
            held.check()
            local_tick()
            os.fsync(held.fd)
            charge_blocks(os.fstat(held.fd), 0)
        for name in ("home",):
            with acquisition.HeldDirectory(worker.path / name, parent_anchor=worker) as root:
                charge_blocks(os.fstat(root.fd), 0)
        charge_blocks(os.fstat(worker.fd), 0)
    local_tick()
    return pair, roots["artifact"], raw_artifact

def evaluate_bundle(bundle, frozen_bundle_sha, receipt_path, frozen_receipt_sha,
                    lock_path, nix, modules, scratch, *, deadline=None):
    work, end = bounds(deadline)
    for digest in (frozen_bundle_sha, frozen_receipt_sha):
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "bundle-selected-digest")
    raw, receipt_facts = evaluator.read_declared(receipt_path, 65536, work, readonly=True)
    require(sha(raw) == frozen_receipt_sha, "bundle-selected-receipt")
    compact = acquired.decode(raw, 65536)
    acquired.fields(compact, ("schemaVersion", "kind", "bundleSha256", "bundleBytes", "pairReceiptSha256",
                             "artifactReceiptSha256", "sourceWrapper", "activation", "evaluationExecuted"))
    require(type(compact["schemaVersion"]) is int and compact["schemaVersion"] == 1
            and compact["kind"] == "omux-home-manager-bundle" and compact["bundleSha256"] == frozen_bundle_sha
            and type(compact["bundleBytes"]) is int and 0 < compact["bundleBytes"] <= MAX_BUNDLE
            and compact["sourceWrapper"] == SOURCE_WRAPPER and compact["activation"] == "unproved"
            and compact["evaluationExecuted"] is False, "bundle-selected-scope")
    lock, lock_facts = evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work)
    path = Path(bundle).absolute()
    inputs = Inputs(path.parent, work)
    with inputs.open(path.name) as (stream, info, check):
        require(info[6] == compact["bundleBytes"], "bundle-selected-size")
        def hash_input():
            digest = hashlib.sha256()
            stream.seek(0)
            while True:
                check()
                data = stream.read(65536)
                if not data:
                    break
                digest.update(data)
            require(digest.hexdigest() == frozen_bundle_sha, "bundle-selected-bytes")
            check()
        hash_input()
        stream.seek(0)
        with private_tree(scratch, end, admission_deadline=work) as worker:
            pair, retained_artifact, artifact_bytes = materialize(stream, check, worker, lock, compact, work)
            tick(work, worker)
            result = evaluator.evaluate_acquired_pair(nix, modules, lock, str(pair), PAIR_SHA,
                str(retained_artifact), artifact_bytes, ARTIFACT_SHA, str(worker.path / "home"), deadline=work)
            hash_input()
            require(evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work) == (lock, lock_facts)
                    and evaluator.read_declared(receipt_path, 65536, work, readonly=True) == (raw, receipt_facts),
                    "bundle-selected-metadata-changed")
            tick(work, worker)
        check()
    tick(end)
    return {**result, "inputBundleSha256": frozen_bundle_sha, "inputBundleReceiptSha256": frozen_receipt_sha,
            "sourceWrapper": SOURCE_WRAPPER, "privateTreesRemoved": True}

class ReconstructionBudget:
    """One logical and physical budget for canonical tree AND compact output."""
    def __init__(self, logical, deadline):
        require(type(logical) is int and 0 <= logical <= acquisition.DISK_BUDGET,
                "reconstruction-joint-disk-budget")
        self.logical, self.deadline, self.blocks = logical, deadline, {}
        self.allocated = 0

    def record(self, info):
        tick(self.deadline)
        key = (info.st_dev, info.st_ino)
        require(key in self.blocks or len(self.blocks) < 3 * acquired.MAX_NODES + 1024,
                "reconstruction-account-bound")
        current = info.st_blocks * 512
        self.allocated += max(0, current - self.blocks.get(key, 0))
        self.blocks[key] = max(current, self.blocks.get(key, 0))
        require(max(self.logical, self.allocated) <= acquisition.DISK_BUDGET,
                "reconstruction-joint-disk-budget")

class RepresentationInputs(Inputs):
    """Exact retained transport mode; execution bits come from pinned metadata."""
    def __init__(self, root, deadline, layout_name):
        super().__init__(root, deadline)
        self.layout_name, self.commitments, self.active_check = layout_name, {}, None

    @contextmanager
    def open(self, name, *, readonly=True):
        with super().open(name, readonly=readonly) as (stream, info, check):
            require(name == self.layout_name or stat.S_IMODE(info[2]) == 0o555,
                    "reconstruction-retained-0555-representation")
            digest, count = hashlib.sha256(), 0
            class Reader:
                def read(self, amount):
                    nonlocal count
                    check()
                    require(type(amount) is int and 0 < amount <= 65536,
                            "reconstruction-read-bound")
                    data = stream.read(amount)
                    count += len(data)
                    require(count <= info[6], "reconstruction-input-growth")
                    digest.update(data)
                    check()
                    return data
            self.active_check = check
            try:
                yield Reader(), info, check
                require(count == info[6], "reconstruction-input-truncated")
                commitment = (count, digest.digest())
                require(name not in self.commitments or self.commitments[name] == commitment,
                        "reconstruction-input-bytes-changed")
                self.commitments[name] = commitment
            finally:
                self.active_check = None

    def recheck(self):
        for name in tuple(self.commitments):
            with self.open(name, readonly=name != self.layout_name) as (stream, _, check):
                while stream.read(65536):
                    check()

class RepresentationStream:
    """Bounded framed bytes; suspended generators retain each input's FD owner."""
    def __init__(self, inputs, headers, descriptors):
        self.inputs, self.pending = inputs, b""
        self.chunks = self.parts(headers, descriptors)

    def parts(self, headers, descriptors):
        for data in (MAGIC, *(part for payload in headers
                              for part in (struct.pack("<Q", len(payload)), payload))):
            for start in range(0, len(data), 65536):
                yield data[start:start + 65536]
        for name, node in entries(descriptors):
            prefix = "artifact" if name == "artifact" else "pair/" + name
            with self.inputs.open(prefix + "/" + node["path"]) as (stream, info, check):
                require(info[6] == node["size"], "bundle-input-size")
                remaining = node["size"]
                while remaining:
                    check()
                    data = stream.read(min(65536, remaining))
                    require(data, "reconstruction-input-truncated")
                    remaining -= len(data)
                    yield data
                require(not stream.read(1), "reconstruction-input-growth")

    def check(self):
        tick(self.inputs.deadline)
        if self.inputs.active_check is not None:
            self.inputs.active_check()

    def read(self, amount):
        require(type(amount) is int and 0 < amount <= 65536,
                "reconstruction-read-bound")
        result = bytearray()
        while len(result) < amount:
            self.check()
            if not self.pending:
                self.pending = next(self.chunks, b"")
                if not self.pending:
                    break
            take = min(amount - len(result), len(self.pending))
            result.extend(self.pending[:take])
            self.pending = self.pending[take:]
        return bytes(result)

    def close(self):
        self.chunks.close()

def reconstruction_file(owner, name, payload, work, account):
    owner.check()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=owner.fd)
    try:
        write_all(fd, payload, work, owner)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        account.record(os.fstat(fd))
    finally:
        close_resources(fd)
    os.fsync(owner.fd)
    account.record(os.fstat(owner.fd))

RECONSTRUCTION_PHASES = frozenset(("metadata", "canonical-materialization", "canonical-pack",
                                  "input-recheck", "owned-cleanup", "publication"))
RECONSTRUCTION_REFUSALS = frozenset((
    "bundle-layout-authority bundle-layout-files bundle-pair-receipt bundle-pair-binding bundle-source-pin "
    "bundle-artifact-manifest bundle-artifact-payload bundle-input-custody bundle-input-changed "
    "bundle-regular-metadata bundle-nar-mismatch bundle-lock-changed bundle-enclosing-deadline "
    "bundle-free-space acquired-verification-deadline reconstruction-joint-disk-budget "
    "reconstruction-account-bound reconstruction-retained-0555-representation reconstruction-read-bound "
    "reconstruction-input-growth reconstruction-input-truncated reconstruction-input-bytes-changed "
    "reconstruction-pending-changed reconstruction-output-scope reconstruction-canonical-complete-inventory "
    "reconstruction-canonical-custody-changed reconstruction-publication-identity "
    "reconstruction-no-replace-primitive-required reconstruction-publication-destination-exists"
).split())

def reconstruction_failure(error, progress):
    phase = progress.get("phase")
    if phase not in RECONSTRUCTION_PHASES:
        phase = "metadata"
    reason = "closed-input-or-execution-refused"
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        if error.args[0] in RECONSTRUCTION_REFUSALS:
            reason = error.args[0]
    return {"phase": phase, "refusal": reason}

def publication_noreplace(source, source_name, destination, destination_name):
    # Linux-only target. The declared Python process already has its locked
    # libc loaded; no host library filename, executable or fallback is selected.
    operation = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    require(operation is not None, "reconstruction-no-replace-primitive-required")
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    if operation(source, os.fsencode(source_name), destination, os.fsencode(destination_name), 1) != 0:
        code = ctypes.get_errno()
        require(code != errno.EEXIST, "reconstruction-publication-destination-exists")
        raise OSError(code, "reconstruction-no-replace-publication-refused")

class PublicationFile:
    """Own one inode through rename, writes, close and exact-name rollback."""
    def __init__(self, name, *, in_output=False):
        require(name in ("bundle", ".pending-bundle", ".pending-receipt", "receipt.json"),
                "reconstruction-publication-identity")
        self.fd, self.name = None, name
        self.output_names = {name} if in_output else set()
        self.identity, self.witness = None, None

    def capture(self):
        info = acquired.snapshot(os.fstat(self.fd))
        identity = (info[0], info[1], info[3])
        require(self.identity is None or identity == self.identity,
                "reconstruction-publication-identity")
        self.identity, self.witness = identity, info
        return info

    def inspect(self, owner):
        owner.check()
        info = self.capture()
        require(stat.S_ISREG(info[2]) and info[3] == os.getuid() and info[5] == 1
                and info == acquired.snapshot(os.stat(self.name, dir_fd=owner.fd, follow_symlinks=False)),
                "reconstruction-publication-identity")
        return info

    def promote(self, source, destination, name):
        self.inspect(source)
        require(name in (".pending-bundle", "bundle", "receipt.json"),
                "reconstruction-publication-identity")
        # Intent precedes the syscall, including cross-directory promotion.
        # An interrupt after successful rename still leaves a finite candidate
        # bound to the same held inode; rollback does not depend on assignment.
        self.output_names.add(name)
        publication_noreplace(source.fd, self.name, destination.fd, name)
        self.name = name
        self.inspect(destination)

    def close(self):
        if self.fd is not None:
            descriptor = self.fd
            try:
                self.capture()
            finally:
                # A failed close may have released the FD. Retain the inode
                # witness and never retry that integer or rely on fstat later.
                self.fd = None
                close_resources(descriptor)

def publication_cleanup_failure(primary, category):
    allowed = frozenset(("bundle-owned-close-refused", "bundle-owned-cleanup-refused",
        "acquisition-held-close-refused", "reconstruction-publication-close-refused",
        "reconstruction-publication-rollback-refused"))
    require(category in allowed, "reconstruction-publication-category")
    prior = getattr(primary, "cleanup_category", "")
    categories = set(prior.split(",")) & allowed if type(prior) is str else set()
    categories.add(category)
    primary.cleanup_category = ",".join(sorted(categories))

def close_publication(files, owner):
    primary, failure = sys.exc_info()[1], None
    for owned in reversed(files):
        try:
            try:
                if primary is None and owned.fd is not None:
                    owner.check()
                    require(owned.witness == acquired.snapshot(os.fstat(owned.fd))
                            == acquired.snapshot(os.stat(owned.name, dir_fd=owner.fd, follow_symlinks=False)),
                            "reconstruction-publication-identity")
            finally:
                owned.close()
        except BaseException as error:
            failure = failure or error
    if failure is not None:
        if primary is not None:
            publication_cleanup_failure(primary, "reconstruction-publication-close-refused")
        else:
            publication_cleanup_failure(failure, "reconstruction-publication-close-refused")
            raise failure

def rollback_publication(outputs, chain_witness, files, end, primary):
    """Reopen only the original owned directory; never delete replacements."""
    try:
        tick(end)
        with acquisition.HeldDirectory(outputs) as owner:
            require(tuple(item[3] for item in owner.chain) == chain_witness,
                    "reconstruction-publication-identity")
            for owned in reversed(files):
                for name in sorted(owned.output_names):
                    try:
                        tick(end, owner)
                        try:
                            named = acquired.snapshot(os.stat(name, dir_fd=owner.fd, follow_symlinks=False))
                        except FileNotFoundError:
                            continue
                        witness = owned.capture() if owned.fd is not None else owned.witness
                        require(witness is not None and witness == named and stat.S_ISREG(named[2])
                                and named[3] == os.getuid() and named[5] == 1,
                                "reconstruction-publication-identity")
                        os.unlink(name, dir_fd=owner.fd)
                        os.fsync(owner.fd)
                    except BaseException:
                        publication_cleanup_failure(primary, "reconstruction-publication-rollback-refused")
    except BaseException:
        publication_cleanup_failure(primary, "reconstruction-publication-rollback-refused")

def canonical_commitments(worker, descriptors, work):
    """Complete private tree proof, including real directories and inert links."""
    result = {}
    for name in (*acquired.NAMES, "artifact"):
        path = worker.path / "artifact" if name == "artifact" else worker.path / "pair" / name
        with acquisition.HeldDirectory(path, parent_anchor=worker) as root:
            nodes, facts = acquired.scan(root.fd, work)
            require(nodes == sorted(descriptors[name]["nodes"], key=lambda n: os.fsencode(n["path"])),
                    "reconstruction-canonical-complete-inventory")
            root.check()
            result[name] = facts
    worker.check()
    return result

def reconstruct_retained(layout_path, lock_path, outputs, *, deadline=None, progress=None):
    """Import exact declared 0555 transport bytes; prove ONLY reconstructed NARs."""
    work, end = bounds(deadline)
    progress = {} if progress is None else progress
    progress["phase"] = "metadata"
    layout_path = Path(layout_path).absolute()
    inputs = RepresentationInputs(layout_path.parent, work, layout_path.name)
    raw_layout = inputs.read(layout_path.name, 65536, readonly=False)
    layout = acquired.decode(raw_layout, 65536)
    acquired.fields(layout, ("schemaVersion", "pairReceipt", "pairInventory", "pairReceiptSha256",
                            "artifactReceipt", "artifactManifest", "artifactReceiptSha256", "artifactFiles", "sourceWrapper"))
    require(layout == {**layout, "schemaVersion": 1, "pairReceipt": "pair/receipt.json",
            "pairInventory": "pair/inventory.json", "pairReceiptSha256": PAIR_SHA,
            "artifactReceipt": "artifact-receipt.json", "artifactManifest": "artifact/release-manifest.json",
            "artifactReceiptSha256": ARTIFACT_SHA, "sourceWrapper": SOURCE_WRAPPER}, "bundle-layout-authority")
    lock, lock_facts = evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work)
    raw_pair = inputs.read("pair/receipt.json", acquired.MAX_RECEIPT_BYTES)
    raw_inventory = inputs.read("pair/inventory.json", acquired.MAX_INVENTORY_BYTES)
    raw_artifact = inputs.read("artifact-receipt.json", 65536)
    _, descriptors = pair_metadata(lock, raw_pair, raw_inventory)
    _, descriptors["artifact"] = artifact_metadata(inputs, raw_artifact)
    require(layout["artifactFiles"] == sorted(n["path"] for n in descriptors["artifact"]["nodes"] if n["type"] == "regular"),
            "bundle-layout-files")
    headers = (raw_pair, raw_inventory, raw_artifact, encoded(descriptors["artifact"]["nodes"]))
    predicted = len(MAGIC) + sum(8 + len(part) for part in headers) + sum(n["size"] for _, n in entries(descriptors))
    # Conservative logical charge includes both trees, duplicated private
    # metadata and the complete bounded final receipt; physical charge is shared.
    account = ReconstructionBudget(2 * predicted + len(raw_layout) + len(raw_artifact) + 65536, work)
    files, chain_witness, result = [], None, None
    try:
        with acquisition.HeldDirectory(outputs) as output:
            chain_witness = tuple(item[3] for item in output.chain)
            tick(work, output)
            with os.scandir(output.fd) as listing:
                require(not any(listing), "reconstruction-output-scope")
            account.record(os.fstat(output.fd))
            try:
                with private_tree(output.path, end, admission_deadline=work) as worker:
                    progress["phase"] = "canonical-materialization"
                    stream = RepresentationStream(inputs, headers, descriptors)
                    try:
                        materialize(stream, stream.check, worker, lock,
                            {"pairReceiptSha256": PAIR_SHA, "artifactReceiptSha256": ARTIFACT_SHA}, work,
                            disk_account=account)
                    finally:
                        close_resources(streams=(stream,))
                    reconstruction_file(worker, "layout.json", raw_layout, work, account)
                    reconstruction_file(worker, "artifact-receipt.json", raw_artifact, work, account)
                    worker.check()
                    tick(work, worker)
                    os.mkdir("publication", 0o700, dir_fd=worker.fd)
                    account.record(os.fstat(worker.fd))
                    with acquisition.HeldDirectory(worker.path / "publication", parent_anchor=worker) as publication:
                        account.record(os.fstat(publication.fd))
                    progress["phase"] = "canonical-pack"
                    canonical_before = canonical_commitments(worker, descriptors, work)
                    result = pack(worker.path / "layout.json", lock_path, worker.path / "publication",
                                  deadline=end, disk_account=account)
                    require(canonical_commitments(worker, descriptors, work) == canonical_before,
                            "reconstruction-canonical-custody-changed")
                    progress["phase"] = "input-recheck"
                    inputs.recheck()
                    require(evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work) == (lock, lock_facts),
                            "bundle-lock-changed")
                    progress["phase"] = "publication"
                    with acquisition.HeldDirectory(worker.path / "publication", parent_anchor=worker) as publication:
                        publication.check()
                        output.check()
                        owned_bundle = PublicationFile("bundle")
                        files.append(owned_bundle)
                        owned_bundle.fd = os.open("bundle", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=publication.fd)
                        pending_facts = owned_bundle.inspect(publication)
                        require(stat.S_IMODE(pending_facts[2]) == 0o444 and pending_facts[6] == result["bundleBytes"],
                                "reconstruction-pending-changed")
                        owned_bundle.promote(publication, output, ".pending-bundle")
                        pending_facts = owned_bundle.inspect(output)
                        account.record(os.fstat(publication.fd))
                    os.fsync(output.fd)
                    account.record(os.fstat(output.fd))
                    progress["phase"] = "owned-cleanup"
                # No final receipt is created until canonical-tree cleanup succeeded.
                progress["phase"] = "publication"
                tick(work, output)
                inputs.recheck()
                require(evaluator.read_declared(lock_path, acquired.MAX_LOCK_BYTES, work) == (lock, lock_facts),
                        "bundle-lock-changed")
                require(pending_facts == owned_bundle.inspect(output), "reconstruction-pending-changed")
                owned_bundle.promote(output, output, "bundle")
                owned_receipt = PublicationFile(".pending-receipt", in_output=True)
                files.append(owned_receipt)
                owned_receipt.fd = os.open(".pending-receipt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=output.fd)
                owned_receipt.inspect(output)
                payload = encoded({k: v for k, v in result.items() if k != "receiptSha256"})
                write_all(owned_receipt.fd, payload, work, output)
                os.fchmod(owned_receipt.fd, 0o444)
                os.fsync(owned_receipt.fd)
                account.record(os.fstat(owned_receipt.fd))
                owned_receipt.inspect(output)
                owned_receipt.promote(output, output, "receipt.json")
                os.fsync(output.fd)
                account.record(os.fstat(output.fd))
                tick(work, output)
            finally:
                close_publication(files, output)
        tick(end)
    except BaseException as primary:
        if chain_witness is not None:
            rollback_publication(outputs, chain_witness, files, end, primary)
        raise
    return {**result, "inputRepresentation": "bazel-retained-readonly-0555-v1",
            "reconstructedCanonicalNarVerified": True, "retainedPhysicalNarVerified": False,
            "privateTreesRemoved": True}

def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    producer = commands.add_parser("pack")
    for flag in ("layout", "lock"):
        producer.add_argument("--" + flag, required=True)
    reconstruction = commands.add_parser("reconstruct")
    for flag in ("layout", "lock"):
        reconstruction.add_argument("--" + flag, required=True)
    consumer = commands.add_parser("evaluate")
    for flag in ("nix", "lock", "bundle", "bundle-receipt", "selection"):
        consumer.add_argument("--" + flag, required=True)
    consumer.add_argument("--module", action="append", default=[])
    args = parser.parse_args(arguments)
    saved, primary, reconstruction_progress = {}, None, {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    try:
        require(os.environ.get("OMUX_EXECUTION_GUARD"), "bundle-contained-context")
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            saved[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        if args.operation == "pack":
            result = pack(args.layout, args.lock, os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        elif args.operation == "reconstruct":
            result = reconstruct_retained(args.layout, args.lock, os.environ["TEST_UNDECLARED_OUTPUTS_DIR"],
                deadline=action_deadline(args.operation, os.environ), progress=reconstruction_progress)
        else:
            modules = {}
            for item in args.module:
                name, path = item.split("=", 1)
                require(name not in modules, "bundle-duplicate-module")
                modules[name] = path
            acquired.fields(modules, evaluator.MODULES)
            result = evaluate_selection(args.selection, args.bundle, args.bundle_receipt,
                args.lock, args.nix, modules, str(Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)),
                deadline=action_deadline(args.operation, os.environ))
    except BaseException as error:
        primary = error
    finally:
        for signum, handler in saved.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.cleanup_category = "bundle-handler-restore-refused"
    if primary is not None:
        output = {"passed": False, "scope": "declared-home-manager-bundle", "activation": "unproved",
                  "category": "bounded-input-or-execution-refused"}
        if args.operation == "reconstruct":
            output["diagnostic"] = reconstruction_failure(primary, reconstruction_progress)
        if isinstance(primary, EvaluationFailure):
            output["category"] = primary.category
        if isinstance(primary, ValueError) and primary.args == ("bundle-selection-pending",):
            output["category"] = "bundle-selection-pending"
        if getattr(primary, "cleanup_category", None) is not None:
            output["cleanup_category"] = primary.cleanup_category
        print(json.dumps(output, sort_keys=True))
        return 2
    print(json.dumps({"passed": True, **result}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
