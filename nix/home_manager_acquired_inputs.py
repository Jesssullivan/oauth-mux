"""Read-only byte proof for an explicitly declared acquired Home Manager pair.

This is a NEW producer interface, not compatibility with an existing receipt.
The caller supplies the trusted receipt SHA256 and exact retained physical roots
as declared action inputs. Metadata never chooses a filesystem path. A producer
must emit an inventory of every node, including directories and inert symlinks:

  inventory = {schemaVersion: 1, sources: {name: {nodes: [NAR nodes]}}}
  receipt = {schemaVersion: 1, kind: "omux-home-manager-acquired-pair",
             lockSha256: HEX, inventorySha256: HEX,
             sources: {name: {revision: COMMIT, narHash: SRI, narSize: INT,
                              url: exact commit archive URL}}}

Names are exactly home-manager and nixpkgs. NAR nodes follow nar_descriptor.py;
their root is omitted because the caller independently selects the physical
tree. The receipt digest must come from a trusted frozen declaration, rather
than being calculated from the supplied bytes by the caller as a trust shortcut.
No daemon, registration, fetching, Nix evaluation or executable is invoked.
Passing proves the selected tree bytes and current descriptor custody only.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from home_manager_inputs import paired_lock

# The isolated launcher adds only the main's nix/ runfiles directory. Preserve
# that logical runfiles namespace; resolving __file__ would escape to the source
# checkout and let undeclared sibling files satisfy imports.
sys.path.insert(0, str(Path(__file__).absolute().parent.parent / "tools"))
from nar_descriptor import serialize, validate_descriptor

NAMES = ("home-manager", "nixpkgs")
REPOSITORIES = {"home-manager": ("nix-community", "home-manager"),
                "nixpkgs": ("NixOS", "nixpkgs")}
MAX_LOCK_BYTES = 65536
MAX_RECEIPT_BYTES = 65536
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_NODES = 200000
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_NAR_BYTES = 2 * 1024 * 1024 * 1024
MAX_SECONDS = 300


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "acquired-duplicate-json-key")
        result[key] = value
    return result


def decode(payload, maximum):
    require(isinstance(payload, bytes) and 0 < len(payload) <= maximum,
            "acquired-metadata-byte-bound")
    return json.loads(payload, object_pairs_hook=unique_object)


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected),
            "acquired-metadata-fields")


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check_deadline(deadline):
    require(time.monotonic() < deadline, "acquired-verification-deadline")


def physical_path(value):
    require(isinstance(value, (str, Path)), "acquired-physical-root")
    raw = os.fspath(value)
    require(raw.startswith("/") and len(os.fsencode(raw)) <= MAX_PATH_BYTES
            and "\x00" not in raw and all(part not in ("", ".", "..")
                                         for part in raw[1:].split("/")),
            "acquired-physical-root")
    return raw


def open_root(path, deadline):
    """No symlink ancestors; root-owned sticky ancestors remain protected."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path[1:].split("/"):
            check_deadline(deadline)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                protected = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                require(info.st_uid in (0, os.getuid())
                        and (not info.st_mode & 0o022 or protected),
                        "acquired-unsafe-ancestor")
                require(snapshot(info) == snapshot(os.stat(component, dir_fd=descriptor,
                                                           follow_symlinks=False)),
                        "acquired-ancestor-changed")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o7222,
                "acquired-tree-root-custody")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def node_custody(info):
    require(info.st_uid == os.getuid(), "acquired-tree-node-owner")
    if stat.S_ISLNK(info.st_mode):
        require(info.st_nlink == 1, "acquired-tree-link-custody")
    else:
        require(not info.st_mode & 0o7222, "acquired-tree-node-writable")
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1 and 0 <= info.st_size <= MAX_FILE_BYTES,
                    "acquired-tree-file-custody")


def scan(root_fd, deadline):
    """Complete descriptor-rooted inventory, never traversing link targets."""
    nodes, facts = [], {}
    logical_bytes = 0
    discovered = 1  # The selected root, including all not-yet-visited children.
    metadata_bytes = 128
    require(discovered <= MAX_NODES and metadata_bytes <= MAX_INVENTORY_BYTES,
            "acquired-tree-entry-or-metadata-bound")

    def visit(directory, relative, depth):
        nonlocal logical_bytes, metadata_bytes, discovered
        check_deadline(deadline)
        require(depth <= MAX_DEPTH and len(nodes) < MAX_NODES,
                "acquired-tree-entry-bound")
        before = os.fstat(directory)
        node_custody(before)
        facts[relative] = snapshot(before)
        nodes.append({"path": relative, "type": "directory"})
        # Iteration is bounded before collecting names; no unbounded listdir.
        names = []
        # scandir(fd) duplicates the descriptor while sharing its directory
        # offset. Every scan must enumerate from the beginning, including the
        # same pinned root descriptor after its contents have been hashed.
        os.lseek(directory, 0, os.SEEK_SET)
        with os.scandir(directory) as entries:
            for entry in entries:
                check_deadline(deadline)
                child_path = relative + "/" + entry.name if relative else entry.name
                path_bytes = len(os.fsencode(child_path))
                require(path_bytes <= MAX_PATH_BYTES and depth + 1 <= MAX_DEPTH,
                        "acquired-tree-path-bound")
                # Ancestors retain their pending name lists during recursion.
                # Charge every discovered entry once, before retaining its name,
                # rather than counting only this directory's local pending list.
                require(discovered + 1 <= MAX_NODES, "acquired-tree-entry-bound")
                require(metadata_bytes + path_bytes + 128 <= MAX_INVENTORY_BYTES,
                        "acquired-tree-metadata-bound")
                discovered += 1
                metadata_bytes += path_bytes + 128
                names.append(entry.name)
        for name in sorted(names, key=os.fsencode):
            check_deadline(deadline)
            child_path = relative + "/" + name if relative else name
            require(len(os.fsencode(child_path)) <= MAX_PATH_BYTES
                    and depth + 1 <= MAX_DEPTH and len(nodes) < MAX_NODES,
                    "acquired-tree-path-bound")
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            node_custody(info)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=directory)
                try:
                    require(snapshot(info) == snapshot(os.fstat(child)),
                            "acquired-directory-changed")
                    visit(child, child_path, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                logical_bytes += info.st_size
                require(logical_bytes <= MAX_TREE_BYTES, "acquired-tree-byte-bound")
                nodes.append({"path": child_path, "type": "regular", "size": info.st_size,
                              "executable": bool(info.st_mode & stat.S_IXUSR)})
                facts[child_path] = snapshot(info)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=directory)
                target_bytes = len(os.fsencode(target))
                require(target_bytes <= MAX_PATH_BYTES,
                        "acquired-link-target-bound")
                require(metadata_bytes + target_bytes <= MAX_INVENTORY_BYTES,
                        "acquired-tree-metadata-bound")
                metadata_bytes += target_bytes
                nodes.append({"path": child_path, "type": "symlink", "target": target})
                facts[child_path] = snapshot(info)
            else:
                raise ValueError("acquired-tree-special-file")
            require(snapshot(info) == snapshot(os.stat(name, dir_fd=directory,
                                                       follow_symlinks=False)),
                    "acquired-tree-node-changed")
            require(metadata_bytes <= MAX_INVENTORY_BYTES, "acquired-tree-metadata-bound")
        require(snapshot(before) == snapshot(os.fstat(directory)),
                "acquired-directory-changed")

    visit(root_fd, "", 0)
    return sorted(nodes, key=lambda node: os.fsencode(node["path"])), facts


@contextmanager
def regular_stream(root_fd, relative, facts, deadline):
    parent = os.dup(root_fd)
    file_fd = None
    try:
        parts = relative.split("/")
        prefix = ""
        for component in parts[:-1]:
            check_deadline(deadline)
            prefix = prefix + "/" + component if prefix else component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            try:
                require(snapshot(os.fstat(child)) == facts[prefix],
                        "acquired-hash-parent-changed")
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        check_deadline(deadline)
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                          | os.O_CLOEXEC, dir_fd=parent)
        require(snapshot(os.fstat(file_fd)) == facts[relative],
                "acquired-hash-file-changed")
        with os.fdopen(file_fd, "rb") as stream:
            file_fd = None
            yield stream
            require(snapshot(os.fstat(stream.fileno())) == facts[relative],
                    "acquired-hash-file-changed")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent)


def verify_acquired_pair(lock_bytes, receipt_bytes, receipt_sha256, inventory_bytes,
                         declared_sources, *, deadline_seconds=120, deadline=None):
    """Rehash every byte against fixed pair pins; return no evaluation authority.

    Retained trees must be immutable exports owned by the current action user.
    Root-owned cached Nix sources retain their separate existing input contract.
    The acquisition producer is not implemented by this validator.
    """
    require(type(deadline_seconds) is int and 1 <= deadline_seconds <= MAX_SECONDS,
            "acquired-deadline-bound")
    local_end = time.monotonic() + deadline_seconds
    if deadline is not None:
        require(type(deadline) in (int, float) and deadline == deadline
                and deadline not in (float("inf"), float("-inf")), "acquired-deadline-bound")
    deadline = local_end if deadline is None else min(local_end, deadline)
    check_deadline(deadline)
    lock = decode(lock_bytes, MAX_LOCK_BYTES)
    try:
        locked = paired_lock(lock)
    except (KeyError, TypeError, ValueError):
        raise ValueError("acquired-paired-lock-invalid") from None
    receipt = decode(receipt_bytes, MAX_RECEIPT_BYTES)
    require(isinstance(receipt_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", receipt_sha256) is not None
            and isinstance(receipt_bytes, bytes)
            and hashlib.sha256(receipt_bytes).hexdigest() == receipt_sha256,
            "acquired-receipt-binding")
    fields(receipt, ("schemaVersion", "kind", "lockSha256", "inventorySha256", "sources"))
    require(type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["kind"] == "omux-home-manager-acquired-pair"
            and receipt["lockSha256"] == hashlib.sha256(lock_bytes).hexdigest(),
            "acquired-lock-binding")
    inventory = decode(inventory_bytes, MAX_INVENTORY_BYTES)
    require(receipt["inventorySha256"] == hashlib.sha256(inventory_bytes).hexdigest(),
            "acquired-inventory-binding")
    fields(inventory, ("schemaVersion", "sources"))
    require(type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1,
            "acquired-inventory-schema")
    for value in (receipt["sources"], inventory["sources"], declared_sources):
        fields(value, NAMES)
    roots = {name: physical_path(declared_sources[name]) for name in NAMES}
    require(roots[NAMES[0]] != roots[NAMES[1]], "acquired-physical-root-alias")
    reports, snapshots = {}, {}
    for name in NAMES:
        check_deadline(deadline)
        row = receipt["sources"][name]
        fields(row, ("revision", "narHash", "narSize", "url"))
        pin = locked[name]
        owner, repository = REPOSITORIES[name]
        require(row["revision"] == pin["rev"] and row["narHash"] == pin["narHash"]
                and row["url"] == f"https://github.com/{owner}/{repository}/archive/{pin['rev']}.tar.gz"
                and type(row["narSize"]) is int and 0 < row["narSize"] <= MAX_NAR_BYTES,
                "acquired-source-lock-binding")
        item = inventory["sources"][name]
        fields(item, ("nodes",))
        require(isinstance(item["nodes"], list) and len(item["nodes"]) <= MAX_NODES,
                "acquired-inventory-entry-bound")
        descriptor = {"schemaVersion": 1, "root": roots[name], "nodes": item["nodes"]}
        try:
            expected_nodes, _ = validate_descriptor(descriptor)
        except (KeyError, TypeError, ValueError):
            raise ValueError("acquired-invalid-nar-inventory") from None
        require(expected_nodes.get("", {}).get("type") == "directory",
                "acquired-inventory-directory-root")
        root_fd = open_root(roots[name], deadline)
        try:
            nodes, facts = scan(root_fd, deadline)
            require({node["path"]: node for node in nodes} == expected_nodes,
                    "acquired-complete-inventory-mismatch")
            digest = hashlib.sha256()
            nar_bytes = 0

            def emit(content):
                nonlocal nar_bytes
                check_deadline(deadline)
                nar_bytes += len(content)
                require(nar_bytes <= MAX_NAR_BYTES, "acquired-nar-byte-bound")
                digest.update(content)

            def opener(selected_root, relative):
                require(selected_root == roots[name] and relative in facts,
                        "acquired-undeclared-hash-input")
                return regular_stream(root_fd, relative, facts, deadline)

            serialize(descriptor, emit, opener=opener, deadline=deadline)
            sri = "sha256-" + base64.b64encode(digest.digest()).decode("ascii")
            require(sri == pin["narHash"] and nar_bytes == row["narSize"],
                    "acquired-source-nar-mismatch")
            after_nodes, after_facts = scan(root_fd, deadline)
            require(nodes == after_nodes and facts == after_facts,
                    "acquired-tree-changed-during-hash")
            final_root = open_root(roots[name], deadline)
            try:
                require(snapshot(os.fstat(final_root)) == facts[""],
                        "acquired-selected-root-replaced")
            finally:
                os.close(final_root)
        finally:
            os.close(root_fd)
        reports[name] = {"sourceDirectory": roots[name], "revision": pin["rev"],
                         "narHash": sri, "narSize": nar_bytes, "nodes": len(nodes)}
        snapshots[name] = (nodes, facts)
    # The first source must not become stale while hashing the second source.
    # Every root is selected again, rather than trusting an old open descriptor.
    for name in NAMES:
        root_fd = open_root(roots[name], deadline)
        try:
            require(scan(root_fd, deadline) == snapshots[name],
                    "acquired-pair-changed-during-verification")
        finally:
            os.close(root_fd)
    return {"schemaVersion": 1, "scope": "declared-acquired-pair-byte-proof",
            "contentRehashed": True, "completeInventoryMatched": True,
            "receiptSha256": receipt_sha256, "sources": reports,
            "linkTargetsFollowed": False, "executionAuthority": False,
            "evaluationAuthority": False, "activation": "unproved",
            "acquisitionActionsVerified": False}
