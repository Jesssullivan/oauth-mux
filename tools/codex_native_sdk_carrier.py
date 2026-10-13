"""SDK-only v1 content transport; original and extracted custody are distinct.

No source ancestry, selector, credential, tool execution or metadata authority.
Link text is carried inertly: extraction never opens a symbolic target. Absolute
JDK/tool paths still require a separately qualified platform before execution.
"""
import argparse
from contextlib import ExitStack
from queue import Empty, Queue
from types import MappingProxyType
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

import codex_retained_sdk_export as sdk
import nar_descriptor as nar

KIND = "omux-native-sdk-carrier-v1"
MANIFEST = "omux-native-sdk-carrier-manifest-v1"
EXTRACTED = "omux-native-sdk-carrier-extracted-v1"
SCRATCH_EXTRACTED = "omux-native-sdk-carrier-action-scratch-v1"
MAX_METADATA = 256 * 1024 * 1024
MAX_BYTES = sdk.MAX_BYTES
MAX_ENTRIES = sdk.MAX_FILES
MAX_DEPTH = 64
FILES = ("manifest.json", "origin-receipt.json", "payload.bin", "receipt.json")


def transport_leaf_mode(root, witness):
    # These four outer transport files carry bytes, not SDK/JDK executable
    # modes. Bazel's READONLY tree-artifact retention changes them to 0555.
    # An independently consumed retained file may be exact 0444 or 0555;
    # the current exclusive writer still requires its freshly sealed 0444.
    modes = (0o444,) if root.owned else (0o444, 0o555)
    return stat.S_IMODE(witness[4]) in modes


def need(value, reason):
    if value is not True:
        raise ValueError("SDK carrier refused: " + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "digest")
    return value


def relative(value, empty=False):
    need(type(value) is str and (empty or bool(value)) and len(value.encode("utf-8")) <= 4096
         and not value.startswith("/") and "\\" not in value
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), "path")
    parts = value.split("/") if value else []
    need(len(parts) <= MAX_DEPTH and all(part not in ("", ".", "..") for part in parts), "traversal")
    return parts


def absolute(value):
    value = os.fspath(value)
    need(type(value) is str and value.startswith("/") and value != "/", "absolute-root")
    relative(value[1:])
    return Path(value)


class Clock:
    def __init__(self, deadline):
        need(type(deadline) in (int, float) and math.isfinite(deadline)
             and 0 < deadline - time.monotonic() <= 1200, "original-deadline")
        self.deadline = deadline
        self.until_ns = None

    def tick(self, unused=0):
        need(time.monotonic() < self.deadline, "deadline")
        if self.until_ns is not None:
            need(time.monotonic_ns() < self.until_ns, "integer-deadline")

    def sdk_budget(self):
        self.tick()
        return sdk.Budget(time.time() + min(1200, self.deadline - time.monotonic()), self.tick)


def identity(info, directory=False):
    value = [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]
    if not directory:
        value += [info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    return value


class Root:
    """Hold every nofollow ancestor; recheck both descriptors and current names."""
    def __init__(self, path, clock, sealed=True, expected_identity=None, owned=False, origin_jdk=False):
        self.path, self.clock, self.chain = absolute(path), clock, []
        self.named, self.owned = {}, owned
        self.leaves = {}
        self.origin_jdk = origin_jdk
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.chain.append((None, fd, identity(os.fstat(fd), True)))
            for part in self.path.parts[1:]:
                clock.tick()
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode), "ancestor-type")
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    held = os.fstat(child)
                    need(identity(before, True) == identity(held, True) == identity(
                        os.stat(part, dir_fd=fd, follow_symlinks=False), True), "ancestor-race")
                    need(held.st_uid in (0, os.getuid()) and
                         (not held.st_mode & 0o022 or bool(held.st_mode & stat.S_ISVTX)), "ancestor-custody")
                except BaseException:
                    os.close(child)
                    raise
                self.chain.append((part, child, identity(held, True)))
                fd = child
            held = os.fstat(fd)
            need(held.st_uid in (0, os.getuid()) and
                 stat.S_IMODE(held.st_mode) == (0o555 if sealed else 0o700), "root-custody")
            if expected_identity is not None:
                need(identity(held, True) == expected_identity, "created-root-join")
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.chain[-1][1]

    def check(self):
        self.clock.tick()
        for index, (name, fd, witness) in enumerate(self.chain):
            need(identity(os.fstat(fd), True) == witness, "held-ancestor")
            if index:
                need(identity(os.stat(name, dir_fd=self.chain[index-1][1], follow_symlinks=False), True)
                     == witness, "named-ancestor")
        for name, selected in self.leaves.items():
            self.clock.tick()
            need(identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == selected, "named-root-leaf")

    def parent(self, name):
        return self._parent(name, None)

    def _parent(self, name, handles):
        parts = relative(name)
        self.check()
        fd = os.dup(self.fd)
        prefix = []
        try:
            for part in parts[:-1]:
                self.clock.tick()
                prefix.append(part)
                key = "/".join(prefix)
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.getuid())
                     and not before.st_mode & 0o022, "internal-parent-custody")
                selected = identity(before, True)
                if self.owned:
                    need(key in self.named, "unowned-output-parent")
                if key in self.named:
                    need(self.named[key] == selected, "internal-parent-replacement")
                child = (handles.take(key, fd, part, selected) if handles is not None else
                         os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd))
                try:
                    need(selected == identity(os.fstat(child), True) == identity(
                        os.stat(part, dir_fd=fd, follow_symlinks=False), True), "internal-parent-race")
                    if handles is not None:
                        handles.keep(key, child, selected)
                except BaseException:
                    os.close(child)
                    raise
                self.named[key] = selected
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def open(self, name):
        fd, leaf = self.parent(name)
        try:
            before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and self.regular_links(before)
                 and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022, "regular-custody")
            if "/" not in name:
                selected = identity(before)
                if name in self.leaves:
                    need(self.leaves[name] == selected, "root-leaf-replacement")
                self.leaves[name] = selected
            child = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            try:
                need(identity(before) == identity(os.fstat(child)) == identity(
                    os.stat(leaf, dir_fd=fd, follow_symlinks=False)), "regular-open-race")
                return child, identity(before)
            except BaseException:
                os.close(child)
                raise
        finally:
            os.close(fd)

    def regular_links(self, info):
        # A selected UID0/nonwritable original Nix JDK may be store-deduplicated.
        # Its stable physical nlink still joins every original witness. Transport
        # carries bytes, never hardlink records; fresh extraction requires1.
        return info.st_nlink == 1 or (self.origin_jdk and str(self.path) == sdk.JDK
               and info.st_uid == 0 and not info.st_mode & 0o222 and info.st_nlink > 1)

    def close(self):
        # Detach ownership before any attempt. A close error does not establish
        # that the numeric FD stayed open; never retry it after possible reuse.
        owned, self.chain = tuple(self.chain), []
        error = None
        for _, fd, _ in reversed(owned):
            try:
                os.close(fd)
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _ParentHandles:
    """At most 32 owned directory FDs, scoped to creation or regular writes.

    Reuse changes open to dup only. Root._parent still performs every external
    and per-component named/before/held/after/custody check on every traversal.
    Close before creating links or changing directory modes.
    """
    def __init__(self, root):
        need(root.owned, "parent-handles-owned")
        self.root, self.entries, self.closed = root, {}, False

    def parent(self, name):
        need(not self.closed, "parent-handles-closed")
        return self.root._parent(name, self)

    def take(self, key, parent, name, selected):
        if key in self.entries:
            fd, witness = self.entries.pop(key)
            self.entries[key] = (fd, witness)
            need(witness == selected, "parent-handle-replacement")
            return os.dup(fd)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)

    def keep(self, key, fd, selected):
        if key not in self.entries:
            if len(self.entries) == 32:
                oldest = next(iter(self.entries))
                prior, _ = self.entries.pop(oldest)
                os.close(prior)
            held = os.dup(fd)
            self.entries[key] = (held, selected)

    def close(self):
        entries, self.entries = self.entries, {}
        self.closed = True
        failure = None
        for fd, _ in entries.values():
            try:
                os.close(fd)
            except OSError as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def read(root, name, limit, pin=None):
    fd, witness = root.open(name)
    try:
        need(witness[6] <= limit, "metadata-bound")
        blocks, count = [], 0
        while True:
            root.clock.tick()
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            count += len(block)
            need(count <= limit, "metadata-bound")
            blocks.append(block)
        raw = b"".join(blocks)
        need(identity(os.fstat(fd)) == witness and len(raw) == witness[6], "metadata-read-race")
        if pin is not None:
            need(sha(raw) == digest(pin), "metadata-pin")
        root.check()
        return raw
    finally:
        os.close(fd)


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=sdk.unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("SDK carrier refused: JSON") from error


def names(fd, expected, clock):
    found = []
    with os.scandir(fd) as entries:
        for entry in entries:
            clock.tick()
            need(len(found) < len(expected) and entry.name in expected, "unselected-directory-entry")
            found.append(entry.name)
    need(set(found) == expected, "missing-directory-entry")
    return sorted(found)


def receipt_shape(receipt, clock):
    need(type(receipt) is dict and set(receipt) == {"schema", "baseline_receipt_sha256",
         "baseline_inventory_sha256", "graph_files", "repositories", "inventory_sha256",
         "mapping_sha256", "excluded", "qualification_only", "nix_store_roots", "modules",
         "nix_inventory", "registry_metadata", "selection_sha256", "producer", "counts"}, "origin-receipt-fields")
    need(receipt["schema"] == sdk.SCHEMA and receipt["qualification_only"] is False
         and receipt["nix_store_roots"] == [sdk.JDK], "origin-receipt-role")
    for name in ("baseline_receipt_sha256", "baseline_inventory_sha256", "inventory_sha256", "mapping_sha256"):
        digest(receipt[name])
    digest(receipt["selection_sha256"])
    need(receipt["producer"] in ("//tools:codex_retained_sdk_export_run",
         "//tools:codex_retained_sdk_export_producer") and type(receipt["counts"]) is dict
         and set(receipt["counts"]) == {"entries_read", "bytes_read", "inventory_passes",
                                      "max_entries_per_pass", "max_inventory_passes"}, "retained-producer")
    counts = receipt["counts"]
    need(type(counts["inventory_passes"]) is dict and set(counts["inventory_passes"]) == {
         "qualification", "copy", "sealed_readback"} and all(type(value) is int and 0 <= value <= sdk.MAX_FILES
         for value in counts["inventory_passes"].values()) and type(counts["entries_read"]) is int
         and counts["entries_read"] == sum(counts["inventory_passes"].values())
         and type(counts["bytes_read"]) is int and 0 <= counts["bytes_read"] <= sdk.MAX_BYTES
         and type(counts["max_entries_per_pass"]) is int and counts["max_entries_per_pass"] == sdk.MAX_FILES
         and type(counts["max_inventory_passes"]) is int and counts["max_inventory_passes"] == 3, "retained-counts")
    need(type(receipt["repositories"]) is list and 0 < len(receipt["repositories"]) <= sdk.MAX_REPOS,
         "repository-bound")
    # Bound rows before canonicalization or the unchanged absence helper builds
    # its object/link dictionaries. Derived parents receive a separate bound.
    need(type(receipt["nix_inventory"]) is list, "nix-inventory-list")
    inventory_rows = len(receipt["nix_inventory"])
    need(inventory_rows <= MAX_ENTRIES, "inventory-row-bound")
    for repo in receipt["repositories"]:
        clock.tick()
        need(type(repo) is dict and type(repo.get("files")) is list, "repository-files-list")
        inventory_rows += len(repo["files"])
        need(inventory_rows <= MAX_ENTRIES, "inventory-row-bound")
    need(type(receipt["graph_files"]) is dict and set(receipt["graph_files"]) == set(sdk.GRAPH)
         and receipt["mapping_sha256"] == receipt["graph_files"]["MODULE.bazel.lock"]["sha256"], "graph")
    need(sha(sdk.canonical(receipt["repositories"])) == receipt["inventory_sha256"], "repository-inventory-pin")
    names = set()
    for repo in receipt["repositories"]:
        clock.tick()
        name = repo["canonical_name"]
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_+.~-]{1,256}", name) is not None
             and name not in names, "repository-name")
        names.add(name)
        need(sha(sdk.canonical(repo["files"])) == digest(repo["inventory_sha256"]), "repository-files-pin")
    # Existing exact link/absence semantic proof operates on inert inventory only.
    absences = sdk.public_link_absences(receipt["repositories"], ClockAdapter(clock))
    need(all(repo.get("absent_links", []) == [item for item in absences
         if item["origin"].split("/")[0] == repo["canonical_name"]]
         for repo in receipt["repositories"]), "absence-inventory")


class ClockAdapter:
    """Replaced per call below; no renewal or independent deadline."""
    def __init__(self, clock=None):
        self.clock = clock

    def check(self, count=0):
        if self.clock:
            self.clock.tick()


def expected_entries(receipt, raw, clock, origin_receipt_mode, graph_modes):
    receipt_shape(receipt, clock)
    need(type(origin_receipt_mode) is int and origin_receipt_mode in (0o400, 0o444), "origin-receipt-mode")
    need(type(graph_modes) is dict and set(graph_modes) == set(sdk.GRAPH)
         and all(type(value) is int and value in (0o400, 0o444) for value in graph_modes.values()), "origin-graph-modes")
    expected = {("sdk", ""): {"kind": "directory", "mode": 0o555},
                ("jdk", ""): {"kind": "directory", "mode": 0o555}}
    def add(role, path, row):
        clock.tick()
        relative(path)
        need((role, path) not in expected, "duplicate-entry")
        need(type(row) is dict and row.get("kind") in ("directory", "file", "symlink"), "entry-kind")
        item = dict(row)
        if item["kind"] == "directory":
            need(set(item) == {"kind", "mode"} and item["mode"] == 0o555, "directory-mode")
        elif item["kind"] == "file":
            need(set(item) in ({"kind", "mode", "sha256", "size"}, {"kind", "mode", "sha256"})
                 and type(item["mode"]) is int and item["mode"] in (
                     (0o400, 0o444) if role == "sdk" and (path == "receipt.json" or path.startswith("graph/"))
                     else (0o444, 0o555)), "file-fields")
            digest(item["sha256"])
            if "size" in item:
                need(type(item["size"]) is int and 0 <= item["size"] <= sdk.MAX_FILE, "file-size")
        else:
            need(set(item) == {"kind", "target"} and type(item["target"]) is str
                 and 0 < len(os.fsencode(item["target"])) <= 65536
                 and not any(ord(c) < 32 or ord(c) == 127 for c in item["target"]), "link-text")
        need(len(expected) < MAX_ENTRIES, "entry-bound")
        expected[(role, path)] = item
    def parents(role, path):
        parts = relative(path)
        for index in range(1, len(parts)):
            key = (role, "/".join(parts[:index]))
            if key not in expected:
                clock.tick()
                need(len(expected) < MAX_ENTRIES, "entry-bound")
                expected[key] = {"kind": "directory", "mode": 0o555}
            need(expected[key]["kind"] == "directory", "symbolic-parent")
    add("sdk", "receipt.json", {"kind": "file", "mode": origin_receipt_mode, "sha256": sha(raw), "size": len(raw)})
    for top in ("repositories", "graph", "registry-cache"):
        add("sdk", top, {"kind": "directory", "mode": 0o555})
    for repo in receipt["repositories"]:
        clock.tick()
        prefix = "repositories/" + repo["canonical_name"]
        add("sdk", prefix, {"kind": "directory", "mode": 0o555})
        for row in repo["files"]:
            path = prefix + "/" + row["path"]
            add("sdk", path, {key: value for key, value in row.items() if key != "path"})
    for name, pin in receipt["graph_files"].items():
        need(set(pin) == {"sha256"}, "graph-pin")
        path = "graph/" + name
        parents("sdk", path)
        add("sdk", path, {"kind": "file", "mode": graph_modes[name], "sha256": digest(pin["sha256"])})
    registry = receipt["registry_metadata"]
    need(type(registry) is dict and registry["schema"] == sdk.REGISTRY_SCHEMA
         and type(registry["files"]) is list and 0 < len(registry["files"]) <= sdk.REGISTRY_MAX_ENTRIES
         and sha(sdk.canonical(registry["files"])) == registry["inventory_sha256"], "registry")
    for row in registry["files"]:
        need(row["path"] == "content_addressable/sha256/" + digest(row["sha256"]) + "/file"
             and row["mode"] == 0o444, "registry-member")
        path = "registry-cache/" + row["path"]
        parents("sdk", path)
        item = {"kind": "file", "mode": 0o444, "sha256": row["sha256"], "size": row["size"]}
        if ("sdk", path) in expected:
            need(expected[("sdk", path)] == item, "registry-duplicate")
        else:
            add("sdk", path, item)
    for row in receipt["nix_inventory"]:
        clock.tick()
        add("jdk", row["path"], {key: value for key, value in row.items() if key != "path"})
    need(len(expected) <= MAX_ENTRIES, "entry-bound")
    for (role, path), item in expected.items():
        if path:
            parent = "/".join(relative(path)[:-1])
            need((role, parent) in expected and expected[(role, parent)]["kind"] == "directory", "entry-parent")
    return expected


def scan(roots, expected, clock):
    """Complete names/types/modes/bytes/text, no target following; per-pass bound."""
    observed, witnesses, total = {}, {}, 0
    children = {}
    for role, path in expected:
        clock.tick()
        if path:
            parts = relative(path)
            children.setdefault((role, "/".join(parts[:-1])), set()).add(parts[-1])
    def walk(role, fd, path):
        nonlocal total
        clock.tick()
        before = os.fstat(fd)
        key = (role, path)
        need(stat.S_IMODE(before.st_mode) == 0o555 and before.st_uid in (0, os.getuid()), "unsealed-directory")
        observed[key] = {"kind": "directory", "mode": 0o555}
        witnesses[key] = identity(before)
        for name in names(fd, children.get(key, set()), clock):
            clock.tick()
            child = path + "/" + name if path else name
            relative(child)
            item_key = (role, child)
            need(item_key in expected, "unselected-member")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            item = expected[item_key]
            if item["kind"] == "directory":
                need(stat.S_ISDIR(info.st_mode), "directory-type")
                nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(identity(info) == identity(os.fstat(nested)), "directory-open-race")
                    walk(role, nested, child)
                finally:
                    os.close(nested)
            elif item["kind"] == "symlink":
                need(stat.S_ISLNK(info.st_mode), "link-type")
                target = os.readlink(name, dir_fd=fd)
                need(target == item["target"], "link-target")
                observed[item_key] = {"kind": "symlink", "target": target}
                witnesses[item_key] = identity(info)
            else:
                need(stat.S_ISREG(info.st_mode) and roots[role].regular_links(info)
                     and stat.S_IMODE(info.st_mode) == item["mode"]
                     and info.st_uid in (0, os.getuid()), "file-mode-type-custody")
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(identity(info) == identity(os.fstat(opened)), "file-open-race")
                    h, count = hashlib.sha256(), 0
                    while True:
                        clock.tick()
                        block = os.read(opened, 65536)
                        if not block:
                            break
                        count += len(block)
                        total += len(block)
                        need(count <= sdk.MAX_FILE and total <= MAX_BYTES, "content-bound")
                        h.update(block)
                    need(identity(info) == identity(os.fstat(opened)) and count == info.st_size, "file-read-race")
                    actual = {"kind": "file", "mode": item["mode"], "sha256": h.hexdigest(), "size": count}
                    need(all(actual[key] == value for key, value in item.items()), "file-content")
                    observed[item_key] = actual
                    witnesses[item_key] = identity(info)
                finally:
                    os.close(opened)
            need(identity(info) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), "node-race")
        need(identity(before) == identity(os.fstat(fd)), "directory-read-race")
    for role, root in roots.items():
        root.check()
        walk(role, root.fd, "")
        root.check()
    need(set(observed) == set(expected), "missing-member")
    return observed, witnesses



def _fresh_namespace(roots, expected, clock):
    """Metadata only: a local closed namespace witness, never content authority."""
    need(0 < len(expected) <= MAX_ENTRIES and set(roots) == {"sdk", "jdk"}, "fresh-entry-bound")
    children, witnesses, total = {}, {}, 0
    for key, row in expected.items():
        clock.tick()
        need(type(key) is tuple and len(key) == 2 and key[0] in roots, "fresh-entry-key")
        role, path = key
        parts = relative(path, empty=True)
        need(row["kind"] in ("directory", "file", "symlink"), "fresh-entry-kind")
        if row["kind"] == "file":
            need(set(row) == {"kind", "mode", "sha256", "size"}
                 and type(row["size"]) is int and 0 <= row["size"] <= sdk.MAX_FILE
                 and type(row["mode"]) is int, "fresh-file-shape")
            digest(row["sha256"])
        elif row["kind"] == "directory":
            need(set(row) == {"kind", "mode"} and row["mode"] == 0o555, "fresh-directory-shape")
        else:
            need(set(row) == {"kind", "target"} and type(row["target"]) is str, "fresh-link-shape")
        if parts:
            parent = (role, "/".join(parts[:-1]))
            need(parent in expected and expected[parent]["kind"] == "directory", "fresh-entry-parent")
            children.setdefault(parent, set()).add(parts[-1])
        else:
            need(row["kind"] == "directory", "fresh-role-root")
    need(all((role, "") in expected for role in roots), "fresh-missing-role")
    def walk(role, fd, path):
        nonlocal total
        clock.tick()
        before = os.fstat(fd)
        key = (role, path)
        need(key in expected and expected[key]["kind"] == "directory"
             and stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o555
             and before.st_uid in (0, os.getuid()), "fresh-directory-custody")
        witnesses[key] = identity(before)
        for name in names(fd, children.get(key, set()), clock):
            clock.tick()
            child = path + "/" + name if path else name
            relative(child)
            selected = (role, child)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = expected[selected]
            if row["kind"] == "directory":
                need(stat.S_ISDIR(info.st_mode), "fresh-directory-type")
                nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(identity(info) == identity(os.fstat(nested)) == identity(
                        os.stat(name, dir_fd=fd, follow_symlinks=False)), "fresh-directory-open-race")
                    walk(role, nested, child)
                finally:
                    os.close(nested)
            elif row["kind"] == "symlink":
                need(stat.S_ISLNK(info.st_mode) and os.readlink(name, dir_fd=fd) == row["target"], "fresh-link-text")
                witnesses[selected] = identity(info)
            else:
                need(stat.S_ISREG(info.st_mode) and roots[role].regular_links(info)
                     and info.st_uid in (0, os.getuid()) and stat.S_IMODE(info.st_mode) == row["mode"]
                     and info.st_size == row["size"], "fresh-file-custody")
                total += info.st_size
                need(total <= MAX_BYTES, "fresh-byte-bound")
                witnesses[selected] = identity(info)
            need(identity(info) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), "fresh-node-race")
        need(identity(before) == identity(os.fstat(fd)), "fresh-directory-read-race")
    for role, root in roots.items():
        root.check()
        walk(role, root.fd, "")
        root.check()
    need(set(witnesses) == set(expected), "fresh-missing-member")
    clock.tick()
    return witnesses


class _FreshNarParents(_ParentHandles):
    """At most 32 cached sealed-parent FDs for one fresh NAR pass.

    This is a local IO owner, not content or namespace authority. Every lookup
    still traverses Root._parent's complete current named/before/held/after
    checks; caching replaces directory open with dup only. Full-nine stream
    parent/leaf checks and both complete namespace passes remain unchanged.
    """
    def __init__(self, root, clock):
        need(type(root) is Root and root.clock is clock and not root.owned,
             "fresh-parent-role")
        root.check()
        info = os.fstat(root.fd)
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555,
             "fresh-parent-sealed-root")
        self.root, self.entries, self.closed = root, {}, False
        self.pending = None
        self.clock, self.deadline, self.until_ns = clock, clock.deadline, clock.until_ns
        self.owner, self.self = threading.get_ident(), self

    def parent(self, name):
        need(self.self is self and threading.get_ident() == self.owner
             and not self.closed and self.root.clock is self.clock
             and self.clock.deadline == self.deadline and self.clock.until_ns == self.until_ns,
             "fresh-parent-current-owner-clock")
        self.clock.tick()
        return self.root._parent(name, self)

    def take(self, key, parent, name, selected):
        if key in self.entries:
            # Keep the cached FD enrolled on a hit. No pop/reinsertion can
            # orphan it; bounded FIFO eviction affects IO cost, not authority.
            fd, witness = self.entries[key]
            need(witness == selected, "fresh-parent-handle-replacement")
            return os.dup(fd)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)

    def keep(self, key, fd, selected):
        need(self.pending is None, "fresh-parent-pending-owner")
        if key not in self.entries:
            if len(self.entries) == 32:
                oldest = next(iter(self.entries))
                prior, unused = self.entries.pop(oldest)
                os.close(prior)
            # Enroll the actual duplicate before dict allocation/validation.
            # A failed insertion leaves pending owned until the all-FD drain.
            self.pending = os.dup(fd)
            self.entries[key] = (self.pending, selected)
            self.pending = None

    def close(self):
        entries, self.entries = self.entries, {}
        pending, self.pending = self.pending, None
        self.closed = True
        failure = None
        for fd, unused in entries.values():
            if fd == pending: pending = None  # insertion may succeed then raise
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None: failure = error
        if pending is not None:
            try:
                os.close(pending)
            except BaseException as error:
                if failure is None: failure = error
        if failure is not None: raise failure

    def __exit__(self, exc_type, error, traceback):
        try:
            self.close()
        except BaseException as cleanup:
            if error is not None: raise error.with_traceback(traceback) from cleanup
            raise


class _FreshNarFile:
    """One owned nofollow stream; SHA hashes exactly the bytes given to NAR."""
    def __init__(self, root, name, row, witnesses, role, observed, completed, aggregate, clock, parents=None):
        self.root, self.name, self.row, self.clock = root, name, row, clock
        need(parents is None or (type(parents) is _FreshNarParents and parents.root is root
             and parents.clock is clock), "fresh-stream-parent-owner")
        self.parents = parents
        self.key, self.observed, self.completed, self.aggregate = (role, name), observed, completed, aggregate
        self.witness = witnesses[self.key]
        self.parent_key = (role, "/".join(relative(name)[:-1]))
        self.parent_witness = witnesses[self.parent_key]
        self.parent = self.fd = None
        self.count, self.hash, self.eof, self.closed = 0, hashlib.sha256(), False, False
        try:
            clock.tick()
            need(self.key not in completed, "fresh-duplicate-stream")
            self.parent, self.leaf = root.parent(name) if parents is None else parents.parent(name)
            need(identity(os.fstat(self.parent)) == self.parent_witness, "fresh-stream-parent")
            before = os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)
            need(identity(before) == self.witness and stat.S_ISREG(before.st_mode)
                 and root.regular_links(before) and before.st_uid in (0, os.getuid())
                 and before.st_size == row["size"] and stat.S_IMODE(before.st_mode) == row["mode"], "fresh-stream-before")
            # A custom opener bypasses the protected serializer's default fstat
            # checks. Restore its exact size/owner-executable predicates here.
            need(bool(before.st_mode & stat.S_IXUSR) == bool(row["mode"] & 0o111), "fresh-stream-executable")
            self.fd = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.parent)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.clock.tick()
        need(not self.closed and identity(os.fstat(self.parent)) == self.parent_witness
             and identity(os.fstat(self.fd)) == self.witness
             and identity(os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)) == self.witness, "fresh-stream-held-name")
        current, leaf = self.root.parent(self.name) if self.parents is None else self.parents.parent(self.name)
        try:
            need(identity(os.fstat(current)) == self.parent_witness
                 and identity(os.stat(leaf, dir_fd=current, follow_symlinks=False)) == self.witness, "fresh-stream-current-parent")
        finally:
            os.close(current)
        self.root.check()

    def read(self, size=-1):
        need(not self.closed and type(size) is int and 0 < size <= 65536, "fresh-stream-read-bound")
        self.clock.tick()
        block = os.read(self.fd, size)
        self.clock.tick()
        self.count += len(block)
        self.aggregate[0] += len(block)
        need(self.count <= self.row["size"] and self.aggregate[0] <= MAX_BYTES, "fresh-stream-byte-bound")
        self.hash.update(block)
        if not block:
            self.eof = True
        return block

    def close(self):
        self.closed = True
        try:
            if self.fd is not None:
                fd, self.fd = self.fd, None
                os.close(fd)
        finally:
            if self.parent is not None:
                parent, self.parent = self.parent, None
                os.close(parent)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *unused):
        try:
            if exc_type is None:
                self.check()
                actual = self.hash.hexdigest()
                need(self.eof and self.count == self.row["size"] and actual == self.row["sha256"], "fresh-stream-content")
                self.observed[self.key] = {"kind": "file", "mode": self.row["mode"], "sha256": actual, "size": self.count}
                self.completed.add(self.key)
                self.clock.tick()
        finally:
            self.close()


def _scan_nar(roots, expected, clock):
    """Fresh byte/NAR equivalence only; no later full scan is replaced."""
    started_ns, events = time.monotonic_ns(), 0
    phases = ("namespace-start", "namespace-complete", "jdk-nar-start", "jdk-nar-complete",
              "sdk-nar-start", "sdk-nar-complete", "final-namespace-start", "final-namespace-complete")
    def progress(phase):
        nonlocal events
        need(phase in phases and events < len(phases), "fresh-nar-diagnostic-bound")
        events += 1
        print("sdk-carrier-nar: " + phase + " elapsed_ns=" + str(max(0,time.monotonic_ns()-started_ns))
              + " remaining_ns=" + str(_remaining_original_ns(clock)), file=sys.stderr, flush=True)
    progress("namespace-start")
    witnesses = _fresh_namespace(roots, expected, clock)
    progress("namespace-complete")
    observed = {key: dict(row) for key, row in expected.items()}
    completed, aggregate, nars = set(), [0], {}
    # One bounded cache at a time: close all its FDs before the last complete
    # namespace observation, including on stream/hash/dup/close refusal.
    for role in sorted(roots):
        progress("jdk-nar-start" if role == "jdk" else "sdk-nar-start")
        with _FreshNarParents(roots[role], clock) as parents:
            def opener(unused, name, selected=role):
                key = (selected, name)
                need(key in expected and expected[key]["kind"] == "file", "fresh-stream-selected")
                return _FreshNarFile(roots[selected], name, expected[key], witnesses, selected,
                                     observed, completed, aggregate, clock, parents)
            nars[role] = nar.hash_descriptor(descriptor(role, expected, clock), opener=opener, deadline=clock.deadline)
            roots[role].check()
        progress("jdk-nar-complete" if role == "jdk" else "sdk-nar-complete")
    need(len(completed) == sum(row["kind"] == "file" for row in expected.values())
         and aggregate[0] == sum(row.get("size", 0) for row in expected.values()), "fresh-stream-complete")
    # Revisit EVERY earlier node after the last role's stream. A per-file exit
    # check alone cannot detect mutation while a later file is being read.
    progress("final-namespace-start")
    need(_fresh_namespace(roots, expected, clock) == witnesses, "fresh-namespace-final")
    progress("final-namespace-complete")
    for root in roots.values():
        root.check()
    clock.tick()
    return observed, witnesses, nars


def descriptor(role, rows, clock):
    nodes = []
    for (selected, path), row in sorted(rows.items()):
        clock.tick()
        if selected != role:
            continue
        node = {"path": path, "type": {"file": "regular"}.get(row["kind"], row["kind"])}
        if row["kind"] == "file":
            node.update(size=row["size"], executable=bool(row["mode"] & 0o111))
        elif row["kind"] == "symlink":
            node["target"] = row["target"]
        nodes.append(node)
    return {"schemaVersion": 1, "root": "/sdk-carrier-logical/" + role, "nodes": nodes}


def origin(origin_root, pin, clock, stack):
    roots = {"sdk": stack.enter_context(Root(origin_root, clock)),
             "jdk": stack.enter_context(Root(sdk.JDK, clock, origin_jdk=True))}
    raw = read(roots["sdk"], "receipt.json", MAX_METADATA, digest(pin))
    receipt = decode(raw)
    fd, selected = roots["sdk"].open("receipt.json")
    os.close(fd)
    graph_modes = {}
    for name in sdk.GRAPH:
        clock.tick()
        fd, metadata = roots["sdk"].open("graph/" + name)
        os.close(fd)
        graph_modes[name] = stat.S_IMODE(metadata[4])
    expected = expected_entries(receipt, raw, clock, stat.S_IMODE(selected[4]), graph_modes)
    sdk.validate_export(roots["sdk"].path, pin, receipt["baseline_inventory_sha256"],
                        receipt["graph_files"], on_read=clock.tick)
    rows, witnesses = scan(roots, expected, clock)
    return roots, raw, receipt, rows, witnesses


def preflight(origin_root, pinned_origin_receipt_sha256, absolute_deadline):
    """Read-only origin proof; not a promise of future mutable-tree stability."""
    clock = Clock(absolute_deadline)
    with ExitStack() as stack:
        roots, raw, receipt, rows, witnesses = origin(origin_root, pinned_origin_receipt_sha256, clock, stack)
        again, after = scan(roots, rows, clock)
        need(rows == again and witnesses == after, "origin-readback")
        return {"kind": KIND + "-origin-preflight", "origin_root": str(roots["sdk"].path),
                "origin_receipt_sha256": sha(raw), "jdk_root": str(roots["jdk"].path),
                "entry_count": len(rows), "bytes": sum(row.get("size", 0) for row in rows.values()),
                "symbolic_count": sum(row["kind"] == "symlink" for row in rows.values()),
                "tree_watch_traversal_authorized": False, "future_custody_proved": False}


class Output:
    """Exclusive owned output; refusal retains partial owned bytes for diagnosis."""
    def __init__(self, path, clock):
        self.path, self.clock = absolute(path), clock
        self.materialized = {}
        parent = self.path.parent
        fd = sdk.open_dir(parent, private=True)
        try:
            os.mkdir(self.path.name, mode=0o700, dir_fd=fd)
            created = os.stat(self.path.name, dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISDIR(created.st_mode) and created.st_uid == os.getuid()
                 and stat.S_IMODE(created.st_mode) == 0o700, "created-output")
            self.root = Root(self.path, clock, sealed=False,
                             expected_identity=identity(created, True), owned=True)
            need(identity(os.stat(self.path.name, dir_fd=fd, follow_symlinks=False), True)
                 == identity(created, True), "created-output-readback")
        finally:
            os.close(fd)

    def mkdir(self, name, *, parent_handles=None):
        need(parent_handles is None or (type(parent_handles) is _ParentHandles
             and parent_handles.root is self.root), "mkdir-parent-owner")
        fd, leaf = (self.root.parent(name) if parent_handles is None else parent_handles.parent(name))
        try:
            os.mkdir(leaf, mode=0o700, dir_fd=fd)
            before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                 and stat.S_IMODE(before.st_mode) == 0o700, "created-directory")
            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                need(identity(before, True) == identity(os.fstat(child), True) == identity(
                    os.stat(leaf, dir_fd=fd, follow_symlinks=False), True), "created-directory-race")
                self.root.named[name] = identity(before, True)
            finally:
                os.close(child)
        finally:
            os.close(fd)

    def seal_directory(self, name):
        fd, leaf = self.root.parent(name)
        try:
            before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            need(identity(before, True) == self.root.named.get(name), "owned-chmod-parent")
            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                need(identity(os.fstat(child), True) == self.root.named[name], "owned-chmod-open")
                os.fchmod(child, 0o555)
                selected = identity(os.fstat(child), True)
                need(identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False), True) == selected,
                     "owned-chmod-readback")
                self.root.named[name] = selected
            finally:
                os.close(child)
        finally:
            os.close(fd)

    def create(self, name):
        self.root.check()
        return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=self.root.fd)

    def file(self, name, raw):
        fd = self.create(name)
        try:
            write_all(fd, raw, self.clock)
            os.fsync(fd)
            os.fchmod(fd, 0o444)
            selected = identity(os.fstat(fd))
            need(selected == identity(os.stat(name, dir_fd=self.root.fd, follow_symlinks=False)), "output-file-name")
            self.materialized[name] = selected
        finally:
            os.close(fd)

    def finish(self):
        self.root.check()
        os.fchmod(self.root.fd, 0o555)
        # Deliberately refresh only the newly published output's own mode witness.
        self.root.chain[-1] = (self.root.chain[-1][0], self.root.fd, identity(os.fstat(self.root.fd), True))
        self.root.check()

    def close(self):
        self.root.close()


def write_all(fd, raw, clock):
    view = memoryview(raw)
    while view:
        clock.tick()
        count = os.write(fd, view)
        need(count > 0, "short-write")
        view = view[count:]


def nar_origins(roots, rows, clock):
    result = {}
    for role in sorted(roots):
        def opener(unused, name, selected=role):
            clock.tick()
            fd, _ = roots[selected].open(name)
            return os.fdopen(fd, "rb")
        result[role] = nar.hash_descriptor(descriptor(role, rows, clock), opener=opener, deadline=clock.deadline)
    return result


def producer_binding(value, deadline=None):
    need(type(value) is dict and set(value) == {"mode", "epoch", "source_commit", "graph_sha256",
         "entry_monotonic_ns", "deadline_monotonic_ns", "work_cutoff_monotonic_ns"}, "producer-context")
    need(value["mode"] == "native-sdk-carrier-seal-reserved" and type(value["epoch"]) is str and re.fullmatch(
        r"(?:/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|"
        r"/home/jess/\.local/state/omux-execution-20261005)/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        value["epoch"]) is not None and type(value["source_commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is not None, "producer-scope")
    digest(value["graph_sha256"])
    for field in ("entry_monotonic_ns", "deadline_monotonic_ns", "work_cutoff_monotonic_ns"):
        need(type(value[field]) is int and value[field] > 0, "producer-clock-type")
    entry, until, work = (value[field] for field in ("entry_monotonic_ns", "deadline_monotonic_ns",
                                                   "work_cutoff_monotonic_ns"))
    need(until - entry == 1200 * 10**9 and work == entry + 1170 * 10**9, "producer-clock-join")
    if deadline is not None:
        need(deadline == work / 10**9, "producer-original-cutoff")
    return dict(value)


def seal(origin_root, pinned_origin_receipt_sha256, output_dir, absolute_deadline, *, producer_context=None):
    clock = Clock(absolute_deadline)
    context = producer_binding(producer_context, absolute_deadline)
    clock.until_ns = context["work_cutoff_monotonic_ns"]
    clock.tick()
    with ExitStack() as stack:
        roots, raw, original, rows, witnesses = origin(origin_root, pinned_origin_receipt_sha256, clock, stack)
        nars = nar_origins(roots, rows, clock)
        output = Output(output_dir, clock)
        stack.callback(output.close)
        payload = output.create("payload.bin")
        entries, h, offset = [], hashlib.sha256(), 0
        try:
            for (role, path), row in sorted(rows.items()):
                clock.tick()
                entry = {"role": role, "path": path, **row}
                if row["kind"] == "file":
                    entry["offset"] = offset
                    fd, before = roots[role].open(path)
                    file_hash, count = hashlib.sha256(), 0
                    try:
                        need(before == witnesses[(role, path)], "pack-original-identity")
                        while True:
                            clock.tick()
                            block = os.read(fd, 65536)
                            if not block:
                                break
                            count += len(block)
                            offset += len(block)
                            need(count <= row["size"] and offset <= MAX_BYTES, "pack-bound")
                            file_hash.update(block)
                            h.update(block)
                            write_all(payload, block, clock)
                        need(count == row["size"] and file_hash.hexdigest() == row["sha256"]
                             and identity(os.fstat(fd)) == before, "pack-readback")
                    finally:
                        os.close(fd)
                entries.append(entry)
            os.fsync(payload)
            os.fchmod(payload, 0o444)
        finally:
            os.close(payload)
        manifest = {"kind": MANIFEST, "origin_root": str(roots["sdk"].path),
                    "origin_receipt_sha256": sha(raw), "jdk_origin_root": str(roots["jdk"].path),
                    "origin_receipt_mode": rows[("sdk", "receipt.json")]["mode"],
                    "origin_graph_modes": {name: rows[("sdk", "graph/" + name)]["mode"] for name in sdk.GRAPH},
                    "entries": entries, "payload_sha256": h.hexdigest(), "payload_bytes": offset,
                    "nars": nars}
        manifest_raw = encoded(manifest)
        need(len(manifest_raw) <= MAX_METADATA, "manifest-bound")
        output.file("manifest.json", manifest_raw)
        output.file("origin-receipt.json", raw)
        after_rows, after_witnesses = scan(roots, rows, clock)
        sdk.validate_export(roots["sdk"].path, sha(raw), original["baseline_inventory_sha256"],
                            original["graph_files"], on_read=clock.tick)
        need(after_rows == rows and after_witnesses == witnesses
             and read(roots["sdk"], "receipt.json", MAX_METADATA, sha(raw)) == raw, "origin-final-readback")
        custody = {role: {"root": str(root.path), "root_identity": root.chain[-1][2],
                         "ancestry_sha256": sha(encoded([item[2] for item in root.chain])),
                         "members_sha256": sha(encoded([[role_name, name, value]
                            for (role_name, name), value in sorted(witnesses.items()) if role_name == role]))}
                   for role, root in roots.items()}
        report = {"kind": KIND, "producer_context": context, "origin": {"root": str(roots["sdk"].path),
                  "receipt_sha256": sha(raw), "receipt_bytes": len(raw),
                  "baseline_receipt_sha256": original["baseline_receipt_sha256"],
                  "baseline_inventory_sha256": original["baseline_inventory_sha256"],
                  "inventory_sha256": original["inventory_sha256"], "mapping_sha256": original["mapping_sha256"],
                  "selection_sha256": original["selection_sha256"], "producer": original["producer"]},
                  "origin_custody": custody, "manifest_sha256": sha(manifest_raw),
                  "manifest_bytes": len(manifest_raw), "payload_sha256": h.hexdigest(),
                  "payload_bytes": offset, "entry_count": len(entries),
                  "origin_fully_rechecked": True, "sdk_execution_qualified": False,
                  "metadata_qualified": False, "source_witnesses_replaced": False}
        # Complete transport rehash/NAR check before the ready receipt is published.
        validate_content(output.root, manifest, rows, clock)
        final_rows, final_witnesses = scan(roots, rows, clock)
        need(final_rows == rows and final_witnesses == witnesses, "origin-publication-readback")
        for root in roots.values():
            root.check()
        output.file("receipt.json", encoded(report))
        need(binding(output.root, sha(encoded(report)), clock)[0] == report, "sealed-output-readback")
        final_rows, final_witnesses = scan(roots, rows, clock)
        need(final_rows == rows and final_witnesses == witnesses, "sealed-origin-last-readback")
        output.finish()
        for root in roots.values():
            root.check()
        return report


class Range(io.RawIOBase):
    def __init__(self, fd, start, size, clock):
        self.fd, self.start, self.size, self.position, self.clock = fd, start, size, 0, clock

    def read(self, size=-1):
        self.clock.tick()
        size = self.size - self.position if size < 0 else min(size, self.size-self.position)
        if size <= 0:
            return b""
        block = os.pread(self.fd, size, self.start+self.position)
        need(bool(block), "payload-truncated")
        self.position += len(block)
        return block



def _payload_sha_pass(fd, files, size, payload_pin, clock):
    """One bounded linear SHA pass through already-validated contiguous extents.

    Borrow the existing held payload FD. Each file receives its own exact SHA;
    the aggregate hashes every actual byte once. Canonical NAR is independently
    reread afterward by validate_content; no physical proof or old authority is
    replaced. This reader owns no additional descriptor or renewed clock.
    """
    loaded = consumed = cursor = 0
    block = None
    total_hash = hashlib.sha256()
    for entry in files.values():
        clock.tick()
        need(entry["offset"] == consumed, "payload-batch-contiguous")
        remaining = entry["size"]
        h = hashlib.sha256()
        while remaining:
            clock.tick()
            if block is None:
                request = min(65536, size-loaded)
                need(request > 0, "payload-truncated")
                block = os.pread(fd, request, loaded)
                clock.tick()
                need(0 < len(block) <= request, "payload-truncated")
                loaded += len(block)
                total_hash.update(block)
                cursor = 0
            count = min(remaining, len(block)-cursor)
            need(count > 0, "payload-batch-progress")
            part = memoryview(block)[cursor:cursor+count]
            try:
                h.update(part)
            finally:
                part.release()
            cursor += count
            consumed += count
            remaining -= count
            if cursor == len(block):
                # Release the sole buffer before allocating the next block.
                block = None
                cursor = 0
        need(h.hexdigest() == digest(entry["sha256"]), "payload-file-digest")
        clock.tick()
    need(consumed == loaded == size and block is None, "payload-batch-complete")
    clock.tick()
    need(os.pread(fd, 1, size) == b"", "payload-trailing-bytes")
    clock.tick()
    need(total_hash.hexdigest() == digest(payload_pin), "payload-digest")
    clock.tick()


def validate_content(root, manifest, expected, clock):
    need(type(manifest) is dict and set(manifest) == {"kind", "origin_root", "origin_receipt_sha256",
         "jdk_origin_root", "origin_receipt_mode", "origin_graph_modes", "entries", "payload_sha256", "payload_bytes", "nars"}
         and manifest["kind"] == MANIFEST and manifest["jdk_origin_root"] == sdk.JDK, "manifest-fields")
    entries = manifest["entries"]
    need(type(entries) is list and 0 < len(entries) <= MAX_ENTRIES, "manifest-entries")
    rows, files, offset, order = {}, {}, 0, []
    for entry in entries:
        clock.tick()
        need(type(entry) is dict and entry.get("role") in ("sdk", "jdk"), "entry-role")
        role, path = entry["role"], entry["path"]
        relative(path, empty=True)
        key = (role, path)
        need(key not in rows and key in expected, "entry-duplicate-or-unselected")
        row = {key: value for key, value in entry.items() if key not in ("role", "path", "offset")}
        need(all(row.get(key) == value for key, value in expected[key].items()), "manifest-inventory")
        if row["kind"] == "file":
            need(set(entry) == {"role", "path", "kind", "mode", "sha256", "size", "offset"}
                 and type(entry["offset"]) is int and entry["offset"] == offset
                 and type(row["size"]) is int and 0 <= row["size"] <= sdk.MAX_FILE, "file-extent")
            files[key] = entry
            offset += row["size"]
        else:
            need(set(entry) == ({"role", "path", "kind", "mode"} if row["kind"] == "directory"
                 else {"role", "path", "kind", "target"}), "entry-fields")
        rows[key] = row
        order.append(key)
    need(order == sorted(rows) and set(rows) == set(expected) and offset <= MAX_BYTES
         and type(manifest["payload_bytes"]) is int and manifest["payload_bytes"] == offset, "complete-extents")
    fd, before = root.open("payload.bin")
    try:
        need(before[6] == offset and transport_leaf_mode(root, before), "payload-size-mode")
        _payload_sha_pass(fd, files, offset, manifest["payload_sha256"], clock)
        need(type(manifest["nars"]) is dict and set(manifest["nars"]) == {"sdk", "jdk"}, "nar-roles")
        for role in ("sdk", "jdk"):
            def opener(unused, name, selected=role):
                entry = files[(selected, name)]
                return Range(fd, entry["offset"], entry["size"], clock)
            need(nar.hash_descriptor(descriptor(role, rows, clock), opener=opener, deadline=clock.deadline)
                 == manifest["nars"][role], "nar-digest")
        need(identity(os.fstat(fd)) == before, "payload-read-race")
        root.check()
        return rows, files
    finally:
        os.close(fd)


def binding(root, pin, clock):
    names(root.fd, set(FILES), clock)
    # All retained transport leaves must be read-only, including metadata.
    # Root.open/check retains the exact actual mode/inode/name witness: an
    # allowed mode transition during this read is still an identity race.
    for name in FILES:
        fd, witness = root.open(name)
        try:
            need(transport_leaf_mode(root, witness), "transport-leaf-mode")
        finally:
            os.close(fd)
    raw = read(root, "receipt.json", 65536, digest(pin))
    report = decode(raw)
    need(type(report) is dict and set(report) == {"kind", "producer_context", "origin", "origin_custody", "manifest_sha256",
         "manifest_bytes", "payload_sha256", "payload_bytes", "entry_count", "origin_fully_rechecked",
         "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced"}
         and report["kind"] == KIND and report["origin_fully_rechecked"] is True
         and all(report[key] is False for key in ("sdk_execution_qualified", "metadata_qualified",
                                                "source_witnesses_replaced")), "carrier-receipt")
    producer_binding(report["producer_context"])
    item = report["origin"]
    need(type(item) is dict and set(item) == {"root", "receipt_sha256", "receipt_bytes",
         "baseline_receipt_sha256", "baseline_inventory_sha256", "inventory_sha256", "mapping_sha256",
         "selection_sha256", "producer"}, "origin-fields")
    absolute(item["root"])
    original_raw = read(root, "origin-receipt.json", MAX_METADATA, item["receipt_sha256"])
    original = decode(original_raw)
    need(type(item["receipt_bytes"]) is int and len(original_raw) == item["receipt_bytes"]
         and all(item[key] == original[key] for key in ("baseline_receipt_sha256",
              "baseline_inventory_sha256", "inventory_sha256", "mapping_sha256", "selection_sha256", "producer")), "origin-lineage")
    need(type(report["origin_custody"]) is dict and set(report["origin_custody"]) == {"sdk", "jdk"}, "custody-roles")
    for role, custody in report["origin_custody"].items():
        need(type(custody) is dict and set(custody) == {"root", "root_identity", "ancestry_sha256", "members_sha256"}
             and custody["root"] == (item["root"] if role == "sdk" else sdk.JDK)
             and type(custody["root_identity"]) is list and len(custody["root_identity"]) == 5
             and all(type(value) is int for value in custody["root_identity"]), "origin-custody-fields")
        digest(custody["ancestry_sha256"])
        digest(custody["members_sha256"])
    manifest_raw = read(root, "manifest.json", MAX_METADATA, report["manifest_sha256"])
    manifest = decode(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {"kind", "origin_root", "origin_receipt_sha256",
         "jdk_origin_root", "origin_receipt_mode", "origin_graph_modes", "entries", "payload_sha256", "payload_bytes", "nars"}, "manifest-fields")
    expected = expected_entries(original, original_raw, clock, manifest["origin_receipt_mode"], manifest["origin_graph_modes"])
    need(type(report["manifest_bytes"]) is int and report["manifest_bytes"] == len(manifest_raw)
         and manifest["origin_root"] == item["root"] and manifest["origin_receipt_sha256"] == item["receipt_sha256"]
         and report["payload_sha256"] == manifest["payload_sha256"]
         and type(report["payload_bytes"]) is int and report["payload_bytes"] == manifest["payload_bytes"]
         and type(report["entry_count"]) is int and report["entry_count"] == len(manifest["entries"]), "carrier-join")
    rows, files = validate_content(root, manifest, expected, clock)
    need(encoded(manifest) == manifest_raw and encoded(report) == raw, "canonical-metadata")
    need(read(root, "receipt.json", 65536, pin) == raw, "carrier-receipt-readback")
    return report, manifest, rows, files


def validate_binding(carrier_dir, pinned_carrier_receipt_sha256, absolute_deadline):
    clock = Clock(absolute_deadline)
    with Root(carrier_dir, clock) as root:
        report, _, _, _ = binding(root, pinned_carrier_receipt_sha256, clock)
        root.check()
        return report


class HeldCarrier:
    """One local proof owner, never a serialized or caller-supplied proof token.

    Hold four exact regular FDs plus the nofollow ancestor chain. Initial and
    mandatory final binding stay full. Intermediate reuse is valid only while
    every held/current name and original clock remains the same.
    """
    def __init__(self, carrier_dir, pin, absolute_deadline):
        self._path, self._pin = absolute(carrier_dir), digest(pin)
        self._self = self
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._clock = Clock(absolute_deadline)
        self._deadline, self._until_ns = self._clock.deadline, self._clock.until_ns
        self._stack, self._held = ExitStack(), ()
        self._root = self._owner = None
        self._chain = ()
        self._facts = None
        self._extracted = None
        self._final_fresh = False
        self._entered = self._active = self._final = False

    def __enter__(self):
        need(self._self is self and not self._entered and os.getpid() == self._pid
             and threading.get_ident() == self._thread, "held-carrier-reentry")
        self._entered = self._active = True
        try:
            self._root = self._owner = self._stack.enter_context(Root(self._path, self._clock))
            self._chain = tuple(self._root.chain)
            held = []
            for name in FILES:
                fd, witness = self._root.open(name)
                self._stack.callback(os.close, fd)
                need(witness[5] == 1 and transport_leaf_mode(self._root, witness), "held-carrier-leaf")
                held.append((name, fd, tuple(witness)))
            self._held = tuple(held)
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def check(self):
        need(self._self is self and self._active and os.getpid() == self._pid
             and threading.get_ident() == self._thread
             and self._root is self._owner and self._root is not None
             and self._root.path == self._path and self._root.clock is self._clock
             and tuple(self._root.chain) == self._chain
             and self._clock.deadline == self._deadline and self._clock.until_ns == self._until_ns,
             "held-carrier-owner-clock")
        self._root.check()
        need(tuple(name for name, _, _ in self._held) == FILES, "held-carrier-four-leaves")
        names(self._root.fd, set(FILES), self._clock)
        for name, fd, witness in self._held:
            self._clock.tick()
            before = os.stat(name, dir_fd=self._root.fd, follow_symlinks=False)
            held = os.fstat(fd)
            after = os.stat(name, dir_fd=self._root.fd, follow_symlinks=False)
            need(identity(before) == identity(held) == identity(after) == list(witness)
                 and stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                 and held.st_uid in (0, os.getuid()) and transport_leaf_mode(self._root, witness),
                 "held-carrier-current-leaf")
        self._root.check()

    def join(self, carrier_dir, pin, absolute_deadline):
        self.check()
        need(absolute(carrier_dir) == self._path and pin == self._pin
             and absolute_deadline == self._deadline, "held-carrier-foreign-use")
        self.check()

    def _binding(self):
        self.check()
        if self._facts is None:
            report, manifest, rows, files = binding(self._root, self._pin, self._clock)
            self.check()
            frozen = []
            for values in (rows, files):
                entries = {}
                for key, row in values.items():
                    self._clock.tick()
                    entries[key] = MappingProxyType(dict(row))
                frozen.append(MappingProxyType(entries))
            self._facts = (encoded(report), encoded(manifest["nars"]), *frozen)
        self.check()
        raw, nars, rows, files = self._facts
        # Only small ordinary copies escape; member facts remain read-only.
        result = decode(raw), {"nars": decode(nars)}, rows, files
        self.check()
        return result

    def report(self):
        result = self._binding()[0]
        self.check()
        return result

    def full_final(self):
        self.check()
        need(self._facts is not None and not self._final, "held-carrier-final-state")
        report, manifest, rows, files = binding(self._root, self._pin, self._clock)
        raw, nars, expected_rows, expected_files = self._facts
        need(encoded(report) == raw and encoded(manifest["nars"]) == nars
             and rows == expected_rows and files == expected_files, "held-carrier-full-final")
        self.check()
        self._final = True

    def _complete_extract(self, path, receipt):
        self.check()
        need(self._extracted is None and not self._final, "held-carrier-one-extraction")
        self._extracted = (absolute(path), sha(encoded(receipt)))
        self.check()

    def _complete_fresh(self, path, receipt):
        self.check()
        need(self._extracted is not None
             and self._extracted == (absolute(path), sha(encoded(receipt))), "held-carrier-fresh-output-join")
        if self._final:
            self._final_fresh = True
        self.check()

    def close(self):
        need(self._self is self, "held-carrier-foreign-close")
        self._active = False
        self._facts = None
        try:
            self._stack.close()
        finally:
            self._held = ()

    def __exit__(self, exc_type, *unused):
        try:
            if exc_type is None:
                self.check()
                need(self._final and (self._extracted is None or self._final_fresh), "held-carrier-final-required")
        finally:
            self.close()

    def __copy__(self):
        raise ValueError("SDK carrier refused: held-carrier-nontransferable")

    def __deepcopy__(self, memo):
        raise ValueError("SDK carrier refused: held-carrier-nontransferable")

    def __reduce_ex__(self, protocol):
        raise ValueError("SDK carrier refused: held-carrier-nontransferable")


def _carrier_clock(held, carrier_dir, pin, deadline):
    if held is None:
        return Clock(deadline)
    need(type(held) is HeldCarrier, "held-carrier-type")
    held.join(carrier_dir, pin, deadline)
    return held._clock


def _carrier_binding(held, root, pin, clock):
    if held is None:
        return binding(root, pin, clock)
    need(root is held._owner and clock is held._clock and pin == held._pin, "held-carrier-binding-owner")
    return held._binding()


class _ProofExitStack(ExitStack):
    """Run every proof/close callback; cleanup cannot replace the body cause."""
    def __exit__(self, exc_type, error, traceback):
        try:
            result = super().__exit__(exc_type, error, traceback)
        except BaseException as cleanup:
            if error is not None: raise BaseException.with_traceback(error, traceback) from cleanup
            raise
        # Proof scopes never turn a body failure into a successful result, even
        # if a future callback accidentally claims suppression.
        return False if error is not None else result


def _remaining_original_ns(clock):
    # Public diagnostic only. No Clock field is changed and no budget renewed.
    until = clock.until_ns if clock.until_ns is not None else int(clock.deadline * 10**9)
    return max(0, min(1200 * 10**9, until - time.monotonic_ns()))


def revalidate_extraction(carrier_dir, pinned_carrier_receipt_sha256, extracted_dir,
                         absolute_deadline, *, pinned_extraction_receipt_sha256=None, _held_carrier=None):
    return _revalidate_extraction(carrier_dir, pinned_carrier_receipt_sha256, extracted_dir,
        absolute_deadline, pinned_extraction_receipt_sha256=pinned_extraction_receipt_sha256,
        _held_carrier=_held_carrier)


def revalidate_action_scratch(carrier_dir, pinned_carrier_receipt_sha256, extracted_dir,
                              absolute_deadline, *, pinned_extraction_receipt_sha256, _held_carrier, consumer_context):
    scope = _ActionScratchScope(_held_carrier, carrier_dir, pinned_carrier_receipt_sha256,
                               extracted_dir, absolute_deadline, consumer_context)
    return _revalidate_extraction(carrier_dir, pinned_carrier_receipt_sha256, extracted_dir,
        absolute_deadline, pinned_extraction_receipt_sha256=pinned_extraction_receipt_sha256,
        _held_carrier=_held_carrier, _scratch_scope=scope)


def _revalidate_extraction(carrier_dir, pinned_carrier_receipt_sha256, extracted_dir,
                         absolute_deadline, *, pinned_extraction_receipt_sha256=None, _held_carrier=None, _scratch_scope=None):
    """Full fresh custody/content proof; scoped carrier facts stay held locally.

    Default calls reauthenticate the carrier fully at both fences. Scoped calls
    require that owner's mandatory full final proof before successful exit.
    """
    clock = _carrier_clock(_held_carrier, carrier_dir, pinned_carrier_receipt_sha256, absolute_deadline)
    if _scratch_scope is not None:
        need(type(_scratch_scope) is _ActionScratchScope, "scratch-revalidation-scope")
        _scratch_scope.join(_held_carrier, extracted_dir, clock)
    if _held_carrier is not None:
        need(_held_carrier._extracted is not None
             and absolute(extracted_dir) == _held_carrier._extracted[0]
             and (pinned_extraction_receipt_sha256 is None
                  or pinned_extraction_receipt_sha256 == _held_carrier._extracted[1]),
             "held-carrier-registered-extraction")
        _held_carrier.check()
    with _ProofExitStack() as stack:
        carrier = stack.enter_context(Root(carrier_dir, clock)) if _held_carrier is None else _held_carrier._owner
        if _held_carrier is not None:
            stack.callback(_held_carrier.check)
        report, manifest, rows, _ = _carrier_binding(_held_carrier, carrier, pinned_carrier_receipt_sha256, clock)
        output = stack.enter_context(Root(extracted_dir, clock))
        names(output.fd, {"sdk", "jdk", "extraction-receipt.json"}, clock)
        raw = read(output, "extraction-receipt.json", 65536, pinned_extraction_receipt_sha256)
        receipt_pin = sha(raw) if pinned_extraction_receipt_sha256 is None else pinned_extraction_receipt_sha256
        receipt = decode(raw)
        extra = {"durability_scope", "consumer_context", "crash_durable_delivery", "downstream_custody_authority"} if _scratch_scope is not None else set()
        need(type(receipt) is dict and set(receipt) == ({"kind", "producer_context", "carrier_receipt_sha256",
             "origin_receipt_sha256", "manifest_sha256", "payload_sha256", "nars", "fresh_custody",
             "extracted_inventory_rechecked", "original_inodes_reused", "absolute_links_materialized_as_mounts",
             "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced"} | extra)
             and receipt["kind"] == (SCRATCH_EXTRACTED if _scratch_scope is not None else EXTRACTED) and receipt["extracted_inventory_rechecked"] is True
             and all(receipt[key] is False for key in ("original_inodes_reused", "absolute_links_materialized_as_mounts",
                  "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced")), "extraction-receipt-fields")
        if _scratch_scope is not None:
            need({key: receipt[key] for key in extra} == _scratch_scope.record(), "scratch-receipt-current-role")
        need(receipt["producer_context"] == report["producer_context"]
             and receipt["carrier_receipt_sha256"] == pinned_carrier_receipt_sha256
             and receipt["origin_receipt_sha256"] == report["origin"]["receipt_sha256"]
             and receipt["manifest_sha256"] == report["manifest_sha256"]
             and receipt["payload_sha256"] == report["payload_sha256"] and receipt["nars"] == manifest["nars"],
             "extraction-lineage")
        need(type(receipt["fresh_custody"]) is dict and set(receipt["fresh_custody"]) == {"sdk", "jdk"}, "fresh-roles")
        roots = {role: stack.enter_context(Root(output.path / role, clock)) for role in ("sdk", "jdk")}
        if _held_carrier is None:
            observed, witnesses = scan(roots, rows, clock)
            need(observed == rows and nar_origins(roots, rows, clock) == manifest["nars"], "fresh-content-nar")
        else:
            observed, witnesses, fresh_nars = _scan_nar(roots, rows, clock)
            need(observed == rows and fresh_nars == manifest["nars"], "fresh-content-nar")
        for role, root in roots.items():
            selected = receipt["fresh_custody"][role]
            need(type(selected) is dict and set(selected) == {"root", "root_identity", "members_sha256"}
                 and selected["root"] == str(root.path) and selected["root_identity"] == root.chain[-1][2]
                 and selected["members_sha256"] == sha(encoded([[name, value]
                    for (which, name), value in sorted(witnesses.items()) if which == role])), "fresh-custody-join")
        need(_carrier_binding(_held_carrier, carrier, pinned_carrier_receipt_sha256, clock)[0] == report, "extraction-carrier-readback")
        after, again = scan(roots, rows, clock)
        need(after == observed and again == witnesses
             and read(output, "extraction-receipt.json", 65536, receipt_pin) == raw, "extraction-final-readback")
        for root in roots.values():
            root.check()
        carrier.check()
        output.check()
        if _held_carrier is not None:
            _held_carrier._complete_fresh(extracted_dir, receipt)
        if _scratch_scope is not None: _scratch_scope.join(_held_carrier, extracted_dir, clock)
        return receipt


def publication_report(carrier_dir, pinned_carrier_receipt_sha256, absolute_deadline, *, _held_carrier=None):
    clock = _carrier_clock(_held_carrier, carrier_dir, pinned_carrier_receipt_sha256, absolute_deadline)
    if _held_carrier is not None:
        report = _held_carrier.report()
        digests = {"manifest.json": report["manifest_sha256"], "origin-receipt.json": report["origin"]["receipt_sha256"],
                   "payload.bin": report["payload_sha256"], "receipt.json": pinned_carrier_receipt_sha256}
        sizes = {"manifest.json": report["manifest_bytes"], "origin-receipt.json": report["origin"]["receipt_bytes"],
                 "payload.bin": report["payload_bytes"], "receipt.json": len(encoded(report))}
        result = {"kind": KIND + "-publication", "carrier_receipt_sha256": pinned_carrier_receipt_sha256,
                  "files": [{"name": name, "sha256": digests[name], "size": sizes[name]} for name in FILES]}
        _held_carrier.check()
        return result
    with Root(carrier_dir, clock) as root:
        report, _, _, _ = binding(root, pinned_carrier_receipt_sha256, clock)
        files = []
        for name in FILES:
            fd, before = root.open(name)
            try:
                h, count = hashlib.sha256(), 0
                limit = MAX_BYTES if name == "payload.bin" else MAX_METADATA
                while True:
                    clock.tick()
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    count += len(block)
                    need(count <= limit, "publication-byte-bound")
                    h.update(block)
                need(identity(os.fstat(fd)) == before and count == before[6]
                     and transport_leaf_mode(root, before), "publication-leaf-readback")
                files.append({"name": name, "sha256": h.hexdigest(), "size": count})
            finally:
                os.close(fd)
        root.check()
        need(next(row["sha256"] for row in files if row["name"] == "receipt.json") == pinned_carrier_receipt_sha256
             and next(row["sha256"] for row in files if row["name"] == "payload.bin") == report["payload_sha256"],
             "publication-join")
        return {"kind": KIND + "-publication", "carrier_receipt_sha256": pinned_carrier_receipt_sha256,
                "files": files}


class _ActionScratchScope:
    """Only the exact current-action transported SDK path, never a skip flag.

    The caller still owns the selected complete carrier and its genuine proof
    aliases. This scope grants no SDK/source/child readiness or durable output.
    """
    fields = ("MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256")

    def __init__(self, held, carrier_dir, pin, path, deadline, context):
        need(type(held) is HeldCarrier, "scratch-live-carrier-type")
        held.join(carrier_dir, pin, deadline)
        values = tuple(os.environ.get("OMUX_NATIVE_FILE_WRITER_MODELS_"+key) for key in self.fields)
        need(all(type(value) is str for value in values) and values[0] == "native-file-writer-models-reserved",
             "scratch-actual-envelope")
        need(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in values[1:3]),
             "scratch-integer-envelope")
        need(type(context) is dict and set(context) == set(self.fields)
             and context == dict(zip(self.fields, values)), "scratch-caller-current-context")
        entry, outer = int(values[1]), int(values[2])
        need(outer-entry == 1200*10**9 and entry <= time.monotonic_ns()
             and held._until_ns == held._clock.until_ns == entry+600*10**9
             and deadline == held._clock.deadline == (entry+600*10**9)/10**9,
             "scratch-original-cutoff")
        need(re.fullmatch(r"(?:/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|"
             r"/home/jess/\.local/state/omux-execution-20261005)/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
             values[3]) is not None and re.fullmatch(r"[0-9a-f]{40}",values[4]) is not None,
             "scratch-actual-epoch-source")
        digest(values[5])
        temporary_alias = absolute(os.environ.get("TEST_TMPDIR", ""))
        temporary = temporary_alias.resolve(strict=True)
        need(absolute(path) == temporary/"siwc-transported-sdk"/"extracted", "scratch-derived-action-path")
        self.held, self.path, self.clock, self.values, self.temporary = held, absolute(path), held._clock, values, temporary
        self.temporary_alias = temporary_alias
        self.pid, self.thread, self.self = os.getpid(), threading.get_ident(), self
        self.check()

    def worker_tick(self):
        self.clock.tick()
        need(tuple(os.environ.get("OMUX_NATIVE_FILE_WRITER_MODELS_"+key) for key in self.fields) == self.values
             and os.environ.get("TEST_TMPDIR", "") == str(self.temporary_alias)
             and self.clock.until_ns == int(self.values[1])+600*10**9
             and self.clock.deadline == self.clock.until_ns/10**9, "scratch-current-context-clock")

    def check(self):
        need(self.self is self and os.getpid() == self.pid and threading.get_ident() == self.thread,
             "scratch-owner-transfer")
        self.worker_tick()
        need(self.temporary_alias.resolve(strict=True) == self.temporary, "scratch-current-derived-parent")
        self.held.check()

    def join(self, held, path, clock):
        self.check()
        need(held is self.held and clock is self.clock and absolute(path) == self.path, "scratch-same-extraction")
        self.check()

    def record(self):
        self.check()
        return {"durability_scope": "ephemeral-current-action",
            "consumer_context": dict(zip(self.fields,self.values)), "crash_durable_delivery": False,
            "downstream_custody_authority": False}


class _CopyState:
    """Bounded invocation-local refusal control, never a proof or new clock."""
    def __init__(self, clock):
        self.clock, self.owner = clock, threading.get_ident()
        self.cancel, self.lock, self.error = threading.Event(), threading.Lock(), None

    @property
    def deadline(self):
        return self.clock.deadline

    def fail(self, error):
        with self.lock:
            if self.error is None:
                self.error = error
            self.cancel.set()

    def sync(self, target):
        os.fsync(target)

    def tick(self):
        self.clock.tick()
        need(not self.cancel.is_set(), "copy-cancelled")

    def owner_tick(self):
        need(threading.get_ident() == self.owner, "copy-owner")
        with self.lock:
            error = self.error
        if error is not None:
            raise error
        self.clock.tick()


class _ActionScratchCopyState(_CopyState):
    def __init__(self, clock, scope):
        need(type(scope) is _ActionScratchScope and scope.clock is clock, "scratch-copy-state")
        scope.check()
        super().__init__(clock)
        self.scope = scope

    def sync(self, target):
        # Current kernel bytes are read back completely before acceptance.
        # Only this exact ephemeral path omits per-leaf power-loss persistence;
        # mode/name/FD/SHA/NAR/current/final/cleanup predicates stay unchanged.
        self.scope.worker_tick()


def _copy_regular_job(state, parent, leaf, parent_witness, payload, entry):
    """Borrow the owner's parent/payload; own and close only this target FD."""
    target = None
    try:
        state.tick()
        need(identity(os.fstat(parent), True) == parent_witness, "copy-worker-parent")
        target = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        initial = os.fstat(target)
        need(stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid()
             and initial.st_nlink == 1 and stat.S_IMODE(initial.st_mode) == 0o600
             and identity(initial) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
             "copy-worker-created-name")
        part = Range(payload, entry["offset"], entry["size"], state)
        h = hashlib.sha256()
        while True:
            block = part.read(65536)
            state.tick()
            if not block:
                break
            h.update(block)
            write_all(target, block, state)
        need(part.position == entry["size"] and h.hexdigest() == entry["sha256"], "extracted-file-digest")
        state.tick()
        state.sync(target)
        state.tick()
        os.fchmod(target, entry["mode"])
        state.tick()
        final = os.fstat(target)
        selected = identity(final)
        need(stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid() and final.st_nlink == 1
             and final.st_size == entry["size"] and stat.S_IMODE(final.st_mode) == entry["mode"]
             and selected == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
             and identity(os.fstat(parent), True) == parent_witness, "extracted-file-name")
        state.tick()
        return selected, part.position
    except BaseException as error:
        state.fail(error)
        raise
    finally:
        if target is not None:
            try:
                os.close(target)
            except BaseException as error:
                state.fail(error)
                raise


def _copy_worker(state, jobs, results, gate, ready, stop):
    """FD-free bootstrap: no job is dispatched until BOTH starts are admitted."""
    try:
        ready.set()
        while not gate.wait(0.05):
            if stop.is_set() or state.cancel.is_set():
                return
            state.tick()
        while not stop.is_set() and not state.cancel.is_set():
            state.tick()
            try:
                number, arguments = jobs.get(timeout=0.05)
            except Empty:
                continue
            state.tick()
            selected, count = _copy_regular_job(state, *arguments)
            state.tick()
            # There are never more than two dispatched/unaccepted jobs, even
            # when the owner refuses before draining their factual results.
            results.put_nowait((number, selected, count))
    except BaseException as error:
        state.fail(error)


def _copy_regulars(output, payload, payload_witness, files, clock, on_copied, *, _scratch_scope=None):
    """Two jobs/leases maximum; physical authority stays on the original owner."""
    if _scratch_scope is not None:
        need(type(_scratch_scope) is _ActionScratchScope and output.root.owned, "scratch-owned-copy")
        _scratch_scope.join(_scratch_scope.held, output.path, clock)
    state = _CopyState(clock) if _scratch_scope is None else _ActionScratchCopyState(clock, _scratch_scope)
    jobs, results = Queue(maxsize=2), Queue(maxsize=2)
    gate, stop = threading.Event(), threading.Event()
    ready = (threading.Event(), threading.Event())
    # Record every Thread object BEFORE start, with no borrowed FD, Root or
    # writer state in its bootstrap arguments. There is no later thread creation.
    workers = tuple(threading.Thread(target=_copy_worker,
                    args=(state, jobs, results, gate, event, stop),
                    name="sdk-copy-" + str(index), daemon=False)
                    for index, event in enumerate(ready))
    attempted, started, pending, leases, completed = [], [], [], {}, {}
    entries, exhausted, sequence = iter(files.items()), False, 0
    with _ParentHandles(output.root) as parents:
        try:
            state.owner_tick()
            for worker in workers:
                attempted.append(worker)
                worker.start()
                started.append(worker)
            for event in ready:
                while not event.wait(0.05):
                    state.owner_tick()
                state.owner_tick()
            # No physical capability was queued until BOTH start calls returned
            # successfully and BOTH FD-free workers reported ready.
            gate.set()
            while pending or not exhausted:
                state.owner_tick()
                while len(pending) < 2 and not exhausted:
                    state.owner_tick()
                    try:
                        (role, path), entry = next(entries)
                    except StopIteration:
                        exhausted = True
                        break
                    name = role + "/" + path
                    parent, leaf = parents.parent(name)
                    sequence += 1
                    # Register the owner lease before the queue operation, so
                    # even interruption AFTER enqueue still joins before close.
                    leases[sequence] = parent
                    selected_parent = identity(os.fstat(parent), True)
                    pending.append((sequence, name, leaf, selected_parent, entry))
                    state.owner_tick()
                    jobs.put_nowait((sequence, (parent, leaf, selected_parent, payload, entry)))
                if not pending:
                    continue
                number, name, leaf, parent_witness, entry = pending[0]
                while number not in completed:
                    state.owner_tick()
                    try:
                        result_number, selected, count = results.get(timeout=0.05)
                    except Empty:
                        continue
                    need(result_number in leases and result_number not in completed,
                         "copy-result-membership")
                    completed[result_number] = selected, count
                    need(len(completed) <= 2, "copy-result-bound")
                selected, count = completed.pop(number)
                state.owner_tick()
                parent = leases[number]
                current, current_leaf = parents.parent(name)
                try:
                    need(current_leaf == leaf
                         and identity(os.fstat(parent), True) == parent_witness
                         and identity(os.fstat(current), True) == parent_witness
                         and identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == selected
                         and identity(os.stat(current_leaf, dir_fd=current, follow_symlinks=False)) == selected,
                         "copy-owner-current-name")
                finally:
                    os.close(current)
                need(count == entry["size"] and identity(os.fstat(payload)) == payload_witness,
                     "copy-owner-payload")
                output.root.check()
                state.owner_tick()
                on_copied(name, selected, count)
                # Detach before close: never retry a possibly reused FD.
                os.close(leases.pop(number))
                pending.pop(0)
        except BaseException as error:
            state.fail(error)
        finally:
            stop.set()
            gate.set()
            for worker in attempted:
                while True:
                    try:
                        worker.join()
                        need(not worker.is_alive(), "copy-worker-join")
                        break
                    except RuntimeError as error:
                        if worker not in started:
                            # Thread.start may be interrupted between OS launch
                            # and its started event. Missing readiness/ident or a
                            # join refusal is NOT proof of nonstart. No jobs/FDs
                            # were admitted in this outcome; any late bootstrap
                            # sees stop/cancel. Refuse, with the original owned
                            # outer guard the ultimate unknown-start cleanup.
                            need(not leases, "copy-unadmitted-capabilities")
                            state.fail(error)
                            with state.lock:
                                state.error.add_note("copy-worker-start-outcome-unknown")
                            break
                        state.fail(error)
                    except BaseException as error:
                        # Blocked fsync is not clock-interruptible. Keep leases
                        # until actual joins; unchanged outer guard is ultimate.
                        state.fail(error)
            closing, leases = tuple(leases.values()), {}
            for parent in closing:
                try:
                    os.close(parent)
                except BaseException as error:
                    state.fail(error)
        state.owner_tick()
        if _scratch_scope is not None: _scratch_scope.join(_scratch_scope.held, output.path, clock)


def extract(carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline, *, on_bound=None, _held_carrier=None):
    return _extract(carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline,
                    on_bound=on_bound, _held_carrier=_held_carrier)


def extract_action_scratch(carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline, *, _held_carrier, consumer_context):
    scope = _ActionScratchScope(_held_carrier, carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline, consumer_context)
    return _extract(carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline,
                    _held_carrier=_held_carrier, _scratch_scope=scope)


def _extract(carrier_dir, pinned_carrier_receipt_sha256, output_dir, absolute_deadline, *, on_bound=None, _held_carrier=None, _scratch_scope=None):
    """Authenticate then extract on one held owner; callback grants no proof token.

    A scoped result remains provisional until its owner completes full_final
    and the consumer performs its last complete fresh output proof afterward.
    """
    need(on_bound is None or callable(on_bound), "bound-callback")
    clock = _carrier_clock(_held_carrier, carrier_dir, pinned_carrier_receipt_sha256, absolute_deadline)
    if _scratch_scope is not None:
        need(type(_scratch_scope) is _ActionScratchScope and on_bound is None, "scratch-closed-extraction")
        _scratch_scope.join(_held_carrier, output_dir, clock)
    if _held_carrier is not None:
        need(_held_carrier._extracted is None and not _held_carrier._final, "held-carrier-one-extraction")
    # Diagnostic time and counters never participate in a proof allowance.
    started_ns, copied_files, copied_bytes, created_directories = time.monotonic_ns(), 0, 0, 0
    phases = ("initial-start", "initial-bound", "directories-start", "directories-ready", "directories-refused",
              "copy-complete", "copy-refused", "links-start", "links-complete", "seal-start", "seal-complete",
              "final-proof-start", "inventory-check-start", "inventory-check-complete",
              "carrier-readback-start", "carrier-readback-complete", "content-readback-start", "content-readback-complete",
              "publication-start", "publication-complete", "published-content-start", "published-content-complete",
              "final-proof-complete")
    events = 0
    def progress(phase):
        nonlocal events
        need(phase in phases and events < len(phases), "extraction-diagnostic-bound")
        events += 1
        print("sdk-carrier-extract: " + phase
              + " elapsed_ns=" + str(max(0, time.monotonic_ns() - started_ns))
              + " copied_files=" + str(copied_files) + " copied_bytes=" + str(copied_bytes)
              + " created_directories=" + str(created_directories),
              file=sys.stderr, flush=True)
    progress("initial-start")
    print("sdk-carrier-budget: extraction-entry remaining_ns=" + str(_remaining_original_ns(clock)),
          file=sys.stderr, flush=True)
    with _ProofExitStack() as stack:
        carrier = stack.enter_context(Root(carrier_dir, clock)) if _held_carrier is None else _held_carrier._owner
        if _held_carrier is not None:
            stack.callback(_held_carrier.check)
        report, manifest, rows, files = _carrier_binding(_held_carrier, carrier, pinned_carrier_receipt_sha256, clock)
        progress("initial-bound")
        if on_bound is not None:
            on_bound(report if _held_carrier is None else decode(encoded(report)))
            # Dependent SOURCE IO does not renew the proof or its deadline.
            # Join held ancestry and all named carrier leaves before output.
            carrier.check()
            if _held_carrier is not None:
                _held_carrier.check()
        output = Output(output_dir, clock)
        stack.callback(output.close)
        progress("directories-start")
        try:
            for role in ("sdk", "jdk"):
                output.mkdir(role)
                created_directories += 1
        except BaseException:
            progress("directories-refused")
            raise
        payload, witness = carrier.open("payload.bin")
        try:
            # All parent directories first; no links exist during writes.
            try:
                with _ParentHandles(output.root) as directory_parents:
                    for role, path in sorted(rows, key=lambda key: (len(relative(key[1], empty=True)), key)):
                        clock.tick()
                        if path and rows[(role, path)]["kind"] == "directory":
                            output.mkdir(role + "/" + path, parent_handles=directory_parents)
                            created_directories += 1
            except BaseException:
                progress("directories-refused")
                raise
            progress("directories-ready")
            copy_complete = False
            try:
                def copied(name, selected, count):
                    nonlocal copied_files, copied_bytes
                    output.materialized[name] = selected
                    copied_files += 1
                    copied_bytes += count
                if _scratch_scope is None:
                    _copy_regulars(output, payload, witness, files, clock, copied)
                else:
                    _copy_regulars(output, payload, witness, files, clock, copied, _scratch_scope=_scratch_scope)
                copy_complete = True
            finally:
                progress("copy-complete" if copy_complete else "copy-refused")
            progress("links-start")
            # Literal targets remain inert, including the original absolute JDK.
            for (role, path), row in rows.items():
                if row["kind"] == "symlink":
                    clock.tick()
                    fd, leaf = output.root.parent(role + "/" + path)
                    try:
                        os.symlink(row["target"], leaf, dir_fd=fd)
                        selected = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                        need(stat.S_ISLNK(selected.st_mode) and os.readlink(leaf, dir_fd=fd) == row["target"],
                             "created-link-name")
                        output.materialized[role + "/" + path] = identity(selected)
                    finally:
                        os.close(fd)
            need(identity(os.fstat(payload)) == witness, "payload-extraction-race")
            progress("links-complete")
        finally:
            os.close(payload)
        progress("seal-start")
        for role, path in sorted(rows, key=lambda key: (-len(relative(key[1], empty=True)), key)):
            if rows[(role, path)]["kind"] == "directory":
                clock.tick()
                output.seal_directory(role + ("/" + path if path else ""))
        progress("seal-complete")
        progress("final-proof-start")
        fresh = {role: stack.enter_context(Root(output.path / role, clock)) for role in ("sdk", "jdk")}
        if _held_carrier is None:
            observed, witnesses = scan(fresh, rows, clock)
            fresh_nars = None
        else:
            observed, witnesses, fresh_nars = _scan_nar(fresh, rows, clock)
        progress("inventory-check-start")
        for (role, path), value in witnesses.items():
            clock.tick()
            name = role + ("/" + path if path else "")
            if rows[(role, path)]["kind"] == "directory":
                need(value[:5] == output.root.named[name], "created-directory-identity")
            else:
                need(value == output.materialized[name], "created-member-identity")
        if _held_carrier is None:
            need(observed == rows and nar_origins(fresh, rows, clock) == manifest["nars"], "extracted-full-proof")
        else:
            need(observed == rows and fresh_nars == manifest["nars"], "extracted-full-proof")
        progress("inventory-check-complete")
        # Default calls fully reauthenticate; scoped calls keep this fence
        # provisional until the owner's mandatory full_final and fresh proof.
        # Neither path reads the old SDK/JDK.
        progress("carrier-readback-start")
        need(_carrier_binding(_held_carrier, carrier, pinned_carrier_receipt_sha256, clock)[0] == report, "carrier-final-proof")
        progress("carrier-readback-complete")
        progress("content-readback-start")
        after, after_witnesses = scan(fresh, rows, clock)
        need(after == observed and after_witnesses == witnesses, "extracted-final-custody")
        progress("content-readback-complete")
        progress("publication-start")
        receipt = {"kind": EXTRACTED if _scratch_scope is None else SCRATCH_EXTRACTED, "carrier_receipt_sha256": digest(pinned_carrier_receipt_sha256),
                   "producer_context": report["producer_context"],
                   "origin_receipt_sha256": report["origin"]["receipt_sha256"],
                   "manifest_sha256": report["manifest_sha256"], "payload_sha256": report["payload_sha256"],
                   "nars": manifest["nars"], "fresh_custody": {role: {"root": str(root.path),
                       "root_identity": root.chain[-1][2], "members_sha256": sha(encoded([
                       [name, value] for (selected, name), value in sorted(witnesses.items()) if selected == role]))}
                       for role, root in fresh.items()}, "extracted_inventory_rechecked": True,
                   "original_inodes_reused": False, "absolute_links_materialized_as_mounts": False,
                   "sdk_execution_qualified": False, "metadata_qualified": False,
                   "source_witnesses_replaced": False}
        if _scratch_scope is not None: receipt.update(_scratch_scope.record())
        output.file("extraction-receipt.json", encoded(receipt))
        for root in fresh.values():
            root.check()
        output.finish()
        need(read(output.root, "extraction-receipt.json", 65536, sha(encoded(receipt))) == encoded(receipt),
             "published-extraction-receipt")
        progress("publication-complete")
        progress("published-content-start")
        # The owned output parent has deliberately changed700→555. Reopen and
        # join its final namespace while preserving all fresh member identities.
        with ExitStack() as final_stack:
            final_roots = {role: final_stack.enter_context(Root(output.path / role, clock))
                           for role in ("sdk", "jdk")}
            final_rows, final_witnesses = scan(final_roots, rows, clock)
            need(final_rows == observed and final_witnesses == witnesses, "publication-extracted-custody")
        progress("published-content-complete")
        output.root.check()
        carrier.check()
        if _held_carrier is not None:
            _held_carrier._complete_extract(output_dir, receipt)
        if _scratch_scope is not None: _scratch_scope.join(_held_carrier, output_dir, clock)
        progress("final-proof-complete")
        return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("seal", "preflight", "extract"), default="seal")
    parser.add_argument("--origin-root")
    parser.add_argument("--origin-receipt-sha256")
    parser.add_argument("--carrier-dir")
    parser.add_argument("--carrier-receipt-sha256")
    parser.add_argument("--output-dir")
    parser.add_argument("--entry-monotonic-ns", type=int, required=True)
    parser.add_argument("--deadline-monotonic-ns", type=int, required=True)
    parser.add_argument("--epoch")
    parser.add_argument("--source-commit")
    parser.add_argument("--graph-sha256")
    args = parser.parse_args()
    need(args.deadline_monotonic_ns - args.entry_monotonic_ns == 1200 * 10**9, "CLI-original-envelope")
    deadline = (args.entry_monotonic_ns + 1170 * 10**9) / 10**9
    Clock(deadline).tick()
    if args.phase == "preflight":
        need(args.origin_root is not None and args.origin_receipt_sha256 is not None
             and args.output_dir is None and args.carrier_dir is None and args.carrier_receipt_sha256 is None, "preflight-arguments")
        result = preflight(args.origin_root, args.origin_receipt_sha256, deadline)
    else:
        need(args.output_dir is not None, "output-argument")
        if args.phase == "seal":
            need(args.origin_root is not None and args.origin_receipt_sha256 is not None
                 and args.carrier_dir is None and args.carrier_receipt_sha256 is None, "seal-arguments")
            context = {"mode": "native-sdk-carrier-seal-reserved", "epoch": args.epoch,
                       "source_commit": args.source_commit, "graph_sha256": args.graph_sha256,
                       "entry_monotonic_ns": args.entry_monotonic_ns,
                       "deadline_monotonic_ns": args.deadline_monotonic_ns,
                       "work_cutoff_monotonic_ns": args.entry_monotonic_ns + 1170 * 10**9}
            result = seal(args.origin_root, args.origin_receipt_sha256, args.output_dir, deadline,
                          producer_context=context)
            result = publication_report(args.output_dir, sha(encoded(result)), deadline)
        else:
            need(args.carrier_dir is not None and args.carrier_receipt_sha256 is not None
                 and args.origin_root is None and args.origin_receipt_sha256 is None, "extract-arguments")
            result = extract(args.carrier_dir, args.carrier_receipt_sha256, args.output_dir, deadline)
            result = {"kind": EXTRACTED + "-publication", "receipt_sha256": sha(encoded(result)),
                      "carrier_receipt_sha256": result["carrier_receipt_sha256"]}
    print(encoded(result).decode("ascii"), flush=True)


if __name__ == "__main__":
    main()
