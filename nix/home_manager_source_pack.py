"""Finite acquired-pair byte transport; metadata supplies no qualification."""
import hashlib
import json
import os
import re
import stat
import struct
import sys

import home_manager_acquired_inputs as acquired

MAGIC = b"OMUX-ACQUIRED-HM-PAIR\x00v1\n"
KIND = "omux-acquired-home-manager-source-pack-v1"
SELECT = "omux-acquired-home-manager-source-pack-selection-v1"
KIND_V2 = "omux-acquired-home-manager-source-pack-v2"
SELECT_V2 = "omux-acquired-home-manager-source-pack-selection-v2"
MAX_BYTES = acquired.MAX_FILE_BYTES  # existing private per-file bound, never widened
STATE = "/home/jess/.local/state/omux-home-manager-prefetch-20261006"
TARGET = "//tools:home_manager_acquisition_producer"
SHA = re.compile("[0-9a-f]{64}")
FIELDS = ("schemaVersion", "kind", "packSha256", "packBytes", "pairReceiptSha256", "pairInventorySha256")


def require(value, reason):
    acquired.require(value, "source-pack-" + reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def metadata(raw):
    value = acquired.decode(raw, 65536)
    v2 = value.get("kind") == KIND_V2
    acquired.fields(value, FIELDS + (("transport",) if v2 else ()))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == (2 if v2 else 1)
        and value["kind"] == (KIND_V2 if v2 else KIND)
        and (not v2 or value["transport"] == "packed-only-v2") and type(value["packBytes"]) is int
        and 0 < value["packBytes"] <= MAX_BYTES
        and all(type(value[key]) is str and SHA.fullmatch(value[key]) for key in
            ("packSha256", "pairReceiptSha256", "pairInventorySha256")), "metadata")
    return value


def selection(raw):
    value = acquired.decode(raw, 65536)
    acquired.fields(value, ("schemaVersion", "kind", "selection"))
    v2 = value["kind"] == SELECT_V2
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == (2 if v2 else 1)
        and value["kind"] == (SELECT_V2 if v2 else SELECT), "selection")
    row = value["selection"]
    require(row is not None, "selection-pending")
    acquired.fields(row, ("root", "packSha256", "packBytes", "metadataSha256", "producer")
                    + (("transport",) if v2 else ()))
    require(not v2 or row["transport"] == "packed-only-v2", "selection-transport")
    require(type(row["packBytes"]) is int and 0 < row["packBytes"] <= MAX_BYTES
        and all(type(row[key]) is str and SHA.fullmatch(row[key]) for key in
            ("packSha256", "metadataSha256")), "selection-digest")
    p = row["producer"]
    acquired.fields(p, ("receipt", "sha256", "source_commit", "source_dirty", "graph_sha256"))
    require(type(p["source_commit"]) is str and re.fullmatch("[0-9a-f]{40}", p["source_commit"])
        and p["source_dirty"] == "false"
        and all(type(p[key]) is str and SHA.fullmatch(p[key]) for key in ("sha256", "graph_sha256")),
        "selection-producer")
    root = acquired.physical_path(row["root"])
    prefix = STATE + "/"
    require(root.startswith(prefix), "selection-state")
    parts = root[len(prefix):].split("/")
    require(len(parts) == 11 and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", parts[0])
        and parts[1:5] == ["output-base", "execroot", "_main", "bazel-out"]
        and re.fullmatch("[A-Za-z0-9_.-]+", parts[5])
        and parts[6:] == ["testlogs", "tools", "home_manager_acquisition_producer", "test.outputs", "home-manager-pair"]
        and p["receipt"] == STATE + "/" + parts[0] + "/receipt.json", "selection-namespace")
    return row


def regular_entries(inventory):
    for name in acquired.NAMES:
        for node in sorted(inventory["sources"][name]["nodes"], key=lambda n: os.fsencode(n["path"])):
            if node["type"] == "regular":
                yield name, node


def register_source(sources, name, fd):
    # The caller owns fd until this enrollment returns successfully.
    sources.append((name, fd, None))


def write(staging_fd, raw_pair, raw_inventory, deadline, *, anchor, charge, sync=os.fsync,
          transport="physical-forest-v1"):
    """Read held real source files once; the owner retains its full NAR proofs."""
    require(transport in ("physical-forest-v1", "packed-only-v2"), "transport")
    require(type(raw_pair) is bytes and 0 < len(raw_pair) <= acquired.MAX_RECEIPT_BYTES
        and type(raw_inventory) is bytes and 0 < len(raw_inventory) <= acquired.MAX_INVENTORY_BYTES, "header-bound")
    inventory = acquired.decode(raw_inventory, acquired.MAX_INVENTORY_BYTES)
    acquired.fields(inventory, ("schemaVersion", "sources"))
    acquired.fields(inventory["sources"], acquired.NAMES)
    require(type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1, "inventory")
    sources, output, total = [], None, 0
    digest = hashlib.sha256()
    def fence():
        acquired.check_deadline(deadline)
        anchor()
        # Anchor checks and scans can block. Their original deadline must be
        # checked again before permitting the next actual filesystem effect.
        acquired.check_deadline(deadline)
    try:
        for name in acquired.NAMES:
            acquired.fields(inventory["sources"][name], ("nodes",))
            fence()
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=staging_fd)
            try:
                register_source(sources, name, fd)
            except BaseException:
                primary = sys.exc_info()[1]
                try: os.close(fd)
                except BaseException: primary.cleanup_category = "source-pack-close-refused"
                raise
            nodes, facts = acquired.scan(fd, deadline)
            fence()
            require(nodes == inventory["sources"][name]["nodes"], "source-inventory")
            sources[-1] = (name, fd, (nodes, facts))
        fence()
        output = os.open("source.pack", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=staging_fd)
        def emit(data):
            nonlocal total
            fence()
            total += len(data); require(total <= MAX_BYTES, "byte-bound")
            digest.update(data)
            view = memoryview(data)
            while view:
                fence()
                count = os.write(output, view); require(count > 0, "short-write"); view = view[count:]
            charge(os.fstat(output)); fence()
        emit(MAGIC)
        for raw in (raw_pair, raw_inventory):
            emit(struct.pack("<Q", len(raw)))
            for start in range(0, len(raw), 65536): emit(raw[start:start+65536])
        by_name = {name: (fd, capture) for name, fd, capture in sources}
        for name, node in regular_entries(inventory):
            fd, capture = by_name[name]
            fence()
            with acquired.regular_stream(fd, node["path"], capture[1], deadline) as incoming:
                remaining = node["size"]
                while remaining:
                    data = incoming.read(min(65536, remaining)); require(data, "truncated")
                    remaining -= len(data); emit(data)
                require(not incoming.read(1), "growth")
        for name, fd, capture in sources:
            fence()
            require(acquired.scan(fd, deadline) == capture
                and acquired.snapshot(os.stat(name, dir_fd=staging_fd, follow_symlinks=False)) == capture[1][""],
                "source-changed")
            fence()
        fence()
        os.fchmod(output, 0o444)
        fence()
        sync(output)
        charge(os.fstat(output))
        fence()
        require(acquired.snapshot(os.fstat(output)) == acquired.snapshot(
            os.stat("source.pack", dir_fd=staging_fd, follow_symlinks=False)), "output-changed")
        fence()
        result = {"schemaVersion": 1, "kind": KIND, "packSha256": digest.hexdigest(), "packBytes": total,
            "pairReceiptSha256": hashlib.sha256(raw_pair).hexdigest(),
            "pairInventorySha256": hashlib.sha256(raw_inventory).hexdigest()}
        if transport == "packed-only-v2":
            result.update(schemaVersion=2, kind=KIND_V2, transport=transport)
        return result
    finally:
        # Attempt every close even when one descriptor refuses.
        primary, failure = sys.exc_info()[1], None
        if output is not None:
            try: os.close(output)
            except BaseException as error: failure = failure or error
        for row in sources:
            try: os.close(row[1])
            except BaseException as error: failure = failure or error
        if failure is not None:
            if primary is not None: primary.cleanup_category = "source-pack-close-refused"
            else: raise failure


class PackedFile:
    """Original named/held regular output byte identity through publication."""
    def __init__(self, parent_fd, value, deadline):
        self.parent_fd, self.value, self.deadline, self.fd = parent_fd, value, deadline, None
        try:
            self.fd = os.open("source.pack", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd)
            self.before = acquired.snapshot(os.fstat(self.fd))
            require(stat.S_ISREG(self.before[2]) and stat.S_IMODE(self.before[2]) == 0o444
                and self.before[3] == os.getuid() and self.before[5] == 1
                and self.before[6] == value["packBytes"], "custody")
            self.recheck()
        except BaseException:
            primary = sys.exc_info()[1]
            try: self.close()
            except BaseException: primary.cleanup_category = "source-pack-close-refused"
            raise

    def recheck(self):
        require(self.fd is not None, "closed")
        digest, count = hashlib.sha256(), 0
        os.lseek(self.fd, 0, os.SEEK_SET)
        while True:
            acquired.check_deadline(self.deadline)
            data = os.read(self.fd, 65536)
            if not data: break
            count += len(data); require(count <= self.value["packBytes"], "growth"); digest.update(data)
        acquired.check_deadline(self.deadline)
        require(count == self.value["packBytes"] and digest.hexdigest() == self.value["packSha256"]
            and self.before == acquired.snapshot(os.fstat(self.fd))
            == acquired.snapshot(os.stat("source.pack", dir_fd=self.parent_fd, follow_symlinks=False)),
            "readback")
        acquired.check_deadline(self.deadline)

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None; os.close(fd)


class ReboundFrame:
    """Insert the current action header; source frame has no execution binding."""
    def __init__(self, stream, check, raw_pair, raw_inventory, raw_binding, current_magic):
        self.stream, self.check = stream, check
        self.pending = current_magic + b"".join(struct.pack("<Q", len(raw)) + raw
            for raw in (raw_pair, raw_inventory, raw_binding))

    def read(self, amount):
        require(type(amount) is int and 0 < amount <= 65536, "read-bound")
        self.check()
        part, self.pending = self.pending[:amount], self.pending[amount:]
        if len(part) < amount and not self.pending:
            part += self.stream.read(amount-len(part))
        self.check(); return part

    def close(self):
        self.pending = b""
