"""Offline finite union of a retained plan, up to 32 shards and tool bundle.

This exports verified bytes only. It neither reads ambient caches nor supplies
Bazel canonical-ID metadata, Git materialization, repository analysis or SDK proof.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from codex_dependency_bundle import (
    Budget, COMMON, HASH, MAX_BYTES, MAX_FILE, MAX_METADATA, MAX_OBJECTS, MAX_ROWS,
    ROOTS, SOURCE_RECEIPT, SOURCE_RECEIPT_SHA, SUFFIX, authority, inventory,
    encoded, load_bundle, payload_fd, require,
    retained_location, row_checked, selected_shard, stream_object, verify_plan_authority,
)
from codex_sdk_profile import ARCHIVE_MANIFEST_SHA, hash_regular, trusted_parent, validate_source
from fetch_codex_archives import ARCHIVES
from restore_pristine_inputs import unique_object

PLAN_ROOT = ROOTS[0] / ("cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee/"
    + SUFFIX + "codex_dependency_bundle_plan/test.outputs/codex-dependency-bundle")
PLAN_SHA = "c6613a0e4d9b0c952a91a9bf03e2010ce02a680c45eec6c84a1df7030d31ce6b"
ACTIVE_PLAN_ROOT = ROOTS[0] / ("440b3f59-05da-42cc-a345-4caff371f768/" + SUFFIX
    + "codex_dependency_bundle_plan/test.outputs/codex-dependency-bundle")
ACTIVE_PLAN_SHA = "e2062afb5cda472861c0e5a442312424252554c8a7fba6baf8f1725609bfdb66"
SHARD_ROOT = ROOTS[1] / ("0ebaff4d-0225-49d7-aa4a-fc78df70db79/" + SUFFIX
    + "codex_dependency_bundle_producer/test.outputs/codex-dependency-bundle")
SHARD_SHA = "c2bd6aa1a8e350c891e9a16f3c7006ccf1e6d22e4394f8885d7906020c291009"
TOOLS_ROOT = ROOTS[1] / ("052fde9c-7e07-490f-a940-fb11820f1d31/" + SUFFIX
    + "fetch_codex_archives_bundle/test.outputs/bundle")
TOOLS_SHA = "1d3d34323a3e19fd7e640146bf0eba006881a9bdd2d376a0493153f4cd8d30a0"
DISK_BYTES = 8 * 1024 * 1024 * 1024
FREE_FLOOR = 4 * 1024 * 1024 * 1024
MAX_SHARDS = 32


class OutputCustody:
    """Hold the complete ancestor chain; mutate only through held directory FDs.

    A rename can invalidate publication, but cannot redirect a write into the
    replacement namespace. Every created directory remains witnessed until close.
    """
    def __init__(self, output, budget=None):
        output = Path(output)
        require(output.is_absolute() and ".." not in output.parts
                and len(output.parts) <= 256, "output path differs")
        self.fds, self.directories, self.files = [], [], []
        self.budget = budget if budget is not None else Budget()
        self.root_path = output / "codex-sdk-dependency-union"
        try:
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(parent)
            self._directory_safe(os.fstat(parent), False)
            for name in output.parts[1:]:
                self.check()
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
                self.fds.append(child)
                witness = os.fstat(child)
                self._directory_safe(witness, False)
                self.directories.append((parent, name, child, witness, False))
                self.check()
                parent = child
            self.output_fd = parent
            self._directory_safe(os.fstat(parent), True)
            require(not os.listdir(parent), "union output must be empty")
            self.root_fd = self.mkdir(parent, "codex-sdk-dependency-union")
            content = self.mkdir(self.root_fd, "content_addressable")
            self.cas_fd = self.mkdir(content, "sha256")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _directory_safe(info, owned):
        require(stat.S_ISDIR(info.st_mode)
                and (info.st_uid == os.getuid() if owned else info.st_uid in (0, os.getuid()))
                and (not info.st_mode & 0o022 or (not owned and info.st_mode & stat.S_ISVTX)),
                "output directory custody differs")

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_mode & 0o7777

    @staticmethod
    def _file_state(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def check(self):
        self.budget.tick()
        for parent, name, child, witness, owned in self.directories:
            self.budget.tick()
            held = os.fstat(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._directory_safe(held, owned)
            require(self._identity(held) == self._identity(witness) == self._identity(named),
                    "output ancestor or directory substituted")
        if hasattr(self, "output_fd"):
            self._directory_safe(os.fstat(self.output_fd), True)
        for parent, name, witness in self.files:
            self.budget.tick()
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(self._file_state(named) == self._file_state(witness),
                    "output file substituted")

    def mkdir(self, parent, name):
        self.check()
        os.mkdir(name, mode=0o700, dir_fd=parent)
        created = os.stat(name, dir_fd=parent, follow_symlinks=False)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        self.fds.append(child)
        witness = os.fstat(child)
        self._directory_safe(witness, True)
        require(self._identity(created) == self._identity(witness)
                and witness.st_mode & 0o777 == 0o700 and not os.listdir(child),
                "output directory creation or mode differs")
        self.directories.append((parent, name, child, witness, True))
        self.check()
        return child

    def disk_check(self):
        self.check()
        # Use the held filesystem and closed owned inventory, never a lexical walk.
        used = sum(os.fstat(fd).st_blocks * 512 for fd in self.fds)
        used += sum(os.stat(name, dir_fd=parent, follow_symlinks=False).st_blocks * 512
                    for parent, name, _ in self.files)
        space = os.fstatvfs(self.root_fd)
        require(used <= DISK_BYTES and space.f_bavail * space.f_frsize >= FREE_FLOOR,
                "union disk budget or free floor differs")

    def _create_file(self, parent, name):
        self.check()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o400, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and info.st_mode & 0o777 == 0o400,
                    "output file custody differs")
            self._active_check(parent, name, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _active_check(self, parent, name, fd):
        self.check()
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(self._file_state(held) == self._file_state(named)
                and held.st_nlink == 1 and held.st_mode & 0o777 == 0o400,
                "output active file substituted")

    def _write(self, parent, name, fd, value):
        view = memoryview(value)
        while view:
            self._active_check(parent, name, fd)
            written = os.write(fd, view)
            require(written > 0, "payload write made no progress")
            view = view[written:]
        self._active_check(parent, name, fd)

    def _seal(self, parent, name, fd):
        self._active_check(parent, name, fd)
        os.fsync(fd)
        self._active_check(parent, name, fd)
        self.files.append((parent, name, os.fstat(fd)))
        os.fsync(parent)
        self.check()

    def copy(self, source, digest, budget):
        require(HASH.fullmatch(digest), "invalid selected digest")
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 <= before.st_size <= MAX_FILE,
                "selected payload custody/type/size differs")
        require(budget.export_bytes + before.st_size <= MAX_BYTES, "bundle export budget exceeded")
        parent = self.mkdir(self.cas_fd, digest)
        fd = self._create_file(parent, "file")
        try:
            size, checksum = 0, hashlib.sha256()
            while chunk := os.read(source, 1024 * 1024):
                budget.tick(len(chunk))
                size += len(chunk)
                require(size <= MAX_FILE and budget.export_bytes + size <= MAX_BYTES,
                        "selected payload grew beyond export bound")
                checksum.update(chunk)
                self._write(parent, "file", fd, chunk)
            after = os.fstat(source)
            require(self._file_state(before) == self._file_state(after)
                    and size == before.st_size and checksum.hexdigest() == digest,
                    "selected payload changed or digest differs")
            self._seal(parent, "file", fd)
            budget.export_bytes += size
            budget.tick()
            return size
        finally:
            os.close(fd)

    def publish(self, report):
        value = encoded(report)
        self.disk_check()
        fd = self._create_file(self.root_fd, "bundle-receipt.json")
        try:
            self._write(self.root_fd, "bundle-receipt.json", fd, value)
            self._seal(self.root_fd, "bundle-receipt.json", fd)
        finally:
            os.close(fd)
        inventory(self.root_fd, report["objects"])
        for directory in reversed(self.fds):
            self.check()
            os.fsync(directory)
        self.disk_check()
        return hashlib.sha256(value).hexdigest()

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def read_tools(root_fd, receipt_sha, budget, archives=ARCHIVES, manifest_sha=ARCHIVE_MANIFEST_SHA, *, on_read=None):
    actual, _, value = hash_regular(root_fd, "receipt.json", MAX_METADATA, True, on_read=on_read)
    require(actual == receipt_sha and HASH.fullmatch(receipt_sha), "tool receipt digest differs")
    report = json.loads(value, object_pairs_hook=unique_object)
    require(report.get("status") == "complete-verified-distdir"
            and report.get("manifest_sha256") == manifest_sha and report.get("missing") == []
            and report.get("native_support") is False and report.get("native_proof") is False,
            "tool bundle authority differs")
    rows = report.get("verified")
    require(isinstance(rows, list) and len(rows) == len(archives), "tool archive count differs")
    require(all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in rows),
            "tool archive record differs")
    selected = {row["name"]: row for row in rows}
    names = {name for name, _, _ in archives}
    require(len(selected) == len(rows) and set(selected) == names
            and set(os.listdir(root_fd)) == names | {"receipt.json"}, "tool bundle closed inventory differs")
    objects = {}
    total = 0
    for name, expected, _ in archives:
        row = selected[name]
        require(row.get("sha256") == expected and row.get("status") == "verified-export"
                and type(row.get("bytes")) is int and 0 <= row["bytes"] <= MAX_FILE,
                "tool object record differs")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        try:
            size, _ = stream_object(fd, expected, budget)
        finally:
            os.close(fd)
        require(size == row["bytes"], "tool object length differs")
        require(expected not in objects, "tool digest identities differ")
        objects[expected] = {"bytes": size, "name": name}
        total += size
        require(total <= MAX_BYTES, "tool bundle exceeds retained budget")
    return objects


def verify_shard(plan, shard, plan_sha, index=0, size=16):
    """A receipt does not select its own slice; independently supplied pins do."""
    selected = selected_shard(plan, index, size)
    require(shard.get("parent_plan_sha256") == plan_sha
            and shard.get("source_inventory_sha256") == plan.get("source_inventory_sha256")
            and type(shard.get("shard_index")) is int and shard["shard_index"] == index
            and type(shard.get("shard_size")) is int and shard["shard_size"] == size
            and shard.get("descriptors") == selected
            and set(shard["objects"]) == {row["sha256"] for row in selected}
            and type(shard.get("remaining_missing_objects")) is int
            and shard["remaining_missing_objects"] == len(plan["missing"]) - len(selected)
            and shard.get("canonical_id_metadata_exported") is False
            and shard.get("unresolved") == plan.get("unresolved"), "shard selection or authority differs")


def shard_bindings(args):
    """Preserve the exact first16; every additional shard is explicitly pinned."""
    extra = args.input_shard
    require(isinstance(extra, list) and len(extra) < MAX_SHARDS, "union shard count exceeds bound")
    bindings = [(SHARD_ROOT, SHARD_SHA, 0, 16)]
    roots, digests, slices = {SHARD_ROOT}, {SHARD_SHA, PLAN_SHA, TOOLS_SHA}, {(0, 16)}
    for entry in extra:
        require(isinstance(entry, (list, tuple)) and len(entry) == 4
                and all(isinstance(value, str) for value in entry), "shard binding shape differs")
        path, digest, index, size = entry
        require(re.fullmatch(r"0|[1-9][0-9]{0,4}", index)
                and re.fullmatch(r"[1-9][0-9]?", size), "shard selection spelling differs")
        root, index, size = Path(path), int(index), int(size)
        retained_location(root, "producer")
        require(str(root) == path and HASH.fullmatch(digest) and digest != "0" * 64
                and 0 <= index < MAX_ROWS and 1 <= size <= 64,
                "shard binding authority differs")
        require(root not in roots and digest not in digests and (index, size) not in slices,
                "duplicate shard root, receipt or selection")
        roots.add(root)
        digests.add(digest)
        slices.add((index, size))
        bindings.append((root, digest, index, size))
    return bindings


def parent_metadata(bindings):
    base = {"plan": PLAN_SHA, "tools": TOOLS_SHA, "tools_manifest": ARCHIVE_MANIFEST_SHA}
    if len(bindings) == 1:
        return {**base, "shard": SHARD_SHA}
    return {**base, "shards": [{"root": str(root), "receipt_sha256": digest,
                               "shard_index": index, "shard_size": size}
                              for root, digest, index, size in bindings]}


def active_selection(args):
    root, digest = getattr(args, "active_plan_root", None), getattr(args, "active_plan_sha256", None)
    shards = getattr(args, "active_shard", [])
    require(isinstance(shards, list), "active shard shape differs")
    if root is None and digest is None:
        require(not shards, "active shards require independently selected active plan")
        return None
    require((root, digest) == (ACTIVE_PLAN_ROOT, ACTIVE_PLAN_SHA), "active plan selection differs")
    return root, digest


def active_shard_bindings(args, historical):
    extra = getattr(args, "active_shard", [])
    active = active_selection(args)
    require(isinstance(extra, list) and len(historical) + len(extra) <= MAX_SHARDS,
            "union shard count exceeds bound")
    if active is None:
        return []
    # Reuse the same canonical path/digest/index/size checks without assigning
    # historical slice meanings to the active list. Its first16 overlap is
    # permitted only when the two independently sealed plan parents differ.
    candidates = []
    for entry in extra:
        require(isinstance(entry, (list, tuple)) and len(entry) == 4
                and all(isinstance(value, str) for value in entry), "active shard binding shape differs")
        path, digest, index, size = entry
        require(re.fullmatch(r"0|[1-9][0-9]{0,4}", index)
                and re.fullmatch(r"[1-9][0-9]?", size), "active shard selection spelling differs")
        root, index, size = Path(path), int(index), int(size)
        retained_location(root, "producer")
        require(str(root) == path and HASH.fullmatch(digest) and digest != "0" * 64
                and 0 <= index < MAX_ROWS and 1 <= size <= 64,
                "active shard binding authority differs")
        candidates.append((root, digest, index, size))
    combined = historical + candidates
    require(len({row[0] for row in combined}) == len(combined)
            and len({row[1] for row in combined}) == len(combined)
            and all(row[1] not in (PLAN_SHA, ACTIVE_PLAN_SHA, TOOLS_SHA) for row in candidates)
            and len({(row[2], row[3]) for row in candidates}) == len(candidates),
            "duplicate active shard root, receipt or selection")
    return candidates


def mixed_parent_metadata(historical, active):
    return {"plan": PLAN_SHA,
            "active_plan": {"root": str(ACTIVE_PLAN_ROOT), "receipt_sha256": ACTIVE_PLAN_SHA},
            "tools": TOOLS_SHA, "tools_manifest": ARCHIVE_MANIFEST_SHA,
            "shards": [{"root": str(root), "receipt_sha256": digest,
                        "parent_plan_sha256": parent, "shard_index": index, "shard_size": size}
                       for parent, rows in ((PLAN_SHA, historical), (ACTIVE_PLAN_SHA, active))
                       for root, digest, index, size in rows]}


def historical_membership(historical, active):
    """Retained c661 rows are byte provenance, never modern plan reconstruction."""
    require(historical.get("source_inventory_sha256") == active.get("source_inventory_sha256"),
            "historical and active source inventory differs")
    admitted = {json.dumps(row_checked(row), sort_keys=True) for row in active["descriptors"]}
    require(all(json.dumps(row_checked(row), sort_keys=True) in admitted
                for row in historical["descriptors"]), "historical descriptor absent from active authority")


def assemble(plan, sources, root, budget, parent_receipts):
    """Copy every selected source again; identical digest overlaps export once."""
    descriptors = plan.get("descriptors")
    require(isinstance(descriptors, list) and len(descriptors) <= MAX_ROWS, "descriptor bound differs")
    admitted = {row_checked(row)["sha256"] for row in descriptors}
    require(isinstance(sources, list)
            and 3 <= len(sources) <= MAX_SHARDS + (3 if "active_plan" in parent_receipts else 2),
            "union source count differs")
    require(all(isinstance(source, tuple) and len(source) == 4
                and isinstance(source[3], str) and HASH.fullmatch(source[3])
                and source[3] != "0" * 64 for source in sources), "union source receipt shape differs")
    require(len({source[3] for source in sources}) == len(sources), "duplicate source receipt")
    objects, origins = {}, {}
    input_count = 0
    for kind, root_fd, selected, receipt_sha in sources:
        require(kind in ("cas", "tools") and len(selected) <= MAX_OBJECTS, "union source shape differs")
        for digest, record in sorted(selected.items()):
            budget.tick()
            require(HASH.fullmatch(digest) and digest in admitted and isinstance(record, dict)
                    and type(record.get("bytes")) is int and 0 <= record["bytes"] <= MAX_FILE,
                    "union contains unselected object")
            require(digest not in objects or objects[digest]["bytes"] == record["bytes"],
                    "duplicate digest length differs")
            if kind == "tools":
                name = record.get("name")
                require(isinstance(name, str) and name not in ("", ".", "..")
                        and Path(name).name == name and not any(char in name for char in "\\\0\r\n"),
                        "tool object path differs")
            input_count += 1
            is_new = digest not in objects
            require(not is_new or len(objects) < MAX_OBJECTS, "union object count exceeds bound")
            fd = (payload_fd(root_fd, digest) if kind == "cas" else
                  os.open(record["name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd))
            try:
                root.disk_check()
                size = root.copy(fd, digest, budget) if is_new else stream_object(fd, digest, budget)[0]
            finally:
                os.close(fd)
            require(size == record["bytes"], "union source object length differs")
            objects[digest] = {"bytes": size}
            origins.setdefault(digest, []).append(receipt_sha)
            root.disk_check()
    missing = [row for row in plan["missing"] if row["sha256"] not in objects]
    require({row["sha256"] for row in missing} == admitted - set(objects),
            "union missing set differs from descriptor authority")
    unresolved = plan.get("unresolved")
    require(isinstance(unresolved, list) and len(unresolved) <= MAX_ROWS, "unresolved bound differs")
    unresolved_counts = {}
    for row in unresolved:
        require(isinstance(row, dict) and isinstance(row.get("type"), str), "unresolved record differs")
        unresolved_counts[row["type"]] = unresolved_counts.get(row["type"], 0) + 1
    missing_counts = {}
    for row in missing:
        missing_counts[row["type"]] = missing_counts.get(row["type"], 0) + 1
    return {**COMMON, "schema_version": 2 if "shards" in parent_receipts else 1,
            "status": "verified-finite-dependency-union",
            "source_inventory_sha256": plan["source_inventory_sha256"],
            "parent_receipts": parent_receipts, "objects": objects, "object_origins": origins,
            "descriptors": descriptors, "derivations": plan.get("derivations", []),
            "missing": missing, "unresolved": unresolved,
            "counts": {"input_objects": input_count, "unique_objects": len(objects),
                       "duplicate_objects": input_count - len(objects),
                       "missing_objects": len(missing), "missing_by_type": missing_counts,
                       "unresolved_rows": len(unresolved), "unresolved_by_type": unresolved_counts},
            "canonical_id_metadata_exported": False, "ambient_cache_read": False,
            "scope": "closed digest CAS union only; Git, canonical IDs and offline SDK analysis remain unproved",
            "budgets": {"read_bytes": MAX_BYTES, "retained_bytes": MAX_BYTES, "per_file_bytes": MAX_FILE,
                        "metadata_bytes": MAX_METADATA, "objects": MAX_OBJECTS,
                        "deadline_seconds": 1200, "sampled_disk_bytes": DISK_BYTES,
                        "sampled_free_floor_bytes": FREE_FLOOR,
                        "disk_enforcement": "sampling plus per-object/export bounds; no hard aggregate disk quota"}}


def input_pins(args):
    require((args.plan_root, args.plan_sha256, args.shard_root, args.shard_sha256,
             args.tools_root, args.tools_sha256) ==
            (PLAN_ROOT, PLAN_SHA, SHARD_ROOT, SHARD_SHA, TOOLS_ROOT, TOOLS_SHA),
            "finite union input selection differs")


def main(arguments=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for kind in ("plan", "shard", "tools"):
        parser.add_argument("--" + kind + "-root", type=Path, required=True)
        parser.add_argument("--" + kind + "-sha256", required=True)
    parser.add_argument("--input-shard", nargs=4, action="append", default=[],
                        metavar=("ROOT", "SHA256", "INDEX", "SIZE"))
    parser.add_argument("--active-plan-root", type=Path)
    parser.add_argument("--active-plan-sha256")
    parser.add_argument("--active-shard", nargs=4, action="append", default=[],
                        metavar=("ROOT", "SHA256", "INDEX", "SIZE"))
    args = parser.parse_args(arguments)
    input_pins(args)
    bindings = shard_bindings(args)
    active = active_selection(args)
    active_bindings = active_shard_bindings(args, bindings)
    require(os.environ.get("OMUX_EXECUTION_GUARD"), "contained union producer context required")
    budget = Budget()
    manifest, source_inventory = authority()
    plan = load_bundle(args.plan_root, args.plan_sha256, "plan", budget)
    require(plan.get("source_inventory_sha256") == source_inventory, "plan source inventory differs")
    with ExitStack() as stack:
        descriptors = []
        for path in (args.plan_root, args.tools_root):
            descriptor = trusted_parent(path)
            stack.callback(os.close, descriptor)
            descriptors.append(descriptor)
        plan_fd, tools_fd = descriptors
        actual, _, _ = hash_regular(plan_fd, "bundle-receipt.json", MAX_METADATA, False)
        require(actual == args.plan_sha256, "held plan receipt differs")
        # PLAN_SHA is the independently pinned historical authority. Today's
        # BCR derivation admits four extra archives; reconstructing c661 with
        # that parser would silently change the reviewed historical contract.
        # Modern derivation is required only for the explicit active plan.
        tools = read_tools(tools_fd, args.tools_sha256, budget)
        sources = [("cas", plan_fd, plan["objects"], args.plan_sha256)]
        selected_plan = plan
        if active is not None:
            selected_plan = load_bundle(active[0], active[1], "plan", budget)
            descriptor = trusted_parent(active[0])
            stack.callback(os.close, descriptor)
            actual, _, _ = hash_regular(descriptor, "bundle-receipt.json", MAX_METADATA, False)
            require(actual == active[1], "held active plan receipt differs")
            verify_plan_authority(selected_plan, manifest, descriptor, budget)
            historical_membership(plan, selected_plan)
            sources.append(("cas", descriptor, selected_plan["objects"], active[1]))
        for path, receipt_sha, index, size in bindings:
            shard = load_bundle(path, receipt_sha, "producer", budget)
            verify_shard(plan, shard, args.plan_sha256, index, size)
            descriptor = trusted_parent(path)
            stack.callback(os.close, descriptor)
            actual, _, _ = hash_regular(descriptor, "bundle-receipt.json", MAX_METADATA, False)
            require(actual == receipt_sha, "held shard receipt differs")
            sources.append(("cas", descriptor, shard["objects"], receipt_sha))
        for path, receipt_sha, index, size in active_bindings:
            shard = load_bundle(path, receipt_sha, "producer", budget)
            verify_shard(selected_plan, shard, active[1], index, size)
            historical_membership(shard, selected_plan)
            descriptor = trusted_parent(path)
            stack.callback(os.close, descriptor)
            actual, _, _ = hash_regular(descriptor, "bundle-receipt.json", MAX_METADATA, False)
            require(actual == receipt_sha, "held active shard receipt differs")
            sources.append(("cas", descriptor, shard["objects"], receipt_sha))
        sources.append(("tools", tools_fd, tools, args.tools_sha256))
        output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        root = OutputCustody(output, budget)
        stack.callback(root.close)
        parents = (parent_metadata(bindings) if active is None else
                   mixed_parent_metadata(bindings, active_bindings))
        report = assemble(selected_plan, sources, root, budget, parents)
        validate_source(SOURCE_RECEIPT.parent, SOURCE_RECEIPT_SHA)
        budget.tick()
        digest = root.publish(report)
    print(json.dumps({"receipt_sha256": digest, "counts": report["counts"],
                      "closure_proved": False, "offline_analysis_proved": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit("Native dependency union refused: input selection, custody, digest or budget mismatch")
