"""Finite digest-selected SDK input export and file-only missing-object shards.

Only declared Bazel targets may dispatch this helper. Neither mode runs an SDK,
evaluates Nix, changes a cache, or establishes repository/dependency closure.
"""

import argparse
from contextlib import ExitStack
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from codex_dependency_cache import (CACHES, DESCRIPTOR, SOURCE_RECEIPT,
                                    SOURCE_RECEIPT_SHA, child_directory,
                                    descriptor_summary, module_descriptors)
from codex_sdk_dependencies import public_url
from codex_sdk_profile import hash_regular, trusted_parent, validate_source
from fetch_codex_archives import (PINNED_CA, PINNED_NIX, child_environment,
                                 disk_check, export_payload, immutable_file,
                                 prefetch_command, run_prefetch)
from restore_pristine_inputs import unique_object

DESCRIPTOR_SHA = "50db24e82808bfea9fd00f20325874962519c76ea8d6c0e2ca2eb311a77b0feb"
MAX_ROWS = 30000
MAX_OBJECTS = 5000
MAX_METADATA = 16 * 1024 * 1024
MAX_SOURCE_JSON = 1024 * 1024
MAX_FILE = 1024 * 1024 * 1024
MAX_BYTES = 4 * MAX_FILE
DISK_BYTES = 8 * MAX_FILE
FREE_FLOOR = 4 * MAX_FILE
MAX_SECONDS = 1200
FILE_SECONDS = 300
MAX_DOWNLOADS = 64
MAX_PARENTS = 32
HASH = re.compile(r"[0-9a-f]{64}")
HOME_HTTP_STATE = Path("/home/jess/.local/state/omux-codex-http-prefetch-20261006")
# This HOME lane is one reviewed declaration, not a caller-selected fetch plan.
# Its receipt digest is still selected independently by every later consumer.
HOME_HTTP_SHARD = ("e2062afb5cda472861c0e5a442312424252554c8a7fba6baf8f1725609bfdb66", 1, 30)
ROOTS = (Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"),
         Path("/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005"),
         HOME_HTTP_STATE)
SUFFIX = "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
COMMON = {"schema_version": 1, "descriptor_sha256": DESCRIPTOR_SHA,
          "source_receipt_sha256": SOURCE_RECEIPT_SHA,
          "closure_proved": False, "offline_analysis_proved": False,
          "native_support": False, "provider_evaluation": False}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(payload) <= MAX_METADATA, "bundle metadata exceeds bound")
    return payload


def row_checked(row):
    require(isinstance(row, dict) and set(row) == {"type", "identity", "sha256", "urls"},
            "descriptor row shape differs")
    require(isinstance(row["sha256"], str) and HASH.fullmatch(row["sha256"]), "invalid digest")
    require(isinstance(row["type"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["type"]),
            "invalid descriptor type")
    require(isinstance(row["identity"], str) and 0 < len(row["identity"]) <= 4096
            and not any(c in row["identity"] for c in "\0\r\n"), "invalid identity")
    urls = row["urls"]
    require(isinstance(urls, list) and 0 < len(urls) <= 16
            and all(isinstance(url, str) and len(url) <= 8192 and public_url(url, row["sha256"]) for url in urls),
            "unsupported public URL")
    return row


class Budget:
    def __init__(self, seconds=MAX_SECONDS):
        require(1 <= seconds <= MAX_SECONDS, "deadline bound differs")
        self.deadline = time.monotonic() + seconds
        self.read_bytes = 0
        self.export_bytes = 0

    def tick(self, count=0):
        require(time.monotonic() < self.deadline, "bundle deadline exceeded")
        self.read_bytes += count
        require(self.read_bytes <= MAX_BYTES, "bundle read budget exceeded")


def payload_fd(root_fd, digest):
    """Open only the selected owned digest object; absence is not refusal."""
    require(HASH.fullmatch(digest), "invalid selected digest")
    descriptors = []
    try:
        parent = root_fd
        for name in ("content_addressable", "sha256", digest):
            parent = child_directory(parent, name)
            descriptors.append(parent)
        return os.open("file", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def stream_object(fd, digest, budget, destination=None, capture=False, limit=MAX_FILE):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and not before.st_mode & 0o022 and 0 <= before.st_size <= limit,
            "selected payload custody/type/size differs")
    if destination is not None:
        require(budget.export_bytes + before.st_size <= MAX_BYTES, "bundle export budget exceeded")
    output = None
    parts, size, checksum = [], 0, hashlib.sha256()
    try:
        if destination is not None:
            output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        while chunk := os.read(fd, 1024 * 1024):
            budget.tick(len(chunk))
            size += len(chunk)
            require(size <= limit, "selected payload grew beyond bound")
            checksum.update(chunk)
            if capture:
                parts.append(chunk)
            if output is not None:
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    require(written > 0, "payload write made no progress")
                    view = view[written:]
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and size == before.st_size and checksum.hexdigest() == digest,
                "selected payload changed or digest differs")
        if output is not None:
            os.fsync(output)
            budget.export_bytes += size
        budget.tick()
        return size, b"".join(parts)
    finally:
        if output is not None:
            os.close(output)


def object_destination(root, digest):
    parent = root / "content_addressable" / "sha256" / digest
    parent.mkdir(mode=0o700)
    return parent / "file"


def make_output(root):
    root.mkdir(mode=0o700)
    (root / "content_addressable").mkdir(mode=0o700)
    (root / "content_addressable/sha256").mkdir(mode=0o700)


def publish(root, report):
    value = encoded(report)
    path = root / "bundle-receipt.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    directory = trusted_parent(root)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(value).hexdigest()


def inventory(root_fd, objects):
    """Closed CAS shape, without arbitrary recursive traversal or marker import."""
    require(set(os.listdir(root_fd)) == {"bundle-receipt.json", "content_addressable"},
            "bundle root contains undeclared entries")
    with ExitStack() as stack:
        content = child_directory(root_fd, "content_addressable")
        stack.callback(os.close, content)
        require(os.listdir(content) == ["sha256"], "bundle CAS algorithms differ")
        hashes = child_directory(content, "sha256")
        stack.callback(os.close, hashes)
        require(set(os.listdir(hashes)) == set(objects), "bundle digest inventory differs")
        for digest in objects:
            item = child_directory(hashes, digest)
            try:
                require(os.listdir(item) == ["file"], "bundle digest contains undeclared entries")
            finally:
                os.close(item)


def retained_location(root, kind):
    require(root.is_absolute() and ".." not in root.parts, "noncanonical retained input")
    home = root.is_relative_to(HOME_HTTP_STATE)
    require(not home or kind == "producer", "HOME HTTP input requires the bundle producer")
    for base in ROOTS:
        if root.is_relative_to(base):
            relative = root.relative_to(base)
            epoch_pattern = (r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}" if home else
                             r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|cache-v2-[0-9a-f]{64})")
            require(len(relative.parts) > 1 and re.fullmatch(epoch_pattern,
                relative.parts[0]), "retained epoch differs")
            target = "codex_dependency_bundle_" + kind
            require(Path(*relative.parts[1:]).as_posix() == SUFFIX + target
                    + "/test.outputs/codex-dependency-bundle", "retained producer suffix differs")
            return
    raise ValueError("undeclared retained producer root")


def load_bundle(root, digest, kind, budget, enforce_location=True, *, on_read=None):
    home = root.is_relative_to(HOME_HTTP_STATE)
    if enforce_location or home:
        retained_location(root, kind)
    root_fd = trusted_parent(root)
    try:
        actual, _, value = hash_regular(root_fd, "bundle-receipt.json", MAX_METADATA, True, on_read=on_read)
        require(actual == digest and HASH.fullmatch(digest), "bundle receipt digest differs")
        report = json.loads(value, object_pairs_hook=unique_object)
        require(all(report.get(key) == expected for key, expected in COMMON.items())
                and all(report.get(key) is False for key in (
                    "closure_proved", "offline_analysis_proved", "native_support", "provider_evaluation"))
                and report.get("status") == ("offline-dependency-plan" if kind == "plan"
                                              else "verified-missing-object-shard"),
                "bundle authority differs")
        if home:
            require(type(report.get("shard_index")) is int and type(report.get("shard_size")) is int
                    and (report.get("parent_plan_sha256"), report["shard_index"], report["shard_size"])
                    == HOME_HTTP_SHARD, "HOME HTTP shard declaration differs")
        objects = report.get("objects")
        require(isinstance(objects, dict) and len(objects) <= MAX_OBJECTS, "object inventory exceeds bound")
        inventory(root_fd, objects)
        total = 0
        for selected, record in objects.items():
            require(HASH.fullmatch(selected) and isinstance(record, dict)
                    and set(record) == {"bytes"} and type(record["bytes"]) is int,
                    "object record differs")
            fd = payload_fd(root_fd, selected)
            try:
                size, _ = stream_object(fd, selected, budget)
            finally:
                os.close(fd)
            require(size == record["bytes"], "object size differs")
            total += size
        require(total <= MAX_BYTES, "input bundle exceeds retained bound")
        return report
    finally:
        os.close(root_fd)


def authority(*, on_read=None):
    validate_source(SOURCE_RECEIPT.parent, SOURCE_RECEIPT_SHA, on_read=on_read)
    with ExitStack() as stack:
        source_fd = trusted_parent(SOURCE_RECEIPT.parent)
        stack.callback(os.close, source_fd)
        actual, _, payload = hash_regular(source_fd, SOURCE_RECEIPT.name, 8 * 1024 * 1024, True, on_read=on_read)
        require(actual == SOURCE_RECEIPT_SHA, "source receipt digest differs")
        source = json.loads(payload, object_pairs_hook=unique_object)
        descriptor_fd = trusted_parent(DESCRIPTOR.parent)
        stack.callback(os.close, descriptor_fd)
        actual, size, payload = hash_regular(descriptor_fd, DESCRIPTOR.name, MAX_METADATA, True, on_read=on_read)
        require(actual == DESCRIPTOR_SHA, "descriptor receipt digest differs")
        manifest = json.loads(payload, object_pairs_hook=unique_object)
        summary = descriptor_summary(manifest, actual, size, source)
    return manifest, summary["source_inventory_sha256"]


def build_plan(manifest, inventory_sha, sources, root, budget):
    """Sources are prevalidated, read-only cache/CAS directory descriptors."""
    pending = deque(manifest["artifacts"])
    rows, objects, missing, origins = {}, {}, set(), {}
    unresolved = list(manifest["unsupported"])
    derivations = []
    metadata_seen = set()
    while pending:
        budget.tick()
        row = row_checked(pending.popleft())
        key = (row["type"], row["identity"])
        require(key not in rows or rows[key] == row, "conflicting descriptor identity")
        if key in rows:
            continue
        rows[key] = row
        require(len(rows) <= MAX_ROWS, "expanded descriptors exceed bound")
        selected = row["sha256"]
        source_json = row["type"] == "bazel-registry-file" and row["identity"].endswith("/source.json")
        value = None
        if selected not in objects and selected not in missing:
            for identity, source_fd in sources:
                try:
                    fd = payload_fd(source_fd, selected)
                except FileNotFoundError:
                    continue
                try:
                    require(len(objects) < MAX_OBJECTS, "export object count exceeds bound")
                    disk_check(root, DISK_BYTES, FREE_FLOOR)
                    size, value = stream_object(fd, selected, budget,
                        object_destination(root, selected), capture=source_json,
                        limit=MAX_SOURCE_JSON if source_json else MAX_FILE)
                finally:
                    os.close(fd)
                objects[selected] = {"bytes": size}
                origins[selected] = identity
                disk_check(root, DISK_BYTES, FREE_FLOOR)
                break
            else:
                missing.add(selected)
        if source_json and selected in objects and key not in metadata_seen:
            if value is None:
                root_fd = trusted_parent(root)
                try:
                    fd = payload_fd(root_fd, selected)
                    try:
                        _, value = stream_object(fd, selected, budget, capture=True, limit=MAX_SOURCE_JSON)
                    finally:
                        os.close(fd)
                finally:
                    os.close(root_fd)
            derived, refused = module_descriptors(row["identity"], value)
            metadata_seen.add(key)
            derivations.append({"identity": row["identity"], "sha256": selected,
                                "descriptors": derived})
            unresolved.extend(refused)
            if any(item["type"] == "bazel-module-archive" for item in derived):
                unresolved = [item for item in unresolved if not (
                    item.get("type") == "bazel-module-archive" and item.get("identity") == row["identity"])]
            pending.extend(derived)
    ordered = [rows[key] for key in sorted(rows)]
    missing_rows = [row for row in ordered if row["sha256"] in missing]
    # Metadata first permits the next offline plan to derive archives before crate acquisition.
    missing_rows.sort(key=lambda row: (row["type"] != "bazel-registry-file",
                                     not row["identity"].endswith("/source.json"),
                                     row["type"], row["identity"]))
    selected_missing = {}
    for row in missing_rows:
        selected_missing.setdefault(row["sha256"], row)
    require(len(unresolved) <= MAX_ROWS and len(derivations) <= MAX_ROWS, "unresolved/derivation bound exceeded")
    return {**COMMON, "status": "offline-dependency-plan", "source_inventory_sha256": inventory_sha,
            "descriptors": ordered, "objects": objects, "missing": list(selected_missing.values()),
            "unresolved": unresolved, "derivations": derivations,
            "object_origins": origins,
            "cache_inputs": [identity for identity, _ in sources],
            "canonical_id_metadata_exported": False,
            "scope": "digest object availability only; Git, repository rules and canonical IDs remain separate",
            "budgets": {"rows": MAX_ROWS, "objects": MAX_OBJECTS, "read_bytes": MAX_BYTES,
                        "retained_bytes": MAX_BYTES, "per_file_bytes": MAX_FILE,
                        "deadline_seconds": MAX_SECONDS}}


def verify_plan_authority(plan, manifest, root_fd, budget):
    """Reconstruct admitted descriptor authority from pinned locks and BCR bytes."""
    rows = {}
    pending = deque(manifest["artifacts"])
    while pending:
        budget.tick()
        row = row_checked(pending.popleft())
        key = (row["type"], row["identity"])
        require(key not in rows or rows[key] == row, "conflicting descriptor identity")
        if key in rows:
            continue
        rows[key] = row
        require(len(rows) <= MAX_ROWS, "expanded descriptor bound exceeded")
        if (row["type"] == "bazel-registry-file" and row["identity"].endswith("/source.json")
                and row["sha256"] in plan["objects"]):
            fd = payload_fd(root_fd, row["sha256"])
            try:
                _, value = stream_object(fd, row["sha256"], budget, capture=True, limit=MAX_SOURCE_JSON)
            finally:
                os.close(fd)
            derived, _ = module_descriptors(row["identity"], value)
            pending.extend(derived)
    require(plan.get("descriptors") == [rows[key] for key in sorted(rows)],
            "plan descriptors do not derive from pinned metadata")
    digests = {row["sha256"] for row in rows.values()}
    require(set(plan["objects"]) <= digests, "plan exports unselected objects")
    missing = plan.get("missing")
    require(isinstance(missing, list) and len(missing) <= MAX_ROWS,
            "missing descriptor bound exceeded")
    require({row_checked(row)["sha256"] for row in missing} == digests - set(plan["objects"]),
            "plan missing object set differs from pinned metadata")


def selected_shard(plan, index, size):
    require(type(index) is int and 0 <= index < MAX_ROWS
            and type(size) is int and 1 <= size <= MAX_DOWNLOADS, "shard bounds differ")
    rows = plan.get("missing")
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "missing inventory exceeds bound")
    digests = set()
    descriptors = {json.dumps(row_checked(row), sort_keys=True) for row in plan.get("descriptors", [])}
    require(len(descriptors) <= MAX_ROWS, "plan descriptors exceed bound")
    for row in rows:
        row_checked(row)
        require(json.dumps(row, sort_keys=True) in descriptors and row["sha256"] not in digests
                and row["sha256"] not in plan["objects"], "missing plan row authority differs")
        digests.add(row["sha256"])
    result = rows[index * size:(index + 1) * size]
    require(result, "selected shard is empty")
    return result


def fetch_shard(plan, plan_digest, index, size, root, scratch, budget, nix, ca):
    rows = selected_shard(plan, index, size)
    objects = {}
    # All network operations are expected-hash Nix file fetches, with no fallback URLs.
    with tempfile.TemporaryDirectory(prefix="codex-dependency-fetch-", dir=scratch) as temporary:
        worker = Path(temporary) / "worker"
        worker.mkdir(mode=0o700)
        for name in ("home", "tmp", "config", "private-store", "distdir"):
            (worker / name).mkdir(mode=0o700)
        for row in rows:
            budget.tick()
            entry = {"name": row["sha256"], "sha256": row["sha256"], "url": row["urls"][0]}
            end = min(budget.deadline, time.monotonic() + FILE_SECONDS)
            reply = run_prefetch(prefetch_command(nix, worker, entry), child_environment(worker, ca),
                                 worker, end, DISK_BYTES, FREE_FLOOR)
            result = export_payload(worker, reply, entry, end, DISK_BYTES, FREE_FLOOR,
                                    MAX_BYTES - budget.export_bytes)
            budget.tick(result["bytes"])
            source = worker / "distdir" / entry["name"]
            require(source.stat().st_dev == root.stat().st_dev, "shard export filesystem differs")
            os.rename(source, object_destination(root, entry["name"]))
            budget.export_bytes += result["bytes"]
            objects[entry["name"]] = {"bytes": result["bytes"]}
            disk_check(worker, DISK_BYTES, FREE_FLOOR)
    return {**COMMON, "status": "verified-missing-object-shard",
            "source_inventory_sha256": plan["source_inventory_sha256"],
            "parent_plan_sha256": plan_digest, "shard_index": index, "shard_size": size,
            "descriptors": rows, "objects": objects, "remaining_missing_objects": len(plan["missing"]) - len(rows),
            "unresolved": plan["unresolved"], "canonical_id_metadata_exported": False,
            "scope": "selected immutable file shard only; no Git or transitive closure proof"}


def main(arguments=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--mode", choices=("plan", "fetch"), required=True)
    parser.add_argument("--input-shard", nargs=2, action="append", default=[], metavar=("ROOT", "SHA256"))
    parser.add_argument("--plan-root", type=Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-size", type=int)
    parser.add_argument("--nix", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args(arguments)
    require(os.environ.get("OMUX_EXECUTION_GUARD"), "declared contained producer context required")
    budget = Budget()
    manifest, inventory_sha = authority()
    outputs = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
    if outputs.is_relative_to(HOME_HTTP_STATE):
        require(args.mode == "fetch" and not args.input_shard
                and (args.plan_sha256, args.shard_index, args.shard_size) == HOME_HTTP_SHARD,
                "HOME HTTP acquisition declaration differs")
    descriptor = trusted_parent(outputs)
    try:
        require(not os.listdir(descriptor), "producer outputs must be empty")
    finally:
        os.close(descriptor)
    root = outputs / "codex-dependency-bundle"
    make_output(root)
    with ExitStack() as stack:
        if args.mode == "plan":
            require(all(value is None for value in (args.plan_root, args.plan_sha256, args.shard_index,
                    args.shard_size, args.nix, args.ca_file)) and len(args.input_shard) <= MAX_PARENTS,
                    "plan inputs differ")
            sources = []
            for path in CACHES:
                descriptor = trusted_parent(path)
                stack.callback(os.close, descriptor)
                sources.append((str(path), descriptor))
            for path, digest in args.input_shard:
                path = Path(path)
                report = load_bundle(path, digest, "producer", budget)
                require(report["source_inventory_sha256"] == inventory_sha, "shard source inventory differs")
                descriptor = trusted_parent(path)
                stack.callback(os.close, descriptor)
                sources.append(("shard-receipt-sha256:" + digest, descriptor))
            report = build_plan(manifest, inventory_sha, sources, root, budget)
        else:
            require(not args.input_shard and all(value is not None for value in (
                args.plan_root, args.plan_sha256, args.shard_index, args.shard_size, args.nix, args.ca_file)),
                "fetch requires exact plan, shard and pinned tools")
            require(args.shard_index >= 0 and 1 <= args.shard_size <= MAX_DOWNLOADS,
                    "fetch shard bounds differ")
            plan = load_bundle(args.plan_root, args.plan_sha256, "plan", budget)
            require(plan["source_inventory_sha256"] == inventory_sha, "plan source inventory differs")
            descriptor = trusted_parent(args.plan_root)
            try:
                verify_plan_authority(plan, manifest, descriptor, budget)
            finally:
                os.close(descriptor)
            nix, ca = immutable_file(args.nix), immutable_file(args.ca_file)
            require(nix == PINNED_NIX and ca == PINNED_CA, "fetch tool pins differ")
            scratch = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
            descriptor = trusted_parent(scratch)
            os.close(descriptor)
            report = fetch_shard(plan, args.plan_sha256, args.shard_index, args.shard_size,
                                 root, scratch, budget, nix, ca)
        validate_source(SOURCE_RECEIPT.parent, SOURCE_RECEIPT_SHA)
        budget.tick()
        digest = publish(root, report)
    print(json.dumps({"receipt_sha256": digest, "status": report["status"],
                      "objects": len(report["objects"]), "closure_proved": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit("SDK dependency producer refused: bounded input, custody, digest or acquisition mismatch")
