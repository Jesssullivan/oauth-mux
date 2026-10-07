"""Qualify finite descriptor-selected cache payloads without fetch or mutation."""

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from codex_sdk_dependencies import public_url, sha
from codex_sdk_profile import EXPORT_MODE_POLICY, GIT_MODE_AUTHORITY, GRAPH, hash_regular, trusted_parent
from restore_pristine_inputs import unique_object

CACHES = (
    Path("/home/jess/.cache/bazel-repo-cache"),
    Path("/srv/fast-local/jess/state/codex/omux-bazel9-owner-coordinator-20261004/cache/repos/v1"),
)
DESCRIPTOR = Path("/home/jess/.local/state/omux-execution-20261005/"
    "cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee/"
    "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
    "codex_sdk_dependency_descriptors/test.outputs/codex-sdk-dependencies/dependency-manifest.json")
SOURCE_RECEIPT = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"
    "cf85bdc6-5de0-4033-a57e-5e8d24301ccb/output-base/execroot/_main/bazel-out/k8-fastbuild/"
    "testlogs/tools/codex_fresh_source_producer/test.outputs/codex-adapter-epoch/source-receipt.json")
SOURCE_RECEIPT_SHA = "6a606a9ca602e31f0050d15625038eeaaaff96432248dd803d51c3a1838871b3"
MAX_BYTES = 4 * 1024 * 1024 * 1024
MAX_FILE = 1024 * 1024 * 1024
MAX_ROWS = 30000


def require(value, message):
    if not value:
        raise ValueError(message)


def child_directory(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError("cache directory custody mismatch")
    return fd


def descriptor_summary(manifest, digest, size, source):
    require(manifest.get("schema_version") == 1 and manifest.get("status") == "source-dependency-descriptors-unfetched"
            and manifest.get("source_receipt_sha256") == SOURCE_RECEIPT_SHA
            and manifest.get("source_inventory_verified") is True
            and manifest.get("physical_mode_policy") == EXPORT_MODE_POLICY
            and manifest.get("git_mode_authority") == GIT_MODE_AUTHORITY
            and manifest.get("module_lock_sha256") == GRAPH["MODULE.bazel.lock"]
            and manifest.get("cargo_lock_sha256") == GRAPH["codex-rs/Cargo.lock"]
            and manifest.get("closure_proved") is False and manifest.get("offline_analysis_proved") is False
            and manifest.get("native_support") is False, "descriptor source authority mismatch")
    files = source.get("files")
    require(source.get("tracked_files") == 8546 and isinstance(files, dict) and len(files) == 8546
            and source.get("complete_inventory_sha256") == hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
            "original source inventory receipt mismatch")
    counts = {}
    for field in ("artifacts", "unsupported"):
        rows = manifest.get(field)
        require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "descriptor summary bound mismatch")
        counts[field] = {}
        for row in rows:
            kind = row.get("type")
            require(isinstance(kind, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", kind), "unsafe descriptor summary type")
            counts[field][kind] = counts[field].get(kind, 0) + 1
    snapshots = manifest.get("rules_rs_snapshots")
    require(isinstance(snapshots, list) and len(snapshots) <= 15000, "snapshot summary bound mismatch")
    return {"status": "observed-retained-descriptor-digest", "descriptor_sha256": digest, "descriptor_bytes": size,
            "counts": counts, "snapshot_count": len(snapshots), "source_receipt_sha256": SOURCE_RECEIPT_SHA,
            "source_inventory_sha256": source["complete_inventory_sha256"],
            "closure_proved": False, "offline_analysis_proved": False, "native_support": False,
            "qualification": "digest of observed retained manifest; does not rerun enumeration or claim dependency availability"}


def module_descriptors(registry_url, value):
    """Extract URLs only from digest-verified public BCR source metadata."""
    require(public_url(registry_url) and registry_url.startswith("https://bcr.bazel.build/modules/")
            and registry_url.endswith("/source.json"), "not a public BCR source descriptor")
    document = json.loads(value, object_pairs_hook=unique_object)
    require(isinstance(document, dict), "source metadata must be an object")
    rows, unresolved = [], []
    urls = document.get("urls")
    if urls is None and isinstance(document.get("url"), str):
        urls = [document["url"]]
    expected = sha(document.get("sha256"), document.get("integrity"))
    if expected and isinstance(urls, list) and urls and all(isinstance(url, str) and public_url(url, expected) for url in urls):
        rows.append({"type": "bazel-module-archive", "identity": registry_url, "urls": urls, "sha256": expected})
    else:
        unresolved.append({"type": "bazel-module-archive", "identity": registry_url,
                           "reason": "source metadata archive digest/public URL unsupported"})
    prefix = registry_url.removesuffix("source.json")
    for kind in ("patches", "overlay"):
        entries = document.get(kind, {})
        require(isinstance(entries, dict) and len(entries) <= 1000, "source supplemental map exceeds bound")
        for name, integrity in sorted(entries.items()):
            path = PurePosixPath(name)
            require(name and not path.is_absolute() and ".." not in path.parts and str(path) == name
                    and not any(char in name for char in "\\\0\r\n?#"), "unsafe source supplemental path")
            digest = sha(None, integrity)
            if digest:
                rows.append({"type": "bazel-module-" + kind, "identity": registry_url + ":" + name,
                             "urls": [prefix + kind + "/" + name], "sha256": digest})
            else:
                unresolved.append({"type": "bazel-module-" + kind, "identity": registry_url,
                                   "reason": "supplemental digest unsupported"})
    if document.get("type") not in (None, "archive"):
        unresolved.append({"type": "bazel-module-source-kind", "identity": registry_url,
                           "reason": "non-archive repository transformation needs separate qualification"})
    return rows, unresolved


def qualify(manifest, cache_fd, deadline_seconds=1200):
    require(manifest.get("status") == "source-dependency-descriptors-unfetched"
            and manifest.get("source_inventory_verified") is True and manifest.get("closure_proved") is False,
            "descriptor manifest authority mismatch")
    rows = manifest.get("artifacts")
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, "descriptor count exceeds bound")
    report = {"status": "offline-cache-qualification", "verified": [], "missing": [], "refused": [],
              "derived_module_descriptors": [], "unresolved": list(manifest.get("unsupported", [])),
              "input_descriptor_unresolved": list(manifest.get("unsupported", [])),
              "closure_proved": False, "offline_analysis_proved": False, "native_support": False}
    memo, consumed, deadline = {}, 0, time.monotonic() + deadline_seconds
    queue = deque(rows)
    while queue:
        require(time.monotonic() < deadline, "cache qualification deadline exceeded")
        require(len(report["verified"]) + len(report["missing"]) + len(report["refused"]) < MAX_ROWS,
                "expanded descriptor count exceeds bound")
        row = queue.popleft()
        expected = row.get("sha256")
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "noncanonical cache digest")
        require(isinstance(row.get("type"), str) and isinstance(row.get("identity"), str), "descriptor identity missing")
        public = row.get("urls")
        require(isinstance(public, list) and public and all(isinstance(url, str) and public_url(url, expected) for url in public),
                "descriptor URLs are not public")
        summary = {"type": row["type"], "identity": row["identity"], "sha256": expected}
        source_json = row["type"] == "bazel-registry-file" and row["identity"].endswith("/source.json")
        key = (expected, source_json)
        if key not in memo:
            descriptors = []
            try:
                parent = cache_fd
                for name in ("content_addressable", "sha256", expected):
                    parent = child_directory(parent, name)
                    descriptors.append(parent)
                limit = min(MAX_FILE, MAX_BYTES - consumed, 1024 * 1024 if source_json else MAX_FILE)
                fd = os.open("file", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                            and not before.st_mode & 0o022 and before.st_size <= limit, "cache payload custody mismatch")
                    value, chunks, size = hashlib.sha256(), [], 0
                    while chunk := os.read(fd, min(1024 * 1024, MAX_BYTES - consumed + 1)):
                        require(time.monotonic() < deadline, "cache qualification deadline exceeded")
                        consumed += len(chunk)
                        size += len(chunk)
                        require(consumed <= MAX_BYTES and size <= limit, "cache payload read budget exceeded")
                        value.update(chunk)
                        if source_json:
                            chunks.append(chunk)
                    after = os.fstat(fd)
                    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            and size == before.st_size, "cache payload changed while reading")
                    actual, payload = value.hexdigest(), b"".join(chunks)
                finally:
                    os.close(fd)
                require(actual == expected, "cache payload digest mismatch")
                memo[key] = ("verified", size, payload)
            except FileNotFoundError:
                memo[key] = ("missing", 0, b"")
            except (OSError, ValueError):
                memo[key] = ("refused", 0, b"")
            finally:
                for fd in reversed(descriptors):
                    os.close(fd)
        state, size, payload = memo[key]
        if state == "verified":
            report[state].append({**summary, "bytes": size})
            if source_json:
                try:
                    derived, unresolved = module_descriptors(row["identity"], payload)
                    report["derived_module_descriptors"].extend(derived)
                    if any(entry["type"] == "bazel-module-archive" for entry in derived):
                        report["unresolved"] = [entry for entry in report["unresolved"]
                            if not (entry.get("type") == "bazel-module-archive" and entry.get("identity") == row["identity"])]
                    report["unresolved"].extend(unresolved)
                    queue.extend(derived)
                except (ValueError, TypeError, KeyError):
                    report["unresolved"].append({"type": "bazel-module-source-json", "identity": row["identity"],
                                                 "reason": "verified payload has unsupported or invalid metadata"})
        else:
            report[state].append({**summary, "reason": "absent selected digest object" if state == "missing"
                                  else "selected object refused by custody/type/size/digest checks"})
    report["total_payload_bytes_read"] = consumed
    report["counts"] = {name: len(report[name]) for name in ("verified", "missing", "refused", "derived_module_descriptors", "unresolved")}
    return report


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--descriptor-manifest", type=Path, required=True)
    parser.add_argument("--descriptor-sha256")
    parser.add_argument("--cache-directory", type=Path)
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    require(args.descriptor_manifest == DESCRIPTOR, "undeclared descriptor root")
    parent = trusted_parent(DESCRIPTOR.parent)
    try:
        expected, size, payload = hash_regular(parent, DESCRIPTOR.name, 16 * 1024 * 1024, True)
        manifest = json.loads(payload, object_pairs_hook=unique_object)
    finally:
        os.close(parent)
    source_parent = trusted_parent(SOURCE_RECEIPT.parent)
    try:
        source_sha, _, source_bytes = hash_regular(source_parent, SOURCE_RECEIPT.name, 8 * 1024 * 1024, True)
        require(source_sha == SOURCE_RECEIPT_SHA, "original source receipt digest mismatch")
        summary = descriptor_summary(manifest, expected, size, json.loads(source_bytes, object_pairs_hook=unique_object))
    finally:
        os.close(source_parent)
    if args.describe:
        require(args.descriptor_sha256 is None and args.cache_directory is None, "digest probe may not qualify a cache")
        report = summary
        print(json.dumps(summary, sort_keys=True))
    else:
        require(args.cache_directory in CACHES and args.descriptor_sha256 == expected, "undeclared cache or descriptor digest mismatch")
        cache = trusted_parent(args.cache_directory)
        try:
            report = qualify(manifest, cache)
        finally:
            os.close(cache)
        report.update(descriptor_sha256=expected, selected_cache=str(args.cache_directory),
                      source_receipt_sha256=SOURCE_RECEIPT_SHA, source_inventory_sha256=summary["source_inventory_sha256"])
    require(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared cache qualification output required")
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    output = trusted_parent(Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]))
    try:
        fd = os.open("codex-sdk-cache-qualification.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=output)
        with os.fdopen(fd, "wb") as stream:
            stream.write(report_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(output)
    print(json.dumps({"output_sha256": hashlib.sha256(report_bytes).hexdigest(),
                      "descriptor_sha256": expected, "source_receipt_sha256": SOURCE_RECEIPT_SHA,
                      "source_inventory_sha256": summary["source_inventory_sha256"], "counts": report["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
