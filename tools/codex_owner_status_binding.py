"""Bind exact actual N1 source as versioned metadata input; never selects SDK.

The native export-persistence investigation may require a sixth delta. This
source binding cannot authorize native/compiler dispatch or reuse fourth proof.
"""
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_live_source as source
import codex_protocol_history_source as history
import codex_owner_status_source as status

ROOT = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/3aceac88-079d-4539-adbf-b6e493bc7e68/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_source_producer/test.outputs/owner-status-source")
RECEIPT_SHA = "31b6bb3ca3c9850fb186dcdbcdb3cc0923f5d01e3f0fcfb7403fea8c780fc843"
INVENTORY_SHA = "82b5471f8428c819673ca4cd68d0792c475de2dfffdbc7f718bff7a5bbba5cb5"
FOURTH_INVENTORY_SHA = "2a47af056eb03b2d9eb53d1fbd535fb78cbfbf49e68a384117e13ba777fd9730"
RECEIPT_BYTES = 3173937
SOURCE_MEMBERS = 8549
SOURCE_BYTES = 84635872
EXPORT_ROOT = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
EXPORT_SHA = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
KIND = "omux-owner-status-metadata-binding-v1"


def expected_receipt(parent, fourth, fifth):
    fourth_inventory = status.inventory(fourth)
    inventory = status.inventory(fifth)
    source.require(source.sha(source.canonical(fourth_inventory)) == FOURTH_INVENTORY_SHA
        and source.sha(source.canonical(inventory)) == INVENTORY_SHA
        and len(fifth) == SOURCE_MEMBERS and sum(len(value) for _, value in fifth.values()) == SOURCE_BYTES)
    return {
        "schema_version": 1, "kind": status.KIND,
        "status": "verified-owner-status-source-pending-sdk-and-schema",
        "commit": source.COMMIT, "parent_source_root": str(history.PARENT),
        "parent_source_receipt_sha256": history.PARENT_RECEIPT_SHA,
        "parent_source_inventory_sha256": history.PARENT_INVENTORY_SHA,
        "fourth_source_inventory_sha256": FOURTH_INVENTORY_SHA,
        "fourth_source_inventory": fourth_inventory,
        "patch_sha256": history.PARENT_PATCHES + [history.PATCH_SHA, status.PATCH_SHA],
        "patches": parent["patches"] + [
            {"patch_sha256": history.PATCH_SHA, "paths": sorted(history.ALLOWED)},
            {"patch_sha256": status.PATCH_SHA, "paths": sorted(status.ALLOWED)}],
        "fifth_preimages": status.PREIMAGES, "source_inventory": inventory,
        "inventory_sha256": INVENTORY_SHA, "tracked_files": SOURCE_MEMBERS, "source_bytes": SOURCE_BYTES,
        "graph_files": {name: {"sha256": source.sha(fifth[name][1])} for name in history.GRAPH},
        "physical_mode_policy": "bazel-retained-export-all-regular-and-directories-0555-v1",
        "sdk_metadata_qualified": False, "schema_producer_qualified": False,
        "native_compile_passed": False, "native_support": False,
        "provider_evaluation": False, "live_handoff_proven": False,
    }


def load_actual():
    fd = source.directory(ROOT)
    try:
        source.require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
        raw, mode = source.read(fd, "source-receipt.json", source.MAX_METADATA)
    finally:
        os.close(fd)
    source.require(mode == 0o555 and len(raw) == RECEIPT_BYTES and source.sha(raw) == RECEIPT_SHA)
    return json.loads(raw, object_pairs_hook=source.unique)


def bind():
    fd = source.directory(ROOT)
    try:
        before = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_uid, stat.S_IMODE(before.st_mode))
        report = load_actual()
        parent_files, parent = history.load_parent()
        fourth = history.transform(parent_files, status.read_patch(history.PATCH_NAME))
        fifth = status.transform(fourth, status.read_patch(status.PATCH_NAME))
        expected = expected_receipt(parent, fourth, fifth)
        source.require(report == expected and source.sha(source.encoded(expected)) == RECEIPT_SHA)
        # Actual named tree, every byte, exact regular/symlink modes/file set.
        source.verify_written(ROOT / "source", fifth)
        source.require(load_actual() == expected)
        named = source.directory(ROOT)
        try:
            after = os.fstat(named)
            source.require((after.st_dev, after.st_ino, after.st_uid, stat.S_IMODE(after.st_mode)) == identity)
        finally:
            os.close(named)
        return {
            "schema_version": 1, "kind": KIND, "status": "verified-n1-source-binding-pending-sdk",
            "metadata_input": {"kind": "omux-owner-status-metadata-input-v1",
                "source_root": str(ROOT), "source_receipt_sha256": RECEIPT_SHA,
                "source_inventory_sha256": INVENTORY_SHA,
                "export_root": EXPORT_ROOT, "export_receipt_sha256": EXPORT_SHA},
            "source_graph": expected["graph_files"],
            "source_reconstructed_and_fully_read": True,
            "sdk_materials_revalidated": False, "sdk_metadata_qualified": False,
            "schema_producer_qualified": False, "native_source_finalized": False,
            "native_compile_passed": False, "native_support": False,
            "provider_evaluation": False, "live_handoff_proven": False,
        }
    finally:
        os.close(fd)


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_TIMEOUT")
        and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    source.require(1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    report = bind()
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    fd = source.directory(output)
    try:
        writer = os.open("owner-status-metadata-binding.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=fd)
        with os.fdopen(writer, "wb") as stream:
            stream.write(source.encoded(report))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
        source.DEADLINE = None
    print("N1 source bound; SDK schema compiler and final native source unqualified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("owner status metadata source binding refused", file=sys.stderr)
        raise SystemExit(1) from None
