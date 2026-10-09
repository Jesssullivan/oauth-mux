"""Bind actual N3 source only; metadata generation and SDK admission are separate."""
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_live_source as source
import codex_owner_status_persistence_source as successor

ROOT = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/95f10057-c0be-4a94-98f8-291dedec0d48/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_source_producer/test.outputs/owner-status-persistence-source")
RECEIPT_SHA = "a17c9b7294fd7b8018f60bd2210f14140598d4b04e10da05aa1733a9482f3eab"
RECEIPT_BYTES = 1592382
INVENTORY_SHA = "252599e5faafa05e2ff688e57e58d1890aea57ead0f35ce0633588754cae5030"
SOURCE_MEMBERS = 8549
SOURCE_BYTES = 84652968
KIND = "omux-owner-status-persistence-metadata-binding-v1"


def identity(fd):
    row = os.fstat(fd)
    return row.st_dev, row.st_ino, row.st_uid, stat.S_IMODE(row.st_mode)


def load_actual():
    fd = source.directory(ROOT)
    try:
        source.require(identity(fd)[3] == 0o555)
        raw, mode = source.read(fd, "source-receipt.json", source.MAX_METADATA)
    finally:
        os.close(fd)
    source.require(mode == 0o555 and len(raw) == RECEIPT_BYTES and source.sha(raw) == RECEIPT_SHA)
    return json.loads(raw, object_pairs_hook=source.unique)


def load_verified_source():
    fd = source.directory(ROOT)
    try:
        anchor = identity(fd)
        report = load_actual()
        parent_report, before = successor.parent.load_verified_source()
        source.require(source.sha(successor.status.read_patch(successor.REVIEWED_NATIVE_NAME)) == successor.REVIEWED_NATIVE_SHA)
        source.require(source.sha(successor.status.read_patch(successor.NORMALIZED_NATIVE_NAME)) == successor.NORMALIZED_NATIVE_SHA)
        result = successor.transform(before, successor.status.read_patch(successor.PATCH_NAME))
        expected = successor.expected_receipt(parent_report, result)
        source.require(expected["inventory_sha256"] == INVENTORY_SHA
            and len(result) == SOURCE_MEMBERS
            and sum(len(value) for _, value in result.values()) == SOURCE_BYTES
            and report == expected and source.sha(source.encoded(expected)) == RECEIPT_SHA)
        source.verify_written(ROOT / "source", result)
        # Re-read the parent proof as well as the child receipt: no adoption of
        # a replaced origin during the child full-tree read.
        after_report, after_files = successor.parent.load_verified_source()
        source.require(after_report == parent_report and after_files == before and load_actual() == expected)
        named = source.directory(ROOT)
        try:
            source.require(identity(named) == anchor)
        finally:
            os.close(named)
        return report, result
    finally:
        os.close(fd)


def bind():
    report, _ = load_verified_source()
    return {
        "schema_version": 1, "kind": KIND,
        "status": "verified-n3-source-binding-pending-metadata-and-sdk",
        "metadata_input": {"kind": "omux-owner-status-persistence-metadata-input-v1",
            "source_root": str(ROOT), "source_receipt_sha256": RECEIPT_SHA,
            "source_inventory_sha256": INVENTORY_SHA},
        "source_graph": report["graph_files"],
        "source_reconstructed_and_fully_read": True,
        "sdk_materials_revalidated": False, "sdk_metadata_qualified": False,
        "schema_producer_qualified": False, "native_source_finalized": False,
        "native_compile_passed": False, "native_support": False,
        "provider_evaluation": False, "live_handoff_proven": False,
    }


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_TIMEOUT")
        and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    source.require(1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    try:
        report = bind()
        output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
        fd = source.directory(output)
        try:
            writer = os.open("owner-status-persistence-metadata-binding.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(writer, "wb") as stream:
                stream.write(source.encoded(report))
                stream.flush()
                os.fchmod(stream.fileno(), 0o444)
                os.fsync(stream.fileno())
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        source.DEADLINE = None
    print("N3 source bound; metadata SDK schema compiler and native proof unqualified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("owner status persistence metadata source binding refused", file=sys.stderr)
        raise SystemExit(1) from None
