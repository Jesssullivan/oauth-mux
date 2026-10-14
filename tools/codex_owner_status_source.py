"""Compose exact fourth source and reviewed fifth status delta, without execution.

Distinct receipt and output intentionally have no metadata/SDK/native admission.
Every retained parent member and the fourth dependency delta are revalidated.
"""
import json
import os
from pathlib import Path
import sys
import time

import codex_live_source as source
import codex_protocol_history_source as history

# Explicit declared runfiles path, deliberately unresolved, as used by the
# existing fresh-source consumer. The isolated tools bootstrap adds only tools.
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "integrations/codex-upstream"))
import patch_io

KIND = "omux-owner-status-source-v1"
PATCH_NAME = "2026-10-09-fresh-native-interface-v2.UNAPPLIED.native.patch"
PATCH_SHA = "d6fa05a49dea0560a8204da1897329d2613530c76287440d7ab1d8b409fc64d2"
PREIMAGES = {
    "codex-rs/core/src/auth_broker.rs": "7bae14fd870ebc3bd880064d81410cc8a6d233a179408913c00990d75b4cbb8c",
    "codex-rs/core/src/auth_broker_owner_tests.rs": "c2a6b9383a8a81d5cad217706799e48f5d893193131b55f69fcc0c307aa41036",
    "codex-rs/app-server/src/owner_control.rs": "6f4aa4d4f82a455f601da08f687fa07f34786b598646d46d2643e7d6d078d646",
    "codex-rs/app-server/src/message_processor.rs": "2a70616871bc03b5c8ea64fcd4886312b751c9f1aa51cfb35e21b85ff024585d",
    "codex-rs/app-server-protocol/src/protocol/v2/thread.rs": "dc51852467f36da40c99eeea01ebb2ff3d40626aa9b2dbf7e54ed188f9ca4b32",
    "codex-rs/app-server-protocol/src/protocol/common.rs": "02358be560f0e10f4eda9cce1325157859c50f2347f3168bf92dc775346b29e8",
}
ALLOWED = frozenset(PREIMAGES)
PHASE = "parent"
PHASES = frozenset(("parent", "fourth", "fifth", "output"))


def read_patch(name):
    fd = source.directory(source.PATCH_DIRECTORY)
    try:
        raw, _ = source.read(fd, name, source.MAX_PATCH)
    finally:
        os.close(fd)
    return raw


def transform(fourth, raw):
    source.require(type(raw) is bytes and source.sha(raw) == PATCH_SHA
        and ALLOWED.isdisjoint(history.ALLOWED) and ALLOWED <= set(fourth))
    for name, pin in PREIMAGES.items():
        source.require(fourth[name][0] == "100644" and source.sha(fourth[name][1]) == pin)
    # The reviewed diff has ordinary ---/+++ headers. Add only git framing for
    # the existing exact-position/context parser; preserve every pinned hunk.
    framed = []
    for line in raw.decode("utf-8").splitlines(keepends=True):
        if line.startswith("--- a/"):
            name = line[len("--- a/"):].removesuffix("\n")
            source.require(name in ALLOWED)
            framed.append(f"diff --git a/{name} b/{name}\n")
        framed.append(line)
    changes = patch_io.apply_exact("".join(framed), {name: fourth[name][1] for name in ALLOWED})
    source.require(set(changes) == ALLOWED)
    result = dict(fourth)
    for name, value in changes.items():
        result[name] = ("100644", value)
    validate_transition(fourth, result)
    return result


def validate_transition(fourth, result):
    source.require(set(result) == set(fourth)
        and {name for name in fourth if fourth[name] != result[name]} == ALLOWED
        and all(fourth[name][0] == result[name][0] for name in fourth)
        and all(fourth[name] == result[name] for name in history.GRAPH))


def inventory(files):
    return {name: {"mode": mode, "sha256": source.sha(value)}
        for name, (mode, value) in files.items()}


def produce(output, seconds):
    global PHASE
    source.require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    PHASE = "parent"
    parent_files, parent = history.load_parent()
    PHASE = "fourth"
    fourth = history.transform(parent_files, read_patch(history.PATCH_NAME))
    fourth_inventory = inventory(fourth)
    PHASE = "fifth"
    result = transform(fourth, read_patch(PATCH_NAME))
    selected_inventory = inventory(result)
    receipt = {
        "schema_version": 1, "kind": KIND,
        "status": "verified-owner-status-source-pending-sdk-and-schema",
        "commit": source.COMMIT,
        "parent_source_root": str(history.PARENT),
        "parent_source_receipt_sha256": history.PARENT_RECEIPT_SHA,
        "parent_source_inventory_sha256": history.PARENT_INVENTORY_SHA,
        "fourth_source_inventory_sha256": source.sha(source.canonical(fourth_inventory)),
        "fourth_source_inventory": fourth_inventory,
        "patch_sha256": history.PARENT_PATCHES + [history.PATCH_SHA, PATCH_SHA],
        "patches": parent["patches"] + [
            {"patch_sha256": history.PATCH_SHA, "paths": sorted(history.ALLOWED)},
            {"patch_sha256": PATCH_SHA, "paths": sorted(ALLOWED)}],
        "fifth_preimages": PREIMAGES,
        "source_inventory": selected_inventory,
        "inventory_sha256": source.sha(source.canonical(selected_inventory)),
        "tracked_files": len(result),
        "source_bytes": sum(len(value) for _, value in result.values()),
        "graph_files": {name: {"sha256": source.sha(result[name][1])} for name in history.GRAPH},
        "physical_mode_policy": "bazel-retained-export-all-regular-and-directories-0555-v1",
        "sdk_metadata_qualified": False, "schema_producer_qualified": False,
        "native_compile_passed": False, "native_support": False,
        "provider_evaluation": False, "live_handoff_proven": False,
    }
    PHASE = "output"
    root = source.write_source(output, result)
    try:
        fd = os.open("source-receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=root)
        with os.fdopen(fd, "wb") as stream:
            stream.write(source.encoded(receipt))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(root)
        os.fchmod(root, 0o555)
    finally:
        os.close(root)
    return receipt


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
        and os.environ.get("TEST_TIMEOUT"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    produce(root / "owner-status-source", seconds)
    print("owner status source composed; SDK schema compiler and live proof unrun")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("owner status source refused at " + (PHASE if PHASE in PHASES else "parent"), file=sys.stderr)
        raise SystemExit(1) from None
