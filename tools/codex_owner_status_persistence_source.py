"""Exact N1 + reviewed persistence v3 source composition, no native execution."""
import os
from pathlib import Path
import sys
import time

import codex_live_source as source
import codex_protocol_history_source as history
import codex_owner_status_binding as parent
import codex_owner_status_source as status

KIND = "omux-owner-status-persistence-source-v1"
REVIEWED_NATIVE_SHA = "be45d43b100fde8628f04371e37950e2998ec97fe14f4425ff5710ccd2ae57a0"
REVIEWED_NATIVE_NAME = "2026-10-09-native-export-bounded-persist-v3.UNAPPLIED.patch"
NORMALIZED_NATIVE_NAME = "2026-10-09-native-export-bounded-persist-v3-normalized.UNAPPLIED.patch"
NORMALIZED_NATIVE_SHA = "137fd38212f0e6c4848b2790714f4d17dddd2d51d237c5f9f376c34d3aea99e0"
PATCH_NAME = "2026-10-09-native-export-bounded-persist-v3-strict.UNAPPLIED.patch"
PATCH_SHA = "2fde65504b83e1fd72684618a631409418a6b9841db33243ed60733f9f031d26"
PREIMAGES = {
    "codex-rs/app-server-protocol/src/protocol/common.rs": "08efb6a54374fd4a92f94c840b09dcac5c75c0dd90bcdc84d8f5c3d9996bd691",
    "codex-rs/app-server-protocol/src/protocol/v2/thread.rs": "e2b7dd948363103cf55a900b1ddd836f34d63ce4dba88669db4a7f6aae8b7711",
    "codex-rs/app-server/src/message_processor.rs": "85d0103dbda27479b6ddd2d21d12772256c645002b183ee4cc4d4d9018779e2b",
    "codex-rs/app-server/src/request_processors/thread_processor.rs": "2f44f27a7b4adc47b8959812859c238ebaa09a9415f5113a67a69917d259d00a",
    "codex-rs/tui/src/app_server_session.rs": "b2373c1424d6307644b6ad4d83a2dacfa5c4043a2e4677c2121e273b0d381815",
    "codex-rs/tui/src/app/transcript_export.rs": "079f1e446c29616048fbd4fe00cc1aa4f8d7945889ebb59b6e6eff2f66c547f3",
    "codex-rs/tui/src/app/transcript_export_tests.rs": "0d8a5cd9e4c00347efbd3e91667e7b86fab919e8d92262143c0ce4446a312260",
    "codex-rs/thread-store/src/local/thread_history_materialization_tests.rs": "64f8eb32db33cdea3a4ecf1226663e6cf053d6d453f77d1efb2dbe09a5b753b1",
}
ALLOWED = frozenset(PREIMAGES)
AFTERIMAGES = {
    "codex-rs/app-server-protocol/src/protocol/common.rs": "6bd00f39bc428f785a0fdb8579a7c1d46abde8610fcf44b84e107a3415b0caa6",
    "codex-rs/app-server-protocol/src/protocol/v2/thread.rs": "27aa7aaaac97abeb05134f5838dbb0068b7f0634b941297090b0eca659acb415",
    "codex-rs/app-server/src/message_processor.rs": "3a6d5b3cc11ce411e0c35fd3a8286e45426cd298ef1085657b6cf79181ddc4b7",
    "codex-rs/app-server/src/request_processors/thread_processor.rs": "b14465f31ee8f3741bfb7d716ff51cba1291f8ff451d013990ee76898d70e47e",
    "codex-rs/tui/src/app_server_session.rs": "43fd053245b65a57e10ae37cbe1fbb274c01639332abde5cb7a39d08b4390fd9",
    "codex-rs/tui/src/app/transcript_export.rs": "79323b0b4afe4a6a4c89b21fa465b90277d9ccaf4859acf7026aab89d430013c",
    "codex-rs/tui/src/app/transcript_export_tests.rs": "0208178b673c9777363021390bb684dda220c11e319ce12e8e61ea8e54d12c04",
    "codex-rs/thread-store/src/local/thread_history_materialization_tests.rs": "1b1e0476a97bd39f1add7a35b236c47cf7991476461a85daea89825fd0082c08",
}
PHASE = "parent"
PHASES = frozenset(("parent", "patch", "output", "readback"))


def frame_patch(raw):
    """Require unique strict-parser headers; return every source byte unchanged."""
    lines = raw.decode("utf-8").splitlines(keepends=True)
    seen, framed = set(), []
    for index, line in enumerate(lines):
        if line.startswith("diff --git "):
            parts = line.removesuffix("\n").split(" ")
            source.require(len(parts) == 4 and parts[2].startswith("a/"))
            name = parts[2][2:]
            source.require(name in ALLOWED and name not in seen and parts[3] == "b/" + name
                and index + 2 < len(lines)
                and lines[index + 1] == f"--- a/{name}\n" and lines[index + 2] == f"+++ b/{name}\n")
            seen.add(name)
        framed.append(line)
    source.require(seen == ALLOWED)
    return "".join(framed)


def validate_transition(before, after):
    source.require(set(before) == set(after)
        and {name for name in before if before[name] != after[name]} == ALLOWED
        and all(before[name][0] == after[name][0] for name in before)
        and all(before[name] == after[name] for name in history.GRAPH))


def transform(files, raw):
    source.require(type(raw) is bytes and source.sha(raw) == PATCH_SHA and ALLOWED <= set(files)
        and set(AFTERIMAGES) == ALLOWED)
    for name, pin in PREIMAGES.items():
        source.require(files[name][0] == "100644" and source.sha(files[name][1]) == pin)
    changes = status.patch_io.apply_exact(frame_patch(raw), {name: files[name][1] for name in ALLOWED})
    source.require(set(changes) == ALLOWED)
    result = dict(files)
    for name, value in changes.items():
        source.require(source.sha(value) == AFTERIMAGES[name])
        result[name] = ("100644", value)
    validate_transition(files, result)
    return result


def expected_receipt(report, result):
    """Pure exact receipt construction shared by production and reconstruction."""
    inventory = status.inventory(result)
    return {
        "schema_version": 1, "kind": KIND,
        "status": "verified-owner-status-persistence-source-pending-sdk-and-schema",
        "commit": source.COMMIT, "parent_source_root": str(parent.ROOT),
        "parent_source_receipt_sha256": parent.RECEIPT_SHA,
        "parent_source_inventory_sha256": parent.INVENTORY_SHA,
        "patch_sha256": report["patch_sha256"] + [PATCH_SHA],
        "patches": report["patches"] + [{"patch_sha256": PATCH_SHA, "paths": sorted(ALLOWED)}],
        "persistence_preimages": PREIMAGES,
        "persistence_afterimages": AFTERIMAGES,
        "reviewed_native_patch_sha256": REVIEWED_NATIVE_SHA,
        "normalized_native_patch_sha256": NORMALIZED_NATIVE_SHA,
        "patch_position_policy": "unique-file-exact-original-and-cumulative-destination-v1",
        "source_inventory": inventory, "inventory_sha256": source.sha(source.canonical(inventory)),
        "tracked_files": len(result), "source_bytes": sum(len(value) for _, value in result.values()),
        "graph_files": report["graph_files"],
        "physical_mode_policy": "bazel-retained-export-all-regular-and-directories-0555-v1",
        "sdk_metadata_qualified": False, "schema_producer_qualified": False,
        "native_compile_passed": False, "native_support": False,
        "provider_evaluation": False, "live_handoff_proven": False,
    }


def produce(output, seconds):
    global PHASE
    source.require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    PHASE = "parent"
    report, before = parent.load_verified_source()
    PHASE = "patch"
    source.require(source.sha(status.read_patch(REVIEWED_NATIVE_NAME)) == REVIEWED_NATIVE_SHA)
    source.require(source.sha(status.read_patch(NORMALIZED_NATIVE_NAME)) == NORMALIZED_NATIVE_SHA)
    result = transform(before, status.read_patch(PATCH_NAME))
    receipt = expected_receipt(report, result)
    PHASE = "output"
    root = source.write_source(output, result)
    try:
        PHASE = "readback"
        after_report, after_files = parent.load_verified_source()
        source.require(after_report == report and after_files == before)
        writer = os.open("source-receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
        with os.fdopen(writer, "wb") as stream:
            stream.write(source.encoded(receipt))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(root)
        os.fchmod(root, 0o555)
    finally:
        os.close(root)
        source.DEADLINE = None
    return receipt


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_TIMEOUT") and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    produce(root / "owner-status-persistence-source", seconds)
    print("N1 persistence successor composed; SDK schema compiler and native proof unrun")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("persistence successor source refused at " + (PHASE if PHASE in PHASES else "parent"), file=sys.stderr)
        raise SystemExit(1) from None
