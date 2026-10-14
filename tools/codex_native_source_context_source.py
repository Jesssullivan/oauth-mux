"""Exact six-patch N3 plus optional read-only native context; no native execution."""
import os
from pathlib import Path
import sys
import time

import codex_live_source as source
import codex_owner_status_persistence_binding as parent
import codex_owner_status_source as status
import codex_protocol_history_source as history

ROOT = Path(__file__).parent.parent  # Unresolved declared Bazel runfiles root.
PATCH_RELATIVE = "integrations/codex-upstream/native-source-context-v1.patch"
PATCH_SHA = "ff7e7971019bd4e7bbf80a6aa5b86c787fc6971f2df0cd60399471ef3783e4a2"
PATCH_BYTES = 37585
KIND = "omux-native-source-context-source-v1"
PREIMAGES = {'codex-rs/app-server/src/lib.rs': '4c7a949948f96315b08a95ffd79e6a36fd72d3453527511fd5aad4b54242d31d', 'codex-rs/app-server/src/message_processor.rs': '3a6d5b3cc11ce411e0c35fd3a8286e45426cd298ef1085657b6cf79181ddc4b7', 'codex-rs/app-server/src/owner_control.rs': '87f8a0141b0e60bb755e89dac2c6b841ee608fc4bc126d160eb8ab0ea6e998f7', 'codex-rs/app-server-protocol/src/protocol/common.rs': '6bd00f39bc428f785a0fdb8579a7c1d46abde8610fcf44b84e107a3415b0caa6', 'codex-rs/app-server-protocol/src/protocol/v2/mod.rs': 'c7bb239424a20be919aca67e5df693aa38b421cd6985d94ff69cae49958c6b93'}
AFTERIMAGES = {'codex-rs/app-server/src/lib.rs': 'c8e04310ebeeee0639b6769e4f15c6808b618d14fa7dd5d84ebe53610d1f9a01', 'codex-rs/app-server/src/message_processor.rs': '5a3a139656a638ce3f242a0208c45b548605db8e8be8c424ba80bb879bfe0d8c', 'codex-rs/app-server/src/owner_control.rs': '2feb63d91dbf1c3fb4df765a21c36df1252895559e22b85a3c6dbf9ed73bc42c', 'codex-rs/app-server/src/owner_source_context.rs': '3e07fa9ed211c2254ef14c15f7ede97a49265745f986c4c3ea95de681b5aaa67', 'codex-rs/app-server-protocol/src/protocol/common.rs': '7c0d8213fbf9e135d9b746427c009e5e95861777652083853c9a788fd3b7d9a9', 'codex-rs/app-server-protocol/src/protocol/v2/mod.rs': 'b0abea332e4fc2211579d0959fe19ba20433c3bf3a70595bac5bed7bd3dec94f', 'codex-rs/app-server-protocol/src/protocol/v2/owner_source_context.rs': '168084d7d40478ef594b831ca62d6cb01b60e901b387a434b4a6dda396778566'}
ALLOWED = frozenset(AFTERIMAGES)
ADDED = ALLOWED - frozenset(PREIMAGES)
PARENT_PATCHES = history.PARENT_PATCHES + [history.PATCH_SHA, status.PATCH_SHA, parent.successor.PATCH_SHA]
PHASE = "parent"
PHASES = frozenset(("parent", "patch", "output", "readback"))


def read_patch():
    # Resolve only the fixed declared data member, then use bounded nofollow IO.
    path = (ROOT / PATCH_RELATIVE).resolve(strict=True)
    fd = source.directory(path.parent)
    try:
        raw, mode = source.read(fd, path.name, PATCH_BYTES)
    finally:
        os.close(fd)
    source.require(mode in (0o444, 0o555, 0o644) and len(raw) == PATCH_BYTES
        and source.sha(raw) == PATCH_SHA)
    return raw


def frame_patch(raw):
    source.require(type(raw) is bytes and len(raw) == PATCH_BYTES
        and len(raw) <= source.MAX_PATCH and raw.endswith(b"\n")
        and source.sha(raw) == PATCH_SHA)
    lines = raw.decode("utf-8").splitlines(keepends=True)
    seen = set()
    for index, line in enumerate(lines):
        if line.startswith("diff --git "):
            parts = line.removesuffix("\n").split(" ")
            source.require(len(parts) == 4 and parts[2].startswith("a/"))
            name = parts[2][2:]
            source.require(name in ALLOWED and name not in seen and parts[3] == "b/" + name)
            offset = index + 1
            if name in ADDED:
                source.require(offset < len(lines) and lines[offset] == "new file mode 100644\n")
                offset += 1
            source.require(offset + 1 < len(lines)
                and lines[offset] == ("--- /dev/null\n" if name in ADDED else f"--- a/{name}\n")
                and lines[offset + 1] == f"+++ b/{name}\n")
            seen.add(name)
    source.require(seen == ALLOWED)
    return "".join(lines)


def validate_transition(before, after):
    source.require(set(after) == set(before) | ADDED and ADDED.isdisjoint(before)
        and {name for name in before if before[name] != after[name]} == set(PREIMAGES)
        and all(before[name] == after[name] for name in before if name not in PREIMAGES)
        and all(before[name][0] == after[name][0] == "100644" for name in PREIMAGES)
        and all(after[name][0] == "100644" for name in ADDED)
        and all(before[name] == after[name] for name in history.GRAPH))


def transform(files, raw):
    source.require(set(PREIMAGES) | ADDED == ALLOWED and ADDED.isdisjoint(files)
        and set(PREIMAGES) <= set(files))
    for name, pin in PREIMAGES.items():
        source.require(files[name][0] == "100644" and source.sha(files[name][1]) == pin)
    changes = status.patch_io.apply_exact(frame_patch(raw),
        {name: files[name][1] for name in PREIMAGES})
    source.require(set(changes) == ALLOWED)
    result = dict(files)
    for name, value in changes.items():
        source.require(source.sha(value) == AFTERIMAGES[name])
        result[name] = ("100644", value)
    validate_transition(files, result)
    return result


def expected_receipt(report, result):
    inventory = status.inventory(result)
    source.require(report["patch_sha256"] == PARENT_PATCHES and len(report["patches"]) == 6
        and report["kind"] == parent.successor.KIND and report["commit"] == source.COMMIT
        and report["inventory_sha256"] == parent.INVENTORY_SHA
        and all(report[key] is False for key in ("sdk_metadata_qualified", "schema_producer_qualified",
            "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven")))
    return {
        "schema_version": 1, "kind": KIND,
        "status": "verified-seventh-native-context-source-uncompiled",
        "commit": source.COMMIT, "parent_source_root": str(parent.ROOT),
        "parent_source_receipt_sha256": parent.RECEIPT_SHA,
        "parent_source_inventory_sha256": parent.INVENTORY_SHA,
        "patch_sha256": report["patch_sha256"] + [PATCH_SHA],
        "patches": report["patches"] + [{"patch_sha256": PATCH_SHA, "paths": sorted(ALLOWED)}],
        "context_preimages": PREIMAGES, "context_afterimages": AFTERIMAGES,
        "added_paths": sorted(ADDED),
        "patch_position_policy": "unique-file-exact-original-and-cumulative-destination-v1",
        "source_inventory": inventory, "inventory_sha256": source.sha(source.canonical(inventory)),
        "tracked_files": len(result), "source_bytes": sum(len(value) for _, value in result.values()),
        "graph_files": report["graph_files"],
        "physical_mode_policy": "bazel-retained-export-all-regular-and-directories-0555-v1",
        "source_context_platform": "linux-x86_64",
        "source_context_scope": "optional-initial-read-only-declaration",
        "context_rotation_implemented": False, "daemon_context_acquisition_implemented": False,
        "native_source_finalized": False, "sdk_metadata_qualified": False,
        "schema_producer_qualified": False, "native_compile_passed": False,
        "native_support": False, "provider_evaluation": False, "live_handoff_proven": False,
    }


def produce(output, seconds):
    global PHASE
    source.require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    root = None
    try:
        PHASE = "parent"
        report, before = parent.load_verified_source()
        PHASE = "patch"
        raw = read_patch()
        result = transform(before, raw)
        receipt = expected_receipt(report, result)
        PHASE = "output"
        root = source.write_source(output, result)
        PHASE = "readback"
        source.verify_written(output / "source", result)
        after_report, after_files = parent.load_verified_source()
        source.require(after_report == report and after_files == before and read_patch() == raw)
        source.verify_written(output / "source", result)
        named = source.directory(output)
        try:
            source.require(parent.identity(named) == parent.identity(root))
        finally:
            os.close(named)
        writer = os.open("source-receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=root)
        with os.fdopen(writer, "wb") as stream:
            stream.write(source.encoded(receipt))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(root)
        os.fchmod(root, 0o555)
        return receipt
    finally:
        if root is not None:
            os.close(root)
        source.DEADLINE = None


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_TIMEOUT")
        and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    produce(output / "native-source-context-source", seconds)
    print("Seventh source composed; native compiler schema SDK acquisition and live proof unqualified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("native context source refused at " + (PHASE if PHASE in PHASES else "parent"), file=sys.stderr)
        raise SystemExit(1) from None
