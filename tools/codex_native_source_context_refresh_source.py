"""Eighth source from actual seventh + exact read-only refresh; no native IO."""
import json
import os
from pathlib import Path
import sys
import time

import codex_live_source as source
import codex_native_source_context_source as seventh

ROOT = Path(__file__).parent.parent
INPUT = "integrations/codex-upstream/native-source-context-seventh-input.json"
PATCH = "integrations/codex-upstream/native-source-context-readonly-refresh-v1.patch"
PATCH_SHA = "f33299b3b9f82f01f2f9377e9e646381626eee5afd7c5776ab7ae6c532d1f7d8"
PATCH_BYTES = 26038
KIND = "omux-native-source-context-refresh-source-v1"
PREIMAGES = {"codex-rs/app-server/src/owner_control.rs": "2feb63d91dbf1c3fb4df765a21c36df1252895559e22b85a3c6dbf9ed73bc42c", "codex-rs/app-server/src/owner_source_context.rs": "3e07fa9ed211c2254ef14c15f7ede97a49265745f986c4c3ea95de681b5aaa67", "codex-rs/core/src/native_peer.rs": "a00174eea5395155a994ef2a5a36b04f4aac3d884c44551921982cca4841cb61"}
AFTERIMAGES = {"codex-rs/app-server/src/owner_control.rs": "ddf145fa4e2f7858f1ccd47053ba02636def7bb267c484e106743f4dbdc50417", "codex-rs/app-server/src/owner_source_context.rs": "0ae0f46e3c2c16db7ae97241f44565281d9b1740edc37c4fd7fd59dec736044b", "codex-rs/core/src/native_peer.rs": "20dcb0de30f0f2c0ab1d2834aa6f9aab41dce544a95288b4eff448defe08e684"}
FLAGS = ("native_source_finalized", "sdk_metadata_qualified", "schema_producer_qualified", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven", "daemon_context_acquisition_implemented")
PHASE = "input"
PHASES = frozenset(("input", "parent", "patch", "output", "readback"))


def declared(relative, maximum):
    path = (ROOT / relative).resolve(strict=True)
    fd = source.directory(path.parent)
    try:
        raw, mode = source.read(fd, path.name, maximum)
    finally:
        os.close(fd)
    source.require(mode in (0o444, 0o555, 0o644))
    return raw


def load_input():
    value = json.loads(declared(INPUT, 8192), object_pairs_hook=source.unique)
    source.require(type(value) is dict and set(value) == {"schema_version", "status", "root", "receipt_sha256", "receipt_bytes", "inventory_sha256", "source_members", "source_bytes"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1 and value["status"] == "actual-seventh-source-pinned")
    source.require(type(value["root"]) is str and Path(value["root"]).is_absolute()
        and str(Path(value["root"])) == value["root"] and ".." not in Path(value["root"]).parts)
    for name in ("receipt_sha256", "inventory_sha256"):
        source.require(type(value[name]) is str and len(value[name]) == 64 and all(c in "0123456789abcdef" for c in value[name]))
    for name, limit in (("receipt_bytes", source.MAX_METADATA), ("source_members", 20000), ("source_bytes", source.MAX_SOURCE)):
        source.require(type(value[name]) is int and 0 < value[name] <= limit)
    return value


def reconstruct_seventh():
    report, before = seventh.parent.load_verified_source()
    result = seventh.transform(before, seventh.read_patch())
    return seventh.expected_receipt(report, result), result


def actual_receipt(config):
    root = source.directory(Path(config["root"]))
    try:
        source.require(seventh.parent.identity(root)[3] == 0o555)
        raw, mode = source.read(root, "source-receipt.json", source.MAX_METADATA)
    finally:
        os.close(root)
    source.require(mode == 0o555 and len(raw) == config["receipt_bytes"] and source.sha(raw) == config["receipt_sha256"])
    return json.loads(raw, object_pairs_hook=source.unique)


def validate_parent(report, files, config):
    source.require(report["kind"] == seventh.KIND and report["status"] == "verified-seventh-native-context-source-uncompiled"
        and report["commit"] == source.COMMIT and report["patch_sha256"] == seventh.PARENT_PATCHES + [seventh.PATCH_SHA]
        and len(report["patches"]) == 7 and all(report[name] is False for name in FLAGS)
        and report["context_rotation_implemented"] is False)
    inventory = seventh.status.inventory(files)
    source.require(report["source_inventory"] == inventory and report["inventory_sha256"] == source.sha(source.canonical(inventory)) == config["inventory_sha256"]
        and report["tracked_files"] == len(files) == config["source_members"]
        and report["source_bytes"] == sum(len(raw) for _, raw in files.values()) == config["source_bytes"])


def load_seventh(config):
    root = source.directory(Path(config["root"]))
    try:
        anchor = seventh.parent.identity(root)
        report = actual_receipt(config)
        expected, files = reconstruct_seventh()
        source.require(report == expected and source.sha(source.encoded(expected)) == config["receipt_sha256"])
        validate_parent(report, files, config)
        source.verify_written(Path(config["root"]) / "source", files)
        after, after_files = reconstruct_seventh()
        source.require(after == expected and after_files == files and actual_receipt(config) == report)
        named = source.directory(Path(config["root"]))
        try:
            source.require(seventh.parent.identity(named) == anchor)
        finally:
            os.close(named)
        return report, files
    finally:
        os.close(root)


def read_patch():
    raw = declared(PATCH, PATCH_BYTES)
    source.require(len(raw) == PATCH_BYTES and source.sha(raw) == PATCH_SHA)
    return raw


def transform(files, raw):
    source.require(type(raw) is bytes and len(raw) == PATCH_BYTES and len(raw) <= source.MAX_PATCH and raw.endswith(b"\n") and source.sha(raw) == PATCH_SHA)
    lines = raw.decode("utf-8").splitlines(keepends=True)
    seen = set()
    for at, line in enumerate(lines):
        if line.startswith("diff --git "):
            parts = line.removesuffix("\n").split(" ")
            source.require(len(parts) == 4 and parts[2].startswith("a/"))
            name = parts[2][2:]
            source.require(name in PREIMAGES and name not in seen and parts[3] == "b/" + name
                and lines[at + 1] == f"--- a/{name}\n" and lines[at + 2] == f"+++ b/{name}\n")
            seen.add(name)
    source.require(seen == set(PREIMAGES) and set(PREIMAGES) <= set(files))
    for name, pin in PREIMAGES.items():
        source.require(files[name][0] == "100644" and source.sha(files[name][1]) == pin)
    changes = seventh.status.patch_io.apply_exact("".join(lines), {name: files[name][1] for name in PREIMAGES})
    source.require(set(changes) == set(PREIMAGES))
    result = dict(files)
    for name, raw_after in changes.items():
        source.require(source.sha(raw_after) == AFTERIMAGES[name])
        result[name] = ("100644", raw_after)
    validate_transition(files, result)
    return result


def validate_transition(before, after):
    source.require(set(before) == set(after) and {name for name in before if before[name] != after[name]} == set(PREIMAGES)
        and all(before[name] == after[name] for name in before if name not in PREIMAGES)
        and all(before[name][0] == after[name][0] == "100644" for name in PREIMAGES)
        and all(before[name] == after[name] for name in seventh.history.GRAPH))


def expected_receipt(report, result, config):
    inventory = seventh.status.inventory(result)
    return {"schema_version": 1, "kind": KIND, "status": "verified-eighth-readonly-refresh-source-uncompiled",
        "commit": source.COMMIT, "parent_source_root": config["root"], "parent_source_receipt_sha256": config["receipt_sha256"],
        "parent_source_inventory_sha256": config["inventory_sha256"], "patch_sha256": report["patch_sha256"] + [PATCH_SHA],
        "patches": report["patches"] + [{"patch_sha256": PATCH_SHA, "paths": sorted(PREIMAGES)}],
        "refresh_preimages": PREIMAGES, "refresh_afterimages": AFTERIMAGES,
        "source_inventory": inventory, "inventory_sha256": source.sha(source.canonical(inventory)),
        "tracked_files": len(result), "source_bytes": sum(len(raw) for _, raw in result.values()), "graph_files": report["graph_files"],
        "patch_position_policy": "unique-file-exact-original-and-cumulative-destination-v1",
        "physical_mode_policy": "bazel-retained-export-all-regular-and-directories-0555-v1",
        "source_context_scope": "single-supervised-readonly-snapshot-memory-adoption-original-deadline",
        "hint_scope": "immutable-owner-locator-not-current-context-or-credential-authority",
        "context_rotation_source_present": True, "context_rotation_runtime_qualified": False,
        "finite_kernel_shutdown_proven": False, **{name: False for name in FLAGS}}


def produce(output, seconds):
    global PHASE
    source.require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic() + seconds
    root = None
    try:
        PHASE = "input"
        config = load_input()
        PHASE = "parent"
        report, before = load_seventh(config)
        PHASE = "patch"
        raw = read_patch()
        result = transform(before, raw)
        receipt = expected_receipt(report, result, config)
        PHASE = "output"
        root = source.write_source(output, result)
        PHASE = "readback"
        source.verify_written(output / "source", result)
        after_report, after_files = load_seventh(config)
        source.require(after_report == report and after_files == before and load_input() == config and read_patch() == raw)
        source.verify_written(output / "source", result)
        named = source.directory(output)
        try:
            source.require(seventh.parent.identity(named) == seventh.parent.identity(root))
        finally:
            os.close(named)
        source.tick()
        writer = os.open("source-receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
        with os.fdopen(writer, "wb") as stream:
            stream.write(source.encoded(receipt)); stream.flush()
            os.fchmod(stream.fileno(), 0o444); os.fsync(stream.fileno())
        os.fsync(root); os.fchmod(root, 0o555)
        source.tick()
        return receipt
    finally:
        if root is not None: os.close(root)
        source.DEADLINE = None


def main():
    source.require(len(sys.argv) == 1 and os.environ.get("TEST_TIMEOUT") and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    seconds = min(840, int(os.environ["TEST_TIMEOUT"]) - 60)
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    produce(output / "native-source-context-refresh-source", seconds)
    print("Eighth source composed; compiler SDK schema acquisition and native proof unqualified")


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print("native context refresh source refused at " + (PHASE if PHASE in PHASES else "input"), file=sys.stderr)
        raise SystemExit(1) from None
