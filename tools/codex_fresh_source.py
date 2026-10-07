"""Prepare one fresh, uncompiled adapter source epoch; no subprocess or fetch."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ROOT = Path(__file__).parent.parent  # Declared runfiles path, deliberately unresolved.
sys.path.insert(0, str(ROOT / "integrations/codex-upstream"))
sys.path.insert(0, str(ROOT / "integrations/codex-adapter-delivery"))
import retirement_delta
import restore_source
from codex_recovery_delta import BASE_PATCH, selected_paths
from patch_io import apply_exact, combine_changes, deterministic_archive, digest, verify_artifact
from refresh_artifact import text_file, text_patch
from restore_pristine_inputs import original_files, unique_object

PRISTINE_SHA = "dbe1a1ec6ce7c6a981b5adf2410be4ae68f8bc906b1dec6b5e65a78efbc3292d"
PRISTINE_RECEIPT_SHA = "8a66e297631d2767e373e0fd8cfe9c7764dbb6357bb2cf61033a6cde1d0a61ba"
MANIFEST_SHA = "8eb4ed424b0373bd77250eaf59334cb765141d1fc6a2885480c840771d462b23"
VALIDATION_SHA = "1e0f27681a57f4c7d2102d69d01f73586d743341b9baea306e863069c74fc86a"
RETIREMENT_SHA = "619f98db5a54988d43b6d3125fe0720577acdb3f005a6ce0ce7070ac7a1e106e"
RETIREMENT_BEFORE = "57def794ace1d8ac0f54376eb6bd8204053d73f5125de851cbc0dc6230489d37"
THREAD_MANAGER = "codex-rs/core/src/thread_manager.rs"
MAX_SOURCE = 512 * 1024 * 1024
MAX_DELTA = 64 * 1024 * 1024
MAX_METADATA = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_bound(path, limit, expected=None):
    fd = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "fresh input exceeds bound")
        value = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(value) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns), "fresh input changed during read")
    require(expected is None or digest(value) == expected, "fresh input digest mismatch")
    return value


def apply_recovery(files, delta, receipt, allowed):
    require(receipt.get("status") == "scoped-source-delta-awaiting-review" and receipt.get("commit") == restore_source.COMMIT
            and receipt.get("baseline_manifest_sha256") == MANIFEST_SHA and receipt.get("baseline_patch_sha256") == BASE_PATCH
            and receipt.get("patch_sha256") == digest(delta), "recovery receipt authority mismatch")
    selected, changes = receipt.get("selected_inputs"), receipt.get("changes")
    require(isinstance(selected, dict) and set(selected) == set(allowed) and isinstance(changes, dict)
            and set(changes) <= set(allowed), "recovery receipt path selection mismatch")
    before = {name: files[name][1] for name in allowed}
    updated = apply_exact(delta.decode(), before)
    require(set(updated) == set(changes), "recovery patch and receipt differ")
    for name in allowed:
        require(selected[name] == {"before_sha256": digest(before[name]), "after_sha256": digest(updated.get(name, before[name]))},
                "recovery selected digest mismatch")
        if name in changes:
            require(changes[name] == selected[name], "recovery change digest mismatch")
    result = dict(files)
    for name, value in updated.items():
        result[name] = (files[name][0], value)
    return result


def apply_retirement(files, expected_before):
    mode, value = files[THREAD_MANAGER]
    require(digest(value) == expected_before == RETIREMENT_BEFORE, "retirement before digest mismatch")
    result = dict(files)
    result[THREAD_MANAGER] = (mode, retirement_delta.transform(value))
    return result


def product_delta(originals, product):
    patches, binary, changes = [], {}, {}
    for name, (mode, value) in sorted(product.items()):
        original = originals.get(name)
        if original == (mode, value):
            continue
        require(name.startswith("codex-rs/") and mode in ("100644", "100755"), "unexpected product path or mode")
        require(original is None or original[0] == mode, "product mode changes require separate review")
        before = original[1] if original else None
        is_text = text_file(name, value) and (before is None or text_file(name, before))
        if is_text:
            patches.append(text_patch(name, before, value))
        else:
            binary[name] = value
        changes[name] = {"before_sha256": digest(before) if before is not None else None,
                         "after_sha256": digest(value), "representation": "patch" if is_text else "binary_overlay"}
    patch = "".join(patches).encode()
    require(len(patch) <= MAX_DELTA, "full product delta exceeds bound")
    require(apply_exact(patch.decode(), {name: value for name, (_, value) in originals.items()}) ==
            {name: product[name][1] for name, entry in changes.items() if entry["representation"] == "patch"},
            "full product patch exact roundtrip failed")
    return patch, deterministic_archive(binary), changes


def validate_paths(files):
    require(len(files) <= 50000 and sum(len(value) for _, value in files.values()) <= MAX_SOURCE, "fresh source inventory exceeds bound")
    for name, (mode, value) in files.items():
        restore_source.safe_name(name)
        require(name != ".", "fresh source path is not a file")
        require(mode in ("100644", "100755", "120000"), "fresh source mode mismatch")
        for parent in PurePosixPath(name).parents:
            require(str(parent) not in files, "fresh source file occupies parent path")
        if mode == "120000":
            target = PurePosixPath(value.decode())
            require(not target.is_absolute() and "\0" not in value.decode(), "fresh source symlink target is unsafe")
            # Normalize path components without touching any operator filesystem.
            parts = list(PurePosixPath(name).parent.parts)
            for part in target.parts:
                if part == "..":
                    require(parts, "fresh source symlink escapes root")
                    parts.pop()
                elif part != ".":
                    parts.append(part)


def trusted_parent(path):
    require(path.is_absolute() and ".." not in path.parts, "fresh output parent is noncanonical")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid in (0, os.getuid()), "fresh ancestor has foreign ownership")
            # Sticky shared roots protect each owned child from unrelated users.
            require(not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX),
                    "fresh ancestor is writable without sticky custody")
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "fresh immediate parent is untrusted")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def source_parent(source_fd, parts):
    descriptor = os.dup(source_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, mode=0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "fresh source directory custody mismatch")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def materialize(root, files):
    validate_paths(files)
    require(root.is_absolute() and root.name not in ("", ".", ".."), "fresh output is noncanonical")
    parent_fd = trusted_parent(root.parent)
    root_fd = source_fd = None
    try:
        os.mkdir(root.name, mode=0o700, dir_fd=parent_fd)
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        os.mkdir("source", mode=0o700, dir_fd=root_fd)
        source_fd = os.open("source", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        for name, (mode, value) in files.items():
            parts = PurePosixPath(name).parts
            directory = source_parent(source_fd, parts[:-1])
            try:
                if mode == "120000":
                    os.symlink(value.decode(), parts[-1], dir_fd=directory)
                else:
                    fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(value)
                        stream.flush()
                        os.fchmod(stream.fileno(), 0o755 if mode == "100755" else 0o644)
                        os.fsync(stream.fileno())
            finally:
                os.close(directory)
        visible = root.lstat()
        require((visible.st_dev, visible.st_ino) == (root_info.st_dev, root_info.st_ino), "fresh output root moved during write")
        source = root / "source"
        restore_source.verify_tree(source, files)
        return source
    finally:
        for descriptor in (source_fd, root_fd, parent_fd):
            if descriptor is not None:
                os.close(descriptor)


def publish_outputs(root, outputs):
    """Publish only into a descriptor-verified private epoch directory."""
    descriptor = trusted_parent(root)
    try:
        info = os.fstat(descriptor)
        for name, value in outputs.items():
            require(PurePosixPath(name).name == name and name not in ("", ".", ".."), "unsafe output basename")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=descriptor)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        visible = root.lstat()
        require((visible.st_dev, visible.st_ino) == (info.st_dev, info.st_ino), "fresh output root moved during publication")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("pristine-archive", "pristine-receipt", "artifact-dir", "recovery-patch", "recovery-receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--recovery-patch-sha256", required=True)
    parser.add_argument("--recovery-receipt-sha256", required=True)
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args()
    original, tree = original_files(args.pristine_archive, PRISTINE_SHA, args.pristine_receipt, PRISTINE_RECEIPT_SHA)
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    manifest = json.loads(read_bound(artifact / "manifest.json", MAX_METADATA, MANIFEST_SHA), object_pairs_hook=unique_object)
    validation = json.loads(read_bound(artifact / "validation.json", MAX_METADATA, VALIDATION_SHA), object_pairs_hook=unique_object)
    for name in (manifest["patch_file"], manifest["binary_overlay_file"], "upstream-base.tar.gz"):
        read_bound(artifact / name, MAX_DELTA)
    base, patch, overlay = verify_artifact(artifact, manifest)
    restore_source.verify_packaged_base(original, base, manifest)
    product = dict(original)
    for name, value in combine_changes(patch, overlay, base, manifest).items():
        product[name] = (original.get(name, ("100644", b""))[0], value)
    validation_overlay = read_bound(artifact / "validation-overlay.patch", MAX_DELTA,
                                    validation["validation_environment"]["validation_overlay_sha256"])
    prepared = dict(product)
    for name, value in restore_source.overlay_changes(validation_overlay, {name: original[name][1] for name in restore_source.OVERLAY_PATHS}).items():
        prepared[name] = (original[name][0], value)
    delta = read_bound(args.recovery_patch, MAX_DELTA, args.recovery_patch_sha256)
    recovery = json.loads(read_bound(args.recovery_receipt, MAX_METADATA, args.recovery_receipt_sha256), object_pairs_hook=unique_object)
    prepared = apply_recovery(prepared, delta, recovery, selected_paths(manifest))
    require(digest(read_bound(Path(retirement_delta.__file__), MAX_METADATA)) == RETIREMENT_SHA, "retirement implementation pin mismatch")
    prepared = apply_retirement(prepared, RETIREMENT_BEFORE)
    # Recovery selection is code-only, so the three validation paths remain
    # separate from the product delta even when forming the final full patch.
    for name in set(recovery["changes"]) | {THREAD_MANAGER}:
        product[name] = prepared[name]
    full_patch, binary, changed = product_delta(original, product)
    graph_fields = {"MODULE.bazel": "module_sha256", "MODULE.bazel.lock": "resolved_module_lock_sha256",
                    "codex-rs/Cargo.lock": "cargo_lock_sha256", "codex-rs/Cargo.toml": "normalized_workspace_manifest_sha256"}
    graph = {name: digest(prepared[name][1]) for name in graph_fields}
    require(all(graph[name] == validation["validation_environment"][field] for name, field in graph_fields.items()), "fresh source graph differs from pinned validation")
    root = args.output_directory
    if root is None:
        require(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared fresh-source output required")
        root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True) / "codex-adapter-epoch"
    frozen_sources = (
        Path("/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004/source"),
        Path("/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004/source"),
    )
    require(not any(root.is_relative_to(path) for path in frozen_sources), "fresh output may not modify preserved SDK source")
    require(not root.is_relative_to(artifact.resolve(strict=True)), "fresh output may not modify baseline artifact custody")
    source = materialize(root, prepared)
    outputs = {"full-product.patch": full_patch, "product-binary-overlay.tar.gz": binary,
               "validation-overlay.patch": validation_overlay}
    inventory = {name: {"mode": mode, "sha256": digest(value)} for name, (mode, value) in sorted(prepared.items())}
    report = {"status": "fresh-adapter-source-uncompiled", "phase": "prepare-adapter", "commit": restore_source.COMMIT,
              "upstream_tree_oid": tree, "source": str(source), "tracked_files": len(inventory),
              "source_bytes": sum(len(value) for _, value in prepared.values()), "files": inventory,
              "complete_inventory_sha256": digest(json.dumps(inventory, sort_keys=True).encode()),
              "pristine_archive_sha256": PRISTINE_SHA, "pristine_receipt_sha256": PRISTINE_RECEIPT_SHA,
              "baseline_manifest_sha256": MANIFEST_SHA, "baseline_validation_sha256": VALIDATION_SHA,
              "baseline_patch_sha256": BASE_PATCH, "baseline_base_sha256": manifest["base_sha256"],
              "baseline_binary_overlay_sha256": manifest["binary_overlay_sha256"],
              "validation_overlay_sha256": digest(validation_overlay), "graph_sha256": graph,
              "recovery_patch_sha256": digest(delta), "recovery_receipt_sha256": args.recovery_receipt_sha256,
              "retirement_implementation_sha256": RETIREMENT_SHA, "retirement_before_sha256": RETIREMENT_BEFORE,
              "retirement_after_sha256": digest(prepared[THREAD_MANAGER][1]), "changed_product_files": changed,
              "outputs": {name: {"sha256": digest(value), "bytes": len(value)} for name, value in outputs.items()},
              "schema_producer_receipt": None, "native_tests_passed": False, "native_support": False}
    publish_outputs(root, {**outputs, "source-receipt.json": (json.dumps(report, indent=2) + "\n").encode()})


if __name__ == "__main__":
    main()
