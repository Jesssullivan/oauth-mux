"""Export a scoped recovery delta from declared, manifest-owned Rust/C inputs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-upstream"))
from patch_io import apply_exact, combine_changes, digest, source_path, verify_artifact
from refresh_artifact import text_patch

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
BASE_PATCH = "2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46"
MAX_FILE = 4 * 1024 * 1024
MAX_INPUTS = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selected_paths(manifest):
    require(manifest.get("upstream_commit") == COMMIT and manifest.get("patch_sha256") == BASE_PATCH,
            "recovery baseline pin mismatch")
    paths = sorted(source_path(name) for name in manifest["files"] if name.endswith((".rs", ".c", ".h")))
    require(paths and len(paths) <= 128, "recovery code allowlist exceeds bound")
    return paths


def build_delta(before, after):
    require(set(before) == set(after), "recovery source selection differs")
    require(sum(map(len, after.values())) <= MAX_INPUTS, "recovery source bytes exceed bound")
    pieces, changes = [], {}
    for name in sorted(before):
        source_path(name)
        require(name.endswith((".rs", ".c", ".h")), "recovery delta excludes non-code paths")
        require(len(before[name]) <= MAX_FILE and len(after[name]) <= MAX_FILE, "recovery code file exceeds bound")
        if before[name] == after[name]:
            continue
        pieces.append(text_patch(name, before[name], after[name]))
        changes[name] = {"before_sha256": digest(before[name]), "after_sha256": digest(after[name])}
    patch = "".join(pieces).encode()
    require(len(patch) <= MAX_INPUTS, "recovery patch exceeds bound")
    expected = {name: after[name] for name in changes}
    require(apply_exact(patch.decode(), before) == expected, "recovery delta exact application mismatch")
    return patch, changes


def read_code(path):
    fd = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and not before.st_mode & 0o022 and before.st_size <= MAX_FILE,
                "declared recovery code custody mismatch")
        value = stream.read(MAX_FILE + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and len(value) == before.st_size, "recovery code changed during read")
        return value


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-input-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args()
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    with (artifact / "manifest.json").open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE and digest(raw) == args.manifest_sha256, "recovery manifest digest mismatch")
    manifest = json.loads(raw)
    paths = selected_paths(manifest)
    originals, patch, overlay = verify_artifact(artifact, manifest)
    prepared = combine_changes(patch, overlay, originals, manifest)
    before = {name: prepared[name] for name in paths}
    inputs = args.source_input_directory.parent if args.source_input_directory.is_file() else args.source_input_directory
    after = {}
    total = 0
    for name in paths:
        value = read_code(inputs / name)
        total += len(value)
        require(total <= MAX_INPUTS, "selected recovery code bytes exceed bound")
        after[name] = value
    delta, changes = build_delta(before, after)
    root = args.output_directory
    if root is None:
        require(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared recovery test output directory required")
        root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True) / "codex-recovery-delta"
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent, "recovery output parent is noncanonical")
    parent = root.parent.stat()
    require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022, "recovery output parent is untrusted")
    root.mkdir(mode=0o700)
    with (root / "recovery-delta.patch").open("xb") as stream:
        stream.write(delta)
        stream.flush()
        os.fsync(stream.fileno())
    report = {"status": "scoped-source-delta-awaiting-review", "commit": COMMIT,
              "baseline_manifest_sha256": args.manifest_sha256, "baseline_patch_sha256": BASE_PATCH,
              "patch_sha256": digest(delta), "changes": changes,
              "selected_inputs": {name: {"before_sha256": digest(before[name]), "after_sha256": digest(after[name])} for name in paths},
              "selected_path_count": len(paths), "selected_source_bytes": total,
              "full_sdk_inventory": False, "schema_producer_receipt": None,
              "native_support": False, "native_proof": False}
    with (root / "recovery-delta-receipt.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    for name in ("recovery-delta.patch", "recovery-delta-receipt.json"):
        (root / name).chmod(0o400)


if __name__ == "__main__":
    main()
