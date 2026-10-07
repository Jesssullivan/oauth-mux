"""Export bounded candidate originals from the verified pinned Git mirror.

R-N13: this coordinator tool never reads prepared source bytes or rewrites the
preserved source/artifact. Git and CA are supplied by the declared Bazel target.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from patch_io import (LICENSE_FILES, MAX_ARCHIVE_BYTES, deterministic_archive,
                      digest, read_archive, source_path, verify_artifact)
from restore_source import (COMMIT, URL, original_files, private_root,
                            source_directory, verify_packaged_base)

MAX_SELECTED_FILES = 4096
SCHEMA_PREFIX = "codex-rs/app-server-protocol/schema/"


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate artifact JSON key")
        result[name] = value
    return result


def selected_originals(files, manifest, packaged_originals, additional, *, include_schema_originals=False):
    """Bind every selected original to Git, retaining existing artifact custody."""
    if (manifest.get("upstream_commit") != COMMIT or
            manifest.get("upstream_repository") != URL.removesuffix(".git") or
            manifest.get("native_support") is not False):
        raise ValueError("candidate pin or support boundary differs")
    verify_packaged_base(files, packaged_originals, manifest)
    names = set(LICENSE_FILES)
    for name, record in manifest["files"].items():
        source_path(name)
        if record["before_sha256"] is not None:
            names.add(name)
    if len(additional) > MAX_SELECTED_FILES:
        raise ValueError("additional selection exceeds its bound")
    for name in additional:
        source_path(name)
        if name in names:
            raise ValueError("duplicate selected original")
        names.add(name)
    if include_schema_originals:
        # R-N13: select original pinned Git blobs only. A producer may change
        # any derived schema, including one untouched by the previous artifact.
        # Union skips existing selections while explicit duplicates still fail.
        names.update(name for name in files if name.startswith(SCHEMA_PREFIX) and
                     name.endswith((".json", ".ts", ".zst")))
    if len(names) > MAX_SELECTED_FILES:
        raise ValueError("selection exceeds its bound")
    selected = {}
    metadata = {}
    for name in sorted(names):
        if name not in files:
            raise ValueError("selected original is absent from pinned Git")
        mode, value = files[name]
        if mode not in ("100644", "100755"):
            raise ValueError("selected original is not a regular Git blob")
        selected[name] = value
        metadata[name] = {"git_mode": mode, "sha256": digest(value), "bytes": len(value)}
    # Include USTAR headers, padding and trailer in the raw parser budget.
    archive_size = sum(512 + ((len(value) + 511) // 512) * 512 for value in selected.values())
    archive_size = ((archive_size + 1024 + 10239) // 10240) * 10240
    if archive_size > MAX_ARCHIVE_BYTES:
        raise ValueError("selected archive exceeds its raw byte bound")
    archive = deterministic_archive(selected)
    if read_archive(archive) != selected:
        raise ValueError("selected archive round trip differs")
    return archive, metadata


def publish_export(output_directory, archive, report):
    """Create one private epoch exclusively; never replace existing outputs."""
    private_root(output_directory, create=True)
    directory_fd = os.open(output_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, value in (
            ("pristine-originals.tar.gz", archive),
            ("export-receipt.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()),
        ):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def export_subset(root, artifact_directory, git, ca_file, additional, output_directory, *,
                  include_schema_originals=False):
    private_root(root)
    source_directory(root / "git")
    if output_directory.resolve().is_relative_to(root):
        raise ValueError("export destination overlaps preserved source custody")
    artifact = artifact_directory.parent if artifact_directory.is_file() else artifact_directory
    manifest = json.loads((artifact / "manifest.json").read_text(), object_pairs_hook=unique_object)
    packaged_originals, _, _ = verify_artifact(artifact, manifest)
    files, tree_oid = original_files(git, root, ca_file)
    archive, metadata = selected_originals(files, manifest, packaged_originals, additional,
                                          include_schema_originals=include_schema_originals)
    inventory = {name: {"mode": mode, "sha256": digest(value)}
                 for name, (mode, value) in sorted(files.items())}
    report = {
        "ruling_id": "R-N13",
        "phase": "export-pristine-subset",
        "upstream_commit": COMMIT,
        "upstream_tree_oid": tree_oid,
        "input_patch_sha256": manifest["patch_sha256"],
        "mirror_inventory_sha256": digest(json.dumps(inventory, sort_keys=True).encode()),
        "mirror_tracked_files": len(files),
        "selected_files": metadata,
        "selected_file_count": len(metadata),
        "include_schema_originals": include_schema_originals,
        "selected_source_bytes": sum(record["bytes"] for record in metadata.values()),
        "archive_file": "pristine-originals.tar.gz",
        "archive_sha256": digest(archive),
        "archive_bytes": len(archive),
        "native_support": False,
        "prepared_source_verified": False,
        "scope": "Pinned Git object originals only; no prepared source, compilation or live proof.",
    }
    publish_export(output_directory, archive, report)
    return {key: value for key, value in report.items() if key != "selected_files"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--git", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True,
                        help="Existing private restoration root containing its verified pinned Git mirror")
    parser.add_argument("--additional-original", action="append", default=[],
                        help="Newly affected existing codex-rs path; repeatable, duplicates rejected")
    parser.add_argument("--include-schema-originals", action="store_true",
                        help="Include all pinned original protocol schema .json/.ts/.zst blobs")
    parser.add_argument("--output-directory", type=Path, required=True,
                        help="New private durable epoch directory; must not already exist")
    args = parser.parse_args()
    try:
        report = export_subset(args.root, args.artifact_dir, args.git, args.ca_file,
                               args.additional_original, args.output_directory,
                               include_schema_originals=args.include_schema_originals)
    except (ValueError, OSError, RuntimeError, UnicodeError, KeyError, TypeError,
            subprocess.SubprocessError):
        # Git diagnostics and arbitrary external paths never enter public output.
        print("pristine subset export rejected; no success receipt", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
