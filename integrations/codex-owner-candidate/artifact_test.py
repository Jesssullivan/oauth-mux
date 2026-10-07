"""R-N13: exact candidate byte custody, with no implementation-text oracle."""

import argparse
import json
import sys
import uuid
from pathlib import Path

# The interpreter launcher exposes only the main's runfiles directory. This
# sibling is explicit BUILD srcs, not an ambient checkout or Python search path.
sys.path.insert(0, str(Path(__file__).parent.parent / "codex-upstream"))
from patch_io import HASH, LICENSE_FILES, combine_changes, digest, source_path, verify_artifact

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
PREFIX = "codex-rs/app-server-protocol/schema/"


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate candidate JSON key")
        result[name] = value
    return result


def read_json(path):
    value = path.read_bytes()
    if len(value) > 16 * 1024 * 1024:
        raise ValueError("candidate JSON exceeds bound")
    return json.loads(value, object_pairs_hook=unique_object)


def verify_candidate(artifact):
    manifest = read_json(artifact / "manifest.json")
    validation = read_json(artifact / "validation.json")
    if (manifest.get("upstream_commit") != COMMIT or
            manifest.get("upstream_repository") != "https://github.com/openai/codex" or
            manifest.get("native_support") is not False or
            manifest.get("status") != "upstream-patch-candidate" or
            validation.get("native_support") is not False or
            validation.get("upstream_commit") != COMMIT or
            validation.get("artifact_status") != "upstream-patch-candidate"):
        raise ValueError("candidate support or upstream boundary differs")
    original, patch, overlay = verify_artifact(artifact, manifest)
    changed = combine_changes(patch, overlay, original, manifest)
    if set(changed) != set(manifest["files"]):
        raise ValueError("candidate changed-file inventory differs")
    for name in LICENSE_FILES:
        if digest(original[name]) != manifest["license_files"][name]:
            raise ValueError("candidate attribution differs")
    current = validation["artifact"]
    for key in ("patch_sha256", "base_sha256", "binary_overlay_sha256"):
        if current.get(key) != manifest[key]:
            raise ValueError("validation describes another artifact")
    if (type(current.get("reviewed_changed_files")) is not int or
            current["reviewed_changed_files"] != len(changed)):
        raise ValueError("validation changed-file count differs")
    if "changed_source" in current:
        name = source_path(current["changed_source"])
        if name not in changed or current.get("changed_source_sha256") != digest(changed[name]):
            raise ValueError("validation current source digest differs")
    environment = validation["validation_environment"]
    if environment.get("validation_overlay") != "validation-overlay.patch":
        raise ValueError("validation overlay filename differs")
    if digest((artifact / "validation-overlay.patch").read_bytes()) != environment.get("validation_overlay_sha256"):
        raise ValueError("validation overlay digest differs")
    # The restoration target independently reconstructs the overlay against the
    # pinned full Git tree and checks these graph hashes. They must be explicit;
    # this subset artifact cannot reconstruct unchanged MODULE/lock files.
    for key in ("module_sha256", "resolved_module_lock_sha256", "cargo_lock_sha256",
                "normalized_workspace_manifest_sha256", "tool_archive_manifest_sha256"):
        if not isinstance(environment.get(key), str) or not HASH.fullmatch(environment[key]):
            raise ValueError("validation graph digest is absent or malformed")
    schema = validation["schema_import"]
    if schema.get("receipt_file") != "schema-import-receipt.json":
        raise ValueError("schema receipt filename differs")
    receipt_bytes = (artifact / schema["receipt_file"]).read_bytes()
    if digest(receipt_bytes) != schema.get("receipt_sha256"):
        raise ValueError("schema receipt digest differs")
    receipt = read_json(artifact / schema["receipt_file"])
    producer = schema["producer_invocation_id"]
    if (str(uuid.UUID(producer)) != producer or receipt.get("producer_invocation_id") != producer or
            receipt.get("phase") != "import-schema-bundle" or receipt.get("status") != "passed" or
            receipt.get("ruling_id") != "R-N13" or receipt.get("native_support") is not False or
            receipt.get("normalization_performed") is not False or
            receipt.get("compression_performed") is not False):
        raise ValueError("schema receipt producer or scope differs")
    files = receipt["files"]
    if (not isinstance(files, list) or not 0 < len(files) <= 8192 or
            type(receipt.get("file_count")) is not int or
            receipt.get("file_count") != len(files)):
        raise ValueError("schema receipt inventory exceeds bound or differs")
    imported = {}
    total = 0
    for record in files:
        name = source_path(record["destination"])
        relative = record["source_relative_path"]
        if name != PREFIX + relative or name in imported:
            raise ValueError("schema receipt destination is foreign or duplicated")
        mode = record["source_mode"]
        valid = (mode == "stable" and (
            relative.startswith("typescript/") and relative.endswith(".ts") or
            relative.startswith("json/") and relative.endswith(".json") or
            relative == "precomputed/app-server-exports-stable.json.zst")) or (
            mode == "experimental" and relative == "precomputed/app-server-exports-experimental.json.zst")
        size = record["bytes"]
        if (not valid or type(size) is not int or not 0 <= size <= 16 * 1024 * 1024 or
                not isinstance(record.get("after_sha256"), str) or not HASH.fullmatch(record["after_sha256"])):
            raise ValueError("schema receipt member scope or digest differs")
        total += size
        imported[name] = record
        if name in changed and (digest(changed[name]) != record["after_sha256"] or len(changed[name]) != size):
            raise ValueError("packaged schema differs from actual producer import")
    if (total > 128 * 1024 * 1024 or type(receipt.get("source_bytes")) is not int or
            receipt["source_bytes"] != total):
        raise ValueError("schema receipt aggregate bytes differ")
    if (PREFIX + "precomputed/app-server-exports-stable.json.zst" not in imported or
            PREFIX + "precomputed/app-server-exports-experimental.json.zst" not in imported or
            not any(name.startswith(PREFIX + "typescript/") for name in imported) or
            not any(name.startswith(PREFIX + "json/") for name in imported)):
        raise ValueError("schema import receipt omits a producer output family")
    if not {name for name in changed if name.startswith(PREFIX)}.issubset(imported):
        raise ValueError("changed schema has no actual producer import binding")
    return len(changed), len(imported)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    try:
        changed, imported = verify_candidate(artifact)
    except (ValueError, OSError, KeyError, TypeError):
        print("Candidate verification refused: byte custody or receipt binding failed.", file=sys.stderr)
        return 1
    print(f"Verified {changed} exact changes and {imported} schema import bindings; native support remains false.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
