"""R-N13: receipt substitution and reconstruction tests with synthetic bytes."""

import copy
import json
import tempfile
from pathlib import Path

from artifact_test import COMMIT, PREFIX, verify_candidate
from patch_io import digest
from refresh_artifact import package


def rejects(operation):
    try:
        operation()
    except (ValueError, OSError, KeyError, TypeError):
        return
    raise AssertionError("invalid candidate byte custody accepted")


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source, artifact = root / "source", root / "artifact"
    source.mkdir()
    artifact.mkdir()
    schema_path = PREFIX + "json/v2/Owner.json"
    target = source / schema_path
    target.parent.mkdir(parents=True)
    target.write_bytes(b'{"type":"string"}\n')
    manifest, patch, base, overlay = package({"LICENSE": b"license", "NOTICE": b"notice"},
                                            source, [schema_path])
    for name, value in ((manifest["patch_file"], patch), ("upstream-base.tar.gz", base),
                        (manifest["binary_overlay_file"], overlay)):
        (artifact / name).write_bytes(value)
    (artifact / "manifest.json").write_text(json.dumps(manifest))
    producer = "12345678-1234-1234-1234-123456789abc"
    receipt = {"ruling_id": "R-N13", "phase": "import-schema-bundle", "status": "passed",
               "producer_invocation_id": producer, "native_support": False,
               "normalization_performed": False, "compression_performed": False,
               "file_count": 1, "source_bytes": len(target.read_bytes()),
               "files": [{"source_mode": "stable", "source_relative_path": "json/v2/Owner.json",
                          "destination": schema_path, "before_sha256": None,
                          "after_sha256": digest(target.read_bytes()), "bytes": len(target.read_bytes())}]}
    for mode, name, value in (
            ("stable", "typescript/v2/Owner.ts", b"export type Owner = string;"),
            ("stable", "precomputed/app-server-exports-stable.json.zst", b"stable native bytes"),
            ("experimental", "precomputed/app-server-exports-experimental.json.zst", b"experimental native bytes")):
        receipt["files"].append({"source_mode": mode, "source_relative_path": name,
                                 "destination": PREFIX + name, "before_sha256": None,
                                 "after_sha256": digest(value), "bytes": len(value)})
    receipt["file_count"] = len(receipt["files"])
    receipt["source_bytes"] = sum(record["bytes"] for record in receipt["files"])
    (artifact / "validation-overlay.patch").write_bytes(b"separate-validation-overlay")
    validation = {"artifact_status": "upstream-patch-candidate", "native_support": False,
                  "upstream_commit": COMMIT,
                  "artifact": {key: manifest[key] for key in (
                      "patch_sha256", "base_sha256", "binary_overlay_sha256")},
                  "validation_environment": {key: "a" * 64 for key in (
                      "module_sha256", "resolved_module_lock_sha256", "cargo_lock_sha256",
                      "normalized_workspace_manifest_sha256", "tool_archive_manifest_sha256")},
                  "schema_import": {"receipt_file": "schema-import-receipt.json",
                                    "producer_invocation_id": producer}}
    validation["artifact"]["reviewed_changed_files"] = 1
    validation["validation_environment"].update({"validation_overlay": "validation-overlay.patch",
        "validation_overlay_sha256": digest((artifact / "validation-overlay.patch").read_bytes())})

    def publish(value):
        encoded = json.dumps(value).encode()
        (artifact / "schema-import-receipt.json").write_bytes(encoded)
        validation["schema_import"]["receipt_sha256"] = digest(encoded)
        (artifact / "validation.json").write_text(json.dumps(validation))

    publish(receipt)
    assert verify_candidate(artifact) == (1, 4)
    changed = copy.deepcopy(receipt)
    changed["files"][0]["after_sha256"] = "b" * 64
    publish(changed)
    rejects(lambda: verify_candidate(artifact))
    changed = copy.deepcopy(receipt)
    changed["files"].append(changed["files"][0])
    changed["file_count"] += 1
    publish(changed)
    rejects(lambda: verify_candidate(artifact))
    changed = copy.deepcopy(receipt)
    changed["producer_invocation_id"] = "22345678-1234-1234-1234-123456789abc"
    publish(changed)
    rejects(lambda: verify_candidate(artifact))
    publish(receipt)
    validation["native_support"] = True
    (artifact / "validation.json").write_text(json.dumps(validation))
    rejects(lambda: verify_candidate(artifact))
    validation["native_support"] = False
    publish(receipt)
    (artifact / "schema-import-receipt.json").write_bytes(b"substituted receipt")
    rejects(lambda: verify_candidate(artifact))
    publish(receipt)
    (artifact / "validation-overlay.patch").write_bytes(b"different overlay")
    rejects(lambda: verify_candidate(artifact))
    (artifact / "manifest.json").write_text('{"files":{},"files":{}}')
    rejects(lambda: verify_candidate(artifact))

print("Candidate reconstruction and substituted schema, duplicate, producer, support, overlay and JSON refusal passed.")
