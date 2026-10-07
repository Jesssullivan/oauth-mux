"""Read-only Codex artifact qualification, never installation or peer authority.

R-HOOK-CONVERGENCE-20261004 / R-N13. This projects existing package bytes into
a bounded digest-bound carrier. Caller-selected source/producer hashes are
independent comparison inputs, not authenticated provenance. No channel,
ownership, custody permit or executable identity is inferred from the package.
All execution belongs to declared locked-Nix/Bazel targets.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

# Fixed repository/runfiles source boundary, as in installed native fixtures.
# runtime_package supplies its own fixed patch_io/restore_source/portable imports.
sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-owner-runtime"))
import runtime_package as runtime

MAX_SELECTION_BYTES = 16 * 1024
MAX_LAUNCHER_BYTES = 16 * 1024
MAX_LOADER_BYTES = 128 * 1024 * 1024
LAUNCHER = "bin/codex"
LOADER = "lib/codex/lib/ld-linux-x86-64.so.2"
PROFILE = "linux-explicit-bundled-loader-v1"
HASH = re.compile(r"[0-9a-f]{64}")
CANDIDATE_FIELDS = (
    "upstream_commit", "patch_sha256", "base_sha256", "binary_overlay_sha256",
    "validation_sha256", "complete_source_inventory_sha256",
    "current_source_receipt_sha256", "compile_invocation_id",
    "source_verification_invocation_id", "current_compile_invocation_id",
    "current_source_verification_invocation_id", "current_configuration",
)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash(value) -> str:
    if not isinstance(value, str) or not HASH.fullmatch(value) or value == "0" * 64:
        raise ValueError("runtime selection requires a canonical nonzero digest")
    return value


def _json(value: bytes):
    if type(value) is not bytes or not 0 < len(value) <= runtime.MAX_METADATA_BYTES:
        raise ValueError("runtime selection metadata exceeds bound")
    try:
        parsed = json.loads(value, object_pairs_hook=runtime.unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("runtime selection metadata is invalid") from error
    if not isinstance(parsed, dict):
        raise ValueError("runtime selection metadata is not an object")
    return parsed


def canonical_selection_bytes(selection: dict) -> bytes:
    """Stable digest encoding; serialization alone grants no authority."""
    value = (json.dumps(selection, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(value) > MAX_SELECTION_BYTES:
        raise ValueError("runtime selection carrier exceeds bound")
    return value


def _role(manifest, files, path, limit, mode):
    record = manifest["files"][path]
    if (not isinstance(record, dict) or type(record.get("bytes")) is not int or
            not 0 < record["bytes"] <= limit or type(record.get("mode")) is not int or
            record["mode"] != mode or len(files[path]) != record["bytes"]):
        raise ValueError("runtime selection role size or mode differs")
    return {"path": path, "sha256": _hash(record["sha256"]),
            "bytes": record["bytes"], "mode": mode, "maximum_bytes": limit}


def qualify_runtime(archive: bytes, manifest_bytes: bytes, receipt_bytes: bytes, *,
                    expected_source_receipt_sha256: str,
                    expected_producer_receipt_sha256: str) -> dict:
    """Verify exact bytes and return an artifact-only selection and its digest.

    Hashes must come from the caller's independently selected input receipts.
    This checks references to those receipts; it does not authenticate or
    validate their contents, an installation, or a running native process.
    Input files are not opened and nothing is written or launched.
    """
    source_hash = _hash(expected_source_receipt_sha256)
    producer_hash = _hash(expected_producer_receipt_sha256)
    if type(archive) is not bytes or not 0 < len(archive) <= runtime.MAX_ARCHIVE_BYTES:
        raise ValueError("runtime selection archive exceeds bound")
    manifest = _json(manifest_bytes)
    receipt = _json(receipt_bytes)
    if (type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1 or
            type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1):
        raise ValueError("runtime selection schema differs")
    try:
        _hash(receipt["archive_sha256"])
        _hash(receipt["manifest_sha256"])
        if type(receipt.get("archive_bytes")) is not int:
            raise ValueError("runtime selection archive length differs")
        # Separate supplied manifest must be byte-identical to the archived one.
        if _digest(manifest_bytes) != receipt["manifest_sha256"]:
            raise ValueError("runtime selection manifest differs from receipt")
        checked, files = runtime.verify_runtime_files(archive, receipt)
        if files[runtime.MANIFEST] != manifest_bytes or checked != manifest:
            raise ValueError("runtime selection manifest differs from archive")
        transformations = manifest["transformations"]
        if not isinstance(transformations, dict):
            raise ValueError("runtime selection transformations are missing")
        if (_hash(transformations["source_receipt_sha256"]) != source_hash or
                _hash(transformations["producer_receipt_sha256"]) != producer_hash or
                source_hash != manifest["candidate"]["current_source_receipt_sha256"]):
            raise ValueError("runtime selection source or producer reference differs")
        if manifest["runtime"]["loader"] != LOADER:
            raise ValueError("runtime selection loader role differs")
        roles = {
            "launcher": _role(manifest, files, LAUNCHER, MAX_LAUNCHER_BYTES, 0o755),
            "backend": _role(manifest, files, runtime.BACKEND, runtime.MAX_BACKEND_BYTES, 0o755),
            "loader": _role(manifest, files, LOADER, MAX_LOADER_BYTES, 0o755),
        }
        # Retain role bounds without increasing the generic Omux collector bound.
        for name in manifest["runtime"]["dependencies"]:
            _role(manifest, files, name, MAX_LOADER_BYTES, 0o755)
        _role(manifest, files, runtime.CA, 16 * 1024 * 1024, 0o644)
        selection = {
            "schema_version": 1,
            "qualification": "artifact_bytes_and_declared_receipt_references_only",
            "target": manifest["target"],
            "archive": {"sha256": _digest(archive), "bytes": len(archive)},
            "manifest_sha256": _digest(manifest_bytes),
            "runtime_receipt_sha256": _digest(receipt_bytes),
            "candidate": {field: manifest["candidate"][field] for field in CANDIDATE_FIELDS},
            "source_receipt_sha256": source_hash,
            "producer_receipt_sha256": producer_hash,
            "launch_profile": PROFILE,
            "roles": roles,
            "installation_ownership": "absent",
            "installed_files": "unverified",
            "channel_authority": "absent",
            "custody_binding": "absent",
            "executable_attribution": "unproved",
            "native_support": False,
        }
        encoded = canonical_selection_bytes(selection)
    except (KeyError, TypeError, AttributeError, IndexError, OverflowError,
            OSError, EOFError, tarfile.TarError, RecursionError) as error:
        raise ValueError("runtime selection package structure differs") from error
    return {"selection": selection, "selection_sha256": _digest(encoded)}
