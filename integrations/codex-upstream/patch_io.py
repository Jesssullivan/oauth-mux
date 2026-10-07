"""Exact patch/overlay application; no subprocess, network, extraction or fuzz."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
LICENSE_FILES = ("LICENSE", "NOTICE")
HASH = re.compile(r"[0-9a-f]{64}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_path(raw: str) -> str:
    path = PurePosixPath(raw)
    if (not raw.startswith("codex-rs/") or path.is_absolute() or ".." in path.parts
            or str(path) != raw or any(char in raw for char in "\\\0\n\r\t")):
        raise ValueError("path is outside the canonical upstream source boundary")
    return raw


def safe_path(raw: str) -> str:
    if raw == "/dev/null":
        return raw
    if not raw.startswith(("a/", "b/")):
        raise ValueError("patch path must have a git prefix")
    return source_path(raw[2:])


def deterministic_archive(files: dict[str, bytes]) -> bytes:
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, value in sorted(files.items()):
            if name not in LICENSE_FILES:
                source_path(name)
            entry = tarfile.TarInfo(name)
            entry.size = len(value)
            entry.mode = 0o644
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(value))
    # Explicit header fields avoid filenames, clocks and platform-dependent gzip OS bytes.
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(packed.getvalue())
    return compressed.getvalue()


def read_archive(data: bytes, *, allow_directories: bool = False) -> dict[str, bytes]:
    if allow_directories and not data.startswith(b"\x1f\x8b"):
        # git archive's default format is an uncompressed tar; emitted bundles are gzip.
        raw = data
    else:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            raw = compressed.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("upstream archive exceeds its bound")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            name = member.name
            if member.isdir() and allow_directories:
                directory = name.rstrip("/")
                if directory != "codex-rs":
                    source_path(directory)
                continue
            if name not in LICENSE_FILES:
                source_path(name)
            if not member.isfile() or name in files:
                raise ValueError("archive has a duplicate or non-file member")
            if member.size < 0 or member.size > MAX_ARCHIVE_BYTES:
                raise ValueError("archive member exceeds its bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("archive member cannot be read")
            value = stream.read()
            if len(value) != member.size:
                raise ValueError("archive member is truncated")
            files[name] = value
    return files


def validate_manifest(manifest: dict) -> None:
    if manifest.get("artifact_version") != 2 or not isinstance(manifest.get("files"), dict):
        raise ValueError("unsupported native hook artifact manifest")
    for key in ("patch_sha256", "base_sha256", "binary_overlay_sha256"):
        if not isinstance(manifest.get(key), str) or not HASH.fullmatch(manifest[key]):
            raise ValueError("manifest has an invalid artifact checksum")
    for key in ("patch_file", "binary_overlay_file"):
        name = manifest.get(key)
        if not isinstance(name, str) or Path(name).name != name or name in ("", ".", ".."):
            raise ValueError("manifest artifact path is invalid")
    if not manifest["files"]:
        raise ValueError("manifest does not modify upstream files")
    for name, record in manifest["files"].items():
        source_path(name)
        if not isinstance(record, dict) or record.get("representation") not in ("patch", "binary_overlay"):
            raise ValueError("manifest file representation is invalid")
        for field in ("before_sha256", "after_sha256"):
            value = record.get(field)
            if field == "before_sha256" and value is None:
                continue
            if not isinstance(value, str) or not HASH.fullmatch(value):
                raise ValueError("manifest has an invalid source checksum")
    licenses = manifest.get("license_files")
    if not isinstance(licenses, dict) or set(licenses) != set(LICENSE_FILES):
        raise ValueError("manifest must preserve upstream LICENSE and NOTICE")
    if any(not isinstance(value, str) or not HASH.fullmatch(value) for value in licenses.values()):
        raise ValueError("manifest has an invalid license checksum")


def apply_exact(patch: str, original: dict[str, bytes]) -> dict[str, bytes]:
    """Return changed files only, checking both exact hunk positions and contents."""
    lines = patch.splitlines(keepends=True)
    output: dict[str, bytes] = {}
    index = 0
    while index < len(lines):
        if not lines[index].startswith("diff --git "):
            raise ValueError("unexpected patch content outside a file diff")
        parts = lines[index].rstrip("\n").split(" ")
        if len(parts) != 4:
            raise ValueError("malformed git patch header")
        old_git, new_git = safe_path(parts[2]), safe_path(parts[3])
        if old_git != new_git:
            raise ValueError("unexpected rename in native hook patch")
        index += 1
        new_file = index < len(lines) and lines[index] == "new file mode 100644\n"
        if new_file:
            index += 1
        if index + 1 >= len(lines) or not lines[index].startswith("--- ") or not lines[index + 1].startswith("+++ "):
            raise ValueError("patch lacks file headers")
        old = safe_path(lines[index][4:].rstrip("\n"))
        new = safe_path(lines[index + 1][4:].rstrip("\n"))
        if new != new_git or (old != "/dev/null" and old != new) or new_file != (old == "/dev/null"):
            raise ValueError("inconsistent patch file headers")
        if new in output or (new_file and new in original):
            raise ValueError("duplicate or existing new patch file")
        if not new_file and new not in original:
            raise ValueError("patch original is missing")
        source = [] if new_file else original[new].decode("utf-8").splitlines(keepends=True)
        result: list[str] = []
        cursor = 0
        index += 2
        hunks = 0
        while index < len(lines) and lines[index].startswith("@@ "):
            header = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", lines[index])
            if header is None:
                raise ValueError("malformed patch hunk")
            old_count, new_count = int(header[2] or 1), int(header[4] or 1)
            # Empty ranges describe the line immediately before an insertion.
            start = int(header[1]) - (1 if old_count else 0)
            target_start = int(header[3]) - (1 if new_count else 0)
            if start < cursor or start > len(source):
                raise ValueError("patch hunk has an invalid source range")
            result.extend(source[cursor:start])
            if target_start != len(result):
                raise ValueError("patch hunk has an invalid destination range")
            cursor = start
            removed = added = 0
            index += 1
            while removed < old_count or added < new_count:
                if index >= len(lines) or lines[index][:1] not in (" ", "+", "-"):
                    raise ValueError("patch hunk is truncated")
                line = lines[index]
                payload = line[1:]
                index += 1
                if index < len(lines) and lines[index] == "\\ No newline at end of file\n":
                    if not payload.endswith("\n"):
                        raise ValueError("malformed missing-newline marker")
                    payload = payload[:-1]
                    index += 1
                if line[0] in " -":
                    if cursor >= len(source) or source[cursor] != payload:
                        raise ValueError(f"patch context differs at {new}:{cursor + 1}")
                    cursor += 1
                    removed += 1
                if line[0] in " +":
                    result.append(payload)
                    added += 1
                if removed > old_count or added > new_count:
                    raise ValueError("patch hunk line counts differ")
            hunks += 1
        if not hunks:
            raise ValueError("patch file has no hunks")
        result.extend(source[cursor:])
        output[new] = "".join(result).encode("utf-8")
    return output


def verify_base(original: dict[str, bytes], manifest: dict) -> None:
    expected = {name for name, record in manifest["files"].items() if record["before_sha256"] is not None}
    if set(original) != expected | set(LICENSE_FILES):
        raise ValueError("packaged upstream originals differ from the manifest file set")
    for name, value in original.items():
        expected_hash = (manifest["license_files"][name] if name in LICENSE_FILES
                         else manifest["files"][name]["before_sha256"])
        if digest(value) != expected_hash:
            raise ValueError(f"packaged upstream original differs from its manifest: {name}")


def verify_inputs(root: Path, manifest: dict) -> dict[str, bytes]:
    validate_manifest(manifest)
    originals: dict[str, bytes] = {}
    root = root.resolve(strict=True)
    for name, record in manifest["files"].items():
        path = root / name
        # Existing symlinks, including dangling ones and parent symlinks, are not write authority.
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("upstream patch path follows a symlink outside checkout")
        if any(parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)):
            raise ValueError("upstream patch parent follows a symlink")
        if record["before_sha256"] is None:
            if path.exists():
                raise ValueError(f"new upstream hook path already exists: {name}")
            continue
        value = path.read_bytes()
        if digest(value) != record["before_sha256"]:
            raise ValueError(f"upstream source differs from the pinned revision: {name}")
        originals[name] = value
    for name, expected in manifest["license_files"].items():
        path = root / name
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError(f"upstream license differs from the pinned revision: {name}")
    return originals


def combine_changes(patch: bytes, overlay: bytes, original: dict[str, bytes], manifest: dict) -> dict[str, bytes]:
    if digest(patch) != manifest["patch_sha256"] or digest(overlay) != manifest["binary_overlay_sha256"]:
        raise ValueError("patch or binary overlay provenance checksum differs")
    changed = apply_exact(patch.decode("utf-8"), original)
    binary = read_archive(overlay)
    expected_text = {name for name, record in manifest["files"].items() if record["representation"] == "patch"}
    expected_binary = set(manifest["files"]) - expected_text
    if set(changed) != expected_text or set(binary) != expected_binary or set(changed) & set(binary):
        raise ValueError("patch and binary overlay file sets differ from manifest")
    changed.update(binary)
    verify_outputs(changed, manifest)
    return changed


def verify_outputs(changed: dict[str, bytes], manifest: dict) -> None:
    if set(changed) != set(manifest["files"]):
        raise ValueError("patched file set differs from manifest")
    for name, value in changed.items():
        if digest(value) != manifest["files"][name]["after_sha256"]:
            raise ValueError(f"patched source differs from reviewed manifest: {name}")


def verify_artifact(artifact: Path, manifest: dict) -> tuple[dict[str, bytes], bytes, bytes]:
    validate_manifest(manifest)
    patch = (artifact / manifest["patch_file"]).read_bytes()
    overlay = (artifact / manifest["binary_overlay_file"]).read_bytes()
    archive = (artifact / "upstream-base.tar.gz").read_bytes()
    if digest(archive) != manifest["base_sha256"]:
        raise ValueError("upstream base provenance checksum differs")
    original = read_archive(archive)
    verify_base(original, manifest)
    combine_changes(patch, overlay, original, manifest)
    return original, patch, overlay
