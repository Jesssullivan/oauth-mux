"""Package reviewed edits against git-exported, immutable upstream originals."""

import argparse
import difflib
import json
from pathlib import Path

from patch_io import (LICENSE_FILES, combine_changes, deterministic_archive, digest,
                      read_archive, source_path, validate_manifest, verify_base)

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
TAG_OBJECT = "ac21625ddf7f9dd5f34b2802212cf20295fdff95"
NEW_FILE = "codex-rs/core/src/auth_broker.rs"


def text_file(name: str, value: bytes) -> bool:
    if name.endswith(".zst") or b"\0" in value:
        return False
    try:
        value.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def text_patch(name: str, before: bytes | None, after: bytes) -> str:
    lines = [f"diff --git a/{name} b/{name}\n"]
    if before is None:
        lines.append("new file mode 100644\n")
    for line in difflib.unified_diff((before or b"").decode("utf-8").splitlines(keepends=True),
                                     after.decode("utf-8").splitlines(keepends=True),
                                     fromfile=f"a/{name}" if before is not None else "/dev/null",
                                     tofile=f"b/{name}", n=3):
        if line.endswith("\n"):
            lines.append(line)
        else:
            lines.extend((line + "\n", "\\ No newline at end of file\n"))
    return "".join(lines)


def package(original: dict[str, bytes], edited: Path, new_files: list[str]) -> tuple[dict, bytes, bytes, bytes]:
    if not set(LICENSE_FILES).issubset(original):
        raise ValueError("original tar must include upstream LICENSE and NOTICE")
    explicit_new = {source_path(name) for name in new_files}
    if explicit_new & set(original):
        raise ValueError("declared new file already occurs in immutable originals")
    files, binary, originals = {}, {}, {name: original[name] for name in LICENSE_FILES}
    patch = []
    for name in sorted(set(original) | explicit_new):
        if name in LICENSE_FILES:
            continue
        source_path(name)
        before = original.get(name)
        after = (edited / name).read_bytes()
        if before == after:
            continue
        representation = ("patch" if (before is not None or after) and text_file(name, after) and
                          (before is None or text_file(name, before)) else "binary_overlay")
        files[name] = {"before_sha256": digest(before) if before is not None else None,
                       "after_sha256": digest(after), "representation": representation}
        if before is not None:
            originals[name] = before
        if representation == "patch":
            patch.append(text_patch(name, before, after))
        else:
            binary[name] = after
    patch_bytes = "".join(patch).encode("utf-8")
    archive = deterministic_archive(originals)
    overlay = deterministic_archive(binary)
    manifest = {
        "artifact_version": 2,
        "status": "upstream-patch-candidate",
        "native_support": False,
        "upstream_repository": "https://github.com/openai/codex",
        "upstream_tag": "rust-v0.157.0",
        "upstream_tag_object": TAG_OBJECT,
        "upstream_commit": COMMIT,
        "patch_file": "codex-0.157-auth-broker.patch",
        "patch_sha256": digest(patch_bytes),
        "base_sha256": digest(archive),
        "binary_overlay_file": "binary-overlay.tar.gz",
        "binary_overlay_sha256": digest(overlay),
        "license_files": {name: digest(original[name]) for name in LICENSE_FILES},
        "files": files,
        "required_checks": ["upstream Bazel compilation", "upstream Rust auth_broker tests",
                            "upstream generated config/protocol fixture reconciliation",
                            "live ordinary launch/resume and late registration",
                            "live concurrent identity isolation and quota handoff",
                            "provider-bound opaque context reconstruction proof"],
    }
    validate_manifest(manifest)
    verify_base(originals, manifest)
    combine_changes(patch_bytes, overlay, originals, manifest)
    return manifest, patch_bytes, archive, overlay


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-tar", type=Path, required=True)
    parser.add_argument("--edited-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--new-file", action="append", default=[],
                        help="Explicit additional generated/source path absent from originals (repeatable)")
    args = parser.parse_args()
    # The auth hook is always newly introduced; generated protocol files are explicit additions.
    new_files = [NEW_FILE, *args.new_file]
    manifest, patch, archive, overlay = package(read_archive(args.original_tar.read_bytes(), allow_directories=True),
                                               args.edited_checkout, new_files)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / manifest["patch_file"]).write_bytes(patch)
    (args.output / "upstream-base.tar.gz").write_bytes(archive)
    (args.output / manifest["binary_overlay_file"]).write_bytes(overlay)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Packaged {len(manifest['files'])} reviewed upstream changes at {COMMIT}; candidate only.")


if __name__ == "__main__":
    main()
