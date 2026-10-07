"""Bounded receipt of explicitly declared Bazel source inputs, never Git state.

The root anchor is a declared repository-root BUILD.bazel. Bazel may expose a
selected input through its runfiles or execution-root aliases; each alias must
retain that input's repository-relative name in the anchor's physical tree.
The aggregate is SHA256 of canonical UTF-8 JSON containing sorted path, size,
SHA256 and executable-bit records. Observational stat metadata is deliberately
outside that deterministic digest. This receipt proves source inventory only.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_FILES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 128 * 1024
EXCLUDED_COMPONENTS = frozenset(("docs", ".git", ".goal", "evidence", "releases"))


class ReceiptError(ValueError):
    """A redacted failure that must not include physical input paths."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _absolute(value):
    raw = os.fspath(value)
    if not raw or any(part in (".", "..") for part in raw.split("/")):
        raise ReceiptError("input path traversal or empty path")
    if "\\" in raw or any(ord(character) < 32 for character in raw):
        raise ReceiptError("unsupported input path characters")
    path = Path(raw)
    return path if path.is_absolute() else Path.cwd() / path


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "link_count": info.st_nlink}


def _regular(info):
    if not stat.S_ISREG(info.st_mode):
        raise ReceiptError("selected input must be a regular file")


def _physical_input(root, relative):
    """No repository source symlinks, including intermediate directories."""
    current = root
    for index, component in enumerate(relative.parts):
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReceiptError("source-tree symlink is not a selected regular input")
        if index < len(relative.parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ReceiptError("selected input parent must be a directory")
        else:
            _regular(info)
    return current


def _selected_input(logical_root, source_root, path, relative, namespaces, hops=0):
    # Resolve only aliases mapping to this exact selected repository path. A
    # foreign intermediate alias is rejected before its target is consulted.
    if hops > 16:
        raise ReceiptError("selected input alias depth exceeded")
    if logical_root == source_root:
        return _physical_input(source_root, relative), source_root
    current = logical_root
    for index, component in enumerate(relative.parts):
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(current)
            if any(part in (".", "..") for part in target.split("/")):
                raise ReceiptError("selected input alias contains traversal")
            destination = Path(target)
            if not destination.is_absolute():
                destination = current.parent / destination
            targets = [root for root in namespaces
                       if destination == root.joinpath(*relative.parts[:index + 1])]
            if not targets:
                raise ReceiptError("selected input alias changes repository path")
            # The complete physical suffix is validated without following any
            # source-tree alias, rather than trusting resolve() on that suffix.
            target_root = targets[0]
            return _selected_input(target_root, source_root, target_root / relative,
                                   relative, namespaces, hops + 1)
        if index < len(relative.parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ReceiptError("selected input parent must be a directory")
        else:
            _regular(info)
    physical = _physical_input(source_root, relative)
    if current != physical:
        # Real regular files in a sandbox are allowed: their bytes, rather than
        # the mutable source-tree copy, are the actual declared action inputs.
        return path, logical_root
    return physical, source_root


def _roots(anchor):
    anchor = _absolute(anchor)
    if anchor.name != "BUILD.bazel":
        raise ReceiptError("root anchor must be repository-root BUILD.bazel")
    # This one declared bootstrap input locates the source tree. Never recurse
    # or scan it. Ordinary Bazel anchor aliases may have a bounded link chain.
    current = anchor
    namespaces = []
    for _ in range(16):
        if current.parent not in namespaces:
            namespaces.append(current.parent)
        info = current.lstat()
        if not stat.S_ISLNK(info.st_mode):
            _regular(info)
            if current.name != "BUILD.bazel":
                raise ReceiptError("root anchor alias changes repository path")
            physical_root = current.parent.resolve(strict=True)
            if physical_root not in namespaces:
                namespaces.append(physical_root)
            return anchor.parent, physical_root, tuple(namespaces)
        target = os.readlink(current)
        if any(part in (".", "..") for part in target.split("/")):
            raise ReceiptError("root anchor alias contains traversal")
        current = Path(target) if os.path.isabs(target) else current.parent / target
    raise ReceiptError("root anchor alias depth exceeded")


def _open_selected(root, relative):
    """Walk selected directories by descriptor; never follow a racing alias."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(relative.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                       dir_fd=directory)
    finally:
        os.close(directory)


def _hash_file(path, root, relative, per_file_limit, remaining):
    # O_NONBLOCK prevents a racing replacement with a FIFO from hanging; the
    # descriptor is validated before any bytes are read. O_NOFOLLOW prevents
    # a racing final-component alias from materializing an undeclared target.
    pathname_before = path.lstat()
    _regular(pathname_before)
    descriptor = _open_selected(root, relative)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        _regular(before)
        if _identity(before) != _identity(pathname_before):
            raise ReceiptError("selected input replaced before hashing")
        if before.st_size > min(per_file_limit, remaining):
            raise ReceiptError("selected input byte limit exceeded")
        digest, count = hashlib.sha256(), 0
        while True:
            block = stream.read(min(CHUNK_BYTES, per_file_limit - count + 1,
                                    remaining - count + 1))
            if not block:
                break
            count += len(block)
            if count > min(per_file_limit, remaining):
                raise ReceiptError("selected input grew beyond byte limit")
            digest.update(block)
        after = os.fstat(stream.fileno())
        if _identity(before) != _identity(after) or count != before.st_size:
            raise ReceiptError("selected input changed during hashing")
    if _identity(path.lstat()) != _identity(after):
        raise ReceiptError("selected input replaced during hashing")
    return digest.hexdigest(), _identity(before), _identity(after)


def collect_inventory(anchor, files, *, max_files=MAX_FILES,
                      max_file_bytes=MAX_FILE_BYTES, max_total_bytes=MAX_TOTAL_BYTES):
    if not (0 < max_files <= MAX_FILES and 0 < max_file_bytes <= MAX_FILE_BYTES
            and 0 < max_total_bytes <= MAX_TOTAL_BYTES):
        raise ReceiptError("inventory limits exceed bounded policy")
    if not files or len(files) > max_files:
        raise ReceiptError("selected input count outside bounded policy")
    logical_root, source_root, namespaces = _roots(anchor)
    selected = {}
    for value in files:
        path = _absolute(value)
        try:
            relative = path.relative_to(logical_root)
        except ValueError:
            raise ReceiptError("foreign input outside declared repository namespace") from None
        name = relative.as_posix()
        if not relative.parts or any(part in EXCLUDED_COMPONENTS for part in relative.parts):
            raise ReceiptError("historical, evidence or private input outside code scope")
        if name in selected:
            raise ReceiptError("duplicate selected repository path")
        selected[name] = (path, relative)
    if "BUILD.bazel" not in selected:
        raise ReceiptError("root anchor must also be a selected inventory input")
    entries, observations, captured, identities = [], [], [], set()
    total = 0
    for name, (logical, relative) in sorted(selected.items()):
        path, physical_root = _selected_input(logical_root, source_root, logical,
                                             relative, namespaces)
        digest, before, after = _hash_file(path, physical_root, relative, max_file_bytes,
                                         max_total_bytes - total)
        identity = (before["device"], before["inode"])
        if identity in identities:
            raise ReceiptError("selected repository paths alias the same input")
        identities.add(identity)
        total += before["size"]
        entries.append({"path": name, "size": before["size"], "sha256": digest,
                        "executable": bool(before["mode"] & 0o111)})
        observations.append({"path": name, "before": before, "after": after})
        captured.append((logical, relative, path, after))
    # Capture-wide validation catches earlier files changing while later files
    # are hashed, including alias retargeting, replacement and same-size writes.
    for logical, relative, path, after in captured:
        if (_selected_input(logical_root, source_root, logical, relative, namespaces)[0] != path
                or _identity(path.lstat()) != after):
            raise ReceiptError("selected input changed before inventory freeze")
    if _roots(anchor) != (logical_root, source_root, namespaces):
        raise ReceiptError("root anchor changed before inventory freeze")
    canonical = {"schema": "omux.runtime-source-inventory.v1", "files": entries}
    return {**canonical, "aggregate_sha256": hashlib.sha256(canonical_bytes(canonical)).hexdigest(),
            "file_count": len(entries), "total_bytes": total,
            "observations": observations}


def write_receipt(output_root, inventory, parent_commit, dirty):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", parent_commit):
        raise ReceiptError("parent commit must be an exact lowercase Git object ID")
    if dirty not in ("true", "false"):
        raise ReceiptError("dirty must be exact caller-supplied true or false")
    root = Path(output_root)
    if not root.is_dir() or root.is_symlink():
        raise ReceiptError("test output root must be an existing directory")
    destination = root / "runtime-source-receipt"
    destination.mkdir(mode=0o700, exist_ok=False)
    receipt = {"schema": "omux.runtime-source-receipt.v1",
               "claim": "source_inventory_only", "authentication_performed": False,
               "payload_output": False, "source_inventory": "source-inventory.json",
               "source_aggregate_sha256": inventory["aggregate_sha256"],
               "caller_arguments": {"--parent-commit": parent_commit, "--dirty": dirty},
               "caller_git_metadata_verified": False,
               "scope": "finite explicitly declared selected code inputs",
               "limitations": ["No application execution or continuity proof",
                               "No source contents retained",
                               "No full repository, toolchain or artifact closure claim",
                               "Freeze covers observed capture interval only"]}
    for name, value in (("source-inventory.json", inventory), ("receipt.json", receipt)):
        with (destination / name).open("xb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-anchor", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--parent-commit", required=True)
    parser.add_argument("--dirty", choices=("true", "false"), required=True)
    parser.add_argument("--expected-source-sha256")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES)
    args = parser.parse_args(argv)
    try:
        inventory = collect_inventory(args.root_anchor, args.file, max_files=args.max_files,
                                      max_file_bytes=args.max_file_bytes,
                                      max_total_bytes=args.max_total_bytes)
        if args.expected_source_sha256 is not None:
            if not re.fullmatch(r"[0-9a-f]{64}", args.expected_source_sha256):
                raise ReceiptError("expected source digest must be exact lowercase SHA256")
            if inventory["aggregate_sha256"] != args.expected_source_sha256:
                raise ReceiptError("selected source digest differs from frozen receipt")
        write_receipt(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"], inventory,
                      args.parent_commit, args.dirty)
    except (ReceiptError, OSError, KeyError):
        # Filesystem exception strings can include physical paths or arbitrary
        # target names. Keep all CLI diagnostics redacted and fail closed.
        print("runtime source receipt failed; no source-inventory claim issued", file=sys.stderr)
        return 1
    print("runtime source receipt: source_inventory_only; no authentication; no payload output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
