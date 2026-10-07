"""Restore and verify the fixed public upstream source using declared coordinator Git."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath

from patch_io import apply_exact, combine_changes, digest, verify_artifact, verify_inputs

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
URL = "https://github.com/openai/codex.git"
OVERLAY_PATHS = ("MODULE.bazel.lock", "codex-rs/Cargo.toml", "workspace_root_test_launcher.sh.tpl")
MAX_SOURCE_BYTES = 512 * 1024 * 1024
BAZEL_CONFIGURATIONS = ("local_linux-fastbuild", "owner-linux-fastbuild", "owner-linux-opt")


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or str(path) != name or any(c in name for c in "\\\0\r\n"):
        raise ValueError("unsafe upstream source path")
    return name


def blob_hash(value):
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()


def source_directory(path, *, private=False):
    info = path.lstat()
    forbidden = 0o077 if private else 0o022
    if not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & forbidden:
        raise ValueError("source directory custody mismatch")


def write_receipt(root, name, report):
    if Path(name).name != name or name in ("", ".", ".."):
        raise ValueError("unsafe receipt name")
    source_directory(root, private=True)
    source_directory(root.parent)
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("receipt directory custody mismatch")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(directory_fd)


def private_root(root, *, create=False):
    resolved = root.resolve()
    if not root.is_absolute() or resolved != root or any(resolved == base or resolved.is_relative_to(base) for base in (Path("/tmp"), Path("/private/tmp"))):
        raise ValueError("source custody root must be durable and canonical")
    parent = root.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise ValueError("source custody parent must be trusted and preexisting")
    if create:
        root.mkdir(mode=0o700, parents=False)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("source custody root must be a private current-user directory")


def git_environment(root, ca_file):
    return {"HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "home"),
            "PATH": "", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_SSL_CAINFO": str(ca_file),
            "GIT_ATTR_NOSYSTEM": "1", "LC_ALL": "C"}


def run_git(git, root, ca_file, *args, input=None):
    command = [str(git), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
               "-c", "core.attributesFile=/dev/null", "-c", "transfer.fsckObjects=true",
               "-c", "fetch.fsckObjects=true", "-c", "protocol.file.allow=never", *args]
    result = subprocess.run(command, input=input, capture_output=True,
                            env=git_environment(root, ca_file), cwd=root, timeout=600)
    if result.returncode:
        raise RuntimeError("declared Git failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def tree_entries(tree):
    entries = []
    seen = set()
    for item in tree.split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        name = safe_name(name.decode())
        if kind != "blob" or mode not in ("100644", "100755", "120000") or not re.fullmatch("[0-9a-f]{40}", oid) or name in seen:
            raise ValueError("unsupported upstream source entry")
        seen.add(name)
        entries.append((name, mode, oid))
    if not entries or len(entries) > 50000:
        raise ValueError("upstream source inventory exceeds its bound")
    return entries


def batch_files(entries, batch):
    if len(batch) > MAX_SOURCE_BYTES:
        raise ValueError("upstream source batch exceeds its bound")
    position = 0
    files = {}
    for name, mode, oid in entries:
        end = batch.index(b"\n", position)
        reported, kind, size = batch[position:end].decode().split()
        size = int(size)
        if size < 0 or size > MAX_SOURCE_BYTES:
            raise ValueError("invalid upstream blob size")
        value = batch[end + 1:end + 1 + size]
        position = end + size + 2
        if reported != oid or kind != "blob" or len(value) != size or blob_hash(value) != oid or batch[end + 1 + size:position] != b"\n":
            raise ValueError("upstream blob identity mismatch")
        files[name] = (mode, value)
    if position != len(batch) or not files:
        raise ValueError("upstream batch is incomplete or has trailing bytes")
    return files


def original_files(git, root, ca_file):
    repo = "--git-dir=" + str(root / "git")
    if run_git(git, root, ca_file, repo, "rev-parse", "FETCH_HEAD").decode().strip() != COMMIT:
        raise ValueError("upstream commit differs from the pinned authority")
    run_git(git, root, ca_file, repo, "fsck", "--full", "--strict")
    tree_oid = run_git(git, root, ca_file, repo, "rev-parse", COMMIT + "^{tree}").decode().strip()
    if not re.fullmatch("[0-9a-f]{40}", tree_oid):
        raise ValueError("invalid upstream tree identity")
    entries = tree_entries(run_git(git, root, ca_file, repo, "ls-tree", "-r", "-z", COMMIT))
    batch = run_git(git, root, ca_file, repo, "cat-file", "--batch",
                    input=b"".join(oid.encode() + b"\n" for _, _, oid in entries))
    return batch_files(entries, batch), tree_oid


def convenience_links(output_base, configuration="local_linux-fastbuild"):
    # R-N13: only these exact reviewed action profiles are eligible. Their targets
    # remain exact descendants of the independently declared output base.
    if configuration not in BAZEL_CONFIGURATIONS:
        raise ValueError("unsupported Bazel convenience configuration")
    source_directory(output_base)
    source_directory(output_base.parent)
    if any(output_base == base or output_base.is_relative_to(base) for base in (Path("/tmp"), Path("/private/tmp"))):
        raise ValueError("Bazel output base must be durable")
    execution = output_base / "execroot/_main"
    targets = {
        "bazel-bin": execution / "bazel-out" / configuration / "bin",
        "bazel-out": execution / "bazel-out",
        "bazel-source": execution,
        "bazel-testlogs": execution / "bazel-out" / configuration / "testlogs",
    }
    if any(path.resolve() != path or not path.resolve().is_relative_to(output_base) for path in targets.values()):
        raise ValueError("Bazel convenience target redirects from its declared location")
    return {name: str(path) for name, path in targets.items()}


def verify_tree(source, files, generated_links=None):
    source_directory(source)
    generated_links = generated_links or {}
    if set(files) & set(generated_links):
        raise ValueError("generated output collides with pinned source")
    for name, target in generated_links.items():
        path = source / name
        info = path.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or os.readlink(path) != target:
            raise ValueError("Bazel convenience link custody mismatch")
    actual = set()
    for directory, dirs, names in os.walk(source, followlinks=False):
        for name in dirs[:]:
            path = Path(directory) / name
            if path.is_symlink():
                names.append(name)
                dirs.remove(name)
        for name in names:
            actual.add(str((Path(directory) / name).relative_to(source)))
    if actual != set(files) | set(generated_links):
        raise ValueError("complete source inventory mismatch")
    for name, (mode, value) in files.items():
        path = source / name
        info = path.lstat()
        if info.st_uid != os.getuid():
            raise ValueError("source ownership mismatch")
        if mode == "120000":
            if not path.is_symlink() or os.readlink(path).encode() != value or not path.resolve().is_relative_to(source):
                raise ValueError("source symlink mismatch or escape")
        elif not stat.S_ISREG(info.st_mode) or path.read_bytes() != value or stat.S_IMODE(info.st_mode) != (0o755 if mode == "100755" else 0o644):
            raise ValueError("source blob or mode mismatch: " + name)


def overlay_changes(overlay, originals):
    mapping = {name: "codex-rs/validation/" + name for name in OVERLAY_PATHS}
    text = overlay.decode()
    text = "".join(line for line in text.splitlines(keepends=True)
                   if not re.fullmatch(r"index [0-9a-f]+\.\.[0-9a-f]+(?: [0-7]+)?\n", line))
    for name, synthetic in mapping.items():
        text = text.replace("a/" + name, "a/" + synthetic).replace("b/" + name, "b/" + synthetic)
    changed = apply_exact(text, {mapping[name]: originals[name] for name in OVERLAY_PATHS})
    if set(changed) != set(mapping.values()):
        raise ValueError("validation overlay scope differs")
    return {name: changed[synthetic] for name, synthetic in mapping.items()}


def verify_packaged_base(files, artifact_original, manifest):
    for name, value in artifact_original.items():
        if name not in files or files[name][1] != value:
            raise ValueError("packaged original differs from pinned Git: " + name)
    for name, entry in manifest["files"].items():
        if entry["before_sha256"] is None:
            if name in files:
                raise ValueError("candidate new file already exists in pinned Git")
        elif name not in files or digest(files[name][1]) != entry["before_sha256"]:
            raise ValueError("candidate original digest differs from pinned Git")


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--git", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--phase", choices=("fetch", "restore-pristine", "verify", "prepare", "verify-prepared"), required=True)
    parser.add_argument("--pristine-archive", type=Path)
    parser.add_argument("--pristine-archive-sha256")
    parser.add_argument("--pristine-receipt", type=Path)
    parser.add_argument("--pristine-receipt-sha256")
    parser.add_argument("--bazel-output-base", type=Path)
    parser.add_argument("--bazel-configuration", choices=BAZEL_CONFIGURATIONS,
                        help="Exact convenience-link profile (default with output base: local_linux-fastbuild)")
    args = parser.parse_args(argv)
    pristine = (args.pristine_archive, args.pristine_archive_sha256,
                args.pristine_receipt, args.pristine_receipt_sha256)
    if any(value is not None for value in pristine) and not all(value is not None for value in pristine):
        parser.error("complete pristine archive and receipt inputs required")
    if args.phase == "restore-pristine" and not all(value is not None for value in pristine):
        parser.error("restore-pristine requires verified archive inputs")
    if args.phase == "fetch" and any(value is not None for value in pristine):
        parser.error("network fetch and cached pristine inputs are exclusive")
    if args.bazel_output_base is not None and args.phase != "verify-prepared":
        parser.error("--bazel-output-base is valid only for verify-prepared")
    if args.bazel_configuration is not None and (
            args.phase != "verify-prepared" or args.bazel_output_base is None):
        parser.error("--bazel-configuration requires verify-prepared and --bazel-output-base")
    if args.bazel_output_base is not None and args.bazel_configuration is None:
        args.bazel_configuration = "local_linux-fastbuild"
    return args


def main():
    args = parse_arguments()
    root = args.root
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    manifest = json.loads((artifact / "manifest.json").read_text())
    validation = json.loads((artifact / "validation.json").read_text())
    if manifest["upstream_commit"] != COMMIT or manifest["upstream_repository"] != URL.removesuffix(".git"):
        raise ValueError("artifact source pin differs")
    artifact_original, patch, overlay = verify_artifact(artifact, manifest)
    private_root(root, create=args.phase in ("fetch", "restore-pristine"))
    generated_links = convenience_links(args.bazel_output_base, args.bazel_configuration) if args.bazel_output_base is not None else {}
    if args.phase == "fetch":
        (root / "home").mkdir(mode=0o700)
        run_git(args.git, root, args.ca_file, "init", "--bare", str(root / "git"))
        run_git(args.git, root, args.ca_file, "--git-dir=" + str(root / "git"), "fetch", "--depth=1", "--no-tags", URL, COMMIT)
    if args.pristine_archive is not None:
        # This dependency is declared only by the cached-source producer lane.
        # Network-based historical targets keep their existing execution inputs.
        # Keep __file__ at its declared runfiles location; resolving it would
        # follow source symlinks and import from an ambient mutable checkout.
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
        from restore_pristine_inputs import original_files as pristine_files
        files, tree_oid = pristine_files(args.pristine_archive, args.pristine_archive_sha256,
                                         args.pristine_receipt, args.pristine_receipt_sha256)
    else:
        files, tree_oid = original_files(args.git, root, args.ca_file)
    verify_packaged_base(files, artifact_original, manifest)
    source = root / "source"
    if args.phase in ("fetch", "restore-pristine"):
        source.mkdir(mode=0o700)
        for name, (mode, value) in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if mode == "120000":
                path.symlink_to(value.decode())
            else:
                path.write_bytes(value)
                path.chmod(0o755 if mode == "100755" else 0o644)
        verify_tree(source, files)
    elif args.phase == "verify":
        verify_tree(source, files)
    else:
        if args.phase == "prepare":
            verify_tree(source, files)
            verify_inputs(source, manifest)
        changed = combine_changes(patch, overlay, artifact_original, manifest)
        validation_overlay = (artifact / "validation-overlay.patch").read_bytes()
        if digest(validation_overlay) != validation["validation_environment"]["validation_overlay_sha256"]:
            raise ValueError("validation overlay digest differs")
        changed.update(overlay_changes(validation_overlay, {name: files[name][1] for name in OVERLAY_PATHS}))
        for name, value in changed.items():
            mode = files.get(name, ("100644", b""))[0]
            files[name] = (mode, value)
        expected = validation["validation_environment"]
        for name, field in [("MODULE.bazel", "module_sha256"), ("MODULE.bazel.lock", "resolved_module_lock_sha256"),
                            ("codex-rs/Cargo.lock", "cargo_lock_sha256"), ("codex-rs/Cargo.toml", "normalized_workspace_manifest_sha256")]:
            if digest(files[name][1]) != expected[field]:
                raise ValueError("validated graph digest mismatch: " + name)
        if args.phase == "prepare":
            for name, value in changed.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
                path.chmod(0o755 if files[name][0] == "100755" else 0o644)
        verify_tree(source, files, generated_links if args.phase == "verify-prepared" else None)
    inventory = {name: {"mode": mode, "sha256": digest(value)} for name, (mode, value) in sorted(files.items())}
    report = {"ruling_id": "R-N13", "phase": args.phase, "commit": COMMIT, "upstream_tree_oid": tree_oid,
              "source": str(source), "tracked_files": len(files), "source_bytes": sum(len(value) for _, value in files.values()),
              "execution_closure": os.environ.get("OMUX_BAZEL_CLOSURE"),
              "coordinator_bootstrap_closure": os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE"),
              "generated_output_links": generated_links,
              "generated_output_link_count": len(generated_links),
              "bazel_configuration": args.bazel_configuration,
              "patch_sha256": manifest["patch_sha256"], "complete_inventory_sha256": digest(json.dumps(inventory, sort_keys=True).encode()),
              "files": inventory}
    if args.pristine_archive is not None:
        report["pristine_input"] = {"archive_sha256": args.pristine_archive_sha256,
                                     "receipt_sha256": args.pristine_receipt_sha256}
    receipt_name = args.phase + "-receipt-" + uuid.uuid4().hex + ".json"
    report["receipt_file"] = str(root / receipt_name)
    write_receipt(root, receipt_name, report)
    print(json.dumps({key: value for key, value in report.items() if key != "files"}, sort_keys=True))


if __name__ == "__main__":
    main()
