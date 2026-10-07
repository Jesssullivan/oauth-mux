"""Offline pristine Codex archive producer from explicitly bound pack inputs."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

# __file__ is the declared main's runfiles path. Never resolve it through the
# runfiles symlink into the mutable checkout or add an ambient repository root.
sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-upstream"))
import restore_source
import restore_pristine_inputs

COMMIT = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
TREE = "6fa1a3767a92ba5d579fcaf724fdce3049c2070b"
PACK = "pack-c4c9ce7cd275c2c4f91c442087b9738342ae193a"
PACK_DIGESTS = {
    "pack": "a5352614ad43f69db50e798865e2787aab7e8835036b2c14c55158c0f728a6d8",
    "idx": "6b9fdc44bdc8fea494bfed8d0422e398ffe9ef780656a676a045c51c7ccd9a43",
    "rev": "c7c1ff72452e4f924d042c06728761f9eb3097ebe60782cb19c6dead1fc72ee9",
}
PINNED_GIT = Path("/nix/store/c0277k5giric1mn9dklllavbzvxl6hzb-git-2.53.0/bin/git")
MAX_PACK = 128 * 1024 * 1024
MAX_OUTPUT = 512 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def copy_bound(source, target, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "pack digest is noncanonical")
    digest = hashlib.sha256()
    fd = os.open(source.resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as incoming:
        info = os.fstat(incoming.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_PACK, "pack input bound mismatch")
        outfd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(outfd, "wb") as outgoing:
            size = 0
            while chunk := incoming.read(1024 * 1024):
                size += len(chunk)
                require(size <= MAX_PACK, "pack input grew beyond bound")
                digest.update(chunk)
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        require(size == info.st_size and digest.hexdigest() == expected, "pack input digest mismatch")
    target.chmod(0o400)
    return {"name": target.name, "sha256": expected, "bytes": size}


def run_git(git, root, ca_file, *args, input=None):
    # Existing original_files() batches blob stdin. It is bounded by tree size.
    command = [str(git), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
               "-c", "core.attributesFile=/dev/null", "-c", "protocol.allow=never", "-c", "tar.umask=0022", *args]
    environment = restore_source.git_environment(root, ca_file)
    process = subprocess.Popen(command, cwd=root, env=environment, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    errors = 0
    try:
        if input is not None:
            require(len(input) <= 4 * 1024 * 1024, "Git stdin exceeds bound")
            # ls-tree OID batch is small; nonblocking write participates in deadline.
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        position = 0
        deadline = time.monotonic() + 120
        while selector.get_map():
            require(time.monotonic() < deadline, "Git action deadline exceeded")
            for key, _ in selector.select(0.05):
                if key.data == "stdin":
                    if position < len(input):
                        position += os.write(key.fileobj.fileno(), input[position:position + 8192])
                    if position == len(input):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "stdout":
                    require(len(output) + len(chunk) <= MAX_OUTPUT, "Git output exceeds bound")
                    output.extend(chunk)
                else:
                    errors += len(chunk)
                    require(errors <= 256 * 1024, "Git diagnostic output exceeds bound")
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            require(time.monotonic() < deadline, "Git exit deadline exceeded")
            time.sleep(0.05)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    require(process.returncode == 0, "offline Git action failed")
    return bytes(output)


def write_archive(archive, output):
    require(len(archive) <= MAX_OUTPUT, "pristine tar exceeds bound")
    with output.open("xb") as stream:
        # Empty gzip filename and fixed mtime make the archive independent of
        # action path and wall clock. Git's tar bytes already bind the commit.
        with gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=stream, mtime=0) as compressed:
            for position in range(0, len(archive), 1024 * 1024):
                compressed.write(archive[position:position + 1024 * 1024])
        stream.flush()
        os.fsync(stream.fileno())
    digest = hashlib.sha256()
    size = 0
    with output.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            require(size <= MAX_OUTPUT, "compressed pristine archive exceeds bound")
            digest.update(chunk)
    return {"archive_format": "tar.gz", "archive_sha256": digest.hexdigest(), "archive_bytes": size,
            "uncompressed_archive_bytes": len(archive)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--git", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path)
    for extension in ("pack", "idx", "rev"):
        parser.add_argument("--" + extension, type=Path, required=True)
        parser.add_argument("--" + extension + "-sha256", required=True)
    args = parser.parse_args()
    require(args.git.resolve(strict=True) == PINNED_GIT.resolve(strict=True), "Git pin mismatch")
    require(args.ca_file.resolve(strict=True).is_relative_to("/nix/store"), "CA outside pinned store")
    root = args.output_directory
    if root is None:
        require(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared test output directory required")
        root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True) / "codex-pristine-source"
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent, "output parent is noncanonical")
    info = root.parent.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "output parent is untrusted")
    root.mkdir(mode=0o700)
    require(os.environ.get("TEST_TMPDIR"), "declared action scratch directory required")
    scratch_parent = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
    info = scratch_parent.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "scratch parent is untrusted")
    with tempfile.TemporaryDirectory(prefix="codex-pristine-work-", dir=scratch_parent) as scratch:
        produce(args, Path(scratch), root)
    # Publish the final receipt only after our owned scratch cleanup succeeds.
    (root / "pristine-receipt.pending.json").rename(root / "pristine-receipt.json")
    (root / "pristine.tar.gz").chmod(0o400)
    (root / "pristine-receipt.json").chmod(0o400)


def produce(args, root, output):
    (root / "home").mkdir(mode=0o700)
    restore_source.run_git = run_git
    run_git(args.git, root, args.ca_file, "init", "--bare", str(root / "git"))
    inputs = []
    for extension in ("pack", "idx", "rev"):
        source = getattr(args, extension)
        require(source.name == PACK + "." + extension, "pack input name mismatch")
        require(getattr(args, extension + "_sha256") == PACK_DIGESTS[extension], "observed pack digest pin mismatch")
        inputs.append(copy_bound(source, root / "git/objects/pack" / source.name, getattr(args, extension + "_sha256")))
    (root / "git/FETCH_HEAD").write_text(COMMIT + "\n")
    # The observed source mirror was fetched depth=1. Pin its shallow boundary
    # explicitly; no missing parent is fetched or treated as local source.
    (root / "git/shallow").write_text(COMMIT + "\n")
    files, tree = restore_source.original_files(args.git, root, args.ca_file)
    require(tree == TREE and len(files) == 8497, "original tree inventory mismatch")
    archive = run_git(args.git, root, args.ca_file, "--git-dir=" + str(root / "git"), "archive", "--format=tar", COMMIT)
    archive_fields = write_archive(archive, output / "pristine.tar.gz")
    inventory = {name: {"mode": mode, "sha256": hashlib.sha256(value).hexdigest()}
                 for name, (mode, value) in sorted(files.items())}
    report = {"status": "verified-pristine-source", "commit": COMMIT, "tree": TREE,
              "inputs": inputs, "files": inventory, "tracked_files": len(files),
              "source_bytes": sum(len(value) for _, value in files.values()),
              "inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
              "native_support": False, "candidate_promoted": False}
    report.update(archive_fields)
    payload = (json.dumps(report, indent=2) + "\n").encode()
    pending_receipt = output / "pristine-receipt.pending.json"
    with pending_receipt.open("xb") as stream:
        stream.write(payload)
    restore_pristine_inputs.original_files(output / "pristine.tar.gz", report["archive_sha256"],
                                          pending_receipt, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    main()
