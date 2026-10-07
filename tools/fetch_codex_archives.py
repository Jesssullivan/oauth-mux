"""Contained file-only Nix prefetch for the exact audited Codex archive set.

Run only as a declared Bazel dependency producer inside the reviewed controller.
This program never evaluates/builds Nix expressions or invokes a shell.
"""

import argparse
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time


MIB = 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_FILES = 20000
MAX_STDOUT = 64 * 1024
MAX_STDERR = 256 * 1024
MAX_FILE_BYTES = 1024 * MIB
MAX_DEADLINE_SECONDS = 1200
MAX_RETAINED_BYTES = 4 * 1024 * MIB
PINNED_NIX = Path("/nix/store/fphbr6vvc2fdmx02nkagnbx0nv04f709-nix-2.34.6/bin/nix")
PINNED_CA = Path("/nix/store/zp564phiicll8d53d973gbh8y3iiwlm7-nss-cacert-3.121/etc/ssl/certs/ca-bundle.crt")
ARCHIVES = (
    ("x86_64-linux-gnu.2.28.tar.zst", "8015f4a710987439dfdcde7539b62cc5db52d2cd9456af5e2e297494f13c56f3", "https://github.com/cerisier/glibc-headers/releases/download/2.28-20250512/"),
    ("6.17.13-x86.tar.zst", "2bb80502d70cadabd1efa0e0cd7ff826873fd787ab593f6394d6ada57248780a", "https://github.com/cerisier/kernel-headers/releases/download/6.17.13-20260228/"),
    ("rustc-1.95.0-x86_64-unknown-linux-gnu.tar.xz", "8426a3d170a5879f5682f5fbdd024a1779b3951e7baba685af2d6dc32a6dfc15", "https://static.rust-lang.org/dist/"),
    ("rust-std-1.95.0-x86_64-unknown-linux-gnu.tar.xz", "047ea7098803d3500fa1072e9cee5392697e21525559e4458128a2bf874aa382", "https://static.rust-lang.org/dist/"),
    ("cargo-1.95.0-x86_64-unknown-linux-gnu.tar.xz", "e74edd2cf7d0f1f1383b4f00eb90c843750bc489e2ccf7214e6476678a907425", "https://static.rust-lang.org/dist/"),
    ("clippy-1.95.0-x86_64-unknown-linux-gnu.tar.xz", "ac779bc9839dd47180806b133e4e2563c4a34716284cd5b8fede8ef289f452ca", "https://static.rust-lang.org/dist/"),
    ("rustfmt-1.95.0-x86_64-unknown-linux-gnu.tar.xz", "f1b2a7301513ffdd95ebf22ebbdd932e4d17fc806f748d93924740d0297b1396", "https://static.rust-lang.org/dist/"),
    ("llvm-toolchain-minimal-22.1.8-linux-amd64-musl.tar.zst", "89f29294a584267251edac00ab723a0a74514b8e1acb7f036840d13635c66bfa", "https://github.com/hermeticbuild/hermetic-llvm/releases/download/llvm-22.1.8-1/"),
    ("toolchain-extra-prebuilts-20260429-linux-amd64-musl.tar.zst", "418a27a0ab8ecf46e2e00bd4381efc0bcb54c28312261c4f36114842e5ecb20e", "https://github.com/hermeticbuild/hermetic-llvm/releases/download/prebuilts-extras-20260429/"),
    ("llvm-project-22.1.8.src.tar.zst", "0a120cd02aa4319887b938ed98f34907563e9b4bcdd4a2aed23a1a05dd5a8157", "https://github.com/hermeticbuild/llvm-redist/releases/download/llvmorg-22.1.8-r1/"),
    ("toml2json_linux_amd64", "87921b36ceb343af152fc988be59eec49ac9865f2e499a48152bed03e66f8228", "https://github.com/hermeticbuild/toml2json/releases/download/v0.0.26/"),
    ("bindgen_linux_amd64.tar.zst", "ec2b39a56443142a34dc76ec32a17cb099c6c09137c3fbac893310c623cb10ac", "https://github.com/hermeticbuild/bindgen/releases/download/v0.0.2/"),
    ("cpython-3.11.14+20251014-x86_64-unknown-linux-gnu-install_only.tar.gz", "d0623c777fb89b904b56cd5aba51af29cbb34b1f9d45f0672f90f6dce30fa93e", "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_manifest(payload, expected):
    require(len(payload) <= MAX_MANIFEST, "manifest exceeds bound")
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "manifest digest is noncanonical")
    require(hashlib.sha256(payload).hexdigest() == expected, "manifest digest mismatch")
    value = json.loads(payload, object_pairs_hook=unique_object)
    require(value.get("schema_version") == 1 and value.get("system") == "x86_64-linux", "manifest schema mismatch")
    entries = value.get("archives")
    require(isinstance(entries, list) and len(entries) == len(ARCHIVES), "archive set mismatch")
    for entry, (name, digest, base) in zip(entries, ARCHIVES):
        require(isinstance(entry, dict) and entry.get("name") == name and entry.get("sha256") == digest
                and entry.get("url") == base + name, "archive allowlist mismatch")
    return entries


def read_manifest(path, expected):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_MANIFEST,
                "manifest must be a bounded regular file")
        payload = bytearray()
        while len(payload) <= MAX_MANIFEST:
            chunk = os.read(descriptor, MAX_MANIFEST + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "manifest changed while reading")
        return load_manifest(bytes(payload), expected)
    finally:
        os.close(descriptor)


def declared_manifest_path(path, helper_file=None):
    """Resolve only the paired manifest alias beside this declared helper."""
    helper = Path(__file__ if helper_file is None else helper_file).absolute()
    supplied = Path(path)
    paired = helper.parent / "codex_upstream_archives.json"
    require(supplied.is_absolute() and supplied == paired, "manifest is not the declared paired runfile")
    # Both declared runfiles must resolve into the same source tools directory.
    # No ambient runfiles directory, cwd fallback or arbitrary link is admitted.
    source = helper.resolve(strict=True).parent / paired.name
    resolved = supplied.resolve(strict=True)
    require(resolved == source and not source.is_symlink(), "declared manifest source context mismatch")
    return resolved


def deadline_bounds(total, per_file):
    require(1 <= per_file <= total <= MAX_DEADLINE_SECONDS, "deadline bounds invalid")


def child_file_limits():
    # Preserve tighter inherited bounds; never raise the controller's limits.
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)
    bound = min([MAX_FILE_BYTES] + [value for value in inherited if value != resource.RLIM_INFINITY])
    return (bound, bound)


def prefetch_reply(payload):
    require(len(payload) <= MAX_STDOUT, "download output exceeded bound")
    return json.loads(payload, object_pairs_hook=unique_object)


def immutable_file(value):
    path = Path(value)
    require(path.is_absolute(), "immutable input must be absolute")
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to("/nix/store"), "input outside pinned store")
    info = resolved.stat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022, "immutable input custody mismatch")
    return resolved


def measure(root):
    """Bounded traversal of only our root; do not follow links or cross mounts."""
    device = root.stat().st_dev
    pending = [root]
    count = logical = allocated = 0
    while pending:
        path = pending.pop()
        try:
            entries = os.scandir(path)
        except FileNotFoundError:
            continue  # Nix may atomically move its own temporary directory.
        with entries:
            for entry in entries:
                count += 1
                require(count <= MAX_FILES, "private file count exceeded")
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                require(info.st_dev == device, "private root crossed filesystem")
                allocated += info.st_blocks * 512
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    logical += info.st_size
    return max(logical, allocated)


def disk_check(root, disk_budget, free_floor):
    require(measure(root) <= disk_budget, "private disk budget exceeded")
    usage = os.statvfs(root)
    require(usage.f_bavail * usage.f_frsize >= free_floor, "filesystem free floor crossed")


def child_environment(root, ca):
    return {"HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "home/config"),
            "XDG_CACHE_HOME": str(root / "home/cache"), "NIX_CONF_DIR": str(root / "config"),
            "NIX_USER_CONF_FILES": "", "NIX_PATH": "", "NIX_REMOTE": "", "PATH": "",
            "TMPDIR": str(root / "tmp"), "SSL_CERT_FILE": str(ca), "NIX_SSL_CERT_FILE": str(ca),
            "LC_ALL": "C", "NIX_CONFIG": "experimental-features = nix-command\nbuild-users-group =\nbuilders =\nsubstituters =\nmax-jobs = 0\nhttp-connections = 1\ndownload-attempts = 1\nconnect-timeout = 15\nstalled-download-timeout = 30\n"}


def prefetch_command(nix, root, entry):
    return [str(nix), "--store", "local?root=" + str(root / "private-store"),
            "store", "prefetch-file", "--json", "--hash-type", "sha256",
            "--expected-hash", entry["sha256"], "--name", entry["name"], entry["url"]]


def run_prefetch(command, environment, root, deadline, disk_budget, free_floor):
    disk_check(root, disk_budget, free_floor)
    require(time.monotonic() < deadline, "download deadline exceeded")
    process = subprocess.Popen(command, env=environment, cwd=root, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                               preexec_fn=partial(resource.setrlimit, resource.RLIMIT_FSIZE, child_file_limits()))
    selector = selectors.DefaultSelector()
    output = bytearray()
    totals = {"stdout": 0, "stderr": 0}
    try:
        for name in totals:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            require(time.monotonic() < deadline, "download deadline exceeded")
            disk_check(root, disk_budget, free_floor)
            for key, _ in selector.select(0.1):
                packet = os.read(key.fileobj.fileno(), 8192)
                if not packet:
                    selector.unregister(key.fileobj)
                    continue
                totals[key.data] += len(packet)
                require(totals[key.data] <= (MAX_STDOUT if key.data == "stdout" else MAX_STDERR), "download output exceeded bound")
                if key.data == "stdout":
                    output.extend(packet)
        # Keep the child unreaped while sending group cleanup, pinning its PGID.
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            require(time.monotonic() < deadline, "download exit deadline exceeded")
            disk_check(root, disk_budget, free_floor)
            time.sleep(0.05)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()
    require(process.returncode == 0, "download child failed")
    disk_check(root, disk_budget, free_floor)
    return prefetch_reply(output)


def export_payload(root, reply, entry, deadline, disk_budget, free_floor, retained_remaining=MAX_RETAINED_BYTES):
    require(isinstance(reply, dict) and set(reply) == {"storePath", "hash"}, "prefetch reply shape mismatch")
    # Nix store hash uses a 32-character Nix-base32 path component.
    logical = reply["storePath"]
    require(isinstance(logical, str) and re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-" + re.escape(entry["name"]), logical), "prefetch store path mismatch")
    import base64
    require(reply["hash"] == "sha256-" + base64.b64encode(bytes.fromhex(entry["sha256"])).decode(), "prefetch hash mismatch")
    source = root / "private-store" / logical.lstrip("/")
    require(source.resolve(strict=True) == source, "private payload traversed link")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    output = root / "distdir" / entry["name"]
    digest = hashlib.sha256()
    size = 0
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o222,
                "private payload custody mismatch")
        require(info.st_size <= min(disk_budget, MAX_FILE_BYTES), "payload exceeds per-file or disk budget")
        require(info.st_size <= retained_remaining, "retained archive sum exceeds bound")
        with os.fdopen(fd, "rb") as incoming:
            fd = None
            outfd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(outfd, "wb") as outgoing:
                while True:
                    require(time.monotonic() < deadline, "export deadline exceeded")
                    disk_check(root, disk_budget, free_floor)
                    chunk = incoming.read(MIB)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    outgoing.write(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        require(size == info.st_size and digest.hexdigest() == entry["sha256"], "exported payload digest mismatch")
        output.chmod(0o400)
    finally:
        if fd is not None:
            os.close(fd)
    disk_check(root, disk_budget, free_floor)
    return {"name": entry["name"], "sha256": digest.hexdigest(), "bytes": size,
            "logical_store_path": logical, "status": "verified-export"}


def receipt(root, report):
    # Atomic replacement touches only our newly owned progress receipt.
    temporary = root / "receipt.next.json"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, root / "receipt.json")


def main(arguments=None, declared_manifest=False):
    parser = argparse.ArgumentParser()
    parser.add_argument("--nix", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--deadline-seconds", type=int, default=MAX_DEADLINE_SECONDS)
    parser.add_argument("--file-deadline-seconds", type=int, default=300)
    parser.add_argument("--disk-budget-bytes", type=int, default=8 * 1024 * MIB)
    parser.add_argument("--free-floor-bytes", type=int, default=4 * 1024 * MIB)
    args = parser.parse_args(arguments)
    deadline_bounds(args.deadline_seconds, args.file_deadline_seconds)
    require(64 * MIB <= args.disk_budget_bytes <= 16 * 1024 * MIB and MIB <= args.free_floor_bytes <= 32 * 1024 * MIB, "disk bounds invalid")
    nix, ca = immutable_file(args.nix), immutable_file(args.ca_file)
    require(nix == PINNED_NIX and ca == PINNED_CA, "bootstrap input pin mismatch")
    with nix.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "Nix input is not the actual native binary")
    manifest_path = declared_manifest_path(args.manifest) if declared_manifest else args.manifest
    entries = read_manifest(manifest_path, args.manifest_sha256)
    root = args.output_directory
    require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent, "output parent is noncanonical")
    info = root.parent.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "output parent is untrusted")
    root.mkdir(mode=0o700)
    for name in ("home", "tmp", "config", "private-store", "distdir"):
        (root / name).mkdir(mode=0o700)
    report = {"status": "partial", "manifest_sha256": args.manifest_sha256,
              "nix": str(nix), "ca_file": str(ca), "native_support": False,
              "native_proof": False, "disk_budget_bytes": args.disk_budget_bytes,
              "free_floor_bytes": args.free_floor_bytes, "deadline_seconds": args.deadline_seconds,
              "file_deadline_seconds": args.file_deadline_seconds,
              "retained_sum_limit_bytes": MAX_RETAINED_BYTES,
              "child_per_file_limit_bytes": child_file_limits()[0],
              "disk_enforcement": "child RLIMIT_FSIZE caps individual files only; aggregate own-root usage is monitored with sampling overshoot, not a hard aggregate quota",
              "verified": [], "missing": [entry["name"] for entry in entries]}
    receipt(root, report)
    deadline = time.monotonic() + args.deadline_seconds
    try:
        for entry in entries:
            end = min(deadline, time.monotonic() + args.file_deadline_seconds)
            reply = run_prefetch(prefetch_command(nix, root, entry), child_environment(root, ca), root,
                                 end, args.disk_budget_bytes, args.free_floor_bytes)
            retained_remaining = MAX_RETAINED_BYTES - sum(row["bytes"] for row in report["verified"])
            report["verified"].append(export_payload(root, reply, entry, end, args.disk_budget_bytes, args.free_floor_bytes, retained_remaining))
            report["missing"].remove(entry["name"])
            receipt(root, report)
        report["status"] = "complete-verified-distdir"
        receipt(root, report)
    except BaseException:
        report["status"] = "failed-partial"
        receipt(root, report)
        raise


def publish_bundle(root, outputs):
    """Publish our verified files atomically without copying archive payloads."""
    report = json.loads((root / "receipt.json").read_bytes(), object_pairs_hook=unique_object)
    require(report.get("status") == "complete-verified-distdir" and not report.get("missing"),
            "incomplete dependency bundle")
    names = {entry[0] for entry in ARCHIVES}
    verified = report.get("verified", [])
    require(len(verified) == len(ARCHIVES) and {row["name"] for row in verified} == names,
            "bundle archive set mismatch")
    require(sum(row["bytes"] for row in verified) <= MAX_RETAINED_BYTES, "retained archive sum exceeds bound")
    distdir = root / "distdir"
    require({path.name for path in distdir.iterdir()} == names, "bundle contains extra files")
    for row in verified:
        path = distdir / row["name"]
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    info.st_size == row["bytes"] and info.st_size <= MAX_FILE_BYTES,
                    "bundle archive custody mismatch")
            value = hashlib.sha256()
            while chunk := os.read(descriptor, MIB):
                value.update(chunk)
            expected = next(digest for name, digest, _ in ARCHIVES if name == row["name"])
            require(value.hexdigest() == row["sha256"] == expected, "bundle archive digest mismatch")
        finally:
            os.close(descriptor)
    require(distdir.stat().st_dev == outputs.stat().st_dev, "bundle output must share the scratch filesystem")
    destination = outputs / "bundle"
    require(not destination.exists() and not destination.is_symlink(), "bundle output already exists")
    os.rename(root / "receipt.json", distdir / "receipt.json")
    os.rename(distdir, destination)
    return report


def bundle_main(arguments):
    require("--output-directory" not in arguments, "bundle owns its output paths")
    scratch = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
    outputs = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    for directory in (scratch, outputs):
        info = directory.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "test output custody mismatch")
    require(not any(outputs.iterdir()), "bundle requires empty undeclared outputs")
    # Scratch is never exported. TemporaryDirectory cleans the private Nix store
    # and configuration on both success and ordinary exception paths; the
    # controller still owns cleanup after forced termination.
    with tempfile.TemporaryDirectory(prefix="codex-archive-fetch-", dir=scratch) as temporary:
        root = Path(temporary) / "worker"
        main([*arguments, "--output-directory", str(root),
              "--disk-budget-bytes", str(8 * 1024 * MIB),
              "--free-floor-bytes", str(4 * 1024 * MIB)], declared_manifest=True)
        publish_bundle(root, outputs)


if __name__ == "__main__":
    if "--bundle" in sys.argv[1:]:
        bundle_main([argument for argument in sys.argv[1:] if argument != "--bundle"])
    else:
        main()
