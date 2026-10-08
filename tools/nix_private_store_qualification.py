"""Manual, local-only Bash build in a freshly seeded private Nix store."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

import nar_descriptor as nar
import nix_private_store_seed as seed

KIND = "omux-nix-private-store-build-qualification-v1"
OUTPUT_NAME = "omux-private-store-namespace-proof"
RESULT = b"omux-private-store-bash-built-v1\n"
MAX_SECONDS = 840
CLEANUP_SECONDS = 30
FREE_FLOOR = 2 * 1024**3
MAX_OUTPUT = 4 * 1024**2
PHASE = "admission"


def tick(deadline):
    seed.require(type(deadline) is float and time.monotonic() < deadline)


def identity(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


class OwnedRoot:
    def __init__(self, parent):
        parent = Path(parent).resolve(strict=True)
        self.path = Path(tempfile.mkdtemp(prefix="nix-private-build-", dir=parent))
        self.fd = None
        self.created = os.lstat(self.path)
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.before = identity(self.fd)
            self.recheck()
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            now = os.lstat(self.path)
            seed.require((now.st_dev, now.st_ino, now.st_uid, now.st_mode) ==
                (self.created.st_dev, self.created.st_ino, self.created.st_uid, self.created.st_mode))
            os.rmdir(self.path)  # Constructor has not made any descendants.
            raise

    def recheck(self):
        seed.require(self.fd is not None and identity(self.fd) == self.before)
        info = os.lstat(self.path)
        seed.require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == self.before
            and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700)
        seed.require(self.path.resolve(strict=True) == self.path)

    def close(self, deadline=None):
        deadline = float(time.monotonic() + CLEANUP_SECONDS) if deadline is None else deadline
        if self.fd is not None:
            try:
                self.recheck()
                # Never follow copied links, including links to host /etc.
                pending = [self.path]
                count = 0
                while pending:
                    tick(deadline)
                    directory = pending.pop()
                    info = os.lstat(directory)
                    seed.require(stat.S_ISDIR(info.st_mode) and info.st_dev == self.before[0])
                    os.chmod(directory, 0o700, follow_symlinks=False)
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            tick(deadline)
                            count += 1
                            seed.require(count <= seed.MAX_FILES * 4)
                            item = entry.stat(follow_symlinks=False)
                            seed.require(item.st_dev == self.before[0])
                            if stat.S_ISDIR(item.st_mode):
                                pending.append(Path(entry.path))
                self.recheck()
                tick(deadline)
                shutil.rmtree(self.path)
            finally:
                os.close(self.fd)
                self.fd = None


def platform(status, uid):
    fields = {}
    for line in status.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            fields[name] = value.strip()
    seed.require(type(uid) is int and uid != 0 and len(status) <= 65536
        and fields.get("NoNewPrivs") == "1" and fields.get("CapEff") == "0000000000000000"
        and fields.get("Uid", "").split() == [str(uid)] * 4)
    return {"nonroot": True, "no_new_privileges": True, "effective_capabilities_empty": True}


def environment(work):
    return {"HOME": str(work / "home"), "PATH": "", "NIX_PATH": "", "NIX_REMOTE": "",
            "NIX_CONFIG": "", "NIX_CONF_DIR": str(work / "config"), "NIX_USER_CONF_FILES": "",
            "XDG_CONFIG_HOME": str(work / "home/config"), "XDG_CACHE_HOME": str(work / "home/cache"),
            "XDG_STATE_HOME": str(work / "home/state"), "TMPDIR": str(work / "tmp"), "LC_ALL": "C"}


def common(executable, private):
    seed.require(re.fullmatch(seed.STORE + r"/bin/(nix|nix-store)", executable) is not None)
    seed.require(private.is_absolute() and private.resolve(strict=True) == private
                 and not any(character in str(private) for character in "?&#"))
    return [executable, "--store", "local?root=" + str(private),
            "--option", "builders", "", "--option", "substituters", "",
            "--option", "fallback", "false", "--option", "build-users-group", "",
            "--option", "sandbox", "true", "--option", "sandbox-fallback", "false",
            "--option", "sandbox-paths", "", "--option", "extra-sandbox-paths", "",
            "--option", "pre-build-hook", "", "--option", "post-build-hook", "",
            "--option", "max-jobs", "1", "--option", "cores", "2",
            "--option", "timeout", "90", "--option", "max-silent-time", "60",
            "--option", "allow-import-from-derivation", "false",
            "--option", "auto-optimise-store", "false"]


def expression(bash):
    seed.require(re.fullmatch(seed.STORE + "/bin/bash", bash) is not None)
    root = bash.rsplit("/bin/", 1)[0]
    script = 'set -eu; test ! -e "$out"; builtin printf "%s\\n" "omux-private-store-bash-built-v1" > "$out"'
    return ('derivation { name = "' + OUTPUT_NAME + '"; system = "x86_64-linux"; '
            'builder = builtins.appendContext ' + json.dumps(bash) + ' { ' + json.dumps(root) + ' = { path = true; }; }; '
            'args = [ "--noprofile" "--norc" "-c" ' + json.dumps(script) + ' ]; '
            'PATH = ""; preferLocalBuild = true; allowSubstitutes = false; }')


def commands(tools, private):
    url = "local?root=" + str(private)
    return (common(tools["nix_store"], private) + ["--load-db"],
            common(tools["nix_store"], private) + ["--dump-db"],
            common(tools["nix"], private) + ["--extra-experimental-features", "nix-command",
                "--offline", "build", "--option", "pure-eval", "true", "--eval-store", url, "--no-link", "--print-out-paths",
                "--expr", expression(tools["bash"])])


def run(command, env, cwd, deadline, *, input_file=None, tool_fd=None, output_limit=MAX_OUTPUT):
    """Every post-Popen operation is inside own-client cleanup."""
    tick(deadline)
    seed.require(type(output_limit) is int and 0 < output_limit <= 32 * 1024**2)
    seed.require(type(tool_fd) is int and tool_fd >= 0)
    info = os.fstat(tool_fd)
    seed.require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & stat.S_IXUSR))
    selected = selectors.DefaultSelector()
    process = None
    output = bytearray()
    count = 0
    cleanup_errors = []
    try:
        process = subprocess.Popen(command, env=env, cwd=cwd,
            stdin=input_file if input_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            executable="/proc/self/fd/" + str(tool_fd), pass_fds=(tool_fd,))
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selected.register(stream, selectors.EVENT_READ, name)
        while selected.get_map():
            tick(deadline)
            for key, _ in selected.select(min(1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selected.unregister(key.fileobj)
                    continue
                count += len(chunk)
                seed.require(count <= output_limit)
                if key.data == "stdout":
                    output.extend(chunk)
                # stderr is bounded and discarded, never retained or printed.
        tick(deadline)
        code = process.wait(timeout=deadline-time.monotonic())
        seed.require(type(code) is int and code == 0)
        return bytes(output)
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
            except ProcessLookupError:
                try:
                    process.wait(timeout=5)
                except BaseException as error:
                    cleanup_errors.append(error)
            except BaseException as error:
                cleanup_errors.append(error)
                try:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except BaseException as nested:
                    cleanup_errors.append(nested)
            for name in ("stdout", "stderr"):
                try:
                    if getattr(process, name) is not None:
                        getattr(process, name).close()
                except BaseException as error:
                    cleanup_errors.append(error)
        try:
            selected.close()
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise ValueError("private-store owned-client cleanup") from None


def source_opener(value, declared):
    """Only canonical regular leaves positively declared by the seed."""
    allowed = {row["source"] for row in value["files"]}
    seed.require(declared == allowed)
    def open_node(root, relative):
        source = root + ("/" + relative if relative else "")
        seed.require(source in allowed)
        return nar.open_regular(root, relative)
    return open_node


def describe_root(logical, physical=None):
    value = nar.describe(logical if physical is None else physical)
    value["root"] = logical
    return value


def verify_nars(value, opener, deadline, *, root_directory=None):
    records = seed.validate(value)
    total = 0
    for root in value["roots"]:
        tick(deadline)
        physical = root_directory / root.rsplit("/", 1)[1] if root_directory is not None else None
        actual = describe_root(root, physical)
        seed.require(seed.encoded(actual) == seed.encoded(value["descriptors"][root]))
        proof = nar.hash_descriptor(value["descriptors"][root], opener=opener, deadline=deadline)
        row = records[root]["record"]
        seed.require(proof["narHash"] == "sha256:" + seed.expected_hash(row[1])
                     and proof["narSize"] == int(row[2]))
        total += proof["narSize"]
        seed.require(total <= seed.MAX_BYTES)
    return total


def copy_seed(value, private, opener, deadline):
    """Exclusive files; inert links; copied bytes rehashed before DB import."""
    store = private / "nix/store"
    store.mkdir(parents=True, mode=0o755)
    for root in value["roots"]:
        tick(deadline)
        descriptor = value["descriptors"][root]
        destination = store / root.rsplit("/", 1)[1]
        for node in sorted(descriptor["nodes"], key=lambda row: (len(row["path"].split("/")) if row["path"] else 0, row["path"])):
            tick(deadline)
            target = destination / node["path"] if node["path"] else destination
            if node["type"] == "directory":
                target.mkdir(mode=0o755)
            elif node["type"] == "symlink":
                target.symlink_to(node["target"])
            else:
                with opener(root, node["path"]) as source:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as output:
                        remaining = node["size"]
                        while remaining:
                            tick(deadline)
                            chunk = source.read(min(65536, remaining))
                            seed.require(bool(chunk))
                            output.write(chunk)
                            remaining -= len(chunk)
                        seed.require(source.read(1) == b"")
                        output.flush()
                        os.fsync(output.fileno())
                        os.fchmod(output.fileno(), 0o555 if node["executable"] else 0o444)
        for node in sorted(descriptor["nodes"], key=lambda row: len(row["path"]), reverse=True):
            if node["type"] == "directory":
                os.chmod(destination / node["path"] if node["path"] else destination, 0o555)
    return verify_nars(value,
        lambda root, relative: nar.open_regular(str(store / root.rsplit("/", 1)[1]), relative), deadline,
        root_directory=store)


def builder_output(private, raw):
    seed.require(isinstance(raw, bytes) and len(raw) <= 512)
    logical = raw.decode("ascii").strip()
    seed.require(raw == (logical + "\n").encode() and re.fullmatch(seed.STORE, logical)
                 and logical.endswith("-" + OUTPUT_NAME))
    actual = private / "nix/store" / logical.rsplit("/", 1)[1]
    with nar.open_regular(str(actual), "") as stream:
        info = os.fstat(stream.fileno())
        payload = stream.read(len(RESULT) + 1)
        seed.require(stat.S_IMODE(info.st_mode) == 0o444 and info.st_uid == os.getuid()
                     and info.st_nlink == 1 and info.st_size == len(RESULT) and payload == RESULT)
    return {"logical_path": logical, "sha256": seed.sha(payload), "bytes": len(payload), "mode": 0o444}



def readback_records(raw, roots):
    """Pinned opDumpDB emits unprefixed base16; declared seed parsing stays strict."""
    global PHASE
    PHASE = "registration-readback-ascii"
    seed.require(isinstance(raw, bytes) and len(raw) <= MAX_OUTPUT)
    lines = raw.decode("ascii").splitlines()
    offset = 0
    while offset < len(lines):
        PHASE = "registration-readback-wire"
        seed.require(offset+5 <= len(lines) and re.fullmatch("[0-9]{1,4}", lines[offset+4]) is not None)
        count = int(lines[offset+4])
        seed.require(count <= 4096 and offset+5+count <= len(lines))
        PHASE = "registration-readback-wire-hash"
        seed.require(re.fullmatch("[0-9a-f]{64}", lines[offset+1]) is not None)
        lines[offset+1] = "sha256:"+lines[offset+1]
        offset += 5+count
    PHASE = "registration-readback-parse"
    return seed.registrations("\n".join(lines)+"\n", roots)


def compare_readback(expected, actual):
    """Exact fields remain mandatory; only fixed predicate names are diagnostic."""
    global PHASE
    PHASE = "registration-readback-roots"
    seed.require(set(expected) == set(actual))
    for name in expected:
        left, right = expected[name], actual[name]
        PHASE = "registration-readback-hash"
        seed.require(seed.expected_hash(left["record"][1]) == seed.expected_hash(right["record"][1]))
        PHASE = "registration-readback-size"
        seed.require(int(left["record"][2]) == int(right["record"][2]))
        PHASE = "registration-readback-deriver"
        seed.require(left["record"][3] == right["record"][3])
        PHASE = "registration-readback-references"
        seed.require(set(left["references"]) == set(right["references"]))


def _qualify(value, seed_raw, parent, source_pins, deadline, opener, tool_fds, *, runner=run):
    global PHASE
    tick(deadline)
    records = seed.validate(value)
    PHASE = "seed-byte-proof"
    verified = verify_nars(value, opener, deadline)
    root = OwnedRoot(parent)
    result = None
    try:
        root.recheck()
        free = os.statvfs(root.path)
        seed.require(free.f_bavail * free.f_frsize >= verified * 2 + FREE_FLOOR)
        for name in ("private-store", "home", "config", "tmp"):
            (root.path / name).mkdir(mode=0o700)
        private = root.path / "private-store"
        PHASE = "seed-copy"
        copied = copy_seed(value, private, opener, deadline)
        seed.require(copied == verified)
        import_cmd, readback_cmd, build_cmd = commands(value["tools"], private)
        for tool in value["tools"].values():
            seed.resolve_member(value, tool)
        registration = root.path / "registration"
        registration.write_bytes(value["registration"].encode("ascii"))
        os.chmod(registration, 0o400)
        PHASE = "registration-import"
        with nar.open_regular(str(registration), "") as stream:
            seed.require(runner(import_cmd, environment(root.path), root.path, deadline,
                                input_file=stream, tool_fd=tool_fds["nix_store"]) == b"")
        root.recheck()
        PHASE = "registration-readback-child"
        dumped = runner(readback_cmd, environment(root.path), root.path, deadline, tool_fd=tool_fds["nix_store"])
        actual_records = readback_records(dumped, value["roots"])
        compare_readback(records, actual_records)
        PHASE = "namespace-build"
        raw = runner(build_cmd, environment(root.path), root.path, deadline, tool_fd=tool_fds["nix"])
        PHASE = "builder-result"
        artifact = builder_output(private, raw)
        seed.require(artifact["logical_path"] not in records)
        root.recheck()
        after = verify_nars(value, opener, deadline)
        seed.require(after == copied and verify_nars(value,
            lambda source, relative: nar.open_regular(str(private / "nix/store" / source.rsplit("/", 1)[1]), relative),
            deadline, root_directory=private / "nix/store") == copied)
        result = {"schema_version": 1, "kind": KIND, "status": "qualified-private-store-build",
            "system": "x86_64-linux", "seed_sha256": seed.sha(seed_raw), "source_sha256": source_pins,
            "seed_roots": len(value["roots"]), "seed_regular_files": len(value["files"]),
            "verified_nar_bytes": verified, "seed_rechecked_after_build": True,
            "builder": artifact, "expression_sha256": seed.sha(expression(value["tools"]["bash"]).encode()),
            "policy": {"store": "fresh-owned-private-local-root", "sandbox": True,
                "sandbox_fallback": False, "builders": [], "substituters": [],
                "daemon_fallback": False, "max_jobs": 1, "cores": 2},
            "native_closure_realized": False, "sdk_qualified": False, "native_support": False,
            "provider_evaluation": False, "outer_guard_success_and_owned_empty_required": True}
    finally:
        failure_phase = PHASE
        PHASE = "private-cleanup"
        root.close(deadline + CLEANUP_SECONDS)
        # Successful cleanup must not hide the actual fixed refusal phase.
        PHASE = failure_phase
    seed.require(not os.path.lexists(root.path))
    result["private_root_removed"] = True
    tick(deadline)
    return result



def qualify(value, seed_raw, parent, source_pins, deadline, *, runner=run):
    """Hold exact canonical Nix tool inodes across proof and fd execution."""
    tick(deadline)
    seed.validate(value)
    base = source_opener(value, {row["source"] for row in value["files"]})
    canonical = {name: seed.resolve_member(value, value["tools"][name]) for name in ("nix", "nix_store")}
    def split(path):
        parts = path.split("/")
        return "/".join(parts[:4]), "/".join(parts[4:])
    def witness(fd):
        row = os.fstat(fd)
        return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode,
                row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    with ExitStack() as held:
        streams = {path: held.enter_context(base(*split(path))) for path in sorted(set(canonical.values()))}
        before = {path: witness(stream.fileno()) for path, stream in streams.items()}
        def pinned(root, relative):
            path = root + ("/" + relative if relative else "")
            if path not in streams:
                return base(root, relative)
            os.lseek(streams[path].fileno(), 0, os.SEEK_SET)
            return os.fdopen(os.dup(streams[path].fileno()), "rb")
        result = _qualify(value, seed_raw, parent, source_pins, deadline, pinned,
            {name: streams[path].fileno() for name, path in canonical.items()}, runner=runner)
        for path, stream in streams.items():
            seed.require(witness(stream.fileno()) == before[path])
            with base(*split(path)) as current:
                seed.require(witness(current.fileno()) == before[path])
        return result


def main():
    global PHASE
    entry = time.monotonic()
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", required=True)
    for name in ("flake", "lock", "zig-index", "archives"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    marker = os.environ.get("OMUX_EXECUTION_GUARD", "")
    seed.require(bool(re.fullmatch(r"/[A-Za-z0-9_./-]{1,900}/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", marker)))
    seed.require(".." not in Path(marker).parts)
    timeout = os.environ.get("TEST_TIMEOUT", "")
    seed.require(bool(re.fullmatch("[0-9]{1,5}", timeout)) and int(timeout) > CLEANUP_SECONDS)
    deadline = float(entry + min(MAX_SECONDS, int(timeout) - CLEANUP_SECONDS))
    with open("/proc/self/status", "r", encoding="ascii") as status:
        platform_result = platform(status.read(65537), os.getuid())
    PHASE = "declared-inputs"
    seed_path = Path(args.seed).resolve(strict=True)
    seed.require(seed_path.name == "private-store-seed.json")
    raw = seed.metadata(seed_path, seed.MAX_METADATA)
    value = json.loads(raw, object_pairs_hook=seed.unique)
    seed.validate(value)
    for row in value["files"]:
        alias = seed_path.parent / row["alias"]
        seed.require(alias.exists() and alias.resolve(strict=True) == Path(row["source"]))
    for name, filename in (("native", "native.json"), ("paths", "store-paths"), ("registration", "registration")):
        payload = seed.metadata(seed_path.parent / filename, seed.MAX_METADATA)
        seed.require(seed.sha(payload) == value["metadata_sha256"][name])
    inventory_pin = seed.sha(seed.metadata(seed_path.parent / "file-inventory.json", seed.MAX_METADATA))
    pins = {}
    for name in ("flake", "lock", "zig_index", "archives"):
        payload = seed.metadata(Path(getattr(args, name)).resolve(strict=True), 2 * 1024**2)
        pins[name] = seed.sha(payload)
    result = qualify(value, raw, os.environ["TEST_TMPDIR"], pins, deadline)
    result["platform"] = platform_result
    result["guard_epoch"] = Path(marker).name
    result["file_inventory_sha256"] = inventory_pin
    result["implementation_sha256"] = {name: seed.sha(seed.metadata(Path(module.__file__).resolve(strict=True), 2 * 1024**2))
        for name, module in (("qualification", sys.modules[__name__]), ("seed", seed), ("nar", nar),
                              ("registration", sys.modules[seed.registrations.__module__]))}
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True) / "private-store-qualification.json"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(seed.encoded(result))
        stream.flush()
        os.fsync(stream.fileno())
    print("private local-store Bash builder qualified; native closure and SDK remain unqualified")


if __name__ == "__main__":
    previous = {}
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, interrupted)
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt):
        print("private-store qualification refused at " + PHASE, file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
