"""Seed-only fixed public runtime009 copy; never native/consumer authority.

The existing copy_retained function remains the only payload writer. Guard and
child independently hold/recheck the fixed original public input; a successful
seed action is retained physically before a separate fresh consumer Admission.
"""
from contextlib import ExitStack
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import codex_owner_runtime_input as runtime

SOURCE_PATH = Path("/srv/fast-local/jess/git/oauth-mux/integrations/codex-owner-runtime/codex-owner-runtime.tar.gz")
LABEL = "//tools:codex_owner_runtime_input_seed"
MODEL = "//tools:codex_owner_runtime_seed_test"
ARGUMENTS = ["test", MODEL, LABEL]
SCOPE = "codex-owner-runtime-public-seed-v1"
PREFIX = "OMUX_CODEX_OWNER_RUNTIME_SEED_"
RECEIPT_SHA = "b6e4a997a15c1a82f5095325e66f23e8c012c94baf43805ace67e8786cc60094"


def require(value, reason):
    if not value:
        raise ValueError("runtime-seed-" + reason)


def selected(profile, arguments):
    if LABEL not in arguments:
        return False
    require(profile == "standard" and arguments == ARGUMENTS, "selection")
    return True


def close_failure(owner, primary):
    try:
        owner.close()
    except BaseException:
        try:
            primary.add_note("runtime-seed-cleanup-refused")
        except BaseException:
            # Diagnostic allocation must not replace the original failure.
            pass


def request(args, arguments):
    if not selected(args.profile, arguments):
        return False
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
               "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
               "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
               "repository_cache", "nixpkgs_source"}
    require(args.manager in ("user", "system") and args.source_dirty == "false"
            and re.fullmatch(r"[0-9a-f]{40}", args.source_commit or "")
            and not any(value for name, value in vars(args).items() if name not in allowed), "guard-selection")
    return True


def source_role():
    return {"schema_version": 1, "kind": SCOPE, "purpose": "public-byte-copy-only",
            "source_path": str(SOURCE_PATH), "archive_name": runtime.NAME,
            "archive_sha256": runtime.ARCHIVE_SHA, "archive_bytes": runtime.ARCHIVE_BYTES,
            "manifest_sha256": runtime.MANIFEST_SHA, "receipt_sha256": RECEIPT_SHA,
            "native_support": False}


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate-role")
        value[key] = item
    return value


def role(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 4096, "role-bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("runtime-seed-role-json") from error
    require(type(value) is dict and type(value.get("schema_version")) is int
            and type(value.get("archive_bytes")) is int
            and value.get("native_support") is False and value == source_role(), "role")
    return value


def directory_identity(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022, "ancestor-custody")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


class FdSlot:
    """Register this empty one-shot owner before any live descriptor exists."""
    def __init__(self):
        self.fd = None

    def close(self):
        fd = self.fd
        self.fd = None
        if fd is not None:
            os.close(fd)


def register_fd(owner):
    slot = FdSlot()
    owner.callback(slot.close)
    return slot


class Held:
    """Physical ancestry and single regular input, with no path discovery."""
    def __init__(self, path=None, deadline_ns=None, maximum=None):
        self.owner = ExitStack()
        self.path = None
        if path is not None:
            self.acquire(path, deadline_ns, maximum)

    def acquire(self, path, deadline_ns, maximum):
        require(self.path is None, "held-already-acquired")
        self.path = Path(path)
        self.deadline_ns = deadline_ns
        self.maximum = maximum
        self.lineage = []
        try:
            require(self.path.is_absolute() and str(self.path) == str(self.path.absolute())
                    and '..' not in self.path.parts and len(os.fsencode(self.path)) <= 4096,
                    "path")
            runtime.budget(deadline_ns)
            root_slot = register_fd(self.owner)
            root_slot.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parent = root_slot.fd
            for part in self.path.parts[1:-1]:
                runtime.budget(deadline_ns)
                named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                child_slot = register_fd(self.owner)
                child_slot.fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent)
                child = child_slot.fd
                identity = directory_identity(os.fstat(child))
                require(identity == directory_identity(named), "ancestor-changed")
                self.lineage.append((child, parent, part, identity))
                parent = child
            self.parent = parent
            leaf_slot = register_fd(self.owner)
            leaf_slot.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=parent)
            self.fd = leaf_slot.fd
            self.identity = runtime.regular(self.fd, maximum=maximum)
            self.recheck()
        except BaseException as primary:
            close_failure(self, primary)
            raise

    def recheck(self):
        runtime.budget(self.deadline_ns)
        for child, parent, name, expected in self.lineage:
            require(directory_identity(os.fstat(child)) == expected
                    and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected,
                    "ancestor-changed")
        require(runtime.regular(self.fd, maximum=self.maximum) == self.identity
                and runtime.identity(os.stat(self.path.name, dir_fd=self.parent,
                                            follow_symlinks=False)) == self.identity,
                "input-changed")
        return self.identity.copy()

    def read(self):
        self.recheck()
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            runtime.budget(self.deadline_ns)
            chunk = os.read(self.fd, min(65536, self.maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= self.maximum, "input-bound")
            chunks.append(chunk)
        self.recheck()
        return b"".join(chunks)

    def close(self):
        self.owner.close()


class Admission:
    """Read-only seed source custody. Grants no archive execution or import."""
    def __init__(self, source_root=None, entry_ns=None, outer_deadline_ns=None):
        self.owner = ExitStack()
        self.entry_ns = None
        if source_root is not None:
            self.acquire(source_root, entry_ns, outer_deadline_ns)

    def acquire(self, source_root, entry_ns, outer_deadline_ns):
        require(self.entry_ns is None, "already-admitted")
        require(type(entry_ns) is int and type(outer_deadline_ns) is int
                and 0 < entry_ns < outer_deadline_ns, "clock")
        self.entry_ns = entry_ns
        self.deadline_ns = min(outer_deadline_ns, entry_ns + 600 * 10**9)
        self.root = Path(source_root)
        try:
            self.source = Held()
            self.owner.callback(self.source.close)
            self.source.acquire(SOURCE_PATH, self.deadline_ns, runtime.ARCHIVE_BYTES)
            self.manifest = Held()
            self.owner.callback(self.manifest.close)
            self.manifest.acquire(self.root / "integrations/codex-owner-runtime/runtime-manifest.json",
                                  self.deadline_ns, 16 * 1024 * 1024)
            self.receipt = Held()
            self.owner.callback(self.receipt.close)
            self.receipt.acquire(self.root / "integrations/codex-owner-runtime/runtime-receipt.json",
                                 self.deadline_ns, 16 * 1024 * 1024)
            require(hashlib.sha256(self.manifest.read()).hexdigest() == runtime.MANIFEST_SHA
                    and self.receipt.read() == runtime.EXPECTED_RECEIPT, "metadata")
            require(hashlib.sha256(runtime.EXPECTED_RECEIPT).hexdigest() == RECEIPT_SHA,
                    "receipt-pin")
            runtime.stream_digest(self.source.fd, self.deadline_ns)
            self.before = self.recheck()
        except BaseException as primary:
            close_failure(self, primary)
            raise

    def recheck(self):
        return {"source": self.source.recheck(), "manifest": self.manifest.recheck(),
                "receipt": self.receipt.recheck()}

    def facts(self):
        return {"scope": SCOPE, "source_path": str(SOURCE_PATH),
                "archive_sha256": runtime.ARCHIVE_SHA, "archive_bytes": runtime.ARCHIVE_BYTES,
                "original_entry_monotonic_ns": self.entry_ns,
                "original_seed_deadline_monotonic_ns": self.deadline_ns,
                "physical": self.before, "consumer_admitted": False,
                "source_qualified": False, "native_support": False}

    def runtime_seconds(self):
        runtime.budget(self.deadline_ns)
        return max(1, (self.deadline_ns - time.monotonic_ns() + 10**9 - 1) // 10**9)

    def close(self):
        self.owner.close()


def admit_owned(owner, source_root, entry_ns, outer_deadline_ns):
    admission = Admission()
    owner.callback(admission.close)
    admission.acquire(source_root, entry_ns, outer_deadline_ns)
    return admission


def copy_seed(admission, archive, descriptor, manifest, receipt, outputs):
    """Declared source/role joins, then the unchanged exclusive copy writer."""
    require(Path(archive).resolve(strict=True) == SOURCE_PATH, "declared-source")
    owner = ExitStack()
    try:
        declared_role = Held()
        owner.callback(declared_role.close)
        declared_role.acquire(Path(descriptor).resolve(strict=True), admission.deadline_ns, 4096)
        role(declared_role.read())
        # Declared tracked runfiles may have a resolved sandbox location. Their
        # exact full bytes are checked by the existing writer and pinned source.
        facts = runtime.pinned_metadata(manifest, receipt, admission.deadline_ns)
        admission.recheck()
        require(facts["manifest"]["sha256"] == runtime.MANIFEST_SHA, "declared-metadata")
        result = runtime.copy_retained(archive, manifest, receipt, outputs, admission.deadline_ns)
        declared_role.recheck()
        admission.recheck()
        require(result["source"] == admission.source.identity, "copy-source")
    except BaseException as primary:
        close_failure(owner, primary)
        raise
    owner.close()
    return result


def finish(admission, graph_reader=None, expected_graph=None):
    """Keep owners live through last graph I/O; close before terminal budget."""
    try:
        admission.recheck()
        if graph_reader is not None:
            require(graph_reader() == expected_graph, "graph-changed")
        after = admission.recheck()
    except BaseException as primary:
        close_failure(admission, primary)
        raise
    admission.close()
    runtime.budget(admission.deadline_ns)
    return after


def context(environment):
    names = {name: environment.get(PREFIX + name, "") for name in
             ("EPOCH", "ENTRY_NS", "DEADLINE_NS", "SOURCE", "GRAPH", "SOURCE_ROOT")}
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", names["EPOCH"])
            and re.fullmatch(r"[0-9a-f]{40}", names["SOURCE"])
            and re.fullmatch(r"[0-9a-f]{64}", names["GRAPH"]), "guard-context")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", names[n]) for n in ("ENTRY_NS", "DEADLINE_NS")), "guard-clock")
    require(Path(names["SOURCE_ROOT"]).is_absolute() and len(os.fsencode(names["SOURCE_ROOT"])) <= 4096
            and not any(char in names["SOURCE_ROOT"] for char in "\\\n\r\0"), "source-root")
    return names


def augment(command, run, entry, deadline, source, graph, source_root):
    require(type(command) is list and command[-2:] == ARGUMENTS[-2:], "command")
    values = {"EPOCH": Path(run).name, "ENTRY_NS": str(entry), "DEADLINE_NS": str(deadline),
              "SOURCE": source, "GRAPH": graph, "SOURCE_ROOT": str(source_root)}
    context({PREFIX + name: value for name, value in values.items()})
    result = list(command)
    where = result.index("test") + 1
    result[where:where] = ["--test_env=OMUX_EXECUTION_GUARD=" + str(run)] + [
        "--test_env=" + PREFIX + name + "=" + value for name, value in values.items()]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "role", "manifest", "receipt"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    require(os.environ.get("OMUX_EXECUTION_GUARD") and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"), "declared-test")
    values = context(os.environ)
    require(os.environ["OMUX_EXECUTION_GUARD"].rstrip('/').split('/')[-1] == values["EPOCH"], "guard-epoch")
    admission = Admission(values["SOURCE_ROOT"], int(values["ENTRY_NS"]), int(values["DEADLINE_NS"]))
    try:
        copy_seed(admission, args.archive, args.role, args.manifest, args.receipt,
                  os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
    except BaseException as primary:
        close_failure(admission, primary)
        raise
    finish(admission)
    print("OMUX_CODEX_OWNER_RUNTIME_PUBLIC_SEED_OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError):
        print("OMUX_CODEX_OWNER_RUNTIME_PUBLIC_SEED_REFUSED", file=sys.stderr)
        sys.exit(125)
