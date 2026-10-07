"""One source-bound Git commit acquisition and independently verified tar proof.

Git transport is confined to one exact public requirement. Export consumes raw
objects, never a checkout, hook, attribute filter or git-archive transformation.
Commit metadata is checked ephemerally and never exported. Offline commit
identity remains a producer-bound witness, distinct from independent tree proof.
The offline verifier does not invoke Git or extract the tar. SDK admission is
outside this producer's authority.
"""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time

# Start before importing source-verification helpers; no phase renews this clock.
PRODUCER_STARTED = time.monotonic()

from codex_dependency_bundle import Budget, HASH, MAX_METADATA, SOURCE_RECEIPT_SHA, encoded, require
from codex_dependency_union import OutputCustody
from codex_repository_inputs import git_requirements, source_graph
from codex_sdk_profile import FAST_STATE, hash_regular
from fetch_codex_archives import PINNED_CA, immutable_file
from restore_pristine_inputs import unique_object

GIT = Path("/nix/store/c0277k5giric1mn9dklllavbzvxl6hzb-git-2.53.0/bin/git")
HOME_GIT_STATE = Path("/home/jess/.local/state/omux-codex-git-prefetch-20261006")
OID = re.compile(r"[0-9a-f]{40}")
MAX_BLOB = 64 * 1024 * 1024
MAX_TREE = 8 * 1024 * 1024
MAX_PROOF = 16 * 1024 * 1024
MAX_SOURCE = 512 * 1024 * 1024
MAX_TAR = 1024 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_WORKER_BYTES = 4 * 1024 * 1024 * 1024
MAX_TASKS = 16
MAX_COMMANDS = MAX_ENTRIES + 4
FREE_FLOOR = 4 * 1024 * 1024 * 1024
MAGIC = b"OMUX-GIT-TREE-PROOF-1\n"
TREE_POLICY = "Git raw-object SHA1 identity; sorted USTAR, uid/gid/mtime0, files0444/0555, dirs0555, links0777"
# The owned Bazel target remains timeout="long" (900 seconds). These are
# tighter execution limits; declared_budgets() preserves its historical caps.
ENCLOSING_SECONDS = 900
COMPLETION_RESERVE = 60
CLEANUP_RESERVE = 10
PHASES = ("arguments", "producer-context", "source-authority", "tool-authority",
          "worker-custody", "git-init", "git-fetch", "object-inventory",
          "source-revalidation", "tar-encode", "tree-proof-verify",
          "output-custody", "output-artifacts", "output-publication",
          "offline-verification", "git-cleanup")
CATEGORIES = ("arguments", "deadline", "bound", "permission", "missing-input",
              "io", "contract", "schema", "process", "cleanup-deadline")


class ArgumentRefusal(ValueError):
    pass


class DeadlineRefusal(ValueError):
    pass


class GitRefusal(ValueError):
    def __init__(self, phase, category, cleanup=None):
        require(phase in PHASES and category in CATEGORIES
                and cleanup in (None, *CATEGORIES), "invalid refusal category")
        self.phase, self.category, self.cleanup = phase, category, cleanup
        super().__init__("categorical Git input refusal")


class Progress:
    def __init__(self, stream=None):
        self.stream = sys.stderr if stream is None else stream
        self.phase = "arguments"
        self.emitted = set()

    def enter(self, phase):
        require(phase in PHASES, "invalid progress phase")
        self.phase = phase
        if phase not in self.emitted:
            self.emitted.add(phase)
            print(json.dumps({"git_input_phase": phase}), file=self.stream, flush=True)


def enter(budget, phase):
    progress = getattr(budget, "progress", None)
    if progress is not None:
        progress.enter(phase)
    budget.tick()


def tick(budget):
    if budget is not None:
        budget.tick()


def refusal_category(error):
    if isinstance(error, ArgumentRefusal):
        return "arguments"
    if isinstance(error, DeadlineRefusal):
        return "deadline"
    if isinstance(error, subprocess.TimeoutExpired):
        return "cleanup-deadline"
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, FileNotFoundError):
        return "missing-input"
    if isinstance(error, OSError):
        return "io"
    if isinstance(error, (json.JSONDecodeError, UnicodeError, RecursionError, tarfile.TarError)):
        return "schema"
    if isinstance(error, subprocess.SubprocessError):
        return "process"
    if isinstance(error, ValueError):
        # Literal implementation messages are compared privately. No exception
        # text, command, path, remote or object identity enters diagnostics.
        if str(error) == "bundle deadline exceeded":
            return "deadline"
        if str(error) in ("bundle read budget exceeded", "Git task bound exceeded",
                          "Git stdout bound exceeded", "Git diagnostic bound exceeded",
                          "worker bytes exceed bound", "worker inventory exceeds bound",
                          "worker free floor differs", "Git command count exceeds bound"):
            return "bound"
    return "contract"


def emit_refusal(progress, error):
    refusal = error if isinstance(error, GitRefusal) else GitRefusal(progress.phase, refusal_category(error))
    print(json.dumps({"status": "git-input-refused", "phase": refusal.phase,
                      "category": refusal.category, "cleanup": refusal.cleanup}),
          file=progress.stream, flush=True)


def cleanup_refusal(phase, primary, cleanup):
    # Preserve the first work category and first cleanup category across every
    # release boundary. Later cleanup faults never replace existing evidence.
    if isinstance(primary, GitRefusal):
        return GitRefusal(primary.phase, primary.category,
                          primary.cleanup or refusal_category(cleanup))
    return GitRefusal(phase, refusal_category(primary), refusal_category(cleanup))


@contextmanager
def owned_selector(phase):
    selector = selectors.DefaultSelector()
    primary = None
    try:
        yield selector
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            selector.close()
        except BaseException as cleanup:
            if primary is not None:
                raise cleanup_refusal(phase, primary, cleanup) from None
            raise GitRefusal(phase, refusal_category(cleanup)) from None


class ProducerBudget(Budget):
    def __init__(self, environment, started, progress):
        observed = environment.get("TEST_TIMEOUT")
        if not isinstance(observed, str) or re.fullmatch(r"[1-9][0-9]{0,5}", observed) is None:
            raise ArgumentRefusal("enclosing timeout shape differs")
        enclosing = min(ENCLOSING_SECONDS, 1200, int(observed))
        if enclosing <= COMPLETION_RESERVE + CLEANUP_RESERVE:
            raise ArgumentRefusal("enclosing timeout lacks reserves")
        self.deadline = started + enclosing - COMPLETION_RESERVE
        self.read_bytes = self.export_bytes = 0
        self.progress = progress
        self.tick()

    def tick(self, count=0):
        if time.monotonic() >= self.deadline:
            raise DeadlineRefusal("producer deadline exhausted")
        super().tick(count)


class CommandBudget:
    """Share byte accounting but stop scans at the command's original deadline."""
    def __init__(self, parent, deadline):
        self.parent, self.deadline = parent, deadline

    def tick(self, count=0):
        if time.monotonic() >= self.deadline:
            raise DeadlineRefusal("command deadline exhausted")
        self.parent.tick(count)
        if time.monotonic() >= self.deadline:
            raise DeadlineRefusal("command deadline exhausted")


REQUIREMENTS = (
    ("https://chromium.googlesource.com/external/github.com/llvm/llvm-project/libc.git", "9309c117ebae84dd2f9df1ef99de4782162527d5"),
    ("https://chromium.googlesource.com/external/github.com/llvm/llvm-project/libcxx.git", "5abc7f839700f0f17338434e1c1c6a8c87c00c11"),
    ("https://chromium.googlesource.com/external/github.com/llvm/llvm-project/libcxxabi.git", "8f11bb1d4438d0239d0dfc1bd9456a9f31629dda"),
    ("https://github.com/dzbarsky/rules_rust", "b56cbaa8465e74127f1ea216f813cd377295ad81"),
    ("https://github.com/helix-editor/nucleo.git", "4253de9faabb4e5c6d81d946a5e35a90f87347ee"),
    ("https://github.com/hyperium/h3", "e07e69412876f7e26f026bd75a48b2704d8c8283"),
    ("https://github.com/microsoft/mxc", "6cd3d58f05d3447e67109cfb75e042803b843ca4"),
    ("https://github.com/openai-oss-forks/crossterm", "efa177859fd9623d57b9fe7ae9bf491ae1ac6ec4"),
    ("https://github.com/openai-oss-forks/tokio-tungstenite", "0e5b2d73aa18dd9f0a50ee9ff199d5aef7594186"),
    ("https://github.com/openai-oss-forks/tungstenite-rs", "4fffad30fe373adbdcffab9545e9e9bf4f2fc19f"),
    ("https://github.com/rust-lang/rust-clippy", "20ce69b9a63bcd2756cd906fe0964d1e901e042a"),
)


def selected_requirement(index, budget):
    require(type(index) is int and 0 <= index < len(REQUIREMENTS), "requirement index differs")
    module, cargo, text = source_graph(budget)
    rows, unsupported = git_requirements(module, cargo, text)
    require(not unsupported and tuple((row["remote"], row["commit"]) for row in rows) == REQUIREMENTS,
            "source-derived Git requirements differ")
    return rows[index]


def object_id(kind, value):
    require(kind in ("commit", "tree", "blob"), "unsupported Git object type")
    return hashlib.sha1(kind.encode() + b" " + str(len(value)).encode() + b"\0" + value).hexdigest()


def component(name):
    require(isinstance(name, bytes) and 0 < len(name) <= 100 and name not in (b".", b"..", b".git")
            and not any(byte < 32 or byte == 127 for byte in name) and b"/" not in name and b"\\" not in name,
            "unsupported Git path component")
    return name.decode("utf-8", "strict")


def tree_entries(value, budget=None):
    tick(budget)
    require(len(value) <= MAX_TREE, "tree object exceeds bound")
    rows, names, cursor = [], set(), 0
    while cursor < len(value):
        tick(budget)
        space = value.find(b" ", cursor)
        end = value.find(b"\0", space + 1)
        require(space > cursor and end > space and end + 21 <= len(value), "malformed Git tree")
        mode = value[cursor:space].decode("ascii", "strict")
        require(mode in ("40000", "100644", "100755", "120000"), "unsupported Git mode or submodule")
        raw_name = value[space + 1:end]
        name = component(raw_name)
        require(name not in names, "duplicate Git tree name")
        names.add(name)
        rows.append((mode, name, value[end + 1:end + 21].hex(),
                     raw_name + (b"/" if mode == "40000" else b"\0")))
        cursor = end + 21
    require([row[3] for row in rows] == sorted(row[3] for row in rows), "Git tree order differs")
    return [(mode, name, oid) for mode, name, oid, _ in rows]


def checked_object(reader, oid, expected, budget):
    require(isinstance(oid, str) and OID.fullmatch(oid), "invalid Git object identity")
    budget.tick()
    kind, value = reader(oid)
    require(kind == expected and isinstance(value, bytes)
            and len(value) <= (MAX_BLOB if kind == "blob" else MAX_TREE), "object type or length differs")
    budget.tick(len(value))
    require(object_id(kind, value) == oid, "Git object digest differs")
    return value


def resolve_links(records, blobs, budget=None):
    tick(budget)
    entries = {row["path"]: row for row in records}
    for row in records:
        tick(budget)
        if row["git_mode"] != "120000":
            continue
        value = blobs[row["git_oid"]]
        require(0 < len(value) <= 100 and not any(byte < 32 or byte == 127 for byte in value),
                "unsupported symlink payload")
        target = value.decode("utf-8", "strict")
        require(not target.startswith("/") and "\\" not in target, "escaping symlink")
        parts = row["path"].split("/")[:-1]
        for part in target.split("/"):
            tick(budget)
            if parts:
                parent = entries.get("/".join(parts))
                require(parent is not None and parent["git_mode"] == "40000", "symlink traverses non-directory")
            if part in ("", "."):
                continue
            if part == "..":
                require(parts, "escaping symlink")
                parts.pop()
            else:
                component(part.encode())
                parts.append(part)
        require(parts and "/".join(parts) in entries, "dangling or root symlink unsupported")
        for end in range(1, len(parts) + 1):
            tick(budget)
            referenced = entries.get("/".join(parts[:end]))
            require(referenced is not None and referenced["git_mode"] != "120000",
                    "nested symlink unsupported")


def snapshot(commit, reader, budget):
    commit_value = checked_object(reader, commit, "commit", budget)
    first = commit_value.split(b"\n", 1)[0]
    require(re.fullmatch(b"tree [0-9a-f]{40}", first), "commit root tree differs")
    root_tree = first[5:].decode()
    witness = {"oid": commit, "tree_oid": root_tree, "bytes": len(commit_value),
               "sha256": hashlib.sha256(commit_value).hexdigest()}
    del commit_value, first
    return (*snapshot_tree(root_tree, reader, budget), witness)


def snapshot_tree(root_tree, reader, budget):
    proof = {}
    records, blobs, source_bytes = [], {}, 0

    def walk(tree, prefix, ancestors):
        nonlocal source_bytes
        require(len(ancestors) < 64 and tree not in ancestors, "nested or cyclic Git tree")
        value = checked_object(reader, tree, "tree", budget)
        proof[tree] = ("tree", value)
        require(sum(len(item[1]) for item in proof.values()) <= MAX_PROOF, "object proof exceeds bound")
        for mode, name, oid in tree_entries(value, budget):
            budget.tick()
            path = prefix + name
            require(len(path.encode()) <= 240 and len(records) < MAX_ENTRIES, "export inventory exceeds bound")
            if mode == "40000":
                records.append({"path": path, "git_mode": mode, "git_oid": oid, "bytes": 0, "sha256": None})
                walk(oid, path + "/", ancestors | {tree})
            else:
                payload = checked_object(reader, oid, "blob", budget)
                source_bytes += len(payload)
                require(source_bytes <= MAX_SOURCE, "source export exceeds bound")
                if name == ".gitattributes":
                    require(not re.search(rb"(?:^|\s)[-!]?filter(?:=|\s|$)", payload), "Git filters unsupported")
                blobs[oid] = payload
                records.append({"path": path, "git_mode": mode, "git_oid": oid, "bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
    walk(root_tree, "", set())
    budget.tick()
    records.sort(key=lambda row: row["path"].encode())
    budget.tick()
    require(len({row["path"] for row in records}) == len(records), "duplicate export path")
    resolve_links(records, blobs, budget)
    return root_tree, records, proof, blobs


def proof_bytes(proof, budget=None):
    tick(budget)
    result = bytearray(MAGIC)
    for oid, (kind, value) in sorted(proof.items()):
        tick(budget)
        require(kind == "tree" and object_id(kind, value) == oid, "proof identity differs")
        result.extend(bytes.fromhex(oid) + b"t" + struct.pack(">Q", len(value)) + value)
        require(len(result) <= MAX_PROOF, "proof framing exceeds bound")
    tick(budget)
    return bytes(result)


def parse_proof(value, budget=None):
    tick(budget)
    require(len(value) <= MAX_PROOF and value.startswith(MAGIC), "proof format differs")
    result, cursor, last = {}, len(MAGIC), ""
    while cursor < len(value):
        tick(budget)
        require(cursor + 29 <= len(value), "truncated proof header")
        oid, code = value[cursor:cursor + 20].hex(), value[cursor + 20:cursor + 21]
        length = struct.unpack(">Q", value[cursor + 21:cursor + 29])[0]
        cursor += 29
        require(code == b"t" and length <= MAX_TREE and cursor + length <= len(value)
                and oid > last, "invalid or duplicate proof object")
        payload = value[cursor:cursor + length]
        kind = "tree"
        require(object_id(kind, payload) == oid, "proof object digest differs")
        result[oid] = (kind, payload)
        cursor += length
        last = oid
        require(len(result) <= MAX_ENTRIES + 1, "proof object count exceeds bound")
    return result


def canonical_tar(records, blobs, budget=None):
    tick(budget)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for row in records:
            tick(budget)
            info = tarfile.TarInfo(row["path"])
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            mode = row["git_mode"]
            if mode == "40000":
                info.type, info.mode = tarfile.DIRTYPE, 0o555
                archive.addfile(info)
            elif mode == "120000":
                info.type, info.mode = tarfile.SYMTYPE, 0o777
                info.linkname = blobs[row["git_oid"]].decode()
                archive.addfile(info)
            else:
                info.mode = 0o555 if mode == "100755" else 0o444
                info.size = row["bytes"]
                archive.addfile(info, io.BytesIO(blobs[row["git_oid"]]))
            tick(budget)
            require(stream.tell() <= MAX_TAR, "tar export exceeds bound")
    tick(budget)
    result = stream.getvalue()
    tick(budget)
    require(len(result) <= MAX_TAR, "tar framing exceeds bound")
    return result


def verify_artifacts(root_tree, tar_value, proof_value, budget):
    """Reconstruct the Git tree from proof objects and unextracted tar payloads."""
    require(len(tar_value) <= MAX_TAR, "tar input exceeds bound")
    proof = parse_proof(proof_value, budget)
    blobs, names, count, payload_bytes = {}, set(), 0, 0
    with tarfile.open(fileobj=io.BytesIO(tar_value), mode="r:") as archive:
        for member in archive:
            budget.tick()
            count += 1
            require(count <= MAX_ENTRIES and member.name not in names and member.name
                    and str(PurePosixPath(member.name)) == member.name and not member.name.startswith("/")
                    and member.type in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE)
                    and not member.pax_headers and member.uid == member.gid == member.mtime == 0
                    and member.uname == member.gname == "", "unsupported tar member")
            for part in member.name.split("/"):
                component(part.encode())
            names.add(member.name)
            if member.isfile():
                require(0 <= member.size <= MAX_BLOB, "tar payload exceeds bound")
                require(payload_bytes + member.size <= MAX_SOURCE, "tar aggregate payload exceeds bound")
                with archive.extractfile(member) as source:
                    payload = source.read(MAX_BLOB + 1)
                require(len(payload) == member.size, "truncated tar payload")
            elif member.issym():
                require(member.size == 0, "symlink tar size differs")
                payload = member.linkname.encode()
            else:
                require(member.size == 0, "directory tar size differs")
                continue
            budget.tick(len(payload))
            payload_bytes += len(payload)
            require(payload_bytes <= MAX_SOURCE, "tar aggregate payload exceeds bound")
            blobs[object_id("blob", payload)] = payload
    def reader(oid):
        if oid in proof:
            return proof[oid]
        require(oid in blobs, "Git blob missing from tar")
        return "blob", blobs[oid]
    tree, records, used, verified_blobs = snapshot_tree(root_tree, reader, budget)
    require(set(used) == set(proof) and proof_bytes(used, budget) == proof_value, "undeclared proof objects")
    require(canonical_tar(records, verified_blobs, budget) == tar_value, "noncanonical or substituted tar bytes")
    return tree, records


class GitOutput(OutputCustody):
    def __init__(self, parent, budget, name="codex-git-input"):
        # Reuse the established full-ancestor witnesses and FD-relative writer,
        # retaining its disclosed inherited custody root instead of path writes.
        super().__init__(parent, budget)
        try:
            self.artifacts_fd = self.mkdir(self.root_fd, name)
            self.artifacts = []
        except BaseException:
            self.close()
            raise

    def write_artifact(self, name, value):
        require(name in ("source.tar", "objects.proof", "git-input-receipt.json"), "artifact name differs")
        fd = self._create_file(self.artifacts_fd, name)
        try:
            self._write(self.artifacts_fd, name, fd, value)
            self._seal(self.artifacts_fd, name, fd)
            self.artifacts.append(name)
        except BaseException:
            # Remove only the still-owned exact open inode. Substitution keeps
            # the failed namespace quarantined for controller-owned cleanup.
            held = os.fstat(fd)
            try:
                named = os.stat(name, dir_fd=self.artifacts_fd, follow_symlinks=False)
            except FileNotFoundError:
                named = None
            if named is not None and self._file_state(held) == self._file_state(named):
                os.unlink(name, dir_fd=self.artifacts_fd)
                self.files[:] = [row for row in self.files
                                 if not (row[0] == self.artifacts_fd and row[1] == name)]
            raise
        finally:
            os.close(fd)


def worker_disk(fd, budget):
    budget.tick()
    total, entries = 0, 0
    def walk(parent, depth=0):
        nonlocal total, entries
        require(depth <= 64, "worker nesting exceeds bound")
        budget.tick()
        for name in os.listdir(parent):
            budget.tick()
            entries += 1
            require(entries <= 2 * MAX_ENTRIES, "worker inventory exceeds bound")
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(info.st_uid == os.getuid() and not info.st_mode & 0o022
                    and not stat.S_ISLNK(info.st_mode), "worker custody differs")
            total += info.st_blocks * 512
            require(total <= MAX_WORKER_BYTES, "worker bytes exceed bound")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    require(OutputCustody._identity(os.fstat(child)) == OutputCustody._identity(info), "worker changed")
                    walk(child, depth + 1)
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "worker file type differs")
    walk(fd)
    budget.tick()
    space = os.fstatvfs(fd)
    budget.tick()
    require(space.f_bavail * space.f_frsize >= FREE_FLOOR, "worker free floor differs")


def git_environment(root, ca):
    return {"HOME": root + "/home", "XDG_CONFIG_HOME": root + "/home", "TMPDIR": root + "/tmp",
            "PATH": str(GIT.parent), "LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": root + "/empty-config",
            "GIT_CONFIG_SYSTEM": root + "/empty-config", "GIT_ATTR_NOSYSTEM": "1",
            "GIT_EXEC_PATH": str(GIT.parent.parent / "libexec/git-core"),
            "GIT_SSL_CAINFO": str(ca), "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"}


GIT_OPTIONS = ["-c", "core.fsmonitor=false", "-c", "credential.helper=", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "http.followRedirects=false",
               "-c", "fetch.recurseSubmodules=false", "-c", "fetch.fsckObjects=true",
               "-c", "transfer.fsckObjects=true", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
               "-c", "pack.threads=1", "-c", "index.threads=1", "-c", "protocol.version=2"]


def process_record(value):
    """Read only process identity fields; process command text is never retained."""
    end = value.rfind(")")
    require(end >= 0, "owned process metadata differs")
    fields = value[end + 2:].split()
    require(len(fields) >= 20, "owned process metadata truncated")
    return int(fields[2]), int(fields[3]), int(fields[19])


def owned_group(group, start, budget, *, proc_root=Path("/proc")):
    """Count threads in the newly created session; never select another session."""
    tasks, members = 0, []
    budget.tick()
    for entry in proc_root.iterdir():
        budget.tick()
        if not entry.name.isdigit():
            continue
        try:
            info = entry.stat()
            if info.st_uid != os.getuid():
                continue
            record = process_record((entry / "stat").read_text())
            if record[0] != group:
                continue
            require(info.st_uid == os.getuid() and record[1] == group and record[2] >= start,
                    "owned process group identity differs")
            for task in (entry / "task").iterdir():
                budget.tick()
                tasks += 1
                require(tasks <= MAX_TASKS, "Git task bound exceeded")
            budget.tick()
            members.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            # A disappearing process cannot receive a signal or add live tasks.
            continue
    return tasks, members


def run_git(arguments, root, worker_fd, budget, ca, input_value=None, limit=MAX_BLOB + 256):
    """Only owned child process groups are signalled; diagnostic bytes never escape."""
    budget.tick()
    # Reserve cleanup inside the original shared deadline; a command cannot
    # spend this interval and then renew the enclosing execution budget.
    deadline = min(budget.deadline - CLEANUP_RESERVE, time.monotonic() + 600)
    if deadline <= time.monotonic():
        raise DeadlineRefusal("Git cleanup reserve exhausted")
    command_budget = CommandBudget(budget, deadline)
    command = [str(GIT)] + GIT_OPTIONS + ["-c", "core.hooksPath=" + root + "/templates",
                                       "--git-dir=" + root + "/repo"] + arguments
    # Allocate buffers and initialize all startup state before owning a child.
    # A failed allocation here cannot strand a spawned process outside cleanup.
    progress = getattr(budget, "progress", None)
    original_phase = progress.phase if progress is not None else "git-cleanup"
    output, errors = bytearray(), 0
    completed = False
    may_signal = True
    primary = escaping = None
    child = subprocess.Popen(command, cwd=root, env=git_environment(root, ca), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, umask=0o077)
    try:
        try:
            # The leader is our unreaped child, so its PID cannot be reused
            # before this witness. Cleanup encloses every post-spawn operation.
            record = process_record(Path("/proc", str(child.pid), "stat").read_text())
            require(record[:2] == (child.pid, child.pid), "Git session identity differs")
            start = record[2]
            if input_value is not None:
                child.stdin.write(input_value)
            child.stdin.close()
            with owned_selector(original_phase) as selector:
                selector.register(child.stdout, selectors.EVENT_READ, True)
                selector.register(child.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    command_budget.tick()
                    tasks, _ = owned_group(child.pid, start, command_budget)
                    require(tasks <= MAX_TASKS, "Git task bound exceeded")
                    worker_disk(worker_fd, command_budget)
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        value = os.read(key.fileobj.fileno(), 65536)
                        if not value:
                            selector.unregister(key.fileobj)
                        elif key.data:
                            command_budget.tick(len(value))
                            output.extend(value)
                            require(len(output) <= limit, "Git stdout bound exceeded")
                        else:
                            errors += len(value)
                            require(errors <= 65536, "Git diagnostic bound exceeded")
            # EOF does not prove leader exit: it could close pipes and fork a
            # helper afterwards. Observe exit without reaping, preserving the
            # exact child PID/group anchor until all fork-capable members are
            # absent. WNOWAIT is required in this native Linux-only lane.
            while True:
                command_budget.tick()
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    require(observed.si_pid == child.pid, "Git exit observation identity differs")
                    break
                tasks, _ = owned_group(child.pid, start, command_budget)
                require(tasks <= MAX_TASKS, "Git task bound exceeded")
                worker_disk(worker_fd, command_budget)
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            # The leader is now irreversibly exited but still unreaped. Other
            # group members cause refusal and anchored group termination.
            command_budget.tick()
            tasks, members = owned_group(child.pid, start, command_budget)
            require(tasks <= MAX_TASKS and all(pid == child.pid for pid in members), "Git child group not drained")
            # Popen.wait may reap while handling KeyboardInterrupt and then
            # rethrow. Once this exact exit/drain proof holds, prohibit group
            # signaling before any potentially reaping wait is entered.
            may_signal = False
            returncode = child.wait(timeout=max(0, min(CLEANUP_RESERVE, budget.deadline - time.monotonic())))
            completed = True
            require(returncode == 0, "Git subprocess failed")
            return bytes(output)
        except BaseException as error:
            primary = error
            raise
        finally:
            if not completed:
                # Popen creates this new session/process group; no external
                # process/session can be selected by caller input. Signals are
                # permitted only before the final potentially reaping wait.
                # Log a fixed cleanup phase without ticking expired work time.
                cleanup_error = None
                if progress is not None:
                    try:
                        progress.enter("git-cleanup")
                    except BaseException as error:
                        cleanup_error = error
                if may_signal:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
                try:
                    child.wait(timeout=max(0, min(CLEANUP_RESERVE, budget.deadline - time.monotonic())))
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                finally:
                    if progress is not None:
                        progress.phase = original_phase
                if cleanup_error is not None:
                    if primary is not None:
                        raise cleanup_refusal(original_phase, primary, cleanup_error) from None
                    raise GitRefusal(original_phase, refusal_category(cleanup_error)) from None
    except BaseException as error:
        escaping = error
        raise
    finally:
        # Every descriptor gets an independent release attempt. Neither an
        # earlier cleanup refusal nor a pipe-close error can skip the others.
        # No context manager may introduce an unbounded child wait here.
        release_error = None
        for channel in (child.stdin, child.stdout, child.stderr):
            try:
                channel.close()
            except BaseException as error:
                release_error = release_error or error
        if release_error is not None:
            if escaping is not None:
                raise cleanup_refusal(original_phase, escaping, release_error) from None
            raise GitRefusal(original_phase, refusal_category(release_error)) from None


def acquire(requirement, worker, budget, ca, runner=run_git):
    require((requirement.get("remote"), requirement.get("commit")) in REQUIREMENTS,
            "undeclared remote or commit")
    for name in ("home", "tmp", "templates"):
        worker.mkdir(worker.artifacts_fd, name)
    fd = os.open("empty-config", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o400, dir_fd=worker.artifacts_fd)
    os.close(fd)
    root = "/proc/" + str(os.getpid()) + "/fd/" + str(worker.artifacts_fd)
    commands = 0
    def run(arguments, input_value=None, limit=MAX_BLOB + 256):
        nonlocal commands
        commands += 1
        require(commands <= MAX_COMMANDS, "Git command count exceeds bound")
        worker.check()
        result = runner(arguments, root, worker.artifacts_fd, budget, ca, input_value, limit)
        worker.check()
        return result
    enter(budget, "git-init")
    run(["init", "--bare", "--template=" + root + "/templates", root + "/repo"], limit=65536)
    enter(budget, "git-fetch")
    run(["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
         requirement["remote"], requirement["commit"]], limit=65536)
    def reader(oid):
        reply = run(["cat-file", "--batch"], oid.encode() + b"\n")
        header, separator, payload = reply.partition(b"\n")
        fields = header.split(b" ")
        require(separator and len(fields) == 3 and fields[0] == oid.encode()
                and re.fullmatch(b"[0-9]+", fields[2]), "Git object frame differs")
        length = int(fields[2])
        require(length <= MAX_BLOB and len(payload) == length + 1 and payload[-1:] == b"\n",
                "Git object frame length differs")
        return fields[1].decode("ascii"), payload[:-1]
    enter(budget, "object-inventory")
    return snapshot(requirement["commit"], reader, budget)


def declared_budgets():
    return {"shared_read_bytes": 4 * 1024 ** 3, "source_bytes": MAX_SOURCE, "blob_bytes": MAX_BLOB,
            "tar_bytes": MAX_TAR, "proof_bytes": MAX_PROOF, "entries": MAX_ENTRIES,
            "seconds": 1200, "per_command_seconds": 600, "worker_disk_bytes": MAX_WORKER_BYTES,
            "tasks": MAX_TASKS, "commands": MAX_COMMANDS,
            "disk_enforcement": "sampled; controller bounds apply"}


def export(requirement, material, destination, budget):
    tree, records, proof, blobs, witness = material
    require(witness.get("oid") == requirement["commit"] and witness.get("tree_oid") == tree,
            "acquisition witness is not the selected commit/tree")
    enter(budget, "tar-encode")
    tar_value, proof_value = canonical_tar(records, blobs, budget), proof_bytes(proof, budget)
    enter(budget, "tree-proof-verify")
    verified_tree, verified_records = verify_artifacts(tree, tar_value, proof_value, budget)
    require((tree, records) == (verified_tree, verified_records), "independent tree export differs")
    enter(budget, "output-artifacts")
    destination.write_artifact("source.tar", tar_value)
    destination.write_artifact("objects.proof", proof_value)
    inventory_sha = hashlib.sha256(encoded(records)).hexdigest()
    report = {"schema_version": 1, "status": "verified-pinned-git-tree-tar", "requirement": requirement,
              "source_receipt_sha256": SOURCE_RECEIPT_SHA, "git": str(GIT), "ca": str(PINNED_CA),
              "commit": requirement["commit"], "tree_oid": tree, "inventory": records,
              "inventory_sha256": inventory_sha,
              "artifacts": {"source.tar": {"sha256": hashlib.sha256(tar_value).hexdigest(), "bytes": len(tar_value)},
                            "objects.proof": {"sha256": hashlib.sha256(proof_value).hexdigest(), "bytes": len(proof_value)}},
              "commit_witness": witness, "commit_object_verified_at_acquisition": True,
              "offline_commit_identity_verified": False, "tree_export_verified": True,
              "tree_policy": TREE_POLICY,
              "closure_proved": False, "offline_analysis_proved": False, "sdk_compilation_admitted": False,
              "native_support": False, "provider_evaluation": False, "archive_sha256": None,
              "budgets": declared_budgets()}
    receipt = encoded(report)
    enter(budget, "output-publication")
    destination.write_artifact("git-input-receipt.json", receipt)
    destination.check()
    require(set(os.listdir(destination.artifacts_fd)) == set(destination.artifacts), "output inventory differs")
    destination.disk_check()
    return report, hashlib.sha256(receipt).hexdigest()


class InputCustody:
    """Hold all input ancestors and file witnesses until independent proof ends."""
    def __init__(self, root, budget):
        root = Path(root)
        require(root.is_absolute() and ".." not in root.parts and len(root.parts) <= 256,
                "input root shape differs")
        self.fds, self.directories, self.files, self.budget = [], [], [], budget
        try:
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(parent)
            OutputCustody._directory_safe(os.fstat(parent), False)
            for name in root.parts[1:]:
                self.check()
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.fds.append(child)
                witness = os.fstat(child)
                OutputCustody._directory_safe(witness, False)
                self.directories.append((parent, name, child, witness))
                self.check()
                parent = child
            self.root_fd = parent
            OutputCustody._directory_safe(os.fstat(parent), True)
        except BaseException:
            self.close()
            raise

    def check(self):
        self.budget.tick()
        for parent, name, child, witness in self.directories:
            held = os.fstat(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            OutputCustody._directory_safe(held, False)
            require(OutputCustody._identity(held) == OutputCustody._identity(named)
                    == OutputCustody._identity(witness), "input ancestor substituted")
        for name, witness in self.files:
            require(OutputCustody._file_state(os.stat(name, dir_fd=self.root_fd, follow_symlinks=False))
                    == OutputCustody._file_state(witness), "input file substituted")

    def read(self, name, limit, capture=True):
        self.check()
        witness = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
        require(stat.S_ISREG(witness.st_mode) and witness.st_nlink == 1, "input file custody differs")
        result = hash_regular(self.root_fd, name, limit, capture, on_read=self.budget.tick)
        require(OutputCustody._file_state(os.stat(name, dir_fd=self.root_fd, follow_symlinks=False))
                == OutputCustody._file_state(witness), "input file changed")
        self.files.append((name, witness))
        self.check()
        return result

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def retained_git_location(root):
    root = Path(root)
    require(root.is_absolute() and ".." not in root.parts, "retained Git root shape differs")
    # Preserve the original FAST selector; HOME admits only the separately
    # declared first-requirement target, never a general HOME cache or checkout.
    if root.is_relative_to(HOME_GIT_STATE):
        relative = root.relative_to(HOME_GIT_STATE)
        producer = "codex_git_input_producer_0"
    else:
        relative = root.relative_to(FAST_STATE)
        producer = "codex_git_input_producer"
    require(relative.parts and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", relative.parts[0]),
            "retained Git controller epoch differs")
    require(Path(*relative.parts[1:]).as_posix() ==
            "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/" + producer + "/"
            "test.outputs/codex-sdk-dependency-union/codex-git-input", "retained Git producer output differs")
    return root


def offline_verify(root, receipt_sha, requirement, budget):
    require(isinstance(receipt_sha, str) and HASH.fullmatch(receipt_sha), "receipt digest shape differs")
    if Path(root).is_relative_to(HOME_GIT_STATE):
        # The HOME output names the first-requirement target. A valid receipt
        # for another pinned commit cannot supply that target's authority.
        retained_git_location(root)
        require(isinstance(requirement, dict)
                and (requirement.get("remote"), requirement.get("commit")) == REQUIREMENTS[0],
                "HOME Git input is not the first canonical requirement")
    with ExitStack() as stack:
        custody = InputCustody(root, budget)
        stack.callback(custody.close)
        fd = custody.root_fd
        require(set(os.listdir(fd)) == {"source.tar", "objects.proof", "git-input-receipt.json"}, "artifact inventory differs")
        actual, _, raw = custody.read("git-input-receipt.json", MAX_METADATA)
        require(actual == receipt_sha, "receipt digest differs")
        report = json.loads(raw, object_pairs_hook=unique_object)
        require(set(report) == {"schema_version", "status", "requirement", "source_receipt_sha256", "git", "ca",
                "commit", "tree_oid", "inventory", "inventory_sha256", "artifacts", "commit_witness",
                "commit_object_verified_at_acquisition", "offline_commit_identity_verified", "tree_export_verified",
                "tree_policy", "closure_proved", "offline_analysis_proved", "sdk_compilation_admitted",
                "native_support", "provider_evaluation", "archive_sha256", "budgets"}, "receipt schema differs")
        require(type(report.get("schema_version")) is int and report["schema_version"] == 1
                and report.get("status") == "verified-pinned-git-tree-tar"
                and report.get("requirement") == requirement and report.get("commit") == requirement["commit"]
                and report.get("source_receipt_sha256") == SOURCE_RECEIPT_SHA
                and report.get("git") == str(GIT) and report.get("ca") == str(PINNED_CA)
                and report.get("commit_object_verified_at_acquisition") is True
                and report.get("offline_commit_identity_verified") is False and report.get("tree_export_verified") is True
                and report.get("tree_policy") == TREE_POLICY and report.get("budgets") == declared_budgets()
                and report.get("archive_sha256") is None
                and all(report.get(key) is False for key in ("closure_proved", "offline_analysis_proved",
                    "sdk_compilation_admitted", "native_support", "provider_evaluation")), "Git receipt authority differs")
        values = {}
        witness = report.get("commit_witness")
        require(isinstance(witness, dict) and set(witness) == {"oid", "tree_oid", "sha256", "bytes"}
                and witness["oid"] == requirement["commit"] and witness["tree_oid"] == report.get("tree_oid")
                and isinstance(witness["sha256"], str) and HASH.fullmatch(witness["sha256"])
                and type(witness["bytes"]) is int and 0 < witness["bytes"] <= MAX_TREE,
                "ephemeral commit witness differs")
        require(set(report["artifacts"]) == {"source.tar", "objects.proof"}, "receipt artifact names differ")
        for name, limit in (("source.tar", MAX_TAR), ("objects.proof", MAX_PROOF)):
            actual, length, value = custody.read(name, limit)
            require(report["artifacts"][name] == {"sha256": actual, "bytes": length}, "artifact digest or length differs")
            values[name] = value
        tree, records = verify_artifacts(report["tree_oid"], values["source.tar"], values["objects.proof"], budget)
        require(report.get("tree_oid") == tree and report.get("inventory") == records
                and report.get("inventory_sha256") == hashlib.sha256(encoded(records)).hexdigest(), "tree receipt differs")
        custody.check()
        require(set(os.listdir(fd)) == {"source.tar", "objects.proof", "git-input-receipt.json"}, "artifact inventory changed")
        final, _, _ = custody.read("git-input-receipt.json", MAX_METADATA, False)
        require(final == receipt_sha, "receipt changed")
        return report


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentRefusal("argument shape differs")


def main(arguments=None):
    progress = Progress()
    progress.enter("arguments")
    try:
        parser = SafeParser(prog="codex-git-inputs", allow_abbrev=False)
        parser.add_argument("--mode", choices=("acquire", "verify"), required=True)
        parser.add_argument("--requirement-index", type=int, required=True)
        parser.add_argument("--git", type=Path)
        parser.add_argument("--ca-file", type=Path)
        parser.add_argument("--bundle-root", type=Path)
        parser.add_argument("--receipt-sha256")
        args = parser.parse_args(arguments)
        require(os.environ.get("OMUX_EXECUTION_GUARD"), "contained Git input context required")
        progress.enter("producer-context")
        # Acquisition alone is clipped to its independently declared Bazel
        # target. The offline verifier keeps the prior library budget policy.
        budget = (ProducerBudget(os.environ, PRODUCER_STARTED, progress)
                  if args.mode == "acquire" else Budget())
        budget.progress = progress
        enter(budget, "source-authority")
        requirement = selected_requirement(args.requirement_index, budget)
        if args.mode == "verify":
            require(args.git is None and args.ca_file is None and args.bundle_root is not None
                    and args.receipt_sha256 is not None, "offline verification arguments differ")
            enter(budget, "offline-verification")
            offline_verify(retained_git_location(args.bundle_root), args.receipt_sha256, requirement, budget)
            print(json.dumps({"status": "verified-git-tree-input", "sdk_compilation_admitted": False}))
            return
        enter(budget, "tool-authority")
        require(args.bundle_root is None and args.receipt_sha256 is None and args.git is not None
                and args.ca_file is not None and immutable_file(args.git) == GIT
                and immutable_file(args.ca_file) == PINNED_CA, "Git acquisition tool or argument pins differ")
        with ExitStack() as stack:
            enter(budget, "worker-custody")
            worker = GitOutput(Path(os.environ["TEST_TMPDIR"]), budget, "private-worker")
            stack.callback(worker.close)
            material = acquire(requirement, worker, budget, PINNED_CA)
            enter(budget, "source-revalidation")
            require(selected_requirement(args.requirement_index, budget) == requirement,
                    "source-derived requirement changed during acquisition")
            enter(budget, "output-custody")
            destination = GitOutput(Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]), budget)
            stack.callback(destination.close)
            report, digest = export(requirement, material, destination, budget)
        print(json.dumps({"receipt_sha256": digest, "files": len(report["inventory"]), "sdk_compilation_admitted": False}))

    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError,
            tarfile.TarError, subprocess.SubprocessError) as error:
        if isinstance(error, GitRefusal):
            raise
        raise GitRefusal(progress.phase, refusal_category(error)) from None


if __name__ == "__main__":
    try:
        main()
    except GitRefusal as error:
        emit_refusal(Progress(), error)
        raise SystemExit(1)
