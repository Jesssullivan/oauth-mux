"""Structural declaration only; Bazel invokes both phases with locked Python.

Action authentication remains in the unchanged metadata/SDK consumers. The
command line has no alternate input selectors. RolePolicy injection and events
are Python model seams, unavailable from the production command line.
"""
import argparse
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import sys

BASE = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"
CONTROL = BASE + "32da88ee-f894-4453-8371-3cc4719c8ade/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_metadata_binding_producer/test.outputs/owner-status-persistence-metadata-binding.json"
CONTROL_SHA = "19903dbf0c939fe88522f3ee45dfb9049739abc12ad68bdb890b04867d2b08fe"
SOURCE = BASE + "95f10057-c0be-4a94-98f8-291dedec0d48/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_source_producer/test.outputs/owner-status-persistence-source"
EXPORT = BASE + "e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
JDK = "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"
SOURCE_SHA = "a17c9b7294fd7b8018f60bd2210f14140598d4b04e10da05aa1733a9482f3eab"
INVENTORY_SHA = "252599e5faafa05e2ff688e57e58d1890aea57ead0f35ce0633588754cae5030"
PLAN = ".metadata-declaration-plan.json"
STAGE = ".metadata-declaration-stage"
KIND = "omux-owner-status-persistence-declaration-plan-v1"
MAX_PLAN = 512 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")


def need(value, category):
    if not value:
        raise ValueError("metadata-declaration-refused: " + category)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def digest(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def relative(value):
    need(type(value) is str and not value.startswith("/") and
         all(part not in ("", ".", "..") for part in value.split("/")) and
         not any(c in value for c in ("\\", "\n", "\r", "\t", "\0")), "relative-path")
    return value


def absolute(value):
    need(type(value) is str and value.startswith("/") and
         all(part not in ("", ".", "..") for part in value.split("/")[1:]) and
         not any(c in value for c in ("\n", "\r", "\t", "\0")), "absolute-path")
    return value


def normalize(value):
    result = []
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            need(result, "link-parent-escape")
            result.pop()
        else:
            result.append(part)
    return ("/" if value.startswith("/") else "") + "/".join(result)


def logical_resolve(key, links):
    seen = set()
    for _ in range(64):
        need(key not in seen, "link-cycle")
        seen.add(key)
        parts = key.split("/")
        prefixes = ("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        prefix = next((p for p in prefixes if p in links), None)
        if prefix is None:
            return key
        key = normalize(links[prefix] + key[len(prefix):])
    need(False, "excessive-link-depth")


def witness(info):
    base = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]
    # Namespace witnesses bind identity/custody; unrelated parent-directory
    # entry changes are not mistaken for a selected file change.
    if stat.S_ISDIR(info.st_mode):
        return ["directory"] + base
    return ["symlink" if stat.S_ISLNK(info.st_mode) else "file"] + base + [
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class Physical:
    """Each traversal checks physical ancestors; no implicit symbolic follow.

    Only one traversal and leaf are open at once. Saved witnesses are re-opened
    and compared, not claimed to be descriptors held between helper processes.
    """
    def __init__(self):
        self.root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.saved = {"/": witness(os.fstat(self.root))}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.root)

    def remember(self, path, value):
        if path in self.saved:
            need(self.saved[path] == value, "changed-input-witness")
        else:
            need(len(self.saved) < 1000000, "witness-bound")
            self.saved[path] = value

    def directory(self, path):
        need(path == "/" or absolute(path), "directory-path")
        fd = os.dup(self.root)
        prefix = ""
        try:
            self.remember("/", witness(os.fstat(fd)))
            for part in path.split("/")[1:]:
                if not part:
                    continue
                prefix += "/" + part
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode), "physical-directory")
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    selected = witness(before)
                    need(selected == witness(os.fstat(child)) == witness(
                        os.stat(part, dir_fd=fd, follow_symlinks=False)), "directory-namespace-race")
                    self.remember(prefix, selected)
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def node(self, path, kind, limit=None):
        absolute(path)
        parent, leaf = path.rsplit("/", 1)
        fd = self.directory(parent or "/")
        opened = None
        try:
            before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            selected = witness(before)
            if kind == "file":
                need(stat.S_ISREG(before.st_mode), "physical-regular-leaf")
                opened = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                need(selected == witness(os.fstat(opened)), "regular-open-race")
                raw = None
                if limit is not None:
                    need(before.st_size <= limit, "metadata-size")
                    chunks, size = [], 0
                    while True:
                        chunk = os.read(opened, min(65536, limit + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                        need(size <= limit, "metadata-size")
                    raw = b"".join(chunks)
                need(selected == witness(os.fstat(opened)), "regular-read-race")
            else:
                need(kind == "symlink" and stat.S_ISLNK(before.st_mode), "physical-symbolic-leaf")
                raw = os.readlink(leaf, dir_fd=fd)
                selected += [raw]
            named = witness(os.stat(leaf, dir_fd=fd, follow_symlinks=False))
            if kind == "symlink":
                named += [os.readlink(leaf, dir_fd=fd)]
            need(selected == named, "leaf-namespace-race")
            self.remember(path, selected)
            return raw
        finally:
            if opened is not None:
                os.close(opened)
            os.close(fd)

    def absent(self, path):
        parent, leaf = absolute(path).rsplit("/", 1)
        fd = self.directory(parent or "/")
        try:
            try:
                os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                self.remember(path, ["missing"])
                return
            need(False, "absent-target-created")
        finally:
            os.close(fd)

    def resolve(self, path, roots, symbolic):
        """Resolve actual components, preserving '..' after symbolic expansion.

        Before every filesystem read, require a declared root or its physical
        namespace ancestry. External JDK symbolic targets are never followed.
        """
        pending = absolute(path).split("/")[1:]
        current, seen, hops = [], set(), 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                need(current, "physical-link-parent-escape")
                current.pop()
                continue
            selected = "/" + "/".join(current + [part])
            need(any(selected == root or selected.startswith(root + "/") or
                     root.startswith(selected + "/") for root in roots), "physical-link-root")
            parent = "/" + "/".join(current)
            fd = self.directory(parent)
            try:
                try:
                    info = os.stat(part, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    self.absent(selected)
                    return normalize(selected + "/" + "/".join(pending)), False
            finally:
                os.close(fd)
            if stat.S_ISLNK(info.st_mode):
                need(selected in symbolic, "undeclared-symbolic-hop")
                raw = self.node(selected, "symlink")
                need(symbolic[selected] is None or raw == symbolic[selected], "symbolic-target-text")
                state = (selected, tuple(pending))
                need(state not in seen and hops < 64, "physical-link-cycle-or-depth")
                seen.add(state)
                hops += 1
                pending = raw.split("/") + pending
                if raw.startswith("/"):
                    current = []
            else:
                current.append(part)
                if pending or stat.S_ISDIR(info.st_mode):
                    opened = self.directory(selected)
                    os.close(opened)
                else:
                    self.node(selected, "file")
        return "/" + "/".join(current), True

    def recheck(self):
        expected = dict(self.saved)
        for path, value in expected.items():
            if value[0] == "directory":
                fd = self.directory(path)
                os.close(fd)
            elif value[0] == "missing":
                self.absent(path)
            else:
                self.node(path, value[0])
        need(self.saved == expected, "recheck-witness-set")


@dataclass(frozen=True)
class RolePolicy:
    control: str = CONTROL
    source: str = SOURCE
    export: str = EXPORT
    jdk: str = JDK
    selection_sha: str = CONTROL_SHA
    source_sha: str = SOURCE_SHA
    inventory_sha: str = INVENTORY_SHA
    control_size: int = 2896
    source_count: int = 8549


def declaration(physical, roles):
    """Preserve the original structural predicates, mapping and watch order."""
    raw = physical.node(roles.control, "file", roles.control_size)
    need(len(raw) == roles.control_size, "actual-n4-size")
    binding = json.loads(raw)
    selection = {"kind": "omux-owner-status-persistence-metadata-input-v1",
        "source_root": roles.source, "source_receipt_sha256": roles.source_sha,
        "source_inventory_sha256": roles.inventory_sha}
    need(binding.get("kind") == "omux-owner-status-persistence-metadata-binding-v1" and
         binding.get("source_reconstructed_and_fully_read") is True and
         binding.get("metadata_input") == selection, "actual-n4-role")
    for path in (roles.source, roles.source + "/source", roles.export, roles.jdk):
        fd = physical.directory(path)
        os.close(fd)
    source_receipt = roles.source + "/source-receipt.json"
    source = json.loads(physical.node(source_receipt, "file", 8 * 1024 * 1024))
    files = source.get("source_inventory", {})
    need(type(files) is dict and source.get("kind") == "omux-owner-status-persistence-source-v1" and
         source.get("status") == "verified-owner-status-persistence-source-pending-sdk-and-schema" and
         source.get("inventory_sha256") == roles.inventory_sha and
         all(source.get(flag) is False for flag in (
             "sdk_metadata_qualified", "native_compile_passed", "provider_evaluation")) and
         len(files) == roles.source_count, "source-receipt-role")
    inputs, watches = [roles.control, source_receipt], []
    source_prefix = roles.source + "/source/"
    source_links = {source_prefix + name: None for name, row in files.items()
        if type(row) is dict and row.get("mode") == "120000"}
    for name, row in sorted(files.items()):
        relative(name)
        need(type(row) is dict and set(row) == {"mode", "sha256"} and
             row["mode"] in ("100644", "100755", "120000") and digest(row["sha256"]), "source-inventory-row")
        path = source_prefix + name
        if row["mode"] == "120000":
            resolved, exists = physical.resolve(path, [source_prefix[:-1]], source_links)
            need(exists and resolved.startswith(source_prefix) and
                 resolved[len(source_prefix):] in files and
                 files[resolved[len(source_prefix):]].get("mode") in ("100644", "100755"), "source-link-target")
            watches.append(path)
        else:
            physical.node(path, "file")
            inputs.append(path)
    export_receipt = roles.export + "/receipt.json"
    exported = json.loads(physical.node(export_receipt, "file", 256 * 1024 * 1024))
    repositories = exported.get("repositories", [])
    need(type(repositories) is list and exported.get("schema") == "omux-retained-native-sdk-export-v1" and
         exported.get("qualification_only") is False and 0 < len(repositories) <= 1600 and
         exported.get("nix_store_roots") == [roles.jdk], "export-receipt-role")
    inputs.append(export_receipt)
    objects, links, paths, absences, symbolic, roots = {}, {}, {}, {}, {}, [roles.jdk]
    for repo in repositories:
        name = repo.get("canonical_name")
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_+.~-]+", name) and
             name not in objects, "repository-name")
        root = roles.export + "/repositories/" + name
        fd = physical.directory(root)
        os.close(fd)
        roots.append(root)
        objects[name], paths[name] = {"kind": "directory"}, root
        for row in repo.get("files", []):
            path = relative(row.get("path"))
            key = name + "/" + path
            need(key not in objects and row.get("kind") in ("file", "directory", "symlink"), "repository-inventory")
            objects[key], paths[key] = row, roles.export + "/repositories/" + key
            if row["kind"] == "symlink":
                target = row.get("target")
                need(type(target) is str and target and not any(c in target for c in ("\n", "\r", "\t", "\0")), "repository-link")
                destination = normalize(target if target.startswith("/") else key.rsplit("/", 1)[0] + "/" + target)
                need(destination.startswith(roles.jdk + "/") or not destination.startswith("/"), "repository-link-root")
                links[key], symbolic[paths[key]] = destination, target
        for absence in repo.get("absent_links", []):
            need(type(absence) is dict and set(absence) == {"origin", "target"} and
                 type(absence["origin"]) is str and type(absence["target"]) is str, "absent-link-role")
            absences[absence["origin"]] = absence["target"]
    need(0 < len(objects) <= 500000 and "rules_rs++crate+crates" in objects, "repository-object-bound")
    objects[roles.jdk], paths[roles.jdk] = {"kind": "directory"}, roles.jdk
    for row in exported.get("nix_inventory", []):
        key = roles.jdk + "/" + relative(row.get("path"))
        need(key not in objects and row.get("kind") in ("file", "directory", "symlink"), "immutable-jdk-inventory")
        objects[key], paths[key] = row, key
        if row["kind"] == "symlink":
            target = row.get("target")
            need(type(target) is str and target, "immutable-jdk-link")
            destination = normalize(target if target.startswith("/") else key.rsplit("/", 1)[0] + "/" + target)
            if destination.startswith(roles.jdk + "/"):
                links[key], symbolic[key] = destination, target
    for key, row in sorted(objects.items()):
        if row["kind"] == "file":
            need(type(row.get("size")) is int and 0 <= row["size"] <= 1024 * 1024 * 1024 and
                 digest(row.get("sha256")) and type(row.get("mode")) is int and
                 row["mode"] in (292, 365), "selected-file-pin")
            physical.node(paths[key], "file")
            inputs.append(paths[key])
        elif row["kind"] == "directory":
            fd = physical.directory(paths[key])
            os.close(fd)
    for key in sorted(links):
        if key.startswith(roles.jdk + "/"):
            continue
        resolved = logical_resolve(key, links)
        actual, exists = physical.resolve(paths[key], roots, symbolic)
        if resolved in objects:
            need(objects[resolved]["kind"] in ("file", "directory") and exists and
                 actual == paths[resolved], "physical-selected-link")
            watches.append(paths[key])
        else:
            need(key in absences and absences[key] == resolved and not exists and
                 not resolved.startswith("/") and resolved.split("/")[0] in objects and
                 actual == roles.export + "/repositories/" + resolved, "qualified-absent-link")
    for name, pin in exported.get("graph_files", {}).items():
        relative(name)
        need(type(pin) is dict and set(pin) == {"sha256"} and digest(pin["sha256"]), "graph-file-pin")
        path = roles.export + "/graph/" + name
        physical.node(path, "file")
        inputs.append(path)
    registry = exported.get("registry_metadata", {}).get("files", [])
    need(type(registry) is list and 0 < len(registry) <= 512, "registry-file-bound")
    for row in registry:
        value = row.get("sha256")
        need(digest(value) and row.get("path") == "content_addressable/sha256/" + value + "/file" and
             type(row.get("size")) is int and 0 <= row["size"] <= 1024 * 1024, "registry-file-pin")
        path = roles.export + "/registry-cache/" + row["path"]
        physical.node(path, "file")
        inputs.append(path)
    need(len(inputs) <= 500000, "declared-file-bound")
    watches.extend(inputs)
    physical.recheck()
    return {"kind": KIND, "selection_sha256": roles.selection_sha,
        "control_raw": raw.decode("utf-8"), "regularInputs": inputs,
        "watchInputs": watches, "witnesses": dict(physical.saved)}


def build_bytes(count):
    labels = ["input-files/" + str(i) for i in range(count)] + ["metadata-input.json", "metadata-input.sha256"]
    # Starlark repr uses double-quoted strings; aliases are ASCII and need no
    # escaping beyond JSON's identical list/string representation here.
    rendered = json.dumps(labels)
    return ("\n".join(['package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(rendered),
        'filegroup(name = "inputs", srcs = {})'.format(rendered), ""])).encode()


def rename_exclusive(source_fd, source, destination_fd, destination):
    # The fixed selected estate is Linux. Never fall back to overwriting rename.
    need(sys.platform == "linux", "publication-platform")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    need(rename is not None, "exclusive-publication-unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1):
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


def identity(info):
    return [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)]


class Publication:
    """Owned output transaction: BUILD-last acceptance, not filesystem atomicity."""
    def __init__(self, root):
        self.root = root
        self.stage = None
        self.aliases = None
        self.records = {}
        self.alias_records = {}
        self.public = {}
        self.contents = {}

    def __enter__(self):
        for name in (STAGE, "input-files", "metadata-input.json", "metadata-input.sha256", "BUILD.bazel"):
            try:
                os.stat(name, dir_fd=self.root, follow_symlinks=False)
            except FileNotFoundError:
                continue
            need(False, "preexisting-publication")
        os.mkdir(STAGE, mode=0o700, dir_fd=self.root)
        self.stage_identity = identity(os.stat(STAGE, dir_fd=self.root, follow_symlinks=False))
        try:
            self.stage = os.open(STAGE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.root)
            need(identity(os.fstat(self.stage)) == self.stage_identity, "stage-open-race")
        except BaseException as primary:
            try:
                need(identity(os.stat(STAGE, dir_fd=self.root, follow_symlinks=False)) == self.stage_identity, "owned-stage-cleanup")
                os.rmdir(STAGE, dir_fd=self.root)
            except BaseException:
                primary.add_note("owned stage cleanup refused")
            if self.stage is not None:
                os.close(self.stage)
                self.stage = None
            raise
        return self

    def file(self, name, raw):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.stage)
        self.records[name] = identity(os.fstat(fd))
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                need(written > 0, "publication-write")
                view = view[written:]
            os.fchmod(fd, 0o644)
            need(identity(os.stat(name, dir_fd=self.stage, follow_symlinks=False)) == self.records[name], "output-file-race")
            self.contents[name] = raw
        finally:
            os.close(fd)

    def check_file(self, parent, name, selected):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = witness(os.fstat(fd))
            info = os.fstat(fd)
            need(identity(info) == selected and stat.S_ISREG(info.st_mode) and
                 stat.S_IMODE(info.st_mode) == 0o644 and info.st_uid == os.getuid(), "output-regular-identity")
            expected = self.contents[name]
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, len(expected) + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                need(size <= len(expected), "output-byte-count")
            need(b"".join(chunks) == expected and before == witness(os.fstat(fd)) ==
                 witness(os.stat(name, dir_fd=parent, follow_symlinks=False)), "output-byte-readback")
        finally:
            os.close(fd)

    def check_aliases(self):
        selected = self.public["input-files"]
        def named_parent():
            info = os.stat("input-files", dir_fd=self.root, follow_symlinks=False)
            held = os.fstat(self.aliases)
            need(identity(info) == selected == identity(held) and
                 stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o755 and
                 info.st_uid == os.getuid() and witness(info) == witness(held), "published-alias-parent")
        named_parent()
        expected = {str(index) for index in range(len(self.alias_records))}
        need(set(os.listdir(self.aliases)) == expected, "published-alias-count")
        for name, (selected_leaf, target) in self.alias_records.items():
            before = os.stat(name, dir_fd=self.aliases, follow_symlinks=False)
            need(identity(before) == selected_leaf and stat.S_ISLNK(before.st_mode) and
                 os.readlink(name, dir_fd=self.aliases) == target and
                 witness(before) == witness(os.stat(name, dir_fd=self.aliases, follow_symlinks=False)),
                 "published-alias-recheck")
        need(set(os.listdir(self.aliases)) == expected, "published-alias-count")
        named_parent()

    def materialize(self, plan, physical, event):
        os.mkdir("input-files", mode=0o755, dir_fd=self.stage)
        self.records["input-files"] = identity(os.stat("input-files", dir_fd=self.stage, follow_symlinks=False))
        self.aliases = os.open("input-files", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.stage)
        need(identity(os.fstat(self.aliases)) == self.records["input-files"], "alias-directory-race")
        os.fchmod(self.aliases, 0o755)
        for index, source in enumerate(plan["regularInputs"]):
            physical.node(source, "file")
            name = str(index)
            os.symlink(source, name, dir_fd=self.aliases)
            self.alias_records[name] = (identity(os.stat(name, dir_fd=self.aliases, follow_symlinks=False)), source)
            need(os.readlink(name, dir_fd=self.aliases) == source, "alias-target")
        need(sorted(os.listdir(self.aliases), key=int) == [str(i) for i in range(len(plan["regularInputs"]))], "alias-count")
        self.file("metadata-input.json", plan["control_raw"].encode("utf-8"))
        self.file("metadata-input.sha256", (plan["selection_sha256"] + "\n").encode())
        build = build_bytes(len(plan["regularInputs"]))
        self.file("BUILD.bazel", build)
        physical.recheck()
        event("before-alias-publication")
        for name in ("input-files", "metadata-input.json", "metadata-input.sha256"):
            self.move(name)
        event("metadata-published")
        physical.recheck()
        self.check_aliases()
        for name in ("metadata-input.json", "metadata-input.sha256"):
            self.check_file(self.root, name, self.public[name])
        event("before-ready")
        self.move("BUILD.bazel")
        event("ready-published")
        physical.recheck()
        for name in ("metadata-input.json", "metadata-input.sha256", "BUILD.bazel"):
            self.check_file(self.root, name, self.public[name])
        self.check_aliases()
        return {"materialized": True, "input_count": len(plan["regularInputs"]),
            "selection_sha256": plan["selection_sha256"], "build_sha256": sha(build)}

    def move(self, name):
        need(identity(os.stat(STAGE, dir_fd=self.root, follow_symlinks=False)) == self.stage_identity and
             identity(os.fstat(self.stage)) == self.stage_identity and
             identity(os.stat(name, dir_fd=self.stage, follow_symlinks=False)) == self.records[name], "publication-namespace-race")
        if name != "input-files":
            self.check_file(self.stage, name, self.records[name])
        rename_exclusive(self.stage, name, self.root, name)
        self.public[name] = self.records.pop(name)
        need(identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) == self.public[name], "published-namespace-race")

    def cleanup(self, rollback):
        failures = []
        def remove(fd, name, selected, directory=False):
            need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == selected, "owned-cleanup-identity")
            (os.rmdir if directory else os.unlink)(name, dir_fd=fd)
        if rollback:
            # Delete readiness first. Continue independent cleanup after a refusal;
            # preserve primary failure and never delete a substituted object.
            for name in reversed(list(self.public)):
                try:
                    if name == "input-files":
                        need(identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) == self.public[name], "owned-alias-parent")
                        self.clear_aliases()
                    remove(self.root, name, self.public[name], name == "input-files")
                except BaseException as error:
                    failures.append(str(error))
        for name in reversed(list(self.records)):
            try:
                if name == "input-files":
                    self.clear_aliases()
                remove(self.stage, name, self.records[name], name == "input-files")
            except BaseException as error:
                failures.append(str(error))
        try:
            remove(self.root, STAGE, self.stage_identity, True)
        except BaseException as error:
            failures.append(str(error))
        return failures

    def clear_aliases(self):
        for name, (selected, target) in reversed(list(self.alias_records.items())):
            need(identity(os.stat(name, dir_fd=self.aliases, follow_symlinks=False)) == selected and
                 os.readlink(name, dir_fd=self.aliases) == target, "owned-alias-cleanup")
            os.unlink(name, dir_fd=self.aliases)

    def __exit__(self, kind, error, _):
        try:
            failures = self.cleanup(kind is not None)
            if failures:
                if error is not None:
                    error.add_note("owned declaration cleanup refused: " + "; ".join(failures))
                else:
                    # A cleanup failure after readiness must fail acceptance too.
                    rollback_failures = self.cleanup(True)
                    need(False, "owned-cleanup-refused: " + "; ".join(failures + rollback_failures))
        finally:
            if self.aliases is not None:
                os.close(self.aliases)
            if self.stage is not None:
                os.close(self.stage)


def output_directory(directory):
    physical = Physical()
    fd = None
    try:
        fd = physical.directory(absolute(directory))
        info = os.fstat(fd)
        need(info.st_uid == os.getuid() and not info.st_mode & 0o022, "output-custody")
        return physical, fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        physical.__exit__()
        raise


def prepare(directory, roles=RolePolicy()):
    with Physical() as physical:
        plan = declaration(physical, roles)
    raw = encode(plan)
    need(len(raw) <= MAX_PLAN, "plan-size")
    output, root = output_directory(directory)
    fd = None
    selected = None
    try:
        fd = os.open(PLAN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
        selected = identity(os.fstat(fd))
        view = memoryview(raw)
        while view:
            amount = os.write(fd, view)
            need(amount > 0, "plan-write")
            view = view[amount:]
        need(identity(os.stat(PLAN, dir_fd=root, follow_symlinks=False)) == selected, "plan-namespace-race")
        output.recheck()
    except BaseException as primary:
        if selected is not None:
            try:
                need(identity(os.stat(PLAN, dir_fd=root, follow_symlinks=False)) == selected, "owned-plan-cleanup")
                os.unlink(PLAN, dir_fd=root)
            except BaseException:
                primary.add_note("owned plan cleanup refused")
        raise
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)
        output.__exit__()
    return {"kind": KIND, "plan_sha256": sha(raw), "selection_sha256": roles.selection_sha,
        "regularInputs": plan["regularInputs"], "watchInputs": plan["watchInputs"],
        "control_raw": plan["control_raw"]}


def materialize(directory, plan_sha, roles=RolePolicy(), *, event=lambda _: None, emit=lambda _: None):
    need(digest(plan_sha), "plan-digest")
    with Physical() as plan_reader:
        raw = plan_reader.node(absolute(directory) + "/" + PLAN, "file", MAX_PLAN)
        need(sha(raw) == plan_sha, "plan-byte-binding")
        expected = json.loads(raw)
        with Physical() as physical:
            actual = declaration(physical, roles)
            need(actual == expected, "original-plan-and-witnesses")
            output, root = output_directory(directory)
            try:
                with Publication(root) as publication:
                    result = publication.materialize(actual, physical, event)
                    plan_reader.recheck()
                    output.recheck()
                    result["plan_sha256"] = plan_sha
                    publication.check_aliases()
                    emit(result)
                return result
            finally:
                os.close(root)
                output.__exit__()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("plan", "materialize"), required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args()
    def emit(value):
        print(encode(value).decode(), flush=True)
    if args.phase == "plan":
        need(args.plan_sha256 is None, "plan-arguments")
        emit(prepare(args.directory))
    else:
        materialize(args.directory, args.plan_sha256, emit=emit)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError) as error:
        print("metadata-declaration-refused", file=sys.stderr)
        for note in getattr(error, "__notes__", []):
            print(note, file=sys.stderr)
        sys.exit(125)
