"""Distinct history13 CLI/package bytes and held ordinary-input custody.

This module supplies predicates, not readiness. Only the actual build callback
and independently retained successful outer receipt can qualify its artifacts.
"""
from contextlib import ExitStack
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time

KIND = "omux-owned-history-tree-cli-package-v3"
STATUS = "compiled-history13-cli-package-experimental"
SELECTION_KIND = "omux-owned-history-tree-runtime-selection-v3"
BACKEND = "lib/codex/libexec/codex.bin"
MANIFEST = "runtime-manifest.json"
CA = "lib/codex/share/ca-bundle.crt"
TARGETS = ("//codex-rs/core:core-unit-tests", "//codex-rs/tui:tui-unit-tests",
           "//codex-rs/app-server:app-server-unit-tests", "//codex-rs/models-manager:models-manager-unit-tests")
CLI = "//codex-rs/cli:codex"
MAX_ARCHIVE, MAX_FILE, MAX_TOTAL, MAX_METADATA = 256*1024*1024, 512*1024*1024, 768*1024*1024, 8*1024*1024
CONTROL_PINS = {
    "siwc-native/expected-tests.json": "81080f6619afb31c3962a3842ea64c450d148e90b54da2c69d46a091c4bb1455",
    "siwc-native-catalog/expected-tests.json": "0fbfea44e7f8a12dd034d69945218e95f13617dd866c2c1a8a8ddc5ce2016189",
    "native-owned-history/expected-tests.json": "ce4c73ba0869471b71fdff14bb118eab130aa39c4ffe5003aa69495e9c26a52c",
}
HISTORY_CONTROL = "9ae90d61ffab78afe467fcc1e9def2c0ada704ab1b458322e4257a1d0b2f9fbd"
HISTORY_PATCH = "030630425f378832d182333d46d95f8ba183f2de3a04ea34195fb2e9b4c98eb1"


def need(value):
    if value is not True:
        raise ValueError("owned-history-runtime-refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(rows):
    result = {}
    for key, value in rows:
        need(key not in result); result[key] = value
    return result


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA)
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)+"\n").encode("ascii")


def pin(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None and value != "0"*64)
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def preserve_primary(primary,cleanup):
    prior=BaseException.__cause__.__get__(primary)
    raise BaseException.with_traceback(primary,BaseException.__traceback__.__get__(primary)) from (cleanup if prior is None else prior)


class Slot:
    def __init__(self): self.fd = None
    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None: os.close(fd)


class Held:
    """Bounded nofollow ancestry + actual original alias/leaf, enrolled before open."""
    def __init__(self, deadline, until_ns):
        need(type(deadline) is float and type(until_ns) is int and deadline <= until_ns/10**9)
        self.deadline, self.until_ns = deadline, until_ns
        self.slots, self.parents, self.files = [], {}, {}
        self.total, self.closed = 0, False

    def tick(self):
        need(not self.closed); self.deadline_check()

    def deadline_check(self):
        need(time.monotonic() < self.deadline and time.monotonic_ns() < self.until_ns)

    def open(self, name, flags, *, parent=None, mode=0o600):
        self.tick(); need(len(self.slots) < 128)
        slot = Slot(); self.slots.append(slot)  # no descriptor exists on insertion failure
        slot.fd = os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode, dir_fd=parent)
        return slot.fd

    def directory(self, path):
        path = Path(path)
        need(path.is_absolute() and str(path) == os.path.normpath(str(path)) and ".." not in path.parts)
        if path in self.parents: return self.parents[path][0]
        current = Path("/")
        if current not in self.parents:
            fd = self.open("/", os.O_RDONLY | os.O_DIRECTORY)
            self.parents[current] = (fd, identity(os.fstat(fd)), None, None)
        for name in path.parts[1:]:
            child = current/name
            if child not in self.parents:
                fd = self.open(name, os.O_RDONLY | os.O_DIRECTORY, parent=self.parents[current][0])
                anchor = identity(os.fstat(fd))
                need(stat.S_ISDIR(anchor[2]) and anchor == identity(os.stat(name, dir_fd=self.parents[current][0], follow_symlinks=False)))
                self.parents[child] = (fd, anchor, current, name)
            current = child
        return self.parents[path][0]

    def add(self, alias, maximum, *, expected=None, size=None, modes=(0o444,0o555), owner=None):
        self.tick(); alias = Path(alias)
        need(alias.is_absolute() and type(maximum) is int and 0 < maximum <= MAX_FILE and len(self.files) < 64)
        parent_path = alias.parent.resolve(strict=True)
        parent = self.directory(parent_path)
        named = os.stat(alias.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) or stat.S_ISLNK(named.st_mode))
        literal = os.readlink(alias.name, dir_fd=parent) if stat.S_ISLNK(named.st_mode) else None
        physical = alias.resolve(strict=True)
        physical_parent = self.directory(physical.parent)
        before = os.stat(physical.name, dir_fd=physical_parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and (before.st_nlink >= 1 if owner == 0 else before.st_nlink == 1)
             and before.st_uid == (os.getuid() if owner is None else owner)
             and stat.S_IMODE(before.st_mode) in modes and 0 <= before.st_size <= maximum
             and self.total+before.st_size <= MAX_TOTAL and alias not in self.files)
        fd = self.open(physical.name, os.O_RDONLY | os.O_NONBLOCK, parent=physical_parent)
        row = {"fd":fd, "path":physical, "parent":physical_parent, "alias_parent":parent,
               "alias_parent_path":parent_path, "alias":identity(named), "literal":literal,
               "identity":identity(before), "size":before.st_size, "sha256":None}
        self.files[alias] = row; self.total += before.st_size
        self.fence_one(alias, row)
        raw = self.raw(alias)
        if expected is not None: need(sha(raw) == pin(expected) and len(raw) == size)
        row["sha256"] = sha(raw)
        return raw

    def fence_one(self, alias, row):
        self.tick()
        need(alias.parent.resolve(strict=True) == row["alias_parent_path"] and alias.resolve(strict=True) == row["path"])
        named = os.stat(alias.name, dir_fd=row["alias_parent"], follow_symlinks=False)
        need(identity(named) == row["alias"])
        if row["literal"] is not None: need(os.readlink(alias.name, dir_fd=row["alias_parent"]) == row["literal"])
        need(identity(os.fstat(row["fd"])) == row["identity"] == identity(os.stat(
            row["path"].name, dir_fd=row["parent"], follow_symlinks=False)))

    def raw(self, alias):
        alias = Path(alias); row = self.files[alias]; self.fence_one(alias,row)
        chunks, offset = [], 0
        while offset < row["size"]:
            self.tick(); body = os.pread(row["fd"], min(65536,row["size"]-offset), offset)
            need(bool(body)); chunks.append(body); offset += len(body)
        need(os.pread(row["fd"],1,offset) == b"")
        raw = b"".join(chunks); self.fence_one(alias,row)
        if row["sha256"] is not None: need(sha(raw) == row["sha256"])
        return raw

    def fence(self):
        self.tick()
        for path,(fd,anchor,parent,name) in self.parents.items():
            need(identity(os.fstat(fd)) == anchor)
            if parent is not None:
                need(identity(os.stat(name,dir_fd=self.parents[parent][0],follow_symlinks=False)) == anchor)
        for alias,row in self.files.items(): self.fence_one(alias,row)
        self.tick()

    def full(self):
        for alias in self.files: self.raw(alias)
        self.fence()

    def named_fence(self):
        """Post-cleanup observation of original names; no reopen, hash or rebase.

        Every FD must already have retired successfully. This bounded physical
        observation is non-atomic and does not promise continuing immutability.
        """
        need(self.closed); self.deadline_check()
        for path,(_,anchor,_,_) in self.parents.items():
            need(identity(os.stat(path,follow_symlinks=False)) == anchor)
        for alias,row in self.files.items():
            self.deadline_check()
            need(alias.parent.resolve(strict=True) == row["alias_parent_path"]
                 and alias.resolve(strict=True) == row["path"]
                 and identity(os.stat(alias,follow_symlinks=False)) == row["alias"]
                 and identity(os.stat(row["path"],follow_symlinks=False)) == row["identity"])
            if row["literal"] is not None: need(os.readlink(alias) == row["literal"])
        self.deadline_check()

    def close(self):
        if self.closed: return
        self.closed = True; first = None
        for slot in reversed(self.slots):
            try: slot.close()
            except BaseException as error:
                if first is None: first = error
        self.slots = []
        if first is not None: raise first

    def __enter__(self): return self
    def __exit__(self, kind, primary, tb):
        try: self.close()
        except BaseException as cleanup:
            if primary is None: raise
            prior=BaseException.__cause__.__get__(primary)
            raise BaseException.with_traceback(primary,tb) from (cleanup if prior is None else prior)
        return False


def required_tests(raws):
    need(set(raws) == set(CONTROL_PINS))
    values = {name:decode(raw) for name,raw in raws.items() if sha(raw) == CONTROL_PINS[name]}
    need(len(values) == 3)
    old, catalog, history = (values[name] for name in CONTROL_PINS)
    result = {TARGETS[0]:catalog["core_unit_tests"]+old["expected"]+history["core_unit_tests"],
              TARGETS[1]:catalog["tui_unit_tests"],
              TARGETS[2]:catalog["app_server_unit_tests"]+history["app_server_unit_tests"], TARGETS[3]:[]}
    need(tuple(map(len,result.values())) == (50,4,6,0) and len({name for names in result.values() for name in names}) == 60)
    return result


def validate_models(value, expected):
    need(value["kind"] == "omux-native-siwc-catalog-models-v1"
         and value["status"] == "executed-normal-native-unit-targets-catalog-test-only"
         and value["targets"] == list(TARGETS)
         and value["new_catalog_methods_passed"] == 20 and value["original_v4_methods_passed"] == 15
         and value["owned_history_methods_passed"] == 25
         and value["normal_unit_target_regressions_passed"] is True
         and all(value[name] is False for name in ("default_cli_binary_qualified","native_image_qualified",
             "installed_or_ordinary_native_qualified","provider_qualified")))
    need(set(value["actual_libtest"]) == set(TARGETS))
    for target in TARGETS:
        row = value["actual_libtest"][target]
        need(row["required_passed"] == expected[target] and row["failed"] == row["filtered_out"] == 0
             and type(row["passed"]) is int and row["passed"] >= len(expected[target]))
        pin(row["log_sha256"])
    need(len(value["source"]["patch_sha256"]) == 13 and value["source"]["patch_sha256"][-1] == HISTORY_PATCH)
    pin(value["source"]["receipt_sha256"]); pin(value["source"]["inventory_sha256"])


def safe_name(name):
    need(type(name) is str and 0 < len(name) <= 4096 and str(PurePosixPath(name)) == name
         and not name.startswith("/") and all(part not in ("",".","..") for part in name.split("/"))
         and not any(c in name for c in ("\\","\0","\r","\n","\t")))


def verify_package(payload, receipt_raw, *, expected_tests, portable, runtime):
    """Whole new receipt family and closed ELF/archive verification; no old projection."""
    receipt = decode(receipt_raw)
    need(set(receipt) == {"schema_version","kind","status","archive_sha256","archive_bytes",
         "manifest_sha256","build","models","source","sdk","tools","native_support","provider_qualified",
         "ordinary_qualified","live_handoff_qualified"})
    need(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1 and receipt["kind"] == KIND and receipt["status"] == STATUS
         and all(receipt[name] is False for name in ("native_support","provider_qualified","ordinary_qualified","live_handoff_qualified"))
         and type(payload) is bytes and 0 < len(payload) <= MAX_ARCHIVE
         and type(receipt["archive_bytes"]) is int and receipt["archive_bytes"] == len(payload)
         and pin(receipt["archive_sha256"]) == sha(payload))
    validate_models(receipt["models"],expected_tests)
    build = receipt["build"]
    need(build["target"] == CLI and type(build["exit"]) is int and build["exit"] == 0 and build["configuration"] == "opt"
         and type(build["argv"]) is list and 0<len(build["argv"])<=4096 and all(type(arg) is str for arg in build["argv"])
         and build["argv"][-1] == CLI
         and build["argv"].count("build") == 1 and sha(encoded(build["argv"])) == build["argv_sha256"]
         and receipt["sdk"]["kind"] == "omux-retained-current-sdk-tree-content-v1"
         and receipt["sdk"] == receipt["models"]["transported_sdk"]
         and build["source_inventory_sha256"] == receipt["models"]["source"]["inventory_sha256"]
         and receipt["source"] == receipt["models"]["source"])
    pin(build["argv_sha256"]); pin(build["stdout_sha256"]); pin(build["stderr_sha256"])
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream: raw = stream.read(MAX_FILE+MAX_METADATA+1)
    need(len(raw) <= MAX_FILE+MAX_METADATA)
    files, modes = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:") as archive:
        for member in archive:
            safe_name(member.name)
            need(member.isfile() and member.name not in files and len(files)<128
                 and member.mode in (0o644,0o755) and 0 <= member.size <= (MAX_FILE if member.name == BACKEND else 32*1024*1024))
            body = archive.extractfile(member).read(member.size+1); need(len(body) == member.size)
            files[member.name],modes[member.name] = body,member.mode
    need(MANIFEST in files and sha(files[MANIFEST]) == pin(receipt["manifest_sha256"]))
    manifest = decode(files.pop(MANIFEST)); need(modes.pop(MANIFEST) == 0o644)
    need(set(manifest) == {"schema_version","kind","status","target","files","runtime","executable","source","models_sha256","sdk_sha256"})
    need(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and manifest["kind"] == KIND and manifest["status"] == STATUS
         and manifest["target"] == "x86_64-linux" and manifest["source"] == receipt["source"]
         and manifest["models_sha256"] == sha(encoded(receipt["models"]))
         and manifest["sdk_sha256"] == sha(encoded(receipt["sdk"]))
         and manifest["files"] == {name:{"sha256":sha(body),"bytes":len(body),"mode":modes[name]} for name,body in sorted(files.items())})
    info = manifest["runtime"]
    dependencies = info["dependencies"]
    need(type(dependencies) is list and dependencies == sorted(set(dependencies)) and 0 < len(dependencies) <= 32
         and info["loader"] in dependencies and info["caBundle"] == CA
         and info["backendInterpreter"] == portable._BACKEND_INTERPRETER
         and set(files) == {"bin/codex",BACKEND,CA,*dependencies})
    names = {Path(name).name for name in dependencies}
    for name in dependencies: need(name == "lib/codex/lib/"+portable._basename(name))
    for name in (BACKEND,*dependencies):
        metadata = portable.elf_metadata(files[name],max_bytes=MAX_FILE if name == BACKEND else 32*1024*1024)
        need(metadata["machine"] == 62 and all("/" not in edge and edge in names for edge in metadata["needed"]))
        need((metadata["interpreter"] == portable._BACKEND_INTERPRETER and metadata["rpath"] == ["$ORIGIN/../lib"])
             if name == BACKEND else (metadata["interpreter"] in (None,portable._BACKEND_INTERPRETER)
                 and all(path == "$ORIGIN" for path in metadata["rpath"])))
    need(files["bin/codex"] == runtime.codex_launcher(Path(info["loader"]).name))
    portable._verify_ca_bundle(files[CA])
    executable = manifest["executable"]
    for phase in ("original","stripped","packaged"):
        pin(executable[phase+"_sha256"]); need(type(executable[phase+"_bytes"]) is int and 0<executable[phase+"_bytes"]<=MAX_FILE)
    need(executable["original_sha256"] == build["binary_sha256"] and executable["original_bytes"] == build["binary_bytes"]
         and executable["packaged_sha256"] == sha(files[BACKEND]) and executable["packaged_bytes"] == len(files[BACKEND]))
    return manifest,files
