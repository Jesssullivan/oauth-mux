"""Held read-only custody for Yoga wrapper metadata and existing store inputs.

No CLI, writer, realization, transport, process launch or permission operation.
The independently SHA-selected controller NAR receipt is required separately
from the historical wrapper companion. Callers must preserve browser authority
qualification and aggregate/display admission before executing returned paths.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

SHA = re.compile(r"[0-9a-f]{64}")
STORE = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}")
TOOLS = frozenset(("python", "systemd_run", "systemctl", "bazel", "closure", "bootstrap_closure", "zig_sdk", "java_home"))
ROLES = frozenset(("dbus_session", "dbus_daemon", "keyring"))
EVIDENCE = frozenset(("companion", "nativeManifest", "registeredNativeManifest", "controllerInventory", "controllerNarProof"))
ENVELOPE_FIELDS = EVIDENCE | {"controllerTools"}
HELPER_FILES = frozenset(("delivery/yoga_wrapper_authority.py", "delivery/yoga_wrapper_custody.py"))
NAR_FIELDS = frozenset(("schemaVersion", "passed", "inventorySha256", "descriptorSha256", "verifiedPaths",
    "verifiedRegularInputs", "verifiedNarBytes", "contentRehashed", "linkTargetsFollowed", "executionAuthority", "flakeMappingVerified", "realized"))
MAXIMUM = {"companion": 65536, "nativeManifest": 1024 * 1024, "registeredNativeManifest": 1024 * 1024,
           "controllerInventory": 8 * 1024 * 1024, "controllerNarProof": 8 * 1024 * 1024}
DATABASE = "/nix/var/nix/db/db.sqlite"


class CustodyRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise CustodyRefusal(reason)


def budget(deadline, now):
    require(type(deadline) is int and 0 < deadline - now() <= 1200 * 10**9, "deadline_exceeded")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "metadata_invalid")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(CustodyRefusal("metadata_invalid")))
    except (ValueError, UnicodeError, RecursionError):
        raise CustodyRefusal("metadata_invalid") from None


def physical(path):
    require(type(path) is str and 1 <= len(path) <= 4096 and path.startswith(("/srv/", "/nix/store/"))
            and re.fullmatch(r"/[A-Za-z0-9+._?=@/-]+", path) and str(Path(path)) == path
            and not {".", ".."}.intersection(path.split("/")), "metadata_invalid")
    if path.startswith("/nix/store/"):
        require(STORE.fullmatch("/".join(path.split("/")[:4])), "metadata_invalid")


def envelope(value):
    require(type(value) is dict and set(value) == ENVELOPE_FIELDS, "metadata_invalid")
    for name in EVIDENCE:
        item = value[name]
        require(type(item) is dict and set(item) == {"path", "sha256"}
                and type(item["sha256"]) is str and SHA.fullmatch(item["sha256"]), "metadata_invalid")
        physical(item["path"])
    tools = value["controllerTools"]
    require(type(tools) is dict and set(tools) == TOOLS, "metadata_invalid")
    for path in tools.values():
        physical(path)
        require(path.startswith("/nix/store/"), "metadata_invalid")
    require(STORE.fullmatch(value["registeredNativeManifest"]["path"]), "metadata_invalid")
    require(Path(value["nativeManifest"]["path"]).name == "native.json", "metadata_invalid")
    return value


def source_hashes(value):
    require(type(value) is dict and set(value) == HELPER_FILES
            and all(type(sha) is str and SHA.fullmatch(sha) for sha in value.values()), "metadata_invalid")
    return value


def witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parent_witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


def parent(path, uid, deadline, now):
    budget(deadline, now)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    walked, observations = Path("/"), []
    try:
        root = os.fstat(descriptor)
        require(root.st_uid == 0 and not root.st_mode & 0o022, "custody_invalid")
        observations.append(parent_witness(root))
        for name in Path(path).parts[1:-1]:
            budget(deadline, now)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                walked /= name
                sticky_store = walked == Path("/nix/store") and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1775
                require(info.st_uid in (0, uid) and (not info.st_mode & 0o022 or sticky_store), "custody_invalid")
                if walked != Path("/nix/store") and walked.is_relative_to("/nix/store"):
                    require(info.st_uid == 0 and not info.st_mode & 0o222, "custody_invalid")
                observations.append(parent_witness(info))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor); descriptor = child
        return descriptor, tuple(observations)
    except BaseException:
        os.close(descriptor)
        raise


class Captured:
    def __init__(self, path, expected, maximum, deadline, now, *, executable=False, read=True):
        self.fd, self.directory = None, None
        self.path, self.deadline, self.now = path, deadline, now
        self.read, self.maximum = read, maximum
        physical(path); budget(deadline, now)
        require(type(maximum) is int and 0 < maximum <= 512 * 1024 * 1024, 'metadata_invalid')
        require(expected is None or type(expected) is str and SHA.fullmatch(expected), "metadata_invalid")
        try:
            self.directory, self.parents = parent(path, os.getuid(), deadline, now)
            self.fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.directory)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
                    and info.st_nlink >= 1 and 0 <= info.st_size <= maximum, "custody_invalid")
            if path.startswith("/nix/store/"):
                require(info.st_uid == 0 and not info.st_mode & 0o222, "custody_invalid")
            require(not executable or bool(info.st_mode & 0o111), "custody_invalid")
            self.identity = witness(info)
            payload = bytearray()
            if read:
                while True:
                    budget(deadline, now)
                    data = os.read(self.fd, min(65536, maximum + 1 - len(payload)))
                    if not data: break
                    payload.extend(data)
                    require(len(payload) <= maximum, "byte_bound")
                require(len(payload) == info.st_size, "input_changed")
            self.data = bytes(payload)
            require(expected is None or hashlib.sha256(self.data).hexdigest() == expected, "digest_mismatch")
            self.digest = hashlib.sha256(self.data).hexdigest()
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        budget(self.deadline, self.now)
        fresh, observations = parent(self.path, os.getuid(), self.deadline, self.now)
        try:
            require(observations == self.parents
                    and parent_witness(os.fstat(fresh)) == parent_witness(os.fstat(self.directory)), "input_changed")
            named = os.stat(Path(self.path).name, dir_fd=fresh, follow_symlinks=False)
            require(witness(os.fstat(self.fd)) == self.identity == witness(named), "input_changed")
            if self.read:
                digest, total = hashlib.sha256(), 0
                while True:
                    budget(self.deadline, self.now)
                    data = os.pread(self.fd, min(65536, self.maximum + 1 - total), total)
                    if not data: break
                    total += len(data)
                    require(total <= self.maximum, "byte_bound")
                    digest.update(data)
                require(total == self.identity[6] and digest.hexdigest() == self.digest, "digest_mismatch")
                final, final_observations = parent(self.path, os.getuid(), self.deadline, self.now)
                try:
                    require(final_observations == self.parents
                            and parent_witness(os.fstat(final)) == parent_witness(os.fstat(self.directory)), "input_changed")
                    named = os.stat(Path(self.path).name, dir_fd=final, follow_symlinks=False)
                    require(witness(os.fstat(self.fd)) == self.identity == witness(named), "input_changed")
                finally:
                    os.close(final)
        finally:
            os.close(fresh)
        budget(self.deadline, self.now)

    def close(self):
        failed = False
        for name in ("fd", "directory"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                try: os.close(descriptor)
                except OSError: failed = True
        require(not failed, "cleanup_incomplete")


def registered_rows(rows, deadline, now=time.monotonic_ns, database=DATABASE):
    budget(deadline, now)
    require(type(rows) is list and 1 <= len(rows) <= 4096, "registry_invalid")
    until = min(deadline, now() + 5 * 10**9)
    connection = sqlite3.connect(Path(database).as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.set_progress_handler(lambda: int(now() >= until), 1000)
        connection.execute("BEGIN")
        for row in rows:
            budget(until, now)
            info = os.lstat(row["path"])
            require(info.st_uid == 0 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode))
                    and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o222), "registry_invalid")
            current = connection.execute("SELECT id,hash,narSize FROM ValidPaths WHERE path=?", (row["path"],)).fetchone()
            require(current is not None and current[1:] == (row["narHash"], row["narSize"]), "registry_changed")
            refs = [item[0] for item in connection.execute("SELECT v.path FROM Refs r JOIN ValidPaths v ON v.id=r.reference WHERE r.referrer=? ORDER BY v.path", (current[0],))]
            require(refs == row["references"], "registry_changed")
        budget(until, now)
    finally:
        connection.close()


class AuthorityCapture:
    def __init__(self, selected, wrapper_paths, wrapper_sha256, deadline_ns, *, validator=None,
                 native_manifest_path=None, now=time.monotonic_ns, registry=registered_rows):
        self.captures, self.deadline, self.now, self.registry = [], deadline_ns, now, registry
        self.selected = decode(canonical(envelope(selected)))
        budget(deadline_ns, now)
        if validator is None:
            import yoga_wrapper_authority as validator
        require(type(wrapper_paths) is dict and set(wrapper_paths) == ROLES
                and type(wrapper_sha256) is dict and set(wrapper_sha256) == ROLES, "metadata_invalid")
        self.wrapper_paths, self.wrapper_sha256 = dict(wrapper_paths), dict(wrapper_sha256)
        def capture(path, sha, bound, **options):
            item = Captured(path, sha, bound, deadline_ns, now, **options)
            self.captures.append(item)
            return item
        try:
            self.metadata = {name: capture(native_manifest_path if name == "nativeManifest" and native_manifest_path is not None
                else value["path"], value["sha256"], MAXIMUM[name]) for name, value in sorted(self.selected.items()) if name in EVIDENCE}
            wrappers = {role: capture(wrapper_paths[role], wrapper_sha256[role], 8192, executable=True) for role in sorted(ROLES)}
            self.result = validator.validate(self.metadata["companion"].data,
                companion_sha256=self.selected["companion"]["sha256"], native_manifest_bytes=self.metadata["nativeManifest"].data,
                native_manifest_sha256=self.selected["nativeManifest"]["sha256"],
                registered_native_manifest_bytes=self.metadata["registeredNativeManifest"].data,
                inventory_bytes=self.metadata["controllerInventory"].data, inventory_sha256=self.selected["controllerInventory"]["sha256"],
                native_manifest_path=self.metadata["nativeManifest"].path, wrapper_paths=wrapper_paths,
                wrapper_bytes={role: item.data for role, item in wrappers.items()}, wrapper_sha256=wrapper_sha256,
                controller_tools=self.selected["controllerTools"], deadline_ns=deadline_ns, now=now)
            companion = decode(self.metadata["companion"].data)
            require(companion["nativeManifest"]["registeredObject"] == self.selected["registeredNativeManifest"]["path"]
                    and companion["nativeManifest"]["registeredManifestSha256"] == self.selected["registeredNativeManifest"]["sha256"], "metadata_invalid")
            self.rows = decode(self.metadata["controllerInventory"].data)["paths"]
            nar = decode(self.metadata["controllerNarProof"].data)
            require(type(nar) is dict and set(nar) == NAR_FIELDS and type(nar["schemaVersion"]) is int and nar["schemaVersion"] == 1
                    and nar["passed"] is True and nar["contentRehashed"] is True
                    and nar["inventorySha256"] == self.selected["controllerInventory"]["sha256"]
                    and type(nar["descriptorSha256"]) is str and SHA.fullmatch(nar["descriptorSha256"])
                    and type(nar["verifiedPaths"]) is int and nar["verifiedPaths"] == len(self.rows)
                    and type(nar["verifiedRegularInputs"]) is int and nar["verifiedRegularInputs"] > 0
                    and type(nar["verifiedNarBytes"]) is int and nar["verifiedNarBytes"] == sum(row["narSize"] for row in self.rows)
                    and all(nar[name] is False for name in ("linkTargetsFollowed", "executionAuthority", "flakeMappingVerified", "realized")), "nar_unqualified")
            for path in sorted({binding.interpreter for binding in self.result.bindings} | {binding.backend for binding in self.result.bindings}):
                capture(path, None, 512 * 1024 * 1024, executable=True, read=False)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.registry(self.rows, self.deadline, self.now)
        for item in self.captures: item.check()
        # Inspect the selected closure's native.json root link literally, never
        # resolve an unregistered link chain through host/configuration paths.
        closure = self.selected["controllerTools"]["closure"]
        directory, _ = parent(closure + "/native.json", os.getuid(), self.deadline, self.now)
        try:
            info = os.stat("native.json", dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                    and os.readlink("native.json", dir_fd=directory) == self.selected["registeredNativeManifest"]["path"], "registry_changed")
        finally:
            os.close(directory)
        for item in self.captures: item.check()
        budget(self.deadline, self.now)

    def close(self):
        failed = False
        for item in reversed(self.captures):
            try: item.close()
            except OSError: failed = True
            except CustodyRefusal: failed = True
        self.captures.clear()
        require(not failed, "cleanup_incomplete")

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is None: self.check()
        finally:
            self.close()
