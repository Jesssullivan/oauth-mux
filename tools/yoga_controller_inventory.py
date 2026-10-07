"""Read-only registered controller inventory and separate declared-wrapper bytes.

The independently selected eight controllers and native manifests select the
roots. A SQLite read transaction supplies their exact reference closure. This
producer never executes a wrapper/backend, realizes a path, imports a closure,
or proves NAR contents or destination registration. The existing declared NAR
byte-proof target must separately consume the emitted inventory digest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from cached_nix_inventory import MAX_REFS, snapshot_inventory
from verify_cached_nars import MAX_BYTES, MAX_INPUT, MAX_PATHS, STORE, parse_inventory
import yoga_proof_inputs as custody

TOOLS = frozenset(("python", "systemd_run", "systemctl", "bazel", "closure", "bootstrap_closure", "zig_sdk", "java_home"))
WRAPPERS = {"dbus_session": ("dbus_run_session", "dbus-run-session"),
            "dbus_daemon": ("dbus_daemon", "dbus-daemon"),
            "keyring": ("gnome_keyring_daemon", "gnome-keyring-daemon")}
FIELDS = frozenset(("schemaVersion", "scope", "controllerTools", "nativeManifestSha256",
                    "bootstrapManifestSha256", "wrapperSha256"))
DATABASE = "/nix/var/nix/db/db.sqlite"
MAX_SELECTION = 65536
MAX_MANIFEST = 1024 * 1024
MAX_WRAPPER = 8192
CLEANUP_NS = 30 * 10**9
SNAPSHOT_NS = 31 * 10**9
REASONS = frozenset(("selection_invalid", "deadline_exceeded", "input_unqualified", "input_changed",
                     "digest_mismatch", "manifest_mismatch", "wrapper_mismatch", "registry_invalid",
                     "registry_changed", "byte_bound", "output_unqualified", "cleanup_incomplete"))


class InventoryError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "registry_invalid"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise InventoryError(reason)


def budget(deadline_ns):
    require(type(deadline_ns) is int and 0 < deadline_ns - time.monotonic_ns() <= 1200 * 10**9, "deadline_exceeded")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode(data):
    def unique(pairs):
        value = {}
        for name, item in pairs:
            require(name not in value, "selection_invalid")
            value[name] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(InventoryError("selection_invalid")))
    except (UnicodeError, json.JSONDecodeError):
        raise InventoryError("selection_invalid") from None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def physical(path):
    # Nix writeText manifests are registered regular-file roots themselves.
    # The eleven runtime-input helper admits only descendants; this producer
    # also reads these exact canonical root objects with regular/immutable FD
    # checks in Capture, never arbitrary store-parent aliases.
    if type(path) is str and STORE.fullmatch(path):
        return
    try:
        custody.valid_path(path)
    except custody.InputError:
        raise InventoryError("selection_invalid") from None


def output_selector(path):
    physical(path)
    require(path.startswith("/srv/"), "output_unqualified")


class Capture:
    """Hold bounded physical regular bytes, with a capture-wide named witness."""
    def __init__(self, path, expected, maximum, deadline_ns, *, executable=False):
        self.path, self.deadline = Path(path), deadline_ns
        self.parent, self.fd = None, None
        physical(path)
        require(expected is None or type(expected) is str and custody.SHA.fullmatch(expected), "selection_invalid")
        try:
            budget(deadline_ns)
            self.parent = custody.open_parent(path, os.getuid(), deadline_ns, time.monotonic_ns)
            self.parent_identity = custody.directory_identity(os.fstat(self.parent))
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.parent)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
                    and info.st_nlink >= 1 and (not executable or info.st_mode & 0o111), "input_unqualified")
            if self.path.is_relative_to("/nix/store"):
                require(info.st_uid == 0 and not info.st_mode & 0o222, "input_unqualified")
            require(0 < info.st_size <= maximum, "byte_bound")
            self.identity = custody.witness(info)
            collected = bytearray()
            while True:
                budget(deadline_ns)
                chunk = os.read(self.fd, min(65536, maximum + 1 - len(collected)))
                if not chunk:
                    break
                collected.extend(chunk)
                require(len(collected) <= maximum, "byte_bound")
            self.data = bytes(collected)
            self.sha256 = digest(self.data)
            require(len(self.data) == info.st_size, "input_changed")
            require(expected is None or self.sha256 == expected, "digest_mismatch")
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        budget(self.deadline)
        named = custody.open_parent(str(self.path), os.getuid(), self.deadline, time.monotonic_ns)
        try:
            require(custody.directory_identity(os.fstat(self.parent)) == self.parent_identity
                    == custody.directory_identity(os.fstat(named)) and custody.witness(os.fstat(self.fd)) == self.identity
                    == custody.witness(os.stat(self.path.name, dir_fd=named, follow_symlinks=False)), "input_changed")
        finally:
            os.close(named)
        budget(self.deadline)

    def close(self):
        failed = False
        for field in ("fd", "parent"):
            descriptor = getattr(self, field)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        require(not failed, "cleanup_incomplete")


def store_root(path):
    require(type(path) is str and path.startswith("/nix/store/"), "selection_invalid")
    parts = Path(path).parts
    root = str(Path(*parts[:4]))
    require(STORE.fullmatch(root) and str(Path(path)) == path and not {".", ".."}.intersection(path.split("/"))
            and len(os.fsencode(path)) <= 4096 and not any(character.isspace() for character in path), "selection_invalid")
    return root


def selected(data):
    value = decode(data)
    require(type(value) is dict and set(value) == FIELDS and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and value["scope"] == "yoga-controller-inventory-selection-v1"
            and type(value["controllerTools"]) is dict and set(value["controllerTools"]) == TOOLS
            and type(value["wrapperSha256"]) is dict and set(value["wrapperSha256"]) == set(WRAPPERS), "selection_invalid")
    for sha in (value["nativeManifestSha256"], value["bootstrapManifestSha256"], *value["wrapperSha256"].values()):
        require(type(sha) is str and custody.SHA.fullmatch(sha), "selection_invalid")
    for name, path in value["controllerTools"].items():
        root = store_root(path)
        require(name not in ("closure", "bootstrap_closure", "zig_sdk", "java_home") or path == root, "selection_invalid")
    return value


def manifests(native, bootstrap, selection):
    for manifest in (native, bootstrap):
        require(type(manifest) is dict and manifest.get("system") == "x86_64-linux"
                and type(manifest.get("packages")) is dict and type(manifest.get("tools")) is dict, "manifest_mismatch")
    tools = selection["controllerTools"]
    try:
        bash = native["packages"]["bash"]["out"] + "/bin/bash"
        require(STORE.fullmatch(native["packages"]["bash"]["out"]), "manifest_mismatch")
        require(store_root(tools["python"]) == bootstrap["packages"]["python"]["out"]
                and tools["java_home"] == native["packages"]["bazel_jdk"]["out"]
                and tools["systemctl"] == native["tools"]["systemctl"]
                and tools["systemd_run"] == store_root(native["tools"]["systemctl"]) + "/bin/systemd-run", "manifest_mismatch")
        backends = {}
        for name, (key, basename) in WRAPPERS.items():
            backend = native["tools"][key]
            require(backend == store_root(backend) + "/bin/" + basename, "manifest_mismatch")
            backends[name] = backend
        require(store_root(backends["dbus_session"]) == store_root(backends["dbus_daemon"])
                == native["packages"]["dbus"]["out"]
                and store_root(backends["keyring"]) == native["packages"]["gnome_keyring"]["out"], "manifest_mismatch")
    except (KeyError, TypeError):
        raise InventoryError("manifest_mismatch") from None
    roots = sorted({store_root(path) for path in tools.values()} | {store_root(path) for path in backends.values()})
    return roots, bash, backends


def store_observation(path, deadline_ns):
    """Inspect one registered root without following any link target."""
    require(STORE.fullmatch(path), "registry_invalid")
    budget(deadline_ns)
    parent = custody.open_parent(path, os.getuid(), deadline_ns, time.monotonic_ns)
    try:
        info = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        require(info.st_uid == 0 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode))
                and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o222), "registry_invalid")
        text = os.readlink(Path(path).name, dir_fd=parent) if stat.S_ISLNK(info.st_mode) else None
        require(text is None or len(os.fsencode(text)) <= 65536, "byte_bound")
        result = (custody.witness(info), text)
    finally:
        os.close(parent)
    budget(deadline_ns)
    return result


def inventory(rows, roots, input_sha256):
    require(type(roots) is list and 1 <= len(roots) <= len(TOOLS) + len(WRAPPERS)
            and all(type(root) is str and STORE.fullmatch(root) for root in roots) and roots == sorted(set(roots)), "registry_invalid")
    require(type(rows) is list and 1 <= len(rows) <= MAX_PATHS
            and all(type(row) is dict and type(row.get("path")) is str for row in rows)
            and rows == sorted(rows, key=lambda row: row["path"]), "registry_invalid")
    edges, total = 0, 0
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "narHash", "narSize", "references"}
                and type(row["narSize"]) is int and row["narSize"] > 0
                and type(row["references"]) is list and all(type(ref) is str and STORE.fullmatch(ref) for ref in row["references"])
                and row["references"] == sorted(set(row["references"])), "registry_invalid")
        edges += len(row["references"])
        total += row["narSize"]
        require(edges <= MAX_REFS and total <= MAX_BYTES, "byte_bound")
    value = {"schemaVersion": 1, "system": "x86_64-linux", "mode": "local-sqlite-readonly-snapshot", "roots": roots,
             "paths": rows, "provenance": {"rootsSha256": digest(canonical(roots)), "inputSha256": input_sha256},
             "contentRehashed": False, "realized": False, "published": False}
    data = canonical(value) + b"\n"
    require(len(data) <= MAX_INPUT, "byte_bound")
    try:
        parsed = parse_inventory(data, digest(data))
    except (ValueError, KeyError, TypeError):
        raise InventoryError("registry_invalid") from None
    graph = {row["path"]: row["references"] for row in parsed}
    reachable, pending = set(), list(roots)
    while pending:
        path = pending.pop()
        require(path in graph, "registry_invalid")
        if path not in reachable:
            reachable.add(path)
            pending.extend(graph[path])
    require(reachable == set(graph), "registry_invalid")
    return value, data


def registered_manifest(root, expected, rows, captures, deadline_ns):
    """Read only the native.json direct registered-file reference, never an alias chain."""
    path = root + "/native.json"
    parent = custody.open_parent(path, os.getuid(), deadline_ns, time.monotonic_ns)
    try:
        first = custody.witness(os.stat("native.json", dir_fd=parent, follow_symlinks=False))
        require(stat.S_ISLNK(first[2]) and first[3] == 0, "manifest_mismatch")
        target = os.readlink("native.json", dir_fd=parent)
        require(STORE.fullmatch(target) and target in rows and target in rows[root]["references"], "manifest_mismatch")
        source = Capture(target, None, MAX_MANIFEST, deadline_ns)
        captures.append(source)
        require(decode(source.data) == expected, "manifest_mismatch")
        require(first == custody.witness(os.stat("native.json", dir_fd=parent, follow_symlinks=False))
                and target == os.readlink("native.json", dir_fd=parent), "input_changed")
        return {"registeredObject": target, "registeredManifestSha256": source.sha256}
    finally:
        os.close(parent)


class Output:
    """Publish an exclusive private pair; roll back only recorded owned inodes."""
    def __init__(self, path, deadline_ns, cleanup_deadline_ns):
        self.path, self.deadline, self.cleanup_deadline = Path(path), deadline_ns, cleanup_deadline_ns
        self.parent, self.fd, self.identity = None, None, None
        self.created, self.files = False, {}
        output_selector(path)
        try:
            budget(deadline_ns)
            self.parent = custody.open_parent(path, os.getuid(), deadline_ns, time.monotonic_ns)
            parent_info = os.fstat(self.parent)
            require(parent_info.st_uid == os.getuid() and not parent_info.st_mode & 0o022, "output_unqualified")
            self.parent_identity = custody.directory_identity(parent_info)
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent)
            self.created = True
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            self.identity = custody.directory_identity(os.fstat(self.fd))
            require(self.identity[2] == os.getuid() and stat.S_IMODE(self.identity[3]) == 0o700, "output_unqualified")
            self.check(); os.fsync(self.parent)
        except BaseException:
            try:
                self.rollback()
            finally:
                self.close()
            raise

    def check(self, *, cleanup=False):
        until = self.cleanup_deadline if cleanup else self.deadline
        budget(until)
        require(self.identity is not None, "output_unqualified")
        named = custody.open_parent(str(self.path), os.getuid(), until, time.monotonic_ns)
        try:
            require(custody.directory_identity(os.fstat(named)) == self.parent_identity
                    == custody.directory_identity(os.fstat(self.parent)) and custody.directory_identity(os.fstat(self.fd)) == self.identity
                    == custody.directory_identity(os.stat(self.path.name, dir_fd=named, follow_symlinks=False)), "output_unqualified")
        finally:
            os.close(named)

    def write(self, name, data):
        require(name in ("controller-inventory.json", "controller-evidence.json") and name not in self.files
                and type(data) is bytes and 0 < len(data) <= MAX_INPUT, "output_unqualified")
        self.check()
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        self.files[name] = None
        try:
            first = os.fstat(descriptor)
            self.files[name] = custody.witness(first)
            offset = 0
            while offset < len(data):
                budget(self.deadline)
                count = os.write(descriptor, data[offset:offset + 65536])
                require(count > 0, "output_unqualified")
                offset += count
            os.fsync(descriptor)
            final = os.fstat(descriptor)
            require(stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid() and stat.S_IMODE(final.st_mode) == 0o600
                    and final.st_nlink == 1 and final.st_size == len(data) and (first.st_dev, first.st_ino) == (final.st_dev, final.st_ino), "output_unqualified")
            self.files[name] = custody.witness(final)
            require(custody.witness(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == self.files[name], "output_unqualified")
            os.fsync(self.fd)
        finally:
            os.close(descriptor)

    def complete(self, expected):
        self.check()
        require(set(self.files) == set(expected), "output_unqualified")
        def layout():
            with os.scandir(self.fd) as entries:
                remaining = set(expected)
                for entry in entries:
                    budget(self.deadline)
                    require(entry.name in remaining, "output_unqualified")
                    remaining.remove(entry.name)
                require(not remaining, "output_unqualified")
        layout()
        captured = []
        try:
            for name, sha in expected.items():
                source = Capture(str(self.path / name), sha, MAX_INPUT, self.deadline)
                captured.append(source)
                require(source.identity == self.files[name], "output_unqualified")
            for source in captured:
                source.check()
            layout()
            self.check(); os.fsync(self.fd); os.fsync(self.parent); budget(self.deadline)
        finally:
            close_captures(captured)

    def rollback(self):
        if not self.created:
            return
        require(self.fd is not None and self.identity is not None, "cleanup_incomplete")
        budget(self.cleanup_deadline)
        for name, identity in self.files.items():
            require(identity is not None, "cleanup_incomplete")
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and (info.st_dev, info.st_ino) == identity[:2], "cleanup_incomplete")
            os.unlink(name, dir_fd=self.fd); os.fsync(self.fd)
        self.check(cleanup=True)
        with os.scandir(self.fd) as entries:
            require(next(entries, None) is None, "cleanup_incomplete")
        os.rmdir(self.path.name, dir_fd=self.parent); os.fsync(self.parent)

    def close(self):
        failed = False
        for field in ("fd", "parent"):
            descriptor = getattr(self, field)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        require(not failed, "cleanup_incomplete")


def close_captures(captures):
    failed = False
    for source in reversed(captures):
        try:
            source.close()
        except BaseException:
            failed = True
    require(not failed, "cleanup_incomplete")


def produce_inventory(selection_path, selection_sha256, native_manifest, bootstrap_manifest, wrapper_paths,
                      output, deadline_ns, *, snapshotter=snapshot_inventory, observer=store_observation):
    budget(deadline_ns)
    until = deadline_ns - CLEANUP_NS
    budget(until)
    require(type(selection_sha256) is str and custody.SHA.fullmatch(selection_sha256)
            and type(wrapper_paths) is dict and set(wrapper_paths) == set(WRAPPERS), "selection_invalid")
    captures, published = [], None
    def capture(path, expected, maximum, **kwargs):
        source = Capture(path, expected, maximum, until, **kwargs)
        captures.append(source)
        return source
    try:
        picked = capture(selection_path, selection_sha256, MAX_SELECTION)
        selection = selected(picked.data)
        native = capture(native_manifest, selection["nativeManifestSha256"], MAX_MANIFEST)
        bootstrap = capture(bootstrap_manifest, selection["bootstrapManifestSha256"], MAX_MANIFEST)
        native_data, bootstrap_data = decode(native.data), decode(bootstrap.data)
        roots, shell, backends = manifests(native_data, bootstrap_data, selection)
        wrappers = {}
        for name, (key, _) in WRAPPERS.items():
            source = capture(wrapper_paths[name], selection["wrapperSha256"][name], MAX_WRAPPER, executable=True)
            require(source.path == native.path.parent / "tool_wrappers" / key, "wrapper_mismatch")
            expected = ('#!' + shell + '\nset -eu\nexec \'' + backends[name] + '\' "$@"\n').encode("ascii")
            require(source.data == expected, "wrapper_mismatch")
            wrappers[name] = {"sha256": source.sha256, "backend": backends[name], "backendRoot": store_root(backends[name]),
                              "interpreter": shell, "abi": "omux-native-capability-wrapper-v1"}
        def snapshot():
            require(until - time.monotonic_ns() > SNAPSHOT_NS, "deadline_exceeded")
            def exists(path):
                observer(path, until)
                return True
            result = snapshotter(DATABASE, roots, exists=exists)
            budget(until)
            return result
        rows = snapshot()
        shas = {"selection": picked.sha256, "native_manifest": native.sha256, "bootstrap_manifest": bootstrap.sha256,
                **{"wrapper/" + name: facts["sha256"] for name, facts in wrappers.items()}}
        value, encoded = inventory(rows, roots, shas)
        by_path = {row["path"]: row for row in rows}
        require(store_root(shell) in by_path, "registry_invalid")
        observed = {path: observer(path, until) for path in by_path}
        native_binding = registered_manifest(selection["controllerTools"]["closure"], native_data, by_path, captures, until)
        bootstrap_binding = registered_manifest(selection["controllerTools"]["bootstrap_closure"], bootstrap_data, by_path, captures, until)
        def refresh():
            for source in captures:
                source.check()
            require(all(observer(path, until) == initial for path, initial in observed.items()), "registry_changed")
            require(snapshot() == rows, "registry_changed")
            budget(until)
        refresh()
        report = {"schemaVersion": 1, "scope": "yoga-controller-registry-and-wrapper-v1", "selectionSha256": picked.sha256,
                  "inventorySha256": digest(encoded), "controllerTools": selection["controllerTools"],
                  "nativeManifest": dict(native_binding, sha256=native.sha256),
                  "bootstrapManifest": dict(bootstrap_binding, sha256=bootstrap.sha256), "wrappers": wrappers,
                  "rootCount": len(roots), "registeredPaths": len(rows), "registeredNarBytes": sum(row["narSize"] for row in rows),
                  "deadlineMonotonicNs": deadline_ns, "registrySnapshotVerified": True, "selectedInputBytesVerified": True,
                  "contentRehashed": False, "wrapperExecuted": False, "backendExecuted": False,
                  "executionAuthority": False, "destinationRegistrationVerified": False, "realized": False}
        report_bytes = canonical(report) + b"\n"
        published = Output(output, until, deadline_ns)
        published.write("controller-inventory.json", encoded)
        published.write("controller-evidence.json", report_bytes)
        refresh()
        published.complete({"controller-inventory.json": digest(encoded), "controller-evidence.json": digest(report_bytes)})
        return {"scope": "yoga-controller-inventory-produced", "inventorySha256": digest(encoded), "receiptSha256": digest(report_bytes),
                "rootCount": len(roots), "registeredPaths": len(rows), "contentRehashed": False,
                "executionAuthority": False, "destinationRegistrationVerified": False, "realized": False}
    except BaseException:
        if published is not None:
            try:
                published.rollback()
            except BaseException:
                raise InventoryError("cleanup_incomplete") from None
        raise
    finally:
        try:
            if published is not None:
                published.close()
        finally:
            close_captures(captures)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InventoryError("selection_invalid")


def main():
    parser = Parser(description=__doc__)
    for name in ("selection", "selection-sha256", "native-manifest", "bootstrap-manifest", "dbus-session", "dbus-daemon", "keyring"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output")
    parser.add_argument("--seconds", type=int, default=120)
    args = parser.parse_args()
    require(type(args.seconds) is int and 1 <= args.seconds <= 600, "selection_invalid")
    deadline_ns = time.monotonic_ns() + args.seconds * 10**9
    guarded = os.environ.get("OMUX_EXECUTION_GUARD")
    require(type(guarded) is str and guarded.startswith("/srv/"), "selection_invalid")
    physical(guarded)
    output = args.output
    if output is None:
        declared = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
        require(type(declared) is str and declared.startswith("/"), "selection_invalid")
        physical(declared)
        # This is the one declared Bazel output namespace; input aliases and
        # selected executable paths remain unresolved throughout this producer.
        output = str(Path(declared).resolve(strict=True) / "yoga-controller-inputs")
        output_selector(output)
    budget(deadline_ns)
    result = produce_inventory(args.selection, args.selection_sha256, args.native_manifest, args.bootstrap_manifest,
                               {"dbus_session": args.dbus_session, "dbus_daemon": args.dbus_daemon, "keyring": args.keyring},
                               output, deadline_ns)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"scope": "yoga-controller-inventory-refused", "reason": error.reason if isinstance(error, InventoryError) else "registry_invalid",
                          "executionAuthority": False, "destinationRegistrationVerified": False, "realized": False}), file=sys.stderr)
        sys.exit(125)
