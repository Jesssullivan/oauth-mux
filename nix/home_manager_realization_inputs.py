"""Complete declared Linux closure content and private registration, never activation.

The selected derivation is an input, not evidence that HM generated it. A later
generation action must independently join its actual HM evaluation and output.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

# Only sibling runfiles declared by this target; no source-tree fallback.
sys.path.insert(0, str(Path(__file__).absolute().parent.parent / "tools"))

import nar_descriptor as nar
import nix_private_store_seed as seed
import nix_private_store_qualification as private
from nix_interpreter_closure import reachable, registrations
from home_manager_inputs import PINS

KIND = "omux-linux-hm-realization-input-closure-v1"
MAX_ROOTS = 4096
MODULES = ("consume-bazel-artifact.nix", "home-manager.nix", "ownership-witness.nix", "service-witness.nix")


def require(value):
    if value is not True:
        raise ValueError("linux-hm-realization-inputs-refused")


def digest(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None)
    return value


def store(value):
    require(type(value) is str and re.fullmatch(seed.STORE, value) is not None)
    return value


def sri(value):
    import base64
    require(type(value) is str and re.fullmatch("sha256-[A-Za-z0-9+/]{43}=", value) is not None)
    return base64.b64decode(value[7:], validate=True).hex()


def shape(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "kind", "system", "sourceCommit",
            "sourceGraphSha256", "moduleSha256", "roles", "roots", "registration", "descriptors", "files",
        "artifact", "pair", "physicalRoots"} and value["schemaVersion"] == 1 and type(value["schemaVersion"]) is int
        and value["kind"] == KIND and value["system"] == "x86_64-linux")
    require(type(value["sourceCommit"]) is str and re.fullmatch("[0-9a-f]{40}", value["sourceCommit"]) is not None)
    digest(value["sourceGraphSha256"])
    require(type(value["moduleSha256"]) is dict and set(value["moduleSha256"]) == set(MODULES))
    for pin in value["moduleSha256"].values(): digest(pin)
    roots = value["roots"]
    require(type(roots) is list and 0 < len(roots) <= MAX_ROOTS and roots == sorted(set(roots)))
    for root in roots: store(root)
    require(type(value["registration"]) is str and len(value["registration"].encode("ascii")) <= 4*1024**2)
    records = registrations(value["registration"], roots)
    roles = value["roles"]
    require(type(roles) is dict and set(roles) == {"home-manager", "nixpkgs", "artifact", "derivation", "bash", "nix", "nix_store"})
    for name in ("home-manager", "nixpkgs", "artifact", "derivation"):
        require(store(roles[name]) in records)
    require(roles["derivation"].endswith(".drv"))
    for name, suffix in (("bash", "/bin/bash"), ("nix", "/bin/nix"), ("nix_store", "/bin/nix-store")):
        require(type(roles[name]) is str and roles[name].endswith(suffix))
        store(roles[name][:-len(suffix)])
    require(roles["nix_store"] == roles["nix"] + "-store")
    selected = [roles[name] for name in ("home-manager", "nixpkgs", "artifact", "derivation")]
    selected += [roles[name].rsplit("/bin/", 1)[0] for name in ("bash", "nix")]
    require(reachable(records, selected) == roots)
    require(type(value["descriptors"]) is dict and set(value["descriptors"]) == set(roots))
    require(type(value["physicalRoots"]) is dict and set(value["physicalRoots"]) == set(roots))
    for path in value["physicalRoots"].values():
        require(type(path) is str and len(path) <= 4096 and Path(path).is_absolute() and path != "/"
            and not any(part in ("", ".", "..") for part in path.split("/")[1:])
            and not any(character.isspace() or character in "\0:" for character in path))
    expected = []
    total = 0
    entries = 0
    for root in roots:
        description = value["descriptors"][root]
        require(description["root"] == root and type(description["schemaVersion"]) is int
            and description["schemaVersion"] == 1)
        nar.validate_descriptor(description)
        require(description["nodes"] == sorted(description["nodes"], key=lambda row: os.fsencode(row["path"])))
        entries += len(description["nodes"])
        require(entries <= seed.MAX_FILES)
        for node in description["nodes"]:
            if node["type"] == "regular":
                total += node["size"]
                expected.append({"root": root, "path": node["path"], "alias": "members/" + str(len(expected)),
                    "source": value["physicalRoots"][root] + ("/" + node["path"] if node["path"] else "")})
        seed.expected_hash(records[root]["record"][1])
    require(0 < len(expected) <= seed.MAX_FILES and total <= seed.MAX_BYTES and value["files"] == expected)
    for name in ("bash", "nix", "nix_store"):
        seed.resolve_member(value, roles[name])
    require(type(value["pair"]) is dict and set(value["pair"]) == {"home-manager", "nixpkgs"})
    for name in value["pair"]:
        row = value["pair"][name]
        require(type(row) is dict and set(row) == {"revision", "narHash"}
            and (row["revision"], row["narHash"]) == PINS[name]
            and seed.expected_hash(records[roles[name]]["record"][1]) == sri(row["narHash"]))
    artifact = value["artifact"]
    require(type(artifact) is dict and set(artifact) == {"narHash", "manifestSha256", "sourceRevision", "channel"}
        and artifact["sourceRevision"] == value["sourceCommit"] and artifact["channel"] in ("development", "release")
        and seed.expected_hash(records[roles["artifact"]]["record"][1]) == sri(artifact["narHash"]))
    digest(artifact["manifestSha256"])
    require(value["descriptors"][roles["derivation"]]["nodes"][0]["path"] == ""
        and value["descriptors"][roles["derivation"]]["nodes"][0]["type"] == "regular")
    return records


def locked_tools(value, selected):
    """The existing pinned bootstrap seed selects tools, not the caller layout.

    Every selected runtime root remains a declared full member/NAR obligation.
    Canonical host locations are required for the immutable ELF loader/reference
    closure. Relocated HM/artifact inputs remain inert until a later build gate.
    """
    original = seed.validate(selected)
    records = shape(value)
    require(selected["tools"] == {name: value["roles"][name] for name in ("bash", "nix", "nix_store")})
    for root in selected["roots"]:
        require(root in records and value["physicalRoots"][root] == root
            and seed.encoded(value["descriptors"][root]) == seed.encoded(selected["descriptors"][root]))
        private.compare_readback({root: original[root]}, {root: records[root]})
    return seed.sha(seed.encoded(selected))


def facts(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def alias_facts(path):
    path = Path(path).absolute()
    require(len(path.parts) <= 256)
    rows = []
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        require(info.st_uid in (0, os.getuid()) and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022 or
            stat.S_ISDIR(info.st_mode) and bool(info.st_mode & stat.S_ISVTX)))
        rows.append((str(current), facts(info) if not stat.S_ISDIR(info.st_mode) else facts(info)[:5],
                     os.readlink(current) if stat.S_ISLNK(info.st_mode) else None))
    return str(path.resolve(strict=True)), tuple(rows)


class RegularReader:
    """Preallocated borrowed regular FD owner; no fdopen allocation after open."""
    __slots__ = ("fd", "parent", "child", "old", "deadline")
    def __init__(self, deadline):
        self.fd = self.parent = self.child = self.old = None
        self.deadline = deadline
    def fileno(self):
        require(self.fd is not None)
        return self.fd
    def read(self, bound):
        require(type(bound) is int and 0 <= bound <= seed.MAX_METADATA + 1)
        result = bytearray()
        while len(result) < bound:
            private.tick(self.deadline)
            block = os.read(self.fileno(), min(65536, bound - len(result)))
            require(type(block) is bytes and len(block) <= bound - len(result))
            if not block: break
            result.extend(block)
        private.tick(self.deadline)
        return bytes(result)


@contextmanager
def regular(path, deadline):
    path = Path(path)
    require(path.is_absolute() and 1 < len(path.parts) <= 256 and
        not any(part in (".", "..") for part in path.parts))
    reader = RegularReader(deadline)
    private.tick(deadline)
    failure = None
    cleanup = None
    try:
        reader.parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for name in path.parts[1:-1]:
            reader.child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=reader.parent)
            reader.old = reader.parent
            reader.parent = reader.child
            reader.child = None
            closing, reader.old = reader.old, None
            os.close(closing)  # Detached old parent; the new parent is already owned.
        reader.fd = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=reader.parent)
        # Initial fstat is inside leaf ownership, not inside an unowned wrapper.
        require(stat.S_ISREG(os.fstat(reader.fd).st_mode))
        closing, reader.parent = reader.parent, None
        os.close(closing)
        yield reader
    except BaseException as error:
        failure = error
        raise
    finally:
        # Transfer interruption may leave two slots for one original FD.
        # Collapse only equal numeric handles, before any detach or close.
        if reader.child == reader.fd: reader.child = None
        if reader.parent == reader.fd or reader.parent == reader.child: reader.parent = None
        if reader.old == reader.fd or reader.old == reader.child or reader.old == reader.parent: reader.old = None
        # Direct detach/attempt-all; no cleanup inventory allocation or retry.
        closing, reader.fd = reader.fd, None
        if closing is not None:
            try: os.close(closing)
            except BaseException as error: cleanup = error
        closing, reader.child = reader.child, None
        if closing is not None:
            try: os.close(closing)
            except BaseException as error:
                if cleanup is None: cleanup = error
        closing, reader.parent = reader.parent, None
        if closing is not None:
            try: os.close(closing)
            except BaseException as error:
                if cleanup is None: cleanup = error
        closing, reader.old = reader.old, None
        if closing is not None:
            try: os.close(closing)
            except BaseException as error:
                if cleanup is None: cleanup = error
        if cleanup is not None:
            if failure is not None: raise failure from cleanup
            raise cleanup


def raw_metadata(path, bound, deadline, *, proc_status=False):
    private.tick(deadline)
    with regular(path, deadline) as stream:
        before = facts(os.fstat(stream.fileno()))
        require(type(proc_status) is bool and (proc_status is False or
            str(path) == "/proc/" + str(os.getpid()) + "/status" and before[6] == 0))
        require(proc_status or 0 <= before[6] <= bound)
        raw = stream.read(bound + 1)
        require(proc_status or len(raw) == before[6])
        require(len(raw) <= bound and before == facts(os.fstat(stream.fileno())) == facts(Path(path).lstat()))
    private.tick(deadline)
    return raw


def control_capture(path):
    alias = alias_facts(path)
    physical = alias_facts(alias[0])
    require(physical[0] == alias[0])
    return alias, physical


def control_check(path, captured):
    alias, physical = captured
    require(alias_facts(path) == alias and alias_facts(alias[0]) == physical)


def control_read(path, bound, captured, deadline):
    control_check(path, captured)
    raw = raw_metadata(captured[0][0], bound, deadline)
    control_check(path, captured)
    return raw


class Inputs:
    """Only exact declared regular aliases; full NAR pins bind inert links."""
    def __init__(self, value, base, deadline):
        self.value, self.base, self.deadline = value, Path(base), deadline
        self.mapping = {(row["root"], row["path"]): (self.base / row["alias"], row["source"]) for row in value["files"]}
        self.nodes = {(root, row["path"]): row for root, description in value["descriptors"].items()
                      for row in description["nodes"] if row["type"] == "regular"}
        self.observed = {}

    @contextmanager
    def open(self, root, relative):
        private.tick(self.deadline)
        require((root, relative) in self.mapping)
        alias, expected = self.mapping[(root, relative)]
        captured = alias_facts(alias)
        require(captured[0] == expected)
        physical_before = alias_facts(captured[0])
        with regular(captured[0], self.deadline) as stream:
            before = facts(os.fstat(stream.fileno()))
            node = self.nodes[(root, relative)]
            require(stat.S_ISREG(before[4]) and before[2] in (0, os.getuid()) and not before[4] & 0o222
                and before[5] >= 1 and before[6] == node["size"] <= seed.MAX_BYTES
                and bool(before[4] & stat.S_IXUSR) == node["executable"]
                and facts(Path(captured[0]).lstat()) == before)
            selected = (captured, physical_before, before)
            require((root, relative) not in self.observed or self.observed[(root, relative)] == selected)
            self.observed[(root, relative)] = selected
            yield stream
            private.tick(self.deadline)
            require(facts(os.fstat(stream.fileno())) == before == facts(Path(captured[0]).lstat())
                and alias_facts(alias) == captured and alias_facts(captured[0]) == physical_before)

    def check(self):
        require(set(self.observed) == set(self.mapping))
        for key, (captured, physical_before, before) in self.observed.items():
            private.tick(self.deadline)
            require(alias_facts(self.mapping[key][0]) == captured and alias_facts(captured[0]) == physical_before
                and facts(Path(captured[0]).lstat()) == before)
        private.tick(self.deadline)


def verify(value, opener, deadline):
    records = shape(value)
    size = 0
    for root in value["roots"]:
        private.tick(deadline)
        result = nar.hash_descriptor(value["descriptors"][root], opener=opener, deadline=deadline)
        row = records[root]["record"]
        require(result["narHash"] == "sha256:" + seed.expected_hash(row[1]) and result["narSize"] == int(row[2]))
        size += result["narSize"]
        require(size <= seed.MAX_BYTES)
    private.tick(deadline)
    return records, size


def artifact_bytes(value, opener, deadline):
    root = value["roles"]["artifact"]
    with opener(root, "release-manifest.json") as source:
        raw = source.read(65537)
    nodes = {node["path"]: node for node in value["descriptors"][root]["nodes"]}
    require(0 < len(raw) == nodes["release-manifest.json"]["size"] <= 65536
        and seed.sha(raw) == value["artifact"]["manifestSha256"])
    manifest = json.loads(raw, object_pairs_hook=seed.unique)
    require(type(manifest) is dict and manifest["schemaVersion"] == 1 and manifest["target"] == "x86_64-linux"
        and manifest["distribution"] == "portable-linux" and manifest["product"]["status"] == "experimental"
        and manifest["channel"] == value["artifact"]["channel"]
        and manifest["provenance"]["sourceRevision"] == value["sourceCommit"]
        and type(manifest["provenance"]["sourceDirty"]) is bool
        and (manifest["channel"] == "development" or manifest["provenance"]["sourceDirty"] is False))
    rows = manifest["artifacts"]
    require(type(rows) is list and 0 < len(rows) <= 256)
    seen = set()
    for row in rows:
        private.tick(deadline)
        name = row["path"]; nar.relative_name(name)
        require(name != "" and name not in seen and row["mode"] in ("0644", "0755")
            and type(row["size"]) is int and 0 <= row["size"] <= seed.MAX_BYTES)
        seen.add(name); digest(row["sha256"])
        nodes = {node["path"]: node for node in value["descriptors"][root]["nodes"]}
        require(name in nodes and nodes[name]["type"] == "regular"
            and nodes[name]["executable"] == (row["mode"] == "0755") and nodes[name]["size"] == row["size"])
        total = 0; hashed = hashlib.sha256()
        with opener(root, name) as source:
            while True:
                private.tick(deadline); block = source.read(65536)
                if not block: break
                total += len(block); require(total <= row["size"]); hashed.update(block)
        require(total == row["size"] and hashed.hexdigest() == row["sha256"])
    require({"bin/omux", "bin/omuxd", "bin/omux-native-host", "bin/omux-control"} <= seen)
    private.tick(deadline)


def copy(value, private_root, opener, deadline):
    destination = private_root / "nix/store"
    destination.mkdir(parents=True, mode=0o755)
    for root in value["roots"]:
        nodes = value["descriptors"][root]["nodes"]
        for row in sorted(nodes, key=lambda item: (len(item["path"].split("/")) if item["path"] else 0, item["path"])):
            private.tick(deadline)
            path = destination / root.rsplit("/", 1)[1]
            if row["path"]: path /= row["path"]
            if row["type"] == "directory": path.mkdir(mode=0o755)
            elif row["type"] == "symlink": path.symlink_to(row["target"])
            else:
                descriptor = None
                failure = None
                try:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with opener(root, row["path"]) as source:
                        remaining = row["size"]
                        while remaining:
                            private.tick(deadline)
                            block = source.read(min(65536, remaining))
                            require(type(block) is bytes and 0 < len(block) <= remaining)
                            offset = 0
                            while offset < len(block):
                                private.tick(deadline)
                                written = os.write(descriptor, block[offset:]); require(written > 0); offset += written
                            remaining -= len(block)
                        require(source.read(1) == b"")
                    os.fchmod(descriptor, 0o555 if row["executable"] else 0o444)
                    os.fsync(descriptor)
                except BaseException as error:
                    failure = error
                    raise
                finally:
                    if descriptor is not None:
                        closing, descriptor = descriptor, None
                        try: os.close(closing)
                        except BaseException as cleanup:
                            if failure is not None: raise failure from cleanup
                            raise
        for row in sorted(nodes, key=lambda item: len(item["path"]), reverse=True):
            if row["type"] == "directory":
                path = destination / root.rsplit("/", 1)[1]
                if row["path"]: path /= row["path"]
                path.chmod(0o555)
    return destination


def copied_opener(directory, deadline):
    return lambda root, relative: regular(directory / root.rsplit("/", 1)[1] / relative, deadline)


def copy_facts(value, directory, deadline):
    captured = {}
    for root in value["roots"]:
        destination = directory / root.rsplit("/", 1)[1]
        actual = nar.describe(destination); actual["root"] = root
        require(seed.encoded(actual) == seed.encoded(value["descriptors"][root]))
        for row in actual["nodes"]:
            private.tick(deadline)
            path = destination / row["path"] if row["path"] else destination
            info = path.lstat()
            require(info.st_uid == os.getuid())
            mode = stat.S_IMODE(info.st_mode)
            require((row["type"] == "directory" and mode == 0o555) or
                (row["type"] == "symlink" and info.st_nlink == 1) or
                (row["type"] == "regular" and info.st_nlink == 1 and mode == (0o555 if row["executable"] else 0o444)))
            captured[str(path)] = facts(info)
    private.tick(deadline)
    return captured


def verify_copy(value, directory, deadline, expected=None):
    before = copy_facts(value, directory, deadline)
    require(expected is None or before == expected)
    for root in value["roots"]:
        private.tick(deadline)
        actual = nar.describe(directory / root.rsplit("/", 1)[1])
        actual["root"] = root
        require(seed.encoded(actual) == seed.encoded(value["descriptors"][root]))
    result = verify(value, copied_opener(directory, deadline), deadline)
    require(copy_facts(value, directory, deadline) == before)
    return result


def registration_commands(tools, private_root):
    # Existing pinned private-store ABI; no build command in this stage.
    return (private.common(tools["nix_store"], private_root) + ["--load-db"],
            private.common(tools["nix_store"], private_root) + ["--dump-db"])


def qualify(value, base, parent, deadline, *, runner=private.run):
    records = shape(value)
    inputs = Inputs(value, base, deadline)
    records, size = verify(value, inputs.open, deadline)
    artifact_bytes(value, inputs.open, deadline)
    inputs.check()
    owned = private.OwnedRoot(parent)
    failure = None
    try:
        owned.recheck()
        free = os.statvfs(owned.path)
        require(free.f_bavail * free.f_frsize >= 2 * size + private.FREE_FLOOR)
        for name in ("private-store", "home", "config", "tmp"): (owned.path / name).mkdir(mode=0o700)
        private_root = owned.path / "private-store"
        directory = copy(value, private_root, inputs.open, deadline)
        copied = copy_facts(value, directory, deadline)
        require(verify_copy(value, directory, deadline, copied)[1] == size)
        inputs.check(); owned.recheck()
        registration = owned.path / "registration"
        registration.write_bytes(value["registration"].encode("ascii")); registration.chmod(0o400)
        tools = {name: value["roles"][name] for name in ("bash", "nix", "nix_store")}
        canonical = seed.resolve_member(value, tools["nix_store"])
        root, relative = canonical[:canonical.index("/", len("/nix/store/"))], canonical[canonical.index("/", len("/nix/store/"))+1:]
        commands = registration_commands(tools, private_root)
        with inputs.open(root, relative) as tool, regular(registration, deadline) as wire:
            require(runner(commands[0], private.environment(owned.path), owned.path, deadline,
                input_file=wire, tool_fd=tool.fileno()) == b"")
            dumped = runner(commands[1], private.environment(owned.path), owned.path, deadline, tool_fd=tool.fileno())
        actual = private.readback_records(dumped, value["roots"])
        private.compare_readback(records, actual)
        require(verify_copy(value, directory, deadline, copied)[1] == size)
        require(verify(value, inputs.open, deadline)[1] == size)
        artifact_bytes(value, inputs.open, deadline)
        inputs.check(); owned.recheck()
        require(copy_facts(value, directory, deadline) == copied)
        private.tick(deadline)
        result = {"schemaVersion": 1, "kind": KIND, "scope": "complete-input-content-and-isolated-registration-only",
            "inputSourceCommit": value["sourceCommit"], "inputSourceGraphSha256": value["sourceGraphSha256"],
            "inputSha256": seed.sha(seed.encoded(value)), "rootCount": len(records), "regularCount": len(value["files"]),
            "narBytes": size, "registrationReadback": "exact", "historicalPhysicalCustodyInherited": False,
            "homeManagerDerivationQualified": False, "generationRealized": False, "activated": False,
            "updated": False, "removed": False, "serviceReady": False, "browserInstalled": False}
    except BaseException as error:
        failure = error
        raise
    finally:
        try: owned.close(deadline + private.CLEANUP_SECONDS)
        except BaseException as cleanup:
            if failure is not None: raise failure from cleanup
            raise
    require(not os.path.lexists(owned.path)); inputs.check(); private.tick(deadline)
    result["privateRootRemoved"] = True
    return result, inputs


def consumer_context(environment, expected=None):
    source = environment.get("OMUX_HM_REALIZATION_SOURCE_COMMIT")
    graph = environment.get("OMUX_HM_REALIZATION_GRAPH_SHA256")
    require(type(source) is str and re.fullmatch("[0-9a-f]{40}", source) is not None)
    digest(graph)
    current = {"sourceCommit": source, "sourceGraphSha256": graph}
    require(expected is None or current == expected)
    return current


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    parser.add_argument("--layout", required=True)
    parser.add_argument("--module", action="append", required=True)
    parser.add_argument("--locked-seed", required=True)
    args = parser.parse_args()
    from guard_native_seed_plan_reserved import envelope, remaining
    entry = int(os.environ["OMUX_HM_ROOT_ENTRY_NS"]); end = int(os.environ["OMUX_HM_ROOT_DEADLINE_NS"])
    require(os.environ["OMUX_HM_RESERVED_PROFILE"] == "home-manager-realization-inputs-reserved")
    remaining(entry, end); until_ns = envelope(entry, end)
    deadline = float(min(until_ns / 1e9, time.monotonic() + private.MAX_SECONDS))
    controls = {path: control_capture(path) for path in (args.selection, args.layout, args.locked_seed)}
    raw = control_read(args.selection, 65536, controls[args.selection], deadline)
    selected = json.loads(raw, object_pairs_hook=seed.unique)
    require(type(selected) is dict and set(selected) == {"schemaVersion", "kind", "selection"}
        and type(selected["schemaVersion"]) is int and selected["schemaVersion"] == 1
        and selected["kind"] == "omux-linux-hm-realization-input-selection-v1"
        and type(selected["selection"]) is dict and set(selected["selection"]) == {"sha256", "bytes", "path"}
        and type(selected["selection"]["path"]) is str and Path(selected["selection"]["path"]).is_absolute()
        and len(selected["selection"]["path"]) <= 4096)
    layout_raw = control_read(args.layout, seed.MAX_METADATA, controls[args.layout], deadline)
    require(seed.sha(layout_raw) == digest(selected["selection"]["sha256"])
        and type(selected["selection"]["bytes"]) is int and 0 < len(layout_raw) == selected["selection"]["bytes"] <= seed.MAX_METADATA)
    value = json.loads(layout_raw, object_pairs_hook=seed.unique); shape(value)
    require(seed.encoded(value) == layout_raw)
    locked_raw = control_read(args.locked_seed, seed.MAX_METADATA, controls[args.locked_seed], deadline)
    locked = json.loads(locked_raw, object_pairs_hook=seed.unique)
    locked_pin = locked_tools(value, locked)
    private.platform(raw_metadata("/proc/" + str(os.getpid()) + "/status", 65536, deadline, proc_status=True).decode("ascii"), os.getuid())
    # Historical selected input provenance cannot encode its containing selector
    # commit/graph. The actual consuming source is independently guardian-bound.
    current = consumer_context(os.environ)
    modules = {}
    for row in args.module:
        name, path = row.split("=", 1); require(name in MODULES and name not in modules)
        controls[path] = control_capture(path)
        modules[name] = control_read(path, 1024**2, controls[path], deadline)
    require(set(modules) == set(MODULES) and {name: seed.sha(data) for name, data in modules.items()} == value["moduleSha256"])
    result, inputs = qualify(value, Path(args.layout).parent, os.environ["TEST_TMPDIR"], deadline)
    result["lockedNixSeedSha256"] = locked_pin
    result["consumerContext"] = current
    consumer_context(os.environ, current)
    require(control_read(args.locked_seed, seed.MAX_METADATA, controls[args.locked_seed], deadline) == locked_raw)
    require(control_read(args.layout, seed.MAX_METADATA, controls[args.layout], deadline) == layout_raw
        and control_read(args.selection, 65536, controls[args.selection], deadline) == raw)
    for row in args.module:
        name, path = row.split("=", 1); require(control_read(path, 1024**2, controls[path], deadline) == modules[name])
    for path, captured in controls.items(): control_check(path, captured)
    inputs.check()
    private.tick(deadline)
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n"); sys.stdout.flush()
    # Success output is provisional. Rejoin original raw controls after stdout,
    # then complete physical-only controls/member checks and original cutoff.
    require(control_read(args.selection, 65536, controls[args.selection], deadline) == raw
        and control_read(args.layout, seed.MAX_METADATA, controls[args.layout], deadline) == layout_raw
        and control_read(args.locked_seed, seed.MAX_METADATA, controls[args.locked_seed], deadline) == locked_raw)
    for row in args.module:
        name, path = row.split("=", 1)
        require(control_read(path, 1024**2, controls[path], deadline) == modules[name])
    inputs.check()
    for path, captured in controls.items(): control_check(path, captured)
    consumer_context(os.environ, current)
    private.tick(deadline)
    require(time.monotonic_ns() < until_ns)
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print("linux-hm-realization-inputs-refused", file=sys.stderr)
        raise SystemExit(125) from None
