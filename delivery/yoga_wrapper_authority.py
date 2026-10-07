"""Validate captured Yoga vault-wrapper data; no IO or execution authority.

Callers must independently select the digests, hold/reobserve bounded regular
input descriptors, qualify the inventory's NAR bytes and current registration,
and preserve the returned wrapper paths for execution. This pure validator
cannot attest pathname custody, an atomic execution, or destination availability.
Chromium's package launcher and Python's selected interpreter are separate
authorities; neither is accepted as one of these three capability roles.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import time

SHA = re.compile(r"[0-9a-f]{64}")
STORE = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}")
TOOLS = frozenset(("python", "systemd_run", "systemctl", "bazel", "closure",
                   "bootstrap_closure", "zig_sdk", "java_home"))
ROLES = {"dbus_session": ("dbus_run_session", "dbus-run-session"),
         "dbus_daemon": ("dbus_daemon", "dbus-daemon"),
         "keyring": ("gnome_keyring_daemon", "gnome-keyring-daemon")}
MAX_INVENTORY = 8 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_COMPANION = 65536
MAX_WRAPPER = 8192
MAX_ROWS = 4096
MAX_REFS = 65536
MAX_NAR_BYTES = 16 * 1024**3
COMPANION_FIELDS = frozenset(("schemaVersion", "scope", "selectionSha256", "inventorySha256",
    "controllerTools", "nativeManifest", "bootstrapManifest", "wrappers", "rootCount", "registeredPaths",
    "registeredNarBytes", "deadlineMonotonicNs", "registrySnapshotVerified", "selectedInputBytesVerified",
    "contentRehashed", "wrapperExecuted", "backendExecuted", "executionAuthority", "destinationRegistrationVerified", "realized"))
FALSE_FIELDS = frozenset(("contentRehashed", "wrapperExecuted", "backendExecuted", "executionAuthority",
                          "destinationRegistrationVerified", "realized"))
REASONS = frozenset(("input_invalid", "digest_mismatch", "schema_invalid", "inventory_invalid",
                     "manifest_mismatch", "closure_mismatch", "wrapper_mismatch", "deadline_exceeded", "byte_bound"))


class WrapperRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "input_invalid"
        super().__init__(self.reason)


@dataclass(frozen=True)
class WrapperBinding:
    role: str
    path: str
    sha256: str
    interpreter: str
    backend: str
    backend_root: str


@dataclass(frozen=True)
class WrapperAuthority:
    companion_sha256: str
    inventory_sha256: str
    native_manifest_sha256: str
    registered_native_manifest_sha256: str
    bindings: tuple


def require(condition, reason):
    if not condition:
        raise WrapperRefusal(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def budget(deadline, now):
    require(type(deadline) is int and 0 < deadline - now() <= 1200 * 10**9, "deadline_exceeded")


def hash_input(data, expected, maximum):
    require(type(data) is bytes and type(expected) is str and SHA.fullmatch(expected), "input_invalid")
    require(0 < len(data) <= maximum, "byte_bound")
    require(digest(data) == expected, "digest_mismatch")


def decode(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "schema_invalid")
            value[key] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(WrapperRefusal("schema_invalid")))
    except (ValueError, UnicodeError, RecursionError):
        raise WrapperRefusal("schema_invalid") from None


def physical(path):
    require(type(path) is str and 1 <= len(path) <= 4096 and path.startswith(("/srv/", "/nix/store/"))
            and re.fullmatch(r"/[A-Za-z0-9+._?=@/-]+", path) and str(PurePosixPath(path)) == path
            and not {".", ".."}.intersection(path.split("/")), "input_invalid")
    if path.startswith("/nix/store/"):
        store_root(path)
    return path


def store_root(path):
    require(type(path) is str and len(path) <= 4096, "closure_mismatch")
    root = "/".join(path.split("/")[:4])
    require(STORE.fullmatch(root) and str(PurePosixPath(path)) == path
            and not {".", ".."}.intersection(path.split("/"))
            and re.fullmatch(r"/[A-Za-z0-9+._?=@/-]+", path), "closure_mismatch")
    return root


def nar_hash(value):
    if type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return
    require(type(value) is str and re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", value), "inventory_invalid")
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except ValueError:
        raise WrapperRefusal("inventory_invalid") from None
    require(len(raw) == 32, "inventory_invalid")


def inventory(value, deadline, now):
    fields = {"schemaVersion", "system", "mode", "roots", "paths", "provenance", "contentRehashed", "realized", "published"}
    require(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and value["system"] == "x86_64-linux"
            and value["mode"] == "local-sqlite-readonly-snapshot"
            and all(value[field] is False for field in ("contentRehashed", "realized", "published")), "inventory_invalid")
    roots, rows = value["roots"], value["paths"]
    require(type(roots) is list and 1 <= len(roots) <= 11 and all(type(root) is str and STORE.fullmatch(root) for root in roots)
            and roots == sorted(set(roots)) and type(rows) is list and 1 <= len(rows) <= MAX_ROWS, "inventory_invalid")
    by_path, edges, total = {}, 0, 0
    for row in rows:
        budget(deadline, now)
        require(type(row) is dict and set(row) == {"path", "narHash", "narSize", "references"}
                and type(row["path"]) is str and STORE.fullmatch(row["path"]) and row["path"] not in by_path
                and type(row["narSize"]) is int and row["narSize"] > 0, "inventory_invalid")
        nar_hash(row["narHash"])
        refs = row["references"]
        require(type(refs) is list and all(type(ref) is str and STORE.fullmatch(ref) for ref in refs)
                and refs == sorted(set(refs)), "inventory_invalid")
        by_path[row["path"]] = row
        edges += len(refs); total += row["narSize"]
        require(edges <= MAX_REFS and total <= MAX_NAR_BYTES, "byte_bound")
    require(list(by_path) == sorted(by_path) and set(roots).issubset(by_path)
            and all(set(row["references"]).issubset(by_path) for row in rows), "inventory_invalid")
    reached, pending = set(), list(roots)
    while pending:
        budget(deadline, now)
        path = pending.pop()
        if path not in reached:
            reached.add(path); pending.extend(by_path[path]["references"])
    require(reached == set(by_path), "closure_mismatch")
    provenance = value["provenance"]
    require(type(provenance) is dict and set(provenance) == {"rootsSha256", "inputSha256"}
            and provenance["rootsSha256"] == digest(canonical(roots)), "inventory_invalid")
    expected_keys = {"selection", "native_manifest", "bootstrap_manifest"} | {"wrapper/" + name for name in ROLES}
    shas = provenance["inputSha256"]
    require(type(shas) is dict and set(shas) == expected_keys
            and all(type(sha) is str and SHA.fullmatch(sha) for sha in shas.values()), "inventory_invalid")
    return by_path, total, shas


def _validate(companion_bytes, *, companion_sha256, native_manifest_bytes, native_manifest_sha256,
              registered_native_manifest_bytes, inventory_bytes, inventory_sha256,
              native_manifest_path, wrapper_paths, wrapper_bytes, wrapper_sha256,
              controller_tools, deadline_ns, now):
    budget(deadline_ns, now)
    hash_input(companion_bytes, companion_sha256, MAX_COMPANION)
    hash_input(native_manifest_bytes, native_manifest_sha256, MAX_MANIFEST)
    hash_input(inventory_bytes, inventory_sha256, MAX_INVENTORY)
    companion, native, selected_inventory = decode(companion_bytes), decode(native_manifest_bytes), decode(inventory_bytes)
    require(type(companion) is dict and set(companion) == COMPANION_FIELDS
            and type(companion["schemaVersion"]) is int and companion["schemaVersion"] == 1
            and companion["scope"] == "yoga-controller-registry-and-wrapper-v1"
            and companion["registrySnapshotVerified"] is True and companion["selectedInputBytesVerified"] is True
            and all(companion[name] is False for name in FALSE_FIELDS)
            and type(companion["deadlineMonotonicNs"]) is int and companion["deadlineMonotonicNs"] > 0,
            "schema_invalid")
    # Historical producer deadline is provenance; admission uses deadline_ns.
    require(type(controller_tools) is dict and set(controller_tools) == TOOLS
            and type(companion["controllerTools"]) is dict and companion["controllerTools"] == controller_tools,
            "closure_mismatch")
    for tool, path in controller_tools.items():
        root = store_root(path)
        require(tool not in ("closure", "bootstrap_closure", "zig_sdk", "java_home") or path == root, "closure_mismatch")
    for mapping in (wrapper_paths, wrapper_bytes, wrapper_sha256):
        require(type(mapping) is dict and set(mapping) == set(ROLES), "input_invalid")
    require(type(companion["wrappers"]) is dict and set(companion["wrappers"]) == set(ROLES), "schema_invalid")
    rows, total, provenance = inventory(selected_inventory, deadline_ns, now)
    require(companion["inventorySha256"] == inventory_sha256
            and type(companion["rootCount"]) is int and companion["rootCount"] == len(selected_inventory["roots"])
            and type(companion["registeredPaths"]) is int and companion["registeredPaths"] == len(rows)
            and type(companion["registeredNarBytes"]) is int and companion["registeredNarBytes"] == total
            and companion["selectionSha256"] == provenance["selection"], "inventory_invalid")
    for name, tool in (("nativeManifest", "closure"), ("bootstrapManifest", "bootstrap_closure")):
        facts = companion[name]
        require(type(facts) is dict and set(facts) == {"sha256", "registeredObject", "registeredManifestSha256"}
                and type(facts["sha256"]) is str and SHA.fullmatch(facts["sha256"])
                and type(facts["registeredManifestSha256"]) is str and SHA.fullmatch(facts["registeredManifestSha256"])
                and type(facts["registeredObject"]) is str and STORE.fullmatch(facts["registeredObject"]), "schema_invalid")
        closure = controller_tools[tool]
        require(closure in rows and facts["registeredObject"] in rows
                and facts["registeredObject"] in rows[closure]["references"], "closure_mismatch")
        key = "native_manifest" if name == "nativeManifest" else "bootstrap_manifest"
        require(facts["sha256"] == provenance[key], "manifest_mismatch")
    require(companion["nativeManifest"]["sha256"] == native_manifest_sha256, "manifest_mismatch")
    registered_sha = companion["nativeManifest"]["registeredManifestSha256"]
    hash_input(registered_native_manifest_bytes, registered_sha, MAX_MANIFEST)
    require(type(native) is dict and native == decode(registered_native_manifest_bytes)
            and native.get("system") == "x86_64-linux" and type(native.get("packages")) is dict
            and type(native.get("tools")) is dict, "manifest_mismatch")
    physical(native_manifest_path)
    require(PurePosixPath(native_manifest_path).name == "native.json", "manifest_mismatch")
    packages, tools = native["packages"], native["tools"]
    bash = packages["bash"]["out"]
    require(type(bash) is str and STORE.fullmatch(bash), "manifest_mismatch")
    interpreter = bash + "/bin/bash"
    require(bash in rows and packages["python"]["out"] == store_root(controller_tools["python"])
            and controller_tools["python"] == packages["python"]["out"] + "/bin/python3"
            and packages["bazel_jdk"]["out"] == controller_tools["java_home"]
            and tools["systemctl"] == controller_tools["systemctl"]
            and controller_tools["systemd_run"] == store_root(tools["systemctl"]) + "/bin/systemd-run", "manifest_mismatch")
    bindings, backend_roots = [], set()
    for role, (key, basename) in ROLES.items():
        budget(deadline_ns, now)
        facts = companion["wrappers"][role]
        require(type(facts) is dict and set(facts) == {"sha256", "backend", "backendRoot", "interpreter", "abi"}
                and facts["abi"] == "omux-native-capability-wrapper-v1", "schema_invalid")
        backend = tools[key]
        backend_root = store_root(backend)
        require(backend == backend_root + "/bin/" + basename and backend_root in rows
                and facts["backend"] == backend and facts["backendRoot"] == backend_root
                and facts["interpreter"] == interpreter, "wrapper_mismatch")
        package = "gnome_keyring" if role == "keyring" else "dbus"
        require(packages[package]["out"] == backend_root, "manifest_mismatch")
        physical(wrapper_paths[role])
        require(wrapper_paths[role] == str(PurePosixPath(native_manifest_path).parent / "tool_wrappers" / key), "wrapper_mismatch")
        sha = wrapper_sha256[role]
        hash_input(wrapper_bytes[role], sha, MAX_WRAPPER)
        require(facts["sha256"] == sha == provenance["wrapper/" + role], "digest_mismatch")
        expected = ('#!' + interpreter + '\nset -eu\nexec \'' + backend + '\' "$@"\n').encode("ascii")
        require(wrapper_bytes[role] == expected, "wrapper_mismatch")
        backend_roots.add(backend_root)
        bindings.append(WrapperBinding(role, wrapper_paths[role], sha, interpreter, backend, backend_root))
    expected_roots = sorted({store_root(path) for path in controller_tools.values()} | backend_roots)
    require(selected_inventory["roots"] == expected_roots, "closure_mismatch")
    budget(deadline_ns, now)
    return WrapperAuthority(companion_sha256, inventory_sha256, native_manifest_sha256, registered_sha, tuple(bindings))


def validate(companion_bytes, *, companion_sha256, native_manifest_bytes, native_manifest_sha256,
             registered_native_manifest_bytes, inventory_bytes, inventory_sha256,
             native_manifest_path, wrapper_paths, wrapper_bytes, wrapper_sha256,
             controller_tools, deadline_ns, now=time.monotonic_ns):
    """Return only captured byte bindings; refuse without executing/opening paths."""
    try:
        return _validate(companion_bytes, companion_sha256=companion_sha256,
            native_manifest_bytes=native_manifest_bytes, native_manifest_sha256=native_manifest_sha256,
            registered_native_manifest_bytes=registered_native_manifest_bytes,
            inventory_bytes=inventory_bytes, inventory_sha256=inventory_sha256,
            native_manifest_path=native_manifest_path, wrapper_paths=wrapper_paths,
            wrapper_bytes=wrapper_bytes, wrapper_sha256=wrapper_sha256,
            controller_tools=controller_tools, deadline_ns=deadline_ns, now=now)
    except WrapperRefusal:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError, OverflowError):
        raise WrapperRefusal("input_invalid") from None
