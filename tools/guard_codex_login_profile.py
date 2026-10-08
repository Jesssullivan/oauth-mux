"""One exact contained native OAuth RUN; no inherited UI descriptors."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import stat
import socket
import struct
import sys
import time
# Only the explicitly declared delivery sibling; never resolve user input.
sys.path.insert(0,str(Path(__file__).parent.parent/'delivery'))
import guard_codex_live_profile as private_inputs
import guard_owner_runtime_input as retained

LABEL = "//delivery:native_account_login"
DESTINATION = "/omux-native-login/input.json"
VARIABLE = "OMUX_NATIVE_LOGIN_INPUT_MANIFEST"
DIRECTORY_VARIABLE = "OMUX_NATIVE_ENROLLMENT_DIRECTORY"
QUALIFICATION_DESTINATION = "/omux-native-login/ui-qualification.json"
AGENT_DESTINATION = "/omux-native-login/ssh-agent.sock"
REMOTE_FIELDS = frozenset(("python_path", "python_sha256", "gio_path", "gio_sha256", "uid",
    "machine_id_sha256", "boot_id_sha256", "wayland_socket", "wayland_device", "wayland_inode",
    "closure_qualified", "seat_qualified", "dialog_path", "dialog_sha256",
    "qt_platform_plugin", "qt_platform_plugin_sha256"))
SSH = "/nix/store/aq5s91svywqgs5l9zyhp1wcjqvnfa0ss-openssh-with-gssapi-10.2p1/bin/ssh"
KNOWN_HOSTS = "/srv/fast-local/jess/state/claude/agent-notes-rescue/2026-10-04/lab-yoga-known-hosts"
UI_FIELDS = frozenset(("host_alias", "ssh_path", "ssh_sha256", "known_hosts_path", "remote",
    "qualification_path", "qualification_sha256", "ssh_auth_socket"))
FIELDS = frozenset(("retained009_bundle", "schema_version", "authorize_provider_login",
    "native_device_contract_qualified", "native_sha256", "source_receipt_sha256",
    "state_parent", "deadline_seconds", "ui"))


BACKEND_SHA = "0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f"
ARCHIVE_SHA = "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
MANIFEST_SHA = "5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678"
RUNTIME_FILES = {
    "bin/codex": ("4ba3c25cd8821ffc6fac24445750460126c0a0130281dd40fc783ff6c622a4f3",421,0o555),
    "lib/codex/lib/ld-linux-x86-64.so.2": ("1640ec4d1cfcc3c19430b368cbbb057c5652eac340ecba12cf9dfbe2c3769d07",263056,0o555),
    "lib/codex/lib/libc.so.6": ("b4ae5be136ce59078de8e83112c2d36e1c7b86894f37dfe7d387b2827eb1120c",2472888,0o555),
    "lib/codex/lib/libdl.so.2": ("cb6e1b1b5762b30f608096da734d74c1366ecbe1ed830b6a3389a87dc9d35093",17400,0o555),
    "lib/codex/lib/libm.so.6": ("b0cd1f6a166e255d28375d7dcd91636971a1fa79d33fc67e88e4b7957961bb51",1127520,0o555),
    "lib/codex/lib/libpthread.so.0": ("bc2abac356f226c4ef4bed4e5b92e25821482a91a0554056cb0e05d1ae3261b0",21656,0o555),
    "lib/codex/lib/librt.so.1": ("bba80a7e69ba2d2afb60dd38ce251babad50bc2ae048fa8e6d4638df3f857671",17568,0o555),
    "lib/codex/lib/libutil.so.1": ("1e10f2f88caf7a5f15543a267c2577f8813325231c2b6a1178d32cfbc7ce1e7c",17472,0o555),
    "lib/codex/libexec/codex.bin": (BACKEND_SHA,318579008,0o555),
    "lib/codex/share/ca-bundle.crt": ("10608e4255ef550895125880d93c736051e54a7b5dfc746d1ec5bdb81816926f",521594,0o444),
}
def runtime_directories():
    result = {"":set()}
    for name in RUNTIME_FILES:
        parts = name.split("/")
        for depth,part in enumerate(parts):
            parent = "/".join(parts[:depth])
            result.setdefault(parent,set()).add(part)
    return result

def open_runtime(root, relative, directory=False):
    if relative and (relative.startswith("/") or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("codex-login-sealed-runtime-selector")
    descriptor = os.dup(root)
    try:
        parts = relative.split("/") if relative else []
        for index,part in enumerate(parts):
            last = index == len(parts)-1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (
                os.O_DIRECTORY if not last or directory else os.O_NONBLOCK)
            child = os.open(part,flags,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if not last or directory:
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o555:
                    raise ValueError("codex-login-sealed-runtime-directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def runtime_membership(fd, expected):
    with os.scandir(fd) as entries:
        names = [next(entries,None) for _ in range(len(expected)+1)]
        if names[-1] is not None or {entry.name for entry in names[:-1] if entry is not None} != expected:
            raise ValueError("codex-login-sealed-runtime-membership")

def device_qualification(value):
    inventory = {name:{"sha256":pin,"bytes":size,"mode":mode}
        for name,(pin,size,mode) in RUNTIME_FILES.items()}
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("kind") != "omux-retained-device-api-qualification-v1"
            or value.get("status") != "provider-free-device-api-qualified"
            or value.get("archive_sha256") != ARCHIVE_SHA
            or value.get("manifest_sha256") != MANIFEST_SHA
            or value.get("backend_sha256") != BACKEND_SHA
            or type(value.get("backend_bytes")) is not int or value["backend_bytes"] != 318579008
            or value.get("runtime_inventory") != inventory
            or value.get("loader_sha256") != RUNTIME_FILES["lib/codex/lib/ld-linux-x86-64.so.2"][0]
            or any(value.get(name) is not False for name in ("native_support","text_continuity","provider_evaluation"))):
        raise ValueError("codex-login-device-resource-qualification")
    api = value.get("device_api")
    if (type(api) is not dict or set(api) != {"method","request","response","provider_invocation"}
            or api["method"] != "account/login/start" or api["provider_invocation"] is not False):
        raise ValueError("codex-login-device-api-qualification")
    request, response = api["request"],api["response"]
    if (type(request) is not dict or type(response) is not dict
            or request.get("type") != "object" or response.get("type") != "object"
            or type(request.get("properties")) is not dict or set(request["properties"]) != {"type"}
            or request.get("required") != ["type"]
            or type(request["properties"]["type"]) is not dict
            or request["properties"]["type"].get("enum") != ["chatgptDeviceCode"]
            or type(response.get("properties")) is not dict
            or set(response["properties"]) != {"type","loginId","verificationUrl","userCode"}
            or type(response.get("required")) is not list
            or any(type(name) is not str for name in response["required"])
            or set(response["required"]) != set(response["properties"])
            or any(type(prop) is not dict for prop in response["properties"].values())
            or response["properties"]["type"].get("enum") != ["chatgptDeviceCode"]
            or any(response["properties"][name].get("type") != "string" for name in response["properties"])):
        raise ValueError("codex-login-device-api-qualification")

def selected(arguments):
    if arguments != ["run", LABEL]:
        raise ValueError("codex-login-exact-run")
    return {"PrivateNetwork": "no"}

def finite(arguments, manager, manifest, directory, reuse, unrelated=(), pins=()):
    selected(arguments)
    if (manager != "system" or manifest is None or directory is None or reuse or any(unrelated)
            or len(pins) != 3 or any(type(pin) is not str or not re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins)):
        raise ValueError("codex-login-exclusive-inputs")

def schema(raw):
    value = json.loads(raw, object_pairs_hook=private_inputs.unique_object)
    if (type(value) is not dict
            or type(value.get("schema_version")) is not int
            or value["schema_version"] not in (1, 2)
            or set(value) != (FIELDS if value["schema_version"] == 1 else FIELDS | {"enrollment"})
            or value["retained009_bundle"] is not True
            or value["authorize_provider_login"] is not True
            or value["native_device_contract_qualified"] is not True
            or type(value["deadline_seconds"]) is not int
            or not 1 <= value["deadline_seconds"] <= 900
            or type(value["ui"]) is not dict):
        raise ValueError("codex-login-manifest-schema")
    for field in ("native_sha256", "source_receipt_sha256"):
        if type(value[field]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise ValueError("codex-login-public-input-pin")
    if value["native_sha256"] != BACKEND_SHA:
        raise ValueError("codex-login-retained009-device-backend-required")
    ui = value["ui"]
    if set(ui) != UI_FIELDS or ui["host_alias"] != "yoga" or type(ui["remote"]) is not dict:
        raise ValueError("codex-login-ui-schema")
    for name in ("ssh_sha256", "qualification_sha256"):
        if type(ui[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", ui[name]):
            raise ValueError("codex-login-ui-pin")
    for name in ("ssh_path", "known_hosts_path", "qualification_path"):
        if type(ui[name]) is not str:
            raise ValueError("codex-login-ui-selector")
        private_inputs.binding_selector(ui[name])
    if ui["ssh_auth_socket"] is not None:
        if type(ui["ssh_auth_socket"]) is not str:
            raise ValueError("codex-login-agent-selector")
        private_inputs.binding_selector(ui["ssh_auth_socket"])
    if ui["ssh_path"] != SSH or ui["known_hosts_path"] != KNOWN_HOSTS:
        raise ValueError("codex-login-fixed-ssh-authority")
    remote = ui["remote"]
    if (set(remote) != REMOTE_FIELDS or remote["closure_qualified"] is not True
            or remote["seat_qualified"] is not True or type(remote["uid"]) is not int or remote["uid"] <= 0):
        raise ValueError("codex-login-remote-qualification-schema")
    for name in ("python_sha256", "gio_sha256", "machine_id_sha256", "boot_id_sha256",
                 "dialog_sha256", "qt_platform_plugin_sha256"):
        if type(remote[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", remote[name]):
            raise ValueError("codex-login-remote-pin")
    for name in ("python_path", "gio_path", "qt_platform_plugin"):
        if (type(remote[name]) is not str or not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]{1,211}/.+", remote[name])
                or ".." in Path(remote[name]).parts or any(c in remote[name] for c in "\\\\ \n\r\x00")):
            raise ValueError("codex-login-remote-immutable-selector")
    if (type(remote["dialog_path"]) is not str or not remote["dialog_path"].startswith("/")
            or remote["dialog_path"] != os.path.normpath(remote["dialog_path"])
            or any(part in ("", ".", "..") for part in remote["dialog_path"].split("/")[1:])
            or "\\" in remote["dialog_path"] or "\x00" in remote["dialog_path"]
            or any(c.isspace() for c in remote["dialog_path"])
            or len(os.fsencode(remote["dialog_path"])) > 4096):
        raise ValueError("codex-login-qualified-dialog-selector")
    if (type(remote["wayland_socket"]) is not str or not re.fullmatch(
            r"/run/user/" + str(remote["uid"]) + r"/wayland-[0-9]{1,3}", remote["wayland_socket"])
            or any(type(remote[name]) is not int or remote[name] <= 0 for name in ("wayland_device", "wayland_inode"))):
        raise ValueError("codex-login-remote-seat-selector")
    parent = value["state_parent"]
    if (type(parent) is not str or not parent.startswith("/") or parent != os.path.normpath(parent)
            or any(part in ("", ".", "..") for part in parent.split("/")[1:])
            or any(c in parent for c in "\\\n\r\x00")):
        raise ValueError("codex-login-private-state-selector")
    if value["schema_version"] == 2:
        from native_login_enrollment_selector import validate_template
        validate_template(value["enrollment"], Path(pwd.getpwuid(os.getuid()).pw_dir))
    return value

def namespace_custody(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("codex-login-private-namespace-custody")

def namespace_membership(fd, agent=False):
    expected = {"input.json", "ui-qualification.json"} | ({"ssh-agent.sock"} if agent else set())
    with os.scandir(fd) as entries:
        names = [next(entries, None) for _ in range(len(expected) + 1)]
        if (names[-1] is not None
                or {entry.name for entry in names[:-1] if entry is not None} != expected):
            raise ValueError("codex-login-private-namespace-members")

def placeholder_custody(info):
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o700) or info.st_nlink != 1):
        raise ValueError("codex-login-private-agent-mountpoint")

def agent_mountpoint_custody(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
            or info.st_nlink != 1 or info.st_size != 0):
        raise ValueError("codex-login-agent-regular-mountpoint")

def agent_mountpoint_identity(directory, descriptor):
    held = os.fstat(descriptor)
    named = os.stat("ssh-agent.sock", dir_fd=directory, follow_symlinks=False)
    agent_mountpoint_custody(held)
    agent_mountpoint_custody(named)
    if private_inputs.identity(held) != private_inputs.identity(named):
        raise ValueError("codex-login-agent-mountpoint-changed")
    return private_inputs.identity(held)

def normalized_bindings(value, leaf_bindings=(), *, readback=False):
    result = []
    leaf_bindings = set(leaf_bindings)
    for token in value.split():
        parts = token.split(":")
        option = parts.pop() if len(parts) == 3 else None
        if len(parts) != 2:
            raise ValueError("codex-login-readonly-bind-refused")
        binding = ":".join(parts)
        # Pinned systemctl prints only recursive binds with an option suffix.
        invalid = ((option is not None if binding in leaf_bindings else option != "rbind")
                   if readback else (option != "norbind" if binding in leaf_bindings else option not in (None, "rbind")))
        if invalid:
            raise ValueError("codex-login-readonly-bind-refused")
        result.append(binding)
    if len(set(result)) != len(result):
        raise ValueError("codex-login-readonly-bind-refused")
    return set(result)

def namespace_id(info):
    return str(info.st_dev) + ":" + str(info.st_ino)

def projection(properties, verified=False):
    result = dict(properties)
    result["BindReadOnlyPaths"] = "verified-native-login-inputs" if verified else "private-input-bind-redacted"
    result["BindPaths"] = "none" if verified else "private-input-bind-redacted"
    return result

def rejection(error):
    return "codex-login-admission-refused"

class Admission:
    def __init__(self, manifest, directory, source, state, deadline, pins):
        self.deadline = deadline
        self.source = Path(source).resolve(strict=True)
        self.state = Path(state).resolve(strict=True)
        self.manifest = Path(private_inputs.binding_selector(str(manifest)))
        self.directory = Path(private_inputs.binding_selector(str(directory)))
        self.namespace = self.manifest.parent
        self.fds = []
        self.identities = []
        self.agent_fd = None
        try:
            if self.manifest.name != "input.json":
                raise ValueError("codex-login-private-namespace-selector")
            self.namespace_fd = retained.directory(self.namespace)
            self.fds.append(self.namespace_fd)
            self.namespace_identity = private_inputs.identity(os.fstat(self.namespace_fd))
            namespace_custody(os.fstat(self.namespace_fd))
            if self.manifest.is_relative_to(self.source) or self.directory.is_relative_to(self.source):
                raise ValueError("codex-login-input-in-repository")
            self.manifest_fd = private_inputs.open_private(self.manifest, 65536, read=True)
            self.fds.append(self.manifest_fd)
            self.manifest_identity = private_inputs.identity(os.fstat(self.manifest_fd))
            raw = os.read(self.manifest_fd, 65537)
            if len(raw) != self.manifest_identity[5]:
                raise ValueError("codex-login-manifest-read")
            self.value = schema(raw)
            if pins != (self.value["native_sha256"], self.value["source_receipt_sha256"], self.value["ui"]["qualification_sha256"]):
                raise ValueError("codex-login-independent-operator-pins")
            self.manifest_digest = hashlib.sha256(raw).digest()
            if (self.directory.name != self.value["native_sha256"]
                    or Path(self.value["state_parent"]).is_relative_to(self.source)
                    or Path(self.value["state_parent"]).is_relative_to(self.state)):
                raise ValueError("codex-login-input-scope")
            self.parent = Path(self.value["state_parent"])
            self.parent_fd = retained.directory(self.parent)
            self.fds.append(self.parent_fd)
            parent_info = os.fstat(self.parent_fd)
            if stat.S_IMODE(parent_info.st_mode) != 0o700:
                raise ValueError("codex-login-private-state-parent")
            self.parent_identity = private_inputs.identity(parent_info)[:4]
            self.directory_fd = retained.directory(self.directory)
            self.fds.append(self.directory_fd)
            self.directory_identity = private_inputs.identity(os.fstat(self.directory_fd))
            if stat.S_IMODE(os.fstat(self.directory_fd).st_mode) != 0o555:
                raise ValueError("codex-login-sealed-native-directory")
            with os.scandir(self.directory_fd) as entries:
                names = [next(entries, None) for _ in range(4)]
                if names[3] is not None or {entry.name for entry in names[:3] if entry is not None} != {"codex", "native-source-receipt.json", "runtime"}:
                    raise ValueError("codex-login-native-membership")
            for name, pin, maximum, executable in (
                    ("codex", self.value["native_sha256"], 600 * 1024 * 1024, True),
                    ("native-source-receipt.json", self.value["source_receipt_sha256"], 16 * 1024 * 1024, False)):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory_fd)
                self.fds.append(fd)
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != (0o555 if executable else 0o444)
                        or not 0 < before.st_size <= maximum or executable and not before.st_mode & 0o100):
                    raise ValueError("codex-login-public-input-custody")
                digest, count = hashlib.sha256(), 0
                while True:
                    self.budget()
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > maximum:
                        raise ValueError("codex-login-public-input-bound")
                    digest.update(block)
                identity = private_inputs.identity(before)
                if count != before.st_size or digest.hexdigest() != pin or private_inputs.identity(os.fstat(fd)) != identity:
                    raise ValueError("codex-login-public-input-changed")
                self.identities.append((name, fd, identity))
            receipt_fd = next(fd for name,fd,_ in self.identities if name == "native-source-receipt.json")
            qualified = json.loads(os.pread(receipt_fd,16*1024*1024+1,0),object_pairs_hook=private_inputs.unique_object)
            device_qualification(qualified)
            self.runtime_fd = retained.directory(self.directory / "runtime")
            self.fds.append(self.runtime_fd)
            if stat.S_IMODE(os.fstat(self.runtime_fd).st_mode) != 0o555:
                raise ValueError("codex-login-sealed-runtime-directory")
            self.runtime_identity = private_inputs.identity(os.fstat(self.runtime_fd))
            self.runtime_dirs, self.runtime_files = [], []
            for name,expected in sorted(runtime_directories().items()):
                fd = open_runtime(self.runtime_fd,name,directory=True)
                self.fds.append(fd)
                runtime_membership(fd,expected)
                self.runtime_dirs.append((name,fd,private_inputs.identity(os.fstat(fd))))
            for name,(pin,size,mode) in sorted(RUNTIME_FILES.items()):
                fd = open_runtime(self.runtime_fd,name)
                self.fds.append(fd)
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_nlink != 1 or before.st_size != size
                        or stat.S_IMODE(before.st_mode) != mode):
                    raise ValueError("codex-login-sealed-runtime-file")
                digest = hashlib.sha256()
                total = 0
                while total < size:
                    self.budget()
                    block = os.read(fd,min(1024*1024,size-total))
                    if not block:
                        raise ValueError("codex-login-sealed-runtime-size")
                    total += len(block)
                    digest.update(block)
                identity = private_inputs.identity(before)
                if (os.read(fd,1) or digest.hexdigest() != pin
                        or private_inputs.identity(os.fstat(fd)) != identity):
                    raise ValueError("codex-login-sealed-runtime-digest")
                self.runtime_files.append((name,fd,identity))
            self.qualification = Path(self.value["ui"]["qualification_path"])
            if self.qualification != self.namespace / "ui-qualification.json":
                raise ValueError("codex-login-private-namespace-members")
            if self.qualification.is_relative_to(self.source):
                raise ValueError("codex-login-ui-qualification-in-source")
            self.qualification_fd = private_inputs.open_private(self.qualification, 32768, read=True)
            self.fds.append(self.qualification_fd)
            self.qualification_identity = private_inputs.identity(os.fstat(self.qualification_fd))
            raw = os.read(self.qualification_fd, 32769)
            if len(raw) != self.qualification_identity[5] or hashlib.sha256(raw).hexdigest() != self.value["ui"]["qualification_sha256"]:
                raise ValueError("codex-login-ui-qualification-pin")
            joined = json.loads(raw, object_pairs_hook=private_inputs.unique_object)
            if (type(joined) is not dict or set(joined) != {"schema_version", "scope", "host_alias",
                    "remote", "controller_ssh", "closure_receipt_sha256", "seat_receipt_sha256"}
                    or type(joined["schema_version"]) is not int or joined["schema_version"] != 1
                    or joined["scope"] != "omux-native-login-ui-qualification-v1"
                    or joined["host_alias"] != "yoga"
                    or joined["remote"] != self.value["ui"]["remote"]
                    or joined["controller_ssh"] != {"path": self.value["ui"]["ssh_path"],
                        "sha256": self.value["ui"]["ssh_sha256"]}
                    or any(type(joined[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", joined[name])
                        for name in ("closure_receipt_sha256", "seat_receipt_sha256"))):
                raise ValueError("codex-login-ui-qualification-binding")
            self.agent_path = self.value["ui"]["ssh_auth_socket"]
            self.placeholder_fd = None
            namespace_membership(self.namespace_fd, self.agent_path is not None)
            if self.agent_path is not None:
                if self.agent_path == str(self.namespace / "ssh-agent.sock"):
                    raise ValueError("codex-login-agent-source-is-mountpoint")
                self.placeholder_fd = os.open("ssh-agent.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.namespace_fd)
                self.fds.append(self.placeholder_fd)
                self.placeholder_identity = agent_mountpoint_identity(self.namespace_fd, self.placeholder_fd)
                parent = retained.directory(Path(self.agent_path).parent)
                try:
                    self.agent_fd = os.open(Path(self.agent_path).name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
                    self.fds.append(self.agent_fd)
                    info = os.fstat(self.agent_fd)
                    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) not in (0o600, 0o700) or info.st_nlink != 1):
                        raise ValueError("codex-login-agent-custody")
                    self.agent_identity = private_inputs.identity(info)
                finally:
                    os.close(parent)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    self.budget()
                    peer.settimeout(min(2, (self.deadline-time.monotonic_ns())/10**9))
                    peer.connect(self.agent_path)
                    self.budget()
                    pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != os.getuid() or pid <= 1:
                        raise ValueError("codex-login-agent-peer")
            self.recheck()
        except BaseException:
            self.close()
            raise

    def budget(self):
        if time.monotonic_ns() >= self.deadline:
            raise ValueError("codex-login-original-deadline")

    def recheck(self):
        self.budget()
        named_namespace = retained.directory(self.namespace)
        try:
            namespace_custody(os.fstat(named_namespace))
            namespace_membership(named_namespace, self.agent_path is not None)
            if (private_inputs.identity(os.fstat(named_namespace)) != self.namespace_identity
                    or private_inputs.identity(os.fstat(self.namespace_fd)) != self.namespace_identity):
                raise ValueError("codex-login-private-namespace-changed")
            if self.placeholder_fd is not None and (
                    agent_mountpoint_identity(named_namespace, self.placeholder_fd) != self.placeholder_identity):
                raise ValueError("codex-login-private-agent-mountpoint-changed")
        finally:
            os.close(named_namespace)
        named = private_inputs.open_private(self.manifest, 65536)
        try:
            if (private_inputs.identity(os.fstat(named)) != self.manifest_identity
                    or private_inputs.identity(os.fstat(self.manifest_fd)) != self.manifest_identity):
                raise ValueError("codex-login-manifest-changed")
        finally:
            os.close(named)
        os.lseek(self.manifest_fd, 0, os.SEEK_SET)
        if hashlib.sha256(os.read(self.manifest_fd, 65537)).digest() != self.manifest_digest:
            raise ValueError("codex-login-manifest-changed")
        named_parent = retained.directory(self.parent)
        try:
            if (private_inputs.identity(os.fstat(named_parent))[:4] != self.parent_identity
                    or private_inputs.identity(os.fstat(self.parent_fd))[:4] != self.parent_identity):
                raise ValueError("codex-login-private-state-parent-changed")
        finally:
            os.close(named_parent)
        named_dir = retained.directory(self.directory)
        try:
            if (private_inputs.identity(os.fstat(named_dir)) != self.directory_identity
                    or private_inputs.identity(os.fstat(self.directory_fd)) != self.directory_identity):
                raise ValueError("codex-login-native-directory-changed")
            with os.scandir(named_dir) as entries:
                names = [next(entries, None) for _ in range(4)]
                if names[3] is not None or {entry.name for entry in names[:3] if entry is not None} != {"codex", "native-source-receipt.json", "runtime"}:
                    raise ValueError("codex-login-native-membership")
            for name, fd, expected in self.identities:
                if (private_inputs.identity(os.fstat(fd)) != expected
                        or private_inputs.identity(os.stat(name, dir_fd=named_dir, follow_symlinks=False)) != expected):
                    raise ValueError("codex-login-public-input-changed")
        finally:
            os.close(named_dir)
        named_runtime = retained.directory(self.directory / "runtime")
        try:
            if (private_inputs.identity(os.fstat(named_runtime)) != self.runtime_identity
                    or private_inputs.identity(os.fstat(self.runtime_fd)) != self.runtime_identity):
                raise ValueError("codex-login-sealed-runtime-changed")
            for name,held,expected in self.runtime_dirs:
                named = open_runtime(named_runtime,name,directory=True)
                try:
                    runtime_membership(named,runtime_directories()[name])
                    if (private_inputs.identity(os.fstat(named)) != expected
                            or private_inputs.identity(os.fstat(held)) != expected):
                        raise ValueError("codex-login-sealed-runtime-changed")
                finally:
                    os.close(named)
            for name,held,expected in self.runtime_files:
                named = open_runtime(named_runtime,name)
                try:
                    if (private_inputs.identity(os.fstat(named)) != expected
                            or private_inputs.identity(os.fstat(held)) != expected):
                        raise ValueError("codex-login-sealed-runtime-changed")
                finally:
                    os.close(named)
        finally:
            os.close(named_runtime)
        named = private_inputs.open_private(self.qualification, 32768)
        try:
            if (private_inputs.identity(os.fstat(named)) != self.qualification_identity
                    or private_inputs.identity(os.fstat(self.qualification_fd)) != self.qualification_identity):
                raise ValueError("codex-login-ui-qualification-changed")
        finally:
            os.close(named)
        if self.agent_fd is not None:
            if (private_inputs.identity(os.fstat(self.agent_fd)) != self.agent_identity
                    or private_inputs.identity(os.stat(self.agent_path, follow_symlinks=False)) != self.agent_identity):
                raise ValueError("codex-login-agent-changed")
        return True

    def bindings(self):
        values = [str(self.namespace) + ":/omux-native-login", str(self.directory) + ":" + str(self.directory)]
        if self.agent_path is not None:
            values.append(self.agent_path + ":" + AGENT_DESTINATION + ":norbind")
        return values

    def verify_bindings(self, actual):
        leaves = [self.agent_path + ":" + AGENT_DESTINATION] if self.agent_path is not None else []
        if (normalized_bindings(actual.get("BindReadOnlyPaths", ""), leaves, readback=True)
                != normalized_bindings(" ".join(self.bindings()), leaves)
                or actual.get("BindPaths", "").strip()):
            raise ValueError("codex-login-readonly-bind-refused")

    def runtime_seconds(self):
        self.budget()
        seconds = (self.deadline - time.monotonic_ns() - 30 * 10**9) // 10**9
        if seconds < 1:
            raise ValueError("codex-login-original-deadline")
        return min(1200, seconds)

    def close(self):
        fds, self.fds = self.fds, []
        failure = None
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError as error:
                failure = failure or error
        if failure is not None:
            raise OSError("codex-login-descriptor-close-refused") from failure
