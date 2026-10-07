"""Exact provider-free Yoga UI preparation admission; no provider/native login."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
import guard_codex_live_profile as inputs
import guard_codex_login_profile as login
import guard_owner_runtime_input as retained

LABEL = "//delivery:native_login_ui_qualification"
DESTINATION = "/omux-native-login-ui-prepare/input.json"
OS_DESTINATION = "/omux-native-login-ui-prepare/os-qualification.json"
AGENT_DESTINATION = "/omux-native-login-ui-prepare/ssh-agent.sock"
OUTPUT_DESTINATION = "/omux-native-login-ui-output"
VARIABLE = "OMUX_NATIVE_LOGIN_UI_PREPARE_INPUT_MANIFEST"
FIELDS = frozenset(("schema_version","scope","os_qualification_sha256","control_sha256",
    "known_hosts_path","ssh_auth_socket","output_parent","deadline_seconds"))
RECEIPTS = frozenset(("closure.json","seat.json","ui-qualification.json"))

UI_ROOTS = frozenset((
    "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12",
    "/nix/store/zcmsivndca5wmam9nwnbjrm0zkgykwfz-glib-2.86.3",
    "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0",
    "/nix/store/l1nqjg1yx6q6vx6zwsnd3ky0s7a0kfk8-qtwayland-6.11.0"))
INVENTORY_SHA = "2be4ecfe05837c67a7267aa216dbae683f2d44d07e96198d3475f3fbd124c7f8"
INVENTORY_PATH = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/8b6bd81f-786e-49c1-b8de-ac1103e986b1/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/yoga_controller_inventory_producer/test.outputs/yoga-controller-inputs/controller-inventory.json")

def canonical_rows(rows):
    return json.dumps(rows,sort_keys=True,separators=(",",":"),allow_nan=False).encode("ascii")

def selected_inventory_rows(raw,expected_sha256=INVENTORY_SHA):
    from verify_cached_nars import parse_inventory
    rows = parse_inventory(raw,expected_sha256)
    if len(rows) != 472:
        raise ValueError("native-ui-source-inventory")
    by_path = {row["path"]:row for row in rows}
    selected,pending = set(),list(UI_ROOTS)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in by_path:
            raise ValueError("native-ui-source-inventory")
        selected.add(name)
        pending.extend(by_path[name]["references"])
    result = [by_path[name] for name in sorted(selected)]
    if len(result) != 181 or sum(row["narSize"] for row in result) != 869166464:
        raise ValueError("native-ui-source-inventory")
    return result

CLOSURE_FIELDS = frozenset(("schema_version","scope","rows","verified_paths","verified_nar_bytes",
    "destination_registration_verified","destination_content_rehashed","store_import_performed",
    "dialog_sha256","source_inventory_sha256","os_qualification_sha256"))
SEAT_EXTRA = frozenset(("schema_version","scope","wayland_peer_pid","wayland_peer_uid",
    "wayland_peer_start_ticks","portal_owner_pid","portal_owner_start_ticks",
    "actual_dialog_ready","actual_dialog_eof_clean_exit","provider_request_performed","portal_openuri_performed"))

def measured_receipts(closure,seat,remote,os_pin,control_pin,rows_sha256):
    if (type(closure) is not dict or set(closure) != CLOSURE_FIELDS
            or type(closure["schema_version"]) is not int or closure["schema_version"] != 1
            or closure["scope"] != "omux-native-login-ui-closure-v1"
            or type(closure["verified_paths"]) is not int or closure["verified_paths"] != 181
            or type(closure["verified_nar_bytes"]) is not int or closure["verified_nar_bytes"] != 869166464
            or closure["destination_registration_verified"] is not True
            or closure["destination_content_rehashed"] is not True
            or closure["store_import_performed"] is not False
            or closure["dialog_sha256"] != control_pin or closure["source_inventory_sha256"] != INVENTORY_SHA
            or closure["os_qualification_sha256"] != os_pin
            or type(closure["rows"]) is not list or len(closure["rows"]) != 181
            or hashlib.sha256(canonical_rows(closure["rows"])).hexdigest() != rows_sha256):
        raise ValueError("native-ui-measured-closure")
    from verify_cached_nars import expected_hash
    rows,names,total = closure["rows"],set(),0
    for row in rows:
        if (type(row) is not dict or set(row) != {"path","narHash","narSize","references"}
                or type(row["path"]) is not str
                or not re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}",row["path"])
                or row["path"] in names or type(row["narSize"]) is not int or row["narSize"] <= 0
                or type(row["references"]) is not list or any(type(ref) is not str for ref in row["references"])):
            raise ValueError("native-ui-measured-closure")
        expected_hash(row["narHash"])
        names.add(row["path"])
        total += row["narSize"]
    if total != 869166464 or not UI_ROOTS <= names or any(not set(row["references"]) <= names for row in rows):
        raise ValueError("native-ui-measured-closure")
    if (type(seat) is not dict or set(seat) != login.REMOTE_FIELDS|SEAT_EXTRA
            or type(seat["schema_version"]) is not int or seat["schema_version"] != 1
            or seat["scope"] != "omux-native-login-ui-seat-v1"
            or any(seat[name] != remote[name] for name in login.REMOTE_FIELDS)
            or seat["actual_dialog_ready"] is not True or seat["actual_dialog_eof_clean_exit"] is not True
            or seat["provider_request_performed"] is not False or seat["portal_openuri_performed"] is not False
            or type(seat["wayland_peer_uid"]) is not int or seat["wayland_peer_uid"] != remote["uid"]
            or any(type(seat[name]) is not int or seat[name] <= 1 for name in
                ("wayland_peer_pid","portal_owner_pid"))
            or any(type(seat[name]) is not int or seat[name] <= 0 for name in
                ("wayland_peer_start_ticks","portal_owner_start_ticks"))):
        raise ValueError("native-ui-measured-seat")

def selected(arguments):
    if arguments != ["run",LABEL]:
        raise ValueError("native-ui-exact-run")
    return {"PrivateNetwork":"no"}

def finite(arguments,manager,manifest,output,reuse,pins,unrelated=()):
    selected(arguments)
    if (manager != "system" or manifest is None or output is None or reuse or any(unrelated)
            or len(pins) != 3 or any(type(pin) is not str or not re.fullmatch(r"[0-9a-f]{64}",pin) for pin in pins)):
        raise ValueError("native-ui-exclusive-inputs")

def schema(raw):
    value = json.loads(raw,object_pairs_hook=inputs.unique_object)
    if (type(value) is not dict or set(value) != FIELDS
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["scope"] != "omux-native-login-ui-prepare-v1"
            or type(value["deadline_seconds"]) is not int or not 1 <= value["deadline_seconds"] <= 900
            or value["known_hosts_path"] != login.KNOWN_HOSTS
            or value["output_parent"] != OUTPUT_DESTINATION):
        raise ValueError("native-ui-plan-schema")
    for name in ("os_qualification_sha256","control_sha256"):
        if type(value[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}",value[name]):
            raise ValueError("native-ui-plan-pin")
    if value["ssh_auth_socket"] is not None:
        if type(value["ssh_auth_socket"]) is not str:
            raise ValueError("native-ui-agent-selector")
        inputs.binding_selector(value["ssh_auth_socket"])
    return value

def members(fd,expected):
    with os.scandir(fd) as entries:
        names = [next(entries,None) for _ in range(len(expected)+1)]
        if names[-1] is not None or {entry.name for entry in names[:-1] if entry is not None} != set(expected):
            raise ValueError("native-ui-exact-namespace")

def agent_mountpoint_custody(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in (0o400,0o600)
            or info.st_nlink != 1 or info.st_size != 0):
        raise ValueError("native-ui-agent-regular-mountpoint")

def agent_mountpoint_identity(directory,descriptor):
    held = os.fstat(descriptor)
    named = os.stat("ssh-agent.sock",dir_fd=directory,follow_symlinks=False)
    agent_mountpoint_custody(held)
    agent_mountpoint_custody(named)
    if inputs.identity(held) != inputs.identity(named):
        raise ValueError("native-ui-agent-mountpoint-changed")
    return inputs.identity(held)

def normalized_bindings(value,leaf_bindings=(),*,readback=False):
    result = []
    leaf_bindings = set(leaf_bindings)
    for token in value.split():
        parts = token.split(":")
        option = parts.pop() if len(parts) == 3 else None
        if len(parts) != 2:
            raise ValueError("native-ui-bind-refused")
        binding = ":".join(parts)
        # Pinned systemctl prints only recursive binds with an option suffix.
        invalid = ((option is not None if binding in leaf_bindings else option != "rbind")
                   if readback else (option != "norbind" if binding in leaf_bindings else option not in (None,"rbind")))
        if invalid:
            raise ValueError("native-ui-bind-refused")
        result.append(binding)
    if len(set(result)) != len(result):
        raise ValueError("native-ui-bind-refused")
    return set(result)

def projection(properties,verified=False):
    result = dict(properties)
    result["BindReadOnlyPaths"] = "verified-ui-prepare-inputs" if verified else "private-bind-redacted"
    result["BindPaths"] = "verified-empty-owned-ui-output" if verified else "private-bind-redacted"
    return result

def rejection(error):
    return "native-ui-prepare-refused"

class Admission:
    def __init__(self,manifest,output,source,state,deadline,pins):
        self.deadline = deadline
        self.fds = []
        self.agent_fd = self.placeholder_fd = None
        self.source = Path(source).resolve(strict=True)
        self.manifest = Path(inputs.binding_selector(str(manifest)))
        self.namespace = self.manifest.parent
        self.output = Path(inputs.binding_selector(str(output)))
        self.pins = pins
        try:
            if (self.manifest.name != "input.json" or self.manifest.is_relative_to(self.source)
                    or self.output.is_relative_to(self.source) or self.output == self.namespace
                    or self.output.is_relative_to(self.namespace) or self.namespace.is_relative_to(self.output)):
                raise ValueError("native-ui-private-scope")
            parent = retained.directory(INVENTORY_PATH.parent)
            try:
                self.inventory_fd = os.open(INVENTORY_PATH.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
                self.fds.append(self.inventory_fd)
            finally:
                os.close(parent)
            info = os.fstat(self.inventory_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode & 0o022
                    or info.st_nlink != 1 or not 0 < info.st_size <= 8*1024*1024):
                raise ValueError("native-ui-source-inventory-custody")
            self.inventory_identity = inputs.identity(info)
            raw = os.pread(self.inventory_fd,8*1024*1024+1,0)
            if len(raw) != info.st_size or inputs.identity(os.fstat(self.inventory_fd)) != self.inventory_identity:
                raise ValueError("native-ui-source-inventory-changed")
            self.rows_sha256 = hashlib.sha256(canonical_rows(selected_inventory_rows(raw))).hexdigest()
            self.namespace_fd = retained.directory(self.namespace)
            self.fds.append(self.namespace_fd)
            login.namespace_custody(os.fstat(self.namespace_fd))
            self.namespace_identity = inputs.identity(os.fstat(self.namespace_fd))
            self.output_fd = retained.directory(self.output)
            self.fds.append(self.output_fd)
            login.namespace_custody(os.fstat(self.output_fd))
            self.output_identity = inputs.identity(os.fstat(self.output_fd))[:4]
            members(self.output_fd,set())
            self.manifest_fd = inputs.open_private(self.manifest,65536,read=True)
            self.fds.append(self.manifest_fd)
            self.manifest_identity = inputs.identity(os.fstat(self.manifest_fd))
            raw = os.pread(self.manifest_fd,65537,0)
            if len(raw) != self.manifest_identity[5] or hashlib.sha256(raw).hexdigest() != pins[0]:
                raise ValueError("native-ui-independent-plan-pin")
            self.value = schema(raw)
            if (self.value["os_qualification_sha256"],self.value["control_sha256"]) != pins[1:]:
                raise ValueError("native-ui-independent-input-pins")
            self.os_path = self.namespace / "os-qualification.json"
            self.os_fd = inputs.open_private(self.os_path,65536,read=True)
            self.fds.append(self.os_fd)
            self.os_identity = inputs.identity(os.fstat(self.os_fd))
            raw = os.pread(self.os_fd,65537,0)
            if len(raw) != self.os_identity[5] or hashlib.sha256(raw).hexdigest() != pins[1]:
                raise ValueError("native-ui-independent-os-pin")
            import yoga_delivery_settings as settings
            self.os_receipt = settings.qualification(json.loads(raw,object_pairs_hook=inputs.unique_object))
            self.agent_path = self.value["ssh_auth_socket"]
            if self.agent_path is not None:
                if self.agent_path == str(self.namespace / "ssh-agent.sock"):
                    raise ValueError("native-ui-agent-source-is-mountpoint")
                self.placeholder_fd = os.open("ssh-agent.sock",os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.namespace_fd)
                self.fds.append(self.placeholder_fd)
                self.placeholder_identity = agent_mountpoint_identity(self.namespace_fd,self.placeholder_fd)
                parent = retained.directory(Path(self.agent_path).parent)
                try:
                    self.agent_fd = os.open(Path(self.agent_path).name,os.O_PATH|os.O_NOFOLLOW,dir_fd=parent)
                    self.fds.append(self.agent_fd)
                    login.placeholder_custody(os.fstat(self.agent_fd))
                    self.agent_identity = inputs.identity(os.fstat(self.agent_fd))
                finally:
                    os.close(parent)
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
                    channel.settimeout(2)
                    channel.connect(self.agent_path)
                    pid,uid,_ = struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid != os.getuid() or pid <= 1:
                        raise ValueError("native-ui-agent-peer")
            self.recheck()
        except BaseException:
            self.close()
            raise

    def budget(self):
        if time.monotonic_ns() >= self.deadline:
            raise ValueError("native-ui-original-deadline")

    def recheck(self):
        self.budget()
        parent = retained.directory(INVENTORY_PATH.parent)
        try:
            named = os.open(INVENTORY_PATH.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
            try:
                if (inputs.identity(os.fstat(named)) != self.inventory_identity
                        or inputs.identity(os.fstat(self.inventory_fd)) != self.inventory_identity
                        or hashlib.sha256(os.pread(self.inventory_fd,8*1024*1024+1,0)).hexdigest() != INVENTORY_SHA):
                    raise ValueError("native-ui-source-inventory-changed")
            finally:
                os.close(named)
        finally:
            os.close(parent)
        for path,held,expected,directory in (
                (self.namespace,self.namespace_fd,self.namespace_identity,True),
                (self.manifest,self.manifest_fd,self.manifest_identity,False),
                (self.os_path,self.os_fd,self.os_identity,False)):
            named = retained.directory(path) if directory else inputs.open_private(path,65536)
            try:
                if inputs.identity(os.fstat(named)) != expected or inputs.identity(os.fstat(held)) != expected:
                    raise ValueError("native-ui-private-input-changed")
            finally:
                os.close(named)
        members(self.namespace_fd,{"input.json","os-qualification.json"}|({"ssh-agent.sock"} if self.agent_fd is not None else set()))
        for held,pin in ((self.manifest_fd,self.pins[0]),(self.os_fd,self.pins[1])):
            if hashlib.sha256(os.pread(held,65537,0)).hexdigest() != pin:
                raise ValueError("native-ui-private-input-changed")
        named = retained.directory(self.output)
        try:
            login.namespace_custody(os.fstat(named))
            if (inputs.identity(os.fstat(named))[:4] != self.output_identity
                    or inputs.identity(os.fstat(self.output_fd))[:4] != self.output_identity):
                raise ValueError("native-ui-output-changed")
            with os.scandir(named) as entries:
                names = [next(entries,None) for _ in range(4)]
                if names[-1] is not None or any(entry.name not in RECEIPTS for entry in names[:-1] if entry is not None):
                    raise ValueError("native-ui-output-membership")
        finally:
            os.close(named)
        if self.agent_fd is not None:
            if (inputs.identity(os.fstat(self.agent_fd)) != self.agent_identity
                    or inputs.identity(os.stat(self.agent_path,follow_symlinks=False)) != self.agent_identity
                    or agent_mountpoint_identity(self.namespace_fd,self.placeholder_fd) != self.placeholder_identity):
                raise ValueError("native-ui-agent-changed")
        return True

    def completed(self):
        self.recheck()
        members(self.output_fd,RECEIPTS)
        rows = {}
        for name in sorted(RECEIPTS):
            maximum = 256*1024 if name == "closure.json" else 16*1024
            fd = inputs.open_private(self.output/name,maximum,read=True)
            try:
                before = inputs.identity(os.fstat(fd))
                if stat.S_IMODE(before[3]) != 0o600:
                    raise ValueError("native-ui-output-custody")
                raw = os.pread(fd,maximum+1,0)
                if len(raw) != before[5] or inputs.identity(os.fstat(fd)) != before:
                    raise ValueError("native-ui-output-changed")
                rows[name] = (hashlib.sha256(raw).hexdigest(),json.loads(raw,object_pairs_hook=inputs.unique_object))
            finally:
                os.close(fd)
        joined = rows["ui-qualification.json"][1]
        if (type(joined) is not dict or set(joined) != {"schema_version","scope","host_alias","remote",
                "controller_ssh","closure_receipt_sha256","seat_receipt_sha256"}
                or type(joined["schema_version"]) is not int or joined["schema_version"] != 1
                or joined["scope"] != "omux-native-login-ui-qualification-v1" or joined["host_alias"] != "yoga"
                or joined["closure_receipt_sha256"] != rows["closure.json"][0]
                or joined["seat_receipt_sha256"] != rows["seat.json"][0]
                or joined["controller_ssh"] != {"path":self.os_receipt["sshPath"],"sha256":self.os_receipt["sshSha256"]}):
            raise ValueError("native-ui-output-join")
        remote = joined["remote"]
        if (type(remote) is not dict or set(remote) != login.REMOTE_FIELDS
                or remote["dialog_sha256"] != self.pins[2] or remote["closure_qualified"] is not True
                or remote["seat_qualified"] is not True
                or remote["uid"] != self.os_receipt["remote"]["uid"]
                or remote["machine_id_sha256"] != self.os_receipt["remote"]["machineIdSha256"]
                or remote["boot_id_sha256"] != self.os_receipt["remote"]["bootIdSha256"]):
            raise ValueError("native-ui-output-authority")
        if (remote["python_path"] != "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin/python3.13"
                or remote["gio_path"] != "/nix/store/zcmsivndca5wmam9nwnbjrm0zkgykwfz-glib-2.86.3/lib/libgio-2.0.so.0.8600.3"
                or remote["qt_platform_plugin"] != "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0/lib/qt-6/plugins/platforms/libqwayland.so"
                or any(type(remote[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}",remote[name]) for name in
                    ("python_sha256","gio_sha256","qt_platform_plugin_sha256","dialog_sha256","machine_id_sha256","boot_id_sha256"))
                or type(remote["uid"]) is not int or remote["uid"] < 0
                or remote["wayland_socket"] != "/run/user/"+str(remote["uid"])+"/"+Path(remote["wayland_socket"]).name
                or not re.fullmatch(r"wayland-[0-9]{1,3}",Path(remote["wayland_socket"]).name)
                or any(type(remote[name]) is not int or remote[name] <= 0 for name in ("wayland_device","wayland_inode"))):
            raise ValueError("native-ui-output-runtime-seat")
        inputs.binding_selector(remote["dialog_path"])
        measured_receipts(rows["closure.json"][1],rows["seat.json"][1],remote,self.pins[1],self.pins[2],self.rows_sha256)
        return {name:pin for name,(pin,_) in rows.items()}

    def bindings(self):
        result = [str(self.namespace)+":/omux-native-login-ui-prepare"]
        if self.agent_path is not None:
            result.append(self.agent_path+":"+AGENT_DESTINATION+":norbind")
        return result

    def writable_binding(self):
        return str(self.output)+":"+OUTPUT_DESTINATION

    def verify_bindings(self,actual):
        leaves = [self.agent_path+":"+AGENT_DESTINATION] if self.agent_path is not None else []
        if (normalized_bindings(actual.get("BindReadOnlyPaths",""),leaves,readback=True)
                != normalized_bindings(" ".join(self.bindings()),leaves)
                or normalized_bindings(actual.get("BindPaths",""),readback=True) != {self.writable_binding()}):
            raise ValueError("native-ui-effective-bind-refused")

    def runtime_seconds(self):
        self.budget()
        seconds = (self.deadline-time.monotonic_ns()-30*10**9)//10**9
        if seconds < 1:
            raise ValueError("native-ui-original-deadline")
        return min(1200,seconds)

    def close(self):
        fds,self.fds = self.fds,[]
        failure = False
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                failure = True
        if failure:
            raise OSError("native-ui-descriptor-close-refused")
