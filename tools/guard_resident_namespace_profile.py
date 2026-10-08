"""One exact provider-free resident namespace qualification, never enrollment."""
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import struct
import time
import uuid

import guard_resident_observation as resident
from guard_resident_continuity_profile import session_owners

LABEL = "//delivery:resident_namespace_qualification"
PROFILE = "resident-namespace"
DESTINATION = "/omux-resident-namespace-inputs"
HANDOFF = "namespace-projection.json"
OUTPUT = "resident-namespace-qualification.json"
SCOPE = "provider_free_resident_namespace_qualification"
DEADLINE_VARIABLE = "OMUX_RESIDENT_NAMESPACE_DEADLINE_NS"
LIMIT = 65536
HEX = re.compile(r"[0-9a-f]{64}\Z")
PROOF_MEMORY = resident.PROOF_MEMORY
PROOF_TASKS = resident.PROOF_TASKS
PROOF_CPU_PERCENT = resident.PROOF_CPU_PERCENT

def require(value):
    if not value:
        raise ValueError("resident-namespace-qualification-refused")

def tick(deadline, reserve=0):
    require(type(deadline) is int and time.monotonic_ns()+reserve < deadline)

def finite(arguments, manager, manifest, reuse, unrelated=()):
    require(arguments == ["run", LABEL] and manager == "system" and manifest is not None
            and not reuse and not any(unrelated))
    # Sandbox build actions remain in Bazel; final RUN shares the host PID
    # namespace. No provider network is available in this distinct profile.
    return {"PrivateNetwork": "yes", "ProtectSystem": "strict", "PrivateTmp": "yes", "PrivatePIDs":"no"}

def manifest_schema(value, home, epoch):
    require(type(value) is dict and set(value) == {"schema_version", "action_epoch", "resident"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["action_epoch"] == epoch and str(uuid.UUID(epoch)) == epoch)
    selected = value["resident"]
    paths = resident.fixed_paths(home)
    require(type(selected) is dict and set(selected) == {"ownership", "prefix", "records", "runtime_state",
        "service_path", "archive_sha256", "executable_sha256", "executable_path", "pid", "start_ticks", "installation"}
        and selected["ownership"] == "omux-installation"
        and all(selected[key] == str(path) for key, path in paths.items())
        and all(type(selected[key]) is str and HEX.fullmatch(selected[key])
            for key in ("archive_sha256", "executable_sha256"))
        and type(selected["pid"]) is int and selected["pid"] > 1
        and type(selected["start_ticks"]) is int and selected["start_ticks"] > 0)
    executable = resident.canonical(selected["executable_path"])
    require(executable in (paths["prefix"]/"bin/omuxd", paths["prefix"]/"lib/omux/libexec/omuxd.bin"))
    resident.installation_selection(selected["installation"])
    require(selected["installation"]["archive"]["sha256"] == selected["archive_sha256"])
    return value

class PublicFile:
    """Only public installer/unit/payload/guard metadata may use this reader."""
    def __init__(self, path, limit, mode=None):
        self.parent = self.fd = None
        self.path = resident.canonical(str(path))
        try:
            self.parent = resident.open_directory(self.path.parent)
            self.parent_id = resident.stable(os.fstat(self.parent))
            self.fd = os.open(self.path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                              dir_fd=self.parent)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and 0 < info.st_size <= limit and (mode is None or stat.S_IMODE(info.st_mode) == mode))
            self.identity = resident.file_identity(info)
            self.raw = os.pread(self.fd, limit+1, 0)
            require(len(self.raw) == info.st_size)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        named_parent = resident.open_directory(self.path.parent)
        try:
            require(resident.stable(os.fstat(named_parent)) == self.parent_id
                == resident.stable(os.fstat(self.parent))
                and resident.file_identity(os.fstat(self.fd)) == self.identity
                == resident.file_identity(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False))
                and os.pread(self.fd, len(self.raw)+1, 0) == self.raw)
        finally:
            os.close(named_parent)

    def close(self):
        held=[]
        for name in ("fd", "parent"):
            fd=getattr(self,name,None)
            setattr(self,name,None)
            if fd is not None: held.append(fd)
        resident.close_owned_resources(held)

def write_new(directory, name, value):
    require(name in ("context-pin.json", HANDOFF, OUTPUT))
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()+b"\n"
    require(len(raw) <= LIMIT)
    fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0)
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    return hashlib.sha256(raw).hexdigest()

def socket_peer(path, selected, deadline):
    """Connect without request bytes; strict actual host resident attribution."""
    tick(deadline)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid()
        and stat.S_IMODE(before.st_mode) == 0o600)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(min(2, (deadline-time.monotonic_ns())/10**9))
        channel.connect(str(path))
        peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer == (selected["pid"], os.getuid(), os.getgid()) and peer[0] > 1
                and resident.start_ticks(peer[0]) == selected["start_ticks"])
    tick(deadline)
    require(resident.stable(before) == resident.stable(path.stat(follow_symlinks=False)))
    return resident.stable(before)

def transport_witness(path, deadline):
    tick(deadline)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(min(2, (deadline-time.monotonic_ns())/10**9))
        channel.connect(str(path))
        pid, uid, gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid > 1 and uid == os.getuid() and gid == os.getgid())
        result = (resident.stable(before), pid, resident.start_ticks(pid))
    tick(deadline)
    require(resident.stable(before) == resident.stable(path.stat(follow_symlinks=False)))
    return result

class InstalledObserver:
    """Existing active owned unit/full payload/caps/process; no vault check."""
    def __init__(self, selected, systemctl, deadline):
        self.selected, self.deadline = selected, deadline
        self.systemctl = resident.canonical(str(systemctl))
        require(str(self.systemctl).startswith("/nix/store/") and str(self.systemctl).endswith("/bin/systemctl"))
        self.resources, self.pidfd = [], None
        try:
            self.unit = resident.OwnedUnitCustody(selected)
            self.resources.append(self.unit)
            self.installation = resident.InstallationWitness(selected,self.unit,deadline)
            self.resources.append(self.installation)
            record = json.loads(self.unit.files[0][4], object_pairs_hook=resident.unique)
            require(record["artifact"]["archiveSha256"] == selected["archive_sha256"])
            self.payload = []
            payload_bytes = 0
            for row in record["files"]:
                tick(deadline)
                item = PublicFile(row["path"], 128*1024*1024, row["mode"])
                self.resources.append(item)
                payload_bytes += len(item.raw)
                require(payload_bytes <= 512*1024*1024)
                require(hashlib.sha256(item.raw).hexdigest() == row["sha256"])
                self.payload.append((item, row["sha256"]))
            matching = [row for row in record["files"] if row["path"] == selected["executable_path"]]
            require(len(matching) == 1 and matching[0]["sha256"] == selected["executable_sha256"])
            self.pidfd = os.pidfd_open(selected["pid"], 0)
            self.pid_namespace = resident.stable(Path("/proc/"+str(selected["pid"])+"/ns/pid").stat())
            self.bounds = None
            self.bus = Path('/run/user')/str(os.getuid())/'bus'
            self.owners = session_owners(self.bus,deadline,True)
            self.observe()
        except BaseException:
            self.close()
            raise

    def observe(self):
        tick(self.deadline)
        require(not select.select([self.pidfd], [], [], 0)[0]
            and resident.start_ticks(self.selected["pid"]) == self.selected["start_ticks"]
            and os.readlink("/proc/"+str(self.selected["pid"])+"/exe") == self.selected["executable_path"]
            and resident.stable(Path("/proc/"+str(self.selected["pid"])+"/ns/pid").stat()) == self.pid_namespace)
        self.unit.recheck()
        self.installation.recheck()
        require(session_owners(self.bus,self.deadline,True) == self.owners)
        for item, digest in self.payload:
            tick(self.deadline)
            item.recheck()
            require(hashlib.sha256(item.raw).hexdigest() == digest)
        check = resident.Admission.__new__(resident.Admission)
        check.deadline_ns, check.selected, check.owned_unit = self.deadline, {**self.selected, "action": "enroll-existing"}, self.unit
        check.service_observation(self.systemctl)
        # The pinned helper's private observed_process addition is required.
        require(check.observed_process == (self.selected["pid"], self.selected["start_ticks"]))
        self.bounds = freeze_bounds(check.observed_bounds, self.bounds)

    def close(self):
        for item in reversed(self.resources):
            item.close()
        self.resources = []
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None

def health_projection(value):
    require(type(value) is dict and type(value.get("protocol_version")) is int
        and value["protocol_version"] == 2 and value.get("live_handoff_proven") is False
        and type(value.get("custody_available")) is bool)
    status = value.get("status")
    require(status in ("ready", "repair_required", "vault_locked"))
    if status == "vault_locked":
        require(set(value) == {"protocol_version", "status", "custody_available", "metadata_loaded", "provider_access",
            "live_handoff_proven", "recovery_action"} and value["custody_available"] is False
            and value["metadata_loaded"] is False and value["provider_access"] is False
            and value["recovery_action"] == "unlock_platform_vault_then_restart_daemon")
    else:
        require(value["custody_available"] is (status == "ready"))
        require("metadata_loaded" not in value or type(value["metadata_loaded"]) is bool)
    return {"health_observation": status, "reported_custody_available": value["custody_available"],
        "health_metadata_loaded": "not_reported" if "metadata_loaded" not in value
            else "true" if value["metadata_loaded"] else "false"}

def read_health(runtime, selected, deadline):
    # Fixed request only; never parameterize method/account/source/credentials.
    path = runtime/"control.sock"
    witness = socket_peer(path, selected, deadline)
    request = b'{"jsonrpc":"2.0","id":1,"method":"system.health"}\n'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        def phase():
            tick(deadline)
            channel.settimeout(min(2, (deadline-time.monotonic_ns())/10**9))
        phase()
        channel.connect(str(path))
        require(struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            == (selected["pid"], os.getuid(), os.getgid()))
        phase()
        channel.sendall(request)
        raw = bytearray()
        while b"\n" not in raw:
            phase()
            chunk = channel.recv(min(4096, LIMIT+1-len(raw)))
            require(chunk and len(raw)+len(chunk) <= LIMIT)
            raw.extend(chunk)
    tick(deadline)
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1
        and socket_peer(path, selected, deadline) == witness)
    value = json.loads(raw, object_pairs_hook=resident.unique)
    require(type(value) is dict and set(value) == {"jsonrpc", "id", "result"}
        and value["jsonrpc"] == "2.0" and type(value["id"]) is int and value["id"] == 1)
    return health_projection(value["result"])

FIXED = {"schema_version": 1, "scope": SCOPE, "host_pid_namespace": True, "nonzero_daemon_peer": True,
    "canonical_private_run_shadow": True, "exact_socket_binds_verified": True,
    "foreign_present_canary_denied": True,
    "carrier_provider_requests": 0, "carrier_credential_rpc_calls": 0, "capability_contents_read": False,
    "source_contents_read": False, "wrapping_key_read": False, "account_qualification": False,
    "custody_proven": False, "live_handoff_proven": False}
VARIABLE = {"health_observation", "reported_custody_available", "health_metadata_loaded"}

def validate_projection(value):
    require(type(value) is dict and set(value) == set(FIXED)|VARIABLE
        and all(type(value[key]) is type(expected) and value[key] == expected for key, expected in FIXED.items())
        and value["health_observation"] in ("ready", "repair_required", "vault_locked")
        and type(value["reported_custody_available"]) is bool
        and value["reported_custody_available"] is (value["health_observation"] == "ready")
        and value["health_metadata_loaded"] in ("true", "false", "not_reported")
        and (value["health_observation"] != "vault_locked" or value["health_metadata_loaded"] == "false"))
    return value

def deny_metadata(path):
    # Only the guard-owned, independently host-present public canary; no reads.
    for operation in (lambda: os.stat(path, follow_symlinks=False),
                      lambda: os.open(path, os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)):
        try:
            result = operation()
        except OSError as error:
            require(error.errno in (errno.ENOENT, errno.EACCES, errno.EPERM))
        else:
            if isinstance(result, int):
                os.close(result)
            require(False)

class NamespaceContext:
    @classmethod
    def open(cls):
        return cls()

    def __init__(self):
        self.resources = []
        self.output_fd = self.namespace_fd = None
        try:
            self.deadline = int(os.environ[DEADLINE_VARIABLE])-30*10**9
            tick(self.deadline)
            self.epoch = os.environ["OMUX_RESIDENT_NAMESPACE_EPOCH"]
            self.namespace_fd = resident.open_directory(Path(DESTINATION), True)
            self.namespace_id = resident.stable(os.fstat(self.namespace_fd))
            require(directory_id(os.fstat(self.namespace_fd)) == os.environ["OMUX_RESIDENT_NAMESPACE_INPUT_ID"]
                and set(os.listdir(self.namespace_fd)) == {"input.json", "context-pin.json", "run"})
            self.input = PublicFile(Path(DESTINATION)/"input.json", LIMIT, 0o600)
            self.resources.append(self.input)
            self.value = manifest_schema(json.loads(self.input.raw, object_pairs_hook=resident.unique),
                Path(pwd.getpwuid(os.getuid()).pw_dir), self.epoch)
            self.pin = PublicFile(Path(DESTINATION)/"context-pin.json", LIMIT, 0o600)
            self.resources.append(self.pin)
            self.context = json.loads(self.pin.raw, object_pairs_hook=resident.unique)
            validate_context(self.context, self.value)
            require(self.context["observer_source_sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            self.selected = self.value["resident"]
            self.observer = InstalledObserver(self.selected, os.environ["OMUX_RESIDENT_NAMESPACE_SYSTEMCTL"], self.deadline)
            self.resources.append(self.observer)
            self.output = resident.canonical(os.environ["OMUX_RESIDENT_NAMESPACE_OUTPUT"])
            require(self.output.name == "namespace-handoff" and self.output.parent.name == self.epoch)
            self.output_fd = resident.open_directory(self.output, True)
            require(os.environ["OMUX_RESIDENT_NAMESPACE_OUTPUT_ID"] == directory_id(os.fstat(self.output_fd))
                and not os.listdir(self.output_fd))
            self.output_identity = resident.stable(os.fstat(self.output_fd))
        except BaseException:
            self.close()
            raise

    def run(self):
        self.recheck()
        uid = os.getuid()
        runtime_parent = Path("/run/user")/str(uid)
        runtime = runtime_parent/resident.runtime_child(self.selected["runtime_state"])
        for path in (Path("/run"), Path("/run/user"), runtime_parent, runtime_parent/"systemd", runtime):
            held = resident.open_directory(path, True)
            os.close(held)
        require(os.listdir("/run") == ["user"] and os.listdir("/run/user") == [str(uid)]
            and set(os.listdir(runtime_parent)) == {"bus", "systemd", runtime.name}
            and os.listdir(runtime_parent/"systemd") == ["private"]
            and directory_id(runtime_parent.stat(follow_symlinks=False)) == self.context["shadow_runtime_parent_id"]
            and directory_id(Path("/proc/self/ns/pid").stat()) == self.context["host_pid_namespace_id"]
            and directory_id(Path("/proc/"+str(self.selected["pid"])+"/ns/pid").stat())
                == self.context["host_pid_namespace_id"])
        require(set(os.listdir(runtime)) == {"control.sock", "adapter.sock", "browser.sock"})
        for name in ("control.sock", "adapter.sock", "browser.sock"):
            witness = socket_peer(runtime/name, self.selected, self.deadline)
            require(list(witness) == self.context["daemon_socket_witnesses"][name])
        for path in (runtime_parent/"bus", runtime_parent/"systemd/private"):
            require(resident.stable(path.stat(follow_symlinks=False)) == tuple(self.context["transport_socket_witnesses"][str(path)]))
        for path in (Path("/run"), runtime, runtime_parent/"bus", runtime_parent/"systemd/private"):
            require(os.statvfs(path).f_flag & os.ST_RDONLY)
        deny_metadata(Path(self.context["foreign_canary_path"]))
        projection = validate_projection({**FIXED, **read_health(runtime, self.selected, self.deadline)})
        self.recheck()
        return projection

    def recheck(self):
        tick(self.deadline)
        require(resident.stable(os.fstat(self.namespace_fd)) == self.namespace_id
            == resident.stable(Path(DESTINATION).stat(follow_symlinks=False))
            and set(os.listdir(self.namespace_fd)) == {"input.json", "context-pin.json", "run"})
        assert_shadow_shape(Path(DESTINATION), resident.runtime_child(self.selected["runtime_state"]))
        for item in self.resources:
            if item is not self.observer:
                item.recheck()
        self.observer.observe()
        require(resident.stable(os.fstat(self.output_fd)) == self.output_identity
            == resident.stable(self.output.stat(follow_symlinks=False)))

    def publish(self, projection):
        self.recheck()
        validate_projection(projection)
        write_new(self.output_fd, HANDOFF, {"producer": LABEL, "action_epoch": self.epoch,
            "producer_source_sha256": self.context["producer_source_sha256"],
            "observer_source_sha256": self.context["observer_source_sha256"], "projection": projection})
        self.recheck()

    def close(self):
        for item in reversed(self.resources):
            item.close()
        self.resources = []
        if self.output_fd is not None:
            os.close(self.output_fd)
            self.output_fd = None
        if self.namespace_fd is not None:
            os.close(self.namespace_fd)
            self.namespace_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()

def directory_id(info):
    return str(info.st_dev)+":"+str(info.st_ino)

def validate_context(value, manifest):
    require(type(value) is dict and set(value) == {"producer", "action_epoch", "producer_source_sha256",
        "observer_source_sha256", "daemon_archive_sha256", "daemon_executable_sha256", "host_pid_namespace_id",
        "shadow_runtime_parent_id", "daemon_socket_witnesses", "transport_socket_witnesses", "foreign_canary_path"}
        and value["producer"] == LABEL and value["action_epoch"] == manifest["action_epoch"]
        and all(type(value[key]) is str and HEX.fullmatch(value[key]) for key in
            ("producer_source_sha256", "observer_source_sha256", "daemon_archive_sha256", "daemon_executable_sha256"))
        and value["daemon_archive_sha256"] == manifest["resident"]["archive_sha256"]
        and value["daemon_executable_sha256"] == manifest["resident"]["executable_sha256"]
        and all(type(value[key]) is str and re.fullmatch(r"[0-9]+:[0-9]+", value[key])
            for key in ("host_pid_namespace_id", "shadow_runtime_parent_id"))
        and set(value["daemon_socket_witnesses"]) == {"control.sock", "adapter.sock", "browser.sock"})
    canary = Path("/run/user")/str(os.getuid())/("omux-ns-canary-"+uuid.UUID(manifest["action_epoch"]).hex)
    require(value["foreign_canary_path"] == str(canary))
    parent = canary.parent
    require(set(value["transport_socket_witnesses"]) == {str(parent/"bus"), str(parent/"systemd/private")})
    for witness in [*value["daemon_socket_witnesses"].values(), *value["transport_socket_witnesses"].values()]:
        require(type(witness) is list and len(witness) == 5 and all(type(v) is int for v in witness))
    return value

class Admission:
    """Guard-owned preparation and post-exit observation; no service mutation."""
    def __init__(self, manifest, home, deadline, epoch, systemctl, producer_sha, observer_sha, source_root):
        self.resources, self.held, self.placeholders = [], [], []
        self.canary_fd = self.output_fd = None
        self.deadline_ns, self.action_epoch, self.systemctl = deadline, epoch, systemctl
        deadline -= 30*10**9
        try:
            tick(deadline)
            self.manifest = resident.canonical(str(manifest))
            require(self.manifest.name == "input.json")
            self.root = self.manifest.parent
            self.directory = resident.open_directory(self.root, True)
            self.held.append(self.directory)
            require(os.listdir(self.directory) == ["input.json"])
            self.root_id = resident.stable(os.fstat(self.directory))
            self.input = PublicFile(self.manifest, LIMIT, 0o600)
            self.resources.append(self.input)
            self.value = manifest_schema(json.loads(self.input.raw, object_pairs_hook=resident.unique), home, epoch)
            self.selected = self.value["resident"]
            require(HEX.fullmatch(producer_sha) and HEX.fullmatch(observer_sha)
                and hashlib.sha256((Path(source_root)/"delivery/resident_namespace_qualification.py").read_bytes()).hexdigest() == producer_sha
                and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == observer_sha)
            self.observer = InstalledObserver(self.selected, systemctl, deadline)
            self.resources.append(self.observer)
            parent = Path("/run/user")/str(os.getuid())
            self.parent = parent
            self.parent_fd = resident.open_directory(parent, True)
            self.held.append(self.parent_fd)
            self.parent_id = resident.stable(os.fstat(self.parent_fd))
            self.runtime = parent/resident.runtime_child(self.selected["runtime_state"])
            runtime_fd = resident.open_directory(self.runtime, True)
            self.held.append(runtime_fd)
            self.runtime_fd = runtime_fd
            self.runtime_id = resident.stable(os.fstat(runtime_fd))
            require(set(os.listdir(runtime_fd)) == {"control.sock", "adapter.sock", "browser.sock"})
            sockets = {name: list(socket_peer(self.runtime/name, self.selected, deadline))
                for name in ("control.sock", "adapter.sock", "browser.sock")}
            transport = {}
            for path in (parent/"bus", parent/"systemd/private"):
                witness = transport_witness(path, deadline)
                self.held_transports = getattr(self, "held_transports", [])+[(path, witness)]
                transport[str(path)] = list(witness[0])
            self.canary = parent/("omux-ns-canary-"+uuid.UUID(epoch).hex)
            os.mkdir(self.canary, 0o700)
            self.canary_fd = resident.open_directory(self.canary, True)
            self.canary_id = resident.stable(os.fstat(self.canary_fd))
            run = self.root/"run"
            os.mkdir(run, 0o700)
            os.mkdir(run/"user", 0o700)
            shadow = run/"user"/str(os.getuid())
            os.mkdir(shadow, 0o700)
            os.mkdir(shadow/"systemd", 0o700)
            os.mkdir(shadow/self.runtime.name, 0o700)
            self.shadow_directories = []
            for path in (run, run/"user", shadow, shadow/"systemd", shadow/self.runtime.name):
                fd = resident.open_directory(path, True)
                self.held.append(fd)
                self.shadow_directories.append((path, fd, resident.stable(os.fstat(fd))))
            for path in (shadow/"bus", shadow/"systemd/private"):
                self.placeholders.append(resident.held_mountpoint(path))
            self.context = {"producer": LABEL, "action_epoch": epoch, "producer_source_sha256": producer_sha,
                "observer_source_sha256": observer_sha, "daemon_archive_sha256": self.selected["archive_sha256"],
                "daemon_executable_sha256": self.selected["executable_sha256"],
                "host_pid_namespace_id": directory_id(Path("/proc/self/ns/pid").stat()),
                "shadow_runtime_parent_id": directory_id(shadow.stat(follow_symlinks=False)),
                "daemon_socket_witnesses": sockets, "transport_socket_witnesses": transport,
                "foreign_canary_path": str(self.canary)}
            require(self.context["host_pid_namespace_id"] == directory_id(Path("/proc/"+str(self.selected["pid"])+"/ns/pid").stat()))
            validate_context(self.context, self.value)
            write_new(self.directory, "context-pin.json", self.context)
            self.context_file = PublicFile(self.root/"context-pin.json", LIMIT, 0o600)
            self.resources.append(self.context_file)
            self.facts = {"scope": SCOPE, "provider_free": True, "resident_memory": resident.RESIDENT_MEMORY,
                "resident_tasks": resident.RESIDENT_TASKS, "resident_cpu_percent": resident.RESIDENT_CPU_PERCENT,
                "proof_memory": PROOF_MEMORY, "proof_tasks": PROOF_TASKS, "proof_cpu_percent": PROOF_CPU_PERCENT}
            self.recheck()
        except BaseException:
            self.close()
            raise

    def bind_run(self, run):
        require(self.output_fd is None and Path(run).name == self.action_epoch)
        self.run = resident.canonical(str(run))
        self.run_fd = resident.open_directory(self.run, True)
        self.held.append(self.run_fd)
        self.run_id = resident.stable(os.fstat(self.run_fd))
        os.mkdir("namespace-handoff", 0o700, dir_fd=self.run_fd)
        self.output = self.run/"namespace-handoff"
        self.output_fd = resident.open_directory(self.output, True)
        self.output_id = resident.stable(os.fstat(self.output_fd))

    def recheck(self):
        reserve = 0 if getattr(self,"collecting",False) else 30*10**9
        tick(self.deadline_ns,reserve)
        for path, held, expected in ((self.parent, self.parent_fd, self.parent_id),
                                    (self.runtime, self.runtime_fd, self.runtime_id)):
            named = resident.open_directory(path, True)
            try:
                require(resident.stable(os.fstat(named)) == expected == resident.stable(os.fstat(held)))
            finally:
                os.close(named)
        require(resident.stable(os.fstat(self.directory)) == self.root_id == resident.stable(self.root.stat(follow_symlinks=False))
            and set(os.listdir(self.directory)) == {"input.json", "context-pin.json", "run"}
            and resident.stable(self.runtime.stat(follow_symlinks=False)) == self.runtime_id
            and resident.stable(os.fstat(self.canary_fd)) == self.canary_id
                == resident.stable(self.canary.stat(follow_symlinks=False)) and not os.listdir(self.canary_fd))
        for path, fd, expected in self.shadow_directories:
            require(resident.stable(os.fstat(fd)) == expected == resident.stable(path.stat(follow_symlinks=False)))
        assert_shadow_shape(self.root, self.runtime.name)
        for path, placeholder, witness in self.placeholders:
            require(resident.regular_mountpoint_witness(path, placeholder.fileno()) == witness)
        for path, witness in self.held_transports:
            require(transport_witness(path, self.deadline_ns-reserve) == witness)
        for name, witness in self.context["daemon_socket_witnesses"].items():
            require(list(socket_peer(self.runtime/name, self.selected, self.deadline_ns-reserve)) == witness)
        for item in self.resources:
            if item is not self.observer:
                item.recheck()
        prior = self.observer.deadline
        try:
            self.observer.deadline = self.deadline_ns-reserve
            self.observer.observe()
        finally:
            self.observer.deadline = prior
        if self.output_fd is not None:
            require(resident.stable(os.fstat(self.run_fd)) == self.run_id == resident.stable(self.run.stat(follow_symlinks=False))
                and resident.stable(os.fstat(self.output_fd)) == self.output_id == resident.stable(self.output.stat(follow_symlinks=False)))
        return self.facts

    def bindings(self):
        parent = self.runtime.parent
        return [str(self.root)+":"+DESTINATION, str(self.root/"run")+":/run",
            str(self.runtime)+":"+str(self.runtime), str(parent/"bus")+":"+str(parent/"bus")+":norbind",
            str(parent/"systemd/private")+":"+str(parent/"systemd/private")+":norbind",
            self.selected["prefix"]+":"+self.selected["prefix"], self.selected["records"]+":"+self.selected["records"]]

    def writable_binding(self):
        require(hasattr(self, "run"))
        return str(self.run)+":"+str(self.run)

    def verify_bindings(self, actual, run=None):
        leaves = [binding.removesuffix(":norbind") for binding in self.bindings() if binding.endswith(":norbind")]
        expected = resident.normalize_binds(" ".join(self.bindings()), leaves)
        observed = resident.normalize_binds(actual.get("BindReadOnlyPaths", ""), leaves, readback=True)
        writable = resident.normalize_binds(actual.get("BindPaths", ""), readback=True)
        require(len(expected) == len(observed) and set(expected) == set(observed)
            and writable == [self.writable_binding()] and run == self.run)

    def environment(self):
        return {DEADLINE_VARIABLE: str(self.deadline_ns), "OMUX_RESIDENT_NAMESPACE_EPOCH": self.action_epoch,
            "OMUX_RESIDENT_NAMESPACE_INPUT_ID": directory_id(os.fstat(self.directory)),
            "OMUX_RESIDENT_NAMESPACE_OUTPUT": str(self.output),
            "OMUX_RESIDENT_NAMESPACE_OUTPUT_ID": directory_id(os.fstat(self.output_fd)),
            "OMUX_RESIDENT_NAMESPACE_SYSTEMCTL": str(self.systemctl),
            "XDG_RUNTIME_DIR": str(self.runtime.parent), "DBUS_SESSION_BUS_ADDRESS": "unix:path="+str(self.runtime.parent/"bus")}

    def runtime_seconds(self):
        tick(self.deadline_ns, 30*10**9)
        return int((self.deadline_ns-time.monotonic_ns())//10**9)-30

    def completed(self, status, cleaned, epoch, producer_sha, graph_sha):
        require(type(status) is int and status == 0 and cleaned is True and epoch == self.action_epoch
            and producer_sha == self.context["producer_source_sha256"] and HEX.fullmatch(graph_sha))
        self.collecting = True
        resident.collection_deadline(self.observer,self.resources,self.deadline_ns)
        self.recheck()
        require(os.listdir(self.output_fd) == [HANDOFF])
        incoming = PublicFile(self.output/HANDOFF, LIMIT, 0o600)
        try:
            handoff = json.loads(incoming.raw, object_pairs_hook=resident.unique)
            require(type(handoff) is dict and set(handoff) == {"producer", "action_epoch", "producer_source_sha256",
                "observer_source_sha256", "projection"})
            for key in set(handoff)-{"projection"}:
                require(handoff[key] == self.context[key])
            projection = validate_projection(handoff["projection"])
            require(read_health(self.runtime, self.selected, self.deadline_ns) == {key: projection[key] for key in VARIABLE})
            self.observer.observe()  # Actual controller/proof descendants already exited.
            self.recheck()
            result = {**projection, **{key: self.context[key] for key in ("producer", "action_epoch", "producer_source_sha256",
                "observer_source_sha256", "daemon_archive_sha256", "daemon_executable_sha256")},
                "resident_daemon_same_process": True, "full_installed_payload_matches": True,
                "resident_unit_ownership_preserved": True, "resident_caps_verified": True,
                "resident_caps_preserved": True,
                "resident_active_after_controller": True, "controller_exited": True, "proof_descendants_empty": True,
                "requires_successful_guard_receipt": True, "guard_graph_sha256": graph_sha}
            validate_final(result)
            digest = write_new(self.run_fd, OUTPUT, result)
            incoming.recheck()
            return {"scope": SCOPE, "basename": OUTPUT, "sha256": digest,
                "verified_after_controller_exit": True, "guard_graph_sha256": graph_sha}
        finally:
            incoming.close()

    def close(self):
        for item in reversed(self.resources):
            item.close()
        self.resources = []
        for _, placeholder, _ in self.placeholders:
            placeholder.close()
        self.placeholders = []
        try:
            if self.canary_fd is not None:
                named_parent = resident.open_directory(self.parent, True)
                try:
                    require(resident.stable(os.fstat(named_parent)) == self.parent_id
                        == resident.stable(os.fstat(self.parent_fd)))
                    if resident.stable(os.fstat(self.canary_fd)) == getattr(self, "canary_id", None) \
                        == resident.stable(self.canary.stat(follow_symlinks=False)) and not os.listdir(self.canary_fd):
                        self.canary.rmdir()
                finally:
                    os.close(named_parent)
        finally:
            try:
                if self.canary_fd is not None:
                    os.close(self.canary_fd)
                    self.canary_fd = None
            finally:
                try:
                    for fd in reversed(self.held):
                        os.close(fd)
                    self.held = []
                finally:
                    if self.output_fd is not None:
                        os.close(self.output_fd)
                        self.output_fd = None

def projection(actual, verified=False):
    return resident.projection(actual, verified)

def rejection(error):
    return "resident-namespace-qualification-refused"

def freeze_bounds(actual, frozen):
    require(type(actual) is tuple and len(actual) == 6)
    require(frozen is None or actual == frozen)
    return actual

def assert_shadow_shape(root, runtime_name):
    shadow = root/"run/user"/str(os.getuid())
    require(os.listdir(root/"run") == ["user"] and os.listdir(root/"run/user") == [str(os.getuid())]
        and set(os.listdir(shadow)) == {"bus", "systemd", runtime_name}
        and os.listdir(shadow/"systemd") == ["private"] and not os.listdir(shadow/runtime_name))

FINAL_FIXED = {"resident_daemon_same_process": True, "full_installed_payload_matches": True,
    "resident_unit_ownership_preserved": True, "resident_caps_verified": True, "resident_caps_preserved": True,
    "resident_active_after_controller": True, "controller_exited": True, "proof_descendants_empty": True,
    "requires_successful_guard_receipt": True}
FINAL_PINS = {"producer_source_sha256", "observer_source_sha256", "daemon_archive_sha256",
              "daemon_executable_sha256", "guard_graph_sha256"}

def validate_final(value):
    require(type(value) is dict and set(value) == set(FIXED)|VARIABLE|set(FINAL_FIXED)|FINAL_PINS|{"producer", "action_epoch"})
    validate_projection({key: value[key] for key in set(FIXED)|VARIABLE})
    require(all(type(value[key]) is type(expected) and value[key] == expected for key, expected in FINAL_FIXED.items())
        and value["producer"] == LABEL and type(value["action_epoch"]) is str
        and str(uuid.UUID(value["action_epoch"])) == value["action_epoch"]
        and all(type(value[key]) is str and HEX.fullmatch(value[key]) for key in FINAL_PINS))
    return value

def validate_guard_join(final, outer, digest):
    validate_final(final)
    require(type(digest) is str and HEX.fullmatch(digest) and type(outer) is dict
        and outer["id"] == final["action_epoch"] and outer["profile"] == PROFILE
        and outer["verb"] == "run" and outer["targets"] == [LABEL]
        and type(outer["exit"]) is int and outer["exit"] == 0
        and type(outer["workload_exit"]) is int and outer["workload_exit"] == 0
        and outer["descendants_empty"] is True and outer["cleanup"]["state"] == "empty"
        and outer["controller_failure"] is None and outer["graph_sha256"] == final["guard_graph_sha256"]
        and outer["resident_namespace"]["verified_after_cleanup"] is True
        and outer["resident_namespace"]["output"]["sha256"] == digest
        and outer["resident_namespace"]["output"]["basename"] == OUTPUT
        and outer["resident_namespace"]["output"]["verified_after_controller_exit"] is True)
    return True
