"""Exact persistent enrollment lane with a complementary resident reservation."""
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess
import time

LABEL = "//delivery:resident_codex_enrollment"
LIFECYCLE_LABEL = "//delivery:resident_owned_lifecycle"
PROFILE = "resident-enrollment"
DESTINATION = "/omux-resident-inputs"
VARIABLE = "OMUX_RESIDENT_ENROLLMENT_MANIFEST"
DEADLINE_VARIABLE = "OMUX_RESIDENT_ORIGINAL_DEADLINE_NS"
RESIDENT_MEMORY = 268435456
RESIDENT_TASKS = 32
RESIDENT_CPU_PERCENT = 10
PROOF_MEMORY = 4294967296 - RESIDENT_MEMORY
PROOF_TASKS = 512 - RESIDENT_TASKS
PROOF_CPU_PERCENT = 200 - RESIDENT_CPU_PERCENT

def require(value):
    if not value:
        raise ValueError("resident-enrollment-admission-refused")

def finite(arguments,manager,manifest,reuse,unrelated=()):
    require(arguments in (["run",LABEL],["run",LIFECYCLE_LABEL]) and manager == "system" and manifest is not None
        and not reuse and not any(unrelated))
    return {"PrivateNetwork":"yes","ProtectSystem":"strict","PrivateTmp":"yes"}

# Public dependency inputs already used by the standard offline build lane.
REPOSITORY_CACHE = Path("/srv/fast-local/jess/state/codex/omux-bazel9-owner-coordinator-20261004/cache/repos/v1")
NIXPKGS_SOURCE = Path("/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source")

def repository_inputs(repository_cache,nixpkgs_source):
    # A repository cache contains hash-addressed BCR metadata as well as archives.
    # This does not select/reuse any output-base or authorize downloads.
    if repository_cache is None and nixpkgs_source is None:
        return []
    require(isinstance(repository_cache,Path) and isinstance(nixpkgs_source,Path)
        and repository_cache == REPOSITORY_CACHE and nixpkgs_source == NIXPKGS_SOURCE)
    return [str(REPOSITORY_CACHE)+":"+str(REPOSITORY_CACHE)]

def carrier_purpose(label,action):
    require(label in (LABEL,LIFECYCLE_LABEL)
        and (action in ("observe-existing","stop-idle-owned")) == (label == LIFECYCLE_LABEL))

def canonical(value):
    require(type(value) is str and value.startswith("/") and len(value) <= 4096
        and not any(c.isspace() or c in ":\\\0" for c in value)
        and not any(p in ("",".","..") for p in value.split("/")[1:]))
    return Path(value)

def runtime_child(state):
    # Match src/paths.zig: hash exact state bytes, render the first16 bytes.
    state = canonical(str(state))
    return "omux-" + hashlib.sha256(str(state).encode("utf-8")).digest()[:16].hex()

def runtime_binding(state,uid):
    require(type(uid) is int and uid >= 0)
    child = runtime_child(state)
    return str(Path("/run/user")/str(uid)/child)+":"+str(Path(DESTINATION)/child)

def unique(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result)
        result[key] = value
    return result

def fixed_paths(home,instance="default"):
    require(instance == "default")
    home = canonical(str(home))
    prefix = home/".local/share/omux"
    return {"prefix":prefix,"records":home/".local/state/omux-install",
        "runtime_state":home/".local/state/omux",
        "service_path":prefix/"units/ai.xoxd.omux.service"}

def manifest_schema(value,home):
    updating = type(value) is dict and value.get("action") == "update-existing"
    starting = type(value) is dict and value.get("action") in ("start-existing","observe-existing","stop-idle-owned")
    stopping = type(value) is dict and value.get("action") == "stop-idle-owned"
    require(type(value) is dict and set(value) == {"schema_version","ownership","action","instance",
        "prefix","records","runtime_state","service_path","native_context","permissions"} | ({"update"} if updating else {"start"} if starting else set())
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["ownership"] in ("omux-installation","home-manager")
        and value["action"] in ("install-and-enroll","activate-existing-and-enroll","enroll-existing","update-existing","start-existing","observe-existing","stop-idle-owned")
        and value["instance"] == "default")
    expected = fixed_paths(home)
    for key in ("records","runtime_state"):
        require(canonical(value[key]) == expected[key])
    prefix,unit = canonical(value["prefix"]),canonical(value["service_path"])
    if value["ownership"] == "omux-installation":
        require(prefix == expected["prefix"] and unit == expected["service_path"])
    else:
        require(value["action"] == "enroll-existing" and prefix.parts[:3] == ("/","nix","store")
            and len(prefix.parts) == 4 and re.fullmatch(r"[a-z0-9]{32}[-][A-Za-z0-9+._-]+",prefix.name)
            and unit == canonical(str(home/".config/systemd/user/ai.xoxd.omux.service")))
    permissions = value["permissions"]
    require(type(permissions) is dict and set(permissions) == {"connect_source","activate_service","restart_daemon"} | ({"stop_service"} if stopping else set())
        and all(type(v) is bool for v in permissions.values()))
    if starting:
        expected_permissions={"connect_source":False,"activate_service":value["action"] == "start-existing","restart_daemon":False}
        if stopping:
            expected_permissions["stop_service"]=True
        require(value["ownership"] == "omux-installation" and value["native_context"] is None
            and permissions == expected_permissions)
        import guard_resident_owned_update as update
        update.start_pins(value["start"],home)
    elif updating:
        require(value["ownership"] == "omux-installation" and value["native_context"] is None
            and not any(permissions.values()))
        import guard_resident_owned_update as update
        update.pins(value["update"],home)
    else:
        context = value["native_context"]
        require(type(context) is dict and set(context) == {"application","provenance","codex_home"}
            and context["application"] == "codex" and context["provenance"] == "authorized-working-native-context")
        source_home = canonical(context["codex_home"])
        for path in (prefix,expected["records"],expected["runtime_state"]):
            require(path != source_home and path not in source_home.parents and source_home not in path.parents)
        require(permissions["connect_source"]
            and (value["action"] not in ("install-and-enroll","activate-existing-and-enroll") or permissions["activate_service"])
            and (value["ownership"] != "home-manager" or not permissions["activate_service"]))
    return value

def quota_us(value):
    from decimal import Decimal
    require(type(value) is str and re.fullmatch(r"[0-9]+(?:[.][0-9]{1,6})?(?:us|ms|s)",value))
    unit = "us" if value.endswith("us") else "ms" if value.endswith("ms") else "s"
    result = Decimal(value[:-len(unit)])*{"us":1,"ms":1000,"s":1000000}[unit]
    require(result == int(result) and 0 < result <= 100000)
    return int(result)

def check_resident_bounds(properties,cgroup_values):
    memory,tasks = str(properties.get("MemoryMax")),str(properties.get("TasksMax"))
    require(memory.isdecimal() and tasks.isdecimal() and 0 < int(memory) <= RESIDENT_MEMORY
        and 0 < int(tasks) <= RESIDENT_TASKS and str(properties.get("MemorySwapMax")) == "0")
    cpu = quota_us(properties.get("CPUQuotaPerSecUSec"))
    require(cgroup_values["memory.max"] == memory and cgroup_values["memory.swap.max"] == "0"
        and cgroup_values["pids.max"] == tasks)
    fields = cgroup_values["cpu.max"].split()
    require(len(fields) == 2 and all(v.isdecimal() for v in fields))
    quota,period = map(int,fields)
    require(0 < quota and 0 < period and quota*1000000 <= cpu*period)
    return True

def start_ticks(pid):
    require(type(pid) is int and pid > 1 and Path("/proc/"+str(pid)).stat().st_uid == os.getuid())
    raw = Path("/proc/"+str(pid)+"/stat").read_text()
    return int(raw[raw.rfind(")")+2:].split()[19])

def observe_existing_session_services(environment,deadline_ns,probe,*,allow_missing_secret_service=False):
    require(type(allow_missing_secret_service) is bool)
    require(environment.get("DBUS_SESSION_BUS_ADDRESS") == "unix:path="+DESTINATION+"/bus")
    now = time.monotonic_ns()
    require(type(deadline_ns) is int and now < deadline_ns <= now+1200*10**9)
    remaining = min(20,(deadline_ns-now)/10**9)
    probe_environment = dict(environment)
    probe_environment[DEADLINE_VARIABLE] = str(deadline_ns)
    result = subprocess.run([str(probe)] + (["--allow-missing-secret-service-before-first-start"]
        if allow_missing_secret_service else []),env=probe_environment,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining,check=False)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 4096)
    value = json.loads(result.stdout,object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {"schema_version","broker","manager","secret_service"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1)
    for name in ("broker","manager","secret_service"):
        row = value[name]
        if row is None:
            require(name == "secret_service" and allow_missing_secret_service)
            continue
        require(type(row) is dict and set(row) == ({"pid","uid"} if name == "broker" else {"owner","pid","uid"})
            and type(row["uid"]) is int and row["uid"] == os.getuid()
            and type(row["pid"]) is int)
        if name != "broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))
        row["start_ticks"] = start_ticks(row["pid"])
    return value

def validate_session_observation(value,allow_missing=False):
    require(type(value) is dict and set(value) == {"schema_version","broker","manager","secret_service"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1)
    for name in ("broker","manager","secret_service"):
        row = value[name]
        if row is None:
            require(name == "secret_service" and allow_missing)
            continue
        require(type(row) is dict and set(row) == ({"pid","uid","start_ticks"} if name == "broker"
            else {"owner","pid","uid","start_ticks"})
            and type(row["pid"]) is int and row["pid"] > 1
            and type(row["uid"]) is int and row["uid"] == os.getuid()
            and type(row["start_ticks"]) is int and row["start_ticks"] > 0)
        if name != "broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))

def same_session_transport(before,after):
    validate_session_observation(before,True)
    validate_session_observation(after,True)
    return before["broker"] == after["broker"] and before["manager"] == after["manager"]

def freeze_session_owners(before,after,*,allow_platform_activation=False):
    require(type(allow_platform_activation) is bool and same_session_transport(before,after))
    validate_session_observation(after,False)
    if before["secret_service"] is None:
        require(allow_platform_activation)
    else:
        require(before["secret_service"] == after["secret_service"])
    # Only the declared new-first-install caller may permit initial absence.
    # Once frozen, default comparisons require the same full provider identity.
    return after

def projection(actual,verified=False):
    result = dict(actual)
    result["BindReadOnlyPaths"] = "verified-resident-inputs" if verified else "resident-inputs-redacted"
    result["BindPaths"] = "verified-owned-product-writes" if verified else "resident-product-writes-redacted"
    return result

def rejection(error):
    return "resident-enrollment-admission-refused"

def stable(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)

def open_directory(path,private=False):
    path = canonical(str(path))
    descriptor = os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode & 0o022)
        info = os.fstat(descriptor)
        require(not private or info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def socket_witness(path,connect=True):
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() )
    if connect:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(str(path))
            pid,uid,gid = struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(uid == os.getuid() and pid > 1)
            witness = (stable(info),pid,start_ticks(pid))
        require(stable(info) == stable(path.stat(follow_symlinks=False)))
        return witness
    require(not info.st_mode & 0o022)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(1)
        try:
            peer.connect(str(path))
        except ConnectionRefusedError:
            return stable(info)
        require(False)

def regular_mountpoint(path):
    descriptor = os.open(path,os.O_RDONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(descriptor,0o600)
        placeholder = os.fdopen(descriptor,"rb")
    except BaseException:
        os.close(descriptor)
        raise
    return placeholder

def regular_mountpoint_witness(path,descriptor):
    info = os.fstat(descriptor)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0
        and stable(info) == stable(path.stat(follow_symlinks=False)))
    return stable(info)

def normalize_binds(value,leaf_bindings=(),*,readback=False):
    result = []
    leaf_bindings = set(leaf_bindings)
    for item in value.split():
        parts = item.split(":")
        option = parts.pop() if len(parts) == 3 else None
        require(len(parts) == 2)
        binding = ":".join(parts)
        # Pinned systemctl serializes a nonrecursive bind with no suffix.
        if readback:
            require(option is None if binding in leaf_bindings else option == "rbind")
        else:
            require(option == "norbind" if binding in leaf_bindings else option in (None,"rbind"))
        result.append(binding)
    return result

def file_identity(info):
    return tuple(getattr(info,name) for name in ("st_dev","st_ino","st_mode","st_uid","st_gid",
        "st_nlink","st_size","st_mtime_ns","st_ctime_ns"))

def resolve_owned_unit_fragment(fragment,selected_service):
    selected = canonical(str(selected_service))
    require(selected.name == "ai.xoxd.omux.service" and len(selected.parents) >= 5
        and selected == fixed_paths(selected.parents[4])["service_path"])
    fragment = canonical(str(fragment))
    alias = selected.parents[4]/".config/systemd/user"/selected.name
    require(fragment in (selected,alias))
    parent = open_directory(fragment.parent)
    physical_parent = None
    descriptor = None
    try:
        physical_parent = open_directory(selected.parent)
        require(os.fstat(parent).st_uid == os.getuid()
            and os.fstat(physical_parent).st_uid == os.getuid())
        before = os.stat(fragment.name,dir_fd=parent,follow_symlinks=False)
        if fragment == alias:
            require(stat.S_ISLNK(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and os.readlink(fragment.name,dir_fd=parent) == str(selected))
        descriptor = os.open(selected.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
            dir_fd=physical_parent)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
            and 0 < info.st_size <= 65536
            and file_identity(info) == file_identity(os.stat(selected.name,
                dir_fd=physical_parent,follow_symlinks=False))
            and file_identity(before) == file_identity(os.stat(fragment.name,dir_fd=parent,follow_symlinks=False)))
        if fragment == alias:
            require(os.readlink(fragment.name,dir_fd=parent) == str(selected))
        return selected
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if physical_parent is not None:
            os.close(physical_parent)
        os.close(parent)

class OwnedUnitCustody:
    """Hold only public installer metadata and the recorded unit, never native auth."""
    def __init__(self,selected):
        self.selected = selected
        self.held = []
        self.files = []
        self.alias = None
        try:
            prefix,records,unit = (canonical(selected[name]) for name in ("prefix","records","service_path"))
            require(selected["ownership"] == "omux-installation")
            for path,limit in ((records/"install.json",131072),(unit,65536)):
                parent = open_directory(path.parent)
                self.held.append(parent)
                require(os.fstat(parent).st_uid == os.getuid())
                descriptor = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                self.held.append(descriptor)
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and 0 < info.st_size <= limit)
                raw = os.pread(descriptor,limit+1,0)
                require(len(raw) == info.st_size)
                self.files.append((path,parent,descriptor,file_identity(info),raw,stable(os.fstat(parent))))
            record = json.loads(self.files[0][4],object_pairs_hook=unique)
            require(type(record) is dict and set(record) == {"schemaVersion","prefix","product","userService",
                "serviceActivated","artifact","files"} and type(record["schemaVersion"]) is int
                and record["schemaVersion"] == 1 and record["prefix"] == str(prefix)
                and record["userService"] == str(unit) and type(record["serviceActivated"]) is bool
                and type(record["artifact"]) is dict
                and type(record["artifact"].get("archiveSha256")) is str
                and re.fullmatch(r"[0-9a-f]{64}",record["artifact"]["archiveSha256"]))
            rows = record["files"]
            require(type(rows) is list and 0 < len(rows) <= 256)
            seen = set()
            unit_row = None
            for row in rows:
                require(type(row) is dict and set(row) == {"path","sha256","mode"}
                    and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"])
                    and type(row["mode"]) is int and row["mode"] in (0o600,0o644,0o755))
                path = canonical(row["path"])
                require(path not in seen)
                seen.add(path)
                relative = str(path.relative_to(prefix)) if prefix in path.parents else ""
                require(path == unit or relative in ("bin/omux","bin/omuxd","bin/oauth-mux",
                    "bin/omux-native-host","bin/git-credential-omux","bin/omux-control")
                    or re.fullmatch(r"lib/omux/(?:lib/[A-Za-z0-9_.+-]+|libexec/omuxd?\.bin|share/ca-bundle\.crt|qt/lib/[A-Za-z0-9_.+-]+|qt/libexec/(?:omux-control\.bin|qt\.conf)|qt/plugins/platforms/[A-Za-z0-9_.+-]+\.so)",relative))
                if path == unit:
                    unit_row = row
            require(unit_row is not None and unit_row["mode"] == 0o600
                and hashlib.sha256(self.files[1][4]).hexdigest() == unit_row["sha256"])
            self.recheck()
        except BaseException:
            self.close()
            raise

    def verify_fragment(self,fragment):
        selected = resolve_owned_unit_fragment(fragment,self.selected["service_path"])
        fragment = canonical(str(fragment))
        if fragment != selected:
            parent = open_directory(fragment.parent)
            try:
                witness = file_identity(os.stat(fragment.name,dir_fd=parent,follow_symlinks=False))
                if self.alias is None:
                    self.held.append(parent)
                    self.alias = (fragment,parent,witness,stable(os.fstat(parent)))
                    parent = None
                else:
                    require(fragment == self.alias[0] and witness == self.alias[2])
            finally:
                if parent is not None:
                    os.close(parent)
        self.recheck()
        return selected

    def recheck(self):
        for path,parent,descriptor,witness,raw,parent_witness in self.files:
            current_parent = open_directory(path.parent)
            try:
                require(stable(os.fstat(parent)) == parent_witness == stable(os.fstat(current_parent)))
            finally:
                os.close(current_parent)
            require(file_identity(os.fstat(descriptor)) == witness
                == file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))
                and os.pread(descriptor,len(raw)+1,0) == raw)
        if self.alias is not None:
            path,parent,witness,parent_witness = self.alias
            current_parent = open_directory(path.parent)
            try:
                require(stable(os.fstat(parent)) == parent_witness == stable(os.fstat(current_parent)))
            finally:
                os.close(current_parent)
            require(file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) == witness
                and os.readlink(path.name,dir_fd=parent) == self.selected["service_path"])
            resolve_owned_unit_fragment(path,self.selected["service_path"])

    def close(self):
        for descriptor in reversed(self.held):
            os.close(descriptor)
        self.held = []

def recovery_loaded_properties(values):
    require(values["LoadState"] == "loaded" and values["ActiveState"] == "inactive"
        and values["SubState"] == "dead" and values["MainPID"] == "0" and values["ControlGroup"] == "")
    require(values["UnitFileState"] == "enabled")
    require(values["MemoryMax"] == str(RESIDENT_MEMORY) and values["MemorySwapMax"] == "0"
        and values["TasksMax"] == str(RESIDENT_TASKS) and quota_us(values["CPUQuotaPerSecUSec"]) == 100000)

class Admission:
    def __init__(self,manifest,home,deadline_ns,*,label=LABEL):
        self.deadline_ns = deadline_ns
        require(label in (LABEL,LIFECYCLE_LABEL))
        self.label=label
        self.lifecycle_identity=None
        self.lifecycle_peer=None
        self.manifest = canonical(str(manifest))
        require(self.manifest.name == "input.json")
        self.root = self.manifest.parent
        self.held = []
        self.created_sockets = []
        self.created_manager = False
        self.created_control = None
        self.owned_unit = None
        self.recovery_empty = []
        self.installation_update = None
        self.owned_start = None
        try:
            self.directory = open_directory(self.root,private=True)
            self.held.append(self.directory)
            require(os.listdir(self.directory) == ["input.json"])
            os.mkdir("systemd",0o700,dir_fd=self.directory)
            self.created_manager = True
            self.created_manager_identity = stable((self.root/"systemd").stat(follow_symlinks=False))
            # Leaf mountpoints are held empty regular files, never live sockets.
            # The mounted sources remain exact peer-checked AF_UNIX endpoints.
            for path in (self.root/"bus",self.root/"systemd/private"):
                placeholder = regular_mountpoint(path)
                self.created_sockets.append((placeholder,path,stable(os.fstat(placeholder.fileno()))))
                regular_mountpoint_witness(path,placeholder.fileno())
            self.manager_directory = open_directory(self.root/"systemd",private=True)
            self.held.append(self.manager_directory)
            require(os.listdir(self.manager_directory) == ["private"])
            self.root_identity = stable(os.fstat(self.directory))
            self.manager_identity = stable(os.fstat(self.manager_directory))
            self.placeholder = {path:(placeholder.fileno(),witness)
                for placeholder,path,witness in self.created_sockets}
            self.sources = {self.root/"bus":Path("/run/user/"+str(os.getuid())+"/bus"),
                self.root/"systemd/private":Path("/run/user/"+str(os.getuid())+"/systemd/private")}
            self.source_parents = []
            runtime = Path("/run/user/"+str(os.getuid()))
            runtime_fd = open_directory(runtime,private=True)
            self.held.append(runtime_fd)
            self.source_parents.append((runtime,runtime_fd,stable(os.fstat(runtime_fd))))
            for path in self.sources.values():
                fd = open_directory(path.parent)
                require(os.fstat(fd).st_uid == os.getuid())
                self.held.append(fd)
                self.source_parents.append((path.parent,fd,stable(os.fstat(fd))))
            self.socket_identities = {path:socket_witness(path) for path in self.sources.values()}
            self.file = os.open("input.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.directory)
            self.held.append(self.file)
            info = os.fstat(self.file)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink == 1 and 0 < info.st_size <= 65536)
            self.file_identity = tuple(getattr(info,n) for n in ("st_dev","st_ino","st_uid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
            self.raw = os.pread(self.file,65537,0)
            require(len(self.raw) == info.st_size)
            self.selected = manifest_schema(json.loads(self.raw,object_pairs_hook=unique),home)
            carrier_purpose(label,self.selected["action"])
            self.control_child = runtime_child(self.selected["runtime_state"])
            self.control_source = runtime/self.control_child
            control_source_fd = open_directory(self.control_source,private=True)
            self.held.append(control_source_fd)
            self.source_parents.append((self.control_source,control_source_fd,stable(os.fstat(control_source_fd))))
            if self.selected["action"] in ("install-and-enroll","activate-existing-and-enroll","start-existing"):
                require(not os.listdir(control_source_fd))
            if self.selected["action"] == "activate-existing-and-enroll":
                self.recovery_empty.append(control_source_fd)
            os.mkdir(self.control_child,0o700,dir_fd=self.directory)
            control_placeholder = self.root/self.control_child
            self.created_control = (control_placeholder,stable(control_placeholder.stat(follow_symlinks=False)))
            control_placeholder_fd = open_directory(control_placeholder,private=True)
            self.held.append(control_placeholder_fd)
            self.source_parents.append((control_placeholder,control_placeholder_fd,self.created_control[1]))
            self.product_directories = []
            for name in ("records","runtime_state")+ (("prefix",) if self.selected["ownership"] == "omux-installation" else ()):
                path = canonical(self.selected[name])
                fd = open_directory(path,private=True)
                self.held.append(fd)
                self.product_directories.append((path,fd,stable(os.fstat(fd))))
                if self.selected["action"] == "install-and-enroll":
                    require(not os.listdir(fd))
                elif self.selected["action"] == "activate-existing-and-enroll" and name == "runtime_state":
                    require(not os.listdir(fd))
                    self.recovery_empty.append(fd)
            if self.selected["action"] == "activate-existing-and-enroll":
                self.owned_unit = OwnedUnitCustody(self.selected)
                selected_unit = canonical(self.selected["service_path"])
                self.owned_unit.verify_fragment(selected_unit.parents[4]/".config/systemd/user"/selected_unit.name)
            if self.selected["action"] == "update-existing":
                import guard_resident_owned_update as update
                self.installation_update = update.InstallationUpdate(self.selected,home,deadline_ns)
            if self.selected["action"] in ("start-existing","observe-existing","stop-idle-owned"):
                import guard_resident_owned_update as update
                self.owned_start = update.OwnedFirstStart(self.selected,home,deadline_ns)
            self.facts = self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        require(time.monotonic_ns() < self.deadline_ns)
        require(stable(os.fstat(self.directory)) == self.root_identity == stable(self.root.stat(follow_symlinks=False))
            and stable(os.fstat(self.manager_directory)) == self.manager_identity
            == stable((self.root/"systemd").stat(follow_symlinks=False))
            and set(os.listdir(self.directory)) == {"input.json","bus","systemd",self.control_child}
            and os.listdir(self.manager_directory) == ["private"])
        require(not os.listdir(self.root/self.control_child))
        info = os.fstat(self.file)
        identity = tuple(getattr(info,n) for n in ("st_dev","st_ino","st_uid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
        require(identity == self.file_identity and os.pread(self.file,65537,0) == self.raw)
        named = os.stat("input.json",dir_fd=self.directory,follow_symlinks=False)
        require(tuple(getattr(named,n) for n in ("st_dev","st_ino","st_uid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")) == identity)
        for path,(descriptor,witness) in self.placeholder.items():
            require(regular_mountpoint_witness(path,descriptor) == witness)
        for path,witness in self.socket_identities.items():
            require(socket_witness(path) == witness)
        for path,fd,witness in self.source_parents+self.product_directories:
            require(stable(os.fstat(fd)) == witness == stable(path.stat(follow_symlinks=False)))
        if getattr(self,"installation_update",None) is not None:
            self.installation_update.recheck()
        if getattr(self,"owned_start",None) is not None:
            self.owned_start.recheck()
        if self.owned_unit is not None:
            self.owned_unit.recheck()
        facts = {"scope":"resident-enrollment","source_contents_read":False,
            "resident_memory":RESIDENT_MEMORY,"resident_tasks":RESIDENT_TASKS,"resident_cpu_percent":RESIDENT_CPU_PERCENT,
            "proof_memory":PROOF_MEMORY,"proof_tasks":PROOF_TASKS,"proof_cpu_percent":PROOF_CPU_PERCENT}
        if getattr(self,"installation_update",None) is not None:
            facts.update(action="update-existing",installation_witness_transition_completed=self.installation_update.finished,
                archive_sha256=self.selected["update"]["archive_sha256"],
                previous_archive_sha256=self.selected["update"]["previous_archive_sha256"],
                qualification_guard_sha256=self.selected["update"]["qualification"]["sha256"],
                runtime_metadata_preserved=True,service_started=False,source_connected=False)
        return facts

    def bindings(self):
        starting = getattr(self,"owned_start",None)
        extra = ([str(path)+":"+str(path) for path,_,_ in self.product_directories]+[
            str(public.path)+":"+str(public.path)+":norbind" for public in starting.files[:2]]) if starting is not None else []
        return extra+list(getattr(self,"offline_repository_bindings",()))+[str(self.root)+":"+DESTINATION]+[
            str(source)+":"+DESTINATION+"/"+str(target.relative_to(self.root))+":norbind"
            for target,source in self.sources.items()] + [runtime_binding(self.selected["runtime_state"],os.getuid())] + (
            [self.selected["runtime_state"]+":"+self.selected["runtime_state"]]+[
                str(file.path)+":"+str(file.path)+":norbind" for file in
                (self.installation_update.archive,self.installation_update.previous_archive,self.installation_update.qualification)]
            if getattr(self,"installation_update",None) is not None else [])

    def writable_binding(self):
        if getattr(self,"owned_start",None) is not None:
            return ""
        return " ".join(str(path)+":"+str(path) for path,_,_ in self.product_directories
            if getattr(self,"installation_update",None) is None or str(path) != self.selected["runtime_state"])

    def verify_bindings(self,actual,run=None):
        expected_rw = normalize_binds(self.writable_binding())
        if run is not None:
            expected_rw.append(str(run)+":"+str(run))
        leaves = [str(source)+":"+DESTINATION+"/"+str(target.relative_to(self.root))
            for target,source in self.sources.items()]
        if getattr(self,"owned_start",None) is not None:
            leaves += [str(public.path)+":"+str(public.path) for public in self.owned_start.files[:2]]
        if getattr(self,"installation_update",None) is not None:
            leaves += [str(file.path)+":"+str(file.path) for file in
                (self.installation_update.archive,self.installation_update.previous_archive,self.installation_update.qualification)]
        expected_ro = normalize_binds(" ".join(self.bindings()),leaves)
        ro,rw = normalize_binds(actual.get("BindReadOnlyPaths",""),leaves,readback=True),normalize_binds(actual.get("BindPaths",""),readback=True)
        require(len(ro) == len(expected_ro) and set(ro) == set(expected_ro)
            and len(rw) == len(expected_rw) and set(rw) == set(expected_rw))

    def service_observation(self,systemctl,starting=False):
        env = {"HOME":pwd.getpwuid(os.getuid()).pw_dir,"LC_ALL":"C",
            "XDG_RUNTIME_DIR":"/run/user/"+str(os.getuid()),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/"+str(os.getuid())+"/bus"}
        remaining = min(15,(self.deadline_ns-time.monotonic_ns())/10**9)
        require(remaining > 0)
        recovering_action = self.selected["action"] in ("activate-existing-and-enroll","update-existing","start-existing","observe-existing","stop-idle-owned")
        properties = "LoadState,ActiveState,SubState,MainPID,FragmentPath,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec"
        if recovering_action:
            properties += ",UnitFileState"
        if self.selected["action"] in ("update-existing","start-existing","observe-existing","stop-idle-owned"):
            import guard_resident_owned_update as update
            properties = ",".join(sorted(update.IDLE_PROPERTIES))
        result = subprocess.run([str(systemctl),"--user","show","--property="+properties,
            "ai.xoxd.omux.service"],env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining,check=False)
        require(type(starting) is bool)
        starting_new = starting and self.selected["action"] == "install-and-enroll" \
            and self.selected["ownership"] == "omux-installation"
        require(result.returncode in ((0,4) if starting_new else (0,))
            and not result.stderr and len(result.stdout) <= 16384)
        values = unique(line.split("=",1) for line in result.stdout.decode("ascii").splitlines())
        require(set(values) == {"LoadState","ActiveState","SubState","MainPID","FragmentPath","ControlGroup",
            "MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec"} | ({"UnitFileState"} if recovering_action else set())
            | ({"Slice","ExecStart","DropInPaths","NeedDaemonReload"} if self.selected["action"] in ("update-existing","start-existing","observe-existing","stop-idle-owned") else set()))
        if self.selected["action"] in ("start-existing","observe-existing","stop-idle-owned"):
            require(self.owned_start is not None)
            self.owned_start.recheck()
            action=self.selected["action"]
            if starting and action == "start-existing":
                self.owned_start.pristine()
                update.inactive_installation(values,self.selected)
                update.inactive_cgroup(self.deadline_ns)
                return {"active":False,"owned_first_start_admitted":True,"bounded":True}
            if action == "stop-idle-owned" and not starting:
                require(self.lifecycle_identity is not None)
                update.inactive_installation(values,self.selected)
                update.inactive_cgroup(self.deadline_ns)
                self.owned_start.pristine()
                require(not os.listdir(self.control_source))
                update.original_process_exited(self.lifecycle_identity[0])
                return {"active":False,"owned_idle_stop_observed":True,"bounded":True,
                    "resident_service_disposition":"stopped_explicitly_custody_retained",
                    "custody_claim_requires_controller_success":True}
            pid,group = update.active_start_properties(values,self.selected)
            # Reuse the declared public process/cgroup projection, never raw state.
            from resident_enrollment import process_identity,cgroup_observation
            identity = process_identity(pid)
            caps,cgroup = cgroup_observation(group,pid)
            check_resident_bounds(values,caps)
            require(process_identity(pid) == identity)
            path = Path("/run/user")/str(os.getuid())/self.control_child/"control.sock"
            peer = socket_witness(path)
            update.start_control_peer(peer,pid)
            if action in ("observe-existing","stop-idle-owned"):
                self.owned_start.pristine()
                current=(identity,cgroup)
                if starting:
                    self.lifecycle_identity=current
                    self.lifecycle_peer=peer
                else:
                    require(current == self.lifecycle_identity and peer == self.lifecycle_peer)
                return {"active":True,"owned_existing_observation_verified":True,"bounded":True,
                    "service_mutation_requested":action == "stop-idle-owned",
                    "control_plane_health_requires_controller_success":True,"custody_claim_requires_controller_success":True}
            return {"active":True,"owned_first_start_observed":True,"bounded":True,
                "control_plane_health_requires_controller_success":True,"custody_claim_requires_controller_success":True}
        if starting_new:
            require(values["LoadState"] == "not-found" and values["ActiveState"] == "inactive"
                and values["SubState"] == "dead" and values["MainPID"] == "0"
                and values["FragmentPath"] == "" and values["ControlGroup"] == "")
            return {"active":False,"new_owned_service_admitted":True}
        if self.selected["action"] == "update-existing":
            update.inactive_installation(values,self.selected)
            update.inactive_cgroup(self.deadline_ns)
            require(self.installation_update is not None)
            self.installation_update.verify_fragment(values["FragmentPath"])
            return {"active":False,"owned_update_inactive_verified":True,"bounded":True,
                "installation_update_completed":self.installation_update.finished}
        recovering = starting and self.selected["action"] == "activate-existing-and-enroll"
        if recovering:
            recovery_loaded_properties(values)
            require(self.selected["ownership"] == "omux-installation"
                and self.selected["permissions"]["activate_service"]
                and len(self.recovery_empty) == 2 and all(not os.listdir(fd) for fd in self.recovery_empty))
            self.owned_unit.verify_fragment(values["FragmentPath"])
            return {"active":False,"owned_partial_install_admitted":True,"bounded":True}
        require(values["LoadState"] == "loaded" and values["ActiveState"] == "active"
            and values["SubState"] == "running" and values["MainPID"].isdecimal())
        fragment = canonical(values["FragmentPath"])
        selected = canonical(self.selected["service_path"])
        if self.selected["ownership"] == "omux-installation":
            if self.owned_unit is None:
                self.owned_unit = OwnedUnitCustody(self.selected)
            self.owned_unit.verify_fragment(fragment)
        else:
            require(fragment == selected or fragment.resolve(strict=True) == selected.resolve(strict=True))
        pid = int(values["MainPID"])
        ticks = start_ticks(pid)
        name = values["ControlGroup"]
        require(name.startswith("/") and ".." not in Path(name).parts
            and Path(name).name == "ai.xoxd.omux.service")
        cgroup = Path("/sys/fs/cgroup")/name.lstrip("/")
        fd = open_directory(cgroup)
        try:
            witness = stable(os.fstat(fd))
            readback = {}
            for key in ("memory.max","memory.swap.max","pids.max","cpu.max","cgroup.procs"):
                child = os.open(key,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    readback[key] = os.read(child,16385).decode("ascii").strip()
                    require(len(readback[key]) <= 16384)
                finally:
                    os.close(child)
            check_resident_bounds(values,readback)
            require(str(pid) in readback["cgroup.procs"].split()
                and stable(os.fstat(fd)) == witness == stable(cgroup.stat(follow_symlinks=False))
                and start_ticks(pid) == ticks)
        finally:
            os.close(fd)
        return {"active":True,"intentionally_retained":True,"bounded":True,
            "resident_memory":RESIDENT_MEMORY,"resident_tasks":RESIDENT_TASKS,"resident_cpu_percent":RESIDENT_CPU_PERCENT,
            "ownership":self.selected["ownership"],"custody_claim_requires_controller_success":True}

    def complete_owned_update(self,workload_status,cleaned):
        require(self.installation_update is not None and type(workload_status) is int
            and workload_status == 0 and cleaned is True)
        result = self.installation_update.completed()
        self.facts = self.recheck()
        return result

    def environment(self):
        info = os.fstat(self.directory)
        return {VARIABLE:DESTINATION+"/input.json",DEADLINE_VARIABLE:str(self.deadline_ns),
            "OMUX_RESIDENT_NAMESPACE_ID":str(info.st_dev)+":"+str(info.st_ino),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path="+DESTINATION+"/bus","XDG_RUNTIME_DIR":DESTINATION}

    def runtime_seconds(self):
        remaining = (self.deadline_ns-time.monotonic_ns())//10**9-30
        require(0 < remaining <= 1200)
        return int(remaining)

    def close(self):
        if getattr(self,"owned_start",None) is not None:
            self.owned_start.close()
            self.owned_start = None
        if getattr(self,"installation_update",None) is not None:
            self.installation_update.close()
            self.installation_update = None
        if getattr(self,"owned_unit",None) is not None:
            self.owned_unit.close()
            self.owned_unit = None
        for placeholder,path,witness in reversed(getattr(self,"created_sockets",[])):
            placeholder.close()
            if path.exists() and stable(path.stat(follow_symlinks=False)) == witness:
                path.unlink()
        self.created_sockets = []
        if getattr(self,"created_control",None) is not None:
            path,witness = self.created_control
            if path.is_dir() and not path.is_symlink() and stable(path.stat(follow_symlinks=False)) == witness and not any(path.iterdir()):
                path.rmdir()
            self.created_control = None
        if getattr(self,"created_manager",False):
            path = self.root/"systemd"
            if path.is_dir() and not path.is_symlink() and stable(path.stat(follow_symlinks=False)) == self.created_manager_identity and not any(path.iterdir()):
                path.rmdir()
        for descriptor in reversed(getattr(self,"held",[])):
            os.close(descriptor)
        self.held = []
