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
    require(arguments == ["run",LABEL] and manager == "system" and manifest is not None
        and not reuse and not any(unrelated))
    return {"PrivateNetwork":"yes","ProtectSystem":"strict","PrivateTmp":"yes"}

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
    require(type(value) is dict and set(value) == {"schema_version","ownership","action","instance",
        "prefix","records","runtime_state","service_path","native_context","permissions"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["ownership"] in ("omux-installation","home-manager")
        and value["action"] in ("install-and-enroll","enroll-existing")
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
    context = value["native_context"]
    require(type(context) is dict and set(context) == {"application","provenance","codex_home"}
        and context["application"] == "codex" and context["provenance"] == "authorized-working-native-context")
    source_home = canonical(context["codex_home"])
    for path in (prefix,expected["records"],expected["runtime_state"]):
        require(path != source_home and path not in source_home.parents and source_home not in path.parents)
    permissions = value["permissions"]
    require(type(permissions) is dict and set(permissions) == {"connect_source","activate_service","restart_daemon"}
        and all(type(v) is bool for v in permissions.values()) and permissions["connect_source"]
        and (value["action"] != "install-and-enroll" or permissions["activate_service"])
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

def normalize_binds(value,leaf_bindings=()):
    result = []
    leaf_bindings = set(leaf_bindings)
    for item in value.split():
        parts = item.split(":")
        option = parts.pop() if len(parts) == 3 else None
        require(len(parts) == 2)
        binding = ":".join(parts)
        require(option == "norbind" if binding in leaf_bindings else option in (None,"rbind"))
        result.append(binding)
    return result

class Admission:
    def __init__(self,manifest,home,deadline_ns):
        self.deadline_ns = deadline_ns
        self.manifest = canonical(str(manifest))
        require(self.manifest.name == "input.json")
        self.root = self.manifest.parent
        self.held = []
        self.created_sockets = []
        self.created_manager = False
        self.created_control = None
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
            self.control_child = runtime_child(self.selected["runtime_state"])
            self.control_source = runtime/self.control_child
            control_source_fd = open_directory(self.control_source,private=True)
            self.held.append(control_source_fd)
            self.source_parents.append((self.control_source,control_source_fd,stable(os.fstat(control_source_fd))))
            if self.selected["action"] == "install-and-enroll":
                require(not os.listdir(control_source_fd))
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
        return {"scope":"resident-enrollment","source_contents_read":False,
            "resident_memory":RESIDENT_MEMORY,"resident_tasks":RESIDENT_TASKS,"resident_cpu_percent":RESIDENT_CPU_PERCENT,
            "proof_memory":PROOF_MEMORY,"proof_tasks":PROOF_TASKS,"proof_cpu_percent":PROOF_CPU_PERCENT}

    def bindings(self):
        return [str(self.root)+":"+DESTINATION]+[
            str(source)+":"+DESTINATION+"/"+str(target.relative_to(self.root))+":norbind"
            for target,source in self.sources.items()] + [runtime_binding(self.selected["runtime_state"],os.getuid())]

    def writable_binding(self):
        return " ".join(str(path)+":"+str(path) for path,_,_ in self.product_directories)

    def verify_bindings(self,actual,run=None):
        expected_rw = normalize_binds(self.writable_binding())
        if run is not None:
            expected_rw.append(str(run)+":"+str(run))
        leaves = [str(source)+":"+DESTINATION+"/"+str(target.relative_to(self.root))
            for target,source in self.sources.items()]
        expected_ro = normalize_binds(" ".join(self.bindings()),leaves)
        ro,rw = normalize_binds(actual.get("BindReadOnlyPaths",""),leaves),normalize_binds(actual.get("BindPaths",""))
        require(len(ro) == len(expected_ro) and set(ro) == set(expected_ro)
            and len(rw) == len(expected_rw) and set(rw) == set(expected_rw))

    def service_observation(self,systemctl,starting=False):
        env = {"HOME":pwd.getpwuid(os.getuid()).pw_dir,"LC_ALL":"C",
            "XDG_RUNTIME_DIR":"/run/user/"+str(os.getuid()),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/"+str(os.getuid())+"/bus"}
        remaining = min(15,(self.deadline_ns-time.monotonic_ns())/10**9)
        require(remaining > 0)
        result = subprocess.run([str(systemctl),"--user","show","--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec",
            "ai.xoxd.omux.service"],env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining,check=False)
        require(type(starting) is bool)
        starting_new = starting and self.selected["action"] == "install-and-enroll" \
            and self.selected["ownership"] == "omux-installation"
        require(result.returncode in ((0,4) if starting_new else (0,))
            and not result.stderr and len(result.stdout) <= 16384)
        values = unique(line.split("=",1) for line in result.stdout.decode("ascii").splitlines())
        require(set(values) == {"LoadState","ActiveState","SubState","MainPID","FragmentPath","ControlGroup",
            "MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec"})
        if starting_new:
            require(values["LoadState"] == "not-found" and values["ActiveState"] == "inactive"
                and values["SubState"] == "dead" and values["MainPID"] == "0"
                and values["FragmentPath"] == "" and values["ControlGroup"] == "")
            return {"active":False,"new_owned_service_admitted":True}
        require(values["LoadState"] == "loaded" and values["ActiveState"] == "active"
            and values["SubState"] == "running" and values["MainPID"].isdecimal())
        fragment = canonical(values["FragmentPath"])
        selected = canonical(self.selected["service_path"])
        require(fragment == selected or self.selected["ownership"] == "home-manager"
            and fragment.resolve(strict=True) == selected.resolve(strict=True))
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
