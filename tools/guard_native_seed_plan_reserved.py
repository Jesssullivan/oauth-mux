"""Finite native seed-plan TEST reservation; kernel metadata only, no resident effects."""
import os
from pathlib import Path
import re
import select as poll
import stat
import time
import guard_resident_observation as resident

PROFILE = "native-seed-plan-reserved"
MODEL_PROFILE = "native-seed-plan-reserved-models"
PROFILES = (PROFILE, MODEL_PROFILE)
LABEL = "//tools:native_flake_seed_plan_qualification"
MODELS = ["test", "//tools:guard_native_seed_plan_reserved_test", "//tools:execution_guard_test",
    "//tools:native_flake_seed_plan_carrier_test", "//:docs_check"]
RECOVERY_MODELS = ["test", "//clients/linux:codex_account_acquisition_test",
    "//clients/linux:setup_ui_test", "//:engine_test", "//:snapshot_import_test", "//:format_test", "//:docs_check"]
MEMORY, TASKS, CPU = resident.PROOF_MEMORY, resident.PROOF_TASKS, resident.PROOF_CPU_PERCENT
RESERVE_NS = 30 * 10**9
ENTRY = "OMUX_NATIVE_SEED_ROOT_ENTRY_NS"
DEADLINE = "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS"
MODE = "OMUX_NATIVE_SEED_RESERVED_PROFILE"

def require(value):
    if not value:
        raise ValueError("native-seed-reservation-refused")

def selected(profile, arguments):
    require(profile in PROFILES and (arguments==["test",LABEL] if profile==PROFILE
        else arguments in (MODELS,RECOVERY_MODELS)))
    return {"PrivateNetwork": "yes"}

def request(args, arguments):
    if args.profile not in PROFILES:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
        "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
        "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and args.reuse_owned_cache is False
        and not any(value for name,value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch(r"[0-9a-f]{40}",args.source_commit)
        and args.source_dirty == "false")
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache,args.nixpkgs_source)
    return True

def properties(base):
    return {**base, "MemoryMax": str(MEMORY), "TasksMax": str(TASKS),
        "CPUQuotaPerSecUSec": "1.9s"}

def envelope(entry, deadline):
    require(type(entry) is int and type(deadline) is int and entry > 0
        and deadline-entry == 1200*10**9)
    return deadline-RESERVE_NS

def remaining(entry, deadline, *, cleanup=False):
    require(type(cleanup) is bool)
    work = envelope(entry,deadline)
    bound = deadline if cleanup else work
    now = time.monotonic_ns()
    require(now >= entry)
    left = bound-now
    require(left > 0)
    return left/10**9

def command(builder, bazel, run, arguments, profile, entry, deadline, **kwargs):
    selected(profile,arguments)
    remaining(entry,deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get("repository_cache"),kwargs.get("nixpkgs_source"))
    result = builder(bazel,run,arguments,profile="standard",**kwargs)
    index = result.index("test")+1
    options = ["--repository_disable_download", "--repo_contents_cache="]
    if profile == PROFILE:
        options += ["--test_env="+MODE+"="+PROFILE,
            "--test_env="+ENTRY+"="+str(entry), "--test_env="+DEADLINE+"="+str(deadline)]
    result[index:index] = options
    return result

def cgroup_path(uid):
    require(type(uid) is int and uid > 0)
    # Same fixed default path as guard_resident_owned_update.active_start_properties.
    return Path("/sys/fs/cgroup/user.slice/user-"+str(uid)+".slice/user@"+str(uid)+
        ".service/app.slice/ai.xoxd.omux.service")

def kernel_bounds(values):
    require(set(values) == {"memory.max","memory.swap.max","pids.max","cpu.max"})
    require(all(type(value) is str for value in values.values()))
    memory,tasks = values["memory.max"],values["pids.max"]
    require(re.fullmatch(r"[1-9][0-9]{0,9}",memory)
        and re.fullmatch(r"[1-9][0-9]?",tasks) and int(memory)<=resident.RESIDENT_MEMORY
        and int(tasks)<=resident.RESIDENT_TASKS and values["memory.swap.max"]=="0")
    fields = values["cpu.max"].split()
    require(len(fields)==2 and all(re.fullmatch(r"[1-9][0-9]{0,8}",part) for part in fields))
    quota,period = map(int,fields)
    require(quota*10 <= period)
    return dict(values)

def process(pid):
    ticks = resident.start_ticks(pid)
    namespace = resident.stable(Path("/proc/"+str(pid)+"/ns/pid").stat())
    require(namespace == resident.stable(Path("/proc/self/ns/pid").stat()))
    executable = os.readlink("/proc/"+str(pid)+"/exe")
    require(executable.startswith("/") and not executable.endswith(" (deleted)"))
    require(resident.start_ticks(pid)==ticks)
    return ticks,namespace,executable

def ancestor(info,path):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,os.getuid())
        and not info.st_mode&0o022)

def open_chain(path):
    held=[]
    try:
        current=Path("/")
        fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        held.append((current,fd,None))
        info=os.fstat(fd);ancestor(info,current)
        held[-1]=(current,fd,resident.stable(info))
        for name in path.parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            current/=name
            held.append((current,child,None)); fd=child
            info=os.fstat(fd);ancestor(info,current)
            held[-1]=(current,fd,resident.stable(info))
        return held
    except BaseException:
        resident.close_owned_resources([row[1] for row in held])
        raise

class Witness:
    """Freeze named kernel object/initial direct processes, not installed software."""
    def __init__(self, entry, deadline):
        self.entry,self.deadline = entry,deadline
        self.resources,self.processes,self.bounds,self.samples = [],[],None,0
        self.directory,self.chain = None,[]
        self.path = cgroup_path(os.getuid())
        try:
            remaining(entry,deadline)
            self.chain = open_chain(self.path)
            self.resources.extend(row[1] for row in self.chain)
            self.directory = self.chain[-1][1]
            self.identity = self.chain[-1][2]
            initial = self.members()
            require(initial)
            for pid in initial:
                fd = os.pidfd_open(pid,0)
                self.resources.append(fd)
                identity = process(pid)
                require(not poll.select([fd],[],[],0)[0])
                self.processes.append((pid,fd,identity))
            self.observe()
        except BaseException:
            self.close()
            raise

    def check_directory(self):
        # Each held ancestor also keeps its exact name under the held parent.
        for index,(path,fd,identity) in enumerate(self.chain):
            named = path.stat(follow_symlinks=False) if index==0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1],follow_symlinks=False)
            require(resident.stable(named)==identity==resident.stable(os.fstat(fd)))
        require(self.chain and self.chain[-1][2]==self.identity)

    def read(self,name):
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,
            dir_fd=self.directory)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode))
            raw = os.read(fd,8193)
            require(len(raw)<=8192 and not os.read(fd,1))
            return raw.decode("ascii").strip()
        finally:
            os.close(fd)

    def members(self):
        raw = self.read("cgroup.procs")
        rows = raw.splitlines()
        require(len(rows)<=resident.RESIDENT_TASKS
            and all(re.fullmatch(r"[1-9][0-9]{0,9}",row) and int(row)>1 for row in rows))
        result = tuple(map(int,rows))
        require(len(set(result))==len(result))
        return result

    def observe(self, *, cleanup=False):
        remaining(self.entry,self.deadline,cleanup=cleanup)
        require(self.directory is not None)
        self.check_directory()
        values = kernel_bounds({name:self.read(name) for name in
            ("memory.max","memory.swap.max","pids.max","cpu.max")})
        require(self.bounds is None or values == self.bounds)
        members = self.members()
        require(all(pid in members and not poll.select([fd],[],[],0)[0]
            and process(pid)==identity for pid,fd,identity in self.processes))
        events = self.read("cgroup.events").splitlines()
        require([line for line in events if line.startswith("populated ")]==["populated 1"])
        current = self.read("pids.current")
        require(re.fullmatch(r"[0-9]{1,2}",current) and 0<int(current)<=int(values["pids.max"]))
        self.check_directory()
        remaining(self.entry,self.deadline,cleanup=cleanup)
        self.bounds=values
        self.samples=min(self.samples+1,65535)
        return {"scope":"sampled-fixed-default-cgroup-kernel-reservation-v1",
            "kernel_bounds":dict(values),"observations":self.samples,
            "initial_direct_processes_retained":True,"initial_direct_process_count":len(self.processes),"outer_pid_namespace_matched":True,
            "hierarchical_caps":True,"descendant_process_inventory":False,
            "installation_qualified":False,"health_observed":False,"custody_observed":False,
            "resident_signalled":False,"whole_host_reservation":False}

    def complete(self,result,cleanup,evidence,source):
        require(type(result) is int and result==0 and cleanup is True
            and evidence is True and source is True)
        return self.observe(cleanup=True)

    def close(self):
        resources,self.resources=self.resources,[]
        resources = list(dict.fromkeys([row[1] for row in self.chain]+resources))
        self.directory,self.chain = None,[]
        resident.close_owned_resources(resources)
