"""Finite native seed-plan TEST reservation; kernel metadata only, no resident effects."""
import os
import errno
from functools import wraps
from pathlib import Path
import re
import select as poll
import stat
import subprocess
import time
import guard_resident_observation as resident

PROFILE = "native-seed-plan-reserved"
MODEL_PROFILE = "native-seed-plan-reserved-models"
PROFILES = (PROFILE, MODEL_PROFILE)
# Kernel worker reuse only; archive admission has its own exact BUILD helper.
WORKLOAD_PROFILES = (*PROFILES, "default-archive-reserved", "query-registration-reserved", "resident-models-reserved", "resident-owner-status-source-reserved", "resident-owner-status-binding-reserved", "resident-owner-status-persistence-source-reserved", "resident-native-source-context-source-reserved", "resident-owner-status-persistence-binding-reserved", "native-metadata-sdk-models-reserved", "native-query-descriptor-reserved", "native-persistence-metadata-reserved", "native-persistence-sdk-reserved", "native-persistence-package-models-reserved", 'resident-custody-runtime-models-reserved', 'resident-custody-runtime-reserved', 'resident-custody-runtime-linux-reserved', 'resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved', "yoga-installed-selection-reserved", "yoga-installed-workspace-reserved", "yoga-installed-models-reserved", "yoga-toolbar-reserved", "yoga-toolbar-reserved-models")
LABEL = "//tools:native_flake_seed_plan_qualification"
MODELS = ["test", "//tools:guard_native_seed_plan_reserved_test", "//tools:execution_guard_test",
    "//tools:native_flake_seed_plan_carrier_test", "//:docs_check"]
RECOVERY_MODELS = ["test", "//clients/linux:codex_account_acquisition_test",
    "//clients/linux:setup_ui_test", "//:engine_test", "//:snapshot_import_test", "//:format_test", "//:docs_check"]
QUERY_MODELS = ["test", "//tools:codex_protocol_history_query_tools_test",
    "//tools:codex_protocol_history_metadata_test", "//tools:codex_protocol_history_sdk_export_test",
    "//tools:native_flake_seed_plan_carrier_test", "//:docs_check"]
ARCHIVE_MODELS = ["test", "//tools:guard_default_archive_reserved_test",
    "//tools:guard_resident_owned_update_test", "//tools:execution_guard_test", "//:docs_check"]
REGISTRATION_MODELS = ["test", "//tools:codex_query_registration_test", *QUERY_MODELS[1:]]
REGISTRATION_RESERVED_MODELS = ["test", "//tools:guard_query_registration_reserved_test",
    "//tools:codex_query_registration_test", "//tools:codex_protocol_history_query_tools_test",
    "//tools:execution_guard_test", "//:docs_check"]
INTEGRATED_MODELS = ["test", "//tools:guard_native_seed_plan_reserved_test",
    "//tools:guard_query_registration_reserved_test", "//tools:guard_default_archive_reserved_test",
    "//tools:guard_resident_owned_update_test", "//tools:codex_query_registration_test",
    "//tools:codex_protocol_history_query_tools_test", "//tools:codex_protocol_history_metadata_test",
    "//tools:codex_protocol_history_sdk_export_test", "//tools:native_flake_seed_plan_carrier_test",
    "//tools:execution_guard_test", "//:docs_check"]
MEMORY, TASKS, CPU = resident.PROOF_MEMORY, resident.PROOF_TASKS, resident.PROOF_CPU_PERCENT
RESERVE_NS = 30 * 10**9
ENTRY = "OMUX_NATIVE_SEED_ROOT_ENTRY_NS"
DEADLINE = "OMUX_NATIVE_SEED_ROOT_DEADLINE_NS"
MODE = "OMUX_NATIVE_SEED_RESERVED_PROFILE"

DIAGNOSTIC_PHASES = frozenset(("unknown", "resident-sample", "resident-completion",
    "worker-pidfd-readiness", "worker-cgroup-custody", "worker-cgroup-bounds",
    "worker-proc-identity", "worker-proc-security", "worker-membership", "worker-alive",
    "monitor-iteration", "terminal-manager-readback", "terminal-recheck", "terminal-result",
    "proc-exit-confirmation", "proc-exit-manager", "proc-exit-readiness"))
PROC_EXIT_OUTCOMES = frozenset(("not-requested", "manager-query-refused", "manager-terminal-refused",
    "pidfd-not-ready", "custody-refused", "deadline-refused", "verified-terminal"))
DIAGNOSTIC_ERRNOS = frozenset(("ENOENT", "ESRCH", "EACCES", "EPERM", "ENOTDIR",
    "ELOOP", "EBADF", "EIO", "EINVAL", "EMFILE", "ENFILE"))

class ReservationOSError(OSError):
    def __init__(self, phase, number):
        self.reservation_phase = phase if type(phase) is str and phase in DIAGNOSTIC_PHASES else "unknown"
        super().__init__(number if type(number) is int else None, "reserved-observation-refused")

class ReservationValueError(ValueError):
    def __init__(self, phase):
        self.reservation_phase = phase if type(phase) is str and phase in DIAGNOSTIC_PHASES else "unknown"
        super().__init__("reserved-observation-refused")

def diagnostic_projection(error):
    if type(error) not in (ReservationOSError, ReservationValueError):
        return None
    phase = error.reservation_phase
    phase = phase if type(phase) is str and phase in DIAGNOSTIC_PHASES else "unknown"
    number = error.errno if type(error) is ReservationOSError else None
    symbol = errno.errorcode.get(number, "other") if type(number) is int else "none"
    result = {"phase": phase, "errno": symbol if symbol in DIAGNOSTIC_ERRNOS or symbol == "none" else "other"}
    outcome = getattr(error, "reservation_proc_exit", None)
    if type(outcome) is str and outcome in PROC_EXIT_OUTCOMES:
        result["proc_exit_confirmation"] = outcome
    return result

def diagnostic_call(phase, invoke, *arguments, **keywords):
    try:
        return invoke(*arguments, **keywords)
    except (OSError, ValueError) as error:
        if type(error) in (ReservationOSError, ReservationValueError):
            raise
        if isinstance(error, OSError):
            raise ReservationOSError(phase, error.errno) from None
        raise ReservationValueError(phase) from None

def diagnostic_method(phase):
    def decorate(method):
        @wraps(method)
        def invoke(*arguments, **keywords):
            return diagnostic_call(phase, method, *arguments, **keywords)
        return invoke
    return decorate

def require(value):
    if not value:
        raise ValueError("native-seed-reservation-refused")

def selected(profile, arguments):
    require(profile in PROFILES and (arguments==["test",LABEL] if profile==PROFILE
        else arguments in (MODELS,RECOVERY_MODELS,QUERY_MODELS,ARCHIVE_MODELS,REGISTRATION_MODELS,REGISTRATION_RESERVED_MODELS,INTEGRATED_MODELS)))
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
        "CPUQuotaPerSecUSec": "1.9s", "RemainAfterExit": "yes"}

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

    @diagnostic_method("resident-sample")
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

    @diagnostic_method("resident-completion")
    def complete(self,result,cleanup,evidence,source):
        require(type(result) is int and result==0 and cleanup is True
            and evidence is True and source is True)
        return self.observe(cleanup=True)

    def close(self):
        resources,self.resources=self.resources,[]
        resources = list(dict.fromkeys([row[1] for row in self.chain]+resources))
        self.directory,self.chain = None,[]
        resident.close_owned_resources(resources)


class WorkloadWitness:
    """Only the admitted reserved proof worker; exit readiness is not exit success."""
    read = Witness.read
    close = Witness.close

    def __init__(self, profile, entry, deadline, pin, actual, original_pid, original_ticks):
        self.entry,self.deadline = entry,deadline
        self.resources,self.chain,self.directory = [],[],None
        self.pin,self.bounds = pin,None
        self.proc_exit_pending = False
        self.proc_exit_confirmation = "not-requested"
        try:
            require(profile in WORKLOAD_PROFILES and actual.get("ActiveState")=="active" and actual.get("RemainAfterExit")=="yes"
                and actual.get("MainPID")==str(original_pid)
                and actual.get("ExecMainPID")==str(original_pid)
                and re.fullmatch(r"[0-9a-f]{32}",actual.get("InvocationID","")))
            self.unit,self.invocation,self.pid = actual["Id"],actual["InvocationID"],original_pid
            require(re.fullmatch(r"omux-execution-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}[.]service",self.unit)
                and pin.path==Path("/sys/fs/cgroup")/actual["ControlGroup"].lstrip("/")
                and pin.path.name==self.unit)
            remaining(entry,deadline)
            self.chain=open_chain(pin.path)
            self.resources.extend(row[1] for row in self.chain)
            self.directory=self.chain[-1][1]
            self.identity=self.chain[-1][2]
            require(self.identity[:2]==pin.identity)
            self.pidfd=os.pidfd_open(original_pid,0)
            self.resources.append(self.pidfd)
            self.worker=process(original_pid)
            require(str(self.worker[0])==str(original_ticks))
            require(self.alive())
        except BaseException:
            self.close()
            raise

    @diagnostic_method("worker-cgroup-custody")
    def check_directory(self, exited):
        for index,(path,fd,identity) in enumerate(self.chain):
            require(resident.stable(os.fstat(fd))==identity)
            try:
                named=path.stat(follow_symlinks=False) if index==0 else os.stat(path.name,
                    dir_fd=self.chain[index-1][1],follow_symlinks=False)
            except FileNotFoundError:
                require(exited and index==len(self.chain)-1 and self.pin.observe()=="absent")
                return False
            require(resident.stable(named)==identity)
        require(self.chain[-1][2]==self.identity)
        return True

    @diagnostic_method("worker-alive")
    def alive(self):
        self.proc_exit_pending = False
        remaining(self.entry,self.deadline)
        require(self.directory is not None)
        exited=bool(diagnostic_call("worker-pidfd-readiness", poll.select, [self.pidfd], [], [], 0)[0])
        named=self.check_directory(exited)
        if not named:
            remaining(self.entry,self.deadline)
            return False
        values=self.check_bounds()
        if not exited:
            try:
                require(diagnostic_call("worker-proc-identity", process, self.pid)==self.worker)
            except ReservationOSError as error:
                # A disappearing proc identity is exit readiness only when the
                # original held pidfd agrees; manager terminal result stays mandatory.
                if error.reservation_phase != "worker-proc-identity" or error.errno != errno.ENOENT:
                    raise
                if self.bounds is None or values != self.bounds:
                    raise
                if not diagnostic_call("worker-pidfd-readiness", poll.select,
                        [self.pidfd], [], [], 0)[0]:
                    self.proc_exit_pending = True
                    raise
                named=self.check_directory(True)
                if named:
                    self.check_bounds()  # Preserve the admitted frozen cap tuple.
                self.check_directory(True)
                remaining(self.entry,self.deadline)
                return False
            self.check_process()
            rows=diagnostic_call("worker-membership", self.read, "cgroup.procs").splitlines()
            require(len(rows)<=TASKS and all(re.fullmatch(r"[1-9][0-9]{0,9}",v) for v in rows)
                and len(set(rows))==len(rows) and str(self.pid) in rows)
            require(self.pin.observe()=="populated")
            current=self.read("pids.current")
            require(re.fullmatch(r"[1-9][0-9]{0,2}",current) and int(current)<=TASKS)
        self.check_directory(exited)
        remaining(self.entry,self.deadline)
        self.bounds=values
        return not exited

    @diagnostic_method("worker-cgroup-bounds")
    def check_bounds(self):
        values={name:self.read(name) for name in
            ("memory.max","memory.swap.max","pids.max","cpu.max","memory.oom.group")}
        require(values["memory.max"]==str(MEMORY) and values["memory.swap.max"]=="0"
            and values["pids.max"]==str(TASKS) and values["memory.oom.group"]=="1")
        fields=values["cpu.max"].split()
        require(len(fields)==2 and all(re.fullmatch(r"[1-9][0-9]{0,8}",v) for v in fields)
            and int(fields[0])*10==19*int(fields[1]))
        require(self.bounds is None or values==self.bounds)
        return values

    @diagnostic_method("worker-proc-security")
    def check_process(self):
        # Fixed public proc metadata only; no cmdline/environment/credential bytes.
        def read(name):
            fd=os.open("/proc/"+str(self.pid)+"/"+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                raw=os.read(fd,8193)
                require(len(raw)<=8192 and not os.read(fd,1))
                return raw.decode("ascii")
            finally:
                os.close(fd)
        require(read("cgroup").splitlines()==
            ["0::/"+str(self.pin.path.relative_to("/sys/fs/cgroup"))])
        fields={}
        for line in read("status").splitlines():
            key,separator,value=line.partition(":")
            if separator:
                require(key not in fields)
                fields[key]=value.split()
        require(fields.get("Uid")==[str(os.getuid())]*4
            and fields.get("Gid")==[str(os.getgid())]*4
            and fields.get("NoNewPrivs")==["1"]
            and all(fields.get(key) and len(fields[key])==1
                and re.fullmatch(r"[0-9a-fA-F]{1,16}",fields[key][0])
                and int(fields[key][0],16)==0 for key in ("CapEff","CapPrm","CapAmb")))

    def authorize_cleanup(self, actual):
        require(actual.get("Id")==self.unit and actual.get("InvocationID")==self.invocation
            and actual.get("ExecMainPID")==str(self.pid) and actual.get("RemainAfterExit")=="yes")
        group="/"+str(self.pin.path.relative_to("/sys/fs/cgroup"))
        remaining(self.entry,self.deadline,cleanup=True)
        exited=bool(poll.select([self.pidfd],[],[],0)[0])
        named=self.check_directory(exited)
        if named:
            self.check_bounds()  # Never reset the pre-GO frozen tuple in cleanup.
        state=self.pin.observe()
        if actual.get("MainPID")=="0":
            require(exited and state in ("populated","empty","absent"))
            require(actual.get("ControlGroup")==group if state=="populated"
                else actual.get("ControlGroup") in ("",group))
            require(state!="populated" or named)
            require(actual.get("ActiveState") in ("inactive","failed")
                or actual.get("ActiveState")=="active" and actual.get("SubState")=="exited")
        else:
            require(named and state=="populated" and actual.get("MainPID")==str(self.pid)
                and actual.get("ControlGroup")==group and not exited and process(self.pid)==self.worker)
        self.check_directory(exited)
        remaining(self.entry,self.deadline,cleanup=True)

    @diagnostic_method("terminal-result")
    def terminal(self, actual):
        require(actual.get("Id")==self.unit and actual.get("InvocationID")==self.invocation
            and actual.get("ExecMainPID")==str(self.pid))
        if actual.get("ActiveState")=="active":
            require(actual.get("SubState")=="exited" and actual.get("MainPID")=="0"
                and actual.get("RemainAfterExit")=="yes")
        elif actual.get("ActiveState") not in ("inactive","failed"):
            return 125
        code,status=actual.get("ExecMainCode"),actual.get("ExecMainStatus")
        require(actual.get("MainPID")=="0" and actual.get("RemainAfterExit")=="yes"
            and code in ("1","2","3") and type(status) is str
            and re.fullmatch(r"0|[1-9][0-9]{0,2}",status) and int(status)<=255)
        result=int(status)
        return 125 if result==0 and (actual.get("Result")!="success" or code!="1") else result

    @diagnostic_method("proc-exit-confirmation")
    def confirm_proc_exit(self, readback, deadline, clock):
        """One terminal query for the admitted ENOENT path; never wait for readiness."""
        require(self.proc_exit_pending is True and self.bounds is not None)
        self.proc_exit_pending = False  # Consume the finite branch before querying.
        self.proc_exit_confirmation = "deadline-refused"
        if clock() >= deadline:
            return 124
        remaining(self.entry, self.deadline)
        self.proc_exit_confirmation = "manager-query-refused"
        actual = diagnostic_call("terminal-manager-readback", readback)
        self.proc_exit_confirmation = "deadline-refused"
        if clock() >= deadline:
            return 124
        remaining(self.entry, self.deadline)
        self.proc_exit_confirmation = "manager-terminal-refused"
        if actual.get("ActiveState") not in ("active", "inactive", "failed"):
            raise ReservationValueError("proc-exit-manager")
        result = self.terminal(actual)  # Original identity/status parser stays mandatory.
        if actual.get("ExecMainStatus") == "0" and result != 0:
            raise ReservationValueError("proc-exit-manager")
        self.proc_exit_confirmation = "pidfd-not-ready"
        if not diagnostic_call("proc-exit-readiness", poll.select, [self.pidfd], [], [], 0)[0]:
            raise ReservationValueError("proc-exit-readiness")
        self.proc_exit_confirmation = "custody-refused"
        named = self.check_directory(True)
        if named:
            self.check_bounds()
        self.check_directory(True)
        self.proc_exit_confirmation = "deadline-refused"
        remaining(self.entry, self.deadline)
        if clock() >= deadline:
            return 124
        self.proc_exit_confirmation = "verified-terminal"
        return result


def monitor(profile, witness, readback, deadline, on_iteration, *,
            clock=time.monotonic, pause=time.sleep):
    """No routine manager reads; one terminal read still owns the exit/result fact."""
    require(profile in WORKLOAD_PROFILES and type(witness) is WorkloadWitness)
    while clock()<deadline:
        diagnostic_call("monitor-iteration", on_iteration)
        if clock()>=deadline:
            return 124
        try:
            alive=witness.alive()
        except ReservationOSError as error:
            if (type(error) is not ReservationOSError or error.reservation_phase != "worker-proc-identity"
                    or error.errno != errno.ENOENT or getattr(witness, "proc_exit_pending", False) is not True
                    or witness.bounds is None):
                raise
            try:
                return witness.confirm_proc_exit(readback, deadline, clock)
            except (ReservationOSError, ReservationValueError) as refusal:
                refusal.reservation_proc_exit = witness.proc_exit_confirmation
                raise
        if clock()>=deadline:
            return 124
        if not alive:
            actual=diagnostic_call("terminal-manager-readback", readback)
            if clock()>=deadline:
                return 124
            require(not diagnostic_call("terminal-recheck", witness.alive))
            if clock()>=deadline:
                return 124
            return witness.terminal(actual)
        left=deadline-clock()
        if left<=0:
            return 124
        pause(min(0.5,left))
    return 124


def release_worker(witness):
    """Detach new FDs before any receipt can promote success; fallback is idempotent."""
    if witness is None:
        return True
    require(type(witness) is WorkloadWitness)
    try:
        witness.close()
    except (OSError,ValueError):
        return False
    return True


def post_stop_projection(actual, identity):
    """Closed diagnostic only: never return unit/PID/invocation strings."""
    def field(name, allowed):
        value=actual.get(name)
        return "missing" if value is None else value if type(value) is str and value in allowed else "other"
    pid=actual.get("MainPID")
    pid_state=("missing" if pid is None else "zero" if pid=="0" else "nonzero"
        if type(pid) is str and re.fullmatch(r"[1-9][0-9]{0,9}",pid) else "other")
    value={"schema_version":1,"scope":"reserved-owned-post-stop-diagnostic-v1",
        "LoadState":field("LoadState",("loaded","not-found","error","masked","bad-setting","stub","merged")),
        "ActiveState":field("ActiveState",("active","inactive","failed","activating","deactivating","reloading")),
        "SubState":field("SubState",("dead","exited","running","failed","start","start-pre","start-post",
            "stop","stop-sigterm","stop-sigkill","stop-post","auto-restart")),
        "MainPID":pid_state,"Id_matches":actual.get("Id")==identity[0],
        "InvocationID_matches":actual.get("InvocationID")==identity[1],
        "ExecMainPID_matches":actual.get("ExecMainPID")==identity[2],
        "original_cgroup_state":"not-observed","predicate":"manager-predicate-passed"}
    if not value["Id_matches"]:value["predicate"]="unit-id-mismatch"
    elif actual.get("ActiveState")!="inactive":value["predicate"]="not-inactive"
    elif actual.get("SubState")!="dead":value["predicate"]="not-dead"
    elif actual.get("MainPID")!="0":value["predicate"]="main-pid-not-zero"
    elif actual.get("LoadState")!="not-found" and not value["InvocationID_matches"]:
        value["predicate"]="invocation-mismatch"
    elif actual.get("LoadState")!="not-found" and not value["ExecMainPID_matches"]:
        value["predicate"]="exec-main-pid-mismatch"
    return value


def failed_terminal_exit(actual):
    """Only a retained normal nonzero exit may qualify the failed cleanup branch."""
    status=actual.get("ExecMainStatus")
    if (actual.get("LoadState")=="loaded" and actual.get("ActiveState")=="failed"
            and actual.get("SubState")=="failed" and actual.get("MainPID")=="0"
            and actual.get("RemainAfterExit")=="yes" and actual.get("ExecMainCode")=="1"
            and actual.get("Result")=="exit-code" and type(status) is str
            and re.fullmatch(r"[1-9][0-9]{0,2}",status) and int(status)<=255):
        return ("1",status,"exit-code")
    return None


def cleanup_retained(*, deadline, readback, authorize, stop, observe,
                     clock=time.monotonic, pause=time.sleep):
    """Same owned cleanup budget; an empty cgroup does not release an active retained unit."""
    from execution_guard import CLEANUP_READ_SECONDS, CONTROLLER_TIMEOUT
    summary={"state":"unproved","stop":"not-requested","ownership":"unproved","readback_attempts":0,
        "post_stop":None}
    def state():
        try:
            return observe()
        except (OSError,ValueError,UnicodeError):
            return "unproved"
    identity=None
    failed_terminal=None
    while clock()<deadline and summary["readback_attempts"]<8:
        current=state()
        if current in ("changed","unproved"):
            summary["state"]="original-"+current
            return summary
        summary["readback_attempts"]+=1
        try:
            actual=readback(min(CLEANUP_READ_SECONDS,deadline-clock()),deadline)
        except (OSError,subprocess.SubprocessError):
            left=deadline-clock()
            if left>0:pause(min(0.1,left))
            continue
        if clock()>=deadline:break
        try:
            require(actual.get("RemainAfterExit")=="yes"
                and re.fullmatch(r"[0-9a-f]{32}",actual.get("InvocationID","")))
            if authorize(actual) is False:
                continue
            identity=(actual["Id"],actual["InvocationID"],actual["ExecMainPID"])
            failed_terminal=failed_terminal_exit(actual)
            summary["ownership"]="verified"
        except (OSError,ValueError,KeyError):
            summary["ownership"]="refused"
            return summary
        if state() in ("changed","unproved"):
            summary["state"]="original-unproved"
            return summary
        left=deadline-clock()
        if left<=0.1:break
        summary["stop"]="unresolved"
        try:
            stop(min(CONTROLLER_TIMEOUT,left-0.1),deadline)
            summary["stop"]="succeeded"
        except (OSError,ValueError,subprocess.SubprocessError):
            pass
        break
    # No adoption after stop: query once within the same immutable cleanup cutoff.
    if identity is not None and clock()<deadline:
        summary["readback_attempts"]+=1
        try:
            actual=readback(min(CLEANUP_READ_SECONDS,deadline-clock()),deadline)
            summary["post_stop"]=post_stop_projection(actual,identity)
            missing=actual.get("LoadState")=="not-found"
            same_terminal_identity=(actual.get("InvocationID")==identity[1]
                and actual.get("ExecMainPID")==identity[2])
            ordinary=(actual.get("ActiveState")=="inactive" and actual.get("SubState")=="dead"
                and (missing or same_terminal_identity))
            owned_failed=(failed_terminal is not None and summary["stop"]=="succeeded"
                and same_terminal_identity and failed_terminal_exit(actual)==failed_terminal)
            require(actual.get("Id")==identity[0] and actual.get("MainPID")=="0"
                and (ordinary or owned_failed))
            if owned_failed:
                summary["post_stop"]["predicate"]="owned-failed-terminal-predicate-passed"
            if clock()<deadline:
                original=state()
                summary["post_stop"]["original_cgroup_state"]=(original
                    if original in ("empty","absent","populated","changed","unproved") else "other")
                if original in ("empty","absent"):
                    summary["state"]="empty"
                    return summary
                summary["post_stop"]["predicate"]="original-group-not-empty"
            else:
                summary["post_stop"]["predicate"]="original-deadline-exhausted"
        except (OSError,ValueError,subprocess.SubprocessError):
            if summary["post_stop"] is None:
                summary["post_stop"]=post_stop_projection({},identity)
                summary["post_stop"]["predicate"]="post-read-failed"
    summary["state"]="deadline-exhausted" if clock()>=deadline else "unproved"
    return summary
