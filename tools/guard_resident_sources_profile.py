"""One local installed Sources launch; no automatic consent/enrollment effects."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import time
import uuid

import guard_resident_observation as resident
import guard_resident_continuity_profile as continuity
import guard_resident_namespace_profile as namespace
import guard_yoga_profile as yoga
import yoga_display_binding as display

sys.path.insert(0, str(Path(__file__).parent.parent / "delivery"))
import codex_device_acquisition_component as component

LABEL = "//delivery:resident_installed_sources"
PROFILE = "resident-sources"
SCOPE = "omux-installed-sources-launch-v1"
DESTINATION = "/omux-resident-sources-inputs"
VARIABLE = "OMUX_RESIDENT_SOURCES_DEADLINE_NS"
HANDOFF = "sources-launch-projection.json"
OUTPUT = "installed-sources-launch.json"
LIMIT = 65536
HEX = re.compile(r"[0-9a-f]{64}\Z")
PROOF_MEMORY = resident.PROOF_MEMORY
PROOF_TASKS = resident.PROOF_TASKS
PROOF_CPU_PERCENT = resident.PROOF_CPU_PERCENT
sources_profile = True

def require(value):
    if not value:
        raise ValueError("resident-sources-refused")

def tick(deadline, reserve=0):
    require(type(deadline) is int and time.monotonic_ns() + reserve < deadline)

def finite(arguments, manager, manifest, reuse, unrelated=()):
    require(arguments == ["run", LABEL] and manager == "system" and manifest is not None
        and not reuse and not any(unrelated))
    return {"PrivateNetwork": "no", "ProtectSystem": "strict", "PrivateTmp": "yes", "PrivatePIDs": "no"}

def manifest_schema(value, home, epoch):
    require(type(value) is dict and set(value) == {"schema_version","scope","action_epoch","resident","seat","component","host_systemctl"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == SCOPE)
    namespace.manifest_schema({key:value[key] for key in ("schema_version","action_epoch","resident")}, home, epoch)
    seat = value["seat"]
    require(type(seat) is dict and set(seat) == {"host","seat","operatorTerminal","sourceSocket","compositorSnapshot"})
    host, selected = seat["host"], seat["seat"]
    require(type(host) is dict and set(host) == {"machineIdSha256","bootIdSha256","uid"}
        and type(host["uid"]) is int and host["uid"] == os.getuid()
        and all(type(host[key]) is str and HEX.fullmatch(host[key]) for key in ("machineIdSha256","bootIdSha256"))
        and type(selected) is dict and set(selected) == {"sessionId","seatId","uid"}
        and type(selected["uid"]) is int and selected["uid"] == os.getuid()
        and type(selected["sessionId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", selected["sessionId"])
        and type(selected["seatId"]) is str and re.fullmatch(r"seat[0-9]{1,3}", selected["seatId"])
        and type(seat["operatorTerminal"]) is str and re.fullmatch(r"/dev/(?:tty[0-9]{1,3}|pts/[0-9]{1,6})", seat["operatorTerminal"]))
    display.valid_snapshot(seat["compositorSnapshot"], os.getuid())
    pins = value["component"]
    require(pins is None or type(pins) is dict and set(pins) == {"component_sha256","install_sha256","producer_sha256"}
        and all(type(pin) is str and HEX.fullmatch(pin) for pin in pins.values()))
    tool = value["host_systemctl"]
    require(tool is None or type(tool) is dict and set(tool)=={"sha256","bytes"}
        and type(tool["sha256"]) is str and HEX.fullmatch(tool["sha256"])
        and type(tool["bytes"]) is int and 0<tool["bytes"]<=32*1024**2)
    return value

def close_items(items):
    failure = None
    for item in reversed(tuple(items)):
        try:
            if isinstance(item, int):
                os.close(item)
            else:
                item.close()
        except BaseException as error:
            if failure is None: failure = error
    if failure is not None: raise failure

def write_new(directory, name, value):
    require(name in ("context-pin.json", HANDOFF, OUTPUT))
    raw = component.encoded(value)
    require(len(raw)<=LIMIT)
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    try:
        os.fchmod(fd,0o600)
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:])
            require(count>0)
            offset+=count
        os.fsync(fd)
    finally:os.close(fd)
    os.fsync(directory)
    return hashlib.sha256(raw).hexdigest()

class HostTool:
    """Fixed optional root-owned host systemctl; no caller-selected executable."""
    def __init__(self, pin, deadline):
        self.resources=[]
        self.fd=None
        self.deadline=deadline
        self.path=Path("/usr/bin/systemctl")
        try:
            self.usr=component.Directory(Path("/usr"))
            self.resources.append(self.usr)
            require(os.fstat(self.usr.fd).st_uid==0)
            try:os.stat("bin",dir_fd=self.usr.fd,follow_symlinks=False)
            except FileNotFoundError:
                require(pin is None)
                self.absent=True
                self.parent=None
                self.recheck()
                return
            self.parent=component.Directory(self.path.parent)
            self.resources.append(self.parent)
            require(os.fstat(self.parent.fd).st_uid==0)
            try:info=os.stat(self.path.name,dir_fd=self.parent.fd,follow_symlinks=False)
            except FileNotFoundError:
                require(pin is None)
                self.absent=True
                self.recheck()
                return
            require(pin is not None)
            self.absent=False
            # Existing unqualified aliases cannot be relabelled as absence.
            require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and stat.S_IMODE(info.st_mode) in (0o555,0o755))
            self.identity=resident.file_identity(info)
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.parent.fd)
            require(resident.file_identity(os.fstat(self.fd))==self.identity and info.st_size==pin["bytes"])
            digest,offset=hashlib.sha256(),0
            while offset<info.st_size:
                tick(deadline)
                raw=os.pread(self.fd,min(1024**2,info.st_size-offset),offset)
                require(raw)
                digest.update(raw);offset+=len(raw)
            require(not os.pread(self.fd,1,offset) and digest.hexdigest()==pin["sha256"])
            self.recheck()
        except BaseException:
            self.close()
            raise
    def recheck(self):
        tick(self.deadline)
        self.usr.recheck()
        if self.parent is None:
            try:os.stat("bin",dir_fd=self.usr.fd,follow_symlinks=False)
            except FileNotFoundError:return
            raise ValueError("resident-sources-refused")
        self.parent.recheck()
        try:current=os.stat(self.path.name,dir_fd=self.parent.fd,follow_symlinks=False)
        except FileNotFoundError:
            require(self.absent)
            return
        require(not self.absent and resident.file_identity(current)==self.identity==resident.file_identity(os.fstat(self.fd)))
    def close(self):
        held,self.resources=self.resources,[]
        fd,self.fd=self.fd,None
        close_items((*held,*(() if fd is None else (fd,))))


class ComponentWitness:
    """Installed public component only; never native auth/profile contents."""
    def __init__(self, home, pins, deadline):
        self.resources = []
        self.tree = None
        self.lease = None
        self.data=self.state=None
        self.missing=[]
        self.deadline=deadline
        try:
            if pins is None:
                for base in (Path(home)/".local/share",Path(home)/".local/state"):
                    parent=component.Directory(base)
                    self.resources.append(parent)
                    for name in ("omux-acquisition","codex"):
                        try:os.stat(name,dir_fd=parent.fd,follow_symlinks=False)
                        except FileNotFoundError:
                            self.missing.append((parent,name))
                            break
                        require(name!="codex")
                        parent=component.Directory(parent.path/name,0o700)
                        self.resources.append(parent)
                require(len(self.missing)==2)
                self.recheck()
                return
            self.data = component.Directory(Path(home)/".local/share/omux-acquisition/codex", 0o700)
            self.resources.append(self.data)
            self.lease=os.open(".lock",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.data.fd)
            lock=os.fstat(self.lease)
            require(stat.S_ISREG(lock.st_mode) and lock.st_uid==os.getuid() and lock.st_gid==os.getgid()
                and lock.st_nlink==1 and lock.st_size==0 and stat.S_IMODE(lock.st_mode)==0o600)
            self.lease_id=resident.file_identity(lock)
            fcntl.flock(self.lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
            self.state = component.Directory(Path(home)/".local/state/omux-acquisition/codex", 0o700)
            self.resources.append(self.state)
            record = component.File(self.state.path/"install.json", deadline, mode=0o600, limit=131072)
            self.resources.append(record)
            require(record.row["sha256"] == pins["install_sha256"])
            selected = component.parsed(record.raw(131072), True)
            require(set(selected) == component.RECORD_KEYS
                and selected["component_sha256"] == pins["component_sha256"]
                and selected["producer"]["sha256"] == pins["producer_sha256"]
                and selected["data_home"] == str(Path(home)/".local/share")
                and selected["state_home"] == str(Path(home)/".local/state"))
            self.tree, held = component.installed(self.data, self.state, selected, deadline)
            self.resources.extend(held)
            descriptor = component.parsed(self.tree.files["component.json"].raw(), True)
            component.validate_component(descriptor)
            require(self.tree.files["component.json"].row["sha256"] == pins["component_sha256"]
                and selected["files"] == descriptor["files"] | {"component.json":self.tree.files["component.json"].row})
            component.inner(component.parsed(self.tree.files["native-source-receipt.json"].raw()))
            # The same existing fixed singleton API outer verifier closes the inner relation.
            outer = component.parsed(self.tree.files["qualification.json"].raw(1024**2))
            q = descriptor["qualification"]["outer"]
            expected = {"path":str(component.selected_path(q["id"], outer)),
                **{key:q[key] for key in ("sha256","bytes","source_commit","graph_sha256")}}
            component.outer(outer, expected, component.DEVICE)
            require(self.tree.files["qualification.json"].row["sha256"] == q["sha256"])
            self.recheck()
        except BaseException:
            self.close()
            raise
    def set_deadline(self, deadline):
        self.deadline=deadline
        for item in (*self.resources, *([] if self.tree is None else self.tree.files.values())):
            if hasattr(item, "deadline"): item.deadline = deadline
    def recheck(self):
        tick(self.deadline)
        for item in self.resources: item.recheck()
        if self.missing:
            require(len(self.missing)==2 and self.tree is None and self.lease is None)
            for parent,name in self.missing:
                try:os.stat(name,dir_fd=parent.fd,follow_symlinks=False)
                except FileNotFoundError:continue
                raise ValueError("resident-sources-refused")
            return
        self.tree.recheck()
        require(self.lease_id==resident.file_identity(os.fstat(self.lease))
            ==resident.file_identity(os.stat(".lock",dir_fd=self.data.fd,follow_symlinks=False)))
    def close(self):
        items, self.resources = self.resources, []
        tree, self.tree = self.tree, None
        lease,self.lease=self.lease,None
        close_items((*items, *(() if tree is None else (tree,)), *(() if lease is None else (lease,))))

class SourceParent:
    """Only fixed own source-parent metadata; never enumerates/reads profiles."""
    def __init__(self, home):
        self.held = []
        self.rows = []
        self.captures=[]
        base = Path(home)/".local/state"
        try:
            capture=component.Directory(base)
            self.captures.append(capture)
            fd = os.dup(capture.fd)
            self.held.append(fd)
            require(os.fstat(fd).st_uid == os.getuid())
            self.rows.append((base,fd,resident.stable(os.fstat(fd))))
            for name in ("omux-native-sources","codex"):
                try: os.stat(name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError: os.mkdir(name,0o700,dir_fd=fd)
                child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                self.held.append(child)
                info = os.fstat(child)
                require(info.st_uid == os.getuid() and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o700)
                base = base/name
                self.rows.append((base, child, resident.stable(info)))
                capture=component.Directory(base,0o700)
                self.captures.append(capture)
                require(resident.stable(os.fstat(capture.fd))==resident.stable(info))
                fd = child
            self.path = base
            self.recheck()
        except BaseException:
            self.close()
            raise
    def recheck(self):
        for capture in self.captures:capture.recheck()
        for path, fd, expected in self.rows:
            named = resident.open_directory(path, path != self.rows[0][0])
            try: require(resident.stable(os.fstat(named)) == expected == resident.stable(os.fstat(fd)))
            finally: os.close(named)
    def close(self):
        held, self.held = self.held, []
        captures,self.captures=self.captures,[]
        close_items((*held,*captures))

def healthy(observer, deadline):
    tick(deadline)
    result = continuity.control_request(observer, "system.health", {}, deadline=deadline)
    require(type(result.get("protocol_version")) is int and result["protocol_version"] == 2
        and result.get("status") == "ready" and result.get("custody_available") is True)
    tick(deadline)

def gui_environment(home, endpoint):
    # No ambient remote-manager, native-home, SSH/proxy/loader/Qt selectors.
    return {"HOME":str(home), "XDG_CONFIG_HOME":str(home/".config"),
        "XDG_DATA_HOME":str(home/".local/share"), "XDG_CACHE_HOME":str(home/".cache"),
        "XDG_STATE_HOME":str(home/".local/state"), "XDG_RUNTIME_DIR":"/run/user/"+str(os.getuid()),
        "DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/"+str(os.getuid())+"/bus",
        "OMUX_INSTANCE":"default", "QT_QPA_PLATFORM":"wayland", "WAYLAND_DISPLAY":str(endpoint),
        "LANG":"C.UTF-8", "LC_ALL":"C.UTF-8", "PATH":"/nonexistent"}

def launch_projection(status):
    require(type(status) is int and status == 0)
    return {"installed_controls_exited":True, "operator_owns_sources_clicks":True,
        "provider_requested_by_carrier":False, "service_changed_by_carrier":False,
        "credential_contents_read_by_carrier":False, "enrollment_verified":False,
        "usable_grant_verified":False, "native_support":False, "same_process_handoff_proven":False}

def validate_projection(value):
    expected=launch_projection(0)
    require(type(value) is dict and set(value)==set(expected)
        and all(type(value[key]) is bool and value[key] is expected[key] for key in expected))
    return value

def launch(context, popen=subprocess.Popen):
    """Owned installed normal controls; no synthetic interaction/readiness claim."""
    context.recheck()
    child = None
    owned_pid = None
    failure = None
    status = None
    try:
        tick(context.work_deadline)
        child = popen([str(context.launcher)], env=gui_environment(context.home, context.endpoint),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True)
        # PID is owned by this exact constructor; never discover/signal another UI.
        require(type(child.pid) is int and child.pid > 1)
        owned_pid=child.pid
        while child.poll() is None:
            tick(context.work_deadline)
            context.recheck()
            left=(context.work_deadline-time.monotonic_ns())/10**9
            require(left>0)
            try:child.wait(timeout=min(0.25,left))
            except subprocess.TimeoutExpired:pass
        status = child.returncode
        context.recheck()
        return launch_projection(status)
    except BaseException as error:
        failure = error
        raise
    finally:
        if child is not None and owned_pid is not None:
            try:cleanup_child(child,context.deadline)
            except BaseException:
                if failure is None:raise

def cleanup_child(child,deadline):
    """Popen-bound parent signals; the outer owned unit qualifies descendants."""
    failure=None
    try:
        if child.poll() is not None:return
    except BaseException as error:failure=error
    try:child.terminate()
    except BaseException as error:
        if failure is None:failure=error
    left=(deadline-time.monotonic_ns())/10**9
    if left>0:
        try:child.wait(timeout=min(5,left))
        except BaseException as error:
            if failure is None:failure=error
    elif failure is None:failure=ValueError("resident-sources-refused")
    try:alive=child.poll() is None
    except BaseException as error:
        alive=True
        if failure is None:failure=error
    if alive:
        try:child.kill()
        except BaseException as error:
            if failure is None:failure=error
        left=(deadline-time.monotonic_ns())/10**9
        if left>0:
            try:child.wait(timeout=left)
            except BaseException as error:
                if failure is None:failure=error
        elif failure is None:failure=ValueError("resident-sources-refused")
    if failure is not None:raise failure

class Admission:
    sources_profile = True
    def __init__(self, manifest, home, deadline, epoch, systemctl, producer_sha, observer_sha, source_root):
        self.resources, self.held, self.placeholders = [], [], []
        self.output_fd = None
        self.deadline_ns, self.action_epoch = deadline, epoch
        self.home = resident.canonical(str(home))
        self.operator = os.dup(sys.stdin.fileno())
        self.held.append(self.operator)
        work = deadline-30*10**9
        try:
            tick(work)
            self.manifest = resident.canonical(str(manifest))
            self.root = self.manifest.parent
            require(self.manifest.name == "input.json" and str(self.root).startswith("/srv/"))
            self.root_capture=component.Directory(self.root,0o700)
            self.resources.append(self.root_capture)
            self.directory = os.dup(self.root_capture.fd)
            self.held.append(self.directory)
            self.root_id = resident.stable(os.fstat(self.directory))
            require(os.listdir(self.directory) == ["input.json"])
            self.input = namespace.PublicFile(self.manifest, LIMIT, 0o600)
            self.resources.append(self.input)
            self.value = manifest_schema(json.loads(self.input.raw,object_pairs_hook=resident.unique), home, epoch)
            self.selected = self.value["resident"]
            require(HEX.fullmatch(producer_sha) and HEX.fullmatch(observer_sha)
                and hashlib.sha256((Path(source_root)/"delivery/resident_installed_sources.py").read_bytes()).hexdigest() == producer_sha
                and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == observer_sha)
            yoga.local_identity(self.value["seat"], work, os.getuid(), self.operator)
            self.observer = continuity.ResidentObserver(self.selected, systemctl, work)
            self.resources.append(self.observer)
            healthy(self.observer, work)
            require(set(os.listdir(self.observer.runtime))=={"control.sock","adapter.sock","browser.sock"})
            self.runtime_sockets={name:namespace.socket_peer(self.observer.runtime/name,self.selected,work)
                for name in ("control.sock","adapter.sock","browser.sock")}
            self.component = ComponentWitness(home, self.value["component"], work)
            self.resources.append(self.component)
            self.source = SourceParent(home)
            self.resources.append(self.source)
            self.launcher = Path(self.selected["prefix"])/"bin/omux-control"
            require(any(str(item.path) == str(self.launcher) for item,_ in self.observer.payload))
            self.host_systemctl = HostTool(self.value["host_systemctl"],work)
            self.resources.append(self.host_systemctl)
            run = self.root/"run"
            for relative in ("", "user", "user/"+str(os.getuid()), "user/"+str(os.getuid())+"/systemd",
                             "user/"+str(os.getuid())+"/"+self.observer.runtime.name):
                path = run/relative
                os.mkdir(path,0o700)
                fd = resident.open_directory(path,True)
                self.held.append(fd)
                self.placeholders.append((path,fd,resident.stable(os.fstat(fd))))
            shadow = run/"user"/str(os.getuid())
            self.mountpoints = []
            for path in (shadow/"bus",shadow/"systemd/private",self.root/"wayland.sock"):
                self.mountpoints.append(resident.held_mountpoint(path))
            self.display, self.display_pin = display.capture_pinned(self.value["seat"]["sourceSocket"],
                str(self.root/"wayland.sock"),str(self.root),os.getuid(),work)
            self.resources.append(self.display_pin)
            require(self.display["snapshot"] == self.value["seat"]["compositorSnapshot"])
            self.endpoint = Path(DESTINATION)/"wayland.sock"
            self.context = {"producer":LABEL,"action_epoch":epoch,"producer_source_sha256":producer_sha,
                "observer_source_sha256":observer_sha,"input_sha256":hashlib.sha256(self.input.raw).hexdigest(),
                "deadline_ns":deadline}
            write_new(self.directory,"context-pin.json",self.context)
            self.context_file = namespace.PublicFile(self.root/"context-pin.json", LIMIT, 0o600)
            self.resources.append(self.context_file)
            self.facts = {"scope":PROFILE, "installed_controls_only":True,"enrollment_requested_by_carrier":False,
                "resident_memory":resident.RESIDENT_MEMORY,"resident_tasks":resident.RESIDENT_TASKS,
                "resident_cpu_percent":resident.RESIDENT_CPU_PERCENT,"proof_memory":PROOF_MEMORY,
                "proof_tasks":PROOF_TASKS,"proof_cpu_percent":PROOF_CPU_PERCENT}
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
        os.mkdir("sources-handoff",0o700,dir_fd=self.run_fd)
        self.output = self.run/"sources-handoff"
        self.output_capture=component.Directory(self.output,0o700)
        self.resources.append(self.output_capture)
        self.output_fd = os.dup(self.output_capture.fd)
        self.output_id = resident.stable(os.fstat(self.output_fd))
    def recheck(self):
        bound = self.deadline_ns if getattr(self,"collecting",False) else self.deadline_ns-30*10**9
        tick(bound)
        require(resident.stable(os.fstat(self.directory)) == self.root_id == resident.stable(self.root.stat(follow_symlinks=False))
            and set(os.listdir(self.directory)) == {"input.json","context-pin.json","run","wayland.sock"})
        for path, fd, expected in self.placeholders:
            require(resident.stable(os.fstat(fd)) == expected == resident.stable(path.stat(follow_symlinks=False)))
        for path, file, expected in self.mountpoints:
            require(resident.regular_mountpoint_witness(path,file.fileno()) == expected)
        for item in self.resources:
            if item not in (self.observer,self.display_pin):
                item.recheck()
        for name,expected in self.runtime_sockets.items():
            require(namespace.socket_peer(self.observer.runtime/name,self.selected,bound)==expected)
        yoga.local_identity(self.value["seat"],bound,os.getuid(),self.operator)
        old = self.observer.deadline
        try:
            self.observer.deadline = bound
            self.observer.observe()
            healthy(self.observer,bound)
        finally: self.observer.deadline = old
        witness = dict(self.display,deadline_ns=bound)
        self.display_pin.check(witness)
        if self.output_fd is not None:
            require(resident.stable(os.fstat(self.run_fd)) == self.run_id == resident.stable(self.run.stat(follow_symlinks=False))
                and resident.stable(os.fstat(self.output_fd)) == self.output_id == resident.stable(self.output.stat(follow_symlinks=False)))
        return self.facts
    def bindings(self):
        parent = self.observer.bus.parent
        return [str(self.root)+":"+DESTINATION,str(self.root/"run")+":/run",
            str(self.observer.runtime)+":"+str(self.observer.runtime),
            str(parent/"bus")+":"+str(parent/"bus")+":norbind",
            str(parent/"systemd/private")+":"+str(parent/"systemd/private")+":norbind",
            str(self.launcher.parent.parent)+":"+str(self.launcher.parent.parent),
            self.selected["records"]+":"+self.selected["records"],
            *([] if self.component.data is None else [str(self.component.data.path)+":"+str(self.component.data.path),
                str(self.component.state.path)+":"+str(self.component.state.path)]),
            self.value["seat"]["sourceSocket"]+":"+str(self.endpoint)+":norbind"]
    def writable_binding(self):
        return str(self.source.path)+":"+str(self.source.path)
    def verify_bindings(self, actual, run=None):
        leaves = [v.removesuffix(":norbind") for v in self.bindings() if v.endswith(":norbind")]
        expected = resident.normalize_binds(" ".join(self.bindings()),leaves)
        got = resident.normalize_binds(actual.get("BindReadOnlyPaths",""),leaves,readback=True)
        writable = resident.normalize_binds(actual.get("BindPaths",""),readback=True)
        require(len(got)==len(expected) and set(got)==set(expected)
            and len(writable)==2 and set(writable)=={self.writable_binding(),str(run)+":"+str(run)} and run==self.run)
    def environment(self):
        require(self.output_fd is not None)
        return {VARIABLE:str(self.deadline_ns),"OMUX_RESIDENT_SOURCES_EPOCH":self.action_epoch,
            "OMUX_RESIDENT_SOURCES_INPUT_ID":namespace.directory_id(os.fstat(self.directory)),
            "OMUX_RESIDENT_SOURCES_OUTPUT":str(self.output),
            "OMUX_RESIDENT_SOURCES_OUTPUT_ID":namespace.directory_id(os.fstat(self.output_fd)),
            "OMUX_RESIDENT_SOURCES_SYSTEMCTL":str(self.observer.systemctl),
            "XDG_RUNTIME_DIR":str(self.observer.runtime.parent),"DBUS_SESSION_BUS_ADDRESS":"unix:path="+str(self.observer.bus)}
    def runtime_seconds(self):
        tick(self.deadline_ns,30*10**9)
        return int((self.deadline_ns-time.monotonic_ns())//10**9)-30
    def completed(self,status,cleaned,epoch,producer_sha,graph_sha):
        require(type(status) is int and status==0 and cleaned is True and epoch==self.action_epoch
            and producer_sha==self.context["producer_source_sha256"] and HEX.fullmatch(graph_sha))
        self.collecting=True
        resident.collection_deadline(self.observer,self.resources,self.deadline_ns)
        self.component.set_deadline(self.deadline_ns)
        self.host_systemctl.deadline=self.deadline_ns
        self.recheck()
        require(os.listdir(self.output_fd)==[HANDOFF])
        incoming=namespace.PublicFile(self.output/HANDOFF,LIMIT,0o600)
        try:
            value=json.loads(incoming.raw,object_pairs_hook=resident.unique)
            require(type(value) is dict and set(value)=={"context","projection"} and value["context"]==self.context
                and validate_projection(value["projection"])==launch_projection(0))
            self.observer.observe(full=True)
            healthy(self.observer,self.deadline_ns)
            result={**value["projection"],"producer":LABEL,"action_epoch":epoch,"input_sha256":self.context["input_sha256"],
                "producer_source_sha256":producer_sha,"observer_source_sha256":self.context["observer_source_sha256"],
                "installed_payload_preserved":True,"normal_resident_custody_observed":True,
                "wayland_peer_preserved":True,"controller_exited":True,"proof_descendants_empty":True,
                "guard_graph_sha256":graph_sha,"requires_successful_guard_receipt":True}
            digest=write_new(self.run_fd,OUTPUT,result)
            incoming.recheck()
            self.recheck()
            return {"scope":SCOPE,"basename":OUTPUT,"sha256":digest,
                "verified_after_controller_exit":True,"guard_graph_sha256":graph_sha}
        finally: incoming.close()
    def close(self):
        resources,self.resources=self.resources,[]
        mounts,self.mountpoints=getattr(self,"mountpoints",[]),[]
        held,self.held=self.held,[]
        output,self.output_fd=self.output_fd,None
        close_items((*held,*resources,*(file for _,file,_ in mounts),*(() if output is None else (output,))))

class SourcesContext:
    @classmethod
    def open(cls):
        self=cls.__new__(cls)
        self.resources,self.held=[],[]
        try:
            self.deadline=int(os.environ[VARIABLE])
            self.work_deadline=self.deadline-30*10**9
            tick(self.work_deadline)
            self.home=Path(pwd.getpwuid(os.getuid()).pw_dir)
            self.namespace_capture=component.Directory(Path(DESTINATION),0o700)
            self.resources.append(self.namespace_capture)
            self.namespace=os.dup(self.namespace_capture.fd)
            self.held.append(self.namespace)
            require(namespace.directory_id(os.fstat(self.namespace))==os.environ["OMUX_RESIDENT_SOURCES_INPUT_ID"]
                and set(os.listdir(self.namespace))=={"input.json","context-pin.json","run","wayland.sock"})
            inp=namespace.PublicFile(Path(DESTINATION)/"input.json",LIMIT,0o600)
            self.resources.append(inp)
            self.value=manifest_schema(json.loads(inp.raw,object_pairs_hook=resident.unique),self.home,os.environ["OMUX_RESIDENT_SOURCES_EPOCH"])
            pin=namespace.PublicFile(Path(DESTINATION)/"context-pin.json",LIMIT,0o600)
            self.resources.append(pin)
            self.context=json.loads(pin.raw,object_pairs_hook=resident.unique)
            require(type(self.context) is dict and set(self.context)=={"producer","action_epoch","producer_source_sha256",
                "observer_source_sha256","input_sha256","deadline_ns"} and self.context["producer"]==LABEL
                and self.context["action_epoch"]==self.value["action_epoch"] and type(self.context["deadline_ns"]) is int
                and self.context["deadline_ns"]==self.deadline and self.context["input_sha256"]==hashlib.sha256(inp.raw).hexdigest()
                and self.context["observer_source_sha256"]==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                and all(HEX.fullmatch(self.context[key]) for key in ("input_sha256","observer_source_sha256","producer_source_sha256")))
            self.observer=continuity.ResidentObserver(self.value["resident"],Path(os.environ["OMUX_RESIDENT_SOURCES_SYSTEMCTL"]),self.work_deadline)
            self.resources.append(self.observer)
            self.component=ComponentWitness(self.home,self.value["component"],self.work_deadline)
            self.resources.append(self.component)
            self.host_tool=HostTool(self.value["host_systemctl"],self.work_deadline)
            self.resources.append(self.host_tool)
            self.source=SourceParent(self.home)
            self.resources.append(self.source)
            self.launcher=Path(self.value["resident"]["prefix"])/"bin/omux-control"
            require(any(str(item.path)==str(self.launcher) for item,_ in self.observer.payload))
            self.endpoint=Path(DESTINATION)/"wayland.sock"
            self.output=resident.canonical(os.environ["OMUX_RESIDENT_SOURCES_OUTPUT"])
            require(self.output.name=="sources-handoff" and self.output.parent.name==self.value["action_epoch"]
                and self.output.parent.parent in resident.PUBLIC_ROOTS)
            self.output_capture=component.Directory(self.output,0o700)
            self.resources.append(self.output_capture)
            self.output_fd=os.dup(self.output_capture.fd)
            self.held.append(self.output_fd)
            self.output_id=resident.stable(os.fstat(self.output_fd))
            require(namespace.directory_id(os.fstat(self.output_fd))==os.environ["OMUX_RESIDENT_SOURCES_OUTPUT_ID"]
                and not os.listdir(self.output_fd))
            self.recheck()
            return self
        except BaseException:
            self.close()
            raise
    def recheck(self):
        tick(self.work_deadline)
        require(namespace.directory_id(os.fstat(self.namespace))==os.environ["OMUX_RESIDENT_SOURCES_INPUT_ID"]
            ==namespace.directory_id(Path(DESTINATION).stat(follow_symlinks=False)))
        for item in self.resources:
            if item is not self.observer:item.recheck()
        runtime=self.observer.runtime
        parent=runtime.parent
        require(os.listdir("/run")==["user"] and os.listdir("/run/user")==[str(os.getuid())]
            and set(os.listdir(parent))=={"bus","systemd",runtime.name}
            and os.listdir(parent/"systemd")==["private"]
            and set(os.listdir(runtime))=={"control.sock","adapter.sock","browser.sock"})
        for name in ("control.sock","adapter.sock","browser.sock"):
            namespace.socket_peer(runtime/name,self.value["resident"],self.work_deadline)
        require(all(os.statvfs(path).f_flag&os.ST_RDONLY for path in (Path("/run"),runtime,parent/"bus",parent/"systemd/private")))
        self.observer.observe()
        healthy(self.observer,self.work_deadline)
        observed=display.inspect_endpoint(str(self.endpoint),os.getuid(),self.work_deadline)
        require(observed==self.value["seat"]["compositorSnapshot"])
        require(os.environ.get("XDG_RUNTIME_DIR")=="/run/user/"+str(os.getuid())
            and os.environ.get("DBUS_SESSION_BUS_ADDRESS")=="unix:path=/run/user/"+str(os.getuid())+"/bus")
        tick(self.work_deadline)
    def publish(self,result):
        self.recheck()
        validate_projection(result)
        write_new(self.output_fd,HANDOFF,{"context":self.context,"projection":result})
        self.recheck()
    def close(self):
        items,self.resources=self.resources,[]
        held,self.held=self.held,[]
        close_items((*held,*items))
    def __enter__(self):return self
    def __exit__(self,*unused):self.close()

def projection(actual,verified=False):
    return resident.projection(actual,verified)

def rejection(error):
    return "resident-sources-refused"
