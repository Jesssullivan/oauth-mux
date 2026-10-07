"""Narrow owned installation update; metadata-only runtime preservation."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shlex
import sys
import time
import uuid
import guard_resident_enrollment_profile as resident
# Public declared delivery sources. No portable generated launcher import here.
sys.path.insert(0,str(Path(__file__).parent.parent/"delivery"))
import install
import pack

def tick(deadline):
    resident.require(type(deadline) is int and time.monotonic_ns() < deadline)

def pins(value,home):
    resident.require(type(value) is dict and set(value) == {"previous_archive_sha256",
        "archive_path","archive_sha256","archive_bytes","manifest_sha256","qualification",
        "previous_archive_path","previous_archive_bytes","previous_manifest_sha256"})
    for name in ("previous_archive_sha256","archive_sha256","manifest_sha256","previous_manifest_sha256"):
        resident.require(type(value[name]) is str and re.fullmatch(r"[0-9a-f]{64}",value[name]))
    resident.require(value["previous_archive_sha256"] != value["archive_sha256"]
        and type(value["archive_bytes"]) is int and 0 < value["archive_bytes"] <= pack.MAX_BYTES)
    qualification = value["qualification"]
    resident.require(type(qualification) is dict and set(qualification) == {
        "path","sha256","bytes","source_commit","graph_sha256"})
    for name in ("sha256","graph_sha256"):
        resident.require(type(qualification[name]) is str and re.fullmatch(r"[0-9a-f]{64}",qualification[name]))
    resident.require(type(qualification["bytes"]) is int and 0 < qualification["bytes"] <= 8*1024*1024
        and type(qualification["source_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}",qualification["source_commit"]))
    path = resident.canonical(qualification["path"])
    resident.require(path.name == "receipt.json" and str(uuid.UUID(path.parent.name)) == path.parent.name)
    parent = path.parent.parent
    home_root = Path(home)/".local/state/omux-execution-20261005"
    fast = parent.parent == Path("/srv/fast-local/jess/state/codex") and re.fullmatch(r"omux-[a-z0-9-]+",parent.name)
    resident.require(parent == home_root or fast)
    previous = resident.canonical(value["previous_archive_path"])
    resident.require(type(value["previous_archive_bytes"]) is int and 0 < value["previous_archive_bytes"] <= pack.MAX_BYTES)
    archive_namespace(previous,home)
    archive = resident.canonical(value["archive_path"])
    output = archive_namespace(archive,home)
    # Only the actual successful receipt can select a cache pointer after its safe read.
    resident.require(output.parent.parent == path.parent.parent)
    return value

ARCHIVE_RELATIVE = Path("execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz")

def archive_namespace(archive,home):
    outputs = [part for part in archive.parents if part.name == "output-base"]
    resident.require(len(outputs) == 1)
    output = outputs[0]
    resident.require(archive == output/ARCHIVE_RELATIVE)
    container = output.parent
    if not re.fullmatch(r"cache-v2-[0-9a-f]{64}",container.name):
        resident.require(str(uuid.UUID(container.name)) == container.name)
    root = container.parent
    resident.require(root == Path(home)/".local/state/omux-execution-20261005"
        or root.parent == Path("/srv/fast-local/jess/state/codex") and re.fullmatch(r"omux-[a-z0-9-]+",root.name))
    return output

def qualification_output(receipt,qualification):
    """Match the guard's canonical argument and exact chosen cache/epoch namespace."""
    path = resident.canonical(qualification["path"])
    epoch = path.parent.name
    resident.require(type(receipt) is dict and receipt["id"] == epoch and receipt["artifact_epoch"] == epoch
        and receipt["profile"] == "standard" and receipt["verb"] == "build"
        and receipt["targets"] == ["//delivery:default_instance_archive"]
        and type(receipt["exit"]) is int and receipt["exit"] == 0
        and type(receipt["workload_exit"]) is int and receipt["workload_exit"] == 0
        and receipt["descendants_empty"] is True and receipt["cleanup"]["state"] == "empty"
        and receipt["controller_failure"] is None
        and type(receipt["source_dirty"]) is str and receipt["source_dirty"] == "false"
        and receipt["source_commit"] == qualification["source_commit"]
        and receipt["graph_sha256"] == qualification["graph_sha256"])
    if receipt["cache_reuse_requested"] is True:
        resident.require(type(receipt["cache_policy"]) is int and receipt["cache_policy"] == 2
            and type(receipt["cache_key"]) is str and re.fullmatch(r"[0-9a-f]{64}",receipt["cache_key"]))
        expected = path.parent.parent/("cache-v2-"+receipt["cache_key"])/"output-base"
    else:
        resident.require(receipt["cache_reuse_requested"] is False and receipt["cache_policy"] is None
            and receipt["cache_key"] is None)
        expected = path.parent/"output-base"
    resident.require(resident.canonical(receipt["output_base"]) == expected)
    return expected

def start_pins(value,home):
    resident.require(type(value) is dict and set(value) == {
        "archive_path","archive_sha256","archive_bytes","manifest_sha256","qualification"})
    for name in ("archive_sha256","manifest_sha256"):
        resident.require(type(value[name]) is str and re.fullmatch(r"[0-9a-f]{64}",value[name]))
    resident.require(type(value["archive_bytes"]) is int and 0 < value["archive_bytes"] <= pack.MAX_BYTES)
    q = value["qualification"]
    resident.require(type(q) is dict and set(q) == {"path","sha256","bytes","source_commit","graph_sha256"})
    for name,width in (("sha256",64),("graph_sha256",64),("source_commit",40)):
        resident.require(type(q[name]) is str and re.fullmatch(r"[0-9a-f]{"+str(width)+"}",q[name]))
    resident.require(type(q["bytes"]) is int and 0 < q["bytes"] <= 8*1024*1024)
    path = resident.canonical(q["path"])
    resident.require(path.name == "receipt.json" and str(uuid.UUID(path.parent.name)) == path.parent.name)
    output = archive_namespace(resident.canonical(value["archive_path"]),home)
    resident.require(output.parent.parent == path.parent.parent)
    return value

def active_start_properties(values,selected):
    resident.require(set(values) == IDLE_PROPERTIES and values["LoadState"] == "loaded"
        and values["ActiveState"] == "active" and values["SubState"] == "running"
        and values["MainPID"].isdigit() and int(values["MainPID"]) > 1)
    uid = os.getuid()
    group = "/user.slice/user-"+str(uid)+".slice/user@"+str(uid)+".service/app.slice/ai.xoxd.omux.service"
    resident.require(values["ControlGroup"] == group)
    inactive = dict(values)
    inactive.update(ActiveState="inactive",SubState="dead",MainPID="0",ControlGroup="")
    inactive_installation(inactive,selected)
    return int(values["MainPID"]),group

def start_control_peer(peer,pid):
    resident.require(stat.S_IMODE(peer[0][2]) == 0o600 and peer[1] == pid
        and peer[2] == resident.start_ticks(pid))

def start_health(value):
    # Version-bound control metadata, matching src/control.zig protocol_version.
    resident.require(type(value) is dict and value.get("protocol_version") == 2
        and type(value.get("protocol_version")) is int and value.get("live_handoff_proven") is False)
    if value.get("status") == "vault_locked":
        resident.require(value.get("custody_available") is False and value.get("metadata_loaded") is False
            and value.get("provider_access") is False
            and value.get("recovery_action") == "unlock_platform_vault_then_restart_daemon")
        return {"control_plane_ready":True,"custody_available":False,"vault_locked":True}
    resident.require(value.get("status") == "ready" and value.get("custody_available") is True
        and type(value.get("revision")) is int and value["revision"] >= 0)
    return {"control_plane_ready":True,"custody_available":True,"vault_locked":False}

def locked_idle_metadata(health,handshake):
    result=start_health(health)
    resident.require(result["vault_locked"] and type(handshake) is dict
        and type(handshake.get("protocol_version")) is int and handshake["protocol_version"] == 2
        and handshake.get("service") == "omuxd" and handshake.get("channel") == "control"
        and handshake.get("custody_available") is False
        and type(handshake.get("capabilities")) is dict
        and handshake["capabilities"].get("credential_free_control") is True
        and handshake["capabilities"].get("native_launch") is False
        and handshake["capabilities"].get("live_handoff_proven") is False)
    return result

def original_process_exited(identity):
    from resident_enrollment import process_identity
    try:
        current=process_identity(identity[0])
    except FileNotFoundError:
        return True
    resident.require(current != identity)
    return True

class OwnedFirstStart:
    """Qualified first start with only the existing zero-byte lock; no DB recovery."""
    def __init__(self,selected,home,deadline):
        self.selected,self.deadline = selected,deadline
        self.files,self.unit,self.directory,self.lock = [],None,None,None
        try:
            self.selection = start_pins(selected["start"],home)
            q = self.selection["qualification"]
            qualification = PublicFile(q["path"],deadline,8*1024*1024)
            self.files.append(qualification)
            resident.require(len(qualification.raw) == q["bytes"] and hashlib.sha256(qualification.raw).hexdigest() == q["sha256"])
            receipt = json.loads(qualification.raw,object_pairs_hook=resident.unique)
            output = qualification_output(receipt,q)
            resident.require(Path(self.selection["archive_path"]) == output/ARCHIVE_RELATIVE)
            self.archive = PublicFile(self.selection["archive_path"],deadline,pack.MAX_BYTES)
            self.files.append(self.archive)
            resident.require(len(self.archive.raw) == self.selection["archive_bytes"]
                and hashlib.sha256(self.archive.raw).hexdigest() == self.selection["archive_sha256"])
            files,_ = pack.archive_contents(self.archive.raw)
            resident.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == self.selection["manifest_sha256"])
            manifest = json.loads(files["release-manifest.json"],object_pairs_hook=resident.unique)
            resident.require(manifest["channel"] == "release" and manifest["distribution"] == "portable-linux"
                and manifest["target"] == "x86_64-linux" and manifest["provenance"] == {"sourceRevision":None,"sourceDirty":True})
            plan = install.installation_plan(manifest,files,Path(selected["prefix"]),Path(selected["records"]),
                Path(selected["service_path"]),"linux",daemon_state_dir=Path(selected["runtime_state"]))
            expected = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode} for path,raw,mode in plan}
            self.unit = resident.OwnedUnitCustody(selected)
            record = json.loads(self.unit.files[0][4],object_pairs_hook=resident.unique)
            resident.require(record["product"] == manifest["product"] and record["artifact"] == {
                "channel":manifest["channel"],"target":manifest["target"],"distribution":manifest["distribution"],
                "provenance":manifest["provenance"],"archiveSha256":self.selection["archive_sha256"],
                "manifestSha256":self.selection["manifest_sha256"]}
                and len(record["files"]) == len(expected)
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]} for row in record["files"]} == expected)
            for row in record["files"]:
                public = PublicFile(row["path"],deadline,128*1024*1024,owned=True)
                self.files.append(public)
                resident.require(stat.S_IMODE(os.fstat(public.fd).st_mode) == row["mode"]
                    and hashlib.sha256(public.raw).hexdigest() == row["sha256"])
            unit = Path(selected["service_path"])
            self.unit.verify_fragment(unit.parents[4]/".config/systemd/user"/unit.name)
            self.state = Path(selected["runtime_state"])
            self.directory = resident.open_directory(self.state,private=True)
            self.root_identity = resident.stable(os.fstat(self.directory))
            self.lock = os.open("daemon.lock",os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory)
            info = os.fstat(self.lock)
            resident.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0)
            self.lock_identity = resident.file_identity(info)
            self.pristine()
        except BaseException:
            self.close()
            raise
    def pristine(self):
        self.recheck()
        resident.require(os.listdir(self.directory) == ["daemon.lock"])
    def recheck(self):
        tick(self.deadline)
        self.unit.recheck()
        for public in self.files:
            public.recheck()
        resident.require(resident.stable(os.fstat(self.directory)) == self.root_identity
            == resident.stable(self.state.stat(follow_symlinks=False))
            and resident.file_identity(os.fstat(self.lock)) == self.lock_identity
            == resident.file_identity(os.stat("daemon.lock",dir_fd=self.directory,follow_symlinks=False)))
        # Fresh startup may create encrypted SQLite and its custody metadata.
        # This never reads contents and never authorizes pre-existing DB recovery.
        names = os.listdir(self.directory)
        resident.require(set(names) <= {"daemon.lock","state.sqlite","state.sqlite.authority","state.sqlite.authority.lock",
            "state.sqlite-wal","state.sqlite-shm","state.sqlite-journal"})
        for name in names:
            info = os.stat(name,dir_fd=self.directory,follow_symlinks=False)
            resident.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
        if self.unit is not None:
            self.unit.close()
            self.unit = None
        for public in reversed(self.files):
            public.close()
        self.files = []

IDLE_PROPERTIES = {"LoadState","ActiveState","SubState","MainPID","FragmentPath","ControlGroup",
    "UnitFileState","Slice","ExecStart","DropInPaths","NeedDaemonReload","MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec"}

def inactive_installation(values,selected):
    resident.require(set(values) == IDLE_PROPERTIES and values["Slice"] == "app.slice" and not values["DropInPaths"]
        and values["NeedDaemonReload"] == "no")
    resident.recovery_loaded_properties(values)
    executable = str(Path(selected["prefix"])/"bin/omuxd")
    state = str(Path(selected["runtime_state"]))
    match = re.fullmatch(r"\{ path=([^;]+) ; argv\[\]=(.*?) ; ignore_errors=no ; .*\}",values["ExecStart"])
    resident.require(match is not None and match[1].strip() == executable
        and shlex.split(match[2]) == [executable,"--state-dir",state])
    return resident.resolve_owned_unit_fragment(values["FragmentPath"],selected["service_path"])

def inactive_cgroup(deadline):
    # Exact fixed owned unit; never enumerate other user scopes or signal a process.
    tick(deadline)
    uid = os.getuid()
    path = Path("/sys/fs/cgroup/user.slice")/("user-"+str(uid)+".slice")/("user@"+str(uid)+".service")/"app.slice/ai.xoxd.omux.service"
    parent = resident.open_directory(path.parent)
    try:
        try:
            named = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            return {"unit_cgroup_absent":True}
        resident.require(stat.S_ISDIR(named.st_mode))
    finally:
        os.close(parent)
    directory = resident.open_directory(path)
    try:
        witness = resident.stable(os.fstat(directory))
        values = {}
        for name in ("cgroup.procs","cgroup.events"):
            tick(deadline)
            fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            try:
                raw = os.read(fd,16385)
                resident.require(len(raw) <= 16384)
                values[name] = raw.decode("ascii").strip()
            finally:
                os.close(fd)
        events = resident.unique(line.split() for line in values["cgroup.events"].splitlines())
        resident.require(not values["cgroup.procs"] and events.get("populated") == "0"
            and resident.stable(os.fstat(directory)) == witness == resident.stable(path.stat(follow_symlinks=False)))
        tick(deadline)
        return {"unit_cgroup_empty":True}
    finally:
        os.close(directory)

class PublicFile:
    def __init__(self,path,deadline,limit,owned=False):
        self.path,self.deadline = Path(path),deadline
        self.parent = self.fd = None
        try:
            self.parent = resident.open_directory(self.path.parent)
            self.parent_identity = resident.stable(os.fstat(self.parent))
            self.fd = os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.parent)
            info = os.fstat(self.fd)
            resident.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode&0o022
                and info.st_uid in ((os.getuid(),) if owned else (0,os.getuid())) and 0 <= info.st_size <= limit)
            self.identity = resident.file_identity(info)
            chunks = []
            total = 0
            while True:
                tick(deadline)
                chunk = os.read(self.fd,min(1024*1024,limit-total+1))
                if not chunk:
                    break
                total += len(chunk)
                resident.require(total <= limit)
                chunks.append(chunk)
            self.raw = b"".join(chunks)
            resident.require(len(self.raw) == info.st_size)
            self.recheck()
        except BaseException:
            self.close()
            raise
    def recheck(self):
        tick(self.deadline)
        current_parent = resident.open_directory(self.path.parent)
        try:
            resident.require(resident.stable(os.fstat(current_parent)) == self.parent_identity
                == resident.stable(os.fstat(self.parent)))
        finally:
            os.close(current_parent)
        resident.require(resident.file_identity(os.fstat(self.fd)) == self.identity
            == resident.file_identity(os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)))
    def close(self):
        for name in ("fd","parent"):
            value = getattr(self,name,None)
            if value is not None:
                os.close(value)
                setattr(self,name,None)

class QualifiedExistingEnrollment:
    """Public archive/installed-software authority; never open private custody."""
    def __init__(self,selected,home,deadline):
        self.deadline = deadline
        self.files,self.unit = [],None
        try:
            self.selection = start_pins(selected["existing_archive"],home)
            q = self.selection["qualification"]
            qualification = PublicFile(q["path"],deadline,8*1024*1024)
            self.files.append(qualification)
            resident.require(len(qualification.raw) == q["bytes"]
                and hashlib.sha256(qualification.raw).hexdigest() == q["sha256"])
            receipt = json.loads(qualification.raw,object_pairs_hook=resident.unique)
            output = qualification_output(receipt,q)
            resident.require(Path(self.selection["archive_path"]) == output/ARCHIVE_RELATIVE)
            archive = PublicFile(self.selection["archive_path"],deadline,pack.MAX_BYTES)
            self.files.append(archive)
            resident.require(len(archive.raw) == self.selection["archive_bytes"]
                and hashlib.sha256(archive.raw).hexdigest() == self.selection["archive_sha256"])
            files,_ = pack.archive_contents(archive.raw)
            resident.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == self.selection["manifest_sha256"])
            manifest = json.loads(files["release-manifest.json"],object_pairs_hook=resident.unique)
            resident.require(manifest["channel"] == "release" and manifest["distribution"] == "portable-linux"
                and manifest["target"] == "x86_64-linux" and manifest["provenance"] == {"sourceRevision":None,"sourceDirty":True})
            plan = install.installation_plan(manifest,files,Path(selected["prefix"]),Path(selected["records"]),
                Path(selected["service_path"]),"linux",daemon_state_dir=Path(selected["runtime_state"]))
            expected = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode} for path,raw,mode in plan}
            self.unit = resident.OwnedUnitCustody(selected)
            record = json.loads(self.unit.files[0][4],object_pairs_hook=resident.unique)
            resident.require(record["product"] == manifest["product"] and record["artifact"] == {
                "channel":manifest["channel"],"target":manifest["target"],"distribution":manifest["distribution"],
                "provenance":manifest["provenance"],"archiveSha256":self.selection["archive_sha256"],
                "manifestSha256":self.selection["manifest_sha256"]}
                and len(record["files"]) == len(expected)
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]} for row in record["files"]} == expected)
            for row in record["files"]:
                public = PublicFile(row["path"],deadline,128*1024*1024,owned=True)
                self.files.append(public)
                resident.require(stat.S_IMODE(os.fstat(public.fd).st_mode) == row["mode"]
                    and hashlib.sha256(public.raw).hexdigest() == row["sha256"])
            self.unit.verify_fragment(Path(home)/".config/systemd/user"/Path(selected["service_path"]).name)
            self.recheck()
        except BaseException:
            self.close()
            raise
    def recheck(self):
        tick(self.deadline)
        self.unit.recheck()
        for public in self.files:
            public.recheck()
    def close(self):
        if self.unit is not None:
            self.unit.close()
            self.unit = None
        for public in reversed(self.files):
            public.close()
        self.files = []

class RuntimeFence:
    """Hold existing singleton lock and exact named/held metadata; read no private bytes."""
    def __init__(self,state,deadline,*,acquire_lock=True):
        self.state,self.deadline = Path(state),deadline
        self.held,self.entries,self.lock = [],[],None
        try:
            root = resident.open_directory(self.state,private=True)
            self.held.append(root)
            resident.require(type(acquire_lock) is bool)
            lock = os.open("daemon.lock",(os.O_RDWR if acquire_lock else os.O_PATH)|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
            self.held.append(lock)
            info = os.fstat(lock)
            resident.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
            if acquire_lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.lock = lock
            self.walk(self.state,root,0)
            self.recheck()
        except BaseException:
            self.close()
            raise
    def walk(self,path,fd,depth):
        tick(self.deadline)
        resident.require(depth <= 16 and len(self.entries) < 4096)
        info = os.fstat(fd)
        resident.require(info.st_uid == os.getuid() and not info.st_mode&0o077)
        children = tuple(sorted(os.listdir(fd))) if stat.S_ISDIR(info.st_mode) else None
        self.entries.append((path,fd,resident.file_identity(info),children))
        if children is not None:
            for name in children:
                resident.require(name not in (".","..") and "/" not in name)
                child = os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                self.held.append(child)
                item = os.fstat(child)
                resident.require(stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode))
                if stat.S_ISREG(item.st_mode):
                    resident.require(item.st_nlink == 1)
                if stat.S_ISDIR(item.st_mode):
                    # O_PATH is sufficient for file metadata but listdir needs a directory read FD.
                    os.close(self.held.pop())
                    child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    self.held.append(child)
                self.walk(path/name,child,depth+1)
    def recheck(self):
        for path,fd,witness,children in self.entries:
            tick(self.deadline)
            resident.require(resident.file_identity(os.fstat(fd)) == witness
                == resident.file_identity(path.stat(follow_symlinks=False)))
            if children is not None:
                resident.require(tuple(sorted(os.listdir(fd))) == children)
    def close(self):
        for fd in reversed(self.held):
            os.close(fd)
        self.held = []

class InstallationUpdate:
    """Only the owned record/unit/payload witness may make an old-to-new transition."""
    def __init__(self,selected,home,deadline):
        self.selected,self.deadline = selected,deadline
        self.files,self.unit,self.runtime,self.payload = [],None,None,None
        self.alias = None
        self.finished = False
        try:
            self.selection = pins(selected["update"],home)
            self.qualification = PublicFile(self.selection["qualification"]["path"],deadline,8*1024*1024)
            self.files.append(self.qualification)
            q = self.selection["qualification"]
            resident.require(len(self.qualification.raw) == q["bytes"]
                and hashlib.sha256(self.qualification.raw).hexdigest() == q["sha256"])
            receipt = json.loads(self.qualification.raw,object_pairs_hook=resident.unique)
            selected_output = qualification_output(receipt,q)
            resident.require(Path(self.selection["archive_path"]) == selected_output/ARCHIVE_RELATIVE)
            self.archive = PublicFile(self.selection["archive_path"],deadline,pack.MAX_BYTES)
            self.files.append(self.archive)
            resident.require(len(self.archive.raw) == self.selection["archive_bytes"]
                and hashlib.sha256(self.archive.raw).hexdigest() == self.selection["archive_sha256"])
            files,modes = pack.archive_contents(self.archive.raw)
            resident.require(pack.REQUIRED_FILES <= set(files)
                and hashlib.sha256(files["release-manifest.json"]).hexdigest() == self.selection["manifest_sha256"])
            manifest = json.loads(files["release-manifest.json"],object_pairs_hook=resident.unique)
            resident.require(manifest["schemaVersion"] == 1 and manifest["target"] == "x86_64-linux"
                and manifest["channel"] == "release" and manifest["distribution"] == "portable-linux"
                and manifest["provenance"] == {"sourceRevision":None,"sourceDirty":True})
            artifacts = manifest["artifacts"]
            resident.require(type(artifacts) is list and len(artifacts) == len(files)-2
                and {row["path"] for row in artifacts} == set(files)-{"release-manifest.json","SHA256SUMS"})
            for row in artifacts:
                resident.require(set(row) == {"path","sha256","size","mode"}
                    and row["sha256"] == hashlib.sha256(files[row["path"]]).hexdigest()
                    and type(row["size"]) is int and row["size"] == len(files[row["path"]])
                    and int(row["mode"],8) == modes[row["path"]])
            self.manifest_provenance = manifest["provenance"]
            self.new_product = manifest["product"]
            self.new_artifact = {"channel":manifest["channel"],"target":manifest["target"],
                "distribution":manifest["distribution"],"provenance":manifest["provenance"],
                "archiveSha256":self.selection["archive_sha256"],"manifestSha256":self.selection["manifest_sha256"]}
            self.plan = install.installation_plan(manifest,files,Path(selected["prefix"]),Path(selected["records"]),
                Path(selected["service_path"]),"linux",daemon_state_dir=Path(selected["runtime_state"]))
            self.expected = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode}
                for path,raw,mode in self.plan}
            resident.require(len(self.expected) == len(self.plan))
            self.previous_archive = PublicFile(self.selection["previous_archive_path"],deadline,pack.MAX_BYTES)
            self.files.append(self.previous_archive)
            resident.require(len(self.previous_archive.raw) == self.selection["previous_archive_bytes"]
                and hashlib.sha256(self.previous_archive.raw).hexdigest() == self.selection["previous_archive_sha256"])
            old_files,_ = pack.archive_contents(self.previous_archive.raw)
            resident.require(hashlib.sha256(old_files["release-manifest.json"]).hexdigest() == self.selection["previous_manifest_sha256"])
            old_manifest = json.loads(old_files["release-manifest.json"],object_pairs_hook=resident.unique)
            resident.require(old_manifest["channel"] == "release" and old_manifest["distribution"] == "portable-linux"
                and old_manifest["target"] == "x86_64-linux")
            old_plan = install.installation_plan(old_manifest,old_files,Path(selected["prefix"]),Path(selected["records"]),
                Path(selected["service_path"]),"linux",daemon_state_dir=Path(selected["runtime_state"]))
            self.previous_product = old_manifest["product"]
            self.previous_artifact = {"channel":old_manifest["channel"],"target":old_manifest["target"],
                "distribution":old_manifest["distribution"],"provenance":old_manifest["provenance"],
                "archiveSha256":self.selection["previous_archive_sha256"],"manifestSha256":self.selection["previous_manifest_sha256"]}
            self.previous_expected = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode}
                for path,raw,mode in old_plan}
            self.runtime = RuntimeFence(selected["runtime_state"],deadline)
            self.unit = resident.OwnedUnitCustody(selected)
            self.capture_payload(self.selection["previous_archive_sha256"],new=False)
            selected_unit = Path(selected["service_path"])
            self.alias_path = selected_unit.parents[4]/".config/systemd/user"/selected_unit.name
            # Enabled owned link is mandatory even when manager reports the physical fragment.
            self.verify_fragment(str(self.alias_path))
        except BaseException:
            self.close()
            raise
    def capture_payload(self,archive_sha,new):
        record = json.loads(self.unit.files[0][4],object_pairs_hook=resident.unique)
        resident.require(record["artifact"]["archiveSha256"] == archive_sha)
        if not new:
            resident.require(record["artifact"] == self.previous_artifact and record["product"] == self.previous_product
                and record["artifact"]["manifestSha256"] == self.selection["previous_manifest_sha256"]
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]} for row in record["files"]} == self.previous_expected)
        if new:
            resident.require(record["artifact"] == self.new_artifact and record["product"] == self.new_product
                and record["serviceActivated"] is False
                and record["artifact"]["manifestSha256"] == self.selection["manifest_sha256"]
                and record["artifact"]["provenance"] == self.manifest_provenance
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]} for row in record["files"]} == self.expected)
        self.payload = []
        for row in record["files"]:
            fence = PublicFile(row["path"],self.deadline,128*1024*1024,owned=True)
            self.files.append(fence)
            resident.require(stat.S_IMODE(os.fstat(fence.fd).st_mode) == row["mode"]
                and hashlib.sha256(fence.raw).hexdigest() == row["sha256"])
            self.payload.append(fence)
    def verify_fragment(self,fragment):
        self.unit.verify_fragment(fragment)
        if self.unit.alias is not None:
            path,parent,witness,parent_witness = self.unit.alias
            if self.alias is None:
                self.alias = (path,os.dup(parent),witness,parent_witness)
            else:
                resident.require(path == self.alias[0] and witness == self.alias[2])
        self.recheck()
    def recheck(self):
        tick(self.deadline)
        if self.alias is not None:
            path,parent,witness,parent_witness = self.alias
            current = resident.open_directory(path.parent)
            try:
                resident.require(resident.stable(os.fstat(parent)) == parent_witness
                    == resident.stable(os.fstat(current))
                    and resident.file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) == witness
                    and os.readlink(path.name,dir_fd=parent) == self.selected["service_path"])
            finally:
                os.close(current)
        self.runtime.recheck()
        self.unit.recheck()
        for file in self.files:
            file.recheck()
    def completed(self):
        # Old installed file identities intentionally become stale only at this qualified transition.
        self.runtime.recheck()
        self.qualification.recheck()
        self.archive.recheck()
        for fence in self.payload:
            self.files.remove(fence)
            fence.close()
        self.unit.close()
        self.unit = resident.OwnedUnitCustody(self.selected)
        self.verify_fragment(str(self.alias_path))
        self.capture_payload(self.selection["archive_sha256"],new=True)
        self.finished = True
        self.recheck()
        return {"installation_updated":True,"service_active":False,"runtime_metadata_preserved":True,
            "source_connected":False,"provider_request_performed":False,"vault_material_read":False,
            "archive_sha256":self.selection["archive_sha256"]}
    def close(self):
        if self.alias is not None:
            os.close(self.alias[1])
            self.alias = None
        if self.unit is not None:
            self.unit.close()
            self.unit = None
        if self.runtime is not None:
            self.runtime.close()
            self.runtime = None
        for file in reversed(self.files):
            file.close()
        self.files = []
