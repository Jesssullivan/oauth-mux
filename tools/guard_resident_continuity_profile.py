"""Exact resident continuity authority and post-exit receipt boundary."""
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

LABEL = "//delivery:resident_codex_live_continuity"
PROFILE = "resident-continuity"
DESTINATION = "/omux-resident-live-inputs"
VARIABLE = "OMUX_RESIDENT_LIVE_MANIFEST"
DEADLINE_VARIABLE = resident.DEADLINE_VARIABLE
SCOPE = "resident_operator_drain_same_process_completed_turn_substitution"
FRESH_KIND = "omux-fresh-native-runtime-v1"
PACKAGE_KIND = "omux-protocol-history-native-package-selection-v1"
PATCHES = ["5b9eb9d8ffc19ac6e53429186b3dc3e51ab05ab9bbb30564c3b621d7d5383ef6",
    "3851e3d5c1901cafa7cd0bae63a7ac84b1baac7b1f6be3102cc7b185e97ecd53",
    "84ec6ddc333361b4785ac0c9b0a212ce7b25f200fb22c30eb0abdc21883c5ec5",
    "b4dd868ac11d863f65e9fe3031d83b8fb7164a5551abca20dc46424c0465c48c"]
PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT = resident.PROOF_MEMORY,resident.PROOF_TASKS,resident.PROOF_CPU_PERCENT
HANDOFF = "native-projection.json"
OUTPUT = "resident-codex-live-proof.json"
LIMIT = 65536
REPLY_LIMIT = 8*1024*1024
HEX = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
NATIVE_FIXED = {"schema_version":1,"scope":"operator_drain_same_process_completed_turn_substitution",
    "transition_reason":"operator_drain","application":"omux-maintained-codex",
    "native_context_mode":"text_transcript_v1","reasoning_summary":"none",
    "minimum_reasoning_effort_verified":True,"native_detach_proven":False,"integration_restoration_proven":False,
    "accounts":["account_a","account_b"],"submitted_turns":2,"accepted_completed_turns":2,"tool_calls":0,
    "provider_usage_records":2,"same_process":True,"same_native_owner":True,"same_native_thread":True,
    "native_store_identity_preserved":True,"accepted_history_prefix_preserved":True,
    "accepted_work_repeated":False,"empty_native_resume_checkpoint_proven":True,
    "accepted_history_cold_resume_proven":False,"provider_rejection_handoff_proven":False,
    "concurrent_handoff_proven":False,"full_native_account_lifecycle_proven":False,"runtime_kind":FRESH_KIND}
NATIVE_VARIABLE = {"application_version","model","reasoning_effort","upstream_commit",
    "candidate_patch_sha256s","runtime_archive_sha256"}

def require(value):
    if not value:
        raise ValueError("resident-continuity-refused")

def tick(deadline,reserve=0):
    require(type(deadline) is int and time.monotonic_ns()+reserve < deadline)

def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()

def finite(arguments,manager,manifest,reuse,unrelated=()):
    require(arguments == ["run",LABEL] and manager == "system" and manifest is not None
        and not reuse and not any(unrelated))
    return {"PrivateNetwork":"no","ProtectSystem":"strict","PrivateTmp":"yes","PrivatePIDs":"no"}

def package_lineage(value):
    require(type(value) is dict and value.get('kind')==PACKAGE_KIND and value.get('patch_sha256')==PATCHES)

def runtime_lineage(value):
    require(type(value) is dict and type(value.get('chain')) is dict
        and value['chain'].get('patch_sha256')==PATCHES
        and type(value['chain'].get('native_protocol_history')) is dict
        and set(value['chain']['native_protocol_history'])=={'protocol','schema','cli','artifact_envelopes','artifact_files'})

def proof_path(home,epoch):
    require(type(epoch) is str and str(uuid.UUID(epoch)) == epoch)
    root = resident.canonical(str(home))/".local/state/omux-rp"/uuid.UUID(epoch).hex
    require(len(os.fsencode(root/"c")) <= 68)
    return root

def manifest_schema(value,home,epoch):
    require(type(value) is dict and set(value) == {"schema_version","action_epoch","model",
        "selected_accounts","drain_account_handle","allow_account_wide_drain","resident","proof_root"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["action_epoch"] == epoch and value["proof_root"] == str(proof_path(home,epoch))
        and type(value["model"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",value["model"])
        and value["allow_account_wide_drain"] is True)
    rows = value["selected_accounts"]
    require(type(rows) is list and len(rows) == 2)
    for row in rows:
        require(type(row) is dict and set(row) == {"account_handle","source_handle","grant_handle","grant_generation"}
            and all(type(row[k]) is str and HEX.fullmatch(row[k])
                for k in ("account_handle","source_handle","grant_handle"))
            and type(row["grant_generation"]) is int and 0 < row["grant_generation"] < 2**64)
    for key in ("account_handle","source_handle","grant_handle"):
        require(rows[0][key] != rows[1][key])
    require(value["drain_account_handle"] == rows[0]["account_handle"])
    selected = value["resident"]
    paths = resident.fixed_paths(home)
    require(type(selected) is dict and set(selected) == {"ownership","prefix","records","runtime_state",
        "service_path","archive_sha256","executable_sha256","executable_path","pid","start_ticks","installation"}
        and selected["ownership"] == "omux-installation"
        and all(selected[k] == str(paths[k]) for k in paths)
        and all(type(selected[k]) is str and HEX.fullmatch(selected[k])
            for k in ("archive_sha256","executable_sha256"))
        and type(selected["pid"]) is int and selected["pid"] > 1
        and type(selected["start_ticks"]) is int and selected["start_ticks"] > 0)
    executable = resident.canonical(selected["executable_path"])
    require(executable in (paths["prefix"]/"bin/omuxd",paths["prefix"]/"lib/omux/libexec/omuxd.bin"))
    resident.installation_selection(selected["installation"])
    require(selected["installation"]["archive"]["sha256"] == selected["archive_sha256"])
    return value

class PublicFile:
    def __init__(self,path,limit,mode=None,metadata_only=False):
        self.path = resident.canonical(str(path))
        self.parent = resident.open_directory(self.path.parent)
        self.fd = None
        try:
            self.parent_identity = resident.stable(os.fstat(self.parent))
            self.fd = os.open(self.path.name,(os.O_PATH if metadata_only else os.O_RDONLY|os.O_NONBLOCK)
                |os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and 0 < info.st_size <= limit and (mode is None or stat.S_IMODE(info.st_mode) == mode))
            self.identity = resident.file_identity(info)
            self.limit,self.metadata_only = limit,metadata_only
            self.raw = None if metadata_only else os.pread(self.fd,limit+1,0)
            require(metadata_only or len(self.raw) == info.st_size)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        current = resident.open_directory(self.path.parent)
        try:
            require(resident.stable(os.fstat(current)) == self.parent_identity == resident.stable(os.fstat(self.parent))
                and resident.file_identity(os.fstat(self.fd)) == self.identity
                == resident.file_identity(os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)))
        finally:
            os.close(current)
        if not self.metadata_only:
            require(os.pread(self.fd,self.limit+1,0) == self.raw)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None

def create_file(directory,name,value):
    require(name in (HANDOFF,OUTPUT,"runtime-pin.json","context-pin.json"))
    raw = encoded(value)
    require(len(raw) <= LIMIT)
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    try:
        os.fchmod(fd,0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd,raw[offset:])
            require(count > 0)
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    return hashlib.sha256(raw).hexdigest()

class BusMetadata:
    """Finite EXTERNAL-authenticated DBus owner metadata; never activates a name."""
    def __init__(self,path,deadline):
        self.deadline = deadline
        self.channel = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            tick(deadline)
            self.channel.settimeout(min(5,(deadline-time.monotonic_ns())/10**9))
            self.channel.connect(str(path))
            self.peer = struct.unpack("3i",self.channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(self.peer[0] > 1 and self.peer[1] == os.getuid())
            tick(self.deadline)
            self.channel.settimeout(min(5,(self.deadline-time.monotonic_ns())/10**9))
            self.channel.sendall(b"\0AUTH EXTERNAL "+str(os.getuid()).encode().hex().encode()+b"\r\n")
            response = bytearray()
            while not response.endswith(b"\r\n"):
                require(len(response) < 256)
                response.extend(self.exact(1))
            require(re.fullmatch(rb"OK [0-9a-fA-F]{32}\r\n",response))
            tick(self.deadline)
            self.channel.settimeout(min(5,(self.deadline-time.monotonic_ns())/10**9))
            self.channel.sendall(b"BEGIN\r\n")
            self.serial = 0
            self.call("Hello",None,"s")
        except BaseException:
            self.close()
            raise

    def exact(self,count):
        tick(self.deadline)
        result = bytearray()
        while len(result) < count:
            tick(self.deadline)
            self.channel.settimeout(min(5,(self.deadline-time.monotonic_ns())/10**9))
            chunk = self.channel.recv(count-len(result))
            require(chunk)
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    def string(raw):
        return struct.pack("<I",len(raw))+raw+b"\0"

    def call(self,member,argument,signature):
        self.serial += 1
        fields = [(1,"o",b"/org/freedesktop/DBus"),(2,"s",b"org.freedesktop.DBus"),
            (3,"s",member.encode()),(6,"s",b"org.freedesktop.DBus")]
        body = b"" if argument is None else self.string(argument.encode())
        if argument is not None:
            fields.append((8,"g",b"s"))
        header = bytearray()
        for code,kind,value in fields:
            header.extend(b"\0"*((-len(header))%8))
            header.extend(bytes((code,1))+kind.encode()+b"\0")
            header.extend(bytes((len(value),))+value+b"\0" if kind == "g" else self.string(value))
        packet = b"l\1\2\1"+struct.pack("<III",len(body),self.serial,len(header))+header
        packet += b"\0"*((-len(packet))%8)+body
        tick(self.deadline)
        self.channel.settimeout(min(5,(self.deadline-time.monotonic_ns())/10**9))
        self.channel.sendall(packet)
        for _ in range(8):
            fixed = self.exact(16)
            require(fixed[0] == ord("l") and fixed[1] in (2,3,4) and fixed[3] == 1)
            body_size,serial,header_size = struct.unpack("<III",fixed[4:])
            require(body_size <= 4096 and header_size <= 4096 and serial > 0)
            data = self.exact(header_size)
            self.exact((-(16+header_size))%8)
            reply = self.exact(body_size)
            parsed,index = {},0
            while index < len(data):
                index += (-index)%8
                require(index+4 <= len(data))
                code,length = data[index:index+2]
                require(length == 1 and data[index+3] == 0 and code not in parsed)
                kind = chr(data[index+2])
                index += 4
                if kind in ("s","o"):
                    require(index+4 <= len(data))
                    size = struct.unpack("<I",data[index:index+4])[0]
                    index += 4
                    require(index+size < len(data) and data[index+size] == 0)
                    item = data[index:index+size].decode("ascii")
                    index += size+1
                elif kind == "u":
                    require(index+4 <= len(data))
                    item = struct.unpack("<I",data[index:index+4])[0]
                    index += 4
                elif kind == "g":
                    require(index < len(data))
                    size = data[index]
                    index += 1
                    require(index+size < len(data) and data[index+size] == 0)
                    item = data[index:index+size].decode("ascii")
                    index += size+1
                else:
                    require(False)
                require(code in (1,2,3,4,5,6,7,8,9))
                parsed[code] = item
            if fixed[1] == 4:
                continue
            require(fixed[1] == 2 and parsed.get(5) == self.serial and parsed.get(8) == signature
                and parsed.get(7) == "org.freedesktop.DBus")
            if signature == "s":
                require(len(reply) >= 5)
                length = struct.unpack("<I",reply[:4])[0]
                require(len(reply) == length+5 and reply[-1] == 0)
                return reply[4:-1].decode("ascii")
            require(signature in ("u","b") and len(reply) == 4)
            value = struct.unpack("<I",reply)[0]
            require(signature != "b" or value in (0,1))
            return value
        require(False)

    def owners(self,allow_missing_secret_service=False):
        result = {"schema_version":1,"broker":{"pid":self.peer[0],"uid":self.peer[1],
            "start_ticks":resident.start_ticks(self.peer[0])}}
        for field,name in (("manager","org.freedesktop.systemd1"),("secret_service","org.freedesktop.secrets")):
            present = self.call("NameHasOwner",name,"b")
            require(type(present) is int and present in (0,1))
            if field == "secret_service" and present == 0:
                require(allow_missing_secret_service)
                result[field] = None
                continue
            require(present == 1)
            owner = self.call("GetNameOwner",name,"s")
            require(re.fullmatch(r":[0-9]+[.][0-9]+",owner))
            uid = self.call("GetConnectionUnixUser",owner,"u")
            pid = self.call("GetConnectionUnixProcessID",owner,"u")
            require(uid == os.getuid() and pid > 1 and self.call("GetNameOwner",name,"s") == owner)
            result[field] = {"owner":owner,"pid":pid,"uid":uid,"start_ticks":resident.start_ticks(pid)}
        resident.validate_session_observation(result,allow_missing_secret_service)
        return result

    def close(self):
        self.channel.close()


def socket_witness(path,deadline,private=False):
    tick(deadline)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid()
        and (not private or stat.S_IMODE(before.st_mode)==0o600 and before.st_gid==os.getgid()))
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        tick(deadline)
        channel.settimeout(min(2,(deadline-time.monotonic_ns())/10**9))
        channel.connect(str(path))
        pid,uid,gid = struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(uid == os.getuid() and pid > 1 and (not private or gid==os.getgid()))
        witness = (resident.stable(before),pid,resident.start_ticks(pid))
    require(resident.stable(path.stat(follow_symlinks=False)) == witness[0])
    tick(deadline)
    return witness

def session_owners(bus,deadline,allow_missing_secret_service=False):
    witness = socket_witness(bus,deadline)
    with_holder = BusMetadata(bus,deadline)
    try:
        result = with_holder.owners(allow_missing_secret_service)
    finally:
        with_holder.close()
    require(socket_witness(bus,deadline) == witness)
    return result

class ResidentObserver:
    def __init__(self,value,systemctl,deadline):
        self.value,self.deadline = value,deadline
        self.systemctl = resident.canonical(str(systemctl))
        require(str(self.systemctl).startswith("/nix/store/"))
        self.resources = []
        self.pidfd = None
        try:
            self.unit = resident.OwnedUnitCustody(value)
            self.resources.append(self.unit)
            self.installation = resident.InstallationWitness(value,self.unit,deadline)
            self.resources.append(self.installation)
            record = json.loads(self.unit.files[0][4],object_pairs_hook=resident.unique)
            require(record["artifact"]["archiveSha256"] == value["archive_sha256"])
            self.payload = []
            for row in record["files"]:
                item = PublicFile(row["path"],128*1024*1024,row["mode"],metadata_only=True)
                self.resources.append(item)
                self.payload.append((item,row["sha256"]))
            matching = [row for row in record["files"] if row["path"] == value["executable_path"]]
            require(len(matching) == 1 and matching[0]["sha256"] == value["executable_sha256"])
            self.runtime = Path("/run/user")/str(os.getuid())/resident.runtime_child(value["runtime_state"])
            self.runtime_fd = resident.open_directory(self.runtime,True)
            self.runtime_identity = resident.stable(os.fstat(self.runtime_fd))
            self.bus = Path("/run/user")/str(os.getuid())/"bus"
            self.bus_parent = resident.open_directory(self.bus.parent,True)
            self.bus_parent_identity = resident.stable(os.fstat(self.bus_parent))
            self.control_socket,self.adapter_socket = self.runtime/"control.sock",self.runtime/"adapter.sock"
            self.socket_identities = {p:socket_witness(p,deadline,p!=self.bus) for p in (self.bus,self.control_socket,self.adapter_socket)}
            require(all(self.socket_identities[path][1:] == (value["pid"],value["start_ticks"])
                for path in (self.control_socket,self.adapter_socket)))
            self.pidfd = os.pidfd_open(value["pid"],0)
            os.set_inheritable(self.pidfd,False)
            self.process_identity = resident.stable(os.fstat(self.pidfd))
            self.pid_namespace = resident.stable(Path("/proc/"+str(value["pid"])+"/ns/pid").stat())
            require(self.pid_namespace == resident.stable(Path("/proc/self/ns/pid").stat()))
            self.bounds = None
            self.owners = session_owners(self.bus,deadline)
            self.observe(full=True)
        except BaseException:
            self.close()
            raise

    def quick(self):
        tick(self.deadline)
        require(not select.select([self.pidfd],[],[],0)[0]
            and resident.stable(os.fstat(self.pidfd)) == self.process_identity
            and resident.start_ticks(self.value["pid"]) == self.value["start_ticks"]
            and os.readlink("/proc/"+str(self.value["pid"])+"/exe") == self.value["executable_path"])
        require(resident.stable(Path("/proc/"+str(self.value["pid"])+"/ns/pid").stat())
            == self.pid_namespace == resident.stable(Path("/proc/self/ns/pid").stat()))
        for path,witness in self.socket_identities.items():
            require(socket_witness(path,self.deadline,path!=self.bus) == witness)
        require(resident.stable(os.fstat(self.runtime_fd)) == self.runtime_identity
            == resident.stable(self.runtime.stat(follow_symlinks=False))
            and resident.stable(os.fstat(self.bus_parent)) == self.bus_parent_identity
            == resident.stable(self.bus.parent.stat(follow_symlinks=False)))
        self.unit.recheck()
        self.installation.recheck()
        for item,_ in self.payload:
            item.recheck()

    def observe(self,full=False):
        self.quick()
        check = resident.Admission.__new__(resident.Admission)
        check.deadline_ns = self.deadline
        check.selected = {**self.value,"action":"enroll-existing"}
        check.owned_unit = self.unit
        check.service_observation(self.systemctl)
        require(check.observed_process == (self.value["pid"],self.value["start_ticks"]))
        require(self.bounds is None or check.observed_bounds == self.bounds)
        self.bounds = check.observed_bounds
        require(session_owners(self.bus,self.deadline) == self.owners)
        if full:
            for item,digest in self.payload:
                descriptor = os.open(item.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                    dir_fd=item.parent)
                try:
                    require(resident.file_identity(os.fstat(descriptor)) == item.identity)
                    measured,count = hashlib.sha256(),0
                    while True:
                        tick(self.deadline)
                        raw = os.read(descriptor,1024*1024)
                        if not raw:
                            break
                        count += len(raw)
                        require(count <= item.limit)
                        measured.update(raw)
                    require(count == item.identity[6] and measured.hexdigest() == digest
                        and resident.file_identity(os.fstat(descriptor)) == item.identity)
                finally:
                    os.close(descriptor)
                item.recheck()
        self.quick()
        return {"resident_daemon_same_process":True,"resident_installation_preserved":True,
            "resident_service_active_after_controller":True,"resident_lifecycle_changed":False,
            "resident_vault_owner_preserved":True}

    def close(self):
        for item in reversed(getattr(self,"resources",[])):
            item.close()
        self.resources = []
        for name in ("pidfd","runtime_fd","bus_parent"):
            if getattr(self,name,None) is not None:
                os.close(getattr(self,name))
                setattr(self,name,None)

def control_request(observer,method,params,*,deadline=None):
    bound = observer.deadline if deadline is None else min(observer.deadline,deadline)
    tick(bound)
    observer.quick()
    tick(bound)
    packet = encoded({"jsonrpc":"2.0","id":1,"method":method,"params":params})
    require(len(packet) <= LIMIT)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(min(10,(bound-time.monotonic_ns())/10**9))
        channel.connect(str(observer.control_socket))
        pid,uid,gid = struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require((pid,uid,gid) == (observer.value["pid"],os.getuid(),os.getgid()))
        tick(bound)
        channel.settimeout(min(10,(bound-time.monotonic_ns())/10**9))
        channel.sendall(packet)
        reply = bytearray()
        while b"\n" not in reply:
            tick(bound)
            channel.settimeout(min(10,(bound-time.monotonic_ns())/10**9))
            raw = channel.recv(65536)
            require(raw and len(reply)+len(raw) <= REPLY_LIMIT)
            reply.extend(raw)
    require(reply.endswith(b"\n") and reply.count(b"\n") == 1)
    value = json.loads(reply,object_pairs_hook=resident.unique)
    require(type(value) is dict and set(value) == {"jsonrpc","id","result"}
        and value["jsonrpc"] == "2.0" and type(value["id"]) is int and value["id"] == 1
        and type(value["result"]) is dict)
    observer.quick()
    tick(bound)
    return value["result"]

def current_domain(snapshot,selected,drained=None):
    now = int(time.time())
    for wanted in selected:
        def row(collection,handle):
            values = [item for item in snapshot[collection] if item["id"] == handle]
            require(len(values) == 1)
            return values[0]
        account,source,grant = row("accounts",wanted["account_handle"]),row("sources",wanted["source_handle"]),row("grants",wanted["grant_handle"])
        require(account["identity"]["provider"] == "codex" and account["identity"].get("verified") is True
            and account["lifecycle"] == ("draining" if account["id"] == drained else "active")
            and source["id"] in account["source_ids"] and source["provider"] == "codex"
            and source["kind"] == "native_store" and source["status"] == "connected"
            and type(source["authorized_at"]) is int and source["authorized_at"] <= now
            and (source["authorized_until"] is None or type(source["authorized_until"]) is int and source["authorized_until"] > now)
            and grant["account_id"] == account["id"] and grant["source_id"] == source["id"]
            and type(grant["generation"]) is int and grant["generation"] == wanted["grant_generation"]
            and grant["credential_kind"] == "oauth_access" and grant["ownership"] == "external"
            and grant["status"] == "ready" and grant["audience"] == "https://chatgpt.com" and "request" in grant["purposes"]
            and type(grant["custody_expires_at"]) is int and grant["custody_expires_at"] > now
            and (grant["provider_expires_at"] is None or type(grant["provider_expires_at"]) is int and grant["provider_expires_at"] > now))
        usable = [item for item in snapshot["grants"] if item["account_id"] == account["id"]
            and item["credential_kind"] == "oauth_access" and item["status"] == "ready"
            and "request" in item["purposes"] and item["audience"] == "https://chatgpt.com"]
        require(len(usable) == 1 and usable[0]["id"] == grant["id"])
    active = {a["id"] for a in snapshot["accounts"] if a["identity"]["provider"] == "codex"
        and a["lifecycle"] == "active"}
    require(active == {row["account_handle"] for row in selected}-{drained})


CONTEXT_FIELDS = {"producer","action_epoch","producer_source_sha256","observer_source_sha256",
    "runtime_selection_sha256","model","application_version","runtime_archive_sha256","upstream_commit",
    "candidate_patch_sha256s","daemon_archive_sha256","daemon_executable_sha256","daemon_source_commit","daemon_graph_sha256"}

def validate_context(value):
    require(type(value) is dict and set(value) == CONTEXT_FIELDS and value["producer"] == LABEL
        and type(value["action_epoch"]) is str and str(uuid.UUID(value["action_epoch"])) == value["action_epoch"]
        and type(value["model"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",value["model"])
        and type(value["application_version"]) is str and VERSION.fullmatch(value["application_version"])
        and type(value["upstream_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}",value["upstream_commit"])
        and value["candidate_patch_sha256s"] == PATCHES
        and type(value["daemon_source_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}",value["daemon_source_commit"])
        and all(type(value[key]) is str and HEX.fullmatch(value[key]) for key in
            ("producer_source_sha256","observer_source_sha256","runtime_selection_sha256",
             "runtime_archive_sha256","daemon_archive_sha256","daemon_executable_sha256","daemon_graph_sha256")))
    return value

def validate_runtime_pin(value,context):
    require(type(value) is dict and set(value) == {"kind","archive_sha256","archive_bytes",
        "receipt_sha256","receipt_bytes","manifest_sha256","manifest_bytes"} and value["kind"] == FRESH_KIND
        and all(type(value[role+"_sha256"]) is str and HEX.fullmatch(value[role+"_sha256"])
            and type(value[role+"_bytes"]) is int and 0 < value[role+"_bytes"] <= 1024*1024*1024
            for role in ("archive","receipt","manifest"))
        and value["archive_sha256"] == context["runtime_archive_sha256"])
    return value

def validate_guard_join(final,outer,digest):
    require(set(final) == set(NATIVE_FIXED)|NATIVE_VARIABLE|{"resident_daemon_same_process",
        "resident_installation_preserved","resident_service_active_after_controller","resident_lifecycle_changed",
        "resident_vault_owner_preserved","producer","action_epoch","producer_source_sha256","observer_source_sha256",
        "runtime_selection_sha256","daemon_archive_sha256","daemon_executable_sha256","daemon_source_commit","daemon_graph_sha256","selected_current_grants_verified",
        "account_drain_disposition","controller_exited","proof_descendants_empty","guard_graph_sha256",
        "requires_successful_guard_receipt"})
    require(type(final) is dict and final["scope"] == SCOPE and final["producer"] == LABEL
        and final["requires_successful_guard_receipt"] is True and HEX.fullmatch(digest))
    require(type(outer) is dict and outer["id"] == final["action_epoch"]
        and outer["profile"] == PROFILE and outer["verb"] == "run" and outer["targets"] == [LABEL]
        and type(outer["exit"]) is int and outer["exit"] == 0
        and type(outer["workload_exit"]) is int and outer["workload_exit"] == 0
        and outer["descendants_empty"] is True and outer["cleanup"]["state"] == "empty"
        and outer["controller_failure"] is None and outer["graph_sha256"] == final["guard_graph_sha256"]
        and outer["resident_continuity"]["verified_after_cleanup"] is True
        and outer["resident_continuity"]["output"]["sha256"] == digest
        and outer["resident_continuity"]["output"]["basename"] == OUTPUT
        and outer["resident_continuity"]["output"]["verified_after_controller_exit"] is True)
    return True

def validate_native(value,context):
    validate_context(context)
    require(type(value) is dict and set(value) == set(NATIVE_FIXED)|NATIVE_VARIABLE)
    require(all(type(value[k]) is type(v) and value[k] == v for k,v in NATIVE_FIXED.items()))
    require(value["model"] == context["model"] and value["application_version"] == context["application_version"]
        and value["runtime_archive_sha256"] == context["runtime_archive_sha256"]
        and value["upstream_commit"] == context["upstream_commit"]
        and value["candidate_patch_sha256s"] == context["candidate_patch_sha256s"]
        and type(value["reasoning_effort"]) is str and value["reasoning_effort"]
            in ("none","minimal","low","medium","high","xhigh","max","ultra","persistent"))
    return value

def joined_native_receipt(final,outer,digest,context):
    """Current producer semantics plus the existing immutable outer join.

    Historical validate_guard_join remains unchanged. This stricter reader is
    required only for the new admitted-attempt measurement; it cannot promote
    a self-consistent false native/resident predicate into success.
    """
    validate_context(context)
    require(type(final) is dict
        and encoded({key:final[key] for key in CONTEXT_FIELDS}) == encoded(context))
    require(type(digest) is str and HEX.fullmatch(digest)
        and hashlib.sha256(encoded(final)).hexdigest() == digest)
    native = {key:final[key] for key in set(NATIVE_FIXED)|NATIVE_VARIABLE}
    validate_native(native,context)
    observation = {key:final[key] for key in (
        "resident_daemon_same_process","resident_installation_preserved",
        "resident_service_active_after_controller","resident_lifecycle_changed",
        "resident_vault_owner_preserved")}
    expected = final_receipt(native,observation,context)
    expected.update(guard_graph_sha256=final["guard_graph_sha256"],requires_successful_guard_receipt=True)
    require(encoded(final) == encoded(expected))
    validate_guard_join(final,outer,digest)
    return True

def lifecycle_projection(context,outer,terminal_ns,*,joined_native):
    """One selected admitted guardian invocation, never all supported demands.

    joined_native is supplied only after joined_native_receipt by Admission or
    the strict receipt consumer. No caller RPC or CLI flag supplies this fact.
    Monotonic endpoints belong to the same original guardian process; stored
    duration survives restart without subtracting a later process clock.
    """
    validate_context(context)
    require(type(outer) is dict and outer["id"] == context["action_epoch"]
        and outer["profile"] == PROFILE and outer["verb"] == "run" and outer["targets"] == [LABEL]
        and type(outer["exit"]) is int and -128 <= outer["exit"] <= 255
        and type(outer["workload_exit"]) is int and -128 <= outer["workload_exit"] <= 255
        and type(joined_native) is bool and type(outer["descendants_empty"]) is bool
        and type(outer["cleanup"]) is dict and type(outer["cleanup"].get("state")) is str
        and type(outer["graph_sha256"]) is str and HEX.fullmatch(outer["graph_sha256"]))
    selected = outer["resident_continuity"]
    require(type(selected) is dict and type(selected["verified_after_cleanup"]) is bool
        and type(selected["original_entry_monotonic_ns"]) is int
        and type(selected["original_deadline_monotonic_ns"]) is int)
    start,deadline = selected["original_entry_monotonic_ns"],selected["original_deadline_monotonic_ns"]
    require(0 <= start < deadline and deadline == start+1200*10**9
        and type(terminal_ns) is int and start <= terminal_ns < 2**63)
    empty = outer["descendants_empty"] is True and outer["cleanup"]["state"] == "empty"
    if joined_native:
        require(outer["exit"] == 0 and outer["workload_exit"] == 0
            and empty and outer["controller_failure"] is None
            and selected["verified_after_cleanup"] is True)
        outcome,cause = "success","none"
    elif not empty or outer["controller_failure"] is not None:
        outcome,cause = "unresolved","owned_cleanup_or_controller_unresolved"
    elif outer["workload_exit"] == 124:
        outcome,cause = "failed_admitted","workload_timeout"
    elif outer["workload_exit"] != 0:
        outcome,cause = "failed_admitted","workload_failed"
    else:
        # A zero workload exit without the complete post-exit/outer join is
        # an admitted validation failure, never a safe pre-effect refusal.
        outcome,cause = "failed_admitted","post_exit_validation_failed"
    pins = {key:context[key] for key in (
        "producer_source_sha256","observer_source_sha256","runtime_selection_sha256",
        "application_version","runtime_archive_sha256","upstream_commit","candidate_patch_sha256s",
        "daemon_archive_sha256","daemon_executable_sha256","daemon_source_commit","daemon_graph_sha256")}
    return {"schema_version":1,"state":"recorded","requirement":"REL-016",
        "scope":"one_admitted_resident_operator_drain_completed_turn_attempt",
        "producer":LABEL,"action_epoch":context["action_epoch"],
        "outcome":outcome,"cause":cause,"native_proof_admitted":joined_native,
        "safe_refusal_proven":False,"side_effect_outcome_inferred":False,
        "timing":{"scope":"original_guard_entry_to_terminal_before_receipt_write",
            "clock":"linux_monotonic_same_guardian_process",
            "original_entry_monotonic_ns":start,"original_deadline_monotonic_ns":deadline,
            "terminal_monotonic_ns":terminal_ns,"observed_guardian_elapsed_ns":terminal_ns-start,
            "deadline_met":terminal_ns <= deadline,"user_request_elapsed_ns":None,
            "local_work_ns":None,"user_provider_wait_ns":None,
            "unknown_duration_reason":"user_ingress_and_wait_partition_unobserved"},
        "provenance":{"pins":pins,"guard_graph_sha256":outer["graph_sha256"],
            "status":"joined_native_and_resident" if joined_native else "selected_before_launch_only",
            "source_verified_after_cleanup":selected["verified_after_cleanup"]},
        "coverage":{"denominator":"one_selected_admitted_guard_invocation",
            "admitted_attempts":1,"pre_admission_refusals_measured":False,
            "complete_supported_demand_coverage":False,"complete_lifecycle_coverage":False,
            "scheduled_baseline_measured":False},"achieved_slo":False}

def validate_lifecycle_guard_join(final,outer,digest):
    """New measurement consumer; legacy receipts keep their original reader."""
    context = {key:final[key] for key in CONTEXT_FIELDS}
    joined_native_receipt(final,outer,digest,context)
    actual = outer["resident_continuity"]["lifecycle_attempt"]
    require(type(actual) is dict and type(actual.get("timing")) is dict)
    expected = lifecycle_projection(context,outer,actual["timing"]["terminal_monotonic_ns"],joined_native=True)
    # Canonical bytes reject bool/int coercion and extra/missing nested fields.
    require(encoded(actual) == encoded(expected))
    return True

def handoff(value,context):
    require(type(value) is dict and set(value) == {"schema_version","producer","action_epoch",
        "producer_source_sha256","observer_source_sha256","runtime_selection_sha256","model","native_result"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1)
    for key in ("producer","action_epoch","producer_source_sha256","observer_source_sha256","runtime_selection_sha256","model"):
        require(value[key] == context[key])
    validate_native(value["native_result"],context)
    return value["native_result"]

def final_receipt(native,observation,context):
    require(type(observation) is dict and set(observation) == {"resident_daemon_same_process",
        "resident_installation_preserved","resident_service_active_after_controller","resident_lifecycle_changed",
        "resident_vault_owner_preserved"})
    require(all(type(observation[k]) is bool and observation[k] is (False if k == "resident_lifecycle_changed" else True)
        for k in observation))
    validate_native(native,context)
    result = {**native,**observation,"scope":SCOPE,"producer":context["producer"],
        "action_epoch":context["action_epoch"],"producer_source_sha256":context["producer_source_sha256"],
        "observer_source_sha256":context["observer_source_sha256"],
        "runtime_selection_sha256":context["runtime_selection_sha256"],
        "daemon_archive_sha256":context["daemon_archive_sha256"],
        "daemon_executable_sha256":context["daemon_executable_sha256"],
        "daemon_source_commit":context["daemon_source_commit"],"daemon_graph_sha256":context["daemon_graph_sha256"],
        "selected_current_grants_verified":2,"account_drain_disposition":"retained","controller_exited":True,
        "proof_descendants_empty":True}
    require(set(result) == set(NATIVE_FIXED)|NATIVE_VARIABLE|set(observation)|{
        "producer","action_epoch","producer_source_sha256","observer_source_sha256","runtime_selection_sha256",
        "daemon_archive_sha256","daemon_executable_sha256","daemon_source_commit","daemon_graph_sha256","selected_current_grants_verified",
        "account_drain_disposition","controller_exited","proof_descendants_empty"})
    return result

class ControllerContext:
    @classmethod
    def open(cls):
        return cls()

    def __init__(self):
        self.resources = []
        try:
            self.deadline = int(os.environ[DEADLINE_VARIABLE])
            tick(self.deadline,30*10**9)
            require(self.deadline <= time.monotonic_ns()+1200*10**9)
            home = Path(pwd.getpwuid(os.getuid()).pw_dir)
            self.action_epoch = os.environ["OMUX_RESIDENT_LIVE_EPOCH"]
            root = Path(DESTINATION)
            self.namespace_fd = resident.open_directory(root,True)
            self.namespace_identity = resident.stable(os.fstat(self.namespace_fd))
            require(os.environ["OMUX_RESIDENT_LIVE_NAMESPACE_ID"] ==
                str(self.namespace_identity[0])+":"+str(self.namespace_identity[1])
                and set(os.listdir(self.namespace_fd)) == {"input.json","runtime-pin.json","context-pin.json","run"})
            self.input = PublicFile(root/"input.json",LIMIT,0o600)
            self.resources.append(self.input)
            self.value = manifest_schema(json.loads(self.input.raw,object_pairs_hook=resident.unique),home,self.action_epoch)
            self.context_file = PublicFile(root/"context-pin.json",LIMIT,0o600)
            self.resources.append(self.context_file)
            self.context = validate_context(json.loads(self.context_file.raw,object_pairs_hook=resident.unique))
            require(self.context["action_epoch"] == self.action_epoch and self.context["model"] == self.value["model"]
                and self.context["producer"] == LABEL
                and self.context["observer_source_sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            self.pin = PublicFile(root/"runtime-pin.json",LIMIT,0o600)
            self.resources.append(self.pin)
            self.runtime_pin = validate_runtime_pin(json.loads(self.pin.raw,object_pairs_hook=resident.unique),self.context)
            self.model,self.selected_accounts = self.value["model"],self.value["selected_accounts"]
            self.drain_account_handle = self.value["drain_account_handle"]
            self.allow_account_wide_drain = True
            self.proof_root = Path(self.value["proof_root"])
            self.output = resident.canonical(os.environ["OMUX_RESIDENT_LIVE_OUTPUT"])
            require(self.output.name == "resident-handoff" and self.output.parent.name == self.action_epoch)
            self.output_fd = resident.open_directory(self.output,True)
            self.output_identity = resident.stable(os.fstat(self.output_fd))
            require(os.environ["OMUX_RESIDENT_LIVE_OUTPUT_ID"] ==
                str(self.output_identity[0])+":"+str(self.output_identity[1]) and not os.listdir(self.output_fd))
            self.observer = ResidentObserver(self.value["resident"],os.environ["OMUX_RESIDENT_LIVE_SYSTEMCTL"],self.deadline-30*10**9)
            self.resources.append(self.observer)
            self.capability = None
            self.mutations = set()
            self.control("system.health")
        except BaseException:
            self.close()
            raise

    def remaining(self):
        tick(self.deadline,30*10**9)
        return (self.deadline-time.monotonic_ns())/10**9-30

    def recheck(self):
        tick(self.deadline,30*10**9)
        require(resident.stable(os.fstat(self.namespace_fd)) == self.namespace_identity
            == resident.stable(Path(DESTINATION).stat(follow_symlinks=False))
            and resident.stable(os.fstat(self.output_fd)) == self.output_identity
            == resident.stable(self.output.stat(follow_symlinks=False)))
        for item in self.resources:
            if item is not self.observer:
                item.recheck()
        self.observer.observe()
        if self.capability is not None:
            self.capability.recheck()
        tick(self.deadline,30*10**9)

    def capture_native_capability(self,config):
        require(Path(config) == self.proof_root/"c/config.toml" and self.capability is None)
        self.capability = PublicFile(Path(self.value["resident"]["runtime_state"])/"integrations/codex.capability",
            64,0o600,metadata_only=True)
        self.resources.append(self.capability)
        require(self.capability.identity[6] == 64)
        self.recheck()

    def control(self,method,params=None):
        params = {} if params is None else params
        require(type(params) is dict and method in {"system.health","state.snapshot","integrations.status",
            "integrations.nativeRequestAudit","integrations.install","integrations.detach","account.drain"})
        if method in ("system.health","state.snapshot"):
            require(not params)
        if method in ("integrations.install","integrations.detach","account.drain"):
            require(method not in self.mutations and type(params.get("operation_id")) is str
                and HEX.fullmatch(params["operation_id"]) and type(params.get("expected_revision")) is int
                and params["expected_revision"] >= 0)
            if method == "account.drain":
                require(set(params) == {"operation_id","expected_revision","account_id"}
                    and params["account_id"] == self.drain_account_handle)
            elif method == "integrations.install":
                require(set(params) == {"operation_id","expected_revision","adapter","codex_home","config_path","native_socket"}
                    and params["adapter"] == "codex" and Path(params["codex_home"]) == self.proof_root/"c"
                    and Path(params["config_path"]) == self.proof_root/"c/config.toml"
                    and self.proof_root/"c" in resident.canonical(params["native_socket"]).parents)
            else:
                require(set(params) == {"adapter","owner_endpoint","thread_id","native_ref",
                    "operation_id","expected_revision"} and params["adapter"] == "codex"
                    and self.proof_root/"c" in resident.canonical(params["owner_endpoint"]).parents
                    and type(params["thread_id"]) is str and str(uuid.UUID(params["thread_id"])) == params["thread_id"]
                    and type(params["native_ref"]) is dict)
            self.mutations.add(method)  # A lost ACK never permits another operation.
        self.recheck()
        result = control_request(self.observer,method,params,deadline=self.deadline-30*10**9)
        if method == "system.health":
            require(result["custody_available"] is True and result["protocol_version"] == 2)
        elif method == "state.snapshot":
            current_domain(result,self.selected_accounts,self.drain_account_handle if "account.drain" in self.mutations else None)
        self.recheck()
        return result

    def publish_native_projection(self,native_result):
        self.recheck()
        validate_native(native_result,self.context)
        value = {k:self.context[k] for k in ("producer","action_epoch","producer_source_sha256",
            "observer_source_sha256","runtime_selection_sha256","model")}
        value.update(schema_version=1,native_result=native_result)
        create_file(self.output_fd,HANDOFF,value)
        self.recheck()

    def close(self):
        for item in reversed(getattr(self,"resources",[])):
            item.close()
        self.resources = []
        for name in ("namespace_fd","output_fd"):
            if getattr(self,name,None) is not None:
                os.close(getattr(self,name))
                setattr(self,name,None)

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.close()

class Admission:
    def __init__(self,manifest,home,deadline,epoch,fresh,systemctl,producer_sha,observer_sha,native_version,source_root):
        self.deadline_ns,self.action_epoch = deadline,epoch
        deadline -= 30*10**9
        self.resources = []
        self.output_fd = None
        self.placeholders = []
        self.namespace_dirs = []
        try:
            tick(deadline)
            self.manifest = resident.canonical(str(manifest))
            require(self.manifest.name == "input.json")
            self.root = self.manifest.parent
            self.directory = resident.open_directory(self.root,True)
            self.root_identity = resident.stable(os.fstat(self.directory))
            require(os.listdir(self.directory) == ["input.json"])
            self.input = PublicFile(self.manifest,LIMIT,0o600)
            self.resources.append(self.input)
            self.selected = manifest_schema(json.loads(self.input.raw,object_pairs_hook=resident.unique),home,epoch)
            self.fresh = fresh
            from guard_fresh_native_runtime_input import Admission as FreshAdmission
            require(type(fresh) is FreshAdmission)
            self.resources.append(fresh)
            fresh.recheck()
            self.package = resident.PinnedMetadata(fresh.selected["package_selection"],deadline)
            self.resources.append(self.package)
            package = json.loads(self.package.raw,object_pairs_hook=resident.unique)
            package_lineage(package)
            require(HEX.fullmatch(producer_sha) and HEX.fullmatch(observer_sha) and VERSION.fullmatch(native_version))
            require(hashlib.sha256((Path(source_root)/"delivery/resident_codex_live_controller.py").read_bytes()).hexdigest() == producer_sha
                and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == observer_sha)
            self.observer = ResidentObserver(self.selected["resident"],systemctl,deadline)
            self.resources.append(self.observer)
            self.proof_root = Path(self.selected["proof_root"])
            self.proof_fd = resident.open_directory(self.proof_root,True)
            self.proof_identity = resident.stable(os.fstat(self.proof_fd))
            require(not os.listdir(self.proof_fd))
            self.integration_root = Path(self.selected["resident"]["runtime_state"])/"integrations"
            self.integration_fd = resident.open_directory(self.integration_root,True)
            self.integration_identity = resident.stable(os.fstat(self.integration_fd))
            run_source = self.root/"run"
            os.mkdir(run_source,0o700)
            os.mkdir(run_source/"user",0o700)
            runtime_source = run_source/"user"/str(os.getuid())
            os.mkdir(runtime_source,0o700)
            os.mkdir(runtime_source/"systemd",0o700)
            os.mkdir(runtime_source/self.observer.runtime.name,0o700)
            for path in (run_source,run_source/"user",runtime_source,runtime_source/"systemd",runtime_source/self.observer.runtime.name):
                descriptor = resident.open_directory(path,True)
                self.namespace_dirs.append((path,descriptor,resident.stable(os.fstat(descriptor))))
            for path in (runtime_source/"bus",runtime_source/"systemd/private"):
                self.placeholders.append(resident.held_mountpoint(path))
            self.runtime_pin = {"kind":FRESH_KIND}
            for role in ("archive","receipt","manifest"):
                self.runtime_pin[role+"_sha256"] = fresh.selected[role]["sha256"]
                self.runtime_pin[role+"_bytes"] = fresh.selected[role]["bytes"]
            self.runtime_receipt = resident.PinnedMetadata(fresh.selected["receipt"],deadline)
            self.resources.append(self.runtime_receipt)
            fresh_receipt = json.loads(self.runtime_receipt.raw,object_pairs_hook=resident.unique)
            runtime_lineage(fresh_receipt)
            self.context = {"producer":LABEL,"action_epoch":epoch,"producer_source_sha256":producer_sha,
                "observer_source_sha256":observer_sha,"runtime_selection_sha256":fresh.facts["selection_sha256"],
                "model":self.selected["model"],"application_version":native_version,
                "runtime_archive_sha256":fresh.selected["archive"]["sha256"],
                "upstream_commit":fresh_receipt["chain"]["upstream_commit"],
                "candidate_patch_sha256s":fresh_receipt["chain"]["patch_sha256"],
                "daemon_archive_sha256":self.selected["resident"]["archive_sha256"],
                "daemon_executable_sha256":self.selected["resident"]["executable_sha256"],
                "daemon_source_commit":self.selected["resident"]["installation"]["source_commit"],
                "daemon_graph_sha256":self.selected["resident"]["installation"]["graph_sha256"]}
            validate_context(self.context)
            validate_runtime_pin(self.runtime_pin,self.context)
            create_file(self.directory,"runtime-pin.json",self.runtime_pin)
            create_file(self.directory,"context-pin.json",self.context)
            self.generated = []
            for name in ("runtime-pin.json","context-pin.json"):
                item = PublicFile(self.root/name,LIMIT,0o600)
                self.resources.append(item)
                self.generated.append(item)
            health = control_request(self.observer,"system.health",{})
            require(health["custody_available"] is True and health["protocol_version"] == 2)
            current_domain(control_request(self.observer,"state.snapshot",{}),self.selected["selected_accounts"])
            self.facts = {"scope":"resident-continuity","credential_source_contents_read":False,
                "capability_contents_read":False,"accounts":2,"resident_memory":resident.RESIDENT_MEMORY,
                "resident_tasks":resident.RESIDENT_TASKS,"resident_cpu_percent":resident.RESIDENT_CPU_PERCENT,
                "proof_memory":PROOF_MEMORY,"proof_tasks":PROOF_TASKS,"proof_cpu_percent":PROOF_CPU_PERCENT}
        except BaseException:
            self.close()
            raise

    def bind_run(self,run):
        require(self.output_fd is None and Path(run).name == self.action_epoch)
        self.run = resident.canonical(str(run))
        self.run_fd = resident.open_directory(self.run,True)
        self.run_identity = resident.stable(os.fstat(self.run_fd))
        os.mkdir("resident-handoff",0o700,dir_fd=self.run_fd)
        self.output = self.run/"resident-handoff"
        self.output_fd = resident.open_directory(self.output,True)
        self.output_identity = resident.stable(os.fstat(self.output_fd))

    def recheck(self):
        reserve = 0 if getattr(self,"collecting",False) else 30*10**9
        tick(self.deadline_ns,reserve)
        require(resident.stable(os.fstat(self.directory)) == self.root_identity
            == resident.stable(self.root.stat(follow_symlinks=False))
            and set(os.listdir(self.directory)) == {"input.json","runtime-pin.json","context-pin.json","run"}
            and resident.stable(os.fstat(self.proof_fd)) == self.proof_identity
            == resident.stable(self.proof_root.stat(follow_symlinks=False))
            and resident.stable(os.fstat(self.integration_fd)) == self.integration_identity
            == resident.stable(self.integration_root.stat(follow_symlinks=False)))
        for item in self.resources:
            if item is not self.observer:
                item.recheck()
        for path,descriptor,witness in self.namespace_dirs:
            require(resident.stable(os.fstat(descriptor)) == witness == resident.stable(path.stat(follow_symlinks=False)))
        require(os.listdir(self.root/"run") == ["user"] and os.listdir(self.root/"run/user") == [str(os.getuid())])
        runtime_source = self.root/"run/user"/str(os.getuid())
        require(set(os.listdir(runtime_source)) == {"bus","systemd",self.observer.runtime.name}
            and os.listdir(runtime_source/"systemd") == ["private"]
            and not os.listdir(runtime_source/self.observer.runtime.name))
        for path,placeholder,witness in self.placeholders:
            require(resident.regular_mountpoint_witness(path,placeholder.fileno()) == witness)
        self.fresh.recheck()
        prior = self.observer.deadline
        try:
            self.observer.deadline = self.deadline_ns-reserve
            self.observer.observe()
        finally:
            self.observer.deadline = prior
        if self.output_fd is not None:
            require(resident.stable(os.fstat(self.run_fd)) == self.run_identity
                == resident.stable(self.run.stat(follow_symlinks=False))
                and resident.stable(os.fstat(self.output_fd)) == self.output_identity
                == resident.stable(self.output.stat(follow_symlinks=False)))
        return self.facts

    def bindings(self):
        return [str(self.root)+":"+DESTINATION,
            str(self.root/"run")+":/run",
            str(self.observer.runtime)+":"+str(self.observer.runtime),
            str(self.observer.bus)+":"+str(self.observer.bus)+":norbind",
            str(self.observer.bus.parent/"systemd/private")+":"+str(self.observer.bus.parent/"systemd/private")+":norbind",
            str(self.integration_root)+":"+str(self.integration_root),
            str(self.fresh.root)+":"+str(self.fresh.root),
            *[str(p)+":"+str(p)+":norbind" for p in (self.fresh.archive,self.fresh.manifest,self.fresh.receipt)]]

    def writable_binding(self):
        return str(self.proof_root)+":"+str(self.proof_root)

    def verify_bindings(self,actual,run=None):
        leaves = [v.removesuffix(":norbind") for v in self.bindings() if v.endswith(":norbind")]
        expected = resident.normalize_binds(" ".join(self.bindings()),leaves)
        ro = resident.normalize_binds(actual.get("BindReadOnlyPaths",""),leaves,readback=True)
        rw = resident.normalize_binds(actual.get("BindPaths",""),readback=True)
        wanted_rw = [self.writable_binding(),str(run)+":"+str(run)]
        require(len(ro) == len(expected) and set(ro) == set(expected)
            and len(rw) == len(wanted_rw) and set(rw) == set(wanted_rw))

    def environment(self):
        require(self.output_fd is not None)
        return {VARIABLE:DESTINATION+"/input.json",DEADLINE_VARIABLE:str(self.deadline_ns),
            "OMUX_RESIDENT_LIVE_EPOCH":self.action_epoch,
            "OMUX_RESIDENT_LIVE_NAMESPACE_ID":str(self.root_identity[0])+":"+str(self.root_identity[1]),
            "OMUX_RESIDENT_LIVE_OUTPUT":str(self.output),
            "OMUX_RESIDENT_LIVE_OUTPUT_ID":str(self.output_identity[0])+":"+str(self.output_identity[1]),
            "OMUX_RESIDENT_LIVE_SYSTEMCTL":str(self.observer.systemctl),
            "XDG_RUNTIME_DIR":str(self.observer.runtime.parent),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path="+str(self.observer.bus)}

    def runtime_seconds(self):
        return resident.Admission.runtime_seconds(self)

    def completed(self,workload_status,cleaned,epoch,producer_sha,graph_sha):
        require(type(workload_status) is int and workload_status == 0 and cleaned is True
            and epoch == self.action_epoch and producer_sha == self.context["producer_source_sha256"]
            and HEX.fullmatch(graph_sha))
        self.collecting = True
        resident.collection_deadline(self.observer,self.resources,self.deadline_ns)
        self.fresh.deadline=self.deadline_ns/10**9
        self.recheck()
        require(os.listdir(self.output_fd) == [HANDOFF])
        projection = PublicFile(self.output/HANDOFF,LIMIT,0o600)
        try:
            native = handoff(json.loads(projection.raw,object_pairs_hook=resident.unique),self.context)
            observation = self.observer.observe(full=True)  # Controller and all proof descendants already exited.
            health = control_request(self.observer,"system.health",{})
            require(health["custody_available"] is True)
            current_domain(control_request(self.observer,"state.snapshot",{}),self.selected["selected_accounts"],
                self.selected["drain_account_handle"])
            self.recheck()
            result = final_receipt(native,observation,self.context)
            result["guard_graph_sha256"] = graph_sha
            result["requires_successful_guard_receipt"] = True
            digest = create_file(self.run_fd,OUTPUT,result)
            projection.recheck()
            # Publish no measurement success before this actual closed output,
            # its input readback and the separate final outer verdict.
            self.completed_receipt = (encoded(result),digest)
            return {"scope":SCOPE,"basename":OUTPUT,"sha256":digest,"guard_graph_sha256":graph_sha,
                "verified_after_controller_exit":True}
        finally:
            projection.close()

    def lifecycle_attempt(self,outer,terminal_ns):
        require(outer["id"] == self.action_epoch
            and outer["resident_continuity"]["original_deadline_monotonic_ns"] == self.deadline_ns)
        joined = False
        if outer["exit"] == 0:
            raw,digest = self.completed_receipt
            final = json.loads(raw,object_pairs_hook=resident.unique)
            joined = joined_native_receipt(final,outer,digest,self.context)
        return lifecycle_projection(self.context,outer,terminal_ns,joined_native=joined)

    def close(self):
        for _,placeholder,_ in reversed(getattr(self,"placeholders",[])):
            placeholder.close()
        self.placeholders = []
        for _,descriptor,_ in reversed(getattr(self,"namespace_dirs",[])):
            os.close(descriptor)
        self.namespace_dirs = []
        for item in reversed(getattr(self,"resources",[])):
            item.close()
        self.resources = []
        for name in ("directory","proof_fd","integration_fd","output_fd","run_fd"):
            if getattr(self,name,None) is not None:
                os.close(getattr(self,name))
                setattr(self,name,None)

projection = resident.projection
rejection = resident.rejection
