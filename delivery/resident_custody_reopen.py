"""Finite, explicit custody recovery on an already qualified owned daemon."""
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import time
import guard_resident_enrollment_profile as guard
import guard_resident_owned_update as owned
import resident_enrollment as resident

SAFE_ERRORS=frozenset(("Locked","Missing","Denied","Cancelled","Unavailable","InvalidKey","Conflict","InvalidRoot","BackendFailure","RecoveryDatabaseMissing","RecoveryDatabaseChanged","Timeout","RepairRequired"))
PROPERTIES=owned.IDLE_PROPERTIES|{"InvocationID","NRestarts"}

def metadata(health,handshake):
    guard.require(type(health) is dict and type(handshake) is dict
        and health.get("protocol_version") == 2 and type(health.get("protocol_version")) is int
        and handshake.get("protocol_version") == 2 and type(handshake.get("protocol_version")) is int
        and handshake.get("service") == "omuxd" and handshake.get("channel") == "control")
    caps=handshake.get("capabilities")
    guard.require(type(caps) is dict and caps.get("custody_reopen") is True
        and caps.get("credential_free_control") is True
        and caps.get("live_handoff_proven") is False
        and health.get("live_handoff_proven") is False)
    guard.require("metadata_loaded" in health and "account_count" in health)
    loaded=health.get("metadata_loaded")
    guard.require(type(loaded) is bool and health.get("custody_available") is loaded
        and handshake.get("custody_available") is loaded)
    count=health.get("account_count")
    if loaded:
        guard.require(health.get("status") == "ready" and type(count) is int and count >= 0)
    else:
        guard.require(count is None and health.get("provider_access") is False)
        status,error,action=health.get("status"),health.get("custody_error"),health.get("recovery_action")
        if status == "vault_locked":
            # Older Locked services lack the additive typed reason field.
            guard.require(error in (None,"Locked") and action == "unlock_platform_vault_then_reopen_custody")
        else:
            guard.require(status == "vault_unavailable" and error in
                ("Missing","Denied","Cancelled","Unavailable","InvalidKey","Conflict","BackendFailure","InvalidRoot"))
            expected="restore_original_vault_key_then_reopen_custody" if error in ("Missing","InvalidKey") \
                else "restore_platform_vault_access_then_reopen_custody"
            guard.require(action == expected)
    return loaded,count

def classify(before,after,envelope):
    guard.require(type(envelope) is dict and envelope.get("jsonrpc") == "2.0"
        and type(envelope.get("id")) is int)
    if set(envelope) == {"jsonrpc","id","result"}:
        result=envelope["result"]
        guard.require(type(result) is dict and set(result) == {"reopened","custody_available",
            "metadata_loaded","account_count","provider_request_initiated","live_handoff_proven"}
            and result["reopened"] is (not before[0])
            and result["custody_available"] is True and result["metadata_loaded"] is True
            and type(result["account_count"]) is int and result["account_count"] >= 0
            and result["provider_request_initiated"] is False and result["live_handoff_proven"] is False
            and after == (True,result["account_count"]))
        return "ready",None
    guard.require(set(envelope) == {"jsonrpc","id","error"})
    error=envelope["error"]
    guard.require(type(error) is dict and set(error) == {"code","message"}
        and type(error["code"]) is int and error["code"] == -32000
        and error["message"] in SAFE_ERRORS and before == after == (False,None))
    return "safe_refusal",error["message"]

class Channel:
    METHODS = ("system.health","system.handshake","custody.reopen")
    def __init__(self,path,pid,deadline):
        self.path,self.pid,self.deadline=path,pid,deadline
        self.serial=0
        self.connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            self.connection.settimeout(self.timeout())
            self.connection.connect(str(path))
            self.peer=self.identity()
        except BaseException:
            self.connection.close()
            raise
    def timeout(self,call_deadline=None):
        left=(min(self.deadline,call_deadline) if call_deadline is not None else self.deadline)-time.monotonic_ns()
        left/=10**9
        guard.require(left > 0)
        return min(15,left)
    def identity(self):
        pid,uid,gid=struct.unpack("3i",self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        guard.require(pid == self.pid and uid == os.getuid() and gid == os.getgid())
        return guard.stable(self.path.stat(follow_symlinks=False)),pid,resident.process_identity(pid)
    def parameters(self,method,params):
        guard.require(params is None or type(params) is dict and not params)
        return {}
    def rpc(self,method,params=None):
        guard.require(method in self.METHODS)
        parameters=self.parameters(method,params)
        call_deadline=min(self.deadline,time.monotonic_ns()+15*10**9)
        guard.require(self.identity() == self.peer)
        self.serial+=1
        self.connection.settimeout(self.timeout(call_deadline))
        self.connection.sendall(json.dumps({"jsonrpc":"2.0","id":self.serial,"method":method,"params":parameters},separators=(",",":")).encode()+b"\n")
        raw=bytearray()
        while b"\n" not in raw:
            self.connection.settimeout(self.timeout(call_deadline))
            part=self.connection.recv(min(4096,1048577-len(raw)))
            guard.require(part and len(raw)+len(part) <= 1048576)
            raw.extend(part)
        guard.require(raw.count(b"\n") == 1 and raw.endswith(b"\n"))
        value=json.loads(raw,object_pairs_hook=guard.unique)
        guard.require(type(value) is dict and value.get("jsonrpc") == "2.0"
            and type(value.get("id")) is int and value["id"] == self.serial)
        guard.require(self.identity() == self.peer)
        self.timeout(call_deadline)
        return value
    def read(self,method):
        value=self.rpc(method)
        guard.require(set(value) == {"jsonrpc","id","result"})
        return value["result"]
    def close(self):
        self.connection.close()

def execute(systemctl,manifest,environment,bounded,remaining,deadline_ns):
    guard.manifest_schema(manifest,environment["HOME"])
    guard.require(manifest["action"] == "reopen-existing")
    deadline=deadline_ns-30*10**9
    witness=owned.OwnedCustodyReopen(manifest,environment["HOME"],deadline)
    channel=None
    try:
        unit=Path(manifest["service_path"]).name
        path=Path(environment["XDG_RUNTIME_DIR"])/guard.runtime_child(manifest["runtime_state"])/"control.sock"
        def active():
            remaining()
            raw=bounded([str(systemctl),"--user","--quiet","show","--property="+",".join(sorted(PROPERTIES)),unit],environment)
            values=guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines())
            guard.require(set(values) == PROPERTIES and re.fullmatch(r"[0-9a-f]{32}",values["InvocationID"])
                and values["NRestarts"].isdigit())
            core={key:values[key] for key in owned.IDLE_PROPERTIES}
            pid,group=owned.active_start_properties(core,manifest)
            identity=resident.process_identity(pid)
            caps,cgroup=resident.cgroup_observation(group,pid)
            guard.check_resident_bounds(core,caps)
            peer=guard.socket_witness(path)
            owned.start_control_peer(peer,pid)
            writer=witness.owner(pid,manifest["prefix"])
            guard.require(resident.process_identity(pid) == identity)
            return values,identity,cgroup,peer,writer
        initial=active()
        channel=Channel(path,initial[1][0],deadline)
        before=metadata(channel.read("system.health"),channel.read("system.handshake"))
        guard.require(active() == initial)
        # Exactly one explicit request; no retry, enrollment, provider request or unlock.
        response=channel.rpc("custody.reopen")
        remaining()
        after=metadata(channel.read("system.health"),channel.read("system.handshake"))
        remaining()
        outcome,refusal=classify(before,after,response)
        guard.require(active() == initial and channel.identity() == channel.peer)
        witness.recheck()
        remaining()
        return {"schema_version":1,"scope":"owned_resident_custody_reopen","outcome":outcome,
            "refusal":refusal,"metadata_loaded_before":before[0],"account_count_before":before[1],
            "metadata_loaded":after[0],"account_count":after[1],"custody_available":after[0],
            "same_process_verified":True,"same_service_invocation_verified":True,
            "same_socket_peer_verified":True,"daemon_singleton_lock_owner_verified":True,"resident_bounds_verified":True,
            "custody_reopen_requests":1,"service_mutation_requested":False,
            "provider_request_requested_by_controller":False,"controller_vault_material_read":False,
            "controller_key_written":False,"source_connected":False,"enrollment_verified":False,
            "same_process_handoff_proven":False,"archive_sha256":manifest["start"]["archive_sha256"]}
    finally:
        if channel is not None:
            channel.close()
        witness.close()
