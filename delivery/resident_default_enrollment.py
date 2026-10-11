"""One explicitly authorized daemon-default Codex source; no profile reader."""
import os
from pathlib import Path
import re
import time
import resident_custody_reopen as custody
import resident_enrollment as resident

guard,owned=custody.guard,custody.owned
HEX=re.compile(r"[0-9a-f]{64}")

class Channel(custody.Channel):
    METHODS=("system.health","system.handshake","state.snapshot","source.connect","enrollment.start")
    def parameters(self,method,params):
        if method not in ("source.connect","enrollment.start"):
            return super().parameters(method,params)
        common={"operation_id","expected_revision"}
        guard.require(type(params) is dict and type(params.get("operation_id")) is str
            and HEX.fullmatch(params["operation_id"])
            and type(params.get("expected_revision")) is int and params["expected_revision"] >= 0)
        if method == "source.connect":
            guard.require(set(params) == common|{"kind","provider","label"}
                and params["kind"] == "native_store" and params["provider"] == "codex"
                and params["label"] == "Authorized native account")
        else:
            guard.require(set(params) == common|{"source_id","include_operation_generation"}
                and type(params["source_id"]) is str and HEX.fullmatch(params["source_id"])
                and params["include_operation_generation"] is True)
        return params

def snapshot(value):
    guard.require(type(value) is dict and type(value.get("revision")) is int and value["revision"] >= 0
        and value.get("custody_available") is True
        and all(type(value.get(key)) is list for key in ("sources","accounts","grants","jobs")))
    return value

def fresh_default(value):
    value=snapshot(value)
    # A pre-existing native source cannot be identified as daemon-default from
    # labels. Refuse ambiguity rather than guess its path or duplicate authority.
    guard.require(all(type(row) is dict for row in value["sources"]))
    guard.require(not any(row.get("provider") == "codex" and row.get("kind") == "native_store"
        for row in value["sources"]))
    return value["revision"]

def connected(value):
    guard.require(type(value) is dict and value.get("status") == "authorized"
        and value.get("identity_admission") == "verification_required"
        and type(value.get("source_id")) is str and HEX.fullmatch(value["source_id"]))
    return value["source_id"]

def admitted(value,source_id):
    guard.require(type(value) is dict and value.get("status") == "verifying_identity"
        and value.get("operation_id") == "reconcile-"+source_id
        and type(value.get("operation_generation")) is int and 0 < value["operation_generation"] < 2**64
        and type(value.get("admitted_revision")) is int and value["admitted_revision"] >= 0)
    return value["operation_id"],value["operation_generation"],value["admitted_revision"]

def progress(value,source_id,operation,generation,revision,now):
    value=snapshot(value)
    guard.require(value["revision"] >= revision)
    source=resident.source_authority(value,source_id,now)
    if source["status"] == "detached":
        return "source_detached",None
    jobs=[row for row in value["jobs"] if type(row) is dict and row.get("id") == operation]
    guard.require(len(jobs) == 1 and jobs[0].get("kind") == "enrollment"
        and type(jobs[0].get("operation_generation")) is int and jobs[0]["operation_generation"] == generation
        and jobs[0].get("status") in ("pending","running","completed","failed"))
    status=jobs[0]["status"]
    if status == "failed":
        return "identity_verification_failed",None
    if status != "completed":
        return "pending",None
    facts=resident.enrolled_authority(value,source_id,now)
    guard.require(facts is not None)
    return "verified",facts

def await_authority(channel,source_id,operation,generation,revision,deadline,remaining):
    poll_deadline=min(deadline,time.monotonic_ns()+120*10**9)
    while True:
        remaining()
        guard.require(time.monotonic_ns() < poll_deadline)
        observed=channel.read("state.snapshot")
        remaining()
        guard.require(time.monotonic_ns() < poll_deadline)
        outcome,facts=progress(observed,source_id,operation,generation,revision,int(time.time()))
        if outcome != "pending":
            return outcome,facts
        delay=min(0.1,(poll_deadline-time.monotonic_ns())/10**9)
        guard.require(delay > 0)
        time.sleep(delay)

def mutation(channel,method,params,revision):
    guard.require(method in ("source.connect","enrollment.start"))
    value=channel.rpc(method,{**params,"operation_id":os.urandom(32).hex(),"expected_revision":revision})
    guard.require(set(value) == {"jsonrpc","id","result"})
    return value["result"]

def execute(systemctl,manifest,environment,bounded,remaining,deadline_ns):
    guard.manifest_schema(manifest,environment["HOME"])
    guard.carrier_purpose(guard.EXISTING_ENROLLMENT_LABEL,manifest["action"],True)
    guard.require(manifest["action"] == "enroll-default-existing")
    deadline=deadline_ns-30*10**9
    selected={**manifest,"start":manifest["existing_archive"]}
    witness=owned.OwnedCustodyReopen(selected,environment["HOME"],deadline)
    channel=None
    try:
        path=Path(environment["XDG_RUNTIME_DIR"])/guard.runtime_child(manifest["runtime_state"])/"control.sock"
        def active():
            remaining()
            raw=bounded([str(systemctl),"--user","--quiet","show","--property="+",".join(sorted(custody.PROPERTIES)),Path(manifest["service_path"]).name],environment)
            values=guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines())
            guard.require(set(values) == custody.PROPERTIES and re.fullmatch(r"[0-9a-f]{32}",values["InvocationID"])
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
        loaded,count=custody.metadata(channel.read("system.health"),channel.read("system.handshake"))
        guard.require(loaded is True)
        initial_snapshot=snapshot(channel.read("state.snapshot"))
        guard.require(count == len(initial_snapshot["accounts"]))
        revision=fresh_default(initial_snapshot)
        guard.require(active() == initial)
        # One explicit source authorization; only the daemon resolves/reads it.
        source_id=connected(mutation(channel,"source.connect",{"kind":"native_store","provider":"codex","label":"Authorized native account"},revision))
        current=snapshot(channel.read("state.snapshot"))
        source=resident.source_authority(current,source_id,int(time.time()))
        guard.require(source["status"] == "connected" and active() == initial)
        operation,generation,revision=admitted(mutation(channel,"enrollment.start",{"source_id":source_id,"include_operation_generation":True},current["revision"]),source_id)
        outcome,facts=await_authority(channel,source_id,operation,generation,revision,deadline,remaining)
        final_snapshot=snapshot(channel.read("state.snapshot"))
        guard.require(progress(final_snapshot,source_id,operation,generation,revision,int(time.time())) == (outcome,facts))
        loaded,count=custody.metadata(channel.read("system.health"),channel.read("system.handshake"))
        guard.require(loaded is True and count == len(final_snapshot["accounts"]))
        guard.require(active() == initial and channel.identity() == channel.peer)
        witness.recheck()
        remaining()
        return {"schema_version":1,"scope":"owned_daemon_default_native_source_enrollment","outcome":outcome,
            "source_handle":source_id,"operation_generation":generation,
            "authority":facts,"verified_source_identities":1 if facts is not None else 0,
            "renewal_writer":"external" if facts is not None else None,
            "same_process_verified":True,"same_service_invocation_verified":True,"resident_bounds_verified":True,
            "service_mutation_requested":False,"credential_contents_read_by_controller":False,
            "controller_provider_requests":False,"daemon_identity_verification_authorized":True,
            "daemon_provider_requests_observed":None,
            "profile_path_selected_by_controller":False,"native_auth_written":False,
            "archive_sha256":manifest["existing_archive"]["archive_sha256"]}
    finally:
        if channel is not None:
            channel.close()
        witness.close()
