"""Explicit owned first start, observation or Locked zero-DB idle-stop."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as guard
import guard_resident_owned_update as owned
import resident_enrollment as resident
import pack

PHASES=frozenset(("manifest","software","start","active-readback","health","idle-admission","stop","stopped-readback"))
PHASE="manifest"
def phase(name):
    global PHASE
    guard.require(name in PHASES)
    PHASE=name

def execute_existing(systemctl,manifest,environment,bounded,remaining,deadline_ns):
    guard.manifest_schema(manifest,environment["HOME"])
    guard.require(manifest["action"] in ("start-existing","observe-existing","stop-idle-owned"))
    if manifest["action"] == "start-existing":
        phase("start")
        import resident_owned_start
        # The existing start contract rechecks full software/qualification,
        # inactive unit/cgroup/zero-lock admission and bounded active health.
        return resident_owned_start.execute_start(Path(manifest["start"]["archive_path"]),
            systemctl,manifest,environment,bounded,remaining,deadline_ns)
    phase("software")
    selection=owned.start_pins(manifest["start"],environment["HOME"])
    payload=pack.read_bundle(Path(selection["archive_path"]))
    guard.require(len(payload) == selection["archive_bytes"]
        and hashlib.sha256(payload).hexdigest() == selection["archive_sha256"])
    _,files=pack.verify_bundle(payload)
    guard.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == selection["manifest_sha256"])
    witness=owned.OwnedFirstStart(manifest,environment["HOME"],deadline_ns-30*10**9)
    try:
        unit=Path(manifest["service_path"]).name
        control=Path(environment["XDG_RUNTIME_DIR"])/guard.runtime_child(manifest["runtime_state"])
        def manager(*arguments):
            remaining()
            return bounded([str(systemctl),"--user","--quiet",*arguments],environment)
        def properties():
            raw=manager("show","--property="+",".join(sorted(owned.IDLE_PROPERTIES)),unit)
            return guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines())
        def active():
            phase("active-readback")
            values=properties()
            pid,group=owned.active_start_properties(values,manifest)
            identity=resident.process_identity(pid)
            caps,cgroup=resident.cgroup_observation(group,pid)
            guard.check_resident_bounds(values,caps)
            peer=guard.socket_witness(control/"control.sock")
            owned.start_control_peer(peer,pid)
            witness.pristine()
            guard.require(resident.process_identity(pid) == identity)
            return values,identity,cgroup,peer
        def rpc(method):
            remaining()
            raw=bounded([str(Path(manifest["prefix"])/"bin/omux"),"--state-dir",manifest["runtime_state"],
                "rpc",method,"-"],environment,b"{}")
            envelope=json.loads(raw,object_pairs_hook=guard.unique)
            guard.require(type(envelope) is dict and set(envelope) == {"jsonrpc","id","result"}
                and envelope["jsonrpc"] == "2.0" and type(envelope["id"]) is int and envelope["id"] == 1)
            return envelope["result"]
        before=active()
        phase("health")
        health=rpc("system.health")
        result=owned.start_health(health)
        handshake=None
        if manifest["action"] == "stop-idle-owned":
            phase("idle-admission")
            handshake=rpc("system.handshake")
            result=owned.locked_idle_metadata(health,handshake)
        guard.require(active() == before)
        witness.pristine()
        receipt={"schema_version":1,"scope":"owned_zero_database_resident_lifecycle",**result,
            "account_counts_observed":False,"enrollment_verified":False,"source_connected":False,
            "provider_request_requested_by_controller":False,"controller_vault_material_read":False,
            "controller_key_written":False,"same_process_handoff_proven":False,
            "resident_bounds_verified":True,"archive_sha256":selection["archive_sha256"]}
        if manifest["action"] == "observe-existing":
            return {**receipt,"service_active":True,"service_mutation_requested":False,
                "resident_service_disposition":"observed_only_retained_under_existing_user_manager"}
        # Actor Locked mode has no loaded metadata, DB or native admission.
        # Exact no-DB custody is rechecked immediately before this explicit stop.
        phase("idle-admission")
        owned.locked_idle_metadata(health,handshake)
        guard.require(active() == before)
        witness.pristine()
        phase("stop")
        manager("stop",unit)
        limit=time.monotonic()+remaining(20)
        while True:
            phase("stopped-readback")
            try:
                owned.inactive_installation(properties(),manifest)
                owned.inactive_cgroup(deadline_ns-30*10**9)
                guard.require(not os.listdir(control))
                owned.original_process_exited(before[1])
                witness.pristine()
                return {**receipt,"service_active":False,"service_mutation_requested":True,
                    "custody_never_loaded":True,"metadata_loaded":False,
                    "native_admission_available":False,"owned_idle_stop_verified":True,
                    "resident_service_disposition":"stopped_explicitly_custody_retained"}
            except (ValueError,OSError):
                guard.require(time.monotonic() < limit)
                time.sleep(min(0.1,remaining(0.1)))
    finally:
        witness.close()

def main():
    resident.DEADLINE_NS=resident.original_deadline(os.environ)
    guard.require(len(sys.argv) == 2)
    systemctl=Path(sys.argv[1]).resolve(strict=True)
    manifest=resident.private_manifest()
    environment=resident.controller_environment(os.environ,manifest["instance"])
    result=execute_existing(systemctl,manifest,environment,resident.bounded,resident.remaining,resident.DEADLINE_NS)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("owned resident lifecycle refused at "+(PHASE if PHASE in PHASES else "manifest"),file=sys.stderr)
        sys.exit(1)
