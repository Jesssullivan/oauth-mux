"""Qualified first start of an enabled owned installation; no source or vault client."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as guard
import guard_resident_owned_update as owned
import pack
import resident_enrollment as resident

def execute_start(bundle,systemctl,manifest,environment,bounded,remaining,deadline_ns):
    selection = owned.start_pins(manifest["start"],environment["HOME"])
    payload = pack.read_bundle(bundle)
    guard.require(len(payload) == selection["archive_bytes"]
        and hashlib.sha256(payload).hexdigest() == selection["archive_sha256"])
    _,files = pack.verify_bundle(payload)
    guard.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == selection["manifest_sha256"])
    witness = owned.OwnedFirstStart(manifest,environment["HOME"],deadline_ns-30*10**9)
    try:
        unit = Path(manifest["service_path"]).name
        def manager(*arguments):
            remaining()
            return bounded([str(systemctl),"--user","--quiet",*arguments],environment)
        def properties():
            raw = manager("show","--property="+",".join(sorted(owned.IDLE_PROPERTIES)),unit)
            return guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines())
        before = properties()
        owned.inactive_installation(before,manifest)
        owned.inactive_cgroup(deadline_ns-30*10**9)
        witness.pristine()
        # Only the exact already enabled unit is started. No enable/reload/install.
        manager("start",unit)
        limit = time.monotonic()+remaining(30)
        while time.monotonic() < limit:
            remaining()
            try:
                values = properties()
                pid,group = owned.active_start_properties(values,manifest)
                identity = resident.process_identity(pid)
                caps,cgroup = resident.cgroup_observation(group,pid)
                guard.check_resident_bounds(values,caps)
                socket = Path(environment["XDG_RUNTIME_DIR"])/guard.runtime_child(manifest["runtime_state"])/"control.sock"
                peer = guard.socket_witness(socket)
                owned.start_control_peer(peer,pid)
                raw = bounded([str(Path(manifest["prefix"])/"bin/omux"),"--state-dir",manifest["runtime_state"],
                    "rpc","system.health","-"],environment,b"{}")
                envelope = json.loads(raw,object_pairs_hook=guard.unique)
                guard.require(type(envelope) is dict and set(envelope) == {"jsonrpc","id","result"}
                    and envelope["jsonrpc"] == "2.0")
                health = owned.start_health(envelope["result"])
                guard.require(resident.process_identity(pid) == identity and properties() == values
                    and guard.socket_witness(socket) == peer)
                witness.recheck()
                return {"schema_version":1,"scope":"owned_first_resident_start",**health,
                    "service_active":True,"resident_bounds_verified":True,
                    "resident_service_disposition":"retained_under_existing_user_manager",
                    "source_connected":False,"provider_request_requested_by_controller":False,
                    "controller_vault_material_read":False,"controller_key_written":False,
                    "enrollment_verified":False,"same_process_handoff_proven":False,
                    "archive_sha256":selection["archive_sha256"]}
            except (ValueError,OSError):
                time.sleep(min(0.1,remaining(0.1)))
        raise ValueError("owned-first-start-control-plane-unavailable")
    finally:
        witness.close()
