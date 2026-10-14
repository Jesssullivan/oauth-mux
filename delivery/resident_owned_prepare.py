"""One explicitly authorized owned installation and non-starting registration."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as guard
import guard_resident_owned_prepare as prepare
import guard_resident_owned_update as owned
import resident_enrollment as resident
import install
import pack

PHASE="manifest"
PHASES=frozenset(("manifest","software","absent-unit","installation","registration","inactive-readback"))
def execute_prepare(systemctl,manifest,environment,bounded,remaining,deadline_ns):
    global PHASE
    prepare.schema(manifest,environment["HOME"])
    guard.require(type(deadline_ns) is int)
    work_deadline=deadline_ns-30*10**9
    owned.tick(work_deadline)
    prefix,records,state,unit=(Path(manifest[key]) for key in ("prefix","records","runtime_state","service_path"))
    witness=None
    try:
        PHASE="software"
        # Guardian alone holds EX daemon.lock. Carrier takes metadata-only fence.
        witness=prepare.InstallationPrepare(manifest,environment["HOME"],work_deadline,acquire_runtime_lock=False)
        payload=witness.files[1].raw
        artifact,files=pack.verify_bundle(payload)
        selection=manifest["install_archive"]
        guard.require(pack.digest(files["release-manifest.json"]) == selection["manifest_sha256"]
            and artifact["channel"] == "release" and artifact["distribution"] == "portable-linux"
            and artifact["target"] == "x86_64-linux"
            and artifact["provenance"] == {"sourceRevision":None,"sourceDirty":True})
        def manager(*arguments,allowed=(0,)):
            remaining(15)
            owned.tick(work_deadline)
            result=bounded([str(systemctl),"--user","--quiet",*arguments],environment,
                timeout=15,allowed_returncodes=allowed)
            owned.tick(work_deadline)
            return result
        def absent():
            raw=manager("show","--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec",
                unit.name,allowed=(0,4))
            prepare.absent_service(guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines()))
            owned.inactive_cgroup(work_deadline)
            witness.parent_recheck()
            witness.alias_recheck()
            witness.runtime.recheck()
        PHASE="absent-unit"
        absent()
        def before():
            remaining()
            witness.before_write()
            absent()
        def after(record):
            remaining()
            witness.written(record)
        PHASE="installation"
        install.prepare_bundle(payload,prefix,records,unit,state,before,after,deadline_ns=work_deadline)
        # Installation transaction is complete. Registration failure retains an
        # explicit owned partial installation; it never retries, starts or rolls
        # back aliases behind manager authority.
        PHASE="registration"
        absent()
        witness.alias_recheck()
        manager("enable",str(unit))  # no --now; future login may start it
        manager("daemon-reload")
        PHASE="inactive-readback"
        raw=manager("show","--property="+",".join(sorted(owned.IDLE_PROPERTIES)),unit.name)
        values=guard.unique(line.split("=",1) for line in raw.decode("ascii").splitlines())
        owned.inactive_installation(values,manifest)
        owned.inactive_cgroup(work_deadline)
        result=witness.installed()
        remaining()
        witness.recheck()
        return {"schema_version":1,"scope":"owned_resident_preparation",**result,
            "enrollment_verified":False,"same_process_handoff_proven":False}
    finally:
        if witness is not None:
            witness.close()

def main():
    resident.DEADLINE_NS=resident.original_deadline(os.environ)
    guard.require(len(sys.argv) == 2)
    systemctl=Path(sys.argv[1]).resolve(strict=True)
    manifest=resident.private_manifest(validator=lambda value:prepare.schema(value,os.environ["HOME"]))
    environment=resident.controller_environment(os.environ,manifest["instance"])
    result=execute_prepare(systemctl,manifest,environment,resident.bounded,resident.remaining,resident.DEADLINE_NS)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("owned installation preparation refused at "+(PHASE if PHASE in PHASES else "manifest"),file=sys.stderr)
        sys.exit(1)

