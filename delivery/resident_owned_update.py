"""Explicit qualified owned update; never activates, enrolls or reads custody."""
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as resident
import guard_resident_owned_update as update
import install
import pack

def execute_update(bundle,systemctl,manifest,environment,bounded,remaining,deadline_ns):
    selection = update.pins(manifest["update"],environment["HOME"])
    prefix,records,state,unit = (Path(manifest[key]) for key in
        ("prefix","records","runtime_state","service_path"))
    payload = pack.read_bundle(bundle)
    resident.require(len(payload) == selection["archive_bytes"]
        and hashlib.sha256(payload).hexdigest() == selection["archive_sha256"])
    # Full declared-template/ABI/ELF/dependency/archive validation remains mandatory here.
    artifact,files = pack.verify_bundle(payload)
    resident.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == selection["manifest_sha256"]
        and artifact["provenance"] == {"sourceRevision":None,"sourceDirty":True}
        and artifact["channel"] == "release" and artifact["distribution"] == "portable-linux"
        and artifact["target"] == "x86_64-linux")
    old_payload = pack.read_bundle(Path(selection["previous_archive_path"]))
    resident.require(len(old_payload) == selection["previous_archive_bytes"]
        and hashlib.sha256(old_payload).hexdigest() == selection["previous_archive_sha256"])
    old_files,_ = pack.archive_contents(old_payload)
    resident.require(hashlib.sha256(old_files["release-manifest.json"]).hexdigest() == selection["previous_manifest_sha256"])
    old_artifact = json.loads(old_files["release-manifest.json"],object_pairs_hook=resident.unique)
    old_plan = install.installation_plan(old_artifact,old_files,prefix,records,unit,"linux",daemon_state_dir=state)
    new_plan = install.installation_plan(artifact,files,prefix,records,unit,"linux",daemon_state_dir=state)
    expected_old = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode} for path,raw,mode in old_plan}
    expected_new = {str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode} for path,raw,mode in new_plan}
    namespace_environment = dict(environment)  # selected allowlist only; no ambient manager selectors
    def manager(*arguments):
        remaining()
        return bounded([str(systemctl),"--user","--quiet",*arguments],namespace_environment)
    def idle():
        output = manager("show","--property="+",".join(sorted(update.IDLE_PROPERTIES)),unit.name)
        values = resident.unique(line.split("=",1) for line in output.decode("ascii").splitlines())
        resident.require(update.inactive_installation(values,manifest) == unit)
        update.inactive_cgroup(deadline_ns-30*10**9)
        return values
    def record_matches(expected,archive_sha,manifest_sha):
        record = install._record(prefix,records)
        resident.require(record is not None and record["userService"] == str(unit)
            and record["artifact"]["archiveSha256"] == archive_sha
            and record["artifact"]["manifestSha256"] == manifest_sha
            and len(record["files"]) == len(expected)
            and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]} for row in record["files"]} == expected
            and all(install._matches(Path(row["path"]),row) for row in record["files"]))
        return record
    fence = old_unit = new_unit = None
    try:
        fence = update.RuntimeFence(state,deadline_ns-30*10**9,acquire_lock=False)
        old_unit = resident.OwnedUnitCustody(manifest)
        values = idle()
        old_unit.verify_fragment(values["FragmentPath"])
        record_matches(expected_old,selection["previous_archive_sha256"],selection["previous_manifest_sha256"])
        def before_replace():
            remaining()
            fence.recheck()
            old_unit.recheck()
            values = idle()
            old_unit.verify_fragment(values["FragmentPath"])
            record_matches(expected_old,selection["previous_archive_sha256"],selection["previous_manifest_sha256"])
        def after_replace(result):
            nonlocal new_unit
            remaining()
            fence.recheck()
            record_matches(expected_new,selection["archive_sha256"],selection["manifest_sha256"])
            new_unit = resident.OwnedUnitCustody(manifest)
            manager("daemon-reload")
            values = idle()
            new_unit.verify_fragment(values["FragmentPath"])
            fence.recheck()
            resident.require(result == install._record(prefix,records))
        try:
            result = install.update_bundle(payload,prefix,records,unit,state,
                selection["previous_archive_sha256"],before_replace,after_replace,
                deadline_ns=deadline_ns-30*10**9)
        except BaseException:
            # Normal transaction failures roll back payload+record. Rejoin manager to those restored bytes.
            # A hard outer kill is not rollback evidence; root must independently inspect that failure.
            if new_unit is not None:
                new_unit.close()
                new_unit = None
            remaining()
            record_matches(expected_old,selection["previous_archive_sha256"],selection["previous_manifest_sha256"])
            manager("daemon-reload")
            idle()
            fence.recheck()
            raise
        remaining()
        fence.recheck()
        new_unit.recheck()
        record_matches(expected_new,selection["archive_sha256"],selection["manifest_sha256"])
        idle()
        return {"schema_version":1,"scope":"resident_owned_inactive_installation_update",
            "installation_updated":True,"service_active":False,"service_started":False,"source_connected":False,
            "provider_request_performed":False,"vault_material_read":False,"runtime_metadata_preserved":True,
            "archive_sha256":selection["archive_sha256"],"previous_archive_sha256":selection["previous_archive_sha256"],
            "same_process_handoff_proven":False}
    finally:
        if new_unit is not None:
            new_unit.close()
        if old_unit is not None:
            old_unit.close()
        if fence is not None:
            fence.close()
