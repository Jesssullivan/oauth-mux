"""Explicit new public installation with durable whole-package retention.

No service registration/start, private runtime read, source enrollment or update.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as guard
import resident_enrollment as resident
import install
import public_package_retention as retained


def schema(value,home):
    guard.require(type(value) is dict and set(value) == {"schema_version","action","ownership","instance",
        "prefix","records","runtime_state","service_path","archive_path","original","permissions"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["action"] == "retain-and-install-public" and value["ownership"] == "omux-installation"
        and value["instance"] == "default"
        and value["permissions"] == {"install_public_files":True,"activate_service":False,
            "connect_source":False,"restart_daemon":False}
        and all(type(v) is bool for v in value["permissions"].values()))
    for key,path in guard.fixed_paths(Path(home)).items():guard.require(retained.canonical(value[key]) == path)
    retained.canonical(value["archive_path"])
    if value["original"] is not None:
        import guard_resident_owned_update as owned
        owned.start_pins(value["original"],Path(home))
        guard.require(value["archive_path"] == value["original"]["archive_path"])
    return value


def execute(value,home,until):
    value=schema(value,home);retained.tick(until)
    prefix,records,service,state=(Path(value[key]) for key in ("prefix","records","service_path","runtime_state"))
    # This first boundary has no update authority, including unqualified images.
    if install._record(prefix,records) is not None:raise ValueError("retained installation requires absent record")
    source=package=None;error=None;result=None
    try:
        source=retained.Source(value["archive_path"],until,original=value["original"],home=home)
        reference=retained.publish(source,records,until)
        package=retained.HeldPackage(Path(reference["path"]).parent,until)
        guard.require(package.reference() == reference)
        def before():
            package.full();source.recheck();package.recheck();retained.tick(until)
        def after(record):
            guard.require(record["publicRetention"] == reference)
            package.full();source.recheck();package.recheck();retained.tick(until)
        record=install.install_bundle(source.archive.raw,prefix,records,service,"linux",
            daemon_state_dir=state,_owned_prepare=(before,after,until),_public_retention=package)
        before()
        result={"schema_version":1,"scope":"public-package-retention-and-new-file-placement-only",
            "retention":reference,"artifact":record["artifact"],"producer_qualified":value["original"] is not None,
            "service_started":False,"source_connected":False,"custody_verified":False,
            "installed_image_qualified":False,"native_runtime_qualified":False}
    except BaseException as failure:error=failure;raise
    finally:
        cleanup=None
        for owner in (package,source):
            if owner is None:continue
            try:owner.close()
            except BaseException as failure:
                if cleanup is None:cleanup=failure
        if cleanup is not None:
            if error is not None:retained.cleanup_cause(error,cleanup)
            raise cleanup
    retained.tick(until)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--manifest",required=True);args=parser.parse_args()
    until=resident.original_deadline(os.environ)-resident.CLEANUP_RESERVE_NS
    owners=retained.Owners();error=None
    try:
        path=retained.canonical(args.manifest)
        parent=owners.add(retained.Directory(path.parent,until,private=False))
        document=owners.add(retained.File(parent,path.name,16384,mode=0o600))
        value=retained.decode(document.raw)
        result=execute(value,Path(os.environ["HOME"]),until)
        document.recheck();parent.recheck()
    except BaseException as failure:error=failure;raise
    finally:
        try:owners.close()
        except BaseException as cleanup:
            if error is not None:retained.cleanup_cause(error,cleanup)
            raise
    retained.tick(until)
    sys.stdout.write(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
    sys.stdout.flush()
    retained.tick(until)
    return 0


if __name__ == "__main__":
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError):
        print("public retained installation refused",file=sys.stderr);sys.exit(125)
