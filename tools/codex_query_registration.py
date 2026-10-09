"""Fixed public registration snapshot only; no Nix child, fetch or byte authority."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import sqlite3
import time
from decimal import Decimal
import xml.etree.ElementTree as ET

import nix_interpreter_closure as closure

KIND = "omux-fixed-query-registration-v1"
TARGET = "//tools:codex_query_registration_producer"
RESERVED_TARGET = "//tools:codex_query_registration_reserved_producer"
CANDIDATE_KIND = "omux-protocol-history-query-registration-selection-v1"
RESERVED_CANDIDATE_KIND = "omux-protocol-history-query-registration-reserved-selection-v1"
CANDIDATE_KINDS = (CANDIDATE_KIND, RESERVED_CANDIDATE_KIND)
COORDINATORS = ("/home/jess/.local/state/omux-execution-20261005",
    "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005")
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
ROLE_NAMES = ("python","bash","git","bazel","coreutils","jdk")
# Names follow the sorted fixed roots, never metadata-provided values.
DATABASE = Path("/nix/var/nix/db/db.sqlite")
MAX_SECONDS = 30
MAX_ROOTS = 4096
MAX_REFS = 65536
MAX_BYTES = 4*1024**3
MAX_OUTPUT = 4*1024**2
PROJECT_FILES = ("flake.nix","flake.lock","tools/zig-index.json","tools/codex_upstream_archives.json")
TOOL_ROOTS = tuple(sorted((
    "/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1",
    "/nix/store/4bwbk4an4bx7cb8xwffghvjjyfyl7m2i-bash-interactive-5.3p9",
    "/nix/store/jjxngswsb214vb58qx485jhmilf0kxxy-coreutils-9.10",
    "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12",
    "/nix/store/c0277k5giric1mn9dklllavbzvxl6hzb-git-2.53.0",
    "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7",
)))

class MissingRoots(ValueError):
    def __init__(self, roles):
        self.roles = roles
        super().__init__("missing fixed query roots")


def guard_epoch(value):
    require(type(value) is str and any(re.fullmatch(re.escape(root)+"/"+UUID,value)
        is not None for root in COORDINATORS))
    return Path(value).name


def require(value):
    if value is not True:
        raise ValueError("fixed query registration refused")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()

def tick(deadline):
    require(type(deadline) is float and math.isfinite(deadline) and time.monotonic()<deadline)

def project_pins(project):
    require(type(project) is dict and set(project)==set(PROJECT_FILES)
        and all(type(raw) is bytes and 0<len(raw)<=2*1024**2 for raw in project.values()))
    return {name:sha(raw) for name,raw in sorted(project.items())}

def present(root):
    # Metadata-only lstat. A NAR link is inert; no referenced target is opened.
    try:info=os.lstat(root)
    except FileNotFoundError:return False
    return bool(info.st_uid in (0,os.getuid())
        and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)))

def canonical_hash(value):
    require(type(value) is str)
    if re.fullmatch(r"sha256:[0-9a-f]{64}",value) is not None:
        return value
    require(re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=",value) is not None)
    decoded=base64.b64decode(value[7:],validate=True)
    require(len(decoded)==32 and base64.b64encode(decoded).decode()==value[7:])
    return "sha256:"+decoded.hex()

def normalize(rows,deadline):
    require(type(rows) is list and 0<len(rows)<=MAX_ROOTS)
    paths=[row["path"] for row in rows]
    require(paths==sorted(set(paths)) and all(closure.current_flake_path_refusal(root) is None for root in paths)
        and set(TOOL_ROOTS)<=set(paths))
    records={};total=references=0
    for row in rows:
        tick(deadline)
        require(type(row) is dict and set(row)=={"path","narHash","narSize","references"})
        refs=row["references"]
        require(type(refs) is list and refs==sorted(set(refs)) and len(refs)<=closure.MAX_RECORDS
            and all(closure.current_flake_path_refusal(ref) is None and ref in paths for ref in refs)
            and type(row["narSize"]) is int and 0<row["narSize"]<=MAX_BYTES)
        total+=row["narSize"];references+=len(refs)
        require(total<=MAX_BYTES and references<=MAX_REFS)
        # The snapshot primitive doesn't query deriver. Empty is an explicit
        # unknown here, never an assertion about the live database's field.
        record=[row["path"],canonical_hash(row["narHash"]),str(row["narSize"]),"",str(len(refs)),*refs]
        records[row["path"]]={"references":refs,"record":record}
    require(closure.reachable(records,TOOL_ROOTS)==paths)
    registration="".join("\n".join(records[root]["record"])+"\n" for root in paths).encode("ascii")
    raw_paths=("\n".join(paths)+"\n").encode("ascii")
    require(len(registration)<=MAX_OUTPUT and len(raw_paths)<=MAX_OUTPUT)
    # Actual canonical wire parser; defaults for runtime seeds remain unchanged.
    require(closure.registrations(registration.decode("ascii"),paths,current_flake_paths=True)==records)
    return registration,raw_paths,{"roots":len(paths),"references":references,"nar_bytes":total}

def database_scope(database):
    # Only public metadata is opened. Reject redirected DB/ancestors before
    # SQLite sees bytes; production main always supplies DATABASE.
    path=Path(database)
    require(os.getuid()!=0 and path.is_absolute() and path.resolve(strict=True)==path)
    current=path
    while current!=current.parent:
        info=os.lstat(current)
        require(info.st_uid==0 and not info.st_mode & 0o022
            and not stat.S_ISLNK(info.st_mode))
        if current==path:require(stat.S_ISREG(info.st_mode) and info.st_nlink==1)
        else:require(stat.S_ISDIR(info.st_mode))
        current=current.parent
    for suffix in ("-wal","-shm"):
        sidecar=Path(str(path)+suffix)
        try:info=os.lstat(sidecar)
        except FileNotFoundError:continue
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022
            and info.st_nlink==1 and sidecar.resolve(strict=True)==sidecar)


def collect(project,deadline,epoch,*,database=DATABASE,exists=present):
    """Only main binds fixed DB/root scope; models inject disposable SQLite."""
    import cached_nix_inventory as cached
    require(cached.MAX_SECONDS==MAX_SECONDS and cached.MAX_PATHS==MAX_ROOTS and cached.MAX_REFS==MAX_REFS)
    pins=project_pins(project);tick(deadline)
    require(type(epoch) is str and re.fullmatch(UUID,epoch) is not None)
    missing=[ROLE_NAMES[index] for index,root in enumerate(TOOL_ROOTS) if not exists(root)]
    if missing:raise MissingRoots(missing)
    database_scope(database);tick(deadline)
    rows=cached.snapshot_inventory(database,list(TOOL_ROOTS),exists,absolute_deadline=deadline)
    tick(deadline);database_scope(database);tick(deadline)
    registration,paths,counts=normalize(rows,deadline)
    report={"schema_version":1,"kind":KIND,"status":"provisional-fixed-query-registration-observed",
        "mode":"local-sqlite-readonly-transaction","guard_epoch":epoch,
        "reader_context":{"nonroot":True,"root_owned_nonwritable_ancestry":True,
            "sidecars":"root-owned-nonwritable-or-absent"},"tool_roots":list(TOOL_ROOTS),"project_sha256":pins,
        "registration":{"sha256":sha(registration),"bytes":len(registration)},
        "store_paths":{"sha256":sha(paths),"bytes":len(paths)},"counts":counts,
        "deriver_metadata":"not-collected","paths_presence_checked":True,
        **{name:False for name in ("content_rehashed","nar_verified","query_tools_qualified","realized",
            "complete_build_seed_verified","native_runtime_qualified","sdk_qualified","execution_authority")}}
    return report,registration,paths

def validate_report(report,registration,paths,project,epoch):
    require(type(registration) is bytes and type(paths) is bytes
        and 0<len(registration)<=MAX_OUTPUT and 0<len(paths)<=MAX_OUTPUT)
    require(type(report) is dict and set(report)=={"schema_version","kind","status","mode","tool_roots",
        "project_sha256","registration","store_paths","counts","deriver_metadata","paths_presence_checked","guard_epoch","reader_context",
        "content_rehashed","nar_verified","query_tools_qualified","realized","complete_build_seed_verified",
        "native_runtime_qualified","sdk_qualified","execution_authority"}
        and type(report["schema_version"]) is int and report["schema_version"]==1 and report["kind"]==KIND
        and report["status"]=="provisional-fixed-query-registration-observed"
        and report["mode"]=="local-sqlite-readonly-transaction" and report["tool_roots"]==list(TOOL_ROOTS)
        and type(epoch) is str and re.fullmatch(UUID,epoch) is not None and report["guard_epoch"]==epoch
        and type(report["reader_context"]) is dict and set(report["reader_context"])=={
            "nonroot","root_owned_nonwritable_ancestry","sidecars"}
        and report["reader_context"]["nonroot"] is True
        and report["reader_context"]["root_owned_nonwritable_ancestry"] is True
        and report["reader_context"]["sidecars"]=="root-owned-nonwritable-or-absent"
        and report["project_sha256"]==project_pins(project)
        and report["deriver_metadata"]=="not-collected" and report["paths_presence_checked"] is True)
    for name in ("content_rehashed","nar_verified","query_tools_qualified","realized","complete_build_seed_verified",
                 "native_runtime_qualified","sdk_qualified","execution_authority"):
        require(report[name] is False)
    require(report["registration"]=={"sha256":sha(registration),"bytes":len(registration)}
        and report["store_paths"]=={"sha256":sha(paths),"bytes":len(paths)}
        and type(report["registration"]["bytes"]) is int and type(report["store_paths"]["bytes"]) is int)
    declared=paths.decode("ascii").splitlines()
    require(declared==sorted(set(declared)) and 0<len(declared)<=MAX_ROOTS)
    records=closure.registrations(registration.decode("ascii"),declared,current_flake_paths=True)
    require(closure.reachable(records,TOOL_ROOTS)==declared)
    expected={"roots":len(declared),"references":sum(len(row["references"]) for row in records.values()),
        "nar_bytes":sum(int(row["record"][2]) for row in records.values())}
    require(type(report["counts"]) is dict and all(type(value) is int for value in report["counts"].values())
        and report["counts"]==expected and expected["nar_bytes"]<=MAX_BYTES
        and expected["references"]<=MAX_REFS)
    return records

def validate_success(candidate,raw,project,plan):
    """Supplied pinned public producer bytes only; no implicit receipt IO."""
    producer=candidate["producer"]
    for name in ("receipt","evidence","log","xml"):
        data=raw["candidate_"+name];pin=producer[name]
        require(type(data) is bytes and 0<len(data)<=MAX_OUTPUT
            and sha(data)==pin["sha256"] and len(data)==pin["bytes"])
    for name in ("registration","paths","report"):
        data=raw["candidate_"+name];pin=candidate[name]
        require(type(data) is bytes and 0<len(data)<=MAX_OUTPUT
            and sha(data)==pin["sha256"] and len(data)==pin["bytes"])
    def decode(data):
        return json.loads(data,object_pairs_hook=unique)
    receipt=decode(raw["candidate_receipt"])
    reserved = receipt.get("profile") == "query-registration-reserved"
    if reserved:
        require(candidate.get("kind") == RESERVED_CANDIDATE_KIND)
        import guard_query_registration_reserved as reservation
        require(reservation.LABEL == RESERVED_TARGET)
        reservation.validate_qualification(receipt)
        target = RESERVED_TARGET
    else:
        require(candidate.get("kind") == CANDIDATE_KIND and receipt.get("profile") == "standard")
        target = TARGET
    epoch=guard_epoch(str(Path(producer["receipt"]["path"]).parent))
    parent=str(Path(producer["receipt"]["path"]).parent)
    require(receipt["id"]==receipt["artifact_epoch"]==epoch
        and receipt["unit"]=="omux-execution-"+epoch+".service"
        and receipt["manager"]=="system"
        and receipt["verb"]=="test" and receipt["targets"]==[target]
        and type(receipt["exit"]) is int and receipt["exit"]==0
        and type(receipt["workload_exit"]) is int and receipt["workload_exit"]==0
        and receipt["controller_failure"] is None and receipt["descendants_empty"] is True
        and receipt["cleanup"]["state"]=="empty" and receipt["source_dirty"]=="false"
        and receipt["cache_reuse_requested"] is False and receipt["output_base"]==parent+"/output-base"
        and receipt["source_commit"]==producer["source_commit"]==plan["source_commit"]
        and receipt["graph_sha256"]==producer["graph_sha256"]==plan["graph_sha256"]
        and receipt["test_evidence"]["state"]=="preserved"
        and receipt["test_evidence"]["sha256"]==producer["evidence"]["sha256"])
    expected={"MemoryMax":"4294967296","MemorySwapMax":"0","TasksMax":"512",
        "PrivateNetwork":"yes","KillMode":"control-group","SendSIGKILL":"yes","OOMPolicy":"kill",
        "NoNewPrivileges":"yes","CapabilityBoundingSet":"","AmbientCapabilities":""}
    if reserved:
        expected.update(MemoryMax="4026531840", TasksMax="480")
        output=parent+"/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"+target.split(":")[1]+"/test.outputs/"
        require(all(candidate[name]["path"] == output+leaf for name, leaf in (
            ("registration", "registration"), ("paths", "store-paths"), ("report", "query-registration.json"))))
    observed=receipt["observed_properties"]
    require(type(observed) is dict and all(observed.get(key)==value for key,value in expected.items()))
    cpu=observed.get("CPUQuotaPerSecUSec")
    match=re.fullmatch(r"([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)",cpu) if type(cpu) is str else None
    require(match is not None and Decimal(match[1])*{"us":1,"ms":1000,"s":1000000}[match[2]]==(1900000 if reserved else 2000000))
    duration=observed.get("RuntimeMaxUSec")
    match=re.fullmatch(r"([1-9][0-9]*)(us|ms|s|min)",duration) if type(duration) is str else None
    require(match is not None and 0<int(match[1])*{"us":1,"ms":1000,"s":1000000,"min":60000000}[match[2]]<=1200*1000000)
    require(type(receipt["epoch_start_ns"]) is int and receipt["epoch_start_ns"]>0)
    evidence=decode(raw["candidate_evidence"])
    require(type(evidence["schema"]) is int and evidence["schema"]==1
        and type(evidence["bazel_exit"]) is int and evidence["bazel_exit"]==0
        and type(evidence["epoch_start_ns"]) is int and evidence["epoch_start_ns"]==receipt["epoch_start_ns"]
        and evidence["targets"]==[target] and len(evidence["results"])==1)
    result=evidence["results"][0]
    require(result["target"]==target and result["state"]=="observed")
    for name in ("log","xml"):
        rows=[row for row in result["files"] if row["source"]=="test."+name]
        require(len(rows)==1 and rows[0]["state"]=="copied"
            and rows[0]["file"]==Path(producer[name]["path"]).name
            and rows[0]["sha256"]==producer[name]["sha256"]
            and type(rows[0]["bytes"]) is int and rows[0]["bytes"]==producer[name]["bytes"])
    xml=ET.fromstring(raw["candidate_xml"])
    suites=[xml] if xml.tag=="testsuite" else list(xml.findall("testsuite"))
    require(xml.tag in ("testsuite","testsuites") and bool(suites)
        and all(int(row.get("tests","0"))>0 and all(int(row.get(key,"0"))==0
            for key in ("failures","errors","skipped")) for row in suites))
    return validate_report(decode(raw["candidate_report"]),raw["candidate_registration"],
        raw["candidate_paths"],project,epoch)


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result)
        result[key]=value
    return result

def read_project(path,deadline):
    tick(deadline)
    # Exactly the four fixed Bazel location args; no metadata-driven path.
    with Path(path).resolve(strict=True).open("rb") as stream:
        before=os.fstat(stream.fileno());require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=2*1024**2)
        raw=stream.read(2*1024**2+1)
        require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            == tuple(getattr(os.fstat(stream.fileno()),name) for name in
                ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")))
    tick(deadline);return raw

def persist(directory,values,deadline):
    require(directory.is_absolute() and directory.resolve(strict=True)==directory and directory.is_dir())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        require(os.fstat(fd).st_uid==os.getuid())
        for name,raw in values.items():
            tick(deadline)
            require(name in ("query-registration.json","registration","store-paths") and 0<len(raw)<=MAX_OUTPUT)
            out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            with os.fdopen(out,"wb") as stream:
                stream.write(raw);stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        os.fsync(fd)
    finally:os.close(fd)
    tick(deadline)

def main(*, absolute_deadline=None):
    entry=float(time.monotonic())
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("flake","lock","zig-index","archives"):parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    require(bool(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")) and bool(os.environ.get("TEST_TIMEOUT")))
    deadline=float(entry+min(MAX_SECONDS,int(os.environ["TEST_TIMEOUT"])-5))
    if absolute_deadline is not None:
        require(type(absolute_deadline) is float and math.isfinite(absolute_deadline))
        deadline=min(deadline,absolute_deadline)
    tick(deadline)
    epoch=guard_epoch(os.environ.get("OMUX_EXECUTION_GUARD"))
    locations=dict(zip(PROJECT_FILES,(args.flake,args.lock,args.zig_index,args.archives)))
    project={name:read_project(path,deadline) for name,path in locations.items()}
    report,registration,paths=collect(project,deadline,epoch)
    require({name:read_project(path,deadline) for name,path in locations.items()}==project)
    require(validate_report(report,registration,paths,project,epoch) is not None)
    directory=Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    persist(directory,{"query-registration.json":encode(report),"registration":registration,"store-paths":paths},deadline)
    tick(deadline)
    print("provisional fixed query registration retained; NAR bytes and native/SDK unqualified")

if __name__=="__main__":
    try:main()
    except MissingRoots as failure:
        print(json.dumps({"passed":False,"reason":"missing-fixed-roots","roles":failure.roles},sort_keys=True),file=sys.stderr)
        raise SystemExit(1) from None
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,json.JSONDecodeError,sqlite3.Error):
        print('{"passed":false,"reason":"bounded-public-registration-unavailable"}',file=sys.stderr)
        raise SystemExit(1) from None
