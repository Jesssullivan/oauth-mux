"""One provider-free existing-vault metadata RUN or user-mapped normal OS unlock."""
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_vault_profile as vault
import guard_resident_enrollment_profile as resident
OBSERVER_PREDICATES = frozenset((
    "observer-arguments","observer-deadline","observer-bus-connect","observer-broker-identity",
    "observer-manager-owner","observer-manager-identity","observer-secret-owner","observer-secret-identity",
    "observer-secret-absence","observer-default-alias","observer-collection-locked",
    "observer-owner-stability","observer-alias-stability"))
PHASES = frozenset(("arguments","deadline","private-input","before-observation","unlock",
    "after-observation","observation-stability","metadata-output"))
PHASE = "arguments"
class ClosedRefusal(ValueError):
    def __init__(self,predicate):
        self.predicate = predicate if predicate in OBSERVER_PREDICATES | {"observer-exit"} else "carrier-gate"
        super().__init__("resident-vault-action-refused")
def refusal_projection(error):
    # Never stringify an exception or reflect observer output/paths into logs.
    return {"status":"resident-vault-action-refused","secret_output":False,"provider_invocation":False,
        "phase":PHASE if PHASE in PHASES else "arguments",
        "predicate":error.predicate if isinstance(error,ClosedRefusal)
            and error.predicate in OBSERVER_PREDICATES | {"observer-exit"} else "carrier-gate"}
def observer_refusal(answer):
    predicate = "observer-exit"
    if answer.returncode == 125 and 0 < len(answer.stdout) <= 16384:
        try:
            value=json.loads(answer.stdout,object_pairs_hook=resident.unique)
            if (type(value) is dict and set(value)=={"schema","predicate"}
                    and value["schema"]=="omux-vault-observer-refusal-v1"
                    and type(value["predicate"]) is str and value["predicate"] in OBSERVER_PREDICATES):
                predicate=value["predicate"]
        except (ValueError,KeyError,TypeError):
            pass
    raise ClosedRefusal(predicate)
def require(value):
    if not value:raise ValueError("resident-vault-action-refused")
def deadline(environment):
    raw=environment.get(vault.DEADLINE_VARIABLE,"")
    require(re.fullmatch(r"[0-9]{1,20}",raw) is not None)
    value=int(raw);now=time.monotonic_ns()
    require(now<value<=now+1200*10**9)
    action=value-30*10**9
    require(now<action);return action
def budget(until,ceiling=20):
    left=(until-time.monotonic_ns())/10**9
    require(left>0);return min(ceiling,left)
def private_manifest():
    require(os.environ.get(vault.VARIABLE)==resident.DESTINATION+"/input.json")
    root=resident.open_directory(Path(resident.DESTINATION),private=True)
    try:
        info=os.fstat(root)
        require(os.environ.get("OMUX_RESIDENT_NAMESPACE_ID")==str(info.st_dev)+":"+str(info.st_ino))
        fd=os.open("input.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=root)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
                and stat.S_IMODE(before.st_mode) in (0o400,0o600) and before.st_nlink==1 and 0<before.st_size<=16384)
            raw=os.pread(fd,16385,0)
            require(len(raw)==before.st_size and vault.identity(before)==vault.identity(os.fstat(fd))
                ==vault.identity(os.stat("input.json",dir_fd=root,follow_symlinks=False)))
            return vault.schema(json.loads(raw,object_pairs_hook=resident.unique))
        finally:os.close(fd)
    finally:os.close(root)
def observe(observer,until):
    environment={"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus",
        vault.DEADLINE_VARIABLE:str(until),"LC_ALL":"C"}
    answer=subprocess.run([observer],env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=budget(until),check=False)
    if answer.returncode!=0:
        observer_refusal(answer)
    require(0<len(answer.stdout)<=16384)
    value=vault.validate_observation(json.loads(answer.stdout,object_pairs_hook=resident.unique))
    for name in ("broker","manager","secret_service"):
        row=value[name]
        if row is not None:
            require(vault.process(row["pid"])=={key:item for key,item in row.items() if key!="owner"})
    return value
def retain(value):
    marker=os.environ.get("OMUX_EXECUTION_GUARD","")
    require(re.fullmatch(r"/(?:srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|home/jess/.local/state/omux-execution-20261005)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",marker) is not None)
    run=resident.open_directory(Path(marker),private=True)
    try:
        fd=os.open("resident-vault-metadata.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=run)
        with os.fdopen(fd,"w") as output:
            output.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
            output.flush();os.fsync(output.fileno())
        os.fsync(run)
    finally:os.close(run)
def unlock(before,selected,client,until):
    vault.unlockable(before)
    require(before==selected["expected"] and selected["mapping"]["user_confirmed"] is True)
    # All current provider/default-alias/Locked witnesses precede factor content IO.
    control=Path(resident.DESTINATION)/"control"
    initial=control.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(initial.st_mode) and initial.st_uid==os.getuid())
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(budget(until,5));channel.connect(str(control))
        pid,uid,gid=struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        row=before["secret_service"]
        require(uid==os.getuid() and pid==row["pid"]
            and vault.process(pid)=={key:item for key,item in row.items() if key!="owner"}
            and resident.stable(initial)==resident.stable(control.stat(follow_symlinks=False)))
        factor=os.open(Path(resident.DESTINATION)/"factor",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(factor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink==1 and 1<=info.st_size<=4096)
            environment={vault.DEADLINE_VARIABLE:str(until),"OMUX_VAULT_HELD_CONTROL_FD":str(channel.fileno()),
                "OMUX_VAULT_EXPECTED_PID":str(pid),"LC_ALL":"C"}
            # Only this declared child reads the held factor, into mlocked zeroizable C storage.
            answer=subprocess.run([client,"--existing-unlock-stdin"],env=environment,stdin=factor,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(channel.fileno(),),
                timeout=budget(until),check=False)
            require(answer.returncode==0 and vault.identity(info)==vault.identity(os.fstat(factor))
                and vault.process(pid)=={key:item for key,item in row.items() if key!="owner"}
                and resident.stable(initial)==resident.stable(control.stat(follow_symlinks=False)))
        finally:os.close(factor)
def main(argv=None):
    global PHASE
    PHASE="arguments"
    arguments=sys.argv[1:] if argv is None else argv
    require(len(arguments)==3 and arguments[0] in ("observe","unlock"))
    action,observer,client=arguments
    PHASE="deadline"
    until=deadline(os.environ)
    PHASE="private-input"
    selected=private_manifest()
    require(selected["purpose"]=={"observe":"observe-default-vault","unlock":"unlock-existing-login-vault"}[action])
    PHASE="before-observation"
    before=observe(observer,until)
    if action=="unlock":
        PHASE="unlock"
        unlock(before,selected,client,until)
        PHASE="after-observation"
        after=observe(observer,until)
        PHASE="observation-stability"
        vault.compare_after(before,after)
    else:
        PHASE="after-observation"
        after=observe(observer,until)
        PHASE="observation-stability"
        require(before==after)
    output={"schema":"omux-resident-vault-action-v1","purpose":selected["purpose"],"observation":after,
        "unlock_dispatched":action=="unlock","unchanged_service_owner":True,
        "factor_contents_read_by_controller":False,"provider_invocation":False,
        "omux_datastore_access":False,"omux_wrapping_key_regeneration":False,
        "atomic_existing_collection_only":False,
        "gnome_server_unlock_may_initialize_token_pins":action=="unlock",
        "normal_os_unlock_passed":action=="unlock","native_support":False}
    PHASE="metadata-output"
    retain(output)
    print(json.dumps({"status":"metadata-observed" if action=="observe" else "normal-os-unlock-observed",
        "provider":after["provider"],"default_exists":after["default_exists"],
        "default_is_login":after["default_is_login"],"locked":after["locked"],
        "provider_invocation":False},sort_keys=True))
    return 0
if __name__=="__main__":
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
        print(json.dumps(refusal_projection(error),sort_keys=True))
        sys.exit(125)
