"""Typed existing-vault namespace; original enrollment admission remains separate."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import socket
import struct
import time
import guard_resident_enrollment_profile as resident

LABEL = "//delivery:resident_vault_metadata"
UNLOCK_LABEL = "//delivery:resident_vault_unlock"
STANDARD_LABEL = "//delivery:resident_standard_vault_metadata"
STANDARD_UNLOCK_LABEL = "//delivery:resident_standard_vault_unlock"
LABELS = (LABEL,UNLOCK_LABEL,STANDARD_LABEL,STANDARD_UNLOCK_LABEL)
DESTINATION = resident.DESTINATION
VARIABLE = "OMUX_RESIDENT_VAULT_MANIFEST"
DEADLINE_VARIABLE = resident.DEADLINE_VARIABLE
PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT = resident.PROOF_MEMORY,resident.PROOF_TASKS,resident.PROOF_CPU_PERCENT
GNOME_EXE = "/nix/store/x1199bxd4ia75dd1nmh0xnnpfzxz1785-gnome-keyring-48.0/bin/.gnome-keyring-daemon-wrapped"
def require(value):
    if not value:
        raise ValueError("resident-vault-admission-refused")
def finite(arguments,manager,manifest,reuse,unrelated=()):
    require(arguments in tuple(["run",label] for label in LABELS) and manager=="system"
        and manifest is not None and not reuse and not any(unrelated))
    return {"PrivateNetwork":"yes","ProtectSystem":"strict","PrivateTmp":"yes"}
def rejection(error):
    return "resident-vault-admission-refused"
def projection(actual,verified=False):
    result=dict(actual)
    result["BindReadOnlyPaths"]="verified-vault-metadata-inputs" if verified else "vault-inputs-redacted"
    result["BindPaths"]="verified-owned-proof-output" if verified else "vault-output-redacted"
    return result
def identity(info):
    return tuple(getattr(info,key) for key in ("st_dev","st_ino","st_uid","st_gid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
def process(pid):
    ticks=resident.start_ticks(pid)
    exe=os.readlink("/proc/"+str(pid)+"/exe")
    require(re.fullmatch(r"/(?:nix/store|usr|run/wrappers/bin)/[A-Za-z0-9/+._-]{1,4000}",exe))
    require(resident.start_ticks(pid)==ticks)
    return {"uid":os.getuid(),"pid":pid,"start_ticks":ticks,"exe":exe}
def standard_process(pid):
    # Fixed v2 consumers use the authenticated local peer/service role.
    ticks=resident.start_ticks(pid)
    require(type(ticks) is int and ticks>0 and resident.start_ticks(pid)==ticks)
    return {"uid":os.getuid(),"pid":pid,"start_ticks":ticks}
def standard_observation(value):
    require(type(value) is dict and set(value)=={"schema","broker","manager","secret_service","provider",
        "default_collection","default_exists","locked","items_read","secrets_read","provider_invocation"}
        and value["schema"]=="omux-existing-vault-metadata-v2"
        and all(value[key] is False for key in ("items_read","secrets_read","provider_invocation")))
    for name in ("broker","manager","secret_service"):
        row=value[name]
        if row is None:
            require(name=="secret_service" and value["provider"]=="absent")
            continue
        require(type(row) is dict and set(row)==({"uid","pid","start_ticks"} if name=="broker"
            else {"uid","pid","start_ticks","owner"}))
        require(type(row["uid"]) is int and row["uid"]==os.getuid()
            and type(row["pid"]) is int and row["pid"]>1
            and type(row["start_ticks"]) is int and row["start_ticks"]>0)
        if name!="broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))
    require(value["provider"] in ("absent","standard-secret-service")
        and (value["provider"]=="absent")==(value["secret_service"] is None))
    if value["provider"]=="standard-secret-service":
        path=value["default_collection"]
        require(type(path) is str and len(path)<=4095
            and re.fullmatch(r"/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?",path))
        require(type(value["default_exists"]) is bool and value["default_exists"]==(path!="/")
            and (type(value["locked"]) is bool if value["default_exists"] else value["locked"] is None))
    else:
        require(value["default_collection"] is value["default_exists"] is value["locked"] is None)
    return value
def standard_unlockable(value):
    standard_observation(value)
    require(value["provider"]=="standard-secret-service" and value["default_exists"] is True
        and value["locked"] is True)
def standard_schema(value):
    require(type(value) is dict and set(value)=={"schema_version","purpose","permissions","mapping","expected"}
        and type(value["schema_version"]) is int and value["schema_version"]==2
        and value["purpose"] in ("observe-standard-vault","unlock-standard-vault"))
    permissions=value["permissions"]
    require(type(permissions) is dict and set(permissions)=={"metadata","unlock"}
        and permissions["metadata"] is True and type(permissions["unlock"]) is bool and value["mapping"] is None)
    if value["purpose"]=="observe-standard-vault":
        require(permissions["unlock"] is False and value["expected"] is None)
    else:
        require(permissions["unlock"] is True)
        standard_unlockable(value["expected"])
    return value
def expected_processes(expected):
    standard=expected["schema"]=="omux-existing-vault-metadata-v2"
    if standard:standard_observation(expected)
    else:validate_observation(expected)
    for name in ("broker","manager","secret_service"):
        row=expected[name]
        if row is not None:
            actual=standard_process(row["pid"]) if standard else process(row["pid"])
            require(actual=={key:item for key,item in row.items() if key!="owner"})
def validate_observation(value):
    require(type(value) is dict and set(value)=={"schema","broker","manager","secret_service","provider",
        "default_exists","default_is_login","locked","items_read","secrets_read","provider_invocation"}
        and value["schema"]=="omux-existing-vault-metadata-v1"
        and all(value[key] is False for key in ("items_read","secrets_read","provider_invocation")))
    for name in ("broker","manager","secret_service"):
        row=value[name]
        if row is None:
            require(name=="secret_service" and value["provider"]=="absent")
            continue
        require(type(row) is dict and set(row)==({"uid","pid","start_ticks","exe"} if name=="broker"
            else {"uid","pid","start_ticks","exe","owner"}))
        require(type(row["uid"]) is int and row["uid"]==os.getuid()
            and type(row["pid"]) is int and row["pid"]>1
            and type(row["start_ticks"]) is int and row["start_ticks"]>0
            and type(row["exe"]) is str and re.fullmatch(r"/(?:nix/store|usr|run/wrappers/bin)/[A-Za-z0-9/+._-]{1,4000}",row["exe"]))
        if name!="broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))
    require(value["provider"] in ("absent","gnome-keyring-48.0","unqualified-existing-provider")
        and (value["provider"]=="absent")== (value["secret_service"] is None))
    if value["provider"]=="gnome-keyring-48.0":
        require(value["secret_service"] is not None and value["secret_service"]["exe"]==GNOME_EXE
            and type(value["default_exists"]) is bool and type(value["default_is_login"]) is bool
            and (type(value["locked"]) is bool if value["default_exists"] else value["locked"] is None)
            and (not value["default_is_login"] or value["default_exists"]))
    else:
        require(value["default_exists"] is value["default_is_login"] is value["locked"] is None)
        require(value["provider"]=="absent" or value["secret_service"] is not None)
    return value
def unlockable(value):
    validate_observation(value)
    require(value["provider"]=="gnome-keyring-48.0" and value["default_exists"] is True
        and value["default_is_login"] is True and value["locked"] is True)
def schema(value):
    if type(value) is dict and value.get("schema_version")==2:
        return standard_schema(value)
    require(type(value) is dict and set(value)=={"schema_version","purpose","permissions","mapping","expected"}
        and type(value["schema_version"]) is int and value["schema_version"]==1
        and value["purpose"] in ("observe-default-vault","unlock-existing-login-vault"))
    permissions=value["permissions"]
    require(type(permissions) is dict and set(permissions)=={"metadata","unlock"}
        and permissions["metadata"] is True and type(permissions["unlock"]) is bool)
    if value["purpose"]=="observe-default-vault":
        require(permissions["unlock"] is False and value["mapping"] is None and value["expected"] is None)
    else:
        require(permissions["unlock"] is True)
        mapping=value["mapping"]
        require(type(mapping) is dict and set(mapping)=={"role","purpose","encoding","user_confirmed"}
            and mapping["user_confirmed"] is True
            and mapping=={"role":"become/password","purpose":"gnome-login-keyring-unlock",
                "encoding":"exact-bytes","user_confirmed":True})
        unlockable(value["expected"])
    return value
def compare_after(before,after):
    validate_observation(before);validate_observation(after)
    require(all(before[key]==after[key] for key in ("broker","manager","secret_service","provider","default_exists","default_is_login"))
        and after["locked"] is False)
    return True
def named_directory(path,witness,private=False):
    # Reopen every named canonical ancestor with O_NOFOLLOW, then compare held identity.
    descriptor=resident.open_directory(path,private=private)
    try:
        require(resident.stable(os.fstat(descriptor))==witness)
    finally:
        os.close(descriptor)
def socket_witness(path,deadline_ns):
    now=time.monotonic_ns();require(now<deadline_ns)
    before=path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid==os.getuid())
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(min(2,(deadline_ns-now)/10**9))
        peer.connect(str(path))
        pid,uid,gid=struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(uid==os.getuid() and pid>1)
        witness=(resident.stable(before),pid,resident.start_ticks(pid))
    require(time.monotonic_ns()<deadline_ns
        and resident.stable(before)==resident.stable(path.stat(follow_symlinks=False)))
    return witness
def generation_target(value,uid):
    require(type(value) is str and re.fullmatch(r"/run/user/"+str(uid)+r"/secrets[.]d/[1-9][0-9]{0,18}",value))
    return resident.canonical(value)
class Admission:
    def __init__(self,manifest,home,deadline_ns,label=None):
        self.deadline_ns=deadline_ns;self.held=[];self.created=[];self.parents=[];self.links=[];self.leaf=None
        self.manifest=resident.canonical(str(manifest));self.root=self.manifest.parent
        require(self.manifest.name=="input.json")
        try:
            self.directory=resident.open_directory(self.root,private=True);self.held.append(self.directory)
            require(os.listdir(self.directory)==["input.json"])
            self.file=os.open("input.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.directory)
            self.held.append(self.file);info=os.fstat(self.file)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink==1 and 0<info.st_size<=16384)
            self.file_identity=identity(info);self.raw=os.pread(self.file,16385,0)
            require(len(self.raw)==info.st_size)
            self.selected=schema(json.loads(self.raw,object_pairs_hook=resident.unique))
            require(label==({"observe-default-vault":LABEL,"unlock-existing-login-vault":UNLOCK_LABEL,
                "observe-standard-vault":STANDARD_LABEL,"unlock-standard-vault":STANDARD_UNLOCK_LABEL}[self.selected["purpose"]]))
            self.root_identity=resident.stable(os.fstat(self.directory))
            runtime=Path("/run/user")/str(os.getuid())
            runtime_fd=resident.open_directory(runtime,private=True);self.held.append(runtime_fd)
            self.parents.append((runtime,runtime_fd,resident.stable(os.fstat(runtime_fd))))
            self.sources={self.root/"bus":runtime/"bus"}
            self.socket_identities={runtime/"bus":socket_witness(runtime/"bus",self.deadline_ns)}
            if self.selected["purpose"]=="unlock-standard-vault":
                expected=self.selected["expected"];bus=self.socket_identities[runtime/"bus"]
                require(bus[1]==expected["broker"]["pid"] and bus[2]==expected["broker"]["start_ticks"])
                expected_processes(expected)
            if self.selected["purpose"]=="unlock-existing-login-vault":
                expected=self.selected["expected"]
                bus=self.socket_identities[runtime/"bus"]
                require(bus[1]==expected["broker"]["pid"] and bus[2]==expected["broker"]["start_ticks"])
                for name in ("broker","manager","secret_service"):
                    require(process(expected[name]["pid"])=={key:value for key,value in expected[name].items() if key!="owner"})
                control=runtime/"keyring"/"control"
                keyring=resident.open_directory(control.parent,private=True);self.held.append(keyring)
                self.parents.append((control.parent,keyring,resident.stable(os.fstat(keyring))))
                witness=socket_witness(control,self.deadline_ns)
                require(witness[1]==expected["secret_service"]["pid"] and witness[2]==expected["secret_service"]["start_ticks"])
                self.sources[self.root/"control"]=control;self.socket_identities[control]=witness
                # Mapping and independently selected public provider witness have passed.
                # Hold only metadata here. The declared carrier preflights current alias/Locked before content IO.
                sops_parent=Path(home)/".config/sops-nix"
                sops_fd=resident.open_directory(sops_parent);self.held.append(sops_fd)
                self.parents.append((sops_parent,sops_fd,resident.stable(os.fstat(sops_fd))))
                projected=os.stat("secrets",dir_fd=sops_fd,follow_symlinks=False)
                require(projected.st_uid==os.getuid())
                if stat.S_ISLNK(projected.st_mode):
                    require(projected.st_nlink==1)
                    target=os.readlink("secrets",dir_fd=sops_fd)
                    secret_root=generation_target(target,os.getuid())
                    self.links.append((sops_fd,identity(projected),target))
                else:
                    require(stat.S_ISDIR(projected.st_mode) and not projected.st_mode&0o022)
                    secret_root=sops_parent/"secrets"
                # One owned generation projection. The held0700 runtime ancestor
                # protects the physical generation from other users.
                for parent in (secret_root.parent,secret_root,secret_root/"become"):
                    parent_fd=resident.open_directory(parent);self.held.append(parent_fd)
                    require(os.fstat(parent_fd).st_uid==os.getuid())
                    self.parents.append((parent,parent_fd,resident.stable(os.fstat(parent_fd))))
                leaf=secret_root/"become/password";self.factor_path=leaf
                factor_parent=parent_fd
                self.leaf=os.open(leaf.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=factor_parent)
                self.held.append(self.leaf);factor=os.fstat(self.leaf)
                require(stat.S_ISREG(factor.st_mode) and factor.st_uid==os.getuid()
                    and stat.S_IMODE(factor.st_mode) in (0o400,0o600) and factor.st_nlink==1 and 1<=factor.st_size<=4096)
                self.factor_identity=identity(factor)
                self.sources[self.root/"factor"]=Path("/proc")/str(os.getpid())/"fd"/str(self.leaf)
            for path in self.sources:
                placeholder=resident.regular_mountpoint(path)
                self.created.append((placeholder,path,resident.stable(os.fstat(placeholder.fileno()))))
            self.facts=self.recheck()
        except BaseException:
            self.close();raise
    def recheck(self):
        require(time.monotonic_ns()<self.deadline_ns and resident.stable(os.fstat(self.directory))==self.root_identity
            ==resident.stable(self.root.stat(follow_symlinks=False)))
        named_directory(self.root,self.root_identity,private=True)
        require(set(os.listdir(self.directory))=={"input.json"}|{path.name for path in self.sources})
        require(identity(os.fstat(self.file))==self.file_identity==identity(os.stat("input.json",dir_fd=self.directory,follow_symlinks=False))
            and os.pread(self.file,16385,0)==self.raw)
        for path,fd,witness in self.parents:
            require(resident.stable(os.fstat(fd))==witness)
            named_directory(path,witness)
        for parent,witness,target in self.links:
            require(identity(os.stat("secrets",dir_fd=parent,follow_symlinks=False))==witness
                and os.readlink("secrets",dir_fd=parent)==target)
        for path,witness in self.socket_identities.items():
            require(socket_witness(path,self.deadline_ns)==witness)
        for placeholder,path,witness in self.created:
            require(resident.regular_mountpoint_witness(path,placeholder.fileno())==witness)
        if self.selected["purpose"]=="unlock-standard-vault":
            expected_processes(self.selected["expected"])
        if self.leaf is not None:
            require(identity(os.fstat(self.leaf))==self.factor_identity==identity(self.factor_path.stat(follow_symlinks=False)))
            for name in ("broker","manager","secret_service"):
                row=self.selected["expected"][name]
                require(process(row["pid"])=={key:value for key,value in row.items() if key!="owner"})
        return {"scope":"existing-vault-metadata-or-authorized-unlock","purpose":self.selected["purpose"],
            "factor_contents_read_by_guard":False,"provider_invocation":False,
            "workload_memory":PROOF_MEMORY,"workload_tasks":PROOF_TASKS,
            "workload_cpu_percent":PROOF_CPU_PERCENT,"resident_reservation_qualified":False}
    def bindings(self):
        return list(getattr(self,"offline_repository_bindings",()))+[str(self.root)+":"+DESTINATION]+[str(source)+":"+DESTINATION+"/"+target.name+":norbind"
            for target,source in self.sources.items()]
    def writable_binding(self):
        return ""
    def verify_bindings(self,actual,run=None):
        leaves=[str(source)+":"+DESTINATION+"/"+target.name for target,source in self.sources.items()]
        expected_ro=resident.normalize_binds(" ".join(self.bindings()),leaves)
        expected_rw=[] if run is None else [str(run)+":"+str(run)]
        ro=resident.normalize_binds(actual.get("BindReadOnlyPaths",""),leaves,readback=True)
        rw=resident.normalize_binds(actual.get("BindPaths",""),readback=True)
        require(len(ro)==len(expected_ro) and set(ro)==set(expected_ro) and len(rw)==len(expected_rw) and set(rw)==set(expected_rw))
    def service_observation(self,systemctl,starting=False):
        return {"service_action":False,"datastore_read":False,"wrapping_key_replacement":False,"purpose":self.selected["purpose"]}
    def environment(self):
        info=os.fstat(self.directory)
        return {VARIABLE:DESTINATION+"/input.json",DEADLINE_VARIABLE:str(self.deadline_ns),
            "OMUX_RESIDENT_NAMESPACE_ID":str(info.st_dev)+":"+str(info.st_ino),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path="+DESTINATION+"/bus","XDG_RUNTIME_DIR":DESTINATION}
    def runtime_seconds(self):
        remaining=(self.deadline_ns-time.monotonic_ns())//10**9-30
        require(0<remaining<=1200);return int(remaining)
    def close(self):
        for placeholder,path,witness in reversed(self.created):
            placeholder.close()
            if path.exists() and resident.stable(path.stat(follow_symlinks=False))==witness: path.unlink()
        self.created=[]
        for fd in reversed(self.held):os.close(fd)
        self.held=[]
