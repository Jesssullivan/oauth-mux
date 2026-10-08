"""Read-only installed resident witnesses; no installer/enrollment dispatcher."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import time

DEADLINE_VARIABLE = "OMUX_RESIDENT_ORIGINAL_DEADLINE_NS"
RESIDENT_MEMORY, RESIDENT_TASKS, RESIDENT_CPU_PERCENT = 268435456, 32, 10
PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT = 4294967296-RESIDENT_MEMORY, 512-RESIDENT_TASKS, 200-RESIDENT_CPU_PERCENT
PUBLIC_ROOTS = (Path('/home/jess/.local/state/omux-execution-20261005'),
    Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'))

def require(value):
    if not value:
        raise ValueError("resident-observation-refused")

def canonical(value):
    require(type(value) is str and value.startswith("/") and len(value)<=4096
        and not any(c.isspace() or c in ":\\\0" for c in value)
        and not any(p in ("",".","..") for p in value.split("/")[1:]))
    return Path(value)

def unique(pairs):
    value = {}
    for key,item in pairs:
        require(key not in value)
        value[key] = item
    return value

def stable(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid

def file_identity(info):
    return tuple(getattr(info,k) for k in ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))

def open_directory(path,private=False):
    path = canonical(str(path))
    fd = os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode&0o022)
        info = os.fstat(fd)
        require(not private or info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise

def runtime_child(state):
    state = canonical(str(state))
    return "omux-"+hashlib.sha256(str(state).encode()).digest()[:16].hex()

def fixed_paths(home,instance="default"):
    require(instance=="default")
    home=canonical(str(home)); prefix=home/".local/share/omux"
    return {"prefix":prefix,"records":home/".local/state/omux-install",
        "runtime_state":home/".local/state/omux","service_path":prefix/"units/ai.xoxd.omux.service"}

def start_ticks(pid):
    require(type(pid) is int and pid>1)
    proc=Path("/proc")/str(pid)
    require(proc.stat().st_uid==os.getuid())
    fd=os.open(proc/"stat",os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        raw=os.read(fd,8193)
        require(0<len(raw)<=8192 and not os.read(fd,1))
    finally:
        os.close(fd)
    require(raw.startswith(str(pid).encode()+b" (") and b") " in raw)
    fields=raw[raw.rfind(b") ")+2:].split()
    require(len(fields)>19 and fields[19].isdigit())
    return int(fields[19])

def regular_mountpoint(path):
    fd=os.open(path,os.O_RDONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        return os.fdopen(fd,"rb")
    except BaseException:
        os.close(fd)
        raise

def regular_mountpoint_witness(path,descriptor):
    info=os.fstat(descriptor)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
        and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size==0
        and stable(info)==stable(path.stat(follow_symlinks=False)))
    return stable(info)

def held_mountpoint(path):
    placeholder=regular_mountpoint(path)
    try: return path,placeholder,regular_mountpoint_witness(path,placeholder.fileno())
    except BaseException:
        placeholder.close()
        raise

def normalize_binds(value,leaf_bindings=(),*,readback=False):
    result=[]; leaves=set(leaf_bindings)
    for item in value.split():
        parts=item.split(":"); option=parts.pop() if len(parts)==3 else None
        require(len(parts)==2)
        binding=":".join(parts)
        require((option is None if binding in leaves else option=="rbind") if readback
            else (option=="norbind" if binding in leaves else option in (None,"rbind")))
        result.append(binding)
    return result

def projection(actual,verified=False):
    value=dict(actual)
    value["BindReadOnlyPaths"]="verified-resident-inputs" if verified else "resident-inputs-redacted"
    value["BindPaths"]="verified-owned-proof-writes" if verified else "resident-proof-writes-redacted"
    return value

def rejection(error):
    return "resident-observation-refused"

def validate_session_observation(value,allow_missing=False):
    require(type(allow_missing) is bool and type(value) is dict and set(value)=={'schema_version','broker','manager','secret_service'}
        and type(value['schema_version']) is int and value['schema_version']==1)
    for key in ('broker','manager','secret_service'):
        row=value[key]
        if key=='secret_service' and row is None:
            require(allow_missing); continue
        require(type(row) is dict and set(row)==({'pid','uid','start_ticks'} if key=='broker' else {'owner','pid','uid','start_ticks'})
            and type(row['pid']) is int and row['pid']>1 and type(row['uid']) is int and row['uid']==os.getuid()
            and type(row['start_ticks']) is int and row['start_ticks']>0)
        if key!='broker': require(type(row['owner']) is str and re.fullmatch(r':[0-9]+[.][0-9]+',row['owner']))
    return value

def quota_us(value):
    from decimal import Decimal
    require(type(value) is str and re.fullmatch(r"[0-9]{1,7}(?:[.][0-9]{1,6})?(?:us|ms|s)",value))
    unit="us" if value.endswith("us") else "ms" if value.endswith("ms") else "s"
    amount=Decimal(value[:-len(unit)])*{"us":1,"ms":1000,"s":1000000}[unit]
    require(amount==int(amount) and 0<amount<=100000)
    return int(amount)

def check_resident_bounds(properties,readback):
    memory,tasks=str(properties.get("MemoryMax")),str(properties.get("TasksMax"))
    require(memory.isdecimal() and tasks.isdecimal() and 0<int(memory)<=RESIDENT_MEMORY
        and 0<int(tasks)<=RESIDENT_TASKS and properties.get("MemorySwapMax")=="0")
    cpu=quota_us(properties.get("CPUQuotaPerSecUSec"))
    require(readback["memory.max"]==memory and readback["memory.swap.max"]=="0" and readback["pids.max"]==tasks)
    fields=readback["cpu.max"].split()
    require(len(fields)==2 and all(v.isdecimal() for v in fields))
    quota,period=map(int,fields)
    require(0<quota and 0<period and quota*1000000<=cpu*period)
    return True

class OwnedUnitCustody:
    """Actual record/unit and mandatory same-target enabled alias, no runtime DB."""
    def __init__(self,selected):
        self.selected=selected; self.held=[]; self.files=[]; self.alias=None
        try:
            prefix,records,unit=(canonical(selected[k]) for k in ("prefix","records","service_path"))
            require(selected["ownership"]=="omux-installation")
            for path,limit in ((records/"install.json",131072),(unit,65536)):
                parent=open_directory(path.parent); self.held.append(parent)
                require(os.fstat(parent).st_uid==os.getuid())
                fd=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                self.held.append(fd); info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=limit)
                raw=os.pread(fd,limit+1,0); require(len(raw)==info.st_size)
                self.files.append((path,parent,fd,file_identity(info),raw,stable(os.fstat(parent))))
            record=json.loads(self.files[0][4],object_pairs_hook=unique)
            require(type(record) is dict and set(record)=={"schemaVersion","prefix","product","userService","serviceActivated","artifact","files"}
                and type(record["schemaVersion"]) is int and record["schemaVersion"]==1
                and record["prefix"]==str(prefix) and record["userService"]==str(unit)
                and type(record["serviceActivated"]) is bool)
            require(type(record["files"]) is list and 0<len(record["files"])<=256)
            seen=set(); unit_row=None
            for row in record["files"]:
                require(type(row) is dict and set(row)=={"path","sha256","mode"}
                    and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"])
                    and type(row["mode"]) is int and row["mode"] in (0o600,0o644,0o755))
                path=canonical(row["path"]); require(path not in seen); seen.add(path)
                relative=str(path.relative_to(prefix)) if prefix in path.parents else ""
                require(path==unit or relative in ("bin/omux","bin/omuxd","bin/oauth-mux","bin/omux-native-host","bin/git-credential-omux","bin/omux-control")
                    or re.fullmatch(r"lib/omux/(?:lib/[A-Za-z0-9_.+-]+|libexec/omuxd?\.bin|share/ca-bundle\.crt|qt/lib/[A-Za-z0-9_.+-]+|qt/libexec/(?:omux-control\.bin|qt\.conf)|qt/plugins/platforms/[A-Za-z0-9_.+-]+\.so)",relative))
                if path==unit: unit_row=row
            require(unit_row is not None and unit_row["mode"]==0o600
                and hashlib.sha256(self.files[1][4]).hexdigest()==unit_row["sha256"])
            self.verify_fragment(prefix.parents[2]/".config/systemd/user"/unit.name)
            self.recheck()
        except BaseException:
            self.close(); raise

    def verify_fragment(self,fragment):
        selected=canonical(self.selected["service_path"])
        alias=selected.parents[4]/".config/systemd/user"/selected.name
        fragment=canonical(str(fragment)); require(fragment in (selected,alias))
        if fragment==alias:
            parent=open_directory(alias.parent)
            try:
                info=os.stat(alias.name,dir_fd=parent,follow_symlinks=False)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                    and os.readlink(alias.name,dir_fd=parent)==str(selected))
                witness=file_identity(info)
                if self.alias is None:
                    self.alias=(alias,parent,witness,stable(os.fstat(parent))); self.held.append(parent); parent=None
                else: require(self.alias[0]==alias and self.alias[2]==witness)
            finally:
                if parent is not None: os.close(parent)
        self.recheck()
        return selected

    def recheck(self):
        for path,parent,fd,witness,raw,parent_witness in self.files:
            current=open_directory(path.parent)
            try: require(stable(os.fstat(parent))==parent_witness==stable(os.fstat(current)))
            finally: os.close(current)
            require(file_identity(os.fstat(fd))==witness==file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))
                and os.pread(fd,len(raw)+1,0)==raw)
        if self.alias is not None:
            path,parent,witness,parent_witness=self.alias; current=open_directory(path.parent)
            try: require(stable(os.fstat(parent))==parent_witness==stable(os.fstat(current)))
            finally: os.close(current)
            require(file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==witness
                and os.readlink(path.name,dir_fd=parent)==self.selected["service_path"])

    def close(self):
        for fd in reversed(self.held): os.close(fd)
        self.held=[]

class Admission:
    """Private observation adapter only; never a profile admission/dispatcher."""
    def runtime_seconds(self):
        require(time.monotonic_ns()+30*10**9<self.deadline_ns)
        return max(1,(self.deadline_ns-time.monotonic_ns()-30*10**9)//10**9)

    def service_observation(self,systemctl):
        remaining=min(15,(self.deadline_ns-time.monotonic_ns())/10**9); require(remaining>0)
        env={"HOME":pwd.getpwuid(os.getuid()).pw_dir,"LC_ALL":"C","XDG_RUNTIME_DIR":"/run/user/"+str(os.getuid()),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/"+str(os.getuid())+"/bus"}
        keys={"LoadState","ActiveState","SubState","MainPID","FragmentPath","ControlGroup","MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec","UnitFileState","DropInPaths","NeedDaemonReload"}
        result=subprocess.run([str(systemctl),"--user","show","--property="+",".join(sorted(keys)),"ai.xoxd.omux.service"],
            env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining,check=False)
        require(time.monotonic_ns()<self.deadline_ns and result.returncode==0 and not result.stderr and len(result.stdout)<=16384)
        values=unique(line.split("=",1) for line in result.stdout.decode("ascii").splitlines())
        require(set(values)==keys and values["LoadState"]=="loaded" and values["ActiveState"]=="active"
            and values["SubState"]=="running" and values["MainPID"].isdecimal()
            and values["UnitFileState"]=="enabled" and values["DropInPaths"]=="" and values["NeedDaemonReload"]=="no")
        self.owned_unit.verify_fragment(values["FragmentPath"])
        pid=int(values["MainPID"]); ticks=start_ticks(pid); group=values["ControlGroup"]
        require(group.startswith("/") and ".." not in Path(group).parts and Path(group).name=="ai.xoxd.omux.service")
        cgroup=Path("/sys/fs/cgroup")/group.lstrip("/"); fd=open_directory(cgroup)
        try:
            witness=stable(os.fstat(fd)); readback={}
            for key in ("memory.max","memory.swap.max","pids.max","cpu.max","cgroup.procs"):
                require(time.monotonic_ns()<self.deadline_ns)
                child=os.open(key,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    raw=os.read(child,16385); require(len(raw)<=16384 and not os.read(child,1)); readback[key]=raw.decode("ascii").strip()
                finally: os.close(child)
            check_resident_bounds(values,readback)
            require(str(pid) in readback["cgroup.procs"].split() and stable(os.fstat(fd))==witness==stable(cgroup.stat(follow_symlinks=False)) and start_ticks(pid)==ticks)
            self.observed_process=(pid,ticks)
            self.observed_bounds=(values["MemoryMax"],values["MemorySwapMax"],values["TasksMax"],quota_us(values["CPUQuotaPerSecUSec"]),readback["cpu.max"],witness)
        finally: os.close(fd)
        require(time.monotonic_ns()<self.deadline_ns)
        return {"active":True,"intentionally_retained":True,"bounded":True}

def installation_selection(value):
    import uuid
    require(type(value) is dict and set(value)=={"archive","manifest_sha256","qualification","source_commit","graph_sha256"})
    for key in ("manifest_sha256","graph_sha256"):
        require(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}",value[key]))
    require(type(value["source_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}",value["source_commit"]))
    for role,maximum in (("archive",256*1024*1024),("qualification",1024*1024)):
        pin=value[role]
        require(type(pin) is dict and set(pin)=={"path","sha256","bytes"}
            and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",pin["sha256"])
            and type(pin["bytes"]) is int and 0<pin["bytes"]<=maximum)
        canonical(pin["path"])
    receipt=Path(value["qualification"]["path"])
    require(receipt.parent.parent in PUBLIC_ROOTS and receipt.name=="receipt.json"
        and str(uuid.UUID(receipt.parent.name))==receipt.parent.name)
    archive=Path(value["archive"]["path"])
    suffix="execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz"
    require(str(archive).endswith('/'+suffix))
    base=Path(str(archive)[:-len(suffix)-1])
    require(base.name=="output-base" and base.parent.parent in PUBLIC_ROOTS)
    epoch=base.parent.name
    require(re.fullmatch(r"cache-v2-[0-9a-f]{64}",epoch) or str(uuid.UUID(epoch))==epoch)
    return value

class PinnedMetadata:
    def __init__(self,pin,deadline):
        self.path=canonical(pin['path']); self.deadline=deadline; self.parent=self.fd=None
        try:
            require(time.monotonic_ns()<deadline)
            self.parent=open_directory(self.path.parent); self.parent_id=stable(os.fstat(self.parent))
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            info=os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                and not info.st_mode&0o022 and info.st_size==pin['bytes'])
            self.identity=file_identity(info); chunks=[]; count=0; measured=hashlib.sha256()
            while count<info.st_size:
                require(time.monotonic_ns()<deadline)
                raw=os.read(self.fd,min(1024*1024,info.st_size-count)); require(raw)
                chunks.append(raw); count+=len(raw); measured.update(raw)
            require(not os.read(self.fd,1) and measured.hexdigest()==pin['sha256'])
            self.raw=b''.join(chunks); self.recheck()
        except BaseException:
            self.close(); raise
    def recheck(self):
        require(time.monotonic_ns()<self.deadline)
        current=open_directory(self.path.parent)
        try: require(stable(os.fstat(current))==self.parent_id==stable(os.fstat(self.parent)))
        finally: os.close(current)
        require(file_identity(os.fstat(self.fd))==self.identity==file_identity(os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)))
    def close(self):
        for key in ('fd','parent'):
            fd=getattr(self,key,None)
            if fd is not None: os.close(fd); setattr(self,key,None)

def rendered_installation(manifest,files,selected):
    """Same existing owned-resident placement; no filesystem mutation."""
    prefix=canonical(selected['prefix']); unit=canonical(selected['service_path'])
    modes={row['path']:int(row['mode'],8) for row in manifest['artifacts']}
    plan={str(prefix/name):{'sha256':hashlib.sha256(raw).hexdigest(),'mode':modes[name]}
        for name,raw in files.items() if name.startswith('bin/') or name.startswith('lib/omux/')}
    executable=str(prefix/'bin/omuxd').replace('%','%%').replace('$','$$').replace('\\','\\\\').replace('"','\\"')
    state=str(selected['runtime_state']).replace('%','%%').replace('$','$$').replace('\\','\\\\').replace('"','\\"')
    text=files['share/omux/services/omux.service.in'].decode().replace('@EXEC@','"'+executable+'" --state-dir "'+state+'"')
    text+='\n[Service]\nMemoryMax=268435456\nMemorySwapMax=0\nTasksMax=32\nCPUQuota=10%\n'
    runtime='/run/user/'+str(os.getuid())
    bindings={'OMUX_INSTALL_PREFIX':str(prefix),'OMUX_INSTALL_RECORD':str(Path(selected['records'])/'install.json'),
        'OMUX_INSTALL_SERVICE_PATH':str(unit),'DBUS_SESSION_BUS_ADDRESS':'unix:path='+runtime+'/bus',
        'XDG_RUNTIME_DIR':runtime,'OMUX_INSTANCE':'default'}
    for key,value in bindings.items():
        value=value.replace('%','%%').replace('\\','\\\\').replace('"','\\"')
        text+='Environment="'+key+'='+value+'"\n'
    plan[str(unit)]={'sha256':hashlib.sha256(text.encode()).hexdigest(),'mode':0o600}
    return plan

class InstallationWitness:
    def __init__(self,selected,unit,deadline):
        self.resources=[]
        try:
            pins=installation_selection(selected['installation'])
            receipt=PinnedMetadata(pins['qualification'],deadline); self.resources.append(receipt)
            q=json.loads(receipt.raw,object_pairs_hook=unique)
            qualification(q,pins)
            require(pins['archive']['sha256']==selected['archive_sha256'])
            archive=PinnedMetadata(pins['archive'],deadline); self.resources.append(archive)
            # Exact declared sibling sources; locked launcher rules declare portable template.
            sys.path.insert(0,str(Path(__file__).parent.parent/'delivery'))
            import pack
            manifest,files=pack.verify_bundle(archive.raw)
            require(time.monotonic_ns()<deadline and manifest['target']=='x86_64-linux' and manifest['channel']=='release'
                and manifest['distribution']=='portable-linux' and manifest['provenance']=={'sourceRevision':None,'sourceDirty':True}
                and hashlib.sha256(files['release-manifest.json']).hexdigest()==pins['manifest_sha256'])
            record=json.loads(unit.files[0][4],object_pairs_hook=unique)
            artifact={'channel':manifest['channel'],'target':manifest['target'],'distribution':manifest['distribution'],
                'provenance':manifest['provenance'],'archiveSha256':pins['archive']['sha256'],'manifestSha256':pins['manifest_sha256']}
            require(record['product']==manifest['product'] and record['artifact']==artifact
                and {r['path']:{'sha256':r['sha256'],'mode':r['mode']} for r in record['files']}==rendered_installation(manifest,files,selected))
            self.recheck()
        except BaseException:
            self.close(); raise
    def recheck(self):
        for resource in self.resources: resource.recheck()
    def close(self):
        for resource in reversed(self.resources): resource.close()
        self.resources=[]

def qualification(q,pins):
    """Producer's actual canonical string and cache-pointer schema, before archive IO."""
    pins=installation_selection(pins)
    epoch=Path(pins['qualification']['path']).parent.name
    require(q['id']==epoch and q['artifact_epoch']==epoch and q['profile']=='standard' and q['verb']=='build'
        and q['targets']==['//delivery:default_instance_archive'] and type(q['exit']) is int and q['exit']==0
        and type(q['workload_exit']) is int and q['workload_exit']==0 and q['descendants_empty'] is True
        and q['cleanup']['state']=='empty' and q['controller_failure'] is None and q['source_dirty']=='false'
        and q['source_commit']==pins['source_commit'] and q['graph_sha256']==pins['graph_sha256'])
    root=Path(pins['qualification']['path']).parent.parent
    if q['cache_reuse_requested'] is True:
        require(type(q['cache_policy']) is int and q['cache_policy']==2 and type(q['cache_key']) is str and re.fullmatch(r'[0-9a-f]{64}',q['cache_key']))
        base=root/('cache-v2-'+q['cache_key'])/'output-base'
    else:
        require(q['cache_reuse_requested'] is False and q['cache_policy'] is None and q['cache_key'] is None)
        base=root/epoch/'output-base'
    require(q['output_base']==str(base) and pins['archive']['path']==str(base/'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz'))
    return base

def collection_deadline(observer,resources,original_deadline):
    """Called only by the guard's successful empty-descendant collection branch."""
    require(type(original_deadline) is int and time.monotonic_ns()<original_deadline)
    observer.deadline=original_deadline
    for resource in tuple(resources)+tuple(observer.installation.resources):
        if type(resource) is PinnedMetadata:
            require(resource.deadline==original_deadline-30*10**9)
            resource.deadline=original_deadline
