"""Finite retained009 component packaging/installation. No executable/provider RPC."""
import fcntl
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))
import guard_codex_login_profile as device

BACKEND = device.BACKEND_SHA
PRODUCER = '//delivery:codex_device_acquisition_component'
INSTALLER = '//delivery:codex_device_acquisition_install'
DEVICE = '//tools:codex_retained_device_api_qualification'
SCOPE = 'omux-codex-device-acquisition-component-v1'
SELECTION = 'omux-codex-device-acquisition-selection-v1'
RECORD = 'omux-codex-device-acquisition-install-v1'
INPUT = 'omux-codex-device-component-input-v1'
DESTINATION = '/omux-codex-component/input.json'
VARIABLE = 'OMUX_CODEX_COMPONENT_INPUT'
DEADLINE = 'OMUX_CODEX_COMPONENT_ORIGINAL_DEADLINE_NS'
NSID = 'OMUX_CODEX_COMPONENT_NAMESPACE_ID'
EPOCH = 'OMUX_CODEX_COMPONENT_EPOCH'
COORDS = (Path('/home/jess/.local/state/omux-execution-20261005'),
    Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'))
SOURCE = 'e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273'
ORIGINAL_PRODUCER = '545727183aa4e361eb1967fa3599dd30e5fd38a78f68dad9fec74793f8f713ee'
HEX = re.compile(r'[0-9a-f]{64}')
PIN = {'path', 'sha256', 'bytes', 'source_commit', 'graph_sha256'}
LIMITS={'MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'512','CPUQuotaPerSecUSec':'2s',
    'RuntimeMaxUSec':'20min','KillMode':'control-group','SendSIGKILL':'yes','TimeoutStopUSec':'10s','OOMPolicy':'kill'}
COMPONENT_KEYS = {'schema_version','scope','purpose','system','backend_sha256','files',
    'qualification','version','renewal_owner','native_support','text_continuity','provider_evaluation'}
RECORD_KEYS = {'schema_version','scope','component_sha256','backend_sha256','data_home',
    'state_home','qualification_sha256','device_receipt_sha256','descriptor_bytes','files','producer'}

def require(value):
    if not value: raise ValueError('codex-device-component-refused')

def tick(deadline):
    require(type(deadline) is int and time.monotonic_ns() < deadline)

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()

def unique(rows):
    value = {}
    for key, item in rows:
        require(key not in value)
        value[key] = item
    return value

def parsed(raw, canonical=False):
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and (not canonical or encoded(value) == raw))
    return value

def sha(raw): return hashlib.sha256(raw).hexdigest()

def close_all(items):
    error=None
    for item in items:
        if item is not None:
            try:item.close()
            except BaseException as caught:
                if error is None:error=caught
    if error is not None:raise error

def canonical(value):
    require(type(value) is str and 0 < len(value) <= 4096 and value.startswith('/')
        and value == os.path.normpath(value) and '..' not in Path(value).parts
        and not any(c.isspace() or c in ':\\\x00' for c in value))
    return Path(value)

def output_parent(path, run):
    path,run=canonical(str(path)),canonical(str(run))
    require(run.parent in COORDS and str(uuid.UUID(run.name))==run.name)
    base=run/'output-base'
    require(path.is_relative_to(base))
    relative=path.relative_to(base).as_posix()
    require(re.fullmatch(r'(?:sandbox/(?:linux-sandbox|processwrapper-sandbox)/(?:0|[1-9][0-9]{0,8})/)?'
        r'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/codex_device_acquisition_component/test\.outputs',relative))
    return path

def identity(info, directory=False):
    result = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    return result if directory else result+(info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

class Directory:
    def __init__(self, path, mode=None):
        self.path, self.fd = canonical(str(path)), -1
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.chain=[identity(os.fstat(fd),True)[:4]]
        try:
            for part in self.path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = child
                info = os.fstat(fd)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                    and not stat.S_IMODE(info.st_mode) & 0o022)
                self.chain.append(identity(info,True)[:4])
            info = os.fstat(fd)
            require(mode is None or (info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode))
            self.fd, self.fence = fd, identity(info, True)
        except BaseException:
            os.close(fd); raise
    def recheck(self):
        other = Directory(self.path)
        try: require(identity(os.fstat(self.fd), True) == self.fence == other.fence and self.chain==other.chain)
        finally: other.close()
    @classmethod
    def child(cls,parent,name,mode):
        require('/' not in name and name not in ('','.','..'))
        parent.recheck()
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
        try:
            info=os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==mode)
            value=cls.__new__(cls);value.path=parent.path/name;value.fd=fd;value.fence=identity(info,True)
            value.chain=parent.chain+[identity(info,True)[:4]]
            value.recheck();return value
        except BaseException:os.close(fd);raise
    def names(self):
        with os.scandir(self.fd) as entries:
            names = [next(entries, None) for _ in range(66)]
        require(names[-1] is None)
        return {entry.name for entry in names if entry is not None}
    def close(self):
        if self.fd >= 0:
            fd,self.fd=self.fd,-1;os.close(fd)

class File:
    def __init__(self, path, deadline, pin=None, mode=None, limit=1024**3):
        self.fd, self.parent = -1, None
        self.path, self.deadline = canonical(str(path)), deadline
        try:
            self.parent = Directory(self.path.parent)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=self.parent.fd)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and not stat.S_IMODE(info.st_mode) & 0o022 and 0 < info.st_size <= limit
                and (mode is None or stat.S_IMODE(info.st_mode) == mode))
            self.fence = identity(info)
            self.row = {'sha256':self.digest(), 'bytes':info.st_size, 'mode':stat.S_IMODE(info.st_mode)}
            if pin is not None:
                require(self.row['sha256'] == pin['sha256'] and self.row['bytes'] == pin['bytes'])
            self.recheck()
        except BaseException:
            self.close(); raise
    def digest(self):
        digest, offset = hashlib.sha256(), 0
        while offset < self.fence[6]:
            tick(self.deadline)
            raw = os.pread(self.fd, min(1024**2, self.fence[6]-offset), offset)
            require(raw); digest.update(raw); offset += len(raw)
        require(not os.pread(self.fd, 1, offset))
        return digest.hexdigest()
    def raw(self, limit=262144):
        require(self.fence[6] <= limit); tick(self.deadline)
        raw = os.pread(self.fd, limit+1, 0)
        require(len(raw) == self.fence[6]); self.recheck(); return raw
    def recheck(self):
        tick(self.deadline); self.parent.recheck()
        require(identity(os.fstat(self.fd)) == self.fence
            == identity(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)))
    def close(self):
        fd,self.fd=self.fd,-1
        parent,self.parent=self.parent,None
        try:
            if fd >= 0:os.close(fd)
        finally:
            if parent is not None:parent.close()

def public_receipt(path):
    path = canonical(str(path))
    require(path.name == 'receipt.json' and path.parent.parent in COORDS)
    require(str(uuid.UUID(path.parent.name)) == path.parent.name)
    return path

def pin(value):
    require(type(value) is dict and set(value) == PIN
        and type(value['sha256']) is str and HEX.fullmatch(value['sha256'])
        and type(value['bytes']) is int and 0 < value['bytes'] <= 1024**2
        and type(value['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', value['source_commit'])
        and type(value['graph_sha256']) is str and HEX.fullmatch(value['graph_sha256']))
    public_receipt(value['path'])
    return value

def outer(value, selected, label):
    """Validate genuine current standard producer fields, never a clean release stamp."""
    pin(selected)
    parent = public_receipt(selected['path']).parent
    require(value.get('id') == parent.name and value.get('artifact_epoch') == parent.name
        and value.get('source_commit') == selected['source_commit'] and value.get('source_dirty') == 'false'
        and value.get('graph_sha256') == selected['graph_sha256']
        and value.get('profile') == ('standard' if label==DEVICE else 'codex-device-component')
        and value.get('manager') == 'system' and value.get('verb') == 'test' and value.get('targets') == [label]
        and type(value.get('exit')) is int and value['exit'] == 0
        and type(value.get('workload_exit')) is int and value['workload_exit'] == 0
        and value.get('descendants_empty') is True and value.get('controller_failure') is None
        and type(value.get('cleanup')) is dict and value['cleanup'].get('state') == 'empty'
        and value['cleanup'].get('ownership') in ('verified','unproved')
        and type(value.get('test_evidence')) is dict and value['test_evidence'].get('state') == 'preserved')
    require(value.get('limits')==LIMITS and type(value.get('observed_properties')) is dict)
    observed=value['observed_properties']
    for key,item in LIMITS.items():
        if key!='RuntimeMaxUSec':require(observed.get(key)==item)
    for key in ('PrivateNetwork','NoNewPrivileges','ProtectControlGroups','RestrictSUIDSGID'):
        require(observed.get(key)=='yes')
    duration=observed.get('RuntimeMaxUSec')
    require(type(duration) is str and len(duration)<=64 and re.fullmatch(r'[0-9]{1,10}(?:\.[0-9]{1,6})?(?:us|ms|s|min|h)(?: [0-9]{1,10}(?:\.[0-9]{1,6})?(?:us|ms|s|min|h))*',duration))
    units={'us':1,'ms':1000,'s':10**6,'min':60*10**6,'h':3600*10**6}
    total=sum(Decimal(number)*units[unit] for number,unit in re.findall(r'([0-9]+(?:\.[0-9]+)?)(us|ms|s|min|h)',duration))
    require(0<total<=1200*10**6)
    cgroup=value.get('original_cgroup_identity')
    require(type(cgroup) is dict and set(cgroup)=={'device','inode'}
        and type(cgroup['device']) is int and cgroup['device']>=0
        and type(cgroup['inode']) is int and cgroup['inode']>0)
    if label==PRODUCER:
        proof=value.get('codex_device_component')
        require(type(proof) is dict and set(proof)=={'input','output','verified_after_cleanup',
                'original_entry_monotonic_ns','original_deadline_monotonic_ns'}
            and proof.get('verified_after_cleanup') is True
            and type(proof['original_entry_monotonic_ns']) is int and proof['original_entry_monotonic_ns']>0
            and type(proof['original_deadline_monotonic_ns']) is int
            and proof['original_deadline_monotonic_ns']-proof['original_entry_monotonic_ns']==1200*10**9
            and type(proof.get('input')) is dict and set(proof['input'])=={'scope','action','manifest_sha256',
                'provider_request_performed','native_execution_performed','resident_effects_authorized',
                'continuity_qualified','credential_contents_read'} and proof['input'].get('action')=='produce'
            and proof['input'].get('scope')=='provider-free-codex-device-component'
            and all(proof['input'][name] is False for name in ('provider_request_performed','native_execution_performed',
                'resident_effects_authorized','continuity_qualified','credential_contents_read'))
            and type(proof['input']['manifest_sha256']) is str and HEX.fullmatch(proof['input']['manifest_sha256'])
            and type(proof.get('output')) is dict and set(proof['output'])=={'action_epoch','controller_graph_sha256',
                'manifest_sha256','action','provider_request_performed','resident_enrollment_completed','continuity_qualified'}
            and proof['output'].get('action')=='produce'
            and proof['output']['manifest_sha256']==proof['input']['manifest_sha256']
            and all(proof['output'][name] is False for name in ('provider_request_performed',
                'resident_enrollment_completed','continuity_qualified'))
            and proof['output'].get('action_epoch')==parent.name
            and proof['output'].get('controller_graph_sha256')==selected['graph_sha256'])
    reused = value.get('cache_reuse_requested')
    if reused is True:
        require(type(value.get('cache_policy')) is int and value['cache_policy'] == 2
            and type(value.get('cache_key')) is str and HEX.fullmatch(value['cache_key']))
        output = parent.parent / ('cache-v2-'+value['cache_key']) / 'output-base'
    else:
        require(reused is False and value.get('cache_key') is None and value.get('cache_policy') is None)
        output = parent / 'output-base'
    require(value.get('output_base') == str(output))
    return output / 'execroot/_main/bazel-out/k8-fastbuild/testlogs' / label[2:].replace(':','/') / 'test.outputs'

def inner(value):
    device.device_qualification(value)
    require(set(value)=={'schema_version','kind','status','upstream_commit','patch_sha256','archive_sha256',
        'archive_bytes','manifest_sha256','source_receipt_sha256','producer_receipt_sha256','backend_sha256',
        'backend_bytes','loader_sha256','version','runtime_inventory','runtime_inventory_sha256',
        'artifact_selection_sha256','device_api','generated_schema_inventory','diagnostics',
        'native_support','text_continuity','provider_evaluation','authority'}
        and value.get('upstream_commit')=='00c972ed5d6ff6499317fd41b7f23605b8e6850d'
        and value.get('patch_sha256')=='2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46'
        and value.get('archive_bytes') == 119923125 and type(value.get('archive_bytes')) is int
        and value.get('source_receipt_sha256') == SOURCE and value.get('producer_receipt_sha256') == ORIGINAL_PRODUCER
        and value.get('version') == 'codex 0.0.0'
        and value.get('runtime_inventory_sha256') == sha(encoded(value['runtime_inventory']))
        and type(value.get('artifact_selection_sha256')) is str and HEX.fullmatch(value['artifact_selection_sha256'])
        and value.get('authority')==['R-HOOK-CONVERGENCE-20261004','R-N13'])
    rows=value['generated_schema_inventory']
    require(type(rows) is dict and set(rows)=={'ClientRequest.json','v2/LoginAccountParams.json','v2/LoginAccountResponse.json'}
        and type(value['diagnostics']) is list and len(value['diagnostics'])==2)
    for row in (*rows.values(),*value['diagnostics']):
        require(type(row) is dict and set(row)=={'sha256','bytes'} and type(row['sha256']) is str
            and HEX.fullmatch(row['sha256']) and type(row['bytes']) is int and 0<=row['bytes']<=8*1024**2)

def inventory():
    return {'codex':{'sha256':BACKEND,'bytes':318579008,'mode':0o555}, **{
        'runtime/'+name:{'sha256':digest,'bytes':size,'mode':mode}
        for name,(digest,size,mode) in device.RUNTIME_FILES.items()}}

def directories(files):
    result = {'':set()}
    for name in files:
        require(type(name) is str and not name.startswith('/')
            and all(part not in ('','.','..') for part in name.split('/')))
        parts = name.split('/')
        for index,part in enumerate(parts): result.setdefault('/'.join(parts[:index]),set()).add(part)
    return result

class Tree:
    def __init__(self, root, files, deadline):
        self.root, self.files, self.dirs = canonical(str(root)), {}, {}
        self.members=directories(files)
        try:
            for relative,names in self.members.items():
                # Only intermediate directories, not leaves, enter this set.
                if relative and relative in files: continue
                held = Directory(self.root / relative, 0o555)
                self.dirs[relative] = held
                require(held.names() == names)
            for name,row in files.items():
                require(type(row) is dict and set(row) == {'sha256','bytes','mode'}
                    and type(row['mode']) is int and row['mode'] in (0o444,0o555))
                self.files[name] = File(self.root/name, deadline, row, row['mode'])
            self.recheck()
        except BaseException:
            self.close(); raise
    def recheck(self):
        for name,directory in self.dirs.items():
            directory.recheck();require(directory.names()==self.members[name])
        for file in self.files.values(): file.recheck()
    def close(self):
        items=(*self.files.values(),*self.dirs.values())
        self.files.clear(); self.dirs.clear()
        close_all(items)

def schema(value, home):
    require(type(value) is dict and type(value.get('schema_version')) is int
        and value['schema_version'] == 1 and value.get('scope') == INPUT)
    if value.get('action') == 'produce':
        require(set(value) == {'schema_version','scope','action','runtime_directory','qualification','device_receipt'})
        pin(value['qualification']); canonical(value['runtime_directory'])
        q = value['device_receipt']
        require(type(q) is dict and set(q) == {'sha256','bytes'} and type(q['sha256']) is str
            and HEX.fullmatch(q['sha256']) and type(q['bytes']) is int and 0 < q['bytes'] <= 262144)
    else:
        require(value.get('action') in ('install','remove')
            and set(value) == {'schema_version','scope','action','data_home','state_home','component_directory',
                'component_sha256','producer'})
        for name in ('data_home','state_home'):
            path = canonical(value[name]); require(path.is_relative_to(home) and path != home)
            require(not any(part.startswith('.') and part not in ('.local',) for part in path.relative_to(home).parts))
        require(value['data_home'] != value['state_home']
            and type(value['component_sha256']) is str and HEX.fullmatch(value['component_sha256']))
        canonical(value['component_directory']); pin(value['producer'])
    return value

def projection(selected):
    return {key:selected[key] for key in ('sha256','bytes','source_commit','graph_sha256')} | {
        'id':Path(selected['path']).parent.name}

def validate_component(value):
    require(type(value) is dict and set(value) == COMPONENT_KEYS and type(value['schema_version']) is int
        and value['schema_version'] == 1 and value['scope'] == SCOPE
        and value['purpose'] == 'device-account-acquisition' and value['system'] == 'x86_64-linux'
        and value['backend_sha256'] == BACKEND and value['version'] == 'codex 0.0.0'
        and value['renewal_owner'] == 'native'
        and all(value[key] is False for key in ('native_support','text_continuity','provider_evaluation'))
        and type(value['files']) is dict
        and set(value['files']) == set(inventory()) | {'native-source-receipt.json','qualification.json'}
        and type(value['qualification']) is dict and set(value['qualification']) == {'inner','outer'})
    for name,row in inventory().items(): require(value['files'][name] == row)
    for name,key in (('native-source-receipt.json','inner'),('qualification.json','outer')):
        row, q = value['files'][name],value['qualification'][key]
        require(type(row) is dict and set(row) == {'sha256','bytes','mode'} and row['mode'] == 0o444
            and type(row['mode']) is int and type(row['bytes']) is int and 0 < row['bytes'] <= 1024**2
            and type(row['sha256']) is str and HEX.fullmatch(row['sha256'])
            and type(q) is dict and set(q) == ({'sha256','bytes'} if key == 'inner' else
                {'sha256','bytes','id','source_commit','graph_sha256'})
            and q['sha256'] == row['sha256'] and type(q['bytes']) is int and q['bytes'] == row['bytes'])
    q=value['qualification']['outer']
    require(type(q['id']) is str and str(uuid.UUID(q['id'])) == q['id']
        and type(q['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}',q['source_commit'])
        and type(q['graph_sha256']) is str and HEX.fullmatch(q['graph_sha256']))

class Qualified:
    def __init__(self, value, deadline):
        self.receipt, self.report, self.tree, self.descriptor = None,None,None,None
        self.value,self.deadline = value,deadline
        try:
            selected = value['qualification'] if value['action']=='produce' else value['producer']
            # Entire selected namespace/shape is checked before its first read.
            pin(selected)
            self.receipt = File(selected['path'],deadline,selected,limit=1024**2)
            raw = self.receipt.raw(1024**2)
            out = outer(parsed(raw), selected, DEVICE if value['action']=='produce' else PRODUCER)
            if value['action']=='produce':
                require(Path(value['runtime_directory']) == out/BACKEND)
                owner = parsed(raw).get('codex_owner_runtime_input')
                require(type(owner) is dict and owner.get('verified_after_cleanup') is True)
                self.report = File(out/BACKEND/'native-source-receipt.json',deadline,value['device_receipt'],0o444)
                inner(parsed(self.report.raw()))
                rows = inventory() | {'native-source-receipt.json':self.report.row}
                self.tree = Tree(out/BACKEND,rows,deadline)
                rows = dict(rows); rows['qualification.json'] = dict(self.receipt.row,mode=0o444)
                self.component = {'schema_version':1,'scope':SCOPE,'purpose':'device-account-acquisition',
                    'system':'x86_64-linux','backend_sha256':BACKEND,'files':rows,
                    'qualification':{'inner':{k:self.report.row[k] for k in ('sha256','bytes')},
                        'outer':projection(selected)},'version':'codex 0.0.0','renewal_owner':'native',
                    'native_support':False,'text_continuity':False,'provider_evaluation':False}
                validate_component(self.component)
            else:
                require(Path(value['component_directory']) == out/'component'/BACKEND)
                self.descriptor = File(out/'component'/BACKEND/'component.json',deadline,mode=0o444)
                require(self.descriptor.row['sha256']==value['component_sha256'])
                self.component=parsed(self.descriptor.raw(),True); validate_component(self.component)
                self.tree=Tree(out/'component'/BACKEND,self.component['files']|{'component.json':self.descriptor.row},deadline)
                inner(parsed(self.tree.files['native-source-receipt.json'].raw()))
                q=self.component['qualification']['outer']
                # Installed metadata preserves the exact original device output join.
                qpin={key:q[key] for key in ('sha256','bytes','source_commit','graph_sha256')}
                qpin['path']=str(selected_path(q['id'],parsed(self.tree.files['qualification.json'].raw(1024**2))))
                original_out=outer(parsed(self.tree.files['qualification.json'].raw(1024**2)),qpin,DEVICE)
                require(original_out.name=='test.outputs')
                owner=parsed(self.tree.files['qualification.json'].raw(1024**2)).get('codex_owner_runtime_input')
                require(type(owner) is dict and owner.get('verified_after_cleanup') is True)
            self.recheck()
        except BaseException:
            self.close(); raise
    def recheck(self):
        tick(self.deadline)
        for item in (self.receipt,self.report,self.descriptor,self.tree):
            if item is not None:item.recheck()
    def close(self):
        items=(self.tree,self.descriptor,self.report,self.receipt)
        self.tree=self.descriptor=self.report=self.receipt=None
        close_all(items)

def selected_path(epoch, receipt):
    # No reading inferred paths: recover only the already embedded public output-root role.
    output=canonical(receipt['output_base'])
    candidates=[base/epoch/'receipt.json' for base in COORDS
        if output.is_relative_to(base)]
    require(len(candidates)==1)
    return public_receipt(candidates[0])

def write(parent, name, raw, mode):
    require('/' not in name)
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        offset=0
        while offset<len(raw):
            amount=os.write(fd,raw[offset:]);require(amount>0);offset+=amount
        os.fchmod(fd,mode); os.fsync(fd)
    finally:os.close(fd)

def copy(file, parent, name, mode, deadline):
    file.recheck()
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        offset=0
        while offset<file.row['bytes']:
            tick(deadline); raw=os.pread(file.fd,min(1024**2,file.row['bytes']-offset),offset);require(raw)
            written=0
            while written<len(raw):
                tick(deadline);amount=os.write(fd,raw[written:]);require(amount>0);written+=amount
            offset+=len(raw)
        os.fchmod(fd,mode);os.fsync(fd)
    finally:os.close(fd)
    file.recheck()

def materialize(root, qualified, deadline):
    """Only a brand-new exact leaf; partial publication never becomes current."""
    root=canonical(str(root)); parent=Directory(root.parent)
    held=None;created={}
    try:
        parent.recheck();tick(deadline)
        os.mkdir(root.name,0o700,dir_fd=parent.fd)
        held=Directory.child(parent,root.name,0o700);created['']=held
        rows=qualified.component['files']
        dirs=directories(rows)
        for relative in sorted((name for name in dirs if name and name not in rows),key=lambda n:n.count('/')):
            parent_name=str(Path(relative).parent)
            owner=created['' if parent_name=='.' else parent_name]
            owner.recheck();parent.recheck();tick(deadline)
            os.mkdir(Path(relative).name,0o700,dir_fd=owner.fd)
            created[relative]=Directory.child(owner,Path(relative).name,0o700)
        for name,row in rows.items():
            parent_name=str(Path(name).parent)
            owner=created['' if parent_name=='.' else parent_name]
            owner.recheck();parent.recheck()
            file=qualified.receipt if name=='qualification.json' and qualified.value['action']=='produce' else qualified.tree.files[name]
            copy(file,owner.fd,Path(name).name,row['mode'],deadline)
            owner.recheck();parent.recheck()
        write(held.fd,'component.json',encoded(qualified.component),0o444)
        for relative in sorted((name for name in dirs if name and name not in rows),key=lambda n:n.count('/'),reverse=True):
            directory=created[relative];directory.recheck();parent.recheck();tick(deadline)
            os.fchmod(directory.fd,0o555);directory.fence=identity(os.fstat(directory.fd),True);os.fsync(directory.fd)
        held.recheck();parent.recheck();os.fchmod(held.fd,0o555);held.fence=identity(os.fstat(held.fd),True)
        os.fsync(held.fd);os.fsync(parent.fd)
        parent.recheck(); require(identity(os.stat(root.name,dir_fd=parent.fd,follow_symlinks=False),True)
            == identity(os.fstat(held.fd),True))
        files=rows|{'component.json':{'sha256':sha(encoded(qualified.component)),'bytes':len(encoded(qualified.component)),'mode':0o444}}
        verified=Tree(root,files,deadline)
        try:verified.recheck();qualified.recheck();parent.recheck()
        finally:verified.close()
        return files
    finally:
        close_all((*created.values(),parent))

class Lease:
    def __init__(self,parent,exclusive=True):
        self.parent,self.fd=parent,-1
        require(parent.names() <= {'.lock','current.json',BACKEND})
        created=False
        try:
            try:self.fd=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent.fd);created=True
            except FileExistsError:self.fd=os.open('.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent.fd)
            info=os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_gid==os.getgid()
                and info.st_nlink==1 and info.st_size==0 and stat.S_IMODE(info.st_mode)==0o600)
            self.fence=identity(info)
            fcntl.flock(self.fd,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
            self.recheck()
        except BaseException:
            self.close();raise
    def recheck(self):
        self.parent.recheck();require(identity(os.fstat(self.fd))==self.fence
            ==identity(os.stat('.lock',dir_fd=self.parent.fd,follow_symlinks=False)))
    def close(self):
        if self.fd>=0:
            fd,self.fd=self.fd,-1;os.close(fd)

def record(value,qualified,files):
    return {'schema_version':1,'scope':RECORD,'component_sha256':value['component_sha256'],
        'backend_sha256':BACKEND,'data_home':value['data_home'],'state_home':value['state_home'],
        'qualification_sha256':qualified.component['qualification']['outer']['sha256'],
        'device_receipt_sha256':qualified.component['qualification']['inner']['sha256'],
        'descriptor_bytes':files['component.json']['bytes'],'files':files,'producer':projection(value['producer'])}

def installed(data,state,expected,deadline):
    """Exact prior ownership before idempotence/removal; no unrecorded adoption."""
    require(data.names()=={'.lock','current.json',BACKEND} and state.names()=={'install.json','producer.json'})
    held=[];tree=None
    try:
        rec=File(state.path/'install.json',deadline,mode=0o600);held.append(rec)
        require(parsed(rec.raw(),True)==expected and set(expected)==RECORD_KEYS)
        selection=File(data.path/'current.json',deadline,mode=0o600);held.append(selection)
        require(parsed(selection.raw(),True)=={'schema_version':1,'scope':SELECTION,
            'component_sha256':expected['component_sha256'],'backend_sha256':BACKEND})
        proof=File(state.path/'producer.json',deadline,expected['producer'],0o600,1024**2);held.append(proof)
        selected={key:expected['producer'][key] for key in ('sha256','bytes','source_commit','graph_sha256')}
        selected['path']=str(selected_path(expected['producer']['id'],parsed(proof.raw(1024**2))))
        outer(parsed(proof.raw(1024**2)),selected,PRODUCER)
        tree=Tree(data.path/BACKEND,expected['files'],deadline);tree.recheck()
        return tree,held
    except BaseException:
        close_all((tree,*held))
        raise

def remove_tree(tree):
    """No private profile/history, lock, or unrecorded entry is ever deleted."""
    tree.recheck()
    for directory in tree.dirs.values():
        directory.recheck();os.fchmod(directory.fd,0o700);directory.fence=identity(os.fstat(directory.fd),True)
    for name,file in tree.files.items():
        # Parent mode changes are our explicit removal step; file identities do not change.
        require(identity(os.fstat(file.fd)) == file.fence == identity(os.stat(
            Path(name).name,dir_fd=file.parent.fd,follow_symlinks=False)))
        relative_parent=str(Path(name).parent)
        tree.dirs['' if relative_parent=='.' else relative_parent].recheck()
        os.unlink(Path(name).name,dir_fd=file.parent.fd)
    for name in sorted((n for n in tree.dirs if n),key=lambda n:n.count('/'),reverse=True):
        parent,name_part=str(Path(name).parent),Path(name).name
        tree.dirs[name].recheck();tree.dirs['' if parent=='.' else parent].recheck()
        os.rmdir(name_part,dir_fd=tree.dirs['' if parent=='.' else parent].fd)
    parent=Directory(tree.root.parent)
    try:
        require(identity(os.stat(tree.root.name,dir_fd=parent.fd,follow_symlinks=False),True)
            == identity(os.fstat(tree.dirs[''].fd),True))
        os.rmdir(tree.root.name,dir_fd=parent.fd)
    finally:parent.close()

def install(value,qualified,deadline):
    data=state=lease=None;tree=None;held=[]
    try:
        data=Directory(Path(value['data_home'])/'omux-acquisition/codex',0o700)
        state=Directory(Path(value['state_home'])/'omux-acquisition/codex',0o700)
        lease=Lease(data)
        require(state.names()<={'install.json','producer.json'})
        files=qualified.component['files']|{'component.json':qualified.descriptor.row}
        expected=record(value,qualified,files)
        if data.names()!={'.lock'} or state.names():
            tree,held=installed(data,state,expected,deadline)
            lease.recheck();qualified.recheck()
            if value['action']=='remove':
                # Invalidate selection first; a crash cannot leave an executable current pointer.
                data.recheck();state.recheck();lease.recheck()
                os.unlink('current.json',dir_fd=data.fd);os.fsync(data.fd)
                remove_tree(tree)
                state.recheck();data.recheck();lease.recheck()
                for item in held:
                    if item.path.name in ('install.json','producer.json'):item.recheck()
                os.unlink('install.json',dir_fd=state.fd);os.unlink('producer.json',dir_fd=state.fd)
                os.fsync(data.fd);os.fsync(state.fd)
            return
        require(value['action']=='install')
        # A partial failed install is intentionally Unqualified, never silently adopted/replaced.
        materialize(data.path/BACKEND,qualified,deadline)
        lease.recheck();qualified.recheck();state.recheck()
        write(state.fd,'producer.json',qualified.receipt.raw(1024**2),0o600)
        write(state.fd,'install.json',encoded(expected),0o600);os.fsync(state.fd)
        write(data.fd,'current.json',encoded({'schema_version':1,'scope':SELECTION,
            'component_sha256':value['component_sha256'],'backend_sha256':BACKEND}),0o600)
        os.fsync(data.fd)
        tree,held=installed(data,state,expected,deadline)
        lease.recheck();qualified.recheck();tree.recheck()
    finally:
        close_all((tree,*held,lease,state,data))

def main():
    deadline=int(os.environ.get(DEADLINE,'0'))-30*10**9;tick(deadline)
    require(os.environ.get(VARIABLE)==DESTINATION)
    namespace=Directory(Path(DESTINATION).parent,0o700)
    manifest=qualified=None
    try:
        info=os.fstat(namespace.fd)
        require(os.environ.get(NSID)==str(info.st_dev)+':'+str(info.st_ino)
            and namespace.names()=={'input.json'})
        manifest=File(DESTINATION,deadline,mode=0o600,limit=65536)
        value=schema(parsed(manifest.raw()),Path(pwd.getpwuid(os.getuid()).pw_dir))
        qualified=Qualified(value,deadline)
        if value['action']=='produce':
            outputs=output_parent(os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR',''),os.environ.get(EPOCH,''))
            parent=Directory(outputs)
            try:require(not parent.names());os.mkdir(outputs/'component',0o700)
            finally:parent.close()
            materialize(outputs/'component'/BACKEND,qualified,deadline)
        else:install(value,qualified,deadline)
        qualified.recheck();manifest.recheck();namespace.recheck();tick(deadline)
        print('codex-device-component-completed')
        return 0
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError,OverflowError):
        print('codex-device-component-refused',file=sys.stderr);return 125
    finally:
        try:close_all((qualified,manifest,namespace))
        except BaseException:
            print('codex-device-component-refused',file=sys.stderr);return 125

if __name__=='__main__':raise SystemExit(main())
