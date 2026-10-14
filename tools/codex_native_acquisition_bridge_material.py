"""Genuine coordinator bridge artifact and registered loader closure custody.

This proof belongs to the coordinator DSO, never the application candidate.
No evaluator, downloader, compiler subprocess or implicit registration is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time
import importlib.util
import codex_native_acquisition_compilation as compilation
import codex_native_acquisition_process as process
import codex_native_acquisition_peer as native
import codex_native_acquisition_material as material
import nix_interpreter_closure as registration
_runfiles=os.environ.get('TEST_SRCDIR')
if type(_runfiles) is not str or not Path(_runfiles).is_absolute():
    raise ValueError('declared-bridge-runfiles-required')
_portable_path=Path(_runfiles)/'_main/delivery/portable.py'
_portable_spec=importlib.util.spec_from_file_location('portable',_portable_path)
if _portable_spec is None or _portable_spec.loader is None:
    raise ValueError('declared-portable-module-required')
portable=importlib.util.module_from_spec(_portable_spec)
_portable_spec.loader.exec_module(portable)

TARGET='//tools:codex_native_acquisition_bridge_material_producer'
KIND='omux-native-acquisition-coordinator-bridge-material-v1'
MARKER='OMUX_NATIVE_ACQUISITION_BRIDGE_MATERIAL '
MAX=256*1024*1024

def require(value):
    if value is not True:raise ValueError('native-coordinator-bridge-material-refused')

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pin(path,raw):return {'path':str(path),'sha256':digest(raw),'bytes':len(raw)}
def named_identity(path):
    s=Path(path).lstat()
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
        s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def bounded(path,deadline,maximum=MAX):
    compilation.tick(deadline)
    with Path(path).open('rb') as reader:
        before=process.identity(reader.fileno())
        require(stat.S_ISREG(before[2]) and 0<=before[6]<=maximum)
        raw=reader.read(maximum+1)
        compilation.tick(deadline)
        require(len(raw)<=maximum and process.identity(reader.fileno())==before)
        return raw

def marker(selection,outer,sha,deadline):
    evidence=compilation.read_json(Path(selection['producer']['receipt']).parent/'test-evidence.json',
        outer['test_evidence']['sha256'],deadline)
    rows=[row for result in evidence['results'] if result['target']==TARGET for row in result['files']
        if row['source']=='test.log' and row['state']=='copied']
    require(len(rows)==1)
    raw=compilation.read_bytes(Path(selection['producer']['receipt']).parent/'test-evidence'/rows[0]['file'],
        rows[0]['sha256'],deadline,8*1024*1024)
    matches=[line[len(MARKER):] for line in raw.decode('utf-8').splitlines() if line.startswith(MARKER)]
    require(matches==[sha])

def envelope(environment):
    import guard_native_acquisition_inputs_reserved as admission
    require(environment.get('OMUX_NATIVE_BRIDGE_MODE')==admission.BRIDGE)
    first=environment.get('OMUX_NATIVE_BRIDGE_ENTRY_NS');last=environment.get('OMUX_NATIVE_BRIDGE_DEADLINE_NS')
    require(type(first) is str and first.isdecimal() and type(last) is str and last.isdecimal())
    first,last=int(first),int(last)
    admission.remaining(first,last)
    return first,last,(last-30*10**9)/10**9

def elf(raw):
    require(type(raw) is bytes and len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01'
        and struct.unpack_from('<H',raw,16)[0] in (2,3))
    value=portable.elf_metadata(raw,max_bytes=MAX)
    require(value['machine']==62 and len(value['needed'])==len(set(value['needed'])))
    return value

def soname(raw):
    """Actual DT_SONAME, not the filesystem basename or an ldconfig guess."""
    elf(raw)
    header=struct.unpack_from('<HHIQQQIHHHHHH',raw,16);loads=[];dynamic=None
    for index in range(header[9]):
        tag,_,offset,virtual,_,size,_,_=struct.unpack_from('<IIQQQQQQ',raw,header[4]+index*header[8])
        if tag==1:loads.append((virtual,offset,size))
        if tag==2:dynamic=raw[offset:offset+size]
    if dynamic is None:return None
    values=[]
    for offset in range(0,len(dynamic),16):
        tag,value=struct.unpack_from('<qQ',dynamic,offset)
        if tag==0:break
        values.append((tag,value))
    names=[value for tag,value in values if tag==14]
    require(len(names)<=1)
    if not names:return None
    addresses=[value for tag,value in values if tag==5];sizes=[value for tag,value in values if tag==10]
    require(len(addresses)==len(sizes)==1)
    mappings=[offset+addresses[0]-virtual for virtual,offset,size in loads
        if addresses[0]>=virtual and addresses[0]-virtual<=size and sizes[0]<=size-(addresses[0]-virtual)]
    require(len(mappings)==1)
    return portable._cstring(raw[mappings[0]:mappings[0]+sizes[0]],names[0])

def loader_environment(environment):
    require(not any(environment.get(key) for key in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT')))

def mapped_authority(proof,deadline,bridge_path=None):
    """Reject foreign executable mappings and ambiguous actual ELF SONAMEs.

    Root membership is justified by full NAR verification before this function;
    a same-name foreign inode cannot coexist with a selected dependency.
    """
    roots={row['path'] for row in proof['registration_rows']}
    names={};mapped={}
    raw=bounded('/proc/self/maps',deadline,8*1024*1024)
    for line in raw.decode('utf-8').splitlines():
        compilation.tick(deadline);fields=line.split(maxsplit=5)
        if len(fields)!=6 or 'x' not in fields[1] or fields[5].startswith('['):continue
        path=fields[5]
        require(path==bridge_path or '/'.join(path.split('/')[:4]) in roots)
        info=Path(path).lstat();require(stat.S_ISREG(info.st_mode))
        major,minor=(int(part,16) for part in fields[3].split(':'))
        require((info.st_dev,info.st_ino)==(os.makedev(major,minor),int(fields[4])))
        if path in mapped:continue
        mapped[path]=(info.st_dev,info.st_ino)
        name=soname(bounded(path,deadline))
        if name is not None:names.setdefault(name,set()).add(path)
    require(all(len(paths)==1 for paths in names.values()))
    for row in proof['files']:
        name=soname(compilation.read_bytes(row['path'],row['sha256'],deadline,MAX))
        if name is not None and name in names:require(names[name]=={row['path']})
    return mapped

def closure(bridge,python,paths,text,inventory,deadline):
    """Resolve only declared registered files and exact ELF lookup edges.

    Absolute Nix RPATH/needed paths and $ORIGIN are accepted; ambient cache,
    LD_LIBRARY_PATH, relative search and basename-only selection are refused.
    """
    records=registration.registrations(text,paths,current_flake_paths=True)
    names=inventory['files'];require(type(names) is list and len(names)==len(set(names)))
    declared={'/nix/store/'+name[len('closure/'):] for name in names if name.startswith('closure/')}
    require(all(registration.current_flake_path_refusal('/'.join(p.split('/')[:4])) is None for p in declared))
    aliases={};files={};edges={};pending=[str(bridge),str(python)]
    mapped={}
    for line in Path('/proc/self/maps').read_text().splitlines():
        parts=line.split(maxsplit=5)
        if len(parts)==6 and parts[5] in declared:
            info=Path(parts[5]).stat();major,minor=(int(p,16) for p in parts[3].split(':'))
            require((info.st_dev,info.st_ino)==(os.makedev(major,minor),int(parts[4])))
            mapped[parts[5]]=None
    def resolve(path):
        require(type(path) is str and path.startswith('/nix/store/') and '..' not in Path(path).parts)
        seen=set()
        while True:
            compilation.tick(deadline);require(path in declared and path not in seen);seen.add(path)
            info=Path(path).lstat();require(info.st_uid==0)
            if not stat.S_ISLNK(info.st_mode):
                require(stat.S_ISREG(info.st_mode) and info.st_mode&0o022==0);return path
            target=os.readlink(path);aliases[path]={'path':path,'target':target}
            path=os.path.normpath(str(Path(target) if Path(target).is_absolute() else Path(path).parent/target))
    python=resolve(str(python))
    bridge_raw=bounded(bridge,deadline,8*1024*1024)
    python_raw=bounded(python,deadline)
    interp=elf(python_raw)['interpreter'];require(type(interp) is str)
    loader=resolve(interp);pending=[str(bridge),python,loader]
    while pending:
        compilation.tick(deadline);owner=pending.pop()
        if owner in files:continue
        require(len(files)<32)
        raw=bridge_raw if owner==str(bridge) else bounded(owner,deadline)
        info=elf(raw);files[owner]=pin(owner,raw);edges[owner]=[]
        for needed in info['needed']:
            require(type(needed) is str and '\x00' not in needed)
            if needed.startswith('/nix/store/'):
                candidate=resolve(needed)
            else:
                require('/' not in needed and needed not in ('.','..'))
                candidates=[]
                for directory in info['rpath']:
                    require(directory.startswith('/nix/store/') or directory=='$ORIGIN'
                        or directory.startswith('$ORIGIN/'))
                    directory=directory.replace('$ORIGIN',str(Path(owner).parent))
                    possible=os.path.normpath(directory+'/'+needed)
                    if possible in declared:candidates.append(resolve(possible))
                if not candidates:
                    # glibc's internal edges may bind an already-loaded object.
                    # Require an actual mapped registered ELF's DT_SONAME;
                    # this never admits a basename/default-directory search.
                    for loaded in mapped:
                        compilation.tick(deadline)
                        if mapped[loaded] is None:
                            loaded_raw=bounded(loaded,deadline)
                            mapped[loaded]=soname(loaded_raw)
                        if mapped[loaded]==needed:candidates.append(resolve(loaded))
                require(len(candidates)>0 and len(set(candidates))==1)
                candidate=candidates[0]
            edges[owner].append({'needed':needed,'path':candidate});pending.append(candidate)
    seeds={'/'.join(p.split('/')[:4]) for p in files if p!=str(bridge)}
    roots=registration.reachable(records,sorted(seeds));require(len(roots)<=process.MAX_ROOTS)
    rows=[]
    for root in roots:
        row=records[root]['record'];count=int(row[4])
        rows.append({'path':root,'narHash':row[1],'narSize':int(row[2]),'references':row[5:5+count]})
    proof={'schema_version':1,'status':'registered-linux-nix-runtime-closure-proof-candidate',
        'native_support':False,'loader_lookup_qualified':False,'target':'x86_64-linux',
        'original_interpreter':interp,'registration_rows':rows,'roots':[{'path':root} for root in roots],
        'files':[files[p] for p in sorted(files) if p!=str(bridge)],'aliases':list(aliases.values())}
    process.verify_closure(proof,interp,deadline)
    return proof,{'python':python,'loader':loader,'edges':edges,'files':files}

def schema(value):
    require(type(value) is dict and set(value)=={'schema_version','kind','source_commit','graph_sha256',
        'entry_ns','deadline_ns','bridge','closure','lookup','source_files','native_runtime_qualified',
        'credential_acquisition','provider_identity_proved','live_handoff_proven'}
        and value['schema_version']==1 and value['kind']==KIND
        and re.fullmatch('[a-f0-9]{40}',value['source_commit']) is not None
        and re.fullmatch('[a-f0-9]{64}',value['graph_sha256']) is not None)
    import guard_native_seed_plan_reserved as kernel
    kernel.envelope(value['entry_ns'],value['deadline_ns'])
    require(all(value[name] is False for name in ('native_runtime_qualified','credential_acquisition',
        'provider_identity_proved','live_handoff_proven')))
    require(type(value['bridge']) is dict and set(value['bridge'])=={'sha256','bytes'}
        and re.fullmatch('[a-f0-9]{64}',value['bridge']['sha256']) is not None
        and type(value['bridge']['bytes']) is int and 0<value['bridge']['bytes']<=8*1024*1024)
    return value

class RegisteredBridge:
    def __init__(self,selection,deadline):
        loader_environment(os.environ)
        require(type(selection) is dict and set(selection)=={'root','producer','receipt_sha256'})
        self.selection=selection;self.deadline=deadline;self.held=[];self.bridge=None;self.declared_bridge=None
        try:
            outer=material.producer_success(selection,TARGET,'bridge-material',deadline)
            root=Path(selection['root']);path=root/'bridge-material.json'
            raw=compilation.read_bytes(path,selection['receipt_sha256'],deadline,8*1024*1024)
            value=schema(json.loads(raw));self.value=value;self.raw=raw
            marker(selection,outer,selection['receipt_sha256'],deadline)
            require(value['source_commit']==outer['source_commit'] and value['graph_sha256']==outer['graph_sha256'])
            fd,witness=process.held_file(path,selection['receipt_sha256'],deadline,8*1024*1024)
            self.held.append((path,fd,witness,selection['receipt_sha256']))
            artifact=root/'native_peer_runtime_bridge.so'
            fd,witness=process.held_file(artifact,value['bridge']['sha256'],deadline,8*1024*1024)
            self.held.append((artifact,fd,witness,value['bridge']['sha256']))
            require(witness[6]==value['bridge']['bytes'])
            for row in value['closure']['files']:
                fd,witness=process.held_file(Path(row['path']),row['sha256'],deadline,MAX)
                self.held.append((Path(row['path']),fd,witness,row['sha256']))
                require(witness[6]==row['bytes'])
            self.recheck()
            runfiles=os.environ.get('TEST_SRCDIR');require(type(runfiles) is str)
            declared=(Path(runfiles)/'_main/native_peer_runtime_bridge.so').resolve(strict=True)
            self.declared_bridge=str(declared)
            actual=compilation.read_bytes(declared,value['bridge']['sha256'],deadline,8*1024*1024)
            require(len(actual)==value['bridge']['bytes'])
            self.bridge=native.Bridge(declared,pin(declared,actual),deadline)
            self.recheck()
        except BaseException:self.close();raise

    def recheck(self):
        loader_environment(os.environ)
        compilation.tick(self.deadline)
        material.producer_success(self.selection,TARGET,'bridge-material',self.deadline)
        value=self.value;proof=value['closure']
        process.verify_closure(proof,proof['original_interpreter'],self.deadline)
        for path,fd,witness,sha in self.held:
            require(process.identity(fd)==witness and named_identity(path)==witness)
            require(digest(os.pread(fd,witness[6]+1,0))==sha)
        # Current coordinator's Python must be the exact independently proved
        # executable; the application image cannot stand in for this authority.
        python=value['lookup']['python']
        require(Path('/proc/self/exe').resolve(strict=True)==Path(python))
        primary=Path('/proc/self/exe').stat()
        expected=[witness for path,fd,witness,sha in self.held if str(path)==python]
        require(len(expected)==1 and (primary.st_dev,primary.st_ino)==expected[0][:2])
        mapped=mapped_authority(proof,self.deadline,self.declared_bridge)
        required={row['path'] for rows in value['lookup']['edges'].values() for row in rows}
        require(required<=set(mapped))
        for path in required:
            info=Path(path).stat()
            require(mapped[path]==(info.st_dev,info.st_ino))
        for row in proof['files']:
            require(compilation.read_bytes(row['path'],row['sha256'],self.deadline,MAX)
                and Path(row['path']).stat().st_size==row['bytes'])

    def close(self):
        failures=[]
        while self.held:
            _,fd,_,_=self.held.pop()
            try:os.close(fd)
            except OSError as error:failures.append(error)
        if failures:raise failures[0]

def load_registered_bridge(selection,deadline):
    return RegisteredBridge(selection,deadline)

def main():
    parser=argparse.ArgumentParser()
    for name in ('bridge','native','paths','registration','inventory'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--source',action='append',required=True)
    args=parser.parse_args()
    first,last,deadline=envelope(os.environ)
    loader_environment(os.environ)
    native_manifest=json.loads(bounded(args.native,deadline,8*1024*1024))
    require(native_manifest['system']=='x86_64-linux')
    python=Path(native_manifest['packages']['python']['out'])/'bin/python3'
    proof,lookup=closure(Path(args.bridge),python,bounded(args.paths,deadline,8*1024*1024).decode().splitlines(),
        bounded(args.registration,deadline,8*1024*1024).decode(),
        json.loads(bounded(args.inventory,deadline,128*1024*1024)),deadline)
    bridge=bounded(args.bridge,deadline,8*1024*1024)
    source_files={Path(path).name:digest(bounded(path,deadline,8*1024*1024)) for path in args.source}
    require(set(source_files)=={'native_peer_runtime_bridge.c','native_peer.c','native_peer.h'})
    value=schema({'schema_version':1,'kind':KIND,'source_commit':os.environ['OMUX_NATIVE_BRIDGE_SOURCE_COMMIT'],
        'graph_sha256':os.environ['OMUX_NATIVE_BRIDGE_GRAPH_SHA256'],'entry_ns':first,'deadline_ns':last,
        'bridge':{'sha256':digest(bridge),'bytes':len(bridge)},'closure':proof,'lookup':lookup,
        'source_files':source_files,'native_runtime_qualified':False,'credential_acquisition':False,
        'provider_identity_proved':False,'live_handoff_proven':False})
    root=Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])/'bridge-material'
    compilation.tick(deadline);root.mkdir(mode=0o700)
    for name,raw in (('native_peer_runtime_bridge.so',bridge),('bridge-material.json',encoded(value))):
        fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        try:
            offset=0
            while offset<len(raw):
                compilation.tick(deadline);count=os.write(fd,raw[offset:]);require(count>0);offset+=count
            os.fsync(fd)
        finally:os.close(fd)
    process.verify_closure(proof,proof['original_interpreter'],deadline)
    compilation.tick(deadline)
    print(MARKER+digest(encoded(value)));return 0

if __name__=='__main__':raise SystemExit(main())
