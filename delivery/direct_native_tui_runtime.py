"""Version-bound direct package for ordinary TUI evaluation, never enrollment.

The public pin selects a genuine PACKAGE guardian; it cannot manufacture one.
All native launch/resume/history predicates remain owned by the existing fixture.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import time
import test_installed_codex_live_continuity as retained
import test_installed_native_tui as tui
import codex_native_acquisition_compilation as compiler
import codex_native_acquisition_material as material
import codex_native_acquisition_process as process
import codex_fresh_native_runtime as fresh
import nix_codex_deployment as deployment

PIN_KIND='omux-direct-native-tui-package-pin-v1'
PROFILE='native-acquisition-ordinary-tui-reserved'
TARGET='//delivery:installed_direct_native_tui_test'
DIRECT_KIND='omux-native-source-acquisition-fresh-native-package-v1'
MAX_METADATA=16*1024*1024

def require(value):
    if value is not True:raise ValueError('direct-native-tui-runtime-refused')

def original_deadlines(environment,clock_ns=time.monotonic_ns):
    require(environment.get('OMUX_NATIVE_ORDINARY_MODE')==PROFILE)
    values=[]
    for name in ('OMUX_NATIVE_ORDINARY_ENTRY_NS','OMUX_NATIVE_ORDINARY_DEADLINE_NS'):
        value=environment.get(name)
        require(type(value) is str and re.fullmatch('[1-9][0-9]{0,18}',value) is not None)
        values.append(int(value))
    entry,until=values
    require(until-entry==1200*10**9 and until<2**63 and entry<=clock_ns()<until-30*10**9)
    return (until-30*10**9)/10**9,until/10**9

def selected_pin(raw,sha):
    require(type(raw) is bytes and 0<len(raw)<=65536 and type(sha) is str
        and re.fullmatch('[0-9a-f]{64}',sha) is not None and hashlib.sha256(raw).hexdigest()==sha)
    value=json.loads(raw,object_pairs_hook=tui.strict_object)
    require(type(value) is dict and set(value)=={'schema_version','kind','package'}
        and type(value['schema_version']) is int and value['schema_version']==1 and value['kind']==PIN_KIND
        and type(value['package']) is dict and set(value['package'])=={'root','producer'})
    from codex_protocol_history_native import producer_pin,path
    producer_pin(value['package']['producer']);path(value['package']['root'])
    return value['package']

def package_log(package,outer,deadline):
    origin=Path(package['producer']['receipt']).parent
    evidence=compiler.read_json(origin/'test-evidence.json',outer['test_evidence']['sha256'],deadline)
    results=[row for row in evidence['results'] if row['target']==deployment.TARGET]
    require(len(results)==1)
    rows=[row for row in results[0]['files'] if row['source']=='test.log' and row['state']=='copied']
    require(len(rows)==1 and re.fullmatch('[0-9a-f]{64}\\.evidence',rows[0]['file']) is not None)
    row=rows[0]
    raw=compiler.read_bytes(origin/'test-evidence'/row['file'],row['sha256'],deadline,MAX_METADATA)
    require(len(raw)==row['bytes'])
    return raw

def mapped_primary(pid,backend,backend_row,proof,deadline):
    """Actual installed main ELF + admitted mapped interpreter, no loader alias."""
    compiler.tick(deadline)
    held=os.open(backend,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    pidfd=actual=None
    try:
        before=process.identity(held)
        require(stat.S_ISREG(before[2]) and before[3]==os.getuid() and before[5]==1
            and stat.S_IMODE(before[2])==backend_row['mode'] and before[2]&0o111!=0
            and before[2]&0o022==0 and before[6]==backend_row['bytes'])
        hasher=hashlib.sha256();offset=0
        while offset<before[6]:
            compiler.tick(deadline)
            raw=os.pread(held,min(65536,before[6]-offset),offset)
            require(bool(raw));offset+=len(raw);hasher.update(raw)
        require(hasher.hexdigest()==backend_row['sha256'] and process.identity(held)==before)
        pidfd=os.pidfd_open(pid,0)
        start=process.process_start(pid,deadline)
        require(not select.select([pidfd],[],[],0)[0])
        actual=os.open('/proc/'+str(pid)+'/exe',os.O_RDONLY|os.O_CLOEXEC)
        require(process.identity(actual)==before)
        allowed={}
        for row in proof['files']:
            info=Path(row['path']).stat()
            allowed[(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)]=row['path']
        admitted=(os.major(before[0]),os.minor(before[0]),before[1]);allowed[admitted]=str(backend)
        interpreter=proof['files'][proof['interpreter_file_index']]['path'];info=Path(interpreter).stat()
        loader=(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)
        with open('/proc/'+str(pid)+'/maps','rb') as stream:raw=stream.read(256*1024+1)
        require(len(raw)<=256*1024)
        seen=set();lines=raw.splitlines();require(len(lines)<=4096)
        for line in lines:
            compiler.tick(deadline)
            parts=line.split(None,5);require(len(parts)>=5)
            if b'x' not in parts[1]:continue
            if len(parts)==6 and parts[5] in (b'[vdso]',b'[vsyscall]'):continue
            require(len(parts)==6 and parts[5].startswith(b'/') and not parts[5].endswith(b' (deleted)'))
            device=parts[3].split(b':');require(len(device)==2)
            identity=(int(device[0],16),int(device[1],16),int(parts[4]))
            require(identity in allowed);seen.add(identity)
        require(admitted in seen and loader in seen and loader!=admitted
            and process.identity(held)==before==process.identity(actual)
            and process.process_start(pid,deadline)==start and not select.select([pidfd],[],[],0)[0])
        named=backend.lstat()
        require((named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid,named.st_nlink,
            named.st_size,named.st_mtime_ns,named.st_ctime_ns)==before)
        compiler.tick(deadline)
    finally:
        try:
            if actual is not None:os.close(actual)
        finally:
            try:
                if pidfd is not None:os.close(pidfd)
            finally:os.close(held)

def verify_installed_files(root,manifest,deadline):
    """Only this disposable fixture's exact materialized four-member runtime."""
    root=Path(root)
    held=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    descriptors=[held];actual=set();witnesses=[]
    def directory_identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        anchor=os.fstat(held)
        require(stat.S_ISDIR(anchor.st_mode) and anchor.st_uid==os.getuid()
            and stat.S_IMODE(anchor.st_mode)==0o700
            and directory_identity(root.lstat())==directory_identity(anchor))
        def visit(parent,relative,depth):
            require(depth<=8)
            with os.scandir(parent) as scan:
                names=[]
                for item in scan:
                    compiler.tick(deadline);require(len(names)<16);names.append(item.name)
            for name in names:
                compiler.tick(deadline)
                child_name=relative+'/'+name if relative else name
                info=os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(info.st_uid==os.getuid())
                if stat.S_ISDIR(info.st_mode):
                    require(stat.S_IMODE(info.st_mode)==0o700 and any(
                        expected.startswith(child_name+'/') for expected in manifest['files']))
                    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    descriptors.append(fd);require(directory_identity(os.fstat(fd))==directory_identity(info))
                    witnesses.append((parent,name,fd,directory_identity(info)))
                    visit(fd,child_name,depth+1)
                    require(directory_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==directory_identity(info))
                else:
                    require(child_name in manifest['files'] and child_name not in actual
                        and stat.S_ISREG(info.st_mode) and info.st_nlink==1)
                    row=manifest['files'][child_name]
                    require(stat.S_IMODE(info.st_mode)==row['mode'] and info.st_size==row['bytes'])
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                    descriptors.append(fd);before=process.identity(fd)
                    require(before==(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
                        info.st_size,info.st_mtime_ns,info.st_ctime_ns))
                    digest=hashlib.sha256();offset=0
                    while offset<info.st_size:
                        compiler.tick(deadline);raw=os.pread(fd,min(65536,info.st_size-offset),offset)
                        require(bool(raw));offset+=len(raw);digest.update(raw)
                    named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                    require(digest.hexdigest()==row['sha256'] and process.identity(fd)==before
                        and before==(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid,named.st_nlink,
                            named.st_size,named.st_mtime_ns,named.st_ctime_ns))
                    witnesses.append((parent,name,fd,before))
                    actual.add(child_name)
        visit(held,'',0)
        for parent,name,fd,before in witnesses:
            compiler.tick(deadline)
            require(process.identity(fd)==before and directory_identity(
                os.stat(name,dir_fd=parent,follow_symlinks=False))==before)
        require(actual==set(manifest['files']) and directory_identity(root.lstat())==directory_identity(anchor))
        compiler.tick(deadline)
    finally:
        failure=None
        for fd in reversed(descriptors):
            try:os.close(fd)
            except OSError as error:
                if failure is None:failure=error
        if failure is not None:raise failure


class DirectReader:
    def __init__(self,pin,sha,deadline):
        self.pin=Path(pin);self.sha=sha;self.deadline=deadline
        self.package=selected_pin(retained.public_runtime_file(self.pin,65536),sha)
        self.manifest=None;self.archive_pin=None;self.receipt_pin=None

    def load(self):
        compiler.tick(self.deadline)
        require(selected_pin(retained.public_runtime_file(self.pin,65536),self.sha)==self.package)
        outer=material.producer_success(self.package,deployment.TARGET,'fresh-native-runtime',self.deadline)
        root=Path(self.package['root'])
        inventory_raw=deployment.bounded_read(root/'package-outputs.json',65536,self.deadline)
        inventory=deployment.closed_inventory(inventory_raw,package_log(self.package,outer,self.deadline))
        files={}
        for name,row in inventory['files'].items():
            files[name]=compiler.read_bytes(root/name,row['sha256'],self.deadline,
                fresh.runtime.MAX_ARCHIVE_BYTES if name.endswith('.tar.gz') else MAX_METADATA)
            require(len(files[name])==row['bytes'])
        receipt=json.loads(files['runtime-receipt.json'],object_pairs_hook=tui.strict_object)
        require(receipt['kind']==DIRECT_KIND and receipt['purpose']=='evaluation-only'
            and receipt['acquisitionContract']=='unsupported' and receipt['native_support'] is False
            and receipt['provider_evaluation'] is False and receipt['launchProfile']=='linux_nix_direct_main_v1'
            and receipt['producer_target']==deployment.TARGET)
        selection=json.loads(files['package-selection.json'],object_pairs_hook=tui.strict_object)
        material.validate_paths(selection)
        values,schemas,evidence=material.load_inputs(selection,
            lambda role,row,maximum:compiler.read_bytes(row['path'],row['sha256'],self.deadline,maximum))
        chain=material.validate_chain(selection,values,schemas,evidence,deadline=self.deadline)
        require(chain==receipt['chain'] and receipt['selection_sha256']==hashlib.sha256(files['package-selection.json']).hexdigest()
            and receipt['executable']['original_sha256']==hashlib.sha256(values['codex']).hexdigest()
            and receipt['executable']['original_bytes']==len(values['codex']))
        manifest,archive_files=fresh.verify_runtime_files(files['fresh-native-runtime.tar.gz'],receipt,files['registration-receipt.json'])
        require(fresh.encoded(manifest)==files['runtime-manifest.json'])
        proof=json.loads(files['registration-receipt.json'],object_pairs_hook=tui.strict_object)
        loader,_=process.verify_closure(proof,manifest['runtime']['original_interpreter'],self.deadline)
        require(loader==proof['files'][proof['interpreter_file_index']])
        compiler.tick(self.deadline)
        return manifest,archive_files,proof,inventory

    def __call__(self,candidate,receipt):
        manifest,files,_,inventory=self.load()
        for path,name in ((candidate,'fresh-native-runtime.tar.gz'),(receipt,'runtime-receipt.json')):
            row=inventory['files'][name]
            raw=retained.public_runtime_file(path,fresh.runtime.MAX_ARCHIVE_BYTES if name.endswith('.tar.gz') else MAX_METADATA)
            require(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'])
        self.manifest=manifest
        self.archive_pin=inventory['files']['fresh-native-runtime.tar.gz'];self.receipt_pin=inventory['files']['runtime-receipt.json']
        return manifest,files

    def verify_process(self,native,binary):
        require(self.manifest is not None)
        manifest,_,proof,_=self.load();require(manifest==self.manifest)
        verify_installed_files(Path(binary).parent.parent,manifest,self.deadline)
        backend=Path(binary).parent.parent/fresh.runtime.BACKEND
        native.alive()
        mapped_primary(native.process.pid,backend,manifest['files'][fresh.runtime.BACKEND],proof,self.deadline)
        native.alive();compiler.tick(self.deadline)
