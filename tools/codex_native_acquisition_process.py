"""Direct-main ownership and byte-proved runtime closure; no resume authority.

No builds, package creation, provider access, or implicit input selection occur.
The registered image owns fds. A child remains behind GO until its original pidfd
is held. Native peer capture is additionally fenced to that original child.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import time
import codex_native_acquisition_compilation as compilation
import nar_descriptor as nar

PACKAGE_TARGET='//tools:codex_native_acquisition_runtime_package'
STORE=re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+')
MAX_ROOTS=32
MAX_NODES=100000
MAX_CLOSURE_BYTES=256*1024*1024

def require(value):
    if value is not True:raise ValueError('native-runtime-registration-refused')

def identity(fd):
    s=os.fstat(fd)
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def held_file(path,pin,deadline,maximum):
    # Existing retained-input reader checks canonical path, sealed parents and
    # full bytes. Repeating through the held fd binds the opened inode as well.
    raw=compilation.read_bytes(path,pin,deadline,maximum)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=identity(fd);require(stat.S_ISREG(before[2]) and before[6]==len(raw))
        digest=hashlib.sha256();offset=0
        while offset<len(raw):
            compilation.tick(deadline)
            chunk=os.pread(fd,min(65536,len(raw)-offset),offset)
            require(bool(chunk));digest.update(chunk);offset+=len(chunk)
        require(identity(fd)==before and digest.hexdigest()==pin)
        return fd,before
    except BaseException:os.close(fd);raise

def descriptor(root,deadline):
    """Full bounded inert inventory, with immutable owner and no link traversal."""
    require(type(root) is str and STORE.fullmatch(root) is not None)
    for parent in reversed(Path(root).parents):
        compilation.tick(deadline);s=parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_mode&0o022==0)
    nodes=[];witnesses=[];total=0
    def visit(relative,depth):
        nonlocal total
        compilation.tick(deadline)
        require(depth<=128 and len(nodes)<MAX_NODES)
        path=Path(root)/relative;s=path.lstat()
        require(s.st_uid==0 and (stat.S_ISLNK(s.st_mode) or s.st_mode&0o022==0))
        witness=(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        witnesses.append((path,witness))
        row={'path':relative}
        if stat.S_ISDIR(s.st_mode):
            row['type']='directory';nodes.append(row)
            # scandir does not follow links; names are validated by NAR schema.
            with os.scandir(path) as entries:
                names=[]
                for entry in entries:
                    compilation.tick(deadline);require(len(names)<MAX_NODES)
                    names.append(entry.name)
            for name in sorted(names,key=os.fsencode):
                visit(relative+'/'+name if relative else name,depth+1)
        elif stat.S_ISREG(s.st_mode):
            total+=s.st_size;require(total<=MAX_CLOSURE_BYTES)
            row.update(type='regular',size=s.st_size,executable=bool(s.st_mode&stat.S_IXUSR));nodes.append(row)
        elif stat.S_ISLNK(s.st_mode):
            # Symlink permission bits are intrinsically 0777, checked separately.
            row.update(type='symlink',target=os.readlink(path));nodes.append(row)
        else:raise ValueError('native-runtime-special-file')
    visit('',0)
    result={'schemaVersion':1,'root':root,'nodes':nodes};nar.validate_descriptor(result)
    return result,witnesses

def recheck_inventory(witnesses,deadline):
    for path,witness in witnesses:
        compilation.tick(deadline);s=path.lstat()
        require((s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==witness)

def nar_hex(value):
    require(type(value) is str and value.startswith('sha256:'))
    encoded=value[7:]
    if re.fullmatch('[0-9a-f]{64}',encoded):return encoded
    alphabet='0123456789abcdfghijklmnpqrsvwxyz'
    require(len(encoded)==52 and all(c in alphabet for c in encoded))
    number=0
    for c in encoded:number=number*32+alphabet.index(c)
    require(number<2**256)
    return number.to_bytes(32,'little').hex()

def verify_closure(proof,pt_interp,deadline):
    require(type(proof) is dict and proof.get('schema_version')==1
        and proof.get('status')=='registered-linux-nix-runtime-closure-proof-candidate'
        and proof.get('native_support') is False and proof.get('loader_lookup_qualified') is False
        and proof.get('target')=='x86_64-linux' and proof.get('original_interpreter')==pt_interp)
    rows=proof['registration_rows'];roots=[row['path'] for row in rows]
    require(0<len(roots)<=MAX_ROOTS and len(set(roots))==len(roots)
        and {r['path'] for r in proof['roots']}==set(roots)
        and all(STORE.fullmatch(root) is not None for root in roots))
    for row in rows:
        require(set(row)=={'path','narHash','narSize','references'}
            and type(row['narSize']) is int and 0<row['narSize']<=MAX_CLOSURE_BYTES
            and type(row['references']) is list and len(set(row['references']))==len(row['references'])
            and set(row['references'])<=set(roots))
    loader_root='/'.join(pt_interp.split('/')[:4]);require(loader_root in roots)
    # All declared roots must be reachable from interpreter/dependency file roots.
    files=proof['files'];require(0<len(files)<=32)
    seeds={'/'.join(row['path'].split('/')[:4]) for row in files}
    require(loader_root in seeds and seeds<=set(roots))
    pending=list(seeds);seen=set();by_root={row['path']:row for row in rows}
    while pending:
        compilation.tick(deadline);root=pending.pop()
        if root not in seen:seen.add(root);pending.extend(by_root[root]['references'])
    require(seen==set(roots))
    total=0;inventories=[]
    for row in rows:
        desc,witnesses=descriptor(row['path'],deadline)
        result=nar.hash_descriptor(desc,deadline=deadline)
        total+=result['narSize'];require(total<=MAX_CLOSURE_BYTES
            and result['narSize']==row['narSize']
            and result['narHash']=='sha256:'+nar_hex(row['narHash']))
        recheck_inventory(witnesses,deadline)
        # A second inventory detects added/removed entries, not just old nodes.
        again,_=descriptor(row['path'],deadline);require(again==desc)
        inventories.append((desc,witnesses))
    for row in files:
        require(STORE.fullmatch('/'.join(row['path'].split('/')[:4])) is not None)
        raw=compilation.read_bytes(row['path'],row['sha256'],deadline,MAX_CLOSURE_BYTES)
        require(len(raw)==row['bytes'])
    aliases=proof['aliases'];require(len(aliases)<=32)
    by_alias={row['path']:row for row in aliases};require(len(by_alias)==len(aliases))
    resolved=pt_interp;visited=set()
    while resolved in by_alias:
        compilation.tick(deadline);require(resolved not in visited);visited.add(resolved)
        row=by_alias[resolved];p=Path(resolved)
        require(p.is_absolute() and '..' not in p.parts and p.is_symlink()
            and os.readlink(p)==row['target'])
        target=Path(row['target'])
        resolved=os.path.normpath(str(target if target.is_absolute() else p.parent/target))
        require('/'.join(resolved.split('/')[:4]) in roots)
    loader=[row for row in files if row['path']==resolved];require(len(loader)==1)
    return loader[0],inventories

class RegisteredImage:
    def __init__(self,image,image_identity,loader,loader_identity,inputs,deadline,revalidate):
        self.image=image;self.loader=loader;self.image_identity=image_identity
        self.loader_identity=loader_identity;self.inputs=inputs;self.deadline=deadline
        self.revalidate=revalidate;self.closed=False
    def check_identity(self):
        """Bounded held inode/deadline fence, not a full material qualification."""
        compilation.tick(self.deadline);require(not self.closed
            and identity(self.image)==self.image_identity and identity(self.loader)==self.loader_identity
            and self.image_identity[:2]!=self.loader_identity[:2])
    def check(self):
        self.check_identity()
        self.revalidate();compilation.tick(self.deadline)
    def close(self):
        if not self.closed:
            self.closed=True
            try:os.close(self.image)
            finally:os.close(self.loader)

def register(document,selection,package,deadline):
    """Only actual compiler + exact successful package outer proof can enter."""
    import codex_native_acquisition_runtime_qualification as runtime
    import codex_native_acquisition_material as material
    require(type(package) is dict and set(package)=={'root','producer','receipt','registration','outputs'})
    material.declared_controller(deadline)
    outer=material.producer_success({'root':package['root'],'producer':package['producer']},
        PACKAGE_TARGET,'fresh-native-runtime',deadline)
    inputs=runtime.compiled_inputs(document,selection,deadline)
    require(Path(package['outputs']['path'])==Path(package['root'])/'package-outputs.json')
    inventory=compilation.read_json(package['outputs']['path'],package['outputs']['sha256'],deadline)
    evidence=compilation.read_json(Path(package['producer']['receipt']).parent/'test-evidence.json',
        outer['test_evidence']['sha256'],deadline)
    member=next(row for row in evidence['results'] if row['target']==PACKAGE_TARGET)
    log=next(row for row in member['files'] if row['source']=='test.log')
    rawlog=compilation.read_bytes(Path(package['producer']['receipt']).parent/'test-evidence'/log['file'],
        log['sha256'],deadline)
    markers=re.findall(rb'^omux-native-package-output-sha256=([0-9a-f]{64})$',rawlog,re.M)
    require(markers==[package['outputs']['sha256'].encode()]
        and inventory['kind']=='omux-native-acquisition-package-output-v1'
        and inventory['purpose']=='evaluation-only' and inventory['acquisitionContract']=='unsupported'
        and set(inventory['files'])=={'fresh-native-runtime.tar.gz','runtime-manifest.json',
            'runtime-receipt.json','registration-receipt.json','package-selection.json'})
    for name,row in inventory['files'].items():
        raw=compilation.read_bytes(Path(package['root'])/name,row['sha256'],deadline,
            MAX_CLOSURE_BYTES if name.endswith('.tar.gz') else 16*1024*1024)
        require(len(raw)==row['bytes'])
    require(inventory['files']['runtime-receipt.json']['sha256']==package['receipt']['sha256']
        and inventory['files']['registration-receipt.json']['sha256']==package['registration']['sha256'])
    package_selection=compilation.read_json(Path(package['root'])/'package-selection.json',
        inventory['files']['package-selection.json']['sha256'],deadline)
    values,schemas,evidence_bytes=material.load_inputs(package_selection,
        lambda role,row,maximum:compilation.read_bytes(row['path'],row['sha256'],deadline,maximum))
    material.validate_chain(package_selection,values,schemas,evidence_bytes,deadline=deadline)
    require(package_selection['compilation']['result']==selection
        and compilation.read_json(package_selection['compilation']['selection']['path'],
            package_selection['compilation']['selection']['sha256'],deadline)==document)
    receipt=compilation.read_json(package['receipt']['path'],package['receipt']['sha256'],deadline)
    require(Path(package['receipt']['path'])==Path(package['root'])/'runtime-receipt.json'
        and Path(package['registration']['path'])==Path(package['root'])/'registration-receipt.json'
        and receipt['kind']=='omux-native-source-acquisition-fresh-native-package-v1'
        and receipt['launchProfile']=='linux_nix_direct_main_v1' and receipt['purpose']=='evaluation-only'
        and receipt['status']=='experimental-qualified-native-runtime' and receipt['provider_evaluation'] is False
        and receipt['acquisitionContract']=='unsupported' and receipt['native_support'] is False
        and receipt['producer_target']==PACKAGE_TARGET
        and receipt['executable']['original_sha256']==inputs['primary_elf_sha256']
        and receipt['runtime']['original_interpreter']==inputs['pt_interp']
        and receipt['runtime']['registration_receipt_sha256']==package['registration']['sha256'])
    proof=compilation.read_json(package['registration']['path'],package['registration']['sha256'],deadline)
    loader,inventories=verify_closure(proof,inputs['pt_interp'],deadline)
    compiled=compilation.read_json(selection['path'],selection['sha256'],deadline)
    image=next(row for row in compiled['artifacts'] if row['role']=='native-cli')
    fd,ident=held_file(image['path'],image['sha256'],deadline,512*1024*1024)
    interp=None
    try:
        require(ident[2]&0o111!=0 and ident[2]&0o022==0)
        interp,interp_ident=held_file(loader['path'],loader['sha256'],deadline,MAX_CLOSURE_BYTES)
        def revalidate():
            require(runtime.compiled_inputs(document,selection,deadline)==inputs)
            require(material.producer_success({'root':package['root'],'producer':package['producer']},
                PACKAGE_TARGET,'fresh-native-runtime',deadline)==outer)
            compilation.read_json(package['receipt']['path'],package['receipt']['sha256'],deadline)
            compilation.read_json(package['registration']['path'],package['registration']['sha256'],deadline)
            compilation.read_json(package['outputs']['path'],package['outputs']['sha256'],deadline)
            for name,row in inventory['files'].items():
                raw=compilation.read_bytes(Path(package['root'])/name,row['sha256'],deadline,
                    MAX_CLOSURE_BYTES if name.endswith('.tar.gz') else 16*1024*1024)
                require(len(raw)==row['bytes'])
            after_values,after_schemas,after_evidence=material.load_inputs(package_selection,
                lambda role,row,maximum:compilation.read_bytes(row['path'],row['sha256'],deadline,maximum))
            material.validate_chain(package_selection,after_values,after_schemas,after_evidence,deadline=deadline)
            for desc,witnesses in inventories:
                recheck_inventory(witnesses,deadline)
                require(descriptor(desc['root'],deadline)[0]==desc)
        result=RegisteredImage(fd,ident,interp,interp_ident,inputs,deadline,revalidate)
        result.check();return result
    except BaseException:
        os.close(fd)
        if interp is not None:os.close(interp)
        raise

def process_start(pid,deadline):
    compilation.tick(deadline)
    with Path('/proc/'+str(pid)+'/stat').open('rb') as stream:raw=stream.read(8193)
    require(len(raw)<=8192 and b') ' in raw)
    fields=raw.rsplit(b') ',1)[1].split();require(len(fields)>=20)
    return int(fields[19])

class OwnedChild:
    """Original direct child only; external guardian still owns descendant tree.

    This component has no ordinary-resume command selector. The rollout authority
    must supply its exact reviewed argv to launch; registration alone never does.
    """
    def __init__(self,registered,cleanup_deadline=None):
        require(isinstance(registered,RegisteredImage));self.registered=registered
        require(type(registered.deadline) is float and math.isfinite(registered.deadline))
        require(cleanup_deadline is None or (type(cleanup_deadline) is float
            and math.isfinite(cleanup_deadline) and cleanup_deadline==registered.deadline+30))
        self._cleanup_deadline=registered.deadline if cleanup_deadline is None else cleanup_deadline
        self.pid=None;self.pidfd=None;self.start=None;self.reaped=False;self.status=None
        self.go_attempted=False;self.go_released=False;self.cleanup_failure=None
        self.stdin=None
        self.descriptor_cleanup_failure=None
    @property
    def cleanup_deadline(self):return self._cleanup_deadline
    def launch(self,argv,private_root):
        require(self.pid is None and argv==('codex','app-server')
            and isinstance(private_root,Path) and private_root.is_absolute())
        # No caller HOME/environment is accepted. These exact directories are
        # created fresh with synthetic nonauthority by the existing component.
        self.registered.check()
        import codex_native_acquisition_runtime_qualification as runtime
        self.context=runtime.isolated_context(private_root)
        self.private_root=private_root
        private_stat=private_root.lstat()
        self.private_identity=(private_stat.st_dev,private_stat.st_ino,private_stat.st_uid,private_stat.st_mode)
        compilation.tick(self.registered.deadline)
        config=('[omux_broker]\nbroker_socket = '+json.dumps(str(private_root/'runtime/adapter.sock'))+
            '\ncapability_path = '+json.dumps(str(self.context[2]))+'\n').encode('ascii')
        require(len(config)<=4096)
        with (private_root/'home/config.toml').open('xb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(config);stream.flush();os.fsync(stream.fileno())
        compilation.tick(self.registered.deadline)
        environment={key:str(private_root/name) for key,name in (
            ('HOME','home'),('XDG_RUNTIME_DIR','runtime'),('XDG_CACHE_HOME','cache'),
            ('XDG_CONFIG_HOME','config'),('XDG_STATE_HOME','state'))}
        environment['CODEX_HOME']=environment['HOME']
        cwd=private_root
        read=write=stdin_read=null=None
        try:
            read,write=os.pipe2(os.O_CLOEXEC)
            stdin_read,self.stdin=os.pipe2(os.O_CLOEXEC)
            null=os.open('/dev/null',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            require(stat.S_ISCHR(os.fstat(null).st_mode))
            require(min(read,write,stdin_read,self.stdin,null)>=3)
            self.pid=os.fork()
            if self.pid==0:
                try:
                    os.close(write)
                    os.close(self.stdin)
                    if os.read(read,1)!=b'G':os._exit(125)
                    os.close(read);os.dup2(stdin_read,0);os.dup2(null,1);os.dup2(null,2)
                    os.close(stdin_read);os.close(null);os.chdir(cwd)
                    os.execve(self.registered.image,argv,environment)
                except BaseException:os._exit(125)
            os.close(read);read=None
            os.close(stdin_read);stdin_read=None;os.close(null);null=None
            self.pidfd=os.pidfd_open(self.pid,0)
            self.start=process_start(self.pid,self.registered.deadline)
            self.registered.check();self.go_attempted=True
            require(os.write(write,b'G')==1)
            self.go_released=True
            return self
        except BaseException as primary:
            # Closing GO makes an unadmitted child exit without executing image.
            if write is not None:os.close(write);write=None
            try:self.close()
            except BaseException as cleanup:
                self.cleanup_failure=cleanup
                primary.add_note('native-runtime-owned-child-cleanup-incomplete')
            raise
        finally:
            if read is not None:os.close(read)
            if write is not None:os.close(write)
            if stdin_read is not None:os.close(stdin_read)
            if null is not None:os.close(null)
            if self.pid is None and self.stdin is not None:os.close(self.stdin);self.stdin=None
    def fence(self,peer):
        require(self.pidfd is not None and not self.reaped)
        require(not select.select([self.pidfd],[],[],0)[0])
        require(process_start(self.pid,self.registered.deadline)==self.start)
        # Full check remains mandatory BEFORE connect and AFTER closed exchange.
        # Accepted native packets have a fixed eight-second cutoff; inside that
        # window only original held-image/process/kernel peer fences run.
        self.registered.check_identity()
        peer.fence_child(self.pidfd)
    def capture_peer(self,bridge,connection):
        """Already-registered image; caller brackets connection with full check.

        No parsed metadata/acquisition result becomes authority until caller
        closes the connection and repeats registered.check. It owns cleanup of
        every received right if that final qualification refuses.
        """
        import codex_native_acquisition_peer as native
        self.registered.check_identity()
        peer=native.Peer(bridge,connection,self.registered.image,self.registered.deadline)
        try:self.fence(peer);return peer
        except BaseException:peer.close();raise
    def reap(self):
        require(self.pid is not None)
        if self.reaped:return self.status
        pid,status=os.waitpid(self.pid,os.WNOHANG)
        if pid==0:return None
        require(pid==self.pid);self.reaped=True;self.status=os.waitstatus_to_exitcode(status)
        return self.status
    def close(self):
        if self.pid is None:return
        if self.descriptor_cleanup_failure is not None:
            raise self.descriptor_cleanup_failure
        # Cleanup consumes only original clock reserve, never extends deadline.
        cutoff=self.cleanup_deadline
        try:
            if not self.reaped:
                if self.pidfd is None:
                    # Pre-GO pidfd acquisition failure: child cannot execute, reap
                    # that exact fork child; never signal by reused numeric pid.
                    require(not self.go_attempted and not self.go_released)
                    while self.reap() is None:
                        compilation.tick(cutoff);time.sleep(min(.01,max(0,cutoff-time.monotonic())))
                else:
                    if not select.select([self.pidfd],[],[],0)[0]:
                        signal.pidfd_send_signal(self.pidfd,signal.SIGKILL,None,0)
                    ready=select.select([self.pidfd],[],[],max(0,cutoff-time.monotonic()))[0]
                    require(bool(ready));require(self.reap() is not None)
            self.cleanup_failure=None
        except BaseException as failure:
            self.cleanup_failure=failure
            raise
        finally:
            # An interrupted/expired cleanup retains original process custody.
            # A later bounded attempt may use that same pidfd and same cutoff;
            # it can never fall back to a numeric-PID signal or pre-GO branch.
            if self.reaped:
                # Consume each owned handle exactly once after actual reap. A
                # Linux close error can already have released the fd; retrying
                # that number could close an unrelated subsequently-opened fd.
                pidfd,stdin=self.pidfd,self.stdin;self.pidfd=self.stdin=None
                failure=None
                try:
                    if pidfd is not None:
                        try:os.close(pidfd)
                        except BaseException as error:failure=error
                finally:
                    if stdin is not None:
                        try:os.close(stdin)
                        except BaseException as error:
                            if failure is None:failure=error
                            else:failure.add_note('native-runtime-stdin-close-also-refused')
                if failure is not None:
                    self.descriptor_cleanup_failure=self.cleanup_failure=failure
                    raise failure
