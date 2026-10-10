"""One externally bound, provider-free sealed workspace and declared NAR transfer."""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time
import zlib
import yoga_install_inputs_receiver as wire
import yoga_install_inputs_stage as prior
import yoga_sealed_transfer_receiver as receiver
import yoga_sealed_transfer_schema as schema
import guard_resident_owned_update as owned
import guard_yoga_installed_workspace as installed
import yoga_controller_delivery as delivery
import yoga_executable_qualification as qualification
import nar_descriptor as nar
from verify_cached_nars import parse_inventory, expected_hash
from ssh_policy import operator_config

ROOT = Path('/srv/fast-local/jess/git/oauth-mux-protocol-sdk-20261008')
LABEL = '//tools:yoga_sealed_transfer_stage'
MODE = 'stage-sealed-workspace'

class StoreRoot:
    """One exact declared store node, including inert regular/symlink roots."""
    def __init__(self,path,deadline,pin=None):
        schema.require(schema.STORE.fullmatch(path) is not None)
        self.path,self.deadline,self.fd=Path(path),deadline,None
        self.parent=wire.Directory(self.path.parent,deadline,immutable_tool=True)
        try:
            info=os.stat(self.path.name,dir_fd=self.parent.fd,follow_symlinks=False)
            schema.require(info.st_uid==0 and (stat.S_ISLNK(info.st_mode) or
                (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and not info.st_mode&0o222))
            self.pin=wire.file_identity(info)
            self.link=os.readlink(self.path.name,dir_fd=self.parent.fd) if stat.S_ISLNK(info.st_mode) else None
            if self.link is None:
                self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.parent.fd)
            schema.require(pin is None or pin==self.pin)
            self.check()
        except BaseException: self.close(); raise

    def check(self):
        wire.tick(self.deadline); self.parent.check()
        schema.require(self.pin==wire.file_identity(os.stat(self.path.name,dir_fd=self.parent.fd,follow_symlinks=False)))
        if self.fd is not None: schema.require(self.pin==wire.file_identity(os.fstat(self.fd)))
        else: schema.require(os.readlink(self.path.name,dir_fd=self.parent.fd)==self.link)

    def close(self):
        try:
            if self.fd is not None: os.close(self.fd); self.fd=None
        finally: self.parent.close()

class BoundedBackend(delivery.Backend):
    """Same finite policy/authority constructor; each SSH operation <=15s."""
    def call(self,script,bound=2*1024*1024,*,stage='authenticated-os-qualification'):
        self.known_hosts.check()
        cutoff=min(self.deadline,time.monotonic()+15)
        try:
            status,output,error=delivery.owned_io([self.ssh,*self.known_hosts.options(),
                *delivery.SSH_OPTIONS,*self.options,delivery.HOST,script],self.env,cutoff,bound)
            if status: raise delivery.ssh_failure(stage,status,error)
            schema.require(not error)
            return output
        finally: self.known_hosts.check()

def original_clock():
    entry=int(os.environ['OMUX_YOGA_SEALED_TRANSFER_ENTRY_NS'])
    deadline=int(os.environ['OMUX_YOGA_DELIVERY_DEADLINE_NS'])
    schema.require(entry>0 and deadline-entry==wire.MAX_NS
        and entry<=time.monotonic_ns()<deadline-wire.RESERVE_NS
        and os.environ.get('OMUX_YOGA_DELIVERY_MODE')==MODE)
    return entry,deadline

class Source:
    def __init__(self,raw,digest,deadline):
        self.deadline,self.held,self.capture=deadline,[],None
        self.public={}; self.root_pins={}
        self.raw,self.digest,self.value=raw,digest,schema.manifest(raw,digest)
        self.descriptors={}
        try:
            receipts={}
            for key,kind in (('selector','selector'),('workspaceProducer','workspace')):
                pin=self.value[key]
                data=self.read(pin['path'],schema.MAX_METADATA,deadline,expected=pin['sha256'])
                schema.require(len(data)==pin['bytes'])
                receipts[kind]=schema.decode(data)
                schema.producer(receipts[kind],pin,self.value,kind)
            selected={'path':schema.SOURCE+'/installed-workspace.json',
                      'sha256':self.value['workspaceReceipt']['sha256']}
            self.capture=installed.Capture(schema.SOURCE,selected,deadline,self.read)
            schema.require(len(self.capture.bytes('installed-workspace.json',schema.MAX_METADATA))==
                           self.value['workspaceReceipt']['bytes'])
            schema.workspace(self.capture.record,self.value)
            selector_root=Path(self.value['selector']['path']).parent/'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs/installed-toolbar-selection'
            selection_raw=self.read(selector_root/'selection.json',schema.MAX_METADATA,deadline,
                                    expected=self.value['selectedData']['sha256'])
            schema.require(len(selection_raw)==self.value['selectedData']['bytes'])
            schema.selected_join(schema.decode(selection_raw),self.capture.record,receipts['workspace'],self.value)
            merged={}
            for name in ('browser-inventory.json','controller-inventory.json'):
                raw_inventory=self.capture.bytes(name,schema.MAX_METADATA)
                # Actual selected inventory bytes must be the selector's outputs.
                schema.require(raw_inventory==self.read(selector_root/name,schema.MAX_METADATA,deadline,
                    expected=self.value['workspaceFiles'][name]['sha256']))
                for row in parse_inventory(raw_inventory,hashlib.sha256(raw_inventory).hexdigest()):
                    schema.require(row['path'] not in merged or merged[row['path']]==row)
                    merged[row['path']]=row
            self.inventory=[merged[name] for name in sorted(merged)]
            projected=[{'path':row['path'],'narSha256':expected_hash(row['narHash']),
                'narSize':row['narSize'],'references':row['references']} for row in self.inventory]
            schema.require(projected==self.value['narRows'])
            proof=self.value['evidence']['controller-nar-proof.json']
            evidence_raw=self.read(proof['path'],schema.MAX_METADATA,deadline,expected=proof['sha256'])
            schema.require(len(evidence_raw)==proof['bytes'])
            evidence=schema.decode(evidence_raw)
            schema.require(evidence.get('passed') is True and evidence.get('contentRehashed') is True
                and evidence.get('linkTargetsFollowed') is False
                and evidence.get('inventorySha256')==self.value['workspaceFiles']['controller-inventory.json']['sha256'])
            self.evidence_raw=evidence_raw
            total=0
            for row in self.value['narRows']:
                holder=StoreRoot(row['path'],deadline)
                try:
                    descriptor=nar.describe(row['path'])
                    total+=len(schema.canonical(descriptor)); schema.require(total<=64*1024**2)
                    hashed=nar.hash_descriptor(descriptor,deadline=deadline/10**9)
                    schema.require(expected_hash(hashed['narHash'])==row['narSha256'] and hashed['narSize']==row['narSize'])
                    holder.check(); self.descriptors[row['path']]=descriptor
                    self.root_pins[row['path']]=holder.pin
                finally: holder.close()
            self.check()
        except BaseException:
            self.close(); raise

    def read(self,path,maximum,deadline,*,expected):
        path=Path(path)
        # Call sites select only fixed workspace or manifest-bound public inputs.
        schema.require(str(path).startswith(schema.SOURCE+'/') or
            any(str(path).startswith(root+'/') for root in schema.PUBLIC))
        if str(path) in self.public:
            held=self.public[str(path)]; held.deadline=deadline; held.recheck()
        else:
            held=owned.PublicFile(path,deadline,maximum)
            self.held.append(held); self.public[str(path)]=held
        schema.require(len(held.raw)<=maximum)
        schema.require(hashlib.sha256(held.raw).hexdigest()==expected)
        return held.raw

    def check(self):
        wire.tick(self.deadline)
        if self.capture is not None: self.capture.recheck()
        for held in self.held:
            if isinstance(held,wire.Directory): held.check()
            else: held.recheck()

    def send(self,fd,deadline):
        self.check()
        wire.emit(fd,{'bytes':len(self.raw),'sha256':self.digest},deadline)
        wire.write_all(fd,self.raw,deadline)
        held_files={str(path.relative_to(Path(schema.SOURCE))):leaf for path,leaf,_ in self.capture.files}
        for name,size,digest,mode in schema.member_rows(self.value):
            self.check(); wire.emit(fd,{'role':name,'bytes':size,'sha256':digest},deadline)
            actual,count=hashlib.sha256(),0
            def emit(chunk):
                nonlocal count
                wire.tick(deadline); count+=len(chunk); schema.require(count<=size)
                actual.update(chunk); wire.write_all(fd,chunk,deadline)
            if name.startswith('workspace/'):
                source_fd=held_files[name[len('workspace/'):]]
                while count<size:
                    chunk=os.pread(source_fd,min(wire.FRAME,size-count),count)
                    schema.require(bool(chunk)); emit(chunk)
            elif name=='evidence/controller-nar-proof.json': emit(self.evidence_raw)
            else:
                root='/nix/store/'+Path(name).name[:-4]
                holder=StoreRoot(root,deadline,self.root_pins[root])
                try:
                    nar.serialize(self.descriptors[root],emit,deadline=deadline/10**9)
                    holder.check()
                finally: holder.close()
            schema.require(count==size and actual.hexdigest()==digest)
            self.check()
        wire.emit(fd,{'end':receiver.SCOPE},deadline)

    def close(self):
        failed=False
        if self.capture is not None:
            try: self.capture.close()
            except BaseException: failed=True
            self.capture=None
        held,self.held=self.held,[]
        for value in reversed(held):
            try: value.close()
            except BaseException: failed=True
        schema.require(not failed)

def bootstrap_source(value,deadline):
    modules=[]
    for name in schema.BOOTSTRAP:
        path=ROOT/'tools'/(name+'.py')
        held=owned.PublicFile(path,deadline,256*1024)
        try:
            schema.require(hashlib.sha256(held.raw).hexdigest()==value['bootstrapSha256'][name])
            modules.append((name,held.raw.decode('utf8'))); held.recheck()
        finally: held.close()
    raw=schema.canonical(modules)
    schema.require(0<len(raw)<=256*1024)
    compressed=base64.b64encode(zlib.compress(raw,9)).decode('ascii')
    # Both unit and OS bootstrap use this same bounded literal loader. The
    # compressed payload avoids Linux's 128KiB single-argument limit without
    # introducing code discovery, file writes or an unbounded decompression.
    loader='import sys,types,json,zlib,base64,hashlib\n'
    loader+='blob=base64.b64decode('+repr(compressed)+',validate=True)\n'
    loader+='d=zlib.decompressobj();raw=d.decompress(blob,262145)\n'
    loader+='assert len(raw)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n'
    loader+='assert hashlib.sha256(raw).hexdigest()=='+repr(hashlib.sha256(raw).hexdigest())+'\n'
    loader+='modules=json.loads(raw);assert [row[0] for row in modules]=='+repr(list(schema.BOOTSTRAP))+'\n'
    loader+='pins='+repr(value['bootstrapSha256'])+'\n'
    loader+='for name,source in modules:\n'
    loader+=' assert hashlib.sha256(source.encode()).hexdigest()==pins[name]\n'
    loader+=' m=types.ModuleType(name);sys.modules[name]=m\n'
    loader+=' exec(compile(source,name+".py","exec"),m.__dict__)\n'
    loader+='import yoga_sealed_transfer_receiver as receiver\nimport yoga_install_inputs_receiver as wire\n'
    loader+='receiver.INPUT_SHA256='+repr(os.environ['OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256'])+'\n'
    loader+='worker=receiver.worker\n'
    schema.require(len(loader.encode())<=60*1024)
    return loader

def program(source,expected,pins):
    # OS qualification code is a fixed source constant, separately passed as
    # JSON text; it is never taken from the transfer manifest or caller code.
    code=source+'\n'+'''
import os,time,subprocess
def bootstrap():
    seconds=int(sys.argv[1])
    wire.require(5<seconds<=1170,'bootstrap-budget')
    initial=time.monotonic_ns()+seconds*10**9
    expected=wire.decode(sys.argv[2]); pins=wire.decode(sys.argv[3]); qualifier=wire.decode(sys.argv[4])
    observed=subprocess.run(['/usr/bin/python3','-I','-S','-c',qualifier,
        str(min(15,seconds)),wire.canonical(expected).decode(),'null'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=min(15,wire.tick(initial)),env={'PATH':'','LANG':'C','LC_ALL':'C',
        'HOME':__import__('pwd').getpwuid(os.getuid()).pw_dir})
    wire.require(observed.returncode==0 and not observed.stderr and len(observed.stdout)<=8192
        and wire.decode(observed.stdout)==expected,'authenticated-host-changed')
    timestamp=time.monotonic_ns()
    os.set_blocking(0,False); os.set_blocking(1,False)
    wire.emit(1,{'scope':receiver.SCOPE,'phase':'clock','timestamp':timestamp,'host':expected},initial)
    request=wire.line(0,initial)
    wire.require(type(request) is dict and set(request)=={'token','work_deadline'},'clock-frame')
    receiver.coordinator(request['token'],timestamp,request['work_deadline'],SOURCE_TEXT,pins)
try: bootstrap()
except BaseException: sys.exit(125)
'''.replace('SOURCE_TEXT',repr(source))
    schema.require(len(code.encode())<=120*1024)
    return code

def transfer(backend,source,receiver_source,pins,entry,deadline):
    schema.require(type(backend) is BoundedBackend)
    token=source.value['transferId']; before=time.monotonic_ns()
    seconds=(deadline-before-wire.RESERVE_NS)//10**9
    schema.require(5<seconds<=1170)
    command='exec /usr/bin/python3 -I -S -c '+shlex.quote(program(receiver_source,backend.authority['remote'],pins))+' '+str(seconds)+' '+ \
        shlex.quote(wire.canonical(backend.authority['remote']).decode())+' '+ \
        shlex.quote(wire.canonical(pins).decode())+' '+shlex.quote(wire.canonical(qualification.REMOTE_CODE).decode())
    child=None; failed=False
    try:
        backend.known_hosts.check()
        child=subprocess.Popen([backend.ssh,*backend.known_hosts.options(),*delivery.SSH_OPTIONS,
            *backend.options,delivery.HOST,command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=backend.env)
        for stream in (child.stdin,child.stdout,child.stderr): os.set_blocking(stream.fileno(),False)
        work=deadline-wire.RESERVE_NS
        clock=wire.line(child.stdout.fileno(),min(work,time.monotonic_ns()+15*10**9))
        after=time.monotonic_ns()
        schema.require(type(clock) is dict and set(clock)=={'scope','phase','timestamp','host'}
            and clock['scope']==receiver.SCOPE and clock['phase']=='clock' and clock['host']==backend.authority['remote'])
        cutoff=wire.freeze_clock(clock['timestamp'],entry,deadline,before,after)
        wire.emit(child.stdin.fileno(),{'token':token,'work_deadline':cutoff},work)
        gate=wire.line(child.stdout.fileno(),min(work,time.monotonic_ns()+15*10**9))
        schema.require(type(gate) is dict and set(gate)=={'scope','phase','token','pid','start','uid',
            'caps_verified','physical_parent_verified','inputSha256'} and gate['scope']==receiver.SCOPE
            and gate['phase']=='go-ready' and gate['token']==token and gate['inputSha256']==source.digest
            and all(type(gate[key]) is int and gate[key]>1 for key in ('pid','start'))
            and type(gate['uid']) is int and gate['uid']==backend.authority['remote']['uid']
            and gate['caps_verified'] is gate['physical_parent_verified'] is True)
        source.check(); backend.known_hosts.check()
        wire.emit(child.stdin.fileno(),{'go':token,'scope':receiver.SCOPE,'inputSha256':source.digest},work)
        source.send(child.stdin.fileno(),work); child.stdin.close()
        receiver.INPUT_SHA256=source.digest
        worker=wire.line(child.stdout.fileno(),deadline)
        schema.exact_result(worker,receiver.result(source.value,'worker-readback'))
        final=wire.line(child.stdout.fileno(),deadline)
        schema.exact_result(final,dict(receiver.result(source.value,'complete'),token=token,receiverCleanupVerified=True))
        schema.require(child.wait(timeout=min(15,wire.tick(deadline)))==0
            and not os.read(child.stderr.fileno(),4096))
        source.check(); backend.known_hosts.check()
        schema.require(backend.qualify()==backend.authority['remote'])
        return final
    finally:
        if child is not None:
            try:
                if child.poll() is None: child.kill()
                child.wait(timeout=min(15,wire.tick(deadline)))
            except BaseException: failed=True
            for stream in (child.stdin,child.stdout,child.stderr):
                try: stream.close()
                except BaseException: failed=True
        schema.require(not failed)

def verify_destination(backend,rows):
    # Preserve the existing exact registry predicate and its finite 472-row
    # bound. The union is checked in disjoint requested batches, not relaxed.
    schema.require(0<len(rows)<=4096 and len({row['path'] for row in rows})==len(rows))
    for index in range(0,len(rows),delivery.REGISTRY_COUNT_BOUND):
        backend.verify(rows[index:index+delivery.REGISTRY_COUNT_BOUND])

def main(argv=None):
    parser=argparse.ArgumentParser()
    for name in ('inventory','receipt','bootstrap-manifest','known-hosts','authority'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--input',default=os.environ.get('OMUX_YOGA_SEALED_TRANSFER_INPUT'))
    parser.add_argument('--input-sha256',default=os.environ.get('OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256'))
    args=parser.parse_args(argv)
    entry,deadline=original_clock(); work=deadline-wire.RESERVE_NS
    schema.require(args.input_sha256==os.environ['OMUX_YOGA_SEALED_TRANSFER_INPUT_SHA256'])
    input_path=Path(args.input)
    schema.require(any(str(input_path).startswith(root+'/') for root in schema.PUBLIC))
    input_file=owned.PublicFile(input_path,work,schema.MAX_METADATA)
    source=None
    try:
        source=Source(input_file.raw,args.input_sha256,work)
        rows=delivery.selected(delivery.read_public(args.inventory,schema.MAX_METADATA,work/10**9),
            delivery.read_public(args.receipt,1024**2,work/10**9))
        bootstrap=delivery.read_public(args.bootstrap_manifest,2*1024**2,work/10**9)
        local=qualification.local_authority(bootstrap,rows,work)
        authority=delivery.strict_json(delivery.read_public(args.authority,16384,work/10**9))
        schema.require(hashlib.sha256(wire.canonical(authority)).hexdigest()==
            os.environ['OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'])
        qualification.remote_schema(authority['remote'])
        import yoga_delivery_settings
        yoga_delivery_settings.qualification(authority)
        remote_source=bootstrap_source(source.value,work)
        pins=prior.tool_pins(work)
        # Receiver's exact executables must be in the selected sealed closure.
        paths={row['path'] for row in source.inventory}
        schema.require(all(str(Path(*Path(path).parts[:4])) in paths for path in wire.TOOLS))
        with delivery.KnownHostAuthority(args.known_hosts,work/10**9) as known, operator_config(include_user=False) as policy:
            options=list(policy)+['-oHostname=100.104.152.110','-oUser=jsullivan2','-oProxyCommand=none','-oProxyJump=none']
            backend=BoundedBackend(qualification.SSH,options,work/10**9,dict(local,remote=authority['remote']),known)
            backend.env={'HOME':os.environ['HOME'],'SSH_AUTH_SOCK':'/omux-yoga-install-inputs/ssh-agent'}
            schema.require(backend.qualify()==authority['remote'])
            verify_destination(backend,source.inventory)
            result=transfer(backend,source,remote_source,pins,entry,deadline)
            # Registration AND destination content are independently rechecked.
            verify_destination(backend,source.inventory)
            schema.require(backend.qualify()==authority['remote'])
            result=dict(result,destinationRegistrationVerified=True,
                producerSourceCommit=source.value['producerSourceCommit'],
                producerGraphSha256=source.value['producerGraphSha256'],
                destinationWorkspace=source.value['destination']['workspace'])
        source.check(); input_file.recheck(); wire.tick(deadline)
        print(schema.canonical(result).decode('ascii')); return 0
    finally:
        if source is not None: source.close()
        input_file.close()

if __name__=='__main__':
    try: sys.exit(main())
    except BaseException:
        print('yoga-sealed-workspace-staging-refused',file=sys.stderr); sys.exit(125)
