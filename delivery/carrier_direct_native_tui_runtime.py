"""Ordinary carrier PACKAGE evaluation from held declared compact evidence.

The genuine PACKAGE action owns full SDK/compiler qualification. This reader
does not reconstruct that pipeline or confer fleet/native/provider support.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import direct_native_tui_runtime as direct

TARGET='//tools:codex_native_carrier_runtime_package'
KIND='omux-native-carrier-native-package-selection-v2'
MAX_BYTES=512*1024*1024
MAX_ROWS=4096

def require(value):direct.require(value)

class HeldInputs:
    """Held physical aliases; every read joins original descriptor and name."""
    def __init__(self,root,deadline,until_ns):
        require(type(deadline) is float and type(until_ns) is int
            and deadline==until_ns/10**9)
        self.root=Path(root);self.deadline=deadline;self.until_ns=until_ns
        self.stack=ExitStack();self.parents={};self.files={};self.closed=False
        self.total=0
    def tick(self):
        direct.compiler.tick(self.deadline)
        require(time.monotonic_ns()<self.until_ns and not self.closed)
    def parent(self,path):
        path=Path(path)
        require(path.is_absolute() and '..' not in path.parts and str(path)==str(path.resolve(strict=True)))
        if path not in self.parents:
            # Reuse the declared-only nofollow ancestry owner, never a SOURCE
            # Session or extraction. It retains every opened ancestor witness.
            import codex_native_carrier_material as custody
            import codex_native_sdk_carrier as carrier
            clock=carrier.Clock(self.deadline);clock.until_ns=self.until_ns
            held=self.stack.enter_context(custody.DeclaredRoot(path,clock))
            self.parents[path]=held
        return self.parents[path]
    def add(self,alias,path,maximum,pin=None,size=None,*,generated_control=False):
        self.tick();path=Path(path);alias=self.root/alias
        require(alias.resolve(strict=True)==path and type(maximum) is int and 0<maximum<=MAX_BYTES)
        if path in self.files:
            row=self.files[path]
            require(alias not in row['aliases'] or alias.resolve(strict=True)==path)
            row['aliases'].add(alias)
            if pin is not None:require(row['pin']==pin and row['size']==size)
            return
        require(len(self.files)<MAX_ROWS)
        parent=self.parent(path.parent);fd,witness=parent.open(path.name)
        self.stack.callback(os.close,fd)
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()
            and stat.S_IMODE(s.st_mode) in ((0o444,0o555,0o644) if generated_control else (0o444,0o555)) and 0<s.st_size<=maximum
            and self.total+s.st_size<=MAX_BYTES)
        self.total+=s.st_size
        row={'fd':fd,'identity':direct.process.identity(fd),'parent':parent,
            'aliases':{alias},'size':s.st_size,'maximum':maximum,'pin':None}
        self.files[path]=row
        raw=self.raw(path)
        digest=hashlib.sha256(raw).hexdigest()
        if pin is not None:require(digest==pin and len(raw)==size)
        row['pin']=digest
    def fence(self,path,row):
        self.tick();row['parent'].check()
        require(all(alias.resolve(strict=True)==path for alias in row['aliases'])
            and direct.process.identity(row['fd'])==row['identity'])
        s=os.stat(path.name,dir_fd=row['parent'].fd,follow_symlinks=False)
        require((s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns)==row['identity'])
    def raw(self,path):
        path=Path(path);require(path in self.files);row=self.files[path]
        self.fence(path,row);chunks=[];offset=0
        while offset<row['size']:
            self.tick();chunk=os.pread(row['fd'],min(65536,row['size']-offset),offset)
            require(bool(chunk));chunks.append(chunk);offset+=len(chunk)
        raw=b''.join(chunks);self.fence(path,row)
        if row['pin'] is not None:require(hashlib.sha256(raw).hexdigest()==row['pin'])
        return raw
    def read(self,path,pin,deadline,maximum=16*1024*1024):
        require(deadline==self.deadline and Path(path) in self.files)
        row=self.files[Path(path)];require(row['pin']==pin and row['size']<=maximum)
        return self.raw(path)
    def read_json(self,path,pin,deadline,maximum=16*1024*1024):
        return json.loads(self.read(path,pin,deadline,maximum),object_pairs_hook=direct.tui.strict_object)
    def recheck(self):
        for path in sorted(self.files):self.raw(path)
        self.fence_all()
    def fence_all(self):
        for path,row in self.files.items():self.fence(path,row)
        self.tick()
    def close(self):
        if not self.closed:
            self.closed=True;self.stack.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def selected_rows(selection):
    direct.material.validate_paths(selection)
    require(selection['kind']==KIND)
    rows=dict(selection['files'])
    for group,prefix in (('protocol_schema_files','schema/'),('native_acquisition_artifact_files','evidence/')):
        rows.update({prefix+name:row for name,row in selection[group].items()})
    for action,group in selection['authority_receipts'].items():
        prefix='authority/'+action+'/'
        rows[prefix+'outer']=group['outer'];rows[prefix+'evidence']=group['evidence']
        rows.update({prefix+name:row for name,row in group['members'].items()})
    import codex_native_carrier_material as carrier_material
    rows.update(carrier_material.package_extra_rows(selection))
    require(0<len(rows)<=MAX_ROWS and sum(row['bytes'] for row in rows.values())<=MAX_BYTES)
    return rows

class CarrierDirectReader(direct.DirectReader):
    """One held compact PACKAGE owner spans bootstrap, TUI and cold resume."""
    def __init__(self,pin,sha,deadline,*,entry_ns,original_deadline_ns):
        require(type(entry_ns) is int and type(original_deadline_ns) is int
            and original_deadline_ns-entry_ns==1200*10**9
            and deadline==(original_deadline_ns-30*10**9)/10**9
            and entry_ns<=time.monotonic_ns()<original_deadline_ns-30*10**9)
        super().__init__(pin,sha,deadline)
        suffix='/testlogs/tools/codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime'
        require(self.package['root'].endswith(suffix))
        self.owner=HeldInputs(self.pin.parent,deadline,original_deadline_ns-30*10**9)
        self.entry_ns=entry_ns;self.original_deadline_ns=original_deadline_ns
        try:
            # These declarations carry candidate bytes. Only the independent
            # selected genuine outer proof+marker below authenticates outputs.
            self.owner.add('input-pin.json',self.pin,65536,sha,len(self.owner_read_pin()),generated_control=True)
            producer=self.package['producer'];outer=Path(producer['receipt'])
            self.owner.add('package-guardian.json',outer,direct.MAX_METADATA,producer['sha256'],outer.stat().st_size)
            guardian=self.owner.read_json(outer,producer['sha256'],deadline)
            index=outer.parent/'test-evidence.json'
            self.owner.add('package-evidence.json',index,direct.MAX_METADATA,guardian['test_evidence']['sha256'],index.stat().st_size)
            evidence=self.owner.read_json(index,guardian['test_evidence']['sha256'],deadline)
            results=[row for row in evidence['results'] if row['target']==TARGET]
            require(len(results)==1)
            members=results[0]['files']
            require(2<=len(members)<=4 and len({row['source'] for row in members})==len(members)
                and all(row['source'] in ('test.log','test.xml','test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
                    for row in members))
            required=[row for row in members if row['source'] in ('test.log','test.xml')]
            require(len(required)==2 and {row['source'] for row in required}=={'test.log','test.xml'})
            for n,row in enumerate(required):
                require(row['state']=='copied' and re.fullmatch(r'[0-9a-f]{64}\.evidence',row['file']) is not None)
                self.owner.add('package-evidence-'+str(n),outer.parent/'test-evidence'/row['file'],
                    direct.MAX_METADATA,row['sha256'],row['bytes'])
            self.outer=direct.material.producer_success(self.package,TARGET,'fresh-native-runtime',deadline,declared=self.owner)
            log_row=next(row for row in required if row['source']=='test.log')
            log=self.owner.read(outer.parent/'test-evidence'/log_row['file'],log_row['sha256'],deadline)
            root=Path(self.package['root'])
            self.owner.add('package-outputs.json',root/'package-outputs.json',65536)
            self.inventory=direct.deployment.closed_inventory(self.owner.raw(root/'package-outputs.json'),log)
            for name,row in self.inventory['files'].items():
                self.owner.add(name,root/name,256*1024*1024 if name.endswith('.tar.gz') else direct.MAX_METADATA,
                    row['sha256'],row['bytes'])
            selection=json.loads(self.owner.raw(root/'package-selection.json'),object_pairs_hook=direct.tui.strict_object)
            rows=selected_rows(selection)
            for n,(role,row) in enumerate(sorted(rows.items())):
                self.owner.add('selected-'+str(n),row['path'],row['bytes'],row['sha256'],row['bytes'])
            self.selection=selection
            mapping=self.pin.parent/'runtime-closure-inputs.json'
            self.owner.add('runtime-closure-inputs.json',mapping,16*1024*1024,generated_control=True)
            self.owner.recheck()
        except BaseException:self.owner.close();raise
    def owner_read_pin(self):return direct.retained.public_runtime_file(self.pin,65536)
    def load(self):
        self.owner.tick()
        require(direct.selected_pin(self.owner.raw(self.pin),self.sha)==self.package)
        require(direct.material.producer_success(self.package,TARGET,'fresh-native-runtime',self.deadline,
            declared=self.owner)==self.outer)
        root=Path(self.package['root'])
        files={name:self.owner.raw(root/name) for name in self.inventory['files']}
        require(json.loads(files['package-selection.json'],object_pairs_hook=direct.tui.strict_object)==self.selection)
        receipt=json.loads(files['runtime-receipt.json'],object_pairs_hook=direct.tui.strict_object)
        require(receipt['kind']==direct.DIRECT_KIND and receipt['purpose']=='evaluation-only'
            and receipt['acquisitionContract']=='unsupported' and receipt['native_support'] is False
            and receipt['provider_evaluation'] is False and receipt['launchProfile']=='linux_nix_direct_main_v1'
            and receipt['producer_target']==TARGET and receipt['selection_sha256']==
                hashlib.sha256(files['package-selection.json']).hexdigest()
            and receipt['chain']['material_family']=='native-carrier-acquisition-evaluation-v2')
        manifest,archive_files=direct.fresh.verify_runtime_files(files['fresh-native-runtime.tar.gz'],
            receipt,files['registration-receipt.json'])
        require(direct.fresh.encoded(manifest)==files['runtime-manifest.json'])
        proof=json.loads(files['registration-receipt.json'],object_pairs_hook=direct.tui.strict_object)
        self.closure_aliases(proof)
        loader,inventories=direct.process.verify_closure(proof,manifest['runtime']['original_interpreter'],self.deadline)
        self.closure_aliases(proof,inventories=inventories)
        require(loader==proof['files'][proof['interpreter_file_index']])
        self.owner.recheck()
        self.final_closure(inventories)
        self.closure_alias_fence()
        self.owner.fence_all()
        self.closure_inventories=inventories
        return manifest,archive_files,proof,self.inventory
    def closure_aliases(self,proof,*,inventories=None):
        roots=[row['path'] for row in proof['registration_rows']]
        require(0<len(roots)<=direct.process.MAX_ROOTS and len(set(roots))==len(roots)
            and all(direct.process.STORE.fullmatch(path) is not None for path in roots))
        mapping=json.loads(self.owner.raw(self.pin.parent/'runtime-closure-inputs.json'),
            object_pairs_hook=direct.tui.strict_object)
        require(type(mapping) is dict and set(mapping)=={'schema_version','kind','roots','members',
                'original_entry_monotonic_ns','original_deadline_monotonic_ns'}
            and type(mapping['schema_version']) is int and mapping['schema_version']==1
            and mapping['kind']=='omux-direct-carrier-runtime-closure-inputs-v1' and mapping['roots']==roots
            and type(mapping['original_entry_monotonic_ns']) is int
            and mapping['original_entry_monotonic_ns']==self.entry_ns
            and type(mapping['original_deadline_monotonic_ns']) is int
            and mapping['original_deadline_monotonic_ns']==self.original_deadline_ns
            and type(mapping['members']) is list and len(mapping['members'])<=direct.process.MAX_NODES)
        if not hasattr(self,'closure_witnesses'):
            self.closure_witnesses={};self.closure_parents={}
        paths=set();aliases=set()
        for row in mapping['members']:
            self.owner.tick()
            require(type(row) is dict and set(row)=={'alias','path'} and type(row['path']) is str
                and type(row['alias']) is str and row['path'] not in paths and row['alias'] not in aliases)
            root='/'.join(row['path'].split('/')[:4]);require(root in roots)
            relative=row['path'][len(root)+1:]
            require(bool(relative) and all(part not in ('','.','..') for part in relative.split('/'))
            expected='runtime-closure/root-'+str(roots.index(root))+'/'+relative
            require(row['alias']==expected and (self.pin.parent/expected).resolve(strict=True)==Path(row['path']))
            alias=self.pin.parent/expected
            selected=self.path_witness(alias)
            if alias in self.closure_witnesses:require(self.closure_witnesses[alias]==selected)
            else:self.closure_witnesses[alias]=selected
            parent=alias.parent
            while parent!=self.pin.parent:
                self.owner.tick();witness=self.path_witness(parent)
                if parent in self.closure_parents:require(self.closure_parents[parent]==witness)
                else:self.closure_parents[parent]=witness
                parent=parent.parent
            paths.add(row['path']);aliases.add(row['alias'])
        if inventories is not None:
            require(len(inventories)==len(roots))
            actual={descriptor['root']+'/'+row['path'] for descriptor,_ in inventories
                for row in descriptor['nodes'] if row['type']=='regular'}
            require(paths==actual)
        self.owner.tick()
    def path_witness(self,path):
        self.owner.tick();info=path.lstat()
        require(info.st_uid in (0,os.getuid()) and (stat.S_ISLNK(info.st_mode) or not info.st_mode&0o022))
        return ((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
                 info.st_size,info.st_mtime_ns,info.st_ctime_ns),
                os.readlink(path) if stat.S_ISLNK(info.st_mode) else None)
    def closure_alias_fence(self):
        for table in (self.closure_parents,self.closure_witnesses):
            for path,witness in table.items():require(self.path_witness(path)==witness)
        self.owner.tick()

    def verify_process(self,native,binary):
        super().verify_process(native,binary)
        self.final_closure(self.closure_inventories)
        self.closure_alias_fence();self.owner.fence_all();native.alive()

    def final_closure(self,inventories):
        # Compact readback can be long. Preserve each original NAR inventory's
        # physical witnesses and complete namespace beyond that work.
        for descriptor,witnesses in inventories:
            current,_=direct.process.descriptor(descriptor['root'],self.deadline)
            require(current==descriptor)
            direct.process.recheck_inventory(witnesses,self.deadline)
        self.owner.tick()

    def finish(self):
        # The original fixture's last native checkpoint cannot authorize a
        # later drift during history/configuration or private-bus cleanup.
        self.load();self.owner.fence_all()
    def close(self):self.owner.close()

