"""Closed ninth material binding; no unproved output or legacy-family promotion."""
import copy
import json
import os
from pathlib import Path
import re
import sys
import time
import stat
from contextlib import ExitStack
from types import MappingProxyType
import codex_native_source_acquisition_source as ninth
import codex_protocol_history_metadata as metadata
import codex_protocol_history_native as protocol

source=ninth.source
KIND='omux-native-source-acquisition-metadata-binding-v1'
INPUT_KIND='omux-native-source-acquisition-metadata-input-v1'
CONFIG='integrations/codex-upstream/native-acquisition-inputs.json'
N9_WITNESS='integrations/codex-upstream/native-acquisition-n9-binding.json'
N9_WITNESS_SHA='57ba94f7c6a5c5b0c3b37dd88bca5a6a01bc971c2bd4e6332bd98b4b50bd9796'
EXPORT_ROOT=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export')
EXPORT_SHA='1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0'
ROOTS=r'(?:/home/jess/\.local/state/omux-execution-20261005|/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)'
SOURCE_SCOPE=re.compile(ROOTS+r'/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/output-base/execroot/_main/bazel-out/[A-Za-z0-9_-]+/testlogs/tools/codex_native_source_acquisition_source_producer/test.outputs/native-source-acquisition-source\Z')
BINDING_SCOPE=re.compile(ROOTS+r'/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/output-base/execroot/_main/bazel-out/[A-Za-z0-9_-]+/testlogs/tools/codex_native_acquisition_binding_producer/test.outputs/native-acquisition-binding/receipt.json\Z')
PHASE='input'
PHASES=frozenset(('input','guardian','third','fourth','fifth','sixth','seventh','eighth','ninth',
    'publication','input-readback','third-readback','fifth-readback','sixth-readback',
    'seventh-readback','ninth-readback','guardian-readback','receipt-readback','terminal'))


def phase(name):
    global PHASE
    source.require(type(name) is str and name in PHASES)
    PHASE=name


def refusal_message():
    selected=PHASE if type(PHASE) is str and PHASE in PHASES else 'input'
    return 'ninth source binding refused at '+selected


def config():
    raw=ninth.parent.declared(CONFIG,16384)
    value=json.loads(raw,object_pairs_hook=source.unique)
    source.require(type(value) is dict and set(value)=={'schema_version','kind','status','source','binding','metadata','sdk','compile'}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['kind']=='omux-native-source-acquisition-input-configuration-v1'
        and value['status']=='actual-ninth-source-pinned')
    row=value['source']
    source.require(type(row) is dict and set(row)=={'root','receipt_sha256','inventory_sha256','producer'}
        and type(row['root']) is str and SOURCE_SCOPE.fullmatch(row['root']))
    protocol.pin(row['receipt_sha256']);protocol.pin(row['inventory_sha256']);protocol.producer_pin(row['producer'])
    witness=n9_witness()
    source.require(row['root']==witness['root'] and row['receipt_sha256']==witness['receipt_sha256']
        and row['inventory_sha256']==witness['inventory_sha256'])
    return value


def n9_witness():
    raw=ninth.parent.declared(N9_WITNESS,16384)
    source.require(source.sha(raw)==N9_WITNESS_SHA)
    value=json.loads(raw,object_pairs_hook=source.unique)
    source.require(value['kind']==ninth.KIND and value['tracked_files']==8552
        and len(value['patch_sha256'])==9 and value['all_future_qualification_false'] is True)
    return value


def identity(info):
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
        'mode':stat.S_IMODE(info.st_mode),'nlink':info.st_nlink}


class SealedSource:
    """Owned held roots/receipt plus complete physical sweeps; no reusable proof token."""
    def __init__(self,root,pin,*,size=None,modes=(0o555,)):
        self.root,self.pin,self.size,self.modes=Path(root),pin,size,modes
        self.held=self.tree=self.receipt=None
        self.files=self.raw=None

    @staticmethod
    def witness(fd):
        row=os.fstat(fd)
        return (row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,
            row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)

    def __enter__(self):
        try:
            self.held=source.directory(self.root);self.tree=source.directory(self.root/'source')
            self.receipt=os.open('source-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.held)
            source.require(all(stat.S_IMODE(os.fstat(fd).st_mode)==0o555 for fd in (self.held,self.tree)))
            info=os.fstat(self.receipt)
            source.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and info.st_nlink==1 and stat.S_IMODE(info.st_mode) in self.modes)
            self.anchors=tuple(self.witness(fd) for fd in (self.held,self.tree,self.receipt))
            self.raw=self.read_receipt()
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def __exit__(self,*unused):
        for name in ('receipt','tree','held'):
            fd=getattr(self,name)
            if fd is not None:
                os.close(fd);setattr(self,name,None)

    def check(self):
        source.tick()
        source.require(tuple(self.witness(fd) for fd in (self.held,self.tree,self.receipt))==self.anchors)
        for path,anchor in ((self.root,self.anchors[0]),(self.root/'source',self.anchors[1])):
            named=source.directory(path)
            try:source.require(self.witness(named)==anchor)
            finally:os.close(named)
        named=os.open('source-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.held)
        try:source.require(self.witness(named)==self.anchors[2])
        finally:os.close(named)

    def read_receipt(self):
        self.check()
        raw,mode=source.read(self.held,'source-receipt.json',source.MAX_METADATA)
        source.require(mode in self.modes and source.sha(raw)==self.pin
            and (self.size is None or len(raw)==self.size))
        self.check()
        return raw

    def accept(self,expected,files,*,canonical=True,tree_already_verified=False):
        source.require(self.files is None and json.loads(self.raw,object_pairs_hook=source.unique)==expected)
        if canonical:source.require(source.sha(source.encoded(expected))==self.pin)
        self.files=MappingProxyType(dict(files))
        if not tree_already_verified:source.verify_written(self.root/'source',self.files)
        source.require(self.read_receipt()==self.raw)

    def recheck(self):
        source.require(self.files is not None)
        self.check()
        source.verify_written(self.root/'source',self.files)
        source.require(self.read_receipt()==self.raw)


class SourceProofSession:
    """One exact linear reconstruction, then every ancestor's original-clock readback."""
    def __init__(self,value):
        self.value=copy.deepcopy(value)
        self.deadline=source.DEADLINE
        self.stack=ExitStack();self.snapshots=[];self.patches=[]
        self.entered=self.finished=False
        self.active=False

    def tick(self):
        source.require(type(self.deadline) is float and source.DEADLINE==self.deadline)
        source.tick()

    def capture(self,name,root,pin,**kwargs):
        self.tick()
        source.require(name in ('third','fifth','sixth','seventh','ninth')
            and name not in {existing for existing,_ in self.snapshots} and len(self.snapshots)<5)
        captured=self.stack.enter_context(SealedSource(root,pin,**kwargs))
        self.snapshots.append((name,captured))
        return captured

    def patch(self,reader):
        source.require(len(self.patches)<8)
        self.tick();raw=reader();self.patches.append((reader,raw))
        return raw

    def guardian(self):
        self.tick()
        from codex_native_acquisition_material import producer_success
        producer_success(self.value['source'],'//tools:codex_native_source_acquisition_source_producer',
            'native-source-acquisition-source',self.deadline)

    def join_n5(self,captured):
        for fd,key,regular in ((captured.held,'root_identity',False),
                (captured.tree,'source_root_identity',False),(captured.receipt,'receipt_identity',True)):
            source.require(ninth.binding.identity(fd,regular)==self.n5_witness[key])

    def join_n9(self,captured):
        for fd,key in ((captured.held,'root_identity'),(captured.tree,'source_root_identity'),
                (captured.receipt,'receipt_identity')):
            source.require(identity(os.fstat(fd))==self.n9_witness[key])
        source.require(os.fstat(captured.receipt).st_size==self.n9_witness['receipt_bytes'])

    def __enter__(self):
        source.require(not self.entered)
        self.entered=self.active=True
        try:
            self.tick();phase('guardian');self.guardian()
            self.n5_config,self.n5_witness=ninth.binding.load()
            self.n9_witness=n9_witness()
            source.require(self.value==config() and self.value['source']['root']==self.n9_witness['root'])
            self.construct()
            for _,captured in self.snapshots:captured.check()
            self.tick()
            return self
        except BaseException:
            self.active=False;self.stack.close()
            raise

    def __exit__(self,*unused):
        self.active=False;self.stack.close()

    def construct(self):
        # Existing exact transforms and receipt constructors; none is replaced
        # by a receipt-only claim. Only the redundant recursive loads disappear.
        refresh=ninth.parent;seventh=refresh.seventh;sixth=seventh.parent
        persistence=sixth.successor;fifth=persistence.parent;status=seventh.status;history=seventh.history
        phase('third')
        base=self.capture('third',history.PARENT,history.PARENT_RECEIPT_SHA,modes=(history.PARENT_RECEIPT_MODE,))
        before,base_report=history.load_parent()
        base.accept(base_report,before,canonical=False,tree_already_verified=True)
        self.baseline=copy.deepcopy(base_report)
        phase('fourth')
        fourth=history.transform(before,self.patch(lambda:status.read_patch(history.PATCH_NAME)))
        phase('fifth')
        n1=self.capture('fifth',fifth.ROOT,fifth.RECEIPT_SHA,size=fifth.RECEIPT_BYTES)
        fifth_files=status.transform(fourth,self.patch(lambda:status.read_patch(status.PATCH_NAME)))
        fifth_report=fifth.expected_receipt(base_report,fourth,fifth_files)
        n1.accept(fifth_report,fifth_files)
        phase('sixth')
        n3=self.capture('sixth',sixth.ROOT,sixth.RECEIPT_SHA,size=sixth.RECEIPT_BYTES)
        source.require(source.sha(self.patch(lambda:status.read_patch(persistence.REVIEWED_NATIVE_NAME)))==persistence.REVIEWED_NATIVE_SHA)
        source.require(source.sha(self.patch(lambda:status.read_patch(persistence.NORMALIZED_NATIVE_NAME)))==persistence.NORMALIZED_NATIVE_SHA)
        sixth_files=persistence.transform(fifth_files,self.patch(lambda:status.read_patch(persistence.PATCH_NAME)))
        sixth_report=persistence.expected_receipt(fifth_report,sixth_files)
        source.require(sixth_report['inventory_sha256']==sixth.INVENTORY_SHA
            and len(sixth_files)==sixth.SOURCE_MEMBERS
            and sum(len(raw) for _,raw in sixth_files.values())==sixth.SOURCE_BYTES)
        n3.accept(sixth_report,sixth_files)
        phase('seventh')
        n5=self.capture('seventh',self.n5_config['root'],self.n5_config['receipt_sha256'],size=self.n5_config['receipt_bytes'])
        self.join_n5(n5)
        seventh_files=seventh.transform(sixth_files,self.patch(seventh.read_patch))
        seventh_report=seventh.expected_receipt(sixth_report,seventh_files)
        refresh.validate_parent(seventh_report,seventh_files,self.n5_config)
        n5.accept(seventh_report,seventh_files)
        phase('eighth')
        eighth_files=refresh.transform(seventh_files,self.patch(refresh.read_patch))
        eighth_report=refresh.expected_receipt(seventh_report,eighth_files,self.n5_config)
        source.require(len(eighth_report['patch_sha256'])==8 and all(eighth_report[name] is False for name in refresh.FLAGS))
        phase('ninth')
        n9=self.capture('ninth',self.value['source']['root'],self.value['source']['receipt_sha256'],
            size=self.n9_witness['receipt_bytes'],modes=(0o444,0o555))
        self.join_n9(n9)
        ninth_files=ninth.transform(eighth_files,self.patch(ninth.read_patch))
        expected=ninth.expected_receipt(eighth_report,ninth_files,self.n5_config)
        source.require(expected['inventory_sha256']==self.value['source']['inventory_sha256']
            and len(expected['patch_sha256'])==9 and len(ninth_files)==8552
            and all(expected[name] is False for name in ninth.FLAGS))
        n9.accept(expected,ninth_files)
        self.source_report=copy.deepcopy(expected);self.source_files=n9.files
        self.report=binding_report(self.value,expected)

    def initial_report(self):
        self.tick();source.require(self.active and self.entered and not self.finished)
        return copy.deepcopy(self.report)

    def finish(self):
        self.tick();source.require(self.active and self.entered and not self.finished
            and [name for name,_ in self.snapshots]==['third','fifth','sixth','seventh','ninth'])
        phase('input-readback')
        source.require(config()==self.value and ninth.binding.load()==(self.n5_config,self.n5_witness)
            and n9_witness()==self.n9_witness)
        for reader,raw in self.patches:
            self.tick();source.require(reader()==raw)
        for name,captured in self.snapshots:
            phase(name+'-readback');self.tick();captured.recheck()
            if name=='seventh':self.join_n5(captured)
            elif name=='ninth':self.join_n9(captured)
        phase('guardian-readback');self.guardian()
        phase('input-readback')
        source.require(config()==self.value and ninth.binding.load()==(self.n5_config,self.n5_witness)
            and n9_witness()==self.n9_witness)
        for reader,raw in self.patches:
            self.tick();source.require(reader()==raw)
        for _,captured in self.snapshots:captured.check()
        self.tick();self.finished=True
        return copy.deepcopy(self.report)


def actual_source(value):
    with SourceProofSession(value) as proof:
        proof.finish()
        return copy.deepcopy(proof.source_report),dict(proof.source_files)


def bind(value=None):
    value=config() if value is None else value
    report,_=actual_source(value)
    return binding_report(value,report)


def binding_report(value,report):
    return {'schema_version':1,'kind':KIND,'status':'verified-ninth-source-binding-pending-metadata-sdk-compile',
        'metadata_input':{'kind':INPUT_KIND,'source_root':value['source']['root'],
            'source_receipt_sha256':value['source']['receipt_sha256'],'source_inventory_sha256':value['source']['inventory_sha256'],
            'export_root':str(EXPORT_ROOT),'export_receipt_sha256':EXPORT_SHA},
        'source':value['source'],'source_graph':report['graph_files'],'patch_sha256':report['patch_sha256'],
        'source_reconstructed_and_fully_read':True,'sdk_materials_revalidated':False,
        'sdk_export_qualified':False,'native_compile_passed':False,'schema_producer_qualified':False,
        'native_support':False,'provider_evaluation':False,'credential_acquisition_qualified':False,'live_handoff_proven':False}


def selected_document(value=None):
    value=config() if value is None else value
    row=value['binding']
    source.require(type(row) is dict and set(row)=={'path','sha256','producer'}
        and type(row['path']) is str and BINDING_SCOPE.fullmatch(row['path']))
    protocol.pin(row['sha256']);protocol.producer_pin(row['producer'])
    document={'kind':INPUT_KIND,'source_root':value['source']['root'],
        'source_receipt_sha256':value['source']['receipt_sha256'],
        'source_inventory_sha256':value['source']['inventory_sha256'],
        'export_root':str(EXPORT_ROOT),'export_receipt_sha256':EXPORT_SHA}
    return {**document,'binding_receipt_sha256':row['sha256']}


def load_verified_source(document):
    value=config();expected=selected_document(value)
    source.require(document==expected)
    from codex_native_acquisition_material import producer_success
    # Binding output is a file; use the exact test.outputs parent role for join.
    row=value['binding'];parent=Path(row['path']).parent
    producer_success({'root':str(parent),'producer':row['producer']},
        '//tools:codex_native_acquisition_binding_producer','native-acquisition-binding',source.DEADLINE)
    fd=source.directory(parent)
    try:
        raw,mode=source.read(fd,Path(row['path']).name,source.MAX_METADATA)
        source.require(mode in (0o444,0o555) and source.sha(raw)==row['sha256'])
        with SourceProofSession(value) as proof:
            source.require(json.loads(raw,object_pairs_hook=source.unique)==proof.initial_report())
            proof.finish()
            again,again_mode=source.read(fd,Path(row['path']).name,source.MAX_METADATA)
            source.require(again==raw and again_mode==mode and config()==value)
            return copy.deepcopy(proof.source_report),dict(proof.source_files),copy.deepcopy(proof.baseline)
    finally:os.close(fd)


def verify_hub_delta(before,after):
    # Original retained hub -> exact history correction + pinned v3 edges only.
    source.require(type(before) is dict and type(after) is dict and set(before)==set(after)
        and {'BUILD.bazel','defs.bzl','data.bzl'}<=set(before) and len(before)<=16
        and all(type(name) is str and '/' not in name and name not in ('','.','..')
            and type(raw) is bytes and len(raw)<=metadata.MAX_HUB_FILE for rows in (before,after) for name,raw in rows.items()))
    source.require(all(before[name]==after[name] for name in before if name!='data.bzl'))
    old=metadata.dep_data(before['data.bzl']);new=metadata.dep_data(after['data.bzl']);expected=copy.deepcopy(old)
    row=expected[metadata.PACKAGE]
    source.require(row['deps'].count(metadata.ROLLOUT)==1 and row['deps'].count(metadata.HISTORY)==1
        and row['aliases'].get(metadata.ROLLOUT)=='codex_rollout' and row['aliases'].get(metadata.HISTORY)=='codex_history')
    row['deps'].remove(metadata.ROLLOUT);del row['aliases'][metadata.ROLLOUT]
    app=expected['codex-rs/app-server'];hmac='@crates//:hmac-0.12.1'
    additions=(hmac,'@crates//:libc-0.2.186','@crates//:zeroize-1.8.2')
    source.require(app['dev_deps'].count(hmac)==1 and all(name not in app['deps'] for name in additions))
    app['dev_deps'].remove(hmac);app['deps']=sorted(app['deps']+list(additions))
    source.require(new==expected)
    return True


def main():
    phase('input')
    source.require(len(sys.argv)==1 and os.environ.get('TEST_TIMEOUT') and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'))
    seconds=min(840,int(os.environ['TEST_TIMEOUT'])-60);source.require(1<=seconds<=840)
    source.DEADLINE=time.monotonic()+seconds
    try:
        with SourceProofSession(config()) as proof:
            report=proof.initial_report()
            phase('publication')
            root=Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)/'native-acquisition-binding'
            root.mkdir(mode=0o700)
            fd=source.directory(root)
            try:
                writer=os.open('receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
                with os.fdopen(writer,'wb') as stream:
                    stream.write(source.encoded(report));stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
                os.fsync(fd)
                output_identity=identity(os.fstat(fd))
                source.require(proof.finish()==report)
                phase('receipt-readback')
                raw,mode=source.read(fd,'receipt.json',source.MAX_METADATA)
                source.require(mode==0o444 and raw==source.encoded(report))
                named=source.directory(root)
                try:source.require(identity(os.fstat(named))==output_identity==identity(os.fstat(fd)))
                finally:os.close(named)
                phase('terminal');proof.tick();os.fchmod(fd,0o555)
            finally:os.close(fd)
    finally:source.DEADLINE=None

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,IndexError):
        print(refusal_message(),file=sys.stderr);raise SystemExit(1) from None
