"""Closed ninth material binding; no unproved output or legacy-family promotion."""
import copy
import json
import os
from pathlib import Path
import re
import sys
import time
import stat
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


def actual_source(value):
    # The complete original guardian/evidence policy is checked before role IO.
    from codex_native_acquisition_material import producer_success
    producer_success(value['source'],'//tools:codex_native_source_acquisition_source_producer',
        'native-source-acquisition-source',source.DEADLINE)
    witness=n9_witness();root=Path(value['source']['root'])
    source.require(str(root)==witness['root'])
    held=tree=receipt=None
    try:
        held=source.directory(root);tree=source.directory(root/'source')
        receipt=os.open('source-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=held)
        source.require(identity(os.fstat(held))==witness['root_identity']
            and identity(os.fstat(tree))==witness['source_root_identity']
            and identity(os.fstat(receipt))==witness['receipt_identity']
            and os.fstat(receipt).st_size==witness['receipt_bytes'])
        report,files=ninth.verify_output(root,value['source']['receipt_sha256'],value['source']['inventory_sha256'])
        source.require(identity(os.fstat(held))==witness['root_identity']
            and identity(os.fstat(tree))==witness['source_root_identity']
            and identity(os.fstat(receipt))==witness['receipt_identity'])
        for path,expected in ((root,witness['root_identity']),(root/'source',witness['source_root_identity'])):
            named=source.directory(path)
            try:source.require(identity(os.fstat(named))==expected)
            finally:os.close(named)
        named=os.open('source-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=held)
        try:source.require(identity(os.fstat(named))==witness['receipt_identity'])
        finally:os.close(named)
    finally:
        for descriptor in (receipt,tree,held):
            if descriptor is not None:os.close(descriptor)
    source.require(len(report['patch_sha256'])==9 and len(files)==8552
        and all(report[name] is False for name in ninth.FLAGS))
    return report,files


def bind(value=None):
    value=config() if value is None else value
    report,_=actual_source(value)
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
        source.require(mode in (0o444,0o555) and source.sha(raw)==row['sha256']
            and json.loads(raw,object_pairs_hook=source.unique)==bind(value))
        report,files=actual_source(value)
        _,baseline=ninth.parent.seventh.history.load_parent()
        again,again_mode=source.read(fd,Path(row['path']).name,source.MAX_METADATA)
        source.require(again==raw and again_mode==mode and config()==value)
        return report,files,baseline
    finally:os.close(fd)


def verify_hub_delta(before,after):
    # Original retained hub -> exact history correction + pinned v3 edges only.
    source.require(type(before) is dict and type(after) is dict and set(before)==set(after)
        and {'BUILD.bazel','defs.bzl','data.bzl'}<=set(before) and len(before)<=16
        and all(type(name) is str and '/' not in name and name not in ('','.','..')
            and type(raw) is bytes and len(raw)<=metadata.MAX_HUB_FILE for rows in (before,after) for name,raw in rows.items())
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
    source.require(len(sys.argv)==1 and os.environ.get('TEST_TIMEOUT') and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'))
    seconds=min(840,int(os.environ['TEST_TIMEOUT'])-60);source.require(1<=seconds<=840)
    source.DEADLINE=time.monotonic()+seconds
    try:
        report=bind();root=Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)/'native-acquisition-binding'
        root.mkdir(mode=0o700)
        fd=source.directory(root)
        try:
            writer=os.open('receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(writer,'wb') as stream:
                stream.write(source.encoded(report));stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
            os.fsync(fd)
            source.require(bind()==report)
            source.tick();os.fchmod(fd,0o555)
        finally:os.close(fd)
    finally:source.DEADLINE=None

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,IndexError):
        print('ninth source binding refused',file=sys.stderr);raise SystemExit(1) from None
