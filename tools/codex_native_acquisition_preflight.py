"""Ninth material plan and genuine offline target query; never compiles a candidate."""
import json
import os
from pathlib import Path
import sys
import time
import codex_native_acquisition_binding as binding
import codex_native_acquisition_material as material
import codex_native_acquisition_metadata as metadata
import codex_native_acquisition_compilation as compilation

source=binding.source

def require(value):
    if value is not True:raise ValueError('native-acquisition-preflight-refused')

def selected_material():
    value=binding.config()
    sdk=value['sdk']
    require(type(sdk) is dict and set(sdk)=={'root','receipt_sha256','inventory_sha256','producer'})
    document={'schema_version':1,'kind':material.INPUT_KIND,'source':value['source'],'sdk':sdk,
        'controller_source_commit':sdk['producer']['source_commit'],
        'controller_graph_sha256':sdk['producer']['graph_sha256']}
    return material.validate_selection(document)

def compact(source_report,sdk_report):
    return {'source_inventory_sha256':source_report['inventory_sha256'],
        'sdk_inventory_sha256':sdk_report['inventory_sha256'],
        'mapping_sha256':sdk_report['mapping_sha256'],'patch_sha256':source_report['patch_sha256']}

def query_plan(work,document,exported):
    material.validate_selection(document)
    require(isinstance(work,Path) and work.is_absolute()
        and exported['registry_cache']==document['sdk']['root']+'/registry-cache'
        and metadata.metadata.HUB in exported['repositories'])
    argv=[metadata.BAZEL,'--batch','--output_user_root='+str(work/'user-root'),
        '--output_base='+str(work/'output-base'),'--host_jvm_args=-Xmx768m',
        '--host_jvm_args=-XX:ActiveProcessorCount=1','--ignore_all_rc_files','query',
        '--lockfile_mode=error','--repository_disable_download',
        '--repository_cache='+exported['registry_cache'],'--repo_contents_cache=',
        '--disk_cache=','--remote_executor=','--remote_cache=','--bes_backend=',
        '--loading_phase_threads=2','--repo_env=PATH='+metadata.LOCKED_PATH,
        '--repo_env=CARGO_NET_OFFLINE=true']
    for name,path in sorted(exported['repositories'].items()):
        require(type(name) is str and metadata.re.fullmatch(r'[A-Za-z0-9._+~-]{1,256}',name) is not None
            and path==document['sdk']['root']+'/repositories/'+name)
        argv.append('--override_repository='+name+'='+path)
    argv+=['--output=label','set('+ ' '.join(compilation.TARGETS)+')']
    env={'PATH':metadata.LOCKED_PATH,'USE_BAZEL_VERSION':'9.0.1','CARGO_NET_OFFLINE':'true',
        'HOME':str(work/'home'),'CARGO_HOME':str(work/'home/cargo'),
        'XDG_CACHE_HOME':str(work/'home/cache'),'XDG_CONFIG_HOME':str(work/'home/config'),
        'XDG_STATE_HOME':str(work/'home/state'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    plan={'argv':argv,'environment':env,'cwd':document['source']['root']+'/source'}
    require(plan['argv'].count('query')==1 and not any(token in ('build','test','run') for token in plan['argv']))
    return plan

def controller_inputs(qualified,source_report,sdk_report):
    # Digest of fully read tool descriptor/NAR mapping plus material graph. This
    # is input closure, not a process/custody/installation qualification.
    value={'schema_version':1,'kind':'omux-native-acquisition-controller-inputs-v1',
        'query_selection_sha256':qualified['selection_sha256'],
        'query_mapping_sha256':qualified['mapping_sha256'],
        'query_tools':qualified['query_tools'],'material':compact(source_report,sdk_report)}
    return source.sha(source.encoded(value))

def produce(mode,document,work,output,deadline,repository):
    require(mode in ('plan','query') and type(deadline) is float and time.monotonic()<deadline
        and not work.exists() and not output.exists())
    source.DEADLINE=metadata.DEADLINE=deadline
    metadata.configure_selection()
    qualified=metadata.query_tools.verify_repository(repository,deadline)
    require(qualified['inputs_rechecked'] is True)
    report,_,_,exported,mappings=material.qualify_selection(document,deadline)
    controller=controller_inputs(qualified,report,exported)
    work.mkdir(mode=0o700)
    for name in ('home','home/cargo','home/cache','home/config','home/state'):
        (work/name).mkdir(mode=0o700)
    plan=query_plan(work,document,mappings)
    if mode=='query':require(metadata.execute_query(plan,output)==0)
    # Every byte/held parent/SDK graph/registry/JDK is independently read again.
    again=material.qualify_selection(document,deadline)
    after=metadata.query_tools.verify_repository(repository,deadline)
    require(again[0]==report and again[3]==exported and after==qualified
        and selected_material()==document)
    value={'schema_version':1,'kind':'omux-native-acquisition-'+mode+'-qualification-v1',
        'material':compact(report,exported),'controller_inventory_sha256':controller,
        'caps':compilation.CAPS,'verb':'test','targets':list(compilation.TARGETS),
        'qualified':True,'exit':0,'closure_rechecked':True}
    output.mkdir(mode=0o700)
    fd=source.directory(output)
    try:
        out=os.open('receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'wb') as stream:
            stream.write(source.encoded(value));stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        raw,mode_bits=source.read(fd,'receipt.json',source.MAX_METADATA)
        require(raw==source.encoded(value) and mode_bits==0o444)
        source.tick();os.fsync(fd);os.fchmod(fd,0o555)
    finally:os.close(fd)
    return value

def main(mode):
    entry=float(time.monotonic())
    require(len(sys.argv)==1 and mode in ('plan','query'))
    seconds=min(840,int(os.environ['TEST_TIMEOUT'])-60);require(1<=seconds<=840)
    deadline=metadata.query_tools.consumer_deadline(entry,seconds)
    source.DEADLINE=metadata.DEADLINE=deadline
    try:
        # Genuine declared runfiles query repository is held and qualified by the
        # same mapper as metadata/SDK producers before any subprocess dispatch.
        metadata.configure_selection()
        metadata.declared_selection()
        require(metadata.QUERY_REPOSITORY is not None)
        document=selected_material()
        outputs=Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
        temporary=Path(os.environ['TEST_TMPDIR']).resolve(strict=True)
        produce(mode,document,temporary/('native-acquisition-'+mode),
            outputs/('native-acquisition-'+mode),deadline,metadata.QUERY_REPOSITORY)
    finally:source.DEADLINE=metadata.DEADLINE=None
