"""Two fixed selected-SDK native gates. No historical cache/receipt admission.

The guard is the only launcher. No selector, successful pin or chain is created
by importing this module. One chain owns two dispatches and one original clock.
"""
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import codex_live_source as source
import codex_protocol_history_metadata as delta
import codex_protocol_history_metadata_producer as inputs
import codex_protocol_history_sdk_export as selected_sdk
import codex_retained_sdk_export as sdk
import codex_native_profile as native
import codex_native_staged_compilation as sealed_io
from codex_native_candidate_cache import controller_inventory
from codex_sdk_profile import metadata, require, hash_regular, verify_inventory, EXPORT_MODE_POLICY
from codex_fresh_source import trusted_parent

KIND = 'omux-protocol-history-native-checks-v1'
SELECTION_KIND = 'omux-protocol-history-native-selection-v1'
STATE = native.STATE
SELECTOR = STATE/'protocol-history-native-selection.json'
CHAIN = STATE/'protocol-history-native-chain.json'
JOURNAL = 'protocol-history-native-journal.json'
ARTIFACTS = 'protocol-history-native-artifacts.json'
HASH = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
SOURCE_SCOPE = inputs.SOURCE_SCOPE
SDK_SCOPE = re.compile(inputs.SOURCE_SCOPE.pattern.replace(
    'codex_protocol_history_source_producer/test.outputs/protocol-history-source',
    'codex_protocol_history_sdk_export_producer/test.outputs/protocol-history-sdk-export'))
PRODUCER_SCOPE = re.compile(r'(?:/home/jess/\.local/state/omux-execution-20261005|'
    r'/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/'
    r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/receipt\.json\Z')
PROTOCOL = '//codex-rs/app-server-protocol:app-server-protocol-unit-tests'
CONFIG = native.CONFIG
GATES = {
    PROTOCOL: tuple('protocol::thread_history_projection::tests::'+name for name in (
        'projects_turn_lifecycle_without_prior_builder_state',
        'projects_failed_turn_completion_as_snapshot',
        'projects_completed_canonical_turn_items',
        'projects_optional_completed_item_lifecycle_timestamps',
        'ignores_legacy_abort_without_turn_id_and_context_only_records',
        'projects_identified_turn_aborts')) + (
        'protocol::thread_history::tests::changed_rollout_item_reports_turn_completion_metadata',
        'protocol::thread_history::tests::uses_explicit_turn_boundaries_for_mid_turn_steering',
        'protocol::thread_history::tests::ignores_plain_user_response_items_in_rollout_replay',
        'protocol::thread_history::tests::rebuilds_hook_prompt_items_from_rollout_response_items',
        'protocol::item_builders::tests::read_command_actions_preserve_native_and_foreign_paths',
        'protocol::item_builders::tests::guardian_stdin_reviews_preserve_parent_command_history',
        'schema_fixtures_tests::typescript_schema_fixtures_match_generated',
        'schema_fixtures_tests::json_schema_fixtures_match_generated',
        'schema_fixtures_tests::stable_precomputed_exports_match_schema_fixtures'),
    CONFIG: native.QUALIFICATION_GATES[CONFIG],
}
MODES = {
    'protocol-history-tests': ('test', (PROTOCOL, CONFIG), None),
    'protocol-history-schema': ('build', ('//bazel/schema:native-config-schema',
        '//bazel/schema:public-schema-bundle'), None),
}
STAGES = {1:'protocol-history-tests', 2:'protocol-history-schema'}
BAZEL = native.BAZEL
COMBINED_MODE = native.COMBINED_MODE
source_io = native.source_io
readonly_paths = native.readonly_paths
verify_readonly = native.verify_readonly
tick = native.tick
runtime = native.runtime


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def sha(value):return hashlib.sha256(value).hexdigest()


def pin(value):
    require(type(value) is str and HASH.fullmatch(value), 'selected SHA256 required')
    return value


def path(value):
    require(type(value) is str and Path(value).is_absolute() and str(Path(value)) == value
        and '..' not in Path(value).parts and not any(c.isspace() or c in ':\\' for c in value),
        'selected canonical pathname required')
    return Path(value)


def read_json(file, expected, deadline, maximum=16*1024*1024):
    pin(expected);tick(deadline)
    fd=trusted_parent(Path(file).parent)
    child=None
    try:
        child=os.open(Path(file).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        before=os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_gid==os.getgid()
            and before.st_nlink==1 and not before.st_mode & 0o7022
            and 0<before.st_size<=maximum, 'selected metadata custody refused')
        chunks=[];count=0
        while True:
            tick(deadline);value=os.read(child,1024*1024)
            if not value:break
            count+=len(value);require(count<=maximum, 'selected metadata grew');chunks.append(value)
        raw=b''.join(chunks)
        named_parent=trusted_parent(Path(file).parent)
        try:
            require((os.fstat(named_parent).st_dev,os.fstat(named_parent).st_ino)==(
                os.fstat(fd).st_dev,os.fstat(fd).st_ino), 'selected metadata ancestry changed')
        finally:os.close(named_parent)
        require(count==before.st_size and sha(raw)==expected
            and witness(before)==witness(os.fstat(child))==witness(os.stat(Path(file).name,dir_fd=fd,follow_symlinks=False)),
            'selected metadata bytes/witness changed')
        return json.loads(raw,object_pairs_hook=source.unique)
    finally:
        if child is not None:os.close(child)
        os.close(fd)


def producer_pin(value):
    require(type(value) is dict and set(value)=={
        'receipt','sha256','source_commit','graph_sha256'}, 'closed producer pin required')
    file=path(value['receipt']);pin(value['sha256']);pin(value['graph_sha256'])
    require(PRODUCER_SCOPE.fullmatch(str(file)) and file.name=='receipt.json' and UUID.fullmatch(file.parent.name)
        and re.fullmatch(r'[0-9a-f]{40}',value['source_commit']), 'producer epoch/source pin required')


def validate_selection(document):
    require(type(document) is dict and set(document)=={
        'schema_version','kind','source','sdk','controller_source_commit','controller_graph_sha256'},
        'closed selected native document required')
    require(type(document['schema_version']) is int and document['schema_version']==1
        and document['kind']==SELECTION_KIND
        and type(document['controller_source_commit']) is str
        and re.fullmatch(r'[0-9a-f]{40}',document['controller_source_commit']),
        'selected native kind/source required')
    pin(document['controller_graph_sha256'])
    for role in ('source','sdk'):
        row=document[role]
        require(type(row) is dict and set(row)=={'root','receipt_sha256','inventory_sha256','producer'},
            'closed selected source/SDK pin required')
        path(row['root']);pin(row['receipt_sha256']);pin(row['inventory_sha256']);producer_pin(row['producer'])
        require((SOURCE_SCOPE if role=='source' else SDK_SCOPE).fullmatch(row['root']),
            'selected source/SDK role namespace required before IO')
    require(document['source']['producer']['receipt']!=document['sdk']['producer']['receipt'],
        'source and SDK must have independent actual producer epochs')
    return document


def producer_success(selection, target, output_name, deadline):
    value=selection['producer'];receipt=read_json(path(value['receipt']),value['sha256'],deadline)
    sealed_io.verify_caps(receipt)
    native.phase2_effective_runtime(receipt['observed_properties']['RuntimeMaxUSec'],1200)
    require(receipt['id']==Path(value['receipt']).parent.name
        and receipt['unit']=='omux-execution-'+receipt['id']+'.service'
        and receipt['profile']=='standard' and receipt['manager']=='system'
        and type(receipt['exit']) is int and receipt['exit']==0
        and type(receipt['workload_exit']) is int and receipt['workload_exit']==0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['cleanup']['state']=='empty' and receipt['source_dirty']=='false'
        and receipt['source_commit']==value['source_commit']
        and receipt['graph_sha256']==value['graph_sha256']
        and receipt['verb']=='test' and receipt['targets']==[target]
        and receipt['test_evidence']['state']=='preserved', 'successful outer producer required')
    output=path(receipt['output_base']);root=path(selection['root'])
    prefix=str(output)+'/execroot/_main/bazel-out/'
    suffix='/testlogs/tools/'+target.split(':')[1]+'/test.outputs/'+output_name
    require(str(root).startswith(prefix) and str(root).endswith(suffix)
        and re.fullmatch(r'[A-Za-z0-9_.-]+',str(root)[len(prefix):-len(suffix)]),
        'selected output is not the actual producer test namespace')
    evidence=read_json(Path(value['receipt']).parent/'test-evidence.json',
        receipt['test_evidence']['sha256'],deadline)
    require(type(evidence['schema']) is int and evidence['schema']==1
        and type(evidence['bazel_exit']) is int and evidence['bazel_exit']==0
        and evidence['epoch_start_ns']==receipt['epoch_start_ns']
        and evidence['targets']==[target] and len(evidence['results'])==1,
        'producer evidence epoch/target mismatch')
    row=evidence['results'][0]
    require(row['target']==target and row['state']=='observed', 'producer evidence absent')
    for member in ('test.log','test.xml'):
        entries=[entry for entry in row['files'] if entry['source']==member]
        require(len(entries)==1 and entries[0]['state']=='copied', 'producer evidence not copied')
        entry=entries[0]
        require(re.fullmatch(r'[0-9a-f]{64}\.evidence',entry['file']), 'producer evidence name refused')
        fd=trusted_parent(Path(value['receipt']).parent/'test-evidence')
        try:
            digest,count,raw=hash_regular(fd,entry['file'],64*1024*1024,True,
                on_read=lambda count:tick(deadline))
            require(digest==entry['sha256'] and type(entry['bytes']) is int
                and count==entry['bytes'] and count>0, 'producer evidence changed')
            if member=='test.xml':
                xml=ET.fromstring(raw)
                suites=[xml] if xml.tag=='testsuite' else list(xml.findall('testsuite'))
                require(suites and all(int(suite.get('tests','0'))>0
                    and all(int(suite.get(name,'0'))==0 for name in ('failures','errors','skipped'))
                    for suite in suites) and xml.tag in ('testsuite','testsuites'),
                    'producer test XML lacks real successful cases')
        finally:os.close(fd)
    return receipt


SDK_FIELDS = frozenset(('schema_version','kind','status','metadata_receipt_sha256','metadata',
    'source_root','source_receipt_sha256','source_inventory_sha256','graph_files','mapping_sha256',
    'retained_export_root','retained_export_receipt_sha256','repositories','inventory_sha256',
    'modules','registry_metadata','nix_store_roots','nix_inventory','counts',
    'native_compile_passed','native_support','provider_evaluation'))
METADATA_FIELDS = frozenset(('schema_version','kind','status','selector_sha256','inputs',
    'source_inventory_sha256','source_graph','parent_export_inventory_sha256','module_lock_unchanged',
    'cargo_lock_unchanged','query_exit','query_plan','generated_hub','retained_hub',
    'source_and_export_rechecked','sdk_export_qualified','native_compile_passed','native_support','provider_evaluation'))


def validate_source(root, receipt_sha256, patch_pins, deadline=None):
    source.DEADLINE=deadline;inputs.DEADLINE=deadline
    document={'kind':inputs.KIND,'source_root':str(root),'source_receipt_sha256':receipt_sha256,
        'export_root':str(inputs.EXPORT_ROOT),'export_receipt_sha256':inputs.EXPORT_SHA}
    inputs.validate_document(document)
    report,_,_=inputs.load_candidate(document)
    require(report['patch_sha256']==list(patch_pins), 'selected source patch tuple differs')
    return report


def verify_selected_export(root, receipt_pin, source_report, document, deadline):
    source.DEADLINE=deadline;inputs.DEADLINE=deadline
    budget=sdk.Budget(time.time()+max(0.001,min(1200,deadline-time.monotonic())),lambda count:tick(deadline))
    report=read_json(root/'receipt.json',receipt_pin,deadline,64*1024*1024)
    require(type(report) is dict and set(report)==SDK_FIELDS
        and type(report['schema_version']) is int and report['schema_version']==1
        and type(report['metadata']) is dict and set(report['metadata'])==METADATA_FIELDS
        and type(report['metadata']['schema_version']) is int and report['metadata']['schema_version']==1
        and report['kind']==selected_sdk.KIND
        and report['source_root']==document['source']['root']
        and report['source_receipt_sha256']==document['source']['receipt_sha256']
        and report['source_inventory_sha256']==source_report['inventory_sha256']
        and report['inventory_sha256']==document['sdk']['inventory_sha256']
        and report['graph_files']==source_report['graph_files']
        and report['mapping_sha256']==source_report['graph_files']['MODULE.bazel.lock']['sha256']
        and type(report['counts']) is dict and set(report['counts'])=={'entries','bytes'}
        and type(report['counts']['bytes']) is int and 0<=report['counts']['bytes']<=sdk.MAX_BYTES
        and type(report['counts']['entries']) is dict
        and set(report['counts']['entries'])=={'qualification','copy','sealed_readback'}
        and all(type(value) is int and 0<=value<=sdk.MAX_FILES for value in report['counts']['entries'].values()),
        'selected SDK kind/source/graph binding refused')
    raw_metadata=read_json(root.parent/'protocol-history-metadata/metadata-receipt.json',
        report['metadata_receipt_sha256'],deadline)
    m=report['metadata']
    expected_inputs={'kind':inputs.KIND,'source_root':document['source']['root'],
        'source_receipt_sha256':document['source']['receipt_sha256'],
        'export_root':str(inputs.EXPORT_ROOT),'export_receipt_sha256':inputs.EXPORT_SHA}
    require(m==raw_metadata and m['inputs']==expected_inputs
        and m['status']=='verified-strict-regenerated-protocol-history-hub'
        and m['source_inventory_sha256']==source_report['inventory_sha256']
        and m['source_graph']==source_report['graph_files']
        and m['module_lock_unchanged'] is True and m['cargo_lock_unchanged'] is True
        and m['sdk_export_qualified'] is False
        and all(m[name] is False for name in ('native_compile_passed','native_support','provider_evaluation')),
        'selected strict metadata report mismatch')
    retained=selected_sdk.load_retained(budget)
    parent=inputs.history.load_parent()[1]
    qualified=sdk.validate_export(inputs.EXPORT_ROOT,inputs.EXPORT_SHA,
        source.BASE_INVENTORY,parent['baseline_graph_files'],on_read=lambda count:tick(deadline))
    require(m['parent_export_inventory_sha256']==qualified['inventory_sha256']
        and report['retained_export_root']==str(inputs.EXPORT_ROOT)
        and report['modules']==retained['modules']
        and report['registry_metadata']==retained['registry_metadata']
        and report['nix_inventory']==retained['nix_inventory']
        and report['nix_store_roots']==retained['nix_store_roots'], 'selected SDK changed retained module/store closure')
    old={row['canonical_name']:row for row in retained['repositories']}
    require(type(report['repositories']) is list and 0<len(report['repositories'])<=sdk.MAX_REPOS,
        'selected SDK bounded repositories required')
    new={row['canonical_name']:row for row in report['repositories']}
    require(len(new)==len(report['repositories']) and set(new)==set(old)
        and all(new[name]=={**old[name],'source_root':str(inputs.EXPORT_ROOT/'repositories'/name)}
            for name in old if name!=delta.HUB),
        'selected SDK changed an unrelated repository')
    old_hub=inputs.read_hub(inputs.EXPORT_ROOT/'repositories'/delta.HUB)
    new_hub=inputs.read_hub(root/'repositories'/delta.HUB)
    query_work=path(m['query_plan']['environment']['HOME']).parent
    require(delta.verify_hub_delta(old_hub,new_hub) is True
        and m['query_plan']==inputs.query_plan(query_work,query_work/'workspace/source',qualified)
        and m['generated_hub']=={name:{'sha256':sha(raw),'bytes':len(raw),'mode':0o444}
            for name,raw in sorted(new_hub.items())}
        and m['retained_hub']=={name:{'sha256':sha(raw),'bytes':len(raw)}
            for name,raw in sorted(old_hub.items())}, 'selected SDK strict hub delta/plan differs')
    require(selected_sdk.verify_export(root,report,budget) is True, 'selected SDK physical inventory refused')
    root_fd=trusted_parent(root)
    try:require(stat.S_IMODE(os.fstat(root_fd).st_mode)==0o555
        and set(os.listdir(root_fd))=={'repositories','graph','registry-cache','receipt.json'},
        'selected SDK extra root members or unsealed root')
    finally:os.close(root_fd)
    graph_names=set(report['graph_files'])
    directory_names={''}|{str(parent) for name in graph_names for parent in Path(name).parents
        if str(parent)!='.'}
    def graph_shape(relative=''):
        directory=root/'graph'/relative;fd=trusted_parent(directory)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o555, 'selected SDK graph directory unsealed')
            expected={name[len(relative)+1:].split('/')[0] if relative else name.split('/')[0]
                for name in graph_names if not relative or name.startswith(relative+'/')}
            require(set(os.listdir(fd))==expected, 'selected SDK physical graph set differs')
            for name in expected:
                child=relative+'/'+name if relative else name
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if child in directory_names:
                    require(stat.S_ISDIR(info.st_mode), 'selected SDK graph directory replaced')
                    graph_shape(child)
                else:require(child in graph_names and stat.S_ISREG(info.st_mode)
                    and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o444,
                    'selected SDK graph file custody refused')
        finally:os.close(fd)
    graph_shape()
    require(new[delta.HUB]['source_root']==str(root.parent/'protocol-history-metadata/hub')
        and new[delta.HUB]['source_files']==new[delta.HUB]['files']
        and new[delta.HUB]['source_inventory_sha256']==new[delta.HUB]['inventory_sha256'],
        'selected generated hub origin/inventory differs')
    repositories={name:str(root/'repositories'/name) for name in new}
    # Modules are byte-identical to the independently fully qualified parent;
    # actual module identities and declarations were checked by validate_export.
    module_overrides={name:repositories[pin['canonical_name']] for name,pin in report['modules'].items()}
    return {'repositories':repositories,'module_overrides':module_overrides,
        'inventory_sha256':report['inventory_sha256'],'mapping_sha256':report['mapping_sha256'],
        'graph_files':report['graph_files'],'registry_cache':str(root/'registry-cache'),
        'registry_inventory_sha256':report['registry_metadata']['inventory_sha256']}


def selected(args):
    values=(getattr(args,'native_protocol_history',None),
        getattr(args,'native_protocol_history_sha256',None),getattr(args,'native_protocol_stage',None))
    if not any(value is not None for value in values):return False
    require(all(value is not None for value in values)
        and args.profile=='codex-native' and args.manager=='system' and args.state_dir==STATE
        and Path(values[0])==SELECTOR and str(values[0])==str(SELECTOR)
        and type(values[2]) is int and values[2] in STAGES
        and args.native_mode==STAGES[values[2]] and args.native_owned_candidate_cache is False
        and args.reuse_owned_cache is False and all(getattr(args,name,None) is None for name in (
            'native_cache_attempt','native_cache_transition','native_cache_transition_sha256',
            'native_cache_phase2','native_cache_phase2_sha256','native_fresh_completion',
            'native_fresh_completion_sha256','native_global_attempt','native_staged_compilation',
            'native_staged_compilation_sha256','native_stage')), 'exclusive selected protocol-history lane required')
    pin(values[1]);return True


def verify_inputs(args):
    require(selected(args), 'distinct selected native inputs required')
    document=validate_selection(read_json(SELECTOR,args.native_protocol_history_sha256,args.native_deadline))
    require(document['source']['root']==str(args.native_source_root)
        and document['source']['receipt_sha256']==args.native_source_sha256
        and document['sdk']['root']==str(args.native_export_root)
        and document['sdk']['receipt_sha256']==args.native_export_sha256
        and document['controller_source_commit']==args.source_commit and args.source_dirty=='false',
        'selected native CLI/source mismatch')
    producer_success(document['source'],'//tools:codex_protocol_history_source_producer',
        'protocol-history-source',args.native_deadline)
    producer_success(document['sdk'],'//tools:codex_protocol_history_sdk_export_producer',
        'protocol-history-sdk-export',args.native_deadline)
    report=validate_source(args.native_source_root,args.native_source_sha256,args.native_patch_sha256,args.native_deadline)
    require(report['inventory_sha256']==document['source']['inventory_sha256'], 'source inventory differs')
    exported=verify_selected_export(args.native_export_root,args.native_export_sha256,report,document,args.native_deadline)
    return report,exported


def completion_deadline(args, original_entry_ns, candidate=None):
    require(type(candidate) is Admission and candidate.verified_before_launch is True
        and selected(args) and type(original_entry_ns) is int
        and original_entry_ns==candidate.action_entry_ns
        and type(args.native_aggregate_seconds) is int and args.native_aggregate_seconds==3600,
        'selected original chain clock requires actual Admission')
    tick(candidate.original_deadline_ns/10**9)
    return candidate.original_deadline_ns/10**9


def command(args, run, locked_path, bash, candidate=None):
    require(type(candidate) is Admission and candidate.authorize_native_mode(args) is True,
        'selected command requires actual fresh owner')
    return native.command_from_verified_inputs(args,run,locked_path,bash,candidate,
        verify_inputs(args),MODES,GATES)


def named_log(raw,target):
    expected=set(GATES[target])
    matches=re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)\r?$',raw,re.MULTILINE)
    require(len(matches)==len(expected) and all(status==b'ok' for _,status in matches)
        and len({name for name,_ in matches})==len(expected)
        and {name.decode('ascii') for name,_ in matches}==expected
        and re.findall(rb'test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;',raw)
            ==[(str(len(expected)).encode(),b'0',b'0')], 'selected exact native tests missing/failed/ignored')
    return sorted(expected)


def meaningful_tests(run,manifest,mode,context=None):
    require(mode==STAGES[1] and context is None
        and manifest['targets']==list(MODES[mode][1]) and len(manifest['results'])==len(GATES)
        and {row['target'] for row in manifest['results']}==set(GATES), 'selected exact test target set differs')
    logs={}
    for row in manifest['results']:
        entries=[entry for entry in row['files'] if entry['source']=='test.log']
        require(row['state']=='observed' and len(entries)==1 and entries[0]['state']=='copied',
            'selected actual native log missing')
        entry=entries[0]
        require(re.fullmatch(r'[0-9a-f]{64}\.evidence',entry['file']), 'selected native evidence name differs')
        fd=trusted_parent(Path(run)/'test-evidence')
        try:
            digest,_,raw=hash_regular(fd,entry['file'],64*1024*1024,True,
                on_read=lambda count:tick(source_io.DEADLINE))
            require(digest==entry['sha256'], 'selected native log changed')
            named_log(raw,row['target'])
        finally:os.close(fd)
        logs[row['target']]=sealed_io.artifact_file(Path(run)/'test-evidence'/entry['file'],
            source_io.DEADLINE,64*1024*1024)
    return logs


def boot_host():
    file=Path('/proc/sys/kernel/random/boot_id')
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
    try:raw=os.read(fd,64).decode('ascii').strip()
    finally:os.close(fd)
    require(UUID.fullmatch(raw), 'actual boot identity refused')
    return {'boot_id':raw,'host':os.uname().nodename,'uid':os.getuid(),'gid':os.getgid()}


def witness(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class Admission:
    def __init__(self,args,run,tools,graph,locked_path,manager,verify_previous,original_entry_ns):
        self.args,self.run,self.tools,self.graph=args,Path(run),dict(tools),graph
        self.locked_path,self.manager,self.verify_previous=locked_path,manager,verify_previous
        self.action_entry_ns=original_entry_ns
        self.stage=args.native_protocol_stage
        self.verified_before_launch=False;self.verified_after_cleanup=None
        self.root_fd=self.lock_fd=self.output_fd=self.chain_fd=self.input_fd=self.source_fd=None
        self.artifacts_sha=None;self.history=[];self.journal_sha=None;self.input_holds=[]
        try:
            require(selected(args) and self.run==STATE/self.run.name and UUID.fullmatch(self.run.name)
                and type(original_entry_ns) is int and original_entry_ns>=0
                and type(args.native_aggregate_seconds) is int and args.native_aggregate_seconds==3600,
                'selected owner finite new epoch required')
            # Read stage1's immutable clock BEFORE expensive input qualification.
            if self.stage==2:
                parent=trusted_parent(CHAIN.parent)
                try:
                    raw,_=source.read(parent,CHAIN.name,8192)
                    initial=json.loads(raw,object_pairs_hook=source.unique)
                finally:os.close(parent)
                self.validate_clock(initial)
                self.original_entry_ns=initial['original_entry_monotonic_ns']
                self.original_deadline_ns=initial['original_deadline_monotonic_ns']
            else:
                self.original_entry_ns=original_entry_ns
                self.original_deadline_ns=original_entry_ns+3600*10**9
            args.native_deadline=self.original_deadline_ns/10**9;tick(args.native_deadline)
            self.document=validate_selection(read_json(SELECTOR,args.native_protocol_history_sha256,args.native_deadline))
            # Outer pinned receipts bind role paths to their actual output_base
            # BEFORE opening any selected source/SDK role directory.
            for role,target,output in (('source','//tools:codex_protocol_history_source_producer','protocol-history-source'),
                ('sdk','//tools:codex_protocol_history_sdk_export_producer','protocol-history-sdk-export')):
                producer_success(self.document[role],target,output,args.native_deadline)
            for root in (Path(self.document['source']['root']),Path(self.document['sdk']['root']),inputs.EXPORT_ROOT):
                self.input_holds.append((root,inputs.hold_root(root)))
            qualified=verify_inputs(args)
            inventory=controller_inventory(Path.cwd(),graph,args.native_deadline)
            require(self.document['controller_graph_sha256']==graph[0]
                and manager=='system' and args.source_dirty=='false'
                and type(tools) is dict and set(tools)=={'bazel','python','systemd_run','systemctl',
                    'bootstrap','closure','java','bash'}
                and all(type(value) is str and value.startswith('/nix/store/')
                    and '..' not in Path(value).parts and not any(c.isspace() for c in value)
                    for value in tools.values()), 'selected actual controller/tools required')
            self.bindings={'kind':KIND,'selection':copy.deepcopy(self.document),
                'controller_inventory':inventory,'controller_graph':graph,'tools':dict(tools),
                'source_sdk_custody':{str(root):{'device':os.fstat(held[0]).st_dev,
                    'inode':os.fstat(held[0]).st_ino,'uid':os.fstat(held[0]).st_uid,
                    'gid':os.fstat(held[0]).st_gid,'mode':stat.S_IMODE(os.fstat(held[0]).st_mode)}
                    for root,held in self.input_holds},
                'locked_path':locked_path,'boot_host':boot_host(),'stages':STAGES,'gates':GATES,
                'limits':{'memory':4294967296,'swap':0,'tasks':512,'cpu_percent':200,
                    'jobs':1,'heap_mib':768,'processors':1,'chain_seconds':3600,'reserve_seconds':120},
                'network':'private','batch':True,'repository_download':False,
                'remote':False,'ambient_caches':False,'core_codegen':native.core_codegen_policy()}
            self.bindings=json.loads(canonical(self.bindings))
            self.key=sha(canonical(self.bindings))
            self.root=STATE/('protocol-history-checks-'+self.key)
            self.source=self.root/'native-input/source'
            self.lease=SimpleNamespace(output_base=self.root/'output-base')
            self.reserve_chain()
            parent=trusted_parent(STATE)
            try:
                if self.stage==1:os.mkdir(self.root.name,0o700,dir_fd=parent);os.fsync(parent)
                self.root_fd=os.open(self.root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            finally:os.close(parent)
            if self.stage==1:
                require(not os.listdir(self.root_fd), 'selected first root must be empty')
                self.lock_fd=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.root_fd)
            else:self.lock_fd=os.open('lock',os.O_RDWR|os.O_NOFOLLOW,dir_fd=self.root_fd)
            fcntl.flock(self.lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if self.stage==1:
                os.mkdir('output-base',0o700,dir_fd=self.root_fd)
                source_io.DEADLINE=args.native_deadline
                self.source=native.copy_source(args.native_source_root,qualified[0],self.root)
            self.output_fd=os.open('output-base',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            self.input_fd=os.open('native-input',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            self.source_fd=os.open('source',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.input_fd)
            self.custody=self.capture_custody()
            if self.stage==1:
                require(not os.listdir(self.output_fd), 'selected output base must be new and empty')
            else:self.admit_previous()
            self.write_journal('pending',self.history,first=self.stage==1)
            self.check_directories();self.recheck_inputs(qualified)
            self.args_snapshot=self.snapshot(args)
            self.verified_before_launch=True
        except BaseException:
            self.close();raise

    def validate_clock(self,document):
        require(type(document) is dict and set(document)=={'schema_version','kind','key','selector_sha256',
            'source_commit','boot_host','original_entry_monotonic_ns','original_deadline_monotonic_ns'}
            and type(document['schema_version']) is int and document['schema_version']==1
            and document['kind']==KIND and document['boot_host']==boot_host()
            and type(document['original_entry_monotonic_ns']) is int
            and document['original_entry_monotonic_ns']>=0
            and type(document['original_deadline_monotonic_ns']) is int
            and document['original_deadline_monotonic_ns']==document['original_entry_monotonic_ns']+3600*10**9
            and self.action_entry_ns>=document['original_entry_monotonic_ns']
            and document['selector_sha256']==self.args.native_protocol_history_sha256
            and document['source_commit']==self.args.source_commit,
            'selected original boot/chain clock differs')
        pin(document['key']);pin(document['selector_sha256'])
        tick(document['original_deadline_monotonic_ns']/10**9)

    def reserve_chain(self):
        self.chain={'schema_version':1,'kind':KIND,'key':self.key,
            'selector_sha256':self.args.native_protocol_history_sha256,'source_commit':self.args.source_commit,
            'boot_host':self.bindings['boot_host'],'original_entry_monotonic_ns':self.original_entry_ns,
            'original_deadline_monotonic_ns':self.original_deadline_ns}
        self.validate_clock(self.chain)
        raw=canonical(self.chain)+b'\n';self.chain_sha=sha(raw)
        parent=trusted_parent(CHAIN.parent)
        try:
            if self.stage==1:self.write_file(parent,CHAIN.name,raw,0o400)
            self.chain_fd=os.open(CHAIN.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            self.chain_witness=witness(os.fstat(self.chain_fd))
            self.check_chain()
            if self.stage==2:
                # Exclusive second-position reservation. A rejected/failed
                # second position cannot reopen stage1's successful journal.
                self.write_file(parent,'protocol-history-native-stage2.json',canonical({
                    'kind':KIND,'key':self.key,'chain_sha256':self.chain_sha,
                    'id':self.run.name,'action_entry_monotonic_ns':self.action_entry_ns})+b'\n',0o400)
        finally:os.close(parent)

    def write_file(self,fd,name,raw,mode):
        output=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            view=memoryview(raw)
            while view:
                tick(self.args.native_deadline)
                count=os.write(output,view);require(count>0,'selected durable short write');view=view[count:]
            os.fchmod(output,mode);os.fsync(output)
        finally:os.close(output)
        os.fsync(fd)

    def check_chain(self):
        parent=trusted_parent(CHAIN.parent)
        try:
            held=os.fstat(self.chain_fd);named=os.stat(CHAIN.name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISREG(held.st_mode) and held.st_uid==os.getuid() and held.st_gid==os.getgid()
                and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o400
                and witness(held)==witness(named)==self.chain_witness, 'selected chain custody changed')
            raw=b'';offset=0
            while offset<=8192:
                tick(self.args.native_deadline);chunk=os.pread(self.chain_fd,8193-offset,offset)
                if not chunk:break
                raw+=chunk;offset+=len(chunk)
            require(len(raw)<=8192 and sha(raw)==self.chain_sha
                and witness(os.fstat(self.chain_fd))==self.chain_witness, 'selected chain content changed')
            self.validate_clock(json.loads(raw,object_pairs_hook=source.unique))
        finally:os.close(parent)

    def capture_custody(self):
        result={}
        for name,fd,mode in (('chain',self.chain_fd,0o400),('root',self.root_fd,0o700),
            ('lock',self.lock_fd,0o600),('output',self.output_fd,0o700),
            ('input',self.input_fd,0o555),('source',self.source_fd,0o555)):
            info=os.fstat(fd)
            require((stat.S_ISREG(info.st_mode) and info.st_nlink==1 if name in ('chain','lock')
                else stat.S_ISDIR(info.st_mode)) and info.st_uid==os.getuid() and info.st_gid==os.getgid()
                and stat.S_IMODE(info.st_mode)==mode, 'selected held directory/lock mode refused')
            result[name]={'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
        return result

    def check_directories(self):
        self.check_chain()
        require(self.capture_custody()==self.custody and set(os.listdir(self.root_fd))=={
            'lock','output-base','native-input',JOURNAL}, 'selected held root shape changed')
        for name,file in (('root',self.root),('lock',self.root/'lock'),('output',self.lease.output_base),
            ('input',self.root/'native-input'),('source',self.source)):
            parent=trusted_parent(file.parent)
            try:info=os.stat(file.name,dir_fd=parent,follow_symlinks=False)
            finally:os.close(parent)
            row=self.custody[name]
            require({'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
                'mode':stat.S_IMODE(info.st_mode)}==row, 'selected canonical root/source/lock replaced')
        sealed_io.read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)

    def snapshot(self,args):
        return canonical({'selector':str(args.native_protocol_history),'pin':args.native_protocol_history_sha256,
            'stage':args.native_protocol_stage,'mode':args.native_mode,'source':str(args.native_source_root),
            'source_pin':args.native_source_sha256,'export':str(args.native_export_root),
            'export_pin':args.native_export_sha256,'patches':args.native_patch_sha256,
            'commit':args.source_commit,'dirty':args.source_dirty,'profile':args.profile,
            'manager':args.manager,'state':str(args.state_dir),'aggregate':args.native_aggregate_seconds})

    def recheck_inputs(self,qualified=None):
        tick(self.args.native_deadline)
        require(read_json(SELECTOR,self.args.native_protocol_history_sha256,self.args.native_deadline)==self.document
            and controller_inventory(Path.cwd(),self.graph,self.args.native_deadline)==self.bindings['controller_inventory']
            and boot_host()==self.bindings['boot_host'], 'selected declaration/controller/boot changed')
        qualified=verify_inputs(self.args) if qualified is None else qualified
        verify_inventory(self.source_fd,qualified[0]['source_inventory'],EXPORT_MODE_POLICY,
            on_read=lambda count:tick(self.args.native_deadline))
        for role,target,output in (('source','//tools:codex_protocol_history_source_producer','protocol-history-source'),
            ('sdk','//tools:codex_protocol_history_sdk_export_producer','protocol-history-sdk-export')):
            prior=producer_success(self.document[role],target,output,self.args.native_deadline)
            require(self.verify_previous(prior) is True, 'selected producer owned unit/cgroup no longer empty')
        for root,held in self.input_holds:inputs.recheck_root(root,held)

    def authorize_native_mode(self,args):
        require(type(self) is Admission and args is self.args and selected(args)
            and self.verified_before_launch is True and self.snapshot(args)==self.args_snapshot,
            'selected exact admitted command required')
        self.check_directories();self.recheck_inputs();self.verify_history();return True

    def journal(self,status,history):
        return {'schema_version':1,'kind':KIND,'key':self.key,'stage':self.stage,'epoch':self.run.name,
            'status':status,'history':copy.deepcopy(history),'custody':copy.deepcopy(self.custody),
            'chain_sha256':self.chain_sha}

    def write_journal(self,status,history,first=False):
        require(status in ('pending','qualified-stage','closed'), 'selected journal status invalid')
        if not first:sealed_io.read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)
        raw=canonical(self.journal(status,history))+b'\n'
        name=JOURNAL if first else 'journal-next-'+self.run.name
        self.write_file(self.root_fd,name,raw,0o600)
        if not first:os.replace(name,JOURNAL,src_dir_fd=self.root_fd,dst_dir_fd=self.root_fd);os.fsync(self.root_fd)
        self.journal_sha=sha(raw)

    def admit_previous(self):
        journal,pin=sealed_io.read_json(self.root_fd,JOURNAL,self.args.native_deadline)
        require(type(journal) is dict and set(journal)==set(self.journal('pending',[]))
            and type(journal['schema_version']) is int and journal['schema_version']==1
            and journal['kind']==KIND and journal['key']==self.key
            and type(journal['stage']) is int and journal['stage']==1
            and journal['status']=='qualified-stage' and journal['custody']==self.custody
            and journal['chain_sha256']==self.chain_sha and type(journal['history']) is list
            and len(journal['history'])==1 and journal['epoch']==journal['history'][0]['id'],
            'selected stage2 requires successful original stage1 custody')
        self.journal_sha=pin;self.history=copy.deepcopy(journal['history']);self.verify_history()

    def facts(self):
        return {'kind':KIND,'key':self.key,'bindings':copy.deepcopy(self.bindings),'stage':self.stage,
            'max_dispatches':2,'workspace':str(self.source),'output_base':str(self.lease.output_base),
            'chain_sha256':self.chain_sha,'custody':copy.deepcopy(self.custody),'history':copy.deepcopy(self.history),
            'original_entry_monotonic_ns':self.original_entry_ns,
            'original_deadline_monotonic_ns':self.original_deadline_ns,'action_entry_monotonic_ns':self.action_entry_ns,
            'verified_before_launch':self.verified_before_launch,'verified_after_cleanup':self.verified_after_cleanup,
            'artifacts_sha256':self.artifacts_sha,'native_support':False,'provider_evaluation':False}

    def verify_history(self):
        require(len(self.history)==self.stage-1, 'selected exact predecessor count differs')
        for row in self.history:
            require(type(row) is dict and set(row)=={'stage','id','sha256','artifacts_sha256'}
                and type(row['stage']) is int and row['stage']==1 and UUID.fullmatch(row['id'])
                and row['id']!=self.run.name, 'selected exact predecessor descriptor required')
            previous=read_json(STATE/row['id']/'receipt.json',row['sha256'],self.args.native_deadline)
            require(previous['id']==row['id'], 'selected prior receipt epoch differs')
            facts=previous['native_protocol_history']
            require(facts['bindings']==self.bindings and facts['key']==self.key
                and facts['custody']==self.custody and facts['chain_sha256']==self.chain_sha
                and facts['original_entry_monotonic_ns']==self.original_entry_ns
                and facts['original_deadline_monotonic_ns']==self.original_deadline_ns
                and facts['history']==[] and facts['artifacts_sha256']==row['artifacts_sha256'],
                'selected prior chain/identity/deadline differs')
            verify_success(previous,self.document,1)
            require(self.verify_previous(previous) is True, 'selected prior unit/cgroup not owned empty')
            envelope=read_json(STATE/row['id']/ARTIFACTS,row['artifacts_sha256'],self.args.native_deadline)
            actual=collect_artifacts(STATE/row['id'],previous,self.args.native_deadline)
            require(envelope==actual, 'selected prior accepted evidence changed')

    def verify_after_cleanup(self,qualified):
        self.check_directories();self.recheck_inputs(qualified);self.verify_history()
        self.verified_after_cleanup=True

    def close(self):
        for _,(fd,_) in self.input_holds:os.close(fd)
        self.input_holds=[]
        for name in ('source_fd','input_fd','output_fd','lock_fd','root_fd','chain_fd'):
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)


def verify_success(receipt,document,stage):
    sealed_io.verify_caps(receipt)
    facts=receipt['native_protocol_history'];sdk_receipt=receipt['native_sdk'];plan=sdk_receipt['plan']
    require(type(facts) is dict and set(facts)=={'kind','key','bindings','stage','max_dispatches',
        'workspace','output_base','chain_sha256','custody','history','original_entry_monotonic_ns',
        'original_deadline_monotonic_ns','action_entry_monotonic_ns','verified_before_launch',
        'verified_after_cleanup','artifacts_sha256','native_support','provider_evaluation'},
        'selected closed success facts required')
    bindings=facts['bindings']
    require(type(bindings) is dict and set(bindings)=={'kind','selection','controller_inventory',
        'controller_graph','tools','source_sdk_custody','locked_path','boot_host','stages','gates',
        'limits','network','batch','repository_download','remote','ambient_caches','core_codegen'}
        and bindings['kind']==KIND and bindings['stages']=={'1':STAGES[1],'2':STAGES[2]}
        and canonical(bindings['gates'])==canonical(GATES)
        and canonical(bindings['limits'])==canonical({'memory':4294967296,'swap':0,'tasks':512,'cpu_percent':200,
            'jobs':1,'heap_mib':768,'processors':1,'chain_seconds':3600,'reserve_seconds':120})
        and bindings['boot_host']==boot_host() and bindings['network']=='private'
        and bindings['batch'] is True and all(bindings[name] is False for name in (
            'repository_download','remote','ambient_caches')),
        'selected fixed whole-chain bindings differ')
    modes={'chain':0o400,'root':0o700,'lock':0o600,'output':0o700,'input':0o555,'source':0o555}
    require(type(facts['custody']) is dict and set(facts['custody'])==set(modes)
        and all(type(row) is dict and set(row)=={'device','inode','uid','gid','mode'}
            and all(type(value) is int for value in row.values()) and row['device']>=0 and row['inode']>0
            and row['uid']==os.getuid() and row['gid']==os.getgid() and row['mode']==modes[name]
            for name,row in facts['custody'].items()), 'selected strict held custody differs')
    require(receipt['profile']=='codex-native' and receipt['manager']=='system'
        and type(receipt['exit']) is int and receipt['exit']==0
        and type(receipt['workload_exit']) is int and receipt['workload_exit']==0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['cleanup']['state']=='empty'
        and all(receipt[name] is None for name in ('native_candidate_cache','native_fresh_completion','native_staged_compilation'))
        and receipt['source_dirty']=='false' and receipt['source_commit']==document['controller_source_commit']
        and receipt['graph_sha256']==document['controller_graph_sha256']
        and facts['kind']==KIND and type(facts['stage']) is int and facts['stage']==stage
        and type(facts['max_dispatches']) is int and facts['max_dispatches']==2
        and facts['verified_before_launch'] is True and facts['verified_after_cleanup'] is True
        and facts['native_support'] is False and facts['provider_evaluation'] is False
        and type(receipt['id']) is str and UUID.fullmatch(receipt['id'])
        and receipt['unit']=='omux-execution-'+receipt['id']+'.service'
        and facts['key']==sha(canonical(facts['bindings']))
        and facts['bindings']['selection']==document
        and facts['workspace']==str(STATE/('protocol-history-checks-'+facts['key'])/'native-input/source')
        and receipt['output_base']==facts['output_base']==str(STATE/('protocol-history-checks-'+facts['key'])/'output-base')
        and sdk_receipt['mode']==STAGES[stage] and receipt['verb']==MODES[STAGES[stage]][0]
        and receipt['targets']==list(MODES[STAGES[stage]][1])
        and sdk_receipt['source_receipt_sha256']==document['source']['receipt_sha256']
        and sdk_receipt['export_receipt_sha256']==document['sdk']['receipt_sha256']
        and sdk_receipt['source_and_export_verified_after_cleanup'] is True
        and type(sdk_receipt['aggregate_seconds']) is int and sdk_receipt['aggregate_seconds']==3600
        and sdk_receipt['original_entry_monotonic_ns']==facts['original_entry_monotonic_ns']
        and sdk_receipt['original_deadline_monotonic_ns']==facts['original_deadline_monotonic_ns']
        and type(facts['original_entry_monotonic_ns']) is int
        and type(facts['original_deadline_monotonic_ns']) is int
        and facts['original_deadline_monotonic_ns']==facts['original_entry_monotonic_ns']+3600*10**9
        and type(facts['action_entry_monotonic_ns']) is int
        and facts['original_entry_monotonic_ns']<=facts['action_entry_monotonic_ns']<facts['original_deadline_monotonic_ns']
        and plan['source_inventory_sha256']==document['source']['inventory_sha256']
        and plan['export_inventory_sha256']==document['sdk']['inventory_sha256']
        and plan['cwd']==facts['workspace'] and plan['candidate_output_base']==facts['output_base'],
        'selected actual successful outer native receipt required')
    # Compare the whole command with the fixed builder result, not presence of
    # flags (which permits duplicate later override flags).
    original=Path(plan['environment']['HOME']).parent
    require(original==STATE/receipt['id'], 'selected private action HOME is not its actual epoch')
    maximum=(facts['original_deadline_monotonic_ns']-facts['action_entry_monotonic_ns'])//10**9-120
    native.phase2_effective_runtime(receipt['observed_properties']['RuntimeMaxUSec'],maximum)
    tick(facts['original_deadline_monotonic_ns']/10**9)
    exported_report=read_json(Path(document['sdk']['root'])/'receipt.json',document['sdk']['receipt_sha256'],
        facts['original_deadline_monotonic_ns']/10**9,64*1024*1024)
    export_root=Path(document['sdk']['root'])
    exported={'repositories':{row['canonical_name']:str(export_root/'repositories'/row['canonical_name'])
        for row in exported_report['repositories']},'module_overrides':{
        name:str(export_root/'repositories'/binding['canonical_name']) for name,binding in exported_report['modules'].items()},
        'registry_cache':str(export_root/'registry-cache'),'inventory_sha256':document['sdk']['inventory_sha256'],
        'mapping_sha256':exported_report['mapping_sha256']}
    fake_args=SimpleNamespace(native_mode=STAGES[stage],native_deadline=facts['original_deadline_monotonic_ns']/10**9,
        native_source_root=Path(document['source']['root']),native_export_root=export_root)
    candidate=SimpleNamespace(source=Path(facts['workspace']),root=Path(facts['workspace']).parent.parent,
        lease=SimpleNamespace(output_base=Path(facts['output_base'])))
    expected=native.command_from_verified_inputs(fake_args,original,facts['bindings']['locked_path'],
        facts['bindings']['tools']['bash'],candidate,
        ({'inventory_sha256':document['source']['inventory_sha256']},exported),MODES,
        GATES if stage==1 else None,prepare=False)
    require(canonical(plan)==canonical(expected), 'selected whole fixed command/environment changed')
    argv=plan['argv']
    require(argv[0]==BAZEL and '--jobs=1' in argv and '--host_jvm_args=-Xmx768m' in argv
        and '--host_jvm_args=-XX:ActiveProcessorCount=1' in argv
        and '--lockfile_mode=error' in argv and '--repository_disable_download' in argv
        and all(argv.count(flag)==1 for flag in ('--batch','--repository_disable_download',
            '--ignore_all_rc_files','--incompatible_strict_action_env'))
        and plan['core_codegen']==native.core_codegen_policy()
        and plan['environment']['USE_BAZEL_VERSION']==native.BAZEL_VERSION,
        'selected immutable offline native plan differs')
    # Closed families reject additions or duplicates before acceptance.
    fixed={'--jobs=':['--jobs=1'],'--host_jvm_args=':['--host_jvm_args=-Xmx768m',
        '--host_jvm_args=-XX:ActiveProcessorCount=1'],'--lockfile_mode=':['--lockfile_mode=error'],
        '--compilation_mode=':['--compilation_mode=opt'],'--disk_cache=':['--disk_cache='],
        '--remote_executor=':['--remote_executor='],'--remote_cache=':['--remote_cache='],
        '--repo_contents_cache=':['--repo_contents_cache='],'--bes_backend=':['--bes_backend='],
        '--experimental_remote_downloader=':['--experimental_remote_downloader='],
        '--sandbox_default_allow_network=':['--sandbox_default_allow_network=false']}
    for prefix,expected in fixed.items():
        require([value for value in argv if value.startswith(prefix)]==expected,'selected duplicate/mutated native flag')
    if stage==1:
        expected=['--test_arg=--exact','--test_arg=--format=pretty','--test_arg=--color=never']
        expected+=['--test_arg='+name for names in GATES.values() for name in names]
        require([value for value in argv if value.startswith('--test_arg=')]==expected
            and not any(value.startswith('--test_filter=') for value in argv)
            and '--nocache_test_results' in argv and '--test_sharding_strategy=disabled' in argv,
            'selected exact tests plan differs')


def collect_artifacts(run,receipt,deadline):
    source_io.DEADLINE=deadline
    stage=receipt['native_protocol_history']['stage']
    if stage==1:
        require(receipt['test_evidence']['state']=='preserved', 'selected test evidence not preserved')
        manifest=read_json(Path(run)/'test-evidence.json',receipt['test_evidence']['sha256'],deadline)
        require(type(manifest['bazel_exit']) is int and manifest['bazel_exit']==0
            and manifest['epoch_start_ns']==receipt['epoch_start_ns'], 'selected test manifest differs')
        artifacts={'manifest':sealed_io.artifact_file(Path(run)/'test-evidence.json',deadline,8*1024*1024,json_object=True),
            'logs':meaningful_tests(run,manifest,STAGES[1])}
    else:
        require(stage==2 and receipt['test_evidence']['state']=='not-applicable', 'selected schema stage evidence differs')
        artifacts=sealed_io.schema_artifacts(Path(receipt['output_base']),deadline)
    return {'schema_version':1,'kind':KIND,'stage':stage,'id':receipt['id'],
        'source_receipt_sha256':receipt['native_sdk']['source_receipt_sha256'],
        'sdk_receipt_sha256':receipt['native_sdk']['export_receipt_sha256'],
        'controller_graph_sha256':receipt['graph_sha256'],'artifacts':artifacts}


def terminal_receipt(admission,receipt):
    try:
        if type(receipt['exit']) is int and receipt['exit']!=0:
            admission.write_journal('closed',admission.history)
        else:
            require(type(receipt['exit']) is int and receipt['exit']==0, 'selected terminal exit is not literal')
            receipt['native_protocol_history']=admission.facts()
            verify_success(receipt,admission.document,admission.stage)
            admission.check_directories();admission.verify_history()
            artifacts=collect_artifacts(admission.run,receipt,admission.args.native_deadline)
            raw=canonical(artifacts)+b'\n'
            fd=trusted_parent(admission.run)
            try:admission.write_file(fd,ARTIFACTS,raw,0o600)
            finally:os.close(fd)
            admission.artifacts_sha=sha(raw)
            require(read_json(admission.run/ARTIFACTS,admission.artifacts_sha,admission.args.native_deadline)==artifacts
                and collect_artifacts(admission.run,receipt,admission.args.native_deadline)==artifacts,
                'selected postcleanup artifacts changed')
            receipt['native_protocol_history']=admission.facts()
            raw=json.dumps(receipt,sort_keys=True)+'\n'
            row={'stage':admission.stage,'id':admission.run.name,'sha256':sha(raw.encode()),
                'artifacts_sha256':admission.artifacts_sha}
            admission.write_journal('qualified-stage' if admission.stage==1 else 'closed',admission.history+[row])
    except (OSError,ValueError,KeyError,TypeError,ET.ParseError):
        receipt['exit']=125
        try:admission.write_journal('closed',admission.history)
        except (OSError,ValueError,KeyError,TypeError):pass
    receipt['native_protocol_history']=admission.facts()
    return json.dumps(receipt,sort_keys=True)+'\n'
