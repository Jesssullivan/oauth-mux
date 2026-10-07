"""Separate four-stage native compilation admission; only the guard constructs it.

No failed output/cache is opened. A begins with an absent independent root.
B/C/D require actual fsynced successful predecessors and rehashed artifacts.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import codex_native_profile as native
import codex_native_fresh_completion as prior
from codex_sdk_profile import require, unique_object, verify_inventory, EXPORT_MODE_POLICY
from codex_fresh_source import trusted_parent

KIND = 'omux-native-staged-compilation-v1'
SELECTOR = native.STATE / 'native-staged-compilation.json'
CHAIN = native.STATE / 'native-staged-compilation-chain.json'
JOURNAL = 'staged-compilation-journal.json'
LOCK = 'staged-compilation.lock'
ARTIFACTS = 'native-staged-artifacts.json'
HASH, UUID = prior.HASH, prior.UUID
MAX_STAGES = 4
MAX_ARTIFACT_BYTES = 1024*1024*1024
MAX_SCHEMA_FILES = 4096
MAX_SCHEMA_BYTES = 64*1024*1024
LIBRARIES = ('//codex-rs/config:config', '//codex-rs/login:login',
    '//codex-rs/app-server-protocol:app-server-protocol')
STAGES = {
    1: ('staged-libraries', 'build', LIBRARIES),
    2: ('cli-opt', 'build', (native.CLI,)),
    3: (native.COMBINED_MODE, 'test', (native.CORE,native.CONFIG,native.LOGIN,native.CLI)),
    4: ('schema', 'build', ('//bazel/schema:native-config-schema','//bazel/schema:public-schema-bundle')),
}
FAILED_NINE = {
    'id':'9047cd6f-924e-4502-ab41-4c0de420f366',
    'sha256':'48feccb2542c7505567827215f1ddb266840c7635e85d1fb467a77bbe0a60fc1',
    'cache_key':'8441b948fba282404f5bd6357acfa72dab6a8ece53d45d6d84dd82582482492c',
    'attempt':9,
}
canonical = prior.canonical
read_small, read_json = prior.read_small, prior.read_json
controller_inventory, fixed_codegen = prior.controller_inventory, prior.fixed_codegen
INPUTS = prior.INPUTS


def consumed_dispatches():
    return prior.consumed_dispatches() + [dict(FAILED_NINE)]


def selected(args):
    fields = tuple(getattr(args,name,None) for name in (
        'native_staged_compilation','native_staged_compilation_sha256','native_stage'))
    if all(value is None for value in fields):
        return False
    require(all(value is not None for value in fields)
        and type(fields[2]) is int and fields[2] in STAGES
        and args.profile == 'codex-native' and args.manager == 'system'
        and args.state_dir == native.STATE and args.source_dirty == 'false'
        and isinstance(args.source_commit,str) and re.fullmatch(r'[0-9a-f]{40}',args.source_commit)
        and args.native_mode == STAGES[fields[2]][0]
        and Path(fields[0]) == SELECTOR and str(fields[0]) == str(SELECTOR)
        and isinstance(fields[1],str) and HASH.fullmatch(fields[1])
        and getattr(args,'native_owned_candidate_cache',False) is False
        and getattr(args,'reuse_owned_cache',False) is False
        and all(getattr(args,name,None) is None for name in (
            'native_cache_attempt','native_cache_transition','native_cache_transition_sha256',
            'native_cache_phase2','native_cache_phase2_sha256','native_fresh_completion',
            'native_fresh_completion_sha256','native_global_attempt')),
        'staged compilation exact exclusive selector/mode required')
    return True


def bindings(args, tools, graph, locked_path, manager, verified_inputs=None):
    require(selected(args) and manager == 'system'
        and type(args.native_aggregate_seconds) is int and args.native_aggregate_seconds == 3600,
        'staged compilation original budget required')
    require(str(args.native_source_root) == INPUTS['source_root']
        and args.native_source_sha256 == INPUTS['source_receipt_sha256']
        and str(args.native_export_root) == INPUTS['export_root']
        and args.native_export_sha256 == INPUTS['export_receipt_sha256']
        and args.native_patch_sha256 == INPUTS['patch_sha256'],
        'staged compilation exact public source/export required')
    require(set(tools) == {'bazel','python','systemd_run','systemctl','bootstrap','closure','java','bash'}
        and all(isinstance(value,str) and value.startswith('/nix/store/')
            and '..' not in Path(value).parts and not any(c.isspace() for c in value)
            for value in tools.values()) and tools['bazel'] == native.BAZEL
        and isinstance(locked_path,str) and locked_path
        and all(part.startswith('/nix/store/') and '..' not in Path(part).parts
            and not any(c.isspace() for c in part) for part in locked_path.split(':')),
        'staged compilation locked tools required')
    source,export = native.verify_inputs(args) if verified_inputs is None else verified_inputs
    require(source['inventory_sha256'] == INPUTS['source_inventory_sha256']
        and export['inventory_sha256'] == INPUTS['export_inventory_sha256']
        and export['mapping_sha256'] == INPUTS['mapping_sha256'],
        'staged compilation full sealed inventories differ')
    return {'kind':KIND,'uid':os.getuid(),'gid':os.getgid(),'manager':manager,
        'tools':tools,'locked_path':locked_path,'source_commit':args.source_commit,
        'controller_graph':graph,'source_root':str(args.native_source_root),
        'source_receipt_sha256':args.native_source_sha256,
        'source_inventory_sha256':source['inventory_sha256'],'source_graph':source['graph_files'],
        'patch_sha256':list(args.native_patch_sha256),'export_root':str(args.native_export_root),
        'export_receipt_sha256':args.native_export_sha256,
        'export_inventory_sha256':export['inventory_sha256'],'mapping_sha256':export['mapping_sha256'],
        'core_codegen':fixed_codegen(),'stages':STAGES,'maximum_stages':4,
        'consumed_dispatches':consumed_dispatches(),
        'limits':{'memory':4294967296,'swap':0,'tasks':512,'cpu_percent':200,'jobs':1,
            'heap_mib':768,'aggregate_seconds':3600,'postcheck_reserve_seconds':120},
        'network':'private','downloads':False,'remote':False,'ambient_caches':False,
        'test_sharding':False,'bazel_dispatcher_environment':{'USE_BAZEL_VERSION':native.BAZEL_VERSION},
        'module_resolution_policy':native.MODULE_RESOLUTION_POLICY}


def validate_document(document, expected, inventory):
    require(isinstance(document,dict) and set(document) == {
            'schema_version','kind','bindings','controller_inventory','previous_dispatches'}
        and type(document['schema_version']) is int and document['schema_version'] == 1
        and document['kind'] == KIND and canonical(document['bindings']) == canonical(expected)
        and canonical(document['controller_inventory']) == canonical(inventory)
        and canonical(document['previous_dispatches']) == canonical(consumed_dispatches()),
        'staged compilation independently pinned closed declaration differs')


def historical_receipts(deadline, verify_previous):
    prior.historical_receipts(deadline,verify_previous)
    value = prior.read_receipt(FAILED_NINE,deadline)
    facts = value['native_fresh_completion']
    require(value['id'] == FAILED_NINE['id'] and value['profile'] == 'codex-native'
        and value['manager'] == 'system'
        and value['unit'] == 'omux-execution-'+FAILED_NINE['id']+'.service'
        and type(value['exit']) is int and value['exit'] == 125
        and type(value['workload_exit']) is int and value['workload_exit'] == 124
        and value['descendants_empty'] is True and value['native_candidate_cache'] is None
        and facts['kind'] == prior.KIND and facts['key'] == FAILED_NINE['cache_key']
        and type(facts['global_attempt']) is int and facts['global_attempt'] == 9
        and facts['verified_before_launch'] is True and facts['verified_after_cleanup'] is True
        and value['native_sdk']['source_and_export_verified_after_cleanup'] is True
        and value['native_sdk']['mode'] == native.COMBINED_MODE
        and value['test_evidence']['state'] != 'preserved',
        'staged compilation must preserve actual closed ninth timeout')
    require(verify_previous(value) is True,'staged historical owned unit/cgroup not empty')


def history_row(row, key, stage):
    require(isinstance(row,dict) and set(row) == {
        'stage','id','sha256','artifacts_sha256','key'}
        and type(row['stage']) is int and row['stage'] == stage
        and UUID.fullmatch(row['id']) and HASH.fullmatch(row['sha256'])
        and HASH.fullmatch(row['artifacts_sha256']) and row['key'] == key,
        'staged compilation exact successful predecessor row required')
    return row




def verify_binding_facts(facts):
    """Pure consumer ABI: derive key from the complete fixed provenance."""
    value=facts['bindings']
    keys={'kind','uid','gid','manager','tools','locked_path','source_commit','controller_graph',
        'source_root','source_receipt_sha256','source_inventory_sha256','source_graph','patch_sha256',
        'export_root','export_receipt_sha256','export_inventory_sha256','mapping_sha256','core_codegen',
        'stages','maximum_stages','consumed_dispatches','limits','network','downloads','remote',
        'ambient_caches','test_sharding','bazel_dispatcher_environment','module_resolution_policy'}
    require(isinstance(value,dict) and set(value) == keys and value['kind'] == KIND
        and type(value['uid']) is int and value['uid'] == os.getuid()
        and type(value['gid']) is int and value['gid'] == os.getgid()
        and value['manager'] == 'system' and value['source_commit'] == facts['source_commit']
        and re.fullmatch(r'[0-9a-f]{40}',value['source_commit'])
        and type(value['maximum_stages']) is int and value['maximum_stages'] == 4
        and canonical(value['stages']) == canonical(STAGES)
        and canonical(value['consumed_dispatches']) == canonical(consumed_dispatches())
        and canonical(value['core_codegen']) == canonical(fixed_codegen())
        and canonical(value['limits']) == canonical({'memory':4294967296,'swap':0,'tasks':512,
            'cpu_percent':200,'jobs':1,'heap_mib':768,'aggregate_seconds':3600,'postcheck_reserve_seconds':120})
        and value['network'] == 'private' and all(value[field] is False for field in (
            'downloads','remote','ambient_caches','test_sharding'))
        and value['bazel_dispatcher_environment'] == {'USE_BAZEL_VERSION':native.BAZEL_VERSION}
        and value['module_resolution_policy'] == native.MODULE_RESOLUTION_POLICY,
        'staged complete fixed provenance/resource identity differs')
    for field in ('source_root','source_receipt_sha256','source_inventory_sha256','export_root',
            'export_receipt_sha256','export_inventory_sha256','mapping_sha256','patch_sha256'):
        require(canonical(value[field]) == canonical(INPUTS[field]),'staged fixed input binding differs')
    tools=value['tools']
    require(isinstance(tools,dict) and set(tools) == {
            'bazel','python','systemd_run','systemctl','bootstrap','closure','java','bash'}
        and tools['bazel'] == native.BAZEL and all(isinstance(path,str)
            and path.startswith('/nix/store/') and '..' not in Path(path).parts
            and not any(c.isspace() for c in path) for path in tools.values())
        and isinstance(value['locked_path'],str) and value['locked_path']
        and all(path.startswith('/nix/store/') and '..' not in Path(path).parts
            and not any(c.isspace() for c in path) for path in value['locked_path'].split(':')),
        'staged immutable tools/PATH differ')
    graph=value['controller_graph']
    require(isinstance(graph,(tuple,list)) and len(graph)==2 and HASH.fullmatch(graph[0])
        and isinstance(graph[1],list) and 0<len(graph[1])<=4096
        and len(set(graph[1]))==len(graph[1]) and all(isinstance(path,str) and path
            and not Path(path).is_absolute() and '..' not in Path(path).parts
            and str(Path(path)) == path and len(path)<=4096 for path in graph[1])
        and sum(len(path.encode()) for path in graph[1])<=128*1024,
        'staged finite complete controller graph differs')
    require(set(value['source_graph']) == set(native.GRAPH)
        and all(set(row)=={'sha256'} and HASH.fullmatch(row['sha256'])
            for row in value['source_graph'].values()),'staged source graph inventory differs')
    key=hashlib.sha256(canonical(value)).hexdigest()
    require(facts['kind']==KIND and facts['key']==facts['provenance_sha256']==key
        and key not in {row['cache_key'] for row in consumed_dispatches()}
        and facts['workspace']==str(native.STATE/('cache-v2-'+key)/'native-input/source')
        and facts['output_base']==str(native.STATE/('cache-v2-'+key)/'output-base')
        and isinstance(facts['selector_sha256'],str) and HASH.fullmatch(facts['selector_sha256'])
        and isinstance(facts['chain_sha256'],str) and HASH.fullmatch(facts['chain_sha256']),
        'staged independently derived namespace/key differs')
    chain={'schema_version':1,'kind':KIND,'key':key,'provenance_sha256':key,
        'source_commit':facts['source_commit'],'selector_sha256':facts['selector_sha256']}
    require(facts['chain_sha256']==hashlib.sha256(canonical(chain)+b'\n').hexdigest(),
        'staged immutable policy-chain digest differs')
    custody=facts['custody']
    modes={'chain':0o400,'root':0o700,'output_base':0o700,'lock':0o600,
        'native_input':0o555,'source':0o555}
    require(isinstance(custody,dict) and set(custody)==set(modes)
        and all(isinstance(row,dict) and set(row)=={'device','inode','uid','gid','mode'}
            and all(type(item) is int for item in row.values())
            and row['device']>=0 and row['inode']>0 and row['uid']==os.getuid()
            and row['gid']==os.getgid() and row['mode']==modes[name]
            for name,row in custody.items()),'staged persistent custody fields differ')
    return value


def verify_caps(receipt):
    observed = receipt['observed_properties']
    require(observed['MemoryMax'] == '4294967296'
        and observed['MemorySwapMax'] == '0' and observed['TasksMax'] == '512'
        and observed['PrivateNetwork'] == 'yes'
        and native.phase2_effective_runtime(observed['CPUQuotaPerSecUSec'],2) == 2000000,
        'staged actual memory/swap/tasks/CPU/network caps differ')
    native.phase2_effective_runtime(observed['RuntimeMaxUSec'],3480)


def verify_plan(receipt):
    facts=receipt['native_staged_compilation']
    plan=receipt['native_sdk']['plan']
    argv=plan['argv']
    require(isinstance(argv,list) and all(isinstance(value,str) for value in argv),
        'staged actual argv must be finite strings')
    fixed={
        '--compilation_mode=':['--compilation_mode=opt'],
        '--lockfile_mode=':['--lockfile_mode=error'],
        '--sandbox_default_allow_network=':['--sandbox_default_allow_network=false'],
        '--jobs=':['--jobs=1'],
        '--host_jvm_args=':['--host_jvm_args=-Xmx768m','--host_jvm_args=-XX:ActiveProcessorCount=1'],
        '--repo_contents_cache=':['--repo_contents_cache='],
        '--disk_cache=':['--disk_cache='],
        '--remote_executor=':['--remote_executor='],
        '--remote_cache=':['--remote_cache='],
        '--experimental_remote_downloader=':['--experimental_remote_downloader='],
        '--bes_backend=':['--bes_backend='],
        '--output_base=':['--output_base='+facts['output_base']],
        '--action_env=PATH=':['--action_env=PATH='+facts['bindings']['locked_path']],
        '--repo_env=PATH=':['--repo_env=PATH='+facts['bindings']['locked_path']],
        '--local_test_jobs=':['--local_test_jobs=1'] if facts['stage']==3 else [],
    }
    for prefix,expected in fixed.items():
        require([value for value in argv if value.startswith(prefix)]==expected,
            'staged fixed flag family differs')
    require([value for value in argv if value.startswith('--repository_disable_download')
        or value.startswith('--norepository_disable_download')]==['--repository_disable_download'],
        'staged downloads cannot be enabled')
    require([value for value in argv if value.startswith('--ignore_all_rc_files')
        or value.startswith('--noignore_all_rc_files')]==['--ignore_all_rc_files'],
        'staged ambient rc cannot be enabled')
    require(plan['environment']=={
        'PATH':facts['bindings']['locked_path'],'USE_BAZEL_VERSION':native.BAZEL_VERSION,
        'HOME':str(native.STATE/receipt['id']/'home'),
        'XDG_CACHE_HOME':str(native.STATE/receipt['id']/'home/cache'),
        'XDG_CONFIG_HOME':str(native.STATE/receipt['id']/'home/config'),
        'XDG_STATE_HOME':str(native.STATE/receipt['id']/'home/state')},
        'staged actual fixed plan environment differs')
    if facts['stage']==3:
        names=[name for names in native.QUALIFICATION_GATES.values() for name in names]
        expected=['--test_arg=--exact','--test_arg=--format=pretty','--test_arg=--color=never']
        expected+=['--test_arg='+name for name in names]
        require([value for value in argv if value.startswith('--test_arg=')]==expected
            and not any(value.startswith('--test_filter=') for value in argv)
            and [value for value in argv if value.startswith('--test_sharding_strategy=')]
                ==['--test_sharding_strategy=disabled']
            and [value for value in argv if value.startswith('--test_timeout=')]==['--test_timeout=1200']
            and argv.count('--nocache_test_results')==1
            and not any(value.startswith('--cache_test_results') for value in argv),
            'staged qualification cannot weaken fourteen-case execution')


def verify_success(receipt, expected_facts, graph, source_pin, export_pin, stage, *, capturing=False):
    require(type(stage) is int and stage in STAGES,'staged completion exact stage')
    mode,verb,targets = STAGES[stage]
    verify_caps(receipt)
    facts = receipt['native_staged_compilation']
    verify_binding_facts(facts)
    verify_plan(receipt)
    sdk,plan = receipt['native_sdk'],receipt['native_sdk']['plan']
    require(receipt['profile'] == 'codex-native' and receipt['manager'] == 'system'
        and type(receipt['exit']) is int and receipt['exit'] == 0
        and type(receipt['workload_exit']) is int and receipt['workload_exit'] == 0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['native_candidate_cache'] is None and receipt['native_fresh_completion'] is None
        and canonical(facts) == canonical(expected_facts)
        and type(facts['stage']) is int and facts['stage'] == stage
        and type(facts['max_stages']) is int and facts['max_stages'] == 4
        and facts['verified_before_launch'] is True and facts['verified_after_cleanup'] is True
        and (facts['artifacts_sha256'] is None if capturing
            else isinstance(facts['artifacts_sha256'],str) and HASH.fullmatch(facts['artifacts_sha256']))
        and receipt['graph_sha256'] == graph[0]
        and receipt['source_commit'] == expected_facts['source_commit']
        and receipt['source_dirty'] == 'false' and UUID.fullmatch(receipt['id'])
        and receipt['unit'] == 'omux-execution-'+receipt['id']+'.service'
        and receipt['output_base'] == expected_facts['output_base']
        and sdk['mode'] == mode and receipt['targets'] == list(targets)
        and sdk['source_and_export_verified_after_cleanup'] is True
        and sdk['source_receipt_sha256'] == source_pin and sdk['export_receipt_sha256'] == export_pin
        and plan['core_codegen'] == fixed_codegen()
        and plan['source_inventory_sha256'] == INPUTS['source_inventory_sha256']
        and plan['export_inventory_sha256'] == INPUTS['export_inventory_sha256']
        and plan['mapping_sha256'] == INPUTS['mapping_sha256']
        and plan['cwd'] == expected_facts['workspace']
        and plan['candidate_output_base'] == expected_facts['output_base']
        and plan['environment']['USE_BAZEL_VERSION'] == native.BAZEL_VERSION
        and plan['argv'][0] == native.BAZEL and verb in plan['argv']
        and plan['argv'][-len(targets):] == list(targets)
        and [value for value in plan['argv'] if value.startswith('--'+native.CORE_CODEGEN_SETTING+'=')]
            == native.core_codegen_arguments()
        and all(value in plan['argv'] for value in (
            '--lockfile_mode=error','--repository_disable_download','--sandbox_default_allow_network=false',
            '--jobs=1','--host_jvm_args=-Xmx768m','--repo_contents_cache=','--disk_cache=',
            '--remote_executor=','--remote_cache='))
        and (stage != 3 or '--local_test_jobs=1' in plan['argv'])
        and type(sdk['aggregate_seconds']) is int and sdk['aggregate_seconds'] == 3600
        and type(sdk['original_entry_monotonic_ns']) is int and sdk['original_entry_monotonic_ns'] >= 0
        and type(sdk['original_deadline_monotonic_ns']) is int
        and sdk['original_deadline_monotonic_ns'] == sdk['original_entry_monotonic_ns']+3600*10**9
        and receipt['test_evidence']['state'] == ('preserved' if stage == 3 else 'not-applicable'),
        'staged compilation actual successful guarded receipt required')


def cli_context(receipt):
    facts,sdk = receipt['native_staged_compilation'],receipt['native_sdk']
    return {'invocation_id':receipt['id'],'output_base':facts['output_base'],
        'source_receipt_sha256':sdk['source_receipt_sha256'],
        'export_receipt_sha256':sdk['export_receipt_sha256'],
        'source_inventory_sha256':sdk['plan']['source_inventory_sha256'],
        'export_inventory_sha256':sdk['plan']['export_inventory_sha256'],
        'candidate_cache_key':facts['key'],'candidate_provenance_sha256':facts['provenance_sha256'],
        'controller_graph_sha256':receipt['graph_sha256'],'bazel':native.BAZEL,
        'workload_exit':receipt['workload_exit'],'descendants_empty':receipt['descendants_empty'],
        'source_and_export_verified_after_cleanup':sdk['source_and_export_verified_after_cleanup']}

def artifact_file(path, deadline, limit, *, magic=None, json_object=False, executable=False):
    path = Path(path)
    require(path.is_absolute() and str(path) == str(Path(str(path)))
        and '..' not in path.parts,'staged artifact noncanonical path')
    parent = trusted_parent(path.parent)
    child = None
    try:
        child = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_gid == os.getgid() and before.st_nlink == 1
            and not before.st_mode & 0o7022 and 0 < before.st_size <= limit
            and (bool(before.st_mode & 0o111) if executable else not before.st_mode & 0o111),
            'staged artifact custody/size refused')
        if magic is not None:
            require(os.pread(child,len(magic),0) == magic,'staged artifact format differs')
        sha,total,parts = hashlib.sha256(),0,[]
        while True:
            native.tick(deadline)
            chunk = os.read(child,1024*1024)
            if not chunk:break
            total += len(chunk)
            require(total <= limit,'staged artifact grew beyond bound')
            sha.update(chunk)
            if json_object:parts.append(chunk)
        current_parent=trusted_parent(path.parent)
        try:
            require((os.fstat(parent).st_dev,os.fstat(parent).st_ino)
                == (os.fstat(current_parent).st_dev,os.fstat(current_parent).st_ino),
                'staged artifact named ancestry changed')
        finally:os.close(current_parent)
        require(total == before.st_size and prior.witness(before) == prior.witness(os.fstat(child))
            == prior.witness(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
            'staged artifact held/named identity changed')
        if json_object:
            require(isinstance(json.loads(b''.join(parts),object_pairs_hook=unique_object),dict),
                'staged generated artifact must be a JSON object')
        return {'path':str(path),'sha256':sha.hexdigest(),'bytes':total,
            'mode':stat.S_IMODE(before.st_mode)}
    finally:
        if child is not None:os.close(child)
        os.close(parent)


def configurations(output):
    root = Path(output)/'execroot/_main/bazel-out'
    fd = trusted_parent(root)
    try:
        names = os.listdir(fd)
        require(len(names) <= 64,'staged configuration inventory bound')
        return [root/name for name in sorted(names)
            if re.fullmatch(r'[A-Za-z0-9_.-]+-opt',name)]
    finally:os.close(fd)


def library_artifacts(output, deadline):
    packages = (('config','codex_config'),('login','codex_login'),
        ('app-server-protocol','codex_app_server_protocol'))
    found = []
    for configuration in configurations(output):
        entries = {}
        for label,(package,crate) in zip(LIBRARIES,packages):
            directory = configuration/'bin/codex-rs'/package
            try:fd = trusted_parent(directory)
            except FileNotFoundError:continue
            try:
                names = os.listdir(fd)
                require(len(names) <= 512,'staged library directory bound')
                matches = [name for name in names if re.fullmatch(
                    'lib'+crate+r'-[0-9]{1,20}\.rlib',name)]
                require(len(matches) <= 1,'staged library ambiguous output')
                if matches:
                    entries[label] = artifact_file(directory/matches[0],deadline,
                        256*1024*1024,magic=b'!<arch>\n')
            finally:os.close(fd)
        if entries:found.append(entries)
    require(len(found) == 1 and set(found[0]) == set(LIBRARIES)
        and sum(row['bytes'] for row in found[0].values()) <= 768*1024*1024,
        'staged library exact three complete outputs required')
    return {'libraries':found[0]}



def rehash_libraries(output, recorded, deadline):
    require(set(recorded)==set(LIBRARIES),'staged selected library set differs')
    packages=(('config','codex_config'),('login','codex_login'),
        ('app-server-protocol','codex_app_server_protocol'))
    result,configs={},set()
    prefix=Path(output)/'execroot/_main/bazel-out'
    for label,(package,crate) in zip(LIBRARIES,packages):
        row=recorded[label]
        require(set(row)=={'path','sha256','bytes','mode'}
            and HASH.fullmatch(row['sha256']) and type(row['bytes']) is int
            and 0<row['bytes']<=256*1024*1024 and type(row['mode']) is int,
            'staged recorded library pin differs')
        path=Path(row['path'])
        relative=path.relative_to(prefix)
        require(str(path)==row['path'] and len(relative.parts)==5
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[0])
            and relative.parts[1:4]==('bin','codex-rs',package)
            and re.fullmatch('lib'+crate+r'-[0-9]{1,20}\.rlib',relative.parts[4]),
            'staged selected A target library path differs')
        configs.add(relative.parts[0])
        result[label]=artifact_file(path,deadline,256*1024*1024,magic=b'!<arch>\n')
    require(len(configs)==1 and sum(row['bytes'] for row in result.values())<=768*1024*1024,
        'staged recorded library configuration/total differs')
    return {'libraries':result}

def qualification_artifacts(run, receipt, deadline):
    facts = receipt['native_staged_compilation']
    parent = trusted_parent(run)
    try:
        manifest,pin = read_json(parent,'test-evidence.json',deadline,receipt['test_evidence']['sha256'])
        group,_ = read_json(parent,'native-qualification.json',deadline)
        xml,xml_pin = read_small(parent,'native-qualification.xml',deadline)
    finally:os.close(parent)
    require(manifest['targets'] == list(STAGES[3][2]) and len(manifest['results']) == 4
        and group['schema'] == 'omux-native-grouped-qualification-v1'
        and type(group['passed']) is int and group['passed'] == 14
        and type(group['failed']) is int and group['failed'] == 0
        and type(group['ignored']) is int and group['ignored'] == 0
        and group['native_support'] is False and group['provider_evaluation'] is False
        and group['xml_sha256'] == xml_pin and set(group['targets']) == set(native.QUALIFICATION_GATES),
        'staged actual grouped14 evidence differs')
    rows = {row['target']:row for row in manifest['results']}
    require(len(rows) == 4 and set(rows) == set(STAGES[3][2])
        and rows[native.CLI]['state'] == 'missing-test-directory'
        and rows[native.CLI]['files'] == [],'staged explicit CLI request differs')
    logs = {}
    fd = trusted_parent(run/'test-evidence')
    try:
        for target,names in native.QUALIFICATION_GATES.items():
            entries = [row for row in rows[target]['files']
                if row['source'] == 'test.log' and row['state'] == 'copied']
            require(len(entries) == 1,'staged one actual log per target required')
            entry = entries[0]
            raw,pin = read_small(fd,entry['file'],deadline,entry['sha256'])
            require(native.qualification_log(raw,target) == sorted(names)
                and canonical(group['targets'][target]) == canonical({
                    'log_sha256':pin,'tests':sorted(names)}),'staged exact named log differs')
            logs[target] = artifact_file(run/'test-evidence'/entry['file'],deadline,8*1024*1024)
    finally:os.close(fd)
    document = ET.fromstring(xml)
    require(document.tag == 'testsuites' and document.attrib == {
        'tests':'14','failures':'0','errors':'0','skipped':'0'},'staged XML total differs')
    suites = document.findall('testsuite')
    require(len(suites) == 3 and {suite.get('name') for suite in suites}
        == set(native.QUALIFICATION_GATES),'staged XML exact suites differ')
    for target,names in native.QUALIFICATION_GATES.items():
        suite = next(row for row in suites if row.get('name') == target)
        cases = suite.findall('testcase')
        require(suite.get('tests') == str(len(names))
            and all(suite.get(key) == '0' for key in ('failures','errors','skipped'))
            and len(cases) == len(names) and sorted(case.get('name') for case in cases) == sorted(names)
            and all(case.get('classname') == target and len(case) == 0 for case in cases)
            and [row.attrib for row in suite.findall('properties/property')] == [
                {'name':'actual_test_log_sha256','value':group['targets'][target]['log_sha256']}],
            'staged XML exact named/log binding differs')
    context = cli_context(receipt)
    native.source_io.DEADLINE = deadline
    cli = native.combined_cli_artifact(context)
    require(canonical(group['cli_context']) == canonical(context)
        and canonical(group['cli_artifact']) == canonical(cli),'staged actual CLI cleanup join differs')
    return {'cli':cli,'cli_context':context,'qualification':{
        'manifest':artifact_file(run/'test-evidence.json',deadline,8*1024*1024,json_object=True),
        'group':artifact_file(run/'native-qualification.json',deadline,8*1024*1024,json_object=True),
        'xml':artifact_file(run/'native-qualification.xml',deadline,8*1024*1024),
        'logs':logs}}


def schema_tree(root, deadline, budget):
    result = {}
    def visit(directory, prefix):
        fd = trusted_parent(directory)
        try:
            names = sorted(os.listdir(fd))
            require(len(names) <= MAX_SCHEMA_FILES,'staged schema directory count bound')
            for name in names:
                native.tick(deadline)
                require(re.fullmatch(r'[A-Za-z0-9_.-]{1,256}',name)
                    and name not in ('.','..'),'staged schema name refused')
                relative = prefix+'/'+name if prefix else name
                require(len(relative) <= 2048 and len(Path(relative).parts) <= 16,
                    'staged schema pathname bound')
                item = os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(item.st_mode):
                    budget['directories'] += 1
                    require(budget['directories'] <= MAX_SCHEMA_FILES,'staged schema directory total bound')
                    visit(directory/name,relative)
                else:
                    require(stat.S_ISREG(item.st_mode) and name.endswith('.json'),
                        'staged schema tree only regular JSON files')
                    budget['files'] += 1
                    require(budget['files'] <= MAX_SCHEMA_FILES,'staged schema total count bound')
                    value = artifact_file(directory/name,deadline,8*1024*1024,json_object=True)
                    budget['bytes'] += value['bytes']
                    require(budget['bytes'] <= MAX_SCHEMA_BYTES,'staged schema aggregate bytes bound')
                    result[relative] = value
        finally:os.close(fd)
    visit(Path(root),'')
    require(result,'staged generated schema tree must not be empty')
    return result


def schema_artifacts(output, deadline):
    found = []
    for configuration in configurations(output):
        directory = configuration/'bin/bazel/schema'
        try:fd = trusted_parent(directory)
        except FileNotFoundError:continue
        try:
            try:item = os.stat('native-config.schema.json',dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:continue
            require(stat.S_ISREG(item.st_mode),'staged generated config must be regular')
            value,_ = read_json(fd,'native-config.schema.json',deadline)
        finally:os.close(fd)
        definitions = value.get('definitions',value.get('$defs',{}))
        require(definitions['OmuxBrokerContextMode']['enum'] == ['full_native','text_transcript_v1']
            and definitions['OmuxBrokerConfig']['properties']['context_mode']['default'] == 'full_native',
            'staged generated config policy differs')
        config = artifact_file(directory/'native-config.schema.json',deadline,8*1024*1024,json_object=True)
        budget = {'files':1,'directories':0,'bytes':config['bytes']}
        files,roots = {},{}
        for mode in ('stable','experimental'):
            root = directory/('public-schema-bundle.'+mode)/'json'
            roots[mode] = str(root)
            for name,row in schema_tree(root,deadline,budget).items():
                files[mode+'/'+name] = row
        found.append({'config_schema':config,'protocol_schema_files':files,
            'protocol_schema_roots':roots})
    require(len(found) == 1,'staged schemas require one complete opt configuration')
    return found[0]


def collect_stage_artifacts(run, receipt, deadline):
    facts = receipt['native_staged_compilation']
    stage = facts['stage']
    require(type(stage) is int and stage in STAGES,'staged artifact exact stage')
    if stage == 1:result = library_artifacts(facts['output_base'],deadline)
    elif stage == 2:
        context = cli_context(receipt)
        native.source_io.DEADLINE = deadline
        result = {'cli':native.combined_cli_artifact(context),'cli_context':context}
    elif stage == 3:result = qualification_artifacts(run,receipt,deadline)
    else:result = schema_artifacts(facts['output_base'],deadline)
    return collect_stage_envelope(receipt,result)


def collect_stage_envelope(receipt,result):
    facts=receipt['native_staged_compilation']
    return {'schema_version':1,'kind':KIND,'stage':facts['stage'],'id':receipt['id'],'key':facts['key'],
        'controller_graph_sha256':receipt['graph_sha256'],
        'source_receipt_sha256':receipt['native_sdk']['source_receipt_sha256'],
        'export_receipt_sha256':receipt['native_sdk']['export_receipt_sha256'],'artifacts':result}


def verify_artifacts(run, receipt, deadline, *, expected=None, rehash_outputs=True):
    facts = receipt['native_staged_compilation']
    parent = trusted_parent(run)
    try:document,pin = read_json(parent,ARTIFACTS,deadline,facts['artifacts_sha256'])
    finally:os.close(parent)
    require(type(document['schema_version']) is int and document['schema_version'] == 1
        and type(document['stage']) is int and document['stage'] == facts['stage'],
        'staged artifact literal version/stage required')
    if rehash_outputs and facts['stage']==1:
        actual=collect_stage_envelope(receipt,rehash_libraries(facts['output_base'],
            document['artifacts']['libraries'],deadline))
    else:actual = collect_stage_artifacts(run,receipt,deadline) if rehash_outputs else expected
    require(actual is not None and canonical(document) == canonical(actual),
        'staged actual artifact inventory changed')
    return document,pin


def terminal_receipt(admission, receipt):
    """Persist successful role only after actual artifact evidence; close failures."""
    original_exit=receipt['exit']
    try:
        if type(original_exit) is int and original_exit != 0:
            receipt['native_staged_compilation']=admission.facts()
            raw=json.dumps(receipt,sort_keys=True)+'\n'
            admission.close_failed(receipt,hashlib.sha256(raw.encode()).hexdigest())
            return raw
        require(type(original_exit) is int and original_exit == 0,'staged literal guard exit required')
        admission.capture_artifacts(receipt)
        receipt['native_staged_compilation']=admission.facts()
        raw=json.dumps(receipt,sort_keys=True)+'\n'
        admission.finish(receipt,hashlib.sha256(raw.encode()).hexdigest())
    except (OSError,ValueError,KeyError,TypeError,ET.ParseError):
        receipt['exit']=125
        receipt['native_staged_compilation']=admission.facts()
        receipt['native_staged_compilation']['terminal_record']='uncommitted'
        raw=json.dumps(receipt,sort_keys=True)+'\n'
        try:admission.close_failed(receipt,hashlib.sha256(raw.encode()).hexdigest())
        except (OSError,ValueError,KeyError,TypeError):pass
    return raw

class Admission:
    def __init__(self,args,run,tools,graph,locked_path,manager,verify_previous):
        require(selected(args),'staged compilation selected policy required')
        self.args,self.run,self.tools = args,Path(run),dict(tools)
        require(self.run == native.STATE/self.run.name and UUID.fullmatch(self.run.name),
            'staged compilation exact new public epoch required')
        self.graph,self.locked_path,self.manager = graph,locked_path,manager
        self.verify_previous,self.stage = verify_previous,args.native_stage
        self.verified_before_launch,self.verified_after_cleanup = False,None
        self.root_fd=self.lock_fd=self.output_fd=self.chain_fd=self.source_fd=self.input_fd=None
        self.journal_sha=self.artifacts_sha=None
        self.artifact_document=None
        self.stage_history=[]
        try:
            self.provenance=bindings(args,tools,graph,locked_path,manager)
            self.provenance_snapshot=canonical(self.provenance)
            self.args_snapshot=self.argument_snapshot(args)
            inventory=controller_inventory(Path.cwd(),graph,args.native_deadline)
            parent=trusted_parent(SELECTOR.parent)
            try:document,_=read_json(parent,SELECTOR.name,args.native_deadline,args.native_staged_compilation_sha256)
            finally:os.close(parent)
            validate_document(document,self.provenance,inventory)
            self.document=document
            self.key=hashlib.sha256(self.provenance_snapshot).hexdigest()
            require(self.key not in {row['cache_key'] for row in consumed_dispatches()},
                'staged compilation cannot select a historical failed key')
            self.root=native.STATE/('cache-v2-'+self.key)
            self.source=self.root/'native-input/source'
            self.lease=SimpleNamespace(output_base=self.root/'output-base')
            self.reserve_chain()
            historical_receipts(args.native_deadline,verify_previous)
            parent=trusted_parent(native.STATE)
            try:
                if self.stage == 1:os.mkdir(self.root.name,0o700,dir_fd=parent)
                self.root_fd=os.open(self.root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            finally:os.close(parent)
            info=os.fstat(self.root_fd)
            require(info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and stat.S_IMODE(info.st_mode) == 0o700,'staged root custody refused')
            self.root_identity=(info.st_dev,info.st_ino)
            self.lock_fd=os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW
                |(os.O_CREAT|os.O_EXCL if self.stage == 1 else 0),0o600,dir_fd=self.root_fd)
            held=os.fstat(self.lock_fd)
            require(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid()
                and held.st_gid == os.getgid() and held.st_nlink == 1
                and stat.S_IMODE(held.st_mode) == 0o600,'staged lock custody refused')
            fcntl.flock(self.lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.lock_identity=(held.st_dev,held.st_ino)
            if self.stage == 1:
                require(os.listdir(self.root_fd) == [LOCK],'staged new root must be empty')
                os.mkdir('output-base',0o700,dir_fd=self.root_fd)
                source=native.validate_source(args.native_source_root,args.native_source_sha256,
                    args.native_patch_sha256,args.native_deadline)
                native.source_io.DEADLINE=args.native_deadline
                self.source=native.copy_source(args.native_source_root,source,self.root)
            else:
                require(set(os.listdir(self.root_fd)) == {LOCK,JOURNAL,'native-input','output-base'},
                    'staged foreign root member before continuation')
            self.output_fd=os.open('output-base',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            output=os.fstat(self.output_fd)
            require(output.st_uid == os.getuid() and output.st_gid == os.getgid()
                and stat.S_IMODE(output.st_mode) == 0o700,'staged output custody refused')
            self.output_identity=(output.st_dev,output.st_ino)
            self.input_fd=os.open('native-input',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.root_fd)
            self.source_fd=os.open('source',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.input_fd)
            self.custody=self.capture_custody()
            self.check_directories()
            self.verify_source_copy()
            if self.stage == 1:
                require(not os.listdir(self.output_fd),'staged first output base must be actually empty')
                self.write_journal('pending',[],first=True)
            else:
                self.admit_predecessors()
                self.write_journal('pending',self.stage_history)
            require(set(os.listdir(self.root_fd)) == {LOCK,JOURNAL,'native-input','output-base'},
                'staged exact private root members required')
            self.verified_before_launch=True
        except BaseException:
            self.close()
            raise


    def reserve_chain(self):
        # One fixed policy-level reservation, even if a later graph/key differs.
        value={'schema_version':1,'kind':KIND,'key':self.key,
            'provenance_sha256':self.key,'source_commit':self.args.source_commit,
            'selector_sha256':self.args.native_staged_compilation_sha256}
        raw=canonical(value)+b'\n'
        expected=hashlib.sha256(raw).hexdigest()
        parent=trusted_parent(native.STATE)
        try:
            if self.stage == 1:
                fd=os.open(CHAIN.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                try:
                    view=memoryview(raw)
                    while view:
                        native.tick(self.args.native_deadline)
                        count=os.write(fd,view);require(count>0,'staged chain short write');view=view[count:]
                    os.fchmod(fd,0o400)
                    os.fsync(fd)
                finally:os.close(fd)
                os.fsync(parent)
            self.chain_fd=os.open(CHAIN.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            info=os.fstat(self.chain_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_gid == os.getgid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == len(raw),
                'staged immutable policy-chain custody refused')
            document,pin=read_json(parent,CHAIN.name,self.args.native_deadline,expected)
            require(canonical(document) == canonical(value),'staged chain belongs to another policy/key')
            self.chain_sha,self.chain_witness=pin,prior.witness(info)
        finally:os.close(parent)

    def check_chain(self):
        require(self.chain_fd is not None,'staged held policy reservation closed')
        parent=trusted_parent(native.STATE)
        try:
            info=os.stat(CHAIN.name,dir_fd=parent,follow_symlinks=False)
            require(prior.witness(info) == self.chain_witness
                == prior.witness(os.fstat(self.chain_fd)),'staged immutable policy reservation changed')
            read_small(parent,CHAIN.name,self.args.native_deadline,self.chain_sha)
        finally:os.close(parent)

    def argument_snapshot(self,args):
        return canonical({'selector':str(args.native_staged_compilation),
            'selector_sha256':args.native_staged_compilation_sha256,'stage':args.native_stage,
            'mode':args.native_mode,'source_commit':args.source_commit,'source_dirty':args.source_dirty,
            'profile':args.profile,'manager':args.manager,'state':str(args.state_dir),
            'source_root':str(args.native_source_root),'source_pin':args.native_source_sha256,
            'export_root':str(args.native_export_root),'export_pin':args.native_export_sha256,
            'patches':list(args.native_patch_sha256),'aggregate_seconds':args.native_aggregate_seconds})

    @property
    def fresh_verified_before_launch(self):return self.verified_before_launch is True
    @property
    def staged_verified_before_launch(self):return self.verified_before_launch is True
    @property
    def staged_contract_kind(self):return KIND
    @property
    def staged_provenance_sha256(self):return self.key
    @property
    def staged_phase(self):return 'ABCD'[self.stage-1]

    def facts(self, *, stage=None, history=None, artifact_sha=None, predecessor=False):
        stage=self.stage if stage is None else stage
        require(type(stage) is int and stage in STAGES,'staged fact stage must be exact')
        return {'kind':KIND,'key':self.key,'provenance_sha256':self.key,
            'bindings':copy.deepcopy(self.provenance),'source_commit':self.args.source_commit,
            'workspace':str(self.source),'output_base':str(self.lease.output_base),
            'stage':stage,'max_stages':4,'mode':STAGES[stage][0],
            'previous_dispatches':consumed_dispatches(),
            'stage_history':copy.deepcopy(self.stage_history if history is None else history),
            'core_codegen':fixed_codegen(),'selector_sha256':self.args.native_staged_compilation_sha256,
            'chain_sha256':self.chain_sha,'custody':copy.deepcopy(self.custody),
            'artifacts_sha256':self.artifacts_sha if artifact_sha is None else artifact_sha,
            'verified_before_launch':True if predecessor else self.verified_before_launch,
            'verified_after_cleanup':True if predecessor else self.verified_after_cleanup}


    def capture_custody(self):
        descriptors={'chain':self.chain_fd,'root':self.root_fd,'output_base':self.output_fd,
            'lock':self.lock_fd,'native_input':self.input_fd,'source':self.source_fd}
        result={}
        modes={'chain':0o400,'root':0o700,'output_base':0o700,'lock':0o600,
            'native_input':0o555,'source':0o555}
        for name,fd in descriptors.items():
            require(fd is not None,'staged full held custody required')
            info=os.fstat(fd)
            regular=name in ('chain','lock')
            require((stat.S_ISREG(info.st_mode) and info.st_nlink==1 if regular
                else stat.S_ISDIR(info.st_mode))
                and info.st_uid==os.getuid() and info.st_gid==os.getgid()
                and stat.S_IMODE(info.st_mode)==modes[name],'staged source/root custody mode differs')
            result[name]={'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
        return result

    def check_directories(self):
        self.check_chain()
        require(self.root_fd is not None and self.output_fd is not None and self.lock_fd is not None,
            'staged held custody is closed')
        parent=trusted_parent(native.STATE)
        try:root=os.stat(self.root.name,dir_fd=parent,follow_symlinks=False)
        finally:os.close(parent)
        output=os.stat('output-base',dir_fd=self.root_fd,follow_symlinks=False)
        input_info=os.stat('native-input',dir_fd=self.root_fd,follow_symlinks=False)
        source_info=os.stat('source',dir_fd=self.input_fd,follow_symlinks=False)
        source_reopen=trusted_parent(self.source)
        try:
            require((os.fstat(source_reopen).st_dev,os.fstat(source_reopen).st_ino)
                == (source_info.st_dev,source_info.st_ino),'staged named source ancestry changed')
        finally:os.close(source_reopen)
        require(canonical(self.capture_custody())==canonical(self.custody)
            and (input_info.st_dev,input_info.st_ino)==(
                self.custody['native_input']['device'],self.custody['native_input']['inode'])
            and (source_info.st_dev,source_info.st_ino)==(
                self.custody['source']['device'],self.custody['source']['inode']),
            'staged persistent held source/output custody changed')
        lock=os.stat(LOCK,dir_fd=self.root_fd,follow_symlinks=False)
        require((root.st_dev,root.st_ino) == self.root_identity
            == (os.fstat(self.root_fd).st_dev,os.fstat(self.root_fd).st_ino)
            and (output.st_dev,output.st_ino) == self.output_identity
            == (os.fstat(self.output_fd).st_dev,os.fstat(self.output_fd).st_ino)
            and (lock.st_dev,lock.st_ino) == self.lock_identity
            == (os.fstat(self.lock_fd).st_dev,os.fstat(self.lock_fd).st_ino)
            and stat.S_ISDIR(root.st_mode) and stat.S_ISDIR(output.st_mode)
            and stat.S_ISREG(lock.st_mode) and lock.st_nlink == 1
            and root.st_uid == output.st_uid == lock.st_uid == os.getuid()
            and root.st_gid == output.st_gid == lock.st_gid == os.getgid()
            and stat.S_IMODE(root.st_mode) == stat.S_IMODE(output.st_mode) == 0o700
            and stat.S_IMODE(lock.st_mode) == 0o600,
            'staged named/held root/output/lock custody changed')

    def verify_source_copy(self):
        source=native.validate_source(self.args.native_source_root,self.args.native_source_sha256,
            self.args.native_patch_sha256,self.args.native_deadline)
        fd=trusted_parent(self.source)
        try:verify_inventory(fd,source['source_inventory'],EXPORT_MODE_POLICY,
            on_read=lambda count:native.tick(self.args.native_deadline))
        finally:os.close(fd)

    def recheck_declaration(self,verified_inputs=None):
        require(selected(self.args) and self.argument_snapshot(self.args) == self.args_snapshot,
            'staged selected arguments changed')
        current=bindings(self.args,self.tools,self.graph,self.locked_path,self.manager,
            verified_inputs=verified_inputs)
        inventory=controller_inventory(Path.cwd(),self.graph,self.args.native_deadline)
        parent=trusted_parent(SELECTOR.parent)
        try:document,_=read_json(parent,SELECTOR.name,self.args.native_deadline,
            self.args.native_staged_compilation_sha256)
        finally:os.close(parent)
        validate_document(document,current,inventory)
        require(canonical(current) == self.provenance_snapshot
            and canonical(document) == canonical(self.document),'staged provenance changed')

    def authorize_native_mode(self,args):
        require(type(self) is Admission and args is self.args
            and self.verified_before_launch is True and selected(args)
            and args.native_stage == self.stage and args.native_mode == STAGES[self.stage][0]
            and self.argument_snapshot(args) == self.args_snapshot,
            'staged command requires exact concrete admitted arguments')
        self.check_directories()
        # Full immutable input qualification is repeated here, before profile
        # construction can produce an executable command.
        self.recheck_declaration()
        self.verify_source_copy()
        read_small(self.root_fd,JOURNAL,args.native_deadline,self.journal_sha)
        self.verify_prior_stages()
        return True

    def journal_document(self,status,history):
        return {'schema_version':1,'kind':KIND,'key':self.key,'status':status,
            'stage':self.stage,'epoch':self.run.name,'stage_history':copy.deepcopy(history),
            'custody':copy.deepcopy(self.custody)}

    def write_journal(self,status,history,first=False):
        require(status in ('pending','qualified-stage','closed')
            and type(self.stage) is int and self.stage in STAGES and UUID.fullmatch(self.run.name),
            'staged journal exact role')
        if not first:read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)
        name=JOURNAL if first else 'journal-next-'+self.run.name
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.root_fd)
        raw=canonical(self.journal_document(status,history))+b'\n'
        try:
            view=memoryview(raw)
            while view:
                native.tick(self.args.native_deadline)
                size=os.write(fd,view);require(size>0,'staged journal short write');view=view[size:]
            os.fsync(fd)
        finally:os.close(fd)
        if not first:os.replace(name,JOURNAL,src_dir_fd=self.root_fd,dst_dir_fd=self.root_fd)
        os.fsync(self.root_fd)
        self.journal_sha=hashlib.sha256(raw).hexdigest()
        read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)

    def read_stage_receipt(self,row):
        history_row(row,self.key,row['stage'])
        fd=trusted_parent(native.STATE/row['id'])
        try:return read_json(fd,'receipt.json',self.args.native_deadline,row['sha256'])[0]
        finally:os.close(fd)

    def verify_prior_stages(self):
        for index,row in enumerate(self.stage_history):
            history_row(row,self.key,index+1)
            require(row['id'] != self.run.name,'staged cannot reuse predecessor epoch')
            receipt=self.read_stage_receipt(row)
            expected=self.facts(stage=index+1,history=self.stage_history[:index],
                artifact_sha=row['artifacts_sha256'],predecessor=True)
            verify_success(receipt,expected,self.graph,self.args.native_source_sha256,
                self.args.native_export_sha256,index+1)
            require(receipt['id'] == row['id'] and self.verify_previous(receipt) is True,
                'staged predecessor actual owned unit/cgroup not empty')
            verify_artifacts(native.STATE/row['id'],receipt,self.args.native_deadline)

    def admit_predecessors(self):
        journal,pin=read_json(self.root_fd,JOURNAL,self.args.native_deadline)
        require(set(journal) == {'schema_version','kind','key','status','stage','epoch','stage_history','custody'}
            and type(journal['schema_version']) is int and journal['schema_version'] == 1
            and journal['kind'] == KIND and journal['key'] == self.key
            and journal['status'] == 'qualified-stage'
            and type(journal['stage']) is int and journal['stage'] == self.stage-1
            and UUID.fullmatch(journal['epoch'])
            and isinstance(journal['stage_history'],list)
            and len(journal['stage_history']) == self.stage-1
            and canonical(journal['custody']) == canonical(self.custody),
            'staged continuation requires exactly completed preceding stage')
        rows=journal['stage_history']
        for index,row in enumerate(rows):history_row(row,self.key,index+1)
        require(len({row['id'] for row in rows}) == len(rows)
            and journal['epoch'] == rows[-1]['id'],'staged duplicate or wrong terminal history epoch')
        self.journal_sha=pin
        self.stage_history=copy.deepcopy(rows)
        self.verify_prior_stages()

    def verify_after_cleanup(self,verified_inputs):
        self.check_directories()
        self.recheck_declaration(verified_inputs=verified_inputs)
        historical_receipts(self.args.native_deadline,self.verify_previous)
        self.verify_source_copy()
        self.verify_prior_stages()
        read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)
        self.verified_after_cleanup=True

    def capture_artifacts(self,receipt):
        require(self.artifacts_sha is None and self.artifact_document is None,
            'staged actual artifacts may be captured only once')
        verify_success(receipt,self.facts(),self.graph,self.args.native_source_sha256,
            self.args.native_export_sha256,self.stage,capturing=True)
        self.check_directories()
        document=collect_stage_artifacts(self.run,receipt,self.args.native_deadline)
        raw=canonical(document)+b'\n'
        require(len(raw)<=prior.MAX_METADATA,'staged artifact receipt bytes bound')
        parent=trusted_parent(self.run)
        try:
            fd=os.open(ARTIFACTS,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            try:
                view=memoryview(raw)
                while view:
                    native.tick(self.args.native_deadline)
                    count=os.write(fd,view);require(count>0,'staged artifact receipt short write');view=view[count:]
                os.fsync(fd)
            finally:os.close(fd)
            os.fsync(parent)
            document_after,pin=read_json(parent,ARTIFACTS,self.args.native_deadline,hashlib.sha256(raw).hexdigest())
        finally:os.close(parent)
        require(canonical(document_after) == canonical(document),'staged artifact receipt readback differs')
        self.artifacts_sha=pin
        self.artifact_document=document

    def finish(self,receipt,receipt_sha):
        require(isinstance(receipt_sha,str) and HASH.fullmatch(receipt_sha),
            'staged actual receipt pin required')
        verify_success(receipt,self.facts(),self.graph,self.args.native_source_sha256,
            self.args.native_export_sha256,self.stage)
        self.check_directories()
        verify_artifacts(self.run,receipt,self.args.native_deadline,
            expected=self.artifact_document,rehash_outputs=False)
        require(self.artifact_document is not None,'staged actual captured artifacts required')
        row={'stage':self.stage,'id':self.run.name,'sha256':receipt_sha,
            'artifacts_sha256':self.artifacts_sha,'key':self.key}
        history_row(row,self.key,self.stage)
        require(len(self.stage_history) == self.stage-1,'staged immutable phase history differs')
        self.write_journal('qualified-stage' if self.stage<4 else 'closed',
            self.stage_history+[row])

    def close_failed(self,receipt,receipt_sha):
        require(receipt['id'] == self.run.name and HASH.fullmatch(receipt_sha),
            'staged failed actual epoch required')
        # Record consumed failure separately, never as a successful predecessor.
        journal=self.journal_document('closed',self.stage_history)
        journal.update(failed_dispatch={'stage':self.stage,'id':self.run.name,
            'sha256':receipt_sha,'key':self.key})
        read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)
        name='journal-failed-'+self.run.name
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.root_fd)
        raw=canonical(journal)+b'\n'
        try:
            view=memoryview(raw)
            while view:
                native.tick(self.args.native_deadline)
                size=os.write(fd,view);require(size>0,'staged failed journal short write');view=view[size:]
            os.fsync(fd)
        finally:os.close(fd)
        os.replace(name,JOURNAL,src_dir_fd=self.root_fd,dst_dir_fd=self.root_fd)
        os.fsync(self.root_fd)
        self.journal_sha=hashlib.sha256(raw).hexdigest()
        read_small(self.root_fd,JOURNAL,self.args.native_deadline,self.journal_sha)

    def close(self):
        for name in ('source_fd','input_fd','output_fd','lock_fd','root_fd','chain_fd'):
            fd=getattr(self,name,None)
            if fd is not None:
                os.close(fd);setattr(self,name,None)
