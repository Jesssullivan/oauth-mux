"""Read completed selected-SDK evidence without reopening its execution clock.

No admission, selector creation, locking, cache adoption or native execution.
The owner of a later action supplies a bounded IO clock. Recorded protocol
entry/deadline, selected bytes, common custody and closed journal remain exact.
"""
import copy
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

import codex_protocol_history_native as protocol
import codex_native_profile as native
from codex_native_candidate_cache import transition_graph
from codex_fresh_source import trusted_parent
from codex_sdk_profile import require

KIND='omux-protocol-history-cli-selection-v1'
STATE=protocol.STATE
STAGES=protocol.STAGES
MODES=protocol.MODES
GATES=protocol.GATES
BAZEL=protocol.BAZEL
UUID=protocol.UUID
canonical=protocol.canonical
sha=protocol.sha
pin=protocol.pin
tick=protocol.tick
boot_host=protocol.boot_host
sealed_io=protocol.sealed_io


def validate_selection(document):
    require(type(document) is dict and set(document)=={
        'schema_version','kind','inputs','input_selection_sha256','predecessors'}
        and type(document['schema_version']) is int and document['schema_version']==1
        and document['kind']==KIND, 'closed CLI completed-input selection required')
    protocol.validate_selection(document['inputs'])
    pin(document['input_selection_sha256'])
    rows=document['predecessors']
    require(type(rows) is dict and set(rows)=={'1','2'}, 'both actual completed predecessors required')
    for position,row in rows.items():
        require(type(row) is dict and set(row)=={'id','sha256','artifacts_sha256'}
            and type(row['id']) is str and UUID.fullmatch(row['id']),
            'closed completed predecessor pin required')
        pin(row['sha256']);pin(row['artifacts_sha256'])
    require(rows['1']['id']!=rows['2']['id'], 'tests and schemas need distinct actual epochs')
    return document


def exported_plan(report,document):
    """Only immutable command mappings. Complete SDK validation stays in its owner."""
    root=Path(document['sdk']['root'])
    if document['kind'] == 'omux-owner-status-persistence-native-selection-v1':
        from codex_persistence_package_family import SDK_EXTRA, export
        require(type(report) is dict and set(report) == protocol.SDK_FIELDS | SDK_EXTRA
            and report['kind'] == export.KIND and report['status'] == 'verified-selected-owner-status-persistence-sdk'
            and report['source_root'] == document['source']['root']
            and report['source_receipt_sha256'] == document['source']['receipt_sha256']
            and report['source_inventory_sha256'] == document['source']['inventory_sha256']
            and report['inventory_sha256'] == document['sdk']['inventory_sha256']
            and report['sdk_export_qualified'] is True
            and all(report[name] is False for name in ('schema_producer_qualified','live_handoff_proven',
                'native_compile_passed','native_support','provider_evaluation')), 'closed persistence SDK command mapping differs')
        return {'repositories':{row['canonical_name']:str(root/'repositories'/row['canonical_name']) for row in report['repositories']},
            'module_overrides':{name:str(root/'repositories'/row['canonical_name']) for name,row in report['modules'].items()},
            'registry_cache':str(root/'registry-cache'),'inventory_sha256':document['sdk']['inventory_sha256'],
            'mapping_sha256':report['mapping_sha256']}
    require(type(report) is dict and set(report)==protocol.SDK_FIELDS
        and report['kind']==protocol.selected_sdk.KIND
        and report['status']=='verified-selected-protocol-history-sdk'
        and report['source_root']==document['source']['root']
        and report['source_receipt_sha256']==document['source']['receipt_sha256']
        and report['source_inventory_sha256']==document['source']['inventory_sha256']
        and report['inventory_sha256']==document['sdk']['inventory_sha256']
        and all(report[name] is False for name in (
            'native_compile_passed','native_support','provider_evaluation')),
        'closed selected SDK command mapping required')
    return {'repositories':{row['canonical_name']:str(root/'repositories'/row['canonical_name'])
            for row in report['repositories']},
        'module_overrides':{name:str(root/'repositories'/row['canonical_name'])
            for name,row in report['modules'].items()},
        'registry_cache':str(root/'registry-cache'),
        'inventory_sha256':document['sdk']['inventory_sha256'],
        'mapping_sha256':report['mapping_sha256']}



def validate_controller(bindings,document):
    require(type(bindings['controller_inventory']) is dict
        and canonical(transition_graph(bindings['controller_inventory']))==canonical(bindings['controller_graph'])
        and bindings['controller_graph'][0]==document['controller_graph_sha256'],
        'completed exact controller graph inventory differs')
    tools=bindings['tools']
    require(type(tools) is dict and set(tools)=={
        'bazel','python','systemd_run','systemctl','bootstrap','closure','java','bash'}
        and tools['bazel']==BAZEL
        and all(type(value) is str and value.startswith('/nix/store/')
            and len(value)<=4096 and '..' not in Path(value).parts
            and not any(c.isspace() for c in value) for value in tools.values())
        and type(bindings['locked_path']) is str and 0<len(bindings['locked_path'])<=8192
        and all(value.startswith('/nix/store/') and '..' not in Path(value).parts
            and not any(c.isspace() for c in value) for value in bindings['locked_path'].split(':')),
        'completed actual immutable tools/locked PATH differ')

def verify_archived_protocol(receipt,document,stage,exported,deadline):
    """Validate recorded execution; current IO uses only the caller's clock."""
    tick(deadline)
    sealed_io.verify_caps(receipt)
    facts=receipt['native_protocol_history'];sdk_receipt=receipt['native_sdk'];plan=sdk_receipt['plan']
    require(type(facts) is dict and set(facts)=={'kind','key','bindings','stage','max_dispatches',
        'workspace','output_base','chain_sha256','custody','history','original_entry_monotonic_ns',
        'original_deadline_monotonic_ns','action_entry_monotonic_ns','verified_before_launch',
        'verified_after_cleanup','artifacts_sha256','native_support','provider_evaluation'},
        'selected closed success facts required')
    bindings=facts['bindings']
    validate_controller(bindings,document)
    require(type(bindings) is dict and set(bindings)=={'kind','selection','controller_inventory',
        'controller_graph','tools','source_sdk_custody','locked_path','boot_host','stages','gates',
        'limits','network','batch','repository_download','remote','ambient_caches','core_codegen'}
        and bindings['kind']==protocol.KIND and bindings['stages']=={'1':STAGES[1],'2':STAGES[2]}
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
        and facts['kind']==protocol.KIND and type(facts['stage']) is int and facts['stage']==stage
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
        and type(sdk_receipt['original_entry_monotonic_ns']) is int
        and type(sdk_receipt['original_deadline_monotonic_ns']) is int
        and sdk_receipt['original_entry_monotonic_ns']==facts['original_entry_monotonic_ns']
        and sdk_receipt['original_deadline_monotonic_ns']==facts['original_deadline_monotonic_ns']
        and type(facts['original_entry_monotonic_ns']) is int and facts['original_entry_monotonic_ns']>=0
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
    export_root=Path(document['sdk']['root'])
    fake_args=SimpleNamespace(native_mode=STAGES[stage],native_deadline=deadline,
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



def same_custody(file,row,deadline, *, directory):
    tick(deadline)
    require(type(row) is dict and set(row)=={'device','inode','uid','gid','mode'}
        and all(type(value) is int for value in row.values()) and row['device']>=0 and row['inode']>0,
        'completed custody scalar types refused')
    parent=trusted_parent(Path(file).parent)
    fd=None
    try:
        fd=os.open(Path(file).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
            |(os.O_DIRECTORY if directory else 0),dir_fd=parent)
        before=os.fstat(fd)
        expected={'device':before.st_dev,'inode':before.st_ino,'uid':before.st_uid,
            'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode)}
        require((stat.S_ISDIR(before.st_mode) if directory else
            stat.S_ISREG(before.st_mode) and before.st_nlink==1)
            and before.st_uid==os.getuid() and before.st_gid==os.getgid()
            and expected==row, 'completed held identity replaced')
        again=trusted_parent(Path(file).parent)
        try:
            require((os.fstat(parent).st_dev,os.fstat(parent).st_ino)==(
                os.fstat(again).st_dev,os.fstat(again).st_ino), 'completed ancestry replaced')
        finally:os.close(again)
        named=os.stat(Path(file).name,dir_fd=parent,follow_symlinks=False)
        require(protocol.witness(before)==protocol.witness(os.fstat(fd))==protocol.witness(named),
            'completed identity changed during readback')
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def recheck_completed_custody(selection,receipts,deadline):
    facts=receipts[2]['native_protocol_history']
    first=receipts[1]['native_protocol_history']
    require(facts['custody']==first['custody']
        and facts['chain_sha256']==first['chain_sha256']
        and facts['bindings']==first['bindings']
        and facts['original_entry_monotonic_ns']==first['original_entry_monotonic_ns']
        and facts['original_deadline_monotonic_ns']==first['original_deadline_monotonic_ns'],
        'completed original chain/custody/clock differs')
    root=STATE/('protocol-history-checks-'+facts['key'])
    files={'chain':protocol.CHAIN,'root':root,'lock':root/'lock',
        'output':root/'output-base','input':root/'native-input','source':root/'native-input/source'}
    for name,file in files.items():
        same_custody(file,facts['custody'][name],deadline,directory=name not in ('chain','lock'))
    chain=protocol.read_json(protocol.CHAIN,facts['chain_sha256'],deadline,8192)
    expected_chain={'schema_version':1,'kind':protocol.KIND,'key':facts['key'],
        'selector_sha256':selection['input_selection_sha256'],
        'source_commit':selection['inputs']['controller_source_commit'],
        'boot_host':facts['bindings']['boot_host'],
        'original_entry_monotonic_ns':facts['original_entry_monotonic_ns'],
        'original_deadline_monotonic_ns':facts['original_deadline_monotonic_ns']}
    require(canonical(chain)==canonical(expected_chain), 'completed immutable chain bytes differ')
    expected=[]
    for stage in (1,2):
        row=selection['predecessors'][str(stage)]
        expected.append({'stage':stage,**row})
    fd=trusted_parent(root)
    try:
        require(set(os.listdir(fd))=={'lock','output-base','native-input',protocol.JOURNAL},
            'completed root shape differs')
        journal,_=sealed_io.read_json(fd,protocol.JOURNAL,deadline)
    finally:os.close(fd)
    require(type(journal) is dict and set(journal)=={
        'schema_version','kind','key','stage','epoch','status','history','custody','chain_sha256'}
        and type(journal['schema_version']) is int and journal['schema_version']==1
        and type(journal['stage']) is int and journal['stage']==2
        and journal['kind']==protocol.KIND and journal['key']==facts['key']
        and journal['epoch']==receipts[2]['id'] and journal['status']=='closed'
        and canonical(journal['history'])==canonical(expected)
        and journal['custody']==facts['custody'] and journal['chain_sha256']==facts['chain_sha256'],
        'completed chain must have exactly two successful closed positions')
    held=facts['bindings']['source_sdk_custody']
    roots=(selection['inputs']['source']['root'],selection['inputs']['sdk']['root'],
        str(protocol.inputs.EXPORT_ROOT))
    require(type(held) is dict and set(held)==set(roots), 'completed source/SDK custody set differs')
    for file in roots:
        require(held[file]['mode']==0o555, 'completed source/SDK must remain sealed')
        same_custody(Path(file),held[file],deadline,directory=True)


def validate_completed_receipts(selection,receipts,envelopes,exported,deadline, *, rehash=True):
    """Supplied receipt/envelope bytes are independently pinned by their caller.

    Package callers supply declared parsed metadata; no selectors or receipt
    paths are opened here. Canonical guard receipt/envelope serialization pins
    are also checked. Physical custody and output rehashes remain required.
    """
    validate_selection(selection)
    require(type(rehash) is bool and rehash is True
        and type(receipts) is dict and set(receipts)=={1,2}
        and type(envelopes) is dict and set(envelopes)=={1,2},
        'complete successful protocol metadata and physical rehash required')
    for stage in (1,2):
        receipt=receipts[stage];row=selection['predecessors'][str(stage)]
        require(sha((json.dumps(receipt,sort_keys=True)+'\n').encode())==row['sha256']
            and sha(canonical(envelopes[stage])+b'\n')==row['artifacts_sha256']
            and receipt['id']==row['id']
            and receipt['native_protocol_history']['artifacts_sha256']==row['artifacts_sha256'],
            'completed receipt/envelope pin differs')
        verify_archived_protocol(receipt,selection['inputs'],stage,exported,deadline)
    first=receipts[1]['native_protocol_history'];second=receipts[2]['native_protocol_history']
    require(first['history']==[] and canonical(second['history'])==canonical([{
        'stage':1,**selection['predecessors']['1']}]), 'completed successful predecessor history differs')
    # Named/inode and chain-content fences precede any output artifact IO.
    recheck_completed_custody(selection,receipts,deadline)
    for stage in (1,2):
        actual=protocol.collect_artifacts(STATE/receipts[stage]['id'],receipts[stage],deadline)
        require(canonical(actual)==canonical(envelopes[stage]), 'completed accepted output evidence changed')
    recheck_completed_custody(selection,receipts,deadline)
    return {'kind':protocol.KIND,'key':first['key'],'chain_sha256':first['chain_sha256'],
        'original_entry_monotonic_ns':first['original_entry_monotonic_ns'],
        'original_deadline_monotonic_ns':first['original_deadline_monotonic_ns'],
        'predecessors':copy.deepcopy(selection['predecessors']),
        'custody':copy.deepcopy(first['custody'])}


def load_completed_inputs(selection,patches,deadline,verify_previous=None):
    validate_selection(selection);document=selection['inputs']
    require(protocol.read_json(protocol.SELECTOR,selection['input_selection_sha256'],deadline)==document,
        'original selected input bytes differ')
    for role,target,output in protocol.producer_roles(document):
        prior=protocol.producer_success(document[role],target,output,deadline)
        if verify_previous is not None:
            require(verify_previous(prior) is True, 'completed producer unit/cgroup no longer empty')
    report=protocol.validate_source(Path(document['source']['root']),
        document['source']['receipt_sha256'],patches,deadline)
    require(report['inventory_sha256']==document['source']['inventory_sha256'],
        'completed selected source inventory differs')
    exported=protocol.verify_selected_export(Path(document['sdk']['root']),
        document['sdk']['receipt_sha256'],report,document,deadline)
    receipts={};envelopes={}
    for stage in (1,2):
        row=selection['predecessors'][str(stage)];run=STATE/row['id']
        receipts[stage]=protocol.read_json(run/'receipt.json',row['sha256'],deadline)
        envelopes[stage]=protocol.read_json(run/protocol.ARTIFACTS,row['artifacts_sha256'],deadline)
    completed=validate_completed_receipts(selection,receipts,envelopes,exported,deadline)
    if verify_previous is not None:
        for receipt in receipts.values():
            require(verify_previous(receipt) is True, 'completed native unit/cgroup no longer empty')
    return (report,exported),completed
