"""Fresh retained SOURCE/HUB content, never previous action SDK/inode authority.

Only this distinct selector/mapping family admits a cache-backed SOURCE phase
followed by an uncached independently bounded delivery and verified cleanup.
Every actual proof read joins the complete declared mapping and original held
alias/parent/leaf witnesses under the current consumer's unchanged proof clock.
"""
import json
import os
from pathlib import Path
import re
import stat
import uuid
import codex_native_file_writer_model_source as family
import guard_native_siwc_catalog_content_source_reserved as guard

source = family.source
SELECTION_KIND = 'omux-native-siwc-catalog-retained-delivery-selection-v1'
STATUS = 'qualified-retained-catalog-content-source-hub-uncompiled'
INPUT_KIND = 'omux-native-siwc-catalog-retained-delivery-input-v1'
REPOSITORY = 'omux_native_siwc_catalog_model_inputs'
PUBLICATION_KIND = 'omux-native-siwc-content-retained-publication-v1'
PHASE_KIND = 'omux-native-siwc-content-source-phase-v1'
LEAF = 'native-siwc-catalog-content-source'
DELIVERY_TARGET = '//tools:codex_native_siwc_content_delivery_producer'
PHASE_KEYS = frozenset(('schema_version','kind','id','profile','targets','source_commit','graph_sha256',
    'context','clocks','exit','workload_exit','epoch_start_ns','output_base','cache_reuse_requested',
    'cache_policy','cache_key','dependency_lease','command','limits','worker','cleanup','descendants_empty',
    'test_evidence','native_siwc_catalog_content_source_reservation'))
FLAGS = ('original_action_sdk_custody_inherited','source_qualification_extended','sdk_execution_qualified',
    'compiler_qualified','native_runtime_qualified','ordinary_launch_qualified','continuity_qualified')


def closed(value, keys):
    source.require(type(value) is dict and set(value) == set(keys))
    return value


def count(value, minimum=1, maximum=source.MAX_METADATA):
    source.require(type(value) is int and minimum <= value <= maximum)
    return value


def selection(value, control_sha):
    closed(value, ('schema_version','kind','status','catalog_controls_sha256','source'))
    source.require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == SELECTION_KIND and value['status'] == STATUS
        and value['catalog_controls_sha256'] == control_sha)
    _row(value['source'])
    return value


def _row(row):
    closed(row, ('root','receipt_sha256','receipt_bytes','inventory_sha256',
        'producer','transport_receipt','source_phase_receipt'))
    family.protocol.producer_pin(row['producer'])
    family.protocol.pin(row['receipt_sha256']); family.protocol.pin(row['inventory_sha256'])
    count(row['receipt_bytes'])
    run = Path(row['producer']['receipt']).parent
    source.require(family.protocol.path(row['root']) == run/'native-content-retained'/LEAF)
    for name in ('transport_receipt','source_phase_receipt'):
        closed(row[name], ('sha256','bytes')); family.protocol.pin(row[name]['sha256']); count(row[name]['bytes'])
    return row


def proof_paths(row):
    run = Path(row['producer']['receipt']).parent
    return run, run/'source-phase-receipt.json', run/'native-content-retained/publication-receipt.json'


class _OwnedFD:
    """Callback is enrolled while empty; acquisition overwrites an existing slot."""
    def __init__(self): self.fd = None
    def close(self):
        fd = self.fd; self.fd = None
        if fd is not None: os.close(fd)


class RetainedInputs(family.Inputs):
    """Role-specific private coordinator metadata; old Inputs mode policy is intact."""
    def __init__(self, runfiles, rows):
        self.role_modes = {}
        super().__init__(runfiles, rows, _repository=REPOSITORY, _kind=INPUT_KIND)

    def admit(self, selected):
        source.require(self.selection == selected)
        run, phase, publication = proof_paths(selected)
        self.role_modes = {str(run/'receipt.json'):(0o600,0o444,0o555),
            str(phase):(0o400,0o600), str(publication):(0o444,)}

    def _capture(self, path, maximum, *, declaration=False):
        path = Path(path)
        if declaration:
            source.require(path == self.path and path.name == 'source-inputs.json' and path.parent.parent.name == 'external')
        modes = ((0o444,0o555,0o644) if declaration else self.role_modes.get(str(path),(0o444,0o555)))
        # Both empty owners are enrolled BEFORE acquiring any new FD. A
        # callback allocation fault, including append-then-raise, owns no new
        # descriptor. Close detaches first and never retries an ambiguous FD.
        parent_owner, leaf_owner = _OwnedFD(), _OwnedFD()
        self.stack.callback(parent_owner.close); self.stack.callback(leaf_owner.close)
        parent_owner.fd = source.directory(path.parent)
        parent = parent_owner.fd
        leaf_owner.fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        fd = leaf_owner.fd
        before = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        anchor = family.tenth.witness(before)
        source.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) in modes and 0 < before.st_size <= maximum
            and family.tenth.witness(os.fstat(fd)) == anchor)
        parent_anchor = family.tenth.witness(os.fstat(parent))
        raw, unused = source.read(parent,path.name,maximum)
        source.require(family.tenth.witness(os.fstat(fd)) == anchor == family.tenth.witness(
            os.stat(path.name,dir_fd=parent,follow_symlinks=False))
            and family.tenth.witness(os.fstat(parent)) == parent_anchor)
        self.held[str(path)] = (parent,fd,anchor,parent_anchor)
        return raw


def _worker(value, identity):
    closed(value, ('unit','invocation','pid','start_ticks','cgroup','kernel_bounds'))
    source.require(value['unit'] == 'omux-execution-'+identity+'.service'
        and type(value['invocation']) is str and re.fullmatch(r'[0-9a-f]{32}',value['invocation']) is not None
        and type(value['start_ticks']) is str and re.fullmatch(r'[1-9][0-9]*',value['start_ticks']) is not None)
    count(value['pid'],maximum=2**31-1)
    cgroup = family.protocol.path(value['cgroup'])
    source.require(str(cgroup).startswith('/sys/fs/cgroup/') and cgroup.name == value['unit'])
    bounds = closed(value['kernel_bounds'], ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group'))
    source.require(bounds['memory.max'] == str(guard.MEMORY) and bounds['memory.swap.max'] == '0'
        and bounds['pids.max'] == str(guard.TASKS) and bounds['memory.oom.group'] == '1')
    cpu = bounds['cpu.max'].split()
    source.require(len(cpu) == 2 and all(re.fullmatch(r'[1-9][0-9]{0,8}',part) for part in cpu)
        and int(cpu[0])*100 == guard.CPU*int(cpu[1]))


def _cleanup(value):
    closed(value, ('state','stop','ownership','readback_attempts','pre_stop','post_stop'))
    source.require(value['state'] == 'empty' and value['ownership'] == 'verified' and value['stop'] == 'succeeded')
    count(value['readback_attempts'],minimum=2,maximum=8)
    before = closed(value['pre_stop'], ('schema_version','scope','LoadState','ActiveState','SubState','MainPID',
        'Id_matches','InvocationID_matches','ExecMainPID_matches','ExecMainCode','Result','RemainAfterExit',
        'ExecMainStatus','terminal_class'))
    after = closed(value['post_stop'], ('schema_version','scope','LoadState','ActiveState','SubState','MainPID',
        'Id_matches','InvocationID_matches','ExecMainPID_matches','original_cgroup_state','predicate'))
    source.require(type(before['schema_version']) is int and type(after['schema_version']) is int
        and before['LoadState'] == 'loaded' and before['ActiveState'] == 'active'
        and before['SubState'] == 'exited' and before['MainPID'] == 'zero' and before['RemainAfterExit'] == 'yes'
        and type(after['InvocationID_matches']) is bool and type(after['ExecMainPID_matches']) is bool
        and before['schema_version'] == after['schema_version'] == 1
        and before['scope'] == 'reserved-owned-pre-stop-diagnostic-v1'
        and after['scope'] == 'reserved-owned-post-stop-diagnostic-v1'
        and before['Id_matches'] is True and before['InvocationID_matches'] is True
        and before['ExecMainPID_matches'] is True and before['ExecMainCode'] == '1'
        and type(before['ExecMainStatus']) is int and before['ExecMainStatus'] == 0
        and before['Result'] == 'success' and before['terminal_class'] == 'unqualified'
        and after['Id_matches'] is True and after['MainPID'] == 'zero'
        and after['ActiveState'] == 'inactive' and after['SubState'] == 'dead'
        and after['original_cgroup_state'] in ('empty','absent') and after['predicate'] == 'manager-predicate-passed'
        and (after['LoadState'] == 'not-found' or
            (after['LoadState'] == 'loaded' and after['InvocationID_matches'] is True and after['ExecMainPID_matches'] is True)))


def _resident(value):
    closed(value, ('scope','kernel_bounds','observations','initial_direct_processes_retained',
        'initial_direct_process_count','outer_pid_namespace_matched','hierarchical_caps',
        'descendant_process_inventory','installation_qualified','health_observed','custody_observed',
        'resident_signalled','whole_host_reservation'))
    source.require(value['scope'] == 'sampled-fixed-default-cgroup-kernel-reservation-v1'
        and value['initial_direct_processes_retained'] is True and value['outer_pid_namespace_matched'] is True
        and value['hierarchical_caps'] is True and all(value[key] is False for key in
            ('descendant_process_inventory','installation_qualified','health_observed','custody_observed',
             'resident_signalled','whole_host_reservation')))
    count(value['observations'],maximum=65535)
    count(value['initial_direct_process_count'],maximum=guard.kernel.resident.RESIDENT_TASKS)
    guard.kernel.kernel_bounds(value['kernel_bounds'])


def _reservation_pair(original, final, entry, until):
    # The SOURCE checkpoint and final outer contain genuine different samples.
    # Only the bounded monotone sample counter may differ; no old qualification
    # clock/process/namespace/capability predicate is extended by this join.
    for value in (original,final):
        source.require(type(value) is dict)
        expected = guard.projection(entry,until,True,value['resident'])
        source.require(value == expected and all(type(value[key]) is bool for key,item in expected.items()
            if type(item) is bool))
        _resident(value['resident'])
    before,after = original['resident'], final['resident']
    source.require(after['observations'] >= before['observations']
        and {key:value for key,value in before.items() if key != 'observations'} ==
            {key:value for key,value in after.items() if key != 'observations'})


def _context(phase, row):
    run = Path(row['producer']['receipt']).parent
    value = closed(phase['context'], ('MODE','ENTRY_NS','DEADLINE_NS','EPOCH','SOURCE_COMMIT','GRAPH_SHA256'))
    source.require(all(type(part) is str for part in value.values()) and value['MODE'] == guard.INPUT_MODE
        and value['EPOCH'] == str(run) and value['SOURCE_COMMIT'] == row['producer']['source_commit']
        and value['GRAPH_SHA256'] == row['producer']['graph_sha256']
        and re.fullmatch(r'[1-9][0-9]*',value['ENTRY_NS']) is not None
        and re.fullmatch(r'[1-9][0-9]*',value['DEADLINE_NS']) is not None)
    entry, until = int(value['ENTRY_NS']), int(value['DEADLINE_NS'])
    guard.kernel.envelope(entry,until)
    source.require(phase['clocks'] == {'source_until_ns':entry+600*10**9,
        'work_until_ns':until-30*10**9,'outer_until_ns':until})
    return value, entry, until


def _lease(value, context):
    closed(value, ('kind','key','namespace','output_base','run_id','checkout','source_commit','graph_sha256',
        'entry_monotonic_ns','deadline_monotonic_ns'))
    family.protocol.pin(value['key'])
    run = Path(context['EPOCH'])
    source.require(value['kind'] == 'omux-native-siwc-content-dependency-lease-v1'
        and value['namespace'] == 'cache-v2-'+value['key'] and value['run_id'] == run.name
        and value['output_base'] == str(run.parent/value['namespace']/'output-base')
        and value['source_commit'] == context['SOURCE_COMMIT'] and value['graph_sha256'] == context['GRAPH_SHA256']
        and type(value['entry_monotonic_ns']) is int and value['entry_monotonic_ns'] == int(context['ENTRY_NS'])
        and type(value['deadline_monotonic_ns']) is int and value['deadline_monotonic_ns'] == int(context['DEADLINE_NS']))
    family.protocol.path(value['checkout']); family.protocol.path(value['output_base'])


def _command(value, context, *, delivery=False, timeout=None, request_pin=None):
    source.require(type(value) is list and 0 < len(value) <= 256
        and all(type(part) is str and 0 < len(part) <= 16384 and '\x00' not in part for part in value))
    # Only interpreted option families are constrained; unrelated canonical
    # Bazel arguments are retained. Bare assignment aliases and contradictory
    # boolean suffix/inverse forms cannot hide next to the required tokens.
    for name in ('remote_cache','remote_executor','repo_contents_cache','test_timeout',
            'output_base','output_user_root','test_env','repo_env'):
        prefix = '--'+name
        source.require(all(part.startswith(prefix+'=') for part in value if part.startswith(prefix)))
    source.require([part for part in value if part.startswith(('--repository_disable_download',
        '--norepository_disable_download'))] == ['--repository_disable_download'])
    source.require([part for part in value if part.startswith(('--nocache_test_results',
        '--cache_test_results'))] == ['--nocache_test_results'])
    source.require([part for part in value if part.startswith('--repo_contents_cache')] == ['--repo_contents_cache='])
    targets = [DELIVERY_TARGET] if delivery else guard.ARGUMENTS[1:]
    source.require(value[-len(targets):] == targets and value.count('test') == 1
        and '--repository_disable_download' in value and '--repo_contents_cache=' in value
        and not any(part.startswith(('--test_filter','--test_arg')) for part in value))
    for prefix in ('--remote_executor=','--remote_cache='):
        source.require([part for part in value if part.startswith(prefix)] == [prefix])
    # Explicit disabled test caching is required in both producer phases.
    source.require(value.count('--nocache_test_results') == 1 and not any(part.startswith('--cache_test_results') for part in value))
    wanted = {'OMUX_NATIVE_FILE_WRITER_MODELS_'+name:value for name,value in context.items()}
    request_keys = ('OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST',
        'OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256')
    request_values = (str(Path(context['EPOCH'])/'native-content-delivery-request.json'),request_pin)
    for kind in ('test_env','repo_env'):
        prefix = '--'+kind+'='
        entries = [part[len(prefix):] for part in value if part.startswith(prefix)]
        # Count the name before its optional value: an inherited protected key
        # cannot hide next to the explicit assignment or override its context.
        for key,expected in wanted.items():
            matches = [entry for entry in entries if entry.partition('=')[0] == key]
            if kind == 'test_env' or not delivery or matches:
                source.require(matches == [key+'='+expected])
        for key,expected in zip(request_keys,request_values):
            matches = [entry for entry in entries if entry.partition('=')[0] == key]
            source.require(matches == ([key+'='+expected] if delivery and kind == 'test_env' else []))
    if not delivery:
        values = [part[len('--test_timeout='):] for part in value if part.startswith('--test_timeout=')]
        source.require(len(values) == 1 and re.fullmatch(r'[1-9][0-9]{0,2}',values[0]) is not None
            and 1 <= int(values[0]) <= guard.ACTION_SECONDS)
    if delivery:
        run = Path(context['EPOCH'])
        for prefix,expected in (('--output_base=',str(run/'delivery-output-base')),
                ('--output_user_root=',str(run/'delivery-user-root')),
                ('--test_timeout=',str(timeout)),
                ('--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST=',str(run/'native-content-delivery-request.json')),
                ('--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256=',request_pin)):
            source.require([part for part in value if part.startswith(prefix)] == [prefix+expected])


def _publication(value, phase, row, evidence_pin, configuration):
    closed(value, ('schema_version','kind','scope','context','clocks','dependency_lease',
        'source_phase_receipt_sha256','test_evidence_sha256','original_action','publication')+FLAGS)
    source.require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == PUBLICATION_KIND and value['scope'] == 'operational-fresh-source-hub-delivery-only'
        and value['context'] == phase['context'] and value['clocks'] == phase['clocks']
        and value['dependency_lease'] == phase['dependency_lease']
        and value['source_phase_receipt_sha256'] == row['source_phase_receipt']['sha256']
        and value['test_evidence_sha256'] == evidence_pin and all(value[name] is False for name in FLAGS))
    action = closed(value['original_action'], ('root','source_receipt_sha256','source_receipt_bytes','inventory_sha256'))
    action_root = Path(phase['output_base'])/'execroot/_main/bazel-out'/configuration/'testlogs/tools/codex_native_siwc_catalog_content_source_producer/test.outputs'/LEAF
    source.require(action == {'root':str(action_root),'source_receipt_sha256':row['receipt_sha256'],
        'source_receipt_bytes':row['receipt_bytes'],'inventory_sha256':row['inventory_sha256']})
    current = closed(value['publication'], ('root','members','source_bytes','fresh_witnesses_sha256'))
    source.require(current['root'] == row['root'] and type(current['members']) is dict
        and 8559 <= len(current['members']) <= 8574)
    count(current['source_bytes'],maximum=512*1024*1024); family.protocol.pin(current['fresh_witnesses_sha256'])


def guardian(row, inputs):
    """Authenticate closed historical phase facts plus current declared delivery bytes."""
    source.require(type(inputs) is RetainedInputs and inputs.selection == row)
    _row(row)
    inputs.admit(row)
    run, phase_path, publication_path = proof_paths(row)
    outer = family.decode(inputs.read(run/'receipt.json',row['producer']['sha256'],source.DEADLINE,16*1024*1024))
    phase_raw = inputs.read(phase_path,row['source_phase_receipt']['sha256'],source.DEADLINE,source.MAX_METADATA)
    source.require(len(phase_raw) == row['source_phase_receipt']['bytes'])
    phase = closed(family.decode(phase_raw),PHASE_KEYS)
    context, entry, until = _context(phase,row)
    _lease(phase['dependency_lease'],context)
    source.require(type(phase['schema_version']) is int and phase['schema_version'] == 1 and phase['kind'] == PHASE_KIND
        and phase['id'] == run.name and phase['profile'] == guard.PROFILE and phase['targets'] == guard.ARGUMENTS[1:]
        and phase['source_commit'] == context['SOURCE_COMMIT'] and phase['graph_sha256'] == context['GRAPH_SHA256']
        and type(phase['exit']) is int and phase['exit'] == 0 and type(phase['workload_exit']) is int and phase['workload_exit'] == 0
        and phase['descendants_empty'] is True and phase['cache_reuse_requested'] is True
        and type(phase['cache_policy']) is int and phase['cache_policy'] == 2
        and phase['cache_key'] == phase['dependency_lease']['key'] and phase['output_base'] == phase['dependency_lease']['output_base'])
    count(phase['epoch_start_ns'],maximum=2**63-1)
    reservation = phase['native_siwc_catalog_content_source_reservation']
    source.require(reservation == guard.projection(entry,until,True,reservation['resident']))
    _resident(reservation['resident'])
    _worker(phase['worker'],run.name); _cleanup(phase['cleanup']); _command(phase['command'],context)
    source.require(outer['id'] == phase['id'] and outer['profile'] == phase['profile'] and outer['targets'] == phase['targets']
        and outer['source_commit'] == phase['source_commit'] and outer['graph_sha256'] == phase['graph_sha256']
        and type(outer['exit']) is int and outer['exit'] == 0 and type(outer['workload_exit']) is int and outer['workload_exit'] == 0
        and outer['controller_failure'] is None and outer['descendants_empty'] is True
        and outer['source_dirty'] == 'false' and outer['verb'] == 'test' and outer['manager'] == 'system'
        and outer['cache_reuse_requested'] is True and type(outer['cache_policy']) is int and outer['cache_policy'] == 2
        and outer['cache_key'] == phase['cache_key'] and outer['output_base'] == phase['output_base']
        and outer['command'] == phase['command'] and outer['limits'] == phase['limits']
        and outer['cleanup'] == phase['cleanup'] and outer['test_evidence'] == phase['test_evidence']
        and outer['epoch_start_ns'] == phase['epoch_start_ns'])
    # These are the final outer's actual flat SOURCE fields. The six-field
    # worker is checkpoint authority; the outer does not emit a worker object.
    properties = outer['observed_properties']
    source.require(type(properties) is dict and outer['unit'] == phase['worker']['unit']
        and properties['MainPID'] == str(phase['worker']['pid'])
        and properties['ControlGroup'] == phase['worker']['cgroup'][len('/sys/fs/cgroup'):])
    history = outer['startup_history']
    source.require(type(history) is list and 1 <= len(history) <= 128)
    for sample in history:
        closed(sample, ('ActiveState','SubState','Result','Job','MainPID','ExecMainPID','ControlGroup'))
        source.require(all(item is None or type(item) is str and len(item) <= 4096 for item in sample.values()))
    last = history[-1]
    source.require(last['MainPID'] == last['ExecMainPID'] == properties['MainPID']
        and last['ControlGroup'] == properties['ControlGroup']
        and last['ActiveState'] == properties['ActiveState'] == 'active'
        and last['Result'] == properties['Result'])
    # This device/inode observation has no equivalent in worker6. Validate its
    # closed historical shape, never pretend it identifies a current cgroup.
    original_group = closed(outer['original_cgroup_identity'], ('device','inode'))
    count(original_group['device'],minimum=0,maximum=2**64-1)
    count(original_group['inode'],maximum=2**64-1)
    family.binding.protocol.native.phase2_effective_runtime(properties['RuntimeMaxUSec'],guard.ACTION_SECONDS)
    _reservation_pair(reservation,outer['native_siwc_catalog_content_source_reservation'],entry,until)
    source.require(outer['source_phase_receipt'] == {'path':'source-phase-receipt.json',**row['source_phase_receipt']})
    source.require(outer['native_siwc_content_dependency_disposition'] == {
        'kind':'omux-native-siwc-content-dependency-disposition-v1',
        'state':'dependencies-after-owned-source-and-delivery-success',
        'checkout':phase['dependency_lease']['checkout'],'key':phase['cache_key'],
        'source_qualified_by_disposition':False,'delivery_qualified_by_disposition':False,'native_runtime_qualified':False})
    evidence_ref = closed(phase['test_evidence'],('state','manifest','sha256','bytes','files'))
    source.require(evidence_ref['state'] == 'preserved' and evidence_ref['manifest'] == 'test-evidence.json')
    family.protocol.pin(evidence_ref['sha256']); count(evidence_ref['bytes'],maximum=64*1024*1024)
    count(evidence_ref['files'],minimum=4,maximum=64)
    index_path = run/'test-evidence.json'
    inputs.role_modes[str(index_path)] = (0o600,0o444,0o555)
    evidence = family.decode(inputs.read(index_path,evidence_ref['sha256'],source.DEADLINE,16*1024*1024))
    source.require(evidence['schema'] == 1 and evidence['bazel_exit'] == 0 and evidence['epoch_start_ns'] == phase['epoch_start_ns']
        and evidence['targets'] == phase['targets'] and type(evidence['results']) is list
        and [result['target'] for result in evidence['results']] == phase['targets'])
    configurations = {result['configuration'] for result in evidence['results']}
    source.require(len(configurations) == 1)
    configuration = configurations.pop()
    source.require(type(configuration) is str and re.fullmatch(r'[A-Za-z0-9_.-]+',configuration) is not None)
    required = {str(run/'receipt.json'),str(phase_path),str(publication_path),str(index_path),row['root']+'/source-receipt.json'}
    for result in evidence['results']:
        source.require(result['state'] == 'observed')
        for name in ('test.log','test.xml'):
            rows = [member for member in result['files'] if member['source'] == name]
            source.require(len(rows) == 1 and rows[0]['state'] == 'copied')
            member = rows[0]; family.protocol.pin(member['sha256'])
            source.require(type(member['file']) is str and re.fullmatch(r'[0-9a-f]{64}[.]evidence',member['file']) is not None)
            path = str(run/'test-evidence'/member['file'])
            source.require(path not in required); required.add(path)
            inputs.role_modes[path] = (0o600,0o444,0o555)
            raw = inputs.read(path,member['sha256'],source.DEADLINE,64*1024*1024)
            count(member['bytes'],maximum=64*1024*1024); source.require(len(raw) == member['bytes'])
            if name == 'test.xml': family.material.declared_xml_success(raw)
    source.require(len(required) == 9)
    publication_raw = inputs.read(publication_path,row['transport_receipt']['sha256'],source.DEADLINE,source.MAX_METADATA)
    source.require(len(publication_raw) == row['transport_receipt']['bytes'])
    publication = family.decode(publication_raw)
    _publication(publication,phase,row,evidence_ref['sha256'],configuration)
    source.require(outer['native_siwc_content_publication'] == {'kind':PUBLICATION_KIND,'root':row['root'],
        'transport_receipt':{'path':str(publication_path),**row['transport_receipt']},
        'source_receipt':{'sha256':row['receipt_sha256'],'bytes':row['receipt_bytes'],'inventory_sha256':row['inventory_sha256']},
        'context':context,'source_phase_receipt_sha256':row['source_phase_receipt']['sha256'],
        'test_evidence_sha256':evidence_ref['sha256'],'original_action_sdk_custody_inherited':False})
    delivery = closed(outer['native_siwc_content_delivery'],('unit','started','phase','command','worker','cleanup',
        'test_evidence','effective_timeout_seconds','timeout_sample_monotonic_ns','exit','workload_exit'))
    identity = str(uuid.uuid5(uuid.UUID(run.name),'omux-native-siwc-content-delivery-v1'))
    source.require(delivery['unit'] == 'omux-execution-'+identity+'.service' and delivery['started'] is True
        and delivery['phase'] == 'complete' and type(delivery['exit']) is int and delivery['exit'] == 0
        and type(delivery['workload_exit']) is int and delivery['workload_exit'] == 0)
    _worker(delivery['worker'],identity); _cleanup(delivery['cleanup'])
    sample = count(delivery['timeout_sample_monotonic_ns'],minimum=entry,maximum=until-30*10**9-1)
    seconds = count(delivery['effective_timeout_seconds'],maximum=840)
    source.require(seconds == min(840,(until-30*10**9-sample)//10**9))
    request = {'schema_version':1,'kind':'omux-native-siwc-content-delivery-request-v1','context':context,
        'clocks':phase['clocks'],'dependency_lease':phase['dependency_lease'],
        'source_phase_receipt_sha256':row['source_phase_receipt']['sha256'],
        'test_evidence_sha256':evidence_ref['sha256'],'configuration':configuration}
    request_raw = (json.dumps(request,sort_keys=True,separators=(',',':'))+'\n').encode()
    _command(delivery['command'],context,delivery=True,timeout=seconds,request_pin=source.sha(request_raw))
    delivery_evidence = closed(delivery['test_evidence'],('state','manifest','sha256','bytes','files'))
    source.require(delivery_evidence['state'] == 'preserved' and delivery_evidence['manifest'] == 'delivery-evidence/test-evidence.json')
    family.protocol.pin(delivery_evidence['sha256']); count(delivery_evidence['bytes'],maximum=64*1024*1024)
    count(delivery_evidence['files'],minimum=2,maximum=64)
    inputs.publication = publication
    inputs.check_all(); source.tick()
    return outer, required


def validate_members(publication, report, files, hub, receipt_raw):
    """Join every transported logical member to this action's independently produced content."""
    expected = {'source/'+name:(mode,raw) for name,(mode,raw) in files.items()}
    expected.update({'hub/source/'+name:('100644',raw) for name,raw in hub.items()})
    expected['source-receipt.json'] = ('100644',receipt_raw)
    current = publication['publication']
    source.require(len(files) == 8557 and 1 <= len(hub) <= 16 and set(current['members']) == set(expected)
        and current['source_bytes'] == report['source_bytes'] == sum(len(raw) for unused,raw in files.values()))
    total = 0
    for path,(mode,raw) in expected.items():
        source.tick(); member = current['members'][path]
        closed(member, ('mode','sha256','bytes','physical_mode','literal') if mode == '120000' else ('mode','sha256','bytes','physical_mode'))
        source.require(member['mode'] == mode and member['sha256'] == source.sha(raw)
            and type(member['bytes']) is int and member['bytes'] == len(raw))
        total += len(raw); source.require(total <= 512*1024*1024+source.MAX_METADATA)
        if mode == '120000':
            source.require(member['physical_mode'] == 0o777 and member['literal'] == raw.decode('utf-8'))
        else:
            source.require(type(member['physical_mode']) is int and member['physical_mode'] in
                ((0o444,0o555) if path == 'source-receipt.json' else (0o555,)))
    source.require(source.sha(receipt_raw) == publication['original_action']['source_receipt_sha256']
        and len(receipt_raw) == publication['original_action']['source_receipt_bytes']
        and report['inventory_sha256'] == publication['original_action']['inventory_sha256']
        and report['producer_context'] == {'mode':publication['context']['MODE'],
            'epoch':publication['context']['EPOCH'],'source_commit':publication['context']['SOURCE_COMMIT'],
            'graph_sha256':publication['context']['GRAPH_SHA256'],
            'entry_monotonic_ns':int(publication['context']['ENTRY_NS']),
            'deadline_monotonic_ns':int(publication['context']['DEADLINE_NS'])})
    source.tick()
