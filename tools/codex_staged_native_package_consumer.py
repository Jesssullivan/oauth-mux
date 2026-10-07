"""Read-only staged package consumer; never admits or dispatches native work."""
import hashlib
import os
from pathlib import Path
import re
import stat
import codex_native_staged_compilation as staged
import codex_fresh_native_runtime as fresh

KIND = 'omux-staged-native-package-selection-v1'
EXTRA_ROLES = frozenset(('library_run', 'library_artifacts', 'compile_artifacts',
    'qualification_artifacts', 'schema_artifacts'))
ROLES = fresh.ROLES | EXTRA_ROLES
RUNS = ('library_run', 'compile', 'qualification_run', 'schema_run')
ARTIFACTS = ('library_artifacts', 'compile_artifacts', 'qualification_artifacts', 'schema_artifacts')
FACTS = frozenset(('kind','key','provenance_sha256','bindings','source_commit','workspace',
    'output_base','stage','max_stages','mode','previous_dispatches','stage_history','core_codegen',
    'selector_sha256','chain_sha256','custody','artifacts_sha256',
    'verified_before_launch','verified_after_cleanup'))
VARIABLE_FACTS = frozenset(('stage','mode','stage_history','artifacts_sha256'))
LIBRARY_LIMIT = 256 * 1024 * 1024
SMALL_LIMIT = 8 * 1024 * 1024


def selected(value):
    return value.get('kind') == KIND


def roles(value):
    if selected(value):
        return ROLES
    fresh.require(value.get('kind') == fresh.SELECTION_KIND,
        'package selection kind must be explicitly qualified')
    return fresh.ROLES


def validate_producer_graph(paths):
    fresh.require(isinstance(paths,list) and 0 < len(paths) <= 4096
        and len(set(paths)) == len(paths)
        and {'tools/codex_fresh_native_runtime.py','tools/codex_staged_native_package_consumer.py',
            'tools/codex_native_staged_compilation.py'} <= set(paths),
        'staged package producer must bind its actual reader and producer ABI in the selected graph')


def validate_paths(value):
    fresh.require(selected(value) and set(value['files']) == ROLES,
        'staged package exact fourteen declared roles required')
    # Preserve the existing source/export/CLI/config/protocol path predicates.
    ordinary = dict(value, kind=fresh.SELECTION_KIND,
        files={name:pin for name,pin in value['files'].items() if name in fresh.ROLES})
    fresh.validate_selection_paths(ordinary)
    for role in EXTRA_ROLES:
        path = fresh.canonical_path(value['files'][role]['path'])
        relative = path.relative_to(fresh.STATE)
        leaf = 'receipt.json' if role == 'library_run' else staged.ARTIFACTS
        fresh.require(len(relative.parts) == 2 and staged.UUID.fullmatch(relative.parts[0])
            and relative.parts[1] == leaf, 'staged public receipt/artifact envelope path differs')
    extra = value['staged_artifact_files']
    fresh.require(isinstance(extra,dict) and len(extra) == 7,
        'staged package requires exactly three libraries and four qualification evidence files')
    for path,pin in extra.items():
        fresh.require(path == pin['path'], 'staged artifact map key differs')
        fresh.canonical_path(path)
        fresh.require(set(pin) == {'path','sha256','bytes','mode'}
            and isinstance(pin['sha256'],str) and fresh.HASH.fullmatch(pin['sha256'])
            and type(pin['bytes']) is int and 0 < pin['bytes'] <= LIBRARY_LIMIT
            and type(pin['mode']) is int and 0 <= pin['mode'] <= 0o777
            and not pin['mode'] & 0o133, 'staged actual file pin differs')
        relative = Path(path).relative_to(fresh.STATE)
        library = (len(relative.parts) == 10
            and re.fullmatch(r'cache-v2-[0-9a-f]{64}',relative.parts[0])
            and relative.parts[1:5] == ('output-base','execroot','_main','bazel-out')
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[5])
            and relative.parts[6:8] == ('bin','codex-rs')
            and relative.parts[8] in ('config','login','app-server-protocol')
            and re.fullmatch(r'libcodex_(config|login|app_server_protocol)-[0-9]{1,20}\.rlib',relative.parts[9]))
        evidence = (staged.UUID.fullmatch(relative.parts[0]) and
            ((len(relative.parts) == 2 and relative.parts[1] == 'test-evidence.json') or
             (len(relative.parts) == 3 and relative.parts[1] == 'test-evidence'
              and re.fullmatch(r'[A-Za-z0-9_.-]+',relative.parts[2]))))
        fresh.require(library or evidence, 'staged extra input leaves exact library/log output scope')


def current_custody(facts):
    """Compare current canonical opened files to A's exact persistent identities."""
    staged.verify_binding_facts(facts)
    root = fresh.canonical_path(facts['output_base']).parent
    paths = {'chain':staged.CHAIN, 'root':root, 'output_base':root/'output-base',
        'lock':root/staged.LOCK, 'native_input':root/'native-input',
        'source':root/'native-input/source'}
    held = []
    chain_witness = None
    def stable(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        for name,path in paths.items():
            fresh.tick()
            if name in ('chain','lock'):
                parent = fresh.trusted(path.parent)
                try:
                    fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                finally:
                    os.close(parent)
            else:
                fd = fresh.trusted(path)
            held.append((name,path,fd))
            info = os.fstat(fd)
            expected = facts['custody'][name]
            row = {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
            fresh.require(row == expected and (stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1 if name in ('chain','lock') else stat.S_ISDIR(info.st_mode)),
                'staged current canonical custody differs from the actual A receipt')
            if name == 'chain':
                fresh.require(0 < info.st_size <= 8192, 'staged fixed chain metadata size differs')
                raw = os.pread(fd,8193,0)
                chain = {'schema_version':1,'kind':staged.KIND,'key':facts['key'],
                    'provenance_sha256':facts['provenance_sha256'],
                    'source_commit':facts['source_commit'],'selector_sha256':facts['selector_sha256']}
                fresh.require(len(raw) == info.st_size and raw == staged.canonical(chain)+b'\n'
                    and fresh.digest(raw) == facts['chain_sha256']
                    and stable(info) == stable(os.fstat(fd)),
                    'staged held chain bytes/full witness differ from the actual fixed A anchor')
                chain_witness = stable(info)
        # Reopen every canonical path after obtaining all witnesses.
        for name,path,fd in held:
            if name in ('chain','lock'):
                parent = fresh.trusted(path.parent)
                try:
                    named = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                finally:
                    os.close(parent)
            else:
                current = fresh.trusted(path)
                try:
                    named = os.fstat(current)
                finally:
                    os.close(current)
            info = os.fstat(fd)
            fresh.require((named.st_dev,named.st_ino,named.st_uid,named.st_gid,
                stat.S_IMODE(named.st_mode)) == (info.st_dev,info.st_ino,info.st_uid,
                info.st_gid,stat.S_IMODE(info.st_mode)), 'staged current custody changed during qualification')
            if name == 'chain':
                fresh.require(stable(named) == stable(info) == chain_witness,
                    'staged fixed chain held/named full witness changed')
    finally:
        for _,_,fd in reversed(held):
            os.close(fd)


def validate_receipts(selection, values, source, exported, *, check_current=True):
    """Runs before any library, CLI, test log or generated schema is read."""
    fresh.require(selected(selection), 'staged receipt reader needs exact staged selection')
    for role in ('source','export',*RUNS):
        pin = selection['files'][role]
        fresh.require(type(pin['bytes']) is int and len(values[role]) == pin['bytes']
            and fresh.digest(values[role]) == pin['sha256'], 'staged receipt/input byte pin differs')
    receipts, history, common, identifiers = {}, [], None, set()
    for stage,role in enumerate(RUNS,1):
        receipt = fresh.parse(values[role])
        facts = receipt['native_staged_compilation']
        fresh.require(isinstance(facts,dict) and set(facts) == FACTS,
            'staged completion closed facts schema differs')
        bindings = staged.verify_binding_facts(facts)
        expected = {key:value for key,value in facts.items() if key not in VARIABLE_FACTS}
        if common is None:
            common = expected
        fresh.require(staged.canonical(expected) == staged.canonical(common)
            and facts['mode'] == staged.STAGES[stage][0]
            and facts['core_codegen'] == staged.fixed_codegen()
            and staged.canonical(facts['previous_dispatches']) == staged.canonical(staged.consumed_dispatches())
            and staged.canonical(facts['stage_history']) == staged.canonical(history),
            'staged stages must preserve the same actual A bindings and complete history')
        fresh.require(bindings['source_inventory_sha256'] == source['inventory_sha256']
            and bindings['export_inventory_sha256'] == exported['inventory_sha256']
            and bindings['source_graph'] == source['graph_files']
            and bindings['source_root'] == selection['source_root']
            and bindings['export_root'] == selection['export_root']
            and bindings['patch_sha256'] == selection['patch_sha256'],
            'staged source/SDK/controller input join differs')
        staged.verify_success(receipt,facts,bindings['controller_graph'],
            selection['files']['source']['sha256'],selection['files']['export']['sha256'],stage)
        fresh.require(receipt['id'] not in identifiers
            and selection['files'][role]['path'] == str(fresh.STATE/receipt['id']/'receipt.json')
            and selection['files'][ARTIFACTS[stage-1]]['path'] == str(fresh.STATE/receipt['id']/staged.ARTIFACTS)
            and selection['files'][ARTIFACTS[stage-1]]['sha256'] == facts['artifacts_sha256'],
            'staged receipts require four distinct positively bound actual epochs and envelopes')
        identifiers.add(receipt['id'])
        history.append({'stage':stage,'id':receipt['id'],
            'sha256':selection['files'][role]['sha256'],
            'artifacts_sha256':facts['artifacts_sha256'],'key':facts['key']})
        receipts[role] = receipt
    if check_current:
        current_custody(receipts['library_run']['native_staged_compilation'])
    facts = receipts['library_run']['native_staged_compilation']
    return receipts,(facts['key'],facts['provenance_sha256'],facts['workspace'],facts['output_base']),True


def envelopes(selection, values, receipts):
    result = []
    for stage,role in enumerate(ARTIFACTS,1):
        document = fresh.parse(values[role])
        receipt = receipts[RUNS[stage-1]]
        facts = receipt['native_staged_compilation']
        fresh.require(isinstance(document,dict) and set(document) == {'schema_version','kind',
            'stage','id','key','controller_graph_sha256','source_receipt_sha256',
            'export_receipt_sha256','artifacts'} and type(document['schema_version']) is int
            and document['schema_version'] == 1 and type(document['stage']) is int
            and document['stage'] == stage and document['kind'] == staged.KIND
            and document['id'] == receipt['id'] and document['key'] == facts['key']
            and document['controller_graph_sha256'] == receipt['graph_sha256']
            and document['source_receipt_sha256'] == selection['files']['source']['sha256']
            and document['export_receipt_sha256'] == selection['files']['export']['sha256']
            and fresh.digest(values[role]) == facts['artifacts_sha256'],
            'staged actual envelope does not match its post-cleanup receipt')
        result.append(document['artifacts'])
    return result


def without_mode(pin):
    return {key:value for key,value in pin.items() if key != 'mode'}


def expected_extra(selection, artifacts, receipts):
    libraries, compile_artifacts, qualified, schema = artifacts
    fresh.require(set(libraries) == {'libraries'} and set(libraries['libraries']) == set(staged.LIBRARIES)
        and sum(pin['bytes'] for pin in libraries['libraries'].values()) <= 768*1024*1024,
        'staged exact three initial library outputs required')
    extra = {}
    configuration = None
    for label,(package,crate) in zip(staged.LIBRARIES,(
            ('config','codex_config'),('login','codex_login'),('app-server-protocol','codex_app_server_protocol'))):
        pin = libraries['libraries'][label]
        relative = fresh.canonical_path(pin['path']).relative_to(
            Path(receipts['library_run']['native_staged_compilation']['output_base'])/'execroot/_main/bazel-out')
        fresh.require(len(relative.parts) == 5 and relative.parts[1:4] == ('bin','codex-rs',package)
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[0])
            and re.fullmatch('lib'+crate+r'-[0-9]{1,20}\.rlib',relative.parts[4]),
            'staged recorded library path differs from its actual requested label')
        configuration = configuration or relative.parts[0]
        fresh.require(relative.parts[0] == configuration, 'staged library configurations differ')
        extra[pin['path']] = pin
    fresh.require(set(compile_artifacts) == {'cli','cli_context'}
        and set(qualified) == {'cli','cli_context','qualification'}, 'staged B/C actual CLI envelope shape differs')
    for role,artifact in (('compile',compile_artifacts),('qualification_run',qualified)):
        context = staged.cli_context(receipts[role])
        pin = selection['files']['codex']
        relative = fresh.canonical_path(pin['path']).relative_to(
            Path(context['output_base'])/'execroot/_main/bazel-out')
        fresh.require(len(relative.parts) == 5 and relative.parts[1:] == ('bin','codex-rs','cli','codex')
            and re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[0]),
            'staged B/C exact declared explicit CLI output required')
        expected_cli = {'kind':'actual-explicit-cli-target-v1','target':fresh.CLI,
            'configuration':relative.parts[0],**pin}
        fresh.require(artifact['cli_context'] == context
            and artifact['cli'] == expected_cli,
            'staged B/C CLI envelope does not join the exact successful invocation')
    fresh.require(compile_artifacts['cli'] == qualified['cli'],
        'staged C must post-cleanup rehash the actual B CLI bytes')
    evidence = qualified['qualification']
    fresh.require(set(evidence) == {'manifest','group','xml','logs'}
        and set(evidence['logs']) == set(fresh.QUALIFICATION_GATES),
        'staged C needs full manifest and all three actual qualification logs')
    root = fresh.STATE/receipts['qualification_run']['id']
    fresh.require(evidence['manifest']['path'] == str(root/'test-evidence.json')
        and evidence['manifest']['sha256'] == receipts['qualification_run']['test_evidence']['sha256']
        and without_mode(evidence['group']) == selection['files']['qualification']
        and without_mode(evidence['xml']) == selection['files']['qualification_xml'],
        'staged C copied evidence output paths/bytes differ')
    for pin in (evidence['manifest'],*evidence['logs'].values()):
        extra[pin['path']] = pin
    fresh.require(extra == selection['staged_artifact_files'] and len(extra) == 7,
        'staged inputs must declare exactly all recorded A libraries and C actual logs')
    return extra


def read_extra(selection, artifacts, receipts, alias_path=None):
    """Stream large rlibs; retain only bounded explicitly declared C evidence."""
    extra = expected_extra(selection,artifacts,receipts)
    library_paths = {pin['path'] for pin in artifacts[0]['libraries'].values()}
    values = {}
    for name,pin in extra.items():
        path = fresh.canonical_path(name)
        if alias_path is not None:
            fresh.require(str(alias_path('staged/'+name,pin)) == name,
                'staged actual output is not an independently declared action input')
        library = name in library_paths
        actual = staged.artifact_file(path, fresh.DEADLINE,
            LIBRARY_LIMIT if library else SMALL_LIMIT,magic=b'!<arch>\n' if library else None)
        fresh.require(actual == pin, 'staged current output differs from actual post-cleanup envelope')
        if not library:
            values[name] = fresh.read_selected(path,without_mode(pin),SMALL_LIMIT)
    current_custody(receipts['library_run']['native_staged_compilation'])
    return values


def load_inputs(selection, read, alias_path=None):
    """Receipt qualification precedes reads of every staged compiled output."""
    validate_paths(selection)
    values = {role:read(role,selection['files'][role],fresh.MAX_METADATA)
        for role in ('source','export',*RUNS)}
    source,exported = fresh.parse(values['source']),fresh.parse(values['export'])
    receipts,_,_ = validate_receipts(selection,values,source,exported)
    for role in sorted(ROLES-set(values)):
        values[role] = read(role,selection['files'][role],
            fresh.runtime.MAX_ORIGINAL_BYTES if role == 'codex' else fresh.MAX_METADATA)
    artifacts = envelopes(selection,values,receipts)
    extra_values = read_extra(selection,artifacts,receipts,alias_path)
    validate_schema_inventory(selection,receipts)
    total,protocol = 0,{}
    for name,pin in selection['protocol_schema_files'].items():
        raw = read('protocol/'+name,pin,SMALL_LIMIT)
        total += len(raw)
        fresh.require(total+len(values['config_schema']) <= 64*1024*1024
            and isinstance(fresh.parse(raw),dict), 'staged D generated JSON aggregate differs')
        protocol[name] = raw
    return values,protocol,extra_values


def validate_schema_inventory(selection,receipts):
    """Bound physical tree metadata before reading selected JSON byte inputs."""
    output = Path(receipts['schema_run']['native_staged_compilation']['output_base'])
    prefix = output/'execroot/_main/bazel-out'
    relative = fresh.canonical_path(selection['files']['config_schema']['path']).relative_to(prefix)
    fresh.require(len(relative.parts) == 5 and relative.parts[1:] == ('bin','bazel','schema','native-config.schema.json')
        and re.fullmatch(r'[A-Za-z0-9_.-]+-opt',relative.parts[0]), 'staged exact D configuration path required')
    roots = selection['protocol_schema_roots']
    fresh.require(set(roots) == {'stable','experimental'}, 'staged exact schema modes required')
    observed,budget = set(),{'directories':0,'files':0,'bytes':selection['files']['config_schema']['bytes']}
    def walk(path,mode,prefix_name='',depth=0):
        fresh.tick()
        fd = fresh.trusted(path)
        try:
            before = os.fstat(fd)
            budget['directories'] += int(depth > 0)  # Producer counts descendants, excluding the two roots.
            fresh.require(depth <= 16 and budget['directories'] <= 4096,
                'staged schema physical directory/depth bound')
            names = sorted(os.listdir(fd))
            fresh.require(len(names) <= 4096, 'staged schema directory member bound')
            for name in names:
                fresh.tick()
                fresh.require(re.fullmatch(r'[A-Za-z0-9_.-]{1,256}',name)
                    and name not in ('.','..'), 'staged physical schema name refused')
                relative_name = prefix_name+name
                fresh.require(len(relative_name) <= 2048 and len(Path(relative_name).parts) <= 16,
                    'staged schema relative path bound')
                info = os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(path/name,mode,relative_name+'/',depth+1)
                else:
                    fresh.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                        and not info.st_mode & 0o7022 and not info.st_mode & 0o111
                        and name.endswith('.json') and 0 < info.st_size <= SMALL_LIMIT,
                        'staged physical schema regular JSON custody differs')
                    budget['files'] += 1
                    budget['bytes'] += info.st_size
                    fresh.require(budget['files'] <= 4096 and budget['bytes'] <= 64*1024*1024,
                        'staged physical schema count/aggregate bound')
                    observed.add(mode+'/json/'+relative_name)
            named = fresh.trusted(path)
            try:
                fresh.require((os.fstat(named).st_dev,os.fstat(named).st_ino)
                    == (before.st_dev,before.st_ino) == (os.fstat(fd).st_dev,os.fstat(fd).st_ino),
                    'staged named physical schema directory changed')
            finally:
                os.close(named)
        finally:
            os.close(fd)
    for mode in ('stable','experimental'):
        expected = prefix/relative.parts[0]/'bin/bazel/schema'/('public-schema-bundle.'+mode)/'json'
        fresh.require(roots[mode] == str(expected), 'staged D schema root leaves its actual output base')
        walk(expected,mode)
    fresh.require(observed == set(selection['protocol_schema_files']),
        'staged complete physical schema membership differs')


def validate_artifacts(selection, values, protocol_values, extra_values, receipts):
    artifacts = envelopes(selection,values,receipts)
    expected_extra(selection,artifacts,receipts)
    # Rehash actual declared rlibs here as well: callers of the shared chain
    # validator cannot bypass their physical output checks by supplying logs.
    actual_extra = read_extra(selection,artifacts,receipts)
    fresh.require(actual_extra == extra_values, 'staged actual copied logs changed before validation')
    qualified,schema = artifacts[2],artifacts[3]
    group = fresh.parse(values['qualification'])
    fresh.require(qualified['cli'] == group['cli_artifact']
        and qualified['cli_context'] == group['cli_context'], 'staged C actual14 CLI group differs')
    evidence = qualified['qualification']
    manifest = fresh.parse(extra_values[evidence['manifest']['path']])
    fresh.require(set(extra_values) == {evidence['manifest']['path'],
        *(pin['path'] for pin in evidence['logs'].values())}
        and manifest['targets'] == list(staged.STAGES[3][2])
        and len(manifest['results']) == 4, 'staged C full copied evidence manifest differs')
    for target,names in fresh.QUALIFICATION_GATES.items():
        rows = [row for row in manifest['results'] if row['target'] == target]
        fresh.require(len(rows) == 1, 'staged C actual copied target log absent')
        entries = [row for row in rows[0]['files'] if row['state'] == 'copied'
            and (row['source'] == 'test.log' or row['source'].endswith('/test.log'))]
        fresh.require(len(entries) == 1, 'staged C ambiguous actual log')
        pin = evidence['logs'][target]
        raw = extra_values[pin['path']]
        fresh.require(pin['path'] == str(fresh.STATE/receipts['qualification_run']['id']/'test-evidence'/entries[0]['file'])
            and pin['sha256'] == entries[0]['sha256'] == group['targets'][target]['log_sha256']
            and fresh.digest(raw) == pin['sha256'] and len(raw) == pin['bytes']
            and staged.native.qualification_log(raw,target) == sorted(names),
            'staged C fourteen actual accepted test results differ')
    cli_rows = [row for row in manifest['results'] if row['target'] == fresh.CLI]
    fresh.require(len(cli_rows) == 1 and cli_rows[0]['state'] == 'missing-test-directory'
        and cli_rows[0]['files'] == [], 'staged explicit CLI build must not manufacture a test result')
    fresh.require(set(schema) == {'config_schema','protocol_schema_files','protocol_schema_roots'}
        and without_mode(schema['config_schema']) == selection['files']['config_schema']
        and schema['protocol_schema_roots'] == selection['protocol_schema_roots'],
        'staged D actual complete config/schema roots differ')
    transformed = {mode+'/json/'+rest:pin for name,pin in schema['protocol_schema_files'].items()
        for mode,rest in [name.split('/',1)]}
    fresh.require({name:without_mode(pin) for name,pin in transformed.items()}
        == selection['protocol_schema_files']
        and len(values['config_schema'])+sum(len(raw) for raw in protocol_values.values()) <= 64*1024*1024,
        'staged D complete selected schema inventory/aggregate differs')
    for pin in (schema['config_schema'],*transformed.values(),
            evidence['group'],evidence['xml']):
        fresh.require(staged.artifact_file(Path(pin['path']),fresh.DEADLINE,SMALL_LIMIT) == pin,
            'staged D/C actual output mode/custody differs')
    current_custody(receipts['library_run']['native_staged_compilation'])
    validate_schema_inventory(selection,receipts)
    return {'kind':staged.KIND,'library_invocation_id':receipts['library_run']['id'],
        'stages':{role:receipts[role]['native_staged_compilation'] for role in RUNS},
        'artifact_envelopes':{role:selection['files'][role] for role in ARTIFACTS},
        'staged_artifact_files':selection['staged_artifact_files']}
