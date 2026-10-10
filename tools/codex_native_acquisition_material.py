"""Exact ninth material family for package validation; no native dispatch or selectors."""
import os
from pathlib import Path
import re
import stat
import time
import hashlib
import json
from decimal import Decimal
import codex_native_acquisition_metadata as producer
import codex_native_acquisition_sdk_export as export
import codex_native_source_acquisition_source as acquisition
import codex_retained_sdk_export as sdk

PACKAGE_KIND = "omux-native-source-acquisition-native-package-selection-v1"
INPUT_KIND = "omux-native-source-acquisition-native-selection-v1"
SDK_EXTRA = frozenset(("binding_receipt_sha256", "sdk_export_qualified",
                       "schema_producer_qualified", "live_handoff_proven"))
METADATA_EXTRA = frozenset(("binding_receipt_sha256", "schema_producer_qualified", "live_handoff_proven"))
SOURCE_TARGET = "//tools:codex_native_source_acquisition_source_producer"
SDK_TARGET = "//tools:codex_native_acquisition_sdk_export_producer"
METADATA_TARGET = "//tools:codex_native_acquisition_metadata_producer"
SDK_SCOPE = re.compile(r"(?:/home/jess/\.local/state/omux-execution-20261005|"
    r"/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/output-base/execroot/_main/bazel-out/"
    r"[A-Za-z0-9_-]+/testlogs/tools/codex_native_acquisition_sdk_export_producer/"
    r"test.outputs/native-acquisition-sdk-export\Z")

# This family describes one actual six-target dispatch, never three aliased runs.
ROLES = frozenset(('source','sdk','sdk_metadata','plan','query','compiler_selection',
    'compiler_ledger','compiler_ledger_snapshot','compiler','compiler_outer',
    'codex','config_schema'))

def _member(row):
    require(type(row) is dict and set(row)=={'path','sha256','bytes'}
        and type(row['path']) is str and Path(row['path']).is_absolute()
        and '..' not in Path(row['path']).parts
        and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None
        and type(row['bytes']) is int and 0<row['bytes']<=1024*1024*1024)

def validate_paths(selection):
    require(type(selection) is dict and set(selection)=={'schema_version','kind','purpose',
        'material','compilation','files','protocol_schema_files','native_acquisition_artifact_files',
        'authority_receipts'}
        and type(selection['schema_version']) is int and selection['schema_version']==1
        and selection['kind']==PACKAGE_KIND and selection['purpose']=='evaluation-only')
    validate_selection(selection['material'])
    require(type(selection['compilation']) is dict
        and set(selection['compilation'])=={'selection','result'})
    selected=selection['compilation']['selection']; result=selection['compilation']['result']
    require(type(selected) is dict and set(selected)=={'path','sha256'}
        and type(result) is dict and set(result)=={'path','sha256','producer'})
    for row in (selected,result):
        require(type(row['path']) is str and Path(row['path']).is_absolute()
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None)
    require(type(selection['authority_receipts']) is dict
        and set(selection['authority_receipts'])=={'source','sdk','plan','query','compiler'})
    for name,group in selection['authority_receipts'].items():
        require(type(group) is dict and set(group)=={'outer','evidence','members'}
            and type(group['members']) is dict and len(group['members'])==(6 if name=='source' else 2))
        _member(group['outer']); _member(group['evidence'])
        for key,row in group['members'].items():
            require(type(key) is str and re.fullmatch('[0-9a-f]{64}\\.evidence',key) is not None)
            _member(row)
    require(type(selection['files']) is dict and set(selection['files'])==ROLES)
    for row in selection['files'].values(): _member(row)
    schemas=selection['protocol_schema_files']; evidence=selection['native_acquisition_artifact_files']
    require(type(schemas) is dict and 2<=len(schemas)<=4096
        and type(evidence) is dict and len(evidence)==6)
    for name,row in schemas.items():
        require(type(name) is str and re.fullmatch('(stable|experimental)/[A-Za-z0-9_./-]+\\.json',name)
            is not None and '..' not in Path(name).parts)
        _member(row)
    for name,row in evidence.items():
        require(type(name) is str and re.fullmatch('[A-Za-z0-9_-]+/(test\\.xml|test\\.log)',name)
            is not None)
        _member(row)
    require(sum(row['bytes'] for row in [*selection['files'].values(),*schemas.values(),
        *evidence.values()])<=1536*1024*1024)

def load_inputs(selection,read,selected_alias=None):
    validate_paths(selection)
    values={name:read(name,row,row['bytes']) for name,row in selection['files'].items()}
    schemas={name:read('schema/'+name,row,row['bytes'])
        for name,row in selection['protocol_schema_files'].items()}
    evidence={name:read('evidence/'+name,row,row['bytes'])
        for name,row in selection['native_acquisition_artifact_files'].items()}
    for action,group in selection['authority_receipts'].items():
        evidence['authority/'+action+'/outer']=read('authority/'+action+'/outer',group['outer'],group['outer']['bytes'])
        evidence['authority/'+action+'/evidence']=read('authority/'+action+'/evidence',group['evidence'],group['evidence']['bytes'])
        for name,row in group['members'].items():
            evidence['authority/'+action+'/'+name]=read('authority/'+action+'/'+name,row,row['bytes'])
    return values,schemas,evidence

def validate_chain(selection,values,protocol_values,staged_values,*,deadline):
    """Full readback qualifies evaluation bytes; it cannot qualify acquisition."""
    import codex_native_acquisition_compilation as compiler
    validate_paths(selection); tick(deadline)
    require(type(values) is dict and set(values)==ROLES
        and type(protocol_values) is dict and set(protocol_values)==set(selection['protocol_schema_files'])
        and type(staged_values) is dict)
    extra=dict(selection['native_acquisition_artifact_files'])
    for action,group in selection['authority_receipts'].items():
        extra['authority/'+action+'/outer']=group['outer']
        extra['authority/'+action+'/evidence']=group['evidence']
        extra.update({'authority/'+action+'/'+name:row for name,row in group['members'].items()})
    require(set(staged_values)==set(extra))
    def raw_join(rows,raws):
        for name,row in rows.items():
            raw=raws[name]
            require(type(raw) is bytes and len(raw)==row['bytes']
                and hashlib.sha256(raw).hexdigest()==row['sha256'])
    raw_join(selection['files'],values)
    raw_join(selection['protocol_schema_files'],protocol_values)
    raw_join(extra,staged_values)
    parsed={name:json.loads(values[name],object_pairs_hook=compiler.unique)
        for name in ROLES-{'codex'}}
    selected=selection['compilation']['selection']; result=selection['compilation']['result']
    document=compiler.selected_document(selected['path'],selected['sha256'],deadline)
    require(document==parsed['compiler_selection'] and document['material']==selection['material'])
    declared_controller(deadline)
    report=compiler.readback(document,result,deadline)
    producer_rows={'source':selection['material']['source']['producer'],
        'sdk':selection['material']['sdk']['producer'],'plan':document['plan']['producer'],
        'query':document['query']['producer'],'compiler':result['producer']}
    for action,row in producer_rows.items():
        group=selection['authority_receipts'][action]; prefix='authority/'+action+'/'
        require(group['outer']['path']==row['receipt'] and group['outer']['sha256']==row['sha256'])
        outer=json.loads(staged_values[prefix+'outer'],object_pairs_hook=compiler.unique)
        manifest=json.loads(staged_values[prefix+'evidence'],object_pairs_hook=compiler.unique)
        parent=Path(row['receipt']).parent
        require(group['evidence']['path']==str(parent/'test-evidence.json')
            and group['evidence']['sha256']==outer['test_evidence']['sha256'])
        entries=[entry for item in manifest['results'] for entry in item['files']
            if entry['source'] in ('test.log','test.xml')]
        require(len(entries)==len(group['members']) and {entry['file'] for entry in entries}==set(group['members']))
        for entry in entries:
            member=group['members'][entry['file']]
            require(entry['state']=='copied' and member=={'path':str(parent/'test-evidence'/entry['file']),
                'sha256':entry['sha256'],'bytes':entry['bytes']})
    joins={'compiler_selection':selected,'compiler':result,'compiler_outer':result['producer'],
        'compiler_ledger':document['ledger'],'plan':document['plan'],'query':document['query'],
        'compiler_ledger_snapshot':parsed['compiler_ledger']['goal_snapshot']}
    for name,row in joins.items():
        require(selection['files'][name]['path']==selected_role_path(name,row)
            and selection['files'][name]['sha256']==row['sha256'])
    for name in ('source','sdk'):
        row=selection['material'][name]
        require(selection['files'][name]['path']==str(Path(row['root'])/('source-receipt.json' if name=='source' else 'receipt.json'))
            and selection['files'][name]['sha256']==row['receipt_sha256'])
    sdk_root=Path(selection['material']['sdk']['root'])
    require(selection['files']['sdk_metadata']['path']==str(sdk_root.parent/
        'native-acquisition-metadata'/'metadata-receipt.json')
        and selection['files']['sdk_metadata']['sha256']==parsed['sdk']['metadata_receipt_sha256'])
    rows=parsed['compiler']['artifacts']
    expected={row['path']:row for row in rows}
    supplied=[selection['files']['codex'],selection['files']['config_schema'],
        *selection['protocol_schema_files'].values(),*selection['native_acquisition_artifact_files'].values()]
    require(len(supplied)==len(expected) and {row['path'] for row in supplied}==set(expected))
    for row in supplied:
        actual=expected[row['path']]
        require(row['sha256']==actual['sha256'] and row['bytes']==actual['bytes'])
    require(expected[selection['files']['codex']['path']]['role']=='native-cli'
        and expected[selection['files']['config_schema']['path']]['role']=='config-schema')
    for name,row in selection['protocol_schema_files'].items():
        require(expected[row['path']]['role']==name.split('/')[0]+'-schema')
    for name,row in selection['native_acquisition_artifact_files'].items():
        require(expected[row['path']]['role']==('test-xml' if name.endswith('.xml') else 'test-log'))
    # Rehash every caller-retained byte and repeat all real physical provenance.
    raw_join(selection['files'],values); raw_join(selection['protocol_schema_files'],protocol_values)
    raw_join(extra,staged_values)
    require(compiler.readback(document,result,deadline)==report)
    return {'material_family':'native-acquisition-evaluation-v1','compiler_qualified':True,
        'schema_qualified':True,'acquisitionContract':'unsupported',
        'runtime_qualified':False,'provider_identity_proved':False,'live_handoff_proven':False}


def require(value, reason=None):
    if value is not True:
        raise ValueError("native-acquisition-material-refused")

def tick(deadline):
    require(type(deadline) is float and time.monotonic()<deadline)

def selected_role_path(role,row):
    import codex_native_acquisition_compilation as compiler
    if role=='compiler_ledger_snapshot':
        require(row['path']==compiler.GOAL_SNAPSHOT_PREFIX+row['sha256']+'.json')
        return str(compiler.PUBLIC_ROOT/row['path'])
    return row.get('path',row.get('receipt'))

def declared_controller(deadline):
    """Resolve genuine declared query tools for producers with their own argv."""
    tick(deadline)
    runfiles=os.environ.get('TEST_SRCDIR',os.environ.get('RUNFILES_DIR'))
    require(type(runfiles) is str and Path(runfiles).is_absolute())
    root=Path(runfiles).resolve(strict=True)
    raw=(root/'_repo_mapping').read_bytes()
    require(0<len(raw)<=1024*1024)
    rows=[line.split(',') for line in raw.decode().splitlines()]
    producer.DEADLINE=producer.source.DEADLINE=deadline
    require(producer.declared_query_tools(root,rows) is True)


def validate_selection(document):
    import codex_protocol_history_native as protocol
    require(type(document) is dict and set(document)=={'schema_version','kind','source','sdk',
        'controller_source_commit','controller_graph_sha256'}
        and type(document['schema_version']) is int and document['schema_version']==1
        and document['kind']==INPUT_KIND and type(document['controller_source_commit']) is str
        and re.fullmatch(r'[0-9a-f]{40}',document['controller_source_commit']) is not None)
    protocol.pin(document['controller_graph_sha256'])
    for role in ('source','sdk'):
        row=document[role]
        require(type(row) is dict and set(row)=={'root','receipt_sha256','inventory_sha256','producer'})
        role_root(role,row['root'])
        protocol.pin(row['receipt_sha256']);protocol.pin(row['inventory_sha256'])
        protocol.producer_pin(row['producer'])
    require(document['source']['producer']['receipt']!=document['sdk']['producer']['receipt'])
    return document


def qualify_selection(document, deadline):
    """Reconstruct all ninth bytes and qualify actual SDK/evidence, under caller clock."""
    import codex_protocol_history_native as protocol
    validate_selection(document)
    require(type(deadline) is float and time.monotonic()<deadline)
    producer_success(document['source'],SOURCE_TARGET,'native-source-acquisition-source',deadline)
    producer_success(document['sdk'],SDK_TARGET,'native-acquisition-sdk-export',deadline)
    source_receipt,files,parent=load_source(Path(document['source']['root']),
        document['source']['receipt_sha256'],_patches(document,deadline),deadline)
    require(source_receipt['inventory_sha256']==document['source']['inventory_sha256'])
    report,exported=verify_sdk(Path(document['sdk']['root']),document['sdk']['receipt_sha256'],
        source_receipt,document,deadline,protocol.SDK_FIELDS,protocol.METADATA_FIELDS,protocol.read_json)
    return source_receipt,files,parent,report,exported


def _patches(document, deadline):
    # Receipt-derived values are only a candidate; load_source reconstructs them.
    import codex_protocol_history_native as protocol
    report=protocol.read_json(Path(document['source']['root'])/'source-receipt.json',
        document['source']['receipt_sha256'],deadline,8*1024*1024)
    require(type(report.get('patch_sha256')) is list and len(report['patch_sha256'])==9)
    return report['patch_sha256']


def role_root(role, root):
    require(type(root) is str and role in ("source", "sdk"))
    require(producer.binding.SOURCE_SCOPE.fullmatch(root) is not None if role == "source"
        else SDK_SCOPE.fullmatch(root) is not None)


def producer_policy(receipt, target):
    import guard_native_seed_plan_reserved as kernel
    if target == SOURCE_TARGET:
        import guard_resident_native_source_acquisition_source_reserved as admission
        profile, targets = admission.PROFILE, admission.ARGUMENTS[1:]
        value = receipt['resident_native_source_acquisition_source_reservation']
        expected = admission.projection(value['original_entry_monotonic_ns'],
            value['original_deadline_monotonic_ns'], True, value['resident'])
    else:
        import guard_native_acquisition_inputs_reserved as admission
        policies = {SDK_TARGET:admission.SDK, METADATA_TARGET:admission.METADATA,
            '//tools:codex_native_acquisition_binding_producer':admission.BINDING,
            '//tools:codex_native_acquisition_plan_producer':admission.PLAN,
            '//tools:codex_native_acquisition_query_producer':admission.QUERY,
            '//tools:codex_native_acquisition_compilation_producer':admission.COMPILE,
            '//tools:codex_native_acquisition_runtime_package':admission.PACKAGE,
            '//tools:codex_native_acquisition_bridge_material_producer':admission.BRIDGE}
        require(target in policies)
        profile = policies[target]
        targets = list(admission.COHORTS[profile])
        value = receipt['native_acquisition_inputs_reservation']
        expected = admission.projection(profile, value['original_entry_monotonic_ns'],
            value['original_deadline_monotonic_ns'], True, value['resident'])
    require(value == expected and receipt['profile'] == profile
        and receipt['cache_reuse_requested'] is False
        and receipt['cache_policy'] is None and receipt['cache_key'] is None)
    observed = receipt['observed_properties']
    require(all(observed.get(name) == setting for name, setting in {
        'MemoryMax':'4026531840','MemorySwapMax':'0','TasksMax':'480','PrivateNetwork':'yes',
        'KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill','RemainAfterExit':'yes'}.items()))
    token = observed.get('CPUQuotaPerSecUSec')
    match = re.fullmatch(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)', token) if type(token) is str else None
    require(match is not None and Decimal(match[1])*{'us':1,'ms':1000,'s':1000000}[match[2]] == 1900000)
    resident = value['resident']
    require(type(resident) is dict and set(resident) == {'scope','kernel_bounds','observations',
        'initial_direct_processes_retained','initial_direct_process_count','outer_pid_namespace_matched',
        'hierarchical_caps','descendant_process_inventory','installation_qualified','health_observed',
        'custody_observed','resident_signalled','whole_host_reservation'}
        and resident['scope'] == 'sampled-fixed-default-cgroup-kernel-reservation-v1'
        and type(resident['observations']) is int and 0 < resident['observations'] <= 65535
        and type(resident['initial_direct_process_count']) is int and 0 < resident['initial_direct_process_count'] <= 32
        and all(resident[name] is True for name in ('initial_direct_processes_retained','outer_pid_namespace_matched','hierarchical_caps'))
        and all(resident[name] is False for name in ('descendant_process_inventory','installation_qualified','health_observed',
            'custody_observed','resident_signalled','whole_host_reservation')))
    kernel.kernel_bounds(resident['kernel_bounds'])
    require(resident['initial_direct_process_count'] <= int(resident['kernel_bounds']['pids.max']))
    return profile, targets


def load_source(root, receipt_pin, patches, deadline):
    role_root("source", str(root))
    old_source, old_producer = producer.source.DEADLINE, producer.DEADLINE
    producer.source.DEADLINE = producer.DEADLINE = deadline
    try:
        producer.configure_selection()
        document = producer.selected_document()
        require(document['source_root'] == str(root) and document['source_receipt_sha256'] == receipt_pin)
        report, files, parent = producer.load_candidate(document)
        require(report["kind"] == acquisition.KIND
            and report["status"] == "verified-ninth-acquisition-source-uncompiled"
            and report["patch_sha256"] == list(patches)
            and len(patches) == 9
            and all(report[name] is False for name in acquisition.FLAGS))
        return report, files, parent
    finally:
        producer.source.DEADLINE, producer.DEADLINE = old_source, old_producer


def sdk_claim(report, document, source_report, sdk_fields, metadata_fields):
    require(type(report) is dict and set(report) == sdk_fields | SDK_EXTRA
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["kind"] == export.KIND
        and report["status"] == "verified-selected-native-source-acquisition-sdk"
        and report["source_root"] == document["source"]["root"]
        and report["source_receipt_sha256"] == document["source"]["receipt_sha256"]
        and report["source_inventory_sha256"] == source_report["inventory_sha256"]
        and report["graph_files"] == source_report["graph_files"]
        and report["mapping_sha256"] == source_report["graph_files"]["MODULE.bazel.lock"]["sha256"]
        and report["inventory_sha256"] == document["sdk"]["inventory_sha256"]
        and type(report['repositories']) is list and 0 < len(report['repositories']) <= sdk.MAX_REPOS
        and type(report['counts']) is dict and set(report['counts']) == {'entries','bytes'}
        and type(report['counts']['bytes']) is int and 0 <= report['counts']['bytes'] <= sdk.MAX_BYTES
        and type(report['counts']['entries']) is dict
        and set(report['counts']['entries']) == {'qualification','copy','sealed_readback'}
        and all(type(value) is int and 0 <= value <= sdk.MAX_FILES for value in report['counts']['entries'].values())
        and report["retained_export_root"] == str(producer.EXPORT_ROOT)
        and report["retained_export_receipt_sha256"] == producer.EXPORT_SHA
        and report["binding_receipt_sha256"] == producer.BINDING_SHA
        and report["sdk_export_qualified"] is True
        and all(report[name] is False for name in ("schema_producer_qualified", "live_handoff_proven",
            "native_compile_passed", "native_support", "provider_evaluation")))
    m = report["metadata"]
    require(type(m) is dict and set(m) == metadata_fields | METADATA_EXTRA
        and type(m["schema_version"]) is int and m["schema_version"] == 1
        and m["kind"] == producer.OUTPUT_KIND
        and m["status"] == "verified-strict-regenerated-native-acquisition-hub"
        and m["inputs"] == producer.selected_document()
        and m["binding_receipt_sha256"] == producer.BINDING_SHA
        and m["source_inventory_sha256"] == source_report["inventory_sha256"]
        and m["source_graph"] == source_report["graph_files"]
        and producer.source.sha(producer.source.encoded(m)) == report["metadata_receipt_sha256"]
        and type(m["selector_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", m["selector_sha256"]) is not None
        and type(m["query_exit"]) is int and m["query_exit"] == 0
        and all(m[name] is True for name in ("module_lock_unchanged", "cargo_lock_unchanged", "source_and_export_rechecked"))
        and all(m[name] is False for name in ("sdk_export_qualified", "schema_producer_qualified",
            "live_handoff_proven", "native_compile_passed", "native_support", "provider_evaluation")))


def verify_sdk(root, receipt_pin, source_report, document, deadline, sdk_fields, metadata_fields, reader):
    role_root("sdk", str(root))
    report = reader(root / "receipt.json", receipt_pin, deadline, 64 * 1024 * 1024)
    require(reader(root.parent / 'native-acquisition-metadata/metadata-receipt.json',
        report['metadata_receipt_sha256'], deadline, 64 * 1024 * 1024) == report['metadata'])
    old_source, old_producer = producer.source.DEADLINE, producer.DEADLINE
    producer.source.DEADLINE = producer.DEADLINE = deadline
    budget = sdk.Budget(time.time() + max(0.001, deadline - time.monotonic()), producer.tick)
    try:
        producer.tick()
        producer.configure_selection()
        sdk_claim(report, document, source_report, sdk_fields, metadata_fields)
        hold = producer.hold_root(root)
        try:
            # Full actual sealed byte/registry/JDK/absence proof, not the claim flags.
            require(export.verify_export(root, report, budget) is True)
            retained, files, parent = producer.load_candidate(producer.selected_document())
            require(retained == source_report)
            qualified = sdk.validate_export(producer.EXPORT_ROOT, producer.EXPORT_SHA,
                producer.source.BASE_INVENTORY, parent['baseline_graph_files'], on_read=producer.tick)
            old = export.load_retained(budget)
            require(report["modules"] == old["modules"] and report["registry_metadata"] == old["registry_metadata"]
                and report["nix_inventory"] == old["nix_inventory"])
            new_repos = {row["canonical_name"]: row for row in report["repositories"]}
            old_repos = {row["canonical_name"]: row for row in old["repositories"]}
            require(len(new_repos) == len(report["repositories"]) and set(new_repos) == set(old_repos))
            hub = producer.metadata.HUB
            require(all(new_repos[name] == {**old_repos[name], "source_root": str(producer.EXPORT_ROOT / "repositories" / name)}
                        for name in old_repos if name != hub))
            previous = producer.read_hub(producer.EXPORT_ROOT / "repositories" / hub)
            generated = producer.read_hub(root / "repositories" / hub)
            producer.binding.verify_hub_delta(previous, generated)
            require(report["metadata"]["generated_hub"] == {name: {"sha256": producer.source.sha(raw),
                "bytes": len(raw), "mode": 0o444} for name, raw in generated.items()}
                and report["metadata"]["retained_hub"] == {name: {"sha256": producer.source.sha(raw), "bytes": len(raw)}
                    for name, raw in previous.items()}
                and report["metadata"]["parent_export_inventory_sha256"] == qualified["inventory_sha256"])
            work = Path(report["metadata"]["query_plan"]["environment"]["HOME"]).parent
            require(report["metadata"]["query_plan"] == producer.query_plan(work, work / "workspace/source", qualified))
            row = new_repos[hub]
            require(row["source_root"] == str(root.parent / "native-acquisition-metadata/hub")
                and row["source_files"] == row["files"] and row["source_inventory_sha256"] == row["inventory_sha256"])
            fd = sdk.open_dir(root)
            try:
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555
                    and set(os.listdir(fd)) == {"repositories", "graph", "registry-cache", "receipt.json"})
            finally: os.close(fd)
            graph_shape(root / 'graph', report['graph_files'], deadline)
            require(producer.load_candidate(producer.selected_document())[0] == source_report)
            producer.recheck_root(root, hold)
            require(reader(root / "receipt.json", receipt_pin, deadline, 64 * 1024 * 1024) == report)
        finally: os.close(hold[0])
    finally:
        producer.source.DEADLINE, producer.DEADLINE = old_source, old_producer
    repositories = {name: str(root / "repositories" / name) for name in new_repos}
    return report, {"repositories": repositories, "module_overrides": {name: repositories[row["canonical_name"]]
        for name, row in report["modules"].items()}, "registry_cache": str(root / "registry-cache"),
        "inventory_sha256": report["inventory_sha256"], "mapping_sha256": report["mapping_sha256"],
        "graph_files": report['graph_files'],
        "registry_inventory_sha256": report['registry_metadata']['inventory_sha256']}


def graph_shape(root, files, deadline):
    """Exact sealed physical graph, including empty/extra-directory refusal."""
    names = set(files)
    directories = {''} | {str(parent) for name in names for parent in Path(name).parents
                           if str(parent) != '.'}
    def visit(relative=''):
        require(time.monotonic() < deadline)
        fd = sdk.open_dir(root / relative)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
            expected = {name[len(relative)+1:].split('/')[0] if relative else name.split('/')[0]
                        for name in names if not relative or name.startswith(relative+'/')}
            require(set(os.listdir(fd)) == expected)
            for name in expected:
                require(time.monotonic() < deadline)
                child = relative+'/'+name if relative else name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if child in directories:
                    require(stat.S_ISDIR(info.st_mode))
                    visit(child)
                else:
                    require(child in names and stat.S_ISREG(info.st_mode)
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444)
        finally:
            os.close(fd)
    visit()
def producer_success(selection, target, output_name, deadline):
    import codex_protocol_history_native as protocol
    from codex_protocol_history_native import read_json, path, native, trusted_parent, hash_regular, tick
    import xml.etree.ElementTree as ET
    value=selection['producer'];receipt=read_json(path(value['receipt']),value['sha256'],deadline)
    protocol.producer_pin(value)
    profile, targets = producer_policy(receipt, target)
    native.phase2_effective_runtime(receipt['observed_properties']['RuntimeMaxUSec'],1200)
    require(receipt['id']==Path(value['receipt']).parent.name
        and receipt['unit']=='omux-execution-'+receipt['id']+'.service'
        and receipt['profile']==profile and receipt['manager']=='system'
        and type(receipt['exit']) is int and receipt['exit']==0
        and type(receipt['workload_exit']) is int and receipt['workload_exit']==0
        and receipt['controller_failure'] is None and receipt['descendants_empty'] is True
        and receipt['cleanup']['state']=='empty' and receipt['source_dirty']=='false'
        and receipt['source_commit']==value['source_commit']
        and receipt['graph_sha256']==value['graph_sha256']
        and receipt['verb']=='test' and receipt['targets']==targets
        and receipt['test_evidence']['state']=='preserved', 'successful outer producer required')
    output=path(receipt['output_base']);root=path(selection['root'])
    prefix=str(output)+'/execroot/_main/bazel-out/'
    suffix='/testlogs/tools/'+target.split(':')[1]+'/test.outputs'+('/'+output_name if output_name else '')
    require(str(root).startswith(prefix) and str(root).endswith(suffix)
        and re.fullmatch(r'[A-Za-z0-9_.-]+',str(root)[len(prefix):-len(suffix)]) is not None,
        'selected output is not the actual producer test namespace')
    evidence=read_json(Path(value['receipt']).parent/'test-evidence.json',
        receipt['test_evidence']['sha256'],deadline)
    require(type(evidence['schema']) is int and evidence['schema']==1
        and type(evidence['bazel_exit']) is int and evidence['bazel_exit']==0
        and evidence['epoch_start_ns']==receipt['epoch_start_ns']
        and evidence['targets']==targets and len(evidence['results'])==len(targets)
        and [row['target'] for row in evidence['results']]==targets,
        'producer evidence epoch/target mismatch')
    row=next(row for row in evidence['results'] if row['target']==target)
    require(row['target']==target and row['state']=='observed', 'producer evidence absent')
    if profile != 'standard':
        require(all(item['state'] == 'observed' and all(
            len([file for file in item['files'] if file['source'] == member and file['state'] == 'copied']) == 1
            for member in ('test.log','test.xml')) for item in evidence['results']),
            'reserved producer cohort evidence incomplete')
    for item in evidence['results']:
      for member in ('test.log','test.xml'):
        entries=[entry for entry in item['files'] if entry['source']==member]
        require(len(entries)==1 and entries[0]['state']=='copied', 'producer evidence not copied')
        entry=entries[0]
        require(re.fullmatch(r'[0-9a-f]{64}\.evidence',entry['file']) is not None, 'producer evidence name refused')
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
