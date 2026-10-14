"""Distinct retained tree-SOURCE delivery into a fresh native model action.

No copied ContentDependencyLease, historical SDK inode or cached test result is
admitted. Current complete SOURCE/HUB files, actual source outer/confirmation and
evidence remain declared aliases; current SDK authority is separately regenerated
by the actual HeldRetainedSdkTree owner under the same original SOURCE600.
"""
import os
from pathlib import Path
import re
import stat
import codex_native_file_writer_model_source as family
import codex_native_owned_history_source as history
import codex_native_siwc_catalog_tree_source as controller
import codex_retained_sdk_tree_reader as reader
import guard_native_sdk_tree_reserved as guard
import codex_native_siwc_content_delivery_inputs as legacy

source = family.source
KIND, STATUS = history.KIND, history.STATUS
SELECTION_KIND = 'omux-native-siwc-catalog-tree-owned-history-selection-v1'
SELECTED_STATUS = 'qualified-retained-tree-owned-history-source-hub-uncompiled'
INPUT_KIND = 'omux-native-siwc-catalog-tree-owned-history-input-v1'
REPOSITORY = 'omux_native_siwc_catalog_model_inputs'
PROFILE = guard.SOURCE_PROFILE
TARGETS = tuple(guard.COHORTS[PROFILE][1:])
LEAF = controller.OUTPUT
SDK_SEMANTIC_FIELDS = ('kind','custody','creator','inventory_sha256','original_mapping',
    'mapping_commitment_scope','original_mapping_document_sha256','physical_mode_policy',
    'complete_members','downstream_requires_fresh_tree_proof','consumer_copied_tree',
    'ambient_original_roots_read','sdk_execution_qualified','source_qualified','compiler_qualified','runtime_qualified')


def closed(value,keys): return legacy.closed(value,keys)


def selection(value):
    closed(value,('schema_version','kind','status','catalog_controls_sha256','source'))
    source.require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == SELECTION_KIND and value['status'] == SELECTED_STATUS
        and value['catalog_controls_sha256'] == history.CONTROL_SHA)
    row = value['source']
    closed(row,('root','receipt_sha256','receipt_bytes','inventory_sha256','producer','source_terminal_confirmation'))
    family.protocol.producer_pin(row['producer']);family.protocol.pin(row['receipt_sha256'])
    family.protocol.pin(row['inventory_sha256']);legacy.count(row['receipt_bytes'])
    confirmation=closed(row['source_terminal_confirmation'],('sha256','bytes'))
    family.protocol.pin(confirmation['sha256']);legacy.count(confirmation['bytes'],maximum=1024*1024)
    # Exact output_base comes from authenticated producer bytes, not a mutable
    # caller root. This lexical bound precedes reading those bytes.
    run=Path(row['producer']['receipt']).parent
    prefix=str(run.parent)+'/cache-v2-sdk-tree-'
    suffix='/output-base/execroot/_main/bazel-out/'
    literal=str(family.protocol.path(row['root']))
    source.require(literal.startswith(prefix))
    tail=literal[len(prefix):];parts=tail.split('/')
    source.require(len(parts) == 11 and re.fullmatch(r'[0-9a-f]{64}',parts[0]) is not None
        and parts[1:5] == ['output-base','execroot','_main','bazel-out']
        and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',parts[5]) is not None
        and parts[6:] == ['testlogs','tools','codex_native_siwc_catalog_tree_source_producer','test.outputs',LEAF])
    return value


class Inputs(legacy.RetainedInputs):
    KIND = INPUT_KIND
    def __init__(self,runfiles,rows):
        source.require(type(self) is Inputs)
        self.role_modes={}
        self._empty_diagnostic=None
        family.Inputs.__init__(self,runfiles,rows,_repository=REPOSITORY,_kind=INPUT_KIND)

    def admit(self,row):
        source.require(self.selection == row)
        run=Path(row['producer']['receipt']).parent
        source.require(str(run/'receipt.json') in self.rows and str(run/'sdk-tree-qualified.json') in self.rows)
        self.role_modes={str(run/'receipt.json'):(0o600,),str(run/'sdk-tree-qualified.json'):(0o600,)}


    def read_empty_optional(self,path,member,deadline):
        # Only an authenticated copied zero-byte optional collector role may
        # use this scope-local capture. Core metadata/source/log/XML policies
        # and every legacy/default capture remain unchanged.
        closed(member,('source','state','file','sha256','bytes'))
        run=Path(self.selection['producer']['receipt']).parent
        path=Path(path)
        source.require(type(self) is Inputs and self._empty_diagnostic is None
            and member['source'] in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
            and member['state'] == 'copied' and type(member['bytes']) is int and member['bytes'] == 0
            and member['sha256'] == source.sha(b'')
            and re.fullmatch(r'[0-9a-f]{64}[.]evidence',member['file']) is not None
            and path == run/'test-evidence'/member['file']
            and str(path) in self.rows and self.role_modes.get(str(path)) == (0o600,))
        self._empty_diagnostic=(str(path),member['source'])
        try:return self.read(path,member['sha256'],deadline,0)
        finally:self._empty_diagnostic=None

    def _capture(self,path,maximum,*,declaration=False):
        path=Path(path)
        if self._empty_diagnostic is None or self._empty_diagnostic[0] != str(path):
            return super()._capture(path,maximum,declaration=declaration)
        source.require(type(self) is Inputs and not declaration and maximum == 0
            and self._empty_diagnostic[1] in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
            and self.role_modes.get(str(path)) == (0o600,))
        parent_owner,leaf_owner=legacy._OwnedFD(),legacy._OwnedFD()
        self.stack.callback(parent_owner.close);self.stack.callback(leaf_owner.close)
        parent_owner.fd=source.directory(path.parent);parent=parent_owner.fd
        leaf_owner.fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        fd=leaf_owner.fd
        before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        anchor=family.tenth.witness(before)
        source.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 0
            and family.tenth.witness(os.fstat(fd)) == anchor)
        parent_anchor=family.tenth.witness(os.fstat(parent))
        raw,unused=source.read(parent,path.name,0)
        source.require(raw == b'' and family.tenth.witness(os.fstat(fd)) == anchor
            == family.tenth.witness(os.stat(path.name,dir_fd=parent,follow_symlinks=False))
            and family.tenth.witness(os.fstat(parent)) == parent_anchor)
        self.held[str(path)]=(parent,fd,anchor,parent_anchor)
        return raw


def validate_report_method(report):
    history.validate_report_method(report)
    source.require(report['tracked_files'] == 8557 and type(report['source_inventory']) is dict
        and len(report['source_inventory']) == 8557
        and report['inventory_sha256'] == source.sha(source.canonical(report['source_inventory'])))
    current=report['transported_sdk']
    source.require(type(current) is dict and current['kind'] == reader.KIND
        and current['custody'] == 'current-complete-retained-public-sdk-tree'
        and current['mapping_commitment_scope'] == 'original-logical-recipe-preserved'
        and current['physical_paths_scope'] == 'current-held-source-invocation-only'
        and current['downstream_requires_fresh_tree_proof'] is True
        and all(current[name] is False for name in ('consumer_copied_tree','ambient_original_roots_read',
            'sdk_execution_qualified','source_qualified','compiler_qualified','runtime_qualified'))
        and type(current['complete_members']) is int and 0 < current['complete_members'] <= reader.core.MAX_ENTRIES
        and 'original_sdk' not in report)
    # Metadata records original creator provenance, not a current root promise.
    for field in ('inventory_sha256','original_mapping_document_sha256','fresh_mapping_document_sha256'):
        family.protocol.pin(current[field])
    actual=report['producer_context']
    context={'MODE':actual['mode'],'ENTRY_NS':str(actual['entry_monotonic_ns']),
        'DEADLINE_NS':str(actual['deadline_monotonic_ns']),'EPOCH':actual['epoch'],
        'SOURCE_COMMIT':actual['source_commit'],'GRAPH_SHA256':actual['graph_sha256']}
    source.require(current['consumer_context'] == context)
    reader.original.validate_context(context)


def same_sdk_recipe(old,current):
    validate_report_method(old);validate_report_method(current)
    source.require(all(old['transported_sdk'][name] == current['transported_sdk'][name]
        for name in SDK_SEMANTIC_FIELDS))


def admit_sdk(sdk,report):
    # The exact sealed owner performs current process/thread/context/clock,
    # current named+held roots and full qualified input fences. Labels alone
    # cannot substitute a transported or caller-created SDK capability.
    source.require(type(sdk) is reader.HeldRetainedSdkTree)
    sdk.check();validate_report_method(report)
    source.require(report['transported_sdk'] == sdk.record())
    sdk.check()
    return sdk.sdk_root


def _configuration(row,outer):
    prefix=outer['output_base']+'/execroot/_main/bazel-out/'
    suffix='/testlogs/tools/codex_native_siwc_catalog_tree_source_producer/test.outputs/'+LEAF
    literal=row['root']
    source.require(literal.startswith(prefix) and literal.endswith(suffix))
    value=literal[len(prefix):-len(suffix)]
    source.require(re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',value) is not None)
    return value


def guardian(row,inputs):
    source.require(type(inputs) is Inputs and inputs.selection == row)
    selection({'schema_version':1,'kind':SELECTION_KIND,'status':SELECTED_STATUS,
        'catalog_controls_sha256':history.CONTROL_SHA,'source':row})
    inputs.admit(row)
    run=Path(row['producer']['receipt']).parent
    raw=inputs.read(run/'receipt.json',row['producer']['sha256'],source.DEADLINE,1024*1024)
    outer=family.decode(raw)
    source.require(outer['id'] == run.name and outer['profile'] == PROFILE and outer['targets'] == list(TARGETS)
        and type(outer['exit']) is int and outer['exit'] == 0
        and type(outer['workload_exit']) is int and outer['workload_exit'] == 0
        and outer['controller_failure'] is None and outer['descendants_empty'] is True
        and outer['source_dirty'] == 'false' and outer['verb'] == 'test' and outer['manager'] == 'system'
        and outer['source_commit'] == row['producer']['source_commit']
        and outer['graph_sha256'] == row['producer']['graph_sha256']
        and outer['cache_reuse_requested'] is True and type(outer['cache_policy']) is int and outer['cache_policy'] == 2)
    pin=row['source_terminal_confirmation']
    confirmed=inputs.read(run/'sdk-tree-qualified.json',pin['sha256'],source.DEADLINE,1024*1024)
    source.require(len(confirmed) == pin['bytes'])
    confirmation=guard.validate_qualification_confirmation(outer,family.decode(confirmed),row['producer']['sha256'],len(raw))
    inputs.check_all()
    source.require(list(inputs.held[str(run/'receipt.json')][2])
        == confirmation['canonical_receipt_creator_witness'])
    legacy._cleanup(outer['cleanup'])
    lease=outer['native_sdk_tree_dependency_lease'];key=lease['key'];family.protocol.pin(key)
    entry,until=lease['entry_monotonic_ns'],lease['deadline_monotonic_ns']
    source.require(type(entry) is int and type(until) is int and until-entry == 1200*10**9
        and lease['kind'] == 'omux-retained-sdk-tree-dependency-lease-v1' and lease['family'] == guard.FAMILY
        and lease['key'] == outer['cache_key'] and lease['namespace'] == 'cache-v2-sdk-tree-'+key
        and lease['profile'] == PROFILE and lease['run_id'] == run.name
        and lease['source_commit'] == outer['source_commit'] and lease['graph_sha256'] == outer['graph_sha256']
        and lease['output_base'] == outer['output_base'] == str(run.parent/lease['namespace']/'output-base'))
    family.protocol.path(lease['checkout'])
    expected={'kind':'omux-retained-sdk-tree-dependency-disposition-v1','family':guard.FAMILY,
        'state':'dependency-data-after-success','checkout':lease['checkout'],'key':key,'namespace':lease['namespace'],
        'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
    source.require(outer['native_sdk_tree_dependency_disposition'] == expected
        and outer['native_sdk_tree_artifact_origin'] is None)
    context={'MODE':guard.old.INPUT_MODE,'ENTRY_NS':str(entry),'DEADLINE_NS':str(until),'EPOCH':str(run),
        'SOURCE_COMMIT':outer['source_commit'],'GRAPH_SHA256':outer['graph_sha256']}
    legacy._command(outer['command'],context,_source_targets=TARGETS)
    source.require([part for part in outer['command'] if part.startswith('--output_base=')] == ['--output_base='+outer['output_base']])
    configuration=_configuration(row,outer)
    evidence_ref=closed(outer['test_evidence'],('state','manifest','sha256','bytes','files'))
    source.require(evidence_ref['state'] == 'preserved' and evidence_ref['manifest'] == 'test-evidence.json')
    legacy.count(evidence_ref['bytes'],maximum=64*1024*1024);legacy.count(evidence_ref['files'],minimum=4,maximum=8)
    family.protocol.pin(evidence_ref['sha256'])
    index_path=run/'test-evidence.json';inputs.role_modes[str(index_path)]=(0o600,)
    evidence=family.decode(inputs.read(index_path,evidence_ref['sha256'],source.DEADLINE,1024*1024))
    source.require(type(evidence) is dict and evidence['schema'] == 1 and evidence['bazel_exit'] == 0
        and evidence['epoch_start_ns'] == outer['epoch_start_ns'] and evidence['targets'] == list(TARGETS)
        and type(evidence['results']) is list and [result['target'] for result in evidence['results']] == list(TARGETS)
        and evidence['bytes'] == evidence_ref['bytes'] and evidence['copied_files'] == evidence_ref['files'])
    required={str(run/'receipt.json'),str(run/'sdk-tree-qualified.json'),str(index_path),row['root']+'/source-receipt.json'}
    actual_bytes=0;actual_files=0
    for result in evidence['results']:
        source.require(result['state'] == 'observed' and result['configuration'] == configuration
            and type(result['files']) is list and [item['source'] for item in result['files']] == [
                'test.log','test.xml','test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS'])
        for member in result['files']:
            if member['state'] in ('missing','stale'):
                source.require(member['source'] in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
                    and set(member) == {'source','state','bytes'} and type(member['bytes']) is int and member['bytes'] == 0)
                continue
            closed(member,('source','state','file','sha256','bytes'))
            source.require(member['state'] == 'copied' and type(member['file']) is str
                and re.fullmatch(r'[0-9a-f]{64}[.]evidence',member['file']) is not None)
            optional=member['source'] in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
            family.protocol.pin(member['sha256']);legacy.count(member['bytes'],minimum=0 if optional else 1,maximum=64*1024*1024)
            path=str(run/'test-evidence'/member['file']);source.require(path not in required)
            required.add(path);inputs.role_modes[path]=(0o600,)
            data=(inputs.read_empty_optional(path,member,source.DEADLINE) if optional and member['bytes'] == 0
                else inputs.read(path,member['sha256'],source.DEADLINE,64*1024*1024))
            source.require(len(data) == member['bytes'])
            if member['source'] == 'test.xml':guard._xml_success(data)
            actual_bytes+=len(data);actual_files+=1
    source.require(actual_bytes == evidence_ref['bytes'] and actual_files == evidence_ref['files'])
    report_raw=inputs.read(Path(row['root'])/'source-receipt.json',row['receipt_sha256'],source.DEADLINE,source.MAX_METADATA)
    source.require(len(report_raw) == row['receipt_bytes'])
    report=family.decode(report_raw);validate_report_method(report)
    source.require(report['inventory_sha256'] == row['inventory_sha256']
        and report['producer_context'] == {'mode':context['MODE'],'entry_monotonic_ns':entry,
            'deadline_monotonic_ns':until,'epoch':str(run),'source_commit':outer['source_commit'],
            'graph_sha256':outer['graph_sha256']})
    inputs.check_all();source.tick()
    return outer,required


def retain_controls(owner):return controller.retain_controls(owner)


def main(*,_child=None,_extra=None,_retainer=None,_admitted=None):
    source.require(controller.selected_recipe() == 'owned-history-thirteen-v3')
    controller.main(_child=_child,_extra=_extra,_retainer=_retainer,_admitted=_admitted)
