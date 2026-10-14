"""Actual normal native targets inside fresh catalog SOURCE/HUB/original SDK custody."""
from contextlib import ExitStack
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import SimpleNamespace
import codex_native_siwc_catalog_source as catalog
import codex_native_siwc_catalog_content_source as content_catalog
import codex_native_owned_history_source as history
import codex_native_siwc_content_delivery_inputs as delivery
import codex_native_file_writer_models as shared
import codex_native_profile as native
import guard_native_siwc_catalog_source_reserved as source_guard
import guard_native_siwc_catalog_content_source_reserved as content_source_guard

family, source = catalog.parent, catalog.source
SELECTION = 'integrations/codex-upstream/siwc-native-catalog-models/qualified-source.json'
REPOSITORY = 'omux_native_siwc_catalog_model_inputs'
INPUT_KIND = 'omux-native-siwc-catalog-model-input-v1'
KIND = 'omux-native-siwc-catalog-models-v1'
TARGETS = ('//codex-rs/core:core-unit-tests', '//codex-rs/tui:tui-unit-tests',
    '//codex-rs/app-server:app-server-unit-tests', '//codex-rs/models-manager:models-manager-unit-tests')
ROLES = ('core', 'tui', 'app-server', 'models-manager')
EVIDENCE_NAMES = tuple(role + '-test.' + extension for role in ROLES for extension in ('log','xml')) + ('native-stdout.log','native-stderr.log')
DELIVERY_STATUSES = (delivery.STATUS, delivery.HISTORY_STATUS)
CONTENT_FAMILIES = (content_catalog, history)
SOURCE_ROUTES = {
    delivery.HISTORY_STATUS: (history, content_source_guard,
        'codex_native_siwc_catalog_content_source_producer', 'native-siwc-catalog-content-source'),
    'qualified-catalog-source-hub-uncompiled': (catalog, source_guard,
        'codex_native_siwc_catalog_source_producer', 'native-siwc-catalog-source'),
    'qualified-catalog-content-source-hub-uncompiled': (content_catalog, content_source_guard,
        'codex_native_siwc_catalog_content_source_producer', 'native-siwc-catalog-content-source'),
    delivery.STATUS: (content_catalog, content_source_guard,
        'codex_native_siwc_catalog_content_source_producer', 'native-siwc-catalog-content-source'),
}

SEMANTIC_FIELDS = ('kind','status','commit','qualified_parent','native_controls_sha256',
    'native_v4_controls_sha256','native_catalog_v3_manifest_sha256','native_delta_manifest_sha256',
    'patch_sha256','patches','source_inventory','inventory_sha256','tracked_files','source_bytes',
    'graph_files','generated_hub','native_test_contract','native_v4_test_contract')


def selection(raw):
    value = family.decode(raw)
    if type(value) is dict and value.get('kind') == delivery.HISTORY_SELECTION_KIND:
        return delivery.history_selection(value)
    if type(value) is dict and value.get('kind') == delivery.SELECTION_KIND:
        return delivery.selection(value,catalog.CONTROL_SHA)
    source.require(type(value) is dict and set(value) == {'schema_version','kind','status','catalog_controls_sha256','source'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'omux-native-siwc-catalog-model-selection-v1'
        and value['catalog_controls_sha256'] == catalog.CONTROL_SHA)
    # Cold declaration is honest data, never a provisional success constructor.
    source.require(value['status'] in SOURCE_ROUTES and value['status'] not in DELIVERY_STATUSES and type(value['source']) is dict)
    row = value['source']
    source.require(set(row) == {'root','receipt_sha256','receipt_bytes','inventory_sha256','producer'}
        and type(row['receipt_bytes']) is int and 0 < row['receipt_bytes'] <= source.MAX_METADATA)
    family.protocol.pin(row['receipt_sha256']); family.protocol.pin(row['inventory_sha256'])
    family.protocol.producer_pin(row['producer'])
    root = family.protocol.path(row['root'])
    prefix = str(Path(row['producer']['receipt']).parent / 'output-base/execroot/_main/bazel-out') + '/'
    unused_family, unused_guard, target, leaf = SOURCE_ROUTES[value['status']]
    suffix = '/testlogs/tools/' + target + '/test.outputs/' + leaf
    source.require(str(root).startswith(prefix) and str(root).endswith(suffix)
        and re.fullmatch(r'[A-Za-z0-9_.-]+',str(root)[len(prefix):-len(suffix)]) is not None)
    return value


def expected_tests():
    current = catalog.controls()[1]
    catalog.model_patch(current)
    value = family.decode(family.pinned_artifact(current['tests']))
    original = family.decode(family.pinned_artifact(catalog.previous.controls()[1]['tests']))
    by_target = {TARGETS[0]:tuple(value['core_unit_tests']) + tuple(original['expected']),
        TARGETS[1]:tuple(value['tui_unit_tests']), TARGETS[2]:tuple(value['app_server_unit_tests']), TARGETS[3]:()}
    source.require(len(by_target[TARGETS[0]]) == 30 and sum(map(len,by_target.values())) == 35
        and len(set(name for names in by_target.values() for name in names)) == 35)
    return by_target


def history_expected_tests():
    original = expected_tests()
    added = history.test_contract(history.controls()[1])
    result = dict(original)
    result[TARGETS[0]] += tuple(added['core_unit_tests'])
    result[TARGETS[2]] += tuple(added['app_server_unit_tests'])
    source.require(tuple(map(len,result.values())) == (50,4,6,0)
        and len({name for names in result.values() for name in names}) == 60)
    return result


def accept_log(raw, expected):
    source.require(type(raw) is bytes and 0 < len(raw) <= shared.MAX_LOG)
    rows = re.findall(rb'^test ([A-Za-z0-9_:]+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)(?:,[^\r\n]*)?\r?$',raw,re.MULTILINE)
    names = [name.decode('ascii') for name,unused in rows]
    source.require(len(names) == len(set(names)) and set(expected) <= set(names)
        and all(result != b'FAILED' for unused,result in rows)
        and all(dict(zip(names,[result for unused,result in rows]))[name] == b'ok' for name in expected))
    runs = re.findall(rb'^running ([0-9]+) tests?\r?$',raw,re.MULTILINE)
    summaries = re.findall(rb'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9]+(?:[.][0-9]+)?s\r?$',raw,re.MULTILINE)
    source.require(len(runs) == len(summaries) == 1 and int(runs[0]) == len(rows))
    status,passed,failed,ignored,measured,filtered = summaries[0]
    source.require(status == b'ok' and failed == measured == filtered == b'0'
        and int(passed) == sum(result == b'ok' for unused,result in rows)
        and int(ignored) == sum(result == b'ignored' for unused,result in rows)
        and int(passed) + int(ignored) == len(rows))
    return {'required_passed':list(expected),'passed':int(passed),'failed':0,'ignored':int(ignored),
        'filtered_out':0,'log_sha256':source.sha(raw),'log_bytes':len(raw)}


class SelectedSource(family.binding.SealedSource):
    def __exit__(self,*unused):
        first = None
        retired = []
        for name in ('receipt','tree','held'):
            fd = getattr(self,name); setattr(self,name,None)
            if fd is not None: retired.append(fd)
        for fd in retired:
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


class ExtraOwners:
    """Selected public proof and evidence stay owned through final SDK/SOURCE IO."""
    def __init__(self):
        self.selected = None
        self.source_family, self.source_guard = catalog, source_guard
        self.stack, self.evidence = ExitStack(), family.HeldControls()
        self.inputs = self.captured = self.row = self.raw_selection = None
        self.output_parent = self.output_anchor = self.streams = None
        self.stream_bytes = None
        self.source_outer = None

    def retain(self, owner):
        original = self.source_family.retain_controls(owner)
        runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
        mapping = [physical for alias,physical,*unused in owner.aliases if alias == runfiles/'_repo_mapping']
        source.require(len(mapping) == 1)
        self.mapping_raw = owner.raws[str(mapping[0])]
        source.require(0 < len(self.mapping_raw) <= 1024*1024)
        raw = owner.add(family.binding.ninth.parent.ROOT / SELECTION, maximum=16384)
        selected = selection(raw)
        source.require(self.selected is None or selected == self.selected)
        self.selected = selected
        self.source_family, self.source_guard, unused_target, unused_leaf = SOURCE_ROUTES[selected['status']]
        self.row = selected['source']; self.raw_selection = raw
        return original

    def admit(self,published,report):
        source.require(self.row is not None and self.inputs is None)
        runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
        # The main owner already bounded/held this exact repo mapping.
        rows = [row.split(',') for row in self.mapping_raw.decode().splitlines()]
        source.require(all(len(row) == 3 for row in rows))
        if self.selected['status'] in DELIVERY_STATUSES:
            self.inputs = self.stack.enter_context((delivery.HistoryRetainedInputs if self.source_family is history else delivery.RetainedInputs)(runfiles,rows))
        elif self.source_family in CONTENT_FAMILIES:
            self.inputs = self.stack.enter_context(content_catalog.intake.ModelProofInputs(runfiles, rows))
            source.require(self.inputs.selection == self.row)
            self.inputs.admit_content_provenance(self.row)
        else:
            self.inputs = self.stack.enter_context(family.Inputs(runfiles,rows,_repository=REPOSITORY,_kind=INPUT_KIND))
        source.require(self.inputs.selection == self.row)
        self.source_outer, required = (delivery.guardian(self.row,self.inputs) if self.selected['status'] in DELIVERY_STATUSES
            else family.guardian(self.row,self.inputs,_guard=self.source_guard))
        old_report = self.inputs.read_json(Path(self.row['root'])/'source-receipt.json',self.row['receipt_sha256'],source.DEADLINE)
        expected_status = ('verified-siwc-catalog-source-uncompiled' if self.source_family is catalog
            else self.source_family.STATUS)
        source.require(old_report['kind'] == self.source_family.KIND and old_report['status'] == expected_status
            and old_report['inventory_sha256'] == self.row['inventory_sha256']
            and len(old_report['patch_sha256']) == (13 if self.source_family is history else 12)
            and all(old_report[name] is False for name in catalog.previous.FALSE_FLAGS)
            and all(old_report[field] == report[field] for field in SEMANTIC_FIELDS))
        if self.source_family is history:
            source.require(all(old_report[field] == report[field] for field in (
                'native_catalog_controls_sha256','native_owned_history_controls_sha256',
                'native_owned_history_manifest_sha256','native_owned_history_preimages',
                'native_owned_history_afterimages','native_owned_history_test_contract')))
        if self.source_family in CONTENT_FAMILIES:
            self.source_family.validate_report_method(old_report)
            self.source_family.validate_report_method(report)
            source.require(old_report['source_intake'] == report['source_intake'])
        self.captured = self.stack.enter_context(SelectedSource(Path(self.row['root']),self.row['receipt_sha256'],
            size=self.row['receipt_bytes'],modes=(0o444,0o555)))
        self.captured.accept(old_report,published.files)
        members = {'source/'+name:row for name,row in published.files.items()}
        hub = published.hub
        source.require(type(hub) is dict and old_report['generated_hub'] == {
            name:{'sha256':source.sha(raw),'bytes':len(raw)} for name,raw in sorted(hub.items())})
        if self.selected['status'] in DELIVERY_STATUSES:
            delivery.validate_members(self.inputs.publication,old_report,published.files,hub,self.captured.raw)
        source.verify_written(Path(self.row['root'])/'hub/source',{name:('100644',raw) for name,raw in hub.items()})
        members.update({'hub/source/'+name:('100644',raw) for name,raw in hub.items()})
        members['source-receipt.json'] = ('100644',self.captured.raw)
        # The publisher seals this regular receipt444; the existing retained
        # Source contract permits Bazel's readonly555 layout. Bind the actual
        # held mode, not a guessed transport state or broader writable policy.
        receipt_mode = stat.S_IMODE(os.fstat(self.captured.receipt).st_mode)
        source.require(receipt_mode in (0o444,0o555))
        published.parents.append(family.tenth.TreeWitness(Path(self.row['root']),members,
            receipt_name='source-receipt.json' if receipt_mode == 0o444 else None))
        required.update(str(Path(self.row['root'])/'source'/name) for name in published.files)
        required.update(str(Path(self.row['root'])/'hub/source'/name) for name in hub)
        source.require(set(self.inputs.rows) == required)
        self.inputs.check_all()

    def full(self):
        source.require(self.captured is not None and self.inputs is not None)
        self.captured.recheck()
        source.verify_written(self.captured.root/'hub/source',self.hub)
        source.require((delivery.guardian(self.row,self.inputs) if self.selected['status'] in DELIVERY_STATUSES
            else family.guardian(self.row,self.inputs,_guard=self.source_guard))[0] == self.source_outer)
        self.inputs.check_all(); self.evidence.full()

    def evidence_full(self):
        self.evidence.full()
        source.require(self.streams is not None and self.stream_bytes is not None)
        for name,raw in self.stream_bytes.items(): source.require(self.streams.bytes(name) == raw)
        self.fence()

    def fence(self):
        source.require(self.inputs is not None and self.captured is not None)
        self.inputs.check_all(); self.short()

    def short(self):
        # After SOURCE terminal observation, no second bulk alias walk. Held
        # alias-parent witnesses reject namespace drift during the other sweep.
        self.captured.check(); self.inputs.check(); self.evidence.fence()
        if self.streams is not None: self.streams.fence()
        if self.output_anchor is not None:
            source.require(family.tenth.witness(os.fstat(self.output_parent)) == self.output_anchor)
            named = source.directory(self.output_path)
            try: source.require(family.tenth.witness(os.fstat(named)) == self.output_anchor)
            finally: os.close(named)

    def close(self):
        first = None
        for cleanup in ((self.streams.close if self.streams is not None else (lambda:None)),self.evidence.close,self.stack.close,
                (lambda:os.close(self.output_parent)) if self.output_parent is not None else (lambda:None)):
            try: cleanup()
            except BaseException as error:
                if first is None: first = error
        self.output_parent = None
        if first is not None: raise first

    def __enter__(self): return self
    def __exit__(self,*unused): self.close()


def native_plan(published,sdk,report,work,cutoff):
    source.require(not work.exists() and report['kind'] in (catalog.KIND, content_catalog.KIND, history.KIND)
        and len(report['patch_sha256']) == (13 if report['kind'] == history.KIND else 12)
        and published.active and all(report[name] is False for name in catalog.previous.FALSE_FLAGS))
    if report['kind'] in (content_catalog.KIND, history.KIND):
        # Admit the concrete owner before SDK/publication/query IO or scratch
        # effects. The later full record/root join remains mandatory unchanged.
        source.require(type(sdk) is content_catalog.transported.HeldTransportedSDK)
        (history if report['kind'] == history.KIND else content_catalog).validate_report_method(report)
    sdk.check(); published.full()
    mapping = sdk.mapping()
    tools = family.query_tools.verify_repository(family.query.QUERY_REPOSITORY,cutoff)
    source.require(tools['status'] == 'declared-fixed-query-tools-byte-qualified' and tools['inputs_rechecked'] is True)
    work.mkdir(mode=0o700)
    candidate = SimpleNamespace(source=published.path/'source',root=work,lease=SimpleNamespace(output_base=work/'output-base'))
    export_root = family.query.EXPORT_ROOT
    if report['kind'] in (content_catalog.KIND, history.KIND):
        source.require(type(sdk) is content_catalog.transported.HeldTransportedSDK
            and 'original_sdk' not in report and report['transported_sdk'] == sdk.record())
        export_root = sdk.sdk_root
    args = SimpleNamespace(native_export_root=export_root,native_mode='siwc-catalog-models')
    plan = native.command_from_verified_inputs(args,work,family.query.LOCKED_PATH,tools['query_tools']['tools']['bash'],
        candidate,(report,mapping),{'siwc-catalog-models':('test',TARGETS,'')},gates=None)
    original = list(plan['argv'])
    plan = shared.project_hub(plan,mapping,published.path/'hub/source',export_root)
    remaining = math.floor(cutoff-time.monotonic()-90)
    source.require(remaining > 0 and tuple(plan['argv'][-len(TARGETS):]) == TARGETS
        and plan['argv'].count('--test_timeout=1200') == 1 and '--test_sharding_strategy=disabled' in plan['argv']
        and plan['argv'].count('--test_filter=') == 1 and not any(row.startswith('--test_arg=') for row in plan['argv']))
    plan['argv'] = [('--test_timeout='+str(remaining)) if row == '--test_timeout=1200' else row for row in plan['argv']]
    plan['environment']['CARGO_NET_OFFLINE'] = 'true'
    plan['argv'][plan['argv'].index('test')+1:plan['argv'].index('test')+1] = ['--repo_env=CARGO_NET_OFFLINE=true','--flaky_test_attempts=1']
    source.require(tools['query_tools']['tools']['bazel'] == native.BAZEL == family.query.BAZEL)
    plan['qualified_query_tools'] = tools
    plan['original_mapping'] = mapping
    plan['original_argv_sha256'] = source.sha(source.canonical(original))
    plan['projected_hub'] = {'root':str(published.path/'hub/source'),'files':report['generated_hub']}
    source.require(family.query_tools.verify_repository(family.query.QUERY_REPOSITORY,cutoff) == tools)
    return plan


def actual_directories(output_base):
    root = output_base/'execroot/_main/bazel-out'
    fd = source.directory(root)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                source.tick(); source.require(len(names)<64); names.append(entry.name)
        selected = [name for name in names if re.fullmatch(r'[A-Za-z0-9_.-]+-opt',name)]
        source.require(len(selected)==1)
        return {target:root/selected[0]/'testlogs'/target[2:].replace(':','/') for target in TARGETS}
    finally: os.close(fd)


def native_child(extra,published,sdk,report,retained,inputs,entry,until,cutoff):
    source.require(cutoff == source.DEADLINE and time.monotonic_ns()<entry+600*10**9)
    extra.admit(published,report)
    extra.hub = {name:('100644',raw) for name,raw in published.hub.items()}
    temporary = Path(os.environ['TEST_TMPDIR']).resolve(strict=True)
    held = source.directory(temporary)
    try: source.require(os.fstat(held).st_uid == os.getuid())
    finally: os.close(held)
    work = temporary/'siwc-catalog-native-work'
    plan = native_plan(published,sdk,report,work,cutoff)
    source.require(family.producer_context() == report['producer_context'])
    expected = history_expected_tests() if report['kind'] == history.KIND else expected_tests()
    streams = shared.ChildStreams(work/'driver-streams')
    extra.streams = streams
    try:
        output = published.path.parent/'native-siwc-catalog-models'
        extra.output_path = output
        output.mkdir(mode=0o700)
        extra.output_parent = source.directory(output)
        anchor = family.tenth.witness(os.fstat(extra.output_parent))
        published.capture()
        inputs.check_all(); retained.full(); extra.full(); published.fence(); sdk.fence()
        extra.fence(); retained.fence(); inputs.check(); published.terminal()
        shared.run_once(plan,streams,cutoff)
        directories = actual_directories(work/'output-base')
        accepted, evidence, observations = {}, {}, {}
        for target,role in zip(TARGETS,ROLES):
            directory = directories[target]
            log,log_physical = shared.read_actual(directory/'test.log',extra.evidence)
            xml,xml_physical = shared.read_actual(directory/'test.xml',extra.evidence)
            family.material.declared_xml_success(xml)
            accepted[target] = accept_log(log,expected[target])
            observations[target] = {kind:{'alias':str(directory/name),'path':str(physical),
                'sha256':source.sha(raw),'bytes':len(raw)} for kind,name,physical,raw in (
                    ('test_log','test.log',log_physical,log),('test_xml','test.xml',xml_physical,xml))}
            evidence[role+'-test.log'] = log; evidence[role+'-test.xml'] = xml
        streams_info = {}
        extra.stream_bytes = {}
        for role in ('stdout','stderr'):
            raw = streams.bytes(role)
            extra.stream_bytes[role] = raw
            if raw: extra.evidence.add(streams.path/role,source.sha(raw),shared.MAX_LOG)
            extra.evidence.add_alias(streams.path/role,streams.path/role)
            source.require(extra.evidence.aliases[-1][5] == streams.anchors[role])
            evidence['native-'+role+'.log'] = raw
            streams_info[role] = {'path':str(streams.path/role),'sha256':source.sha(raw),'bytes':len(raw)}
        source.require(family.query_tools.verify_repository(family.query.QUERY_REPOSITORY,cutoff) == plan['qualified_query_tools'])
        result = {'schema_version':1,'kind':KIND,'status':'executed-normal-native-unit-targets-catalog-test-only',
            'targets':list(TARGETS),'actual_libtest':accepted,'target_evidence':observations,'stdout_stderr':streams_info,
            'producer_context':report['producer_context'],'original_entry_monotonic_ns':entry,
            'original_outer_deadline_monotonic_ns':until,'original_proof_deadline_monotonic_ns':entry+600*10**9,
            'selected_catalog_source':extra.row,'selected_source_outer_sha256':extra.row['producer']['sha256'],
            **({'selected_source_delivery':{'kind':delivery.PUBLICATION_KIND,
                'transport_receipt':extra.row['transport_receipt'],'source_phase_receipt':extra.row['source_phase_receipt'],
                'authority':'current-retained-content-and-historical-source-phase-only',
                'original_action_sdk_custody_inherited':False,'source_qualification_extended':False}}
                if extra.selected['status'] in DELIVERY_STATUSES else {}),
            'source':{'receipt_path':str(published.path/'source-receipt.json'),'receipt_sha256':source.sha(published.raw),
                'inventory_sha256':report['inventory_sha256'],'patch_sha256':report['patch_sha256'],'graph_files':report['graph_files']},
            'generated_hub':report['generated_hub'],
            **({'transported_sdk':report['transported_sdk']} if report['kind'] in (content_catalog.KIND, history.KIND)
                else {'original_sdk':report['original_sdk']}),
            'sdk_input_qualification':report['sdk_input_qualification'],'plan':plan,
            'new_catalog_methods_passed':20,'original_v4_methods_passed':15,
            **({'owned_history_methods_passed':25} if report['kind'] == history.KIND else {}),
            'normal_unit_target_regressions_passed':True,'default_cli_binary_qualified':False,
            'native_image_qualified':False,'installed_or_ordinary_native_qualified':False,'provider_qualified':False,
            'retained_evidence':{name:{'path':str(output/name),'sha256':source.sha(raw),'bytes':len(raw)} for name,raw in evidence.items()}}
        row = shared.publish_result(output,result,extra.evidence,prepared=(extra.output_parent,anchor),
            evidence=evidence,_evidence_names=EVIDENCE_NAMES)
        extra.output_anchor = family.tenth.witness(os.fstat(extra.output_parent))
        inputs.check_all(); retained.full(); extra.evidence_full(); sdk.fence(); published.fence(); streams.fence()
        return row
    finally:
        # Original writers remain held by ExtraOwners across final source/SDK IO.
        # The outer context retires all owners on either success or refusal.
        pass


def main():
    source.require(sys.argv == [sys.argv[0]])
    entry, until, cutoff = family.admission()
    source.DEADLINE = family.query.DEADLINE = cutoff
    try:
        context = family.producer_context()
        initial = selection(family.declared(SELECTION,16384))
        results, envelope = [], []
        with ExtraOwners() as extra:
            extra.selected = initial
            extra.source_family, extra.source_guard, unused_target, unused_leaf = SOURCE_ROUTES[initial['status']]
            def execute(*arguments):
                source.require((arguments[5], arguments[6]) == (entry, until)
                    and family.producer_context() == context)
                envelope.append((arguments[5],arguments[6]))
                results.append(native_child(extra,*arguments))
            source.require(family.producer_context() == context)
            extra.source_family.main(_child=execute,_extra=extra,_retainer=extra.retain,
                _admitted=(entry, until, cutoff, source.encoded(context)))
            extra.short()
        source.require(len(results) == len(envelope) == 1 and envelope[0] == (entry, until))
        source.require(time.monotonic_ns()<entry+600*10**9 and time.monotonic_ns()<until)
        print('native-siwc-catalog-models: selected named SIWC methods passed on four normal unit targets; native image unqualified',flush=True)
        source.require(time.monotonic_ns()<entry+600*10**9 and time.monotonic_ns()<until)
    finally:
        source.DEADLINE = family.query.DEADLINE = None


if __name__ == '__main__':
    try: main()
    except shared.REFUSAL_ERRORS:
        print('native SIWC catalog models refused',file=sys.stderr)
        raise SystemExit(1) from None
