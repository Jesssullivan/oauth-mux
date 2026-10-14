"""Explicit thirteenth source delta; no compiled/image or historical custody credit."""
import codex_native_siwc_catalog_content_source as content
source, catalog, previous, parent, tenth, binding = (content.source, content.catalog,
    content.previous, content.parent, content.tenth, content.binding)
BASE = 'integrations/codex-upstream/native-owned-history/'
CONTROLS = BASE + 'native-source-controls.json'
COMPOSITION = BASE + 'source-composition.json'
CONTROL_SHA = '9ae90d61ffab78afe467fcc1e9def2c0ada704ab1b458322e4257a1d0b2f9fbd'
PATCH_SHA = '030630425f378832d182333d46d95f8ba183f2de3a04ea34195fb2e9b4c98eb1'
MANIFEST_SHA = 'd1b7bfc9bc81ccbc8672165e301f3000bc42b56a848758ab348f4e97d810b588'
KIND = 'omux-native-siwc-catalog-owned-history-source-v3'
STATUS = 'verified-siwc-catalog-owned-history-source-uncompiled'
PATHS = frozenset(('codex-rs/app-server/src/message_processor.rs', 'codex-rs/app-server/src/owner_control.rs', 'codex-rs/app-server/src/request_processors/thread_processor.rs', 'codex-rs/core/src/codex_thread.rs', 'codex-rs/core/src/native_peer.rs', 'codex-rs/core/src/session/handlers.rs', 'codex-rs/core/src/session/mod.rs', 'codex-rs/core/src/session/session.rs', 'codex-rs/core/src/session/tests.rs', 'codex-rs/core/src/thread_manager.rs'))
OUTPUT = content.OUTPUT


def recipe(raw):
    value = previous.decode(raw)
    source.require(type(value) is dict and set(value) == {'schema_version','kind','recipe'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'omux-native-source-composition-v1'
        and value['recipe'] in ('catalog-twelve-v1','owned-history-thirteen-v3'))
    return value['recipe']


def controls():
    raw = previous.declared(CONTROLS,32768)
    source.require(source.sha(raw) == CONTROL_SHA)
    value = previous.decode(raw)
    source.require(type(value) is dict and set(value) == {'schema_version','kind','status',
        'catalog_controls_sha256','reviewed_native_v3_manifest_sha256','rebased_bridge_manifest_sha256',
        'delta','tests','native_build_graph','capabilities'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'native-owned-history-source-controls-v3'
        and value['status'] == 'DECLARED-DELTA-UNQUALIFIED'
        and value['catalog_controls_sha256'] == catalog.CONTROL_SHA
        and value['reviewed_native_v3_manifest_sha256'] == '9e7ada74ff83b6ca6ae6597b47490b808ddcb4c27c43933456da684955de3e43'
        and value['rebased_bridge_manifest_sha256'] == '9ed6a2efdd6d16aca95c7fb709ef5e5f30013fa6115b585cb46414392f48a05a'
        and set(value['delta']) == {'patch','manifest','paths'} and set(value['delta']['paths']) == PATHS
        and value['native_build_graph'] == catalog.controls()[1]['native_build_graph']
        and value['capabilities'] == catalog.controls()[1]['capabilities']
        and all(flag is False for flag in value['capabilities'].values()))
    return raw,value


def test_contract(control):
    value = previous.decode(parent.pinned_artifact(control['tests']))
    names = value['core_unit_tests'] + value['app_server_unit_tests']
    source.require(value['kind'] == 'owned-history-v3-required-native-methods'
        and value['state'] == 'ALL_UNRUN' and value['new_normal_methods'] == 25
        and len(value['core_unit_tests']) == 20 and len(value['app_server_unit_tests']) == 5
        and len(names) == len(set(names)) == 25 and value['not_compiled_or_executed'] is True
        and value['unfiltered_default_targets'] is True and value['native_targets'] == [
            '//codex-rs/core:core-unit-tests','//codex-rs/tui:tui-unit-tests',
            '//codex-rs/app-server:app-server-unit-tests','//codex-rs/models-manager:models-manager-unit-tests']
        and value['preserve_existing_catalog_methods'] == {'core':30,'tui':4,'app_server':1,'total':35}
        and value['required_combined_named_methods'] == {'core':50,'tui':4,'app_server':6,'models_manager':0,'total':60}
        and value['ignored_child_fixture'] == 'native_peer::tests::peer_lease_process_child')
    return value


def model_patch(control):
    raw = parent.pinned_artifact(control['delta']['patch'])
    manifest = previous.decode(parent.pinned_artifact(control['delta']['manifest']))
    source.require(type(manifest) is dict and set(manifest) == {'schema_version','kind','patch','paths'}
        and manifest['schema_version'] == 1 and manifest['kind'] == 'native-owned-history-ten-path-delta-v3'
        and manifest['patch'] == {'sha256':source.sha(raw),'bytes':len(raw)}
        and source.sha(raw) == PATCH_SHA and control['delta']['manifest']['sha256'] == MANIFEST_SHA
        and manifest['paths'] == [{'path':name,**control['delta']['paths'][name],'logical_mode':'100644'} for name in sorted(PATHS)])
    test_contract(control)
    return raw


def validate_transition(before,after,control):
    tenth.bounded_files(after)
    source.require(set(after) == set(before)
        and {name for name in before if before[name] != after[name]} == PATHS
        and all(before[name] == after[name] for name in before if name not in PATHS))
    for name in PATHS:
        pin = control['delta']['paths'][name]['after']
        source.require(after[name][0] == '100644' and len(after[name][1]) == pin['bytes']
            and source.sha(after[name][1]) == pin['sha256'])
    for name,pin in control['native_build_graph'].items():
        source.require(name in after and name in before and after[name] == before[name] and len(after[name][1]) == pin['bytes']
            and source.sha(after[name][1]) == pin['sha256'])


def transform(before,raw,control):
    tenth.bounded_files(before)
    source.require(type(raw) is bytes and raw.endswith(b'\n') and len(raw) <= source.MAX_PATCH
        and len(raw) == control['delta']['patch']['bytes'] and source.sha(raw) == control['delta']['patch']['sha256'])
    for name in PATHS:
        pin = control['delta']['paths'][name]['before']
        source.require(name in before and before[name][0] == '100644' and len(before[name][1]) == pin['bytes']
            and source.sha(before[name][1]) == pin['sha256'])
    changes = binding.ninth.parent.seventh.status.patch_io.apply_exact(raw.decode('utf-8'),
        {name:before[name][1] for name in PATHS})
    source.require(set(changes) == PATHS)
    after = dict(before)
    for name,raw in changes.items(): after[name] = ('100644',raw)
    validate_transition(before,after,control)
    return after


def compose(before,v4_patch,v4_control):
    intermediate = catalog.compose(before,v4_patch,v4_control)
    control = controls()[1]
    return transform(intermediate,model_patch(control),control)


def validate_report_method(report):
    control = controls()[1]
    source.require(report['kind'] == KIND and report['status'] == STATUS
        and report['native_controls_sha256'] == report['native_owned_history_controls_sha256'] == CONTROL_SHA
        and report['native_catalog_controls_sha256'] == catalog.CONTROL_SHA
        and report['native_v4_controls_sha256'] == catalog.previous.CONTROL_SHA
        and report['native_catalog_v3_manifest_sha256'] == catalog.controls()[1]['native_catalog_v3_manifest_sha256']
        and report['native_delta_manifest_sha256'] == catalog.controls()[1]['delta']['manifest']['sha256']
        and report['native_owned_history_manifest_sha256'] == MANIFEST_SHA
        and report['native_owned_history_test_contract'] == test_contract(control)
        and report['native_owned_history_preimages'] == {name:row['before'] for name,row in control['delta']['paths'].items()}
        and report['native_owned_history_afterimages'] == {name:row['after'] for name,row in control['delta']['paths'].items()}
        and len(report['patch_sha256']) == len(report['patches']) == 13
        and report['patch_sha256'][:10] == content.intake_record()['historical_patch_sha256']
        and report['patch_sha256'][-3:] == [catalog.previous.controls()[1]['delta']['patch']['sha256'],
            catalog.controls()[1]['delta']['patch']['sha256'],PATCH_SHA]
        and report['patch_sha256'][-1] == PATCH_SHA
        and report['patches'][-1] == {'patch_sha256':PATCH_SHA,'paths':sorted(PATHS)}
        and report['source_intake'] == content.intake_record()
        and report['historical_ancestor_reexecution'] is False and report['native_runtime_qualified'] is False)
    for name,pin in report['native_owned_history_afterimages'].items():
        source.require(report['source_inventory'][name] == {'mode':'100644','sha256':pin['sha256']})


def make_report(parent_report,files,v4_control,config,*,hub=None):
    # The same full output inventory is generated by the existing report owner;
    # old V4/catalog ledgers stay ordered provenance, not fresh runtime proof.
    report = content.make_report(parent_report,files,v4_control,config,hub=hub)
    control = controls()[1]; patch = model_patch(control)
    report['kind'],report['status'] = KIND,STATUS
    report['native_catalog_controls_sha256'] = report['native_controls_sha256']
    report['native_controls_sha256'] = report['native_owned_history_controls_sha256'] = CONTROL_SHA
    report['native_owned_history_manifest_sha256'] = MANIFEST_SHA
    report['native_owned_history_preimages'] = {name:row['before'] for name,row in control['delta']['paths'].items()}
    report['native_owned_history_afterimages'] = {name:row['after'] for name,row in control['delta']['paths'].items()}
    report['native_owned_history_test_contract'] = test_contract(control)
    report['patch_sha256'].append(source.sha(patch))
    report['patches'].append({'patch_sha256':source.sha(patch),'paths':sorted(PATHS)})
    validate_report_method(report)
    return report


def retain_controls(owner):
    original = content.retain_controls(owner)
    raw,control = controls(); model_patch(control)
    root = binding.ninth.parent.ROOT
    source.require(owner.add(root/CONTROLS,CONTROL_SHA,32768) == raw)
    for row in (control['delta']['patch'],control['delta']['manifest'],control['tests']):
        owner.add(root/row['path'],row['sha256'],row['bytes'])
    composition = owner.add(root/COMPOSITION,maximum=16384)
    # Recipe selection is retained input, never a qualification flag. A model
    # consumer may regenerate its independently selected history source while
    # the ordinary producer's default recipe remains the historical twelve.
    recipe(composition)
    return original


def retain_selected_controls(owner):
    original = retain_controls(owner)
    raw = owner.add(binding.ninth.parent.ROOT/COMPOSITION,maximum=16384)
    source.require(recipe(raw) == 'owned-history-thirteen-v3')
    return original


def produce(*args,**kwargs):
    return previous.produce(*args,**kwargs,_transform=compose,_report=make_report,
        _source_intake=content.intake.source_intake,_regenerator=content.transported.regenerate,
        _sdk_record=content.transported.record)


def main(*,_child=None,_extra=None,_retainer=None,_admitted=None):
    previous.main(_child=_child,_extra=_extra,_admitted=_admitted,_producer=produce,
        _retainer=retain_selected_controls if _retainer is None else _retainer,
        _input_factory=content.intake.Inputs,_sdk_factory=content.transported.open_sdk,_output=OUTPUT,
        _marker='native-siwc-catalog-owned-history: exact thirteen-patch composition; native image unqualified')
