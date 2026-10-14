"""Pinned N10 + reviewed V4 + catalog V3, complete HUB; no native execution proof."""
import copy
import sys
import codex_native_siwc_source as previous
source, parent, tenth, binding = previous.source, previous.parent, previous.tenth, previous.binding
BASE = 'integrations/codex-upstream/siwc-native-catalog/'
CONTROLS = BASE + 'native-source-controls.json'
CONTROL_SHA = '1e1ca67e3a7e5e061da1a5d5e6636767295ed579c5c83846b5a165075f39ddab'
KIND = 'omux-native-siwc-catalog-source-v1'
PATHS = frozenset(('codex-rs/app-server/src/config_manager.rs', 'codex-rs/app-server/src/config_manager_provider_tests.rs', 'codex-rs/app-server/src/model_catalog.rs', 'codex-rs/core/src/auth_broker.rs', 'codex-rs/core/src/broker_model_catalog.rs', 'codex-rs/core/src/broker_model_catalog_tests.rs', 'codex-rs/core/src/client.rs', 'codex-rs/core/src/lib.rs', 'codex-rs/core/src/session/mod.rs', 'codex-rs/core/src/thread_manager.rs', 'codex-rs/models-manager/src/manager.rs', 'codex-rs/tui/src/app_server_session.rs', 'codex-rs/tui/src/app_server_session/rollout_history.rs', 'codex-rs/tui/src/lib.rs'))
NEW = frozenset(('codex-rs/core/src/broker_model_catalog.rs', 'codex-rs/core/src/broker_model_catalog_tests.rs'))


def controls():
    raw = previous.declared(CONTROLS, 32768)
    source.require(source.sha(raw) == CONTROL_SHA)
    value = previous.decode(raw)
    source.require(type(value) is dict and set(value) == {'schema_version', 'kind', 'status',
        'parent_configuration_sha256', 'v4_controls_sha256', 'native_catalog_v3_manifest_sha256',
        'delta', 'tests', 'native_build_graph', 'capabilities'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'native-siwc-catalog-source-controls-v1'
        and value['status'] == 'DECLARED-DELTA-UNQUALIFIED'
        and value['parent_configuration_sha256'] == previous.CONFIG_SHA
        and value['v4_controls_sha256'] == previous.CONTROL_SHA
        and set(value['delta']) == {'patch', 'manifest', 'paths'}
        and set(value['delta']['paths']) == PATHS
        and value['native_build_graph'] == previous.controls()[1]['native_build_graph']
        and value['capabilities'] == previous.controls()[1]['capabilities']
        and all(flag is False for flag in value['capabilities'].values()))
    return raw, value


def model_patch(control):
    raw = parent.pinned_artifact(control['delta']['patch'])
    manifest = previous.decode(parent.pinned_artifact(control['delta']['manifest']))
    source.require(type(manifest) is dict and set(manifest) == {'schema_version', 'kind', 'patch', 'paths'}
        and manifest['schema_version'] == 1 and manifest['kind'] == 'native-siwc-catalog-fourteen-path-delta-v3'
        and manifest['patch'] == {'sha256': source.sha(raw), 'bytes': len(raw)}
        and manifest['paths'] == [{'path': name, **control['delta']['paths'][name], 'logical_mode': '100644'} for name in sorted(PATHS)])
    expected = previous.decode(parent.pinned_artifact(control['tests']))
    names = expected['core_unit_tests'] + expected['tui_unit_tests'] + expected['app_server_unit_tests']
    source.require(expected['status'] == 'ALL_UNRUN' and expected['new_methods'] == 20
        and len(names) == len(set(names)) == 20
        and len(expected['core_unit_tests']) == 15 and len(expected['tui_unit_tests']) == 4
        and len(expected['app_server_unit_tests']) == 1
        and expected['native_targets'] == ['//codex-rs/core:core-unit-tests', '//codex-rs/tui:tui-unit-tests',
            '//codex-rs/models-manager:models-manager-unit-tests', '//codex-rs/app-server:app-server-unit-tests']
        and expected['no_mirrored_harness_or_filtered_compile'] is True)
    return raw


def transform(before, raw, control):
    tenth.bounded_files(before)
    source.require(type(raw) is bytes and raw.endswith(b'\n')
        and len(raw) == control['delta']['patch']['bytes'] and len(raw) <= source.MAX_PATCH
        and source.sha(raw) == control['delta']['patch']['sha256'] and NEW.isdisjoint(before))
    for name in PATHS - NEW:
        pin = control['delta']['paths'][name]['before']
        source.require(name in before and before[name][0] == '100644'
            and len(before[name][1]) == pin['bytes'] and source.sha(before[name][1]) == pin['sha256'])
    # This reviewed successor already has exact git/new-file framing. Reuse the
    # maintained exact-context parser; never synthesize preimages or skip hunks.
    changes = binding.ninth.parent.seventh.status.patch_io.apply_exact(raw.decode('utf-8'),
        {name: before[name][1] for name in PATHS - NEW})
    source.require(set(changes) == PATHS)
    after = dict(before)
    for name, value in changes.items(): after[name] = ('100644', value)
    validate_transition(before, after, control)
    return after


def validate_transition(before, after, control):
    tenth.bounded_files(after)
    source.require(set(after) == set(before) | NEW
        and {name for name in before if before[name] != after[name]} == PATHS - NEW
        and all(before[name] == after[name] for name in before if name not in PATHS))
    for name in PATHS:
        pin = control['delta']['paths'][name]['after']
        source.require(after[name][0] == '100644' and len(after[name][1]) == pin['bytes']
            and source.sha(after[name][1]) == pin['sha256'])
    for name, pin in control['native_build_graph'].items():
        source.require(name in after and after[name] == before[name]
            and len(after[name][1]) == pin['bytes'] and source.sha(after[name][1]) == pin['sha256'])


def compose(before, v4_patch, v4_control):
    intermediate = previous.transform(before, v4_patch, v4_control)
    control = controls()[1]
    return transform(intermediate, model_patch(control), control)


def make_report(parent_report, files, v4_control, config, *, hub=None):
    control = controls()[1]
    patch = model_patch(control)
    report = previous.make_report(parent_report, files, v4_control, config, hub=hub)
    report['kind'] = KIND
    report['status'] = 'verified-siwc-catalog-source-uncompiled'
    report['native_v4_controls_sha256'] = report['native_controls_sha256']
    report['native_controls_sha256'] = CONTROL_SHA
    report['native_catalog_v3_manifest_sha256'] = control['native_catalog_v3_manifest_sha256']
    report['native_v4_preimages'] = report['native_preimages']
    report['native_v4_afterimages'] = report['native_afterimages']
    report['native_preimages'] = {name: row['before'] for name, row in control['delta']['paths'].items()}
    report['native_afterimages'] = {name: row['after'] for name, row in control['delta']['paths'].items()}
    report['native_delta_manifest_sha256'] = control['delta']['manifest']['sha256']
    report['patch_sha256'].append(source.sha(patch))
    report['patches'].append({'patch_sha256': source.sha(patch), 'paths': sorted(PATHS)})
    report['native_v4_test_contract'] = report['native_test_contract']
    report['native_test_contract'] = previous.decode(parent.pinned_artifact(control['tests']))
    report['native_catalog_source_present'] = True
    return report


def retain_controls(owner):
    original = previous.retain_model_controls(owner)
    raw, control = controls()
    model_patch(control)
    root = binding.ninth.parent.ROOT
    owner.add(root / CONTROLS, CONTROL_SHA, 32768)
    for row in (control['delta']['patch'], control['delta']['manifest'], control['tests']):
        owner.add(root / row['path'], row['sha256'], row['bytes'])
    return original


def produce(*args, **kwargs):
    # The retained parent implementation owns every source/output/proof lifetime,
    # complete HUB/SDK pass, terminal flat member join and original clock.
    return previous.produce(*args, **kwargs, _transform=compose, _report=make_report)


def main(*, _child=None, _extra=None, _retainer=None, _admitted=None):
    previous.main(_child=_child, _extra=_extra, _admitted=_admitted, _producer=produce, _retainer=retain_controls if _retainer is None else _retainer,
        _output='native-siwc-catalog-source',
        _marker='native-siwc-catalog-source: exact V4 plus fourteen-path catalog composition')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native SIWC catalog source refused', file=sys.stderr)
        raise SystemExit(1) from None
