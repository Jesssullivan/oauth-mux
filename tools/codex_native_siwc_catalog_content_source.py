"""Selected N10 content -> exact V4/catalog delta; no old ancestor reexecution."""
import copy
import sys
import codex_native_siwc_catalog_source as catalog
import codex_native_n10_source_intake as intake

source, parent, tenth, binding = catalog.source, catalog.parent, catalog.tenth, catalog.binding
previous = catalog.previous
CONTROL_SHA = catalog.CONTROL_SHA
KIND = 'omux-native-siwc-catalog-content-source-v1'
STATUS = 'verified-siwc-catalog-content-source-uncompiled'
OUTPUT = 'native-siwc-catalog-content-source'


def intake_record():
    selector_raw, selected = intake.configuration()
    original = tenth.load_config()[1]
    return {'kind': intake.INPUT_KIND, 'method': intake.METHOD,
        'selector_sha256': source.sha(selector_raw), 'selected_N10': copy.deepcopy(selected['parent']),
        'input_kind': tenth.KIND, 'input_inventory_sha256': selected['parent']['inventory_sha256'],
        'input_members': 8553, 'input_source_bytes': 84807456,
        'historical_patch_sha256': original['parent']['patch_sha256'] + [original['storage']['patch_sha256']],
        'historical_ancestor_reexecution': False, 'native_runtime_qualified': False}


def validate_report_method(report):
    source.require(report['kind'] == KIND and report['status'] == STATUS
        and report['source_intake'] == intake_record()
        and report['historical_ancestor_reexecution'] is False
        and report['native_runtime_qualified'] is False)


def make_report(parent_report, files, v4_control, config, *, hub=None):
    record = intake_record()
    source.require(record['selected_N10'] == config['parent']
        and parent_report['kind'] == record['input_kind']
        and parent_report['inventory_sha256'] == record['input_inventory_sha256']
        and parent_report['tracked_files'] == record['input_members']
        and parent_report['source_bytes'] == record['input_source_bytes']
        and parent_report['patch_sha256'] == record['historical_patch_sha256'])
    report = catalog.make_report(parent_report, files, v4_control, config, hub=hub)
    report['kind'], report['status'] = KIND, STATUS
    report['historical_ancestor_reexecution'] = False
    report['native_runtime_qualified'] = False
    report['source_intake'] = record
    validate_report_method(report)
    return report


def retain_controls(owner):
    initial = catalog.retain_controls(owner)
    raw, selected = intake.configuration()
    root = binding.ninth.parent.ROOT
    source.require(owner.add(root / intake.CONFIG, intake.CONFIG_SHA, 16384) == raw)
    # These are static SDK recipe/provenance controls, never an instruction to
    # reopen historical N9/N5 trees. Retain their actual bytes through final IO.
    owner.add(root / binding.CONFIG, maximum=16384)
    owner.add(root / binding.N9_WITNESS, binding.N9_WITNESS_SHA, 16384)
    return initial


def produce(*args, **kwargs):
    return previous.produce(*args, **kwargs, _transform=catalog.compose,
        _report=make_report, _source_intake=intake.source_intake)


def main(*, _child=None, _extra=None, _retainer=None, _admitted=None):
    previous.main(_child=_child, _extra=_extra, _admitted=_admitted, _producer=produce,
        _retainer=retain_controls if _retainer is None else _retainer,
        _input_factory=intake.Inputs, _output=OUTPUT,
        _marker='native-siwc-catalog-content-source: selected N10 bytes plus exact V4/catalog composition; old ancestors not reexecuted')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native SIWC catalog content source refused', file=sys.stderr)
        raise SystemExit(1) from None
