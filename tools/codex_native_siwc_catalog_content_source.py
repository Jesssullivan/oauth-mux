"""Selected N10 content -> exact V4/catalog delta; no old ancestor reexecution."""
import copy
import codex_transported_sdk_inputs as transported
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
        _report=make_report, _source_intake=intake.source_intake,
        _regenerator=transported.regenerate, _sdk_record=transported.record)


def main(*, _child=None, _extra=None, _retainer=None, _admitted=None):
    previous.main(_child=_child, _extra=_extra, _admitted=_admitted, _producer=produce,
        _retainer=retain_controls if _retainer is None else _retainer,
        _input_factory=intake.Inputs, _sdk_factory=transported.open_sdk, _output=OUTPUT,
        _marker='native-siwc-catalog-content-source: selected N10 bytes plus exact V4/catalog composition; old ancestors not reexecuted')


REFUSAL_ERRORS = (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError, MemoryError)
MAX_TRACE_SCAN = 32
MAX_TRACE_ROWS = 8
MAX_SOURCE_LINE = 65535
MAX_DIAGNOSTIC_BYTES = 512
ALLOWED_ERRNOS = frozenset((1, 2, 5, 9, 12, 13, 17, 20, 21, 22, 24, 28, 30, 40, 110))


def refusal_diagnostic(error):
    # Module dictionary identity supplies closed roles. Never inspect traceback
    # filenames/function names, frame locals, namespace contents or exception text.
    roles = (('content-controller', sys.modules[__name__]), ('content-inputs', intake),
        ('catalog-transform', catalog), ('siwc-controller', previous),
        ('file-writer-custody', parent), ('n10-custody', tenth),
        ('binding-custody', binding), ('source-io', source),
        ('carrier-metadata', sys.modules.get('codex_native_carrier_metadata')),
        ('sdk-inputs', sys.modules.get('codex_original_sdk_inputs')),
        ('sdk-transported', transported),
        ('query', parent.query), ('query-tools', parent.query_tools),
        ('material', parent.material), ('sdk-carrier', parent.carrier),
        ('protocol', parent.protocol), ('parent-guard', parent.parent_guard))
    category = 'unknown'
    for kind, value in ((UnicodeError, 'UnicodeError'), (ValueError, 'ValueError'),
            (OSError, 'OSError'), (KeyError, 'KeyError'), (TypeError, 'TypeError'), (IndexError, 'IndexError'),
            (MemoryError, 'MemoryError')):
        if isinstance(error, kind): category = value; break
    number = 0
    if isinstance(error, OSError):
        # The built-in descriptor bypasses subclass attribute hooks. Only this
        # closed numeric errno set is allowed; filenames/strerror are untouched.
        raw = OSError.errno.__get__(error)
        if type(raw) is int and raw in ALLOWED_ERRNOS: number = raw
    rows, scanned, omitted = [], 0, False
    trace = BaseException.__traceback__.__get__(error)
    while trace is not None and scanned < MAX_TRACE_SCAN:
        role, line = 'unknown', 0
        for name, module in roles:
            if module is not None and trace.tb_frame.f_globals is vars(module):
                role = name
                if type(trace.tb_lineno) is int and 0 < trace.tb_lineno <= MAX_SOURCE_LINE:
                    line = trace.tb_lineno
                break
        if len(rows) == MAX_TRACE_ROWS: rows.pop(0); omitted = True
        rows.append(role + ':' + str(line))
        scanned += 1
        trace = trace.tb_next
    if trace is not None: omitted = True
    if not rows: rows.append('unknown:0')
    return ('native SIWC catalog content source refused; class=' + category +
        '; errno=' + str(number) + '; locus=' + ','.join(rows) +
        '; truncated=' + ('1' if omitted else '0'))


def entrypoint():
    try: main()
    except REFUSAL_ERRORS as error:
        try: print(refusal_diagnostic(error), file=sys.stderr)
        finally:
            # Advisory diagnostic failure cannot replace the original exit code.
            raise SystemExit(1) from None


if __name__ == '__main__': entrypoint()
