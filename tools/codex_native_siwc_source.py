"""Exact qualified N10 + five-path SIWC native source; compiler/issuer gates stay false."""
import copy
import os
from pathlib import Path
import re
import sys
import time
import threading
import codex_native_file_writer_model_source as parent

source, tenth, binding, protocol, query, query_tools, material = (parent.source, parent.tenth,
    parent.binding, parent.protocol, parent.query, parent.query_tools, parent.material)
Inputs, HeldControls, Publication = parent.Inputs, parent.HeldControls, parent.Publication
parent_source, regenerate, publish_receipt = parent.parent_source, parent.regenerate, parent.publish_receipt
producer_context, declaration_context, admission, declared, decode = (parent.producer_context,
    parent.declaration_context, parent.admission, parent.declared, parent.decode)
CONFIG, CONFIG_SHA = parent.CONFIG, parent.CONFIG_SHA
CONFIGURATION = parent.configuration
BASE = 'integrations/codex-upstream/siwc-native/'
CONTROLS = BASE + 'native-source-controls.json'
CONTROL_SHA = '3b2ab6fd1fafd4deb938c8546b1dd6a996a3d7d542f9391fd63cb4b6b5e7e15b'
KIND = 'omux-native-siwc-source-v1'
OUTPUT = 'native-siwc-source'
TARGET = '//tools:codex_native_siwc_source_producer'
PATHS = frozenset(('codex-rs/core/src/auth_broker.rs', 'codex-rs/core/src/broker_request_profile.rs', 'codex-rs/core/src/broker_request_profile_tests.rs', 'codex-rs/core/src/client.rs', 'codex-rs/core/src/lib.rs'))
NEW = frozenset(('codex-rs/core/src/broker_request_profile.rs', 'codex-rs/core/src/broker_request_profile_tests.rs'))
FALSE_FLAGS = tuple(dict.fromkeys(parent.FALSE_FLAGS + ('native_siwc_ready', 'siwc_issuer_qualified', 'siwc_provider_qualified', 'ordinary_handoff_qualified')))


def configuration():
    raw, value = CONFIGURATION()
    source.require(source.sha(raw) == CONFIG_SHA)
    return raw, value


def controls():
    raw = declared(CONTROLS, 16384)
    source.require(source.sha(raw) == CONTROL_SHA)
    value = decode(raw)
    source.require(type(value) is dict and set(value) == {'schema_version', 'kind', 'status',
        'parent_configuration_sha256', 'native_parent_receipt_sha256', 'native_parent_inventory_sha256',
        'native_v4_manifest_sha256', 'delta', 'tests', 'native_build_graph', 'capabilities'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'native-siwc-source-controls-v1' and value['status'] == 'DECLARED-DELTA-UNQUALIFIED'
        and value['parent_configuration_sha256'] == CONFIG_SHA
        and set(value['delta']) == {'patch', 'manifest', 'paths'} and set(value['delta']['paths']) == PATHS
        and all(flag is False for flag in value['capabilities'].values()))
    config = configuration()[1]
    source.require(value['native_parent_receipt_sha256'] == config['parent']['receipt_sha256']
        and value['native_parent_inventory_sha256'] == config['parent']['inventory_sha256'])
    return raw, value


def model_patch(control):
    raw = parent.pinned_artifact(control['delta']['patch'])
    native = decode(parent.pinned_artifact(control['delta']['manifest']))
    source.require(type(native) is dict and set(native) == {'schema_version', 'kind', 'patch', 'paths'}
        and native['schema_version'] == 1 and native['kind'] == 'native-siwc-five-path-delta-v4'
        and native['patch'] == {'sha256': source.sha(raw), 'bytes': len(raw)}
        and native['paths'] == [{'path': name, **control['delta']['paths'][name], 'logical_mode': '100644'} for name in sorted(PATHS)])
    expected = decode(parent.pinned_artifact(control['tests']))
    source.require(expected['kind'] == 'native-siwc-exact-model-names-v1' and expected['status'] == 'DECLARED-UNRUN'
        and expected['target'] == '//codex-rs/core:core-unit-tests'
        and expected['binary_target'] == '//codex-rs/core:core-unit-tests-bin'
        and expected['default_build_target'] == '//codex-rs/core:core'
        and expected['default_regression_target'] == expected['target']
        and len(expected['expected']) == 15 and len(set(expected['expected'])) == 15
        and all(re.fullmatch(r'(broker_request_profile::tests|auth_broker::tests::unix_transport)::[A-Za-z0-9_]+', name) is not None for name in expected['expected']))
    return raw


def transform(files, raw, control):
    tenth.bounded_files(files)
    row = control['delta']['patch']
    source.require(type(raw) is bytes and len(raw) == row['bytes'] and len(raw) <= source.MAX_PATCH
        and raw.endswith(b'\n') and source.sha(raw) == row['sha256'] and NEW.isdisjoint(files))
    for name in PATHS - NEW:
        pin = control['delta']['paths'][name]['before']
        source.require(name in files and files[name][0] == '100644'
            and len(files[name][1]) == pin['bytes'] and source.sha(files[name][1]) == pin['sha256'])
    # Preserve the reviewed ordinary unified patch exactly; add only closed git
    # framing for the existing exact-context/position parser, including new files.
    lines = raw.decode('utf-8').splitlines(keepends=True)
    framed = []
    for index, line in enumerate(lines):
        if line.startswith('--- '):
            old = line[4:].removesuffix('\n')
            source.require(index + 1 < len(lines) and lines[index + 1].startswith('+++ b/'))
            name = lines[index + 1][6:].removesuffix('\n')
            source.require(name in PATHS and old == ('/dev/null' if name in NEW else 'a/' + name))
            framed.append('diff --git a/' + name + ' b/' + name + '\n')
            if name in NEW: framed.append('new file mode 100644\n')
        framed.append(line)
    changes = binding.ninth.parent.seventh.status.patch_io.apply_exact(''.join(framed),
        {name: files[name][1] for name in PATHS - NEW})
    source.require(set(changes) == PATHS)
    result = dict(files)
    for name, after in changes.items(): result[name] = ('100644', after)
    validate_transition(files, result, control)
    return result


def validate_transition(before, after, control):
    tenth.bounded_files(after)
    source.require(set(after) == set(before) | NEW
        and {name for name in before if before[name] != after[name]} == PATHS - NEW
        and all(before[name] == after[name] for name in before if name not in PATHS))
    for name in PATHS:
        pin = control['delta']['paths'][name]['after']
        source.require(after[name][0] == '100644' and len(after[name][1]) == pin['bytes']
            and source.sha(after[name][1]) == pin['sha256'])
    # Actual native declaration/Cargo locks stay complete and unchanged. Core's
    # existing src glob sees both added modules; no mirrored target is introduced.
    for name, pin in control['native_build_graph'].items():
        source.require(name in after and after[name] == before[name]
            and len(after[name][1]) == pin['bytes'] and source.sha(after[name][1]) == pin['sha256'])


def make_report(parent_report, files, control, config, *, hub=None):
    source.require(parent_report['kind'] == tenth.KIND
        and parent_report['status'] == 'verified-tenth-file-writer-source-uncompiled'
        and parent_report['inventory_sha256'] == config['parent']['inventory_sha256']
        and len(parent_report['patch_sha256']) == 10 and all(parent_report[name] is False for name in tenth.FLAGS))
    inventory = binding.ninth.parent.seventh.status.inventory(files)
    graph = set(parent_report['graph_files']) | set(control['native_build_graph'])
    return {'schema_version': 1, 'kind': KIND, 'status': 'verified-siwc-source-uncompiled',
        'commit': source.COMMIT, 'qualified_parent': config['parent'], 'native_controls_sha256': CONTROL_SHA,
        'native_delta_manifest_sha256': control['delta']['manifest']['sha256'],
        'native_v4_manifest_sha256': control['native_v4_manifest_sha256'],
        'patch_sha256': parent_report['patch_sha256'] + [control['delta']['patch']['sha256']],
        'patches': parent_report['patches'] + [{'patch_sha256': control['delta']['patch']['sha256'], 'paths': sorted(PATHS)}],
        'native_preimages': {name: row['before'] for name, row in control['delta']['paths'].items()},
        'native_afterimages': {name: row['after'] for name, row in control['delta']['paths'].items()},
        'source_inventory': inventory, 'inventory_sha256': source.sha(source.canonical(inventory)),
        'tracked_files': len(files), 'source_bytes': sum(len(raw) for mode, raw in files.values()),
        'graph_files': {name: {'sha256': source.sha(files[name][1])} for name in sorted(graph)},
        'native_test_contract': decode(parent.pinned_artifact(control['tests'])),
        'source_materialized': True, 'native_siwc_source_present': True,
        'physical_mode_policy': 'bazel-retained-export-all-regular-and-directories-0555-v1',
        'generated_hub': None if hub is None else {name: {'sha256': source.sha(raw), 'bytes': len(raw)} for name, raw in sorted(hub.items())},
        **{name: False for name in FALSE_FLAGS}}


def retain_model_controls(owner):
    raw_config, config = configuration(); raw_control, control = controls()
    root = binding.ninth.parent.ROOT
    for name, pin, maximum in [(CONFIG, CONFIG_SHA, 16384), (CONTROLS, CONTROL_SHA, 16384)] + [
        (row['path'], row['sha256'], row['bytes']) for row in
        (control['delta']['patch'], control['delta']['manifest'], control['tests'])]:
        owner.add(root / name, pin, maximum)
    return (raw_config, config), (raw_control, control)


def produce(output, inputs, work, publication, *, sdk_session=None, query_repository=None, context=None, sdk_qualification=None, _transform=None, _report=None, _source_intake=None, _regenerator=None, _sdk_record=None):
    """Called with one admitted cutoff; caller retains SDK/publication owners to final acceptance."""
    intake_source = parent_source if _source_intake is None else _source_intake
    transform_source = transform if _transform is None else _transform
    report_source = make_report if _report is None else _report
    regenerate_source = regenerate if _regenerator is None else _regenerator
    source.require(callable(intake_source) and callable(transform_source) and callable(report_source) and callable(regenerate_source)
        and (_sdk_record is None or callable(_sdk_record)))
    raw_config, config = configuration()
    raw_control, control = controls()
    patch = model_patch(control)
    output_fd = receipt_fd = tree = None
    transferred = False
    try:
        with intake_source(config, inputs, publication.parents) as (proof, captured, ancestors, before, parent_report):
            files = transform_source(before, patch, control)
            output_fd = source.write_source(output, files)
            hub = plan = tools = None
            if sdk_session is not None:
                hub, plan, tools = regenerate_source(files, sdk_session, work, output, query_repository)
                fd = source.write_source(output / 'hub', {name: ('100644', raw) for name, raw in hub.items()})
                try: os.fchmod(fd, 0o555)
                finally: os.close(fd)
            report = report_source(parent_report, files, control, config, hub=hub)
            if context is not None: report['producer_context'] = copy.deepcopy(context)
            if hub is not None:
                source.require(type(sdk_qualification) is dict and set(sdk_qualification) == {
                    'selector_sha256', 'selection', 'qualified_producer', 'declaration', 'proof_inputs'})
                report['sdk_input_qualification'] = copy.deepcopy(sdk_qualification)
                report['hub_query_plan'] = plan
                if _sdk_record is None:
                    report['original_sdk'] = {'root': str(query.EXPORT_ROOT), 'receipt_sha256': query.EXPORT_SHA,
                        'mapping': sdk_session.mapping(), 'custody': 'fresh-declared-original-sdk-content-v1',
                        'declaration_sha256': source.sha(sdk_session.catalogue.raw),
                        'declaration_context': declaration_context(context),
                        'carrier_receipt_sha256': sdk_session.carrier_pin, 'complete_members': len(sdk_session.expected)}
                else:
                    report['transported_sdk'] = _sdk_record(sdk_session)
                report['query_tool_closure'] = tools
            raw_report = source.encoded(report)
            receipt_fd, receipt_anchor = publish_receipt(output_fd, raw_report)
            os.fsync(output_fd)
            output_anchor = tenth.witness(os.fstat(output_fd))
            members = {'source/' + name: row for name, row in files.items()}
            if hub is not None: members.update({'hub/source/' + name: ('100644', raw) for name, raw in hub.items()})
            members['source-receipt.json'] = ('100644', raw_report)
            tree = tenth.TreeWitness(output, members, root_mode=0o700, receipt_name='source-receipt.json')
            source.verify_written(output / 'source', files)
            if hub is not None: source.verify_written(output / 'hub/source', {name: ('100644', raw) for name, raw in hub.items()})
            source.require(configuration() == (raw_config, config) and controls() == (raw_control, control)
                and model_patch(control) == patch)
            source.verify_written(output / 'source', files)
            if hub is not None: source.verify_written(output / 'hub/source', {name: ('100644', raw) for name, raw in hub.items()})
            again, mode = source.read(output_fd, 'source-receipt.json', source.MAX_METADATA)
            source.require(again == raw_report and mode == 0o444
                and tenth.witness(os.fstat(receipt_fd)) == receipt_anchor)
            tree.check()
        # All final parent full IO, guardians and descriptor closes precede this fence.
        source.require(configuration() == (raw_config, config) and controls() == (raw_control, control)
            and model_patch(control) == patch)
        inputs.check()
        os.fchmod(output_fd, 0o555)
        tree.accept_root_seal(output_anchor, tenth.witness(os.fstat(output_fd)))
        tree.check()
        publication.bind(output, output_fd, receipt_fd, receipt_anchor, tree, files, hub, raw_report)
        transferred = True
        return report
    finally:
        error = None
        for owner in (() if transferred else (tree,)):
            if owner is not None:
                try: owner.close()
                except BaseException as failure:
                    if error is None: error = failure
        for fd in (() if transferred else (receipt_fd, output_fd)):
            if fd is not None:
                try: os.close(fd)
                except BaseException as failure:
                    if error is None: error = failure
        if error is not None: raise error



class _SourcePhaseObserver:
    """Ten fixed scalar diagnostics; never proof, clock or resource authority."""
    stages = ('controller-entry', 'controls-complete', 'inputs-complete',
        'carrier-proofs-complete', 'producer-qualified', 'transported-entry',
        'held-leaves-open', 'initial-binding-complete', 'declaration-joined',
        'extraction-dispatch')

    def __init__(self, entry, until, cutoff):
        source.require(type(entry) is int and type(until) is int and entry > 0
            and until-entry == 1200*10**9 and cutoff == (entry+600*10**9)/10**9
            and source.DEADLINE == cutoff)
        self.entry, self.until, self.cutoff = entry, until, cutoff
        self.owner = None
        self.count = 0
        self.pid, self.thread = os.getpid(), threading.get_ident()

    def bind(self, owner):
        source.require(self.owner is None and type(owner) is HeldControls)
        self.owner = owner
        owner._source_phase_observer = self

    def emit(self, stage):
        source.require(type(stage) is str and self.count < len(self.stages)
            and stage == self.stages[self.count] and os.getpid() == self.pid
            and threading.get_ident() == self.thread and source.DEADLINE == self.cutoff)
        source.tick()
        now = time.monotonic_ns()
        source.require(self.entry <= now < self.entry+600*10**9 and now < self.until)
        elapsed = now-self.entry
        remaining = self.entry+600*10**9-now
        line = ('native-source-budget: phase='+stage+' elapsed_ns='+str(elapsed)
            +' remaining_ns='+str(remaining))
        source.require(len(line.encode('ascii')) <= 160)
        # Diagnostics have no unwind callback and cannot replace a pending body
        # error. Actual write/flush refusal propagates through existing cleanup.
        print(line, file=sys.stderr, flush=True)
        source.tick()
        source.require(time.monotonic_ns() < self.entry+600*10**9
            and time.monotonic_ns() < self.until)
        self.count += 1


def main(*, _producer=None, _retainer=None, _child=None, _extra=None, _input_factory=None, _admitted=None, _sdk_factory=None, _output=OUTPUT, _marker="native-siwc-source: exact five-path source composition"):
    # Only pinned source-family modules supply these callables; no runtime flag
    # or request claims source qualification. Defaults retain the original route.
    input_factory = Inputs if _input_factory is None else _input_factory
    produce_source = produce if _producer is None else _producer
    retain_source = retain_model_controls if _retainer is None else _retainer
    source.require(callable(input_factory) and callable(produce_source) and callable(retain_source)
        and (_child is None or callable(_child)) and ((_child is None) == (_extra is None))
        and _output in (OUTPUT, "native-siwc-catalog-source", "native-siwc-catalog-content-source")
        and type(_marker) is str and (_sdk_factory is None or callable(_sdk_factory)))
    source.require(sys.argv in ([sys.argv[0]], [sys.argv[0], '--source-only']))
    source_only = len(sys.argv) == 2
    source.require(not source_only or _child is None)
    entry, until, cutoff = admission() if _admitted is None else parent.reuse_admission(_admitted)
    if _admitted is None: source.DEADLINE = query.DEADLINE = cutoff
    sdk_session = None
    try:
        source.tick()
        observer = _SourcePhaseObserver(entry, until, cutoff) if not source_only and _sdk_factory is not None else None
        if observer is not None: observer.emit('controller-entry')
        runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
        output = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
        with Publication() as published:
            with HeldControls() as retained:
                if observer is not None: observer.bind(retained)
                mapping = retained.add(runfiles / '_repo_mapping', maximum=1024*1024)
                rows = [row.split(',') for row in mapping.decode().splitlines()]
                source.require(all(len(row) == 3 for row in rows))
                initial_config, initial_control = retain_source(retained)
                initial_context = producer_context()
                if observer is not None: observer.emit('controls-complete')
                with input_factory(runfiles, rows) as inputs:
                    if observer is not None: observer.emit('inputs-complete')
                    if not source_only:
                        import codex_original_sdk_inputs as original_sdk
                        import codex_native_carrier_metadata as metadata
                        with metadata.proof_scope(cutoff):
                            selected_raw = retained.add(binding.ninth.parent.ROOT / metadata.CONFIG, maximum=16384)
                            selected = metadata.selection(selected_raw)
                            root, aliases, declaration = metadata.declared_carrier(runfiles, rows, selected, cutoff)
                            for alias, physical in aliases: retained.add_alias(alias, physical)
                            proofs = metadata.declared_proofs(runfiles, rows, selected, cutoff)
                            retained.add(proofs.aliases[0][0], proofs.sha256, 65536)
                            captured_proofs = retained.carrier_proofs(selected, proofs, cutoff)
                            material.declared_xml_success(captured_proofs['test_xml'])
                            retained.add(Path(declaration['selection_path']), declaration['selection_sha256'], 8192)
                            if observer is not None: observer.emit('carrier-proofs-complete')
                            qualified = metadata.qualify_producer(selected, cutoff, proofs)
                            if observer is not None: observer.emit('producer-qualified')
                            if _sdk_factory is None:
                                manifest_alias, manifest = original_sdk.declared_manifest(runfiles, rows)
                                sdk_session = original_sdk.HeldOriginalSDK(manifest_alias, manifest, root,
                                    selected['carrier']['receipt_sha256'], entry, until, declaration_context(initial_context))
                            else:
                                sdk_session = _sdk_factory(root, selected['carrier']['receipt_sha256'], entry, until,
                                    declaration_context(initial_context), aliases, declaration, retained)
                            sdk_session.__enter__()
                            query.declared_query_tools(runfiles, rows)
                            report = produce_source(output / _output, inputs, output / 'model-hub-work', published,
                                sdk_session=sdk_session, query_repository=query.QUERY_REPOSITORY, context=initial_context,
                                sdk_qualification={'selector_sha256': source.sha(selected_raw), 'selection': selected,
                                    'qualified_producer': qualified, 'declaration': declaration, 'proof_inputs': proofs.record()})
                            if _child is not None:
                                _child(published, sdk_session, report, retained, inputs, entry, until, cutoff)
                            if not published.members_captured: published.capture()
                            # All owners span the last full source/output/carrier/original reads.
                            published.full()
                            if _extra is not None: _extra.full()
                            sdk_session.finish()
                            source.require(metadata.qualify_producer(selected, cutoff, proofs) == qualified)
                            metadata.recheck_aliases(aliases, cutoff); proofs.recheck(cutoff)
                            source.require(declared(metadata.CONFIG, 16384) == selected_raw)
                            source.require(configuration() == initial_config and controls() == initial_control
                                and producer_context() == initial_context)
                            retained.full(); inputs.check_all()
                            if _extra is not None: _extra.evidence_full()
                            # One same-held terminal observation phase. Full byte/NAR
                            # work precedes all physical-only namespace/FD/root joins.
                            published.fence(); sdk_session.fence()
                            retained.fence(); inputs.check(); published.roots()
                            sdk_session.__exit__(None, None, None)
                            sdk_session = None
                            retained.fence(); inputs.check(); published.roots()
                    else:
                        produce_source(output / _output, inputs, output / 'unused-work', published, context=initial_context)
                        published.capture()
                        published.full()
                        source.require(configuration() == initial_config and controls() == initial_control
                            and producer_context() == initial_context)
                        retained.full(); inputs.check_all(); published.fence()
                        retained.fence(); inputs.check(); published.roots()
                    if _extra is not None: _extra.fence()
                    # SDK bulk walks and normal SDK close have completed. Every
                    # SOURCE/output member now joins its original witness via
                    # retained parents while all proof/control/alias owners live.
                    retained.fence(); inputs.check()
                    published.terminal()
                    if _extra is not None: _extra.short()
                    retained.fence(); inputs.check(); published.roots()
                # Input close performs no full SOURCE/SDK work. Retain captured
                # controls and publication descriptors through that cleanup.
                retained.fence(); published.roots()
            published.roots()
        source.tick()
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
        print(_marker +
            (' and complete HUB regeneration' if not source_only else '') + '; compilation unqualified', flush=True)
        source.tick()
        source.require(time.monotonic_ns() < entry + 600*10**9 and time.monotonic_ns() < until)
    finally:
        try:
            if sdk_session is not None: sdk_session.__exit__(*sys.exc_info())
        finally:
            if _admitted is None: source.DEADLINE = query.DEADLINE = None


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
        print('native SIWC source refused', file=sys.stderr)
        raise SystemExit(1) from None
