"""Distinct retained-tree SDK input route; unchanged selected native source delta.

This controller does not change the historical transported source family. A
successful source report would prove only its exact declared source predicates;
no compilation/image/native/runtime or SDK execution authority is inherited.
"""
import os
from pathlib import Path
import sys
import time

import codex_native_siwc_catalog_content_source as content
import codex_native_owned_history_source as history
import codex_retained_sdk_tree_reader as retained_sdk

previous = content.previous
source, query = previous.source, previous.query
Inputs, HeldControls, Publication = previous.Inputs, previous.HeldControls, previous.Publication
parent, producer_context, declaration_context = previous.parent, previous.producer_context, previous.declaration_context
admission, configuration, controls = previous.admission, previous.configuration, previous.controls
OUTPUT = "native-siwc-catalog-tree-source"
TARGET = "//tools:codex_native_siwc_catalog_tree_source_producer"


def selected_recipe():
    return history.recipe(previous.declared(history.COMPOSITION, 16384))


def retain_controls(owner):
    choice = selected_recipe()
    return history.retain_selected_controls(owner) if choice == "owned-history-thirteen-v3" else content.retain_controls(owner)


def produce(*args, **kwargs):
    choice = selected_recipe()
    transform = history.compose if choice == "owned-history-thirteen-v3" else content.catalog.compose
    report = history.make_report if choice == "owned-history-thirteen-v3" else content.make_report
    return previous.produce(*args, **kwargs, _transform=transform, _report=report,
        _source_intake=content.intake.source_intake, _regenerator=retained_sdk.regenerate,
        _sdk_record=retained_sdk.record)


def main(*, _producer=None, _retainer=None, _child=None, _extra=None, _input_factory=None, _admitted=None, _output=OUTPUT, _marker="native-siwc-catalog-tree-source: current retained SDK plus exact native composition"):
    # Only pinned source-family modules supply these callables; no runtime flag
    # or request claims source qualification. This distinct default requires tree proof.
    input_factory = content.intake.Inputs if _input_factory is None else _input_factory
    produce_source = produce if _producer is None else _producer
    retain_source = retain_controls if _retainer is None else _retainer
    source.require(callable(input_factory) and callable(produce_source) and callable(retain_source)
        and (_child is None or callable(_child)) and ((_child is None) == (_extra is None))
        and _output == OUTPUT
        and type(_marker) is str)
    source.require(sys.argv == [sys.argv[0]])
    source_only = False
    source.require(not source_only or _child is None)
    entry, until, cutoff = admission() if _admitted is None else parent.reuse_admission(_admitted)
    if _admitted is None: source.DEADLINE = query.DEADLINE = cutoff
    sdk_session = None
    try:
        source.tick()
        observer = previous._SourcePhaseObserver(entry, until, cutoff)
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
                        import codex_native_carrier_metadata as metadata
                        with metadata.proof_scope(cutoff):
                            # The new typed manifest/proof owner replaces the flat
                            # SDK DATA branch only in this distinct controller.
                            sdk_session = retained_sdk.open_declared(runfiles, rows, entry, until,
                                declaration_context(initial_context), retained)
                            sdk_session.__enter__()
                            query.declared_query_tools(runfiles, rows)
                            report = produce_source(output / _output, inputs, output / 'model-hub-work', published,
                                sdk_session=sdk_session, query_repository=query.QUERY_REPOSITORY, context=initial_context,
                                sdk_qualification=sdk_session.qualification_record())
                            if _child is not None:
                                _child(published, sdk_session, report, retained, inputs, entry, until, cutoff)
                            if not published.members_captured: published.capture()
                            # All owners span the last full SOURCE and current-tree reads.
                            published.full()
                            if _extra is not None: _extra.full()
                            sdk_session.finish()
                            # finish() already reread all creator metadata before
                            # its last current-tree proof. Only small physical
                            # fences occur after that last complete scan.
                            sdk_session.fence()
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


def entrypoint():
    try: main()
    except content.REFUSAL_ERRORS as error:
        # Existing bounded locus projection remains a diagnostic, never proof.
        try: print(content.refusal_diagnostic(error), file=sys.stderr)
        finally: raise SystemExit(1) from None


if __name__ == "__main__": entrypoint()
