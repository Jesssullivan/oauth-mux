"""Guarded carrier plan/query/compiler entry, one original extraction lifetime."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import sys
import time

import codex_native_carrier_material as material
import codex_native_acquisition_preflight as preflight
import codex_native_acquisition_compilation as compilation

PROFILES = {name:'native-sdk-carrier-'+name+'-reserved' for name in ('plan','query','compilation')}


def envelope(mode,environment):
    material.require(mode in PROFILES and environment.get('OMUX_NATIVE_CARRIER_MODE') == PROFILES[mode])
    raw = [environment.get('OMUX_NATIVE_CARRIER_'+name+'_NS') for name in ('ENTRY','DEADLINE')]
    material.require(all(type(value) is str and re.fullmatch('[1-9][0-9]{0,18}',value) is not None for value in raw))
    entry,until = map(int,raw)
    material.metadata.kernel.envelope(entry,until)
    material.metadata.kernel.remaining(entry,until)
    epoch = material.protocol.path(environment.get('OMUX_NATIVE_CARRIER_EPOCH'))
    material.require(material.protocol.UUID.fullmatch(epoch.name) is not None)
    commit = environment.get('OMUX_NATIVE_CARRIER_SOURCE_COMMIT')
    material.require(type(commit) is str and re.fullmatch('[0-9a-f]{40}',commit) is not None)
    material.protocol.pin(environment.get('OMUX_NATIVE_CARRIER_GRAPH_SHA256'))
    return entry,until


def main(mode):
    material.require(len(sys.argv) == 1 and all(os.environ.get(name) for name in
        ('TEST_SRCDIR','TEST_UNDECLARED_OUTPUTS_DIR','TEST_TMPDIR','TEST_TIMEOUT')))
    entry,until = envelope(mode,os.environ)
    configured,config_pin = material.config()
    document = configured['selection']
    material.validate_selection(document)
    runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
    outputs = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    temporary = Path(os.environ['TEST_TMPDIR']).resolve(strict=True)
    saved = (material.source.DEADLINE,material.metadata.legacy.DEADLINE)
    report = raw = output_pin = None
    try:
        with material.query_tools.consumer_phase(entry,until) as phase:
            material.source.DEADLINE = material.metadata.legacy.DEADLINE = phase.query_deadline
            selected_raw = material.binding.ninth.parent.declared(material.metadata.CONFIG,16384)
            # The publisher remains held through Session's final SOURCE/fresh
            # scans; final writer/FD/name checks occur after that long phase.
            with compilation.carrier_outputs(phase.query_deadline):
                with material.session_scope(document,phase.work_deadline,
                        temporary/('native-carrier-'+mode+'-session'),runfiles) as session:
                    if mode == 'compilation':
                        selected = configured['compile']
                        material.require(selected is not None and selected['result'] is None)
                        row = selected['selection']
                        candidate = compilation.selected_document(row['path'],row['sha256'],phase.work_deadline)
                        material.require(candidate['material'] == document)
                        report = compilation.produce(candidate,outputs/'native-acquisition-compilation',phase.work_deadline)
                    else:
                        report = preflight.produce(mode,document,temporary/('native-carrier-'+mode+'-work'),
                            outputs/('native-acquisition-'+mode),phase.work_deadline,material.metadata.legacy.QUERY_REPOSITORY)
                    material.require(material.config()[1] == config_pin)
                    material.tick(session.deadline)
                # Session close performs long proof work. Keep every publisher
                # FD held through final selector reads and report encoding;
                # its exit joins all writer witnesses after this final IO.
                material.require(material.config()[1] == config_pin
                    and material.binding.ninth.parent.declared(material.metadata.CONFIG,16384) == selected_raw)
                material.require(type(report) is dict)
                raw = compilation.encoded(report) if mode == 'compilation' else material.source.encoded(report)
                output_pin = material.source.sha(raw)
                material.tick(phase.query_deadline)
    finally:
        material.source.DEADLINE,material.metadata.legacy.DEADLINE = saved
    material.require(type(raw) is bytes)
    material.tick(phase.query_deadline)
    material.require(time.monotonic_ns() < phase.query_deadline_ns)
    print('omux-native-carrier-'+mode+'-output-sha256='+output_pin,flush=True)
