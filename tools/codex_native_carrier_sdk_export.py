"""Genuine SDK-v2 projection producer, full carrier proof with compact output.

This action verifies complete carrier SDK/JDK bytes and SOURCE ancestry. Output
is the regenerated HUB/graph and authenticated lineage, not a substituted SDK.
"""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_native_carrier_material as material
import codex_native_carrier_metadata as metadata
import codex_native_sdk_carrier as carrier
import codex_native_acquisition_binding as binding
import codex_protocol_history_query_tools as query_tools
import codex_retained_sdk_export as sdk

source = binding.source
require = material.require
TARGET = material.SDK_TARGET
PROFILE = material.SDK_PROFILE
OUTPUT = 'native-carrier-sdk-export'


def envelope(environment):
    require(environment.get('OMUX_NATIVE_CARRIER_MODE') == PROFILE)
    raw = [environment.get('OMUX_NATIVE_CARRIER_' + name + '_NS') for name in ('ENTRY','DEADLINE')]
    require(all(type(value) is str and metadata.re.fullmatch('[1-9][0-9]{0,18}',value) is not None for value in raw))
    entry,until = map(int,raw)
    require(until-entry == 1200*10**9)
    metadata.kernel.remaining(entry,until)
    epoch = metadata.protocol.path(environment.get('OMUX_NATIVE_CARRIER_EPOCH'))
    require(metadata.protocol.UUID.fullmatch(epoch.name) is not None)
    commit,graph = [environment.get('OMUX_NATIVE_CARRIER_' + name) for name in ('SOURCE_COMMIT','GRAPH_SHA256')]
    require(type(commit) is str and metadata.re.fullmatch('[0-9a-f]{40}',commit) is not None)
    metadata.protocol.pin(graph)
    query_ns = entry + 600*10**9
    require(time.monotonic_ns() < query_ns)
    return entry,until,float(query_ns/10**9)


def mapped_members(values,logical_modes=None):
    rows = {}
    for name,raw in values.items():
        carrier.relative(name)
        require(type(raw) is bytes and len(raw) <= material.MAX_DOCUMENT)
        mode = '100644' if logical_modes is None else logical_modes[name]
        require(mode in ('100644','100755'))
        rows[name] = {'sha256':source.sha(raw),'bytes':len(raw),'mode':mode}
    return material.member_map(rows)


def write_members(output,role,values,rows):
    """Every internal parent is tracked; no path-based chmod or generic extract."""
    output.mkdir(role); parents = {role}
    for name,raw in sorted(values.items()):
        output.clock.tick(); parts = (role + '/' + name).split('/')
        for length in range(2,len(parts)):
            parent = '/'.join(parts[:length])
            if parent not in parents: output.mkdir(parent); parents.add(parent)
        parent,leaf = output.root.parent('/'.join(parts))
        try:
            fd = os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            try:
                carrier.write_all(fd,raw,output.clock); os.fsync(fd)
                os.fchmod(fd,0o555 if rows[name]['mode'] == '100755' else 0o444)
                witness = carrier.identity(os.fstat(fd))
                require(witness == carrier.identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False)))
                output.materialized['/'.join(parts)] = witness
            finally: os.close(fd)
        finally: os.close(parent)
    for name in sorted(parents,key=lambda value:(-value.count('/'),value)): output.seal_directory(name)
    output.root.check()


def metadata_program(selected,inputs,deadline):
    row = selected['program']; meta_root = Path(row['path']).parent
    outer = material.legacy.producer_success({'root':str(meta_root),'producer':selected['producer']},
        material.METADATA_TARGET,'native-sdk-carrier-metadata',deadline,declared=inputs)
    raw = inputs.read(row['path'],row['sha256'],deadline)
    require(len(raw) == row['bytes'])
    report = json.loads(raw,object_pairs_hook=source.unique)
    require(type(report) is dict and set(report) == metadata.OUTPUT_FIELDS
        and type(report.get('schema_version')) is int and report['schema_version'] == 2
        and report['kind'] == metadata.OUTPUT_KIND and report['original_selection'] == binding.selected_document()
        and report['status'] == 'verified-fresh-carrier-custody-regenerated-native-acquisition-hub'
        and type(report['query_exit']) is int and report['query_exit'] == 0
        and report['query_tool_closure_independently_rechecked'] is True
        and report['source_and_extracted_carrier_rechecked'] is True
        and report['module_and_cargo_lock_unchanged'] is True
        and all(report[name] is False for name in metadata.FALSE_FLAGS))
    reservation = outer['native_acquisition_inputs_reservation']
    require(report['consumer_context'] == {'mode':metadata.PROFILE,'epoch':str(Path(selected['producer']['receipt']).parent),
        'source_commit':selected['producer']['source_commit'],'graph_sha256':selected['producer']['graph_sha256'],
        'entry_monotonic_ns':reservation['original_entry_monotonic_ns'],
        'deadline_monotonic_ns':reservation['original_deadline_monotonic_ns']})
    material.output_marker(inputs.role('metadata/test-log.evidence'),
        'omux-native-carrier-metadata-output-sha256=',row['sha256'])
    return report


def produce(configuration,inputs,carrier_root,aliases,declaration,seal_inputs,selected_carrier,temporary,output,deadline,*,_publication_stack=None):
    material.tick(deadline)
    require(_publication_stack is None or type(_publication_stack) is ExitStack)
    require(configuration['selection'] is None and configuration['compile'] is None and configuration['metadata'] is not None)
    selected = configuration['metadata']; material.program(selected)
    initial_metadata = metadata_program(selected,inputs,deadline)
    pin = selected_carrier['carrier']['receipt_sha256']
    require(metadata._SCOPE.get() == deadline)
    with ExitStack() as stack:
        source_proof = stack.enter_context(binding.SourceProofSession(binding.config()))
        source_proof.initial_report()
        source_report = copy.deepcopy(source_proof.source_report); files = dict(source_proof.source_files)
        parent = copy.deepcopy(source_proof.baseline)
        hold = stack.enter_context(carrier.Root(carrier_root,carrier.Clock(deadline)))
        origin = carrier.validate_binding(carrier_root,pin,deadline); metadata.origin_join(origin)
        seal = metadata.qualify_producer(selected_carrier,deadline,seal_inputs)
        material.seal_marker(seal_inputs,seal['report'],deadline)
        metadata.recheck_declaration(declaration,seal,carrier_root,pin,deadline)
        require(initial_metadata['carrier']['receipt_sha256'] == pin
            and initial_metadata['carrier']['origin'] == origin['origin']
            and initial_metadata['carrier']['producer_context'] == origin['producer_context']
            and initial_metadata['carrier']['qualification'] == seal
            and initial_metadata['source_inventory_sha256'] == source_report['inventory_sha256']
            and initial_metadata['source_graph'] == source_report['graph_files']
            and initial_metadata['patch_sha256'] == source_report['patch_sha256'])
        require(not temporary.exists() and not output.exists())
        temporary_hold = stack.enter_context(material.private_child(temporary,carrier.Clock(deadline)))
        extracted = temporary/'extracted'
        extraction = carrier.extract(carrier_root,pin,extracted,deadline)
        extraction_pin = carrier.sha(carrier.encoded(extraction))
        fresh = {role:stack.enter_context(carrier.Root(extracted/role,carrier.Clock(deadline))) for role in ('sdk','jdk')}
        fresh_custody = material.FreshCustody(hold,origin,extraction,fresh,carrier.Clock(deadline))
        stack.callback(fresh_custody.close)
        exported = sdk.validate_export(extracted/'sdk',metadata.legacy.EXPORT_SHA,source.BASE_INVENTORY,
            parent['baseline_graph_files'],on_read=lambda count:material.tick(deadline))
        previous = metadata.legacy.read_hub(extracted/'sdk/repositories'/metadata.legacy.metadata.HUB)
        hub = {}
        require(type(initial_metadata['generated_hub']) is list and 0 < len(initial_metadata['generated_hub']) <= 16)
        for row in initial_metadata['generated_hub']:
            require(type(row) is dict and set(row) == {'path','sha256'} and '/' not in row['path'] and row['path'] not in hub)
            raw = inputs.role('metadata/hub/' + row['path'])
            require(source.sha(raw) == row['sha256']); hub[row['path']] = raw
        binding.verify_hub_delta(previous,hub)
        graph = {name:files[name][1] for name in sdk.GRAPH}
        hub_rows = mapped_members(hub)
        graph_rows = mapped_members(graph,{name:files[name][0] for name in sdk.GRAPH})
        for name,row in graph_rows.items(): require(row['sha256'] == source_report['graph_files'][name]['sha256'])
        authority = {'schema_version':2,'kind':material.CORE_KIND,'source':copy.deepcopy(binding.config()['source']),
            'original_selection':copy.deepcopy(binding.selected_document()),
            'carrier_files':[{'name':row['name'],'sha256':row['sha256'],'bytes':row['size']} for row in seal['report']['files']],
            'seal':{'producer':copy.deepcopy(selected_carrier['qualification']['producer']),
                'program':{'path':selected_carrier['qualification']['report']['path'],
                    'sha256':selected_carrier['qualification']['report']['sha256'],
                    'bytes':len(carrier.encoded(seal['report']))}},
            'metadata':copy.deepcopy(selected),'hub_inventory_sha256':source.sha(carrier.encoded(hub_rows)),
            'graph_inventory_sha256':source.sha(carrier.encoded(graph_rows))}
        material.core(authority); authority_raw = carrier.encoded(authority)
        authority_pin = source.sha(authority_raw)
        report = {**authority,'kind':material.SDK_KIND,'status':'verified-carrier-sdk-projection-with-fresh-custody',
            'authority_sha256':authority_pin,'inventory_sha256':authority_pin,'hub_files':hub_rows,'graph_files':graph_rows,
            'mapping_sha256':graph_rows['MODULE.bazel.lock']['sha256'],'patch_sha256':source_report['patch_sha256'],
            'sdk_export_qualified':True,'source_and_carrier_rechecked':True,**{name:False for name in material.FALSE_FLAGS}}
        material.report_shape(report,authority_raw)
        published = material.ProjectionOutput(output,carrier.Clock(deadline))
        (stack if _publication_stack is None else _publication_stack).callback(published.close)
        write_members(published,'hub',hub,hub_rows); write_members(published,'graph',graph,graph_rows)
        published.file('authority.json',authority_raw)
        require(material.projection_read(published.root,report,published.clock,complete=False) == {'hub':hub,'graph':graph})
        require(metadata_program(selected,inputs,deadline) == initial_metadata)
        for name,held in source_proof.snapshots:
            held.recheck()
            if name == 'seventh': source_proof.join_n5(held)
            if name == 'ninth': source_proof.join_n9(held)
        require(metadata.qualify_producer(selected_carrier,deadline,seal_inputs) == seal)
        require(sdk.validate_export(extracted/'sdk',metadata.legacy.EXPORT_SHA,source.BASE_INVENTORY,
            parent['baseline_graph_files'],on_read=lambda count:material.tick(deadline)) == exported)
        query = query_tools.verify_repository(metadata.legacy.QUERY_REPOSITORY,deadline)
        require(query['status'] == 'declared-fixed-query-tools-byte-qualified')
        require(query['inputs_rechecked'] is True)
        require(carrier.validate_binding(carrier_root,pin,deadline) == origin)
        require(carrier.revalidate_extraction(carrier_root,pin,extracted,deadline,
            pinned_extraction_receipt_sha256=extraction_pin) == extraction)
        metadata.recheck_aliases(aliases,deadline); inputs.recheck()
        published.file('sdk-receipt.json',carrier.encoded(report)); published.finish()
        require(material.projection_read(published.root,report,published.clock) == {'hub':hub,'graph':graph})
        require(carrier.read(published.root,'authority.json',material.MAX_DOCUMENT,authority_pin) == authority_raw)
        require(carrier.read(published.root,'sdk-receipt.json',material.MAX_DOCUMENT) == carrier.encoded(report))
        # Last long carrier pass precedes fresh final scan, not the reverse.
        require(carrier.revalidate_extraction(carrier_root,pin,extracted,deadline,
            pinned_extraction_receipt_sha256=extraction_pin) == extraction)
        source_proof.finish()
        require(carrier.revalidate_extraction(carrier_root,pin,extracted,deadline,
            pinned_extraction_receipt_sha256=extraction_pin) == extraction)
        for name,held in source_proof.snapshots:
            held.recheck()
            if name == 'seventh': source_proof.join_n5(held)
            if name == 'ninth': source_proof.join_n9(held)
        require(material.projection_read(published.root,report,published.clock) == {'hub':hub,'graph':graph})
        inputs.recheck(); hold.check(); temporary_hold.check(); published.root.check()
        fresh_custody.check()
        for root in fresh.values(): root.check()
        material.tick(deadline)
        return report if _publication_stack is None else (report,published)


def publication_names(published,report):
    """Complete cheap namespace fence after every potentially long body read."""
    root,clock = published.root,published.clock
    root.check()
    carrier.names(root.fd,{'hub','graph','authority.json','sdk-receipt.json'},clock)
    for role in ('hub','graph'):
        children = {role:set()}
        for name in report[role+'_files']:
            clock.tick(); parts = (role+'/'+name).split('/')
            for index in range(1,len(parts)):
                children.setdefault('/'.join(parts[:index]),set()).add(parts[index])
        for parent,expected in children.items():
            fd,_ = root.parent(parent+'/selected-entry')
            try:
                require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o555)
                carrier.names(fd,expected,clock)
            finally:os.close(fd)
    root.check()


def readback_publication(published,report,raw,deadline):
    """Join actual original writer custody after the final selector/encoding IO."""
    require(type(published) is material.ProjectionOutput and published.clock.deadline == deadline)
    material.tick(deadline)
    authority = carrier.read(published.root,'authority.json',material.MAX_DOCUMENT,report['authority_sha256'])
    material.report_shape(report,authority)
    material.projection_read(published.root,report,published.clock)
    require(carrier.read(published.root,'sdk-receipt.json',material.MAX_DOCUMENT) == raw)
    publication_names(published,report)
    material.tick(deadline)


def main():
    os.umask(0o077)
    require(len(sys.argv) == 1 and all(os.environ.get(name) for name in
        ('TEST_SRCDIR','TEST_UNDECLARED_OUTPUTS_DIR','TEST_TMPDIR','TEST_TIMEOUT')))
    _,_,deadline = envelope(os.environ)
    with metadata.proof_scope(deadline):
        configuration,config_pin = material.config()
        require(configuration['metadata'] is not None)
        selected_raw = binding.ninth.parent.declared(metadata.CONFIG,16384)
        selected = metadata.selection(selected_raw)
        runfiles = Path(os.environ['TEST_SRCDIR']).resolve(strict=True)
        raw = (runfiles/'_repo_mapping').read_bytes(); require(len(raw) <= 1024*1024)
        rows = [line.split(',') for line in raw.decode().splitlines()]
        require(metadata.legacy.declared_query_tools(runfiles,rows) is True)
        initial_query = query_tools.verify_repository(metadata.legacy.QUERY_REPOSITORY,deadline)
        require(initial_query['status'] == 'declared-fixed-query-tools-byte-qualified')
        require(initial_query['inputs_rechecked'] is True)
        root,aliases,declaration = metadata.declared_carrier(runfiles,rows,selected,deadline)
        proofs = metadata.declared_proofs(runfiles,rows,selected,deadline)
        with ExitStack() as publication_stack:
            with material.DeclaredInputs(runfiles,rows,deadline,stage='metadata') as inputs:
                report,published = produce(configuration,inputs,root,aliases,declaration,proofs,selected,
                    Path(os.environ['TEST_TMPDIR']).resolve(strict=True)/'native-carrier-sdk-work',
                    Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)/OUTPUT,deadline,
                    _publication_stack=publication_stack)
                require(material.config()[1] == config_pin)
                require(binding.ninth.parent.declared(metadata.CONFIG,16384) == selected_raw)
                raw = carrier.encoded(report)
                output_pin = carrier.sha(raw)
                material.tick(deadline)
            # Declared-input cleanup also precedes the last original output fence.
            readback_publication(published,report,raw,deadline)
    material.tick(deadline)
    print('omux-native-carrier-sdk-output-sha256=' + output_pin,flush=True)


if __name__ == '__main__': main()
