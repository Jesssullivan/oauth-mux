"""Declared evaluation deployment staging; Nix/Home Manager owns activation.

This producer preserves genuine package-action authority and selected bytes. It
does not create a guardian, install an application, or authorize credentials.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

TARGET = '//tools:codex_native_acquisition_runtime_package'
CARRIER_TARGET = '//tools:codex_native_carrier_runtime_package'
OUTPUTS = ('fresh-native-runtime.tar.gz','runtime-manifest.json','runtime-receipt.json',
           'registration-receipt.json','package-selection.json')
MARKER = re.compile(rb'^omux-native-package-output-sha256=([0-9a-f]{64})$',re.M)
MAX_DECLARATION = 64*1024
CARRIER_PACKAGE = 'omux-native-carrier-native-package-selection-v2'
MAX_RETAINED_BYTES = 512*1024*1024
MAX_RETAINED_ROWS = 4096

def require(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def closed_json(raw):
    def pairs(values):
        result = {}
        for name,value in values:
            require(name not in result,'deployment duplicate JSON field')
            result[name] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs)

def package_producer_target(root):
    # Candidate namespace chooses one verifier, never an authority fallback.
    # producer_success must authenticate the actual outer target and this root.
    suffix = '/testlogs/tools/codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime'
    return CARRIER_TARGET if str(root).endswith(suffix) else TARGET

def carrier_evidence_members(members, outer):
    """Collector names identify source/config/target, never content hashes."""
    require(type(members) is list and 2 <= len(members) <= 4,'carrier bounded evidence index')
    selected, seen = {}, set()
    for row in members:
        require(type(row) is dict and row.get('source') not in seen,'carrier unique evidence source')
        seen.add(row['source'])
        if row['source'] in ('test.log','test.xml'):
            require(set(row) == {'source','state','file','sha256','bytes'} and row['state'] == 'copied'
                and type(row['file']) is str and re.fullmatch('[0-9a-f]{64}\\.evidence',row['file'])
                and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
                and type(row['bytes']) is int and 0 < row['bytes'] <= 16*1024*1024,
                'carrier required copied log/XML')
            require(row['file'] not in selected,'carrier distinct copied log/XML identities')
            selected[row['file']] = {'path':str(Path(outer).parent/'test-evidence'/row['file']),
                'sha256':row['sha256'],'bytes':row['bytes']}
        else:
            require(row['source'] in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS'),
                'carrier bounded diagnostic source')
            if row.get('state') == 'missing':
                require(set(row) == {'source','state','bytes'} and type(row['bytes']) is int
                    and row['bytes'] == 0,'carrier missing diagnostic shape')
            else:
                require(set(row) == {'source','state','file','sha256','bytes'} and row['state'] == 'copied'
                    and type(row['file']) is str and re.fullmatch('[0-9a-f]{64}\\.evidence',row['file'])
                    and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
                    and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024*1024,
                    'carrier copied diagnostic shape')
    require({'test.log','test.xml'} <= seen and len(selected) == 2,'carrier both required proofs')
    return selected

def carrier_retention_plan(selection, root, inventory, inventory_raw, outer_row, evidence_row, package_members):
    """Compute all aliases and controls before creating any retained output."""
    rows = []
    lengths = {}
    def retain(row):
        require(type(row) is dict and set(row) == {'path','sha256','bytes'}
            and type(row['path']) is str and Path(row['path']).is_absolute()
            and str(Path(row['path'])) == row['path'] and '..' not in Path(row['path']).parts
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
            and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_RETAINED_BYTES,
            'carrier compact retained row')
        name = 'inputs/'+row['sha256']
        require(name not in lengths or lengths[name] == row['bytes'],'carrier conflicting digest length')
        lengths[name] = row['bytes']; rows.append(row)
        return {'path':name,'sha256':row['sha256'],'bytes':row['bytes']}
    def maps(values):
        return [{'name':name,**retain(row)} for name,row in sorted(values.items())]
    def authority(group):
        return {'outer':retain(group['outer']),'evidence':retain(group['evidence']),'members':maps(group['members'])}
    package_rows = {name:retain({'path':str(root/name),**inventory['files'][name]}) for name in OUTPUTS}
    compact = selection['carrier_materials']
    require(type(compact) is dict and set(compact) == {'schema_version','kind','authority_sha256',
        'carrier_files','projection','receipts','authorities'} and type(compact['schema_version']) is int
        and compact['schema_version'] == 2 and compact['kind'] == 'omux-native-carrier-retained-authority-v2'
        and set(compact['receipts']) == {'authority_document','carrier_receipt','seal_program','metadata_program'}
        and set(compact['authorities']) == {'seal','metadata'},'carrier closed compact authority')
    require(compact['receipts']['authority_document']['sha256'] == compact['authority_sha256']
        and compact['projection']['inventory_sha256'] == compact['authority_sha256']
        and compact['receipts']['metadata_program'] == selection['files']['sdk_metadata'],
        'carrier actual raw authority identity')
    declaration = {'schema_version':2,'kind':'omux-native-source-acquisition-deployment-v1',
        'target':'x86_64-linux','launch_profile':'linux_nix_direct_main_v1',
        'inputs':{'archive':package_rows[OUTPUTS[0]],'manifest':package_rows[OUTPUTS[1]],
            'runtime_receipt':package_rows[OUTPUTS[2]],'registration_receipt':package_rows[OUTPUTS[3]],
            'source_receipt':retain(selection['files']['source']),'producer_receipt':retain(outer_row)},
        'modern_materials':{'package_selection':package_rows[OUTPUTS[4]],
            'package_outputs':retain({'path':str(root/'package-outputs.json'),
                'sha256':hashlib.sha256(inventory_raw).hexdigest(),'bytes':len(inventory_raw)}),
            'package_output_root':str(root),'roles':{name:retain(row) for name,row in selection['files'].items()},
            'protocol_schema_files':maps(selection['protocol_schema_files']),
            'native_acquisition_artifact_files':maps(selection['native_acquisition_artifact_files']),
            'authority_receipts':{name:authority(group) for name,group in selection['authority_receipts'].items()},
            'package_authority':authority({'outer':outer_row,'evidence':evidence_row,'members':package_members}),
            'carrier_materials':{'receipts':{name:retain(row) for name,row in compact['receipts'].items()},
                'authorities':{name:authority(group) for name,group in compact['authorities'].items()}}}}
    raw = encoded(declaration)
    require(len(raw) <= MAX_DECLARATION and len(rows)+1 <= MAX_RETAINED_ROWS
        and sum(lengths.values())+len(raw) <= MAX_RETAINED_BYTES,
        'carrier retention includes aliases and declaration before creation')
    return declaration,raw,rows

def stage_carrier(selection, root, inventory, inventory_raw, selected_package, receipt,
                  evidence_raw, members, destination, deadline):
    outer = Path(selected_package['producer']['receipt'])
    outer_raw = bounded_read(outer,16*1024*1024,deadline)
    outer_row = {'path':str(outer),'sha256':selected_package['producer']['sha256'],'bytes':len(outer_raw)}
    require(hashlib.sha256(outer_raw).hexdigest() == outer_row['sha256'],'carrier outer readback')
    evidence_row = {'path':str(outer.parent/'test-evidence.json'),
        'sha256':receipt['test_evidence']['sha256'],'bytes':len(evidence_raw)}
    package_members = carrier_evidence_members(members,outer)
    declaration,raw,rows = carrier_retention_plan(selection,root,inventory,inventory_raw,outer_row,evidence_row,package_members)
    # The genuine PACKAGE already authenticated full transport/fresh SDK data.
    # Retention reads only these compact rows, never a carrier tuple filename.
    def authenticate(row):
        require(time.monotonic() < deadline,'carrier original retention deadline')
        path = Path(row['path'])
        require(path.lstat().st_mode & 0o222 == 0,'carrier immutable retained source')
        value = bounded_read(path,row['bytes'],deadline)
        require(len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'],
            'carrier retained raw byte authority')
        return value
    # Raw authority bytes and the inert four-member tuple remain authenticated;
    # no tuple name is resolved into an ambient transport path.
    compact = selection['carrier_materials']
    core_raw = authenticate(compact['receipts']['authority_document'])
    core = closed_json(core_raw)
    require(type(core) is dict and set(core) == {'schema_version','kind','source','original_selection',
        'carrier_files','seal','metadata','hub_inventory_sha256','graph_inventory_sha256'}
        and type(core['schema_version']) is int and core['schema_version'] == 2
        and core['kind'] == 'omux-native-carrier-sdk-authority-core-v2'
        and core['carrier_files'] == compact['carrier_files'], 'carrier raw core tuple identity')
    carrier_raw = authenticate(compact['receipts']['carrier_receipt'])
    carrier = closed_json(carrier_raw)
    expected_tuple = [
        {'name':'manifest.json','sha256':carrier['manifest_sha256'],'bytes':carrier['manifest_bytes']},
        {'name':'origin-receipt.json','sha256':carrier['origin']['receipt_sha256'],'bytes':carrier['origin']['receipt_bytes']},
        {'name':'payload.bin','sha256':carrier['payload_sha256'],'bytes':carrier['payload_bytes']},
        {'name':'receipt.json','sha256':hashlib.sha256(carrier_raw).hexdigest(),'bytes':len(carrier_raw)}]
    require(compact['carrier_files'] == expected_tuple,'carrier authenticated inert transport tuple')
    # Check installed report family against the actual selected raw PACKAGE.
    reports = []
    for name in ('runtime-manifest.json','runtime-receipt.json'):
        report = closed_json(authenticate({'path':str(root/name),**inventory['files'][name]}))
        require(report.get('kind') == 'omux-native-source-acquisition-fresh-native-package-v1'
            and report.get('chain',{}).get('material_family') == 'native-carrier-acquisition-evaluation-v2'
            and report.get('native_support') is False and report.get('provider_evaluation') is False,
            'carrier installed report family/unsupported flags')
        require(report.get('selection_sha256') == inventory['files']['package-selection.json']['sha256'],
            'carrier report actual PACKAGE selection hash')
        require(report.get('producer_target') == CARRIER_TARGET,'carrier exact package producer target')
        reports.append(report)
    require(reports[0]['chain'] == reports[1]['chain'],'carrier manifest/runtime chain equality')
    destination = Path(destination)
    require(time.monotonic() < deadline,'carrier deadline before retention')
    destination.mkdir(mode=0o700); (destination/'inputs').mkdir(mode=0o700)
    copied = set()
    for row in rows:
        value = authenticate(row)
        name = 'inputs/'+row['sha256']
        if name in copied:
            require(bounded_read(destination/name,row['bytes'],deadline) == value,'carrier retained alias drift')
        else:
            with (destination/name).open('xb') as stream:
                stream.write(value); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(),0o444)
            copied.add(name)
    # Full original and retained readback after the last potentially long copy.
    for row in rows:
        require(bounded_read(destination/('inputs/'+row['sha256']),row['bytes'],deadline) == authenticate(row),
            'carrier final compact readback')
    require(time.monotonic() < deadline,'carrier final original deadline')
    target = destination/'share/omux/native/codex'
    target.mkdir(parents=True,mode=0o700)
    with (target/'deployment.json').open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(),0o444)
    require(bounded_read(target/'deployment.json',MAX_DECLARATION,deadline) == raw,'carrier declaration readback')
    for row in rows:
        require(bounded_read(destination/('inputs/'+row['sha256']),row['bytes'],deadline) == authenticate(row),
            'carrier post-publication compact readback')
    require(time.monotonic() < deadline,'carrier original deadline after final authentication')
    return declaration

def bounded_read(path, maximum, deadline):
    path=Path(path)
    require(path.is_absolute() and str(path.resolve(strict=True))==str(path),'deployment physical metadata path')
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,'deployment bounded metadata leaf')
    values,size=[],0
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as stream:
        require(os.fstat(stream.fileno()).st_dev==before.st_dev and os.fstat(stream.fileno()).st_ino==before.st_ino,'deployment metadata opened identity')
        while True:
            require(time.monotonic()<deadline,'deployment original deadline')
            raw=stream.read(65536)
            if not raw:break
            size+=len(raw)
            require(size<=maximum and size<=before.st_size,'deployment metadata growth')
            values.append(raw)
        after=os.fstat(stream.fileno())
    witness=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    require(size==before.st_size and witness(before)==witness(after)==witness(path.lstat()),'deployment metadata drift')
    return b''.join(values)

def closed_inventory(raw, log):
    require(len(raw) <= MAX_DECLARATION and len(log) <= 16*1024*1024,'deployment inventory/log bound')
    def pairs(values):
        result = {}
        for key,value in values:
            require(key not in result,'deployment duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw,object_pairs_hook=pairs)
    require(set(value)=={'schema_version','kind','purpose','acquisitionContract','files'}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['kind']=='omux-native-acquisition-package-output-v1'
        and value['purpose']=='evaluation-only' and value['acquisitionContract']=='unsupported'
        and set(value['files'])==set(OUTPUTS),'deployment exact package output inventory')
    for name,row in value['files'].items():
        require(type(row) is dict and set(row)=={'sha256','bytes'}
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
            and type(row['bytes']) is int and 0 < row['bytes'] <= (256*1024*1024 if name.endswith('.tar.gz') else 16*1024*1024),
            'deployment bounded package output row')
    markers = MARKER.findall(log)
    # Any marker-like line which is not the one exact closed record also refuses.
    lines = [line for line in log.splitlines() if b'omux-native-package-output-sha256=' in line]
    require(len(markers)==len(lines)==1 and lines[0]==b'omux-native-package-output-sha256='+markers[0]
        and markers[0].decode()==hashlib.sha256(raw).hexdigest(),'deployment genuine package log inventory hash')
    return value

def stage(recipe, destination, deadline):
    """Caller supplies a declared selected package producer pin, never wire DTOs.

    All authority is checked by the real guarded-action verifier before output
    staging. The destination must be new; caller/Nix owns failed-output cleanup.
    """
    import codex_native_acquisition_material as material
    require(type(recipe) is dict and set(recipe)=={'schema_version','kind','package'}
        and type(recipe['schema_version']) is int and recipe['schema_version']==1 and recipe['kind']=='omux-native-acquisition-deployment-input-v1',
        'deployment exact selected recipe')
    selected_package = recipe['package']
    require(type(selected_package) is dict and set(selected_package)=={'root','producer'},'deployment exact package origin')
    target = package_producer_target(selected_package['root'])
    receipt = material.producer_success(selected_package,target,'fresh-native-runtime',deadline)
    root = Path(selected_package['root'])
    require(time.monotonic()<deadline,'deployment original deadline')
    outer = Path(selected_package['producer']['receipt'])
    evidence_raw = bounded_read(outer.parent/'test-evidence.json',16*1024*1024,deadline)
    require(hashlib.sha256(evidence_raw).hexdigest()==receipt['test_evidence']['sha256'],'deployment evidence pin drift')
    evidence = json.loads(evidence_raw)
    results = [row for row in evidence['results'] if row['target']==target]
    require(len(results)==1,'deployment exact package evidence target')
    members = results[0]['files']
    logs = [row for row in members if row['source']=='test.log' and row['state']=='copied']
    require(len(logs)==1,'deployment exact preserved package log')
    log_row = logs[0]
    require(re.fullmatch('[0-9a-f]{64}\\.evidence',log_row['file']),'deployment package log leaf')
    log = bounded_read(outer.parent/'test-evidence'/log_row['file'],16*1024*1024,deadline)
    require(len(log)==log_row['bytes'] and hashlib.sha256(log).hexdigest()==log_row['sha256'],'deployment package log pin drift')
    inventory_raw = bounded_read(root/'package-outputs.json',MAX_DECLARATION,deadline)
    inventory = closed_inventory(inventory_raw,log)
    # V1 below remains the existing retention branch. The new family preflights
    # all compact rows and generated declaration before output creation.
    selected_raw = bounded_read(root/'package-selection.json',16*1024*1024,deadline)
    selected = json.loads(selected_raw)
    if selected.get('kind') == CARRIER_PACKAGE:
        require(target == CARRIER_TARGET,'carrier PACKAGE requires distinct genuine producer')
        selected = closed_json(selected_raw)
        require(len(selected_raw) == inventory['files']['package-selection.json']['bytes']
            and hashlib.sha256(selected_raw).hexdigest() == inventory['files']['package-selection.json']['sha256'],
            'carrier actual selected PACKAGE bytes')
        material.validate_paths(selected)
        return stage_carrier(selected,root,inventory,inventory_raw,selected_package,receipt,
            evidence_raw,members,destination,deadline)
    require(target == TARGET,'legacy PACKAGE cannot inherit carrier producer')
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    inputs_dir = destination/'inputs'
    inputs_dir.mkdir(mode=0o700)
    total, count = 0, 0
    copied = {}
    def copy_row(row):
        nonlocal total,count
        require(type(row) is dict and set(row)=={'path','sha256','bytes'}
            and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row['bytes']) is int
            and 0 < row['bytes'] <= 512*1024*1024,'deployment actual input row')
        require(time.monotonic()<deadline,'deployment original deadline')
        source = Path(row['path'])
        require(source.is_absolute() and str(source.resolve(strict=True))==str(source),'deployment physical selected input')
        before = source.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o222==0 and before.st_size==row['bytes'],
                'deployment immutable selected input')
        name = 'inputs/'+row['sha256']
        previous = copied.get(name)
        require(previous is None or previous==row['bytes'],'deployment conflicting digest length')
        require(previous is not None or total+row['bytes'] <= 512*1024*1024,
                'deployment finite copied bytes before creation')
        count += 1
        require(count <= 4096,'deployment finite selected row count')
        hasher, size = hashlib.sha256(), 0
        sink = None if previous is not None else (destination/name).open('xb')
        try:
            with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as stream:
                require(os.fstat(stream.fileno()).st_ino==before.st_ino and os.fstat(stream.fileno()).st_dev==before.st_dev,
                        'deployment selected opened identity')
                while True:
                    require(time.monotonic()<deadline,'deployment original deadline')
                    raw = stream.read(65536)
                    if not raw:
                        break
                    size += len(raw)
                    require(size <= row['bytes'],'deployment selected input growth')
                    hasher.update(raw)
                    if sink is not None:
                        sink.write(raw)
                after = os.fstat(stream.fileno())
            named = source.lstat()
            witness = lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            require(witness(before)==witness(after)==witness(named) and size==row['bytes']
                and hasher.hexdigest()==row['sha256'],'deployment selected byte or identity drift')
            if sink is not None:
                sink.flush();os.fsync(sink.fileno());os.fchmod(sink.fileno(),0o444)
                total += size
                require(total <= 512*1024*1024,'deployment finite copied bytes')
                copied[name] = size
        finally:
            if sink is not None:
                sink.close()
        return {'path':name,'sha256':row['sha256'],'bytes':row['bytes']}
    package_rows = {name:copy_row({'path':str(root/name),**inventory['files'][name]}) for name in OUTPUTS}
    selection_raw = bounded_read(root/'package-selection.json',16*1024*1024,deadline)
    require(hashlib.sha256(selection_raw).hexdigest()==inventory['files']['package-selection.json']['sha256']
        and len(selection_raw)==inventory['files']['package-selection.json']['bytes'],'deployment full selection drift')
    selection = json.loads(selection_raw)
    material.validate_paths(selection)
    # Complete selected raw document is retained. A summary cannot replace it.
    def maps(values):
        return [{'name':name,**copy_row(row)} for name,row in sorted(values.items())]
    def authority(group):
        return {'outer':copy_row(group['outer']),'evidence':copy_row(group['evidence']),
                'members':maps(group['members'])}
    package_members = {}
    for member in members:
        require(member['source'] in ('test.log','test.xml') and member['state']=='copied'
            and re.fullmatch('[0-9a-f]{64}\\.evidence',member['file']),'deployment package evidence exact members')
        package_members[member['file']]={'path':str(outer.parent/'test-evidence'/member['file']),
            'sha256':member['sha256'],'bytes':member['bytes']}
    require(len(package_members)==2,'deployment two distinct package evidence members')
    outer_row={'path':str(outer),'sha256':selected_package['producer']['sha256'],'bytes':outer.stat().st_size}
    declaration={'schema_version':2,'kind':'omux-native-source-acquisition-deployment-v1',
        'target':'x86_64-linux','launch_profile':'linux_nix_direct_main_v1',
        'inputs':{'archive':package_rows[OUTPUTS[0]],'manifest':package_rows[OUTPUTS[1]],
            'runtime_receipt':package_rows[OUTPUTS[2]],'registration_receipt':package_rows[OUTPUTS[3]],
            'source_receipt':copy_row(selection['files']['source']),'producer_receipt':copy_row(outer_row)},
        'modern_materials':{'package_selection':package_rows[OUTPUTS[4]],
            'package_outputs':copy_row({'path':str(root/'package-outputs.json'),'sha256':hashlib.sha256(inventory_raw).hexdigest(),'bytes':len(inventory_raw)}),
            'package_output_root':str(root),'roles':{name:copy_row(row) for name,row in selection['files'].items()},
            'protocol_schema_files':maps(selection['protocol_schema_files']),
            'native_acquisition_artifact_files':maps(selection['native_acquisition_artifact_files']),
            'authority_receipts':{name:authority(group) for name,group in selection['authority_receipts'].items()},
            'package_authority':authority({'outer':outer_row,
                'evidence':{'path':str(outer.parent/'test-evidence.json'),'sha256':receipt['test_evidence']['sha256'],'bytes':len(evidence_raw)},
                'members':package_members})}}
    raw = encoded(declaration)
    require(len(raw)<=MAX_DECLARATION and time.monotonic()<deadline,'deployment bounded terminal declaration')
    target = destination/'share/omux/native/codex'
    target.mkdir(parents=True,mode=0o700)
    with (target/'deployment.json').open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o444)
    # This is sealed staging data, not a root-owned registered deployment.
    # Declarative Nix packaging must import it; Engine independently verifies
    # configured registered-root identity and the full constructor afterwards.
    return declaration
