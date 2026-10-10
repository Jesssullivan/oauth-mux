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
OUTPUTS = ('fresh-native-runtime.tar.gz','runtime-manifest.json','runtime-receipt.json',
           'registration-receipt.json','package-selection.json')
MARKER = re.compile(rb'^omux-native-package-output-sha256=([0-9a-f]{64})$',re.M)
MAX_DECLARATION = 64*1024

def require(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

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
    receipt = material.producer_success(selected_package,TARGET,'fresh-native-runtime',deadline)
    root = Path(selected_package['root'])
    require(time.monotonic()<deadline,'deployment original deadline')
    outer = Path(selected_package['producer']['receipt'])
    evidence_raw = bounded_read(outer.parent/'test-evidence.json',16*1024*1024,deadline)
    require(hashlib.sha256(evidence_raw).hexdigest()==receipt['test_evidence']['sha256'],'deployment evidence pin drift')
    evidence = json.loads(evidence_raw)
    results = [row for row in evidence['results'] if row['target']==TARGET]
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
