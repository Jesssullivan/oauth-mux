"""Digest-selected sealed public carrier; no transport, imports or seat authority."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCOPE = 'omux-yoga-sealed-workspace-transfer-input-v1'
PARENT = '/srv/omux-yoga-sealed-workspaces-20261010'
SOURCE = '/srv/fast-local/jess/state/codex/omux-installed-toolbar-public-20261008/outputs/workspace'
PUBLIC = ('/home/jess/.local/state/omux-execution-20261005',
          '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
SHA = re.compile('[a-f0-9]{64}')
REV = re.compile('[a-f0-9]{40}')
UUID = re.compile('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
STORE = re.compile('/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}')
MAX_METADATA, MAX_FILES, MAX_BYTES = 8*1024**2, 1024, 16*1024**3
BOOTSTRAP = ('yoga_install_inputs_receiver', 'guard_resident_observation',
             'guard_native_seed_plan_reserved', 'yoga_sealed_transfer_schema',
             'yoga_sealed_transfer_receiver')

def require(value):
    if value is not True: raise ValueError('sealed-transfer-refused')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()

def exact_result(actual,expected):
    require(type(actual) is dict and set(actual)==set(expected)
        and all(type(actual[key]) is type(item) and actual[key]==item for key,item in expected.items()))

def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_METADATA)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('sealed-transfer-refused')))

def relative(value):
    require(type(value) is str and 0 < len(value.encode()) <= 4096
        and str(PurePosixPath(value)) == value and not value.startswith('/')
        and not {'.', '..'}.intersection(value.split('/'))
        and not any(ord(c) < 33 or c == '\\' for c in value))
    return value

def pin(value):
    require(type(value) is dict and set(value) == {'sha256', 'bytes'}
        and type(value['sha256']) is str and SHA.fullmatch(value['sha256']) is not None
        and type(value['bytes']) is int and 0 < value['bytes'] <= MAX_BYTES)
    return value

def receipt_pin(value):
    require(type(value) is dict and set(value) == {'epoch', 'path', 'sha256', 'bytes'})
    require(type(value['epoch']) is str and UUID.fullmatch(value['epoch']) is not None)
    require(value['path'] in {root+'/'+value['epoch']+'/receipt.json' for root in PUBLIC})
    pin({key:value[key] for key in ('sha256','bytes')})
    require(value['bytes'] <= MAX_METADATA)
    return value

def manifest(raw, digest):
    require(type(digest) is str and SHA.fullmatch(digest) is not None
        and hashlib.sha256(raw).hexdigest() == digest)
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schemaVersion','scope','transferId',
        'producerSourceCommit','producerGraphSha256','selector','workspaceProducer',
        'workspaceReceipt','workspaceFiles','selectedData','evidence','narRows','bootstrapSha256','destination'}
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and value['scope'] == SCOPE)
    require(type(value['transferId']) is str and UUID.fullmatch(value['transferId']) is not None
        and type(value['producerSourceCommit']) is str and REV.fullmatch(value['producerSourceCommit']) is not None
        and type(value['producerGraphSha256']) is str and SHA.fullmatch(value['producerGraphSha256']) is not None)
    receipt_pin(value['selector']); receipt_pin(value['workspaceProducer'])
    require(value['selector']['epoch'] != value['workspaceProducer']['epoch'])
    pin(value['workspaceReceipt']); require(value['workspaceReceipt']['bytes'] <= MAX_METADATA)
    pin(value['selectedData']); require(value['selectedData']['bytes'] <= MAX_METADATA)
    files = value['workspaceFiles']
    require(type(files) is dict and 1 <= len(files) <= MAX_FILES and 'installed-workspace.json' not in files)
    for name, row in files.items():
        relative(name)
        require(type(row) is dict and set(row) == {'sha256','bytes','mode'}
            and type(row['mode']) is int and row['mode'] in (0o444,0o555))
        require(type(row['sha256']) is str and SHA.fullmatch(row['sha256']) is not None
            and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_BYTES)
    require({'MODULE.bazel','BUILD.bazel','tools/BUILD.bazel','installed-launcher.sh',
        'execution_guard.sh','yoga_reserved_session_qualification.sh','browser-inventory.json',
        'controller-inventory.json','tools/guard_yoga_toolbar_reserved.py',
        'tools/guard_yoga_installed_workspace.py','yoga_local_console_qualification.sh',
        'tools/yoga_local_console_qualification.py','tools/yoga_local_console_scope.py'}.issubset(files))
    evidence = value['evidence']
    require(type(evidence) is dict and set(evidence) == {'controller-nar-proof.json'})
    selected = evidence['controller-nar-proof.json']
    require(type(selected) is dict and set(selected) == {'path','sha256','bytes'})
    path = selected['path']
    require(type(path) is str and str(Path(path)) == path and not {'.','..'}.intersection(path.split('/'))
        and not any(ord(c)<33 or c=='\\' for c in path)
        and any(path.startswith(root+'/') for root in PUBLIC)
        and '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/' in path)
    pin({key:selected[key] for key in ('sha256','bytes')}); require(selected['bytes'] <= MAX_METADATA)
    rows = value['narRows']
    require(type(rows) is list and 1 <= len(rows) <= 4096)
    by_path = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'path','narSha256','narSize','references'}
            and type(row['path']) is str and STORE.fullmatch(row['path']) is not None and row['path'] not in by_path
            and type(row['narSha256']) is str and SHA.fullmatch(row['narSha256']) is not None
            and type(row['narSize']) is int and 0 < row['narSize'] <= MAX_BYTES
            and type(row['references']) is list and len(row['references']) <= 4096
            and len(set(row['references'])) == len(row['references']))
        by_path[row['path']] = row
    require(all(type(ref) is str and ref in by_path for row in rows for ref in row['references'])
        and sum(len(row['references']) for row in rows) <= 65536)
    require(type(value['bootstrapSha256']) is dict and set(value['bootstrapSha256']) == set(BOOTSTRAP)
        and all(type(sha) is str and SHA.fullmatch(sha) is not None for sha in value['bootstrapSha256'].values()))
    require(value['destination'] == {'host':'yoga','user':'jsullivan2','parent':PARENT,
        'workspace':PARENT+'/'+value['transferId']+'/workspace'})
    require(sum(row['bytes'] for row in files.values())+value['workspaceReceipt']['bytes']
        +sum(row['bytes'] for row in evidence.values())+sum(row['narSize'] for row in rows) <= MAX_BYTES)
    return value

def producer(receipt, selected, value, kind):
    require(kind in ('selector','workspace'))
    profile,target,verb = ('yoga-installed-selection-reserved','//delivery:yoga_installed_selection','test') if kind=='selector' else (
        'yoga-installed-workspace-reserved','//delivery:yoga_installed_workspace','run')
    require(type(receipt) is dict and receipt.get('id') == receipt.get('artifact_epoch') == selected['epoch']
        and receipt.get('source_commit') == value['producerSourceCommit'] and receipt.get('source_dirty') == 'false'
        and receipt.get('graph_sha256') == value['producerGraphSha256']
        and receipt.get('profile') == profile and receipt.get('targets') == [target] and receipt.get('verb') == verb
        and type(receipt.get('exit')) is int and receipt['exit'] == 0
        and type(receipt.get('workload_exit')) is int and receipt['workload_exit'] == 0
        and receipt.get('controller_failure') is None and receipt.get('rejection') is None
        and receipt.get('descendants_empty') is True)
    cleanup = receipt.get('cleanup')
    require(type(cleanup) is dict and cleanup.get('ownership') == 'verified' and cleanup.get('state') == 'empty'
        and type(cleanup.get('readback_attempts')) is int and cleanup['readback_attempts'] >= 2
        and receipt.get('output_base') == str(Path(selected['path']).parent/'output-base'))
    reserved = receipt.get('yoga_installed_reservation')
    require(type(reserved) is dict and reserved.get('mode') == ('selection' if kind=='selector' else 'workspace')
        and reserved.get('verified_after_cleanup') is True
        and reserved.get('browser_invoked') is False and reserved.get('provider_invoked') is False)

def workspace(record, value):
    require(type(record) is dict and record.get('schemaVersion') == 2
        and record.get('scope') == 'yoga-installed-toolbar-workspace-v2'
        and record.get('workspaceFiles') == value['workspaceFiles'])
    for name in ('executionAuthority','destinationRegistrationVerified','seatQualified','toolbarConsentProved',
                 'embeddedArtifactProvenanceRewritten'):
        require(record.get(name) is False)
    require(type(record.get('workspaceGraphSha256')) is str and SHA.fullmatch(record['workspaceGraphSha256']) is not None)
    return record

def selected_join(selection, record, receipt, value, *, controller_root):
    require(selection.get('schemaVersion') == 2 and type(selection.get('controllerPackage')) is dict
        and type(controller_root) is str and selection['controllerPackage'].get('root') == controller_root
        and record.get('controllerPackageSha256') == {name: row['sha256']
            for name,row in selection['controllerPackage']['files'].items()}
        and record.get('inputSha256') == selection.get('inputSha256')
        and record.get('nativeManifestSha256') == selection.get('nativeManifestSha256'))
    projection = receipt.get('yoga_installed_producer_input')
    require(type(projection) is dict and projection.get('verified_after_cleanup') is True
        and all(type(projection.get(stage)) is dict and projection[stage].get('selection_sha256') ==
            value['selectedData']['sha256'] for stage in ('before','after')))

def member_rows(value):
    rows = [('workspace/'+name,row['bytes'],row['sha256'],row['mode']) for name,row in sorted(value['workspaceFiles'].items())]
    rows.append(('workspace/installed-workspace.json',value['workspaceReceipt']['bytes'],value['workspaceReceipt']['sha256'],0o444))
    rows.extend(('evidence/'+name,row['bytes'],row['sha256'],0o444) for name,row in sorted(value['evidence'].items()))
    rows.extend(('nars/'+Path(row['path']).name+'.nar',row['narSize'],row['narSha256'],0o444) for row in sorted(value['narRows'],key=lambda row:row['path']))
    require(len({row[0] for row in rows}) == len(rows))
    return rows
