"""Versioned current-artifact authority. Historical dirty verifier is unchanged."""
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET

import home_manager_artifact as artifact
import home_manager_acquired_inputs as acquired
import home_manager_acquired_evaluation as evaluator
sys.path.insert(0, str(Path(__file__).absolute().parent.parent / 'tools'))
import guard_current_home_manager_artifact_reserved as admission
import guard_native_seed_plan_reserved as kernel

PUBLIC = ('/home/jess/.local/state/omux-execution-20261005',
          '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
TARGET = '//delivery:current_home_manager_artifact'
FIELDS = {'schemaVersion','kind','sourceRevision','sourceDirty','graphSha256','originalEntryMonotonicNs',
    'originalDeadlineMonotonicNs','archiveSha256','archiveBytes','manifestSha256','narHash','narSize','system',
    'channel','nativeBins','extensionSha256','extensionBytes','extensionMetadataSha256','sourceQualification',
    'shipped','activationQualified','browserQualified','custodyQualified','continuityQualified','liveQualified'}
require = acquired.require
sha = artifact.sha


def selected_document(raw):
    value=acquired.decode(raw,65536)
    acquired.fields(value,('schemaVersion','kind','selection'))
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['kind']=='omux-current-home-manager-selection-v1','current-hm-selection-schema')
    selection=value['selection']
    require(selection is not None,'current-hm-selection-pending')
    acquired.fields(selection,('root','receiptSha256','inventorySha256','producer'))
    acquired.fields(selection['producer'],('receipt','sha256','source_commit','source_dirty','graph_sha256'))
    for name in ('receiptSha256','inventorySha256'):
        require(type(selection[name]) is str and re.fullmatch('[0-9a-f]{64}',selection[name]),'current-hm-selection-digest')
    producer=selection['producer']
    require(type(producer['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',producer['source_commit'])
        and producer['source_dirty'] in ('true','false')
        and all(type(producer[key]) is str and re.fullmatch('[0-9a-f]{64}',producer[key])
                for key in ('sha256','graph_sha256')),'current-hm-selection-source')
    path=acquired.physical_path(producer['receipt']); epoch=Path(path).parent.name
    require(str(uuid.UUID(epoch))==epoch and Path(path).name=='receipt.json'
        and str(Path(path).parent.parent) in PUBLIC,'current-hm-producer-public-epoch')
    root=acquired.physical_path(selection['root'])
    prefix=str(Path(path).parent/'output-base/execroot/_main/bazel-out')+'/'
    suffix='/testlogs/delivery/current_home_manager_artifact/test.outputs/current-home-manager'
    require(root.startswith(prefix) and root.endswith(suffix)
        and re.fullmatch('[A-Za-z0-9_.-]+',root[len(prefix):-len(suffix)]) is not None,
        'current-hm-selected-output-namespace')
    return selection


def read(path, maximum, deadline, expected=None, *, readonly=True):
    physical=acquired.physical_path(os.fspath(path))
    with artifact.HeldDirectory(Path(physical).parent,owned=False) as parent:
        raw,capture=evaluator.read_at(parent,Path(physical).name,maximum,deadline,readonly=readonly)
    require(capture[3]==os.getuid() and not capture[2] & 0o6022,'current-hm-selected-owner-mode')
    require(expected is None or sha(raw)==expected,'current-hm-selected-bytes')
    return raw,capture


def policy(outer):
    reservation=outer['current_home_manager_artifact_reservation']
    expected=admission.projection(admission.PROFILE,reservation['original_entry_monotonic_ns'],
        reservation['original_deadline_monotonic_ns'],True,reservation['resident'])
    require(reservation==expected and outer['profile']==admission.PROFILE
        and outer['cache_reuse_requested'] is False and outer['cache_policy'] is None
        and outer['cache_key'] is None,'current-hm-producer-reservation')
    properties=outer['observed_properties']
    require(all(properties.get(key)==value for key,value in {'MemoryMax':'4026531840','MemorySwapMax':'0',
        'TasksMax':'480','PrivateNetwork':'yes','KillMode':'control-group','SendSIGKILL':'yes',
        'OOMPolicy':'kill','RemainAfterExit':'yes'}.items()),'current-hm-worker-caps')
    token=properties.get('CPUQuotaPerSecUSec')
    match=re.fullmatch(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)',token) if type(token) is str else None
    require(match is not None and Decimal(match[1])*{'us':1,'ms':1000,'s':1000000}[match[2]]==1900000,
        'current-hm-worker-cpu')
    runtime=properties.get('RuntimeMaxUSec')
    matches=list(re.finditer(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s|min|h)',runtime)) if type(runtime) is str and len(runtime)<=64 else []
    scales={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000}
    require(matches and ''.join(row.group(0) for row in matches)==runtime.replace(' ','')
        and 0<sum(Decimal(row[1])*scales[row[2]] for row in matches)<=1200000000,
        'current-hm-worker-runtime')
    resident=reservation['resident']
    require(type(resident) is dict and set(resident)=={'scope','kernel_bounds','observations','initial_direct_processes_retained',
        'initial_direct_process_count','outer_pid_namespace_matched','hierarchical_caps','descendant_process_inventory',
        'installation_qualified','health_observed','custody_observed','resident_signalled','whole_host_reservation'}
        and resident['scope']=='sampled-fixed-default-cgroup-kernel-reservation-v1'
        and type(resident['observations']) is int and 0<resident['observations']<=65535
        and type(resident['initial_direct_process_count']) is int and 0<resident['initial_direct_process_count']<=32
        and all(resident[key] is True for key in ('initial_direct_processes_retained','outer_pid_namespace_matched','hierarchical_caps'))
        and all(resident[key] is False for key in ('descendant_process_inventory','installation_qualified','health_observed',
            'custody_observed','resident_signalled','whole_host_reservation')),'current-hm-resident-witness')
    kernel.kernel_bounds(resident['kernel_bounds'])
    require(resident['initial_direct_process_count']<=int(resident['kernel_bounds']['pids.max']),
        'current-hm-resident-task-count')
    return reservation


def successful_xml(raw):
    root=ET.fromstring(raw)
    suites=[root] if root.tag=='testsuite' else list(root.findall('testsuite'))
    require(root.tag in ('testsuite','testsuites') and suites and all(int(suite.get('tests','0'))>0
        and all(int(suite.get(key,'0'))==0 for key in ('failures','errors','skipped')) for suite in suites),
        'current-hm-producer-successful-cases')


def producer_authority(selection, receipt, deadline):
    producer=selection['producer']; raw,capture=read(producer['receipt'],16*1024*1024,deadline,producer['sha256'],readonly=False)
    outer=acquired.decode(raw,16*1024*1024); reservation=policy(outer)
    epoch=Path(producer['receipt']).parent.name
    require(outer['id']==epoch and outer['unit']=='omux-execution-'+epoch+'.service'
        and outer['manager']=='system' and type(outer['exit']) is int and outer['exit']==0
        and type(outer['workload_exit']) is int and outer['workload_exit']==0
        and outer['controller_failure'] is None and outer['descendants_empty'] is True
        and outer['cleanup']['state']=='empty' and outer['cleanup']['ownership']=='verified'
        and type(outer['cleanup']['readback_attempts']) is int and 2<=outer['cleanup']['readback_attempts']<=8 and outer['source_commit']==producer['source_commit']
        and outer['source_dirty']==producer['source_dirty'] and outer['graph_sha256']==producer['graph_sha256']
        and outer['verb']=='test' and outer['targets']==[TARGET] and outer['test_evidence']['state']=='preserved',
        'current-hm-producer-terminal')
    require(outer['output_base']==str(Path(producer['receipt']).parent/'output-base'),'current-hm-original-output-base')
    prefix=acquired.physical_path(outer['output_base'])+'/execroot/_main/bazel-out/'
    suffix='/testlogs/delivery/current_home_manager_artifact/test.outputs/current-home-manager'
    root=selection['root']
    require(root.startswith(prefix) and root.endswith(suffix)
        and re.fullmatch('[A-Za-z0-9_.-]+',root[len(prefix):-len(suffix)]) is not None,
        'current-hm-producer-output-namespace')
    require(receipt['sourceRevision']==producer['source_commit']
        and receipt['sourceDirty']==(producer['source_dirty']=='true')
        and receipt['graphSha256']==producer['graph_sha256']
        and receipt['originalEntryMonotonicNs']==reservation['original_entry_monotonic_ns']
        and receipt['originalDeadlineMonotonicNs']==reservation['original_deadline_monotonic_ns'],
        'current-hm-producer-source-clock')
    evidence_path=Path(producer['receipt']).parent/'test-evidence.json'
    evidence_raw,evidence_capture=read(evidence_path,16*1024*1024,deadline,outer['test_evidence']['sha256'],readonly=False)
    evidence=acquired.decode(evidence_raw,16*1024*1024)
    require(type(evidence['schema']) is int and evidence['schema']==1
        and type(evidence['bazel_exit']) is int and evidence['bazel_exit']==0
        and evidence['epoch_start_ns']==outer['epoch_start_ns'] and evidence['targets']==[TARGET]
        and len(evidence['results'])==1 and evidence['results'][0]['target']==TARGET
        and evidence['results'][0]['state']=='observed','current-hm-producer-evidence')
    captures={str(producer['receipt']):(capture,16*1024*1024,False),
              str(evidence_path):(evidence_capture,16*1024*1024,False)}
    for member in ('test.xml','test.log'):
        rows=[row for row in evidence['results'][0]['files'] if row['source']==member]
        require(len(rows)==1 and rows[0]['state']=='copied' and re.fullmatch('[0-9a-f]{64}[.]evidence',rows[0]['file']),
            'current-hm-producer-evidence-member')
        row=rows[0];path=evidence_path.parent/'test-evidence'/row['file']
        contents,witness=read(path,64*1024*1024,deadline,row['sha256'],readonly=False)
        require(type(row['bytes']) is int and len(contents)==row['bytes'] and len(contents)>0,
            'current-hm-producer-evidence-size');captures[str(path)]=(witness,64*1024*1024,False)
        if member=='test.xml': successful_xml(contents)
        else:
            marker={'scope':receipt['kind'],'manifestSha256':receipt['manifestSha256'],
                    'narHash':receipt['narHash'],'shipped':False}
            lines=[]
            for line in contents.splitlines():
                try: value=json.loads(line)
                except (ValueError,UnicodeError): continue
                if value==marker: lines.append(value)
            require(len(lines)==1,'current-hm-producer-log-binding')
    return captures


def validate_receipt(raw, digest):
    require(sha(raw)==digest,'current-hm-receipt-digest')
    value=acquired.decode(raw,65536); acquired.fields(value,FIELDS)
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['kind']=='omux-current-home-manager-artifact-v1'
        and value['system']=='x86_64-linux' and value['channel']=='development'
        and type(value['sourceDirty']) is bool and value['nativeBins']==artifact.NATIVE_BINS
        and value['sourceQualification']=='original-coordinator-source-and-declared-current-graph'
        and all(value[key] is False for key in ('shipped','activationQualified','browserQualified','custodyQualified',
            'continuityQualified','liveQualified')),'current-hm-receipt-schema')
    for key in ('graphSha256','archiveSha256','manifestSha256','extensionSha256','extensionMetadataSha256'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}',value[key]),'current-hm-receipt-hash')
    require(type(value['sourceRevision']) is str and re.fullmatch('[0-9a-f]{40}',value['sourceRevision']),
        'current-hm-receipt-source')
    kernel.envelope(value['originalEntryMonotonicNs'],value['originalDeadlineMonotonicNs'])
    for key,limit in (('archiveBytes',artifact.MAX_BYTES),('extensionBytes',artifact.MAX_BYTES),
                      ('narSize',artifact.MAX_BYTES+4*1024*1024)):
        require(type(value[key]) is int and 0<value[key]<=limit,'current-hm-receipt-size')
    require(type(value['narHash']) is str and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=',value['narHash']),
        'current-hm-receipt-nar')
    return value


def inventory_binding(inventory,nodes,nar_hash,nar_size,receipt):
    acquired.fields(inventory,('schemaVersion','nodes'))
    require(type(inventory['schemaVersion']) is int and inventory['schemaVersion']==1
        and inventory['nodes']==nodes and nar_hash==receipt['narHash'] and nar_size==receipt['narSize'],
        'current-hm-inventory-nar-binding')


def verify_selected(selection, deadline):
    root=Path(selection['root'])
    raw,receipt_capture=read(root/'receipt.json',65536,deadline,selection['receiptSha256'])
    receipt=validate_receipt(raw,selection['receiptSha256'])
    captures=producer_authority(selection,receipt,deadline)
    inventory_raw,inventory_capture=read(root/'inventory.json',16*1024*1024,deadline,selection['inventorySha256'])
    inventory=acquired.decode(inventory_raw,16*1024*1024); acquired.fields(inventory,('schemaVersion','nodes'))
    require(type(inventory['schemaVersion']) is int and inventory['schemaVersion']==1,'current-hm-inventory-schema')
    files,nodes,facts,nar_hash,nar_size=artifact.tree_bytes(root/'artifact',deadline)
    inventory_binding(inventory,nodes,nar_hash,nar_size,receipt)
    manifest=artifact.verify_copied_bundle(files,nodes)
    require(manifest['target']=='x86_64-linux' and manifest['channel']=='development'
        and manifest['distribution']=='portable-linux' and manifest['product']['status']=='experimental'
        and manifest['provenance']=={'sourceRevision':receipt['sourceRevision'],'sourceDirty':receipt['sourceDirty']}
        and 'qt' in manifest['runtime'] and all(name in files for name in artifact.NATIVE_BINS)
        and sha(files['release-manifest.json'])==receipt['manifestSha256'],'current-hm-archive-manifest')
    archive_raw,archive_capture=read(root.parent/'current-home-manager.tar.gz',artifact.MAX_BYTES,deadline,
        receipt['archiveSha256'],readonly=False)
    require(len(archive_raw)==receipt['archiveBytes'] and artifact.pack.verify_bundle(archive_raw)[1]==files,
        'current-hm-original-archive-binding')
    extension,extension_capture=read(root/'extension.zip',artifact.MAX_BYTES,deadline,receipt['extensionSha256'])
    metadata,metadata_capture=read(root/'extension-metadata.json',artifact.MAX_BYTES,deadline,receipt['extensionMetadataSha256'])
    require(len(extension)==receipt['extensionBytes'],'current-hm-extension-size')
    captures.update({str(root/'receipt.json'):(receipt_capture,65536,True),
        str(root/'inventory.json'):(inventory_capture,16*1024*1024,True),
        str(root.parent/'current-home-manager.tar.gz'):(archive_capture,artifact.MAX_BYTES,False),
        str(root/'extension.zip'):(extension_capture,artifact.MAX_BYTES,True),
        str(root/'extension-metadata.json'):(metadata_capture,artifact.MAX_BYTES,True)})
    with artifact.HeldDirectory(root) as held:
        held.check()
        require(set(os.listdir(held.fd))=={'artifact','receipt.json','inventory.json','extension.zip','extension-metadata.json'},
            'current-hm-envelope-members')
    require(artifact.tree_bytes(root/'artifact',deadline)[2]==facts,'current-hm-tree-late-change')
    # Re-read exact selected metadata/evidence under the same named/held check API.
    for path,(witness,maximum,readonly) in captures.items():
        _,again=read(path,maximum,deadline,readonly=readonly)
        require(again==witness,'current-hm-authority-late-change')
    return {**receipt,'fullQt':True,'metadataCommitment':sha(artifact.encoded(facts)),
            'executionAuthority':False,'activationPerformed':False,'selectedAuthoritySha256':sha(artifact.encoded(selection))}
