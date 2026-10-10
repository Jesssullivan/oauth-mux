"""Typed current HM source-pair transport: no legacy Omux artifact authority."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time
import home_manager_bundle as old
import home_manager_current_artifact as current
import home_manager_current_retained_artifact as retained

acquisition,acquired,evaluator = old.acquisition,old.acquired,old.evaluator
require,tick,relative,sha,encoded = old.require,old.tick,old.relative,old.sha,old.encoded
parent_fd,close_resources,write_all,exact = old.parent_fd,old.close_resources,old.write_all,old.exact
MAGIC=b'OMUX-CURRENT-HM-PAIR\x00v1\n'
KIND='omux-current-home-manager-pair-bundle-v1'
SELECT='omux-current-home-manager-pair-selection-v1'
TARGET='//tools:home_manager_current_pair_reconstruction_producer'
BINDING_FIELDS=('schemaVersion','kind','sourceRevision','sourceDirty','graphSha256',
    'originalEntryMonotonicNs','originalDeadlineMonotonicNs')
RECEIPT_FIELDS=('schemaVersion','kind','bundleSha256','bundleBytes','pairReceiptSha256',
    'pairInventorySha256','bindingSha256','binding','sourceWrapper','reconstructedCanonicalNarVerified',
    'retainedPhysicalNarVerified','privateTreesRemoved','activationQualified','currentArtifactQualified',
    'custodyQualified','continuityQualified','liveQualified')


def binding_document(raw):
    value=acquired.decode(raw,65536);acquired.fields(value,BINDING_FIELDS)
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['kind']=='omux-current-home-manager-pair-action-v1'
        and type(value['sourceDirty']) is bool
        and type(value['sourceRevision']) is str and re.fullmatch('[0-9a-f]{40}',value['sourceRevision'])
        and type(value['graphSha256']) is str and re.fullmatch('[0-9a-f]{64}',value['graphSha256']),
        'current-pair-action-binding')
    current.kernel.envelope(value['originalEntryMonotonicNs'],value['originalDeadlineMonotonicNs'])
    return value


def original_binding(environment):
    require(environment.get('OMUX_CURRENT_HM_MODE')==current.admission.PAIR,'current-pair-action-mode')
    values={}
    for key in ('ENTRY_NS','DEADLINE_NS'):
        token=environment.get('OMUX_CURRENT_HM_'+key)
        require(type(token) is str and re.fullmatch('[1-9][0-9]{0,19}',token),'current-pair-action-clock')
        values[key]=int(token)
    current.kernel.remaining(values['ENTRY_NS'],values['DEADLINE_NS'])
    dirty=environment.get('OMUX_CURRENT_HM_SOURCE_DIRTY')
    require(dirty in ('true','false'),'current-pair-action-source')
    value={'schemaVersion':1,'kind':'omux-current-home-manager-pair-action-v1',
        'sourceRevision':environment.get('OMUX_CURRENT_HM_SOURCE_COMMIT'),'sourceDirty':dirty=='true',
        'graphSha256':environment.get('OMUX_CURRENT_HM_GRAPH_SHA256'),
        'originalEntryMonotonicNs':values['ENTRY_NS'],'originalDeadlineMonotonicNs':values['DEADLINE_NS']}
    return binding_document(encoded(value)), min(current.kernel.envelope(values['ENTRY_NS'],values['DEADLINE_NS'])/1e9,
                                                time.monotonic()+old.MAX_SECONDS)


def entries(descriptors):
    require(set(descriptors)==set(acquired.NAMES),'current-pair-source-family')
    for name in acquired.NAMES:
        for node in sorted(descriptors[name]['nodes'],key=lambda n:os.fsencode(n['path'])):
            if node['type']=='regular':yield name,node


class PairStream(old.RepresentationStream):
    def parts(self,headers,descriptors):
        for data in (MAGIC,*(part for payload in headers for part in (struct.pack('<Q',len(payload)),payload))):
            for start in range(0,len(data),65536):yield data[start:start+65536]
        for name,node in entries(descriptors):
            with self.inputs.open('pair/'+name+'/'+node['path']) as (stream,info,check):
                require(info[6]==node['size'],'bundle-input-size')
                remaining=node['size']
                while remaining:
                    check();data=stream.read(min(65536,remaining))
                    require(data,'reconstruction-input-truncated');remaining-=len(data);yield data
                require(not stream.read(1),'reconstruction-input-growth')


def canonical_pair(worker,lock,raw_pair,raw_inventory,descriptors,work):
    result={}
    pair=worker.path/'pair'
    for name in acquired.NAMES:
        with acquisition.HeldDirectory(pair/name,parent_anchor=worker) as root:
            nodes,facts=acquired.scan(root.fd,work)
            require(nodes==sorted(descriptors[name]['nodes'],key=lambda n:os.fsencode(n['path'])),
                'current-pair-canonical-inventory')
            root.check();result[name]=facts
    proof=acquired.verify_acquired_pair(lock,raw_pair,old.PAIR_SHA,raw_inventory,
        {name:str(pair/name) for name in acquired.NAMES},deadline_seconds=evaluator.remaining(work),deadline=work)
    with acquisition.HeldDirectory(pair,parent_anchor=worker) as owner:
        receipt,inventory=evaluator.pair_metadata(owner,work)
        require(receipt[0]==raw_pair and inventory[0]==raw_inventory,'current-pair-canonical-metadata')
        require(set(os.listdir(owner.fd))==set(acquired.NAMES)|{'receipt.json','inventory.json'},
            'current-pair-canonical-members')
        owner.check()
    worker.check();return result,proof

def materialize_pair(stream, check, worker, lock, compact, work, *, disk_account=None):
    require(exact(stream, len(MAGIC), check) == MAGIC, "bundle-magic")
    metadata = []
    for maximum in (acquired.MAX_RECEIPT_BYTES, acquired.MAX_INVENTORY_BYTES, 65536):
        length = struct.unpack("<Q", exact(stream, 8, check))[0]
        require(0 < length <= maximum, "current-pair-header-bound")
        metadata.append(exact(stream, length, check))
    raw_pair, raw_inventory, raw_binding = metadata
    _, descriptors = old.pair_metadata(lock, raw_pair, raw_inventory)
    binding = binding_document(raw_binding)
    require(compact['pairReceiptSha256'] == old.PAIR_SHA
        and compact['pairInventorySha256'] == sha(raw_inventory)
        and compact['bindingSha256'] == sha(raw_binding) and compact['binding']==binding, 'current-pair-header-binding')
    logical_bytes = sum(node['size'] for _,node in entries(descriptors)) + len(raw_pair) + len(raw_inventory)
    require(logical_bytes <= acquisition.DISK_BUDGET, "bundle-private-disk-budget")
    def local_tick():
        tick(work, worker)
        check()
        acquired.check_deadline(work)
    allocated = [0]
    def charge_blocks(info, previous):
        local_tick()
        if disk_account is not None:
            disk_account.record(info)
        allocated[0] += max(0, info.st_blocks * 512 - previous)
        require(max(logical_bytes, allocated[0]) <= acquisition.DISK_BUDGET, "bundle-private-disk-budget")
    with acquisition.FileSyncOwner(local_tick, charge_blocks) as sync:
        for name in ("pair", "home"):
            worker.check()
            local_tick()
            os.mkdir(name, 0o700, dir_fd=worker.fd)
        pair = worker.path / "pair"
        roots = {name: pair / name for name in acquired.NAMES}
        with acquisition.HeldDirectory(pair, parent_anchor=worker) as pair_owner:
            for name in acquired.NAMES:
                local_tick()
                pair_owner.check()
                local_tick()
                os.mkdir(name, 0o700, dir_fd=pair_owner.fd)
        for name, descriptor in descriptors.items():
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                for node in sorted(descriptor["nodes"], key=lambda n: (n["path"].count("/"), os.fsencode(n["path"]))):
                    if node["type"] != "directory" or not node["path"]:
                        continue
                    local_tick()
                    parent, leaf = parent_fd(root.fd, node["path"])
                    try:
                        local_tick()
                        os.mkdir(leaf, 0o700, dir_fd=parent)
                    finally:
                        close_resources(parent)
        for name, node in entries(descriptors):
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                parent, leaf = parent_fd(root.fd, node["path"])
                fd = None
                try:
                    local_tick()
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    remaining = node["size"]
                    while remaining:
                        data = exact(stream, min(65536, remaining), check)
                        write_all(fd, data, work, worker)
                        remaining -= len(data)
                    local_tick()
                    os.fchmod(fd, 0o555 if node["executable"] else 0o444)
                    sync.submit(fd, parent, leaf, 0)
                finally:
                    close_resources(fd, parent)
        sync.drain()
        require(not stream.read(1), "bundle-trailing-byte")
        check()
        for name, descriptor in descriptors.items():
            with acquisition.HeldDirectory(roots[name], parent_anchor=worker) as root:
                for node in descriptor["nodes"]:
                    if node["type"] != "symlink":
                        continue
                    local_tick()
                    parent, leaf = parent_fd(root.fd, node["path"])
                    try:
                        local_tick()
                        os.symlink(node["target"], leaf, dir_fd=parent)
                        charge_blocks(os.stat(leaf, dir_fd=parent, follow_symlinks=False), 0)
                    finally:
                        close_resources(parent)
                for node in sorted((n for n in descriptor["nodes"] if n["type"] == "directory"),
                                   key=lambda n: (n["path"].count("/"), os.fsencode(n["path"])), reverse=True):
                    local_tick()
                    fd, parent = None, None
                    try:
                        if not node["path"]:
                            fd = os.dup(root.fd)
                        else:
                            parent, leaf = parent_fd(root.fd, node["path"])
                            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        local_tick()
                        os.fchmod(fd, 0o555)
                        local_tick()
                        os.fsync(fd)
                        charge_blocks(os.fstat(fd), 0)
                    finally:
                        close_resources(fd, parent)
        with acquisition.HeldDirectory(pair, parent_anchor=worker) as held:
            for name, payload in (("receipt.json", raw_pair), ("inventory.json", raw_inventory)):
                held.check()
                local_tick()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=held.fd)
                try:
                    write_all(fd, payload, work, worker)
                    local_tick()
                    os.fchmod(fd, 0o444)
                    sync.submit(fd, held.fd, name, 0)
                finally:
                    close_resources(fd)
            sync.drain()
            # Preserve HeldDirectory.mode's custody/mode/postcheck predicates,
            # inserting the deadline fence after its blocking custody check.
            held.check()
            local_tick()
            os.fchmod(held.fd, 0o555)
            require(stat.S_IMODE(os.fstat(held.fd).st_mode) == 0o555,
                    "acquisition-held-directory-mode")
            held.check()
            local_tick()
            os.fsync(held.fd)
            charge_blocks(os.fstat(held.fd), 0)
        for name in ("home",):
            with acquisition.HeldDirectory(worker.path / name, parent_anchor=worker) as root:
                charge_blocks(os.fstat(root.fd), 0)
        charge_blocks(os.fstat(worker.fd), 0)
    local_tick()
    return pair

def validate_compact(raw,digest):
    require(sha(raw)==digest,'current-pair-compact-receipt-digest')
    value=acquired.decode(raw,65536);acquired.fields(value,RECEIPT_FIELDS)
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['kind']==KIND
        and value['pairReceiptSha256']==old.PAIR_SHA and value['sourceWrapper']==old.SOURCE_WRAPPER
        and all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}',value[k]) for k in
            ('bundleSha256','pairInventorySha256','bindingSha256'))
        and type(value['bundleBytes']) is int and 0<value['bundleBytes']<=old.MAX_BUNDLE
        and all(value[k] is True for k in ('reconstructedCanonicalNarVerified','privateTreesRemoved'))
        and all(value[k] is False for k in ('retainedPhysicalNarVerified','activationQualified',
            'currentArtifactQualified','custodyQualified','continuityQualified','liveQualified')),
        'current-pair-compact-receipt-schema')
    binding_document(encoded(value['binding']))
    require(sha(encoded(value['binding']))==value['bindingSha256'],'current-pair-compact-action-digest')
    return value


def write_frame(inputs,headers,descriptors,publication,work,account,binding):
    stream=PairStream(inputs,headers,descriptors);fd=None;digest=hashlib.sha256();size=0
    try:
        tick(work,publication)
        fd=os.open('bundle',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=publication.fd)
        while True:
            data=stream.read(65536)
            if not data:break
            size+=len(data);require(size<=old.MAX_BUNDLE,'current-pair-compact-byte-bound')
            digest.update(data);write_all(fd,data,work,publication);account.record(os.fstat(fd))
        stream.check();tick(work,publication);os.fchmod(fd,0o444);os.fsync(fd)
        account.record(os.fstat(fd));publication.check()
        require(acquired.snapshot(os.fstat(fd))==acquired.snapshot(os.stat('bundle',dir_fd=publication.fd,
            follow_symlinks=False)),'current-pair-compact-output-changed')
        os.fsync(publication.fd);account.record(os.fstat(publication.fd))
    finally:
        close_resources(fd,streams=(stream,))
    return {'schemaVersion':1,'kind':KIND,'bundleSha256':digest.hexdigest(),'bundleBytes':size,
        'pairReceiptSha256':old.PAIR_SHA,'pairInventorySha256':sha(headers[1]),'bindingSha256':sha(headers[2]),
        'binding':binding,'sourceWrapper':old.SOURCE_WRAPPER,'reconstructedCanonicalNarVerified':True,
        'retainedPhysicalNarVerified':False,'privateTreesRemoved':True,'activationQualified':False,
        'currentArtifactQualified':False,'custodyQualified':False,'continuityQualified':False,'liveQualified':False}


def reconstruct(layout_path,lock_path,outputs,binding,*,deadline,progress=None):
    work,end=old.bounds(deadline);progress={} if progress is None else progress;progress['phase']='metadata'
    binding_document(encoded(binding))
    current.kernel.remaining(binding['originalEntryMonotonicNs'],binding['originalDeadlineMonotonicNs'])
    require(end<=current.kernel.envelope(binding['originalEntryMonotonicNs'],binding['originalDeadlineMonotonicNs'])/1e9,
        'current-pair-original-cutoff')
    layout_path=Path(layout_path).absolute()
    inputs=old.RepresentationInputs(layout_path.parent,work,layout_path.name)
    raw_layout=inputs.read(layout_path.name,65536,readonly=False);layout=acquired.decode(raw_layout,65536)
    require(layout=={'schemaVersion':1,'kind':'omux-current-home-manager-pair-layout-v1',
        'pairReceipt':'pair/receipt.json','pairInventory':'pair/inventory.json','pairReceiptSha256':old.PAIR_SHA,
        'sourceWrapper':old.SOURCE_WRAPPER},'current-pair-layout-authority')
    lock,lock_facts=evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)
    raw_pair=inputs.read('pair/receipt.json',acquired.MAX_RECEIPT_BYTES)
    raw_inventory=inputs.read('pair/inventory.json',acquired.MAX_INVENTORY_BYTES)
    _,descriptors=old.pair_metadata(lock,raw_pair,raw_inventory)
    headers=(raw_pair,raw_inventory,encoded(binding))
    predicted=len(MAGIC)+sum(8+len(part) for part in headers)+sum(node['size'] for _,node in entries(descriptors))
    account=old.ReconstructionBudget(2*predicted+len(raw_layout)+65536,work)
    files=[];chain_witness=None;result=None
    try:
        with acquisition.HeldDirectory(outputs) as output:
            chain_witness=tuple(item[3] for item in output.chain);tick(work,output)
            with os.scandir(output.fd) as listing:require(not any(listing),'reconstruction-output-scope')
            account.record(os.fstat(output.fd))
            try:
                with old.private_tree(output.path,end,admission_deadline=work) as worker:
                    progress['phase']='canonical-materialization'
                    stream=PairStream(inputs,headers,descriptors)
                    compact={'pairReceiptSha256':old.PAIR_SHA,'pairInventorySha256':sha(raw_inventory),
                             'bindingSha256':sha(headers[2]),'binding':binding}
                    try:materialize_pair(stream,stream.check,worker,lock,compact,work,disk_account=account)
                    finally:close_resources(streams=(stream,))
                    before=canonical_pair(worker,lock,raw_pair,raw_inventory,descriptors,work)
                    worker.check();tick(work,worker);os.mkdir('publication',0o700,dir_fd=worker.fd)
                    account.record(os.fstat(worker.fd))
                    with acquisition.HeldDirectory(worker.path/'publication',parent_anchor=worker) as publication:
                        progress['phase']='canonical-pack'
                        result=write_frame(inputs,headers,descriptors,publication,work,account,binding)
                        require(canonical_pair(worker,lock,raw_pair,raw_inventory,descriptors,work)==before,
                            'current-pair-canonical-drift')
                        progress['phase']='input-recheck';inputs.recheck()
                        require(evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)==(lock,lock_facts),
                            'bundle-lock-changed')
                        output.check();publication.check()
                        owned_bundle=old.PublicationFile('bundle');files.append(owned_bundle)
                        owned_bundle.fd=os.open('bundle',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,
                            dir_fd=publication.fd)
                        pending=owned_bundle.inspect(publication)
                        require(stat.S_IMODE(pending[2])==0o444 and pending[6]==result['bundleBytes'],
                            'reconstruction-pending-changed')
                        owned_bundle.promote(publication,output,'.pending-bundle')
                        pending=owned_bundle.inspect(output)
                        account.record(os.fstat(publication.fd))
                    os.fsync(output.fd);account.record(os.fstat(output.fd));progress['phase']='owned-cleanup'
                # Final names/receipt exist ONLY after exact owned private cleanup.
                progress['phase']='publication';tick(work,output);inputs.recheck()
                require(evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)==(lock,lock_facts),
                    'bundle-lock-changed')
                require(pending==owned_bundle.inspect(output),'reconstruction-pending-changed')
                owned_bundle.promote(output,output,'bundle')
                owned_receipt=old.PublicationFile('.pending-receipt',in_output=True);files.append(owned_receipt)
                owned_receipt.fd=os.open('.pending-receipt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                    0o600,dir_fd=output.fd)
                owned_receipt.inspect(output);raw=encoded(result);write_all(owned_receipt.fd,raw,work,output)
                os.fchmod(owned_receipt.fd,0o444);os.fsync(owned_receipt.fd);account.record(os.fstat(owned_receipt.fd))
                owned_receipt.inspect(output);owned_receipt.promote(output,output,'receipt.json')
                os.fsync(output.fd);account.record(os.fstat(output.fd));tick(work,output)
            finally:old.close_publication(files,output)
        tick(end)
    except BaseException as error:
        if chain_witness is not None:old.rollback_publication(outputs,chain_witness,files,end,error)
        raise
    return {**result,'receiptSha256':sha(raw)}


def selected_document(raw):
    value=acquired.decode(raw,65536);acquired.fields(value,('schemaVersion','kind','selection'))
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['kind']==SELECT,
        'current-pair-selection-schema')
    row=value['selection'];require(row is not None,'current-pair-selection-pending')
    acquired.fields(row,('root','bundleSha256','receiptSha256','producer'))
    for key in ('bundleSha256','receiptSha256'):
        require(type(row[key]) is str and re.fullmatch('[0-9a-f]{64}',row[key]),'current-pair-selection-digest')
    p=row['producer'];acquired.fields(p,('receipt','sha256','source_commit','source_dirty','graph_sha256'))
    require(type(p['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',p['source_commit'])
        and p['source_dirty'] in ('true','false') and all(type(p[k]) is str and re.fullmatch('[0-9a-f]{64}',p[k])
            for k in ('sha256','graph_sha256')),'current-pair-selection-source')
    path=acquired.physical_path(p['receipt']);epoch=Path(path).parent.name
    require(str(current.uuid.UUID(epoch))==epoch and Path(path).name=='receipt.json'
        and str(Path(path).parent.parent) in current.PUBLIC,'current-pair-selected-public-epoch')
    root=acquired.physical_path(row['root']);prefix=str(Path(path).parent/'output-base/execroot/_main/bazel-out')+'/'
    suffix='/testlogs/tools/home_manager_current_pair_reconstruction_producer/test.outputs'
    require(root.startswith(prefix) and root.endswith(suffix)
        and re.fullmatch('[A-Za-z0-9_.-]+',root[len(prefix):-len(suffix)]),'current-pair-selected-output-namespace')
    return row


def producer_authority(selection,receipt,deadline):
    p=selection['producer'];raw,capture=current.read(p['receipt'],16*1024*1024,deadline,p['sha256'],readonly=False)
    outer=acquired.decode(raw,16*1024*1024);r=current.producer_policy(outer,current.admission.PAIR)
    epoch=Path(p['receipt']).parent.name
    require(outer['id']==epoch and outer['unit']=='omux-execution-'+epoch+'.service'
        and outer['manager']=='system' and type(outer['exit']) is int and outer['exit']==0
        and type(outer['workload_exit']) is int and outer['workload_exit']==0 and outer['controller_failure'] is None
        and outer['descendants_empty'] is True and outer['cleanup']['state']=='empty'
        and outer['cleanup']['ownership']=='verified' and type(outer['cleanup']['readback_attempts']) is int
        and 2<=outer['cleanup']['readback_attempts']<=8 and outer['source_commit']==p['source_commit']
        and outer['source_dirty']==p['source_dirty'] and outer['graph_sha256']==p['graph_sha256']
        and outer['verb']=='test' and outer['targets']==[TARGET] and outer['test_evidence']['state']=='preserved'
        and outer['output_base']==str(Path(p['receipt']).parent/'output-base'),'current-pair-producer-terminal')
    binding=receipt['binding']
    require(binding['sourceRevision']==p['source_commit'] and binding['sourceDirty']==(p['source_dirty']=='true')
        and binding['graphSha256']==p['graph_sha256'] and binding['originalEntryMonotonicNs']==r['original_entry_monotonic_ns']
        and binding['originalDeadlineMonotonicNs']==r['original_deadline_monotonic_ns'],
        'current-pair-producer-source-clock')
    captures={p['receipt']:(capture,16*1024*1024,False)}
    ep=Path(p['receipt']).parent/'test-evidence.json'
    data,w=current.read(ep,16*1024*1024,deadline,outer['test_evidence']['sha256'],readonly=False)
    e=acquired.decode(data,16*1024*1024)
    require(type(e['schema']) is int and e['schema']==1 and type(e['bazel_exit']) is int and e['bazel_exit']==0
        and e['epoch_start_ns']==outer['epoch_start_ns'] and e['targets']==[TARGET] and len(e['results'])==1
        and e['results'][0]['target']==TARGET and e['results'][0]['state']=='observed','current-pair-producer-evidence')
    captures[str(ep)]=(w,16*1024*1024,False)
    marker={'scope':KIND,'bundleSha256':receipt['bundleSha256'],'receiptSha256':selection['receiptSha256'],
            'pairReceiptSha256':receipt['pairReceiptSha256'],'bindingSha256':receipt['bindingSha256'],'activationQualified':False}
    for member in ('test.xml','test.log'):
        rows=[x for x in e['results'][0]['files'] if x['source']==member]
        require(len(rows)==1 and rows[0]['state']=='copied' and type(rows[0]['file']) is str
            and re.fullmatch('[0-9a-f]{64}[.]evidence',rows[0]['file']),'current-pair-evidence-leaf')
        row=rows[0];path=ep.parent/'test-evidence'/row['file']
        contents,w=current.read(path,64*1024*1024,deadline,row['sha256'],readonly=False)
        require(type(row['bytes']) is int and len(contents)==row['bytes'] and len(contents)>0,'current-pair-evidence-size')
        captures[str(path)]=(w,64*1024*1024,False)
        if member=='test.xml':current.successful_xml(contents)
        else:
            matches=0
            for line in contents.splitlines():
                try:value=json.loads(line)
                except (ValueError,UnicodeError):continue
                if value==marker:matches+=1
            require(matches==1,'current-pair-evidence-marker')
    return captures


def selected_inputs(selection,deadline):
    path=Path(selection['root'])/'receipt.json'
    raw,w=current.read(path,65536,deadline,selection['receiptSha256']);receipt=validate_compact(raw,selection['receiptSha256'])
    require(receipt['bundleSha256']==selection['bundleSha256'],'current-pair-selected-bundle-digest')
    captures=producer_authority(selection,receipt,deadline);captures[str(path)]=(w,65536,True)
    inputs=old.Inputs(selection['root'],deadline)
    return receipt,captures,inputs


def recheck_captures(captures,deadline):
    for path,(w,maximum,readonly) in captures.items():
        require(current.read(path,maximum,deadline,readonly=readonly)[1]==w,'current-pair-selected-authority-drift')


def artifact_bound():
    # Existing per-artifact byte limit plus bounded metadata/directory charge;
    # physical blocks of both trees are also charged to the same account.
    return current.artifact.MAX_BYTES+4*1024*1024


def evaluate_selected(selection,lock_path,nix,modules,scratch,current_selection,clock,deadline):
    current.kernel.remaining(*clock);work,end=old.bounds(deadline)
    require(end<=current.kernel.envelope(*clock)/1e9,'current-pair-evaluation-original-cutoff')
    receipt,captures,inputs=selected_inputs(selection,work)
    lock,lock_facts=evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)
    with inputs.open('bundle') as (stream,info,check):
        require(info[6]==receipt['bundleBytes'],'current-pair-selected-size')
        def hash_input():
            stream.seek(0);digest=hashlib.sha256()
            while True:
                check();data=stream.read(65536)
                if not data:break
                digest.update(data)
            require(digest.hexdigest()==selection['bundleSha256'],'current-pair-selected-byte-binding');check()
        hash_input();stream.seek(0)
        transport=current.verify_retained_selected(current_selection,work)
        # ONE allocation budget and ONE private cleanup owner cover both trees.
        # BundleBytes bounds pair payload and metadata; artifact archiveBytes
        # does not bound expanded bytes, so charge the declared full tree bound.
        account=old.ReconstructionBudget(receipt['bundleBytes']+artifact_bound(),work)
        with old.private_tree(scratch,end,admission_deadline=work) as worker:
            with retained.CanonicalArtifact(current_selection,worker,work,account) as canonical:
                pair=materialize_pair(stream,check,worker,lock,receipt,work,disk_account=account)
                current_receipt,_=current.read(Path(current_selection['root'])/'receipt.json',65536,work,
                    current_selection['receiptSha256'])
                result=evaluator.evaluate_acquired_pair(nix,modules,lock,str(pair),old.PAIR_SHA,
                    str(canonical.path),current_receipt,current_selection['receiptSha256'],
                    str(worker.path/'home'),deadline=work,current_selection=current_selection,original_clock=clock,
                    canonical_artifact=canonical)
                canonical.verify(work);hash_input();recheck_captures(captures,work)
                require(evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)==(lock,lock_facts),'bundle-lock-changed')
                tick(work,worker)
        require(current.verify_retained_selected(current_selection,work)==transport,'current-hm-retained-authority-after-cleanup')
        check();recheck_captures(captures,work)
        require(evaluator.read_declared(lock_path,acquired.MAX_LOCK_BYTES,work)==(lock,lock_facts),'bundle-lock-changed')
    tick(end)
    return {**result,'currentPairBundleSha256':selection['bundleSha256'],
        'currentPairReceiptSha256':selection['receiptSha256'],'currentPairPrivateTreesRemoved':True,
        'sourceWrapper':old.SOURCE_WRAPPER}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--layout',required=True);parser.add_argument('--lock',required=True)
    args=parser.parse_args();progress={}
    saved={}
    def interrupted(signum,frame):
        raise InterruptedError('current-pair-interrupted')
    try:
        for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
            saved[signum]=signal.signal(signum,interrupted)
        require(os.environ.get('OMUX_EXECUTION_GUARD'),'current-pair-contained-context')
        binding,deadline=original_binding(os.environ)
        result=reconstruct(args.layout,args.lock,os.environ['TEST_UNDECLARED_OUTPUTS_DIR'],binding,
            deadline=deadline,progress=progress)
        print(json.dumps({'scope':KIND,'bundleSha256':result['bundleSha256'],'receiptSha256':result['receiptSha256'],
            'pairReceiptSha256':result['pairReceiptSha256'],'bindingSha256':result['bindingSha256'],'activationQualified':False},sort_keys=True));return 0
    except BaseException as error:
        print(json.dumps({'scope':KIND,'passed':False,'activationQualified':False,
            'diagnostic':old.reconstruction_failure(error,progress)},sort_keys=True));return 2
    finally:
        for signum,handler in saved.items():signal.signal(signum,handler)

if __name__=='__main__':raise SystemExit(main())
