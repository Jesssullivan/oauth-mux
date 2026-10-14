"""Fresh actual byte/custody qualification of an ORIGINAL prepared public tuple.

Never launch a runner, install/register/start software, unlock a vault, contact a
provider or claim consent. Old producer clocks remain history; this action uses
only its own original coordinator budget. Output is provisional until exit0.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import yoga_public_artifact_prepare as prepared

LABEL = '//delivery:yoga_public_artifact_receive_qualification'
VARIABLE = 'OMUX_YOGA_PUBLIC_RECEIVE_'
SCOPE = 'yoga-public-toolbar-fresh-physical-qualification-v1'
FIELDS = frozenset(('EPOCH','ENTRY_NS','DEADLINE_NS','SOURCE_COMMIT','GRAPH_SHA256',
    'SOURCE_ROOT','SELECTION_PATH','SELECTION_SHA256'))
DESCRIPTOR_FIELDS = frozenset(('schemaVersion','scope','context','retentionMode',
    'originalOutputBase','originalRunfilesRoot','originalControlRunfilesRoot','runnerLabel',
    'roles','declaration','metadata','inventorySha256','inventoryBytes','directoryWitnesses',
    'originalOuterReceiptJoinRequired','freshConsumerQualificationRequired')) | frozenset(prepared.FALSE)


def require(value):
    if value is not True:raise ValueError('toolbar-public-receiver-refused')


def absolute(value):
    require(type(value) is str and 0 < len(os.fsencode(value)) <= 8192
        and value.startswith('/') and not value.startswith('//')
        and str(Path(value)) == value and os.path.normpath(value) == value
        and len(Path(value).parts) <= 256 and '\x00' not in value)
    return Path(value)


def sha(value):require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None)


class Metadata:
    """Preregister every empty FD owner before acquisition, hold through last IO."""
    def __init__(self,clock):self.clock=clock;self.owners=prepared.Owned();self.chains=[];self.files=[]
    def open(self,path,maximum,*,expected=None,private_parent=False):
        if expected is not None:
            require(type(expected) is dict and set(expected)=={'sha256','bytes'}
                and type(expected['bytes']) is int and 0<expected['bytes']<=maximum)
            sha(expected['sha256'])
        path=absolute(str(path));chain=[];selected=Path('/')
        slot=self.owners.empty_directory()
        slot.fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        chain.append((selected,slot,prepared.witness(os.fstat(slot.fd))[:5]))
        for part in path.parts[1:-1]:
            self.clock.tick();parent=slot;selected/=part
            named=os.stat(part,dir_fd=parent.fd,follow_symlinks=False)
            slot=self.owners.empty_directory()
            slot.fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
            held=os.fstat(slot.fd)
            require(stat.S_ISDIR(held.st_mode) and prepared.directory_custody(selected,held)
                and prepared.witness(named)==prepared.witness(held))
            chain.append((selected,slot,prepared.witness(held)[:5]))
        parent_information=os.fstat(slot.fd)
        require(parent_information.st_uid==os.getuid()
            and (not private_parent or stat.S_IMODE(parent_information.st_mode)==0o700))
        # Outer ancestors use stable identity/mode; this exact metadata parent
        # stays full-nine through all later tuple IO and post-close readback.
        # Commit exactly the observation whose UID/private policy was checked;
        # a later unchecked fstat must not silently become the baseline.
        chain[-1]=(chain[-1][0],slot,prepared.witness(parent_information))
        self.chains.append(chain)
        named=os.stat(path.name,dir_fd=slot.fd,follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_uid==os.getuid()
            and stat.S_IMODE(named.st_mode)==0o600 and named.st_nlink==1
            and 0<named.st_size<=maximum)
        leaf=self.owners.empty_directory()
        leaf.fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=slot.fd)
        fact=prepared.witness(os.fstat(leaf.fd));require(fact==prepared.witness(named))
        chunks=[];count=0
        while True:
            self.clock.tick();block=os.read(leaf.fd,min(1024*1024,maximum-count+1))
            if not block:break
            count+=len(block);require(count<=maximum);chunks.append(block)
        raw=b''.join(chunks);require(count==fact[6])
        self.files.append((path,leaf,fact));self.recheck()
        if expected is not None:
            require(len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256'])
        return raw
    def recheck(self,*,held=True):
        self.clock.tick()
        for chain in self.chains:
            for path,slot,fact in chain:
                current=prepared.witness(path.lstat())
                require(current[:len(fact)]==fact and stat.S_ISDIR(current[4]))
                if held:require(prepared.witness(os.fstat(slot.fd))[:len(fact)]==fact)
        for path,slot,fact in self.files:
            require(prepared.witness(path.lstat())==fact)
            if held:require(prepared.witness(os.fstat(slot.fd))==fact)
        self.clock.tick()
    def close(self,primary=None):
        self.owners.drain(primary)
        if primary is None:self.recheck(held=False)


def selection(raw):
    value=prepared.decode(raw)
    require(type(value) is dict and set(value)=={'schemaVersion','scope','producerContext',
        'artifact','producerReceipt','retirement'} and type(value['schemaVersion']) is int
        and value['schemaVersion']==1 and value['scope']=='yoga-public-toolbar-receiver-selection-v1')
    context=value['producerContext']
    require(type(context) is dict and set(context)=={'epoch','entryNs','deadlineNs','sourceCommit','graphSha256','sourceRoot'})
    # Shape only: historical creator deadline is never used as a fresh budget.
    for name in ('entryNs','deadlineNs'):require(type(context[name]) is int and context[name]>=0)
    require(context['deadlineNs']-context['entryNs']==1200*10**9)
    for name,size in (('sourceCommit',40),('graphSha256',64)):
        require(type(context[name]) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',context[name]) is not None)
    epoch=absolute(context['epoch']);absolute(context['sourceRoot'])
    require(str(prepared.uuid.UUID(epoch.name))==epoch.name)
    for name in ('artifact','producerReceipt','retirement'):
        record=value[name];require(type(record) is dict and set(record)=={'sha256','bytes'})
        sha(record['sha256']);require(type(record['bytes']) is int and 0<record['bytes']<=prepared.MAX_METADATA)
    return value


def qualify(selection_path,selection_sha256,current):
    clock=prepared.Clock(current);sha(selection_sha256)
    metadata=Metadata(clock);inputs=None;primary=None;result=None
    try:
        raw=metadata.open(selection_path,32768,private_parent=True)
        require(hashlib.sha256(raw).hexdigest()==selection_sha256)
        selected=selection(raw);creator=selected['producerContext'];epoch=absolute(creator['epoch'])
        require(epoch!=Path(current['epoch']) and epoch.parent==Path(current['epoch']).parent
            and creator['sourceRoot']==current['sourceRoot'])
        base=epoch/'output-base'
        receipt_raw=metadata.open(epoch/'receipt.json',2*1024**2,expected=selected['producerReceipt'])
        retirement_raw=metadata.open(epoch/'test-evidence-retirement.json',1024**2,expected=selected['retirement'])
        receipt=prepared.decode(receipt_raw);retirement=prepared.decode(retirement_raw)
        require(type(receipt) is dict and receipt.get('id')==epoch.name
            and receipt.get('verb')=='test' and receipt.get('targets')==[prepared.LABEL]
            and type(receipt.get('exit')) is int and receipt['exit']==0
            and type(receipt.get('workload_exit')) is int and receipt['workload_exit']==0
            and receipt.get('source_commit')==creator['sourceCommit'] and receipt.get('source_dirty')=='false'
            and receipt.get('graph_sha256')==creator['graphSha256'] and receipt.get('output_base')==str(base)
            and receipt.get('descendants_empty') is True and 'controller_failure' in receipt
            and receipt['controller_failure'] is None
            and receipt.get('profile')=='standard' and receipt.get('manager')=='system'
            and receipt.get('cache_reuse_requested') is False)
        preparation=receipt.get('yoga_public_artifact_preparation')
        require(type(preparation) is dict
            and preparation.get('scope')=='yoga-current-public-toolbar-retained-v1'
            and preparation.get('cached_candidate_input_only') is True
            and preparation.get('verified_after_cleanup') is True
            and preparation.get('original_entry_monotonic_ns')==creator['entryNs']
            and preparation.get('original_deadline_monotonic_ns')==creator['deadlineNs']
            and type(preparation.get('original_entry_monotonic_ns')) is int
            and type(preparation.get('original_deadline_monotonic_ns')) is int
            and type(preparation.get('action_jobs')) is int and preparation['action_jobs']==1 and preparation.get('original_runfiles_retained_only') is True
            and preparation.get('fresh_consumer_qualification_required') is True
            and preparation.get('execution_authority') is False and preparation.get('seat_qualified') is False
            and preparation.get('toolbar_consent_proved') is False)
        require(type(retirement) is dict and type(retirement.get('schema')) is int and retirement['schema']==1
            and retirement.get('policy')=='bounded-post-terminal-fixed-owned-children-v2'
            and retirement.get('state')=='complete' and retirement.get('reason')=='qualified-terminal'
            and retirement.get('receipt_sha256')==selected['producerReceipt']['sha256']
            and retirement.get('retained_output_contract')==[prepared.LABEL]
            and type(retirement.get('children')) is dict
            and retirement['children'].get('output-base')=='retained-declared-producer')
        budget=retirement.get('budget')
        require(type(budget) is dict and type(budget.get('original_entry_monotonic_ns')) is int
            and type(budget.get('original_deadline_monotonic_ns')) is int
            and budget['original_entry_monotonic_ns']==creator['entryNs']
            and budget.get('original_deadline_monotonic_ns')==creator['deadlineNs'])
        physical=retirement.get('retained_physical_root')
        require(type(physical) is dict and set(physical)=={'device','inode'}
            and all(type(item) is int and item>=0 for item in physical.values())
            and base.lstat().st_dev==physical['device'] and base.lstat().st_ino==physical['inode'])
        inputs=prepared.Inputs(clock,base,creator['sourceRoot'])
        product=base/'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_public_artifact_prepare_producer/test.outputs/yoga-public-toolbar'
        artifact_raw=metadata.open(product/'artifact.json',prepared.MAX_METADATA,expected=selected['artifact'])
        artifact=prepared.decode(artifact_raw)
        require(type(artifact) is dict and set(artifact)==DESCRIPTOR_FIELDS
            and type(artifact['schemaVersion']) is int and artifact['schemaVersion']==2
            and artifact['scope']==prepared.SCOPE and artifact['context']==creator
            and artifact['retentionMode']=='original-output-base-and-declared-runfiles-only'
            and artifact['originalOutputBase']==str(base) and artifact['runnerLabel']==prepared.RUNNER
            and artifact['originalOuterReceiptJoinRequired'] is True
            and artifact['freshConsumerQualificationRequired'] is True
            and all(artifact[flag] is False for flag in prepared.FALSE))
        inventory_raw=metadata.open(product/'runfiles-inventory.json',prepared.MAX_METADATA,
            expected={'sha256':artifact['inventorySha256'],'bytes':artifact['inventoryBytes']})
        clock.tick();wire=prepared.json_decode(inventory_raw)
        inventory=prepared.inventory_expand(wire,clock)
        require(inventory['context']==creator and inventory['originalOutputBase']==str(base)
            and inventory['originalRunfilesRoot']==artifact['originalRunfilesRoot']
            and inventory['originalControlRunfilesRoot']==artifact['originalControlRunfilesRoot'])
        controls=absolute(artifact['originalControlRunfilesRoot']);runfiles=absolute(artifact['originalRunfilesRoot'])
        physical_root=base/'execroot/_main/bazel-out/k8-fastbuild/bin/delivery'
        require(controls==physical_root/'yoga_public_artifact_prepare_producer.sh.runfiles'
            and runfiles==physical_root/'yoga_toolbar_consent_proof.sh.runfiles')
        inputs.hold_directory(controls);inputs.hold_directory(runfiles)
        commitments=artifact['directoryWitnesses']
        require(type(commitments) is list and len(commitments)==4)
        for record in commitments:
            require(type(record) is dict and set(record)=={'path','witness'})
            absolute(record['path']);fact=record['witness']
            require(type(fact) is list and len(fact)==9
                and all(type(number) is int and 0<=number<2**128 for number in fact[:7])
                and all(type(number) is int and -2**127<=number<2**127 for number in fact[7:]))
        fresh_directories=inputs.directory_commitments()
        # Original timestamp/size/link counts remain provenance: a fresh Bazel
        # phase may legitimately change root child metadata. Original identity
        # and custody never change; CURRENT full-nine stays pinned through all
        # remaining tuple IO and final held/named/post-close checks.
        require([{'path':row['path'],'witness':row['witness'][:5]} for row in commitments]
            ==[{'path':row['path'],'witness':row['witness'][:5]} for row in fresh_directories])
        declared=artifact['declaration'];require(type(declared) is dict)
        declaration_path=physical_root/'yoga_public_artifact_inputs.json'
        declaration_raw=inputs.read('declaration',controls/'_main/delivery/yoga_public_artifact_inputs.json',
            declaration_path,content=True,maximum=prepared.MAX_METADATA)
        require(inputs.rows['declaration']==declared and inventory['declarationSha256']==declared['sha256'])
        declaration,files=prepared.declaration(declaration_raw,creator)
        rows={row['key']:row for row in inventory['files']}
        require(inventory['roles']==declaration['roles'] and inventory['declaredFileCount']==len(files)
            and set(rows)==set(files)|({'_repo_mapping'} if declaration['repoMappingKey'] is not None else set())
            and artifact['roles']=={role:rows[key] for role,key in declaration['roles'].items()})
        data={};execroot=base/'execroot/_main'
        for role in ('native_manifest','native_store_paths','runtime_authority'):
            key=declaration['roles'][role]
            data[role]=inputs.read(key,controls/key,execroot/files[key]['executionPath'],content=True,maximum=16*1024**2)
            require(inputs.rows[key]==rows[key])
        browser=prepared.runtime.validate_authority(data['runtime_authority'])
        roots=data['native_store_paths'].decode('ascii').splitlines();require(roots==sorted(set(roots)))
        inputs.add_nix_roots(sorted(set(roots)|set(browser['storePaths'])))
        # Revisit EVERY original alias, including an original action alias that
        # is not needed by this receiver's own argv. Missing ephemeral aliases
        # refuse; prior observations never supply current physical custody.
        original_links={row['path']:row for row in inventory['symlinks']}
        for path,row in original_links.items():
            clock.tick();named=absolute(path)
            require(inputs.allowed(named) and stat.S_ISLNK(named.lstat().st_mode)
                and list(prepared.witness(named.lstat()))==row['witness']
                and os.readlink(named)==row['target'])
            inputs.resolve(named)
        for path,(fact,target) in inputs.links.items():
            require(path in original_links and list(fact)==original_links[path]['witness']
                and target==original_links[path]['target'])
        key=declaration['roles']['runner_manifest']
        data['runner_manifest']=inputs.read(key,controls/key,execroot/files[key]['executionPath'],content=True,maximum=prepared.MAX_METADATA)
        require(inputs.rows[key]==rows[key]);manifest=prepared.runfiles_manifest(data['runner_manifest'],clock)
        require(set(manifest)-{'_repo_mapping'}=={key for key,row in files.items() if row['inRunner']})
        mapping=declaration['repoMappingKey'];require(('_repo_mapping' in manifest)==(mapping is not None))
        if mapping is not None:
            expected=execroot/files[mapping]['executionPath']
            require(expected.is_relative_to(base) and inputs.resolve(manifest['_repo_mapping'])==inputs.resolve(expected))
            for key,alias in ((mapping,controls/mapping),('_repo_mapping',runfiles/'_repo_mapping')):
                inputs.read(key,alias,expected,maximum=prepared.MAX_METADATA);require(inputs.rows[key]==rows[key])
        roles={key:role for role,key in declaration['roles'].items()}
        for key,row in files.items():
            clock.tick()
            if key in inputs.rows:
                if row['inRunner']:
                    require(inputs.resolve(runfiles/key)==Path(rows[key]['physical'])
                        and inputs.resolve(manifest[key])==Path(rows[key]['physical']))
                continue
            role=roles.get(key);executable=role in ('chromium','node')
            maximum=prepared.pack.MAX_BYTES if role=='bundle' else 4*1024**2 if role=='extension' else prepared.MAX_FILE if executable or role is None else 16*1024**2
            raw=inputs.read(key,(runfiles if row['inRunner'] else controls)/key,execroot/row['executionPath'],
                aliases=(manifest[key],) if row['inRunner'] else (),content=role is not None and not executable,maximum=maximum)
            require(inputs.rows[key]==rows[key])
            if role is not None:data[role]=raw
        require(prepared.tuple_metadata(data,declaration)==artifact['metadata'])
        links=[{'path':path,'witness':list(fact),'target':target} for path,(fact,target) in sorted(inputs.links.items())]
        require(links==inventory['symlinks'] and inputs.directory_commitments()==fresh_directories)
        inputs.recheck();metadata.recheck();clock.tick()
        result={'schemaVersion':1,'scope':SCOPE,'currentContext':current,'producerContext':creator,
            'selectionSha256':selection_sha256,'artifactSha256':selected['artifact']['sha256'],
            'inventorySha256':artifact['inventorySha256'],'inventoryBytes':artifact['inventoryBytes'],
            'producerReceiptSha256':selected['producerReceipt']['sha256'],'retirementSha256':selected['retirement']['sha256'],
            'verifiedFileCount':len(rows),'verifiedSymlinkCount':len(links),'verifiedDirectoryCount':4,
            'fullBytesRehashed':True,'originalPhysicalRootsMatched':True,'freshPhysicalReadback':True,
            'originalDirectoryIdentityMatched':True,'freshDirectoryWitnesses':fresh_directories,
            **{flag:False for flag in prepared.FALSE},'freshConsumerQualificationRequired':True,
            'humanToolbarConsentRequired':True,'candidateRunnerExecuted':False}
    except BaseException as error:primary=error;raise
    finally:
        first=None
        for owner in (inputs,metadata):
            if owner is None:continue
            try:owner.close(primary)
            except BaseException as error:
                if first is None:first=error
        if first is not None:
            if primary is not None:raise primary from first
            raise first
        if primary is None:
            # No owner may perform another FD close after either role's last
            # named fence. The joint post-drain checks cover mutations caused by
            # later metadata closure after Inputs.close's own readback.
            inputs.recheck(held=False);metadata.recheck(held=False);clock.tick()
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.parse_args()
    environment=os.environ
    require({name[len(VARIABLE):] for name in environment if name.startswith(VARIABLE)}==FIELDS)
    current={'epoch':environment[VARIABLE+'EPOCH'],'entryNs':int(environment[VARIABLE+'ENTRY_NS']),
        'deadlineNs':int(environment[VARIABLE+'DEADLINE_NS']),'sourceCommit':environment[VARIABLE+'SOURCE_COMMIT'],
        'graphSha256':environment[VARIABLE+'GRAPH_SHA256'],'sourceRoot':environment[VARIABLE+'SOURCE_ROOT']}
    result=qualify(environment[VARIABLE+'SELECTION_PATH'],environment[VARIABLE+'SELECTION_SHA256'],current)
    clock=prepared.Clock(current);clock.tick()
    sys.stdout.write(prepared.canonical(result).decode('ascii'));sys.stdout.flush();clock.tick()
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError,MemoryError):
        print('toolbar-public-receiver-refused',file=sys.stderr);sys.exit(125)
