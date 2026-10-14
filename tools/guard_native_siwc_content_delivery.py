"""Sequential, owned local delivery; SOURCE's original600 is never renewed.

Only bounded metadata crosses the coordinator. The declared delivery action owns
all SOURCE/HUB copy, current member proof and fresh transport publication under
original1170. These observations are not a transferred Python proof capability.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import guard_native_siwc_catalog_content_source_reserved as policy

MAX_METADATA=8*1024*1024
FALSE_FLAGS=('original_action_sdk_custody_inherited','source_qualification_extended',
    'sdk_execution_qualified','compiler_qualified','native_runtime_qualified',
    'ordinary_launch_qualified','continuity_qualified')


class DeliveryRefused(ValueError):
    """Actual bounded observations, never an ownership capability or raw error."""
    def __init__(self,checkpoint,observation):
        super().__init__('native-content-delivery-refused')
        self.checkpoint,self.observation=checkpoint,observation


def owned_empty(observation):
    if observation.get('started') is False: return True
    if observation.get('started') is not True: return False
    cleanup=observation.get('cleanup',{})
    return (cleanup.get('state')=='empty' and cleanup.get('ownership')=='verified'
        and type(cleanup.get('readback_attempts')) is int and cleanup['readback_attempts']>=2)


def aggregate_empty(source_empty,observation):
    return source_empty is True and owned_empty(observation)


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def unique(rows):
    value={}
    for key,item in rows:
        policy.require(key not in value); value[key]=item
    return value


def tick(entry,until):
    policy.require(type(entry) is int and type(until) is int and until-entry==1200*10**9
        and entry <= time.monotonic_ns() < until-30*10**9)


class Owned(list):
    """Enrolled descriptors drain once; uninserted failures close immediately."""
    def enroll(self,fd):
        try:
            self.append(fd)
        except BaseException as error:
            # An interrupted/failed append may have inserted before raising.
            # That descriptor remains owned by the enclosing final drain.
            # If insertion never happened, retire it here exactly once.
            if fd not in self:
                try: os.close(fd)
                except BaseException as cleanup: raise error from cleanup
            raise
        return fd


def _drain(owned,primary=None):
    failure=None
    while owned:
        fd=owned.pop()  # detach before the attempt; unknown close is never retried.
        try: os.close(fd)
        except BaseException as error:
            if failure is None: failure=error
    if failure is not None:
        if primary is not None: raise primary from failure
        raise failure


def parent_join(path,fd,anchor):
    policy.require(path.resolve(strict=True)==path
        and anchor==policy._witness(os.fstat(fd))==policy._witness(os.stat(path,follow_symlinks=False)))


def closed_parent_join(path,anchor):
    policy.require(path.resolve(strict=True)==path
        and anchor==policy._witness(os.stat(path,follow_symlinks=False)))


def read_metadata(path,*,entry,until,mode=0o600,maximum=MAX_METADATA,pin=None):
    """Bounded nofollow read, full named/held witness and EOF after actual IO."""
    tick(entry,until); path=Path(path); owned=Owned(); primary=None
    try:
        parent=policy.cache.trusted_directory(path.parent); owned.enroll(parent)
        parent_anchor=policy._witness(os.fstat(parent)); parent_join(path.parent,parent,parent_anchor)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent); owned.enroll(fd)
        anchor=policy._witness(os.fstat(fd))
        policy.require(stat.S_ISREG(anchor[4]) and anchor[2]==os.getuid() and anchor[5]==1
            and stat.S_IMODE(anchor[4])==mode and 0<anchor[6]<=maximum
            and anchor==policy._witness(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
        blocks=[]; count=0
        while True:
            tick(entry,until); block=os.read(fd,65536)
            if not block: break
            count+=len(block); policy.require(count<=anchor[6]); blocks.append(block)
        raw=b''.join(blocks)
        policy.require(count==anchor[6] and (pin is None or hashlib.sha256(raw).hexdigest()==pin)
            and anchor==policy._witness(os.fstat(fd))==policy._witness(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
        parent_join(path.parent,parent,parent_anchor)
        return json.loads(raw,object_pairs_hook=unique),raw,anchor
    except BaseException as error: primary=error; raise
    finally:
        _drain(owned,primary)
        # Failure already refuses publication. A terminal clock error must
        # not replace its first cause after all close attempts succeed.
        if primary is None:
            closed_parent_join(path.parent,parent_anchor)
            policy.require(anchor==policy._witness(os.stat(path,follow_symlinks=False)))
            closed_parent_join(path.parent,parent_anchor)
            tick(entry,until)


def write_metadata(run,name,value,mode,entry,until):
    tick(entry,until); raw=encoded(value); policy.require(len(raw)<=MAX_METADATA)
    owned=Owned(); primary=None
    try:
        parent=policy.cache.trusted_directory(run); owned.enroll(parent)
        parent_before=policy._witness(os.fstat(parent)); parent_join(run,parent,parent_before)
        fd=os.open(name,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent); owned.enroll(fd)
        position=0
        while position<len(raw):
            tick(entry,until); written=os.write(fd,raw[position:]); policy.require(written>0); position+=written
        os.fchmod(fd,mode); os.fsync(fd); os.fsync(parent)
        witness=policy._witness(os.fstat(fd))
        policy.require(witness[2]==os.getuid() and witness[5]==1 and stat.S_IMODE(witness[4])==mode
            and os.pread(fd,len(raw)+1,0)==raw
            and witness==policy._witness(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        parent_anchor=policy._witness(os.fstat(parent))
        # Creating this one regular leaf changes directory size/timestamps;
        # its original inode/owner/gid/mode/link count may not be rebased.
        policy.require(parent_anchor[:6]==parent_before[:6])
        parent_join(run,parent,parent_anchor)
        return {'path':name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    except BaseException as error: primary=error; raise
    finally:
        _drain(owned,primary)
        # Failure already refuses publication. A terminal clock error must
        # not replace its first cause after all close attempts succeed.
        if primary is None:
            closed_parent_join(run,parent_anchor)
            policy.require(witness==policy._witness(os.stat(run/name,follow_symlinks=False)))
            closed_parent_join(run,parent_anchor)
            tick(entry,until)


def source_checkpoint(run,lease,source,entry,until):
    """Only verified genuine SOURCE success can create the delivery handoff."""
    tick(entry,until)
    policy.require(type(lease) is policy.ContentDependencyLease and lease.capture_ready
        and source['exit']==0 and source['workload_exit']==0
        and source['targets']==policy.ARGUMENTS[1:] and source['profile']==policy.PROFILE
        and source['descendants_empty'] is True and source['cleanup']['state']=='empty'
        and source['cleanup']['ownership']=='verified' and source['cleanup']['readback_attempts']>=2
        and source['test_evidence']['state']=='preserved'
        and source['native_siwc_catalog_content_source_reservation']['verified_after_cleanup'] is True
        and source['source_commit']==lease.source_commit and source['graph_sha256']==lease.graph_sha256)
    context={'MODE':policy.INPUT_MODE,'ENTRY_NS':str(entry),'DEADLINE_NS':str(until),
        'EPOCH':str(run),'SOURCE_COMMIT':lease.source_commit,'GRAPH_SHA256':lease.graph_sha256}
    clocks={'source_until_ns':entry+600*10**9,'work_until_ns':until-30*10**9,'outer_until_ns':until}
    checkpoint={key:source[key] for key in ('id','profile','targets','source_commit','graph_sha256','exit',
        'workload_exit','epoch_start_ns','command','limits','worker','cleanup','descendants_empty',
        'test_evidence','native_siwc_catalog_content_source_reservation')}
    checkpoint.update(schema_version=1,kind='omux-native-siwc-content-source-phase-v1',context=context,clocks=clocks,
        output_base=str(lease.output_base),cache_reuse_requested=True,cache_policy=2,cache_key=lease.key,
        dependency_lease=lease.facts())
    policy.require(checkpoint['id']==run.name)
    manifest,raw,_=read_metadata(run/'test-evidence.json',entry=entry,until=until,pin=source['test_evidence']['sha256'])
    rows=[row for row in manifest['results'] if row['target']==policy.ARGUMENTS[2]]
    policy.require(len(rows)==1 and rows[0]['state']=='observed'
        and {row['target'] for row in manifest['results']}==set(policy.ARGUMENTS[1:])
        and len(manifest['results'])==2)
    configuration=rows[0]['configuration']
    policy.require(type(configuration) is str and configuration and '/' not in configuration
        and configuration not in ('.','..') and not any(char.isspace() for char in configuration))
    checkpoint_pin=write_metadata(run,'source-phase-receipt.json',checkpoint,0o600,entry,until)
    request={'schema_version':1,'kind':'omux-native-siwc-content-delivery-request-v1','context':context,
        'clocks':clocks,'dependency_lease':lease.facts(),'source_phase_receipt_sha256':checkpoint_pin['sha256'],
        'test_evidence_sha256':hashlib.sha256(raw).hexdigest(),'configuration':configuration}
    request_pin=write_metadata(run,'native-content-delivery-request.json',request,0o400,entry,until)
    lease.fence(); tick(entry,until)
    return checkpoint_pin,request,request_pin


def publication_descriptor(run,lease,request,entry,until):
    """Read actual transport metadata only, after independently owned cleanup."""
    path=run/'native-content-retained/publication-receipt.json'
    # The worker seals this parent555; trusted_directory is700 by design, so
    # enroll through the already trusted run and join the named child explicitly.
    owned=Owned(); primary=None
    try:
        tick(entry,until); runfd=policy.cache.trusted_directory(run); owned.enroll(runfd)
        run_anchor=policy._witness(os.fstat(runfd)); parent_join(run,runfd,run_anchor)
        parent=os.open('native-content-retained',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=runfd); owned.enroll(parent)
        parent_anchor=policy._witness(os.fstat(parent))
        policy.require(parent_anchor[2]==os.getuid() and stat.S_IMODE(parent_anchor[4])==0o555
            and parent_anchor==policy._witness(os.stat('native-content-retained',dir_fd=runfd,follow_symlinks=False)))
        fd=os.open('publication-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent); owned.enroll(fd)
        anchor=policy._witness(os.fstat(fd))
        policy.require(stat.S_ISREG(anchor[4]) and anchor[2]==os.getuid() and anchor[5]==1
            and stat.S_IMODE(anchor[4])==0o444 and 0<anchor[6]<=MAX_METADATA)
        blocks=[]; count=0
        while True:
            tick(entry,until); block=os.read(fd,65536)
            if not block: break
            count+=len(block); policy.require(count<=anchor[6]); blocks.append(block)
        raw=b''.join(blocks); receipt=json.loads(raw,object_pairs_hook=unique)
        expected={'schema_version','kind','scope','context','clocks','dependency_lease',
            'source_phase_receipt_sha256','test_evidence_sha256','original_action','publication',*FALSE_FLAGS}
        policy.require(set(receipt)==expected and receipt['schema_version']==1
            and receipt['kind']=='omux-native-siwc-content-retained-publication-v1'
            and receipt['scope']=='operational-fresh-source-hub-delivery-only'
            and receipt['context']==request['context'] and receipt['clocks']==request['clocks']
            and receipt['dependency_lease']==request['dependency_lease']==lease.facts()
            and receipt['source_phase_receipt_sha256']==request['source_phase_receipt_sha256']
            and receipt['test_evidence_sha256']==request['test_evidence_sha256']
            and all(receipt[key] is False for key in FALSE_FLAGS)
            and receipt['publication']['root']==str(path.parent/'native-siwc-catalog-content-source'))
        policy.require(count==anchor[6] and anchor==policy._witness(os.fstat(fd))==policy._witness(
            os.stat('publication-receipt.json',dir_fd=parent,follow_symlinks=False))
            and parent_anchor==policy._witness(os.fstat(parent))==policy._witness(
                os.stat('native-content-retained',dir_fd=runfd,follow_symlinks=False)))
        parent_join(run,runfd,run_anchor)
        origin=receipt['original_action']
        return {'kind':receipt['kind'],'root':receipt['publication']['root'],
            'transport_receipt':{'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},
            'source_receipt':{'sha256':origin['source_receipt_sha256'],'bytes':origin['source_receipt_bytes'],
                'inventory_sha256':origin['inventory_sha256']},'context':receipt['context'],
            'source_phase_receipt_sha256':receipt['source_phase_receipt_sha256'],
            'test_evidence_sha256':receipt['test_evidence_sha256'],'original_action_sdk_custody_inherited':False}
    except BaseException as error: primary=error; raise
    finally:
        _drain(owned,primary)
        # Failure already refuses publication. A terminal clock error must
        # not replace its first cause after all close attempts succeed.
        if primary is None:
            closed_parent_join(run,run_anchor)
            closed_parent_join(path.parent,parent_anchor)
            policy.require(anchor==policy._witness(os.stat(path,follow_symlinks=False)))
            closed_parent_join(path.parent,parent_anchor)
            closed_parent_join(run,run_anchor)
            tick(entry,until)


def execute_delivery(api,*,call,run,lease,source,resident,entry,until,bazel,python,runner,control,
                     environment,isolation,repository_cache,nixpkgs_source):
    """Actual separate manager invocation; no producer bytes copied by parent."""
    tick(entry,until); policy.require(type(lease) is policy.ContentDependencyLease)
    policy.require(source['cleanup']['state']=='empty' and source['cleanup']['ownership']=='verified'
        and source['cleanup']['readback_attempts']>=2 and source['descendants_empty'] is True)
    # Allocate direct run children before the worker holds the metadata parent9.
    for name in ('native-content-retained','delivery-output-base','delivery-user-root','delivery-evidence'):
        os.mkdir(run/name,mode=0o700)
    root=run/'delivery-evidence'
    checkpoint,request,request_pin=source_checkpoint(run,lease,source,entry,until)
    identity,unit=policy.delivery_identity(run)
    sample=time.monotonic_ns(); seconds=policy.delivery_seconds(entry,until,sample_ns=sample)
    command,_=policy.delivery_command(api.bazel_command,bazel,run,entry,until,request_pin['sha256'],
        source_commit=lease.source_commit,graph_sha256=lease.graph_sha256,seconds=seconds,sample_ns=sample,
        repository_cache=repository_cache,nixpkgs_source=nixpkgs_source)
    settings=dict(api.PROPERTIES); settings.update(isolation)
    for key in ('CPUQuotaPerSecUSec','RuntimeMaxUSec','TimeoutStopUSec'): settings.pop(key)
    settings.update(MemoryMax=str(policy.MEMORY),MemorySwapMax='0',TasksMax=str(policy.TASKS),CPUQuota='190%',
        RuntimeMaxSec=str(seconds),TimeoutStopSec='10',RemainAfterExit='yes',User=str(os.getuid()),
        Group=str(os.getgid()),PrivateUsers='no',CapabilityBoundingSet='',AmbientCapabilities='',StandardInput='null',
        ProtectSystem='strict',ReadWritePaths=' '.join(str(run/name) for name in
            ('native-content-retained','delivery-output-base','delivery-user-root','delivery-evidence')),
        BindReadOnlyPaths=str(lease.state_root/lease.name)+' '+str(lease.checkout))
    launch=[runner,'--system','--no-block','--unit='+unit,'--property=Type=exec',
        '--property=StandardOutput=null','--property=StandardError=null','--property=WorkingDirectory='+str(lease.checkout),
        '--property=TemporaryFileSystem='+api.system_masks(profile='standard'),
        '--property=UnsetEnvironment='+' '.join(api.DELEGATION_ENV),'--setenv=OMUX_EXECUTION_GUARD='+str(root)]
    launch+=['--setenv='+key+'='+value for key,value in environment.items()]
    launch+=['--property='+key+'='+value for key,value in settings.items()]
    launch+=[python,str(Path(api.__file__).resolve()),'--worker',str(root),'--']+command
    pin=worker=None; started=False; actual={}; pid=ticks=None; status=125
    cleanup={'state':'not-started','ownership':'unproved','readback_attempts':0}
    worker_facts=None; primary=None; wall=None; phase='startup'; release_failed=False
    def readback(timeout=api.CONTROLLER_TIMEOUT,absolute=None,phase='delivery'):
        return api.properties(call([control,'--system','show','--all',unit],operation='unit-readback',
            phase=phase,timeout=timeout,deadline=absolute))
    try:
        resident.observe(); lease.fence(); tick(entry,until)
        started=True
        call(launch,operation='launch',phase='delivery',authenticate=True)
        actual,_=api.await_startup(readback)
        policy.require(actual.get('ActiveState')=='active' and actual.get('Id')==unit
            and actual.get('ControlGroup','').startswith('/') and Path(actual['ControlGroup']).name==unit
            and '..' not in Path(actual['ControlGroup']).parts)
        cgroup=Path('/sys/fs/cgroup')/actual['ControlGroup'].lstrip('/')
        policy.require(not any(row=='0::'+actual['ControlGroup'] or row.startswith('0::'+actual['ControlGroup']+'/')
            for row in Path('/proc/self/cgroup').read_text().splitlines()))
        pin=api.CgroupPin(cgroup); pid=int(actual['MainPID']); ticks=api.process_start_ticks(pid)
        api.verify(actual,cgroup,'system',isolation,policy.PROFILE,runtime_seconds=seconds)
        api.unit_epoch_identity(actual,unit=unit,manager='system',run=root,python=python,worker=str(Path(api.__file__).resolve()))
        api.system_identity(actual,pid)
        policy.require(actual.get('ProtectSystem')=='strict'
            and set(actual.get('ReadWritePaths','').split())==set(settings['ReadWritePaths'].split())
            and set(actual.get('BindReadOnlyPaths','').split())==set(settings['BindReadOnlyPaths'].split())
            and {key+'='+value for key,value in environment.items()}.issubset(set(actual.get('Environment','').split())))
        worker=policy.WorkloadWitness(policy.PROFILE,entry,until,pin,actual,pid,ticks)
        worker_facts={'unit':unit,'invocation':worker.invocation,'pid':pid,'start_ticks':ticks,
            'cgroup':str(pin.path),'kernel_bounds':dict(worker.bounds)}
        resident.observe(); lease.fence(); tick(entry,until)
        wall=time.time_ns(); (root/'go').touch(mode=0o600,exist_ok=False)
        def iteration():
            tick(entry,until); resident.observe(); lease.fence(); api.check_free_space(run.parent)
        phase='monitor'
        status=policy.monitor(policy.PROFILE,worker,readback,(until-30*10**9)/10**9,iteration)
        worker_facts={'unit':unit,'invocation':worker.invocation,'pid':pid,'start_ticks':ticks,
            'cgroup':str(pin.path),'kernel_bounds':dict(worker.bounds)}
    except BaseException as error: primary=error
    finally:
        close_error=None
        if started:
            cleanup_until=min(time.monotonic()+api.CLEANUP_SECONDS,until/10**9)
            def authorize(owned):
                nonlocal pin,pid,ticks
                if pin is None:
                    pin,pid,ticks=api.capture_cleanup_pin(owned,unit=unit,manager='system',run=root,
                        python=python,worker=str(Path(api.__file__).resolve()))
                    return False
                api.unit_epoch_identity(owned,unit=unit,manager='system',run=root,python=python,worker=str(Path(api.__file__).resolve()))
                if worker is not None: worker.authorize_cleanup(owned)
                else: api.authorize_cleanup(owned,unit=unit,manager='system',run=root,python=python,
                    worker=str(Path(api.__file__).resolve()),cgroup=pin.path,original_pid=pid,original_ticks=ticks)
            try:
                cleanup=policy.cleanup_retained(deadline=cleanup_until,
                    readback=lambda timeout,absolute:readback(timeout,absolute,'cleanup'),authorize=authorize,
                    stop=lambda timeout,absolute:call([control,'--system','stop',unit],operation='unit-stop',
                        phase='cleanup',authenticate=True,timeout=timeout,deadline=absolute),
                    observe=lambda:pin.observe() if pin is not None else 'uncaptured')
            except BaseException as error:
                close_error=error
                if primary is None: phase='cleanup'
        for owned in (worker,pin):
            if owned is not None:
                try: owned.close()
                except BaseException as error:
                    if close_error is None: close_error=error
        if close_error is not None:
            release_failed=True
            if primary is None: primary=close_error; phase='resource-release'
    observation={'command':command,'unit':unit,'started':started,'worker':worker_facts,
        'cleanup':cleanup,'test_evidence':{'state':'not-preserved'},'exit':125,'workload_exit':status,
        'effective_timeout_seconds':seconds,'timeout_sample_monotonic_ns':sample,'phase':phase}
    # Preserve bounded copied evidence even for a failed monitor/body. The
    # original first phase remains the refusal reason; no failure becomes0.
    if wall is not None and owned_empty(observation):
        try:
            tick(entry,until)
            evidence=api.capture_test_evidence(run/'delivery-output-base',root,policy.DELIVERY_ARGUMENTS[1:],status,wall)
            policy.require(len(evidence['results'])==1 and evidence['results'][0]['target']==policy.DELIVERY_ARGUMENTS[1]
                and evidence['results'][0]['state']=='observed'
                and all(any(file['source']==name and file['state']=='copied' for file in evidence['results'][0]['files'])
                    for name in ('test.log','test.xml')))
            _,raw,_=read_metadata(root/'test-evidence.json',entry=entry,until=until)
            observation['test_evidence']={'state':'preserved','manifest':'delivery-evidence/test-evidence.json',
                'sha256':hashlib.sha256(raw).hexdigest(),'bytes':evidence['bytes'],'files':evidence['copied_files']}
        except BaseException as error:
            if primary is None: primary=error; observation['phase']='evidence'
    if primary is not None or release_failed or not owned_empty(observation):
        raise DeliveryRefused(checkpoint,observation) from primary
    try:
        policy.require(status==0 and wall is not None and worker_facts is not None
            and observation['test_evidence']['state']=='preserved')
        resident.observe(); lease.fence(); tick(entry,until)
        phase=observation['phase']='publication'
        descriptor=publication_descriptor(run,lease,request,entry,until)
        read_metadata(run/'source-phase-receipt.json',entry=entry,until=until,pin=checkpoint['sha256'])
        read_metadata(run/'native-content-delivery-request.json',entry=entry,until=until,mode=0o400,pin=request_pin['sha256'])
        resident.observe(); lease.fence(); tick(entry,until)
        observation.update(exit=0,phase='complete')
        return checkpoint,descriptor,observation
    except BaseException as error:
        raise DeliveryRefused(checkpoint,observation) from error
