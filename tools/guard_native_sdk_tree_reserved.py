"""Distinct two-cohort artifact custody; cached bytes never SDK authority.

The old content-source profile, lease and transported SDK route stay unchanged.
This parent owner serializes the new checkout namespace; child SDK consumers
independently prove declared bytes under their original SOURCE600 admission.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from decimal import Decimal
import xml.etree.ElementTree as ET
import guard_cache as cache
import guard_native_seed_plan_reserved as kernel
import guard_native_siwc_catalog_content_source_reserved as old

PRODUCER = 'native-sdk-tree-producer-reserved'
SOURCE_PROFILE = 'native-retained-sdk-tree-source-reserved'
PROFILES = (PRODUCER, SOURCE_PROFILE)
TARGET = '//tools:codex_native_retained_sdk_tree_producer'
COHORTS = {PRODUCER: ['test', TARGET], SOURCE_PROFILE: ['test',
    '//tools:codex_native_siwc_catalog_tree_source_test',
    '//tools:codex_native_siwc_catalog_tree_source_producer']}
FAMILY = 'fixed-retained-sdk-tree-dependency-state-v1'
LAYOUT = 'tools/codex_native_retained_sdk_tree_materialized/sdk-tree-public'
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness, WorkloadWitness = kernel.Witness, kernel.WorkloadWitness
properties, cleanup_retained = kernel.properties, kernel.cleanup_retained
monitor, release_worker = kernel.monitor, kernel.release_worker
remaining = kernel.remaining


def require(value):
    if value is not True: raise ValueError('retained-sdk-tree-reservation-refused')


def pin(value, size=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None)
    return value


def selected(profile, arguments):
    require(profile in PROFILES and arguments == COHORTS[profile])
    return {'PrivateNetwork':'yes'}


def request(args, arguments):
    if args.profile not in PROFILES: return False
    selected(args.profile,arguments)
    allowed = {'profile','manager','arguments','python','systemd_run','systemctl','bazel',
        'closure','bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty',
        'state_dir','initialize_state_dir','coordination_dir','become_file',
        'reuse_owned_cache','repository_cache','nixpkgs_source'}
    require(args.manager == 'system' and args.reuse_owned_cache is True
        and not any(value for name,value in vars(args).items() if name not in allowed)
        and args.source_dirty == 'false')
    pin(args.source_commit,40)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache,args.nixpkgs_source)
    return True


def policy(profile):
    require(type(profile) is dict and type(profile.get('execution')) is dict)
    # Exact checkout/toolchain/isolation still enter stable_fingerprint. Only
    # these two declared cohorts share the namespace; epochs are evidence.
    return {**profile,'artifact_family':FAMILY,'cohorts':COHORTS,
        'execution':{**profile['execution'],'source_convenience_symlinks':'ignore'}}


def runtime_seconds(profile,entry,deadline):
    require(profile in PROFILES)
    return min(1170 if profile == PRODUCER else 840,int(remaining(entry,deadline)))


BOOT_ID_PATH = Path('/proc/sys/kernel/random/boot_id')


def current_boot_id(entry,deadline,profile=PRODUCER):
    """Fixed bounded kernel clock-domain role, projected as a declared input.

    SDK actions do not read this host path. No caller boot value/path or cached
    receipt can supply the current role. All opened descriptors drain once.
    """
    require(profile in PROFILES and type(entry) is int and type(deadline) is int and deadline-entry == 1200*10**9)
    cutoff=entry+(1170 if profile == PRODUCER else 600)*10**9
    require(entry <= time.monotonic_ns() < cutoff)
    parts=BOOT_ID_PATH.parts[1:]
    slots=[None]*(len(parts)+1)
    primary=None;raw=None
    try:
        slots[0]=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        for index,part in enumerate(parts):
            require(entry <= time.monotonic_ns() < cutoff)
            parent=slots[index]
            final=index == len(parts)-1
            before=old._witness(os.stat(part,dir_fd=parent,follow_symlinks=False))
            if not final:before=before[:5]  # kernel directories: stable identity, as core.Root
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
            if not final:flags |= os.O_DIRECTORY
            slot=index+1  # compute the preallocated owner index before acquisition
            slots[slot]=os.open(part,flags,dir_fd=parent)
            held=old._witness(os.fstat(slots[slot]))
            named=old._witness(os.stat(part,dir_fd=parent,follow_symlinks=False))
            if not final:held,named=held[:5],named[:5]
            require(before == held == named)
            require(held[2] in (0,os.getuid()))
            if final:
                require(stat.S_ISREG(held[4]) and stat.S_IMODE(held[4]) == 0o444 and held[5] == 1
                    and 0 <= held[6] <= 128)
                raw=os.pread(slots[index+1],129,0)
                require(0 < len(raw) <= 128 and os.pread(slots[index+1],129,0) == raw
                    and old._witness(os.fstat(slots[index+1])) == held
                    == old._witness(os.stat(part,dir_fd=parent,follow_symlinks=False)))
            else:
                require(stat.S_ISDIR(held[4]) and (not held[4]&0o022 or bool(held[4]&stat.S_ISVTX)))
        token=raw.decode('ascii')
        require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n',token) is not None)
        require(entry <= time.monotonic_ns() < cutoff)
    except BaseException as error:primary=error
    cleanup=None
    for index in range(len(slots)-1,-1,-1):
        fd,slots[index]=slots[index],None
        if fd is not None:
            try:os.close(fd)
            except BaseException as error:
                if cleanup is None:cleanup=error
    if primary is not None:
        if cleanup is not None:raise primary from cleanup
        raise primary
    if cleanup is not None:raise cleanup
    require(entry <= time.monotonic_ns() < cutoff)
    return token[:-1]


def verify_runtime(value,seconds):
    require(type(seconds) is int and 1 <= seconds <= 1170)
    from yoga_delivery_settings import effective_runtime
    effective_runtime(value,seconds)


def command(builder,bazel,run,arguments,profile,entry,deadline,*,graph_sha256,dependency_lease,**kwargs):
    selected(profile,arguments);remaining(entry,deadline)
    require(type(dependency_lease) is SDKTreeDependencyLease
        and dependency_lease.profile == profile and not dependency_lease.capture_ready
        and dependency_lease.run_id == run.name and dependency_lease.state_root == run.parent
        and dependency_lease.checkout == Path.cwd().resolve(strict=True)
        and (dependency_lease.entry,dependency_lease.deadline) == (entry,deadline)
        and dependency_lease.source_commit == kwargs.get('source_commit')
        and dependency_lease.graph_sha256 == graph_sha256 and kwargs.get('output_base') is None)
    dependency_lease.fence();pin(graph_sha256);pin(kwargs['source_commit'],40)
    require(kwargs.get('source_dirty') == 'false')
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get('repository_cache'),kwargs.get('nixpkgs_source'))
    prefix = 'OMUX_NATIVE_SDK_TREE_' if profile == PRODUCER else 'OMUX_NATIVE_FILE_WRITER_MODELS_'
    context = {'MODE':PRODUCER if profile == PRODUCER else old.INPUT_MODE,
        'ENTRY_NS':str(entry),'DEADLINE_NS':str(deadline),'EPOCH':str(run),
        'SOURCE_COMMIT':kwargs['source_commit'],'GRAPH_SHA256':graph_sha256}
    if profile == PRODUCER:context['BOOT_ID']=dependency_lease.boot_id
    result=builder(bazel,run,arguments,profile='standard',output_base=dependency_lease.output_base,**kwargs)
    require('--disk_cache=' in result and '--remote_cache=' in result and '--remote_executor=' in result)
    flags=['--experimental_convenience_symlinks=ignore','--repository_disable_download',
        '--repo_contents_cache=','--test_timeout='+str(runtime_seconds(profile,entry,deadline))]
    flags += ['--'+kind+'='+prefix+name+'='+value for kind in ('repo_env','test_env')
        for name,value in context.items()]
    if profile == PRODUCER:
        flags += ['--action_env='+prefix+name+'='+value for name,value in context.items()]
    # Boot-only current role is stable across same-boot epochs and is an
    # explicit action input for both cohorts; never the selected old value.
    flags += ['--'+kind+'=OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID='+dependency_lease.boot_id
        for kind in ('action_env','test_env')]
    index=result.index('test')+1;result[index:index]=flags
    dependency_lease.fence()
    return result


def projection(profile,entry,deadline,verified,resident):
    require(profile in PROFILES and (verified is None or type(verified) is bool))
    kernel.envelope(entry,deadline)
    return {'scope':'fixed-'+profile+'-v1','profile':profile,
        'original_entry_monotonic_ns':entry,'original_deadline_monotonic_ns':deadline,
        'work_cutoff_monotonic_ns':entry+(1170 if profile == PRODUCER else 600)*10**9,
        'action_cap_seconds':1170 if profile == PRODUCER else 840,
        'verified_after_cleanup':verified,'resident':resident,'artifact_family':FAMILY,
        'sdk_execution_qualified':False,'source_qualified':False,'compiler_qualified':False,
        'runtime_qualified':False,'continuity_qualified':False,'live_qualified':False}


def publication_record(entry,deadline):
    """Historical atomic-commit facts; never a current parent-lock claim."""
    kernel.envelope(entry,deadline)
    return {'schema_version':1,'kind':'omux-retained-sdk-tree-terminal-publication-v1',
        'state':'committed-at-canonical-rename','method':'qualified-input-drain-before-owned-atomic-rename-v1',
        'original_entry_monotonic_ns':entry,'original_deadline_monotonic_ns':deadline,
        'publication_cutoff_monotonic_ns':deadline-30*10**9,
        'writer_exclusive_through_commit':True,'qualification_input_closes_verified_before_commit':True,
        'post_commit_writer_release_is_receipt_authority':False,'current_parent_lock_claim':False,
        'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}


def qualification_record(outer,digest,extent,observed,witness):
    """Historical observed qualification; no later delivery-time assertion."""
    pin(digest)
    lease=outer['native_sdk_tree_dependency_lease']
    entry,deadline=lease['entry_monotonic_ns'],lease['deadline_monotonic_ns']
    kernel.envelope(entry,deadline)
    require(type(extent) is int and 0 < extent <= 1024*1024
        and type(observed) is int and entry <= observed < deadline-30*10**9
        and type(witness) is list and len(witness) == 9 and all(type(value) is int for value in witness)
        and stat.S_ISREG(witness[4]) and stat.S_IMODE(witness[4]) == 0o600
        and witness[2] == os.getuid() and witness[5] == 1 and witness[6] == extent)
    return {'schema_version':1,'kind':'omux-retained-sdk-tree-qualification-confirmation-v1',
        'epoch':str(Path(lease['output_base']).parent.parent/outer['id']),
        'profile':outer['profile'],'source_commit':outer['source_commit'],'graph_sha256':outer['graph_sha256'],
        'receipt':{'sha256':digest,'bytes':extent},'original_entry_monotonic_ns':entry,
        'original_deadline_monotonic_ns':deadline,'observed_qualified_monotonic_ns':observed,
        'canonical_receipt_creator_witness':witness,
        'qualification':{'scope':'same-owned-canonical-receipt-postcommit-full-proof-v1',
            'canonical_held_named_join':True,'current_graph_join':True,
            'qualification_input_closes_verified':True,'original_cutoff_join':True,
            'writer_exclusive':True,'current_parent_lock_claim':False},
        'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}


def validate_qualification_confirmation(outer,confirmation,outer_sha256,outer_bytes):
    """Join held creator facts; caller still supplies actual fresh physical proof."""
    require(type(confirmation) is dict and set(confirmation) == {'schema_version','kind','epoch','profile',
        'source_commit','graph_sha256','receipt','original_entry_monotonic_ns','original_deadline_monotonic_ns',
        'observed_qualified_monotonic_ns','canonical_receipt_creator_witness','qualification',
        'sdk_execution_qualified','source_qualified','runtime_qualified'})
    require(type(confirmation['schema_version']) is int and confirmation['schema_version'] == 1
        and all(type(confirmation[name]) is int for name in ('original_entry_monotonic_ns',
            'original_deadline_monotonic_ns','observed_qualified_monotonic_ns'))
        and type(confirmation['receipt']) is dict and set(confirmation['receipt']) == {'sha256','bytes'}
        and type(confirmation['receipt']['bytes']) is int
        and type(confirmation['qualification']) is dict
        and all(confirmation['qualification'].get(name) is True for name in ('canonical_held_named_join',
            'current_graph_join','qualification_input_closes_verified','original_cutoff_join','writer_exclusive'))
        and confirmation['qualification'].get('current_parent_lock_claim') is False
        and all(confirmation[name] is False for name in ('sdk_execution_qualified','source_qualified','runtime_qualified')))
    require(confirmation == qualification_record(outer,outer_sha256,outer_bytes,
        confirmation['observed_qualified_monotonic_ns'],confirmation['canonical_receipt_creator_witness']))
    _terminal_facts(outer)
    return dict(confirmation)


def _terminal_facts(receipt):
    """Closed prior cohort and kernel bounds, never an SDK readiness verdict."""
    profile=receipt['profile'];require(profile in PROFILES and receipt['manager'] == 'system')
    lease=receipt['native_sdk_tree_dependency_lease']
    require(type(lease) is dict and set(lease) == {'kind','family','key','namespace','output_base','run_id',
        'checkout','profile','source_commit','graph_sha256','entry_monotonic_ns','deadline_monotonic_ns',
        'sdk_execution_qualified','source_qualified','runtime_qualified'}
        and all(lease[name] is False for name in ('sdk_execution_qualified','source_qualified','runtime_qualified')))
    entry,deadline=lease['entry_monotonic_ns'],lease['deadline_monotonic_ns']
    kernel.envelope(entry,deadline)
    publication=receipt['native_sdk_tree_terminal_publication']
    require(type(publication) is dict and publication == publication_record(entry,deadline)
        and type(publication['schema_version']) is int
        and all(type(publication[name]) is int for name in ('original_entry_monotonic_ns',
            'original_deadline_monotonic_ns','publication_cutoff_monotonic_ns'))
        and publication['writer_exclusive_through_commit'] is True
        and publication['qualification_input_closes_verified_before_commit'] is True
        and all(publication[name] is False for name in ('post_commit_writer_release_is_receipt_authority',
            'current_parent_lock_claim','sdk_execution_qualified','source_qualified','runtime_qualified')))
    name='native_sdk_tree_reservation' if profile == PRODUCER else 'native_sdk_tree_source_reservation'
    reserved=receipt[name]
    require(type(reserved) is dict and reserved == projection(profile,entry,deadline,True,reserved['resident']))
    resident=reserved['resident']
    require(type(resident) is dict and set(resident) == {'scope','kernel_bounds','observations',
        'initial_direct_processes_retained','initial_direct_process_count','outer_pid_namespace_matched',
        'hierarchical_caps','descendant_process_inventory','installation_qualified','health_observed',
        'custody_observed','resident_signalled','whole_host_reservation'}
        and resident['scope'] == 'sampled-fixed-default-cgroup-kernel-reservation-v1'
        and type(resident['observations']) is int and 0 < resident['observations'] <= 65535
        and type(resident['initial_direct_process_count']) is int and 0 < resident['initial_direct_process_count'] <= 32
        and all(resident[key] is True for key in ('initial_direct_processes_retained','outer_pid_namespace_matched','hierarchical_caps'))
        and all(resident[key] is False for key in ('descendant_process_inventory','installation_qualified','health_observed',
            'custody_observed','resident_signalled','whole_host_reservation')))
    kernel.kernel_bounds(resident['kernel_bounds'])
    require(resident['initial_direct_process_count'] <= int(resident['kernel_bounds']['pids.max']))
    observed=receipt['observed_properties']
    require(type(observed) is dict and all(observed.get(key) == value for key,value in {
        'MemoryMax':str(MEMORY),'MemorySwapMax':'0','TasksMax':str(TASKS),'PrivateNetwork':'yes',
        'KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill','RemainAfterExit':'yes'}.items()))
    token=observed.get('CPUQuotaPerSecUSec')
    match=re.fullmatch(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)',token) if type(token) is str else None
    require(match is not None and Decimal(match[1])*{'us':1,'ms':1000,'s':1000000}[match[2]] == 1900000)
    verify_runtime(observed.get('RuntimeMaxUSec'),1170 if profile == PRODUCER else 840)
    require(receipt['unit'] == 'omux-execution-'+receipt['id']+'.service'
        and type(receipt['epoch_start_ns']) is int and receipt['epoch_start_ns'] > 0)
    return entry,deadline


def _xml_success(raw):
    require(0 < len(raw) <= 64*1024*1024 and b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw)
    try:root=ET.fromstring(raw)
    except (ET.ParseError,LookupError):raise ValueError('retained-sdk-tree-reservation-refused') from None
    require(root.tag in ('testsuite','testsuites'))
    suites=[root] if root.tag == 'testsuite' else list(root)
    require(0 < len(suites) <= 4096 and all(node.tag == 'testsuite' for node in suites))
    for node in [root]+([] if root.tag == 'testsuite' else suites):
        for name in ('failures','errors','skipped'):
            value=node.get(name,'0');require(re.fullmatch(r'[0-9]{1,10}',value) is not None and int(value) == 0)
    for node in suites:
        value=node.get('tests','0')
        require(re.fullmatch(r'[0-9]{1,10}',value) is not None and int(value) > 0
            and not any(child.tag in ('failure','error','skipped') for child in node.iter()))


class SDKTreeDependencyLease(old.ContentDependencyLease):
    """New namespace and receipt grammar; old implementation is unmodified.

Inherited mechanics keep real exclusive flock, current held/name/full-nine
checkout/marker/lock/base fences and terminal cleanup before clean publication.
The new type accepts exactly two cohorts and never supplies a child lock claim.
"""
    def __init__(self,*args,profile,**kwargs):
        require(profile in PROFILES)
        self.profile=profile
        self.boot_id=current_boot_id(kwargs["entry"],kwargs["deadline"],profile)
        self._lease_self=self
        self.publication_ready=False
        self._pending_terminal=None
        self.terminal_stage='not-attempted'
        super().__init__(*args,**kwargs)
        self.name='cache-v2-sdk-tree-'+self.key
        self.output_base=self.state_root/self.name/'output-base'
        self.binding=self._binding()

    def _binding(self):
        return (*super()._binding(),self.profile,FAMILY,self.boot_id)

    def _clock(self):
        cutoff=self.deadline-30*10**9 if self.capture_ready or self.profile == PRODUCER else self.entry+600*10**9
        require(type(self) is SDKTreeDependencyLease and self.active and self.binding == self._binding()
            and self._lease_self is self
            and self.pid == os.getpid() and self.thread == threading.get_ident()
            and self.entry <= time.monotonic_ns() < cutoff and time.monotonic_ns() < self.deadline)

    def facts(self):
        self.fence()
        return {'kind':'omux-retained-sdk-tree-dependency-lease-v1','family':FAMILY,
            'key':self.key,'namespace':self.name,'output_base':str(self.output_base),
            'run_id':self.run_id,'checkout':str(self.checkout),'profile':self.profile,
            'source_commit':self.source_commit,'graph_sha256':self.graph_sha256,
            'entry_monotonic_ns':self.entry,'deadline_monotonic_ns':self.deadline,
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}

    def __copy__(self): raise ValueError('SDK tree lease is not transferable')
    def __deepcopy__(self,memo): raise ValueError('SDK tree lease is not transferable')

    def fence(self):
        if self.publication_ready:self.publication_fence()
        else:super().fence()

    def prepare_publication(self):
        """Drain qualification inputs, keeping writer namespace/lock exclusive."""
        require(not self.publication_ready and self.capture_ready)
        self.fence()
        owned=[self.marker_fd,self.base_fd,self.checkout_fd]
        self.marker_fd=self.base_fd=self.checkout_fd=None
        failure=None
        for fd in owned:
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:
                    if failure is None:failure=error
        if failure is not None:raise failure
        self.publication_ready=True
        self.publication_fence()

    def publication_fence(self):
        self._clock()
        require(self.publication_ready and self.marker_fd is None and self.base_fd is None and self.checkout_fd is None
            and self.state_fd is not None and self.directory is not None and self.lock is not None)
        require(old._witness(os.fstat(self.state_fd))[:5] == self.state_anchor == old._witness(
                os.stat(self.state_root,follow_symlinks=False))[:5]
            and old._witness(os.fstat(self.directory)) == self.directory_anchor == old._witness(
                os.stat(self.name,dir_fd=self.state_fd,follow_symlinks=False))
            and old._witness(os.fstat(self.lock)) == self.lock_anchor == old._witness(
                os.stat('cache.lock',dir_fd=self.directory,follow_symlinks=False)))
        require(self.checkout.resolve(strict=True) == self.checkout
            and old._witness(os.stat(self.checkout,follow_symlinks=False)) == self.checkout_anchor
            and old._witness(os.stat('output-base',dir_fd=self.directory,follow_symlinks=False)) == self.capture_anchor
            and old._witness(os.stat('owner.json',dir_fd=self.directory,follow_symlinks=False)) == self.marker_anchor
            and cache.read_marker(self.directory) == self.marker_value)
        # The marker reader's owned close precedes these final named/clock joins.
        require(old._witness(os.fstat(self.state_fd))[:5] == self.state_anchor == old._witness(
                os.stat(self.state_root,follow_symlinks=False))[:5]
            and self.checkout.resolve(strict=True) == self.checkout
            and old._witness(os.stat(self.checkout,follow_symlinks=False)) == self.checkout_anchor
            and old._witness(os.stat('output-base',dir_fd=self.directory,follow_symlinks=False)) == self.capture_anchor
            and old._witness(os.fstat(self.lock)) == self.lock_anchor == old._witness(
                os.stat('cache.lock',dir_fd=self.directory,follow_symlinks=False))
            and old._witness(os.stat('owner.json',dir_fd=self.directory,follow_symlinks=False)) == self.marker_anchor
            and old._witness(os.fstat(self.directory)) == self.directory_anchor == old._witness(
                os.stat(self.name,dir_fd=self.state_fd,follow_symlinks=False)))
        self._clock()

    def disposition(self,receipt):
        self.fence()
        require(self.capture_ready and receipt['descendants_empty'] is True
            and receipt['cleanup']['ownership'] == 'verified' and receipt['cleanup']['state'] == 'empty'
            and type(receipt['cleanup']['readback_attempts']) is int
            and receipt['cleanup']['readback_attempts'] >= 2 and receipt['test_evidence']['state'] == 'preserved')
        failed=receipt['workload_exit'] != 0
        require((failed and type(receipt['exit']) is int and receipt['exit'] != 0)
            or (not failed and receipt['exit'] == 0))
        return {'kind':'omux-retained-sdk-tree-dependency-disposition-v1','family':FAMILY,
            'state':'dependency-only-after-owned-failure' if failed else 'dependency-data-after-success',
            'checkout':str(self.checkout),'key':self.key,'namespace':self.name,
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}

    def _readback_tick(self):
        # Prior receipts are qualified during __enter__, before active=True.
        # The already-held namespace lock does not create a new work clock.
        cutoff=self.deadline-30*10**9 if self.capture_ready or self.profile == PRODUCER else self.entry+600*10**9
        require(type(self) is SDKTreeDependencyLease and self._lease_self is self
            and self.binding == self._binding() and self.pid == os.getpid()
            and self.thread == threading.get_ident() and self.entry <= time.monotonic_ns() < cutoff)

    def _evidence(self,run,receipt):
        """Full held/name readback of the epoch's immutable evidence copies."""
        evidence=receipt['test_evidence']
        require(type(evidence) is dict and set(evidence) == {'state','manifest','sha256','bytes','files'}
            and evidence['state'] == 'preserved' and evidence['manifest'] == 'test-evidence.json'
            and type(evidence['bytes']) is int and 0 <= evidence['bytes'] <= 64*1024*1024
            and type(evidence['files']) is int and 0 <= evidence['files'] <= 256)
        pin(evidence['sha256']);slots=[];anchors=[];primary=None;opened={}
        def read(parent,name,expected,maximum):
            self._readback_tick();slots.append(None);slot=len(slots)-1
            slots[slot]=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
            fd=slots[slot];before=old._witness(os.fstat(fd))
            require(stat.S_ISREG(before[4]) and before[2] == os.getuid() and before[5] == 1
                and stat.S_IMODE(before[4]) == 0o600 and 0 <= before[6] <= maximum)
            blocks=[];position=0
            while position < before[6]:
                self._readback_tick();raw=os.pread(fd,min(65536,before[6]-position),position)
                require(len(raw) > 0);blocks.append(raw);position+=len(raw)
            raw=b''.join(blocks)
            require(os.pread(fd,1,position) == b'' and len(raw) == before[6]
                and hashlib.sha256(raw).hexdigest() == expected)
            anchors.append((parent,name,fd,before));self._readback_tick();return raw
        try:
            raw=read(run,'test-evidence.json',evidence['sha256'],1024*1024);index=json.loads(raw)
            require(type(index) is dict and set(index) == {'schema','bazel_exit','epoch_start_ns','targets','bytes',
                'copied_files','results','acceptance'} and type(index['schema']) is int and index['schema'] == 1
                and type(index['bazel_exit']) is int and index['bazel_exit'] == receipt['workload_exit']
                and index['epoch_start_ns'] == receipt['epoch_start_ns'] and index['targets'] == receipt['targets']
                and index['bytes'] == evidence['bytes'] and index['copied_files'] == evidence['files']
                and index['acceptance'] == 'evidence copies preserve invocation status; no inferred PASS'
                and type(index['results']) is list and len(index['results']) == len(receipt['targets']))
            slots.append(None);slot=len(slots)-1
            slots[slot]=os.open('test-evidence',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=run)
            directory=slots[slot];directory_anchor=old._witness(os.fstat(directory))
            require(stat.S_ISDIR(directory_anchor[4]) and directory_anchor[2] == os.getuid()
                and stat.S_IMODE(directory_anchor[4]) == 0o700)
            copied=used=0;seen_targets=set()
            for row in index['results']:
                self._readback_tick()
                require(type(row) is dict and row['target'] in receipt['targets'] and row['target'] not in seen_targets)
                seen_targets.add(row['target'])
                if row['state'] == 'missing-test-directory':
                    require(set(row) == {'target','state','files'} and row['files'] == [] and receipt['workload_exit'] != 0)
                    continue
                require(set(row) == {'target','configuration','state','files'} and row['state'] == 'observed'
                    and type(row['configuration']) is str and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',row['configuration']) is not None
                    and type(row['files']) is list and len(row['files']) == 4)
                allowed=('test.log','test.xml','test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')
                require([member['source'] for member in row['files']] == list(allowed));logs={}
                for member in row['files']:
                    self._readback_tick()
                    if member['state'] == 'copied':
                        require(set(member) == {'source','state','bytes','sha256','file'} and type(member['bytes']) is int
                            and 0 <= member['bytes'] <= 64*1024*1024);pin(member['sha256'])
                        filename=hashlib.sha256((row['target']+'\0'+row['configuration']+'\0'+member['source']).encode()).hexdigest()+'.evidence'
                        require(member['file'] == filename and filename not in opened)
                        raw=read(directory,filename,member['sha256'],64*1024*1024)
                        require(len(raw) == member['bytes']);opened[filename]=True;copied+=1;used+=len(raw)
                        require(copied <= 256 and used <= 64*1024*1024)
                        if member['source'] in ('test.log','test.xml'):logs[member['source']]=raw
                    else:
                        require(set(member) == {'source','state','bytes'} and member['state'] in ('missing','stale')
                            and type(member['bytes']) is int and member['bytes'] == 0)
                if receipt['workload_exit'] == 0:
                    require(set(logs) == {'test.log','test.xml'} and len(logs['test.log']) > 0);_xml_success(logs['test.xml'])
                    if receipt['profile'] == PRODUCER:
                        origin=receipt['native_sdk_tree_artifact_origin']
                        report_pin=next(item['sha256'] for item in origin['created_metadata'] if item['name'] == 'receipt.json')
                        marker=('retained-sdk-tree: receipt-sha256='+report_pin).encode()
                        require(logs['test.log'].splitlines().count(marker) == 1)
            require(copied == evidence['files'] and used == evidence['bytes'])
            for parent,name,fd,before in anchors:
                self._readback_tick()
                require(old._witness(os.fstat(fd)) == before == old._witness(os.stat(name,dir_fd=parent,follow_symlinks=False)))
            require(old._witness(os.fstat(directory)) == directory_anchor == old._witness(
                os.stat('test-evidence',dir_fd=run,follow_symlinks=False)));self._readback_tick()
        except BaseException as error:primary=error;raise
        finally:
            failure=None
            for fd in reversed(slots):
                if fd is not None:
                    try:os.close(fd)
                    except BaseException as error:
                        if failure is None:failure=error
            if failure is not None:
                if primary is not None:raise primary from failure
                raise failure
        # Closed child directories need reopening for the last named checks.
        for parent,name,fd,before in anchors:
            self._readback_tick()
            selected=run if name == 'test-evidence.json' else None
            if selected is not None:require(before == old._witness(os.stat(name,dir_fd=selected,follow_symlinks=False)))
            else:
                directory=os.open('test-evidence',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=run)
                primary=None
                try:require(old._witness(os.fstat(directory)) == directory_anchor
                    and before == old._witness(os.stat(name,dir_fd=directory,follow_symlinks=False)))
                except BaseException as error:primary=error;raise
                finally:
                    closing,directory=directory,None
                    try:os.close(closing)
                    except BaseException as cleanup:
                        if primary is not None:raise primary from cleanup
                        raise
        require(directory_anchor == old._witness(os.stat('test-evidence',dir_fd=run,follow_symlinks=False)));self._readback_tick()

    def _confirmation(self,run,receipt,digest,extent,outer_witness):
        self._readback_tick();fd=None;primary=None
        try:
            fd=os.open('sdk-tree-qualified.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=run)
            before=old._witness(os.fstat(fd))
            require(stat.S_ISREG(before[4]) and before[2] == os.getuid() and before[5] == 1
                and stat.S_IMODE(before[4]) == 0o600 and 0 < before[6] <= 65536)
            raw=os.pread(fd,before[6]+1,0)
            require(len(raw) == before[6])
            confirmation=json.loads(raw)
            validate_qualification_confirmation(receipt,confirmation,digest,extent)
            require(confirmation['canonical_receipt_creator_witness'] == list(outer_witness)
                and old._witness(os.fstat(fd)) == before == old._witness(
                    os.stat('sdk-tree-qualified.json',dir_fd=run,follow_symlinks=False)))
            self._readback_tick()
        except BaseException as error:primary=error;raise
        finally:
            closing,fd=fd,None
            if closing is not None:
                try:os.close(closing)
                except BaseException as cleanup:
                    if primary is not None:raise primary from cleanup
                    raise
            if primary is None:
                require(before == old._witness(os.stat('sdk-tree-qualified.json',dir_fd=run,follow_symlinks=False)))
                self._readback_tick()

    def _receipt(self,run_id,digest,*,previous=False):
        pin(digest);require(str(uuid.UUID(run_id)) == run_id)
        parent=run=fd=None;primary=None
        try:
            parent=cache.trusted_directory(self.state_root)
            parent_anchor=old._witness(os.fstat(parent))
            run=os.open(run_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            run_anchor=old._witness(os.fstat(run))
            require(stat.S_ISDIR(run_anchor[4]) and run_anchor[2] == os.getuid() and stat.S_IMODE(run_anchor[4]) == 0o700)
            candidate=self._pending_terminal if not previous and run_id == self.run_id else None
            name='receipt.json'
            if candidate is not None:
                require(type(candidate) is _TerminalCandidate and candidate.lease is self and candidate.digest == digest)
                candidate.check();name='receipt.pending.json'
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=run)
            before=old._witness(os.fstat(fd))
            require(stat.S_ISREG(before[4]) and before[2] == os.getuid() and before[5] == 1
                and stat.S_IMODE(before[4]) == 0o600 and 0 < before[6] <= 1024*1024)
            raw=os.pread(fd,before[6]+1,0)
            require(len(raw) == before[6] and hashlib.sha256(raw).hexdigest() == digest)
            receipt=json.loads(raw)
            profile=receipt['profile'];require(profile in PROFILES)
            prior_entry,prior_deadline=_terminal_facts(receipt)
            self._readback_tick()
            disposition=receipt['native_sdk_tree_dependency_disposition']
            expected={'kind':'omux-retained-sdk-tree-dependency-disposition-v1','family':FAMILY,
                'state':'dependency-only-after-owned-failure' if receipt['workload_exit'] != 0 else 'dependency-data-after-success',
                'checkout':str(self.checkout),'key':self.key,'namespace':self.name,
                'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
            require(receipt['id'] == run_id and receipt['verb'] == 'test' and receipt['targets'] == COHORTS[profile][1:]
                and receipt['cache_key'] == self.key and receipt['cache_policy'] == 2
                and receipt['cache_reuse_requested'] is True and receipt['output_base'] == str(self.output_base)
                and receipt['source_dirty'] == 'false' and disposition == expected
                and receipt['descendants_empty'] is True and receipt['controller_failure'] is None
                and receipt['cleanup']['ownership'] == 'verified' and receipt['cleanup']['state'] == 'empty'
                and type(receipt['cleanup']['readback_attempts']) is int
                and receipt['cleanup']['readback_attempts'] >= 2 and receipt['test_evidence']['state'] == 'preserved')
            pin(receipt['source_commit'],40);pin(receipt['graph_sha256'])
            require(type(receipt['workload_exit']) is int and type(receipt['exit']) is int
                and ((receipt['workload_exit'] == 0 and receipt['exit'] == 0)
                    or (receipt['workload_exit'] != 0 and receipt['exit'] != 0)))
            if not previous:
                require(profile == self.profile and receipt['source_commit'] == self.source_commit
                    and receipt['graph_sha256'] == self.graph_sha256)
            if profile == PRODUCER:
                if receipt['exit'] == 0:
                    origin=receipt['native_sdk_tree_artifact_origin']
                    validate_artifact_origin(receipt,origin['creator_context'],origin['materialization'])
                else:
                    require(receipt.get('native_sdk_tree_artifact_origin') is None)
            lease=receipt['native_sdk_tree_dependency_lease']
            require(lease['kind'] == 'omux-retained-sdk-tree-dependency-lease-v1' and lease['family'] == FAMILY
                and lease['key'] == self.key and lease['namespace'] == self.name
                and lease['checkout'] == str(self.checkout) and lease['output_base'] == str(self.output_base)
                and lease['profile'] == profile and lease['run_id'] == run_id
                and lease['source_commit'] == receipt['source_commit'] and lease['graph_sha256'] == receipt['graph_sha256']
                and lease['sdk_execution_qualified'] is False and lease['source_qualified'] is False
                and lease['runtime_qualified'] is False
                and lease['entry_monotonic_ns'] == prior_entry and lease['deadline_monotonic_ns'] == prior_deadline)
            self._evidence(run,receipt)
            if candidate is None:self._confirmation(run,receipt,digest,len(raw),before)
            require(old._witness(os.fstat(fd)) == before == old._witness(os.stat(name,dir_fd=run,follow_symlinks=False))
                and old._witness(os.fstat(run)) == run_anchor == old._witness(os.stat(run_id,dir_fd=parent,follow_symlinks=False))
                and old._witness(os.fstat(parent)) == parent_anchor == old._witness(os.stat(self.state_root,follow_symlinks=False)))
            return receipt
        except BaseException as error: primary=error;raise
        finally:
            failure=None
            for owned in (fd,run,parent):
                if owned is not None:
                    try: os.close(owned)
                    except BaseException as error:
                        if failure is None: failure=error
            if failure is not None:
                if primary is not None: raise primary from failure
                raise failure
            if primary is None:
                require(run_anchor == old._witness(os.stat(self.state_root/run_id,follow_symlinks=False))
                    and before == old._witness(os.stat(self.state_root/run_id/name,follow_symlinks=False))
                    and parent_anchor == old._witness(os.stat(self.state_root,follow_symlinks=False)))


class TerminalPostCommitError(ValueError):
    """Commit may exist; caller must not claim rollback or acknowledge success."""
    def __init__(self,state):
        require(state in ('commit-unknown','committed-unqualified','qualified-confirmation-delivery-unknown',
            'committed-writer-release-failed','committed-reply-failed'))
        self.state=state
        super().__init__('retained-sdk-terminal-'+state)


def _write_closed_terminal(run,name,raw,tick=None,*,writer_directory=None):
    """Close every qualification writer before an atomic publication attempt."""
    require(name in ('receipt.pending.json','receipt.refused.pending.json','sdk-tree-qualified.pending.json') and type(raw) is bytes
        and 0 < len(raw) <= 1024*1024)
    owned=[];primary=None
    def open_owned(path,flags,*,dir_fd=None):
        owned.append(None);slot=len(owned)-1
        owned[slot]=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dir_fd)
        return owned[slot]
    def check_clock():
        if tick is not None:tick()
    try:
        check_clock();directory=open_owned(run if writer_directory is None else '.',os.O_RDONLY|os.O_DIRECTORY,
            dir_fd=writer_directory)
        info=os.fstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        fd=open_owned(name,os.O_RDWR|os.O_CREAT|os.O_EXCL,dir_fd=directory)
        position=0
        while position < len(raw):
            check_clock();count=os.write(fd,raw[position:position+65536]);require(count > 0);position+=count
        os.fsync(fd);before=old._witness(os.fstat(fd))
        require(stat.S_ISREG(before[4]) and before[2] == os.getuid() and before[5] == 1
            and stat.S_IMODE(before[4]) == 0o600 and before[6] == len(raw)
            and os.pread(fd,len(raw)+1,0) == raw
            and before == old._witness(os.stat(name,dir_fd=directory,follow_symlinks=False)))
        os.fsync(directory);parent=old._witness(os.fstat(directory))
        check_clock()
    except BaseException as error:primary=error;raise
    finally:
        failure=None
        for fd in reversed(owned):
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:
                    if failure is None:failure=error
        if failure is not None:
            if primary is not None:raise primary from failure
            raise failure
    check_clock()
    require(parent == old._witness(os.stat(run,follow_symlinks=False))
        and before == old._witness(os.stat(run/name,follow_symlinks=False)))
    check_clock();return before,parent


class _TerminalCandidate:
    """Fixed unselectable per-epoch bytes; never a published producer verdict."""
    def __init__(self,lease,raw):
        require(type(lease) is SDKTreeDependencyLease and lease.capture_ready and not lease.publication_ready)
        self.lease=lease;self.run=lease.state_root/lease.run_id
        self.digest=hashlib.sha256(raw).hexdigest()
        self.writer_fd=None
        try:
            self.writer_fd=os.open(lease.run_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                dir_fd=lease.state_fd)
            require(old._witness(os.fstat(self.writer_fd)) == old._witness(os.stat(self.run,follow_symlinks=False)))
            self.witness,self.parent=_write_closed_terminal(self.run,'receipt.pending.json',raw,
                lease._readback_tick,writer_directory=self.writer_fd)
            self.check()
        except BaseException as primary:
            try:self.close()
            except BaseException as cleanup:raise primary from cleanup
            raise
    def check(self):
        self.lease._readback_tick()
        require(self.writer_fd is not None
            and self.parent == old._witness(os.fstat(self.writer_fd)) == old._witness(
                os.stat(self.lease.run_id,dir_fd=self.lease.state_fd,follow_symlinks=False))
            and self.parent == old._witness(os.stat(self.run,follow_symlinks=False))
            and self.witness == old._witness(os.stat('receipt.pending.json',dir_fd=self.writer_fd,follow_symlinks=False)))
        self.lease._readback_tick()
    def committed_check(self):
        require(self.writer_fd is not None)
        current=old._witness(os.fstat(self.writer_fd))
        require(self.parent[:5] == current[:5] and current == old._witness(
                os.stat(self.lease.run_id,dir_fd=self.lease.state_fd,follow_symlinks=False))
            and current == old._witness(os.stat(self.run,follow_symlinks=False))
            and self.witness[:8] == old._witness(os.stat('receipt.json',dir_fd=self.writer_fd,follow_symlinks=False))[:8])
    def refusal_check(self):
        # Refusal metadata is not SDK qualification, but still needs the
        # original writer owner. Never re-authorize a replacement UID700 root.
        require(self.writer_fd is not None and self.lease.state_fd is not None)
        current=old._witness(os.fstat(self.writer_fd))
        require(self.parent[:5] == current[:5] and current == old._witness(
                os.stat(self.lease.run_id,dir_fd=self.lease.state_fd,follow_symlinks=False))
            and current == old._witness(os.stat(self.run,follow_symlinks=False))
            and old._witness(os.fstat(self.lease.state_fd))[:5] == self.lease.state_anchor == old._witness(
                os.stat(self.lease.state_root,follow_symlinks=False))[:5])
    def read_committed(self,extent):
        self.committed_check();fd=None;primary=None
        try:
            fd=os.open('receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.writer_fd)
            before=old._witness(os.fstat(fd))
            require(before[:8] == self.witness[:8] and before[6] == extent)
            raw=os.pread(fd,extent+1,0)
            require(len(raw) == extent and hashlib.sha256(raw).hexdigest() == self.digest
                and old._witness(os.fstat(fd)) == before == old._witness(
                    os.stat('receipt.json',dir_fd=self.writer_fd,follow_symlinks=False)))
            self.lease._readback_tick()
        except BaseException as error:primary=error;raise
        finally:
            closing,fd=fd,None
            if closing is not None:
                try:os.close(closing)
                except BaseException as cleanup:
                    if primary is not None:raise primary from cleanup
                    raise
            if primary is None:
                require(before == old._witness(os.stat('receipt.json',dir_fd=self.writer_fd,follow_symlinks=False)))
                self.committed_check();self.lease._readback_tick()
        return before
    def close(self):
        owned,self.writer_fd=self.writer_fd,None
        if owned is not None:os.close(owned)


def _drain_operations(operations,primary=None):
    failure=primary
    secondary=None
    for close in operations:
        try:close()
        except BaseException as error:
            if failure is None:failure=error
            elif secondary is None:secondary=error
    # Attempt every owned close before diagnostic chaining. Use the base
    # descriptor, not a hostile exception subclass's attribute hooks.
    if failure is not None and secondary is not None and BaseException.__cause__.__get__(failure) is None:
        BaseException.__cause__.__set__(failure,secondary)
    return failure


def publish_refused_terminal(lease,run,receipt,*,writer_directory,close_inputs=()):
    """Publish actual nonzero observation without dependency/SDK qualification.

    The coordinator supplies its original held private epoch directory. Missing
    cleanup/capture predicates stay missing: no confirmation or clean marker is
    created, and the existing qualified publication path is not retried.
    """
    require(type(lease) is SDKTreeDependencyLease and lease.active and lease._lease_self is lease
        and lease.pid == os.getpid() and lease.thread == threading.get_ident()
        and lease.binding == lease._binding() and lease.profile in PROFILES
        and run == lease.state_root/lease.run_id and type(writer_directory) is int
        and type(close_inputs) is tuple and len(close_inputs) <= 8 and all(callable(close) for close in close_inputs)
        and type(receipt) is dict and receipt['id'] == lease.run_id and receipt['profile'] == lease.profile
        and receipt['targets'] == COHORTS[lease.profile][1:]
        and receipt['source_commit'] == lease.source_commit and receipt['graph_sha256'] == lease.graph_sha256
        and type(receipt['exit']) is int and receipt['exit'] != 0
        and type(receipt['workload_exit']) is int and lease._pending_terminal is None)
    writer = None
    primary = None
    committed = False
    inputs_attempted = False
    expected = None
    canonical = parent_after = None
    def tick():
        require(lease.entry <= time.monotonic_ns() < lease.deadline)
    def root_check():
        tick()
        require(lease.state_fd is not None and writer is not None
            and old._witness(os.fstat(lease.state_fd))[:5] == lease.state_anchor == old._witness(
                os.stat(lease.state_root,follow_symlinks=False))[:5])
        held = old._witness(os.fstat(writer))
        require(stat.S_ISDIR(held[4]) and held[2] == os.getuid() and stat.S_IMODE(held[4]) == 0o700
            and held[:5] == original[:5]
            and held == old._witness(os.fstat(writer_directory)) == old._witness(
                os.stat(lease.run_id,dir_fd=lease.state_fd,follow_symlinks=False))
            and held == old._witness(os.stat(run,follow_symlinks=False)))
        tick()
    try:
        tick()
        # Register the duplicate before inspection. The original borrowed FD
        # remains owned by RunRetirement through publication and later cleanup.
        writer = os.dup(writer_directory)
        original = old._witness(os.fstat(writer))
        root_check()
        for name in ('receipt.json','sdk-tree-qualified.json','receipt.pending.json'):
            try: os.stat(name,dir_fd=writer,follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError('SDK failure terminal already exists')
        inputs_attempted = True
        failure = _drain_operations(close_inputs)
        if failure is not None:
            primary = failure
            receipt['exit'] = 125
        receipt['native_sdk_tree_artifact_origin'] = None
        receipt.pop('native_sdk_tree_dependency_disposition',None)
        receipt['native_sdk_tree_terminal_publication'] = {'schema_version':1,
            'kind':'omux-retained-sdk-tree-terminal-publication-v1','state':'failed-observation-only',
            'input_closes_verified':failure is None,'dependency_adopted':False,
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
        raw = (json.dumps(receipt,sort_keys=True)+'\n').encode()
        root_check()
        expected,parent = _write_closed_terminal(run,'receipt.refused.pending.json',raw,tick,
            writer_directory=writer)
        root_check()
        require(parent == old._witness(os.fstat(writer))
            and expected == old._witness(os.stat('receipt.refused.pending.json',dir_fd=writer,follow_symlinks=False)))
        tick()
        os.rename('receipt.refused.pending.json','receipt.json',src_dir_fd=writer,dst_dir_fd=writer)
        committed = True
        root_check()
        canonical = old._witness(os.stat('receipt.json',dir_fd=writer,follow_symlinks=False))
        parent_after = old._witness(os.fstat(writer))
        require(expected[:8] == canonical[:8])
        tick()
    except BaseException as error:
        if primary is None: primary = error
        elif BaseException.__cause__.__get__(primary) is None: BaseException.__cause__.__set__(primary,error)
    finally:
        if not inputs_attempted: primary = _drain_operations(close_inputs,primary)
        owned,writer = writer,None
        if owned is not None:
            try: os.close(owned)
            except BaseException as error:
                if primary is None: primary = error
                elif BaseException.__cause__.__get__(primary) is None: BaseException.__cause__.__set__(primary,error)
        try: lease.close()
        except BaseException as error:
            if primary is None: primary = error
            elif BaseException.__cause__.__get__(primary) is None: BaseException.__cause__.__set__(primary,error)
    if committed:
        # Post-drain metadata is an observation, never a writer/SDK success flag.
        try:
            require(parent_after == old._witness(os.fstat(writer_directory)) == old._witness(
                    os.stat(run,follow_symlinks=False))
                and canonical == old._witness(os.stat('receipt.json',dir_fd=writer_directory,follow_symlinks=False)))
            tick()
        except BaseException as error:
            if primary is None: primary = error
            elif BaseException.__cause__.__get__(primary) is None: BaseException.__cause__.__set__(primary,error)
    if primary is not None: raise primary
    require(committed)
    return receipt['exit']


def publish_terminal(lease,run,receipt,expected_graph,*,close_inputs=()):
    """Qualify/drain before commit; retain writer exclusivity through rename.

The canonical rename is the commit point. Its exception can be commit-unknown;
post-commit writer/reply failures never rewrite the immutable historical fact.
The staged file and its directory are fsynced before commit. No claim of a
post-rename directory fsync or power-loss durability is made by this method.
"""
    require(type(lease) is SDKTreeDependencyLease and run == lease.state_root/lease.run_id
        and lease.capture_ready and not lease.publication_ready and lease._pending_terminal is None
        and type(receipt) is dict and type(close_inputs) is tuple and len(close_inputs) <= 8
        and all(callable(close) for close in close_inputs))
    require(not (run/'receipt.json').exists())
    receipt['native_sdk_tree_terminal_publication']=publication_record(lease.entry,lease.deadline)
    committed=False;commit_attempted=False;inputs_attempted=False;primary=None;candidate=None;confirmed=False
    def delivery_tick():
        require(lease.entry <= time.monotonic_ns() < lease.deadline)
    try:
        lease.fence()
        raw=(json.dumps(receipt,sort_keys=True)+'\n').encode()
        candidate=_TerminalCandidate(lease,raw);lease._pending_terminal=candidate
        require('native_sdk_tree_dependency_disposition' in receipt
            and cache.graph_digest(lease.checkout) == expected_graph)
        require(cache.graph_digest(lease.checkout) == expected_graph)
        lease.complete(True,candidate.digest)
        # Qualification input FDs must close successfully while writer FDs and
        # the independent coordinator execution lock remain held.
        lease.prepare_publication()
        inputs_attempted=True
        failure=_drain_operations(close_inputs)
        if failure is not None:raise failure
        require(cache.graph_digest(lease.checkout) == expected_graph)
        lease.publication_fence();candidate.check()
        lease.publication_fence()
        commit_attempted=True
        lease.terminal_stage='commit-unknown'
        try:os.rename('receipt.pending.json','receipt.json',
            src_dir_fd=candidate.writer_fd,dst_dir_fd=candidate.writer_fd)
        except BaseException as error:raise TerminalPostCommitError('commit-unknown') from error
        committed=True
        lease.terminal_stage='committed'
        # Canonical bytes are artifact provenance only. Actual successful
        # creator admission additionally needs a separately held confirmation
        # of timely postcommit read/SHA/FD-close/named/graph qualification.
        lease.publication_fence()
        canonical_witness=candidate.read_committed(len(raw))
        require(cache.graph_digest(lease.checkout) == expected_graph)
        lease.publication_fence();candidate.committed_check()
        require(canonical_witness == old._witness(os.stat('receipt.json',
            dir_fd=candidate.writer_fd,follow_symlinks=False)))
        observed=time.monotonic_ns()
        confirmation=qualification_record(receipt,candidate.digest,len(raw),observed,list(canonical_witness))
        validate_qualification_confirmation(receipt,confirmation,candidate.digest,len(raw))
        confirmed_raw=(json.dumps(confirmation,sort_keys=True)+'\n').encode()
        require(len(confirmed_raw) <= 65536)
        # Metadata delivery uses only the original outer envelope. It
        # attests the earlier observed qualification, not its rename time.
        expected_confirm,parent=_write_closed_terminal(run,'sdk-tree-qualified.pending.json',confirmed_raw,
            delivery_tick,writer_directory=candidate.writer_fd)
        candidate.committed_check()
        require(old._witness(os.fstat(candidate.writer_fd)) == parent == old._witness(
                os.stat(lease.run_id,dir_fd=lease.state_fd,follow_symlinks=False))
            and expected_confirm == old._witness(os.stat('sdk-tree-qualified.pending.json',
                dir_fd=candidate.writer_fd,follow_symlinks=False)))
        delivery_tick()
        lease.terminal_stage='qualification-observed'
        try:os.rename('sdk-tree-qualified.pending.json','sdk-tree-qualified.json',
            src_dir_fd=candidate.writer_fd,dst_dir_fd=candidate.writer_fd)
        except BaseException as error:
            raise TerminalPostCommitError('qualified-confirmation-delivery-unknown') from error
        confirmed=True
        lease.terminal_stage='qualified'
        candidate.committed_check()
        require(expected_confirm[:8] == old._witness(os.stat('sdk-tree-qualified.json',
            dir_fd=candidate.writer_fd,follow_symlinks=False))[:8])
        delivery_tick()
    except BaseException as error:
        primary=error
        if committed and not confirmed and not isinstance(error,TerminalPostCommitError):
            primary=TerminalPostCommitError('committed-unqualified')
            BaseException.__cause__.__set__(primary,error)
        elif confirmed and not isinstance(error,TerminalPostCommitError):
            primary=TerminalPostCommitError('committed-reply-failed')
            BaseException.__cause__.__set__(primary,error)
    if not commit_attempted:
        # These failed predicates never made canonical success selectable.
        receipt['exit']=125;receipt['native_sdk_tree_artifact_origin']=None
        receipt.pop('native_sdk_tree_dependency_disposition',None)
        receipt['native_sdk_tree_terminal_publication']={'schema_version':1,
            'kind':'omux-retained-sdk-tree-terminal-publication-v1','state':'refused-before-commit',
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
        if not inputs_attempted:primary=_drain_operations(close_inputs,primary)
        try:
            if candidate is not None:
                candidate.refusal_check();delivery_tick()
                raw=(json.dumps(receipt,sort_keys=True)+'\n').encode()
                _write_closed_terminal(run,'receipt.refused.pending.json',raw,delivery_tick,
                    writer_directory=candidate.writer_fd)
                candidate.refusal_check();delivery_tick()
                os.rename('receipt.refused.pending.json','receipt.json',
                    src_dir_fd=candidate.writer_fd,dst_dir_fd=candidate.writer_fd)
        except BaseException as cleanup:
            if primary is None:primary=cleanup
            elif BaseException.__cause__.__get__(primary) is None:BaseException.__cause__.__set__(primary,cleanup)
        primary=_drain_operations(((candidate.close,) if candidate is not None else ())+(lease.close,),primary)
    else:
        release=_drain_operations(((candidate.close,) if candidate is not None else ())+(lease.close,))
        if release is not None:
            if primary is None:primary=TerminalPostCommitError('committed-writer-release-failed')
            if BaseException.__cause__.__get__(primary) is None:BaseException.__cause__.__set__(primary,release)
    if primary is not None:raise primary
    require(committed and confirmed)
    return receipt['exit']


def validate_artifact_origin(outer,selected_context,materialization):
    """Creator provenance only; no child claim of current parent lock/custody."""
    require(type(outer) is dict and outer.get('profile') == PRODUCER
        and outer.get('verb') == 'test' and outer.get('targets') == [TARGET]
        and type(outer.get('exit')) is int and outer['exit'] == 0
        and type(outer.get('workload_exit')) is int and outer['workload_exit'] == 0)
    entry,deadline=_terminal_facts(outer)
    require(str(uuid.UUID(outer['id'])) == outer['id'])
    pin(outer['source_commit'],40);pin(outer['graph_sha256'])
    require(type(materialization) is dict and set(materialization) == {'recipe_sha256','action_inputs_sha256'})
    for digest in materialization.values(): pin(digest)
    origin=outer['native_sdk_tree_artifact_origin']
    require(type(origin) is dict and set(origin) == {'schema_version','kind','family','checkout','namespace','key',
        'output_base','creator_run_id','creator_source_commit','creator_graph_sha256','creator_context','materialization',
        'artifact_layout','created_metadata','sdk_execution_qualified','source_qualified','runtime_qualified'}
        and type(origin['schema_version']) is int and origin['schema_version'] == 1
        and origin['kind'] == 'omux-retained-sdk-tree-artifact-origin-v1' and origin['family'] == FAMILY
        and origin['creator_context'] == selected_context and origin['materialization'] == materialization
        and origin['artifact_layout'] == LAYOUT and origin['sdk_execution_qualified'] is False
        and origin['source_qualified'] is False and origin['runtime_qualified'] is False)
    key=pin(origin['key']);require(origin['namespace'] == 'cache-v2-sdk-tree-'+key)
    require(type(selected_context) is dict and set(selected_context) == {'MODE','ENTRY_NS','DEADLINE_NS',
        'EPOCH','SOURCE_COMMIT','GRAPH_SHA256','BOOT_ID'} and all(type(value) is str for value in selected_context.values())
        and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',selected_context['BOOT_ID']) is not None
        and selected_context['MODE'] == PRODUCER
        and selected_context['SOURCE_COMMIT'] == outer['source_commit']
        and selected_context['GRAPH_SHA256'] == outer['graph_sha256']
        and Path(selected_context['EPOCH']).name == outer['id']
        and re.fullmatch(r'[1-9][0-9]{0,19}',selected_context['ENTRY_NS']) is not None
        and re.fullmatch(r'[1-9][0-9]{0,19}',selected_context['DEADLINE_NS']) is not None
        and int(selected_context['ENTRY_NS']) == entry and int(selected_context['DEADLINE_NS']) == deadline
        and Path(selected_context['EPOCH']).is_absolute()
        and os.path.normpath(selected_context['EPOCH']) == selected_context['EPOCH'])
    metadata=origin['created_metadata']
    names=['creator-context.json','inventory.json','receipt.json','recipe.json']
    require(type(metadata) is list and len(metadata) == 4)
    for index,row in enumerate(metadata):
        require(type(row) is dict and set(row) == {'name','path','sha256','bytes'}
            and row['name'] == names[index]
            and row['path'] == selected_context['EPOCH']+'/sdk-tree-created/'+row['name']
            and type(row['bytes']) is int and 0 < row['bytes'] <= (256*1024*1024
                if row['name'] in ('inventory.json','recipe.json') else 65536))
        pin(row['sha256'])
    require(metadata[-1]['sha256'] == materialization['recipe_sha256'])
    require(outer['cache_key'] == key and outer['cache_policy'] == 2 and outer['cache_reuse_requested'] is True
        and origin['creator_run_id'] == outer['id'] and origin['creator_source_commit'] == outer['source_commit']
        and origin['creator_graph_sha256'] == outer['graph_sha256']
        and origin['output_base'] == outer['output_base']
        and origin['output_base'] == str(Path(selected_context['EPOCH']).parent/origin['namespace']/'output-base'))
    lease=outer['native_sdk_tree_dependency_lease']
    require(lease['kind'] == 'omux-retained-sdk-tree-dependency-lease-v1' and lease['family'] == FAMILY
        and lease['key'] == key and lease['namespace'] == origin['namespace']
        and lease['checkout'] == origin['checkout'] and lease['output_base'] == origin['output_base']
        and lease['run_id'] == outer['id'] and lease['profile'] == PRODUCER
        and lease['source_commit'] == outer['source_commit'] and lease['graph_sha256'] == outer['graph_sha256'])
    require(type(origin['checkout']) is str and Path(origin['checkout']).is_absolute()
        and os.path.normpath(origin['checkout']) == origin['checkout']
        and outer['descendants_empty'] is True and outer['controller_failure'] is None
        and outer['cleanup']['ownership'] == 'verified' and outer['cleanup']['state'] == 'empty'
        and type(outer['cleanup']['readback_attempts']) is int and outer['cleanup']['readback_attempts'] >= 2)
    return dict(origin)


def capture_creator_metadata(lease,epoch):
    """Preserve small public creator metadata, never copy the SDK TreeArtifact.

Call only after the actual singleton worker/evidence and owned cleanup are
qualified. This function does not create that outcome or terminal receipt.
"""
    require(type(lease) is SDKTreeDependencyLease and lease.profile == PRODUCER
        and lease.capture_ready and epoch == lease.state_root/lease.run_id)
    lease.fence()
    root=lease.output_base/'execroot/_main/bazel-out'
    require(root.resolve(strict=True) == root)
    configurations=list(root.iterdir())
    require(len(configurations) <= 64)
    candidates=[]
    for configuration in configurations:
        lease.fence()
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',configuration.name) is None:continue
        candidate=configuration/'bin'/LAYOUT
        try:info=os.stat(candidate,follow_symlinks=False)
        except FileNotFoundError:continue
        require(stat.S_ISDIR(info.st_mode) and candidate.resolve(strict=True) == candidate)
        candidates.append(candidate)
    require(len(candidates) == 1)
    source=candidates[0]
    names=['creator-context.json','inventory.json','receipt.json','recipe.json']
    slots=[];source_anchors={};raws={};created=None;destination=None;primary=None
    def owned_open(path,flags):
        # Enroll an empty slot before opening any fallible descriptor.
        slots.append(None);index=len(slots)-1
        slots[index]=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        return slots[index]
    try:
        parent=owned_open(source,os.O_RDONLY|os.O_DIRECTORY)
        parent_anchor=old._witness(os.fstat(parent))
        for name in names:
            lease.fence()
            fd=owned_open(source/name,os.O_RDONLY|os.O_NONBLOCK)
            anchor=old._witness(os.fstat(fd));source_anchors[name]=(fd,anchor)
            limit=256*1024*1024 if name in ('inventory.json','recipe.json') else 65536
            require(stat.S_ISREG(anchor[4]) and anchor[2] == os.getuid() and anchor[5] == 1
                and stat.S_IMODE(anchor[4]) in (0o444,0o555) and 0 < anchor[6] <= limit)
            chunks=[];position=0
            while position < anchor[6]:
                lease.fence();block=os.pread(fd,min(65536,anchor[6]-position),position)
                require(len(block) > 0);chunks.append(block);position+=len(block)
            raw=b''.join(chunks)
            require(position == anchor[6] and os.pread(fd,1,position) == b''
                and old._witness(os.fstat(fd)) == anchor == old._witness(os.stat(name,dir_fd=parent,follow_symlinks=False)))
            raws[name]=raw
        context=json.loads(raws['creator-context.json'])
        require(context == {'MODE':PRODUCER,'ENTRY_NS':str(lease.entry),'DEADLINE_NS':str(lease.deadline),
            'EPOCH':str(epoch),'SOURCE_COMMIT':lease.source_commit,'GRAPH_SHA256':lease.graph_sha256,'BOOT_ID':lease.boot_id})
        report=json.loads(raws['receipt.json'])
        require(report['kind'] == 'omux-retained-public-sdk-tree-producer-v1'
            and report['producer'] == TARGET and report['tree_root'] == 'tree'
            and report['inventory'] == {'sha256':hashlib.sha256(raws['inventory.json']).hexdigest(),
                'bytes':len(raws['inventory.json'])})
        complete_materialization=report['materialization']
        require(type(complete_materialization) is dict and set(complete_materialization) == {
            'recipe_sha256','action_inputs_sha256','inventory_sha256','sdk_nar','jdk_nar'})
        inventory=json.loads(raws['inventory.json'])
        require(complete_materialization['recipe_sha256'] == hashlib.sha256(raws['recipe.json']).hexdigest()
            and complete_materialization['inventory_sha256'] == hashlib.sha256(raws['inventory.json']).hexdigest()
            and complete_materialization['sdk_nar'] == inventory['nars']['sdk']
            and complete_materialization['jdk_nar'] == inventory['nars']['jdk'])
        materialization={name:complete_materialization[name] for name in ('recipe_sha256','action_inputs_sha256')}
        for digest in materialization.values():pin(digest)
        target=epoch/'sdk-tree-created';os.mkdir(target,mode=0o700)
        destination=owned_open(target,os.O_RDONLY|os.O_DIRECTORY)
        rows=[];output_anchors={}
        for name in names:
            lease.fence();raw=raws[name]
            fd=owned_open(target/name,os.O_RDWR|os.O_CREAT|os.O_EXCL)
            offset=0
            while offset < len(raw):
                lease.fence();written=os.write(fd,raw[offset:offset+65536]);require(written > 0);offset+=written
            os.fchmod(fd,0o444);os.fsync(fd)
            anchor=old._witness(os.fstat(fd));output_anchors[name]=(fd,anchor)
            require(stat.S_ISREG(anchor[4]) and anchor[2] == os.getuid() and anchor[5] == 1
                and stat.S_IMODE(anchor[4]) == 0o444 and anchor[6] == len(raw)
                and os.pread(fd,len(raw)+1,0) == raw)
            rows.append({'name':name,'path':str(target/name),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
        os.fsync(destination)
        destination_anchor=old._witness(os.fstat(destination))
        for directory,path,anchor in ((parent,source,parent_anchor),(destination,target,destination_anchor)):
            lease.fence()
            require(old._witness(os.fstat(directory)) == anchor == old._witness(os.stat(path,follow_symlinks=False)))
        for name in names:
            lease.fence()
            for directory,owners in ((parent,source_anchors),(destination,output_anchors)):
                fd,anchor=owners[name]
                require(old._witness(os.fstat(fd)) == anchor == old._witness(os.stat(name,dir_fd=directory,follow_symlinks=False)))
        lease.fence()
        created={'schema_version':1,'kind':'omux-retained-sdk-tree-artifact-origin-v1','family':FAMILY,
            'checkout':str(lease.checkout),'namespace':lease.name,'key':lease.key,'output_base':str(lease.output_base),
            'creator_run_id':lease.run_id,'creator_source_commit':lease.source_commit,'creator_graph_sha256':lease.graph_sha256,
            'creator_context':context,'materialization':materialization,'artifact_layout':LAYOUT,'created_metadata':rows,
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
    except BaseException as error:primary=error;raise
    finally:
        failure=None
        for fd in reversed(slots):
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:
                    if failure is None:failure=error
        if failure is not None:
            if primary is not None:raise primary from failure
            raise failure
    # All byte/copy/close work precedes the last named leaf and original clock
    # checks. No partial copied tree metadata can become a selected origin.
    for name in names:
        lease.fence()
        require(source_anchors[name][1] == old._witness(os.stat(source/name,follow_symlinks=False))
            and output_anchors[name][1] == old._witness(os.stat(epoch/'sdk-tree-created'/name,follow_symlinks=False)))
    require(source.resolve(strict=True) == source
        and parent_anchor == old._witness(os.stat(source,follow_symlinks=False))
        and destination_anchor == old._witness(os.stat(epoch/'sdk-tree-created',follow_symlinks=False)))
    lease.fence()
    return created
