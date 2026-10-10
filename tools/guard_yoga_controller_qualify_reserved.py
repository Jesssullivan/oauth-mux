"""Three exact reserved readonly roles; old standard admission retained."""
from pathlib import Path
import re
import guard_native_seed_plan_reserved as kernel
import yoga_delivery_settings as readonly
import yoga_controller_http_inputs as http_inputs

PROFILE='yoga-controller-qualify-reserved'
STATE_PROFILE='yoga-controller-delivery'
INSPECT_PROFILE='yoga-controller-inspect-reserved'
VERIFY_PROFILE='yoga-controller-verify-reserved'
COMPANION_PROFILE='yoga-wrapper-companion-reserved'
READONLY_PROFILES=(INSPECT_PROFILE,VERIFY_PROFILE)
PRIOR_PROFILES=(*READONLY_PROFILES,COMPANION_PROFILE)
ROLES={PROFILE:'//tools:yoga_controller_qualify',
    INSPECT_PROFILE:'//tools:yoga_controller_inspect',
    VERIFY_PROFILE:'//tools:yoga_controller_verify',
    COMPANION_PROFILE:'//tools:yoga_wrapper_companion'}
PROFILES=tuple(ROLES)
ARGUMENTS=['run',ROLES[PROFILE]]
STATE,COORDINATION=readonly.profile.STATE,readonly.profile.COORDINATION
CLEANUP_RESERVE_NS=readonly.CLEANUP_RESERVE_NS
MEMORY,TASKS,CPU=kernel.MEMORY,kernel.TASKS,kernel.CPU
Witness=kernel.Witness
WorkloadWitness=kernel.WorkloadWitness
monitor=kernel.monitor
cleanup_retained=kernel.cleanup_retained
release_worker=kernel.release_worker
properties=kernel.properties
remaining=kernel.remaining
SCOPE='fixed-yoga-controller-qualify-reservation-v1'

def selected(profile,arguments):
    kernel.require(profile in PROFILES and arguments==[
        'test' if profile==COMPANION_PROFILE else 'run',ROLES[profile]])
    return {'PrivateNetwork':'yes' if profile==COMPANION_PROFILE else 'no'}

def request(args,arguments):
    if args.profile not in PROFILES:return False
    selected(args.profile,arguments)
    allowed={'profile','manager','arguments','python','systemd_run','systemctl','bazel','closure',
        'bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'coordination_dir','become_file','initialize_state_dir'}
    if args.profile in PRIOR_PROFILES:
        allowed.add('yoga_delivery_epoch')
        kernel.require(type(getattr(args,'yoga_delivery_epoch',None)) is str
            and readonly.UUID.fullmatch(args.yoga_delivery_epoch) is not None)
    if args.profile==COMPANION_PROFILE:
        allowed.update(('yoga_wrapper_request','yoga_wrapper_request_sha256'))
        from yoga_wrapper_companion_inputs import selection
        selection(args.yoga_wrapper_request,args.yoga_wrapper_request_sha256)
    kernel.require(args.manager=='system'
        and not any(value for name,value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch('[a-f0-9]{40}',args.source_commit) is not None
        and args.source_dirty=='false' and args.state_dir is not None and args.coordination_dir is not None
        and Path(args.state_dir)==STATE and Path(args.coordination_dir)==COORDINATION)
    return True

def command(builder,bazel,run,arguments,profile,entry,deadline,*,prior=None,
            wrapper_request=None,graph=None,lock=None,**kwargs):
    selected(profile,arguments);remaining(entry,deadline)
    kernel.require(kwargs.get('repository_cache') is None and kwargs.get('nixpkgs_source') is None
        and kwargs.get('output_base') is None)
    if profile==PROFILE:
        kernel.require(prior is None)
    else:
        # The guard alone selects this held raw receipt/extraction chain under
        # the original HOME lock; no caller-selected path/digest is admitted.
        kernel.require(type(prior) is dict and set(prior)=={'path','sha256','producer_epoch',
            'producer_receipt_sha256','directory_identity','receipt_identity',
            'qualification_identity','ancestor_identities'}
            and type(prior['producer_epoch']) is str
            and readonly.UUID.fullmatch(prior['producer_epoch']) is not None
            and prior['path']==str(STATE/prior['producer_epoch']/'qualification.json')
            and all(type(prior[key]) is str and re.fullmatch('[a-f0-9]{64}',prior[key]) is not None
                for key in ('sha256','producer_receipt_sha256')))
    if profile==COMPANION_PROFILE:
        import json
        kernel.require(wrapper_request is not None and type(graph) is str
            and re.fullmatch('[a-f0-9]{64}',graph) is not None and type(lock) is dict)
        wrapper_request.recheck()
        facts=wrapper_request.facts()
        result=builder(bazel,run,arguments,profile='standard',**kwargs)
        values={'OMUX_YOGA_WRAPPER_REQUEST':str(wrapper_request.path),
            'OMUX_YOGA_WRAPPER_REQUEST_SHA256':facts['request_sha256'],
            'OMUX_YOGA_WRAPPER_PRIOR':json.dumps(prior,sort_keys=True,separators=(',',':')),
            'OMUX_YOGA_WRAPPER_SOURCE_COMMIT':kwargs['source_commit'],
            'OMUX_YOGA_WRAPPER_GRAPH_SHA256':graph,
            'OMUX_YOGA_WRAPPER_LOCK_WITNESS':json.dumps(lock,sort_keys=True,separators=(',',':')),
            kernel.ENTRY:str(entry),kernel.DEADLINE:str(deadline)}
        index=result.index('test')+1
        result[index:index]=['--repository_disable_download','--repo_contents_cache=',
            '--repository_cache='+str(http_inputs.cache_path(run)),
            '--sandbox_default_allow_network=false',
            *['--test_env='+key+'='+value for key,value in sorted(values.items())]]
        return result
    kernel.require(wrapper_request is None and graph is None and lock is None)
    from execution_guard import yoga_delivery_command
    result,_=yoga_delivery_command(bazel,run,arguments,deadline,prior,**kwargs)
    index=result.index('run')+1
    result[index:index]=['--repository_disable_download','--repo_contents_cache=',
        '--repository_cache='+str(http_inputs.cache_path(run))]
    return result

def projection(entry,deadline,verified,resident):
    kernel.envelope(entry,deadline)
    kernel.require(verified is None or type(verified) is bool)
    return {'scope':SCOPE,'original_entry_monotonic_ns':entry,
        'original_deadline_monotonic_ns':deadline,'verified_after_cleanup':verified,'resident':resident,
        'copy_performed':False,'installation_qualified':False,'seat_qualified':False,
        'toolbar_consent_proved':False,'credential_acquisition':False}

def readonly_projection(profile,entry,deadline,verified,resident):
    kernel.require(profile in READONLY_PROFILES)
    value=projection(entry,deadline,verified,resident)
    return dict(value,scope='fixed-yoga-controller-readonly-reservation-v1',
        mode=readonly.profile.MODES[ROLES[profile]])

def select_prior(epoch,graph,limits,deadline,lock,*,source_commit):
    return readonly.select_prior(epoch,graph,limits,deadline,lock,
        reserved=True,source_commit=source_commit)

def recheck(prior,graph,limits,deadline,lock,*,source_commit):
    return readonly.recheck(prior,graph,limits,deadline,lock,
        reserved=True,source_commit=source_commit)

def verify_runtime(actual,seconds):
    from guard_yoga_sealed_transfer_profile import effective_runtime
    effective_runtime(actual,seconds)

def prior_receipt(receipt,epoch,graph,base_limits,lock,*,source_commit):
    # Validate the distinct actual producer first. Only the unchanged common
    # qualification/data/lock predicates receive a temporary normalized view.
    kernel.require(type(receipt) is dict and receipt.get('profile')==PROFILE
        and receipt.get('limits')==properties(base_limits)
        and receipt.get('source_dirty')=='false'
        and type(receipt.get('source_commit')) is str
        and re.fullmatch('[a-f0-9]{40}',receipt['source_commit']) is not None
        and receipt['source_commit']==source_commit
        and type(receipt.get('cleanup')) is dict and receipt['cleanup'].get('ownership')=='verified'
        and type(receipt['cleanup'].get('readback_attempts')) is int
        and receipt['cleanup']['readback_attempts']>=2 and receipt.get('reserved_failure') is None)
    inputs=receipt.get('yoga_controller_http_inputs')
    kernel.require(type(inputs) is dict and inputs.get('scope')=='fixed-yoga-controller-locked-http-snapshot-v1'
        and inputs.get('module_sha256')==http_inputs.MODULE_SHA256 and inputs.get('lock_sha256')==http_inputs.LOCK_SHA256
        and type(inputs.get('declared_inputs')) is int and inputs['declared_inputs']==len(http_inputs.DECLARED)
        and type(inputs.get('copied_files')) is int
        and sum(required for _,required in http_inputs.DECLARED)<=inputs['copied_files']<=len(http_inputs.DECLARED)
        and type(inputs.get('missing_optional_inputs')) is int
        and inputs['missing_optional_inputs']==len(http_inputs.DECLARED)-inputs['copied_files']
        and type(inputs.get('copied_bytes')) is int
        and inputs['copied_files']<=inputs['copied_bytes']<=http_inputs.MAX_TOTAL
        and type(inputs.get('snapshot_sha256')) is str and re.fullmatch('[a-f0-9]{64}',inputs['snapshot_sha256']) is not None
        and inputs.get('verified_after_cleanup') is True and inputs.get('custody_released') is True
        and inputs.get('downloads_allowed') is False and inputs.get('complete_dependency_closure_proved') is False)
    reservation=receipt.get('yoga_controller_qualify_reservation')
    kernel.require(type(reservation) is dict and reservation.get('scope')==SCOPE
        and reservation.get('verified_after_cleanup') is True)
    kernel.envelope(reservation.get('original_entry_monotonic_ns'),reservation.get('original_deadline_monotonic_ns'))
    resident=reservation.get('resident')
    kernel.require(type(resident) is dict
        and resident.get('scope')=='sampled-fixed-default-cgroup-kernel-reservation-v1'
        and type(resident.get('observations')) is int and 0<resident['observations']<=65535
        and resident.get('initial_direct_processes_retained') is True
        and resident.get('outer_pid_namespace_matched') is True and resident.get('hierarchical_caps') is True
        and resident.get('resident_signalled') is False)
    kernel.kernel_bounds(resident.get('kernel_bounds'))
    common=dict(receipt,profile=readonly.profile.PROFILE,limits=base_limits)
    return readonly.prior_receipt(common,epoch,graph,base_limits,lock)

# Persisted receipt, graph, role, source, limits and epoch remain untouched.
def finite(arguments,manager,epoch,unrelated):
    if arguments==['test',ROLES[COMPANION_PROFILE]]:
        kernel.require(manager=='system' and not any(unrelated)
            and type(epoch) is str and readonly.UUID.fullmatch(epoch) is not None)
    else:
        readonly.finite(arguments,manager,epoch,unrelated)
tools=readonly.tools
budget=readonly.budget
lock_witness=readonly.lock_witness
def finish(run,arguments,workload_exit,empty,source_verified,deadline,lock):
    if arguments!=['test',ROLES[COMPANION_PROFILE]]:
        return readonly.finish(run,arguments,workload_exit,empty,source_verified,deadline,lock)
    readonly.budget(deadline)
    return {'mode':'wrapper-companion-metadata','controller_tools':readonly.TOOLS,
        'source_verified_after_cleanup':source_verified,'qualification':None,
        'coordination_lock_witness':lock,'copy_performed':False,
        'remote_owned_containment_verified':False,'remote_cleanup':'unknown'}

def companion_projection(entry,deadline,verified,resident):
    return dict(projection(entry,deadline,verified,resident),
        scope='fixed-yoga-wrapper-companion-reservation-v1',metadata_only=True,
        remote_mutation=False,provider_identity_proved=False)

def runtime_seconds(deadline):
    return int(remaining(deadline-1200*10**9,deadline))

http_snapshot=http_inputs.Snapshot
