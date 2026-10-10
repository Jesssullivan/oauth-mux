"""Exact reserved read-only qualification; old standard admission retained."""
from pathlib import Path
import re
import guard_native_seed_plan_reserved as kernel
import yoga_delivery_settings as readonly

PROFILE='yoga-controller-qualify-reserved'
STATE_PROFILE='yoga-controller-delivery'
PROFILES=(PROFILE,)
ARGUMENTS=['run','//tools:yoga_controller_qualify']
STATE,COORDINATION=readonly.profile.STATE,readonly.profile.COORDINATION
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
    kernel.require(profile==PROFILE and arguments==ARGUMENTS)
    return {'PrivateNetwork':'no'}

def request(args,arguments):
    if args.profile!=PROFILE:return False
    selected(args.profile,arguments)
    allowed={'profile','manager','arguments','python','systemd_run','systemctl','bazel','closure',
        'bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'coordination_dir','become_file','initialize_state_dir'}
    kernel.require(args.manager=='system'
        and not any(value for name,value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str and re.fullmatch('[a-f0-9]{40}',args.source_commit) is not None
        and args.source_dirty=='false' and args.state_dir is not None and args.coordination_dir is not None
        and Path(args.state_dir)==STATE and Path(args.coordination_dir)==COORDINATION)
    return True

def command(builder,bazel,run,arguments,profile,entry,deadline,**kwargs):
    selected(profile,arguments);remaining(entry,deadline)
    kernel.require(kwargs.get('repository_cache') is None and kwargs.get('nixpkgs_source') is None
        and kwargs.get('output_base') is None)
    from execution_guard import yoga_delivery_command
    result,_=yoga_delivery_command(bazel,run,arguments,deadline,None,**kwargs)
    index=result.index('run')+1
    result[index:index]=['--repository_disable_download','--repo_contents_cache=']
    return result

def projection(entry,deadline,verified,resident):
    kernel.envelope(entry,deadline)
    kernel.require(verified is None or type(verified) is bool)
    return {'scope':SCOPE,'original_entry_monotonic_ns':entry,
        'original_deadline_monotonic_ns':deadline,'verified_after_cleanup':verified,'resident':resident,
        'copy_performed':False,'installation_qualified':False,'seat_qualified':False,
        'toolbar_consent_proved':False,'credential_acquisition':False}

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
finite=readonly.finite
tools=readonly.tools
budget=readonly.budget
lock_witness=readonly.lock_witness
finish=readonly.finish

def runtime_seconds(deadline):
    return int(remaining(deadline-1200*10**9,deadline))
